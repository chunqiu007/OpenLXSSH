import COpenLXSSHFiles
import CryptoKit
import Darwin
import Foundation
import OpenLXSSHTrust
import XCTest
@testable import OpenLXSSHFiles

private final class FailureWeakSession {
    weak var value: LibSSH2ShellSession?
    init(_ value: LibSSH2ShellSession?) { self.value = value }
}
private final class FailureCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.withLock { value += 1 } }
    var count: Int { lock.withLock { value } }
}
private final class FailureManualDispatcher: @unchecked Sendable {
    private let lock = NSLock()
    private var queued: [@Sendable () -> Void] = []
    var dispatcher: FileTrustCallbackDispatcher {
        FileTrustCallbackDispatcher { [self] work in lock.withLock { queued.append(work) } }
    }
    var count: Int { lock.withLock { queued.count } }
    func runAll() {
        let work = lock.withLock { let work = queued; queued.removeAll(); return work }
        work.forEach { $0() }
    }
}
private final class FailureProviderGate: @unchecked Sendable {
    private let lock = NSLock()
    private var released = false
    private var entered = false
    private var returned = false
    var started: Bool { lock.withLock { entered } }
    var completed: Bool { lock.withLock { returned } }
    func release() { lock.withLock { released = true } }
    func wait() async throws {
        lock.withLock { entered = true }
        defer { lock.withLock { returned = true } }
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !lock.withLock({ released }) {
            guard .now < deadline else { throw NativeShellError(.timeout, operation: "test-provider-gate") }
            // Finite and explicitly releasable; intentionally ignores task cancellation.
            await withCheckedContinuation { continuation in
                DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(10)) { continuation.resume() }
            }
        }
    }
}

/// Offline failure facts/accounting only. AF_UNIX socketpairs are not SSH interoperability,
/// server authentication, graphical presentation, Keychain, or App retirement evidence.
final class NativeFailureObservabilityTests: XCTestCase, @unchecked Sendable {
    private func pair() throws -> [Int32] {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw FileServiceError(.io, operation: "failure-observability-socketpair")
        }
        return fds
    }
    private func options() throws -> NativeShellOptions {
        try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: 0.05,
                               interactionTimeout: 0.04, authenticationTimeout: 0.2)
    }
    private func key(port: UInt16 = 2222) throws -> HostKey {
        let bytes = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        var blob = Data()
        for field in [Data("ssh-ed25519".utf8), bytes] {
            var size = UInt32(field.count).bigEndian
            withUnsafeBytes(of: &size) { blob.append(contentsOf: $0) }; blob.append(field)
        }
        return HostKey(identity: try ServerIdentity(host: "127.0.0.1", port: port), rawKey: blob,
                       algorithmCode: Int32(LIBSSH2_HOSTKEY_TYPE_ED25519))
    }
    private func host(_ port: Int = 2222) throws -> HostIdentity {
        HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(port))
    }
    private func trustedFixture() async throws -> (URL, HostTrustStore, HostIdentity, HostKey, Data) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("NativeFailure-" + UUID().uuidString)
        let trust = try HostTrustStore(directory: AbsolutePath(root.path)), identity = try host(), old = try key()
        let parsed = try SharedHostTrust.parse(old)
        guard case .pending(let pending) = try await trust.evaluate(host: identity, key: parsed) else {
            throw FileServiceError(.untrusted, operation: "test-fixture-pending")
        }
        try await trust.confirm(pending, displayedFingerprint: pending.fingerprint)
        return (root, trust, identity, old, try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value)))
    }
    private func eventually(_ predicate: @escaping @Sendable () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !predicate() {
            guard .now < deadline else { return XCTFail("finite test condition did not complete") }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    /// Independent registry policy tests explicitly supply both facts. Real session tests below
    /// use only close/deinit to establish nativeClosed; they never mark it on the session's behalf.
    private func closeFacts(_ tasks: NativeShellInteractionTasks) {
        tasks.revoke(); tasks.seal(); tasks.markNativeClosed()
    }

    func testChangedWithoutHandlerCarriesExactFactAndDoesNotModifyKnownHosts() async throws {
        let (root, trust, identity, old, before) = try await trustedFixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let presented = try key(), attempt = FileHostTrustAttempt()
        do {
            try await SharedHostTrust.verify(presented, identity: identity, store: trust, timeout: 1,
                token: CancellationToken(), attempt: attempt, handler: nil)
            XCTFail("changed must reject")
        } catch let error as FileServiceError {
            let changed = try XCTUnwrap(error.changedHostKey)
            XCTAssertEqual(error.kind, .untrusted); XCTAssertEqual(changed.host, identity)
            XCTAssertEqual(changed.expectedFingerprint, try SharedHostTrust.parse(old).fingerprint)
            XCTAssertEqual(changed.presentedFingerprint, try SharedHostTrust.parse(presented).fingerprint)
            XCTAssertEqual(attempt.changedHostKey, changed)
        }
        XCTAssertEqual(before, try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value)))
    }
    func testChangedDelayedCallbackIsRegisteredBeforeCloseAndFactSurvivesSuppression() async throws {
        let (root, trust, identity, _, before) = try await trustedFixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let tasks = NativeShellInteractionTasks(), dispatcher = FailureManualDispatcher(), callbacks = FailureCounter()
        let token = CancellationToken(), lifetime = CancellationToken(), attempt = FileHostTrustAttempt()
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options(), interactionTasks: tasks, trustAttempt: attempt)
        defer { dispatcher.runAll() }
        let reply = ChallengeReply<Bool>()
        SharedHostTrust.respond(to: try key(), reply: reply, identity: identity, store: trust, timeout: 1,
            token: token, attempt: attempt, tasks: tasks, dispatcher: dispatcher.dispatcher, lifetime: lifetime) { _, _ in
                callbacks.increment()
            }
        XCTAssertFalse(try NativeShellInteraction.wait(reply, token: token, lifetime: lifetime,
            deadline: .now.advanced(by: .seconds(1)), tasks: tasks))
        XCTAssertNotNil(attempt.changedHostKey); XCTAssertEqual(callbacks.count, 0)
        XCTAssertEqual(dispatcher.count, 1)
        token.cancel(); lifetime.cancel()
        let start = ContinuousClock.now
        await session.close()
        XCTAssertLessThan(start.duration(to: .now), .seconds(1))
        let failure = session.failureAfterClose(NativeShellError(.untrusted, operation: "host-key"), operation: "connect")
        XCTAssertEqual(failure.changedHostKey, attempt.changedHostKey)
        XCTAssertEqual(failure.pendingInteractionTasks, 1); XCTAssertFalse(session.interactionSnapshot().drained)
        dispatcher.runAll()
        let drained = try await session.interactionDrain.wait(timeout: 1)
        XCTAssertTrue(drained.drained); XCTAssertEqual(callbacks.count, 0)
        XCTAssertEqual(before, try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value)))
    }
    func testDelayedChangedInformationalReplyCanNeverConfirmOrReplaceKnownKey() async throws {
        let (root, trust, identity, _, before) = try await trustedFixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let dispatcher = FailureManualDispatcher(), attempt = FileHostTrustAttempt(), callbacks = FailureCounter()
        defer { dispatcher.runAll() }
        do {
            try await SharedHostTrust.verify(key(), identity: identity, store: trust, timeout: 1,
                token: CancellationToken(), attempt: attempt, dispatcher: dispatcher.dispatcher) { event, reply in
                    guard case .changed(let changed) = event else { return XCTFail("changed rejection only") }
                    callbacks.increment()
                    XCTAssertFalse(reply.resolve(.confirm(displayedFingerprint: changed.presentedFingerprint)))
                    XCTAssertFalse(reply.resolve(.confirmOnce(displayedFingerprint: changed.presentedFingerprint)))
                }
            XCTFail("changed must reject")
        } catch let error as FileServiceError { XCTAssertEqual(error.changedHostKey, attempt.changedHostKey) }
        XCTAssertEqual(callbacks.count, 0); XCTAssertEqual(dispatcher.count, 1)
        dispatcher.runAll(); XCTAssertEqual(callbacks.count, 1)
        XCTAssertEqual(before, try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value)))
        XCTAssertTrue(attempt.enriching(CancellationError()) is CancellationError)
    }
    func testNativeBoolFailureAfterActualClosePreservesAttemptFactAndCanonicalHandle() async throws {
        let (root, trust, identity, _, before) = try await trustedFixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let attempt = FileHostTrustAttempt(), tasks = NativeShellInteractionTasks()
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options(), interactionTasks: tasks, trustAttempt: attempt)
        let reply = ChallengeReply<Bool>(), primaryCalls = FailureCounter()
        let token = CancellationToken(), lifetime = CancellationToken()
        SharedHostTrust.respond(to: try key(), reply: reply, identity: identity, store: trust, timeout: 1,
            token: token, attempt: attempt, tasks: tasks, lifetime: lifetime, handler: nil)
        let accepted = try NativeShellInteraction.wait(reply, token: token, lifetime: lifetime,
            deadline: .now.advanced(by: .seconds(1)), tasks: tasks)
        XCTAssertFalse(accepted)
        let source = NativeShellAuthenticationSource(method: .password, provider: { _ in
            primaryCalls.increment(); return .password(Data())
        }, keyboard: nil)
        XCTAssertThrowsError(try NativeShellPrimaryGate().acquire(source: source, sessionID: session.sessionID,
            trusted: accepted, methods: ["password"], token: token, lifetime: lifetime,
            budget: NativeShellAuthenticationBudget(options: options()), tasks: tasks))
        await session.close()
        let failure = session.failureAfterClose(NativeShellError(.untrusted, operation: "host-key"), operation: "connect")
        XCTAssertEqual(failure.changedHostKey, attempt.changedHostKey); XCTAssertNotNil(failure.changedHostKey)
        XCTAssertTrue(failure.interactionDrain === session.interactionDrain)
        XCTAssertTrue(try XCTUnwrap(failure.interactionDrain).snapshot.drained)
        XCTAssertEqual(failure.pendingInteractionTasks, 0); XCTAssertEqual(primaryCalls.count, 0)
        XCTAssertEqual(before, try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value)))
    }
    func testFileErrorConversionAndWrappingDoNotDiscardChangedFact() async throws {
        let (root, trust, identity, _, _) = try await trustedFixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let attempt = FileHostTrustAttempt(), session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options())
        var rejection: FileServiceError?
        do {
            try await SharedHostTrust.verify(key(), identity: identity, store: trust, timeout: 1,
                token: CancellationToken(), attempt: attempt, handler: nil)
            XCTFail("changed must reject")
        } catch let error as FileServiceError { rejection = error }
        await session.close()
        let converted = session.failureAfterClose(try XCTUnwrap(rejection), operation: "connect")
        let wrapped = session.failureAfterClose(converted, operation: "outer")
        XCTAssertEqual(converted.changedHostKey, attempt.changedHostKey)
        XCTAssertEqual(wrapped.changedHostKey, converted.changedHostKey); XCTAssertEqual(converted, wrapped)
    }
    func testSFTPBoolFailureEnrichmentAfterCloseUsesSameFactWithoutCallback() async throws {
        let (root, trust, identity, _, before) = try await trustedFixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let service = try LibSSH2FileService(connectedSocket: fds[0], operationTimeout: 0.05)
        let attempt = FileHostTrustAttempt(), reply = ChallengeReply<Bool>(), token = CancellationToken()
        SharedHostTrust.respond(to: try key(), reply: reply, identity: identity, store: trust, timeout: 1,
            token: token, attempt: attempt, handler: nil)
        XCTAssertFalse(try reply.wait(token: token, deadline: Date().addingTimeInterval(1)))
        await service.close()
        let failure = try XCTUnwrap(attempt.enriching(FileServiceError(.untrusted, operation: "host-key")) as? FileServiceError)
        XCTAssertEqual(failure.changedHostKey?.host, identity); XCTAssertEqual(failure.changedHostKey, attempt.changedHostKey)
        XCTAssertEqual(before, try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value)))
    }
    func testEndpointAndRawAlgorithmMismatchNeverManufactureChangedFact() async throws {
        let (root, trust, _, old, before) = try await trustedFixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let attempt = FileHostTrustAttempt(), callbacks = FailureCounter()
        let mismatches = [(old, try host(2223)),
            (HostKey(identity: old.identity, rawKey: old.rawKey, algorithmCode: Int32(LIBSSH2_HOSTKEY_TYPE_RSA)), try host())]
        for (actual, identity) in mismatches {
            do {
                try await SharedHostTrust.verify(actual, identity: identity, store: trust, timeout: 1,
                    token: CancellationToken(), attempt: attempt) { _, _ in callbacks.increment() }
                XCTFail("mismatch must reject")
            } catch let error as FileServiceError { XCTAssertNil(error.changedHostKey) }
            catch { /* Mature parser rejects the raw-blob/algorithm mismatch. */ }
        }
        XCTAssertNil(attempt.changedHostKey); XCTAssertEqual(callbacks.count, 0)
        XCTAssertEqual(before, try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value)))
    }
    func testPrecancelledTrustDoesNotObserveOrInventChangedFact() async throws {
        let (root, trust, identity, _, _) = try await trustedFixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let attempt = FileHostTrustAttempt(), token = CancellationToken(); token.cancel()
        do {
            try await SharedHostTrust.verify(key(), identity: identity, store: trust, timeout: 1,
                token: token, attempt: attempt, handler: nil)
            XCTFail("cancelled")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled); XCTAssertNil(error.changedHostKey) }
        XCTAssertNil(attempt.changedHostKey)
    }
    func testInitialZeroAndNativeClosedAloneAreNotTerminalDrain() throws {
        let tasks = NativeShellInteractionTasks()
        XCTAssertEqual(tasks.snapshot.pendingTasks, 0); XCTAssertFalse(tasks.snapshot.drained)
        tasks.markNativeClosed(); XCTAssertFalse(tasks.snapshot.drained)
        let id = try tasks.begin(provider: false)
        tasks.revoke(); tasks.seal()
        XCTAssertFalse(tasks.snapshot.drained)
        tasks.finish(id); XCTAssertTrue(tasks.snapshot.drained)
        XCTAssertThrowsError(try tasks.begin(provider: true))
    }
    func testBeginInstallRevokeSealAndFinishRemainMonotonicAndCancelOutsideLock() throws {
        let tasks = NativeShellInteractionTasks(), calls = FailureCounter()
        let first = try tasks.begin(provider: false), late = try tasks.begin(provider: true)
        tasks.install(first) { _ = tasks.snapshot; calls.increment() }
        tasks.revoke(); tasks.revoke(); tasks.seal(); tasks.seal()
        tasks.install(late) { _ = tasks.snapshot; calls.increment() }
        XCTAssertEqual(calls.count, 2)
        tasks.markNativeClosed(); XCTAssertFalse(tasks.snapshot.drained)
        XCTAssertThrowsError(try tasks.begin(provider: false))
        tasks.finish(first); XCTAssertFalse(tasks.snapshot.drained)
        tasks.finish(late); XCTAssertTrue(tasks.snapshot.drained)
        tasks.finish(first); tasks.revoke(); tasks.seal(); tasks.markNativeClosed()
        XCTAssertEqual(calls.count, 2); XCTAssertTrue(tasks.snapshot.drained)
    }
    func testDuplicateAndLateInstallCancelOnlyOnceAndDoNotRevokeCompletedAnswer() throws {
        let tasks = NativeShellInteractionTasks(), first = try tasks.begin(provider: false), calls = FailureCounter()
        XCTAssertTrue(tasks.install(first) { calls.increment() })
        XCTAssertFalse(tasks.install(first) { calls.increment() })
        tasks.revoke(); tasks.revoke(); XCTAssertEqual(calls.count, 1)
        tasks.finish(first)
        XCTAssertFalse(tasks.install(first) { calls.increment() }); XCTAssertEqual(calls.count, 1)
        let lateTasks = NativeShellInteractionTasks(), late = try lateTasks.begin(provider: false)
        lateTasks.revoke(); lateTasks.finish(late)
        XCTAssertTrue(lateTasks.install(late) { calls.increment() })
        XCTAssertFalse(lateTasks.install(late) { calls.increment() }); XCTAssertEqual(calls.count, 2)
        let completedTasks = NativeShellInteractionTasks(), completed = try completedTasks.begin(provider: false)
        let reply = ChallengeReply<Bool>(); reply.resolve(true); completedTasks.finish(completed)
        XCTAssertTrue(completedTasks.install(completed) { reply.cancel() })
        XCTAssertTrue(try reply.wait(token: CancellationToken(), deadline: Date().addingTimeInterval(1)))
    }
    func testProducerAndLateInstallationAccountingAreBoundedWithoutFakingPendingCompletion() throws {
        let tasks = NativeShellInteractionTasks()
        let ids = try (0..<NativeShellInteractionTasks.maximumProducers).map { _ in try tasks.begin(provider: true) }
        XCTAssertThrowsError(try tasks.begin(provider: false)) {
            XCTAssertEqual(($0 as? NativeShellError)?.kind, .resourceLimit)
        }
        ids.forEach { tasks.finish($0) } // Actual completion, deliberately before installation.
        XCTAssertEqual(tasks.pendingInstallations, ids.count); XCTAssertEqual(tasks.snapshot.pendingTasks, 0)
        XCTAssertFalse(tasks.snapshot.drained)
        XCTAssertThrowsError(try tasks.begin(provider: false))
        closeFacts(tasks); XCTAssertTrue(tasks.snapshot.drained)
        for _ in 0..<10 { XCTAssertThrowsError(try tasks.begin(provider: false)) }
        XCTAssertEqual(tasks.pendingInstallations, ids.count)
        let cancels = FailureCounter()
        for id in ids { XCTAssertTrue(tasks.install(id) { cancels.increment() }) }
        XCTAssertEqual(tasks.pendingInstallations, 0); XCTAssertEqual(cancels.count, ids.count)
        XCTAssertTrue(tasks.snapshot.drained)
    }
    func testConcurrentBeginRevokeSealNeverAdmitsAfterTerminalDrain() {
        for _ in 0..<20 {
            let tasks = NativeShellInteractionTasks(), ids = FailureIDBox(), cancels = FailureCounter()
            DispatchQueue.concurrentPerform(iterations: 24) { index in
                if index == 0 { tasks.revoke(); tasks.seal(); return }
                if let id = try? tasks.begin(provider: index.isMultiple(of: 2)) {
                    ids.append(id)
                    tasks.install(id) { _ = tasks.snapshot; cancels.increment() }
                }
            }
            tasks.revoke(); tasks.seal(); tasks.markNativeClosed()
            XCTAssertEqual(tasks.snapshot.pendingTasks, ids.values.count)
            if !ids.values.isEmpty { XCTAssertFalse(tasks.snapshot.drained) }
            ids.values.forEach { tasks.finish($0) }
            XCTAssertTrue(tasks.snapshot.drained); XCTAssertEqual(cancels.count, ids.values.count)
            XCTAssertThrowsError(try tasks.begin(provider: false))
        }
    }
    func testQueuedCallbackPreventsEarlyDrainAndSealedDispatcherRejectsNewWork() throws {
        let tasks = NativeShellInteractionTasks(), dispatcher = FailureManualDispatcher(), calls = FailureCounter()
        defer { dispatcher.runAll() }
        try tasks.dispatch(using: dispatcher.dispatcher, cancel: {}) { calls.increment() }
        closeFacts(tasks)
        XCTAssertFalse(tasks.snapshot.drained); XCTAssertEqual(tasks.snapshot.pendingTasks, 1)
        XCTAssertThrowsError(try tasks.dispatch(using: dispatcher.dispatcher, cancel: {}) { calls.increment() })
        XCTAssertEqual(dispatcher.count, 1)
        dispatcher.runAll(); XCTAssertEqual(calls.count, 0); XCTAssertTrue(tasks.snapshot.drained)
    }
    func testNoncooperativeProviderOutlivesSessionAndBoundedDrainUntilActualReturn() async throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let tasks = NativeShellInteractionTasks(), gate = FailureProviderGate(), consumed = FailureCounter()
        defer { gate.release() }
        var session: LibSSH2ShellSession? = try LibSSH2ShellSession(connectedSocket: fds[0], options: options(), interactionTasks: tasks)
        let weakSession = FailureWeakSession(session)
        let handle = try XCTUnwrap(session).interactionDrain
        let token = CancellationToken(), lifetime = CancellationToken()
        let budget = NativeShellAuthenticationBudget(options: try options())
        let source = NativeShellAuthenticationSource(method: .password, provider: { _ in
            try await gate.wait(); return .password(Data([1]))
        }, keyboard: nil)
        let acquisition = Task.detached {
            do {
                _ = try NativeShellPrimaryGate().acquire(source: source, sessionID: UUID(), trusted: true,
                    methods: ["password"], token: token, lifetime: lifetime, budget: budget, tasks: tasks)
                consumed.increment(); return false
            } catch { return true }
        }
        try await eventually { gate.started }
        let rejected = await acquisition.value
        XCTAssertTrue(rejected)
        let start = ContinuousClock.now
        await session?.close()
        XCTAssertLessThan(start.duration(to: .now), .seconds(1))
        XCTAssertFalse(handle.snapshot.drained); XCTAssertEqual(handle.snapshot.pendingProviders, 1)
        XCTAssertTrue(handle.snapshot.nativeClosed); XCTAssertTrue(handle.snapshot.producersSealed)
        session = nil; XCTAssertNil(weakSession.value)
        let held = try await handle.wait(timeout: 0.05)
        XCTAssertFalse(held.drained); XCTAssertFalse(gate.completed); XCTAssertEqual(consumed.count, 0)
        gate.release()
        let drained = try await handle.wait(timeout: 1)
        XCTAssertTrue(drained.drained); XCTAssertEqual(drained.pendingProviders, 0); XCTAssertTrue(gate.completed)
        XCTAssertEqual(consumed.count, 0)
    }
    func testCancelledWaiterDoesNotCancelProviderOrOtherWaiterAndObservers() async throws {
        let tasks = NativeShellInteractionTasks(), id = try tasks.begin(provider: true)
        let handle = NativeShellDrainHandle(tasks: tasks), a = FailureCounter(), b = FailureCounter(), removed = FailureCounter()
        try handle.observeCompletion { _ in a.increment() }; try handle.observeCompletion { _ in b.increment() }
        let removedID = try handle.observeCompletion { _ in removed.increment() }; handle.removeCompletionObserver(removedID)
        let cancelled = Task { try await handle.wait(timeout: 2) }
        let other = Task { try await handle.wait(timeout: 2) }
        try await eventually { tasks.subscriptionCounts.waiters == 2 }
        cancelled.cancel()
        do { _ = try await cancelled.value; XCTFail("waiter cancellation must throw") } catch is CancellationError { }
        XCTAssertEqual(tasks.subscriptionCounts.waiters, 1); XCTAssertEqual(tasks.snapshot.pendingProviders, 1)
        XCTAssertFalse(tasks.snapshot.revoked)
        closeFacts(tasks); XCTAssertEqual(a.count, 0); XCTAssertEqual(b.count, 0)
        tasks.finish(id)
        let drained = try await other.value
        XCTAssertTrue(drained.drained)
        try await eventually { a.count == 1 && b.count == 1 && tasks.subscriptionCounts.observers == 0 }
        XCTAssertEqual(a.count, 1); XCTAssertEqual(b.count, 1); XCTAssertEqual(removed.count, 0)
        tasks.finish(id); closeFacts(tasks)
        XCTAssertEqual(a.count, 1); XCTAssertEqual(b.count, 1)
        XCTAssertEqual(tasks.subscriptionCounts.waiters, 0); XCTAssertEqual(tasks.subscriptionCounts.observers, 0)
    }
    func testLateCompletionSubscriptionsAreOnceAndErrorEqualityIsStable() async throws {
        let tasks = NativeShellInteractionTasks(), id = try tasks.begin(provider: false)
        let handle = NativeShellDrainHandle(tasks: tasks), other = NativeShellDrainHandle(tasks: NativeShellInteractionTasks())
        let error = NativeShellError(.timeout, operation: "provider", pendingInteractionTasks: 1, interactionDrain: handle)
        let copy = NativeShellError(.timeout, operation: "provider", pendingInteractionTasks: 1, interactionDrain: handle)
        let unequal = NativeShellError(.timeout, operation: "provider", pendingInteractionTasks: 1, interactionDrain: other)
        XCTAssertEqual(error, copy); XCTAssertNotEqual(error, unequal)
        closeFacts(tasks); tasks.finish(id)
        XCTAssertEqual(error, copy); XCTAssertEqual(error.pendingInteractionTasks, 1)
        XCTAssertTrue(try XCTUnwrap(error.interactionDrain).snapshot.drained)
        let calls = FailureCounter()
        let first = try handle.observeCompletion { snapshot in XCTAssertTrue(snapshot.drained); calls.increment() }
        let second = try handle.observeCompletion { _ in calls.increment() }
        XCTAssertNotEqual(first, second)
        try await eventually { calls.count == 2 && tasks.subscriptionCounts.observers == 0 }
        XCTAssertEqual(calls.count, 2)
        handle.removeCompletionObserver(first); closeFacts(tasks); XCTAssertEqual(calls.count, 2)
    }
    func testInvalidDrainBudgetsRejectAndZeroAndTimeoutReturnActualSnapshot() async throws {
        let tasks = NativeShellInteractionTasks(), id = try tasks.begin(provider: true)
        let handle = NativeShellDrainHandle(tasks: tasks)
        defer { closeFacts(tasks); tasks.finish(id) }
        for invalid in [-1.0, .nan, .infinity, -.infinity, 5.001] {
            do { _ = try await handle.wait(timeout: invalid); XCTFail("invalid budget") }
            catch let error as NativeShellError { XCTAssertEqual(error.kind, .invalidConfiguration) }
        }
        let immediate = try await handle.wait(timeout: 0)
        XCTAssertEqual(immediate, tasks.snapshot)
        let start = ContinuousClock.now, timedOut = try await handle.wait(timeout: 0.03)
        XCTAssertLessThan(start.duration(to: .now), .milliseconds(500))
        XCTAssertEqual(timedOut, tasks.snapshot); XCTAssertEqual(timedOut.pendingProviders, 1)
        XCTAssertFalse(timedOut.drained); XCTAssertEqual(tasks.subscriptionCounts.waiters, 0)
    }
    func testObserverAndWaiterCapacityRejectExplicitlyAndReleaseSlots() async throws {
        let tasks = NativeShellInteractionTasks(), id = try tasks.begin(provider: true)
        let handle = NativeShellDrainHandle(tasks: tasks), callbacks = FailureCounter()
        var observations: [UUID] = []
        for _ in 0..<NativeShellInteractionTasks.maximumObservers {
            observations.append(try handle.observeCompletion { _ in callbacks.increment() })
        }
        XCTAssertThrowsError(try handle.observeCompletion { _ in callbacks.increment() }) {
            XCTAssertEqual(($0 as? NativeShellError)?.kind, .resourceLimit)
        }
        handle.removeCompletionObserver(observations.removeLast())
        try handle.observeCompletion { _ in callbacks.increment() }
        let waiters = (0..<NativeShellInteractionTasks.maximumWaiters).map { _ in Task { try await handle.wait(timeout: 2) } }
        defer { waiters.forEach { $0.cancel() }; closeFacts(tasks); tasks.finish(id) }
        try await eventually { tasks.subscriptionCounts.waiters == NativeShellInteractionTasks.maximumWaiters }
        do { _ = try await handle.wait(timeout: 1); XCTFail("waiter capacity") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .resourceLimit) }
        waiters[0].cancel()
        do { _ = try await waiters[0].value; XCTFail("cancelled waiter") } catch is CancellationError { }
        XCTAssertEqual(tasks.subscriptionCounts.waiters, NativeShellInteractionTasks.maximumWaiters - 1)
        closeFacts(tasks); tasks.finish(id)
        for waiter in waiters.dropFirst() { let snapshot = try await waiter.value; XCTAssertTrue(snapshot.drained) }
        try await eventually { callbacks.count == NativeShellInteractionTasks.maximumObservers && tasks.subscriptionCounts.observers == 0 }
        XCTAssertEqual(callbacks.count, NativeShellInteractionTasks.maximumObservers)
        XCTAssertEqual(tasks.subscriptionCounts.waiters, 0); XCTAssertEqual(tasks.subscriptionCounts.observers, 0)
    }
    func testBlockingCompletionObserverCannotHoldNativeCloseOrOtherObservers() async throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options())
        let entered = FailureCounter(), returned = FailureCounter(), other = FailureCounter()
        let release = DispatchSemaphore(value: 0)
        defer { release.signal() }
        try session.interactionDrain.observeCompletion { snapshot in
            XCTAssertTrue(snapshot.drained); entered.increment()
            XCTAssertEqual(release.wait(timeout: .now() + 3), .success)
            returned.increment()
        }
        try session.interactionDrain.observeCompletion { _ in other.increment() }
        let start = ContinuousClock.now
        await session.close()
        XCTAssertLessThan(start.duration(to: .now), .seconds(1))
        try await eventually { entered.count == 1 && other.count == 1 }
        XCTAssertEqual(returned.count, 0); XCTAssertTrue(session.interactionDrain.snapshot.drained)
        release.signal()
        try await eventually { returned.count == 1 }
    }
    func testActualCloseAndDeinitPublishNativeClosedOnlyAfterDisposal() async throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        var session: LibSSH2ShellSession? = try LibSSH2ShellSession(connectedSocket: fds[0], options: options())
        let handle = try XCTUnwrap(session).interactionDrain
        XCTAssertFalse(handle.snapshot.nativeClosed); XCTAssertFalse(handle.snapshot.drained)
        await session?.close(); await session?.close()
        XCTAssertTrue(handle.snapshot.nativeClosed); XCTAssertTrue(handle.snapshot.producersSealed)
        XCTAssertTrue(try XCTUnwrap(session).interactionSnapshot().drained)
        session = nil
        let closed = try await handle.wait(timeout: 0)
        XCTAssertTrue(closed.drained)
        let secondPair = try pair(); defer { secondPair.forEach { Darwin.close($0) } }
        var second: LibSSH2ShellSession? = try LibSSH2ShellSession(connectedSocket: secondPair[0], options: options())
        let secondHandle = try XCTUnwrap(second).interactionDrain
        second = nil
        let disposed = try await secondHandle.wait(timeout: 1)
        XCTAssertTrue(disposed.nativeClosed); XCTAssertTrue(disposed.producersSealed); XCTAssertTrue(disposed.drained)
    }
    func testOldErrorInitializersSendabilityAndExhaustiveKindSwitchesRemainCompatible() throws {
        let old: (FileServiceError.Kind, String, RemotePath?, Int64?) -> FileServiceError = FileServiceError.init
        let file = old(.untrusted, "legacy", nil, nil), native = NativeShellError(.untrusted, operation: "legacy")
        func sendable<T: Sendable>(_ value: T) { }
        sendable(file); sendable(native)
        XCTAssertNil(file.changedHostKey); XCTAssertNil(native.changedHostKey); XCTAssertNil(native.interactionDrain)
        XCTAssertEqual(native.pendingInteractionTasks, 0)
        switch native.kind {
        case .invalidConfiguration, .resourceLimit, .busy, .cancelled, .timeout, .untrusted,
             .authentication, .transport, .closed, .protocolFailure, .unsupported: break
        }
        switch file.kind {
        case .invalidPath, .notFound, .permissionDenied, .conflict, .symbolicLink, .unsupported,
             .cancelled, .timeout, .untrusted, .authentication, .transport, .protocolFailure, .closed,
             .resourceLimit, .integrity, .io, .needsCapabilityConfirmation, .riskRejected, .raceDetected: break
        }
    }
}
private final class FailureIDBox: @unchecked Sendable {
    private let lock = NSLock()
    private var ids: [UUID] = []
    func append(_ id: UUID) { lock.withLock { ids.append(id) } }
    var values: [UUID] { lock.withLock { ids } }
}
