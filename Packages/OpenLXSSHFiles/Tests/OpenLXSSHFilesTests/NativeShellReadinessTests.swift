import COpenLXSSHFiles
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

private final class ReadinessCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.withLock { value += 1 } }
    var count: Int { lock.withLock { value } }
}
private final class ReadinessAsyncGate: @unchecked Sendable {
    private let lock = NSLock()
    private var released = false
    func release() { lock.withLock { released = true } }
    func wait() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(1))
        while !lock.withLock({ released }) {
            guard .now < deadline else { throw NativeShellError(.timeout, operation: "test-async-gate") }
            // Deliberately ignores task cancellation, but remains finite and releasable by defer.
            await withCheckedContinuation { continuation in
                DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(5)) { continuation.resume() }
            }
        }
    }
}
private final class ReadinessReplyBox<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var reply: ChallengeReply<Value>?
    func store(_ reply: ChallengeReply<Value>) { lock.withLock { self.reply = reply } }
    var value: ChallengeReply<Value>? { lock.withLock { reply } }
}

/// Policy/mailbox/state-machine regressions only. No mock SSH packets, real endpoint, Keychain
/// or saved credential reader. A policy success here is NOT authenticated-shell/live proof.
final class NativeShellReadinessTests: XCTestCase, @unchecked Sendable {
    private func options(network: Double = 0.1, interaction: Double = 0.3, overall: Double = 0.5) throws -> NativeShellOptions {
        try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: network,
                               interactionTimeout: interaction, authenticationTimeout: overall)
    }
    private func pair() throws -> [Int32] {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw FileServiceError(.io, operation: "readiness-socketpair") }
        return fds
    }
    func testLegacyBudgetsDoNotExpandAndProductionBudgetsAreExplicit() throws {
        let size = try NativeShellSize(columns: 80, rows: 24)
        let legacy = try NativeShellOptions(size: size, operationTimeout: 15)
        XCTAssertEqual(legacy.operationTimeout, 15); XCTAssertEqual(legacy.interactionTimeout, 15)
        XCTAssertEqual(legacy.authenticationTimeout, 15); XCTAssertNil(legacy.liveness)
        let production = try NativeShellOptions(size: size, operationTimeout: 10, interactionTimeout: 120, authenticationTimeout: 300)
        XCTAssertEqual(production.interactionTimeout, 120); XCTAssertEqual(production.authenticationTimeout, 300)
        for invalid in [0, -1, .infinity, .nan, 121] {
            XCTAssertThrowsError(try NativeShellOptions(size: size, interactionTimeout: invalid))
        }
        for invalid in [0, -1, .infinity, .nan, 301] {
            XCTAssertThrowsError(try NativeShellOptions(size: size, authenticationTimeout: invalid))
        }
    }
    func testMonotonicInteractionDeadlineIsCappedByWholeAuthentication() throws {
        let now = ContinuousClock.now
        let budget = NativeShellAuthenticationBudget(options: try options(network: 1, interaction: 2, overall: 3), now: now)
        XCTAssertEqual(try budget.interactionDeadline(now: now), now.advanced(by: .seconds(2)))
        XCTAssertEqual(try budget.interactionDeadline(now: now.advanced(by: .seconds(2))), budget.deadline)
        XCTAssertEqual(try budget.remaining(now: now.advanced(by: .seconds(2))), 1, accuracy: 0.000001)
        XCTAssertThrowsError(try budget.remaining(now: budget.deadline))
        XCTAssertThrowsError(try budget.interactionDeadline(now: budget.deadline))
    }
    func testProviderCannotReadBeforeTrustOrUnavailableMethod() throws {
        let calls = ReadinessCounter()
        let source = NativeShellAuthenticationSource(method: .password, provider: { _ in calls.increment(); return .password(Data()) }, keyboard: nil)
        let gate = NativeShellPrimaryGate(), token = CancellationToken(), lifetime = CancellationToken()
        let budget = NativeShellAuthenticationBudget(options: try options())
        XCTAssertThrowsError(try gate.acquire(source: source, sessionID: UUID(), trusted: false, methods: ["password"],
            token: token, lifetime: lifetime, budget: budget)) { XCTAssertEqual(($0 as? NativeShellError)?.kind, .untrusted) }
        XCTAssertThrowsError(try gate.acquire(source: source, sessionID: UUID(), trusted: true, methods: ["publickey"],
            token: token, lifetime: lifetime, budget: budget)) { XCTAssertEqual(($0 as? NativeShellError)?.kind, .authentication) }
        XCTAssertEqual(calls.count, 0)
    }
    func testProviderOnlyOnceAndRequestBoundToChosenMethodAndSession() throws {
        let calls = ReadinessCounter(), session = UUID(), token = CancellationToken()
        let source = NativeShellAuthenticationSource(method: .password, provider: { request in
            XCTAssertEqual(request.method, .password); XCTAssertEqual(request.sessionID, session)
            XCTAssertTrue(request.token === token); try request.token.check()
            calls.increment(); return .password(Data([1]))
        }, keyboard: nil)
        let gate = NativeShellPrimaryGate(), lifetime = CancellationToken()
        let budget = NativeShellAuthenticationBudget(options: try options())
        let material = try gate.acquire(source: source, sessionID: session, trusted: true, methods: ["password"],
            token: token, lifetime: lifetime, budget: budget)
        guard case .password(let bytes) = material else { return XCTFail("typed password") }
        XCTAssertEqual(bytes, Data([1])); XCTAssertEqual(calls.count, 1)
        XCTAssertThrowsError(try gate.acquire(source: source, sessionID: session, trusted: true, methods: ["password"],
            token: token, lifetime: lifetime, budget: budget))
        XCTAssertEqual(calls.count, 1)
    }
    func testProviderMethodMismatchNeverChangesChosenMethodOrRetries() throws {
        let calls = ReadinessCounter()
        let source = NativeShellAuthenticationSource(method: .password, provider: { _ in
            calls.increment(); return .publicKey(publicKey: nil, privateKey: Data([1]), passphrase: nil)
        }, keyboard: nil)
        let gate = NativeShellPrimaryGate(), token = CancellationToken(), lifetime = CancellationToken()
        let budget = NativeShellAuthenticationBudget(options: try options())
        XCTAssertThrowsError(try gate.acquire(source: source, sessionID: UUID(), trusted: true, methods: ["password", "publickey"],
            token: token, lifetime: lifetime, budget: budget)) {
            XCTAssertEqual(($0 as? NativeShellError)?.operation, "primary-method-mismatch")
        }
        XCTAssertThrowsError(try gate.acquire(source: source, sessionID: UUID(), trusted: true, methods: ["password"],
            token: token, lifetime: lifetime, budget: budget))
        XCTAssertEqual(calls.count, 1)
    }
    func testCancellationWhileProviderIgnoresCancellationRejectsLateMaterial() throws {
        let started = DispatchSemaphore(value: 0), release = ReadinessAsyncGate(), completed = DispatchSemaphore(value: 0)
        let calls = ReadinessCounter(), token = CancellationToken(), lifetime = CancellationToken()
        defer { release.release() }
        let source = NativeShellAuthenticationSource(method: .password, provider: { request in
            calls.increment(); started.signal()
            try await release.wait()
            defer { completed.signal() }
            XCTAssertTrue(request.token.isCancelled)
            return .password(Data([1])) // Deliberate late *test bytes*, never used by native auth.
        }, keyboard: nil)
        DispatchQueue.global().async {
            if started.wait(timeout: .now() + 1) == .success { token.cancel() }
            release.release()
        }
        XCTAssertThrowsError(try NativeShellPrimaryGate().acquire(source: source, sessionID: UUID(), trusted: true,
            methods: ["password"], token: token, lifetime: lifetime, budget: NativeShellAuthenticationBudget(options: options()))) {
            XCTAssertEqual(($0 as? FileServiceError)?.kind, .cancelled)
        }
        XCTAssertEqual(completed.wait(timeout: .now() + 1), .success); XCTAssertEqual(calls.count, 1)
    }
    func testNoncooperativeProviderRemainsObservableUntilActualCompletion() async throws {
        let tasks = NativeShellInteractionTasks(), release = ReadinessAsyncGate()
        defer { release.release() }
        let source = NativeShellAuthenticationSource(method: .password, provider: { _ in
            // Finite test substitute for a caller that ignores Swift cancellation.
            try await release.wait()
            return .password(Data())
        }, keyboard: nil)
        let token = CancellationToken()
        let budget = NativeShellAuthenticationBudget(options: try options(interaction: 0.02))
        let result = await Task.detached { () -> Bool in
            do {
                _ = try NativeShellPrimaryGate().acquire(source: source, sessionID: UUID(), trusted: true,
                    methods: ["password"], token: token, lifetime: CancellationToken(), budget: budget, tasks: tasks)
                return false
            } catch { return true }
        }.value
        XCTAssertTrue(result); tasks.revoke(); tasks.seal(); tasks.markNativeClosed()
        let pending = await tasks.drain(timeout: 0.02)
        XCTAssertFalse(pending.drained); XCTAssertEqual(pending.pendingProviders, 1); XCTAssertTrue(pending.revoked)
        release.release()
        let drained = await tasks.drain(timeout: 1)
        XCTAssertTrue(drained.drained); XCTAssertEqual(drained.pendingProviders, 0)
    }
    func testProviderCanWaitLongerThanNetworkButNotInteractionBudget() throws {
        let source = NativeShellAuthenticationSource(method: .password, provider: { _ in
            try await Task.sleep(for: .milliseconds(45)); return .password(Data())
        }, keyboard: nil)
        let material = try NativeShellPrimaryGate().acquire(source: source, sessionID: UUID(), trusted: true, methods: ["password"],
            token: CancellationToken(), lifetime: CancellationToken(),
            budget: NativeShellAuthenticationBudget(options: options(network: 0.01, interaction: 0.3, overall: 0.5)))
        guard case .password = material else { return XCTFail("typed password") }
        let token = CancellationToken()
        XCTAssertThrowsError(try NativeShellPrimaryGate().acquire(source: source, sessionID: UUID(), trusted: true, methods: ["password"],
            token: token, lifetime: CancellationToken(),
            budget: NativeShellAuthenticationBudget(options: options(network: 1, interaction: 0.01, overall: 0.5))))
        XCTAssertTrue(token.isCancelled)
    }
    func testActualSilentHandshakeNeverCallsProvider() async throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options(network: 0.02))
        let calls = ReadinessCounter()
        let source = NativeShellAuthenticationSource(method: .password, provider: { _ in calls.increment(); return .password(Data()) }, keyboard: nil)
        do {
            try await session.establish(identity: ServerIdentity(host: "offline.invalid", port: 22), username: Data("fixture".utf8),
                source: source, hostKeyHandler: nil, token: CancellationToken())
            XCTFail("silent peer cannot handshake")
        } catch let error as NativeShellError { XCTAssertEqual(error.kind, .timeout) }
        XCTAssertEqual(calls.count, 0); await session.close()
    }
    func testReplyCancelWakesSingleWaiterAndRejectsResolvedAndLateAnswer() async throws {
        let reply = ChallengeReply<[Data]>(), token = CancellationToken()
        let waiter = Task.detached { try reply.wait(token: token, deadline: Date().addingTimeInterval(2)) }
        token.cancel(); reply.cancel()
        do { _ = try await waiter.value; XCTFail("cancelled") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        XCTAssertFalse(reply.resolve([]))
        let resolved = ChallengeReply<Bool>(); XCTAssertTrue(resolved.resolve(true)); resolved.cancel()
        XCTAssertThrowsError(try resolved.wait(token: CancellationToken(), deadline: Date().addingTimeInterval(1)))
        XCTAssertFalse(resolved.resolve(true))
    }
    func testZeroPromptCancellationIsNotEmptySuccessfulAnswer() throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let native = try XCTUnwrap(rf_connection_create(fds[0])); defer { rf_connection_destroy(native) }
        let token = CancellationToken(), replies = ReadinessReplyBox<[Data]>()
        let owner = NativeShellKeyboardOwner(connection: native, handler: { _, reply in
            replies.store(reply); token.cancel(); reply.cancel()
        }, token: token, lifetime: CancellationToken(), authenticationBudget: NativeShellAuthenticationBudget(options: try options()))
        XCTAssertEqual(owner.answer(name: nil, nameLength: 0, instruction: nil, instructionLength: 0,
            count: 0, prompts: nil, responses: nil), -1)
        XCTAssertTrue(token.isCancelled); XCTAssertFalse(try XCTUnwrap(replies.value).resolve([]))
        let success = NativeShellKeyboardOwner(connection: native, handler: { challenge, reply in
            XCTAssertTrue(challenge.prompts.isEmpty); reply.resolve([])
        }, token: CancellationToken(), lifetime: CancellationToken(), authenticationBudget: NativeShellAuthenticationBudget(options: try options()))
        XCTAssertEqual(success.answer(name: nil, nameLength: 0, instruction: nil, instructionLength: 0,
            count: 0, prompts: nil, responses: nil), 0)
    }
    func testLivenessSinglePendingDeadlineCannotBeResetByOrdinaryActivity() throws {
        let now = ContinuousClock.now, policy = try NativeShellLivenessCandidate(interval: 2, maxUnresponsivePeriods: 3)
        var state = NativeShellLivenessState(policy: policy, now: now)
        XCTAssertFalse(state.beginIfDue(now: now.advanced(by: .seconds(1))))
        XCTAssertTrue(state.beginIfDue(now: now.advanced(by: .seconds(2))))
        XCTAssertEqual(state.deadline, now.advanced(by: .seconds(8)))
        for offset in 3...7 {
            state.applicationRead(now: now.advanced(by: .seconds(offset)))
            XCTAssertFalse(state.beginIfDue(now: now.advanced(by: .seconds(offset))))
        }
        XCTAssertEqual(state.facts.probesStarted, 1); XCTAssertEqual(state.facts.helperChannels, 0)
        XCTAssertThrowsError(try state.checkDeadline(now: now.advanced(by: .seconds(8)))) {
            XCTAssertEqual(($0 as? NativeShellError)?.operation, "ssh-round-trip")
        }
        state.disposed(); XCTAssertFalse(state.facts.pending); XCTAssertEqual(state.facts.helperChannels, 0)
    }
    func testLivenessRemoteRejectionIsAliveAndSuccessRequiresCloseFree() throws {
        let now = ContinuousClock.now, policy = try NativeShellLivenessCandidate(interval: 1, maxUnresponsivePeriods: 2)
        var state = NativeShellLivenessState(policy: policy, now: now)
        XCTAssertTrue(state.beginIfDue(now: now.advanced(by: .seconds(1))))
        state.rejected(now: now.advanced(by: .seconds(1.1)))
        XCTAssertEqual(state.facts.remoteRejections, 1); XCTAssertEqual(state.phase, .idle)
        XCTAssertFalse(state.beginIfDue(now: now.advanced(by: .seconds(2))))
        XCTAssertTrue(state.beginIfDue(now: now.advanced(by: .seconds(2.1))))
        state.confirmed(cleanupTimeout: 1, now: now.advanced(by: .seconds(2.2)))
        XCTAssertEqual(state.facts.helperChannels, 1); XCTAssertTrue(state.facts.pending)
        XCTAssertFalse(state.beginIfDue(now: now.advanced(by: .seconds(3))))
        state.closed(); state.freed(now: now.advanced(by: .seconds(2.4)))
        XCTAssertEqual(state.facts.confirmations, 1); XCTAssertEqual(state.facts.helpersFreed, 1)
        XCTAssertEqual(state.facts.helperChannels, 0); XCTAssertFalse(state.facts.pending)
    }
    func testFixedNativeErrorOriginRejectsLocalChannelFailureAndUnknownMessages() {
        for message in ["Channel open failure", "Channel open failure (resource shortage)",
                        "Channel open failure (administratively prohibited)", "Channel open failure (connect failed)",
                        "Channel open failure (unknown channel type)"] {
            message.withCString { XCTAssertEqual(rf_shell_probe_rejection_is_reply(-21, $0, message.utf8.count), 1) }
        }
        for message in ["Unexpected error", "Unable to send channel-open request", "Channel open failure extra", "", "remote text"] {
            message.withCString { XCTAssertEqual(rf_shell_probe_rejection_is_reply(-21, $0, message.utf8.count), 0) }
        }
        "Channel open failure".withCString { XCTAssertEqual(rf_shell_probe_rejection_is_reply(-7, $0, 20), 0) }
    }
    func testNewBridgeCallsBeforeTrustSendNothing() throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let native = try XCTUnwrap(rf_connection_create(fds[0])); defer { rf_connection_destroy(native) }
        let token = CancellationToken()
        XCTAssertEqual(rf_shell_packet_read_timeout(native, 302), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_probe_open_step(native, token.native), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_probe_close_step(native, token.native), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_probe_free_step(native, token.native), Int32(RF_UNTRUSTED))
        var bytes = [UInt8](repeating: 0, count: 32)
        XCTAssertEqual(recv(fds[1], &bytes, bytes.count, MSG_DONTWAIT), -1); XCTAssertEqual(errno, EAGAIN)
    }
}
