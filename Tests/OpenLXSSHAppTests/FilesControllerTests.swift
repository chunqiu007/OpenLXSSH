import Combine
import Darwin
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTrust

@MainActor final class FilesControllerTests: XCTestCase {
    private func root() throws -> URL {
        let url = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: url) }
        return url
    }
    private func host() -> HostConfiguration { .init(name: "Local Files fixture (not SFTP)", address: "never-connected.invalid", username: "fixture") }
    private func input() -> FilesConnectInput { .init(primary: .manual(.init(utf8: UUID().uuidString))) }
    private func local() throws -> (URL, LocalFilesTestConnector, FilesController) {
        let root = try root(); let connector = LocalFilesTestConnector(root: root)
        return (root, connector, FilesController(connector: connector, idleTimeout: nil))
    }
    private func connect(_ model: FilesController) async {
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
    }
    func testStartsHiddenAndRepeatedShowDoesNotConnect() async throws {
        let (_, connector, model) = try local()
        XCTAssertFalse(model.visible)
        XCTAssertEqual(awaited: await connector.count, 0)
        model.show(host: host()); model.show(host: host()); model.hide(); model.show(host: host())
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(awaited: await connector.count, 0)
        model.connect(input()); model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(awaited: await connector.count, 1)
        model.hide(); XCTAssertEqual(model.state, .ready)
        await model.closeForWindow(); XCTAssertFalse(model.visible)
    }
    func testLocalRawNameBrowseGoMkdirRenameConflictAndDeletePlanChange() async throws {
        let (root, _, model) = try local()
        let special = "中文 e\u{301} line\nname"
        try FileManager.default.createDirectory(at: root.appendingPathComponent(special), withIntermediateDirectories: false)
        try Data("original".utf8).write(to: root.appendingPathComponent("source"))
        try Data("existing".utf8).write(to: root.appendingPathComponent("existing"))
        await connect(model)
        let firstNames = Set(model.entries.map(\.name.bytes))
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(Set(model.entries.map(\.name.bytes)), firstNames)
        let entry = try XCTUnwrap(model.entries.first { $0.name.bytes == Data(special.utf8) })
        model.enter(entry); await model.waitUntilCurrentWorkCompletes()
        let raw = try RemotePath.root.appending(entry.name)
        XCTAssertEqual(model.path.bytes, raw.bytes)
        XCTAssertTrue(FileDisplay.path(raw).contains("\\n")) // escaped display is never re-parsed
        model.go(manualUTF8: ""); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.path.bytes, raw.bytes)
        model.mkdir(try FileName("created"), acknowledgedRemoteRisk: true); await model.waitUntilCurrentWorkCompletes()
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent(special).appendingPathComponent("created").path))
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        let source = try XCTUnwrap(model.entries.first { $0.name == (try? FileName("source")) })
        model.rename(source, name: try FileName("existing"), conflict: .fail); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.issue?.code, "files.conflict")
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("existing")), Data("existing".utf8))
        model.rename(source, name: try FileName("renamed"), conflict: .fail); await model.waitUntilCurrentWorkCompletes()
        let renamed = try XCTUnwrap(model.entries.first { $0.name == (try? FileName("renamed")) })
        model.prepareDelete(renamed, removeLinkOnly: false); await model.waitUntilCurrentWorkCompletes()
        let review = try XCTUnwrap(model.deleteReview)
        XCTAssertEqual(review.plan.items.count, 1)
        try Data("changed-after-plan".utf8).write(to: root.appendingPathComponent("renamed"))
        model.executeDelete(review, confirmed: true); await model.waitUntilCurrentWorkCompletes()
        XCTAssertFalse(try XCTUnwrap(model.lastDeleteReport).allSucceeded)
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent("renamed").path))
        await model.closeForWindow()
    }
    func testSymbolicLinkDoesNotEnterAndOnlyLinkDeleteIsExplicit() async throws {
        let (root, _, model) = try local()
        try Data("keep".utf8).write(to: root.appendingPathComponent("target"))
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("link"), withDestinationURL: root.appendingPathComponent("target"))
        await connect(model)
        let link = try XCTUnwrap(model.entries.first { $0.attributes.kind == .symbolicLink })
        model.enter(link); XCTAssertEqual(model.issue?.code, "files.symbolicLink")
        model.prepareDelete(link, removeLinkOnly: false); await model.waitUntilCurrentWorkCompletes()
        XCTAssertFalse(try XCTUnwrap(model.deleteReview).plan.canExecute)
        model.discardDeleteReview()
        model.prepareDelete(link, removeLinkOnly: true); await model.waitUntilCurrentWorkCompletes()
        let review = try XCTUnwrap(model.deleteReview)
        model.executeDelete(review, confirmed: true); await model.waitUntilCurrentWorkCompletes()
        XCTAssertTrue(try XCTUnwrap(model.lastDeleteReport).allSucceeded)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("target")), Data("keep".utf8))
        await model.closeForWindow()
    }
    func testSameIDHostEditOnlyManualReconnectUsesNewSnapshot() async throws {
        let (_, connector, model) = try local()
        await connect(model)
        var edited = try XCTUnwrap(model.selectedHost); edited.port = 2228; edited.username = "changed"
        model.show(host: edited); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(awaited: await connector.count, 1)
        XCTAssertEqual(model.state, .ready)
        XCTAssertEqual(model.issue?.code, "files.hostChanged")
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.selectedHost, edited)
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(awaited: await connector.lastHost?.port, 2228)
        XCTAssertEqual(awaited: await connector.lastHost?.username, "changed")
        await model.closeForWindow()
    }
    func testWindowCloseCancelsPreparationAndReopenCreatesFreshManager() async throws {
        let root = try root(), pause = FilesTestPause()
        let connector = LocalFilesTestConnector(root: root, pause: pause)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        let previous = model.manager
        await pause.arm(); model.connect(input()); await pause.waitForArrival()
        let started = FilesTestEvent()
        let close = Task { started.signal(); await model.closeForWindow() }
        await started.wait(); await pause.release(); await close.value
        XCTAssertFalse(model.visible); XCTAssertNil(model.selectedHost)
        XCTAssertEqual(model.state, .disconnected)
        XCTAssertFalse(previous === model.manager)
        let previousSnapshot = await previous.snapshot()
        XCTAssertTrue(previousSnapshot.isClosed)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
        await model.closeForWindow()
    }
    func testOverwriteRequiresExplicitRiskAndBoundProbeOnlyCreatesApprovedOwnDirectory() async throws {
        let root = try root()
        try Data("source-data".utf8).write(to: root.appendingPathComponent("source"))
        try Data("target-data".utf8).write(to: root.appendingPathComponent("target"))
        let service = try BoundLocalFilesService(root: root), model = FilesController(connector: FixedFilesConnector(service: service), idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes(); model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        let source = try XCTUnwrap(model.entries.first { $0.name.bytes == Data("source".utf8) })
        let rejectedRisk = Task { @MainActor in await self.nextRisk(model) }
        await Task.yield(); model.rename(source, name: try FileName("target"), conflict: .overwrite)
        let firstID = await rejectedRisk.value
        model.answerRisk(false, id: firstID); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("target")), Data("target-data".utf8))
        let acceptedRisk = Task { @MainActor in await self.nextRisk(model) }
        await Task.yield(); model.rename(source, name: try FileName("target"), conflict: .overwrite)
        let secondID = await acceptedRisk.value
        XCTAssertNotEqual(firstID, secondID)
        model.answerRisk(true, id: firstID) // stale confirmation must not unblock this operation
        XCTAssertEqual(model.riskID, secondID)
        model.answerRisk(true, id: secondID); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("target")), Data("source-data".utf8))
        model.prepareProbe(); await model.waitUntilCurrentWorkCompletes()
        let review = try XCTUnwrap(model.probeReview)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.path + FileDisplay.path(review.plan.temporaryDirectory)))
        model.executeProbe(review, approved: false)
        XCTAssertNil(model.lastProbeResult)
        model.executeProbe(review, approved: true); await model.waitUntilCurrentWorkCompletes()
        XCTAssertTrue(try XCTUnwrap(model.lastProbeResult).passed)
        XCTAssertTrue(try XCTUnwrap(model.lastProbeResult).retainedPaths.isEmpty)
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: root.path)), ["target"])
        await model.closeForWindow()
    }
    private func nextRisk(_ model: FilesController) async -> UUID {
        await withCheckedContinuation { reply in
            var subscription: AnyCancellable?
            subscription = model.$riskID.sink { value in
                guard let value else { return }
                reply.resume(returning: value); subscription?.cancel(); subscription = nil
            }
        }
    }
    func testManagerLeaseKeepsBlockedBrowseAliveAndHostChangeAwaitsOldCleanup() async throws {
        let root = try root(), pause = FilesTestPause()
        let wrapped = try BrowsePauseService(root: root, pause: pause)
        let connector = FixedFilesConnector(service: wrapped)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        await pause.arm(); model.browse(.root); await pause.waitForArrival()
        XCTAssertTrue(model.busy)
        let pending = await model.manager.snapshot()
        XCTAssertFalse(pending.serviceOperations.isEmpty)
        XCTAssertTrue(pending.hasActiveWork)
        XCTAssertFalse(model.hasActiveTransfers)
        await model.manager.closeIdleServices()
        let closesWhileBusy = await wrapped.closeCount
        XCTAssertEqual(closesWhileBusy, 0)
        var next = host(); next.id = UUID()
        model.show(host: next)
        model.connect(input()) // This is queued behind the owned old cleanup, not admitted early.
        let connectBeforeRelease = await connector.count
        XCTAssertEqual(connectBeforeRelease, 1)
        await pause.release(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertFalse(model.busy)
        XCTAssertFalse(model.hasPendingOperations)
        await model.closeForWindow()
    }
    func testSyntheticCallbackCancellationAtWindowCloseDoesNotBecomeTransferDecision() async throws {
        let root = try root(), connector = KeyboardFilesTestConnector(root: root)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        let wait = Task { @MainActor in await self.nextKeyboard(model) }
        await Task.yield(); model.connect(input()); _ = await wait.value
        XCTAssertTrue(model.hasPendingOperations); XCTAssertFalse(model.hasActiveTransfers)
        await model.closeForWindow()
        XCTAssertFalse(model.hasPendingOperations); XCTAssertNil(model.keyboardPrompt); XCTAssertFalse(model.visible)
    }
    func testMultiRoundKeyboardAndZeroPromptRemainBoundAndSingleAnswer() async throws {
        let root = try root(), connector = ScriptedFilesConnector(root: root, script: .keyboard)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        let firstWait = Task { @MainActor in await self.nextKeyboard(model) }
        await Task.yield()
        model.connect(input())
        let first = await firstWait.value
        XCTAssertEqual(first.prompts.count, 2)
        XCTAssertFalse(first.prompts[0].echo); XCTAssertTrue(first.prompts[1].echo)
        XCTAssertTrue(first.instruction.contains("\\u{001B}"))
        model.hide(); XCTAssertNotNil(model.keyboardPrompt)
        let zeroWait = Task { @MainActor in await self.nextKeyboard(model, excluding: first.id) }
        await Task.yield()
        XCTAssertFalse(model.answerKeyboard(first, answers: [.init(utf8: "wrong-count")]))
        XCTAssertTrue(model.answerKeyboard(first, answers: [.init(utf8: "one"), .init(utf8: "two")]))
        XCTAssertFalse(model.answerKeyboard(first, answers: [.init(utf8: "one"), .init(utf8: "two")]))
        await connector.advanceRound()
        let zero = await zeroWait.value
        XCTAssertTrue(zero.prompts.isEmpty)
        XCTAssertTrue(model.answerKeyboard(zero, answers: []))
        await connector.advanceRound()
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
        let resolved = await connector.repliesAlreadyResolved
        XCTAssertEqual(resolved, [true, true])
        await model.closeForWindow()
    }
    func testSyntheticTrustRequiresExplicitFingerprintAndChangedIsRejected() async throws {
        let root = try root(), connector = ScriptedFilesConnector(root: root, script: .trust)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        let promptWait = Task { @MainActor in await self.nextTrust(model) }
        await Task.yield(); model.connect(input())
        let prompt = await promptWait.value
        XCTAssertFalse(model.answerTrust(prompt, verified: false))
        XCTAssertTrue(model.answerTrust(prompt, verified: true))
        XCTAssertFalse(model.answerTrust(prompt, verified: true))
        await connector.advanceRound()
        await model.waitUntilCurrentWorkCompletes(); XCTAssertEqual(model.state, .ready)
        await model.closeForWindow()
        let changedConnector = ScriptedFilesConnector(root: root, script: .changed)
        let changed = FilesController(connector: changedConnector, idleTimeout: nil)
        changed.show(host: host()); await changed.waitUntilCurrentWorkCompletes()
        changed.connect(input()); await changed.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(changed.state, .failed)
        XCTAssertEqual(changed.issue?.code, "files.untrusted")
        if let prompt = changed.trustPrompt { XCTAssertFalse(changed.answerTrust(prompt, verified: true)) }
        await changed.closeForWindow()
    }
    private func nextKeyboard(_ model: FilesController, excluding: UUID? = nil) async -> FilesKeyboardPrompt {
        await withCheckedContinuation { reply in
            var subscription: AnyCancellable?
            subscription = model.$keyboardPrompt.sink { value in
                guard let value, value.id != excluding else { return }
                reply.resume(returning: value); subscription?.cancel(); subscription = nil
            }
        }
    }
    private func nextTrust(_ model: FilesController) async -> FilesTrustPrompt {
        await withCheckedContinuation { reply in
            var subscription: AnyCancellable?
            subscription = model.$trustPrompt.sink { value in
                guard let value else { return }
                reply.resume(returning: value); subscription?.cancel(); subscription = nil
            }
        }
    }
    func testCallbackCancelAndHostSwitchRejectOldKeyboardAnswers() async throws {
        let root = try root(), connector = KeyboardFilesTestConnector(root: root)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        await withCheckedContinuation { (arrived: CheckedContinuation<Void, Never>) in
            var subscription: AnyCancellable?
            subscription = model.$keyboardPrompt.sink { prompt in
                guard prompt != nil else { return }
                arrived.resume(); subscription?.cancel(); subscription = nil
            }
            model.connect(input())
        }
        let old = try XCTUnwrap(model.keyboardPrompt)
        model.hide(); XCTAssertNotNil(model.keyboardPrompt)
        var next = host(); next.id = UUID(); next.username = "next"
        model.show(host: next)
        XCTAssertFalse(model.answerKeyboard(old, answers: [.init(utf8: UUID().uuidString)]))
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertNil(model.keyboardPrompt)
        await model.closeForWindow()
    }
}

private actor BoundLocalFilesService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    nonisolated let serverBinding: UUID? = UUID()
    let base: LocalFileService
    init(root: URL) throws { base = try LocalFileService(root: root) }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(path, token: token) }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(path, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(path, mode: mode, token: token) }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(handle, maxBytes: maxBytes, token: token) }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(handle, data: data, token: token) }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await base.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await base.closeHandle(handle) }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { try await base.mkdir(path, token: token) }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(source, to: destination, mode: mode, token: token) }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await base.commit(source, to: destination, request: request, token: token) }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(path, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { await base.close() }
}

private actor FixedFilesConnector: FilesConnecting {
    let service: any RemoteFileService
    private(set) var count = 0
    init(service: any RemoteFileService) { self.service = service }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService { count += 1; try token.check(); return service }
}
private actor BrowsePauseService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: LocalFileService
    let pause: FilesTestPause
    private(set) var closeCount = 0
    init(root: URL, pause: FilesTestPause) throws { base = try LocalFileService(root: root); self.pause = pause }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { await pause.suspendIfArmed(); return try await base.list(path, token: token) }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(path, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(path, mode: mode, token: token) }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(handle, maxBytes: maxBytes, token: token) }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(handle, data: data, token: token) }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await base.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await base.closeHandle(handle) }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { try await base.mkdir(path, token: token) }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(source, to: destination, mode: mode, token: token) }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(path, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { closeCount += 1; await base.close() }
}

private actor LocalFilesTestConnector: FilesConnecting {
    let root: URL
    let pause: FilesTestPause?
    private(set) var count = 0
    private(set) var lastHost: HostConfiguration?
    init(root: URL, pause: FilesTestPause? = nil) { self.root = root; self.pause = pause }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        count += 1; lastHost = request.host
        await pause?.suspendIfArmed(); try token.check()
        guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "local-fixture-stale") }
        return try LocalFileService(root: root)
    }
}
private actor FilesTestPause {
    private var armed = false, arrived = false
    private var waiter: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    func arm() { armed = true; arrived = false }
    func suspendIfArmed() async { guard armed else { return }; arrived = true; observer?.resume(); observer = nil; await withCheckedContinuation { waiter = $0 } }
    func waitForArrival() async { if !arrived { await withCheckedContinuation { observer = $0 } } }
    func release() { armed = false; waiter?.resume(); waiter = nil }
}
@MainActor private final class FilesTestEvent {
    private var arrived = false
    private var waiter: CheckedContinuation<Void, Never>?
    func signal() { arrived = true; waiter?.resume(); waiter = nil }
    func wait() async { if !arrived { await withCheckedContinuation { waiter = $0 } } }
}
private actor FilesCallbackEvent {
    private var arrived = false
    private var waiter: CheckedContinuation<Void, Never>?
    func signal() { arrived = true; waiter?.resume(); waiter = nil }
    func wait() async { if !arrived { await withCheckedContinuation { waiter = $0 } } }
}
private actor KeyboardFilesTestConnector: FilesConnecting {
    let root: URL
    let sent = FilesCallbackEvent()
    init(root: URL) { self.root = root }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        let reply = ChallengeReply<[Data]>()
        keyboard(FilesKeyboardChallenge(name: Data("fixture".utf8), instruction: Data("manual only".utf8), prompts: [(Data("unknown".utf8), false)]), reply)
        await sent.signal()
        while !token.isCancelled { try await Task.sleep(for: .milliseconds(5)) }
        throw FileServiceError(.cancelled, operation: "keyboard-fixture")
    }
}
private actor ScriptedFilesConnector: FilesConnecting {
    enum Script { case keyboard, trust, changed }
    let root: URL
    let script: Script
    private(set) var repliesAlreadyResolved: [Bool] = []
    init(root: URL, script: Script) { self.root = root; self.script = script }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        switch script {
        case .keyboard:
            for prompts: [(Data, Bool)] in [[(Data("unknown".utf8), false), (Data("visible".utf8), true)], []] {
                await round.arm()
                let reply = ChallengeReply<[Data]>()
                keyboard(FilesKeyboardChallenge(name: Data("name".utf8), instruction: Data("instruction\u{1B}".utf8), prompts: prompts.map { ($0.0, $0.1) }), reply)
                await round.suspendIfArmed()
                repliesAlreadyResolved.append(!reply.resolve([]))
                try token.check()
            }
        case .trust, .changed:
            let store = try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("trust-fixture").path))
            let identity = HostIdentity(address: try HostAddress(request.host.address), port: try SSHPort(request.host.port))
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg") }.value
            guard case .pending(let decision) = try await store.evaluate(host: identity, key: key) else { throw FileServiceError(.untrusted, operation: "fixture") }
            if script == .trust {
                await round.arm()
                let reply = ChallengeReply<FileHostTrustAnswer>()
                trust(.pending(decision), reply)
                await round.suspendIfArmed()
                repliesAlreadyResolved.append(!reply.resolve(.reject))
                try token.check()
            } else {
                _ = try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
                let next = try await Task.detached { try HostPublicKey(openSSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C") }.value
                if case .rejected(let change) = try await store.evaluate(host: identity, key: next) { trust(.changed(change), ChallengeReply<FileHostTrustAnswer>()) }
                throw FileServiceError(.untrusted, operation: "changed-fixture")
            }
        }
        guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "fixture-stale") }
        return try LocalFileService(root: root)
    }
    private let round = FilesTestPause()
    func advanceRound() async { await round.waitForArrival(); await round.release() }
}

private func XCTAssertEqual<T: Equatable>(awaited value: T, _ expected: T, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertEqual(value, expected, file: file, line: line)
}
