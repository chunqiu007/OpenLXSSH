import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

// All fixtures perform real LocalFileService FD I/O. Hooks control timing/lifetime failures only.
// These tests are NOT SSH/SFTP interoperability or server-capability evidence.
private final class ManagerFixture: @unchecked Sendable {
    let root: URL
    let sourceURL: URL
    let destinationURL: URL
    let source: LocalFileService
    let destination: LocalFileService
    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-Manager-\(UUID().uuidString)")
        sourceURL = root.appendingPathComponent("source"); destinationURL = root.appendingPathComponent("destination")
        try FileManager.default.createDirectory(at: sourceURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: destinationURL, withIntermediateDirectories: true)
        source = try LocalFileService(root: sourceURL); destination = try LocalFileService(root: destinationURL)
    }
    func put(_ path: String, bytes: Data, destination: Bool = false) throws {
        try bytes.write(to: (destination ? destinationURL : sourceURL).appendingPathComponent(path))
    }
    func cleanup() async {
        await source.close(); await destination.close(); try? FileManager.default.removeItem(at: root)
    }
}
private actor ManagerBarrier {
    private(set) var arrived = false
    private var released = false
    func block(_ token: CancellationToken? = nil) async throws {
        arrived = true
        while !released { try token?.check(); try await Task.sleep(for: .milliseconds(2)) }
    }
    func release() { released = true }
}
private actor ManagerFlag {
    private(set) var value = false
    func set() { value = true }
}
private actor ProgressRecorder {
    private(set) var maximum: UInt64 = 0
    private(set) var sawTerminal = false
    var hasProgressAndTerminal: Bool { maximum > 0 && sawTerminal }
    func record(_ snapshot: TransferManagerSnapshot) {
        maximum = max(maximum, snapshot.jobs.map(\.transferredBytes).max() ?? 0)
        sawTerminal = sawTerminal || snapshot.jobs.contains { !$0.state.isActive }
    }
}
private final class ManagedLocalProbe: RemoteFileService, @unchecked Sendable {
    let local: LocalFileService
    let capabilities: FileServiceCapabilities
    let serverBinding: UUID?
    let beforeRead: (@Sendable (CancellationToken) async throws -> Void)?
    let afterWrite: (@Sendable (CancellationToken) async throws -> Void)?
    let beforeCloseHandle: (@Sendable () async -> Void)?
    let beforeClose: (@Sendable () async -> Void)?
    init(_ local: LocalFileService, remotePolicy: Bool = false,
         beforeRead: (@Sendable (CancellationToken) async throws -> Void)? = nil,
         afterWrite: (@Sendable (CancellationToken) async throws -> Void)? = nil,
         beforeCloseHandle: (@Sendable () async -> Void)? = nil, beforeClose: (@Sendable () async -> Void)? = nil) {
        self.local = local; self.beforeRead = beforeRead; self.afterWrite = afterWrite
        self.beforeCloseHandle = beforeCloseHandle; self.beforeClose = beforeClose
        capabilities = remotePolicy ? FileServiceCapabilities(traversal: .remoteComponentLstat, exclusiveCreate: true,
            noReplace: .needsServerConfirmation, canAttemptAtomicReplace: true) : local.capabilities
        serverBinding = remotePolicy ? UUID() : nil
    }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await local.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await local.lstat(p, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await local.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        try await beforeRead?(token); return try await local.read(h, maxBytes: maxBytes, token: token)
    }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        let count = try await local.write(h, data: data, token: token); try await afterWrite?(token); return count
    }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await local.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { await beforeCloseHandle?(); try await local.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await local.mkdir(p, token: token) }
    func commit(_ s: RemotePath, to d: RemotePath, request: CommitRequest, token: CancellationToken) async throws {
        try await local.commit(s, to: d, request: request, token: token)
    }
    func rename(_ s: RemotePath, to d: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await local.rename(s, to: d, mode: mode, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await local.remove(p, directory: directory, token: token) }
    func cancel() { local.cancel() }
    func close() async { await beforeClose?(); await local.close() }
}
private final class WeakManagedService: @unchecked Sendable {
    weak var service: (any RemoteFileService)?
    init(_ service: any RemoteFileService) { self.service = service }
}

final class TransferManagerTests: XCTestCase, @unchecked Sendable {
    private func payload(_ count: Int = 90_123) -> Data { Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 37) }) }
    private func waitUntil(_ condition: @Sendable () async throws -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(8))
        while try await !condition() {
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "manager-test-wait") }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    private func job(_ manager: TransferManager, _ id: TransferJobID,
                     matching predicate: @Sendable (TransferJobSnapshot) -> Bool) async throws -> TransferJobSnapshot {
        try await waitUntil { await manager.snapshot().jobs.contains { $0.id == id && predicate($0) } }
        let snapshot = await manager.snapshot()
        return try XCTUnwrap(snapshot.jobs.first { $0.id == id })
    }
    private func terminal(_ manager: TransferManager, _ id: TransferJobID) async throws -> TransferJobSnapshot {
        try await job(manager, id, matching: { !$0.state.isActive })
    }
    private func pending(_ manager: TransferManager, _ id: TransferJobID,
                         state: TransferJobState = .waitingConflict) async throws -> TransferDecisionRequest {
        let snapshot = try await job(manager, id, matching: { $0.state == state })
        return try XCTUnwrap(snapshot.pendingDecision)
    }
    private func locations(_ manager: TransferManager, _ f: ManagerFixture) async throws -> (TransferServiceID, TransferServiceID) {
        (try await manager.registerService(f.source), try await manager.registerService(f.destination))
    }
    private func request(_ services: (TransferServiceID, TransferServiceID), host: String = "fixture",
                         source: String = "/file", destination: String = "/out", batch: UUID = UUID(),
                         kind: TransferKind = .file) throws -> TransferRequest {
        TransferRequest(hostID: host, batchID: batch, source: TransferLocation(serviceID: services.0, path: try RemotePath(source)),
            destination: TransferLocation(serviceID: services.1, path: try RemotePath(destination)), kind: kind)
    }

    func testBoundedQueueFIFOAndByteProgressThroughMetadataStream() async throws {
        let f = try ManagerFixture(); let bytes = payload(); try f.put("file", bytes: bytes)
        let gate = ManagerBarrier(), progress = ProgressRecorder()
        let source = ManagedLocalProbe(f.source, beforeRead: { token in
            try await gate.block(token); try await Task.sleep(for: .milliseconds(1))
        })
        let manager = TransferManager(engine: SafeTransferEngine(chunkSize: 4096), maxConcurrentJobs: 1, maxQueuedJobs: 1, idleTimeout: nil)
        let ids = (try await manager.registerService(source, hostID: "fixture"), try await manager.registerService(f.destination))
        let stream = try await manager.updates()
        let observation = Task { for await snapshot in stream { await progress.record(snapshot) } }
        let first = try await manager.enqueue(request(ids, destination: "/first"))
        try await waitUntil { await gate.arrived }
        let second = try await manager.enqueue(request(ids, destination: "/second"))
        let queued = try await job(manager, second, matching: { $0.state == .queued })
        XCTAssertEqual(queued.transferredBytes, 0); XCTAssertEqual(queued.request.source.serviceID, ids.0)
        do { _ = try await manager.enqueue(request(ids, destination: "/overflow")); XCTFail("Queue must be bounded") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .resourceLimit) }
        let active = await manager.hasActiveWork; XCTAssertTrue(active)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.destinationURL.appendingPathComponent("second").path))
        await gate.release()
        let a = try await terminal(manager, first), b = try await terminal(manager, second)
        XCTAssertEqual(a.state, .succeeded); XCTAssertEqual(b.state, .succeeded)
        XCTAssertEqual(a.transferredBytes, UInt64(bytes.count)); XCTAssertEqual(b.transferredBytes, UInt64(bytes.count))
        XCTAssertEqual(SHA256.hash(data: try Data(contentsOf: f.destinationURL.appendingPathComponent("second"))), SHA256.hash(data: bytes))
        try await waitUntil { await progress.hasProgressAndTerminal }
        observation.cancel(); await manager.cancelAllAndWait()
        let inactive = await manager.hasActiveWork; XCTAssertFalse(inactive)
        await f.cleanup()
    }

    func testQueuedAndRunningCancellationWaitForCleanupAndActualServiceClose() async throws {
        let f = try ManagerFixture(); try f.put("file", bytes: payload())
        let read = ManagerBarrier(), handle = ManagerBarrier(), close = ManagerBarrier(), finished = ManagerFlag()
        let source = ManagedLocalProbe(f.source, beforeRead: { try await read.block($0) },
            beforeCloseHandle: { try? await handle.block() }, beforeClose: { try? await close.block() })
        let manager = TransferManager(maxConcurrentJobs: 1, idleTimeout: nil)
        let ids = (try await manager.registerService(source), try await manager.registerService(f.destination))
        let first = try await manager.enqueue(request(ids)), second = try await manager.enqueue(request(ids, destination: "/queued"))
        try await waitUntil { await read.arrived }
        let queuedCancelled = await manager.cancel(second); XCTAssertTrue(queuedCancelled)
        let secondResult = try await terminal(manager, second); XCTAssertEqual(secondResult.state, .cancelled)
        let runningCancelled = await manager.cancel(first); XCTAssertTrue(runningCancelled)
        try await waitUntil { await handle.arrived }
        let stillActive = await manager.hasActiveWork; XCTAssertTrue(stillActive)
        let shutdown = Task { await manager.cancelAllAndWait(); await finished.set() }
        try await Task.sleep(for: .milliseconds(15))
        let early = await finished.value; XCTAssertFalse(early)
        await handle.release()
        try await waitUntil { await close.arrived }
        let beforeClose = await finished.value; XCTAssertFalse(beforeClose)
        await close.release(); await shutdown.value
        let firstResult = try await terminal(manager, first)
        XCTAssertEqual(firstResult.state, .cancelled); XCTAssertEqual(firstResult.error?.kind, .cancelled)
        XCTAssertTrue(firstResult.retainedTemporaryPaths.isEmpty)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: f.destinationURL.path).isEmpty)
        do { _ = try await f.source.list(.root, token: CancellationToken()); XCTFail("Service must really be closed") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        await manager.cancelAllAndWait()
        do { _ = try await manager.enqueue(request(ids)); XCTFail("Shutdown must stop admission") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        await f.cleanup()
    }

    func testSkipAppliesOnlyToCurrentBatchAndLateAnswersAreRejected() async throws {
        let f = try ManagerFixture(); try f.put("file", bytes: payload(100))
        for name in ["a", "b", "c"] { try f.put(name, bytes: Data(name.utf8), destination: true) }
        let manager = TransferManager(maxConcurrentJobs: 2, idleTimeout: nil), batch = UUID()
        let services = try await locations(manager, f)
        let ids = try await manager.enqueueBatch([request(services, destination: "/a", batch: batch), request(services, destination: "/b", batch: batch)])
        let decision = try await pending(manager, ids[0])
        let wrongType = await manager.resolve(decision, answer: .risk(accepted: true)); XCTAssertFalse(wrongType)
        let stale = TransferDecisionRequest(id: decision.id, jobID: decision.jobID, generation: UUID(), question: decision.question)
        let oldGeneration = await manager.resolve(stale, answer: .conflict(.overwrite, applyToBatch: true)); XCTAssertFalse(oldGeneration)
        let accepted = await manager.resolve(decision, answer: .conflict(.skip, applyToBatch: true)); XCTAssertTrue(accepted)
        let duplicate = await manager.resolve(decision, answer: .conflict(.overwrite, applyToBatch: true)); XCTAssertFalse(duplicate)
        for id in ids {
            let item = try await terminal(manager, id)
            XCTAssertEqual(item.state, .skipped); XCTAssertFalse(item.state.isActive)
            XCTAssertTrue(item.items.allSatisfy { $0.state == .skipped }); XCTAssertEqual(item.transferredBytes, 0)
        }
        let activeAfterSkips = await manager.hasActiveWork; XCTAssertFalse(activeAfterSkips)
        let skippedSnapshot = await manager.snapshot(); XCTAssertFalse(skippedSnapshot.hasActiveWork)
        let other = try await manager.enqueue(request(services, destination: "/c"))
        let otherDecision = try await pending(manager, other)
        let cancelled = await manager.cancel(other); XCTAssertTrue(cancelled)
        let late = await manager.resolve(otherDecision, answer: .conflict(.overwrite, applyToBatch: true)); XCTAssertFalse(late)
        let result = try await terminal(manager, other); XCTAssertEqual(result.state, .cancelled)
        for name in ["a", "b", "c"] { XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent(name)), Data(name.utf8)) }
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testSameBatchIDDoesNotShareDecisionsOrServicesAcrossHosts() async throws {
        let f = try ManagerFixture(), g = try ManagerFixture()
        try f.put("file", bytes: payload(44)); try g.put("file", bytes: payload(55))
        try f.put("out", bytes: Data([1]), destination: true); try g.put("out", bytes: Data([2]), destination: true)
        let manager = TransferManager(idleTimeout: nil), batch = UUID()
        let a = (try await manager.registerService(f.source), try await manager.registerService(f.destination, hostID: "A"))
        let b = (try await manager.registerService(g.source), try await manager.registerService(g.destination, hostID: "B"))
        do { _ = try await manager.enqueue(request(a, host: "B")); XCTFail("A service cannot run as host B") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .conflict); XCTAssertEqual(error.operation, "transfer-service-host-mismatch") }
        let one = try await manager.enqueue(request(a, host: "A", batch: batch))
        let two = try await manager.enqueue(request(b, host: "B", batch: batch))
        let first = try await pending(manager, one), second = try await pending(manager, two)
        let ok = await manager.resolve(first, answer: .conflict(.skip, applyToBatch: true)); XCTAssertTrue(ok)
        let result = try await terminal(manager, one); XCTAssertEqual(result.state, .skipped)
        let waiting = try await job(manager, two, matching: { $0.state == .waitingConflict })
        XCTAssertEqual(waiting.pendingDecision, second)
        let next = await manager.resolve(second, answer: .conflict(.renameTo(try FileName("host-B-copy")), applyToBatch: false)); XCTAssertTrue(next)
        let copied = try await terminal(manager, two); XCTAssertEqual(copied.state, .succeeded)
        XCTAssertEqual(try Data(contentsOf: g.destinationURL.appendingPathComponent("host-B-copy")), payload(55))
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out")), Data([1]))
        await manager.cancelAllAndWait(); await f.cleanup(); await g.cleanup()
    }

    func testBatchOverwriteDoesNotImplicitlyConfirmRiskAndFailurePreservesOriginal() async throws {
        let f = try ManagerFixture(); let bytes = payload(1234); try f.put("file", bytes: bytes)
        for name in ["a", "b"] { try f.put(name, bytes: Data("original".utf8), destination: true) }
        let manager = TransferManager(idleTimeout: nil), batch = UUID(), services = try await locations(manager, f)
        let ids = try await manager.enqueueBatch([request(services, destination: "/a", batch: batch), request(services, destination: "/b", batch: batch)])
        let conflict = try await pending(manager, ids[0])
        let overwrite = await manager.resolve(conflict, answer: .conflict(.overwrite, applyToBatch: true)); XCTAssertTrue(overwrite)
        let risk = try await pending(manager, ids[0], state: .waitingRisk)
        XCTAssertEqual(risk.question, .risk(.overwriteIsAtomicButNotCompareAndSwap(path: try RemotePath("/a"))))
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("a")), Data("original".utf8))
        let rejected = await manager.resolve(risk, answer: .risk(accepted: false)); XCTAssertTrue(rejected)
        let failed = try await terminal(manager, ids[0]); XCTAssertEqual(failed.state, .failed); XCTAssertEqual(failed.error?.kind, .riskRejected)
        // Batch overwrite bypasses only the second conflict question, NOT this second explicit risk.
        let nextRisk = try await pending(manager, ids[1], state: .waitingRisk)
        let approved = await manager.resolve(nextRisk, answer: .risk(accepted: true)); XCTAssertTrue(approved)
        let succeeded = try await terminal(manager, ids[1]); XCTAssertEqual(succeeded.state, .succeeded)
        XCTAssertEqual(succeeded.items.first?.acknowledgedRisks, [.overwriteIsAtomicButNotCompareAndSwap(path: try RemotePath("/b"))])
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("a")), Data("original".utf8))
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("b")), bytes)
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testRenameIsSingleItemAndAnOccupiedAlternateFailsWithoutOverwrite() async throws {
        let f = try ManagerFixture(); try f.put("file", bytes: payload(111))
        for name in ["out", "taken"] { try f.put(name, bytes: Data(name.utf8), destination: true) }
        let manager = TransferManager(idleTimeout: nil), services = try await locations(manager, f)
        let first = try await manager.enqueue(request(services))
        let conflict = try await pending(manager, first)
        let rename = ConflictDecision.renameTo(try FileName("renamed 中文 $"))
        let invalidBatch = await manager.resolve(conflict, answer: .conflict(rename, applyToBatch: true)); XCTAssertFalse(invalidBatch)
        let accepted = await manager.resolve(conflict, answer: .conflict(rename, applyToBatch: false)); XCTAssertTrue(accepted)
        let succeeded = try await terminal(manager, first); XCTAssertEqual(succeeded.state, .succeeded)
        XCTAssertEqual(succeeded.items.first?.destination, try RemotePath("/renamed 中文 $"))
        let next = try await manager.enqueue(request(services))
        let nextConflict = try await pending(manager, next)
        let occupied = await manager.resolve(nextConflict, answer: .conflict(.renameTo(try FileName("taken")), applyToBatch: false)); XCTAssertTrue(occupied)
        let failed = try await terminal(manager, next); XCTAssertEqual(failed.state, .failed); XCTAssertEqual(failed.error?.kind, .conflict)
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out")), Data("out".utf8))
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("taken")), Data("taken".utf8))
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("renamed 中文 $")), payload(111))
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testTreeWithoutFailuresCompletesWithSkipsAndAccurateBytes() async throws {
        let f = try ManagerFixture()
        try FileManager.default.createDirectory(at: f.sourceURL.appendingPathComponent("tree/层 空格"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: f.destinationURL.appendingPathComponent("out/层 空格"), withIntermediateDirectories: true)
        for name in ["甲 '$\n", "乙"] {
            try f.put("tree/层 空格/" + name, bytes: payload(33))
            try f.put("out/层 空格/" + name, bytes: Data("original".utf8), destination: true)
        }
        let manager = TransferManager(engine: SafeTransferEngine(chunkSize: 64), idleTimeout: nil)
        let services = try await locations(manager, f)
        // First reproduce the exact zero-byte case: directory successes plus two skipped files.
        // Then add one new file to prove only actually transferred bytes accumulate.
        for copiedByteCount in [0, 777] {
            if copiedByteCount > 0 { try f.put("tree/new file", bytes: payload(copiedByteCount)) }
            let id = try await manager.enqueue(request(services, source: "/tree", kind: .tree))
            let conflict = try await pending(manager, id)
            let accepted = await manager.resolve(conflict, answer: .conflict(.skip, applyToBatch: true)); XCTAssertTrue(accepted)
            let result = try await terminal(manager, id)
            XCTAssertEqual(result.state, .completedWithSkips); XCTAssertNotEqual(result.state, .succeeded)
            XCTAssertFalse(result.state.isActive); XCTAssertNil(result.error)
            XCTAssertEqual(result.items.filter { $0.state == .skipped }.count, 2)
            XCTAssertTrue(result.items.contains { $0.state == .succeeded(bytes: 0) })
            XCTAssertTrue(result.items.allSatisfy { if case .failed = $0.state { return false }; return true })
            XCTAssertFalse(TransferReport(items: result.items).allSucceeded)
            XCTAssertEqual(result.transferredBytes, UInt64(copiedByteCount))
            let completedBytes = result.items.reduce(UInt64(0)) { total, item in
                if case .succeeded(let bytes) = item.state { return total + bytes }; return total
            }
            XCTAssertEqual(completedBytes, UInt64(copiedByteCount))
            let active = await manager.hasActiveWork; XCTAssertFalse(active)
            let snapshot = await manager.snapshot(); XCTAssertFalse(snapshot.hasActiveWork)
            XCTAssertEqual(snapshot.jobs.first { $0.id == id }?.state, .completedWithSkips)
        }
        for name in ["甲 '$\n", "乙"] {
            XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out/层 空格/" + name)), Data("original".utf8))
        }
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out/new file")), payload(777))
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testTreeConflictResolverReusesBatchPolicyAndReportsSymlinkFailure() async throws {
        let f = try ManagerFixture()
        try FileManager.default.createDirectory(at: f.sourceURL.appendingPathComponent("树/层 空格"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: f.destinationURL.appendingPathComponent("out/层 空格"), withIntermediateDirectories: true)
        for name in ["甲 '$\n", "乙"] {
            try f.put("树/层 空格/" + name, bytes: payload(33))
            try f.put("out/层 空格/" + name, bytes: Data("old".utf8), destination: true)
        }
        XCTAssertEqual(symlink("..", f.sourceURL.appendingPathComponent("树/cycle").path), 0)
        let manager = TransferManager(idleTimeout: nil), services = try await locations(manager, f)
        let id = try await manager.enqueue(request(services, source: "/树", kind: .tree))
        let conflict = try await pending(manager, id)
        let accepted = await manager.resolve(conflict, answer: .conflict(.skip, applyToBatch: true)); XCTAssertTrue(accepted)
        let result = try await terminal(manager, id)
        XCTAssertEqual(result.state, .failed); XCTAssertEqual(result.error?.kind, .symbolicLink)
        XCTAssertEqual(result.items.filter { $0.state == .skipped }.count, 2)
        XCTAssertTrue(result.items.contains { if case .failed(let error) = $0.state { return error.kind == .symbolicLink }; return false })
        XCTAssertEqual(result.transferredBytes, 0); XCTAssertFalse(result.state.isActive)
        let active = await manager.hasActiveWork; XCTAssertFalse(active)
        let snapshot = await manager.snapshot(); XCTAssertFalse(snapshot.hasActiveWork)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.destinationURL.appendingPathComponent("out/cycle").path))
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testTreeRenameRiskRejectionRetainsOnlyPreviouslyAcknowledgedRisks() async throws {
        for acceptFirstAlternateRisk in [false, true] {
            let f = try ManagerFixture()
            try FileManager.default.createDirectory(at: f.sourceURL.appendingPathComponent("tree"), withIntermediateDirectories: true)
            try f.put("tree/file", bytes: payload(44)); try f.put("out", bytes: Data("original".utf8), destination: true)
            let remotePolicyOnly = ManagedLocalProbe(f.destination, remotePolicy: true)
            let manager = TransferManager(idleTimeout: nil)
            let services = (try await manager.registerService(f.source), try await manager.registerService(remotePolicyOnly, hostID: "fixture"))
            let id = try await manager.enqueue(request(services, source: "/tree", kind: .tree))
            let originalRisk = TransferRisk.remotePathChecksAreNotAtomic(path: try RemotePath("/out"))
            let initial = try await pending(manager, id, state: .waitingRisk)
            XCTAssertEqual(initial.question, .risk(originalRisk))
            let initialAccepted = await manager.resolve(initial, answer: .risk(accepted: true)); XCTAssertTrue(initialAccepted)
            let conflict = try await pending(manager, id)
            let renamed = await manager.resolve(conflict, answer: .conflict(.renameTo(try FileName("alternate")), applyToBatch: false))
            XCTAssertTrue(renamed)
            let alternateRisk = TransferRisk.remotePathChecksAreNotAtomic(path: try RemotePath("/alternate"))
            let alternate = try await pending(manager, id, state: .waitingRisk)
            XCTAssertEqual(alternate.question, .risk(alternateRisk))
            let alternateAnswered = await manager.resolve(alternate, answer: .risk(accepted: acceptFirstAlternateRisk)); XCTAssertTrue(alternateAnswered)
            if acceptFirstAlternateRisk {
                // Reservation succeeded; rejection in the recursive alternate walk must not erase
                // either the original acknowledgement or the one made before reservation.
                try await waitUntil {
                    await manager.snapshot().jobs.contains { $0.id == id && $0.pendingDecision?.id != alternate.id && $0.state == .waitingRisk }
                }
                let recursive = try await pending(manager, id, state: .waitingRisk)
                XCTAssertEqual(recursive.question, .risk(alternateRisk))
                let rejected = await manager.resolve(recursive, answer: .risk(accepted: false)); XCTAssertTrue(rejected)
            }
            let result = try await terminal(manager, id)
            XCTAssertEqual(result.state, .failed); XCTAssertEqual(result.error?.kind, .riskRejected)
            XCTAssertEqual(result.items.count, 1)
            XCTAssertEqual(result.items.first?.acknowledgedRisks, acceptFirstAlternateRisk ? [originalRisk, alternateRisk] : [originalRisk])
            XCTAssertEqual(result.transferredBytes, 0)
            let active = await manager.hasActiveWork; XCTAssertFalse(active)
            XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out")), Data("original".utf8))
            await manager.cancelAllAndWait(); await f.cleanup()
        }
    }

    func testFileRenameRiskRejectionAndSkipRetainOriginalAcknowledgement() async throws {
        let f = try ManagerFixture(); try f.put("file", bytes: payload(55)); try f.put("out", bytes: Data("old".utf8), destination: true)
        let remotePolicyOnly = ManagedLocalProbe(f.destination, remotePolicy: true)
        let manager = TransferManager(idleTimeout: nil)
        let services = (try await manager.registerService(f.source), try await manager.registerService(remotePolicyOnly, hostID: "fixture"))
        let originalRisk = TransferRisk.remotePathChecksAreNotAtomic(path: try RemotePath("/out"))
        for decision in [ConflictDecision.renameTo(try FileName("alternate")), .skip] {
            let id = try await manager.enqueue(request(services))
            let initial = try await pending(manager, id, state: .waitingRisk)
            XCTAssertEqual(initial.question, .risk(originalRisk))
            let accepted = await manager.resolve(initial, answer: .risk(accepted: true)); XCTAssertTrue(accepted)
            let conflict = try await pending(manager, id)
            let selected = await manager.resolve(conflict, answer: .conflict(decision, applyToBatch: false)); XCTAssertTrue(selected)
            if case .renameTo = decision {
                let alternate = try await pending(manager, id, state: .waitingRisk)
                XCTAssertEqual(alternate.question, .risk(.remotePathChecksAreNotAtomic(path: try RemotePath("/alternate"))))
                let rejected = await manager.resolve(alternate, answer: .risk(accepted: false)); XCTAssertTrue(rejected)
            }
            let result = try await terminal(manager, id)
            XCTAssertEqual(result.state, decision == .skip ? .skipped : .failed)
            XCTAssertEqual(result.error?.kind, decision == .skip ? nil : .riskRejected)
            XCTAssertEqual(result.items.first?.acknowledgedRisks, [originalRisk])
            XCTAssertEqual(result.transferredBytes, 0)
        }
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out")), Data("old".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.destinationURL.appendingPathComponent("alternate").path))
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testTreeAgainstFileCanRenameRootUsingEngineReservation() async throws {
        let f = try ManagerFixture(); try f.put("out", bytes: Data("original".utf8), destination: true)
        try FileManager.default.createDirectory(at: f.sourceURL.appendingPathComponent("tree"), withIntermediateDirectories: true)
        try f.put("tree/中文 file", bytes: payload(42))
        let manager = TransferManager(idleTimeout: nil), services = try await locations(manager, f)
        let id = try await manager.enqueue(request(services, source: "/tree", kind: .tree))
        let conflict = try await pending(manager, id)
        let accepted = await manager.resolve(conflict, answer: .conflict(.renameTo(try FileName("new tree")), applyToBatch: false)); XCTAssertTrue(accepted)
        let result = try await terminal(manager, id); XCTAssertEqual(result.state, .succeeded)
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("new tree/中文 file")), payload(42))
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out")), Data("original".utf8))
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testRetryUsesNewJobAndGenerationStartsFromZeroAndKeepsOriginalReport() async throws {
        let f = try ManagerFixture(); try f.put("out", bytes: Data("original".utf8), destination: true)
        let manager = TransferManager(idleTimeout: nil), services = try await locations(manager, f)
        let first = try await manager.enqueue(request(services))
        let failed = try await terminal(manager, first)
        XCTAssertEqual(failed.state, .failed); XCTAssertEqual(failed.error?.kind, .notFound)
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out")), Data("original".utf8))
        try f.put("file", bytes: payload(222))
        let retry = try await manager.retry(first); XCTAssertNotEqual(retry, first)
        let retryPending = try await pending(manager, retry)
        let newJob = try await job(manager, retry, matching: { $0.state == .waitingConflict })
        XCTAssertEqual(newJob.retryOf, first); XCTAssertNotEqual(newJob.generation, failed.generation)
        XCTAssertNotEqual(newJob.request.batchID, failed.request.batchID); XCTAssertEqual(newJob.transferredBytes, 0)
        let accepted = await manager.resolve(retryPending, answer: .conflict(.renameTo(try FileName("retried")), applyToBatch: false)); XCTAssertTrue(accepted)
        let succeeded = try await terminal(manager, retry); XCTAssertEqual(succeeded.state, .succeeded)
        let original = try await terminal(manager, first); XCTAssertEqual(original, failed)
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("retried")), payload(222))
        do { _ = try await manager.retry(retry); XCTFail("A succeeded job cannot be retried") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .conflict) }
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testDroppedObservationDoesNotOwnJobsAndIdleReleaseWaitsForNoActiveWork() async throws {
        let f = try ManagerFixture(); try f.put("file", bytes: payload(4444))
        let gate = ManagerBarrier(), closed = ManagerFlag()
        let manager = TransferManager(idleTimeout: .milliseconds(40))
        func attach() async throws -> (TransferServiceID, WeakManagedService) {
            let service = ManagedLocalProbe(f.source, beforeRead: { try await gate.block($0) }, beforeClose: { await closed.set() })
            let weak = WeakManagedService(service)
            return (try await manager.registerService(service), weak)
        }
        let (source, weak) = try await attach()
        let destination = try await manager.registerService(f.destination)
        let id = try await manager.enqueue(request((source, destination)))
        let view = Task { let stream = try await manager.updates(); for await _ in stream { if Task.isCancelled { break } } }
        try await waitUntil { await gate.arrived }
        view.cancel(); _ = try await view.value
        await manager.closeIdleServices()
        try await Task.sleep(for: .milliseconds(70))
        XCTAssertNotNil(weak.service)
        let closedWhileActive = await closed.value; XCTAssertFalse(closedWhileActive)
        let active = await manager.hasActiveWork; XCTAssertTrue(active)
        await gate.release()
        let result = try await terminal(manager, id); XCTAssertEqual(result.state, .succeeded)
        try await waitUntil { await closed.value }
        try await waitUntil { weak.service == nil }
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out")), payload(4444))
        do { _ = try await manager.enqueue(request((source, destination))); XCTFail("No implicit reconnect after idle close") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testCancellationWhileWaitingRiskRejectsLateApprovalAndNewGenerationStaysIndependent() async throws {
        let f = try ManagerFixture(); try f.put("file", bytes: payload(55)); try f.put("out", bytes: Data("old".utf8), destination: true)
        let manager = TransferManager(idleTimeout: nil), services = try await locations(manager, f)
        let id = try await manager.enqueue(request(services))
        let conflict = try await pending(manager, id)
        let selected = await manager.resolve(conflict, answer: .conflict(.overwrite, applyToBatch: false)); XCTAssertTrue(selected)
        let risk = try await pending(manager, id, state: .waitingRisk)
        let cancelled = await manager.cancel(id); XCTAssertTrue(cancelled)
        let late = await manager.resolve(risk, answer: .risk(accepted: true)); XCTAssertFalse(late)
        let result = try await terminal(manager, id); XCTAssertEqual(result.state, .cancelled); XCTAssertEqual(result.error?.kind, .cancelled)
        let retry = try await manager.retry(id)
        let next = try await pending(manager, retry)
        let old = await manager.resolve(conflict, answer: .conflict(.overwrite, applyToBatch: true)); XCTAssertFalse(old)
        let skipped = await manager.resolve(next, answer: .conflict(.skip, applyToBatch: false)); XCTAssertTrue(skipped)
        let retryResult = try await terminal(manager, retry); XCTAssertEqual(retryResult.state, .skipped)
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("out")), Data("old".utf8))
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testUnknownServerCapabilitiesNeverAcquireInventedConfirmation() async throws {
        let f = try ManagerFixture(); try f.put("file", bytes: payload(66))
        let remotePolicyOnly = ManagedLocalProbe(f.destination, remotePolicy: true)
        let manager = TransferManager(idleTimeout: nil)
        do { _ = try await manager.registerService(remotePolicyOnly); XCTFail("Remote-style service needs a host binding") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .conflict) }
        let ids = (try await manager.registerService(f.source), try await manager.registerService(remotePolicyOnly, hostID: "fixture"))
        let mismatched = try ServerCommitConfirmation(serverBinding: UUID(), evidence: "Mismatched local fixture, not SFTP evidence")
        do { _ = try await manager.enqueue(request(ids), serverConfirmation: mismatched); XCTFail("Evidence is service-bound") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .needsCapabilityConfirmation) }
        let id = try await manager.enqueue(request(ids))
        let risk = try await pending(manager, id, state: .waitingRisk)
        let accepted = await manager.resolve(risk, answer: .risk(accepted: true)); XCTAssertTrue(accepted)
        let result = try await terminal(manager, id)
        XCTAssertEqual(result.state, .failed); XCTAssertEqual(result.error?.kind, .needsCapabilityConfirmation)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: f.destinationURL.path).isEmpty)
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testDisconnectedLocalFixtureExposesRetainedTemporaryAndStructuredFailure() async throws {
        let f = try ManagerFixture(); try f.put("file", bytes: payload())
        try f.put("unrelated", bytes: Data("keep".utf8), destination: true)
        let unavailable = ManagedLocalProbe(f.destination, afterWrite: { _ in
            f.destination.cancel()
            throw FileServiceError(.transport, operation: "local-fixture-disconnected-after-write")
        })
        let manager = TransferManager(idleTimeout: nil)
        let services = (try await manager.registerService(f.source), try await manager.registerService(unavailable))
        let id = try await manager.enqueue(request(services))
        let result = try await terminal(manager, id)
        XCTAssertEqual(result.state, .failed); XCTAssertEqual(result.error?.kind, .transport)
        XCTAssertEqual(result.error?.operation, "local-fixture-disconnected-after-write")
        let temp = try XCTUnwrap(result.retainedTemporaryPaths.first)
        XCTAssertTrue(String(decoding: temp.bytes, as: UTF8.self).hasPrefix("/.openlxssh-transfer."))
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.destinationURL.appendingPathComponent(String(decoding: temp.bytes.dropFirst(), as: UTF8.self)).path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.destinationURL.appendingPathComponent("out").path))
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("unrelated")), Data("keep".utf8))
        let removed = await manager.removeFinishedJobs([id]); XCTAssertEqual(removed, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.destinationURL.appendingPathComponent(String(decoding: temp.bytes.dropFirst(), as: UTF8.self)).path))
        await manager.cancelAllAndWait(); await f.cleanup()
    }
}
