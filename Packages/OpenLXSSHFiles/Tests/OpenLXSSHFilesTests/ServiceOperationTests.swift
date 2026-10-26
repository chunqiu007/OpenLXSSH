import Foundation
import XCTest
@testable import OpenLXSSHFiles

// Real LocalFileService I/O with controlled waits only. No SSH/SFTP interoperability claim.
private final class OperationFixture: @unchecked Sendable {
    let root: URL
    let sourceURL: URL
    let destinationURL: URL
    let source: LocalFileService
    let destination: LocalFileService
    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-service-operation-\(UUID().uuidString)")
        sourceURL = root.appendingPathComponent("source"); destinationURL = root.appendingPathComponent("destination")
        try FileManager.default.createDirectory(at: sourceURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: destinationURL, withIntermediateDirectories: true)
        try Data("local-file".utf8).write(to: sourceURL.appendingPathComponent("file"))
        source = try LocalFileService(root: sourceURL); destination = try LocalFileService(root: destinationURL)
    }
    func cleanup() async { await source.close(); await destination.close(); try? FileManager.default.removeItem(at: root) }
}
private actor OperationGate {
    private(set) var arrivals = 0
    private var released = false
    func wait(_ token: CancellationToken? = nil) async throws {
        arrivals += 1
        while !released { try token?.check(); try await Task.sleep(for: .milliseconds(1)) }
    }
    func release() { released = true }
}
private actor OperationCounter {
    private(set) var value = 0
    func increment() { value += 1 }
}
private final class OperationProbe: RemoteFileService, @unchecked Sendable {
    let local: LocalFileService
    let capabilities: FileServiceCapabilities
    let serverBinding: UUID? = UUID() // Local probe-policy fixture only, NOT evidence for a server.
    let beforeList: (@Sendable (CancellationToken) async throws -> Void)?
    let beforeRead: (@Sendable (CancellationToken) async throws -> Void)?
    let beforeClose: (@Sendable () async -> Void)?
    private let lock = NSLock()
    private var cancelCount = 0
    private var closeCount = 0
    init(_ local: LocalFileService, beforeList: (@Sendable (CancellationToken) async throws -> Void)? = nil,
         beforeRead: (@Sendable (CancellationToken) async throws -> Void)? = nil, beforeClose: (@Sendable () async -> Void)? = nil) {
        self.local = local; capabilities = local.capabilities
        self.beforeList = beforeList; self.beforeRead = beforeRead; self.beforeClose = beforeClose
    }
    var cancellations: Int { lock.withLock { cancelCount } }
    var closes: Int { lock.withLock { closeCount } }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        try await beforeList?(token); return try await local.list(p, token: token)
    }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await local.lstat(p, token: token) }
    func fstat(_ h: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await local.fstat(h, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await local.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        try await beforeRead?(token); return try await local.read(h, maxBytes: maxBytes, token: token)
    }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await local.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await local.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await local.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await local.mkdir(p, token: token) }
    func commit(_ s: RemotePath, to d: RemotePath, request: CommitRequest, token: CancellationToken) async throws {
        try await local.commit(s, to: d, request: request, token: token)
    }
    func rename(_ s: RemotePath, to d: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await local.rename(s, to: d, mode: mode, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await local.remove(p, directory: directory, token: token) }
    func cancel() { lock.withLock { cancelCount += 1 }; local.cancel() }
    func close() async { lock.withLock { closeCount += 1 }; await beforeClose?(); await local.close() }
}

final class ServiceOperationTests: XCTestCase, @unchecked Sendable {
    private func waitUntil(_ condition: @Sendable () async throws -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(8))
        while try await !condition() {
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "service-operation-test") }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    private func assertCancelled<T: Sendable>(_ task: Task<T, Error>, file: StaticString = #filePath, line: UInt = #line) async {
        do { _ = try await task.value; XCTFail("Expected cancellation after cleanup", file: file, line: line) }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled, file: file, line: line) }
        catch { XCTFail("Unexpected error: \(error)", file: file, line: line) }
    }

    func testSlowListProtectsServiceFromTwoMillisecondIdleAndExplicitCloseThenReleases() async throws {
        let f = try OperationFixture(), list = OperationGate()
        let probe = OperationProbe(f.source, beforeList: { try await list.wait($0) })
        let manager = TransferManager(idleTimeout: .milliseconds(2))
        let id = try await manager.registerService(probe, hostID: "host")
        let operation = Task { try await manager.withServiceOperation(serviceID: id, hostID: "host") { service, token in
            try await service.list(.root, token: token)
        } }
        try await waitUntil { await list.arrivals == 1 }
        let metadata = await manager.snapshot()
        XCTAssertEqual(metadata.serviceOperations.count, 1); XCTAssertEqual(metadata.serviceOperations.first?.serviceID, id)
        XCTAssertEqual(metadata.serviceOperations.first?.hostID, "host"); XCTAssertTrue(metadata.hasActiveWork)
        XCTAssertTrue(metadata.jobs.isEmpty)
        await manager.closeIdleServices(); try await Task.sleep(for: .milliseconds(15))
        XCTAssertEqual(probe.closes, 0)
        await list.release()
        let entries = try await operation.value; XCTAssertEqual(entries.map(\.name), [try FileName("file")])
        try await waitUntil { probe.closes == 1 }
        let ended = await manager.snapshot(); XCTAssertTrue(ended.serviceOperations.isEmpty); XCTAssertFalse(ended.hasActiveWork)
        do {
            _ = try await manager.withServiceOperation(serviceID: id, hostID: "host") { service, token in try await service.list(.root, token: token) }
            XCTFail("Idle-closed service ID must stay stale")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testCallerCancellationOnlySignalsTokenAndAwaitsCleanupRejectingLateSuccess() async throws {
        let f = try OperationFixture(), running = OperationGate(), cleanup = OperationGate(), returned = OperationCounter()
        let probe = OperationProbe(f.source), manager = TransferManager(idleTimeout: nil)
        let id = try await manager.registerService(probe)
        let task = Task { () throws -> [DirectoryEntry] in
            do {
                let value = try await manager.withServiceOperation(serviceID: id, hostID: "local") { service, token in
                    let entries = try await service.list(.root, token: token)
                    do { try await running.wait(token) } catch {
                        XCTAssertTrue(token.isCancelled); XCTAssertFalse(Task.isCancelled)
                        try await cleanup.wait()
                        return entries // Deliberately late success: the facade must reject it.
                    }
                    return entries
                }
                await returned.increment(); return value
            } catch { await returned.increment(); throw error }
        }
        try await waitUntil { await running.arrivals == 1 }
        task.cancel(); try await waitUntil { await cleanup.arrivals == 1 }
        let active = await manager.snapshot()
        XCTAssertEqual(active.serviceOperations.count, 1); XCTAssertEqual(active.serviceOperations.first?.cancellationRequested, true)
        XCTAssertTrue(active.hasActiveWork)
        await manager.closeIdleServices(); XCTAssertEqual(probe.closes, 0); XCTAssertEqual(probe.cancellations, 0)
        let early = await returned.value; XCTAssertEqual(early, 0)
        await cleanup.release(); await assertCancelled(task)
        let finished = await manager.snapshot(); XCTAssertTrue(finished.serviceOperations.isEmpty); XCTAssertFalse(finished.hasActiveWork)
        let next = try await manager.withServiceOperation(serviceID: id, hostID: "local") { service, token in try await service.list(.root, token: token) }
        XCTAssertEqual(next.count, 1); XCTAssertEqual(probe.cancellations, 0)
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testConcurrentShutdownWaitsForOperationCleanupAndActualSingleServiceClose() async throws {
        let f = try OperationFixture(), running = OperationGate(), cleanup = OperationGate(), close = OperationGate(), returns = OperationCounter()
        let probe = OperationProbe(f.source, beforeClose: { try? await close.wait() })
        let manager = TransferManager(idleTimeout: nil), id = try await manager.registerService(probe)
        let operation = Task { try await manager.withServiceOperation(serviceID: id, hostID: "local") { service, token in
            _ = try await service.list(.root, token: token)
            do { try await running.wait(token) } catch { try await cleanup.wait(); throw error }
        } }
        try await waitUntil { await running.arrivals == 1 }
        let first = Task { await manager.cancelAllAndWait(); await returns.increment() }
        try await waitUntil { await cleanup.arrivals == 1 }
        let second = Task { await manager.cancelAllAndWait(); await returns.increment() }
        first.cancel() // Cancellation of the close caller must not cancel the shared drain.
        try await Task.sleep(for: .milliseconds(10))
        let early = await returns.value; XCTAssertEqual(early, 0)
        let shuttingDown = await manager.snapshot(); XCTAssertTrue(shuttingDown.isClosed); XCTAssertTrue(shuttingDown.hasActiveWork)
        XCTAssertEqual(probe.closes, 0); XCTAssertEqual(probe.cancellations, 0)
        await cleanup.release(); try await waitUntil { await close.arrivals == 1 }
        let beforeActualClose = await returns.value; XCTAssertEqual(beforeActualClose, 0)
        XCTAssertEqual(probe.closes, 1)
        await close.release(); await first.value; await second.value; await assertCancelled(operation)
        await manager.cancelAllAndWait(); XCTAssertEqual(probe.closes, 1)
        let ended = await manager.snapshot(); XCTAssertTrue(ended.isClosed); XCTAssertFalse(ended.hasActiveWork)
        do {
            _ = try await manager.withServiceOperation(serviceID: id, hostID: "local") { service, token in try await service.list(.root, token: token) }
            XCTFail("Shutdown must stop admission")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        do { _ = try await f.source.list(.root, token: CancellationToken()); XCTFail("Actual service close must finish") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        await f.cleanup()
    }

    func testOperationBoundUnknownHostMismatchErrorsAndReentryDoNotLeakUsers() async throws {
        let compatibleSnapshot = TransferManagerSnapshot(jobs: [], isClosed: false)
        XCTAssertTrue(compatibleSnapshot.serviceOperations.isEmpty); XCTAssertFalse(compatibleSnapshot.hasActiveWork)
        let f = try OperationFixture(), gate = OperationGate(), manager = TransferManager(idleTimeout: nil, maxServiceOperations: 2)
        let probe = OperationProbe(f.source), id = try await manager.registerService(probe, hostID: "host")
        for (serviceID, host, expected) in [(UUID(), "host", FileServiceError.Kind.closed), (id, "other", .conflict)] {
            do {
                _ = try await manager.withServiceOperation(serviceID: serviceID, hostID: host) { _, _ in XCTFail("Invalid operation ran") }
                XCTFail("Expected rejected admission")
            } catch let error as FileServiceError { XCTAssertEqual(error.kind, expected) }
        }
        let first = Task { try await manager.withServiceOperation(serviceID: id, hostID: "host", scheduling: .callerScheduled) { _, _ in try await gate.wait() } }
        let second = Task { try await manager.withServiceOperation(serviceID: id, hostID: "host", scheduling: .callerScheduled) { _, _ in try await gate.wait() } }
        try await waitUntil { await gate.arrivals == 2 }
        do {
            _ = try await manager.withServiceOperation(serviceID: id, hostID: "host") { _, _ in XCTFail("Overflow operation ran") }
            XCTFail("Operation count must be bounded")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .resourceLimit) }
        await gate.release(); try await first.value; try await second.value
        do {
            _ = try await manager.withServiceOperation(serviceID: id, hostID: "host") { service, token in
                _ = try await service.list(RemotePath("/missing"), token: token)
            }
            XCTFail("Local list error must propagate")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .notFound) }
        try await manager.withServiceOperation(serviceID: id, hostID: "host") { service, token in
            let snapshot = await manager.snapshot(); XCTAssertEqual(snapshot.serviceOperations.count, 1)
            await manager.closeIdleServices(); XCTAssertEqual(probe.closes, 0)
            do {
                _ = try await manager.withServiceOperation(serviceID: id, hostID: "host", scheduling: .callerScheduled) { _, _ in XCTFail("Nested operation ran") }
                XCTFail("Same-manager nesting must be rejected instead of deadlocking")
            } catch let error as FileServiceError { XCTAssertEqual(error.kind, .conflict); XCTAssertEqual(error.operation, "nested-service-operation") }
            _ = try await service.list(.root, token: token)
        }
        let snapshot = await manager.snapshot(); XCTAssertTrue(snapshot.serviceOperations.isEmpty)
        await manager.closeIdleServices(); XCTAssertEqual(probe.closes, 1)
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testClosingServiceRejectsOperationAndStaleIDsCannotAffectNewService() async throws {
        let f = try OperationFixture(), close = OperationGate()
        let manager = TransferManager(idleTimeout: nil), probe = OperationProbe(f.source, beforeClose: { try? await close.wait() })
        let oldID = try await manager.registerService(probe)
        let closing = Task { await manager.closeIdleServices() }
        try await waitUntil { await close.arrivals == 1 }
        do {
            _ = try await manager.withServiceOperation(serviceID: oldID, hostID: "local") { _, _ in XCTFail("Closing operation ran") }
            XCTFail("Closing service must reject")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        await close.release(); await closing.value
        let freshID = try await manager.registerService(f.destination)
        XCTAssertNotEqual(freshID, oldID)
        do {
            _ = try await manager.withServiceOperation(serviceID: oldID, hostID: "local") { _, _ in XCTFail("Stale operation ran") }
            XCTFail("Closed ID must not alias another service")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        try await manager.withServiceOperation(serviceID: freshID, hostID: "local") { service, token in try await service.mkdir(RemotePath("/new"), token: token) }
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testSerializedOperationSharesEngineHostGateButOtherHostCanProceed() async throws {
        let f = try OperationFixture(), reading = OperationGate(), list = OperationGate()
        let scheduler = TransferScheduler(maxConcurrentChunks: 2), probe = OperationProbe(f.source, beforeList: { try await list.wait($0) }, beforeRead: { try await reading.wait($0) })
        let manager = TransferManager(engine: SafeTransferEngine(scheduler: scheduler), idleTimeout: nil)
        let source = try await manager.registerService(probe, hostID: "host"), destination = try await manager.registerService(f.destination)
        let request = TransferRequest(hostID: "host", source: TransferLocation(serviceID: source, path: try RemotePath("/file")),
            destination: TransferLocation(serviceID: destination, path: try RemotePath("/out")))
        let job = try await manager.enqueue(request)
        try await waitUntil { await reading.arrivals == 1 }
        let operation = Task { try await manager.withServiceOperation(serviceID: source, hostID: "host") { service, token in try await service.list(.root, token: token) } }
        let queuedCancellation = Task { try await manager.withServiceOperation(serviceID: source, hostID: "host") { _, _ in
            XCTFail("Cancelled queued operation must not enter its closure")
        } }
        try await waitUntil { await manager.snapshot().serviceOperations.count == 2 }
        queuedCancellation.cancel(); await assertCancelled(queuedCancellation)
        try await waitUntil { await manager.snapshot().serviceOperations.count == 1 }
        try await Task.sleep(for: .milliseconds(10)); let notStarted = await list.arrivals; XCTAssertEqual(notStarted, 0)
        let other = try await manager.withServiceOperation(serviceID: destination, hostID: "other") { service, token in try await service.list(.root, token: token) }
        XCTAssertTrue(other.allSatisfy { $0.name != request.destination.path.name })
        await reading.release(); try await waitUntil { await list.arrivals == 1 }
        await manager.closeIdleServices(); XCTAssertEqual(probe.closes, 0)
        await list.release(); let entries = try await operation.value; XCTAssertEqual(entries.count, 1)
        try await waitUntil { await manager.snapshot().jobs.first { $0.id == job }?.state == .succeeded }
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testCallerScheduledSafeOperationsAndProbeUseOwnHostGateWithoutDeadlock() async throws {
        let f = try OperationFixture(), scheduler = TransferScheduler(maxConcurrentChunks: 2)
        let manager = TransferManager(engine: SafeTransferEngine(scheduler: scheduler), idleTimeout: nil)
        let probe = OperationProbe(f.source), id = try await manager.registerService(probe, hostID: "host")
        let result = try await manager.withServiceOperation(serviceID: id, hostID: "host", scheduling: .callerScheduled) { service, token in
            try await SafeFileOperations(service: service, hostID: "host", scheduler: scheduler).rename(RemotePath("/file"), to: FileName("renamed"), token: token)
        }
        XCTAssertEqual(result.state, .succeeded)
        let probeResult = try await manager.withServiceOperation(serviceID: id, hostID: "host", scheduling: .callerScheduled) { service, token in
            let plan = try ServerCommitProbe.prepare(service: service, parent: .root)
            return try await ServerCommitProbe.run(plan, service: service, hostID: "host", approvedPlanID: plan.id,
                acknowledgedRisks: plan.requiredRisks, token: token, scheduler: scheduler)
        }
        XCTAssertTrue(probeResult.passed); XCTAssertTrue(probeResult.retainedPaths.isEmpty)
        // The fixture validates lifecycle/scheduling only, not remote server capability evidence.
        let remaining = try await manager.withServiceOperation(serviceID: id, hostID: "host") { service, token in try await service.list(.root, token: token) }
        XCTAssertEqual(remaining.map(\.name), [try FileName("renamed")])
        await manager.cancelAllAndWait(); await f.cleanup()
    }

    func testSharedServiceJobAndMultipleOperationsReleaseOnlyAfterLastUser() async throws {
        let f = try OperationFixture(), reading = OperationGate(), operations = OperationGate()
        let manager = TransferManager(idleTimeout: nil), probe = OperationProbe(f.source, beforeRead: { try await reading.wait($0) })
        let id = try await manager.registerService(probe, hostID: "host"), destination = try await manager.registerService(f.destination)
        let job = try await manager.enqueue(TransferRequest(hostID: "host", source: TransferLocation(serviceID: id, path: RemotePath("/file")),
            destination: TransferLocation(serviceID: destination, path: RemotePath("/out"))))
        try await waitUntil { await reading.arrivals == 1 }
        let one = Task { try await manager.withServiceOperation(serviceID: id, hostID: "host", scheduling: .callerScheduled) { _, _ in try await operations.wait() } }
        let two = Task { try await manager.withServiceOperation(serviceID: id, hostID: "host", scheduling: .callerScheduled) { _, _ in try await operations.wait() } }
        try await waitUntil { await operations.arrivals == 2 }
        await operations.release(); try await one.value; try await two.value
        await manager.closeIdleServices(); XCTAssertEqual(probe.closes, 0)
        await reading.release(); try await waitUntil { await manager.snapshot().jobs.first { $0.id == job }?.state == .succeeded }
        await manager.closeIdleServices(); XCTAssertEqual(probe.closes, 1)
        let snapshot = await manager.snapshot(); XCTAssertFalse(snapshot.hasActiveWork)
        await manager.cancelAllAndWait(); await f.cleanup()
    }
}
