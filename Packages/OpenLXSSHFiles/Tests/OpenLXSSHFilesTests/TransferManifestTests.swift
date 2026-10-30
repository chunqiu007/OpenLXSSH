import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

private func manifestEqual<T: Equatable>(_ actual: T, _ expected: T, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertEqual(actual, expected, file: file, line: line)
}
private func manifestUnwrap<T>(_ value: T?, file: StaticString = #filePath, line: UInt = #line) throws -> T {
    try XCTUnwrap(value, file: file, line: line)
}

// Real temporary-file/FD I/O plus explicitly logical raw-name mappings. No SSH/SFTP connection,
// server capability evidence, Keychain access or physical invalid-UTF8 APFS claim.
private actor ManifestGate {
    private(set) var arrivals = 0
    private var released = false
    func wait(_ token: CancellationToken, ignoresCancellation: Bool = false) async throws {
        arrivals += 1
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !released {
            if !ignoresCancellation { try token.check() }
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "manifest-test-gate") }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    func release() { released = true }
}
private final class ManifestCounts: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Int] = [:]
    func add(_ key: String) { lock.lock(); defer { lock.unlock() }; values[key, default: 0] += 1 }
    func value(_ key: String) -> Int { lock.lock(); defer { lock.unlock() }; return values[key, default: 0] }
    var mutations: Int { ["writeOpen", "write", "mkdir", "commit", "rename", "remove"].reduce(0) { $0 + value($1) } }
}
private actor ManifestService: RemoteFileService {
    nonisolated let capabilities: FileServiceCapabilities
    nonisolated let serverBinding: UUID? = nil
    nonisolated let counts = ManifestCounts()
    let base: LocalFileService
    private var listGate: ManifestGate?
    private var ignoreCancellation = false
    private var readGate: ManifestGate?
    private var duplicate = false
    private var unknownSizes = false
    private var rawMapping: (raw: FileName, backing: FileName)?
    private var failReads = false
    init(_ base: LocalFileService, remoteRisks: Bool = false) {
        self.base = base
        capabilities = remoteRisks ? .init(traversal: .remoteComponentLstat, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true) : base.capabilities
    }
    func configure(listGate: ManifestGate? = nil, ignoreCancellation: Bool = false, readGate: ManifestGate? = nil,
                   duplicate: Bool = false, unknownSizes: Bool = false, failReads: Bool = false) {
        self.listGate = listGate; self.ignoreCancellation = ignoreCancellation; self.readGate = readGate
        self.duplicate = duplicate; self.unknownSizes = unknownSizes; self.failReads = failReads
    }
    func mapRaw(_ raw: FileName, backing: FileName) { rawMapping = (raw, backing) }
    private func mapped(_ path: RemotePath) throws -> RemotePath {
        guard let mapping = rawMapping else { return path }
        return try path.components.reduce(RemotePath.root) { try $0.appending($1 == mapping.raw ? mapping.backing : $1) }
    }
    private func attrs(_ attr: FileAttributes) -> FileAttributes {
        if unknownSizes && attr.kind == .regular {
            return .init(kind: attr.kind, permissions: attr.permissions, modifiedSeconds: attr.modifiedSeconds,
                         modifiedNanoseconds: attr.modifiedNanoseconds, identity: attr.identity)
        }
        return attr
    }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        counts.add("list")
        if let gate = listGate { listGate = nil; try await gate.wait(token, ignoresCancellation: ignoreCancellation) }
        var rows = try await base.list(mapped(path), token: token).map { row in
            DirectoryEntry(name: row.name == rawMapping?.backing ? rawMapping!.raw : row.name, attributes: attrs(row.attributes))
        }
        if duplicate, let first = rows.first { rows.append(first) }
        return rows
    }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes {
        counts.add("lstat"); if path.bytes.contains(255) { counts.add("rawLstat") }
        return attrs(try await base.lstat(mapped(path), token: token))
    }
    func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(handle, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        switch mode { case .read: counts.add("readOpen"); case .exclusiveWrite: counts.add("writeOpen") }
        return try await base.open(mapped(path), mode: mode, token: token)
    }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        counts.add("read")
        if let gate = readGate { readGate = nil; try await gate.wait(token) }
        if failReads { throw FileServiceError(.io, operation: "manifest-injected-read") }
        return try await base.read(handle, maxBytes: maxBytes, token: token)
    }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        counts.add("write"); return try await base.write(handle, data: data, token: token)
    }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await base.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await base.closeHandle(handle) }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { counts.add("mkdir"); try await base.mkdir(mapped(path), token: token) }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws {
        counts.add("commit"); try await base.commit(mapped(source), to: mapped(destination), request: request, token: token)
    }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws {
        counts.add("rename"); try await base.rename(mapped(source), to: mapped(destination), mode: mode, token: token)
    }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { counts.add("remove"); try await base.remove(mapped(path), directory: directory, token: token) }
    nonisolated func cancel() { counts.add("cancel"); base.cancel() }
    func close() async { counts.add("close"); await base.close() }
}
private struct ManifestFixture: Sendable {
    let root: URL
    let left: URL
    let right: URL
    let source: ManifestService
    let destination: ManifestService
    static func make(remoteRisks: Bool = false) throws -> Self {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-Manifest-" + UUID().uuidString)
        let left = root.appendingPathComponent("left"), right = root.appendingPathComponent("right")
        try FileManager.default.createDirectory(at: left, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: right, withIntermediateDirectories: true)
        return Self(root: root, left: left, right: right, source: ManifestService(try LocalFileService(root: left), remoteRisks: remoteRisks),
                    destination: ManifestService(try LocalFileService(root: right)))
    }
    func mkdir(_ name: String, rightSide: Bool = false) throws {
        try FileManager.default.createDirectory(at: (rightSide ? right : left).appendingPathComponent(name), withIntermediateDirectories: true)
    }
    func put(_ name: String, _ value: String = "contents", rightSide: Bool = false) throws {
        try Data(value.utf8).write(to: (rightSide ? right : left).appendingPathComponent(name))
    }
}
final class TransferManifestTests: XCTestCase, @unchecked Sendable {
    private func fixture(_ limits: TransferPlanLimits = .init(), remoteRisks: Bool = false) async throws -> (ManifestFixture, TransferManager, TransferRequest) {
        let f = try ManifestFixture.make(remoteRisks: remoteRisks)
        let manager = TransferManager(idleTimeout: nil, planLimits: limits)
        addTeardownBlock {
            await manager.cancelAllAndWait(); await f.source.close(); await f.destination.close()
            try FileManager.default.removeItem(at: f.root)
        }
        let source = try await manager.registerService(f.source, hostID: remoteRisks ? "fixture" : nil)
        let destination = try await manager.registerService(f.destination)
        let request = TransferRequest(hostID: "fixture", source: .init(serviceID: source, path: try RemotePath("/tree")),
                                      destination: .init(serviceID: destination, path: try RemotePath("/out")), kind: .tree)
        return (f, manager, request)
    }
    private func waitUntil(_ condition: @Sendable () async throws -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while try await !condition() {
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "manifest-test-wait") }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    private func terminal(_ manager: TransferManager, _ id: UUID) async throws -> TransferJobSnapshot {
        try await waitUntil { await manager.snapshot().jobs.contains { $0.id == id && !$0.state.isActive } }
        return try manifestUnwrap(await manager.snapshot().jobs.first { $0.id == id })
    }
    private func assertZero(_ f: ManifestFixture, _ manager: TransferManager, file: StaticString = #filePath, line: UInt = #line) async {
        let snapshot = await manager.snapshot()
        XCTAssertTrue(snapshot.jobs.isEmpty, file: file, line: line)
        XCTAssertEqual(f.source.counts.mutations + f.destination.counts.mutations, 0, file: file, line: line)
        XCTAssertEqual(f.source.counts.value("read") + f.destination.counts.value("read"), 0, file: file, line: line)
    }
    private func expectError<T: Sendable>(_ kind: FileServiceError.Kind, _ body: () async throws -> T,
                                           file: StaticString = #filePath, line: UInt = #line) async {
        do { _ = try await body(); XCTFail("Expected \(kind)", file: file, line: line) }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, kind, file: file, line: line) }
        catch { XCTFail("Unexpected \(error)", file: file, line: line) }
    }
    func testReadOnlyCountsExactRawRootsHiddenChildrenAndSharedReferences() async throws {
        let (f, manager, request) = try await fixture()
        try f.mkdir("tree/子 目录"); try f.put("tree/.hidden", "123"); try f.put("tree/子 目录/e\u{301} line\n", "12345")
        let plan = try await manager.prepareBatch([request])
        XCTAssertTrue(plan.canExecute); XCTAssertEqual(plan.itemCount, 4); XCTAssertEqual(plan.fileCount, 2)
        XCTAssertEqual(plan.directoryCount, 2); XCTAssertEqual(plan.totalBytes, 8)
        let manifest = try XCTUnwrap(plan.requests[0].sourceManifest)
        XCTAssertEqual(manifest.source, request.source); XCTAssertEqual(manifest.destination, request.destination)
        XCTAssertTrue(manifest.entries.contains { $0.path.bytes == Data("/tree/.hidden".utf8) })
        await assertZero(f, manager)
        await manager.discardPreparedBatch(plan.id)
        manifestEqual(await manager.snapshot().planResources, .empty)
        XCTAssertEqual(try Data(contentsOf: f.left.appendingPathComponent("tree/.hidden")), Data("123".utf8))
    }
    func testUnknownBytesStayNilAndReverseDirectionUsesSameReadOnlyPlan() async throws {
        let (f, manager, request) = try await fixture()
        try f.mkdir("tree"); try f.put("tree/a")
        await f.source.configure(unknownSizes: true)
        let plan = try await manager.prepareBatch([request])
        XCTAssertTrue(plan.canExecute); XCTAssertNil(plan.totalBytes)
        await manager.discardPreparedBatch(plan.id)
        try f.mkdir("incoming", rightSide: true); try f.put("incoming/back", "reverse", rightSide: true)
        let reverse = TransferRequest(hostID: "fixture", source: .init(serviceID: request.destination.serviceID, path: try RemotePath("/incoming")),
            destination: .init(serviceID: request.source.serviceID, path: try RemotePath("/download")), kind: .tree)
        let down = try await manager.prepareBatch([reverse]); XCTAssertEqual(down.totalBytes, 7)
        await assertZero(f, manager); await manager.discardPreparedBatch(down.id)
    }
    func testCancelDuringMetadataAndShutdownWaitForActualDrainWithoutClosingB() async throws {
        let (f, manager, request) = try await fixture(), gate = ManifestGate()
        addTeardownBlock { await gate.release() }
        try f.mkdir("tree"); try f.put("tree/a")
        await f.source.configure(listGate: gate, ignoreCancellation: true)
        let token = CancellationToken(), task = Task { try await manager.prepareBatch([request], token: token) }
        try await waitUntil { await gate.arrivals == 1 }
        token.cancel()
        await manager.closeIdleServices([request.source.serviceID, request.destination.serviceID])
        XCTAssertEqual(f.source.counts.value("close"), 0); XCTAssertEqual(f.destination.counts.value("close"), 0)
        let other = try await manager.withServiceOperation(serviceID: request.destination.serviceID, hostID: "other") { service, token in
            try await service.list(.root, token: token)
        }
        XCTAssertTrue(other.isEmpty); XCTAssertEqual(f.destination.counts.value("cancel"), 0)
        let shutdown = Task { await manager.cancelAllAndWait() }
        try await waitUntil { await manager.snapshot().isClosed }
        XCTAssertEqual(f.source.counts.value("close"), 0)
        await gate.release(); await expectError(.cancelled) { try await task.value }; await shutdown.value
        await assertZero(f, manager); manifestEqual(await manager.snapshot().planResources, .empty)
    }
    func testConfirmRejectsAddedAndDeletedChildrenBeforeAnyJobsOrWrites() async throws {
        for adding in [true, false] {
            let (f, manager, request) = try await fixture()
            try f.mkdir("tree"); try f.put("tree/a")
            let plan = try await manager.prepareBatch([request])
            if adding { try f.put("tree/new") } else { try FileManager.default.removeItem(at: f.left.appendingPathComponent("tree/a")) }
            await expectError(.raceDetected) { try await manager.confirmPreparedBatch(plan.id) }
            await assertZero(f, manager); manifestEqual(await manager.snapshot().planResources, .empty)
        }
    }
    func testConfirmRejectsRootReplacementAndFileAttributesChange() async throws {
        for replaceRoot in [true, false] {
            let (f, manager, request) = try await fixture()
            try f.mkdir("tree"); try f.put("tree/a")
            let plan = try await manager.prepareBatch([request])
            if replaceRoot {
                try FileManager.default.moveItem(at: f.left.appendingPathComponent("tree"), to: f.left.appendingPathComponent("old"))
                try f.mkdir("tree"); try f.put("tree/a")
            } else { try f.put("tree/a", "changed-size") }
            await expectError(.raceDetected) { try await manager.confirmPreparedBatch(plan.id) }
            await assertZero(f, manager)
        }
    }
    func testEnqueuedMutationAtRiskCannotAppendNewChildrenOrWrite() async throws {
        let (f, manager, request) = try await fixture(remoteRisks: true)
        try f.mkdir("tree"); try f.put("tree/a")
        let plan = try await manager.prepareBatch([request]), ids = try await manager.confirmPreparedBatch(plan.id)
        try await waitUntil { await manager.snapshot().jobs.first?.pendingDecision != nil }
        let pending = try manifestUnwrap(await manager.snapshot().jobs.first?.pendingDecision)
        try f.put("tree/new", "never-approved")
        let accepted = await manager.resolve(pending, answer: .risk(accepted: true)); XCTAssertTrue(accepted)
        let job = try await terminal(manager, ids[0])
        XCTAssertEqual(job.state, .failed); XCTAssertEqual(job.error?.kind, .raceDetected)
        XCTAssertEqual(f.destination.counts.mutations, 0); XCTAssertFalse(FileManager.default.fileExists(atPath: f.right.appendingPathComponent("out/new").path))
        XCTAssertTrue(job.request.sourceManifest === plan.requests[0].sourceManifest)
    }
    func testConflictAwaitReplacementRejectsBeforeSourceReadAndPreservesOriginal() async throws {
        let (f, manager, request) = try await fixture()
        try f.mkdir("tree"); try f.put("tree/a", "source"); try f.mkdir("out", rightSide: true); try f.put("out/a", "original", rightSide: true)
        let plan = try await manager.prepareBatch([request]), ids = try await manager.confirmPreparedBatch(plan.id)
        try await waitUntil { await manager.snapshot().jobs.first?.state == .waitingConflict }
        try f.put("tree/a", "different-source")
        let pending = try manifestUnwrap(await manager.snapshot().jobs.first?.pendingDecision)
        _ = await manager.resolve(pending, answer: .conflict(.overwrite, applyToBatch: false))
        let job = try await terminal(manager, ids[0])
        XCTAssertEqual(job.error?.kind, .raceDetected); XCTAssertEqual(f.source.counts.value("readOpen"), 0)
        XCTAssertEqual(f.destination.counts.value("writeOpen"), 0)
        XCTAssertEqual(try Data(contentsOf: f.right.appendingPathComponent("out/a")), Data("original".utf8))
    }
    func testLinkSpecialAndDuplicateNamePlansAreExplicitlyUnconfirmable() async throws {
        for kind in ["link", "fifo", "duplicate"] {
            let (f, manager, request) = try await fixture()
            try f.mkdir("tree"); try f.put("tree/a")
            if kind == "link" { try FileManager.default.createSymbolicLink(atPath: f.left.appendingPathComponent("tree/z").path, withDestinationPath: "a") }
            if kind == "fifo" { XCTAssertEqual(mkfifo(f.left.appendingPathComponent("tree/z").path, 0o600), 0) }
            if kind == "duplicate" { await f.source.configure(duplicate: true) }
            let plan = try await manager.prepareBatch([request])
            XCTAssertFalse(plan.canExecute); XCTAssertFalse(plan.enumerationComplete); XCTAssertNil(plan.totalBytes)
            XCTAssertFalse(plan.issues.isEmpty)
            XCTAssertEqual(plan.issues.first?.error.kind, kind == "link" ? .symbolicLink : kind == "fifo" ? .unsupported : .protocolFailure)
            await expectError(.conflict) { try await manager.confirmPreparedBatch(plan.id) }
            await assertZero(f, manager); await manager.discardPreparedBatch(plan.id)
        }
    }
    func testDepthItemsMetadataAndDeepParentLimitsDoNotProducePartialExecutablePlan() async throws {
        for limits in [TransferPlanLimits(maxEntries: 2), TransferPlanLimits(maxDepth: 0)] {
            let (f, manager, request) = try await fixture(limits)
            try f.mkdir("tree/sub"); try f.put("tree/sub/a")
            let plan = try await manager.prepareBatch([request])
            XCTAssertFalse(plan.canExecute); XCTAssertEqual(plan.issues.first?.error.kind, .resourceLimit)
            await assertZero(f, manager); await manager.discardPreparedBatch(plan.id)
            manifestEqual(await manager.snapshot().planResources, .empty)
        }
        let (bounded, boundedManager, boundedRequest) = try await fixture(.init(maxMetadataBytes: 1600))
        try bounded.mkdir("tree/sub"); try bounded.put("tree/sub/a")
        // No allowance remains for a safe issue-bearing snapshot: reject and release instead
        // of returning an oversized partial plan. Error type and zero-I/O assertions stay exact.
        await expectError(.resourceLimit) { try await boundedManager.prepareBatch([boundedRequest]) }
        await assertZero(bounded, boundedManager)
        manifestEqual(await boundedManager.snapshot().planResources, .empty)
        let (long, longManager, longRequest) = try await fixture(.init(maxMetadataBytes: 4096))
        var longParent = ""
        for index in 0..<6 { longParent += (index == 0 ? "" : "/") + String(repeating: "p", count: 100) }
        try long.mkdir(longParent)
        let longInput = TransferRequest(hostID: longRequest.hostID,
            source: .init(serviceID: longRequest.source.serviceID, path: try RemotePath("/" + longParent + "/leaf")), destination: longRequest.destination, kind: .tree)
        let longPlan = try await longManager.prepareBatch([longInput])
        XCTAssertEqual(longPlan.issues.first?.error.operation, "manifest-ancestor-limit")
        XCTAssertFalse(longPlan.canExecute); await assertZero(long, longManager)
        await longManager.discardPreparedBatch(longPlan.id); manifestEqual(await longManager.snapshot().planResources, .empty)
        let (f, manager, request) = try await fixture()
        let path = try RemotePath("/" + Array(repeating: "a", count: 34).joined(separator: "/"))
        let deep = TransferRequest(hostID: request.hostID, source: .init(serviceID: request.source.serviceID, path: path), destination: request.destination, kind: .tree)
        let plan = try await manager.prepareBatch([deep])
        XCTAssertEqual(plan.issues.first?.error.operation, "manifest-parent-depth-limit")
        await assertZero(f, manager); await manager.discardPreparedBatch(plan.id)
        manifestEqual(await manager.snapshot().planResources, .empty)
        // The exact item/depth boundary is executable, not off by one.
        try f.mkdir("tree"); try f.put("tree/a")
        let exactManager = TransferManager(idleTimeout: nil, planLimits: .init(maxEntries: 2, maxDepth: 1))
        let s = try await exactManager.registerService(f.source), d = try await exactManager.registerService(f.destination)
        let exact = TransferRequest(hostID: "fixture", source: .init(serviceID: s, path: request.source.path), destination: .init(serviceID: d, path: request.destination.path), kind: .tree)
        let boundary = try await exactManager.prepareBatch([exact]); XCTAssertTrue(boundary.canExecute); XCTAssertEqual(boundary.itemCount, 2)
        await exactManager.cancelAllAndWait()
    }
    func testLogicalInvalidUTF8PreservesRawIdentityWithoutClaimingPhysicalAPFSNames() async throws {
        let (f, manager, request) = try await fixture()
        try f.mkdir("tree"); try f.put("tree/backing", "raw-data"); try f.put("tree/�", "distinct")
        let raw = try FileName(bytes: Data([255, 32, 65, 10])), backing = try FileName("backing")
        await f.source.mapRaw(raw, backing: backing); await f.destination.mapRaw(raw, backing: backing)
        let plan = try await manager.prepareBatch([request])
        let manifest = try XCTUnwrap(plan.requests[0].sourceManifest)
        XCTAssertEqual(manifest.entries.filter { $0.attributes.kind == .regular }.count, 2)
        XCTAssertTrue(manifest.entries.contains { $0.path.name?.bytes == raw.bytes })
        XCTAssertGreaterThan(f.source.counts.value("rawLstat"), 0)
        let ids = try await manager.confirmPreparedBatch(plan.id), job = try await terminal(manager, ids[0])
        XCTAssertEqual(job.state, .succeeded)
        XCTAssertEqual(try Data(contentsOf: f.right.appendingPathComponent("out/backing")), Data("raw-data".utf8))
        XCTAssertEqual(try Data(contentsOf: f.right.appendingPathComponent("out/�")), Data("distinct".utf8))
    }
    func testDoubleConfirmAndForgedRequestCannotAdmitAdditionalJobs() async throws {
        let (f, manager, request) = try await fixture()
        try f.mkdir("tree"); try f.put("tree/a")
        let plan = try await manager.prepareBatch([request])
        await expectError(.conflict) { try await manager.enqueue(plan.requests[0]) }
        let gate = ManifestGate(); addTeardownBlock { await gate.release() }
        await f.source.configure(listGate: gate)
        let confirmation = Task { try await manager.confirmPreparedBatch(plan.id) }
        try await waitUntil { await gate.arrivals == 1 }
        await expectError(.conflict) { try await manager.confirmPreparedBatch(plan.id) }
        manifestEqual(await manager.snapshot().jobs.count, 0)
        await gate.release()
        let ids = try await confirmation.value
        await expectError(.conflict) { try await manager.confirmPreparedBatch(plan.id) }
        manifestEqual(await manager.snapshot().jobs.count, 1)
        manifestEqual(try await terminal(manager, ids[0]).state, .succeeded)
    }
    func testDiscardExpiryAndChangedDestinationRejectOldPlanAndReleaseLeases() async throws {
        let (f, manager, request) = try await fixture(.init(lifetime: .milliseconds(80)))
        try f.mkdir("tree"); try f.put("tree/a")
        let discarded = try await manager.prepareBatch([request])
        await manager.discardPreparedBatch(discarded.id); await manager.discardPreparedBatch(discarded.id)
        await expectError(.conflict) { try await manager.confirmPreparedBatch(discarded.id) }
        let expired = try await manager.prepareBatch([request])
        try await waitUntil { await manager.snapshot().planResources == .empty }
        await expectError(.conflict) { try await manager.confirmPreparedBatch(expired.id) }
        let changed = try await manager.prepareBatch([request])
        try f.put("unrelated-parent-change", "target", rightSide: true)
        await expectError(.raceDetected) { try await manager.confirmPreparedBatch(changed.id) }
        await assertZero(f, manager)
        await manager.closeIdleServices([request.source.serviceID])
        XCTAssertEqual(f.source.counts.value("close"), 1); XCTAssertEqual(f.destination.counts.value("close"), 0)
    }
    func testBusyHostQueuedPrepareAndConfirmCancellationDrainWithoutCancellingJobB() async throws {
        let (f, manager, request) = try await fixture(), gate = ManifestGate()
        addTeardownBlock { await gate.release() }
        try f.mkdir("tree"); try f.put("tree/a"); try f.put("b", "job-b")
        let ready = try await manager.prepareBatch([request])
        await f.source.configure(readGate: gate)
        let b = TransferRequest(hostID: "fixture", source: .init(serviceID: request.source.serviceID, path: try RemotePath("/b")),
                                destination: .init(serviceID: request.destination.serviceID, path: try RemotePath("/b-out")))
        let jobB = try await manager.enqueue(b)
        try await waitUntil { await gate.arrivals == 1 }
        let token = CancellationToken(), preparing = Task { try await manager.prepareBatch([request], token: token) }
        try await waitUntil { await manager.snapshot().serviceOperations.count == 1 }
        token.cancel(); await expectError(.cancelled) { try await preparing.value }
        let confirming = Task { try await manager.confirmPreparedBatch(ready.id) }
        try await waitUntil { await manager.snapshot().planResources.confirming == 1 }
        await manager.discardPreparedBatch(ready.id)
        await expectError(.cancelled) { try await confirming.value }
        let snapshot = await manager.snapshot()
        XCTAssertEqual(snapshot.jobs.first?.id, jobB); XCTAssertTrue(snapshot.jobs.first?.state.isActive == true)
        XCTAssertTrue(snapshot.serviceOperations.isEmpty); XCTAssertEqual(snapshot.planResources, .empty)
        XCTAssertEqual(f.source.counts.value("cancel") + f.destination.counts.value("cancel"), 0)
        await gate.release(); manifestEqual(try await terminal(manager, jobB).state, .succeeded)
    }
    func testPreparationCapacityReservedBeforeIOAndAtomicQueueAdmissionFailure() async throws {
        let limits = TransferPlanLimits(maxEntries: 4, maxTotalEntries: 4, maxConcurrentPreparations: 1)
        let (f, manager, request) = try await fixture(limits), gate = ManifestGate()
        addTeardownBlock { await gate.release() }
        try f.mkdir("tree"); try f.put("tree/a")
        await f.source.configure(listGate: gate)
        let token = CancellationToken(), first = Task { try await manager.prepareBatch([request], token: token) }
        try await waitUntil { await gate.arrivals == 1 }
        let reads = f.source.counts.value("lstat")
        await expectError(.resourceLimit) { try await manager.prepareBatch([request]) }
        XCTAssertEqual(f.source.counts.value("lstat"), reads)
        token.cancel(); await expectError(.cancelled) { try await first.value }
        manifestEqual(await manager.snapshot().planResources, .empty)
        await gate.release()
        let ready = try await manager.prepareBatch([request])
        await expectError(.resourceLimit) { try await manager.prepareBatch([request]) }
        await manager.discardPreparedBatch(ready.id)
        let (byteFixture, byteManager, byteRequest) = try await fixture(.init(maxEntries: 4, maxMetadataBytes: 4096, maxTotalMetadataBytes: 4096))
        try byteFixture.mkdir("tree"); try byteFixture.put("tree/a")
        let bytePlan = try await byteManager.prepareBatch([byteRequest])
        let byteUsage = await byteManager.snapshot().planResources
        XCTAssertEqual(byteUsage.reservedEntries, 2); XCTAssertGreaterThan(byteUsage.reservedMetadataBytes, 0)
        XCTAssertLessThanOrEqual(byteUsage.reservedMetadataBytes, 4096)
        await expectError(.resourceLimit) { try await byteManager.prepareBatch([byteRequest]) }
        await assertZero(byteFixture, byteManager)
        await byteManager.discardPreparedBatch(bytePlan.id); manifestEqual(await byteManager.snapshot().planResources, .empty)
        // Queue capacity changed during review: admission of a two-root plan remains atomic.
        let small = TransferManager(maxConcurrentJobs: 1, maxQueuedJobs: 1, maxStoredJobs: 3, idleTimeout: nil)
        let s = try await small.registerService(f.source), d = try await small.registerService(f.destination)
        try f.mkdir("other"); try f.put("other/b"); try f.mkdir("reviewed-target", rightSide: true)
        // A separately rooted real FD namespace: blocker/filler writes cannot change its root
        // attributes. All source and destination revalidation assertions remain enabled.
        let reviewed = try LocalFileService(root: f.right.appendingPathComponent("reviewed-target"))
        let reviewDestination = try await small.registerService(reviewed)
        let one = TransferRequest(hostID: "fixture", source: .init(serviceID: s, path: request.source.path), destination: .init(serviceID: reviewDestination, path: try RemotePath("/out")), kind: .tree)
        let two = TransferRequest(hostID: "fixture", source: .init(serviceID: s, path: try RemotePath("/other")), destination: .init(serviceID: reviewDestination, path: try RemotePath("/other-out")), kind: .tree)
        let plan = try await small.prepareBatch([one, two])
        let blocker = ManifestGate(); addTeardownBlock { await blocker.release(); await small.cancelAllAndWait() }
        await f.source.configure(readGate: blocker)
        let b = try await small.enqueue(TransferRequest(hostID: "fixture", source: .init(serviceID: s, path: try RemotePath("/tree/a")), destination: .init(serviceID: d, path: try RemotePath("/b"))))
        try await waitUntil { await blocker.arrivals == 1 }
        let confirm = Task { try await small.confirmPreparedBatch(plan.id) }
        try await waitUntil { await small.snapshot().serviceOperations.count == 1 }
        // The running record + filler leaves too little space for both reviewed roots.
        let filler = try await small.enqueue(TransferRequest(hostID: "other-host", source: .init(serviceID: s, path: try RemotePath("/other/b")), destination: .init(serviceID: d, path: try RemotePath("/filler"))))
        await blocker.release()
        _ = try await terminal(small, b)
        _ = try await terminal(small, filler)
        await expectError(.resourceLimit) { try await confirm.value }
        manifestEqual(await small.snapshot().jobs.count, 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.right.appendingPathComponent("reviewed-target/out").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.right.appendingPathComponent("reviewed-target/other-out").path))
    }
    func testRetryRequiresFreshReviewFromZeroAndHistoryRemovalReturnsManifestBudget() async throws {
        let limits = TransferPlanLimits(maxEntries: 2, maxTotalEntries: 4)
        let (f, manager, request) = try await fixture(limits)
        try f.mkdir("tree"); try f.put("tree/a", "new-content")
        await f.source.configure(failReads: true)
        let plan = try await manager.prepareBatch([request]), ids = try await manager.confirmPreparedBatch(plan.id)
        let failed = try await terminal(manager, ids[0]); XCTAssertEqual(failed.state, .failed)
        await expectError(.conflict) { try await manager.retry(ids[0]) }
        let retryPlan = try await manager.prepareRetry(ids[0])
        XCTAssertFalse(retryPlan.requests[0].sourceManifest === failed.request.sourceManifest)
        manifestEqual(await manager.snapshot().jobs.count, 1)
        await f.source.configure()
        let retried = try await manager.confirmPreparedBatch(retryPlan.id), done = try await terminal(manager, retried[0])
        XCTAssertEqual(done.retryOf, failed.id); XCTAssertNotEqual(done.generation, failed.generation)
        XCTAssertEqual(done.transferredBytes, UInt64("new-content".utf8.count)); XCTAssertEqual(done.state, .succeeded)
        manifestEqual(await manager.snapshot().planResources.reservedEntries, 4)
        await expectError(.resourceLimit) { try await manager.prepareBatch([request]) }
        manifestEqual(await manager.removeFinishedJobs([failed.id]), 1)
        manifestEqual(await manager.snapshot().planResources.reservedEntries, 2)
        manifestEqual(await manager.removeFinishedJobs(retried), 1)
        manifestEqual(await manager.snapshot().planResources, .empty)
        XCTAssertEqual(try Data(contentsOf: f.right.appendingPathComponent("out/a")), Data("new-content".utf8))
    }
    func testEngineManifestRootRenamePreservesSourceIdentityAndLegacyPartialRemains() async throws {
        let (f, manager, request) = try await fixture()
        try f.mkdir("tree"); try f.put("tree/a", "approved")
        let plan = try await manager.prepareBatch([request]), manifest = try XCTUnwrap(plan.requests[0].sourceManifest)
        let engine = SafeTransferEngine()
        let report = try await engine.copyTree(hostID: request.hostID, source: f.source, sourcePath: request.source.path,
            destination: f.destination, destinationPath: request.destination.path, conflict: .renameTo(try FileName("renamed")),
            token: CancellationToken(), sourceManifest: manifest)
        XCTAssertTrue(report.allSucceeded); XCTAssertEqual(manifest.source.path, request.source.path)
        XCTAssertEqual(try Data(contentsOf: f.right.appendingPathComponent("renamed/a")), Data("approved".utf8))
        await manager.discardPreparedBatch(plan.id)
        try FileManager.default.createSymbolicLink(atPath: f.left.appendingPathComponent("tree/zlink").path, withDestinationPath: "a")
        let legacy = try await engine.copyTree(hostID: request.hostID, source: f.source, sourcePath: request.source.path,
            destination: f.destination, destinationPath: try RemotePath("/legacy"), token: CancellationToken())
        XCTAssertFalse(legacy.allSucceeded)
        XCTAssertTrue(legacy.items.contains { if case .failed(let error) = $0.state { return error.kind == .symbolicLink }; return false })
        XCTAssertEqual(try Data(contentsOf: f.right.appendingPathComponent("legacy/a")), Data("approved".utf8))
    }
    func testExecutionMutationAfterFirstCommittedChildStopsWithTruePartialResult() async throws {
        let (f, manager, request) = try await fixture()
        try f.mkdir("tree"); try f.put("tree/a", "first-approved"); try f.put("tree/b", "second-approved")
        let plan = try await manager.prepareBatch([request]), manifest = try XCTUnwrap(plan.requests[0].sourceManifest)
        let report = try await SafeTransferEngine().copyTree(hostID: request.hostID, source: f.source, sourcePath: request.source.path,
            destination: f.destination, destinationPath: request.destination.path, token: CancellationToken(),
            hooks: .init(beforeCommit: { _, path in
                if path.name == (try? FileName("b")) { try f.put("tree/new", "not-approved") }
            }), sourceManifest: manifest)
        XCTAssertFalse(report.allSucceeded)
        XCTAssertTrue(report.items.contains { $0.source.name == (try? FileName("a")) && $0.state == .succeeded(bytes: 14) })
        XCTAssertTrue(report.items.contains { if case .failed(let error) = $0.state { return error.kind == .raceDetected }; return false })
        XCTAssertEqual(try Data(contentsOf: f.right.appendingPathComponent("out/a")), Data("first-approved".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.right.appendingPathComponent("out/b").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.right.appendingPathComponent("out/new").path))
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: f.right.appendingPathComponent("out").path).contains { $0.hasPrefix(".openlxssh-transfer.") })
        await manager.discardPreparedBatch(plan.id)
    }
    func testDefaultBudgetShrinksTinyHistoryAndAllowsFourConsecutivePlans() async throws {
        let (f, manager, request) = try await fixture()
        try f.mkdir("tree"); try f.put("tree/a", "small")
        var ids: [UUID] = []
        for index in 0..<4 {
            let next = TransferRequest(hostID: request.hostID, source: request.source,
                destination: .init(serviceID: request.destination.serviceID, path: try RemotePath("/out-\(index)")), kind: .tree)
            let plan = try await manager.prepareBatch([next])
            let newIDs = try await manager.confirmPreparedBatch(plan.id)
            let job = try await terminal(manager, newIDs[0]); XCTAssertEqual(job.state, .succeeded)
            ids += newIDs
        }
        let usage = await manager.snapshot().planResources
        XCTAssertEqual(usage.reservedEntries, 8)
        XCTAssertGreaterThan(usage.reservedMetadataBytes, 0); XCTAssertLessThan(usage.reservedMetadataBytes, 64 * 1024)
        manifestEqual(await manager.removeFinishedJobs(ids), 4)
        manifestEqual(await manager.snapshot().planResources, .empty)
        for index in 0..<4 { XCTAssertEqual(try Data(contentsOf: f.right.appendingPathComponent("out-\(index)/a")), Data("small".utf8)) }
    }
    func testSameNamespaceAndOverlappingRootsCannotProduceExecutablePlan() async throws {
        let (f, manager, request) = try await fixture()
        try f.mkdir("tree"); try f.put("tree/a")
        let alias = TransferRequest(hostID: request.hostID, source: request.source,
            destination: .init(serviceID: request.source.serviceID, path: try RemotePath("/tree/copy")), kind: .tree)
        let plan = try await manager.prepareBatch([alias])
        XCTAssertEqual(plan.issues.first?.error.operation, "manifest-same-namespace-copy-not-supported")
        XCTAssertFalse(plan.canExecute)
        let issueUsage = await manager.snapshot().planResources
        XCTAssertEqual(issueUsage.reservedEntries, 1); XCTAssertGreaterThan(issueUsage.reservedMetadataBytes, 0)
        await manager.discardPreparedBatch(plan.id)
        await expectError(.conflict) { try await manager.prepareBatch([request, request]) }
        await assertZero(f, manager)
    }
}
