import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHRemoteFileProbe

private final class FixturePair: @unchecked Sendable {
    let root: URL
    let leftURL: URL
    let rightURL: URL
    let left: LocalFixtureFileService
    let right: LocalFixtureFileService
    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-P3-\(UUID().uuidString)", isDirectory: true)
        leftURL = root.appendingPathComponent("source", isDirectory: true)
        rightURL = root.appendingPathComponent("destination", isDirectory: true)
        try FileManager.default.createDirectory(at: leftURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: rightURL, withIntermediateDirectories: true)
        left = try LocalFixtureFileService(root: leftURL); right = try LocalFixtureFileService(root: rightURL)
    }
    func cleanup() async { await left.close(); await right.close(); try? FileManager.default.removeItem(at: root) }
    func put(_ name: String, data: Data, right: Bool = false) throws {
        try data.write(to: (right ? rightURL : leftURL).appendingPathComponent(name))
    }
}
private actor HoldPoint {
    private var reached = false
    private var released = false
    func hold() async {
        reached = true
        while !released { try? await Task.sleep(for: .milliseconds(5)) }
    }
    func waitForArrival() async throws {
        let deadline = Date().addingTimeInterval(3)
        while !reached {
            guard Date() < deadline else { throw FileServiceError(.timeout, operation: "test-hold") }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func release() { released = true }
}
private actor Activity {
    var active = 0
    var maximum = 0
    var paths: Set<RemotePath> = []
    func enter(_ path: RemotePath) { active += 1; maximum = max(maximum, active); paths.insert(path) }
    func leave() { active -= 1 }
    func snapshot() -> (Int, Int) { (maximum, paths.count) }
}

final class TransferPolicyTests: XCTestCase, @unchecked Sendable {
    private func payload(_ count: Int = 300_123) -> Data { Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31) }) }
    private func assertFailed(_ result: TransferReport, _ kind: FileServiceError.Kind,
                              file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(result.allSucceeded, file: file, line: line)
        guard case .failed(let error)? = result.items.last?.state else {
            XCTFail("Expected typed failure", file: file, line: line); return
        }
        XCTAssertEqual(error.kind, kind, file: file, line: line)
    }
    func testStreamingHashRoundTripAndNoTemporaryResidue() async throws {
        let f = try FixturePair(); let bytes = payload()
        try f.put("输入 中文 $' \n.txt", data: bytes)
        let path = try RemotePath("/输入 中文 $' \n.txt")
        let engine = SafeTransferEngine(chunkSize: 8192)
        let upload = try await engine.copy(hostID: "fixture", source: f.left, sourcePath: path,
            destination: f.right, destinationPath: path, token: CancellationToken())
        XCTAssertTrue(upload.allSucceeded)
        let download = try await engine.copy(hostID: "fixture", source: f.right, sourcePath: path,
            destination: f.left, destinationPath: RemotePath("/returned"), token: CancellationToken())
        XCTAssertTrue(download.allSucceeded)
        let roundTrip = try Data(contentsOf: f.leftURL.appendingPathComponent("returned"))
        XCTAssertEqual(SHA256.hash(data: roundTrip), SHA256.hash(data: bytes))
        let entries = try await f.right.list(.root, token: CancellationToken())
        XCTAssertEqual(entries.map(\.name), [try FileName("输入 中文 $' \n.txt")])
        await f.cleanup()
    }
    func testHostFilesystemRejectsNonUTF8WithoutRewritingName() async throws {
        let f = try FixturePair()
        let name = try FileName(bytes: Data([0xff, 0xfe, 32, 36, 39]))
        let path = try RemotePath.root.appending(name)
        // This macOS/APFS filesystem returns EILSEQ for non-UTF8 names. The transport model
        // retains raw bytes; local download must fail explicitly, never normalize/substitute.
        do {
            _ = try await f.left.open(path, mode: .exclusiveWrite, token: CancellationToken())
            XCTFail("Expected the host filesystem to reject this non-UTF8 filename")
        } catch let error as FileServiceError {
            XCTAssertEqual(error.kind, .invalidPath); XCTAssertEqual(error.code, Int64(EILSEQ))
            XCTAssertEqual(error.path?.bytes, path.bytes)
        }
        let names = try await f.left.list(.root, token: CancellationToken()).map(\.name)
        XCTAssertTrue(names.isEmpty)
        await f.cleanup()
    }
    func testConflictSkipAndOverwriteRefusalPreserveOriginal() async throws {
        let f = try FixturePair(); try f.put("file", data: payload()); try f.put("file", data: Data("original".utf8), right: true)
        let engine = SafeTransferEngine(); let path = try RemotePath("/file")
        let fail = try await engine.copy(hostID: "conflict", source: f.left, sourcePath: path,
            destination: f.right, destinationPath: path, token: CancellationToken())
        assertFailed(fail, .conflict)
        let skip = try await engine.copy(hostID: "conflict", source: f.left, sourcePath: path,
            destination: f.right, destinationPath: path, conflict: .skip, token: CancellationToken())
        XCTAssertFalse(skip.allSucceeded); XCTAssertEqual(skip.items.first?.state, .skipped)
        let overwrite = try await engine.copy(hostID: "conflict", source: f.left, sourcePath: path,
            destination: f.right, destinationPath: path, conflict: .overwrite, token: CancellationToken())
        assertFailed(overwrite, .riskRejected)
        XCTAssertEqual(try Data(contentsOf: f.rightURL.appendingPathComponent("file")), Data("original".utf8))
        let entries = try await f.right.list(.root, token: CancellationToken()); XCTAssertEqual(entries.count, 1)
        await f.cleanup()
    }
    func testRiskConfirmedOverwriteCommitsOnlyAfterCompleteTemporary() async throws {
        let f = try FixturePair(); let new = payload(123_456)
        try f.put("file", data: new); try f.put("target", data: Data("old".utf8), right: true)
        let report = try await SafeTransferEngine().copy(hostID: "overwrite", source: f.left, sourcePath: RemotePath("/file"),
            destination: f.right, destinationPath: RemotePath("/target"), conflict: .overwrite, token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { risk in
                if case .overwriteIsAtomicButNotCompareAndSwap = risk { return true }; return false
            }), hooks: TransferHooks(beforeCommit: { temporary, _ in
                XCTAssertEqual(try Data(contentsOf: f.rightURL.appendingPathComponent("target")), Data("old".utf8))
                let completedTemp = try Data(contentsOf: f.rightURL.appendingPathComponent(String(decoding: temporary.bytes.dropFirst(), as: UTF8.self)))
                XCTAssertEqual(SHA256.hash(data: completedTemp), SHA256.hash(data: new))
            }))
        XCTAssertTrue(report.allSucceeded)
        XCTAssertEqual(report.items.first?.acknowledgedRisks, [.overwriteIsAtomicButNotCompareAndSwap(path: try RemotePath("/target"))])
        XCTAssertEqual(try Data(contentsOf: f.rightURL.appendingPathComponent("target")), new)
        await f.cleanup()
    }
    func testOverwriteDetectsSameLengthChangedTargetBeforeAtomicCommit() async throws {
        let f = try FixturePair(); try f.put("file", data: payload(444)); try f.put("target", data: Data("before".utf8), right: true)
        let competitor = Data("racing".utf8)
        let report = try await SafeTransferEngine().copy(hostID: "overwrite-race", source: f.left, sourcePath: RemotePath("/file"),
            destination: f.right, destinationPath: RemotePath("/target"), conflict: .overwrite, token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { _ in true }),
            hooks: TransferHooks(beforeCommit: { _, _ in try f.put("target", data: competitor, right: true) }))
        assertFailed(report, .raceDetected)
        XCTAssertEqual(try Data(contentsOf: f.rightURL.appendingPathComponent("target")), competitor)
        XCTAssertNil(report.items.first?.retainedTemporary)
        await f.cleanup()
    }
    func testCancelledRiskConfirmedOverwritePreservesOriginal() async throws {
        let f = try FixturePair(); try f.put("file", data: payload()); try f.put("target", data: Data("original".utf8), right: true)
        let token = CancellationToken()
        let report = try await SafeTransferEngine(chunkSize: 4096).copy(hostID: "overwrite-cancel", source: f.left, sourcePath: RemotePath("/file"),
            destination: f.right, destinationPath: RemotePath("/target"), conflict: .overwrite, token: token,
            policy: TransferPolicy(confirmRisk: { _ in true }), hooks: TransferHooks(progress: { _, _ in token.cancel() }))
        assertFailed(report, .cancelled)
        XCTAssertEqual(try Data(contentsOf: f.rightURL.appendingPathComponent("target")), Data("original".utf8))
        let entries = try await f.right.list(.root, token: CancellationToken()); XCTAssertEqual(entries.count, 1)
        await f.cleanup()
    }
    func testCancellationBeforeCommitCleansTempAndKeepsRacingOriginal() async throws {
        let f = try FixturePair(); try f.put("file", data: payload())
        let token = CancellationToken(); let original = Data("late-original".utf8)
        let report = try await SafeTransferEngine().copy(hostID: "cancel", source: f.left, sourcePath: RemotePath("/file"),
            destination: f.right, destinationPath: RemotePath("/file"), token: token,
            hooks: TransferHooks(beforeCommit: { _, _ in
                try f.put("file", data: original, right: true); token.cancel()
            }))
        assertFailed(report, .cancelled)
        XCTAssertEqual(try Data(contentsOf: f.rightURL.appendingPathComponent("file")), original)
        XCTAssertNil(report.items.first?.retainedTemporary)
        let entries = try await f.right.list(.root, token: CancellationToken()); XCTAssertEqual(entries.count, 1)
        await f.cleanup()
    }
    func testCancellationMidChunkLeavesNoPartialFinal() async throws {
        let f = try FixturePair(); try f.put("file", data: payload())
        let token = CancellationToken()
        let report = try await SafeTransferEngine(chunkSize: 4096).copy(hostID: "cancel", source: f.left, sourcePath: RemotePath("/file"),
            destination: f.right, destinationPath: RemotePath("/new"), token: token,
            hooks: TransferHooks(progress: { _, _ in token.cancel() }))
        assertFailed(report, .cancelled)
        let entries = try await f.right.list(.root, token: CancellationToken()); XCTAssertTrue(entries.isEmpty)
        await f.cleanup()
    }
    func testRaceAtCommitCannotOverwriteCompetitor() async throws {
        let f = try FixturePair(); try f.put("file", data: payload())
        let competitor = Data("competitor".utf8)
        let report = try await SafeTransferEngine().copy(hostID: "race", source: f.left, sourcePath: RemotePath("/file"),
            destination: f.right, destinationPath: RemotePath("/new"), token: CancellationToken(),
            hooks: TransferHooks(beforeCommit: { _, _ in try f.put("new", data: competitor, right: true) }))
        assertFailed(report, .conflict)
        XCTAssertEqual(try Data(contentsOf: f.rightURL.appendingPathComponent("new")), competitor)
        XCTAssertNil(report.items.first?.retainedTemporary)
        await f.cleanup()
    }
    func testPermissionDeniedMissingAndIOAreDistinct() async throws {
        let f = try FixturePair(); try f.put("file", data: payload(123))
        let locked = f.rightURL.appendingPathComponent("locked")
        try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(locked.path, 0), 0)
        let engine = SafeTransferEngine()
        let denied = try await engine.copy(hostID: "permission", source: f.left, sourcePath: RemotePath("/file"),
            destination: f.right, destinationPath: RemotePath("/locked/new"), token: CancellationToken())
        XCTAssertEqual(chmod(locked.path, 0o700), 0)
        assertFailed(denied, .permissionDenied)
        let missing = try await engine.copy(hostID: "missing", source: f.left, sourcePath: RemotePath("/absent"),
            destination: f.right, destinationPath: RemotePath("/new"), token: CancellationToken())
        assertFailed(missing, .notFound)
        let readOnly = try await f.left.open(RemotePath("/file"), mode: .read, token: CancellationToken())
        do {
            _ = try await f.left.write(readOnly, data: Data([1]), token: CancellationToken()); XCTFail("write must fail on read-only FD")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .io); XCTAssertEqual(error.code, Int64(EBADF)) }
        try await f.left.closeHandle(readOnly)
        await f.cleanup()
    }
    func testRecursiveSpecialNamesSymlinksAndDepthBound() async throws {
        let f = try FixturePair()
        try FileManager.default.createDirectory(at: f.leftURL.appendingPathComponent("树 中文/层 空格/deep"), withIntermediateDirectories: true)
        try f.put("树 中文/层 空格/quote'$;\n", data: payload(44))
        try f.put("树 中文/层 空格/deep/file", data: payload(22))
        XCTAssertEqual(symlink("..", f.leftURL.appendingPathComponent("树 中文/cycle").path), 0)
        let engine = SafeTransferEngine(maxDepth: 1)
        let report = try await engine.copyTree(hostID: "tree", source: f.left, sourcePath: RemotePath("/树 中文"),
            destination: f.right, destinationPath: RemotePath("/out"), token: CancellationToken())
        XCTAssertFalse(report.allSucceeded)
        XCTAssertTrue(report.items.contains { if case .failed(let e) = $0.state { return e.kind == .symbolicLink }; return false })
        XCTAssertTrue(report.items.contains { if case .failed(let e) = $0.state { return e.kind == .resourceLimit }; return false })
        let unboundedEnough = try await SafeTransferEngine().copyTree(hostID: "tree", source: f.left, sourcePath: RemotePath("/树 中文/层 空格"),
            destination: f.right, destinationPath: RemotePath("/normal"), token: CancellationToken())
        XCTAssertTrue(unboundedEnough.allSucceeded)
        XCTAssertEqual(try Data(contentsOf: f.rightURL.appendingPathComponent("normal/quote'$;\n")), payload(44))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.rightURL.appendingPathComponent("out/cycle").path))
        await f.cleanup()
    }
    func testDownloadDestinationSymlinkCannotEscapeRoot() async throws {
        let f = try FixturePair(); try f.put("file", data: payload())
        let outside = f.root.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        XCTAssertEqual(symlink(outside.path, f.rightURL.appendingPathComponent("escape").path), 0)
        let report = try await SafeTransferEngine().copy(hostID: "escape", source: f.left, sourcePath: RemotePath("/file"),
            destination: f.right, destinationPath: RemotePath("/escape/file"), token: CancellationToken())
        assertFailed(report, .symbolicLink)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: outside.path), [])
        let sourceLink = f.leftURL.appendingPathComponent("source-link")
        XCTAssertEqual(symlink("file", sourceLink.path), 0)
        let rejected = try await SafeTransferEngine().copy(hostID: "escape", source: f.left, sourcePath: RemotePath("/source-link"),
            destination: f.right, destinationPath: RemotePath("/link-copy"), token: CancellationToken())
        assertFailed(rejected, .symbolicLink)
        await f.cleanup()
    }
    func testPerHostQueueCancellationAndOriginalPreservation() async throws {
        let f = try FixturePair(); try f.put("file", data: payload(123)); try f.put("original", data: Data("original".utf8), right: true)
        let engine = SafeTransferEngine(scheduler: TransferScheduler(maxConcurrentChunks: 1))
        let hold = HoldPoint()
        let first = Task {
            try await engine.copy(hostID: "same-host", source: f.left, sourcePath: RemotePath("/file"),
                destination: f.right, destinationPath: RemotePath("/first"), token: CancellationToken(),
                hooks: TransferHooks(beforeCommit: { _, _ in await hold.hold() }))
        }
        try await hold.waitForArrival()
        let token = CancellationToken()
        let second = Task {
            try await engine.copy(hostID: "same-host", source: f.left, sourcePath: RemotePath("/file"),
                destination: f.right, destinationPath: RemotePath("/original"), conflict: .overwrite, token: token)
        }
        try await Task.sleep(for: .milliseconds(30)); token.cancel()
        do { _ = try await second.value; XCTFail("Cancelled queue entry must throw") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        await hold.release()
        let completed = try await first.value; XCTAssertTrue(completed.allSucceeded)
        XCTAssertEqual(try Data(contentsOf: f.rightURL.appendingPathComponent("original")), Data("original".utf8))
        await f.cleanup()
    }
    func testSingleHostJobsDoNotInterleave() async throws {
        let f = try FixturePair(); try f.put("file", data: payload(64))
        let engine = SafeTransferEngine(scheduler: TransferScheduler(maxConcurrentChunks: 3))
        let activity = Activity()
        let hooks = TransferHooks(beforeCommit: { _, path in
            await activity.enter(path); try await Task.sleep(for: .milliseconds(20)); await activity.leave()
        })
        try await withThrowingTaskGroup(of: TransferReport.self) { group in
            for i in 0..<6 {
                group.addTask {
                    try await engine.copy(hostID: "one", source: f.left, sourcePath: RemotePath("/file"),
                        destination: f.right, destinationPath: RemotePath("/out\(i)"), token: CancellationToken(), hooks: hooks)
                }
            }
            for try await result in group { XCTAssertTrue(result.allSucceeded) }
        }
        let (maximum, count) = await activity.snapshot(); XCTAssertEqual(maximum, 1); XCTAssertEqual(count, 6)
        await f.cleanup()
    }
    func testGlobalChunkBudgetIsBoundedAcrossIndependentJobs() async throws {
        let scheduler = TransferScheduler(maxConcurrentChunks: 2)
        let activity = Activity()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<12 {
                group.addTask {
                    try await scheduler.chunk(CancellationToken()) {
                        await activity.enter(try RemotePath("/job\(i)"))
                        try await Task.sleep(for: .milliseconds(15))
                        await activity.leave()
                    }
                }
            }
            try await group.waitForAll()
        }
        let (maximum, count) = await activity.snapshot()
        XCTAssertEqual(maximum, 2); XCTAssertEqual(count, 12)
    }
    func testCloseAndCancelAreTerminalAndIdempotent() async throws {
        let f = try FixturePair(); try f.put("file", data: payload(3))
        let handle = try await f.left.open(RemotePath("/file"), mode: .read, token: CancellationToken())
        await f.left.close(); await f.left.close()
        do { _ = try await f.left.read(handle, maxBytes: 1, token: CancellationToken()); XCTFail("closed") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        f.right.cancel()
        do { _ = try await f.right.list(.root, token: CancellationToken()); XCTFail("cancelled") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        await f.cleanup()
    }
}
