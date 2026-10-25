import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

// Real local descriptor I/O only. These regressions are not SFTP/server interoperability evidence.
private final class IntegrityFixture: @unchecked Sendable {
    let root: URL
    let sourceURL: URL
    let destinationURL: URL
    let source: LocalFileService
    let destination: LocalFileService
    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-integrity-\(UUID().uuidString)")
        sourceURL = root.appendingPathComponent("source"); destinationURL = root.appendingPathComponent("destination")
        try FileManager.default.createDirectory(at: sourceURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: destinationURL, withIntermediateDirectories: true)
        source = try LocalFileService(root: sourceURL); destination = try LocalFileService(root: destinationURL)
    }
    func cleanup() async { await source.close(); await destination.close(); try? FileManager.default.removeItem(at: root) }
    func seedFile() throws {
        try Data("AAAABBBB".utf8).write(to: sourceURL.appendingPathComponent("file"))
        try Data("original".utf8).write(to: destinationURL.appendingPathComponent("target"))
        try Data("unrelated".utf8).write(to: destinationURL.appendingPathComponent("unrelated.part"))
        let fd = Darwin.open(sourceURL.appendingPathComponent("file").path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw FileServiceError(.io, operation: "test-open") }; defer { Darwin.close(fd) }
        try setMtime(fd, nanoseconds: 100_000_000)
    }
    func setMtime(_ fd: Int32, nanoseconds: Int) throws {
        var times = [timespec(tv_sec: 1_700_000_000, tv_nsec: nanoseconds), timespec(tv_sec: 1_700_000_000, tv_nsec: nanoseconds)]
        guard futimens(fd, &times) == 0 else { throw FileServiceError(.io, operation: "test-futimens") }
    }
    func rewriteSameInode(nanoseconds: Int = 200_000_000) throws {
        let fd = Darwin.open(sourceURL.appendingPathComponent("file").path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw FileServiceError(.io, operation: "test-open") }; defer { Darwin.close(fd) }
        let bytes = Data("CCCCDDDD".utf8)
        guard bytes.withUnsafeBytes({ pwrite(fd, $0.baseAddress, $0.count, 0) }) == bytes.count else {
            throw FileServiceError(.io, operation: "test-pwrite")
        }
        try setMtime(fd, nanoseconds: nanoseconds)
    }
    func replacePath() throws {
        let replacement = sourceURL.appendingPathComponent("replacement")
        try Data("CCCCDDDD".utf8).write(to: replacement)
        let fd = Darwin.open(replacement.path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw FileServiceError(.io, operation: "test-open") }
        do { try setMtime(fd, nanoseconds: 100_000_000) } catch { Darwin.close(fd); throw error }
        Darwin.close(fd)
        guard Darwin.rename(replacement.path, sourceURL.appendingPathComponent("file").path) == 0 else {
            throw FileServiceError(.io, operation: "test-replace")
        }
    }
}

/// Intentionally implements only the original protocol API. A future optional handle-stat default
/// must leave this conformer source-compatible and must not pretend it has descriptor metadata.
private final class PathOnlyIntegrityService: RemoteFileService, @unchecked Sendable {
    let local: LocalFileService
    let capabilities: FileServiceCapabilities
    let coarseMetadata: Bool
    let onOpen: (@Sendable () async throws -> Void)?
    let onRead: (@Sendable (CancellationToken) async throws -> Void)?
    let onCloseHandle: (@Sendable () async throws -> Void)?
    init(_ local: LocalFileService, coarseMetadata: Bool = true,
         onOpen: (@Sendable () async throws -> Void)? = nil,
         onRead: (@Sendable (CancellationToken) async throws -> Void)? = nil,
         onCloseHandle: (@Sendable () async throws -> Void)? = nil) {
        self.local = local; self.capabilities = local.capabilities; self.coarseMetadata = coarseMetadata
        self.onOpen = onOpen; self.onRead = onRead; self.onCloseHandle = onCloseHandle
    }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await local.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes {
        let a = try await local.lstat(p, token: token)
        return coarseMetadata ? FileAttributes(kind: a.kind, size: a.size, permissions: a.permissions, modifiedSeconds: a.modifiedSeconds) : a
    }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        try await onOpen?(); return try await local.open(p, mode: mode, token: token)
    }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        try await onRead?(token); return try await local.read(h, maxBytes: maxBytes, token: token)
    }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await local.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await local.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await local.closeHandle(h); try await onCloseHandle?() }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await local.mkdir(p, token: token) }
    func rename(_ s: RemotePath, to d: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await local.rename(s, to: d, mode: mode, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await local.remove(p, directory: directory, token: token) }
    func cancel() { local.cancel() }
    func close() async { await local.close() }
}

private actor IntegrityIOCounts {
    private(set) var opens = 0
    private(set) var closes = 0
    private(set) var reads = 0
    func opened() { opens += 1 }
    func closed() { closes += 1 }
    func reading() -> (Int, Int) { reads += 1; return (opens, reads) }
    func counts() -> (Int, Int, Int) { (opens, closes, reads) }
}

final class SourceIntegrityTests: XCTestCase, @unchecked Sendable {
    private func copy(_ f: IntegrityFixture, source: (any RemoteFileService)? = nil,
                      token: CancellationToken = CancellationToken(), hooks: TransferHooks = .init()) async throws -> TransferReport {
        try await SafeTransferEngine(chunkSize: 4).copy(hostID: "local-integrity", source: source ?? f.source, sourcePath: RemotePath("/file"),
            destination: f.destination, destinationPath: RemotePath("/target"), conflict: .overwrite, token: token,
            policy: TransferPolicy(confirmRisk: { if case .overwriteIsAtomicButNotCompareAndSwap = $0 { return true }; return false }), hooks: hooks)
    }
    private func assertFailure(_ report: TransferReport, _ kind: FileServiceError.Kind, _ f: IntegrityFixture,
                               file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertFalse(report.allSucceeded, file: file, line: line)
        if case .failed(let error)? = report.items.last?.state { XCTAssertEqual(error.kind, kind, file: file, line: line) }
        else { XCTFail("Expected \(kind), got \(report.items.map(\.state))", file: file, line: line) }
        XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("target")), Data("original".utf8), file: file, line: line)
        XCTAssertNil(report.items.last?.retainedTemporary, file: file, line: line)
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: f.destinationURL.path)), ["target", "unrelated.part"], file: file, line: line)
    }

    func testRepeatedAndConcurrentRootListHasIndependentOffsets() async throws {
        let f = try IntegrityFixture()
        for name in ["甲.txt", "space file", "quote'$\n"] { try Data(name.utf8).write(to: f.sourceURL.appendingPathComponent(name)) }
        let expected = Set(try ["甲.txt", "space file", "quote'$\n"].map(FileName.init))
        for _ in 0..<3 {
            let names = try await f.source.list(.root, token: CancellationToken()).map(\.name)
            XCTAssertEqual(names.count, expected.count); XCTAssertEqual(Set(names), expected)
        }
        try await withThrowingTaskGroup(of: [FileName].self) { group in
            for _ in 0..<8 { group.addTask { try await f.source.list(.root, token: CancellationToken()).map(\.name) } }
            for try await names in group { XCTAssertEqual(names.count, expected.count); XCTAssertEqual(Set(names), expected) }
        }
        await f.cleanup()
    }

    func testRootPreviewThenCopyTreePreservesExactFileCountAndSHA256() async throws {
        let f = try IntegrityFixture()
        try FileManager.default.createDirectory(at: f.sourceURL.appendingPathComponent("dir 空/leaf"), withIntermediateDirectories: true)
        let files = ["root 中文.txt": Data(repeating: 0xA5, count: 1025), "empty": Data(), "dir 空/子 '$\n": Data([0, 1, 2, 255]), "dir 空/leaf/deep": Data("deep-data".utf8)]
        for (path, bytes) in files { try bytes.write(to: f.sourceURL.appendingPathComponent(path)) }
        let preview = try await f.source.list(.root, token: CancellationToken()); XCTAssertEqual(preview.count, 3)
        let report = try await SafeTransferEngine(chunkSize: 64).copyTree(hostID: "root-copy", source: f.source, sourcePath: .root,
            destination: f.destination, destinationPath: RemotePath("/out"), token: CancellationToken())
        XCTAssertTrue(report.allSucceeded); XCTAssertEqual(report.items.count, 7)
        XCTAssertEqual(report.items.filter { if case .succeeded(let bytes) = $0.state { return bytes > 0 }; return false }.count, 3)
        var received: [String: Data] = [:]
        for path in files.keys {
            if let bytes = try? Data(contentsOf: f.destinationURL.appendingPathComponent("out/" + path)) { received[path] = Data(SHA256.hash(data: bytes)) }
        }
        XCTAssertEqual(received, files.mapValues { Data(SHA256.hash(data: $0)) })
        let copiedRoot = try await f.destination.list(RemotePath("/out"), token: CancellationToken()); XCTAssertEqual(copiedRoot.count, 3)
        await f.cleanup()
    }

    func testEqualLengthSameInodeCrossChunkMutationIsRaceNotMixedSuccess() async throws {
        let f = try IntegrityFixture(); try f.seedFile()
        let before = try await f.source.lstat(RemotePath("/file"), token: CancellationToken())
        let report = try await copy(f, hooks: TransferHooks(progress: { _, bytes in
            if bytes == 4 { do { try f.rewriteSameInode() } catch { XCTFail("Local mutation failed: \(error)") } }
        }))
        let after = try await f.source.lstat(RemotePath("/file"), token: CancellationToken())
        XCTAssertEqual(before.identity, after.identity); XCTAssertEqual(before.size, after.size); XCTAssertEqual(before.modifiedSeconds, after.modifiedSeconds)
        XCTAssertNotEqual(before.modifiedNanoseconds, after.modifiedNanoseconds)
        try assertFailure(report, .raceDetected, f)
        await f.cleanup()
    }

    func testPathReplacementWithEqualSizeAndTimestampIsRace() async throws {
        let f = try IntegrityFixture(); try f.seedFile()
        let before = try await f.source.lstat(RemotePath("/file"), token: CancellationToken())
        let report = try await copy(f, hooks: TransferHooks(progress: { _, bytes in
            if bytes == 4 { do { try f.replacePath() } catch { XCTFail("Local replacement failed: \(error)") } }
        }))
        let after = try await f.source.lstat(RemotePath("/file"), token: CancellationToken())
        XCTAssertNotEqual(before.identity, after.identity); XCTAssertEqual(before.size, after.size)
        XCTAssertEqual(before.modifiedSeconds, after.modifiedSeconds); XCTAssertEqual(before.modifiedNanoseconds, after.modifiedNanoseconds)
        try assertFailure(report, .raceDetected, f)
        await f.cleanup()
    }

    func testSourceMutationAtBeforeCommitIsRaceAndOriginalTargetSurvives() async throws {
        let f = try IntegrityFixture(); try f.seedFile()
        let report = try await copy(f, hooks: TransferHooks(beforeCommit: { _, _ in try f.rewriteSameInode() }))
        try assertFailure(report, .raceDetected, f)
        await f.cleanup()
    }

    func testPathOnlyCoarseMetadataUsesBoundedDigestRecheck() async throws {
        let f = try IntegrityFixture(); try f.seedFile(); let fallback = PathOnlyIntegrityService(f.source)
        let before = try await fallback.lstat(RemotePath("/file"), token: CancellationToken())
        let report = try await copy(f, source: fallback, hooks: TransferHooks(progress: { _, bytes in
            if bytes == 4 { do { try f.rewriteSameInode(nanoseconds: 100_000_000) } catch { XCTFail("Local mutation failed: \(error)") } }
        }))
        let after = try await fallback.lstat(RemotePath("/file"), token: CancellationToken()); XCTAssertEqual(before, after)
        try assertFailure(report, .raceDetected, f)
        await f.cleanup()
    }

    func testFinalSourcePathBecomingSymlinkIsRejectedWithoutFollowing() async throws {
        let f = try IntegrityFixture(); try f.seedFile()
        try Data("outside-data".utf8).write(to: f.sourceURL.appendingPathComponent("other"))
        let report = try await copy(f, hooks: TransferHooks(beforeCommit: { _, _ in
            try FileManager.default.removeItem(at: f.sourceURL.appendingPathComponent("file"))
            guard symlink("other", f.sourceURL.appendingPathComponent("file").path) == 0 else { throw FileServiceError(.io, operation: "test-symlink") }
        }))
        try assertFailure(report, .raceDetected, f)
        XCTAssertEqual(try Data(contentsOf: f.sourceURL.appendingPathComponent("other")), Data("outside-data".utf8))
        await f.cleanup()
    }

    func testOpenedHandleStatRetainsIdentityAcrossPathReplacementAndDoesNotAdvanceOffset() async throws {
        let f = try IntegrityFixture(); try f.seedFile(); let token = CancellationToken(), path = try RemotePath("/file")
        let handle = try await f.source.open(path, mode: .read, token: token)
        let initial = try await f.source.fstat(handle, token: token)
        let before = try await f.source.lstat(path, token: token)
        XCTAssertEqual(initial, before)
        try f.replacePath()
        let retained = try await f.source.fstat(handle, token: token), replacement = try await f.source.lstat(path, token: token)
        XCTAssertEqual(retained?.identity, before.identity); XCTAssertNotEqual(retained?.identity, replacement.identity)
        let bytes = try await f.source.read(handle, maxBytes: 8, token: token); XCTAssertEqual(bytes, Data("AAAABBBB".utf8))
        try await f.source.closeHandle(handle)
        do { _ = try await f.source.fstat(handle, token: token); XCTFail("Closed handle cannot be statted") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        let compatibilityHandle = try await f.source.open(path, mode: .read, token: token)
        let fallback = try await PathOnlyIntegrityService(f.source).fstat(compatibilityHandle, token: token); XCTAssertNil(fallback)
        try await f.source.closeHandle(compatibilityHandle)
        await f.cleanup()
    }

    func testCancellationDuringWeakDigestRecheckStopsOnceAndClosesBothHandles() async throws {
        let f = try IntegrityFixture(); try f.seedFile(); let counts = IntegrityIOCounts(), token = CancellationToken()
        let fallback = PathOnlyIntegrityService(f.source, onOpen: { await counts.opened() }, onRead: { token in
            let (opens, _) = await counts.reading(); if opens == 2 { token.cancel() }
        }, onCloseHandle: { await counts.closed() })
        let report = try await copy(f, source: fallback, token: token)
        try assertFailure(report, .cancelled, f)
        let (opens, closes, _) = await counts.counts(); XCTAssertEqual(opens, 2); XCTAssertEqual(closes, 2)
        await f.cleanup()
    }

    func testGrowingWeakSourceRecheckIsBoundedAndDoesNotRetry() async throws {
        let f = try IntegrityFixture(); try f.seedFile(); let counts = IntegrityIOCounts()
        let fallback = PathOnlyIntegrityService(f.source, onOpen: { await counts.opened() }, onRead: { _ in
            let (opens, _) = await counts.reading()
            if opens == 2 {
                let fd = Darwin.open(f.sourceURL.appendingPathComponent("file").path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { throw FileServiceError(.io, operation: "test-open") }; defer { Darwin.close(fd) }
                let data = Data("more".utf8)
                guard data.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress, $0.count) }) == data.count else { throw FileServiceError(.io, operation: "test-append") }
            }
        }, onCloseHandle: { await counts.closed() })
        let report = try await copy(f, source: fallback)
        try assertFailure(report, .raceDetected, f)
        let (opens, closes, reads) = await counts.counts(); XCTAssertEqual(opens, 2); XCTAssertEqual(closes, 2)
        XCTAssertLessThanOrEqual(reads, 6)
        await f.cleanup()
    }

    func testCloseDuringSourceReadPreservesClosedFailureAndCleansTemporary() async throws {
        let f = try IntegrityFixture(); try f.seedFile()
        let report = try await copy(f, hooks: TransferHooks(progress: { _, bytes in if bytes == 4 { await f.source.close() } }))
        try assertFailure(report, .closed, f)
        await f.cleanup()
    }

    func testStaticStrongAndPathOnlySourcesStillCopySuccessfully() async throws {
        for fallback in [false, true] {
            let f = try IntegrityFixture(); try f.seedFile()
            let report = try await copy(f, source: fallback ? PathOnlyIntegrityService(f.source) : f.source)
            XCTAssertTrue(report.allSucceeded); XCTAssertEqual(report.items.last?.state, .succeeded(bytes: 8))
            XCTAssertEqual(try Data(contentsOf: f.destinationURL.appendingPathComponent("target")), Data("AAAABBBB".utf8))
            await f.cleanup()
        }
    }

    func testCancellationWinsOverConcurrentSourceMutationAndCleansTemporary() async throws {
        let f = try IntegrityFixture(); try f.seedFile(); let token = CancellationToken()
        let report = try await copy(f, token: token, hooks: TransferHooks(beforeCommit: { _, _ in try f.rewriteSameInode(); token.cancel() }))
        try assertFailure(report, .cancelled, f)
        await f.source.close(); await f.source.close()
        do { _ = try await f.source.list(.root, token: CancellationToken()); XCTFail("Source must be closed") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        await f.cleanup()
    }
}
