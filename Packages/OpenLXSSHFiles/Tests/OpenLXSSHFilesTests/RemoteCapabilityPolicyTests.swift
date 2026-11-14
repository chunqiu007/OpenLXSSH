import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

/// These test-created local fixture paths are known UTF-8. Decode strictly and preserve
/// their exact absolute POSIX bytes; do not import the application's display/escaping UI.
private func fixtureUTF8Path(_ path: RemotePath) throws -> String {
    guard let text = String(data: path.bytes, encoding: .utf8), Data(text.utf8) == path.bytes,
          try RemotePath(text).bytes == path.bytes else {
        throw FileServiceError(.invalidPath, operation: "test-fixture-noncanonical-utf8-path", path: path)
    }
    return text
}

/// Capability policy fixture over REAL local FD I/O, not SFTP and not a claim that a server supports
/// any feature. Exposes remote-style lstat risk/confirmation to exercise the production transfer engine.
private final class RemoteSemanticsFixture: RemoteFileService, @unchecked Sendable {
    let capabilities = FileServiceCapabilities(traversal: .remoteComponentLstat, exclusiveCreate: true,
        noReplace: .needsServerConfirmation, canAttemptAtomicReplace: true)
    let serverBinding: UUID? = UUID()
    let local: LocalFileService
    let root: URL
    let fsyncUnavailable: Bool
    var rejectProbeWrites = false
    var unsafeRename = false
    var unsupportedRename = false
    var mkdirAfterCreateFailure: FileServiceError.Kind?
    var partOpenAfterCreateFailure: FileServiceError.Kind?
    var beforeProbeWrite: (@Sendable (CancellationToken) async throws -> Void)?
    var beforeProbeCleanup: (@Sendable () throws -> Void)?
    private(set) var probeParents: [RemotePath] = []
    init(root: URL, fsyncUnavailable: Bool = false) throws {
        self.root = root; self.fsyncUnavailable = fsyncUnavailable
        local = try LocalFileService(root: root)
    }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await local.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await local.lstat(p, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        if mode == .exclusiveWrite && p.bytes.range(of: Data(".openlxssh-capability.".utf8)) != nil {
            try await beforeProbeWrite?(token)
        }
        let handle = try await local.open(p, mode: mode, token: token)
        if mode == .exclusiveWrite, p.name?.bytes.starts(with: Data(".openlxssh-transfer.".utf8)) == true,
           let failure = partOpenAfterCreateFailure {
            try await local.closeHandle(handle)
            throw FileServiceError(failure, operation: "fixture-open-ack-lost", path: p, code: 7191)
        }
        return handle
    }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await local.read(h, maxBytes: maxBytes, token: token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await local.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws {
        if fsyncUnavailable { throw FileServiceError(.unsupported, operation: "fixture-no-fsync-extension") }
        try await local.finish(h, token: token)
    }
    func closeHandle(_ h: FileHandleID) async throws { try await local.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws {
        if p.name?.bytes.starts(with: Data(".openlxssh-capability.".utf8)) == true {
            probeParents.append(p.parent)
            if rejectProbeWrites { throw FileServiceError(.permissionDenied, operation: "fixture-probe-mkdir", path: p) }
        }
        try await local.mkdir(p, token: token)
        if p.name?.bytes.starts(with: Data(".openlxssh-capability.".utf8)) == true, let failure = mkdirAfterCreateFailure {
            throw FileServiceError(failure, operation: "fixture-mkdir-ack-lost", path: p, code: 7190)
        }
    }
    func rename(_ s: RemotePath, to d: RemotePath, mode: RenameMode, token: CancellationToken) async throws {
        guard mode == .noReplace else { throw FileServiceError(.unsupported, operation: "fixture-no-posix-extension") }
        if unsupportedRename { throw FileServiceError(.unsupported, operation: "fixture-no-rename") }
        if unsafeRename {
            try token.check()
            guard Darwin.rename(root.path + (try fixtureUTF8Path(s)), root.path + (try fixtureUTF8Path(d))) == 0 else {
                throw FileServiceError(.io, operation: "fixture-unsafe-rename", code: Int64(errno))
            }
        } else { try await local.rename(s, to: d, mode: mode, token: token) }
    }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws {
        if p.bytes.range(of: Data(".openlxssh-capability.".utf8)) != nil { try beforeProbeCleanup?() }
        try await local.remove(p, directory: directory, token: token)
    }
    func cancel() { local.cancel() }
    func close() async { await local.close() }
}
private actor DirectConflictAnswerCount {
    private(set) var count = 0
    func skip() -> ConflictDecision { count += 1; return .skip }
    func overwrite() -> ConflictDecision { count += 1; return .overwrite }
}
final class RemoteCapabilityPolicyTests: XCTestCase, @unchecked Sendable {
    private func roots() throws -> (URL, URL, URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("P3-capabilities-\(UUID().uuidString)")
        let a = root.appendingPathComponent("a"); let b = root.appendingPathComponent("b")
        try FileManager.default.createDirectory(at: a, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: b, withIntermediateDirectories: true)
        return (root, a, b)
    }
    private func kind(_ report: TransferReport) -> FileServiceError.Kind? {
        if case .failed(let e)? = report.items.last?.state { return e.kind }; return nil
    }
    func testComponentCheckedDownloadWorksWithExplicitRiskButNoServerCommitConfirmation() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: a.appendingPathComponent("dir"), withIntermediateDirectories: false)
        let bytes = Data((0..<170001).map { UInt8(truncatingIfNeeded: $0) }); try bytes.write(to: a.appendingPathComponent("dir/中文 $ file"))
        let source = try RemoteSemanticsFixture(root: a); let local = try LocalFileService(root: b)
        let engine = SafeTransferEngine(chunkSize: 4096)
        let rejected = try await engine.copy(hostID: "fixture", source: source, sourcePath: RemotePath("/dir/中文 $ file"),
            destination: local, destinationPath: RemotePath("/download"), token: CancellationToken())
        XCTAssertEqual(kind(rejected), .riskRejected)
        let accepted = try await engine.copy(hostID: "fixture", source: source, sourcePath: RemotePath("/dir/中文 $ file"),
            destination: local, destinationPath: RemotePath("/download"), token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { if case .remotePathChecksAreNotAtomic = $0 { return true }; return false }))
        XCTAssertTrue(accepted.allSucceeded)
        XCTAssertEqual(SHA256.hash(data: try Data(contentsOf: b.appendingPathComponent("download"))), SHA256.hash(data: bytes))
        XCTAssertEqual(accepted.items.first?.acknowledgedRisks.count, 1)
        await source.close(); await local.close()
    }
    func testUploadAutomaticallyVerifiesScopedServerAndPreservesRacingOriginal() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let bytes = Data((0..<94001).map { UInt8(truncatingIfNeeded: $0 * 7) }); try bytes.write(to: a.appendingPathComponent("file"))
        let source = try LocalFileService(root: a); let destination = try RemoteSemanticsFixture(root: b)
        let engine = SafeTransferEngine()
        let success = try await engine.copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
            destination: destination, destinationPath: RemotePath("/new"), token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { _ in true }))
        XCTAssertTrue(success.allSucceeded)
        XCTAssertEqual(destination.probeParents, [.root])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: b.path), ["new"])
        XCTAssertEqual(SHA256.hash(data: try Data(contentsOf: b.appendingPathComponent("new"))), SHA256.hash(data: bytes))
        let competing = Data("competitor".utf8)
        let race = try await engine.copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
            destination: destination, destinationPath: RemotePath("/racing"), token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { _ in true }),
            hooks: TransferHooks(beforeCommit: { _, _ in try competing.write(to: b.appendingPathComponent("racing")) }))
        XCTAssertEqual(kind(race), .conflict)
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("racing")), competing)
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: b.path)), ["new", "racing"])
        await source.close(); await destination.close()
    }
    func testAutomaticProbeRejectsUnsafeOrUnsupportedRenameAndPermissionWithoutTouchingOriginals() async throws {
        for behavior in ["unsafe", "unsupported", "permission"] {
            let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
            let original = Data("preserve me".utf8)
            try Data("upload".utf8).write(to: a.appendingPathComponent("file")); try original.write(to: b.appendingPathComponent("unrelated"))
            let source = try LocalFileService(root: a), remote = try RemoteSemanticsFixture(root: b)
            remote.unsafeRename = behavior == "unsafe"; remote.unsupportedRename = behavior == "unsupported"; remote.rejectProbeWrites = behavior == "permission"
            let result = try await SafeTransferEngine().copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
                destination: remote, destinationPath: RemotePath("/new"), token: CancellationToken(), policy: TransferPolicy(confirmRisk: { _ in true }))
            XCTAssertEqual(kind(result), behavior == "permission" ? .permissionDenied : .unsupported)
            XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("unrelated")), original)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: b.path), ["unrelated"])
            XCTAssertNil(result.items.first?.retainedTemporary)
            await source.close(); await remote.close()
        }
    }
    func testAutomaticProbeCancellationAndFailedCleanupReportOnlyOwnedDirectory() async throws {
        for retained in [false, true] {
            let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
            try Data("upload".utf8).write(to: a.appendingPathComponent("file")); let keep = Data("keep".utf8); try keep.write(to: b.appendingPathComponent("unrelated"))
            let source = try LocalFileService(root: a), remote = try RemoteSemanticsFixture(root: b), token = CancellationToken()
            remote.beforeProbeWrite = { token in token.cancel(); try token.check() }
            if retained { remote.beforeProbeCleanup = { throw FileServiceError(.permissionDenied, operation: "fixture-cleanup-denied") } }
            let result = try await SafeTransferEngine().copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
                destination: remote, destinationPath: RemotePath("/new"), token: token, policy: TransferPolicy(confirmRisk: { _ in true }))
            XCTAssertEqual(kind(result), .cancelled)
            XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("unrelated")), keep)
            let remaining = try FileManager.default.contentsOfDirectory(atPath: b.path)
            XCTAssertEqual(remaining.count, retained ? 2 : 1)
            if retained {
                let path = try XCTUnwrap(result.items.first?.retainedTemporary)
                XCTAssertTrue(path.name?.bytes.starts(with: Data(".openlxssh-capability.".utf8)) == true)
                XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: b.path + (try fixtureUTF8Path(path))), [])
            } else { XCTAssertNil(result.items.first?.retainedTemporary) }
            XCTAssertFalse(FileManager.default.fileExists(atPath: b.appendingPathComponent("new").path))
            await source.close(); await remote.close()
        }
    }
    func testAutomaticTreeUploadChecksEachActualParentAndRejectsCrossParentCommitEvidence() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: a.appendingPathComponent("目录/子目录"), withIntermediateDirectories: true)
        try Data("第一".utf8).write(to: a.appendingPathComponent("目录/中文.txt")); try Data("第二".utf8).write(to: a.appendingPathComponent("目录/子目录/另一个.txt"))
        let source = try LocalFileService(root: a), remote = try RemoteSemanticsFixture(root: b)
        let report = try await SafeTransferEngine().copyTree(hostID: "fixture", source: source, sourcePath: RemotePath("/目录"),
            destination: remote, destinationPath: RemotePath("/副本"), token: CancellationToken(), policy: TransferPolicy(confirmRisk: { _ in true }))
        XCTAssertTrue(report.allSucceeded)
        XCTAssertEqual(Set(remote.probeParents), [try RemotePath("/副本"), try RemotePath("/副本/子目录")])
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("副本/中文.txt")), Data("第一".utf8))
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("副本/子目录/另一个.txt")), Data("第二".utf8))
        let wrongParent = try ServerCommitConfirmation(serverBinding: XCTUnwrap(remote.serverBinding), parent: .root, evidence: "root only")
        do {
            try await remote.commit(RemotePath("/副本/中文.txt"), to: RemotePath("/副本/renamed"),
                request: .init(mode: .noReplace, serverConfirmation: wrongParent), token: CancellationToken())
            XCTFail("An unrelated directory's evidence must not authorize this commit")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .needsCapabilityConfirmation) }
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("副本/中文.txt")), Data("第一".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath: b.appendingPathComponent("副本/renamed").path))
        await source.close(); await remote.close()
    }
    func testLostExclusiveCreateAcknowledgementReportsCandidateWithoutDeletingUnprovenObject() async throws {
        for kind in [FileServiceError.Kind.timeout, .cancelled, .transport] {
            for directory in [true, false] {
                let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
                let original = Data("original unchanged".utf8)
                try Data("upload".utf8).write(to: a.appendingPathComponent("file")); try original.write(to: b.appendingPathComponent("original"))
                let source = try LocalFileService(root: a), remote = try RemoteSemanticsFixture(root: b)
                if directory { remote.mkdirAfterCreateFailure = kind } else { remote.partOpenAfterCreateFailure = kind }
                let report = try await SafeTransferEngine().copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
                    destination: remote, destinationPath: RemotePath("/new"), token: CancellationToken(), policy: TransferPolicy(confirmRisk: { _ in true }))
                let item = try XCTUnwrap(report.items.first), candidate = try XCTUnwrap(item.retainedTemporary)
                guard case .failed(let error) = item.state else { return XCTFail("Uncertain create cannot be reported successful") }
                XCTAssertEqual(error.kind, kind)
                XCTAssertEqual(error.operation, directory ? "probe-directory-create-outcome-uncertain" : "transfer-file-create-outcome-uncertain")
                XCTAssertEqual(error.code, directory ? 7190 : 7191)
                XCTAssertEqual(candidate.parent, .root)
                XCTAssertTrue(candidate.name?.bytes.starts(with: Data((directory ? ".openlxssh-capability." : ".openlxssh-transfer.").utf8)) == true)
                XCTAssertTrue(FileManager.default.fileExists(atPath: b.path + (try fixtureUTF8Path(candidate))), "Do not remove an object whose create acknowledgement was lost")
                XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("original")), original)
                XCTAssertFalse(FileManager.default.fileExists(atPath: b.appendingPathComponent("new").path))
                XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: b.path).count, 2)
                await source.close(); await remote.close()
            }
        }
    }
    func testRemoteAncestorLinkRejectedEvenAfterUserAcceptsResidualRisk() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: a.appendingPathComponent("real"), withIntermediateDirectories: false)
        try Data([1, 2, 3]).write(to: a.appendingPathComponent("real/file"))
        XCTAssertEqual(symlink("real", a.appendingPathComponent("link").path), 0)
        let source = try RemoteSemanticsFixture(root: a); let destination = try LocalFileService(root: b)
        let report = try await SafeTransferEngine().copy(hostID: "fixture", source: source, sourcePath: RemotePath("/link/file"),
            destination: destination, destinationPath: RemotePath("/new"), token: CancellationToken(), policy: TransferPolicy(confirmRisk: { _ in true }))
        XCTAssertEqual(kind(report), .symbolicLink)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: b.path).isEmpty)
        await source.close(); await destination.close()
    }
    func testFsyncUnsupportedRequiresAdditionalExplicitRiskAcknowledgement() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let bytes = Data([8, 9, 10]); try bytes.write(to: a.appendingPathComponent("file"))
        let source = try LocalFileService(root: a)
        let destination = try RemoteSemanticsFixture(root: b, fsyncUnavailable: true)
        let evidence = try ServerCommitConfirmation(serverBinding: XCTUnwrap(destination.serverBinding), evidence: "local fixture only")
        let engine = SafeTransferEngine()
        let refused = try await engine.copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"), destination: destination,
            destinationPath: RemotePath("/new"), token: CancellationToken(), policy: TransferPolicy(confirmRisk: { risk in
                if case .remoteFsyncUnavailable = risk { return false }; return true
            }, serverCommit: evidence))
        XCTAssertEqual(kind(refused), .riskRejected)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: b.path).isEmpty)
        let accepted = try await engine.copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"), destination: destination,
            destinationPath: RemotePath("/new"), token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { _ in true }, serverCommit: evidence))
        XCTAssertTrue(accepted.allSucceeded)
        XCTAssertTrue(accepted.items.first?.acknowledgedRisks.contains(.remoteFsyncUnavailable(path: try RemotePath("/new"))) == true)
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("new")), bytes)
        await source.close(); await destination.close()
    }
    func testFingerprintDetectsEqualSizeContentChangeWithSameSuppliedMetadata() async throws {
        let (root, a, _) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let path = try RemotePath("/target"); let before = Data("before".utf8); let after = Data("racing".utf8)
        try before.write(to: a.appendingPathComponent("target"))
        let local = try LocalFileService(root: a)
        let digest = try await TransferChecks.contentFingerprint(local, path: path, token: CancellationToken())
        try after.write(to: a.appendingPathComponent("target"))
        // Supplying current attrs deliberately bypasses the metadata branch. The old content hash
        // must still detect the equal-length difference; no synthetic filesystem backend is used.
        let current = try await local.lstat(path, token: CancellationToken())
        do {
            try await TransferChecks.requireUnchanged(local, path: path, expected: current, digest: digest, token: CancellationToken())
            XCTFail("content fingerprint must detect same-size change")
        } catch let e as FileServiceError { XCTAssertEqual(e.kind, .raceDetected); XCTAssertEqual(e.operation, "target-fingerprint-changed") }
        XCTAssertEqual(try Data(contentsOf: a.appendingPathComponent("target")), after)
        await local.close()
    }
    func testExplicitNoReplaceProbeUsesOnlyOwnedDirectoryAndDoesNotAutoApprove() async throws {
        let (root, a, _) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try RemoteSemanticsFixture(root: a)
        let plan = try ServerCommitProbe.prepare(service: fixture, parent: .root)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: a.path).isEmpty)
        do {
            _ = try await ServerCommitProbe.run(plan, service: fixture, hostID: "fixture", approvedPlanID: UUID(),
                acknowledgedRisks: plan.requiredRisks, token: CancellationToken()); XCTFail("must not auto approve")
        } catch let e as FileServiceError { XCTAssertEqual(e.kind, .riskRejected) }
        let result = try await ServerCommitProbe.run(plan, service: fixture, hostID: "fixture", approvedPlanID: plan.id,
            acknowledgedRisks: plan.requiredRisks, token: CancellationToken())
        XCTAssertTrue(result.passed); XCTAssertNotNil(result.confirmation); XCTAssertTrue(result.retainedPaths.isEmpty)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: a.path).isEmpty)
        // Only a local capability-policy fixture was probed. This creates no SFTP interoperability evidence.
        await fixture.close()
    }
    func testTransferCleanupFailureReturnsOwnedTemporaryWithoutScanningOtherFiles() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let file = Data((0..<20000).map { UInt8(truncatingIfNeeded: $0) }); try file.write(to: a.appendingPathComponent("file"))
        let unrelated = Data("keep".utf8); try unrelated.write(to: b.appendingPathComponent("unrelated"))
        let source = try LocalFileService(root: a); let destination = try LocalFileService(root: b)
        let token = CancellationToken()
        let result = try await SafeTransferEngine(chunkSize: 4096).copy(hostID: "fixture", source: source,
            sourcePath: RemotePath("/file"), destination: destination, destinationPath: RemotePath("/new"), token: token,
            hooks: TransferHooks(progress: { _, _ in token.cancel(); destination.cancel() }))
        XCTAssertEqual(kind(result), .cancelled)
        let temporary = try XCTUnwrap(result.items.first?.retainedTemporary)
        XCTAssertTrue(String(decoding: temporary.bytes, as: UTF8.self).hasPrefix("/.openlxssh-transfer."))
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("unrelated")), unrelated)
        let remaining = try FileManager.default.contentsOfDirectory(atPath: b.path)
        XCTAssertEqual(remaining.count, 2); XCTAssertFalse(remaining.contains("new"))
        await source.close(); await destination.close()
    }
    func testUnsupportedAtomicReplaceNeverFallsBackOrDeletesOriginal() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        try Data([1, 2, 3]).write(to: a.appendingPathComponent("file")); let old = Data("old".utf8); try old.write(to: b.appendingPathComponent("target"))
        let source = try LocalFileService(root: a); let destination = try RemoteSemanticsFixture(root: b)
        let report = try await SafeTransferEngine().copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
            destination: destination, destinationPath: RemotePath("/target"), conflict: .overwrite, token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { _ in true }))
        XCTAssertEqual(kind(report), .unsupported)
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("target")), old)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: b.path), ["target"])
        await source.close(); await destination.close()
    }

    func testDirectDirectoryIntoRegularForcedOverwriteAsksOnceAndPreservesOriginal() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: a.appendingPathComponent("source"), withIntermediateDirectories: false)
        let incoming = Data("incoming child".utf8), original = Data("original file".utf8)
        try incoming.write(to: a.appendingPathComponent("source/child"))
        try original.write(to: b.appendingPathComponent("target"))
        var before = stat(); XCTAssertEqual(lstat(b.appendingPathComponent("target").path, &before), 0)
        let source = try LocalFileService(root: a), destination = try LocalFileService(root: b), answers = DirectConflictAnswerCount()
        let report = try await SafeTransferEngine().copyTree(hostID: "direct", source: source, sourcePath: RemotePath("/source"),
            destination: destination, destinationPath: RemotePath("/target"), token: CancellationToken(), policy: TransferPolicy(acceptsTechnicalLimits: true),
            hooks: TransferHooks(resolveConflict: { conflict in
                XCTAssertEqual(conflict.sourceKind, .directory); XCTAssertEqual(conflict.existing.kind, .regular)
                return await answers.overwrite()
            }))
        let count = await answers.count; XCTAssertEqual(count, 1)
        XCTAssertEqual(kind(report), .conflict); XCTAssertTrue(report.items.allSatisfy { $0.retainedTemporary == nil })
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("target")), original)
        XCTAssertEqual(try Data(contentsOf: a.appendingPathComponent("source/child")), incoming)
        var after = stat(); XCTAssertEqual(lstat(b.appendingPathComponent("target").path, &after), 0)
        XCTAssertEqual(after.st_dev, before.st_dev); XCTAssertEqual(after.st_ino, before.st_ino)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: b.path), ["target"])
        await source.close(); await destination.close()
    }
    func testLateNoReplaceCollisionHonorsSingleSkipAnswerAndKeepsRacingOriginal() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let incoming = Data("incoming".utf8), racing = Data("racing original".utf8)
        try incoming.write(to: a.appendingPathComponent("file"))
        let source = try LocalFileService(root: a), destination = try LocalFileService(root: b), answers = DirectConflictAnswerCount()
        let report = try await SafeTransferEngine().copy(hostID: "direct", source: source, sourcePath: RemotePath("/file"), destination: destination,
            destinationPath: RemotePath("/target"), token: CancellationToken(), policy: TransferPolicy(acceptsTechnicalLimits: true),
            hooks: TransferHooks(beforeCommit: { _, _ in try racing.write(to: b.appendingPathComponent("target")) }, resolveConflict: { _ in await answers.skip() }))
        XCTAssertEqual(report.items.first?.state, .skipped)
        let count = await answers.count; XCTAssertEqual(count, 1)
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("target")), racing)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: b.path), ["target"])
        await source.close(); await destination.close()
    }
    func testDirectPolicyTransfersWithoutRiskWaitAndReusesOnlyScopedSuccessfulProof() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let payload = Data("direct 中文".utf8); try payload.write(to: a.appendingPathComponent("file"))
        let source = try LocalFileService(root: a), remote = try RemoteSemanticsFixture(root: b, fsyncUnavailable: true)
        let engine = SafeTransferEngine(), policy = TransferPolicy(acceptsTechnicalLimits: true)
        for name in ["one", "two"] {
            let report = try await engine.copy(hostID: "direct", source: source, sourcePath: RemotePath("/file"), destination: remote,
                destinationPath: RemotePath("/" + name), token: CancellationToken(), policy: policy)
            XCTAssertTrue(report.allSucceeded)
            XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent(name)), payload)
        }
        XCTAssertEqual(remote.probeParents, [.root], "One successful check is reused for this exact service and parent")
        try FileManager.default.createDirectory(at: b.appendingPathComponent("other"), withIntermediateDirectories: false)
        let other = try await engine.copy(hostID: "direct", source: source, sourcePath: RemotePath("/file"), destination: remote,
            destinationPath: RemotePath("/other/three"), token: CancellationToken(), policy: policy)
        XCTAssertTrue(other.allSucceeded); XCTAssertEqual(remote.probeParents, [.root, try RemotePath("/other")])
        await remote.close()
        let replacement = try RemoteSemanticsFixture(root: b)
        let fresh = try await engine.copy(hostID: "direct", source: source, sourcePath: RemotePath("/file"), destination: replacement,
            destinationPath: RemotePath("/four"), token: CancellationToken(), policy: policy)
        XCTAssertTrue(fresh.allSucceeded); XCTAssertEqual(replacement.probeParents, [.root], "New connection gets its own evidence")
        await source.close(); await replacement.close()
    }
    func testDirectAutoRenameKeepsOriginalBytesAndRetriesCommitCollisionWithoutOverwrite() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let original = Data("original".utf8), incoming = Data("incoming".utf8)
        try incoming.write(to: a.appendingPathComponent("file")); try original.write(to: b.appendingPathComponent("report.zip"))
        let source = try LocalFileService(root: a), destination = try LocalFileService(root: b)
        let report = try await SafeTransferEngine().copy(hostID: "direct", source: source, sourcePath: RemotePath("/file"), destination: destination,
            destinationPath: RemotePath("/report.zip"), token: CancellationToken(), policy: TransferPolicy(acceptsTechnicalLimits: true),
            hooks: TransferHooks(beforeCommit: { _, path in
                if path == (try RemotePath("/report (1).zip")) { try original.write(to: b.appendingPathComponent("report (1).zip")) }
            }, resolveConflict: { _ in .autoRename }))
        XCTAssertTrue(report.allSucceeded); XCTAssertEqual(report.items.first?.destination, try RemotePath("/report (2).zip"))
        for name in ["report.zip", "report (1).zip"] { XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent(name)), original) }
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("report (2).zip")), incoming)
        XCTAssertEqual(try SafeTransferEngine.automaticName(FileName(bytes: Data([0xff, 46, 122])), index: 3).bytes, Data([0xff]) + Data(" (3).z".utf8))
        XCTAssertEqual(try SafeTransferEngine.automaticName(FileName(".hidden"), index: 1), try FileName(".hidden (1)"))
        await source.close(); await destination.close()
    }
    func testDirectTreeRootAutoRenameDoesNotMergeOrTouchOriginalDirectory() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: a.appendingPathComponent("目录"), withIntermediateDirectories: false)
        try Data("new".utf8).write(to: a.appendingPathComponent("目录/new.txt"))
        try FileManager.default.createDirectory(at: b.appendingPathComponent("目录"), withIntermediateDirectories: false)
        let original = Data("keep".utf8); try original.write(to: b.appendingPathComponent("目录/original.txt"))
        let source = try LocalFileService(root: a), destination = try LocalFileService(root: b)
        let report = try await SafeTransferEngine().copyTree(hostID: "direct", source: source, sourcePath: RemotePath("/目录"), destination: destination,
            destinationPath: RemotePath("/目录"), token: CancellationToken(), policy: TransferPolicy(acceptsTechnicalLimits: true),
            hooks: TransferHooks(resolveConflict: { _ in .autoRename }))
        XCTAssertTrue(report.allSucceeded)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: b.appendingPathComponent("目录").path), ["original.txt"])
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("目录/original.txt")), original)
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("目录 (1)/new.txt")), Data("new".utf8))
        await source.close(); await destination.close()
    }
    func testDirectManagerCapturesConflictPolicyAndDoesNotCreateTechnicalDecision() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        try Data("incoming".utf8).write(to: a.appendingPathComponent("file")); try Data("keep".utf8).write(to: b.appendingPathComponent("file"))
        let source = try LocalFileService(root: a), destination = try RemoteSemanticsFixture(root: b, fsyncUnavailable: true)
        let manager = TransferManager(idleTimeout: nil, executionMode: .direct, conflictPolicy: .autoRename)
        let sid = try await manager.registerService(source), did = try await manager.registerService(destination, hostID: "direct")
        let id = try await manager.enqueue(TransferRequest(hostID: "direct", source: .init(serviceID: sid, path: RemotePath("/file")), destination: .init(serviceID: did, path: RemotePath("/file"))))
        await manager.setConflictPolicy(.overwrite)
        let deadline = ContinuousClock.now + .seconds(5)
        while true {
            let jobs = await manager.snapshot().jobs
            let job = try XCTUnwrap(jobs.first { $0.id == id })
            XCTAssertNil(job.pendingDecision); XCTAssertNotEqual(job.state, .waitingRisk)
            if !job.state.isActive { XCTAssertEqual(job.state, .succeeded); XCTAssertEqual(job.items.first?.destination, try RemotePath("/file (1)")); break }
            guard .now < deadline else { XCTFail("Direct transfer unexpectedly waits"); break }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("file")), Data("keep".utf8))
        await manager.cancelAllAndWait()
    }
}
