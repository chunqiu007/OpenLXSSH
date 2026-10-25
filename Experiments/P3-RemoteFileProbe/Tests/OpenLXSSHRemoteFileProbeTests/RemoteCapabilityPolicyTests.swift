import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHRemoteFileProbe

/// Capability policy fixture over REAL local FD I/O, not SFTP and not a claim that a server supports
/// any feature. Exposes remote-style lstat risk/confirmation to exercise the production transfer engine.
private final class RemoteSemanticsFixture: RemoteFileService, @unchecked Sendable {
    let capabilities = FileServiceCapabilities(traversal: .remoteComponentLstat, exclusiveCreate: true,
        noReplace: .needsServerConfirmation, canAttemptAtomicReplace: true)
    let serverBinding: UUID? = UUID()
    let local: LocalFixtureFileService
    let root: URL
    let fsyncUnavailable: Bool
    init(root: URL, fsyncUnavailable: Bool = false) throws {
        self.root = root; self.fsyncUnavailable = fsyncUnavailable
        local = try LocalFixtureFileService(root: root)
    }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await local.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await local.lstat(p, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await local.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await local.read(h, maxBytes: maxBytes, token: token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await local.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws {
        if fsyncUnavailable { throw FileServiceError(.unsupported, operation: "fixture-no-fsync-extension") }
        try await local.finish(h, token: token)
    }
    func closeHandle(_ h: FileHandleID) async throws { try await local.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await local.mkdir(p, token: token) }
    func rename(_ s: RemotePath, to d: RemotePath, mode: RenameMode, token: CancellationToken) async throws {
        guard mode == .noReplace else { throw FileServiceError(.unsupported, operation: "fixture-no-posix-extension") }
        try await local.rename(s, to: d, mode: mode, token: token)
    }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await local.remove(p, directory: directory, token: token) }
    func cancel() { local.cancel() }
    func close() async { await local.close() }
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
        let source = try RemoteSemanticsFixture(root: a); let local = try LocalFixtureFileService(root: b)
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
    func testUploadRequiresScopedServerEvidenceThenUsesRealExclusiveTempAndNoReplace() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let bytes = Data((0..<94001).map { UInt8(truncatingIfNeeded: $0 * 7) }); try bytes.write(to: a.appendingPathComponent("file"))
        let source = try LocalFixtureFileService(root: a); let destination = try RemoteSemanticsFixture(root: b)
        let engine = SafeTransferEngine()
        let blocked = try await engine.copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
            destination: destination, destinationPath: RemotePath("/new"), token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { _ in true }))
        XCTAssertEqual(kind(blocked), .needsCapabilityConfirmation)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: b.path).isEmpty)
        let evidence = try ServerCommitConfirmation(serverBinding: XCTUnwrap(destination.serverBinding), evidence: "local fixture RENAME_EXCL, not SFTP evidence")
        let success = try await engine.copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
            destination: destination, destinationPath: RemotePath("/new"), token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { _ in true }, serverCommit: evidence))
        XCTAssertTrue(success.allSucceeded)
        XCTAssertEqual(SHA256.hash(data: try Data(contentsOf: b.appendingPathComponent("new"))), SHA256.hash(data: bytes))
        let competing = Data("competitor".utf8)
        let race = try await engine.copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
            destination: destination, destinationPath: RemotePath("/racing"), token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { _ in true }, serverCommit: evidence),
            hooks: TransferHooks(beforeCommit: { _, _ in try competing.write(to: b.appendingPathComponent("racing")) }))
        XCTAssertEqual(kind(race), .conflict)
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("racing")), competing)
        await source.close(); await destination.close()
    }
    func testRemoteAncestorLinkRejectedEvenAfterUserAcceptsResidualRisk() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: a.appendingPathComponent("real"), withIntermediateDirectories: false)
        try Data([1, 2, 3]).write(to: a.appendingPathComponent("real/file"))
        XCTAssertEqual(symlink("real", a.appendingPathComponent("link").path), 0)
        let source = try RemoteSemanticsFixture(root: a); let destination = try LocalFixtureFileService(root: b)
        let report = try await SafeTransferEngine().copy(hostID: "fixture", source: source, sourcePath: RemotePath("/link/file"),
            destination: destination, destinationPath: RemotePath("/new"), token: CancellationToken(), policy: TransferPolicy(confirmRisk: { _ in true }))
        XCTAssertEqual(kind(report), .symbolicLink)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: b.path).isEmpty)
        await source.close(); await destination.close()
    }
    func testFsyncUnsupportedRequiresAdditionalExplicitRiskAcknowledgement() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        let bytes = Data([8, 9, 10]); try bytes.write(to: a.appendingPathComponent("file"))
        let source = try LocalFixtureFileService(root: a)
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
        let local = try LocalFixtureFileService(root: a)
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
    func testUnsupportedAtomicReplaceNeverFallsBackOrDeletesOriginal() async throws {
        let (root, a, b) = try roots(); defer { try? FileManager.default.removeItem(at: root) }
        try Data([1, 2, 3]).write(to: a.appendingPathComponent("file")); let old = Data("old".utf8); try old.write(to: b.appendingPathComponent("target"))
        let source = try LocalFixtureFileService(root: a); let destination = try RemoteSemanticsFixture(root: b)
        let report = try await SafeTransferEngine().copy(hostID: "fixture", source: source, sourcePath: RemotePath("/file"),
            destination: destination, destinationPath: RemotePath("/target"), conflict: .overwrite, token: CancellationToken(),
            policy: TransferPolicy(confirmRisk: { _ in true }))
        XCTAssertEqual(kind(report), .unsupported)
        XCTAssertEqual(try Data(contentsOf: b.appendingPathComponent("target")), old)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: b.path), ["target"])
        await source.close(); await destination.close()
    }
}
