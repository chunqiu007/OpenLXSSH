import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHSecurity

@MainActor
final class KeyStoreTests: XCTestCase {
    private func roundtrip(_ algorithm: KeyAlgorithm, encrypted: Bool) async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = try KeyStore(directory: root.appendingPathComponent("Source"))
        let destinationURL = root.appendingPathComponent("AppSupportKeys")
        let destination = try KeyStore(directory: destinationURL)
        let secret = try SecretBytes.random()
        let passphrase = SecretBytes(Data(secret.withUnsafeBytes { Data($0).base64EncodedString().utf8 }))
        let protection: KeyProtection = encrypted ? .passphrase(passphrase) : .unencrypted
        let original = try await source.generate(algorithm: algorithm, protection: protection)
        let sourceURL = source.rootURL.appendingPathComponent("\(original.id.uuidString).openssh")
        let before = try PrivateDirectory.readSource(sourceURL)
        let modified = try FileManager.default.attributesOfItem(atPath: sourceURL.path)[.modificationDate] as? Date
        let id = UUID()
        let copy = try await destination.importKey(from: sourceURL, protection: protection, id: id)
        XCTAssertEqual(copy.id, id); XCTAssertEqual(copy.encrypted, encrypted); XCTAssertEqual(copy.publicKey, original.publicKey)
        XCTAssertEqual(try PublicKey(copy.publicKey.copyString), copy.publicKey)
        let permissions = try FileManager.default.attributesOfItem(atPath: destinationURL.appendingPathComponent("\(id.uuidString).openssh").path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o600)
        try await destination.close()
        let reopened = try KeyStore(directory: destinationURL)
        let loaded = try await reopened.key(id: id)
        XCTAssertEqual(loaded, copy)
        XCTAssertTrue(try PrivateDirectory.readSource(sourceURL) == before)
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: sourceURL.path)[.modificationDate] as? Date, modified)
        do { _ = try await reopened.importKey(from: sourceURL, protection: protection, id: id); XCTFail("Existing UUID overwritten") }
        catch let failure as KeyFailure { XCTAssertEqual(failure, .duplicateKey) }
        let stillLoaded = try await reopened.key(id: id)
        XCTAssertEqual(stillLoaded, copy)
        let deleted = try await reopened.deleteExact(id)
        let absent = try await reopened.deleteExact(id)
        XCTAssertEqual(deleted, .deleted); XCTAssertEqual(absent, .alreadyAbsent)
        try await reopened.close(); try await source.close()
    }

    func testRealEd25519UnencryptedAndReopen() async throws { try await roundtrip(.ed25519, encrypted: false) }
    func testRealEd25519EncryptedAndReopen() async throws { try await roundtrip(.ed25519, encrypted: true) }
    func testRealRSAUnencryptedAndReopen() async throws { try await roundtrip(.rsa, encrypted: false) }
    func testRealRSAEncryptedAndReopen() async throws { try await roundtrip(.rsa, encrypted: true) }

    func testWrongPassphraseCancellationTimeoutLeaveNoKeyOrSilentTicket() async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = try KeyStore(directory: root.appendingPathComponent("Source"))
        let destination = try KeyStore(directory: root.appendingPathComponent("Keys"))
        let original = try await source.generateEd25519(protection: .passphrase(.init(utf8: UUID().uuidString)))
        let url = source.rootURL.appendingPathComponent("\(original.id.uuidString).openssh")
        do { _ = try await destination.importKey(from: url, protection: .unencrypted); XCTFail("Missing passphrase accepted") }
        catch let failure as KeyFailure { XCTAssertEqual(failure, .passphraseRequired) }
        do { _ = try await destination.importKey(from: url, protection: .passphrase(.init(utf8: UUID().uuidString))); XCTFail("Wrong passphrase accepted") }
        catch let failure as KeyOperationFailure {
            XCTAssertEqual(failure.primary, .keygenRejected); XCTAssertNil(failure.cleanupTicket); XCTAssertTrue(failure.cleanupFailures.isEmpty)
        }
        let cancelled = Task { try await destination.generateEd25519(protection: .passphrase(.init(utf8: UUID().uuidString))) }
        cancelled.cancel()
        do { _ = try await cancelled.value; XCTFail("Cancelled operation committed") }
        catch let failure as KeyOperationFailure { XCTAssertEqual(failure.primary, .cancelled); XCTAssertNil(failure.cleanupTicket) }
        let timeout = try KeyStore(directory: root.appendingPathComponent("Timeout"), tool: SSHKeygenTool(timeout: .nanoseconds(1)))
        do { _ = try await timeout.generateEd25519(protection: .unencrypted); XCTFail("Deadline ignored") }
        catch let failure as KeyOperationFailure { XCTAssertEqual(failure.primary, .timedOut); XCTAssertNil(failure.cleanupTicket) }
        for store in [destination, timeout] {
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: store.rootURL.path), [".OpenLXSSH.lock"])
            try await store.close()
        }
        try await source.close()
    }

    func testDirectoryOwnershipLockReopenAndNoScanningUnknownFiles() async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("Keys")
        let store = try KeyStore(directory: directory)
        XCTAssertThrowsError(try KeyStore(directory: directory)) { XCTAssertEqual($0 as? KeyFailure, .busy) }
        let unknown = directory.appendingPathComponent("unrelated.txt")
        try Data("not a key".utf8).write(to: unknown)
        let id = UUID()
        do { _ = try await store.key(id: id); XCTFail("Unknown UUID found") }
        catch let failure as KeyFailure { XCTAssertEqual(failure, .missing) }
        let noKey = try await store.deleteExact(id)
        XCTAssertEqual(noKey, .alreadyAbsent)
        try await store.close()
        XCTAssertTrue(FileManager.default.fileExists(atPath: unknown.path))
        let reopened = try KeyStore(directory: directory)
        try await reopened.close()
        guard chmod(directory.path, 0o755) == 0 else { throw KeyFailure.unsafePermissions }
        XCTAssertThrowsError(try KeyStore(directory: directory)) { XCTAssertEqual($0 as? KeyFailure, .unsafePermissions) }
    }

    func testSymlinkImportAndDeletionCannotEscapeOrDeleteSource() async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = try KeyStore(directory: root.appendingPathComponent("Source"))
        let destination = try KeyStore(directory: root.appendingPathComponent("Keys"))
        let original = try await source.generateEd25519(protection: .unencrypted)
        let url = source.rootURL.appendingPathComponent("\(original.id.uuidString).openssh")
        let link = root.appendingPathComponent("linked-source")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: url)
        do { _ = try await destination.importKey(from: link, protection: .unencrypted); XCTFail("Source link followed") }
        catch let failure as KeyFailure { XCTAssertEqual(failure, .symbolicLinkOrEscape) }
        let copy = try await destination.importKey(from: url, protection: .unencrypted)
        let managed = destination.rootURL.appendingPathComponent("\(copy.id.uuidString).openssh")
        try FileManager.default.removeItem(at: managed)
        try FileManager.default.createSymbolicLink(at: managed, withDestinationURL: url)
        do { _ = try await destination.deleteExact(copy.id); XCTFail("Managed link followed") }
        catch let failure as KeyFailure { XCTAssertEqual(failure, .symbolicLinkOrEscape) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        try FileManager.default.removeItem(at: managed)
        try await destination.close(); try await source.close()
    }

    func testAtomicCommitCollisionPreservesExistingDestinationAndReportsOwnership() throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try PrivateDirectory(directory: root.appendingPathComponent("Keys"))
        var pendingOwned = false, existingOwned = false
        try directory.write(Data("new pending".utf8), name: "pending", created: &pendingOwned)
        try directory.write(Data("existing must survive".utf8), name: "existing", created: &existingOwned)
        var committed = false
        XCTAssertThrowsError(try directory.commit(stage: "pending", destination: "existing", committed: &committed))
        XCTAssertTrue(pendingOwned); XCTAssertTrue(existingOwned); XCTAssertFalse(committed)
        XCTAssertTrue(try directory.read("existing") == Data("existing must survive".utf8))
        XCTAssertTrue(try directory.read("pending") == Data("new pending".utf8))
    }

    func testCleanupFailureReturnsTicketAndNeverDeletesLinkedTarget() async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try KeyStore(directory: root.appendingPathComponent("Keys"))
        let id = UUID()
        let stage = "\(id.uuidString).\(UUID().uuidString).pending"
        let outside = root.appendingPathComponent("outside.txt")
        try Data("outside must survive".utf8).write(to: outside)
        let url = store.rootURL.appendingPathComponent(stage)
        try FileManager.default.createSymbolicLink(at: url, withDestinationURL: outside)
        let ticket = KeyCleanupTicket(id: id, pendingName: stage, includesPublicSidecar: false, includesCommittedKey: false)
        do { try await store.retryCleanup(ticket); XCTFail("Unsafe cleanup succeeded") }
        catch let failure as KeyOperationFailure {
            XCTAssertEqual(failure.primary, .cleanupRequired)
            XCTAssertEqual(failure.cleanupTicket, ticket)
            XCTAssertEqual(failure.cleanupFailures[stage], .symbolicLinkOrEscape)
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: outside.path))
        try FileManager.default.removeItem(at: url)
        try await store.retryCleanup(ticket)
        try await store.close()
    }

    func testRootReplacementClosedOwnerAndCorruptFileRejected() async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("Keys")
        let store = try KeyStore(directory: url)
        let key = try await store.generateEd25519(protection: .unencrypted)
        let moved = root.appendingPathComponent("Moved")
        try FileManager.default.moveItem(at: url, to: moved)
        try FileManager.default.createSymbolicLink(at: url, withDestinationURL: moved)
        do { _ = try await store.publicKey(for: key.id); XCTFail("Replaced root followed") }
        catch let failure as KeyFailure { XCTAssertEqual(failure, .symbolicLinkOrEscape) }
        try FileManager.default.removeItem(at: url)
        try FileManager.default.moveItem(at: moved, to: url)
        let file = url.appendingPathComponent("\(key.id.uuidString).openssh")
        try Data("invalid private key".utf8).write(to: file)
        guard chmod(file.path, 0o600) == 0 else { throw KeyFailure.unsafePermissions }
        do { _ = try await store.key(id: key.id); XCTFail("Corrupt file accepted") }
        catch let failure as KeyFailure { XCTAssertEqual(failure, .invalidOpenSSH) }
        try await store.close()
        do { _ = try await store.key(id: key.id); XCTFail("Closed owner read") }
        catch let failure as KeyFailure { XCTAssertEqual(failure, .closed) }
    }

    func testCleanupTicketValidationAndRetryNeverAcceptArbitraryPath() async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try KeyStore(directory: root.appendingPathComponent("Keys"))
        let id = UUID(), stage = "\(UUID().uuidString).pending"
        do {
            try await store.retryCleanup(.init(id: id, pendingName: "../" + stage, includesPublicSidecar: true, includesCommittedKey: true))
            XCTFail("Path escaping cleanup ticket accepted")
        } catch let failure as KeyFailure { XCTAssertEqual(failure, .invalidPath) }
        let name = "\(id.uuidString).\(UUID().uuidString).pending"
        let stageURL = store.rootURL.appendingPathComponent(name)
        try Data("owned failed staging".utf8).write(to: stageURL)
        guard chmod(stageURL.path, 0o600) == 0 else { throw KeyFailure.unsafePermissions }
        try await store.retryCleanup(.init(id: id, pendingName: name, includesPublicSidecar: false, includesCommittedKey: false))
        XCTAssertFalse(FileManager.default.fileExists(atPath: stageURL.path))
        try await store.close()
    }
}
