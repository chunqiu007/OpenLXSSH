import Darwin
import Foundation
import SecurityTestSupport
import XCTest
@testable import OpenLXSSHSecurity

@MainActor
final class KeyAuthenticationMaterialTests: XCTestCase {
    private func temporaryRoot() throws -> URL {
        let root = try makeTemporaryRoot()
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: root.path)[.posixPermissions] as? NSNumber, 0o700)
        return root
    }

    private func cleanup(_ root: URL, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNoThrow(try FileManager.default.removeItem(at: root), file: file, line: line)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.path), file: file, line: line)
    }

    private func expectFailure(_ expected: KeyFailure, store: KeyStore, id: UUID,
                               file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await store.privateKeyForAuthentication(id: id)
            XCTFail("Unsafe authentication material returned", file: file, line: line)
        } catch let failure as KeyFailure {
            XCTAssertEqual(failure, expected, file: file, line: line)
        } catch {
            XCTFail("Unexpected failure type: \(type(of: error))", file: file, line: line)
        }
    }

    private func roundtrip(_ algorithm: KeyAlgorithm, encrypted: Bool) async throws {
        let root = try temporaryRoot()
        defer { cleanup(root) }
        let source = try KeyStore(directory: root.appendingPathComponent("Source"))
        let destinationURL = root.appendingPathComponent("Keys")
        let destination = try KeyStore(directory: destinationURL)
        let protection: KeyProtection = encrypted ? .passphrase(.init(utf8: UUID().uuidString)) : .unencrypted
        let key = try await source.generate(algorithm: algorithm, protection: protection)
        let sourceURL = source.rootURL.appendingPathComponent("\(key.id.uuidString).openssh")
        let original = try PrivateDirectory.readSource(sourceURL)
        let before = try FileManager.default.attributesOfItem(atPath: sourceURL.path)
        let copy = try await destination.importKey(from: sourceURL, protection: protection)
        let names = try FileManager.default.contentsOfDirectory(atPath: destinationURL.path).sorted()
        let material = try await destination.privateKeyForAuthentication(id: copy.id)
        XCTAssertTrue(material.withUnsafeBytes { Data($0) == original }, "Must return exact OpenSSH bytes without decrypting or rewriting")
        let envelope = try material.withUnsafeBytes { try OpenSSHEnvelope(Data($0)) }
        XCTAssertEqual(envelope.publicKey, key.publicKey)
        XCTAssertEqual(envelope.publicKey.algorithm, algorithm)
        XCTAssertEqual(envelope.encrypted, encrypted)
        XCTAssertEqual(String(describing: material), "<redacted>")
        XCTAssertEqual(String(reflecting: material), "<redacted>")
        XCTAssertTrue(Mirror(reflecting: material).children.isEmpty)
        // Files' publicKey authentication boundary accepts a length-delimited Data buffer.
        let input = material.withUnsafeBytes { Data($0) }
        XCTAssertFalse(input.isEmpty)
        XCTAssertFalse(input.contains(0))
        XCTAssertTrue(input.count <= 1_048_576)
        XCTAssertTrue(input == original)
        try await destination.close()
        let reopened = try KeyStore(directory: destinationURL)
        let again = try await reopened.privateKeyForAuthentication(id: copy.id)
        XCTAssertTrue(again.matches(material))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: destinationURL.path).sorted(), names,
                       "Authentication read must not persist another copy")
        XCTAssertTrue(try PrivateDirectory.readSource(sourceURL) == original)
        let after = try FileManager.default.attributesOfItem(atPath: sourceURL.path)
        for attribute in [FileAttributeKey.modificationDate, .posixPermissions, .ownerAccountID, .systemFileNumber, .size] {
            XCTAssertTrue((before[attribute] as? NSObject)?.isEqual(after[attribute]) == true, "Source metadata changed")
        }
        try await reopened.close()
        try await source.close()
    }

    func testRealEd25519UnencryptedMaterialAndSourceUnchanged() async throws { try await roundtrip(.ed25519, encrypted: false) }
    func testRealEd25519EncryptedMaterialAndSourceUnchanged() async throws { try await roundtrip(.ed25519, encrypted: true) }
    func testRealRSAUnencryptedMaterialAndSourceUnchanged() async throws { try await roundtrip(.rsa, encrypted: false) }
    func testRealRSAEncryptedMaterialAndSourceUnchanged() async throws { try await roundtrip(.rsa, encrypted: true) }

    func testUnknownUUIDDoesNotReadPendingOrAnotherKeyAndClosedRejects() async throws {
        let root = try temporaryRoot()
        defer { cleanup(root) }
        let store = try KeyStore(directory: root.appendingPathComponent("Keys"))
        let existing = try await store.generateEd25519(protection: .unencrypted)
        let missing = UUID()
        let pending = store.rootURL.appendingPathComponent("\(missing.uuidString).\(UUID().uuidString).pending")
        try Data("nonsecret pending marker".utf8).write(to: pending)
        guard chmod(pending.path, 0o600) == 0 else { throw KeyFailure.systemCall("chmod fixture", errno) }
        await expectFailure(.missing, store: store, id: missing)
        XCTAssertTrue(FileManager.default.fileExists(atPath: pending.path))
        let material = try await store.privateKeyForAuthentication(id: existing.id)
        XCTAssertTrue(material.withUnsafeBytes { !$0.isEmpty })
        try await store.close()
        await expectFailure(.closed, store: store, id: existing.id)
        XCTAssertTrue(FileManager.default.fileExists(atPath: store.rootURL.appendingPathComponent("\(existing.id.uuidString).openssh").path))
    }

    func testUnsafeKeyRootAndLockModesRejectedWithoutRepair() async throws {
        let root = try temporaryRoot()
        defer { cleanup(root) }
        let store = try KeyStore(directory: root.appendingPathComponent("Keys"))
        let key = try await store.generateEd25519(protection: .unencrypted)
        let final = store.rootURL.appendingPathComponent("\(key.id.uuidString).openssh")
        let lock = store.rootURL.appendingPathComponent(".OpenLXSSH.lock")
        for (target, unsafe, restored): (URL, mode_t, mode_t) in [(final, 0o644, 0o600), (store.rootURL, 0o750, 0o700), (lock, 0o640, 0o600)] {
            guard chmod(target.path, unsafe) == 0 else { throw KeyFailure.systemCall("chmod own fixture", errno) }
            await expectFailure(.unsafePermissions, store: store, id: key.id)
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: target.path)[.posixPermissions] as? NSNumber,
                           NSNumber(value: unsafe), "Read must not repair mode")
            guard chmod(target.path, restored) == 0 else { throw KeyFailure.systemCall("restore own fixture mode", errno) }
        }
        let material = try await store.privateKeyForAuthentication(id: key.id)
        XCTAssertTrue(material.withUnsafeBytes { !$0.isEmpty })
        try await store.close()
    }

    func testKeyRootAndLockACLRejectedWithoutClearing() async throws {
        let root = try temporaryRoot()
        defer { cleanup(root) }
        let store = try KeyStore(directory: root.appendingPathComponent("Keys"))
        let key = try await store.generateEd25519(protection: .unencrypted)
        let final = store.rootURL.appendingPathComponent("\(key.id.uuidString).openssh")
        let original = try PrivateDirectory.readSource(final)
        for target in [final, store.rootURL, store.rootURL.appendingPathComponent(".OpenLXSSH.lock")] {
            // All descriptors are inside this test-created tree. Never alter a user ACL.
            let fd = Darwin.open(target.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { throw KeyFailure.systemCall("open ACL fixture", errno) }
            defer { _ = Darwin.close(fd) }
            let set = olxs_test_set_everyone_file_acl(fd, 1, 0)
            guard set == 0 else { throw KeyFailure.systemCall("set own fixture ACL", set) }
            await expectFailure(.unsafePermissions, store: store, id: key.id)
            var state: Int32 = 0
            XCTAssertEqual(olxs_test_file_acl_state(fd, &state), 0)
            XCTAssertEqual(state & 5, 5, "Authentication read must not clear ACL")
            let cleared = olxs_test_clear_file_acl(fd)
            guard cleared == 0 else { throw KeyFailure.systemCall("clear own fixture ACL", cleared) }
        }
        let material = try await store.privateKeyForAuthentication(id: key.id)
        XCTAssertTrue(material.withUnsafeBytes { Data($0) == original })
        try await store.close()
    }

    func testSymlinkHardlinkNonRegularOversizeAndInvalidEnvelopeRejected() async throws {
        let root = try temporaryRoot()
        defer { cleanup(root) }
        let store = try KeyStore(directory: root.appendingPathComponent("Keys"))
        let key = try await store.generateEd25519(protection: .unencrypted)
        let final = store.rootURL.appendingPathComponent("\(key.id.uuidString).openssh")
        let outside = root.appendingPathComponent("Original")
        try FileManager.default.moveItem(at: final, to: outside)
        let original = try PrivateDirectory.readSource(outside)
        try FileManager.default.createSymbolicLink(at: final, withDestinationURL: outside)
        await expectFailure(.symbolicLinkOrEscape, store: store, id: key.id)
        try FileManager.default.removeItem(at: final)
        guard Darwin.link(outside.path, final.path) == 0 else { throw KeyFailure.systemCall("link own fixture", errno) }
        await expectFailure(.unsafePermissions, store: store, id: key.id)
        try FileManager.default.removeItem(at: final)
        guard mkdir(final.path, 0o700) == 0 else { throw KeyFailure.systemCall("mkdir own fixture", errno) }
        await expectFailure(.notRegularFile, store: store, id: key.id)
        try FileManager.default.removeItem(at: final)
        let fd = Darwin.open(final.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw KeyFailure.systemCall("create own fixture", errno) }
        let sized = ftruncate(fd, 1_048_577)
        _ = Darwin.close(fd)
        guard sized == 0 else { throw KeyFailure.systemCall("size own fixture", errno) }
        await expectFailure(.fileTooLarge, store: store, id: key.id)
        try FileManager.default.removeItem(at: final)
        try Data("not an OpenSSH envelope".utf8).write(to: final)
        guard chmod(final.path, 0o600) == 0 else { throw KeyFailure.systemCall("chmod own fixture", errno) }
        await expectFailure(.invalidOpenSSH, store: store, id: key.id)
        XCTAssertTrue(try PrivateDirectory.readSource(outside) == original, "Refused reads must not delete or change original")
        try await store.close()
    }
}
