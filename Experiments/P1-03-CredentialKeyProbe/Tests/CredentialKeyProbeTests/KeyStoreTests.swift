import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHCredentialKeyProbe

@MainActor
final class KeyStoreTests: XCTestCase {
    private func fileURL(_ store: KeyStore, _ key: ManagedKey) -> URL {
        store.rootURL.appendingPathComponent("\(key.id.uuidString).openssh")
    }

    private func withStores(_ body: (KeyStore, KeyStore) async throws -> Void) async throws {
        let source = try KeyStore(), destination = try KeyStore()
        do {
            try await body(source, destination)
        } catch {
            try await destination.destroy()
            try await source.destroy()
            throw error
        }
        try await destination.destroy()
        try await source.destroy()
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.rootURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: source.rootURL.path))
    }

    private func roundTrip(_ algorithm: KeyAlgorithm, encrypted: Bool) async throws {
        let protection: KeyProtection = encrypted ? .passphrase(try .randomPassphrase()) : .unencrypted
        try await withStores { source, destination in
            let generated = try await source.generate(algorithm: algorithm, protection: protection)
            let originalURL = self.fileURL(source, generated)
            let original = try PrivateDirectory.readSource(originalURL)
            let sourceAttributes = try FileManager.default.attributesOfItem(atPath: originalURL.path)
            let copied = try await destination.importKey(from: originalURL, protection: protection)
            XCTAssertNotEqual(generated.id, copied.id)
            XCTAssertEqual(copied.publicKey.algorithm, algorithm)
            XCTAssertEqual(copied.encrypted, encrypted)
            let observed = try await destination.publicKey(for: copied.id)
            XCTAssertEqual(observed, generated.publicKey)
            XCTAssertEqual(try PublicKey(observed.copyString), observed)
            XCTAssertFalse(observed.copyString.contains("PRIVATE"))
            let copiedURL = self.fileURL(destination, copied)
            let copy = try PrivateDirectory.readSource(copiedURL)
            XCTAssertTrue(copy == original, "Managed copy must preserve private-key bytes without printing them")
            let attributes = try FileManager.default.attributesOfItem(atPath: copiedURL.path)
            let rootAttributes = try FileManager.default.attributesOfItem(atPath: destination.rootURL.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
            XCTAssertEqual((rootAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path).count, 1)
            do {
                _ = try await destination.importKey(from: originalURL, protection: protection)
                XCTFail("Duplicate public identity imported twice")
            } catch let error as KeyOperationFailure {
                XCTAssertEqual(error.primary, .duplicateKey)
                XCTAssertTrue(error.cleanupFailures.isEmpty)
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path).count, 1)
            try await destination.delete(copied.id)
            try await destination.delete(copied.id)
            XCTAssertFalse(FileManager.default.fileExists(atPath: copiedURL.path))
            XCTAssertTrue(try PrivateDirectory.readSource(originalURL) == original)
            let sourceAfter = try FileManager.default.attributesOfItem(atPath: originalURL.path)
            XCTAssertEqual((sourceAfter[.posixPermissions] as? NSNumber)?.intValue,
                           (sourceAttributes[.posixPermissions] as? NSNumber)?.intValue)
            XCTAssertEqual(sourceAfter[.modificationDate] as? Date, sourceAttributes[.modificationDate] as? Date)
        }
    }

    func testRealEd25519UnencryptedImportGenerateAndPublicCopy() async throws { try await roundTrip(.ed25519, encrypted: false) }
    func testRealEd25519EncryptedImportGenerateAndPublicCopy() async throws { try await roundTrip(.ed25519, encrypted: true) }
    func testRealRSAUnencryptedImportAndPublicCopy() async throws { try await roundTrip(.rsa, encrypted: false) }
    func testRealRSAEncryptedImportAndPublicCopy() async throws { try await roundTrip(.rsa, encrypted: true) }

    func testRealImportStripsMultilineCommentFromPublicCopy() async throws {
        try await withStores { source, destination in
            let url = source.rootURL.appendingPathComponent("commented")
            let protection = KeyProtection.passphrase(try .randomPassphrase())
            try await SSHKeygenTool().generate(at: url.path, algorithm: .ed25519, protection: protection,
                                              comment: "fixture comment 中文\nnot-a-key second line")
            defer {
                try? FileManager.default.removeItem(at: url)
                try? FileManager.default.removeItem(at: url.appendingPathExtension("pub"))
            }
            let key = try await destination.importKey(from: url, protection: protection)
            XCTAssertEqual(key.publicKey.copyString.split(separator: " ").count, 2)
            XCTAssertFalse(key.publicKey.copyString.contains("fixture"))
            XCTAssertFalse(key.publicKey.copyString.contains("second"))
            XCTAssertFalse(key.publicKey.copyString.contains("\n"))
        }
    }

    func testWrongOrMissingPassphraseDoesNotCommitAndSourceSurvives() async throws {
        let protection = KeyProtection.passphrase(try .randomPassphrase())
        try await withStores { source, destination in
            let key = try await source.generateEd25519(protection: protection)
            let url = self.fileURL(source, key)
            let before = try PrivateDirectory.readSource(url)
            do {
                _ = try await destination.importKey(from: url, protection: .unencrypted)
                XCTFail("Encrypted source accepted without passphrase")
            } catch let error as KeyFailure { XCTAssertEqual(error, .passphraseRequired) }
            do {
                _ = try await destination.importKey(from: url, protection: .passphrase(try .randomPassphrase()))
                XCTFail("Wrong passphrase accepted")
            } catch let error as KeyOperationFailure {
                XCTAssertEqual(error.primary, .keygenRejected)
                XCTAssertTrue(error.cleanupFailures.isEmpty)
            }
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path).isEmpty)
            XCTAssertTrue(try PrivateDirectory.readSource(url) == before)
        }
    }

    func testCancelledImportCleansStagingAndLeavesSource() async throws {
        try await withStores { source, destination in
            let key = try await source.generateEd25519(protection: .unencrypted)
            let url = self.fileURL(source, key)
            let task = Task { try await destination.importKey(from: url, protection: .unencrypted) }
            task.cancel()
            do { _ = try await task.value; XCTFail("Cancelled import unexpectedly committed") }
            catch let error as KeyOperationFailure {
                XCTAssertEqual(error.primary, .cancelled)
                XCTAssertTrue(error.cleanupFailures.isEmpty)
            }
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path).isEmpty)
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        }
    }

    func testGenerationCancelledDuringChildExecutionReapsAndCleans() async throws {
        let store = try KeyStore()
        do {
            let protection = KeyProtection.passphrase(try .randomPassphrase())
            let task = Task { try await store.generate(algorithm: .rsa, protection: protection) }
            try await Task.sleep(for: .milliseconds(5))
            task.cancel()
            do { _ = try await task.value; XCTFail("Cancelled generation committed") }
            catch let failure as KeyOperationFailure {
                XCTAssertEqual(failure.primary, .cancelled)
                XCTAssertTrue(failure.cleanupFailures.isEmpty)
            }
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: store.rootURL.path).isEmpty)
        } catch {
            try await store.destroy()
            throw error
        }
        try await store.destroy()
    }

    func testMalformedSourceRejectedBeforeCopyAndInsecurePermissionsRejected() async throws {
        try await withStores { source, destination in
            let url = source.rootURL.appendingPathComponent("malformed")
            // This is not key material; static framing only. No secret fixture is checked in.
            try Data("not an OpenSSH private key\n".utf8).write(to: url)
            guard chmod(url.path, 0o600) == 0 else { throw KeyFailure.systemCall("chmod fixture", errno) }
            defer { try? FileManager.default.removeItem(at: url) }
            do { _ = try await destination.importKey(from: url, protection: .unencrypted); XCTFail("Malformed key accepted") }
            catch let error as KeyFailure { XCTAssertEqual(error, .invalidOpenSSH) }
            guard chmod(url.path, 0o644) == 0 else { throw KeyFailure.systemCall("chmod fixture", errno) }
            do { _ = try await destination.importKey(from: url, protection: .unencrypted); XCTFail("Insecure permissions accepted") }
            catch let error as KeyFailure { XCTAssertEqual(error, .unsafePermissions) }
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path).isEmpty)
        }
    }

    func testSymlinkLeafAncestorAndTraversalCannotImport() async throws {
        try await withStores { source, destination in
            let key = try await source.generateEd25519(protection: .unencrypted)
            let original = self.fileURL(source, key)
            let leaf = source.rootURL.appendingPathComponent("linked")
            let ancestor = destination.rootURL.appendingPathComponent("linked-root")
            try FileManager.default.createSymbolicLink(at: leaf, withDestinationURL: original)
            try FileManager.default.createSymbolicLink(at: ancestor, withDestinationURL: source.rootURL)
            defer {
                try? FileManager.default.removeItem(at: leaf)
                try? FileManager.default.removeItem(at: ancestor)
            }
            for url in [leaf, ancestor.appendingPathComponent(original.lastPathComponent)] {
                do { _ = try await destination.importKey(from: url, protection: .unencrypted); XCTFail("Symlink accepted") }
                catch let error as KeyFailure { XCTAssertEqual(error, .symbolicLinkOrEscape) }
            }
            do { _ = try PrivateDirectory.openDirectory(source.rootURL.path + "/../" + source.rootURL.lastPathComponent); XCTFail("Traversal accepted") }
            catch let error as KeyFailure { XCTAssertEqual(error, .symbolicLinkOrEscape) }
            XCTAssertTrue(FileManager.default.fileExists(atPath: original.path))
        }
    }

    func testDeleteDoesNotFollowReplacedManagedFileSymlink() async throws {
        try await withStores { source, destination in
            let key = try await source.generateEd25519(protection: .unencrypted)
            let original = self.fileURL(source, key)
            let imported = try await destination.importKey(from: original, protection: .unencrypted)
            let managed = self.fileURL(destination, imported)
            try FileManager.default.removeItem(at: managed)
            try FileManager.default.createSymbolicLink(at: managed, withDestinationURL: original)
            do { try await destination.delete(imported.id); XCTFail("Deletion followed malicious symlink") }
            catch let error as KeyFailure { XCTAssertEqual(error, .symbolicLinkOrEscape) }
            XCTAssertTrue(FileManager.default.fileExists(atPath: original.path))
            // Remove only the symlink we inserted so normal exact-name cleanup can complete.
            try FileManager.default.removeItem(at: managed)
            try await destination.delete(imported.id)
        }
    }

    func testNoShellInjectionFromSourceFilename() async throws {
        try await withStores { source, destination in
            let key = try await source.generateEd25519(protection: .unencrypted)
            let original = self.fileURL(source, key)
            let unusual = source.rootURL.appendingPathComponent("-$(touch NEVER_EXECUTED); key ' \" 中文")
            try FileManager.default.copyItem(at: original, to: unusual)
            defer { try? FileManager.default.removeItem(at: unusual) }
            let imported = try await destination.importKey(from: unusual, protection: .unencrypted)
            XCTAssertEqual(imported.publicKey, key.publicKey)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: source.rootURL.path).count, 2)
        }
    }

    func testPromptInputBoundariesAndTimeoutAreExplicit() async throws {
        // Non-secret malformed input, used solely to exercise framing validation.
        for value in [Data(), Data([0]), Data([10]), Data([13]), Data(repeating: 65, count: 1024)] {
            XCTAssertThrowsError(try KeyProtection.passphrase(SecretBytes(value)).inputLines(count: 1)) { error in
                XCTAssertEqual(error as? KeyFailure, .invalidPassphraseInput)
            }
        }
        XCTAssertTrue(try KeyProtection.unencrypted.inputLines(count: 2) == Data([10, 10]))
        let source = try KeyStore()
        let path = source.rootURL.appendingPathComponent("timed-out").path
        do {
            try await SSHKeygenTool(timeout: .nanoseconds(1)).generate(at: path, algorithm: .rsa, protection: .unencrypted)
            XCTFail("Expired subprocess deadline accepted")
        } catch let error as KeyFailure { XCTAssertEqual(error, .timedOut) }
        // The lower-level tool has no artifact ownership. Clean only its two exact fixture paths.
        for name in [path, path + ".pub"] where FileManager.default.fileExists(atPath: name) {
            try FileManager.default.removeItem(atPath: name)
        }
        try await source.destroy()
    }

    func testUnsupportedPrivateAlgorithmAndSymlinkRootReplacementAreRejected() async throws {
        try await withStores { source, destination in
            let key = try await source.generateEd25519(protection: .unencrypted)
            let original = self.fileURL(source, key)
            let lines = String(decoding: try PrivateDirectory.readSource(original), as: UTF8.self).components(separatedBy: "\n")
            var raw = Data(base64Encoded: lines.dropFirst().dropLast(2).joined())!
            let algorithm = Data(KeyAlgorithm.ed25519.rawValue.utf8)
            let range = raw.range(of: algorithm)!
            raw.replaceSubrange(range, with: Data(repeating: 120, count: algorithm.count))
            let unsupported = Data(("-----BEGIN OPENSSH PRIVATE KEY-----\n" + raw.base64EncodedString() + "\n-----END OPENSSH PRIVATE KEY-----\n").utf8)
            XCTAssertThrowsError(try OpenSSHEnvelope(unsupported)) { error in
                XCTAssertEqual(error as? KeyFailure, .unsupportedAlgorithm)
            }
            let root = destination.rootURL
            let renamed = root.appendingPathExtension("moved-by-test")
            try FileManager.default.moveItem(at: root, to: renamed)
            try FileManager.default.createSymbolicLink(at: root, withDestinationURL: source.rootURL)
            defer {
                try? FileManager.default.removeItem(at: root)
                try? FileManager.default.moveItem(at: renamed, to: root)
            }
            do { _ = try await destination.importKey(from: original, protection: .unencrypted); XCTFail("Symlink root accepted") }
            catch let error as KeyFailure { XCTAssertEqual(error, .symbolicLinkOrEscape) }
            XCTAssertTrue(FileManager.default.fileExists(atPath: original.path))
        }
    }

    func testPublicCopyAndEnvelopeRejectInvalidFramingAlgorithmsAndCorruption() async throws {
        XCTAssertThrowsError(try PublicKey("ssh-ed25519 invalid-base64"))
        XCTAssertThrowsError(try PublicKey("ssh-ed25519 AAAA\ncomment"))
        XCTAssertThrowsError(try PublicKey("ssh-dss AAAA"))
        for data in [Data(), Data("-----BEGIN RSA PRIVATE KEY-----\n".utf8), Data(repeating: 0, count: 32)] {
            XCTAssertThrowsError(try OpenSSHEnvelope(data))
        }
        try await withStores { source, destination in
            let key = try await source.generateEd25519(protection: .unencrypted)
            let url = self.fileURL(source, key)
            let envelopeText = String(decoding: try PrivateDirectory.readSource(url), as: UTF8.self)
            let lines = envelopeText.components(separatedBy: "\n")
            var raw = Data(base64Encoded: lines.dropFirst().dropLast(2).joined())!
            // Corrupt the actual private section while preserving the public envelope.
            raw[raw.count - 1] ^= 0xff
            let corrupt = Data(("-----BEGIN OPENSSH PRIVATE KEY-----\n" + raw.base64EncodedString() + "\n-----END OPENSSH PRIVATE KEY-----\n").utf8)
            let corruptURL = source.rootURL.appendingPathComponent("corrupt")
            try corrupt.write(to: corruptURL)
            guard chmod(corruptURL.path, 0o600) == 0 else { throw KeyFailure.systemCall("chmod fixture", errno) }
            defer { try? FileManager.default.removeItem(at: corruptURL) }
            do { _ = try await destination.importKey(from: corruptURL, protection: .unencrypted); XCTFail("Corrupt private section accepted") }
            catch let error as KeyOperationFailure {
                XCTAssertEqual(error.primary, .keygenRejected)
                XCTAssertTrue(error.cleanupFailures.isEmpty)
            }
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path).isEmpty)
        }
    }
}
