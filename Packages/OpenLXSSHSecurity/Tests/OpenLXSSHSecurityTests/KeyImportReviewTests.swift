import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHSecurity

@MainActor
final class KeyImportReviewTests: XCTestCase {
    private func fixture() throws -> (URL, KeyStore, KeyStore) {
        let root = try makeTemporaryRoot()
        addTeardownBlock { try FileManager.default.removeItem(at: root) }
        return (root, try KeyStore(directory: root.appendingPathComponent("Source")),
                try KeyStore(directory: root.appendingPathComponent("Keys")))
    }
    private func sourceURL(_ store: KeyStore, _ key: ManagedKey) -> URL {
        store.rootURL.appendingPathComponent(key.id.uuidString + ".openssh")
    }
    private func expectStale(_ operation: () async throws -> Void) async {
        do { try await operation(); XCTFail("Stale review accepted") }
        catch { XCTAssertEqual(error as? KeyImportReviewFailure, .staleReview) }
    }

    private func assertDestinationState(_ destination: KeyStore, committed: [String: Data],
                                        file: StaticString = #filePath, line: UInt = #line) throws {
        let expectedNames = Set([".OpenLXSSH.lock"]).union(committed.keys)
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path)), expectedNames,
                       "Only the lock and exact previously committed keys may remain; no review stage", file: file, line: line)
        for (name, bytes) in committed {
            XCTAssertTrue(try PrivateDirectory.readSource(destination.rootURL.appendingPathComponent(name)) == bytes,
                          "A previously committed key must remain byte-for-byte unchanged", file: file, line: line)
        }
    }

    func testReviewedEdAndRSARequireCorrectPassphraseAndCommitExactBytes() async throws {
        let (_, source, destination) = try fixture()
        var committed: [String: Data] = [:]
        for algorithm in [KeyAlgorithm.ed25519, .rsa] {
            try assertDestinationState(destination, committed: committed)
            let phrase = SecretBytes(utf8: UUID().uuidString)
            let key = try await source.generate(algorithm: algorithm, protection: .passphrase(phrase))
            let url = sourceURL(source, key), before = try PrivateDirectory.readSource(sourceURL(source, key))
            do {
                _ = try await destination.reviewImport(from: url, protection: .passphrase(.init(utf8: UUID().uuidString)))
                XCTFail("Wrong passphrase accepted")
            } catch let error as KeyOperationFailure {
                XCTAssertEqual(error.primary, .keygenRejected); XCTAssertNil(error.cleanupTicket)
            }
            try assertDestinationState(destination, committed: committed)
            let review = try await destination.reviewImport(from: url, protection: .passphrase(phrase))
            XCTAssertEqual(review.publicKey, key.publicKey); XCTAssertTrue(review.encrypted)
            try assertDestinationState(destination, committed: committed)
            let imported = try await destination.commitImport(review)
            XCTAssertEqual(imported.publicKey, key.publicKey)
            XCTAssertTrue(try PrivateDirectory.readSource(sourceURL(destination, imported)) == before)
            XCTAssertTrue(try PrivateDirectory.readSource(url) == before)
            committed[imported.id.uuidString + ".openssh"] = before
            try assertDestinationState(destination, committed: committed)
            await expectStale { _ = try await destination.commitImport(review) }
            try assertDestinationState(destination, committed: committed)
        }
        try await source.close(); try await destination.close()
    }

    func testCancelledSupersededForeignAndClosedReviewsNeverCommit() async throws {
        let (root, source, destination) = try fixture()
        let key = try await source.generateEd25519(protection: .unencrypted)
        let url = sourceURL(source, key)
        let old = try await destination.reviewImport(from: url, protection: .unencrypted)
        let current = try await destination.reviewImport(from: url, protection: .unencrypted)
        await expectStale { _ = try await destination.commitImport(old) }
        try await destination.cancelImportReview(old) // cannot cancel the current owner
        try await destination.validateImportReview(current)
        let other = try KeyStore(directory: root.appendingPathComponent("Other"))
        await expectStale { _ = try await other.commitImport(current) }
        try await destination.cancelImportReview(current)
        await expectStale { _ = try await destination.commitImport(current) }
        let final = try await destination.reviewImport(from: url, protection: .unencrypted)
        try await destination.close()
        await expectStale { _ = try await destination.commitImport(final) }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path), [".OpenLXSSH.lock"])
        try await source.close(); try await other.close()
    }

    func testReviewExpiryIsCheckedWithoutDependingOnTimerScheduling() async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = try KeyStore(directory: root.appendingPathComponent("Source"))
        let destination = try KeyStore(directory: root.appendingPathComponent("Keys"), tool: SSHKeygenTool(), reviewLifetime: .zero)
        let key = try await source.generateEd25519(protection: .unencrypted)
        let review = try await destination.reviewImport(from: sourceURL(source, key), protection: .unencrypted)
        await expectStale { _ = try await destination.commitImport(review) }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path), [".OpenLXSSH.lock"])
        try await source.close(); try await destination.close()
    }

    func testSourceReplacementIncludingIdenticalBytesRejectsReview() async throws {
        let (_, source, destination) = try fixture()
        let key = try await source.generateEd25519(protection: .unencrypted)
        let url = sourceURL(source, key), bytes = try PrivateDirectory.readSource(sourceURL(source, key))
        let review = try await destination.reviewImport(from: url, protection: .unencrypted)
        let replacement = url.deletingLastPathComponent().appendingPathComponent("replacement")
        try bytes.write(to: replacement)
        XCTAssertEqual(chmod(replacement.path, 0o600), 0)
        XCTAssertEqual(rename(replacement.path, url.path), 0)
        await expectStale { _ = try await destination.commitImport(review) }
        XCTAssertTrue(try PrivateDirectory.readSource(url) == bytes)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: destination.rootURL.path), [".OpenLXSSH.lock"])
        try await source.close(); try await destination.close()
    }

    func testSourceContentChangeAndSymlinkAreRejectedWithoutDeletingTargets() async throws {
        let (root, source, destination) = try fixture()
        let first = try await source.generateEd25519(protection: .unencrypted)
        let second = try await source.generateEd25519(protection: .unencrypted)
        let url = sourceURL(source, first), target = sourceURL(source, second)
        let review = try await destination.reviewImport(from: url, protection: .unencrypted)
        let otherBytes = try PrivateDirectory.readSource(target)
        try otherBytes.write(to: url)
        await expectStale { _ = try await destination.commitImport(review) }
        let link = root.appendingPathComponent("linked-source")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        do { _ = try await destination.reviewImport(from: link, protection: .unencrypted); XCTFail("Followed symlink") }
        catch { XCTAssertEqual(error as? KeyFailure, .symbolicLinkOrEscape) }
        XCTAssertTrue(try PrivateDirectory.readSource(target) == otherBytes)
        try await source.close(); try await destination.close()
    }

    func testCleanupFailureReturnsOnlyOwnedValidationTicketAndRetryPreservesExistingKey() async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = try KeyStore(directory: root.appendingPathComponent("Source"))
        let leaf = root.appendingPathComponent("Keys"), moved = root.appendingPathComponent("HeldKeys")
        let destination = try KeyStore(directory: leaf, tool: SSHKeygenTool(), beforeReviewCleanup: {
            // Change only this newly-created fixture's root identity. Exact cleanup must
            // refuse the replacement, report its own ticket, and never scan either tree.
            try FileManager.default.moveItem(at: leaf, to: moved)
            try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        })
        let existing = try await destination.generateEd25519(protection: .unencrypted)
        let existingURL = leaf.appendingPathComponent(existing.id.uuidString + ".openssh")
        let before = try PrivateDirectory.readSource(existingURL)
        let key = try await source.generateEd25519(protection: .unencrypted)
        let failure: KeyOperationFailure
        do { _ = try await destination.reviewImport(from: sourceURL(source, key), protection: .unencrypted); return XCTFail("Expected cleanup failure") }
        catch let error as KeyOperationFailure { failure = error }
        let ticket = try XCTUnwrap(failure.cleanupTicket)
        XCTAssertFalse(ticket.includesCommittedKey); XCTAssertNotEqual(ticket.id, existing.id)
        XCTAssertFalse(failure.cleanupFailures.isEmpty)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: leaf.path).isEmpty)
        try FileManager.default.removeItem(at: leaf); try FileManager.default.moveItem(at: moved, to: leaf)
        try await destination.retryCleanup(ticket)
        XCTAssertTrue(try PrivateDirectory.readSource(existingURL) == before)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: leaf.path).sorted(), [".OpenLXSSH.lock", existing.id.uuidString + ".openssh"].sorted())
        try await source.close(); try await destination.close()
    }

    func testCommentAndReencodedEnvelopeShareCanonicalPublicIdentity() async throws {
        let (_, source, destination) = try fixture()
        let key = try await source.generateEd25519(protection: .unencrypted)
        let url = sourceURL(source, key)
        // Re-wrap the standard outer base64 only; no private-key parsing or crypto.
        let text = try String(contentsOf: url, encoding: .utf8)
        let encoded = text.components(separatedBy: "\n").dropFirst().dropLast(2).joined()
        let lines = stride(from: 0, to: encoded.count, by: 48).map { start -> String in
            let lower = encoded.index(encoded.startIndex, offsetBy: start)
            let upper = encoded.index(lower, offsetBy: min(48, encoded.count - start))
            return String(encoded[lower..<upper])
        }
        let renamed = url.deletingLastPathComponent().appendingPathComponent("different-filename")
        try ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + lines.joined(separator: "\n") + "\n-----END OPENSSH PRIVATE KEY-----\n").write(to: renamed, atomically: false, encoding: .utf8)
        XCTAssertEqual(chmod(renamed.path, 0o600), 0)
        let review = try await destination.reviewImport(from: renamed, protection: .unencrypted)
        XCTAssertEqual(review.publicKey, key.publicKey)
        try await destination.cancelImportReview(review)
        let tool = SSHKeygenTool()
        let commentURL = url.deletingLastPathComponent().appendingPathComponent("comment-key")
        try await tool.generate(at: commentURL.path, algorithm: .ed25519, protection: .unencrypted, comment: "public fixture comment with spaces")
        let commented = try await destination.reviewImport(from: commentURL, protection: .unencrypted)
        XCTAssertFalse(commented.publicKey.copyString.contains("fixture"))
        try await destination.cancelImportReview(commented)
        try await source.close(); try await destination.close()
    }
}
