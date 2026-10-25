import Darwin
import Foundation
import SecurityTestSupport
import SecurityPOSIX
import XCTest
@testable import OpenLXSSHSecurity

/// ACL edits are restricted to this test's newly created 0700 UUID tree. No user key,
/// Keychain ACL, parent temporary directory ACL or application directory is changed.
private final class ACLFixture {
    let root: URL

    init() throws {
        guard let parent = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw KeyFailure.invalidPath }
        defer { free(parent) }
        root = URL(fileURLWithPath: String(cString: parent))
            .appendingPathComponent("OpenLXSSHSecurity-ACL-\(UUID().uuidString)", isDirectory: true)
        guard mkdir(root.path, 0o700) == 0 else { throw KeyFailure.systemCall("create ACL fixture", errno) }
    }

    func cleanup(file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNoThrow(try FileManager.default.removeItem(at: root), file: file, line: line)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.path), "Own UUID tree remains", file: file, line: line)
    }

    private func withDescriptor<T>(_ url: URL, body: (Int32) throws -> T) throws -> T {
        guard url == root || url.path.hasPrefix(root.path + "/") else { throw KeyFailure.invalidPath }
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw KeyFailure.systemCall("open ACL fixture", errno) }
        defer { _ = Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == geteuid() else { throw KeyFailure.unsafePermissions }
        return try body(fd)
    }

    func setACL(_ url: URL, inheritable: Bool = false, denyOnly: Bool = false) throws {
        let code = try withDescriptor(url) { olxs_test_set_everyone_file_acl($0, inheritable ? 1 : 0, denyOnly ? 1 : 0) }
        guard code == 0 else { throw KeyFailure.systemCall("set own fixture ACL", code) }
    }

    func clearACL(_ url: URL) throws {
        let code = try withDescriptor(url) { olxs_test_clear_file_acl($0) }
        guard code == 0 else { throw KeyFailure.systemCall("clear own fixture ACL", code) }
    }

    func state(_ url: URL) throws -> Int32 {
        try withDescriptor(url) { fd in
            var state: Int32 = 0
            let code = olxs_test_file_acl_state(fd, &state)
            guard code == 0 else { throw KeyFailure.systemCall("query own fixture ACL", code) }
            return state
        }
    }

    func mode(_ url: URL) throws -> mode_t {
        try withDescriptor(url) { fd in
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw KeyFailure.systemCall("stat ACL fixture", errno) }
            return info.st_mode & 0o777
        }
    }
}

@MainActor
final class KeyACLTests: XCTestCase {
    private func expectUnsafe<T>(_ operation: () async throws -> T,
                                 file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await operation()
            XCTFail("Extended ACL accepted", file: file, line: line)
        } catch let error as KeyFailure {
            XCTAssertEqual(error, .unsafePermissions, file: file, line: line)
        } catch let error as KeyOperationFailure {
            XCTAssertEqual(error.primary, .unsafePermissions, file: file, line: line)
        } catch {
            XCTFail("Unexpected failure type: \(type(of: error))", file: file, line: line)
        }
    }

    func testInheritedEveryoneACLRejectsNewLeafBeforeGenerateOrLock() async throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        try fixture.setACL(fixture.root, inheritable: true)
        let parentACL = try fixture.state(fixture.root)
        XCTAssertEqual(parentACL & 5, 5)
        let leaf = fixture.root.appendingPathComponent("Keys")
        await expectUnsafe {
            let store = try KeyStore(directory: leaf)
            do { _ = try await store.generateEd25519(protection: .unencrypted) }
            catch { try await store.close(); throw error }
            try await store.close()
        }
        XCTAssertEqual(try fixture.mode(leaf), 0o700, "0700 must not be mistaken for absent ACL")
        XCTAssertEqual(try fixture.state(leaf) & 7, 7, "Rejection must preserve inherited ACL, not clear it")
        XCTAssertEqual(try fixture.state(fixture.root), parentACL)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: leaf.path), [], "No lock or private key before rejection")
    }

    func testInheritedEveryoneACLRejectsNewDestinationBeforeImport() async throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        let source = try KeyStore(directory: fixture.root.appendingPathComponent("Source"))
        let key = try await source.generateEd25519(protection: .unencrypted)
        let sourceURL = source.rootURL.appendingPathComponent("\(key.id.uuidString).openssh")
        let original = try PrivateDirectory.readSource(sourceURL)
        let parent = fixture.root.appendingPathComponent("InheritedParent")
        guard mkdir(parent.path, 0o700) == 0 else { throw KeyFailure.systemCall("create test parent", errno) }
        try fixture.setACL(parent, inheritable: true)
        let leaf = parent.appendingPathComponent("Keys")
        await expectUnsafe {
            let store = try KeyStore(directory: leaf)
            do { _ = try await store.importKey(from: sourceURL, protection: .unencrypted) }
            catch { try await store.close(); throw error }
            try await store.close()
        }
        XCTAssertEqual(try fixture.state(leaf) & 7, 7)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: leaf.path), [])
        XCTAssertTrue(try PrivateDirectory.readSource(sourceURL) == original, "Source must remain unchanged")
        XCTAssertEqual(try fixture.state(sourceURL), 0)
        try await source.close()
    }

    func testExistingRootAndLockACLRejectReopenWithoutClearing() async throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        let leaf = fixture.root.appendingPathComponent("Keys")
        let store = try KeyStore(directory: leaf)
        try await store.close()
        let lock = leaf.appendingPathComponent(".OpenLXSSH.lock")
        for target in [leaf, lock] {
            try fixture.setACL(target, inheritable: target == leaf)
            let acl = try fixture.state(target)
            await expectUnsafe {
                let reopened = try KeyStore(directory: leaf)
                try await reopened.close()
            }
            XCTAssertEqual(try fixture.state(target), acl, "Existing ACL must not be removed")
            XCTAssertEqual(try fixture.mode(target), target == leaf ? 0o700 : 0o600)
            try fixture.clearACL(target)
        }
        let reopened = try KeyStore(directory: leaf)
        try await reopened.close()
    }

    func testImportSourceInheritedACLIsRejectedBeforeParsingAndNeverChanged() async throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        let store = try KeyStore(directory: fixture.root.appendingPathComponent("Keys"))
        let parent = fixture.root.appendingPathComponent("SourceParent")
        guard mkdir(parent.path, 0o700) == 0 else { throw KeyFailure.systemCall("create test parent", errno) }
        try fixture.setACL(parent, inheritable: true)
        let source = parent.appendingPathComponent("not-a-private-key")
        let fd = Darwin.open(source.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw KeyFailure.systemCall("create source fixture", errno) }
        // Deliberately not a key: ACL rejection must precede parsing these nonsecret bytes.
        let marker = Data("invalid framing, never a secret".utf8)
        let written = marker.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        _ = Darwin.close(fd)
        XCTAssertEqual(written, marker.count)
        XCTAssertEqual(try fixture.mode(source), 0o600)
        XCTAssertEqual(try fixture.state(source) & 7, 7)
        await expectUnsafe { try await store.importKey(from: source, protection: .unencrypted) }
        XCTAssertEqual(try fixture.state(source) & 7, 7)
        XCTAssertTrue(try Data(contentsOf: source) == marker)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: store.rootURL.path), [".OpenLXSSH.lock"])
        try await store.close()
    }

    func testRuntimeRootACLBlocksReadGenerateImportAndDirectWrite() async throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        let source = try KeyStore(directory: fixture.root.appendingPathComponent("Source"))
        let original = try await source.generateEd25519(protection: .unencrypted)
        let sourceURL = source.rootURL.appendingPathComponent("\(original.id.uuidString).openssh")
        let leaf = fixture.root.appendingPathComponent("Keys")
        let store = try KeyStore(directory: leaf)
        let key = try await store.generateEd25519(protection: .unencrypted)
        let before = try FileManager.default.contentsOfDirectory(atPath: leaf.path).sorted()
        try fixture.setACL(leaf, inheritable: true)
        await expectUnsafe { try await store.key(id: key.id) }
        await expectUnsafe { try await store.generateEd25519(protection: .unencrypted) }
        await expectUnsafe { try await store.importKey(from: sourceURL, protection: .unencrypted) }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: leaf.path).sorted(), before)
        try fixture.clearACL(leaf)
        let loaded = try await store.key(id: key.id)
        XCTAssertEqual(loaded, key)
        try await store.close()
        try await source.close()

        let directory = try PrivateDirectory(directory: fixture.root.appendingPathComponent("Direct"))
        try fixture.setACL(directory.url, inheritable: true)
        var created = false
        XCTAssertThrowsError(try directory.write(Data("nonsecret".utf8), name: "pending", created: &created)) {
            XCTAssertEqual($0 as? KeyFailure, .unsafePermissions)
        }
        XCTAssertFalse(created)
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.url.appendingPathComponent("pending").path))
    }

    func testRuntimeLockACLBlocksUseAndRetainsPermissionError() async throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        let store = try KeyStore(directory: fixture.root.appendingPathComponent("Keys"))
        let key = try await store.generateEd25519(protection: .unencrypted)
        let lock = store.rootURL.appendingPathComponent(".OpenLXSSH.lock")
        try fixture.setACL(lock)
        await expectUnsafe { try await store.key(id: key.id) }
        await expectUnsafe { try await store.generateEd25519(protection: .unencrypted) }
        XCTAssertEqual(try fixture.state(lock) & 5, 5)
        try fixture.clearACL(lock)
        let loaded = try await store.key(id: key.id)
        XCTAssertEqual(loaded, key)
        try await store.close()
    }

    func testFinalKeyACLRejectedAfterReopenAndRuntimeAndSourceNotImported() async throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        let leaf = fixture.root.appendingPathComponent("Keys")
        let store = try KeyStore(directory: leaf)
        let key = try await store.generateEd25519(protection: .unencrypted)
        let final = leaf.appendingPathComponent("\(key.id.uuidString).openssh")
        try await store.close()
        try fixture.setACL(final)
        let reopened = try KeyStore(directory: leaf) // No scanning of unreferenced files.
        await expectUnsafe { try await reopened.key(id: key.id) }
        let destination = try KeyStore(directory: fixture.root.appendingPathComponent("Destination"))
        await expectUnsafe { try await destination.importKey(from: final, protection: .unencrypted) }
        XCTAssertEqual(try fixture.state(final) & 5, 5)
        try fixture.clearACL(final)
        let loaded = try await reopened.key(id: key.id)
        XCTAssertEqual(loaded, key)
        try fixture.setACL(final)
        await expectUnsafe { try await reopened.key(id: key.id) }
        try await reopened.close()
        try await destination.close()
    }

    func testStagingACLRejectedBeforeReadOrCommitAndIsNotCleared() throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        let directory = try PrivateDirectory(directory: fixture.root.appendingPathComponent("Keys"))
        var created = false
        try directory.write(Data("not secret staging".utf8), name: "stage", created: &created)
        let stage = directory.url.appendingPathComponent("stage")
        try fixture.setACL(stage)
        XCTAssertEqual(try fixture.mode(stage), 0o600)
        XCTAssertThrowsError(try directory.read("stage")) { XCTAssertEqual($0 as? KeyFailure, .unsafePermissions) }
        var committed = false
        XCTAssertThrowsError(try directory.commit(stage: "stage", destination: "final", committed: &committed)) {
            XCTAssertEqual($0 as? KeyFailure, .unsafePermissions)
        }
        XCTAssertFalse(committed)
        XCTAssertTrue(FileManager.default.fileExists(atPath: stage.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.url.appendingPathComponent("final").path))
        if !committed { XCTAssertEqual(try fixture.state(stage) & 5, 5) }
    }

    func testDenyOnlyACLIsConservativelyRejected() async throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        let store = try KeyStore(directory: fixture.root.appendingPathComponent("Keys"))
        let key = try await store.generateEd25519(protection: .unencrypted)
        let final = store.rootURL.appendingPathComponent("\(key.id.uuidString).openssh")
        try fixture.setACL(final, denyOnly: true)
        await expectUnsafe { try await store.key(id: key.id) }
        XCTAssertEqual(try fixture.state(final), 1)
        try await store.close()
    }

    func testACLQueryFailureIsDistinctAndFailClosed() throws {
        var present: Int32 = 0
        XCTAssertEqual(olxs_file_has_extended_acl(-1, &present), EBADF)
        XCTAssertEqual(present, 1, "ACL query failure must never look like an ACL-free file")
        XCTAssertThrowsError(try PrivateDirectory.requireNoExtendedACL(-1)) {
            XCTAssertEqual($0 as? KeyFailure, .systemCall("query filesystem ACL", EBADF))
        }
    }

    func testPlain07000600GenerateImportAndReopenRemainCompatible() async throws {
        let fixture = try ACLFixture()
        defer { fixture.cleanup() }
        let source = try KeyStore(directory: fixture.root.appendingPathComponent("Source"))
        let destinationURL = fixture.root.appendingPathComponent("Keys")
        let destination = try KeyStore(directory: destinationURL)
        let original = try await source.generateEd25519(protection: .unencrypted)
        let sourceURL = source.rootURL.appendingPathComponent("\(original.id.uuidString).openssh")
        let copy = try await destination.importKey(from: sourceURL, protection: .unencrypted)
        XCTAssertEqual(copy.publicKey, original.publicKey)
        XCTAssertEqual(try fixture.mode(destinationURL), 0o700)
        for file in [sourceURL, destinationURL.appendingPathComponent("\(copy.id.uuidString).openssh"),
                     destinationURL.appendingPathComponent(".OpenLXSSH.lock")] {
            XCTAssertEqual(try fixture.mode(file), 0o600)
            XCTAssertEqual(try fixture.state(file), 0)
        }
        XCTAssertEqual(try fixture.state(destinationURL), 0)
        try await destination.close()
        let reopened = try KeyStore(directory: destinationURL)
        let loaded = try await reopened.key(id: copy.id)
        XCTAssertEqual(loaded, copy)
        try await reopened.close()
        try await source.close()
    }
}
