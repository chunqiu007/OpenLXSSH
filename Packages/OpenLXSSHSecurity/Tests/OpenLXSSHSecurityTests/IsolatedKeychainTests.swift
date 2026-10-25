import Darwin
import Foundation
import Security
import SecurityTestSupport
import XCTest
@testable import OpenLXSSHSecurity

private final class IsolatedKeychainBackend: KeychainBackend {
    func add(_ query: [String: Any]) -> OSStatus { SecItemAdd(query as CFDictionary, nil) }
    func copy(_ query: [String: Any]) -> (OSStatus, Data?) {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result as? Data)
    }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }
    func delete(_ query: [String: Any]) -> OSStatus { SecItemDelete(query as CFDictionary) }
}

func makeTemporaryRoot() throws -> URL {
    guard let parent = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw KeyFailure.invalidPath }
    defer { free(parent) }
    var template = Array((String(cString: parent) + "/OpenLXSSHSecurity-XXXXXX").utf8CString)
    guard mkdtemp(&template) != nil else { throw KeyFailure.systemCall("mkdtemp", errno) }
    return URL(fileURLWithPath: String(decoding: template.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
}

@MainActor
final class IsolatedKeychainTests: XCTestCase {
    func testRealSelfOwnedKeychainLockUnlockUnavailableAndCleanup() async throws {
        let root = try makeTemporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("only-test.keychain-db")
        func keychainState() throws -> (CFArray, SecKeychain) {
            var search: Unmanaged<CFArray>?, defaultKeychain: Unmanaged<SecKeychain>?
            guard olxs_test_copy_search_list(&search) == errSecSuccess,
                  olxs_test_copy_default(&defaultKeychain) == errSecSuccess,
                  let search, let defaultKeychain else { throw CredentialFailure.unavailable }
            return (search.takeRetainedValue(), defaultKeychain.takeRetainedValue())
        }
        let before = try keychainState()
        let random = try SecretBytes.random()
        let password = random.withUnsafeBytes { SecretBytes(utf8: Data($0).base64EncodedString()) }
        var handle: Unmanaged<SecKeychain>?
        let created = password.withUnsafeBytes { olxs_test_keychain_create(path.path, UInt32($0.count), $0.baseAddress, &handle) }
        guard created == errSecSuccess, let keychain = handle?.takeRetainedValue() else {
            XCTFail("Creating explicitly authorized isolated test Keychain failed, status=\(created)")
            return
        }
        var deleted = false
        defer { if !deleted { _ = olxs_test_keychain_delete(keychain) } }
        let during = try keychainState()
        XCTAssertTrue(CFEqual(before.0, during.0), "Creating own test Keychain must not change user search list")
        XCTAssertTrue(CFEqual(before.1, during.1), "Creating own test Keychain must not change user default")
        let store = try CredentialStore(testNamespace: UUID(), backend: IsolatedKeychainBackend(), selected: SelectedKeychain(keychain),
                                        coordinator: KeychainProcessCoordinator.shared)
        let reference = CredentialReference(kind: .password)
        let secret = try SecretBytes.random()
        let saved = await store.save(secret, as: reference, authorization: .granted)
        XCTAssertEqual(saved, .saved(reference))
        XCTAssertEqual(olxs_test_keychain_lock(keychain), errSecSuccess)
        guard case .manualEntryRequired(let locked) = await store.read(reference) else {
            try await store.close(); return XCTFail("Locked owned test Keychain did not require manual fallback")
        }
        XCTAssertTrue([CredentialFailure.interactionNotAllowed, .denied].contains(locked))
        let unlocked = password.withUnsafeBytes { olxs_test_keychain_unlock(keychain, UInt32($0.count), $0.baseAddress) }
        XCTAssertEqual(unlocked, errSecSuccess)
        guard case .available(let observed) = await store.read(reference) else {
            try await store.close(); return XCTFail("Owned Keychain did not recover after unlock")
        }
        XCTAssertTrue(observed.matches(secret))
        let removed = await store.deleteExact(reference)
        XCTAssertEqual(removed, .deleted)
        guard case .missing = await store.read(reference) else { return XCTFail("Own item remains") }
        XCTAssertEqual(olxs_test_keychain_delete(keychain), errSecSuccess)
        deleted = true
        // A deleted explicitly selected handle may yield unavailable/missing; record the
        // actual distinction rather than pretend we changed the user's default Keychain.
        switch await store.read(reference) {
        case .missing: print("ISOLATED KEYCHAIN after_delete_result: missing")
        case .manualEntryRequired(let failure):
            print("ISOLATED KEYCHAIN after_delete_result: \(failure)")
            XCTAssertEqual(failure, .unavailable)
        case .available: XCTFail("Deleted own test Keychain still yielded a secret")
        }
        try await store.close()
        let after = try keychainState()
        XCTAssertTrue(CFEqual(before.0, after.0))
        XCTAssertTrue(CFEqual(before.1, after.1))
        try FileManager.default.removeItem(at: root)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.path))
        print("ISOLATED KEYCHAIN lock_fallback_unlock_restore_cleanup: PASS; user_default_and_search_unchanged=true")
        XCTAssertFalse(FileManager.default.fileExists(atPath: path.path))
    }
}
