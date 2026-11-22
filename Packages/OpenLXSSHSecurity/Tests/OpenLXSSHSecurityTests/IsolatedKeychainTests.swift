import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHSecurity

func makeTemporaryRoot() throws -> URL {
    guard let parent = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw KeyFailure.invalidPath }
    defer { free(parent) }
    var template = Array((String(cString: parent) + "/OpenLXSSHSecurity-XXXXXX").utf8CString)
    guard mkdtemp(&template) != nil else { throw KeyFailure.systemCall("mkdtemp", errno) }
    return URL(fileURLWithPath: String(decoding: template.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
}

@MainActor
final class IsolatedKeychainTests: XCTestCase {
    func testRealKeychainCRUDDuplicateReplaceExactDeleteAndClose() async throws {
        let store = try CredentialStore(testNamespace: UUID())
        let reference = CredentialReference(kind: .password)
        let unapproved = CredentialReference(kind: .privateKeyPassphrase)
        let secret = try SecretBytes.random()
        let replacement = try SecretBytes.random()

        // Ensure test items are always cleaned up even if an assertion fails mid-test.
        addTeardownBlock {
            _ = await store.deleteExact(reference)
            _ = await store.deleteExact(unapproved)
            try? await store.close()
        }

        XCTAssertTrue([KeychainStorageMode.dataProtection, .standard].contains(store.storageMode))

        let denied = await store.save(secret, as: unapproved, authorization: .notGranted)
        XCTAssertEqual(denied, .notAuthorized)
        guard case .missing = await store.read(unapproved) else {
            return XCTFail("Unauthorized save wrote an item to Keychain")
        }

        let saved = await store.save(secret, as: reference, authorization: .granted)
        XCTAssertEqual(saved, .saved(reference))

        let duplicate = await store.save(replacement, as: reference, authorization: .granted)
        XCTAssertEqual(duplicate, .failed(.duplicate))

        guard case .available(let observed) = await store.read(reference) else {
            return XCTFail("Saved item could not be read back from Keychain")
        }
        XCTAssertTrue(observed.matches(secret))

        let unauthReplace = await store.replace(replacement, at: reference, authorization: .notGranted)
        XCTAssertEqual(unauthReplace, .notAuthorized)

        let updated = await store.replace(replacement, at: reference, authorization: .granted)
        XCTAssertEqual(updated, .updated(reference))

        guard case .available(let afterReplace) = await store.read(reference) else {
            return XCTFail("Updated item could not be read back from Keychain")
        }
        XCTAssertTrue(afterReplace.matches(replacement))

        let removed = await store.deleteExact(reference)
        XCTAssertEqual(removed, .deleted)
        guard case .missing = await store.read(reference) else {
            return XCTFail("Deleted item still present in Keychain")
        }
        let absent = await store.deleteExact(reference)
        XCTAssertEqual(absent, .alreadyAbsent)

        try await store.close()
        try await store.close()
        let closedSave = await store.save(secret, as: reference, authorization: .granted)
        XCTAssertEqual(closedSave, .failed(.closed))
    }
}
