import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import OpenLXSSHCredentialKeyProbe

final class StubKeychainBackend: KeychainBackend {
    var addStatus: OSStatus = errSecSuccess
    var copyStatus: OSStatus = errSecItemNotFound
    var copyData: Data?
    var updateStatus: OSStatus = errSecSuccess
    var updates: [([String: Any], [String: Any])] = []
    var deleteStatuses: [OSStatus] = [errSecSuccess]
    var adds: [[String: Any]] = []
    var copies: [[String: Any]] = []
    var deletes: [[String: Any]] = []
    func add(_ attributes: [String: Any]) -> OSStatus { adds.append(attributes); return addStatus }
    func copy(_ query: [String: Any]) -> (OSStatus, Data?) { copies.append(query); return (copyStatus, copyData) }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        updates.append((query, attributes)); return updateStatus
    }
    func delete(_ query: [String: Any]) -> OSStatus {
        deletes.append(query)
        return deleteStatuses.count > 1 ? deleteStatuses.removeFirst() : deleteStatuses[0]
    }
}

final class CredentialStoreTests: XCTestCase {
    func testNoAuthorizationNeverTouchesBackend() throws {
        let backend = StubKeychainBackend()
        let store = CredentialStore(namespace: UUID(), backend: backend)
        XCTAssertEqual(store.save(try .random(), as: .init(kind: .password), authorization: .notGranted), .notAuthorized)
        XCTAssertTrue(backend.adds.isEmpty)
        XCTAssertTrue(backend.copies.isEmpty)
        XCTAssertTrue(backend.deletes.isEmpty)
    }

    func testLocalUnlockedNoninteractivePolicyAndExactQueries() throws {
        let backend = StubKeychainBackend()
        let store = CredentialStore(namespace: UUID(), backend: backend)
        let reference = CredentialReference(kind: .privateKeyPassphrase)
        XCTAssertEqual(store.save(try .random(), as: reference, authorization: .granted), .saved(reference))
        _ = store.read(reference)
        _ = store.delete(reference)
        for query in backend.adds + backend.copies + backend.deletes {
            XCTAssertEqual(query[kSecAttrService as String] as? String, store.service)
            XCTAssertEqual(query[kSecAttrAccount as String] as? String, reference.account)
            XCTAssertEqual(query[kSecAttrSynchronizable as String] as? Bool, false)
            XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
            XCTAssertEqual((query[kSecUseAuthenticationContext as String] as? LAContext)?.interactionNotAllowed, true)
            XCTAssertNil(query[kSecAttrAccessControl as String])
        }
        XCTAssertEqual(backend.adds[0][kSecAttrAccessible as String] as? String,
                       kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        XCTAssertEqual(backend.copies[0][kSecMatchLimit as String] as? String, kSecMatchLimitOne as String)
    }

    func testReadMissingAndSuccessfulSecretNeverPrintsBytes() throws {
        let backend = StubKeychainBackend()
        let store = CredentialStore(namespace: UUID(), backend: backend)
        let reference = CredentialReference(kind: .password)
        guard case .missing = store.read(reference) else { return XCTFail("Missing result not preserved") }
        let secret = try SecretBytes.random()
        backend.copyStatus = errSecSuccess
        backend.copyData = secret.bytes
        guard case .available(let observed) = store.read(reference) else { return XCTFail("Missing secret result") }
        XCTAssertTrue(observed.matches(secret))
        XCTAssertEqual(String(describing: observed), "<redacted>")
        XCTAssertEqual(String(reflecting: observed), "<redacted>")
        XCTAssertTrue(Mirror(reflecting: observed).children.isEmpty)
    }

    func testFailureStatusesRequireManualEntryWithoutRetry() throws {
        let backend = StubKeychainBackend()
        let store = CredentialStore(namespace: UUID(), backend: backend)
        let reference = CredentialReference(kind: .password)
        let cases: [(OSStatus, CredentialFailure)] = [
            (errSecUserCanceled, .cancelled), (errSecInteractionNotAllowed, .interactionNotAllowed),
            (errSecNotAvailable, .unavailable), (errSecAuthFailed, .denied),
            (errSecMissingEntitlement, .missingEntitlement), (-12345, .status(-12345))
        ]
        for (status, expected) in cases {
            backend.copyStatus = status
            backend.addStatus = status
            let before = backend.copies.count
            guard case .manualEntryRequired(let failure) = store.read(reference) else { return XCTFail("No manual fallback") }
            XCTAssertEqual(failure, expected)
            XCTAssertEqual(backend.copies.count, before + 1)
            XCTAssertEqual(store.save(try .random(), as: reference, authorization: .granted), .failed(expected))
        }
    }

    func testDeletionRetryIsExplicitBoundedAndIdempotent() {
        let backend = StubKeychainBackend()
        backend.deleteStatuses = [errSecNotAvailable, errSecSuccess, errSecItemNotFound]
        let store = CredentialStore(namespace: UUID(), backend: backend)
        let reference = CredentialReference(kind: .password)
        XCTAssertEqual(store.delete(reference), .retryRequired(.unavailable))
        XCTAssertEqual(backend.deletes.count, 1)
        XCTAssertEqual(store.delete(reference), .deleted)
        XCTAssertEqual(store.delete(reference), .alreadyAbsent)
        XCTAssertEqual(backend.deletes.count, 3)
    }

    func testEmptyAndDuplicateCannotSilentlyOverwrite() throws {
        let backend = StubKeychainBackend()
        let store = CredentialStore(namespace: UUID(), backend: backend)
        let reference = CredentialReference(kind: .password)
        XCTAssertEqual(store.save(SecretBytes(Data()), as: reference, authorization: .granted), .failed(.invalidData))
        XCTAssertTrue(backend.adds.isEmpty)
        backend.addStatus = errSecDuplicateItem
        XCTAssertEqual(store.save(try .random(), as: reference, authorization: .granted), .failed(.duplicate))
        XCTAssertEqual(backend.adds.count, 1)
        XCTAssertTrue(backend.deletes.isEmpty)
        backend.copyStatus = errSecSuccess
        backend.copyData = Data()
        guard case .manualEntryRequired(.invalidData) = store.read(reference) else { return XCTFail("Invalid data not rejected") }
    }

    func testExplicitReplacementRequiresAuthorizationAndPreservesExactPolicy() throws {
        let backend = StubKeychainBackend()
        let store = CredentialStore(namespace: UUID(), backend: backend)
        let reference = CredentialReference(kind: .password)
        let secret = try SecretBytes.random()
        XCTAssertEqual(store.replace(secret, at: reference, authorization: .notGranted), .notAuthorized)
        XCTAssertTrue(backend.updates.isEmpty)
        XCTAssertEqual(store.replace(secret, at: reference, authorization: .granted), .updated(reference))
        XCTAssertEqual(backend.updates[0].0[kSecAttrAccount as String] as? String, reference.account)
        XCTAssertEqual(backend.updates[0].0[kSecAttrService as String] as? String, store.service)
        XCTAssertEqual(backend.updates[0].1[kSecAttrSynchronizable as String] as? Bool, false)
        XCTAssertEqual(backend.updates[0].1[kSecAttrAccessible as String] as? String,
                       kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        backend.updateStatus = errSecItemNotFound
        XCTAssertEqual(store.replace(secret, at: reference, authorization: .granted), .missing)
        backend.updateStatus = errSecNotAvailable
        XCTAssertEqual(store.replace(secret, at: reference, authorization: .granted), .failed(.unavailable))
        XCTAssertTrue(backend.adds.isEmpty)
        XCTAssertTrue(backend.deletes.isEmpty)
    }

    func testKindsAndNamespacesCannotCrossMatch() {
        let namespace = UUID()
        let a = CredentialStore(namespace: namespace, backend: StubKeychainBackend())
        let b = CredentialStore(namespace: UUID(), backend: StubKeychainBackend())
        XCTAssertNotEqual(a.service, b.service)
        let id = UUID()
        XCTAssertNotEqual(CredentialReference(id: id, kind: .password).account,
                          CredentialReference(id: id, kind: .privateKeyPassphrase).account)
    }
}

final class RealKeychainTests: XCTestCase {
    /// Deliberately neither skipped nor converted into a pass if this CLI lacks entitlements,
    /// if the Keychain is locked, or if system policy disallows access.
    func testRealUUIDNamespaceCRUDAndDeferredCleanup() throws {
        try LiveKeychainProbe.run()
    }
}
