import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import OpenLXSSHSecurity

final class KeychainStub: KeychainBackend, @unchecked Sendable {
    private let lock = NSLock()
    var addStatus: OSStatus = errSecSuccess
    var readStatus: OSStatus = errSecItemNotFound
    var updateStatus: OSStatus = errSecSuccess
    var deleteStatus: OSStatus = errSecSuccess
    var readData: Data?
    var queries: [[String: Any]] = []
    var updates: [[String: Any]] = []

    func add(_ query: [String: Any]) -> OSStatus {
        lock.withLock {
            queries.append(query)
            return addStatus
        }
    }

    func copy(_ query: [String: Any]) -> (OSStatus, Data?) {
        lock.withLock {
            queries.append(query)
            return (readStatus, readData)
        }
    }

    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        lock.withLock {
            queries.append(query)
            updates.append(attributes)
            return updateStatus
        }
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        lock.withLock {
            queries.append(query)
            return deleteStatus
        }
    }
}

@MainActor
final class CredentialStoreTests: XCTestCase {
    func testStableNamespaceTypesAndRedaction() throws {
        XCTAssertEqual(CredentialStore.productionService, "org.openlxssh.credentials.v2")
        let id = UUID()
        XCTAssertNotEqual(
            CredentialReference(id: id, kind: .password).account,
            CredentialReference(id: id, kind: .privateKeyPassphrase).account
        )
        let secret = try SecretBytes.random()
        XCTAssertEqual(String(describing: secret), "<redacted>")
        XCTAssertEqual(String(reflecting: secret), "<redacted>")
        XCTAssertTrue(Mirror(reflecting: secret).children.isEmpty)
    }

    func testStorageModeProbeSelectsDataProtectionOrStandardFallback() {
        for status in [errSecItemNotFound, errSecSuccess, errSecInteractionNotAllowed] {
            let backend = KeychainStub()
            backend.updateStatus = status
            let store = CredentialStore(testNamespace: UUID(), backend: backend)
            XCTAssertEqual(store.storageMode, .dataProtection)
            XCTAssertEqual(backend.queries.count, 1)
            let probe = backend.queries[0]
            XCTAssertEqual(probe[kSecUseDataProtectionKeychain as String] as? Bool, true)
            XCTAssertEqual(probe[kSecAttrSynchronizable as String] as? Bool, false)
            let context = probe[kSecUseAuthenticationContext as String] as? LAContext
            XCTAssertEqual(context?.interactionNotAllowed, true)
            XCTAssertTrue((probe[kSecAttrAccount as String] as? String)?.hasPrefix("probe:") == true)
            XCTAssertNil(probe[kSecValueData as String])
        }

        let fallbackBackend = KeychainStub()
        fallbackBackend.updateStatus = errSecMissingEntitlement
        let fallbackStore = CredentialStore(testNamespace: UUID(), backend: fallbackBackend)
        XCTAssertEqual(fallbackStore.storageMode, .standard)
        XCTAssertEqual(fallbackBackend.queries.count, 1)
        XCTAssertEqual(fallbackBackend.queries[0][kSecUseDataProtectionKeychain as String] as? Bool, true)
    }

    func testDataProtectionQueriesAuthorizationAndLAContext() async throws {
        let backend = KeychainStub()
        let namespace = UUID()
        let reference = CredentialReference(kind: .password)
        let store = CredentialStore(testNamespace: namespace, backend: backend, storageMode: .dataProtection)
        let secret = try SecretBytes.random()

        let noSave = await store.save(secret, as: reference, authorization: .notGranted)
        let noReplace = await store.replace(secret, at: reference, authorization: .notGranted)
        XCTAssertEqual(noSave, .notAuthorized)
        XCTAssertEqual(noReplace, .notAuthorized)
        XCTAssertTrue(backend.queries.isEmpty)

        _ = await store.save(secret, as: reference, authorization: .granted)
        _ = await store.read(reference)
        _ = await store.replace(secret, at: reference, authorization: .granted)
        _ = await store.deleteExact(reference)

        XCTAssertEqual(backend.queries.count, 4)
        var contexts: [ObjectIdentifier] = []
        for query in backend.queries {
            XCTAssertEqual(query[kSecAttrService as String] as? String, "org.openlxssh.credentials.v2.test.\(namespace.uuidString)")
            XCTAssertEqual(query[kSecAttrAccount as String] as? String, reference.account)
            XCTAssertEqual(query[kSecAttrSynchronizable as String] as? Bool, false)
            XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
            let context = try XCTUnwrap(query[kSecUseAuthenticationContext as String] as? LAContext)
            XCTAssertTrue(context.interactionNotAllowed)
            contexts.append(ObjectIdentifier(context))
            XCTAssertNil(query[kSecAttrAccessGroup as String])
            XCTAssertNil(query[kSecAttrAccessControl as String])
        }
        // Every operation gets a fresh per-call LAContext.
        XCTAssertEqual(Set(contexts).count, 4)

        XCTAssertEqual(backend.queries[0][kSecAttrAccessible as String] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        XCTAssertNil(backend.queries[1][kSecAttrAccessible as String])
        XCTAssertNil(backend.queries[2][kSecAttrAccessible as String])
        XCTAssertNil(backend.queries[3][kSecAttrAccessible as String])
        XCTAssertEqual(backend.updates[0].count, 2)
        XCTAssertEqual(backend.updates[0][kSecAttrAccessible as String] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        XCTAssertNotNil(backend.updates[0][kSecValueData as String])
        try await store.close()
    }

    func testStandardFallbackQueriesUseLAContextWithoutDataProtectionOrLegacyHandles() async throws {
        let backend = KeychainStub()
        let namespace = UUID()
        let reference = CredentialReference(kind: .privateKeyPassphrase)
        let store = CredentialStore(testNamespace: namespace, backend: backend, storageMode: .standard)
        let secret = try SecretBytes.random()

        _ = await store.save(secret, as: reference, authorization: .granted)
        _ = await store.read(reference)
        _ = await store.replace(secret, at: reference, authorization: .granted)
        _ = await store.deleteExact(reference)

        XCTAssertEqual(backend.queries.count, 4)
        for query in backend.queries {
            XCTAssertEqual(query[kSecAttrService as String] as? String, "org.openlxssh.credentials.v2.test.\(namespace.uuidString)")
            XCTAssertEqual(query[kSecAttrAccount as String] as? String, reference.account)
            XCTAssertEqual(query[kSecAttrSynchronizable as String] as? Bool, false)
            XCTAssertNil(query[kSecUseDataProtectionKeychain as String])
            XCTAssertNil(query[kSecAttrAccessible as String])
            let context = try XCTUnwrap(query[kSecUseAuthenticationContext as String] as? LAContext)
            XCTAssertTrue(context.interactionNotAllowed)
        }
        XCTAssertEqual(backend.updates[0].count, 1)
        XCTAssertNotNil(backend.updates[0][kSecValueData as String])
        try await store.close()
    }

    func testCloseIsIdempotentAndBlocksSubsequentOperations() async throws {
        let backend = KeychainStub()
        let store = CredentialStore(testNamespace: UUID(), backend: backend, storageMode: .dataProtection)
        let ref = CredentialReference(kind: .password)
        let secret = try SecretBytes.random()

        try await store.close()
        try await store.close()

        let closedSave = await store.save(secret, as: ref, authorization: .granted)
        XCTAssertEqual(closedSave, .failed(.closed))
        let unauthSave = await store.save(secret, as: ref, authorization: .notGranted)
        XCTAssertEqual(unauthSave, .notAuthorized)
        let closedReplace = await store.replace(secret, at: ref, authorization: .granted)
        XCTAssertEqual(closedReplace, .failed(.closed))
        guard case .manualEntryRequired(.closed) = await store.read(ref) else {
            return XCTFail("Closed read must require manual entry with .closed")
        }
        let closedDelete = await store.deleteExact(ref)
        XCTAssertEqual(closedDelete, .retryRequired(.closed))
        XCTAssertTrue(backend.queries.isEmpty)
    }

    func testManualFallbackMissingDuplicateUpdateAndBoundedDeleteRetry() async throws {
        let backend = KeychainStub()
        let store = CredentialStore(testNamespace: UUID(), backend: backend, storageMode: .dataProtection)
        let reference = CredentialReference(kind: .privateKeyPassphrase)

        guard case .missing = await store.read(reference) else {
            return XCTFail("Missing not preserved")
        }

        let cases: [(OSStatus, CredentialFailure)] = [
            (errSecInteractionNotAllowed, .interactionNotAllowed),
            (errSecNotAvailable, .unavailable),
            (errSecNoSuchKeychain, .unavailable),
            (errSecNoDefaultKeychain, .unavailable),
            (errSecInvalidKeychain, .unavailable),
            (errSecUserCanceled, .cancelled),
            (errSecAuthFailed, .denied),
            (-12345, .status(-12345))
        ]
        for (status, expected) in cases {
            backend.readStatus = status
            backend.deleteStatus = status
            guard case .manualEntryRequired(let failure) = await store.read(reference) else {
                return XCTFail("No manual fallback")
            }
            XCTAssertEqual(failure, expected)
            let before = backend.queries.count
            let deletion = await store.deleteExact(reference)
            XCTAssertEqual(deletion, .retryRequired(expected))
            XCTAssertEqual(backend.queries.count, before + 1)
        }

        let emptySave = await store.save(SecretBytes(Data()), as: reference, authorization: .granted)
        XCTAssertEqual(emptySave, .failed(.invalidData))

        backend.addStatus = errSecDuplicateItem
        let duplicate = await store.save(try .random(), as: reference, authorization: .granted)
        XCTAssertEqual(duplicate, .failed(.duplicate))
        XCTAssertTrue(backend.updates.isEmpty)

        backend.updateStatus = errSecItemNotFound
        let missing = await store.replace(try .random(), at: reference, authorization: .granted)
        XCTAssertEqual(missing, .missing)

        backend.deleteStatus = errSecItemNotFound
        let absent = await store.deleteExact(reference)
        XCTAssertEqual(absent, .alreadyAbsent)

        try await store.close()
    }

    func testConcurrentIndependentStoresOperateWithoutSharedGlobalState() async throws {
        let backend = KeychainStub()
        let stores = (0..<8).map { _ in
            CredentialStore(testNamespace: UUID(), backend: backend, storageMode: .dataProtection)
        }
        await withTaskGroup(of: Void.self) { group in
            for store in stores {
                group.addTask {
                    _ = await store.read(.init(kind: .password))
                    try? await store.close()
                }
            }
        }
        XCTAssertEqual(backend.queries.count, 8)
    }
}
