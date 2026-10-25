import Foundation
import Security
import XCTest
@testable import OpenLXSSHSecurity

final class InteractionStub: InteractionDriver {
    var allowed = true
    var sets: [Bool] = []
    var setFailure: OSStatus?
    func get() -> (OSStatus, Bool) { (errSecSuccess, allowed) }
    func set(_ allowed: Bool) -> OSStatus {
        sets.append(allowed)
        if let setFailure { return setFailure }
        self.allowed = allowed
        return errSecSuccess
    }
}
final class KeychainStub: KeychainBackend, @unchecked Sendable {
    var addStatus: OSStatus = errSecSuccess
    var readStatus: OSStatus = errSecItemNotFound
    var updateStatus: OSStatus = errSecSuccess
    var deleteStatus: OSStatus = errSecSuccess
    var readData: Data?
    var queries: [[String: Any]] = []
    var updates: [[String: Any]] = []
    func add(_ query: [String: Any]) -> OSStatus { queries.append(query); return addStatus }
    func copy(_ query: [String: Any]) -> (OSStatus, Data?) { queries.append(query); return (readStatus, readData) }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        queries.append(query); updates.append(attributes); return updateStatus
    }
    func delete(_ query: [String: Any]) -> OSStatus { queries.append(query); return deleteStatus }
}

@MainActor
final class CredentialStoreTests: XCTestCase {
    func testStableNamespaceTypesAndRedaction() throws {
        XCTAssertEqual(CredentialStore.productionService, "org.openlxssh.credentials")
        let id = UUID()
        XCTAssertNotEqual(CredentialReference(id: id, kind: .password).account,
                          CredentialReference(id: id, kind: .privateKeyPassphrase).account)
        let secret = try SecretBytes.random()
        XCTAssertEqual(String(describing: secret), "<redacted>")
        XCTAssertEqual(String(reflecting: secret), "<redacted>")
        XCTAssertTrue(Mirror(reflecting: secret).children.isEmpty)
    }

    func testNoAuthorizationNoBackendAndExplicitPolicy() async throws {
        let driver = InteractionStub(), backend = KeychainStub()
        let coordinator = KeychainProcessCoordinator(driver: driver)
        let namespace = UUID(), reference = CredentialReference(kind: .password)
        let store = try CredentialStore(testNamespace: namespace, backend: backend, coordinator: coordinator)
        let secret = try SecretBytes.random()
        let noSave = await store.save(secret, as: reference, authorization: .notGranted)
        let noReplace = await store.replace(secret, at: reference, authorization: .notGranted)
        XCTAssertEqual(noSave, .notAuthorized); XCTAssertEqual(noReplace, .notAuthorized)
        XCTAssertTrue(backend.queries.isEmpty)
        _ = await store.save(secret, as: reference, authorization: .granted)
        _ = await store.read(reference)
        _ = await store.replace(secret, at: reference, authorization: .granted)
        _ = await store.deleteExact(reference)
        for query in backend.queries {
            XCTAssertEqual(query[kSecAttrService as String] as? String, "org.openlxssh.credentials.test.\(namespace.uuidString)")
            XCTAssertEqual(query[kSecAttrAccount as String] as? String, reference.account)
            XCTAssertEqual(query[kSecAttrSynchronizable as String] as? Bool, false)
            XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, false)
            for key in [kSecAttrAccess, kSecAttrAccessControl, kSecAttrAccessGroup, kSecAttrAccessible, kSecUseAuthenticationContext] {
                XCTAssertNil(query[key as String])
            }
        }
        XCTAssertNotNil(backend.queries[0][kSecUseKeychain as String])
        XCTAssertNotNil(backend.queries[1][kSecMatchSearchList as String])
        XCTAssertEqual(backend.updates[0].count, 1)
        try await store.close()
        XCTAssertEqual(driver.sets, [false, true])
    }

    func testTwoOwnersNeverRestoreEarlyAndCloseIsIdempotent() async throws {
        let driver = InteractionStub()
        let shared = KeychainProcessCoordinator(driver: driver)
        let a = try CredentialStore(testNamespace: UUID(), backend: KeychainStub(), coordinator: shared)
        let b = try CredentialStore(testNamespace: UUID(), backend: KeychainStub(), coordinator: shared)
        XCTAssertEqual(driver.sets, [false])
        try await a.close()
        try await a.close()
        XCTAssertFalse(driver.allowed)
        XCTAssertEqual(driver.sets, [false])
        let ref = CredentialReference(kind: .password)
        let closedSave = await a.save(try .random(), as: ref, authorization: .granted)
        XCTAssertEqual(closedSave, .failed(.closed))
        try await b.close()
        XCTAssertTrue(driver.allowed)
        XCTAssertEqual(driver.sets, [false, true])
    }

    func testDeinitLastOwnerAndAlreadyDisabledPreviousState() async throws {
        let driver = InteractionStub()
        driver.allowed = false
        let coordinator = KeychainProcessCoordinator(driver: driver)
        var a: CredentialStore? = try CredentialStore(testNamespace: UUID(), backend: KeychainStub(), coordinator: coordinator)
        var b: CredentialStore? = try CredentialStore(testNamespace: UUID(), backend: KeychainStub(), coordinator: coordinator)
        XCTAssertNotNil(a); XCTAssertNotNil(b)
        a = nil
        XCTAssertEqual(driver.sets, [false])
        b = nil
        XCTAssertEqual(driver.sets, [false, false])
        XCTAssertFalse(driver.allowed)
    }

    func testCloseFailureCanBeExplicitlyRetried() async throws {
        let driver = InteractionStub()
        let shared = KeychainProcessCoordinator(driver: driver)
        let store = try CredentialStore(testNamespace: UUID(), backend: KeychainStub(), coordinator: shared)
        driver.setFailure = errSecNotAvailable
        do { try await store.close(); XCTFail("Restore failure hidden") }
        catch let failure as CredentialFailure { XCTAssertEqual(failure, .interactionPolicyRestoreFailed) }
        let rejected = await store.save(try .random(), as: .init(kind: .password), authorization: .granted)
        XCTAssertEqual(rejected, .failed(.closed))
        XCTAssertThrowsError(try CredentialStore(testNamespace: UUID(), backend: KeychainStub(), coordinator: shared)) {
            XCTAssertEqual($0 as? CredentialFailure, .interactionPolicyRestoreFailed)
        }
        driver.setFailure = nil
        try await store.close()
        XCTAssertTrue(driver.allowed)
    }

    func testFailedDeinitRestoreCanRecoverOnNextOwnerWithoutLosingOriginalState() throws {
        let driver = InteractionStub()
        let shared = KeychainProcessCoordinator(driver: driver)
        var store: CredentialStore? = try CredentialStore(testNamespace: UUID(), backend: KeychainStub(), coordinator: shared)
        XCTAssertNotNil(store)
        driver.setFailure = errSecNotAvailable
        store = nil
        XCTAssertFalse(driver.allowed)
        driver.setFailure = nil
        var recovered: CredentialStore? = try CredentialStore(testNamespace: UUID(), backend: KeychainStub(), coordinator: shared)
        XCTAssertNotNil(recovered)
        recovered = nil
        XCTAssertTrue(driver.allowed)
    }

    func testManualFallbackMissingDuplicateUpdateAndBoundedDeleteRetry() async throws {
        let backend = KeychainStub(), driver = InteractionStub()
        let store = try CredentialStore(testNamespace: UUID(), backend: backend, coordinator: KeychainProcessCoordinator(driver: driver))
        let reference = CredentialReference(kind: .privateKeyPassphrase)
        guard case .missing = await store.read(reference) else { return XCTFail("Missing not preserved") }
        let cases: [(OSStatus, CredentialFailure)] = [
            (errSecInteractionNotAllowed, .interactionNotAllowed), (errSecNotAvailable, .unavailable),
            (errSecNoSuchKeychain, .unavailable), (errSecNoDefaultKeychain, .unavailable),
            (errSecInvalidKeychain, .unavailable), (errSecUserCanceled, .cancelled),
            (errSecAuthFailed, .denied), (-12345, .status(-12345))
        ]
        for (status, expected) in cases {
            backend.readStatus = status; backend.deleteStatus = status
            guard case .manualEntryRequired(let failure) = await store.read(reference) else { return XCTFail("No manual fallback") }
            XCTAssertEqual(failure, expected)
            let before = backend.queries.count
            let deletion = await store.deleteExact(reference)
            XCTAssertEqual(deletion, .retryRequired(expected))
            XCTAssertEqual(backend.queries.count, before + 1)
        }
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

    func testConcurrentOwnersAndCallsSerializeOnePolicyLifetime() async throws {
        let driver = InteractionStub(), backend = KeychainStub()
        let coordinator = KeychainProcessCoordinator(driver: driver)
        let stores = try (0..<8).map { _ in try CredentialStore(testNamespace: UUID(), backend: backend, coordinator: coordinator) }
        await withTaskGroup(of: Void.self) { group in
            for store in stores {
                group.addTask { _ = await store.read(.init(kind: .password)); try? await store.close() }
            }
        }
        XCTAssertEqual(backend.queries.count, 8)
        XCTAssertEqual(driver.sets, [false, true])
    }
}
