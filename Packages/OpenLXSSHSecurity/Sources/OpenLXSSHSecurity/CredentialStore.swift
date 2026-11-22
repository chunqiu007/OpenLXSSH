import Foundation
import LocalAuthentication
import Security

protocol KeychainBackend: AnyObject, Sendable {
    func add(_ query: [String: Any]) -> OSStatus
    func copy(_ query: [String: Any]) -> (OSStatus, Data?)
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

private final class SystemKeychainBackend: KeychainBackend {
    func add(_ query: [String: Any]) -> OSStatus {
        SecItemAdd(query as CFDictionary, nil)
    }

    func copy(_ query: [String: Any]) -> (OSStatus, Data?) {
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        return (status, value as? Data)
    }

    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        SecItemDelete(query as CFDictionary)
    }
}

public enum KeychainStorageMode: String, Equatable, Sendable {
    case dataProtection
    case standard
}

/// Modern macOS Keychain credential store using per-operation non-interactive LAContext.
/// Prefers the Data Protection Keychain when entitlements are active, and cleanly falls back
/// to the standard Keychain (still non-interactive via LAContext, never synced) for unsigned
/// or ad-hoc builds without a Provisioning Profile.
/// Core owns metadata and shared-reference authorization before deleteExact().
public actor CredentialStore {
    public static let productionService = "org.openlxssh.credentials.v2"
    public static let legacyProductionService = "org.openlxssh.credentials"
    private static let testServicePrefix = "org.openlxssh.credentials.v2.test."
    private static let legacyTestServicePrefix = "org.openlxssh.credentials.test."
    public nonisolated let service: String
    private nonisolated let legacyService: String?
    public nonisolated let storageMode: KeychainStorageMode
    private let backend: any KeychainBackend
    private var closed = false

    public init() throws {
        self.init(service: Self.productionService, backend: SystemKeychainBackend(), storageMode: nil)
    }

    /// UUID-only namespace injection for isolated tests. Never use production namespace in tests.
    public init(testNamespace: UUID) throws {
        self.init(
            service: Self.testServicePrefix + testNamespace.uuidString,
            backend: SystemKeychainBackend(),
            storageMode: nil
        )
    }

    init(testNamespace: UUID, backend: any KeychainBackend, storageMode: KeychainStorageMode? = nil) {
        self.init(
            service: Self.testServicePrefix + testNamespace.uuidString,
            backend: backend,
            storageMode: storageMode
        )
    }

    init(service: String, backend: any KeychainBackend, storageMode: KeychainStorageMode?) {
        self.service = service
        if service == Self.productionService {
            self.legacyService = Self.legacyProductionService
        } else if service.hasPrefix(Self.testServicePrefix) {
            self.legacyService = Self.legacyTestServicePrefix + service.dropFirst(Self.testServicePrefix.count)
        } else {
            self.legacyService = nil
        }
        self.backend = backend
        self.storageMode = storageMode ?? Self.probeStorageMode(backend: backend, service: service)
    }

    private static func nonInteractiveContext() -> LAContext {
        let context = LAContext()
        context.interactionNotAllowed = true
        return context
    }

    /// Single zero-write probe for Data Protection Keychain entitlement availability.
    /// Note: on macOS 26, SecItemCopyMatching with kSecUseDataProtectionKeychain: true can
    /// return errSecItemNotFound even without entitlements, whereas SecItemUpdate on a
    /// non-existent random probe account reliably returns errSecMissingEntitlement (-34018)
    /// when unentitled and errSecItemNotFound (-25300) when entitled, without creating or
    /// modifying any Keychain item.
    private static func probeStorageMode(backend: any KeychainBackend, service: String) -> KeychainStorageMode {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "probe:\(UUID().uuidString)",
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: nonInteractiveContext()
        ]
        let status = backend.update(query, attributes: [kSecAttrLabel as String: ""])
        switch status {
        case errSecItemNotFound, errSecSuccess, errSecInteractionNotAllowed:
            return .dataProtection
        case errSecMissingEntitlement:
            return .standard
        default:
            return .standard
        }
    }

    /// Idempotent close. After closing, all subsequent operations fail with `.closed`.
    public func close() throws {
        closed = true
    }

    private func baseQuery(_ reference: CredentialReference) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: reference.account,
            kSecAttrSynchronizable as String: false,
            kSecUseAuthenticationContext as String: Self.nonInteractiveContext()
        ]
        if storageMode == .dataProtection {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
    }

    public func save(_ secret: SecretBytes, as reference: CredentialReference,
                     authorization: RememberAuthorization) -> CredentialSaveResult {
        guard authorization == .granted else { return .notAuthorized }
        guard !closed else { return .failed(.closed) }
        guard !secret.bytes.isEmpty else { return .failed(.invalidData) }
        var query = baseQuery(reference)
        if storageMode == .dataProtection {
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        query[kSecValueData as String] = secret.bytes
        let status = backend.add(query)
        return status == errSecSuccess ? .saved(reference) : .failed(.from(status))
    }

    public func read(_ reference: CredentialReference) -> CredentialReadResult {
        guard !closed else { return .manualEntryRequired(.closed) }
        var query = baseQuery(reference)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, data) = backend.copy(query)
        if status == errSecItemNotFound { return .missing }
        guard status == errSecSuccess else { return .manualEntryRequired(.from(status)) }
        guard let data, !data.isEmpty else { return .manualEntryRequired(.invalidData) }
        return .available(SecretBytes(data))
    }

    public func replace(_ secret: SecretBytes, at reference: CredentialReference,
                        authorization: RememberAuthorization) -> CredentialUpdateResult {
        guard authorization == .granted else { return .notAuthorized }
        guard !closed else { return .failed(.closed) }
        guard !secret.bytes.isEmpty else { return .failed(.invalidData) }
        var attributes: [String: Any] = [kSecValueData as String: secret.bytes]
        if storageMode == .dataProtection {
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        switch backend.update(baseQuery(reference), attributes: attributes) {
        case errSecSuccess: return .updated(reference)
        case errSecItemNotFound: return .missing
        case let status: return .failed(.from(status))
        }
    }

    private func legacyDeleteQuery(_ reference: CredentialReference, legacyService: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyService,
            kSecAttrAccount as String: reference.account,
            kSecAttrSynchronizable as String: false,
            kSecUseAuthenticationContext as String: Self.nonInteractiveContext()
        ]
    }

    /// Only Core can decide that no host/key still references this item.
    /// Deletes from the current v2 namespace and, when a matching legacy v1 namespace exists,
    /// also attempts exact deletion from standard Keychain v1 so "Forget" never silently leaves
    /// an old v1 secret behind. Never reads or migrates legacy v1 items.
    public func deleteExact(_ reference: CredentialReference) -> CredentialDeleteResult {
        guard !closed else { return .retryRequired(.closed) }
        let v2Status = backend.delete(baseQuery(reference))
        guard v2Status == errSecSuccess || v2Status == errSecItemNotFound else {
            return .retryRequired(.from(v2Status))
        }
        let deletedV2 = (v2Status == errSecSuccess)
        guard let legacyService else {
            return deletedV2 ? .deleted : .alreadyAbsent
        }
        let legacyStatus = backend.delete(legacyDeleteQuery(reference, legacyService: legacyService))
        switch legacyStatus {
        case errSecSuccess:
            return .deleted
        case errSecItemNotFound:
            return deletedV2 ? .deleted : .alreadyAbsent
        default:
            return .retryRequired(.from(legacyStatus))
        }
    }
}
