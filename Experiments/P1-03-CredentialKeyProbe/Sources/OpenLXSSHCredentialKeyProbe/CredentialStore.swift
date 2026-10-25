import Foundation
import LocalAuthentication
import Security

/// In-memory only, deliberately neither Codable nor printable. Swift/Data may copy memory;
/// this probe does not promise that every copy can be zeroized.
public struct SecretBytes: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let bytes: Data

    public init(_ bytes: Data) { self.bytes = bytes }
    public var description: String { "<redacted>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
    public func matches(_ other: SecretBytes) -> Bool { bytes == other.bytes }

    public static func random() throws -> SecretBytes {
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw CredentialFailure.status(status) }
        return SecretBytes(bytes)
    }

    /// Printable random input for ssh-keygen's line-based prompt, never argv/environment.
    public static func randomPassphrase() throws -> SecretBytes {
        let random = try random()
        let alphabet = Array("0123456789abcdef".utf8)
        return SecretBytes(Data(random.bytes.flatMap { [alphabet[Int($0 >> 4)], alphabet[Int($0 & 15)]] }))
    }
}

public struct CredentialReference: Hashable, Sendable {
    public enum Kind: String, Sendable { case password, privateKeyPassphrase }
    public let id: UUID
    public let kind: Kind
    public init(id: UUID = UUID(), kind: Kind) { self.id = id; self.kind = kind }
    var account: String { "\(kind.rawValue):\(id.uuidString)" }
}

public enum RememberAuthorization: Sendable { case notGranted, granted }

public enum CredentialFailure: Error, Equatable, Sendable {
    case cancelled, interactionNotAllowed, unavailable, denied, missingEntitlement, duplicate, invalidData
    case status(Int32)

    public static func from(_ status: OSStatus) -> CredentialFailure {
        switch status {
        case errSecUserCanceled: .cancelled
        case errSecInteractionNotAllowed: .interactionNotAllowed
        case errSecNotAvailable: .unavailable
        case errSecAuthFailed: .denied
        case errSecMissingEntitlement: .missingEntitlement
        case errSecDuplicateItem: .duplicate
        default: .status(status)
        }
    }
}

public enum CredentialSaveResult: Equatable, Sendable {
    case notAuthorized
    case saved(CredentialReference)
    case failed(CredentialFailure)
}

public enum CredentialUpdateResult: Equatable, Sendable {
    case notAuthorized, missing
    case updated(CredentialReference)
    case failed(CredentialFailure)
}

public enum CredentialReadResult: Sendable {
    case missing
    case available(SecretBytes)
    /// Caller must ask for manual input; there is no automatic retry or disk fallback.
    case manualEntryRequired(CredentialFailure)
}

public enum CredentialDeleteResult: Equatable, Sendable {
    case deleted, alreadyAbsent
    /// Caller retains an exact-reference cleanup ticket and explicitly retries later.
    case retryRequired(CredentialFailure)
}

public protocol CredentialStorage: AnyObject {
    func save(_ secret: SecretBytes, as reference: CredentialReference,
              authorization: RememberAuthorization) -> CredentialSaveResult
    func read(_ reference: CredentialReference) -> CredentialReadResult
    func replace(_ secret: SecretBytes, at reference: CredentialReference,
                 authorization: RememberAuthorization) -> CredentialUpdateResult
    func delete(_ reference: CredentialReference) -> CredentialDeleteResult
}

// Injection is solely for status/policy tests. Production calls always use Security.framework.
protocol KeychainBackend {
    func add(_ attributes: [String: Any]) -> OSStatus
    func copy(_ query: [String: Any]) -> (OSStatus, Data?)
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

struct SecurityKeychainBackend: KeychainBackend {
    func add(_ attributes: [String: Any]) -> OSStatus { SecItemAdd(attributes as CFDictionary, nil) }
    func copy(_ query: [String: Any]) -> (OSStatus, Data?) {
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        return (status, value as? Data)
    }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }
    func delete(_ query: [String: Any]) -> OSStatus { SecItemDelete(query as CFDictionary) }
}

/// Exact service+account queries only. No enumeration, synchronization, biometrics,
/// login-keychain fallback or attempts to approve an authorization dialog.
public final class CredentialStore: CredentialStorage {
    let service: String
    private let backend: any KeychainBackend

    public convenience init(namespace: UUID) {
        self.init(namespace: namespace, backend: SecurityKeychainBackend())
    }

    init(namespace: UUID, backend: any KeychainBackend) {
        service = "org.openlxssh.p1-03.\(namespace.uuidString)"
        self.backend = backend
    }

    private func query(_ reference: CredentialReference) -> [String: Any] {
        let context = LAContext()
        context.interactionNotAllowed = true
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: reference.account,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context
        ]
    }

    public func save(_ secret: SecretBytes, as reference: CredentialReference,
                     authorization: RememberAuthorization) -> CredentialSaveResult {
        guard authorization == .granted else { return .notAuthorized }
        guard !secret.bytes.isEmpty else { return .failed(.invalidData) }
        var attributes = query(reference)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        attributes[kSecValueData as String] = secret.bytes
        let status = backend.add(attributes)
        return status == errSecSuccess ? .saved(reference) : .failed(.from(status))
    }

    /// Explicit authorized replacement, never an implicit duplicate-item overwrite/upsert.
    public func replace(_ secret: SecretBytes, at reference: CredentialReference,
                        authorization: RememberAuthorization) -> CredentialUpdateResult {
        guard authorization == .granted else { return .notAuthorized }
        guard !secret.bytes.isEmpty else { return .failed(.invalidData) }
        let attributes: [String: Any] = [
            kSecValueData as String: secret.bytes,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        switch backend.update(query(reference), attributes: attributes) {
        case errSecSuccess: return .updated(reference)
        case errSecItemNotFound: return .missing
        case let status: return .failed(.from(status))
        }
    }

    public func read(_ reference: CredentialReference) -> CredentialReadResult {
        var attributes = query(reference)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, data) = backend.copy(attributes)
        if status == errSecItemNotFound { return .missing }
        guard status == errSecSuccess else { return .manualEntryRequired(.from(status)) }
        guard let data, !data.isEmpty else { return .manualEntryRequired(.invalidData) }
        return .available(SecretBytes(data))
    }

    public func delete(_ reference: CredentialReference) -> CredentialDeleteResult {
        switch backend.delete(query(reference)) {
        case errSecSuccess: .deleted
        case errSecItemNotFound: .alreadyAbsent
        case let status: .retryRequired(.from(status))
        }
    }
}
