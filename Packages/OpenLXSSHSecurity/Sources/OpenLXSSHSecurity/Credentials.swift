import Foundation
import Security

/// Memory-only secret. Intentionally not Codable, Hashable or printable. Swift/Data can
/// copy bytes; this type does not promise complete zeroization of all compiler copies.
public struct SecretBytes: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let bytes: Data
    public init(_ bytes: Data) { self.bytes = bytes }
    public init(utf8 text: String) { bytes = Data(text.utf8) }
    public var description: String { "<redacted>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
    public func matches(_ other: SecretBytes) -> Bool { bytes == other.bytes }
    /// Access only at a direct, user-authorized authentication/input boundary, never log.
    public func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try bytes.withUnsafeBytes(body)
    }
    public static func random() throws -> SecretBytes {
        var value = Data(count: 32)
        let status = value.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw CredentialFailure.status(status) }
        return SecretBytes(value)
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
    case cancelled, interactionNotAllowed, unavailable, denied, duplicate, invalidData, closed
    case interactionPolicyRestoreFailed, status(Int32)
    static func from(_ status: OSStatus) -> CredentialFailure {
        switch status {
        case errSecUserCanceled: .cancelled
        case errSecInteractionNotAllowed: .interactionNotAllowed
        case errSecNotAvailable, errSecNoSuchKeychain, errSecNoDefaultKeychain, errSecInvalidKeychain: .unavailable
        case errSecAuthFailed: .denied
        case errSecDuplicateItem: .duplicate
        default: .status(status)
        }
    }
}

public enum CredentialSaveResult: Equatable, Sendable {
    case notAuthorized, saved(CredentialReference), failed(CredentialFailure)
}
public enum CredentialUpdateResult: Equatable, Sendable {
    case notAuthorized, missing, updated(CredentialReference), failed(CredentialFailure)
}
public enum CredentialReadResult: Sendable {
    case missing, available(SecretBytes), manualEntryRequired(CredentialFailure)
}
public enum CredentialDeleteResult: Equatable, Sendable {
    case deleted, alreadyAbsent
    /// Retain this exact reference in Core's cleanup journal and explicitly retry later.
    case retryRequired(CredentialFailure)
}
