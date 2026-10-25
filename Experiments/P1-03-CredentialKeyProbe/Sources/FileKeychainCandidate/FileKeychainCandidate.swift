import Darwin
import FileKeychainLegacy
import Foundation
import OpenLXSSHCredentialKeyProbe
import Security

public struct FileCandidateSecret: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let bytes: Data
    public init(_ bytes: Data) { self.bytes = bytes }
    public var description: String { "<redacted>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
    public func matches(_ other: FileCandidateSecret) -> Bool { bytes == other.bytes }
    public static func random() throws -> FileCandidateSecret {
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw FileCandidateFailure.keychain(.from(status)) }
        return FileCandidateSecret(bytes)
    }
}

public enum FileCandidateRead {
    case missing, available(FileCandidateSecret), manualEntryRequired(CredentialFailure)
}

public enum FileCandidateFailure: Error, Equatable {
    case keychain(CredentialFailure)
    case invalidItem, unexpectedPolicy, proofMismatch, invalidTicket, interactionRestoreFailed
}

/// An isolated, single-threaded fixture process only. This guard changes a *process*
/// legacy interaction flag, never user/global Keychain settings. Per-call restoration
/// is NOT safe to copy into a concurrent production application without serialization.
public final class FileKeychainNoUIProcess {
    private let previous: Bool
    private var finished = false
    public init() throws {
        var previous = DarwinBoolean(false)
        let status = fkc_begin_no_ui(&previous)
        guard status == errSecSuccess else { throw FileCandidateFailure.keychain(.from(status)) }
        self.previous = previous.boolValue
    }
    func requireActive() throws {
        guard !finished else { throw FileCandidateFailure.unexpectedPolicy }
    }
    public func finish() throws -> Bool {
        if finished { return true }
        var restored = DarwinBoolean(false)
        let status = fkc_end_no_ui(previous, &restored)
        finished = status == errSecSuccess && restored.boolValue
        guard finished else { throw FileCandidateFailure.interactionRestoreFailed }
        return true
    }
    deinit {
        if !finished { var restored = DarwinBoolean(false); _ = fkc_end_no_ui(previous, &restored) }
    }
}

protocol FileCandidateBackend {
    func add(_ query: [String: Any]) -> OSStatus
    func copy(_ query: [String: Any]) -> (OSStatus, Any?)
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

struct FileSecurityBackend: FileCandidateBackend {
    func add(_ query: [String: Any]) -> OSStatus { SecItemAdd(query as CFDictionary, nil) }
    func copy(_ query: [String: Any]) -> (OSStatus, Any?) {
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        return (status, value)
    }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }
    func delete(_ query: [String: Any]) -> OSStatus { SecItemDelete(query as CFDictionary) }
}

public struct FileCandidateACL: Equatable {
    public let decryptACLCount: UInt32
    public let trustedApplicationCount: UInt32
    public let unrestrictedDecryptACLCount: UInt32
    public let uninspectableDecryptACLCount: UInt32
    public let creatorMatchesTrustedApplication: Bool
    public let requiresPassphraseForDecrypt: Bool
    public let belongsToSelectedFileKeychain: Bool
    public let synchronizableAttributePresent: Bool
    public let synchronizableAttributeIsFalse: Bool
}

/// Explicit candidate, never instantiated by CredentialStore and never a DP error fallback.
/// Binds queries to the existing default file Keychain handle, not every search-list item.
/// Uses exact UUID service/account, default creator ACL, no custom SecAccess/allow-all list.
/// No accessibility class is claimed; accessibility follows actual file Keychain lock + ACL.
public final class FileKeychainCandidate {
    let service: String
    private let backend: any FileCandidateBackend
    private let selected: Any
    private let keychain: SecKeychain?
    private let interactionGuard: FileKeychainNoUIProcess?

    public init(namespace: UUID, noUIProcess: FileKeychainNoUIProcess) throws {
        try noUIProcess.requireActive()
        var unmanaged: Unmanaged<SecKeychain>?
        let status = fkc_copy_default(&unmanaged)
        guard status == errSecSuccess, let keychain = unmanaged?.takeRetainedValue() else { throw FileCandidateFailure.keychain(.from(status)) }
        service = "org.openlxssh.p1-03.file-candidate.\(namespace.uuidString)"
        selected = keychain
        self.keychain = keychain
        backend = FileSecurityBackend()
        interactionGuard = noUIProcess
    }

    init(namespace: UUID, backend: any FileCandidateBackend) {
        service = "org.openlxssh.p1-03.file-candidate.\(namespace.uuidString)"
        self.backend = backend
        selected = "unit-test-existing-keychain-handle"
        keychain = nil
        interactionGuard = nil
    }

    private func query(_ reference: CredentialReference, adding: Bool = false) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "\(reference.kind.rawValue):\(reference.id.uuidString)",
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: false
        ]
        if adding { query[kSecUseKeychain as String] = selected }
        else { query[kSecMatchSearchList as String] = [selected] }
        // Do not assume LAContext/UI query keys suppress legacy UI. The required process
        // guard is the documented SecKeychainSetUserInteractionAllowed(false) mechanism.
        return query
    }

    private var interactionActive: Bool {
        guard let interactionGuard else { return true } // injected backend only
        do { try interactionGuard.requireActive(); return true }
        catch { return false }
    }

    public func save(_ secret: FileCandidateSecret, as reference: CredentialReference,
                     authorization: RememberAuthorization) -> CredentialSaveResult {
        guard authorization == .granted else { return .notAuthorized }
        guard interactionActive else { return .failed(.interactionNotAllowed) }
        let bytes = secret.bytes
        guard !bytes.isEmpty else { return .failed(.invalidData) }
        var add = query(reference, adding: true)
        add[kSecValueData as String] = bytes
        let status = backend.add(add)
        return status == errSecSuccess ? .saved(reference) : .failed(.from(status))
    }

    public func read(_ reference: CredentialReference) -> FileCandidateRead {
        guard interactionActive else { return .manualEntryRequired(.interactionNotAllowed) }
        var read = query(reference)
        read[kSecReturnData as String] = true
        read[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, value) = backend.copy(read)
        if status == errSecItemNotFound { return .missing }
        guard status == errSecSuccess else { return .manualEntryRequired(.from(status)) }
        guard let bytes = value as? Data, !bytes.isEmpty else { return .manualEntryRequired(.invalidData) }
        return .available(FileCandidateSecret(bytes))
    }

    public func replace(_ secret: FileCandidateSecret, at reference: CredentialReference,
                        authorization: RememberAuthorization) -> CredentialUpdateResult {
        guard authorization == .granted else { return .notAuthorized }
        guard interactionActive else { return .failed(.interactionNotAllowed) }
        let bytes = secret.bytes
        guard !bytes.isEmpty else { return .failed(.invalidData) }
        switch backend.update(query(reference), attributes: [kSecValueData as String: bytes]) {
        case errSecSuccess: return .updated(reference)
        case errSecItemNotFound: return .missing
        case let status: return .failed(.from(status))
        }
    }

    public func delete(_ reference: CredentialReference) -> CredentialDeleteResult {
        guard interactionActive else { return .retryRequired(.interactionNotAllowed) }
        switch backend.delete(query(reference)) {
        case errSecSuccess: return .deleted
        case errSecItemNotFound: return .alreadyAbsent
        case let status: return .retryRequired(.from(status))
        }
    }

    public func currentKeychainUnlocked() throws -> Bool {
        guard let keychain else { throw FileCandidateFailure.invalidItem }
        var unlocked = DarwinBoolean(false)
        let status = fkc_default_status(keychain, &unlocked)
        guard status == errSecSuccess else { throw FileCandidateFailure.keychain(.from(status)) }
        return unlocked.boolValue
    }

    public func inspectOwnItem(_ reference: CredentialReference) throws -> FileCandidateACL {
        guard interactionActive else { throw FileCandidateFailure.keychain(.interactionNotAllowed) }
        guard let keychain else { throw FileCandidateFailure.invalidItem }
        var read = query(reference)
        read[kSecReturnRef as String] = true
        read[kSecReturnAttributes as String] = true
        read[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, value) = backend.copy(read)
        guard status == errSecSuccess else { throw FileCandidateFailure.keychain(.from(status)) }
        guard let attributes = value as? [String: Any], let itemValue = attributes[kSecValueRef as String] else {
            throw FileCandidateFailure.invalidItem
        }
        let opaque = itemValue as CFTypeRef
        guard CFGetTypeID(opaque) == fkc_keychain_item_type_id() else { throw FileCandidateFailure.invalidItem }
        let item = unsafeDowncast(opaque, to: SecKeychainItem.self)
        var summary = FKCAccessSummary()
        let aclStatus = fkc_inspect_own_item(item, keychain, &summary)
        guard aclStatus == errSecSuccess else { throw FileCandidateFailure.keychain(.from(aclStatus)) }
        let sync = attributes[kSecAttrSynchronizable as String] as? Bool
        return FileCandidateACL(decryptACLCount: summary.decrypt_acl_count,
                                trustedApplicationCount: summary.trusted_application_count,
                                unrestrictedDecryptACLCount: summary.unrestricted_decrypt_acl_count,
                                uninspectableDecryptACLCount: summary.uninspectable_decrypt_acl_count,
                                creatorMatchesTrustedApplication: summary.creator_matches_trusted_application.boolValue,
                                requiresPassphraseForDecrypt: summary.requires_passphrase_for_decrypt.boolValue,
                                belongsToSelectedFileKeychain: summary.belongs_to_selected_file_keychain.boolValue,
                                synchronizableAttributePresent: sync != nil,
                                synchronizableAttributeIsFalse: sync == false)
    }
}
