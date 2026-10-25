import Foundation
import Security
import SecurityPOSIX

protocol KeychainBackend: AnyObject, Sendable {
    func add(_ query: [String: Any]) -> OSStatus
    func copy(_ query: [String: Any]) -> (OSStatus, Data?)
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

private final class SystemKeychainBackend: KeychainBackend {
    func add(_ query: [String: Any]) -> OSStatus { SecItemAdd(query as CFDictionary, nil) }
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

struct SelectedKeychain: @unchecked Sendable {
    // Opaque immutable Security handle; every use is serialized by the shared coordinator.
    let value: Any
    init(_ value: Any) { self.value = value }
}

protocol InteractionDriver: AnyObject {
    func get() -> (OSStatus, Bool)
    func set(_ allowed: Bool) -> OSStatus
}
private final class SystemInteractionDriver: InteractionDriver {
    func get() -> (OSStatus, Bool) {
        var allowed = DarwinBoolean(false)
        let status = olxs_interaction_get(&allowed)
        return (status, allowed.boolValue)
    }
    func set(_ allowed: Bool) -> OSStatus { olxs_interaction_set(allowed) }
}

/// This *single serial queue* owns every library SecItem call, every lease transition,
/// and the process-wide legacy interaction setting. Never restore while another store
/// or an in-flight queue operation still owns a lease. No per-call restore races.
/// Other code in the App must not independently toggle the legacy process flag.
final class KeychainProcessCoordinator: @unchecked Sendable {
    static let shared = KeychainProcessCoordinator(driver: SystemInteractionDriver())
    private let queue = DispatchQueue(label: "org.openlxssh.security.keychain")
    private let driver: any InteractionDriver
    private var leases: Set<UUID> = []
    private var savedInteraction: Bool?
    private var restorePending = false

    init(driver: any InteractionDriver) { self.driver = driver }
    func sync<T>(_ body: () throws -> T) rethrows -> T { try queue.sync(execute: body) }

    // Must be called within sync. Kept internal for deterministic policy tests.
    func acquire() throws -> UUID {
        guard !restorePending || leases.isEmpty else { throw CredentialFailure.interactionPolicyRestoreFailed }
        if leases.isEmpty {
            let (status, previous) = driver.get()
            guard status == errSecSuccess else { throw CredentialFailure.from(status) }
            if savedInteraction == nil { savedInteraction = previous }
            let setStatus = driver.set(false)
            guard setStatus == errSecSuccess else {
                restorePending = true
                _ = try? restore()
                throw CredentialFailure.from(setStatus)
            }
            let (verified, allowed) = driver.get()
            guard verified == errSecSuccess, !allowed else {
                restorePending = true
                _ = try? restore()
                throw CredentialFailure.interactionNotAllowed
            }
            restorePending = false
        }
        let token = UUID()
        leases.insert(token)
        return token
    }

    func require(_ token: UUID) throws {
        guard leases.contains(token), !restorePending else { throw CredentialFailure.closed }
    }

    func release(_ token: UUID) throws {
        guard leases.contains(token) else {
            if leases.isEmpty, restorePending { try restore() }
            return
        }
        if leases.count > 1 { leases.remove(token); return }
        // Keep the final lease if restore fails, so explicit close can retry.
        try restore()
        leases.remove(token)
    }

    func abandon(_ token: UUID) {
        do { try release(token) }
        catch {
            // Object cannot retry after deinit. Preserve saved state for the next acquisition,
            // and keep UI disabled on failure rather than restoring early for another owner.
            leases.remove(token)
            restorePending = true
        }
    }

    private func restore() throws {
        guard let previous = savedInteraction else { return }
        let status = driver.set(previous)
        let (readStatus, observed) = driver.get()
        guard status == errSecSuccess, readStatus == errSecSuccess, observed == previous else {
            restorePending = true
            throw CredentialFailure.interactionPolicyRestoreFailed
        }
        savedInteraction = nil
        restorePending = false
    }
}

/// Explicit V1 file-based Keychain store (ADR-P1-03). No DP fallback, custom ACL,
/// synchronization, biometrics or claim of ThisDeviceOnly/screen-lock semantics.
/// Core owns metadata and shared-reference authorization before deleteExact().
public actor CredentialStore {
    public static let productionService = "org.openlxssh.credentials"
    public nonisolated let service: String
    private let coordinator: KeychainProcessCoordinator
    private let backend: any KeychainBackend
    private let selected: Any
    private let lease: UUID
    private var closed = false
    private var closing = false

    public init() throws {
        try self.init(service: Self.productionService)
    }
    /// UUID-only namespace injection for isolated tests. Never use production namespace in tests.
    public init(testNamespace: UUID) throws {
        try self.init(service: "org.openlxssh.credentials.test.\(testNamespace.uuidString)")
    }
    private init(service: String) throws {
        let coordinator = KeychainProcessCoordinator.shared
        let opened: (UUID, SecKeychain) = try coordinator.sync {
            let lease = try coordinator.acquire()
            do {
                var value: Unmanaged<SecKeychain>?
                let status = olxs_copy_default_keychain(&value)
                guard status == errSecSuccess, let keychain = value?.takeRetainedValue() else {
                    throw CredentialFailure.from(status)
                }
                return (lease, keychain)
            } catch { coordinator.abandon(lease); throw error }
        }
        self.service = service
        self.coordinator = coordinator
        backend = SystemKeychainBackend()
        lease = opened.0
        selected = opened.1
    }

    init(testNamespace: UUID, backend: any KeychainBackend, selected: SelectedKeychain = .init("test-handle"),
         coordinator: KeychainProcessCoordinator) throws {
        service = "org.openlxssh.credentials.test.\(testNamespace.uuidString)"
        self.backend = backend
        self.selected = selected.value
        self.coordinator = coordinator
        lease = try coordinator.sync { try coordinator.acquire() }
    }

    deinit {
        let coordinator = coordinator, lease = lease
        coordinator.sync { coordinator.abandon(lease) }
    }

    /// Explicit bounded close, retryable if process-flag restoration failed.
    public func close() throws {
        if closed { return }
        closing = true
        try coordinator.sync { try coordinator.release(lease) }
        closed = true
    }

    private func query(_ reference: CredentialReference, adding: Bool = false) -> [String: Any] {
        var value: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: reference.account,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: false
        ]
        if adding { value[kSecUseKeychain as String] = selected }
        else { value[kSecMatchSearchList as String] = [selected] }
        return value
    }

    public func save(_ secret: SecretBytes, as reference: CredentialReference,
                     authorization: RememberAuthorization) -> CredentialSaveResult {
        guard authorization == .granted else { return .notAuthorized }
        guard !closed, !closing else { return .failed(.closed) }
        guard !secret.bytes.isEmpty else { return .failed(.invalidData) }
        return coordinator.sync {
            do { try coordinator.require(lease) } catch { return .failed(.closed) }
            var value = query(reference, adding: true)
            value[kSecValueData as String] = secret.bytes
            let status = backend.add(value)
            return status == errSecSuccess ? .saved(reference) : .failed(.from(status))
        }
    }

    public func read(_ reference: CredentialReference) -> CredentialReadResult {
        guard !closed, !closing else { return .manualEntryRequired(.closed) }
        return coordinator.sync {
            do { try coordinator.require(lease) } catch { return .manualEntryRequired(.closed) }
            var value = query(reference)
            value[kSecReturnData as String] = true
            value[kSecMatchLimit as String] = kSecMatchLimitOne
            let (status, data) = backend.copy(value)
            if status == errSecItemNotFound { return .missing }
            guard status == errSecSuccess else { return .manualEntryRequired(.from(status)) }
            guard let data, !data.isEmpty else { return .manualEntryRequired(.invalidData) }
            return .available(SecretBytes(data))
        }
    }

    public func replace(_ secret: SecretBytes, at reference: CredentialReference,
                        authorization: RememberAuthorization) -> CredentialUpdateResult {
        guard authorization == .granted else { return .notAuthorized }
        guard !closed, !closing else { return .failed(.closed) }
        guard !secret.bytes.isEmpty else { return .failed(.invalidData) }
        return coordinator.sync {
            do { try coordinator.require(lease) } catch { return .failed(.closed) }
            switch backend.update(query(reference), attributes: [kSecValueData as String: secret.bytes]) {
            case errSecSuccess: return .updated(reference)
            case errSecItemNotFound: return .missing
            case let status: return .failed(.from(status))
            }
        }
    }

    /// Only Core can decide that no host/key still references this item. One attempt only.
    public func deleteExact(_ reference: CredentialReference) -> CredentialDeleteResult {
        guard !closed, !closing else { return .retryRequired(.closed) }
        return coordinator.sync {
            do { try coordinator.require(lease) } catch { return .retryRequired(.closed) }
            switch backend.delete(query(reference)) {
            case errSecSuccess: return .deleted
            case errSecItemNotFound: return .alreadyAbsent
            case let status: return .retryRequired(.from(status))
            }
        }
    }
}
