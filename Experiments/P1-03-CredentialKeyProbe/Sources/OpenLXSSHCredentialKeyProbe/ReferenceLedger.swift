import Foundation

public enum StoredResource: Hashable, Sendable {
    case credential(CredentialReference)
    case key(UUID)
}

public enum CleanupFailure: Equatable, Sendable {
    case credential(CredentialFailure), key(KeyFailure), metadataCommit
}

public enum ResourceDeletion: Equatable, Sendable { case deleted, retryRequired(CleanupFailure) }

public struct ReferenceSnapshot: Equatable, Sendable {
    public var hosts: [UUID: Set<StoredResource>] = [:]
    public var resources: Set<StoredResource> = []
    public var pendingDeletion: Set<StoredResource> = []
    public init() {}
}

public struct CleanupTicket: Equatable, Sendable {
    public let resource: StoredResource
    public let failure: CleanupFailure
}

public enum LedgerResult: Equatable, Sendable {
    case committed, notAuthorized, unknownResource, alreadyRegistered, busy, metadataFailed
    case credentialSaveFailed(CredentialFailure)
    /// false means the ticket exists only in memory/this returned result, not a durable journal.
    case cleanupPending([CleanupTicket], journaled: Bool)
}

/// Minimal serial state machine, NOT a database. A production repository must durably journal
/// pending deletion and compensate crashes. The injected commit contains references only.
/// Commit-before-delete plus exact, idempotent retries prevent deleting shared resources or
/// silently assigning a keychain secret to a mismatched metadata reference.
@MainActor
public final class ReferenceLedger {
    public private(set) var snapshot = ReferenceSnapshot()
    private let commit: @MainActor (ReferenceSnapshot) throws -> Void
    private let delete: @MainActor (StoredResource) async -> ResourceDeletion
    private var mutating = false

    public init(commit: @escaping @MainActor (ReferenceSnapshot) throws -> Void,
                delete: @escaping @MainActor (StoredResource) async -> ResourceDeletion) {
        self.commit = commit
        self.delete = delete
    }

    public func createCredential(_ secret: SecretBytes, reference: CredentialReference, host: UUID,
                                 authorization: RememberAuthorization, store: any CredentialStorage) async -> LedgerResult {
        guard !mutating else { return .busy }
        // No mutation may enter between Keychain save and metadata compensation.
        mutating = true
        defer { mutating = false }
        guard !snapshot.resources.contains(.credential(reference)) else { return .alreadyRegistered }
        switch store.save(secret, as: reference, authorization: authorization) {
        case .notAuthorized: return .notAuthorized
        case .failed(let failure): return .credentialSaveFailed(failure)
        case .saved: return await registerCreatedImpl(.credential(reference), host: host)
        }
    }

    /// Called only for a key/credential just created by this operation. Existing shared keys
    /// must use attach(); they must never be deleted as a "failed-create" compensation.
    public func registerCreated(_ resource: StoredResource, host: UUID) async -> LedgerResult {
        guard !mutating else { return .busy }
        mutating = true
        defer { mutating = false }
        guard !snapshot.resources.contains(resource) else { return .alreadyRegistered }
        return await registerCreatedImpl(resource, host: host)
    }

    private func registerCreatedImpl(_ resource: StoredResource, host: UUID) async -> LedgerResult {
        var desired = snapshot
        desired.resources.insert(resource)
        desired.hosts[host, default: []].insert(resource)
        do {
            try commit(desired)
            snapshot = desired
            return .committed
        } catch {
            // Cross-store writes are not atomic: remove only the newly created exact resource.
            switch await delete(resource) {
            case .deleted: return .metadataFailed
            case .retryRequired(let failure):
                snapshot.resources.insert(resource)
                snapshot.pendingDeletion.insert(resource)
                var journaled = false
                do { try commit(snapshot); journaled = true } catch { /* surfaced explicitly below */ }
                return .cleanupPending([CleanupTicket(resource: resource, failure: failure)], journaled: journaled)
            }
        }
    }

    public func attach(_ resource: StoredResource, host: UUID) -> LedgerResult {
        guard !mutating else { return .busy }
        guard snapshot.resources.contains(resource), !snapshot.pendingDeletion.contains(resource) else { return .unknownResource }
        var desired = snapshot
        desired.hosts[host, default: []].insert(resource)
        do { try commit(desired); snapshot = desired; return .committed }
        catch { return .metadataFailed }
    }

    public func removeHost(_ host: UUID) async -> LedgerResult {
        guard !mutating else { return .busy }
        mutating = true
        defer { mutating = false }
        var desired = snapshot
        let removed = desired.hosts.removeValue(forKey: host) ?? []
        let used = desired.hosts.values.reduce(into: Set<StoredResource>()) { $0.formUnion($1) }
        desired.pendingDeletion.formUnion(removed.subtracting(used))
        do { try commit(desired); snapshot = desired }
        catch { return .metadataFailed }
        return await cleanupImpl()
    }

    /// Exactly one deletion attempt per pending resource per explicit call, never a loop retry.
    public func retryCleanup() async -> LedgerResult {
        guard !mutating else { return .busy }
        mutating = true
        defer { mutating = false }
        do { try commit(snapshot) } catch { return .metadataFailed }
        return await cleanupImpl()
    }

    private func cleanupImpl() async -> LedgerResult {
        let used = snapshot.hosts.values.reduce(into: Set<StoredResource>()) { $0.formUnion($1) }
        var failures: [CleanupTicket] = []
        for resource in snapshot.pendingDeletion where !used.contains(resource) {
            switch await delete(resource) {
            case .retryRequired(let failure): failures.append(CleanupTicket(resource: resource, failure: failure))
            case .deleted:
                var desired = snapshot
                desired.pendingDeletion.remove(resource)
                desired.resources.remove(resource)
                do { try commit(desired); snapshot = desired }
                catch { failures.append(CleanupTicket(resource: resource, failure: .metadataCommit)) }
            }
        }
        return failures.isEmpty ? .committed : .cleanupPending(failures, journaled: true)
    }
}
