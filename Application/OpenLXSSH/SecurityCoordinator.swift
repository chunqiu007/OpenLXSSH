import Foundation
import OpenLXSSHCore
import OpenLXSSHSecurity

protocol CredentialAccess: Sendable {
    func save(_ secret: SecretBytes, as reference: OpenLXSSHSecurity.CredentialReference, authorization: RememberAuthorization) async -> CredentialSaveResult
    func read(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialReadResult
    func deleteExact(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialDeleteResult
    func close() async throws
}
extension CredentialStore: CredentialAccess {}

/// Lazy initialization also happens on this worker, never from a View or MainActor init.
actor SystemCredentials: CredentialAccess {
    let testNamespace: UUID?
    private var store: CredentialStore?
    init(testNamespace: UUID? = nil) { self.testNamespace = testNamespace }
    private func opened() throws -> CredentialStore {
        if let store { return store }
        let value = try testNamespace.map { try CredentialStore(testNamespace: $0) } ?? CredentialStore()
        store = value; return value
    }
    func save(_ secret: SecretBytes, as reference: OpenLXSSHSecurity.CredentialReference, authorization: RememberAuthorization) async -> CredentialSaveResult {
        do { return await (try opened()).save(secret, as: reference, authorization: authorization) }
        catch { return .failed((error as? CredentialFailure) ?? .unavailable) }
    }
    func read(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialReadResult {
        do { return await (try opened()).read(reference) }
        catch { return .manualEntryRequired((error as? CredentialFailure) ?? .unavailable) }
    }
    func deleteExact(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialDeleteResult {
        do { return await (try opened()).deleteExact(reference) }
        catch { return .retryRequired((error as? CredentialFailure) ?? .unavailable) }
    }
    func close() async throws { try await store?.close(); store = nil }
}

enum SecurityUIFailure: Error {
    case credential(CredentialFailure), key(KeyFailure), journal, busy, notAuthorized, pendingCleanup, preparedIntent, staleRecoveryReview
}
enum PasswordChoice: Sendable { case preserve, manual, forget, remember(SecretBytes) }
enum KeyCreation: Sendable { case generate, importFile(URL) }
enum SecuritySaveOutcome: Sendable { case saved, savedWithCleanupPending }
struct KeyCreationOutcome: Equatable, Sendable {
    let id: UUID
    let cleanupPending: Bool
    // A returned value always means the key and its metadata have already committed.
}
struct RecoveryReview: Equatable, Identifiable, Sendable {
    let intent: SecurityIntent
    let revision: UUID
    let metadataRegistered: Bool
    let hasCoreTicket: Bool
    var id: UUID { intent.id }
    var canDiscard: Bool { intent.state == .prepared && !metadataRegistered && !hasCoreTicket }
}
struct SecurityOverview: Sendable {
    let metadata: SecurityMetadata
    let pendingCount: Int
    let uncertainCount: Int
    let recoveryReviews: [RecoveryReview]
}

actor SecurityCoordinator {
    let repository: any AppRepositoryProtocol
    let credentials: any CredentialAccess
    private let location: AppDataLocation
    private var keys: KeyStore?
    private var journal: SecurityJournal?
    private let journalWriteCheck: @Sendable () throws -> Void
    private var busy = false
    private var closing = false

    init(repository: any AppRepositoryProtocol, location: AppDataLocation = .applicationSupport,
         credentials: any CredentialAccess = SystemCredentials(),
         journalWriteCheck: @escaping @Sendable () throws -> Void = {}) {
        self.repository = repository; self.location = location; self.credentials = credentials
        self.journalWriteCheck = journalWriteCheck
    }
    private func storage() throws -> (KeyStore, SecurityJournal) {
        if let keys, let journal {
            _ = try location.databaseDirectory()
            try journal.validateAccess()
            return (keys, journal)
        }
        let parent = try AppDataLocation.canonical(location.databaseDirectory().deletingLastPathComponent())
        let journal = try SecurityJournal(parent: parent, beforePersist: journalWriteCheck)
        let keys = try KeyStore(directory: parent.appendingPathComponent("Keys", isDirectory: true))
        self.journal = journal; self.keys = keys
        return (keys, journal)
    }
    private func begin() throws {
        guard !busy, !closing else { throw SecurityUIFailure.busy }
        busy = true
    }
    func overview() async throws -> SecurityOverview {
        let (_, journal) = try storage()
        let metadata = try await repository.securityMetadata()
        let intents = try journal.all()
        let pending = Set(metadata.tickets.map(\.resourceID)).union(intents.map(\.id))
        let reviews = try intents.compactMap { intent -> RecoveryReview? in
            guard let revision = try journal.revision(for: intent.id) else { return nil }
            return RecoveryReview(intent: intent, revision: revision,
                                  metadataRegistered: Self.hasMetadata(intent.id, in: metadata),
                                  hasCoreTicket: (metadata.tickets + metadata.completedTickets).contains { $0.resourceID == intent.id })
        }
        return SecurityOverview(metadata: metadata, pendingCount: pending.count,
                                uncertainCount: intents.filter { $0.state == .prepared }.count,
                                recoveryReviews: reviews)
    }
    private static func hasMetadata(_ id: UUID, in metadata: SecurityMetadata) -> Bool {
        metadata.keys.contains { $0.id == id || $0.passphraseCredentialRef == id }
            || metadata.credentials.contains { $0.id == id }
            || metadata.hosts.contains { $0.credentialRef == id || $0.keyRef == id }
    }
    func discardPreparedRecord(_ review: RecoveryReview) async throws {
        try begin(); defer { busy = false }
        let (_, journal) = try storage()
        let metadata = try await repository.securityMetadata()
        guard review.canDiscard, !Self.hasMetadata(review.id, in: metadata),
              !(metadata.tickets + metadata.completedTickets).contains(where: { $0.resourceID == review.id }) else { throw SecurityUIFailure.staleRecoveryReview }
        // No KeyStore/Keychain read, enumeration or deletion here. An unconfirmed intent
        // does not establish ownership or even existence of an external resource.
        try journal.discardPrepared(review.intent, revision: review.revision)
    }
    func validatedPrivateKeyPath(_ id: UUID) async throws -> String {
        let metadata = try await repository.securityMetadata()
        guard let reference = metadata.keys.first(where: { $0.id == id }) else { throw RepositoryError.notFound }
        let keys = try storage().0
        // KeyStore validates the exact owned UUID, directory identity, regular-file
        // type, owner, mode and OpenSSH envelope. Never accept a user-supplied path.
        let key = try await keys.key(id: id)
        guard (reference.algorithm == .ed25519 && key.publicKey.algorithm == .ed25519)
                || (reference.algorithm == .rsa && key.publicKey.algorithm == .rsa) else { throw KeyFailure.invalidOpenSSH }
        return keys.rootURL.appendingPathComponent(id.uuidString + ".openssh").path
    }
    func privateKeyForFileAuthentication(host: HostConfiguration, authorized: Bool) async throws -> SecretBytes {
        guard authorized, !Task.isCancelled, host.authentication.needsKey, let id = host.keyRef else { throw SecurityUIFailure.notAuthorized }
        let metadata = try await repository.securityMetadata()
        try Task.checkCancellation()
        guard metadata.hosts.contains(where: { $0.matchesConnection(of: host) }), let reference = metadata.keys.first(where: { $0.id == id }) else { throw RepositoryError.notFound }
        let keys = try storage().0
        let key = try await keys.key(id: id)
        try Task.checkCancellation()
        guard (reference.algorithm == .ed25519 && key.publicKey.algorithm == .ed25519)
                || (reference.algorithm == .rsa && key.publicKey.algorithm == .rsa) else { throw KeyFailure.invalidOpenSSH }
        let secret = try await keys.privateKeyForAuthentication(id: id)
        try Task.checkCancellation()
        let after = try await repository.securityMetadata()
        try Task.checkCancellation()
        guard after.hosts.contains(where: { $0.matchesConnection(of: host) }), after.keys.contains(reference) else { throw SecurityUIFailure.notAuthorized }
        return secret
    }
    func publicKey(_ id: UUID) async throws -> PublicKey {
        guard try await repository.securityMetadata().keys.contains(where: { $0.id == id }) else { throw RepositoryError.notFound }
        return try await storage().0.publicKey(for: id)
    }

    @discardableResult func saveHost(_ supplied: HostConfiguration, isNew: Bool, password: PasswordChoice) async throws -> SecuritySaveOutcome {
        try begin(); defer { busy = false }
        let (_, journal) = try storage()
        let metadata = try await repository.securityMetadata()
        let original = metadata.hosts.first { $0.id == supplied.id }
        if isNew, original != nil { throw RepositoryError.conflictingID }
        if !isNew, original == nil { throw RepositoryError.notFound }
        var host = supplied
        var created: SecurityIntent?
        switch password {
        case .preserve:
            if !host.authentication.needsKey {
                host.credentialRef = original?.credentialRef; host.savePasswordAuthorized = original?.savePasswordAuthorized ?? false
            }
        case .manual, .forget:
            host.credentialRef = nil; host.savePasswordAuthorized = false
        case .remember(let secret):
            guard !host.authentication.needsKey else { throw SecurityUIFailure.notAuthorized }
            let intent = SecurityIntent(id: UUID(), kind: .password, state: .prepared)
            try journal.set(intent)
            switch await credentials.save(secret, as: .init(id: intent.id, kind: .password), authorization: .granted) {
            case .saved:
                var owned = intent; owned.state = .created; created = owned
                do { try journal.set(owned) } catch { try await compensate(owned); throw error }
                host.credentialRef = intent.id; host.savePasswordAuthorized = true
            case .notAuthorized: try journal.remove(intent.id); throw SecurityUIFailure.notAuthorized
            case .failed(let reason): try journal.remove(intent.id); throw SecurityUIFailure.credential(reason)
            }
        }
        if host.authentication.needsKey { host.credentialRef = nil; host.savePasswordAuthorized = false }
        var changes: [RepositoryChange] = []
        if let created { changes.append(.registerCredential(.init(id: created.id, purpose: .password, isSavingAuthorized: true))) }
        changes.append(isNew ? .insertHost(host) : .updateHost(host))
        do { try await repository.apply(changes) }
        catch is AppStorageFailure { return .savedWithCleanupPending }
        catch { if let created { try await compensate(created) }; throw error }
        do {
            if let created { try journal.remove(created.id) }
            // Old shared references are never deleted before the new host transaction commits.
            if let old = original?.credentialRef, old != host.credentialRef { try await deleteIfUnusedCredential(old) }
            let metadata = try await repository.securityMetadata()
            return metadata.tickets.isEmpty ? .saved : .savedWithCleanupPending
        } catch {
            // Host is already committed. Never make the editor retry insertion or claim that
            // the metadata save failed just because later exact cleanup needs attention.
            return .savedWithCleanupPending
        }
    }

    func createKey(_ creation: KeyCreation, protection: KeyProtection, rememberPassphrase: SecretBytes?) async throws -> KeyCreationOutcome {
        try begin(); defer { busy = false }
        if let rememberPassphrase {
            guard case .passphrase(let supplied) = protection, supplied.matches(rememberPassphrase) else { throw SecurityUIFailure.notAuthorized }
        }
        let (keys, journal) = try storage()
        let keyID = UUID()
        var intent = SecurityIntent(id: keyID, kind: .privateKey, state: .prepared)
        try journal.set(intent)
        let managed: ManagedKey
        do {
            switch creation {
            case .generate: managed = try await keys.generateEd25519(protection: protection, id: keyID)
            case .importFile(let url): managed = try await keys.importKey(from: url, protection: protection, id: keyID)
            }
        } catch {
            if let failure = error as? KeyOperationFailure, let ticket = failure.cleanupTicket {
                intent.state = .created; intent.pendingName = ticket.pendingName
                intent.includesCommittedKey = ticket.includesCommittedKey; intent.includesPublicSidecar = ticket.includesPublicSidecar
                try journal.set(intent)
                try await repository.apply([.scheduleOrphanCleanup(.init(kind: .privateKey, id: keyID))])
            } else { try journal.remove(keyID) }
            throw error
        }
        intent.state = .created
        do { try journal.set(intent) } catch { try await compensate(intent); throw error }
        var passphraseIntent: SecurityIntent?
        do {
            try Task.checkCancellation()
            if let secret = rememberPassphrase {
                guard managed.encrypted else { throw SecurityUIFailure.notAuthorized }
                var passphrase = SecurityIntent(id: UUID(), kind: .privateKeyPassphrase, state: .prepared)
                try journal.set(passphrase)
                switch await credentials.save(secret, as: .init(id: passphrase.id, kind: .privateKeyPassphrase), authorization: .granted) {
                case .saved:
                    passphrase.state = .created; passphraseIntent = passphrase
                    try journal.set(passphrase)
                case .notAuthorized: try journal.remove(passphrase.id); throw SecurityUIFailure.notAuthorized
                case .failed(let reason): try journal.remove(passphrase.id); throw SecurityUIFailure.credential(reason)
                }
            }
            var changes: [RepositoryChange] = []
            if let passphraseIntent { changes.append(.registerCredential(.init(id: passphraseIntent.id, purpose: .privateKeyPassphrase, isSavingAuthorized: true))) }
            changes.append(.registerKey(.init(id: keyID, algorithm: managed.publicKey.algorithm == .ed25519 ? .ed25519 : .rsa,
                                              passphraseCredentialRef: passphraseIntent?.id)))
            try Task.checkCancellation()
            try await repository.apply(changes)
        } catch is AppStorageFailure {
            return KeyCreationOutcome(id: keyID, cleanupPending: true)
        } catch {
            if let passphraseIntent {
                do { try await compensate(passphraseIntent) }
                catch { try await compensate(intent); throw error }
            }
            try await compensate(intent)
            throw error
        }
        var cleanupPending = false
        // Core has committed. Only forget recovery records now; never compensate an
        // already registered key/passphrase or report creation as failed and invite retry.
        do { try journal.remove(keyID) } catch { cleanupPending = true }
        if let passphraseIntent {
            do { try journal.remove(passphraseIntent.id) } catch { cleanupPending = true }
        }
        return KeyCreationOutcome(id: keyID, cleanupPending: cleanupPending)
    }

    @discardableResult func forgetKeyPassphrase(_ keyID: UUID) async throws -> SecuritySaveOutcome {
        try begin(); defer { busy = false }
        let metadata = try await repository.securityMetadata()
        guard let key = metadata.keys.first(where: { $0.id == keyID }) else { throw RepositoryError.notFound }
        guard let old = key.passphraseCredentialRef else { return .saved }
        do { try await repository.apply([.updateKeyPassphrase(keyID: keyID, credentialRef: nil)]) }
        catch is AppStorageFailure { return .savedWithCleanupPending }
        do {
            try await deleteIfUnusedCredential(old)
            return try await repository.securityMetadata().tickets.isEmpty ? .saved : .savedWithCleanupPending
        } catch {
            // The reference was detached successfully. A later cleanup failure must not
            // make the user repeat a metadata operation which has already committed.
            return .savedWithCleanupPending
        }
    }

    func deleteKey(_ id: UUID) async throws {
        try begin(); defer { busy = false }
        let metadata = try await repository.securityMetadata()
        guard let key = metadata.keys.first(where: { $0.id == id }) else { throw RepositoryError.notFound }
        try await prepareDeletion(.init(id: id, kind: .privateKey, state: .deleting), change: .deleteKey(id))
        try await cleanupInternal()
        if let passphrase = key.passphraseCredentialRef { try await deleteIfUnusedCredential(passphrase) }
    }
    func forgetHostPassword(_ hostID: UUID) async throws {
        let metadata = try await repository.securityMetadata()
        guard let host = metadata.hosts.first(where: { $0.id == hostID }) else { throw RepositoryError.notFound }
        try await saveHost(host, isNew: false, password: .forget)
    }
    func deleteUnusedCredential(_ id: UUID) async throws {
        try begin(); defer { busy = false }
        let metadata = try await repository.securityMetadata()
        guard let reference = metadata.credentials.first(where: { $0.id == id }) else { throw RepositoryError.notFound }
        let intent = SecurityIntent(id: id, kind: reference.purpose == .password ? .password : .privateKeyPassphrase, state: .deleting)
        try await prepareDeletion(intent, change: .deleteCredential(id))
        try await cleanupInternal()
    }
    private func deleteIfUnusedCredential(_ id: UUID) async throws {
        let metadata = try await repository.securityMetadata()
        guard !metadata.hosts.contains(where: { $0.credentialRef == id }),
              !metadata.keys.contains(where: { $0.passphraseCredentialRef == id }),
              let ref = metadata.credentials.first(where: { $0.id == id }) else { return }
        try await prepareDeletion(.init(id: id, kind: ref.purpose == .password ? .password : .privateKeyPassphrase, state: .deleting), change: .deleteCredential(id))
        try await cleanupInternal()
    }
    private func prepareDeletion(_ intent: SecurityIntent, change: RepositoryChange) async throws {
        let (_, journal) = try storage()
        try journal.set(intent)
        do { try await repository.apply([change]) }
        catch is AppStorageFailure { throw AppStorageFailure.committedStorageUnsafe }
        catch { try journal.remove(intent.id); throw error }
    }

    private func compensate(_ intent: SecurityIntent) async throws {
        let (keys, journal) = try storage()
        do {
            if intent.kind == .privateKey {
                if let ticket = intent.keyTicket { try await keys.retryCleanup(ticket) }
                else { _ = try await keys.deleteExact(intent.id) }
            } else {
                let result = await credentials.deleteExact(.init(id: intent.id, kind: intent.kind == .password ? .password : .privateKeyPassphrase))
                if case .retryRequired(let failure) = result { throw SecurityUIFailure.credential(failure) }
            }
            try journal.remove(intent.id)
        } catch {
            // Attempt both records independently: a full/unavailable journal must not
            // prevent Core from retaining the exact orphan UUID for a later retry.
            var journalFailed = false
            do { try journal.set(intent) } catch { journalFailed = true }
            try await repository.apply([.scheduleOrphanCleanup(.init(kind: intent.kind == .privateKey ? .privateKey : .credential, id: intent.id))])
            if journalFailed { throw SecurityUIFailure.journal }
        }
    }

    func retryCleanup() async throws {
        try begin(); defer { busy = false }
        try await cleanupInternal()
    }
    private func cleanupInternal() async throws {
        let (keys, journal) = try storage()
        var metadata = try await repository.securityMetadata()
        for intent in try journal.all() {
            let registered = intent.kind == .privateKey ? metadata.keys.contains { $0.id == intent.id } : metadata.credentials.contains { $0.id == intent.id }
            if registered { try journal.remove(intent.id); continue }
            guard intent.state != .prepared else { continue } // uncertain creation: never guess ownership
            if !metadata.tickets.contains(where: { $0.resourceID == intent.id }) {
                try await repository.apply([.scheduleOrphanCleanup(.init(kind: intent.kind == .privateKey ? .privateKey : .credential, id: intent.id))])
            }
        }
        metadata = try await repository.securityMetadata()
        for ticket in metadata.tickets {
            let intent = try journal.all().first { $0.id == ticket.resourceID }
            do {
                switch ticket.resourceKind {
                case .privateKey:
                    if let keyTicket = intent?.keyTicket { try await keys.retryCleanup(keyTicket) }
                    else { _ = try await keys.deleteExact(ticket.resourceID) }
                case .credential:
                    guard let intent, intent.kind != .privateKey else { throw SecurityUIFailure.journal }
                    switch await credentials.deleteExact(.init(id: ticket.resourceID, kind: intent.kind == .password ? .password : .privateKeyPassphrase)) {
                    case .deleted, .alreadyAbsent: break
                    case .retryRequired(let failure): throw SecurityUIFailure.credential(failure)
                    }
                }
                try await repository.completeCleanup(ticket.id)
                if intent != nil { try journal.remove(ticket.resourceID) }
            } catch {
                try await repository.recordCleanupFailure(ticket.id, failure: Self.cleanupFailure(error))
            }
        }
    }
    private static func cleanupFailure(_ error: Error) -> CleanupFailure {
        if case SecurityUIFailure.credential(let failure) = error {
            switch failure {
            case .denied, .interactionNotAllowed: return .permissionDenied
            case .unavailable, .closed: return .unavailable
            default: return .transient
            }
        }
        return .transient
    }
    func close() async throws {
        closing = true
        while busy { try await Task.sleep(for: .milliseconds(20)) }
        try await keys?.close(); keys = nil; journal = nil
        try await credentials.close()
    }
}
