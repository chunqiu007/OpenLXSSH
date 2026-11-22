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
    case staleKeyImportReview, duplicatePublicKey, keyNotEncrypted
}
enum PasswordChoice: Sendable { case preserve, manual, forget, remember(SecretBytes) }
enum KeyCreation: Sendable { case generate, importFile(URL) }
enum SecuritySaveOutcome: Sendable { case saved, savedWithCleanupPending }
struct SecurityKeyAuthenticationMaterial: Sendable {
    let bytes: SecretBytes
    let encrypted: Bool
}
struct SecurityHostSaveResult: Sendable {
    let host: HostConfiguration
    let outcome: SecuritySaveOutcome
}
struct KeyCreationOutcome: Equatable, Sendable {
    let id: UUID
    let cleanupPending: Bool
    // A returned value always means the key and its metadata have already committed.
}
struct SecurityKeyImportReview: Equatable, Sendable {
    let id: UUID
    let key: KeyImportReview
    let candidates: [ManagedKeyReference]
    var publicKey: PublicKey { key.publicKey }
    var encrypted: Bool { key.encrypted }
}
enum KeyImportChoice: Sendable { case create, reuse(UUID) }
enum KeyImportOutcome: Sendable {
    case created(KeyCreationOutcome), reused(ManagedKeyReference), duplicate(SecurityKeyImportReview)
}
private struct PendingSecurityKeyImport {
    var review: SecurityKeyImportReview
    var remember: SecretBytes?
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
    private var pendingKeyImport: PendingSecurityKeyImport?
    private var keyImportExpiry: Task<Void, Never>?

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
        guard after.hosts.contains(where: { $0.matchesConnection(of: host) }),
              after.keys.contains(where: { $0.authenticationIdentity == reference.authenticationIdentity }) else { throw SecurityUIFailure.notAuthorized }
        return secret
    }
    /// The encryption fact is read from KeyStore's validated envelope, never guessed
    /// from an authentication failure or a server's untrusted prompt text.
    func keyAuthenticationMaterial(host: HostConfiguration, expectedKey: ManagedKeyReference) async throws -> SecurityKeyAuthenticationMaterial {
        guard !Task.isCancelled, host.authentication.needsKey, host.keyRef == expectedKey.id else { throw SecurityUIFailure.notAuthorized }
        let before = try await repository.securityMetadata()
        try Task.checkCancellation()
        guard before.hosts.contains(where: { $0.matchesConnection(of: host) }),
              before.keys.contains(where: { $0.authenticationIdentity == expectedKey.authenticationIdentity }) else { throw SecurityUIFailure.notAuthorized }
        let keys = try storage().0
        let key = try await keys.key(id: expectedKey.id)
        try Task.checkCancellation()
        guard (expectedKey.algorithm == .ed25519 && key.publicKey.algorithm == .ed25519)
                || (expectedKey.algorithm == .rsa && key.publicKey.algorithm == .rsa) else { throw KeyFailure.invalidOpenSSH }
        let bytes = try await keys.privateKeyForAuthentication(id: expectedKey.id)
        try Task.checkCancellation()
        let after = try await repository.securityMetadata()
        try Task.checkCancellation()
        guard after.hosts.contains(where: { $0.matchesConnection(of: host) }),
              after.keys.contains(where: { $0.authenticationIdentity == expectedKey.authenticationIdentity }) else { throw SecurityUIFailure.notAuthorized }
        return SecurityKeyAuthenticationMaterial(bytes: bytes, encrypted: key.encrypted)
    }
    func publicKey(_ id: UUID) async throws -> PublicKey {
        guard try await repository.securityMetadata().keys.contains(where: { $0.id == id }) else { throw RepositoryError.notFound }
        return try await storage().0.publicKey(for: id)
    }
    func managedKey(_ id: UUID) async throws -> ManagedKey {
        guard try await repository.securityMetadata().keys.contains(where: { $0.id == id }) else { throw RepositoryError.notFound }
        return try await storage().0.key(id: id)
    }

    @discardableResult func saveHost(_ supplied: HostConfiguration, isNew: Bool, password: PasswordChoice, tagIDs: Set<UUID>? = nil) async throws -> SecuritySaveOutcome {
        try await saveHostCommitted(supplied, isNew: isNew, password: password, tagIDs: tagIDs).outcome
    }

    /// Returns the actual committed credential reference, not the pre-save supplied snapshot.
    /// Existing callers keep the outcome-only API; editors additionally supply their read baseline.
    func saveHostCommitted(_ supplied: HostConfiguration, isNew: Bool, password: PasswordChoice,
                           tagIDs: Set<UUID>? = nil, expected: HostEditPrecondition? = nil) async throws -> SecurityHostSaveResult {
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
        if isNew { changes.append(.insertHost(host)) }
        else if let original {
            changes.append(.updateHostIfUnchanged(host, expected: expected ?? .init(host: original)))
        }
        if let tagIDs { changes.append(.setHostTags(hostID: host.id, tagIDs: tagIDs)) }
        do { try await repository.apply(changes) }
        catch is AppStorageFailure { return .init(host: host, outcome: .savedWithCleanupPending) }
        catch { if let created { try await compensate(created) }; throw error }
        do {
            if let created { try journal.remove(created.id) }
            // Old shared references are never deleted before the new host transaction commits.
            if let old = original?.credentialRef, old != host.credentialRef { try await deleteIfUnusedCredential(old) }
            let metadata = try await repository.securityMetadata()
            return .init(host: host, outcome: metadata.tickets.isEmpty ? .saved : .savedWithCleanupPending)
        } catch {
            // Host is already committed. Never make the editor retry insertion or claim that
            // the metadata save failed just because later exact cleanup needs attention.
            return .init(host: host, outcome: .savedWithCleanupPending)
        }
    }

    func reviewKeyImport(from source: URL, protection: KeyProtection, rememberPassphrase: SecretBytes?) async throws -> SecurityKeyImportReview {
        try begin(); defer { busy = false }
        try await clearKeyImport()
        if let rememberPassphrase {
            guard case .passphrase(let supplied) = protection, supplied.matches(rememberPassphrase) else { throw SecurityUIFailure.notAuthorized }
        }
        let keys = try storage().0
        var reviewed: KeyImportReview?
        do {
            let key = try await keys.reviewImport(from: source, protection: protection)
            reviewed = key
            if rememberPassphrase != nil, !key.encrypted { throw SecurityUIFailure.notAuthorized }
            let candidates = try await duplicateCandidates(for: key.publicKey, keys: keys)
            try Task.checkCancellation()
            let review = SecurityKeyImportReview(id: UUID(), key: key, candidates: candidates)
            pendingKeyImport = .init(review: review, remember: candidates.isEmpty && key.encrypted ? rememberPassphrase : nil)
            keyImportExpiry = Task { [weak self] in
                do { try await Task.sleep(for: .seconds(120)) } catch { return }
                await self?.expireKeyImport(review.id)
            }
            return review
        } catch {
            if let reviewed { try? await keys.cancelImportReview(reviewed) }
            try await recordImportCleanup(error)
            throw error
        }
    }

    func confirmKeyImport(_ review: SecurityKeyImportReview, choice: KeyImportChoice) async throws -> KeyImportOutcome {
        try begin(); defer { busy = false }
        guard let pending = pendingKeyImport, pending.review == review else { throw SecurityUIFailure.staleKeyImportReview }
        let keys = try storage().0
        do {
            try await keys.validateImportReview(review.key)
            let current = try await duplicateCandidates(for: review.publicKey, keys: keys)
            try await keys.validateImportReview(review.key)
            try Task.checkCancellation()
            guard pendingKeyImport?.review == review else { throw SecurityUIFailure.staleKeyImportReview }
            switch choice {
            case .reuse(let id):
                // Bind the explicit choice to the exact reference shown in the review,
                // including its existing saved-secret authorization. Never read its secret.
                guard let selected = review.candidates.first(where: { $0.id == id }),
                      current.contains(selected) else { throw SecurityUIFailure.staleKeyImportReview }
                try await clearKeyImport()
                return .reused(selected)
            case .create:
                if !current.isEmpty {
                    let refreshed = SecurityKeyImportReview(id: review.id, key: review.key, candidates: current)
                    pendingKeyImport = .init(review: refreshed, remember: nil)
                    return .duplicate(refreshed)
                }
                // A duplicate review may never silently become a fresh import after deletion.
                guard review.candidates.isEmpty else { throw SecurityUIFailure.staleKeyImportReview }
                pendingKeyImport = nil; keyImportExpiry?.cancel(); keyImportExpiry = nil
                let result = try await createKeyCommit(nil, protection: .unencrypted,
                                                       rememberPassphrase: pending.remember, reviewed: review.key)
                return .created(result)
            }
        } catch {
            try? await clearKeyImport()
            try? await keys.cancelImportReview(review.key)
            throw error
        }
    }

    func cancelKeyImport(_ review: SecurityKeyImportReview) async throws {
        try begin(); defer { busy = false }
        guard pendingKeyImport?.review.id == review.id else { return }
        try await clearKeyImport()
    }
    private func clearKeyImport() async throws {
        let previous = pendingKeyImport
        pendingKeyImport = nil; keyImportExpiry?.cancel(); keyImportExpiry = nil
        if let previous { try await keys?.cancelImportReview(previous.review.key) }
    }
    private func expireKeyImport(_ id: UUID) async {
        guard pendingKeyImport?.review.id == id else { return }
        try? await clearKeyImport()
    }
    private func duplicateCandidates(for publicKey: PublicKey, keys: KeyStore) async throws -> [ManagedKeyReference] {
        let before = try await repository.securityMetadata().keys.sorted { $0.id.uuidString < $1.id.uuidString }
        var matches: [ManagedKeyReference] = []
        for reference in before {
            try Task.checkCancellation()
            let managed = try await keys.key(id: reference.id)
            guard (reference.algorithm == .ed25519 && managed.publicKey.algorithm == .ed25519)
                    || (reference.algorithm == .rsa && managed.publicKey.algorithm == .rsa) else { throw KeyFailure.invalidOpenSSH }
            if managed.publicKey == publicKey { matches.append(reference) }
        }
        let after = try await repository.securityMetadata().keys.sorted { $0.id.uuidString < $1.id.uuidString }
        guard before == after else { throw SecurityUIFailure.staleKeyImportReview }
        return matches
    }
    private func recordImportCleanup(_ error: Error) async throws {
        guard let failure = error as? KeyOperationFailure, let ticket = failure.cleanupTicket else { return }
        var intent = SecurityIntent(id: ticket.id, kind: .privateKey, state: .created)
        intent.pendingName = ticket.pendingName; intent.includesCommittedKey = ticket.includesCommittedKey
        intent.includesPublicSidecar = ticket.includesPublicSidecar
        let journal = try storage().1
        var journalFailed = false
        do { try journal.set(intent) } catch { journalFailed = true }
        try await repository.apply([.scheduleOrphanCleanup(.init(kind: .privateKey, id: ticket.id))])
        if journalFailed { throw SecurityUIFailure.journal }
    }

    /// Compatibility for existing callers. Interactive import uses review/confirm so a
    /// duplicate can be explicitly reused; this API rejects it without creating anything.
    func createKey(_ creation: KeyCreation, protection: KeyProtection, rememberPassphrase: SecretBytes?) async throws -> KeyCreationOutcome {
        if case .importFile(let source) = creation {
            let review = try await reviewKeyImport(from: source, protection: protection, rememberPassphrase: rememberPassphrase)
            if !review.candidates.isEmpty {
                try await cancelKeyImport(review)
                throw SecurityUIFailure.duplicatePublicKey
            }
            switch try await confirmKeyImport(review, choice: .create) {
            case .created(let outcome): return outcome
            case .duplicate(let updated):
                try await cancelKeyImport(updated)
                throw SecurityUIFailure.duplicatePublicKey
            case .reused: throw SecurityUIFailure.staleKeyImportReview
            }
        }
        try begin(); defer { busy = false }
        return try await createKeyCommit(creation, protection: protection, rememberPassphrase: rememberPassphrase)
    }

    private func createKeyCommit(_ creation: KeyCreation?, protection: KeyProtection, rememberPassphrase: SecretBytes?,
                                 reviewed: KeyImportReview? = nil) async throws -> KeyCreationOutcome {
        if let rememberPassphrase, reviewed == nil {
            guard case .passphrase(let supplied) = protection, supplied.matches(rememberPassphrase) else { throw SecurityUIFailure.notAuthorized }
        }
        let (keys, journal) = try storage()
        let keyID = UUID()
        var intent = SecurityIntent(id: keyID, kind: .privateKey, state: .prepared)
        try journal.set(intent)
        let managed: ManagedKey
        do {
            if let reviewed { managed = try await keys.commitImport(reviewed, id: keyID) }
            else {
                guard let creation, case .generate = creation else { throw SecurityUIFailure.staleKeyImportReview }
                managed = try await keys.generateEd25519(protection: protection, id: keyID)
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
            if let reviewed {
                // The managed copy is not registered yet. Recheck after KeyStore's actor
                // hop and before creating any remembered-secret authorization.
                guard try await duplicateCandidates(for: reviewed.publicKey, keys: keys).isEmpty else {
                    throw SecurityUIFailure.duplicatePublicKey
                }
            }
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

    @discardableResult
    func rememberKeyPassphrase(
        keyID: UUID,
        passphrase: SecretBytes,
        authorization: RememberAuthorization
    ) async throws -> ManagedKeyReference {
        guard authorization == .granted else { throw SecurityUIFailure.notAuthorized }
        let nonEmpty = passphrase.withUnsafeBytes { !$0.isEmpty }
        guard nonEmpty else { throw SecurityUIFailure.notAuthorized }
        try begin(); defer { busy = false }
        let (keys, journal) = try storage()
        let metadata = try await repository.securityMetadata()
        guard let original = metadata.keys.first(where: { $0.id == keyID }) else { throw RepositoryError.notFound }
        let managed = try await keys.key(id: keyID)
        guard (original.algorithm == .ed25519 && managed.publicKey.algorithm == .ed25519)
                || (original.algorithm == .rsa && managed.publicKey.algorithm == .rsa) else {
            throw KeyFailure.invalidOpenSSH
        }
        guard managed.encrypted else { throw SecurityUIFailure.keyNotEncrypted }
        _ = try await keys.verifyPassphrase(passphrase, for: keyID)
        try Task.checkCancellation()

        // Re-check current key metadata after verification before writing to Keychain.
        let beforeSave = try await repository.securityMetadata()
        guard let current = beforeSave.keys.first(where: { $0.id == keyID }) else { throw RepositoryError.notFound }

        var intent = SecurityIntent(id: UUID(), kind: .privateKeyPassphrase, state: .prepared)
        try journal.set(intent)
        switch await credentials.save(passphrase, as: .init(id: intent.id, kind: .privateKeyPassphrase), authorization: .granted) {
        case .saved:
            intent.state = .created
            do { try journal.set(intent) } catch { try await compensate(intent); throw error }
        case .notAuthorized:
            try journal.remove(intent.id)
            throw SecurityUIFailure.notAuthorized
        case .failed(let reason):
            try journal.remove(intent.id)
            throw SecurityUIFailure.credential(reason)
        }

        let changes: [RepositoryChange] = [
            .registerCredential(.init(id: intent.id, purpose: .privateKeyPassphrase, isSavingAuthorized: true)),
            .updateKeyPassphrase(keyID: keyID, credentialRef: intent.id)
        ]
        var updated = current
        updated.passphraseCredentialRef = intent.id
        do {
            try await repository.apply(changes)
        } catch is AppStorageFailure {
            return updated
        } catch {
            try await compensate(intent)
            throw error
        }

        do {
            try journal.remove(intent.id)
            if let old = current.passphraseCredentialRef, old != intent.id {
                try await deleteIfUnusedCredential(old)
            }
        } catch {
            // The new credential reference is already committed. Any pending cleanup
            // remains visible via SecurityOverview for explicit retry.
        }
        return updated
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
        _ = try await saveHostCommitted(host, isNew: false, password: .forget, expected: .init(host: host))
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
        try await clearKeyImport()
        try await keys?.close(); keys = nil; journal = nil
        try await credentials.close()
    }
}
