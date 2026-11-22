import Foundation

public struct ManagedKey: Hashable, Sendable {
    public let id: UUID
    public let publicKey: PublicKey
    public let encrypted: Bool
}

/// Core may persist this nonsecret exact cleanup ticket. Only the failed operation's UUID
/// and its controlled pending/public/committed names are permitted; never an arbitrary path.
public struct KeyCleanupTicket: Equatable, Sendable {
    public let id: UUID
    public let pendingName: String
    public let includesPublicSidecar: Bool
    public let includesCommittedKey: Bool
    public init(id: UUID, pendingName: String, includesPublicSidecar: Bool, includesCommittedKey: Bool) {
        self.id = id; self.pendingName = pendingName
        self.includesPublicSidecar = includesPublicSidecar; self.includesCommittedKey = includesCommittedKey
    }
}
public struct KeyOperationFailure: Error, Equatable, Sendable {
    public let primary: KeyFailure
    public let cleanupTicket: KeyCleanupTicket?
    public let cleanupFailures: [String: KeyFailure]
}
public enum KeyDeleteResult: Equatable, Sendable { case deleted, alreadyAbsent }

public enum KeyImportReviewFailure: Error, Equatable, Sendable { case staleReview }

/// Nonsecret, opaque and single-use. Only the issuing KeyStore can resolve this token.
/// No source path, private bytes or passphrase crosses this review boundary.
public struct KeyImportReview: Equatable, Sendable {
    fileprivate let token: UUID
    public let publicKey: PublicKey
    public let encrypted: Bool
}

private struct PendingKeyImport: Sendable {
    let review: KeyImportReview
    let source: KeySourceSnapshot
    let deadline: ContinuousClock.Instant
}

/// Durable App-owned key files, no metadata database and no scanning. The caller supplies
/// an Application Support leaf whose parent exists. Files are referenced only by UUID.
/// Core must authorize deletion after checking every host and passphrase reference.
/// Root/lock and imported/managed private files must have no extended filesystem ACL,
/// including deny-only ACLs. ACL presence throws `KeyFailure.unsafePermissions`; lookup
/// failure throws `KeyFailure.systemCall` without falling back to mode bits. ACLs are never
/// removed or repaired automatically. A refused newly created leaf remains empty for review.
public actor KeyStore {
    public nonisolated let rootURL: URL
    private var directory: PrivateDirectory?
    private let tool: SSHKeygenTool
    private let reviewLifetime: Duration
    private let beforeReviewCleanup: @Sendable () throws -> Void
    private var mutating = false
    private var pendingImport: PendingKeyImport?
    private var reviewExpiry: Task<Void, Never>?

    public init(directory: URL) throws {
        self.directory = try PrivateDirectory(directory: directory)
        rootURL = directory
        tool = SSHKeygenTool()
        reviewLifetime = .seconds(120)
        beforeReviewCleanup = {}
    }
    init(directory: URL, tool: SSHKeygenTool, reviewLifetime: Duration = .seconds(120),
         beforeReviewCleanup: @escaping @Sendable () throws -> Void = {}) throws {
        self.directory = try PrivateDirectory(directory: directory)
        rootURL = directory
        self.tool = tool
        self.reviewLifetime = reviewLifetime
        self.beforeReviewCleanup = beforeReviewCleanup
    }

    private func open() throws -> PrivateDirectory {
        guard let directory else { throw KeyFailure.closed }
        try directory.verify()
        return directory
    }
    private func finalName(_ id: UUID) -> String { "\(id.uuidString).openssh" }
    private func stageName(_ id: UUID) -> String { "\(id.uuidString).\(UUID().uuidString).pending" }

    public func close() throws {
        guard !mutating else { throw KeyFailure.busy }
        clearImportReview()
        directory = nil // only closes handles/lock; never removes durable keys or directories.
    }

    /// Validate an exact source through the system ssh-keygen without committing a managed
    /// key. The temporary validation file is removed before a review is returned. A failed
    /// cleanup returns the existing exact ticket; callers must retain it for recovery.
    public func reviewImport(from source: URL, protection: KeyProtection) async throws -> KeyImportReview {
        guard !mutating else { throw KeyFailure.busy }
        mutating = true
        defer { mutating = false }
        clearImportReview()
        let directory = try open()
        try Task.checkCancellation()
        let snapshot = try PrivateDirectory.sourceSnapshot(source)
        let envelope = try OpenSSHEnvelope(snapshot.bytes)
        if envelope.encrypted, case .unencrypted = protection { throw KeyFailure.passphraseRequired }
        let stageID = UUID()
        let stage = stageName(stageID)
        var created = false
        do {
            try directory.write(snapshot.bytes, name: stage, created: &created)
            try directory.validatePrivateFile(stage)
            let observed = try await tool.publicKey(at: rootURL.appendingPathComponent(stage).path, protection: protection)
            guard observed == envelope.publicKey, try directory.read(stage) == snapshot.bytes else { throw KeyFailure.invalidOpenSSH }
            try snapshot.validateCurrent()
            try Task.checkCancellation()
            // Narrow package-test seam, production is a no-op. No private material or
            // cleanup name is exposed to the hook.
            try beforeReviewCleanup()
            _ = try directory.remove(stage)
            let review = KeyImportReview(token: UUID(), publicKey: observed, encrypted: envelope.encrypted)
            pendingImport = PendingKeyImport(review: review, source: snapshot, deadline: .now + reviewLifetime)
            let lifetime = reviewLifetime
            reviewExpiry = Task { [weak self] in
                do { try await Task.sleep(for: lifetime) } catch { return }
                await self?.expireImportReview(review)
            }
            return review
        } catch {
            throw compensate(error, ticket: .init(id: stageID, pendingName: stage,
                                                  includesPublicSidecar: false, includesCommittedKey: false), cleanPending: created)
        }
    }

    public func validateImportReview(_ review: KeyImportReview) throws {
        guard !mutating else { throw KeyFailure.busy }
        _ = try reviewedImport(review)
    }

    public func cancelImportReview(_ review: KeyImportReview) throws {
        guard !mutating else { throw KeyFailure.busy }
        guard pendingImport?.review == review else { return }
        clearImportReview()
    }

    /// Commit only the bytes already approved by ssh-keygen. No new path read can replace
    /// them, and the current source identity/ctime/bytes must still match the review.
    public func commitImport(_ review: KeyImportReview, id: UUID = UUID()) throws -> ManagedKey {
        guard !mutating else { throw KeyFailure.busy }
        let pending = try reviewedImport(review)
        mutating = true
        defer { mutating = false; clearImportReview() }
        let directory = try open()
        guard !(try directory.exists(finalName(id))) else { throw KeyFailure.duplicateKey }
        let stage = stageName(id)
        var created = false, committed = false
        do {
            try Task.checkCancellation()
            try directory.write(pending.source.bytes, name: stage, created: &created)
            try pending.source.validateCurrent()
            guard try directory.read(stage) == pending.source.bytes else { throw KeyFailure.changedWhileReading }
            try Task.checkCancellation()
            try directory.commit(stage: stage, destination: finalName(id), committed: &committed)
            return ManagedKey(id: id, publicKey: review.publicKey, encrypted: review.encrypted)
        } catch {
            throw compensate(error, ticket: .init(id: id, pendingName: stage,
                                                  includesPublicSidecar: false, includesCommittedKey: committed), cleanPending: created)
        }
    }

    private func reviewedImport(_ review: KeyImportReview) throws -> PendingKeyImport {
        guard let pending = pendingImport, pending.review == review, ContinuousClock.now < pending.deadline else {
            if pendingImport?.review == review { clearImportReview() }
            throw KeyImportReviewFailure.staleReview
        }
        do {
            _ = try open()
            try pending.source.validateCurrent()
            guard try OpenSSHEnvelope(pending.source.bytes).publicKey == review.publicKey else { throw KeyImportReviewFailure.staleReview }
        } catch { clearImportReview(); throw error }
        return pending
    }
    private func expireImportReview(_ review: KeyImportReview) {
        if pendingImport?.review == review { clearImportReview() }
    }
    private func clearImportReview() {
        pendingImport = nil; reviewExpiry?.cancel(); reviewExpiry = nil
    }

    public func key(id: UUID) throws -> ManagedKey {
        let envelope = try OpenSSHEnvelope(open().read(finalName(id)))
        return ManagedKey(id: id, publicKey: envelope.publicKey, encrypted: envelope.encrypted)
    }
    public func publicKey(for id: UUID) throws -> PublicKey { try key(id: id).publicKey }

    /// Verifies that `passphrase` decrypts this managed encrypted private key via system ssh-keygen,
    /// without modifying or exporting the private key file.
    public func verifyPassphrase(_ passphrase: SecretBytes, for id: UUID) async throws -> ManagedKey {
        guard !mutating else { throw KeyFailure.busy }
        let directory = try open()
        let name = finalName(id)
        let bytes = try directory.read(name)
        let envelope = try OpenSSHEnvelope(bytes)
        guard envelope.encrypted else { throw KeyFailure.invalidPassphraseInput }
        try directory.validatePrivateFile(name)
        let observed = try await tool.publicKey(
            at: rootURL.appendingPathComponent(name).path,
            protection: .passphrase(passphrase)
        )
        try directory.validatePrivateFile(name)
        guard observed == envelope.publicKey else { throw KeyFailure.invalidOpenSSH }
        return ManagedKey(id: id, publicKey: observed, encrypted: envelope.encrypted)
    }

    /// Returns this exact managed UUID's OpenSSH private bytes in memory only, for a direct,
    /// user-authorized authentication boundary. The caller must first validate the Core
    /// host/key reference and user authorization; this store has no reference database.
    /// Retain only as long as authentication needs it: never log, serialize, persist or use
    /// this as a private-key file export. Encrypted keys remain encrypted; the caller supplies
    /// any separately authorized passphrase to the authentication implementation.
    /// Uses the same root/lock, owner, mode, ACL, no-follow, link and size checks as `key(id:)`,
    /// and validates the OpenSSH envelope before returning. It never modifies/deletes the file.
    /// Swift/Data and downstream libraries can copy bytes; complete zeroization is not promised.
    public func privateKeyForAuthentication(id: UUID) throws -> SecretBytes {
        let bytes = try open().read(finalName(id))
        _ = try OpenSSHEnvelope(bytes)
        return SecretBytes(bytes)
    }

    public func importKey(from source: URL, protection: KeyProtection, id: UUID = UUID()) async throws -> ManagedKey {
        guard !mutating else { throw KeyFailure.busy }
        mutating = true
        defer { mutating = false }
        let directory = try open()
        guard !(try directory.exists(finalName(id))) else { throw KeyFailure.duplicateKey }
        let bytes = try PrivateDirectory.readSource(source)
        let envelope = try OpenSSHEnvelope(bytes)
        if envelope.encrypted, case .unencrypted = protection { throw KeyFailure.passphraseRequired }
        let stage = stageName(id)
        var created = false, committed = false
        do {
            try Task.checkCancellation()
            try directory.write(bytes, name: stage, created: &created)
            try directory.validatePrivateFile(stage)
            let observed = try await tool.publicKey(at: rootURL.appendingPathComponent(stage).path, protection: protection)
            try directory.validatePrivateFile(stage)
            guard observed == envelope.publicKey else { throw KeyFailure.invalidOpenSSH }
            try Task.checkCancellation()
            try directory.commit(stage: stage, destination: finalName(id), committed: &committed)
            return ManagedKey(id: id, publicKey: observed, encrypted: envelope.encrypted)
        } catch {
            throw compensate(error, ticket: KeyCleanupTicket(id: id, pendingName: stage,
                                                            includesPublicSidecar: false, includesCommittedKey: committed),
                             cleanPending: created)
        }
    }

    public func generateEd25519(protection: KeyProtection, id: UUID = UUID()) async throws -> ManagedKey {
        try await generate(algorithm: .ed25519, protection: protection, id: id)
    }
    // RSA is imported in production; internal RSA generation only supports real local tests.
    func generate(algorithm: KeyAlgorithm, protection: KeyProtection, id: UUID = UUID()) async throws -> ManagedKey {
        guard !mutating else { throw KeyFailure.busy }
        mutating = true
        defer { mutating = false }
        let directory = try open()
        guard !(try directory.exists(finalName(id))) else { throw KeyFailure.duplicateKey }
        let stage = stageName(id)
        guard !(try directory.exists(stage)), !(try directory.exists(stage + ".pub")) else { throw KeyFailure.duplicateKey }
        var committed = false
        do {
            // Verify the ACL-free root immediately before system ssh-keygen creates its
            // stage. Its umask/0600 alone cannot suppress an inherited filesystem ACL.
            try directory.prepareGeneration(stage)
            try await tool.generate(at: rootURL.appendingPathComponent(stage).path, algorithm: algorithm, protection: protection)
            try directory.validatePrivateFile(stage)
            let envelope = try OpenSSHEnvelope(directory.read(stage))
            try directory.validatePrivateFile(stage)
            let observed = try await tool.publicKey(at: rootURL.appendingPathComponent(stage).path, protection: protection)
            try directory.validatePrivateFile(stage)
            guard observed == envelope.publicKey, observed.algorithm == algorithm else { throw KeyFailure.invalidOpenSSH }
            try Task.checkCancellation()
            try directory.remove(stage + ".pub")
            try directory.commit(stage: stage, destination: finalName(id), committed: &committed)
            return ManagedKey(id: id, publicKey: observed, encrypted: envelope.encrypted)
        } catch {
            throw compensate(error, ticket: KeyCleanupTicket(id: id, pendingName: stage,
                                                            includesPublicSidecar: true, includesCommittedKey: committed), cleanPending: true)
        }
    }

    @discardableResult
    public func deleteExact(_ id: UUID) throws -> KeyDeleteResult {
        guard !mutating else { throw KeyFailure.busy }
        return try open().remove(finalName(id)) ? .deleted : .alreadyAbsent
    }

    public func retryCleanup(_ ticket: KeyCleanupTicket) throws {
        guard !mutating else { throw KeyFailure.busy }
        guard valid(ticket) else { throw KeyFailure.invalidPath }
        let failures = cleanup(ticket, cleanPending: true)
        guard failures.isEmpty else { throw KeyOperationFailure(primary: .cleanupRequired, cleanupTicket: ticket, cleanupFailures: failures) }
    }

    private func valid(_ ticket: KeyCleanupTicket) -> Bool {
        let parts = ticket.pendingName.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 3 && parts[0] == Substring(ticket.id.uuidString) && UUID(uuidString: String(parts[1])) != nil && parts[2] == "pending"
    }
    private func cleanup(_ ticket: KeyCleanupTicket, cleanPending: Bool) -> [String: KeyFailure] {
        var names = cleanPending ? [ticket.pendingName] : []
        if ticket.includesPublicSidecar { names.append(ticket.pendingName + ".pub") }
        if ticket.includesCommittedKey { names.append(finalName(ticket.id)) }
        var failures: [String: KeyFailure] = [:]
        for name in names {
            do { try open().remove(name) }
            catch { failures[name] = sanitized(error) }
        }
        return failures
    }
    private func compensate(_ error: any Error, ticket: KeyCleanupTicket, cleanPending: Bool) -> KeyOperationFailure {
        let failures = cleanup(ticket, cleanPending: cleanPending)
        return KeyOperationFailure(primary: sanitized(error), cleanupTicket: failures.isEmpty ? nil : ticket, cleanupFailures: failures)
    }
    private func sanitized(_ error: any Error) -> KeyFailure {
        if error is CancellationError { return .cancelled }
        if error is KeyImportReviewFailure { return .changedWhileReading }
        return (error as? KeyFailure) ?? .systemCall("unexpected failure", 0)
    }
}
