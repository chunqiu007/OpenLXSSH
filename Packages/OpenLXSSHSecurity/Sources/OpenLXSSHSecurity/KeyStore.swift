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
    private var mutating = false

    public init(directory: URL) throws {
        self.directory = try PrivateDirectory(directory: directory)
        rootURL = directory
        tool = SSHKeygenTool()
    }
    init(directory: URL, tool: SSHKeygenTool) throws {
        self.directory = try PrivateDirectory(directory: directory)
        rootURL = directory
        self.tool = tool
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
        directory = nil // only closes handles/lock; never removes durable keys or directories.
    }

    public func key(id: UUID) throws -> ManagedKey {
        let envelope = try OpenSSHEnvelope(open().read(finalName(id)))
        return ManagedKey(id: id, publicKey: envelope.publicKey, encrypted: envelope.encrypted)
    }
    public func publicKey(for id: UUID) throws -> PublicKey { try key(id: id).publicKey }

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
        return (error as? KeyFailure) ?? .systemCall("unexpected failure", 0)
    }
}
