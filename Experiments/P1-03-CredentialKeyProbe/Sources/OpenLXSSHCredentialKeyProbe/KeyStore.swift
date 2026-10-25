import Darwin
import Foundation

public struct ManagedKey: Hashable, Sendable {
    public let id: UUID
    public let publicKey: PublicKey
    public let encrypted: Bool
}

public struct KeyOperationFailure: Error, Equatable, Sendable {
    public let primary: KeyFailure
    /// UUID-only artifact names; nonempty means cleanup must be explicitly retried.
    public let cleanupFailures: [String: KeyFailure]
}

/// App-managed copies only. A fresh owner-only temporary root is used by this experiment;
/// production Application Support locations, persistence and crash recovery are out of scope.
public actor KeyStore {
    public nonisolated let rootURL: URL
    private let directory: PrivateDirectory
    private let tool: SSHKeygenTool
    private var records: [UUID: ManagedKey] = [:]
    private var artifacts: Set<String> = []
    private var destroyed = false
    private var mutating = false

    public init() throws {
        let directory = try PrivateDirectory()
        self.directory = directory
        rootURL = directory.url
        tool = SSHKeygenTool()
    }

    private func ensureOpen() throws {
        guard !destroyed else { throw KeyFailure.missing }
        try directory.verify()
    }

    private func stageNames() -> (id: UUID, stage: String, final: String) {
        let id = UUID()
        return (id, "\(id.uuidString).pending", "\(id.uuidString).openssh")
    }

    public func importKey(from source: URL, protection: KeyProtection) async throws -> ManagedKey {
        guard !mutating else { throw KeyFailure.busy }
        mutating = true
        defer { mutating = false }
        try ensureOpen()
        // The source is opened once without following links. It is never chmod'ed, renamed,
        // overwritten or deleted. Validate framing/algorithm before staging a private copy.
        let bytes = try PrivateDirectory.readSource(source)
        let envelope = try OpenSSHEnvelope(bytes)
        if envelope.encrypted, case .unencrypted = protection { throw KeyFailure.passphraseRequired }
        let names = stageNames()
        artifacts.formUnion([names.stage, names.final])
        do {
            try directory.write(bytes, name: names.stage)
            let observed = try await tool.publicKey(at: rootURL.appendingPathComponent(names.stage).path,
                                                    protection: protection)
            guard observed == envelope.publicKey else { throw KeyFailure.invalidOpenSSH }
            try ensureOpen()
            guard !records.values.contains(where: { $0.publicKey == observed }) else { throw KeyFailure.duplicateKey }
            try directory.commit(stage: names.stage, destination: names.final)
            artifacts.remove(names.stage)
            let record = ManagedKey(id: names.id, publicKey: observed, encrypted: envelope.encrypted)
            records[record.id] = record
            return record
        } catch {
            throw compensate(error, names: [names.stage, names.final])
        }
    }

    public func generateEd25519(protection: KeyProtection) async throws -> ManagedKey {
        try await generate(algorithm: .ed25519, protection: protection)
    }

    // RSA generation is test-fixture support only; the public product-facing API generates Ed25519.
    func generate(algorithm: KeyAlgorithm, protection: KeyProtection) async throws -> ManagedKey {
        guard !mutating else { throw KeyFailure.busy }
        mutating = true
        defer { mutating = false }
        try ensureOpen()
        let names = stageNames()
        let publicName = names.stage + ".pub"
        artifacts.formUnion([names.stage, publicName, names.final])
        do {
            try await tool.generate(at: rootURL.appendingPathComponent(names.stage).path,
                                    algorithm: algorithm, protection: protection)
            try ensureOpen()
            let bytes = try directory.read(names.stage)
            let envelope = try OpenSSHEnvelope(bytes)
            let observed = try await tool.publicKey(at: rootURL.appendingPathComponent(names.stage).path,
                                                    protection: protection)
            guard observed.algorithm == algorithm, observed == envelope.publicKey else { throw KeyFailure.invalidOpenSSH }
            try ensureOpen()
            guard !records.values.contains(where: { $0.publicKey == observed }) else { throw KeyFailure.duplicateKey }
            try directory.remove(publicName)
            artifacts.remove(publicName)
            try directory.commit(stage: names.stage, destination: names.final)
            artifacts.remove(names.stage)
            let record = ManagedKey(id: names.id, publicKey: observed, encrypted: envelope.encrypted)
            records[record.id] = record
            return record
        } catch {
            throw compensate(error, names: [names.stage, publicName, names.final])
        }
    }

    public func publicKey(for id: UUID) throws -> PublicKey {
        try ensureOpen()
        guard let record = records[id] else { throw KeyFailure.missing }
        let envelope = try OpenSSHEnvelope(directory.read("\(id.uuidString).openssh"))
        guard envelope.publicKey == record.publicKey, envelope.encrypted == record.encrypted else {
            throw KeyFailure.invalidOpenSSH
        }
        return record.publicKey
    }

    public func delete(_ id: UUID) throws {
        guard !mutating else { throw KeyFailure.busy }
        try ensureOpen()
        guard records[id] != nil else { return }
        let name = "\(id.uuidString).openssh"
        try directory.remove(name)
        artifacts.remove(name)
        records.removeValue(forKey: id)
    }

    /// Explicit test/CLI lifecycle cleanup, never a recursive delete of a user-supplied path.
    public func destroy() throws {
        guard !mutating else { throw KeyFailure.busy }
        if destroyed { return }
        try directory.verify()
        var failures: [String: KeyFailure] = [:]
        for name in artifacts.sorted() {
            do { try directory.remove(name); artifacts.remove(name) }
            catch { failures[name] = sanitized(error) }
        }
        if !failures.isEmpty { throw KeyOperationFailure(primary: .systemCall("cleanup", 0), cleanupFailures: failures) }
        guard rmdir(rootURL.path) == 0 else { throw KeyFailure.systemCall("remove root", errno) }
        records.removeAll()
        destroyed = true
    }

    private func compensate(_ error: any Error, names: [String]) -> KeyOperationFailure {
        var failures: [String: KeyFailure] = [:]
        for name in names {
            do { try directory.remove(name); artifacts.remove(name) }
            catch { failures[name] = sanitized(error) }
        }
        return KeyOperationFailure(primary: sanitized(error), cleanupFailures: failures)
    }

    private func sanitized(_ error: any Error) -> KeyFailure {
        (error as? KeyFailure) ?? .systemCall("unexpected failure", 0)
    }
}
