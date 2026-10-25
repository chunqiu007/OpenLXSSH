import CryptoKit
import Foundation

public struct TrustedHostKey: Hashable, Sendable {
    public let host: HostIdentity
    public let key: HostPublicKey
}

public enum TrustPromptReason: Equatable, Sendable {
    case firstKey
    case additionalAlgorithm
    case manuallyVerifiedReplacement(previousFingerprint: String)
}

/// Immutable display data and an opaque, store-instance-bound, one-use request ID.
public struct PendingTrustDecision: Equatable, Sendable {
    public let id: UUID
    public let host: HostIdentity
    public let algorithm: String
    public let fingerprint: String
    public let reason: TrustPromptReason
}

public struct ChangedHostKey: Equatable, Sendable {
    public let host: HostIdentity
    public let algorithm: String
    public let expectedFingerprint: String
    public let presentedFingerprint: String
}

public enum HostTrustEvaluation: Equatable, Sendable {
    case trusted(TrustedHostKey)
    case pending(PendingTrustDecision)
    case rejected(ChangedHostKey)
}

/// Single authoritative OpenSSH known_hosts file. No system ~/.ssh access and no TOFU auto-save.
/// All writers must use this store/lock; same-UID malicious modification is not a security boundary.
public actor HostTrustStore {
    public nonisolated let knownHostsPath: AbsolutePath
    private let directory: PrivateDirectory
    private var pending: [UUID: Request] = [:]
    private static let file = "known_hosts"
    private static let lock = "trust.lock"

    private struct Request {
        let display: PendingTrustDecision
        let key: HostPublicKey
        let revision: String
        let expires: ContinuousClock.Instant
    }

    public init(directory path: AbsolutePath) throws {
        let directory = try PrivateDirectory(path)
        self.directory = directory
        knownHostsPath = try directory.path.appending(Self.file)
        try directory.withLock(Self.lock, allowCreation: true) { created in
            if let data = try directory.read(Self.file) {
                _ = try State(data: data)
            } else if created {
                try directory.atomicWrite(Self.file, data: State(records: []).encoded())
            } else {
                throw HostTrustError.corruptStorage
            }
        }
    }

    public func evaluate(host: HostIdentity, key: HostPublicKey) throws -> HostTrustEvaluation {
        try directory.withLock(Self.lock) { _ in
            let state = try readState()
            if let existing = state.record(host: host, algorithm: key.algorithm) {
                if existing.key == key { return .trusted(existing) }
                return .rejected(ChangedHostKey(host: host, algorithm: key.algorithm,
                    expectedFingerprint: existing.key.fingerprint, presentedFingerprint: key.fingerprint))
            }
            let reason: TrustPromptReason = state.records.contains(where: { $0.host == host })
                ? .additionalAlgorithm : .firstKey
            return .pending(makeRequest(host: host, key: key, reason: reason, revision: state.revision))
        }
    }

    /// Management-only path after independent human verification; never called by evaluate().
    /// The caller must supply the current fingerprint observed in the management UI.
    public func prepareReplacement(host: HostIdentity, key: HostPublicKey,
                                   expectedCurrentFingerprint: String) throws -> PendingTrustDecision {
        try directory.withLock(Self.lock) { _ in
            let state = try readState()
            guard let existing = state.record(host: host, algorithm: key.algorithm), existing.key != key else {
                throw HostTrustError.noChangedKey
            }
            guard existing.key.fingerprint == expectedCurrentFingerprint else {
                throw HostTrustError.fingerprintMismatch
            }
            return makeRequest(host: host, key: key,
                reason: .manuallyVerifiedReplacement(previousFingerprint: existing.key.fingerprint),
                revision: state.revision)
        }
    }

    /// Explicit acceptance of exactly the fingerprint shown to the user. No default-accept API.
    /// Every attempted answer consumes the token, including stale or incorrect answers.
    @discardableResult
    public func confirm(_ decision: PendingTrustDecision, displayedFingerprint: String) throws -> TrustedHostKey {
        guard let request = pending.removeValue(forKey: decision.id), request.display == decision,
              ContinuousClock.now < request.expires else { throw HostTrustError.expiredDecision }
        guard displayedFingerprint == request.key.fingerprint else { throw HostTrustError.fingerprintMismatch }
        return try directory.withLock(Self.lock) { _ in
            let state = try readState()
            guard request.revision == state.revision else { throw HostTrustError.storageChanged }
            let existing = state.record(host: decision.host, algorithm: request.key.algorithm)
            switch decision.reason {
            case .firstKey, .additionalAlgorithm:
                guard existing == nil else { throw HostTrustError.storageChanged }
            case .manuallyVerifiedReplacement(let previous):
                guard existing?.key.fingerprint == previous else { throw HostTrustError.storageChanged }
            }
            var records = state.records.filter {
                !($0.host == decision.host && $0.key.algorithm == request.key.algorithm)
            }
            let accepted = TrustedHostKey(host: decision.host, key: request.key)
            records.append(accepted)
            try directory.atomicWrite(Self.file, data: State(records: records).encoded())
            return accepted
        }
    }

    public func cancel(_ decision: PendingTrustDecision) {
        pending.removeValue(forKey: decision.id)
    }

    /// Call on session close/address edit. Fresh endpoints must be evaluated independently.
    public func cancelAllPendingDecisions() { pending.removeAll() }

    public func records() throws -> [TrustedHostKey] {
        try directory.withLock(Self.lock) { _ in try readState().records }
    }

    private func makeRequest(host: HostIdentity, key: HostPublicKey, reason: TrustPromptReason,
                             revision: String) -> PendingTrustDecision {
        pending = pending.filter { ContinuousClock.now < $0.value.expires }
        // Bounded transient UI state. Discarding an unanswered request can only cause rejection.
        if pending.count >= 128 { pending.removeAll() }
        let decision = PendingTrustDecision(id: UUID(), host: host, algorithm: key.algorithm,
                                           fingerprint: key.fingerprint, reason: reason)
        pending[decision.id] = Request(display: decision, key: key, revision: revision,
                                      expires: .now.advanced(by: .seconds(300)))
        return decision
    }

    private func readState() throws -> State {
        // A missing file after initialization is damage, not a new empty trust database.
        guard let data = try directory.read(Self.file) else { throw HostTrustError.corruptStorage }
        return try State(data: data)
    }

    private struct State {
        private static let prefix = "# OpenLXSSH-host-trust-v1 "
        let generation: UUID
        let records: [TrustedHostKey]
        var revision: String { Data(SHA256.hash(data: encoded())).base64EncodedString() }

        init(records: [TrustedHostKey]) {
            generation = UUID()
            self.records = records
        }

        init(data: Data) throws {
            guard let text = String(data: data, encoding: .utf8), text.hasSuffix("\n") else {
                throw HostTrustError.corruptStorage
            }
            let lines = text.dropLast().split(separator: "\n", omittingEmptySubsequences: false)
            guard let first = lines.first, first.hasPrefix(Self.prefix),
                  let generation = UUID(uuidString: String(first.dropFirst(Self.prefix.count))),
                  first == Substring(Self.prefix + generation.uuidString) else {
                throw HostTrustError.corruptStorage
            }
            self.generation = generation
            var parsed: [TrustedHostKey] = []
            var identities = Set<String>()
            do {
                for line in lines.dropFirst() {
                    let fields = line.split(separator: " ", omittingEmptySubsequences: false)
                    guard fields.count == 3 else { throw HostTrustError.corruptStorage }
                    let host = try HostIdentity(knownHostsName: String(fields[0]))
                    let key = try HostPublicKey(algorithm: String(fields[1]), base64: String(fields[2]))
                    guard identities.insert(host.knownHostsName + " " + key.algorithm).inserted else {
                        throw HostTrustError.corruptStorage
                    }
                    parsed.append(TrustedHostKey(host: host, key: key))
                }
            } catch { throw HostTrustError.corruptStorage }
            records = parsed
            // Strict app-owned subset: no wildcard/hashed/CA/revoked/comment/imported rows.
            guard encoded() == data else { throw HostTrustError.corruptStorage }
        }

        func record(host: HostIdentity, algorithm: String) -> TrustedHostKey? {
            records.first { $0.host == host && $0.key.algorithm == algorithm }
        }

        func encoded() -> Data {
            let lines = records.map { $0.host.knownHostsName + " " + $0.key.openSSH }.sorted()
            return Data((Self.prefix + generation.uuidString + "\n" +
                         (lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n")).utf8)
        }
    }
}
