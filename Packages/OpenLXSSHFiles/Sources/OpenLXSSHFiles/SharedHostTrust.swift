import COpenLXSSHFiles
import Foundation
import OpenLXSSHTrust

public enum FileHostTrustEvent: Sendable {
    case pending(PendingTrustDecision)
    case changed(ChangedHostKey) // Informational rejection; no automatic replacement path.
}
public enum FileHostTrustAnswer: Sendable {
    case reject
    case confirm(displayedFingerprint: String)
    /// Exact key for the current handshake only; never persists or replaces a changed key.
    case confirmOnce(displayedFingerprint: String)
}
public typealias FileHostTrustHandler = @Sendable (FileHostTrustEvent, ChallengeReply<FileHostTrustAnswer>) -> Void

/// Internal scheduling seam: native callers pre-register callbacks before this dispatcher can
/// enqueue them; offline tests can hold a queued callback without sleeping or running a server.
struct FileTrustCallbackDispatcher: Sendable {
    let submit: @Sendable (@escaping @Sendable () -> Void) -> Void
    static let global = FileTrustCallbackDispatcher { work in DispatchQueue.global().async(execute: work) }
}
/// One actual connection attempt. The verified rejection is recorded before a lossy Bool reply
/// or any best-effort UI callback. No callback/token lifetime can erase an observed fact.
final class FileHostTrustAttempt: @unchecked Sendable {
    private let lock = NSLock()
    private var changed: ChangedHostKey?
    var changedHostKey: ChangedHostKey? { lock.withLock { changed } }
    func record(_ fact: ChangedHostKey) { lock.withLock { if changed == nil { changed = fact } } }
    func enriching(_ error: any Error) -> any Error {
        guard let fact = changedHostKey else { return error }
        if let typed = error as? FileServiceError {
            return FileServiceError(typed.kind, operation: typed.operation, path: typed.path, code: typed.code,
                                    changedHostKey: typed.changedHostKey ?? fact)
        }
        return error
    }
}

enum SharedHostTrust {
    /// Shared production Bool bridge. It stores changed facts inside verify before replying false;
    /// the optional native registry owns this exact task without retaining a session/native owner.
    static func respond(to key: HostKey, reply: ChallengeReply<Bool>, identity: HostIdentity,
                        store: HostTrustStore, timeout: TimeInterval, token: CancellationToken,
                        attempt: FileHostTrustAttempt, tasks: NativeShellInteractionTasks? = nil,
                        dispatcher: FileTrustCallbackDispatcher = .global,
                        lifetime: CancellationToken? = nil, handler: FileHostTrustHandler?) {
        do {
            let taskID = try tasks?.begin(provider: false)
            let task = Task.detached {
                defer { if let tasks, let taskID { tasks.finish(taskID) } }
                do {
                    try lifetime?.check(); try token.check()
                    try await verify(key, identity: identity, store: store, timeout: timeout, token: token,
                        attempt: attempt, tasks: tasks, dispatcher: dispatcher, lifetime: lifetime, handler: handler)
                    try lifetime?.check(); try token.check()
                    reply.resolve(true)
                } catch { reply.resolve(false) }
            }
            if let tasks, let taskID { tasks.install(taskID) { reply.cancel(); task.cancel() } }
        } catch { reply.cancel() }
    }
    static func parse(_ key: HostKey) throws -> HostPublicKey {
        let algorithm: String
        switch key.algorithmCode {
        case Int32(LIBSSH2_HOSTKEY_TYPE_RSA): algorithm = "ssh-rsa"
        case Int32(LIBSSH2_HOSTKEY_TYPE_ECDSA_256): algorithm = "ecdsa-sha2-nistp256"
        case Int32(LIBSSH2_HOSTKEY_TYPE_ECDSA_384): algorithm = "ecdsa-sha2-nistp384"
        case Int32(LIBSSH2_HOSTKEY_TYPE_ECDSA_521): algorithm = "ecdsa-sha2-nistp521"
        case Int32(LIBSSH2_HOSTKEY_TYPE_ED25519): algorithm = "ssh-ed25519"
        default: throw FileServiceError(.untrusted, operation: "unsupported-host-key")
        }
        // The mature system parser validates that raw key blob and algorithm agree.
        return try HostPublicKey(algorithm: algorithm, base64: key.rawKey.base64EncodedString())
    }
    static func verify(_ key: HostKey, identity: HostIdentity, store: HostTrustStore,
                       timeout: TimeInterval, token: CancellationToken,
                       attempt: FileHostTrustAttempt? = nil, tasks: NativeShellInteractionTasks? = nil,
                       dispatcher: FileTrustCallbackDispatcher = .global,
                       lifetime: CancellationToken? = nil, handler: FileHostTrustHandler?) async throws {
        guard timeout.isFinite, timeout > 0 else { throw FileServiceError(.timeout, operation: "host-key") }
        let deadline = ContinuousClock.now.advanced(by: .seconds(timeout))
        try token.check()
        guard try HostAddress(key.identity.host) == identity.address,
              key.identity.port == identity.port.value else { throw FileServiceError(.untrusted, operation: "host-key-identity-mismatch") }
        let parsed = try parse(key) // Invoked off the caller/main queue by connect's task below.
        try token.check()
        let evaluation = try await store.evaluate(host: identity, key: parsed)
        switch evaluation {
        case .trusted(let record):
            guard record.host == identity, record.key.blob == key.rawKey else {
                throw FileServiceError(.untrusted, operation: "trust-binding")
            }
        case .rejected(let changed):
            attempt?.record(changed)
            if let handler {
                // Delivery is best-effort and never a prerequisite for failure/close. The fact
                // above survives a queued callback that is suppressed by later revocation.
                let informational = ChallengeReply<FileHostTrustAnswer>()
                informational.cancel()
                try? dispatch(.changed(changed), reply: informational,
                    token: token, lifetime: lifetime, tasks: tasks, dispatcher: dispatcher, handler: handler)
            }
            throw FileServiceError(.untrusted, operation: "host-key-changed", changedHostKey: changed)
        case .pending(let pending):
            do {
                try token.check()
                guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "host-key") }
                guard let handler else { throw FileServiceError(.untrusted, operation: "host-key-needs-confirmation") }
                let reply = ChallengeReply<FileHostTrustAnswer>()
                defer { reply.cancel() }
                try dispatch(.pending(pending), reply: reply, token: token, lifetime: lifetime,
                             tasks: tasks, dispatcher: dispatcher, handler: handler)
                let answer = try await reply.waitAsync(token: token, deadline: deadline)
                try token.check()
                guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "host-key") }
                let accepted: TrustedHostKey
                switch answer {
                case .reject: throw FileServiceError(.untrusted, operation: "host-key-rejected")
                case .confirm(let fingerprint):
                    accepted = try await store.confirm(pending, displayedFingerprint: fingerprint)
                case .confirmOnce(let fingerprint):
                    accepted = try await store.confirmOnce(pending, displayedFingerprint: fingerprint)
                }
                try token.check()
                guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "host-key") }
                guard accepted.host == identity, accepted.key.blob == key.rawKey else {
                    throw FileServiceError(.untrusted, operation: "trust-binding")
                }
            } catch { await store.cancel(pending); throw error }
        }
        try token.check()
        guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "host-key") }
    }
    private static func dispatch(_ event: FileHostTrustEvent, reply: ChallengeReply<FileHostTrustAnswer>,
                                 token: CancellationToken, lifetime: CancellationToken?,
                                 tasks: NativeShellInteractionTasks?, dispatcher: FileTrustCallbackDispatcher,
                                 handler: @escaping FileHostTrustHandler) throws {
        let work: @Sendable () -> Void = {
            guard !token.isCancelled, lifetime?.isCancelled != true else { reply.cancel(); return }
            handler(event, reply)
        }
        if let tasks { try tasks.dispatch(using: dispatcher, cancel: { reply.cancel() }, work: work) }
        else { dispatcher.submit(work) }
    }
}

extension LibSSH2FileService {
    /// Product-facing entry: typed endpoint -> private socket -> same-session handshake key -> shared
    /// trust store -> explicit authentication. No host-key scan, arbitrary-FD product API or shell.
    public static func connect(configuration: SSHConnection, authentication: [FileAuthentication],
                               trustStore: HostTrustStore, trustHandler: FileHostTrustHandler?,
                               connectionTimeout: TimeInterval = 10, operationTimeout: TimeInterval = 10,
                               token: CancellationToken) async throws -> LibSSH2FileService {
        let socket = try await TCPConnector.connect(configuration.host, timeout: connectionTimeout, token: token)
        defer { socket.close() }
        let service = try LibSSH2FileService(connectedSocket: socket.descriptor, operationTimeout: operationTimeout)
        let attempt = FileHostTrustAttempt()
        do {
            let identity = try ServerIdentity(host: configuration.host.address.value, port: configuration.host.port.value)
            try await service.establish(identity: identity, username: Data(configuration.user.value.utf8),
                authentication: authentication, hostKeyHandler: { key, reply in
                    SharedHostTrust.respond(to: key, reply: reply, identity: configuration.host, store: trustStore,
                        timeout: operationTimeout, token: token, attempt: attempt, handler: trustHandler)
                }, token: token)
            return service
        } catch { await service.close(); throw attempt.enriching(error) }
    }
}
