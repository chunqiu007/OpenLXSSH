import CRemoteFileBridge
import Foundation
import OpenLXSSHTrust

public enum FileHostTrustEvent: Sendable {
    case pending(PendingTrustDecision)
    case changed(ChangedHostKey) // Informational rejection; no automatic replacement path.
}
public enum FileHostTrustAnswer: Sendable {
    case reject
    case confirm(displayedFingerprint: String)
}
public typealias FileHostTrustHandler = @Sendable (FileHostTrustEvent, ChallengeReply<FileHostTrustAnswer>) -> Void

enum SharedHostTrust {
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
                       handler: FileHostTrustHandler?) async throws {
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
            if let handler { DispatchQueue.global().async { handler(.changed(changed), ChallengeReply<FileHostTrustAnswer>()) } }
            throw FileServiceError(.untrusted, operation: "host-key-changed")
        case .pending(let pending):
            do {
                try token.check()
                guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "host-key") }
                guard let handler else { throw FileServiceError(.untrusted, operation: "host-key-needs-confirmation") }
                let reply = ChallengeReply<FileHostTrustAnswer>()
                DispatchQueue.global().async { handler(.pending(pending), reply) }
                let answer = try await reply.waitAsync(token: token, deadline: deadline)
                try token.check()
                guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "host-key") }
                guard case .confirm(let fingerprint) = answer else { throw FileServiceError(.untrusted, operation: "host-key-rejected") }
                let accepted = try await store.confirm(pending, displayedFingerprint: fingerprint)
                guard accepted.host == identity, accepted.key.blob == key.rawKey else {
                    throw FileServiceError(.untrusted, operation: "trust-binding")
                }
            } catch { await store.cancel(pending); throw error }
        }
        try token.check()
        guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "host-key") }
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
        do {
            let identity = try ServerIdentity(host: configuration.host.address.value, port: configuration.host.port.value)
            try await service.establish(identity: identity, username: Data(configuration.user.value.utf8),
                authentication: authentication, hostKeyHandler: { key, reply in
                    Task.detached {
                        do {
                            try await SharedHostTrust.verify(key, identity: configuration.host, store: trustStore,
                                                             timeout: operationTimeout, token: token, handler: trustHandler)
                            reply.resolve(true)
                        } catch { reply.resolve(false) }
                    }
                }, token: token)
            return service
        } catch { await service.close(); throw error }
    }
}
