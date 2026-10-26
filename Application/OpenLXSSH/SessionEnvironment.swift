import Darwin
import Foundation
import OpenLXSSHCore
import OpenLXSSHTransport
import OpenLXSSHTrust

struct DefaultSystemScanner: HostKeyScanning {
    func scan(_ host: HostIdentity) async throws -> [HostKeyCandidate] { try await SystemHostKeyScanner().scan(host) }
}

struct SessionResources: Sendable {
    let trust: HostTrustStore
    let directory: AbsolutePath
    let helper: BundledAskpassHelper
}

/// All filesystem/trust initialization and typed host validation happens off MainActor.
actor SessionEnvironment {
    private let location: AppDataLocation
    private var resources: SessionResources?
    init(location: AppDataLocation) { self.location = location }
    func opened() throws -> SessionResources {
        let parent = try AppDataLocation.canonical(location.databaseDirectory().deletingLastPathComponent())
        if let resources {
            try Self.validateDirectories(parent: parent, create: false)
            return resources
        }
        try Self.validateDirectories(parent: parent, create: true)
        let trust = try HostTrustStore(directory: AbsolutePath(parent.appendingPathComponent("Trust").path))
        let helper = try BundledAskpassHelper.discover()
        try Self.validateDirectories(parent: parent, create: false)
        let value = SessionResources(trust: trust, directory: try AbsolutePath(parent.appendingPathComponent("Sessions").path), helper: helper)
        resources = value
        return value
    }
    static func validateDirectories(parent: URL, create: Bool) throws {
        let fd = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw TransportError.invalidConfiguration }
        defer { Darwin.close(fd) }
        try AppFileSecurity.directory(fd)
        for name in ["Trust", "Sessions"] {
            if create, mkdirat(fd, name, 0o700) != 0 && errno != EEXIST { throw TransportError.invalidConfiguration }
            let child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard child >= 0 else { throw TransportError.invalidConfiguration }
            defer { Darwin.close(child) }
            try AppFileSecurity.directory(child)
        }
        try AppFileSecurity.directory(fd)
    }
    func trustStore() throws -> HostTrustStore { try opened().trust }
    nonisolated static func configuration(host: HostConfiguration, keyPath: String?) throws -> SSHSessionConfiguration {
        let identity = HostIdentity(address: try HostAddress(host.address), port: try SSHPort(host.port))
        let auth: SSHAuthentication.Method
        switch host.authentication {
        case .password: auth = .passwordOnly
        case .passwordWithMFA: auth = .passwordAndKeyboardInteractive
        case .privateKey, .privateKeyWithMFA:
            guard let keyPath else { throw TransportError.invalidConfiguration }
            auth = .privateKey(try AbsolutePath(keyPath), keyboardInteractive: host.authentication == .privateKeyWithMFA)
        }
        return try SSHSessionConfiguration(connection: SSHConnection(host: identity, user: SSHUser(host.username)),
                                           authentication: SSHAuthentication(method: auth), serverAliveInterval: host.keepaliveInterval,
                                           serverAliveCountMax: host.keepaliveCountMax)
    }
}

@MainActor final class DirectSessionBuilder: SessionBuilding {
    let repository: any AppRepositoryProtocol
    let security: SecurityCoordinator
    let environment: SessionEnvironment
    let scanner: any HostKeyScanning
    init(repository: any AppRepositoryProtocol, security: SecurityCoordinator, environment: SessionEnvironment,
         scanner: any HostKeyScanning) {
        self.repository = repository; self.security = security; self.environment = environment; self.scanner = scanner
    }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        let metadata = try await repository.securityMetadata()
        guard let host = metadata.hosts.first(where: { $0.id == hostID }) else { throw RepositoryError.notFound }
        let keyPath: String?
        if host.authentication.needsKey {
            guard let id = host.keyRef, metadata.keys.contains(where: { $0.id == id }) else { throw TransportError.invalidConfiguration }
            keyPath = try await security.validatedPrivateKeyPath(id)
        } else { keyPath = nil }
        let configuration = try await Task.detached { try SessionEnvironment.configuration(host: host, keyPath: keyPath) }.value
        return (host, configuration)
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        let (host, configuration) = try await configuration(hostID: hostID)
        let resources = try await environment.opened()
        try Task.checkCancellation()
        let session = DirectSSHSession(sessionID: sessionID, trustStore: resources.trust, sessionDirectory: resources.directory,
                                       helper: resources.helper, scanner: scanner)
        return ReadySession(host: host, configuration: configuration, driver: DirectSessionDriver(session))
    }
}
