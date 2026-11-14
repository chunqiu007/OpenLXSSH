import Darwin
import Foundation
import OpenLXSSHCore
import OpenLXSSHFiles
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
    private var sharedTrust: HostTrustStore?
    init(location: AppDataLocation) { self.location = location }
    func opened() throws -> SessionResources {
        let parent = try AppDataLocation.canonical(location.databaseDirectory().deletingLastPathComponent())
        if let resources {
            try Self.validateDirectories(parent: parent, create: false)
            return resources
        }
        try Self.validateDirectories(parent: parent, create: true)
        let trust = try sharedTrustStore()
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
    func sharedTrustStore() throws -> HostTrustStore {
        let parent = try AppDataLocation.canonical(location.databaseDirectory().deletingLastPathComponent())
        try Self.validateDirectories(parent: parent, create: true)
        if let sharedTrust { return sharedTrust }
        let trust = try HostTrustStore(directory: AbsolutePath(parent.appendingPathComponent("Trust").path))
        try Self.validateDirectories(parent: parent, create: false)
        sharedTrust = trust; return trust
    }
    func trustStore() throws -> HostTrustStore { try sharedTrustStore() }
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

/// Production factory shared by ordinary opens and prepared once-password opens.
/// Independent injection seams remain available for logical legacy-boundary tests.
@MainActor struct AppSessionBuilders {
    let ordinary: any SessionBuilding
    let prepared: any SessionBuilding
    init(repository: any AppRepositoryProtocol, security: SecurityCoordinator, environment: SessionEnvironment,
         ordinary: (any SessionBuilding)? = nil, prepared: (any SessionBuilding)? = nil) {
        let unified = NativeSessionBuilder(repository: repository, security: security, environment: environment)
        self.ordinary = ordinary ?? unified
        self.prepared = prepared ?? unified
    }
}

/// Typed primary authentication and manual server challenges use one native session owner.
@MainActor final class NativeSessionBuilder: SessionBuilding {
    let repository: any AppRepositoryProtocol
    let security: SecurityCoordinator
    let environment: SessionEnvironment
    private let connector: (any NativeSessionConnecting)?
    init(repository: any AppRepositoryProtocol, security: SecurityCoordinator, environment: SessionEnvironment,
         connector: (any NativeSessionConnecting)? = nil) {
        self.repository = repository; self.security = security; self.environment = environment; self.connector = connector
    }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        let metadata = try await repository.securityMetadata()
        try Task.checkCancellation()
        guard let host = metadata.hosts.first(where: { $0.id == hostID }) else { throw RepositoryError.notFound }
        let keyPath: String?
        if host.authentication.needsKey {
            guard let id = host.keyRef, metadata.keys.contains(where: { $0.id == id }) else { throw TransportError.invalidConfiguration }
            keyPath = try await security.validatedPrivateKeyPath(id)
        } else { keyPath = nil }
        let configuration = try SessionEnvironment.configuration(host: host, keyPath: keyPath)
        return (host, configuration)
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        let (host, configuration) = try await configuration(hostID: hostID)
        let native: any NativeSessionConnecting
        if let connector { native = connector }
        else { native = NativeLibraryConnector(store: try await environment.sharedTrustStore()) }
        try Task.checkCancellation()
        let driver = try NativeSessionDriver(sessionID: sessionID, host: host, repository: repository, security: security, connector: native)
        return ReadySession(host: host, configuration: configuration, driver: driver)
    }
}
