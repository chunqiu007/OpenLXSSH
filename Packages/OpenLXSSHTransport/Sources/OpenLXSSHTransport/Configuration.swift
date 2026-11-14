import Foundation
import Darwin
import OpenLXSSHTrust

public struct SessionToken: Hashable, Sendable {
    public let sessionID: UUID
    public let generation: UInt64
    public init(sessionID: UUID, generation: UInt64) { self.sessionID = sessionID; self.generation = generation }
}
public enum SessionTrustPersistence: Equatable, Sendable {
    case persistent, once
}
public enum SSHSessionState: Equatable, Sendable {
    case idle, preparing, awaitingTrust, authenticating
    /// Local process exists, but there is no trusted authenticated event yet.
    case connectionPending
    /// Verified outer authentication event, not evidence of PTY/shell readiness.
    case connected
    case disconnected(Int32?), failed(SessionFailure), closing, closed
}
public enum SessionFailure: String, Error, Equatable, Sendable {
    case invalidConfiguration, launchFailed, trustRejected, trustScanFailed, authenticationFailed, authenticationTimeout, inputFailed
}
public enum TransportError: Error, Equatable, Sendable {
    case busy, closed, stale, invalidConfiguration, inputFull, inactive
}

public struct SSHAuthentication: Equatable, Sendable {
    public enum Method: Equatable, Sendable {
        case passwordAndKeyboardInteractive
        case passwordOnly
        case privateKey(AbsolutePath, keyboardInteractive: Bool)
    }
    public let method: Method
    public init(method: Method = .passwordAndKeyboardInteractive) { self.method = method }
    // Saved-password authorization is per connection and only eligible in the
    // separately gated strict passwordOnly mode; mixed challenges remain manual.
}
public struct SSHSessionConfiguration: Equatable, Sendable {
    public let connection: SSHConnection
    public let authentication: SSHAuthentication
    public let connectTimeout: Int
    public let serverAliveInterval: Int
    public let serverAliveCountMax: Int
    public init(connection: SSHConnection, authentication: SSHAuthentication = .init(), connectTimeout: Int = 10,
                serverAliveInterval: Int = 15, serverAliveCountMax: Int = 3) throws {
        guard (1...60).contains(connectTimeout), (0...3600).contains(serverAliveInterval), (1...10).contains(serverAliveCountMax) else { throw TransportError.invalidConfiguration }
        self.connection = connection; self.authentication = authentication; self.connectTimeout = connectTimeout
        self.serverAliveInterval = serverAliveInterval; self.serverAliveCountMax = serverAliveCountMax
    }
}
public struct DirectSSHInvocation: Equatable, Sendable {
    public let executable: String
    public let arguments: [String]
    public let environment: [String: String]
    package init(executable: String, arguments: [String], environment: [String: String]) {
        self.executable = executable; self.arguments = arguments; self.environment = environment
    }
}

/// Session-only extension of the reviewed P1-02 controlled configuration.
/// No shell, arbitrary flags, remote command, environment or user ssh_config.
public struct DirectSSHConfiguration: Sendable {
    public let configuration: SSHSessionConfiguration
    public let knownHostsPath: AbsolutePath
    public let allowedHostKeyAlgorithms: [String]
    public let authenticatedEventCommand: String?
    public static let destination = "openlxssh-direct"
    public init(configuration: SSHSessionConfiguration, trustStore: HostTrustStore, trustedKeys: [HostPublicKey], helper: BundledAskpassHelper? = nil) throws {
        try self.init(configuration: configuration, knownHostsPath: trustStore.knownHostsPath, trustedKeys: trustedKeys, helper: helper)
    }
    fileprivate init(configuration: SSHSessionConfiguration, knownHostsPath: AbsolutePath, trustedKeys: [HostPublicKey], helper: BundledAskpassHelper?) throws {
        guard !trustedKeys.isEmpty else { throw TransportError.invalidConfiguration }
        self.configuration = configuration; self.knownHostsPath = knownHostsPath
        authenticatedEventCommand = try helper.map { try AuthenticatedEventCommand.make(helper: $0) }
        allowedHostKeyAlgorithms = Array(Set(trustedKeys.flatMap { key in
            key.algorithm == "ssh-rsa" ? ["rsa-sha2-512", "rsa-sha2-256"] : [key.algorithm]
        })).sorted()
    }
    public var text: String {
        let connection = configuration.connection
        var auth: String
        switch configuration.authentication.method {
        case .passwordAndKeyboardInteractive:
            auth = "IdentityFile none\n    PubkeyAuthentication no\n    PasswordAuthentication yes\n    KbdInteractiveAuthentication yes\n    PreferredAuthentications keyboard-interactive,password"
        case .passwordOnly:
            auth = "IdentityFile none\n    PubkeyAuthentication no\n    PasswordAuthentication yes\n    KbdInteractiveAuthentication no\n    PreferredAuthentications password"
        case .privateKey(let path, let keyboardInteractive):
            auth = "IdentityFile \(Self.quote(path.value, expandTokens: true))\n    PubkeyAuthentication yes\n    PasswordAuthentication no\n    KbdInteractiveAuthentication \(keyboardInteractive ? "yes" : "no")\n    PreferredAuthentications \(keyboardInteractive ? "publickey,keyboard-interactive" : "publickey")"
        }
        return """
        Host \(Self.destination)
            HostName \(Self.quote(connection.host.address.value, expandTokens: true))
            HostKeyAlias \(Self.quote(connection.host.knownHostsName, expandTokens: false))
            HostKeyAlgorithms \(allowedHostKeyAlgorithms.joined(separator: ","))
            Port \(connection.host.port.value)
            User \(Self.quote(connection.user.value, expandTokens: false))
            UserKnownHostsFile \(Self.quote(knownHostsPath.value, expandTokens: true))
            GlobalKnownHostsFile /dev/null
            KnownHostsCommand none
            StrictHostKeyChecking yes
            UpdateHostKeys no
            VerifyHostKeyDNS no
            CheckHostIP no
            HashKnownHosts no
            CanonicalizeHostname no
            ForwardAgent no
            IdentityAgent none
            IdentitiesOnly yes
            \(auth)
            CertificateFile none
            AddKeysToAgent no
            PKCS11Provider none
            UseKeychain no
            BatchMode no
            ForwardX11 no
            ForwardX11Trusted no
            ClearAllForwardings yes
            Tunnel no
            GatewayPorts no
            ProxyCommand none
            ProxyJump none
            ProxyUseFdpass no
            ControlMaster no
            ControlPath none
            ControlPersist no
            PermitLocalCommand \(authenticatedEventCommand == nil ? "no" : "yes")
            LocalCommand \(authenticatedEventCommand ?? "none")
            RemoteCommand none
            PermitRemoteOpen none
            EnableEscapeCommandline no
            EscapeChar none
            RequestTTY force
            ConnectTimeout \(configuration.connectTimeout)
            ConnectionAttempts 1
            ServerAliveInterval \(configuration.serverAliveInterval)
            ServerAliveCountMax \(configuration.serverAliveCountMax)
            TCPKeepAlive yes
            NumberOfPasswordPrompts 1
            GSSAPIAuthentication no
            GSSAPIDelegateCredentials no
            HostbasedAuthentication no
            FingerprintHash sha256
            LogLevel ERROR

        """
    }
    private static func quote(_ value: String, expandTokens: Bool) -> String {
        var result = value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        if expandTokens { result = result.replacingOccurrences(of: "%", with: "%%") }
        return "\"" + result + "\""
    }
}

/// Owns a UUID configuration and, only for one-time trust, an exact ephemeral key snapshot.
/// Path checks reduce same-UID races; system ssh still opens these files by pathname.
/// Immutable descriptors/bytes may be transferred from preparation to the session
/// actor. Methods never mutate this owner; the last reference alone closes the FDs.
final class SessionWorkspace: Sendable {
    let directory: String
    private let rootPath: String
    private let root: Int32
    private let descriptor: Int32
    private let configurationDescriptor: Int32
    private let trustDescriptor: Int32
    private let name: String
    private let configurationBytes: Data
    private let trustBytes: Data?
    private static let trustFile = "known_hosts"

    enum Checkpoint { case directoryOpened, fileOpened, fileWritten, trustFileOpened, trustFileWritten }

    convenience init(root path: AbsolutePath, text: String) throws {
        try self.init(root: path, temporaryTrust: nil, configurationText: { _ in text }, checkpoint: { _, _ in })
    }
    convenience init(root path: AbsolutePath, configuration: SSHSessionConfiguration,
                     temporaryTrust: TrustedHostKey, helper: BundledAskpassHelper? = nil) throws {
        guard temporaryTrust.host == configuration.connection.host else { throw TransportError.invalidConfiguration }
        try self.init(root: path, temporaryTrust: temporaryTrust, configurationText: { directory in
            try DirectSSHConfiguration(configuration: configuration,
                knownHostsPath: AbsolutePath(directory + "/" + Self.trustFile),
                trustedKeys: [temporaryTrust.key], helper: helper).text
        }, checkpoint: { _, _ in })
    }
    #if TRANSPORT_HOST_PROBE
    // Probe hooks preserve the production FD, ACL and path checks.
    convenience init(probeRoot path: AbsolutePath, text: String, checkpoint: (Checkpoint, String) throws -> Void) throws {
        try self.init(root: path, temporaryTrust: nil, configurationText: { _ in text }, checkpoint: checkpoint)
    }
    convenience init(probeRoot path: AbsolutePath, configuration: SSHSessionConfiguration,
                     temporaryTrust: TrustedHostKey, checkpoint: (Checkpoint, String) throws -> Void) throws {
        guard temporaryTrust.host == configuration.connection.host else { throw TransportError.invalidConfiguration }
        try self.init(root: path, temporaryTrust: temporaryTrust, configurationText: { directory in
            try DirectSSHConfiguration(configuration: configuration,
                knownHostsPath: AbsolutePath(directory + "/" + Self.trustFile),
                trustedKeys: [temporaryTrust.key], helper: nil).text
        }, checkpoint: checkpoint)
    }
    #endif
    private init(root path: AbsolutePath, temporaryTrust: TrustedHostKey?,
                 configurationText: (String) throws -> String,
                 checkpoint: (Checkpoint, String) throws -> Void) throws {
        let openedRoot = open(path.value, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard openedRoot >= 0 else { throw TransportError.invalidConfiguration }
        var openedDirectory: Int32 = -1, openedConfiguration: Int32 = -1, openedTrust: Int32 = -1
        var createdDirectory = false, succeeded = false
        let sessionName = "session-" + UUID().uuidString
        let sessionDirectory = path.value + "/" + sessionName
        defer {
            if !succeeded {
                if openedTrust >= 0 {
                    Self.unlinkOwned(openedTrust, directory: openedDirectory, name: Self.trustFile)
                    Darwin.close(openedTrust)
                }
                if openedConfiguration >= 0 {
                    Self.unlinkOwned(openedConfiguration, directory: openedDirectory, name: "ssh_config")
                    Darwin.close(openedConfiguration)
                }
                if createdDirectory, openedDirectory >= 0 {
                    Self.unlinkOwned(openedDirectory, directory: openedRoot, name: sessionName, flags: AT_REMOVEDIR)
                }
                if openedDirectory >= 0 { Darwin.close(openedDirectory) }
                Darwin.close(openedRoot)
            }
        }
        try TransportFileSecurity.directory(openedRoot)
        guard mkdirat(openedRoot, sessionName, 0o700) == 0 else { throw TransportError.invalidConfiguration }
        createdDirectory = true
        openedDirectory = openat(openedRoot, sessionName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard openedDirectory >= 0 else { throw TransportError.invalidConfiguration }
        try checkpoint(.directoryOpened, sessionDirectory)
        try TransportFileSecurity.directory(openedRoot)
        try TransportFileSecurity.directory(openedDirectory)
        openedConfiguration = openat(openedDirectory, "ssh_config", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard openedConfiguration >= 0 else { throw TransportError.invalidConfiguration }
        try checkpoint(.fileOpened, sessionDirectory)
        try Self.validate(rootPath: path.value, name: sessionName, root: openedRoot,
                          directory: openedDirectory, configuration: openedConfiguration, trust: openedTrust)
        let configBytes = Data(try configurationText(sessionDirectory).utf8)
        try Self.write(configBytes, to: openedConfiguration)
        try checkpoint(.fileWritten, sessionDirectory)
        try Self.validate(rootPath: path.value, name: sessionName, root: openedRoot,
                          directory: openedDirectory, configuration: openedConfiguration, trust: openedTrust)
        let knownHostsBytes = temporaryTrust.map { Data(($0.host.knownHostsName + " " + $0.key.openSSH + "\n").utf8) }
        if let knownHostsBytes {
            openedTrust = openat(openedDirectory, Self.trustFile, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard openedTrust >= 0 else { throw TransportError.invalidConfiguration }
            try checkpoint(.trustFileOpened, sessionDirectory)
            try Self.validate(rootPath: path.value, name: sessionName, root: openedRoot,
                              directory: openedDirectory, configuration: openedConfiguration, trust: openedTrust)
            try Self.write(knownHostsBytes, to: openedTrust)
            try checkpoint(.trustFileWritten, sessionDirectory)
            try Self.validate(rootPath: path.value, name: sessionName, root: openedRoot,
                              directory: openedDirectory, configuration: openedConfiguration, trust: openedTrust)
            try Self.validateBytes(knownHostsBytes, descriptor: openedTrust)
        }
        try Self.validateBytes(configBytes, descriptor: openedConfiguration)
        rootPath = path.value; root = openedRoot; descriptor = openedDirectory
        configurationDescriptor = openedConfiguration; trustDescriptor = openedTrust
        configurationBytes = configBytes; trustBytes = knownHostsBytes
        name = sessionName; directory = sessionDirectory
        succeeded = true
    }

    func validateForLaunch(authentication: SSHAuthentication = .init()) throws {
        try Self.validate(rootPath: rootPath, name: name, root: root, directory: descriptor,
                          configuration: configurationDescriptor, trust: trustDescriptor)
        if let trustBytes {
            try Self.validateBytes(configurationBytes, descriptor: configurationDescriptor)
            try Self.validateBytes(trustBytes, descriptor: trustDescriptor)
            try Self.validate(rootPath: rootPath, name: name, root: root, directory: descriptor,
                              configuration: configurationDescriptor, trust: trustDescriptor)
        }
        try TransportFileSecurity.validateAuthentication(authentication)
    }

    private static func write(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw TransportError.invalidConfiguration }
                offset += count
            }
        }
        guard fsync(descriptor) == 0 else { throw TransportError.invalidConfiguration }
    }

    private static func validateBytes(_ expected: Data, descriptor: Int32) throws {
        guard try TransportFileSecurity.regularFile(descriptor).st_size == off_t(expected.count) else { throw TransportError.invalidConfiguration }
        var actual = Data(count: expected.count)
        try actual.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = pread(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, off_t(offset))
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw TransportError.invalidConfiguration }
                offset += count
            }
        }
        guard actual == expected else { throw TransportError.invalidConfiguration }
    }

    private static func validate(rootPath: String, name: String, root: Int32, directory: Int32,
                                 configuration: Int32, trust: Int32) throws {
        let rootMetadata = try TransportFileSecurity.directory(root)
        let directoryMetadata = try TransportFileSecurity.directory(directory)
        let configurationMetadata = try TransportFileSecurity.regularFile(configuration)
        let currentRoot = open(rootPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard currentRoot >= 0 else { throw TransportError.invalidConfiguration }
        defer { Darwin.close(currentRoot) }
        guard TransportFileSecurity.sameObject(rootMetadata, try TransportFileSecurity.directory(currentRoot)) else { throw TransportError.invalidConfiguration }
        let currentDirectory = openat(currentRoot, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard currentDirectory >= 0 else { throw TransportError.invalidConfiguration }
        defer { Darwin.close(currentDirectory) }
        guard TransportFileSecurity.sameObject(directoryMetadata, try TransportFileSecurity.directory(currentDirectory)) else { throw TransportError.invalidConfiguration }
        try validateNamedFile("ssh_config", metadata: configurationMetadata, directory: currentDirectory)
        if trust >= 0 {
            try validateNamedFile(Self.trustFile, metadata: TransportFileSecurity.regularFile(trust), directory: currentDirectory)
        }
    }

    private static func validateNamedFile(_ name: String, metadata: stat, directory: Int32) throws {
        let current = openat(directory, name, O_EVTONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else { throw TransportError.invalidConfiguration }
        defer { Darwin.close(current) }
        guard TransportFileSecurity.sameObject(metadata, try TransportFileSecurity.regularFile(current)) else { throw TransportError.invalidConfiguration }
    }

    private static func unlinkOwned(_ descriptor: Int32, directory: Int32, name: String, flags: Int32 = 0) {
        var opened = stat(), named = stat()
        guard fstat(descriptor, &opened) == 0,
              fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              TransportFileSecurity.sameObject(opened, named) else { return }
        _ = unlinkat(directory, name, flags)
    }

    func invocation(preview: Bool = false) -> DirectSSHInvocation {
        DirectSSHInvocation(executable: "/usr/bin/ssh", arguments: (preview ? ["-G"] : []) + ["-F", directory + "/ssh_config", "--", DirectSSHConfiguration.destination],
                            environment: ["PATH": "/usr/bin:/bin", "SHELL": "/bin/sh", "TERM": "xterm-256color", "LANG": "en_US.UTF-8", "LC_CTYPE": "UTF-8", "HOME": directory, "TMPDIR": directory])
    }
    deinit {
        if trustDescriptor >= 0 {
            Self.unlinkOwned(trustDescriptor, directory: descriptor, name: Self.trustFile)
            Darwin.close(trustDescriptor)
        }
        Self.unlinkOwned(configurationDescriptor, directory: descriptor, name: "ssh_config")
        Darwin.close(configurationDescriptor)
        Self.unlinkOwned(descriptor, directory: root, name: name, flags: AT_REMOVEDIR)
        Darwin.close(descriptor); Darwin.close(root)
    }
}
