import Foundation
import Darwin
import OpenLXSSHTrust

public struct SessionToken: Hashable, Sendable {
    public let sessionID: UUID
    public let generation: UInt64
    public init(sessionID: UUID, generation: UInt64) { self.sessionID = sessionID; self.generation = generation }
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
        guard !trustedKeys.isEmpty else { throw TransportError.invalidConfiguration }
        self.configuration = configuration; knownHostsPath = trustStore.knownHostsPath
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

/// Only writes its one fixed configuration file in its own UUID subdirectory.
/// Does not implement a second trust store or modify ~/.ssh. Descriptor checks
/// reject extended ACLs; they are not a sandbox against same-UID mutation after
/// validation (system ssh still opens its configuration and key by path).
final class SessionWorkspace {
    let directory: String
    private let rootPath: String
    private let root: Int32
    private let descriptor: Int32
    private let configurationDescriptor: Int32
    private let name: String

    enum Checkpoint { case directoryOpened, fileOpened, fileWritten }

    convenience init(root path: AbsolutePath, text: String) throws {
        try self.init(root: path, text: text, checkpoint: { _, _ in })
    }
    #if TRANSPORT_HOST_PROBE
    // Deterministic real-filesystem race/error tests; unavailable to shipping
    // clients and does not replace any production security check.
    convenience init(probeRoot path: AbsolutePath, text: String, checkpoint: (Checkpoint, String) throws -> Void) throws {
        try self.init(root: path, text: text, checkpoint: checkpoint)
    }
    #endif
    private init(root path: AbsolutePath, text: String, checkpoint: (Checkpoint, String) throws -> Void) throws {
        let openedRoot = open(path.value, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard openedRoot >= 0 else { throw TransportError.invalidConfiguration }
        var openedDirectory: Int32 = -1, openedConfiguration: Int32 = -1
        var createdDirectory = false, succeeded = false
        let sessionName = "session-" + UUID().uuidString
        let sessionDirectory = path.value + "/" + sessionName
        defer {
            if !succeeded {
                if openedConfiguration >= 0 {
                    Darwin.close(openedConfiguration)
                    _ = unlinkat(openedDirectory, "ssh_config", 0)
                }
                if openedDirectory >= 0 { Darwin.close(openedDirectory) }
                if createdDirectory { _ = unlinkat(openedRoot, sessionName, AT_REMOVEDIR) }
                Darwin.close(openedRoot)
            }
        }
        // A root ACL must fail before creating even a UUID directory. Do not
        // chmod or remove ACLs to make an unsafe pre-existing root acceptable.
        try TransportFileSecurity.directory(openedRoot)
        guard mkdirat(openedRoot, sessionName, 0o700) == 0 else { throw TransportError.invalidConfiguration }
        createdDirectory = true
        openedDirectory = openat(openedRoot, sessionName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard openedDirectory >= 0 else { throw TransportError.invalidConfiguration }
        try checkpoint(.directoryOpened, sessionDirectory)
        // Reject inherited/new ACEs on the UUID directory before creating a file.
        try TransportFileSecurity.directory(openedRoot)
        try TransportFileSecurity.directory(openedDirectory)
        openedConfiguration = openat(openedDirectory, "ssh_config", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard openedConfiguration >= 0 else { throw TransportError.invalidConfiguration }
        try checkpoint(.fileOpened, sessionDirectory)
        // Creating with mode0600 does not remove inherited ACEs. Validate the
        // actual file and both directories before writing the first byte.
        try Self.validate(rootPath: path.value, name: sessionName, root: openedRoot,
                          directory: openedDirectory, configuration: openedConfiguration)
        try Data(text.utf8).withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(openedConfiguration, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw TransportError.invalidConfiguration }; offset += n
            }
        }
        guard fsync(openedConfiguration) == 0 else { throw TransportError.invalidConfiguration }
        try checkpoint(.fileWritten, sessionDirectory)
        try Self.validate(rootPath: path.value, name: sessionName, root: openedRoot,
                          directory: openedDirectory, configuration: openedConfiguration)
        rootPath = path.value; root = openedRoot; descriptor = openedDirectory
        configurationDescriptor = openedConfiguration; name = sessionName; directory = sessionDirectory
        succeeded = true
    }

    func validateForLaunch(authentication: SSHAuthentication = .init()) throws {
        try Self.validate(rootPath: rootPath, name: name, root: root, directory: descriptor, configuration: configurationDescriptor)
        // KeyStore validation happened earlier; check again immediately before
        // launch in case a managed key acquired an ACL or unsafe mode meanwhile.
        try TransportFileSecurity.validateAuthentication(authentication)
    }

    private static func validate(rootPath: String, name: String, root: Int32, directory: Int32, configuration: Int32) throws {
        let rootMetadata = try TransportFileSecurity.directory(root)
        let directoryMetadata = try TransportFileSecurity.directory(directory)
        let configurationMetadata = try TransportFileSecurity.regularFile(configuration)
        // ssh consumes pathnames, so also reject replaced/unlinked objects.
        let currentRoot = open(rootPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard currentRoot >= 0 else { throw TransportError.invalidConfiguration }
        defer { Darwin.close(currentRoot) }
        guard TransportFileSecurity.sameObject(rootMetadata, try TransportFileSecurity.directory(currentRoot)) else { throw TransportError.invalidConfiguration }
        let currentDirectory = openat(currentRoot, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard currentDirectory >= 0 else { throw TransportError.invalidConfiguration }
        defer { Darwin.close(currentDirectory) }
        guard TransportFileSecurity.sameObject(directoryMetadata, try TransportFileSecurity.directory(currentDirectory)) else { throw TransportError.invalidConfiguration }
        let currentConfiguration = openat(currentDirectory, "ssh_config", O_EVTONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard currentConfiguration >= 0 else { throw TransportError.invalidConfiguration }
        defer { Darwin.close(currentConfiguration) }
        guard TransportFileSecurity.sameObject(configurationMetadata, try TransportFileSecurity.regularFile(currentConfiguration)) else { throw TransportError.invalidConfiguration }
    }

    func invocation(preview: Bool = false) -> DirectSSHInvocation {
        DirectSSHInvocation(executable: "/usr/bin/ssh", arguments: (preview ? ["-G"] : []) + ["-F", directory + "/ssh_config", "--", DirectSSHConfiguration.destination],
                            environment: ["PATH": "/usr/bin:/bin", "SHELL": "/bin/sh", "TERM": "xterm-256color", "LANG": "en_US.UTF-8", "LC_CTYPE": "UTF-8", "HOME": directory, "TMPDIR": directory])
    }
    deinit {
        Darwin.close(configurationDescriptor)
        _ = unlinkat(descriptor, "ssh_config", 0); Darwin.close(descriptor)
        _ = unlinkat(root, name, AT_REMOVEDIR); Darwin.close(root)
    }
}
