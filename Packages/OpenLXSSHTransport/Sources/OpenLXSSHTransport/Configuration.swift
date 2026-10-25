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
/// Does not implement a second trust store or modify ~/.ssh.
final class SessionWorkspace {
    let directory: String
    private let root: Int32
    private let descriptor: Int32
    private let name: String
    init(root path: AbsolutePath, text: String) throws {
        root = open(path.value, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var metadata = stat()
        guard root >= 0 else { throw TransportError.invalidConfiguration }
        guard fstat(root, &metadata) == 0, metadata.st_uid == getuid(), metadata.st_mode & 0o7777 == 0o700 else {
            Darwin.close(root); throw TransportError.invalidConfiguration
        }
        name = "session-" + UUID().uuidString
        guard mkdirat(root, name, 0o700) == 0 else { Darwin.close(root); throw TransportError.invalidConfiguration }
        directory = path.value + "/" + name
        descriptor = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { _ = unlinkat(root, name, AT_REMOVEDIR); Darwin.close(root); throw TransportError.invalidConfiguration }
        let fd = openat(descriptor, "ssh_config", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else {
            Darwin.close(descriptor); _ = unlinkat(root, name, AT_REMOVEDIR); Darwin.close(root); throw TransportError.invalidConfiguration
        }
        defer { Darwin.close(fd) }
        var succeeded = false
        defer {
            if !succeeded {
                _ = unlinkat(descriptor, "ssh_config", 0); Darwin.close(descriptor)
                _ = unlinkat(root, name, AT_REMOVEDIR); Darwin.close(root)
            }
        }
        try Data(text.utf8).withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw TransportError.invalidConfiguration }; offset += n
            }
        }
        guard fsync(fd) == 0 else { throw TransportError.invalidConfiguration }
        succeeded = true
    }
    func invocation(preview: Bool = false) -> DirectSSHInvocation {
        DirectSSHInvocation(executable: "/usr/bin/ssh", arguments: (preview ? ["-G"] : []) + ["-F", directory + "/ssh_config", "--", DirectSSHConfiguration.destination],
                            environment: ["PATH": "/usr/bin:/bin", "SHELL": "/bin/sh", "TERM": "xterm-256color", "LANG": "en_US.UTF-8", "LC_CTYPE": "UTF-8", "HOME": directory, "TMPDIR": directory])
    }
    deinit {
        _ = unlinkat(descriptor, "ssh_config", 0); Darwin.close(descriptor)
        _ = unlinkat(root, name, AT_REMOVEDIR); Darwin.close(root)
    }
}
