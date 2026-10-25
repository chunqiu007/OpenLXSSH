import Darwin
import Foundation

public struct SSHInvocation: Equatable, Sendable {
    public let executable: String
    public let arguments: [String]
    public let environment: [String: String]
}

/// Can only be produced by writing a controlled configuration, not from an arbitrary -F path.
public struct PreparedSSHConfiguration: Sendable {
    public let path: AbsolutePath
    fileprivate init(path: AbsolutePath) { self.path = path }

    public func invocation(preview: Bool = false) -> SSHInvocation {
        SSHInvocation(executable: "/usr/bin/ssh",
            arguments: (preview ? ["-G"] : []) + ["-F", path.value, "--", ControlledSSHConfiguration.destination],
            environment: ["PATH": "/usr/bin:/bin", "LC_ALL": "C", "TERM": "xterm-256color"])
    }
}

/// Immutable session configuration. No arbitrary options, commands, credentials or env input.
public struct ControlledSSHConfiguration: Sendable {
    public let connection: SSHConnection
    public let knownHostsPath: AbsolutePath
    public static let destination = "openlxssh-direct"

    public init(connection: SSHConnection, trustStore: HostTrustStore) {
        self.connection = connection
        self.knownHostsPath = trustStore.knownHostsPath
    }

    public var text: String {
        // Only this fixed alias is passed as a destination, never user@host or an option.
        """
        Host \(Self.destination)
            HostName \(Self.quote(connection.host.address.value, expandTokens: true))
            HostKeyAlias \(Self.quote(connection.host.knownHostsName, expandTokens: false))
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
            IdentityFile none
            CertificateFile none
            AddKeysToAgent no
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
            PermitLocalCommand no
            LocalCommand none
            RemoteCommand none
            PermitRemoteOpen none
            EnableEscapeCommandline no
            EscapeChar none
            ConnectTimeout 10
            ConnectionAttempts 1
            ServerAliveInterval 15
            ServerAliveCountMax 3
            TCPKeepAlive yes
            NumberOfPasswordPrompts 1
            GSSAPIAuthentication no
            GSSAPIDelegateCredentials no
            HostbasedAuthentication no
            FingerprintHash sha256
            LogLevel ERROR

        """
    }

    /// Creates a private, uniquely named immutable config; caller owns its session lifetime.
    /// Worker-only: synchronously validates the directory and writes/fsyncs under a file lock.
    /// OpenSSH later opens by path; this is not a boundary against same-UID mutation/TOCTOU.
    public func write(in directoryPath: AbsolutePath) throws -> PreparedSSHConfiguration {
        if let zone = connection.host.address.value.split(separator: "%").dropFirst().first,
           !zone.utf8.allSatisfy({ (48...57).contains($0) }),
           String(zone).withCString({ if_nametoindex($0) }) == 0 {
            // OpenSSH silently removes nonexistent named scopes during address normalization.
            throw HostTrustError.invalidAddress
        }
        let directory = try PrivateDirectory(directoryPath)
        return try directory.withLock("configuration.lock", allowCreation: true) { _ in
            let name = "ssh-config-" + UUID().uuidString
            try directory.atomicWrite(name, data: Data(text.utf8))
            return PreparedSSHConfiguration(path: try directory.path.appending(name))
        }
    }

    private static func quote(_ value: String, expandTokens: Bool) -> String {
        var escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        if expandTokens { escaped = escaped.replacingOccurrences(of: "%", with: "%%") }
        return "\"" + escaped + "\""
    }
}
