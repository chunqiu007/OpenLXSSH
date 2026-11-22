import Foundation
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
    /// Local session exists, but there is no trusted authenticated event yet.
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
}

public struct SSHSessionConfiguration: Equatable, Sendable {
    public let connection: SSHConnection
    public let authentication: SSHAuthentication
    public let connectTimeout: Int
    public let serverAliveInterval: Int
    public let serverAliveCountMax: Int
    public init(connection: SSHConnection, authentication: SSHAuthentication = .init(), connectTimeout: Int = 10,
                serverAliveInterval: Int = 15, serverAliveCountMax: Int = 3) throws {
        guard (1...60).contains(connectTimeout), (0...3600).contains(serverAliveInterval), (1...10).contains(serverAliveCountMax) else {
            throw TransportError.invalidConfiguration
        }
        self.connection = connection
        self.authentication = authentication
        self.connectTimeout = connectTimeout
        self.serverAliveInterval = serverAliveInterval
        self.serverAliveCountMax = serverAliveCountMax
    }
}
