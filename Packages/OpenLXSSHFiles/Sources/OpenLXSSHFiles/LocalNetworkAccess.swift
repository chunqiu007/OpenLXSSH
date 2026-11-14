import Foundation
import Network
import OpenLXSSHTrust

/// Only the OS's explicit local-network policy state opens a human-response budget.
/// Other path errors fall through to the existing DNS/TCP implementation and its diagnostics.
enum LocalNetworkAccessEvent: Sendable { case preparing, ready, localNetworkDenied, fallback, cancelled }

protocol LocalNetworkReadinessSource: AnyObject, Sendable {
    func start(_ receive: @escaping @Sendable (LocalNetworkAccessEvent) -> Void)
    func cancel()
}

private final class LocalNetworkAccessState: @unchecked Sendable {
    enum Decision { case pending, waitingForPermission, proceed, cancelled }
    private let lock = NSLock()
    private var value = Decision.pending
    private var finished = false
    func receive(_ event: LocalNetworkAccessEvent) {
        lock.lock(); defer { lock.unlock() }
        guard !finished else { return }
        switch value { case .proceed, .cancelled: return; default: break }
        switch event {
        case .preparing: break
        case .localNetworkDenied: value = .waitingForPermission
        case .ready, .fallback: value = .proceed
        case .cancelled: value = .cancelled
        }
    }
    func snapshot() -> Decision { lock.lock(); defer { lock.unlock() }; return value }
    func cancel() { lock.lock(); value = .cancelled; finished = true; lock.unlock() }
    func finish() { lock.lock(); finished = true; lock.unlock() }
}

enum LocalNetworkAccess {
    static func wait(for identity: HostIdentity, token: CancellationToken) async throws {
        try token.check()
        let source = NetworkUDPReadinessSource(identity: identity)
        try await wait(source: source, token: token)
    }

    /// Internal source seam covers OS events without resetting a user's privacy settings.
    /// The ordinary probe has a short bound; only an observed policy denial gets a separate
    /// human-response budget. The original TCP timeout starts after this function returns.
    static func wait(source: any LocalNetworkReadinessSource, token: CancellationToken,
                     readinessTimeout: Duration = .seconds(3), permissionTimeout: Duration = .seconds(120)) async throws {
        let state = LocalNetworkAccessState()
        try await withTaskCancellationHandler {
            try token.check()
            let readinessDeadline = ContinuousClock.now + readinessTimeout
            var permissionDeadline: ContinuousClock.Instant?
            defer { state.finish(); source.cancel() }
            source.start { state.receive($0) }
            while true {
                try token.check()
                switch state.snapshot() {
                case .proceed:
                    try token.check(); return
                case .cancelled:
                    throw FileServiceError(.cancelled, operation: "local-network-access")
                case .waitingForPermission:
                    let deadline = permissionDeadline ?? (.now + permissionTimeout)
                    permissionDeadline = deadline
                    guard ContinuousClock.now < deadline else {
                        throw FileServiceError(.timeout, operation: "local-network-access")
                    }
                case .pending:
                    // A UDP preflight cannot diagnose the target server. If it cannot
                    // settle promptly, let the original DNS/TCP path make that decision.
                    if ContinuousClock.now >= readinessDeadline { return }
                }
                do { try await Task.sleep(for: .milliseconds(10)) }
                catch { throw FileServiceError(.cancelled, operation: "local-network-access") }
            }
        } onCancel: {
            token.cancel(); state.cancel(); source.cancel()
        }
    }
}

/// Starting an unsent UDP association lets the OS resolve and check a path, without
/// application UDP payloads, a second TCP connection, an SSH handshake, or credentials.
private final class NetworkUDPReadinessSource: LocalNetworkReadinessSource, @unchecked Sendable {
    private let lock = NSLock()
    private var connection: NWConnection?
    private var stopped = false
    private var started = false
    init(identity: HostIdentity) {
        connection = NWConnection(host: NWEndpoint.Host(identity.address.value),
            port: NWEndpoint.Port(rawValue: identity.port.value)!, using: .udp)
    }
    func start(_ receive: @escaping @Sendable (LocalNetworkAccessEvent) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, !started, let connection else { return }
        started = true
        connection.stateUpdateHandler = { [weak connection] state in
            guard let connection else { return }
            switch state {
            case .setup, .preparing: receive(.preparing)
            case .ready: receive(.ready)
            case .waiting:
                receive(connection.currentPath?.unsatisfiedReason == .localNetworkDenied ? .localNetworkDenied : .fallback)
            case .failed: receive(.fallback)
            case .cancelled: receive(.cancelled)
            @unknown default: receive(.fallback)
            }
        }
        connection.start(queue: DispatchQueue(label: "org.openlxssh.network-access"))
    }
    func cancel() {
        lock.lock()
        stopped = true
        let current = connection; connection = nil
        lock.unlock()
        // A cancelled callback alone is not resource release: remove the handler and
        // the last owned connection reference as well. Late state events are ignored.
        current?.stateUpdateHandler = nil; current?.cancel()
    }
    deinit { cancel() }
}
