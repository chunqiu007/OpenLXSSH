#if HOST_PROBE
import AppKit
import Foundation
import OpenLXSSHCore
import OpenLXSSHTransport
import OpenLXSSHTrust

/// Public-key-only observation substitute: the real DirectSSHSession stops at
/// awaitingTrust, so no ssh/keyscan socket or arbitrary process is launched.
struct OfflineCandidateScanner: HostKeyScanning {
    func scan(_ host: HostIdentity) async throws -> [HostKeyCandidate] {
        try SystemHostKeyScanner.parse(Data((host.knownHostsName + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFhJwF6sPz9bZWdnLdkV1FY9JSt0XgTDbZd7ABl6KQSr\n").utf8), for: host)
    }
}

/// Explicit GUI logic substitute: never starts SSH, scans a network or claims interoperability.
@MainActor final class ProbeSessionBuilder: SessionBuilding {
    let repository: any AppRepositoryProtocol
    private(set) var drivers: [ProbeSessionDriver] = []
    init(repository: any AppRepositoryProtocol) { self.repository = repository }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        guard let host = try await repository.securityMetadata().hosts.first(where: { $0.id == hostID }) else { throw RepositoryError.notFound }
        return (host, try SessionEnvironment.configuration(host: host, keyPath: nil))
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        let (host, configuration) = try await configuration(hostID: hostID)
        let driver = ProbeSessionDriver(id: sessionID); drivers.append(driver)
        return ReadySession(host: host, configuration: configuration, driver: driver)
    }
}
@MainActor final class ProbeSessionDriver: SessionDriving {
    let id: UUID
    let terminal = NativeTerminalView()
    private(set) var token: SessionToken?
    private(set) var state: SSHSessionState = .idle
    var canReconnect: Bool { switch state { case .idle, .disconnected, .failed: true; default: false } }
    var onState: ((SessionToken?, SSHSessionState) -> Void)?
    var onTrust: (([SessionTrustPrompt]) -> Void)?
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)?
    var configuration: SSHSessionConfiguration?
    var responseCount = 0
    var closeDelay: Duration = .zero
    var closeCompletion: (() -> Void)?
    var closeDidStart: (() -> Void)?
    var holdClose = false
    private var closeContinuation: CheckedContinuation<Void, Never>?
    private var closeStarted = false
    init(id: UUID) { self.id = id }
    func connect(_ configuration: SSHSessionConfiguration, savedPassword: SavedPasswordAuthorization?) throws -> SessionToken {
        let token = SessionToken(sessionID: id, generation: (self.token?.generation ?? 0) + 1)
        self.token = token; self.configuration = configuration
        state = .connectionPending; onState?(token, state)
        terminal.feed(text: "GUI logic substitute only — not SSH interoperability\r\n")
        return token
    }
    func showTrust() {
        guard let token, let configuration else { return }
        state = .awaitingTrust; onState?(token, state)
        onTrust?([SessionTrustPrompt(token: token, id: UUID(), host: configuration.connection.host, algorithm: "ssh-ed25519",
            fingerprint: "SHA256:GUI-FIXTURE-NOT-A-SERVER", source: "逻辑替身，无网络预扫，不证明身份", transport: nil)])
    }
    func showAuthentication(kind: AuthenticationChallengeKind = .unknownMasked) {
        guard let token else { return }
        state = .authenticating; onState?(token, state)
        onAuthentication?(SessionAuthenticationPrompt(token: token, id: UUID(), kind: kind,
            text: SafePrompt.display("Fixture unknown challenge\u{1B}[31m\u{202E} https://untrusted.invalid/ — no remembered answer")))
    }
    func accept(_ prompt: SessionTrustPrompt) async throws {
        guard token == prompt.token, state == .awaitingTrust else { throw TransportError.stale }
        state = .connectionPending; onState?(token, state)
    }
    func respond(_ response: AuthenticationResponse, to prompt: SessionAuthenticationPrompt) throws {
        guard token == prompt.token, state == .authenticating else { throw TransportError.stale }
        responseCount += 1; state = .connectionPending; onState?(token, state)
    }
    func cancel() { state = .disconnected(nil); onState?(token, state) }
    func closeTab() {
        guard !closeStarted else { return }; closeStarted = true
        state = .closing; onState?(token, state)
        Task {
            if holdClose {
                await withCheckedContinuation { continuation in
                    closeContinuation = continuation
                    closeDidStart?()
                }
            } else {
                closeDidStart?()
                try? await Task.sleep(for: closeDelay)
            }
            state = .closed; terminal.releaseResources(); onState?(token, state); closeCompletion?()
        }
    }
    func releaseClose() {
        holdClose = false
        let continuation = closeContinuation; closeContinuation = nil; continuation?.resume()
    }
}
#endif
