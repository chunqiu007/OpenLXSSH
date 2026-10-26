#if HOST_PROBE
import AppKit
import Foundation
import OpenLXSSHCore
import OpenLXSSHTransport
import OpenLXSSHTrust
import SwiftTerm

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
    private(set) var drivers: [ProbeWeakDriver] = []
    init(repository: any AppRepositoryProtocol) { self.repository = repository }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        guard let host = try await repository.securityMetadata().hosts.first(where: { $0.id == hostID }) else { throw RepositoryError.notFound }
        return (host, try SessionEnvironment.configuration(host: host, keyPath: nil))
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        let (host, configuration) = try await configuration(hostID: hostID)
        let driver = ProbeSessionDriver(id: sessionID); drivers.append(ProbeWeakDriver(driver))
        return ReadySession(host: host, configuration: configuration, driver: driver)
    }
}
@MainActor final class ProbeWeakDriver {
    weak var value: ProbeSessionDriver?
    init(_ value: ProbeSessionDriver) { self.value = value }
}
@MainActor final class ProbeTerminalMetrics {
    var fedBytes: UInt64 = 0
    var fedBatches = 0
    var hiddenBatches = 0
    var input = Data()
    var resizeEvents = 0
    var closeCount = 0
    var disposedCount = 0
}
@MainActor final class ProbeSessionDriver: SessionDriving, TerminalViewDelegate {
    let id: UUID
    let terminal = NativeTerminalView()
    let terminalMetrics = ProbeTerminalMetrics()
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
    init(id: UUID) { self.id = id; terminal.terminalDelegate = self }
    func feedPressure(_ bytes: Data) throws {
        guard state == .connectionPending, !closeStarted, bytes.count <= 16384 else { throw TransportError.invalidConfiguration }
        terminal.feed(byteArray: [UInt8](bytes)[...])
        terminalMetrics.fedBytes += UInt64(bytes.count); terminalMetrics.fedBatches += 1
        if terminal.isHidden { terminalMetrics.hiddenBatches += 1 }
    }
    func send(source: TerminalView, data: ArraySlice<UInt8>) {
        guard !closeStarted, terminalMetrics.input.count + data.count <= TerminalSettings.maximumInputBytes else { return }
        terminalMetrics.input.append(contentsOf: data)
    }
    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) { terminalMetrics.resizeEvents += 1 }
    func setTerminalTitle(source: TerminalView, title: String) {}
    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    func scrolled(source: TerminalView, position: Double) {}
    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {}
    func bell(source: TerminalView) {}
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
        guard !closeStarted else { return }; closeStarted = true; terminalMetrics.closeCount += 1
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
            state = .closed; terminal.terminalDelegate = nil; terminal.releaseResources()
            if terminal.updateUiClosed() { terminalMetrics.disposedCount += 1 }
            onState?(token, state); closeCompletion?()
        }
    }
    func releaseClose() {
        holdClose = false
        let continuation = closeContinuation; closeContinuation = nil; continuation?.resume()
    }
}
struct ProbeOutputLoad {
    static let viewCount = 5
    static let batches = 200
    static let intervalMilliseconds = 40
    static let historyLines = 10000
    static let maximumBatchBytes = 8192
    static func marker(view: Int) -> String { "P7-END-V\(view)-000199" }
    static func batch(view: Int, index: Int) -> Data {
        precondition((0..<viewCount).contains(view) && (0..<batches).contains(index))
        let line = String(format: "V%d-B%06d ", view, index) + "中文 e\u{301} output " + String(repeating: "0123456789abcdef", count: 8)
        var text = String(repeating: "\u{1b}[32m" + line + "\u{1b}[0m\r\n", count: 24)
        text += "status old\r\u{1b}[2Kstatus replaced V\(view)-\(index)\r\n"
        if index == batches - 1 { text += marker(view: view) + "\r\n" }
        let bytes = Data(text.utf8)
        precondition(bytes.count <= maximumBatchBytes)
        return bytes
    }
}
#endif
