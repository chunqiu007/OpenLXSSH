import AppKit
import Foundation
import Darwin
import SwiftTerm
import OpenLXSSHTrust
import OpenLXSSHAskpass

public struct SessionTrustChallenge: Equatable, Sendable {
    public let token: SessionToken
    public let candidate: HostKeyCandidate
    public let decision: PendingTrustDecision
}

/// One retained instance per tab, one new LocalProcess per explicit connection.
/// Output survives disconnect/cancel and is released only with closeTab().
@MainActor
public final class DirectSSHSession: NSObject, @MainActor TerminalViewDelegate {
    public let sessionID: UUID
    public let terminal: NativeTerminalView
    public private(set) var token: SessionToken?
    public private(set) var state: SSHSessionState = .idle
    public private(set) var trustChallenges: [SessionTrustChallenge] = []
    public private(set) var lastExitCode: Int32?
    public private(set) var inputError: TransportError?
    public var onStateChange: ((SessionToken?, SSHSessionState) -> Void)?
    public var onTrustRequired: (([SessionTrustChallenge]) -> Void)?
    public var onAuthenticationRequest: ((SessionToken, AuthenticationRequest) -> Void)?
    public var onOutput: ((SessionToken) -> Void)?

    private let trustStore: HostTrustStore
    private let sessionDirectory: AbsolutePath
    private let helper: BundledAskpassHelper?
    private let scanner: any HostKeyScanning
    private var configuration: SSHSessionConfiguration?
    private var preparation: Task<Void, Never>?
    private var preflightCandidates: [HostKeyCandidate] = []
    private var runner: PTYGeneration?
    private var broker: AskpassBroker?
    private var workspace: SessionWorkspace?
    private var tabClosed = false
    private var cancellationRequested = false
    private var failureAfterCleanup: SessionFailure?
    private var trustOperationActive = false
    private var connectionMutationActive = false
    private var savedPassword: SavedPasswordAuthorization?
    private var passwordBudget = SavedPasswordBudget(eligible: false)
    private var automaticAnswerTask: Task<Void, Never>?

    public init(sessionID: UUID = UUID(), trustStore: HostTrustStore, sessionDirectory: AbsolutePath,
                helper: BundledAskpassHelper, scanner: any HostKeyScanning) {
        self.sessionID = sessionID; self.trustStore = trustStore; self.sessionDirectory = sessionDirectory
        self.helper = helper; self.scanner = scanner; terminal = NativeTerminalView()
        super.init(); terminal.terminalDelegate = self
    }
    // Not public: only the host verification executable can instantiate without
    // a signed bundled helper. No arbitrary PID/launch adoption in the public API.
    package init(probeStore: HostTrustStore, directory: AbsolutePath, scanner: any HostKeyScanning) {
        sessionID = UUID(); trustStore = probeStore; sessionDirectory = directory
        helper = nil; self.scanner = scanner; terminal = NativeTerminalView()
        super.init(); terminal.terminalDelegate = self
    }
    public var ownedProcessID: pid_t? { runner.map { $0.pid } }
    public var pendingInputBytes: Int { runner?.pendingInputBytes ?? 0 }
    public var canReconnect: Bool {
        guard !tabClosed, runner == nil, preparation == nil, !trustOperationActive, !connectionMutationActive else { return false }
        switch state { case .idle, .disconnected, .failed: return true; default: return false }
    }
    @discardableResult
    public func connect(_ configuration: SSHSessionConfiguration, savedPassword: SavedPasswordAuthorization? = nil) throws -> SessionToken {
        guard !tabClosed else { throw TransportError.closed }
        guard canReconnect, (token?.generation ?? 0) < UInt64.max else { throw TransportError.busy }
        connectionMutationActive = true
        defer { connectionMutationActive = false }
        let next = SessionToken(sessionID: sessionID, generation: (token?.generation ?? 0) + 1)
        token = next; self.configuration = configuration; self.savedPassword = savedPassword
        passwordBudget = SavedPasswordBudget(eligible: false); lastExitCode = nil; inputError = nil
        cancellationRequested = false; failureAfterCleanup = nil
        preflightCandidates = []; trustChallenges = []
        setState(.preparing)
        // This task is kept through cancellation until in-flight scanner and
        // store operations complete. New generations cannot overtake a write.
        preparation = Task { [weak self] in await self?.prepare(next) }
        return next
    }
    @discardableResult
    public func reconnect(savedPassword: SavedPasswordAuthorization? = nil) throws -> SessionToken {
        guard let configuration else { throw TransportError.invalidConfiguration }
        return try connect(configuration, savedPassword: savedPassword)
    }
    private func prepare(_ current: SessionToken) async {
        defer {
            if token == current {
                preparation = nil
                if cancellationRequested, runner == nil { completeCancellation() }
            }
        }
        do {
            guard let configuration, isCurrent(current) else { return }
            // Scanning and key validation must never monopolize the UI actor,
            // including an injected scanner that has synchronous local work.
            let scanner = scanner
            let scan = Task.detached { try await scanner.scan(configuration.connection.host) }
            let candidates = try await withTaskCancellationHandler { try await scan.value } onCancel: { scan.cancel() }
            guard isCurrent(current), !Task.isCancelled else { return }
            guard !candidates.isEmpty, candidates.count <= 5,
                  candidates.allSatisfy({ $0.host == configuration.connection.host }) else { throw HostScanError.invalidOutput }
            preflightCandidates = candidates
            try await evaluateTrust(current)
        } catch {
            guard isCurrent(current) else { return }
            savedPassword = nil
            setState(.failed((error as? SessionFailure) ?? .trustScanFailed))
        }
    }
    private func evaluateTrust(_ current: SessionToken) async throws {
        let old = trustChallenges; trustChallenges = []
        for challenge in old { await trustStore.cancel(challenge.decision) }
        var trusted = [HostPublicKey](), pending = [SessionTrustChallenge]()
        do {
            for candidate in preflightCandidates {
                guard isCurrent(current) else { throw TransportError.stale }
                let result = try await trustStore.evaluate(host: candidate.host, key: candidate.key)
                guard isCurrent(current) else {
                    if case .pending(let decision) = result { await trustStore.cancel(decision) }
                    throw TransportError.stale
                }
                switch result {
                case .trusted(let record): trusted.append(record.key)
                case .pending(let decision): pending.append(SessionTrustChallenge(token: current, candidate: candidate, decision: decision))
                case .rejected: throw SessionFailure.trustRejected
                }
            }
        } catch {
            for challenge in pending { await trustStore.cancel(challenge.decision) }
            throw error
        }
        guard isCurrent(current) else { return }
        // An already trusted algorithm is sufficient. Never silently add another
        // algorithm from keyscan. Actual handshake is pinned to trusted only.
        if !trusted.isEmpty {
            for challenge in pending { await trustStore.cancel(challenge.decision) }
            try await launch(current, keys: trusted)
        } else {
            trustChallenges = pending; setState(.awaitingTrust); onTrustRequired?(pending)
        }
    }
    public func acceptTrust(_ challenge: SessionTrustChallenge, displayedFingerprint: String) async throws {
        guard state == .awaitingTrust, isCurrent(challenge.token), trustChallenges.contains(challenge), preparation == nil, !trustOperationActive else { throw TransportError.stale }
        trustOperationActive = true
        defer {
            trustOperationActive = false
            if cancellationRequested, runner == nil { completeCancellation() }
        }
        // Move out of awaitingTrust before suspension; a second UI answer cannot
        // race. Store confirm consumes the token on every attempted answer.
        setState(.preparing)
        guard isCurrent(challenge.token) else { throw TransportError.stale }
        do {
            _ = try await trustStore.confirm(challenge.decision, displayedFingerprint: displayedFingerprint)
            guard isCurrent(challenge.token) else { throw TransportError.stale }
            try await evaluateTrust(challenge.token)
        } catch {
            if isCurrent(challenge.token) { savedPassword = nil; setState(.failed((error as? SessionFailure) ?? .trustRejected)) }
            throw error
        }
    }
    private func launch(_ current: SessionToken, keys: [HostPublicKey]) async throws {
        guard let configuration, let helper, isCurrent(current) else { throw TransportError.invalidConfiguration }
        let compatible = await PasswordAutomationGate.evaluate()
        guard isCurrent(current) else { throw TransportError.stale }
        passwordBudget = SavedPasswordBudget(eligible: compatible && savedPassword != nil && configuration.authentication.method == .passwordOnly)
        let trustStore = trustStore, root = sessionDirectory
        let workspace = try await Task.detached {
            let controlled = try DirectSSHConfiguration(configuration: configuration, trustStore: trustStore, trustedKeys: keys, helper: helper)
            try TransportFileSecurity.validateAuthentication(configuration.authentication)
            return try SessionWorkspace(root: root, text: controlled.text)
        }.value
        guard isCurrent(current) else { throw TransportError.stale }
        let broker = try AskpassBroker(token: current)
        var invocation = workspace.invocation()
        invocation = DirectSSHInvocation(executable: invocation.executable, arguments: invocation.arguments,
            environment: invocation.environment.merging(broker.environment(helper: helper), uniquingKeysWith: { _, new in new }))
        self.workspace = workspace; self.broker = broker
        broker.onAuthenticated = { [weak self] in
            guard let self, self.isCurrent(current) else { return }
            self.savedPassword = nil; self.automaticAnswerTask?.cancel(); self.automaticAnswerTask = nil
            self.setState(.connected)
        }
        broker.onRequest = { [weak self] request in
            guard let self, self.isCurrent(current) else { return }
            self.handleAuthenticationRequest(request, token: current)
        }
        broker.onFailure = { [weak self] error in
            guard let self, self.isCurrent(current) else { return }
            if error == .cancelled { self.cancel() }
            else { self.stop(failure: error == .timeout ? .authenticationTimeout : .authenticationFailed) }
        }
        do {
            // No suspension between this final metadata/ACL check and spawning
            // the sole SwiftTerm-owned PTY process. This reduces, but cannot
            // eliminate, pathname races from another process with the same UID.
            try workspace.validateForLaunch(authentication: configuration.authentication)
            try startOwned(current, invocation: invocation, directory: workspace.directory) { pid in try broker.registerCreatedProcess(pid) }
        } catch {
            broker.close(); self.broker = nil
            if runner != nil { stop(failure: .launchFailed) } else { self.workspace = nil }
            throw error
        }
    }
    private func handleAuthenticationRequest(_ request: AuthenticationRequest, token current: SessionToken) {
        setState(.authenticating)
        guard isCurrent(current) else { return }
        guard passwordBudget.claim(request), let authorization = savedPassword else {
            // Any first request disqualifying the one-time allowance also drops
            // the provider; later password-change/OTP requests stay manual.
            savedPassword = nil
            onAuthenticationRequest?(current, request); return
        }
        savedPassword = nil // consume before awaiting; never retry automatically
        automaticAnswerTask = Task { [weak self] in
            var answer: AuthenticationSecret?
            do { answer = try await authorization.provider(current) } catch { answer = nil }
            guard let self, self.isCurrent(current), !Task.isCancelled else { return }
            self.automaticAnswerTask = nil
            if let answer {
                do { try self.respond(.manual(answer), requestID: request.id, token: current) }
                catch { /* broker has already invalidated/cancelled this request */ }
            } else { self.onAuthenticationRequest?(current, request) }
        }
    }
    private func startOwned(_ current: SessionToken, invocation: DirectSSHInvocation, directory: String,
                            register: (pid_t) throws -> Void = { _ in }) throws {
        let generation = PTYGeneration(token: current)
        generation.dimensions = { [weak self] in
            winsize(ws_row: UInt16(clamping: self?.terminal.rows ?? 24), ws_col: UInt16(clamping: self?.terminal.columns ?? 80), ws_xpixel: 0, ws_ypixel: 0)
        }
        generation.onOutput = { [weak self] token, bytes in self?.receive(bytes, token: token) }
        generation.onExit = { [weak self] result in self?.processEnded(result) }
        generation.onInputFailure = { [weak self] in self?.stop(failure: .inputFailed) }
        runner = generation
        do { try generation.start(invocation, directory: directory); try register(generation.pid) }
        catch {
            if generation.pid > 0 { generation.cancel() } else { runner = nil }
            throw error
        }
        // Start success is NEVER proof of host authentication.
        setState(.connectionPending)
    }
    private func receive(_ bytes: ArraySlice<UInt8>, token current: SessionToken) {
        guard isCurrent(current) else { return }
        terminal.feed(byteArray: bytes); onOutput?(current)
    }
    private func processEnded(_ result: PTYResult) {
        guard token == result.token else { return }
        broker?.close(.parentExited); broker = nil; runner = nil; workspace = nil
        automaticAnswerTask?.cancel(); automaticAnswerTask = nil; savedPassword = nil
        lastExitCode = result.exitCode
        if cancellationRequested { completeCancellation() }
        else if let failureAfterCleanup { setState(.failed(failureAfterCleanup)) }
        else if result.exitCode == 0 { setState(.disconnected(0)) }
        else { setState(.failed(.launchFailed)) }
    }
    public func respond(_ response: AuthenticationResponse, requestID: UUID, token: SessionToken) throws {
        guard isCurrent(token), let broker else { throw TransportError.stale }
        try broker.submit(response, requestID: requestID, token: token)
        if isCurrent(token), state == .authenticating { setState(.connectionPending) }
    }
    public func sendInput(_ data: Data) throws {
        guard let runner, !tabClosed else { throw TransportError.inactive }
        do { try runner.enqueue(Array(data)[...]) }
        catch let failure as TransportError { inputError = failure; throw failure }
    }
    /// Disconnect without removing the tab or its in-memory output.
    public func cancel() { stop(failure: nil) }
    /// Permanent terminal disposal; not used by tab switching/minimize/hide.
    public func closeTab() {
        guard !tabClosed else { return }; tabClosed = true
        stop(failure: nil); terminal.terminalDelegate = nil; terminal.releaseResources()
        onOutput = nil; onAuthenticationRequest = nil; onTrustRequired = nil
    }
    private func stop(failure: SessionFailure?) {
        if state == .closed { return }
        cancellationRequested = failure == nil; failureAfterCleanup = failure
        setState(.closing)
        preparation?.cancel(); automaticAnswerTask?.cancel(); automaticAnswerTask = nil; savedPassword = nil
        let stale = trustChallenges; trustChallenges = []
        if !stale.isEmpty { Task { [trustStore] in for challenge in stale { await trustStore.cancel(challenge.decision) } } }
        broker?.close(); broker = nil
        if let runner { runner.cancel() }
        else if preparation == nil, !trustOperationActive { completeCancellation() }
    }
    private func completeCancellation() {
        workspace = nil
        if tabClosed { setState(.closed) }
        else if let failureAfterCleanup { setState(.failed(failureAfterCleanup)) }
        else { setState(.disconnected(nil)) }
    }
    private func isCurrent(_ current: SessionToken) -> Bool {
        token == current && !tabClosed && !cancellationRequested && state != .closing && state != .closed
    }
    private func setState(_ next: SSHSessionState) { state = next; onStateChange?(token, next) }

    public func send(source: TerminalView, data: ArraySlice<UInt8>) {
        guard let runner else { return }
        do { try runner.enqueue(data) } catch { inputError = (error as? TransportError) ?? .inactive; NSSound.beep() }
    }
    public func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
        var size = winsize(ws_row: UInt16(clamping: newRows), ws_col: UInt16(clamping: newCols), ws_xpixel: 0, ws_ypixel: 0)
        runner?.resize(&size)
    }
    public func setTerminalTitle(source: TerminalView, title: String) {}
    public func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    public func scrolled(source: TerminalView, position: Double) {}
    public func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    public func clipboardRead(source: TerminalView) -> Data? { nil }
    public func clipboardCopy(source: TerminalView, content: Data) {}
    public func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {}

    deinit {
        preparation?.cancel(); automaticAnswerTask?.cancel()
        let view = terminal
        Task { @MainActor in view.terminalDelegate = nil; view.releaseResources() }
        // runner and broker deinit revoke rights and invoke the sole upstream
        // PID-safe reaper even if the tab owner forgot closeTab().
    }
    #if TRANSPORT_HOST_PROBE
    /// Compiled out of the default macOS 26 package; no production arbitrary
    /// executable/PID adoption. Used for real local PTY and system readpass tests.
    package func startProbe(_ invocation: DirectSSHInvocation, directory: String, broker probeBroker: AskpassBroker? = nil) throws -> SessionToken {
        guard canReconnect, !tabClosed else { throw TransportError.busy }
        let current = SessionToken(sessionID: sessionID, generation: (token?.generation ?? 0) + 1)
        token = current; cancellationRequested = false; failureAfterCleanup = nil
        self.broker = probeBroker
        probeBroker?.onAuthenticated = { [weak self] in
            guard let self, self.isCurrent(current) else { return }; self.setState(.connected)
        }
        try startOwned(current, invocation: invocation, directory: directory) { pid in try probeBroker?.registerCreatedProcess(pid) }
        return current
    }
    package func configureProbeSavedPassword(_ authorization: SavedPasswordAuthorization, eligible: Bool) {
        savedPassword = authorization; passwordBudget = SavedPasswordBudget(eligible: eligible)
        let current = token!
        broker?.onRequest = { [weak self] request in self?.handleAuthenticationRequest(request, token: current) }
    }
    package func deliverProbeOutput(_ data: Data, token: SessionToken) { receive(Array(data)[...], token: token) }
    #endif
}
