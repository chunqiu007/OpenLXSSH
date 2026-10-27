import Darwin
import Foundation
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

@MainActor final class ConcurrentOwner {
    struct Held { let token: SessionToken; let requestID: UUID }
    let input: OpenSSHInput, session: DirectSSHSession, management: OpenSSHManagement
    var budget: OpenSSHAnswerBudget
    private(set) var token: SessionToken?, held: Held?, handler: Task<Void, Never>?, failure: OpenSSHError?
    private(set) var closing = false, released = false, ended = false
    private(set) var connectedEvents = 0, primaryReads = 0, otpReads = 0, successfulSubmissions = 0
    var barrierPID: Int32?, otpPendingUptime: Double?
    init(input: OpenSSHInput, trust: HostTrustStore, sessions: String, helper: BundledAskpassHelper, management: OpenSSHManagement) throws {
        self.input = input; self.management = management
        budget = try OpenSSHAnswerBudget(service: .passwordKbd, primary: .password, primaryHash: ConcurrentPolicy.primaryHash, start: ProcessInfo.processInfo.systemUptime)
        session = DirectSSHSession(trustStore: trust, sessionDirectory: try AbsolutePath(sessions), helper: helper,
                                   scanner: try SystemHostKeyScanner(timeoutSeconds: OpenSSHContract.scanSeconds))
        session.terminal.setHistoryLimit(0)
        session.onStateChange = { [weak self] current, state in
            guard let self, current == self.token, current == self.session.token else { return }
            switch state { case .connected: self.connectedEvents += 1; case .failed, .disconnected: self.ended = true; default: break }
        }
        session.onTrustRequired = { [weak self] _ in self?.fail(.fingerprintMismatch) }
        session.onAuthenticationRequest = { [weak self] token, request in self?.request(token, request) }
    }
    func start(_ configuration: SSHSessionConfiguration) throws {
        guard token == nil, !closing else { throw OpenSSHError.staleRequest }
        token = try session.connect(configuration) // Frozen once; never reconnect in this fixed case.
    }
    private func active(_ current: SessionToken) throws {
        guard !closing, failure == nil, current == token, current == session.token else { throw OpenSSHError.staleRequest }
    }
    private func fail(_ error: OpenSSHError) {
        if failure == nil { failure = error }
        beginClose()
    }
    private func request(_ current: SessionToken, _ request: AuthenticationRequest) {
        do {
            try active(current)
            guard request.session == current.sessionID, request.generation == current.generation, held == nil, handler == nil else { throw OpenSSHError.staleRequest }
            let phase = try budget.claim(id: request.id, prompt: request.prompt, kind: request.kind.rawValue,
                                         hasHint: request.hint != nil, now: ProcessInfo.processInfo.systemUptime)
            if case .otp(_, 0) = phase { held = Held(token: current, requestID: request.id); otpPendingUptime = ProcessInfo.processInfo.systemUptime; return }
            schedule(current, request.id, phase)
        } catch { fail((error as? OpenSSHError) ?? .unknownRequest) }
    }
    private func schedule(_ current: SessionToken, _ id: UUID, _ phase: OpenSSHPhase) {
        handler = Task { @MainActor [self] in
            defer { handler = nil }
            var answer = Data(); defer { answer.resetBytes(in: 0..<answer.count) }
            do {
                try active(current); try Task.checkCancellation()
                switch phase {
                case .primary:
                    primaryReads += 1
                    let input = self.input
                    answer = try await Task.detached { try input.primarySecret() }.value
                case .otp(let identifier, let index):
                    guard released, identifier == budget.sessionID else { throw OpenSSHError.wrongRound }
                    otpReads += 1
                    let management = self.management
                    answer = try await Task.detached { try management.response(session: identifier, index: index).value }.value
                }
                try Task.checkCancellation(); try active(current)
                try budget.consume(id: id, now: ProcessInfo.processInfo.systemUptime)
                try session.respond(.manual(try AuthenticationSecret(answer)), requestID: id, token: current)
                successfulSubmissions += 1
            } catch { if !closing { fail((error as? OpenSSHError) ?? .staleRequest) } }
        }
    }
    func releaseB() throws {
        guard let held, let phase = budget.pendingPhase, case .otp(_, 0) = phase, handler == nil, !released else { throw OpenSSHError.staleRequest }
        try active(held.token)
        released = true; self.held = nil; schedule(held.token, held.requestID, phase)
    }
    func wait(connected: Bool, stop: StopMonitor) async throws {
        var wait = try WaitBudget(start: ProcessInfo.processInfo.systemUptime, seconds: max(0.001, budget.deadline - ProcessInfo.processInfo.systemUptime), maximumTicks: 3000)
        while connected ? (connectedEvents == 0 || handler != nil) : (held == nil || handler != nil) {
            if let failure { throw failure }
            guard !ended, !closing else { throw OpenSSHError.connectionFailed }
            try wait.tick(now: ProcessInfo.processInfo.systemUptime, stopped: stop.requested)
            try await Task.sleep(for: .milliseconds(20))
        }
        if let failure { throw failure }
        try Task.checkCancellation(); guard !stop.requested, !ended, !closing, session.token == token else { throw OpenSSHError.cancelled }
        if connected { guard connectedEvents == 1, session.state == .connected else { throw OpenSSHError.connectionFailed }; try budget.requireComplete() }
    }
    func beginClose() {
        closing = true; held = nil; budget.close(); management.cancel(); handler?.cancel(); session.cancel(); session.closeTab()
    }
    func drain() async throws {
        var wait = try WaitBudget(start: ProcessInfo.processInfo.systemUptime, seconds: OpenSSHContract.drainSeconds, maximumTicks: 600)
        while session.state != .closed || session.ownedProcessID != nil || handler != nil {
            try wait.tick(now: ProcessInfo.processInfo.systemUptime); try await Task.sleep(for: .milliseconds(20))
        }
    }
    var evidence: ConcurrentEvidence {
        ConcurrentEvidence(sessionID: session.sessionID, generation: token?.generation, challengeID: budget.sessionID, barrierPID: barrierPID, otpPendingUptime: otpPendingUptime,
            requests: budget.requests, primaryAnswers: budget.primaryAnswers, otpAnswers: budget.otpAnswers, primaryReads: primaryReads, otpReads: otpReads,
            successfulSubmissions: successfulSubmissions, connectedEvents: connectedEvents, closed: session.state == .closed,
            ownedPIDReleased: session.ownedProcessID == nil, handlerDrained: handler == nil)
    }
}

@MainActor enum ConcurrentCase {
    static func run(a: ConcurrentOwner, b: ConcurrentOwner, configuration: SSHSessionConfiguration, stop: StopMonitor, report: inout ConcurrentReport) async throws {
        try a.start(configuration); try b.start(configuration)
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { @MainActor @Sendable [a, stop] in try await a.wait(connected: false, stop: stop) }
            group.addTask { @MainActor @Sendable [b, stop] in try await b.wait(connected: false, stop: stop) }
            try await group.waitForAll()
        }
        guard let old = a.held, let other = b.held, old.token != other.token, old.token.sessionID != other.token.sessionID,
              old.requestID != other.requestID, let ca = a.budget.sessionID, let cb = b.budget.sessionID, ca != cb,
              let pa = a.session.ownedProcessID, let pb = b.session.ownedProcessID, pa > 0, pb > 0, pa != pb,
              kill(pa, 0) == 0, kill(pb, 0) == 0, a.connectedEvents == 0, b.connectedEvents == 0,
              a.otpReads == 0, b.otpReads == 0, a.handler == nil, b.handler == nil else { throw OpenSSHError.provenanceMismatch }
        a.barrierPID = pa; b.barrierPID = pb; report.simultaneousPending = true; report.barrierUptime = ProcessInfo.processInfo.systemUptime // No await inside pending/PID barrier.
        let submissions = a.successfulSubmissions
        a.beginClose(); try await a.drain(); report.aClosedUptime = ProcessInfo.processInfo.systemUptime
        guard b.held?.requestID == other.requestID, b.token == other.token, b.session.token == other.token,
              b.session.ownedProcessID == pb, kill(pb, 0) == 0, b.failure == nil, !b.ended, !b.closing,
              b.connectedEvents == 0, b.otpReads == 0, b.handler == nil else { throw OpenSSHError.connectionFailed }
        report.bPendingAfterAClose = true
        do {
            try a.session.respond(.cancel, requestID: old.requestID, token: old.token)
            throw OpenSSHError.staleRequest
        } catch let error as TransportError where error == .stale { report.lateReplyRejected = true }
        guard a.session.state == .closed, a.session.ownedProcessID == nil, a.handler == nil,
              a.successfulSubmissions == submissions, a.otpReads == 0 else { throw OpenSSHError.cleanupIncomplete }
        try b.releaseB(); try await b.wait(connected: true, stop: stop); report.bConnectedUptime = ProcessInfo.processInfo.systemUptime
        guard a.connectedEvents == 0, a.primaryReads == 1, a.otpReads == 0, a.successfulSubmissions == 1,
              b.primaryReads == 1, b.otpReads == 3, b.successfulSubmissions == 4 else { throw OpenSSHError.extraRequest }
    }
}
