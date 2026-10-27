import AppKit
import Foundation
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

/// Only the real public production path decides whether the saved-password
/// allowance is eligible. This owner cannot override gate/broker policy.
@MainActor final class SavedPasswordPublicOwner {
    let input: SavedPasswordPublicInput
    let session: DirectSSHSession
    private var budget: SavedPasswordPublicBudget
    private var report: SavedPasswordPublicReport
    private var ended = false
    private var failure: SavedPasswordPublicError?
    private var providerActive = 0
    private var manualTask: Task<Void, Never>?
    init(input: SavedPasswordPublicInput, trust: HostTrustStore, sessions: String, helper: BundledAskpassHelper) throws {
        self.input = input
        budget = SavedPasswordPublicBudget(testCase: input.contract.testCase, manualHash: input.contract.manualPromptSHA256)
        report = SavedPasswordPublicReport(testCase: input.contract.testCase)
        session = DirectSSHSession(trustStore: trust, sessionDirectory: try AbsolutePath(sessions), helper: helper,
                                   scanner: try SystemHostKeyScanner(timeoutSeconds: 15))
        session.terminal.setHistoryLimit(100)
        session.onStateChange = { [weak self] token, state in
            guard let self, token == self.session.token else { return }
            switch state {
            case .connected: self.report.connectedEvents += 1
            case .failed, .disconnected: self.ended = true
            default: break
            }
        }
        session.onTrustRequired = { [weak self] _ in self?.fail(.fingerprintMismatch) }
        session.onAuthenticationRequest = { [weak self] token, request in self?.manual(token: token, request: request) }
    }
    private func isCurrent(_ token: SessionToken) -> Bool {
        !budget.closed && failure == nil && !ended && session.token == token && session.state == .authenticating
    }
    private func fail(_ error: SavedPasswordPublicError) {
        if failure == nil { failure = error }
        budget.fail(error); budget.close(); manualTask?.cancel(); session.cancel()
    }
    private func readPassword() async throws -> Data {
        let input = self.input
        let read = Task.detached { try Task.checkCancellation(); return try input.password() }
        return try await withTaskCancellationHandler { try await read.value } onCancel: { read.cancel() }
    }
    /// No prompt parameter exists in this public API; do not claim hash-based
    /// classification here. The production gate and passwordOnly config control it.
    private func provide(_ token: SessionToken) async -> AuthenticationSecret? {
        providerActive += 1
        defer { providerActive -= 1 }
        do {
            try budget.beginProvider(session: token.sessionID, generation: token.generation, cancelled: Task.isCancelled)
            guard isCurrent(token), !Task.isCancelled else { throw SavedPasswordPublicError.staleGeneration }
            try budget.claimProviderRead(session: token.sessionID, generation: token.generation, cancelled: Task.isCancelled)
            var bytes = try await readPassword()
            defer { bytes.resetBytes(in: 0..<bytes.count) }
            guard isCurrent(token), !Task.isCancelled else { throw SavedPasswordPublicError.staleGeneration }
            let secret = try AuthenticationSecret(bytes)
            try budget.finishProvider(session: token.sessionID, generation: token.generation, cancelled: Task.isCancelled)
            guard isCurrent(token), !Task.isCancelled else { throw SavedPasswordPublicError.staleGeneration }
            return secret
        } catch {
            // No raw error/credential is emitted. Late results never return bytes.
            if !budget.closed { fail((error as? SavedPasswordPublicError) ?? .providerFailed) }
            return nil
        }
    }
    private func manual(token: SessionToken, request: AuthenticationRequest) {
        do {
            guard token == session.token, request.session == token.sessionID, request.generation == token.generation,
                  isCurrent(token), manualTask == nil else { throw SavedPasswordPublicError.staleGeneration }
            try budget.claimManual(id: request.id, session: token.sessionID, generation: token.generation,
                prompt: request.prompt, kind: request.kind.rawValue, hasHint: request.hint != nil)
            // Authorized mode fails gateNotCovered in claimManual BEFORE any read;
            // only the separately declared no-authorization case can get here.
            manualTask = Task { @MainActor [weak self] in
                guard let self else { return }
                defer { self.manualTask = nil }
                do {
                    guard self.isCurrent(token), !Task.isCancelled else { throw SavedPasswordPublicError.staleGeneration }
                    var bytes = try await self.readPassword()
                    defer { bytes.resetBytes(in: 0..<bytes.count) }
                    guard self.isCurrent(token), !Task.isCancelled else { throw SavedPasswordPublicError.staleGeneration }
                    try self.budget.finishManual(id: request.id, session: token.sessionID, generation: token.generation, cancelled: Task.isCancelled)
                    try self.session.respond(.manual(try AuthenticationSecret(bytes)), requestID: request.id, token: token)
                } catch { self.fail((error as? SavedPasswordPublicError) ?? .providerFailed) }
            }
        } catch { fail((error as? SavedPasswordPublicError) ?? .unknownManualRequest) }
    }
    func run(configuration: SSHSessionConfiguration, stop: StopMonitor, processDeadline: Double) async -> SavedPasswordPublicReport {
        do {
            let token: SessionToken
            if input.contract.testCase == .authorized {
                let authorization = SavedPasswordAuthorization(provider: { [weak self] current in
                    guard let self else { return nil }
                    return await self.provide(current)
                })
                token = try session.connect(configuration, savedPassword: authorization)
            } else {
                token = try session.connect(configuration) // Deliberately NO authorization/provider.
            }
            try budget.bind(session: token.sessionID, generation: token.generation)
            let deadline = min(ProcessInfo.processInfo.systemUptime + SavedPasswordPublicContract.activeSeconds,
                               processDeadline - SavedPasswordPublicContract.drainSeconds)
            for _ in 0..<1200 {
                if report.connectedEvents > 0 || ended || failure != nil { break }
                guard !stop.requested else { throw SavedPasswordPublicError.cancelled }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw SavedPasswordPublicError.timeout }
                try await Task.sleep(for: .milliseconds(50))
            }
            if let failure { throw failure }
            guard !ended, providerActive == 0, manualTask == nil else { throw SavedPasswordPublicError.connectionFailed }
            try budget.requireExpected(connectedEvents: report.connectedEvents)
            report.productionGateExercised = input.contract.testCase == .authorized
            report.result = input.contract.testCase == .authorized ? "expected-public-provider-connected" : "expected-no-authorization-manual-connected"
        } catch { report.failure = (error as? SavedPasswordPublicError) ?? .connectionFailed }
        budget.close(); manualTask?.cancel(); session.cancel(); session.closeTab()
        do {
            let deadline = min(processDeadline, ProcessInfo.processInfo.systemUptime + SavedPasswordPublicContract.drainSeconds)
            for _ in 0..<600 {
                if session.state == .closed && session.ownedProcessID == nil && providerActive == 0 && manualTask == nil { break }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw SavedPasswordPublicError.cleanupIncomplete }
                try await Task.sleep(for: .milliseconds(20))
            }
            guard session.state == .closed, session.ownedProcessID == nil, providerActive == 0, manualTask == nil else { throw SavedPasswordPublicError.cleanupIncomplete }
            report.closeCompleted = true; report.ownedPIDReleased = true; report.providerAndManualTasksDrained = true
        } catch { report.failure = .cleanupIncomplete }
        report.record(budget); report.exitCode = session.lastExitCode
        if report.failure != nil { report.result = "failed" }
        return report
    }
}
