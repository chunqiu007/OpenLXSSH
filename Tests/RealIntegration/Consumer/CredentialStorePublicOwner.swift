import AppKit
import Foundation
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

/// Real public saved-password path, sourcing its one returned secret only from
/// the exact freshly saved test reference. No fixture-file fallback or Keychain
/// enumeration, test eligibility override, prompt parsing or automatic retry.
@MainActor final class CredentialStorePublicOwner {
    let session: DirectSSHSession
    private let store: CredentialStore
    private let reference: OpenLXSSHSecurity.CredentialReference
    private let stopGuard: CredentialStorePublicStopGuard
    private var budget = SavedPasswordPublicBudget(testCase: .authorized, manualHash: nil)
    private var active = 0
    private var connected = 0
    private var manualRequests = 0
    private var ended = false
    private var failure: CredentialStorePublicError?
    private(set) var credentialFailure: CredentialStorePublicFailure?
    init(store: CredentialStore, reference: OpenLXSSHSecurity.CredentialReference, trust: HostTrustStore, sessions: String,
         helper: BundledAskpassHelper, stopGuard: CredentialStorePublicStopGuard) throws {
        self.store = store; self.reference = reference; self.stopGuard = stopGuard
        session = DirectSSHSession(trustStore: trust, sessionDirectory: try AbsolutePath(sessions), helper: helper,
                                   scanner: try SystemHostKeyScanner(timeoutSeconds: 15))
        session.terminal.setHistoryLimit(100)
        session.onStateChange = { [weak self] token, state in
            guard let self, token == self.session.token else { return }
            switch state { case .connected: self.connected += 1; case .failed, .disconnected: self.ended = true; default: break }
        }
        session.onTrustRequired = { [weak self] _ in self?.fail(.invalidContract) }
        session.onAuthenticationRequest = { [weak self] _, _ in self?.manualFallback() }
    }
    private func current(_ token: SessionToken) -> Bool {
        (try? stopGuard.check()) != nil && !budget.closed && failure == nil && !ended && session.token == token && session.state == .authenticating
    }
    private func fail(_ reason: CredentialStorePublicError) {
        if failure == nil { failure = reason }; budget.close(); session.cancel()
    }
    private func manualFallback() {
        manualRequests += 1
        do { try stopGuard.check(); fail(.gateNotCovered) }
        catch { fail(CredentialStorePublicErrorMap.classify(error, fallback: .gateNotCovered)) }
    } // NO credential read or manual answer.
    private func provide(_ token: SessionToken) async -> AuthenticationSecret? {
        active += 1; defer { active -= 1 }
        do {
            try stopGuard.check()
            try budget.beginProvider(session: token.sessionID, generation: token.generation, cancelled: Task.isCancelled)
            try stopGuard.checkCurrent(current(token))
            try budget.claimProviderRead(session: token.sessionID, generation: token.generation, cancelled: Task.isCancelled)
            let result = try await stopGuard.checkedValue { await store.read(reference) } // Exact reference, stop checked before/after await.
            try stopGuard.checkCurrent(current(token))
            let secret: AuthenticationSecret
            switch result {
            case .available(let stored): secret = try stored.withUnsafeBytes { try AuthenticationSecret(Data($0)) }
            case .missing: throw CredentialStorePublicError.credentialReadFailed
            case .manualEntryRequired(let reason):
                credentialFailure = CredentialStorePublicStatus.failure(reason)
                throw CredentialStorePublicError.credentialReadFailed
            }
            try stopGuard.checkCurrent(current(token))
            try budget.finishProvider(session: token.sessionID, generation: token.generation, cancelled: Task.isCancelled)
            try stopGuard.checkCurrent(current(token))
            return secret
        } catch {
            if !budget.closed { fail(CredentialStorePublicErrorMap.classify(error, fallback: .credentialReadFailed)) }
            return nil
        }
    }
    func run(configuration: SSHSessionConfiguration, deadline: Double, report: inout CredentialStorePublicReport) async {
        do {
            try stopGuard.check()
            let authorization = SavedPasswordAuthorization(provider: { [weak self] token in
                guard let self else { return nil }; return await self.provide(token)
            })
            let token = try session.connect(configuration, savedPassword: authorization)
            try budget.bind(session: token.sessionID, generation: token.generation)
            let authDeadline = min(deadline - CredentialStorePublicContract.drainSeconds, ProcessInfo.processInfo.systemUptime + CredentialStorePublicContract.activeSeconds)
            for _ in 0..<1200 {
                try stopGuard.check()
                if connected > 0 || ended || failure != nil { break }
                guard ProcessInfo.processInfo.systemUptime < authDeadline else { throw CredentialStorePublicError.timeout }
                try await Task.sleep(for: .milliseconds(50))
            }
            try stopGuard.check()
            if let failure { throw failure }
            guard !ended, active == 0 else { throw CredentialStorePublicError.connectionFailed }
            try budget.requireExpected(connectedEvents: connected)
            try stopGuard.check()
            report.productionGateExercised = true
        } catch { report.failure = CredentialStorePublicErrorMap.classify(error, fallback: .connectionFailed) }
        budget.close(); session.cancel(); session.closeTab()
        do {
            let drain = min(deadline, ProcessInfo.processInfo.systemUptime + CredentialStorePublicContract.drainSeconds)
            for _ in 0..<600 {
                if session.state == .closed && session.ownedProcessID == nil && active == 0 { break }
                guard ProcessInfo.processInfo.systemUptime < drain else { throw CredentialStorePublicError.cleanupIncomplete }
                try await Task.sleep(for: .milliseconds(20))
            }
            guard session.state == .closed, session.ownedProcessID == nil, active == 0 else { throw CredentialStorePublicError.cleanupIncomplete }
            report.closeCompleted = true; report.ownedPIDReleased = true; report.providerTasksDrained = true
        } catch { report.failure = .cleanupIncomplete }
        report.connectedEvents = connected; report.providerCalls = budget.providerCalls
        do { try stopGuard.check() }
        catch { report.failure = CredentialStorePublicErrorMap.classify(error, fallback: .cancelled); report.productionGateExercised = false }
        report.providerReadCount = budget.providerSecretReads; report.providerReturns = budget.providerReturns
        report.manualRequests = manualRequests
        report.credentialFailure = credentialFailure
    }
}
