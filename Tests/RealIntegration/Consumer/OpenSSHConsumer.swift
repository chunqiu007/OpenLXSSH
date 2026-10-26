import AppKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

@MainActor final class OpenSSHCaseOwner {
    let input: OpenSSHInput
    let session: DirectSSHSession
    let management: OpenSSHManagement
    var budget: OpenSSHAnswerBudget
    var report: OpenSSHReport
    var failure: OpenSSHError?
    var ended = false
    var handler: Task<Void, Never>?
    init(input: OpenSSHInput, trust: HostTrustStore, sessions: String, helper: BundledAskpassHelper, management: OpenSSHManagement) throws {
        self.input = input; self.management = management
        budget = try OpenSSHAnswerBudget(service: input.contract.service, primary: input.contract.primary,
                                         primaryHash: input.contract.primaryPromptSHA256, start: ProcessInfo.processInfo.systemUptime)
        report = OpenSSHReport(contract: input.contract)
        session = DirectSSHSession(trustStore: trust, sessionDirectory: try AbsolutePath(sessions), helper: helper,
                                   scanner: try SystemHostKeyScanner(timeoutSeconds: OpenSSHContract.scanSeconds))
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
        session.onAuthenticationRequest = { [weak self] token, request in self?.request(token: token, request: request) }
    }
    private func fail(_ error: OpenSSHError) {
        if failure == nil { failure = error }
        budget.close(); management.cancel(); session.cancel()
    }
    private func request(token: SessionToken, request: AuthenticationRequest) {
        guard token == session.token, request.session == token.sessionID, request.generation == token.generation else { fail(.staleRequest); return }
        if input.contract.testCase == .observeChallenge {
            guard report.observation == nil, report.connectedEvents == 0 else { fail(.extraRequest); return }
            report.observation = OpenSSHObservation(prompt: request.prompt, kind: request.kind.rawValue,
                hasHint: request.hint != nil, service: input.contract.service)
            // Intentionally no secret reads, dummy replies or auth-success claim.
            budget.close(); session.cancel(); ended = true
            return
        }
        do {
            guard handler == nil else { throw OpenSSHError.extraRequest }
            let phase = try budget.claim(id: request.id, prompt: request.prompt, kind: request.kind.rawValue,
                                         hasHint: request.hint != nil, now: ProcessInfo.processInfo.systemUptime)
            handler = Task { @MainActor [weak self] in
                guard let self else { return }
                defer { self.handler = nil }
                do {
                    var answer: Data
                    switch phase {
                    case .primary:
                        let input = self.input
                        answer = try await Task.detached { try input.primarySecret() }.value
                    case .otp(let identifier, let index):
                        self.report.secretManagementReads += 1
                        let management = self.management
                        answer = try await Task.detached { try management.response(session: identifier, index: index).value }.value
                    }
                    defer { answer.resetBytes(in: 0..<answer.count) }
                    try Task.checkCancellation()
                    guard token == self.session.token, self.failure == nil else { throw OpenSSHError.staleRequest }
                    try self.budget.consume(id: request.id, now: ProcessInfo.processInfo.systemUptime)
                    try self.session.respond(.manual(try AuthenticationSecret(answer)), requestID: request.id, token: token)
                } catch { self.fail((error as? OpenSSHError) ?? .staleRequest) }
            }
        } catch {
            report.observation = OpenSSHObservation(prompt: request.prompt, kind: request.kind.rawValue,
                hasHint: request.hint != nil, service: input.contract.service)
            fail((error as? OpenSSHError) ?? .unknownRequest)
        }
    }
    func run(configuration: SSHSessionConfiguration, stop: StopMonitor) async -> OpenSSHReport {
        do {
            _ = try session.connect(configuration)
            var wait = try WaitBudget(start: ProcessInfo.processInfo.systemUptime, seconds: OpenSSHContract.activeSeconds, maximumTicks: 1200)
            while report.connectedEvents == 0 && !ended && failure == nil {
                try wait.tick(now: ProcessInfo.processInfo.systemUptime, stopped: stop.requested)
                try await Task.sleep(for: .milliseconds(50))
            }
            if let failure { throw failure }
            if input.contract.testCase == .positive {
                guard report.connectedEvents == 1, !ended, handler == nil else { throw OpenSSHError.connectionFailed }
                try budget.requireComplete()
                report.result = "expected-outer-auth-connected"
            } else {
                guard report.observation != nil, report.connectedEvents == 0, report.secretManagementReads == 0 else { throw OpenSSHError.connectionFailed }
                report.result = "observed-request-cancelled-not-auth-pass"
            }
        } catch {
            report.failure = (error as? OpenSSHError) ?? (stop.requested ? .cancelled : .timeout)
        }
        report.requests = budget.requests; report.primaryAnswers = budget.primaryAnswers
        report.otpAnswers = budget.otpAnswers; report.sessionID = budget.sessionID
        budget.close(); management.cancel(); handler?.cancel(); session.cancel(); session.closeTab()
        do {
            var drain = try WaitBudget(start: ProcessInfo.processInfo.systemUptime, seconds: OpenSSHContract.drainSeconds, maximumTicks: 600)
            while session.state != .closed || session.ownedProcessID != nil || handler != nil {
                try drain.tick(now: ProcessInfo.processInfo.systemUptime)
                try await Task.sleep(for: .milliseconds(20))
            }
            report.closeCompleted = true; report.ownedPIDReleased = true; report.managementChildrenReaped = true
        } catch { report.failure = .cleanupIncomplete }
        report.exitCode = session.lastExitCode
        if report.failure != nil { report.result = "failed" }
        return report
    }
}

@MainActor enum OpenSSHConsumer {
    static func execute(path: String, fixtureRoot: String, buildRoot: String) async -> Int32 {
        var report: OpenSSHReport?, output: String?
        let fullDeadline = ProcessInfo.processInfo.systemUptime + 85 // Including management + connect + drain.
        do {
            let input = try await Task.detached { try OpenSSHInput.load(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: NSHomeDirectory()) }.value
            report = OpenSSHReport(contract: input.contract)
            try PrivateInput.checkDirectory(buildRoot)
            let run = buildRoot + "/openssh-live-" + UUID().uuidString.lowercased()
            _ = umask(0o077)
            guard mkdir(run, 0o700) == 0, mkdir(run + "/trust", 0o700) == 0, mkdir(run + "/sessions", 0o700) == 0 else { throw OpenSSHError.unsafeMaterial }
            output = run + "/result.json"
            let management = try OpenSSHManagement(contract: input.contract, deadline: fullDeadline - OpenSSHContract.drainSeconds - 4)
            let stop = StopMonitor(); defer { stop.dispose() }
            let preflightWatch = Task { @MainActor in
                while !Task.isCancelled {
                    if stop.requested { management.cancel(); return }
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
            }
            do { try await Task.detached { try management.verify() }.value }
            catch { preflightWatch.cancel(); await preflightWatch.value; throw error }
            preflightWatch.cancel(); await preflightWatch.value
            guard !stop.requested else { throw OpenSSHError.cancelled }
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            guard key.fingerprint == input.contract.expectedFingerprint else { throw OpenSSHError.fingerprintMismatch }
            let trust = try await Task.detached { try HostTrustStore(directory: AbsolutePath(run + "/trust")) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(input.contract.port))
            guard case .pending(let pending) = try await trust.evaluate(host: host, key: key) else { throw OpenSSHError.invalidContract }
            _ = try await trust.confirm(pending, displayedFingerprint: input.contract.expectedFingerprint)
            let authentication: SSHAuthentication
            switch input.contract.service {
            case .keyonly, .keyKbd:
                guard let path = input.keyPath else { throw OpenSSHError.invalidContract }
                authentication = SSHAuthentication(method: .privateKey(try AbsolutePath(path), keyboardInteractive: input.contract.service.mfa))
            case .passwordonly: authentication = SSHAuthentication(method: .passwordOnly)
            case .passwordKbd: authentication = SSHAuthentication(method: .passwordAndKeyboardInteractive)
            }
            let configuration = try SSHSessionConfiguration(connection: SSHConnection(host: host, user: SSHUser("fixture")),
                authentication: authentication, connectTimeout: OpenSSHContract.connectionSeconds, serverAliveInterval: 5, serverAliveCountMax: 1)
            let owner = try OpenSSHCaseOwner(input: input, trust: trust, sessions: run + "/sessions", helper: BundledAskpassHelper.discover(), management: management)
            let watchdog = Task { @MainActor in
                while !Task.isCancelled {
                    if ProcessInfo.processInfo.systemUptime >= fullDeadline - OpenSSHContract.drainSeconds - 4 { owner.session.cancel(); return }
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
            }
            report = await owner.run(configuration: configuration, stop: stop)
            watchdog.cancel(); await watchdog.value
            report?.policyVerified = true
            if input.contract.testCase == .positive, input.contract.service.mfa, let identifier = report?.sessionID, report?.failure == nil {
                let cleanup = try OpenSSHManagement(contract: input.contract, deadline: fullDeadline)
                report?.serverSessionFileRemoved = try await Task.detached { try cleanup.sessionRemoved(identifier) }.value
                guard report?.serverSessionFileRemoved == true else { throw OpenSSHError.cleanupIncomplete }
            }
            guard let report, let output else { throw OpenSSHError.invalidContract }
            let bytes = try JSONEncoder().encode(report); try PrivateInput.writeExclusive(bytes + Data([10]), to: output)
            print(String(decoding: bytes, as: UTF8.self))
            return report.failure == nil ? 0 : 1
        } catch {
            if var report, let output {
                report.failure = (error as? OpenSSHError) ?? .invalidContract; report.result = "failed"
                if let data = try? JSONEncoder().encode(report) {
                    try? PrivateInput.writeExclusive(data + Data([10]), to: output); print(String(decoding: data, as: UTF8.self))
                }
            } else { fputs("OpenSSH fixture refused; no captured details emitted.\n", stderr) }
            return 1
        }
    }
}
