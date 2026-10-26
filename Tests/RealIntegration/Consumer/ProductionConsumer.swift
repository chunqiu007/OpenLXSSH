// Real public production API consumer. Not part of the shipping App or Stability driver.
import AppKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore
import Security

@MainActor final class StopMonitor {
    var requested = false
    private var signals: [DispatchSourceSignal] = []
    init() {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in self?.requested = true }
            source.resume(); signals.append(source)
        }
    }
    func dispose() { signals.forEach { $0.cancel() }; signals.removeAll() }
}

enum SignatureGuard {
    static func validate() throws {
        guard Bundle.main.bundleIdentifier == "org.openlxssh.OpenLXSSH",
              Bundle.main.bundleURL.pathExtension == "app",
              Bundle.main.object(forInfoDictionaryKey: "OpenLXSSHRealIntegrationTestOnly") as? Bool == true else { throw SmokeError.signedAppRequired }
        var requirement: SecRequirement?, code: SecCode?
        guard SecRequirementCreateWithString("anchor apple generic and identifier \"org.openlxssh.OpenLXSSH\"" as CFString, [], &requirement) == errSecSuccess,
              SecCodeCopySelf([], &code) == errSecSuccess, let code, let requirement,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw SmokeError.signedAppRequired }
        // Production discover/broker independently enforce fixed helper ID,
        // same Team, Hardened Runtime and no-entitlements on the live path.
    }
}

@MainActor final class SSHCase {
    let session: DirectSSHSession
    let input: FixtureInput
    var response: Data?
    var budget: ResponseBudget
    var report: SmokeReport
    var failure: SmokeError?
    var terminalFailure: SessionFailure?
    var ended = false

    init(input: FixtureInput, trust: HostTrustStore, sessions: String, helper: BundledAskpassHelper, response: Data?) throws {
        self.input = input; self.response = response
        budget = ResponseBudget(plan: input.contract.responsePlan); report = SmokeReport(contract: input.contract)
        session = DirectSSHSession(trustStore: trust, sessionDirectory: try AbsolutePath(sessions), helper: helper,
                                   scanner: try SystemHostKeyScanner(timeoutSeconds: 3))
        session.terminal.setHistoryLimit(100)
        session.onStateChange = { [weak self] token, state in
            guard let self, token == self.session.token else { return }
            switch state {
            case .connected: self.report.connectedEvents += 1
            case .failed(let reason): self.terminalFailure = reason; self.ended = true
            case .disconnected: self.ended = true
            default: break
            }
        }
        session.onTrustRequired = { [weak self] _ in
            // Only the independently exported key was seeded. No first-contact
            // UI acceptance, keyscan auto-accept, replacement or fallback.
            self?.failure = .fingerprintMismatch; self?.session.cancel()
        }
        session.onAuthenticationRequest = { [weak self] token, request in
            guard let self else { return }
            do {
                try self.budget.claim(prompt: request.prompt, masked: request.kind == .unknownMasked, hasHint: request.hint != nil)
                guard let answer = self.response else { throw SmokeError.extraAnswer }
                self.response = nil // Consume before responding; never saved-password automation.
                try self.session.respond(.manual(try AuthenticationSecret(answer)), requestID: request.id, token: token)
            } catch {
                self.failure = (error as? SmokeError) ?? .unknownPrompt
                self.response = nil; self.session.cancel()
            }
        }
        // Deliberately no onOutput callback, terminal.text, sendInput, CLI wrapper,
        // LocalCommand override, probe initializer or startProbe invocation.
    }
    func run(configuration: SSHSessionConfiguration, stop: StopMonitor) async -> SmokeReport {
        do {
            _ = try session.connect(configuration)
            var wait = try WaitBudget(start: ProcessInfo.processInfo.systemUptime, seconds: Contract.caseSeconds, maximumTicks: 600)
            while report.connectedEvents == 0 && !ended && failure == nil {
                try wait.tick(now: ProcessInfo.processInfo.systemUptime, stopped: stop.requested)
                try await Task.sleep(for: .milliseconds(50))
            }
            if let failure { throw failure }
            if input.contract.testCase == .positive {
                guard report.connectedEvents == 1, !ended else { throw SmokeError.connectionFailed }
                try budget.requireConsumed()
            } else {
                guard report.connectedEvents == 0 else { throw SmokeError.unexpectedConnection }
                try budget.requireConsumed()
                // Public DirectSSHSession may expose generic launchFailed/255
                // for ssh auth rejection. Never call that definitive bad-credential
                // evidence: network disconnects can have the same public result.
                guard terminalFailure == .authenticationFailed else { throw SmokeError.negativeUnclassified }
            }
            report.result = "expected-outcome"
        } catch { report.failure = ((error as? SmokeError) ?? .connectionFailed).rawValue }
        response = nil
        session.cancel(); session.closeTab()
        do {
            var drain = try WaitBudget(start: ProcessInfo.processInfo.systemUptime, seconds: Contract.drainSeconds, maximumTicks: 240)
            while session.state != .closed || session.ownedProcessID != nil {
                try drain.tick(now: ProcessInfo.processInfo.systemUptime)
                try await Task.sleep(for: .milliseconds(50))
            }
            report.closeCompleted = true; report.ownedPIDReleased = true
        } catch { report.failure = SmokeError.cleanupIncomplete.rawValue; report.result = "failed" }
        report.exitCode = session.lastExitCode
        report.requestCount = budget.requestCount; report.answerCount = budget.answerCount; report.refusedRequests = budget.refusedCount
        if report.failure != nil { report.result = "failed" }
        return report
    }
}

@MainActor enum FileCase {
    static func run(input: FixtureInput, connection: SSHConnection, trust: HostTrustStore,
                    authentication: [FileAuthentication], stop: StopMonitor, id: UUID) async -> SmokeReport {
        var report = SmokeReport(contract: input.contract)
        let token = CancellationToken()
        let watchdog = Task { @MainActor in
            for _ in 0..<600 {
                if stop.requested { token.cancel(); return }
                do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
            }
            token.cancel()
        }
        defer { watchdog.cancel() }
        var service: LibSSH2FileService?
        do {
            service = try await LibSSH2FileService.connect(configuration: connection, authentication: authentication,
                trustStore: trust, trustHandler: { _, reply in reply.resolve(.reject) },
                connectionTimeout: Contract.connectionSeconds, operationTimeout: Contract.operationSeconds, token: token)
            guard let service else { throw SmokeError.connectionFailed }
            if input.contract.testCase != .positive { throw SmokeError.unexpectedConnection }
            report.connectedEvents = 1 // For SFTP: actual connect returned only after authenticated SFTP init.
            try await tinyRoundTrip(service: service, token: token, ownership: RemoteOwnership(id: id), report: &report)
            report.result = "expected-outcome"
        } catch let error as FileServiceError {
            if input.contract.testCase != .positive && error.kind == .authentication {
                report.result = "expected-outcome"
            } else { report.failure = error.kind == .cancelled ? (stop.requested ? SmokeError.cancelled.rawValue : SmokeError.timeout.rawValue) : "file-" + error.kind.rawValue }
        } catch { report.failure = ((error as? SmokeError) ?? .connectionFailed).rawValue }
        if let service {
            service.cancel(); await service.close() // Await serial native-queue disposal, never fire-and-forget.
            report.closeCompleted = true
        } else {
            // connect's documented public error path already awaits service.close.
            report.closeCompleted = true
        }
        if report.failure != nil { report.result = "failed" }
        return report
    }

    private static func tinyRoundTrip(service: LibSSH2FileService, token: CancellationToken,
                                      ownership: RemoteOwnership, report: inout SmokeReport) async throws {
        let directory = try RemotePath(ownership.directory), payload = try RemotePath(ownership.payload)
        for path in ["/", "/fixture", "/fixture/home"] {
            guard try await service.lstat(RemotePath(path), token: token).kind == .directory else { throw SmokeError.integrity }
            report.lstatChecks += 1
        }
        // mkdir must succeed on this fresh UUID before any cleanup is authorized.
        try await service.mkdir(directory, token: token)
        var payloadOwned = false, handle: FileHandleID?, bodyFailure: Error?
        let bytes = Data(("OpenLXSSH disposable tiny SFTP round trip " + UUID().uuidString + "\n").utf8)
        do {
            guard try await service.lstat(directory, token: token).kind == .directory else { throw SmokeError.integrity }
            report.lstatChecks += 1
            let listed = try await service.list(directory, token: token)
            try ownership.checkListing(listed.map { $0.name.bytes }, payloadOwned: false); report.listChecks += 1
            handle = try await service.open(payload, mode: .exclusiveWrite, token: token); payloadOwned = true
            var offset = 0
            while offset < bytes.count {
                let n = try await service.write(handle!, data: Data(bytes.dropFirst(offset)), token: token)
                guard n > 0, n <= bytes.count - offset else { throw SmokeError.integrity }
                offset += n; report.bytesWritten += n
            }
            try await service.closeHandle(handle!); handle = nil
            let attributes = try await service.lstat(payload, token: token); report.lstatChecks += 1
            guard attributes.kind == .regular, attributes.size == UInt64(bytes.count) else { throw SmokeError.integrity }
            let names = try await service.list(directory, token: token)
            try ownership.checkListing(names.map { $0.name.bytes }, payloadOwned: true); report.listChecks += 1
            handle = try await service.open(payload, mode: .read, token: token)
            var received = Data()
            for _ in 0..<4 {
                let chunk = try await service.read(handle!, maxBytes: 1024, token: token)
                if chunk.isEmpty { break }
                guard received.count + chunk.count <= 1024 else { throw SmokeError.integrity }
                received += chunk; report.bytesRead += chunk.count
            }
            guard received.count == bytes.count, PrivateInput.sha256(received) == PrivateInput.sha256(bytes) else { throw SmokeError.integrity }
            try await service.closeHandle(handle!); handle = nil
        } catch { bodyFailure = error }
        // Cleanup only the UUID we successfully mkdir'd and the exact payload we
        // exclusively opened. Refuse unexpected/symlink children; NEVER recurse.
        do {
            if let handle { try await service.closeHandle(handle) }
            let cleanup = CancellationToken()
            guard try await service.lstat(directory, token: cleanup).kind == .directory else { throw SmokeError.cleanupIncomplete }
            let entries = try await service.list(directory, token: cleanup)
            try ownership.checkListing(entries.map { $0.name.bytes }, payloadOwned: payloadOwned)
            if payloadOwned {
                guard entries.count == 1, entries[0].attributes.kind == .regular,
                      try await service.lstat(payload, token: cleanup).kind == .regular else { throw SmokeError.cleanupIncomplete }
                try await service.remove(payload, directory: false, token: cleanup)
            }
            guard try await service.list(directory, token: cleanup).isEmpty else { throw SmokeError.cleanupIncomplete }
            try await service.remove(directory, directory: true, token: cleanup)
            report.remoteCleanupCompleted = true
        } catch { throw SmokeError.cleanupIncomplete }
        if let bodyFailure { throw bodyFailure }
    }
}
