import AppKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

@MainActor enum SFTPOTPNegativeConsumer {
    static func execute(path: String, fixtureRoot: String, buildRoot: String) async -> Int32 {
        var report: SFTPOTPNegativeReport?, output: String?
        let fullDeadline = ProcessInfo.processInfo.systemUptime + SFTPOTPNegativeContract.fullSeconds
        do {
            let input = try await Task.detached { try SFTPOTPNegativeInput.load(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: NSHomeDirectory()) }.value
            report = SFTPOTPNegativeReport(testCase: input.contract.testCase)
            try PrivateInput.checkDirectory(buildRoot); _ = umask(0o077)
            let run = buildRoot + "/sftp-otp-negative-live-" + UUID().uuidString.lowercased()
            guard mkdir(run, 0o700) == 0, mkdir(run + "/trust", 0o700) == 0 else { throw SFTPOTPNegativeError.invalidContract }
            output = run + "/result.json"
            let management = try OpenSSHManagement(contract: input.contract.positiveIdentity().rootManagementIdentity(), deadline: fullDeadline - SFTPOTPNegativeContract.drainSeconds)
            let stop = StopMonitor(); defer { stop.dispose() }
            let prepWatch = Task { @MainActor in
                while !Task.isCancelled {
                    if stop.requested { management.cancel(); return }
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
            }
            do { try await Task.detached { try management.verify() }.value }
            catch { prepWatch.cancel(); await prepWatch.value; throw error }
            prepWatch.cancel(); await prepWatch.value
            guard !stop.requested else { throw SFTPOTPNegativeError.cancelled }
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            guard key.fingerprint == input.contract.expectedFingerprint else { throw SFTPOTPNegativeError.invalidContract }
            let trust = try await Task.detached { try HostTrustStore(directory: AbsolutePath(run + "/trust")) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22223))
            guard case .pending(let pending) = try await trust.evaluate(host: host, key: key) else { throw SFTPOTPNegativeError.invalidContract }
            _ = try await trust.confirm(pending, displayedFingerprint: input.contract.expectedFingerprint)
            let token = CancellationToken()
            let owner = try SFTPOTPNegativeCallbacks(testCase: input.contract.testCase, management: management, token: token)
            let start = ProcessInfo.processInfo.systemUptime
            var service: LibSSH2FileService?
            let watchdog = Task { @MainActor in
                while !Task.isCancelled {
                    if stop.requested { owner.cancel(.cancelled); service?.cancel(); return }
                    if ProcessInfo.processInfo.systemUptime >= min(start + SFTPOTPNegativeContract.activeSeconds, fullDeadline - SFTPOTPNegativeContract.drainSeconds) {
                        owner.cancel(.timeout); service?.cancel(); return
                    }
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
            }
            var typedRejected = false
            do {
                service = try await LibSSH2FileService.connect(configuration: SSHConnection(host: host, user: SSHUser("fixture")),
                    authentication: [.publicKey(publicKey: input.publicKey, privateKey: input.privateKey, passphrase: nil),
                        .keyboardInteractive { challenge, reply in owner.handle(challenge, reply: reply) }],
                    trustStore: trust, trustHandler: { _, reply in owner.cancel(.unknownTrust); reply.resolve(.reject) },
                    connectionTimeout: SFTPOTPNegativeContract.connectionSeconds, operationTimeout: SFTPOTPNegativeContract.operationSeconds, token: token)
                report?.actualSFTPConnects = 1
                report?.failure = .unexpectedConnection // NO file operations on any path.
            } catch let error as FileServiceError {
                report?.backendKind = error.kind.rawValue
                report?.backendOperation = ["authenticate", "handshake", "sftp-init", "challenge", "connect", "dns", "host-key"].contains(error.operation) ? error.operation : "other"
                report?.backendCode = error.code
                typedRejected = SFTPOTPNegativeBudget.isTypedAuthentication(kind: error.kind.rawValue, operation: error.operation, code: error.code)
                if !typedRejected { report?.failure = .unclassifiedFailure }
            } catch { report?.failure = (error as? SFTPOTPNegativeError) ?? .unclassifiedFailure }
            owner.closeReplies(); management.cancel()
            if let service { service.cancel(); await service.close() }
            report?.closeCompleted = true // Public connect error path already awaited native close.
            watchdog.cancel(); await watchdog.value
            do { try await owner.drain(); report?.managementChildrenReaped = true }
            catch { report?.failure = .cleanupIncomplete }
            let budget = owner.snapshot(); report?.record(budget); report?.unexpectedChallenge = owner.unexpectedSnapshot()
            if let failure = budget.failure { report?.failure = failure }
            report?.typedAuthenticationRejected = typedRejected
            if let session = budget.sessionID {
                let cleanup = try OpenSSHManagement(contract: input.contract.positiveIdentity().rootManagementIdentity(), deadline: fullDeadline)
                report?.serverSessionFileRemoved = try await Task.detached { try cleanup.sessionRemoved(session) }.value
                if report?.serverSessionFileRemoved != true { report?.failure = .cleanupIncomplete }
            }
            if report?.failure == nil {
                try budget.requireInjected()
                guard typedRejected, report?.actualSFTPConnects == 0, report?.closeCompleted == true,
                      report?.managementChildrenReaped == true, report?.serverSessionFileRemoved == true else { throw SFTPOTPNegativeError.unclassifiedFailure }
                report?.result = "expected-typed-otp-authentication-rejection"
            }
            guard let report, let output else { throw SFTPOTPNegativeError.invalidContract }
            let bytes = try JSONEncoder().encode(report); try PrivateInput.writeExclusive(bytes + Data([10]), to: output)
            print(String(decoding: bytes, as: UTF8.self)); return report.failure == nil ? 0 : 1
        } catch {
            if var report, let output {
                report.failure = (error as? SFTPOTPNegativeError) ?? .invalidContract; report.result = "failed"
                if let bytes = try? JSONEncoder().encode(report) {
                    try? PrivateInput.writeExclusive(bytes + Data([10]), to: output); print(String(decoding: bytes, as: UTF8.self))
                }
            } else { fputs("OTP negative fixture refused; no captured details emitted.\n", stderr) }
            return 1
        }
    }
}
