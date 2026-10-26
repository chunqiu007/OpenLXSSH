import AppKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

@MainActor enum SFTPAuthConsumer {
    static func execute(path: String, fixtureRoot: String, buildRoot: String) async -> Int32 {
        var report: SFTPAuthReport?, output: String?
        let fullDeadline = ProcessInfo.processInfo.systemUptime + SFTPAuthContract.fullSeconds
        do {
            let input = try await Task.detached { try SFTPAuthInput.load(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: NSHomeDirectory()) }.value
            report = SFTPAuthReport(contract: input.contract)
            try PrivateInput.checkDirectory(buildRoot)
            _ = umask(0o077)
            let id = UUID(), run = buildRoot + "/sftp-auth-live-" + id.uuidString.lowercased()
            guard mkdir(run, 0o700) == 0, mkdir(run + "/trust", 0o700) == 0 else { throw SFTPAuthError.unsafeMaterial }
            output = run + "/result.json"
            let stop = StopMonitor(); defer { stop.dispose() }
            let management = try OpenSSHManagement(contract: input.contract.rootManagementIdentity(), deadline: fullDeadline - SFTPAuthContract.drainSeconds)
            let prepWatch = Task { @MainActor in
                while !Task.isCancelled {
                    if stop.requested { management.cancel(); return }
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
            }
            do { try await Task.detached { try management.verify() }.value }
            catch { prepWatch.cancel(); await prepWatch.value; throw error }
            prepWatch.cancel(); await prepWatch.value
            guard !stop.requested else { throw SFTPAuthError.cancelled }
            report?.policyVerified = true
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            guard key.fingerprint == input.contract.expectedFingerprint else { throw SFTPAuthError.fingerprintMismatch }
            let trust = try await Task.detached { try HostTrustStore(directory: AbsolutePath(run + "/trust")) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(input.contract.port))
            guard case .pending(let pending) = try await trust.evaluate(host: host, key: key) else { throw SFTPAuthError.invalidContract }
            _ = try await trust.confirm(pending, displayedFingerprint: input.contract.expectedFingerprint)
            let token = CancellationToken()
            let owner = try SFTPAuthCallbacks(mfa: input.contract.service.mfa, management: management, token: token)
            let start = ProcessInfo.processInfo.systemUptime
            var service: LibSSH2FileService?
            let watchdog = Task { @MainActor in
                while !Task.isCancelled {
                    if stop.requested { owner.cancel(.cancelled); service?.cancel(); return }
                    if ProcessInfo.processInfo.systemUptime >= min(start + SFTPAuthContract.activeSeconds, fullDeadline - SFTPAuthContract.drainSeconds) {
                        owner.cancel(.timeout); service?.cancel(); return
                    }
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
            }
            do {
                let primary: FileAuthentication
                if let privateKey = input.privateKey {
                    primary = .publicKey(publicKey: input.publicKey, privateKey: privateKey, passphrase: input.passphrase)
                } else if let password = input.password { primary = .password(password) }
                else { throw SFTPAuthError.invalidContract }
                var authentication: [FileAuthentication] = [primary]
                if input.contract.service.mfa {
                    authentication.append(.keyboardInteractive { challenge, reply in owner.handle(challenge, reply: reply) })
                }
                service = try await LibSSH2FileService.connect(configuration: SSHConnection(host: host, user: SSHUser("fixture")),
                    authentication: authentication, trustStore: trust,
                    trustHandler: { _, reply in owner.cancel(.unknownTrust); reply.resolve(.reject) },
                    connectionTimeout: SFTPAuthContract.connectionSeconds, operationTimeout: SFTPAuthContract.operationSeconds, token: token)
                guard let service else { throw SFTPAuthError.connectionFailed }
                report?.authenticatedSFTPConnects = 1 // Only actual authenticated SFTP init returned.
                owner.closeReplies(); try await owner.drain(); try owner.snapshot().requireComplete()
                guard var current = report else { throw SFTPAuthError.invalidContract }
                do { try await SFTPAuthRoundTrip.run(service: service, token: token, id: id, report: &current) }
                catch { report = current; throw error }
                report = current
            } catch let error as FileServiceError {
                report?.fileErrorKind = error.kind.rawValue // Typed fixed kind only, never remote/raw description.
                report?.failure = error.kind == .cancelled ? (stop.requested ? .cancelled : .timeout) : .connectionFailed
            } catch { report?.failure = (error as? SFTPAuthError) ?? .integrity }
            owner.closeReplies()
            if let service { service.cancel(); await service.close() }
            report?.closeCompleted = true // Public connect's error path also awaited native close.
            watchdog.cancel(); await watchdog.value
            management.cancel()
            do { try await owner.drain(); report?.managementChildrenReaped = true }
            catch { report?.failure = .cleanupIncomplete }
            let budget = owner.snapshot(); report?.record(budget)
            report?.unexpectedChallenge = owner.unexpectedChallengeSnapshot()
            if let error = budget.failure { report?.failure = error }
            if report?.failure == nil {
                try budget.requireComplete()
                if let session = budget.sessionID {
                    let cleanup = try OpenSSHManagement(contract: input.contract.rootManagementIdentity(), deadline: fullDeadline)
                    report?.serverSessionFileRemoved = try await Task.detached { try cleanup.sessionRemoved(session) }.value
                    guard report?.serverSessionFileRemoved == true else { throw SFTPAuthError.cleanupIncomplete }
                }
                guard report?.authenticatedSFTPConnects == 1, report?.bytesWritten == 79, report?.bytesRead == 79,
                      report?.hashMatched == true, report?.remoteCleanupCompleted == true, report?.closeCompleted == true,
                      report?.managementChildrenReaped == true else { throw SFTPAuthError.integrity }
                report?.result = "expected-authenticated-sftp-roundtrip"
            }
            guard let report, let output else { throw SFTPAuthError.invalidContract }
            let bytes = try JSONEncoder().encode(report); try PrivateInput.writeExclusive(bytes + Data([10]), to: output)
            print(String(decoding: bytes, as: UTF8.self))
            return report.failure == nil ? 0 : 1
        } catch {
            if var report, let output {
                report.failure = (error as? SFTPAuthError) ?? .invalidContract; report.result = "failed"
                if let bytes = try? JSONEncoder().encode(report) {
                    try? PrivateInput.writeExclusive(bytes + Data([10]), to: output); print(String(decoding: bytes, as: UTF8.self))
                }
            } else { fputs("SFTP auth fixture refused; no captured details emitted.\n", stderr) }
            return 1
        }
    }
}
