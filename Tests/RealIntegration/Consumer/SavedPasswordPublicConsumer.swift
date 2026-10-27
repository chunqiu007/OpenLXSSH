import AppKit
import Darwin
import Foundation
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

@MainActor enum SavedPasswordPublicConsumer {
    static func execute(path: String, fixtureRoot: String, buildRoot: String) async -> Int32 {
        var report: SavedPasswordPublicReport?, output: String?
        let deadline = ProcessInfo.processInfo.systemUptime + SavedPasswordPublicContract.fullSeconds
        do {
            let input = try await Task.detached { try SavedPasswordPublicInput.load(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: NSHomeDirectory()) }.value
            report = SavedPasswordPublicReport(testCase: input.contract.testCase)
            try PrivateInput.checkDirectory(buildRoot); _ = umask(0o077)
            let run = buildRoot + "/saved-password-live-" + UUID().uuidString.lowercased()
            guard mkdir(run, 0o700) == 0, mkdir(run + "/trust", 0o700) == 0, mkdir(run + "/sessions", 0o700) == 0 else { throw SavedPasswordPublicError.unsafeMaterial }
            output = run + "/result.json"
            let management = try OpenSSHManagement(contract: input.contract.rootManagementIdentity(), deadline: deadline - SavedPasswordPublicContract.drainSeconds)
            let stop = StopMonitor(); defer { stop.dispose() }
            let watcher = Task { @MainActor in
                while !Task.isCancelled {
                    if stop.requested { management.cancel(); return }
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
            }
            do { try await Task.detached { try management.verify() }.value }
            catch { watcher.cancel(); await watcher.value; throw error }
            watcher.cancel(); await watcher.value
            guard !stop.requested else { throw SavedPasswordPublicError.cancelled }
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            guard key.fingerprint == input.contract.expectedFingerprint else { throw SavedPasswordPublicError.fingerprintMismatch }
            let trust = try await Task.detached { try HostTrustStore(directory: AbsolutePath(run + "/trust")) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22222))
            guard case .pending(let pending) = try await trust.evaluate(host: host, key: key) else { throw SavedPasswordPublicError.invalidContract }
            _ = try await trust.confirm(pending, displayedFingerprint: input.contract.expectedFingerprint)
            let configuration = try SSHSessionConfiguration(connection: SSHConnection(host: host, user: SSHUser("fixture")),
                authentication: SSHAuthentication(method: .passwordOnly), connectTimeout: 20, serverAliveInterval: 5, serverAliveCountMax: 1)
            let owner = try SavedPasswordPublicOwner(input: input, trust: trust, sessions: run + "/sessions", helper: BundledAskpassHelper.discover())
            report = await owner.run(configuration: configuration, stop: stop, processDeadline: deadline)
            report?.managementChildrenReaped = true // Preflight uses sole-waiter bounded tool owner.
            guard let report, let output else { throw SavedPasswordPublicError.invalidContract }
            let bytes = try JSONEncoder().encode(report); try PrivateInput.writeExclusive(bytes + Data([10]), to: output)
            print(String(decoding: bytes, as: UTF8.self)); return report.failure == nil ? 0 : 1
        } catch {
            if var report, let output {
                report.failure = (error as? SavedPasswordPublicError) ?? .invalidContract; report.result = "failed"
                if let bytes = try? JSONEncoder().encode(report) {
                    try? PrivateInput.writeExclusive(bytes + Data([10]), to: output); print(String(decoding: bytes, as: UTF8.self))
                }
            } else { fputs("Saved-password public fixture refused; no captured details emitted.\n", stderr) }
            return 1
        }
    }
}
