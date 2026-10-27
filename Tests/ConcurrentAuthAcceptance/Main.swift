import AppKit
import Darwin
import Foundation
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

@main enum Main {
    @MainActor static func main() {
        do {
            let (action, path) = try ConcurrentPolicy.parse(Array(CommandLine.arguments.dropFirst()))
            if action == .help { print(ConcurrentPolicy.help); return }
            if action == .validate { print("Syntax only; no I/O, signature, AppKit, Docker, credentials or connection. NOT runtime authorization."); return }
            if action == .offline { try ConcurrentPolicy.offlineCheck(); print("Pure budget/CLI checks passed; NOT real concurrent authentication."); return }
            try SignatureGuard.validate() // Reuse parent guard; public helper discovery/broker also require same Team.
            guard Bundle.main.object(forInfoDictionaryKey: "OpenLXSSHConcurrentAuthTestOnly") as? Bool == true, let path,
                  let fixture = Bundle.main.object(forInfoDictionaryKey: "RealIntegrationFixtureRoot") as? String,
                  let inputRoot = Bundle.main.object(forInfoDictionaryKey: "RealIntegrationBuildRoot") as? String,
                  let outputRoot = Bundle.main.object(forInfoDictionaryKey: "ConcurrentAuthBuildRoot") as? String,
                  fixture.hasSuffix("/Tests/IntegrationEnvironment"), inputRoot.hasSuffix("/Tests/RealIntegration/.build"),
                  outputRoot.hasSuffix("/Tests/ConcurrentAuthAcceptance/.build") else { throw OpenSSHError.invalidContract }
            _ = NSApplication.shared; NSApp.setActivationPolicy(.prohibited)
            Task { @MainActor in exit(await execute(path, fixture, inputRoot, outputRoot)) }; NSApp.run()
        } catch { fputs("Concurrent auth refused; no captured details emitted.\n", stderr); exit(2) }
    }
    @MainActor static func execute(_ path: String, _ fixture: String, _ inputRoot: String, _ outputRoot: String) async -> Int32 {
        var report = ConcurrentReport(), owners: [ConcurrentOwner] = []
        let stop = StopMonitor(); defer { stop.dispose() }
        let deadline = ProcessInfo.processInfo.systemUptime + 85
        do {
            let input = try await Task.detached { try OpenSSHInput.load(path: path, buildRoot: inputRoot, fixtureRoot: fixture, home: NSHomeDirectory()) }.value
            try ConcurrentPolicy.check(input)
            let ma = try OpenSSHManagement(contract: input.contract, deadline: deadline - OpenSSHContract.drainSeconds - 4)
            let mb = try OpenSSHManagement(contract: input.contract, deadline: deadline - OpenSSHContract.drainSeconds - 4)
            let preflight = Task { @MainActor in
                while !Task.isCancelled { if stop.requested { ma.cancel(); return }; do { try await Task.sleep(for: .milliseconds(50)) } catch { return } }
            }
            do { try await Task.detached { try ma.verify() }.value } catch { preflight.cancel(); await preflight.value; throw error }
            preflight.cancel(); await preflight.value
            guard !stop.requested else { throw OpenSSHError.cancelled }; report.policyVerified = true // Once, shared exact current contract/CID.
            try PrivateInput.checkDirectory(outputRoot)
            _ = umask(0o077)
            let runID = UUID(), run = outputRoot + "/concurrent-" + runID.uuidString.lowercased()
            guard mkdir(run, 0o700) == 0 else { throw OpenSSHError.unsafeMaterial }
            report.runID = runID; report.runDirectory = run
            let receipt = try JSONEncoder().encode(ConcurrentRunReceipt(runID: runID, runDirectory: run))
            try PrivateInput.writeExclusive(receipt + Data([10]), to: run + "/run-receipt.json"); report.receiptWritten = true
            print(String(decoding: receipt, as: UTF8.self)); fflush(stdout)
            guard mkdir(run + "/trust", 0o700) == 0, mkdir(run + "/sessions", 0o700) == 0 else { throw OpenSSHError.unsafeMaterial }
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            guard key.fingerprint == input.contract.expectedFingerprint else { throw OpenSSHError.fingerprintMismatch }
            let trust = try await Task.detached { try HostTrustStore(directory: AbsolutePath(run + "/trust")) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22224))
            guard case .pending(let pending) = try await trust.evaluate(host: host, key: key) else { throw OpenSSHError.invalidContract }
            _ = try await trust.confirm(pending, displayedFingerprint: input.contract.expectedFingerprint)
            let helper = try BundledAskpassHelper.discover()
            let a = try ConcurrentOwner(input: input, trust: trust, sessions: run + "/sessions", helper: helper, management: ma); owners.append(a)
            let b = try ConcurrentOwner(input: input, trust: trust, sessions: run + "/sessions", helper: helper, management: mb); owners.append(b)
            let configuration = try SSHSessionConfiguration(connection: SSHConnection(host: host, user: SSHUser("fixture")),
                authentication: SSHAuthentication(method: .passwordAndKeyboardInteractive), connectTimeout: OpenSSHContract.connectionSeconds, serverAliveInterval: 5, serverAliveCountMax: 1)
            try await ConcurrentCase.run(a: a, b: b, configuration: configuration, stop: stop, report: &report)
        } catch { report.failure = (error as? OpenSSHError) ?? .connectionFailed }
        for owner in owners { owner.beginClose() }
        for owner in owners { do { try await owner.drain() } catch { report.failure = .cleanupIncomplete } }
        if owners.count == 2 {
            report.a = owners[0].evidence; report.b = owners[1].evidence
            if report.failure == nil {
                do {
                    let cleanup = try OpenSSHManagement(contract: owners[0].input.contract, deadline: deadline)
                    for owner in owners {
                        guard let id = owner.budget.sessionID else { throw OpenSSHError.cleanupIncomplete }
                        let removed = try await Task.detached { try cleanup.sessionRemoved(id) }.value
                        guard removed else { throw OpenSSHError.cleanupIncomplete }; report.serverSessionsRemoved += 1
                    }
                } catch { report.failure = .cleanupIncomplete }
            }
        }
        if let bytes = try? JSONEncoder().encode(report) { print(String(decoding: bytes, as: UTF8.self)) } // Typed nonsecret metadata/counters only.
        return report.failure == nil ? 0 : 1
    }
}
