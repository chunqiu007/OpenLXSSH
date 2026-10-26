import AppKit
import COpenLXSSHAskpass
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore
import RealIntegrationPOSIX

@main enum Main {
    @MainActor static func main() {
        do {
            let options = try Options.parse(Array(CommandLine.arguments.dropFirst()))
            if options.action == .help { print(Options.help); return }
            if options.action == .validate { print("Syntax valid; no file I/O, signature check, AppKit or network; NOT acceptance."); return }
            try SignatureGuard.validate()
            guard let path = options.contractPath,
                  let fixtureRoot = Bundle.main.object(forInfoDictionaryKey: "RealIntegrationFixtureRoot") as? String,
                  let buildRoot = Bundle.main.object(forInfoDictionaryKey: "RealIntegrationBuildRoot") as? String,
                  fixtureRoot.hasSuffix("/Tests/IntegrationEnvironment"), buildRoot.hasSuffix("/Tests/RealIntegration/.build") else { throw SmokeError.invalidContract }
            _ = NSApplication.shared
            NSApp.setActivationPolicy(.prohibited)
            Task { @MainActor in exit(await execute(path: path, fixtureRoot: fixtureRoot, buildRoot: buildRoot)) }
            NSApp.run() // Real production broker Timer needs AppKit common run-loop modes.
        } catch { refuse(error); exit(2) }
    }
    // Reuse the production bounded PID-safe short-tool owner. Fixed executable,
    // no shell, inherited credentials or secret arguments; empty -N is not a
    // passphrase. No cryptography/key parsing is implemented by this consumer.
    nonisolated private static func generateDisposableKey(_ path: String) throws {
        let argumentStrings: [String] = ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "OpenLXSSH disposable unregistered", "-f", path]
        let environmentStrings: [String] = ["PATH=/usr/bin:/bin", "LC_ALL=C"]
        let arguments = argumentStrings.map { $0.withCString { Darwin.strdup($0) } } + [nil]
        let environment = environmentStrings.map { $0.withCString { Darwin.strdup($0) } } + [nil]
        defer { arguments.forEach { free($0) }; environment.forEach { free($0) } }
        guard arguments.dropLast().allSatisfy({ $0 != nil }), environment.dropLast().allSatisfy({ $0 != nil }) else { throw SmokeError.toolFailed }
        guard let cancellation = ap_cancel_create() else { throw SmokeError.toolFailed }
        defer { ap_cancel_free(cancellation) }
        var bytes = [UInt8](repeating: 0, count: 1024), count = 0, status: Int32 = -1
        let rc = arguments.withUnsafeBufferPointer { args in
            environment.withUnsafeBufferPointer { env in
                ap_tool("/usr/bin/ssh-keygen", UnsafeMutablePointer(mutating: args.baseAddress!), UnsafeMutablePointer(mutating: env.baseAddress!),
                        cancellation, 5, 0, &bytes, bytes.count, &count, &status)
            }
        }
        guard rc == 0, status == 0, count == 0 else { throw SmokeError.toolFailed }
    }
    private static func refuse(_ error: Error) {
        fputs("Real consumer refused/failed: \((error as? SmokeError)?.rawValue ?? "invalidFixture"). No secret details emitted.\n", stderr)
    }
    @MainActor private static func execute(path: String, fixtureRoot: String, buildRoot: String) async -> Int32 {
        var root: String?, report: SmokeReport?
        do {
            let input = try await Task.detached { try FixtureInput.load(contractPath: path, fixtureRoot: fixtureRoot) }.value
            let helper = input.contract.mode == .ssh ? try BundledAskpassHelper.discover() : nil
            try PrivateInput.checkDirectory(buildRoot)
            // Process-local only: keygen's new public/private files must both
            // satisfy the same 0600/noACL input gate; never chmod a pathname.
            _ = umask(0o077)
            let id = UUID(), run = buildRoot + "/live-" + id.uuidString.lowercased()
            guard mkdir(run, 0o700) == 0 else { throw SmokeError.unsafeMaterial }
            root = run; try PrivateInput.checkDirectory(run)
            for name in ["trust", "sessions"] {
                guard mkdir(run + "/" + name, 0o700) == 0 else { throw SmokeError.unsafeMaterial }
                try PrivateInput.checkDirectory(run + "/" + name)
            }
            // Trust comes ONLY from local container-management export plus the
            // exact manually verified fingerprint, never from scanner acceptance.
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            guard key.fingerprint == input.fingerprint else { throw SmokeError.fingerprintMismatch }
            let trust = try await Task.detached { try HostTrustStore(directory: AbsolutePath(run + "/trust")) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(Int(input.contract.port)))
            let connection = SSHConnection(host: host, user: try SSHUser("fixture"))
            guard case .pending(let decision) = try await trust.evaluate(host: host, key: key) else { throw SmokeError.invalidFixture }
            _ = try await trust.confirm(decision, displayedFingerprint: input.fingerprint)
            let stop = StopMonitor(); defer { stop.dispose() }
            var privateKey = input.privateKey, publicKey = input.clientPublicKey, password = input.password
            let keyPath = run + "/id_ed25519"
            if input.contract.testCase == .unregisteredKey {
                // Fresh disposable unregistered key, generated only in this
                // explicit live run. No reading another service/generation key.
                try await Task.detached {
                    try generateDisposableKey(keyPath)
                }.value
                privateKey = try PrivateInput.read(keyPath, limit: 32768)
                publicKey = try PrivateInput.read(keyPath + ".pub", limit: 4096)
                guard publicKey != input.clientPublicKey else { throw SmokeError.invalidFixture }
            } else if let privateKey, input.contract.mode == .ssh {
                try PrivateInput.writeExclusive(privateKey, to: keyPath)
            }
            if input.contract.testCase == .badPassword {
                guard var bad = password, !bad.isEmpty else { throw SmokeError.invalidFixture }
                bad[0] = bad[0] == 65 ? 66 : 65 // Guaranteed different; never print/store the answer.
                password = bad
            }
            if input.contract.mode == .ssh {
                let authentication: SSHAuthentication
                if input.contract.service == .keyonly { authentication = SSHAuthentication(method: .privateKey(try AbsolutePath(keyPath), keyboardInteractive: false)) }
                else { authentication = SSHAuthentication(method: .passwordOnly) }
                let configuration = try SSHSessionConfiguration(connection: connection, authentication: authentication,
                                                               connectTimeout: 10, serverAliveInterval: 5, serverAliveCountMax: 1)
                guard let helper else { throw SmokeError.signedAppRequired }
                let item = try SSHCase(input: input, trust: trust, sessions: run + "/sessions", helper: helper, response: password)
                report = await item.run(configuration: configuration, stop: stop)
            } else {
                let authentication: [FileAuthentication]
                if let privateKey { authentication = [.publicKey(publicKey: publicKey, privateKey: privateKey, passphrase: nil)] }
                else if let password { authentication = [.password(password)] }
                else { throw SmokeError.invalidFixture }
                report = await FileCase.run(input: input, connection: connection, trust: trust, authentication: authentication, stop: stop, id: id)
            }
            // Remove only known local disposable key files after awaited closure.
            for name in ["id_ed25519", "id_ed25519.pub"] {
                let target = run + "/" + name
                if access(target, F_OK) == 0 {
                    _ = try PrivateInput.read(target, limit: 32768)
                    guard unlink(target) == 0 else { throw SmokeError.cleanupIncomplete }
                }
            }
            guard let report else { throw SmokeError.connectionFailed }
            let encoded = try JSONEncoder().encode(report)
            try PrivateInput.writeExclusive(encoded + Data([10]), to: run + "/result.json")
            print(String(decoding: encoded, as: UTF8.self)) // Fixed metadata/counters only.
            return report.result == "expected-outcome" ? 0 : 1
        } catch {
            // No terminal/error descriptions, fixture paths or response values.
            // If key cleanup cannot complete, retain the private exact run root
            // for explicit coordinator cleanup rather than broad deletion.
            if var report, let root {
                report.failure = ((error as? SmokeError) ?? .invalidFixture).rawValue; report.result = "failed"
                if let data = try? JSONEncoder().encode(report) { try? PrivateInput.writeExclusive(data + Data([10]), to: root + "/result.json") }
            }
            refuse(error); return 2
        }
    }
}
