import AppKit
import Foundation
import Darwin
import OpenLXSSHAskpass
import OpenLXSSHTrust
import OpenLXSSHTransport
import COpenLXSSHAskpass

// Host-probe target only. No fixture parent policy enters the shipping graph.
@MainActor
enum IPCVerification {
    enum Failure: Error { case check }
    static func require(_ condition: @autoclosure () -> Bool, line: UInt = #line) throws {
        if !condition() { print("IPC check failed line=\(line)"); throw Failure.check }
    }
    static func spin(seconds: Double = 10, _ condition: () -> Bool) -> Bool {
        let end = ProcessInfo.processInfo.systemUptime + seconds
        while !condition() && ProcessInfo.processInfo.systemUptime < end { RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.005)) }
        return condition()
    }
    static func run() throws {
        _ = NSApplication.shared
        guard let work = ProcessInfo.processInfo.environment["TRANSPORT_FIXTURE_WORK"] else { throw Failure.check }
        let root = URL(fileURLWithPath: work).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let key = root.appendingPathComponent("key")
        var secret = try randomBytes(24).map { String(format: "%02x", $0) }.joined().data(using: .utf8)!
        let providerSecret = secret
        defer { secret.resetBytes(in: 0..<secret.count) }
        // System keygen reads random one-time passphrase from an anonymous pipe,
        // with no controlling terminal. Never argv/environment/log/snapshot.
        let process = Process(), input = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-q", "-t", "ed25519", "-f", key.path, "-C", ""]
        process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
        process.standardInput = input; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run()
        var answer = secret; answer.append(10); answer.append(secret); answer.append(10)
        try input.fileHandleForWriting.write(contentsOf: answer); try input.fileHandleForWriting.close()
        answer.resetBytes(in: 0..<answer.count); process.waitUntilExit()
        try require(process.terminationStatus == 0)
        let expected = try Data(contentsOf: key.appendingPathExtension("pub"))
        print("IPC keygen ready")
        let helper = try BundledAskpassHelper.discover()
        print("IPC bundled helper verified")
        // Verify actual OpenSSH parsing of the fixed LocalCommand, including a
        // signed bundle path containing spaces, single quotes and percent.
        let configPath = root.appendingPathComponent("event-ssh-config")
        let connection = SSHConnection(host: HostIdentity(address: try HostAddress("event.example"), port: try SSHPort(22)), user: try SSHUser("fixture"))
        let sessionConfig = try SSHSessionConfiguration(connection: connection, authentication: SSHAuthentication(method: .passwordOnly))
        let configStore = try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("config-trust").path))
        let keyFixture = try HostPublicKey(openSSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg")
        let controlled = try DirectSSHConfiguration(configuration: sessionConfig, trustStore: configStore, trustedKeys: [keyFixture], helper: helper)
        try Data(controlled.text.utf8).write(to: configPath)
        let preview = Process(), previewPipe = Pipe()
        preview.executableURL = URL(fileURLWithPath: "/usr/bin/ssh"); preview.arguments = ["-G", "-F", configPath.path, "--", "openlxssh-direct"]
        preview.standardOutput = previewPipe; preview.standardError = FileHandle.nullDevice
        preview.environment = ["PATH": "/usr/bin:/bin", "SHELL": "/bin/sh"]
        try preview.run(); let parsed = previewPipe.fileHandleForReading.readDataToEndOfFile(); preview.waitUntilExit()
        try require(preview.terminationStatus == 0)
        let parsedText = String(decoding: parsed, as: UTF8.self)
        try require(parsedText.contains("permitlocalcommand yes"))
        try require(parsedText.contains("localcommand " + controlled.authenticatedEventCommand!))
        let trust = try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("trust").path))
        let scanner = try SystemHostKeyScanner()
        // Warm process/framework caches before counting.
        var fdBefore: Int32?, portsBefore: Int32?
        var allServices: [String] = []
        for mode in ["success", "cancel", "port-revocation", "wrong-parent", "success", "success"] {
            print("IPC mode=\(mode)")
            let session = try DirectSSHSession(probeStore: trust, directory: AbsolutePath(root.path), scanner: scanner)
            let token = SessionToken(sessionID: session.sessionID, generation: 1)
            let broker = try AskpassBroker(token: token, validateImage: { expected in
                var expected = expected
                return ap_signed_probe_keygen(&expected) == 0 && ap_process_has_ctty(expected.pid) != 0
            })
            var request: AuthenticationRequest?
            broker.onRequest = { request = $0 }
            var brokerFailed = false
            broker.onFailure = { _ in brokerFailed = true; session.cancel() }
            let env = ["PATH": "/usr/bin:/bin", "TERM": "xterm-256color", "LANG": "en_US.UTF-8"].merging(broker.environment(helper: helper), uniquingKeysWith: { _, new in new })
            let invocation = DirectSSHInvocation(executable: "/usr/bin/ssh-keygen", arguments: ["-y", "-f", key.path], environment: env)
            let actual = try session.startProbe(invocation, directory: root.path, broker: broker)
            try require(actual == token)
            let parentPID = try session.ownedProcessID.unwrap()
            if mode == "wrong-parent" {
                let fake = Process(), pipe = Pipe()
                fake.executableURL = helper.url; fake.arguments = ["untrusted parent fixture"]
                fake.environment = env; fake.standardOutput = pipe; fake.standardError = FileHandle.nullDevice
                try fake.run()
                try require(spin { !fake.isRunning })
                fake.waitUntilExit(); try require(fake.terminationStatus != 0)
                try require(pipe.fileHandleForReading.readDataToEndOfFile().isEmpty)
                try require(broker.rejectedRequests > 0)
            }
            if mode == "success", fdBefore != nil {
                // Exercise the actual production coordinator provider path using
                // synthetic keygen readpass. This proves delivery/cancellation,
                // NOT that keygen is an eligible production password context.
                session.configureProbeSavedPassword(SavedPasswordAuthorization { _ in try SecretBytes(providerSecret) }, eligible: true)
                session.onAuthenticationRequest = { [weak session] _, requestValue in
                    guard session != nil else { return }
                    request = requestValue
                }
            }
            try require(spin { request != nil || session.canReconnect })
            if mode == "success", fdBefore != nil { try require(request == nil) }
            if request == nil {
                try require(mode == "success" && session.lastExitCode == 0)
                try require(!session.terminal.text.contains(String(decoding: secret, as: UTF8.self)))
                let actualKey = session.terminal.text.filter { !$0.isWhitespace }
                try require(actualKey.contains(String(decoding: expected, as: UTF8.self).filter { !$0.isWhitespace }))
                session.closeTab(); allServices.append(broker.serviceName); continue
            }
            let accepted = try request.unwrap()
            try require(accepted.kind == .unknownMasked)
            let helperID = try broker.helperIdentities.last.unwrap()
            if mode == "success" || mode == "wrong-parent" {
                try session.respond(.manual(try SecretBytes(secret)), requestID: accepted.id, token: token)
                try require(spin { session.canReconnect })
                try require(session.lastExitCode == 0)
                let terminalText = session.terminal.text
                // Public key line wraps at terminal width; compare all non-layout
                // bytes, not a guessed wait or a marker-only success assertion.
                let expectedKey = String(decoding: expected, as: UTF8.self).filter { !$0.isWhitespace }
                try require(terminalText.filter { !$0.isWhitespace }.contains(expectedKey))
                try require(!terminalText.contains(String(decoding: secret, as: UTF8.self)))
            } else if mode == "port-revocation" {
                // Destroy only the send-once reply right, with no process signal.
                // This must wake the helper and make readpass fail promptly.
                broker.revokeProbeReplyPort()
                try require(spin(seconds: 3) { session.canReconnect })
            } else {
                session.cancel(); try require(spin { session.canReconnect })
                do { try session.respond(.manual(try SecretBytes(secret)), requestID: accepted.id, token: token); throw Failure.check }
                catch is Failure { throw Failure.check } catch {}
            }
            try require(spin {
                var current = ap_identity()
                return ap_identity_read(helperID.pid, &current) != 0 || !same(current, helperID)
            })
            try require(kill(parentPID, 0) == -1 && errno == ESRCH)
            try require(!brokerFailed)
            session.closeTab(); try require(session.state == .closed)
            allServices.append(broker.serviceName)
            if fdBefore == nil {
                _ = spin(seconds: 0.2) { false }
                fdBefore = ap_fd_count(); portsBefore = ap_port_count()
            }
        }
        _ = spin(seconds: 0.2) { false }
        try require(ap_fd_count() <= fdBefore! + 2)
        try require(ap_port_count() <= portsBefore! + 3)
        for service in allServices { print("POSTEXIT_SERVICE \(service)") }
        try verifyEvents(root: root, trust: trust, helper: helper)
        print("TRANSPORT IPC PASS real-system-readpass scenarios=6 events=4 no-network no-SSH-success")
    }
    static func verifyEvents(root: URL, trust: HostTrustStore, helper: BundledAskpassHelper) throws {
        let scanner = try SystemHostKeyScanner()
        let image = Bundle.main.executableURL!.path
        for mode in ["valid", "replay", "cancel", "wrong-parent"] {
            let session = try DirectSSHSession(probeStore: trust, directory: AbsolutePath(root.path), scanner: scanner)
            let token = SessionToken(sessionID: session.sessionID, generation: 1)
            let broker = try AskpassBroker(token: token, validateImage: { expected in
                var current = expected
                return ap_signed_probe_parent(&current) == 0
            })
            let environment = ["PATH": "/usr/bin:/bin", "SHELL": "/bin/sh", "TERM": "xterm-256color"].merging(broker.environment(helper: helper), uniquingKeysWith: { _, new in new })
            let invocation = DirectSSHInvocation(executable: image, arguments: ["--event-parent", helper.url.path, mode], environment: environment)
            _ = try session.startProbe(invocation, directory: root.path, broker: broker)
            if mode == "cancel" {
                session.cancel(); try require(spin { session.canReconnect })
                try require(broker.authenticatedEvents == 0)
            } else {
                if mode == "wrong-parent" {
                    let fake = Process()
                    fake.executableURL = helper.url; fake.arguments = ["--authenticated-event", "v1"]; fake.environment = environment
                    fake.standardOutput = FileHandle.nullDevice; fake.standardError = FileHandle.nullDevice
                    try fake.run(); try require(spin { !fake.isRunning }); fake.waitUntilExit()
                    try require(fake.terminationStatus != 0); try require(broker.rejectedRequests >= 1)
                }
                try require(spin { broker.authenticatedEvents == 1 })
                try require(session.state == .connected || session.canReconnect)
                try require(spin { session.canReconnect })
                try require(session.lastExitCode == 0)
                if mode == "replay" { try require(broker.rejectedRequests >= 1) }
            }
            session.closeTab(); print("POSTEXIT_SERVICE \(broker.serviceName)")
        }
    }
}
private extension Optional {
    func unwrap() throws -> Wrapped { guard let value = self else { throw IPCVerification.Failure.check }; return value }
}
