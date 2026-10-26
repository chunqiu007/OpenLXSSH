import AppKit
import Foundation
import Darwin
import OpenLXSSHAskpass
import OpenLXSSHTrust
import OpenLXSSHTransport
import COpenLXSSHAskpass
import CTransportAdversary

@MainActor
extension IPCVerification {
    static func runAdversarial() throws {
        _ = NSApplication.shared
        let environment = ProcessInfo.processInfo.environment
        guard let work = environment["TRANSPORT_FIXTURE_WORK"], let mirrorsPath = environment["TRANSPORT_ADVERSARY_MIRRORS"] else { throw Failure.check }
        let root = URL(fileURLWithPath: work).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let mirrors = URL(fileURLWithPath: mirrorsPath)
        let helper = try BundledAskpassHelper.discover()
        let trust = try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("trust").path))
        let scanner = try SystemHostKeyScanner()
        let image = Bundle.main.executableURL!.path
        let helperMirror = mirrors.appendingPathComponent("helper").path
        let wrongIdentifier = mirrors.appendingPathComponent("wrong-identifier").path
        let adHoc = mirrors.appendingPathComponent("adhoc-helper").path
        // Static bundle discovery and dynamic audit-token validation are both
        // exercised. adHoc has the correct identifier, NOT a second Apple Team.
        try require(ap_signed_bundled_helper(helperMirror) == 0)
        try require(ap_signed_bundled_helper(wrongIdentifier) != 0)
        try require(ap_signed_bundled_helper(adHoc) != 0)
        let rawNames = ["complex-empty", "port-descriptor", "ool-memory", "ool-ports", "voucher", "wrong-id", "no-reply", "send-not-sendonce", "short-header", "long-inline", "zero-count", "high-count", "size-mismatch", "receive-too-large"]
        try require(rawNames.count == ADV_CASE_COUNT)
        let initialFD = ap_fd_count(), initialPorts = ap_port_count()
        try require(initialFD > 0 && initialPorts > 0)
        var baselineFD: Int32?, baselinePorts: Int32?, count = 0
        let modes = ["raw-4", "control", "wrong-identifier", "adhoc-signer", "wrong-parent", "wrong-session", "wrong-generation", "wrong-nonce", "replay",
                     "queued-wrong-to-helper", "queued-helper-to-broker", "queued-helper-to-helper", "cancel", "parent-exit", "closed"]
            + rawNames.indices.filter { $0 != 4 }.map { "raw-\($0)" }
        for mode in modes {
            print("ADVERSARIAL mode=\(mode)")
            do {
                let session = try DirectSSHSession(probeStore: trust, directory: AbsolutePath(root.path), scanner: scanner)
                defer { session.closeTab() }
                let token = SessionToken(sessionID: session.sessionID, generation: 1)
                let broker = try AskpassBroker(token: token, validateImage: { expected in
                    var expected = expected
                    return ap_signed_probe_parent(&expected) == 0
                })
                let record = root.appendingPathComponent(UUID().uuidString).path
                var request: Request?, failure: AskpassError?
                broker.onRequest = { request = $0 }
                broker.onFailure = { failure = $0 }
                let parentEnvironment = ["PATH": "/usr/bin:/bin", "TERM": "xterm-256color"].merging(broker.environment(helper: helper), uniquingKeysWith: { _, new in new })
                let selected = mode == "wrong-identifier" || mode == "queued-wrong-to-helper" ? wrongIdentifier : (mode == "adhoc-signer" ? adHoc : helperMirror)
                let next = mode == "queued-helper-to-broker" ? image : helperMirror
                let clientMode = ["wrong-identifier", "adhoc-signer"].contains(mode) ? "reject" : mode
                let invocation = DirectSSHInvocation(executable: image, arguments: ["--adversarial-parent", clientMode, selected, next, record], environment: parentEnvironment)
                _ = try session.startProbe(invocation, directory: root.path, broker: broker)
                let parentPID = try unwrap(session.ownedProcessID)
                let parentIdentity = try identity(parentPID)
                if mode.hasPrefix("raw-") {
                    try require(spin(seconds: 2) { request != nil || broker.rejectedRequests > 0 })
                    if mode == "raw-4" { print("ADVERSARIAL voucher-valid-request accepted=\(broker.acceptedRequests) rejected=\(broker.rejectedRequests)") }
                    try require(broker.acceptedRequests == 0 && broker.rejectedRequests == 1 && request == nil)
                    try Data().write(to: URL(fileURLWithPath: record + ".received"))
                }
                if mode.hasPrefix("queued-") {
                    // Deliberately do not pump the main RunLoop until exec has
                    // completed, so no request can be validated pre-exec by luck.
                    try require(waitWithoutRunLoop(seconds: 2) { FileManager.default.fileExists(atPath: record + ".stage") })
                    let childPID = try Int32(String(contentsOfFile: record + ".stage", encoding: .utf8)).unwrapForAdversary()
                    let before = try identity(childPID)
                    let expectedIdentifier = next == image ? "org.openlxssh.OpenLXSSH" : "org.openlxssh.askpass"
                    try require(ap_adv_current_identifier(childPID, expectedIdentifier) == 0)
                    let after = try identity(childPID)
                    try require(same(after, before))
                    try require(before.ppid == parentPID && broker.acceptedRequests == 0)
                    try require(spin(seconds: 2) { broker.rejectedRequests == 1 })
                    try require(broker.acceptedRequests == 0 && request == nil && failure == nil)
                    session.cancel()
                } else if mode == "wrong-parent" {
                    // A genuine signed helper with complete leaked correlation
                    // data, but a direct child of the host, not registered parent.
                    // Keep the registered parent busy with its own valid request.
                    try require(spin(seconds: 2) { request != nil })
                    let pipe = Pipe()
                    let fakePID = try spawnAdversarial(helperMirror, ["--adversarial-client", "reject", record + ".unregistered", helperMirror], output: pipe.fileHandleForWriting.fileDescriptor, environment: parentEnvironment)
                    try pipe.fileHandleForWriting.close()
                    var status: Int32 = 0, reaped = false
                    defer { if !reaped { _ = kill(fakePID, SIGKILL); while waitpid(fakePID, &status, 0) < 0 && errno == EINTR {} } }
                    try require(spin(seconds: 2) { if !reaped { reaped = waitpid(fakePID, &status, WNOHANG) == fakePID }; return reaped })
                    try require(status == 0 && pipe.fileHandleForReading.readDataToEndOfFile().isEmpty)
                    try require(broker.rejectedRequests == 1 && broker.acceptedRequests == 1)
                    session.cancel()
                } else if ["control", "replay", "cancel", "parent-exit", "closed"].contains(mode) {
                    try require(spin(seconds: 2) { request != nil })
                    let accepted = try unwrap(request)
                    if mode == "control" || mode == "replay" {
                        try session.respond(.confirm(true), requestID: accepted.id, token: token)
                    } else {
                        var randomAnswer = try randomBytes(24).base64EncodedData()
                        defer { randomAnswer.resetBytes(in: 0..<randomAnswer.count) }
                        if mode == "cancel" { session.cancel() }
                        if mode == "closed" { session.closeTab() }
                        if mode == "parent-exit" {
                            // Parent reaps its controlled helper and exits while
                            // the broker is not pumped; submit must recheck parent.
                            try Data().write(to: URL(fileURLWithPath: record + ".exit"))
                            try require(waitWithoutRunLoop(seconds: 2) { FileManager.default.fileExists(atPath: record) && !identityAlive(parentIdentity) })
                        }
                        do { try session.respond(.manual(SecretBytes(randomAnswer)), requestID: accepted.id, token: token); throw Failure.check }
                        catch is Failure { throw Failure.check }
                        catch {
                            // identity() itself fails for an exited/zombie PID;
                            // either category must close the broker without sending.
                            if mode == "parent-exit" { try require(error as? AskpassError == .parentExited || error as? AskpassError == .identity) }
                            else { try require(error as? TransportError == .stale) }
                        }
                        do { try session.respond(.manual(SecretBytes(randomAnswer)), requestID: accepted.id, token: token); throw Failure.check }
                        catch is Failure { throw Failure.check }
                        catch { try require(error as? AskpassError == .stale || error as? TransportError == .stale) }
                    }
                }
                try require(spin(seconds: 5) { session.canReconnect || session.state == .closed })
                try require(FileManager.default.fileExists(atPath: record))
                let result = try String(contentsOfFile: record, encoding: .utf8).split(separator: " ").compactMap { Int32($0) }
                try require(result.count == 3 && result[2] == 0)
                if mode != "parent-exit" && result[1] != 0 { print("ADVERSARIAL child-exit mode=\(mode) status=\(result[1]) bytes=\(result[2])") }
                try require(mode == "parent-exit" || result[1] == 0)
                var helperIdentity = ap_identity()
                try require(ap_identity_read(result[0], &helperIdentity) != 0)
                try require(kill(parentPID, 0) == -1 && errno == ESRCH)
                try require(ap_mach_name_unknown(broker.serviceName) != 0)
                switch mode {
                case "control": try require(broker.acceptedRequests == 1 && broker.rejectedRequests == 0)
                case "replay", "wrong-parent": try require(broker.acceptedRequests == 1 && broker.rejectedRequests == 1)
                case "cancel", "closed": try require(broker.acceptedRequests == 1 && failure == nil)
                case "parent-exit": try require(broker.acceptedRequests == 1 && (failure == .parentExited || failure == .identity))
                default: try require(broker.acceptedRequests == 0 && broker.rejectedRequests == 1 && failure == nil)
                }
                session.closeTab()
                print("POSTEXIT_SERVICE \(broker.serviceName)")
            }
            _ = spin(seconds: 0.04) { false }
            if let baselineFD, let baselinePorts {
                let fd = ap_fd_count(), ports = ap_port_count()
                if fd > baselineFD + 2 || ports > baselinePorts + 2 { print("ADVERSARIAL resource-delta mode=\(mode) fd=\(fd - baselineFD) ports=\(ports - baselinePorts)") }
                try require(fd <= baselineFD + 2 && ports <= baselinePorts + 2)
            } else { baselineFD = ap_fd_count(); baselinePorts = ap_port_count() }
            count += 1
            print("ADVERSARIAL PASS \(mode)")
        }
        // Production ap_mach_receive/mach_msg_destroy with exact port-name and
        // virtual-mapping deltas, in addition to the broker process cases above.
        for (kind, name) in rawNames.enumerated() {
            let result = ap_adv_check_local_ownership(Int32(kind))
            if result != 0 { print("ADVERSARIAL local-ownership kind=\(name) error=\(result)") }
            try require(result == 0)
        }
        let sendOnce = ap_adv_check_send_once()
        if sendOnce != 0 { print("ADVERSARIAL sendonce error=\(sendOnce)") }
        try require(sendOnce == 0)
        print("ADVERSARIAL PASS raw-ownership kinds=14 messages-per-kind=3 sendonce-success-dead-invalid=3 request-send-timeout=1")
        print("ADVERSARIAL resources fd-before=\(initialFD) fd-after=\(ap_fd_count()) ports-before=\(initialPorts) ports-after=\(ap_port_count()) steady-state-slack=2")
        print("TRANSPORT ADVERSARIAL PASS scenarios=\(count) raw-kinds=14 owned-children-reaped no-secret-output no-network second-Apple-Team=not-tested")
    }
    private static func waitWithoutRunLoop(seconds: Double, _ condition: () -> Bool) -> Bool {
        let end = now() + seconds
        while !condition() && now() < end { usleep(5000) }
        return condition()
    }
    private static func identityAlive(_ expected: ap_identity) -> Bool {
        var current = ap_identity()
        return ap_identity_read(expected.pid, &current) == 0 && same(current, expected)
    }
    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw Failure.check }; return value
    }
}
private extension Optional {
    func unwrapForAdversary() throws -> Wrapped {
        guard let value = self else { throw IPCVerification.Failure.check }; return value
    }
}
