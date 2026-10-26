import Foundation
import Darwin
import OpenLXSSHAskpass
import COpenLXSSHAskpass
import CTransportAdversary

// All modes are confined to TransportFixture. The shipping helper has no test
// arguments, arbitrary-PID registration, raw Mach API or alternate trust policy.
private func adversarialGrant(_ environment: [String: String]) throws -> SessionGrant {
    guard let session = environment["AP_SESSION"].flatMap(UUID.init(uuidString:)),
          let generation = environment["AP_GENERATION"].flatMap(UInt64.init),
          let nonce = environment["AP_NONCE"] else { throw AskpassError.unavailable }
    return SessionGrant(session: session, generation: generation, nonce: nonce)
}

func runAdversarialClient(mode: String, record: String, nextImage: String) -> Int32 {
    do {
        let environment = ProcessInfo.processInfo.environment
        guard let service = environment["AP_SERVICE"] else { return 81 }
        let original = try adversarialGrant(environment)
        let grant: SessionGrant
        switch mode {
        case "wrong-session": grant = SessionGrant(generation: original.generation, nonce: original.nonce)
        case "wrong-generation": grant = SessionGrant(session: original.session, generation: original.generation + 1, nonce: original.nonce)
        case "wrong-nonce": grant = SessionGrant(session: original.session, generation: original.generation, nonce: try nonce())
        default: grant = original
        }
        let confirmation = ["control", "replay"].contains(mode)
        let request = Request(grant: grant, prompt: "Local adversarial fixture", hint: confirmation ? "confirm" : nil)
        if mode.hasPrefix("raw-"), let kind = Int32(mode.dropFirst(4)) {
            var reply: UInt32 = 0, extra: UInt32 = 0
            let bytes = try JSONEncoder().encode(request)
            let result = bytes.withUnsafeBytes { ap_adv_send_invalid(service, kind, $0.baseAddress, bytes.count, &reply, &extra) }
            guard result == 0 else { return 82 }
            return ap_adv_finish_invalid(reply, extra, kind) == 0 ? 0 : 83
        }
        let inbox = try sendRequest(request, service: service)
        if mode.hasPrefix("queued-") {
            // The request has already entered the kernel queue. exec retains PID
            // and start-time but changes pidversion/code identity in audit tokens.
            let arguments = [nextImage, "--adversarial-standby", record + ".stage"]
            let argv = arguments.map { strdup($0) } + [nil]
            defer { argv.forEach { free($0) } }
            return withExtendedLifetime(inbox) {
                nextImage.withCString { path in argv.withUnsafeBufferPointer { _ = execv(path, $0.baseAddress!) } }
                return 84
            }
        }
        if confirmation {
            let response = try receiveMach(inbox.raw, reply: true, timeout: 2000)
            let peer = try replyPeer(response.token), reply = try response.decode(Reply.self)
            guard peer.pid == environment["AP_BROKER_PID"].flatMap(Int32.init), reply.session == request.session,
                  reply.generation == request.generation, reply.id == request.id,
                  reply.action == "confirm", reply.answer == nil else { return 85 }
            if mode == "control" { return 0 }
            let replay = try sendRequest(request, service: service)
            return try expectNoAnswer(replay)
        }
        return try expectNoAnswer(inbox)
    } catch { return 86 }
}

private func expectNoAnswer(_ inbox: ReplyInbox) throws -> Int32 {
    do {
        _ = try receiveMach(inbox.raw, reply: true, timeout: 2500)
        return 87 // Any application payload, including an empty answer, is wrong.
    } catch AskpassError.protocolViolation {
        return 0 // Send-once destruction notification, not an application reply.
    }
}

func runAdversarialStandby(stage: String) -> Int32 {
    ap_adv_parent_signals()
    do { try Data(String(getpid()).utf8).write(to: URL(fileURLWithPath: stage), options: .atomic) }
    catch { return 88 }
    let end = now() + 4
    while now() < end && ap_adv_parent_cancelled() == 0 { usleep(5000) }
    return 0
}

func spawnAdversarial(_ path: String, _ arguments: [String], output: Int32, environment: [String: String] = ProcessInfo.processInfo.environment) throws -> pid_t {
    let argv = ([path] + arguments).map { strdup($0) } + [nil]
    let env = environment.sorted { $0.key < $1.key }.map { strdup("\($0.key)=\($0.value)") } + [nil]
    defer { (argv + env).forEach { free($0) } }
    var actions: posix_spawn_file_actions_t?
    guard posix_spawn_file_actions_init(&actions) == 0 else { throw AskpassError.unavailable }
    defer { posix_spawn_file_actions_destroy(&actions) }
    guard posix_spawn_file_actions_adddup2(&actions, output, STDOUT_FILENO) == 0,
          posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0,
          posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0 else { throw AskpassError.unavailable }
    var pid: pid_t = 0
    let result = argv.withUnsafeBufferPointer { argv in env.withUnsafeBufferPointer { environment in
        posix_spawn(&pid, path, &actions, nil, UnsafeMutablePointer(mutating: argv.baseAddress!), UnsafeMutablePointer(mutating: environment.baseAddress!))
    } }
    guard result == 0 else { throw AskpassError.unavailable }
    return pid
}

func runAdversarialParent(mode: String, client: String, nextImage: String, record: String) -> Int32 {
    ap_adv_parent_signals()
    let pipe = Pipe()
    let readFD = pipe.fileHandleForReading.fileDescriptor
    _ = fcntl(readFD, F_SETFL, O_NONBLOCK)
    var child: pid_t = 0, reaped = false, status: Int32 = 0, outputCount = 0
    defer {
        if child > 0 && !reaped {
            _ = kill(child, SIGKILL)
            while waitpid(child, &status, 0) < 0 && errno == EINTR {}
        }
    }
    do {
        child = try spawnAdversarial(client, ["--adversarial-client", mode, record, nextImage], output: pipe.fileHandleForWriting.fileDescriptor)
        try pipe.fileHandleForWriting.close()
        let end = now() + 5
        var buffer = [UInt8](repeating: 0, count: 1024)
        while now() < end {
            let count = Darwin.read(readFD, &buffer, buffer.count)
            if count > 0 { outputCount += count; if outputCount > 1024 { return 89 } }
            let waited = waitpid(child, &status, WNOHANG)
            if waited == child { reaped = true; break }
            if waited < 0 && errno != EINTR { return 90 }
            if mode == "parent-exit", FileManager.default.fileExists(atPath: record + ".exit") { _ = kill(child, SIGTERM) }
            if mode.hasPrefix("queued-"), ap_adv_parent_cancelled() != 0 { _ = kill(child, SIGTERM) }
            usleep(5000)
        }
        guard reaped else { return 91 }
        if mode.hasPrefix("raw-") {
            // No-reply headers do not have a send-once notification handshake.
            // Keep this owned parent alive until the host observes broker reject.
            let ackEnd = now() + 2
            while !FileManager.default.fileExists(atPath: record + ".received") && now() < ackEnd && ap_adv_parent_cancelled() == 0 { usleep(5000) }
            guard FileManager.default.fileExists(atPath: record + ".received") else { return 94 }
        }
        while true {
            let count = Darwin.read(readFD, &buffer, buffer.count)
            if count <= 0 { break }; outputCount += count
        }
        let exitCode = status & 0x7f == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
        // Only public lifecycle evidence is written; never captured payload bytes.
        try Data("\(child) \(exitCode) \(outputCount)".utf8).write(to: URL(fileURLWithPath: record), options: .atomic)
        return outputCount == 0 && (exitCode == 0 || mode == "parent-exit") ? 0 : 92
    } catch { return 93 }
}
