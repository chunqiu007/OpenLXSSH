import Foundation
import Darwin
import AskpassPOSIX

struct HelperContext {
    let service: String
    let brokerPID: Int32
    let brokerSeconds: UInt64
    let brokerMicros: UInt64
    var grant: SessionGrant
    init(environment: [String: String]) throws {
        guard let service = environment["AP_SERVICE"], service.utf8.count < 128,
              let pid = environment["AP_BROKER_PID"].flatMap(Int32.init), pid > 0,
              let seconds = environment["AP_BROKER_SECONDS"].flatMap(UInt64.init),
              let micros = environment["AP_BROKER_MICROS"].flatMap(UInt64.init),
              let session = environment["AP_SESSION"].flatMap(UUID.init(uuidString:)),
              let generation = environment["AP_GENERATION"].flatMap(UInt64.init), generation > 0,
              let nonce = environment["AP_NONCE"], nonce.utf8.count == 64 else { throw ProbeError.protocolViolation }
        self.service = service; brokerPID = pid; brokerSeconds = seconds; brokerMicros = micros
        grant = SessionGrant(session: session, generation: generation, nonce: nonce)
    }
}
func exchange(_ request: Request, context: HelperContext) throws -> Reply {
    let inbox = try sendRequest(request, service: context.service)
    let envelope = try receiveMach(inbox.raw, reply: true, timeout: Int32(Limits.helperSeconds * 1000))
    let broker = try replyPeer(envelope.token)
    guard broker.pid == context.brokerPID, broker.seconds == context.brokerSeconds,
          broker.microseconds == context.brokerMicros else { throw ProbeError.identity }
    let reply = try envelope.decode(Reply.self)
    guard reply.session == request.session, reply.generation == request.generation, reply.id == request.id else { throw ProbeError.stale }
    return reply
}

public func runAskpassHelper(arguments: [String], environment: [String: String]) -> Int32 {
    do {
        // No read from stdin anywhere on this helper entry path. The sole argument
        // is untrusted display text, never an authentication-method discriminator.
        guard arguments.count == 1, arguments[0].utf8.count <= Limits.promptBytes,
              !arguments[0].utf8.contains(0), (environment["SSH_ASKPASS_PROMPT"]?.utf8.count ?? 0) <= 64 else { throw ProbeError.bounds }
        let context = try HelperContext(environment: environment)
        let request = Request(grant: context.grant, prompt: arguments[0], hint: environment["SSH_ASKPASS_PROMPT"])
        let reply = try exchange(request, context: context)
        switch (request.kind, reply.action, reply.answer) {
        case (.unknownMasked, "answer", .some(let bytes)):
            try Limits.validateAnswer(bytes); try writePipe(bytes, fd: STDOUT_FILENO); return 0
        case (.confirmation, "confirm", .none), (.notification, "notice", .none): return 0
        case (.confirmation, "decline", .none), (_, "cancel", .none): return 1
        default: throw ProbeError.protocolViolation
        }
    } catch {
        // Error categories are intentionally not interpolated with prompt or reply.
        let text = "askpass: unavailable, rejected, or cancelled\n"
        _ = text.withCString { Darwin.write(STDERR_FILENO, $0, strlen($0)) }
        return 70
    }
}

// Authenticated-but-malicious fixture clients exercise protocol rejection after
// code verification. This is not a product helper mode or a real SSH fixture.
public func runClientFixture(mode: String, environment: [String: String]) -> Int32 {
    do {
        var context = try HelperContext(environment: environment)
        let original = context.grant
        if mode == "wrong-nonce" { context.grant = SessionGrant(session: original.session, generation: original.generation, nonce: String(repeating: "0", count: 64)) }
        if mode == "wrong-generation" { context.grant = SessionGrant(session: original.session, generation: original.generation + 1, nonce: original.nonce) }
        if mode == "wrong-session" { context.grant = SessionGrant(session: UUID(), generation: original.generation, nonce: original.nonce) }
        let request = Request(grant: context.grant, prompt: "fixture challenge", hint: nil)
        if mode == "queued-exec" {
            let inbox = try sendRequest(request, service: context.service)
            let path = URL(fileURLWithPath: try executablePath()).deletingLastPathComponent().appendingPathComponent("openlxssh-askpass-probe").path
            withExtendedLifetime(inbox) {
                let argv = [strdup(path), strdup("--standby"), nil]
                defer { argv.forEach { free($0) } }
                path.withCString { path in argv.withUnsafeBufferPointer { _ = execv(path, $0.baseAddress!) } }
            }
            return 73
        }
        if mode == "crash" {
            let inbox = try sendRequest(request, service: context.service)
            usleep(100_000)
            withExtendedLifetime(inbox) { }; return 71
        }
        if ["oversize", "complex", "ool"].contains(mode) {
            let kind: Int32 = mode == "complex" ? 1 : (mode == "ool" ? 2 : 0)
            guard ap_mach_test_invalid(context.service, kind) == 0 else { throw ProbeError.unavailable }
        } else if mode == "budget" {
            for _ in 0..<Limits.requestsPerSession { _ = try exchange(Request(grant: context.grant, prompt: "fixture", hint: nil), context: context) }
            do { _ = try exchange(Request(grant: context.grant, prompt: "fixture", hint: nil), context: context); return 72 } catch { }
        } else if mode == "replay" {
            _ = try exchange(request, context: context)
            do { _ = try exchange(request, context: context); return 72 } catch { }
        } else {
            do { _ = try exchange(request, context: context); return 72 } catch { }
        }
        try writePipe(Data("probe-ok".utf8), fd: STDOUT_FILENO); return 0
    } catch { return 73 }
}

public func runControlledFixture(arguments: [String], environment: [String: String]) -> Int32 {
    guard arguments.count == 2 else { return 74 }
    ap_fixture_signals()
    let mode = arguments[0], helper = arguments[1]
    // Only this synthetic parent, never the askpass helper, consumes this anonymous
    // pipe. Expected random answers never appear in argv/env, snapshots or logs.
    var expected = Data(), buffer = [UInt8](repeating: 0, count: 1024)
    while true {
        let count = Darwin.read(STDIN_FILENO, &buffer, buffer.count)
        if count < 0 && errno == EINTR { continue }
        guard count >= 0, expected.count + max(0, count) <= Limits.answerBytes else { return 75 }
        if count == 0 { break }; expected.append(contentsOf: buffer.prefix(count))
    }
    func invoke(_ prompt: String, hint: String?, client: String? = nil) throws -> (Int32, Data) {
        var env = environment
        env.removeValue(forKey: "SSH_ASKPASS_PROMPT")
        if let hint { env["SSH_ASKPASS_PROMPT"] = hint }
        let args = client.map { ["--client-fixture", $0] } ?? [prompt]
        let child = try spawn(path: helper, arguments: args, environment: env, newGroup: false)
        // Keep stdin open and empty: a helper that accidentally reads it hangs and
        // fails the bounded fixture. Legitimate helper requests complete regardless.
        defer { Darwin.close(child.1); Darwin.close(child.2) }
        var bytes = Data(), status: Int32 = 0
        let deadline = now() + 6
        while now() < deadline {
            try readAvailable(child.2, into: &bytes, limit: Limits.answerBytes)
            if ap_wait(child.0, &status) == 1 { try readAvailable(child.2, into: &bytes, limit: Limits.answerBytes); return (ap_exit_status(status), bytes) }
            if ap_fixture_cancelled() != 0 { _ = kill(child.0, SIGTERM) }
            usleep(5_000)
        }
        _ = kill(child.0, SIGKILL)
        for _ in 0..<100 { if ap_wait(child.0, &status) == 1 { break }; usleep(5_000) }
        throw ProbeError.timeout
    }
    do {
        if mode == "max-prompt" {
            let result = try invoke(String(repeating: "x", count: Limits.promptBytes), hint: nil)
            guard result.0 == 0, result.1 == expected else { return 89 }
        } else if ["wrong-nonce", "wrong-generation", "wrong-session", "replay", "oversize", "complex", "ool", "budget"].contains(mode) {
            let result = try invoke("", hint: nil, client: mode)
            guard result.0 == 0, result.1 == Data("probe-ok".utf8) else { return 76 }
        } else if mode == "queued-exec" {
            _ = try invoke("", hint: nil, client: mode); return 0
        } else if mode == "crash" {
            _ = try invoke("", hint: nil, client: "crash")
            // Deliberately stubborn parent proves broker cancellation is not just
            // a nonzero helper status. SIGTERM handler keeps it alive until KILL.
            while true { usleep(10_000) }
        } else if mode == "nested" {
            let result = try invoke("fixture challenge", hint: nil, client: "nested")
            guard result.0 == 0, result.1 == Data("probe-ok".utf8) else { return 78 }
        } else if mode == "bad-signature" {
            let result = try invoke("fixture challenge", hint: nil)
            guard result.0 != 0, result.1.isEmpty else { return 79 }
        } else {
            let result = try invoke(mode == "empty" ? "" : "fixture challenge", hint: nil)
            guard result.0 == 0, result.1 == expected else { return 80 }
            if mode == "normal" {
                let unknown = try invoke("Password: this text grants no method knowledge", hint: "unrecognised")
                guard unknown.0 == 0, unknown.1 == expected else { return 81 }
                let confirmation = try invoke("fixture confirmation", hint: "confirm")
                guard confirmation.0 == 0, confirmation.1.isEmpty else { return 82 }
                let notice = try invoke("fixture notification", hint: "none")
                guard notice.0 == 0, notice.1.isEmpty else { return 83 }
            }
        }
        guard ap_fixture_cancelled() == 0 else { return 84 }
        try writePipe(Data("fixture-ok".utf8), fd: STDOUT_FILENO); return 0
    } catch { return 85 }
}

// Its helper is a grandchild of the registered fixture, not a direct child.
public func runNestedFixture(environment: [String: String]) -> Int32 {
    do {
        let child = try spawn(path: executablePath(), arguments: ["--client-fixture", "wrong-parent"], environment: environment, newGroup: false)
        Darwin.close(child.1); defer { Darwin.close(child.2) }
        var bytes = Data(), status: Int32 = 0
        let deadline = now() + 2
        while now() < deadline {
            try readAvailable(child.2, into: &bytes)
            if ap_wait(child.0, &status) == 1 { try readAvailable(child.2, into: &bytes); guard ap_exit_status(status) == 0, bytes == Data("probe-ok".utf8) else { return 86 }; try writePipe(bytes, fd: STDOUT_FILENO); return 0 }
            usleep(5_000)
        }
        _ = kill(child.0, SIGKILL); for _ in 0..<100 { if ap_wait(child.0, &status) == 1 { break }; usleep(5_000) }
        return 87
    } catch { return 88 }
}
