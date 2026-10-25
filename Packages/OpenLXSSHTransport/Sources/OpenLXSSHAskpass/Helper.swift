import Foundation
import Darwin
import COpenLXSSHAskpass

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
              let nonce = environment["AP_NONCE"], nonce.utf8.count == 64 else { throw AskpassError.protocolViolation }
        self.service = service; brokerPID = pid; brokerSeconds = seconds; brokerMicros = micros
        grant = SessionGrant(session: session, generation: generation, nonce: nonce)
    }
}
func exchange(_ request: Request, context: HelperContext) throws -> Reply {
    let inbox = try sendRequest(request, service: context.service)
    let envelope = try receiveMach(inbox.raw, reply: true, timeout: Int32(Limits.helperSeconds * 1000))
    let broker = try replyPeer(envelope.token)
    guard broker.pid == context.brokerPID, broker.seconds == context.brokerSeconds,
          broker.microseconds == context.brokerMicros else { throw AskpassError.identity }
    let reply = try envelope.decode(Reply.self)
    guard reply.session == request.session, reply.generation == request.generation, reply.id == request.id else { throw AskpassError.stale }
    return reply
}

public func runAskpassHelper(arguments: [String], environment: [String: String]) -> Int32 {
    do {
        if arguments == ["--authenticated-event", "v1"] {
            let context = try HelperContext(environment: environment)
            let event = ControlEvent(grant: context.grant)
            let inbox = try sendRequest(event, service: context.service)
            let response = try receiveMach(inbox.raw, reply: true, timeout: 5000)
            let broker = try replyPeer(response.token)
            guard broker.pid == context.brokerPID, broker.seconds == context.brokerSeconds,
                  broker.microseconds == context.brokerMicros else { throw AskpassError.identity }
            let ack = try response.decode(ControlAcknowledgement.self)
            guard ack.session == event.session, ack.generation == event.generation, ack.id == event.id else { throw AskpassError.stale }
            return 0
        }
        // No read from stdin anywhere on this helper entry path. The sole argument
        // is untrusted display text, never an authentication-method discriminator.
        guard arguments.count == 1, arguments[0].utf8.count <= Limits.promptBytes,
              !arguments[0].utf8.contains(0), (environment["SSH_ASKPASS_PROMPT"]?.utf8.count ?? 0) <= 64 else { throw AskpassError.bounds }
        let context = try HelperContext(environment: environment)
        let request = Request(grant: context.grant, prompt: arguments[0], hint: environment["SSH_ASKPASS_PROMPT"])
        let reply = try exchange(request, context: context)
        switch (request.kind, reply.action, reply.answer) {
        case (.unknownMasked, "answer", .some(let bytes)):
            try Limits.validateAnswer(bytes); try writePipe(bytes, fd: STDOUT_FILENO); return 0
        case (.confirmation, "confirm", .none), (.notification, "notice", .none): return 0
        case (.confirmation, "decline", .none), (_, "cancel", .none): return 1
        default: throw AskpassError.protocolViolation
        }
    } catch {
        // Error categories are intentionally not interpolated with prompt or reply.
        let text = "askpass: unavailable, rejected, or cancelled\n"
        _ = text.withCString { Darwin.write(STDERR_FILENO, $0, strlen($0)) }
        return 70
    }
}
