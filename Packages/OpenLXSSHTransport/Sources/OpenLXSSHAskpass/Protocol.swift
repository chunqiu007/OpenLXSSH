import Foundation
import Darwin
import COpenLXSSHAskpass

public enum AskpassError: String, Error {
    case identity, unavailable, protocolViolation, bounds, stale, replay, cancelled, timeout, parentExited, helperFailed
}

public enum ChallengeKind: String, Codable, Sendable {
    case unknownMasked, confirmation, notification
    public init(hint: String?) {
        switch hint {
        case "confirm": self = .confirmation
        case "none": self = .notification
        default: self = .unknownMasked
        }
    }
}

public enum Limits {
    public static let promptBytes = 4096
    public static let answerBytes = 1023
    public static let frameBytes = 12_288
    public static let requestsPerSession = 8
    public static let sessions = 8
    public static let requestSeconds: TimeInterval = 120
    public static let sessionSeconds: TimeInterval = 300
    public static let helperSeconds: TimeInterval = 125
    public static func validateAnswer(_ data: Data) throws {
        guard data.count <= answerBytes, !data.contains(0), !data.contains(10), !data.contains(13) else { throw AskpassError.bounds }
    }
}

public struct SessionGrant: Equatable, Sendable {
    public let session: UUID
    public let generation: UInt64
    public let nonce: String
    public init(session: UUID = UUID(), generation: UInt64, nonce: String) {
        self.session = session; self.generation = generation; self.nonce = nonce
    }
}

package struct ControlEvent: Codable {
    package let session: UUID
    package let generation: UInt64
    package let nonce: String
    package let id: UUID
    package let event: String
    package init(grant: SessionGrant, id: UUID = UUID()) {
        session = grant.session; generation = grant.generation; nonce = grant.nonce; self.id = id
        event = "authenticated-v1"
    }
}
package struct ControlAcknowledgement: Codable {
    package let session: UUID
    package let generation: UInt64
    package let id: UUID
    package init(session: UUID, generation: UInt64, id: UUID) {
        self.session = session; self.generation = generation; self.id = id
    }
}

public struct Request: Codable, Equatable, Sendable {
    public let session: UUID
    public let generation: UInt64
    public let nonce: String
    public let id: UUID
    public let prompt: String
    public let hint: String?
    public var kind: ChallengeKind { ChallengeKind(hint: hint) }
    public init(grant: SessionGrant, id: UUID = UUID(), prompt: String, hint: String?) {
        session = grant.session; generation = grant.generation; nonce = grant.nonce
        self.id = id; self.prompt = prompt; self.hint = hint
    }
}

// This state machine knows no passwords, OTPs, prompt patterns or Keychain references.
public struct AuthenticationState {
    public enum Phase: Equatable { case active, waiting(UUID), closed(AskpassError) }
    public let grant: SessionGrant
    public private(set) var phase: Phase = .active
    public private(set) var used: Set<UUID> = []
    public private(set) var deadline: TimeInterval?
    public let expires: TimeInterval
    public init(grant: SessionGrant, now: TimeInterval) { self.grant = grant; expires = now + Limits.sessionSeconds }
    public mutating func begin(_ request: Request, now: TimeInterval) throws {
        guard phase == .active else { throw AskpassError.stale }
        guard now < expires else { close(.timeout); throw AskpassError.timeout }
        guard request.session == grant.session, request.generation == grant.generation, request.nonce == grant.nonce else { throw AskpassError.stale }
        guard !used.contains(request.id) else { throw AskpassError.replay }
        guard used.count < Limits.requestsPerSession, request.prompt.utf8.count <= Limits.promptBytes,
              (request.hint?.utf8.count ?? 0) <= 64, !request.prompt.utf8.contains(0) else { throw AskpassError.bounds }
        used.insert(request.id); phase = .waiting(request.id); deadline = min(expires, now + Limits.requestSeconds)
    }
    public mutating func finish(_ id: UUID, generation: UInt64, now: TimeInterval) throws {
        guard generation == grant.generation, phase == .waiting(id) else { throw AskpassError.stale }
        guard let deadline, now < deadline, now < expires else { close(.timeout); throw AskpassError.timeout }
        phase = .active; self.deadline = nil
    }
    public mutating func close(_ reason: AskpassError) { phase = .closed(reason); deadline = nil }
}

public struct SecretBytes: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    package let data: Data
    public init(_ data: Data) throws { try Limits.validateAnswer(data); self.data = data }
    public var description: String { "<redacted>" }
    public var debugDescription: String { "<redacted>" }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}
public enum Decision: Sendable { case manual(SecretBytes), confirm(Bool), acknowledge, cancel }
package struct Reply: Codable {
    package let session: UUID
    package let generation: UInt64
    package let id: UUID
    package let action: String
    package let answer: Data?
    package init(request: Request, decision: Decision) throws {
        session = request.session; generation = request.generation; id = request.id
        switch (request.kind, decision) {
        case (.unknownMasked, .manual(let bytes)):
            try Limits.validateAnswer(bytes.data); action = "answer"; answer = bytes.data
        case (.confirmation, .confirm(let accepted)):
            action = accepted ? "confirm" : "decline"; answer = nil
        case (.notification, .acknowledge): action = "notice"; answer = nil
        case (_, .cancel): action = "cancel"; answer = nil
        default: throw AskpassError.protocolViolation
        }
    }
}

package func now() -> TimeInterval { ProcessInfo.processInfo.systemUptime }
package func randomBytes(_ count: Int) throws -> Data {
    var bytes = Data(count: count)
    let result = bytes.withUnsafeMutableBytes { ap_random($0.baseAddress, count) }
    guard result == 0 else { throw AskpassError.unavailable }
    return bytes
}
package func nonce() throws -> String { try randomBytes(32).map { String(format: "%02x", $0) }.joined() }
package func identity(_ pid: pid_t) throws -> ap_identity {
    var value = ap_identity()
    guard ap_identity_read(pid, &value) == 0 else { throw AskpassError.identity }
    return value
}
package func same(_ a: ap_identity, _ b: ap_identity) -> Bool { var a = a, b = b; return ap_identity_equal(&a, &b) != 0 }
package func requestPeer(_ token: audit_token_t) throws -> ap_identity {
    var token = token, value = ap_identity()
    guard ap_mach_validate_request(&token, &value) == 0 else { throw AskpassError.identity }
    return value
}
package func replyPeer(_ token: audit_token_t) throws -> ap_identity {
    var token = token, value = ap_identity()
    guard ap_mach_validate_reply(&token, &value) == 0 else { throw AskpassError.identity }
    return value
}
package final class ReplyRight {
    package private(set) var raw: UInt32
    package init(_ raw: UInt32) { self.raw = raw }
    deinit { ap_mach_drop_reply(raw) }
    package func send<T: Encodable>(_ value: T) throws {
        let bytes = try JSONEncoder().encode(value)
        guard !bytes.isEmpty, bytes.count <= Limits.frameBytes else { throw AskpassError.bounds }
        let right = raw; raw = 0 // C consumes the right on success and failure.
        guard bytes.withUnsafeBytes({ ap_mach_send_reply(right, $0.baseAddress, bytes.count) }) == 0 else { throw AskpassError.unavailable }
    }
}
package struct MachEnvelope {
    package let data: Data
    package let token: audit_token_t
    package let reply: ReplyRight?
    package func decode<T: Decodable>(_ type: T.Type) throws -> T {
        guard let value = try? JSONDecoder().decode(type, from: data) else { throw AskpassError.protocolViolation }
        return value
    }
}
package func receiveMach(_ port: UInt32, reply: Bool, timeout: Int32) throws -> MachEnvelope {
    var message = ap_mach_message()
    defer { _ = withUnsafeMutableBytes(of: &message) { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
    let error = ap_mach_receive(port, reply ? 1 : 0, timeout, &message)
    if error == ETIMEDOUT { throw AskpassError.timeout }
    if error == EMSGSIZE { throw AskpassError.bounds }
    guard error == 0 else { throw AskpassError.protocolViolation }
    let bytes = Data(bytes: ap_mach_bytes(&message), count: Int(message.count))
    return MachEnvelope(data: bytes, token: message.token, reply: message.reply_right == 0 ? nil : ReplyRight(message.reply_right))
}
package final class ReplyInbox {
    package let raw: UInt32
    package init(_ raw: UInt32) { self.raw = raw }
    deinit { ap_mach_drop_receive(raw) }
}
package func sendRequest<T: Encodable>(_ value: T, service: String) throws -> ReplyInbox {
    let bytes = try JSONEncoder().encode(value)
    guard !bytes.isEmpty, bytes.count <= Limits.frameBytes else { throw AskpassError.bounds }
    var receive: UInt32 = 0
    guard bytes.withUnsafeBytes({ ap_mach_send_request(service, $0.baseAddress, bytes.count, &receive) }) == 0 else { throw AskpassError.unavailable }
    return ReplyInbox(receive)
}
package func writePipe(_ data: Data, fd: Int32) throws {
    var offset = 0
    while offset < data.count {
        let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw AskpassError.unavailable }
        offset += count
    }
}
