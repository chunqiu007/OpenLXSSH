import Foundation
import Darwin
import AskpassPOSIX

public enum ProbeError: String, Error {
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
    public static let requestSeconds: TimeInterval = 2
    public static let sessionSeconds: TimeInterval = 8
    public static let helperSeconds: TimeInterval = 4
    public static func validateAnswer(_ data: Data) throws {
        guard data.count <= answerBytes, !data.contains(0), !data.contains(10), !data.contains(13) else { throw ProbeError.bounds }
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
    public enum Phase: Equatable { case active, waiting(UUID), closed(ProbeError) }
    public let grant: SessionGrant
    public private(set) var phase: Phase = .active
    public private(set) var used: Set<UUID> = []
    public private(set) var deadline: TimeInterval?
    public let expires: TimeInterval
    public init(grant: SessionGrant, now: TimeInterval) { self.grant = grant; expires = now + Limits.sessionSeconds }
    public mutating func begin(_ request: Request, now: TimeInterval) throws {
        guard phase == .active else { throw ProbeError.stale }
        guard now < expires else { close(.timeout); throw ProbeError.timeout }
        guard request.session == grant.session, request.generation == grant.generation, request.nonce == grant.nonce else { throw ProbeError.stale }
        guard !used.contains(request.id) else { throw ProbeError.replay }
        guard used.count < Limits.requestsPerSession, request.prompt.utf8.count <= Limits.promptBytes,
              (request.hint?.utf8.count ?? 0) <= 64, !request.prompt.utf8.contains(0) else { throw ProbeError.bounds }
        used.insert(request.id); phase = .waiting(request.id); deadline = min(expires, now + Limits.requestSeconds)
    }
    public mutating func finish(_ id: UUID, generation: UInt64, now: TimeInterval) throws {
        guard generation == grant.generation, phase == .waiting(id) else { throw ProbeError.stale }
        guard let deadline, now < deadline, now < expires else { close(.timeout); throw ProbeError.timeout }
        phase = .active; self.deadline = nil
    }
    public mutating func close(_ reason: ProbeError) { phase = .closed(reason); deadline = nil }
}

public enum Decision: Sendable { case manual(Data), confirm(Bool), acknowledge, cancel }
struct Reply: Codable {
    let session: UUID
    let generation: UInt64
    let id: UUID
    let action: String
    let answer: Data?
    init(request: Request, decision: Decision) throws {
        session = request.session; generation = request.generation; id = request.id
        switch (request.kind, decision) {
        case (.unknownMasked, .manual(let bytes)):
            try Limits.validateAnswer(bytes); action = "answer"; answer = bytes
        case (.confirmation, .confirm(let accepted)):
            action = accepted ? "confirm" : "decline"; answer = nil
        case (.notification, .acknowledge): action = "notice"; answer = nil
        case (_, .cancel): action = "cancel"; answer = nil
        default: throw ProbeError.protocolViolation
        }
    }
}

func now() -> TimeInterval { ProcessInfo.processInfo.systemUptime }
func randomBytes(_ count: Int) throws -> Data {
    var bytes = Data(count: count)
    let result = bytes.withUnsafeMutableBytes { ap_random($0.baseAddress, count) }
    guard result == 0 else { throw ProbeError.unavailable }
    return bytes
}
func nonce() throws -> String { try randomBytes(32).map { String(format: "%02x", $0) }.joined() }
func identity(_ pid: pid_t) throws -> ap_identity {
    var value = ap_identity()
    guard ap_identity_read(pid, &value) == 0 else { throw ProbeError.identity }
    return value
}
func same(_ a: ap_identity, _ b: ap_identity) -> Bool { var a = a, b = b; return ap_identity_equal(&a, &b) != 0 }
func signed(_ expected: ap_identity) throws { var value = expected; guard ap_signed_process(&value) == 0 else { throw ProbeError.identity } }
func requestPeer(_ token: audit_token_t) throws -> ap_identity {
    var token = token, value = ap_identity()
    guard ap_mach_validate_request(&token, &value) == 0 else { throw ProbeError.identity }
    return value
}
func replyPeer(_ token: audit_token_t) throws -> ap_identity {
    var token = token, value = ap_identity()
    guard ap_mach_validate_reply(&token, &value) == 0 else { throw ProbeError.identity }
    return value
}
final class ReplyRight {
    private(set) var raw: UInt32
    init(_ raw: UInt32) { self.raw = raw }
    deinit { ap_mach_drop_reply(raw) }
    func send<T: Encodable>(_ value: T) throws {
        let bytes = try JSONEncoder().encode(value)
        guard !bytes.isEmpty, bytes.count <= Limits.frameBytes else { throw ProbeError.bounds }
        let right = raw; raw = 0 // C consumes the right on success and failure.
        guard bytes.withUnsafeBytes({ ap_mach_send_reply(right, $0.baseAddress, bytes.count) }) == 0 else { throw ProbeError.unavailable }
    }
}
struct MachEnvelope {
    let data: Data
    let token: audit_token_t
    let reply: ReplyRight?
    func decode<T: Decodable>(_ type: T.Type) throws -> T {
        guard let value = try? JSONDecoder().decode(type, from: data) else { throw ProbeError.protocolViolation }
        return value
    }
}
func receiveMach(_ port: UInt32, reply: Bool, timeout: Int32) throws -> MachEnvelope {
    var message = ap_mach_message()
    defer { _ = withUnsafeMutableBytes(of: &message) { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
    let error = ap_mach_receive(port, reply ? 1 : 0, timeout, &message)
    if error == ETIMEDOUT { throw ProbeError.timeout }
    if error == EMSGSIZE { throw ProbeError.bounds }
    guard error == 0 else { throw ProbeError.protocolViolation }
    let bytes = Data(bytes: ap_mach_bytes(&message), count: Int(message.count))
    return MachEnvelope(data: bytes, token: message.token, reply: message.reply_right == 0 ? nil : ReplyRight(message.reply_right))
}
final class ReplyInbox {
    let raw: UInt32
    init(_ raw: UInt32) { self.raw = raw }
    deinit { ap_mach_drop_receive(raw) }
}
func sendRequest<T: Encodable>(_ value: T, service: String) throws -> ReplyInbox {
    let bytes = try JSONEncoder().encode(value)
    guard !bytes.isEmpty, bytes.count <= Limits.frameBytes else { throw ProbeError.bounds }
    var receive: UInt32 = 0
    guard bytes.withUnsafeBytes({ ap_mach_send_request(service, $0.baseAddress, bytes.count, &receive) }) == 0 else { throw ProbeError.unavailable }
    return ReplyInbox(receive)
}
func writePipe(_ data: Data, fd: Int32) throws {
    var offset = 0
    while offset < data.count {
        let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw ProbeError.unavailable }
        offset += count
    }
}
func readAvailable(_ fd: Int32, into data: inout Data, limit: Int = Limits.frameBytes, pty: Bool = false) throws {
    var buffer = [UInt8](repeating: 0, count: 2048)
    while true {
        let count = Darwin.read(fd, &buffer, buffer.count)
        if count < 0 && errno == EINTR { continue }
        if count < 0 && (errno == EAGAIN || (pty && errno == EIO)) { return }
        guard count >= 0 else { throw ProbeError.unavailable }
        if count == 0 { return }
        guard data.count + count <= limit else { throw ProbeError.bounds }
        data.append(contentsOf: buffer.prefix(count))
    }
}
func spawn(path: String, arguments: [String], environment: [String: String], suspended: Bool = false, newGroup: Bool = true) throws -> (pid_t, Int32, Int32) {
    let argv = ([path] + arguments).map { strdup($0) } + [nil]
    let envp = environment.sorted(by: { $0.key < $1.key }).map { strdup("\($0.key)=\($0.value)") } + [nil]
    defer { for pointer in argv + envp { free(pointer) } }
    var pid: pid_t = -1, input: Int32 = -1, output: Int32 = -1
    let error = path.withCString { path in argv.withUnsafeBufferPointer { args in envp.withUnsafeBufferPointer { env in
        ap_spawn(path, UnsafeMutablePointer(mutating: args.baseAddress!), UnsafeMutablePointer(mutating: env.baseAddress!), suspended ? 1 : 0, newGroup ? 1 : 0, &pid, &input, &output)
    } } }
    guard error == 0 else { throw ProbeError.unavailable }
    return (pid, input, output)
}
public func executablePath() throws -> String {
    var bytes = [CChar](repeating: 0, count: 4096)
    guard ap_executable(&bytes, bytes.count) == 0 else { throw ProbeError.unavailable }
    return String(decoding: bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
}
