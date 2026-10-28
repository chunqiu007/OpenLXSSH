import Foundation
import CoreFoundation
import RemoteTerminalCore

public enum KeepaliveError: String, Error, Codable, Sendable { case arguments, control, identity, deadline, connection, authentication, cleanup, provenance }
public struct ProcessBirth: Codable, Equatable, Sendable {
    public let pid: Int32, ppid: Int32, uid: UInt32
    public let startSeconds: UInt64, startMicroseconds: UInt64
    public var valid: Bool { pid > 1 && ppid > 0 && startSeconds > 0 && startMicroseconds < 1_000_000 }
}
public enum KRole: String, Codable, Sendable { case normal, blackhole }
public enum KeepaliveNonce {
    public static func fresh(from previous: String) throws -> String {
        guard Syntax.hex(previous,32),let first = previous.first else { throw KeepaliveError.arguments }
        return (first == "0" ? "1" : "0") + previous.dropFirst()
    }
}
public struct KeepaliveOptions: Sendable {
    public let live: Bool, contract: String?, role: KRole?, run: String?
    public static func parse(_ args: [String]) throws -> Self {
        if args.isEmpty || args == ["--help"] { return .init(live: false, contract: nil, role: nil, run: nil) }
        guard args.count == 9, args[0] == "--live-test-only", args[1] == "--contract", args[3] == "--role",
              args[5] == "--run", args[7] == "--authorized-local-fixture", args[8] == "--primary-reviewed",
              let role = KRole(rawValue: args[4]), Syntax.hex(args[6],32) else { throw KeepaliveError.arguments }
        try Syntax.path(args[2])
        guard args[2].hasSuffix("/remote-terminal.json") else { throw KeepaliveError.arguments }
        return .init(live: true,contract: args[2],role: role,run: args[6])
    }
}
public enum KeepaliveControl {
    public static func decode(_ data: Data, op: String, run: String, role: KRole) throws -> [String: Any] {
        guard data.count > 0, data.count < 2048, data.last == 10, data.filter({$0 == 10}).count == 1,
              let text = String(data:data,encoding:.utf8) else { throw KeepaliveError.control }
        let keys = op == "drop-confirmed" ? ["op","run","role","ok","mode","armedAt","armedWall","relayNow","relayWall"] : ["op","run","role","ok"]
        // Closed ACKs contain only scalars; reject escapes/nesting and duplicate property spellings BEFORE JSONSerialization.
        guard !text.contains("\\"),!text.contains("["),!text.contains("]"),text.filter({$0 == "{"}).count == 1,text.filter({$0 == "}"}).count == 1 else { throw KeepaliveError.control }
        let regex = try NSRegularExpression(pattern:"\"([^\"]+)\"\\s*:")
        let matches = regex.matches(in:text,range:NSRange(text.startIndex...,in:text))
        let found = try matches.map { match -> String in
            guard let range = Range(match.range(at:1),in:text) else { throw KeepaliveError.control }; return String(text[range])
        }
        guard found.count == keys.count,Set(found).count == found.count,Set(found) == Set(keys),
              let value = try JSONSerialization.jsonObject(with:data) as? [String:Any],Set(value.keys) == Set(keys),
              value["op"] as? String == op,value["run"] as? String == run,value["role"] as? String == role.rawValue,
              let ok = value["ok"] as? NSNumber,CFGetTypeID(ok) == CFBooleanGetTypeID(),ok.boolValue else { throw KeepaliveError.control }
        if op == "drop-confirmed" {
            guard value["mode"] as? String == "drop" else { throw KeepaliveError.control }
            for key in ["armedAt","armedWall","relayNow","relayWall"] {
                guard let number = value[key] as? NSNumber,CFGetTypeID(number) != CFBooleanGetTypeID(),number.doubleValue.isFinite,number.doubleValue > 0 else { throw KeepaliveError.control }
            }
        }
        return value
    }
}
public struct KeepaliveReport: Codable, Sendable {
    public var role: KRole
    public var serverAliveInterval = 2, serverAliveCountMax = 2
    public var shellACK = false, freshACK = false
    public var authenticationRequests = 0, trustRequests = 0
    public var quietSeconds: Double = 0, quietSamples = 0, sameTokenPIDDuringQuiet = false, quietApplicationOutputEvents = 0
    public var relayConsumerClockOffset: Double?, relayConsumerClockDisagreement: Double?
    public var dropToExitSeconds: Double?, lastExitCode: Int32?, naturalState: String?
    public var sessionID: UUID?, generation: UInt64?, ssh: ProcessBirth?
    public var armMetadata: String?
    public var stopBeforeResult = false, cancelBeforeResult = false, deadlineBeforeResult = false
    public var closed = false, pidGone = false, fdReturnedToBaseline = false
    public var failure: KeepaliveError?
    public init(role: KRole) { self.role = role }
}
