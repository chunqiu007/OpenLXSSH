import Foundation
import CoreFoundation

public enum NativeLivenessRole: String, Codable, Sendable {
    case normal, blackhole, maxSessions = "maxsessions"
    public var relayRole: String { self == .blackhole ? "blackhole" : "normal" }
}
public enum NativeLivenessControlError: String, Error, Sendable { case arguments, schema, replay, order, clock, cancelled, deadline, owner, evidence }
/// Closed CLI: one fixed approved keyonly fixture, never caller-selected endpoints or commands.
public struct NativeLivenessOptions: Equatable, Sendable {
    public let contractPath: String?
    public let ownerPID: Int32?
    public static func parse(_ arguments: [String], buildRoot: String) throws -> Self {
        if arguments.isEmpty || arguments == ["--help"] { return Self(contractPath: nil, ownerPID: nil) }
        guard arguments.count == 8, arguments[0] == "--live-native-liveness",
              arguments[1] == "--authorized-local-fixture", arguments[2] == "--primary-reviewed",
              arguments[3] == "--contract", arguments[5] == "--owner-pid",
              let owner = Int32(arguments[6]), owner > 1, arguments[7] == "--private-pipes" else {
            throw NativeLivenessControlError.arguments
        }
        try NativeLivenessContract.checkPath(arguments[4], buildRoot: buildRoot)
        return Self(contractPath: arguments[4], ownerPID: owner)
    }
}
public enum NativeLivenessJSON {
    /// Flat public control/material-reference schema only. Reject duplicate/escaped field names,
    /// noncanonical booleans masquerading as integers and nesting. Contract JSON may contain
    /// legal whitespace; private PIPE framing is separately checked by frameObject.
    public static func object(_ data: Data, keys: Set<String>) throws -> [String: Any] {
        guard !data.isEmpty, data.count < 4096, let text = String(data: data, encoding: .utf8),
              !text.contains("\\"), !text.contains("["), !text.contains("]"),
              text.filter({ $0 == "{" }).count == 1, text.filter({ $0 == "}" }).count == 1 else { throw NativeLivenessControlError.schema }
        let regex = try NSRegularExpression(pattern: "\"([^\"]+)\"\\s*:")
        let matches = regex.matches(in: text, range: NSRange(text.startIndex..., in: text))
        let names = try matches.map { match -> String in
            guard let range = Range(match.range(at: 1), in: text) else { throw NativeLivenessControlError.schema }
            return String(text[range])
        }
        guard names.count == keys.count, Set(names) == keys, Set(names).count == names.count,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(value.keys) == keys else {
            throw NativeLivenessControlError.schema
        }
        return value
    }
    public static func frameObject(_ data: Data, keys: Set<String>) throws -> [String: Any] {
        guard !data.isEmpty, data.count < 2048, data.last == 10, data.filter({ $0 == 10 }).count == 1 else {
            throw NativeLivenessControlError.schema
        }
        return try object(data, keys: keys)
    }
    public static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              String(cString: number.objCType) != "d", String(cString: number.objCType) != "f" else { return nil }
        return Int(exactly: number.int64Value)
    }
    public static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }
    public static func finite(_ value: Any?) -> Double? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite else { return nil }
        return number.doubleValue
    }
}

/// Public material reference only. Disposable secrets remain inside the existing stable selected
/// reader in the consumer. Each role gets a distinct fresh case, nonce and original generation.
public struct NativeLivenessContract: Codable, Equatable, Sendable {
    public let schema: Int
    public let taskID: String
    public let run: String
    public let role: NativeLivenessRole
    public let materialContractPath: String
    public let issuedAt: Double
    public let collectedAt: Double
    public static let keys: Set<String> = ["schema", "taskID", "run", "role", "materialContractPath", "issuedAt", "collectedAt"]
    public static func hex(_ text: String, count: Int) -> Bool {
        text.utf8.count == count && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    public static func checkPath(_ path: String, buildRoot: String) throws {
        let prefix = buildRoot + "/native-liveness-case-", suffix = "/liveness.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix),
              hex(String(path.dropFirst(prefix.count).dropLast(suffix.count)), count: 12),
              !path.contains("/../"), !path.contains("/./"), !path.contains("//") else { throw NativeLivenessControlError.arguments }
    }
    public func validate(path: String, buildRoot: String, now: Double) throws {
        try Self.checkPath(path, buildRoot: buildRoot)
        try ShellProbeCommand.checkContractPath(materialContractPath, buildRoot: buildRoot)
        guard schema == 1, taskID == "NATIVE-LIVENESS-SUPERVISOR-R2", Self.hex(run, count: 32),
              now.isFinite, issuedAt.isFinite, collectedAt.isFinite, collectedAt > 0,
              0 <= now - issuedAt, now - issuedAt <= 120,
              0 <= now - collectedAt, now - collectedAt <= 120, collectedAt <= issuedAt else {
            throw NativeLivenessControlError.schema
        }
    }
}
public struct NativeLivenessProof: Codable, Equatable, Sendable {
    public let started: Int
    public let confirmed: Int
    public let rejected: Int
    public let freed: Int
    public let helpers: Int
    public let pending: Bool
    public init(started: Int, confirmed: Int, rejected: Int, freed: Int, helpers: Int, pending: Bool) {
        self.started = started; self.confirmed = confirmed; self.rejected = rejected
        self.freed = freed; self.helpers = helpers; self.pending = pending
    }
    public var settled: Bool {
        started >= 2 && confirmed >= 0 && rejected >= 0 && confirmed + rejected == started &&
            freed == confirmed && helpers == 0 && !pending
    }
}
/// One owner, one waiter, fixed inbound order. Duplicate/stale ACKs cannot advance another case.
public struct NativeLivenessControlSequence: Sendable {
    public let run: String
    public let role: NativeLivenessRole
    public let session: String
    private var next = 1
    private var lastStamp: Double = 0
    public init(run: String, role: NativeLivenessRole, session: String) {
        self.run = run; self.role = role; self.session = session
    }
    public mutating func accept(op: String, sequence: Int, run: String, role: NativeLivenessRole,
                                session: String, stamp: Double) throws {
        let expected = ["binding-confirmed", self.role == .blackhole ? "drop-confirmed" : "normal-ready", "result-recorded"]
        guard next <= expected.count, sequence == next else { throw NativeLivenessControlError.replay }
        guard op == expected[next - 1], run == self.run, role == self.role, session == self.session else {
            throw NativeLivenessControlError.order
        }
        guard stamp.isFinite, stamp > lastStamp else { throw NativeLivenessControlError.clock }
        lastStamp = stamp; next += 1
    }
}
/// Additional fail-closed causal bounds. No wall-clock point estimate is used for proof age.
public struct NativeLivenessArmAge: Codable, Equatable, Sendable {
    public let offsetLower: Double
    public let offsetUpper: Double
    public let minimumAge: Double
    public let maximumAge: Double
    public init(proofLower: Double, proofUpper: Double, consumerSent: Double, consumerACK: Double,
                relayArmed: Double, relayReply: Double) throws {
        guard [proofLower, proofUpper, consumerSent, consumerACK, relayArmed, relayReply].allSatisfy({ $0.isFinite && $0 > 0 }),
              proofLower <= proofUpper, proofUpper <= consumerSent, consumerSent <= consumerACK,
              relayArmed <= relayReply else { throw NativeLivenessControlError.clock }
        offsetLower = relayReply - consumerACK
        offsetUpper = relayArmed - consumerSent
        minimumAge = relayArmed - (proofUpper + offsetUpper)
        maximumAge = relayArmed - (proofLower + offsetLower)
        guard offsetLower <= offsetUpper, minimumAge >= 0, minimumAge <= maximumAge, maximumAge <= 1.5 else {
            throw NativeLivenessControlError.clock
        }
    }
}

public struct NativeLivenessClockEvidence: Codable, Equatable, Sendable {
    public let offset: Double
    public let disagreement: Double
    public let elapsedAtACK: Double
    public init(armedAt: Double, armedWall: Double, relayNow: Double, relayWall: Double,
                localNow: Double, localWall: Double) throws {
        guard [armedAt, armedWall, relayNow, relayWall, localNow, localWall].allSatisfy({ $0.isFinite && $0 > 0 }) else {
            throw NativeLivenessControlError.clock
        }
        let transit = localWall - relayWall
        let elapsed = localWall - armedWall, relayElapsed = relayNow - armedAt
        let disagreement = abs((relayWall - armedWall) - relayElapsed)
        guard transit >= 0, transit < 2, elapsed >= 0, elapsed < 2,
              relayElapsed >= 0, relayElapsed <= elapsed + 0.2, disagreement < 0.2 else {
            throw NativeLivenessControlError.clock
        }
        offset = localNow - relayNow - transit; self.disagreement = disagreement; elapsedAtACK = elapsed
    }
}
