import CryptoKit
import CoreFoundation
import Foundation

public enum TerminalCheckError: String, Error, Codable, Sendable {
    case arguments, authorization, contract, provenance, unsafeFile, signature, authRequest, trustRequest
    case connection, unexpectedFrame, deadline, cancelled, input, remoteFailure, cleanup, integrity
}

public struct TerminalOptions: Sendable {
    public enum Action: Sendable { case help, validate, live }
    public let action: Action
    public let contractPath: String?
    public static func parse(_ args: [String]) throws -> Self {
        if args.isEmpty || args == ["--help"] { return Self(action: .help, contractPath: nil) }
        guard let first = args.first, ["validate", "--live"].contains(first) else { throw TerminalCheckError.arguments }
        var path: String?, authorized = false, ready = false, index = 1
        while index < args.count {
            switch args[index] {
            case "--contract":
                guard path == nil, index + 1 < args.count else { throw TerminalCheckError.arguments }
                index += 1; path = args[index]; try Syntax.path(path!)
                guard path!.hasSuffix("/remote-terminal.json") else { throw TerminalCheckError.arguments }
            case "--authorized-local-fixture": guard !authorized else { throw TerminalCheckError.arguments }; authorized = true
            case "--engine-ready": guard !ready else { throw TerminalCheckError.arguments }; ready = true
            default: throw TerminalCheckError.arguments
            }
            index += 1
        }
        guard let path else { throw TerminalCheckError.arguments }
        if first == "--live" {
            guard authorized && ready else { throw TerminalCheckError.authorization }
            return Self(action: .live, contractPath: path)
        }
        guard !authorized && !ready else { throw TerminalCheckError.arguments }
        return Self(action: .validate, contractPath: path)
    }
}

public enum Syntax {
    public static func hex(_ value: String, _ count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    public static func path(_ path: String) throws {
        guard path.hasPrefix("/"), path != "/", !path.hasSuffix("/"), path.utf8.count < 4096,
              !path.contains("$"), !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw TerminalCheckError.unsafeFile }
    }
    public static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    public static func validateMounts(binds: Any?, mounts: Any?, project: String) throws {
        guard project.hasPrefix("openlxssh-fixture-"), Syntax.hex(String(project.dropFirst("openlxssh-fixture-".count)), 12) else { throw TerminalCheckError.provenance }
        let volume = project + "_key-data"
        guard let binds = binds as? [String], binds == [volume + ":/fixture:rw"],
              let mounts = mounts as? [[String: Any]], mounts.count == 1 else { throw TerminalCheckError.provenance }
        let mount = mounts[0]
        guard Set(mount.keys) == ["Type", "Name", "Source", "Destination", "Driver", "Mode", "RW", "Propagation"],
              mount["Type"] as? String == "volume", mount["Name"] as? String == volume,
              mount["Source"] as? String == "/var/lib/docker/volumes/" + volume + "/_data",
              mount["Destination"] as? String == "/fixture", mount["Driver"] as? String == "local",
              mount["Mode"] as? String == "rw",
              let rw = mount["RW"] as? NSNumber, CFGetTypeID(rw) == CFBooleanGetTypeID(), rw.boolValue,
              mount["Propagation"] as? String == "" else { throw TerminalCheckError.provenance }
    }
    public static func validateImage(_ data: Data, contract: TerminalContract) throws {
        guard let items = try JSONSerialization.jsonObject(with: data) as? [[String: Any]], items.count == 1 else { throw TerminalCheckError.provenance }
        let item = items[0]
        guard item["Id"] as? String == contract.imageID, item["Architecture"] as? String == "arm64", item["Os"] as? String == "linux",
              let config = item["Config"] as? [String: Any], let labels = config["Labels"] as? [String: String],
              labels["org.openlxssh.fixture"] == "env-fixture-a", labels["org.openlxssh.fixture.base"] == contract.baseImage else { throw TerminalCheckError.provenance }
    }
    public static func object(_ data: Data, keys: Set<String>) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys else { throw TerminalCheckError.contract }
        return object
    }
    public static func fingerprint(_ value: String) -> Bool {
        guard value.hasPrefix("SHA256:"), let data = Data(base64Encoded: String(value.dropFirst(7)) + "=") else { return false }
        return data.count == 32 && data.base64EncodedString().dropLast() == value.dropFirst(7)
    }
}

public struct TerminalContract: Codable, Sendable {
    public let schema: Int
    public let taskID: String
    public let service: String
    public let host: String
    public let port: Int
    public let user: String
    public let key: String
    public let credentialDirectory: String
    public let expectedFingerprint: String
    public let baseImage: String
    public let imageID: String
    public let containerID: String
    public let project: String
    public let networkID: String
    public let context: String
    public let endpoint: String
    public let collectedAt: Double
    public let expiresAt: Double
    public static let keys: Set<String> = ["schema", "taskID", "service", "host", "port", "user", "key", "credentialDirectory", "expectedFingerprint", "baseImage", "imageID", "containerID", "project", "networkID", "context", "endpoint", "collectedAt", "expiresAt"]
    public static let base = "docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d"
    public static let scanSeconds = 15 // Test-only relay allowance, never product defaults.
    public static let connectSeconds = 20
    public static let fullSeconds = 160.0
    public static let drainSeconds = 12.0
    public func validate(path: String, ownRoot: String, fixtureRoot: String, home: String, now: Double) throws {
        try Syntax.path(path); try Syntax.path(credentialDirectory)
        let prefix = ownRoot + "/.runtime/case-", suffix = "/remote-terminal.json"
        let generationPrefix = fixtureRoot + "/.runtime/keyonly/credentials-"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix), Syntax.hex(String(path.dropFirst(prefix.count).dropLast(suffix.count)), 12),
              schema == 1, taskID == "REAL-OUTER-PTY-TUI-PREP-A", service == "keyonly", host == "127.0.0.1", port == 22221,
              user == "fixture", key == "edplain", credentialDirectory.hasPrefix(generationPrefix),
              Syntax.hex(String(credentialDirectory.dropFirst(generationPrefix.count)), 12), Syntax.fingerprint(expectedFingerprint), baseImage == Self.base,
              imageID.hasPrefix("sha256:"), Syntax.hex(String(imageID.dropFirst(7)), 64), Syntax.hex(containerID, 64), Syntax.hex(networkID, 64),
              project.hasPrefix("openlxssh-fixture-"), Syntax.hex(String(project.dropFirst("openlxssh-fixture-".count)), 12),
              ["default", "desktop-linux"].contains(context), ["unix:///var/run/docker.sock", "unix://" + home + "/.docker/run/docker.sock"].contains(endpoint),
              now.isFinite, collectedAt.isFinite, expiresAt.isFinite, collectedAt > 0, collectedAt <= now,
              now < expiresAt, expiresAt - collectedAt <= 3600 else { throw TerminalCheckError.contract }
    }
}

public enum ProbePlan {
    public static let input = Data("ASCII / 中文 / e\u{301}".utf8)
    public static let document = Data("VIM ASCII 中文 e\u{301}\n".utf8)
    public static let width = 93
    public static let height = 31
    private static let loader = #"""
import base64,hashlib,os,select,signal,sys,termios,time,tty
nonce,count,digest=sys.argv[1:]
count=int(count)
if len(nonce)!=32 or any(c not in '0123456789abcdef' for c in nonce) or not 0<count<=32768:raise SystemExit(64)
original=termios.tcgetattr(0)
source=bytearray()
try:
 tty.setraw(0,termios.TCSANOW)
 print('\r\nRT1|'+nonce+'|load-ready|'+str(count)+','+digest+'|END\r\n',flush=True)
 deadline=time.monotonic()+12
 while len(source)<count:
  left=deadline-time.monotonic()
  if left<=0:raise SystemExit(65)
  if select.select([0],[],[],min(left,.1))[0]:
   part=os.read(0,count-len(source))
   if not part:raise SystemExit(65)
   source.extend(part)
finally:termios.tcsetattr(0,termios.TCSANOW,original)
if hashlib.sha256(source).hexdigest()!=digest:raise SystemExit(65)
sys.argv=['<openlxssh-fixed-terminal-probe>',nonce]
namespace={'__name__':'__main__'}
exec(compile(source,'<openlxssh-fixed-terminal-probe>','exec'),namespace)
"""#
    public static func command(source: Data, nonce: String) throws -> Data {
        guard Syntax.hex(nonce, 32), source.count <= 32768, !source.isEmpty else { throw TerminalCheckError.contract }
        // A short fixed loader avoids remote canonical MAX_CANON truncation. Source
        // bytes follow only its nonce/count/hash ACK after it has disabled echo.
        let encoded = Data(loader.utf8).base64EncodedString()
        let value = "/usr/bin/python3 -c 'import base64;exec(compile(base64.b64decode(\"" + encoded + "\"),\"<fixed-loader>\",\"exec\"))' " + nonce + " " + String(source.count) + " " + Syntax.hash(source) + "; r=$?; printf '\\122\\1241|" + nonce + "|returned|%s|END\\n' \"$r\"\r"
        guard value.utf8.count < 4096 else { throw TerminalCheckError.contract }
        return Data(value.utf8)
    }
    public static let vimKeys = Data("iVIM ASCII 中文 e\u{301}\u{1b}:wq\r".utf8)
}

public enum ProbeAction: Equatable, Sendable {
    case none, source, sample, interrupt, resize, vimKeys, complete
}

public struct ProbeBudget: Sendable {
    public let nonce: String
    public let deadline: Double
    public private(set) var events = 0
    public private(set) var remotePID: Int?
    public private(set) var cleanupAcknowledged = false
    private var next = 0
    private let sourceCount: Int
    private let sourceSHA256: String
    private var consumed = Set<String>()
    private let expected = ["load-ready", "hello", "input-ready", "input", "interrupt-ready", "interrupt", "resize-ready", "size", "vim-ready", "vim", "done", "returned"]
    public init(nonce: String, sourceCount: Int, sourceSHA256: String, start: Double) throws {
        guard Syntax.hex(nonce, 32), (1...32768).contains(sourceCount), Syntax.hex(sourceSHA256, 64), start.isFinite, start >= 0 else { throw TerminalCheckError.contract }
        self.nonce = nonce; self.sourceCount = sourceCount; self.sourceSHA256 = sourceSHA256; deadline = start + 125
    }
    public mutating func inspect(_ rendered: String, now: Double) throws -> ProbeAction {
        guard now.isFinite, now < deadline else { throw TerminalCheckError.deadline }
        // SwiftTerm may wrap one finite frame over several rows. Retain only local
        // temporary flattening; never store/print terminal output or parse auth prompts.
        let bytes = Data(rendered.utf8)
        guard bytes.count <= 65536 else { throw TerminalCheckError.unexpectedFrame }
        let text = rendered.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        let prefix = "RT1|" + nonce + "|"
        var cursor = text.startIndex
        var action: ProbeAction = .none
        while let range = text.range(of: prefix, range: cursor..<text.endIndex) {
            guard let end = text.range(of: "|END", range: range.upperBound..<text.endIndex) else { break }
            let frame = String(text[range.upperBound..<end.lowerBound])
            guard frame.utf8.count <= 256 else { throw TerminalCheckError.unexpectedFrame }
            cursor = end.upperBound
            if consumed.contains(frame) { continue } // Retained screen/history, not a replayed action.
            let parts = frame.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 2, parts[0] != "failed", next < expected.count, parts[0] == expected[next] else { throw TerminalCheckError.unexpectedFrame }
            let values = parts[1].split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            // Values are comma-separated to keep a strict two-field envelope.
            let fields = values[0].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            var candidate: ProbeAction = .none
            switch parts[0] {
            case "load-ready": guard fields == [String(sourceCount), sourceSHA256] else { throw TerminalCheckError.integrity }; candidate = .source
            case "hello":
                guard fields.count == 2, fields[0] == "10000", let pid = Int(fields[1]), pid > 1 else { throw TerminalCheckError.unexpectedFrame }
                remotePID = pid
            case "input-ready": guard fields == [String(ProbePlan.input.count)] else { throw TerminalCheckError.unexpectedFrame }; candidate = .sample
            case "input": guard fields == [String(ProbePlan.input.count), Syntax.hash(ProbePlan.input)] else { throw TerminalCheckError.integrity }
            case "interrupt-ready": guard fields == [""] else { throw TerminalCheckError.unexpectedFrame }; candidate = .interrupt
            case "interrupt": guard fields == ["1"] else { throw TerminalCheckError.unexpectedFrame }
            case "resize-ready": guard fields == [""] else { throw TerminalCheckError.unexpectedFrame }; candidate = .resize
            case "size": guard fields == ["31", "93"] else { throw TerminalCheckError.integrity }
            case "vim-ready": guard fields == [""] else { throw TerminalCheckError.unexpectedFrame }; candidate = .vimKeys
            case "vim": guard fields == [String(ProbePlan.document.count), Syntax.hash(ProbePlan.document)] else { throw TerminalCheckError.integrity }
            case "done": guard fields == ["1"] else { throw TerminalCheckError.cleanup }; cleanupAcknowledged = true
            case "returned": guard fields == ["0"] else { throw TerminalCheckError.remoteFailure }; candidate = .complete
            default: throw TerminalCheckError.unexpectedFrame
            }
            if candidate != .none {
                guard action == .none else { throw TerminalCheckError.unexpectedFrame }
                action = candidate
            }
            consumed.insert(frame); next += 1; events += 1
        }
        return action
    }
    public func requireComplete() throws { guard next == expected.count, events == expected.count, remotePID != nil else { throw TerminalCheckError.unexpectedFrame } }
}

public enum PostAuthStage: String, Codable, Sendable {
    case initialized, connecting, shortACKEnqueue, waitingShortACK, loaderEnqueue, waitingProbe
    case sourceEnqueue, sampleEnqueue, interruptEnqueue, resizeEnqueue, vimEnqueue, probeComplete, closing, closed
}
public enum ObservedSessionState: String, Codable, Sendable {
    case idle, preparing, awaitingTrust, authenticating, connectionPending, connected, disconnected, failed, closing, closed
}
public enum ObservedSessionFailure: String, Codable, Sendable {
    case invalidConfiguration, launchFailed, trustRejected, trustScanFailed, authenticationFailed, authenticationTimeout, inputFailed
}
public enum ObservedInputError: String, Codable, Sendable {
    case busy, closed, stale, invalidConfiguration, inputFull, inactive
}
public enum PostAuthEvent: String, Codable, Sendable {
    case connectRequested, connected, firstInputAttempt, firstInputReturned, shortACKEnqueued, shortACKReceived
    case loaderAttempt, loaderEnqueued, firstProbeFrame, lastProbeFrame, sourceEnqueued, sampleEnqueued
    case interruptEnqueued, resizeApplied, vimEnqueued, probeComplete, sessionEnded, cleanupStarted, cleanupEnded
}
public struct SessionObservation: Encodable, Equatable, Sendable {
    public let state: ObservedSessionState
    public let failure: ObservedSessionFailure?
    public let lastExitCode: Int32?
    public let inputError: ObservedInputError?
    public let pendingInputBytes: Int
    public let ownedPID: Int32?
    public init(state: ObservedSessionState, failure: ObservedSessionFailure?, lastExitCode: Int32?, inputError: ObservedInputError?, pendingInputBytes: Int, ownedPID: Int32?) {
        self.state = state; self.failure = failure; self.lastExitCode = lastExitCode; self.inputError = inputError
        self.pendingInputBytes = pendingInputBytes; self.ownedPID = ownedPID
    }
}
public struct RelativeTime: Encodable, Sendable {
    public let event: PostAuthEvent
    public let seconds: Double
}
/// Closed typed metadata only: no terminal strings, errors/descriptions, prompts or input data.
public struct PostAuthDiagnostics: Encodable, Sendable {
    private let start: Double
    public var stage: PostAuthStage = .initialized
    public var failureStage: PostAuthStage?
    public var lastObservedSession: SessionObservation?
    public var preCloseSession: SessionObservation?
    public var failureSession: SessionObservation?
    public var firstInputBefore: SessionObservation?
    public var firstInputAfter: SessionObservation?
    public var lastInputAfter: SessionObservation?
    public var terminalFailure: ObservedSessionFailure?
    public var stopRequested = false
    /// True means loader enqueue returned, NOT that a remote process started.
    public var remoteStarted = false
    public var remotePID: Int?
    public var remotePIDConfirmed: Bool { remotePID != nil }
    public var inputAttempts = 0
    public var inputReturns = 0
    public var lastInputByteCount = 0
    public private(set) var relativeTimes: [RelativeTime] = []
    private enum CodingKeys: String, CodingKey {
        case stage, failureStage, lastObservedSession, preCloseSession, failureSession, firstInputBefore, firstInputAfter
        case lastInputAfter, terminalFailure, stopRequested, remoteStarted, remotePID, remotePIDConfirmed
        case inputAttempts, inputReturns, lastInputByteCount, relativeTimes
    }
    public init(start: Double) throws {
        guard start.isFinite, start >= 0 else { throw TerminalCheckError.integrity }
        self.start = start
    }
    public mutating func mark(_ event: PostAuthEvent, now: Double) throws {
        guard now.isFinite, now >= start, now - start <= 180 else { throw TerminalCheckError.integrity }
        if let index = relativeTimes.firstIndex(where: { $0.event == event }) {
            if event == .lastProbeFrame { relativeTimes[index] = RelativeTime(event: event, seconds: now - start) }
            return
        }
        relativeTimes.append(RelativeTime(event: event, seconds: now - start))
    }
    public func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(stage, forKey: .stage); try values.encodeIfPresent(failureStage, forKey: .failureStage)
        try values.encodeIfPresent(lastObservedSession, forKey: .lastObservedSession); try values.encodeIfPresent(preCloseSession, forKey: .preCloseSession)
        try values.encodeIfPresent(failureSession, forKey: .failureSession); try values.encodeIfPresent(firstInputBefore, forKey: .firstInputBefore)
        try values.encodeIfPresent(firstInputAfter, forKey: .firstInputAfter); try values.encodeIfPresent(lastInputAfter, forKey: .lastInputAfter)
        try values.encodeIfPresent(terminalFailure, forKey: .terminalFailure); try values.encode(stopRequested, forKey: .stopRequested)
        try values.encode(remoteStarted, forKey: .remoteStarted); try values.encode(remotePID, forKey: .remotePID)
        try values.encode(remotePIDConfirmed, forKey: .remotePIDConfirmed); try values.encode(inputAttempts, forKey: .inputAttempts)
        try values.encode(inputReturns, forKey: .inputReturns); try values.encode(lastInputByteCount, forKey: .lastInputByteCount)
        try values.encode(relativeTimes, forKey: .relativeTimes)
    }
}

/// Independent short shell check. It cannot authorize source input before the ACK.
public struct ShortShellACK: Sendable {
    private let nonce: String
    public let deadline: Double
    public private(set) var enqueued = false
    public private(set) var acknowledged = false
    public init(nonce: String, start: Double) throws {
        guard Syntax.hex(nonce, 32), start.isFinite, start >= 0 else { throw TerminalCheckError.contract }
        self.nonce = nonce; deadline = start + 12
    }
    public func command() throws -> Data {
        // The literal command echo has no matching RTS1 prefix. Shell printf alone
        // emits the nonce-bound ACK; no host/path/source/user text is interpolated.
        let bytes = Data(("printf '\\122\\124S1|" + nonce + "|shell-ready|1|END\\n'\r").utf8)
        guard bytes.count <= 256, bytes.allSatisfy({ $0 < 128 }) else { throw TerminalCheckError.contract }
        return bytes
    }
    public mutating func didEnqueue(now: Double) throws {
        guard now.isFinite, now < deadline, !enqueued, !acknowledged else { throw TerminalCheckError.unexpectedFrame }
        enqueued = true
    }
    public mutating func inspect(rendered: String, now: Double) throws -> Bool {
        guard enqueued else { throw TerminalCheckError.unexpectedFrame }
        guard now.isFinite, now < deadline else { throw TerminalCheckError.deadline }
        guard rendered.utf8.count <= 65536 else { throw TerminalCheckError.unexpectedFrame }
        let text = rendered.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        if let early = text.range(of: "RT1|" + nonce + "|"), text.range(of: "|END", range: early.upperBound..<text.endIndex) != nil {
            throw TerminalCheckError.unexpectedFrame
        }
        let prefix = "RTS1|" + nonce + "|"
        guard let range = text.range(of: prefix), let end = text.range(of: "|END", range: range.upperBound..<text.endIndex) else { return false }
        guard text[range.upperBound..<end.lowerBound] == "shell-ready|1" else { throw TerminalCheckError.unexpectedFrame }
        if let duplicate = text.range(of: prefix, range: end.upperBound..<text.endIndex), text.range(of: "|END", range: duplicate.upperBound..<text.endIndex) != nil {
            throw TerminalCheckError.unexpectedFrame
        }
        guard !acknowledged else { return false } // Re-inspecting retained terminal history sends nothing twice.
        acknowledged = true
        return true
    }
    public func requireAcknowledged() throws {
        guard enqueued, acknowledged else { throw TerminalCheckError.unexpectedFrame }
    }
}

public struct TerminalReport: Encodable, Sendable {
    public let taskID = "REAL-OUTER-PTY-TUI-PREP-A"
    public let productAcceptance = false
    public let nestedAuthenticationTested = false
    public let imeTested = false
    public let allTUIToolsTested = false
    public let macOS26RuntimeTested = false
    public var connectedEvents = 0
    public var authenticationRequests = 0
    public var postConnectedAuthenticationRequests = 0
    public var ownedPID: Int32?
    public var shellACK = false
    public var probeProcessACK = false
    public var postAuth: PostAuthDiagnostics?
    public var inputByteHashMatched = false
    public var interruptObserved = false
    public var remoteSizeMatched = false
    public var vimBytesHashMatched = false
    public var probeEvents = 0
    public var remoteCleanup = false
    public var returnedToOuter = false
    public var remoteProcessReleased = false
    public var ownedPIDReleased = false
    public var closed = false
    public var fdReturnedToBaseline = false
    public var failure: TerminalCheckError?
    public init() {}
}
