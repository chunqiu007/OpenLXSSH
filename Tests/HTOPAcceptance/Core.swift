import Foundation
import RemoteTerminalCore

public enum HAction: Equatable, Sendable { case none, source, start, complete }
public enum HStage: String, Codable, Sendable { case initialized, starting, ready, sized, exited, failed }
public enum HFailureStage: String, Codable, Sendable { case preflight, launch, readiness, resize, exit, cleanup }
public enum HFailureKind: String, Codable, Sendable { case refused, deadline, osError = "os-error", sourceError = "source-error" }
public enum HErrno: String, Codable, Sendable { case none, enoent, eacces, eperm, eio, other }
public struct HIdentity: Codable, Equatable, Sendable {
    public let pid: Int
    public let startTicks: UInt64
    public init(pid: Int, startTicks: UInt64) { self.pid = pid; self.startTicks = startTicks }
    var valid: Bool { pid > 1 && startTicks > 0 }
}
public struct HBinding: Encodable, Sendable {
    public let parent: HIdentity
    public let directoryDevice: UInt64, directoryInode: UInt64, statusDevice: UInt64, statusInode: UInt64
}
public struct HFailure: Codable, Equatable, Sendable {
    public let stage: HFailureStage
    public let kind: HFailureKind
    public let errno: HErrno
}
/// Closed management metadata, produced only from the held own status inode.
public struct HStatus: Codable, Equatable, Sendable {
    public let schema: Int
    public let stage: HStage
    public let parent: HIdentity
    public let htop: HIdentity?
    public let child: HIdentity?
    public let rows: Int?
    public let cols: Int?
    public let failure: HFailure?
    public let configPresent: Bool
    public static let keys: Set<String> = ["schema", "stage", "parent", "htop", "child", "rows", "cols", "failure", "configPresent"]
    public static func decode(_ bytes: Data) throws -> Self {
        guard bytes.count <= 2048 else { throw TerminalCheckError.integrity }
        let object = try Syntax.object(bytes, keys: keys)
        for name in ["parent", "htop", "child"] {
            if object[name] is NSNull { continue }
            guard let value = object[name] as? [String: Any], Set(value.keys) == ["pid", "startTicks"] else { throw TerminalCheckError.integrity }
        }
        if let failure = object["failure"] as? [String: Any], Set(failure.keys) != ["stage", "kind", "errno"] { throw TerminalCheckError.integrity }
        let status = try JSONDecoder().decode(Self.self, from: bytes)
        guard status.schema == 1, status.parent.valid, status.htop?.valid != false, status.child?.valid != false else { throw TerminalCheckError.integrity }
        if let rows = status.rows { guard (1...65535).contains(rows) else { throw TerminalCheckError.integrity } }
        if let cols = status.cols { guard (1...65535).contains(cols) else { throw TerminalCheckError.integrity } }
        return status
    }
}
public struct HStatusBudget: Sendable {
    private let expectedParent: HIdentity
    private var parent: HIdentity?, htop: HIdentity?, child: HIdentity?
    private var stage: HStage = .initialized
    public private(set) var readyObserved = false, sizeObserved = false
    public init(parent: HIdentity) { expectedParent = parent }
    public mutating func inspect(_ status: HStatus) throws {
        guard status.parent == expectedParent else { throw TerminalCheckError.integrity }
        if let parent { guard parent == status.parent else { throw TerminalCheckError.integrity } }
        if let htop { guard htop == status.htop else { throw TerminalCheckError.integrity } }
        if let child { guard child == status.child else { throw TerminalCheckError.integrity } }
        if status.stage == .failed { throw TerminalCheckError.remoteFailure }
        switch status.stage {
        case .initialized: guard stage == .initialized else { throw TerminalCheckError.unexpectedFrame }
        case .ready:
            guard stage == .initialized || stage == .ready, status.htop != nil, status.child != nil, status.failure == nil else { throw TerminalCheckError.unexpectedFrame }
            readyObserved = true
        case .sized:
            guard stage == .ready || stage == .sized, readyObserved, status.htop != nil, status.child != nil, status.rows == 31, status.cols == 93, status.failure == nil else { throw TerminalCheckError.integrity }
            sizeObserved = true
        default: throw TerminalCheckError.unexpectedFrame
        }
        parent = status.parent; htop = status.htop; child = status.child; stage = status.stage
    }
}
public enum HPlan {
    public static let start = Data("H\r".utf8)
    public static let quit = Data([113]) // q only; no F9, signal UI or arbitrary process selection.
    public static let width = 93, height = 31
}
public struct HBudget: Sendable {
    private let nonce: String, sourceHash: String
    private let count: Int
    private let expected = ["load-ready", "hello", "exited", "done", "returned"]
    private var consumed = Set<String>()
    public let deadline: Double
    public private(set) var events = 0, remotePID: Int?
    public private(set) var binding: HBinding?
    public private(set) var normalExit = false, cleanup = false
    public private(set) var failure: HFailure?
    public init(nonce: String, count: Int, sourceHash: String, start: Double) throws {
        guard Syntax.hex(nonce, 32), (1...32768).contains(count), Syntax.hex(sourceHash, 64), start.isFinite, start >= 0 else { throw TerminalCheckError.contract }
        self.nonce = nonce; self.count = count; self.sourceHash = sourceHash; deadline = start + 125
    }
    public mutating func inspect(_ rendered: String, now: Double) throws -> HAction {
        guard now.isFinite, now < deadline else { throw TerminalCheckError.deadline }
        guard rendered.utf8.count <= 65536 else { throw TerminalCheckError.unexpectedFrame }
        let text = rendered.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        var cursor = text.startIndex, action: HAction = .none
        while let begin = text.range(of: "RT1|" + nonce + "|", range: cursor..<text.endIndex) {
            guard let end = text.range(of: "|END", range: begin.upperBound..<text.endIndex) else { break }
            let frame = String(text[begin.upperBound..<end.lowerBound]); cursor = end.upperBound
            guard frame.utf8.count <= 256 else { throw TerminalCheckError.unexpectedFrame }
            if consumed.contains(frame) { continue }
            let parts = frame.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 2 else { throw TerminalCheckError.unexpectedFrame }
            let fields = parts[1].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            if parts[0] == "failed" {
                guard fields.count == 3, let stage = HFailureStage(rawValue: fields[0]), let kind = HFailureKind(rawValue: fields[1]), let errno = HErrno(rawValue: fields[2]) else { throw TerminalCheckError.unexpectedFrame }
                failure = HFailure(stage: stage, kind: kind, errno: errno); throw TerminalCheckError.remoteFailure
            }
            guard events < expected.count, parts[0] == expected[events] else { throw TerminalCheckError.unexpectedFrame }
            var next: HAction = .none
            switch parts[0] {
            case "load-ready": guard fields == [String(count), sourceHash] else { throw TerminalCheckError.integrity }; next = .source
            case "hello":
                guard fields.count == 7, fields[0] == "10000", let pid = Int(fields[1]), pid > 1,
                      let start = UInt64(fields[2]), start > 0, let directoryDevice = UInt64(fields[3]), let directoryInode = UInt64(fields[4]), directoryInode > 0,
                      let statusDevice = UInt64(fields[5]), let statusInode = UInt64(fields[6]), statusInode > 0 else { throw TerminalCheckError.unexpectedFrame }
                remotePID = pid; binding = HBinding(parent: HIdentity(pid: pid, startTicks: start), directoryDevice: directoryDevice, directoryInode: directoryInode, statusDevice: statusDevice, statusInode: statusInode); next = .start
            case "exited": guard fields == ["0"] else { throw TerminalCheckError.remoteFailure }; normalExit = true
            case "done": guard fields == ["1"] else { throw TerminalCheckError.cleanup }; cleanup = true
            case "returned": guard fields == ["0"] else { throw TerminalCheckError.remoteFailure }; next = .complete
            default: throw TerminalCheckError.unexpectedFrame
            }
            if next != .none { guard action == .none else { throw TerminalCheckError.unexpectedFrame }; action = next }
            consumed.insert(frame); events += 1
        }
        return action
    }
    public func requireComplete() throws { guard events == expected.count, remotePID != nil, normalExit, cleanup else { throw TerminalCheckError.unexpectedFrame } }
}
public struct HReport: Encodable, Sendable {
    public let taskID = "REAL-HTOP-OWN-CHILD-A", tool = "htop"
    public let productAcceptance = false, pixelsVerified = false, internalStateVerified = false, imeTested = false
    public var connectedEvents = 0, authenticationRequests = 0, postConnectedAuthenticationRequests = 0
    public var ownedPID: Int32?, postAuth: PostAuthDiagnostics?
    public var shellACK = false, probeProcessACK = false, remoteCleanup = false, returnedToOuter = false, remoteProcessReleased = false
    public var ownedPIDReleased = false, closed = false, fdReturnedToBaseline = false
    public var toolStage: HStage = .initialized
    public var readinessVerified = false, remoteSizeMatched = false, quitEnqueued = false, normalExit = false
    public var probeEvents = 0, statusReadCount = 0
    public var binding: HBinding?
    public var status: HStatus?, remoteProbeFailure: HFailure?, failure: TerminalCheckError?
    public init() {}
    public mutating func recordProbe(_ budget: HBudget) {
        probeProcessACK = budget.remotePID != nil; postAuth?.remotePID = budget.remotePID; binding = budget.binding
        probeEvents = budget.events; normalExit = budget.normalExit; remoteCleanup = budget.cleanup; remoteProbeFailure = budget.failure
    }
}
