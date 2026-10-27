import Foundation
import RemoteTerminalCore

public enum TUIAction: Equatable, Sendable { case none, source, start, sample, prepareResize, resize, allowDetach, detach, complete }
public enum TUIStage: String, Codable, Sendable { case initialized, loader, starting, input, preparingResize, resizing, detachReady, detaching, complete, closing }
public enum TUIFrame: String, Codable, Sendable {
    case loadReady = "load-ready", hello, tmuxReady = "tmux-ready", input, resizeReady = "resize-ready", size
    case detachReady = "detach-ready", detached, done, returned, failed, unrecognized
}
public enum TUIRejectReason: String, Codable, Sendable {
    case deadline, renderLimit, frameLimit, envelope, sequence, fieldCount, fields, integrity, size, actions, remoteFailure, cleanup, returned
}
public enum TUIFieldCount: String, Codable, Sendable {
    case zero = "0", one = "1", two = "2", three = "3", other
    init(_ count: Int) {
        switch count { case 0: self = .zero; case 1: self = .one; case 2: self = .two; case 3: self = .three; default: self = .other }
    }
}
public enum TUIRemoteStage: String, Codable, Sendable { case preflight, start, input, resize, detach, cleanup }
public enum TUIRemoteKind: String, Codable, Sendable { case refused, deadline, osError = "os-error", processExit = "process-exit", sourceError = "source-error" }
public enum TUIErrno: String, Codable, Sendable { case none, enoent, eacces, eperm, ebadf, eio, other }
public struct TUIRemoteFailure: Encodable, Sendable {
    public let stage: TUIRemoteStage
    public let kind: TUIRemoteKind
    public let errno: TUIErrno
    public let seenRows: Int?
    public let seenCols: Int?
    init?(_ values: [String]) {
        guard values.count == 3 || values.count == 5, let stage = TUIRemoteStage(rawValue: values[0]), let kind = TUIRemoteKind(rawValue: values[1]), let errno = TUIErrno(rawValue: values[2]) else { return nil }
        if values.count == 5 {
            guard stage == .resize, let rows = Int(values[3]), let cols = Int(values[4]), (1...65535).contains(rows), (1...65535).contains(cols) else { return nil }
            seenRows = rows; seenCols = cols
        } else { seenRows = nil; seenCols = nil }
        self.stage = stage; self.kind = kind; self.errno = errno
    }
}
public enum TmuxPlan {
    public static let input = Data("TMUX ASCII 中文 e\u{301}".utf8)
    public static let start = Data("T\r".utf8)
    public static let prepareResize = Data("C".utf8)
    public static let resize = Data("R".utf8)
    public static let allowDetach = Data("D".utf8)
    public static let detach = Data([2, 100]) // Actual tmux default prefix Ctrl-b, then d; not a management detach command.
    public static let width = 93, height = 31
}
public struct TUIBudget: Sendable {
    private let nonce: String, sourceHash: String
    private let sourceCount: Int
    public let deadline: Double
    private let expected = ["load-ready", "hello", "tmux-ready", "input", "resize-ready", "size", "detach-ready", "detached", "done", "returned"]
    private var consumed = Set<String>()
    public private(set) var events = 0
    public private(set) var remotePID: Int?, panePID: Int?, serverPID: Int?
    public private(set) var inputMatched = false, sizeMatched = false, detached = false, cleaned = false
    public private(set) var unexpected: TUIFrame?
    public private(set) var remoteFailure: TUIRemoteFailure?
    public private(set) var rejectReason: TUIRejectReason?
    public private(set) var rejectFieldCount: TUIFieldCount?
    public private(set) var inputLengthMatch: Bool?
    public private(set) var inputHashMatch: Bool?
    public init(nonce: String, sourceCount: Int, sourceHash: String, start: Double) throws {
        guard Syntax.hex(nonce, 32), (1...32768).contains(sourceCount), Syntax.hex(sourceHash, 64), start.isFinite, start >= 0 else { throw TerminalCheckError.contract }
        self.nonce = nonce; self.sourceCount = sourceCount; self.sourceHash = sourceHash; deadline = start + 100
    }
    private mutating func rejection(_ reason: TUIRejectReason, _ error: TerminalCheckError) -> TerminalCheckError {
        rejectReason = reason
        return error
    }
    public mutating func inspect(_ rendered: String, now: Double) throws -> TUIAction {
        guard now.isFinite, now < deadline else { throw rejection(.deadline, .deadline) }
        guard rendered.utf8.count <= 65536 else { throw rejection(.renderLimit, .unexpectedFrame) }
        let text = rendered.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        let prefix = "RT1|" + nonce + "|"
        var cursor = text.startIndex, action: TUIAction = .none
        while let begin = text.range(of: prefix, range: cursor..<text.endIndex) {
            guard let end = text.range(of: "|END", range: begin.upperBound..<text.endIndex) else { break }
            let frame = String(text[begin.upperBound..<end.lowerBound]); cursor = end.upperBound
            guard frame.utf8.count <= 256 else { unexpected = .unrecognized; throw rejection(.frameLimit, .unexpectedFrame) }
            if consumed.contains(frame) { continue }
            rejectFieldCount = nil; inputLengthMatch = nil; inputHashMatch = nil
            let parts = frame.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            unexpected = TUIFrame(rawValue: parts.first ?? "") ?? .unrecognized
            // Inspect only the bounded first payload for closed diagnostics; malformed envelopes still fail first.
            let fields = parts.count > 1 ? parts[1].split(separator: ",", omittingEmptySubsequences: false).map(String.init) : []
            rejectFieldCount = TUIFieldCount(fields.count)
            if parts.first == "input" {
                inputLengthMatch = fields.first.map { $0 == String(TmuxPlan.input.count) }
                inputHashMatch = fields.count > 1 ? fields[1] == Syntax.hash(TmuxPlan.input) : nil
            }
            guard parts.count == 2 else { throw rejection(.envelope, .unexpectedFrame) }
            if parts[0] == "failed" {
                guard let failure = TUIRemoteFailure(fields) else { throw rejection(fields.count == 3 || fields.count == 5 ? .fields : .fieldCount, .unexpectedFrame) }
                remoteFailure = failure; throw rejection(.remoteFailure, .remoteFailure)
            }
            guard events < expected.count, parts[0] == expected[events] else { throw rejection(.sequence, .unexpectedFrame) }
            var candidate: TUIAction = .none
            switch parts[0] {
            case "load-ready": guard fields == [String(sourceCount), sourceHash] else { throw rejection(fields.count == 2 ? .integrity : .fieldCount, .integrity) }; candidate = .source
            case "hello": guard fields.count == 2, fields[0] == "10000", let pid = Int(fields[1]), pid > 1 else { throw rejection(fields.count == 2 ? .fields : .fieldCount, .unexpectedFrame) }; remotePID = pid; candidate = .start
            case "tmux-ready": guard fields.count == 3, fields[0] == "10000", let pid = Int(fields[1]), pid > 1, fields[2] == String(TmuxPlan.input.count) else { throw rejection(fields.count == 3 ? .fields : .fieldCount, .unexpectedFrame) }; panePID = pid; candidate = .sample
            case "input": guard fields == [String(TmuxPlan.input.count), Syntax.hash(TmuxPlan.input)] else { throw rejection(fields.count == 2 ? .integrity : .fieldCount, .integrity) }; candidate = .prepareResize
            case "resize-ready": guard fields == [""] else { throw rejection(fields.count == 1 ? .fields : .fieldCount, .unexpectedFrame) }; candidate = .resize
            case "size": guard fields == ["31", "93"] else { throw rejection(fields.count == 2 ? .size : .fieldCount, .integrity) }; candidate = .allowDetach
            case "detach-ready": guard fields == [""] else { throw rejection(fields.count == 1 ? .fields : .fieldCount, .unexpectedFrame) }; candidate = .detach
            case "detached": guard fields.count == 2, fields[0] == "1", let pid = Int(fields[1]), pid > 1 else { throw rejection(fields.count == 2 ? .fields : .fieldCount, .unexpectedFrame) }; serverPID = pid
            case "done": guard fields == ["1"] else { throw rejection(.cleanup, .cleanup) }
            case "returned": guard fields == ["0"] else { throw rejection(.returned, .remoteFailure) }; candidate = .complete
            default: throw rejection(.sequence, .unexpectedFrame)
            }
            if candidate != .none { guard action == .none else { throw rejection(.actions, .unexpectedFrame) }; action = candidate }
            if parts[0] == "input" { inputMatched = true }
            if parts[0] == "size" { sizeMatched = true }
            if parts[0] == "detached" { detached = true }
            if parts[0] == "done" { cleaned = true }
            consumed.insert(frame); events += 1; unexpected = nil
            rejectReason = nil; rejectFieldCount = nil; inputLengthMatch = nil; inputHashMatch = nil
        }
        return action
    }
    public func requireComplete() throws {
        guard events == expected.count, remotePID != nil, panePID != nil, serverPID != nil, inputMatched, sizeMatched, detached, cleaned else { throw TerminalCheckError.unexpectedFrame }
    }
}
public struct TUIReport: Encodable, Sendable {
    public let taskID = "REAL-TUI-TMUX-A"
    public let tool = "tmux", productAcceptance = false, pixelsVerified = false, imeTested = false, htopTested = false
    public var connectedEvents = 0, authenticationRequests = 0, postConnectedAuthenticationRequests = 0
    public var ownedPID: Int32?
    public var shellACK = false, probeProcessACK = false
    public var postAuth: PostAuthDiagnostics?
    public var toolStage: TUIStage = .initialized
    public var toolFailureStage: TUIStage?
    public var inputByteHashMatched = false, remoteSizeMatched = false, detached = false, remoteCleanup = false
    public var returnedToOuter = false, remoteProcessReleased = false, ownedPIDReleased = false, closed = false, fdReturnedToBaseline = false
    public var probeEvents = 0, remotePanePID: Int?, remoteServerPID: Int?
    public var unexpectedProbeFrame: TUIFrame?, remoteProbeFailure: TUIRemoteFailure?
    public var rejectReason: TUIRejectReason?, rejectFieldCount: TUIFieldCount?
    public var inputLengthMatch: Bool?, inputHashMatch: Bool?
    public var failure: TerminalCheckError?
    public init() {}
    public mutating func recordProbe(_ budget: TUIBudget) {
        probeProcessACK = budget.remotePID != nil; postAuth?.remotePID = budget.remotePID
        remotePanePID = budget.panePID; remoteServerPID = budget.serverPID; probeEvents = budget.events
        inputByteHashMatched = budget.inputMatched; remoteSizeMatched = budget.sizeMatched
        detached = budget.detached; remoteCleanup = budget.cleaned
        unexpectedProbeFrame = budget.unexpected; remoteProbeFailure = budget.remoteFailure
        rejectReason = budget.rejectReason; rejectFieldCount = budget.rejectFieldCount
        inputLengthMatch = budget.inputLengthMatch; inputHashMatch = budget.inputHashMatch
    }
}
