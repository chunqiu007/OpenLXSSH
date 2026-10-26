import Foundation

public enum SFTPAuthPhase: Equatable, Sendable {
    case secret(session: String, index: Int)
    case terminalZero
}

/// Root-PAM fixture contract: three exact secret rounds followed by the one
/// observed empty protocol tail. The tail is not authentication-success proof.
public struct SFTPAuthBudget: Sendable {
    public let expectedCallbacks: Int
    public let deadline: Double
    public private(set) var callbacks = 0
    public private(set) var replies = 0
    public private(set) var secretResponses = 0
    public private(set) var terminalZeroReplies = 0
    public private(set) var managementReads = 0
    public private(set) var lateReplies = 0
    public private(set) var sessionID: String?
    public private(set) var promptCounts: [Int] = []
    public private(set) var echoFlags: [[Bool]] = []
    public private(set) var pendingPhase: SFTPAuthPhase?
    private var awaitingResolution = false
    private var resolvedReplies = 0
    public private(set) var closed = false
    public private(set) var failure: SFTPAuthError?
    public init(mfa: Bool, start: Double) throws {
        guard start.isFinite, start >= 0 else { throw SFTPAuthError.invalidContract }
        expectedCallbacks = mfa ? 4 : 0; deadline = start + SFTPAuthContract.activeSeconds
    }
    public static func prompt(session: String, index: Int) throws -> Data {
        guard Contract.hex(session, count: 24), (0..<3).contains(index) else { throw SFTPAuthError.unknownChallenge }
        return Data((["One-time response A", "Unclassified verification B", "Next-round response C"][index] + " [" + session + "]: ").utf8)
    }
    public mutating func claim(name: Data, instruction: Data, prompts: [Data], echo: [Bool], now: Double) throws -> SFTPAuthPhase {
        do {
            guard !closed, failure == nil, now.isFinite, now < deadline, pendingPhase == nil, !awaitingResolution else { throw SFTPAuthError.staleReply }
            callbacks += 1
            guard expectedCallbacks == 4, callbacks == replies + 1, callbacks <= 4,
                  name.isEmpty, instruction.isEmpty else { throw SFTPAuthError.unknownChallenge }
            if callbacks == 4 {
                guard secretResponses == 3, replies == 3, resolvedReplies == 3, managementReads == 3,
                      terminalZeroReplies == 0, sessionID != nil, prompts.isEmpty, echo.isEmpty else { throw SFTPAuthError.unknownChallenge }
                pendingPhase = .terminalZero; promptCounts.append(0); echoFlags.append([])
                return .terminalZero // No secret read; only the exact observed tail.
            }
            guard prompts.count == 1, echo == [false], secretResponses == replies, resolvedReplies == replies else { throw SFTPAuthError.unknownChallenge }
            let index = secretResponses, value = prompts[0], suffix = Data("]: ".utf8)
            guard value.suffix(suffix.count) == suffix, let text = String(data: value, encoding: .utf8),
                  let range = text.range(of: " [", options: .backwards) else { throw SFTPAuthError.unknownChallenge }
            let id = String(text[range.upperBound..<text.index(text.endIndex, offsetBy: -3)])
            guard Contract.hex(id, count: 24), value == (try Self.prompt(session: id, index: index)),
                  sessionID == nil || sessionID == id else { throw SFTPAuthError.unknownChallenge }
            let phase = SFTPAuthPhase.secret(session: id, index: index)
            sessionID = id; pendingPhase = phase; managementReads += 1
            promptCounts.append(1); echoFlags.append(echo)
            return phase
        } catch {
            failure = (error as? SFTPAuthError) ?? .unknownChallenge
            throw error
        }
    }
    public mutating func consume(phase: SFTPAuthPhase, now: Double) throws {
        guard !closed, failure == nil, now.isFinite, now < deadline, pendingPhase == phase, !awaitingResolution else {
            lateReplies += 1; failure = .staleReply; throw SFTPAuthError.staleReply
        }
        switch phase {
        case .secret(let id, let index):
            guard sessionID == id, index == secretResponses, replies == secretResponses, index < 3 else {
                failure = .staleReply; throw SFTPAuthError.staleReply
            }
            secretResponses += 1
        case .terminalZero:
            guard callbacks == 4, replies == 3, secretResponses == 3, terminalZeroReplies == 0, resolvedReplies == 3 else {
                failure = .staleReply; throw SFTPAuthError.staleReply
            }
            terminalZeroReplies = 1
        }
        replies += 1; pendingPhase = nil; awaitingResolution = true // Consume before resolve; no replay on false.
    }
    public mutating func resolved(_ accepted: Bool) {
        guard !closed, failure == nil, awaitingResolution, accepted else {
            lateReplies += 1; failure = .staleReply; return
        }
        resolvedReplies += 1; awaitingResolution = false
    }
    public func requireResolutionAccepted() throws {
        if let failure { throw failure }
        guard !awaitingResolution else { throw SFTPAuthError.staleReply }
    }
    public mutating func fail(_ reason: SFTPAuthError) { if failure == nil { failure = reason }; close() }
    public mutating func close() { closed = true; pendingPhase = nil }
    public func requireComplete() throws {
        if let failure { throw failure }
        let mfa = expectedCallbacks == 4
        guard pendingPhase == nil, !awaitingResolution, callbacks == expectedCallbacks, replies == expectedCallbacks,
              resolvedReplies == expectedCallbacks, secretResponses == (mfa ? 3 : 0), terminalZeroReplies == (mfa ? 1 : 0),
              managementReads == (mfa ? 3 : 0), lateReplies == 0,
              promptCounts == (mfa ? [1, 1, 1, 0] : []),
              echoFlags == (mfa ? [[false], [false], [false], []] : []) else { throw SFTPAuthError.extraCallback }
    }
}

public struct SFTPAuthReport: Encodable, Sendable {
    public let taskID = "REAL-SFTP-COMBINED-AUTH-A"
    public let callbackContract = "root-pam-three-secrets-terminal-zero-v1"
    public let productAcceptance = false
    public let firstContactGUIAcceptance = false
    public let testOnlyHostMinimum = "15.0"
    public let service: String
    public let key: String
    public let authenticationOrder: [String]
    public var authenticatedSFTPConnects = 0
    public var callbackCount = 0
    public var replyCount = 0
    public var secretResponseCount = 0
    public var terminalZeroReplyCount = 0
    public var promptCounts: [Int] = []
    public var echoFlags: [[Bool]] = []
    public var managementResponseReads = 0
    public var lateReplyCount = 0
    public var sessionID: String?
    public var bytesWritten = 0
    public var bytesRead = 0
    public var listChecks = 0
    public var lstatChecks = 0
    public var hashMatched = false
    public var remoteCleanupCompleted = false
    public var serverSessionFileRemoved = false
    public var closeCompleted = false
    public var managementChildrenReaped = false
    public var policyVerified = false
    public var result = "failed"
    public var failure: SFTPAuthError?
    public var fileErrorKind: String?
    public var unexpectedChallenge: UnexpectedChallengeShape?
    public init(contract: SFTPAuthContract) {
        service = contract.service.rawValue; key = contract.key.rawValue; authenticationOrder = contract.authenticationOrder
    }
    public mutating func record(_ budget: SFTPAuthBudget) {
        callbackCount = budget.callbacks; replyCount = budget.replies; promptCounts = budget.promptCounts; echoFlags = budget.echoFlags
        secretResponseCount = budget.secretResponses; terminalZeroReplyCount = budget.terminalZeroReplies
        managementResponseReads = budget.managementReads; lateReplyCount = budget.lateReplies; sessionID = budget.sessionID
    }
}
