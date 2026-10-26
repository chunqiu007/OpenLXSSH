import Foundation

/// Separate negative-only state machine. It never changes the positive KBI
/// budget and never treats timeout/transport/cancelled as credential rejection.
public struct SFTPOTPNegativeBudget: Sendable {
    public let testCase: SFTPOTPNegativeCase
    public let deadline: Double
    public private(set) var callbacks = 0
    public private(set) var replies = 0
    public private(set) var resolvedReplies = 0
    public private(set) var managementReads = 0
    public private(set) var sessionID: String?
    public private(set) var pendingIndex: Int?
    public private(set) var readIndex: Int?
    public private(set) var expiresAt: Double?
    public private(set) var cReadWall: Double?
    public private(set) var cReadUptime: Double?
    public private(set) var cSubmittedWall: Double?
    public private(set) var cSubmittedUptime: Double?
    public private(set) var mutatedDigitCount = 0
    public private(set) var wrongCVerified = false
    public private(set) var realExpiryWaitVerified = false
    public private(set) var lateReplies = 0
    public private(set) var closed = false
    public private(set) var failure: SFTPOTPNegativeError?
    private var awaitingResolution = false
    public init(testCase: SFTPOTPNegativeCase, start: Double) throws {
        guard start.isFinite, start >= 0 else { throw SFTPOTPNegativeError.invalidContract }
        self.testCase = testCase; deadline = start + SFTPOTPNegativeContract.activeSeconds
    }
    public mutating func claim(name: Data, instruction: Data, prompts: [Data], echo: [Bool], now: Double) throws -> (String, Int) {
        do {
            guard !closed, failure == nil, now.isFinite, now < deadline, pendingIndex == nil, !awaitingResolution else { throw SFTPOTPNegativeError.staleReply }
            callbacks += 1
            guard callbacks <= 3, callbacks == replies + 1, resolvedReplies == replies, name.isEmpty, instruction.isEmpty,
                  prompts.count == 1, echo == [false], let text = String(data: prompts[0], encoding: .utf8),
                  text.hasSuffix("]: "), let range = text.range(of: " [", options: .backwards) else { throw SFTPOTPNegativeError.unknownChallenge }
            let id = String(text[range.upperBound..<text.index(text.endIndex, offsetBy: -3)]), index = replies
            guard Contract.hex(id, count: 24), prompts[0] == (try SFTPAuthBudget.prompt(session: id, index: index)),
                  sessionID == nil || sessionID == id else { throw SFTPOTPNegativeError.unknownChallenge }
            sessionID = id; pendingIndex = index; readIndex = nil
            return (id, index)
        } catch { fail((error as? SFTPOTPNegativeError) ?? .unknownChallenge); throw error }
    }
    public mutating func recordRead(index: Int, expiry: Double, wall: Double, uptime: Double) throws {
        guard !closed, failure == nil, pendingIndex == index, readIndex == nil, managementReads == index,
              wall.isFinite, uptime.isFinite, uptime < deadline, expiry.isFinite, expiry > wall, expiry <= wall + 75,
              expiresAt == nil || expiresAt == expiry else { throw SFTPOTPNegativeError.invalidResponse }
        readIndex = index; managementReads += 1; expiresAt = expiry
        if index == 2 { cReadWall = wall; cReadUptime = uptime }
    }
    public static func mutateOneDigit(_ original: Data) throws -> Data {
        guard original.count == 8, original.allSatisfy({ (48...57).contains($0) }) else { throw SFTPOTPNegativeError.invalidResponse }
        var wrong = original
        wrong[0] = wrong[0] == 57 ? 48 : wrong[0] + 1
        return wrong
    }
    public mutating func recordWrongC(original: Data, wrong: Data) throws {
        guard testCase == .badOTP, pendingIndex == 2, readIndex == 2, mutatedDigitCount == 0,
              original.count == 8, wrong.count == 8,
              original.allSatisfy({ (48...57).contains($0) }), wrong.allSatisfy({ (48...57).contains($0) }),
              zip(original, wrong).filter({ $0 != $1 }).count == 1, original != wrong else { throw SFTPOTPNegativeError.invalidResponse }
        mutatedDigitCount = 1; wrongCVerified = true
    }
    public func expiryReached(wall: Double, uptime: Double) throws -> Bool {
        guard testCase == .expiredOTP, pendingIndex == 2, readIndex == 2, let expiresAt, let cReadWall, let cReadUptime,
              wall.isFinite, uptime.isFinite, !closed, failure == nil, uptime < deadline else { throw SFTPOTPNegativeError.staleReply }
        // BOTH actual wall-clock expiry and elapsed monotonic duration must pass.
        // Clock jumps cannot manufacture an early expired-answer submission.
        return wall >= expiresAt + 0.05 && uptime >= cReadUptime + (expiresAt - cReadWall) + 0.05
    }
    public mutating func consume(index: Int, wall: Double, uptime: Double) throws {
        guard !closed, failure == nil, !awaitingResolution, pendingIndex == index, readIndex == index,
              index == replies, resolvedReplies == replies, wall.isFinite, uptime.isFinite, uptime < deadline, let expiresAt else {
            lateReplies += 1; throw SFTPOTPNegativeError.staleReply
        }
        if index == 2 {
            switch testCase {
            case .badOTP:
                guard wrongCVerified, mutatedDigitCount == 1, wall < expiresAt else { throw SFTPOTPNegativeError.earlyExpiry }
            case .expiredOTP:
                guard try expiryReached(wall: wall, uptime: uptime), mutatedDigitCount == 0 else { throw SFTPOTPNegativeError.earlyExpiry }
                realExpiryWaitVerified = true
            }
            cSubmittedWall = wall; cSubmittedUptime = uptime
        } else { guard wall < expiresAt else { throw SFTPOTPNegativeError.earlyExpiry } }
        replies += 1; pendingIndex = nil; readIndex = nil; awaitingResolution = true
    }
    public mutating func resolved(_ accepted: Bool) throws {
        guard !closed, failure == nil, awaitingResolution, accepted else { lateReplies += 1; throw SFTPOTPNegativeError.staleReply }
        resolvedReplies += 1; awaitingResolution = false
    }
    public mutating func fail(_ reason: SFTPOTPNegativeError) { if failure == nil { failure = reason }; close() }
    public mutating func close() { closed = true; pendingIndex = nil; readIndex = nil }
    public func requireInjected() throws {
        if let failure { throw failure }
        guard callbacks == 3, replies == 3, resolvedReplies == 3, managementReads == 3, !awaitingResolution, lateReplies == 0,
              cReadWall != nil, cSubmittedWall != nil,
              testCase == .badOTP ? (wrongCVerified && mutatedDigitCount == 1) : (realExpiryWaitVerified && mutatedDigitCount == 0) else { throw SFTPOTPNegativeError.invalidResponse }
    }
    public static func isTypedAuthentication(kind: String, operation: String, code: Int64?) -> Bool {
        kind == "authentication" && operation == "authenticate" && code == nil
    }
}

public struct SFTPOTPNegativeReport: Encodable, Sendable {
    public let taskID = "SFTP-OTP-NEGATIVE-A"
    public let productAcceptance = false
    public let firstContactGUIAcceptance = false
    public let service = "key-kbd"
    public let key = "edplain"
    public let authenticationOrder = ["publickey", "keyboard-interactive"]
    public let fileOperations = 0
    public let testCase: String
    public var actualSFTPConnects = 0
    public var callbackCount = 0
    public var secretReplyCount = 0
    public var managementResponseReads = 0
    public var lateReplyCount = 0
    public var sessionID: String?
    public var cExpiresAt: Double?
    public var cReadWall: Double?
    public var cSubmittedWall: Double?
    public var cHeldMonotonicSeconds: Double?
    public var mutatedDigitCount = 0
    public var wrongCVerified = false
    public var realExpiryWaitVerified = false
    public var typedAuthenticationRejected = false
    public var backendKind: String?
    public var backendOperation: String?
    public var backendCode: Int64?
    public var unexpectedChallenge: UnexpectedChallengeShape?
    public var closeCompleted = false
    public var managementChildrenReaped = false
    public var serverSessionFileRemoved = false
    public var result = "failed"
    public var failure: SFTPOTPNegativeError?
    public init(testCase: SFTPOTPNegativeCase) { self.testCase = testCase.rawValue }
    public mutating func record(_ budget: SFTPOTPNegativeBudget) {
        callbackCount = budget.callbacks; secretReplyCount = budget.replies; managementResponseReads = budget.managementReads
        lateReplyCount = budget.lateReplies; sessionID = budget.sessionID; cExpiresAt = budget.expiresAt
        cReadWall = budget.cReadWall; cSubmittedWall = budget.cSubmittedWall
        if let read = budget.cReadUptime, let submit = budget.cSubmittedUptime { cHeldMonotonicSeconds = submit - read }
        mutatedDigitCount = budget.mutatedDigitCount; wrongCVerified = budget.wrongCVerified; realExpiryWaitVerified = budget.realExpiryWaitVerified
    }
}
