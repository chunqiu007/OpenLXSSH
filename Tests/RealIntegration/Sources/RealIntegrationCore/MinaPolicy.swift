import CoreFoundation
import Foundation

/// Test-only exact fixture envelope correlation, never a prompt/password classifier.
public struct MinaCallbackBudget: Sendable {
    public let testCase: MinaCase
    public let deadline: Double
    public private(set) var callbackCount = 0
    public private(set) var replyCount = 0
    public private(set) var responseCount = 0
    public private(set) var managementReads = 0
    public private(set) var lateReplyCount = 0
    public private(set) var promptCounts: [Int] = []
    public private(set) var echoes: [[Bool]] = []
    public private(set) var attemptID: String?
    public private(set) var closed = false
    public private(set) var failure: MinaError?
    public init(testCase: MinaCase, start: Double) throws {
        guard start.isFinite, start >= 0 else { throw MinaError.invalidContract }
        self.testCase = testCase; deadline = start + MinaContract.caseSeconds
    }
    public mutating func claim(name: Data, instruction: Data, prompts: [Data], echo: [Bool], now: Double) throws -> String {
        callbackCount += 1
        do {
            guard !closed, now.isFinite, now < deadline else { throw MinaError.lateReply }
            guard callbackCount == 1, replyCount == 0 else { throw MinaError.extraCallback }
            let prefix = Data("OpenLXSSH fixture ".utf8)
            guard name.starts(with: prefix), name.count == prefix.count + 24 else { throw MinaError.unknownChallenge }
            let id = String(decoding: name.dropFirst(prefix.count), as: UTF8.self)
            guard Contract.hex(id, count: 24) else { throw MinaError.unknownChallenge }
            let suffix = testCase == .twoCorrect ? "; enter the two independent test responses."
                : "; no input prompts. " + testCase.scenario + "; cancellation closes this connection."
            guard instruction == Data(("Disposable test only; attempt " + id + suffix).utf8) else { throw MinaError.unknownChallenge }
            let expected = testCase == .twoCorrect ? [Data("Test response A: ".utf8), Data("Unclassified test response B: ".utf8)] : []
            guard prompts == expected, echo == (testCase == .twoCorrect ? [false, true] : []) else { throw MinaError.unknownChallenge }
            promptCounts.append(prompts.count); echoes.append(echo); attemptID = id
            return id
        } catch {
            failure = (error as? MinaError) ?? .unknownChallenge
            throw error
        }
    }
    public mutating func claimManagementRead() throws {
        guard !closed, testCase == .twoCorrect, callbackCount == 1, managementReads == 0 else {
            failure = .extraCallback; throw MinaError.extraCallback
        }
        managementReads = 1
    }
    public mutating func claimReply(responseCount count: Int, now: Double) throws {
        guard !closed, now.isFinite, now < deadline else { lateReplyCount += 1; failure = .lateReply; throw MinaError.lateReply }
        guard failure == nil, callbackCount == 1, attemptID != nil, replyCount == 0,
              count == testCase.promptCount, managementReads == (testCase == .twoCorrect ? 1 : 0) else {
            failure = .extraCallback; throw MinaError.extraCallback
        }
        replyCount = 1; responseCount = count // Consume BOTH answers before the single resolve.
    }
    public mutating func resolved(_ accepted: Bool) {
        if !accepted { lateReplyCount += 1; failure = .lateReply }
    }
    public mutating func fail(_ error: MinaError) { if failure == nil { failure = error } }
    public mutating func close() { closed = true }
    public func requireComplete() throws {
        if let failure { throw failure }
        guard callbackCount == 1, replyCount == 1, responseCount == testCase.promptCount,
              promptCounts == [testCase.promptCount], echoes == (testCase == .twoCorrect ? [[false, true]] : [[]]),
              managementReads == (testCase == .twoCorrect ? 1 : 0), lateReplyCount == 0 else { throw MinaError.statusMismatch }
    }
}

/// No printable/Codable/mirror surface for the management response bytes.
public struct MinaResponses: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "<redacted MINA responses>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
    public let values: [Data]
    public static func decode(_ data: Data, attempt: String, now: Double) throws -> Self {
        guard Contract.hex(attempt, count: 24), now.isFinite else { throw MinaError.invalidResponses }
        let object = try MinaJSON.object(data, keys: ["attempt", "expires_at", "responses", "echo"])
        guard object["attempt"] as? String == attempt,
              let expiry = object["expires_at"] as? NSNumber, CFGetTypeID(expiry) != CFBooleanGetTypeID(),
              expiry.doubleValue.isFinite, expiry.doubleValue > now, expiry.doubleValue <= now + 75,
              let echo = object["echo"] as? [NSNumber], echo.count == 2,
              echo.allSatisfy({ CFGetTypeID($0) == CFBooleanGetTypeID() }), echo.map({ $0.boolValue }) == [false, true],
              let strings = object["responses"] as? [String], strings.count == 2,
              strings.allSatisfy({ $0.utf8.count == 10 && $0.utf8.allSatisfy({ (48...57).contains($0) }) }) else { throw MinaError.invalidResponses }
        return Self(values: strings.map { Data($0.utf8) })
    }
}

public struct MinaStatus: Sendable, Codable {
    public let generated: Int
    public let response_callbacks: Int
    public let zero_response_callbacks: Int
    public let ignored_late_results: Int
    public let sessions: Int
    public let scheduler_queue: Int
    public let pending: [Pending]
    public let outcomes: [String: Int]
    public struct Pending: Sendable, Codable {
        public let attempt: String
        public let scenario: String
        public let prompt_count: Int
        public let responded: Bool
        public let expires_at: Int
    }
    public static func decode(_ data: Data) throws -> Self {
        let object = try MinaJSON.object(data, keys: ["generated", "response_callbacks", "zero_response_callbacks", "ignored_late_results", "sessions", "scheduler_queue", "pending", "outcomes"])
        for key in ["generated", "response_callbacks", "zero_response_callbacks", "ignored_late_results", "sessions", "scheduler_queue"] {
            guard let n = object[key] as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue.isFinite,
                  n.doubleValue >= 0, n.doubleValue <= Double(Int32.max), n.doubleValue.rounded() == n.doubleValue else { throw MinaError.statusMismatch }
        }
        let status = try JSONDecoder().decode(Self.self, from: data)
        let reasons: Set<String> = ["replaced", "setup-failed", "rejected", "accepted", "approved", "expired", "session-closed", "shutdown"]
        guard status.sessions <= 8, status.scheduler_queue <= 16, status.pending.count <= 8,
              Set(status.outcomes.keys).isSubset(of: reasons), status.outcomes.values.allSatisfy({ $0 >= 0 && $0 <= Int32.max }) else { throw MinaError.statusMismatch }
        return status
    }
    public func requireIdle() throws {
        guard sessions == 0, scheduler_queue == 0, pending.isEmpty else { throw MinaError.statusMismatch }
    }
    public func requireRespondedCancellation(attempt: String, before: Self) throws {
        try before.requireIdle()
        guard Contract.hex(attempt, count: 24), sessions == 1, pending.count == 1,
              pending[0].attempt == attempt, pending[0].scenario == "cancel", pending[0].prompt_count == 0,
              pending[0].responded, scheduler_queue <= 2,
              generated == before.generated + 1, response_callbacks == before.response_callbacks + 1,
              zero_response_callbacks == before.zero_response_callbacks + 1,
              ignored_late_results == before.ignored_late_results else { throw MinaError.statusMismatch }
        for key in Set(outcomes.keys).union(before.outcomes.keys) {
            guard outcomes[key, default: 0] == before.outcomes[key, default: 0] else { throw MinaError.statusMismatch }
        }
    }
    public func requireExactDelta(from before: Self, testCase: MinaCase) throws {
        try before.requireIdle(); try requireIdle()
        guard generated == before.generated + 1, response_callbacks == before.response_callbacks + 1,
              zero_response_callbacks == before.zero_response_callbacks + (testCase == .twoCorrect ? 0 : 1),
              ignored_late_results == before.ignored_late_results else { throw MinaError.statusMismatch }
        let expected = testCase.expectedOutcome
        for key in Set(outcomes.keys).union(before.outcomes.keys).union([expected]) {
            guard outcomes[key, default: 0] == before.outcomes[key, default: 0] + (key == expected ? 1 : 0) else { throw MinaError.statusMismatch }
        }
    }
}

public enum MinaBackendObservation: String, Codable, Sendable {
    case authenticatedThenSFTPUnavailable, authenticationRejected, authenticationCancelled, unexpectedSuccess, unexpectedFailure
    public static func classify(kind: String, operation: String, code: Int64?) -> Self {
        // Locked libssh2 1.11.1 converts a denied SFTP subsystem request to -21.
        // SharedHostTrust's public error path has already awaited native close.
        if kind == "transport", operation == "sftp-init", code == -21 { return .authenticatedThenSFTPUnavailable }
        if kind == "authentication", operation == "authenticate", code == nil { return .authenticationRejected }
        if kind == "cancelled", operation == "authenticate", code == -10001 { return .authenticationCancelled }
        return .unexpectedFailure
    }
    public func requireExpected(_ testCase: MinaCase) throws {
        let expected: Self
        switch testCase {
        case .cancelWait: expected = .authenticationCancelled
        case .zeroReject, .reject: expected = .authenticationRejected
        default: expected = .authenticatedThenSFTPUnavailable
        }
        guard self == expected else { throw MinaError.backendMismatch }
    }
}

/// Monotonic timing from immediately BEFORE the successful zero reply resolve.
/// A post-close late callback count of zero is not proof of a raced completion.
public struct MinaAsyncEvidence: Sendable, Encodable {
    public let reference = "monotonic-before-successful-zero-reply-resolve"
    public private(set) var replyAt: Double?
    public private(set) var backendAt: Double?
    public private(set) var pendingObservedAt: Double?
    public private(set) var cancelRequestedAt: Double?
    public private(set) var postDecisionStatusAt: Double?
    public private(set) var providerPolicyVerified = false
    public private(set) var pendingRespondedVerified = false
    public let fixedProviderDelaySeconds = MinaContract.providerDelaySeconds
    public let minimumCancelAfterReplySeconds = MinaContract.cancelAfterReplySeconds
    public init() {}
    public mutating func recordReply(at now: Double) throws {
        guard replyAt == nil, now.isFinite, now >= 0 else { throw MinaError.statusMismatch }
        replyAt = now
    }
    public mutating func recordBackend(at now: Double) throws {
        guard let replyAt, now.isFinite, now >= replyAt, backendAt == nil else { throw MinaError.statusMismatch }
        backendAt = now
    }
    public mutating func recordPolicyVerified() { providerPolicyVerified = true }
    public mutating func recordPending(_ status: MinaStatus, before: MinaStatus, attempt: String, now: Double) throws {
        guard let replyAt, now.isFinite, now >= replyAt, pendingObservedAt == nil else { throw MinaError.statusMismatch }
        try status.requireRespondedCancellation(attempt: attempt, before: before)
        pendingObservedAt = now; pendingRespondedVerified = true
    }
    public mutating func recordCancellation(at now: Double) throws {
        guard let replyAt, let pendingObservedAt, now.isFinite,
              now >= replyAt + MinaContract.cancelAfterReplySeconds, now >= pendingObservedAt,
              now < replyAt + MinaContract.providerDelaySeconds, cancelRequestedAt == nil,
              pendingRespondedVerified, providerPolicyVerified else { throw MinaError.statusMismatch }
        cancelRequestedAt = now
    }
    public mutating func recordPostDecisionStatus(at now: Double) throws {
        guard let pendingObservedAt, now.isFinite,
              now >= pendingObservedAt + MinaContract.providerDelaySeconds else { throw MinaError.statusMismatch }
        postDecisionStatusAt = now
    }
    public func requireExpected(_ testCase: MinaCase) throws {
        guard testCase.isAsync, providerPolicyVerified, let replyAt, let backendAt else { throw MinaError.statusMismatch }
        if testCase == .cancelWait {
            guard pendingRespondedVerified, let cancelled = cancelRequestedAt, let pending = pendingObservedAt,
                  backendAt >= cancelled, cancelled >= replyAt + MinaContract.cancelAfterReplySeconds,
                  cancelled < replyAt + MinaContract.providerDelaySeconds,
                  let after = postDecisionStatusAt, after >= pending + MinaContract.providerDelaySeconds else { throw MinaError.statusMismatch }
        } else {
            guard backendAt - replyAt >= MinaContract.providerDelaySeconds, cancelRequestedAt == nil else { throw MinaError.statusMismatch }
        }
    }
}

public struct MinaReport: Encodable, Sendable {
    public let taskID = "AUTH-MINA-PRODUCTION-KBI-A"
    public let authOnly = true
    public let sftpSuccess = false
    public let fileAcceptance = false
    public let productAcceptance = false
    public let firstContactGUIAcceptance = false
    public let testOnlyHostMinimum = "15.0"
    public let testCase: String
    public var callbackCount = 0
    public var promptCounts: [Int] = []
    public var echoFlags: [[Bool]] = []
    public var replyCount = 0
    public var responseCount = 0
    public var managementResponseReads = 0
    public var lateReplyCount = 0
    public var attemptID: String?
    public var backend = MinaBackendObservation.unexpectedFailure
    public var before: MinaStatus?
    public var after: MinaStatus?
    public var statusDeltaVerified = false
    public var closeCompleted = false
    public var managementChildrenReaped = false
    public var asyncEvidence: MinaAsyncEvidence?
    public var postDecisionStatus: MinaStatus?
    public var postDecisionStatusVerified = false
    public var result = "failed"
    public var failure: MinaError?
    public init(testCase: MinaCase) { self.testCase = testCase.rawValue }
    public mutating func record(_ budget: MinaCallbackBudget) {
        callbackCount = budget.callbackCount; promptCounts = budget.promptCounts; echoFlags = budget.echoes
        replyCount = budget.replyCount; responseCount = budget.responseCount; managementResponseReads = budget.managementReads
        lateReplyCount = budget.lateReplyCount; attemptID = budget.attemptID
    }
}
