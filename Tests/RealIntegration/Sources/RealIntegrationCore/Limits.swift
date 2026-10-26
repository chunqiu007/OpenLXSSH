import Foundation

/// Exact request binding, not prompt interpretation. One answer per SSH run,
/// and no answers at all for key-only. Used by the real public callback.
public struct ResponseBudget: Sendable {
    public private(set) var requestCount = 0
    public private(set) var answerCount = 0
    public private(set) var refusedCount = 0
    private let plan: ResponsePlan
    public init(plan: ResponsePlan) { self.plan = plan }
    public mutating func claim(prompt: String, masked: Bool, hasHint: Bool) throws {
        requestCount += 1
        guard requestCount == 1, answerCount == 0 else { refusedCount += 1; throw SmokeError.extraAnswer }
        guard plan.kind == .singleManualPassword, masked, !hasHint,
              PrivateInput.sha256(Data(prompt.utf8)) == plan.expectedPromptSHA256 else {
            refusedCount += 1; throw SmokeError.unknownPrompt
        }
        answerCount += 1
    }
    public func requireConsumed() throws {
        let expected = plan.kind == .singleManualPassword ? 1 : 0
        guard answerCount == expected, requestCount == expected, refusedCount == 0 else { throw SmokeError.extraAnswer }
    }
}

public struct WaitBudget: Sendable {
    public let deadline: Double
    public let maximumTicks: Int
    public private(set) var ticks = 0
    public init(start: Double, seconds: Double, maximumTicks: Int) throws {
        guard start.isFinite, start >= 0, seconds.isFinite, seconds > 0,
              seconds <= 60, maximumTicks > 0, maximumTicks <= 6000 else { throw SmokeError.invalidArguments }
        deadline = start + seconds; self.maximumTicks = maximumTicks
    }
    public mutating func tick(now: Double, stopped: Bool = false) throws {
        if stopped { throw SmokeError.cancelled }
        guard now.isFinite, now < deadline, ticks < maximumTicks else { throw SmokeError.timeout }
        ticks += 1
    }
}

/// UUID-rooted single known payload; no recursion, broad path, unknown child
/// deletion, symlink following or caller-supplied remote path.
public struct RemoteOwnership: Sendable {
    public let directory: String
    public let payload: String
    public let payloadName = "tiny-payload.bin"
    public init(id: UUID = UUID()) {
        directory = "/fixture/home/openlxssh-real-" + id.uuidString.lowercased()
        payload = directory + "/tiny-payload.bin"
    }
    public func checkListing(_ names: [Data], payloadOwned: Bool) throws {
        guard names == (payloadOwned ? [Data(payloadName.utf8)] : []) else { throw SmokeError.cleanupIncomplete }
    }
}

/// Fixed metadata only. No prompt, terminal output, credential paths/values,
/// filesystem/server text, Error.description or arbitrary key/value properties.
public struct SmokeReport: Encodable, Sendable {
    public let schema = 1
    public let taskID = "LIVE-SMOKE-HOST15-A"
    public let productAcceptance = false
    public let firstContactGUIAcceptance = false
    public let testOnlyHostMinimum = "15.0"
    public let mode: String
    public let testCase: String
    public let service: String
    public var connectedEvents = 0
    public var requestCount = 0
    public var answerCount = 0
    public var refusedRequests = 0
    public var bytesWritten = 0
    public var bytesRead = 0
    public var listChecks = 0
    public var lstatChecks = 0
    public var closeCompleted = false
    public var ownedPIDReleased = false
    public var remoteCleanupCompleted = false
    public var exitCode: Int32?
    public var result = "failed"
    public var failure: String?
    public init(contract: Contract) {
        mode = contract.mode.rawValue; testCase = contract.testCase.rawValue; service = contract.service.rawValue
    }
}
