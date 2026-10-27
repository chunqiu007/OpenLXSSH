import Foundation

/// Counts public provider/manual control flow only, NOT persistence or a prompt
/// classifier. Authorization provider receives a generation token, not a prompt.
public struct SavedPasswordPublicBudget: Sendable {
    public let testCase: SavedPasswordPublicCase
    private let manualHash: String?
    public private(set) var sessionID: UUID?
    public private(set) var generation: UInt64?
    public private(set) var providerCalls = 0
    public private(set) var providerSecretReads = 0
    public private(set) var providerReturns = 0
    public private(set) var manualRequests = 0
    public private(set) var manualSecretReads = 0
    public private(set) var manualReplies = 0
    public private(set) var gateNotCovered = false
    public private(set) var closed = false
    public private(set) var failure: SavedPasswordPublicError?
    private var providerInFlight = false
    private var pendingManualID: UUID?
    private var manualIDs: Set<UUID> = []
    public init(testCase: SavedPasswordPublicCase, manualHash: String?) {
        self.testCase = testCase; self.manualHash = manualHash
    }
    public mutating func bind(session: UUID, generation: UInt64) throws {
        guard !closed, sessionID == nil, self.generation == nil, generation > 0 else { throw SavedPasswordPublicError.staleGeneration }
        sessionID = session; self.generation = generation
    }
    private func current(_ session: UUID, _ generation: UInt64) -> Bool {
        !closed && sessionID == session && self.generation == generation
    }
    public mutating func beginProvider(session: UUID, generation: UInt64, cancelled: Bool) throws {
        providerCalls += 1
        do {
            guard testCase == .authorized, !cancelled, current(session, generation), failure == nil else { throw SavedPasswordPublicError.staleGeneration }
            guard providerCalls == 1, providerSecretReads == 0, providerReturns == 0, !providerInFlight, manualRequests == 0 else { throw SavedPasswordPublicError.extraProviderCall }
            providerInFlight = true
        } catch { failure = (error as? SavedPasswordPublicError) ?? .providerFailed; throw error }
    }
    public mutating func claimProviderRead(session: UUID, generation: UInt64, cancelled: Bool) throws {
        guard !cancelled, current(session, generation), failure == nil, providerInFlight, providerSecretReads == 0 else { throw SavedPasswordPublicError.staleGeneration }
        providerSecretReads = 1 // Consume before the no-follow asynchronous read.
    }
    public mutating func finishProvider(session: UUID, generation: UInt64, cancelled: Bool) throws {
        guard !cancelled, current(session, generation), failure == nil, providerInFlight, providerSecretReads == 1, providerReturns == 0 else { throw SavedPasswordPublicError.staleGeneration }
        providerReturns = 1; providerInFlight = false
    }
    public mutating func claimManual(id: UUID, session: UUID, generation: UInt64, prompt: String, kind: String, hasHint: Bool) throws {
        manualRequests += 1
        do {
            guard current(session, generation), failure == nil else { throw SavedPasswordPublicError.staleGeneration }
            if testCase == .authorized { gateNotCovered = true; throw SavedPasswordPublicError.gateNotCovered }
            guard providerCalls == 0, manualRequests == 1, pendingManualID == nil, !manualIDs.contains(id),
                  kind == "unknownMasked", !hasHint, let manualHash, PrivateInput.sha256(Data(prompt.utf8)) == manualHash else { throw SavedPasswordPublicError.unknownManualRequest }
            manualIDs.insert(id); pendingManualID = id
            manualSecretReads = 1
        } catch { failure = (error as? SavedPasswordPublicError) ?? .unknownManualRequest; throw error }
    }
    public mutating func finishManual(id: UUID, session: UUID, generation: UInt64, cancelled: Bool) throws {
        guard !cancelled, current(session, generation), failure == nil, pendingManualID == id, manualSecretReads == 1, manualReplies == 0 else { throw SavedPasswordPublicError.staleGeneration }
        pendingManualID = nil; manualReplies = 1 // Before session.respond; never replay.
    }
    public mutating func fail(_ reason: SavedPasswordPublicError) { if failure == nil { failure = reason } }
    public mutating func close() { closed = true; pendingManualID = nil }
    public func requireExpected(connectedEvents: Int) throws {
        if let failure { throw failure }
        guard connectedEvents == 1, !gateNotCovered else { throw SavedPasswordPublicError.connectionFailed }
        switch testCase {
        case .authorized:
            guard providerCalls == 1, providerSecretReads == 1, providerReturns == 1, !providerInFlight,
                  manualRequests == 0, manualSecretReads == 0, manualReplies == 0 else { throw SavedPasswordPublicError.gateNotCovered }
        case .manualFallback:
            guard providerCalls == 0, providerSecretReads == 0, providerReturns == 0,
                  manualRequests == 1, manualSecretReads == 1, manualReplies == 1 else { throw SavedPasswordPublicError.connectionFailed }
        }
    }
}

public struct SavedPasswordPublicReport: Encodable, Sendable {
    public let taskID = "SAVED-PASSWORD-PUBLIC-A"
    public let productAcceptance = false
    public let keychainAccess = false
    public let persistenceVerified = false
    public let testOnlyHostMinimum = "15.0"
    public let providerHasPromptParameter = false
    public let testCase: String
    public var connectedEvents = 0
    public var providerCalls = 0
    public var providerSecretReads = 0
    public var providerReturns = 0
    public var manualRequests = 0
    public var manualSecretReads = 0
    public var manualReplies = 0
    public var productionGateExercised = false
    public var gateNotCovered = false
    public var closeCompleted = false
    public var ownedPIDReleased = false
    public var providerAndManualTasksDrained = false
    public var managementChildrenReaped = false
    public var exitCode: Int32?
    public var result = "failed"
    public var failure: SavedPasswordPublicError?
    public init(testCase: SavedPasswordPublicCase) { self.testCase = testCase.rawValue }
    public mutating func record(_ budget: SavedPasswordPublicBudget) {
        providerCalls = budget.providerCalls; providerSecretReads = budget.providerSecretReads; providerReturns = budget.providerReturns
        manualRequests = budget.manualRequests; manualSecretReads = budget.manualSecretReads; manualReplies = budget.manualReplies
        gateNotCovered = budget.gateNotCovered
    }
}
