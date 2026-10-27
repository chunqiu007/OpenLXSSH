import Foundation

public enum CredentialStorePublicFailure: String, Codable, Sendable {
    case cancelled, interactionNotAllowed, unavailable, denied, duplicate, invalidData, closed
    case interactionPolicyRestoreFailed, otherStatus
}
public enum CredentialStorePublicSaveOutcome: Sendable { case saved, notAuthorized, failed(CredentialStorePublicFailure) }
public enum CredentialStorePublicDeleteOutcome: Sendable { case deleted, alreadyAbsent, retryRequired(CredentialStorePublicFailure) }

/// Pure lifecycle/recovery state. This is NOT an automatic recovery/adopt/delete
/// command: a prepared record alone never proves an external item's ownership.
public struct CredentialStorePublicState: Encodable, Sendable {
    public enum Phase: String, Codable, Sendable {
        case notPrepared, prepared, saveNotOwned, savedOwned, deletePending, deleted, missingVerified, closed
    }
    public let schema = 1
    public let namespace: UUID
    public let referenceID: UUID
    public let runID: UUID
    public private(set) var phase: Phase = .notPrepared
    public private(set) var ownsExactItem = false
    public private(set) var saveAttempted = false
    public private(set) var deleteAttempts = 0
    public private(set) var missingReadVerified = false
    public private(set) var interactionRestored = false
    public private(set) var failure: CredentialStorePublicError?
    public private(set) var credentialFailure: CredentialStorePublicFailure?
    public var service: String { "org.openlxssh.credentials.test." + namespace.uuidString }
    public var mayAttemptExactDelete: Bool { ownsExactItem && deleteAttempts == 0 }
    public init(namespace: UUID, referenceID: UUID, runID: UUID) {
        self.namespace = namespace; self.referenceID = referenceID; self.runID = runID
    }
    public mutating func preparedWasDurable() throws {
        guard phase == .notPrepared, !saveAttempted else { throw CredentialStorePublicError.recoveryRecordFailed }
        phase = .prepared
    }
    public mutating func beginSave() throws {
        guard phase == .prepared, !saveAttempted, failure == nil else { throw CredentialStorePublicError.recoveryRecordFailed }
        saveAttempted = true // Consume once. A killed process may retain only prepared.
    }
    public mutating func finishSave(_ outcome: CredentialStorePublicSaveOutcome) throws {
        guard phase == .prepared, saveAttempted, !ownsExactItem else { throw CredentialStorePublicError.ownershipUnconfirmed }
        switch outcome {
        case .saved: ownsExactItem = true; phase = .savedOwned
        case .notAuthorized: phase = .saveNotOwned; fail(.saveNotAuthorized)
        case .failed(let reason):
            phase = .saveNotOwned; credentialFailure = reason
            fail(reason == .duplicate ? .duplicateNotOwned : .saveFailed)
        }
    }
    public mutating func beginExactDelete() throws {
        guard mayAttemptExactDelete else { throw CredentialStorePublicError.ownershipUnconfirmed }
        deleteAttempts = 1; phase = .deletePending
    }
    public mutating func finishDelete(_ outcome: CredentialStorePublicDeleteOutcome) throws {
        guard phase == .deletePending, ownsExactItem, deleteAttempts == 1 else { throw CredentialStorePublicError.ownershipUnconfirmed }
        switch outcome {
        case .deleted, .alreadyAbsent: ownsExactItem = false; phase = .deleted
        case .retryRequired(let reason): credentialFailure = reason; fail(.deleteRetryRequired)
        }
    }
    public mutating func recordMissing(_ missing: Bool) throws {
        guard phase == .deleted else { throw CredentialStorePublicError.missingNotVerified }
        guard missing else { fail(.missingNotVerified); return }
        missingReadVerified = true; phase = .missingVerified
    }
    public mutating func recordClose(restored: Bool) {
        interactionRestored = restored
        if !restored { fail(.interactionRestoreFailed) }
        else if phase == .missingVerified { phase = .closed }
    }
    public mutating func fail(_ error: CredentialStorePublicError) { if failure == nil { failure = error } }
    public mutating func recordCredentialFailure(_ reason: CredentialStorePublicFailure) { credentialFailure = reason }
    public func requireSuccessfulLifecycle() throws {
        if let failure { throw failure }
        guard phase == .closed, saveAttempted, !ownsExactItem, deleteAttempts == 1, missingReadVerified, interactionRestored else { throw CredentialStorePublicError.cleanupIncomplete }
    }
}

/// Immutable nonsecret evidence only; no input path/credential value/hash/ACL.
public struct CredentialStorePublicRecoveryRecord: Encodable, Sendable {
    public let schema = 1
    public let taskID = "PUBLIC-CREDENTIAL-STORE-A"
    public let event: String
    public let state: CredentialStorePublicState
    public let keychainScope = CredentialStorePublicContract.scope
    public let physicalKeychainIsolation = false
    public let automaticRecoveryDeletionAllowed = false
    public init(event: String, state: CredentialStorePublicState) { self.event = event; self.state = state }
}

public struct CredentialStorePublicReport: Encodable, Sendable {
    public let taskID = "PUBLIC-CREDENTIAL-STORE-A"
    public let productAcceptance = false
    public let appUISaveForgetVerified = false
    public let physicalKeychainIsolation = false
    public let keychainScope = CredentialStorePublicContract.scope
    public let syncingDisabledByProductionQuery = true
    public let customACLConfigured = false
    public let sandboxAcceptance = false
    public let osGateScope = "existing-production-gate-no-whitelist-expansion"
    public var recoveryRunID: UUID
    public var testNamespace: UUID
    public var credentialReferenceID: UUID
    public var preparedRecordDurable = false
    public var saveConfirmedOwned = false
    public var storeOpened = false
    public var connectedEvents = 0
    public var providerCalls = 0
    public var providerReadCount = 0
    public var providerReturns = 0
    public var manualRequests = 0
    public var productionGateExercised = false
    public var closeCompleted = false
    public var ownedPIDReleased = false
    public var providerTasksDrained = false
    public var deleteAttempted = false
    public var exactDeleteConfirmed = false
    public var postForgetReadMissing = false
    public var storeCloseRestoredInteraction = false
    public var lifecycleVerified = false
    public var recoveryRecordsRetained = true
    public var result = "failed"
    public var failure: CredentialStorePublicError?
    public var credentialFailure: CredentialStorePublicFailure?
    public init(state: CredentialStorePublicState) {
        recoveryRunID = state.runID; testNamespace = state.namespace; credentialReferenceID = state.referenceID
    }
}
