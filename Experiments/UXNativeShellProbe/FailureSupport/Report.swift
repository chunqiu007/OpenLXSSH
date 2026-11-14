import Foundation
import OpenLXSSHFiles
import UXNativeShellProbeSupport

public enum NativeFailureObservation: String, Encodable, Sendable {
    case nativeUntrusted, nativeCancelled, sftpUntrusted, positiveShell, unexpected
}
public enum NativeFailureFailure: String, Encodable, Sendable {
    case preparation, nativeOrEvidence, activeDeadline, interrupted, cleanup, validation
}
/// Only these static public operation labels may cross the diagnostic boundary. Unknown
/// operation text is replaced, never copied (it could otherwise contain a path or payload).
public enum NativeFailureOperation: String, Encodable, Sendable {
    case handshake, connect, dns, socket, cancel, close, authentication
    case adoptSocket = "adopt-socket", hostKey = "host-key", changedHostKey = "host-key-changed"
    case handshakeHostKey = "handshake-host-key", authMethods = "auth-methods"
    case primaryAuthentication = "primary-authentication", keyboardAuthentication = "keyboard-authentication"
    case channelOpen = "channel-open", requestPTY = "request-pty", shellStart = "shell-start"
    case interactionDeadline = "interaction-deadline", authenticationDeadline = "authentication-deadline"
    case primaryProviderDeadline = "primary-provider-deadline", primaryMethodUnavailable = "primary-method-unavailable"
    case interactionProducerSealed = "interaction-producer-sealed", drainTimeout = "interaction-drain-timeout"
    case socketFlags = "socket-flags", connectPoll = "connect-poll", connectStatus = "connect-status"
    case dnsWorkers = "dns-workers", dnsNoAddress = "dns-no-address"
    case otherPublicOperation
    public init(publicOperation: String) {
        self = Self(rawValue: publicOperation) ?? .otherPublicOperation
    }
}
public enum NativeFailureErrorDomain: String, Encodable, Sendable { case nativeShell, fileService }
public struct NativeFailureTypedDiagnostic: Encodable, Sendable {
    public let domain: NativeFailureErrorDomain
    public let kind: String // Always the closed public Kind.rawValue, never Error.description.
    public let operation: NativeFailureOperation
    public let code: Int64?
    public let pendingInteractionTasks: Int?
    public let interactionDrainPresent: Bool?
    public init(_ error: NativeShellError) {
        domain = .nativeShell; kind = error.kind.rawValue
        operation = NativeFailureOperation(publicOperation: error.operation)
        code = error.code.map(Int64.init); pendingInteractionTasks = error.pendingInteractionTasks
        interactionDrainPresent = error.interactionDrain != nil
    }
    public init(_ error: FileServiceError) {
        domain = .fileService; kind = error.kind.rawValue
        operation = NativeFailureOperation(publicOperation: error.operation)
        code = error.code; pendingInteractionTasks = nil; interactionDrainPresent = nil
    }
}
public enum NativeFailureValidationFailure: String, Error, Encodable, Sendable {
    case nativeChangedCapture, providerEntry, providerCancellationCapture
    case sftpChangedCapture, unexpectedSFTPConnection, caseExecution, finalReport
}
public struct NativeFailureStages: Encodable, Sendable {
    public var advertised = 0
    public var advertisedPublicKey = false
    public var primaryStarted = 0
    public var primaryResults = 0
    public var keyboardStarted = 0
    public var keyboardResults = 0
    public var authenticated = 0
    public var shellReady = 0
    public init(_ stages: [NativeShellAuthenticationStage]) {
        for stage in stages {
            switch stage {
            case .advertised(_, let publicKey, _): advertised += 1; advertisedPublicKey = publicKey
            case .primaryStarted: primaryStarted += 1
            case .primaryResult: primaryResults += 1
            case .keyboardStarted: keyboardStarted += 1
            case .keyboardResult: keyboardResults += 1
            case .authenticated: authenticated += 1
            case .shellReady: shellReady += 1
            }
        }
    }
    public var noAuthenticationStarted: Bool {
        primaryStarted == 0 && primaryResults == 0 && keyboardStarted == 0 && keyboardResults == 0 &&
        authenticated == 0 && shellReady == 0
    }
}
public struct NativeFailureDrain: Encodable, Sendable {
    public let pending: Int, providers: Int
    public let revoked: Bool, nativeClosed: Bool, sealed: Bool, drained: Bool
    public init(_ value: NativeShellInteractionSnapshot) {
        self.init(pending: value.pendingTasks, providers: value.pendingProviders, revoked: value.revoked,
            nativeClosed: value.nativeClosed, sealed: value.producersSealed)
    }
    /// Pure test-report data initializer; not a product interaction registry or a live fact source.
    public init(pending: Int, providers: Int, revoked: Bool, nativeClosed: Bool, sealed: Bool) {
        self.pending = pending; self.providers = providers; self.revoked = revoked
        self.nativeClosed = nativeClosed; self.sealed = sealed
        drained = nativeClosed && sealed && pending == 0
    }
}

/// Closed static schema: never serializes errors, argv, paths, terminal bytes, prompt text,
/// credentials, key lengths/hashes or management output. Nil means unavailable, never a fake zero.
public struct NativeFailureReport: Encodable, Sendable {
    public static let taskIdentifier = "NATIVE-FAILURE-LIVE-CONSUMER-R1"
    public let taskID = Self.taskIdentifier
    public let schema = 1
    public let diagnosticRevision = 2
    public let testOnly = true
    public let productAcceptance = false
    public let minimumOS = "26.0"
    public let rawHandshakeBytesExposed = false
    public let controlledTrustDispatcherPubliclyAvailable = false
    public let delayedCallbackCaseIncluded = false
    public let sftpAuthenticationInstrumentationAvailable = false
    public let testCase: NativeFailureCase
    public let service: String
    public let key: String
    public var sessionAttempts = 0
    public var fixedIdentityVerified = false
    public var policyVerified = false
    public var freshWithin120Seconds = false
    public var observation: NativeFailureObservation = .unexpected
    public var typedError: NativeFailureTypedDiagnostic?
    public var validationFailure: NativeFailureValidationFailure?
    public var stages: NativeFailureStages?
    public var primaryProviderCalls: Int?
    public var providerEntered = false
    public var providerReturnedAfterCancellation = false
    public var providerFinished = false
    public var referencesDroppedBeforeWait = false
    public var handleIdentityStable = false
    public var handleFromTypedError = false
    public var beforeRelease: NativeFailureDrain?
    public var afterShortWait: NativeFailureDrain?
    public var afterRelease: NativeFailureDrain?
    public var closeAfterCancellationSeconds: Double?
    public var heldAfterCloseSeconds: Double?
    public var laterDrainSeconds: Double?
    public var changedEndpointExact = false
    public var changedAlgorithmExact = false
    public var expectedFingerprintMatchesSeed = false
    public var presentedFingerprintMatchesOutOfBand = false
    public var knownHostsBytesUnchanged = false
    public var knownHostsInodeUnchanged = false
    public var publicFixtureKnownHostsUnchanged = false
    public var inputCalls = 0
    public var authentication: ShellProbeAuthenticationEvidence?
    public var ack = false
    public var remotePTY = false
    public var resized37x113 = false
    public var remoteEOF = false
    public var exitStatus: Int32?
    public var exitSignalPresent = false
    public var closeCompleted = false
    public var callbackCount = 0
    public var replyCount = 0
    public var managementResponseReads = 0
    public var terminalZeroReplies = 0
    public var lateReplies = 0
    public var managementChildrenReaped = false
    public var serverSessionFileRemoved = false
    public var descriptorCountBefore: Int?
    public var descriptorCountAfter: Int?
    public var childCountBefore: Int?
    public var childCountAfter: Int?
    public var processIDBefore: Int?
    public var processIDAfter: Int?
    public var resourcesReturnedToBaseline = false
    public var ownedTestRootRemoved = false
    public var providerGateReleasedDuringTeardown = false
    public var activeSeconds = 0.0
    public var cleanupSeconds = 0.0
    public var failure: NativeFailureFailure?
    public var result = "failed"
    public init(testCase: NativeFailureCase) {
        self.testCase = testCase; service = testCase.fixture.rawValue; key = testCase.key
    }
    private var changedExact: Bool {
        changedEndpointExact && changedAlgorithmExact && expectedFingerprintMatchesSeed &&
        presentedFingerprintMatchesOutOfBand && knownHostsBytesUnchanged && knownHostsInodeUnchanged
    }
    public func requireExpected() throws {
        guard failure == nil, sessionAttempts == 1, fixedIdentityVerified, policyVerified,
              freshWithin120Seconds, activeSeconds.isFinite, activeSeconds >= 0,
              activeSeconds <= testCase.activeLimit, cleanupSeconds.isFinite, cleanupSeconds >= 0,
              cleanupSeconds <= 12, closeCompleted, resourcesReturnedToBaseline, ownedTestRootRemoved,
              publicFixtureKnownHostsUnchanged, managementChildrenReaped, serverSessionFileRemoved,
              let before = descriptorCountBefore, before > 0, descriptorCountAfter == before,
              let children = childCountBefore, children >= 0, childCountAfter == children,
              let pid = processIDBefore, pid > 1, processIDAfter == pid else { throw NativeFailureCheckError.evidence }
        switch testCase {
        case .nativeChangedNoHandler:
            guard observation == .nativeUntrusted, changedExact, primaryProviderCalls == 0,
                  let stages, stages.advertised == 0, stages.noAuthenticationStarted,
                  handleFromTypedError, handleIdentityStable, afterRelease?.drained == true,
                  afterRelease?.nativeClosed == true, afterRelease?.sealed == true,
                  callbackCount == 0, replyCount == 0, managementResponseReads == 0, inputCalls == 0 else {
                throw NativeFailureCheckError.evidence
            }
        case .sftpChangedNoHandler:
            guard observation == .sftpUntrusted, changedExact, stages == nil, primaryProviderCalls == nil,
                  callbackCount == 0, replyCount == 0, managementResponseReads == 0, inputCalls == 0 else {
                throw NativeFailureCheckError.evidence
            }
        case .nativeCancelledProvider:
            guard observation == .nativeCancelled, primaryProviderCalls == 1, providerEntered,
                  providerReturnedAfterCancellation, providerFinished, referencesDroppedBeforeWait,
                  providerGateReleasedDuringTeardown, handleFromTypedError, handleIdentityStable,
                  let stages, stages.advertised == 1, stages.advertisedPublicKey, stages.noAuthenticationStarted,
                  let beforeRelease, beforeRelease.nativeClosed, beforeRelease.sealed, beforeRelease.revoked,
                  beforeRelease.pending > 0, beforeRelease.providers == 1, !beforeRelease.drained,
                  let afterShortWait, afterShortWait.nativeClosed, afterShortWait.sealed,
                  afterShortWait.pending > 0, afterShortWait.providers == 1, !afterShortWait.drained,
                  afterRelease?.drained == true, afterRelease?.pending == 0, afterRelease?.providers == 0,
                  let close = closeAfterCancellationSeconds, close.isFinite, close >= 0.5, close <= 3,
                  let held = heldAfterCloseSeconds, held.isFinite, held >= 0.05, held <= 1,
                  let later = laterDrainSeconds, later.isFinite, later >= 0, later <= 2,
                  callbackCount == 0, replyCount == 0, managementResponseReads == 0, inputCalls == 0 else {
                throw NativeFailureCheckError.evidence
            }
        case .keyKIPositive, .passwordKIPositive:
            guard observation == .positiveShell, let authentication,
                  authentication.primaryMethod == (testCase == .keyKIPositive ? "publicKey" : "password"),
                  authentication.primaryStarted == 1, authentication.primaryResults == 1,
                  authentication.primaryCode == (testCase == .keyKIPositive ? -19 : -18),
                  !authentication.primaryAuthenticated, authentication.keyboardStarted == 1,
                  authentication.keyboardResults == 1, authentication.keyboardCode == 0,
                  authentication.keyboardAuthenticated == true, authentication.authenticatedEvents == 1,
                  authentication.shellReadyEvents == 1, ack, remotePTY, resized37x113, remoteEOF,
                  exitStatus == 7, !exitSignalPresent, inputCalls == 1, callbackCount == 4,
                  replyCount == 4, managementResponseReads == 3, terminalZeroReplies == 1, lateReplies == 0 else {
                throw NativeFailureCheckError.evidence
            }
        }
    }
}
