import Foundation

public struct NativeLivenessReport: Encodable, Sendable {
    public let taskID = "NATIVE-LIVENESS-SUPERVISOR-R2"
    public let run: String
    public let role: NativeLivenessRole
    public let instrumented: Bool
    public var session: String?
    public var sourcePort: Int?
    public var prepareSeconds = 0.0
    public var quietSeconds = 0.0
    public var quietOutputBytes = 0
    public var shellACK = false
    public var freshACK = false
    public var sourceGateVerified = true // Build record gate, supervisor independently revalidates.
    public var contractFresh = false
    public var preArm: NativeLivenessProof?
    public var final: NativeLivenessProof?
    public var nativeKind: String?
    public var nativeOperation: String?
    public var naturalResultAt: Double?
    public var dropToResultSeconds: Double?
    public var clock: NativeLivenessClockEvidence?
    public var proofLower: Double?
    public var proofUpper: Double?
    public var armReadySent: Double?
    public var dropACKReceived: Double?
    public var armAge: NativeLivenessArmAge?
    public var naturalExit: Int32?
    public var naturalResultBeforeCancel = false
    public var cancelBeforeResult = false
    public var deadlineBeforeResult = false
    public var ownerLostBeforeResult = false
    public var stoppedBeforeResult = false
    public var closed = false
    public var interactionsDrained = false
    public var fdReturnedToBaseline = false
    public var extraChannelsAtProof = 0
    public var extraChannelsAfterClose = 0
    public var instrumentedRealOpenCode = 0
    public var instrumentedRejections = 0
    public var instrumentedSessionFreed = false
    public var instrumentedThreadViolation = false
    public var failure: String?
    public init(run: String, role: NativeLivenessRole, instrumented: Bool) {
        self.run = run; self.role = role; self.instrumented = instrumented
    }
}
