import Foundation

public enum OpenSSHPhase: Equatable, Sendable { case primary, otp(session: String, index: Int) }

public struct OpenSSHAnswerBudget: Sendable {
    private let service: OpenSSHService
    private let primary: OpenSSHPrimary
    private let primaryHash: String?
    public let deadline: Double
    public private(set) var requests = 0
    public private(set) var primaryAnswers = 0
    public private(set) var otpAnswers = 0
    public private(set) var sessionID: String?
    public private(set) var usedRequests: Set<UUID> = []
    public private(set) var pending: UUID?
    public private(set) var pendingPhase: OpenSSHPhase?
    public private(set) var closed = false
    public init(service: OpenSSHService, primary: OpenSSHPrimary, primaryHash: String?, start: Double) throws {
        guard start.isFinite, start >= 0 else { throw OpenSSHError.invalidContract }
        self.service = service; self.primary = primary; self.primaryHash = primaryHash; deadline = start + OpenSSHContract.activeSeconds
    }
    public static func otpPrompt(port: Int, session: String, index: Int) throws -> String {
        guard (22221...22224).contains(port), Contract.hex(session, count: 24), (0..<3).contains(index) else { throw OpenSSHError.unknownRequest }
        let stem = ["One-time response A", "Unclassified verification B", "Next-round response C"][index]
        // OpenSSH9.9p2 input_userauth_info_req wraps the prompt using HostKeyAlias.
        // This full fixture-specific envelope must be observed unchanged in live;
        // no substring, unprefixed fallback or secret-type inference is permitted.
        return "(fixture@[127.0.0.1]:\(port)) \(stem) [\(session)]: "
    }
    public mutating func claim(id: UUID, prompt: String, kind: String, hasHint: Bool, now: Double) throws -> OpenSSHPhase {
        guard !closed, now.isFinite, now < deadline, pending == nil, !usedRequests.contains(id) else { throw OpenSSHError.staleRequest }
        requests += 1; usedRequests.insert(id)
        guard requests <= (primary == .none ? 0 : 1) + (service.mfa ? 3 : 0), kind == "unknownMasked", !hasHint else { throw OpenSSHError.extraRequest }
        let phase: OpenSSHPhase
        if primary != .none && primaryAnswers == 0 {
            guard let primaryHash, PrivateInput.sha256(Data(prompt.utf8)) == primaryHash else { throw OpenSSHError.unknownRequest }
            phase = .primary
        } else {
            guard service.mfa, otpAnswers < 3 else { throw OpenSSHError.extraRequest }
            let marker = " [", suffix = "]: "
            guard prompt.hasSuffix(suffix), let range = prompt.range(of: marker, options: .backwards) else { throw OpenSSHError.unknownRequest }
            let idText = String(prompt[range.upperBound..<prompt.index(prompt.endIndex, offsetBy: -suffix.count)])
            guard Contract.hex(idText, count: 24), try prompt == Self.otpPrompt(port: service.port, session: idText, index: otpAnswers),
                  sessionID == nil || sessionID == idText else { throw OpenSSHError.wrongRound }
            sessionID = idText; phase = .otp(session: idText, index: otpAnswers)
        }
        pending = id; pendingPhase = phase
        return phase
    }
    public mutating func consume(id: UUID, now: Double) throws {
        guard !closed, pending == id, now.isFinite, now < deadline, let phase = pendingPhase else { throw OpenSSHError.staleRequest }
        switch phase { case .primary: primaryAnswers += 1; case .otp: otpAnswers += 1 }
        pending = nil; pendingPhase = nil // Consume BEFORE public session.respond.
    }
    public mutating func close() { closed = true; pending = nil; pendingPhase = nil }
    public func requireComplete() throws {
        guard !closed, pending == nil, primaryAnswers == (primary == .none ? 0 : 1), otpAnswers == (service.mfa ? 3 : 0), requests == primaryAnswers + otpAnswers else { throw OpenSSHError.extraRequest }
    }
}

public struct OpenSSHOTP: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "<redacted root fixture response>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
    public let value: Data
    public let expiresAt: Double
    public static func decode(_ data: Data, session: String, index: Int, now: Double) throws -> Self {
        let object = try MinaJSON.object(data, keys: ["session", "index", "expires_at", "response"])
        guard Contract.hex(session, count: 24), (0..<3).contains(index), object["session"] as? String == session,
              object["index"] as? Int == index, let expires = object["expires_at"] as? Double, expires.isFinite,
              now.isFinite, expires > now, expires <= now + 75,
              let text = object["response"] as? String, text.utf8.count == 8, text.utf8.allSatisfy({ (48...57).contains($0) }) else { throw OpenSSHError.expiredResponse }
        return Self(value: Data(text.utf8), expiresAt: expires)
    }
}

public struct OpenSSHObservation: Encodable, Sendable {
    public let promptSHA256: String
    public let promptByteCount: Int
    public let kind: String
    public let hasHint: Bool
    public let matchesExpectedOTPEnvelope: Bool
    public init(prompt: String, kind: String, hasHint: Bool, service: OpenSSHService) {
        promptSHA256 = PrivateInput.sha256(Data(prompt.utf8)); promptByteCount = prompt.utf8.count
        self.kind = ["unknownMasked", "confirmation", "notification"].contains(kind) ? kind : "invalid"
        self.hasHint = hasHint
        let end = "]: "
        if prompt.hasSuffix(end), let range = prompt.range(of: " [", options: .backwards) {
            let id = String(prompt[range.upperBound..<prompt.index(prompt.endIndex, offsetBy: -end.count)])
            matchesExpectedOTPEnvelope = (0..<3).contains { (try? OpenSSHAnswerBudget.otpPrompt(port: service.port, session: id, index: $0)) == prompt }
        } else { matchesExpectedOTPEnvelope = false }
    }
}

public struct OpenSSHReport: Encodable, Sendable {
    public let taskID = "OPENSSH-FOUR-AUTH-A"
    public let productAcceptance = false
    public let firstContactGUIAcceptance = false
    public let testOnlyHostMinimum = "15.0"
    public let service: String
    public let key: String
    public let testCase: String
    public var connectedEvents = 0
    public var requests = 0
    public var primaryAnswers = 0
    public var otpAnswers = 0
    public var secretManagementReads = 0
    public var sessionID: String?
    public var observation: OpenSSHObservation?
    public var policyVerified = false
    public var serverSessionFileRemoved = false
    public var closeCompleted = false
    public var ownedPIDReleased = false
    public var managementChildrenReaped = false
    public var exitCode: Int32?
    public var result = "failed"
    public var failure: OpenSSHError?
    public init(contract: OpenSSHContract) { service = contract.service.rawValue; key = contract.key.rawValue; testCase = contract.testCase.rawValue }
}
