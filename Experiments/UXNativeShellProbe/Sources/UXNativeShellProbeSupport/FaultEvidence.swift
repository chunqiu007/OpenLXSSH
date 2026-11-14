import Foundation
import OpenLXSSHFiles

/// Test-only finite cases. The material schema still selects a disposable generation/key;
/// this enum cannot select an arbitrary endpoint, command, credential path or retry plan.
public enum ShellProbeCase: String, CaseIterable, Sendable {
    case positive
    case wrongPrimary = "wrong-primary"
    case hostkeyMismatch = "hostkey-mismatch"
    case cancelKI = "cancel-ki"
    case cancelAfterReady = "cancel-after-ready"
    case encryptedEd = "encrypted-ed"
    case rsa
    public var isNegative: Bool {
        switch self {
        case .wrongPrimary, .hostkeyMismatch, .cancelKI, .cancelAfterReady: true
        default: false
        }
    }
    public func validate(fixture: ShellProbeFixture, key: String) throws {
        switch self {
        case .positive: break // Original strict material schema remains authoritative.
        case .wrongPrimary, .hostkeyMismatch, .cancelAfterReady:
            guard fixture == .passwordonly, key == "none" else { throw ShellProbeError.fixture }
        case .cancelKI:
            guard fixture == .passwordKbd, key == "none" else { throw ShellProbeError.fixture }
        case .encryptedEd:
            guard fixture == .keyonly, key == "edencrypted" else { throw ShellProbeError.fixture }
        case .rsa:
            guard fixture == .keyonly, ["rsaplain", "rsaencrypted"].contains(key) else { throw ShellProbeError.fixture }
        }
    }
    /// Exactly one deliberate in-memory mutation, only after the fixed disposable material gate.
    /// No fabricated probe credential, repeated attempt or writeback of the mutated value.
    public static func wrongPrimary(_ password: Data) throws -> Data {
        guard !password.isEmpty, password.count <= 65536 else { throw ShellProbeError.fixture }
        var changed = password
        changed[changed.startIndex] ^= 1
        return changed
    }
}

/// Public native facts, used to reject false-green negative results. No raw challenges or secrets.
public struct ShellProbeAttemptFacts: Encodable, Sendable {
    public let primaryStarted: Int
    public let primaryResults: Int
    public let primaryCode: Int32?
    public let primaryAuthenticated: Bool?
    public let keyboardStarted: Int
    public let keyboardResults: Int
    public let keyboardCode: Int32?
    public let authenticatedEvents: Int
    public let shellReadyEvents: Int
    private let order: [String]
    public init(stages: [NativeShellAuthenticationStage]) throws {
        var starts = 0, results = 0, ks = 0, kr = 0, auth = 0, shell = 0, methods = 0
        var pc: Int32?, pa: Bool?, kc: Int32?, order: [String] = []
        for stage in stages {
            switch stage {
            case .advertised: methods += 1; order.append("methods")
            case .primaryStarted(let method):
                guard method == .password else { throw ShellProbeError.missingEvidence }
                starts += 1; order.append("primary-start")
            case .primaryResult(let method, let code, let authenticated):
                guard method == .password else { throw ShellProbeError.missingEvidence }
                results += 1; pc = code; pa = authenticated; order.append("primary-result")
            case .keyboardStarted: ks += 1; order.append("keyboard-start")
            case .keyboardResult(let code, let authenticated):
                guard !authenticated else { throw ShellProbeError.missingEvidence }
                kr += 1; kc = code; order.append("keyboard-result")
            case .authenticated: auth += 1; order.append("authenticated")
            case .shellReady: shell += 1; order.append("shell-ready")
            }
        }
        guard methods <= 1, starts <= 1, results <= 1, ks <= 1, kr <= 1, auth <= 1, shell <= 1 else {
            throw ShellProbeError.missingEvidence
        }
        primaryStarted = starts; primaryResults = results; primaryCode = pc; primaryAuthenticated = pa
        keyboardStarted = ks; keyboardResults = kr; keyboardCode = kc
        authenticatedEvents = auth; shellReadyEvents = shell; self.order = order
    }
    public func requireExpected(_ testCase: ShellProbeCase, nativeKind: NativeShellError.Kind?, nativeCode: Int32?,
                                cancelled: Bool, changedKeyRejected: Bool, firstChallengeValidated: Bool,
                                callbackCount: Int, replies: Int, managementReads: Int,
                                inputCalls: Int, closeCompleted: Bool, timedOut: Bool, stopped: Bool) throws {
        guard !timedOut, !stopped, closeCompleted, inputCalls == 0, managementReads == 0, replies == 0 else {
            throw ShellProbeError.missingEvidence
        }
        switch testCase {
        case .wrongPrimary:
            guard nativeKind == .authentication, nativeCode == -18, !cancelled,
                  order == ["methods", "primary-start", "primary-result"], primaryCode == -18,
                  primaryAuthenticated == false, callbackCount == 0 else { throw ShellProbeError.missingEvidence }
        case .hostkeyMismatch:
            guard nativeKind == .untrusted, order.isEmpty, changedKeyRejected,
                  !cancelled, callbackCount == 0 else { throw ShellProbeError.missingEvidence }
        case .cancelKI:
            guard nativeKind == .cancelled, cancelled, firstChallengeValidated, callbackCount == 1,
                  order == ["methods", "primary-start", "primary-result", "keyboard-start", "keyboard-result"],
                  primaryCode == -18, primaryAuthenticated == false, keyboardCode == -10001 else {
                throw ShellProbeError.missingEvidence
            }
        case .cancelAfterReady:
            guard nativeKind == nil, cancelled, callbackCount == 0,
                  order == ["methods", "primary-start", "primary-result", "authenticated", "shell-ready"],
                  primaryCode == 0, primaryAuthenticated == true else { throw ShellProbeError.missingEvidence }
        default: throw ShellProbeError.fixture
        }
    }
}
