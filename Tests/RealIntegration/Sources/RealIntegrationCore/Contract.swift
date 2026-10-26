import Foundation

public enum SmokeError: String, Error, Sendable {
    case invalidArguments, authorizationRequired, unsafePath, unsafeMaterial, invalidContract
    case invalidFixture, fingerprintMismatch, provenanceMismatch, unknownPrompt, extraAnswer
    case timeout, cancelled, unexpectedConnection, connectionFailed, negativeUnclassified
    case cleanupIncomplete, integrity, signedAppRequired, toolFailed
}

public enum Action: Sendable { case help, validate, live }
public struct Options: Sendable {
    public let action: Action
    public let contractPath: String?
    // Parsing has no filesystem, AppKit, signature, Keychain or network access.
    public static func parse(_ arguments: [String]) throws -> Self {
        if arguments.isEmpty || arguments == ["--help"] { return Self(action: .help, contractPath: nil) }
        guard let first = arguments.first, ["validate", "--live"].contains(first) else { throw SmokeError.invalidArguments }
        var path: String?, authorized = false, ready = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--contract":
                guard path == nil, index + 1 < arguments.count else { throw SmokeError.invalidArguments }
                index += 1; path = arguments[index]; try PrivateInput.validateSyntax(path!)
                guard path!.hasSuffix("/real-integration.json") else { throw SmokeError.invalidArguments }
            case "--authorized-local-fixture":
                guard !authorized else { throw SmokeError.invalidArguments }; authorized = true
            case "--engine-ready":
                guard !ready else { throw SmokeError.invalidArguments }; ready = true
            default: throw SmokeError.invalidArguments
            }
            index += 1
        }
        guard let path else { throw SmokeError.invalidArguments }
        if first == "--live" {
            guard authorized && ready else { throw SmokeError.authorizationRequired }
            return Self(action: .live, contractPath: path)
        }
        guard !authorized && !ready else { throw SmokeError.invalidArguments }
        return Self(action: .validate, contractPath: path)
    }
    public static let help = """
    OpenLXSSH test-only host15 consumer; NOT the macOS26 product/stability driver.
    Default/--help: no I/O. validate --contract /exact/generation/real-integration.json:
    syntax only; does NOT open the contract or credentials, build, sign or connect.
    Future only, after primary Engine-ready AND authorization:
      --live --authorized-local-fixture --engine-ready --contract /exact/generation/real-integration.json
    Only fixture@127.0.0.1:22221 keyonly or :22222 passwordonly. No MFA,
    arbitrary hosts, CLI credential overrides, retries or terminal recording.
    Flags acknowledge prerequisites; they do not provide human authorization.
    """
}

public enum SmokeMode: String, Codable, Sendable { case ssh, sftp }
public enum SmokeCase: String, Codable, Sendable { case positive, badPassword = "bad-password", unregisteredKey = "unregistered-key" }
public enum FixtureService: String, Codable, Sendable {
    case keyonly, passwordonly
    public var port: UInt16 { self == .keyonly ? 22221 : 22222 }
}
public struct ResponsePlan: Codable, Sendable {
    public enum Kind: String, Codable, Sendable { case none, singleManualPassword = "single-manual-password" }
    public let kind: Kind
    // Non-secret hash of the exact prompt independently reviewed by the manual
    // test coordinator. Never infer an answer from prompt wording/substrings.
    public let expectedPromptSHA256: String?
}
public struct Contract: Codable, Sendable {
    public let schema: Int
    public let fixtureLabel: String
    public let mode: SmokeMode
    public let testCase: SmokeCase
    public let service: FixtureService
    public let host: String
    public let port: UInt16
    public let user: String
    public let credentialDirectory: String
    public let expectedFingerprint: String
    public let expectedBaseImage: String
    public let expectedBuiltImageID: String
    public let responsePlan: ResponsePlan
    // Test-only relay allowance for a bounded 3s Docker metadata check plus
    // exec/forwarding overhead; not shipping defaults or product PERF budgets.
    public static let hostKeyScanSeconds = 15
    public static let connectionSeconds = 20
    // The Files backend also applies this per-operation limit to handshake,
    // trust, authentication and SFTP init after the local TCP connect returns.
    public static let operationSeconds = 20.0
    public static let caseSeconds = 30.0
    public static let drainSeconds = 12.0

    public func validate(contractPath: String, fixtureRoot: String) throws {
        guard schema == 1, fixtureLabel == "env-fixture-a", host == "127.0.0.1", user == "fixture",
              port == service.port else { throw SmokeError.invalidContract }
        try PrivateInput.validateSyntax(credentialDirectory)
        let prefix = fixtureRoot + "/.runtime/" + service.rawValue + "/credentials-"
        guard credentialDirectory.hasPrefix(prefix), Self.hex(String(credentialDirectory.dropFirst(prefix.count)), count: 12),
              contractPath == credentialDirectory + "/real-integration.json" else { throw SmokeError.invalidContract }
        guard expectedFingerprint.hasPrefix("SHA256:"),
              let fingerprint = Data(base64Encoded: String(expectedFingerprint.dropFirst(7)) + "="), fingerprint.count == 32,
              fingerprint.base64EncodedString().dropLast() == expectedFingerprint.dropFirst(7),
              Self.digest(expectedBaseImage, prefix: "docker.io/library/ubuntu:24.04@sha256:"),
              Self.digest(expectedBuiltImageID, prefix: "sha256:") else { throw SmokeError.invalidContract }
        guard testCase != .badPassword || service == .passwordonly,
              testCase != .unregisteredKey || service == .keyonly else { throw SmokeError.invalidContract }
        if mode == .ssh && service == .passwordonly {
            guard responsePlan.kind == .singleManualPassword,
                  let digest = responsePlan.expectedPromptSHA256, Self.hex(digest, count: 64) else { throw SmokeError.invalidContract }
        } else {
            guard responsePlan.kind == .none, responsePlan.expectedPromptSHA256 == nil else { throw SmokeError.invalidContract }
        }
    }
    public static func hex(_ value: String, count: Int) -> Bool {
        value.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    public static func digest(_ value: String, prefix: String) -> Bool {
        value.hasPrefix(prefix) && hex(String(value.dropFirst(prefix.count)), count: 64)
    }
}
