import Foundation

public enum StabilityError: String, Error, Sendable {
    case invalidArguments, authorizationRequired, unsafeEndpoint, unsafePath, unsafePermissions
    case invalidFixture, fingerprintMismatch, signedAppRequired, unsupportedAuthentication
    case timerDiscontinuity, connectionLost, incompleteDuration, cleanupIncomplete, resourceUnavailable
    case evidenceLimit, cancelled, timeout, invalidLifecycle
}

public enum RunMode: String, Codable, Sendable { case cycles, soak }
public enum Action: String, Sendable { case help, validate, run }

public struct Options: Sendable {
    public var action: Action = .help
    public var mode: RunMode = .cycles
    public var host = "127.0.0.1"
    public var port = 22221
    public var cycles = 200
    public var sessions = 5
    public var durationSeconds = 86_400
    public var sampleSeconds = 30
    public var cancelEvery = 10
    public var authorized = false
    public var credentials: String?
    public var verifiedFingerprint: String?
    public var outputParent: String?

    public static let help = """
    OpenLXSSH stability acceptance preparation — no network by default.
      stability-preflight [help]
      stability-preflight validate [options]   # read-only, never connects/writes
      Signed .app executable run [options] --authorized-isolated-run
    Options (no passwords/passphrases, environment credentials, or remote commands):
      --mode cycles|soak                  200 authenticated cycles OR 5 sessions >=24h
      --host 127.0.0.1 --port 22221       exact official keyonly fixture only
      --cycles 200 --sessions 5 --duration-seconds 86400..604800
      --sample-seconds 5..60 --cancel-every 0..200
      --credentials /absolute/.../Tests/IntegrationEnvironment/.runtime/keyonly/credentials-<12hex>
      --verified-host-fingerprint SHA256:<out-of-band verified fingerprint>
      --output-parent /absolute/private-0700-directory   # run only; UUID child created
    The flag is an accident guard, NOT user authorization. Runtime/fixture approval
    and a reviewed signed macOS 26 .app are still required. No scheduling or resume.
    Encrypted private keys, passwords and MFA are manual/unsupported in this driver.
    """

    public static func parse(_ arguments: [String]) throws -> Options {
        var result = Options()
        guard let first = arguments.first else { return result }
        if first == "--help" || first == "-h" { return result }
        guard let action = Action(rawValue: first) else { throw StabilityError.invalidArguments }
        result.action = action
        if action == .help {
            guard arguments.count == 1 else { throw StabilityError.invalidArguments }
            return result
        }
        var index = 1, seen = Set<String>()
        while index < arguments.count {
            let name = arguments[index]
            guard seen.insert(name).inserted else { throw StabilityError.invalidArguments }
            if name == "--authorized-isolated-run" { result.authorized = true; index += 1; continue }
            guard index + 1 < arguments.count else { throw StabilityError.invalidArguments }
            let value = arguments[index + 1]
            switch name {
            case "--mode": guard let mode = RunMode(rawValue: value) else { throw StabilityError.invalidArguments }; result.mode = mode
            case "--host": result.host = value
            case "--port": result.port = try integer(value)
            case "--cycles": result.cycles = try integer(value)
            case "--sessions": result.sessions = try integer(value)
            case "--duration-seconds": result.durationSeconds = try integer(value)
            case "--sample-seconds": result.sampleSeconds = try integer(value)
            case "--cancel-every": result.cancelEvery = try integer(value)
            case "--credentials": result.credentials = value
            case "--verified-host-fingerprint": result.verifiedFingerprint = value
            case "--output-parent": result.outputParent = value
            default: throw StabilityError.invalidArguments
            }
            index += 2
        }
        // Before opening ANY file, checking material metadata, AppKit, or creating output.
        if action == .run && !result.authorized { throw StabilityError.authorizationRequired }
        guard result.host == "127.0.0.1", result.port == 22221 else { throw StabilityError.unsafeEndpoint }
        guard result.cycles == 200, result.sessions == 5,
              (86_400...604_800).contains(result.durationSeconds),
              (5...60).contains(result.sampleSeconds), (0...200).contains(result.cancelEvery),
              result.durationSeconds / result.sampleSeconds + 10 < BoundedEvidence.maximumRows else {
            throw StabilityError.invalidArguments
        }
        for path in [result.credentials, result.outputParent].compactMap({ $0 }) { try PrivateMaterial.validateSyntax(path) }
        if let fingerprint = result.verifiedFingerprint {
            guard fingerprint.hasPrefix("SHA256:"), fingerprint.count == 50,
                  fingerprint.dropFirst(7).allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "+" || $0 == "/") }) else {
                throw StabilityError.invalidArguments
            }
        }
        return result
    }

    private static func integer(_ value: String) throws -> Int {
        guard let n = Int(value), String(n) == value else { throw StabilityError.invalidArguments }
        return n
    }
}
