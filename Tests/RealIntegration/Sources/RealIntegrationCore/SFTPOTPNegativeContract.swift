import Foundation

public enum SFTPOTPNegativeCase: String, Codable, Sendable { case badOTP = "bad-otp", expiredOTP = "expired-otp" }
public enum SFTPOTPNegativeError: String, Error, Codable, Sendable {
    case invalidContract, unknownChallenge, extraCallback, staleReply, invalidResponse, earlyExpiry
    case cancelled, timeout, managementFailed, unexpectedConnection, unclassifiedFailure, cleanupIncomplete, unknownTrust
}

public struct SFTPOTPNegativeOptions: Sendable {
    public let action: Action
    public let contractPath: String?
    public static func parse(_ args: [String]) throws -> Self {
        if args.isEmpty || args == ["--help"] { return Self(action: .help, contractPath: nil) }
        guard let first = args.first, ["validate", "--live"].contains(first) else { throw SmokeError.invalidArguments }
        var path: String?, authorized = false, ready = false, index = 1
        while index < args.count {
            switch args[index] {
            case "--contract":
                guard path == nil, index + 1 < args.count else { throw SmokeError.invalidArguments }
                index += 1; path = args[index]; try PrivateInput.validateSyntax(path!)
                guard path!.hasSuffix("/sftp-otp-negative.json") else { throw SmokeError.invalidArguments }
            case "--authorized-local-fixture": guard !authorized else { throw SmokeError.invalidArguments }; authorized = true
            case "--engine-ready": guard !ready else { throw SmokeError.invalidArguments }; ready = true
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
    --sftp-otp-negative: test-only bad-otp / expired-otp; fixed key-kbd Edplain fixture@127.0.0.1:22223.
    --help or validate --contract /exact/sftp-otp-negative-case-12hex/sftp-otp-negative.json: syntax-only/no I/O.
    Future explicit release only: --live --authorized-local-fixture --engine-ready --contract <exactPath>
    C read exactly once BEFORE real TTL expiry; mutate one digit or hold in memory until real expiry.
    Only typed authentication +3 secret replies +injection/expiry proof passes; no SFTP/file operations.
    """
}

public struct SFTPOTPNegativeContract: Codable, Sendable {
    public let schema: Int
    public let taskID: String
    public let testCase: SFTPOTPNegativeCase
    public let service: String
    public let host: String
    public let port: Int
    public let user: String
    public let key: String
    public let credentialDirectory: String
    public let expectedFingerprint: String
    public let baseImage: String
    public let imageID: String
    public let containerID: String
    public let project: String
    public let networkID: String
    public let context: String
    public let endpoint: String
    public static let connectionSeconds = 20.0
    public static let operationSeconds = 85.0
    public static let activeSeconds = 100.0
    public static let fullSeconds = 140.0
    public static let drainSeconds = 12.0
    public static func checkPath(_ path: String, buildRoot: String) throws {
        try PrivateInput.validateSyntax(path)
        let prefix = buildRoot + "/sftp-otp-negative-case-", suffix = "/sftp-otp-negative.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix), Contract.hex(String(path.dropFirst(prefix.count).dropLast(suffix.count)), count: 12) else { throw SFTPOTPNegativeError.invalidContract }
    }
    public func positiveIdentity() -> SFTPAuthContract {
        SFTPAuthContract(schema: 1, taskID: "REAL-SFTP-COMBINED-AUTH-A", service: .keyKbd, host: host, port: port, user: user, key: .edplain,
            credentialDirectory: credentialDirectory, expectedFingerprint: expectedFingerprint, baseImage: baseImage, imageID: imageID,
            containerID: containerID, project: project, networkID: networkID, context: context, endpoint: endpoint)
    }
    public func validate(path: String, buildRoot: String, fixtureRoot: String, home: String) throws {
        try Self.checkPath(path, buildRoot: buildRoot)
        guard schema == 1, taskID == "SFTP-OTP-NEGATIVE-A", service == "key-kbd", key == "edplain", host == "127.0.0.1", port == 22223, user == "fixture" else { throw SFTPOTPNegativeError.invalidContract }
        // Reuse only fixed endpoint/provenance validation with an inert syntax path.
        try positiveIdentity().validate(path: buildRoot + "/sftp-auth-case-000000000000/sftp-auth.json", buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: home)
    }
    public static func load(path: String, buildRoot: String, fixtureRoot: String, home: String) throws -> Self {
        try checkPath(path, buildRoot: buildRoot)
        let data = try PrivateInput.read(path, limit: 8192)
        _ = try MinaJSON.object(data, keys: ["schema", "taskID", "testCase", "service", "host", "port", "user", "key", "credentialDirectory", "expectedFingerprint", "baseImage", "imageID", "containerID", "project", "networkID", "context", "endpoint"])
        let value = try JSONDecoder().decode(Self.self, from: data)
        try value.validate(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: home)
        return value
    }
}

public struct SFTPOTPNegativeInput: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "<redacted OTP negative input>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
    public let contract: SFTPOTPNegativeContract
    public let hostKeyLine: String
    public let publicKey: Data
    public let privateKey: Data
    public static func load(path: String, buildRoot: String, fixtureRoot: String, home: String) throws -> Self {
        let contract = try SFTPOTPNegativeContract.load(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: home)
        let identity = contract.positiveIdentity()
        for folder in [fixtureRoot + "/.runtime", fixtureRoot + "/.runtime/key-kbd", identity.credentialDirectory] { try PrivateInput.checkDirectory(folder) }
        let state = try MinaJSON.object(PrivateInput.read(fixtureRoot + "/.runtime/state.json", limit: 4096), keys: ["version", "project", "image"])
        guard state["version"] as? Int == 1, state["project"] as? String == identity.project, state["image"] as? String == identity.baseImage else { throw SFTPOTPNegativeError.invalidContract }
        let provenance = try MinaJSON.object(PrivateInput.read(identity.credentialDirectory + "/provenance.json", limit: 4096), keys: ["base_image", "built_image_id", "service", "collected_at"])
        guard provenance["base_image"] as? String == identity.baseImage, provenance["built_image_id"] as? String == identity.imageID,
              provenance["service"] as? String == "key-kbd", let collected = provenance["collected_at"] as? Double, collected.isFinite, collected > 0 else { throw SFTPOTPNegativeError.invalidContract }
        let known = try PrivateInput.text(PrivateInput.read(identity.credentialDirectory + "/known_hosts", limit: 4096))
        let fields = known.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard known.hasSuffix("\n"), !known.dropLast().contains("\n"), fields.count == 3, fields[0] == "[127.0.0.1]:22223", fields[1] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51, blob.base64EncodedString() == fields[2] else { throw SFTPOTPNegativeError.invalidContract }
        // Mature public key parsing/fingerprint validation is still performed by the consumer.
        let exported = try PrivateInput.text(PrivateInput.read(identity.credentialDirectory + "/fingerprint.txt", limit: 1024)).split(whereSeparator: { $0.isWhitespace })
        guard exported.count >= 2, exported[1] == Substring(identity.expectedFingerprint) else { throw SFTPOTPNegativeError.invalidContract }
        let privateKey = try PrivateInput.read(identity.credentialDirectory + "/id_ed25519", limit: 32768)
        let publicKey = try PrivateInput.read(identity.credentialDirectory + "/id_ed25519.pub", limit: 4096)
        guard !privateKey.isEmpty, !publicKey.isEmpty else { throw SFTPOTPNegativeError.invalidContract }
        return Self(contract: contract, hostKeyLine: "ssh-ed25519 " + fields[2], publicKey: publicKey, privateKey: privateKey)
    }
}
