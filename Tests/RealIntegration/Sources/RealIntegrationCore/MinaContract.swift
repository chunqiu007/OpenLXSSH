import CryptoKit
import Foundation

public enum MinaError: String, Error, Codable, Sendable {
    case invalidContract, unsafeMaterial, provenanceMismatch, fingerprintMismatch
    case unknownChallenge, extraCallback, lateReply, invalidResponses, expiredResponses
    case managementFailed, managementTimeout, managementCancelled, unknownTrust
    case backendMismatch, statusMismatch, cancelled, timeout, cleanupIncomplete
}

public enum MinaCase: String, Codable, Sendable {
    case twoCorrect = "two-correct", zeroAccept = "zero-accept", zeroReject = "zero-reject"
    case approval, reject, cancelWait = "cancel-wait"
    public var scenario: String {
        switch self { case .twoCorrect: return "two"; case .cancelWait: return "cancel"; default: return rawValue }
    }
    public var promptCount: Int { self == .twoCorrect ? 2 : 0 }
    public var isAsync: Bool { [.approval, .reject, .cancelWait].contains(self) }
    public var expectedOutcome: String {
        switch self {
        case .approval: return "approved"
        case .reject, .zeroReject: return "rejected"
        case .cancelWait: return "session-closed"
        default: return "accepted"
        }
    }
}

// Separate syntax and schema: the existing SSH/SFTP Options/Contract stay strict.
public struct MinaOptions: Sendable {
    public let action: Action
    public let contractPath: String?
    public static func parse(_ arguments: [String]) throws -> Self {
        if arguments.isEmpty || arguments == ["--help"] { return Self(action: .help, contractPath: nil) }
        guard let first = arguments.first, ["validate", "--live"].contains(first) else { throw SmokeError.invalidArguments }
        var path: String?, authorized = false, ready = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--contract":
                guard path == nil, index + 1 < arguments.count else { throw SmokeError.invalidArguments }
                index += 1; path = arguments[index]; try PrivateInput.validateSyntax(path!)
                guard path!.hasSuffix("/auth-only.json") else { throw SmokeError.invalidArguments }
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
    OpenLXSSH test-only MINA AUTH-ONLY consumer, NOT SFTP/FILE or product acceptance.
    --auth-only [--help | validate --contract /exact/mina-case-12hex/auth-only.json]
    Syntax only; no files, signature, Docker, AppKit, Keychain or connections.
    After separate primary release only:
      --auth-only --live --authorized-local-fixture --engine-ready --contract /exact/mina-case-12hex/auth-only.json
    Fixed fixture@127.0.0.1:22225; two-correct / zero-accept / zero-reject /
    approval / reject / cancel-wait only; async policy delay is fixed to 8s.
    No scenario changes, service lifecycle, retries, password guessing or transcripts.
    """
}

public struct MinaContract: Codable, Sendable {
    public let schema: Int
    public let taskID: String
    public let testCase: MinaCase
    public let service: String
    public let fixtureLabel: String
    public let host: String
    public let port: Int
    public let user: String
    public let context: String
    public let endpoint: String
    public let containerID: String
    public let imageID: String
    public let project: String
    public let networkID: String
    public let sourceSHA256: String
    public let baseImage: String
    public let trustDirectory: String
    public let expectedFingerprint: String
    public static let connectionSeconds = 20.0
    public static let operationSeconds = 20.0
    public static let caseSeconds = 30.0
    public static let managementSeconds = 10.0
    public static let drainSeconds = 12.0
    public static let providerDelaySeconds = 8.0
    public static let cancelAfterReplySeconds = 1.0
    public static let base = "docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d"

    public static func validatePath(_ path: String, buildRoot: String) throws {
        try PrivateInput.validateSyntax(path)
        let prefix = buildRoot + "/mina-case-", suffix = "/auth-only.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix),
              Contract.hex(String(path.dropFirst(prefix.count).dropLast(suffix.count)), count: 12) else { throw MinaError.invalidContract }
    }
    public func validate(path: String, buildRoot: String, fixtureRoot: String, home: String) throws {
        try Self.validatePath(path, buildRoot: buildRoot)
        guard schema == 1, taskID == "AUTH-MINA-PRODUCTION-KBI-A", service == "multiprompt",
              fixtureLabel == "auth-mina-fixture-a", host == "127.0.0.1", port == 22225, user == "fixture",
              ["default", "desktop-linux"].contains(context),
              ["unix:///var/run/docker.sock", "unix://" + home + "/.docker/run/docker.sock"].contains(endpoint),
              Contract.hex(containerID, count: 64), Contract.digest(imageID, prefix: "sha256:"),
              project.hasPrefix("openlxssh-mina-"), Contract.hex(String(project.dropFirst("openlxssh-mina-".count)), count: 12),
              Contract.hex(networkID, count: 64), Contract.hex(sourceSHA256, count: 64), baseImage == Self.base else { throw MinaError.invalidContract }
        let prefix = fixtureRoot + "/.runtime/trust-"
        guard trustDirectory.hasPrefix(prefix), Contract.hex(String(trustDirectory.dropFirst(prefix.count)), count: 12),
              expectedFingerprint.hasPrefix("SHA256:"),
              let fingerprint = Data(base64Encoded: String(expectedFingerprint.dropFirst(7)) + "="), fingerprint.count == 32,
              fingerprint.base64EncodedString().dropLast() == expectedFingerprint.dropFirst(7) else { throw MinaError.invalidContract }
    }
}

public enum MinaJSON {
    public static func object(_ data: Data, keys: Set<String>) throws -> [String: Any] {
        guard data.count <= 131072, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == keys else { throw MinaError.invalidContract }
        return object
    }
}

public struct MinaInput: Sendable {
    public let contract: MinaContract
    public let hostKeyLine: String
    public static func load(path: String, buildRoot: String, fixtureRoot: String, home: String) throws -> Self {
        try MinaContract.validatePath(path, buildRoot: buildRoot) // Before opening any file.
        let data = try PrivateInput.read(path, limit: 8192)
        _ = try MinaJSON.object(data, keys: ["schema", "taskID", "testCase", "service", "fixtureLabel", "host", "port", "user", "context", "endpoint", "containerID", "imageID", "project", "networkID", "sourceSHA256", "baseImage", "trustDirectory", "expectedFingerprint"])
        let contract = try JSONDecoder().decode(MinaContract.self, from: data)
        try contract.validate(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: home)
        try PrivateInput.checkDirectory(fixtureRoot + "/.runtime")
        try PrivateInput.checkDirectory(contract.trustDirectory)
        let state = try MinaJSON.object(PrivateInput.read(fixtureRoot + "/.runtime/state.json", limit: 4096),
            keys: ["version", "project", "label", "image", "base", "context", "endpoint", "source"])
        let build = try MinaJSON.object(PrivateInput.read(fixtureRoot + "/.runtime/build.json", limit: 4096),
            keys: ["version", "project", "image_id", "source"])
        guard state["version"] as? Int == 1, state["project"] as? String == contract.project,
              state["label"] as? String == contract.fixtureLabel, state["image"] as? String == "openlxssh-auth-mina-fixture:2.20.0-arm64",
              state["base"] as? String == contract.baseImage, state["context"] as? String == contract.context,
              state["endpoint"] as? String == contract.endpoint, state["source"] as? String == contract.sourceSHA256,
              build["version"] as? Int == 1, build["project"] as? String == contract.project,
              build["image_id"] as? String == contract.imageID, build["source"] as? String == contract.sourceSHA256 else { throw MinaError.provenanceMismatch }
        let known = try PrivateInput.text(PrivateInput.read(contract.trustDirectory + "/known_hosts", limit: 4096))
        let fields = known.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard known.hasSuffix("\n"), !known.dropLast().contains("\n"), fields.count == 3,
              fields[0] == "[127.0.0.1]:22225", fields[1] == "ssh-rsa",
              let blob = Data(base64Encoded: String(fields[2])), blob.base64EncodedString() == fields[2] else { throw MinaError.invalidContract }
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast()
        let exported = try PrivateInput.text(PrivateInput.read(contract.trustDirectory + "/fingerprint.txt", limit: 256))
        guard exported == contract.expectedFingerprint + "\n", fingerprint == contract.expectedFingerprint else { throw MinaError.fingerprintMismatch }
        return Self(contract: contract, hostKeyLine: "ssh-rsa " + fields[2])
    }
}
