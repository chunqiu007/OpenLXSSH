import CryptoKit
import Foundation

public enum OpenSSHError: String, Error, Codable, Sendable {
    case invalidContract, provenanceMismatch, unsafeMaterial, fingerprintMismatch
    case unknownRequest, extraRequest, staleRequest, wrongRound, expiredResponse
    case managementFailed, managementTimeout, cancelled, timeout, connectionFailed, cleanupIncomplete
}
public enum OpenSSHService: String, Codable, Sendable {
    case keyonly, passwordonly, keyKbd = "key-kbd", passwordKbd = "password-kbd"
    public var port: Int { switch self { case .keyonly: return 22221; case .passwordonly: return 22222; case .keyKbd: return 22223; case .passwordKbd: return 22224 } }
    public var usesKey: Bool { self == .keyonly || self == .keyKbd }
    public var mfa: Bool { self == .keyKbd || self == .passwordKbd }
}
public enum OpenSSHKey: String, Codable, Sendable {
    case none, edplain, edencrypted, rsaplain, rsaencrypted
    public var file: String? {
        switch self { case .none: return nil; case .edplain: return "id_ed25519"; case .edencrypted: return "id_ed25519_encrypted"; case .rsaplain: return "id_rsa"; case .rsaencrypted: return "id_rsa_encrypted" }
    }
    public var encrypted: Bool { self == .edencrypted || self == .rsaencrypted }
}
public enum OpenSSHCase: String, Codable, Sendable { case positive, observeChallenge = "observe-challenge" }
public enum OpenSSHPrimary: String, Codable, Sendable { case none, password, keyPassphrase = "key-passphrase" }

public struct OpenSSHOptions: Sendable {
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
                guard path!.hasSuffix("/openssh-auth.json") else { throw SmokeError.invalidArguments }
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
    --openssh-auth: test-only production DirectSSHSession; NOT GUI/product acceptance.
    --help or validate --contract /exact/openssh-case-12hex/openssh-auth.json: syntax only, no I/O.
    Future primary release only: --live --authorized-local-fixture --engine-ready --contract <exactPath>
    Fixed fixture@127.0.0.1 ports22221..22224, four declared services; no retries or saved-secret API.
    positive or observe-challenge (one request metadata then cancel, NO answers/NO auth-pass claim).
    """
}

public struct OpenSSHContract: Codable, Sendable {
    public let schema: Int
    public let taskID: String
    public let testCase: OpenSSHCase
    public let service: OpenSSHService
    public let host: String
    public let port: Int
    public let user: String
    public let key: OpenSSHKey
    public let primary: OpenSSHPrimary
    public let primaryPromptSHA256: String?
    public let credentialDirectory: String
    public let expectedFingerprint: String
    public let baseImage: String
    public let imageID: String
    public let containerID: String
    public let project: String
    public let networkID: String
    public let context: String
    public let endpoint: String
    public static let activeSeconds = 60.0
    public static let drainSeconds = 12.0
    public static let managementSeconds = 10.0
    public static let scanSeconds = 15
    public static let connectionSeconds = 20
    public static func checkPath(_ path: String, buildRoot: String) throws {
        try PrivateInput.validateSyntax(path)
        let prefix = buildRoot + "/openssh-case-", suffix = "/openssh-auth.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix), Contract.hex(String(path.dropFirst(prefix.count).dropLast(suffix.count)), count: 12) else { throw OpenSSHError.invalidContract }
    }
    public func validate(path: String, buildRoot: String, fixtureRoot: String, home: String) throws {
        try Self.checkPath(path, buildRoot: buildRoot)
        guard schema == 1, taskID == "OPENSSH-FOUR-AUTH-A", host == "127.0.0.1", user == "fixture", port == service.port,
              service.usesKey == (key != .none), primary == (service.usesKey ? (key.encrypted ? .keyPassphrase : .none) : .password),
              baseImage == MinaContract.base, Contract.digest(imageID, prefix: "sha256:"), Contract.hex(containerID, count: 64), Contract.hex(networkID, count: 64),
              project.hasPrefix("openlxssh-fixture-"), Contract.hex(String(project.dropFirst("openlxssh-fixture-".count)), count: 12),
              ["default", "desktop-linux"].contains(context),
              ["unix:///var/run/docker.sock", "unix://" + home + "/.docker/run/docker.sock"].contains(endpoint) else { throw OpenSSHError.invalidContract }
        let prefix = fixtureRoot + "/.runtime/" + service.rawValue + "/credentials-"
        guard credentialDirectory.hasPrefix(prefix), Contract.hex(String(credentialDirectory.dropFirst(prefix.count)), count: 12),
              expectedFingerprint.hasPrefix("SHA256:"), let digest = Data(base64Encoded: String(expectedFingerprint.dropFirst(7)) + "="),
              digest.count == 32, digest.base64EncodedString().dropLast() == expectedFingerprint.dropFirst(7) else { throw OpenSSHError.invalidContract }
        if primary == .none { guard primaryPromptSHA256 == nil else { throw OpenSSHError.invalidContract } }
        else if testCase == .positive { guard let primaryPromptSHA256, Contract.hex(primaryPromptSHA256, count: 64) else { throw OpenSSHError.invalidContract } }
        else if let primaryPromptSHA256 { guard Contract.hex(primaryPromptSHA256, count: 64) else { throw OpenSSHError.invalidContract } }
    }
}

public struct OpenSSHInput: Sendable {
    public let contract: OpenSSHContract
    public let hostKeyLine: String
    public var keyPath: String? { contract.key.file.map { contract.credentialDirectory + "/" + $0 } }
    public static func load(path: String, buildRoot: String, fixtureRoot: String, home: String) throws -> Self {
        try OpenSSHContract.checkPath(path, buildRoot: buildRoot)
        let data = try PrivateInput.read(path, limit: 8192)
        _ = try MinaJSON.object(data, keys: ["schema", "taskID", "testCase", "service", "host", "port", "user", "key", "primary", "primaryPromptSHA256", "credentialDirectory", "expectedFingerprint", "baseImage", "imageID", "containerID", "project", "networkID", "context", "endpoint"])
        let value = try JSONDecoder().decode(OpenSSHContract.self, from: data)
        try value.validate(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: home)
        for folder in [fixtureRoot + "/.runtime", fixtureRoot + "/.runtime/" + value.service.rawValue, value.credentialDirectory] { try PrivateInput.checkDirectory(folder) }
        let state = try MinaJSON.object(PrivateInput.read(fixtureRoot + "/.runtime/state.json", limit: 4096), keys: ["version", "project", "image"])
        guard state["version"] as? Int == 1, state["project"] as? String == value.project, state["image"] as? String == value.baseImage else { throw OpenSSHError.provenanceMismatch }
        let provenance = try MinaJSON.object(PrivateInput.read(value.credentialDirectory + "/provenance.json", limit: 4096), keys: ["base_image", "built_image_id", "service", "collected_at"])
        guard provenance["base_image"] as? String == value.baseImage, provenance["built_image_id"] as? String == value.imageID,
              provenance["service"] as? String == value.service.rawValue, let time = provenance["collected_at"] as? Double, time.isFinite, time > 0 else { throw OpenSSHError.provenanceMismatch }
        let known = try PrivateInput.text(PrivateInput.read(value.credentialDirectory + "/known_hosts", limit: 4096))
        let fields = known.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard known.hasSuffix("\n"), !known.dropLast().contains("\n"), fields.count == 3, fields[0] == "[127.0.0.1]:\(value.port)",
              fields[1] == "ssh-ed25519", let blob = Data(base64Encoded: String(fields[2])), blob.count == 51,
              blob.base64EncodedString() == fields[2] else { throw OpenSSHError.invalidContract }
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast()
        let exported = try PrivateInput.text(PrivateInput.read(value.credentialDirectory + "/fingerprint.txt", limit: 1024)).split(whereSeparator: { $0.isWhitespace })
        guard fingerprint == value.expectedFingerprint, exported.count >= 2, exported[1] == Substring(fingerprint) else { throw OpenSSHError.fingerprintMismatch }
        if let name = value.key.file {
            // Read only this selected generation. System ssh subsequently opens this
            // exact stable path, making an observed passphrase-prompt hash reusable.
            // There is still a documented same-UID pathname race, as in production.
            guard !(try PrivateInput.read(value.credentialDirectory + "/" + name, limit: 32768)).isEmpty else { throw OpenSSHError.unsafeMaterial }
            _ = try PrivateInput.read(value.credentialDirectory + "/" + name + ".pub", limit: 4096)
        }
        return Self(contract: value, hostKeyLine: "ssh-ed25519 " + fields[2])
    }
    public func primarySecret() throws -> Data {
        guard contract.testCase == .positive, contract.primary != .none else { throw OpenSSHError.unknownRequest }
        let name = contract.primary == .password ? "password.txt" : "key-passphrase.txt"
        return try PrivateInput.secretLine(PrivateInput.read(contract.credentialDirectory + "/" + name, limit: 1024))
    }
}
