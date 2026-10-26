import CryptoKit
import Foundation

public enum SFTPAuthError: String, Error, Codable, Sendable {
    case invalidContract, unsafeMaterial, provenanceMismatch, fingerprintMismatch, unknownTrust
    case unknownChallenge, extraCallback, staleReply, expiredResponse, cancelled, timeout
    case connectionFailed, integrity, cleanupIncomplete, managementFailed
}

public struct SFTPAuthOptions: Sendable {
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
                guard path!.hasSuffix("/sftp-auth.json") else { throw SmokeError.invalidArguments }
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
    --sftp-auth: test-only public LibSSH2FileService ordered auth +79-byte SFTP roundtrip.
    --help or validate --contract /exact/sftp-auth-case-12hex/sftp-auth.json: syntax only, no I/O.
    Future primary release only: --live --authorized-local-fixture --engine-ready --contract <exactPath>
    Four fixed root fixture services/ports22221..22224 only; explicit key/password then optional KBI.
    No system prompt hashes, retries, Keychain, terminal input or auth-only success shortcut.
    """
}

public struct SFTPAuthContract: Codable, Sendable {
    public let schema: Int
    public let taskID: String
    public let service: OpenSSHService
    public let host: String
    public let port: Int
    public let user: String
    public let key: OpenSSHKey
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
    public static let operationSeconds = 20.0
    public static let activeSeconds = 45.0
    public static let drainSeconds = 12.0
    public static let fullSeconds = 85.0
    public var authenticationOrder: [String] {
        [service.usesKey ? "publickey" : "password"] + (service.mfa ? ["keyboard-interactive"] : [])
    }
    public static func checkPath(_ path: String, buildRoot: String) throws {
        try PrivateInput.validateSyntax(path)
        let prefix = buildRoot + "/sftp-auth-case-", suffix = "/sftp-auth.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix), Contract.hex(String(path.dropFirst(prefix.count).dropLast(suffix.count)), count: 12) else { throw SFTPAuthError.invalidContract }
    }
    public func validate(path: String, buildRoot: String, fixtureRoot: String, home: String) throws {
        try Self.checkPath(path, buildRoot: buildRoot)
        guard schema == 1, taskID == "REAL-SFTP-COMBINED-AUTH-A", host == "127.0.0.1", user == "fixture", port == service.port,
              service.usesKey == (key != .none), baseImage == MinaContract.base,
              Contract.digest(imageID, prefix: "sha256:"), Contract.hex(containerID, count: 64), Contract.hex(networkID, count: 64),
              project.hasPrefix("openlxssh-fixture-"), Contract.hex(String(project.dropFirst("openlxssh-fixture-".count)), count: 12),
              ["default", "desktop-linux"].contains(context), ["unix:///var/run/docker.sock", "unix://" + home + "/.docker/run/docker.sock"].contains(endpoint) else { throw SFTPAuthError.invalidContract }
        let prefix = fixtureRoot + "/.runtime/" + service.rawValue + "/credentials-"
        guard credentialDirectory.hasPrefix(prefix), Contract.hex(String(credentialDirectory.dropFirst(prefix.count)), count: 12),
              expectedFingerprint.hasPrefix("SHA256:"), let digest = Data(base64Encoded: String(expectedFingerprint.dropFirst(7)) + "="),
              digest.count == 32, digest.base64EncodedString().dropLast() == expectedFingerprint.dropFirst(7) else { throw SFTPAuthError.invalidContract }
    }
    /// Reuse ONLY the frozen root management identity/policy reader. This value
    /// is never used for system SSH, prompt matching, secret answers or reports.
    public func rootManagementIdentity() -> OpenSSHContract {
        OpenSSHContract(schema: 1, taskID: "OPENSSH-FOUR-AUTH-A", testCase: .positive, service: service, host: host, port: port,
            user: user, key: key, primary: .none, primaryPromptSHA256: nil, credentialDirectory: credentialDirectory,
            expectedFingerprint: expectedFingerprint, baseImage: baseImage, imageID: imageID, containerID: containerID,
            project: project, networkID: networkID, context: context, endpoint: endpoint)
    }
}

public struct SFTPAuthInput: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "<redacted SFTP auth input>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
    public let contract: SFTPAuthContract
    public let hostKeyLine: String
    public let publicKey: Data?
    public let privateKey: Data?
    public let passphrase: Data?
    public let password: Data?
    public static func load(path: String, buildRoot: String, fixtureRoot: String, home: String) throws -> Self {
        try SFTPAuthContract.checkPath(path, buildRoot: buildRoot)
        let bytes = try PrivateInput.read(path, limit: 8192)
        _ = try MinaJSON.object(bytes, keys: ["schema", "taskID", "service", "host", "port", "user", "key", "credentialDirectory", "expectedFingerprint", "baseImage", "imageID", "containerID", "project", "networkID", "context", "endpoint"])
        let value = try JSONDecoder().decode(SFTPAuthContract.self, from: bytes)
        try value.validate(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: home)
        for folder in [fixtureRoot + "/.runtime", fixtureRoot + "/.runtime/" + value.service.rawValue, value.credentialDirectory] { try PrivateInput.checkDirectory(folder) }
        let state = try MinaJSON.object(PrivateInput.read(fixtureRoot + "/.runtime/state.json", limit: 4096), keys: ["version", "project", "image"])
        guard state["version"] as? Int == 1, state["project"] as? String == value.project, state["image"] as? String == value.baseImage else { throw SFTPAuthError.provenanceMismatch }
        let provenance = try MinaJSON.object(PrivateInput.read(value.credentialDirectory + "/provenance.json", limit: 4096), keys: ["base_image", "built_image_id", "service", "collected_at"])
        guard provenance["base_image"] as? String == value.baseImage, provenance["built_image_id"] as? String == value.imageID,
              provenance["service"] as? String == value.service.rawValue, let collected = provenance["collected_at"] as? Double, collected.isFinite, collected > 0 else { throw SFTPAuthError.provenanceMismatch }
        let known = try PrivateInput.text(PrivateInput.read(value.credentialDirectory + "/known_hosts", limit: 4096))
        let fields = known.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard known.hasSuffix("\n"), !known.dropLast().contains("\n"), fields.count == 3, fields[0] == "[127.0.0.1]:\(value.port)",
              fields[1] == "ssh-ed25519", let blob = Data(base64Encoded: String(fields[2])), blob.count == 51, blob.base64EncodedString() == fields[2] else { throw SFTPAuthError.invalidContract }
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast()
        let exported = try PrivateInput.text(PrivateInput.read(value.credentialDirectory + "/fingerprint.txt", limit: 1024)).split(whereSeparator: { $0.isWhitespace })
        guard fingerprint == value.expectedFingerprint, exported.count >= 2, exported[1] == Substring(fingerprint) else { throw SFTPAuthError.fingerprintMismatch }
        if let file = value.key.file {
            let privateKey = try PrivateInput.read(value.credentialDirectory + "/" + file, limit: 32768)
            let publicKey = try PrivateInput.read(value.credentialDirectory + "/" + file + ".pub", limit: 4096)
            guard !privateKey.isEmpty, !publicKey.isEmpty else { throw SFTPAuthError.unsafeMaterial }
            let passphrase = value.key.encrypted ? try PrivateInput.secretLine(PrivateInput.read(value.credentialDirectory + "/key-passphrase.txt", limit: 1024)) : nil
            return Self(contract: value, hostKeyLine: "ssh-ed25519 " + fields[2], publicKey: publicKey, privateKey: privateKey, passphrase: passphrase, password: nil)
        }
        let password = try PrivateInput.secretLine(PrivateInput.read(value.credentialDirectory + "/password.txt", limit: 1024))
        return Self(contract: value, hostKeyLine: "ssh-ed25519 " + fields[2], publicKey: nil, privateKey: nil, passphrase: nil, password: password)
    }
}
