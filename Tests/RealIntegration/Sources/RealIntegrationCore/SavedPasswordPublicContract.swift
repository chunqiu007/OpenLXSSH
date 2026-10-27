import CryptoKit
import Foundation

public enum SavedPasswordPublicCase: String, Codable, Sendable {
    case authorized = "positive-public-authorization"
    case manualFallback = "no-authorization-manual-fallback"
}
public enum SavedPasswordPublicError: String, Error, Codable, Sendable {
    case invalidContract, unsafeMaterial, provenanceMismatch, fingerprintMismatch
    case staleGeneration, extraProviderCall, extraManualRequest, unknownManualRequest
    case gateNotCovered, providerFailed, cancelled, timeout, connectionFailed, cleanupIncomplete
}

public struct SavedPasswordPublicOptions: Sendable {
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
                guard path!.hasSuffix("/saved-password-public.json") else { throw SmokeError.invalidArguments }
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
    --saved-password-public: public production gate +explicit per-generation memory provider, NO Keychain.
    --help or validate --contract /exact/saved-password-case-12hex/saved-password-public.json: syntax-only/no I/O.
    Future release only: --live --authorized-local-fixture --engine-ready --contract <exactPath>
    Fixed passwordonly fixture@127.0.0.1:22222; positive-public-authorization / no-authorization-manual-fallback.
    No eligible override, probe, gate whitelist changes, retries, terminal parsing or saved-storage claims.
    """
}

public struct SavedPasswordPublicContract: Codable, Sendable {
    public let schema: Int
    public let taskID: String
    public let testCase: SavedPasswordPublicCase
    public let service: String
    public let host: String
    public let port: Int
    public let user: String
    public let manualPromptSHA256: String?
    public let credentialDirectory: String
    public let expectedFingerprint: String
    public let baseImage: String
    public let imageID: String
    public let containerID: String
    public let project: String
    public let networkID: String
    public let context: String
    public let endpoint: String
    public static let activeSeconds = 45.0
    public static let fullSeconds = 85.0
    public static let drainSeconds = 12.0
    public static func checkPath(_ path: String, buildRoot: String) throws {
        try PrivateInput.validateSyntax(path)
        let prefix = buildRoot + "/saved-password-case-", suffix = "/saved-password-public.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix), Contract.hex(String(path.dropFirst(prefix.count).dropLast(suffix.count)), count: 12) else { throw SavedPasswordPublicError.invalidContract }
    }
    public func rootManagementIdentity() -> OpenSSHContract {
        OpenSSHContract(schema: 1, taskID: "OPENSSH-FOUR-AUTH-A", testCase: .positive, service: .passwordonly,
            host: host, port: port, user: user, key: .none, primary: .password, primaryPromptSHA256: manualPromptSHA256,
            credentialDirectory: credentialDirectory, expectedFingerprint: expectedFingerprint, baseImage: baseImage,
            imageID: imageID, containerID: containerID, project: project, networkID: networkID, context: context, endpoint: endpoint)
    }
    public func validate(path: String, buildRoot: String, fixtureRoot: String, home: String) throws {
        try Self.checkPath(path, buildRoot: buildRoot)
        guard schema == 1, taskID == "SAVED-PASSWORD-PUBLIC-A", service == "passwordonly", host == "127.0.0.1", port == 22222, user == "fixture",
              baseImage == MinaContract.base, Contract.digest(imageID, prefix: "sha256:"), Contract.hex(containerID, count: 64), Contract.hex(networkID, count: 64),
              project.hasPrefix("openlxssh-fixture-"), Contract.hex(String(project.dropFirst("openlxssh-fixture-".count)), count: 12),
              ["default", "desktop-linux"].contains(context), ["unix:///var/run/docker.sock", "unix://" + home + "/.docker/run/docker.sock"].contains(endpoint) else { throw SavedPasswordPublicError.invalidContract }
        let prefix = fixtureRoot + "/.runtime/passwordonly/credentials-"
        guard credentialDirectory.hasPrefix(prefix), Contract.hex(String(credentialDirectory.dropFirst(prefix.count)), count: 12),
              expectedFingerprint.hasPrefix("SHA256:"), let digest = Data(base64Encoded: String(expectedFingerprint.dropFirst(7)) + "="),
              digest.count == 32, digest.base64EncodedString().dropLast() == expectedFingerprint.dropFirst(7) else { throw SavedPasswordPublicError.invalidContract }
        switch testCase {
        case .authorized: guard manualPromptSHA256 == nil else { throw SavedPasswordPublicError.invalidContract }
        case .manualFallback: guard let manualPromptSHA256, Contract.hex(manualPromptSHA256, count: 64) else { throw SavedPasswordPublicError.invalidContract }
        }
    }
}

/// Public trust/provenance only during load. The password is read ONLY when an
/// authorized provider/manual phase claims the current generation's one allowance.
public struct SavedPasswordPublicInput: Sendable {
    public let contract: SavedPasswordPublicContract
    public let hostKeyLine: String
    public static func load(path: String, buildRoot: String, fixtureRoot: String, home: String) throws -> Self {
        try SavedPasswordPublicContract.checkPath(path, buildRoot: buildRoot)
        let data = try PrivateInput.read(path, limit: 8192)
        _ = try MinaJSON.object(data, keys: ["schema", "taskID", "testCase", "service", "host", "port", "user", "manualPromptSHA256", "credentialDirectory", "expectedFingerprint", "baseImage", "imageID", "containerID", "project", "networkID", "context", "endpoint"])
        let contract = try JSONDecoder().decode(SavedPasswordPublicContract.self, from: data)
        try contract.validate(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: home)
        for folder in [fixtureRoot + "/.runtime", fixtureRoot + "/.runtime/passwordonly", contract.credentialDirectory] { try PrivateInput.checkDirectory(folder) }
        let state = try MinaJSON.object(PrivateInput.read(fixtureRoot + "/.runtime/state.json", limit: 4096), keys: ["version", "project", "image"])
        guard state["version"] as? Int == 1, state["project"] as? String == contract.project, state["image"] as? String == contract.baseImage else { throw SavedPasswordPublicError.provenanceMismatch }
        let provenance = try MinaJSON.object(PrivateInput.read(contract.credentialDirectory + "/provenance.json", limit: 4096), keys: ["base_image", "built_image_id", "service", "collected_at"])
        guard provenance["base_image"] as? String == contract.baseImage, provenance["built_image_id"] as? String == contract.imageID,
              provenance["service"] as? String == "passwordonly", let collected = provenance["collected_at"] as? Double, collected.isFinite, collected > 0 else { throw SavedPasswordPublicError.provenanceMismatch }
        let known = try PrivateInput.text(PrivateInput.read(contract.credentialDirectory + "/known_hosts", limit: 4096))
        let fields = known.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard known.hasSuffix("\n"), !known.dropLast().contains("\n"), fields.count == 3, fields[0] == "[127.0.0.1]:22222", fields[1] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51, blob.base64EncodedString() == fields[2] else { throw SavedPasswordPublicError.invalidContract }
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast()
        let exported = try PrivateInput.text(PrivateInput.read(contract.credentialDirectory + "/fingerprint.txt", limit: 1024)).split(whereSeparator: { $0.isWhitespace })
        guard fingerprint == contract.expectedFingerprint, exported.count >= 2, exported[1] == Substring(fingerprint) else { throw SavedPasswordPublicError.fingerprintMismatch }
        return Self(contract: contract, hostKeyLine: "ssh-ed25519 " + fields[2])
    }
    public func password() throws -> Data {
        try PrivateInput.secretLine(PrivateInput.read(contract.credentialDirectory + "/password.txt", limit: 1024))
    }
}
