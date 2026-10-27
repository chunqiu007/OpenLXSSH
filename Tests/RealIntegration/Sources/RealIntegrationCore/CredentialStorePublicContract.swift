import CryptoKit
import Foundation

public enum CredentialStorePublicError: String, Error, Codable, Sendable {
    case invalidContract, unsafeMaterial, recoveryRecordFailed, credentialStoreUnavailable, saveNotAuthorized, saveFailed, duplicateNotOwned
    case ownershipUnconfirmed, staleGeneration, extraProviderCall, gateNotCovered, credentialReadFailed
    case provenanceMismatch, fingerprintMismatch, extraManualRequest, unknownManualRequest, providerFailed
    case cancelled, timeout, connectionFailed, cleanupIncomplete, deleteRetryRequired, missingNotVerified, interactionRestoreFailed
}

public struct CredentialStorePublicOptions: Sendable {
    public let action: Action
    public let contractPath: String?
    public static func parse(_ args: [String]) throws -> Self {
        if args.isEmpty || args == ["--help"] { return Self(action: .help, contractPath: nil) }
        guard let first = args.first, ["validate", "--live"].contains(first) else { throw SmokeError.invalidArguments }
        var path: String?, local = false, ready = false, keychain = false, index = 1
        while index < args.count {
            switch args[index] {
            case "--contract":
                guard path == nil, index + 1 < args.count else { throw SmokeError.invalidArguments }
                index += 1; path = args[index]; try PrivateInput.validateSyntax(path!)
                guard path!.hasSuffix("/credential-store-public.json") else { throw SmokeError.invalidArguments }
            case "--authorized-local-fixture": guard !local else { throw SmokeError.invalidArguments }; local = true
            case "--engine-ready": guard !ready else { throw SmokeError.invalidArguments }; ready = true
            case "--authorized-test-keychain": guard !keychain else { throw SmokeError.invalidArguments }; keychain = true
            default: throw SmokeError.invalidArguments
            }
            index += 1
        }
        guard let path else { throw SmokeError.invalidArguments }
        if first == "--live" {
            guard local && ready && keychain else { throw SmokeError.authorizationRequired }
            return Self(action: .live, contractPath: path)
        }
        guard !local && !ready && !keychain else { throw SmokeError.invalidArguments }
        return Self(action: .validate, contractPath: path)
    }
    public static let help = """
    --credential-store-public: future explicitly authorized test-namespace credential lifecycle.
    --help / validate --contract /exact/credential-store-case-12hex/credential-store-public.json: syntax-only/no I/O.
    NOT released by build or normal Goal. Future only after separate primary Keychain authorization:
      --live --authorized-local-fixture --engine-ready --authorized-test-keychain --contract <exactPath>
    Uses CURRENT DEFAULT FILE KEYCHAIN + UUID service namespace, NOT an isolated physical Keychain.
    One fixture password save/read/public-provider/exact-forget; no ACL/default/search-list/UI changes.
    """
}

public struct CredentialStorePublicContract: Codable, Sendable {
    public let schema: Int
    public let taskID: String
    public let testCase: String
    public let keychainScope: String
    public let savingAuthorized: Bool
    public let service: String
    public let host: String
    public let port: Int
    public let user: String
    public let credentialDirectory: String
    public let expectedFingerprint: String
    public let baseImage: String
    public let imageID: String
    public let containerID: String
    public let project: String
    public let networkID: String
    public let context: String
    public let endpoint: String
    public static let scope = "current-default-file-keychain-test-namespace"
    public static let fullSeconds = 110.0
    public static let activeSeconds = 45.0
    public static let drainSeconds = 12.0
    public static func checkPath(_ path: String, buildRoot: String) throws {
        try PrivateInput.validateSyntax(path)
        let prefix = buildRoot + "/credential-store-case-", suffix = "/credential-store-public.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix), Contract.hex(String(path.dropFirst(prefix.count).dropLast(suffix.count)), count: 12) else { throw CredentialStorePublicError.invalidContract }
    }
    public func validate(path: String, buildRoot: String, fixtureRoot: String, home: String) throws {
        try Self.checkPath(path, buildRoot: buildRoot)
        guard schema == 1, taskID == "PUBLIC-CREDENTIAL-STORE-A", testCase == "save-read-provider-forget",
              keychainScope == Self.scope, savingAuthorized, service == "passwordonly", host == "127.0.0.1", port == 22222, user == "fixture",
              baseImage == MinaContract.base, Contract.digest(imageID, prefix: "sha256:"), Contract.hex(containerID, count: 64), Contract.hex(networkID, count: 64),
              project.hasPrefix("openlxssh-fixture-"), Contract.hex(String(project.dropFirst("openlxssh-fixture-".count)), count: 12),
              ["default", "desktop-linux"].contains(context), ["unix:///var/run/docker.sock", "unix://" + home + "/.docker/run/docker.sock"].contains(endpoint) else { throw CredentialStorePublicError.invalidContract }
        let prefix = fixtureRoot + "/.runtime/passwordonly/credentials-"
        guard credentialDirectory.hasPrefix(prefix), Contract.hex(String(credentialDirectory.dropFirst(prefix.count)), count: 12),
              expectedFingerprint.hasPrefix("SHA256:"), let digest = Data(base64Encoded: String(expectedFingerprint.dropFirst(7)) + "="),
              digest.count == 32, digest.base64EncodedString().dropLast() == expectedFingerprint.dropFirst(7) else { throw CredentialStorePublicError.invalidContract }
    }
    public func rootManagementIdentity() -> OpenSSHContract {
        OpenSSHContract(schema: 1, taskID: "OPENSSH-FOUR-AUTH-A", testCase: .positive, service: .passwordonly, host: host, port: port, user: user,
            key: .none, primary: .password, primaryPromptSHA256: nil, credentialDirectory: credentialDirectory, expectedFingerprint: expectedFingerprint,
            baseImage: baseImage, imageID: imageID, containerID: containerID, project: project, networkID: networkID, context: context, endpoint: endpoint)
    }
}

public struct CredentialStorePublicInput: Sendable {
    public let contract: CredentialStorePublicContract
    public let hostKeyLine: String
    public static func load(path: String, buildRoot: String, fixtureRoot: String, home: String) throws -> Self {
        try CredentialStorePublicContract.checkPath(path, buildRoot: buildRoot)
        let data = try PrivateInput.read(path, limit: 8192)
        _ = try MinaJSON.object(data, keys: ["schema", "taskID", "testCase", "keychainScope", "savingAuthorized", "service", "host", "port", "user", "credentialDirectory", "expectedFingerprint", "baseImage", "imageID", "containerID", "project", "networkID", "context", "endpoint"])
        let value = try JSONDecoder().decode(CredentialStorePublicContract.self, from: data)
        try value.validate(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: home)
        for folder in [fixtureRoot + "/.runtime", fixtureRoot + "/.runtime/passwordonly", value.credentialDirectory] { try PrivateInput.checkDirectory(folder) }
        let state = try MinaJSON.object(PrivateInput.read(fixtureRoot + "/.runtime/state.json", limit: 4096), keys: ["version", "project", "image"])
        guard state["version"] as? Int == 1, state["project"] as? String == value.project, state["image"] as? String == value.baseImage else { throw CredentialStorePublicError.invalidContract }
        let provenance = try MinaJSON.object(PrivateInput.read(value.credentialDirectory + "/provenance.json", limit: 4096), keys: ["base_image", "built_image_id", "service", "collected_at"])
        guard provenance["base_image"] as? String == value.baseImage, provenance["built_image_id"] as? String == value.imageID,
              provenance["service"] as? String == "passwordonly", let collected = provenance["collected_at"] as? Double, collected.isFinite, collected > 0 else { throw CredentialStorePublicError.invalidContract }
        let known = try PrivateInput.text(PrivateInput.read(value.credentialDirectory + "/known_hosts", limit: 4096))
        let fields = known.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard known.hasSuffix("\n"), !known.dropLast().contains("\n"), fields.count == 3, fields[0] == "[127.0.0.1]:22222", fields[1] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51, blob.base64EncodedString() == fields[2] else { throw CredentialStorePublicError.invalidContract }
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast()
        let exported = try PrivateInput.text(PrivateInput.read(value.credentialDirectory + "/fingerprint.txt", limit: 1024)).split(whereSeparator: { $0.isWhitespace })
        guard fingerprint == value.expectedFingerprint, exported.count >= 2, exported[1] == Substring(fingerprint) else { throw CredentialStorePublicError.invalidContract }
        return Self(contract: value, hostKeyLine: "ssh-ed25519 " + fields[2])
    }
    public func fixturePasswordForExplicitSave() throws -> Data {
        try PrivateInput.secretLine(PrivateInput.read(contract.credentialDirectory + "/password.txt", limit: 1024))
    }
}
