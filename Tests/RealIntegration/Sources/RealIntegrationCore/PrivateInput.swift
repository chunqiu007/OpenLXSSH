import CryptoKit
import Darwin
import Foundation
import RealIntegrationPOSIX

public enum PrivateInput {
    public static func validateSyntax(_ path: String) throws {
        guard path.hasPrefix("/"), path != "/", !path.hasSuffix("/"), path.utf8.count < 4096,
              !path.contains("$"), !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw SmokeError.unsafePath
        }
    }
    public static func checkDirectory(_ path: String) throws {
        try validateSyntax(path)
        let fd = ri_open_private(path, 1)
        guard fd >= 0 else { throw SmokeError.unsafeMaterial }
        Darwin.close(fd)
    }
    public static func read(_ path: String, limit: Int) throws -> Data {
        try validateSyntax(path)
        guard (1...1_048_576).contains(limit) else { throw SmokeError.unsafeMaterial }
        let fd = ri_open_private(path, 0)
        guard fd >= 0 else { throw SmokeError.unsafeMaterial }
        defer { Darwin.close(fd) }
        var data = Data(count: limit + 1), total = 0
        while total < data.count {
            let n = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: total), $0.count - total) }
            if n == 0 { break }
            if n < 0 { if errno == EINTR { continue }; throw SmokeError.unsafeMaterial }
            total += n
        }
        guard total <= limit else { throw SmokeError.unsafeMaterial }
        data.count = total; return data
    }
    public static func writeExclusive(_ data: Data, to path: String) throws {
        try validateSyntax(path)
        let fd = ri_create_private(path)
        guard fd >= 0 else { throw SmokeError.unsafeMaterial }
        defer { Darwin.close(fd) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw SmokeError.unsafeMaterial }; offset += count
        }
        guard fsync(fd) == 0 else { throw SmokeError.unsafeMaterial }
    }
    public static func text(_ data: Data) throws -> String {
        guard let text = String(data: data, encoding: .utf8),
              !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && $0 != "\n" }) else { throw SmokeError.invalidFixture }
        return text
    }
    public static func secretLine(_ data: Data) throws -> Data {
        guard data.last == 10, data.count > 1, data.count <= 1024 else { throw SmokeError.invalidFixture }
        let answer = Data(data.dropLast())
        guard !answer.contains(0), !answer.contains(10), !answer.contains(13) else { throw SmokeError.invalidFixture }
        return answer
    }
    public static func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}

// Not Codable/printable: secret Data is never part of a report/description.
public struct FixtureInput: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "<redacted fixture input>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
    public let contract: Contract
    public let hostKeyLine: String
    public let fingerprint: String
    public let privateKey: Data?
    public let clientPublicKey: Data?
    public let password: Data?

    public static func load(contractPath: String, fixtureRoot: String) throws -> Self {
        try PrivateInput.validateSyntax(fixtureRoot)
        try PrivateInput.validateSyntax(contractPath)
        // Refuse arbitrary files BEFORE any open. No search/latest, symlink
        // resolution, credential override or previous-generation fallback.
        guard FixtureService.all.contains(where: { service in
            let prefix = fixtureRoot + "/.runtime/" + service.rawValue + "/credentials-"
            guard contractPath.hasPrefix(prefix), contractPath.hasSuffix("/real-integration.json") else { return false }
            return Contract.hex(String(contractPath.dropFirst(prefix.count).dropLast("/real-integration.json".count)), count: 12)
        }) else { throw SmokeError.invalidContract }
        let contractData = try PrivateInput.read(contractPath, limit: 8192)
        guard let object = try JSONSerialization.jsonObject(with: contractData) as? [String: Any],
              Set(object.keys) == Set(["schema", "fixtureLabel", "mode", "testCase", "service", "host", "port", "user", "credentialDirectory", "expectedFingerprint", "expectedBaseImage", "expectedBuiltImageID", "responsePlan"]),
              let plan = object["responsePlan"] as? [String: Any], Set(plan.keys).isSubset(of: ["kind", "expectedPromptSHA256"]),
              plan["kind"] is String else { throw SmokeError.invalidContract }
        let contract = try JSONDecoder().decode(Contract.self, from: contractData)
        try contract.validate(contractPath: contractPath, fixtureRoot: fixtureRoot)
        let directory = contract.credentialDirectory
        for parent in [fixtureRoot + "/.runtime", fixtureRoot + "/.runtime/" + contract.service.rawValue, directory] {
            try PrivateInput.checkDirectory(parent)
        }
        let provenance = try JSONSerialization.jsonObject(with: PrivateInput.read(directory + "/provenance.json", limit: 4096)) as? [String: Any]
        guard let provenance, Set(provenance.keys) == Set(["base_image", "built_image_id", "service", "collected_at"]),
              provenance["base_image"] as? String == contract.expectedBaseImage,
              provenance["built_image_id"] as? String == contract.expectedBuiltImageID,
              provenance["service"] as? String == contract.service.rawValue,
              let time = provenance["collected_at"] as? Double, time.isFinite, time > 0 else { throw SmokeError.provenanceMismatch }
        let known = try PrivateInput.text(PrivateInput.read(directory + "/known_hosts", limit: 4096))
        let fields = known.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard known.hasSuffix("\n"), !known.dropLast().contains("\n"), fields.count == 3,
              fields[0] == "[127.0.0.1]:\(contract.port)", fields[1] == "ssh-ed25519",
              let key = Data(base64Encoded: String(fields[2])), key.count == 51,
              key.base64EncodedString() == fields[2] else { throw SmokeError.invalidFixture }
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: key)).base64EncodedString().dropLast()
        let exported = try PrivateInput.text(PrivateInput.read(directory + "/fingerprint.txt", limit: 1024)).split(whereSeparator: { $0.isWhitespace })
        guard exported.count >= 2, exported[1] == Substring(fingerprint), fingerprint == contract.expectedFingerprint else { throw SmokeError.fingerprintMismatch }
        let publicBytes: Data?, privateBytes: Data?, password: Data?
        if contract.service == .keyonly {
            publicBytes = try PrivateInput.read(directory + "/id_ed25519.pub", limit: 4096)
            privateBytes = try PrivateInput.read(directory + "/id_ed25519", limit: 32768)
            password = nil
            let line = try PrivateInput.text(publicBytes!).trimmingCharacters(in: .newlines).split(separator: " ")
            guard line.count >= 2, line[0] == "ssh-ed25519", !privateBytes!.isEmpty else { throw SmokeError.invalidFixture }
        } else {
            publicBytes = nil; privateBytes = nil
            password = try PrivateInput.secretLine(PrivateInput.read(directory + "/password.txt", limit: 1024))
        }
        return Self(contract: contract, hostKeyLine: "ssh-ed25519 " + fields[2], fingerprint: String(fingerprint),
                    privateKey: privateBytes, clientPublicKey: publicBytes, password: password)
    }
}
extension FixtureService {
    fileprivate static let all: [Self] = [.keyonly, .passwordonly]
}
