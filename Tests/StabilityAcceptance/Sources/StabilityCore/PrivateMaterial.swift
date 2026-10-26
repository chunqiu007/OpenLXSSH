import CryptoKit
import Darwin
import Foundation
import StabilityPOSIX

public enum PrivateMaterial {
    public static func validateSyntax(_ path: String) throws {
        guard path.hasPrefix("/"), path != "/", !path.hasSuffix("/"), path.utf8.count < 4096,
              !path.contains("$"), !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw StabilityError.unsafePath
        }
    }
    public static func check(_ path: String, directory: Bool) throws {
        try validateSyntax(path)
        let fd = stability_open_private(path, directory ? 1 : 2)
        guard fd >= 0 else { throw StabilityError.unsafePermissions }
        Darwin.close(fd)
    }
    public static func readPublic(_ path: String, limit: Int = 32_768) throws -> Data {
        try validateSyntax(path)
        let fd = stability_open_private(path, 0)
        guard fd >= 0 else { throw StabilityError.unsafePermissions }
        defer { Darwin.close(fd) }
        var bytes = [UInt8](repeating: 0, count: limit + 1), total = 0
        while total < bytes.count {
            let n = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: total), $0.count - total) }
            if n == 0 { break }
            if n < 0 { if errno == EINTR { continue }; throw StabilityError.invalidFixture }
            total += n
        }
        guard total <= limit else { throw StabilityError.invalidFixture }
        return Data(bytes.prefix(total))
    }
}

/// Public-only snapshot. It intentionally has no password, passphrase, key bytes,
/// credential-directory path or arbitrary server-controlled text in its Codable surface.
public struct FixturePublic: Sendable {
    public let hostKeyLine: String
    public let hostFingerprint: String
    public let clientPublicKeyLine: String
    public let baseImage: String
    public let builtImageID: String
    public let collectedAt: Double

    public static func inspect(_ options: Options) throws -> Self {
        guard let directory = options.credentials, let expected = options.verifiedFingerprint else {
            throw StabilityError.invalidArguments
        }
        try PrivateMaterial.validateSyntax(directory)
        return try inspectExactSuffix(options, directory: directory, expected: expected)
    }

    private static func inspectExactSuffix(_ options: Options, directory: String, expected: String) throws -> Self {
        let parts = directory.split(separator: "/").map(String.init)
        guard parts.count >= 5, Array(parts.suffix(5).prefix(4)) == ["Tests", "IntegrationEnvironment", ".runtime", "keyonly"],
              let name = parts.last, name.hasPrefix("credentials-"), name.count == 24,
              name.dropFirst(12).allSatisfy({ "0123456789abcdef".contains($0) }) else { throw StabilityError.invalidFixture }
        let service = URL(fileURLWithPath: directory).deletingLastPathComponent().path
        let runtime = URL(fileURLWithPath: service).deletingLastPathComponent().path
        for path in [runtime, service, directory] { try PrivateMaterial.check(path, directory: true) }
        // Metadata only. No read(), no keygen on a private key, and no password/passphrase file opens.
        try PrivateMaterial.check(directory + "/id_ed25519", directory: false)
        let known = try text(directory + "/known_hosts")
        let fields = known.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard known.hasSuffix("\n"), !known.dropLast().contains("\n"), fields.count == 3,
              fields[0] == "[127.0.0.1]:22221", fields[1] == "ssh-ed25519" else { throw StabilityError.invalidFixture }
        let key = try publicKey(String(fields[1]), String(fields[2]))
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: key)).base64EncodedString().replacingOccurrences(of: "=", with: "")
        let exported = try text(directory + "/fingerprint.txt").split(whereSeparator: { $0.isWhitespace })
        guard exported.count >= 2, exported[1] == Substring(fingerprint), expected == fingerprint else { throw StabilityError.fingerprintMismatch }
        let client = try text(directory + "/id_ed25519.pub").trimmingCharacters(in: .newlines)
        let clientFields = client.split(separator: " ")
        guard clientFields.count >= 2, clientFields[0] == "ssh-ed25519" else { throw StabilityError.invalidFixture }
        _ = try publicKey(String(clientFields[0]), String(clientFields[1]))
        let provenance = try JSONDecoder().decode(Provenance.self, from: PrivateMaterial.readPublic(directory + "/provenance.json"))
        guard provenance.service == "keyonly", provenance.collected_at.isFinite, provenance.collected_at > 0,
              provenance.base_image.hasPrefix("docker.io/library/ubuntu:24.04@sha256:"),
              hexSuffix(provenance.base_image, prefix: "docker.io/library/ubuntu:24.04@sha256:"),
              hexSuffix(provenance.built_image_id, prefix: "sha256:") else { throw StabilityError.invalidFixture }
        return Self(hostKeyLine: "ssh-ed25519 " + String(fields[2]), hostFingerprint: fingerprint,
                    clientPublicKeyLine: "ssh-ed25519 " + String(clientFields[1]), baseImage: provenance.base_image,
                    builtImageID: provenance.built_image_id, collectedAt: provenance.collected_at)
    }

    private struct Provenance: Decodable {
        let service: String, base_image: String, built_image_id: String
        let collected_at: Double
    }
    private static func hexSuffix(_ text: String, prefix: String) -> Bool {
        text.hasPrefix(prefix) && text.count == prefix.count + 64 && text.dropFirst(prefix.count).allSatisfy({ "0123456789abcdef".contains($0) })
    }
    private static func text(_ path: String) throws -> String {
        guard let text = String(data: try PrivateMaterial.readPublic(path), encoding: .utf8),
              !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && $0 != "\n" }) else {
            throw StabilityError.invalidFixture
        }
        return text
    }
    private static func publicKey(_ algorithm: String, _ base64: String) throws -> Data {
        guard algorithm == "ssh-ed25519", let blob = Data(base64Encoded: base64),
              blob.base64EncodedString() == base64, blob.count == 51 else { throw StabilityError.invalidFixture }
        // This is a public-key fingerprint/shape check, not a new SSH parser. The
        // signed driver additionally invokes the mature HostPublicKey validator.
        return blob
    }
}
