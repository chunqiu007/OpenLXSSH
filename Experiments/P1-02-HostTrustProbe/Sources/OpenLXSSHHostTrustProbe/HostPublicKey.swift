import CryptoKit
import Darwin
import Foundation

public struct HostPublicKey: Hashable, Sendable {
    public let algorithm: String
    public let blob: Data
    public var base64: String { blob.base64EncodedString() }
    public var fingerprint: String {
        "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
    }
    public var openSSH: String { algorithm + " " + base64 }

    /// Uses OpenSSH's parser, not a home-grown SSH wire-format or crypto implementation.
    /// Certificates and CA/revocation records are intentionally outside this prototype.
    public init(algorithm: String, base64: String) throws {
        let supported = ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                         "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                         "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"]
        guard supported.contains(algorithm), base64.utf8.count <= 16_384,
              let bytes = Data(base64Encoded: base64), !bytes.isEmpty,
              bytes.base64EncodedString() == base64 else { throw HostTrustError.invalidPublicKey }
        let line = algorithm + " " + base64 + "\n"
        let output = try LocalKeyParser.fingerprint(Data(line.utf8))
        let digest = "SHA256:" + Data(SHA256.hash(data: bytes)).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        guard output.split(whereSeparator: { $0.isWhitespace }).dropFirst().first == Substring(digest) else {
            throw HostTrustError.invalidPublicKey
        }
        self.algorithm = algorithm
        blob = bytes
    }

    public init(openSSHPublicKey line: String) throws {
        guard line.utf8.count <= 17_000,
              !line.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              line == line.trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw HostTrustError.invalidPublicKey
        }
        let fields = line.split(separator: " ", omittingEmptySubsequences: true)
        guard fields.count >= 2 else { throw HostTrustError.invalidPublicKey }
        try self.init(algorithm: String(fields[0]), base64: String(fields[1]))
    }
}

private enum LocalKeyParser {
    static func fingerprint(_ publicKey: Data) throws -> String {
        let process = Process()
        let input = Pipe()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-l", "-f", "-", "-E", "sha256"]
        process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { throw HostTrustError.publicKeyToolFailed }
        do {
            try input.fileHandleForWriting.write(contentsOf: publicKey)
            try input.fileHandleForWriting.close()
        } catch {
            process.terminate()
            process.waitUntilExit()
            throw HostTrustError.publicKeyToolFailed
        }
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while process.isRunning && ContinuousClock.now < deadline { Thread.sleep(forTimeInterval: 0.002) }
        if process.isRunning {
            process.terminate()
            Thread.sleep(forTimeInterval: 0.02)
            if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            throw HostTrustError.publicKeyToolFailed
        }
        process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        try? output.fileHandleForReading.close()
        guard process.terminationStatus == 0, data.count < 4096,
              let text = String(data: data, encoding: .utf8) else { throw HostTrustError.invalidPublicKey }
        return text
    }
}
