import CredentialKeyPOSIX
import Darwin
import Foundation

public enum KeyFailure: Error, Equatable, Sendable {
    case invalidPath, unsafePermissions, symbolicLinkOrEscape, notRegularFile, fileTooLarge, changedWhileReading
    case invalidOpenSSH, unsupportedAlgorithm, passphraseRequired, invalidPassphraseInput
    case keygenRejected, secretEchoDetected, timedOut, cancelled, outputLimit
    case duplicateKey, missing, busy, systemCall(String, Int32)
}

public enum KeyAlgorithm: String, Sendable { case ed25519 = "ssh-ed25519", rsa = "ssh-rsa" }

public enum KeyProtection: Sendable {
    /// Explicitly unencrypted. The empty value is not a secret.
    case unencrypted
    case passphrase(SecretBytes)

    func inputLines(count: Int) throws -> Data {
        let bytes: Data
        switch self {
        case .unencrypted: bytes = Data()
        case .passphrase(let secret):
            guard !secret.bytes.isEmpty, secret.bytes.count <= 1023,
                  !secret.bytes.contains(where: { $0 == 0 || $0 == 10 || $0 == 13 }) else {
                throw KeyFailure.invalidPassphraseInput
            }
            bytes = secret.bytes
        }
        var input = Data()
        for _ in 0..<count { input.append(bytes); input.append(10) }
        return input
    }

    var secret: Data? {
        if case .passphrase(let value) = self { return value.bytes }
        return nil
    }
}

/// Finite local subprocess, not an SSH authentication bridge. The child has no controlling
/// terminal, display or askpass helper; stock ssh-keygen reads its RP_ALLOW_STDIN prompts
/// from a pipe. Both input and output are bounded. Only sanitized errors escape this type.
struct SSHKeygenTool: Sendable {
    let timeout: Duration
    init(timeout: Duration = .seconds(10)) { self.timeout = timeout }

    func generate(at path: String, algorithm: KeyAlgorithm, protection: KeyProtection, comment: String = "") async throws {
        guard !comment.utf8.contains(0) else { throw KeyFailure.invalidPath }
        var arguments = ["-q", "-t", algorithm == .ed25519 ? "ed25519" : "rsa"]
        if algorithm == .rsa { arguments += ["-b", "2048"] }
        arguments += ["-f", path, "-C", comment]
        _ = try await run(arguments: arguments, input: protection.inputLines(count: 2), secret: protection.secret)
    }

    func publicKey(at path: String, protection: KeyProtection) async throws -> PublicKey {
        let output = try await run(arguments: ["-y", "-f", path],
                                   input: protection.inputLines(count: 1), secret: protection.secret)
        // Prompts and diagnostics are discarded at stderr. Accept only algorithm/blob pairs;
        // comments and arbitrary process output are never returned to a caller.
        guard let text = String(data: output, encoding: .utf8) else { throw KeyFailure.keygenRejected }
        let candidates = text.components(separatedBy: .newlines).compactMap { line -> PublicKey? in
            // ssh-keygen -y may append a private-key comment, including spaces/newlines.
            let fields = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard fields.count >= 2 else { return nil }
            return try? PublicKey("\(fields[0]) \(fields[1])")
        }
        guard candidates.count == 1, let result = candidates.first else { throw KeyFailure.keygenRejected }
        return result
    }

    private func run(arguments: [String], input: Data, secret: Data?) async throws -> Data {
        guard !Task.isCancelled else { throw KeyFailure.cancelled }
        guard arguments.allSatisfy({ !$0.utf8.contains(0) }), input.count <= 2048 else {
            throw KeyFailure.invalidPath
        }
        let argv = (["/usr/bin/ssh-keygen"] + arguments).map { strdup($0) } + [nil]
        defer { for value in argv { free(value) } }
        guard argv.dropLast().allSatisfy({ $0 != nil }) else { throw KeyFailure.systemCall("strdup", ENOMEM) }
        var child: pid_t = 0
        var inputFD: Int32 = -1
        var outputFD: Int32 = -1
        let code = argv.withUnsafeBufferPointer { ck_spawn_keygen($0.baseAddress, &child, &inputFD, &outputFD) }
        guard code == 0 else { throw KeyFailure.systemCall("spawn", code) }
        defer {
            if inputFD >= 0 { _ = Darwin.close(inputFD) }
            if outputFD >= 0 { _ = Darwin.close(outputFD) }
        }
        let deadline = ContinuousClock.now + timeout
        var stop: KeyFailure?
        var killAt: ContinuousClock.Instant?
        var reaped = false
        var eof = false
        var output = Data()
        var sent = 0
        var status: Int32 = 0
        var drainUntil: ContinuousClock.Instant?
        var buffer = [UInt8](repeating: 0, count: 4096)
        while !reaped || !eof {
            if stop == nil {
                if Task.isCancelled { stop = .cancelled }
                else if ContinuousClock.now >= deadline { stop = .timedOut }
            }
            if stop != nil, !reaped, killAt == nil {
                _ = kill(child, SIGTERM)
                killAt = .now + .milliseconds(100)
                if inputFD >= 0 { _ = Darwin.close(inputFD); inputFD = -1 }
            }
            if !reaped, let killAt, ContinuousClock.now >= killAt { _ = kill(child, SIGKILL) }
            if stop == nil, inputFD >= 0 {
                let count = input.withUnsafeBytes { bytes in
                    Darwin.write(inputFD, bytes.baseAddress!.advanced(by: sent), bytes.count - sent)
                }
                if count > 0 { sent += count }
                else if count < 0, errno != EAGAIN, errno != EINTR {
                    stop = .systemCall("write input", errno)
                }
                if sent == input.count { _ = Darwin.close(inputFD); inputFD = -1 }
            }
            if !eof {
                for _ in 0..<8 {
                    let count = buffer.withUnsafeMutableBytes { Darwin.read(outputFD, $0.baseAddress, $0.count) }
                    if count > 0 {
                        if output.count + count > 65_536 { stop = .outputLimit }
                        else { output.append(contentsOf: buffer.prefix(count)) }
                    } else if count == 0 { eof = true; break }
                    else if errno == EAGAIN { break }
                    else if errno != EINTR { stop = .systemCall("read output", errno); eof = true; break }
                }
            }
            if !reaped {
                let result = waitpid(child, &status, WNOHANG)
                if result == child { reaped = true; drainUntil = .now + .milliseconds(100) }
                else if result < 0, errno != EINTR {
                    // No external owner may waitpid this child. It is no longer safe to signal it.
                    reaped = true; stop = .systemCall("waitpid", errno); drainUntil = .now
                }
            }
            if reaped, let drainUntil, ContinuousClock.now >= drainUntil { eof = true }
            if !reaped || !eof { try? await Task.sleep(for: .milliseconds(2)) }
        }
        if let secret, !secret.isEmpty, output.range(of: secret) != nil { throw KeyFailure.secretEchoDetected }
        if let stop { throw stop }
        guard ck_exit_code(status) == 0, ck_exit_signal(status) == 0 else { throw KeyFailure.keygenRejected }
        return output
    }
}
