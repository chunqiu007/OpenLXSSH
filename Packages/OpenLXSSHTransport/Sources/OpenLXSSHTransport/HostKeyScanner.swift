import Foundation
import Darwin
import COpenLXSSHAskpass
import OpenLXSSHTrust

public enum HostScanError: Error, Equatable, Sendable {
    case cancelled, timeout, unavailable, outputLimit, invalidOutput, noKeys, failed(Int32)
}

public enum HostKeySource: Equatable, Sendable {
    /// Unauthenticated network observation; NOT proof of server identity.
    case systemSSHKeyscan
}
public struct HostKeyCandidate: Equatable, Sendable {
    public let host: HostIdentity
    public let key: HostPublicKey
    public let source: HostKeySource
}

public protocol HostKeyScanning: Sendable {
    func scan(_ host: HostIdentity) async throws -> [HostKeyCandidate]
}

/// The scanner only obtains candidates. No path here writes trust records.
public struct SystemHostKeyScanner: HostKeyScanning {
    public let timeoutSeconds: Int
    public init(timeoutSeconds: Int = 5) throws {
        guard (1...15).contains(timeoutSeconds) else { throw HostScanError.timeout }
        self.timeoutSeconds = timeoutSeconds
    }
    public func scan(_ host: HostIdentity) async throws -> [HostKeyCandidate] {
        let cancellation = ToolCancellation()
        let arguments = ["-T", String(timeoutSeconds), "-p", String(host.port.value), "-t", "ed25519,ecdsa,rsa", host.address.value]
        return try await withTaskCancellationHandler {
            let candidates = try await Task.detached {
                let result = try BoundedTool.run("/usr/bin/ssh-keyscan", arguments, seconds: Double(timeoutSeconds + 2), cancellation: cancellation)
                guard result.status == 0 else { throw HostScanError.failed(result.status) }
                return try Self.parse(result.output, for: host)
            }.value
            try Task.checkCancellation()
            return candidates
        } onCancel: { cancellation.cancel() }
    }

    /// Strict app-owned subset of ssh-keyscan output. Host field must match the
    /// requested endpoint exactly; comments never become trust/diagnostic text.
    public static func parse(_ output: Data, for host: HostIdentity) throws -> [HostKeyCandidate] {
        guard output.count <= 128 * 1024, let text = String(data: output, encoding: .utf8),
              text.isEmpty || text.hasSuffix("\n") else { throw HostScanError.invalidOutput }
        var keys: [HostPublicKey] = []
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if line.hasPrefix("#") { continue }
            guard !line.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw HostScanError.invalidOutput }
            let fields = line.split(separator: " ", omittingEmptySubsequences: false)
            guard fields.count == 3, fields[0] == Substring(host.knownHostsName),
                  ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"].contains(String(fields[1])) else {
                throw HostScanError.invalidOutput
            }
            let key = try HostPublicKey(algorithm: String(fields[1]), base64: String(fields[2]))
            if let previous = keys.first(where: { $0.algorithm == key.algorithm }), previous != key { throw HostScanError.invalidOutput }
            if !keys.contains(key) { keys.append(key) }
            guard keys.count <= 5 else { throw HostScanError.invalidOutput }
        }
        guard !keys.isEmpty else { throw HostScanError.noKeys }
        return keys.map { HostKeyCandidate(host: host, key: $0, source: .systemSSHKeyscan) }
    }
}

final class ToolCancellation: @unchecked Sendable {
    let raw: OpaquePointer
    init() { raw = ap_cancel_create()! }
    func cancel() { ap_cancel_set(raw) }
    deinit { ap_cancel_free(raw) }
}

enum BoundedTool {
    struct Result { let output: Data; let status: Int32 }
    static func run(_ path: String, _ arguments: [String], seconds: Double,
                    cancellation: ToolCancellation = ToolCancellation(), includeStandardError: Bool = false) throws -> Result {
        let argv = ([path] + arguments).map { strdup($0) } + [nil]
        let environmentStrings: [String] = ["PATH=/usr/bin:/bin", "LC_ALL=C"]
        let env: [UnsafeMutablePointer<CChar>?] = environmentStrings.map { strdup($0) } + [nil]
        defer { (argv + env).forEach { free($0) } }
        var bytes = Data(count: 128 * 1024), count = 0, status: Int32 = -1
        let code = argv.withUnsafeBufferPointer { args in env.withUnsafeBufferPointer { environment in
            bytes.withUnsafeMutableBytes { raw in
                ap_tool(path, UnsafeMutablePointer(mutating: args.baseAddress!), UnsafeMutablePointer(mutating: environment.baseAddress!),
                        cancellation.raw, seconds, includeStandardError ? 1 : 0, raw.baseAddress, raw.count, &count, &status)
            }
        } }
        switch code {
        case 0: return Result(output: Data(bytes.prefix(count)), status: status)
        case ECANCELED: throw HostScanError.cancelled
        case ETIMEDOUT: throw HostScanError.timeout
        case EMSGSIZE: throw HostScanError.outputLimit
        default: throw HostScanError.unavailable
        }
    }
}
