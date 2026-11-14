import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust

/// Separate from OpenSSH's accepted keepalive report. The candidate proves a same-session
/// CHANNEL_OPEN reply, not N ServerAlive requests or TCP keepalive. Relay validation lives in
/// Tests/KeepaliveAcceptance/NativeSupport and keeps the original strict DROP rules unchanged.
public enum ShellLivenessRole: String, Sendable { case normal, blackhole }
public struct ShellLivenessProbeResult: Sendable {
    public let role: ShellLivenessRole
    public let sessionID: UUID
    public let preArm: NativeShellLivenessSnapshot
    public let final: NativeShellLivenessSnapshot
    public let freshACK: Bool
    public let quietOutputBytes: Int
    public let timeoutOperation: String?
    public let closed: Bool
    public let interactionsDrained: Bool
}
/// Future source-reviewed fixture consumer only. Not called by the CLI: live DROP requires a
/// separately audited private-PIPE supervisor that binds the exact native consumer TCP tuple,
/// confirms a fresh shell ACK BEFORE arm, and preserves all original source/freshness/no-FIN
/// assertions. This method never starts a relay, Docker, management reader or credential loader.
public enum ReleasedShellLivenessProbe {
    public static func run(role: ShellLivenessRole, primary: FileAuthentication, trust: HostTrustStore,
                           token: CancellationToken,
                           armExactOwnedRelay: @Sendable (UUID) async throws -> Void) async throws -> ShellLivenessProbeResult {
        guard case .publicKey = primary else { throw ShellProbeError.fixture }
        let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22221))
        let policy = try NativeShellLivenessCandidate(interval: 2, maxUnresponsivePeriods: 2)
        let options = try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: 10,
            interactionTimeout: 15, authenticationTimeout: 45, liveness: policy)
        let session = try await LibSSH2ShellSession.connect(configuration: SSHConnection(host: host, user: SSHUser("fixture")),
            primaryMethod: .publicKey, primaryProvider: { request in try request.token.check(); return primary },
            trustStore: trust, trustHandler: { _, reply in reply.resolve(.reject) }, options: options, connectionTimeout: 5, token: token)
        do {
            // A new unpredictable marker is built remotely from pieces; echoed input lacks ACK.
            let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            try await writeACK(session, nonce: nonce, token: token)
            try await awaitACK(session, nonce: nonce, token: token)
            let quietDeadline = ContinuousClock.now.advanced(by: .seconds(12))
            var quietBytes = 0
            while .now < quietDeadline {
                switch try await session.receive(wait: 0.2, token: token) {
                case .wouldBlock: break
                case .bytes(let bytes):
                    quietBytes += bytes.count
                    guard quietBytes <= 65536 else { throw ShellProbeError.outputLimit }
                default: throw ShellProbeError.missingEvidence
                }
            }
            guard let before = await session.livenessSnapshot(), before.probesStarted >= 2,
                  before.confirmations + before.remoteRejections >= 2,
                  before.helperChannels == 0, !before.pending else { throw ShellProbeError.missingEvidence }
            // Fresh ACK after the quiet window rules out stale pre-quiet terminal bytes.
            let fresh = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            try await writeACK(session, nonce: fresh, token: token)
            try await awaitACK(session, nonce: fresh, token: token)
            if role == .blackhole {
                try await armExactOwnedRelay(session.sessionID)
                let deadline = ContinuousClock.now.advanced(by: .seconds(10))
                var timeout: String?
                do {
                    while .now < deadline {
                        switch try await session.receive(wait: 0.2, token: token) {
                        case .wouldBlock: break
                        case .bytes: throw ShellProbeError.missingEvidence // Nothing forwarded after DROP.
                        default: throw ShellProbeError.missingEvidence
                        }
                    }
                    throw ShellProbeError.deadline
                } catch let error as NativeShellError {
                    guard error.kind == .timeout, error.operation == "ssh-round-trip", !token.isCancelled else { throw error }
                    timeout = error.operation
                }
                await session.close()
                guard let final = await session.livenessSnapshot(), !final.pending, final.helperChannels == 0,
                      session.interactionSnapshot().drained else { throw ShellProbeError.missingEvidence }
                return ShellLivenessProbeResult(role: role, sessionID: session.sessionID, preArm: before,
                    final: final, freshACK: true, quietOutputBytes: quietBytes, timeoutOperation: timeout,
                    closed: true, interactionsDrained: true)
            }
            // Explicit finite test input only. No hidden startup/periodic shell commands.
            try await session.resize(NativeShellSize(columns: 113, rows: 37), token: token)
            try await session.write(Data("exit 7\n".utf8), token: token)
            let deadline = ContinuousClock.now.advanced(by: .seconds(10))
            var exited = false
            while !exited, .now < deadline {
                switch try await session.receive(wait: 0.2, token: token) {
                case .bytes, .wouldBlock, .eof: break
                case .exit(let exit):
                    guard exit.reportedStatus == 7, exit.signal == nil else { throw ShellProbeError.missingEvidence }
                    exited = true
                }
            }
            guard exited else { throw ShellProbeError.deadline }
            await session.close()
            guard let final = await session.livenessSnapshot(), final.helperChannels == 0, !final.pending,
                  session.interactionSnapshot().drained else { throw ShellProbeError.missingEvidence }
            return ShellLivenessProbeResult(role: role, sessionID: session.sessionID, preArm: before, final: final,
                freshACK: true, quietOutputBytes: quietBytes, timeoutOperation: nil, closed: true, interactionsDrained: true)
        } catch { session.cancel(); await session.close(); throw error }
    }
    private static func writeACK(_ session: LibSSH2ShellSession, nonce: String, token: CancellationToken) async throws {
        let input = "n='" + nonce + "'; printf 'NATIVE_ACK_%s\\n' \"$n\"\n"
        try await session.write(Data(input.utf8), token: token)
    }
    private static func awaitACK(_ session: LibSSH2ShellSession, nonce: String, token: CancellationToken) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        var evidence = ShellProbeEvidence(token: nonce)
        while .now < deadline {
            switch try await session.receive(wait: 0.2, token: token) {
            case .bytes(let bytes): try evidence.consume(bytes); if evidence.ack { return }
            case .wouldBlock: break
            default: throw ShellProbeError.missingEvidence
            }
        }
        throw ShellProbeError.deadline
    }
}
