import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust

public struct ShellProbeResult: Sendable {
    public let authentication: [NativeShellAuthenticationStage]
    public let bytesReceived: Int
    public let ack: Bool
    public let remotePTY: Bool
    public let resized: Bool
    public let remoteEOF: Bool
    public let exit: NativeShellExit
    public let localCloseCompleted: Bool
}
/// Source-reviewed finite real shell case for a future MAIN-RELEASED consumer. Not called by
/// this package's CLI/tests. Takes already approved IN-MEMORY primary material, a manual KI
/// handler, and the EXISTING approved shared store. Does not load credentials or manage Docker.
/// No arbitrary target, command, startup command, relay, process or shell execution API.
public enum ReleasedShellProbeCase {
    /// The retained stage sink records typed facts even if finite I/O later fails. It must not
    /// perform I/O or dispatch another connection; the consumer uses a tiny locked in-memory box.
    public static func run(fixture: ShellProbeFixture, primary: FileAuthentication,
                           manualKeyboardHandler: KeyboardHandler?, trustStore: HostTrustStore,
                           token: CancellationToken,
                           recordAuthenticatedStages: (@Sendable ([NativeShellAuthenticationStage]) -> Void)? = nil) async throws -> ShellProbeResult {
        switch primary {
        case .publicKey: guard fixture.usesKey else { throw ShellProbeError.fixture }
        case .password: guard !fixture.usesKey else { throw ShellProbeError.fixture }
        case .keyboardInteractive: throw ShellProbeError.fixture
        }
        let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(fixture.port))
        let options = try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: 15,
            interactionTimeout: 15, authenticationTimeout: 45)
        let deadline = ContinuousClock.now.advanced(by: .seconds(60))
        let method: NativeShellPrimaryMethod = fixture.usesKey ? .publicKey : .password
        let session = try await LibSSH2ShellSession.connect(configuration: SSHConnection(host: host, user: SSHUser("fixture")),
            primaryMethod: method, primaryProvider: { request in try request.token.check(); return primary },
            keyboardHandler: manualKeyboardHandler, trustStore: trustStore,
            trustHandler: { _, reply in reply.resolve(.reject) }, options: options, connectionTimeout: 5, token: token)
        recordAuthenticatedStages?(await session.authenticationStages())
        do {
            try await session.resize(NativeShellSize(columns: 113, rows: 37), token: token)
            let tokenText = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            var evidence = ShellProbeEvidence(token: tokenText)
            // Explicit test input AFTER connect, never part of the reusable session startup.
            // Hex-only token is assigned remotely; complete markers aren't in echoed input text.
            let input = "n='" + tokenText + "'; printf 'NATIVE_ACK_%s\\n' \"$n\"; " +
                "if test -t 0; then printf 'NATIVE_PTY_%s\\n' \"$n\"; fi; " +
                "printf 'NATIVE_SIZE_%s ' \"$n\"; stty size; exit 7\n"
            try await session.write(Data(input.utf8), token: token)
            var remoteEOF = false
            while ContinuousClock.now < deadline {
                try token.check()
                switch try await session.receive(wait: 0.25, token: token) {
                case .bytes(let bytes): try evidence.consume(bytes)
                case .wouldBlock: continue
                case .eof: remoteEOF = true
                case .exit(let exit):
                    let authentication = await session.authenticationStages()
                    await session.close()
                    guard session.interactionSnapshot().drained,
                          evidence.ack, evidence.pty, evidence.size, remoteEOF,
                          exit.reportedStatus == 7, exit.signal == nil,
                          authentication.last == .shellReady else { throw ShellProbeError.missingEvidence }
                    return ShellProbeResult(authentication: authentication, bytesReceived: evidence.count,
                        ack: evidence.ack, remotePTY: evidence.pty, resized: evidence.size, remoteEOF: remoteEOF,
                        exit: exit, localCloseCompleted: true)
                }
            }
            throw ShellProbeError.deadline
        } catch { session.cancel(); await session.close(); throw error }
    }
}
