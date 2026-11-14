import CryptoKit
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import UXNativeShellProbeSupport

struct NativeShellFaultResult: Sendable {
    let stages: [NativeShellAuthenticationStage]
    let kind: NativeShellError.Kind?
    let code: Int32?
    let closed: Bool
    let returnedUnexpectedShell: Bool
    let providerCalls: Int
    let pendingInteractionTasks: Int
}
private final class NativeShellPrimaryCallCount: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func claim() throws {
        try lock.withLock {
            guard count == 0 else { throw ShellProbeError.missingEvidence }
            count += 1
        }
    }
    var value: Int { lock.withLock { count } }
}
enum NativeShellFaultCase {
    static func mismatchKey(actual: HostPublicKey) throws -> HostPublicKey {
        // Only isolated test trust data. CryptoKit creates the public key; the existing mature
        // parser validates its OpenSSH public serialization. No custom signing or SSH exchange.
        let generated = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        var blob = Data()
        for field in [Data("ssh-ed25519".utf8), generated] {
            var length = UInt32(field.count).bigEndian
            withUnsafeBytes(of: &length) { blob.append(contentsOf: $0) }; blob.append(field)
        }
        let wrong = try HostPublicKey(algorithm: "ssh-ed25519", base64: blob.base64EncodedString())
        guard wrong.blob != actual.blob else { throw ShellProbeError.fixture }
        return wrong
    }
    static func run(testCase: ShellProbeCase, fixture: ShellProbeFixture, primary: FileAuthentication,
                    trust: HostTrustStore, changedKey: NativeShellChangedKeyObservation,
                    callbacks: NativeShellFaultCallbacks, token: CancellationToken) async throws -> NativeShellFaultResult {
        guard testCase.isNegative else { throw ShellProbeError.fixture }
        let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(fixture.port))
        let options = try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: 15,
            interactionTimeout: 15, authenticationTimeout: 45)
        let calls = NativeShellPrimaryCallCount()
        let keyboard: KeyboardHandler?
        if testCase == .wrongPrimary { keyboard = nil }
        else { keyboard = { challenge, reply in callbacks.handle(challenge, reply: reply) } }
        do {
            let session = try await LibSSH2ShellSession.connect(configuration: SSHConnection(host: host, user: SSHUser("fixture")),
                primaryMethod: .password, primaryProvider: { request in
                    try request.token.check(); try calls.claim(); return primary
                },
                keyboardHandler: keyboard,
                trustStore: trust, trustHandler: { event, reply in changedKey.handle(event, reply) },
                options: options, connectionTimeout: 5, token: token)
            let stages = await session.authenticationStages()
            // This branch sends NO input, no resize/startup command, no read loop. In particular,
            // cancel-after-ready is only allowed once the ACTUAL public shell connect returned.
            if testCase == .cancelAfterReady { token.cancel() }
            session.cancel(); await session.close()
            return NativeShellFaultResult(stages: stages, kind: nil, code: nil, closed: true,
                                          returnedUnexpectedShell: testCase != .cancelAfterReady,
                                          providerCalls: calls.value, pendingInteractionTasks: session.interactionSnapshot().pendingTasks)
        } catch let error as NativeShellError {
            // Public connect has already awaited close before throwing; retain the original
            // typed error. Authentication, timeout and cancellation are never interchangeable.
            return NativeShellFaultResult(stages: error.authenticationStages, kind: error.kind, code: error.code,
                                          closed: true, returnedUnexpectedShell: false,
                                          providerCalls: calls.value, pendingInteractionTasks: error.pendingInteractionTasks)
        }
    }
}
