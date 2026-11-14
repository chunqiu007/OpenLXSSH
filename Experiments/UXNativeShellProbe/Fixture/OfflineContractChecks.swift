import Foundation
import OpenLXSSHFiles
import RealIntegrationCore
import UXNativeShellProbeSupport

/// Invoked only by the offline-check executable. Synthetic in-memory material schemas, no file
/// reader, no management owner construction, no real key/password, no network or processes.
public enum NativeShellFixtureOfflineChecks {
    public static func run() throws -> Int {
        var checks = 0
        func require(_ condition: @autoclosure () throws -> Bool) throws {
            guard try condition() else { throw SFTPAuthError.integrity }; checks += 1
        }
        func refuses(_ body: () throws -> Void) throws {
            do { try body() } catch { checks += 1; return }
            throw SFTPAuthError.integrity
        }
        let build = "/offline/probe/.build", root = "/offline/fixture", home = "/offline/home"
        let path = build + "/sftp-auth-case-012345abcdef/sftp-auth.json"
        func object(_ service: OpenSSHService, _ key: OpenSSHKey) -> [String: Any] {
            ["schema": 1, "taskID": "REAL-SFTP-COMBINED-AUTH-A", "service": service.rawValue,
             "host": "127.0.0.1", "port": service.port, "user": "fixture", "key": key.rawValue,
             "credentialDirectory": root + "/.runtime/" + service.rawValue + "/credentials-012345abcdef",
             "expectedFingerprint": "SHA256:" + Data(repeating: 1, count: 32).base64EncodedString().dropLast(),
             "baseImage": MinaContract.base, "imageID": "sha256:" + String(repeating: "a", count: 64),
             "containerID": String(repeating: "b", count: 64), "networkID": String(repeating: "c", count: 64),
             "project": "openlxssh-fixture-012345abcdef", "context": "desktop-linux",
             "endpoint": "unix://" + home + "/.docker/run/docker.sock"]
        }
        func decode(_ value: [String: Any]) throws -> SFTPAuthContract {
            try NativeShellMaterialContract.decode(JSONSerialization.data(withJSONObject: value), path: path,
                buildRoot: build, fixtureRoot: root, home: home)
        }
        for service in [OpenSSHService.keyonly, .passwordonly, .keyKbd, .passwordKbd] {
            for key in service.usesKey ? [OpenSSHKey.edplain, .edencrypted, .rsaplain, .rsaencrypted] : [.none] {
                try require(try decode(object(service, key)).service == service)
            }
        }
        for change: [String: Any] in [["schema": 2], ["taskID": "U0-NATIVE-SHELL-LIVE-A"], ["host": "localhost"],
            ["host": "192.0.2.1"], ["port": 22225], ["user": "root"], ["key": "none"], ["containerID": "short"],
            ["endpoint": "tcp://127.0.0.1:2375"], ["credentialDirectory": root + "/.runtime/key-kbd/credentials-latest"],
            ["unexpected": "field"], ["password": "forbidden"], ["command": "forbidden"]] {
            var value = object(.keyKbd, .edplain); change.forEach { value[$0.key] = $0.value }
            try refuses { _ = try decode(value) }
        }
        for invalid in ["/etc/passwd", build + "/sftp-auth-case-latest/sftp-auth.json", build + "/sftp-auth-case-012345ABCDEF/sftp-auth.json",
                        build + "/sftp-auth-case-012345abcdef/../sftp-auth.json", build + "/sftp-auth-case-012345abcdef/sftp-auth.json\n"] {
            try refuses { try ShellProbeCommand.checkContractPath(invalid, buildRoot: build) }
        }
        // Unmodified exact test callback budget: A/B/C same session, echo0, then terminal empty0.
        let session = "012345abcdef012345abcdef"
        var budget = try SFTPAuthBudget(mfa: true, start: 100)
        for index in 0..<3 {
            let prompt = try SFTPAuthBudget.prompt(session: session, index: index)
            let phase = try budget.claim(name: Data(), instruction: Data(), prompts: [prompt], echo: [false], now: 101 + Double(index))
            try budget.consume(phase: phase, now: 102 + Double(index)); budget.resolved(true)
        }
        let zero = try budget.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 106)
        try budget.consume(phase: zero, now: 107); budget.resolved(true); try budget.requireComplete(); checks += 1
        try require(budget.managementReads == 3 && budget.replies == 4 && budget.terminalZeroReplies == 1)
        var unknown = try SFTPAuthBudget(mfa: true, start: 100)
        try refuses { _ = try unknown.claim(name: Data(), instruction: Data(), prompts: [Data("Password:".utf8)], echo: [false], now: 101) }
        try require(unknown.managementReads == 0 && unknown.replies == 0)
        var echo = try SFTPAuthBudget(mfa: true, start: 100)
        try refuses { _ = try echo.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: 0)], echo: [true], now: 101) }
        var crossed = try SFTPAuthBudget(mfa: true, start: 100)
        let first = try crossed.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: 0)], echo: [false], now: 101)
        try crossed.consume(phase: first, now: 102); crossed.resolved(true)
        try refuses { _ = try crossed.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: String(repeating: "f", count: 24), index: 1)], echo: [false], now: 103) }
        try require(SFTPAuthContract.activeSeconds == 45 && SFTPAuthContract.drainSeconds == 12 && SFTPAuthContract.fullSeconds == 85)
        let identity = try decode(object(.keyKbd, .edplain)).rootManagementIdentity()
        try refuses { _ = try OpenSSHManagementPolicy.arguments(contract: identity, session: "../../bad", index: 0) }
        try refuses { _ = try OpenSSHManagementPolicy.arguments(contract: identity, session: session, index: 3) }
        let arguments = try OpenSSHManagementPolicy.arguments(contract: identity, session: session, index: 0)
        try require(arguments.prefix(3) == ["--host", identity.endpoint, "exec"] && arguments.suffix(3) == ["response", session, "0"])
        // New negative evidence validators only; no synthetic bytes are claimed as live SSH.
        try ShellProbeCase.encryptedEd.validate(fixture: .keyonly, key: "edencrypted"); checks += 1
        for key in ["rsaplain", "rsaencrypted"] { try ShellProbeCase.rsa.validate(fixture: .keyonly, key: key); checks += 1 }
        try refuses { try ShellProbeCase.wrongPrimary.validate(fixture: .passwordKbd, key: "none") }
        let methods = NativeShellAuthenticationStage.advertised(password: true, publicKey: false, keyboardInteractive: false)
        let refusal: [NativeShellAuthenticationStage] = [methods, .primaryStarted(.password), .primaryResult(.password, code: -18, authenticated: false)]
        func expected(_ facts: [NativeShellAuthenticationStage], replies: Int = 0, reads: Int = 0) throws {
            try ShellProbeAttemptFacts(stages: facts).requireExpected(.wrongPrimary, nativeKind: .authentication, nativeCode: -18,
                cancelled: false, changedKeyRejected: false, firstChallengeValidated: false, callbackCount: 0,
                replies: replies, managementReads: reads, inputCalls: 0, closeCompleted: true, timedOut: false, stopped: false)
        }
        try expected(refusal); checks += 1
        try refuses { try expected(refusal + [.primaryStarted(.password)]) }
        try refuses { try expected(refusal, replies: 1) }
        try refuses { try expected(refusal, reads: 1) }
        return checks
    }
}
