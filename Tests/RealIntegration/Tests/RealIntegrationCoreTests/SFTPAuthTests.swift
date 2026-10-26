import Foundation
import XCTest
@testable import RealIntegrationCore

final class SFTPAuthTests: XCTestCase {
    let session = "0123456789abcdef01234567"
    func object(service: OpenSSHService = .keyKbd, key: OpenSSHKey = .edplain) -> [String: Any] {
        ["schema": 1, "taskID": "REAL-SFTP-COMBINED-AUTH-A", "service": service.rawValue, "host": "127.0.0.1", "port": service.port,
         "user": "fixture", "key": key.rawValue, "credentialDirectory": "/fixture/.runtime/" + service.rawValue + "/credentials-012345abcdef",
         "expectedFingerprint": "SHA256:" + Data(repeating: 1, count: 32).base64EncodedString().dropLast(), "baseImage": MinaContract.base,
         "imageID": "sha256:" + String(repeating: "a", count: 64), "containerID": String(repeating: "b", count: 64),
         "project": "openlxssh-fixture-012345abcdef", "networkID": String(repeating: "c", count: 64), "context": "desktop-linux",
         "endpoint": "unix:///Users/test/.docker/run/docker.sock"]
    }
    func contract(_ value: [String: Any]) throws -> SFTPAuthContract {
        try JSONDecoder().decode(SFTPAuthContract.self, from: JSONSerialization.data(withJSONObject: value))
    }
    func testIndependentStrictContractAndFixedAuthenticationOrder() throws {
        XCTAssertEqual(try SFTPAuthOptions.parse([]).action, .help)
        XCTAssertEqual(try SFTPAuthOptions.parse(["validate", "--contract", "/missing/sftp-auth.json"]).action, .validate)
        XCTAssertThrowsError(try SFTPAuthOptions.parse(["--live", "--contract", "/missing/sftp-auth.json"]))
        XCTAssertThrowsError(try SFTPAuthOptions.parse(["validate", "--contract", "/missing/openssh-auth.json"]))
        XCTAssertThrowsError(try SFTPAuthInput.load(path: "/etc/passwd", buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        let path = "/build/sftp-auth-case-012345abcdef/sftp-auth.json"
        for service in [OpenSSHService.keyonly, .passwordonly, .keyKbd, .passwordKbd] {
            for key in (service.usesKey ? [OpenSSHKey.edplain, .edencrypted, .rsaplain, .rsaencrypted] : [.none]) {
                let value = try contract(object(service: service, key: key))
                XCTAssertNoThrow(try value.validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
                XCTAssertEqual(value.authenticationOrder, [service.usesKey ? "publickey" : "password"] + (service.mfa ? ["keyboard-interactive"] : []))
            }
        }
        for change: [String: Any] in [["host": "localhost"], ["host": "192.0.2.1"], ["port": 22225], ["key": "none"], ["user": "root"],
            ["endpoint": "tcp://127.0.0.1:2375"], ["containerID": "short"], ["project": "openlxssh-mina-012345abcdef"],
            ["credentialDirectory": "/fixture/.runtime/key-kbd/credentials-latest"]] {
            var bad = object(); change.forEach { bad[$0.key] = $0.value }
            XCTAssertThrowsError(try contract(bad).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        }
        let expectedKeys = Set(object().keys)
        for key in ["primary", "primaryPromptSHA256", "mode", "responsePlan"] {
            var bad = object(); bad[key] = "forbidden"
            XCTAssertThrowsError(try MinaJSON.object(JSONSerialization.data(withJSONObject: bad), keys: expectedKeys))
        }
        XCTAssertThrowsError(try SFTPAuthContract.checkPath("/build/sftp-auth-case-latest/sftp-auth.json", buildRoot: "/build"))
    }
    func testExactRawSinglePromptThreeRoundsAndNoCallbackForSingleMethod() throws {
        var budget = try SFTPAuthBudget(mfa: true, start: 100)
        for index in 0..<3 {
            let prompt = try SFTPAuthBudget.prompt(session: session, index: index)
            let claim = try budget.claim(name: Data(), instruction: Data(), prompts: [prompt], echo: [false], now: Double(101 + index))
            XCTAssertEqual(claim, .secret(session: session, index: index))
            try budget.consume(phase: claim, now: Double(102 + index)); budget.resolved(true)
        }
        XCTAssertThrowsError(try budget.requireComplete()) // Three secrets alone omit the observed protocol tail.
        let tail = try budget.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 106)
        XCTAssertEqual(tail, .terminalZero)
        try budget.consume(phase: tail, now: 107); budget.resolved(true)
        XCTAssertNoThrow(try budget.requireComplete()); XCTAssertEqual(budget.managementReads, 3)
        XCTAssertEqual(budget.replies, 4); XCTAssertEqual(budget.secretResponses, 3); XCTAssertEqual(budget.terminalZeroReplies, 1)
        XCTAssertEqual(budget.promptCounts, [1, 1, 1, 0]); XCTAssertEqual(budget.echoFlags, [[false], [false], [false], []])
        XCTAssertThrowsError(try budget.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: 0)], echo: [false], now: 110))
        var none = try SFTPAuthBudget(mfa: false, start: 100)
        XCTAssertNoThrow(try none.requireComplete())
        XCTAssertThrowsError(try none.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 101))
    }
    func testUnknownHeaderEchoCountOrderCrossSessionAndConcurrentCallbackRefuse() throws {
        let first = try SFTPAuthBudget.prompt(session: session, index: 0)
        for tuple in [(Data("header".utf8), Data(), [first], [false]), (Data(), Data("instruction".utf8), [first], [false]),
                      (Data(), Data(), [first], [true]), (Data(), Data(), [first, first], [false, false]),
                      (Data(), Data(), [Data("Password:".utf8)], [false]),
                      (Data(), Data(), [Data(("(fixture@[127.0.0.1]:22223) " + String(decoding: first, as: UTF8.self)).utf8)], [false])] {
            var budget = try SFTPAuthBudget(mfa: true, start: 100)
            XCTAssertThrowsError(try budget.claim(name: tuple.0, instruction: tuple.1, prompts: tuple.2, echo: tuple.3, now: 101))
            XCTAssertEqual(budget.managementReads, 0); XCTAssertEqual(budget.replies, 0)
        }
        var concurrent = try SFTPAuthBudget(mfa: true, start: 100)
        _ = try concurrent.claim(name: Data(), instruction: Data(), prompts: [first], echo: [false], now: 101)
        XCTAssertThrowsError(try concurrent.claim(name: Data(), instruction: Data(), prompts: [first], echo: [false], now: 102))
        XCTAssertEqual(concurrent.managementReads, 1)
        var crossed = try SFTPAuthBudget(mfa: true, start: 100)
        _ = try crossed.claim(name: Data(), instruction: Data(), prompts: [first], echo: [false], now: 101)
        try crossed.consume(phase: .secret(session: session, index: 0), now: 102); crossed.resolved(true)
        XCTAssertThrowsError(try crossed.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: String(repeating: "f", count: 24), index: 1)], echo: [false], now: 103))
        var wrongOrder = try SFTPAuthBudget(mfa: true, start: 100)
        XCTAssertThrowsError(try wrongOrder.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: 2)], echo: [false], now: 101))
    }
    func testCloseTimeoutReplayAndFailedResolutionCannotSendAgain() throws {
        let prompt = try SFTPAuthBudget.prompt(session: session, index: 0)
        var closed = try SFTPAuthBudget(mfa: true, start: 100)
        _ = try closed.claim(name: Data(), instruction: Data(), prompts: [prompt], echo: [false], now: 101)
        closed.close(); XCTAssertThrowsError(try closed.consume(phase: .secret(session: session, index: 0), now: 102)); XCTAssertEqual(closed.replies, 0)
        var timed = try SFTPAuthBudget(mfa: true, start: 100)
        XCTAssertThrowsError(try timed.claim(name: Data(), instruction: Data(), prompts: [prompt], echo: [false], now: 145))
        var replay = try SFTPAuthBudget(mfa: true, start: 100)
        _ = try replay.claim(name: Data(), instruction: Data(), prompts: [prompt], echo: [false], now: 101)
        try replay.consume(phase: .secret(session: session, index: 0), now: 102); replay.resolved(false)
        XCTAssertThrowsError(try replay.consume(phase: .secret(session: session, index: 0), now: 103))
        XCTAssertThrowsError(try replay.requireComplete()); XCTAssertEqual(replay.replies, 1)
        var cancelled = try SFTPAuthBudget(mfa: true, start: 100)
        cancelled.fail(.cancelled); XCTAssertThrowsError(try cancelled.claim(name: Data(), instruction: Data(), prompts: [prompt], echo: [false], now: 101))
    }
    func testOTPOnlyCurrentIndexTTLAndBoundedTinyPayload() throws {
        let value: [String: Any] = ["session": session, "index": 1, "expires_at": 150.0, "response": "01234567"]
        XCTAssertEqual(try OpenSSHOTP.decode(JSONSerialization.data(withJSONObject: value), session: session, index: 1, now: 100).value.count, 8)
        XCTAssertThrowsError(try OpenSSHOTP.decode(JSONSerialization.data(withJSONObject: value), session: session, index: 2, now: 100))
        XCTAssertThrowsError(try OpenSSHOTP.decode(JSONSerialization.data(withJSONObject: value), session: session, index: 1, now: 150))
        let id = UUID(uuidString: "12345678-1234-1234-1234-123456789abc")!
        let bytes = Data(("OpenLXSSH disposable tiny SFTP round trip " + id.uuidString + "\n").utf8)
        XCTAssertEqual(bytes.count, 79)
        let ownership = RemoteOwnership(id: id)
        XCTAssertThrowsError(try ownership.checkListing([Data("unknown".utf8)], payloadOwned: true))
        XCTAssertEqual(SFTPAuthContract.connectionSeconds, 20); XCTAssertEqual(SFTPAuthContract.operationSeconds, 20)
        XCTAssertEqual(SFTPAuthContract.activeSeconds, 45); XCTAssertEqual(SFTPAuthContract.drainSeconds, 12); XCTAssertEqual(SFTPAuthContract.fullSeconds, 85)
    }
}
