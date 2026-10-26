import Foundation
import XCTest
@testable import RealIntegrationCore

final class SFTPOTPNegativeTests: XCTestCase {
    let session = "0123456789abcdef01234567"
    func contract(changes: [String: Any] = [:]) throws -> SFTPOTPNegativeContract {
        var object: [String: Any] = ["schema": 1, "taskID": "SFTP-OTP-NEGATIVE-A", "testCase": "bad-otp", "service": "key-kbd", "host": "127.0.0.1", "port": 22223,
            "user": "fixture", "key": "edplain", "credentialDirectory": "/fixture/.runtime/key-kbd/credentials-012345abcdef",
            "expectedFingerprint": "SHA256:" + Data(repeating: 1, count: 32).base64EncodedString().dropLast(), "baseImage": MinaContract.base,
            "imageID": "sha256:" + String(repeating: "a", count: 64), "containerID": String(repeating: "b", count: 64),
            "project": "openlxssh-fixture-012345abcdef", "networkID": String(repeating: "c", count: 64), "context": "desktop-linux",
            "endpoint": "unix:///Users/test/.docker/run/docker.sock"]
        changes.forEach { object[$0.key] = $0.value }
        return try JSONDecoder().decode(SFTPOTPNegativeContract.self, from: JSONSerialization.data(withJSONObject: object))
    }
    func prepared(_ testCase: SFTPOTPNegativeCase) throws -> SFTPOTPNegativeBudget {
        var budget = try SFTPOTPNegativeBudget(testCase: testCase, start: 100)
        for index in 0..<2 {
            _ = try budget.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: index)], echo: [false], now: Double(101 + index))
            try budget.recordRead(index: index, expiry: 175, wall: Double(101 + index), uptime: Double(101 + index))
            try budget.consume(index: index, wall: Double(102 + index), uptime: Double(102 + index)); try budget.resolved(true)
        }
        _ = try budget.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: 2)], echo: [false], now: 104)
        try budget.recordRead(index: 2, expiry: 175, wall: 104, uptime: 104)
        return budget
    }
    func testIndependentFixedNegativeContractAndBudgets() throws {
        XCTAssertEqual(try SFTPOTPNegativeOptions.parse([]).action, .help)
        XCTAssertEqual(try SFTPOTPNegativeOptions.parse(["validate", "--contract", "/missing/sftp-otp-negative.json"]).action, .validate)
        XCTAssertThrowsError(try SFTPOTPNegativeOptions.parse(["--live", "--contract", "/missing/sftp-otp-negative.json"]))
        XCTAssertThrowsError(try SFTPOTPNegativeOptions.parse(["validate", "--contract", "/missing/sftp-auth.json"]))
        let path = "/build/sftp-otp-negative-case-012345abcdef/sftp-otp-negative.json"
        for name in ["bad-otp", "expired-otp"] {
            XCTAssertNoThrow(try contract(changes: ["testCase": name]).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        }
        for change: [String: Any] in [["service": "password-kbd"], ["port": 22224], ["key": "edencrypted"], ["host": "localhost"], ["user": "root"],
            ["endpoint": "tcp://127.0.0.1:2375"], ["credentialDirectory": "/fixture/.runtime/key-kbd/credentials-latest"]] {
            XCTAssertThrowsError(try contract(changes: change).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        }
        XCTAssertThrowsError(try contract(changes: ["testCase": "positive"]))
        XCTAssertThrowsError(try SFTPOTPNegativeContract.load(path: "/etc/passwd", buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        XCTAssertEqual(SFTPOTPNegativeContract.operationSeconds, 85); XCTAssertEqual(SFTPOTPNegativeContract.activeSeconds, 100)
        XCTAssertEqual(SFTPOTPNegativeContract.fullSeconds, 140)
        XCTAssertEqual(SFTPAuthContract.operationSeconds, 20); XCTAssertEqual(SFTPAuthContract.activeSeconds, 45)
    }
    func testBadCIsOneDigitDifferentExactlyOnceAndBeforeExpiry() throws {
        var budget = try prepared(.badOTP)
        let original = Data("01234567".utf8), wrong = try SFTPOTPNegativeBudget.mutateOneDigit(original)
        XCTAssertNotEqual(original, wrong); XCTAssertEqual(zip(original, wrong).filter { $0 != $1 }.count, 1)
        try budget.recordWrongC(original: original, wrong: wrong)
        XCTAssertThrowsError(try budget.recordWrongC(original: original, wrong: wrong))
        try budget.consume(index: 2, wall: 105, uptime: 105); try budget.resolved(true)
        XCTAssertNoThrow(try budget.requireInjected())
        XCTAssertEqual(budget.replies, 3); XCTAssertEqual(budget.managementReads, 3); XCTAssertEqual(budget.mutatedDigitCount, 1)
        var expired = try prepared(.badOTP)
        try expired.recordWrongC(original: original, wrong: wrong)
        XCTAssertThrowsError(try expired.consume(index: 2, wall: 175.1, uptime: 175.1))
        XCTAssertThrowsError(try SFTPOTPNegativeBudget.mutateOneDigit(Data("bad".utf8)))
    }
    func testExpiredCRequiresRealWallAndMonotonicExpiryNotRereadOrFakeTime() throws {
        var budget = try prepared(.expiredOTP)
        XCTAssertFalse(try budget.expiryReached(wall: 174.99, uptime: 174.99))
        XCTAssertFalse(try budget.expiryReached(wall: 180, uptime: 105)) // Wall jump cannot fake duration.
        XCTAssertFalse(try budget.expiryReached(wall: 105, uptime: 180)) // Duration alone cannot fake server wall.
        XCTAssertThrowsError(try budget.consume(index: 2, wall: 174.99, uptime: 174.99))
        XCTAssertThrowsError(try budget.recordRead(index: 2, expiry: 175, wall: 105, uptime: 105))
        XCTAssertEqual(budget.managementReads, 3)
        XCTAssertTrue(try budget.expiryReached(wall: 175.1, uptime: 175.1))
        try budget.consume(index: 2, wall: 175.1, uptime: 175.1); try budget.resolved(true)
        XCTAssertNoThrow(try budget.requireInjected()); XCTAssertTrue(budget.realExpiryWaitVerified)
        XCTAssertEqual(budget.mutatedDigitCount, 0)
    }
    func testUnknownCallbackWrongIDReplayCancelAndClosedRefuseWithoutMoreReads() throws {
        var budget = try prepared(.badOTP)
        XCTAssertThrowsError(try budget.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 105))
        XCTAssertEqual(budget.managementReads, 3); XCTAssertEqual(budget.replies, 2)
        var unknown = try SFTPOTPNegativeBudget(testCase: .badOTP, start: 100)
        XCTAssertThrowsError(try unknown.claim(name: Data("name".utf8), instruction: Data(), prompts: [], echo: [], now: 101))
        XCTAssertEqual(unknown.managementReads, 0)
        var crossed = try SFTPOTPNegativeBudget(testCase: .badOTP, start: 100)
        _ = try crossed.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: 0)], echo: [false], now: 101)
        try crossed.recordRead(index: 0, expiry: 175, wall: 101, uptime: 101)
        try crossed.consume(index: 0, wall: 102, uptime: 102); try crossed.resolved(true)
        XCTAssertThrowsError(try crossed.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: String(repeating: "f", count: 24), index: 1)], echo: [false], now: 103))
        var cancelled = try prepared(.expiredOTP)
        cancelled.fail(.cancelled)
        XCTAssertThrowsError(try cancelled.expiryReached(wall: 176, uptime: 176))
        XCTAssertThrowsError(try cancelled.consume(index: 2, wall: 176, uptime: 176))
        var replay = try prepared(.badOTP)
        let original = Data("01234567".utf8), wrong = try SFTPOTPNegativeBudget.mutateOneDigit(original)
        try replay.recordWrongC(original: original, wrong: wrong)
        try replay.consume(index: 2, wall: 105, uptime: 105); try replay.resolved(true)
        XCTAssertThrowsError(try replay.consume(index: 2, wall: 106, uptime: 106))
        XCTAssertEqual(replay.replies, 3); XCTAssertEqual(replay.managementReads, 3)
        let tooLate = try prepared(.expiredOTP)
        XCTAssertThrowsError(try tooLate.expiryReached(wall: 201, uptime: 201))
    }
    func testOnlyTypedAuthenticationAndThreeSubmittedSecretsCanPassClassification() throws {
        XCTAssertTrue(SFTPOTPNegativeBudget.isTypedAuthentication(kind: "authentication", operation: "authenticate", code: nil))
        for tuple: (String, String, Int64?) in [("timeout", "authenticate", -10002), ("cancelled", "authenticate", -10001),
            ("transport", "authenticate", -43), ("authentication", "handshake", nil), ("authentication", "authenticate", -18)] {
            XCTAssertFalse(SFTPOTPNegativeBudget.isTypedAuthentication(kind: tuple.0, operation: tuple.1, code: tuple.2))
        }
        let beforeC = try prepared(.expiredOTP)
        XCTAssertThrowsError(try beforeC.requireInjected())
        let report = SFTPOTPNegativeReport(testCase: .badOTP)
        XCTAssertEqual(report.actualSFTPConnects, 0); XCTAssertEqual(report.fileOperations, 0); XCTAssertEqual(report.result, "failed")
        let bytes = try JSONEncoder().encode(report), text = String(decoding: bytes, as: UTF8.self)
        XCTAssertFalse(text.contains("responseHash")); XCTAssertFalse(text.contains("answer"))
    }
    func testWrongEchoCountHeadersAndPostInjectionNotificationRemainRefused() throws {
        let first = try SFTPAuthBudget.prompt(session: session, index: 0)
        for tuple in [(Data(), Data(), [first], [true]), (Data(), Data("information".utf8), [], []),
                      (Data(), Data(), [first, first], [false, false]), (Data(), Data(), [], [])] {
            var budget = try SFTPOTPNegativeBudget(testCase: .badOTP, start: 100)
            XCTAssertThrowsError(try budget.claim(name: tuple.0, instruction: tuple.1, prompts: tuple.2, echo: tuple.3, now: 101))
            XCTAssertEqual(budget.managementReads, 0); XCTAssertEqual(budget.replies, 0)
        }
        var injected = try prepared(.badOTP)
        let original = Data("01234567".utf8), wrong = try SFTPOTPNegativeBudget.mutateOneDigit(original)
        try injected.recordWrongC(original: original, wrong: wrong)
        try injected.consume(index: 2, wall: 105, uptime: 105); try injected.resolved(true)
        XCTAssertNoThrow(try injected.requireInjected())
        XCTAssertThrowsError(try injected.claim(name: Data(), instruction: Data("information".utf8), prompts: [], echo: [], now: 106))
        XCTAssertEqual(injected.replies, 3); XCTAssertEqual(injected.managementReads, 3)
        XCTAssertEqual(injected.failure, .unknownChallenge); XCTAssertThrowsError(try injected.requireInjected())
    }
    func testExpiresMetadataDoesNotRelaxExistingReaderExpiryGate() throws {
        let data = try JSONSerialization.data(withJSONObject: ["session": session, "index": 2, "expires_at": 175.0, "response": "01234567"])
        let value = try OpenSSHOTP.decode(data, session: session, index: 2, now: 104)
        XCTAssertEqual(value.expiresAt, 175); XCTAssertEqual(value.value.count, 8)
        XCTAssertThrowsError(try OpenSSHOTP.decode(data, session: session, index: 2, now: 175))
        XCTAssertEqual(String(reflecting: value), "<redacted root fixture response>")
    }
}
