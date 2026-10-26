import Foundation
import XCTest
@testable import RealIntegrationCore

final class OpenSSHTests: XCTestCase {
    let session = "0123456789abcdef01234567"
    let primaryPrompt = "exact independently reviewed broker request"
    func contract(service: OpenSSHService = .keyonly, key: OpenSSHKey = .edplain, testCase: OpenSSHCase = .positive, changes: [String: Any] = [:]) throws -> OpenSSHContract {
        let primary: OpenSSHPrimary = service.usesKey ? (key.encrypted ? .keyPassphrase : .none) : .password
        var value: [String: Any] = ["schema": 1, "taskID": "OPENSSH-FOUR-AUTH-A", "testCase": testCase.rawValue, "service": service.rawValue,
            "host": "127.0.0.1", "port": service.port, "user": "fixture", "key": key.rawValue, "primary": primary.rawValue,
            "primaryPromptSHA256": primary == .none ? NSNull() : PrivateInput.sha256(Data(primaryPrompt.utf8)) as Any,
            "credentialDirectory": "/fixture/.runtime/" + service.rawValue + "/credentials-012345abcdef",
            "expectedFingerprint": "SHA256:" + Data(repeating: 1, count: 32).base64EncodedString().dropLast(),
            "baseImage": MinaContract.base, "imageID": "sha256:" + String(repeating: "a", count: 64), "containerID": String(repeating: "b", count: 64),
            "project": "openlxssh-fixture-012345abcdef", "networkID": String(repeating: "c", count: 64), "context": "desktop-linux",
            "endpoint": "unix:///Users/test/.docker/run/docker.sock"]
        changes.forEach { value[$0.key] = $0.value }
        return try JSONDecoder().decode(OpenSSHContract.self, from: JSONSerialization.data(withJSONObject: value))
    }
    func testIndependentParsingAndFixedFourFlowContract() throws {
        XCTAssertEqual(try OpenSSHOptions.parse([]).action, .help)
        XCTAssertEqual(try OpenSSHOptions.parse(["validate", "--contract", "/not/a/file/openssh-auth.json"]).action, .validate)
        XCTAssertThrowsError(try OpenSSHOptions.parse(["--live", "--contract", "/not/a/file/openssh-auth.json"]))
        XCTAssertThrowsError(try Options.parse(["--openssh-auth"]))
        XCTAssertThrowsError(try MinaOptions.parse(["--openssh-auth"]))
        XCTAssertThrowsError(try OpenSSHInput.load(path: "/etc/passwd", buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        let path = "/build/openssh-case-012345abcdef/openssh-auth.json"
        for service in [OpenSSHService.keyonly, .passwordonly, .keyKbd, .passwordKbd] {
            let value = try contract(service: service, key: service.usesKey ? .edplain : .none)
            XCTAssertNoThrow(try value.validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        }
        for key in [OpenSSHKey.edplain, .edencrypted, .rsaplain, .rsaencrypted] {
            XCTAssertNoThrow(try contract(key: key).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        }
        for change: [String: Any] in [["host": "localhost"], ["host": "192.0.2.1"], ["port": 22225], ["user": "root"], ["endpoint": "tcp://127.0.0.1:2375"],
            ["containerID": "short"], ["project": "openlxssh-mina-012345abcdef"], ["credentialDirectory": "/fixture/.runtime/keyonly/credentials-latest"]] {
            XCTAssertThrowsError(try contract(changes: change).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        }
        XCTAssertThrowsError(try contract(service: .passwordonly, key: .none, changes: ["primaryPromptSHA256": NSNull()]).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        XCTAssertNoThrow(try contract(service: .passwordonly, key: .none, testCase: .observeChallenge, changes: ["primaryPromptSHA256": NSNull()]).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
    }
    func testExplicitPrimaryAndOrderedSameIDThreeRounds() throws {
        for service in [OpenSSHService.keyonly, .passwordonly, .keyKbd, .passwordKbd] {
            let primary: OpenSSHPrimary = service.usesKey ? .none : .password
            var budget = try OpenSSHAnswerBudget(service: service, primary: primary, primaryHash: primary == .none ? nil : PrivateInput.sha256(Data(primaryPrompt.utf8)), start: 100)
            if primary != .none {
                let request = UUID()
                XCTAssertEqual(try budget.claim(id: request, prompt: primaryPrompt, kind: "unknownMasked", hasHint: false, now: 101), .primary)
                try budget.consume(id: request, now: 102)
            }
            if service.mfa {
                for index in 0..<3 {
                    let request = UUID(), prompt = try OpenSSHAnswerBudget.otpPrompt(port: service.port, session: session, index: index)
                    XCTAssertEqual(try budget.claim(id: request, prompt: prompt, kind: "unknownMasked", hasHint: false, now: Double(103 + index)), .otp(session: session, index: index))
                    try budget.consume(id: request, now: Double(104 + index))
                }
            }
            XCTAssertNoThrow(try budget.requireComplete())
            XCTAssertEqual(budget.otpAnswers, service.mfa ? 3 : 0)
            XCTAssertThrowsError(try budget.claim(id: UUID(), prompt: primaryPrompt, kind: "unknownMasked", hasHint: false, now: 110))
        }
    }
    func testUnknownHintHashOrderCrossSessionReplayAndClosedFail() throws {
        let prompt = try OpenSSHAnswerBudget.otpPrompt(port: 22223, session: session, index: 0)
        for values in [("Password:", "unknownMasked", false), (primaryPrompt, "confirmation", false), (primaryPrompt, "unknownMasked", true)] {
            var budget = try OpenSSHAnswerBudget(service: .passwordonly, primary: .password, primaryHash: PrivateInput.sha256(Data(primaryPrompt.utf8)), start: 100)
            XCTAssertThrowsError(try budget.claim(id: UUID(), prompt: values.0, kind: values.1, hasHint: values.2, now: 101))
            XCTAssertEqual(budget.primaryAnswers, 0)
        }
        var budget = try OpenSSHAnswerBudget(service: .keyKbd, primary: .none, primaryHash: nil, start: 100)
        let id = UUID(); _ = try budget.claim(id: id, prompt: prompt, kind: "unknownMasked", hasHint: false, now: 101)
        XCTAssertThrowsError(try budget.claim(id: UUID(), prompt: prompt, kind: "unknownMasked", hasHint: false, now: 102))
        try budget.consume(id: id, now: 102)
        XCTAssertThrowsError(try budget.claim(id: id, prompt: prompt, kind: "unknownMasked", hasHint: false, now: 103))
        XCTAssertThrowsError(try budget.claim(id: UUID(), prompt: OpenSSHAnswerBudget.otpPrompt(port: 22223, session: String(repeating: "f", count: 24), index: 1), kind: "unknownMasked", hasHint: false, now: 103))
        budget.close(); XCTAssertThrowsError(try budget.consume(id: id, now: 104))
        var expired = try OpenSSHAnswerBudget(service: .keyKbd, primary: .none, primaryHash: nil, start: 100)
        XCTAssertThrowsError(try expired.claim(id: UUID(), prompt: prompt, kind: "unknownMasked", hasHint: false, now: 160))
    }
    func testCurrentIndexResponseSchemaTTLAndObservationNeverAnswers() throws {
        let value: [String: Any] = ["session": session, "index": 1, "expires_at": 150.0, "response": "01234567"]
        let data = try JSONSerialization.data(withJSONObject: value)
        let result = try OpenSSHOTP.decode(data, session: session, index: 1, now: 100)
        XCTAssertEqual(result.value.count, 8); XCTAssertEqual(String(reflecting: result), "<redacted root fixture response>")
        for changes: [String: Any] in [["session": String(repeating: "f", count: 24)], ["index": 0], ["expires_at": 100], ["expires_at": 176], ["response": "bad"], ["responses": []]] {
            var wrong = value; changes.forEach { wrong[$0.key] = $0.value }
            XCTAssertThrowsError(try OpenSSHOTP.decode(JSONSerialization.data(withJSONObject: wrong), session: session, index: 1, now: 100))
        }
        let observation = OpenSSHObservation(prompt: primaryPrompt, kind: "unknownMasked", hasHint: false, service: .passwordonly)
        XCTAssertEqual(observation.promptSHA256, PrivateInput.sha256(Data(primaryPrompt.utf8)))
        XCTAssertFalse(observation.matchesExpectedOTPEnvelope)
    }
    func testFixedRootReaderArgumentsAndBoundedBudgets() throws {
        let value = try contract(service: .keyKbd)
        let args = try OpenSSHManagementPolicy.arguments(contract: value, session: session, index: 2)
        XCTAssertEqual(Array(args.prefix(6)), ["--host", value.endpoint, "exec", "--user", "0:0", value.containerID])
        XCTAssertEqual(Array(args.suffix(3)), ["response", session, "2"])
        XCTAssertThrowsError(try OpenSSHManagementPolicy.arguments(contract: value, session: "../../secret", index: 0))
        XCTAssertThrowsError(try OpenSSHManagementPolicy.arguments(contract: value, session: session, index: 3))
        XCTAssertEqual(OpenSSHContract.activeSeconds, 60); XCTAssertEqual(OpenSSHContract.drainSeconds, 12)
        XCTAssertEqual(OpenSSHContract.scanSeconds, 15); XCTAssertEqual(OpenSSHContract.connectionSeconds, 20)
        XCTAssertEqual(OpenSSHContract.managementSeconds, 10)
    }
}
