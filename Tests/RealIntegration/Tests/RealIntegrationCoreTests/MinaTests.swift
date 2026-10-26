import Foundation
import XCTest
@testable import RealIntegrationCore

final class MinaTests: XCTestCase {
    let attempt = "0123456789abcdef01234567"
    func envelope(_ testCase: MinaCase) -> (Data, Data, [Data], [Bool]) {
        let suffix = testCase == .twoCorrect ? "; enter the two independent test responses."
            : "; no input prompts. " + testCase.scenario + "; cancellation closes this connection."
        return (Data(("OpenLXSSH fixture " + attempt).utf8), Data(("Disposable test only; attempt " + attempt + suffix).utf8),
                testCase == .twoCorrect ? [Data("Test response A: ".utf8), Data("Unclassified test response B: ".utf8)] : [],
                testCase == .twoCorrect ? [false, true] : [])
    }
    func status(generated: Int = 0, callbacks: Int = 0, zero: Int = 0, late: Int = 0, sessions: Int = 0, queue: Int = 0,
                outcomes: [String: Int] = [:]) throws -> MinaStatus {
        try MinaStatus.decode(JSONSerialization.data(withJSONObject: ["generated": generated, "response_callbacks": callbacks,
            "zero_response_callbacks": zero, "ignored_late_results": late, "sessions": sessions, "scheduler_queue": queue,
            "pending": [], "outcomes": outcomes]))
    }
    func contract(_ changes: [String: Any] = [:]) throws -> MinaContract {
        var object: [String: Any] = ["schema": 1, "taskID": "AUTH-MINA-PRODUCTION-KBI-A", "testCase": "two-correct",
            "service": "multiprompt", "fixtureLabel": "auth-mina-fixture-a", "host": "127.0.0.1", "port": 22225, "user": "fixture",
            "context": "desktop-linux", "endpoint": "unix:///Users/test/.docker/run/docker.sock", "containerID": String(repeating: "a", count: 64),
            "imageID": "sha256:" + String(repeating: "b", count: 64), "project": "openlxssh-mina-012345abcdef",
            "networkID": String(repeating: "c", count: 64), "sourceSHA256": String(repeating: "d", count: 64),
            "baseImage": MinaContract.base, "trustDirectory": "/fixture/multiprompt/.runtime/trust-012345abcdef",
            "expectedFingerprint": "SHA256:" + Data(repeating: 1, count: 32).base64EncodedString().dropLast()]
        changes.forEach { object[$0.key] = $0.value }
        return try JSONDecoder().decode(MinaContract.self, from: JSONSerialization.data(withJSONObject: object))
    }
    func testSeparateOptionsAreInertAndOriginalContractStaysClosed() throws {
        XCTAssertEqual(try MinaOptions.parse([]).action, .help)
        XCTAssertEqual(try MinaOptions.parse(["validate", "--contract", "/missing/auth-only.json"]).action, .validate)
        for args in [["--live", "--contract", "/missing/auth-only.json"],
                     ["--live", "--authorized-local-fixture", "--contract", "/missing/auth-only.json"]] {
            XCTAssertThrowsError(try MinaOptions.parse(args)) { XCTAssertEqual($0 as? SmokeError, .authorizationRequired) }
        }
        XCTAssertThrowsError(try Options.parse(["--auth-only"]))
        XCTAssertThrowsError(try MinaOptions.parse(["--host", "127.0.0.1"]))
        XCTAssertThrowsError(try MinaOptions.parse(["validate", "--contract", "/missing/real-integration.json"]))
        XCTAssertThrowsError(try MinaInput.load(path: "/etc/passwd", buildRoot: "/build", fixtureRoot: "/fixture/multiprompt", home: "/Users/test")) { XCTAssertEqual($0 as? MinaError, .invalidContract) }
    }
    func testFixedEndpointIdentityAndExactGeneration() throws {
        let path = "/build/mina-case-012345abcdef/auth-only.json"
        let valid = try contract()
        XCTAssertNoThrow(try valid.validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture/multiprompt", home: "/Users/test"))
        for change: [String: Any] in [["host": "localhost"], ["host": "192.0.2.1"], ["port": 22224], ["user": "root"],
            ["endpoint": "tcp://127.0.0.1:2375"], ["endpoint": "unix:///another/docker.sock"], ["service": "keyonly"],
            ["containerID": "short"], ["project": "openlxssh-fixture-012345abcdef"], ["trustDirectory": "/fixture/multiprompt/.runtime/trust-latest"]] {
            XCTAssertThrowsError(try contract(change).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture/multiprompt", home: "/Users/test"))
        }
        XCTAssertThrowsError(try valid.validate(path: "/build/mina-case-latest/auth-only.json", buildRoot: "/build", fixtureRoot: "/fixture/multiprompt", home: "/Users/test"))
        XCTAssertThrowsError(try contract(["testCase": "timeout"]))
        XCTAssertEqual(try contract(["testCase": "approval"]).testCase, .approval)
        XCTAssertEqual(try contract(["testCase": "reject"]).testCase, .reject)
        XCTAssertEqual(try contract(["testCase": "cancel-wait"]).testCase, .cancelWait)
        XCTAssertEqual(MinaContract.connectionSeconds, 20); XCTAssertEqual(MinaContract.operationSeconds, 20)
        XCTAssertEqual(MinaContract.caseSeconds, 30); XCTAssertEqual(MinaContract.managementSeconds, 10); XCTAssertEqual(MinaContract.drainSeconds, 12)
    }
    func testExactTwoAndZeroCallbackBudget() throws {
        for testCase in [MinaCase.twoCorrect, .zeroAccept, .zeroReject] {
            var budget = try MinaCallbackBudget(testCase: testCase, start: 100)
            let (name, instruction, prompts, echo) = envelope(testCase)
            XCTAssertEqual(try budget.claim(name: name, instruction: instruction, prompts: prompts, echo: echo, now: 101), attempt)
            if testCase == .twoCorrect { try budget.claimManagementRead() }
            try budget.claimReply(responseCount: testCase.promptCount, now: 102); budget.resolved(true)
            XCTAssertNoThrow(try budget.requireComplete())
            XCTAssertEqual(budget.callbackCount, 1); XCTAssertEqual(budget.replyCount, 1)
            XCTAssertEqual(budget.responseCount, testCase.promptCount); XCTAssertEqual(budget.echoes, [echo])
            XCTAssertThrowsError(try budget.claim(name: name, instruction: instruction, prompts: prompts, echo: echo, now: 103))
            XCTAssertThrowsError(try budget.requireComplete())
        }
    }
    func testUnknownShapeCountEchoHeaderAndLateResponseFailClosed() throws {
        let (name, instruction, prompts, echo) = envelope(.twoCorrect)
        for pair in [(Data("Password:".utf8), instruction, prompts, echo), (name + Data([0]), instruction, prompts, echo),
                     (name, instruction + Data([32]), prompts, echo), (name, instruction, Array(prompts.reversed()), echo),
                     (name, instruction, [prompts[0]], [false]), (name, instruction, prompts, [true, false])] {
            var budget = try MinaCallbackBudget(testCase: .twoCorrect, start: 100)
            XCTAssertThrowsError(try budget.claim(name: pair.0, instruction: pair.1, prompts: pair.2, echo: pair.3, now: 101))
            XCTAssertEqual(budget.replyCount, 0); XCTAssertThrowsError(try budget.requireComplete())
        }
        var late = try MinaCallbackBudget(testCase: .twoCorrect, start: 100)
        _ = try late.claim(name: name, instruction: instruction, prompts: prompts, echo: echo, now: 101)
        try late.claimManagementRead()
        XCTAssertThrowsError(try late.claimManagementRead())
        var deadline = try MinaCallbackBudget(testCase: .twoCorrect, start: 100)
        _ = try deadline.claim(name: name, instruction: instruction, prompts: prompts, echo: echo, now: 101)
        try deadline.claimManagementRead()
        XCTAssertThrowsError(try deadline.claimReply(responseCount: 2, now: 130)) { XCTAssertEqual($0 as? MinaError, .lateReply) }
        XCTAssertEqual(deadline.replyCount, 0); XCTAssertEqual(deadline.lateReplyCount, 1)
        var closed = try MinaCallbackBudget(testCase: .zeroAccept, start: 100)
        let zero = envelope(.zeroAccept)
        _ = try closed.claim(name: zero.0, instruction: zero.1, prompts: zero.2, echo: zero.3, now: 101)
        closed.close(); XCTAssertThrowsError(try closed.claimReply(responseCount: 0, now: 102))
    }
    func testResponsesMemoryOnlySchemaTTLAndAttemptBinding() throws {
        // Offline synthetic bytes only, not fixture answers or a live run.
        let object: [String: Any] = ["attempt": attempt, "expires_at": 150, "responses": ["0123456789", "9876543210"], "echo": [false, true]]
        let data = try JSONSerialization.data(withJSONObject: object)
        let values = try MinaResponses.decode(data, attempt: attempt, now: 100)
        XCTAssertEqual(values.values.map { $0.count }, [10, 10])
        XCTAssertEqual(String(reflecting: values), "<redacted MINA responses>")
        for change: [String: Any] in [["attempt": String(repeating: "f", count: 24)], ["expires_at": 100], ["expires_at": 176],
                                     ["responses": ["one"]], ["echo": [true, false]], ["echo": [0, 1]], ["extra": "refuse"]] {
            var bad = object; change.forEach { bad[$0.key] = $0.value }
            XCTAssertThrowsError(try MinaResponses.decode(JSONSerialization.data(withJSONObject: bad), attempt: attempt, now: 100))
        }
    }
    func testExactBackendAndStatusConjunctionNeverGenericFailure() throws {
        XCTAssertEqual(MinaBackendObservation.classify(kind: "transport", operation: "sftp-init", code: -21), .authenticatedThenSFTPUnavailable)
        XCTAssertEqual(MinaBackendObservation.classify(kind: "authentication", operation: "authenticate", code: nil), .authenticationRejected)
        for tuple: (String, String, Int64?) in [("timeout", "sftp-init", -21), ("transport", "handshake", -21),
            ("transport", "sftp-init", -22), ("transport", "sftp-init", nil), ("authentication", "authenticate", -18)] {
            XCTAssertEqual(MinaBackendObservation.classify(kind: tuple.0, operation: tuple.1, code: tuple.2), .unexpectedFailure)
        }
        let before = try status()
        for testCase in [MinaCase.twoCorrect, .zeroAccept, .zeroReject] {
            let after = try status(generated: 1, callbacks: 1, zero: testCase == .twoCorrect ? 0 : 1,
                                   outcomes: [testCase == .zeroReject ? "rejected" : "accepted": 1])
            XCTAssertNoThrow(try after.requireExactDelta(from: before, testCase: testCase))
        }
        for bad in [try status(generated: 2, callbacks: 1, outcomes: ["accepted": 1]),
                    try status(generated: 1, callbacks: 0, outcomes: ["accepted": 1]),
                    try status(generated: 1, callbacks: 1, late: 1, outcomes: ["accepted": 1]),
                    try status(generated: 1, callbacks: 1, sessions: 1, outcomes: ["accepted": 1]),
                    try status(generated: 1, callbacks: 1, queue: 1, outcomes: ["accepted": 1]),
                    try status(generated: 1, callbacks: 1, outcomes: ["accepted": 1, "session-closed": 1])] {
            XCTAssertThrowsError(try bad.requireExactDelta(from: before, testCase: .twoCorrect))
        }
        XCTAssertThrowsError(try MinaBackendObservation.unexpectedSuccess.requireExpected(.twoCorrect))
        XCTAssertThrowsError(try MinaBackendObservation.authenticationRejected.requireExpected(.zeroAccept))
    }
    func testAsyncZeroEnvelopeAndNoAnswerAfterClosure() throws {
        for testCase in [MinaCase.approval, .reject, .cancelWait] {
            let values = envelope(testCase)
            var budget = try MinaCallbackBudget(testCase: testCase, start: 100)
            XCTAssertEqual(try budget.claim(name: values.0, instruction: values.1, prompts: values.2, echo: values.3, now: 101), attempt)
            try budget.claimReply(responseCount: 0, now: 102); budget.resolved(true)
            XCTAssertNoThrow(try budget.requireComplete())
            XCTAssertEqual(budget.managementReads, 0)
            budget.close()
            XCTAssertThrowsError(try budget.claimReply(responseCount: 0, now: 103))
            XCTAssertEqual(budget.replyCount, 1); XCTAssertEqual(budget.responseCount, 0)
            XCTAssertThrowsError(try budget.requireComplete())
        }
    }
    func testAsyncAcceptRejectRequireEightSecondsFromZeroResolve() throws {
        XCTAssertEqual(MinaContract.providerDelaySeconds, 8)
        XCTAssertEqual(MinaContract.cancelAfterReplySeconds, 1)
        XCTAssertEqual(MinaContract.operationSeconds, 20); XCTAssertEqual(MinaContract.caseSeconds, 30)
        for testCase in [MinaCase.approval, .reject] {
            var timing = MinaAsyncEvidence(); timing.recordPolicyVerified()
            try timing.recordReply(at: 100); try timing.recordBackend(at: 108)
            XCTAssertNoThrow(try timing.requireExpected(testCase))
            var fast = MinaAsyncEvidence(); fast.recordPolicyVerified()
            try fast.recordReply(at: 100); try fast.recordBackend(at: 107.999)
            XCTAssertThrowsError(try fast.requireExpected(testCase))
            var unverified = MinaAsyncEvidence()
            try unverified.recordReply(at: 100); try unverified.recordBackend(at: 110)
            XCTAssertThrowsError(try unverified.requireExpected(testCase))
            let before = try status()
            let after = try status(generated: 1, callbacks: 1, zero: 1, outcomes: [testCase.expectedOutcome: 1])
            XCTAssertNoThrow(try after.requireExactDelta(from: before, testCase: testCase))
        }
        XCTAssertNoThrow(try MinaBackendObservation.authenticatedThenSFTPUnavailable.requireExpected(.approval))
        XCTAssertNoThrow(try MinaBackendObservation.authenticationRejected.requireExpected(.reject))
        XCTAssertThrowsError(try MinaBackendObservation.authenticationRejected.requireExpected(.approval))
        XCTAssertThrowsError(try MinaBackendObservation.authenticatedThenSFTPUnavailable.requireExpected(.reject))
    }
    func testCancelRequiresRespondedExactAttemptThenLocalTokenAndPastDueStatus() throws {
        let before = try status()
        let pendingData = try JSONSerialization.data(withJSONObject: ["generated": 1, "response_callbacks": 1, "zero_response_callbacks": 1,
            "ignored_late_results": 0, "sessions": 1, "scheduler_queue": 2,
            "pending": [["attempt": attempt, "scenario": "cancel", "prompt_count": 0, "responded": true, "expires_at": 175]], "outcomes": [:]] as [String: Any])
        let pending = try MinaStatus.decode(pendingData)
        XCTAssertNoThrow(try pending.requireRespondedCancellation(attempt: attempt, before: before))
        XCTAssertThrowsError(try pending.requireRespondedCancellation(attempt: String(repeating: "f", count: 24), before: before))
        var timing = MinaAsyncEvidence(); timing.recordPolicyVerified(); try timing.recordReply(at: 100)
        XCTAssertThrowsError(try timing.recordCancellation(at: 101))
        try timing.recordPending(pending, before: before, attempt: attempt, now: 100.5)
        XCTAssertThrowsError(try timing.recordCancellation(at: 100.999))
        try timing.recordCancellation(at: 101)
        try timing.recordBackend(at: 101.1)
        XCTAssertThrowsError(try timing.recordPostDecisionStatus(at: 108.499))
        XCTAssertThrowsError(try timing.requireExpected(.cancelWait))
        try timing.recordPostDecisionStatus(at: 108.5)
        XCTAssertNoThrow(try timing.requireExpected(.cancelWait))
        var tooLate = MinaAsyncEvidence(); tooLate.recordPolicyVerified(); try tooLate.recordReply(at: 100)
        try tooLate.recordPending(pending, before: before, attempt: attempt, now: 101)
        XCTAssertThrowsError(try tooLate.recordCancellation(at: 108))
        let after = try status(generated: 1, callbacks: 1, zero: 1, outcomes: ["session-closed": 1])
        XCTAssertNoThrow(try after.requireExactDelta(from: before, testCase: .cancelWait))
        let approved = try status(generated: 1, callbacks: 1, zero: 1, outcomes: ["session-closed": 1, "approved": 1])
        XCTAssertThrowsError(try approved.requireExactDelta(from: before, testCase: .cancelWait))
        XCTAssertEqual(MinaBackendObservation.classify(kind: "cancelled", operation: "authenticate", code: -10001), .authenticationCancelled)
        XCTAssertNoThrow(try MinaBackendObservation.authenticationCancelled.requireExpected(.cancelWait))
        for tuple: (String, String, Int64?) in [("transport", "authenticate", -10001), ("cancelled", "handshake", -10001),
            ("cancelled", "authenticate", nil), ("timeout", "authenticate", -10002)] {
            XCTAssertEqual(MinaBackendObservation.classify(kind: tuple.0, operation: tuple.1, code: tuple.2), .unexpectedFailure)
        }
    }
    func testFixedAsyncProviderPolicyRefusesWrongDelayOrScenario() throws {
        for testCase in [MinaCase.approval, .reject, .cancelWait] {
            XCTAssertNoThrow(try MinaManagementPolicy.validatePolicy(JSONSerialization.data(withJSONObject: ["scenario": testCase.scenario, "delay": 8]), testCase: testCase))
            XCTAssertThrowsError(try MinaManagementPolicy.validatePolicy(JSONSerialization.data(withJSONObject: ["scenario": testCase.scenario, "delay": 60]), testCase: testCase))
            XCTAssertThrowsError(try MinaManagementPolicy.validatePolicy(JSONSerialization.data(withJSONObject: ["scenario": "timeout", "delay": 8]), testCase: testCase))
        }
    }
    func testManagementHasFixedCommandAndNeverArbitraryAttemptPath() throws {
        let contract = try contract()
        let args = try MinaManagementPolicy.readerArguments(contract: contract, attempt: attempt)
        XCTAssertEqual(Array(args.prefix(6)), ["--host", contract.endpoint, "exec", "--user", "10000:10000", contract.containerID])
        XCTAssertEqual(Array(args.suffix(2)), ["responses", attempt])
        XCTAssertThrowsError(try MinaManagementPolicy.readerArguments(contract: contract, attempt: "../../secret"))
        XCTAssertEqual(Array(try MinaManagementPolicy.readerArguments(contract: contract, attempt: nil).suffix(2)), ["status", "none"])
        XCTAssertThrowsError(try MinaManagementPolicy.validateContainer(Data("[]".utf8), contract: contract))
        XCTAssertThrowsError(try MinaManagementPolicy.validateImage(Data("[]".utf8), contract: contract))
        XCTAssertThrowsError(try MinaManagementPolicy.validateNetwork(Data("[]".utf8), contract: contract))
    }
}
