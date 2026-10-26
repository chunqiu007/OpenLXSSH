import Foundation
import XCTest
@testable import RealIntegrationCore

final class SFTPTerminalZeroTests: XCTestCase {
    let session = "0123456789abcdef01234567"
    func prefix(_ count: Int = 3) throws -> SFTPAuthBudget {
        var budget = try SFTPAuthBudget(mfa: true, start: 100)
        for index in 0..<count {
            let phase = try budget.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: index)], echo: [false], now: Double(101 + index))
            try budget.consume(phase: phase, now: Double(102 + index)); budget.resolved(true)
        }
        return budget
    }
    func testEarlyZeroAtEverySecretPositionAndNonMFAZeroRefuse() throws {
        for completed in 0..<3 {
            var budget = try prefix(completed)
            XCTAssertThrowsError(try budget.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 110))
            XCTAssertEqual(budget.secretResponses, completed); XCTAssertEqual(budget.managementReads, completed)
            XCTAssertEqual(budget.terminalZeroReplies, 0); XCTAssertThrowsError(try budget.requireComplete())
        }
        var single = try SFTPAuthBudget(mfa: false, start: 100)
        XCTAssertThrowsError(try single.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 101))
        XCTAssertEqual(single.replies, 0); XCTAssertEqual(single.managementReads, 0)
    }
    func testExactTailDoesNotPermitHeaderEchoOrAnyFourthPrompt() throws {
        for tuple in [(Data("header".utf8), Data(), [Data](), [Bool]()),
                      (Data(), Data("instruction".utf8), [Data](), [Bool]()),
                      (Data(), Data(), [Data](), [false]),
                      (Data(), Data(), [Data()], [false]),
                      (Data(), Data(), [try SFTPAuthBudget.prompt(session: session, index: 2)], [false]),
                      (Data(repeating: 65, count: 65537), Data(), [Data](), [Bool]()),
                      (Data(), Data(), Array(repeating: Data(), count: 33), Array(repeating: false, count: 33))] {
            var budget = try prefix()
            XCTAssertThrowsError(try budget.claim(name: tuple.0, instruction: tuple.1, prompts: tuple.2, echo: tuple.3, now: 110))
            XCTAssertEqual(budget.secretResponses, 3); XCTAssertEqual(budget.managementReads, 3)
            XCTAssertEqual(budget.terminalZeroReplies, 0); XCTAssertThrowsError(try budget.requireComplete())
        }
    }
    func testUnresolvedThirdCannotClaimZeroAndCrossSessionCannotReachTail() throws {
        var budget = try prefix(2)
        let third = try budget.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: 2)], echo: [false], now: 106)
        try budget.consume(phase: third, now: 107) // Deliberately no successful resolve.
        XCTAssertThrowsError(try budget.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 108))
        XCTAssertEqual(budget.terminalZeroReplies, 0)
        var crossed = try prefix(2)
        XCTAssertThrowsError(try crossed.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: String(repeating: "f", count: 24), index: 2)], echo: [false], now: 106))
        XCTAssertThrowsError(try crossed.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 108))
        XCTAssertEqual(crossed.secretResponses, 2); XCTAssertEqual(crossed.managementReads, 2)
    }
    func testTerminalConsumeReplayClosedDeadlineAndFalseResolveRefuse() throws {
        var replay = try prefix()
        let terminal = try replay.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 110)
        try replay.consume(phase: terminal, now: 111); replay.resolved(true)
        XCTAssertNoThrow(try replay.requireComplete())
        XCTAssertThrowsError(try replay.consume(phase: terminal, now: 112))
        XCTAssertEqual(replay.replies, 4); XCTAssertEqual(replay.terminalZeroReplies, 1)
        var closed = try prefix()
        let closedTail = try closed.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 110)
        closed.close(); XCTAssertThrowsError(try closed.consume(phase: closedTail, now: 111))
        XCTAssertEqual(closed.terminalZeroReplies, 0)
        var deadline = try prefix()
        XCTAssertThrowsError(try deadline.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 145))
        XCTAssertEqual(deadline.terminalZeroReplies, 0)
        var lateConsume = try prefix()
        let lateTail = try lateConsume.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 144)
        XCTAssertThrowsError(try lateConsume.consume(phase: lateTail, now: 145))
        var refused = try prefix()
        let refusedTail = try refused.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 110)
        try refused.consume(phase: refusedTail, now: 111); refused.resolved(false)
        XCTAssertThrowsError(try refused.requireResolutionAccepted())
        XCTAssertThrowsError(try refused.requireComplete()); XCTAssertEqual(refused.managementReads, 3)
    }
    func testTypedPhaseAndReportCountersNeverClaimAuthenticationSuccess() throws {
        var budget = try prefix()
        XCTAssertThrowsError(try budget.requireComplete())
        let tail = try budget.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 110)
        XCTAssertEqual(tail, .terminalZero)
        try budget.consume(phase: tail, now: 111); budget.resolved(true)
        XCTAssertNoThrow(try budget.requireComplete())
        let value = SFTPAuthContract(schema: 1, taskID: "REAL-SFTP-COMBINED-AUTH-A", service: .keyKbd, host: "127.0.0.1", port: 22223,
            user: "fixture", key: .edplain, credentialDirectory: "/synthetic", expectedFingerprint: "synthetic", baseImage: "synthetic",
            imageID: "synthetic", containerID: "synthetic", project: "synthetic", networkID: "synthetic", context: "synthetic", endpoint: "synthetic")
        var report = SFTPAuthReport(contract: value); report.record(budget)
        XCTAssertEqual(report.replyCount, 4); XCTAssertEqual(report.secretResponseCount, 3); XCTAssertEqual(report.terminalZeroReplyCount, 1)
        XCTAssertEqual(report.managementResponseReads, 3); XCTAssertEqual(report.authenticatedSFTPConnects, 0)
        XCTAssertEqual(report.result, "failed"); XCTAssertFalse(report.hashMatched); XCTAssertFalse(report.closeCompleted)
    }
}
