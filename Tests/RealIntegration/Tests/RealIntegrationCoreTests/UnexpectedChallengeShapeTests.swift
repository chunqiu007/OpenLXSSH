import Foundation
import XCTest
@testable import RealIntegrationCore

final class UnexpectedChallengeShapeTests: XCTestCase {
    func testOnlyLengthsDigestsAndEchoAreEncodedNeverRawFields() throws {
        let name = Data("synthetic-private-name".utf8), instruction = Data("synthetic-private-instruction".utf8)
        let prompt = Data("synthetic-private-prompt".utf8)
        let shape = UnexpectedChallengeShape(ordinal: 4, name: name, instruction: instruction, prompts: [prompt], echo: [false])
        XCTAssertEqual(shape.callbackOrdinal, 4); XCTAssertEqual(shape.nameField.byteCount, name.count)
        XCTAssertEqual(shape.nameField.sha256, PrivateInput.sha256(name))
        XCTAssertEqual(shape.instructionField.sha256, PrivateInput.sha256(instruction))
        XCTAssertEqual(shape.prompts[0].field.sha256, PrivateInput.sha256(prompt))
        XCTAssertFalse(shape.truncated); XCTAssertFalse(shape.invalid)
        let encoded = try JSONEncoder().encode(shape), text = String(decoding: encoded, as: UTF8.self)
        for raw in [name, instruction, prompt] { XCTAssertFalse(text.contains(String(decoding: raw, as: UTF8.self))) }
        let object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        XCTAssertEqual(Set(object.keys), ["callbackOrdinal", "nameField", "instructionField", "promptCount", "prompts", "truncated", "invalid"])
    }
    func testNativeBoundsMarkTruncationWithoutUnboundedOutput() throws {
        let oversized = Data(repeating: 65, count: 65537)
        let shape = UnexpectedChallengeShape(ordinal: 4, name: oversized, instruction: Data(),
            prompts: Array(repeating: oversized, count: 33), echo: Array(repeating: false, count: 33))
        XCTAssertEqual(shape.promptCount, 33); XCTAssertEqual(shape.prompts.count, 32)
        XCTAssertTrue(shape.truncated); XCTAssertTrue(shape.invalid)
        XCTAssertNil(shape.nameField.sha256); XCTAssertTrue(shape.prompts.allSatisfy { $0.field.sha256 == nil })
        XCTAssertLessThan(try JSONEncoder().encode(shape).count, 12000)
        let mismatch = UnexpectedChallengeShape(ordinal: 0, name: Data(), instruction: Data(), prompts: [Data()], echo: [])
        XCTAssertTrue(mismatch.invalid)
    }
    func testOnlyProvenFourthZeroSequenceAcceptsTailAndFifthRemainsDiagnosed() throws {
        var budget = try SFTPAuthBudget(mfa: true, start: 100)
        let session = "0123456789abcdef01234567"
        for index in 0..<3 {
            let phase = try budget.claim(name: Data(), instruction: Data(), prompts: [SFTPAuthBudget.prompt(session: session, index: index)], echo: [false], now: Double(101 + index))
            try budget.consume(phase: phase, now: Double(102 + index)); budget.resolved(true)
        }
        let terminal = try budget.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 110)
        XCTAssertEqual(terminal, .terminalZero)
        try budget.consume(phase: terminal, now: 111); budget.resolved(true)
        XCTAssertEqual(budget.callbacks, 4); XCTAssertEqual(budget.replies, 4)
        XCTAssertEqual(budget.secretResponses, 3); XCTAssertEqual(budget.terminalZeroReplies, 1); XCTAssertEqual(budget.managementReads, 3)
        XCTAssertNoThrow(try budget.requireComplete())
        XCTAssertThrowsError(try budget.claim(name: Data(), instruction: Data(), prompts: [], echo: [], now: 112)) {
            XCTAssertEqual($0 as? SFTPAuthError, .unknownChallenge)
        }
        let shape = UnexpectedChallengeShape(ordinal: budget.callbacks, name: Data(), instruction: Data(), prompts: [], echo: [])
        XCTAssertEqual(shape.callbackOrdinal, 5); XCTAssertEqual(shape.promptCount, 0)
        XCTAssertEqual(shape.nameField.sha256, PrivateInput.sha256(Data()))
        XCTAssertEqual(budget.failure, .unknownChallenge); XCTAssertThrowsError(try budget.requireComplete())
        XCTAssertEqual(budget.secretResponses, 3); XCTAssertEqual(budget.terminalZeroReplies, 1); XCTAssertEqual(budget.managementReads, 3)
    }
}
