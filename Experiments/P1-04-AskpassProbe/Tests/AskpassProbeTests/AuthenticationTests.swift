import XCTest
@testable import OpenLXSSHAskpassProbe

final class AuthenticationTests: XCTestCase {
    func grant(_ generation: UInt64 = 1) -> SessionGrant { SessionGrant(generation: generation, nonce: String(repeating: "a", count: 64)) }
    func testUnrecognisedHintsNeverIdentifyAuthenticationMethod() {
        XCTAssertEqual(ChallengeKind(hint: nil), .unknownMasked)
        XCTAssertEqual(ChallengeKind(hint: "password"), .unknownMasked)
        XCTAssertEqual(ChallengeKind(hint: "confirm"), .confirmation)
        XCTAssertEqual(ChallengeKind(hint: "none"), .notification)
    }
    func testManualAnswerByteBoundaryAndForbiddenDelimiters() throws {
        try Limits.validateAnswer(Data())
        try Limits.validateAnswer(Data(repeating: 65, count: 1023))
        for bytes in [Data([0]), Data([10]), Data([13]), Data(repeating: 65, count: 1024)] {
            XCTAssertThrowsError(try Limits.validateAnswer(bytes)) { XCTAssertEqual($0 as? ProbeError, .bounds) }
        }
    }
    func testOnceOnlyRequestID() throws {
        let grant = grant(); var state = AuthenticationState(grant: grant, now: 0)
        let request = Request(grant: grant, prompt: "fixture", hint: nil)
        try state.begin(request, now: 0)
        try state.finish(request.id, generation: grant.generation, now: 1)
        XCTAssertThrowsError(try state.begin(request, now: 1)) { XCTAssertEqual($0 as? ProbeError, .replay) }
    }
    func testCrossSessionGenerationAndNonceRejected() {
        let original = grant()
        let wrong = [SessionGrant(generation: 1, nonce: original.nonce),
                     SessionGrant(session: original.session, generation: 2, nonce: original.nonce),
                     SessionGrant(session: original.session, generation: 1, nonce: "wrong")]
        for grant in wrong {
            var state = AuthenticationState(grant: original, now: 0)
            XCTAssertThrowsError(try state.begin(Request(grant: grant, prompt: "fixture", hint: nil), now: 0)) { XCTAssertEqual($0 as? ProbeError, .stale) }
            XCTAssertEqual(state.phase, .active)
        }
    }
    func testConcurrentRequestsRejected() throws {
        let grant = grant(); var state = AuthenticationState(grant: grant, now: 0)
        try state.begin(Request(grant: grant, prompt: "first", hint: nil), now: 0)
        XCTAssertThrowsError(try state.begin(Request(grant: grant, prompt: "second", hint: nil), now: 1)) { XCTAssertEqual($0 as? ProbeError, .stale) }
    }
    func testCancelRevokesLateAnswerAndNewRequest() throws {
        let grant = grant(); var state = AuthenticationState(grant: grant, now: 0)
        let request = Request(grant: grant, prompt: "fixture", hint: nil)
        try state.begin(request, now: 0); state.close(.cancelled)
        XCTAssertThrowsError(try state.finish(request.id, generation: 1, now: 1))
        XCTAssertThrowsError(try state.begin(Request(grant: grant, prompt: "late", hint: nil), now: 1))
        XCTAssertThrowsError(try state.begin(Request(grant: grant, prompt: "later than expiry", hint: nil), now: Limits.sessionSeconds + 1))
        XCTAssertEqual(state.phase, .closed(.cancelled))
    }
    func testRequestTimeoutIncludesBoundary() throws {
        let grant = grant(); var state = AuthenticationState(grant: grant, now: 0)
        let request = Request(grant: grant, prompt: "fixture", hint: nil)
        try state.begin(request, now: 0)
        XCTAssertThrowsError(try state.finish(request.id, generation: 1, now: Limits.requestSeconds)) { XCTAssertEqual($0 as? ProbeError, .timeout) }
        XCTAssertEqual(state.phase, .closed(.timeout))
    }
    func testSessionTimeoutAndFiniteRequestBudget() throws {
        let grant = grant(); var state = AuthenticationState(grant: grant, now: 0)
        for _ in 0..<Limits.requestsPerSession {
            let request = Request(grant: grant, prompt: "fixture", hint: nil)
            try state.begin(request, now: 0); try state.finish(request.id, generation: 1, now: 0.1)
        }
        XCTAssertThrowsError(try state.begin(Request(grant: grant, prompt: "over budget", hint: nil), now: 1)) { XCTAssertEqual($0 as? ProbeError, .bounds) }
        var expired = AuthenticationState(grant: grant, now: 0)
        XCTAssertThrowsError(try expired.begin(Request(grant: grant, prompt: "expired", hint: nil), now: Limits.sessionSeconds)) { XCTAssertEqual($0 as? ProbeError, .timeout) }
    }
    func testPromptUTF8BoundNotCharacterCount() throws {
        let grant = grant(); var state = AuthenticationState(grant: grant, now: 0)
        XCTAssertThrowsError(try state.begin(Request(grant: grant, prompt: String(repeating: "界", count: 1366), hint: nil), now: 0)) { XCTAssertEqual($0 as? ProbeError, .bounds) }
        try state.begin(Request(grant: grant, prompt: "", hint: nil), now: 0)
    }
    func testExplicitConfirmNotificationAndManualPolicies() throws {
        let grant = grant()
        let confirmation = Request(grant: grant, prompt: "fixture", hint: "confirm")
        XCTAssertThrowsError(try Reply(request: confirmation, decision: .manual(Data())))
        XCTAssertEqual(try Reply(request: confirmation, decision: .confirm(false)).action, "decline")
        let notification = Request(grant: grant, prompt: "fixture", hint: "none")
        XCTAssertThrowsError(try Reply(request: notification, decision: .manual(Data())))
        XCTAssertEqual(try Reply(request: notification, decision: .acknowledge).action, "notice")
        let unknown = Request(grant: grant, prompt: "Password: unrelated display text", hint: nil)
        XCTAssertThrowsError(try Reply(request: unknown, decision: .confirm(true)))
        XCTAssertEqual(try Reply(request: unknown, decision: .manual(Data())).action, "answer")
    }
    func testWrongGenerationCannotCompletePendingRequest() throws {
        let grant = grant(); var state = AuthenticationState(grant: grant, now: 0)
        let request = Request(grant: grant, prompt: "fixture", hint: nil)
        try state.begin(request, now: 0)
        XCTAssertThrowsError(try state.finish(request.id, generation: 2, now: 1)) { XCTAssertEqual($0 as? ProbeError, .stale) }
        XCTAssertEqual(state.phase, .waiting(request.id))
    }
    func testNotificationAndConfirmationPreserveEmptyStdout() throws {
        let grant = grant()
        let confirmation = try Reply(request: Request(grant: grant, prompt: "fixture", hint: "confirm"), decision: .confirm(true))
        let notification = try Reply(request: Request(grant: grant, prompt: "fixture", hint: "none"), decision: .acknowledge)
        XCTAssertNil(confirmation.answer); XCTAssertNil(notification.answer)
    }
    func testHintSizeAndNULPromptRejected() {
        let grant = grant()
        for request in [Request(grant: grant, prompt: "display\0text", hint: nil),
                        Request(grant: grant, prompt: "fixture", hint: String(repeating: "a", count: 65))] {
            var state = AuthenticationState(grant: grant, now: 0)
            XCTAssertThrowsError(try state.begin(request, now: 0)) { XCTAssertEqual($0 as? ProbeError, .bounds) }
            XCTAssertEqual(state.phase, .active)
        }
    }
    func testMachEnvelopeUsesUTF8BytesAndRetainsProtocolBounds() throws {
        let grant = grant()
        let request = Request(grant: grant, prompt: String(repeating: "界", count: 1365), hint: "unrecognised")
        let bytes = try JSONEncoder().encode(request)
        XCTAssertLessThanOrEqual(bytes.count, Limits.frameBytes)
        let decoded = try JSONDecoder().decode(Request.self, from: bytes)
        XCTAssertEqual(decoded, request)
        XCTAssertEqual(decoded.kind, .unknownMasked)
    }
    func testRequestIDCannotCompleteAnotherPendingChallenge() throws {
        let grant = grant(); var state = AuthenticationState(grant: grant, now: 0)
        let request = Request(grant: grant, prompt: "fixture", hint: nil)
        try state.begin(request, now: 0)
        XCTAssertThrowsError(try state.finish(UUID(), generation: grant.generation, now: 1)) { XCTAssertEqual($0 as? ProbeError, .stale) }
        XCTAssertEqual(state.phase, .waiting(request.id))
    }
    func testNewGenerationHasIndependentState() throws {
        let first = grant(); let second = SessionGrant(session: first.session, generation: 2, nonce: first.nonce)
        var state = AuthenticationState(grant: second, now: 0)
        XCTAssertThrowsError(try state.begin(Request(grant: first, prompt: "stale", hint: nil), now: 0))
        try state.begin(Request(grant: second, prompt: "current", hint: nil), now: 0)
    }
}
