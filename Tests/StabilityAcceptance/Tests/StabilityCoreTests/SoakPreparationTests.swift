import XCTest
@testable import StabilityCore

@MainActor private final class PreparingSession: AcceptanceSession {
    var phase: SessionPhase = .pending
    var ownedPID: Int32?
    var authenticated = false
    var failure: StabilityError?
    var cancellationEligible: Bool { false }
    var connects = 0
    func connect() throws { connects += 1 }
    func cancel() { phase = .closing }
    func close() { phase = .closed; ownedPID = nil }
    func accept(_ pid: Int32) { phase = .connected; authenticated = true; ownedPID = pid }
}

final class SoakPreparationTests: XCTestCase {
    @MainActor func testNextConnectionWaitsForAuthenticatedOwner() async throws {
        var sessions: [PreparingSession] = []
        var waits = 0
        try await FiniteLifecycle.connectFiveSequentially(interruption: { nil }, make: {
            XCTAssertTrue(sessions.allSatisfy { $0.phase == .connected && $0.authenticated && $0.ownedPID != nil })
            let session = PreparingSession(); sessions.append(session); return session
        }, wait: {
            waits += 1
            sessions.last?.accept(Int32(70000 + sessions.count))
        })
        XCTAssertEqual(sessions.count, 5)
        XCTAssertEqual(waits, 5)
        XCTAssertTrue(sessions.allSatisfy { $0.connects == 1 })
    }

    @MainActor func testMissingAuthenticationOrPIDCannotAdvance() async {
        for missingAuthentication in [true, false] {
            let session = PreparingSession()
            session.phase = .connected
            session.authenticated = !missingAuthentication
            session.ownedPID = missingAuthentication ? 70001 : nil
            var makes = 0, waits = 0
            do {
                try await FiniteLifecycle.connectFiveSequentially(interruption: { nil }, make: {
                    makes += 1; return session
                }, wait: { waits += 1 })
                XCTFail("Incomplete authentication must not pass")
            } catch { XCTAssertEqual(error as? StabilityError, .timeout) }
            XCTAssertEqual(makes, 1)
            XCTAssertEqual(waits, 600)
        }
    }

    @MainActor func testEarlierDisconnectFailsDuringLaterPreparation() async {
        var sessions: [PreparingSession] = []
        do {
            try await FiniteLifecycle.connectFiveSequentially(interruption: { nil }, make: {
                let session = PreparingSession(); sessions.append(session); return session
            }, wait: {
                if sessions.count == 1 { sessions[0].accept(70001) }
                else { sessions[0].phase = .closed; sessions[0].ownedPID = nil }
            })
            XCTFail("An earlier disconnect must abort preparation")
        } catch { XCTAssertEqual(error as? StabilityError, .connectionLost) }
        XCTAssertEqual(sessions.count, 2)
    }

    @MainActor func testLatchedFailureAndTerminalPhasesDoNotCreateNextSession() async {
        for phase in [SessionPhase.failed, .closing, .closed, .connected] {
            let session = PreparingSession(); session.accept(70001); session.phase = phase
            if phase == .connected { session.failure = .connectionLost }
            var makes = 0
            do {
                try await FiniteLifecycle.connectFiveSequentially(interruption: { nil }, make: {
                    makes += 1; return session
                }, wait: { XCTFail("Failure must not wait") })
                XCTFail("Failure must abort")
            } catch { XCTAssertEqual(error as? StabilityError, .connectionLost) }
            XCTAssertEqual(makes, 1)
        }
    }

    @MainActor func testCancellationAndSleepAreNotConvertedToSuccessfulPreparation() async {
        for reason in [StabilityError.cancelled, .timerDiscontinuity] {
            var waits = 0, makes = 0
            do {
                try await FiniteLifecycle.connectFiveSequentially(interruption: { waits > 0 ? reason : nil }, make: {
                    makes += 1; return PreparingSession()
                }, wait: { waits += 1 })
                XCTFail("Interruption must abort")
            } catch { XCTAssertEqual(error as? StabilityError, reason) }
            XCTAssertEqual(makes, 1)
        }
    }
}
