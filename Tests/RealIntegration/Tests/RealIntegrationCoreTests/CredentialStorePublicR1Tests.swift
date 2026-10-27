import Foundation
import XCTest
@testable import RealIntegrationCore

@MainActor final class CredentialStorePublicR1Tests: XCTestCase {
    final class StopFlag { var requested = false }
    func policy(_ flag: StopFlag) -> CredentialStorePublicStopGuard {
        CredentialStorePublicStopGuard(isStopRequested: { flag.requested })
    }
    func testStopDuringFakeFixtureAwaitForbidsSave() async throws {
        let flag = StopFlag()
        let stop = policy(flag); var saves = 0
        do {
            let _: String = try await stop.checkedValue { await Task.yield(); flag.requested = true; return "synthetic" }
            try stop.check(); saves += 1
            XCTFail("save admitted after stopped fixture read")
        } catch { XCTAssertEqual(error as? CredentialStorePublicError, .cancelled) }
        XCTAssertEqual(saves, 0)
    }
    func testStopAtSaveBoundaryForbidsSideEffect() async throws {
        let flag = StopFlag(), stop = policy(flag); var saves = 0
        let _: String = try await stop.checkedValue { "synthetic" }
        flag.requested = true
        XCTAssertThrowsError(try stop.check()); if (try? stop.check()) != nil { saves += 1 }
        XCTAssertEqual(saves, 0)
    }
    func testStopDuringFakeStoreAwaitForbidsProviderReturn() async throws {
        let flag = StopFlag(), stop = policy(flag); var returns = 0
        do {
            let _: String = try await stop.checkedValue { await Task.yield(); flag.requested = true; return "synthetic" }
            try stop.checkCurrent(true); returns += 1
            XCTFail("provider returned after stop")
        } catch { XCTAssertEqual(error as? CredentialStorePublicError, .cancelled) }
        XCTAssertEqual(returns, 0)
    }
    func testConnectedAndStopSameTickAndCancellationAreStopFirst() throws {
        let flag = StopFlag(), stop = policy(flag); let connected = true
        flag.requested = true
        XCTAssertThrowsError(try stop.checkCurrent(connected)) { XCTAssertEqual($0 as? CredentialStorePublicError, .cancelled) }
        XCTAssertThrowsError(try stop.checkCurrent(false)) { XCTAssertEqual($0 as? CredentialStorePublicError, .cancelled) }
        let cancelled = CredentialStorePublicStopGuard(isStopRequested: { false }, isCancelled: { true })
        XCTAssertThrowsError(try cancelled.check()) { XCTAssertEqual($0 as? CredentialStorePublicError, .cancelled) }
    }
    func testConfirmedSavedDuringStopStillOwnsAndCompensatesExactItem() throws {
        let flag = StopFlag(), stop = policy(flag)
        var state = CredentialStorePublicState(namespace: UUID(), referenceID: UUID(), runID: UUID())
        let exactReference = state.referenceID
        try state.preparedWasDurable(); try state.beginSave()
        flag.requested = true // Save completed while stop was arriving.
        try state.finishSave(.saved) // Ownership MUST precede stop check.
        XCTAssertThrowsError(try stop.check())
        state.fail(.cancelled)
        XCTAssertTrue(state.mayAttemptExactDelete); XCTAssertEqual(state.referenceID, exactReference)
        try state.beginExactDelete(); try state.finishDelete(.deleted); try state.recordMissing(true); state.recordClose(restored: true)
        XCTAssertFalse(state.ownsExactItem); XCTAssertEqual(state.deleteAttempts, 1)
        XCTAssertThrowsError(try state.requireSuccessfulLifecycle()) // Cleanup is not operation success.
    }
    func testDurabilityOrderAndEveryInjectedFailureBlockAdmission() throws {
        var trace: [String] = []
        try CredentialStorePublicDurability.commit(validateIdentity: { trace.append("identity") }, writeAndSyncFile: { trace.append("file") },
            syncRun: { trace.append("run") }, syncParent: { trace.append("parent") })
        XCTAssertEqual(trace, ["identity", "file", "identity", "run", "parent", "identity"])
        for failAt in 0..<6 {
            var count = 0, externalActions = 0
            func step() throws { defer { count += 1 }; if count == failAt { throw CredentialStorePublicError.recoveryRecordFailed } }
            do {
                try CredentialStorePublicDurability.commit(validateIdentity: step, writeAndSyncFile: step, syncRun: step, syncParent: step)
                externalActions += 1
            } catch { XCTAssertEqual(error as? CredentialStorePublicError, .recoveryRecordFailed) }
            XCTAssertEqual(externalActions, 0); XCTAssertEqual(count, failAt + 1)
        }
    }
    func testExplicitSavedBudgetMapPreservesEveryTypedReason() throws {
        let pairs: [(SavedPasswordPublicError, CredentialStorePublicError)] = [
            (.invalidContract, .invalidContract), (.unsafeMaterial, .unsafeMaterial), (.provenanceMismatch, .provenanceMismatch),
            (.fingerprintMismatch, .fingerprintMismatch), (.staleGeneration, .staleGeneration), (.extraProviderCall, .extraProviderCall),
            (.extraManualRequest, .extraManualRequest), (.unknownManualRequest, .unknownManualRequest), (.gateNotCovered, .gateNotCovered),
            (.providerFailed, .providerFailed), (.cancelled, .cancelled), (.timeout, .timeout), (.connectionFailed, .connectionFailed), (.cleanupIncomplete, .cleanupIncomplete)]
        for (input, expected) in pairs { XCTAssertEqual(CredentialStorePublicErrorMap.classify(input, fallback: .credentialReadFailed), expected) }
        XCTAssertEqual(CredentialStorePublicErrorMap.classify(CancellationError(), fallback: .credentialReadFailed), .cancelled)
        XCTAssertEqual(CredentialStorePublicErrorMap.classify(CredentialStorePublicError.deleteRetryRequired, fallback: .invalidContract), .deleteRetryRequired)
        XCTAssertEqual(CredentialStorePublicErrorMap.classify(NSError(domain: "synthetic", code: 1), fallback: .credentialReadFailed), .credentialReadFailed)
    }
    func testUnstoppedAwaitAndCurrentGenerationRemainUsable() async throws {
        let flag = StopFlag(), stop = policy(flag)
        let value = try await stop.checkedValue { await Task.yield(); return 1 }
        XCTAssertEqual(value, 1); XCTAssertNoThrow(try stop.checkCurrent(true))
        XCTAssertThrowsError(try stop.checkCurrent(false)) { XCTAssertEqual($0 as? CredentialStorePublicError, .staleGeneration) }
    }
}
