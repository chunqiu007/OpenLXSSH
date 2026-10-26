import Darwin
import XCTest
@testable import StabilityCore
import StabilityPOSIX

/// Pure offline injected observations. None of these invented PIDs is queried,
/// enumerated, spawned, signalled or used by a real Transport session.
final class CleanupObservationRegressionTests: XCTestCase {
    private let owner = ProcessIdentity(pid: 71000, parentPID: 1, uid: 501, startSeconds: 1, startMicroseconds: 1)
    private let ssh = ProcessIdentity(pid: 71001, parentPID: 71000, uid: 501, startSeconds: 2, startMicroseconds: 2)
    private let helper = ProcessIdentity(pid: 71002, parentPID: 71001, uid: 501, startSeconds: 3, startMicroseconds: 3)

    private func sampler(helperRead: @escaping (Int32, inout stability_process) -> Int32) throws -> ResourceSampler {
        var scope = OwnedProcessScope(owner: owner)
        try scope.registerSSH(ssh, sessionOwnedPID: ssh.pid)
        try scope.registerHelper(helper, parent: ssh)
        return ResourceSampler(scope: scope, cleanupRead: { [ssh] pid, value in
            if pid == ssh.pid { return 1 } // Explicitly confirmed absent.
            return helperRead(pid, &value)
        })
    }
    private func snapshot(_ identity: ProcessIdentity, complete: Bool = true) -> stability_process {
        var value = stability_process()
        value.pid = identity.pid; value.ppid = identity.parentPID; value.uid = identity.uid
        value.start_seconds = identity.startSeconds; value.start_microseconds = identity.startMicroseconds
        value.metrics_complete = complete ? 1 : 0
        return value
    }

    func testUnknownEACCESObservationCannotBecomeEmptyCleanup() throws {
        let sampler = try sampler { _, _ in errno = EACCES; return -1 }
        XCTAssertThrowsError(try sampler.observedChildrenStillAlive()) {
            XCTAssertEqual($0 as? StabilityError, .resourceUnavailable)
        }
    }
    func testPartialIdentitySnapshotCannotBecomeEmptyCleanup() throws {
        let sampler = try sampler { pid, value in
            value.pid = pid // A partial query must not imply gone/recycled.
            return -1
        }
        XCTAssertThrowsError(try sampler.observedChildrenStillAlive()) {
            XCTAssertEqual($0 as? StabilityError, .resourceUnavailable)
        }
    }
    func testSameBirthUIDMismatchIsUnknownNotRecycled() throws {
        let changedUID = ProcessIdentity(pid: helper.pid, parentPID: 1, uid: 999, startSeconds: helper.startSeconds, startMicroseconds: helper.startMicroseconds)
        let sampler = try sampler { _, value in value = self.snapshot(changedUID); return 0 }
        XCTAssertThrowsError(try sampler.observedChildrenStillAlive()) {
            XCTAssertEqual($0 as? StabilityError, .resourceUnavailable)
        }
    }
    func testConfirmedGoneAndDifferentBirthAreTheOnlyIgnoredObservations() throws {
        let gone = try sampler { _, _ in 1 }
        XCTAssertTrue(try gone.observedChildrenStillAlive().isEmpty)
        // Even a different UID is safe to ignore ONLY after birth differs.
        let recycled = ProcessIdentity(pid: helper.pid, parentPID: 1, uid: 999, startSeconds: 99, startMicroseconds: 0)
        let sampler = try sampler { _, value in value = self.snapshot(recycled); return 0 }
        XCTAssertTrue(try sampler.observedChildrenStillAlive().isEmpty)
    }
    func testSameAliveReparentedHelperWithIncompleteMetricsRemainsOwned() throws {
        let reparented = ProcessIdentity(pid: helper.pid, parentPID: 1, uid: helper.uid, startSeconds: helper.startSeconds, startMicroseconds: helper.startMicroseconds)
        let sampler = try sampler { _, value in value = self.snapshot(reparented, complete: false); return 0 }
        XCTAssertEqual(try sampler.observedChildrenStillAlive(), [helper])
    }
    func testSuccessfulButMalformedIdentityIsUnknown() throws {
        let sampler = try sampler { pid, value in value.pid = pid; return 0 }
        XCTAssertThrowsError(try sampler.observedChildrenStillAlive()) {
            XCTAssertEqual($0 as? StabilityError, .resourceUnavailable)
        }
    }
}

private final class OfflineIdentityQuery {
    struct Reply {
        let bytes: Int32
        let error: Int32
        var identity: proc_bsdinfo = proc_bsdinfo()
    }
    var replies: [Reply]
    var calls = 0
    init(_ replies: [Reply]) { self.replies = replies }
    static func complete(uid: UInt32 = 501, parent: UInt32 = 71001, birth: UInt64 = 3) -> Reply {
        var value = proc_bsdinfo()
        value.pbi_pid = 71002; value.pbi_ppid = parent; value.pbi_uid = uid; value.pbi_ruid = uid
        value.pbi_start_tvsec = birth; value.pbi_start_tvusec = 3
        return Reply(bytes: Int32(MemoryLayout<proc_bsdinfo>.size), error: 0, identity: value)
    }
}

private func offlineIdentityQuery(_ pid: pid_t, _ out: UnsafeMutablePointer<proc_bsdinfo>?,
                                  _ context: UnsafeMutableRawPointer?) -> Int32 {
    guard pid == 71002, let out, let context else { errno = EINVAL; return 0 }
    let query = Unmanaged<OfflineIdentityQuery>.fromOpaque(context).takeUnretainedValue()
    guard query.calls < query.replies.count else { errno = EIO; return 0 }
    let reply = query.replies[query.calls]; query.calls += 1
    out.pointee = reply.identity; errno = reply.error
    return reply.bytes
}

/// Exercises the real C classifier with injected proc_pidinfo-style replies.
/// No kernel PID query occurs in any test in this class.
final class IdentityQueryClassificationTests: XCTestCase {
    private func observe(_ replies: [OfflineIdentityQuery.Reply]) -> (Int32, stability_process, Int) {
        let query = OfflineIdentityQuery(replies)
        var value = stability_process()
        let code = stability_identity_read_using(71002, &value, offlineIdentityQuery, Unmanaged.passUnretained(query).toOpaque())
        return (code, value, query.calls)
    }
    func testAccessFailureUnspecifiedFailureAndPartialStatRemainUnknown() {
        for reply in [OfflineIdentityQuery.Reply(bytes: 0, error: EACCES),
                      .init(bytes: 0, error: 0), .init(bytes: -1, error: EIO),
                      .init(bytes: Int32(MemoryLayout<proc_bsdinfo>.size - 1), error: 0)] {
            let (status, value, _) = observe([reply])
            XCTAssertEqual(status, Int32(STABILITY_IDENTITY_UNKNOWN))
            XCTAssertEqual(value.pid, 0, "Unknown must not expose a partial lifetime as reusable")
        }
    }
    func testOnlyExplicitInitialESRCHConfirmsGone() {
        let (status, _, calls) = observe([.init(bytes: 0, error: ESRCH)])
        XCTAssertEqual(status, Int32(STABILITY_IDENTITY_GONE))
        XCTAssertEqual(calls, 1)
        let (unstable, _, _) = observe([OfflineIdentityQuery.complete(), .init(bytes: 0, error: ESRCH)])
        XCTAssertEqual(unstable, Int32(STABILITY_IDENTITY_UNKNOWN), "Disappearance mid-query needs a later independent confirmation")
    }
    func testSecondQueryPartialAccessAndIdentityMutationRemainUnknown() {
        let secondReads: [OfflineIdentityQuery.Reply] = [
            .init(bytes: 1, error: 0), .init(bytes: 0, error: EACCES),
            OfflineIdentityQuery.complete(uid: 999), OfflineIdentityQuery.complete(parent: 1), OfflineIdentityQuery.complete(birth: 99)
        ]
        for after in secondReads {
            let (status, value, calls) = observe([OfflineIdentityQuery.complete(), after])
            XCTAssertEqual(status, Int32(STABILITY_IDENTITY_UNKNOWN))
            XCTAssertEqual(value.pid, 0)
            XCTAssertEqual(calls, 2)
        }
    }
    func testStableUIDAndBirthAreReturnedEvenWhenNotCurrentOwner() {
        for identity in [OfflineIdentityQuery.complete(), OfflineIdentityQuery.complete(uid: 999), OfflineIdentityQuery.complete(uid: 999, birth: 99)] {
            let (status, value, calls) = observe([identity, identity])
            XCTAssertEqual(status, Int32(STABILITY_IDENTITY_PRESENT))
            XCTAssertEqual(value.uid, identity.identity.pbi_uid)
            XCTAssertEqual(value.start_seconds, identity.identity.pbi_start_tvsec)
            XCTAssertEqual(value.metrics_complete, 0, "Identity observation does not fabricate RSS/FD metrics")
            XCTAssertEqual(calls, 2)
        }
    }
}

@MainActor private final class CancelRegressionSession: AcceptanceSession {
    var phase = SessionPhase.pending
    var ownedPID: Int32?
    var authenticated = false
    var failure: StabilityError?
    var backendEligible = true
    var cancellationEligible: Bool { backendEligible && phase == .pending && failure == nil && !authenticated }
    var cancels = 0, closes = 0, drains = 0
    func connect() throws { ownedPID = 72001 }
    func cancel() { cancels += 1; phase = .closing }
    func close() { closes += 1; phase = .closing }
    func drain() {
        drains += 1
        if drains == 1 { phase = .closed } // Still owns PID: insufficient cleanup.
        if drains >= 2 { ownedPID = nil; phase = .closed }
    }
}

final class CancellationEligibilityRegressionTests: XCTestCase {
    @MainActor private func checkRefusal(phase: SessionPhase, failure: StabilityError?, authenticated: Bool = false,
                                        backendEligible: Bool = true) async throws {
        var sessions: [CancelRegressionSession] = [], checkpoints: [CycleTotals] = []
        var firstWait = true
        do {
            _ = try await FiniteLifecycle.cycles(cancelEvery: 1, stopped: { false }, make: {
                // Old code tries to start a success session after miscounting cancel.
                guard sessions.isEmpty else { throw StabilityError.invalidLifecycle }
                let session = CancelRegressionSession(); sessions.append(session); return session
            }, wait: {
                guard let session = sessions.last else { return }
                if firstWait {
                    firstWait = false; session.phase = phase; session.failure = failure; session.authenticated = authenticated
                    session.backendEligible = backendEligible
                } else { session.drain() }
            }, checkpoint: { checkpoints.append($0) })
            XCTFail("Expected invalid cancellation to refuse")
        } catch { XCTAssertEqual(error as? StabilityError, .invalidLifecycle) }
        XCTAssertEqual(sessions.count, 1)
        XCTAssertTrue(checkpoints.isEmpty, "A backend failure must never increment cancelledAttempts")
        XCTAssertEqual(sessions[0].cancels, 0, "No active cancel coverage after backend failure/closure")
        XCTAssertGreaterThanOrEqual(sessions[0].closes, 1)
        XCTAssertEqual(sessions[0].drains, 2, "Even invalid cancellation must await closed AND nil owner")
        XCTAssertEqual(sessions[0].phase, .closed); XCTAssertNil(sessions[0].ownedPID)
    }
    @MainActor func testBackendClosingAtFirstWaitIsNotCancellationCoverage() async throws {
        try await checkRefusal(phase: .closing, failure: nil)
    }
    @MainActor func testFailureLatchInPendingStateIsNotCancellationCoverage() async throws {
        try await checkRefusal(phase: .pending, failure: .unsupportedAuthentication)
    }
    @MainActor func testPendingPhaseStillRequiresBackendEligibility() async throws {
        try await checkRefusal(phase: .pending, failure: nil, backendEligible: false)
    }
    @MainActor func testFailedClosedAndAuthenticatedStatesRefuseAndDrain() async throws {
        for phase in [SessionPhase.failed, .closed] { try await checkRefusal(phase: phase, failure: .connectionLost) }
        try await checkRefusal(phase: .connected, failure: nil, authenticated: true)
    }
}
