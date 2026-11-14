import Darwin
import Foundation
import OpenLXSSHTrust
import XCTest
@testable import OpenLXSSHFiles

private final class AccessEventSource: LocalNetworkReadinessSource, @unchecked Sendable {
    private let lock = NSLock()
    private var receive: (@Sendable (LocalNetworkAccessEvent) -> Void)?
    private var previous: (@Sendable (LocalNetworkAccessEvent) -> Void)?
    private var started = false
    private var stopped = false
    private var cancellations = 0
    func start(_ receive: @escaping @Sendable (LocalNetworkAccessEvent) -> Void) {
        lock.withLock { guard !stopped else { return }; started = true; self.receive = receive; previous = receive }
    }
    func cancel() { lock.withLock { if !stopped { cancellations += 1 }; stopped = true; receive = nil } }
    func emit(_ event: LocalNetworkAccessEvent) { lock.withLock { receive }?(event) }
    func emitLate(_ event: LocalNetworkAccessEvent) { lock.withLock { previous }?(event) }
    var hasStarted: Bool { lock.withLock { started } }
    var cancellationCount: Int { lock.withLock { cancellations } }
}
private final class ResolverCallCount: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    func record() { lock.withLock { calls += 1 } }
    var value: Int { lock.withLock { calls } }
}

final class LocalNetworkAccessTests: XCTestCase, @unchecked Sendable {
    private func identity() throws -> HostIdentity {
        HostIdentity(address: try HostAddress("never-connected.invalid"), port: try SSHPort(22))
    }
    private func waitStarted(_ source: AccessEventSource) async throws {
        let deadline = ContinuousClock.now + .seconds(2)
        while !source.hasStarted {
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "test-access-start") }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    private func originalPath(_ source: AccessEventSource, token: CancellationToken, calls: ResolverCallCount,
                              timeout: TimeInterval = 1, permission: Duration = .seconds(1)) throws -> Task<ConnectedSocket, any Error> {
        let identity = try identity()
        let resolver = AddressResolver { _ in calls.record(); throw FileServiceError(.transport, operation: "dns", code: -1234) }
        return Task {
            try await TCPConnector.connect(identity, timeout: timeout, token: token, resolver: resolver, access: { _, token in
                try await LocalNetworkAccess.wait(source: source, token: token,
                    readinessTimeout: .seconds(1), permissionTimeout: permission)
            })
        }
    }
    private func assertOriginalDNS(_ task: Task<ConnectedSocket, any Error>) async {
        do { _ = try await task.value; XCTFail("The injected original resolver must fail before opening TCP") }
        catch let error as FileServiceError {
            XCTAssertEqual(error.kind, .transport); XCTAssertEqual(error.operation, "dns"); XCTAssertEqual(error.code, -1234)
        } catch { XCTFail("Unexpected error type") }
    }
    func testReadyReleasesGateThenInvokesOriginalDNSExactlyOnce() async throws {
        let source = AccessEventSource(), calls = ResolverCallCount()
        let task = try originalPath(source, token: CancellationToken(), calls: calls)
        try await waitStarted(source); XCTAssertEqual(calls.value, 0)
        source.emit(.ready)
        await assertOriginalDNS(task)
        XCTAssertEqual(calls.value, 1); XCTAssertEqual(source.cancellationCount, 1)
        source.emitLate(.localNetworkDenied); source.emitLate(.ready)
        XCTAssertEqual(calls.value, 1, "Late OS callbacks cannot begin a second DNS/TCP attempt")
    }
    func testExplicitPolicyWaitDoesNotConsumeOriginalConnectionTimeoutOrReadDNS() async throws {
        let source = AccessEventSource(), calls = ResolverCallCount()
        let task = try originalPath(source, token: CancellationToken(), calls: calls, timeout: 0.05)
        try await waitStarted(source); source.emit(.localNetworkDenied)
        try await Task.sleep(for: .milliseconds(120))
        XCTAssertEqual(calls.value, 0)
        source.emit(.ready)
        await assertOriginalDNS(task)
        XCTAssertEqual(calls.value, 1); XCTAssertEqual(source.cancellationCount, 1)
    }
    func testTokenCancellationWhilePolicyWaitPreventsDNSAndRejectsLateReady() async throws {
        let source = AccessEventSource(), calls = ResolverCallCount(), token = CancellationToken()
        let task = try originalPath(source, token: token, calls: calls)
        try await waitStarted(source); source.emit(.localNetworkDenied); token.cancel()
        do { _ = try await task.value; XCTFail("Cancellation must end the current attempt") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        source.emitLate(.ready)
        XCTAssertEqual(calls.value, 0); XCTAssertEqual(source.cancellationCount, 1)
    }
    func testTaskCancellationWhilePolicyWaitPreventsDNS() async throws {
        let source = AccessEventSource(), calls = ResolverCallCount(), token = CancellationToken()
        let task = try originalPath(source, token: token, calls: calls)
        try await waitStarted(source); source.emit(.localNetworkDenied); task.cancel()
        do { _ = try await task.value; XCTFail("Task cancellation must end the current attempt") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        source.emitLate(.ready)
        XCTAssertTrue(token.isCancelled); XCTAssertEqual(calls.value, 0); XCTAssertEqual(source.cancellationCount, 1)
    }
    func testPolicyDeadlineIsSpecificAndNeverStartsOriginalDNS() async throws {
        let source = AccessEventSource(), calls = ResolverCallCount()
        let task = try originalPath(source, token: CancellationToken(), calls: calls, permission: .milliseconds(30))
        try await waitStarted(source); source.emit(.localNetworkDenied)
        do { _ = try await task.value; XCTFail("Unapproved network access must have a bounded wait") }
        catch let error as FileServiceError {
            XCTAssertEqual(error.kind, .timeout); XCTAssertEqual(error.operation, "local-network-access")
        }
        source.emitLate(.ready)
        XCTAssertEqual(calls.value, 0); XCTAssertEqual(source.cancellationCount, 1)
    }
    func testNonPolicyWaitingOrFailureReturnsToOriginalDNSDiagnosis() async throws {
        let source = AccessEventSource(), calls = ResolverCallCount()
        let task = try originalPath(source, token: CancellationToken(), calls: calls)
        try await waitStarted(source); source.emit(.fallback)
        await assertOriginalDNS(task)
        XCTAssertEqual(calls.value, 1); XCTAssertEqual(source.cancellationCount, 1)
    }
    func testPolicyThenNonPolicyFallbackIsNotClaimedAsPermissionGrant() async throws {
        let source = AccessEventSource(), calls = ResolverCallCount()
        let task = try originalPath(source, token: CancellationToken(), calls: calls)
        try await waitStarted(source); source.emit(.localNetworkDenied)
        try await Task.sleep(for: .milliseconds(15)); XCTAssertEqual(calls.value, 0)
        source.emit(.fallback)
        await assertOriginalDNS(task)
        XCTAssertEqual(calls.value, 1, "An unrelated path condition goes back to DNS/TCP; UDP does not claim TCP or trust success")
    }
    func testUnsettledUDPProbeFallsThroughWithoutClaimingPermissionError() async throws {
        let source = AccessEventSource()
        try await LocalNetworkAccess.wait(source: source, token: CancellationToken(), readinessTimeout: .milliseconds(15))
        XCTAssertEqual(source.cancellationCount, 1)
    }
    func testAlreadyCancelledTokenNeverStartsReadinessOrDNS() async throws {
        let source = AccessEventSource(), calls = ResolverCallCount(), token = CancellationToken(); token.cancel()
        let task = try originalPath(source, token: token, calls: calls)
        do { _ = try await task.value; XCTFail("Already cancelled") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        XCTAssertFalse(source.hasStarted); XCTAssertEqual(calls.value, 0)
    }
}
