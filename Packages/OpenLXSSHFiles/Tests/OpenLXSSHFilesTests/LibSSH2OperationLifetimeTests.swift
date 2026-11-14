import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

/// Real native connection allocation/socketpair/serial queue. Body gates isolate admission
/// and cancellation ownership; this is deliberately not SSH/SFTP interoperability evidence.
private final class NativeOperationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var entered = false
    private var released = false
    func hold(_ token: CancellationToken) throws -> Int {
        lock.withLock { entered = true }
        let deadline = ContinuousClock.now + .seconds(3)
        while !lock.withLock({ released }) {
            try token.check()
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "test-native-operation-gate") }
            Thread.sleep(forTimeInterval: 0.001)
        }
        try token.check(); return 7
    }
    var hasEntered: Bool { lock.withLock { entered } }
    func release() { lock.withLock { released = true } }
}
private final class NativeBodyCount: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func enter() { lock.withLock { count += 1 } }
    var value: Int { lock.withLock { count } }
}
final class LibSSH2OperationLifetimeTests: XCTestCase, @unchecked Sendable {
    private func fixture() throws -> (LibSSH2FileService, Int32) {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw FileServiceError(.io, operation: "test-socketpair") }
        do {
            let service = try LibSSH2FileService(connectedSocket: pair[0])
            Darwin.close(pair[0]) // Native backend owns its private duplicate, not this input FD.
            return (service, pair[1])
        } catch { Darwin.close(pair[0]); Darwin.close(pair[1]); throw error }
    }
    private func waitEntered(_ gate: NativeOperationGate) async throws {
        let deadline = ContinuousClock.now + .seconds(2)
        while !gate.hasEntered {
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "test-queue-entry") }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    private func peerEOF(_ peer: Int32) -> Bool {
        var byte: UInt8 = 0
        return recv(peer, &byte, 1, MSG_DONTWAIT) == 0
    }
    func testCancellingQueuedOperationNeverClosesDifferentActiveSessionOperation() async throws {
        let (service, peer) = try fixture(); defer { Darwin.close(peer) }
        let firstToken = CancellationToken(), queuedToken = CancellationToken(), gate = NativeOperationGate(), queuedBody = NativeBodyCount()
        let first = Task { try await service.perform(firstToken) { _ in try gate.hold(firstToken) } }
        try await waitEntered(gate)
        let queued = Task { try await service.perform(queuedToken) { _ in queuedBody.enter(); return 99 } }
        await Task.yield(); queued.cancel()
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertFalse(firstToken.isCancelled); XCTAssertFalse(peerEOF(peer)); XCTAssertNil(service.terminalFailure)
        gate.release()
        let firstResult = try await first.value; XCTAssertEqual(firstResult, 7)
        do { _ = try await queued.value; XCTFail("Queued cancellation must reject before entering native body") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        XCTAssertEqual(queuedBody.value, 0); XCTAssertNil(service.terminalFailure); XCTAssertFalse(peerEOF(peer))
        let next = try await service.perform(CancellationToken()) { _ in 11 }; XCTAssertEqual(next, 11)
        await service.close(); XCTAssertTrue(peerEOF(peer))
    }
    func testCancellingEnteredOperationPublishesCancellationDispositionAndActuallyClosesOwnedSocket() async throws {
        let (service, peer) = try fixture(); defer { Darwin.close(peer) }
        let token = CancellationToken(), gate = NativeOperationGate(), laterBody = NativeBodyCount()
        let active = Task { try await service.perform(token) { _ in try gate.hold(token) } }
        try await waitEntered(gate); active.cancel()
        do { _ = try await active.value; XCTFail("Native active cancellation must end the admitted operation") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        XCTAssertEqual(service.terminalFailure?.kind, .cancelled)
        XCTAssertTrue(peerEOF(peer), "The backend fact must correspond to actual native socket disposal")
        do { _ = try await service.perform(CancellationToken()) { _ in laterBody.enter(); return 1 }; XCTFail("Disposed native state cannot be reused") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        XCTAssertEqual(laterBody.value, 0); XCTAssertEqual(service.terminalFailure?.kind, .cancelled)
        await service.close(); XCTAssertTrue(peerEOF(peer))
    }
    func testEnteredClosedResultPublishesBackendDispositionAndDisposesSocket() async throws {
        let (service, peer) = try fixture(); defer { Darwin.close(peer) }
        do {
            let _: Int = try await service.perform(CancellationToken()) { _ in
                throw FileServiceError(.closed, operation: "test-native-closed", code: -9004)
            }
            XCTFail("An entered native closed result must fail")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .closed) }
        XCTAssertEqual(service.terminalFailure?.kind, .closed)
        XCTAssertEqual(service.terminalFailure?.operation, "test-native-closed")
        XCTAssertEqual(service.terminalFailure?.code, -9004)
        XCTAssertTrue(peerEOF(peer)); await service.close()
    }
    func testNonfatalOperationErrorKeepsOriginalResultWhileFailedCleanupPublishesActualClosure() async throws {
        let (service, peer) = try fixture(); defer { Darwin.close(peer) }
        do {
            let _: Int = try await service.perform(CancellationToken()) { _ in
                let original = FileServiceError(.resourceLimit, operation: "test-readdir-limit", code: 7100)
                service.terminate(disposition: FileServiceError(.closed, operation: "closedir-cleanup-failed", code: -37))
                throw original
            }
            XCTFail("The original operation must still fail")
        } catch let error as FileServiceError {
            XCTAssertEqual(error.kind, .resourceLimit); XCTAssertEqual(error.operation, "test-readdir-limit")
            XCTAssertEqual(error.code, 7100)
        }
        XCTAssertEqual(service.terminalFailure?.kind, .closed)
        XCTAssertEqual(service.terminalFailure?.operation, "closedir-cleanup-failed")
        XCTAssertEqual(service.terminalFailure?.code, -37)
        XCTAssertTrue(peerEOF(peer), "The cleanup disposition must correspond to actual native FD disposal")
        await service.close()
        XCTAssertEqual(service.terminalFailure?.operation, "closedir-cleanup-failed", "Later explicit close preserves the original backend termination cause")
    }
    func testExplicitUnusedServiceCloseDoesNotInventNetworkFailure() async throws {
        let (service, peer) = try fixture(); defer { Darwin.close(peer) }
        XCTAssertFalse(peerEOF(peer)); await service.close()
        XCTAssertTrue(peerEOF(peer)); XCTAssertEqual(service.terminalFailure?.kind, .cancelled)
        XCTAssertNotEqual(service.terminalFailure?.kind, .transport); XCTAssertNotEqual(service.terminalFailure?.kind, .timeout)
    }
}
