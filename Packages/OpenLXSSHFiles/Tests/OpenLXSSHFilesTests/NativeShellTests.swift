import COpenLXSSHFiles
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

/// Offline only: AF_UNIX socketpairs, no endpoint/listener, SSH server, credentials or Keychain.
/// A silent peer cannot prove authentication, a remote PTY, output or a clean remote exit.
final class NativeShellTests: XCTestCase, @unchecked Sendable {
    private func pair() throws -> [Int32] {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw FileServiceError(.io, operation: "shell-test-socketpair")
        }
        return fds
    }
    private func options(_ timeout: TimeInterval = 0.1) throws -> NativeShellOptions {
        try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: timeout)
    }
    private func establish(_ session: LibSSH2ShellSession, token: CancellationToken) async throws {
        try await session.establish(identity: ServerIdentity(host: "offline.invalid", port: 22),
            username: Data("fixture".utf8), plan: NativeShellAuthenticationPlan(primary: .password(Data()), keyboard: nil),
            hostKeyHandler: nil, token: token)
    }
    func testPTYAndTimeoutBoundsRejectWithoutConnection() throws {
        for (cols, rows) in [(0, 24), (-1, 24), (80, 0), (65536, 24), (80, 65536)] {
            XCTAssertThrowsError(try NativeShellSize(columns: cols, rows: rows))
        }
        XCTAssertEqual(try NativeShellSize(columns: 65535, rows: 1).columns, 65535)
        for timeout in [0, -1, .infinity, .nan, 301] {
            XCTAssertThrowsError(try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: timeout))
        }
        XCTAssertThrowsError(try LibSSH2ShellSession(connectedSocket: -1, options: options()))
    }
    func testTypedPrimaryRequiredAndSecretBounds() throws {
        XCTAssertThrowsError(try NativeShellAuthenticationPlan(primary: .keyboardInteractive { _, _ in }, keyboard: nil))
        XCTAssertThrowsError(try NativeShellAuthenticationPlan(primary: .password(Data(count: 65537)), keyboard: nil))
        XCTAssertThrowsError(try NativeShellAuthenticationPlan(primary: .publicKey(publicKey: nil, privateKey: Data(), passphrase: nil), keyboard: nil))
        XCTAssertThrowsError(try NativeShellAuthenticationPlan(primary: .publicKey(publicKey: nil, privateKey: Data([1]), passphrase: Data([0])), keyboard: nil))
        XCTAssertEqual(try NativeShellAuthenticationPlan(primary: .password(Data([0, 1])), keyboard: nil).method, .password)
        // Opaque encrypted in-memory material is delegated to mature libssh2, not locally parsed.
        XCTAssertEqual(try NativeShellAuthenticationPlan(primary: .publicKey(publicKey: nil, privateKey: Data([1]), passphrase: Data([2])), keyboard: nil).method, .publicKey)
    }
    func testAmbiguousPrimaryResultOnlyAllowsOneDistinctManualMethod() {
        for code in [Int32(LIBSSH2_ERROR_AUTHENTICATION_FAILED), Int32(LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED)] {
            XCTAssertTrue(NativeShellAuthenticationPlan.mayContinueToKeyboard(code: code, authenticated: false, hasHandler: true))
            XCTAssertFalse(NativeShellAuthenticationPlan.mayContinueToKeyboard(code: code, authenticated: true, hasHandler: true))
            XCTAssertFalse(NativeShellAuthenticationPlan.mayContinueToKeyboard(code: code, authenticated: false, hasHandler: false))
        }
        for code in [Int32(0), Int32(RF_TIMEOUT), Int32(RF_CANCELLED), Int32(LIBSSH2_ERROR_EAGAIN), Int32(LIBSSH2_ERROR_SOCKET_RECV)] {
            XCTAssertFalse(NativeShellAuthenticationPlan.mayContinueToKeyboard(code: code, authenticated: false, hasHandler: true))
        }
    }
    func testInputAdmissionIsBoundedBeforeDispatchAndReleasesExactly() throws {
        let gate = NativeShellAdmission()
        try gate.reserveWrite(256 * 1024)
        XCTAssertEqual(gate.pendingInputBytes, 256 * 1024)
        XCTAssertThrowsError(try gate.reserveWrite(1))
        gate.releaseWrite(256 * 1024)
        XCTAssertEqual(gate.pendingInputBytes, 0)
        for _ in 0..<128 { try gate.reserveWrite(1) }
        XCTAssertThrowsError(try gate.reserveWrite(1))
        for _ in 0..<128 { gate.releaseWrite(1) }
        XCTAssertThrowsError(try gate.reserveWrite(0))
        XCTAssertThrowsError(try gate.reserveWrite(256 * 1024 + 1))
        gate.close(); XCTAssertThrowsError(try gate.reserveWrite(1))
        XCTAssertEqual(gate.pendingInputBytes, 0)
    }
    func testSinglePullConsumerAndControlAdmissionBound() throws {
        let gate = NativeShellAdmission()
        try gate.reserveReceive(); XCTAssertThrowsError(try gate.reserveReceive())
        try gate.reserveControl(); XCTAssertThrowsError(try gate.reserveControl())
        gate.releaseReceive(); gate.releaseControl()
        try gate.reserveReceive(); try gate.reserveControl()
        gate.releaseReceive(); gate.releaseControl(); gate.close()
        XCTAssertThrowsError(try gate.reserveReceive()); XCTAssertThrowsError(try gate.reserveControl())
    }
    func testStableWriteBufferRetainsBytesAndChunkAcrossEAGAINNoAdvance() {
        let source = Data((0..<(70 * 1024)).map { UInt8(truncatingIfNeeded: $0) })
        let owner = NativeShellWriteBuffer(source)
        let first = owner.stepPointer
        for _ in 0..<10 { XCTAssertEqual(owner.stepPointer, first); XCTAssertEqual(owner.stepLength, 32768) }
        XCTAssertEqual(Data(bytes: owner.stepPointer, count: owner.stepLength), source.prefix(32768))
        owner.advance(17)
        XCTAssertEqual(owner.stepPointer, first.advanced(by: 17)); XCTAssertEqual(owner.stepLength, 32768)
        while !owner.complete { owner.advance(owner.stepLength) }
        XCTAssertEqual(owner.offset, source.count); XCTAssertEqual(owner.stepLength, 0)
    }
    func testKeyboardWholeTransactionBudgetBoundsZeroAndMultiRounds() throws {
        var budget = NativeShellKeyboardBudget()
        for _ in 0..<16 { try budget.claim(prompts: 0, bytes: 1) }
        XCTAssertEqual(budget.rounds, 16); XCTAssertThrowsError(try budget.claim(prompts: 0, bytes: 0))
        var prompts = NativeShellKeyboardBudget()
        for _ in 0..<4 { try prompts.claim(prompts: 32, bytes: 1) }
        XCTAssertThrowsError(try prompts.claim(prompts: 1, bytes: 1))
        var bytes = NativeShellKeyboardBudget(); try bytes.claim(prompts: 0, bytes: 1024 * 1024)
        XCTAssertThrowsError(try bytes.claim(prompts: 0, bytes: 1))
    }
    func testNativeNoTrustRefusesAllShellAndMethodCallsWithoutSending() throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let c = try XCTUnwrap(rf_connection_create(fds[0])); defer { rf_connection_destroy(c) }
        let token = CancellationToken()
        XCTAssertEqual(rf_shell_open(c, token.native, 0.1), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_request_pty(c, 80, 24, token.native, 0.1), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_start(c, token.native, 0.1), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_poll(c, token.native), Int32(RF_UNTRUSTED))
        var bytes = [CChar](repeating: 0, count: 64); var len = 0
        XCTAssertEqual(rf_auth_methods(c, "fixture", 7, &bytes, bytes.count, &len, token.native, 0.1), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_read_step(c, &bytes, bytes.count, token.native), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_write_step(c, &bytes, bytes.count, token.native), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_resize_step(c, 80, 24, token.native), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_send_eof_step(c, token.native), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_eof(c, token.native), Int32(RF_UNTRUSTED))
        var status = rf_shell_exit()
        XCTAssertEqual(rf_shell_exit_step(c, &status, token.native), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_close_step(c, token.native), Int32(RF_UNTRUSTED))
        XCTAssertEqual(rf_shell_free_step(c, token.native), Int32(RF_UNTRUSTED))
        XCTAssertEqual(recv(fds[1], &bytes, bytes.count, MSG_DONTWAIT), -1); XCTAssertEqual(errno, EAGAIN)
        token.cancel()
        XCTAssertEqual(rf_shell_open(c, token.native, 0.1), Int32(RF_CANCELLED))
    }
    func testSilentPeerHandshakeTimeoutNoAuthNoSFTPShellClaim() async throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options(0.04))
        let start = ContinuousClock.now
        do { try await establish(session, token: CancellationToken()); XCTFail("silent peer cannot speak SSH") }
        catch let error as NativeShellError {
            XCTAssertEqual(error.kind, .timeout); XCTAssertEqual(error.operation, "handshake")
            XCTAssertTrue(error.authenticationStages.isEmpty)
        }
        XCTAssertLessThan(start.duration(to: .now), .seconds(1))
        let stages = await session.authenticationStages(); XCTAssertTrue(stages.isEmpty)
        await session.close(); await session.close()
        XCTAssertNotEqual(fcntl(fds[0], F_GETFD), -1) // Caller FD was not adopted/closed.
        var byte: UInt8 = 0; XCTAssertEqual(recv(fds[0], &byte, 1, MSG_DONTWAIT), 0)
    }
    func testNativeTokenCancellationDuringHandshakeIsPromptAndDrained() async throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options(2))
        let token = CancellationToken()
        let task = Task { try await self.establish(session, token: token) }
        try await Task.sleep(for: .milliseconds(25)); let start = ContinuousClock.now; token.cancel()
        do { try await task.value; XCTFail("cancel") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .cancelled) }
        XCTAssertLessThan(start.duration(to: .now), .milliseconds(500))
        await session.close(); XCTAssertEqual(session.pendingInputBytes, 0)
    }
    func testSwiftTaskCancellationAndConcurrentCloseDrainOneOwner() async throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options(2))
        let task = Task { try await self.establish(session, token: CancellationToken()) }
        try await Task.sleep(for: .milliseconds(25)); task.cancel()
        async let a: Void = session.close(); async let b: Void = session.close()
        do { try await task.value; XCTFail("cancel") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .cancelled) }
        _ = await (a, b)
        do { try await session.write(Data([1]), token: CancellationToken()); XCTFail("closed") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .closed) }
    }
    func testPrecancelledTokenSendsNoHandshakeBytes() async throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options())
        let token = CancellationToken(); token.cancel()
        do { try await establish(session, token: token); XCTFail("cancel") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .cancelled) }
        var bytes = [UInt8](repeating: 0, count: 32)
        XCTAssertEqual(recv(fds[1], &bytes, bytes.count, MSG_DONTWAIT), 0)
        await session.close()
    }
    func testPeerEOFIsTransportFailureNotReadyOrExit() async throws {
        let fds = try pair(); defer { Darwin.close(fds[0]) }
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options())
        Darwin.close(fds[1])
        do { try await establish(session, token: CancellationToken()); XCTFail("EOF") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .transport) }
        let stages = await session.authenticationStages(); XCTAssertFalse(stages.contains(.shellReady))
        await session.close()
    }
    func testReadBoundsAndNotReadyNeverSucceed() async throws {
        let fds = try pair(); defer { fds.forEach { Darwin.close($0) } }
        let session = try LibSSH2ShellSession(connectedSocket: fds[0], options: options())
        for count in [0, -1, 65537] {
            do { _ = try await session.receive(maxBytes: count, token: CancellationToken()); XCTFail("bounds") }
            catch let error as NativeShellError { XCTAssertEqual(error.kind, .invalidConfiguration) }
        }
        for wait in [-1.0, .nan, .infinity, 301] {
            do { _ = try await session.receive(wait: wait, token: CancellationToken()); XCTFail("bounds") }
            catch let error as NativeShellError { XCTAssertEqual(error.kind, .invalidConfiguration) }
        }
        do { _ = try await session.receive(token: CancellationToken()); XCTFail("not ready") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .closed) }
        do { try await session.resize(NativeShellSize(columns: 100, rows: 40), token: CancellationToken()); XCTFail("not ready") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .closed) }
        do { try await session.sendEOF(token: CancellationToken()); XCTFail("not ready") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .closed) }
        await session.close()
    }
    func testCancelledMailboxUIWaitRejectsLateAnswer() async throws {
        let reply = ChallengeReply<Bool>(), token = CancellationToken()
        let wait = Task { try reply.wait(token: token, deadline: Date().addingTimeInterval(2)) }
        try await Task.sleep(for: .milliseconds(10)); token.cancel()
        do { _ = try await wait.value; XCTFail("cancel") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        XCTAssertFalse(reply.resolve(true))
    }
    func testNativeLibrarySmokeDoesNotNeedEndpoint() {
        XCTAssertEqual(NativeDiagnostics.smoke(), 0)
        XCTAssertEqual(NativeDiagnostics.libssh2, "1.11.1")
    }
}
