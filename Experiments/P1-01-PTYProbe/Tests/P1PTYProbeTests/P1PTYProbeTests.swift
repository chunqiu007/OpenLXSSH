import Darwin
import Foundation
import XCTest
@testable import P1PTYProbe

@MainActor
final class P1PTYProbeTests: XCTestCase {
    private func assertReleased(_ result: ProbeResult, session: PTYProbeSession, child: pid_t, fd: Int32) async {
        XCTAssertTrue(result.childReaped)
        XCTAssertTrue(result.masterClosed)
        XCTAssertEqual(result.ownedAsyncTasks, 0)
        let snapshot = await session.snapshot()
        XCTAssertNil(snapshot.pid)
        XCTAssertNil(snapshot.masterFD)
        XCTAssertEqual(snapshot.ownedAsyncTasks, 0)
        XCTAssertEqual(snapshot.pendingInputBytes, 0)
        XCTAssertEqual(kill(child, 0), -1)
        XCTAssertEqual(errno, ESRCH)
        XCTAssertEqual(fcntl(fd, F_GETFD), -1)
        XCTAssertEqual(errno, EBADF)
    }

    private func started(_ configuration: PTYProbeSession.Configuration) async throws -> (PTYProbeSession, pid_t, Int32) {
        let session = PTYProbeSession(configuration: configuration)
        try await session.start()
        let snapshot = await session.snapshot()
        return (session, try XCTUnwrap(snapshot.pid), try XCTUnwrap(snapshot.masterFD))
    }

    func testLocalSmokeIncludingExactArgvIOResizeAndOpenSSHWithoutNetwork() async throws {
        let summary = try await runLocalSmoke()
        XCTAssertEqual(summary.count, 4)
    }

    func testHostBoundariesRoundTripAsExactArgvNeverAsPythonSourceOrShell() async throws {
        for host in ProbeFixture.edgeArguments {
            let vector = try SSHArgumentVector.inspectionArguments(host: host)
            XCTAssertEqual(vector.last, host)
            XCTAssertEqual(vector.dropLast().last, "--")
            let (session, child, fd) = try await started(ProbeFixture.configuration("argv", arguments: vector))
            let result = await session.wait()
            let text = String(decoding: result.output, as: UTF8.self)
            let start = try XCTUnwrap(text.range(of: "ARGV:"))
            let line = try XCTUnwrap(text[start.upperBound...].split(whereSeparator: { $0 == "\r" || $0 == "\n" }).first)
            let decoded = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String]
            XCTAssertEqual(decoded, vector)
            XCTAssertEqual(result.exitCode, 0)
            await assertReleased(result, session: session, child: child, fd: fd)
        }
    }

    func testNoNetworkOpenSSHConfigModeAndRejectedHost() async throws {
        // Only -G is allowed here. No -G test contacts a host or supplies a secret.
        for host in ["2001:db8::1", "host with spaces", "line\nbreak", "-leading", "quote'\""] {
            let (session, child, fd) = try await started(.init(
                executable: SSHArgumentVector.executable,
                arguments: SSHArgumentVector.inspectionArguments(host: host)
            ))
            let result = await session.wait()
            XCTAssertEqual(result.exitCode, host == "2001:db8::1" ? 0 : 255)
            XCTAssertEqual(result.reason, .exited)
            await assertReleased(result, session: session, child: child, fd: fd)
        }
    }

    func testNormalExitDrainsExactBinaryTailAndEOFBeforeCleanup() async throws {
        let (session, child, fd) = try await started(ProbeFixture.configuration("burst", arguments: ["512"]))
        let result = await session.wait()
        XCTAssertEqual(result.reason, .exited)
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertNil(result.errorNumber)
        XCTAssertTrue(result.reachedEOF)
        XCTAssertEqual(result.output, Data((0..<512).flatMap { _ in (0..<256).map(UInt8.init) }))
        await assertReleased(result, session: session, child: child, fd: fd)
    }

    func testPTYEOFBeforeProcessExitStillReapsOnDeadline() async throws {
        let (session, child, fd) = try await started(ProbeFixture.configuration("eof-first", timeout: .milliseconds(300)))
        let result = await session.wait()
        XCTAssertTrue(result.reachedEOF)
        XCTAssertEqual(result.reason, .timedOut)
        XCTAssertNotNil(result.signal)
        await assertReleased(result, session: session, child: child, fd: fd)
    }

    func testCancellationSIGTERMAndConcurrentIdempotentClose() async throws {
        let (session, child, fd) = try await started(ProbeFixture.configuration("sleep"))
        try await waitForOutput(Data("READY".utf8), from: session)
        async let one = session.cancel()
        async let two = session.close()
        async let three = session.wait()
        let (first, second, third) = await (one, two, three)
        XCTAssertEqual(first, second)
        XCTAssertEqual(second, third)
        XCTAssertTrue([StopReason.cancelled, .closed].contains(first.reason))
        XCTAssertEqual(first.signal, SIGTERM)
        XCTAssertFalse(first.escalatedToKill)
        let repeated = await session.close()
        XCTAssertEqual(repeated, first)
        await assertReleased(first, session: session, child: child, fd: fd)
    }

    func testCancelOnlyAffectsTheOwnedDirectChildNotAnotherSession() async throws {
        let (one, onePID, oneFD) = try await started(ProbeFixture.configuration("ignore-term"))
        let (two, twoPID, twoFD) = try await started(ProbeFixture.configuration("sleep"))
        try await waitForOutput(Data("READY".utf8), from: one)
        try await waitForOutput(Data("READY".utf8), from: two)
        let oneResult = await one.cancel()
        await assertReleased(oneResult, session: one, child: onePID, fd: oneFD)
        XCTAssertEqual(kill(twoPID, 0), 0)
        let twoSnapshot = await two.snapshot()
        XCTAssertEqual(twoSnapshot.pid, twoPID)
        XCTAssertEqual(twoSnapshot.ownedAsyncTasks, 1)
        let twoResult = await two.close()
        await assertReleased(twoResult, session: two, child: twoPID, fd: twoFD)
    }

    func testTimeoutEscalatesIgnoredSIGTERMToSIGKILLWithoutBlockingMainActor() async throws {
        let (session, child, fd) = try await started(ProbeFixture.configuration("ignore-term", timeout: .milliseconds(350)))
        try await waitForOutput(Data("READY".utf8), from: session)
        let clock = ContinuousClock.now
        var mainActorHeartbeats = 0
        let heartbeat = Task { @MainActor in
            while !Task.isCancelled {
                mainActorHeartbeats += 1
                try? await Task.sleep(for: .milliseconds(10))
            }
        }
        let result = await session.wait()
        heartbeat.cancel()
        await heartbeat.value
        XCTAssertGreaterThan(mainActorHeartbeats, 3)
        XCTAssertLessThan(ContinuousClock.now - clock, .seconds(2))
        XCTAssertEqual(result.reason, .timedOut)
        XCTAssertEqual(result.signal, SIGKILL)
        XCTAssertTrue(result.escalatedToKill)
        await assertReleased(result, session: session, child: child, fd: fd)
    }

    func testCancellingWaiterTerminatesItsSession() async throws {
        let (session, child, fd) = try await started(ProbeFixture.configuration("ignore-term"))
        try await waitForOutput(Data("READY".utf8), from: session)
        let waiter = Task { await session.wait() }
        waiter.cancel()
        let result = await waiter.value
        XCTAssertEqual(result.reason, .cancelled)
        XCTAssertEqual(result.signal, SIGKILL)
        await assertReleased(result, session: session, child: child, fd: fd)
    }

    func testCloseBeforeStartAndLateCallbacksCannotTouchReusedDescriptor() async throws {
        let preclosed = PTYProbeSession(configuration: try ProbeFixture.configuration("sleep"))
        let first = await preclosed.close()
        let again = await preclosed.close()
        XCTAssertEqual(first, again)
        do {
            try await preclosed.start()
            XCTFail("closed single-use session restarted")
        } catch { XCTAssertEqual(error as? ProbeError, .closed) }

        let (session, child, fd) = try await started(ProbeFixture.configuration("sleep"))
        let result = await session.close()
        await assertReleased(result, session: session, child: child, fd: fd)
        let reused = open("/dev/null", O_RDWR)
        defer { _ = Darwin.close(reused) }
        XCTAssertGreaterThanOrEqual(reused, 0)
        if reused != fd {
            XCTAssertEqual(dup2(reused, fd), fd)
        }
        defer { if reused != fd { _ = Darwin.close(fd) } }
        let duplicate = await session.close()
        XCTAssertEqual(duplicate, result)
        do { try await session.send(Data([1])); XCTFail("late input accepted") } catch {}
        do { _ = try await session.resize(WindowSize(rows: 1, columns: 1)); XCTFail("late resize accepted") } catch {}
        try await Task.sleep(for: .milliseconds(150))
        XCTAssertGreaterThanOrEqual(fcntl(reused, F_GETFD), 0)
        XCTAssertGreaterThanOrEqual(fcntl(fd, F_GETFD), 0)
    }

    func testFailedExecNonzeroExitAndConfigurationErrorsAreObservable() async throws {
        let (missing, child, fd) = try await started(.init(executable: "/nonexistent-openlxssh-p1-fixture", arguments: []))
        let missingResult = await missing.wait()
        XCTAssertEqual(missingResult.exitCode, 127)
        await assertReleased(missingResult, session: missing, child: child, fd: fd)
        let (nonzero, nextChild, nextFD) = try await started(ProbeFixture.configuration("exit", arguments: ["23"]))
        let nonzeroResult = await nonzero.wait()
        XCTAssertEqual(nonzeroResult.exitCode, 23)
        await assertReleased(nonzeroResult, session: nonzero, child: nextChild, fd: nextFD)
        XCTAssertThrowsError(try PTYProbeSession.Configuration(executable: "relative", arguments: []))
        XCTAssertThrowsError(try PTYProbeSession.Configuration(executable: "/usr/bin/ssh", arguments: ["bad\0value"]))
        XCTAssertThrowsError(try SSHArgumentVector.inspectionArguments(host: "bad\0host"))
        XCTAssertThrowsError(try SSHArgumentVector.inspectionArguments(host: "host", port: 0))
        XCTAssertThrowsError(try WindowSize(rows: 0, columns: 80))
    }

    func testBoundedOutputAndRejectedOversizedInput() async throws {
        let (burst, child, fd) = try await started(ProbeFixture.configuration("burst", arguments: ["512"], maximumOutputBytes: 1024))
        let result = await burst.wait()
        XCTAssertEqual(result.reason, .outputLimit)
        XCTAssertLessThanOrEqual(result.output.count, 1024)
        await assertReleased(result, session: burst, child: child, fd: fd)
        let (input, inputChild, inputFD) = try await started(ProbeFixture.configuration("sleep"))
        do { try await input.send(Data(repeating: 1, count: 65_537)); XCTFail("unbounded input") }
        catch { XCTAssertEqual(error as? ProbeError, .inputTooLarge) }
        let inputResult = await input.close()
        await assertReleased(inputResult, session: input, child: inputChild, fd: inputFD)
    }

    func testChildDoesNotInheritParentFileDescriptor() async throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("openlxssh-p1-fd-\(UUID().uuidString)")
        let marker = open(file.path, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR)
        XCTAssertGreaterThanOrEqual(marker, 0)
        defer { _ = Darwin.close(marker); try? FileManager.default.removeItem(at: file) }
        _ = fcntl(marker, F_SETFD, 0) // Deliberately not CLOEXEC to verify the spawn boundary.
        let (session, child, fd) = try await started(ProbeFixture.configuration("fd", arguments: [file.path, String(marker)]))
        let result = await session.wait()
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(String(decoding: result.output, as: UTF8.self).contains("INHERITED:False"))
        XCTAssertGreaterThanOrEqual(fcntl(marker, F_GETFD), 0)
        await assertReleased(result, session: session, child: child, fd: fd)
    }

    func testRepeatedLocalCyclesHaveNoOwnedProcessFDTaskOrObjectAccumulation() async throws {
        // Finite local sanity check; this is NOT AC-28's 200 authenticated SSH cycles.
        for index in 0..<20 {
            let (session, child, fd) = try await started(ProbeFixture.configuration(index.isMultiple(of: 2) ? "exit" : "sleep", arguments: index.isMultiple(of: 2) ? ["0"] : []))
            let result: ProbeResult
            if index.isMultiple(of: 2) { result = await session.wait() }
            else { result = await session.close() }
            await assertReleased(result, session: session, child: child, fd: fd)
        }
        weak var weakSession: PTYProbeSession?
        var owner: PTYProbeSession? = PTYProbeSession(configuration: try ProbeFixture.configuration("exit", arguments: ["0"]))
        weakSession = owner
        try await owner?.start()
        _ = await owner?.wait()
        owner = nil
        for _ in 0..<20 {
            if weakSession == nil { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertNil(weakSession)
    }
}
