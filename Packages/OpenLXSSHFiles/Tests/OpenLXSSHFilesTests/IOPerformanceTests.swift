import COpenLXSSHFiles
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

private actor GateWaiterSignal {
    private var arrived = false
    private var arrivedWaiters: [CheckedContinuation<Void, Never>] = []
    private var released = false
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func markArrived() {
        arrived = true
        let list = arrivedWaiters; arrivedWaiters.removeAll()
        list.forEach { $0.resume() }
    }
    func waitArrived() async {
        if arrived { return }
        await withCheckedContinuation { arrivedWaiters.append($0) }
    }
    func waitRelease() async {
        if released { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }
    func release() {
        released = true
        let list = releaseWaiters; releaseWaiters.removeAll()
        list.forEach { $0.resume() }
    }
}

private actor ExecutionOrderRecorder {
    private(set) var values: [Int] = []
    func append(_ value: Int) { values.append(value) }
}

private final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = 0
    @discardableResult func increment() -> Int {
        lock.withLock { storage += 1; return storage }
    }
    var value: Int { lock.withLock { storage } }
}

final class IOPerformanceTests: XCTestCase, @unchecked Sendable {
    private func openFDCount() -> Int {
        var count = 0
        for fd: Int32 in 0..<2048 {
            if fcntl(fd, F_GETFD) != -1 { count += 1 }
        }
        return count
    }

    func testAsyncGateFIFOOrderingAndImmediateCancellationWakeup() async throws {
        let scheduler = TransferScheduler(maxConcurrentChunks: 1)
        let hold = GateWaiterSignal()
        let order = ExecutionOrderRecorder()

        let holder = Task {
            try await scheduler.chunk(CancellationToken()) {
                await hold.markArrived()
                await hold.waitRelease()
            }
        }
        await hold.waitArrived()

        // Enqueue 5 waiters sequentially so arrival order at the gate is deterministic.
        let token2 = CancellationToken()
        var tasks: [Task<Void, any Error>] = []
        for index in 1...5 {
            let tok = index == 2 ? token2 : CancellationToken()
            let t = Task {
                try await scheduler.chunk(tok) {
                    await order.append(index)
                }
            }
            tasks.append(t)
            // Yield briefly so each task registers in FIFO order before the next spawns.
            try await Task.sleep(for: .milliseconds(2))
        }

        // Cancel waiter 2 via CancellationToken and waiter 4 via Task cancellation.
        let cancelStart = ContinuousClock.now
        token2.cancel()
        tasks[3].cancel()

        do {
            try await tasks[1].value
            XCTFail("Waiter 2 should fail on token.cancel()")
        } catch let error as FileServiceError {
            XCTAssertEqual(error.kind, .cancelled)
        }
        do {
            try await tasks[3].value
            XCTFail("Waiter 4 should fail on Task.cancel()")
        } catch let error as FileServiceError {
            XCTAssertEqual(error.kind, .cancelled)
        }
        let cancelElapsed = cancelStart.duration(to: .now)
        XCTAssertLessThan(cancelElapsed, .milliseconds(50), "Cancellation must wake immediately without polling")

        // Release slot 0 and verify remaining waiters execute in strict FIFO order [1, 3, 5].
        await hold.release()
        try await holder.value
        try await tasks[0].value
        try await tasks[2].value
        try await tasks[4].value

        let executed = await order.values
        XCTAssertEqual(executed, [1, 3, 5])

        // Verify slot accounting is intact after mixed completions and cancellations.
        let followUp = try await scheduler.chunk(CancellationToken()) { 42 }
        XCTAssertEqual(followUp, 42)
    }

    func testDefaultSafeTransferEngineChunkSizeIs256KiBAndRoundTrips() async throws {
        let engine = SafeTransferEngine()
        XCTAssertEqual(engine.chunkSize, 262_144)

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("OpenLXSSH-chunk256-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }

        let service = try LocalFileService(root: root)
        defer { Task { await service.close() } }

        let payload = Data((0..<(300 * 1024)).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
        let srcURL = root.appendingPathComponent("source.bin")
        try payload.write(to: srcURL)

        let report = try await engine.copy(
            hostID: "local-chunk256",
            source: service,
            sourcePath: try RemotePath("/source.bin"),
            destination: service,
            destinationPath: try RemotePath("/dest.bin"),
            token: CancellationToken()
        )
        XCTAssertTrue(report.allSucceeded)
        let copied = try Data(contentsOf: root.appendingPathComponent("dest.bin"))
        XCTAssertEqual(copied, payload)
        await service.close()
    }

    func testConnectionSocketTCPNoDelayAndDoublyLinkedAllocationTracking() throws {
        XCTAssertEqual(rf_connection_socket(nil), -1)

        // Create a real loopback TCP socket pair to verify TCP_NODELAY and rf_connection_socket.
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(listener, 0)
        defer { Darwin.close(listener) }

        var one: Int32 = 1
        XCTAssertEqual(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size)), 0)

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bindRC = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        XCTAssertEqual(bindRC, 0)
        XCTAssertEqual(Darwin.listen(listener, 1), 0)

        var boundAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameRC = withUnsafeMutablePointer(to: &boundAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(listener, $0, &addrLen)
            }
        }
        XCTAssertEqual(nameRC, 0)

        let client = socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(client, 0)
        defer { Darwin.close(client) }

        let connectRC = withUnsafePointer(to: &boundAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        XCTAssertEqual(connectRC, 0)

        let accepted = Darwin.accept(listener, nil, nil)
        XCTAssertGreaterThanOrEqual(accepted, 0)
        defer { Darwin.close(accepted) }

        guard let conn = rf_connection_create(client) else {
            return XCTFail("rf_connection_create failed on loopback TCP socket")
        }
        let ownedFD = rf_connection_socket(conn)
        XCTAssertGreaterThanOrEqual(ownedFD, 0)
        XCTAssertNotEqual(ownedFD, client)

        var nodelay: Int32 = 0
        var optLen = socklen_t(MemoryLayout<Int32>.size)
        XCTAssertEqual(getsockopt(ownedFD, IPPROTO_TCP, TCP_NODELAY, &nodelay, &optLen), 0)
        XCTAssertNotEqual(nodelay, 0, "TCP_NODELAY must be enabled on adopted TCP sockets")

        // Exercise O(1) doubly-linked allocation tracking across many allocations and reclaim on close.
        let allocCount = 2000
        var responses = [LIBSSH2_USERAUTH_KBDINT_RESPONSE](repeating: LIBSSH2_USERAUTH_KBDINT_RESPONSE(), count: allocCount)
        let secret: [UInt8] = [0x53, 0x65, 0x63, 0x72, 0x65, 0x74]
        for i in 0..<allocCount {
            let rc = secret.withUnsafeBufferPointer { buf in
                rf_keyboard_set_response(conn, &responses, Int32(i), buf.baseAddress, buf.count)
            }
            XCTAssertEqual(rc, 0)
        }

        rf_connection_close(conn)
        XCTAssertEqual(rf_connection_socket(conn), -1, "Closed connection must return -1 from rf_connection_socket")
        rf_connection_destroy(conn)
    }

    func testEventDrivenShellZeroIdlePollingImmediateWakeupAndZeroFDLeak() async throws {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            return XCTFail("socketpair failed")
        }
        defer { fds.forEach { Darwin.close($0) } }

        let readCalls = LockedCounter()
        let steps = NativeShellPumpSteps(
            now: { .now },
            poll: { _, _ in Int32(RF_SHELL_POLL_INBOUND) },
            write: { _, _, len, _ in Int32(len) },
            read: { c, buffer, length, _ in
                readCalls.increment()
                let fd = rf_connection_socket(c)
                guard fd >= 0 else { return Int32(RF_CLOSED) }
                let rc = Darwin.recv(fd, buffer, length, MSG_DONTWAIT)
                if rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return Int32(LIBSSH2_ERROR_EAGAIN)
                }
                return Int32(rc)
            },
            exit: { _, _, _ in Int32(LIBSSH2_ERROR_EAGAIN) },
            eof: { _, _ in 0 },
            resize: { _, _, _, _ in 0 },
            sendEOF: { _, _ in 0 }
        )

        let options = try NativeShellOptions(size: try NativeShellSize(columns: 80, rows: 24), operationTimeout: 5, keepalive: nil)
        let session = try LibSSH2ShellSession(offlineEventDrivenPumpSocket: fds[0], options: options, steps: steps)

        // 1. Verify zero idle polling while waiting on a 60s receive.
        let readTask = Task {
            try await session.receive(maxBytes: 64, wait: 60.0, token: CancellationToken())
        }
        try await Task.sleep(for: .milliseconds(60))
        XCTAssertEqual(readCalls.value, 1, "Event-driven shell must NOT poll while idle")

        // 2. Write bytes to peer socket and verify immediate kqueue wakeup.
        let wakeStart = ContinuousClock.now
        let payload = Array("ping".utf8)
        let sent = payload.withUnsafeBytes { Darwin.send(fds[1], $0.baseAddress!, $0.count, 0) }
        XCTAssertEqual(sent, payload.count)

        let received = try await readTask.value
        let wakeElapsed = wakeStart.duration(to: .now)
        XCTAssertEqual(received, .bytes(Data("ping".utf8)))
        XCTAssertLessThan(wakeElapsed, .milliseconds(50), "kqueue DispatchSourceRead should wake immediately")

        // 3. Verify deadline timer fires cleanly without idle polling.
        let beforeTimerReads = readCalls.value
        let timerStart = ContinuousClock.now
        let timedOut = try await session.receive(maxBytes: 64, wait: 0.04, token: CancellationToken())
        let timerElapsed = timerStart.duration(to: .now)
        XCTAssertEqual(timedOut, .wouldBlock)
        XCTAssertGreaterThanOrEqual(timerElapsed, .milliseconds(30))
        XCTAssertLessThan(timerElapsed, .milliseconds(250))
        XCTAssertLessThanOrEqual(readCalls.value - beforeTimerReads, 3, "Deadline timer must not busy-poll")

        // 4. Verify CancellationToken.cancel() wakes an idle 60s receive immediately.
        let cancelToken = CancellationToken()
        let cancelledRead = Task {
            try await session.receive(maxBytes: 64, wait: 60.0, token: cancelToken)
        }
        try await Task.sleep(for: .milliseconds(20))
        let cancelStart = ContinuousClock.now
        cancelToken.cancel()
        do {
            _ = try await cancelledRead.value
            XCTFail("Expected cancelled error")
        } catch let error as NativeShellError {
            XCTAssertEqual(error.kind, .cancelled)
        }
        XCTAssertLessThan(cancelStart.duration(to: .now), .milliseconds(50))

        await session.close()

        // 5. Verify zero FD leak across 20 cycles of arming kqueue sources and closing.
        let baselineFDs = openFDCount()
        for _ in 0..<20 {
            var pair: [Int32] = [-1, -1]
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
            let s = try LibSSH2ShellSession(offlineEventDrivenPumpSocket: pair[0], options: options, steps: steps)
            let pending = Task { try await s.receive(maxBytes: 64, wait: 60.0, token: CancellationToken()) }
            try await Task.sleep(for: .milliseconds(5))
            await s.close()
            _ = try? await pending.value
            Darwin.close(pair[0])
            Darwin.close(pair[1])
        }
        let afterFDs = openFDCount()
        XCTAssertLessThanOrEqual(afterFDs, baselineFDs + 2, "Repeated event-driven sessions must not leak FDs (baseline=\(baselineFDs), after=\(afterFDs))")
    }
}
