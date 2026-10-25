import Darwin
import Foundation
import ProbePOSIX

public enum ProbeError: Error, Equatable, Sendable {
    case invalidConfiguration
    case alreadyStarted
    case closed
    case notRunning
    case inputTooLarge
    case systemCall(String, Int32)
}

public struct WindowSize: Equatable, Sendable {
    public let rows: UInt16
    public let columns: UInt16

    public static let probeDefault = WindowSize(rows: 24, columns: 80, validated: ())

    private init(rows: UInt16, columns: UInt16, validated: Void) {
        self.rows = rows
        self.columns = columns
    }

    public init(rows: UInt16, columns: UInt16) throws {
        guard rows > 0, columns > 0 else { throw ProbeError.invalidConfiguration }
        self.rows = rows
        self.columns = columns
    }
}

public enum StopReason: String, Sendable {
    case exited, closed, cancelled, timedOut, ioError, outputLimit
}

public struct ProbeResult: Equatable, Sendable {
    public let reason: StopReason
    public let exitCode: Int32?
    public let signal: Int32?
    public let errorNumber: Int32?
    public let output: Data
    public let reachedEOF: Bool
    public let escalatedToKill: Bool
    public let childReaped: Bool
    public let masterClosed: Bool
    public let ownedAsyncTasks: Int
}

public struct ResourceSnapshot: Sendable {
    public let pid: pid_t?
    public let masterFD: Int32?
    public let slaveName: String?
    public let ownedAsyncTasks: Int
    public let pendingInputBytes: Int
    public let capturedOutputBytes: Int
    public let closeRequested: Bool
}

private struct SpawnedPTY: Sendable {
    let pid: pid_t
    let master: Int32
    let name: String
}

// Keep all pointer lifetimes inside one synchronous, nonisolated call.
private func spawnPTY(_ configuration: PTYProbeSession.Configuration) throws -> SpawnedPTY {
    var child: pid_t = 0
    var master: Int32 = -1
    var name = [CChar](repeating: 0, count: 128)
    let argv: [UnsafeMutablePointer<CChar>?] = ([configuration.executable] + configuration.arguments).map { strdup($0) } + [nil]
    let environment: [String] = ["PATH=/usr/bin:/bin", "TERM=xterm-256color", "LC_ALL=C"]
    let envp: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) } + [nil]
    defer {
        for value in argv { free(value) }
        for value in envp { free(value) }
    }
    guard argv.dropLast().allSatisfy({ $0 != nil }), envp.dropLast().allSatisfy({ $0 != nil }) else {
        throw ProbeError.systemCall("strdup", ENOMEM)
    }
    let code = argv.withUnsafeBufferPointer { argvBuffer in
        envp.withUnsafeBufferPointer { environmentBuffer in
            probe_spawn_pty(
                configuration.executable, argvBuffer.baseAddress, environmentBuffer.baseAddress,
                configuration.size.rows, configuration.size.columns,
                &child, &master, &name, name.count
            )
        }
    }
    guard code == 0 else { throw ProbeError.systemCall("spawn PTY", code) }
    let slaveName = String(decoding: name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    return SpawnedPTY(pid: child, master: master, name: slaveName)
}

/// Experiment-only, single-use owner. Every syscall and state transition is actor-isolated.
/// One cooperative polling task performs nonblocking PTY I/O and waitpid(WNOHANG).
/// Output/input are capped; this is a finite probe, NOT a production terminal data path.
public actor PTYProbeSession {
    public struct Configuration: Sendable {
        public let executable: String
        public let arguments: [String]
        public let size: WindowSize
        public let timeout: Duration
        public let terminationGrace: Duration
        public let maximumOutputBytes: Int
        public let maximumInputBytes: Int

        public init(
            executable: String, arguments: [String],
            size: WindowSize = .probeDefault,
            timeout: Duration = .seconds(3), terminationGrace: Duration = .milliseconds(100),
            maximumOutputBytes: Int = 1_048_576, maximumInputBytes: Int = 65_536
        ) throws {
            guard executable.hasPrefix("/"), !executable.utf8.contains(0),
                  arguments.allSatisfy({ !$0.utf8.contains(0) }),
                  timeout > .zero, timeout <= .seconds(30),
                  terminationGrace >= .zero, terminationGrace <= .seconds(2),
                  maximumOutputBytes > 0, maximumOutputBytes <= 4_194_304,
                  maximumInputBytes > 0, maximumInputBytes <= 1_048_576 else {
                throw ProbeError.invalidConfiguration
            }
            self.executable = executable
            self.arguments = arguments
            self.size = size
            self.timeout = timeout
            self.terminationGrace = terminationGrace
            self.maximumOutputBytes = maximumOutputBytes
            self.maximumInputBytes = maximumInputBytes
        }
    }

    private let configuration: Configuration
    private var started = false
    private var pid: pid_t?
    private var masterFD: Int32?
    private var slaveName: String?
    private var pumpTask: Task<Void, Never>?
    private var deadline: ContinuousClock.Instant?
    private var killDeadline: ContinuousClock.Instant?
    private var drainDeadline: ContinuousClock.Instant?
    private var reason: StopReason?
    private var errorNumber: Int32?
    private var escalated = false
    private var reachedEOF = false
    private var reaped = false
    private var exitCode: Int32?
    private var exitSignal: Int32?
    private var output = Data()
    private var pendingInput = Data()
    private var completed: ProbeResult?
    private var waiters: [CheckedContinuation<ProbeResult, Never>] = []

    deinit {
        // Normally finish() already closed it; also cover an owner that was never started.
        if let fd = masterFD { _ = Darwin.close(fd) }
    }

    public init(configuration: Configuration) {
        self.configuration = configuration
    }

    public func start() throws {
        guard !started else { throw ProbeError.alreadyStarted }
        guard completed == nil, reason == nil else { throw ProbeError.closed }
        let spawned = try spawnPTY(configuration)
        started = true
        pid = spawned.pid
        masterFD = spawned.master
        slaveName = spawned.name
        deadline = .now + configuration.timeout
        // The owner intentionally stays alive until the finite pump has reaped and closed everything.
        pumpTask = Task { [self] in
            while !tick() {
                try? await Task.sleep(for: .milliseconds(2))
            }
        }
    }

    /// Enqueues a bounded input block. Partial writes/EAGAIN are retried by the pump, in order.
    public func send(_ bytes: Data) throws {
        guard started, reason == nil, completed == nil, !reaped, masterFD != nil else {
            throw ProbeError.notRunning
        }
        guard pendingInput.count + bytes.count <= configuration.maximumInputBytes else {
            throw ProbeError.inputTooLarge
        }
        pendingInput.append(bytes)
    }

    /// TIOCSWINSZ also notifies the foreground process group through SIGWINCH.
    public func resize(_ size: WindowSize) throws -> WindowSize {
        guard reason == nil, !reaped, let fd = masterFD else { throw ProbeError.notRunning }
        var value = winsize(ws_row: size.rows, ws_col: size.columns, ws_xpixel: 0, ws_ypixel: 0)
        guard ioctl(fd, TIOCSWINSZ, &value) == 0 else {
            throw ProbeError.systemCall("TIOCSWINSZ", errno)
        }
        var observed = winsize()
        guard ioctl(fd, TIOCGWINSZ, &observed) == 0 else {
            throw ProbeError.systemCall("TIOCGWINSZ", errno)
        }
        return try WindowSize(rows: observed.ws_row, columns: observed.ws_col)
    }

    public func snapshot() -> ResourceSnapshot {
        ResourceSnapshot(
            pid: pid, masterFD: masterFD, slaveName: slaveName,
            ownedAsyncTasks: pumpTask == nil ? 0 : 1,
            pendingInputBytes: pendingInput.count, capturedOutputBytes: output.count,
            closeRequested: reason != nil
        )
    }

    public func capturedOutput() -> Data { output }

    /// Cancellation of a waiting Swift task is bound to this single-use session, never another PID.
    public func wait() async -> ProbeResult {
        await withTaskCancellationHandler {
            if Task.isCancelled { requestStop(.cancelled) }
            return await waitForCompletion()
        } onCancel: {
            Task { await self.requestStop(.cancelled) }
        }
    }

    @discardableResult
    public func close() async -> ProbeResult {
        requestStop(.closed)
        return await waitForCompletion()
    }

    @discardableResult
    public func cancel() async -> ProbeResult {
        requestStop(.cancelled)
        return await waitForCompletion()
    }

    private func waitForCompletion() async -> ProbeResult {
        let ownedTask = pumpTask
        let result: ProbeResult
        if let completed {
            result = completed
        } else {
            if !started { requestStop(.closed) }
            if let completed { result = completed }
            else { result = await withCheckedContinuation { waiters.append($0) } }
        }
        // A returned result means the pump itself has exited, not just that it requested cleanup.
        await ownedTask?.value
        return result
    }

    private func requestStop(_ requestedReason: StopReason) {
        guard completed == nil, reason == nil else { return }
        reason = requestedReason
        pendingInput.removeAll(keepingCapacity: false)
        guard started else {
            finish()
            return
        }
        // Actor serialization prevents PID-reuse/fd-reuse races with reaping and late callers.
        signalOwnedChild(SIGTERM)
        killDeadline = .now + configuration.terminationGrace
        // Keep the master open until TERM/KILL has taken effect. Closing it first sends SIGHUP.
    }

    private func signalOwnedChild(_ signal: Int32) {
        guard let pid, !reaped else { return }
        // The unreaped child pins the PID. Never signal a saved PID after waitpid has returned it.
        if kill(pid, signal) != 0, errno != ESRCH { errorNumber = errno }
    }

    private func tick() -> Bool {
        guard completed == nil else { return true }
        let now = ContinuousClock.now
        readAvailable()
        reapIfExited()
        if !reaped, reason == nil {
            writePendingInput()
            if let deadline, now >= deadline { requestStop(.timedOut) }
        }
        if !reaped, reason != nil, let killDeadline, now >= killDeadline, !escalated {
            signalOwnedChild(SIGKILL)
            escalated = true
        }
        if reaped {
            // The process can exit before the final readable event: drain, do not truncate the tail.
            readAvailable()
            if masterFD != nil, let drainDeadline, now >= drainDeadline {
                errorNumber = ETIMEDOUT
                if reason == nil { reason = .ioError }
                closeMaster()
            }
            if masterFD == nil {
                finish()
                return true
            }
        }
        return false
    }

    private func readAvailable() {
        guard let fd = masterFD else { return }
        var buffer = [UInt8](repeating: 0, count: 4096)
        // Finite work per tick keeps cancel/resize responsive during a flood.
        for _ in 0..<16 {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if count > 0 {
                guard output.count + count <= configuration.maximumOutputBytes else {
                    requestStop(.outputLimit)
                    closeMaster()
                    return
                }
                output.append(contentsOf: buffer.prefix(count))
            } else if count == 0 || (count < 0 && errno == EIO) {
                reachedEOF = true // Darwin PTY hangup may appear as EIO, not read(2) == 0.
                closeMaster()
                return
            } else if errno == EINTR {
                continue
            } else if errno == EAGAIN || errno == EWOULDBLOCK {
                return
            } else {
                errorNumber = errno
                requestStop(.ioError)
                closeMaster()
                return
            }
        }
    }

    private func writePendingInput() {
        guard let fd = masterFD, !pendingInput.isEmpty else { return }
        let count = pendingInput.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, min($0.count, 4096)) }
        if count > 0 {
            pendingInput.removeFirst(count)
        } else if count < 0, errno != EAGAIN, errno != EWOULDBLOCK, errno != EINTR {
            errorNumber = errno
            requestStop(.ioError)
        }
    }

    private func reapIfExited() {
        guard let child = pid, !reaped else { return }
        var status: Int32 = 0
        let result = waitpid(child, &status, WNOHANG)
        if result == child {
            let code = probe_exit_code(status)
            let signal = probe_exit_signal(status)
            exitCode = code >= 0 ? code : nil
            exitSignal = signal > 0 ? signal : nil
            reaped = true
            pid = nil
            pendingInput.removeAll(keepingCapacity: false)
            drainDeadline = .now + .milliseconds(250)
        } else if result < 0, errno != EINTR {
            // No external code is allowed to reap our child. Surface rather than hang on violation.
            errorNumber = errno
            reason = .ioError
            pid = nil
            closeMaster()
            finish()
        }
    }

    private func closeMaster() {
        if let fd = masterFD {
            masterFD = nil
            // Do not retry close(EINTR): a reused descriptor must never be closed by a late callback.
            if Darwin.close(fd) != 0 { errorNumber = errno }
        }
    }

    private func finish() {
        guard completed == nil else { return }
        closeMaster()
        pendingInput.removeAll(keepingCapacity: false)
        deadline = nil
        killDeadline = nil
        drainDeadline = nil
        pumpTask = nil
        let result = ProbeResult(
            reason: reason ?? .exited, exitCode: exitCode, signal: exitSignal,
            errorNumber: errorNumber, output: output, reachedEOF: reachedEOF,
            escalatedToKill: escalated, childReaped: reaped,
            masterClosed: masterFD == nil, ownedAsyncTasks: 0
        )
        completed = result
        let pendingWaiters = waiters
        waiters.removeAll(keepingCapacity: false)
        for waiter in pendingWaiters { waiter.resume(returning: result) }
    }
}
