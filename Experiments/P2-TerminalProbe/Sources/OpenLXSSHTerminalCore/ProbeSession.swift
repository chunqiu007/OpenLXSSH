import AppKit
import Darwin
import SwiftTerm

public struct ProbeResult: Codable {
    public let pid: Int32
    public let exitCode: Int32?
    public let closedByUser: Bool
    public let escalated: Bool
    public let bytesReceived: Int
    public let peakInputBytes: Int
}

public enum ProbeSessionError: Error { case busy, invalidExecutable, launchFailed, inputFull, inactive }

/// Main-queue facade for one upstream LocalProcess. LocalProcess exclusively
/// creates/reads/closes/reaps its PTY/child. The preview API provides checked,
/// serialized writes and safe resize. The stable comparison borrows childfd
/// only for nonblocking writes and never duplicates or closes it.
/// No additional PTY or process monitor is created by the adapter.
@MainActor
public final class ProbeSession: NSObject, @MainActor TerminalViewDelegate, LocalProcessDelegate {
    public let terminal = ProbeTerminalView()
    public private(set) var process: LocalProcess?
    public private(set) var result: ProbeResult?
    public private(set) var pendingInputBytes = 0
    public private(set) var bytesReceived = 0
    public private(set) var inputError: String?
    public var onStateChange: (() -> Void)?
    public var onOutput: (() -> Void)?
    public var onExit: ((ProbeResult) -> Void)?

    private var pid: pid_t = 0
    private var closing = false
    private var escalated = false
    private var closeDeadline: TimeInterval = 0
    private var peakInputBytes = 0
    private var input = [UInt8]()
    private var offset = 0
    private var writeInFlight = false
    private var timer: Timer?

    public override init() {
        super.init()
        terminal.terminalDelegate = self
    }

    public var isRunning: Bool { pid > 0 && result == nil }
    public var childPID: pid_t { pid }
    public var masterFD: Int32 { process?.childfd ?? -1 }
    public var ownedTimerCount: Int { timer == nil ? 0 : 1 }

    public func start(executable: String, arguments: [String] = [], directory: String) throws {
        guard process == nil, result == nil else { throw ProbeSessionError.busy }
        guard executable.hasPrefix("/"), !executable.utf8.contains(0),
              arguments.allSatisfy({ !$0.utf8.contains(0) }),
              FileManager.default.isExecutableFile(atPath: executable) else { throw ProbeSessionError.invalidExecutable }
        // No inherited credential/agent environment and no shell/startup files.
        let environment = ["PATH=/usr/bin:/bin", "TERM=xterm-256color", "LANG=en_US.UTF-8",
                           "LC_CTYPE=UTF-8", "HOME=\(directory)", "TMPDIR=\(directory)"]
        let runner = LocalProcess(delegate: self, dispatchQueue: .main)
        process = runner
        #if P2_PREVIEW_API
        guard case .success = runner.startProcessChecked(executable: executable, args: arguments,
                                                         environment: environment, currentDirectory: directory) else {
            process = nil
            throw ProbeSessionError.launchFailed
        }
        #else
        runner.startProcess(executable: executable, args: arguments,
                            environment: environment, currentDirectory: directory)
        #endif
        pid = runner.shellPid
        guard pid > 0, runner.childfd >= 0 else {
            process = nil
            throw ProbeSessionError.launchFailed
        }
        // Older SwiftTerm doesn't mark its master close-on-exec. Child #2 must
        // not inherit child #1's PTY. No additional descriptor ownership.
        let fd = runner.childfd
        _ = fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC)
        #if P2_PREVIEW_API
        // The normal callback must follow all already-readable output; never
        // use a fixed delay in this adapter to guess whether output was read.
        runner.drainTimeout = .infinity
        runner.killEscalationDelay = 0.35
        #else
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        #endif
        onStateChange?()
    }

    /// Admission is all-or-nothing. Full input is visibly rejected rather than
    /// silently truncated. A bounded 256 KiB queue retries EAGAIN in order.
    public func enqueue(_ bytes: ArraySlice<UInt8>) throws {
        guard process != nil, !closing else { throw ProbeSessionError.inactive }
        guard bytes.count <= ProbeSettings.maximumInputBytes - pendingInputBytes else {
            inputError = "Input queue full (256 KiB): input was not accepted"
            onStateChange?()
            throw ProbeSessionError.inputFull
        }
        if offset > 0 { input.removeFirst(offset); offset = 0 }
        input.append(contentsOf: bytes)
        pendingInputBytes += bytes.count
        peakInputBytes = max(peakInputBytes, pendingInputBytes)
        flushInput()
        if pendingInputBytes > 0 { ensureTimer() }
    }

    private func flushInput() {
        guard let process, process.childfd >= 0 else { return }
        #if P2_PREVIEW_API
        guard !writeInFlight, pendingInputBytes > 0 else { return }
        let count = min(pendingInputBytes, 16 * 1024)
        let bytes = Array(input[offset..<(offset + count)])
        offset += count
        writeInFlight = true
        // Exactly one bounded upstream DispatchIO write exists at a time.
        process.send(data: bytes[...]) { [weak self] result in
            DispatchQueue.main.async {
                guard let self, self.process != nil, !self.closing else { return }
                self.writeInFlight = false
                self.pendingInputBytes -= count
                if case .failure(let failure) = result {
                    self.inputError = "Local PTY write failed: \(failure); session closing"
                    self.close()
                    return
                }
                if self.pendingInputBytes == 0 { self.input.removeAll(); self.offset = 0 }
                self.flushInput()
            }
        }
        #else
        var budget = 64 * 1024
        while pendingInputBytes > 0 && budget > 0 {
            let count = min(pendingInputBytes, budget)
            let written = input.withUnsafeBytes { raw in
                Darwin.write(process.childfd, raw.baseAddress!.advanced(by: offset), count)
            }
            if written > 0 {
                offset += written
                pendingInputBytes -= written
                budget -= written
            } else if written < 0 && errno == EINTR {
                continue
            } else if written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                return
            } else {
                inputError = "Local PTY write failed (errno \(errno)); session closing"
                close()
                return
            }
        }
        if pendingInputBytes == 0 { input.removeAll(keepingCapacity: false); offset = 0 }
        #endif
    }

    private func ensureTimer() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 0.005, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        if let timer { RunLoop.main.add(timer, forMode: .common) }
    }

    private func tick() {
        #if P2_PREVIEW_API
        if closing {
            if ProcessInfo.processInfo.systemUptime >= closeDeadline { escalated = true }
            var info = siginfo_t()
            let observed = waitid(P_PID, id_t(pid), &info, WEXITED | WNOHANG | WNOWAIT)
            if observed == -1 && errno == ECHILD {
                // Upstream has reaped our child. A recycled PID belonging to
                // somebody else must not keep this session alive.
                finish(exitCode: nil)
                return
            }
        }
        #else
        if closing && !escalated && ProcessInfo.processInfo.systemUptime >= closeDeadline {
            signalOwnedChild(SIGKILL)
            escalated = true
        } else if !closing {
            flushInput()
        }
        #endif
        if !isRunning || (!closing && pendingInputBytes == 0) {
            timer?.invalidate()
            timer = nil
        }
    }

    private func signalOwnedChild(_ value: Int32) {
        guard pid > 0, process != nil else { return }
        // waitid(WNOWAIT) verifies parentage without stealing the upstream
        // reaper's wait. All upstream exit callbacks use the same main queue.
        var info = siginfo_t()
        if waitid(P_PID, id_t(pid), &info, WEXITED | WNOHANG | WNOWAIT) == 0 {
            _ = kill(pid, value)
        }
    }

    public func close() {
        guard process != nil, !closing else { return }
        closing = true
        // Input cancellation is explicit at close, not an output/protocol drop.
        input.removeAll(); offset = 0; pendingInputBytes = 0
        closeDeadline = ProcessInfo.processInfo.systemUptime + 0.35
        #if P2_PREVIEW_API
        // Release the upstream owner to use its PID-safe TERM/KILL reaper.
        // Unlike signaling the published pid from a timer, this cannot race a
        // background reap and kill a reused PID. The observer only waits for
        // our child to disappear; it never reaps or signals anything itself.
        process = nil
        #else
        signalOwnedChild(SIGTERM)
        #endif
        ensureTimer()
        onStateChange?()
    }

    public func setHistory(_ lines: Int) { terminal.changeScrollback(ProbeSettings.history(lines)) }

    public func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
        guard let process, process.childfd >= 0 else { return }
        var size = getWindowSize()
        #if P2_PREVIEW_API
        _ = process.updateWindowSize(&size)
        #else
        _ = PseudoTerminalHelpers.setWinSize(masterPtyDescriptor: process.childfd, windowSize: &size)
        #endif
    }
    public func setTerminalTitle(source: TerminalView, title: String) {}
    public func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    public func scrolled(source: TerminalView, position: Double) {}
    public func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    public func send(source: TerminalView, data: ArraySlice<UInt8>) {
        do { try enqueue(data) } catch { NSSound.beep() }
    }
    // No OSC clipboard reads/writes, URL opening, authentication or secrets.
    public func clipboardRead(source: TerminalView) -> Data? { nil }
    public func clipboardCopy(source: TerminalView, content: Data) {}
    public func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {}

    nonisolated public func getWindowSize() -> winsize {
        MainActor.assumeIsolated {
            winsize(ws_row: UInt16(clamping: terminal.rows), ws_col: UInt16(clamping: terminal.columns), ws_xpixel: 0, ws_ypixel: 0)
        }
    }
    nonisolated public func dataReceived(slice: ArraySlice<UInt8>) {
        MainActor.assumeIsolated {
            bytesReceived += slice.count
            terminal.feed(byteArray: slice)
            onOutput?()
        }
    }
    nonisolated public func processTerminated(_ source: LocalProcess, exitCode: Int32?) {
        MainActor.assumeIsolated {
            guard process === source else { return }
            #if P2_PREVIEW_API
            let normalized = exitCode
            #else
            let normalized = exitCode.flatMap { $0 & 0x7f == 0 ? ($0 >> 8) & 0xff : nil }
            #endif
            finish(exitCode: normalized)
        }
    }

    private func finish(exitCode: Int32?) {
        guard result == nil else { return }
        let completed = ProbeResult(pid: pid, exitCode: exitCode, closedByUser: closing,
                                    escalated: escalated, bytesReceived: bytesReceived, peakInputBytes: peakInputBytes)
        result = completed
        timer?.invalidate(); timer = nil
        input.removeAll(); offset = 0; pendingInputBytes = 0; writeInFlight = false
        process = nil
        onStateChange?()
        onExit?(completed)
    }

    deinit { timer?.invalidate() }
}
