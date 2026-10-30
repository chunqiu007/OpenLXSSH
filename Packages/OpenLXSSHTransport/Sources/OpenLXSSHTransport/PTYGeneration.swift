import AppKit
import Darwin
import SwiftTerm

struct PTYResult {
    let token: SessionToken
    let pid: pid_t
    let exitCode: Int32?
    let cancelled: Bool
    let bytesReceived: Int
    let peakInputBytes: Int
}

/// P2 preview-only adapter. LocalProcess owns every PTY descriptor, reader and
/// wait/reap operation. This facade never signals a published PID or PGID.
@MainActor
final class PTYGeneration: LocalProcessDelegate {
    let token: SessionToken
    private(set) var process: LocalProcess?
    private(set) var pid: pid_t = 0
    private(set) var pendingInputBytes = 0
    private(set) var bytesReceived = 0
    private var peakInputBytes = 0
    private var bytes = [UInt8]()
    private var offset = 0
    private var inFlight = false
    private var closing = false
    private var finished = false
    private var timer: Timer?
    var dimensions: (() -> winsize)?
    var onOutput: ((SessionToken, ArraySlice<UInt8>) -> Void)?
    var onExit: ((PTYResult) -> Void)?
    var onInputFailure: (() -> Void)?

    init(token: SessionToken) { self.token = token }
    func start(_ invocation: DirectSSHInvocation, directory: String) throws {
        guard process == nil, pid == 0 else { throw TransportError.busy }
        let runner = LocalProcess(delegate: self, dispatchQueue: .main)
        runner.drainTimeout = .infinity
        runner.killEscalationDelay = 0.35
        process = runner
        guard case .success = runner.startProcessChecked(executable: invocation.executable, args: invocation.arguments,
            environment: invocation.environment.sorted(by: { $0.key < $1.key }).map { "\($0.key)=\($0.value)" }, currentDirectory: directory) else {
            process = nil; throw SessionFailure.launchFailed
        }
        pid = runner.shellPid
        guard pid > 0, runner.childfd >= 0 else { process = nil; throw SessionFailure.launchFailed }
        _ = fcntl(runner.childfd, F_SETFD, fcntl(runner.childfd, F_GETFD) | FD_CLOEXEC)
    }
    func enqueue(_ input: ArraySlice<UInt8>) throws {
        guard process != nil, !closing, !finished else { throw TransportError.inactive }
        guard input.count <= TerminalSettings.maximumInputBytes - pendingInputBytes else { throw TransportError.inputFull }
        if offset > 0 { bytes.removeFirst(offset); offset = 0 }
        bytes.append(contentsOf: input); pendingInputBytes += input.count
        peakInputBytes = max(peakInputBytes, pendingInputBytes)
        flush()
    }
    private func flush() {
        guard let process, !inFlight, !closing, pendingInputBytes > 0 else { return }
        let count = min(pendingInputBytes, 16 * 1024)
        let chunk = Array(bytes[offset..<(offset + count)])
        offset += count; inFlight = true
        process.send(data: chunk[...]) { [weak self] result in
            DispatchQueue.main.async {
                guard let self, !self.closing, !self.finished else { return }
                self.inFlight = false; self.pendingInputBytes -= count
                if case .failure = result { self.onInputFailure?(); self.cancel(); return }
                if self.pendingInputBytes == 0 { self.bytes.removeAll(); self.offset = 0 }
                self.flush()
            }
        }
    }
    func resize(_ size: inout winsize) { _ = process?.updateWindowSize(&size) }
    func cancel() {
        guard !closing, !finished else { return }
        closing = true
        bytes.removeAll(); offset = 0; pendingInputBytes = 0
        // Upstream deinit's lock protects signal + final reap from PID reuse.
        // No arbitrary descendant/group cleanup is promised by this API.
        process = nil
        timer = Timer.scheduledTimer(withTimeInterval: 0.01, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                var info = siginfo_t()
                if waitid(P_PID, id_t(self.pid), &info, WEXITED | WNOHANG | WNOWAIT) == -1 && errno == ECHILD {
                    self.finish(nil)
                }
            }
        }
        if let timer { RunLoop.main.add(timer, forMode: .common) }
    }
    private func finish(_ code: Int32?) {
        guard !finished else { return }
        finished = true; timer?.invalidate(); timer = nil
        process = nil; bytes.removeAll(); offset = 0; pendingInputBytes = 0; inFlight = false
        onExit?(PTYResult(token: token, pid: pid, exitCode: code, cancelled: closing, bytesReceived: bytesReceived, peakInputBytes: peakInputBytes))
    }
    nonisolated func getWindowSize() -> winsize { MainActor.assumeIsolated { dimensions?() ?? winsize(ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0) } }
    nonisolated func dataReceived(slice: ArraySlice<UInt8>) {
        MainActor.assumeIsolated {
            guard !closing, !finished else { return }
            bytesReceived += slice.count; onOutput?(token, slice)
        }
    }
    nonisolated func processTerminated(_ source: LocalProcess, exitCode: Int32?) {
        let identity = ObjectIdentifier(source)
        MainActor.assumeIsolated {
            guard let process, ObjectIdentifier(process) == identity else { return }
            finish(exitCode)
        }
    }
    isolated deinit { timer?.invalidate() }
}
