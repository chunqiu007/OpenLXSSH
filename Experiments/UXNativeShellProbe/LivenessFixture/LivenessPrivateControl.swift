import Darwin
import Foundation
import RealIntegrationCore
import UXNativeShellProbeSupport

/// Inherited anonymous FIFOs only. Terminal SSH bytes never share these descriptors. The
/// supervisor passes public fixed schemas; arbitrary nesting/duplicate keys/replay are refused.
struct NativeLivenessPrivateControl: Sendable {
    let ownerPID: Int32
    init(ownerPID: Int32) throws {
        guard getppid() == ownerPID, ownerPID > 1 else { throw NativeLivenessControlError.owner }
        for fd: Int32 in [0, 1] {
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFIFO, info.st_uid == getuid(),
                  fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw NativeLivenessControlError.owner }
        }
        guard fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK) == 0,
              fcntl(1, F_SETFL, fcntl(1, F_GETFL) | O_NONBLOCK) == 0 else { throw NativeLivenessControlError.owner }
        self.ownerPID = ownerPID
        signal(SIGPIPE, SIG_IGN)
    }
    func send(_ value: [String: Any]) throws {
        guard getppid() == ownerPID else { throw NativeLivenessControlError.owner }
        let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) + Data([10])
        guard !bytes.isEmpty, bytes.count < 4096 else { throw NativeLivenessControlError.schema }
        var offset = 0
        let deadline = ContinuousClock.now.advanced(by: .seconds(1))
        while offset < bytes.count {
            guard getppid() == ownerPID, .now < deadline else { throw NativeLivenessControlError.owner }
            let written = bytes.withUnsafeBytes { Darwin.write(1, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if written < 0, errno == EINTR { continue }
            if written < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                var fd = pollfd(fd: 1, events: Int16(POLLOUT), revents: 0)
                _ = Darwin.poll(&fd, 1, 10); continue
            }
            guard written > 0 else { throw NativeLivenessControlError.owner }
            offset += written
        }
    }
    func receive(op: String, sequence: Int, contract: NativeLivenessContract, session: String,
                 seconds: Double, state: inout NativeLivenessControlSequence) async throws -> [String: Any] {
        let deadline = ContinuousClock.now.advanced(by: .seconds(seconds))
        var data = Data(), buffer = [UInt8](repeating: 0, count: 2048)
        while .now < deadline {
            guard getppid() == ownerPID else { throw NativeLivenessControlError.owner }
            let count = Darwin.read(0, &buffer, buffer.count)
            if count < 0, [EAGAIN, EWOULDBLOCK, EINTR].contains(errno) {
                try await Task.sleep(for: .milliseconds(5)); continue
            }
            guard count > 0 else { throw NativeLivenessControlError.owner }
            data.append(contentsOf: buffer.prefix(count))
            guard data.count < 2048 else { throw NativeLivenessControlError.schema }
            if data.last == 10 {
                let common: Set<String> = ["op", "sequence", "run", "role", "session", "stamp", "ok"]
                let extra: Set<String> = op == "drop-confirmed" ? ["armedAt", "armedWall", "relayNow", "relayWall"] : []
                let value = try NativeLivenessJSON.frameObject(data, keys: common.union(extra))
                guard value["op"] as? String == op, NativeLivenessJSON.integer(value["sequence"]) == sequence,
                      value["run"] as? String == contract.run, value["role"] as? String == contract.role.rawValue,
                      value["session"] as? String == session, NativeLivenessJSON.boolean(value["ok"]) == true,
                      let stamp = NativeLivenessJSON.finite(value["stamp"]) else { throw NativeLivenessControlError.schema }
                try state.accept(op: op, sequence: sequence, run: contract.run, role: contract.role, session: session, stamp: stamp)
                return value
            }
        }
        throw NativeLivenessControlError.deadline
    }
}
final class NativeLivenessStop: @unchecked Sendable {
    private let lock = NSLock()
    private var requested = false
    private var sources: [DispatchSourceSignal] = []
    var stopped: Bool { lock.withLock { requested } }
    init() {
        for number in [SIGTERM, SIGINT] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
            source.setEventHandler { [weak self] in self?.mark() }
            source.resume(); sources.append(source)
        }
    }
    private func mark() { lock.withLock { requested = true } }
    func close() { sources.forEach { $0.cancel() }; sources.removeAll() }
}
