import Darwin
import Foundation
import RealIntegrationCore

/// Metadata-only fixed child protocol. All reads/writes have an absolute deadline
/// and <=4KiB lines. Never interprets SSH traffic or accepts a command/path override.
actor DiskManagement {
    private let process: Process
    private let input: FileHandle
    private let output: FileHandle
    private let id: String
    private let deadline: UInt64
    private var actions: Set<String> = []
    private(set) var events: [HelperEvent] = []
    private(set) var stopped = false
    init(path: String, id: String) throws {
        let child = Process(), incoming = Pipe(), outgoing = Pipe()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        child.arguments = [BuildLocation.managementScript, "live", "--case", path, "--primary-reviewed"]
        child.environment = ["PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "PYTHONDONTWRITEBYTECODE":"1"]
        child.standardInput = incoming; child.standardOutput = outgoing; child.standardError = FileHandle.nullDevice
        // The test executable owns no arbitrary child input; ignore only its
        // own SIGPIPE so an exited metadata child produces a handled EPIPE.
        _ = Darwin.signal(SIGPIPE, SIG_IGN)
        try child.run()
        try incoming.fileHandleForReading.close(); try outgoing.fileHandleForWriting.close()
        self.process = child; self.input = incoming.fileHandleForWriting; self.output = outgoing.fileHandleForReading
        self.id = id; self.deadline = DispatchTime.now().uptimeNanoseconds + 135_000_000_000
        for fd in [input.fileDescriptor, output.fileDescriptor] {
            guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0 else { throw DiskError.helper }
        }
    }
    private func wait(_ fd: Int32, _ event: Int16, until limit: UInt64) throws {
        while DispatchTime.now().uptimeNanoseconds < min(limit, deadline) {
            var descriptor = pollfd(fd: fd, events: event, revents: 0)
            let result = poll(&descriptor, 1, 50)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw DiskError.helper }
            if result > 0 { return }
        }
        throw DiskError.timeout
    }
    private func readEvent(expected: String, seconds: UInt64 = 15) throws -> HelperEvent {
        let limit = min(deadline, DispatchTime.now().uptimeNanoseconds + seconds * 1_000_000_000)
        var bytes = Data()
        while bytes.count <= 4096 {
            try wait(output.fileDescriptor, Int16(POLLIN), until: limit)
            var value: UInt8 = 0
            let count = Darwin.read(output.fileDescriptor, &value, 1)
            if count < 0 && [EAGAIN, EINTR].contains(errno) { continue }
            guard count == 1 else { throw DiskError.helper }
            bytes.append(value)
            if value == 10 {
                guard bytes.count <= 4096 else { throw DiskError.helper }
                let event = try JSONDecoder().decode(HelperEvent.self, from: bytes)
                try event.validate(id: id, event: expected)
                events.append(event); return event
            }
        }
        throw DiskError.helper
    }
    func ready() throws -> HelperEvent {
        guard events.isEmpty else { throw DiskError.helper }
        return try readEvent(expected: "ready", seconds: 30)
    }
    func command(_ action: String) throws -> HelperEvent {
        guard ["fill", "sample", "release", "stop"].contains(action), !stopped,
              !actions.contains(action) else { throw DiskError.helper }
        actions.insert(action)
        let bytes = try JSONSerialization.data(withJSONObject: ["caseID":id, "action":action]) + Data([10])
        guard bytes.count <= 1024 else { throw DiskError.helper }
        let limit = min(deadline, DispatchTime.now().uptimeNanoseconds + 3_000_000_000)
        var offset = 0
        while offset < bytes.count {
            try wait(input.fileDescriptor, Int16(POLLOUT), until: limit)
            let count = bytes.withUnsafeBytes { Darwin.write(input.fileDescriptor, $0.baseAddress!.advanced(by:offset), $0.count-offset) }
            if count < 0 && [EAGAIN, EINTR].contains(errno) { continue }
            guard count > 0 else { throw DiskError.helper }; offset += count
        }
        return try readEvent(expected: action == "fill" ? "filled" : action == "sample" ? "sampled" : "released")
    }
    func stop() async -> Bool {
        if stopped { return !process.isRunning && process.terminationStatus == 0 }
        let receipt = try? command("stop")
        stopped = true
        try? input.close()
        // Closing our pipe asks the held helper to release even if event parsing
        // failed. Never kill/discover arbitrary containers or start replacement exec.
        let end = min(deadline, DispatchTime.now().uptimeNanoseconds + 125_000_000_000)
        while process.isRunning && DispatchTime.now().uptimeNanoseconds < end {
            try? await Task.sleep(for:.milliseconds(25))
        }
        if process.isRunning {
            process.terminate()
            for _ in 0..<40 where process.isRunning { try? await Task.sleep(for:.milliseconds(25)) }
        }
        if process.isRunning {
            _ = Darwin.kill(process.processIdentifier, SIGKILL) // only this unreaped Process child
            for _ in 0..<40 where process.isRunning { try? await Task.sleep(for:.milliseconds(25)) }
        }
        if !process.isRunning { process.waitUntilExit() }
        try? output.close()
        return !process.isRunning && process.terminationStatus == 0 && receipt?.directoryRemoved == true && receipt?.availableBytes == DiskFixed.capacity
    }
}
