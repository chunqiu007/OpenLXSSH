import Darwin
import Foundation

/// Synchronous worker-only runner. The production call site fixes ssh-keygen/arguments/environment.
/// This object is the sole waiter for its direct child: no Foundation Process reaper, SIGCHLD
/// handler or external waitpid(-1) may consume that child. A PID is signalled only while owned
/// and unreaped, so an exited zombie still reserves the PID until our waitpid consumes it.
/// Internal configurability exists only for the separate XCTest fixture; it is not public API.
enum BoundedToolRunner {
    enum Failure: Error, Equatable {
        case invalidInput
        case launch(Int32)
        case io(Int32)
        case wait(Int32)
        case timedOut
        case outputLimit
    }

    struct Result {
        let waitStatus: Int32
        let output: Data
        var exitedSuccessfully: Bool { (waitStatus & 0x7f) == 0 && (waitStatus >> 8) == 0 }
    }

    static func run(executable: String, arguments: [String], input: Data,
                    timeout: Duration = .seconds(3), outputLimit: Int = 4095) throws -> Result {
        guard input.count <= 1_048_576, (0...1_048_576).contains(outputLimit),
              timeout > .zero, timeout <= .seconds(10), executable.hasPrefix("/"),
              !([executable] + arguments).contains(where: { $0.utf8.contains(0) }) else {
            throw Failure.invalidInput
        }
        let inputPipe = try makePipe()
        defer { inputPipe.closeRead(); inputPipe.closeWrite() }
        let outputPipe = try makePipe()
        defer { outputPipe.closeRead(); outputPipe.closeWrite() }
        try nonblocking(inputPipe.write)
        try nonblocking(outputPipe.read)
        guard fcntl(inputPipe.write, F_SETNOSIGPIPE, 1) == 0 else { throw Failure.io(errno) }

        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        try check(posix_spawn_file_actions_init(&actions))
        defer { posix_spawn_file_actions_destroy(&actions) }
        try check(posix_spawnattr_init(&attributes))
        defer { posix_spawnattr_destroy(&attributes) }
        try check(posix_spawn_file_actions_adddup2(&actions, inputPipe.read, STDIN_FILENO))
        try check(posix_spawn_file_actions_adddup2(&actions, outputPipe.write, STDOUT_FILENO))
        try check(posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0))
        for fd in [inputPipe.read, inputPipe.write, outputPipe.read, outputPipe.write] {
            try check(posix_spawn_file_actions_addclose(&actions, fd))
        }
        var mask = sigset_t()
        var defaults = sigset_t()
        sigemptyset(&mask)
        sigemptyset(&defaults)
        for number in [SIGTERM, SIGINT, SIGHUP, SIGPIPE, SIGCHLD] { sigaddset(&defaults, number) }
        try check(posix_spawnattr_setsigmask(&attributes, &mask))
        try check(posix_spawnattr_setsigdefault(&attributes, &defaults))
        try check(posix_spawnattr_setflags(&attributes,
            Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)))
        let argv = ([executable] + arguments).map { strdup($0) } + [nil]
        let environmentStrings: [String] = ["PATH=/usr/bin:/bin", "LC_ALL=C"]
        let environment = environmentStrings.map { strdup($0) } + [nil]
        defer {
            for pointer in argv { free(pointer) }
            for pointer in environment { free(pointer) }
        }
        guard argv.dropLast().allSatisfy({ $0 != nil }),
              environment.dropLast().allSatisfy({ $0 != nil }) else { throw Failure.launch(ENOMEM) }
        var identifier: pid_t = 0
        let deadline = ContinuousClock.now.advanced(by: timeout)
        let launchResult = argv.withUnsafeBufferPointer { argv in
            environment.withUnsafeBufferPointer { environment in
                posix_spawn(&identifier, executable, &actions, &attributes,
                            UnsafeMutablePointer(mutating: argv.baseAddress!),
                            UnsafeMutablePointer(mutating: environment.baseAddress!))
            }
        }
        try check(launchResult)
        let child = OwnedChild(identifier)
        defer { child.finish() }
        // Parent never keeps the child's ends alive. Remaining parent ends close in the outer defer.
        inputPipe.closeRead()
        outputPipe.closeWrite()
        var inputOpen = true
        var outputOpen = true
        var offset = 0
        var output = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            try child.pollStatus()
            if child.status != nil && !outputOpen { break }
            guard ContinuousClock.now < deadline else { throw Failure.timedOut }
            var progressed = false
            if outputOpen {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(outputPipe.read, $0.baseAddress, $0.count) }
                if count > 0 {
                    guard output.count + count <= outputLimit else { throw Failure.outputLimit }
                    output.append(contentsOf: buffer.prefix(count))
                    progressed = true
                } else if count == 0 {
                    outputOpen = false
                    progressed = true
                } else if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                    throw Failure.io(errno)
                }
            }
            if inputOpen {
                if offset == input.count {
                    inputPipe.closeWrite()
                    inputOpen = false
                    progressed = true
                } else {
                    let count = input.withUnsafeBytes {
                        Darwin.write(inputPipe.write, $0.baseAddress!.advanced(by: offset), min(4096, input.count - offset))
                    }
                    if count > 0 {
                        offset += count
                        progressed = true
                    } else if count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                        throw Failure.io(errno)
                    }
                }
            }
            if !progressed { Thread.sleep(forTimeInterval: 0.002) }
        }
        return Result(waitStatus: child.status!, output: output)
    }

    private final class Descriptors {
        var read: Int32
        var write: Int32
        init(read: Int32, write: Int32) { self.read = read; self.write = write }
        func closeRead() {
            if read >= 0 { close(read); read = -1 }
        }
        func closeWrite() {
            if write >= 0 { close(write); write = -1 }
        }
    }

    private static func makePipe() throws -> Descriptors {
        var descriptors: [Int32] = [-1, -1]
        guard pipe(&descriptors) == 0 else { throw Failure.io(errno) }
        defer { close(descriptors[0]); close(descriptors[1]) }
        // Keep sources away from 0/1/2, including in hosts with a closed standard descriptor.
        let read = fcntl(descriptors[0], F_DUPFD_CLOEXEC, 3)
        guard read >= 0 else { throw Failure.io(errno) }
        let write = fcntl(descriptors[1], F_DUPFD_CLOEXEC, 3)
        guard write >= 0 else { close(read); throw Failure.io(errno) }
        return Descriptors(read: read, write: write)
    }

    private static func nonblocking(_ fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw Failure.io(errno) }
    }

    private static func check(_ result: Int32) throws {
        if result != 0 { throw Failure.launch(result) }
    }

    private final class OwnedChild {
        private var identifier: pid_t?
        private(set) var status: Int32?
        init(_ identifier: pid_t) { self.identifier = identifier }

        func pollStatus() throws {
            guard let identifier else { return }
            var value: Int32 = 0
            let result = waitpid(identifier, &value, WNOHANG)
            if result == identifier {
                self.identifier = nil // Clear ownership before any further signal can be attempted.
                status = value
            } else if result < 0 && errno != EINTR {
                let failure = errno
                self.identifier = nil // Includes ECHILD: do not signal an externally reaped PID.
                throw Failure.wait(failure)
            }
        }

        func finish() {
            guard identifier != nil else { return }
            send(SIGTERM)
            if pollUntil(.now.advanced(by: .milliseconds(50))) { return }
            send(SIGKILL)
            if pollUntil(.now.advanced(by: .seconds(1))) { return }
            // A kernel-stuck child must not hang the caller. Transfer sole wait ownership to a
            // background reaper; it sends no signals and cannot race with this owner afterwards.
            guard let remaining = identifier else { return }
            identifier = nil
            DispatchQueue.global(qos: .utility).async {
                var status: Int32 = 0
                while true {
                    let result = waitpid(remaining, &status, WNOHANG)
                    if result == remaining || (result < 0 && errno != EINTR) { return }
                    Thread.sleep(forTimeInterval: 0.01)
                }
            }
        }

        private func send(_ signal: Int32) {
            // No other thread/reaper can clear ownership between this check and kill.
            if let identifier { _ = kill(identifier, signal) }
        }

        private func pollUntil(_ deadline: ContinuousClock.Instant) -> Bool {
            repeat {
                try? pollStatus()
                if identifier == nil { return true }
                Thread.sleep(forTimeInterval: 0.002)
            } while ContinuousClock.now < deadline
            return false
        }
    }
}
