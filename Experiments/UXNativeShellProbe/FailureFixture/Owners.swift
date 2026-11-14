import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore
import UXNativeFailureSupport

/// The only deliberate noncooperation is a checked continuation with an unconditional teardown
/// release. It ignores cancellation until the consumer opens it; no sleeps or blocked worker.
final class NativeFailureProviderGate: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    private var opened = false
    private var calls = 0
    private var returned = false
    private var returnedCancelled = false
    var entered: Bool { lock.withLock { calls == 1 } }
    var snapshot: (Int, Bool, Bool, Bool) { lock.withLock { (calls, returned, returnedCancelled, opened) } }
    func hold() async throws {
        try lock.withLock {
            guard calls == 0 else { throw NativeFailureCheckError.evidence }
            calls += 1
        }
        await withCheckedContinuation { next in
            let immediate = lock.withLock {
                if opened { return true }
                continuation = next; return false
            }
            if immediate { next.resume() }
        }
    }
    func recordReturn(cancelled: Bool) { lock.withLock { returned = true; returnedCancelled = cancelled } }
    func release() {
        let next = lock.withLock {
            opened = true
            let value = continuation; continuation = nil; return value
        }
        next?.resume()
    }
}
final class NativeFailureCallCount: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    func increment() { lock.withLock { calls += 1 } }
    var value: Int { lock.withLock { calls } }
}
final class NativeFailureStop: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    private var sources: [DispatchSourceSignal] = []
    var requested: Bool { lock.withLock { stopped } }
    init() {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global(qos: .userInitiated))
            source.setEventHandler { [weak self] in self?.mark() }
            source.resume(); sources.append(source)
        }
    }
    private func mark() { lock.withLock { stopped = true } }
    func close() { sources.forEach { $0.cancel() }; sources.removeAll() }
}

/// Holds public test trust bytes and inode via the mature private-file gate, not user ~/.ssh.
struct NativeFailurePublicFile {
    let path: String
    let bytes: Data
    let device: dev_t
    let inode: ino_t
    init(_ path: String) throws {
        self.path = path
        let held = StableFixtureFiles(); try held.hold(path, directory: false)
        var info = stat()
        guard lstat(path, &info) == 0 else { throw NativeFailureCheckError.contract }
        bytes = try StableFixtureFiles.read(path, limit: 4096)
        try held.check(); device = info.st_dev; inode = info.st_ino
    }
    func compare() throws -> (bytes: Bool, inode: Bool) {
        let held = StableFixtureFiles(); try held.hold(path, directory: false)
        var info = stat()
        guard lstat(path, &info) == 0 else { throw NativeFailureCheckError.cleanup }
        let current = try StableFixtureFiles.read(path, limit: 4096)
        try held.check()
        return (current == bytes, info.st_dev == device && info.st_ino == inode)
    }
}

/// Deletes only exact raw test files created below a newly owned marked root; never a recursive
/// user-selected path or original credential generation. No fixture/server files are removed.
final class NativeFailureRunRoot {
    static let marker = "NATIVE-FAILURE-LIVE-CONSUMER-R1\n"
    let path: String
    private let descriptor: Int32
    private let device: dev_t
    private let inode: ino_t
    init(buildRoot: String) throws {
        let requested = buildRoot + "/native-failure-run-" + UUID().uuidString.lowercased()
        path = requested
        guard mkdir(requested, 0o700) == 0 else { throw NativeFailureCheckError.cleanup }
        let fd = open(requested, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { _ = rmdir(requested); throw NativeFailureCheckError.cleanup }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else {
            Darwin.close(fd); _ = rmdir(requested); throw NativeFailureCheckError.cleanup
        }
        do { try PrivateInput.writeExclusive(Data(Self.marker.utf8), to: requested + "/.native-failure-run-owner") }
        catch {
            _ = unlinkat(fd, ".native-failure-run-owner", 0)
            Darwin.close(fd); _ = rmdir(requested); throw error
        }
        // Transfer only after all throwing work, so a throwing initializer never double-closes.
        descriptor = fd; device = info.st_dev; inode = info.st_ino
    }
    deinit { Darwin.close(descriptor) }
    func cleanup() throws {
        var current = stat()
        guard lstat(path, &current) == 0, current.st_dev == device, current.st_ino == inode else {
            throw NativeFailureCheckError.cleanup
        }
        try StableFixtureFiles.checkMarker(directory: path, file: ".native-failure-run-owner", expected: Self.marker)
        if faccessat(descriptor, "trust", F_OK, AT_SYMLINK_NOFOLLOW) == 0 {
            let trust = openat(descriptor, "trust", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard trust >= 0 else { throw NativeFailureCheckError.cleanup }
            defer { Darwin.close(trust) }
            try PrivateInput.checkDirectory(path + "/trust")
            let names = try FileManager.default.contentsOfDirectory(atPath: path + "/trust")
            guard Set(names).isSubset(of: ["known_hosts", "trust.lock"]) else { throw NativeFailureCheckError.cleanup }
            for name in names {
                _ = try StableFixtureFiles.read(path + "/trust/" + name, limit: 4096)
                guard unlinkat(trust, name, 0) == 0 else { throw NativeFailureCheckError.cleanup }
            }
            guard unlinkat(descriptor, "trust", AT_REMOVEDIR) == 0 else { throw NativeFailureCheckError.cleanup }
        }
        guard try FileManager.default.contentsOfDirectory(atPath: path) == [".native-failure-run-owner"],
              unlinkat(descriptor, ".native-failure-run-owner", 0) == 0, rmdir(path) == 0 else {
            throw NativeFailureCheckError.cleanup
        }
        var after = stat()
        guard lstat(path, &after) != 0, errno == ENOENT else { throw NativeFailureCheckError.cleanup }
    }
}
