import Darwin
import Foundation

/// A retained private directory FD anchors all file operations. No check-then-open by path.
/// File locks coordinate cooperating processes; they are not a sandbox against the same UID.
final class PrivateDirectory: @unchecked Sendable {
    let path: AbsolutePath
    private let descriptor: Int32
    private var lockIdentities: [String: (device: dev_t, inode: ino_t)] = [:]
    private let operationLock = NSLock()
    private static let maxFileSize = 1_048_576

    init(_ requestedPath: AbsolutePath) throws {
        if mkdir(requestedPath.value, 0o700) != 0 && errno != EEXIST {
            throw HostTrustError.systemOperation("mkdir", errno)
        }
        var initial = stat()
        guard lstat(requestedPath.value, &initial) == 0, Self.isDirectory(initial),
              let resolved = realpath(requestedPath.value, nil) else {
            throw HostTrustError.unsafeStorage("private directory")
        }
        defer { free(resolved) }
        path = try AbsolutePath(String(cString: resolved))
        descriptor = open(path.value, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw HostTrustError.systemOperation("open directory", errno) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0, Self.isDirectory(opened),
              initial.st_dev == opened.st_dev, initial.st_ino == opened.st_ino else {
            close(descriptor)
            throw HostTrustError.unsafeStorage("private directory")
        }
    }

    deinit { close(descriptor) }

    func withLock<T>(_ name: String, allowCreation: Bool = false,
                     _ action: (_ created: Bool) throws -> T) throws -> T {
        operationLock.lock()
        defer { operationLock.unlock() }
        try validateDirectory()
        var created = false
        var fd = openat(descriptor, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 && errno == ENOENT && allowCreation {
            fd = openat(descriptor, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
            if fd >= 0 {
                created = true
            } else if errno == EEXIST {
                fd = openat(descriptor, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            }
        }
        guard fd >= 0 else { throw HostTrustError.unsafeStorage("lock file") }
        defer { close(fd) }
        try validateFile(fd)
        let deadline = ContinuousClock.now.advanced(by: .seconds(10))
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            guard errno == EWOULDBLOCK || errno == EAGAIN else {
                throw HostTrustError.systemOperation("flock", errno)
            }
            guard ContinuousClock.now < deadline else {
                throw HostTrustError.systemOperation("flock timeout", ETIMEDOUT)
            }
            Thread.sleep(forTimeInterval: 0.002)
        }
        defer { _ = flock(fd, LOCK_UN) }
        try validateDirectory()
        try validateFile(fd)
        var locked = stat()
        var named = stat()
        guard fstat(fd, &locked) == 0,
              fstatat(descriptor, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              locked.st_dev == named.st_dev, locked.st_ino == named.st_ino else {
            throw HostTrustError.unsafeStorage("replaced lock file")
        }
        if let expected = lockIdentities[name],
           expected.device != locked.st_dev || expected.inode != locked.st_ino {
            throw HostTrustError.unsafeStorage("replaced lock file")
        }
        lockIdentities[name] = (locked.st_dev, locked.st_ino)
        return try action(created)
    }

    func read(_ name: String) throws -> Data? {
        let fd = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw HostTrustError.unsafeStorage("read file")
        }
        defer { close(fd) }
        try validateFile(fd)
        var metadata = stat()
        guard fstat(fd, &metadata) == 0, metadata.st_size <= Self.maxFileSize else {
            throw HostTrustError.unsafeStorage("file size limit")
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                throw HostTrustError.systemOperation("read", errno)
            }
            if count == 0 { break }
            guard data.count + count <= Self.maxFileSize else {
                throw HostTrustError.unsafeStorage("file size limit")
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        return data
    }

    /// Called only while holding the corresponding stable lock. Existing files must be safe.
    func atomicWrite(_ name: String, data: Data) throws {
        guard data.count <= Self.maxFileSize else { throw HostTrustError.unsafeStorage("file size limit") }
        _ = try read(name)
        let temporary = ".pending-" + UUID().uuidString
        let fd = openat(descriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw HostTrustError.systemOperation("create temporary file", errno) }
        defer {
            close(fd)
            _ = unlinkat(descriptor, temporary, 0)
        }
        try validateFile(fd)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    throw HostTrustError.systemOperation("write", errno)
                }
                guard count > 0 else { throw HostTrustError.systemOperation("write", EIO) }
                offset += count
            }
        }
        guard fsync(fd) == 0 else { throw HostTrustError.systemOperation("fsync file", errno) }
        guard renameat(descriptor, temporary, descriptor, name) == 0 else {
            throw HostTrustError.systemOperation("rename", errno)
        }
        guard fsync(descriptor) == 0 else { throw HostTrustError.systemOperation("fsync directory", errno) }
    }

    private func validateDirectory() throws {
        var opened = stat()
        var named = stat()
        guard fstat(descriptor, &opened) == 0, lstat(path.value, &named) == 0,
              Self.isDirectory(opened), Self.isDirectory(named),
              opened.st_dev == named.st_dev, opened.st_ino == named.st_ino else {
            throw HostTrustError.unsafeStorage("replaced private directory")
        }
    }

    private static func isDirectory(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFDIR && metadata.st_uid == geteuid() &&
        (metadata.st_mode & 0o7777) == 0o700
    }

    private func validateFile(_ fd: Int32) throws {
        var metadata = stat()
        guard fstat(fd, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(), (metadata.st_mode & 0o7777) == 0o600,
              metadata.st_nlink == 1, metadata.st_size >= 0 else {
            throw HostTrustError.unsafeStorage("file permissions, owner or type")
        }
    }
}
