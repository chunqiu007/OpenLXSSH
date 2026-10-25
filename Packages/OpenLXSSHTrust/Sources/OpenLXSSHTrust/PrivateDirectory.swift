import Darwin
import Foundation

/// A retained private directory FD anchors all file operations. No check-then-open by path.
/// File locks coordinate cooperating processes; they are not a sandbox against the same UID.
final class PrivateDirectory: @unchecked Sendable {
    let path: AbsolutePath
    private let descriptor: Int32
    private var lockIdentities: [String: (device: dev_t, inode: ino_t)] = [:]
    private var heldLock: (name: String, descriptor: Int32)?
    private var accessedFiles = Set<String>()
    private let operationLock = NSLock()
    private static let maxFileSize = 1_048_576
    // Internal injection point for deterministic boundary tests; production always checks real FDs.
    private let metadataReader: (Int32) throws -> stat

    init(_ requestedPath: AbsolutePath,
         metadataReader: @escaping (Int32) throws -> stat = { try PrivateDirectory.metadataWithoutACL($0) }) throws {
        self.metadataReader = metadataReader
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
        let openedDescriptor = open(path.value, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard openedDescriptor >= 0 else { throw HostTrustError.systemOperation("open directory", errno) }
        do {
            // mkdir's mode does not remove inherited ACEs. Check before any lock/file creation.
            let opened = try metadataReader(openedDescriptor)
            guard Self.isDirectory(opened), Self.sameIdentity(initial, opened) else {
                throw HostTrustError.unsafeStorage("private directory")
            }
        } catch {
            close(openedDescriptor)
            throw error
        }
        // Transfer ownership only after validation. A fully initialized throwing Swift init runs
        // deinit, so assigning earlier then closing in catch would close the same FD twice.
        descriptor = openedDescriptor
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
            try validateDirectory()
            fd = openat(descriptor, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
            if fd >= 0 {
                created = true
            } else if errno == EEXIST {
                fd = openat(descriptor, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            }
        }
        guard fd >= 0 else { throw HostTrustError.unsafeStorage("lock file") }
        defer { close(fd) }
        _ = try validateFile(fd, named: name)
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
        heldLock = (name, fd)
        accessedFiles.removeAll(keepingCapacity: true)
        defer {
            heldLock = nil
            accessedFiles.removeAll(keepingCapacity: true)
        }
        try validateLockedStorage()
        // Revalidate even after parsing or another action throws: an ACL mutation is unsafe,
        // never a new/empty trust store, a successful decision, or a plain corruption fallback.
        let result: T
        do { result = try action(created) }
        catch {
            try validateLockedStorage()
            throw error
        }
        try validateLockedStorage()
        return result
    }

    func read(_ name: String) throws -> Data? {
        try validateLockedStorage()
        let fd = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT {
                try validateLockedStorage()
                return nil
            }
            throw HostTrustError.unsafeStorage("read file")
        }
        defer { close(fd) }
        let before = try validateFile(fd, named: name)
        accessedFiles.insert(name)
        guard before.st_size <= Self.maxFileSize else {
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
        let after = try validateFile(fd, named: name)
        guard Self.sameIdentity(before, after), before.st_size == after.st_size,
              Self.sameTime(before.st_mtimespec, after.st_mtimespec),
              Self.sameTime(before.st_ctimespec, after.st_ctimespec),
              data.count == after.st_size else {
            throw HostTrustError.unsafeStorage("file changed while reading")
        }
        try validateLockedStorage()
        return data
    }

    /// Called only while holding the corresponding stable lock. Existing files must be safe.
    func atomicWrite(_ name: String, data: Data) throws {
        guard data.count <= Self.maxFileSize else { throw HostTrustError.unsafeStorage("file size limit") }
        let original = try read(name)
        let temporary = ".pending-" + UUID().uuidString
        let fd = openat(descriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw HostTrustError.systemOperation("create temporary file", errno) }
        defer {
            // Do not unlink another inode if a non-cooperating writer replaced our temporary.
            var opened = stat()
            var named = stat()
            if fstat(fd, &opened) == 0,
               fstatat(descriptor, temporary, &named, AT_SYMLINK_NOFOLLOW) == 0,
               Self.sameIdentity(opened, named) {
                _ = unlinkat(descriptor, temporary, 0)
            }
            close(fd)
        }
        _ = try validateFile(fd, named: temporary)
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
        // ACLs can change while data is written. Recheck the destination, root, stable lock and
        // exact temporary inode before publishing; never chmod/remove an existing user's ACL.
        guard try read(name) == original else { throw HostTrustError.storageChanged }
        try validateLockedStorage()
        _ = try validateFile(fd, named: temporary)
        guard renameat(descriptor, temporary, descriptor, name) == 0 else {
            throw HostTrustError.systemOperation("rename", errno)
        }
        _ = try validateFile(fd, named: name)
        accessedFiles.insert(name)
        try validateLockedStorage()
        guard fsync(descriptor) == 0 else { throw HostTrustError.systemOperation("fsync directory", errno) }
    }

    private func validateLockedStorage() throws {
        try validateDirectory()
        guard let heldLock else { throw HostTrustError.unsafeStorage("unlocked storage operation") }
        let locked = try validateFile(heldLock.descriptor, named: heldLock.name)
        if let expected = lockIdentities[heldLock.name],
           expected.device != locked.st_dev || expected.inode != locked.st_ino {
            throw HostTrustError.unsafeStorage("replaced lock file")
        }
        lockIdentities[heldLock.name] = (locked.st_dev, locked.st_ino)
        for name in accessedFiles {
            let fd = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { throw HostTrustError.unsafeStorage("accessed file") }
            defer { close(fd) }
            _ = try validateFile(fd, named: name)
        }
    }

    private func validateDirectory() throws {
        let opened = try metadataReader(descriptor)
        var named = stat()
        guard lstat(path.value, &named) == 0, Self.isDirectory(opened), Self.isDirectory(named),
              Self.sameIdentity(opened, named) else {
            throw HostTrustError.unsafeStorage("replaced private directory")
        }
    }

    private static func sameIdentity(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev && first.st_ino == second.st_ino
    }

    private static func sameTime(_ first: timespec, _ second: timespec) -> Bool {
        first.tv_sec == second.tv_sec && first.tv_nsec == second.tv_nsec
    }

    private static func isDirectory(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFDIR && metadata.st_uid == geteuid() &&
        (metadata.st_mode & 0o7777) == 0o700
    }

    @discardableResult
    private func validateFile(_ fd: Int32, named name: String) throws -> stat {
        let metadata = try metadataReader(fd)
        var named = stat()
        guard (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(), (metadata.st_mode & 0o7777) == 0o600,
              metadata.st_nlink == 1, metadata.st_size >= 0,
              fstatat(descriptor, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              Self.sameIdentity(metadata, named) else {
            throw HostTrustError.unsafeStorage("file permissions, owner, type or identity")
        }
        return metadata
    }

    /// Darwin's acl_get_fd_np conflates absent ACLs with query failures (NULL/ENOENT).
    /// Use fstatx_np + property presence instead; even an empty explicit ACL is rejected.
    /// SDK sys/{stat,fcntl}.h; Apple Libc sys/statx_np.c and gen/filesec.c define this contract.
    static func metadataWithoutACL(_ fd: Int32,
        queryProperty: (filesec_t, filesec_property_t, UnsafeMutablePointer<Int32>) -> Int32 = filesec_query_property
    ) throws -> stat {
        guard let security = filesec_init() else {
            throw HostTrustError.unsafeStorage("file security allocation (errno \(errno))")
        }
        defer { filesec_free(security) } // Also owns/frees the internal ACL; no acl_t copy needed.
        var metadata = stat()
        let result = fstatx_np(fd, &metadata, security)
        let failure = errno
        guard result == 0 else {
            throw HostTrustError.unsafeStorage("file security stat (\(result), errno \(failure))")
        }
        var populated: Int32 = 0
        let modeResult = queryProperty(security, FILESEC_MODE, &populated)
        let modeFailure = errno
        // Also catches Libc's realloc-failure edge case returning 0 before filling properties.
        guard modeResult == 0 else {
            throw HostTrustError.unsafeStorage("file security mode query (\(modeResult), errno \(modeFailure))")
        }
        guard populated != 0 else {
            // There was no failing call whose errno could be used; report EIO, not stale errno.
            throw HostTrustError.unsafeStorage("unpopulated file security mode (errno \(EIO))")
        }
        var present: Int32 = 0
        let aclResult = queryProperty(security, FILESEC_ACL, &present)
        let aclFailure = errno
        guard aclResult == 0 else {
            throw HostTrustError.unsafeStorage("file security ACL query (\(aclResult), errno \(aclFailure))")
        }
        // Presence is a bitmask (currently 32), not a boolean that is necessarily equal to 1.
        // Ignore stale errno after successful calls. Fail closed for every explicit/inherited ACE,
        // including deny-only entries, rather than interpreting access or changing users' ACLs.
        guard present == 0 else { throw HostTrustError.unsafeStorage("extended ACL") }
        return metadata
    }
}
