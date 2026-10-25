import Darwin
import Foundation

/// Owns only the supplied leaf directory. Its parent must already exist; callers must use an App-owned location.
/// No process-global umask is changed. SQLite inherits 0600 from the precreated database for WAL/journals;
/// the enclosing 0700 directory also protects sidecar creation and replacement. Any extended ACL
/// presence is rejected: chmod alone does not remove inherited access on Darwin.
final class SecureDatabaseLocation: Sendable {
    let directory: URL
    let databaseURL: URL
    private let directoryFD: Int32
    private let lockFD: Int32
    private let directoryDevice: dev_t
    private let directoryInode: ino_t
    private let databaseDevice: dev_t
    private let databaseInode: ino_t
    private let lockDevice: dev_t
    private let lockInode: ino_t
    private static let files = ["OpenLXSSH.sqlite", "OpenLXSSH.sqlite-wal", "OpenLXSSH.sqlite-shm", "OpenLXSSH.sqlite-journal"]

    init(directory suppliedURL: URL) throws {
        guard suppliedURL.isFileURL else { throw RepositoryError.unsafeDatabaseLocation }
        let leaf = suppliedURL.lastPathComponent
        guard !leaf.isEmpty, leaf != ".", leaf != "..", leaf != "/" else { throw RepositoryError.unsafeDatabaseLocation }
        let parent = suppliedURL.deletingLastPathComponent().resolvingSymlinksInPath()
        directory = parent.appendingPathComponent(leaf, isDirectory: true)
        databaseURL = directory.appendingPathComponent(Self.files[0])
        let parentFD = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parentFD >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
        defer { Darwin.close(parentFD) }
        if mkdirat(parentFD, leaf, 0o700) != 0 && errno != EEXIST { throw RepositoryError.unsafeDatabaseLocation }
        let fd = openat(parentFD, leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
        do {
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_uid == geteuid(), (info.st_mode & S_IFMT) == S_IFDIR else {
                throw RepositoryError.unsafeDatabaseLocation
            }
            // A newly created leaf may inherit ACEs even with mode 0700. Reject it before
            // creating the database, lock, or any other configuration metadata; never strip ACLs.
            try DatabaseFileACL.requireNoExtendedACL(fd: fd, matching: info)
            guard fchmod(fd, 0o700) == 0 else { throw RepositoryError.unsafeDatabaseLocation }
            try DatabaseFileACL.requireNoExtendedACL(fd: fd, matching: info)
            // Check every pre-existing inode before creating anything or allowing SQLite to
            // inspect a journal/WAL, run schema discovery, or repair ordinary mode bits.
            for name in Self.files + ["OpenLXSSH.lock"] {
                _ = try Self.checkedFile(name, in: fd, ephemeral: name != Self.files[0] && name != "OpenLXSSH.lock")
            }
            let db = try Self.secureFile(Self.files[0], in: fd, create: true)!
            for name in Self.files.dropFirst() { _ = try Self.secureFile(name, in: fd, create: false, ephemeral: true) }
            directoryDevice = info.st_dev; directoryInode = info.st_ino
            databaseDevice = db.st_dev; databaseInode = db.st_ino
        } catch {
            Darwin.close(fd)
            throw error
        }
        directoryFD = fd
        do {
            guard let info = try Self.secureFile("OpenLXSSH.lock", in: fd, create: true) else { throw RepositoryError.unsafeDatabaseLocation }
            let lock = openat(fd, "OpenLXSSH.lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            guard lock >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
            var opened = stat()
            do {
                guard fstat(lock, &opened) == 0, opened.st_dev == info.st_dev, opened.st_ino == info.st_ino else {
                    throw RepositoryError.unsafeDatabaseLocation
                }
                try DatabaseFileACL.requireNoExtendedACL(fd: lock, matching: opened)
            } catch {
                Darwin.close(lock)
                throw error
            }
            lockFD = lock; lockDevice = info.st_dev; lockInode = info.st_ino
        } catch {
            Darwin.close(fd)
            throw error
        }
    }

    deinit { Darwin.close(lockFD); Darwin.close(directoryFD) }

    // GRDB serializes each connection, but migration discovery itself needs cross-process
    // serialization so two fresh launches cannot both plan the same pending migration.
    func withInitializationLock<T>(_ body: () throws -> T) throws -> T {
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        while flock(lockFD, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK || errno == EINTR else { throw RepositoryError.unsafeDatabaseLocation }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw RepositoryError.databaseBusy }
            Thread.sleep(forTimeInterval: 0.01)
        }
        defer { _ = flock(lockFD, LOCK_UN) }
        try validateAndSecureFiles()
        return try body()
    }

    func validateAndSecureFiles() throws {
        var directoryInfo = stat()
        guard lstat(directory.path, &directoryInfo) == 0,
              directoryInfo.st_dev == directoryDevice, directoryInfo.st_ino == directoryInode,
              (directoryInfo.st_mode & S_IFMT) == S_IFDIR, directoryInfo.st_uid == geteuid(),
              directoryInfo.st_mode & 0o777 == 0o700 else { throw RepositoryError.unsafeDatabaseLocation }
        try DatabaseFileACL.requireNoExtendedACL(fd: directoryFD, matching: directoryInfo)
        var checkedDirectory = stat()
        guard lstat(directory.path, &checkedDirectory) == 0,
              checkedDirectory.st_dev == directoryDevice, checkedDirectory.st_ino == directoryInode,
              (checkedDirectory.st_mode & S_IFMT) == S_IFDIR, checkedDirectory.st_uid == geteuid(),
              checkedDirectory.st_mode & 0o777 == 0o700 else { throw RepositoryError.unsafeDatabaseLocation }
        guard let db = try Self.secureFile(Self.files[0], in: directoryFD, create: false),
              db.st_dev == databaseDevice, db.st_ino == databaseInode,
              let lock = try Self.secureFile("OpenLXSSH.lock", in: directoryFD, create: false),
              lock.st_dev == lockDevice, lock.st_ino == lockInode else { throw RepositoryError.unsafeDatabaseLocation }
        for name in Self.files.dropFirst() { _ = try Self.secureFile(name, in: directoryFD, create: false, ephemeral: true) }
    }

    private static func checkedFile(_ name: String, in directoryFD: Int32, ephemeral: Bool) throws -> stat? {
        var info = stat()
        if fstatat(directoryFD, name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw RepositoryError.unsafeDatabaseLocation }
            return nil
        }
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1 else {
            throw RepositoryError.unsafeDatabaseLocation
        }
        // getattrlistat performs metadata lookup without opening/closing the SQLite inode.
        // A query error is never treated as no ACL, even for an ephemeral sidecar.
        try DatabaseFileACL.requireNoExtendedACL(at: name, in: directoryFD, matching: info)
        var checked = stat()
        if fstatat(directoryFD, name, &checked, AT_SYMLINK_NOFOLLOW) != 0 {
            if ephemeral && errno == ENOENT { return nil }
            throw RepositoryError.unsafeDatabaseLocation
        }
        guard checked.st_dev == info.st_dev, checked.st_ino == info.st_ino,
              (checked.st_mode & S_IFMT) == S_IFREG, checked.st_uid == geteuid(), checked.st_nlink == 1 else {
            throw RepositoryError.unsafeDatabaseLocation
        }
        return checked
    }

    private static func secureFile(_ name: String, in directoryFD: Int32, create: Bool, ephemeral: Bool = false) throws -> stat? {
        // Never open/close an *existing* SQLite DB/WAL/SHM file here. Closing an additional
        // descriptor can release this process's POSIX SQLite locks on the same inode.
        var info: stat
        if let existing = try checkedFile(name, in: directoryFD, ephemeral: ephemeral) {
            info = existing
        } else {
            if !create { return nil }
            var created = false
            for _ in 0..<10 {
                let fd = openat(directoryFD, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
                if fd >= 0 {
                    // Only our new inode is opened here. No configuration data has been written.
                    defer { Darwin.close(fd) }
                    var opened = stat()
                    guard fstat(fd, &opened) == 0 else { throw RepositoryError.unsafeDatabaseLocation }
                    try DatabaseFileACL.requireNoExtendedACL(fd: fd, matching: opened)
                    guard fchmod(fd, 0o600) == 0 else { throw RepositoryError.unsafeDatabaseLocation }
                    try DatabaseFileACL.requireNoExtendedACL(fd: fd, matching: opened)
                    created = true
                    break
                }
                let code = errno
                if code == EEXIST { created = true; break }
                // APFS can return ENOENT during concurrent creation, reproduced without SQLite.
                guard code == ENOENT || code == EINTR else { throw RepositoryError.unsafeDatabaseLocation }
                Thread.sleep(forTimeInterval: 0.002)
            }
            guard created, let checked = try checkedFile(name, in: directoryFD, ephemeral: ephemeral) else {
                throw RepositoryError.unsafeDatabaseLocation
            }
            info = checked
        }
        if info.st_mode & 0o777 != 0o600 {
            if fchmodat(directoryFD, name, 0o600, AT_SYMLINK_NOFOLLOW) != 0 {
                // SQLite may remove an ephemeral sidecar while its final connection closes.
                if ephemeral && errno == ENOENT { return nil }
                throw RepositoryError.unsafeDatabaseLocation
            }
            guard let secured = try checkedFile(name, in: directoryFD, ephemeral: ephemeral) else {
                if ephemeral { return nil }
                throw RepositoryError.unsafeDatabaseLocation
            }
            guard secured.st_dev == info.st_dev, secured.st_ino == info.st_ino,
                  secured.st_mode & 0o777 == 0o600 else { throw RepositoryError.unsafeDatabaseLocation }
            info = secured
        }
        return info
    }
}
