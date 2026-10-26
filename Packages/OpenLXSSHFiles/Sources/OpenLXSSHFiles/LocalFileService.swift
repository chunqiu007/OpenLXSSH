import Darwin
import Foundation

/// Sandboxed local upload/download backend rooted at an explicitly selected directory.
/// Every component is traversed through retained directory FDs using openat/O_NOFOLLOW.
public actor LocalFileService: RemoteFileService {
    public nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow,
        exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    private var rootFD: Int32
    private var closed = false
    private var handles: [FileHandleID: Int32] = [:]
    private nonisolated let lifetime = CancellationToken()
    public init(root: URL) throws {
        let fd = root.withUnsafeFileSystemRepresentation { Darwin.open($0!, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
        guard fd >= 0 else { throw Self.error("fixture-root") }
        rootFD = fd
    }
    /// Copies an already-open local directory FD; the caller retains ownership and must keep it
    /// valid during initialization. The caller is responsible for safely selecting/traversing
    /// the upstream directory path. No URL is reopened and non-directory FDs are rejected.
    public init(rootDirectoryDescriptor: Int32) throws {
        let fd = fcntl(rootDirectoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw Self.error("duplicate-local-root") }
        do {
            var st = stat()
            guard Darwin.fstat(fd, &st) == 0 else { throw Self.error("stat-local-root") }
            guard st.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
                throw FileServiceError(.unsupported, operation: "local-root-not-directory", code: Int64(ENOTDIR))
            }
        } catch { Darwin.close(fd); throw error }
        rootFD = fd
    }
    deinit {
        for fd in handles.values { Darwin.close(fd) }
        Darwin.close(rootFD)
    }
    private static func error(_ operation: String, path: RemotePath? = nil, code: Int32 = errno) -> FileServiceError {
        let kind: FileServiceError.Kind
        switch code {
        case ENOENT: kind = .notFound
        case EILSEQ, ENAMETOOLONG: kind = .invalidPath
        case EACCES, EPERM, EROFS: kind = .permissionDenied
        case EEXIST, ENOTEMPTY: kind = .conflict
        case ELOOP, ENOTDIR: kind = .symbolicLink
        default: kind = .io
        }
        return FileServiceError(kind, operation: operation, path: path, code: Int64(code))
    }
    private func check(_ token: CancellationToken) throws {
        guard !closed else { throw FileServiceError(.closed, operation: "fixture") }
        try lifetime.check(); try token.check()
    }
    private func directory(_ path: RemotePath) throws -> Int32 {
        // dup() would share rootFD's directory offset: every listing needs a new open description.
        var fd = openat(rootFD, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Self.error("open-root-directory", path: path) }
        do {
            for part in path.components {
                let next = part.cBytes.withUnsafeBufferPointer {
                    openat(fd, $0.baseAddress!, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                }
                guard next >= 0 else { throw Self.error("directory", path: path) }
                Darwin.close(fd); fd = next
            }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    private func parent(_ path: RemotePath) throws -> (Int32, FileName) {
        guard let name = path.name else { throw FileServiceError(.invalidPath, operation: "root-operation", path: path) }
        return (try directory(path.parent), name)
    }
    private func attributes(_ st: stat) -> FileAttributes {
        let kind: FileKind
        switch st.st_mode & mode_t(S_IFMT) {
        case mode_t(S_IFREG): kind = .regular
        case mode_t(S_IFDIR): kind = .directory
        case mode_t(S_IFLNK): kind = .symbolicLink
        default: kind = .other
        }
        return FileAttributes(kind: kind, size: UInt64(max(0, st.st_size)), permissions: UInt32(st.st_mode),
                              modifiedSeconds: UInt64(max(0, st.st_mtimespec.tv_sec)), modifiedNanoseconds: UInt32(st.st_mtimespec.tv_nsec),
                              identity: "\(st.st_dev):\(st.st_ino)")
    }
    public func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes {
        try check(token)
        var st = stat()
        if path == .root {
            guard Darwin.fstat(rootFD, &st) == 0 else { throw Self.error("fstat", path: path) }
        } else {
            let (fd, name) = try parent(path); defer { Darwin.close(fd) }
            let rc = name.cBytes.withUnsafeBufferPointer { fstatat(fd, $0.baseAddress!, &st, AT_SYMLINK_NOFOLLOW) }
            guard rc == 0 else { throw Self.error("lstat", path: path) }
        }
        return attributes(st)
    }
    public func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        try check(token)
        let fd = try directory(path)
        guard let dir = fdopendir(fd) else { Darwin.close(fd); throw Self.error("fdopendir", path: path) }
        defer { closedir(dir) }
        var results: [DirectoryEntry] = []
        while true {
            try token.check()
            errno = 0
            guard let entry = readdir(dir) else {
                if errno != 0 { throw Self.error("readdir", path: path) }
                break
            }
            let count = Int(entry.pointee.d_namlen)
            let bytes = withUnsafeBytes(of: entry.pointee.d_name) { Data($0.prefix(count)) }
            if bytes == Data([46]) || bytes == Data([46, 46]) { continue }
            let name = try FileName(bytes: bytes)
            var st = stat()
            let rc = name.cBytes.withUnsafeBufferPointer { fstatat(fd, $0.baseAddress!, &st, AT_SYMLINK_NOFOLLOW) }
            guard rc == 0 else { throw Self.error("list-lstat", path: try path.appending(name)) }
            guard results.count < 100000 else { throw FileServiceError(.resourceLimit, operation: "list", path: path) }
            results.append(DirectoryEntry(name: name, attributes: attributes(st)))
        }
        return results
    }
    public func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        try check(token)
        guard handles.count < 64 else { throw FileServiceError(.resourceLimit, operation: "open", path: path) }
        let (parent, name) = try parent(path); defer { Darwin.close(parent) }
        let flags = (mode == .read ? O_RDONLY : O_WRONLY | O_CREAT | O_EXCL) | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        let fd = name.cBytes.withUnsafeBufferPointer { openat(parent, $0.baseAddress!, flags, mode_t(0o600)) }
        guard fd >= 0 else { throw Self.error("open", path: path) }
        var st = stat()
        guard Darwin.fstat(fd, &st) == 0, st.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
            Darwin.close(fd); throw FileServiceError(.unsupported, operation: "nonregular", path: path)
        }
        let id = FileHandleID(); handles[id] = fd; return id
    }
    private func handle(_ id: FileHandleID) throws -> Int32 {
        guard let fd = handles[id] else { throw FileServiceError(.closed, operation: "handle") }; return fd
    }
    public func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? {
        try check(token)
        var st = stat()
        guard Darwin.fstat(try self.handle(handle), &st) == 0 else { throw Self.error("fstat-handle") }
        return attributes(st)
    }
    public func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        try check(token)
        guard maxBytes > 0, maxBytes <= 1024 * 1024 else { throw FileServiceError(.resourceLimit, operation: "read") }
        var bytes = Data(count: maxBytes)
        let fd = try self.handle(handle)
        var count: Int
        repeat {
            count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, maxBytes) }
            if count < 0 && errno == EINTR { try token.check() }
        } while count < 0 && errno == EINTR
        guard count >= 0 else { throw Self.error("read") }
        bytes.count = count; return bytes
    }
    public func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        try check(token)
        guard !data.isEmpty, data.count <= 1024 * 1024 else { throw FileServiceError(.resourceLimit, operation: "write") }
        let fd = try self.handle(handle)
        var count: Int
        repeat {
            count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, data.count) }
            if count < 0 && errno == EINTR { try token.check() }
        } while count < 0 && errno == EINTR
        guard count >= 0 else { throw Self.error("write") }; return count
    }
    public func finish(_ handle: FileHandleID, token: CancellationToken) async throws {
        try check(token)
        guard fsync(try self.handle(handle)) == 0 else { throw Self.error("fsync") }
    }
    public func closeHandle(_ handle: FileHandleID) async throws {
        guard let fd = handles.removeValue(forKey: handle) else { return }
        guard Darwin.close(fd) == 0 else { throw Self.error("close") }
    }
    public func mkdir(_ path: RemotePath, token: CancellationToken) async throws {
        try check(token)
        let (fd, name) = try parent(path); defer { Darwin.close(fd) }
        let rc = name.cBytes.withUnsafeBufferPointer { mkdirat(fd, $0.baseAddress!, mode_t(0o700)) }
        guard rc == 0 else { throw Self.error("mkdir", path: path) }
    }
    public func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws {
        try check(token)
        // Public raw rename stays no-replace. Risk-confirmed replace is only available via commit().
        guard mode == .noReplace else { throw FileServiceError(.unsupported, operation: "use-risk-confirmed-commit", path: destination) }
        let (fromFD, from) = try parent(source); defer { Darwin.close(fromFD) }
        let (toFD, to) = try parent(destination); defer { Darwin.close(toFD) }
        let rc = from.cBytes.withUnsafeBufferPointer { a in to.cBytes.withUnsafeBufferPointer { b in
            renameatx_np(fromFD, a.baseAddress!, toFD, b.baseAddress!, UInt32(RENAME_EXCL))
        } }
        guard rc == 0 else { throw Self.error("rename-excl", path: destination) }
    }
    public func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws {
        try check(token)
        if request.mode == .noReplace {
            try await rename(source, to: destination, mode: .noReplace, token: token); return
        }
        guard request.acceptNonCASOverwriteRisk, let expected = request.expectedTarget,
              let digest = request.expectedContentSHA256 else {
            throw FileServiceError(.unsupported, operation: "overwrite-preconditions", path: destination)
        }
        try await TransferChecks.requireUnchanged(self, path: destination, expected: expected, digest: digest, token: token)
        try check(token)
        let (fromFD, from) = try parent(source); defer { Darwin.close(fromFD) }
        let (toFD, to) = try parent(destination); defer { Darwin.close(toFD) }
        let rc = from.cBytes.withUnsafeBufferPointer { a in to.cBytes.withUnsafeBufferPointer { b in
            renameat(fromFD, a.baseAddress!, toFD, b.baseAddress!)
        } }
        guard rc == 0 else { throw Self.error("atomic-risk-confirmed-replace", path: destination) }
    }
    public func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws {
        try check(token)
        let (fd, name) = try parent(path); defer { Darwin.close(fd) }
        let rc = name.cBytes.withUnsafeBufferPointer { unlinkat(fd, $0.baseAddress!, directory ? AT_REMOVEDIR : 0) }
        guard rc == 0 else { throw Self.error("remove", path: path) }
    }
    public nonisolated func cancel() { lifetime.cancel() }
    public func close() async {
        guard !closed else { return }; closed = true; lifetime.cancel()
        for fd in handles.values { Darwin.close(fd) }; handles.removeAll()
        Darwin.close(rootFD); rootFD = -1
    }
}
