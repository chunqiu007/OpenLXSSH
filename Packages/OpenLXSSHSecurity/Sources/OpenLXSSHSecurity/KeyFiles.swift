import Darwin
import Foundation

/// Only standard OpenSSH framing is parsed here. Decryption, key consistency and private
/// algorithm validation are delegated to the system ssh-keygen, never custom cryptography.
struct WireReader {
    let bytes: Data
    var offset = 0
    mutating func uint32() throws -> UInt32 {
        guard offset <= bytes.count - 4 else { throw KeyFailure.invalidOpenSSH }
        let value = bytes[offset..<(offset + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        offset += 4
        return value
    }
    mutating func field() throws -> Data {
        let size = Int(try uint32())
        guard size <= bytes.count - offset else { throw KeyFailure.invalidOpenSSH }
        defer { offset += size }
        return Data(bytes[offset..<(offset + size)])
    }
}

public struct PublicKey: Equatable, Hashable, Sendable {
    public let algorithm: KeyAlgorithm
    /// Safe display/copy representation: algorithm and base64 only, no source comment.
    public let copyString: String

    public init(_ text: String) throws {
        let parts = text.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 2, !text.contains(where: { $0.isNewline }),
              let algorithm = KeyAlgorithm(rawValue: String(parts[0])),
              let blob = Data(base64Encoded: String(parts[1])), blob.count <= 16_384 else {
            throw KeyFailure.invalidOpenSSH
        }
        try self.init(blob: blob, expected: algorithm)
    }

    init(blob: Data, expected: KeyAlgorithm? = nil) throws {
        var wire = WireReader(bytes: blob)
        let type = String(data: try wire.field(), encoding: .utf8)
        guard let type, let algorithm = KeyAlgorithm(rawValue: type) else { throw KeyFailure.unsupportedAlgorithm }
        if let expected, algorithm != expected { throw KeyFailure.invalidOpenSSH }
        switch algorithm {
        case .ed25519:
            guard try wire.field().count == 32 else { throw KeyFailure.invalidOpenSSH }
        case .rsa:
            let exponent = try wire.field()
            let modulus = try wire.field()
            guard !exponent.isEmpty, exponent.count <= 8, !modulus.isEmpty,
                  modulus.count <= 2049 else { throw KeyFailure.invalidOpenSSH }
        }
        guard wire.offset == blob.count else { throw KeyFailure.invalidOpenSSH }
        self.algorithm = algorithm
        copyString = "\(algorithm.rawValue) \(blob.base64EncodedString())"
    }
}

struct OpenSSHEnvelope {
    let publicKey: PublicKey
    let encrypted: Bool

    init(_ data: Data) throws {
        guard let text = String(data: data, encoding: .utf8),
              text.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----\n"),
              text.hasSuffix("-----END OPENSSH PRIVATE KEY-----\n") else { throw KeyFailure.invalidOpenSSH }
        let lines = text.components(separatedBy: "\n")
        guard lines.count >= 4 else { throw KeyFailure.invalidOpenSSH }
        let base64 = lines.dropFirst().dropLast(2).joined()
        guard let raw = Data(base64Encoded: base64), raw.starts(with: Data("openssh-key-v1\0".utf8)) else {
            throw KeyFailure.invalidOpenSSH
        }
        var wire = WireReader(bytes: raw, offset: 15)
        guard let cipher = String(data: try wire.field(), encoding: .utf8),
              let kdf = String(data: try wire.field(), encoding: .utf8) else { throw KeyFailure.invalidOpenSSH }
        let options = try wire.field()
        guard try wire.uint32() == 1 else { throw KeyFailure.invalidOpenSSH }
        publicKey = try PublicKey(blob: wire.field())
        let privateSection = try wire.field()
        guard !privateSection.isEmpty, wire.offset == raw.count else { throw KeyFailure.invalidOpenSSH }
        encrypted = cipher != "none"
        if encrypted {
            guard !cipher.isEmpty, kdf == "bcrypt", !options.isEmpty else { throw KeyFailure.invalidOpenSSH }
        } else {
            guard kdf == "none", options.isEmpty else { throw KeyFailure.invalidOpenSSH }
        }
    }
}

/// Descriptor-relative file operations, owner-only permissions, and explicit rejection of
/// every symlink/path-traversal component. This is not a defense against a malicious process
/// already running as the same user and able to rewrite that user's files.
final class PrivateDirectory {
    let url: URL
    let fd: Int32

    private let lockFD: Int32

    /// The supplied App-owned leaf may be created; its parent must already exist. Never
    /// resolve user path symlinks, recursively create ancestors or chmod an existing root.
    init(directory: URL) throws {
        guard directory.isFileURL, directory.path.hasPrefix("/"), !directory.path.utf8.contains(0),
              !directory.path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }),
              !directory.lastPathComponent.isEmpty, directory.path != "/" else { throw KeyFailure.invalidPath }
        url = directory
        let parent = try Self.openDirectory(directory.deletingLastPathComponent().path)
        defer { _ = Darwin.close(parent) }
        if mkdirat(parent, directory.lastPathComponent, 0o700) != 0, errno != EEXIST {
            throw KeyFailure.systemCall("create key directory", errno)
        }
        let opened = try Self.openDirectory(directory.path)
        do {
            var info = stat()
            guard fstat(opened, &info) == 0, info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
                throw KeyFailure.unsafePermissions
            }
            let lock = openat(opened, ".OpenLXSSH.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
            guard lock >= 0 else { throw KeyFailure.systemCall("open key lock", errno) }
            var lockInfo = stat()
            guard fstat(lock, &lockInfo) == 0, lockInfo.st_mode & S_IFMT == S_IFREG,
                  lockInfo.st_uid == geteuid(), lockInfo.st_nlink == 1, lockInfo.st_mode & 0o777 == 0o600 else {
                _ = Darwin.close(lock)
                throw KeyFailure.unsafePermissions
            }
            guard flock(lock, LOCK_EX | LOCK_NB) == 0 else {
                _ = Darwin.close(lock)
                throw KeyFailure.busy
            }
            lockFD = lock
        } catch { _ = Darwin.close(opened); throw error }
        fd = opened
    }

    deinit { _ = Darwin.close(lockFD); _ = Darwin.close(fd) }

    static func openDirectory(_ path: String) throws -> Int32 {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else { throw KeyFailure.invalidPath }
        let parts = path.split(separator: "/", omittingEmptySubsequences: true)
        guard !parts.contains(".."), !parts.contains(".") else { throw KeyFailure.symbolicLinkOrEscape }
        var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw KeyFailure.systemCall("open root", errno) }
        for part in parts {
            let next = openat(current, String(part), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            let code = errno
            _ = Darwin.close(current)
            guard next >= 0 else {
                if code == ELOOP || code == ENOTDIR { throw KeyFailure.symbolicLinkOrEscape }
                throw KeyFailure.systemCall("open directory", code)
            }
            current = next
        }
        return current
    }

    func verify() throws {
        let observed = try Self.openDirectory(url.path)
        defer { _ = Darwin.close(observed) }
        var a = stat(), b = stat()
        guard fstat(fd, &a) == 0, fstat(observed, &b) == 0 else { throw KeyFailure.systemCall("stat root", errno) }
        guard a.st_dev == b.st_dev, a.st_ino == b.st_ino else { throw KeyFailure.symbolicLinkOrEscape }
        guard a.st_uid == geteuid(), a.st_mode & 0o777 == 0o700 else { throw KeyFailure.unsafePermissions }
        var lock = stat(), onDiskLock = stat()
        guard fstat(lockFD, &lock) == 0,
              fstatat(fd, ".OpenLXSSH.lock", &onDiskLock, AT_SYMLINK_NOFOLLOW) == 0,
              lock.st_dev == onDiskLock.st_dev, lock.st_ino == onDiskLock.st_ino,
              onDiskLock.st_mode & S_IFMT == S_IFREG, onDiskLock.st_uid == geteuid(),
              onDiskLock.st_nlink == 1, onDiskLock.st_mode & 0o777 == 0o600 else {
            throw KeyFailure.symbolicLinkOrEscape
        }
    }

    static func readSource(_ url: URL) throws -> Data {
        guard url.isFileURL, !url.path.utf8.contains(0) else { throw KeyFailure.invalidPath }
        let components = url.path.split(separator: "/")
        guard !components.contains(".."), !components.contains("."), let name = components.last else {
            throw KeyFailure.symbolicLinkOrEscape
        }
        let parent = "/" + components.dropLast().joined(separator: "/")
        let parentFD = try openDirectory(parent)
        defer { _ = Darwin.close(parentFD) }
        return try read(at: parentFD, name: String(name))
    }

    func read(_ name: String) throws -> Data {
        try verify()
        try Self.checkName(name)
        return try Self.read(at: fd, name: name)
    }

    private static func checkName(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.utf8.contains(0) else {
            throw KeyFailure.symbolicLinkOrEscape
        }
    }

    private static func read(at directory: Int32, name: String) throws -> Data {
        let file = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard file >= 0 else {
            if errno == ELOOP { throw KeyFailure.symbolicLinkOrEscape }
            if errno == ENOENT { throw KeyFailure.missing }
            throw KeyFailure.systemCall("open key", errno)
        }
        defer { _ = Darwin.close(file) }
        var before = stat()
        guard fstat(file, &before) == 0 else { throw KeyFailure.systemCall("stat key", errno) }
        guard before.st_mode & S_IFMT == S_IFREG else { throw KeyFailure.notRegularFile }
        guard before.st_uid == geteuid(), before.st_mode & 0o077 == 0, before.st_nlink == 1 else {
            throw KeyFailure.unsafePermissions
        }
        guard before.st_size > 0, before.st_size <= 1_048_576 else { throw KeyFailure.fileTooLarge }
        var bytes = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(file, $0.baseAddress, $0.count) }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw KeyFailure.systemCall("read key", errno)
            }
            guard bytes.count + count <= 1_048_576 else { throw KeyFailure.fileTooLarge }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard fstat(file, &after) == 0 else { throw KeyFailure.systemCall("stat key", errno) }
        guard bytes.count == Int(before.st_size), before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw KeyFailure.changedWhileReading }
        return bytes
    }

    func exists(_ name: String) throws -> Bool {
        try verify()
        try Self.checkName(name)
        var info = stat()
        if fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        guard errno == ENOENT else { throw KeyFailure.systemCall("check key", errno) }
        return false
    }

    func write(_ data: Data, name: String, created: inout Bool) throws {
        try verify()
        try Self.checkName(name)
        let file = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard file >= 0 else { throw KeyFailure.systemCall("create key", errno) }
        created = true
        defer { _ = Darwin.close(file) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { Darwin.write(file, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw KeyFailure.systemCall("write key", errno) }
            offset += count
        }
        guard fchmod(file, 0o600) == 0, fsync(file) == 0 else { throw KeyFailure.systemCall("sync key", errno) }
    }

    @discardableResult
    func remove(_ name: String) throws -> Bool {
        try verify()
        try Self.checkName(name)
        var attributes = stat()
        if fstatat(fd, name, &attributes, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return false }
            throw KeyFailure.systemCall("stat removal", errno)
        }
        guard attributes.st_mode & S_IFMT == S_IFREG, attributes.st_uid == geteuid(),
              attributes.st_nlink == 1 else { throw KeyFailure.symbolicLinkOrEscape }
        guard unlinkat(fd, name, 0) == 0 else { throw KeyFailure.systemCall("remove key", errno) }
        guard fsync(fd) == 0 else { throw KeyFailure.systemCall("sync deletion", errno) }
        return true
    }

    func commit(stage: String, destination: String, committed: inout Bool) throws {
        try verify()
        try Self.checkName(stage)
        try Self.checkName(destination)
        _ = try read(stage)
        guard renameatx_np(fd, stage, fd, destination, UInt32(RENAME_EXCL)) == 0 else {
            throw KeyFailure.systemCall("commit key", errno)
        }
        committed = true
        guard fsync(fd) == 0 else { throw KeyFailure.systemCall("sync root", errno) }
    }
}
