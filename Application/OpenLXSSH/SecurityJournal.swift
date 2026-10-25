import Darwin
import Foundation
import OpenLXSSHSecurity

/// Nonsecret write-ahead intent. A prepared intent is not proof that an external UUID was
/// created: duplicates are never cleaned. Recovery first consults Core, and only .created
/// entries or a library-issued exact cleanup ticket authorize external removal.
struct SecurityIntent: Codable, Equatable, Sendable, Identifiable {
    enum Kind: String, Codable { case password, privateKeyPassphrase, privateKey }
    enum State: String, Codable { case prepared, created, deleting }
    let id: UUID
    let kind: Kind
    var state: State
    var pendingName: String?
    var includesPublicSidecar = false
    var includesCommittedKey = false
    var keyTicket: KeyCleanupTicket? {
        guard let pendingName else { return nil }
        return KeyCleanupTicket(id: id, pendingName: pendingName, includesPublicSidecar: includesPublicSidecar, includesCommittedKey: includesCommittedKey)
    }
}

/// One bounded journal, no enumeration of private key files or Keychain items. Owns only
/// Recovery/security-intents.json. O_NOFOLLOW + exclusive owner checks on every open.
final class SecurityJournal {
    private let root: URL
    private let fd: Int32
    private var entries: [SecurityIntent]
    private var revisions: [UUID: UUID] = [:]
    private let beforePersist: @Sendable () throws -> Void
    init(parent: URL, beforePersist: @escaping @Sendable () throws -> Void = {}) throws {
        self.beforePersist = beforePersist
        root = parent.appendingPathComponent("Recovery", isDirectory: true)
        let parentFD = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard parentFD >= 0 else { throw SecurityUIFailure.journal }
        defer { Darwin.close(parentFD) }
        if mkdirat(parentFD, "Recovery", 0o700) != 0 && errno != EEXIST { throw SecurityUIFailure.journal }
        fd = openat(parentFD, "Recovery", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw SecurityUIFailure.journal }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
            Darwin.close(fd); throw SecurityUIFailure.journal
        }
        do {
            let file = openat(fd, "security-intents.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            if file < 0 {
                guard errno == ENOENT else { throw SecurityUIFailure.journal }
                entries = []
            } else {
                defer { Darwin.close(file) }
                var value = stat()
                guard fstat(file, &value) == 0, value.st_mode & S_IFMT == S_IFREG,
                      value.st_uid == geteuid(), value.st_nlink == 1, value.st_mode & 0o777 == 0o600,
                      value.st_size <= 1_048_576 else { throw SecurityUIFailure.journal }
                let data = try FileHandle(fileDescriptor: file, closeOnDealloc: false).readToEnd() ?? Data()
                entries = try JSONDecoder().decode([SecurityIntent].self, from: data)
                guard entries.count <= 2048, Set(entries.map(\.id)).count == entries.count else { throw SecurityUIFailure.journal }
                for entry in entries { try Self.validate(entry) }
            }
        } catch {
            Darwin.close(fd)
            throw SecurityUIFailure.journal
        }
        for entry in entries { revisions[entry.id] = UUID() }
    }
    deinit { Darwin.close(fd) }
    func all() -> [SecurityIntent] { entries }
    func revision(for id: UUID) -> UUID? { revisions[id] }
    func set(_ entry: SecurityIntent) throws {
        try Self.validate(entry)
        var next = entries.filter { $0.id != entry.id }; next.append(entry)
        guard next.count <= 2048 else { throw SecurityUIFailure.journal }
        try persist(next); entries = next; revisions[entry.id] = UUID()
    }
    func remove(_ id: UUID) throws {
        let next = entries.filter { $0.id != id }
        try persist(next); entries = next; revisions[id] = nil
    }
    func discardPrepared(_ expected: SecurityIntent, revision: UUID) throws {
        guard expected.state == .prepared, entries.first(where: { $0.id == expected.id }) == expected,
              revisions[expected.id] == revision else { throw SecurityUIFailure.staleRecoveryReview }
        try remove(expected.id)
    }
    private static func validate(_ entry: SecurityIntent) throws {
        guard let name = entry.pendingName else { return }
        let parts = name.split(separator: ".", omittingEmptySubsequences: false)
        guard entry.kind == .privateKey, parts.count == 3, parts[0] == Substring(entry.id.uuidString),
              UUID(uuidString: String(parts[1])) != nil, parts[2] == "pending" else { throw SecurityUIFailure.journal }
    }
    private func persist(_ next: [SecurityIntent]) throws {
        // Narrow failure-injection seam; production always uses the no-op default.
        try beforePersist()
        var current = stat(), held = stat()
        guard lstat(root.path, &current) == 0, fstat(fd, &held) == 0,
              current.st_dev == held.st_dev, current.st_ino == held.st_ino,
              current.st_mode & S_IFMT == S_IFDIR, current.st_uid == geteuid(), current.st_mode & 0o777 == 0o700 else { throw SecurityUIFailure.journal }
        let data = try JSONEncoder().encode(next)
        guard data.count <= 1_048_576 else { throw SecurityUIFailure.journal }
        let name = UUID().uuidString + ".tmp"
        let file = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw SecurityUIFailure.journal }
        defer { Darwin.close(file); _ = unlinkat(fd, name, 0) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { Darwin.write(file, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw SecurityUIFailure.journal }
            offset += count
        }
        guard fsync(file) == 0, renameat(fd, name, fd, "security-intents.json") == 0, fsync(fd) == 0 else { throw SecurityUIFailure.journal }
    }
}
