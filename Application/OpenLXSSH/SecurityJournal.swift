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
enum JournalWriteFailure: Error { case committedUnsafe }

final class SecurityJournal {
    private let parent: URL
    private let parentFD: Int32
    private let fd: Int32
    private var entries: [SecurityIntent]
    private var revisions: [UUID: UUID] = [:]
    private let beforePersist: @Sendable () throws -> Void
    private let beforeCommit: @Sendable () throws -> Void
    private let afterRename: @Sendable () throws -> Void
    init(parent: URL, beforePersist: @escaping @Sendable () throws -> Void = {},
         beforeCommit: @escaping @Sendable () throws -> Void = {},
         afterRename: @escaping @Sendable () throws -> Void = {},
         beforeFinalValidation: @Sendable () throws -> Void = {},
         afterInitializationFailureCleanup: @Sendable (Int32, Int32) -> Void = { _, _ in }) throws {
        // Keep ownership local until *every* throwing validation succeeds. Once all
        // stored properties are initialized, a throwing init runs deinit; closing
        // stored FDs in catch as well could close unrelated, reused descriptors.
        let openedParent = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard openedParent >= 0 else { throw SecurityUIFailure.journal }
        var openedRecovery: Int32 = -1
        var transferred = false
        defer {
            if !transferred {
                if openedRecovery >= 0 { Darwin.close(openedRecovery) }
                Darwin.close(openedParent)
                afterInitializationFailureCleanup(openedParent, openedRecovery)
            }
        }
        do {
            try AppFileSecurity.directory(openedParent)
            if mkdirat(openedParent, "Recovery", 0o700) != 0 && errno != EEXIST { throw SecurityUIFailure.journal }
            openedRecovery = openat(openedParent, "Recovery", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard openedRecovery >= 0 else { throw SecurityUIFailure.journal }
            try AppFileSecurity.directory(openedRecovery)
            try AppFileSecurity.directory(openedParent)
            let loadedEntries: [SecurityIntent]
            let file = openat(openedRecovery, "security-intents.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            if file < 0 {
                guard errno == ENOENT else { throw SecurityUIFailure.journal }
                loadedEntries = []
            } else {
                defer { Darwin.close(file) }
                try AppFileSecurity.regularFile(file)
                var value = stat()
                guard fstat(file, &value) == 0, value.st_size <= 1_048_576 else { throw SecurityUIFailure.journal }
                let data = try FileHandle(fileDescriptor: file, closeOnDealloc: false).readToEnd() ?? Data()
                try AppFileSecurity.regularFile(file)
                loadedEntries = try JSONDecoder().decode([SecurityIntent].self, from: data)
                guard loadedEntries.count <= 2048, Set(loadedEntries.map(\.id)).count == loadedEntries.count else { throw SecurityUIFailure.journal }
                for entry in loadedEntries { try Self.validate(entry) }
            }
            // Narrow seams verify an ACL appearing after decoding and FD reuse
            // after failed-init cleanup. Neither closure is retained by the journal.
            try beforeFinalValidation()
            try AppFileSecurity.directory(openedRecovery); try AppFileSecurity.directory(openedParent)
            let loadedRevisions = Dictionary(uniqueKeysWithValues: loadedEntries.map { ($0.id, UUID()) })
            self.parent = parent; parentFD = openedParent; fd = openedRecovery
            entries = loadedEntries; revisions = loadedRevisions
            self.beforePersist = beforePersist; self.beforeCommit = beforeCommit; self.afterRename = afterRename
            transferred = true
        } catch {
            throw SecurityUIFailure.journal
        }
    }
    deinit { Darwin.close(fd); Darwin.close(parentFD) }
    func validateAccess() throws {
        do {
            try AppFileSecurity.directory(parentFD); try AppFileSecurity.directory(fd)
            var parentNamed = stat(), parentHeld = stat(), current = stat(), held = stat()
            guard lstat(parent.path, &parentNamed) == 0, fstat(parentFD, &parentHeld) == 0,
                  parentNamed.st_dev == parentHeld.st_dev, parentNamed.st_ino == parentHeld.st_ino,
                  fstatat(parentFD, "Recovery", &current, AT_SYMLINK_NOFOLLOW) == 0, fstat(fd, &held) == 0,
                  current.st_dev == held.st_dev, current.st_ino == held.st_ino else { throw SecurityUIFailure.journal }
            let file = openat(fd, "security-intents.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            if file >= 0 { defer { Darwin.close(file) }; try AppFileSecurity.regularFile(file) }
            else if errno != ENOENT { throw SecurityUIFailure.journal }
        } catch { throw SecurityUIFailure.journal }
    }
    func all() throws -> [SecurityIntent] { try validateAccess(); return entries }
    func revision(for id: UUID) throws -> UUID? { try validateAccess(); return revisions[id] }
    func set(_ entry: SecurityIntent) throws {
        try Self.validate(entry)
        var next = entries.filter { $0.id != entry.id }; next.append(entry)
        guard next.count <= 2048 else { throw SecurityUIFailure.journal }
        do { try persist(next) }
        catch is JournalWriteFailure { entries = next; revisions[entry.id] = UUID(); throw JournalWriteFailure.committedUnsafe }
        entries = next; revisions[entry.id] = UUID()
    }
    func remove(_ id: UUID) throws {
        let next = entries.filter { $0.id != id }
        do { try persist(next) }
        catch is JournalWriteFailure { entries = next; revisions[id] = nil; throw JournalWriteFailure.committedUnsafe }
        entries = next; revisions[id] = nil
    }
    func discardPrepared(_ expected: SecurityIntent, revision: UUID) throws {
        try validateAccess()
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
        try validateAccess()
        let data = try JSONEncoder().encode(next)
        guard data.count <= 1_048_576 else { throw SecurityUIFailure.journal }
        let name = UUID().uuidString + ".tmp"
        let file = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw SecurityUIFailure.journal }
        defer { Darwin.close(file); _ = unlinkat(fd, name, 0) }
        do { try AppFileSecurity.regularFile(file) } catch { throw SecurityUIFailure.journal }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { Darwin.write(file, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw SecurityUIFailure.journal }
            offset += count
        }
        guard fsync(file) == 0 else { throw SecurityUIFailure.journal }
        try beforeCommit() // Narrow fault/ACL-race injection seam; production no-op.
        do { try AppFileSecurity.regularFile(file) } catch { throw SecurityUIFailure.journal }
        try validateAccess()
        guard renameat(fd, name, fd, "security-intents.json") == 0 else { throw SecurityUIFailure.journal }
        do {
            try afterRename()
            guard fsync(fd) == 0 else { throw SecurityUIFailure.journal }
            try validateAccess()
        } catch { throw JournalWriteFailure.committedUnsafe }
    }
}
