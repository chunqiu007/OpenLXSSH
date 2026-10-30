import Darwin
import Foundation
import OpenLXSSHCore

enum AppStorageFailure: Error, Sendable { case committedStorageUnsafe }

struct AppSnapshot: Sendable {
    var hosts: [HostConfiguration]
    var folders: [HostFolder]
    var keys: [ManagedKeyReference]
    var settings: AppSettings
    var allHosts: [HostConfiguration]? = nil
}

protocol AppRepositoryProtocol: Sendable {
    func snapshot(query: HostQuery) async throws -> AppSnapshot
    func apply(_ changes: [RepositoryChange]) async throws
    func copyHost(id: UUID) async throws -> HostConfiguration
    func copyFolder(id: UUID) async throws -> HostFolder
    func close() async throws
    func securityMetadata() async throws -> SecurityMetadata
    func completeCleanup(_ id: UUID) async throws
    func recordCleanupFailure(_ id: UUID, failure: CleanupFailure) async throws
}

struct SecurityMetadata: Sendable {
    var hosts: [HostConfiguration]
    var keys: [ManagedKeyReference]
    var credentials: [OpenLXSSHCore.CredentialReference]
    var tickets: [CleanupTicket]
    var completedTickets: [CleanupTicket] = []
}

extension AppRepositoryProtocol {
    func securityMetadata() async throws -> SecurityMetadata { throw RepositoryError.notFound }
    func completeCleanup(_ id: UUID) async throws { throw RepositoryError.notFound }
    func recordCleanupFailure(_ id: UUID, failure: CleanupFailure) async throws { throw RepositoryError.notFound }
}

enum AppDataLocation: Sendable {
    case applicationSupport
    /// Test callers must supply an existing, exclusively owned temporary directory.
    case isolated(URL)

    func databaseDirectory() throws -> URL {
        switch self {
        case .applicationSupport:
            guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
                throw RepositoryError.unsafeDatabaseLocation
            }
            // Do not chmod Library or Application Support. Only create/secure our own child.
            let base = support.resolvingSymlinksInPath()
            let fd = open(base.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
            defer { Darwin.close(fd) }
            try Self.ensureAppParent(in: fd)
            return base.appendingPathComponent("OpenLXSSH", isDirectory: true).appendingPathComponent("Data", isDirectory: true)
        case .isolated(let supplied):
            let temporary = try Self.canonical(FileManager.default.temporaryDirectory)
            let parent = try Self.canonical(supplied.deletingLastPathComponent())
            let name = supplied.lastPathComponent
            guard supplied.isFileURL, parent == temporary,
                  name.hasPrefix("OpenLXSSH-AppSmoke-") || name.hasPrefix("OpenLXSSH-AppTests-") else {
                throw RepositoryError.unsafeDatabaseLocation
            }
            let fd = open(supplied.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
            defer { Darwin.close(fd) }
            try AppFileSecurity.directory(fd)
            return supplied.appendingPathComponent("Data", isDirectory: true)
        }
    }

    static func canonical(_ url: URL) throws -> URL {
        guard let path = realpath(url.path, nil) else { throw RepositoryError.unsafeDatabaseLocation }
        defer { free(path) }
        return URL(fileURLWithPath: String(cString: path), isDirectory: true)
    }

    static func ensureAppParent(in parent: Int32) throws {
        try AppFileSecurity.applicationSupportParent(parent)
        if mkdirat(parent, "OpenLXSSH", 0o700) != 0 && errno != EEXIST { throw RepositoryError.unsafeDatabaseLocation }
        let fd = openat(parent, "OpenLXSSH", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
        defer { Darwin.close(fd) }
        // Check ACL before chmod: never silently repair access policy supplied by a user.
        try AppFileSecurity.directory(fd, mode: nil)
        guard fchmod(fd, 0o700) == 0 else { throw RepositoryError.unsafeDatabaseLocation }
        try AppFileSecurity.directory(fd)
        try AppFileSecurity.applicationSupportParent(parent)
    }
}

/// This actor owns initialization, reads, writes and closure of the synchronous Core boundary.
/// Nothing in this type is MainActor-isolated, and no database work runs in a SwiftUI body.
actor AppRepository: AppRepositoryProtocol {
    private let location: AppDataLocation
    private var database: OpenLXSSHDatabase?
    private let afterCommit: @Sendable () throws -> Void
    init(location: AppDataLocation = .applicationSupport, afterCommit: @escaping @Sendable () throws -> Void = {}) {
        self.location = location; self.afterCommit = afterCommit
    }

    private func opened() throws -> OpenLXSSHDatabase {
        let directory = try location.databaseDirectory()
        if let database { return database }
        let value = try OpenLXSSHDatabase(directory: directory)
        database = value
        return value
    }

    func snapshot(query: HostQuery) throws -> AppSnapshot {
        let db = try opened()
        let snapshot = AppSnapshot(hosts: try db.hosts(query), folders: try db.folders(), keys: try db.keys(), settings: try db.settings(), allHosts: try db.hosts())
        _ = try location.databaseDirectory()
        return snapshot
    }

    private func validateCommittedStorage() throws {
        do { try afterCommit(); _ = try location.databaseDirectory() }
        catch { throw AppStorageFailure.committedStorageUnsafe }
    }
    func apply(_ changes: [RepositoryChange]) throws {
        try opened().apply(changes)
        try validateCommittedStorage()
    }

    func copyHost(id: UUID) throws -> HostConfiguration {
        let db = try opened()
        guard let original = try db.host(id: id) else { throw RepositoryError.notFound }
        let copy = try db.copyHost(id: id, name: Self.copyName(original.name))
        try validateCommittedStorage()
        return copy
    }

    /// Copy configuration in one transaction. Shared key/credential references stay shared;
    /// neither external secrets nor connection history are copied or created here.
    func copyFolder(id: UUID) throws -> HostFolder {
        let db = try opened()
        guard let original = try db.folders().first(where: { $0.id == id }) else { throw RepositoryError.notFound }
        let copy = HostFolder(name: Self.copyName(original.name), sortOrder: original.sortOrder)
        var changes: [RepositoryChange] = [.saveFolder(copy)]
        for var host in try db.hosts(HostQuery(folder: .folder(id))) {
            host.id = UUID(); host.folderID = copy.id; host.lastConnectedAt = nil
            changes.append(.insertHost(host))
        }
        try db.apply(changes)
        try validateCommittedStorage()
        return copy
    }

    private static func copyName(_ name: String) -> String {
        let suffix = " 副本"
        var prefix = name
        while prefix.utf8.count + suffix.utf8.count > 256 { prefix.removeLast() }
        return prefix + suffix
    }

    func securityMetadata() async throws -> SecurityMetadata {
        let db = try opened()
        let tickets = try db.cleanupTickets(includeCompleted: true)
        let metadata = SecurityMetadata(hosts: try db.hosts(), keys: try db.keys(), credentials: try db.credentials(),
                                        tickets: tickets.filter { $0.state == .pending }, completedTickets: tickets.filter { $0.state == .completed })
        _ = try location.databaseDirectory()
        return metadata
    }
    func completeCleanup(_ id: UUID) async throws { try opened().completeCleanup(ticketID: id); try validateCommittedStorage() }
    func recordCleanupFailure(_ id: UUID, failure: CleanupFailure) async throws { try opened().recordCleanupFailure(ticketID: id, failure: failure); try validateCommittedStorage() }

    func close() throws {
        try database?.close()
        database = nil
    }
}
