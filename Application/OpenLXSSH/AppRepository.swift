import Darwin
import Foundation
import OpenLXSSHCore

struct AppSnapshot: Sendable {
    var hosts: [HostConfiguration]
    var folders: [HostFolder]
    var keys: [ManagedKeyReference]
    var settings: AppSettings
}

protocol AppRepositoryProtocol: Sendable {
    func snapshot(query: HostQuery) async throws -> AppSnapshot
    func apply(_ changes: [RepositoryChange]) async throws
    func copyHost(id: UUID) async throws -> HostConfiguration
    func copyFolder(id: UUID) async throws -> HostFolder
    func close() async throws
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
            let temporary = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().standardizedFileURL
            let parent = supplied.deletingLastPathComponent().resolvingSymlinksInPath().standardizedFileURL
            let name = supplied.lastPathComponent
            guard supplied.isFileURL, parent == temporary,
                  name.hasPrefix("OpenLXSSH-AppSmoke-") || name.hasPrefix("OpenLXSSH-AppTests-") else {
                throw RepositoryError.unsafeDatabaseLocation
            }
            let fd = open(supplied.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
            defer { Darwin.close(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
                throw RepositoryError.unsafeDatabaseLocation
            }
            return supplied.appendingPathComponent("Data", isDirectory: true)
        }
    }

    private static func ensureAppParent(in parent: Int32) throws {
        var owner = stat()
        guard fstat(parent, &owner) == 0, owner.st_uid == geteuid() else { throw RepositoryError.unsafeDatabaseLocation }
        if mkdirat(parent, "OpenLXSSH", 0o700) != 0 && errno != EEXIST { throw RepositoryError.unsafeDatabaseLocation }
        let fd = openat(parent, "OpenLXSSH", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
        defer { Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == geteuid(), info.st_mode & S_IFMT == S_IFDIR,
              fchmod(fd, 0o700) == 0 else { throw RepositoryError.unsafeDatabaseLocation }
    }
}

/// This actor owns initialization, reads, writes and closure of the synchronous Core boundary.
/// Nothing in this type is MainActor-isolated, and no database work runs in a SwiftUI body.
actor AppRepository: AppRepositoryProtocol {
    private let location: AppDataLocation
    private var database: OpenLXSSHDatabase?
    init(location: AppDataLocation = .applicationSupport) { self.location = location }

    private func opened() throws -> OpenLXSSHDatabase {
        if let database { return database }
        let value = try OpenLXSSHDatabase(directory: location.databaseDirectory())
        database = value
        return value
    }

    func snapshot(query: HostQuery) throws -> AppSnapshot {
        let db = try opened()
        return AppSnapshot(hosts: try db.hosts(query), folders: try db.folders(), keys: try db.keys(), settings: try db.settings())
    }

    func apply(_ changes: [RepositoryChange]) throws { try opened().apply(changes) }

    func copyHost(id: UUID) throws -> HostConfiguration {
        let db = try opened()
        guard let original = try db.host(id: id) else { throw RepositoryError.notFound }
        return try db.copyHost(id: id, name: Self.copyName(original.name))
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
        return copy
    }

    private static func copyName(_ name: String) -> String {
        let suffix = " 副本"
        var prefix = name
        while prefix.utf8.count + suffix.utf8.count > 256 { prefix.removeLast() }
        return prefix + suffix
    }

    func close() throws {
        try database?.close()
        database = nil
    }
}
