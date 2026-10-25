import Foundation
import GRDB

/// Thread-safe synchronous data boundary. UI callers should schedule database work off the main thread.
/// No sessions, terminal output, secret storage, network, or Keychain operations live here.
public final class OpenLXSSHDatabase: Sendable {
    public let databaseURL: URL
    private let location: SecureDatabaseLocation
    let queue: DatabaseQueue

    /// The existing parent must be owned by the caller; the leaf is reserved exclusively for this database.
    public init(directory: URL) throws {
        let location = try SecureDatabaseLocation(directory: directory)
        var configuration = Configuration()
        configuration.label = "OpenLXSSHCore"
        configuration.foreignKeysEnabled = true
        configuration.publicStatementArguments = false
        configuration.journalMode = .wal
        configuration.busyMode = .timeout(5)
        configuration.prepareDatabase { db in
            try location.validateAndSecureFiles()
            try db.execute(sql: "PRAGMA synchronous = FULL")
            db.add(function: DatabaseFunction("openlxssh_fold", argumentCount: 1, pure: true) { values in
                Self.fold(String.fromDatabaseValue(values[0]) ?? "")
            })
        }
        let queue = try location.withInitializationLock {
            let queue = try DatabaseQueue(path: location.databaseURL.path, configuration: configuration)
            do {
                // GRDB's WAL setup selects NORMAL after prepareDatabase; restore durability
                // on the final writer connection before any migrations or application writes.
                try queue.writeWithoutTransaction { try $0.execute(sql: "PRAGMA synchronous = FULL") }
                try CoreSchema.migrate(queue)
                try location.validateAndSecureFiles()
                return queue
            } catch {
                try? queue.close()
                throw error
            }
        }
        self.location = location; self.databaseURL = location.databaseURL; self.queue = queue
    }

    /// Close only once no work is in flight. Repeated close calls are safe.
    public func close() throws { try queue.close() }

    public func host(id: UUID) throws -> HostConfiguration? {
        try read { try HostConfiguration.fetchOne($0, key: id) }
    }
    public func hosts(_ query: HostQuery = HostQuery()) throws -> [HostConfiguration] {
        try read { db in
            var predicates: [String] = []
            var arguments = StatementArguments()
            if !query.search.isEmpty {
                predicates.append("(instr(openlxssh_fold(name), ?) > 0 OR instr(openlxssh_fold(address), ?) > 0 OR instr(openlxssh_fold(username), ?) > 0)")
                let search = Self.fold(query.search)
                arguments += [search, search, search]
            }
            if query.favoritesOnly { predicates.append("isFavorite = 1") }
            switch query.folder {
            case .all: break
            case .ungrouped: predicates.append("folderID IS NULL")
            case .folder(let id): predicates.append("folderID = ?"); arguments += [id]
            }
            let order: String
            switch query.sort {
            case .name: order = "openlxssh_fold(name), name, id"
            case .recentlyConnected: order = "lastConnectedAt IS NULL, lastConnectedAt DESC, openlxssh_fold(name), name, id"
            case .favorites: order = "isFavorite DESC, favoriteOrder, openlxssh_fold(name), name, id"
            }
            let filter = predicates.isEmpty ? "" : " WHERE " + predicates.joined(separator: " AND ")
            return try HostConfiguration.fetchAll(db, sql: "SELECT * FROM hosts" + filter + " ORDER BY " + order, arguments: arguments)
        }
    }
    public func folders() throws -> [HostFolder] {
        try read { try HostFolder.fetchAll($0, sql: "SELECT * FROM folders ORDER BY sortOrder, openlxssh_fold(name), name, id") }
    }
    public func credentials() throws -> [CredentialReference] {
        try read { try CredentialReference.fetchAll($0, sql: "SELECT * FROM credentials ORDER BY id") }
    }
    public func keys() throws -> [ManagedKeyReference] {
        try read { try ManagedKeyReference.fetchAll($0, sql: "SELECT * FROM managedKeys ORDER BY id") }
    }
    public func settings() throws -> AppSettings {
        try read { db in
            guard let value = try AppSettings.fetchOne(db, key: 1) else { throw RepositoryError.notFound }
            return value
        }
    }
    public func cleanupTickets(includeCompleted: Bool = false) throws -> [CleanupTicket] {
        try read { try CleanupTicket.fetchAll($0, sql: "SELECT * FROM cleanupTickets" + (includeCompleted ? "" : " WHERE state = 'pending'") + " ORDER BY createdAt, id") }
    }

    public func addHost(_ host: HostConfiguration) throws { try apply([.insertHost(host)]) }
    public func updateHost(_ host: HostConfiguration) throws { try apply([.updateHost(host)]) }
    public func deleteHost(id: UUID) throws { try apply([.deleteHost(id)]) }
    public func saveFolder(_ folder: HostFolder) throws { try apply([.saveFolder(folder)]) }
    public func deleteFolder(id: UUID) throws { try apply([.deleteFolder(id)]) }
    public func registerCredential(_ reference: CredentialReference) throws { try apply([.registerCredential(reference)]) }
    public func registerKey(_ reference: ManagedKeyReference) throws { try apply([.registerKey(reference)]) }
    public func deleteCredential(id: UUID) throws { try apply([.deleteCredential(id)]) }
    public func deleteKey(id: UUID) throws { try apply([.deleteKey(id)]) }
    public func saveSettings(_ value: AppSettings) throws { try apply([.saveSettings(value)]) }
    public func setFavorite(hostID: UUID, isFavorite: Bool, order: Int = 0) throws { try apply([.setFavorite(hostID, isFavorite, order: order)]) }
    public func markConnected(hostID: UUID, at date: Date) throws { try apply([.markConnected(hostID, date)]) }
    public func scheduleOrphanCleanup(_ resource: ExternalResource) throws { try apply([.scheduleOrphanCleanup(resource)]) }

    /// Copies configuration and shared references. A copy has no connection history, and a new stable identity.
    @discardableResult
    public func copyHost(id: UUID, name: String? = nil) throws -> HostConfiguration {
        try write { db in
            guard var copy = try HostConfiguration.fetchOne(db, key: id) else { throw RepositoryError.notFound }
            copy.id = UUID(); copy.name = name ?? copy.name; copy.lastConnectedAt = nil
            try copy.validate()
            try copy.insert(db)
            return copy
        }
    }

    /// Changes execute in array order inside one immediate SQLite write transaction.
    public func apply(_ changes: [RepositoryChange]) throws {
        try applyTransaction(changes, beforeCommit: {})
    }

    // Narrow test seam: the injected error happens after real SQL and before the actual COMMIT.
    func applyTransaction(_ changes: [RepositoryChange], beforeCommit: () throws -> Void) throws {
        try write { db in
            for change in changes { try perform(change, db: db) }
            try beforeCommit()
        }
    }

    /// Called by an external resource worker *after* an idempotent deletion succeeds (including already absent).
    /// Completed tombstones are retained so a UUID can never be re-registered during/after cleanup.
    public func completeCleanup(ticketID: UUID) throws {
        try write { db in
            guard try CleanupTicket.fetchOne(db, key: ticketID) != nil else { throw RepositoryError.notFound }
            try db.execute(sql: "UPDATE cleanupTickets SET state = 'completed', lastFailure = NULL WHERE id = ?", arguments: [ticketID])
        }
    }
    public func recordCleanupFailure(ticketID: UUID, failure: CleanupFailure) throws {
        try write { db in
            guard try CleanupTicket.fetchOne(db, key: ticketID) != nil else { throw RepositoryError.notFound }
            try db.execute(sql: "UPDATE cleanupTickets SET attemptCount = min(attemptCount + 1, 1000000), lastFailure = ? WHERE id = ? AND state = 'pending'", arguments: [failure, ticketID])
        }
    }

    private func perform(_ change: RepositoryChange, db: Database) throws {
        switch change {
        case .insertHost(let value):
            try value.validate(); try value.insert(db)
        case .updateHost(let value):
            try value.validate()
            guard try HostConfiguration.fetchOne(db, key: value.id) != nil else { throw RepositoryError.notFound }
            try value.update(db)
        case .deleteHost(let id):
            _ = try HostConfiguration.deleteOne(db, key: id)
        case .saveFolder(let value):
            try validateText(value.name, field: "folderName", limit: 256)
            try value.save(db)
        case .deleteFolder(let id):
            _ = try HostFolder.deleteOne(db, key: id) // FK SET NULL, never cascade host deletion.
        case .registerCredential(let value):
            guard value.isSavingAuthorized else { throw RepositoryError.savingNotAuthorized }
            try ensureNotScheduled(ExternalResource(kind: .credential, id: value.id), db: db)
            if let old = try CredentialReference.fetchOne(db, key: value.id) {
                guard old == value else { throw RepositoryError.conflictingID }
            } else { try value.insert(db) }
        case .registerKey(let value):
            try ensureNotScheduled(ExternalResource(kind: .privateKey, id: value.id), db: db)
            if let old = try ManagedKeyReference.fetchOne(db, key: value.id) {
                guard old == value else { throw RepositoryError.conflictingID }
            } else { try value.insert(db) }
        case .deleteCredential(let id):
            try deleteResource(ExternalResource(kind: .credential, id: id), db: db)
        case .deleteKey(let id):
            try deleteResource(ExternalResource(kind: .privateKey, id: id), db: db)
        case .saveSettings(let value):
            try value.validate(); try value.update(db)
        case .setFavorite(let id, let favorite, let order):
            guard (-1_000_000_000...1_000_000_000).contains(order) else { throw RepositoryError.invalidField("favoriteOrder") }
            guard try HostConfiguration.fetchOne(db, key: id) != nil else { throw RepositoryError.notFound }
            try db.execute(sql: "UPDATE hosts SET isFavorite = ?, favoriteOrder = ? WHERE id = ?", arguments: [favorite, order, id])
        case .markConnected(let id, let date):
            guard date.timeIntervalSince1970.isFinite else { throw RepositoryError.invalidField("lastConnectedAt") }
            guard try HostConfiguration.fetchOne(db, key: id) != nil else { throw RepositoryError.notFound }
            // A late activity notification must not move a host backwards in the recent list.
            try db.execute(sql: "UPDATE hosts SET lastConnectedAt = ? WHERE id = ? AND (lastConnectedAt IS NULL OR lastConnectedAt < ?)", arguments: [date.timeIntervalSince1970, id, date.timeIntervalSince1970])
        case .scheduleOrphanCleanup(let resource):
            guard try !resourceExists(resource, db: db) else { throw RepositoryError.resourceStillRegistered }
            try schedule(resource, reason: .orphanedExternalResource, db: db)
        }
    }

    private func ensureNotScheduled(_ resource: ExternalResource, db: Database) throws {
        if try Bool.fetchOne(db, sql: "SELECT EXISTS(SELECT 1 FROM cleanupTickets WHERE resourceKind = ? AND resourceID = ?)", arguments: [resource.kind, resource.id]) == true {
            throw RepositoryError.cleanupAlreadyScheduled
        }
    }
    private func resourceExists(_ resource: ExternalResource, db: Database) throws -> Bool {
        let table = resource.kind == .credential ? "credentials" : "managedKeys"
        return try Bool.fetchOne(db, sql: "SELECT EXISTS(SELECT 1 FROM \(table) WHERE id = ?)", arguments: [resource.id]) == true
    }
    private func deleteResource(_ resource: ExternalResource, db: Database) throws {
        guard try resourceExists(resource, db: db) else { return }
        let inUse: Bool
        switch resource.kind {
        case .credential:
            inUse = try Bool.fetchOne(db, sql: "SELECT EXISTS(SELECT 1 FROM hosts WHERE credentialRef = ?) OR EXISTS(SELECT 1 FROM managedKeys WHERE passphraseCredentialRef = ?)", arguments: [resource.id, resource.id]) == true
        case .privateKey:
            inUse = try Bool.fetchOne(db, sql: "SELECT EXISTS(SELECT 1 FROM hosts WHERE keyRef = ?)", arguments: [resource.id]) == true
        }
        guard !inUse else { throw RepositoryError.resourceInUse }
        let table = resource.kind == .credential ? "credentials" : "managedKeys"
        try db.execute(sql: "DELETE FROM \(table) WHERE id = ?", arguments: [resource.id])
        try schedule(resource, reason: .removedReference, db: db)
    }
    private func schedule(_ resource: ExternalResource, reason: CleanupReason, db: Database) throws {
        // A unique (kind, ID) makes retries stable; never erase a completed tombstone.
        try db.execute(sql: """
            INSERT INTO cleanupTickets(id, resourceKind, resourceID, reason, state, createdAt, attemptCount)
            VALUES (?, ?, ?, ?, 'pending', ?, 0) ON CONFLICT(resourceKind, resourceID) DO NOTHING
            """, arguments: [UUID(), resource.kind, resource.id, reason, Date().timeIntervalSince1970])
    }
    private func read<T>(_ body: (Database) throws -> T) throws -> T {
        try location.validateAndSecureFiles()
        return try queue.read(body)
    }
    private func write<T>(_ body: (Database) throws -> T) throws -> T {
        try location.validateAndSecureFiles()
        return try queue.write { db in
            let result = try body(db)
            try location.validateAndSecureFiles()
            return result
        }
    }
    private static func fold(_ text: String) -> String {
        text.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "en_US_POSIX"))
    }
}
