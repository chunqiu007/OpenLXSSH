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
        try read { try fetchHosts(query, db: $0) }
    }
    public func folders() throws -> [HostFolder] {
        try read { try fetchFolders(db: $0) }
    }
    public func folder(id: UUID) throws -> HostFolder? {
        try read { try HostFolder.fetchOne($0, key: id) }
    }
    public func folderPaths() throws -> [HostFolderPath] {
        try read { try makeFolderPaths(fetchFolders(db: $0)) }
    }
    public func folderPath(id: UUID) throws -> HostFolderPath? {
        try folderPaths().first { $0.id == id }
    }
    public func tags() throws -> [HostTag] {
        try read { try fetchTags(db: $0) }
    }
    public func tag(id: UUID) throws -> HostTag? {
        try read { try HostTag.fetchOne($0, key: id) }
    }
    /// Unknown hosts are errors, not a misleading empty assignment list.
    public func tagIDs(hostID: UUID) throws -> Set<UUID> {
        try read { db in
            try requireHost(hostID, db: db)
            return Set(try UUID.fetchAll(db, sql: "SELECT tagID FROM hostTags WHERE hostID = ?", arguments: [hostID]))
        }
    }
    public func hostMetadata(id: UUID) throws -> HostMetadata? {
        try read { db in
            guard let host = try HostConfiguration.fetchOne(db, key: id) else { return nil }
            return try makeHostMetadata([host], folders: makeFolderPaths(fetchFolders(db: db)), tags: fetchTags(db: db), db: db).first
        }
    }
    public func hostsMetadata(_ query: HostQuery = HostQuery()) throws -> [HostMetadata] {
        try vaultMetadata(query).hosts
    }
    public func vaultMetadata(_ query: HostQuery = HostQuery()) throws -> VaultMetadataSnapshot {
        try read { db in
            let folders = try makeFolderPaths(fetchFolders(db: db))
            let tags = try fetchTags(db: db)
            let hosts = try makeHostMetadata(fetchHosts(query, db: db), folders: folders, tags: tags, db: db)
            return VaultMetadataSnapshot(hosts: hosts, folders: folders, tags: tags)
        }
    }
    public func folderDeletionImpact(id: UUID) throws -> FolderDeletionImpact {
        try read { db in
            guard let folder = try HostFolder.fetchOne(db, key: id) else { throw RepositoryError.notFound }
            return FolderDeletionImpact(folder: folder,
                directHostCount: try Int.fetchOne(db, sql: "SELECT count(*) FROM hosts WHERE folderID = ?", arguments: [id]) ?? 0,
                directChildFolderCount: try Int.fetchOne(db, sql: "SELECT count(*) FROM folders WHERE parentID = ?", arguments: [id]) ?? 0)
        }
    }
    public func tagDeletionImpact(id: UUID) throws -> TagDeletionImpact {
        try read { db in
            guard let tag = try HostTag.fetchOne(db, key: id) else { throw RepositoryError.notFound }
            return TagDeletionImpact(tag: tag,
                hostCount: try Int.fetchOne(db, sql: "SELECT count(*) FROM hostTags WHERE tagID = ?", arguments: [id]) ?? 0)
        }
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
    public func moveFolder(id: UUID, parentID: UUID?) throws { try apply([.moveFolder(id, parentID: parentID)]) }
    public func deleteFolder(id: UUID) throws { try apply([.deleteFolder(id)]) }
    public func deleteFolders(ids: Set<UUID>) throws { try apply([.deleteFolders(ids)]) }
    public func moveHost(id: UUID, folderID: UUID?) throws { try apply([.moveHost(id, folderID: folderID)]) }
    public func addTag(_ tag: HostTag) throws { try apply([.addTag(tag)]) }
    public func saveTag(_ tag: HostTag) throws { try apply([.saveTag(tag)]) }
    public func renameTag(id: UUID, name: String) throws { try apply([.renameTag(id, name: name)]) }
    public func deleteTag(id: UUID) throws { try apply([.deleteTag(id)]) }
    public func assignTag(hostID: UUID, tagID: UUID) throws { try apply([.assignTag(hostID: hostID, tagID: tagID)]) }
    public func unassignTag(hostID: UUID, tagID: UUID) throws { try apply([.unassignTag(hostID: hostID, tagID: tagID)]) }
    public func setHostTags(hostID: UUID, tagIDs: Set<UUID>) throws { try apply([.setHostTags(hostID: hostID, tagIDs: tagIDs)]) }
    public func registerCredential(_ reference: CredentialReference) throws { try apply([.registerCredential(reference)]) }
    public func registerKey(_ reference: ManagedKeyReference) throws { try apply([.registerKey(reference)]) }
    /// Updates only this key's saved-passphrase reference. Detaching never deletes credential metadata;
    /// callers must explicitly delete an unreferenced credential to schedule external cleanup.
    public func updateKeyPassphrase(keyID: UUID, credentialRef: UUID?) throws {
        try apply([.updateKeyPassphrase(keyID: keyID, credentialRef: credentialRef)])
    }
    /// Presentation metadata only: never reads private material or changes saved-passphrase authorization.
    public func updateKeyLabel(keyID: UUID, label: String) throws { try apply([.updateKeyLabel(keyID: keyID, label: label)]) }
    public func deleteCredential(id: UUID) throws { try apply([.deleteCredential(id)]) }
    public func deleteKey(id: UUID) throws { try apply([.deleteKey(id)]) }
    public func saveSettings(_ value: AppSettings) throws { try apply([.saveSettings(value)]) }
    public func mergeSettings(edited: AppSettings, base: AppSettings) throws { try apply([.mergeSettings(edited: edited, base: base)]) }
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
            try db.execute(sql: "INSERT INTO hostTags(hostID, tagID) SELECT ?, tagID FROM hostTags WHERE hostID = ?", arguments: [copy.id, id])
            return copy
        }
    }

    /// Recursively copies local organization and host configuration in one immediate transaction.
    /// Concurrent writers cannot revoke/change a source reference between its read and insertion.
    /// Only the root may be renamed; its original parent and all descendant relationships are kept.
    @discardableResult
    public func copyFolder(id: UUID, name: String? = nil) throws -> HostFolder {
        try write { db in
            let paths = try makeFolderPaths(fetchFolders(db: db))
            guard let original = paths.first(where: { $0.id == id })?.components.last else { throw RepositoryError.notFound }
            let subtree = paths.filter { $0.folderIDs.contains(id) }.sorted {
                if $0.components.count != $1.components.count { return $0.components.count < $1.components.count }
                return $0.identityPath < $1.identityPath
            }
            let copiedIDs = Dictionary(uniqueKeysWithValues: subtree.map { ($0.id, UUID()) })
            guard let rootID = copiedIDs[id] else { throw RepositoryError.notFound }
            var rootCopy = original
            rootCopy.id = rootID; rootCopy.name = name ?? original.name
            for path in subtree {
                guard var folder = path.components.last, let copiedID = copiedIDs[folder.id] else { throw RepositoryError.notFound }
                folder.id = copiedID
                if path.id == id {
                    folder.name = rootCopy.name
                } else {
                    guard let parent = folder.parentID, let copiedParent = copiedIDs[parent] else { throw RepositoryError.invalidField("folderParentID") }
                    folder.parentID = copiedParent
                }
                try validateFolder(folder, db: db)
                try folder.insert(db)
            }
            for originalHost in try fetchHosts(HostQuery(folder: .folderAndDescendants(id)), db: db) {
                guard let folderID = originalHost.folderID, let copiedFolderID = copiedIDs[folderID] else { throw RepositoryError.invalidField("folderParentID") }
                var host = originalHost
                host.id = UUID(); host.folderID = copiedFolderID; host.lastConnectedAt = nil
                try host.validate()
                try host.insert(db)
                try db.execute(sql: "INSERT INTO hostTags(hostID, tagID) SELECT ?, tagID FROM hostTags WHERE hostID = ?", arguments: [host.id, originalHost.id])
            }
            return rootCopy
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
        case .updateHostIfUnchanged(var value, let expected):
            guard value.id == expected.host.id else { throw RepositoryError.staleRecord }
            guard let current = try HostConfiguration.fetchOne(db, key: value.id) else { throw RepositoryError.notFound }
            var comparable = current
            comparable.lastConnectedAt = expected.host.lastConnectedAt
            guard comparable == expected.host else { throw RepositoryError.staleRecord }
            if let tags = expected.tagIDs {
                let currentTags = Set(try UUID.fetchAll(db, sql: "SELECT tagID FROM hostTags WHERE hostID = ?", arguments: [value.id]))
                guard currentTags == tags else { throw RepositoryError.staleRecord }
            }
            value.lastConnectedAt = current.lastConnectedAt
            try value.validate(); try value.update(db)
        case .deleteHost(let id):
            _ = try HostConfiguration.deleteOne(db, key: id)
        case .saveFolder(let value):
            try validateFolder(value, db: db)
            try value.save(db)
        case .moveFolder(let id, let parentID):
            guard var folder = try HostFolder.fetchOne(db, key: id) else { throw RepositoryError.notFound }
            folder.parentID = parentID
            try validateFolder(folder, db: db)
            try folder.update(db)
        case .deleteFolder(let id):
            try dissolveFolders([id], db: db)
        case .deleteFolders(let ids):
            try dissolveFolders(ids, db: db)
        case .moveHost(let id, let folderID):
            try requireHost(id, db: db)
            if let folderID, try HostFolder.fetchOne(db, key: folderID) == nil { throw RepositoryError.notFound }
            try db.execute(sql: "UPDATE hosts SET folderID = ? WHERE id = ?", arguments: [folderID, id])
        case .addTag(let value):
            try validateText(value.name, field: "tagName", limit: 256)
            guard try HostTag.fetchOne(db, key: value.id) == nil else { throw RepositoryError.conflictingID }
            try value.insert(db)
        case .saveTag(let value):
            try validateText(value.name, field: "tagName", limit: 256)
            try value.save(db)
        case .renameTag(let id, let name):
            try validateText(name, field: "tagName", limit: 256)
            try requireTag(id, db: db)
            try db.execute(sql: "UPDATE tags SET name = ? WHERE id = ?", arguments: [name, id])
        case .deleteTag(let id):
            _ = try HostTag.deleteOne(db, key: id) // Cascades associations only, never hosts.
        case .assignTag(let hostID, let tagID):
            try requireHost(hostID, db: db); try requireTag(tagID, db: db)
            try db.execute(sql: "INSERT INTO hostTags(hostID, tagID) VALUES (?, ?) ON CONFLICT DO NOTHING", arguments: [hostID, tagID])
        case .unassignTag(let hostID, let tagID):
            try requireHost(hostID, db: db); try requireTag(tagID, db: db)
            try db.execute(sql: "DELETE FROM hostTags WHERE hostID = ? AND tagID = ?", arguments: [hostID, tagID])
        case .setHostTags(let hostID, let tagIDs):
            try requireHost(hostID, db: db)
            for id in tagIDs { try requireTag(id, db: db) }
            try db.execute(sql: "DELETE FROM hostTags WHERE hostID = ?", arguments: [hostID])
            for id in tagIDs.sorted(by: { $0.uuidString < $1.uuidString }) {
                try db.execute(sql: "INSERT INTO hostTags(hostID, tagID) VALUES (?, ?)", arguments: [hostID, id])
            }
        case .registerCredential(let value):
            guard value.isSavingAuthorized else { throw RepositoryError.savingNotAuthorized }
            try ensureNotScheduled(ExternalResource(kind: .credential, id: value.id), db: db)
            if let old = try CredentialReference.fetchOne(db, key: value.id) {
                guard old == value else { throw RepositoryError.conflictingID }
            } else { try value.insert(db) }
        case .registerKey(let value):
            try validateKeyLabel(value.label)
            try ensureNotScheduled(ExternalResource(kind: .privateKey, id: value.id), db: db)
            if let old = try ManagedKeyReference.fetchOne(db, key: value.id) {
                guard old == value else { throw RepositoryError.conflictingID }
            } else { try value.insert(db) }
        case .updateKeyPassphrase(let keyID, let credentialRef):
            guard try ManagedKeyReference.fetchOne(db, key: keyID) != nil else { throw RepositoryError.notFound }
            if let credentialRef {
                guard let credential = try CredentialReference.fetchOne(db, key: credentialRef) else { throw RepositoryError.notFound }
                guard credential.purpose == .privateKeyPassphrase else { throw RepositoryError.invalidField("passphraseCredentialRef") }
                guard credential.isSavingAuthorized else { throw RepositoryError.savingNotAuthorized }
            }
            try db.execute(sql: "UPDATE managedKeys SET passphraseCredentialRef = ? WHERE id = ?", arguments: [credentialRef, keyID])
        case .updateKeyLabel(let keyID, let label):
            try validateKeyLabel(label)
            guard try ManagedKeyReference.fetchOne(db, key: keyID) != nil else { throw RepositoryError.notFound }
            try db.execute(sql: "UPDATE managedKeys SET label = ? WHERE id = ?", arguments: [label, keyID])
        case .deleteCredential(let id):
            try deleteResource(ExternalResource(kind: .credential, id: id), db: db)
        case .deleteKey(let id):
            try deleteResource(ExternalResource(kind: .privateKey, id: id), db: db)
        case .saveSettings(let value):
            try value.validate(); try value.update(db)
        case .mergeSettings(let edited, let base):
            guard let current = try AppSettings.fetchOne(db, key: 1) else { throw RepositoryError.notFound }
            let merged = AppSettings.merging(edited: edited, base: base, onto: current)
            try merged.validate(); try merged.update(db)
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

    private func fetchHosts(_ query: HostQuery, db: Database) throws -> [HostConfiguration] {
        var commonTables: [String] = []
        var predicates: [String] = []
        var arguments = StatementArguments()
        if case .folderAndDescendants(let id) = query.folder {
            commonTables.append("""
                selectedFolders(id) AS (
                    SELECT id FROM folders WHERE id = ?
                    UNION SELECT f.id FROM folders f JOIN selectedFolders p ON f.parentID = p.id
                )
                """)
            arguments += [id]
        }
        if !query.search.isEmpty {
            commonTables.append("""
                folderPaths(id, path) AS (
                    SELECT id, name FROM folders WHERE parentID IS NULL
                    UNION ALL SELECT f.id, p.path || ' / ' || f.name FROM folders f JOIN folderPaths p ON f.parentID = p.id
                )
                """)
            predicates.append("""
                (instr(openlxssh_fold(h.name), ?) > 0 OR instr(openlxssh_fold(h.address), ?) > 0 OR
                 instr(openlxssh_fold(h.username), ?) > 0 OR
                 EXISTS(SELECT 1 FROM folderPaths p WHERE p.id = h.folderID AND instr(openlxssh_fold(p.path), ?) > 0) OR
                 EXISTS(SELECT 1 FROM hostTags ht JOIN tags t ON t.id = ht.tagID
                        WHERE ht.hostID = h.id AND instr(openlxssh_fold(t.name), ?) > 0))
                """)
            let search = Self.fold(query.search)
            arguments += [search, search, search, search, search]
        }
        if query.favoritesOnly { predicates.append("h.isFavorite = 1") }
        switch query.folder {
        case .all: break
        case .ungrouped: predicates.append("h.folderID IS NULL")
        case .folder(let id): predicates.append("h.folderID = ?"); arguments += [id]
        case .folderAndDescendants: predicates.append("h.folderID IN (SELECT id FROM selectedFolders)")
        }
        if !query.tagIDs.isEmpty {
            let ids = query.tagIDs.sorted { $0.uuidString < $1.uuidString }
            let placeholders = Array(repeating: "?", count: ids.count).joined(separator: ", ")
            predicates.append("(SELECT count(*) FROM hostTags ht WHERE ht.hostID = h.id AND ht.tagID IN (\(placeholders))) = ?")
            for id in ids { arguments += [id] }
            arguments += [ids.count]
        }
        let direction = query.sortDirection == .ascending ? "ASC" : "DESC"
        let nameOrder = "openlxssh_fold(h.name) \(direction), h.name \(direction), h.id"
        let order: String
        switch query.sort {
        case .name: order = nameOrder
        // Never-connected hosts are last in both directions; ties always have an exact UUID fallback.
        case .recentlyConnected: order = "h.lastConnectedAt IS NULL, h.lastConnectedAt \(direction), openlxssh_fold(h.name), h.name, h.id"
        case .favorites: order = "h.isFavorite DESC, h.favoriteOrder \(direction), openlxssh_fold(h.name), h.name, h.id"
        }
        let prefix = commonTables.isEmpty ? "" : "WITH RECURSIVE " + commonTables.joined(separator: ", ") + " "
        let filter = predicates.isEmpty ? "" : " WHERE " + predicates.joined(separator: " AND ")
        return try HostConfiguration.fetchAll(db, sql: prefix + "SELECT h.* FROM hosts h" + filter + " ORDER BY " + order, arguments: arguments)
    }

    private func fetchFolders(db: Database) throws -> [HostFolder] {
        try HostFolder.fetchAll(db, sql: "SELECT * FROM folders ORDER BY sortOrder, openlxssh_fold(name), name, id")
    }
    private func fetchTags(db: Database) throws -> [HostTag] {
        try HostTag.fetchAll(db, sql: "SELECT * FROM tags ORDER BY openlxssh_fold(name), name, id")
    }
    private func makeFolderPaths(_ folders: [HostFolder]) throws -> [HostFolderPath] {
        let byID = Dictionary(uniqueKeysWithValues: folders.map { ($0.id, $0) })
        var paths: [UUID: HostFolderPath] = [:]
        for folder in folders {
            var pending: [HostFolder] = []
            var current: UUID? = folder.id
            var visited: Set<UUID> = []
            while let id = current, paths[id] == nil {
                guard visited.insert(id).inserted, let ancestor = byID[id] else { throw RepositoryError.invalidField("folderParentID") }
                pending.append(ancestor)
                current = ancestor.parentID
            }
            var components = current.flatMap { paths[$0]?.components } ?? []
            for ancestor in pending.reversed() {
                components.append(ancestor)
                paths[ancestor.id] = HostFolderPath(components: components)
            }
        }
        return try folders.map {
            guard let path = paths[$0.id] else { throw RepositoryError.invalidField("folderParentID") }
            return path
        }
    }
    private func makeHostMetadata(_ hosts: [HostConfiguration], folders: [HostFolderPath], tags: [HostTag], db: Database) throws -> [HostMetadata] {
        let paths = Dictionary(uniqueKeysWithValues: folders.map { ($0.id, $0) })
        var assigned: [UUID: Set<UUID>] = [:]
        for row in try Row.fetchAll(db, sql: "SELECT hostID, tagID FROM hostTags") {
            let hostID: UUID = row["hostID"], tagID: UUID = row["tagID"]
            assigned[hostID, default: []].insert(tagID)
        }
        return hosts.map { host in
            HostMetadata(host: host, folderPath: host.folderID.flatMap { paths[$0] },
                         tags: tags.filter { assigned[host.id]?.contains($0.id) == true })
        }
    }
    private func requireHost(_ id: UUID, db: Database) throws {
        guard try HostConfiguration.fetchOne(db, key: id) != nil else { throw RepositoryError.notFound }
    }
    private func requireTag(_ id: UUID, db: Database) throws {
        guard try HostTag.fetchOne(db, key: id) != nil else { throw RepositoryError.notFound }
    }
    private func validateKeyLabel(_ label: String) throws {
        // An empty label is a valid legacy/default value, not a fabricated key identity.
        if !label.isEmpty { try validateText(label, field: "keyLabel", limit: 256) }
    }
    private func validateFolder(_ folder: HostFolder, db: Database) throws {
        try validateText(folder.name, field: "folderName", limit: 256)
        var current = folder.parentID
        var visited: Set<UUID> = [folder.id]
        while let id = current {
            guard visited.insert(id).inserted else { throw RepositoryError.invalidField("folderParentID") }
            guard let parent = try HostFolder.fetchOne(db, key: id) else { throw RepositoryError.notFound }
            current = parent.parentID
        }
    }
    private func dissolveFolders(_ ids: Set<UUID>, db: Database) throws {
        let folders = try fetchFolders(db: db)
        let byID = Dictionary(uniqueKeysWithValues: folders.map { ($0.id, $0) })
        let deleted = ids.filter { byID[$0] != nil }
        func survivingParent(of folder: HostFolder) throws -> UUID? {
            var parent = folder.parentID
            var visited: Set<UUID> = [folder.id]
            while let id = parent, deleted.contains(id) {
                guard visited.insert(id).inserted, let ancestor = byID[id] else { throw RepositoryError.invalidField("folderParentID") }
                parent = ancestor.parentID
            }
            return parent
        }
        // All destinations use the original hierarchy, not a Set's iteration order.
        for folder in folders where !deleted.contains(folder.id) && folder.parentID.map({ deleted.contains($0) }) == true {
            try db.execute(sql: "UPDATE folders SET parentID = ? WHERE id = ?", arguments: [try survivingParent(of: folder), folder.id])
        }
        let ordered = deleted.sorted { $0.uuidString < $1.uuidString }
        for id in ordered {
            guard let folder = byID[id] else { continue }
            try db.execute(sql: "UPDATE hosts SET folderID = ? WHERE folderID = ?", arguments: [try survivingParent(of: folder), id])
            // Detach deleted nodes from one another before exact-ID deletes enforce RESTRICT.
            try db.execute(sql: "UPDATE folders SET parentID = NULL WHERE id = ?", arguments: [id])
        }
        for id in ordered { _ = try HostFolder.deleteOne(db, key: id) }
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
