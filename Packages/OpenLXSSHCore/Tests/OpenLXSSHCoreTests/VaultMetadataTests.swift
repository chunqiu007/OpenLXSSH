import Foundation
import GRDB
import XCTest
@testable import OpenLXSSHCore

final class VaultMetadataTests: XCTestCase {
    private var directory: URL!
    private var database: OpenLXSSHDatabase!
    private let legacyVersions = ["v1_host_metadata", "v2_settings_and_cleanup"]

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("openlxssh-vault-test-" + UUID().uuidString, isDirectory: true)
        database = try OpenLXSSHDatabase(directory: directory)
    }
    override func tearDownWithError() throws {
        try database?.close()
        database = nil
        if let directory, FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
    }
    private func reopen() throws {
        try database.close(); database = nil
        database = try OpenLXSSHDatabase(directory: directory)
    }
    private func host(_ name: String = "synthetic", folderID: UUID? = nil) -> HostConfiguration {
        HostConfiguration(name: name, address: "never-connected.invalid", username: "fixture", folderID: folderID)
    }
    private func expect(_ expected: RepositoryError, _ body: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? RepositoryError, expected, file: file, line: line)
        }
    }
    private func checkIntegrity(file: StaticString = #filePath, line: UInt = #line) throws {
        try database.queue.read {
            XCTAssertEqual(try String.fetchOne($0, sql: "PRAGMA integrity_check"), "ok", file: file, line: line)
            XCTAssertTrue(try Row.fetchAll($0, sql: "PRAGMA foreign_key_check").isEmpty, file: file, line: line)
        }
    }
    private func installLegacy(version: Int, extraSQL: String = "") throws -> URL {
        try database.close(); database = nil
        try FileManager.default.removeItem(at: directory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let url = directory.appendingPathComponent("OpenLXSSH.sqlite")
        XCTAssertTrue(FileManager.default.createFile(atPath: url.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
        let raw = try DatabaseQueue(path: url.path)
        try raw.write { db in
            for number in 1...version {
                let fixture = try XCTUnwrap(Bundle.module.url(forResource: "schema-v\(number)", withExtension: "sql", subdirectory: "Fixtures"))
                try db.execute(sql: String(contentsOf: fixture, encoding: .utf8))
            }
            try db.execute(sql: extraSQL)
        }
        try raw.close()
        return url
    }
    private struct LegacyTable {
        var name: String
        var columns: [String]
        var rows: [Row]
    }
    private func captureLegacy(_ url: URL, version: Int) throws -> [LegacyTable] {
        let raw = try DatabaseQueue(path: url.path)
        defer { try? raw.close() }
        return try raw.read { db in
            try (["folders", "credentials", "managedKeys", "hosts"] + (version == 2 ? ["settings", "cleanupTickets"] : [])).map { table in
                let columns = try Row.fetchAll(db, sql: "PRAGMA table_info(\(table))").map { $0["name"] as String }
                return LegacyTable(name: table, columns: columns, rows: try Row.fetchAll(db, sql: "SELECT * FROM \(table) ORDER BY id"))
            }
        }
    }
    private func assertPreserved(_ baseline: [LegacyTable], db: Database, file: StaticString = #filePath, line: UInt = #line) throws {
        for table in baseline {
            let projection = table.columns.map { "\"\($0)\"" }.joined(separator: ", ")
            XCTAssertEqual(try Row.fetchAll(db, sql: "SELECT \(projection) FROM \(table.name) ORDER BY id"), table.rows, table.name, file: file, line: line)
        }
    }

    func testV1MigrationPreservesEveryLegacyColumnAndSafeMetadataDefaults() throws {
        let url = try installLegacy(version: 1)
        let baseline = try captureLegacy(url, version: 1)
        database = try OpenLXSSHDatabase(directory: directory)
        try database.queue.read { try assertPreserved(baseline, db: $0) }
        XCTAssertEqual(try database.hosts().count, 2)
        XCTAssertEqual(try database.folders().map(\.parentID), [nil])
        XCTAssertEqual(try database.keys().map(\.label), [""])
        XCTAssertEqual(try database.keys().first?.id, UUID(uuidString: "44444444-4444-4444-8444-444444444444"))
        XCTAssertEqual(try database.keys().first?.passphraseCredentialRef, UUID(uuidString: "33333333-3333-4333-8333-333333333333"))
        let saved = try XCTUnwrap(database.hosts().first { $0.credentialRef != nil })
        XCTAssertTrue(saved.savePasswordAuthorized)
        XCTAssertEqual(saved.authentication, .password)
        XCTAssertEqual(saved.favoriteOrder, 0)
        XCTAssertTrue(saved.isFavorite)
        XCTAssertEqual(saved.lastConnectedAt, Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertTrue(try database.tags().isEmpty)
        XCTAssertTrue(try database.hostsMetadata().allSatisfy { $0.tags.isEmpty })
        try reopen()
        try database.queue.read { try assertPreserved(baseline, db: $0) }
        try checkIntegrity()
    }

    func testV2MigrationPreservesIDsReferencesFourAuthKindsSettingsAndTombstones() throws {
        let url = try installLegacy(version: 2)
        let baseline = try captureLegacy(url, version: 2)
        database = try OpenLXSSHDatabase(directory: directory)
        try database.queue.read { db in
            try assertPreserved(baseline, db: db)
            XCTAssertEqual(try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations ORDER BY identifier"), legacyVersions + ["v3_vault_metadata"])
        }
        XCTAssertEqual(Set(try database.hosts().map(\.authentication)), [.password, .passwordWithMFA, .privateKey, .privateKeyWithMFA])
        XCTAssertEqual(try database.hosts().filter { $0.savePasswordAuthorized }.count, 2)
        XCTAssertEqual(try database.hosts().filter { $0.credentialRef != nil }.count, 2)
        XCTAssertEqual(try database.hosts().filter { $0.keyRef != nil }.count, 2)
        XCTAssertEqual(try database.settings().historyLines, 4321)
        XCTAssertEqual(try database.keys().map(\.label), [""])
        XCTAssertEqual(try database.cleanupTickets().count, 1)
        XCTAssertEqual(try database.cleanupTickets(includeCompleted: true).count, 2)
        expect(.cleanupAlreadyScheduled) {
            try database.registerKey(ManagedKeyReference(id: UUID(uuidString: "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC")!, algorithm: .rsa))
        }
        try reopen()
        try database.queue.read { try assertPreserved(baseline, db: $0) }
        try checkIntegrity()
    }

    func testCopiesOfMigratedV1AndV2KeepLegacyAuthorizationAndSharedReferences() throws {
        for version in [1, 2] {
            _ = try installLegacy(version: version)
            database = try OpenLXSSHDatabase(directory: directory)
            let originals = try database.hosts()
            let credentials = try database.credentials(), keys = try database.keys()
            let tickets = try database.cleanupTickets(includeCompleted: true)
            let parent = try XCTUnwrap(database.folders().first)
            let nested = HostFolder(name: "new nested metadata", parentID: parent.id)
            let tag = HostTag(name: "local tag")
            try database.apply([.saveFolder(nested), .addTag(tag)])
            for original in originals {
                try database.apply([.moveHost(original.id, folderID: nested.id), .assignTag(hostID: original.id, tagID: tag.id)])
                let copied = try database.copyHost(id: original.id)
                var expected = original
                expected.id = copied.id; expected.folderID = nested.id; expected.lastConnectedAt = nil
                XCTAssertEqual(copied, expected)
                XCTAssertEqual(try database.tagIDs(hostID: copied.id), [tag.id])
                XCTAssertEqual(try database.hostMetadata(id: copied.id)?.folderPath?.folderIDs, [parent.id, nested.id])
            }
            XCTAssertEqual(try database.credentials(), credentials)
            XCTAssertEqual(try database.keys(), keys)
            XCTAssertEqual(try database.cleanupTickets(includeCompleted: true), tickets)
            try reopen()
            XCTAssertEqual(try database.hosts().count, originals.count * 2)
            try checkIntegrity()
        }
    }

    func testV3MigrationFailureRollsBackBothALTERsAndCanRetryWithoutDataReset() throws {
        let url = try installLegacy(version: 2, extraSQL: "CREATE TABLE tags(marker TEXT); INSERT INTO tags VALUES ('preserve collision');")
        let baseline = try captureLegacy(url, version: 2)
        XCTAssertThrowsError(try OpenLXSSHDatabase(directory: directory))
        let raw = try DatabaseQueue(path: url.path)
        try raw.read { db in
            try assertPreserved(baseline, db: db)
            XCTAssertFalse(try Row.fetchAll(db, sql: "PRAGMA table_info(folders)").contains { ($0["name"] as String) == "parentID" })
            XCTAssertFalse(try Row.fetchAll(db, sql: "PRAGMA table_info(managedKeys)").contains { ($0["name"] as String) == "label" })
            XCTAssertFalse(try db.tableExists("hostTags"))
            XCTAssertEqual(try String.fetchOne(db, sql: "SELECT marker FROM tags"), "preserve collision")
            XCTAssertEqual(try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations ORDER BY identifier"), legacyVersions)
        }
        try raw.write { try $0.execute(sql: "DROP TABLE tags") }
        try raw.close()
        database = try OpenLXSSHDatabase(directory: directory)
        try database.queue.read { try assertPreserved(baseline, db: $0) }
        try checkIntegrity()
    }

    func testMigrationRejectsKnownVersionGapWithoutAddingColumnsOrReset() throws {
        let url = try installLegacy(version: 2, extraSQL: "DELETE FROM grdb_migrations WHERE identifier = 'v1_host_metadata';")
        let baseline = try captureLegacy(url, version: 2)
        expect(.unsupportedSchema) { _ = try OpenLXSSHDatabase(directory: directory) }
        let raw = try DatabaseQueue(path: url.path)
        defer { try? raw.close() }
        try raw.read { db in
            try assertPreserved(baseline, db: db)
            XCTAssertEqual(try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations"), ["v2_settings_and_cleanup"])
            XCTAssertFalse(try db.tableExists("tags"))
            XCTAssertFalse(try Row.fetchAll(db, sql: "PRAGMA table_info(managedKeys)").contains { ($0["name"] as String) == "label" })
        }
    }

    func testV2ForeignKeyViolationFailsV3TransactionWithoutErasingLegacyRows() throws {
        let url = try installLegacy(version: 2)
        let corrupt = try DatabaseQueue(path: url.path)
        try corrupt.writeWithoutTransaction { db in
            try db.execute(sql: "PRAGMA foreign_keys = OFF")
            try db.execute(sql: "UPDATE hosts SET folderID = X'DDDDDDDDDDDD4DDD8DDDDDDDDDDDDDDD' WHERE folderID IS NOT NULL")
        }
        try corrupt.close()
        let baseline = try captureLegacy(url, version: 2)
        XCTAssertThrowsError(try OpenLXSSHDatabase(directory: directory))
        let raw = try DatabaseQueue(path: url.path)
        defer { try? raw.close() }
        try raw.read { db in
            try assertPreserved(baseline, db: db)
            XCTAssertEqual(try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations ORDER BY identifier"), legacyVersions)
            XCTAssertFalse(try db.tableExists("tags"))
            XCTAssertFalse(try Row.fetchAll(db, sql: "PRAGMA table_info(folders)").contains { ($0["name"] as String) == "parentID" })
        }
    }

    func testOlderCodableMetadataUsesSafeDefaultsAndStillRejectsMalformedFields() throws {
        let folderID = UUID(), keyID = UUID(), credentialID = UUID(), hostID = UUID()
        let decoder = JSONDecoder()
        let folder = try decoder.decode(HostFolder.self, from: Data("{\"id\":\"\(folderID)\",\"name\":\"旧分组\"}".utf8))
        XCTAssertEqual(folder, HostFolder(id: folderID, name: "旧分组"))
        let key = try decoder.decode(ManagedKeyReference.self, from: Data("{\"id\":\"\(keyID)\",\"algorithm\":\"rsa\",\"passphraseCredentialRef\":\"\(credentialID)\"}".utf8))
        XCTAssertEqual(key, ManagedKeyReference(id: keyID, algorithm: .rsa, passphraseCredentialRef: credentialID))
        let oldHost = try decoder.decode(HostConfiguration.self, from: Data("{\"id\":\"\(hostID)\",\"name\":\"old\",\"address\":\"old.invalid\",\"username\":\"fixture\",\"credentialRef\":\"\(credentialID)\"}".utf8))
        XCTAssertFalse(oldHost.savePasswordAuthorized)
        XCTAssertEqual(oldHost.favoriteOrder, 0)
        XCTAssertEqual(oldHost.port, 22)
        XCTAssertEqual(oldHost.keepaliveInterval, 30)
        XCTAssertEqual(oldHost.keepaliveCountMax, 3)
        XCTAssertNil(oldHost.folderID)
        XCTAssertNil(oldHost.lastConnectedAt)
        expect(.savingNotAuthorized) { try database.addHost(oldHost) }
        XCTAssertThrowsError(try decoder.decode(HostFolder.self, from: Data("{\"id\":\"\(folderID)\",\"name\":\"bad\",\"parentID\":false}".utf8)))
        XCTAssertThrowsError(try decoder.decode(ManagedKeyReference.self, from: Data("{\"id\":\"\(keyID)\",\"algorithm\":\"rsa\",\"label\":42}".utf8)))
        let nested = HostFolder(name: "nested", sortOrder: 3, parentID: folderID)
        XCTAssertEqual(try decoder.decode(HostFolder.self, from: JSONEncoder().encode(nested)), nested)
        let labeled = ManagedKeyReference(algorithm: .ed25519, label: "测试密钥")
        XCTAssertEqual(try decoder.decode(ManagedKeyReference.self, from: JSONEncoder().encode(labeled)), labeled)
    }

    func testDeleteNestedFolderReparentsDirectHostsAndChildrenWithoutDeletingData() throws {
        let root = HostFolder(name: "root"), other = HostFolder(name: "unrelated")
        let middle = HostFolder(name: "middle", parentID: root.id)
        var child = HostFolder(name: "child", parentID: middle.id)
        let grandchild = HostFolder(name: "grandchild", parentID: child.id)
        let direct = host("middle host", folderID: middle.id), below = host("child host", folderID: child.id)
        let rootHost = host("root host", folderID: root.id), ungrouped = host("ungrouped")
        let tag = HostTag(name: "preserved")
        try database.apply([.saveFolder(root), .saveFolder(other), .saveFolder(middle), .saveFolder(child), .saveFolder(grandchild),
                            .insertHost(direct), .insertHost(below), .insertHost(rootHost), .insertHost(ungrouped), .addTag(tag), .assignTag(hostID: direct.id, tagID: tag.id)])
        let impact = try database.folderDeletionImpact(id: middle.id)
        XCTAssertEqual(impact.folder, middle)
        XCTAssertEqual(impact.directHostCount, 1)
        XCTAssertEqual(impact.directChildFolderCount, 1)
        try database.deleteFolder(id: middle.id)
        child.parentID = root.id
        XCTAssertEqual(try database.folder(id: child.id), child)
        XCTAssertEqual(try database.folder(id: grandchild.id), grandchild)
        XCTAssertEqual(try database.host(id: direct.id)?.folderID, root.id)
        XCTAssertEqual(try database.host(id: below.id), below)
        XCTAssertEqual(try database.host(id: rootHost.id), rootHost)
        XCTAssertEqual(try database.host(id: ungrouped.id), ungrouped)
        XCTAssertEqual(try database.tagIDs(hostID: direct.id), [tag.id])
        XCTAssertEqual(try database.hosts().count, 4)
        XCTAssertEqual(try database.folders().count, 4)
        XCTAssertTrue(try database.cleanupTickets(includeCompleted: true).isEmpty)
        try database.deleteFolder(id: root.id)
        XCTAssertNil(try database.folder(id: child.id)?.parentID)
        XCTAssertNil(try database.host(id: direct.id)?.folderID)
        XCTAssertNil(try database.host(id: rootHost.id)?.folderID)
        XCTAssertEqual(try database.folder(id: other.id), other)
        try reopen(); try checkIntegrity()
        XCTAssertEqual(try database.hosts().count, 4)
    }

    func testBulkDeleteFoldersUsesOriginalNearestSurvivingParentAndIsIdempotent() throws {
        let root = HostFolder(name: "root")
        let a = HostFolder(name: "a", parentID: root.id), unrelated = HostFolder(name: "unrelated")
        let b = HostFolder(name: "b", parentID: a.id)
        let c = HostFolder(name: "c", parentID: b.id)
        let d = HostFolder(name: "d", parentID: c.id)
        let directA = host("in a", folderID: a.id), directB = host("in b", folderID: b.id)
        let directC = host("in c", folderID: c.id), directD = host("in d", folderID: d.id)
        try database.apply([.saveFolder(root), .saveFolder(a), .saveFolder(b), .saveFolder(c), .saveFolder(d), .saveFolder(unrelated),
                            .insertHost(directA), .insertHost(directB), .insertHost(directC), .insertHost(directD)])
        let deleted: Set<UUID> = [c.id, a.id, UUID()]
        try database.apply([.deleteFolders(deleted)])
        XCTAssertEqual(try database.folder(id: b.id)?.parentID, root.id)
        XCTAssertEqual(try database.folder(id: d.id)?.parentID, b.id)
        XCTAssertEqual(try database.host(id: directA.id)?.folderID, root.id)
        XCTAssertEqual(try database.host(id: directB.id), directB)
        XCTAssertEqual(try database.host(id: directC.id)?.folderID, b.id)
        XCTAssertEqual(try database.host(id: directD.id), directD)
        try database.deleteFolders(ids: deleted)
        try database.deleteFolders(ids: [b.id, root.id])
        XCTAssertNil(try database.folder(id: d.id)?.parentID)
        XCTAssertNil(try database.host(id: directA.id)?.folderID)
        XCTAssertNil(try database.host(id: directB.id)?.folderID)
        XCTAssertNil(try database.host(id: directC.id)?.folderID)
        XCTAssertEqual(try database.host(id: directD.id)?.folderID, d.id)
        XCTAssertEqual(Set(try database.folders().map(\.id)), [d.id, unrelated.id])
        XCTAssertEqual(try database.hosts().count, 4)
        try reopen(); try checkIntegrity()
    }

    func testParentChildDeleteCommandsAreOrderIndependentInsideOneBatch() throws {
        for parentFirst in [true, false] {
            let root = HostFolder(name: "root"), parent = HostFolder(name: "parent")
            let nestedParent = HostFolder(id: parent.id, name: parent.name, parentID: root.id)
            let child = HostFolder(name: "child", parentID: parent.id)
            let leaf = HostFolder(name: "leaf", parentID: child.id)
            let inParent = host("parent host", folderID: parent.id), inChild = host("child host", folderID: child.id), inLeaf = host("leaf host", folderID: leaf.id)
            try database.apply([.saveFolder(root), .saveFolder(nestedParent), .saveFolder(child), .saveFolder(leaf), .insertHost(inParent), .insertHost(inChild), .insertHost(inLeaf)])
            let deletes: [RepositoryChange] = parentFirst ? [.deleteFolder(parent.id), .deleteFolder(child.id)] : [.deleteFolder(child.id), .deleteFolder(parent.id)]
            try database.apply(deletes)
            XCTAssertEqual(try database.host(id: inParent.id)?.folderID, root.id)
            XCTAssertEqual(try database.host(id: inChild.id)?.folderID, root.id)
            XCTAssertEqual(try database.host(id: inLeaf.id), inLeaf)
            XCTAssertEqual(try database.folder(id: leaf.id)?.parentID, root.id)
            XCTAssertEqual(try database.folderPath(id: leaf.id)?.folderIDs, [root.id, leaf.id])
            try checkIntegrity()
            try database.apply([.deleteHost(inParent.id), .deleteHost(inChild.id), .deleteHost(inLeaf.id), .deleteFolders([root.id, leaf.id])])
            XCTAssertTrue(try database.hosts().isEmpty)
            XCTAssertTrue(try database.folders().isEmpty)
        }
    }

    func testFolderCyclesMissingParentsAndBatchRollbackAreRejected() throws {
        enum Injected: Error { case beforeCommit }
        let root = HostFolder(name: "root"), child = HostFolder(name: "child")
        let nested = HostFolder(id: child.id, name: child.name, parentID: root.id)
        let grandchild = HostFolder(name: "grandchild", parentID: child.id)
        let savedHost = host(folderID: child.id), marker = HostTag(name: "must roll back")
        try database.apply([.saveFolder(root), .saveFolder(nested), .saveFolder(grandchild), .insertHost(savedHost)])
        for destination in [root.id, child.id, grandchild.id] {
            expect(.invalidField("folderParentID")) {
                try database.apply([.addTag(marker), .moveFolder(root.id, parentID: destination)])
            }
            XCTAssertTrue(try database.tags().isEmpty)
            XCTAssertEqual(try database.folder(id: root.id), root)
        }
        var cycle = root; cycle.parentID = grandchild.id
        expect(.invalidField("folderParentID")) { try database.saveFolder(cycle) }
        expect(.notFound) { try database.moveFolder(id: root.id, parentID: UUID()) }
        expect(.notFound) { try database.saveFolder(HostFolder(name: "orphan", parentID: UUID())) }
        expect(.notFound) { try database.moveFolder(id: UUID(), parentID: nil) }
        XCTAssertThrowsError(try database.applyTransaction([.deleteFolders([root.id, child.id])], beforeCommit: { throw Injected.beforeCommit }))
        expect(.notFound) { try database.apply([.deleteFolder(child.id), .assignTag(hostID: savedHost.id, tagID: UUID())]) }
        XCTAssertEqual(try database.folder(id: child.id), nested)
        XCTAssertEqual(try database.folder(id: grandchild.id), grandchild)
        XCTAssertEqual(try database.host(id: savedHost.id), savedHost)
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE folders SET parentID = ? WHERE id = ?", arguments: [grandchild.id, root.id]) })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE folders SET parentID = ? WHERE id = ?", arguments: [root.id.uuidString, child.id]) })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE folders SET parentID = ? WHERE id = ?", arguments: [UUID(), child.id]) })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "DELETE FROM folders WHERE id = ?", arguments: [root.id]) })
        try reopen(); try checkIntegrity()
        XCTAssertEqual(try database.host(id: savedHost.id), savedHost)
    }

    func testSameNamePathsRetainIDsAcrossRenameMoveAndRestart() throws {
        var left = HostFolder(name: "left"), right = HostFolder(name: "right")
        let first = HostFolder(name: "same / 中文", parentID: left.id)
        let sibling = HostFolder(name: first.name, parentID: left.id)
        let second = HostFolder(name: first.name, parentID: right.id)
        try database.apply([.saveFolder(left), .saveFolder(right), .saveFolder(first), .saveFolder(sibling), .saveFolder(second)])
        let firstPath = try XCTUnwrap(database.folderPath(id: first.id))
        let siblingPath = try XCTUnwrap(database.folderPath(id: sibling.id))
        XCTAssertEqual(firstPath.components, [left, first])
        XCTAssertEqual(firstPath.folderIDs, [left.id, first.id])
        XCTAssertEqual(firstPath.displayName, "left / same / 中文")
        XCTAssertEqual(firstPath.displayName, siblingPath.displayName)
        XCTAssertNotEqual(firstPath.identityPath, siblingPath.identityPath)
        XCTAssertEqual(try database.folderPath(id: second.id)?.displayName, "right / same / 中文")
        try reopen()
        XCTAssertEqual(try database.folderPath(id: first.id), firstPath)
        left.name = "renamed"
        try database.saveFolder(left)
        XCTAssertEqual(try database.folderPath(id: first.id)?.identityPath, firstPath.identityPath)
        XCTAssertEqual(try database.folderPath(id: first.id)?.displayName, "renamed / same / 中文")
        try database.moveFolder(id: first.id, parentID: right.id)
        XCTAssertEqual(try database.folderPath(id: first.id)?.folderIDs, [right.id, first.id])
        XCTAssertNil(try database.folderPath(id: UUID()))
        try checkIntegrity()
    }

    func testRecursiveFolderFilterAndSearchAncestryTagsAreLiteralUnicodeAndLocal() throws {
        let root = HostFolder(name: "Café中文%_")
        let child = HostFolder(name: "子组", parentID: root.id), outside = HostFolder(name: "other")
        let leaf = HostFolder(name: "leaf", parentID: child.id)
        let a = host("A", folderID: root.id), b = host("B", folderID: child.id), c = host("C", folderID: leaf.id), d = host("D", folderID: outside.id)
        let tag = HostTag(name: "Équipe标签%_ ' OR 1=1 --")
        try database.apply([.saveFolder(root), .saveFolder(child), .saveFolder(leaf), .saveFolder(outside),
                            .insertHost(a), .insertHost(b), .insertHost(c), .insertHost(d), .addTag(tag), .assignTag(hostID: b.id, tagID: tag.id)])
        XCTAssertEqual(try database.hosts(HostQuery(folder: .folder(root.id))).map(\.id), [a.id])
        XCTAssertEqual(try database.hosts(HostQuery(folder: .folderAndDescendants(root.id))).map(\.id), [a.id, b.id, c.id])
        XCTAssertEqual(try database.hosts(HostQuery(folder: .folderAndDescendants(child.id))).map(\.id), [b.id, c.id])
        XCTAssertTrue(try database.hosts(HostQuery(folder: .folderAndDescendants(UUID()))).isEmpty)
        XCTAssertEqual(try database.hosts(HostQuery(search: "CAFE中")).map(\.id), [a.id, b.id, c.id])
        XCTAssertEqual(try database.hosts(HostQuery(search: "cafe中文%_ / 子组 / LEAF")).map(\.id), [c.id])
        XCTAssertEqual(try database.hosts(HostQuery(search: "EQUIPE标签")).map(\.id), [b.id])
        XCTAssertEqual(try database.hosts(HostQuery(search: "%_")).map(\.id), [a.id, b.id, c.id])
        XCTAssertEqual(try database.hosts(HostQuery(search: "' OR 1=1 --")).map(\.id), [b.id])
        XCTAssertTrue(try database.hosts(HostQuery(search: "' OR 2=2 --")).isEmpty)
        XCTAssertEqual(try database.hosts(HostQuery(search: "子组", folder: .folderAndDescendants(root.id), tagIDs: [tag.id])).map(\.id), [b.id])
        try reopen()
        XCTAssertEqual(try database.hosts(HostQuery(search: "cafe中文%_ / 子组")).map(\.id), [b.id, c.id])
    }

    func testTagsMetadataAssignmentsANDFilteringAndDeletionAreSeparate() throws {
        let a = host("A"), b = host("B"), c = host("C")
        let first = HostTag(name: "same"), sameName = HostTag(name: "same"), second = HostTag(name: "other")
        try database.apply([.insertHost(a), .insertHost(b), .insertHost(c), .addTag(first), .saveTag(sameName), .addTag(second)])
        XCTAssertTrue(try database.tagIDs(hostID: a.id).isEmpty)
        expect(.conflictingID) { try database.addTag(first) }
        try database.apply([.assignTag(hostID: a.id, tagID: first.id), .assignTag(hostID: a.id, tagID: second.id),
                            .assignTag(hostID: b.id, tagID: first.id), .assignTag(hostID: c.id, tagID: sameName.id)])
        try database.assignTag(hostID: a.id, tagID: first.id)
        XCTAssertEqual(try database.hosts(HostQuery(tagIDs: [first.id])).map(\.id), [a.id, b.id])
        XCTAssertEqual(try database.hosts(HostQuery(tagIDs: [first.id, second.id])).map(\.id), [a.id])
        XCTAssertTrue(try database.hosts(HostQuery(tagIDs: [first.id, sameName.id])).isEmpty)
        XCTAssertTrue(try database.hosts(HostQuery(tagIDs: [UUID()])).isEmpty)
        try database.renameTag(id: first.id, name: "重命名")
        XCTAssertEqual(try database.tag(id: first.id)?.name, "重命名")
        XCTAssertEqual(try database.tagIDs(hostID: b.id), [first.id])
        let impact = try database.tagDeletionImpact(id: first.id)
        XCTAssertEqual(impact.hostCount, 2)
        XCTAssertEqual(impact.tag.id, first.id)
        try database.unassignTag(hostID: b.id, tagID: first.id)
        try database.unassignTag(hostID: b.id, tagID: first.id)
        XCTAssertNotNil(try database.tag(id: first.id))
        try database.setHostTags(hostID: c.id, tagIDs: [first.id, second.id])
        XCTAssertEqual(try database.hosts(HostQuery(tagIDs: [first.id, second.id])).map(\.id), [a.id, c.id])
        try database.deleteTag(id: first.id); try database.deleteTag(id: first.id)
        XCTAssertEqual(try database.tagIDs(hostID: a.id), [second.id])
        XCTAssertEqual(try database.hosts().count, 3)
        try database.deleteHost(id: c.id)
        XCTAssertNotNil(try database.tag(id: second.id))
        XCTAssertEqual(try database.tagDeletionImpact(id: second.id).hostCount, 1)
        XCTAssertTrue(try database.cleanupTickets().isEmpty)
        try reopen(); try checkIntegrity()
    }

    func testInvalidTagHostAndBulkChangesRollBackAtomically() throws {
        let folder = HostFolder(name: "destination")
        let a = host("A"), b = host("B"), tag = HostTag(name: "tag")
        try database.apply([.saveFolder(folder), .insertHost(a), .insertHost(b), .addTag(tag), .assignTag(hostID: a.id, tagID: tag.id)])
        let invalid: [RepositoryChange] = [
            .assignTag(hostID: a.id, tagID: UUID()), .assignTag(hostID: UUID(), tagID: tag.id),
            .unassignTag(hostID: a.id, tagID: UUID()), .unassignTag(hostID: UUID(), tagID: tag.id),
            .setHostTags(hostID: a.id, tagIDs: [tag.id, UUID()]), .setHostTags(hostID: UUID(), tagIDs: []),
            .renameTag(UUID(), name: "not registered"), .moveHost(a.id, folderID: UUID()), .moveHost(UUID(), folderID: folder.id)
        ]
        for command in invalid {
            expect(.notFound) { try database.apply([.moveHost(a.id, folderID: folder.id), .setFavorite(b.id, true), .setHostTags(hostID: b.id, tagIDs: [tag.id]), command]) }
            XCTAssertEqual(try database.host(id: a.id), a)
            XCTAssertEqual(try database.host(id: b.id), b)
            XCTAssertEqual(try database.tagIDs(hostID: a.id), [tag.id])
            XCTAssertTrue(try database.tagIDs(hostID: b.id).isEmpty)
        }
        expect(.notFound) { _ = try database.tagIDs(hostID: UUID()) }
        try database.apply([.moveHost(a.id, folderID: folder.id), .moveHost(b.id, folderID: folder.id),
                            .setFavorite(a.id, true, order: 2), .setFavorite(b.id, true, order: 1),
                            .setHostTags(hostID: a.id, tagIDs: []), .setHostTags(hostID: b.id, tagIDs: [tag.id])])
        XCTAssertEqual(try database.hosts(HostQuery(favoritesOnly: true, folder: .folder(folder.id), sort: .favorites)).map(\.id), [b.id, a.id])
        XCTAssertTrue(try database.tagIDs(hostID: a.id).isEmpty)
        XCTAssertEqual(try database.tagIDs(hostID: b.id), [tag.id])
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "INSERT INTO hostTags(hostID, tagID) VALUES (?, ?)", arguments: [UUID(), tag.id]) })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "INSERT INTO hostTags(hostID, tagID) VALUES (?, ?)", arguments: [a.id, UUID()]) })
        try reopen(); try checkIntegrity()
    }

    func testNameAndRecentSortBothDirectionsHaveStableTiesAndNeverConnectedLast() throws {
        let ids = (1...5).map { UUID(uuidString: String(format: "00000000-0000-4000-8000-%012d", $0))! }
        let a = HostConfiguration(id: ids[0], name: "same", address: "a.invalid", username: "fixture", lastConnectedAt: Date(timeIntervalSince1970: 20))
        let b = HostConfiguration(id: ids[1], name: "same", address: "b.invalid", username: "fixture", lastConnectedAt: Date(timeIntervalSince1970: 20))
        let c = HostConfiguration(id: ids[2], name: "Zulu", address: "c.invalid", username: "fixture", lastConnectedAt: Date(timeIntervalSince1970: 10))
        let d = HostConfiguration(id: ids[3], name: "Never", address: "d.invalid", username: "fixture")
        let e = HostConfiguration(id: ids[4], name: "Never", address: "e.invalid", username: "fixture")
        try database.apply([e, c, b, d, a].map { .insertHost($0) })
        XCTAssertEqual(try database.hosts(HostQuery(sort: .name, sortDirection: .ascending)).map(\.id), [d.id, e.id, a.id, b.id, c.id])
        XCTAssertEqual(try database.hosts(HostQuery(sort: .name, sortDirection: .descending)).map(\.id), [c.id, a.id, b.id, d.id, e.id])
        XCTAssertEqual(try database.hosts(HostQuery(sort: .recentlyConnected)).map(\.id), [a.id, b.id, c.id, d.id, e.id])
        XCTAssertEqual(try database.hosts(HostQuery(sort: .recentlyConnected, sortDirection: .ascending)).map(\.id), [c.id, a.id, b.id, d.id, e.id])
        try reopen()
        XCTAssertEqual(try database.hosts(HostQuery(sort: .name, sortDirection: .descending)).map(\.id), [c.id, a.id, b.id, d.id, e.id])
    }

    func testKeyLabelChangesOnlyPublicMetadataAndNotSavedSecretIdentity() throws {
        let phrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .ed25519, passphraseCredentialRef: phrase.id)
        let second = ManagedKeyReference(algorithm: .rsa, passphraseCredentialRef: phrase.id, label: "unrelated")
        let linked = HostConfiguration(name: "linked", address: "key.invalid", username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id)
        try database.apply([.registerCredential(phrase), .registerKey(key), .registerKey(second), .insertHost(linked)])
        try database.updateKeyLabel(keyID: key.id, label: "工作用 Unicode🔑")
        var renamed = key; renamed.label = "工作用 Unicode🔑"
        XCTAssertEqual(try database.keys().first { $0.id == key.id }, renamed)
        XCTAssertNotEqual(renamed, key)
        XCTAssertEqual(renamed.authenticationIdentity, key.authenticationIdentity)
        XCTAssertEqual(try database.keys().first { $0.id == second.id }, second)
        XCTAssertEqual(try database.host(id: linked.id), linked)
        XCTAssertEqual(try database.credentials(), [phrase])
        XCTAssertTrue(try database.cleanupTickets(includeCompleted: true).isEmpty)
        expect(.conflictingID) { try database.registerKey(key) }
        try database.registerKey(renamed)
        try reopen()
        XCTAssertEqual(try database.keys().first { $0.id == key.id }, renamed)
        try database.updateKeyPassphrase(keyID: key.id, credentialRef: nil)
        let detached = try XCTUnwrap(database.keys().first { $0.id == key.id })
        XCTAssertEqual(detached.label, renamed.label)
        XCTAssertNotEqual(detached.authenticationIdentity, renamed.authenticationIdentity)
        try database.updateKeyLabel(keyID: key.id, label: "")
        XCTAssertEqual(try database.keys().first { $0.id == key.id }?.label, "")
        XCTAssertEqual(try database.credentials(), [phrase])
        expect(.notFound) { try database.updateKeyLabel(keyID: UUID(), label: "missing") }
        for invalid in [" ", "line\nbreak", String(repeating: "é", count: 129)] {
            expect(.invalidField("keyLabel")) { try database.apply([.deleteHost(linked.id), .updateKeyLabel(keyID: key.id, label: invalid)]) }
            XCTAssertEqual(try database.host(id: linked.id), linked)
        }
        let columns = try database.queue.read { try Row.fetchAll($0, sql: "PRAGMA table_info(managedKeys)").map { $0["name"] as String } }
        XCTAssertEqual(columns, ["id", "algorithm", "passphraseCredentialRef", "label"])
        try checkIntegrity()
    }

    func testMetadataNameBoundsRemainUTF8LimitedAndAtomic() throws {
        let folder = HostFolder(name: String(repeating: "é", count: 128))
        let tag = HostTag(name: String(repeating: "a", count: 256))
        let key = ManagedKeyReference(algorithm: .rsa, label: String(repeating: "a", count: 256))
        try database.apply([.saveFolder(folder), .addTag(tag), .registerKey(key)])
        for invalid in ["", " \t", "bad\u{0000}name", String(repeating: "é", count: 129)] {
            expect(.invalidField("folderName")) { try database.saveFolder(HostFolder(name: invalid)) }
            expect(.invalidField("tagName")) { try database.saveTag(HostTag(name: invalid)) }
        }
        XCTAssertEqual(try database.folders(), [folder])
        XCTAssertEqual(try database.tags(), [tag])
        XCTAssertEqual(try database.keys(), [key])
    }

    func testCopyHostPreservesGroupTagsSharedRefsAndExactAuthorizationWithoutHistory() throws {
        let root = HostFolder(name: "root"), tag = HostTag(name: "public config")
        let group = HostFolder(name: "nested", parentID: root.id)
        let password = CredentialReference(purpose: .password, isSavingAuthorized: true)
        let phrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .rsa, passphraseCredentialRef: phrase.id, label: "shared")
        let source = HostConfiguration(name: "saved", address: "saved.invalid", username: "fixture", authentication: .passwordWithMFA,
            credentialRef: password.id, savePasswordAuthorized: true, folderID: group.id, isFavorite: true, favoriteOrder: 7, lastConnectedAt: Date(timeIntervalSince1970: 42))
        let keyHost = HostConfiguration(name: "key", address: "key.invalid", username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id, folderID: group.id)
        let unsaved = host("unsaved", folderID: group.id)
        try database.apply([.saveFolder(root), .saveFolder(group), .addTag(tag), .registerCredential(password), .registerCredential(phrase), .registerKey(key),
                            .insertHost(source), .insertHost(keyHost), .insertHost(unsaved), .assignTag(hostID: source.id, tagID: tag.id), .assignTag(hostID: keyHost.id, tagID: tag.id)])
        let copy = try database.copyHost(id: source.id, name: "copy")
        var expected = source; expected.id = copy.id; expected.name = "copy"; expected.lastConnectedAt = nil
        XCTAssertNotEqual(copy.id, source.id)
        XCTAssertEqual(copy, expected)
        XCTAssertEqual(try database.tagIDs(hostID: copy.id), [tag.id])
        let keyCopy = try database.copyHost(id: keyHost.id)
        XCTAssertEqual(keyCopy.keyRef, keyHost.keyRef)
        XCTAssertFalse(keyCopy.savePasswordAuthorized)
        XCTAssertEqual(try database.tagIDs(hostID: keyCopy.id), [tag.id])
        let unsavedCopy = try database.copyHost(id: unsaved.id)
        XCTAssertFalse(unsavedCopy.savePasswordAuthorized)
        XCTAssertNil(unsavedCopy.credentialRef)
        XCTAssertTrue(try database.tagIDs(hostID: unsavedCopy.id).isEmpty)
        XCTAssertEqual(try database.keys(), [key])
        XCTAssertEqual(Set(try database.credentials().map(\.id)), [password.id, phrase.id])
        XCTAssertTrue(try database.cleanupTickets(includeCompleted: true).isEmpty)
        XCTAssertThrowsError(try database.copyHost(id: source.id, name: ""))
        XCTAssertEqual(try database.hosts().count, 6)
        try database.deleteHost(id: source.id)
        expect(.resourceInUse) { try database.deleteCredential(id: password.id) }
        try reopen()
        XCTAssertEqual(try database.tagIDs(hostID: copy.id), [tag.id])
        XCTAssertEqual(try database.hostMetadata(id: copy.id)?.folderPath?.folderIDs, [root.id, group.id])
        try checkIntegrity()
    }

    func testRecursiveFolderCopyKeepsSubtreeTagsSharedReferencesAndOriginals() throws {
        let parent = HostFolder(name: "outside parent")
        let root = HostFolder(name: "source", sortOrder: 7, parentID: parent.id)
        let child = HostFolder(name: "same", sortOrder: 2, parentID: root.id)
        let sibling = HostFolder(name: "same", sortOrder: 3, parentID: root.id)
        let leaf = HostFolder(name: "leaf", parentID: child.id)
        let tag = HostTag(name: "shared tag")
        let password = CredentialReference(purpose: .password, isSavingAuthorized: true)
        let phrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .ed25519, passphraseCredentialRef: phrase.id, label: "shared key")
        let saved = HostConfiguration(name: "saved", address: "saved.invalid", username: "fixture", authentication: .passwordWithMFA,
            credentialRef: password.id, savePasswordAuthorized: true, folderID: root.id, isFavorite: true, favoriteOrder: 9, lastConnectedAt: Date(timeIntervalSince1970: 30))
        let keyed = HostConfiguration(name: "keyed", address: "key.invalid", username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id, folderID: leaf.id)
        let plain = host("plain", folderID: sibling.id)
        let outside = host("outside", folderID: parent.id)
        try database.apply([.saveFolder(parent), .saveFolder(root), .saveFolder(child), .saveFolder(sibling), .saveFolder(leaf),
                            .registerCredential(password), .registerCredential(phrase), .registerKey(key), .addTag(tag),
                            .insertHost(saved), .insertHost(keyed), .insertHost(plain), .insertHost(outside),
                            .assignTag(hostID: saved.id, tagID: tag.id), .assignTag(hostID: keyed.id, tagID: tag.id)])
        let originalCatalog = try database.vaultMetadata()
        let copy = try database.copyFolder(id: root.id, name: "copy")
        XCTAssertNotEqual(copy.id, root.id)
        XCTAssertEqual(copy.name, "copy")
        XCTAssertEqual(copy.parentID, parent.id)
        XCTAssertEqual(copy.sortOrder, root.sortOrder)
        let copiedFolders = try database.folderPaths().filter { $0.folderIDs.contains(copy.id) }
        XCTAssertEqual(copiedFolders.count, 4)
        XCTAssertTrue(Set(copiedFolders.map(\.id)).isDisjoint(with: Set(originalCatalog.folders.map(\.id))))
        let copiedChild = try XCTUnwrap(copiedFolders.first { $0.components.last?.sortOrder == child.sortOrder })
        let copiedLeaf = try XCTUnwrap(copiedFolders.first { $0.components.last?.name == leaf.name })
        XCTAssertEqual(copiedLeaf.components.last?.parentID, copiedChild.id)
        let copiedHosts = try database.hostsMetadata(HostQuery(folder: .folderAndDescendants(copy.id)))
        XCTAssertEqual(copiedHosts.count, 3)
        for original in originalCatalog.hosts.filter({ $0.folderPath?.folderIDs.contains(root.id) == true }) {
            let copied = try XCTUnwrap(copiedHosts.first { $0.host.name == original.host.name })
            var expected = original.host
            expected.id = copied.id; expected.folderID = copied.host.folderID; expected.lastConnectedAt = nil
            XCTAssertNotEqual(copied.id, original.id)
            XCTAssertEqual(copied.host, expected)
            XCTAssertEqual(copied.tagIDs, original.tagIDs)
        }
        for original in originalCatalog.hosts { XCTAssertEqual(try database.hostMetadata(id: original.id), original) }
        for original in originalCatalog.folders { XCTAssertEqual(try database.folderPath(id: original.id), original) }
        XCTAssertEqual(try database.keys(), [key])
        XCTAssertEqual(Set(try database.credentials().map(\.id)), [password.id, phrase.id])
        XCTAssertTrue(try database.cleanupTickets(includeCompleted: true).isEmpty)
        try reopen(); try checkIntegrity()
    }

    func testRecursiveFolderCopyRollsBackAllFoldersHostsAndTagsOnLateSQLFailure() throws {
        let root = HostFolder(name: "root"), marker = HostTag(name: "tag")
        let child = HostFolder(name: "child", parentID: root.id)
        let source = host("fail copied host", folderID: child.id)
        try database.apply([.saveFolder(root), .saveFolder(child), .insertHost(source), .addTag(marker), .assignTag(hostID: source.id, tagID: marker.id)])
        let baseline = try database.vaultMetadata()
        try database.queue.write { db in
            try db.execute(sql: """
                CREATE TRIGGER deny_copied_host BEFORE INSERT ON hosts
                WHEN NEW.name = 'fail copied host'
                BEGIN SELECT RAISE(ABORT, 'injected copy failure'); END;
                """)
        }
        XCTAssertThrowsError(try database.copyFolder(id: root.id, name: "must roll back"))
        XCTAssertEqual(try database.vaultMetadata(), baseline)
        try database.queue.write { try $0.execute(sql: "DROP TRIGGER deny_copied_host") }
        expect(.invalidField("folderName")) { _ = try database.copyFolder(id: root.id, name: "") }
        expect(.notFound) { _ = try database.copyFolder(id: UUID()) }
        XCTAssertEqual(try database.vaultMetadata(), baseline)
        _ = try database.copyFolder(id: root.id)
        XCTAssertEqual(try database.hosts().count, 2)
        try checkIntegrity()
    }

    func testRecursiveFolderCopyWaitsForConcurrentWriterAndUsesCommittedAuthorization() throws {
        let group = HostFolder(name: "source")
        let credential = CredentialReference(purpose: .password, isSavingAuthorized: true)
        let source = HostConfiguration(name: "saved", address: "saved.invalid", username: "fixture",
            credentialRef: credential.id, savePasswordAuthorized: true, folderID: group.id)
        try database.apply([.saveFolder(group), .registerCredential(credential), .insertHost(source)])
        let second = try OpenLXSSHDatabase(directory: directory)
        defer { try? second.close() }
        let acquired = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        let failure = CopyThreadFailure()
        DispatchQueue.global().async {
            defer { finished.signal() }
            do {
                try second.queue.write { db in
                    try db.execute(sql: "UPDATE hosts SET credentialRef = NULL, savePasswordAuthorized = 0 WHERE id = ?", arguments: [source.id])
                    acquired.signal()
                    Thread.sleep(forTimeInterval: 0.25)
                }
            } catch { failure.record(error); acquired.signal() }
        }
        XCTAssertEqual(acquired.wait(timeout: .now() + 5), .success)
        let copiedFolder = try database.copyFolder(id: group.id)
        XCTAssertEqual(finished.wait(timeout: .now() + 5), .success)
        XCTAssertNil(failure.error)
        let copied = try XCTUnwrap(database.hosts(HostQuery(folder: .folder(copiedFolder.id))).first)
        XCTAssertNil(copied.credentialRef)
        XCTAssertFalse(copied.savePasswordAuthorized)
        XCTAssertEqual(try database.credentials(), [credential])
        try checkIntegrity()
    }

    func testStructuredVaultSnapshotContainsPathsAndPerHostTagIDsWithoutSecretData() throws {
        let root = HostFolder(name: "root"), group = HostFolder(name: "group")
        let nested = HostFolder(id: group.id, name: group.name, parentID: root.id)
        let tag = HostTag(name: "tag"), orphanTag = HostTag(name: "unassigned")
        let linked = host("linked", folderID: group.id), plain = host("plain")
        try database.apply([.saveFolder(root), .saveFolder(nested), .addTag(tag), .addTag(orphanTag), .insertHost(linked), .insertHost(plain), .assignTag(hostID: linked.id, tagID: tag.id)])
        let snapshot = try database.vaultMetadata(HostQuery(tagIDs: [tag.id]))
        XCTAssertEqual(snapshot.hosts.count, 1)
        XCTAssertEqual(snapshot.hosts.first?.host, linked)
        XCTAssertEqual(snapshot.hosts.first?.folderPath?.components, [root, nested])
        XCTAssertEqual(snapshot.hosts.first?.tagIDs, [tag.id])
        XCTAssertEqual(Set(snapshot.tags.map(\.id)), [tag.id, orphanTag.id])
        XCTAssertEqual(Set(snapshot.folders.map(\.id)), [root.id, group.id])
        XCTAssertEqual(try database.hostsMetadata(HostQuery(tagIDs: [tag.id])), snapshot.hosts)
        XCTAssertEqual(try database.hostMetadata(id: linked.id), snapshot.hosts.first)
        XCTAssertNil(try database.hostMetadata(id: plain.id)?.folderPath)
        XCTAssertEqual(try database.hostMetadata(id: plain.id)?.tagIDs, [])
        XCTAssertNil(try database.hostMetadata(id: UUID()))
    }
}

private final class CopyThreadFailure: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Error?
    func record(_ error: Error) { lock.lock(); defer { lock.unlock() }; stored = error }
    var error: Error? { lock.lock(); defer { lock.unlock() }; return stored }
}
