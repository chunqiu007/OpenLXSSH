import Darwin
import Foundation
import GRDB
import XCTest
@testable import OpenLXSSHCore

final class OpenLXSSHCoreTests: XCTestCase {
    private var directory: URL!
    private var database: OpenLXSSHDatabase!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("openlxssh-core-test-" + UUID().uuidString, isDirectory: true)
        database = try OpenLXSSHDatabase(directory: directory)
        XCTAssertEqual(try permissions(directory), 0o700)
    }
    override func tearDownWithError() throws {
        try database?.close()
        database = nil
        if let directory, FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
        directory = nil
    }
    private func permissions(_ url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes[.posixPermissions] as! NSNumber).intValue & 0o777
    }
    private func sampleHost(_ name: String = "example") -> HostConfiguration {
        HostConfiguration(name: name, address: "test.invalid", username: "fixture")
    }
    private func reopen() throws {
        try database.close()
        database = try OpenLXSSHDatabase(directory: directory)
    }
    private func expect(_ expected: RepositoryError, _ body: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual(error as? RepositoryError, expected, file: file, line: line)
        }
    }

    func testDefaultsAndRealSQLiteConfiguration() throws {
        let settings = try database.settings()
        XCTAssertEqual(settings.historyLines, 10_000)
        XCTAssertEqual(settings.theme, .system)
        XCTAssertEqual(settings.keepaliveInterval, 30)
        try database.queue.read { db in
            XCTAssertEqual(try Int.fetchOne(db, sql: "PRAGMA foreign_keys"), 1)
            XCTAssertEqual(try String.fetchOne(db, sql: "PRAGMA journal_mode"), "wal")
            XCTAssertEqual(try Int.fetchOne(db, sql: "PRAGMA synchronous"), 2)
            XCTAssertEqual(try Int.fetchOne(db, sql: "PRAGMA busy_timeout"), 5000)
            XCTAssertEqual(try String.fetchOne(db, sql: "PRAGMA integrity_check"), "ok")
            XCTAssertTrue(try Row.fetchAll(db, sql: "PRAGMA foreign_key_check").isEmpty)
            XCTAssertEqual(try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations ORDER BY identifier"), CoreSchema.versions)
        }
    }

    func testCRUDCopyAndRestartPersistence() throws {
        let folder = HostFolder(name: "工作")
        let credential = CredentialReference(purpose: .password, isSavingAuthorized: true)
        var original = HostConfiguration(name: "主机", address: "2001:db8::1", port: 2222, username: "fixture", authentication: .passwordWithMFA,
                            credentialRef: credential.id, savePasswordAuthorized: true, folderID: folder.id, isFavorite: true)
        try database.apply([.saveFolder(folder), .registerCredential(credential), .insertHost(original)])
        original.name = "已编辑"; original.keepaliveInterval = 45
        try database.updateHost(original)
        let time = Date(timeIntervalSince1970: 1_730_000_000.125)
        try database.markConnected(hostID: original.id, at: time)
        let copy = try database.copyHost(id: original.id, name: "副本")
        XCTAssertNotEqual(copy.id, original.id)
        XCTAssertEqual(copy.credentialRef, credential.id)
        XCTAssertEqual(copy.folderID, original.folderID)
        XCTAssertTrue(copy.savePasswordAuthorized)
        XCTAssertTrue(copy.isFavorite)
        XCTAssertNil(copy.lastConnectedAt)
        try reopen()
        XCTAssertEqual(try database.host(id: original.id)?.name, "已编辑")
        XCTAssertEqual(try database.host(id: original.id)?.lastConnectedAt, time)
        XCTAssertEqual(try database.host(id: copy.id), copy)
        try database.deleteHost(id: original.id)
        try database.deleteHost(id: original.id)
        XCTAssertEqual(try database.credentials(), [credential])
        expect(.resourceInUse) { try database.deleteCredential(id: credential.id) }
        XCTAssertNotNil(try database.host(id: copy.id))
    }

    func testRootFoldersUnGroupRatherThanDeleteHosts() throws {
        var folder = HostFolder(name: "文件夹")
        var host = sampleHost(); host.folderID = folder.id
        try database.apply([.saveFolder(folder), .insertHost(host)])
        folder.name = "重命名"; try database.saveFolder(folder)
        XCTAssertEqual(try database.folders(), [folder])
        XCTAssertEqual(try database.hosts(HostQuery(folder: .folder(folder.id))), [host])
        try database.deleteFolder(id: folder.id)
        try database.deleteFolder(id: folder.id)
        XCTAssertTrue(try database.folders().isEmpty)
        XCTAssertNil(try database.host(id: host.id)?.folderID)
        XCTAssertEqual(try database.hosts(HostQuery(folder: .ungrouped)).count, 1)
        let columns = try database.queue.read { try Row.fetchAll($0, sql: "PRAGMA table_info(folders)").map { $0["name"] as String } }
        XCTAssertTrue(columns.contains("parentID"))
        let parentColumn = try database.queue.read { try Row.fetchAll($0, sql: "PRAGMA foreign_key_list(folders)").first { ($0["from"] as String) == "parentID" } }
        XCTAssertEqual(parentColumn?["table"] as String?, "folders")
        XCTAssertEqual(parentColumn?["on_delete"] as String?, "RESTRICT")
    }

    func testLiteralUnicodeSearchFavoritesAndStableSort() throws {
        var first = HostConfiguration(id: UUID(uuidString: "00000000-0000-4000-8000-000000000001")!, name: "Café中文", address: "alpha.invalid", username: "Alice")
        var second = HostConfiguration(id: UUID(uuidString: "00000000-0000-4000-8000-000000000002")!, name: "Café中文", address: "percent%_.invalid", username: "Bob")
        first.isFavorite = true; first.favoriteOrder = 8
        second.isFavorite = true; second.favoriteOrder = 1
        let third = sampleHost("Third")
        try database.apply([.insertHost(second), .insertHost(third), .insertHost(first)])
        XCTAssertEqual(try database.hosts(HostQuery(search: "CAFE中")).map(\.id), [first.id, second.id])
        XCTAssertEqual(try database.hosts(HostQuery(search: "ALICE")).map(\.id), [first.id])
        XCTAssertEqual(try database.hosts(HostQuery(search: "alpha.invalid")).map(\.id), [first.id])
        XCTAssertEqual(try database.hosts(HostQuery(search: "%_")).map(\.id), [second.id])
        XCTAssertTrue(try database.hosts(HostQuery(search: "' OR 1=1 --")).isEmpty)
        XCTAssertEqual(try database.hosts(HostQuery(favoritesOnly: true, sort: .favorites)).map(\.id), [second.id, first.id])
        try database.setFavorite(hostID: first.id, isFavorite: false)
        try database.setFavorite(hostID: first.id, isFavorite: false)
        XCTAssertEqual(try database.hosts(HostQuery(favoritesOnly: true)).map(\.id), [second.id])
        XCTAssertEqual(try database.hosts().count, 3)
        try reopen()
        XCTAssertEqual(try database.hosts(HostQuery(search: "cafe")).map(\.id), [first.id, second.id])
    }

    func testRecentTimestampOnlyAdvances() throws {
        let first = sampleHost("A"), second = sampleHost("B")
        try database.apply([.insertHost(first), .insertHost(second)])
        try database.markConnected(hostID: first.id, at: Date(timeIntervalSince1970: 20))
        try database.markConnected(hostID: first.id, at: Date(timeIntervalSince1970: 10))
        try database.markConnected(hostID: second.id, at: Date(timeIntervalSince1970: 30))
        XCTAssertEqual(try database.host(id: first.id)?.lastConnectedAt, Date(timeIntervalSince1970: 20))
        XCTAssertEqual(try database.hosts(HostQuery(sort: .recentlyConnected)).map(\.id), [second.id, first.id])
        expect(.notFound) { try database.markConnected(hostID: UUID(), at: Date()) }
    }

    func testSharedKeysPassphraseAndExplicitDeletionTickets() throws {
        let passphrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .ed25519, passphraseCredentialRef: passphrase.id)
        let host = HostConfiguration(name: "key", address: "key.invalid", username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id)
        try database.apply([.registerCredential(passphrase), .registerKey(key), .insertHost(host)])
        let copy = try database.copyHost(id: host.id)
        expect(.resourceInUse) { try database.deleteKey(id: key.id) }
        expect(.resourceInUse) { try database.deleteCredential(id: passphrase.id) }
        try database.deleteHost(id: host.id)
        expect(.resourceInUse) { try database.deleteKey(id: key.id) }
        try database.deleteHost(id: copy.id)
        XCTAssertEqual(try database.keys(), [key])
        try database.deleteKey(id: key.id)
        try database.deleteKey(id: key.id)
        XCTAssertEqual(try database.credentials(), [passphrase])
        try database.deleteCredential(id: passphrase.id)
        try reopen()
        let tickets = try database.cleanupTickets()
        XCTAssertEqual(Set(tickets.map(\.resourceID)), [key.id, passphrase.id])
        XCTAssertEqual(Set(tickets.map(\.reason)), [.removedReference])
        expect(.cleanupAlreadyScheduled) { try database.registerKey(key) }
    }

    func testUpdateKeyPassphraseDetachesOnlyOneSharedKey() throws {
        let passphrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let first = ManagedKeyReference(algorithm: .ed25519, passphraseCredentialRef: passphrase.id)
        let second = ManagedKeyReference(algorithm: .rsa, passphraseCredentialRef: passphrase.id)
        let host = HostConfiguration(name: "linked key", address: "key.invalid", username: "fixture", authentication: .privateKey, keyRef: first.id)
        try database.apply([.registerCredential(passphrase), .registerKey(first), .registerKey(second), .insertHost(host)])
        try database.updateKeyPassphrase(keyID: first.id, credentialRef: nil)
        try database.updateKeyPassphrase(keyID: first.id, credentialRef: nil)
        var detached = first; detached.passphraseCredentialRef = nil
        XCTAssertEqual(Set(try database.keys().map(\.id)), [first.id, second.id])
        XCTAssertEqual(try database.keys().first { $0.id == first.id }, detached)
        XCTAssertEqual(try database.keys().first { $0.id == second.id }, second)
        XCTAssertEqual(try database.host(id: host.id), host)
        XCTAssertEqual(try database.credentials(), [passphrase])
        XCTAssertTrue(try database.cleanupTickets().isEmpty)
        expect(.resourceInUse) { try database.deleteCredential(id: passphrase.id) }
        // Registration still rejects changes to an existing key; it is not an upsert.
        expect(.conflictingID) { try database.registerKey(first) }
        try database.registerKey(detached)
        try reopen()
        XCTAssertEqual(try database.keys().first { $0.id == first.id }, detached)
        XCTAssertEqual(try database.keys().first { $0.id == second.id }, second)
        XCTAssertEqual(try database.credentials(), [passphrase])
        try database.updateKeyPassphrase(keyID: second.id, credentialRef: nil)
        XCTAssertEqual(try database.credentials(), [passphrase])
        XCTAssertTrue(try database.cleanupTickets().isEmpty)
        try database.deleteCredential(id: passphrase.id)
        try reopen()
        XCTAssertTrue(try database.keys().allSatisfy { $0.passphraseCredentialRef == nil })
        XCTAssertEqual(Set(try database.keys().map(\.id)), [first.id, second.id])
        XCTAssertEqual(try database.host(id: host.id), host)
        XCTAssertTrue(try database.credentials().isEmpty)
        XCTAssertEqual(try database.cleanupTickets().map(\.resourceID), [passphrase.id])
    }

    func testUpdateKeyPassphraseReplacementAndExplicitCleanupPersist() throws {
        let old = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let replacement = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let unrelated = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .ed25519, passphraseCredentialRef: old.id)
        try database.apply([.registerCredential(old), .registerCredential(unrelated), .registerKey(key)])
        try database.apply([.registerCredential(replacement), .updateKeyPassphrase(keyID: key.id, credentialRef: replacement.id)])
        try database.updateKeyPassphrase(keyID: key.id, credentialRef: replacement.id)
        var changed = key; changed.passphraseCredentialRef = replacement.id
        XCTAssertEqual(try database.keys(), [changed])
        XCTAssertEqual(Set(try database.credentials().map(\.id)), [old.id, replacement.id, unrelated.id])
        XCTAssertTrue(try database.cleanupTickets().isEmpty)
        expect(.conflictingID) { try database.registerKey(key) }
        try database.deleteCredential(id: old.id)
        try database.apply([.updateKeyPassphrase(keyID: key.id, credentialRef: nil), .deleteCredential(replacement.id)])
        try reopen()
        changed.passphraseCredentialRef = nil
        XCTAssertEqual(try database.keys(), [changed])
        XCTAssertEqual(try database.credentials(), [unrelated])
        let tickets = try database.cleanupTickets()
        XCTAssertEqual(tickets.count, 2)
        XCTAssertEqual(Set(tickets.map(\.resourceID)), [old.id, replacement.id])
        XCTAssertTrue(tickets.allSatisfy { $0.resourceKind == .credential && $0.reason == .removedReference && $0.state == .pending })
        try database.deleteCredential(id: replacement.id)
        XCTAssertEqual(try database.cleanupTickets(), tickets)
        try database.queue.read { XCTAssertTrue(try Row.fetchAll($0, sql: "PRAGMA foreign_key_check").isEmpty) }
    }

    func testUpdateKeyPassphraseInvalidReferencesRollBackBatch() throws {
        let passphrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let password = CredentialReference(purpose: .password, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .rsa, passphraseCredentialRef: passphrase.id)
        try database.apply([.registerCredential(passphrase), .registerCredential(password), .registerKey(key)])
        let folder = HostFolder(name: "must roll back")
        let invalid: [(RepositoryChange, RepositoryError)] = [
            (.updateKeyPassphrase(keyID: key.id, credentialRef: password.id), .invalidField("passphraseCredentialRef")),
            (.updateKeyPassphrase(keyID: key.id, credentialRef: UUID()), .notFound),
            (.updateKeyPassphrase(keyID: UUID(), credentialRef: passphrase.id), .notFound),
            (.updateKeyPassphrase(keyID: UUID(), credentialRef: nil), .notFound)
        ]
        for (change, error) in invalid {
            expect(error) { try database.apply([.saveFolder(folder), change]) }
            XCTAssertTrue(try database.folders().isEmpty)
            XCTAssertEqual(try database.keys(), [key])
            XCTAssertTrue(try database.cleanupTickets().isEmpty)
        }
        // SQL constraints remain effective independently of the new checked API.
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE managedKeys SET passphraseCredentialRef = ? WHERE id = ?", arguments: [password.id, key.id]) })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE managedKeys SET passphraseCredentialRef = ? WHERE id = ?", arguments: [UUID(), key.id]) })
        try reopen()
        XCTAssertEqual(try database.keys(), [key])
        XCTAssertEqual(Set(try database.credentials().map(\.id)), [passphrase.id, password.id])
    }

    func testUpdateKeyPassphraseDeletionAndTicketRollBackOnLaterFailure() throws {
        enum Injected: Error { case fail }
        let passphrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .ed25519, passphraseCredentialRef: passphrase.id)
        try database.apply([.registerCredential(passphrase), .registerKey(key)])
        let detachAndDelete: [RepositoryChange] = [.updateKeyPassphrase(keyID: key.id, credentialRef: nil), .deleteCredential(passphrase.id)]
        var invalidHost = sampleHost(); invalidHost.folderID = UUID()
        XCTAssertThrowsError(try database.apply(detachAndDelete + [.insertHost(invalidHost)]))
        XCTAssertThrowsError(try database.applyTransaction(detachAndDelete, beforeCommit: { throw Injected.fail }))
        expect(.notFound) {
            try database.apply(detachAndDelete + [.updateKeyPassphrase(keyID: key.id, credentialRef: passphrase.id)])
        }
        try reopen()
        XCTAssertEqual(try database.keys(), [key])
        XCTAssertEqual(try database.credentials(), [passphrase])
        XCTAssertTrue(try database.cleanupTickets(includeCompleted: true).isEmpty)
        XCTAssertTrue(try database.hosts().isEmpty)
        try database.queue.read { XCTAssertTrue(try Row.fetchAll($0, sql: "PRAGMA foreign_key_check").isEmpty) }
    }

    func testUpdateKeyPassphraseRejectsUnauthorizedExistingMetadata() throws {
        let key = ManagedKeyReference(algorithm: .rsa)
        let unauthorized = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: false)
        try database.registerKey(key)
        // Deliberately corrupt one metadata row to exercise the API's defensive authorization check.
        // Production registration and the unchanged schema both reject this row normally.
        try database.queue.writeWithoutTransaction { db in
            try db.execute(sql: "PRAGMA ignore_check_constraints = ON")
            defer { try? db.execute(sql: "PRAGMA ignore_check_constraints = OFF") }
            try db.execute(sql: "INSERT INTO credentials(id, purpose, isSavingAuthorized) VALUES (?, 'privateKeyPassphrase', 0)", arguments: [unauthorized.id])
        }
        let folder = HostFolder(name: "unauthorized batch must roll back")
        expect(.savingNotAuthorized) {
            try database.apply([.saveFolder(folder), .updateKeyPassphrase(keyID: key.id, credentialRef: unauthorized.id)])
        }
        XCTAssertEqual(try database.keys(), [key])
        XCTAssertTrue(try database.folders().isEmpty)
        XCTAssertTrue(try database.cleanupTickets().isEmpty)
        try database.queue.write { db in
            XCTAssertEqual(try Int.fetchOne(db, sql: "PRAGMA ignore_check_constraints"), 0)
            try db.execute(sql: "DELETE FROM credentials WHERE id = ?", arguments: [unauthorized.id])
            XCTAssertEqual(try String.fetchOne(db, sql: "PRAGMA integrity_check"), "ok")
        }
    }

    func testCredentialAuthorizationAndPurposeEnforcement() throws {
        expect(.savingNotAuthorized) { try database.registerCredential(CredentialReference(purpose: .password, isSavingAuthorized: false)) }
        let password = CredentialReference(purpose: .password, isSavingAuthorized: true)
        let passphrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        try database.apply([.registerCredential(password), .registerCredential(passphrase)])
        var host = sampleHost(); host.credentialRef = password.id
        expect(.savingNotAuthorized) { try database.addHost(host) }
        host.savePasswordAuthorized = true
        try database.addHost(host)
        var other = sampleHost(); other.credentialRef = passphrase.id; other.savePasswordAuthorized = true
        XCTAssertThrowsError(try database.addHost(other))
        XCTAssertThrowsError(try database.registerKey(ManagedKeyReference(algorithm: .rsa, passphraseCredentialRef: password.id)))
        host.savePasswordAuthorized = false
        expect(.savingNotAuthorized) { try database.updateHost(host) }
        XCTAssertTrue(try database.host(id: host.id)!.savePasswordAuthorized)
        XCTAssertEqual(try database.hosts().count, 1)
    }

    func testBatchSQLFailureRollsBackAllChanges() throws {
        let folder = HostFolder(name: "must roll back")
        var invalid = sampleHost(); invalid.folderID = UUID()
        XCTAssertThrowsError(try database.apply([.saveFolder(folder), .insertHost(sampleHost("also rolls back")), .insertHost(invalid)]))
        XCTAssertTrue(try database.folders().isEmpty)
        XCTAssertTrue(try database.hosts().isEmpty)
    }

    func testInjectedBeforeCommitFailureRollsBackResourceDeletionAndTicket() throws {
        enum Injected: Error { case fail }
        let credential = CredentialReference(purpose: .password, isSavingAuthorized: true)
        try database.registerCredential(credential)
        var settings = AppSettings(); settings.historyLines = 999
        XCTAssertThrowsError(try database.applyTransaction([.insertHost(sampleHost()), .saveSettings(settings), .deleteCredential(credential.id)], beforeCommit: { throw Injected.fail }))
        try reopen()
        XCTAssertTrue(try database.hosts().isEmpty)
        XCTAssertEqual(try database.credentials(), [credential])
        XCTAssertTrue(try database.cleanupTickets().isEmpty)
        XCTAssertEqual(try database.settings().historyLines, 10_000)
    }

    func testIdempotencyDuplicateInsertAndConflictingRegistration() throws {
        let credential = CredentialReference(purpose: .password, isSavingAuthorized: true)
        try database.registerCredential(credential); try database.registerCredential(credential)
        expect(.conflictingID) { try database.registerCredential(CredentialReference(id: credential.id, purpose: .privateKeyPassphrase, isSavingAuthorized: true)) }
        let key = ManagedKeyReference(algorithm: .rsa)
        try database.registerKey(key); try database.registerKey(key)
        expect(.conflictingID) { try database.registerKey(ManagedKeyReference(id: key.id, algorithm: .ed25519)) }
        let host = sampleHost()
        try database.addHost(host)
        XCTAssertThrowsError(try database.addHost(host))
        XCTAssertEqual(try database.hosts().count, 1)
        expect(.notFound) { try database.updateHost(sampleHost()) }
        try database.deleteHost(id: host.id); try database.deleteHost(id: host.id)
        XCTAssertTrue(try database.hosts().isEmpty)
    }

    func testOrphanCleanupRetriesRestartAndCompletedTombstone() throws {
        let resource = ExternalResource(kind: .credential, id: UUID())
        try database.scheduleOrphanCleanup(resource); try database.scheduleOrphanCleanup(resource)
        let ticket = try XCTUnwrap(database.cleanupTickets().first)
        XCTAssertEqual(ticket.reason, .orphanedExternalResource)
        try database.recordCleanupFailure(ticketID: ticket.id, failure: .unavailable)
        try reopen()
        XCTAssertEqual(try database.cleanupTickets().first?.id, ticket.id)
        XCTAssertEqual(try database.cleanupTickets().first?.attemptCount, 1)
        XCTAssertEqual(try database.cleanupTickets().first?.lastFailure, .unavailable)
        expect(.cleanupAlreadyScheduled) { try database.registerCredential(CredentialReference(id: resource.id, purpose: .password, isSavingAuthorized: true)) }
        try database.completeCleanup(ticketID: ticket.id); try database.completeCleanup(ticketID: ticket.id)
        try database.recordCleanupFailure(ticketID: ticket.id, failure: .transient)
        try database.scheduleOrphanCleanup(resource)
        XCTAssertTrue(try database.cleanupTickets().isEmpty)
        XCTAssertEqual(try database.cleanupTickets(includeCompleted: true).first?.state, .completed)
        XCTAssertNil(try database.cleanupTickets(includeCompleted: true).first?.lastFailure)
        expect(.cleanupAlreadyScheduled) { try database.registerCredential(CredentialReference(id: resource.id, purpose: .password, isSavingAuthorized: true)) }
        let active = CredentialReference(purpose: .password, isSavingAuthorized: true)
        try database.registerCredential(active)
        expect(.resourceStillRegistered) { try database.scheduleOrphanCleanup(ExternalResource(kind: .credential, id: active.id)) }
        expect(.notFound) { try database.completeCleanup(ticketID: UUID()) }
    }

    func testDatabaseForeignKeysAndConstraintsCannotBeBypassed() throws {
        let credential = CredentialReference(purpose: .password, isSavingAuthorized: true)
        let host = HostConfiguration(name: "linked", address: "test.invalid", username: "fixture", credentialRef: credential.id, savePasswordAuthorized: true)
        try database.apply([.registerCredential(credential), .insertHost(host)])
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "DELETE FROM credentials WHERE id = ?", arguments: [credential.id]) })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE hosts SET folderID = ? WHERE id = ?", arguments: [UUID(), host.id]) })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE hosts SET savePasswordAuthorized = 0 WHERE id = ?", arguments: [host.id]) })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE hosts SET port = 0 WHERE id = ?", arguments: [host.id]) })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE settings SET historyLines = 100001") })
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "UPDATE settings SET backgroundColor = '#GG0000'") })
        let orphan = ExternalResource(kind: .privateKey, id: UUID())
        try database.scheduleOrphanCleanup(orphan)
        XCTAssertThrowsError(try database.queue.write { try $0.execute(sql: "INSERT INTO managedKeys(id, algorithm) VALUES (?, 'rsa')", arguments: [orphan.id]) })
        try database.queue.read { XCTAssertTrue(try Row.fetchAll($0, sql: "PRAGMA foreign_key_check").isEmpty) }
    }

    func testSettingsPersistenceAndBoundaryValidation() throws {
        var settings = AppSettings()
        settings.historyLines = 100_000; settings.fontName = "Menlo-Regular"; settings.fontSize = 72
        settings.theme = .dark; settings.foregroundColor = "#aAbB00"; settings.backgroundColor = "#000000"; settings.cursorColor = "#FFFFFF"
        settings.keepaliveInterval = 0; settings.keepaliveCountMax = 10
        try database.saveSettings(settings); try reopen()
        XCTAssertEqual(try database.settings(), settings)
        var invalid = settings; invalid.historyLines = 100_001
        expect(.invalidField("historyLines")) { try database.saveSettings(invalid) }
        invalid = settings; invalid.fontSize = .infinity
        expect(.invalidField("fontSize")) { try database.saveSettings(invalid) }
        invalid = settings; invalid.fontSize = 5.9
        expect(.invalidField("fontSize")) { try database.saveSettings(invalid) }
        invalid = settings; invalid.fontName = "bad\nfont"
        expect(.invalidField("fontName")) { try database.saveSettings(invalid) }
        invalid = settings; invalid.cursorColor = "#１２３４５６"
        expect(.invalidField("color")) { try database.saveSettings(invalid) }
        invalid = settings; invalid.keepaliveInterval = 3601
        expect(.invalidField("keepalive")) { try database.saveSettings(invalid) }
        invalid = settings; invalid.keepaliveCountMax = 0
        expect(.invalidField("keepalive")) { try database.saveSettings(invalid) }
        XCTAssertEqual(try database.settings(), settings)
        settings.historyLines = 0; settings.fontSize = 6; settings.keepaliveInterval = 3600; settings.keepaliveCountMax = 1
        try database.saveSettings(settings)
    }

    func testHostInputValidationHasNoCountLimit() throws {
        var invalid = sampleHost(); invalid.address = "bad\naddress"
        expect(.invalidField("address")) { try database.addHost(invalid) }
        invalid = sampleHost(); invalid.username = "two words"
        expect(.invalidField("username")) { try database.addHost(invalid) }
        invalid = sampleHost(); invalid.port = 65536
        expect(.invalidField("port")) { try database.addHost(invalid) }
        invalid = sampleHost(); invalid.name = "  "
        expect(.invalidField("name")) { try database.addHost(invalid) }
        invalid = sampleHost(); invalid.keepaliveInterval = -1
        expect(.invalidField("keepalive")) { try database.addHost(invalid) }
        invalid = sampleHost(); invalid.authentication = .privateKey; invalid.savePasswordAuthorized = true
        expect(.invalidField("authenticationReferences")) { try database.addHost(invalid) }
        // More than ten is intentionally supported. No sessions are created by recording metadata.
        try database.apply((0..<125).map { .insertHost(sampleHost("host-\($0)")) })
        try reopen()
        XCTAssertEqual(try database.hosts().count, 125)
    }

    private func installV1Fixture(extraSQL: String = "") throws {
        try database.close(); database = nil
        try FileManager.default.removeItem(at: directory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let url = try XCTUnwrap(Bundle.module.url(forResource: "schema-v1", withExtension: "sql", subdirectory: "Fixtures"))
        let fixture = try String(contentsOf: url, encoding: .utf8)
        let databaseURL = directory.appendingPathComponent("OpenLXSSH.sqlite")
        XCTAssertTrue(FileManager.default.createFile(atPath: databaseURL.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
        let raw = try DatabaseQueue(path: databaseURL.path)
        try raw.write { try $0.execute(sql: fixture + extraSQL) }
        try raw.close()
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: directory.appendingPathComponent("OpenLXSSH.sqlite").path)
    }

    func testV1FixtureMigratesWithoutLosingReferencesOrAuthorization() throws {
        try installV1Fixture()
        database = try OpenLXSSHDatabase(directory: directory)
        let passwordID = UUID(uuidString: "55555555-5555-4555-8555-555555555555")!
        let keyID = UUID(uuidString: "66666666-6666-4666-8666-666666666666")!
        let passwordHost = try XCTUnwrap(database.host(id: passwordID))
        XCTAssertEqual(passwordHost.name, "旧密码主机")
        XCTAssertTrue(passwordHost.savePasswordAuthorized)
        XCTAssertEqual(passwordHost.favoriteOrder, 0)
        XCTAssertEqual(passwordHost.lastConnectedAt, Date(timeIntervalSince1970: 1700000000))
        XCTAssertFalse(try database.host(id: keyID)!.savePasswordAuthorized)
        XCTAssertEqual(try database.keys().count, 1)
        XCTAssertEqual(try database.credentials().count, 2)
        XCTAssertEqual(try database.settings().historyLines, 10000)
        try database.updateHost(passwordHost)
        try reopen()
        XCTAssertEqual(try database.hosts().count, 2)
        try database.queue.read {
            XCTAssertEqual(try String.fetchAll($0, sql: "SELECT identifier FROM grdb_migrations ORDER BY identifier"), CoreSchema.versions)
            XCTAssertTrue(try Row.fetchAll($0, sql: "PRAGMA foreign_key_check").isEmpty)
        }
    }

    func testMigrationFailureRollsBackALTERsAndVersionAndCanRetry() throws {
        // Force an actual failure after the two ALTERs and authorization backfill.
        try installV1Fixture(extraSQL: "CREATE TABLE settings(blockMigration INTEGER);")
        XCTAssertThrowsError(try OpenLXSSHDatabase(directory: directory))
        let raw = try DatabaseQueue(path: directory.appendingPathComponent("OpenLXSSH.sqlite").path)
        try raw.read { db in
            let columns = try Row.fetchAll(db, sql: "PRAGMA table_info(hosts)").map { $0["name"] as String }
            XCTAssertFalse(columns.contains("savePasswordAuthorized"))
            XCTAssertFalse(columns.contains("favoriteOrder"))
            XCTAssertEqual(try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations"), ["v1_host_metadata"])
            XCTAssertEqual(try Int.fetchOne(db, sql: "SELECT count(*) FROM hosts"), 2)
        }
        try raw.write { try $0.execute(sql: "DROP TABLE settings") }
        try raw.close()
        database = try OpenLXSSHDatabase(directory: directory)
        XCTAssertEqual(try database.hosts().count, 2)
        XCTAssertEqual(try database.settings().historyLines, 10_000)
    }

    func testMigrationDoesNotAuthorizeWrongPurposeLegacyReference() throws {
        try installV1Fixture(extraSQL: "UPDATE hosts SET credentialRef = X'33333333333343338333333333333333' WHERE authentication = 'password';")
        expect(.savingNotAuthorized) { _ = try OpenLXSSHDatabase(directory: directory) }
        let raw = try DatabaseQueue(path: directory.appendingPathComponent("OpenLXSSH.sqlite").path)
        XCTAssertEqual(try raw.read { try String.fetchAll($0, sql: "SELECT identifier FROM grdb_migrations") }, ["v1_host_metadata"])
        try raw.close()
    }

    func testDesktopPreferencesRoundTripAndOnlySettingsChange() throws {
        let host = sampleHost(), credential = CredentialReference(purpose: .password, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .ed25519)
        try database.apply([.insertHost(host), .registerCredential(credential), .registerKey(key)])
        let hosts = try database.hosts(), credentials = try database.credentials(), keys = try database.keys()
        var settings = AppSettings(); settings.cursorShape = .bar; settings.cursorBlink = false; settings.startupPage = .lastManagement
        settings.foregroundColor = "#AABBCC"; settings.backgroundColor = "#112233"; settings.cursorColor = "#445566"
        try database.saveSettings(settings); try reopen()
        XCTAssertEqual(try database.settings(), settings)
        try database.saveSettings(AppSettings())
        XCTAssertEqual(try database.hosts(), hosts); XCTAssertEqual(try database.credentials(), credentials); XCTAssertEqual(try database.keys(), keys)
        XCTAssertTrue(try database.cleanupTickets(includeCompleted: true).isEmpty)
    }

    func testDesktopPreferencesCodableDefaultsAndMalformedValuesReject() throws {
        let decoder = JSONDecoder()
        let old = try decoder.decode(AppSettings.self, from: Data("{\"fontName\":\"Menlo-Regular\",\"backgroundColor\":\"#123456\"}".utf8))
        XCTAssertEqual(old.cursorShape, .block); XCTAssertTrue(old.cursorBlink); XCTAssertEqual(old.startupPage, .vault)
        XCTAssertEqual(old.fontName, "Menlo-Regular"); XCTAssertEqual(old.backgroundColor, "#123456")
        for text in ["{\"cursorShape\":\"circle\"}", "{\"cursorBlink\":\"yes\"}", "{\"startupPage\":\"session\"}", "{\"id\":2}", "{\"fontSize\":73}", "{\"backgroundColor\":\"white\"}"] {
            XCTAssertThrowsError(try decoder.decode(AppSettings.self, from: Data(text.utf8)), text)
        }
        var changed = old; changed.cursorShape = .underline; changed.cursorBlink = false; changed.startupPage = .sftp
        XCTAssertEqual(try decoder.decode(AppSettings.self, from: JSONEncoder().encode(changed)), changed)
    }

    func testDesktopPreferencesSQLConstraintsAndBadBatchRollback() throws {
        let original = try database.settings()
        for assignment in ["cursorShape = 'circle'", "cursorBlink = 2", "startupPage = 'session'"] {
            XCTAssertThrowsError(try database.queue.write { db in
                try db.execute(sql: "UPDATE settings SET fontSize = 21")
                try db.execute(sql: "UPDATE settings SET \(assignment)")
            })
            XCTAssertEqual(try database.settings(), original)
        }
        var invalid = original; invalid.fontSize = .infinity
        expect(.invalidField("fontSize")) { try database.apply([.insertHost(sampleHost()), .saveSettings(invalid)]) }
        XCTAssertTrue(try database.hosts().isEmpty)
        try reopen(); XCTAssertEqual(try database.settings(), original)
    }

    /// Build the exact v3 shape by removing only v4's three added columns from a
    /// synthetic database. Old columns and their data are captured before re-opening.
    private func installDesktopV3Snapshot(extraSQL: String = "") throws -> (URL, [Row]) {
        var settings = AppSettings(); settings.historyLines = 3210; settings.fontSize = 17
        settings.foregroundColor = "#AABBCC"; settings.backgroundColor = "#112233"; settings.cursorColor = "#445566"
        try database.apply([.insertHost(sampleHost()), .saveSettings(settings)])
        try database.queue.write { db in
            try db.execute(sql: "ALTER TABLE settings DROP COLUMN cursorShape; ALTER TABLE settings DROP COLUMN cursorBlink; ALTER TABLE settings DROP COLUMN startupPage;")
            try db.execute(sql: "DELETE FROM grdb_migrations WHERE identifier = 'v4_desktop_preferences'")
            try db.execute(sql: extraSQL)
        }
        let rows = try database.queue.read { try Row.fetchAll($0, sql: "SELECT * FROM settings") }
        let url = database.databaseURL
        try database.close(); database = nil
        return (url, rows)
    }

    func testV3DesktopPreferencesMigrationPreservesOldColorsAndHosts() throws {
        let (_, rows) = try installDesktopV3Snapshot()
        database = try OpenLXSSHDatabase(directory: directory)
        let settings = try database.settings()
        XCTAssertEqual(settings.historyLines, 3210); XCTAssertEqual(settings.fontSize, 17)
        XCTAssertEqual(settings.foregroundColor, "#AABBCC"); XCTAssertEqual(settings.backgroundColor, "#112233"); XCTAssertEqual(settings.cursorColor, "#445566")
        XCTAssertEqual(settings.cursorShape, .block); XCTAssertTrue(settings.cursorBlink); XCTAssertEqual(settings.startupPage, .vault)
        let projection = rows[0].columnNames.map { "\"" + $0 + "\"" }.joined(separator: ", ")
        try database.queue.read { db in
            XCTAssertEqual(try Row.fetchAll(db, sql: "SELECT \(projection) FROM settings"), rows)
            XCTAssertEqual(try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations ORDER BY identifier"), CoreSchema.versions)
            XCTAssertTrue(try Row.fetchAll(db, sql: "PRAGMA foreign_key_check").isEmpty)
        }
        XCTAssertEqual(try database.hosts().count, 1); try reopen(); XCTAssertEqual(try database.settings(), settings)
    }

    func testV4DesktopPreferencesMigrationFailureRollsBackAddedColumnsAndRetries() throws {
        let (url, rows) = try installDesktopV3Snapshot(extraSQL: "ALTER TABLE settings ADD COLUMN cursorBlink INTEGER NOT NULL DEFAULT 1;")
        XCTAssertThrowsError(try OpenLXSSHDatabase(directory: directory))
        let raw = try DatabaseQueue(path: url.path)
        try raw.read { db in
            XCTAssertEqual(try Row.fetchAll(db, sql: "SELECT * FROM settings"), rows)
            let columns = try Row.fetchAll(db, sql: "PRAGMA table_info(settings)").map { $0["name"] as String }
            XCTAssertFalse(columns.contains("cursorShape")); XCTAssertFalse(columns.contains("startupPage"))
            XCTAssertEqual(try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations ORDER BY identifier"), Array(CoreSchema.versions.prefix(3)))
            XCTAssertEqual(try Int.fetchOne(db, sql: "SELECT count(*) FROM hosts"), 1)
        }
        try raw.write { try $0.execute(sql: "ALTER TABLE settings DROP COLUMN cursorBlink") }; try raw.close()
        database = try OpenLXSSHDatabase(directory: directory)
        XCTAssertEqual(try database.settings().backgroundColor, "#112233"); XCTAssertEqual(try database.hosts().count, 1)
    }

    func testUnknownFutureMigrationRefusedWithoutErasingData() throws {
        let host = sampleHost()
        try database.addHost(host)
        try database.queue.write { try $0.execute(sql: "INSERT INTO grdb_migrations(identifier) VALUES ('v99_future')") }
        try database.close(); database = nil
        expect(.unsupportedSchema) { _ = try OpenLXSSHDatabase(directory: directory) }
        let raw = try DatabaseQueue(path: directory.appendingPathComponent("OpenLXSSH.sqlite").path)
        XCTAssertEqual(try raw.read { try Int.fetchOne($0, sql: "SELECT count(*) FROM hosts") }, 1)
        try raw.close()
    }

    func testDirectoryDatabaseAndLiveWALPermissions() throws {
        try database.addHost(sampleHost())
        for filename in ["OpenLXSSH.sqlite", "OpenLXSSH.sqlite-wal", "OpenLXSSH.sqlite-shm"] {
            let url = directory.appendingPathComponent(filename)
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), filename)
            XCTAssertEqual(try permissions(url), 0o600, filename)
        }
        XCTAssertEqual(try permissions(directory), 0o700)
        try database.close()
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: directory.appendingPathComponent("OpenLXSSH.sqlite").path)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
        database = try OpenLXSSHDatabase(directory: directory)
        XCTAssertEqual(try permissions(directory), 0o700)
        XCTAssertEqual(try permissions(database.databaseURL), 0o600)
    }

    func testUnrelatedFilesAreNotSilentlyPermissionChanged() throws {
        let unrelated = directory.appendingPathComponent("unrelated.txt")
        XCTAssertTrue(FileManager.default.createFile(atPath: unrelated.path, contents: Data(), attributes: [.posixPermissions: 0o644]))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: unrelated.path)
        try reopen()
        XCTAssertEqual(try permissions(unrelated), 0o644)
    }

    func testSymlinkHardlinkAndSidecarAttacksRejected() throws {
        try database.close(); database = nil
        let dbURL = directory.appendingPathComponent("OpenLXSSH.sqlite")
        let savedURL = directory.appendingPathComponent("saved.sqlite")
        try FileManager.default.moveItem(at: dbURL, to: savedURL)
        try FileManager.default.createSymbolicLink(atPath: dbURL.path, withDestinationPath: savedURL.path)
        expect(.unsafeDatabaseLocation) { _ = try OpenLXSSHDatabase(directory: directory) }
        try FileManager.default.removeItem(at: dbURL)
        try FileManager.default.linkItem(at: savedURL, to: dbURL)
        expect(.unsafeDatabaseLocation) { _ = try OpenLXSSHDatabase(directory: directory) }
        try FileManager.default.removeItem(at: dbURL)
        try FileManager.default.moveItem(at: savedURL, to: dbURL)
        let sidecar = directory.appendingPathComponent("OpenLXSSH.sqlite-wal")
        if FileManager.default.fileExists(atPath: sidecar.path) { try FileManager.default.removeItem(at: sidecar) }
        try FileManager.default.createSymbolicLink(atPath: sidecar.path, withDestinationPath: dbURL.path)
        expect(.unsafeDatabaseLocation) { _ = try OpenLXSSHDatabase(directory: directory) }
        try FileManager.default.removeItem(at: sidecar)
        database = try OpenLXSSHDatabase(directory: directory)
    }

    func testDirectorySymlinkAndLiveReplacementRejected() throws {
        let alias = directory.deletingLastPathComponent().appendingPathComponent("openlxssh-core-test-alias-" + UUID().uuidString)
        try FileManager.default.createSymbolicLink(atPath: alias.path, withDestinationPath: directory.path)
        defer { try? FileManager.default.removeItem(at: alias) }
        expect(.unsafeDatabaseLocation) { _ = try OpenLXSSHDatabase(directory: alias) }
        let originalURL = database.databaseURL
        let saved = directory.appendingPathComponent("old.sqlite")
        try FileManager.default.moveItem(at: originalURL, to: saved)
        _ = FileManager.default.createFile(atPath: originalURL.path, contents: Data(), attributes: [.posixPermissions: 0o600])
        expect(.unsafeDatabaseLocation) { _ = try database.hosts() }
        try FileManager.default.removeItem(at: originalURL)
        try FileManager.default.moveItem(at: saved, to: originalURL)
        // SQLite may poison a connection after its live file was renamed; never reuse it.
        try reopen()
        XCTAssertTrue(try database.hosts().isEmpty)
    }

    func testTwoDatabaseInstancesWriteConcurrentlyAndBusyWaits() throws {
        let second = try OpenLXSSHDatabase(directory: directory)
        defer { try? second.close() }
        let first = try XCTUnwrap(database)
        let failures = LockedErrors()
        DispatchQueue.concurrentPerform(iterations: 80) { index in
            do { try (index.isMultiple(of: 2) ? first : second).addHost(HostConfiguration(name: "parallel-\(index)", address: "test.invalid", username: "fixture")) }
            catch { failures.append(error) }
        }
        XCTAssertEqual(failures.count, 0)
        XCTAssertEqual(try database.hosts().count, 80)
        let acquired = DispatchSemaphore(value: 0)
        let released = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            do {
                try first.queue.write { _ in acquired.signal(); Thread.sleep(forTimeInterval: 0.25) }
            } catch { failures.append(error) }
            released.signal()
        }
        XCTAssertEqual(acquired.wait(timeout: .now() + 5), .success)
        let start = Date()
        try second.addHost(sampleHost("busy writer"))
        XCTAssertGreaterThan(Date().timeIntervalSince(start), 0.1)
        XCTAssertEqual(released.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(failures.count, 0)
    }

    private func fixture(mode: String, extra: [String] = []) throws -> Process {
        let binary = Bundle(for: OpenLXSSHCoreTests.self).bundleURL.deletingLastPathComponent().appendingPathComponent("OpenLXSSHDatabaseFixture")
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: binary.path), "SwiftPM must build the test fixture")
        let process = Process()
        process.executableURL = binary
        process.arguments = [mode, directory.path] + extra
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run()
        return process
    }

    func testIndependentProcessesWriteToSameTemporaryDatabase() throws {
        let first = try fixture(mode: "write", extra: ["process-a", "40"])
        let second = try fixture(mode: "write", extra: ["process-b", "40"])
        first.waitUntilExit(); second.waitUntilExit()
        XCTAssertEqual(first.terminationStatus, 0)
        XCTAssertEqual(second.terminationStatus, 0)
        XCTAssertEqual(try database.hosts().count, 80)
        try database.queue.read { XCTAssertEqual(try String.fetchOne($0, sql: "PRAGMA integrity_check"), "ok") }
    }

    func testCrossProcessWriterStillWaitsAfterPermissionChecks() throws {
        let readyURL = directory.appendingPathComponent("writer.ready")
        let process = try fixture(mode: "hold-write")
        let deadline = Date().addingTimeInterval(5)
        while !FileManager.default.fileExists(atPath: readyURL.path) && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: readyURL.path))
        let started = Date()
        try database.addHost(sampleHost("waited for child"))
        XCTAssertGreaterThan(Date().timeIntervalSince(started), 0.15)
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertEqual(try database.hosts().count, 2)
        try database.queue.read { XCTAssertEqual(try String.fetchOne($0, sql: "PRAGMA integrity_check"), "ok") }
    }

    func testACLChecksPreserveHeldSQLitePOSIXLocksAgainstIndependentProcess() throws {
        let location = try SecureDatabaseLocation(directory: directory)
        try database.queue.write { db in
            try db.execute(sql: "INSERT INTO hosts(id, name, address, username, authentication) VALUES (?, 'parent-held-lock', 'test.invalid', 'fixture', 'password')", arguments: [UUID()])
            // This is the dangerous direction: a close of an extra descriptor in *this*
            // process releases our existing SQLite locks, even while GRDB owns the writer.
            for _ in 0..<25 { try location.validateAndSecureFiles() }
            let posixProbe = try fixture(mode: "probe-posix-lock")
            posixProbe.waitUntilExit()
            XCTAssertEqual(posixProbe.terminationStatus, 74, "Core checks must preserve the DB inode's POSIX locks")
            let process = try fixture(mode: "probe-writer-lock")
            process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 74, "Independent writer must still receive SQLITE_BUSY")
        }
        let process = try fixture(mode: "probe-writer-lock")
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0, "Lock must be released normally after COMMIT")
        XCTAssertEqual(try database.hosts().count, 2)
        try database.queue.read { XCTAssertEqual(try String.fetchOne($0, sql: "PRAGMA integrity_check"), "ok") }
    }

    func testFreshDatabaseConcurrentProcessInitializationAndMigration() throws {
        try database.close(); database = nil
        try FileManager.default.removeItem(at: directory)
        // Race creation and migration, not just updates to an already initialized database.
        let first = try fixture(mode: "write", extra: ["fresh-a", "20"])
        let second = try fixture(mode: "write", extra: ["fresh-b", "20"])
        first.waitUntilExit(); second.waitUntilExit()
        XCTAssertEqual(first.terminationStatus, 0)
        XCTAssertEqual(second.terminationStatus, 0)
        database = try OpenLXSSHDatabase(directory: directory)
        XCTAssertEqual(try database.hosts().count, 40)
        try database.queue.read { db in
            XCTAssertEqual(try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations ORDER BY identifier"), CoreSchema.versions)
        }
    }

    func testAbruptChildExitRecoversCommittedWAL() throws {
        try database.close(); database = nil
        let process = try fixture(mode: "abrupt-commit")
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 71)
        let wal = directory.appendingPathComponent("OpenLXSSH.sqlite-wal")
        XCTAssertGreaterThan((try FileManager.default.attributesOfItem(atPath: wal.path)[.size] as! NSNumber).intValue, 32)
        XCTAssertEqual(try permissions(wal), 0o600)
        database = try OpenLXSSHDatabase(directory: directory)
        XCTAssertEqual(try database.hosts().map(\.name), ["committed"])
        try database.queue.read { XCTAssertEqual(try String.fetchOne($0, sql: "PRAGMA integrity_check"), "ok") }
    }

    func testDeletionAndOrphanCleanupSurviveAbruptExit() throws {
        let credential = CredentialReference(id: UUID(uuidString: "88888888-8888-4888-8888-888888888888")!, purpose: .password, isSavingAuthorized: true)
        try database.registerCredential(credential)
        try database.close(); database = nil
        let process = try fixture(mode: "abrupt-cleanup")
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 73)
        database = try OpenLXSSHDatabase(directory: directory)
        XCTAssertTrue(try database.credentials().isEmpty)
        let tickets = try database.cleanupTickets()
        XCTAssertEqual(tickets.count, 2)
        XCTAssertEqual(Set(tickets.map(\.reason)), [.removedReference, .orphanedExternalResource])
        XCTAssertTrue(tickets.contains { $0.resourceID == credential.id })
        expect(.cleanupAlreadyScheduled) { try database.registerCredential(credential) }
    }

    func testAbruptChildExitRollsBackSpilledUncommittedTransaction() throws {
        let baseline = sampleHost("baseline")
        try database.addHost(baseline)
        try database.close(); database = nil
        let process = try fixture(mode: "abrupt-transaction")
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 72)
        let metricsURL = directory.appendingPathComponent("uncommitted-wal.json")
        let metrics = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: metricsURL)) as? [String: Int])
        XCTAssertGreaterThan(try XCTUnwrap(metrics["walAfter"]), try XCTUnwrap(metrics["walBefore"]))
        XCTAssertEqual(try permissions(metricsURL), 0o600)
        let wal = directory.appendingPathComponent("OpenLXSSH.sqlite-wal")
        XCTAssertGreaterThan((try FileManager.default.attributesOfItem(atPath: wal.path)[.size] as! NSNumber).intValue, 32)
        database = try OpenLXSSHDatabase(directory: directory)
        XCTAssertEqual(try database.hosts(), [baseline])
        try database.queue.read {
            XCTAssertEqual(try String.fetchOne($0, sql: "PRAGMA integrity_check"), "ok")
            XCTAssertTrue(try Row.fetchAll($0, sql: "PRAGMA foreign_key_check").isEmpty)
        }
    }
}

private final class LockedErrors: @unchecked Sendable {
    private let lock = NSLock()
    private var errors: [Error] = []
    func append(_ error: Error) { lock.lock(); defer { lock.unlock() }; errors.append(error) }
    var count: Int { lock.lock(); defer { lock.unlock() }; return errors.count }
}
