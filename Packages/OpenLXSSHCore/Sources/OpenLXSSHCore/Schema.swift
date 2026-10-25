import Foundation
import GRDB

enum CoreSchema {
    static let versions = ["v1_host_metadata", "v2_settings_and_cleanup"]

    static func migrate(_ queue: DatabaseQueue) throws {
        // Never silently open a database written by a newer app, and never erase on schema change.
        try queue.read { db in
            if try db.tableExists("grdb_migrations") {
                let applied = try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations")
                guard Set(applied).isSubset(of: Set(versions)) else { throw RepositoryError.unsupportedSchema }
            }
        }
        var migrator = DatabaseMigrator()
        migrator.registerMigration(versions[0]) { db in try db.execute(sql: version1) }
        migrator.registerMigration(versions[1]) { db in
            // v1 metadata is never a reason to authorize a wrong-purpose or missing credential.
            if try Bool.fetchOne(db, sql: """
                SELECT EXISTS(SELECT 1 FROM hosts h LEFT JOIN credentials c ON c.id = h.credentialRef
                    WHERE h.credentialRef IS NOT NULL AND (c.id IS NULL OR c.purpose != 'password' OR c.isSavingAuthorized != 1))
                """) == true { throw RepositoryError.savingNotAuthorized }
            try db.execute(sql: """
                ALTER TABLE hosts ADD COLUMN savePasswordAuthorized INTEGER NOT NULL DEFAULT 0 CHECK(savePasswordAuthorized IN (0, 1));
                ALTER TABLE hosts ADD COLUMN favoriteOrder INTEGER NOT NULL DEFAULT 0 CHECK(favoriteOrder BETWEEN -1000000000 AND 1000000000);
                UPDATE hosts SET savePasswordAuthorized = 1 WHERE credentialRef IS NOT NULL;
                CREATE TABLE settings (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    historyLines INTEGER NOT NULL DEFAULT 10000 CHECK(historyLines BETWEEN 0 AND 100000),
                    fontName TEXT NOT NULL DEFAULT 'SFMono-Regular' CHECK(length(fontName) BETWEEN 1 AND 256),
                    fontSize REAL NOT NULL DEFAULT 13 CHECK(fontSize BETWEEN 6 AND 72),
                    theme TEXT NOT NULL DEFAULT 'system' CHECK(theme IN ('system', 'light', 'dark')),
                    foregroundColor TEXT NOT NULL DEFAULT '#D8DEE9' CHECK(\(colorCheck("foregroundColor"))),
                    backgroundColor TEXT NOT NULL DEFAULT '#20242C' CHECK(\(colorCheck("backgroundColor"))),
                    cursorColor TEXT NOT NULL DEFAULT '#D8DEE9' CHECK(\(colorCheck("cursorColor"))),
                    keepaliveInterval INTEGER NOT NULL DEFAULT 30 CHECK(keepaliveInterval BETWEEN 0 AND 3600),
                    keepaliveCountMax INTEGER NOT NULL DEFAULT 3 CHECK(keepaliveCountMax BETWEEN 1 AND 10)
                );
                INSERT INTO settings(id) VALUES (1);
                CREATE TABLE cleanupTickets (
                    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
                    resourceKind TEXT NOT NULL CHECK(resourceKind IN ('credential', 'privateKey')),
                    resourceID BLOB NOT NULL CHECK(length(resourceID) = 16),
                    reason TEXT NOT NULL CHECK(reason IN ('removedReference', 'orphanedExternalResource')),
                    state TEXT NOT NULL CHECK(state IN ('pending', 'completed')),
                    createdAt REAL NOT NULL,
                    attemptCount INTEGER NOT NULL DEFAULT 0 CHECK(attemptCount BETWEEN 0 AND 1000000),
                    lastFailure TEXT CHECK(lastFailure IN ('unavailable', 'permissionDenied', 'transient')),
                    UNIQUE(resourceKind, resourceID)
                );
                CREATE INDEX cleanup_pending ON cleanupTickets(state, createdAt, id);
                CREATE INDEX hosts_favorites ON hosts(isFavorite, favoriteOrder, name, id);
                CREATE INDEX hosts_recent ON hosts(lastConnectedAt DESC, id);
                """)
            // Cleanup tickets deliberately outlive their registry rows: no FK to a deleted resource.
            // Tombstones prevent reference resurrection while an external deletion is in flight or complete.
            for (table, kind) in [("credentials", "credential"), ("managedKeys", "privateKey")] {
                try db.execute(sql: """
                    CREATE TRIGGER \(table)_deny_tombstone BEFORE INSERT ON \(table)
                    WHEN EXISTS(SELECT 1 FROM cleanupTickets WHERE resourceKind = '\(kind)' AND resourceID = NEW.id)
                    BEGIN SELECT RAISE(ABORT, 'resource cleanup scheduled'); END;
                    CREATE TRIGGER cleanup_deny_\(table) BEFORE INSERT ON cleanupTickets
                    WHEN NEW.resourceKind = '\(kind)' AND EXISTS(SELECT 1 FROM \(table) WHERE id = NEW.resourceID)
                    BEGIN SELECT RAISE(ABORT, 'resource still registered'); END;
                    """)
            }
            for action in ["INSERT", "UPDATE"] {
                try db.execute(sql: """
                    CREATE TRIGGER hosts_authorization_\(action) BEFORE \(action) ON hosts
                    WHEN (NEW.credentialRef IS NOT NULL AND (NEW.savePasswordAuthorized != 1 OR
                         NOT EXISTS(SELECT 1 FROM credentials WHERE id = NEW.credentialRef AND purpose = 'password' AND isSavingAuthorized = 1)))
                         OR (NEW.authentication IN ('privateKey', 'privateKeyWithMFA') AND NEW.savePasswordAuthorized != 0)
                    BEGIN SELECT RAISE(ABORT, 'invalid credential authorization'); END;
                    """)
            }
        }
        try migrator.migrate(queue)
    }

    private static func colorCheck(_ column: String) -> String {
        "length(\(column)) = 7 AND substr(\(column), 1, 1) = '#' AND substr(\(column), 2) NOT GLOB '*[^0-9a-fA-F]*'"
    }

    // Version 1 is frozen. An independent SQL fixture in Tests represents this exact published baseline.
    private static let version1 = """
        CREATE TABLE folders (
            id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
            name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 256),
            sortOrder INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE credentials (
            id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
            purpose TEXT NOT NULL CHECK(purpose IN ('password', 'privateKeyPassphrase')),
            isSavingAuthorized INTEGER NOT NULL CHECK(isSavingAuthorized = 1)
        );
        CREATE TABLE managedKeys (
            id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
            algorithm TEXT NOT NULL CHECK(algorithm IN ('ed25519', 'rsa')),
            passphraseCredentialRef BLOB REFERENCES credentials(id) ON DELETE RESTRICT
        );
        CREATE INDEX keys_credential ON managedKeys(passphraseCredentialRef);
        CREATE TABLE hosts (
            id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
            name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 256),
            address TEXT NOT NULL CHECK(length(address) BETWEEN 1 AND 1024),
            port INTEGER NOT NULL DEFAULT 22 CHECK(port BETWEEN 1 AND 65535),
            username TEXT NOT NULL CHECK(length(username) BETWEEN 1 AND 256),
            authentication TEXT NOT NULL CHECK(authentication IN ('password', 'passwordWithMFA', 'privateKey', 'privateKeyWithMFA')),
            credentialRef BLOB REFERENCES credentials(id) ON DELETE RESTRICT,
            keyRef BLOB REFERENCES managedKeys(id) ON DELETE RESTRICT,
            folderID BLOB REFERENCES folders(id) ON DELETE SET NULL,
            isFavorite INTEGER NOT NULL DEFAULT 0 CHECK(isFavorite IN (0, 1)),
            lastConnectedAt REAL,
            keepaliveInterval INTEGER NOT NULL DEFAULT 30 CHECK(keepaliveInterval BETWEEN 0 AND 3600),
            keepaliveCountMax INTEGER NOT NULL DEFAULT 3 CHECK(keepaliveCountMax BETWEEN 1 AND 10),
            CHECK((authentication IN ('password', 'passwordWithMFA') AND keyRef IS NULL) OR
                  (authentication IN ('privateKey', 'privateKeyWithMFA') AND credentialRef IS NULL))
        );
        CREATE INDEX hosts_folder ON hosts(folderID);
        CREATE INDEX hosts_credential ON hosts(credentialRef);
        CREATE INDEX hosts_key ON hosts(keyRef);
        CREATE TRIGGER key_passphrase_insert BEFORE INSERT ON managedKeys
        WHEN NEW.passphraseCredentialRef IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM credentials WHERE id = NEW.passphraseCredentialRef AND purpose = 'privateKeyPassphrase' AND isSavingAuthorized = 1)
        BEGIN SELECT RAISE(ABORT, 'invalid passphrase reference'); END;
        CREATE TRIGGER key_passphrase_update BEFORE UPDATE ON managedKeys
        WHEN NEW.passphraseCredentialRef IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM credentials WHERE id = NEW.passphraseCredentialRef AND purpose = 'privateKeyPassphrase' AND isSavingAuthorized = 1)
        BEGIN SELECT RAISE(ABORT, 'invalid passphrase reference'); END;
        """
}
