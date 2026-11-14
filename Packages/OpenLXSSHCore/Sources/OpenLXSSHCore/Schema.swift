import Foundation
import GRDB

enum CoreSchema {
    static let versions = ["v1_host_metadata", "v2_settings_and_cleanup", "v3_vault_metadata", "v4_desktop_preferences", "v5_direct_file_transfer", "v6_ask_before_file_replacement"]

    static func migrate(_ queue: DatabaseQueue) throws {
        // Never silently open a database written by a newer app, and never erase on schema change.
        try queue.read { db in
            if try db.tableExists("grdb_migrations") {
                let applied = try String.fetchAll(db, sql: "SELECT identifier FROM grdb_migrations")
                let appliedSet = Set(applied)
                guard appliedSet.isSubset(of: Set(versions)),
                      appliedSet == Set(versions.prefix(appliedSet.count)) else { throw RepositoryError.unsupportedSchema }
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
        migrator.registerMigration(versions[2]) { db in
            // Additive only: existing rows, UUIDs, authorizations, and cleanup tombstones stay intact.
            // GRDB wraps the migration and its version record in a transaction.
            try db.execute(sql: """
                ALTER TABLE folders ADD COLUMN parentID BLOB REFERENCES folders(id) ON DELETE RESTRICT
                    CHECK(parentID IS NULL OR (typeof(parentID) = 'blob' AND length(parentID) = 16 AND parentID != id));
                CREATE INDEX folders_parent ON folders(parentID);
                ALTER TABLE managedKeys ADD COLUMN label TEXT NOT NULL DEFAULT '' CHECK(length(CAST(label AS BLOB)) <= 256);
                CREATE TABLE tags (
                    id BLOB PRIMARY KEY NOT NULL CHECK(typeof(id) = 'blob' AND length(id) = 16),
                    name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 256)
                );
                CREATE TABLE hostTags (
                    hostID BLOB NOT NULL REFERENCES hosts(id) ON DELETE CASCADE CHECK(typeof(hostID) = 'blob' AND length(hostID) = 16),
                    tagID BLOB NOT NULL REFERENCES tags(id) ON DELETE CASCADE CHECK(typeof(tagID) = 'blob' AND length(tagID) = 16),
                    PRIMARY KEY(hostID, tagID)
                );
                CREATE INDEX hostTags_tag ON hostTags(tagID, hostID);
                """)
            for action in ["INSERT", "UPDATE OF parentID"] {
                let suffix = action == "INSERT" ? "insert" : "update"
                try db.execute(sql: """
                    CREATE TRIGGER folders_no_cycle_\(suffix) BEFORE \(action) ON folders
                    WHEN NEW.parentID IS NOT NULL AND EXISTS(
                        WITH RECURSIVE ancestors(id) AS (
                            SELECT NEW.parentID
                            UNION
                            SELECT f.parentID FROM folders f JOIN ancestors a ON f.id = a.id WHERE f.parentID IS NOT NULL
                        ) SELECT 1 FROM ancestors WHERE id = NEW.id)
                    BEGIN SELECT RAISE(ABORT, 'folder cycle'); END;
                    """)
            }
        }
        migrator.registerMigration(versions[3]) { db in
            // Preferences only. Do not rewrite old colors or any host/secret/trust metadata.
            try db.execute(sql: """
                ALTER TABLE settings ADD COLUMN cursorShape TEXT NOT NULL DEFAULT 'block'
                    CHECK(cursorShape IN ('block', 'underline', 'bar'));
                ALTER TABLE settings ADD COLUMN cursorBlink INTEGER NOT NULL DEFAULT 1 CHECK(cursorBlink IN (0, 1));
                ALTER TABLE settings ADD COLUMN startupPage TEXT NOT NULL DEFAULT 'vault'
                    CHECK(startupPage IN ('vault', 'sftp', 'lastManagement'));
                """)
        }
        migrator.registerMigration(versions[4]) { db in
            try db.execute(sql: "ALTER TABLE settings ADD COLUMN fileConflictPolicy TEXT NOT NULL DEFAULT 'autoRename' CHECK(fileConflictPolicy IN ('autoRename', 'overwrite', 'skip', 'ask'))")
        }
        migrator.registerMigration(versions[5]) { db in
            // v5 shipped autoRename as the ordinary default. Change only that prior
            // preference once; explicit overwrite/skip/ask and all other data stay intact.
            try db.execute(sql: "UPDATE settings SET fileConflictPolicy = 'ask' WHERE fileConflictPolicy = 'autoRename'")
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
