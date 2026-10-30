-- Frozen OpenLXSSHCore v2_settings_and_cleanup SQL baseline.
-- Apply after the independent schema-v1.sql fixture; never call the current migrator to construct v2.
-- All UUIDs and metadata below are synthetic. No external secret or private-key material is needed.
ALTER TABLE hosts ADD COLUMN savePasswordAuthorized INTEGER NOT NULL DEFAULT 0 CHECK(savePasswordAuthorized IN (0, 1));
ALTER TABLE hosts ADD COLUMN favoriteOrder INTEGER NOT NULL DEFAULT 0 CHECK(favoriteOrder BETWEEN -1000000000 AND 1000000000);
UPDATE hosts SET savePasswordAuthorized = 1 WHERE credentialRef IS NOT NULL;
CREATE TABLE settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    historyLines INTEGER NOT NULL DEFAULT 10000 CHECK(historyLines BETWEEN 0 AND 100000),
    fontName TEXT NOT NULL DEFAULT 'SFMono-Regular' CHECK(length(fontName) BETWEEN 1 AND 256),
    fontSize REAL NOT NULL DEFAULT 13 CHECK(fontSize BETWEEN 6 AND 72),
    theme TEXT NOT NULL DEFAULT 'system' CHECK(theme IN ('system', 'light', 'dark')),
    foregroundColor TEXT NOT NULL DEFAULT '#D8DEE9' CHECK(length(foregroundColor) = 7 AND substr(foregroundColor, 1, 1) = '#' AND substr(foregroundColor, 2) NOT GLOB '*[^0-9a-fA-F]*'),
    backgroundColor TEXT NOT NULL DEFAULT '#20242C' CHECK(length(backgroundColor) = 7 AND substr(backgroundColor, 1, 1) = '#' AND substr(backgroundColor, 2) NOT GLOB '*[^0-9a-fA-F]*'),
    cursorColor TEXT NOT NULL DEFAULT '#D8DEE9' CHECK(length(cursorColor) = 7 AND substr(cursorColor, 1, 1) = '#' AND substr(cursorColor, 2) NOT GLOB '*[^0-9a-fA-F]*'),
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
CREATE TRIGGER credentials_deny_tombstone BEFORE INSERT ON credentials
WHEN EXISTS(SELECT 1 FROM cleanupTickets WHERE resourceKind = 'credential' AND resourceID = NEW.id)
BEGIN SELECT RAISE(ABORT, 'resource cleanup scheduled'); END;
CREATE TRIGGER cleanup_deny_credentials BEFORE INSERT ON cleanupTickets
WHEN NEW.resourceKind = 'credential' AND EXISTS(SELECT 1 FROM credentials WHERE id = NEW.resourceID)
BEGIN SELECT RAISE(ABORT, 'resource still registered'); END;
CREATE TRIGGER managedKeys_deny_tombstone BEFORE INSERT ON managedKeys
WHEN EXISTS(SELECT 1 FROM cleanupTickets WHERE resourceKind = 'privateKey' AND resourceID = NEW.id)
BEGIN SELECT RAISE(ABORT, 'resource cleanup scheduled'); END;
CREATE TRIGGER cleanup_deny_managedKeys BEFORE INSERT ON cleanupTickets
WHEN NEW.resourceKind = 'privateKey' AND EXISTS(SELECT 1 FROM managedKeys WHERE id = NEW.resourceID)
BEGIN SELECT RAISE(ABORT, 'resource still registered'); END;
CREATE TRIGGER hosts_authorization_INSERT BEFORE INSERT ON hosts
WHEN (NEW.credentialRef IS NOT NULL AND (NEW.savePasswordAuthorized != 1 OR
     NOT EXISTS(SELECT 1 FROM credentials WHERE id = NEW.credentialRef AND purpose = 'password' AND isSavingAuthorized = 1)))
     OR (NEW.authentication IN ('privateKey', 'privateKeyWithMFA') AND NEW.savePasswordAuthorized != 0)
BEGIN SELECT RAISE(ABORT, 'invalid credential authorization'); END;
CREATE TRIGGER hosts_authorization_UPDATE BEFORE UPDATE ON hosts
WHEN (NEW.credentialRef IS NOT NULL AND (NEW.savePasswordAuthorized != 1 OR
     NOT EXISTS(SELECT 1 FROM credentials WHERE id = NEW.credentialRef AND purpose = 'password' AND isSavingAuthorized = 1)))
     OR (NEW.authentication IN ('privateKey', 'privateKeyWithMFA') AND NEW.savePasswordAuthorized != 0)
BEGIN SELECT RAISE(ABORT, 'invalid credential authorization'); END;
INSERT INTO grdb_migrations(identifier) VALUES ('v2_settings_and_cleanup');

-- Exercise nondefault ordering, authorization, settings, history, shared references, and tombstones.
UPDATE hosts SET favoriteOrder = 17, keepaliveInterval = 47, keepaliveCountMax = 6 WHERE authentication = 'password';
INSERT INTO hosts(id, name, address, port, username, authentication, credentialRef, savePasswordAuthorized, isFavorite, favoriteOrder, lastConnectedAt)
VALUES (X'77777777777747778777777777777777', '旧共享密码MFA', 'shared.invalid', 2222, 'fixture', 'passwordWithMFA', X'22222222222242228222222222222222', 1, 1, -9, 1700000001.125);
INSERT INTO hosts(id, name, address, username, authentication, keyRef, folderID)
VALUES (X'88888888888848888888888888888888', '旧共享密钥', 'shared-key.invalid', 'fixture', 'privateKey', X'44444444444444448444444444444444', X'11111111111141118111111111111111');
UPDATE settings SET historyLines = 4321, fontName = 'Menlo-Regular', fontSize = 16, theme = 'dark', backgroundColor = '#000000', keepaliveInterval = 42;
INSERT INTO cleanupTickets(id, resourceKind, resourceID, reason, state, createdAt, attemptCount, lastFailure)
VALUES (X'99999999999949998999999999999999', 'credential', X'AAAAAAAAAAAA4AAA8AAAAAAAAAAAAAAA', 'removedReference', 'pending', 1700000010.5, 2, 'transient');
INSERT INTO cleanupTickets(id, resourceKind, resourceID, reason, state, createdAt, attemptCount)
VALUES (X'BBBBBBBBBBBB4BBB8BBBBBBBBBBBBBBB', 'privateKey', X'CCCCCCCCCCCC4CCC8CCCCCCCCCCCCCCC', 'orphanedExternalResource', 'completed', 1700000011.5, 1);
