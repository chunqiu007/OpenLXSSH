-- Frozen OpenLXSSHCore v1_host_metadata fixture. Credentials were explicitly authorized in v1.
-- UUIDs are BLOB(16). No secret bytes or external file paths are stored here.
CREATE TABLE grdb_migrations (identifier TEXT NOT NULL PRIMARY KEY);
INSERT INTO grdb_migrations(identifier) VALUES ('v1_host_metadata');
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
INSERT INTO folders(id, name, sortOrder) VALUES (X'11111111111141118111111111111111', '旧文件夹', 2);
INSERT INTO credentials(id, purpose, isSavingAuthorized) VALUES (X'22222222222242228222222222222222', 'password', 1);
INSERT INTO credentials(id, purpose, isSavingAuthorized) VALUES (X'33333333333343338333333333333333', 'privateKeyPassphrase', 1);
INSERT INTO managedKeys(id, algorithm, passphraseCredentialRef) VALUES (X'44444444444444448444444444444444', 'ed25519', X'33333333333343338333333333333333');
INSERT INTO hosts(id, name, address, username, authentication, credentialRef, folderID, isFavorite, lastConnectedAt)
VALUES (X'55555555555545558555555555555555', '旧密码主机', 'old.invalid', 'fixture', 'password', X'22222222222242228222222222222222', X'11111111111141118111111111111111', 1, 1700000000);
INSERT INTO hosts(id, name, address, username, authentication, keyRef)
VALUES (X'66666666666646668666666666666666', '旧密钥主机', 'key.invalid', 'fixture', 'privateKeyWithMFA', X'44444444444444448444444444444444');
