import Darwin
import Foundation
@testable import OpenLXSSHTrust
import XCTest

@MainActor
final class ACLTests: XCTestCase {
    func testInheritedEveryoneACLIsRejectedBeforeStoreFilesAreCreated() async throws {
        let parent = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        defer { removeFixtureACLs(parent.url) }
        try addACL("everyone allow read,write,execute,file_inherit,directory_inherit", at: parent.url)
        let root = parent.file("trust")
        let path = try AbsolutePath(root.path)

        // The old implementation accepted 0700/0600 despite inherited everyone write access.
        // Continue through the actual exploit when init succeeds, so the pre-fix log records it.
        let store: HostTrustStore
        do {
            store = try HostTrustStore(directory: path)
            XCTFail("An inherited extended ACL must be rejected before creating store files")
        } catch {
            assertUnsafeStorage(error)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [])
            XCTAssertTrue(try aclPresence(root))
            return
        }
        let identity = try host()
        let original = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let changed = try HostPublicKey(openSSHPublicKey: changedFixture)
        try await accept(store, identity, original)
        let knownHosts = root.appendingPathComponent("known_hosts")
        let before = try metadata(knownHosts)
        XCTAssertEqual(before.st_mode & 0o7777, 0o600)
        XCTAssertTrue(try aclPresence(root))
        XCTAssertTrue(try aclPresence(knownHosts))
        try replaceKeyInPlace(at: knownHosts, from: original, to: changed)
        XCTAssertEqual(try metadata(knownHosts).st_ino, before.st_ino)
        do {
            let result = try await store.evaluate(host: identity, key: changed)
            print("Inherited everyone ACL, 0700 root/0600 known_hosts, same-inode valid-header keyA-to-B evaluation: \(result)")
            XCTFail("ACL-enabled in-place replacement must never be trusted")
        } catch { assertUnsafeStorage(error) }
    }

    func testRuntimeKnownHostsACLAndInPlaceKeyChangeAreRejected() async throws {
        let directory = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        defer { removeFixtureACLs(directory.url) }
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let original = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let changed = try HostPublicKey(openSSHPublicKey: changedFixture)
        try await accept(store, identity, original)
        let file = directory.file("known_hosts")
        let before = try metadata(file)
        try addACL("everyone allow read,write", at: file)
        try replaceKeyInPlace(at: file, from: original, to: changed)
        XCTAssertEqual(try metadata(file).st_ino, before.st_ino)
        XCTAssertEqual(try metadata(file).st_mode & 0o7777, 0o600)
        XCTAssertTrue(try aclPresence(file))
        do {
            let result = try await store.evaluate(host: identity, key: changed)
            print("Runtime known_hosts everyone ACL, same-inode valid-header keyA-to-B evaluation: \(result)")
            XCTFail("Runtime extended ACL must cause unsafeStorage, not trusted/pending/rejected")
        } catch { assertUnsafeStorage(error) }
    }

    func testExistingRootLockAndKnownHostsACLsAreRejectedWithoutModification() async throws {
        for surface in ["root", "trust.lock", "known_hosts"] {
            for denyOnly in [false, true] {
                let directory = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
                defer { removeFixtureACLs(directory.url) }
                let store = try HostTrustStore(directory: directory.path)
                try await accept(store, try host(), try HostPublicKey(openSSHPublicKey: ed25519Fixture))
                let target = surface == "root" ? directory.url : directory.file(surface)
                let before = try snapshot(directory.url)
                let entry = denyOnly ? "everyone deny delete" :
                    (surface == "root" ? "everyone allow read,write,execute" : "everyone allow read,write")
                try addACL(entry, at: target)
                let aclBefore = try aclDescription(target)
                XCTAssertThrowsError(try HostTrustStore(directory: directory.path)) { assertUnsafeStorage($0) }
                XCTAssertEqual(try snapshot(directory.url), before)
                XCTAssertEqual(try aclDescription(target), aclBefore, "Reject, do not repair the user's ACL")
                XCTAssertTrue(try aclPresence(target))
            }
        }
    }

    func testRuntimeACLsRejectEveryTrustOperationAndConsumeConfirmation() async throws {
        for surface in ["root", "trust.lock", "known_hosts"] {
            for denyOnly in [false, true] {
                let directory = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
                defer { removeFixtureACLs(directory.url) }
                let store = try HostTrustStore(directory: directory.path)
                let identity = try host()
                let original = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
                let changed = try HostPublicKey(openSSHPublicKey: changedFixture)
                try await accept(store, identity, original)
                let decision = try pendingDecision(try await store.evaluate(host: host("new.example"), key: original))
                let target = surface == "root" ? directory.url : directory.file(surface)
                let before = try snapshot(directory.url)
                try addACL(denyOnly ? "everyone deny delete" : "everyone allow read,write", at: target)
                let aclBefore = try aclDescription(target)
                await expectUnsafeStorage { try await store.records() }
                await expectUnsafeStorage { try await store.evaluate(host: identity, key: original) }
                await expectUnsafeStorage { try await store.evaluate(host: identity, key: changed) }
                await expectUnsafeStorage {
                    try await store.prepareReplacement(host: identity, key: changed,
                                                       expectedCurrentFingerprint: original.fingerprint)
                }
                await expectUnsafeStorage { try await store.confirm(decision, displayedFingerprint: decision.fingerprint) }
                await assertAsyncError(.expiredDecision) {
                    try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
                }
                XCTAssertEqual(try snapshot(directory.url), before)
                XCTAssertEqual(try aclDescription(target), aclBefore)
            }
        }
    }

    func testPOSIXChmodDoesNotClearAnACLAndStoreDoesNotRepairIt() async throws {
        let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        defer { removeFixtureACLs(fixture.url) }
        let store = try HostTrustStore(directory: fixture.path)
        let before = try snapshot(fixture.url)
        let file = fixture.file("known_hosts")
        try addACL("everyone allow read,write", at: file)
        XCTAssertEqual(chmod(file.path, 0o600), 0)
        XCTAssertEqual(chmod(fixture.url.path, 0o700), 0)
        XCTAssertTrue(try aclPresence(file), "POSIX chmod is not ACL removal")
        let aclBefore = try aclDescription(file)
        await expectUnsafeStorage { try await store.records() }
        XCTAssertThrowsError(try HostTrustStore(directory: fixture.path)) { assertUnsafeStorage($0) }
        XCTAssertEqual(try snapshot(fixture.url), before)
        XCTAssertEqual(try aclDescription(file), aclBefore)
    }

    func testRuntimeInheritableRootACLPreventsAnyNewWrite() async throws {
        let directory = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        defer { removeFixtureACLs(directory.url) }
        let store = try HostTrustStore(directory: directory.path)
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let decision = try pendingDecision(try await store.evaluate(host: host(), key: key))
        let before = try snapshot(directory.url)
        try addACL("everyone allow read,write,execute,file_inherit,directory_inherit", at: directory.url)
        await expectUnsafeStorage { try await store.confirm(decision, displayedFingerprint: key.fingerprint) }
        XCTAssertEqual(try snapshot(directory.url), before)
        XCTAssertFalse(try aclPresence(directory.file("known_hosts")), "Existing files did not inherit; root itself must be checked")
    }

    func testACLChangedWhileWaitingForFlockIsRejectedInsideLock() async throws {
        let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        defer { removeFixtureACLs(fixture.url) }
        _ = try HostTrustStore(directory: fixture.path)
        let file = fixture.file("trust.lock")
        let lockInode = try metadata(file).st_ino
        let observedPreLockValidation = DispatchSemaphore(value: 0)
        let directory = try PrivateDirectory(fixture.path, metadataReader: { fd in
            let value = try PrivateDirectory.metadataWithoutACL(fd)
            if value.st_ino == lockInode { observedPreLockValidation.signal() }
            return value
        })
        let blocker = open(file.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(blocker, 0)
        defer { _ = flock(blocker, LOCK_UN); close(blocker) }
        XCTAssertEqual(flock(blocker, LOCK_EX | LOCK_NB), 0)
        let operation = Task.detached { () -> (HostTrustError?, Bool) in
            var actionExecuted = false
            do {
                try directory.withLock("trust.lock") { _ in actionExecuted = true }
                return (nil, actionExecuted)
            } catch { return (error as? HostTrustError, actionExecuted) }
        }
        XCTAssertEqual(observedPreLockValidation.wait(timeout: .now() + 2), .success)
        try addACL("everyone allow read,write", at: file)
        XCTAssertEqual(flock(blocker, LOCK_UN), 0)
        let (error, actionExecuted) = await operation.value
        XCTAssertFalse(actionExecuted, "Revalidate after flock acquisition, before calling action")
        guard let error else { return XCTFail("ACL added during flock wait must prevent action execution") }
        assertUnsafeStorage(error)
        XCTAssertTrue(try aclPresence(file))
    }

    func testReadRevalidatesFileDirectoryAndLockAfterReading() async throws {
        for surface in ["root", "trust.lock", "known_hosts"] {
            let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
            defer { removeFixtureACLs(fixture.url) }
            _ = try HostTrustStore(directory: fixture.path)
            let target = surface == "root" ? fixture.url : fixture.file(surface)
            let knownHosts = fixture.file("known_hosts")
            let inode = try metadata(knownHosts).st_ino
            let before = try Data(contentsOf: knownHosts)
            var reads = 0
            var injected = false
            let directory = try PrivateDirectory(fixture.path, metadataReader: { fd in
                var raw = stat()
                XCTAssertEqual(fstat(fd, &raw), 0)
                if raw.st_ino == inode {
                    reads += 1
                    if reads == 2 {
                        try self.addACL("everyone allow read,write", at: target)
                        injected = true
                    }
                }
                return try PrivateDirectory.metadataWithoutACL(fd)
            })
            XCTAssertThrowsError(try directory.withLock("trust.lock") { _ in try directory.read("known_hosts") }) {
                assertUnsafeStorage($0)
            }
            XCTAssertTrue(injected, "Inject immediately after the data read, not before opening")
            XCTAssertEqual(try Data(contentsOf: knownHosts), before)
            XCTAssertTrue(try aclPresence(target))
        }
    }

    func testLockExitRevalidatesAccessedFilesAfterAction() async throws {
        for surface in ["root", "trust.lock", "known_hosts"] {
            let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
            defer { removeFixtureACLs(fixture.url) }
            _ = try HostTrustStore(directory: fixture.path)
            let directory = try PrivateDirectory(fixture.path)
            let target = surface == "root" ? fixture.url : fixture.file(surface)
            XCTAssertThrowsError(try directory.withLock("trust.lock") { _ in
                _ = try directory.read("known_hosts")
                try addACL("everyone deny delete", at: target)
                return "must not escape as a trusted result"
            }) { assertUnsafeStorage($0) }
            XCTAssertTrue(try aclPresence(target))
        }
    }

    func testAtomicTemporaryInheritedACLIsRejectedBeforeWritingAndCleanedUp() async throws {
        let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        defer { removeFixtureACLs(fixture.url) }
        _ = try HostTrustStore(directory: fixture.path)
        let knownHosts = fixture.file("known_hosts")
        let inode = try metadata(knownHosts).st_ino
        let before = try snapshot(fixture.url)
        var knownChecks = 0
        var inheritedTemporaryObserved = false
        let directory = try PrivateDirectory(fixture.path, metadataReader: { fd in
            var raw = stat()
            XCTAssertEqual(fstat(fd, &raw), 0)
            let names = try FileManager.default.contentsOfDirectory(atPath: fixture.url.path)
            if let temporary = names.first(where: { $0.hasPrefix(".pending-") }) {
                let file = fixture.file(temporary)
                if try self.metadata(file).st_ino == raw.st_ino {
                    inheritedTemporaryObserved = try self.aclPresence(file)
                    XCTAssertEqual(raw.st_size, 0, "Reject inherited ACL before writing bytes")
                }
            }
            let checked = try PrivateDirectory.metadataWithoutACL(fd)
            if checked.st_ino == inode {
                knownChecks += 1
                if knownChecks == 3 {
                    // Simulate root changing immediately after the read's final checks.
                    try self.addACL("everyone allow read,write,execute,file_inherit,directory_inherit", at: fixture.url)
                }
            }
            return checked
        })
        XCTAssertThrowsError(try directory.withLock("trust.lock") { _ in
            try directory.atomicWrite("known_hosts", data: Data("never published\n".utf8))
        }) { assertUnsafeStorage($0) }
        XCTAssertTrue(inheritedTemporaryObserved)
        XCTAssertEqual(try snapshot(fixture.url), before)
        XCTAssertTrue(try aclPresence(fixture.url), "Failure must not clear the existing root's ACL")
    }

    func testAtomicWriteRevalidatesEveryStorageObjectBeforeCommit() async throws {
        for surface in ["root", "trust.lock", "known_hosts", "temporary"] {
            let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
            defer { removeFixtureACLs(fixture.url) }
            _ = try HostTrustStore(directory: fixture.path)
            let before = try snapshot(fixture.url)
            var temporaryChecks = 0
            var injectedTarget: URL?
            let directory = try PrivateDirectory(fixture.path, metadataReader: { fd in
                var raw = stat()
                XCTAssertEqual(fstat(fd, &raw), 0)
                let pending = try FileManager.default.contentsOfDirectory(atPath: fixture.url.path)
                    .first(where: { $0.hasPrefix(".pending-") })
                let temporary = pending.map { fixture.file($0) }
                let isTemporary = try temporary.map { try self.metadata($0).st_ino == raw.st_ino } ?? false
                if isTemporary { temporaryChecks += 1 }
                let checked = try PrivateDirectory.metadataWithoutACL(fd)
                if isTemporary && temporaryChecks == 1 {
                    let target = surface == "temporary" ? temporary! :
                        (surface == "root" ? fixture.url : fixture.file(surface))
                    try self.addACL("everyone allow read,write", at: target)
                    injectedTarget = target
                }
                return checked
            })
            XCTAssertThrowsError(try directory.withLock("trust.lock") { _ in
                try directory.atomicWrite("known_hosts", data: Data("never published\n".utf8))
            }) { assertUnsafeStorage($0) }
            XCTAssertNotNil(injectedTarget)
            if surface == "temporary" { XCTAssertGreaterThanOrEqual(temporaryChecks, 2, "Recheck the temp ACL before rename") }
            else { XCTAssertTrue(try aclPresence(injectedTarget!)) }
            XCTAssertEqual(try snapshot(fixture.url), before, "No rename, no pending file, no data or inode changes")
        }
    }

    func testAtomicCleanupDoesNotUnlinkAReplacedTemporaryInode() async throws {
        let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        defer { removeFixtureACLs(fixture.url) }
        _ = try HostTrustStore(directory: fixture.path)
        let before = try Data(contentsOf: fixture.file("known_hosts"))
        let marker = Data("other inode must not be cleaned up".utf8)
        var replacedName: String?
        let directory = try PrivateDirectory(fixture.path, metadataReader: { fd in
            let checked = try PrivateDirectory.metadataWithoutACL(fd)
            if replacedName == nil,
               let name = try FileManager.default.contentsOfDirectory(atPath: fixture.url.path)
                .first(where: { $0.hasPrefix(".pending-") }),
               try self.metadata(fixture.file(name)).st_ino == checked.st_ino {
                try FileManager.default.moveItem(at: fixture.file(name), to: fixture.file("owned-temporary"))
                XCTAssertTrue(FileManager.default.createFile(atPath: fixture.file(name).path, contents: marker,
                                                           attributes: [.posixPermissions: 0o600]))
                replacedName = name
            }
            return checked
        })
        XCTAssertThrowsError(try directory.withLock("trust.lock") { _ in
            try directory.atomicWrite("known_hosts", data: Data("never published\n".utf8))
        }) { assertUnsafeStorage($0) }
        let name = try XCTUnwrap(replacedName)
        XCTAssertEqual(try Data(contentsOf: fixture.file(name)), marker)
        XCTAssertEqual(try Data(contentsOf: fixture.file("known_hosts")), before)
    }

    func testMetadataQueryErrorsAndUnpopulatedModeFailClosed() throws {
        let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        let fd = open(fixture.url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { close(fd) }
        XCTAssertThrowsError(try PrivateDirectory.metadataWithoutACL(-1)) { assertUnsafeStorage($0) }
        for property in [FILESEC_MODE, FILESEC_ACL] {
            for failure in [EIO, ENOENT, EACCES, ENOMEM, ENOTSUP] {
                XCTAssertThrowsError(try PrivateDirectory.metadataWithoutACL(fd, queryProperty: { security, queried, value in
                    if queried == property { errno = failure; return -1 }
                    return filesec_query_property(security, queried, value)
                })) { assertUnsafeStorage($0) }
            }
        }
        XCTAssertThrowsError(try PrivateDirectory.metadataWithoutACL(fd, queryProperty: { security, property, value in
            if property == FILESEC_MODE { value.pointee = 0; return 0 }
            return filesec_query_property(security, property, value)
        })) { assertUnsafeStorage($0) }
        XCTAssertThrowsError(try PrivateDirectory(fixture.path, metadataReader: { fd in
            try PrivateDirectory.metadataWithoutACL(fd, queryProperty: { security, property, value in
                if property == FILESEC_ACL { errno = EIO; return -1 }
                return filesec_query_property(security, property, value)
            })
        })) { assertUnsafeStorage($0) }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: fixture.url.path), [])
    }

    func testRuntimeACLQueryFailureCannotBeTreatedAsMissingStorageOrCommitted() async throws {
        let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        _ = try HostTrustStore(directory: fixture.path)
        let before = try snapshot(fixture.url)
        var failQuery = false
        let directory = try PrivateDirectory(fixture.path, metadataReader: { fd in
            try PrivateDirectory.metadataWithoutACL(fd, queryProperty: { security, property, value in
                if failQuery && property == FILESEC_ACL { errno = ENOENT; return -1 }
                return filesec_query_property(security, property, value)
            })
        })
        failQuery = true
        XCTAssertThrowsError(try directory.withLock("trust.lock") { _ in try directory.read("known_hosts") }) {
            assertUnsafeStorage($0)
        }
        XCTAssertThrowsError(try directory.withLock("trust.lock") { _ in
            try directory.atomicWrite("known_hosts", data: Data("never published\n".utf8))
        }) { assertUnsafeStorage($0) }
        XCTAssertEqual(try snapshot(fixture.url), before)
        failQuery = false
        try directory.withLock("trust.lock") { _ in
            XCTAssertEqual(try directory.read("known_hosts"), before["known_hosts"]?.bytes)
        }
    }

    func testSuccessfulMetadataQueriesIgnoreStaleErrnoAndUseNonzeroPresence() throws {
        let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
        let fd = open(fixture.url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { close(fd) }
        errno = ENOENT
        let metadata = try PrivateDirectory.metadataWithoutACL(fd, queryProperty: { security, property, value in
            let result = filesec_query_property(security, property, value)
            errno = EINVAL
            return result
        })
        XCTAssertEqual(metadata.st_mode & 0o7777, 0o700)
        for bitmask: Int32 in [1, 32, 256] {
            XCTAssertThrowsError(try PrivateDirectory.metadataWithoutACL(fd, queryProperty: { security, property, value in
                if property == FILESEC_ACL { value.pointee = bitmask; return 0 }
                return filesec_query_property(security, property, value)
            })) { assertUnsafeStorage($0) }
        }
    }

    func testRepeatedACLFailuresReleaseDirectoryLockReadAndTemporaryDescriptors() async throws {
        for surface in ["root", "trust.lock", "known_hosts", "temporary"] {
            let fixture = try TemporaryDirectory(name: "OpenLXSSH-ACL-")
            defer { removeFixtureACLs(fixture.url) }
            _ = try HostTrustStore(directory: fixture.path)
            let directory = try PrivateDirectory(fixture.path, metadataReader: { fd in
                let checked = try PrivateDirectory.metadataWithoutACL(fd)
                if surface == "temporary",
                   let name = try FileManager.default.contentsOfDirectory(atPath: fixture.url.path)
                    .first(where: { $0.hasPrefix(".pending-") }),
                   try self.metadata(fixture.file(name)).st_ino == checked.st_ino {
                    try self.addACL("everyone allow read,write", at: fixture.file(name))
                    return try PrivateDirectory.metadataWithoutACL(fd)
                }
                return checked
            })
            if surface != "temporary" {
                try addACL("everyone allow read,write", at: surface == "root" ? fixture.url : fixture.file(surface))
            }
            let baseline = descriptors()
            for _ in 0..<16 {
                if surface == "root" {
                    XCTAssertThrowsError(try HostTrustStore(directory: fixture.path)) { assertUnsafeStorage($0) }
                }
                XCTAssertThrowsError(try directory.withLock("trust.lock") { _ in
                    try directory.atomicWrite("known_hosts", data: Data("not committed\n".utf8))
                }) { assertUnsafeStorage($0) }
            }
            XCTAssertEqual(descriptors(), baseline, "No descriptor leaks for \(surface)")
            XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: fixture.url.path)),
                           Set(["known_hosts", "trust.lock"]))
            // A second independent FD can immediately take flock after every rejected operation.
            let lock = open(fixture.file("trust.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(lock, 0)
            defer { close(lock) }
            XCTAssertEqual(flock(lock, LOCK_EX | LOCK_NB), 0)
            XCTAssertEqual(flock(lock, LOCK_UN), 0)
        }
    }

    private struct Snapshot: Equatable {
        let inode: ino_t
        let mode: mode_t
        let bytes: Data?
    }

    private func snapshot(_ root: URL) throws -> [String: Snapshot] {
        var values: [String: Snapshot] = [:]
        for name in ["."] + (try FileManager.default.contentsOfDirectory(atPath: root.path)).sorted() {
            let file = name == "." ? root : root.appendingPathComponent(name)
            let value = try metadata(file)
            values[name] = Snapshot(inode: value.st_ino, mode: value.st_mode & 0o7777,
                bytes: (value.st_mode & S_IFMT) == S_IFREG ? try Data(contentsOf: file) : nil)
        }
        return values
    }

    private func aclDescription(_ url: URL) throws -> String {
        let result = try runTool("/bin/ls", ["-lde", url.path])
        XCTAssertEqual(result.status, 0, result.error)
        return result.output
    }

    private func descriptors() -> Set<Int32> {
        Set((0..<1024).compactMap { fcntl(Int32($0), F_GETFD) < 0 ? nil : Int32($0) })
    }

    private func expectUnsafeStorage<T>(_ operation: () async throws -> T) async {
        do { _ = try await operation(); XCTFail("Expected unsafeStorage") }
        catch { assertUnsafeStorage(error) }
    }

    private func replaceKeyInPlace(at file: URL, from original: HostPublicKey,
                                   to changed: HostPublicKey) throws {
        let before = try String(contentsOf: file, encoding: .utf8)
        XCTAssertTrue(before.hasPrefix("# OpenLXSSH-host-trust-v1 "))
        XCTAssertTrue(before.contains(original.openSSH))
        let replacement = before.replacingOccurrences(of: original.openSSH, with: changed.openSSH)
        XCTAssertNotEqual(replacement, before)
        let handle = try FileHandle(forWritingTo: file)
        defer { try? handle.close() }
        try handle.truncate(atOffset: 0)
        try handle.write(contentsOf: Data(replacement.utf8))
        try handle.synchronize()
    }

    private func addACL(_ entry: String, at url: URL) throws {
        // Use the already-tested sole-waiter runner so repeated ACL/resource checks do not
        // depend on Foundation Process/Pipe autorelease timing in the XCTest main actor.
        let result = try BoundedToolRunner.run(executable: "/bin/chmod", arguments: ["+a", entry, url.path], input: Data())
        XCTAssertTrue(result.exitedSuccessfully, "Fixture chmod failed: \(result.waitStatus)")
        guard result.exitedSuccessfully else { throw HostTrustError.systemOperation("test chmod ACL", result.waitStatus) }
        XCTAssertTrue(try aclPresence(url), "Fixture must contain an actual extended ACL")
    }

    private func removeFixtureACLs(_ root: URL) {
        // Only test-owned UUID roots reach this helper, never production storage or ancestors.
        XCTAssertTrue(root.lastPathComponent.hasPrefix("OpenLXSSH-ACL-"))
        let result = try? runTool("/bin/chmod", ["-RN", root.path])
        XCTAssertEqual(result?.status, 0, result?.error ?? "Fixture ACL cleanup failed")
    }

    private func metadata(_ url: URL) throws -> stat {
        var value = stat()
        guard lstat(url.path, &value) == 0 else { throw HostTrustError.systemOperation("test lstat", errno) }
        return value
    }

    private func aclPresence(_ url: URL) throws -> Bool {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw HostTrustError.systemOperation("test open", errno) }
        defer { close(fd) }
        guard let security = filesec_init() else { throw HostTrustError.systemOperation("test filesec_init", errno) }
        defer { filesec_free(security) }
        var value = stat()
        guard fstatx_np(fd, &value, security) == 0 else { throw HostTrustError.systemOperation("test fstatx", errno) }
        var populated: Int32 = 0
        guard filesec_query_property(security, FILESEC_MODE, &populated) == 0, populated != 0 else {
            throw HostTrustError.unsafeStorage("test unpopulated metadata")
        }
        var present: Int32 = 0
        guard filesec_query_property(security, FILESEC_ACL, &present) == 0 else {
            throw HostTrustError.systemOperation("test filesec query", errno)
        }
        return present != 0
    }

    private func assertUnsafeStorage(_ error: Error, file: StaticString = #filePath, line: UInt = #line) {
        guard case .unsafeStorage = error as? HostTrustError else {
            return XCTFail("Expected unsafeStorage, got \(error)", file: file, line: line)
        }
    }
}
