import Darwin
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHSecurity

@MainActor final class AppACLTests: XCTestCase {
    private func directory() throws -> URL {
        let value = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: value, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: value) }
        return value
    }
    private func addACL(_ url: URL, inherited: Bool = false) throws {
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", inherited ? "everyone allow read,write,delete,add_file,add_subdirectory,file_inherit,directory_inherit" : "everyone allow read,write,delete", url.path]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
    }
    private func expectFailure(_ operation: () async throws -> Void) async {
        do { try await operation(); XCTFail("Unsafe ACL accepted") } catch {}
    }
    private func setSyntheticACL(_ url: URL, rule: String) throws {
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", rule, url.path]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw CocoaError(.fileWriteNoPermission) }
        // Only synthetic test paths are changed or cleaned. Never alter the
        // real Library/Application Support ACL to make the App start.
        addTeardownBlock {
            let cleanup = Process(); cleanup.executableURL = URL(fileURLWithPath: "/bin/chmod")
            cleanup.arguments = ["-N", url.path]
            cleanup.standardOutput = FileHandle.nullDevice; cleanup.standardError = FileHandle.nullDevice
            try cleanup.run(); cleanup.waitUntilExit()
        }
    }
    private func ACLBytes(_ descriptor: Int32) throws -> Data {
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else { throw CocoaError(.fileReadUnknown) }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        let size = acl_size(acl)
        guard size > 0, size <= 16 * 1024 else { throw CocoaError(.fileReadUnknown) }
        var data = Data(count: size)
        guard data.withUnsafeMutableBytes({ acl_copy_ext($0.baseAddress, acl, size) }) == size else { throw CocoaError(.fileReadUnknown) }
        return data
    }
    func testSystemParentDeleteDenyAllowsPrivateAppChildWithoutChangingParentPolicy() throws {
        let root = try directory(); try setSyntheticACL(root, rule: "everyone deny delete")
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { Darwin.close(fd) }
        var before = stat(); XCTAssertEqual(fstat(fd, &before), 0)
        let beforeACL = try ACLBytes(fd)
        // The same real ACL is unsafe on App-owned storage, but a normal
        // user-container protection must not prevent creating a private child.
        XCTAssertThrowsError(try AppFileSecurity.requireNoACL(fd))
        try AppDataLocation.ensureAppParent(in: fd)
        let child = root.appendingPathComponent("OpenLXSSH")
        let childFD = open(child.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(childFD, 0); defer { Darwin.close(childFD) }
        XCTAssertNoThrow(try AppFileSecurity.directory(childFD))
        let database = try OpenLXSSHDatabase(directory: child.appendingPathComponent("Data"))
        try database.apply([.insertHost(HostConfiguration(name: "synthetic", address: "acl.invalid", username: "fixture"))])
        XCTAssertEqual(try database.hosts().count, 1); try database.close()
        try AppDataLocation.ensureAppParent(in: fd)
        var after = stat(); XCTAssertEqual(fstat(fd, &after), 0)
        XCTAssertEqual(before.st_mode, after.st_mode); XCTAssertEqual(before.st_uid, after.st_uid)
        XCTAssertEqual(before.st_gid, after.st_gid); XCTAssertEqual(before.st_flags, after.st_flags)
        XCTAssertEqual(before.st_dev, after.st_dev); XCTAssertEqual(before.st_ino, after.st_ino)
        XCTAssertEqual(try ACLBytes(fd), beforeACL)
    }
    func testSystemParentACLOnlyAcceptsTheExactNoninheritingDeleteDeny() throws {
        for rule in ["everyone allow read", "everyone allow delete", "everyone deny readattr",
                     "everyone deny delete,writeattr", "everyone deny delete,file_inherit",
                     "everyone deny delete,directory_inherit", "everyone deny delete,only_inherit,directory_inherit",
                     "group:staff deny delete"] {
            let root = try directory(); try setSyntheticACL(root, rule: rule)
            let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            defer { Darwin.close(fd) }
            // Some deny rules themselves prevent ACL metadata reads. That is
            // a refusal case too, not evidence that no ACL is present.
            let before = try? ACLBytes(fd)
            XCTAssertThrowsError(try AppDataLocation.ensureAppParent(in: fd), rule)
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("OpenLXSSH").path), rule)
            XCTAssertEqual(try? ACLBytes(fd), before, rule)
        }
        let root = try directory(); try setSyntheticACL(root, rule: "everyone deny delete")
        try setSyntheticACL(root, rule: "everyone allow read")
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        defer { Darwin.close(fd) }
        XCTAssertThrowsError(try AppDataLocation.ensureAppParent(in: fd))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("OpenLXSSH").path))
    }
    func testProtectiveDenyRemainsForbiddenForAppOwnedAndIsolatedDirectories() throws {
        let root = try directory()
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        defer { Darwin.close(fd) }
        try AppDataLocation.ensureAppParent(in: fd)
        let child = root.appendingPathComponent("OpenLXSSH")
        try setSyntheticACL(child, rule: "everyone deny delete")
        XCTAssertThrowsError(try AppDataLocation.ensureAppParent(in: fd))
        let isolated = try directory(); try setSyntheticACL(isolated, rule: "everyone deny delete")
        XCTAssertThrowsError(try AppDataLocation.isolated(isolated).databaseDirectory())
        XCTAssertFalse(FileManager.default.fileExists(atPath: isolated.appendingPathComponent("Data").path))
    }
    func testSystemParentQueryFailureWritableModeAndSymlinkChildAreRejected() throws {
        XCTAssertThrowsError(try AppDataLocation.ensureAppParent(in: -1))
        let root = try directory()
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        defer { Darwin.close(fd) }
        XCTAssertEqual(fchmod(fd, 0o770), 0)
        XCTAssertThrowsError(try AppDataLocation.ensureAppParent(in: fd))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("OpenLXSSH").path))
        XCTAssertEqual(fchmod(fd, 0o700), 0)
        let target = try directory()
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("OpenLXSSH"), withDestinationURL: target)
        XCTAssertThrowsError(try AppDataLocation.ensureAppParent(in: fd))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: target.path).isEmpty)
    }
    func testPermissionIssuesExplainACLWithoutExposingSystemError() {
        let storage = AppIssue.sanitized(RepositoryError.unsafeDatabaseLocation)
        XCTAssertTrue(storage.message.contains("ACL")); XCTAssertTrue(storage.message.contains("不会静默删除"))
        let journal = AppIssue.security(SecurityUIFailure.journal)
        XCTAssertTrue(journal.message.contains("ACL")); XCTAssertTrue(journal.message.contains("不会静默删除"))
    }
    func testDescriptorNoACLAndQueryFailureAreDifferent() throws {
        let root = try directory()
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { Darwin.close(fd) }
        XCTAssertNoThrow(try AppFileSecurity.requireNoACL(fd))
        XCTAssertThrowsError(try AppFileSecurity.requireNoACL(-1))
        try addACL(root)
        XCTAssertThrowsError(try AppFileSecurity.requireNoACL(fd))
    }
    func testInheritableParentRefusedBeforeCreatingAppLeaf() throws {
        let root = try directory(); try addACL(root, inherited: true)
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        defer { Darwin.close(fd) }
        XCTAssertThrowsError(try AppDataLocation.ensureAppParent(in: fd))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("OpenLXSSH").path))
    }
    func testExistingAppRootACLRejectedWithoutRepairingIt() throws {
        let root = try directory()
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        defer { Darwin.close(fd) }
        try AppDataLocation.ensureAppParent(in: fd)
        let app = root.appendingPathComponent("OpenLXSSH")
        try addACL(app)
        XCTAssertThrowsError(try AppDataLocation.ensureAppParent(in: fd))
        let appFD = open(app.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        defer { Darwin.close(appFD) }
        XCTAssertThrowsError(try AppFileSecurity.requireNoACL(appFD))
    }
    func testIsolatedRootInitialAndRuntimeACLBlocksRepository() async throws {
        let first = try directory(); try addACL(first, inherited: true)
        XCTAssertThrowsError(try AppDataLocation.isolated(first).databaseDirectory())
        XCTAssertFalse(FileManager.default.fileExists(atPath: first.appendingPathComponent("Data").path))
        let root = try directory(); let repository = AppRepository(location: .isolated(root))
        _ = try await repository.snapshot(query: HostQuery())
        try addACL(root)
        await expectFailure { _ = try await repository.snapshot(query: HostQuery()) }
        await expectFailure { try await repository.apply([.insertHost(HostConfiguration(name: "blocked", address: "acl.invalid", username: "fixture"))]) }
        try await repository.close()
    }
    func testSessionDirectoriesRejectRootAndRuntimeChildACL() throws {
        let root = try directory(); try SessionEnvironment.validateDirectories(parent: root, create: true)
        try addACL(root.appendingPathComponent("Trust"))
        XCTAssertThrowsError(try SessionEnvironment.validateDirectories(parent: root, create: false))
        let other = try directory(); try SessionEnvironment.validateDirectories(parent: other, create: true)
        try addACL(other.appendingPathComponent("Sessions"))
        XCTAssertThrowsError(try SessionEnvironment.validateDirectories(parent: other, create: false))
        let inherited = try directory(); try addACL(inherited, inherited: true)
        XCTAssertThrowsError(try SessionEnvironment.validateDirectories(parent: inherited, create: true))
        XCTAssertFalse(FileManager.default.fileExists(atPath: inherited.appendingPathComponent("Trust").path))
    }
    func testJournalInitialACLAndRuntimeACLPreventReadAndPersist() throws {
        let root = try directory()
        let journal = try SecurityJournal(parent: root)
        let entry = SecurityIntent(id: UUID(), kind: .password, state: .prepared)
        try journal.set(entry)
        let path = root.appendingPathComponent("Recovery/security-intents.json")
        let before = try Data(contentsOf: path)
        try addACL(path)
        XCTAssertThrowsError(try SecurityJournal(parent: root))
        XCTAssertThrowsError(try journal.validateAccess())
        var created = entry; created.state = .created
        XCTAssertThrowsError(try journal.set(created))
        XCTAssertEqual(try Data(contentsOf: path), before)
        XCTAssertThrowsError(try journal.all())
    }
    func testJournalRecoveryAndParentACLRefuseBeforeCreatingOrWriting() throws {
        let inherited = try directory(); try addACL(inherited, inherited: true)
        XCTAssertThrowsError(try SecurityJournal(parent: inherited))
        XCTAssertFalse(FileManager.default.fileExists(atPath: inherited.appendingPathComponent("Recovery").path))
        let root = try directory(); let journal = try SecurityJournal(parent: root)
        try addACL(root.appendingPathComponent("Recovery"), inherited: true)
        XCTAssertThrowsError(try journal.set(.init(id: UUID(), kind: .password, state: .prepared)))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("Recovery/security-intents.json").path))
    }
    func testACLAddedToJournalTemporaryBeforeCommitRejectsPublish() throws {
        let root = try directory()
        let journal = try SecurityJournal(parent: root, beforeCommit: {
            // Only inspect this test-owned directory to inject an ACL onto this
            // operation's just-created temporary; production never enumerates it.
            let recovery = root.appendingPathComponent("Recovery")
            let temporary = try FileManager.default.contentsOfDirectory(at: recovery, includingPropertiesForKeys: nil).first { $0.pathExtension == "tmp" }
            guard let temporary else { throw SecurityUIFailure.journal }
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = ["+a", "everyone allow read,write,delete", temporary.path]
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw SecurityUIFailure.journal }
        })
        XCTAssertThrowsError(try journal.set(.init(id: UUID(), kind: .password, state: .prepared)))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("Recovery/security-intents.json").path))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("Recovery").path).isEmpty)
    }
    func testCoreCommitThenParentACLDoesNotCompensateKeyOrSecretAndEditorSucceeds() async throws {
        let root = try directory()
        let repository = AppRepository(location: .isolated(root), afterCommit: {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = ["+a", "everyone allow read,write,delete", root.path]
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw SecurityUIFailure.journal }
        })
        let credentials = FakeCredentials()
        let coordinator = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        let model = SecurityViewModel(coordinator: coordinator)
        let phrase = SecretBytes(utf8: UUID().uuidString)
        let success = await model.create(.generate, protection: .passphrase(phrase), remember: phrase)
        XCTAssertTrue(success)
        let result = try XCTUnwrap(model.lastCreatedKey)
        XCTAssertTrue(result.cleanupPending)
        let database = try OpenLXSSHDatabase(directory: root.appendingPathComponent("Data"))
        let keys = try database.keys(); let refs = try database.credentials()
        XCTAssertEqual(keys.map(\.id), [result.id]); XCTAssertEqual(refs.count, 1)
        XCTAssertEqual(keys[0].passphraseCredentialRef, refs[0].id)
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent("Keys/" + result.id.uuidString + ".openssh").path))
        let count = await credentials.count, deletes = await credentials.deleteCount
        XCTAssertEqual(count, 1); XCTAssertEqual(deletes, 0)
        try database.close(); try await coordinator.close(); try await repository.close()
    }
    func testHostCommitThenParentACLDismissesSaveWithoutRetryInsert() async throws {
        let root = try directory()
        let repository = AppRepository(location: .isolated(root), afterCommit: {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = ["+a", "everyone allow read,write,delete", root.path]
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw SecurityUIFailure.journal }
        })
        let credentials = FakeCredentials()
        let coordinator = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        let model = AppModel(repository: repository, security: coordinator, location: .isolated(root))
        let host = HostConfiguration(name: "committed", address: "acl.invalid", username: "fixture")
        let success = await model.saveHostSecurely(host, isNew: true, password: .remember(.init(utf8: UUID().uuidString)))
        XCTAssertTrue(success); XCTAssertEqual(model.issue?.code, "security.cleanupPending")
        let db = try OpenLXSSHDatabase(directory: root.appendingPathComponent("Data"))
        XCTAssertEqual(try db.hosts().map(\.id), [host.id]); XCTAssertEqual(try db.credentials().count, 1)
        let count = await credentials.count, deletes = await credentials.deleteCount
        XCTAssertEqual(count, 1); XCTAssertEqual(deletes, 0)
        try db.close(); try await coordinator.close(); try await repository.close()
    }
    func testJournalPostRenameACLRetainsCommittedRecordForRecovery() throws {
        let root = try directory()
        let entry = SecurityIntent(id: UUID(), kind: .password, state: .created)
        let journal = try SecurityJournal(parent: root, afterRename: {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = ["+a", "everyone allow read,write,delete", root.appendingPathComponent("Recovery/security-intents.json").path]
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw SecurityUIFailure.journal }
        })
        XCTAssertThrowsError(try journal.set(entry)) { XCTAssertTrue($0 is JournalWriteFailure) }
        let data = try Data(contentsOf: root.appendingPathComponent("Recovery/security-intents.json"))
        XCTAssertEqual(try JSONDecoder().decode([SecurityIntent].self, from: data), [entry])
        XCTAssertThrowsError(try journal.all())
        XCTAssertThrowsError(try SecurityJournal(parent: root))
    }
    func testJournalFinalACLFailureAfterEmptyReadDoesNotCloseReusedFDs() throws {
        try verifyJournalFinalACLFailurePreservesReusedFDs(seedExistingRecord: false)
    }
    func testJournalFinalACLFailureAfterDecodeDoesNotCloseReusedFDs() throws {
        try verifyJournalFinalACLFailurePreservesReusedFDs(seedExistingRecord: true)
    }
    private func verifyJournalFinalACLFailurePreservesReusedFDs(seedExistingRecord: Bool) throws {
        let root = try directory()
        if seedExistingRecord {
            let journal = try SecurityJournal(parent: root)
            try journal.set(.init(id: UUID(), kind: .password, state: .prepared))
        }
        let recovery = root.appendingPathComponent("Recovery")
        let evidence = JournalFDReuseEvidence()
        let sentinel = open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(sentinel, 0)
        defer { Darwin.close(sentinel); evidence.closeOwnedDuplicates() }
        var rejected = false
        do {
            _ = try SecurityJournal(parent: root, beforeFinalValidation: {
                // The journal's []/decoded result is complete; now make the real
                // final descriptor ACL validation fail, not a synthetic throw.
                let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
                process.arguments = ["+a", "everyone allow read,write,delete", recovery.path]
                process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
                try process.run(); process.waitUntilExit()
                guard process.terminationStatus == 0 else { throw SecurityUIFailure.journal }
                evidence.noteACLInjected()
            }, afterInitializationFailureCleanup: { parentFD, recoveryFD in
                // F_DUPFD_CLOEXEC never overwrites another owner's descriptor.
                // Exact equality proves these two just-freed slots were reused.
                evidence.reuseJustClosed(parentFD, recoveryFD, from: sentinel)
            })
        } catch { rejected = true }
        let snapshot = evidence.snapshot()
        let reusedStillOpen = snapshot.duplicates.map { fcntl($0, F_GETFD) >= 0 }
        XCTAssertTrue(rejected)
        XCTAssertTrue(snapshot.injected)
        XCTAssertTrue(snapshot.originalsWereClosed)
        XCTAssertEqual(snapshot.duplicates, snapshot.targets)
        XCTAssertEqual(reusedStillOpen, [true, true])
    }
    func testCoordinatorRechecksRuntimeJournalACLWithoutDeletingExternalItem() async throws {
        let root = try directory(); let repository = AppRepository(location: .isolated(root)); let credentials = FakeCredentials()
        let coordinator = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        _ = try await coordinator.overview()
        let journal = try SecurityJournal(parent: root)
        try journal.set(.init(id: UUID(), kind: .password, state: .prepared))
        try addACL(root.appendingPathComponent("Recovery/security-intents.json"))
        await expectFailure { _ = try await coordinator.overview() }
        await expectFailure { try await coordinator.retryCleanup() }
        let deletes = await credentials.deleteCount
        XCTAssertEqual(deletes, 0)
        try await coordinator.close(); try await repository.close()
    }
}

/// Synchronous fault hooks cross a Sendable boundary; only this test's FD numbers
/// and booleans are stored. Never dup2/overwrite another thread's file descriptor.
private final class JournalFDReuseEvidence: @unchecked Sendable {
    private let lock = NSLock()
    private var injected = false
    private var originalsWereClosed = false
    private var targets: [Int32] = []
    private var duplicates: [Int32] = []
    func noteACLInjected() { lock.lock(); defer { lock.unlock() }; injected = true }
    func reuseJustClosed(_ parent: Int32, _ recovery: Int32, from sentinel: Int32) {
        lock.lock(); defer { lock.unlock() }
        targets = [parent, recovery].sorted()
        originalsWereClosed = targets.allSatisfy { fcntl($0, F_GETFD) == -1 && errno == EBADF }
        guard originalsWereClosed else { return }
        for target in targets { duplicates.append(fcntl(sentinel, F_DUPFD_CLOEXEC, target)) }
    }
    func snapshot() -> (injected: Bool, originalsWereClosed: Bool, targets: [Int32], duplicates: [Int32]) {
        lock.lock(); defer { lock.unlock() }
        return (injected, originalsWereClosed, targets, duplicates)
    }
    func closeOwnedDuplicates() {
        lock.lock(); defer { lock.unlock() }
        for descriptor in duplicates where descriptor >= 0 { Darwin.close(descriptor) }
        duplicates = []
    }
}
