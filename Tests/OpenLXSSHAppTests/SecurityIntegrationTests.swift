import AppKit
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHSecurity

@MainActor final class SecurityIntegrationTests: XCTestCase {
    private func fixture() throws -> (URL, AppRepository, FakeCredentials, SecurityCoordinator) {
        let directory = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let repo = AppRepository(location: .isolated(directory))
        let credentials = FakeCredentials()
        return (directory, repo, credentials, SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials))
    }
    private func host() -> HostConfiguration { HostConfiguration(name: "security", address: "security.invalid", username: "fixture") }
    private func expectFailure(_ body: () async throws -> Void) async {
        do { try await body(); XCTFail("Expected failure") } catch {}
    }

    func testGenerateEncryptedAndUnencryptedPublicCopyAndRestart() async throws {
        let (directory, repo, credentials, coordinator) = try fixture()
        let viewModel = SecurityViewModel(coordinator: coordinator)
        let plain = await viewModel.create(.generate, protection: .unencrypted, remember: nil)
        checkTrue(plain)
        let secret = try SecretBytes.random()
        // Binary random bytes need not satisfy a line-based key passphrase; use a random UUID.
        _ = secret
        let phrase = SecretBytes(utf8: UUID().uuidString)
        let encrypted = await viewModel.create(.generate, protection: .passphrase(phrase), remember: phrase)
        checkTrue(encrypted)
        checkEqual(viewModel.metadata.keys.count, 2)
        let protected = try XCTUnwrap(viewModel.metadata.keys.first { $0.passphraseCredentialRef != nil })
        checkTrue(viewModel.copyPublicKey(protected.id))
        checkEqual(NSPasteboard.general.string(forType: .string), viewModel.publicKeys[protected.id])
        checkTrue(viewModel.publicKeys.values.allSatisfy { $0.hasPrefix("ssh-ed25519 ") && !$0.contains("PRIVATE") })
        let snapshot = try await repo.securityMetadata()
        checkEqual(snapshot.credentials.first?.purpose, .privateKeyPassphrase)
        let stored = await credentials.read(.init(id: protected.passphraseCredentialRef!, kind: .privateKeyPassphrase))
        if case .available(let value) = stored { checkTrue(value.matches(phrase)) } else { XCTFail("Missing phrase") }
        try await coordinator.close(); try await repo.close()
        let reopened = AppRepository(location: .isolated(directory))
        let next = SecurityCoordinator(repository: reopened, location: .isolated(directory), credentials: credentials)
        let overview = try await next.overview()
        checkEqual(overview.metadata.keys.count, 2)
        let publicKey = try await next.publicKey(protected.id)
        checkEqual(publicKey.copyString, viewModel.publicKeys[protected.id])
        try await next.close(); try await reopened.close()
    }

    func testImportRSAAndEd25519CopiesWithoutChangingSource() async throws {
        let (directory, repo, _, coordinator) = try fixture()
        for algorithm in ["ed25519", "rsa"] {
            let source = directory.appendingPathComponent("source-" + algorithm)
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
            process.arguments = ["-q", "-t", algorithm, "-f", source.path, "-N", "", "-C", ""]
            process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit(); checkEqual(process.terminationStatus, 0)
            let before = try Data(contentsOf: source)
            let id = try await coordinator.createKey(.importFile(source), protection: .unencrypted, rememberPassphrase: nil).id
            checkEqual(try Data(contentsOf: source), before)
            let key = try await coordinator.publicKey(id)
            checkEqual(key.algorithm, algorithm == "rsa" ? .rsa : .ed25519)
            try await coordinator.deleteKey(id)
            checkEqual(try Data(contentsOf: source), before)
        }
        try await coordinator.close(); try await repo.close()
    }

    func testEncryptedImportWrongPassphraseRetriesAndCancelsWithoutMetadata() async throws {
        let (directory, repo, _, coordinator) = try fixture()
        let sourceStore = try KeyStore(directory: directory.appendingPathComponent("SourceKeys"))
        let phrase = SecretBytes(utf8: UUID().uuidString)
        let sourceKey = try await sourceStore.generateEd25519(protection: .passphrase(phrase))
        let source = directory.appendingPathComponent("SourceKeys").appendingPathComponent(sourceKey.id.uuidString + ".openssh")
        let before = try Data(contentsOf: source)
        await expectFailure { _ = try await coordinator.createKey(.importFile(source), protection: .passphrase(.init(utf8: "wrong-temporary-input")), rememberPassphrase: nil) }
        checkTrue(try await repo.securityMetadata().keys.isEmpty)
        let imported = try await coordinator.createKey(.importFile(source), protection: .passphrase(phrase), rememberPassphrase: nil).id
        checkEqual(try await coordinator.publicKey(imported), sourceKey.publicKey)
        checkEqual(try Data(contentsOf: source), before)
        let cancelled = Task { _ = try await coordinator.createKey(.generate, protection: .unencrypted, rememberPassphrase: nil) }
        cancelled.cancel()
        do { try await cancelled.value; XCTFail("Expected cancellation") } catch {}
        checkEqual(try await repo.securityMetadata().keys.count, 1)
        try await sourceStore.close(); try await coordinator.close(); try await repo.close()
    }

    func testSharedKeyDeletionRejectedUntilAllHostsUnlinked() async throws {
        let (_, repo, _, coordinator) = try fixture()
        let key = try await coordinator.createKey(.generate, protection: .unencrypted, rememberPassphrase: nil).id
        var original = host(); original.authentication = .privateKey; original.keyRef = key
        try await coordinator.saveHost(original, isNew: true, password: .manual)
        let copied = try await repo.copyHost(id: original.id)
        await expectFailure { try await coordinator.deleteKey(key) }
        checkNotNil(try await coordinator.publicKey(key))
        try await repo.apply([.deleteHost(original.id)])
        await expectFailure { try await coordinator.deleteKey(key) }
        try await repo.apply([.deleteHost(copied.id)])
        try await coordinator.deleteKey(key)
        checkTrue(try await repo.securityMetadata().keys.isEmpty)
        checkTrue(try await repo.securityMetadata().tickets.isEmpty)
        try await coordinator.close(); try await repo.close()
    }

    func testRememberFalseWritesNoCredentialAndTrueCommitsOnlyAfterSave() async throws {
        let (_, repo, credentials, coordinator) = try fixture()
        var original = host()
        try await coordinator.saveHost(original, isNew: true, password: .manual)
        checkEqual(await credentials.saveCount, 0)
        checkTrue(try await repo.securityMetadata().credentials.isEmpty)
        let phrase = SecretBytes(utf8: UUID().uuidString)
        try await coordinator.saveHost(original, isNew: false, password: .remember(phrase))
        var metadata = try await repo.securityMetadata()
        original = try XCTUnwrap(metadata.hosts.first)
        checkTrue(original.savePasswordAuthorized)
        checkNotNil(original.credentialRef)
        let copied = try await repo.copyHost(id: original.id)
        try await coordinator.forgetHostPassword(original.id)
        metadata = try await repo.securityMetadata()
        checkNil(metadata.hosts.first { $0.id == original.id }?.credentialRef)
        checkEqual(metadata.hosts.first { $0.id == copied.id }?.credentialRef, original.credentialRef)
        checkEqual(metadata.credentials.count, 1)
        try await coordinator.forgetHostPassword(copied.id)
        checkTrue(try await repo.securityMetadata().credentials.isEmpty)
        checkEqual(await credentials.count, 0)
        try await coordinator.close(); try await repo.close()
    }

    func testKeychainFailureDoesNotWriteAuthorizationAndAllowsManualFallback() async throws {
        let (_, repo, credentials, coordinator) = try fixture()
        await credentials.setSaveFailure(.interactionNotAllowed)
        let model = AppModel(repository: repo, security: coordinator)
        let original = host()
        let saved = await model.saveHostSecurely(original, isNew: true, password: .remember(.init(utf8: UUID().uuidString)))
        checkFalse(saved)
        checkEqual(model.issue?.code, "keychain.lockedOrDenied")
        checkTrue(try await repo.securityMetadata().hosts.isEmpty)
        checkTrue(try await repo.securityMetadata().credentials.isEmpty)
        checkEqual(await credentials.count, 0)
        let fallback = await model.saveHostSecurely(original, isNew: true, password: .manual)
        checkTrue(fallback)
        checkFalse(model.hosts[0].savePasswordAuthorized)
        checkNil(model.hosts[0].credentialRef)
        try await coordinator.close(); try await repo.close()
    }

    func testCoreFailureCompensatesOnlyNewCredential() async throws {
        let (directory, repo, credentials, _) = try fixture()
        let failing = FailingCommitRepository(base: repo)
        let coordinator = SecurityCoordinator(repository: failing, location: .isolated(directory), credentials: credentials)
        let unrelated = OpenLXSSHSecurity.CredentialReference(kind: .password)
        _ = await credentials.save(.init(utf8: UUID().uuidString), as: unrelated, authorization: .granted)
        await expectFailure { try await coordinator.saveHost(self.host(), isNew: true, password: .remember(.init(utf8: UUID().uuidString))) }
        checkEqual(await credentials.count, 1)
        if case .available = await credentials.read(unrelated) {} else { XCTFail("Unrelated item was removed") }
        checkTrue(try await repo.securityMetadata().credentials.isEmpty)
        checkTrue(try await repo.securityMetadata().tickets.isEmpty)
        try await coordinator.close(); try await repo.close()
    }

    func testCompensationFailurePersistsExactTicketAndRetriesAfterRestart() async throws {
        let (directory, repo, credentials, _) = try fixture()
        let failing = FailingCommitRepository(base: repo)
        let coordinator = SecurityCoordinator(repository: failing, location: .isolated(directory), credentials: credentials)
        await credentials.setDeleteFailure(.denied)
        await expectFailure { try await coordinator.saveHost(self.host(), isNew: true, password: .remember(.init(utf8: UUID().uuidString))) }
        var metadata = try await repo.securityMetadata()
        checkEqual(metadata.tickets.count, 1)
        checkEqual(await credentials.count, 1)
        try await coordinator.retryCleanup()
        metadata = try await repo.securityMetadata()
        checkEqual(metadata.tickets.first?.attemptCount, 1)
        checkEqual(metadata.tickets.first?.lastFailure, .permissionDenied)
        try await coordinator.close()
        await credentials.setDeleteFailure(nil)
        let next = SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials)
        try await next.retryCleanup()
        checkTrue(try await repo.securityMetadata().tickets.isEmpty)
        checkEqual(await credentials.count, 0)
        checkEqual(try await next.overview().pendingCount, 0)
        try await next.close(); try await repo.close()
    }

    func testKeyRegistrationRollbackRemovesOnlyNewKeyAndPassphrase() async throws {
        let (directory, repo, credentials, _) = try fixture()
        let coordinator = SecurityCoordinator(repository: FailingCommitRepository(base: repo), location: .isolated(directory), credentials: credentials)
        let phrase = SecretBytes(utf8: UUID().uuidString)
        await expectFailure { _ = try await coordinator.createKey(.generate, protection: .passphrase(phrase), rememberPassphrase: phrase) }
        checkTrue(try await repo.securityMetadata().keys.isEmpty)
        checkTrue(try await repo.securityMetadata().credentials.isEmpty)
        checkEqual(await credentials.count, 0)
        let files = try FileManager.default.contentsOfDirectory(atPath: directory.appendingPathComponent("Keys").path)
        checkEqual(files, [".OpenLXSSH.lock"])
        try await coordinator.close(); try await repo.close()
    }

    func testRememberedPassphraseMismatchRejectedBeforeCreatingKey() async throws {
        let (_, repo, credentials, coordinator) = try fixture()
        await expectFailure { _ = try await coordinator.createKey(.generate, protection: .passphrase(.init(utf8: UUID().uuidString)), rememberPassphrase: .init(utf8: UUID().uuidString)) }
        checkTrue(try await repo.securityMetadata().keys.isEmpty)
        checkEqual(await credentials.saveCount, 0)
        try await coordinator.close(); try await repo.close()
    }

    func testCommittedForgetReturnsCleanupWarningWithoutReinsertingHost() async throws {
        let (_, repo, credentials, coordinator) = try fixture()
        let original = host()
        try await coordinator.saveHost(original, isNew: true, password: .remember(.init(utf8: UUID().uuidString)))
        await credentials.setDeleteFailure(.denied)
        let model = AppModel(repository: repo, security: coordinator)
        _ = await model.reload()
        let saved = await model.saveHostSecurely(model.hosts[0], isNew: false, password: .forget)
        checkTrue(saved)
        checkEqual(model.issue?.code, "security.cleanupPending")
        checkEqual(model.hosts.count, 1)
        checkNil(model.hosts[0].credentialRef)
        checkEqual(try await repo.securityMetadata().tickets.count, 1)
        await credentials.setDeleteFailure(nil)
        try await coordinator.retryCleanup()
        checkEqual(await credentials.count, 0)
        try await coordinator.close(); try await repo.close()
    }

    func testRecoveryJournalRejectsTraversalAndSymlinkWithoutChangingOtherFile() throws {
        let (directory, _, _, _) = try fixture()
        let journal = try SecurityJournal(parent: directory)
        var entry = SecurityIntent(id: UUID(), kind: .privateKey, state: .created)
        entry.pendingName = "../unrelated"
        XCTAssertThrowsError(try journal.set(entry))
        let unrelated = directory.appendingPathComponent("unrelated")
        try Data("unchanged".utf8).write(to: unrelated)
        try FileManager.default.createSymbolicLink(at: directory.appendingPathComponent("Recovery/security-intents.json"), withDestinationURL: unrelated)
        XCTAssertThrowsError(try SecurityJournal(parent: directory))
        checkEqual(try String(contentsOf: unrelated, encoding: .utf8), "unchanged")
    }

    func testForgetSharedKeyPassphraseKeepsFilesAndRetriesLastCredentialAfterRestart() async throws {
        let (directory, repo, credentials, coordinator) = try fixture()
        let phrase = SecretBytes(utf8: UUID().uuidString)
        let first = try await coordinator.createKey(.generate, protection: .passphrase(phrase), rememberPassphrase: phrase).id
        let second = try await coordinator.createKey(.generate, protection: .passphrase(phrase), rememberPassphrase: nil).id
        let initial = try await repo.securityMetadata()
        let ref = try XCTUnwrap(initial.keys.first { $0.id == first }?.passphraseCredentialRef)
        try await repo.apply([.updateKeyPassphrase(keyID: second, credentialRef: ref)])
        let files = [first, second].map { directory.appendingPathComponent("Keys/" + $0.uuidString + ".openssh") }
        let before = try files.map { try Data(contentsOf: $0) }
        let model = SecurityViewModel(coordinator: coordinator)
        checkTrue(await model.forgetKeyPassphrase(first))
        var metadata = try await repo.securityMetadata()
        checkNil(metadata.keys.first { $0.id == first }?.passphraseCredentialRef)
        checkEqual(metadata.keys.first { $0.id == second }?.passphraseCredentialRef, ref)
        checkEqual(metadata.credentials.map(\.id), [ref])
        checkEqual(await credentials.count, 1)
        checkTrue(metadata.tickets.isEmpty)
        checkEqual(try files.map { try Data(contentsOf: $0) }, before)
        await credentials.setDeleteFailure(.denied)
        checkTrue(await model.forgetKeyPassphrase(second))
        checkEqual(model.issue?.code, "security.cleanupPending")
        metadata = try await repo.securityMetadata()
        checkTrue(metadata.keys.allSatisfy { $0.passphraseCredentialRef == nil })
        checkTrue(metadata.credentials.isEmpty)
        checkEqual(metadata.tickets.first?.resourceID, ref)
        checkEqual(metadata.tickets.first?.lastFailure, .permissionDenied)
        checkEqual(await credentials.count, 1)
        try await coordinator.close(); try await repo.close()
        await credentials.setDeleteFailure(nil)
        let reopened = AppRepository(location: .isolated(directory))
        let next = SecurityCoordinator(repository: reopened, location: .isolated(directory), credentials: credentials)
        try await next.retryCleanup()
        checkTrue(try await reopened.securityMetadata().tickets.isEmpty)
        checkEqual(await credentials.count, 0)
        checkEqual(try files.map { try Data(contentsOf: $0) }, before)
        checkEqual(try await reopened.securityMetadata().keys.count, 2)
        try await next.close(); try await reopened.close()
    }

    func testPreparedRecordDiscardIsMetadataOnlyAndSurvivesRestart() async throws {
        let (directory, repo, credentials, _) = try fixture()
        let entry = SecurityIntent(id: UUID(), kind: .password, state: .prepared)
        do { let journal = try SecurityJournal(parent: directory); try journal.set(entry) }
        let ref = OpenLXSSHSecurity.CredentialReference(id: entry.id, kind: .password)
        _ = await credentials.save(.init(utf8: UUID().uuidString), as: ref, authorization: .granted)
        let file = directory.appendingPathComponent("unrelated")
        try Data("unchanged".utf8).write(to: file)
        let coordinator = SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials)
        let model = SecurityViewModel(coordinator: coordinator)
        await model.load()
        let review = try XCTUnwrap(model.recoveryReviews.first)
        checkEqual(review.intent, entry)
        checkTrue(review.canDiscard)
        checkTrue(await model.discardPrepared(review))
        checkTrue(model.recoveryReviews.isEmpty)
        checkEqual(await credentials.count, 1)
        checkEqual(await credentials.readCount, 0)
        checkEqual(await credentials.deleteCount, 0)
        checkEqual(try Data(contentsOf: file), Data("unchanged".utf8))
        checkTrue(try await repo.securityMetadata().tickets.isEmpty)
        try await coordinator.close(); try await repo.close()
        let reopened = AppRepository(location: .isolated(directory))
        let next = SecurityCoordinator(repository: reopened, location: .isolated(directory), credentials: credentials)
        checkTrue(try await next.overview().recoveryReviews.isEmpty)
        try await next.close(); try await reopened.close()
    }

    func testPreparedDiscardRejectsCoreReferencesTicketsAndNonPreparedStates() async throws {
        let (directory, repo, credentials, _) = try fixture()
        let registered = SecurityIntent(id: UUID(), kind: .password, state: .prepared)
        let ticketed = SecurityIntent(id: UUID(), kind: .privateKey, state: .prepared)
        let completed = SecurityIntent(id: UUID(), kind: .privateKey, state: .prepared)
        let created = SecurityIntent(id: UUID(), kind: .password, state: .created)
        let deleting = SecurityIntent(id: UUID(), kind: .privateKey, state: .deleting)
        do {
            let journal = try SecurityJournal(parent: directory)
            for entry in [registered, ticketed, completed, created, deleting] { try journal.set(entry) }
        }
        try await repo.apply([.registerCredential(.init(id: registered.id, purpose: .password, isSavingAuthorized: true)),
                              .scheduleOrphanCleanup(.init(kind: .privateKey, id: ticketed.id)),
                              .scheduleOrphanCleanup(.init(kind: .privateKey, id: completed.id))])
        let pending = try await repo.securityMetadata().tickets
        let completedTicket = try XCTUnwrap(pending.first { $0.resourceID == completed.id })
        try await repo.completeCleanup(completedTicket.id)
        let coordinator = SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials)
        let reviews = try await coordinator.overview().recoveryReviews
        checkEqual(reviews.count, 5)
        for review in reviews {
            checkFalse(review.canDiscard)
            await expectFailure { try await coordinator.discardPreparedRecord(review) }
        }
        checkEqual(try await coordinator.overview().recoveryReviews, reviews)
        checkEqual(await credentials.readCount, 0)
        checkEqual(await credentials.deleteCount, 0)
        try await coordinator.close(); try await repo.close()
    }

    func testPreparedReviewExpiresAfterReopenOrCoreReferenceChange() async throws {
        let (directory, repo, credentials, _) = try fixture()
        let entry = SecurityIntent(id: UUID(), kind: .password, state: .prepared)
        do { let journal = try SecurityJournal(parent: directory); try journal.set(entry) }
        let coordinator = SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials)
        let oldOverview = try await coordinator.overview()
        let old = try XCTUnwrap(oldOverview.recoveryReviews.first)
        try await coordinator.close()
        let next = SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials)
        await expectFailure { try await next.discardPreparedRecord(old) }
        let currentOverview = try await next.overview()
        let current = try XCTUnwrap(currentOverview.recoveryReviews.first)
        try await repo.apply([.registerCredential(.init(id: entry.id, purpose: .password, isSavingAuthorized: true))])
        await expectFailure { try await next.discardPreparedRecord(current) }
        checkEqual(try await next.overview().recoveryReviews.count, 1)
        try await next.close(); try await repo.close()
    }

    func testJournalDiscardBindsContentAndGenerationIncludingABA() throws {
        let (directory, _, _, _) = try fixture()
        let journal = try SecurityJournal(parent: directory)
        let entry = SecurityIntent(id: UUID(), kind: .password, state: .prepared)
        try journal.set(entry)
        let first = try XCTUnwrap(try journal.revision(for: entry.id))
        var changed = entry; changed.state = .created
        try journal.set(changed)
        XCTAssertThrowsError(try journal.discardPrepared(entry, revision: first))
        try journal.set(entry) // same content restored, but a different generation
        XCTAssertThrowsError(try journal.discardPrepared(entry, revision: first))
        let current = try XCTUnwrap(try journal.revision(for: entry.id))
        try journal.discardPrepared(entry, revision: current)
        checkTrue(try journal.all().isEmpty)
    }

    func testKeyCommittedWithJournalFailureIsSuccessfulAndRecoversWithoutCompensation() async throws {
        let (directory, repo, credentials, _) = try fixture()
        let failure = JournalFailureSwitch()
        let wrapped = AfterKeyCommitRepository(base: repo, failure: failure)
        let coordinator = SecurityCoordinator(repository: wrapped, location: .isolated(directory), credentials: credentials,
                                              journalWriteCheck: { try failure.check() })
        let phrase = SecretBytes(utf8: UUID().uuidString)
        let model = SecurityViewModel(coordinator: coordinator)
        checkTrue(await model.create(.generate, protection: .passphrase(phrase), remember: phrase))
        let result = try XCTUnwrap(model.lastCreatedKey)
        checkTrue(result.cleanupPending)
        checkEqual(model.issue?.code, "security.keyCommittedCleanupPending")
        checkEqual(try await repo.securityMetadata().keys.map(\.id), [result.id])
        checkEqual(try await repo.securityMetadata().credentials.count, 1)
        checkEqual(await credentials.count, 1)
        checkEqual(await credentials.deleteCount, 0)
        checkTrue(try await repo.securityMetadata().tickets.isEmpty)
        let file = directory.appendingPathComponent("Keys/" + result.id.uuidString + ".openssh")
        let before = try Data(contentsOf: file)
        checkEqual(try await coordinator.overview().pendingCount, 2)
        checkTrue(failure.rejectedWrites > 0)
        try await coordinator.close(); try await repo.close()
        let reopened = AppRepository(location: .isolated(directory))
        let next = SecurityCoordinator(repository: reopened, location: .isolated(directory), credentials: credentials)
        try await next.retryCleanup()
        checkEqual(try await next.overview().pendingCount, 0)
        checkEqual(try await reopened.securityMetadata().keys.map(\.id), [result.id])
        checkEqual(try await reopened.securityMetadata().credentials.count, 1)
        checkEqual(try Data(contentsOf: file), before)
        checkEqual(await credentials.deleteCount, 0)
        try await next.close(); try await reopened.close()
    }

    func testPreparedIntentNeverDeletesUnprovenExternalOwnership() async throws {
        let (directory, repo, credentials, _) = try fixture()
        _ = try AppDataLocation.isolated(directory).databaseDirectory()
        let id = UUID()
        do { let journal = try SecurityJournal(parent: directory); try journal.set(.init(id: id, kind: .password, state: .prepared)) }
        let ref = OpenLXSSHSecurity.CredentialReference(id: id, kind: .password)
        _ = await credentials.save(.init(utf8: UUID().uuidString), as: ref, authorization: .granted)
        let coordinator = SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials)
        try await coordinator.retryCleanup()
        checkEqual(await credentials.count, 1)
        checkEqual(try await coordinator.overview().uncertainCount, 1)
        // An unknown prepared intent does not block independent normal operations.
        try await coordinator.saveHost(host(), isNew: true, password: .manual)
        let key = try await coordinator.createKey(.generate, protection: .unencrypted, rememberPassphrase: nil).id
        checkEqual(try await repo.securityMetadata().hosts.count, 1)
        checkEqual(try await repo.securityMetadata().keys.map(\.id), [key])
        checkEqual(try await coordinator.overview().recoveryReviews.map(\.id), [id])
        checkEqual(await credentials.readCount, 0)
        checkEqual(await credentials.deleteCount, 0)
        try await coordinator.close(); try await repo.close()
    }
}

actor FakeCredentials: CredentialAccess {
    private var values: [OpenLXSSHSecurity.CredentialReference: SecretBytes] = [:]
    private var saveFailure: CredentialFailure?
    private var deleteFailure: CredentialFailure?
    private(set) var saveCount = 0
    private(set) var readCount = 0
    private(set) var deleteCount = 0
    var count: Int { values.count }
    func setSaveFailure(_ failure: CredentialFailure?) { saveFailure = failure }
    func setDeleteFailure(_ failure: CredentialFailure?) { deleteFailure = failure }
    func save(_ secret: SecretBytes, as reference: OpenLXSSHSecurity.CredentialReference, authorization: RememberAuthorization) -> CredentialSaveResult {
        saveCount += 1
        guard authorization == .granted else { return .notAuthorized }
        if let saveFailure { return .failed(saveFailure) }
        guard values[reference] == nil else { return .failed(.duplicate) }
        values[reference] = secret; return .saved(reference)
    }
    func read(_ reference: OpenLXSSHSecurity.CredentialReference) -> CredentialReadResult {
        readCount += 1
        return values[reference].map { .available($0) } ?? .missing
    }
    func deleteExact(_ reference: OpenLXSSHSecurity.CredentialReference) -> CredentialDeleteResult {
        deleteCount += 1
        if let deleteFailure { return .retryRequired(deleteFailure) }
        return values.removeValue(forKey: reference) == nil ? .alreadyAbsent : .deleted
    }
    func close() {}
}

private actor FailingCommitRepository: AppRepositoryProtocol {
    let base: AppRepository
    init(base: AppRepository) { self.base = base }
    func snapshot(query: HostQuery) async throws -> AppSnapshot { try await base.snapshot(query: query) }
    func apply(_ changes: [RepositoryChange]) async throws {
        if changes.contains(where: { change in
            switch change { case .insertHost, .registerKey: true; default: false }
        }) { throw RepositoryError.databaseBusy }
        try await base.apply(changes)
    }
    func securityMetadata() async throws -> SecurityMetadata { try await base.securityMetadata() }
    func completeCleanup(_ id: UUID) async throws { try await base.completeCleanup(id) }
    func recordCleanupFailure(_ id: UUID, failure: CleanupFailure) async throws { try await base.recordCleanupFailure(id, failure: failure) }
    func copyHost(id: UUID) async throws -> HostConfiguration { try await base.copyHost(id: id) }
    func copyFolder(id: UUID) async throws -> HostFolder { try await base.copyFolder(id: id) }
    func close() async throws { try await base.close() }
}

private final class JournalFailureSwitch: @unchecked Sendable {
    private let lock = NSLock()
    private var failing = false
    private var rejected = 0
    var rejectedWrites: Int { lock.lock(); defer { lock.unlock() }; return rejected }
    func arm() { lock.lock(); defer { lock.unlock() }; failing = true }
    func check() throws {
        lock.lock(); defer { lock.unlock() }
        if failing { rejected += 1; throw SecurityUIFailure.journal }
    }
}

private actor AfterKeyCommitRepository: AppRepositoryProtocol {
    let base: AppRepository
    let failure: JournalFailureSwitch
    init(base: AppRepository, failure: JournalFailureSwitch) { self.base = base; self.failure = failure }
    func snapshot(query: HostQuery) async throws -> AppSnapshot { try await base.snapshot(query: query) }
    func apply(_ changes: [RepositoryChange]) async throws {
        try await base.apply(changes)
        if changes.contains(where: { if case .registerKey = $0 { return true }; return false }) { failure.arm() }
    }
    func securityMetadata() async throws -> SecurityMetadata { try await base.securityMetadata() }
    func completeCleanup(_ id: UUID) async throws { try await base.completeCleanup(id) }
    func recordCleanupFailure(_ id: UUID, failure: CleanupFailure) async throws { try await base.recordCleanupFailure(id, failure: failure) }
    func copyHost(id: UUID) async throws -> HostConfiguration { try await base.copyHost(id: id) }
    func copyFolder(id: UUID) async throws -> HostFolder { try await base.copyFolder(id: id) }
    func close() async throws { try await base.close() }
}

private func checkEqual<T: Equatable>(_ a: T, _ b: T, file: StaticString = #filePath, line: UInt = #line) { XCTAssertEqual(a, b, file: file, line: line) }
private func checkTrue(_ a: Bool, file: StaticString = #filePath, line: UInt = #line) { XCTAssertTrue(a, file: file, line: line) }
private func checkFalse(_ a: Bool, file: StaticString = #filePath, line: UInt = #line) { XCTAssertFalse(a, file: file, line: line) }
private func checkNotNil<T>(_ a: T?, file: StaticString = #filePath, line: UInt = #line) { XCTAssertNotNil(a, file: file, line: line) }
private func checkNil<T>(_ a: T?, file: StaticString = #filePath, line: UInt = #line) { XCTAssertNil(a, file: file, line: line) }
