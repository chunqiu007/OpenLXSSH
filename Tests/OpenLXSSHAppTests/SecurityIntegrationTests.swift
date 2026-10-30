import AppKit
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHSecurity
import OpenLXSSHTrust

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
        let pasteboard = NSPasteboard.withUniqueName()
        defer { pasteboard.releaseGlobally() }
        checkTrue(viewModel.copyPublicKey(protected.id, to: pasteboard))
        checkEqual(pasteboard.string(forType: .string), viewModel.publicKeys[protected.id])
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

@MainActor final class TrustManagementRegressionTests: XCTestCase {
    private let edLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg"
    private let changedLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C"
    private let rsaLine = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtEucvt1w5resIpf/BvuuR1zddYXDeUVM0LOZt8mis3XGozl6xpF3V3jkVOfXM1oaq0faq2MKnzxCZx4GmlofE4qdcMqa4cbL7QTNvO/Z6ACTTb92kpNp9DS/4BSLsIebvMM0UVWivxmj3Mq3REqIThBXQVwqkhmWj6bzfSKqsstCjjRmRuzi/IDCUL8lIbJGzpYek4/cp5VhUyB2kIYqz/Fpg5+eJTa2x/7qYEKNKg4dXebuExQYe3Z47D8o1i9pDXWpYw/KlBn8LA/K89h7BkEsdY4ePPGroTS+lepAKqItDWwMm4wf6gDJSoNbCt6T+L5U7gjpbA3kEZd89PxvJ"

    private func fixture() async throws -> (URL, HostTrustStore, KeyTrustTestStore, TrustManagementModel) {
        let directory = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let store = try await Task.detached { try HostTrustStore(directory: AbsolutePath(directory.path)) }.value
        let wrapper = KeyTrustTestStore(store: store)
        return (directory, store, wrapper, TrustManagementModel(store: wrapper))
    }
    private func key(_ line: String) async throws -> HostPublicKey {
        try await Task.detached { try HostPublicKey(openSSHPublicKey: line) }.value
    }
    private func host(_ address: String = "trust-management.invalid", port: Int = 22) throws -> HostIdentity {
        HostIdentity(address: try HostAddress(address), port: try SSHPort(port))
    }
    private func accept(_ store: HostTrustStore, host: HostIdentity, key: HostPublicKey, once: Bool = false) async throws -> TrustedHostKey {
        guard case .pending(let decision) = try await store.evaluate(host: host, key: key) else {
            XCTFail("Expected a fresh exact decision"); throw HostTrustError.noChangedKey
        }
        if once { return try await store.confirmOnce(decision, displayedFingerprint: decision.fingerprint) }
        return try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
    }

    func testRemovalUsesExactRecordAndPreservesOtherAlgorithmsPortsAndEndpoints() async throws {
        let (_, store, wrapper, model) = try await fixture()
        let ed = try await key(edLine), rsa = try await key(rsaLine)
        let target = try await accept(store, host: host(), key: ed)
        let algorithm = try await accept(store, host: host(), key: rsa)
        let port = try await accept(store, host: host(port: 2222), key: ed)
        let endpoint = try await accept(store, host: host("other.invalid"), key: ed)
        await model.load()
        checkTrue(model.reviewRemoval(target))
        let review = try XCTUnwrap(model.removalReview)
        checkEqual(review.record, target)
        checkEqual(review.record.key.blob, ed.blob)
        checkTrue(await model.remove(review))
        checkEqual(await wrapper.removeCount, 1)
        checkEqual(Set(try await store.records()), Set([algorithm, port, endpoint]))
        checkEqual(Set(model.records), Set([algorithm, port, endpoint]))
        checkNotNil(model.notice)
        guard case .pending(let next) = try await store.evaluate(host: target.host, key: target.key) else {
            return XCTFail("Removed key must need confirmation again")
        }
        checkEqual(next.reason, .additionalAlgorithm)
        await store.cancel(next)
    }

    func testWrongRecordCancelledAndSupersededReviewsMakeNoWrite() async throws {
        let (directory, store, wrapper, model) = try await fixture()
        let ed = try await key(edLine), changed = try await key(changedLine), rsa = try await key(rsaLine)
        let wrongBlob = try await accept(store, host: host(), key: changed, once: true)
        let target = try await accept(store, host: host(), key: ed)
        let wrongAlgorithm = try await accept(store, host: host(), key: rsa, once: true)
        let unlisted = try await accept(store, host: host("not-persisted.invalid"), key: ed, once: true)
        await model.load()
        let before = try Data(contentsOf: directory.appendingPathComponent("known_hosts"))
        checkFalse(model.reviewRemoval(unlisted))
        checkFalse(model.reviewRemoval(wrongBlob))
        checkFalse(model.reviewRemoval(wrongAlgorithm))
        checkNil(model.removalReview)
        checkTrue(model.reviewRemoval(target))
        let cancelled = try XCTUnwrap(model.removalReview)
        model.cancelReview()
        checkFalse(await model.remove(cancelled))
        checkTrue(model.reviewRemoval(target))
        let current = try XCTUnwrap(model.removalReview)
        checkFalse(await model.remove(cancelled))
        checkEqual(model.removalReview, current)
        checkEqual(await wrapper.removeCount, 0)
        checkEqual(try Data(contentsOf: directory.appendingPathComponent("known_hosts")), before)
        checkEqual(try await store.records(), [target])
    }

    func testRemovalRejectsIndependentReplacementRatherThanDeletingNewRecord() async throws {
        let (directory, store, wrapper, model) = try await fixture()
        let ed = try await key(edLine), changed = try await key(changedLine)
        let target = try await accept(store, host: host(), key: ed)
        await model.load(); checkTrue(model.reviewRemoval(target))
        let review = try XCTUnwrap(model.removalReview)
        let other = try await Task.detached { try HostTrustStore(directory: AbsolutePath(directory.path)) }.value
        let decision = try await other.prepareReplacement(host: target.host, key: changed, expectedCurrentFingerprint: ed.fingerprint)
        let replacement = try await other.confirm(decision, displayedFingerprint: decision.fingerprint)
        checkFalse(await model.remove(review))
        checkEqual(await wrapper.removeCount, 1)
        checkEqual(model.issue?.code, "trust.removalRejected")
        checkEqual(try await store.records(), [replacement])
        checkEqual(model.records, [replacement])
    }

    func testConcurrentRemovalAndIndependentReplacementCannotBothSucceed() async throws {
        let (directory, store, _, model) = try await fixture()
        let ed = try await key(edLine), changed = try await key(changedLine)
        let target = try await accept(store, host: host(), key: ed)
        let other = try await Task.detached { try HostTrustStore(directory: AbsolutePath(directory.path)) }.value
        let decision = try await other.prepareReplacement(host: target.host, key: changed, expectedCurrentFingerprint: ed.fingerprint)
        await model.load(); checkTrue(model.reviewRemoval(target))
        let review = try XCTUnwrap(model.removalReview)
        async let removed = model.remove(review)
        let replacement = Task {
            do { _ = try await other.confirm(decision, displayedFingerprint: decision.fingerprint); return true }
            catch { return false }
        }
        let didRemove = await removed, didReplace = await replacement.value
        checkEqual([didRemove, didReplace].filter { $0 }.count, 1)
        let records = try await store.records()
        if didRemove { checkTrue(records.isEmpty) }
        else { checkEqual(records.count, 1); checkEqual(records.first?.key, changed) }
    }

    func testSearchReadFailurePreservesLastRecordsAndSuccessfulRetryRecovers() async throws {
        let (_, store, wrapper, model) = try await fixture()
        let ed = try await key(edLine), rsa = try await key(rsaLine)
        let first = try await accept(store, host: host(), key: ed)
        let second = try await accept(store, host: host("different.invalid", port: 2222), key: rsa)
        await model.load()
        model.search = "TRUST-MANAGEMENT.INVALID:22"; checkEqual(model.filteredRecords, [first])
        model.search = "SSH-RSA"; checkEqual(model.filteredRecords, [second])
        model.search = first.key.fingerprint; checkEqual(model.filteredRecords, [first])
        model.search = "no-such-record"; checkTrue(model.filteredRecords.isEmpty); checkEqual(model.records.count, 2)
        await wrapper.failRecords(true); await model.load()
        checkEqual(model.loadIssue?.code, "trust.readFailed")
        checkTrue(model.hasLoaded); checkEqual(Set(model.records), Set([first, second]))
        await wrapper.failRecords(false); await model.load()
        checkNil(model.loadIssue); model.search = ""; checkEqual(model.filteredRecords.count, 2)
    }

    func testInitialReadErrorIsNotSuccessfulEmptyStateAndRetryCanReadEmptyStore() async throws {
        let (_, _, wrapper, model) = try await fixture()
        await wrapper.failRecords(true); await model.load()
        checkFalse(model.hasLoaded); checkNotNil(model.loadIssue); checkTrue(model.records.isEmpty)
        await wrapper.failRecords(false); await model.load()
        checkTrue(model.hasLoaded); checkNil(model.loadIssue); checkTrue(model.records.isEmpty)
        checkFalse(model.loading)
    }

    func testDuplicateAndLateLoadsCannotOverwriteReopenedOwnerIncludingLateError() async throws {
        for failing in [false, true] {
            let (_, store, wrapper, model) = try await fixture()
            let ed = try await key(edLine)
            _ = try await accept(store, host: host(), key: ed)
            let gate = KeyTrustTestGate()
            await wrapper.failRecords(failing); await wrapper.pauseAfterNext(.records, on: gate)
            let old = Task { await model.load() }
            await gate.waitUntilEntered()
            checkTrue(model.loading)
            let duplicate = Task { await model.load() }
            checkEqual(await wrapper.readCount, 1)
            model.close(); model.open()
            let added = try await accept(store, host: host("new-owner.invalid"), key: ed)
            await wrapper.failRecords(false); await model.load()
            let fresh = model.records
            checkTrue(fresh.contains(added)); checkEqual(fresh.count, 2)
            await gate.release(); await old.value; await duplicate.value
            checkEqual(model.records, fresh); checkNil(model.loadIssue); checkFalse(model.loading)
            checkTrue(model.reviewRemoval(added))
        }
    }

    func testLatePrepareCancelsOnlyItsDecisionAndKeepsNewReviewAfterReopen() async throws {
        let (_, store, wrapper, model) = try await fixture()
        let ed = try await key(edLine)
        let first = try await accept(store, host: host(), key: ed)
        let second = try await accept(store, host: host("second.invalid"), key: ed)
        await model.load(); checkTrue(model.beginReplacement(first))
        let gate = KeyTrustTestGate(); await wrapper.pauseAfterNext(.prepare, on: gate)
        let line = changedLine
        let old = Task { await model.prepare(first, line: line) }
        await gate.waitUntilEntered()
        let preparedValue = await wrapper.lastPrepared
        let prepared = try XCTUnwrap(preparedValue)
        model.close(); model.open(); await model.load(); checkTrue(model.reviewRemoval(second))
        let current = model.removalReview
        await gate.release(); await old.value
        checkNil(model.pending); checkEqual(model.removalReview, current); checkFalse(model.busy)
        checkEqual(await wrapper.cancelledIDs, [prepared.id])
        do { _ = try await store.confirm(prepared, displayedFingerprint: prepared.fingerprint); XCTFail("Late decision was not cancelled") }
        catch { checkEqual(error as? HostTrustError, .expiredDecision) }
        checkEqual(Set(try await store.records()), Set([first, second]))
    }

    func testLateCommittedConfirmationDoesNotClearNewOwnerOrWriteSelection() async throws {
        let (_, store, wrapper, model) = try await fixture()
        let ed = try await key(edLine)
        let first = try await accept(store, host: host(), key: ed)
        let second = try await accept(store, host: host("second.invalid"), key: ed)
        await model.load(); checkTrue(model.beginReplacement(first)); await model.prepare(first, line: changedLine)
        let decision = try XCTUnwrap(model.pending)
        let gate = KeyTrustTestGate(); await wrapper.pauseAfterNext(.confirm, on: gate)
        let old = Task { await model.confirm(decision) }
        await gate.waitUntilEntered()
        model.close(); model.open(); await model.load(); checkTrue(model.reviewRemoval(second))
        let current = model.removalReview, fresh = model.records
        await gate.release(); checkTrue(await old.value)
        await model.load() // Join the independently owned post-commit read.
        checkEqual(model.removalReview, current); checkEqual(model.records, fresh); checkNil(model.notice); checkFalse(model.busy)
        checkEqual(fresh.first { $0.host == first.host }?.key.fingerprint, decision.fingerprint)
    }

    func testLateCommittedRemovalDoesNotClearNewReviewOrOverrideReopenedData() async throws {
        let (_, store, wrapper, model) = try await fixture()
        let ed = try await key(edLine)
        let first = try await accept(store, host: host(), key: ed)
        let second = try await accept(store, host: host("second.invalid"), key: ed)
        await model.load(); checkTrue(model.reviewRemoval(first))
        let review = try XCTUnwrap(model.removalReview)
        let gate = KeyTrustTestGate(); await wrapper.pauseAfterNext(.remove, on: gate)
        let old = Task { await model.remove(review) }
        await gate.waitUntilEntered()
        checkFalse(model.reviewRemoval(second))
        model.close(); model.open(); await model.load(); checkTrue(model.reviewRemoval(second))
        let current = model.removalReview
        await gate.release(); checkTrue(await old.value)
        await model.load() // Join the independently owned post-commit read.
        checkEqual(model.removalReview, current); checkEqual(model.records, [second]); checkNil(model.notice); checkFalse(model.busy)
        checkEqual(try await store.records(), [second])
    }

    func testCommittedRemovalAfterReopenRereadsRatherThanRestoringOldSnapshot() async throws {
        let (_, store, wrapper, model) = try await fixture()
        let ed = try await key(edLine)
        let first = try await accept(store, host: host(), key: ed)
        let second = try await accept(store, host: host("second.invalid"), key: ed)
        await model.load(); checkTrue(model.reviewRemoval(first))
        let review = try XCTUnwrap(model.removalReview), gate = KeyTrustTestGate()
        await wrapper.pauseBeforeNextRemoval(on: gate)
        let old = Task { await model.remove(review) }
        await gate.waitUntilEntered()
        model.close(); model.open(); await model.load()
        checkTrue(model.records.contains(first)) // Reopen happened before the write committed.
        checkTrue(model.reviewRemoval(second)); let current = model.removalReview
        await wrapper.failRecords(true)
        await gate.release(); checkTrue(await old.value)
        checkEqual(try await store.records(), [second]) // The real store committed before recovery.
        await model.load()
        checkTrue(model.refreshRequired); checkEqual(model.loadIssue?.code, "trust.readFailed")
        checkFalse(model.loading)
        checkEqual(model.removalReview, current); checkNil(model.notice)
        await wrapper.failRecords(false); await model.load()
        checkEqual(model.records, [second]); checkFalse(model.refreshRequired); checkNil(model.loadIssue)
        checkFalse(model.loading)
        checkEqual(model.removalReview, current)
    }

    func testRemovalCommittedWithReadFailureShowsPendingRefreshInsteadOfInvitingAnotherWrite() async throws {
        let (_, store, wrapper, model) = try await fixture()
        let ed = try await key(edLine)
        let first = try await accept(store, host: host(), key: ed)
        await model.load(); checkTrue(model.reviewRemoval(first))
        let review = try XCTUnwrap(model.removalReview)
        await wrapper.failRecords(true)
        checkTrue(await model.remove(review))
        checkTrue(try await store.records().isEmpty)
        checkTrue(model.refreshRequired); checkNotNil(model.loadIssue)
        checkEqual(model.records, [first]); checkNil(model.removalReview)
        await wrapper.failRecords(false); await model.load()
        checkTrue(model.records.isEmpty); checkFalse(model.refreshRequired); checkNil(model.loadIssue)
    }

    func testReplacementKeepsAlgorithmAndIndependentVerificationSafetyGates() async throws {
        let (_, store, _, model) = try await fixture()
        let ed = try await key(edLine)
        let first = try await accept(store, host: host(), key: ed)
        await model.load(); checkTrue(model.beginReplacement(first))
        await model.prepare(first, line: rsaLine)
        checkNil(model.pending); checkEqual(model.issue?.code, "trust.replacementRejected")
        await model.prepare(first, line: changedLine)
        let decision = try XCTUnwrap(model.pending)
        checkEqual(decision.reason, .manuallyVerifiedReplacement(previousFingerprint: first.key.fingerprint))
        _ = try await accept(store, host: host("independent-write.invalid"), key: ed)
        checkFalse(await model.confirm(decision))
        checkEqual(model.issue?.code, "trust.confirmationRejected")
        checkTrue(try await store.records().contains(first))
        let changed = try await key(changedLine)
        guard case .rejected = try await store.evaluate(host: first.host, key: changed) else {
            return XCTFail("Changed key must still be rejected")
        }
    }

    func testCopiesExactPublicMetadataToIndependentPasteboardWithoutChangingReview() async throws {
        let (_, store, _, model) = try await fixture()
        let ed = try await key(edLine)
        let first = try await accept(store, host: host("2001:db8::1", port: 2222), key: ed)
        let second = try await accept(store, host: host("second.invalid"), key: ed)
        await model.load(); checkTrue(model.reviewRemoval(second))
        let current = model.removalReview
        let pasteboard = NSPasteboard.withUniqueName(); defer { pasteboard.releaseGlobally() }
        checkTrue(model.copyEndpoint(first, to: pasteboard))
        checkEqual(pasteboard.string(forType: .string), "[2001:db8::1]:2222")
        checkTrue(model.copyFingerprint(first, to: pasteboard))
        checkEqual(pasteboard.string(forType: .string), first.key.fingerprint)
        checkNotNil(model.notice); checkEqual(model.removalReview, current)
        checkEqual(Set(try await store.records()), Set([first, second]))
    }
}

private actor KeyTrustTestGate {
    private var entered = false
    private var released = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var continuation: CheckedContinuation<Void, Never>?
    func pause() async {
        entered = true; waiters.forEach { $0.resume() }; waiters.removeAll()
        guard !released else { return }
        await withCheckedContinuation { continuation = $0 }
    }
    func waitUntilEntered() async {
        if entered { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func release() { released = true; continuation?.resume(); continuation = nil }
}

private enum KeyTrustTestCall: Hashable, Sendable { case records, prepare, confirm, remove }
private actor KeyTrustTestStore: TrustManagementStoring {
    let store: HostTrustStore
    private var gates: [KeyTrustTestCall: KeyTrustTestGate] = [:]
    private var beforeRemoveGate: KeyTrustTestGate?
    private var recordsFailure = false
    private(set) var readCount = 0
    private(set) var removeCount = 0
    private(set) var lastPrepared: PendingTrustDecision?
    private(set) var cancelledIDs: [UUID] = []
    init(store: HostTrustStore) { self.store = store }
    func failRecords(_ value: Bool) { recordsFailure = value }
    func pauseAfterNext(_ call: KeyTrustTestCall, on gate: KeyTrustTestGate) { gates[call] = gate }
    func pauseBeforeNextRemoval(on gate: KeyTrustTestGate) { beforeRemoveGate = gate }
    func records() async throws -> [TrustedHostKey] {
        readCount += 1
        let gate = gates.removeValue(forKey: .records), fail = recordsFailure
        let values = try await store.records()
        if let gate { await gate.pause() }
        if fail { throw HostTrustError.corruptStorage }
        return values
    }
    func prepareReplacement(host: HostIdentity, key: HostPublicKey, expectedCurrentFingerprint: String) async throws -> PendingTrustDecision {
        let gate = gates.removeValue(forKey: .prepare)
        let decision = try await store.prepareReplacement(host: host, key: key, expectedCurrentFingerprint: expectedCurrentFingerprint)
        lastPrepared = decision
        if let gate { await gate.pause() }
        return decision
    }
    func confirm(_ decision: PendingTrustDecision, displayedFingerprint: String) async throws {
        let gate = gates.removeValue(forKey: .confirm)
        _ = try await store.confirm(decision, displayedFingerprint: displayedFingerprint)
        if let gate { await gate.pause() }
    }
    func remove(_ expected: TrustedHostKey) async throws {
        removeCount += 1
        let gate = gates.removeValue(forKey: .remove), before = beforeRemoveGate
        beforeRemoveGate = nil
        if let before { await before.pause() }
        try await store.remove(expected)
        if let gate { await gate.pause() }
    }
    func cancel(_ decision: PendingTrustDecision) async {
        cancelledIDs.append(decision.id); await store.cancel(decision)
    }
}

@MainActor final class KeyLabelCompletionRegressionTests: XCTestCase {
    private func fixture() throws -> (URL, AppRepository, KeyTrustLabelRepository, FakeCredentials, SecurityCoordinator, SecurityViewModel) {
        let directory = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let base = AppRepository(location: .isolated(directory))
        let repository = KeyTrustLabelRepository(base: base)
        let credentials = FakeCredentials()
        let coordinator = SecurityCoordinator(repository: repository, location: .isolated(directory), credentials: credentials)
        return (directory, base, repository, credentials, coordinator, SecurityViewModel(coordinator: coordinator))
    }

    func testCommittedCreationLabelFailureRetriesExactUUIDWithoutCreatingAgain() async throws {
        let (_, base, repository, credentials, coordinator, model) = try fixture()
        let editor = KeyCreationEditorState()
        await repository.failNextLabel()
        checkFalse(await editor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                       label: "first label", ownsPresentation: { true }))
        let outcome = try XCTUnwrap(editor.created)
        checkTrue(editor.labelPending); checkEqual(editor.savedLabel, "")
        checkEqual(model.issue?.code, "key.labelPending")
        await model.load()
        checkEqual(model.issue?.code, "key.labelPending") // load never clears a label error.
        checkEqual(try await base.securityMetadata().keys.map(\.id), [outcome.id])
        checkEqual(await repository.createCount, 1)
        checkEqual(await repository.labelKeyIDs, [outcome.id])
        checkTrue(await editor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                      label: "corrected label", ownsPresentation: { true }))
        checkFalse(editor.labelPending); checkEqual(editor.savedLabel, "corrected label")
        checkEqual(editor.created, outcome)
        checkEqual(await repository.createCount, 1)
        checkEqual(await repository.labelKeyIDs, [outcome.id, outcome.id])
        checkEqual(try await base.securityMetadata().keys.first?.label, "corrected label")
        checkTrue(editor.publishCompletion(to: model, ownsPresentation: { true }))
        checkEqual(model.lastCreatedKey, outcome); checkEqual(model.lastCreatedKeyLabel, "corrected label")
        checkEqual(await credentials.saveCount, 0); checkEqual(await credentials.readCount, 0)
        try await coordinator.close(); try await base.close()
    }

    func testFinishAfterLabelFailureKeepsCommittedKeyAndSelectsItsActualEmptyLabel() async throws {
        let (_, base, repository, _, coordinator, model) = try fixture()
        let previous = KeyCreationEditorState()
        checkTrue(await previous.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                        label: "previous key", ownsPresentation: { true }))
        let previousID = try XCTUnwrap(previous.created?.id)
        let selection = KeyLabelSelectionModel()
        selection.select(id: previousID, label: previous.savedLabel)
        let editor = KeyCreationEditorState()
        await repository.failNextLabel()
        checkFalse(await editor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                       label: "not yet saved", ownsPresentation: { true }))
        let outcome = try XCTUnwrap(editor.created)
        checkTrue(editor.publishCompletion(to: model, ownsPresentation: { true }))
        selection.select(id: outcome.id, label: model.lastCreatedKeyLabel)
        checkEqual(selection.selectedKeyID, outcome.id); checkEqual(selection.labelDraft, "")
        checkFalse(selection.hasChanges)
        checkEqual(try await base.securityMetadata().keys.count, 2)
        checkEqual(await repository.createCount, 2)
        checkEqual(try await base.securityMetadata().keys.first { $0.id == previousID }?.label, "previous key")
        editor.close()
        checkFalse(await editor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                       label: "late edit", ownsPresentation: { true }))
        checkEqual(await repository.createCount, 2)
        try await coordinator.close(); try await base.close()
    }

    func testImportLabelFailureRetriesLabelNotImportAndSelectionDoesNotUsePreviousLabel() async throws {
        let (directory, base, repository, credentials, coordinator, model) = try fixture()
        let sourceStore = try KeyStore(directory: directory.appendingPathComponent("SourceKeys"))
        let sourceKey = try await sourceStore.generateEd25519(protection: .unencrypted)
        let source = directory.appendingPathComponent("SourceKeys/" + sourceKey.id.uuidString + ".openssh")
        let before = try Data(contentsOf: source)
        let selection = KeyLabelSelectionModel()
        selection.select(id: UUID(), label: "previous selection label")
        let editor = KeyCreationEditorState()
        await repository.failNextLabel()
        checkFalse(await editor.submit(model: model, creation: .importFile(source), protection: .unencrypted, remember: nil,
                                       label: "imported", ownsPresentation: { true }))
        let imported = try XCTUnwrap(editor.created)
        checkTrue(await editor.submit(model: model, creation: .importFile(source), protection: .unencrypted, remember: nil,
                                      label: "imported", ownsPresentation: { true }))
        checkTrue(editor.publishCompletion(to: model, ownsPresentation: { true }))
        selection.select(id: imported.id, label: model.lastCreatedKeyLabel)
        checkEqual(selection.selectedKeyID, imported.id); checkEqual(selection.labelDraft, "imported")
        checkEqual(await repository.createCount, 1)
        checkEqual(await repository.labelKeyIDs, [imported.id, imported.id])
        checkEqual(try Data(contentsOf: source), before)
        checkEqual(try await coordinator.publicKey(imported.id), sourceKey.publicKey)
        checkEqual(await credentials.saveCount, 0); checkEqual(await credentials.readCount, 0)
        try await sourceStore.close(); try await coordinator.close(); try await base.close()
    }

    func testChangedCreationInputsAfterCommitStillOnlyUpdateCommittedUUID() async throws {
        let (_, base, repository, credentials, coordinator, model) = try fixture()
        let editor = KeyCreationEditorState()
        await repository.failNextLabel()
        checkFalse(await editor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                       label: "pending", ownsPresentation: { true }))
        let first = try XCTUnwrap(editor.created)
        checkTrue(await model.create(.generate, protection: .unencrypted, remember: nil))
        let later = try XCTUnwrap(model.lastCreatedKey)
        let phrase = SecretBytes(utf8: UUID().uuidString)
        checkTrue(await editor.submit(model: model, creation: .importFile(URL(fileURLWithPath: "/not-an-authorized-source")),
                                      protection: .passphrase(phrase), remember: phrase, label: "only first", ownsPresentation: { true }))
        checkEqual(editor.created, first)
        checkEqual(await repository.createCount, 2)
        checkEqual(await repository.labelKeyIDs, [first.id, first.id])
        let metadata = try await base.securityMetadata()
        checkEqual(metadata.keys.first { $0.id == first.id }?.label, "only first")
        checkEqual(metadata.keys.first { $0.id == later.id }?.label, "")
        checkEqual(await credentials.saveCount, 0); checkEqual(await credentials.readCount, 0)
        try await coordinator.close(); try await base.close()
    }

    func testCancelledCreationOwnerCannotLabelOrPublishForLaterEditor() async throws {
        let (_, base, repository, _, coordinator, model) = try fixture()
        let editor = KeyCreationEditorState(), gate = KeyTrustTestGate()
        await repository.pauseNextRegistration(on: gate)
        let task = Task { await editor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                             label: "expired label", ownsPresentation: { true }) }
        await gate.waitUntilEntered()
        editor.close(); await gate.release()
        checkFalse(await task.value)
        let outcome = try XCTUnwrap(editor.created)
        checkFalse(editor.publishCompletion(to: model, ownsPresentation: { true }))
        checkEqual(await repository.createCount, 1); checkTrue(await repository.labelKeyIDs.isEmpty)
        checkEqual(try await base.securityMetadata().keys.first { $0.id == outcome.id }?.label, "")
        try await coordinator.close(); try await base.close()
    }

    func testLabelAwaitCannotOverwriteNewSelectionDraftIncludingABAAndNewTyping() async throws {
        let (_, base, repository, _, coordinator, model) = try fixture()
        let firstEditor = KeyCreationEditorState(), secondEditor = KeyCreationEditorState()
        checkTrue(await firstEditor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                           label: "first", ownsPresentation: { true }))
        checkTrue(await secondEditor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                            label: "second", ownsPresentation: { true }))
        let first = try XCTUnwrap(model.metadata.keys.first { $0.id == firstEditor.created?.id })
        let second = try XCTUnwrap(model.metadata.keys.first { $0.id == secondEditor.created?.id })
        let selection = KeyLabelSelectionModel()
        selection.select(first); selection.edit("saved first")
        let save = try XCTUnwrap(selection.captureSave()), gate = KeyTrustTestGate()
        await repository.pauseNextLabel(on: gate)
        let pending = Task {
            let result = await model.updateLabel(save.keyID, label: save.label)
            selection.complete(save, succeeded: result)
            return result
        }
        await gate.waitUntilEntered()
        selection.select(second); selection.edit("unsaved second")
        await gate.release(); checkTrue(await pending.value)
        checkEqual(selection.selectedKeyID, second.id); checkEqual(selection.labelDraft, "unsaved second")
        checkEqual(try await base.securityMetadata().keys.first { $0.id == first.id }?.label, "saved first")
        checkEqual(try await base.securityMetadata().keys.first { $0.id == second.id }?.label, "second")
        selection.select(first); selection.edit("before ABA")
        let aba = try XCTUnwrap(selection.captureSave())
        selection.select(second); selection.select(first); selection.edit("new first draft")
        selection.complete(aba, succeeded: true)
        checkEqual(selection.labelDraft, "new first draft")
        let typed = try XCTUnwrap(selection.captureSave())
        selection.edit("typed while awaiting"); selection.complete(typed, succeeded: true)
        checkEqual(selection.labelDraft, "typed while awaiting")
        try await coordinator.close(); try await base.close()
    }

    func testDuplicateLabelRetryIsRejectedWhileExactWriteIsInFlight() async throws {
        let (_, base, repository, _, coordinator, model) = try fixture()
        let editor = KeyCreationEditorState()
        await repository.failNextLabel()
        checkFalse(await editor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                       label: "pending", ownsPresentation: { true }))
        let outcome = try XCTUnwrap(editor.created), gate = KeyTrustTestGate()
        await repository.pauseNextLabel(on: gate)
        let retry = Task { await editor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                              label: "retry", ownsPresentation: { true }) }
        await gate.waitUntilEntered()
        checkFalse(await editor.submit(model: model, creation: .generate, protection: .unencrypted, remember: nil,
                                       label: "duplicate", ownsPresentation: { true }))
        checkFalse(editor.publishCompletion(to: model, ownsPresentation: { true }))
        await gate.release(); checkTrue(await retry.value)
        checkEqual(await repository.createCount, 1)
        checkEqual(await repository.labelKeyIDs, [outcome.id, outcome.id])
        checkEqual(try await base.securityMetadata().keys.first?.label, "retry")
        try await coordinator.close(); try await base.close()
    }
}

private actor KeyTrustLabelRepository: AppRepositoryProtocol {
    let base: AppRepository
    private var rejectLabel = false
    private var labelGate: KeyTrustTestGate?
    private var registrationGate: KeyTrustTestGate?
    private(set) var createCount = 0
    private(set) var labelKeyIDs: [UUID] = []
    init(base: AppRepository) { self.base = base }
    func failNextLabel() { rejectLabel = true }
    func pauseNextLabel(on gate: KeyTrustTestGate) { labelGate = gate }
    func pauseNextRegistration(on gate: KeyTrustTestGate) { registrationGate = gate }
    func snapshot(query: HostQuery) async throws -> AppSnapshot { try await base.snapshot(query: query) }
    func apply(_ changes: [RepositoryChange]) async throws {
        let registration = changes.contains { if case .registerKey = $0 { return true }; return false }
        let gate = registration ? registrationGate : nil
        if registration { registrationGate = nil; createCount += 1 }
        try await base.apply(changes)
        if let gate { await gate.pause() }
    }
    func updateKeyLabel(keyID: UUID, label: String) async throws {
        labelKeyIDs.append(keyID)
        let gate = labelGate; labelGate = nil
        if let gate { await gate.pause() }
        if rejectLabel { rejectLabel = false; throw RepositoryError.databaseBusy }
        try await base.updateKeyLabel(keyID: keyID, label: label)
    }
    func securityMetadata() async throws -> SecurityMetadata { try await base.securityMetadata() }
    func completeCleanup(_ id: UUID) async throws { try await base.completeCleanup(id) }
    func recordCleanupFailure(_ id: UUID, failure: CleanupFailure) async throws { try await base.recordCleanupFailure(id, failure: failure) }
    func copyHost(id: UUID) async throws -> HostConfiguration { try await base.copyHost(id: id) }
    func copyFolder(id: UUID) async throws -> HostFolder { try await base.copyFolder(id: id) }
    func close() async throws { try await base.close() }
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
