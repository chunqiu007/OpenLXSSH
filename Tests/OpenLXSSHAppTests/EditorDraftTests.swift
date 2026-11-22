import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHSecurity
import OpenLXSSHTransport

@MainActor final class EditorDraftTests: XCTestCase {
    func testDraftPreservesLegacyMethodsReferencesIdentityAndCase() throws {
        for method in [AuthenticationKind.password, .passwordWithMFA, .privateKey, .privateKeyWithMFA] {
            let credential = method.needsKey ? nil : UUID(), key = method.needsKey ? UUID() : nil
            let original = HostConfiguration(name: "legacy", address: "EXAMPLE.invalid", username: "MixedCase", authentication: method,
                credentialRef: credential, keyRef: key, savePasswordAuthorized: credential != nil)
            var draft = VaultHostDraft(host: original, settings: AppSettings())
            draft.changePrimaryMethod(method.needsKey ? "key" : "password")
            XCTAssertEqual(try draft.value(), original)
            XCTAssertFalse(draft.isDirty)
            XCTAssertEqual(try draft.value().username, "MixedCase")
        }
    }
    func testChangingPrimaryMethodDropsIncompatibleReferencesWithoutNewAuthorization() throws {
        let original = HostConfiguration(name: "legacy", address: "example.invalid", username: "Fixture",
            credentialRef: UUID(), savePasswordAuthorized: true)
        var draft = VaultHostDraft(host: original, settings: AppSettings())
        draft.changePrimaryMethod("key")
        XCTAssertTrue(draft.configuration.authentication.needsKey)
        XCTAssertNil(draft.configuration.credentialRef)
        XCTAssertFalse(draft.configuration.savePasswordAuthorized)
        XCTAssertNil(draft.configuration.keyRef)
        XCTAssertNotNil(draft.fieldErrors["key"])
        draft.configuration.keyRef = UUID()
        XCTAssertTrue(draft.fieldErrors.isEmpty)
        draft.changePrimaryMethod("password")
        XCTAssertNil(draft.configuration.keyRef)
        XCTAssertNil(draft.configuration.credentialRef)
        XCTAssertFalse(draft.configuration.savePasswordAuthorized)
    }
    func testValidationMatchesConnectionBoundariesAndNeverSilentlyNormalizesUsername() throws {
        var draft = VaultHostDraft(host: HostConfiguration(name: "host", address: "2001:db8::1", username: "CaseSensitive"), settings: AppSettings())
        draft.port = "65535"
        XCTAssertTrue(draft.fieldErrors.isEmpty)
        XCTAssertEqual(try draft.value().username, "CaseSensitive")
        for address in ["ssh://user@host.invalid", "host.invalid:2222", "bad address", "127.1", "-option"] {
            draft.configuration.address = address
            XCTAssertNotNil(draft.fieldErrors["address"], address)
        }
        draft.configuration.address = "[2001:db8::1]"
        XCTAssertNil(draft.fieldErrors["address"])
        draft.configuration.username = "two words"
        XCTAssertNotNil(draft.fieldErrors["username"])
        draft.configuration.username = "demo#root#00000000-0000-4000-8000-000000000001"
        XCTAssertNil(draft.fieldErrors["username"])
        var jumpDraft = VaultHostDraft(settings: AppSettings())
        XCTAssertTrue(jumpDraft.applySSHCommand("ssh demo#root#00000000-0000-4000-8000-000000000001@bastion.example.test -p 2224"))
        XCTAssertEqual(jumpDraft.configuration.address, "bastion.example.test")
        XCTAssertEqual(jumpDraft.configuration.username, "demo#root#00000000-0000-4000-8000-000000000001")
        XCTAssertEqual(jumpDraft.port, "2224")
        XCTAssertEqual(jumpDraft.configuration.name, "bastion.example.test")
        XCTAssertTrue(jumpDraft.fieldErrors.isEmpty)
        XCTAssertFalse(jumpDraft.applySSHCommand("ssh -oProxyCommand=id user@bastion.example.test"))
        draft.configuration.username = "CaseSensitive"
        for port in ["0", "65536", "22x", "022", ""] { draft.port = port; XCTAssertNotNil(draft.fieldErrors["port"]) }
        draft.port = "22"; draft.interval = "3601"; draft.count = "0"
        XCTAssertNotNil(draft.fieldErrors["interval"]); XCTAssertNotNil(draft.fieldErrors["count"])
    }
    func testNonSecretDraftDirtyStateIncludesTagsAndInputStrings() throws {
        let host = HostConfiguration(name: "host", address: "host.invalid", username: "fixture")
        let tag = UUID()
        var draft = VaultHostDraft(host: host, settings: AppSettings(), tagIDs: [tag])
        XCTAssertFalse(draft.isDirty)
        draft.tagIDs = []
        XCTAssertTrue(draft.isDirty)
        draft.tagIDs = [tag]; draft.port = "2222"
        XCTAssertTrue(draft.isDirty)
        draft.port = "22"; draft.configuration.name = "renamed"
        XCTAssertTrue(draft.isDirty)
        XCTAssertEqual(draft.id, host.id)
    }
    func testNewHostCloseReviewOnlyPromptsForActualChanges() {
        let folder = UUID()
        let editor = VaultHostEditorModel(draft: VaultHostDraft(settings: AppSettings(), folderID: folder))
        var dismissCount = 0
        let review = VaultHostCloseReview(editor: editor, dismiss: { dismissCount += 1 })
        review.begin()
        XCTAssertEqual(dismissCount, 1)
        XCTAssertNil(review.prompt)
        editor.password = "temporary input"
        review.begin()
        XCTAssertEqual(review.prompt?.kind, .dirty)
        XCTAssertEqual(dismissCount, 1)
        editor.password = ""
        editor.draft.configuration.folderID = nil
        XCTAssertTrue(editor.dirty)
        editor.draft.configuration.folderID = folder
        XCTAssertFalse(editor.dirty)
    }
    func testCommittedNewDraftKeepsIDButRetriesAsUpdate() throws {
        var draft = VaultHostDraft(settings: AppSettings())
        draft.configuration.name = "new"; draft.configuration.address = "new.invalid"; draft.configuration.username = "fixture"
        let saved = try draft.value()
        XCTAssertTrue(draft.isNew)
        draft.markCommitted(saved)
        XCTAssertFalse(draft.isNew)
        XCTAssertFalse(draft.isDirty)
        XCTAssertEqual(draft.id, saved.id)
        draft.configuration.name = "retry changed label"
        XCTAssertTrue(draft.isDirty)
        XCTAssertEqual(draft.id, saved.id)
    }
    func testPublicFingerprintUsesValidatedBlobAndRejectsPrivateOrMalformedText() throws {
        var blob = Data()
        func append(_ bytes: Data) {
            var size = UInt32(bytes.count).bigEndian
            withUnsafeBytes(of: &size) { blob.append(contentsOf: $0) }
            blob.append(bytes)
        }
        append(Data("ssh-ed25519".utf8)); append(Data(repeating: 7, count: 32))
        let value = "ssh-ed25519 " + blob.base64EncodedString()
        let info = try XCTUnwrap(SecurityViewModel.publicInformation(value))
        XCTAssertEqual(info.bits, 256)
        XCTAssertTrue(info.fingerprint.hasPrefix("SHA256:"))
        XCTAssertFalse(info.fingerprint.contains("="))
        XCTAssertNil(SecurityViewModel.publicInformation("-----BEGIN OPENSSH PRIVATE KEY-----"))
        XCTAssertNil(SecurityViewModel.publicInformation("ssh-ed25519 invalid"))
    }
    func testTransientConnectionIntentIsExactAndOneShot() throws {
        let host = HostConfiguration(name: "host", address: "host.invalid", username: "fixture")
        let secret = SecretBytes(utf8: UUID().uuidString)
        let intent = VaultTransientConnectionIntent(host: host, secret: secret)
        let token = OpenLXSSHTransport.SessionToken(sessionID: UUID(), generation: 1), request = UUID()
        var changed = host; changed.port = 2222
        XCTAssertThrowsError(try intent.bind(to: token, host: changed))
        XCTAssertFalse(intent.consumed)
        try intent.bind(to: token, host: host)
        try intent.bindPrimaryRequest(request, token: token, host: host)
        XCTAssertThrowsError(try intent.take(for: host, token: token, primaryRequestID: UUID()))
        let material = try XCTUnwrap(intent.take(for: host, token: token, primaryRequestID: request))
        XCTAssertTrue(secret.matches(material))
        XCTAssertTrue(intent.consumed)
        XCTAssertThrowsError(try intent.take(for: host, token: token, primaryRequestID: request))
        let cancelled = VaultTransientConnectionIntent(host: host, secret: secret)
        cancelled.cancel()
        XCTAssertThrowsError(try cancelled.bind(to: token, host: host))
    }
}

@MainActor final class ReliabilityEditorTests: XCTestCase {
    private func fixture() throws -> (URL, AppRepository, FakeCredentials) {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let base = AppRepository(location: .isolated(root)), credentials = FakeCredentials()
        addTeardownBlock { try await base.close(); try FileManager.default.removeItem(at: root) }
        return (root, base, credentials)
    }
    private func host() -> HostConfiguration { HostConfiguration(name: "fixture", address: "never-connected.invalid", username: "Fixture") }
    private func vault(_ repository: any AppRepositoryProtocol) -> VaultDesktopModel {
        VaultDesktopModel(repository: repository, preferenceKey: "Reliability." + UUID().uuidString)
    }
    private func coordinator(_ root: URL, _ repository: any AppRepositoryProtocol, _ credentials: FakeCredentials) -> SecurityCoordinator {
        let value = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        addTeardownBlock { try await value.close() }
        return value
    }
    func testRememberCommitReadFailureRetriesOnlyReadsAndRetainsNewAuthorization() async throws {
        for isNew in [false, true] {
            let (root, base, credentials) = try fixture(), original = host()
            if !isNew { try await base.apply([.insertHost(original)]) }
            let repository = ReliabilityFaultRepository(base: base), vault = vault(repository)
            _ = await vault.load()
            let security = coordinator(root, repository, credentials)
            let editor = VaultHostEditorModel(draft: VaultHostDraft(host: isNew ? nil : original, settings: AppSettings()))
            if isNew { editor.draft.configuration = original }
            editor.password = UUID().uuidString; editor.remember = true; editor.showPassword = true
            await repository.failSnapshots(2); await repository.failPostCommitSecurityRead()
            rFalse(await editor.save(security: security, vault: vault))
            XCTAssertTrue(editor.committedAwaitingRefresh); XCTAssertFalse(editor.canEdit)
            XCTAssertEqual(editor.issue?.code, "host.committedAwaitingRefresh")
            XCTAssertTrue(editor.cleanupPending); XCTAssertFalse(editor.draft.isNew)
            XCTAssertTrue(editor.password.isEmpty); XCTAssertFalse(editor.showPassword); XCTAssertFalse(editor.remember)
            let committed = try rUnwrap(try await base.securityMetadata().hosts.first)
            XCTAssertNotNil(committed.credentialRef); XCTAssertTrue(committed.savePasswordAuthorized)
            XCTAssertEqual(editor.draft.configuration.credentialRef, committed.credentialRef)
            editor.edit { $0.draft.configuration.name = "must not change read-only form" }
            XCTAssertEqual(editor.draft.configuration.name, original.name)
            rFalse(await editor.save(security: security, vault: vault)); XCTAssertTrue(editor.committedAwaitingRefresh)
            rTrue(await editor.reloadCurrent(vault: vault)); XCTAssertFalse(editor.committedAwaitingRefresh)
            XCTAssertEqual(editor.draft.configuration, committed); XCTAssertTrue(editor.canEdit)
            rEqual(await credentials.saveCount, 1); rEqual(await credentials.deleteCount, 0); rEqual(await repository.applyCount, 1)
            rEqual(try await base.securityMetadata().hosts.count, 1)
            rEqual(try await base.securityMetadata().credentials.map(\.id), [try XCTUnwrap(committed.credentialRef)])
            XCTAssertNotNil(vault.notice, "Cleanup-pending outcome survives read recovery")
        }
    }
    func testInFlightSaveFreezesDraftCloseAndNestedInputThenRetainsFailureDraft() async throws {
        let (root, base, credentials) = try fixture(), repository = ReliabilityFaultRepository(base: base), gate = ReliabilityGate()
        let vault = vault(repository), security = coordinator(root, repository, credentials)
        let original = host(); try await base.apply([.insertHost(original)]); _ = await vault.load()
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: original, settings: AppSettings()))
        editor.draft.configuration.name = "unsaved"; editor.password = UUID().uuidString
        let input = editor.password
        await repository.holdNextApply(gate, fail: true)
        let save = Task { await editor.save(security: security, vault: vault) }
        await gate.waitForArrival()
        XCTAssertTrue(editor.writing); XCTAssertFalse(editor.canClose); XCTAssertFalse(editor.canEdit)
        editor.edit { $0.draft.configuration.name = "late input"; $0.draft.configuration.keyRef = UUID(); $0.password = "late" }
        rFalse(await editor.save(security: security, vault: vault))
        XCTAssertEqual(editor.draft.configuration.name, "unsaved"); XCTAssertEqual(editor.password, input)
        await gate.release(); rFalse(await save.value)
        XCTAssertFalse(editor.writing); XCTAssertTrue(editor.canClose)
        XCTAssertEqual(editor.draft.configuration.name, "unsaved"); XCTAssertEqual(editor.password, input)
        XCTAssertTrue(editor.draft.isDirty); XCTAssertNotNil(editor.issue)
        rEqual(try await base.securityMetadata().hosts.first?.name, original.name)
    }
    func testLateSuccessAndFailureCannotCommitOldDraftOrClearNewPresentationCloseOwner() async throws {
        for fail in [false, true] {
            let (root, base, credentials) = try fixture(), repository = ReliabilityFaultRepository(base: base), gate = ReliabilityGate()
            let vault = vault(repository), security = coordinator(root, repository, credentials), owner = PresentationOwner<String>()
            owner.present("old"); let oldID = try XCTUnwrap(owner.item?.id)
            let original = host(); try await base.apply([.insertHost(original)]); _ = await vault.load()
            let editor = VaultHostEditorModel(draft: VaultHostDraft(host: original, settings: AppSettings()), ownsPresentation: { owner.owns(oldID) })
            editor.draft.configuration.name = "old save"; editor.password = UUID().uuidString
            owner.registerClose(oldID) { editor.canClose }
            await repository.holdNextApply(gate, fail: fail)
            let save = Task { await editor.save(security: security, vault: vault) }
            await gate.waitForArrival(); XCTAssertFalse(owner.attemptClose())
            owner.present("new"); let newID = try XCTUnwrap(owner.item?.id)
            owner.registerClose(newID) { false }
            editor.deactivate(); owner.clearClose(oldID)
            await gate.release(); rFalse(await save.value)
            XCTAssertEqual(owner.item?.id, newID); XCTAssertFalse(owner.attemptClose())
            XCTAssertTrue(editor.draft.isDirty); XCTAssertNil(editor.issue); XCTAssertTrue(editor.password.isEmpty)
            owner.dismiss(oldID); XCTAssertEqual(owner.item?.id, newID)
        }
    }
    func testStaleEditorCannotRestoreUnlinkedKeyAndCanExplicitlyReload() async throws {
        let (root, base, credentials) = try fixture(), key = ManagedKeyReference(algorithm: .ed25519), tag = HostTag(name: "tag")
        var original = host(); original.authentication = .privateKeyWithMFA; original.keyRef = key.id
        try await base.apply([.registerKey(key), .insertHost(original), .addTag(tag), .assignTag(hostID: original.id, tagID: tag.id)])
        let security = coordinator(root, base, credentials), vault = vault(base)
        _ = await vault.load()
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: original, settings: AppSettings(), tagIDs: [tag.id]))
        editor.draft.configuration.name = "stale rename"
        let manager = SecurityViewModel(coordinator: security)
        rTrue(await manager.unlinkKey(key.id, hostIDs: [original.id]))
        rFalse(await editor.save(security: security, vault: vault))
        XCTAssertEqual(editor.issue?.code, "storage.staleRecord"); XCTAssertTrue(editor.draft.isDirty)
        var current = try rUnwrap(try await base.securityMetadata().hosts.first)
        XCTAssertNil(current.keyRef); XCTAssertEqual(current.authentication, .passwordWithMFA)
        editor.password = UUID().uuidString; editor.remember = true; editor.showPassword = true
        rTrue(await editor.reloadCurrent(vault: vault))
        XCTAssertTrue(editor.password.isEmpty); XCTAssertFalse(editor.remember); XCTAssertFalse(editor.showPassword)
        editor.draft.configuration.name = "fresh rename"
        rTrue(await editor.save(security: security, vault: vault))
        current = try rUnwrap(try await base.securityMetadata().hosts.first)
        XCTAssertEqual(current.name, "fresh rename"); XCTAssertNil(current.keyRef); XCTAssertFalse(current.savePasswordAuthorized)
    }
    func testSaveAndConnectConsumerDismissesExactOwnerBeforeRoutingOnce() async throws {
        let (root, base, credentials) = try fixture(), original = host(), router = ReliabilityRecordingRouter()
        try await base.apply([.insertHost(original)])
        let security = coordinator(root, base, credentials)
        let app = AppModel(repository: base, sessionRouter: router, security: security, location: .isolated(root))
        let vault = VaultDesktopModel(app: app); _ = await vault.load()
        let owner = PresentationOwner<String>(); owner.present("editor")
        let id = try XCTUnwrap(owner.item?.id)
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: original, settings: AppSettings()), ownsPresentation: { owner.owns(id) })
        editor.draft.configuration.name = "committed before connection"
        owner.registerClose(id) { editor.canClose && !editor.dirty }
        app.registerWorkspaceNavigationGuard(owner: UUID()) {
            guard owner.item != nil else { return true }
            return owner.attemptClose()
        }
        app.requestSession(hostID: original.id, mode: .newSession)
        XCTAssertTrue(router.requests.isEmpty, "Ordinary navigation cannot bypass the dirty editor")
        let result = await editor.saveAndFinish(security: security, vault: vault, dismiss: { owner.dismiss(id) },
            afterDismiss: { saved in
                XCTAssertFalse(editor.writing); XCTAssertNil(owner.item)
                app.requestSession(hostID: saved.id, mode: .newSession)
            })
        XCTAssertTrue(result); XCTAssertEqual(router.requests, [SessionRequest(hostID: original.id, mode: .newSession)])
        rEqual(try await base.securityMetadata().hosts.first?.name, "committed before connection")
        let duplicate = await editor.saveAndFinish(security: security, vault: vault, dismiss: { owner.dismiss(id) },
            afterDismiss: { app.requestSession(hostID: $0.id, mode: .newSession) })
        XCTAssertFalse(duplicate); XCTAssertEqual(router.requests.count, 1)
    }
    func testConnectionFailureAfterCommitRetainsSavedHostAndNeverDismissesNewOwner() async throws {
        let (root, base, credentials) = try fixture(), original = host()
        try await base.apply([.insertHost(original)])
        let security = coordinator(root, base, credentials), vault = vault(base), owner = PresentationOwner<String>()
        _ = await vault.load(); owner.present("old"); let id = try XCTUnwrap(owner.item?.id)
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: original, settings: AppSettings()), ownsPresentation: { owner.owns(id) })
        editor.draft.configuration.name = "saved despite connect error"
        var dismissed = false
        let failed = await editor.saveAndFinish(security: security, vault: vault,
            connect: { _, _ in throw RepositoryError.databaseBusy }, dismiss: { dismissed = true; owner.dismiss(id) })
        XCTAssertFalse(failed); XCTAssertFalse(dismissed); XCTAssertEqual(owner.item?.id, id)
        XCTAssertFalse(editor.draft.isDirty); XCTAssertNotNil(editor.issue)
        rEqual(try await base.securityMetadata().hosts.first?.name, "saved despite connect error")
        editor.draft.configuration.name = "second saved before late connection"
        let gate = ReliabilityGate()
        let late = Task {
            await editor.saveAndFinish(security: security, vault: vault,
                connect: { _, _ in await gate.suspend() }, dismiss: { dismissed = true; owner.dismiss(id) })
        }
        await gate.waitForArrival(); owner.present("new form"); let next = try XCTUnwrap(owner.item?.id)
        await gate.release(); rFalse(await late.value)
        XCTAssertFalse(dismissed); XCTAssertEqual(owner.item?.id, next)
        rEqual(try await base.securityMetadata().hosts.first?.name, "second saved before late connection")
    }
    func testRaceAfterSecurityReadRejectsChangedTagsAndCompensatesOnlyNewSecret() async throws {
        let (root, base, credentials) = try fixture(), original = host(), tag = HostTag(name: "external assignment")
        try await base.apply([.insertHost(original), .addTag(tag)])
        let repository = ReliabilityFaultRepository(base: base), gate = ReliabilityGate(), vault = vault(repository)
        _ = await vault.load()
        let security = coordinator(root, repository, credentials)
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: original, settings: AppSettings()))
        editor.draft.configuration.name = "stale"; editor.password = UUID().uuidString; editor.remember = true
        await repository.holdNextApply(gate, fail: false)
        let save = Task { await editor.save(security: security, vault: vault) }
        await gate.waitForArrival()
        try await base.apply([.assignTag(hostID: original.id, tagID: tag.id)])
        await gate.release(); rFalse(await save.value)
        XCTAssertEqual(editor.issue?.code, "storage.staleRecord")
        rEqual(try await base.snapshot(query: HostQuery()).hostTagIDs[original.id], [tag.id])
        rEqual(try await base.securityMetadata().hosts.first, original)
        rTrue(try await base.securityMetadata().credentials.isEmpty)
        rEqual(await credentials.saveCount, 1); rEqual(await credentials.deleteCount, 1)
        XCTAssertFalse(editor.password.isEmpty)
    }
}

@MainActor final class DesktopCloseEditorTests: XCTestCase {
    private func fixture(isNew: Bool = false) async throws -> DesktopCloseFixture {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let base = AppRepository(location: .isolated(root)), credentials = FakeCredentials()
        let host = HostConfiguration(name: "close fixture", address: "never-connected.invalid", username: "Fixture")
        if !isNew { try await base.apply([.insertHost(host)]) }
        let repository = ReliabilityFaultRepository(base: base)
        let security = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        let app = AppModel(repository: repository, security: security, location: .isolated(root))
        let vault = VaultDesktopModel(repository: repository, preferenceKey: "DesktopClose." + UUID().uuidString)
        _ = await vault.load()
        let owner = PresentationOwner<String>(); owner.present("host editor")
        let id = try XCTUnwrap(owner.item?.id)
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: isNew ? nil : host, settings: AppSettings()), ownsPresentation: { [weak owner] in owner?.owns(id) == true })
        if isNew { editor.draft.configuration = host }
        editor.draft.configuration.name = "unsaved close draft"
        let review = VaultHostCloseReview(editor: editor, dismiss: { [weak owner] in owner?.dismiss(id) },
            complete: { [weak owner] request in owner?.completeWindowCloseReview(request, dismissing: id) })
        owner.registerWindowCloseReview(id, begin: { [weak review] request in
            guard let review else { request.resolve(false); return }; review.begin(request)
        }, cancel: { [weak review] in review?.cancelPending() })
        app.registerWindowCloseReview(owner: UUID(), begin: { [weak owner] request in
            guard let owner else { request.resolve(false); return }; owner.beginWindowCloseReview(request)
        }, cancel: { [weak owner] in owner?.cancelWindowCloseReview() })
        addTeardownBlock { try await security.close(); try await base.close(); try FileManager.default.removeItem(at: root) }
        return DesktopCloseFixture(base: base, repository: repository, credentials: credentials,
            app: app, vault: vault, owner: owner, ownerID: id, editor: editor, review: review)
    }
    func testDirtyNewAndExistingCancelPreservesDraftSecretAndAdmissionWithoutCredentialReads() async throws {
        for isNew in [false, true] {
            let f = try await fixture(isNew: isNew), files = DesktopCloseFiles()
            f.app.lifecycle.files = files
            f.editor.password = UUID().uuidString; f.editor.remember = true; f.editor.showPassword = true
            let draft = f.editor.draft, password = f.editor.password
            let request = f.app.requestWindowCloseReview()
            let prompt = try XCTUnwrap(f.review.prompt)
            XCTAssertEqual(prompt.kind, .dirty); XCTAssertFalse(f.editor.showPassword)
            XCTAssertEqual(files.freezeCount, 0); XCTAssertEqual(files.closeCount, 0)
            XCTAssertTrue(f.review.cancel(prompt.id))
            let admitted = await f.app.lifecycle.freezeAfterCloseReview(request, isCurrent: { f.app.isWindowCloseReviewCurrent(request) })
            XCTAssertFalse(admitted); XCTAssertFalse(f.app.isWindowCloseReviewCurrent(request))
            XCTAssertEqual(f.editor.draft, draft); XCTAssertEqual(f.editor.password, password); XCTAssertTrue(f.editor.remember)
            XCTAssertEqual(f.owner.item?.id, f.ownerID); XCTAssertFalse(f.editor.writing)
            XCTAssertEqual(files.freezeCount, 0); XCTAssertEqual(files.closeCount, 0); XCTAssertEqual(files.cancelCount, 0)
            rEqual(await f.credentials.readCount, 0); rEqual(await f.credentials.saveCount, 0); rEqual(await f.repository.applyCount, 0)
            f.app.finishWindowCloseReview()
        }
    }
    func testDiscardClearsTransientInputAndOnlyThenAllowsExistingLifecycleCleanupOnce() async throws {
        let f = try await fixture(), files = DesktopCloseFiles()
        f.app.lifecycle.files = files
        f.editor.password = UUID().uuidString; f.editor.remember = true; f.editor.forgetExisting = true
        let request = f.app.requestWindowCloseReview(), prompt = try XCTUnwrap(f.review.prompt)
        let wait = Task { await f.app.lifecycle.freezeAfterCloseReview(request, isCurrent: { f.app.isWindowCloseReviewCurrent(request) }) }
        XCTAssertEqual(files.freezeCount, 0)
        f.review.discard(prompt.id)
        rTrue(await wait.value)
        XCTAssertTrue(f.editor.password.isEmpty); XCTAssertFalse(f.editor.remember); XCTAssertFalse(f.editor.forgetExisting)
        XCTAssertNil(f.owner.item); XCTAssertTrue(f.app.isWindowCloseReviewCurrent(request))
        rTrue(await f.app.lifecycle.closeConnections(cancelTransfers: true))
        XCTAssertEqual(files.closeCount, 1); rEqual(await f.repository.applyCount, 0)
        rEqual(await f.credentials.readCount, 0)
        let saved = try rUnwrap(try await f.base.securityMetadata().hosts.first)
        XCTAssertEqual(saved.name, "close fixture", "Discard must not persist the dirty name")
        f.app.finishWindowCloseReview()
    }
    func testCloseSaveNewAndExistingCommitsAndRefreshesBeforeAdmissionThenTransferContinueKeepsSavedConfiguration() async throws {
        for isNew in [false, true] {
            let f = try await fixture(isNew: isNew), files = DesktopCloseFiles()
            files.hasActiveTransfers = true; f.app.lifecycle.files = files
            f.editor.password = UUID().uuidString; f.editor.remember = true
            let request = f.app.requestWindowCloseReview(), prompt = try XCTUnwrap(f.review.prompt)
            rTrue(await f.review.save(prompt.id, security: f.app.security, vault: f.vault))
            XCTAssertNil(f.owner.item); XCTAssertFalse(f.editor.writing); XCTAssertFalse(f.editor.committedAwaitingRefresh)
            XCTAssertEqual(files.freezeCount, 0, "Even successful Save does not freeze until the awaited review is accepted")
            rTrue(await f.app.lifecycle.freezeAfterCloseReview(request, isCurrent: { f.app.isWindowCloseReviewCurrent(request) }))
            rTrue(await f.app.lifecycle.activeTransferSnapshot())
            // Logical transfer prompt substitute: the user chooses Continue, not cleanup.
            f.app.lifecycle.resumeAfterContinue(); f.app.finishWindowCloseReview()
            XCTAssertEqual(files.closeCount, 0); XCTAssertEqual(files.cancelCount, 0); XCTAssertEqual(files.resumeCount, 1)
            let saved = try rUnwrap(try await f.base.securityMetadata().hosts.first)
            XCTAssertEqual(saved.name, "unsaved close draft"); XCTAssertNotNil(saved.credentialRef); XCTAssertTrue(saved.savePasswordAuthorized)
            XCTAssertEqual(f.editor.draft.configuration.credentialRef, saved.credentialRef)
            rEqual(try await f.base.securityMetadata().hosts.count, 1)
            rEqual(await f.credentials.saveCount, 1); rEqual(await f.credentials.readCount, 0); rEqual(await f.repository.applyCount, 1)
        }
    }
    func testPrecommitFailureKeepsOriginalDraftAndPromptThenCancelCannotFreezeOrClose() async throws {
        let f = try await fixture(), files = DesktopCloseFiles(), gate = ReliabilityGate()
        f.app.lifecycle.files = files
        f.editor.password = UUID().uuidString
        let password = f.editor.password, draft = f.editor.draft
        let request = f.app.requestWindowCloseReview(), prompt = try XCTUnwrap(f.review.prompt)
        await f.repository.holdNextApply(gate, fail: true)
        let save = Task { await f.review.save(prompt.id, security: f.app.security, vault: f.vault) }
        await gate.waitForArrival()
        XCTAssertTrue(f.editor.writing); XCTAssertTrue(f.review.saving); XCTAssertNil(request.result)
        XCTAssertFalse(f.review.cancel(prompt.id)); f.review.discard(prompt.id)
        rFalse(await f.review.save(prompt.id, security: f.app.security, vault: f.vault))
        XCTAssertEqual(files.freezeCount, 0)
        await gate.release(); rFalse(await save.value)
        XCTAssertNil(request.result); XCTAssertEqual(f.review.prompt?.id, prompt.id)
        XCTAssertEqual(f.editor.draft, draft); XCTAssertEqual(f.editor.password, password); XCTAssertNotNil(f.editor.issue)
        XCTAssertTrue(f.review.cancel(prompt.id))
        rFalse(await f.app.lifecycle.freezeAfterCloseReview(request, isCurrent: { f.app.isWindowCloseReviewCurrent(request) }))
        XCTAssertEqual(files.freezeCount, 0); XCTAssertEqual(files.closeCount, 0)
        rEqual(try await f.base.securityMetadata().hosts.first?.name, "close fixture")
        rEqual(await f.credentials.readCount, 0)
        f.app.finishWindowCloseReview()
    }
    func testCloseSaveCommittedReadFailureRetriesReadOnlyOrClosesAlreadyCommittedWithoutDuplicateWrites() async throws {
        for isNew in [false, true] {
            for retry in [false, true] {
                let f = try await fixture(isNew: isNew)
                f.editor.password = UUID().uuidString; f.editor.remember = true
                let request = f.app.requestWindowCloseReview(), prompt = try XCTUnwrap(f.review.prompt)
                await f.repository.failSnapshots(2); await f.repository.failPostCommitSecurityRead()
                rFalse(await f.review.save(prompt.id, security: f.app.security, vault: f.vault))
                XCTAssertNil(request.result); XCTAssertTrue(f.editor.committedAwaitingRefresh)
                XCTAssertTrue(f.editor.password.isEmpty); XCTAssertFalse(f.editor.canEdit)
                let committed = try rUnwrap(try await f.base.securityMetadata().hosts.first)
                XCTAssertNotNil(committed.credentialRef); XCTAssertEqual(f.editor.draft.configuration.credentialRef, committed.credentialRef)
                if retry {
                    rFalse(await f.review.save(prompt.id, security: f.app.security, vault: f.vault))
                    XCTAssertNil(request.result)
                    rTrue(await f.review.save(prompt.id, security: f.app.security, vault: f.vault))
                } else { f.review.discard(prompt.id) }
                rTrue(await request.wait()); XCTAssertTrue(f.app.isWindowCloseReviewCurrent(request)); XCTAssertNil(f.owner.item)
                rEqual(await f.credentials.saveCount, 1); rEqual(await f.credentials.deleteCount, 0)
                rEqual(await f.credentials.readCount, 0); rEqual(await f.repository.applyCount, 1)
                rEqual(try await f.base.securityMetadata().hosts, [committed])
                f.app.finishWindowCloseReview()
            }
        }
    }
    func testAlreadyWritingRefusesCloseAndResolvesWaiterWithoutSecondSaveOrPermanentFreeze() async throws {
        let f = try await fixture(), gate = ReliabilityGate(), files = DesktopCloseFiles()
        f.app.lifecycle.files = files
        await f.repository.holdNextApply(gate, fail: true)
        let save = Task { await f.editor.save(security: f.app.security, vault: f.vault) }
        await gate.waitForArrival()
        let request = f.app.requestWindowCloseReview()
        XCTAssertEqual(f.review.prompt?.kind, .writing); XCTAssertEqual(f.editor.issue?.code, "host.closeWriting")
        rFalse(await f.app.lifecycle.freezeAfterCloseReview(request, isCurrent: { f.app.isWindowCloseReviewCurrent(request) }))
        XCTAssertEqual(files.freezeCount, 0); XCTAssertEqual(files.closeCount, 0)
        f.app.finishWindowCloseReview(); XCTAssertNil(f.review.prompt)
        XCTAssertEqual(f.editor.issue?.code, "host.closeWriting", "Finishing a refused global close must leave the editor's busy explanation visible")
        XCTAssertTrue(f.editor.writing); XCTAssertEqual(files.freezeCount, 0); XCTAssertEqual(files.closeCount, 0)
        await gate.release(); rFalse(await save.value)
        XCTAssertTrue(f.editor.canEdit); XCTAssertFalse(f.editor.writing)
        let again = f.app.requestWindowCloseReview(), prompt = try XCTUnwrap(f.review.prompt)
        XCTAssertEqual(prompt.kind, .dirty); XCTAssertTrue(f.review.cancel(prompt.id)); rFalse(await again.wait())
        rEqual(await f.repository.applyCount, 1); rEqual(await f.credentials.readCount, 0)
        f.app.finishWindowCloseReview()
    }
    func testOwnerReplacementDuringSaveRejectsLateSuccessWithoutClosingNewForm() async throws {
        let f = try await fixture(), gate = ReliabilityGate(), files = DesktopCloseFiles()
        f.app.lifecycle.files = files
        let request = f.app.requestWindowCloseReview(), prompt = try XCTUnwrap(f.review.prompt)
        await f.repository.holdNextApply(gate, fail: false)
        let save = Task { await f.review.save(prompt.id, security: f.app.security, vault: f.vault) }
        await gate.waitForArrival()
        f.owner.present("new form"); let newID = try XCTUnwrap(f.owner.item?.id)
        f.editor.deactivate()
        await gate.release(); rFalse(await save.value); rFalse(await request.wait())
        XCTAssertEqual(f.owner.item?.id, newID); XCTAssertFalse(f.app.isWindowCloseReviewCurrent(request))
        f.review.discard(prompt.id)
        rFalse(await f.app.lifecycle.freezeAfterCloseReview(request, isCurrent: { f.app.isWindowCloseReviewCurrent(request) }))
        XCTAssertEqual(files.freezeCount, 0); XCTAssertEqual(files.closeCount, 0)
        let committedName = try await f.base.securityMetadata().hosts.first?.name
        XCTAssertEqual(committedName, "unsaved close draft", "A completed commit is not rolled back")
        f.app.finishWindowCloseReview()
    }
    func testLocalDirtyConfirmationIsReusedForGlobalCloseAndStalePromptCannotAnswerNextAttempt() async throws {
        let f = try await fixture()
        f.review.begin(); let local = try XCTUnwrap(f.review.prompt)
        let first = f.app.requestWindowCloseReview()
        XCTAssertEqual(f.review.prompt?.id, local.id, "Global close joins the visible local confirmation")
        XCTAssertTrue(f.review.cancel(local.id)); rFalse(await first.wait())
        f.app.finishWindowCloseReview()
        let next = f.app.requestWindowCloseReview(), current = try XCTUnwrap(f.review.prompt)
        XCTAssertNotEqual(current.id, local.id)
        f.review.discard(local.id); XCTAssertNil(next.result); XCTAssertEqual(f.owner.item?.id, f.ownerID)
        XCTAssertTrue(f.review.cancel(current.id)); rFalse(await next.wait())
        f.app.finishWindowCloseReview()
    }
    func testCloseReviewHandlersDoNotRetainPresentationOrEditor() async throws {
        let f = try await fixture()
        weak var releasedOwner: PresentationOwner<String>?
        weak var releasedReview: VaultHostCloseReview?
        weak var releasedEditor: VaultHostEditorModel?
        do {
            let owner = PresentationOwner<String>(); owner.present("temporary editor")
            let id = try XCTUnwrap(owner.item?.id)
            let editor = VaultHostEditorModel(draft: f.editor.draft, ownsPresentation: { [weak owner] in owner?.owns(id) == true })
            let review = VaultHostCloseReview(editor: editor, dismiss: { [weak owner] in owner?.dismiss(id) })
            owner.registerWindowCloseReview(id, begin: { [weak review] request in review?.begin(request) }, cancel: { [weak review] in review?.cancelPending() })
            releasedOwner = owner; releasedReview = review; releasedEditor = editor
        }
        XCTAssertNil(releasedOwner); XCTAssertNil(releasedReview); XCTAssertNil(releasedEditor)
    }
    func testPageInvalidationAndShutdownResolveOutstandingPromptWithoutDiscardingDraftOnCancel() async throws {
        for shutdown in [false, true] {
            let f = try await fixture()
            f.editor.password = UUID().uuidString
            let secret = f.editor.password, request = f.app.requestWindowCloseReview()
            if shutdown { f.app.windowClosed() } else { f.owner.setActive(false) }
            rFalse(await request.wait()); XCTAssertFalse(f.app.isWindowCloseReviewCurrent(request))
            XCTAssertNil(f.review.prompt); XCTAssertEqual(f.editor.password, secret)
            f.review.discard(UUID()); XCTAssertEqual(f.editor.password, secret)
        }
    }
    func testVaultHostCloseReviewSaveInvokesAfterDismissOnSheetCloseOnlyAndNotOnWindowClose() async throws {
        // 1) Normal sheet close (request == nil): save must invoke afterDismiss with the saved host.
        let sheetFixture = try await fixture()
        var sheetSavedHosts: [HostConfiguration] = []
        sheetFixture.review.begin()
        let sheetPrompt = try XCTUnwrap(sheetFixture.review.prompt)
        rTrue(await sheetFixture.review.save(
            sheetPrompt.id,
            security: sheetFixture.app.security,
            vault: sheetFixture.vault,
            afterDismiss: { host in sheetSavedHosts.append(host) }
        ))
        XCTAssertEqual(sheetSavedHosts.count, 1)
        XCTAssertEqual(sheetSavedHosts.first?.name, "unsaved close draft")
        XCTAssertNil(sheetFixture.owner.item)

        // 2) Window-close / termination review (request != nil): save must NOT invoke afterDismiss.
        let quitFixture = try await fixture()
        var quitSavedHosts: [HostConfiguration] = []
        let request = quitFixture.app.requestWindowCloseReview()
        let quitPrompt = try XCTUnwrap(quitFixture.review.prompt)
        rTrue(await quitFixture.review.save(
            quitPrompt.id,
            security: quitFixture.app.security,
            vault: quitFixture.vault,
            afterDismiss: { host in quitSavedHosts.append(host) }
        ))
        rTrue(await request.wait())
        XCTAssertTrue(quitSavedHosts.isEmpty, "Window close / app quit save must not run post-dismiss page routing")
        XCTAssertNil(quitFixture.owner.item)
        quitFixture.app.finishWindowCloseReview()
    }
}

@MainActor private struct DesktopCloseFixture {
    let base: AppRepository
    let repository: ReliabilityFaultRepository
    let credentials: FakeCredentials
    let app: AppModel
    let vault: VaultDesktopModel
    let owner: PresentationOwner<String>
    let ownerID: UUID
    let editor: VaultHostEditorModel
    let review: VaultHostCloseReview
}
/// Files/transfer decision substitute only; no SFTP service, job worker or network.
@MainActor private final class DesktopCloseFiles: FilesWindowLifecycle {
    var hasActiveTransfers = false
    var hasPendingOperations = false
    var freezeCount = 0, resumeCount = 0, closeCount = 0, cancelCount = 0
    func freezeTransferAdmission() { freezeCount += 1 }
    func resumeTransferAdmission() { resumeCount += 1 }
    func beginWindowClose() { cancelCount += 1 }
    func closeForWindow() async { closeCount += 1 }
    func beginTermination() {}
}

@MainActor private final class ReliabilityRecordingRouter: SessionRouting {
    private(set) var requests: [SessionRequest] = []
    func open(_ request: SessionRequest) -> SessionRouteResult { requests.append(request); return .transportUnavailable(request) }
    func closeAll() {}
}
actor ReliabilityGate {
    private var arrived = false
    private var pending: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    func suspend() async { arrived = true; observer?.resume(); observer = nil; await withCheckedContinuation { pending = $0 } }
    func waitForArrival() async { if !arrived { await withCheckedContinuation { observer = $0 } } }
    func release() { pending?.resume(); pending = nil }
}
private actor ReliabilityFaultRepository: AppRepositoryProtocol {
    let base: AppRepository
    private var snapshotFailures = 0
    private var postCommitFailure = false
    private var securityFailure = false
    private var hold: (ReliabilityGate, Bool)?
    private(set) var applyCount = 0
    init(base: AppRepository) { self.base = base }
    func failSnapshots(_ count: Int) { snapshotFailures = count }
    func failPostCommitSecurityRead() { postCommitFailure = true }
    func holdNextApply(_ gate: ReliabilityGate, fail: Bool) { hold = (gate, fail) }
    func snapshot(query: HostQuery) async throws -> AppSnapshot {
        if snapshotFailures > 0 { snapshotFailures -= 1; throw RepositoryError.databaseBusy }
        return try await base.snapshot(query: query)
    }
    func apply(_ changes: [RepositoryChange]) async throws {
        applyCount += 1
        if let (gate, fail) = hold { hold = nil; await gate.suspend(); if fail { throw RepositoryError.databaseBusy } }
        try await base.apply(changes)
        if postCommitFailure { postCommitFailure = false; securityFailure = true }
    }
    func securityMetadata() async throws -> SecurityMetadata {
        if securityFailure { securityFailure = false; throw RepositoryError.databaseBusy }
        return try await base.securityMetadata()
    }
    func copyHost(id: UUID) async throws -> HostConfiguration { try await base.copyHost(id: id) }
    func copyFolder(id: UUID) async throws -> HostFolder { try await base.copyFolder(id: id) }
    func close() {}
}
private func rEqual<T: Equatable>(_ a: T, _ b: T, file: StaticString = #filePath, line: UInt = #line) { XCTAssertEqual(a, b, file: file, line: line) }
private func rTrue(_ value: Bool, file: StaticString = #filePath, line: UInt = #line) { XCTAssertTrue(value, file: file, line: line) }
private func rFalse(_ value: Bool, file: StaticString = #filePath, line: UInt = #line) { XCTAssertFalse(value, file: file, line: line) }
private func rUnwrap<T>(_ value: T?, file: StaticString = #filePath, line: UInt = #line) throws -> T { try XCTUnwrap(value, file: file, line: line) }
