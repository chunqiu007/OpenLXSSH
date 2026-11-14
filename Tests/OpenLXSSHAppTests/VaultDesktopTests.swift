import Foundation
import XCTest
import OpenLXSSHCore

@MainActor final class VaultDesktopTests: XCTestCase {
    private func preferences() throws -> UserDefaults {
        let name = "OpenLXSSH.Vault.Tests." + UUID().uuidString
        let value = try XCTUnwrap(UserDefaults(suiteName: name))
        addTeardownBlock { value.removePersistentDomain(forName: name) }
        return value
    }
    private func sample(_ name: String = "sample") -> HostConfiguration { HostConfiguration(name: name, address: "test.invalid", username: "CaseSensitive") }
    func testLateQueryCannotReplaceNewerSnapshotAndFailureRetainsSuccess() async throws {
        let repository = VaultDesktopFakeRepository()
        let model = VaultDesktopModel(repository: repository, defaults: try preferences())
        model.search = "old"
        let old = Task { await model.load() }
        try await Task.sleep(for: .milliseconds(20))
        model.search = "new"
        let loaded = await model.load()
        XCTAssertTrue(loaded)
        _ = await old.value
        XCTAssertEqual(model.hosts.map(\.name), ["new"])
        await repository.failNextRead()
        let failed = await model.load()
        XCTAssertFalse(failed)
        XCTAssertEqual(model.hosts.map(\.name), ["new"])
        XCTAssertNotNil(model.issue)
        XCTAssertTrue(model.didLoad)
        XCTAssertFalse(model.isLoading)
    }
    func testSelectionRangeCommandAllAndConnectionTargetRemainExplicit() async throws {
        let hosts = [sample("A"), sample("B"), sample("C"), sample("D")]
        let repository = VaultDesktopFakeRepository(hosts: hosts)
        let model = VaultDesktopModel(repository: repository, defaults: try preferences())
        _ = await model.load()
        model.choose(hosts[1].id)
        XCTAssertEqual(model.selectedIDs, [hosts[1].id])
        model.choose(hosts[3].id, shift: true)
        XCTAssertEqual(model.selectedIDs, [hosts[1].id, hosts[2].id, hosts[3].id])
        XCTAssertEqual(model.focusedID, hosts[3].id)
        model.choose(hosts[2].id, command: true)
        XCTAssertEqual(model.selectedIDs, [hosts[1].id, hosts[3].id])
        XCTAssertEqual(model.actionIDs(for: hosts[0].id), [hosts[0].id])
        model.selectAll()
        XCTAssertEqual(model.selectedIDs.count, 4)
        model.moveSelection(by: -1)
        XCTAssertEqual(model.selectedIDs.count, 1)
        XCTAssertNotNil(model.focusedID)
    }
    func testQueryIncludesRecursiveGroupANDTagsAndExplicitSort() throws {
        let model = VaultDesktopModel(repository: VaultDesktopFakeRepository(), defaults: try preferences())
        let group = UUID(), tags: Set<UUID> = [UUID(), UUID()]
        model.search = "%_ Café"; model.section = .folder(group); model.tagFilter = tags
        model.preferences.order = VaultOrdering.recent.rawValue; model.preferences.descending = false
        XCTAssertEqual(model.query.search, "%_ Café")
        XCTAssertEqual(model.query.folder, .folderAndDescendants(group))
        XCTAssertEqual(model.query.tagIDs, tags)
        XCTAssertEqual(model.query.sort, .recentlyConnected)
        XCTAssertEqual(model.query.sortDirection, .ascending)
        model.preferences.descending = true
        XCTAssertEqual(model.query.sortDirection, .descending)
    }
    func testBatchPreparationMutatesNothingAndConfirmationUsesOneApply() async throws {
        var first = sample("A"); first.favoriteOrder = 19
        var second = sample("B"); second.favoriteOrder = -7
        let repository = VaultDesktopFakeRepository(hosts: [first, second])
        let model = VaultDesktopModel(repository: repository, defaults: try preferences())
        _ = await model.load()
        let confirmation = model.favoriteConfirmation(ids: [first.id, second.id], value: true)
        let before = await repository.batches
        XCTAssertTrue(before.isEmpty)
        XCTAssertEqual(confirmation.hostIDs, [first.id, second.id])
        let committed = await model.apply(confirmation.changes)
        XCTAssertTrue(committed)
        let after = await repository.batches
        XCTAssertEqual(after.count, 1)
        XCTAssertEqual(after.first?.count, 2)
        if case .setFavorite(let id, let favorite, let order) = after[0][0] {
            XCTAssertEqual(id, first.id); XCTAssertTrue(favorite); XCTAssertEqual(order, 19)
        } else { XCTFail("Expected one favorite change") }
        if case .setFavorite(_, _, let order) = after[0][1] { XCTAssertEqual(order, -7) }
        else { XCTFail("Expected second favorite change") }
    }
    func testPreferencesPersistOnlyNonSecretWhitelistedFields() throws {
        let defaults = try preferences()
        let model = VaultDesktopModel(repository: VaultDesktopFakeRepository(), defaults: defaults)
        model.search = "search should not persist"
        model.preferences.view = VaultDisplayMode.cards.rawValue
        model.preferences.order = VaultOrdering.recent.rawValue
        model.preferences.inspector = false
        let groupID = UUID(); model.preferences.expandedFolders = [groupID]
        let reopened = VaultDesktopModel(repository: VaultDesktopFakeRepository(), defaults: defaults)
        XCTAssertEqual(reopened.displayMode, .cards)
        XCTAssertEqual(reopened.ordering, .recent)
        XCTAssertFalse(reopened.preferences.inspector)
        XCTAssertEqual(reopened.preferences.expandedFolders, [groupID])
        XCTAssertTrue(reopened.search.isEmpty)
        let data = try XCTUnwrap(defaults.data(forKey: "OpenLXSSH.Vault.Desktop.v1"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["view", "order", "descending", "inspector", "expandedFolders"])
    }
}

extension VaultDesktopTests {
    private func navigationRepository(root suppliedRoot: URL? = nil) throws -> AppRepository {
        let root = try suppliedRoot ?? AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let repository = AppRepository(location: .isolated(root))
        addTeardownBlock { try await repository.close(); try FileManager.default.removeItem(at: root) }
        return repository
    }

    func testWindowTabsVaultRestoresTypedManagementPageSectionAndValidSelection() async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        let repository = try navigationRepository(root: root), defaults = try preferences(), folder = HostFolder(name: "synthetic group")
        var host = sample("synthetic selected host"); host.folderID = folder.id; host.isFavorite = true
        try await repository.apply([.saveFolder(folder), .insertHost(host)])
        for page in VaultManagementPage.allCases {
            for section in [VaultSection.all, .favorites, .ungrouped, .folder(folder.id)] {
                let key = "windowtabs." + UUID().uuidString
                let selected: Set<UUID> = section == .ungrouped ? [] : [host.id]
                let saved = VaultNavigationPreferences(page: page, section: section, selectedIDs: selected, focusedID: selected.first)
                defaults.set(try JSONEncoder().encode(saved), forKey: key + ".navigation.v1")
                let model = VaultDesktopModel(repository: repository, defaults: defaults, preferenceKey: key)
                let loaded = await model.load(); XCTAssertTrue(loaded)
                XCTAssertEqual(model.managementPage, page); XCTAssertEqual(model.section, section)
                XCTAssertEqual(model.selectedIDs, selected); XCTAssertEqual(model.focusedID, selected.first)
                XCTAssertTrue(model.search.isEmpty); XCTAssertTrue(model.tagFilter.isEmpty)
            }
        }
        let model = VaultDesktopModel(repository: repository, defaults: defaults, preferenceKey: "windowtabs.navigation.guard")
        _ = await model.load()
        let owner = PresentationOwner<String>(), registration = UUID()
        model.registerManagementNavigationGuard(owner: registration) { [weak owner] in
            guard let owner, owner.item != nil else { return true }
            _ = owner.attemptClose(); return false
        }
        owner.present("dirty actual editor")
        let id = try XCTUnwrap(owner.item?.id)
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: host, settings: AppSettings()), ownsPresentation: { owner.owns(id) })
        editor.draft.configuration.name = "unsaved name"
        let close = VaultHostCloseReview(editor: editor, dismiss: { owner.dismiss(id) })
        owner.registerClose(id) { close.begin(); return false }
        XCTAssertFalse(model.performManagementNavigation { model.managementPage = .keys })
        let prompt = try XCTUnwrap(close.prompt); XCTAssertTrue(close.cancel(prompt.id))
        XCTAssertEqual(model.managementPage, .hosts); XCTAssertEqual(owner.item?.id, id); XCTAssertTrue(editor.dirty)
        XCTAssertFalse(model.performManagementNavigation { model.section = .favorites })
        XCTAssertEqual(model.section, .all)
        model.requestFocus(VaultHostFocusRequest(hostID: host.id))
        XCTAssertEqual(model.managementPage, .hosts); XCTAssertNil(model.focusedID)
        close.discard(try XCTUnwrap(close.prompt?.id))
        XCTAssertNil(owner.item); XCTAssertTrue(model.performManagementNavigation { model.managementPage = .keys })
        XCTAssertEqual(model.managementPage, .keys)
        owner.present("next actual editor")
        let nextID = try XCTUnwrap(owner.item?.id)
        let next = VaultHostEditorModel(draft: VaultHostDraft(host: host, settings: AppSettings()), ownsPresentation: { owner.owns(nextID) })
        next.draft.configuration.name = "saved navigation name"
        let security = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: FakeCredentials())
        let review = VaultHostCloseReview(editor: next, dismiss: { owner.dismiss(nextID) })
        owner.registerClose(nextID) { review.begin(); return false }
        XCTAssertFalse(model.performManagementNavigation { model.managementPage = .trust })
        let saved = await review.save(try XCTUnwrap(review.prompt?.id), security: security, vault: model)
        XCTAssertTrue(saved); XCTAssertNil(owner.item); XCTAssertEqual(model.managementPage, .keys)
        XCTAssertTrue(model.performManagementNavigation { model.managementPage = .trust })
        XCTAssertEqual(model.managementPage, .trust)
        owner.present("replacement")
        let replacement = try XCTUnwrap(owner.item?.id)
        owner.registerClose(replacement) { false }; owner.dismiss(nextID)
        XCTAssertFalse(model.performManagementNavigation { model.managementPage = .hosts })
        XCTAssertEqual(owner.item?.id, replacement); XCTAssertEqual(model.managementPage, .trust)
        model.clearManagementNavigationGuard(owner: UUID())
        XCTAssertFalse(model.performManagementNavigation { model.section = .favorites })
        model.clearManagementNavigationGuard(owner: registration); owner.invalidate(); editor.deactivate(); next.deactivate()
        try await security.close()
    }

    func testWindowTabsVaultInvalidFolderSelectionAndMalformedNavigationRecoverToAll() async throws {
        let repository = try navigationRepository(), defaults = try preferences(), host = sample("current")
        try await repository.apply([.insertHost(host)])
        let key = "windowtabs.invalid", deleted = UUID()
        defaults.set(try JSONEncoder().encode(VaultNavigationPreferences(page: .hosts, section: .folder(deleted), selectedIDs: [deleted], focusedID: deleted)), forKey: key + ".navigation.v1")
        let model = VaultDesktopModel(repository: repository, defaults: defaults, preferenceKey: key)
        let loaded = await model.load(); XCTAssertTrue(loaded)
        XCTAssertEqual(model.section, .all); XCTAssertTrue(model.selectedIDs.isEmpty); XCTAssertNil(model.focusedID)
        let corrected = try JSONDecoder().decode(VaultNavigationPreferences.self, from: XCTUnwrap(defaults.data(forKey: key + ".navigation.v1")))
        XCTAssertEqual(corrected.section, .all); XCTAssertNil(corrected.folderID); XCTAssertTrue(corrected.selectedIDs.isEmpty)
        for payload in ["not json", "{\"page\":\"terminal\",\"section\":\"all\",\"selectedIDs\":[]}", "{\"page\":\"hosts\",\"section\":\"folder\",\"folderID\":\"not-a-uuid\",\"selectedIDs\":[]}"] {
            defaults.set(Data(payload.utf8), forKey: key + ".navigation.v1")
            let recovered = VaultDesktopModel(repository: repository, defaults: defaults, preferenceKey: key)
            XCTAssertEqual(recovered.managementPage, .hosts); XCTAssertEqual(recovered.section, .all)
            XCTAssertNil(defaults.data(forKey: key + ".navigation.v1"))
            let read = await recovered.load(); XCTAssertTrue(read)
            XCTAssertTrue(recovered.selectedIDs.isEmpty); XCTAssertNil(recovered.focusedID)
        }
    }

    func testWindowTabsVaultFailedFirstCatalogDoesNotDiscardUnvalidatedSavedIDs() async throws {
        let host = sample("valid after retry"), repository = VaultDesktopFakeRepository(hosts: [host]), defaults = try preferences()
        let key = "windowtabs.readfailure", missing = UUID()
        let saved = VaultNavigationPreferences(page: .keys, section: .all, selectedIDs: [host.id, missing], focusedID: host.id)
        let original = try JSONEncoder().encode(saved)
        defaults.set(original, forKey: key + ".navigation.v1")
        let model = VaultDesktopModel(repository: repository, defaults: defaults, preferenceKey: key)
        await repository.failNextRead()
        let failed = await model.load(); XCTAssertFalse(failed)
        XCTAssertEqual(defaults.data(forKey: key + ".navigation.v1"), original)
        XCTAssertTrue(model.selectedIDs.isEmpty); XCTAssertEqual(model.managementPage, .keys)
        let loaded = await model.load(); XCTAssertTrue(loaded)
        XCTAssertEqual(model.selectedIDs, [host.id]); XCTAssertEqual(model.focusedID, host.id)
        let corrected = try JSONDecoder().decode(VaultNavigationPreferences.self, from: XCTUnwrap(defaults.data(forKey: key + ".navigation.v1")))
        XCTAssertEqual(corrected.selectedIDs, [host.id]); XCTAssertEqual(corrected.page, .keys)
    }

    func testWindowTabsVaultPersistenceContainsOnlyEnumAndUUIDNeverQueryOrDisplayText() async throws {
        let host = sample("display label must not persist"), repository = VaultDesktopFakeRepository(hosts: [host]), defaults = try preferences()
        let key = "windowtabs.allowlist", model = VaultDesktopModel(repository: repository, defaults: defaults, preferenceKey: key)
        let loaded = await model.load(); XCTAssertTrue(loaded)
        model.choose(host.id); model.managementPage = .trust
        model.search = "synthetic query not persisted"; model.tagFilter = [UUID()]
        let data = try XCTUnwrap(defaults.data(forKey: key + ".navigation.v1"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["page", "section", "selectedIDs", "focusedID"])
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertFalse(text.contains(host.name)); XCTAssertFalse(text.contains(host.address)); XCTAssertFalse(text.contains(host.username)); XCTAssertFalse(text.contains(model.search))
        let restored = VaultDesktopModel(repository: repository, defaults: defaults, preferenceKey: key)
        XCTAssertEqual(restored.managementPage, .trust); XCTAssertTrue(restored.search.isEmpty); XCTAssertTrue(restored.tagFilter.isEmpty)
        restored.requestFocus(VaultHostFocusRequest(hostID: host.id))
        XCTAssertEqual(restored.managementPage, .hosts); XCTAssertEqual(restored.section, .all)
        let deadline = ContinuousClock.now + .seconds(2)
        while restored.focusedID != host.id, ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertEqual(restored.focusedID, host.id); XCTAssertEqual(restored.selectedIDs, [host.id])
    }
}

@MainActor final class ReliabilityVaultTests: XCTestCase {
    private func fixture() throws -> (URL, AppRepository) {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let repository = AppRepository(location: .isolated(root))
        addTeardownBlock { try await repository.close(); try FileManager.default.removeItem(at: root) }
        return (root, repository)
    }
    private func eventually(_ condition: @MainActor () -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while !condition(), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertTrue(condition())
    }
    func testRepositoryExistentialMetadataStreamEmitsMutationButNotReads() async throws {
        let (_, base) = try fixture()
        let repository: any AppRepositoryProtocol = base
        let stream = await repository.metadataChanges()
        let received = expectation(description: "Existential stream receives committed metadata")
        let reader = Task { @MainActor in
            var iterator = stream.makeAsyncIterator()
            if await iterator.next() != nil { received.fulfill() }
        }
        let host = HostConfiguration(name: "commit", address: "never.invalid", username: "fixture")
        try await repository.apply([.insertHost(host)])
        await fulfillment(of: [received], timeout: 2)
        reader.cancel(); await reader.value
        let value = try await repository.snapshot(query: HostQuery())
        XCTAssertEqual(value.hosts.map(\.id), [host.id])
    }
    func testPublicMutationInvalidatesRetainedVaultAndAppWithoutReloadLoop() async throws {
        let (root, repository) = try fixture(), credentials = FakeCredentials()
        let key = ManagedKeyReference(algorithm: .ed25519)
        let host = HostConfiguration(name: "old", address: "never.invalid", username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id)
        try await repository.apply([.registerKey(key), .insertHost(host)])
        let security = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        addTeardownBlock { try await security.close() }
        let counted = ReliabilityCountingRepository(base: repository)
        let app = AppModel(repository: counted, security: security, location: .isolated(root))
        let vault = VaultDesktopModel(app: app)
        _ = await vault.load()
        XCTAssertEqual(vault.catalog.first?.keyRef, key.id)
        let manager = SecurityViewModel(coordinator: security)
        let unlinked = await manager.unlinkKey(key.id, hostIDs: [host.id]); XCTAssertTrue(unlinked)
        try await eventually { vault.catalog.first?.authentication == .passwordWithMFA && app.connectionHosts.first?.keyRef == nil }
        XCTAssertNil(vault.catalog.first?.keyRef)
        try await repository.apply([.setFavorite(host.id, true), .updateKeyLabel(keyID: key.id, label: "new public label")])
        try await eventually { vault.catalog.first?.isFavorite == true && vault.snapshot?.keys.first?.label == "new public label" }
        try await Task.sleep(for: .milliseconds(80))
        let before = await counted.reads
        try await Task.sleep(for: .milliseconds(100))
        let after = await counted.reads
        XCTAssertEqual(after, before, "Refresh reads must not emit fresh invalidations")
    }
    func testDeletedFiltersRequeryUsingEffectiveQueryAndReadFailureKeepsLastSuccess() async throws {
        let (_, repository) = try fixture(), group = HostFolder(name: "group"), tag = HostTag(name: "tag")
        let host = HostConfiguration(name: "retained", address: "never.invalid", username: "fixture", folderID: group.id)
        try await repository.apply([.saveFolder(group), .addTag(tag), .insertHost(host), .assignTag(hostID: host.id, tagID: tag.id)])
        let wrapper = ReliabilityCountingRepository(base: repository, observe: false)
        let vault = VaultDesktopModel(repository: wrapper)
        vault.section = .folder(group.id); vault.tagFilter = [tag.id]
        let initial = await vault.load(); XCTAssertTrue(initial); XCTAssertEqual(vault.hosts.map(\.id), [host.id])
        try await repository.apply([.deleteFolder(group.id), .deleteTag(tag.id)])
        await wrapper.failUnfilteredRead()
        let failed = await vault.load(); XCTAssertFalse(failed)
        XCTAssertEqual(vault.section, .all); XCTAssertTrue(vault.tagFilter.isEmpty)
        XCTAssertEqual(vault.hosts.map(\.id), [host.id]); XCTAssertEqual(vault.hosts.first?.folderID, group.id)
        let loaded = await vault.load(); XCTAssertTrue(loaded)
        XCTAssertEqual(vault.hosts.map(\.id), [host.id]); XCTAssertNil(vault.hosts.first?.folderID)
        let last = await wrapper.lastQuery
        XCTAssertEqual(last, vault.query); XCTAssertNil(vault.issue)
    }
    func testNavigationGuardRetainsDirtyDraftAndInFlightSaveWithoutReplacingOwner() async throws {
        let (root, repository) = try fixture(), credentials = FakeCredentials()
        let security = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        addTeardownBlock { try await security.close() }
        let app = AppModel(repository: repository, security: security, location: .isolated(root))
        let owner = PresentationOwner<String>(), registration = UUID()
        owner.present("dirty editor"); let id = try XCTUnwrap(owner.item?.id)
        var asked = 0
        owner.registerClose(id) { asked += 1; return false }
        app.registerWorkspaceNavigationGuard(owner: registration) {
            guard owner.item != nil else { return true }
            _ = owner.attemptClose(); return false
        }
        app.showWorkspace(.sftp)
        XCTAssertEqual(app.workspacePage, .vault); XCTAssertEqual(owner.item?.id, id); XCTAssertEqual(asked, 1)
        owner.dismiss(id) // Only the editor's explicit Save/Discard decision may reach this point.
        app.showWorkspace(.sftp); XCTAssertEqual(app.workspacePage, .sftp)
        let newer = UUID()
        app.registerWorkspaceNavigationGuard(owner: newer) { false }
        app.clearWorkspaceNavigationGuard(owner: registration)
        app.showWorkspace(.vault); app.showWorkspace(.sftp)
        XCTAssertEqual(app.workspacePage, .vault, "Old owner must not clear newer navigation protection")
        app.clearWorkspaceNavigationGuard(owner: newer)
    }
    func testMetadataObserversDoNotRetainAppOrVaultOwners() async throws {
        let (root, repository) = try fixture(), credentials = FakeCredentials()
        let security = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        addTeardownBlock { try await security.close() }
        var app: AppModel? = AppModel(repository: repository, security: security, location: .isolated(root))
        var vault: VaultDesktopModel? = VaultDesktopModel(app: try XCTUnwrap(app))
        _ = await vault?.load()
        let released: @MainActor () -> Bool = { [weak app, weak vault] in app == nil && vault == nil }
        app = nil; vault = nil
        try await eventually(released)
    }
    func testOwnerRejectsDelayedImpactDropPickerAndOldCloseAfterNewFormOrRoute() async throws {
        for action in ["folder impact", "tag impact", "drop provider", "key picker completion", "folder save", "tag save", "confirm"] {
            let owner = PresentationOwner<String>(), gate = ReliabilityGate()
            owner.present("old form")
            let old = try XCTUnwrap(owner.item?.id), ticket = owner.capture()
            let callback = Task { @MainActor in
                await gate.suspend()
                if action.hasSuffix("save") || action == "confirm" { owner.dismiss(old) }
                else { _ = owner.present(action, ifCurrent: ticket) }
            }
            await gate.waitForArrival()
            owner.present("new form"); let next = try XCTUnwrap(owner.item?.id)
            owner.registerClose(next) { false }; owner.clearClose(old)
            await gate.release(); await callback.value
            XCTAssertEqual(owner.item?.id, next, action); XCTAssertFalse(owner.attemptClose(), action)
            let routeTicket = owner.capture(); owner.setActive(false); owner.setActive(true)
            XCTAssertFalse(owner.present("late after return", ifCurrent: routeTicket), action)
            XCTAssertNil(owner.item)
        }
    }
}

@MainActor final class DesktopCloseStateTests: XCTestCase {
    func testDuplicateWindowAndQuitUpgradeShareOneReviewAndResetAfterRefusal() async {
        var state = AppCloseRequestState()
        XCTAssertTrue(state.request(.window)); let id = state.id
        XCTAssertFalse(state.request(.window)); XCTAssertEqual(state.id, id)
        XCTAssertFalse(state.request(.quit)); XCTAssertEqual(state.intent, .quit); XCTAssertEqual(state.id, id)
        XCTAssertFalse(state.request(.window)); XCTAssertEqual(state.intent, .quit)
        let registry = WindowCloseReviewRegistry(), owner = UUID()
        var begins = 0, pending: WindowCloseReviewRequest?
        registry.register(owner: owner, begin: { begins += 1; pending = $0 }, cancel: {})
        let first = registry.request(), duplicate = registry.request()
        XCTAssertTrue(first === duplicate); XCTAssertEqual(begins, 1)
        pending?.resolve(false)
        let allowed = await first.wait(); XCTAssertFalse(allowed)
        registry.finishAttempt(); state.reset()
        XCTAssertNil(state.intent); XCTAssertNil(state.id); XCTAssertFalse(state.approved)
        XCTAssertTrue(state.request(.quit)); XCTAssertNotEqual(state.id, id)
        let next = registry.request(); XCTAssertFalse(next === first); XCTAssertEqual(begins, 2)
        next.resolve(true); state.approve(); XCTAssertTrue(state.approved); XCTAssertEqual(state.intent, .quit)
        XCTAssertTrue(registry.isCurrent(next))
        registry.invalidate()
    }
    func testOldOwnerClearAndLateReplyNeverApproveNewOwner() async {
        let registry = WindowCloseReviewRegistry(), oldOwner = UUID(), newOwner = UUID()
        var oldCancelled = 0, newBegins = 0
        registry.register(owner: oldOwner, begin: { _ in }, cancel: { oldCancelled += 1 })
        let old = registry.request()
        registry.register(owner: newOwner, begin: { _ in newBegins += 1 }, cancel: {})
        let refused = await old.wait(); XCTAssertFalse(refused); XCTAssertEqual(oldCancelled, 1)
        registry.clear(owner: oldOwner)
        let new = registry.request(); XCTAssertEqual(newBegins, 1)
        old.resolve(true); XCTAssertFalse(registry.isCurrent(old)); XCTAssertNil(new.result)
        new.resolve(true); XCTAssertTrue(registry.isCurrent(new))
        registry.clear(owner: newOwner); XCTAssertFalse(registry.isCurrent(new))
    }
    func testPresentationEpochRejectsLateAnswerAndReplacementAfterExplicitApproval() async throws {
        let owner = PresentationOwner<String>()
        owner.present("old"); let oldID = try XCTUnwrap(owner.item?.id)
        owner.registerWindowCloseReview(oldID, begin: { _ in }, cancel: {})
        let old = WindowCloseReviewRequest(); owner.beginWindowCloseReview(old)
        owner.present("new"); let newID = try XCTUnwrap(owner.item?.id)
        owner.registerWindowCloseReview(newID, begin: { _ in }, cancel: {})
        owner.clearWindowCloseReview(oldID)
        old.resolve(true); let refused = await old.wait(); XCTAssertFalse(refused)
        let current = WindowCloseReviewRequest(); owner.beginWindowCloseReview(current)
        owner.completeWindowCloseReview(current, dismissing: oldID)
        let wrongOwner = await current.wait(); XCTAssertFalse(wrongOwner)
        XCTAssertEqual(owner.item?.id, newID)
        let approved = WindowCloseReviewRequest(); owner.beginWindowCloseReview(approved)
        owner.completeWindowCloseReview(approved, dismissing: newID)
        XCTAssertTrue(approved.isApprovedAndCurrent); XCTAssertNil(owner.item)
        owner.present("later form")
        XCTAssertFalse(approved.isApprovedAndCurrent, "An old approved Save/Discard is not a reusable close capability")
    }
    func testPageDeactivationAndRegistryDeinitResolveOutstandingWaiters() async throws {
        let owner = PresentationOwner<String>(); owner.present("draft")
        let id = try XCTUnwrap(owner.item?.id)
        owner.registerWindowCloseReview(id, begin: { _ in }, cancel: {})
        let pageRequest = WindowCloseReviewRequest(); owner.beginWindowCloseReview(pageRequest)
        owner.setActive(false)
        let pageAllowed = await pageRequest.wait(); XCTAssertFalse(pageAllowed)
        var registry: WindowCloseReviewRegistry? = WindowCloseReviewRegistry()
        registry?.register(owner: UUID(), begin: { _ in }, cancel: {})
        let teardownRequest = try XCTUnwrap(registry?.request())
        registry = nil
        let teardownAllowed = await teardownRequest.wait(); XCTAssertFalse(teardownAllowed)
    }
    func testCancelledWaiterResolvesWithoutAResponderAndCannotLaterApprove() async {
        let request = WindowCloseReviewRequest()
        let waiter = Task { await request.wait() }
        waiter.cancel()
        let allowed = await waiter.value; XCTAssertFalse(allowed)
        request.resolve(true); XCTAssertEqual(request.result, false)
    }
    func testHiddenEmptyVaultReviewApprovesButRouteGenerationChangeInvalidatesIt() {
        let owner = PresentationOwner<String>(); owner.setActive(false)
        let request = WindowCloseReviewRequest(); owner.beginWindowCloseReview(request)
        XCTAssertTrue(request.isApprovedAndCurrent)
        owner.setActive(true); XCTAssertFalse(request.isApprovedAndCurrent)
    }
}

private actor ReliabilityCountingRepository: AppRepositoryProtocol {
    let base: AppRepository
    let observe: Bool
    private(set) var reads = 0
    private(set) var lastQuery: HostQuery?
    private var failUnfiltered = false
    init(base: AppRepository, observe: Bool = true) { self.base = base; self.observe = observe }
    func failUnfilteredRead() { failUnfiltered = true }
    func metadataChanges() async -> AsyncStream<Void> { if observe { return await base.metadataChanges() }; return AsyncStream { $0.finish() } }
    func snapshot(query: HostQuery) async throws -> AppSnapshot {
        reads += 1; lastQuery = query
        if failUnfiltered, query.folder == .all, query.tagIDs.isEmpty { failUnfiltered = false; throw RepositoryError.databaseBusy }
        return try await base.snapshot(query: query)
    }
    func apply(_ changes: [RepositoryChange]) async throws { try await base.apply(changes) }
    func copyHost(id: UUID) async throws -> HostConfiguration { try await base.copyHost(id: id) }
    func copyFolder(id: UUID) async throws -> HostFolder { try await base.copyFolder(id: id) }
    func close() {}
}

private actor VaultDesktopFakeRepository: AppRepositoryProtocol {
    private var hosts: [HostConfiguration]
    private var failRead = false
    private(set) var batches: [[RepositoryChange]] = []
    init(hosts: [HostConfiguration] = []) { self.hosts = hosts }
    func failNextRead() { failRead = true }
    func snapshot(query: HostQuery) async throws -> AppSnapshot {
        if failRead { failRead = false; throw RepositoryError.databaseBusy }
        if query.search == "old" { try await Task.sleep(for: .milliseconds(120)) }
        let values = hosts.isEmpty ? [HostConfiguration(name: query.search, address: "test.invalid", username: "fixture")] : hosts
        return AppSnapshot(hosts: values, folders: [], keys: [], settings: AppSettings(), allHosts: values)
    }
    func apply(_ changes: [RepositoryChange]) { batches.append(changes) }
    func copyHost(id: UUID) throws -> HostConfiguration { throw RepositoryError.notFound }
    func copyFolder(id: UUID) throws -> HostFolder { throw RepositoryError.notFound }
    func close() {}
}
