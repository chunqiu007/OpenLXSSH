import AppKit
import Darwin
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHFiles

@MainActor final class OpenLXSSHAppTests: XCTestCase {
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: url) }
        return url
    }
    private func repository() throws -> (AppRepository, URL) {
        let directory = try temporaryDirectory()
        return (AppRepository(location: .isolated(directory)), directory)
    }
    private func sample(_ name: String = "测试主机") -> HostConfiguration {
        HostConfiguration(name: name, address: "unit.invalid", username: "fixture")
    }

    func testFixedWorkspaceRoutingCommandsAndConnectionCatalog() async throws {
        let (repository, _) = try repository()
        let model = AppModel(repository: repository)
        let first = sample("first"), second = sample("second")
        XCTAssertTrue(awaiting: await model.saveHost(first, isNew: true))
        XCTAssertTrue(awaiting: await model.saveHost(second, isNew: true))
        model.search = "first"
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertEqual(model.hosts.map(\.id), [first.id])
        XCTAssertEqual(Set(model.connectionHosts.map(\.id)), Set([first.id, second.id]))
        XCTAssertEqual(model.workspacePage, .vault)
        model.showWorkspace(.sftp)
        XCTAssertEqual(model.workspacePage, .sftp)
        XCTAssertTrue(model.sessions.tabs.isEmpty)
        let closedSession = await model.closeCurrentWorkspace()
        XCTAssertFalse(closedSession)
        XCTAssertEqual(model.workspacePage, .sftp)
        model.switchWorkspace(by: 1)
        XCTAssertEqual(model.workspacePage, .vault)
        model.switchWorkspace(by: -1)
        XCTAssertEqual(model.workspacePage, .sftp)
        model.sendWorkspaceCommand(.newConnection)
        let firstCommand = model.workspaceCommand
        model.sendWorkspaceCommand(.newConnection)
        XCTAssertEqual(model.workspaceCommand?.command, .newConnection)
        XCTAssertNotEqual(model.workspaceCommand?.id, firstCommand?.id)
        model.showWorkspace(.session(UUID()))
        XCTAssertEqual(model.workspacePage, .sftp)
        model.windowClosed()
        XCTAssertEqual(model.workspacePage, .vault)
        XCTAssertNil(model.workspaceCommand)
        await model.files.closeForWindow(); try await repository.close()
    }

    func testSearchConsumerAndQueueNavigationAreExplicitAndPreserveManager() async throws {
        let (repository, _) = try repository()
        let model = AppModel(repository: repository)
        XCTAssertTrue(model.sendWorkspaceCommand(.search))
        let focus = model.hostSearchFocusRequest
        XCTAssertNotNil(focus)
        XCTAssertTrue(model.sendWorkspaceCommand(.search))
        XCTAssertNotEqual(model.hostSearchFocusRequest, focus)
        let command = model.workspaceCommand
        let manager = model.files.manager, controller = model.files
        model.showWorkspace(.sftp)
        XCTAssertFalse(model.canSearchWorkspace)
        XCTAssertFalse(model.sendWorkspaceCommand(.search))
        XCTAssertEqual(model.workspaceCommand, command)
        for visible in [false, true] {
            model.files.tasksVisible = visible
            model.showWorkspace(.vault)
            model.showTransferTasks()
            XCTAssertEqual(model.workspacePage, .sftp)
            XCTAssertTrue(model.files.tasksVisible)
            XCTAssertTrue(model.files === controller)
            XCTAssertTrue(model.files.manager === manager)
        }
        model.returnToVaultFromFiles()
        XCTAssertEqual(model.workspacePage, .vault)
        XCTAssertFalse(model.files.visible)
        XCTAssertTrue(model.files.tasksVisible)
        XCTAssertTrue(model.files.manager === manager)
        await model.files.closeForWindow(); try await repository.close()
    }

    private func connectedFilesModel() async throws -> (AppRepository, AppModel, AppModelFilesConnector, HostConfiguration) {
        let (repository, directory) = try repository()
        let remote = try AppDataLocation.canonical(directory).appendingPathComponent("local-files-only", isDirectory: true)
        try FileManager.default.createDirectory(at: remote, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let connector = AppModelFilesConnector(root: remote)
        let model = AppModel(repository: repository, location: .isolated(directory), filesConnector: connector)
        addTeardownBlock { await model.files.closeForWindow(); try await repository.close() }
        let original = sample("connected snapshot A")
        XCTAssertTrue(awaiting: await model.saveHost(original, isNew: true))
        model.selectedHostID = original.id; model.showWorkspace(.sftp)
        await model.files.waitUntilCurrentWorkCompletes()
        model.files.connect(.init(primary: .manual(.init(utf8: UUID().uuidString))))
        await model.files.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.files.state, .ready)
        return (repository, model, connector, original)
    }

    func testSFTPWorkspaceEntryKeepsCurrentCoreEditPendingUntilExplicitReconnect() async throws {
        let (repository, model, connector, original) = try await connectedFilesModel()
        let manager = model.files.manager, context = try model.files.transferContext(upload: false)
        var changed = original; changed.port += 1; changed.username = "updated-B"
        try await repository.apply([.updateHost(changed)])
        XCTAssertTrue(awaiting: await model.reload())
        for _ in 0..<3 {
            model.showWorkspace(.vault); model.showWorkspace(.sftp)
            XCTAssertEqual(model.files.issue?.code, "files.hostChanged")
            XCTAssertEqual(model.files.selectedHost, original)
            XCTAssertEqual(model.files.state, .ready)
            XCTAssertTrue(model.files.manager === manager)
            XCTAssertEqual(try model.files.transferContext(upload: false).serviceID, context.serviceID)
        }
        let before = await connector.hosts
        XCTAssertEqual(before, [original])
        model.files.cancelCurrent(); await model.files.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.files.selectedHost, changed)
        model.files.connect(.init(primary: .manual(.init(utf8: UUID().uuidString))))
        await model.files.waitUntilCurrentWorkCompletes()
        let after = await connector.hosts
        XCTAssertEqual(after, [original, changed])
        XCTAssertEqual(model.files.state, .ready)
    }

    func testOnlyActualCoreReversionClearsSFTPConfigurationWarning() async throws {
        let (repository, model, connector, original) = try await connectedFilesModel()
        let manager = model.files.manager, context = try model.files.transferContext(upload: false)
        var changed = original; changed.port += 1
        try await repository.apply([.updateHost(changed)])
        XCTAssertTrue(awaiting: await model.reload())
        model.showWorkspace(.vault); model.showWorkspace(.sftp)
        XCTAssertEqual(model.files.issue?.code, "files.hostChanged")
        var reverted = original; reverted.name = "Core really reverted to A"; reverted.isFavorite = true
        try await repository.apply([.updateHost(reverted)])
        XCTAssertTrue(awaiting: await model.reload())
        model.showWorkspace(.vault); model.showWorkspace(.sftp)
        XCTAssertNil(model.files.issue)
        XCTAssertEqual(model.files.selectedHost, reverted)
        XCTAssertTrue(model.files.manager === manager)
        XCTAssertEqual(try model.files.transferContext(upload: false).serviceID, context.serviceID)
        let before = await connector.hosts
        XCTAssertEqual(before, [original])
        model.files.cancelCurrent(); await model.files.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.files.selectedHost, reverted)
        model.files.connect(.init(primary: .manual(.init(utf8: UUID().uuidString))))
        await model.files.waitUntilCurrentWorkCompletes()
        let after = await connector.hosts
        XCTAssertEqual(after, [original, reverted])
    }

    func testHiddenSFTPReloadAndEntryResolveNewestCoreRow() async throws {
        let (repository, model, connector, original) = try await connectedFilesModel()
        let manager = model.files.manager, context = try model.files.transferContext(upload: false)
        model.returnToVaultFromFiles(); XCTAssertFalse(model.files.visible)
        var changed = original; changed.port += 1
        try await repository.apply([.updateHost(changed)])
        model.search = "no-match"
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertTrue(model.hosts.isEmpty)
        XCTAssertFalse(model.files.visible)
        XCTAssertEqual(model.files.issue?.code, "files.hostChanged")
        XCTAssertEqual(model.files.selectedHost, original)
        model.showWorkspace(.sftp)
        XCTAssertEqual(model.files.issue?.code, "files.hostChanged")
        XCTAssertTrue(model.files.manager === manager)
        XCTAssertEqual(try model.files.transferContext(upload: false).serviceID, context.serviceID)
        model.files.cancelCurrent(); await model.files.waitUntilCurrentWorkCompletes()
        model.returnToVaultFromFiles()
        var latest = changed; latest.username = "newest-C"
        try await repository.apply([.updateHost(latest)])
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertFalse(model.files.visible)
        XCTAssertEqual(model.files.selectedHost, latest)
        model.showWorkspace(.sftp)
        XCTAssertEqual(model.files.selectedHost, latest)
        await model.files.waitUntilCurrentWorkCompletes()
        model.files.connect(.init(primary: .manual(.init(utf8: UUID().uuidString))))
        await model.files.waitUntilCurrentWorkCompletes()
        let connected = await connector.hosts
        XCTAssertEqual(connected, [original, latest])
    }

    func testDeletedSFTPRowDoesNotReviveOldSnapshotOrSelectUnrelatedVaultHost() async throws {
        let (repository, model, connector, original) = try await connectedFilesModel()
        let other = sample("unrelated Vault selection")
        try await repository.apply([.insertHost(other), .deleteHost(original.id)])
        model.selectedHostID = other.id
        model.showWorkspace(.vault)
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertNil(model.files.selectedHost)
        XCTAssertEqual(model.files.state, .disconnected)
        model.selectedHostID = nil
        model.showWorkspace(.sftp)
        XCTAssertNil(model.files.selectedHost)
        XCTAssertFalse(model.files.canConnect)
        let connected = await connector.hosts
        XCTAssertEqual(connected, [original])
    }

    func testModalRoutingPolicyBlocksWorkspaceButLeavesTextEditingIndependent() {
        XCTAssertTrue(WorkspaceInteractionContext().allowsWorkspaceActions)
        for context in [WorkspaceInteractionContext(hasAttachedSheet: true),
                        WorkspaceInteractionContext(hasModalWindow: true),
                        WorkspaceInteractionContext(hasOtherKeyWindow: true)] {
            XCTAssertFalse(context.allowsWorkspaceActions)
            XCTAssertFalse(context.allowsWorkspaceSearch)
        }
        let editing = WorkspaceInteractionContext(isEditingText: true)
        XCTAssertTrue(editing.allowsWorkspaceActions)
        XCTAssertFalse(editing.allowsWorkspaceSearch)
    }

    func testNativeWorkspaceContainerResignsFieldEditorAndExcludesHiddenHitTesting() throws {
        _ = NSApplication.shared
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 500, height: 240), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.orderOut(nil); window.contentView = nil }
        let root = NSView(frame: window.contentRect(forFrameRect: window.frame)); window.contentView = root
        let first = NativeWorkspacePageView(frame: root.bounds), second = NativeWorkspacePageView(frame: root.bounds)
        let a = NSTextField(string: "A"), b = NSTextField(string: "B")
        a.frame = NSRect(x: 20, y: 60, width: 200, height: 26); b.frame = a.frame
        first.addSubview(a); second.addSubview(b); root.addSubview(first); root.addSubview(second)
        second.setPageVisible(false)
        window.makeKeyAndOrderFront(nil)
        XCTAssertTrue(window.makeFirstResponder(a))
        let oldEditor = try XCTUnwrap(a.currentEditor())
        XCTAssertTrue(window.firstResponder === oldEditor)
        first.setPageVisible(false); second.setPageVisible(true)
        XCTAssertTrue(first.isHidden)
        XCTAssertNil(first.hitTest(NSPoint(x: 30, y: 70)))
        XCTAssertFalse(first.acceptsFirstResponder)
        XCTAssertNil(a.currentEditor())
        XCTAssertFalse(window.firstResponder === oldEditor)
        XCTAssertTrue(window.makeFirstResponder(b))
        XCTAssertTrue(window.firstResponder === b.currentEditor())
        let editor = try XCTUnwrap(b.currentEditor() as? NSTextView)
        editor.selectAll(nil); editor.insertText("edited B", replacementRange: NSRange(location: NSNotFound, length: 0))
        window.endEditing(for: b)
        XCTAssertEqual(b.stringValue, "edited B")
        XCTAssertEqual(a.stringValue, "A")
        second.setPageVisible(false); first.setPageVisible(true)
        XCTAssertTrue(window.makeFirstResponder(a))
        XCTAssertTrue(window.firstResponder === a.currentEditor())
    }

    func testEmptyStartupHasDefaultsAndDoesNotRoute() async throws {
        let (repository, _) = try repository()
        let router = RecordingRouter()
        let model = AppModel(repository: repository, sessionRouter: router)
        let loaded = await model.reload()
        XCTAssertTrue(loaded)
        XCTAssertTrue(model.hosts.isEmpty)
        XCTAssertTrue(model.folders.isEmpty)
        XCTAssertTrue(model.keys.isEmpty)
        XCTAssertEqual(model.settings.historyLines, 10_000)
        XCTAssertEqual(model.settings.keepaliveInterval, 30)
        XCTAssertTrue(router.requests.isEmpty)
        XCTAssertNil(model.connectionNotice)
        try await repository.close()
    }

    func testViewModelCRUDAndCopyPersistsAcrossReopen() async throws {
        let (repository, directory) = try repository()
        let model = AppModel(repository: repository)
        var host = sample()
        XCTAssertTrue(awaiting: await model.saveHost(host, isNew: true))
        host.name = "已编辑"; host.port = 2222; host.keepaliveInterval = 50
        XCTAssertTrue(awaiting: await model.saveHost(host, isNew: false))
        XCTAssertEqual(model.hosts.first?.port, 2222)
        XCTAssertTrue(awaiting: await model.copyHost(host.id))
        XCTAssertEqual(model.hosts.count, 2)
        let copy = try XCTUnwrap(model.hosts.first { $0.id != host.id })
        XCTAssertEqual(copy.name, "已编辑 副本")
        XCTAssertNil(copy.lastConnectedAt)
        try await repository.close()
        let reopened = AppRepository(location: .isolated(directory))
        let second = AppModel(repository: reopened)
        XCTAssertTrue(awaiting: await second.reload())
        XCTAssertEqual(second.hosts.count, 2)
        XCTAssertTrue(awaiting: await second.deleteHost(host.id))
        XCTAssertEqual(second.hosts.map(\.id), [copy.id])
        try await reopened.close()
    }

    func testFolderRenameCopyAndDeleteUngroupsNotDeletes() async throws {
        let (repository, _) = try repository()
        let model = AppModel(repository: repository)
        var folder = HostFolder(name: "工作")
        XCTAssertTrue(awaiting: await model.saveFolder(folder))
        var host = sample(); host.folderID = folder.id; host.isFavorite = true
        XCTAssertTrue(awaiting: await model.saveHost(host, isNew: true))
        folder.name = "重命名"
        XCTAssertTrue(awaiting: await model.saveFolder(folder))
        XCTAssertTrue(awaiting: await model.copyFolder(folder.id))
        XCTAssertEqual(model.folders.count, 2)
        XCTAssertEqual(model.hosts.count, 2)
        let copiedFolder = try XCTUnwrap(model.folders.first { $0.id != folder.id })
        let copiedHost = try XCTUnwrap(model.hosts.first { $0.folderID == copiedFolder.id })
        XCTAssertNotEqual(copiedHost.id, host.id)
        XCTAssertTrue(copiedHost.isFavorite)
        XCTAssertNil(copiedHost.lastConnectedAt)
        model.selection = .folder(folder.id)
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertTrue(awaiting: await model.deleteFolder(folder.id))
        XCTAssertEqual(model.selection, .all)
        XCTAssertEqual(model.hosts.count, 2)
        XCTAssertNil(model.hosts.first { $0.id == host.id }?.folderID)
        try await repository.close()
    }

    func testFavoriteAndLiteralUnicodeSearchFilters() async throws {
        let (repository, _) = try repository()
        let model = AppModel(repository: repository)
        let first = sample("Café 中文")
        var second = sample("其它"); second.address = "percent%_.invalid"
        XCTAssertTrue(awaiting: await model.saveHost(first, isNew: true))
        XCTAssertTrue(awaiting: await model.saveHost(second, isNew: true))
        XCTAssertTrue(awaiting: await model.favorite(first))
        model.selection = .favorites
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertEqual(model.hosts.map(\.id), [first.id])
        model.search = "CAFE 中"
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertEqual(model.hosts.map(\.id), [first.id])
        model.search = "' OR 1=1 --"
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertTrue(model.hosts.isEmpty)
        model.selection = .all; model.search = "%_"
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertEqual(model.hosts.map(\.id), [second.id])
        try await repository.close()
    }

    func testSettingsPersistentAndUILimitNeverSilentlyClamps() async throws {
        let (repository, directory) = try repository()
        let model = AppModel(repository: repository)
        XCTAssertTrue(awaiting: await model.reload())
        var settings = model.settings
        settings.historyLines = 50_001
        XCTAssertFalse(awaiting: await model.saveSettings(settings))
        XCTAssertEqual(model.issue?.code, "validation.invalid")
        XCTAssertEqual(model.settings.historyLines, 10_000)
        settings.historyLines = 50_000; settings.fontName = "Menlo-Regular"; settings.fontSize = 16
        settings.theme = .dark; settings.keepaliveInterval = 0; settings.keepaliveCountMax = 10
        (settings.foregroundColor, settings.backgroundColor, settings.cursorColor) = ColorPreset.solarized.colors
        XCTAssertTrue(awaiting: await model.saveSettings(settings))
        try await repository.close()
        let reopened = AppRepository(location: .isolated(directory))
        let snapshot = try await reopened.snapshot(query: HostQuery())
        XCTAssertEqual(snapshot.settings, settings)
        XCTAssertEqual(ColorPreset.matching(settings), .solarized)
        settings.foregroundColor = "#AABBCC"
        XCTAssertEqual(ColorPreset.matching(settings), .custom)
        for preset in ColorPreset.allCases where preset != .custom {
            (settings.foregroundColor, settings.backgroundColor, settings.cursorColor) = preset.colors
            XCTAssertEqual(ColorPreset.matching(settings), preset)
        }
        try await reopened.close()
    }

    func testInvalidInputsShowErrorsAndLeaveStoreUnchanged() async throws {
        let (repository, _) = try repository()
        let model = AppModel(repository: repository)
        var host = sample(); host.port = 0
        XCTAssertFalse(awaiting: await model.saveHost(host, isNew: true))
        XCTAssertEqual(model.issue?.code, "validation.invalid")
        XCTAssertTrue(model.hosts.isEmpty)
        var settings = AppSettings(); settings.backgroundColor = "#GG0000"
        XCTAssertFalse(awaiting: await model.saveSettings(settings))
        XCTAssertEqual(model.issue?.code, "validation.invalid")
        XCTAssertEqual(model.settings.backgroundColor, AppSettings().backgroundColor)
        XCTAssertFalse(awaiting: await model.copyHost(UUID()))
        XCTAssertEqual(model.issue?.code, "storage.notFound")
        try await repository.close()
    }

    func testSessionRequestsAndWindowReopenNeverWriteHistory() async throws {
        let (repository, _) = try repository()
        let router = RecordingRouter()
        let model = AppModel(repository: repository, sessionRouter: router)
        let host = sample()
        XCTAssertTrue(awaiting: await model.saveHost(host, isNew: true))
        model.requestSession(hostID: host.id, mode: .reuse)
        model.requestSession(hostID: host.id, mode: .newSession)
        XCTAssertEqual(router.requests, [SessionRequest(hostID: host.id, mode: .reuse), SessionRequest(hostID: host.id, mode: .newSession)])
        model.selectedHostID = host.id; model.search = "测试"; model.selection = .favorites
        model.windowClosed()
        XCTAssertEqual(router.closeCount, 1)
        XCTAssertNil(model.connectionNotice)
        XCTAssertNil(model.selectedHostID)
        XCTAssertEqual(model.selection, .all)
        XCTAssertTrue(model.search.isEmpty)
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertNil(model.hosts.first?.lastConnectedAt)
        XCTAssertEqual(router.requests.count, 2)
        model.requestSession(hostID: UUID(), mode: .reuse)
        XCTAssertEqual(model.issue?.code, "storage.notFound")
        try await repository.close()
    }

    func testRegisteredKeySelectionAndDeletionDoesNotDeleteSharedKey() async throws {
        let (repository, _) = try repository()
        let key = ManagedKeyReference(algorithm: .ed25519)
        try await repository.apply([.registerKey(key)])
        let model = AppModel(repository: repository)
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertEqual(model.keys, [key])
        let host = HostConfiguration(name: "key", address: "key.invalid", username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id)
        XCTAssertTrue(awaiting: await model.saveHost(host, isNew: true))
        XCTAssertTrue(awaiting: await model.copyHost(host.id))
        XCTAssertTrue(awaiting: await model.deleteHost(host.id))
        XCTAssertEqual(model.hosts.first?.keyRef, key.id)
        XCTAssertEqual(model.keys, [key])
        try await repository.close()
    }

    func testHostDraftHasNoNewCredentialAuthorizationAndPreservesReferences() throws {
        for kind in AuthenticationKind.choices {
            var draft = HostDraft(settings: AppSettings())
            draft.changeAuthentication(kind)
            let value = try draft.value()
            XCTAssertEqual(value.authentication, kind)
            XCTAssertNil(value.credentialRef)
            XCTAssertFalse(value.savePasswordAuthorized)
        }
        let ref = UUID()
        let host = HostConfiguration(name: "existing", address: "x.invalid", username: "fixture", credentialRef: ref, savePasswordAuthorized: true)
        var draft = HostDraft(host: host, settings: AppSettings())
        XCTAssertEqual(try draft.value().credentialRef, ref)
        draft.changeAuthentication(.privateKey)
        XCTAssertNil(try draft.value().credentialRef)
        XCTAssertFalse(try draft.value().savePasswordAuthorized)
        draft.port = "22oops"
        XCTAssertThrowsError(try draft.value())
        var settings = SettingsDraft(AppSettings()); settings.history = "100000"
        XCTAssertThrowsError(try settings.validated())
    }

    func testStorageErrorsAreSanitizedAndCanRetry() async throws {
        let repository = FailingRepository()
        let model = AppModel(repository: repository)
        XCTAssertFalse(awaiting: await model.reload())
        XCTAssertEqual(model.issue?.code, "storage.failed")
        XCTAssertFalse(model.issue?.message.contains("DO-NOT-LEAK") ?? true)
        XCTAssertFalse(model.isLoading)
        await repository.recover()
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertTrue(model.didLoad)
        XCTAssertNil(model.issue)
    }

    func testLateSearchResultDoesNotOverwriteNewerResults() async throws {
        let repository = DelayedRepository()
        let model = AppModel(repository: repository)
        model.search = "old"
        let older = Task { await model.reload() }
        try await Task.sleep(for: .milliseconds(30))
        model.search = "new"
        XCTAssertTrue(awaiting: await model.reload())
        _ = await older.value
        XCTAssertEqual(model.hosts.map(\.name), ["new"])
        XCTAssertFalse(model.isLoading)
    }

    func testIsolationDirectoryRejectsSymlinkAndWrongRoot() async throws {
        let directory = try temporaryDirectory()
        let alias = directory.deletingLastPathComponent().appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: directory)
        defer { try? FileManager.default.removeItem(at: alias) }
        XCTAssertThrowsError(try AppDataLocation.isolated(alias).databaseDirectory())
        XCTAssertThrowsError(try AppDataLocation.isolated(directory.appendingPathComponent("nested")).databaseDirectory())
        let repo = AppRepository(location: .isolated(alias))
        let model = AppModel(repository: repo)
        XCTAssertFalse(awaiting: await model.reload())
        XCTAssertEqual(model.issue?.code, "storage.unsafeLocation")
    }

    func testPrivateDataPermissionsAndLongUnicodeCopyNames() async throws {
        let (repository, directory) = try repository()
        let host = sample(String(repeating: "中", count: 85))
        try await repository.apply([.insertHost(host)])
        let copy = try await repository.copyHost(id: host.id)
        XCTAssertLessThanOrEqual(copy.name.utf8.count, 256)
        XCTAssertTrue(copy.name.hasSuffix(" 副本"))
        let data = directory.appendingPathComponent("Data")
        let permissions = try FileManager.default.attributesOfItem(atPath: data.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o700)
        let dbPermissions = try FileManager.default.attributesOfItem(atPath: data.appendingPathComponent("OpenLXSSH.sqlite").path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(dbPermissions?.intValue, 0o600)
        try await repository.close()
    }
}

// Evaluate async results before passing them into XCTest's synchronous autoclosures.
private func XCTAssertTrue(awaiting value: Bool, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertTrue(value, file: file, line: line)
}
private func XCTAssertFalse(awaiting value: Bool, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertFalse(value, file: file, line: line)
}

/// Real local file service only; records model routing, never SSH/SFTP or Keychain.
private actor AppModelFilesConnector: FilesConnecting {
    let root: URL
    private(set) var hosts: [HostConfiguration] = []
    init(root: URL) { self.root = root }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        try token.check()
        guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "app-model-local-stale") }
        hosts.append(request.host)
        return try LocalFileService(root: root)
    }
}

@MainActor private final class RecordingRouter: SessionRouting {
    var requests: [SessionRequest] = []
    var closeCount = 0
    func open(_ request: SessionRequest) -> SessionRouteResult { requests.append(request); return .transportUnavailable(request) }
    func closeAll() { closeCount += 1 }
}

private actor FailingRepository: AppRepositoryProtocol {
    var fail = true
    func recover() { fail = false }
    func snapshot(query: HostQuery) throws -> AppSnapshot {
        if fail { throw NSError(domain: "DO-NOT-LEAK", code: 1, userInfo: [NSLocalizedDescriptionKey: "DO-NOT-LEAK"]) }
        return AppSnapshot(hosts: [], folders: [], keys: [], settings: AppSettings())
    }
    func apply(_ changes: [RepositoryChange]) throws {}
    func copyHost(id: UUID) throws -> HostConfiguration { throw RepositoryError.notFound }
    func copyFolder(id: UUID) throws -> HostFolder { throw RepositoryError.notFound }
    func close() {}
}
private actor DelayedRepository: AppRepositoryProtocol {
    func snapshot(query: HostQuery) async throws -> AppSnapshot {
        if query.search == "old" { try await Task.sleep(for: .milliseconds(150)) }
        return AppSnapshot(hosts: [HostConfiguration(name: query.search, address: "test.invalid", username: "fixture")], folders: [], keys: [], settings: AppSettings())
    }
    func apply(_ changes: [RepositoryChange]) throws {}
    func copyHost(id: UUID) throws -> HostConfiguration { throw RepositoryError.notFound }
    func copyFolder(id: UUID) throws -> HostFolder { throw RepositoryError.notFound }
    func close() {}
}
