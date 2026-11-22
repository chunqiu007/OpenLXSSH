import AppKit
import Darwin
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHTransport
import OpenLXSSHFiles
import SwiftUI

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
    private func preferenceReviewResult(_ request: WindowCloseReviewRequest) async -> Bool {
        let completed = expectation(description: "preference close review resolved")
        let waiter = Task { let value = await request.wait(); completed.fulfill(); return value }
        await fulfillment(of: [completed], timeout: 2)
        // Also release the exact continuation after a failed bounded expectation.
        request.cancel()
        return await waiter.value
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
        let firstRequest = try XCTUnwrap(model.workspaceCommand)
        XCTAssertNil(model.hostSearchFocusRequest, "The current visible subpage owns focus consumption")
        XCTAssertTrue(model.focusHostSearch(for: firstRequest))
        let focus = model.hostSearchFocusRequest
        XCTAssertNotNil(focus)
        XCTAssertTrue(model.sendWorkspaceCommand(.search))
        XCTAssertFalse(model.focusHostSearch(for: firstRequest), "An old command cannot refocus a later page")
        XCTAssertTrue(model.focusHostSearch(for: try XCTUnwrap(model.workspaceCommand)))
        XCTAssertNotEqual(model.hostSearchFocusRequest, focus)
        let latestFocus = model.hostSearchFocusRequest
        let command = model.workspaceCommand
        let manager = model.files.manager, controller = model.files
        model.showWorkspace(.sftp)
        XCTAssertTrue(model.canSearchWorkspace)
        XCTAssertTrue(model.sendWorkspaceCommand(.search))
        XCTAssertNotEqual(model.workspaceCommand, command)
        XCTAssertFalse(model.focusHostSearch(for: try XCTUnwrap(model.workspaceCommand)), "SFTP search cannot steal the Vault host field")
        XCTAssertEqual(model.hostSearchFocusRequest, latestFocus)
        for visible in [false, true] {
            model.files.tasksVisible = visible
            model.showWorkspace(.vault)
            model.showTransferTasks()
            XCTAssertEqual(model.workspacePage, .vault, "Global transfer details do not change the current page")
            XCTAssertTrue(model.files.tasksVisible)
            XCTAssertTrue(model.files === controller)
            XCTAssertTrue(model.files.manager === manager)
        }
        model.returnToVaultFromFiles()
        XCTAssertEqual(model.workspacePage, .vault)
        XCTAssertFalse(model.focusHostSearch(for: try XCTUnwrap(model.workspaceCommand)), "Returning to Vault must not consume an old SFTP search")
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
            XCTAssertFalse(context.allowsWorkspaceFind(hasMarkedText: false))
        }
        let editing = WorkspaceInteractionContext(isEditingText: true)
        XCTAssertTrue(editing.allowsWorkspaceActions)
        XCTAssertFalse(editing.allowsWorkspaceSearch)
        XCTAssertTrue(editing.allowsWorkspaceFind(hasMarkedText: false))
        XCTAssertFalse(editing.allowsWorkspaceFind(hasMarkedText: true), "Find cannot take focus while the input method owns marked text")
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

    func testTerminalPresetLegacyDefaultsAndNonMonospacedPreferenceValidation() async throws {
        let (repository, _) = try repository(), model = AppModel(repository: repository)
        XCTAssertEqual(ColorPreset.matching(AppSettings()), .nord)
        XCTAssertEqual(ColorPreset.nord.colors.0, "#D6D6CC")
        XCTAssertEqual(ColorPreset.nord.colors.1, "#101010")
        var custom = AppSettings(); custom.foregroundColor = "#D8DEE8"
        XCTAssertEqual(ColorPreset.matching(custom), .custom)
        var settings = AppSettings(); settings.fontName = "Helvetica"
        XCTAssertFalse(awaiting: await model.saveSettings(settings))
        XCTAssertEqual(model.issue?.code, "validation.invalid")
        XCTAssertEqual(model.settings.fontName, AppSettings().fontName)
        await model.files.closeForWindow(); try await repository.close()
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

    func testPreferenceCategoryResetChangesOnlyItsFields() throws {
        var settings = AppSettings(); settings.theme = .dark; settings.startupPage = .sftp
        settings.fontName = "Menlo-Regular"; settings.fontSize = 19; settings.historyLines = 4321
        settings.backgroundColor = "#123456"; settings.cursorShape = .bar; settings.cursorBlink = false
        settings.keepaliveInterval = 17; settings.keepaliveCountMax = 7
        let baseline = SettingsDraft(settings)
        var general = baseline; general.reset(.general)
        XCTAssertEqual(general.value.theme, .system); XCTAssertEqual(general.value.startupPage, .vault)
        general.value.theme = settings.theme; general.value.startupPage = settings.startupPage
        XCTAssertEqual(general, baseline)
        var terminal = baseline; terminal.reset(.terminal)
        XCTAssertEqual(terminal.value.cursorShape, .block); XCTAssertTrue(terminal.value.cursorBlink)
        XCTAssertEqual(terminal.value.fontName, AppSettings().fontName)
        XCTAssertEqual(terminal.value.foregroundColor, ColorPreset.nord.colors.0)
        XCTAssertEqual(terminal.value.backgroundColor, ColorPreset.nord.colors.1)
        XCTAssertEqual(terminal.value.cursorColor, ColorPreset.nord.colors.2)
        XCTAssertEqual(terminal.size, "13.0"); XCTAssertEqual(terminal.history, "10000")
        XCTAssertEqual(terminal.value.theme, settings.theme); XCTAssertEqual(terminal.value.startupPage, settings.startupPage)
        XCTAssertEqual(terminal.interval, baseline.interval); XCTAssertEqual(terminal.count, baseline.count)
        var connection = baseline; connection.reset(.connection)
        XCTAssertEqual(connection.interval, "30"); XCTAssertEqual(connection.count, "3")
        connection.interval = baseline.interval; connection.count = baseline.count; XCTAssertEqual(connection, baseline)
        for category in [PreferencesCategory.files, .privacy, .about] {
            var staticCategory = baseline; staticCategory.reset(category); XCTAssertEqual(staticCategory, baseline)
        }
    }

    func testMonospacedPickerAndSharedPreviewApplyUseExactRendererDefaults() throws {
        let choices = TerminalPreferences.availableFonts()
        XCTAssertEqual(choices.first?.name, "SFMono-Regular")
        XCTAssertEqual(Set(choices.map(\.name)).count, choices.count)
        XCTAssertTrue(choices.allSatisfy { TerminalPreferences.font(name: $0.name, size: 13).map(NativeTerminalView.isMonospaced) == true })
        XCTAssertNil(TerminalPreferences.font(name: "Helvetica", size: 13))
        XCTAssertNil(TerminalPreferences.font(name: "OpenLXSSH-Missing-\(UUID())", size: 13))
        let terminal = NativeTerminalView(); defer { terminal.releaseResources() }
        let legacyDraft = SettingsDraft(AppSettings())
        XCTAssertEqual(legacyDraft.value.backgroundColor, ColorPreset.nord.colors.1)
        var distinct = AppSettings(); distinct.backgroundColor = "#123456"
        XCTAssertEqual(SettingsDraft(distinct).value, distinct)
        var settings = AppSettings(); settings.theme = .light
        try TerminalPreferences.apply(settings, to: terminal)
        XCTAssertEqual(terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB), NativeTerminalView.desktopBackground.usingColorSpace(.deviceRGB))
        XCTAssertEqual(terminal.nativeForegroundColor.usingColorSpace(.deviceRGB), NativeTerminalView.desktopForeground.usingColorSpace(.deviceRGB))
        XCTAssertEqual(terminal.font.fontName, NSFont.monospacedSystemFont(ofSize: 13, weight: .regular).fontName)
        settings.backgroundColor = "#112233"; settings.cursorColor = "#445566"; settings.theme = .dark
        try TerminalPreferences.apply(settings, to: terminal)
        XCTAssertEqual(terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB), NSColor(sessionHex: "#112233").usingColorSpace(.deviceRGB))
        XCTAssertEqual(terminal.caretColor.usingColorSpace(.deviceRGB), NSColor(sessionHex: "#445566").usingColorSpace(.deviceRGB))
    }

    func testSettingsSaveFreezesCloseAndDuplicateThenRetainsFailureDraft() async throws {
        let editor = SettingsEditorModel(AppSettings()); editor.draft.size = "18"
        let arrived = expectation(description: "settings save owns frozen draft")
        let gate = PreferenceSaveGate()
        addTeardownBlock { await gate.release() }
        let save = Task { await editor.save { _ in arrived.fulfill(); await gate.suspend(); return false } }
        await fulfillment(of: [arrived], timeout: 2)
        XCTAssertTrue(editor.isWriting); XCTAssertFalse(editor.canEdit); XCTAssertFalse(editor.attemptClose())
        let refused = WindowCloseReviewRequest(); editor.beginCloseReview(refused, dismiss: { XCTFail("Writing editor dismissed") })
        XCTAssertEqual(refused.result, false)
        let duplicate = await editor.save { _ in XCTFail("Duplicate save admitted"); return true }
        XCTAssertFalse(duplicate)
        await gate.release(); XCTAssertFalse(awaiting: await save.value)
        XCTAssertFalse(editor.isWriting); XCTAssertTrue(editor.canEdit); XCTAssertTrue(editor.isDirty)
        XCTAssertEqual(editor.draft.size, "18")
        editor.draft.size = "nan"
        XCTAssertFalse(awaiting: await editor.save { _ in XCTFail("Invalid preference reached repository"); return true })
        XCTAssertEqual(editor.issue?.code, "validation.invalid"); XCTAssertEqual(editor.draft.size, "nan")
    }

    func testSettingsDirtyCancelAndStalePromptNeverDiscardNewOwner() throws {
        let editor = SettingsEditorModel(AppSettings()); editor.draft.size = "18"
        XCTAssertFalse(editor.attemptClose()); let prompt = try XCTUnwrap(editor.prompt)
        editor.cancelClose(prompt.id); XCTAssertNil(editor.prompt); XCTAssertTrue(editor.isDirty)
        XCTAssertFalse(editor.attemptClose()); let next = try XCTUnwrap(editor.prompt)
        XCTAssertNotEqual(next.id, prompt.id); XCTAssertFalse(editor.discard(prompt.id)); XCTAssertEqual(editor.draft.size, "18")
        editor.deactivate(); XCTAssertFalse(editor.discard(next.id)); XCTAssertEqual(editor.draft.size, "18")
        let replacement = SettingsEditorModel(AppSettings()); replacement.draft.size = "21"
        XCTAssertTrue(replacement.isActive); XCTAssertEqual(replacement.draft.size, "21")
        let blockedByReset = WindowCloseReviewRequest()
        replacement.resetReview = PreferencesResetReview(category: .general)
        replacement.beginCloseReview(blockedByReset, dismiss: { XCTFail("Reset review replaced") })
        XCTAssertEqual(blockedByReset.result, false); XCTAssertFalse(replacement.attemptClose())
        replacement.deactivate()
    }

    func testSettingsOverlayCancelKeepsUnderlyingDirtyOwner() async throws {
        let registry = WindowCloseReviewRegistry(), editor = SettingsEditorModel(AppSettings()), base = UUID()
        defer { registry.invalidate(); editor.deactivate() }
        editor.draft.size = "18"; var underlyingReviews = 0
        registry.register(owner: base, begin: { _ in underlyingReviews += 1 }, cancel: {})
        registry.registerPreferences(owner: editor.id, begin: { editor.beginCloseReview($0, dismiss: { XCTFail("Dirty overlay dismissed") }) }, cancel: { editor.cancelClose() })
        let root = registry.request(); let prompt = try XCTUnwrap(editor.prompt)
        registry.register(owner: base, begin: { _ in underlyingReviews += 1 }, cancel: {})
        registry.registerPreferences(owner: editor.id, begin: { editor.beginCloseReview($0, dismiss: {}) }, cancel: { editor.cancelClose() })
        XCTAssertTrue(registry.request() === root); XCTAssertNil(root.result); XCTAssertEqual(editor.prompt?.id, prompt.id)
        editor.cancelClose(prompt.id)
        XCTAssertFalse(awaiting: await preferenceReviewResult(root)); XCTAssertEqual(underlyingReviews, 0)
        registry.finishAttempt(); editor.deactivate(); registry.clearPreferences(owner: editor.id)
        let second = registry.request(); XCTAssertEqual(underlyingReviews, 1)
        registry.clear(owner: base); XCTAssertEqual(second.result, false); registry.invalidate()
    }

    func testSettingsOverlaySaveAndDiscardContinueToUnderlyingRefusalOnlyAfterRemoval() async throws {
        for save in [false, true] {
            let registry = WindowCloseReviewRegistry(), editor = SettingsEditorModel(AppSettings())
            defer { registry.invalidate(); editor.deactivate() }
            editor.draft.size = "18"
            let baseArrived = expectation(description: "underlying dirty guard reached")
            var underlyingReviews = 0
            registry.register(owner: UUID(), begin: { request in
                underlyingReviews += 1; baseArrived.fulfill(); request.resolve(false)
            }, cancel: {})
            registry.registerPreferences(owner: editor.id, begin: { editor.beginCloseReview($0, dismiss: {}) }, cancel: { editor.cancelClose() })
            let root = registry.request(), prompt = try XCTUnwrap(editor.prompt)
            if save {
                XCTAssertFalse(awaiting: await editor.save(reviewID: UUID()) { _ in XCTFail("Stale save prompt admitted"); return true })
                XCTAssertTrue(awaiting: await editor.save(reviewID: prompt.id) { $0.fontSize == 18 })
            }
            else { XCTAssertTrue(editor.discard(prompt.id)) }
            XCTAssertNil(root.result); XCTAssertEqual(underlyingReviews, 0) // still physically mounted
            editor.deactivate(); registry.clearPreferences(owner: editor.id)
            await fulfillment(of: [baseArrived], timeout: 2)
            XCTAssertFalse(awaiting: await preferenceReviewResult(root)); XCTAssertEqual(underlyingReviews, 1)
            XCTAssertFalse(registry.isCurrent(root)); registry.invalidate()
        }
    }

    func testSettingsOverlayApprovedChainInvalidatesWhenEitherOwnerChanges() async throws {
        let registry = WindowCloseReviewRegistry(), editor = SettingsEditorModel(AppSettings())
        defer { registry.invalidate(); editor.deactivate() }
        let base = UUID(), reached = expectation(description: "base approval reached")
        var baseRevision = 0
        registry.register(owner: base, begin: { request in
            request.validateApproval { baseRevision == 0 }; reached.fulfill(); request.resolve(true)
        }, cancel: {})
        registry.registerPreferences(owner: editor.id, begin: { editor.beginCloseReview($0, dismiss: {}) }, cancel: { editor.cancelClose() })
        let root = registry.request(); XCTAssertTrue(editor.closeApproval); XCTAssertNil(root.result)
        editor.deactivate(); registry.clearPreferences(owner: editor.id)
        await fulfillment(of: [reached], timeout: 2)
        XCTAssertTrue(awaiting: await preferenceReviewResult(root)); XCTAssertTrue(registry.isCurrent(root))
        editor.draft.size = "24"; XCTAssertFalse(registry.isCurrent(root))
        baseRevision = 1; XCTAssertFalse(registry.isCurrent(root))
        let replacement = SettingsEditorModel(AppSettings()); replacement.draft.size = "25"
        registry.registerPreferences(owner: replacement.id, begin: { replacement.beginCloseReview($0, dismiss: {}) }, cancel: { replacement.cancelClose() })
        XCTAssertFalse(registry.isCurrent(root)); registry.clearPreferences(owner: editor.id)
        let newer = registry.request(); let prompt = try XCTUnwrap(replacement.prompt)
        XCTAssertFalse(editor.discard(prompt.id)); XCTAssertNil(newer.result); XCTAssertEqual(replacement.draft.size, "25")
        editor.cancelClose(); XCTAssertNil(newer.result)
        replacement.cancelClose(prompt.id); XCTAssertFalse(awaiting: await preferenceReviewResult(newer)); registry.invalidate()
    }

    func testSettingsOverlayRealVaultDirtyGuardSurvivesApprovalAndRejectsClose() async throws {
        let registry = WindowCloseReviewRegistry(), owner = PresentationOwner<String>()
        owner.present("host editor"); let hostOwner = try XCTUnwrap(owner.item?.id)
        let host = HostConfiguration(name: "original host", address: "never-connected.invalid", username: "fixture")
        let hostEditor = VaultHostEditorModel(draft: VaultHostDraft(host: host, settings: AppSettings()), ownsPresentation: { owner.owns(hostOwner) })
        hostEditor.draft.configuration.name = "unsaved host name"
        let hostDraft = hostEditor.draft
        let hostReview = VaultHostCloseReview(editor: hostEditor, dismiss: { owner.dismiss(hostOwner) },
            complete: { owner.completeWindowCloseReview($0, dismissing: hostOwner) })
        owner.registerWindowCloseReview(hostOwner, begin: { hostReview.begin($0) }, cancel: { hostReview.cancelPending() })
        let hostArrived = expectation(description: "real dirty Vault guard reached")
        registry.register(owner: UUID(), begin: { request in owner.beginWindowCloseReview(request); hostArrived.fulfill() }, cancel: { owner.cancelWindowCloseReview() })
        let settings = SettingsEditorModel(AppSettings()); settings.draft.size = "18"
        registry.registerPreferences(owner: settings.id, begin: { settings.beginCloseReview($0, dismiss: {}) }, cancel: { settings.cancelClose() })
        defer { registry.invalidate(); settings.deactivate(); hostEditor.deactivate(); owner.invalidate() }
        let root = registry.request(); let settingsPrompt = try XCTUnwrap(settings.prompt)
        XCTAssertNil(hostReview.prompt); XCTAssertTrue(settings.discard(settingsPrompt.id))
        settings.deactivate(); registry.clearPreferences(owner: settings.id)
        await fulfillment(of: [hostArrived], timeout: 2)
        let hostPrompt = try XCTUnwrap(hostReview.prompt); XCTAssertEqual(hostPrompt.kind, .dirty)
        XCTAssertTrue(hostReview.cancel(hostPrompt.id))
        XCTAssertFalse(awaiting: await preferenceReviewResult(root)); XCTAssertFalse(registry.isCurrent(root))
        XCTAssertEqual(hostEditor.draft, hostDraft); XCTAssertEqual(owner.item?.id, hostOwner)
    }

    func testSettingsOverlayRealVaultCancellationNeverReachedWhenSettingsCancel() async throws {
        let registry = WindowCloseReviewRegistry(), owner = PresentationOwner<String>()
        owner.present("host editor"); let id = try XCTUnwrap(owner.item?.id)
        let hostEditor = VaultHostEditorModel(draft: VaultHostDraft(host: sample(), settings: AppSettings()), ownsPresentation: { owner.owns(id) })
        hostEditor.draft.configuration.name = "dirty Vault"
        let review = VaultHostCloseReview(editor: hostEditor, dismiss: { owner.dismiss(id) }, complete: { owner.completeWindowCloseReview($0, dismissing: id) })
        owner.registerWindowCloseReview(id, begin: { review.begin($0) }, cancel: { review.cancelPending() })
        registry.register(owner: UUID(), begin: { owner.beginWindowCloseReview($0) }, cancel: { owner.cancelWindowCloseReview() })
        let settings = SettingsEditorModel(AppSettings()); settings.draft.size = "22"
        registry.registerPreferences(owner: settings.id, begin: { settings.beginCloseReview($0, dismiss: {}) }, cancel: { settings.cancelClose() })
        defer { registry.invalidate(); settings.deactivate(); hostEditor.deactivate(); owner.invalidate() }
        let request = registry.request(), prompt = try XCTUnwrap(settings.prompt)
        settings.cancelClose(prompt.id)
        XCTAssertFalse(awaiting: await preferenceReviewResult(request)); XCTAssertNil(review.prompt)
        XCTAssertEqual(owner.item?.id, id); XCTAssertTrue(hostEditor.dirty); XCTAssertTrue(settings.isDirty)
    }

    func testStartupManagementPreferencePersistsOnlyFixedPageAndNeverConnects() async throws {
        let suite = "OpenLXSSH.PreferencesTests." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite)); defer { defaults.removePersistentDomain(forName: suite) }
        let (repository, directory) = try repository(), router = RecordingRouter()
        var settings = AppSettings(); settings.startupPage = .lastManagement
        try await repository.apply([.saveSettings(settings)])
        defaults.set("session-secret-answer", forKey: ManagementPagePreferences.key)
        XCTAssertEqual(ManagementPagePreferences.startup(.lastManagement, defaults: defaults), .vault)
        ManagementPagePreferences.record(.sftp, defaults: defaults)
        ManagementPagePreferences.record(.session(UUID()), defaults: defaults)
        let model = AppModel(repository: repository, sessionRouter: router, location: .isolated(directory), preferencesDefaults: defaults)
        XCTAssertTrue(awaiting: await model.reload()); XCTAssertEqual(model.workspacePage, .sftp)
        XCTAssertTrue(model.sessions.tabs.isEmpty); XCTAssertTrue(router.requests.isEmpty); XCTAssertNil(model.connectionNotice)
        XCTAssertEqual(defaults.string(forKey: ManagementPagePreferences.key), "sftp")
        model.windowClosed(); XCTAssertEqual(defaults.string(forKey: ManagementPagePreferences.key), "sftp")
        await model.files.closeForWindow(); try await repository.close()
    }

    func testDiagnosticPreviewCopiesOnlyApprovedCategoriesToIndependentPasteboard() throws {
        var settings = AppSettings(); settings.fontName = "/private/path/NOT-PUBLIC"; settings.backgroundColor = "#123456"
        let snapshot = PublicDiagnosticSnapshot(version: "1.2.3", build: "42", operatingSystem: "macOS synthetic · arm64", hostCount: 4, keyCount: 2, sessionCount: 1, settings: settings)
        let versionOnly = snapshot.preview(categories: [.version])
        XCTAssertTrue(versionOnly.contains("1.2.3")); XCTAssertTrue(versionOnly.contains("42"))
        XCTAssertFalse(versionOnly.contains("macOS")); XCTAssertFalse(versionOnly.contains("数量")); XCTAssertFalse(versionOnly.contains("终端："))
        let all = snapshot.preview(categories: Set(DiagnosticCategory.allCases))
        XCTAssertTrue(all.contains("macOS synthetic")); XCTAssertTrue(all.contains("主机 4")); XCTAssertTrue(all.contains("字号 13.0"))
        XCTAssertFalse(all.contains("NOT-PUBLIC")); XCTAssertFalse(all.contains("#123456")); XCTAssertFalse(all.contains("/private"))
        let board = NSPasteboard.withUniqueName(); defer { board.releaseGlobally() }
        XCTAssertTrue(PublicDiagnosticSnapshot.copy(versionOnly, to: board))
        XCTAssertEqual(board.string(forType: .string), versionOnly)
        XCTAssertEqual(snapshot.preview(categories: []), "未选择任何诊断项目。")
        XCTAssertTrue(DesktopHelp.localDataDescription.contains("Keychain")); XCTAssertTrue(DesktopHelp.shortcuts.contains("⌘W"))
        let missing = DesktopLicense(id: "missing", title: "synthetic missing", resource: "OpenLXSSH-Missing-\(UUID()).txt")
        XCTAssertTrue(DesktopHelp.licenseText(missing, bundle: Bundle(for: Self.self)).contains("不会从网络补取"))
        let noResources = Bundle(for: Self.self)
        if noResources.url(forResource: "GRDB-LICENSE", withExtension: "txt") == nil {
            let grdb = try XCTUnwrap(DesktopHelp.licenses.first { $0.id == "grdb" })
            XCTAssertTrue(DesktopHelp.licenseText(grdb, bundle: noResources).contains("不会从网络补取"))
        }
    }

    func testSettingsCommittedAfterReadFailureApplyWithoutHostMutation() async throws {
        let repository = PreferencesReadFailureRepository(), directory = try temporaryDirectory()
        let model = AppModel(repository: repository, location: .isolated(directory))
        var settings = AppSettings(); settings.cursorShape = .underline; settings.startupPage = .sftp; settings.fontSize = 19
        XCTAssertTrue(awaiting: await model.saveSettings(settings))
        XCTAssertEqual(model.settings, settings); XCTAssertEqual(model.issue?.code, "storage.busy")
        let persisted = await repository.settings, changes = await repository.writeCount
        XCTAssertEqual(persisted, settings); XCTAssertEqual(changes, 1)
        await model.files.closeForWindow()
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

    func testExplicitReloadCoalescesMetadataReadsAndWaitsForLatestAppliedSFTPAndCRUDState() async throws {
        let (base, directory) = try repository(), original = sample("connected before refresh")
        try await base.apply([.insertHost(original)])
        let controlled = ControlledReloadRepository(base: base)
        let remote = directory.appendingPathComponent("remote")
        try FileManager.default.createDirectory(at: remote, withIntermediateDirectories: false)
        let connector = AppModelFilesConnector(root: remote)
        let model = AppModel(repository: controlled, location: .isolated(directory), filesConnector: connector)
        addTeardownBlock {
            await MainActor.run { model.windowClosed() }
            await controlled.releaseAll(); await model.files.closeForWindow(); try await controlled.close()
        }
        XCTAssertTrue(awaiting: await model.reload())
        model.selectedHostID = original.id; model.showWorkspace(.sftp)
        await model.files.waitUntilCurrentWorkCompletes()
        model.files.connect(.init(primary: .manual(.init(utf8: UUID().uuidString))))
        await model.files.waitUntilCurrentWorkCompletes(); XCTAssertEqual(model.files.state, .ready)
        let firstRead = expectation(description: "explicit read holds its old database snapshot")
        let latestRead = expectation(description: "coalesced worker starts a fresh read after notifications")
        let metadataOne = expectation(description: "first revocation metadata read is independent of held GUI read")
        let metadataTwo = expectation(description: "observer processes another revocation before GUI read drains")
        await controlled.holdNextReads(2)
        await controlled.whenSnapshotStarts(1) { firstRead.fulfill() }
        await controlled.whenSnapshotStarts(2) { latestRead.fulfill() }
        await controlled.whenMetadataReads(1) { metadataOne.fulfill() }
        await controlled.whenMetadataReads(2) { metadataTwo.fulfill() }
        var finished = false
        let explicit = Task { let result = await model.reload(); finished = true; return result }
        await fulfillment(of: [firstRead], timeout: 2)
        var changed = original; changed.port = 2222
        try await controlled.apply([.updateHost(changed)])
        await fulfillment(of: [metadataOne], timeout: 2)
        var latest = changed; latest.username = "latest-user"
        try await controlled.apply([.updateHost(latest)])
        // Entering the second security read proves the observer scheduled the
        // first metadata refresh without awaiting the still-blocked GUI worker.
        await fulfillment(of: [metadataTwo], timeout: 2)
        try await controlled.releaseSnapshot(1)
        await fulfillment(of: [latestRead], timeout: 2)
        XCTAssertFalse(finished); XCTAssertEqual(model.connectionHosts, [original])
        try await controlled.releaseSnapshot(2)
        XCTAssertTrue(awaiting: await explicit.value)
        XCTAssertEqual(model.connectionHosts, [latest]); XCTAssertFalse(model.isLoading)
        XCTAssertEqual(model.files.issue?.code, "files.hostChanged")
        XCTAssertEqual(model.files.selectedHost, original)
        let connected = await connector.hosts; XCTAssertEqual(connected, [original])
        let beforeWrite = await controlled.writeCount
        var saved = latest; saved.name = "committed and refreshed once"
        XCTAssertTrue(awaiting: await model.saveHost(saved, isNew: false))
        XCTAssertEqual(model.connectionHosts, [saved])
        let afterWrite = await controlled.writeCount; XCTAssertEqual(afterWrite, beforeWrite + 1)
    }

    func testCoalescedReloadRejectsChangedQueryAndWindowCloseWithoutApplyingLateRead() async throws {
        let (base, directory) = try repository(), old = sample("old query"), new = sample("new query")
        try await base.apply([.insertHost(old), .insertHost(new)])
        let controlled = ControlledReloadRepository(base: base)
        let model = AppModel(repository: controlled, location: .isolated(directory))
        addTeardownBlock {
            await MainActor.run { model.windowClosed() }
            await controlled.releaseAll(); await model.files.closeForWindow(); try await controlled.close()
        }
        XCTAssertTrue(awaiting: await model.reload())
        await controlled.holdNextReads(1)
        let oldRead = expectation(description: "old query is suspended")
        await controlled.whenSnapshotStarts(1) { oldRead.fulfill() }
        model.search = "old"
        let older = Task { await model.reload() }
        await fulfillment(of: [oldRead], timeout: 2)
        model.search = "new"
        XCTAssertTrue(awaiting: await model.reload())
        XCTAssertFalse(awaiting: await older.value)
        XCTAssertEqual(model.hosts.map(\.id), [new.id]); XCTAssertFalse(model.isLoading)
        await controlled.holdNextReads(1)
        let index = await controlled.nextSnapshotIndex
        let closingRead = expectation(description: "read is held before window close")
        await controlled.whenSnapshotStarts(index) { closingRead.fulfill() }
        let closing = Task { await model.reload() }
        await fulfillment(of: [closingRead], timeout: 2)
        model.windowClosed()
        XCTAssertFalse(awaiting: await closing.value)
        XCTAssertEqual(model.hosts.map(\.id), [new.id]); XCTAssertFalse(model.isLoading)
        let pending = await controlled.pendingReadCount; XCTAssertEqual(pending, 0)
    }

    func testCommittedSecretSaveWithCoalescedReadFailureKeepsSnapshotAndNeverRepeatsWrite() async throws {
        let (base, directory) = try repository(), original = sample("last successful snapshot")
        try await base.apply([.insertHost(original)])
        let controlled = ControlledReloadRepository(base: base), credentials = FakeCredentials()
        let security = SecurityCoordinator(repository: controlled, location: .isolated(directory), credentials: credentials)
        let model = AppModel(repository: controlled, security: security, location: .isolated(directory))
        addTeardownBlock {
            await MainActor.run { model.windowClosed() }
            await controlled.releaseAll(); await model.files.closeForWindow(); try await security.close(); try await controlled.close()
        }
        XCTAssertTrue(awaiting: await model.reload())
        await controlled.failSnapshotReads()
        let saved = sample("new committed host")
        XCTAssertTrue(awaiting: await model.saveHostSecurely(saved, isNew: true,
            password: .remember(.init(utf8: "public disposable in-memory test value"))))
        XCTAssertEqual(model.hosts, [original]); XCTAssertEqual(model.issue?.code, "storage.busy")
        XCTAssertFalse(awaiting: await model.reload())
        XCTAssertEqual(model.hosts, [original]); XCTAssertFalse(model.isLoading)
        let writes = await controlled.writeCount, saves = await credentials.saveCount
        XCTAssertEqual(writes, 1); XCTAssertEqual(saves, 1)
        let persisted = try await base.snapshot(query: HostQuery())
        let committed = try XCTUnwrap(persisted.hosts.first { $0.id == saved.id })
        XCTAssertTrue(committed.savePasswordAuthorized); XCTAssertNotNil(committed.credentialRef)
    }

    func testOldWindowSecurityReadCannotRevokeNewPreparedOwnerButCurrentWindowStillRevokesWithoutGUIRead() async throws {
        let (base, directory) = try repository(), original = sample("old window catalog")
        try await base.apply([.insertHost(original)])
        let controlled = ControlledReloadRepository(base: base), next = sample("new window prepared host")
        let builder = PreparedMetadataBuilder(host: next)
        let model = AppModel(repository: controlled, location: .isolated(directory), nativeCandidateBuilder: builder)
        addTeardownBlock {
            await MainActor.run { model.windowClosed() }
            await controlled.releaseAll(); await model.sessions.closeAll()
            await model.files.closeForWindow(); try await controlled.close()
        }
        XCTAssertTrue(awaiting: await model.reload())
        let oldRead = expectation(description: "old-window security metadata captured before new host exists")
        await controlled.holdNextMetadataRead()
        await controlled.whenMetadataReads(1) { oldRead.fulfill() }
        var renamed = original; renamed.name = "old window committed update"
        try await controlled.apply([.updateHost(renamed)])
        await fulfillment(of: [oldRead], timeout: 2)
        model.windowClosed()
        XCTAssertTrue(awaiting: await model.reload())
        try await controlled.apply([.insertHost(next)])
        XCTAssertTrue(awaiting: await model.reload())
        let intent = VaultTransientConnectionIntent(host: next, secret: .init(utf8: "public disposable prepared test value"))
        let prepared = try await model.prepareTransientConnection(next, intent: intent)
        defer { prepared.cancel() }
        let driver = try XCTUnwrap(builder.driver)
        XCTAssertFalse(intent.consumed); XCTAssertEqual(driver.state, .idle)
        let currentRead = expectation(description: "observer advances past discarded old security response")
        await controlled.whenMetadataReads(2) { currentRead.fulfill() }
        try await controlled.releaseMetadataRead()
        await fulfillment(of: [currentRead], timeout: 2)
        XCTAssertFalse(intent.consumed); XCTAssertEqual(driver.state, .idle)
        XCTAssertTrue(model.sessions.tabs.isEmpty)

        // Bring every subsequent GUI request onto the same current query before
        // holding one. A query change must not suppress current-window revocation.
        model.search = "held current query"
        XCTAssertTrue(awaiting: await model.reload())
        let guiRead = expectation(description: "current GUI snapshot is held independently")
        let heldIndex = await controlled.holdNextSnapshot { guiRead.fulfill() }
        var guiFinished = false
        let gui = Task { let result = await model.reload(); guiFinished = true; return result }
        await fulfillment(of: [guiRead], timeout: 2)
        let revokedRead = expectation(description: "current-window deletion metadata reaches observer")
        let followingRead = expectation(description: "observer passed current revocation while GUI remains held")
        await controlled.whenMetadataReads(3) { revokedRead.fulfill() }
        await controlled.whenMetadataReads(4) { followingRead.fulfill() }
        try await controlled.apply([.deleteHost(next.id)])
        await fulfillment(of: [revokedRead], timeout: 2)
        renamed.name = "current window following notification"
        try await controlled.apply([.updateHost(renamed)])
        await fulfillment(of: [followingRead], timeout: 2)
        XCTAssertFalse(guiFinished)
        XCTAssertTrue(intent.consumed); XCTAssertEqual(driver.state, .closed)
        XCTAssertThrowsError(try prepared.commit())
        XCTAssertTrue(model.sessions.tabs.isEmpty)
        try await controlled.releaseSnapshot(heldIndex)
        XCTAssertTrue(awaiting: await gui.value)
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

extension OpenLXSSHAppTests {
    func testWindowTabsViewportUsesMeasuredBoundsAndTabEdgesForNavigation() async throws {
        let a = UUID(), b = UUID(), c = UUID(), ids = [a, b, c]
        let frames = [a: CGRect(x: 4, y: 0, width: 90, height: 34), b: CGRect(x: 98, y: 0, width: 180, height: 34), c: CGRect(x: 282, y: 0, width: 120, height: 34)]
        let start = WorkspaceTabViewport(visibleRect: CGRect(x: 0, y: 0, width: 220, height: 40), contentWidth: 406)
        XCTAssertFalse(start.canGoBack); XCTAssertTrue(start.canGoForward)
        XCTAssertNil(start.navigationTarget(in: ids, frames: frames, forwards: false))
        XCTAssertEqual(start.navigationTarget(in: ids, frames: frames, forwards: true), b)
        XCTAssertTrue(start.contains(frames[a]!)); XCTAssertFalse(start.contains(frames[b]!))
        let end = WorkspaceTabViewport(visibleRect: CGRect(x: 186, y: 0, width: 220, height: 40), contentWidth: 406)
        XCTAssertTrue(end.canGoBack); XCTAssertFalse(end.canGoForward)
        XCTAssertEqual(end.navigationTarget(in: ids, frames: frames, forwards: false), b)
        XCTAssertNil(end.navigationTarget(in: ids, frames: frames, forwards: true))
        let resized = WorkspaceTabViewport(visibleRect: CGRect(x: 0, y: 0, width: 500, height: 40), contentWidth: 406)
        XCTAssertFalse(resized.canGoBack); XCTAssertFalse(resized.canGoForward); XCTAssertTrue(resized.contains(frames[c]!))
        XCTAssertNil(start.navigationTarget(in: [UUID()], frames: frames, forwards: true))
        try await verifyOwnedWindowTabStrip()
    }

    private func verifyOwnedWindowTabStrip() async throws {
        _ = NSApplication.shared
        let (repository, directory) = try repository(), host = sample("synthetic overflow")
        try await repository.apply([.insertHost(host)])
        let app = AppModel(repository: repository, location: .isolated(directory), sessionBuilder: WindowTabsLayoutBuilder(host: host))
        _ = await app.reload()
        for _ in 0..<9 { app.requestSession(hostID: host.id, mode: .newSession); await app.sessions.selectedTab?.preparation?.value }
        let ids = app.sessions.tabs.map(\.id)
        app.showWorkspace(.session(ids[0]))
        let window = WindowTabsEventWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 160), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.setFrameOrigin(NSPoint(x: -5000, y: -5000))
        let hosting = NSHostingView(rootView: WorkspaceTabBar(model: app))
        window.contentView = hosting
        window.orderFront(nil)
        defer { window.orderOut(nil); window.contentView = nil }
        addTeardownBlock { await app.sessions.closeAll(); await app.files.closeForWindow(); try await repository.close() }
        func descendants(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(descendants) }
        try await settleWindowTabs(window) { !descendants(hosting).compactMap { $0 as? NSScrollView }.isEmpty }
        let scroll = try XCTUnwrap(descendants(hosting).compactMap { $0 as? NSScrollView }.first)
        func tabView(_ id: UUID) throws -> WorkspaceTabMiddleClickView {
            try XCTUnwrap(descendants(hosting).compactMap { $0 as? WorkspaceTabMiddleClickView }.first { $0.identifier?.rawValue == "tab.middle." + id.uuidString })
        }
        func fullyVisible(_ id: UUID) throws -> Bool {
            let tab = try tabView(id), rect = tab.convert(tab.bounds, to: scroll.contentView)
            return scroll.contentView.bounds.insetBy(dx: -1, dy: -1).contains(rect)
        }
        XCTAssertGreaterThan(try XCTUnwrap(scroll.documentView).bounds.width, scroll.contentView.bounds.width)
        XCTAssertTrue(try fullyVisible(ids[0]))
        func arrow(_ id: String) throws -> NSButton {
            try XCTUnwrap(descendants(hosting).compactMap { $0 as? NSButton }.first { $0.identifier?.rawValue == id })
        }
        let forward = try arrow("workspace.tabs.forward")
        XCTAssertTrue(forward.isEnabled); forward.performClick(nil)
        try await settleWindowTabs(window) { scroll.contentView.bounds.minX > 0 }
        let arrowOffset = scroll.contentView.bounds.minX
        XCTAssertGreaterThan(arrowOffset, 0)
        try await settleWindowTabs(window)
        XCTAssertEqual(scroll.contentView.bounds.minX, arrowOffset, accuracy: 1, "Arrow navigation must not snap back to the active tab")
        let clip = scroll.contentView, document = try XCTUnwrap(scroll.documentView)
        let manual = min(document.bounds.width - clip.bounds.width, arrowOffset + clip.bounds.width / 2)
        clip.scroll(to: NSPoint(x: manual, y: clip.bounds.minY)); scroll.reflectScrolledClipView(clip)
        try await settleWindowTabs(window)
        XCTAssertEqual(clip.bounds.minX, manual, accuracy: 1, "User scrolling must not reveal the old active tab")
        window.setContentSize(NSSize(width: 1000, height: 160))
        try await settleWindowTabs(window) { try fullyVisible(ids[0]) }
        XCTAssertTrue(try fullyVisible(ids[0]), "Resize must reveal the active tab")
        app.showWorkspace(.session(ids[8])); try await settleWindowTabs(window) { try fullyVisible(ids[8]) }
        XCTAssertTrue(try fullyVisible(ids[8]), "Selection must reveal the exact active tab")
        app.sessions.moveTab(ids[8], before: ids[0]); try await settleWindowTabs(window) { try fullyVisible(ids[8]) }
        XCTAssertTrue(try fullyVisible(ids[8]), "Reorder must reveal the active tab after layout")
        XCTAssertTrue(try arrow("workspace.tabs.forward").isEnabled)
        XCTAssertFalse(try arrow("workspace.tabs.back").isEnabled)
        XCTAssertEqual(app.workspacePage, .session(ids[8]))
        print("WindowTabs owned NSWindow: arrow/manual retention and resize/select/reorder reveal reached")
        await app.sessions.closeAll(); await app.files.closeForWindow(); try await repository.close()
    }

    private func settleWindowTabs(_ window: NSWindow, until condition: (() throws -> Bool)? = nil) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        var stableBounds: CGRect?, stablePasses = 0
        repeat {
            window.contentView?.layoutSubtreeIfNeeded()
            if let condition, try condition() { return }
            if condition == nil {
                let bounds = window.contentView?.bounds
                stablePasses = bounds == stableBounds ? stablePasses + 1 : 0; stableBounds = bounds
                if stablePasses >= 10 { return } // Stability observation only, never an async completion signal.
            }
            try await Task.sleep(for: .milliseconds(10))
        } while ContinuousClock.now < deadline
        XCTFail("Owned window did not reach the observed layout condition within 3 seconds")
    }

    func testWindowTabsFrameRecoveryPreservesVisibleAndClampsMissingDisplayCorruption() {
        let main = NSRect(x: 0, y: 24, width: 1440, height: 876), other = NSRect(x: -1920, y: 24, width: 1920, height: 1056)
        let good = NSRect(x: -1800, y: 70, width: 1120, height: 720)
        XCTAssertEqual(MainWindowFramePreferences.recoveredFrame(good, visibleFrames: [main, other]), good)
        for input in [good, NSRect(x: 30_000, y: -30_000, width: 1120, height: 720), NSRect(x: 0, y: 0, width: 9000, height: 9000), NSRect(x: 20, y: 20, width: 30, height: 40), NSRect(x: CGFloat.nan, y: 0, width: 1200, height: CGFloat.infinity)] {
            let result = MainWindowFramePreferences.recoveredFrame(input, visibleFrames: [main])
            XCTAssertTrue(main.contains(result)); XCTAssertGreaterThanOrEqual(result.width, 920); XCTAssertGreaterThanOrEqual(result.height, 580)
        }
        let noScreen = MainWindowFramePreferences.recoveredFrame(.zero, visibleFrames: [])
        XCTAssertEqual(noScreen.size, MainWindowFramePreferences.minimumSize)
    }

    func testWindowTabsMiddleClickBelongsOnlyToExactNativeTargetAndNoModifierOrEditor() async throws {
        _ = NSApplication.shared
        let window = WindowTabsEventWindow(contentRect: NSRect(x: 0, y: 0, width: 600, height: 200), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.contentView = nil; window.orderOut(nil) }
        let root = try XCTUnwrap(window.contentView)
        let a = WorkspaceTabMiddleClickView(frame: NSRect(x: 120, y: 100, width: 160, height: 34))
        let b = WorkspaceTabMiddleClickView(frame: NSRect(x: 290, y: 100, width: 160, height: 34))
        let editor = NSTextField(string: "editor"), fixed = NSButton(title: "fixed", target: nil, action: nil)
        editor.frame = NSRect(x: 120, y: 30, width: 220, height: 26); fixed.frame = NSRect(x: 0, y: 100, width: 100, height: 34)
        let nativeViews: [NSView] = [fixed, editor, a, b]
        nativeViews.forEach { root.addSubview($0) }
        var aClosed = 0, bClosed = 0; a.closeAction = { aClosed += 1 }; b.closeAction = { bClosed += 1 }
        func event(_ type: NSEvent.EventType, point: NSPoint, flags: NSEvent.ModifierFlags = []) throws -> NSEvent {
            let base = try XCTUnwrap(NSEvent.mouseEvent(with: type, location: point, modifierFlags: flags, timestamp: 1, windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 0))
            guard type == .otherMouseDown || type == .otherMouseUp else { return base }
            let cg = try XCTUnwrap(base.cgEvent)
            cg.setIntegerValueField(.mouseEventButtonNumber, value: 2)
            let screen = window.convertPoint(toScreen: point)
            let height = NSScreen.screens.first?.frame.maxY ?? 0
            cg.location = CGPoint(x: screen.x, y: height - screen.y)
            let initial = try XCTUnwrap(NSEvent(cgEvent: cg))
            let location = cg.location
            cg.location = CGPoint(x: location.x + point.x - initial.locationInWindow.x, y: location.y + initial.locationInWindow.y - point.y)
            let middle = try XCTUnwrap(NSEvent(cgEvent: cg))
            XCTAssertEqual(middle.windowNumber, window.windowNumber)
            XCTAssertEqual(middle.locationInWindow.x, point.x, accuracy: 0.1)
            XCTAssertEqual(middle.locationInWindow.y, point.y, accuracy: 0.1)
            return middle
        }
        let point = a.convert(NSPoint(x: 50, y: 15), to: nil)
        let down = try event(.otherMouseDown, point: point), up = try event(.otherMouseUp, point: point)
        print("WindowTabs middle public facts: button=\(down.buttonNumber) windowMatches=\(down.window === window) input=\(point) actual=\(down.locationInWindow) local=\(a.convert(down.locationInWindow, from: nil)) hidden=\(a.isHiddenOrHasHiddenAncestor) modal=\(NSApp.modalWindow != nil) sheet=\(window.attachedSheet != nil)")
        XCTAssertEqual(down.buttonNumber, 2); XCTAssertTrue(a.owns(down)); XCTAssertFalse(b.owns(down))
        a.otherMouseDown(with: down); a.otherMouseUp(with: up); XCTAssertEqual(aClosed, 1); XCTAssertEqual(bClosed, 0)
        for flags in [NSEvent.ModifierFlags.command, .control, .option, .shift] {
            let modified = try event(.otherMouseDown, point: point, flags: flags)
            XCTAssertFalse(a.owns(modified)); a.otherMouseDown(with: modified); a.otherMouseUp(with: up)
        }
        XCTAssertFalse(a.owns(try event(.leftMouseDown, point: point))); XCTAssertFalse(a.owns(try event(.rightMouseDown, point: point)))
        for view in [editor, fixed, b] as [NSView] {
            let outside = view.convert(NSPoint(x: 10, y: 10), to: nil)
            XCTAssertFalse(a.owns(try event(.otherMouseDown, point: outside)))
        }
        a.otherMouseDown(with: down); a.otherMouseUp(with: try event(.otherMouseUp, point: NSPoint(x: 10, y: 10)))
        a.isHidden = true; XCTAssertFalse(a.owns(down)); a.otherMouseDown(with: down); a.otherMouseUp(with: up)
        XCTAssertEqual(aClosed, 1); XCTAssertEqual(bClosed, 0); XCTAssertFalse(a.acceptsFirstResponder)
        XCTAssertEqual(editor.stringValue, "editor")
        a.isHidden = false
        try await settleWindowTabs(window)
        let parentPoint = a.convert(NSPoint(x: 50, y: 15), to: a.superview)
        XCTAssertFalse(a.bounds.contains(parentPoint), "The test must exercise parent coordinates, not accidental local bounds")
        XCTAssertNil(a.hitTest(parentPoint), "No current middle event must fall through")
        var hitMiddle = false, ordinaryFellThrough = false
        var routedTypes: [NSEvent.EventType] = []
        window.observeEvent = { current, resolvedHit in
            routedTypes.append(current.type)
            XCTAssertTrue(NSApp.currentEvent === current, "NSApplication dispatch must establish this exact event, not a previous event")
            XCTAssertTrue(current.window === window)
            XCTAssertEqual(current.windowNumber, window.windowNumber)
            guard current.window === window else { return }
            let point = a.convert(current.locationInWindow, from: nil)
            let parent = a.convert(point, to: a.superview)
            if current.type == .otherMouseDown || current.type == .otherMouseUp { XCTAssertEqual(current.buttonNumber, 2) }
            if current.type == .otherMouseDown {
                XCTAssertTrue(resolvedHit === a, "The owning window must resolve the real child hit target")
                hitMiddle = a.hitTest(parent) === a
            }
            if current.type == .leftMouseUp { ordinaryFellThrough = a.hitTest(parent) == nil }
        }
        // App-local dispatch only: do not post to the global event stream or replace currentEvent.
        NSApp.sendEvent(down); NSApp.sendEvent(up)
        XCTAssertTrue(hitMiddle, "Exact window middle event must hit the owned child using parent coordinates")
        XCTAssertEqual(aClosed, 2); XCTAssertEqual(bClosed, 0)
        let leftUp = try event(.leftMouseUp, point: point)
        NSApp.sendEvent(leftUp)
        XCTAssertTrue(ordinaryFellThrough); XCTAssertEqual(aClosed, 2)
        XCTAssertEqual(routedTypes, [.otherMouseDown, .otherMouseUp, .leftMouseUp], "All three exact events must reach only the owned window")
        window.observeEvent = nil
        print("WindowTabs owned NSApplication dispatch: routed=\(routedTypes.count) exactMiddleHit=\(hitMiddle) primaryFallThrough=\(ordinaryFellThrough) closeA=\(aClosed) closeB=\(bClosed)")
    }

    func testWindowTabsIsolatedPreferencesDoNotUseGlobalFrameAutosaveOrRestoreConnections() async throws {
        let (repository, directory) = try repository(), router = RecordingRouter()
        let suite = "OpenLXSSH.WindowTabs.Tests." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite)); defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("sftp", forKey: ManagementPagePreferences.key)
        let isolated = AppModel(repository: repository, sessionRouter: router, location: .isolated(directory), preferencesDefaults: defaults)
        XCTAssertNil(isolated.mainWindowFrameAutosaveName)
        XCTAssertTrue(isolated.desktopPreferencesDefaults === defaults)
        XCTAssertTrue(awaiting: await isolated.reload()); XCTAssertTrue(isolated.sessions.tabs.isEmpty); XCTAssertTrue(router.requests.isEmpty)
        let vault = VaultDesktopModel(app: isolated); XCTAssertTrue(awaiting: await vault.load())
        vault.managementPage = .trust
        XCTAssertNotNil(defaults.data(forKey: "OpenLXSSH.Vault.Desktop.v1.navigation.v1"))
        XCTAssertTrue(isolated.sessions.tabs.isEmpty); XCTAssertTrue(router.requests.isEmpty)
        await isolated.files.closeForWindow(); try await repository.close()
    }

    func testMultiWindowSharedInfrastructureKeepsWorkspaceSessionsSplitsAndSFTPIndependent() async throws {
        let (repository, directory) = try repository()
        let location = AppDataLocation.isolated(directory)
        let security = SecurityCoordinator(repository: repository, location: location, credentials: FakeCredentials())
        let environment = SessionEnvironment(location: location)
        let remoteRoot = try AppDataLocation.canonical(directory).appendingPathComponent("multi-window-sftp", isDirectory: true)
        try FileManager.default.createDirectory(at: remoteRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])

        let hostA = sample("multi-window-A")
        let hostB = sample("multi-window-B")
        try await repository.apply([.insertHost(hostA), .insertHost(hostB)])

        let connector1 = AppModelFilesConnector(root: remoteRoot)
        let connector2 = AppModelFilesConnector(root: remoteRoot)
        let model1 = AppModel(
            repository: repository,
            security: security,
            sessionEnvironment: environment,
            location: location,
            sessionBuilder: WindowTabsLayoutBuilder(host: hostA),
            filesConnector: connector1
        )
        let model2 = AppModel(
            repository: repository,
            security: security,
            sessionEnvironment: environment,
            location: location,
            sessionBuilder: WindowTabsLayoutBuilder(host: hostB),
            filesConnector: connector2
        )
        addTeardownBlock {
            await model1.sessions.closeAll()
            await model2.sessions.closeAll()
            await model1.files.closeForWindow()
            await model2.files.closeForWindow()
            try await security.close()
            try await repository.close()
        }

        XCTAssertTrue(model1.sessionEnvironment === model2.sessionEnvironment)
        XCTAssertTrue(model1.security === model2.security)
        XCTAssertTrue(DesktopHelp.shortcuts.contains("⌘N 新建窗口"))
        XCTAssertTrue(awaiting: await model1.reload())
        XCTAssertTrue(awaiting: await model2.reload())

        // Window 1 opens a session tab and splits horizontally.
        model1.requestSession(hostID: hostA.id, mode: .newSession)
        let firstTab = try XCTUnwrap(model1.sessions.selectedTab)
        await firstTab.preparation?.value
        let splitTab = try XCTUnwrap(model1.sessions.splitCurrentSession(axis: .horizontal))
        await splitTab.preparation?.value
        XCTAssertEqual(model1.sessions.tabs.count, 2)
        XCTAssertTrue(model1.sessions.isSplitActive)
        XCTAssertEqual(model1.workspacePage, .session(splitTab.id))

        // Window 2 independently switches to SFTP for hostB and connects.
        model2.selectedHostID = hostB.id
        model2.showWorkspace(.sftp)
        await model2.files.waitUntilCurrentWorkCompletes()
        model2.files.connect(.init(primary: .manual(.init(utf8: UUID().uuidString))))
        await model2.files.waitUntilCurrentWorkCompletes()

        XCTAssertEqual(model2.workspacePage, .sftp)
        XCTAssertEqual(model2.files.state, .ready)
        XCTAssertEqual(model2.files.selectedHost?.id, hostB.id)
        XCTAssertTrue(model2.sessions.tabs.isEmpty)
        XCTAssertFalse(model2.sessions.isSplitActive)

        // Window 1 remains unaffected by Window 2's page and SFTP state.
        XCTAssertEqual(model1.workspacePage, .session(splitTab.id))
        XCTAssertEqual(model1.sessions.tabs.count, 2)
        XCTAssertTrue(model1.sessions.isSplitActive)
        XCTAssertEqual(model1.files.state, .disconnected)
        XCTAssertNil(model1.files.selectedHost)
    }

    func testConcurrentSettingsSaveAcrossTwoWindowsMergesChangedFieldsWithoutOverwriting() async throws {
        let (repository, directory) = try repository()
        let location = AppDataLocation.isolated(directory)
        let security = SecurityCoordinator(repository: repository, location: location, credentials: FakeCredentials())
        let environment = SessionEnvironment(location: location)

        let windowA = AppModel(repository: repository, security: security, sessionEnvironment: environment, location: location)
        let windowB = AppModel(repository: repository, security: security, sessionEnvironment: environment, location: location)
        addTeardownBlock {
            await windowA.files.closeForWindow()
            await windowB.files.closeForWindow()
            try await security.close()
            try await repository.close()
        }

        XCTAssertTrue(awaiting: await windowA.reload())
        XCTAssertTrue(awaiting: await windowB.reload())

        // Both windows open Settings editors from the same initial snapshot.
        let editorA = SettingsEditorModel(windowA.settings)
        let editorB = SettingsEditorModel(windowB.settings)

        // Window A edits fileConflictPolicy and saves.
        editorA.draft.value.fileConflictPolicy = .overwrite
        let baseA = editorA.initial
        let savedA = await editorA.save(using: { await windowA.saveSettings($0, base: baseA) })
        XCTAssertTrue(savedA)

        // Window B edits fontSize (without knowing about Window A's save) and saves using its original base.
        editorB.draft.size = "16"
        let baseB = editorB.initial
        let savedB = await editorB.save(using: { await windowB.saveSettings($0, base: baseB) })
        XCTAssertTrue(savedB)

        // Persisted settings must contain BOTH edits without overwriting Window A's change.
        let persisted = try await repository.loadSettings()
        XCTAssertEqual(persisted.fileConflictPolicy, .overwrite)
        XCTAssertEqual(persisted.fontSize, 16)

        // Also verify clean editor syncs external updates while dirty editor keeps its draft intact.
        let cleanEditor = SettingsEditorModel(persisted)
        let dirtyEditor = SettingsEditorModel(persisted)
        dirtyEditor.draft.value.cursorBlink = false

        var external = persisted
        external.theme = .dark
        cleanEditor.syncExternal(external)
        dirtyEditor.syncExternal(external)

        XCTAssertFalse(cleanEditor.isDirty)
        XCTAssertEqual(cleanEditor.draft.value.theme, .dark)
        XCTAssertEqual(cleanEditor.initial.theme, .dark)
        XCTAssertTrue(dirtyEditor.isDirty)
        XCTAssertEqual(dirtyEditor.draft.value.cursorBlink, false)
        XCTAssertEqual(dirtyEditor.draft.value.theme, persisted.theme)

        // True concurrent saves via withTaskGroup: both edits must persist atomically in SQLite.
        let concurrentBase = try await repository.loadSettings()
        var editedA = concurrentBase
        editedA.fileConflictPolicy = .skip
        var editedB = concurrentBase
        editedB.fontSize = 18
        let finalA = editedA
        let finalB = editedB

        let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            group.addTask {
                await windowA.saveSettings(finalA, base: concurrentBase)
            }
            group.addTask {
                await windowB.saveSettings(finalB, base: concurrentBase)
            }
            var outcomes: [Bool] = []
            for await outcome in group {
                outcomes.append(outcome)
            }
            return outcomes
        }
        XCTAssertEqual(results, [true, true])

        let concurrentPersisted = try await repository.loadSettings()
        XCTAssertEqual(concurrentPersisted.fileConflictPolicy, .skip)
        XCTAssertEqual(concurrentPersisted.fontSize, 18)
    }

    func testSettingsAndDiagnosticsCommandsRouteToGlobalHandlerWithoutDuplicateLocalCommand() throws {
        let (repository, directory) = try repository()
        let model = AppModel(repository: repository, location: .isolated(directory))
        var openedCategories: [PreferencesCategory?] = []
        model.onOpenSettings = { category in
            openedCategories.append(category)
        }

        XCTAssertTrue(model.sendWorkspaceCommand(.settings))
        XCTAssertNil(model.workspaceCommand)
        XCTAssertTrue(model.sendWorkspaceCommand(.diagnostics))
        XCTAssertNil(model.workspaceCommand)
        XCTAssertEqual(openedCategories, [nil, .privacy])

        // Standalone fallback without AppDelegate still publishes workspaceCommand for MainView sheet.
        model.onOpenSettings = nil
        XCTAssertTrue(model.sendWorkspaceCommand(.settings))
        XCTAssertEqual(model.workspaceCommand?.command, .settings)
        XCTAssertTrue(model.sendWorkspaceCommand(.diagnostics))
        XCTAssertEqual(model.workspaceCommand?.command, .diagnostics)
    }

    func testDiagnosticSnapshotAggregatesLiveSessionCountAcrossMultipleWorkspaceWindows() async throws {
        let (repository, directory) = try repository()
        let location = AppDataLocation.isolated(directory)
        let security = SecurityCoordinator(repository: repository, location: location, credentials: FakeCredentials())
        let environment = SessionEnvironment(location: location)

        let hostA = sample("diag-window-a")
        let hostB = sample("diag-window-b")
        try await repository.apply([.insertHost(hostA), .insertHost(hostB)])

        let settingsModel = AppModel(repository: repository, security: security, sessionEnvironment: environment, location: location)
        let windowA = AppModel(
            repository: repository,
            security: security,
            sessionEnvironment: environment,
            location: location,
            sessionBuilder: WindowTabsLayoutBuilder(host: hostA)
        )
        let windowB = AppModel(
            repository: repository,
            security: security,
            sessionEnvironment: environment,
            location: location,
            sessionBuilder: WindowTabsLayoutBuilder(host: hostB)
        )
        addTeardownBlock {
            await settingsModel.sessions.closeAll(); await settingsModel.files.closeForWindow()
            await windowA.sessions.closeAll(); await windowA.files.closeForWindow()
            await windowB.sessions.closeAll(); await windowB.files.closeForWindow()
            try await security.close()
            try await repository.close()
        }

        XCTAssertTrue(awaiting: await settingsModel.reload())
        XCTAssertTrue(awaiting: await windowA.reload())
        XCTAssertTrue(awaiting: await windowB.reload())

        let workspaceModels = [windowA, windowB]
        windowA.requestSession(hostID: hostA.id, mode: .newSession)
        windowA.requestSession(hostID: hostA.id, mode: .newSession)
        windowB.requestSession(hostID: hostB.id, mode: .newSession)
        XCTAssertEqual(windowA.sessions.tabs.count, 2)
        XCTAssertEqual(windowB.sessions.tabs.count, 1)
        XCTAssertEqual(settingsModel.sessions.tabs.count, 0)

        let totalSessions = workspaceModels.reduce(0) { $0 + $1.sessions.tabs.count }
        XCTAssertEqual(totalSessions, 3)

        let aggregated = PublicDiagnosticSnapshot(model: settingsModel, sessionCountOverride: totalSessions)
        XCTAssertEqual(aggregated.sessionCount, 3)
        XCTAssertEqual(aggregated.hostCount, 2)
        XCTAssertTrue(aggregated.preview(categories: [.counts]).contains("SSH 标签 3"))

        let localOnly = PublicDiagnosticSnapshot(model: settingsModel)
        XCTAssertEqual(localOnly.sessionCount, 0)
    }

    func testClosingSecondaryWindowLeavesPrimaryWindowSessionsSFTPAndSharedRepositoryIntact() async throws {
        _ = NSApplication.shared
        let (repository, directory) = try repository()
        let location = AppDataLocation.isolated(directory)
        let security = SecurityCoordinator(repository: repository, location: location, credentials: FakeCredentials())
        let environment = SessionEnvironment(location: location)
        let remoteRoot = try AppDataLocation.canonical(directory).appendingPathComponent("multi-window-close", isDirectory: true)
        try FileManager.default.createDirectory(at: remoteRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])

        let hostA = sample("primary-host")
        let hostB = sample("secondary-host")
        try await repository.apply([.insertHost(hostA), .insertHost(hostB)])

        let primary = AppModel(
            repository: repository,
            security: security,
            sessionEnvironment: environment,
            location: location,
            sessionBuilder: WindowTabsLayoutBuilder(host: hostA),
            filesConnector: AppModelFilesConnector(root: remoteRoot)
        )
        let secondary = AppModel(
            repository: repository,
            security: security,
            sessionEnvironment: environment,
            location: location,
            sessionBuilder: WindowTabsLayoutBuilder(host: hostB),
            filesConnector: AppModelFilesConnector(root: remoteRoot)
        )

        let window1 = NSWindow(
            contentRect: NSRect(x: -5000, y: -5000, width: 1000, height: 640),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        let window2 = NSWindow(
            contentRect: NSRect(x: -4960, y: -5040, width: 1000, height: 640),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window1.isReleasedWhenClosed = false
        window2.isReleasedWhenClosed = false
        WorkspaceWindowChrome.configure(window1)
        WorkspaceWindowChrome.configure(window2)
        window1.contentView = NSHostingView(rootView: MainView(model: primary))
        window2.contentView = NSHostingView(rootView: MainView(model: secondary))
        defer {
            window1.orderOut(nil); window1.contentView = nil; window1.close()
            window2.orderOut(nil); window2.contentView = nil; window2.close()
        }
        addTeardownBlock {
            await primary.sessions.closeAll()
            await secondary.sessions.closeAll()
            await primary.files.closeForWindow()
            await secondary.files.closeForWindow()
            try await security.close()
            try await repository.close()
        }

        XCTAssertTrue(awaiting: await primary.reload())
        XCTAssertTrue(awaiting: await secondary.reload())

        // Both windows open active SFTP and an SSH session tab.
        primary.selectedHostID = hostA.id
        primary.showWorkspace(.sftp)
        await primary.files.waitUntilCurrentWorkCompletes()
        primary.files.connect(.init(primary: .manual(.init(utf8: UUID().uuidString))))
        await primary.files.waitUntilCurrentWorkCompletes()
        primary.requestSession(hostID: hostA.id, mode: .newSession)
        let primaryTab = try XCTUnwrap(primary.sessions.selectedTab)
        await primaryTab.preparation?.value

        secondary.selectedHostID = hostB.id
        secondary.showWorkspace(.sftp)
        await secondary.files.waitUntilCurrentWorkCompletes()
        secondary.files.connect(.init(primary: .manual(.init(utf8: UUID().uuidString))))
        await secondary.files.waitUntilCurrentWorkCompletes()
        secondary.requestSession(hostID: hostB.id, mode: .newSession)
        let secondaryTab = try XCTUnwrap(secondary.sessions.selectedTab)
        await secondaryTab.preparation?.value

        XCTAssertEqual(primary.files.state, .ready)
        XCTAssertEqual(secondary.files.state, .ready)
        XCTAssertEqual(primary.sessions.tabs.count, 1)
        XCTAssertEqual(secondary.sessions.tabs.count, 1)

        // Close window 2 only.
        let closeResult = await secondary.lifecycle.closeConnectionsResult(cancelTransfers: true, retainAdmissionFreeze: true)
        XCTAssertTrue(closeResult.complete)
        secondary.windowClosed()
        window2.orderOut(nil)
        window2.contentView = nil
        window2.close()
        secondary.lifecycle.resumeAfterContinue()

        XCTAssertTrue(secondary.sessions.tabs.isEmpty)
        XCTAssertEqual(secondary.files.state, .disconnected)
        XCTAssertEqual(secondary.workspacePage, .vault)

        // Window 1's active session, SFTP, and shared repository remain fully intact and writable.
        XCTAssertEqual(primary.sessions.tabs.map(\.id), [primaryTab.id])
        XCTAssertEqual(primary.workspacePage, .session(primaryTab.id))
        XCTAssertEqual(primary.files.state, .ready)
        XCTAssertEqual(primary.files.selectedHost?.id, hostA.id)
        XCTAssertFalse(primary.lifecycle.terminating)

        let addedAfterClose = sample("added-after-window2-close")
        XCTAssertTrue(awaiting: await primary.saveHost(addedAfterClose, isNew: true))
        XCTAssertTrue(primary.connectionHosts.contains(where: { $0.id == addedAfterClose.id }))
    }

    func testMultiWindowRepositoryCommitSynchronizesLiveAcrossWindows() async throws {
        let (repository, directory) = try repository()
        let location = AppDataLocation.isolated(directory)
        let security = SecurityCoordinator(repository: repository, location: location, credentials: FakeCredentials())
        let environment = SessionEnvironment(location: location)

        let window1 = AppModel(repository: repository, security: security, sessionEnvironment: environment, location: location)
        let window2 = AppModel(repository: repository, security: security, sessionEnvironment: environment, location: location)
        let vault2 = VaultDesktopModel(app: window2)
        addTeardownBlock {
            await window1.files.closeForWindow()
            await window2.files.closeForWindow()
            try await security.close()
            try await repository.close()
        }

        XCTAssertTrue(awaiting: await window1.reload())
        XCTAssertTrue(awaiting: await window2.reload())
        XCTAssertTrue(awaiting: await vault2.load())
        XCTAssertTrue(window2.hosts.isEmpty)
        XCTAssertTrue(vault2.hosts.isEmpty)

        // Save a new host in window 1; window 2 and its VaultDesktopModel receive live updates via metadataChanges().
        let created = sample("synced-across-windows")
        XCTAssertTrue(awaiting: await window1.saveHost(created, isNew: true))

        let deadline = ContinuousClock.now + .seconds(2)
        while ContinuousClock.now < deadline {
            if window2.hosts.contains(where: { $0.id == created.id })
                && window2.connectionHosts.contains(where: { $0.id == created.id })
                && vault2.hosts.contains(where: { $0.id == created.id }) {
                break
            }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTAssertTrue(window2.hosts.contains(where: { $0.id == created.id }))
        XCTAssertTrue(window2.connectionHosts.contains(where: { $0.id == created.id }))
        XCTAssertTrue(vault2.hosts.contains(where: { $0.id == created.id }))

        // Explicit reload on window 2 also reflects updates committed by window 1.
        var renamed = created
        renamed.name = "synced-renamed"
        XCTAssertTrue(awaiting: await window1.saveHost(renamed, isNew: false))
        XCTAssertTrue(awaiting: await window2.reload())
        XCTAssertEqual(window2.hosts.first(where: { $0.id == created.id })?.name, "synced-renamed")
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

@MainActor private final class WindowTabsLayoutBuilder: SessionBuilding {
    let host: HostConfiguration
    init(host: HostConfiguration) { self.host = host }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        (host, try SessionEnvironment.configuration(host: host, keyPath: nil))
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        ReadySession(host: host, configuration: try SessionEnvironment.configuration(host: host, keyPath: nil), driver: WindowTabsLayoutDriver(id: sessionID))
    }
}
@MainActor private final class WindowTabsLayoutDriver: SessionDriving {
    let id: UUID
    let terminal = NativeTerminalView()
    var token: SessionToken?
    var state: SSHSessionState = .idle
    var canReconnect: Bool { false }
    var onState: ((SessionToken?, SSHSessionState) -> Void)?
    var onTrust: (([SessionTrustPrompt]) -> Void)?
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)?
    init(id: UUID) { self.id = id }
    func connect(_ configuration: SSHSessionConfiguration, primary: SessionPrimaryAuthorization) throws -> SessionToken {
        let value = SessionToken(sessionID: id, generation: 1); token = value; state = .connectionPending; onState?(value, state); return value
    }
    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) async throws {}
    func respond(_ answer: SessionAuthenticationAnswer, to prompt: SessionAuthenticationPrompt) throws {}
    func cancel() { state = .disconnected(nil); onState?(token, state) }
    func closeTab() { state = .closed; terminal.releaseResources(); onState?(token, state) }
}
@MainActor private final class WindowTabsEventWindow: NSWindow {
    var observeEvent: ((NSEvent, NSView?) -> Void)?
    override func sendEvent(_ event: NSEvent) {
        if let contentView {
            let point = contentView.convert(event.locationInWindow, from: nil)
            let parentPoint = contentView.convert(point, to: contentView.superview)
            observeEvent?(event, contentView.hitTest(parentPoint))
        }
        super.sendEvent(event)
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
private actor PreferenceSaveGate {
    private var released = false
    private var pending: CheckedContinuation<Void, Never>?
    func suspend() async { if !released { await withCheckedContinuation { pending = $0 } } }
    func release() { released = true; pending?.resume(); pending = nil }
}

private actor PreferencesReadFailureRepository: AppRepositoryProtocol {
    private(set) var settings = AppSettings()
    private(set) var writeCount = 0
    func snapshot(query: HostQuery) throws -> AppSnapshot { throw RepositoryError.databaseBusy }
    func apply(_ changes: [RepositoryChange]) throws {
        guard changes.count == 1 else { throw RepositoryError.invalidField("preferencesOnly") }
        switch changes[0] {
        case .saveSettings(let value):
            settings = value; writeCount += 1
        case .mergeSettings(let edited, let base):
            settings = AppSettings.merging(edited: edited, base: base, onto: settings); writeCount += 1
        default:
            throw RepositoryError.invalidField("preferencesOnly")
        }
    }
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

/// Real isolated SQLite snapshots with a few explicitly held read boundaries.
/// Metadata invalidations are the base repository's real stream; no SSH/Keychain.
private actor ControlledReloadRepository: AppRepositoryProtocol {
    let base: AppRepository
    private var heldReads = 0
    private var failReads = false
    private var startedReads: Set<Int> = []
    private var readObservers: [Int: @Sendable () -> Void] = [:]
    private var metadataObservers: [Int: @Sendable () -> Void] = [:]
    private var pending: [Int: (snapshot: AppSnapshot, reply: CheckedContinuation<AppSnapshot, Error>)] = [:]
    private var holdMetadata = false
    private var pendingMetadata: (value: SecurityMetadata, reply: CheckedContinuation<SecurityMetadata, Never>)?
    private(set) var nextSnapshotIndex = 0
    private(set) var metadataReadCount = 0
    private(set) var writeCount = 0
    var pendingReadCount: Int { pending.count }
    init(base: AppRepository) { self.base = base }
    func holdNextReads(_ count: Int) { precondition((1...2).contains(count)); heldReads = count }
    func holdNextSnapshot(_ observer: @escaping @Sendable () -> Void) -> Int {
        precondition(heldReads == 0)
        heldReads = 1; readObservers[nextSnapshotIndex] = observer
        return nextSnapshotIndex
    }
    func holdNextMetadataRead() { precondition(!holdMetadata && pendingMetadata == nil); holdMetadata = true }
    func failSnapshotReads() { failReads = true }
    func whenSnapshotStarts(_ index: Int, _ observer: @escaping @Sendable () -> Void) {
        precondition(index < 32)
        if startedReads.contains(index) { observer() } else { readObservers[index] = observer }
    }
    func whenMetadataReads(_ count: Int, _ observer: @escaping @Sendable () -> Void) {
        precondition((1...32).contains(count))
        if metadataReadCount >= count { observer() } else { metadataObservers[count] = observer }
    }
    private func started(_ index: Int) { startedReads.insert(index); readObservers.removeValue(forKey: index)?() }
    func snapshot(query: HostQuery) async throws -> AppSnapshot {
        let index = nextSnapshotIndex; nextSnapshotIndex += 1; precondition(index < 32)
        if failReads { throw RepositoryError.databaseBusy }
        let hold = heldReads > 0
        if hold { heldReads -= 1 }
        let value = try await base.snapshot(query: query)
        if !hold { started(index); return value }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { reply in
                pending[index] = (value, reply); started(index)
            }
        } onCancel: { Task { await self.cancelSnapshot(index) } }
    }
    private func cancelSnapshot(_ index: Int) { pending.removeValue(forKey: index)?.reply.resume(throwing: CancellationError()) }
    func releaseSnapshot(_ index: Int) throws {
        guard let value = pending.removeValue(forKey: index) else { throw RepositoryError.notFound }
        value.reply.resume(returning: value.snapshot)
    }
    func releaseAll() {
        let values = pending.values; pending = [:]
        for value in values { value.reply.resume(throwing: CancellationError()) }
        if let value = pendingMetadata { pendingMetadata = nil; value.reply.resume(returning: value.value) }
    }
    func metadataChanges() async -> AsyncStream<Void> { await base.metadataChanges() }
    func securityMetadata() async throws -> SecurityMetadata {
        let hold = holdMetadata; holdMetadata = false
        let value = try await base.securityMetadata()
        metadataReadCount += 1
        if hold {
            return await withCheckedContinuation { reply in
                pendingMetadata = (value, reply)
                metadataObservers.removeValue(forKey: metadataReadCount)?()
            }
        }
        metadataObservers.removeValue(forKey: metadataReadCount)?()
        return value
    }
    func releaseMetadataRead() throws {
        guard let value = pendingMetadata else { throw RepositoryError.notFound }
        pendingMetadata = nil; value.reply.resume(returning: value.value)
    }
    func apply(_ changes: [RepositoryChange]) async throws { writeCount += 1; try await base.apply(changes) }
    func copyHost(id: UUID) async throws -> HostConfiguration { try await base.copyHost(id: id) }
    func copyFolder(id: UUID) async throws -> HostFolder { try await base.copyFolder(id: id) }
    func close() async throws { releaseAll(); try await base.close() }
}

/// Prepared-only logical driver. Neither preparation nor commit reaches SSH.
@MainActor private final class PreparedMetadataBuilder: SessionBuilding {
    let host: HostConfiguration
    private(set) var driver: PreparedMetadataDriver?
    init(host: HostConfiguration) { self.host = host }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        guard hostID == host.id else { throw RepositoryError.notFound }
        return (host, try SessionEnvironment.configuration(host: host, keyPath: nil))
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        let valueConfiguration = try await configuration(hostID: hostID)
        let value = PreparedMetadataDriver(id: sessionID); driver = value
        return ReadySession(host: host, configuration: valueConfiguration.1, driver: value)
    }
}
@MainActor private final class PreparedMetadataDriver: SessionDriving {
    let id: UUID
    let terminal = NativeTerminalView()
    var token: SessionToken?
    private(set) var state: SSHSessionState = .idle
    var canReconnect: Bool { false }
    var onState: ((SessionToken?, SSHSessionState) -> Void)?
    var onTrust: (([SessionTrustPrompt]) -> Void)?
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)?
    init(id: UUID) { self.id = id }
    func connect(_ configuration: SSHSessionConfiguration, primary: SessionPrimaryAuthorization) throws -> SessionToken {
        XCTFail("Prepared metadata regression must not start a connection")
        throw TransportError.invalidConfiguration
    }
    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) async throws {}
    func respond(_ answer: SessionAuthenticationAnswer, to prompt: SessionAuthenticationPrompt) throws {}
    func cancel() { state = .disconnected(nil) }
    func closeTab() { state = .closed; terminal.releaseResources() }
}
