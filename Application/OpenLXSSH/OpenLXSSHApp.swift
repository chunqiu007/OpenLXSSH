import AppKit
import SwiftUI
import OpenLXSSHTransport

@main enum OpenLXSSHEntry {
    @MainActor static func main() {
        let application = NSApplication.shared
        application.setActivationPolicy(.regular)
        let delegate = AppDelegate()
        application.delegate = delegate
        withExtendedLifetime(delegate) { application.run() }
    }
}

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSMenuItemValidation {
    let model: AppModel
    private(set) var mainWindow: NSWindow?
    private var terminating = false
    private var windowClosing = false
    private var windowCloseApproved = false
    private var closeAdmissionFrozen = false
    private var closeRequest = AppCloseRequestState()
    private var closeIntent: AppCloseIntent? { closeRequest.intent }
    private var closeFlow: Task<Void, Never>?
    private var terminationReplyPending = false
    private var closeApproved: Bool { closeRequest.approved }
    private var transferClosePrompt: NSPanel?
    private var transferCloseReply: CheckedContinuation<Bool, Never>?
    private var retainedCleanupReply: CheckedContinuation<Void, Never>?

    override init() {
        model = AppModel(repository: AppRepository(), preferencesDefaults: .standard)
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        showMainWindow()
    }

    @objc func showMainWindow() {
        guard !terminating, !model.lifecycle.terminating else { return }
        if let mainWindow { mainWindow.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); return }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1120, height: 720), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "OpenLXSSH"
        window.identifier = NSUserInterfaceItemIdentifier("OpenLXSSH.main")
        WorkspaceWindowChrome.configure(window)
        window.isReleasedWhenClosed = false
        window.minSize = MainWindowFramePreferences.minimumSize
        window.contentView = NSHostingView(rootView: MainView(model: model))
        window.delegate = self
        window.center()
        if let name = model.mainWindowFrameAutosaveName {
            _ = window.setFrameUsingName(name, force: true)
            recoverMainWindowFrame(window)
            _ = window.setFrameAutosaveName(name)
        }
        mainWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        Task { await model.reload() }
    }

    private func recoverMainWindowFrame(_ window: NSWindow) {
        guard !window.styleMask.contains(.fullScreen), !window.inLiveResize else { return }
        let frame = MainWindowFramePreferences.recoveredFrame(window.frame, visibleFrames: NSScreen.screens.map(\.visibleFrame))
        if window.frame != frame { window.setFrame(frame, display: window.isVisible) }
    }
    func windowDidChangeScreen(_ notification: Notification) {
        guard let window = notification.object as? NSWindow, window === mainWindow else { return }
        recoverMainWindowFrame(window)
    }
    func applicationDidChangeScreenParameters(_ notification: Notification) {
        if let mainWindow { recoverMainWindowFrame(mainWindow) }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        guard sender === mainWindow else { return true }
        if windowCloseApproved { return true }
        requestClose(.window)
        return false
    }
    func windowWillClose(_ notification: Notification) {
        guard notification.object as? NSWindow === mainWindow else { return }
        model.windowClosed()
        mainWindow?.contentView = nil
        mainWindow = nil
        windowCloseApproved = false; closeAdmissionFrozen = false
        if !terminating { model.lifecycle.resumeAfterContinue() }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard !terminating, !model.lifecycle.terminating else { return false }
        if !flag { showMainWindow() }
        return true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateLater }
        terminationReplyPending = true
        requestClose(.quit)
        return .terminateLater
    }
    private func requestClose(_ intent: AppCloseIntent) {
        let startsFlow = closeRequest.request(intent)
        // A quit joining an approved window cleanup shares its result. Permanent
        // termination is gated below, never merely by approving presentation review.
        guard startsFlow else { return }
        windowClosing = true
        closeFlow = Task { @MainActor [self] in
            // Review runs before admission revocation, transfer snapshots, credential
            // reads, or any cleanup. A cancelled review is purely presentation state.
            guard allowsGlobalCloseReview else { cancelCloseAttempt(); return }
            let review = model.requestWindowCloseReview()
            guard await model.lifecycle.freezeAfterCloseReview(review, isCurrent: { model.isWindowCloseReviewCurrent(review) }) else {
                cancelCloseAttempt(); return
            }
            closeAdmissionFrozen = true
            let active = await model.lifecycle.activeTransferSnapshot()
            guard model.isWindowCloseReviewCurrent(review) else { cancelCloseAttempt(); return }
            if active {
                let cancelAndClose = await askTransferClose()
                guard cancelAndClose, model.isWindowCloseReviewCurrent(review) else { cancelCloseAttempt(); return }
            }
            // Draft and transfer decisions stay before cleanup. Approval is not proof
            // the native connection is closed; keep quit reversible until the result gate.
            model.finishWindowCloseReview()
            closeRequest.approve()
            let managerBeforeClose = model.files.manager
            let labelsBeforeClose = model.files.transferLabels
            model.files.deferResetUntilCloseAcknowledged()
            let closeResult = await model.lifecycle.closeConnectionsResult(cancelTransfers: true, retainAdmissionFreeze: true)
            let finalTransfers = await managerBeforeClose.snapshot()
            let retained = finalTransfers.jobs.flatMap { job in job.retainedTemporaryPaths.map { path -> String in
                let label = labelsBeforeClose[job.id]
                let root = label?.localRoots[job.request.destination.serviceID]
                let bytes = root.map { ($0 == .root ? Data() : $0.bytes) + path.bytes } ?? path.bytes
                return (label?.endpoint ?? job.request.hostID) + " · " + FileDisplay.bytes(bytes)
            } }
            if !retained.isEmpty { await showRetainedCleanup(retained) }
            model.files.finishWindowCloseReset()
            guard closeResult.complete else {
                model.issue = SessionController.incompleteCloseIssue
                cancelCloseAttempt()
                return
            }
            if closeIntent == .quit {
                approveTermination()
                do { try await model.security.close(); try await model.repository.close() }
                catch {
                    /* Do not log database or credential error descriptions. */
                }
                terminationReplyPending = false; replyToTermination(true)
            } else {
                windowCloseApproved = true; mainWindow?.performClose(nil)
                closeRequest.reset(); closeFlow = nil; windowClosing = false
            }
        }
    }
    /// Unknown system sheets/open panels are never force-ended or replaced by the
    /// global review. Owned editor sheets route their exact nested prompt themselves.
    private var allowsGlobalCloseReview: Bool {
        var sheet = mainWindow?.attachedSheet
        while let current = sheet {
            guard current is NativeOwnedSheetWindow else {
                return false
            }
            sheet = current.attachedSheet
        }
        if NSApp.modalWindow != nil {
            return false
        }
        if let key = NSApp.keyWindow, key !== mainWindow, !(key is NativeOwnedSheetWindow) {
            return false
        }
        return true
    }
    private func cancelCloseAttempt() {
        model.finishWindowCloseReview()
        if closeAdmissionFrozen { model.lifecycle.resumeAfterContinue() }
        closeAdmissionFrozen = false
        closeRequest.reset(); closeFlow = nil; windowClosing = false
        // Preserve the current editor/auth responder instead of forcing the parent key.
        if mainWindow?.attachedSheet == nil { mainWindow?.makeKeyAndOrderFront(nil) }
        if terminationReplyPending { terminationReplyPending = false; replyToTermination(false) }
    }
    private func approveTermination() {
        guard !terminating else { return }
        terminating = true; model.lifecycle.beginTermination(); model.windowClosed()
    }
    private func replyToTermination(_ approved: Bool) {
        RunLoop.main.perform(inModes: [.default, .eventTracking, .modalPanel]) {
            MainActor.assumeIsolated { NSApp.reply(toApplicationShouldTerminate: approved) }
        }
    }
    private func askTransferClose() async -> Bool {
        await withCheckedContinuation { continuation in
            transferCloseReply = continuation
            let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 520, height: 205), styleMask: [.titled], backing: .buffered, defer: false)
            panel.title = "OpenLXSSH · 活动传输"
            let text = NSTextField(wrappingLabelWithString: "仍有传输任务。继续传输会保留主窗口并取消本次退出；取消传输并关闭会等待任务、临时文件清理及全部连接真正结束。已提交项目不会回滚；无法清理的临时文件会留在任务结果中。")
            text.frame = NSRect(x: 22, y: 78, width: 476, height: 103)
            let keep = NSButton(title: "继续传输", target: self, action: #selector(continueTransfers))
            keep.identifier = .init("lifecycle.transfers.continue"); keep.frame = NSRect(x: 30, y: 23, width: 180, height: 32)
            let cancel = NSButton(title: "取消传输并关闭", target: self, action: #selector(cancelTransfersAndClose))
            cancel.identifier = .init("lifecycle.transfers.cancelClose"); cancel.frame = NSRect(x: 260, y: 23, width: 220, height: 32)
            panel.contentView?.addSubview(text); panel.contentView?.addSubview(keep); panel.contentView?.addSubview(cancel)
            panel.isReleasedWhenClosed = false; panel.level = .modalPanel; panel.center()
            transferClosePrompt = panel
            // App-level panel can coexist with a pending transfer/auth sheet. It never
            // dismantles that sheet merely because the user considered closing the App.
            panel.makeKeyAndOrderFront(nil)
        }
    }
    private func showRetainedCleanup(_ paths: [String]) async {
        await withCheckedContinuation { continuation in
            retainedCleanupReply = continuation
            let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 700, height: 340), styleMask: [.titled], backing: .buffered, defer: false)
            panel.title = "OpenLXSSH · 未清理的自有临时文件"
            let heading = NSTextField(wrappingLabelWithString: "连接已关闭，以下自有临时文件未能清理。App 不会扫描或自动删除它们。请复制精确路径并在独立核实后人工处理；关闭后不会恢复这些任务记录。")
            heading.frame = NSRect(x: 20, y: 258, width: 660, height: 60)
            let scroll = NSScrollView(frame: NSRect(x: 20, y: 68, width: 660, height: 178)); scroll.hasVerticalScroller = true
            let text = NSTextView(frame: scroll.bounds); text.isEditable = false; text.isSelectable = true
            text.string = paths.joined(separator: "\n"); scroll.documentView = text
            let done = NSButton(title: "已记录路径，继续关闭", target: self, action: #selector(acknowledgeRetainedCleanup))
            done.identifier = .init("lifecycle.transfers.retained.acknowledge"); done.frame = NSRect(x: 430, y: 20, width: 250, height: 32)
            panel.contentView?.addSubview(heading); panel.contentView?.addSubview(scroll); panel.contentView?.addSubview(done)
            panel.isReleasedWhenClosed = false; panel.level = .modalPanel; panel.center(); transferClosePrompt = panel; panel.makeKeyAndOrderFront(nil)
        }
    }
    @objc private func acknowledgeRetainedCleanup() {
        transferClosePrompt?.orderOut(nil); transferClosePrompt = nil
        let reply = retainedCleanupReply; retainedCleanupReply = nil; reply?.resume()
    }
    @objc private func continueTransfers() { resolveTransferClose(false) }
    @objc private func cancelTransfersAndClose() { resolveTransferClose(true) }
    private func resolveTransferClose(_ cancel: Bool) {
        transferClosePrompt?.orderOut(nil); transferClosePrompt = nil
        let reply = transferCloseReply; transferCloseReply = nil; reply?.resume(returning: cancel)
    }

    private func buildMenu() {
        let menu = NSMenu()
        let app = NSMenuItem(); menu.addItem(app)
        let appMenu = NSMenu(title: "OpenLXSSH"); app.submenu = appMenu
        appMenu.addItem(withTitle: "关于 OpenLXSSH", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        let settings = appMenu.addItem(withTitle: "设置…", action: #selector(openSettings), keyEquivalent: ","); settings.target = self
        appMenu.addItem(.separator())
        let services = NSMenu(title: "服务"); let servicesItem = NSMenuItem(title: "服务", action: nil, keyEquivalent: ""); servicesItem.submenu = services; appMenu.addItem(servicesItem); NSApp.servicesMenu = services
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "隐藏 OpenLXSSH", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "退出 OpenLXSSH", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let file = NSMenuItem(); menu.addItem(file)
        let fileMenu = NSMenu(title: "会话"); file.submenu = fileMenu
        let reopen = fileMenu.addItem(withTitle: "打开主窗口", action: #selector(showMainWindow), keyEquivalent: "n"); reopen.target = self
        for (title, action, key) in [("新连接…", #selector(newConnection), "t"), ("新建主机…", #selector(newHost), ""), ("当前连接信息", #selector(connectionInfo), ""), ("断开当前连接", #selector(disconnectSession), ""), ("重新连接", #selector(reconnectSession), "")] {
            let item = fileMenu.addItem(withTitle: title, action: action, keyEquivalent: key); item.target = self
        }
        fileMenu.addItem(.separator())
        let close = fileMenu.addItem(withTitle: "关闭当前标签或窗口", action: #selector(closeWorkspace), keyEquivalent: "w"); close.target = self
        let edit = NSMenuItem(); menu.addItem(edit)
        let editMenu = NSMenu(title: "编辑"); edit.submenu = editMenu
        for (title, selector, key) in [("撤销", "undo:", "z"), ("剪切", "cut:", "x"), ("复制", "copy:", "c"), ("粘贴", "paste:", "v"), ("全选", "selectAll:", "a")] {
            editMenu.addItem(withTitle: title, action: Selector(selector), keyEquivalent: key)
        }
        let find = editMenu.addItem(withTitle: "查找", action: #selector(findInWorkspace), keyEquivalent: "f"); find.target = self
        let viewItem = NSMenuItem(); menu.addItem(viewItem)
        let viewMenu = NSMenu(title: "显示"); viewItem.submenu = viewMenu
        for (title, action, key) in [("保险箱", #selector(showVault), "1"), ("SFTP", #selector(showSFTP), "2"), ("下一个标签", #selector(nextWorkspace), "]"), ("上一个标签", #selector(previousWorkspace), "[")] {
            let item = viewMenu.addItem(withTitle: title, action: action, keyEquivalent: key); item.target = self
            if key == "]" || key == "[" { item.keyEquivalentModifierMask = [.command, .shift] }
        }
        let terminalItem = NSMenuItem(); menu.addItem(terminalItem)
        let terminalMenu = NSMenu(title: "终端"); terminalItem.submenu = terminalMenu
        for action in [TerminalDesktopAction.search, .clearHistory, .scrollToBottom, .increaseFont, .decreaseFont, .resetFont, .connectionInfo, .disconnect, .reconnect] {
            if [.clearHistory, .increaseFont, .connectionInfo].contains(action) { terminalMenu.addItem(.separator()) }
            let key: String
            switch action { case .increaseFont: key = "+"; case .decreaseFont: key = "-"; case .resetFont: key = "0"; default: key = "" }
            let item = terminalMenu.addItem(withTitle: action.title, action: #selector(terminalAction(_:)), keyEquivalent: key)
            item.target = self; item.representedObject = action.rawValue
            item.identifier = NSUserInterfaceItemIdentifier("terminal." + action.rawValue)
        }
        let fontPlus = terminalMenu.addItem(withTitle: "放大字号", action: #selector(terminalAction(_:)), keyEquivalent: "=")
        fontPlus.target = self; fontPlus.representedObject = TerminalDesktopAction.increaseFont.rawValue
        fontPlus.isAlternate = true
        let windowItem = NSMenuItem(); menu.addItem(windowItem)
        let windowMenu = NSMenu(title: "窗口"); windowItem.submenu = windowMenu; NSApp.windowsMenu = windowMenu
        windowMenu.addItem(withTitle: "最小化", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "缩放", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        let fullScreen = windowMenu.addItem(withTitle: "进入全屏幕", action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f"); fullScreen.keyEquivalentModifierMask = [.command, .control]
        NSApp.mainMenu = menu
        let helpItem = NSMenuItem(); menu.addItem(helpItem)
        let helpMenu = NSMenu(title: "帮助"); helpItem.submenu = helpMenu; NSApp.helpMenu = helpMenu
        let shortcuts = helpMenu.addItem(withTitle: "快捷键与鼠标", action: #selector(showTerminalHelp), keyEquivalent: ""); shortcuts.target = self
        for (title, action) in [("版本与本地数据说明", #selector(showLocalDataHelp)), ("本地诊断预览…", #selector(showDiagnostics)), ("第三方许可…", #selector(showLicenses))] {
            let item = helpMenu.addItem(withTitle: title, action: action, keyEquivalent: ""); item.target = self
        }
    }
    private var interactionContext: WorkspaceInteractionContext {
        let keyWindow = NSApp.keyWindow
        let responder = (keyWindow ?? mainWindow)?.firstResponder
        return WorkspaceInteractionContext(hasAttachedSheet: mainWindow?.attachedSheet != nil,
            hasModalWindow: NSApp.modalWindow != nil || transferClosePrompt != nil,
            hasOtherKeyWindow: keyWindow != nil && keyWindow !== mainWindow,
            isEditingText: responder is NSTextView || responder is NSTextField)
    }
    private var allowsWorkspaceActions: Bool {
        !terminating && !windowClosing && !model.lifecycle.terminating && interactionContext.allowsWorkspaceActions
    }
    private var allowsWorkspaceFind: Bool {
        guard allowsWorkspaceActions, model.canSearchWorkspace else { return false }
        let responder = (NSApp.keyWindow ?? mainWindow)?.firstResponder
        let fieldInput = (responder as? NSTextField)?.currentEditor() as? any NSTextInputClient
        let marked = (responder as? any NSTextInputClient)?.hasMarkedText() == true
            || fieldInput?.hasMarkedText() == true
        return interactionContext.allowsWorkspaceFind(hasMarkedText: marked)
    }
    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        guard !terminating, !model.lifecycle.terminating else { return false }
        if menuItem.action == #selector(closeWorkspace) {
            return transferClosePrompt == nil && (!windowClosing || (!closeApproved && mainWindow?.attachedSheet != nil))
        }
        guard allowsWorkspaceActions else { return false }
        if menuItem.action == #selector(terminalAction(_:)),
           let raw = menuItem.representedObject as? String, let action = TerminalDesktopAction(rawValue: raw) {
            return !interactionContext.isEditingText && model.sessions.canPerformTerminalAction(action)
        }
        if menuItem.action == #selector(findInWorkspace) { return allowsWorkspaceFind }
        if menuItem.action == #selector(disconnectSession) { return model.workspacePage.sessionID != nil && model.sessions.selectedTab?.isReusable == true }
        if menuItem.action == #selector(reconnectSession) { return model.workspacePage.sessionID != nil && model.sessions.selectedTab?.canReconnect == true }
        if menuItem.action == #selector(connectionInfo) { return model.workspacePage.sessionID != nil }
        return true
    }
    @objc private func newConnection() { guard allowsWorkspaceActions else { return }; showMainWindow(); model.sendWorkspaceCommand(.newConnection) }
    @objc private func newHost() { guard allowsWorkspaceActions else { return }; showMainWindow(); model.showWorkspace(.vault); model.sendWorkspaceCommand(.newHost) }
    @objc private func openSettings() { guard allowsWorkspaceActions else { return }; showMainWindow(); model.sendWorkspaceCommand(.settings) }
    @objc private func showVault() { guard allowsWorkspaceActions else { return }; showMainWindow(); model.showWorkspace(.vault) }
    @objc private func showSFTP() { guard allowsWorkspaceActions else { return }; showMainWindow(); model.showWorkspace(.sftp) }
    @objc private func nextWorkspace() { guard allowsWorkspaceActions else { return }; model.switchWorkspace(by: 1) }
    @objc private func previousWorkspace() { guard allowsWorkspaceActions else { return }; model.switchWorkspace(by: -1) }
    @objc private func connectionInfo() { guard allowsWorkspaceActions else { return }; model.sessions.performTerminalAction(.connectionInfo) }
    @objc private func terminalAction(_ sender: NSMenuItem) {
        guard allowsWorkspaceActions, !interactionContext.isEditingText,
              let raw = sender.representedObject as? String, let action = TerminalDesktopAction(rawValue: raw) else { return }
        model.sessions.performTerminalAction(action)
    }
    @objc private func showTerminalHelp() {
        showPublicHelp(title: "快捷键与鼠标", text: DesktopHelp.shortcuts)
    }
    @objc private func showLocalDataHelp() {
        showPublicHelp(title: "版本与本地数据", text: DesktopHelp.versionDescription() + "\n\n" + DesktopHelp.localDataDescription)
    }
    @objc private func showDiagnostics() {
        guard allowsWorkspaceActions else { return }
        showMainWindow(); model.sendWorkspaceCommand(.diagnostics)
    }
    @objc private func showLicenses() {
        guard allowsWorkspaceActions else { return }
        let text = DesktopHelp.licenses.map { "—— " + $0.title + " ——\n\n" + DesktopHelp.licenseText($0) }.joined(separator: "\n\n")
        showPublicHelp(title: "第三方许可（本地 bundle）", text: text)
    }
    private func showPublicHelp(title: String, text: String) {
        guard allowsWorkspaceActions else { return }
        showMainWindow()
        guard let mainWindow else { return }
        let alert = NSAlert(); alert.messageText = title
        alert.informativeText = "本地只读内容，不访问网络、不收集日志。"
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 630, height: 350))
        scroll.hasVerticalScroller = true; scroll.borderType = .bezelBorder
        let view = NSTextView(frame: scroll.bounds)
        view.isEditable = false; view.isSelectable = true; view.isRichText = false
        view.font = .systemFont(ofSize: 13); view.string = text
        view.isVerticallyResizable = true; view.isHorizontallyResizable = false
        view.autoresizingMask = [.width]
        view.textContainer?.widthTracksTextView = true
        scroll.documentView = view; alert.accessoryView = scroll
        alert.addButton(withTitle: "关闭"); NativeSheetCloseRouting.register(alert); alert.beginSheetModal(for: mainWindow)
    }
    @objc private func findInWorkspace() {
        guard allowsWorkspaceFind else { return }
        model.sendWorkspaceCommand(.search)
    }
    @objc private func disconnectSession() { guard allowsWorkspaceActions else { return }; if let id = model.workspacePage.sessionID { model.sessions.disconnect(id) } }
    @objc private func reconnectSession() { guard allowsWorkspaceActions else { return }; if let id = model.workspacePage.sessionID { model.sessions.reconnect(id) } }
    @objc private func closeWorkspace() {
        guard !terminating, transferClosePrompt == nil else { return }
        if let sheet = mainWindow?.attachedSheet {
            var current = sheet
            while let nested = current.attachedSheet { current = nested }
            _ = NativeSheetCloseRouting.attemptClose(current)
            return
        }
        guard !windowClosing else { return }
        if let modal = NSApp.modalWindow {
            _ = NativeSheetCloseRouting.attemptClose(modal)
            return
        }
        if let keyWindow = NSApp.keyWindow, keyWindow !== mainWindow {
            _ = NativeSheetCloseRouting.attemptClose(keyWindow)
            return
        }
        if model.workspacePage.sessionID != nil { Task { _ = await model.closeCurrentWorkspace() } }
        else { mainWindow?.performClose(nil) }
    }
}
