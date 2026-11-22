import AppKit
import SwiftUI
import OpenLXSSHTransport

@main enum OpenLXSSHEntry {
    @MainActor static func main() {
        let application = NSApplication.shared
        application.setActivationPolicy(.regular)
        let delegate = AppDelegate()
        application.delegate = delegate
        withExtendedLifetime(delegate) {
            application.run()
        }
    }
}

/// Owns a single macOS workspace window, its independent `AppModel`, and its
/// window-local close review, active-transfer prompt, and connection cleanup flow.
@MainActor final class ManagedWorkspaceWindow: NSObject {
    let id = UUID()
    let window: NSWindow
    let model: AppModel

    private(set) var windowClosing = false
    private(set) var windowCloseApproved = false
    private(set) var closeAdmissionFrozen = false
    private var closeRequest = AppCloseRequestState()
    private var closeIntent: AppCloseIntent? { closeRequest.intent }
    private(set) var closeFlow: Task<Bool, Never>?
    private var transferClosePrompt: NSPanel?
    private var transferCloseReply: CheckedContinuation<Bool, Never>?
    private var retainedCleanupReply: CheckedContinuation<Void, Never>?

    var closeApproved: Bool { closeRequest.approved }
    var hasTransferClosePrompt: Bool { transferClosePrompt != nil }

    init(window: NSWindow, model: AppModel) {
        self.window = window
        self.model = model
        super.init()
    }

    /// Unknown system sheets/open panels are never force-ended or replaced by the
    /// global review. Owned editor sheets route their exact nested prompt themselves.
    func allowsGlobalCloseReview(managedWindows: [ManagedWorkspaceWindow]) -> Bool {
        var sheet = window.attachedSheet
        while let current = sheet {
            guard current is NativeOwnedSheetWindow else {
                return false
            }
            sheet = current.attachedSheet
        }
        if NSApp.modalWindow != nil {
            return false
        }
        if managedWindows.contains(where: { $0.hasTransferClosePrompt }) {
            return false
        }
        if let key = NSApp.keyWindow,
           key !== window,
           !(key is NativeOwnedSheetWindow),
           !managedWindows.contains(where: { $0.window === key }) {
            return false
        }
        return true
    }

    func bringToFrontForReview() {
        // Preserve an attached editor/auth sheet's responder instead of forcing the parent key.
        if window.attachedSheet == nil {
            window.makeKeyAndOrderFront(nil)
        } else {
            window.orderFront(nil)
        }
    }

    /// Closes ONLY this window: dirty-editor review -> freeze admission -> active-transfer
    /// confirmation -> close this window's sessions & SFTP -> performClose.
    func requestClose(managedWindowsProvider: @escaping @MainActor () -> [ManagedWorkspaceWindow]) {
        let startsFlow = closeRequest.request(.window)
        guard startsFlow else { return }
        windowClosing = true
        closeFlow = Task { @MainActor [self] in
            // Review runs before admission revocation, transfer snapshots, credential
            // reads, or any cleanup. A cancelled review is purely presentation state.
            guard allowsGlobalCloseReview(managedWindows: managedWindowsProvider()) else {
                cancelCloseAttempt(focusWindow: true)
                return false
            }
            let review = model.requestWindowCloseReview()
            if review.result == nil {
                bringToFrontForReview()
            }
            guard await model.lifecycle.freezeAfterCloseReview(review, isCurrent: { model.isWindowCloseReviewCurrent(review) }) else {
                cancelCloseAttempt(focusWindow: true)
                return false
            }
            closeAdmissionFrozen = true
            let active = await model.lifecycle.activeTransferSnapshot()
            guard model.isWindowCloseReviewCurrent(review) else {
                cancelCloseAttempt(focusWindow: true)
                return false
            }
            if active {
                bringToFrontForReview()
                let cancelAndClose = await askTransferClose()
                guard cancelAndClose, model.isWindowCloseReviewCurrent(review) else {
                    cancelCloseAttempt(focusWindow: true)
                    return false
                }
            }
            // Draft and transfer decisions stay before cleanup. Approval is not proof
            // the native connection is closed; wait for the actual close result gate.
            model.finishWindowCloseReview()
            closeRequest.approve()
            let closedCleanly = await closeConnectionsAndNotifyRetained()
            guard closedCleanly else {
                model.issue = SessionController.incompleteCloseIssue
                cancelCloseAttempt(focusWindow: true)
                return false
            }
            windowCloseApproved = true
            window.performClose(nil)
            closeRequest.reset()
            closeFlow = nil
            windowClosing = false
            return true
        }
    }

    func awaitInFlightCloseIfNeeded() async -> Bool? {
        guard let flow = closeFlow else { return nil }
        return await flow.value
    }

    /// Phase 1 of app termination for this window: runs presentation review, freezes
    /// admission, and confirms cancelling active transfers without tearing down
    /// connections until every open window has approved.
    func reviewForTermination(managedWindows: [ManagedWorkspaceWindow]) async -> WindowCloseReviewRequest? {
        guard closeRequest.request(.quit) else { return nil }
        windowClosing = true
        guard allowsGlobalCloseReview(managedWindows: managedWindows) else {
            cancelCloseAttempt(focusWindow: true)
            return nil
        }
        let review = model.requestWindowCloseReview()
        if review.result == nil {
            bringToFrontForReview()
        }
        guard await model.lifecycle.freezeAfterCloseReview(review, isCurrent: { model.isWindowCloseReviewCurrent(review) }) else {
            cancelCloseAttempt(focusWindow: true)
            return nil
        }
        closeAdmissionFrozen = true
        let active = await model.lifecycle.activeTransferSnapshot()
        guard model.isWindowCloseReviewCurrent(review) else {
            cancelCloseAttempt(focusWindow: true)
            return nil
        }
        if active {
            bringToFrontForReview()
            let cancelAndClose = await askTransferClose()
            guard cancelAndClose, model.isWindowCloseReviewCurrent(review) else {
                cancelCloseAttempt(focusWindow: true)
                return nil
            }
        }
        return review
    }

    func approveForTermination() {
        model.finishWindowCloseReview()
        closeRequest.approve()
    }

    func closeConnectionsAndNotifyRetained() async -> Bool {
        let managerBeforeClose = model.files.manager
        let labelsBeforeClose = model.files.transferLabels
        model.files.deferResetUntilCloseAcknowledged()
        let closeResult = await model.lifecycle.closeConnectionsResult(cancelTransfers: true, retainAdmissionFreeze: true)
        let finalTransfers = await managerBeforeClose.snapshot()
        let retained = finalTransfers.jobs.flatMap { job in
            job.retainedTemporaryPaths.map { path -> String in
                let label = labelsBeforeClose[job.id]
                let root = label?.localRoots[job.request.destination.serviceID]
                let bytes = root.map { ($0 == .root ? Data() : $0.bytes) + path.bytes } ?? path.bytes
                return (label?.endpoint ?? job.request.hostID) + " · " + FileDisplay.bytes(bytes)
            }
        }
        if !retained.isEmpty {
            bringToFrontForReview()
            await showRetainedCleanup(retained)
        }
        model.files.finishWindowCloseReset()
        return closeResult.complete
    }

    func finishTermination() {
        model.lifecycle.beginTermination()
        model.windowClosed()
    }

    func handleDidClose(terminating: Bool) {
        model.windowClosed()
        window.delegate = nil
        window.contentView = nil
        windowCloseApproved = false
        closeAdmissionFrozen = false
        if !terminating {
            model.lifecycle.resumeAfterContinue()
        }
    }

    func cancelCloseAttempt(focusWindow: Bool) {
        model.finishWindowCloseReview()
        if closeAdmissionFrozen {
            model.lifecycle.resumeAfterContinue()
        }
        closeAdmissionFrozen = false
        closeRequest.reset()
        closeFlow = nil
        windowClosing = false
        // Preserve the current editor/auth responder instead of forcing the parent key.
        if focusWindow, window.attachedSheet == nil {
            window.makeKeyAndOrderFront(nil)
        }
    }

    private func askTransferClose() async -> Bool {
        await withCheckedContinuation { continuation in
            transferCloseReply = continuation
            let panel = NSPanel(
                contentRect: NSRect(x: 0, y: 0, width: 520, height: 205),
                styleMask: [.titled],
                backing: .buffered,
                defer: false
            )
            panel.title = "OpenLXSSH · 活动传输"
            let text = NSTextField(
                wrappingLabelWithString: "仍有传输任务。继续传输会保留窗口并取消本次关闭；取消传输并关闭会等待任务、临时文件清理及全部连接真正结束。已提交项目不会回滚；无法清理的临时文件会留在任务结果中。"
            )
            text.frame = NSRect(x: 22, y: 78, width: 476, height: 103)
            let keep = NSButton(title: "继续传输", target: self, action: #selector(continueTransfers))
            keep.identifier = .init("lifecycle.transfers.continue")
            keep.frame = NSRect(x: 30, y: 23, width: 180, height: 32)
            let cancel = NSButton(title: "取消传输并关闭", target: self, action: #selector(cancelTransfersAndClose))
            cancel.identifier = .init("lifecycle.transfers.cancelClose")
            cancel.frame = NSRect(x: 260, y: 23, width: 220, height: 32)
            panel.contentView?.addSubview(text)
            panel.contentView?.addSubview(keep)
            panel.contentView?.addSubview(cancel)
            panel.isReleasedWhenClosed = false
            panel.level = .modalPanel
            panel.center()
            transferClosePrompt = panel
            // App-level panel can coexist with a pending transfer/auth sheet. It never
            // dismantles that sheet merely because the user considered closing the window.
            panel.makeKeyAndOrderFront(nil)
        }
    }

    private func showRetainedCleanup(_ paths: [String]) async {
        await withCheckedContinuation { continuation in
            retainedCleanupReply = continuation
            let panel = NSPanel(
                contentRect: NSRect(x: 0, y: 0, width: 700, height: 340),
                styleMask: [.titled],
                backing: .buffered,
                defer: false
            )
            panel.title = "OpenLXSSH · 未清理的自有临时文件"
            let heading = NSTextField(
                wrappingLabelWithString: "连接已关闭，以下自有临时文件未能清理。App 不会扫描或自动删除它们。请复制精确路径并在独立核实后人工处理；关闭后不会恢复这些任务记录。"
            )
            heading.frame = NSRect(x: 20, y: 258, width: 660, height: 60)
            let scroll = NSScrollView(frame: NSRect(x: 20, y: 68, width: 660, height: 178))
            scroll.hasVerticalScroller = true
            let text = NSTextView(frame: scroll.bounds)
            text.isEditable = false
            text.isSelectable = true
            text.string = paths.joined(separator: "\n")
            scroll.documentView = text
            let done = NSButton(title: "已记录路径，继续关闭", target: self, action: #selector(acknowledgeRetainedCleanup))
            done.identifier = .init("lifecycle.transfers.retained.acknowledge")
            done.frame = NSRect(x: 430, y: 20, width: 250, height: 32)
            panel.contentView?.addSubview(heading)
            panel.contentView?.addSubview(scroll)
            panel.contentView?.addSubview(done)
            panel.isReleasedWhenClosed = false
            panel.level = .modalPanel
            panel.center()
            transferClosePrompt = panel
            panel.makeKeyAndOrderFront(nil)
        }
    }

    @objc private func acknowledgeRetainedCleanup() {
        transferClosePrompt?.orderOut(nil)
        transferClosePrompt = nil
        let reply = retainedCleanupReply
        retainedCleanupReply = nil
        reply?.resume()
    }

    @objc private func continueTransfers() {
        resolveTransferClose(false)
    }

    @objc private func cancelTransfersAndClose() {
        resolveTransferClose(true)
    }

    private func resolveTransferClose(_ cancel: Bool) {
        transferClosePrompt?.orderOut(nil)
        transferClosePrompt = nil
        let reply = transferCloseReply
        transferCloseReply = nil
        reply?.resume(returning: cancel)
    }
}

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSMenuItemValidation {
    let sharedRepository: AppRepository
    let sharedSecurity: SecurityCoordinator
    let sharedEnvironment: SessionEnvironment

    private(set) var windows: [ManagedWorkspaceWindow] = []
    private var terminating = false
    private var terminationReplyPending = false
    private var terminationFlow: Task<Void, Never>?

    var activeWindow: ManagedWorkspaceWindow? {
        managedWindow(for: NSApp.keyWindow)
            ?? managedWindow(for: NSApp.mainWindow)
            ?? windows.first
    }

    private var hasAnyTransferClosePrompt: Bool {
        windows.contains(where: { $0.hasTransferClosePrompt })
    }

    override init() {
        let repository = AppRepository()
        sharedRepository = repository
        sharedSecurity = SecurityCoordinator(repository: repository)
        sharedEnvironment = SessionEnvironment(location: .applicationSupport)
        super.init()
    }

    private func managedWindow(for window: NSWindow?) -> ManagedWorkspaceWindow? {
        var current = window
        while let candidate = current {
            if let match = windows.first(where: { $0.window === candidate }) {
                return match
            }
            current = candidate.sheetParent
        }
        return nil
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        _ = openNewWindow()
    }

    @discardableResult
    func openNewWindow() -> ManagedWorkspaceWindow? {
        guard !terminating, !terminationReplyPending else { return nil }
        let isFirstWindow = windows.isEmpty
        let anchorWindow = activeWindow?.window

        let model = AppModel(
            repository: sharedRepository,
            security: sharedSecurity,
            sessionEnvironment: sharedEnvironment,
            location: .applicationSupport,
            preferencesDefaults: .standard
        )

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1120, height: 720),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "OpenLXSSH"
        let managed = ManagedWorkspaceWindow(window: window, model: model)
        window.identifier = NSUserInterfaceItemIdentifier(
            isFirstWindow ? "OpenLXSSH.main" : "OpenLXSSH.window.\(managed.id.uuidString)"
        )
        WorkspaceWindowChrome.configure(window)
        window.isReleasedWhenClosed = false
        window.minSize = MainWindowFramePreferences.minimumSize
        window.contentView = NSHostingView(rootView: MainView(model: model))
        window.delegate = self

        if isFirstWindow {
            window.center()
            if let name = model.mainWindowFrameAutosaveName {
                _ = window.setFrameUsingName(name, force: true)
                recoverWindowFrame(window)
                _ = window.setFrameAutosaveName(name)
            }
        } else if let anchorWindow {
            if !anchorWindow.styleMask.contains(.fullScreen) {
                window.setFrame(NSRect(origin: window.frame.origin, size: anchorWindow.frame.size), display: false)
            }
            let topLeft = NSPoint(x: anchorWindow.frame.minX, y: anchorWindow.frame.maxY)
            if topLeft != .zero {
                _ = window.cascadeTopLeft(from: topLeft)
            } else {
                window.center()
            }
            recoverWindowFrame(window)
        } else {
            window.center()
            recoverWindowFrame(window)
        }

        windows.append(managed)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        Task { await model.reload() }
        return managed
    }

    @discardableResult
    private func ensureActiveWindow() -> ManagedWorkspaceWindow? {
        guard !terminating, !terminationReplyPending else { return nil }
        if let active = activeWindow {
            active.window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return active
        }
        return openNewWindow()
    }

    private func recoverWindowFrame(_ window: NSWindow) {
        guard !window.styleMask.contains(.fullScreen), !window.inLiveResize else { return }
        let frame = MainWindowFramePreferences.recoveredFrame(window.frame, visibleFrames: NSScreen.screens.map(\.visibleFrame))
        if window.frame != frame {
            window.setFrame(frame, display: window.isVisible)
        }
    }

    func windowDidChangeScreen(_ notification: Notification) {
        guard let window = notification.object as? NSWindow,
              windows.contains(where: { $0.window === window }) else { return }
        recoverWindowFrame(window)
    }

    func applicationDidChangeScreenParameters(_ notification: Notification) {
        for managed in windows {
            recoverWindowFrame(managed.window)
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        guard let managed = windows.first(where: { $0.window === sender }) else { return true }
        if managed.windowCloseApproved { return true }
        guard !terminating, !terminationReplyPending else { return false }
        managed.requestClose(managedWindowsProvider: { [weak self] in self?.windows ?? [] })
        return false
    }

    func windowWillClose(_ notification: Notification) {
        guard let sender = notification.object as? NSWindow,
              let index = windows.firstIndex(where: { $0.window === sender }) else { return }
        let managed = windows.remove(at: index)
        managed.handleDidClose(terminating: terminating)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard !terminating, !terminationReplyPending else { return false }
        if windows.isEmpty {
            _ = openNewWindow()
        } else {
            activeWindow?.window.makeKeyAndOrderFront(nil)
            if !flag {
                NSApp.activate(ignoringOtherApps: true)
            }
        }
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateLater }
        guard !terminationReplyPending else { return .terminateLater }
        terminationReplyPending = true
        terminationFlow = Task { @MainActor [self] in
            await performApplicationTermination()
        }
        return .terminateLater
    }

    private func performApplicationTermination() async {
        var reviewed: [(managed: ManagedWorkspaceWindow, review: WindowCloseReviewRequest)] = []

        func abortTermination(focusing failed: ManagedWorkspaceWindow? = nil) {
            for entry in reviewed {
                entry.managed.cancelCloseAttempt(focusWindow: entry.managed === failed)
            }
            if let failed, !reviewed.contains(where: { $0.managed === failed }) {
                failed.cancelCloseAttempt(focusWindow: true)
            }
            terminationFlow = nil
            if terminationReplyPending {
                terminationReplyPending = false
                replyToTermination(false)
            }
        }

        // Phase 1: coordinate close review sequentially across all currently open windows.
        let snapshot = windows
        for managed in snapshot {
            if let inFlightResult = await managed.awaitInFlightCloseIfNeeded() {
                if !inFlightResult {
                    abortTermination(focusing: managed)
                    return
                }
                continue
            }
            guard windows.contains(where: { $0 === managed }) else { continue }
            guard let review = await managed.reviewForTermination(managedWindows: windows) else {
                abortTermination(focusing: managed)
                return
            }
            reviewed.append((managed, review))
        }

        // Re-verify every reviewed window is still current before tearing down any connections.
        for entry in reviewed {
            guard entry.managed.model.isWindowCloseReviewCurrent(entry.review) else {
                abortTermination(focusing: entry.managed)
                return
            }
        }

        // Phase 2: all windows approved review & transfers; close connections across all windows.
        for entry in reviewed {
            entry.managed.approveForTermination()
        }

        var firstFailed: ManagedWorkspaceWindow?
        for entry in reviewed {
            let closedCleanly = await entry.managed.closeConnectionsAndNotifyRetained()
            if !closedCleanly {
                entry.managed.model.issue = SessionController.incompleteCloseIssue
                if firstFailed == nil {
                    firstFailed = entry.managed
                }
            }
        }

        if let firstFailed {
            abortTermination(focusing: firstFailed)
            return
        }

        // Only when ALL windows approve and close cleanly, close shared resources once.
        terminating = true
        for managed in windows {
            managed.finishTermination()
        }
        do {
            try await sharedSecurity.close()
            try await sharedRepository.close()
        } catch {
            /* Do not log database or credential error descriptions. */
        }
        terminationFlow = nil
        terminationReplyPending = false
        replyToTermination(true)
    }

    private func replyToTermination(_ approved: Bool) {
        RunLoop.main.perform(inModes: [.default, .eventTracking, .modalPanel]) {
            MainActor.assumeIsolated {
                NSApp.reply(toApplicationShouldTerminate: approved)
            }
        }
    }

    private func buildMenu() {
        let menu = NSMenu()

        let app = NSMenuItem()
        menu.addItem(app)
        let appMenu = NSMenu(title: "OpenLXSSH")
        app.submenu = appMenu
        appMenu.addItem(withTitle: "关于 OpenLXSSH", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        let settings = appMenu.addItem(withTitle: "设置…", action: #selector(openSettings), keyEquivalent: ",")
        settings.target = self
        appMenu.addItem(.separator())
        let services = NSMenu(title: "服务")
        let servicesItem = NSMenuItem(title: "服务", action: nil, keyEquivalent: "")
        servicesItem.submenu = services
        appMenu.addItem(servicesItem)
        NSApp.servicesMenu = services
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "隐藏 OpenLXSSH", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "退出 OpenLXSSH", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        let file = NSMenuItem()
        menu.addItem(file)
        let fileMenu = NSMenu(title: "会话")
        file.submenu = fileMenu
        let newWindowItem = fileMenu.addItem(withTitle: "新建窗口", action: #selector(newWindow), keyEquivalent: "n")
        newWindowItem.target = self
        for (title, action, key) in [
            ("新连接…", #selector(newConnection), "t"),
            ("新建主机…", #selector(newHost), ""),
            ("当前连接信息", #selector(connectionInfo), ""),
            ("断开当前连接", #selector(disconnectSession), ""),
            ("重新连接", #selector(reconnectSession), "")
        ] {
            let item = fileMenu.addItem(withTitle: title, action: action, keyEquivalent: key)
            item.target = self
        }
        fileMenu.addItem(.separator())
        let close = fileMenu.addItem(withTitle: "关闭当前标签或窗口", action: #selector(closeWorkspace), keyEquivalent: "w")
        close.target = self

        let edit = NSMenuItem()
        menu.addItem(edit)
        let editMenu = NSMenu(title: "编辑")
        edit.submenu = editMenu
        for (title, selector, key) in [
            ("撤销", "undo:", "z"),
            ("剪切", "cut:", "x"),
            ("复制", "copy:", "c"),
            ("粘贴", "paste:", "v"),
            ("全选", "selectAll:", "a")
        ] {
            editMenu.addItem(withTitle: title, action: Selector(selector), keyEquivalent: key)
        }
        let find = editMenu.addItem(withTitle: "查找", action: #selector(findInWorkspace), keyEquivalent: "f")
        find.target = self

        let viewItem = NSMenuItem()
        menu.addItem(viewItem)
        let viewMenu = NSMenu(title: "显示")
        viewItem.submenu = viewMenu
        for (title, action, key) in [
            ("保险箱", #selector(showVault), "1"),
            ("SFTP", #selector(showSFTP), "2"),
            ("下一个标签", #selector(nextWorkspace), "]"),
            ("上一个标签", #selector(previousWorkspace), "[")
        ] {
            let item = viewMenu.addItem(withTitle: title, action: action, keyEquivalent: key)
            item.target = self
            if key == "]" || key == "[" {
                item.keyEquivalentModifierMask = [.command, .shift]
            }
        }

        let terminalItem = NSMenuItem()
        menu.addItem(terminalItem)
        let terminalMenu = NSMenu(title: "终端")
        terminalItem.submenu = terminalMenu
        for action in [
            TerminalDesktopAction.search, .clearHistory, .scrollToBottom,
            .increaseFont, .decreaseFont, .resetFont,
            .connectionInfo, .disconnect, .reconnect
        ] {
            if [.clearHistory, .increaseFont, .connectionInfo].contains(action) {
                terminalMenu.addItem(.separator())
            }
            let key: String
            switch action {
            case .increaseFont: key = "+"
            case .decreaseFont: key = "-"
            case .resetFont: key = "0"
            default: key = ""
            }
            let item = terminalMenu.addItem(withTitle: action.title, action: #selector(terminalAction(_:)), keyEquivalent: key)
            item.target = self
            item.representedObject = action.rawValue
            item.identifier = NSUserInterfaceItemIdentifier("terminal." + action.rawValue)
        }
        let fontPlus = terminalMenu.addItem(withTitle: "放大字号", action: #selector(terminalAction(_:)), keyEquivalent: "=")
        fontPlus.target = self
        fontPlus.representedObject = TerminalDesktopAction.increaseFont.rawValue
        fontPlus.isAlternate = true
        terminalMenu.addItem(.separator())

        let splitH = terminalMenu.addItem(withTitle: "左右分屏（新建同主机会话）", action: #selector(splitSessionHorizontal), keyEquivalent: "d")
        splitH.target = self
        splitH.keyEquivalentModifierMask = [.command]
        splitH.identifier = NSUserInterfaceItemIdentifier("terminal.splitHorizontal")

        let splitV = terminalMenu.addItem(withTitle: "上下分屏（新建同主机会话）", action: #selector(splitSessionVertical), keyEquivalent: "d")
        splitV.target = self
        splitV.keyEquivalentModifierMask = [.command, .shift]
        splitV.identifier = NSUserInterfaceItemIdentifier("terminal.splitVertical")

        let focusSplit = terminalMenu.addItem(withTitle: "切换分屏焦点", action: #selector(focusOtherSplitPane), keyEquivalent: "]")
        focusSplit.target = self
        focusSplit.keyEquivalentModifierMask = [.command, .option]
        focusSplit.identifier = NSUserInterfaceItemIdentifier("terminal.focusOtherSplitPane")

        let unsplit = terminalMenu.addItem(withTitle: "取消分屏", action: #selector(unsplitSession), keyEquivalent: "d")
        unsplit.target = self
        unsplit.keyEquivalentModifierMask = [.command, .option, .shift]
        unsplit.identifier = NSUserInterfaceItemIdentifier("terminal.unsplit")

        let windowItem = NSMenuItem()
        menu.addItem(windowItem)
        let windowMenu = NSMenu(title: "窗口")
        windowItem.submenu = windowMenu
        NSApp.windowsMenu = windowMenu
        windowMenu.addItem(withTitle: "最小化", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "缩放", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        let fullScreen = windowMenu.addItem(withTitle: "进入全屏幕", action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f")
        fullScreen.keyEquivalentModifierMask = [.command, .control]

        NSApp.mainMenu = menu

        let helpItem = NSMenuItem()
        menu.addItem(helpItem)
        let helpMenu = NSMenu(title: "帮助")
        helpItem.submenu = helpMenu
        NSApp.helpMenu = helpMenu
        let shortcuts = helpMenu.addItem(withTitle: "快捷键与鼠标", action: #selector(showTerminalHelp), keyEquivalent: "")
        shortcuts.target = self
        for (title, action) in [
            ("版本与本地数据说明", #selector(showLocalDataHelp)),
            ("本地诊断预览…", #selector(showDiagnostics)),
            ("第三方许可…", #selector(showLicenses))
        ] {
            let item = helpMenu.addItem(withTitle: title, action: action, keyEquivalent: "")
            item.target = self
        }
    }

    private func interactionContext(for managed: ManagedWorkspaceWindow?) -> WorkspaceInteractionContext {
        let keyWindow = NSApp.keyWindow
        let targetWindow = managed?.window
        let responder = (keyWindow ?? targetWindow)?.firstResponder
        return WorkspaceInteractionContext(
            hasAttachedSheet: targetWindow?.attachedSheet != nil,
            hasModalWindow: NSApp.modalWindow != nil || hasAnyTransferClosePrompt,
            hasOtherKeyWindow: keyWindow != nil && keyWindow !== targetWindow,
            isEditingText: responder is NSTextView || responder is NSTextField
        )
    }

    private var allowsNewWindow: Bool {
        !terminating && !terminationReplyPending && NSApp.modalWindow == nil && !hasAnyTransferClosePrompt
    }

    private func allowsWorkspaceActions(for managed: ManagedWorkspaceWindow?) -> Bool {
        guard !terminating, !terminationReplyPending else { return false }
        if let managed {
            guard !managed.windowClosing, !managed.model.lifecycle.terminating else { return false }
        }
        return interactionContext(for: managed).allowsWorkspaceActions
    }

    private func allowsWorkspaceFind(for managed: ManagedWorkspaceWindow?) -> Bool {
        guard let managed, allowsWorkspaceActions(for: managed), managed.model.canSearchWorkspace else { return false }
        let responder = (NSApp.keyWindow ?? managed.window).firstResponder
        let fieldInput = (responder as? NSTextField)?.currentEditor() as? any NSTextInputClient
        let marked = (responder as? any NSTextInputClient)?.hasMarkedText() == true
            || fieldInput?.hasMarkedText() == true
        return interactionContext(for: managed).allowsWorkspaceFind(hasMarkedText: marked)
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        guard !terminating, !terminationReplyPending else { return false }

        if menuItem.action == #selector(newWindow) {
            return allowsNewWindow
        }

        let managed = activeWindow
        if menuItem.action == #selector(closeWorkspace) {
            guard !hasAnyTransferClosePrompt else { return false }
            if let managed {
                return !managed.windowClosing || (!managed.closeApproved && managed.window.attachedSheet != nil)
            }
            return NSApp.modalWindow != nil || NSApp.keyWindow != nil
        }

        guard allowsWorkspaceActions(for: managed) else { return false }

        if menuItem.action == #selector(terminalAction(_:)),
           let raw = menuItem.representedObject as? String,
           let action = TerminalDesktopAction(rawValue: raw) {
            guard let managed else { return false }
            return !interactionContext(for: managed).isEditingText && managed.model.sessions.canPerformTerminalAction(action)
        }
        if menuItem.action == #selector(findInWorkspace) {
            return allowsWorkspaceFind(for: managed)
        }
        if menuItem.action == #selector(nextWorkspace) || menuItem.action == #selector(previousWorkspace) {
            return managed != nil
        }
        if menuItem.action == #selector(disconnectSession) {
            guard let managed else { return false }
            return managed.model.workspacePage.sessionID != nil && managed.model.sessions.selectedTab?.isReusable == true
        }
        if menuItem.action == #selector(reconnectSession) {
            guard let managed else { return false }
            return managed.model.workspacePage.sessionID != nil && managed.model.sessions.selectedTab?.canReconnect == true
        }
        if menuItem.action == #selector(connectionInfo) {
            guard let managed else { return false }
            return managed.model.workspacePage.sessionID != nil
        }
        if menuItem.action == #selector(splitSessionHorizontal) || menuItem.action == #selector(splitSessionVertical) {
            guard let managed else { return false }
            return managed.model.workspacePage.sessionID != nil
                && !interactionContext(for: managed).isEditingText
                && managed.model.sessions.selectedTab?.host != nil
        }
        if menuItem.action == #selector(focusOtherSplitPane) || menuItem.action == #selector(unsplitSession) {
            guard let managed else { return false }
            return managed.model.workspacePage.sessionID != nil
                && !interactionContext(for: managed).isEditingText
                && managed.model.sessions.isSplitActive
        }
        return true
    }

    @objc private func newWindow() {
        guard allowsNewWindow else { return }
        _ = openNewWindow()
    }

    @objc private func newConnection() {
        guard allowsWorkspaceActions(for: activeWindow), let managed = ensureActiveWindow() else { return }
        managed.model.sendWorkspaceCommand(.newConnection)
    }

    @objc private func newHost() {
        guard allowsWorkspaceActions(for: activeWindow), let managed = ensureActiveWindow() else { return }
        managed.model.showWorkspace(.vault)
        managed.model.sendWorkspaceCommand(.newHost)
    }

    @objc private func openSettings() {
        guard allowsWorkspaceActions(for: activeWindow), let managed = ensureActiveWindow() else { return }
        managed.model.sendWorkspaceCommand(.settings)
    }

    @objc private func showVault() {
        guard allowsWorkspaceActions(for: activeWindow), let managed = ensureActiveWindow() else { return }
        managed.model.showWorkspace(.vault)
    }

    @objc private func showSFTP() {
        guard allowsWorkspaceActions(for: activeWindow), let managed = ensureActiveWindow() else { return }
        managed.model.showWorkspace(.sftp)
    }

    @objc private func nextWorkspace() {
        guard let managed = activeWindow, allowsWorkspaceActions(for: managed) else { return }
        managed.model.switchWorkspace(by: 1)
    }

    @objc private func previousWorkspace() {
        guard let managed = activeWindow, allowsWorkspaceActions(for: managed) else { return }
        managed.model.switchWorkspace(by: -1)
    }

    @objc private func connectionInfo() {
        guard let managed = activeWindow, allowsWorkspaceActions(for: managed) else { return }
        managed.model.sessions.performTerminalAction(.connectionInfo)
    }

    @objc private func terminalAction(_ sender: NSMenuItem) {
        guard let managed = activeWindow,
              allowsWorkspaceActions(for: managed),
              !interactionContext(for: managed).isEditingText,
              let raw = sender.representedObject as? String,
              let action = TerminalDesktopAction(rawValue: raw) else { return }
        managed.model.sessions.performTerminalAction(action)
    }

    @objc private func showTerminalHelp() {
        showPublicHelp(title: "快捷键与鼠标", text: DesktopHelp.shortcuts)
    }

    @objc private func showLocalDataHelp() {
        showPublicHelp(
            title: "版本与本地数据",
            text: DesktopHelp.versionDescription() + "\n\n" + DesktopHelp.localDataDescription
        )
    }

    @objc private func showDiagnostics() {
        guard allowsWorkspaceActions(for: activeWindow), let managed = ensureActiveWindow() else { return }
        managed.model.sendWorkspaceCommand(.diagnostics)
    }

    @objc private func showLicenses() {
        guard allowsWorkspaceActions(for: activeWindow) else { return }
        let text = DesktopHelp.licenses
            .map { "—— " + $0.title + " ——\n\n" + DesktopHelp.licenseText($0) }
            .joined(separator: "\n\n")
        showPublicHelp(title: "第三方许可（本地 bundle）", text: text)
    }

    private func showPublicHelp(title: String, text: String) {
        guard allowsWorkspaceActions(for: activeWindow), let managed = ensureActiveWindow() else { return }
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = "本地只读内容，不访问网络、不收集日志。"
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 630, height: 350))
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        let view = NSTextView(frame: scroll.bounds)
        view.isEditable = false
        view.isSelectable = true
        view.isRichText = false
        view.font = .systemFont(ofSize: 13)
        view.string = text
        view.isVerticallyResizable = true
        view.isHorizontallyResizable = false
        view.autoresizingMask = [.width]
        view.textContainer?.widthTracksTextView = true
        scroll.documentView = view
        alert.accessoryView = scroll
        alert.addButton(withTitle: "关闭")
        NativeSheetCloseRouting.register(alert)
        alert.beginSheetModal(for: managed.window)
    }

    @objc private func findInWorkspace() {
        guard let managed = activeWindow, allowsWorkspaceFind(for: managed) else { return }
        managed.model.sendWorkspaceCommand(.search)
    }

    @objc private func disconnectSession() {
        guard let managed = activeWindow, allowsWorkspaceActions(for: managed) else { return }
        if let id = managed.model.workspacePage.sessionID {
            managed.model.sessions.disconnect(id)
        }
    }

    @objc private func reconnectSession() {
        guard let managed = activeWindow, allowsWorkspaceActions(for: managed) else { return }
        if let id = managed.model.workspacePage.sessionID {
            managed.model.sessions.reconnect(id)
        }
    }

    @objc private func splitSessionHorizontal() {
        guard let managed = activeWindow,
              allowsWorkspaceActions(for: managed),
              !interactionContext(for: managed).isEditingText,
              managed.model.workspacePage.sessionID != nil else { return }
        managed.model.sessions.splitCurrentSession(axis: .horizontal)
    }

    @objc private func splitSessionVertical() {
        guard let managed = activeWindow,
              allowsWorkspaceActions(for: managed),
              !interactionContext(for: managed).isEditingText,
              managed.model.workspacePage.sessionID != nil else { return }
        managed.model.sessions.splitCurrentSession(axis: .vertical)
    }

    @objc private func focusOtherSplitPane() {
        guard let managed = activeWindow,
              allowsWorkspaceActions(for: managed),
              !interactionContext(for: managed).isEditingText,
              managed.model.workspacePage.sessionID != nil,
              managed.model.sessions.isSplitActive else { return }
        managed.model.sessions.focusOtherSplitPane()
    }

    @objc private func unsplitSession() {
        guard let managed = activeWindow,
              allowsWorkspaceActions(for: managed),
              !interactionContext(for: managed).isEditingText,
              managed.model.workspacePage.sessionID != nil,
              managed.model.sessions.isSplitActive else { return }
        managed.model.sessions.unsplit()
    }

    @objc private func closeWorkspace() {
        guard !terminating, !hasAnyTransferClosePrompt else { return }
        let managed = activeWindow
        if let sheet = managed?.window.attachedSheet {
            var current = sheet
            while let nested = current.attachedSheet {
                current = nested
            }
            _ = NativeSheetCloseRouting.attemptClose(current)
            return
        }
        if managed?.windowClosing == true { return }
        if let modal = NSApp.modalWindow {
            _ = NativeSheetCloseRouting.attemptClose(modal)
            return
        }
        if let keyWindow = NSApp.keyWindow, !windows.contains(where: { $0.window === keyWindow }) {
            _ = NativeSheetCloseRouting.attemptClose(keyWindow)
            return
        }
        guard let managed else { return }
        if managed.model.workspacePage.sessionID != nil {
            Task { _ = await managed.model.closeCurrentWorkspace() }
        } else {
            managed.window.performClose(nil)
        }
    }
}
