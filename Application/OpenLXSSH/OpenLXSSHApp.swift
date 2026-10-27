import AppKit
import SwiftUI
#if HOST_PROBE
import OpenLXSSHFiles
#endif

@main enum OpenLXSSHEntry {
    @MainActor static func main() {
        do {
            #if HOST_PROBE
            let real = try AppRealIntegrationArguments.parse(Array(CommandLine.arguments.dropFirst()), hostProbe: true)
            #else
            let real = try AppRealIntegrationArguments.parse(Array(CommandLine.arguments.dropFirst()), hostProbe: false)
            #endif
            if real.action == .help { print(AppRealIntegrationArguments.help); return }
            if real.action == .validate { print("Real fixture syntax only; no file/network I/O."); return }
        } catch {
            FileHandle.standardError.write(Data("OpenLXSSH: real fixture flags refused.\n".utf8)); exit(64)
        }
        let application = NSApplication.shared
        application.setActivationPolicy(.regular)
        let delegate: AppDelegate
        do { delegate = try AppDelegate(arguments: Array(CommandLine.arguments.dropFirst())) }
        catch {
            FileHandle.standardError.write(Data("OpenLXSSH: invalid isolated test arguments.\n".utf8))
            exit(64)
        }
        application.delegate = delegate
        withExtendedLifetime(delegate) { application.run() }
    }
}

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let model: AppModel
    private(set) var mainWindow: NSWindow?
    private var terminating = false
    private var windowClosing = false
    private var windowCloseApproved = false
    private var closeIntent: CloseIntent?
    private var closeFlow: Task<Void, Never>?
    private var terminationReplyPending = false
    private var closeApproved = false
    private var transferClosePrompt: NSPanel?
    private var transferCloseReply: CheckedContinuation<Bool, Never>?
    private var retainedCleanupReply: CheckedContinuation<Void, Never>?
    private enum CloseIntent { case window, quit }
    #if HOST_PROBE
    private let smoke: NativeSmoke.Options?
    private var realIntegration: AppRealIntegration?
    var realQuitBeforeStoresClose: ((TransferManagerSnapshot) async throws -> Void)?
    var realQuitAfterStoresClose: (() async throws -> Void)?
    var realQuitFailure: (() -> Void)?
    #endif

    init(arguments: [String]) throws {
        #if HOST_PROBE
        let real = try AppRealIntegrationArguments.parse(arguments, hostProbe: true)
        if real.action == .live {
            guard let path = real.contractPath,
                  let epoch = Bundle.main.object(forInfoDictionaryKey: "OpenLXSSHRealFixtureBuildEpoch") as? Double else { throw AppRealIntegrationFailure.contract }
            try AppRealIntegration.validateSignature()
            let input = try AppRealPublicMaterial.load(path, buildEpoch: epoch)
            let store = try AppRealOwnedStore(runID: input.contract.runID)
            let location = AppDataLocation.isolated(store.url), repository = AppRepository(location: location)
            let credentials = AppRealNoCredentials(namespace: UUID(uuidString: input.contract.runID)!)
            let security = SecurityCoordinator(repository: repository, location: location, credentials: credentials)
            let environment = SessionEnvironment(location: location), facts = AppRealFilesFacts()
            let builder = DirectSessionBuilder(repository: repository, security: security, environment: environment,
                scanner: AppRealSystemScanner(seconds: real.scanSeconds))
            let connector = AppRealFilesConnector(LibSSH2FilesConnector(repository: repository, security: security, environment: environment), facts: facts)
            model = AppModel(repository: repository, security: security, location: location, sessionBuilder: builder, filesConnector: connector)
            smoke = nil
            super.init()
            realIntegration = AppRealIntegration(delegate: self, options: real, input: input, store: store, facts: facts, credentials: credentials)
            return
        }
        let options = try NativeSmoke.Options(arguments)
        smoke = options
        let location = options.map { AppDataLocation.isolated($0.directory) } ?? .applicationSupport
        let repository = AppRepository(location: location)
        let builder = options.map { _ in ProbeSessionBuilder(repository: repository) }
        let filesConnector: LocalFilesProbeConnector?
        if let options {
            let root = options.directory.appendingPathComponent("LocalFilesFixture", isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            filesConnector = LocalFilesProbeConnector(root: root)
        } else { filesConnector = nil }
        model = AppModel(repository: repository, security: SecurityCoordinator(repository: repository, location: location,
                         credentials: SystemCredentials(testNamespace: options?.namespace)), location: location, sessionBuilder: builder, filesConnector: filesConnector)
        #else
        _ = try AppRealIntegrationArguments.parse(arguments, hostProbe: false)
        guard !arguments.contains(where: { $0.hasPrefix("--self-test") }) else { throw CocoaError(.validationMissingMandatoryProperty) }
        model = AppModel(repository: AppRepository())
        #endif
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        showMainWindow()
        #if HOST_PROBE
        if let realIntegration { Task { await realIntegration.run() } }
        else if let smoke {
            Task { await NativeSmoke(delegate: self, options: smoke).run() }
        }
        #endif
    }

    @objc func showMainWindow() {
        guard !terminating, !model.lifecycle.terminating else { return }
        if let mainWindow { mainWindow.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); return }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1120, height: 720), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "OpenLXSSH"
        window.identifier = NSUserInterfaceItemIdentifier("OpenLXSSH.main")
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 920, height: 580)
        window.contentView = NSHostingView(rootView: MainView(model: model))
        window.delegate = self
        window.center()
        mainWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        Task { await model.reload() }
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
        windowCloseApproved = false
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
    private func requestClose(_ intent: CloseIntent) {
        if closeIntent == .quit || intent == .quit { closeIntent = .quit } else { closeIntent = .window }
        // Synchronous revocation precedes the first task/actor hop, but does not cancel jobs.
        model.lifecycle.freezeCloseAdmission()
        if closeFlow != nil, closeApproved, intent == .quit { approveTermination() }
        guard closeFlow == nil else { return }
        windowClosing = true
        closeFlow = Task { @MainActor [self] in
            let active = await model.lifecycle.activeTransferSnapshot()
            if active {
                let cancelAndClose = await askTransferClose()
                if !cancelAndClose {
                    model.lifecycle.resumeAfterContinue()
                    closeIntent = nil; closeFlow = nil; closeApproved = false; windowClosing = false
                    mainWindow?.makeKeyAndOrderFront(nil)
                    if terminationReplyPending { terminationReplyPending = false; replyToTermination(false) }
                    return
                }
            }
            // A declined quit never sets these permanent flags. An approved quit joining
            // window cleanup does so immediately and shares the same owned cleanup task.
            closeApproved = true
            if closeIntent == .quit { approveTermination() }
            let managerBeforeClose = model.files.manager
            let labelsBeforeClose = model.files.transferLabels
            model.files.deferResetUntilCloseAcknowledged()
            _ = await model.lifecycle.closeConnections(cancelTransfers: true, retainAdmissionFreeze: true)
            let finalTransfers = await managerBeforeClose.snapshot()
            let retained = finalTransfers.jobs.flatMap { job in job.retainedTemporaryPaths.map { path -> String in
                let label = labelsBeforeClose[job.id]
                let root = label?.localRoots[job.request.destination.serviceID]
                let bytes = root.map { ($0 == .root ? Data() : $0.bytes) + path.bytes } ?? path.bytes
                return (label?.endpoint ?? job.request.hostID) + " · " + FileDisplay.bytes(bytes)
            } }
            if !retained.isEmpty { await showRetainedCleanup(retained) }
            model.files.finishWindowCloseReset()
            if closeIntent == .quit {
                approveTermination()
                #if HOST_PROBE
                if let smoke, smoke.phase == "sessions-exit" {
                    let result = ["cleanupCompleted": model.sessions.tabs.isEmpty, "selectedTabCleared": model.sessions.selectedTabID == nil]
                    if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) { try? data.write(to: smoke.directory.appendingPathComponent("termination-cleanup.json")) }
                }
                if let smoke, smoke.phase == "files-transfer-exit" {
                    let final = await managerBeforeClose.snapshot()
                    let result = ["managerClosed": final.isClosed, "allWorkDrained": !final.hasActiveWork,
                                  "cancelledTransfer": final.jobs.contains { $0.state == .cancelled },
                                  "sshTabsCleared": model.sessions.tabs.isEmpty,
                                  "noRetainedTemps": final.jobs.allSatisfy { $0.retainedTemporaryPaths.isEmpty }]
                    if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) { try? data.write(to: smoke.directory.appendingPathComponent("transfer-exit-cleanup.json")) }
                }
                #endif
                #if HOST_PROBE
                if let realQuitBeforeStoresClose {
                    do { try await realQuitBeforeStoresClose(finalTransfers) }
                    catch {
                        realQuitFailure?(); terminationReplyPending = false; replyToTermination(false); return
                    }
                }
                #endif
                do { try await model.security.close(); try await model.repository.close() }
                catch {
                    #if HOST_PROBE
                    if realQuitBeforeStoresClose != nil {
                        realQuitFailure?(); terminationReplyPending = false; replyToTermination(false); return
                    }
                    #endif
                    /* Do not log database or credential error descriptions. */
                }
                #if HOST_PROBE
                if let realQuitAfterStoresClose {
                    do { try await realQuitAfterStoresClose() }
                    catch {
                        realQuitFailure?(); terminationReplyPending = false; replyToTermination(false); return
                    }
                }
                #endif
                terminationReplyPending = false; replyToTermination(true)
            } else {
                windowCloseApproved = true; mainWindow?.performClose(nil)
                closeIntent = nil; closeFlow = nil; closeApproved = false; windowClosing = false
            }
        }
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
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "隐藏 OpenLXSSH", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "退出 OpenLXSSH", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let file = NSMenuItem(); menu.addItem(file)
        let fileMenu = NSMenu(title: "文件"); file.submenu = fileMenu
        let reopen = fileMenu.addItem(withTitle: "打开主窗口", action: #selector(showMainWindow), keyEquivalent: "n"); reopen.target = self
        fileMenu.addItem(withTitle: "关闭窗口", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        let edit = NSMenuItem(); menu.addItem(edit)
        let editMenu = NSMenu(title: "编辑"); edit.submenu = editMenu
        for (title, selector, key) in [("撤销", "undo:", "z"), ("剪切", "cut:", "x"), ("复制", "copy:", "c"), ("粘贴", "paste:", "v"), ("全选", "selectAll:", "a")] {
            editMenu.addItem(withTitle: title, action: Selector(selector), keyEquivalent: key)
        }
        NSApp.mainMenu = menu
    }
}
