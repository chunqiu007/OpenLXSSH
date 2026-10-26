import AppKit
import SwiftUI

@main enum OpenLXSSHEntry {
    @MainActor static func main() {
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
    #if HOST_PROBE
    private let smoke: NativeSmoke.Options?
    #endif

    init(arguments: [String]) throws {
        #if HOST_PROBE
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
        guard !arguments.contains(where: { $0.hasPrefix("--self-test") }) else { throw CocoaError(.validationMissingMandatoryProperty) }
        model = AppModel(repository: AppRepository())
        #endif
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        showMainWindow()
        #if HOST_PROBE
        if let smoke {
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
        guard !windowClosing else { return false }
        // Files UI will supply the visible transfer decision before this seam returns true.
        guard !model.lifecycle.requiresTransferDecision else { return false }
        windowClosing = true
        Task {
            if await model.lifecycle.closeConnections() {
                windowCloseApproved = true
                sender.performClose(nil)
            }
            windowClosing = false
        }
        return false
    }
    func windowWillClose(_ notification: Notification) {
        guard notification.object as? NSWindow === mainWindow else { return }
        model.windowClosed()
        mainWindow?.contentView = nil
        mainWindow = nil
        windowCloseApproved = false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard !terminating, !model.lifecycle.terminating else { return false }
        if !flag { showMainWindow() }
        return true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateLater }
        guard !model.lifecycle.requiresTransferDecision else { return .terminateCancel }
        terminating = true
        model.lifecycle.beginTermination()
        model.windowClosed()
        let repository = model.repository
        let security = model.security
        Task {
            _ = await model.lifecycle.closeConnections()
            #if HOST_PROBE
            if let smoke, smoke.phase == "sessions-exit" {
                let result = ["cleanupCompleted": model.sessions.tabs.isEmpty, "selectedTabCleared": model.sessions.selectedTabID == nil]
                if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) {
                    try? data.write(to: smoke.directory.appendingPathComponent("termination-cleanup.json"))
                }
            }
            #endif
            do { try await security.close(); try await repository.close() }
            catch { /* Exit still releases owned resources; never print database descriptions. */ }
            // AppKit may be inside its terminateLater nested event loop. Use the run loop,
            // not a MainActor task/main-queue block that can be excluded by that loop.
            RunLoop.main.perform(inModes: [.default, .eventTracking, .modalPanel]) {
                MainActor.assumeIsolated { NSApp.reply(toApplicationShouldTerminate: true) }
            }
        }
        return .terminateLater
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
