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
    #if HOST_PROBE
    private let smoke: NativeSmoke.Options?
    #endif

    init(arguments: [String]) throws {
        #if HOST_PROBE
        let options = try NativeSmoke.Options(arguments)
        smoke = options
        model = AppModel(repository: AppRepository(location: options.map { .isolated($0.directory) } ?? .applicationSupport))
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

    func windowWillClose(_ notification: Notification) {
        guard notification.object as? NSWindow === mainWindow else { return }
        model.windowClosed()
        mainWindow?.contentView = nil
        mainWindow = nil
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { showMainWindow() }
        return true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateNow }
        terminating = true
        model.windowClosed()
        let repository = model.repository
        Task.detached {
            do { try await repository.close() }
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
