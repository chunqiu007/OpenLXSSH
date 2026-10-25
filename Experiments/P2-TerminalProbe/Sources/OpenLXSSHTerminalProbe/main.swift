import AppKit
import OpenLXSSHTerminalCore

@MainActor
final class ProbeApp: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var window: NSWindow!
    private var session: ProbeSession?
    private var workDirectory: URL!
    private var terminalContainer = NSView()
    private let status = NSTextField(labelWithString: "Local fixture; no SSH")
    private let search = NSSearchField()
    private let theme = NSPopUpButton()
    private let fonts = NSPopUpButton()
    private let fontSize = NSStepper()
    private var shuttingDown = false
    private var smoke: GUISmoke?

    func applicationDidFinishLaunching(_ notification: Notification) {
        do {
            workDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-P2-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: workDirectory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            createMenu()
            createWindow()
            let vimSmoke = CommandLine.arguments.contains("--vim-smoke")
            try start(vim: vimSmoke)
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            if CommandLine.arguments.contains("--gui-smoke") || vimSmoke {
                smoke = GUISmoke(window: window, session: session!, directory: workDirectory, vim: vimSmoke,
                                 completion: { [weak self] code in
                                     if code == 0 { self?.window.performClose(nil) }
                                     else { self?.shutdown(exitCode: code) }
                                 })
                smoke?.start()
            }
        } catch { fputs("Probe startup failed: \(error)\n", stderr); shutdown(exitCode: 1) }
    }

    private func createMenu() {
        let menu = NSMenu()
        let app = NSMenuItem(); menu.addItem(app)
        app.submenu = NSMenu()
        app.submenu?.addItem(withTitle: "Quit OpenLXSSH Terminal Probe", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let edit = NSMenuItem(title: "Edit", action: nil, keyEquivalent: ""); menu.addItem(edit)
        edit.submenu = NSMenu(title: "Edit")
        edit.submenu?.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.submenu?.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.submenu?.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        edit.submenu?.addItem(withTitle: "Find", action: #selector(focusSearch), keyEquivalent: "f").target = self
        NSApp.mainMenu = menu
    }

    private func button(_ title: String, _ selector: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: selector)
        button.bezelStyle = .rounded
        return button
    }
    private func createWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1120, height: 720),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "OpenLXSSH — Local Terminal Probe (SwiftTerm \(ProbeSettings.candidate))"
        window.identifier = .init("OpenLXSSH.LocalTerminalProbe")
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 850, height: 440)
        window.delegate = self
        window.center()
        let root = NSStackView()
        root.orientation = .vertical; root.spacing = 8; root.edgeInsets = NSEdgeInsets(top: 10, left: 10, bottom: 10, right: 10)
        window.contentView = root
        let notice = NSTextField(labelWithString: "LOCAL ONLY · fixed fixture / clean Vim · no SSH, network, credentials or user startup files")
        notice.textColor = .secondaryLabelColor
        root.addArrangedSubview(notice)
        let controls = NSStackView(views: [button("New Fixture", #selector(newFixture)), button("Clean Vim", #selector(newVim)),
                                         button("Close Session", #selector(closeSession)), button("Hide / Show", #selector(toggleVisible))])
        controls.spacing = 8
        theme.addItems(withTitles: ["System", "Light", "Dark"]); theme.target = self; theme.action = #selector(appearanceChanged)
        fonts.addItems(withTitles: ["System Mono", "Menlo", "Monaco"]); fonts.target = self; fonts.action = #selector(fontChanged)
        fontSize.minValue = 10; fontSize.maxValue = 28; fontSize.increment = 1; fontSize.integerValue = 14
        fontSize.target = self; fontSize.action = #selector(fontChanged)
        controls.addArrangedSubview(theme); controls.addArrangedSubview(fonts)
        controls.addArrangedSubview(NSTextField(labelWithString: "Size")); controls.addArrangedSubview(fontSize)
        root.addArrangedSubview(controls)
        search.placeholderString = "Search retained history (Cmd+F)"; search.target = self; search.action = #selector(findNext)
        let searchRow = NSStackView(views: [search, button("Previous", #selector(findPrevious)), button("Next", #selector(findNext)),
                                         button("Copy", #selector(copySelection)), button("Paste", #selector(paste)),
                                         button("Unicode Paste", #selector(pasteSample))])
        searchRow.spacing = 8
        search.widthAnchor.constraint(greaterThanOrEqualToConstant: 300).isActive = true
        root.addArrangedSubview(searchRow)
        let history = NSPopUpButton()
        history.addItems(withTitles: ["History 1,000", "History 10,000", "History 50,000 (max)"])
        history.selectItem(at: 1); history.target = self; history.action = #selector(historyChanged(_:))
        root.addArrangedSubview(history)
        root.addArrangedSubview(terminalContainer)
        terminalContainer.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -20).isActive = true
        terminalContainer.heightAnchor.constraint(greaterThanOrEqualToConstant: 200).isActive = true
        status.lineBreakMode = .byTruncatingMiddle
        root.addArrangedSubview(status)
    }

    private func fixturePath() -> String {
        URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
            .appendingPathComponent("openlxssh-terminal-fixture").standardizedFileURL.path
    }
    private func start(vim: Bool) throws {
        guard session?.isRunning != true else { status.stringValue = "Close current session first; no overlapping PTY owners"; return }
        session?.terminal.releaseUI()
        session?.terminal.removeFromSuperview()
        let next = ProbeSession()
        session = next
        next.terminal.frame = terminalContainer.bounds
        next.terminal.autoresizingMask = [.width, .height]
        terminalContainer.addSubview(next.terminal)
        next.onStateChange = { [weak self] in self?.updateStatus() }
        next.onExit = { [weak self] _ in
            guard let self else { return }
            self.updateStatus()
            if self.shuttingDown { self.finishShutdown() }
        }
        if vim {
            let document = workDirectory.appendingPathComponent("local-vim.txt")
            try "OpenLXSSH local Vim fixture\n\(ProbeSettings.unicodeSample)\n".write(to: document, atomically: true, encoding: .utf8)
            // No vimrc, viminfo, plugins, swap, user shell or remote target.
            try next.start(executable: "/usr/bin/vim", arguments: ["-u", "NONE", "-U", "NONE", "-i", "NONE", "-n", "--noplugin", document.path], directory: workDirectory.path)
        } else {
            try next.start(executable: fixturePath(), directory: workDirectory.path)
        }
        appearanceChanged(); fontChanged()
        window.makeFirstResponder(next.terminal)
        updateStatus()
    }
    private func updateStatus() {
        guard let session else { return }
        if let result = session.result {
            status.stringValue = "Exited PID \(result.pid), code \(result.exitCode.map(String.init) ?? "signal"), bytes \(result.bytesReceived). Output retained until New Fixture."
        } else {
            status.stringValue = session.inputError ?? "LOCAL PID \(session.childPID) · PTY fd \(session.masterFD) · \(session.terminal.columns)×\(session.terminal.rows) · history max 50,000"
        }
    }
    @objc private func newFixture() { do { try start(vim: false) } catch { status.stringValue = "Start failed: \(error)" } }
    @objc private func newVim() { do { try start(vim: true) } catch { status.stringValue = "Start failed: \(error)" } }
    @objc private func closeSession() { session?.close() }
    @objc private func toggleVisible() { session?.terminal.isHidden.toggle() }
    @objc private func focusSearch() { window.makeFirstResponder(search) }
    @objc private func findNext() { _ = session?.terminal.findNext(search.stringValue) }
    @objc private func findPrevious() { _ = session?.terminal.findPrevious(search.stringValue) }
    @objc private func copySelection() { session?.terminal.copy(self) }
    @objc private func paste() { session?.terminal.paste(self); window.makeFirstResponder(session?.terminal) }
    @objc private func pasteSample() { session?.terminal.pasteTextFromApp(ProbeSettings.unicodeSample + "\nline two"); window.makeFirstResponder(session?.terminal) }
    @objc private func historyChanged(_ sender: NSPopUpButton) { session?.setHistory([1_000, 10_000, 50_000][sender.indexOfSelectedItem]) }
    @objc private func fontChanged() {
        let size = CGFloat(fontSize.integerValue)
        let name = fonts.titleOfSelectedItem ?? "System Mono"
        session?.terminal.font = name == "System Mono" ? .monospacedSystemFont(ofSize: size, weight: .regular) : (NSFont(name: name, size: size) ?? .monospacedSystemFont(ofSize: size, weight: .regular))
    }
    @objc private func appearanceChanged() {
        window.appearance = theme.indexOfSelectedItem == 1 ? NSAppearance(named: .aqua) : (theme.indexOfSelectedItem == 2 ? NSAppearance(named: .darkAqua) : nil)
        session?.terminal.applyColors(for: window.effectiveAppearance)
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool { shutdown(exitCode: 0); return false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if shuttingDown { return .terminateNow }
        shutdown(exitCode: 0)
        return .terminateCancel
    }
    private var exitCode: Int32 = 0
    private func shutdown(exitCode: Int32) {
        guard !shuttingDown else { return }
        shuttingDown = true; self.exitCode = exitCode
        if session?.isRunning == true { session?.close() } else { finishShutdown() }
    }
    private func finishShutdown() {
        session?.terminal.releaseUI()
        session?.terminal.removeFromSuperview(); session = nil
        window?.orderOut(nil)
        if let workDirectory { try? FileManager.default.removeItem(at: workDirectory) }
        // Allow DispatchIO cleanup and upstream view observers to retire.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { Darwin.exit(self.exitCode) }
    }
}

MainActor.assumeIsolated {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let delegate = ProbeApp()
    app.delegate = delegate
    withExtendedLifetime(delegate) { app.run() }
}
