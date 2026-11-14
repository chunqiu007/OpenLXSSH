#if HOST_PROBE
import AppKit
import Darwin
import Foundation
import ObjectiveC
import SwiftUI
import OpenLXSSHCore
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust
import OpenLXSSHFiles

/// HostProbe-only in-process GUI exercise. All mutations go through rendered native controls
/// and their target/action paths, and all files are confined to a marked temporary test root.
@MainActor final class NativeSmoke {
    struct Options {
        let directory: URL
        let phase: String
        let namespace: UUID
        init?(_ arguments: [String]) throws {
            guard arguments.contains("--self-test-data-dir") else {
                guard !arguments.contains(where: { $0.hasPrefix("--self-test") }) else { throw Failure.invalidArguments }
                return nil
            }
            guard arguments.count == 4, arguments[0] == "--self-test-data-dir", arguments[2] == "--self-test-phase",
                  ["native-discovery", "desktop-cua", "native-dismiss", "terminal-desktop-cua", "terminal-desktop", "workspace", "exercise", "reopen", "sessions", "sessions-exit", "sessions-pressure", "files-local", "files-transfers", "files-transfer-exit", "transport-config", "security-sheets", "security", "security-read", "security-cleanup"].contains(arguments[3]) else { throw Failure.invalidArguments }
            directory = URL(fileURLWithPath: arguments[1], isDirectory: true)
            phase = arguments[3]
            _ = try AppDataLocation.isolated(directory).databaseDirectory()
            guard try String(contentsOf: directory.appendingPathComponent(".openlxssh-app-smoke"), encoding: .utf8) == "OpenLXSSH isolated GUI smoke\n" else {
                throw Failure.invalidArguments
            }
            let namespaceFile = directory.appendingPathComponent("test-namespace.txt")
            if let text = try? String(contentsOf: namespaceFile, encoding: .utf8), let value = UUID(uuidString: text.trimmingCharacters(in: .whitespacesAndNewlines)) { namespace = value }
            else { namespace = UUID(); try namespace.uuidString.write(to: namespaceFile, atomically: true, encoding: .utf8) }
        }
    }
    enum Failure: Error { case invalidArguments, timeout(String), check(String), missing(String) }
    struct Check: Codable { let name: String; let passed: Bool }
    struct Report: Codable {
        let kind: String
        let phase: String
        let passed: Bool
        let checks: [Check]
        let actions: [String]
        let failureCode: String?
        let productRuntimeVerified: Bool
        let scope: String?
    }
    let delegate: AppDelegate
    let options: Options
    var model: AppModel { delegate.model }
    private var checks: [Check] = []
    private var actions: [String] = []
    private var transferPromptTimer: Timer?
    private var cuaDeadline: ContinuousClock.Instant?
    private var cuaWindow: NSWindow?
    private var cuaDriver: ProbeSessionDriver?
    private var cuaOwnsPasteboard = false
    private var desktopCUACleanupTask: Task<Void, Error>?
    private var desktopCUACleanupFinished = false
    private var controlDiagnosticSequence = 0
    private var ownedWindowKeySamples: [[String: Any]] = []
    private var terminationEvents: [[String: Any]] = []
    private var terminationObserver: (any NSObjectProtocol)?
    init(delegate: AppDelegate, options: Options) { self.delegate = delegate; self.options = options }

    func run() async {
        do {
            try await wait("initial-load") { self.model.didLoad && !self.model.isLoading }
            if options.phase != "desktop-cua" {
                try check("native-main-window", delegate.mainWindow?.isVisible == true)
                try check("startup-no-session", model.connectionNotice == nil)
            }
            if options.phase == "native-discovery" { try await nativeDiscoveryExercise() }
            else if options.phase == "desktop-cua" { try await desktopCUAHold() }
            else if options.phase == "native-dismiss" { try await nativeDismissExercise() }
            else if options.phase == "terminal-desktop" || options.phase == "terminal-desktop-cua" { try await terminalDesktopExercise() }
            else if options.phase == "workspace" { try await workspaceExercise() }
            else if options.phase == "exercise" { try await exercise() }
            else if options.phase == "reopen" { try await verifyRelaunch() }
            else if options.phase == "security-sheets" { try await securitySheets() }
            else if options.phase == "sessions" || options.phase == "sessions-exit" { try await sessionExercise() }
            else if options.phase == "sessions-pressure" { try await sessionPressureExercise() }
            else if options.phase == "transport-config" { try await transportConfiguration() }
            else if options.phase == "files-local" { try await filesLocalExercise() }
            else if options.phase == "files-transfers" || options.phase == "files-transfer-exit" { try await filesTransferExercise() }
            else { try await securityExercise() }
            if options.phase == "terminal-desktop-cua" { await cleanupCUAResources() }
            try finish(success: true, failure: nil)
            scheduleAppKitTermination()
        } catch {
            // Only static scenario labels are emitted. Never serialize arbitrary Error descriptions.
            var code: String
            switch error {
            case Failure.timeout(let label): code = "timeout." + label
            case Failure.check(let label): code = "check." + label
            case Failure.missing(let label): code = "missing." + label
            default: code = "smoke.failed"
            }
            if options.phase == "terminal-desktop-cua" { await cleanupCUAResources() }
            if options.phase == "desktop-cua", let window = delegate.mainWindow {
                try? writeCUAReady(window: window, step: "incomplete-desktop-cua")
            }
            if options.phase == "desktop-cua" {
                if desktopCUACleanupTask == nil {
                    do { try await cleanupDesktopCUAResources() }
                    catch { code = "incomplete.desktop-cua-cleanup" }
                }
            }
            try? finish(success: false, failure: code)
            exit(1)
        }
    }

    /// Audit scheduling without treating a written smoke report as process-exit proof.
    /// Keep AppDelegate's real terminateLater / stores-close / reply path intact.
    private func scheduleAppKitTermination() {
        terminationObserver = NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: NSApp, queue: .main) { [self] _ in
            MainActor.assumeIsolated { recordTermination("will-terminate") }
        }
        recordTermination("scheduled")
        // Deliberately retain the existing run-loop scheduling while diagnosing R0.
        // The external verifier must still observe an actual, natural process exit.
        RunLoop.main.perform { [self] in
            MainActor.assumeIsolated {
                recordTermination("dispatched")
                NSApp.terminate(nil)
                recordTermination("returned-from-terminate")
            }
        }
    }
    private func recordTermination(_ event: String) {
        guard terminationEvents.count < 8 else { return }
        let mode: String
        switch RunLoop.main.currentMode {
        case .some(.default): mode = "default"
        case .some(.eventTracking): mode = "eventTracking"
        case .some(.modalPanel): mode = "modalPanel"
        case .none: mode = "none"
        default: mode = "other"
        }
        terminationEvents.append(["event": event, "uptime": ProcessInfo.processInfo.systemUptime,
            "runLoopMode": mode, "modelTerminating": model.lifecycle.terminating,
            "mainWindowVisible": delegate.mainWindow?.isVisible == true,
            "desktopCleanupStarted": desktopCUACleanupTask != nil, "desktopCleanupFinished": desktopCUACleanupFinished])
        guard let data = try? JSONSerialization.data(withJSONObject: ["events": terminationEvents], options: [.prettyPrinted, .sortedKeys]) else { return }
        try? data.write(to: options.directory.appendingPathComponent("termination-audit.json"), options: .atomic)
    }
    /// Fixed public AppKit state only; no AX traversal expansion, text or field values.
    private func recordOwnedWindowKey(stage: String, owner: NSWindow, root: NSView) {
        guard ownedWindowKeySamples.count < 8,
              ["before-activation", "after-activation-call", "activation-wait-timeout", "after-activation-yield"].contains(stage) else { return }
        let parent = owner.sheetParent
        func state(_ window: NSWindow?) -> [String: Any] {
            guard let window else { return ["present": false] }
            let mask = window.styleMask
            return ["present": true, "canBecomeKey": window.canBecomeKey, "canBecomeMain": window.canBecomeMain,
                "isKey": window.isKeyWindow, "isMain": window.isMainWindow, "isVisible": window.isVisible,
                "isMiniaturized": window.isMiniaturized, "frameSize": [window.frame.width, window.frame.height],
                "style": ["borderless": mask.isEmpty, "titled": mask.contains(.titled), "closable": mask.contains(.closable),
                    "miniaturizable": mask.contains(.miniaturizable), "resizable": mask.contains(.resizable),
                    "docModalWindow": mask.contains(.docModalWindow), "nonactivatingPanel": mask.contains(.nonactivatingPanel),
                    "fullSizeContentView": mask.contains(.fullSizeContentView)]]
        }
        let mode: String
        switch RunLoop.main.currentMode {
        case .some(.default): mode = "default"
        case .some(.eventTracking): mode = "eventTracking"
        case .some(.modalPanel): mode = "modalPanel"
        case .none: mode = "none"
        default: mode = "other"
        }
        let policy: String
        switch NSApp.activationPolicy() {
        case .regular: policy = "regular"
        case .accessory: policy = "accessory"
        case .prohibited: policy = "prohibited"
        default: policy = "other"
        }
        let exactRoot = owner.contentView === root && root.window === owner
        let fields = exactRoot ? controlTree(in: owner).nodes.compactMap { $0.object as? NSTextField } : []
        let editors = fields.compactMap { $0.currentEditor() as? NSTextView }.filter(\.isFieldEditor)
        ownedWindowKeySamples.append(["stage": stage, "isMainThread": Thread.isMainThread, "runLoopMode": mode,
            "activationPolicy": policy, "appIsActive": NSApp.isActive, "owner": state(owner), "sheetParent": state(parent),
            "currentOwnerExact": interactiveWindow() === owner, "exactRoot": exactRoot,
            "sheetParentIsMainWindow": parent != nil && parent === delegate.mainWindow,
            "parentAttachedSheetExact": parent?.attachedSheet === owner,
            "nativeParentIsSheetParent": parent != nil && owner.parent === parent,
            "keyWindowPresent": NSApp.keyWindow != nil, "keyWindowIsOwner": NSApp.keyWindow === owner,
            "keyWindowIsSheetParent": parent != nil && NSApp.keyWindow === parent,
            "keyWindowIsChildOfOwner": NSApp.keyWindow?.parent === owner,
            "mainWindowIsOwner": NSApp.mainWindow === owner, "mainWindowIsSheetParent": parent != nil && NSApp.mainWindow === parent,
            "actualFieldEditorPresent": !editors.isEmpty, "actualFieldEditorWindowIsOwner": editors.contains { $0.window === owner },
            "actualFieldEditorWindowIsChildOfOwner": editors.contains { $0.window?.parent === owner },
            "actualFieldEditorWindowIsAppKey": editors.contains { $0.window != nil && $0.window === NSApp.keyWindow },
            "actualFieldEditorIsOwnerFirstResponder": editors.contains { owner.firstResponder === $0 },
            "arbitraryTextSerialized": false, "fieldValuesInspected": false])
        guard let data = try? JSONSerialization.data(withJSONObject: ["samples": ownedWindowKeySamples], options: [.prettyPrinted, .sortedKeys]) else { return }
        try? data.write(to: options.directory.appendingPathComponent("owned-window-key-diagnostics.json"), options: .atomic)
    }
    private func nativeDiscoveryExercise() async throws {
        try check("discovery-fresh-isolated-store", try await model.repository.securityMetadata().hosts.isEmpty)
        try await menuAction("newHost")
        try await wait("discovery-editor-sheet") { self.delegate.mainWindow?.attachedSheet is NativeOwnedSheetWindow }
        try await pause()
        let owner = try require(interactiveWindow(), "discovery-interactive-window")
        let root = try require(owner.contentView, "discovery-content-root")
        guard owner is NativeOwnedSheetWindow, root.window === owner else { throw Failure.check("discovery-owned-root") }
        writeControlDiagnostics(stage: "editor-presented", window: owner) // A: unchanged public candidates.
        recordOwnedWindowKey(stage: "before-activation", owner: owner, root: root)
        owner.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
        recordOwnedWindowKey(stage: "after-activation-call", owner: owner, root: root)
        do {
            try await wait("discovery-owned-window-key") {
                self.interactiveWindow() === owner && owner.contentView === root && root.window === owner &&
                    owner.isKeyWindow && NSApp.keyWindow === owner
            }
        } catch {
            recordOwnedWindowKey(stage: "activation-wait-timeout", owner: owner, root: root)
            throw error
        }
        try await pause() // Yield to the real App event loop before rereading the same root.
        recordOwnedWindowKey(stage: "after-activation-yield", owner: owner, root: root)
        guard interactiveWindow() === owner, owner.contentView === root, root.window === owner,
              owner.isKeyWindow, NSApp.keyWindow === owner else { throw Failure.check("discovery-owned-root") }
        writeControlDiagnostics(stage: "editor-after-owned-activation", window: owner) // B: activation only.
        for id in ["host.address", "host.name", "host.username"] {
            try check("discovery-unique-" + id, controlMatches(id, in: owner).count == 1)
        }
        try check("discovery-unique-save", buttonMatches(title: "保存", in: owner).count == 1)
        try await menuKey("w")
        try await wait("discovery-new-editor-close-confirmation") { owner.attachedSheet is NativeOwnedSheetWindow }
        let prompt = try require(owner.attachedSheet, "discovery-close-confirmation-owner")
        try await pressVisibleButton("放弃更改", owner: prompt)
        try await wait("discovery-editor-closed") { self.delegate.mainWindow?.attachedSheet == nil }
        try check("discovery-did-not-write", try await model.repository.securityMetadata().hosts.isEmpty)
    }

    private func terminalDesktopExercise() async throws {
        _ = try await createEditorFixture(name: "Terminal desktop fixture", waitLabel: "terminal-fixture-host")
        try await selectFirstHost(); try await doubleClickFirstHost()
        try await wait("terminal-fixture-driver") { self.model.sessions.selectedTab?.driver != nil }
        let tab = try require(model.sessions.selectedTab, "terminal-tab")
        let driver = try require(tab.driver as? ProbeSessionDriver, "terminal-logic-driver"), terminal = driver.terminal
        let token = driver.token, parent = terminal.superview
        // A synthetic control event exercises the connected layout; no SSH or PTY.
        driver.onState?(token, .connected)
        try await pause()
        try check("connected-layout-no-permanent-buttons", find("terminal.copy", as: NSButton.self) == nil && find("terminal.paste", as: NSButton.self) == nil && find("terminal.disconnect", as: NSButton.self) == nil && find("terminal.search", as: NSTextField.self) == nil)
        let window = try require(delegate.mainWindow, "terminal-window")
        terminal.feed(text: "\u{1b}[2J\u{1b}[Hfixture@desktop % printf 'color sample'\r\nerror stderr stays ordinary text\r\n\u{1b}[31mANSI-red\u{1b}[0m \u{1b}[38;5;196m256-red\u{1b}[0m \u{1b}[38;2;80;190;220mtruecolor\u{1b}[0m \u{1b}[1mbold\u{1b}[0m \u{1b}[7mreverse\u{1b}[0m\r\n中文 🙂 e\u{301} · real SwiftTerm renderer\r\n")
        for size in [NSSize(width: 1000, height: 650), NSSize(width: 1280, height: 800), NSSize(width: 1440, height: 900)] {
            window.setContentSize(size); window.contentView?.layoutSubtreeIfNeeded(); try await pause()
            try check("terminal-fills-page-\(Int(size.width))", terminal.bounds.height >= size.height - DesktopStyle.barHeight - 18 && terminal.bounds.width >= size.width - 18)
            try capture("terminal-desktop-\(Int(size.width))x\(Int(size.height)).png")
        }
        let snapshot = try require(terminal.terminalContentSnapshot(region: .viewport), "renderer-color-snapshot")
        let ordinary = try require(snapshot.rows.first { $0.text.contains("error stderr") }, "ordinary-text-row")
        try check("ordinary-error-has-default-style", ordinary.cells.prefix(12).allSatisfy { $0.attribute.fg == .defaultColor })
        let colored = try require(snapshot.rows.first { $0.text.contains("ANSI-red") }, "ANSI-row")
        try check("actual-ANSI-256-truecolor-bold-reverse", colored.cells.contains { $0.attribute.fg == .ansi256(code: 1) } && colored.cells.contains { $0.attribute.fg == .ansi256(code: 196) } && colored.cells.contains { $0.attribute.fg == .trueColor(red: 80, green: 190, blue: 220) } && colored.cells.contains { $0.attribute.style.contains(.bold) } && colored.cells.contains { $0.attribute.style.contains(.inverse) })
        for appearance in [NSAppearance.Name.aqua, .darkAqua] {
            terminal.appearance = NSAppearance(named: appearance); terminal.viewDidChangeEffectiveAppearance()
            try check("default-stays-dark-" + appearance.rawValue, terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB) == NativeTerminalView.desktopBackground.usingColorSpace(.deviceRGB))
        }
        let isCUA = options.phase == "terminal-desktop-cua"
        let payload = isCUA ? "OpenLXSSH CUA exact paste 中文 🙂 e\u{301}\nsecond line\n" : "printf '中文🙂 e\u{301}'\nsecond\r\n\t\u{03}"
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents(); pasteboard.setString(payload, forType: .string)
        terminal.selectNone(); window.makeFirstResponder(terminal)
        terminal.copy(NSNull())
        try check("empty-copy-keeps-pasteboard", pasteboard.string(forType: .string) == payload)
        let inputStart = driver.terminalMetrics.input.count
        if isCUA {
            cuaWindow = window; cuaDriver = driver; cuaOwnsPasteboard = true
            cuaDeadline = ContinuousClock.now.advanced(by: .seconds(120))
            try await waitForCUAPaste(driver: driver, window: window, inputStart: inputStart,
                                      expected: Data(payload.utf8), step: "activate-terminal-and-press-Cmd-V-plain")
        } else {
            window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
            try await wait("terminal-window-key-for-native-edit-menu") { window.isKeyWindow && NSApp.keyWindow === window }
            try await editMenuKey("v")
        }
        let pastedBytes = Data(driver.terminalMetrics.input.dropFirst(inputStart))
        if pastedBytes != Data(payload.utf8) {
            let diagnostics: [String: Any] = ["keyWindow": NSApp.keyWindow === window, "mainWindow": NSApp.mainWindow === window,
                "windowKey": window.isKeyWindow, "firstResponder": String(describing: window.firstResponder.map { Swift.type(of: $0) }),
                "expectedBytes": Array(payload.utf8), "actualBytes": Array(pastedBytes), "pasteboardMatches": pasteboard.string(forType: .string) == payload]
            try JSONSerialization.data(withJSONObject: diagnostics, options: [.prettyPrinted, .sortedKeys]).write(to: options.directory.appendingPathComponent("paste-routing-diagnostics.json"))
        }
        try check("Cmd-V-exact-UTF8-multiline", pastedBytes == Data(payload.utf8))
        terminal.feed(text: "\u{1b}[?2004h")
        let bracketedStart = driver.terminalMetrics.input.count
        if isCUA {
            try await waitForCUAPaste(driver: driver, window: window, inputStart: bracketedStart,
                expected: Data("\u{1b}[200~".utf8) + Data(payload.utf8) + Data("\u{1b}[201~".utf8),
                step: "press-Cmd-V-bracketed")
        } else { try await editMenuKey("v") }
        try check("Cmd-V-exact-bracketed-UTF8", Data(driver.terminalMetrics.input.dropFirst(bracketedStart)) == Data("\u{1b}[200~".utf8) + Data(payload.utf8) + Data("\u{1b}[201~".utf8))
        if isCUA {
            try check("CUA-paste-retains-native-owner", tab.driver === driver && driver.terminal === terminal && driver.token == token && terminal.superview === parent)
            actions.append("CUA.real-plain-and-bracketed-paste-observed")
            return // This opt-in phase does not impersonate the later automated IME/menu steps.
        }
        terminal.feed(text: "\u{1b}[?2004l")
        let countBeforeOversize = driver.terminalMetrics.input.count
        try check("oversize-paste-rejected-before-queue", !terminal.pasteUserText(String(repeating: "x", count: TerminalSettings.maximumInputBytes + 1)) && driver.terminalMetrics.input.count == countBeforeOversize)
        let controlStart = driver.terminalMetrics.input.count
        terminal.keyDown(with: try require(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [.control], timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber, context: nil, characters: "\u{03}", charactersIgnoringModifiers: "c", isARepeat: false, keyCode: 8), "Ctrl-C"))
        try check("Ctrl-C-remains-terminal-interrupt", Data(driver.terminalMetrics.input.dropFirst(controlStart)) == Data([3]))
        try await editMenuKey("a"); try await editMenuKey("c")
        try check("Cmd-A-C-selects-native-buffer", pasteboard.string(forType: .string)?.contains("error stderr") == true)
        terminal.selectNone()
        let compositionStart = driver.terminalMetrics.input.count
        terminal.setMarkedText("中", selectedRange: NSRange(location: 1, length: 0), replacementRange: NSRange(location: NSNotFound, length: 0))
        try check("composition-preedit-does-not-send", terminal.hasMarkedText() && driver.terminalMetrics.input.count == compositionStart)
        terminal.insertText("中文🙂 e\u{301}", replacementRange: NSRange(location: NSNotFound, length: 0)); terminal.unmarkText()
        try check("composition-commit-exact-UTF8", Data(driver.terminalMetrics.input.dropFirst(compositionStart)) == Data("中文🙂 e\u{301}".utf8))
        let font = terminal.font, columns = terminal.columns
        try await terminalMenu(.increaseFont)
        try check("menu-font-actually-changes-renderer", terminal.font.pointSize == font.pointSize + 1 && terminal.font.fontName == font.fontName && terminal.columns < columns)
        try await terminalMenu(.decreaseFont); try await terminalMenu(.resetFont)
        try check("font-reset-uses-explicit-settings", terminal.font.pointSize == model.settings.fontSize)
        window.makeFirstResponder(terminal); try await menuKey("f")
        try await type("terminal.search", "error")
        try await click("terminal.search.next")
        try check("search-shows-real-match-summary", tab.searchMatchCount == 1 && tab.searchMatchIndex == 1)
        let search = try require(find("terminal.search", as: NSTextField.self), "desktop-search")
        window.makeFirstResponder(search)
        let textEditor = try require(search.currentEditor() as? NSTextView, "desktop-field-editor")
        textEditor.selectAll(nil); textEditor.insertText("editing-only", replacementRange: NSRange(location: NSNotFound, length: 0))
        let editingInput = driver.terminalMetrics.input.count
        try await editMenuKey("a"); try await editMenuKey("c")
        try check("input-field-editing-does-not-route-to-terminal", pasteboard.string(forType: .string) == "editing-only" && driver.terminalMetrics.input.count == editingInput)
        textEditor.doCommand(by: #selector(NSResponder.cancelOperation(_:)))
        try await wait("desktop-Escape-focus") { !tab.searchVisible && window.firstResponder === terminal }
        for index in 0..<100 { try driver.feedPressure(Data("LOCAL-OUTPUT-\(index)\r\n".utf8)) }
        terminal.scrollTo(row: 2)
        let viewport = terminal.terminalStateSnapshot().viewportRow
        try driver.feedPressure(Data("OUTPUT-WHILE-SCROLLED\r\n".utf8))
        try check("new-output-does-not-jump-scrolled-viewport", terminal.terminalStateSnapshot().viewportRow == viewport)
        try await terminalMenu(.scrollToBottom)
        try check("back-to-live-action-scrolls", terminal.terminalStateSnapshot().viewportRow > viewport)
        let live = terminal.terminalContentSnapshot(region: .viewport)?.rows.map(\.text), clearStart = driver.terminalMetrics.input.count
        try await terminalMenu(.clearHistory)
        try check("clear-history-local-only-keeps-current-screen", terminal.terminalContentSnapshot(region: .viewport)?.rows.map(\.text) == live && driver.terminalMetrics.input.count == clearStart && !terminal.search("LOCAL-OUTPUT-0"))
        let menu = try require(terminal.menu(for: try keyEvent("")), "native-context-menu")
        let pasteItem = try require(menu.items.first { $0.representedObject as? String == TerminalDesktopAction.paste.rawValue }, "native-context-paste")
        pasteboard.clearContents(); pasteboard.setString("context-paste", forType: .string)
        let contextStart = driver.terminalMetrics.input.count
        try check("right-click-action-has-current-target", pasteItem.isEnabled && pasteItem.target === terminal)
        if let action = pasteItem.action { NSApp.sendAction(action, to: pasteItem.target, from: pasteItem) }
        try check("right-click-same-paste-path", Data(driver.terminalMetrics.input.dropFirst(contextStart)) == Data("context-paste".utf8))
        for _ in 0..<3 { try await menuAction("showVault"); model.showWorkspace(.session(tab.id)); try await pause() }
        try check("desktop-owner-view-token-parent-retained", tab.driver === driver && terminal.superview === parent && driver.token == token)
        try await menuAction("disconnectSession")
        let disconnectedInput = driver.terminalMetrics.input.count
        terminal.insertText("blocked", replacementRange: NSRange(location: NSNotFound, length: 0))
        try check("disconnected-input-blocked-history-retained", !terminal.inputEnabled && driver.terminalMetrics.input.count == disconnectedInput && terminal.text.contains("OUTPUT-WHILE-SCROLLED"))
        try await menuAction("reconnectSession")
        try await wait("desktop-manual-reconnect") { driver.token?.generation == (token?.generation ?? 0) + 1 }
        try check("manual-reconnect-keeps-native-renderer", tab.driver === driver && driver.terminal === terminal && terminal.superview === parent)
        pasteboard.clearContents()
    }

    private struct CUAReady: Encodable {
        let pid: Int32
        let windowNumber: Int
        let expectedStep: String
    }
    private func writeCUAReady(window: NSWindow, step: String) throws {
        let ready = CUAReady(pid: ProcessInfo.processInfo.processIdentifier, windowNumber: window.windowNumber, expectedStep: step)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(ready).write(to: options.directory.appendingPathComponent("Ready.json"), options: .atomic)
    }
    /// Manual inspection only: no menu actions, seeded hosts, input or connections.
    /// ProbeSessionBuilder/LocalFilesProbeConnector remain explicit network substitutes.
    private func desktopCUAHold() async throws {
        let directory = open(options.directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else { throw Failure.check("desktop-cua-owned-directory") }
        defer { Darwin.close(directory) }
        guard try !desktopCUAFinishExists(in: directory) else { throw Failure.check("desktop-cua-stale-finish-signal") }
        let window = try require(delegate.mainWindow, "desktop-cua-window")
        try check("desktop-cua-ready", window.isVisible)
        try writeCUAReady(window: window, step: "inspect-desktop")
        let deadline = ContinuousClock.now.advanced(by: .seconds(600))
        while true {
            try Task.checkCancellation()
            guard delegate.mainWindow === window, window.isVisible, !model.lifecycle.terminating else {
                throw Failure.check("desktop-cua-ended-before-finish")
            }
            guard ContinuousClock.now < deadline else { throw Failure.timeout("desktop-cua-incomplete-no-finish") }
            if try desktopCUAFinishExists(in: directory) { break }
            try await Task.sleep(for: .milliseconds(100))
        }
        try await cleanupDesktopCUAResources()
        try writeCUAReady(window: window, step: "finished-desktop-cua")
        try check("desktop-cua-finish-signal", true)
    }
    private func desktopCUAFinishExists(in directory: Int32) throws -> Bool {
        var value = stat()
        guard fstatat(directory, ".desktop-cua-finish", &value, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT { return false }
            throw Failure.check("desktop-cua-finish-signal-unreadable")
        }
        // Presence alone ends the hold. Never read bytes or follow a symlink.
        guard value.st_mode & S_IFMT == S_IFREG, value.st_uid == getuid(), value.st_nlink == 1, value.st_size == 0 else {
            throw Failure.check("desktop-cua-finish-signal-invalid")
        }
        return true
    }
    private func cleanupDesktopCUAResources() async throws {
        if desktopCUACleanupTask == nil {
            model.lifecycle.beginTermination()
            model.windowClosed()
            desktopCUACleanupTask = Task { @MainActor [self] in
                defer { desktopCUACleanupFinished = true }
                guard await model.lifecycle.closeConnections(cancelTransfers: true, retainAdmissionFreeze: true) else {
                    throw Failure.check("desktop-cua-cleanup-incomplete")
                }
                try await model.security.close()
                try await model.repository.close()
            }
        }
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while !desktopCUACleanupFinished {
            guard ContinuousClock.now < deadline else { throw Failure.timeout("desktop-cua-cleanup-incomplete") }
            try await Task.sleep(for: .milliseconds(25))
        }
        guard let cleanup = desktopCUACleanupTask else { throw Failure.check("desktop-cua-cleanup-not-started") }
        try await cleanup.value
    }
    private func waitForCUAPaste(driver: ProbeSessionDriver, window: NSWindow, inputStart: Int, expected: Data, step: String) async throws {
        guard expected.count <= TerminalSettings.maximumInputBytes, let deadline = cuaDeadline else { throw Failure.check("CUA-invalid-paste-bounds") }
        try writeCUAReady(window: window, step: step)
        while true {
            try Task.checkCancellation()
            guard window.isVisible, model.sessions.tabs.contains(where: { $0.driver === driver }), driver.state != .closed else { throw Failure.check("CUA-window-or-session-closed") }
            let bytes = Data(driver.terminalMetrics.input.dropFirst(inputStart))
            guard bytes.count <= expected.count, expected.starts(with: bytes) else { throw Failure.check("CUA-input-not-exact-payload") }
            if bytes == expected {
                try check("CUA-actual-input-" + step, window.isKeyWindow && window.firstResponder === driver.terminal)
                try writeCUAReady(window: window, step: "completed-" + step)
                actions.append("CUA.received-" + step)
                return
            }
            guard ContinuousClock.now < deadline else { throw Failure.timeout("CUA-real-paste") }
            // Yield to the actual AppKit event loop. No synthetic menu/key action
            // or direct driver input can satisfy this opt-in handshake.
            try await Task.sleep(for: .milliseconds(25))
        }
    }
    private func cleanupCUAResources() async {
        if let cuaWindow { try? writeCUAReady(window: cuaWindow, step: "finished-or-cancelled") }
        if cuaOwnsPasteboard { NSPasteboard.general.clearContents(); cuaOwnsPasteboard = false }
        await model.sessions.closeAll()
        await model.files.closeForWindow()
        try? await model.security.close()
        try? await model.repository.close()
        if let cuaWindow { cuaWindow.orderOut(nil) }
        cuaDriver = nil; cuaWindow = nil
    }

    /// Fixture data is entered only through the presented editor, then independently
    /// read from the repository. No AppModel/editor draft mutation can satisfy this.
    private func createEditorFixture(name: String, waitLabel: String) async throws -> HostConfiguration {
        try check("fixture-fresh-isolated-store", try await model.repository.securityMetadata().hosts.isEmpty)
        try await menuAction("newHost")
        try await type("host.name", name)
        try await type("host.address", "never-connected.invalid")
        try await type("host.username", "fixture")
        let editor = try require(interactiveWindow(), "fixture-editor-owner")
        try check("fixture-not-written-before-save", try await model.repository.securityMetadata().hosts.isEmpty)
        try await pressVisibleButton("保存", owner: editor)
        try await wait(waitLabel) { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        let stored = try await model.repository.securityMetadata().hosts
        try check("fixture-real-editor-persisted", stored.count == 1 && stored[0].name == name &&
            stored[0].address == "never-connected.invalid" && stored[0].username == "fixture" &&
            stored[0].credentialRef == nil && !stored[0].savePasswordAuthorized)
        return try require(stored.first, "fixture-persisted-host")
    }
    private func nativeDismissExercise() async throws {
        let fixtureHost = try await createEditorFixture(name: "Dismiss logic fixture", waitLabel: "dismiss-fixture-host")
        try await selectFirstHost(); try await doubleClickFirstHost()
        try await wait("dismiss-logic-driver") { self.model.sessions.selectedTab?.driver != nil }
        let tab = try require(model.sessions.selectedTab, "dismiss-tab")
        let driver = try require(tab.driver as? ProbeSessionDriver, "dismiss-driver")
        let parent = try require(delegate.mainWindow, "dismiss-parent")
        try await actualEditorDismissExercise(host: fixtureHost, tab: tab, driver: driver, parent: parent)
        let fixture = DismissSmokeState()
        let anchor = NSHostingView(rootView: DismissSmokeAnchor(state: fixture))
        anchor.frame = NSRect(x: 0, y: 0, width: 1, height: 1)
        parent.contentView?.addSubview(anchor)
        defer { anchor.removeFromSuperview() }
        fixture.presentation = DismissSmokePresentation()
        try await wait("dismiss-hook-sheet") { parent.attachedSheet is NativeOwnedSheetWindow }
        try await type("dismiss.fixture.draft", "unsaved fixture draft")
        let owned = try require(parent.attachedSheet as? NativeOwnedSheetWindow, "dismiss-owned-sheet")
        try await menuKey("w")
        try check("native-sheet-Cmd-W-hook-denies-and-keeps-draft", fixture.attempts == 1 && fixture.draft == "unsaved fixture draft" && fixture.presentation != nil && parent.attachedSheet === owned)
        owned.cancelOperation(nil)
        try await pause()
        try check("native-sheet-Escape-hook-denies-and-keeps-draft", fixture.attempts == 2 && fixture.draft == "unsaved fixture draft" && parent.attachedSheet === owned)
        fixture.allowsDismiss = true
        try await menuKey("w")
        try await wait("dismiss-hook-accepts") { fixture.presentation == nil && parent.attachedSheet == nil }
        try check("native-sheet-accept-closes-only-owned-editor", fixture.attempts == 3 && model.sessions.selectedTab === tab && driver.state != .closed)
        driver.showAuthentication()
        try await click("terminal.authenticate")
        try await wait("dismiss-default-auth") { self.find("authentication.answer", as: NSSecureTextField.self) != nil }
        try await type("authentication.answer", "public fixture answer")
        try await menuKey("w")
        try await wait("dismiss-default-auth-closed") { parent.attachedSheet == nil }
        try check("default-auth-Cmd-W-keeps-tab-without-answer", model.sessions.selectedTab === tab && driver.responseCount == 0)
        try await click("terminal.authenticate")
        try await wait("dismiss-fresh-auth") { self.find("authentication.answer", as: NSSecureTextField.self) != nil }
        try check("default-auth-dismiss-never-revives-answer", find("authentication.answer", as: NSSecureTextField.self)?.stringValue.isEmpty == true)
        try await menuKey("w")
        try await wait("dismiss-fresh-auth-closed") { parent.attachedSheet == nil }
        let unknown = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 200, height: 100), styleMask: [.titled], backing: .buffered, defer: false)
        unknown.isReleasedWhenClosed = false
        parent.beginSheet(unknown, completionHandler: nil)
        try await pause()
        try await menuKey("w")
        try check("unknown-sheet-Cmd-W-is-not-ended", parent.attachedSheet === unknown && unknown.sheetParent === parent)
        parent.endSheet(unknown); unknown.orderOut(nil) // Exact synthetic fixture cleanup, not product routing.
        try await wait("unknown-fixture-cleanup") { parent.attachedSheet == nil }
        let alert = NSAlert(); alert.messageText = "Synthetic app-owned alert"; alert.addButton(withTitle: "关闭")
        NativeSheetCloseRouting.register(alert)
        parent.beginSheet(alert.window, completionHandler: nil)
        try await pause()
        try await menuKey("w")
        try await wait("registered-alert-dismissed") { parent.attachedSheet == nil }
        try check("registered-owned-alert-Cmd-W-cancels", alert.window.sheetParent == nil && model.sessions.selectedTab === tab)
    }

    private func actualEditorDismissExercise(host: HostConfiguration, tab: SessionTab, driver: ProbeSessionDriver, parent: NSWindow) async throws {
        let token = driver.token
        let storedBefore = try await model.repository.securityMetadata().hosts
        func sessionUnchanged() -> Bool {
            delegate.mainWindow === parent && parent.isVisible && model.sessions.tabs.contains { $0 === tab } &&
                model.sessions.selectedTab === tab && tab.driver === driver && driver.token == token && driver.state != .closed
        }
        func confirmation(for editor: NSWindow) -> NSWindow? {
            guard let current = interactiveWindow(), current !== editor, editor.attachedSheet === current,
                  current.sheetParent === editor, current is NativeOwnedSheetWindow else { return nil }
            return current
        }
        func fieldEquals(_ id: String, _ expected: String, in owner: NSWindow) -> Bool {
            let matches = controlMatches(id, in: owner)
            guard matches.count == 1 else { return false }
            if let field = matches[0].object as? NSTextField { return field.stringValue == expected }
            return (matches[0].element?.accessibilityValue() as? String) == expected
        }

        // Reopen the saved record using the native row context-menu target/action.
        try await menuAction("showVault")
        try await selectFirstHost(); try await hostContextCommand("编辑…")
        try await wait("actual-editor-reopened") { parent.attachedSheet is NativeOwnedSheetWindow }
        let editor = try require(parent.attachedSheet as? NativeOwnedSheetWindow, "actual-editor-owner")
        writeControlDiagnostics(stage: "actual-editor-reopened", window: editor)
        try check("actual-editor-loads-persisted-record", fieldEquals("host.name", host.name, in: editor))
        try await type("host.name", "Draft retained after Cancel")
        try check("actual-editor-dirty-not-yet-written", try await model.repository.securityMetadata().hosts == storedBefore)
        try await menuKey("w")
        try await wait("actual-editor-Cmd-W-confirmation") { confirmation(for: editor) != nil }
        let firstPrompt = try require(confirmation(for: editor), "actual-editor-close-confirmation")
        writeControlDiagnostics(stage: "dirty-close-confirmation", window: firstPrompt)
        try check("actual-editor-Cmd-W-only-opens-owned-confirmation", parent.attachedSheet === editor && sessionUnchanged())
        try await pressVisibleButton("取消", owner: firstPrompt)
        try await wait("actual-editor-cancel-keeps-draft") { self.interactiveWindow() === editor && editor.attachedSheet == nil }
        try check("actual-editor-Cancel-preserves-draft-and-owner", fieldEquals("host.name", "Draft retained after Cancel", in: editor) && sessionUnchanged())
        try check("actual-editor-Cancel-does-not-write", try await model.repository.securityMetadata().hosts == storedBefore)

        // Escape reaches the current editor, then closes only its nested confirmation.
        editor.cancelOperation(nil); try await pause()
        try await wait("actual-editor-Escape-confirmation") { confirmation(for: editor) != nil }
        let escapePrompt = try require(confirmation(for: editor) as? NativeOwnedSheetWindow, "actual-editor-Escape-owner")
        escapePrompt.cancelOperation(nil); try await pause()
        try await wait("actual-editor-Escape-cancels-only-confirmation") { self.interactiveWindow() === editor && editor.attachedSheet == nil }
        try check("actual-editor-Escape-preserves-draft-and-session", fieldEquals("host.name", "Draft retained after Cancel", in: editor) && sessionUnchanged())
        try check("actual-editor-Escape-does-not-write", try await model.repository.securityMetadata().hosts == storedBefore)

        editor.cancelOperation(nil); try await pause()
        try await wait("actual-editor-discard-confirmation") { confirmation(for: editor) != nil }
        try await pressVisibleButton("放弃更改", owner: try require(confirmation(for: editor), "actual-editor-discard-owner"))
        try await wait("actual-editor-discard-closed") { parent.attachedSheet == nil }
        try check("actual-editor-Discard-does-not-write", try await model.repository.securityMetadata().hosts == storedBefore)
        try check("actual-editor-Discard-preserves-session", sessionUnchanged())

        try await selectFirstHost(); try await hostContextCommand("编辑…")
        try await wait("actual-editor-reopened-after-discard") { parent.attachedSheet is NativeOwnedSheetWindow }
        let savedEditor = try require(parent.attachedSheet as? NativeOwnedSheetWindow, "actual-editor-save-owner")
        try check("actual-editor-discarded-draft-not-revived", fieldEquals("host.name", host.name, in: savedEditor))
        try await type("host.name", "Persisted by dirty close Save")
        try await menuKey("w")
        try await wait("actual-editor-save-confirmation") { confirmation(for: savedEditor) != nil }
        try await pressVisibleButton("保存", owner: try require(confirmation(for: savedEditor), "actual-editor-save-confirmation-owner"))
        try await wait("actual-editor-save-closed") { parent.attachedSheet == nil && self.model.hosts.first?.name == "Persisted by dirty close Save" }
        let storedAfter = try await model.repository.securityMetadata().hosts
        var expected = host; expected.name = "Persisted by dirty close Save"
        try check("actual-editor-dirty-Save-persists-exact-record", storedAfter == [expected])
        try check("actual-editor-dirty-Save-preserves-session", sessionUnchanged())

        // A clean editor closes immediately by Escape, without affecting the retained tab.
        try await selectFirstHost(); try await hostContextCommand("编辑…")
        try await wait("actual-editor-reopened-after-save") { parent.attachedSheet is NativeOwnedSheetWindow }
        let cleanEditor = try require(parent.attachedSheet as? NativeOwnedSheetWindow, "actual-editor-clean-owner")
        try check("actual-editor-reopen-reads-saved-value", fieldEquals("host.name", expected.name, in: cleanEditor))
        cleanEditor.cancelOperation(nil); try await pause()
        try await wait("actual-editor-clean-Escape-closes") { parent.attachedSheet == nil }
        try check("actual-editor-clean-Escape-keeps-session", sessionUnchanged())
        try await selectSession(tab.id)
    }

    private func selectSession(_ id: UUID) async throws {
        // Top-level tabs are SwiftUI buttons, not NativeButton NSButton controls.
        // Traverse the actual AppKit navigation menu until that visible tab wins.
        guard model.sessions.tabs.contains(where: { $0.id == id }) else { throw Failure.missing("session-tab") }
        for _ in 0..<(model.sessions.tabs.count + 2) {
            if model.workspacePage == .session(id) { actions.append("menu.select-session"); return }
            try await menuAction("nextWorkspace")
        }
        throw Failure.timeout("menu-select-session")
    }
    private func terminalMenu(_ action: TerminalDesktopAction) async throws {
        func visit(_ menu: NSMenu) -> NSMenuItem? {
            for item in menu.items {
                if item.identifier?.rawValue == "terminal." + action.rawValue { return item }
                if let submenu = item.submenu, let found = visit(submenu) { return found }
            }
            return nil
        }
        let item = try require(NSApp.mainMenu.flatMap(visit), "terminal-menu-" + action.rawValue)
        guard delegate.validateMenuItem(item), let selector = item.action, NSApp.sendAction(selector, to: item.target, from: item) else { throw Failure.check("terminal-menu-" + action.rawValue) }
        actions.append("terminal-menu." + action.rawValue); try await pause()
    }
    private func editMenuKey(_ key: String) async throws {
        guard let window = delegate.mainWindow, let responder = window.firstResponder else { throw Failure.missing("edit-first-responder") }
        let selector: Selector
        switch key { case "a": selector = #selector(NSResponder.selectAll(_:)); case "c": selector = #selector(NativeTerminalView.copy(_:)); default: selector = #selector(NativeTerminalView.paste(_:)) }
        // Force the real responder-chain target in an in-process NSMenu test;
        // no hidden control or direct tab-model mutation stands in for editing.
        guard responder.responds(to: selector) else { throw Failure.missing("edit-responder") }
        try await menuKey(key)
    }

    /// U1 routing/focus only: real AppKit menus/fields, synthetic terminal driver,
    /// local file fixture. No SSH, Keychain operation or pixel-parity claim.
    private func workspaceExercise() async throws {
        try await menuAction("newHost")
        try await type("host.name", "Workspace fixture")
        try await type("host.address", "never-connected.invalid")
        try await type("host.username", "fixture")
        try await click("host.save")
        try await wait("workspace-host") { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        try await selectFirstHost()
        try await doubleClickFirstHost()
        try await wait("workspace-session-A") { self.model.sessions.selectedTab?.driver != nil }
        let a = try require(model.sessions.selectedTab, "tab-A")
        let driver = try require(a.driver as? ProbeSessionDriver, "logic-driver")
        let terminal = driver.terminal, token = driver.token
        try await wait("terminal-mounted") { terminal.superview != nil }
        let terminalParent = terminal.superview
        let manager = model.files.manager, files = model.files
        delegate.mainWindow?.makeFirstResponder(terminal)
        try await menuKey("f")
        try await wait("search-focused-A") { self.find("terminal.search", as: NSTextField.self)?.currentEditor() === self.delegate.mainWindow?.firstResponder }
        try await type("terminal.search", "logic substitute")
        try await click("terminal.search.next")
        try check("cmd-F-has-search-consumer", a.searchVisible && a.searchFound == true)
        try await click("terminal.search.previous")
        try check("search-previous-result", a.searchFound == true)
        let searchA = try require(find("terminal.search", as: NSTextField.self), "search-A")
        try check("search-can-be-first-responder", delegate.mainWindow?.makeFirstResponder(searchA) == true)
        try check("search-has-real-field-editor", searchA.currentEditor() != nil && delegate.mainWindow?.firstResponder === searchA.currentEditor())
        let command = model.workspaceCommand
        try check("find-disabled-in-text-editor", !delegate.validateMenuItem(try workspaceMenu("findInWorkspace")))
        _ = NSApp.mainMenu?.performKeyEquivalent(with: try keyEvent("f"))
        try check("text-editor-find-not-stolen", model.workspaceCommand == command)
        let inputBeforeEdit = driver.terminalMetrics.input.count
        let editor = try require(searchA.currentEditor() as? NSTextView, "search-editor")
        editor.selectAll(nil)
        editor.insertText("logic substitute", replacementRange: NSRange(location: NSNotFound, length: 0))
        try check("native-text-edit-not-terminal-input", driver.terminalMetrics.input.count == inputBeforeEdit)
        model.requestSession(hostID: a.hostID, mode: .newSession)
        try await wait("workspace-session-B") { self.model.sessions.tabs.count == 2 && self.model.sessions.selectedTab?.driver != nil }
        let b = try require(model.sessions.selectedTab, "tab-B")
        try check("hidden-search-loses-field-editor", searchA.currentEditor() == nil && searchA.isHiddenOrHasHiddenAncestor)
        try check("search-B-independent", b.searchText.isEmpty && !b.searchVisible && b.searchFound == nil)
        delegate.mainWindow?.makeFirstResponder(b.driver?.terminal)
        try await menuKey("f")
        try await type("terminal.search", "B-no-match")
        try await click("terminal.search.next")
        try check("search-B-result-independent", b.searchFound == false)
        try await menuAction("showVault")
        delegate.mainWindow?.makeFirstResponder(nil)
        try await menuKey("f")
        try await wait("host-search-focused") { self.find("vault.hosts.search", as: NSTextField.self)?.currentEditor() === self.delegate.mainWindow?.firstResponder }
        let hostSearch = try require(find("vault.hosts.search", as: NSTextField.self), "hosts.search")
        try await menuAction("showSFTP")
        try check("hidden-vault-native-field-editor-resigned", hostSearch.currentEditor() == nil && hostSearch.isHiddenOrHasHiddenAncestor)
        try check("SFTP-find-explicitly-disabled", !delegate.validateMenuItem(try workspaceMenu("findInWorkspace")))
        let sftpPage = try require(workspacePage("workspace.page.sftp"), "page-sftp")
        let vaultPage = try require(workspacePage("workspace.page.vault"), "page-vault")
        try check("hidden-page-not-hittable", vaultPage.isHidden && vaultPage.hitTest(NSPoint(x: 40, y: 40)) == nil && !sftpPage.isHidden)
        try await wait("files-local-ready") { self.model.files.localBrowser.path != nil && !self.model.files.localBrowser.loading }
        let localTable = try require(find("files.local.entries", as: NSTableView.self), "local-files-table")
        try check("current-SFTP-native-table-editable", delegate.mainWindow?.makeFirstResponder(localTable) == true)
        try await type("files.initial.secret", "public metadata fixture")
        let secretField = try require(find("files.initial.secret", as: NSSecureTextField.self), "files.initial.secret")
        let secretBeforeMetadata = secretField.stringValue
        var metadataOnly = try require(model.files.selectedHost, "sftp-selected-host")
        metadataOnly.name = "Workspace renamed"; metadataOnly.isFavorite.toggle(); metadataOnly.lastConnectedAt = Date()
        model.files.show(host: metadataOnly)
        try await pause()
        try check("SFTP-metadata-keeps-native-browser-owner", find("files.local.entries", as: NSTableView.self) === localTable)
        try check("SFTP-metadata-keeps-unsent-input", secretField.stringValue == secretBeforeMetadata)
        model.returnToVaultFromFiles()
        try check("SFTP-return-visible-without-owner-reset", model.workspacePage == .vault && model.files === files && model.files.manager === manager)
        for visible in [false, true] {
            model.files.tasksVisible = visible
            try await menuAction("showSFTP")
            try await pressVisibleButton("传输 0")
            try check("queue-entry-always-expands-" + String(visible), model.workspacePage == .sftp && model.files.tasksVisible)
            try await menuAction("showVault")
        }
        model.showWorkspace(.session(a.id)); try await pause()
        try check("A-search-and-result-retained", a.searchVisible && a.searchText == "logic substitute" && a.searchFound == true)
        try check("native-terminal-owner-view-token-not-rebuilt", a.driver === driver && driver.terminal === terminal && driver.token == token && terminal.superview === terminalParent && model.files.manager === manager)
        try await click("terminal.search.close")
        try await wait("terminal-focus-after-close") { self.delegate.mainWindow?.firstResponder === terminal }
        try await menuKey("f")
        try await wait("search-editor-after-reopen") { self.find("terminal.search", as: NSTextField.self)?.currentEditor() != nil }
        let reopenedSearch = try require(find("terminal.search", as: NSTextField.self), "reopened-search")
        let reopenedEditor = try require(reopenedSearch.currentEditor() as? NSTextView, "reopened-editor")
        reopenedEditor.doCommand(by: #selector(NSResponder.cancelOperation(_:)))
        try await wait("terminal-focus-after-Escape") { !a.searchVisible && self.delegate.mainWindow?.firstResponder === terminal }
        driver.showAuthentication()
        try await click("terminal.authenticate")
        try await wait("auth-sheet") { self.find("authentication.answer", as: NSSecureTextField.self) != nil }
        try await type("authentication.answer", UUID().uuidString)
        for action in ["disconnectSession", "reconnectSession", "connectionInfo", "nextWorkspace", "previousWorkspace", "newConnection"] {
            let item = try workspaceMenu(action)
            try check("sheet-disables-" + action, !delegate.validateMenuItem(item))
            if let selector = item.action { _ = NSApp.sendAction(selector, to: item.target, from: item) }
        }
        try check("sheet-actions-cannot-touch-workspace", model.workspacePage == .session(a.id) && driver.token == token && driver.responseCount == 0 && a.authentication != nil)
        try await menuKey("w")
        try await wait("cmd-W-dismisses-sheet") { self.delegate.mainWindow?.attachedSheet == nil }
        try check("cmd-W-sheet-preserves-tab", model.sessions.tabs.count == 2 && driver.responseCount == 0)
        try await click("terminal.authenticate")
        try await wait("fresh-answer-editor") { self.find("authentication.answer", as: NSSecureTextField.self) != nil }
        try check("old-answer-never-revived", find("authentication.answer", as: NSSecureTextField.self)?.stringValue.isEmpty == true)
        model.showWorkspace(.session(b.id))
        try await wait("tab-change-dismisses-auth") { self.delegate.mainWindow?.attachedSheet == nil }
        model.showWorkspace(.session(a.id)); try await pause()
        try check("tab-change-does-not-reopen-or-submit-auth", delegate.mainWindow?.attachedSheet == nil && a.dialog == nil && driver.responseCount == 0)
        try await menuKey("t")
        try await wait("cmd-T-chooser") { self.delegate.mainWindow?.attachedSheet != nil }
        try await menuKey("w")
        try await wait("chooser-dismissed") { self.delegate.mainWindow?.attachedSheet == nil }
        try await menuKey("w")
        try await wait("cmd-W-closes-current-SSH") { self.model.sessions.tabs.count == 1 && self.model.workspacePage == .session(b.id) }
        try await menuKey("w")
        try await wait("last-SSH-returns-Vault") { self.model.sessions.tabs.isEmpty && self.model.workspacePage == .vault }
        try check("last-tab-clears-workspace-visibility", !model.sessions.workspaceVisible && model.files.manager === manager)
        try capture("workspace-r5.png")
        try await menuAction("showSFTP")
        try await menuKey("w")
        try await wait("fixed-page-Cmd-W-closes-window") { self.delegate.mainWindow == nil }
        try check("fixed-page-close-is-window-context", model.workspacePage == .vault && model.sessions.tabs.isEmpty)
    }

    private func require<T>(_ value: T?, _ label: String) throws -> T {
        guard let value else { throw Failure.missing(label) }; return value
    }
    private func workspacePage(_ id: String) -> NativeWorkspacePageView? {
        func visit(_ view: NSView) -> NativeWorkspacePageView? {
            if view.identifier?.rawValue == id { return view as? NativeWorkspacePageView }
            return view.subviews.compactMap(visit).first
        }
        return delegate.mainWindow?.contentView.flatMap(visit)
    }
    private func workspaceMenu(_ action: String) throws -> NSMenuItem {
        func visit(_ menu: NSMenu) -> NSMenuItem? {
            for item in menu.items {
                if item.action == Selector(action) { return item }
                if let submenu = item.submenu, let found = visit(submenu) { return found }
            }
            return nil
        }
        return try require(NSApp.mainMenu.flatMap(visit), "menu-" + action)
    }
    private func menuAction(_ action: String) async throws {
        let item = try workspaceMenu(action)
        guard delegate.validateMenuItem(item), let selector = item.action,
              NSApp.sendAction(selector, to: item.target, from: item) else { throw Failure.check("menu-" + action) }
        actions.append("menu." + action); try await pause()
    }
    private func keyEvent(_ key: String) throws -> NSEvent {
        try require(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [.command], timestamp: ProcessInfo.processInfo.systemUptime,
            windowNumber: delegate.mainWindow?.windowNumber ?? 0, context: nil, characters: key, charactersIgnoringModifiers: key,
            isARepeat: false, keyCode: 0), "menu-key-event")
    }
    private func menuKey(_ key: String) async throws {
        guard NSApp.mainMenu?.performKeyEquivalent(with: try keyEvent(key)) == true else { throw Failure.check("menu-key-" + key) }
        actions.append("menu-key." + key); try await pause()
    }

    private func exercise() async throws {
        try check("fresh-store-empty", model.hosts.isEmpty && model.folders.isEmpty)
        try await click("folder.add")
        try await type("folder.name", "GUI 文件夹")
        try await click("folder.save")
        try await wait("folder-created") { self.model.folders.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        let folder = model.folders[0]
        try await click("folder." + folder.id.uuidString)
        try await menuAction("newHost")
        try await click("host.save")
        try await wait("invalid-host-visible") { self.model.issue?.code == "validation.invalid" }
        try check("invalid-host-no-write", model.hosts.isEmpty)
        try await click("issue.dismiss")
        try await type("host.name", "GUI 中文主机")
        try await type("host.address", "gui-smoke.invalid")
        try await type("host.username", "fixture")
        try await type("host.port", "2222")
        try await type("host.interval", "45")
        try await popup("host.authentication", value: "passwordWithMFA")
        try capture("host-editor.png")
        try await click("host.save")
        try await wait("host-created") { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        try check("host-fields-persisted", model.hosts[0].folderID == folder.id && model.hosts[0].port == 2222 && model.hosts[0].authentication == .passwordWithMFA && model.hosts[0].keepaliveInterval == 45)
        try await selectFirstHost()
        try await click("host.edit")
        try await type("host.name", "GUI 编辑主机")
        try await click("host.save")
        try await wait("host-edited") { self.model.hosts.first?.name == "GUI 编辑主机" && self.delegate.mainWindow?.attachedSheet == nil }
        try await click("host.favorite")
        try await wait("favorite-saved") { self.model.hosts.first?.isFavorite == true }
        try await click("sidebar.favorites")
        try await wait("favorites-filter") { !self.model.isLoading && self.model.hosts.count == 1 }
        try await type("hosts.search", "NOT-A-MATCH")
        try await wait("search-empty") { !self.model.isLoading && self.model.hosts.isEmpty }
        try await type("hosts.search", "编辑")
        try await wait("search-match") { !self.model.isLoading && self.model.hosts.count == 1 }
        try await type("hosts.search", "")
        try await selectFirstHost()
        try await click("host.copy")
        try await wait("host-copied") { self.model.hosts.count == 2 }
        try check("copy-new-id-no-history", Set(model.hosts.map(\.id)).count == 2 && model.hosts.allSatisfy { $0.lastConnectedAt == nil })
        try await selectFirstHost()
        try await doubleClickFirstHost()
        try await wait("double-click-route") { self.model.connectionNotice != nil }
        if case .opened(let request, _) = model.connectionNotice { try check("reuse-route", request.mode == .reuse && request.hostID == model.hosts[0].id) }
        else { throw Failure.check("reuse-route") }
        try await menuAction("showVault")
        try await click("session.new")
        if case .opened(let request, _) = model.connectionNotice { try check("new-route", request.mode == .newSession) }
        else { throw Failure.check("new-route") }
        try check("route-never-marks-connected", model.hosts.allSatisfy { $0.lastConnectedAt == nil })
        try capture("logic-session-route.png")
        await model.sessions.closeAll()
        try await click("host.delete")
        try await click("delete.confirm")
        try await wait("host-deleted") { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        try await click("folder." + folder.id.uuidString)
        try await click("folder.edit")
        try await type("folder.name", "GUI 重命名文件夹")
        try await click("folder.save")
        try await wait("folder-renamed") { self.model.folders.first?.name == "GUI 重命名文件夹" && self.delegate.mainWindow?.attachedSheet == nil }
        try await click("folder.copy")
        try await wait("folder-copied") { self.model.folders.count == 2 }
        try await click("folder.delete")
        try await click("delete.confirm")
        try await wait("folder-deleted") { self.model.folders.count == 1 && self.delegate.mainWindow?.attachedSheet == nil && !self.model.isWriting }
        try await click("sidebar.ungrouped")
        try await wait("ungrouped-preserved") { !self.model.isLoading && self.model.hosts.count == 1 && self.model.hosts[0].folderID == nil }
        checks.append(Check(name: "group-delete-preserves-host", passed: true))
        try await click("settings.open")
        try await type("settings.font", "Menlo-Regular")
        try await type("settings.size", "15")
        try await popup("settings.theme", value: "dark")
        try await popup("settings.preset", value: "Solarized")
        try await type("settings.history", "50001")
        try await click("settings.save")
        try await wait("history-limit-error") { self.model.issue?.code == "validation.invalid" }
        try check("history-limit-no-truncation", model.settings.historyLines == 10_000)
        try await click("issue.dismiss")
        try await type("settings.history", "50000")
        try await type("settings.interval", "60")
        try await type("settings.count", "4")
        try await click("settings.save")
        try await wait("settings-persisted") { self.model.settings.historyLines == 50_000 && self.delegate.mainWindow?.attachedSheet == nil }
        try check("settings-fields", model.settings.fontName == "Menlo-Regular" && model.settings.fontSize == 15 && model.settings.theme == .dark && model.settings.backgroundColor == "#002B36" && model.settings.keepaliveInterval == 60)
        delegate.mainWindow?.performClose(nil)
        try await wait("window-closed") { self.delegate.mainWindow == nil }
        try check("close-clears-route-selection", model.connectionNotice == nil && model.selectedHostID == nil && model.search.isEmpty && model.selection == .all)
        _ = delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false)
        try await wait("window-reopened") { self.delegate.mainWindow?.isVisible == true && !self.model.isLoading && self.model.hosts.count == 2 }
        try check("reopen-list-only", model.connectionNotice == nil && model.selectedHostID == nil)
        try capture("exercise-window.png")
    }

    private func verifyRelaunch() async throws {
        try check("relaunch-metadata", model.hosts.count == 2 && model.folders.count == 1 && model.hosts.allSatisfy { $0.lastConnectedAt == nil })
        try check("relaunch-settings", model.settings.historyLines == 50_000 && model.settings.fontName == "Menlo-Regular" && model.settings.theme == .dark && model.settings.keepaliveCountMax == 4)
        try check("relaunch-no-restore", model.selectedHostID == nil && model.connectionNotice == nil && model.selection == .all)
        try await menuAction("newHost")
        try await wait("default-keepalive") { self.find("host.interval", as: NSTextField.self)?.stringValue == "60" }
        for kind in ["privateKey", "privateKeyWithMFA"] {
            try await popup("host.authentication", value: kind)
            guard let key = find("host.key", as: NSPopUpButton.self) else { throw Failure.missing("host.key") }
            try check("empty-key-picker-" + kind, key.numberOfItems == 1 && key.selectedItem?.representedObject as? String == "")
        }
        try await popup("host.authentication", value: "password")
        try await click("editor.cancel")
        try await click("settings.open")
        try capture("settings-editor.png")
        try await popup("settings.preset", value: "Classic")
        try await type("settings.foreground", "#AABBCC")
        try await click("settings.save")
        try await wait("custom-color") { self.model.settings.foregroundColor == "#AABBCC" && self.delegate.mainWindow?.attachedSheet == nil }
        try check("custom-color-persisted", model.settings.backgroundColor == "#000000" && model.settings.cursorColor == "#00FF00")
        try capture("reopen-window.png")
    }

    private func sessionExercise() async throws {
        try await menuAction("newHost")
        try await type("host.name", "Session logic fixture")
        try await type("host.address", "never-scanned.invalid")
        try await type("host.username", "fixture")
        try await click("host.save")
        try await wait("session-fixture-host") { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        try await selectFirstHost()
        try await doubleClickFirstHost()
        try await wait("session-tab-ready") { self.model.sessions.tabs.first?.driver != nil }
        delegate.mainWindow?.setContentSize(NSSize(width: 1120, height: 1000))
        try await pause()
        let first = model.sessions.tabs[0]
        guard let driver = first.driver as? ProbeSessionDriver else { throw Failure.check("logic-substitute-required") }
        let view = driver.terminal
        try await menuAction("showVault")
        try await doubleClickFirstHost()
        try check("double-click-reuses-valid-tab", model.sessions.tabs.count == 1 && model.sessions.selectedTabID == first.id)
        try await menuAction("showVault")
        try await click("session.new")
        try await wait("independent-session-tab") { self.model.sessions.tabs.count == 2 && self.model.sessions.tabs[1].driver != nil }
        try await selectSession(first.id)
        try check("terminal-instance-retained", first.driver?.terminal === view && !view.isHidden)
        delegate.mainWindow?.makeFirstResponder(view)
        try await menuKey("f")
        try await type("terminal.search", "logic substitute")
        try await click("terminal.search.next")
        try check("native-terminal-history-search", view.search("logic substitute"))
        driver.showTrust()
        try await click("terminal.trust")
        try await wait("trust-accept-visible") { self.find("trust.accept", as: NSButton.self) != nil }
        try check("trust-requires-explicit-verification", find("trust.accept", as: NSButton.self)?.isEnabled == false)
        try await click("trust.verified")
        try await click("trust.accept")
        try await wait("trust-modal-closed") { self.delegate.mainWindow?.attachedSheet == nil }
        try check("synthetic-trust-not-connected", first.state == .connectionPending)
        driver.showAuthentication()
        try await click("terminal.authenticate")
        try await wait("unknown-auth-field-visible") { self.find("authentication.answer", as: NSSecureTextField.self) != nil }
        try check("unknown-auth-secure-field", find("authentication.answer", as: NSSecureTextField.self) != nil)
        try await type("authentication.answer", UUID().uuidString)
        try await click("authentication.submit")
        try await wait("authentication-modal-closed") { self.delegate.mainWindow?.attachedSheet == nil }
        try check("manual-auth-only", driver.responseCount == 1 && first.state == .connectionPending)
        driver.showAuthentication(kind: .notification)
        try await click("terminal.authenticate")
        try check("notification-not-secret-input", find("authentication.answer", as: NSSecureTextField.self) == nil)
        try await click("authentication.acknowledge")
        try await wait("notification-modal-closed") { self.delegate.mainWindow?.attachedSheet == nil }
        driver.showAuthentication(kind: .confirmation)
        try await click("terminal.authenticate")
        try await click("authentication.decline")
        try await wait("confirmation-modal-closed") { self.delegate.mainWindow?.attachedSheet == nil }
        let generation = driver.token?.generation
        try await menuAction("disconnectSession")
        try await menuAction("reconnectSession")
        try await wait("manual-new-generation") { driver.token?.generation == (generation ?? 0) + 1 }
        try check("reconnect-retains-terminal", driver.terminal === view)
        try check("no-auth-event-no-history", try await model.repository.securityMetadata().hosts.allSatisfy { $0.lastConnectedAt == nil })
        driver.showAuthentication()
        try await click("terminal.authenticate")
        try await click("authentication.cancel")
        try await wait("cancel-invalidates-request") { self.delegate.mainWindow?.attachedSheet == nil && first.state == .disconnected(nil) }
        try await selectSession(first.id)
        try await menuKey("w")
        try await wait("tab-closed") { !self.model.sessions.tabs.contains { $0.id == first.id } }
        try check("tab-close-releases-driver", driver.state == .closed)
        if options.phase == "sessions-exit" {
            let active = model.sessions.tabs.filter(\.isReusable).count
            try check("exit-with-active-tab", active > 0)
            guard let remaining = model.sessions.tabs.first?.driver as? ProbeSessionDriver,
                  let window = delegate.mainWindow else { throw Failure.check("exit-logic-driver") }
            remaining.holdClose = true
            await withCheckedContinuation { (started: CheckedContinuation<Void, Never>) in
                remaining.closeDidStart = { started.resume() }
                // Exercise the actual window-close path before NSApp.terminate,
                // keeping its cleanup suspended until quit joins the same batch.
                window.performClose(nil)
            }
            remaining.closeDidStart = nil
            try check("window-close-cleanup-pending-before-quit", model.sessions.closingAll && !model.sessions.tabs.isEmpty)
            let repeatTimer = Timer(timeInterval: 0.12, repeats: false) { _ in
                MainActor.assumeIsolated {
                    let reply = self.delegate.applicationShouldTerminate(NSApp)
                    let reopenRefused = !self.delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false)
                    let noAdmission = self.model.hosts.first.map { self.model.sessions.open($0, mode: .newSession) == nil } ?? false
                    let report = ["secondQuitWaits": reply == .terminateLater, "activeCleanupStillPending": !self.model.sessions.tabs.isEmpty]
                    let admission = ["windowCloseOverlappedQuit": self.model.sessions.closingAll, "terminationPermanent": self.model.sessions.terminating,
                                     "reopenRefused": reopenRefused, "newSessionRefused": noAdmission]
                    if let data = try? JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]) {
                        try? data.write(to: self.options.directory.appendingPathComponent("termination-repeat.json"))
                    }
                    if let data = try? JSONSerialization.data(withJSONObject: admission, options: [.sortedKeys]) {
                        try? data.write(to: self.options.directory.appendingPathComponent("termination-admission.json"))
                    }
                    remaining.releaseClose()
                }
            }
            RunLoop.main.add(repeatTimer, forMode: .common)
            return // run() invokes real NSApp.terminate with this tab still active.
        }
        delegate.mainWindow?.performClose(nil)
        try await wait("sessions-window-closed") { self.delegate.mainWindow == nil }
        try check("window-awaits-all-tab-close", model.sessions.tabs.isEmpty)
        _ = delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false)
        try await wait("sessions-reopen-list-only") { self.delegate.mainWindow?.isVisible == true && !self.model.isLoading }
        try check("no-session-restore", model.sessions.tabs.isEmpty && model.connectionNotice == nil)
    }

    private func sessionPressureExercise() async throws {
        let started = ProcessInfo.processInfo.systemUptime
        let deadline = started + 55
        var samples: [[String: Any]] = []
        var heartbeatCount = 0, heartbeatMaximum = 0.0
        var lastHeartbeat = ProcessInfo.processInfo.systemUptime
        let heartbeat = Timer(timeInterval: 0.05, repeats: true) { _ in MainActor.assumeIsolated {
            let now = ProcessInfo.processInfo.systemUptime
            heartbeatMaximum = max(heartbeatMaximum, now - lastHeartbeat); lastHeartbeat = now; heartbeatCount += 1
        } }
        RunLoop.main.add(heartbeat, forMode: .common)
        defer { heartbeat.invalidate() }
        samples.append(try pressureSample(stage: "before-five-views"))
        try await click("host.add"); try await type("host.name", "P7 render logic fixture, not SSH")
        try await type("host.address", "never-connected.invalid"); try await type("host.username", "fixture")
        try await click("host.save")
        try await wait("pressure-host") { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        try await selectFirstHost()
        for _ in 0..<ProbeOutputLoad.viewCount { try await click("session.new") }
        try await wait("pressure-five-drivers") { self.model.sessions.tabs.count == 5 && self.model.sessions.tabs.allSatisfy { $0.driver is ProbeSessionDriver && $0.preparation == nil } }
        var ids: [UUID] = [], identities: [ObjectIdentifier] = [], weakViews: [PressureWeakTerminal] = [], metrics: [ProbeTerminalMetrics] = []
        for tab in model.sessions.tabs {
            guard let driver = tab.driver as? ProbeSessionDriver else { throw Failure.check("pressure-fixture-only") }
            ids.append(tab.id); identities.append(ObjectIdentifier(driver.terminal)); weakViews.append(PressureWeakTerminal(driver.terminal)); metrics.append(driver.terminalMetrics)
            driver.terminal.setHistoryLimit(ProbeOutputLoad.historyLines); driver.terminal.resize(cols: 80, rows: 24)
        }
        try check("pressure-five-real-views-distinct", Set(identities).count == 5)
        try check("pressure-no-authenticated-network-state", model.sessions.tabs.allSatisfy { $0.state == .connectionPending })
        samples.append(try pressureSample(stage: "five-views-before-output"))
        var producerFailure: String?
        let outputStart = ProcessInfo.processInfo.systemUptime
        let producer = Task { @MainActor in
            do {
                for batch in 0..<ProbeOutputLoad.batches {
                    try Task.checkCancellation()
                    guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.timeout("pressure-producer") }
                    for view in 0..<ProbeOutputLoad.viewCount {
                        guard let driver = self.model.sessions.tabs.first(where: { $0.id == ids[view] })?.driver as? ProbeSessionDriver else { throw Failure.missing("pressure-driver") }
                        try driver.feedPressure(ProbeOutputLoad.batch(view: view, index: batch))
                    }
                    // One batch is created/fed at a time; no unbounded producer queue or byte drops.
                    try await Task.sleep(for: .milliseconds(ProbeOutputLoad.intervalMilliseconds))
                }
            } catch { producerFailure = "producer.failed-or-deadline" }
        }
        defer { producer.cancel() }
        var interactions = 0
        while metrics[0].fedBatches < ProbeOutputLoad.batches && producerFailure == nil {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.timeout("pressure-interactions") }
            let index = interactions % ids.count
            try await click("tab.select." + ids[index].uuidString)
            delegate.mainWindow?.makeFirstResponder(model.sessions.selectedTab?.driver?.terminal)
            try await menuKey("f")
            try await type("terminal.search", "V\(index)-B")
            try await click("terminal.search.next")
            guard let driver = model.sessions.selectedTab?.driver as? ProbeSessionDriver else { throw Failure.missing("pressure-selected") }
            try check("pressure-same-instance-\(interactions)", ObjectIdentifier(driver.terminal) == identities[index])
            guard let window = delegate.mainWindow else { throw Failure.missing("pressure-window") }
            let size = interactions.isMultiple(of: 2) ? NSSize(width: 1260, height: 920) : NSSize(width: 1510, height: 1000)
            window.setContentSize(size); window.contentView?.layoutSubtreeIfNeeded(); actions.append("resize.pressure-window")
            if interactions % 5 == 0 {
                window.orderOut(nil)
                let batchBefore = metrics.map(\.fedBatches)
                try await Task.sleep(for: .milliseconds(120))
                window.makeKeyAndOrderFront(nil); actions.append("hideShow.pressure-window")
                try check("pressure-hidden-window-consumes-\(interactions)", zip(metrics, batchBefore).allSatisfy { $0.fedBatches > $1 })
            }
            samples.append(try pressureSample(stage: "output-\(interactions)")); interactions += 1
        }
        await producer.value
        try check("pressure-producer-finished", producerFailure == nil)
        let outputElapsed = ProcessInfo.processInfo.systemUptime - outputStart
        var viewReports: [[String: Any]] = []
        for view in 0..<ids.count {
            try await click("tab.select." + ids[view].uuidString)
            guard let driver = model.sessions.selectedTab?.driver as? ProbeSessionDriver else { throw Failure.missing("pressure-final-driver") }
            try check("pressure-final-instances-unchanged-\(view)", ObjectIdentifier(driver.terminal) == identities[view])
            try check("pressure-resize-events-observed-\(view)", metrics[view].resizeEvents > 1)
            let expected = (0..<ProbeOutputLoad.batches).reduce(UInt64(0)) { $0 + UInt64(ProbeOutputLoad.batch(view: view, index: $1).count) }
            let marker = ProbeOutputLoad.marker(view: view)
            try check("pressure-exact-byte-batch-count-\(view)", metrics[view].fedBytes == expected && metrics[view].fedBatches == ProbeOutputLoad.batches)
            try check("pressure-hidden-view-consumed-\(view)", metrics[view].hiddenBatches > 0)
            try check("pressure-final-marker-\(view)", driver.terminal.text.contains(marker))
            try await type("terminal.search", marker); try await click("terminal.search.next")
            try check("pressure-final-search-\(view)", driver.terminal.search(marker))
            let input = "P7-INPUT-\(view)-中文"
            NSPasteboard.general.clearContents(); NSPasteboard.general.setString(input, forType: .string)
            delegate.mainWindow?.makeFirstResponder(driver.terminal)
            try await editMenuKey("v")
            try check("pressure-real-paste-input-\(view)", metrics[view].input == Data(input.utf8))
            try check("pressure-scrollback-bounded-\(view)", driver.terminal.retainedRowCount <= ProbeOutputLoad.historyLines + driver.terminal.rows)
            viewReports.append(["view":view,"expectedBytes":expected,"fedBytes":metrics[view].fedBytes,"batches":metrics[view].fedBatches,"hiddenBatches":metrics[view].hiddenBatches,"markerFound":true,"searchFound":true,"inputBytes":metrics[view].input.count,"resizeEvents":metrics[view].resizeEvents,"columns":driver.terminal.columns,"rows":driver.terminal.rows,"retainedRows":driver.terminal.retainedRowCount])
        }
        NSPasteboard.general.clearContents()
        heartbeat.invalidate()
        try check("pressure-heartbeat-under-500ms", heartbeatCount > 20 && heartbeatMaximum <= 0.5)
        try await menuAction("showVault")
        try await click("hosts.refresh")
        try await wait("pressure-ui-restored") { !self.model.isLoading }
        samples.append(try pressureSample(stage: "stopped-before-close"))
        delegate.mainWindow?.performClose(nil); actions.append("close.pressure-window")
        try await wait("pressure-window-closed") { self.delegate.mainWindow == nil && self.model.sessions.tabs.isEmpty }
        try check("pressure-five-closed-disposed", metrics.reduce(0) { $0 + $1.closeCount } == 5 && metrics.reduce(0) { $0 + $1.disposedCount } == 5)
        try await wait("pressure-weak-views-released") { weakViews.allSatisfy { $0.value == nil } }
        samples.append(try pressureSample(stage: "after-close-weak-zero"))
        _ = delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false)
        try await wait("pressure-reopen") { self.delegate.mainWindow?.isVisible == true && !self.model.isLoading }
        try check("pressure-reopen-no-tabs", model.sessions.tabs.isEmpty && model.connectionNotice == nil)
        try await click("hosts.refresh")
        samples.append(try pressureSample(stage: "after-reopen"))
        let report: [String: Any] = ["scope":"HostProbe unoptimized logic driver + real NativeTerminalView render input; not SSH/PTY/network/PERF acceptance","durationSeconds":ProcessInfo.processInfo.systemUptime-started,"outputSeconds":outputElapsed,"declaredIntervalMilliseconds":ProbeOutputLoad.intervalMilliseconds,"maximumBatchBytes":ProbeOutputLoad.maximumBatchBytes,"configuredHistory":ProbeOutputLoad.historyLines,"initialColumns":80,"initialRows":24,"producerQueueBatches":1,"droppedBytes":0,"heartbeatCount":heartbeatCount,"heartbeatMaximumMilliseconds":heartbeatMaximum*1000,"heartbeatCheckMilliseconds":500,"interactions":interactions,"views":viewReports,"closed":5,"disposed":5,"weakViewsAliveAfterClose":weakViews.filter { $0.value != nil }.count,"resourceSamples":samples]
        try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted,.sortedKeys]).write(to: options.directory.appendingPathComponent("pressure-metrics.json"))
        try check("pressure-under-60-seconds", ProcessInfo.processInfo.systemUptime-started < 60)
    }
    private func pressureSample(stage: String) throws -> [String: Any] {
        let pid = ProcessInfo.processInfo.processIdentifier
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-p", String(pid), "-o", "%cpu=,rss="]
        process.environment = ["PATH":"/usr/bin:/bin", "LC_ALL":"C"]
        let output = Pipe(); process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Failure.check("pressure-self-resource-sample") }
        let fdBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard fdBytes > 0 else { throw Failure.check("pressure-self-fd-sample") }
        var storage = [UInt8](repeating: 0, count: Int(fdBytes) + 64 * MemoryLayout<proc_fdinfo>.stride)
        let captured = storage.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
        guard captured > 0 else { throw Failure.check("pressure-self-fd-sample") }
        return ["stage":stage,"time":ProcessInfo.processInfo.systemUptime,"selfPID":pid,"fdCount":Int(captured)/MemoryLayout<proc_fdinfo>.stride,"cpuAndRSSKiB":String(decoding:bytes,as:UTF8.self).trimmingCharacters(in:.whitespacesAndNewlines)]
    }
    private func filesLocalExercise() async throws {
        guard let connector = model.files.connector as? LocalFilesProbeConnector else { throw Failure.check("local-files-fixture-required") }
        let root = options.directory.appendingPathComponent("LocalFilesFixture")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("原始\n目录"), withIntermediateDirectories: false)
        try Data("keep-target".utf8).write(to: root.appendingPathComponent("target"))
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("link"), withDestinationURL: root.appendingPathComponent("target"))
        let startupCount = await connector.count
        try check("files-startup-hidden-no-connect", !model.files.visible && startupCount == 0)
        try await menuAction("newHost")
        try await type("host.name", "真实 Local fixture（不是 SFTP）")
        try await type("host.address", "never-scanned.invalid")
        try await type("host.username", "fixture")
        try await click("host.save")
        try await wait("files-host-ready") { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        try await selectFirstHost()
        delegate.mainWindow?.setContentSize(NSSize(width: 1600, height: 1000))
        try await click("files.open")
        try check("files-open-no-connect", await connector.count == 0)
        try await click("files.connect")
        try await wait("files-local-list-ready") { self.model.files.state == .ready && !self.model.files.busy }
        try check("files-real-local-list", model.files.entries.count == 3)
        try await click("files.refresh")
        try await wait("files-repeat-list-ready") { !self.model.files.busy }
        let repeatCount = await connector.count
        try check("files-repeated-root-list", model.files.entries.count == 3 && repeatCount == 1)
        try await click("files.mkdir")
        try await type("files.operation.name", "GUI 目录")
        try await click("files.mkdir.risk")
        try await click("files.operation.confirm")
        try await wait("files-mkdir-ready") { !self.model.files.busy && self.delegate.mainWindow?.attachedSheet == nil }
        try check("files-local-mkdir", FileManager.default.fileExists(atPath: root.appendingPathComponent("GUI 目录").path))
        try await selectFile("GUI 目录")
        try await click("files.rename")
        try await type("files.operation.name", "GUI renamed")
        try await click("files.operation.confirm")
        try await wait("files-rename-ready") { !self.model.files.busy && self.delegate.mainWindow?.attachedSheet == nil }
        try check("files-local-safe-rename", FileManager.default.fileExists(atPath: root.appendingPathComponent("GUI renamed").path))
        try await selectFile("GUI renamed")
        try await click("files.delete")
        try await click("files.delete.prepare")
        try await wait("files-delete-plan-ready") { self.model.files.deleteReview != nil && !self.model.files.busy }
        try await click("files.delete.review")
        try await click("files.delete.acknowledge")
        try await click("files.delete.execute")
        try await wait("files-delete-complete") { self.model.files.lastDeleteReport != nil && !self.model.files.busy }
        try check("files-local-exact-delete", model.files.lastDeleteReport?.allSucceeded == true && !FileManager.default.fileExists(atPath: root.appendingPathComponent("GUI renamed").path))
        try check("files-preserves-unselected-target", try Data(contentsOf: root.appendingPathComponent("target")) == Data("keep-target".utf8))
        _ = try fixtureEntry("原始\n目录")
        try await doubleClickFile("原始\n目录")
        await model.files.waitUntilCurrentWorkCompletes()
        let rawPath = model.files.path
        try await click("files.go")
        try await wait("files-raw-go-ready") { !self.model.files.busy }
        try check("files-raw-go-does-not-reparse-display", model.files.path == rawPath && rawPath.bytes == Data("/原始\n目录".utf8))
        try await click("files.hide")
        try check("files-hide-keeps-ready", model.files.state == .ready && !model.files.visible)
        let previous = model.files.manager
        delegate.mainWindow?.performClose(nil)
        try await wait("files-window-closed") { self.delegate.mainWindow == nil }
        try check("files-window-closes-services", await previous.snapshot().isClosed)
        _ = delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false)
        try await wait("files-window-reopen") { self.delegate.mainWindow?.isVisible == true && !self.model.isLoading }
        try check("files-reopen-hidden-no-restore", !model.files.visible && model.files.state == .disconnected && model.files.selectedHost == nil)
    }
    private func filesTransferExercise() async throws {
        guard let connector = model.files.connector as? LocalFilesProbeConnector else { throw Failure.check("transfer-local-fixture") }
        let base = try AppDataLocation.canonical(options.directory)
        let local = base.appendingPathComponent("TransferSource"), downloads = base.appendingPathComponent("TransferDownloads")
        let remote = base.appendingPathComponent("LocalFilesFixture")
        try FileManager.default.createDirectory(at: local, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: downloads, withIntermediateDirectories: false)
        try Data(repeating: 61, count: 250000).write(to: local.appendingPathComponent("upload 中文\nfile"))
        try Data("drop-content".utf8).write(to: local.appendingPathComponent("Finder drop"))
        try await click("host.add"); try await type("host.name", "Transfers Local fixture")
        try await type("host.address", "never-connected.invalid"); try await type("host.username", "fixture")
        try await click("host.save"); try await wait("transfer-host") { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        try await selectFirstHost(); delegate.mainWindow?.setContentSize(NSSize(width: 1650, height: 1050))
        try await click("files.open"); try await click("files.connect")
        try await wait("transfer-ready") { self.model.files.state == .ready && !self.model.files.busy }
        model.files.pathPicker.testSelection = [local.appendingPathComponent("upload 中文\nfile")]
        try await click("files.upload")
        try await wait("upload-job-finished") { self.model.files.transferSnapshot.jobs.first?.state == .succeeded }
        try check("picker-target-action-real-local-upload", try Data(contentsOf: remote.appendingPathComponent("upload 中文\nfile")) == Data(contentsOf: local.appendingPathComponent("upload 中文\nfile")))
        guard let table = find("files.entries", as: NSTableView.self), let source = table.dataSource else { throw Failure.missing("transfer-table") }
        try check("native-file-url-drop-registered", table.registeredDraggedTypes.contains(.fileURL))
        let pasteboard = NSPasteboard(name: .init("OpenLXSSH.Drop." + UUID().uuidString))
        pasteboard.writeObjects([local.appendingPathComponent("Finder drop") as NSURL])
        let drag = FilesProbeDraggingInfo(pasteboard: pasteboard, window: table.window)
        let operation = source.tableView?(table, validateDrop: drag, proposedRow: -1, proposedDropOperation: .on)
        let accepted = source.tableView?(table, acceptDrop: drag, row: -1, dropOperation: .on)
        try check("registered-native-drop-handler-accepts-fileURLs", operation == .copy && accepted == true)
        try await wait("drop-job-finished") { self.model.files.transferSnapshot.jobs.count == 2 && self.model.files.transferSnapshot.jobs.allSatisfy { $0.state == .succeeded } }
        try check("pasteboard-drop-real-local-content", try Data(contentsOf: remote.appendingPathComponent("Finder drop")) == Data("drop-content".utf8))
        pasteboard.clearContents(); pasteboard.setString("https://not-a-file.invalid", forType: .string)
        try check("native-drop-rejects-external-text", source.tableView?(table, validateDrop: drag, proposedRow: -1, proposedDropOperation: .on) == [])
        pasteboard.releaseGlobally()
        try await click("files.refresh"); try await wait("download-list") { !self.model.files.busy && self.model.files.entries.count == 2 }
        try await selectFile("upload 中文\nfile")
        model.files.pathPicker.testSelection = [downloads]
        try await click("files.download")
        try await wait("download-job-finished") { self.model.files.transferSnapshot.jobs.count == 3 && self.model.files.transferSnapshot.jobs.allSatisfy { $0.state == .succeeded } }
        try check("directory-picker-target-action-real-download", try Data(contentsOf: downloads.appendingPathComponent("upload 中文\nfile")) == Data(contentsOf: local.appendingPathComponent("upload 中文\nfile")))
        // A waiting conflict remains owned at application level while the panel is hidden.
        model.files.pathPicker.testSelection = [local.appendingPathComponent("upload 中文\nfile")]
        try await click("files.upload")
        try await wait("native-transfer-conflict") { self.model.files.transferSnapshot.jobs.last?.state == .waitingConflict }
        let conflictID = try model.files.transferSnapshot.jobs.last.map { $0.id } ?? { throw Failure.missing("conflict-job") }()
        try await click("files.hide")
        try check("tasks-entry-with-panel-hidden", find("transfers.open", as: NSButton.self) != nil && !model.files.visible)
        try await click("transfer.decision." + conflictID.uuidString)
        try await click("transfer.conflict.batch"); try await click("transfer.conflict.overwrite")
        try await wait("native-transfer-risk") { self.model.files.transferSnapshot.jobs.last?.state == .waitingRisk && self.delegate.mainWindow?.attachedSheet == nil }
        try await click("transfer.decision." + conflictID.uuidString)
        try await click("transfer.risk.reject")
        try await wait("native-risk-failed") { self.model.files.transferSnapshot.jobs.last?.state == .failed && self.delegate.mainWindow?.attachedSheet == nil }
        try check("overwrite-did-not-implicitly-accept-risk", model.files.transferSnapshot.jobs.last?.error?.kind == .riskRejected)
        try await click("transfer.retry." + conflictID.uuidString)
        try await wait("native-retry-conflict") { self.model.files.transferSnapshot.jobs.last?.state == .waitingConflict }
        let retried = try model.files.transferSnapshot.jobs.last ?? { throw Failure.missing("retry-job") }()
        try check("native-retry-new-id-generation-zero", retried.id != conflictID && retried.retryOf == conflictID && retried.transferredBytes == 0)
        try await click("transfer.decision." + retried.id.uuidString)
        try await type("transfer.conflict.name", "renamed native")
        try await click("transfer.conflict.rename")
        try await wait("native-rename-success") { self.model.files.transferSnapshot.jobs.last?.state == .succeeded && self.delegate.mainWindow?.attachedSheet == nil }
        try check("native-single-item-alternate", FileManager.default.fileExists(atPath: remote.appendingPathComponent("renamed native").path))
        try await click("transfers.remove.prepare")
        try await click("transfers.remove.confirm")
        try await wait("native-history-exact-removal") { self.model.files.transferSnapshot.jobs.isEmpty }
        try check("native-history-review-removes-records-not-files", FileManager.default.fileExists(atPath: remote.appendingPathComponent("renamed native").path))
        try await click("files.open")
        await connector.holdTransfer()
        try Data(repeating: 72, count: 800000).write(to: local.appendingPathComponent("active-lifecycle"))
        model.files.pathPicker.testSelection = [local.appendingPathComponent("active-lifecycle")]
        try await click("files.upload"); await connector.waitForTransfer()
        let activeID = try model.files.transferSnapshot.jobs.last.map { $0.id } ?? { throw Failure.missing("active-job") }()
        delegate.mainWindow?.performClose(nil)
        try await wait("lifecycle-first-prompt") { self.find("lifecycle.transfers.continue", as: NSButton.self) != nil }
        delegate.mainWindow?.performClose(nil)
        let repeatReply = delegate.applicationShouldTerminate(NSApp)
        let promptCount = NSApp.windows.filter { $0.isVisible && $0.title == "OpenLXSSH · 活动传输" }.count
        try check("repeated-window-quit-shares-one-transfer-decision", repeatReply == .terminateLater && promptCount == 1 && !model.lifecycle.terminating)
        try await click("lifecycle.transfers.continue")
        try check("native-window-continue-retains-window-job", delegate.mainWindow?.isVisible == true && model.files.transferSnapshot.jobs.last?.state.isActive == true && !model.files.admissionFrozen)
        // Actual NSApp termination enters AppKit's terminateLater loop. A run-loop timer
        // drives the real prompt button so the main-queue exclusion cannot hide a deadlock.
        let keepTimer = Timer(timeInterval: 0.18, repeats: true) { _ in MainActor.assumeIsolated {
            if let button = self.find("lifecycle.transfers.continue", as: NSButton.self) { button.performClick(nil); self.transferPromptTimer?.invalidate(); self.transferPromptTimer = nil }
        } }
        transferPromptTimer = keepTimer
        RunLoop.main.add(keepTimer, forMode: .common)
        RunLoop.main.perform { MainActor.assumeIsolated { NSApp.terminate(nil) } }
        try await wait("quit-continue-resumes") { !self.model.files.admissionFrozen && !self.model.lifecycle.terminating && keepTimer.isValid == false }
        try check("native-quit-continue-does-not-kill-job", delegate.mainWindow?.isVisible == true && model.files.transferSnapshot.jobs.last?.state.isActive == true)
        if options.phase == "files-transfer-exit" {
            let cancelTimer = Timer(timeInterval: 0.18, repeats: true) { _ in MainActor.assumeIsolated {
                if let button = self.find("lifecycle.transfers.cancelClose", as: NSButton.self) { button.performClick(nil); self.transferPromptTimer?.invalidate(); self.transferPromptTimer = nil }
            } }
            transferPromptTimer = cancelTimer
            RunLoop.main.add(cancelTimer, forMode: .common)
            try check("native-exit-starts-with-active-job", model.files.transferSnapshot.jobs.last?.state.isActive == true)
            return // run() issues real NSApp.terminate; package cancellation releases the held I/O.
        }
        let previous = model.files.manager
        delegate.mainWindow?.performClose(nil)
        try await click("lifecycle.transfers.cancelClose")
        try await wait("transfer-window-cancel-closed") { self.delegate.mainWindow == nil }
        let final = await previous.snapshot()
        try check("native-window-awaits-job-and-service-cleanup", final.isClosed && final.jobs.first { $0.id == activeID }?.state == .cancelled && !final.hasActiveWork)
        _ = delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false)
        try await wait("transfer-window-reopened") { self.delegate.mainWindow?.isVisible == true && !self.model.isLoading }
        try check("transfer-reopen-fresh-hidden-manager", !model.files.visible && model.files.transferSnapshot.jobs.isEmpty && !(previous === model.files.manager))
        await connector.releaseTransfer()
    }
    private func fixtureEntry(_ name: String) throws -> DirectoryEntry {
        guard let entry = model.files.entries.first(where: { $0.name.bytes == Data(name.utf8) }) else { throw Failure.missing("files-entry") }
        return entry
    }
    private func selectFile(_ name: String) async throws {
        try await wait("files-table") { self.find("files.entries", as: NSTableView.self) != nil }
        guard let table = find("files.entries", as: NSTableView.self), let row = model.files.entries.firstIndex(where: { $0.name.bytes == Data(name.utf8) }) else { throw Failure.missing("files-row") }
        table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        try await pause()
    }
    private func doubleClickFile(_ name: String) async throws {
        guard let table = find("files.entries", as: NSTableView.self), let window = table.window,
              let row = model.files.entries.firstIndex(where: { $0.name.bytes == Data(name.utf8) }) else { throw Failure.missing("files-row") }
        let point = table.convert(NSPoint(x: 50, y: table.rect(ofRow: row).midY), to: nil)
        let now = ProcessInfo.processInfo.systemUptime
        for click in 1...2 {
            guard let down = NSEvent.mouseEvent(with: .leftMouseDown, location: point, modifierFlags: [], timestamp: now + Double(click) * 0.03, windowNumber: window.windowNumber, context: nil, eventNumber: click * 2, clickCount: click, pressure: 1),
                  let up = NSEvent.mouseEvent(with: .leftMouseUp, location: point, modifierFlags: [], timestamp: now + Double(click) * 0.03 + 0.01, windowNumber: window.windowNumber, context: nil, eventNumber: click * 2 + 1, clickCount: click, pressure: 0) else { throw Failure.missing("files-double-click") }
            NSApp.postEvent(down, atStart: false); NSApp.postEvent(up, atStart: false)
            try await Task.sleep(for: .milliseconds(60))
        }
        try await wait("files-enter-directory") { self.model.files.path.bytes == Data(("/" + name).utf8) }
    }
    private func transportConfiguration() async throws {
        let resources = try await model.sessionEnvironment.opened()
        try check("strict-bundled-helper-discovered", resources.helper.url.path == Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/openlxssh-askpass").path)
        let configuration = try SessionEnvironment.configuration(host: HostConfiguration(name: "offline config", address: "offline-config.invalid", username: "fixture"), keyPath: nil)
        // Validate public material through the mature parser without any network access.
        let key = try await Task.detached { try OpenLXSSHTrust.HostPublicKey(openSSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFhJwF6sPz9bZWdnLdkV1FY9JSt0XgTDbZd7ABl6KQSr") }.value
        let controlled = try DirectSSHConfiguration(configuration: configuration, trustStore: resources.trust, trustedKeys: [key], helper: resources.helper)
        let preview = options.directory.appendingPathComponent("controlled-preview.conf")
        try Data(controlled.text.utf8).write(to: preview)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: preview.path)
        let result = try await Task.detached {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
            process.arguments = ["-G", "-F", preview.path, "--", DirectSSHConfiguration.destination]
            process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": preview.deletingLastPathComponent().path]
            let pipe = Pipe(); process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
            try process.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
            return (process.terminationStatus, String(decoding: data, as: UTF8.self))
        }.value
        try check("system-ssh-G-offline", result.0 == 0 && result.1.contains("stricthostkeychecking true") && result.1.contains("proxyjump none") == false)
        try check("controlled-config-helper-command", controlled.text.contains("--authenticated-event v1") && controlled.text.contains("StrictHostKeyChecking yes") && controlled.text.contains("ProxyJump none"))
        try FileManager.default.removeItem(at: preview)
        try check("offline-preview-no-session", model.sessions.tabs.isEmpty)
        try check("files-native-static-diagnostics", NativeDiagnostics.smoke() == 0 && NativeDiagnostics.libssh2 == "1.11.1" && NativeDiagnostics.openssl.contains("3.5.9"))
        let authorizedKey = try await model.security.createKey(.generate, protection: .unencrypted, rememberPassphrase: nil).id
        let keyHost = HostConfiguration(name: "signed SFTP material boundary", address: "never-connected.invalid", username: "fixture", authentication: .privateKey, keyRef: authorizedKey)
        try await model.repository.apply([.insertHost(keyHost)])
        let material = try await model.security.privateKeyForFileAuthentication(host: keyHost, authorized: true)
        try check("signed-exact-key-memory-material", material.withUnsafeBytes { !$0.isEmpty })
        do {
            _ = try await model.security.privateKeyForFileAuthentication(host: keyHost, authorized: false)
            throw Failure.check("private-material-requires-authorization")
        } catch SecurityUIFailure.notAuthorized { }
        try check("private-material-requires-authorization", true)
        try await model.repository.apply([.deleteHost(keyHost.id)])
        try await model.security.deleteKey(authorizedKey)
        try check("signed-material-exact-cleanup", try await model.repository.securityMetadata().keys.isEmpty)
        let direct = DirectSSHSession(trustStore: resources.trust, sessionDirectory: resources.directory,
                                      helper: resources.helper, scanner: OfflineCandidateScanner())
        _ = try direct.connect(configuration)
        try await wait("real-direct-session-awaiting-trust") { direct.state == .awaitingTrust }
        try check("real-direct-session-no-process-before-trust", direct.ownedProcessID == nil && direct.trustChallenges.count == 1)
        direct.closeTab()
        try await wait("real-direct-session-cancelled") { direct.state == .closed }
        try check("real-direct-session-cancelled-without-network", direct.state == .closed && direct.ownedProcessID == nil)
    }

    private func securitySheets() async throws {
        try await click("security.open")
        try await click("keys.generate")
        try await click("key.protection")
        try await click("key.create")
        try await wait("sheet-key-created") { self.model.keys.count == 1 }
        try await click("security.done")
        try await wait("sheet-manager-closed-after-create") { self.delegate.mainWindow?.attachedSheet == nil }
        try check("sheet-manager-closed-after-create", true)
        let key = try await model.repository.securityMetadata().keys[0]
        try await menuAction("newHost")
        try await type("host.name", "Sheet lifecycle fixture")
        try await type("host.address", "sheet.invalid")
        try await type("host.username", "fixture")
        try await popup("host.authentication", value: "privateKey")
        try await popup("host.key", value: key.id.uuidString)
        try await click("host.save")
        try await wait("sheet-host-editor-closed") { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        try check("sheet-host-editor-closed", true)
        try await click("security.open")
        try await click("key.public." + key.id.uuidString)
        try await click("public.close")
        try await click("key.delete." + key.id.uuidString)
        try await click("key.delete.confirm")
        try await wait("sheet-shared-key-error-visible") { self.find("issue.dismiss", as: NSButton.self) != nil }
        try check("sheet-shared-key-error-visible", true)
        try await click("key.delete.cancel")
        let linkedHost = try await model.repository.securityMetadata().hosts[0]
        try await model.repository.apply([.deleteHost(linkedHost.id)])
        try await click("security.refresh")
        try await click("key.delete." + key.id.uuidString)
        try await click("key.delete.confirm")
        try await wait("sheet-key-deleted") { self.find("key.delete.confirm", as: NSButton.self) == nil }
        try await click("security.done")
        try await wait("sheet-manager-closed-after-delete") { self.delegate.mainWindow?.attachedSheet == nil }
        try check("sheet-manager-closed-after-delete", true)
        try check("sheet-key-metadata-deleted", try await model.repository.securityMetadata().keys.isEmpty)
    }

    private func securityExercise() async throws {
        if options.phase == "security" {
            try check("security-fresh", model.hosts.isEmpty)
            try await click("security.open")
            try await click("keys.generate")
            try await type("key.passphrase", UUID().uuidString)
            // Use one ephemeral string solely in secure fields, never in reports/arguments/files.
            try await click("key.editor.cancel")
            try await click("keys.generate")
            let phrase = UUID().uuidString
            try await type("key.passphrase", phrase)
            try await type("key.confirm", phrase)
            try await click("key.remember")
            try await click("key.create")
            try await wait("generated-key") { self.model.keys.count == 1 }
            try await click("security.done")
            try await wait("security-manager-dismissed-after-key") { self.delegate.mainWindow?.attachedSheet == nil }
            try check("security-manager-dismissed-after-key", true)
            try await menuAction("newHost")
            try await type("host.name", "Security GUI host")
            try await type("host.address", "security-gui.invalid")
            try await type("host.username", "fixture")
            try await type("host.password", UUID().uuidString)
            try check("secure-password-control", find("host.password", as: NSSecureTextField.self) != nil)
            try await click("host.remember")
            try await click("host.save")
            try await wait("credential-committed") { self.model.hosts.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
            try check("host-remember-explicit", model.hosts[0].savePasswordAuthorized && model.hosts[0].credentialRef != nil)
            try await selectFirstHost()
            try await click("host.copy")
            try await wait("shared-password-copy") { self.model.hosts.count == 2 }
            try await click("security.open")
            let key = try await model.repository.securityMetadata().keys[0]
            try await click("key.public." + key.id.uuidString)
            try await click("public.copy")
            try await click("public.close")
            try await click("key.copy." + key.id.uuidString)
            let publicKey = try await model.security.publicKey(key.id)
            try check("clipboard-public-only", NSPasteboard.general.string(forType: .string) == publicKey.copyString)
            try capture("security-manager.png")
            try await click("security.done")
            try await wait("security-manager-dismissed-after-public") { self.delegate.mainWindow?.attachedSheet == nil }
            try check("security-manager-dismissed-after-public", true)
            // Simulate an interrupted, unconfirmed creation only after releasing this
            // process's KeyStore/journal. The next real App launch must load the record.
            try await model.security.close()
            let unrelated = options.directory.appendingPathComponent("preserved-recovery-fixture")
            try Data("preserve".utf8).write(to: unrelated)
            let journal = try SecurityJournal(parent: AppDataLocation.canonical(options.directory))
            try journal.set(.init(id: UUID(), kind: .password, state: .prepared))
        } else if options.phase == "security-read" {
            let metadata = try await model.repository.securityMetadata()
            try check("security-restart-metadata", metadata.hosts.count == 2 && metadata.keys.count == 1 && metadata.credentials.count == 2)
            for credential in metadata.credentials {
                let kind: OpenLXSSHSecurity.CredentialReference.Kind = credential.purpose == .password ? .password : .privateKeyPassphrase
                switch await model.security.credentials.read(.init(id: credential.id, kind: kind)) {
                case .available: break
                default: throw Failure.check("signed-app-keychain-read")
                }
            }
            try check("signed-app-keychain-read", true)
            try check("security-no-connection", model.connectionNotice == nil && metadata.hosts.allSatisfy { $0.lastConnectedAt == nil })
            let key = metadata.keys[0]
            try await menuAction("newHost")
            try await type("host.name", "Shared key host")
            try await type("host.address", "shared-key.invalid")
            try await type("host.username", "fixture")
            try await popup("host.authentication", value: "privateKey")
            try await popup("host.key", value: key.id.uuidString)
            try await click("host.save")
            try await wait("host-key-associated") { self.model.hosts.count == 3 && self.delegate.mainWindow?.attachedSheet == nil }
            try await click("security.open")
            let overview = try await model.security.overview()
            guard let review = overview.recoveryReviews.first(where: { $0.canDiscard }) else { throw Failure.missing("prepared-recovery-record") }
            let unrelated = options.directory.appendingPathComponent("preserved-recovery-fixture")
            let beforeReview = try Data(contentsOf: unrelated)
            try await click("recovery.review." + review.id.uuidString)
            try check("prepared-discard-explicit-confirmation", find("recovery.discard", as: NSButton.self)?.title == "仅丢弃恢复记录，不删除任何文件/Keychain")
            try await click("recovery.discard")
            try await wait("recovery-record-discarded") { self.find("recovery.review." + review.id.uuidString, as: NSButton.self) == nil }
            let reviewed = try await model.security.overview()
            try check("prepared-discard-record-only", try Data(contentsOf: unrelated) == beforeReview && reviewed.recoveryReviews.isEmpty)
            try check("prepared-discard-preserves-metadata", reviewed.metadata.hosts == overview.metadata.hosts && reviewed.metadata.keys == overview.metadata.keys && reviewed.metadata.credentials == overview.metadata.credentials)
            for credential in metadata.credentials {
                let kind: OpenLXSSHSecurity.CredentialReference.Kind = credential.purpose == .password ? .password : .privateKeyPassphrase
                if case .available = await model.security.credentials.read(.init(id: credential.id, kind: kind)) {} else { throw Failure.check("prepared-discard-preserves-keychain") }
            }
            try check("prepared-discard-preserves-keychain", true)
            try await click("key.delete." + key.id.uuidString)
            try await click("key.delete.confirm")
            try await wait("shared-key-refused") { self.find("issue.dismiss", as: NSButton.self) != nil }
            try check("shared-key-delete-refused", try await model.repository.securityMetadata().keys.count == 1)
            try await click("key.delete.cancel")
            let keyFile = options.directory.appendingPathComponent("Keys/" + key.id.uuidString + ".openssh")
            let beforeForget = try Data(contentsOf: keyFile)
            try await click("key.forgetPassphrase." + key.id.uuidString)
            try await wait("key-passphrase-forgotten") { self.find("key.forgetPassphrase." + key.id.uuidString, as: NSButton.self) == nil }
            let forgotten = try await model.repository.securityMetadata()
            try check("key-passphrase-detached", forgotten.keys.first { $0.id == key.id }?.passphraseCredentialRef == nil)
            try check("forget-keeps-key-file", try Data(contentsOf: keyFile) == beforeForget)
            if let ref = key.passphraseCredentialRef {
                if case .missing = await model.security.credentials.read(.init(id: ref, kind: .privateKeyPassphrase)) {} else { throw Failure.check("forgotten-keyphrase-absent") }
            }
            try check("forgotten-keyphrase-absent", true)
            let keyHost = try await model.repository.securityMetadata().hosts.first { $0.keyRef == key.id }!
            try await model.repository.apply([.deleteHost(keyHost.id)])
            try await click("security.refresh")
            try await click("key.delete." + key.id.uuidString)
            try await click("key.delete.confirm")
            try await wait("key-deletion-dialog-closed") { self.find("key.delete.confirm", as: NSButton.self) == nil }
            try check("unshared-key-deleted", try await model.repository.securityMetadata().keys.isEmpty)
            try await click("security.done")
            try await wait("security-manager-dismissed-after-recovery-delete") { self.delegate.mainWindow?.attachedSheet == nil }
            try check("security-manager-dismissed-after-recovery-delete", true)
        } else {
            let metadata = try await model.repository.securityMetadata()
            for host in metadata.hosts where host.credentialRef != nil { try await model.security.forgetHostPassword(host.id) }
            for host in metadata.hosts { try await model.repository.apply([.deleteHost(host.id)]) }
            for key in metadata.keys { try await model.security.deleteKey(key.id) }
            try await model.security.retryCleanup()
            let cleaned = try await model.repository.securityMetadata()
            try check("security-exact-cleanup", cleaned.hosts.isEmpty && cleaned.keys.isEmpty && cleaned.credentials.isEmpty && cleaned.tickets.isEmpty)
            for credential in metadata.credentials {
                let kind: OpenLXSSHSecurity.CredentialReference.Kind = credential.purpose == .password ? .password : .privateKeyPassphrase
                if case .missing = await model.security.credentials.read(.init(id: credential.id, kind: kind)) {} else { throw Failure.check("keychain-absent-after-cleanup") }
            }
            try check("keychain-absent-after-cleanup", true)
            try check("recovery-empty", try await model.security.overview().pendingCount == 0)
        }
    }

    private struct ControlNode {
        let object: NSObject
        let element: (any NSAccessibilityProtocol)?
        var reachedNatively: Bool
        var reachedByAccessibility: Bool
    }
    private struct ControlTree {
        var nodes: [ControlNode] = []
        var visitedNodes = 0
        var truncated = false
        var rejectedHidden = 0
        var rejectedForeignOwner = 0
        var rejectedApplicationOrMenu = 0
        var rootNativeWindowMatches = false
        var rootAXWindowIsParent = false
        var rootAXTopLevelIsParent = false
    }
    private static let publicFieldIdentities: [(id: String, caption: String)] = [
        ("host.address", "服务器地址"), ("host.name", "名称"), ("host.username", "用户名"),
        ("host.port", "端口"), ("host.password", "本次密码"),
        ("host.interval", "保活间隔（秒）"), ("host.count", "保活失败次数")
    ]
    private static let diagnosticFieldIDs = publicFieldIdentities.map(\.id)
    private static let diagnosticButtonTitles = ["保存", "关闭主机编辑", "关闭", "放弃更改", "取消"]
    private func interactiveWindow() -> NSWindow? {
        guard var window = delegate.mainWindow, window.isVisible else { return nil }
        var visited = Set<ObjectIdentifier>([ObjectIdentifier(window)])
        for _ in 0..<8 {
            guard let sheet = window.attachedSheet else { return window }
            guard sheet.isVisible, sheet.sheetParent === window,
                  visited.insert(ObjectIdentifier(sheet)).inserted else { return nil }
            window = sheet
        }
        return nil
    }
    /// AX may report a sheet's containing document window as its top-level owner.
    /// Validate that relationship from AppKit's real, bidirectional sheet chain;
    /// these ancestors are metadata only, never additional traversal roots.
    private func verifiedSheetParents(of window: NSWindow) -> [NSWindow]? {
        var current = window, parents: [NSWindow] = [], visited = Set<ObjectIdentifier>([ObjectIdentifier(window)])
        for _ in 0..<8 {
            guard let parent = current.sheetParent else { return parents }
            guard current.isVisible, parent.isVisible, parent.attachedSheet === current,
                  visited.insert(ObjectIdentifier(parent)).inserted else { return nil }
            parents.append(parent); current = parent
        }
        return current.sheetParent == nil ? parents : nil
    }
    /// Start at the exact content owner, never NSApplication or its menus. Native
    /// subviews and public AX children are complementary on SwiftUI editors.
    private func controlTree(in window: NSWindow) -> ControlTree {
        var result = ControlTree(), visited = Set<ObjectIdentifier>(), accepted: [ObjectIdentifier: Int] = [:]
        guard window.isVisible, let root = window.contentView else { return result }
        result.rootNativeWindowMatches = root.window === window
        guard let sheetParents = verifiedSheetParents(of: window) else { result.rejectedForeignOwner = 1; return result }
        let rootElement = root as any NSAccessibilityProtocol
        if let owner = rootElement.accessibilityWindow() as? NSWindow {
            result.rootAXWindowIsParent = sheetParents.contains { $0 === owner }
        }
        if let owner = rootElement.accessibilityTopLevelUIElement() as? NSWindow {
            result.rootAXTopLevelIsParent = sheetParents.contains { $0 === owner }
        }
        func ownerMetadataAllowed(_ owner: NSWindow) -> Bool {
            owner === window || sheetParents.contains { $0 === owner }
        }
        let maximumNodes = 1024, maximumDepth = 36, maximumChildren = 128
        func visit(_ value: Any, depth: Int, native: Bool) {
            guard let object = value as? NSObject else { return }
            let identity = ObjectIdentifier(object)
            if visited.contains(identity) {
                if let index = accepted[identity] {
                    if native { result.nodes[index].reachedNatively = true }
                    else { result.nodes[index].reachedByAccessibility = true }
                }
                return
            }
            guard depth <= maximumDepth, visited.count < maximumNodes else { result.truncated = true; return }
            visited.insert(identity); result.visitedNodes = visited.count
            let element = object as? any NSAccessibilityProtocol
            let role = element?.accessibilityRole()
            if object is NSApplication || object is NSMenu || object is NSMenuItem ||
                role == .application || role == .menu || role == .menuBar || role == .menuBarItem || role == .menuItem {
                result.rejectedApplicationOrMenu += 1; return
            }
            // A window is never a content descendant. Even verified sheet parents
            // are forbidden as nodes, so their content cannot leak into this owner.
            if object is NSWindow {
                result.rejectedForeignOwner += 1; return
            }
            if let view = object as? NSView {
                guard view.window === window, view === root || view.isDescendant(of: root) else {
                    result.rejectedForeignOwner += 1; return
                }
                guard !view.isHiddenOrHasHiddenAncestor else { result.rejectedHidden += 1; return }
            }
            if let element {
                guard !element.isAccessibilityHidden() else { result.rejectedHidden += 1; return }
                // NSView.window / exact content ancestry remains the native authority.
                // AX window/topLevel can legitimately name a verified sheet ancestor.
                if let owner = element.accessibilityWindow() as? NSWindow, !ownerMetadataAllowed(owner) {
                    result.rejectedForeignOwner += 1; return
                }
                if let owner = element.accessibilityTopLevelUIElement() as? NSWindow, !ownerMetadataAllowed(owner) {
                    result.rejectedForeignOwner += 1; return
                }
            }
            accepted[identity] = result.nodes.count
            result.nodes.append(ControlNode(object: object, element: element, reachedNatively: native, reachedByAccessibility: !native))
            if let view = object as? NSView {
                let children = view.subviews
                if children.count > maximumChildren { result.truncated = true }
                for child in children.prefix(maximumChildren) { visit(child, depth: depth + 1, native: true) }
            }
            if let element {
                let children = element.accessibilityChildren() ?? []
                if children.count > maximumChildren { result.truncated = true }
                for child in children.prefix(maximumChildren) { visit(child, depth: depth + 1, native: false) }
            }
        }
        visit(root, depth: 0, native: true)
        return result
    }
    /// Diagnostic categories are constants, never reflected class descriptions.
    /// Walk public superclass metadata only to recognize the generic NSHostingView.
    private func diagnosticClassCategory(_ object: NSObject) -> String {
        var kind: AnyClass? = object_getClass(object)
        for _ in 0..<16 {
            guard let current = kind else { break }
            let name = NSStringFromClass(current)
            if name == "SwiftUI.NSHostingView" || name.hasPrefix("SwiftUI.NSHostingView<") { return "NSHostingView" }
            kind = class_getSuperclass(current)
        }
        if object is NSSecureTextField { return "NSSecureTextField" }
        if object is NSTextField { return "NSTextField" }
        if object is NSScrollView { return "NSScrollView" }
        if object is NSClipView { return "NSClipView" }
        if object is NSStackView { return "NSStackView" }
        if object is NSSplitView { return "NSSplitView" }
        if object is NSButton { return "NSButton" }
        if object is NSTextView { return "NSTextView" }
        if object is NSAccessibilityElement { return "NSAccessibilityElement" }
        if object is NativeWorkspacePageView { return "NativeWorkspacePageView" }
        if Swift.type(of: object) == NSView.self { return "NSView" }
        if Swift.type(of: object) == NSObject.self { return "NSObject" }
        return "other"
    }
    private func diagnosticRoleCategory(_ role: NSAccessibility.Role?) -> String {
        switch role {
        case .some(.textField): return "AXTextField"
        case .some(.textArea): return "AXTextArea"
        case .some(.button): return "AXButton"
        case .some(.group): return "AXGroup"
        case .some(.scrollArea): return "AXScrollArea"
        case .some(.layoutArea): return "AXLayoutArea"
        case .some(.splitGroup): return "AXSplitGroup"
        case .some(.staticText): return "AXStaticText"
        case .some(.checkBox): return "AXCheckBox"
        case .some(.popUpButton): return "AXPopUpButton"
        case .some(.image): return "AXImage"
        case .some(.unknown): return "AXUnknown"
        case .none: return "none"
        default: return "other"
        }
    }
    /// Compare only immutable design captions. Never serialize a returned public
    /// placeholder/title/label (or inspect any field value) to establish identity.
    private func publicFieldIdentityMatches(_ object: NSObject) -> [[String: Any]] {
        let field = object as? NSTextField, element = object as? any NSAccessibilityProtocol
        guard field != nil || element?.accessibilityRole() == .textField || element?.accessibilityRole() == .textArea else { return [] }
        var matches: [[String: Any]] = []
        for identity in Self.publicFieldIdentities {
            let nativePlaceholder = field?.placeholderString == identity.caption
            let AXPlaceholder = element?.accessibilityPlaceholderValue() == identity.caption
            let AXTitle = element?.accessibilityTitle() == identity.caption
            let AXLabel = element?.accessibilityLabel() == identity.caption
            if nativePlaceholder || AXPlaceholder || AXTitle || AXLabel {
                matches.append(["fieldIdentity": identity.id, "nativePlaceholderMatches": nativePlaceholder,
                    "AXPlaceholderMatches": AXPlaceholder, "AXTitleMatches": AXTitle, "AXLabelMatches": AXLabel])
            }
        }
        return matches
    }
    /// A read-only census independent of controlTree's acceptance policy. No node
    /// discovered here can satisfy find/type/click or any editor assertion.
    private func controlDiagnosticCensus(in window: NSWindow) -> [String: Any] {
        var counts: [String: Int] = [:], classes: [String: Int] = [:], roles: [String: Int] = [:]
        var nativeClassCounts: [String: Int] = [:], AXClassCounts: [String: Int] = [:]
        var nativeRoleCounts: [String: Int] = [:], AXRoleCounts: [String: Int] = [:]
        var bridgeRecords: [[String: Any]] = [], hiddenRecords: [[String: Any]] = [], candidates: [[String: Any]] = []
        var buttonCandidates: [[String: Any]] = []
        var visited = Set<ObjectIdentifier>(), visitedCount = 0, attempts = 0, truncated = false
        let maximumNodes = 1024, maximumDepth = 36, maximumChildren = 128, maximumAttempts = 4096
        guard window.isVisible, let root = window.contentView, root.window === window,
              let sheetParents = verifiedSheetParents(of: window) else { return ["exactRootAvailable": false] }
        let minimumProtocol = NSProtocolFromString("NSAccessibilityElement")
        func bump(_ name: String) { counts[name, default: 0] += 1 }
        func sameOwner(_ owner: NSWindow) -> Bool { owner === window || sheetParents.contains { $0 === owner } }
        func fixedIdentifier(_ object: NSObject) -> String? {
            let view = object as? NSView
            let element = object as? any NSAccessibilityProtocol
            return Self.diagnosticFieldIDs.first { view?.identifier?.rawValue == $0 || element?.accessibilityIdentifier() == $0 }
        }
        func visit(_ value: Any, depth: Int, source: String, parentRole: String, parentClass: String,
                   parentFieldID: String?, behindAXHiddenContainer: Bool) {
            guard attempts < maximumAttempts else { truncated = true; return }
            attempts += 1
            if source == "AX" {
                bump("AXReturnedEdgesInspected")
                if value is NSAccessibilityElement { bump("AXReturnedNSAccessibilityElement") }
                if value is any NSAccessibilityProtocol { bump("AXReturnedFullAXProtocol") }
            }
            guard let object = value as? NSObject else {
                bump("notNSObject")
                if source == "AX" { bump("AXReturnedNotNSObject") }
                if bridgeRecords.count < 24 {
                    bridgeRecords.append(["depth": depth, "classCategory": "other", "role": "uninspected",
                        "isNSObject": false, "isNativeView": false, "isNSAccessibilityElement": false,
                        "fullAXProtocolCast": value is any NSAccessibilityProtocol,
                        "minimalAXElementProtocol": false, "minimalProtocolCheckAvailable": false,
                        "publicGettersInspected": false])
                }
                return
            }
            if source == "AX" { bump("AXReturnedNSObject") }
            let identity = ObjectIdentifier(object)
            guard !visited.contains(identity) else { bump("duplicateEdges"); return }
            guard depth <= maximumDepth, visited.count < maximumNodes else { truncated = true; return }
            visited.insert(identity); visitedCount = visited.count
            // Establish native visibility before reading any AX metadata. A hidden
            // native view is an unconditional leaf, even for this read-only census.
            if let view = object as? NSView {
                guard view.window === window, view === root || view.isDescendant(of: root) else { bump("foreignNativeOwnerRejected"); return }
                if view.isHiddenOrHasHiddenAncestor {
                    bump("nativeHiddenRejected")
                    if hiddenRecords.count < 16 {
                        hiddenRecords.append(["reason": "native-hidden", "depth": depth, "source": source,
                            "classCategory": diagnosticClassCategory(object), "role": "uninspected",
                            "parentClassCategory": parentClass, "parentRole": parentRole,
                            "nativeIsHidden": view.isHidden, "nativeIsHiddenOrHasHiddenAncestor": true,
                            "nativeWindowMatches": true, "AXMetadataInspected": false, "childrenInspected": false])
                    }
                    return
                }
            }
            let element = object as? any NSAccessibilityProtocol
            let role = element?.accessibilityRole(), roleCategory = diagnosticRoleCategory(role)
            let category = diagnosticClassCategory(object), view = object as? NSView
            bump(source == "native" ? "nativeEdges" : "AXEdges")
            if object is NSApplication || object is NSMenu || object is NSMenuItem ||
                role == .application || role == .menu || role == .menuBar || role == .menuBarItem || role == .menuItem {
                bump("applicationOrMenuRejected"); return
            }
            if object is NSWindow { bump("windowNodeRejected"); return }
            if let element {
                if let owner = element.accessibilityWindow() as? NSWindow, !sameOwner(owner) { bump("foreignAXOwnerRejected"); return }
                if let owner = element.accessibilityTopLevelUIElement() as? NSWindow, !sameOwner(owner) { bump("foreignAXTopLevelRejected"); return }
            }
            classes[category, default: 0] += 1; roles[roleCategory, default: 0] += 1
            if source == "native" {
                nativeClassCounts[category, default: 0] += 1; nativeRoleCounts[roleCategory, default: 0] += 1
            } else {
                AXClassCounts[category, default: 0] += 1; AXRoleCounts[roleCategory, default: 0] += 1
            }
            if view != nil { bump("nativeView") }
            if element != nil { bump("fullAXProtocol") }
            if object is NSAccessibilityElement { bump("NSAccessibilityElement") }
            let minimal = minimumProtocol.map { object.conforms(to: $0) } ?? false
            if minimal { bump("minimalAXElementProtocol") }
            let roleGetter = object.responds(to: #selector(NSAccessibilityProtocol.accessibilityRole))
            let childrenGetter = object.responds(to: #selector(NSAccessibilityProtocol.accessibilityChildren))
            let identifierGetter = object.responds(to: #selector(NSAccessibilityProtocol.accessibilityIdentifier))
            if element == nil {
                bump("fullAXProtocolCastFailed")
                if roleGetter { bump("castFailedWithRoleGetter") }
                if childrenGetter { bump("castFailedWithChildrenGetter") }
            }
            if source == "AX", bridgeRecords.count < 24 {
                bridgeRecords.append(["depth": depth, "classCategory": category, "role": roleCategory,
                    "isNSObject": true, "isNativeView": view != nil, "isNSAccessibilityElement": object is NSAccessibilityElement,
                    "fullAXProtocolCast": element != nil, "minimalAXElementProtocol": minimal,
                    "minimalProtocolCheckAvailable": minimumProtocol != nil,
                    "publicRoleGetter": roleGetter, "publicChildrenGetter": childrenGetter,
                    "publicIdentifierGetter": identifierGetter])
            }
            let nativeChildren = view?.subviews ?? []
            let fixedButton = Self.diagnosticButtonTitles.first { title in
                (object as? NSButton)?.title == title || element?.accessibilityLabel() == title || element?.accessibilityTitle() == title
            }
            if (fixedButton != nil || object is NSButton || role == .button), buttonCandidates.count < 24 {
                buttonCandidates.append(["buttonIdentity": fixedButton ?? "none", "depth": depth, "source": source,
                    "classCategory": category, "role": roleCategory, "parentClassCategory": parentClass,
                    "nativeTitleMatches": fixedButton != nil && (object as? NSButton)?.title == fixedButton,
                    "AXLabelMatches": fixedButton != nil && element?.accessibilityLabel() == fixedButton,
                    "AXTitleMatches": fixedButton != nil && element?.accessibilityTitle() == fixedButton,
                    "AXIsElement": element?.isAccessibilityElement() == true, "AXHidden": element?.isAccessibilityHidden() == true,
                    "AXPressAllowed": element?.isAccessibilitySelectorAllowed(#selector(NSAccessibilityProtocol.accessibilityPerformPress)) == true,
                    "nativeVisibleBoundsIntersectionNonempty": view.map { !$0.visibleRect.intersection($0.bounds).isEmpty } ?? false])
            }
            let nativeVisibleChildren = nativeChildren.filter {
                $0.window === window && ($0 === root || $0.isDescendant(of: root)) && !$0.isHiddenOrHasHiddenAncestor
            }
            let fieldID = fixedIdentifier(object)
            let isField = object is NSTextField || role == .textField || role == .textArea
            if isField { bump("fieldRoleOrNativeField") }
            if object is NSTextField { bump("nativeTextField") }
            if fieldID != nil { bump("allowlistedIdentifier") }
            if fieldID != nil && !isField { bump("allowlistedIdentifierOnNonField") }
            if behindAXHiddenContainer { bump("nativeVisibleNodeBehindAXHiddenContainer") }
            if isField && fieldID == nil && parentFieldID != nil { bump("fieldWithAllowlistedParent") }
            if (fieldID != nil || isField), candidates.count < 48 {
                candidates.append(["depth": depth, "source": source, "classCategory": category, "role": roleCategory,
                    "fieldIdentity": fieldID ?? "none", "parentFieldIdentity": parentFieldID ?? "none",
                    "parentClassCategory": parentClass, "parentRole": parentRole,
                    "nativeIdentifierMatches": fieldID != nil && view?.identifier?.rawValue == fieldID,
                    "AXIdentifierMatches": fieldID != nil && element?.accessibilityIdentifier() == fieldID,
                    "nativeWindowMatches": view?.window === window,
                    "nativeIsHidden": view?.isHidden == true, "nativeIsHiddenOrHasHiddenAncestor": view?.isHiddenOrHasHiddenAncestor == true,
                    "nativeVisibleRectNonempty": view.map { !$0.visibleRect.isEmpty } ?? false,
                    "nativeVisibleBoundsIntersectionNonempty": view.map { !$0.visibleRect.intersection($0.bounds).isEmpty } ?? false,
                    "nativeFrame": view.map { [$0.frame.origin.x, $0.frame.origin.y, $0.frame.width, $0.frame.height] } ?? [],
                    "nativeBounds": view.map { [$0.bounds.width, $0.bounds.height] } ?? [],
                    "nativeVisibleRect": view.map { [$0.visibleRect.origin.x, $0.visibleRect.origin.y, $0.visibleRect.width, $0.visibleRect.height] } ?? [],
                    "parentBounds": view?.superview.map { [$0.bounds.width, $0.bounds.height] } ?? [],
                    "AXFrame": element.map { [$0.accessibilityFrame().origin.x, $0.accessibilityFrame().origin.y, $0.accessibilityFrame().width, $0.accessibilityFrame().height] } ?? [],
                    "publicIdentityMatches": publicFieldIdentityMatches(object),
                    "AXHidden": element?.isAccessibilityHidden() == true,
                    "AXIsElement": element?.isAccessibilityElement() == true,
                    "isFieldRoleOrNativeField": isField, "behindAXHiddenNonElementContainer": behindAXHiddenContainer])
            }
            if let element, element.isAccessibilityHidden() {
                bump("AXHiddenRejectedByControlTree")
                let canInspectNativeChildren = view != nil && !element.isAccessibilityElement()
                if hiddenRecords.count < 16 {
                    hiddenRecords.append(["reason": "AX-hidden", "depth": depth, "source": source,
                        "classCategory": category, "role": roleCategory, "parentClassCategory": parentClass,
                        "parentRole": parentRole, "nativeIsHidden": view?.isHidden == true,
                        "nativeIsHiddenOrHasHiddenAncestor": view?.isHiddenOrHasHiddenAncestor == true,
                        "nativeWindowMatches": view?.window === window, "AXHidden": true,
                        "AXIsElement": element.isAccessibilityElement(), "nativeChildCount": nativeChildren.count,
                        "nativeVisibleChildCount": nativeVisibleChildren.count,
                        "nativeChildrenInspectedForDiagnosticsOnly": canInspectNativeChildren,
                        "AXChildrenInspected": false])
                }
                // Observation only: non-element AX containers may wrap visible native controls.
                // Do not inspect their AX children, and never add these descendants to controlTree.
                guard canInspectNativeChildren else { return }
                if nativeChildren.count > maximumChildren { truncated = true }
                for child in nativeChildren.prefix(maximumChildren) {
                    visit(child, depth: depth + 1, source: "native", parentRole: roleCategory, parentClass: category,
                          parentFieldID: fieldID ?? parentFieldID, behindAXHiddenContainer: true)
                }
                return
            }
            if nativeChildren.count > maximumChildren { truncated = true }
            for child in nativeChildren.prefix(maximumChildren) {
                visit(child, depth: depth + 1, source: "native", parentRole: roleCategory, parentClass: category,
                      parentFieldID: fieldID ?? parentFieldID, behindAXHiddenContainer: behindAXHiddenContainer)
            }
            if let element, !behindAXHiddenContainer {
                let children = element.accessibilityChildren() ?? []
                bump("AXChildrenGetterInvoked")
                counts["AXReturnedChildCount", default: 0] += children.count
                if children.count > maximumChildren { truncated = true }
                for child in children.prefix(maximumChildren) {
                    visit(child, depth: depth + 1, source: "AX", parentRole: roleCategory, parentClass: category,
                          parentFieldID: fieldID ?? parentFieldID, behindAXHiddenContainer: behindAXHiddenContainer)
                }
                // Read-only alternate public, untyped AX hierarchies. Do not call
                // accessibilityChildrenInNavigationOrder: R4 proved its typed Swift
                // bridge traps on NSAccessibilitySegment. No census node is actionable.
                let alternatives: [(String, [Any])] = [
                    ("AXVisible", element.accessibilityVisibleChildren() ?? []),
                    ("AXContents", element.accessibilityContents() ?? []),
                    ("AXUnignored", NSAccessibility.unignoredChildrenForOnlyChild(from: object))
                ]
                for (route, nodes) in alternatives {
                    counts[route + "ReturnedChildCount", default: 0] += nodes.count
                    if nodes.count > maximumChildren { truncated = true }
                    for child in nodes.prefix(maximumChildren) {
                        visit(child, depth: depth + 1, source: route, parentRole: roleCategory, parentClass: category,
                              parentFieldID: fieldID ?? parentFieldID, behindAXHiddenContainer: false)
                    }
                }
            }
        }
        visit(root, depth: 0, source: "native", parentRole: "none", parentClass: "none", parentFieldID: nil, behindAXHiddenContainer: false)
        return ["exactRootAvailable": true, "visitedNodes": visitedCount, "edgeAttempts": attempts,
            "nodeLimit": maximumNodes, "depthLimit": maximumDepth, "childLimit": maximumChildren, "edgeAttemptLimit": maximumAttempts,
            "truncated": truncated, "counts": counts, "classCounts": classes, "roleCounts": roles,
            "nativeClassCounts": nativeClassCounts, "AXClassCounts": AXClassCounts,
            "nativeRoleCounts": nativeRoleCounts, "AXRoleCounts": AXRoleCounts,
            "minimalAXElementProtocolLookupAvailable": minimumProtocol != nil,
            "hiddenRejections": hiddenRecords, "AXBridgeSamples": bridgeRecords, "fieldCandidates": candidates,
            "buttonCandidates": buttonCandidates,
            "diagnosticOnly": true, "changesControlAcceptance": false, "fieldContentsInspected": false,
            "arbitraryTextSerialized": false, "AXHiddenContainerChildrenAreNativeOnly": true]
    }

    private func hasIdentifier(_ node: ControlNode, _ id: String) -> Bool {
        (node.object as? NSView)?.identifier?.rawValue == id || node.element?.accessibilityIdentifier() == id
    }
    private func isVisibleControl(_ node: ControlNode, in window: NSWindow) -> Bool {
        if let view = node.object as? NSView {
            return view.window === window && !view.isHiddenOrHasHiddenAncestor && !view.visibleRect.intersection(view.bounds).isEmpty
        }
        guard let element = node.element, !element.isAccessibilityHidden() else { return false }
        let frame = element.accessibilityFrame()
        return !frame.isEmpty && frame.intersects(window.frame)
    }
    private func fieldCandidates(_ id: String, in tree: ControlTree) -> [ControlNode] {
        guard !tree.truncated else { return [] }
        let fields = tree.nodes.filter { node in
            node.object is NSTextField || node.element?.accessibilityRole() == .textField || node.element?.accessibilityRole() == .textArea
        }
        let identified = fields.filter { hasIdentifier($0, id) }
        if !identified.isEmpty {
            let native = identified.filter { $0.object is NSTextField }
            return native.isEmpty ? identified : native
        }
        guard let caption = Self.publicFieldIdentities.first(where: { $0.id == id })?.caption else { return [] }
        // R4 runtime evidence confirmed these exact native placeholders. Never use
        // virtual+native duplicates, positional order or arbitrary displayed text.
        let fallback = fields.filter { ($0.object as? NSTextField)?.placeholderString == caption }
        return fallback.count == 1 ? fallback : []
    }
    private func controlMatches(_ id: String, in window: NSWindow) -> [ControlNode] {
        fieldCandidates(id, in: controlTree(in: window)).filter { isVisibleControl($0, in: window) }
    }
    private func revealFieldIfNeeded(_ id: String, in window: NSWindow) async throws {
        guard controlMatches(id, in: window).isEmpty else { return }
        let candidates = fieldCandidates(id, in: controlTree(in: window))
        guard candidates.count == 1, let field = candidates[0].object as? NSTextField,
              field.window === window, !field.isHiddenOrHasHiddenAncestor,
              let scroll = field.enclosingScrollView, scroll.window === window,
              !scroll.isHiddenOrHasHiddenAncestor, let document = scroll.documentView,
              field === document || field.isDescendant(of: document),
              let root = window.contentView, document === root || document.isDescendant(of: root),
              !scroll.visibleRect.intersection(scroll.bounds).isEmpty else { return }
        // Move the public viewport, not the field value/focus while it is offscreen.
        let target = field.convert(field.bounds, to: document)
        _ = document.scrollToVisible(target.insetBy(dx: -8, dy: -8))
        scroll.reflectScrolledClipView(scroll.contentView)
        window.contentView?.layoutSubtreeIfNeeded()
        try await pause()
        try check("input-scroll-reveals-" + id, interactiveWindow() === window && controlMatches(id, in: window).count == 1)
        actions.append("scroll.public-field-into-viewport." + id)
    }
    private func find<T: NSView>(_ id: String, as type: T.Type) -> T? {
        let window: NSWindow?
        if id.hasPrefix("lifecycle.transfers.") {
            let panels = NSApp.windows.filter { $0.isVisible && $0 is NSPanel }
            window = panels.count == 1 ? panels[0] : nil
        } else { window = interactiveWindow() }
        guard let window else { return nil }
        let tree = controlTree(in: window)
        guard !tree.truncated else { return nil }
        let matches = tree.nodes.filter { hasIdentifier($0, id) && isVisibleControl($0, in: window) }.compactMap { $0.object as? T }
        return matches.count == 1 ? matches[0] : nil
    }
    private func click(_ id: String) async throws {
        if id == "host.save" { try await pressVisibleButton("保存"); return }
        if id == "host.edit" { try await hostContextCommand("编辑…"); return }
        if id == "session.new" { try await hostContextCommand("在新会话打开"); return }
        try await wait(id) { self.find(id, as: NSButton.self)?.isEnabled == true }
        guard let button = find(id, as: NSButton.self) else { throw Failure.missing(id) }
        button.performClick(nil)
        actions.append("click." + (id.hasPrefix("folder.") && UUID(uuidString: String(id.dropFirst(7))) != nil ? "folder.row" : id))
        try await pause()
    }
    private func type(_ id: String, _ text: String) async throws {
        if Self.diagnosticFieldIDs.contains(id) {
            try await wait("host-editor-owner") { self.delegate.mainWindow?.attachedSheet is NativeOwnedSheetWindow }
            writeControlDiagnostics(stage: "before-input")
        }
        let owner = try require(interactiveWindow(), "input-owner")
        try await revealFieldIfNeeded(id, in: owner)
        try await wait(id) { self.interactiveWindow() === owner && self.controlMatches(id, in: owner).count == 1 }
        guard interactiveWindow() === owner, let node = controlMatches(id, in: owner).first else { throw Failure.missing(id) }
        if let field = node.object as? NSTextField {
            guard field.isEditable, field.isEnabled, field.window === owner, owner.makeFirstResponder(field) else { throw Failure.check("input-native-focus") }
            // currentEditor, not fieldEditor(true,...), proves AppKit actually began editing this field.
            try await wait("input-native-field-editor") { field.currentEditor() is NSTextView && owner.firstResponder === field.currentEditor() }
            guard let editor = field.currentEditor() as? NSTextView, owner.firstResponder === editor else { throw Failure.missing("input-field-editor") }
            editor.selectAll(nil); editor.insertText(text, replacementRange: NSRange(location: NSNotFound, length: 0))
            guard owner.makeFirstResponder(nil) else { throw Failure.check("input-native-commit") }
            // Do not send a SwiftUI TextField action: its public onSubmit can save the form.
            // Ending its real field editor commits through the control's normal input binding.
            try await pause()
            try await wait("input-keeps-committed-field") {
                self.controlMatches(id, in: owner).first.map { committed in
                    if id == "host.password" || committed.object is NSSecureTextField { return true }
                    return (committed.object as? NSTextField)?.stringValue == text
                } == true
            }
            if id != "host.password" && !(field is NSSecureTextField) {
                let committed = controlMatches(id, in: owner)
                try check("input-committed-" + id, committed.count == 1 &&
                    (committed.first?.object as? NSTextField)?.stringValue == text)
            }
            actions.append("type.native-field-editor." + id)
        } else {
            guard let element = node.element, element.isAccessibilityEnabled() else { throw Failure.check("input-AX-disabled") }
            let canSetValue = element.isAccessibilitySelectorAllowed(#selector(NSAccessibilityProtocol.setAccessibilityValue(_:)))
            let canFocus = element.isAccessibilitySelectorAllowed(#selector(NSAccessibilityProtocol.setAccessibilityFocused(_:)))
            if canFocus { element.setAccessibilityFocused(true); try await pause() }
            guard interactiveWindow() === owner else { throw Failure.check("input-AX-owner-changed") }
            if canFocus, element.isAccessibilityFocused(), let editor = owner.firstResponder as? NSTextView, editor.isFieldEditor {
                editor.selectAll(nil); editor.insertText(text, replacementRange: NSRange(location: NSNotFound, length: 0))
                actions.append("type.AX-focused-field-editor." + id)
            } else {
                guard canSetValue else { throw Failure.check("input-AX-value-not-settable") }
                element.setAccessibilityValue(text)
                actions.append("type.AX-set-value." + id)
            }
            guard owner.makeFirstResponder(nil) else { throw Failure.check("input-AX-commit") }
            try await pause()
            if id != "host.password" {
                let committed = controlMatches(id, in: owner)
                try check("input-committed-" + id, committed.count == 1 && (committed[0].element?.accessibilityValue() as? String) == text)
            }
        }
        try check("input-keeps-current-owner-" + id, interactiveWindow() === owner)
        actions.append("type." + id)
    }
    private func buttonMatches(title: String, in window: NSWindow) -> [ControlNode] {
        let tree = controlTree(in: window)
        guard !tree.truncated else { return [] }
        let native = tree.nodes.filter { node in
            (node.object as? NSButton)?.title == title && isVisibleControl(node, in: window)
        }
        if !native.isEmpty { return native }
        return tree.nodes.filter { node in
            guard isVisibleControl(node, in: window), let element = node.element, element.accessibilityRole() == .button else { return false }
            // Read only button identity, never a text/body node. Only the exact fixed
            // requested title is matched; duplicate buttons are a failure, not first-wins.
            return element.accessibilityLabel() == title || element.accessibilityTitle() == title
        }
    }
    private func pressVisibleButton(_ title: String, owner expectedOwner: NSWindow? = nil) async throws {
        let owner = try require(expectedOwner ?? interactiveWindow(), "button-owner")
        if Self.diagnosticButtonTitles.contains(title) { writeControlDiagnostics(stage: "before-button", window: owner) }
        try await wait("visible-button-" + title) {
            guard self.interactiveWindow() === owner else { return false }
            let matches = self.buttonMatches(title: title, in: owner)
            return matches.count == 1 && ((matches[0].object as? NSButton)?.isEnabled == true || matches[0].element?.isAccessibilityEnabled() == true)
        }
        guard interactiveWindow() === owner, let node = buttonMatches(title: title, in: owner).first else { throw Failure.missing("visible-button-" + title) }
        if let button = node.object as? NSButton {
            guard button.isEnabled else { throw Failure.check("button-native-disabled") }
            button.performClick(nil)
        } else {
            guard let element = node.element, element.isAccessibilityEnabled(),
                  element.isAccessibilitySelectorAllowed(#selector(NSAccessibilityProtocol.accessibilityPerformPress)),
                  element.accessibilityPerformPress() else { throw Failure.check("button-AX-press-not-supported") }
        }
        actions.append("press-visible." + title); try await pause()
    }
    private func hostContextCommand(_ title: String) async throws {
        let table = try await nativeHostTable()
        guard let window = table.window else { throw Failure.missing("vault-table-window") }
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        let point = table.convert(NSPoint(x: 60, y: table.rect(ofRow: 0).midY), to: nil)
        let event = try require(NSEvent.mouseEvent(with: .rightMouseDown, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber, context: nil, eventNumber: 1, clickCount: 1, pressure: 1), "vault-context-event")
        guard let menu = table.menu(for: event), let item = menu.items.first(where: { $0.title == title }), let action = item.action,
              NSApp.sendAction(action, to: item.target, from: item) else { throw Failure.missing("vault-context-" + title) }
        actions.append("vault-context." + title); try await pause()
    }
    private func popup(_ id: String, value: String) async throws {
        try await wait(id) { self.find(id, as: NSPopUpButton.self) != nil }
        guard let control = find(id, as: NSPopUpButton.self), let item = control.itemArray.first(where: { $0.representedObject as? String == value }) else { throw Failure.missing(id) }
        control.select(item); control.sendAction(control.action, to: control.target)
        actions.append("select." + id)
        try await pause()
    }
    private func selectFirstHost() async throws {
        try await wait("hosts.table") { self.find("vault.hosts.table", as: NSTableView.self)?.numberOfRows ?? 0 > 0 }
        let table = try await nativeHostTable()
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        try await pause()
    }
    private func nativeHostTable() async throws -> NSTableView {
        try await wait("hosts.table") { self.find("vault.hosts.table", as: NSTableView.self)?.numberOfRows ?? 0 > 0 }
        guard let candidate = find("vault.hosts.table", as: NSTableView.self), let content = candidate.window?.contentView else { throw Failure.missing("hosts.table") }
        let row = candidate.rowView(atRow: 0, makeIfNecessary: true)
        // NSView.hitTest receives coordinates in its superview, not its own
        // flipped coordinates. A terminal below the table made the old check hit
        // the opposite half of the window after layout changed.
        let point = candidate.convert(NSPoint(x: 60, y: row?.frame.midY ?? candidate.rect(ofRow: 0).midY), to: content.superview)
        var hit = content.hitTest(point)
        while let view = hit {
            if let table = view as? NSTableView { return table }
            hit = view.superview
        }
        throw Failure.missing("hittable-host-table")
    }
    private func doubleClickFirstHost() async throws {
        let table = try await nativeHostTable()
        guard let window = table.window else { throw Failure.missing("hosts.table") }
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(table)
        table.layoutSubtreeIfNeeded()
        let row = table.rowView(atRow: 0, makeIfNecessary: true)
        let local = NSPoint(x: table.bounds.minX + 60, y: row?.frame.midY ?? table.rect(ofRow: 0).midY)
        try check("double-click-local-row", table.row(at: local) == 0)
        let point = table.convert(local, to: nil)
        let time = ProcessInfo.processInfo.systemUptime
        for click in 1...2 {
            guard let down = NSEvent.mouseEvent(with: .leftMouseDown, location: point, modifierFlags: [], timestamp: time + Double(click) * 0.03, windowNumber: window.windowNumber, context: nil, eventNumber: click * 2, clickCount: click, pressure: 1),
                  let up = NSEvent.mouseEvent(with: .leftMouseUp, location: point, modifierFlags: [], timestamp: time + Double(click) * 0.03 + 0.01, windowNumber: window.windowNumber, context: nil, eventNumber: click * 2 + 1, clickCount: click, pressure: 0) else { throw Failure.missing("double-click-pair") }
            // Dispatch from the App event loop so NSApplication.currentEvent is the actual
            // down event. Direct mouseDown calls retain a stale currentEvent after sheets.
            NSApp.postEvent(down, atStart: false)
            NSApp.postEvent(up, atStart: false)
            try await Task.sleep(for: .milliseconds(60))
        }
        actions.append("doubleClick.hosts.table")
        try await pause()
    }
    private func wait(_ name: String, predicate: () -> Bool) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 8
        while !predicate() {
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                writeWaitDiagnostics(for: name)
                throw Failure.timeout(name)
            }
            try await Task.sleep(for: .milliseconds(25))
        }
    }
    private func writeWaitDiagnostics(for identifier: String) {
        if Self.diagnosticFieldIDs.contains(identifier) || identifier.hasPrefix("visible-button-") {
            writeControlDiagnostics(stage: "wait-timeout")
        }
    }
    private func writeControlDiagnostics(stage: String, window supplied: NSWindow? = nil) {
        // This is not an AX dump. No value, placeholder, body, arbitrary label,
        // title, identifier, class name or description is ever serialized.
        guard controlDiagnosticSequence < 48 else { return }
        controlDiagnosticSequence += 1
        let window = supplied ?? interactiveWindow()
        let tree = window.map { controlTree(in: $0) } ?? ControlTree()
        let census = window.map { controlDiagnosticCensus(in: $0) } ?? ["exactRootAvailable": false]
        var records: [[String: Any]] = []
        for node in tree.nodes {
            let field = Self.diagnosticFieldIDs.first { hasIdentifier(node, $0) }
            var button: String?
            button = Self.diagnosticButtonTitles.first { title in
                (node.object as? NSButton)?.title == title ||
                    (node.element?.accessibilityRole() == .button &&
                     (node.element?.accessibilityLabel() == title || node.element?.accessibilityTitle() == title))
            }
            guard let identity = field ?? button else { continue }
            let role: String
            switch node.element?.accessibilityRole() {
            case .some(.textField): role = "AXTextField"
            case .some(.textArea): role = "AXTextArea"
            case .some(.button): role = "AXButton"
            case .some(.group): role = "AXGroup"
            case .none: role = "none"
            default: role = "other"
            }
            let fieldControl = node.object as? NSTextField
            let element = node.element
            records.append(["identity": identity, "matchKind": field != nil ? "identifier" : "fixed-button-title",
                "nativeButtonTitleMatches": button != nil && (node.object as? NSButton)?.title == button,
                "nativeButtonEnabled": (node.object as? NSButton)?.isEnabled == true,
                "nativeIdentifierMatches": (node.object as? NSView)?.identifier?.rawValue == field && field != nil,
                "accessibilityIdentifierMatches": element?.accessibilityIdentifier() == field && field != nil,
                "role": role, "nativeTextField": fieldControl != nil, "nativeSecureField": node.object is NSSecureTextField,
                "reachedNatively": node.reachedNatively, "reachedByAccessibility": node.reachedByAccessibility,
                "visible": window.map { isVisibleControl(node, in: $0) } ?? false,
                "enabled": element?.isAccessibilityEnabled() == true,
                "nativeEditable": fieldControl?.isEditable == true,
                "nativeFieldEditorActive": fieldControl?.currentEditor() != nil,
                "valueSettable": element?.isAccessibilitySelectorAllowed(#selector(NSAccessibilityProtocol.setAccessibilityValue(_:))) == true,
                "focusSettable": element?.isAccessibilitySelectorAllowed(#selector(NSAccessibilityProtocol.setAccessibilityFocused(_:))) == true,
                "pressAllowed": element?.isAccessibilitySelectorAllowed(#selector(NSAccessibilityProtocol.accessibilityPerformPress)) == true])
        }
        let result: [String: Any] = ["stage": stage, "sequence": controlDiagnosticSequence,
            "mainWindowVisible": delegate.mainWindow?.isVisible == true,
            "hasAttachedSheet": delegate.mainWindow?.attachedSheet != nil,
            "interactiveWindowVisible": window?.isVisible == true,
            "interactiveWindowIsKey": window?.isKeyWindow == true,
            "interactiveMatchesAppKeyWindow": window != nil && NSApp.keyWindow === window,
            "interactiveIsMainWindow": window != nil && window === delegate.mainWindow,
            "interactiveIsOwnedSheet": window is NativeOwnedSheetWindow,
            "interactiveHasAttachedSheet": window?.attachedSheet != nil,
            "interactiveWindowIsCurrentOwner": window != nil && window === interactiveWindow(),
            "windowNumber": window?.windowNumber ?? 0,
            "windowFrameSize": window.map { [$0.frame.width, $0.frame.height] } ?? [],
            "contentFrameSize": window?.contentView.map { [$0.frame.width, $0.frame.height] } ?? [],
            "contentBoundsSize": window?.contentView.map { [$0.bounds.width, $0.bounds.height] } ?? [],
            "rootNativeWindowMatches": tree.rootNativeWindowMatches,
            "rootAXWindowIsParent": tree.rootAXWindowIsParent,
            "rootAXTopLevelIsParent": tree.rootAXTopLevelIsParent,
            "traversedNodes": tree.visitedNodes, "acceptedNodes": tree.nodes.count, "nodeLimit": 1024, "depthLimit": 36, "childLimit": 128,
            "truncated": tree.truncated, "rejectedHidden": tree.rejectedHidden,
            "rejectedForeignOwner": tree.rejectedForeignOwner, "rejectedApplicationOrMenu": tree.rejectedApplicationOrMenu,
            "fieldContentsInspected": false, "arbitraryTextSerialized": false, "controls": records,
            "discoveryCensus": census]
        guard let data = try? JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys]) else { return }
        let filename = String(format: "control-diagnostics-%02d.json", controlDiagnosticSequence)
        try? data.write(to: options.directory.appendingPathComponent(filename), options: .atomic)
    }
    private func pause() async throws { try await Task.sleep(for: .milliseconds(100)) }
    private func check(_ name: String, _ condition: Bool) throws {
        checks.append(Check(name: name, passed: condition))
        guard condition else { throw Failure.check(name) }
    }
    private func capture(_ name: String) throws {
        guard let window = delegate.mainWindow,
              let view = (window.attachedSheet ?? window).contentView,
              let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw Failure.missing("window-capture") }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        guard let data = bitmap.representation(using: .png, properties: [:]) else { throw Failure.missing("window-capture") }
        try data.write(to: options.directory.appendingPathComponent(name), options: .atomic)
    }
    private func finish(success: Bool, failure: String?) throws {
        let report = Report(kind: "HostProbe-native-GUI", phase: options.phase, passed: success, checks: checks, actions: actions, failureCode: failure, productRuntimeVerified: false,
            scope: options.phase == "desktop-cua" ? "Isolated desktop ready/finish lifecycle only; interactions not asserted; SSH/SFTP use network substitutes." : nil)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(report)
        try data.write(to: options.directory.appendingPathComponent("smoke-" + options.phase + ".json"), options: .atomic)
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data("\n".utf8))
    }
}

@MainActor private struct DismissSmokePresentation: Identifiable { let id = UUID() }
@MainActor private final class DismissSmokeState: ObservableObject {
    @Published var presentation: DismissSmokePresentation?
    @Published var draft = ""
    @Published var allowsDismiss = false
    @Published var attempts = 0
    func attemptDismiss() -> Bool { attempts += 1; return allowsDismiss }
}
private struct DismissSmokeAnchor: View {
    @ObservedObject var state: DismissSmokeState
    var body: some View {
        Color.clear.nativeSheet(item: $state.presentation, onAttemptDismiss: { state.attemptDismiss() }) { _ in
            VStack(alignment: .leading, spacing: 12) {
                Text("Synthetic unsaved editor").font(.headline)
                NativeField(placeholder: "Public fixture draft", id: "dismiss.fixture.draft", text: $state.draft).frame(width: 320, height: 26)
                Text("Cmd+W / Escape uses the close hook; no host configuration is changed.").font(.caption)
            }.padding(24)
        }
    }
}

@MainActor private final class PressureWeakTerminal {
    weak var value: NativeTerminalView?
    init(_ value: NativeTerminalView) { self.value = value }
}

/// Synthetic drag metadata exercises the registered NSTableView destination callbacks with
/// an actual NSPasteboard file-URL payload. It is not a claim of human Finder drag acceptance.
@MainActor private final class FilesProbeDraggingInfo: NSObject, NSDraggingInfo {
    let draggingPasteboard: NSPasteboard
    let draggingDestinationWindow: NSWindow?
    init(pasteboard: NSPasteboard, window: NSWindow?) { draggingPasteboard = pasteboard; draggingDestinationWindow = window }
    var draggingSourceOperationMask: NSDragOperation { .copy }
    var draggingLocation: NSPoint { .zero }
    var draggedImageLocation: NSPoint { .zero }
    nonisolated var draggedImage: NSImage? { nil }
    var draggingSource: Any? { nil }
    var draggingSequenceNumber: Int { 1 }
    var draggingFormation: NSDraggingFormation = .none
    var animatesToDestination = false
    var numberOfValidItemsForDrop = 1
    var springLoadingHighlight: NSSpringLoadingHighlight { .none }
    func slideDraggedImage(to screenPoint: NSPoint) {}
    override nonisolated func namesOfPromisedFilesDropped(atDestination dropDestination: URL) -> [String]? { nil }
    func enumerateDraggingItems(options enumOpts: NSDraggingItemEnumerationOptions, for view: NSView?, classes classArray: [AnyClass], searchOptions: [NSPasteboard.ReadingOptionKey: Any], using block: (NSDraggingItem, Int, UnsafeMutablePointer<ObjCBool>) -> Void) {}
    func resetSpringLoading() {}
}
#endif
