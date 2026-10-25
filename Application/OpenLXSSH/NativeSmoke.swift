#if HOST_PROBE
import AppKit
import Foundation
import OpenLXSSHCore

/// HostProbe-only in-process GUI exercise. All mutations go through rendered native controls
/// and their target/action paths, and all files are confined to a marked temporary test root.
@MainActor final class NativeSmoke {
    struct Options {
        let directory: URL
        let phase: String
        init?(_ arguments: [String]) throws {
            guard arguments.contains("--self-test-data-dir") else {
                guard !arguments.contains(where: { $0.hasPrefix("--self-test") }) else { throw Failure.invalidArguments }
                return nil
            }
            guard arguments.count == 4, arguments[0] == "--self-test-data-dir", arguments[2] == "--self-test-phase",
                  ["exercise", "reopen"].contains(arguments[3]) else { throw Failure.invalidArguments }
            directory = URL(fileURLWithPath: arguments[1], isDirectory: true)
            phase = arguments[3]
            _ = try AppDataLocation.isolated(directory).databaseDirectory()
            guard try String(contentsOf: directory.appendingPathComponent(".openlxssh-app-smoke"), encoding: .utf8) == "OpenLXSSH isolated GUI smoke\n" else {
                throw Failure.invalidArguments
            }
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
    }
    let delegate: AppDelegate
    let options: Options
    var model: AppModel { delegate.model }
    private var checks: [Check] = []
    private var actions: [String] = []
    init(delegate: AppDelegate, options: Options) { self.delegate = delegate; self.options = options }

    func run() async {
        do {
            try await wait("initial-load") { self.model.didLoad && !self.model.isLoading }
            try check("native-main-window", delegate.mainWindow?.isVisible == true)
            try check("startup-no-session", model.connectionNotice == nil)
            if options.phase == "exercise" { try await exercise() }
            else { try await verifyRelaunch() }
            try finish(success: true, failure: nil)
            // Leave this Swift MainActor job before AppKit enters its termination loop.
            // This mirrors a normal menu action rather than nesting terminate inside a task.
            RunLoop.main.perform {
                MainActor.assumeIsolated { NSApp.terminate(nil) }
            }
        } catch {
            // Only static scenario labels are emitted. Never serialize arbitrary Error descriptions.
            let code: String
            switch error {
            case Failure.timeout(let label): code = "timeout." + label
            case Failure.check(let label): code = "check." + label
            case Failure.missing(let label): code = "missing." + label
            default: code = "smoke.failed"
            }
            try? finish(success: false, failure: code)
            exit(1)
        }
    }

    private func exercise() async throws {
        try check("fresh-store-empty", model.hosts.isEmpty && model.folders.isEmpty)
        try await click("folder.add")
        try await type("folder.name", "GUI 文件夹")
        try await click("folder.save")
        try await wait("folder-created") { self.model.folders.count == 1 && self.delegate.mainWindow?.attachedSheet == nil }
        let folder = model.folders[0]
        try await click("folder." + folder.id.uuidString)
        try await click("host.add")
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
        if case .transportUnavailable(let request) = model.connectionNotice { try check("reuse-route", request.mode == .reuse && request.hostID == model.hosts[0].id) }
        else { throw Failure.check("reuse-route") }
        try await click("session.new")
        if case .transportUnavailable(let request) = model.connectionNotice { try check("new-route", request.mode == .newSession) }
        else { throw Failure.check("new-route") }
        try check("route-never-marks-connected", model.hosts.allSatisfy { $0.lastConnectedAt == nil })
        try capture("unavailable-route.png")
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
        try await click("host.add")
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

    private func windows() -> [NSWindow] {
        guard let window = delegate.mainWindow else { return [] }
        return [window.attachedSheet, window].compactMap { $0 }
    }
    private func find<T: NSView>(_ id: String, as type: T.Type) -> T? {
        func visit(_ view: NSView) -> T? {
            if view.identifier?.rawValue == id, let value = view as? T { return value }
            for child in view.subviews { if let value = visit(child) { return value } }
            return nil
        }
        for window in windows() { if let view = window.contentView, let value = visit(view) { return value } }
        return nil
    }
    private func click(_ id: String) async throws {
        try await wait(id) { self.find(id, as: NSButton.self)?.isEnabled == true }
        guard let button = find(id, as: NSButton.self) else { throw Failure.missing(id) }
        button.performClick(nil)
        actions.append("click." + (id.hasPrefix("folder.") && UUID(uuidString: String(id.dropFirst(7))) != nil ? "folder.row" : id))
        try await pause()
    }
    private func type(_ id: String, _ text: String) async throws {
        try await wait(id) { self.find(id, as: NSTextField.self) != nil }
        guard let field = find(id, as: NSTextField.self), let window = field.window else { throw Failure.missing(id) }
        window.makeFirstResponder(field)
        guard let editor = window.fieldEditor(true, for: field) as? NSTextView else { throw Failure.missing(id) }
        editor.selectAll(nil); editor.insertText(text, replacementRange: NSRange(location: NSNotFound, length: 0))
        window.makeFirstResponder(nil)
        field.sendAction(field.action, to: field.target)
        actions.append("type." + id)
        try await pause()
    }
    private func popup(_ id: String, value: String) async throws {
        try await wait(id) { self.find(id, as: NSPopUpButton.self) != nil }
        guard let control = find(id, as: NSPopUpButton.self), let item = control.itemArray.first(where: { $0.representedObject as? String == value }) else { throw Failure.missing(id) }
        control.select(item); control.sendAction(control.action, to: control.target)
        actions.append("select." + id)
        try await pause()
    }
    private func selectFirstHost() async throws {
        try await wait("hosts.table") { self.find("hosts.table", as: NSTableView.self)?.numberOfRows ?? 0 > 0 }
        guard let table = find("hosts.table", as: NSTableView.self) else { throw Failure.missing("hosts.table") }
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        try await pause()
    }
    private func doubleClickFirstHost() async throws {
        guard let table = find("hosts.table", as: NSTableView.self), let window = table.window else { throw Failure.missing("hosts.table") }
        let point = table.convert(NSPoint(x: 60, y: table.rect(ofRow: 0).midY), to: nil)
        guard let down = NSEvent.mouseEvent(with: .leftMouseDown, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber, context: nil, eventNumber: 1, clickCount: 2, pressure: 1) else { throw Failure.missing("double-click") }
        guard let up = NSEvent.mouseEvent(with: .leftMouseUp, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime + 0.01, windowNumber: window.windowNumber, context: nil, eventNumber: 2, clickCount: 2, pressure: 0) else { throw Failure.missing("double-click-up") }
        // NSTableView tracks until mouseUp. Queue the matching event before entering tracking.
        NSApp.postEvent(up, atStart: true)
        table.mouseDown(with: down)
        actions.append("doubleClick.hosts.table")
        try await pause()
    }
    private func wait(_ name: String, predicate: () -> Bool) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 8
        while !predicate() {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.timeout(name) }
            try await Task.sleep(for: .milliseconds(25))
        }
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
        let report = Report(kind: "HostProbe-native-GUI", phase: options.phase, passed: success, checks: checks, actions: actions, failureCode: failure, productRuntimeVerified: false)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(report)
        try data.write(to: options.directory.appendingPathComponent("smoke-" + options.phase + ".json"), options: .atomic)
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data("\n".utf8))
    }
}
#endif
