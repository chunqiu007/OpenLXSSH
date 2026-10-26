#if HOST_PROBE
import AppKit
import Foundation
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
                  ["exercise", "reopen", "sessions", "sessions-exit", "files-local", "transport-config", "security-sheets", "security", "security-read", "security-cleanup"].contains(arguments[3]) else { throw Failure.invalidArguments }
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
            else if options.phase == "reopen" { try await verifyRelaunch() }
            else if options.phase == "security-sheets" { try await securitySheets() }
            else if options.phase == "sessions" || options.phase == "sessions-exit" { try await sessionExercise() }
            else if options.phase == "transport-config" { try await transportConfiguration() }
            else if options.phase == "files-local" { try await filesLocalExercise() }
            else { try await securityExercise() }
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
        if case .opened(let request, _) = model.connectionNotice { try check("reuse-route", request.mode == .reuse && request.hostID == model.hosts[0].id) }
        else { throw Failure.check("reuse-route") }
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

    private func sessionExercise() async throws {
        try await click("host.add")
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
        try await doubleClickFirstHost()
        try check("double-click-reuses-valid-tab", model.sessions.tabs.count == 1 && model.sessions.selectedTabID == first.id)
        try await click("session.new")
        try await wait("independent-session-tab") { self.model.sessions.tabs.count == 2 && self.model.sessions.tabs[1].driver != nil }
        try await click("tab.select." + first.id.uuidString)
        try check("terminal-instance-retained", first.driver?.terminal === view && !view.isHidden)
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
        try await click("terminal.disconnect")
        try await click("terminal.reconnect")
        try await wait("manual-new-generation") { driver.token?.generation == (generation ?? 0) + 1 }
        try check("reconnect-retains-terminal", driver.terminal === view)
        try check("no-auth-event-no-history", try await model.repository.securityMetadata().hosts.allSatisfy { $0.lastConnectedAt == nil })
        driver.showAuthentication()
        try await click("terminal.authenticate")
        try await click("authentication.cancel")
        try await wait("cancel-invalidates-request") { self.delegate.mainWindow?.attachedSheet == nil && first.state == .disconnected(nil) }
        try await click("tab.close." + first.id.uuidString)
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

    private func filesLocalExercise() async throws {
        guard let connector = model.files.connector as? LocalFilesProbeConnector else { throw Failure.check("local-files-fixture-required") }
        let root = options.directory.appendingPathComponent("LocalFilesFixture")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("原始\n目录"), withIntermediateDirectories: false)
        try Data("keep-target".utf8).write(to: root.appendingPathComponent("target"))
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("link"), withDestinationURL: root.appendingPathComponent("target"))
        let startupCount = await connector.count
        try check("files-startup-hidden-no-connect", !model.files.visible && startupCount == 0)
        try await click("host.add")
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
        try await click("host.add")
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
            try await click("host.add")
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
            try await click("host.add")
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

    private func interactiveWindow() -> NSWindow? {
        guard var window = delegate.mainWindow else { return nil }
        while let sheet = window.attachedSheet { window = sheet }
        return window
    }
    private func find<T: NSView>(_ id: String, as type: T.Type) -> T? {
        func visit(_ view: NSView) -> T? {
            if view.identifier?.rawValue == id, let value = view as? T { return value }
            for child in view.subviews { if let value = visit(child) { return value } }
            return nil
        }
        if let view = interactiveWindow()?.contentView { return visit(view) }
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
        let table = try await nativeHostTable()
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        try await pause()
    }
    private func nativeHostTable() async throws -> NSTableView {
        try await wait("hosts.table") { self.find("hosts.table", as: NSTableView.self)?.numberOfRows ?? 0 > 0 }
        guard let candidate = find("hosts.table", as: NSTableView.self), let content = candidate.window?.contentView else { throw Failure.missing("hosts.table") }
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
