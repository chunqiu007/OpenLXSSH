#if HOST_PROBE
import AppKit
import CryptoKit
import Darwin
import Foundation
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust
import Security

/// Hard-denied credential namespace: .none key import must never touch a real/test Keychain.
actor AppRealNoCredentials: CredentialAccess {
    let namespace: UUID
    private(set) var forbiddenCalls = 0
    init(namespace: UUID) { self.namespace = namespace }
    func save(_ secret: OpenLXSSHSecurity.SecretBytes, as reference: OpenLXSSHSecurity.CredentialReference, authorization: RememberAuthorization) async -> CredentialSaveResult { forbiddenCalls += 1; return .notAuthorized }
    func read(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialReadResult { forbiddenCalls += 1; return .manualEntryRequired(.denied) }
    func deleteExact(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialDeleteResult { forbiddenCalls += 1; return .retryRequired(.denied) }
    func close() async throws {}
}
struct AppRealSystemScanner: HostKeyScanning {
    let seconds: Int
    func scan(_ host: HostIdentity) async throws -> [HostKeyCandidate] { try await SystemHostKeyScanner(timeoutSeconds: seconds).scan(host) }
}
actor AppRealFilesFacts {
    private(set) var connectionAttempts = 0, returnedProductionServices = 0, lists = 0, closedServices = 0
    private(set) var latestListRawNames: [String] = []
    private(set) var bindings: [String] = []
    func attempted() { connectionAttempts += 1 }
    func connected(_ service: LibSSH2FileService) { returnedProductionServices += 1; if let id = service.serverBinding { bindings.append(id.uuidString) } }
    func listed(_ values: [DirectoryEntry]) { lists += 1; latestListRawNames = values.map { $0.name.bytes.base64EncodedString() } }
    func closed() { closedServices += 1 }
}
/// Observation only. All production connector arguments, trust callbacks and bytes pass unchanged.
actor AppRealFilesConnector: FilesConnecting {
    let production: LibSSH2FilesConnector, facts: AppRealFilesFacts
    init(_ production: LibSSH2FilesConnector, facts: AppRealFilesFacts) { self.production = production; self.facts = facts }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken, trust: @escaping FileHostTrustHandler,
                 keyboard: @escaping FilesKeyboardHandler, isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        await facts.attempted()
        let service = try await production.connect(request: request, input: input, token: token, trust: trust, keyboard: keyboard, isCurrent: isCurrent)
        guard let native = service as? LibSSH2FileService else { await service.close(); throw AppRealIntegrationFailure.failedCheck }
        await facts.connected(native)
        return AppRealObservedFiles(native, facts: facts)
    }
}
actor AppRealObservedFiles: RemoteFileService {
    nonisolated let native: LibSSH2FileService
    let facts: AppRealFilesFacts
    nonisolated var capabilities: FileServiceCapabilities { native.capabilities }
    nonisolated var serverBinding: UUID? { native.serverBinding }
    private var closed = false
    init(_ native: LibSSH2FileService, facts: AppRealFilesFacts) { self.native = native; self.facts = facts }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { let entries = try await native.list(path, token: token); await facts.listed(entries); return entries }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await native.lstat(path, token: token) }
    func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await native.fstat(handle, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await native.open(path, mode: mode, token: token) }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await native.read(handle, maxBytes: maxBytes, token: token) }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await native.write(handle, data: data, token: token) }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await native.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await native.closeHandle(handle) }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { try await native.mkdir(path, token: token) }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await native.rename(source, to: destination, mode: mode, token: token) }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await native.commit(source, to: destination, request: request, token: token) }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { try await native.remove(path, directory: directory, token: token) }
    nonisolated func cancel() { native.cancel() }
    func close() async { await native.close(); if !closed { closed = true; await facts.closed() } }
}

/// Owns only a freshly created canonical temp namespace. No caller-provided app store path.
final class AppRealOwnedStore: @unchecked Sendable {
    let url: URL
    private let parent: Int32, held: Int32, name: String, device: dev_t, inode: ino_t
    init(runID: String) throws {
        let temporary = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
        parent = open(temporary.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw AppRealIntegrationFailure.isolation }
        name = "OpenLXSSH-AppTests-real-" + runID
        guard mkdirat(parent, name, 0o700) == 0 else { Darwin.close(parent); throw AppRealIntegrationFailure.isolation }
        url = temporary.appendingPathComponent(name, isDirectory: true)
        held = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard held >= 0 else { Darwin.close(parent); throw AppRealIntegrationFailure.isolation }
        var info = stat()
        do {
            try AppFileSecurity.directory(held)
            guard fstat(held, &info) == 0 else { throw AppRealIntegrationFailure.isolation }
            try AppRealPrivateInput.write(Data(("OpenLXSSH real fixture " + runID + "\n").utf8), parent: held, name: ".openlxssh-real-fixture")
        } catch { Darwin.close(held); Darwin.close(parent); throw error }
        device = info.st_dev; inode = info.st_ino
    }
    deinit { Darwin.close(held); Darwin.close(parent) }
    func cleanupEmptyStore() throws {
        var info = stat()
        guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_dev == device, info.st_ino == inode else { throw AppRealIntegrationFailure.cleanup }
        try AppFileSecurity.directory(held)
        // Fixed generated layout only, NEVER recursive unknown cleanup. Unknown entries retain root.
        let layout: [String: Set<String>] = [
            "Data": ["OpenLXSSH.sqlite", "OpenLXSSH.sqlite-wal", "OpenLXSSH.sqlite-shm", "OpenLXSSH.sqlite-journal", "OpenLXSSH.lock"],
            "Keys": [".OpenLXSSH.lock"], "Recovery": ["security-intents.json"], "Trust": ["known_hosts", "trust.lock"], "Sessions": []]
        let actual = try children(held)
        guard Set(actual).isSubset(of: Set(layout.keys).union([".openlxssh-real-fixture"])) else { throw AppRealIntegrationFailure.cleanup }
        for dir in actual where dir != ".openlxssh-real-fixture" {
            guard let allowed = layout[dir] else { throw AppRealIntegrationFailure.cleanup }
            let fd = openat(held, dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw AppRealIntegrationFailure.cleanup }; defer { Darwin.close(fd) }
            try AppFileSecurity.directory(fd)
            let entries = try children(fd); guard Set(entries).isSubset(of: allowed) else { throw AppRealIntegrationFailure.cleanup }
            for item in entries {
                let file = openat(fd, item, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard file >= 0 else { throw AppRealIntegrationFailure.cleanup }; defer { Darwin.close(file) }
                try AppFileSecurity.regularFile(file)
                var before = stat(), current = stat()
                guard fstat(file, &before) == 0, fstatat(fd, item, &current, AT_SYMLINK_NOFOLLOW) == 0,
                      before.st_dev == current.st_dev, before.st_ino == current.st_ino, unlinkat(fd, item, 0) == 0 else { throw AppRealIntegrationFailure.cleanup }
            }
            guard unlinkat(held, dir, AT_REMOVEDIR) == 0 else { throw AppRealIntegrationFailure.cleanup }
        }
        guard unlinkat(held, ".openlxssh-real-fixture", 0) == 0, unlinkat(parent, name, AT_REMOVEDIR) == 0 else { throw AppRealIntegrationFailure.cleanup }
    }
    private func children(_ fd: Int32) throws -> [String] {
        let copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let dir = fdopendir(copy) else { throw AppRealIntegrationFailure.cleanup }; defer { closedir(dir) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(dir) else { guard errno == 0 else { throw AppRealIntegrationFailure.cleanup }; break }
            let bytes = withUnsafeBytes(of: entry.pointee.d_name) { Data($0.prefix(Int(entry.pointee.d_namlen))) }
            guard let name = String(data: bytes, encoding: .utf8) else { throw AppRealIntegrationFailure.cleanup }
            if name != "." && name != ".." { names.append(name) }
        }
        return names
    }
}

struct AppRealSessionFailure: Error {
    let code: String
    init(_ reason: SessionFailure) {
        switch reason {
        case .trustScanFailed: code = "session.trustScanFailed"
        case .trustRejected: code = "session.trustRejected"
        case .authenticationTimeout: code = "session.authenticationTimeout"
        case .authenticationFailed: code = "session.authenticationFailed"
        default: code = "session.failed"
        }
    }
}
@MainActor final class AppRealIntegration {
    struct Check: Encodable { let name: String; let passed: Bool }
    struct Report: Encodable {
        let taskID = "APP-REAL-KEYONLY-PREP-A", kind = "HostProbe-native-real-keyonly"
        let productRuntimeVerified = false, testMinimumOS = "15.0"
        let scanSeconds: Int, connectSeconds = 10
        let passed: Bool, failureCode: String?
        let checks: [Check], actualOwnedSSHPID: Int32?, sshClosedAndPIDReleased: Bool
        let filesConnectionAttempts: Int, returnedProductionServices: Int, actualLists: Int, filesCloseAwaited: Int
        let actualListRawNames: [String], forbiddenCredentialCalls: Int
        let localStoreRemoved: Bool
        let boundary = "Real App native double-click/trust controls and on-demand read-only SFTP. Outer-auth is not shellReady. No nested SSH, terminal output capture, transfer lifecycle, Finder/IME, macOS26 runtime or product PERF claim. Expected CID/image/network are management prerequisites, not inspected by App."
    }
    let delegate: AppDelegate, options: AppRealIntegrationArguments.Options, input: AppRealPublicMaterial, store: AppRealOwnedStore
    let facts: AppRealFilesFacts, credentials: AppRealNoCredentials
    private var checks: [Check] = []
    private var ssh: DirectSessionDriver?, actualPID: Int32?, sshReleased = false
    init(delegate: AppDelegate, options: AppRealIntegrationArguments.Options, input: AppRealPublicMaterial, store: AppRealOwnedStore,
         facts: AppRealFilesFacts, credentials: AppRealNoCredentials) {
        self.delegate = delegate; self.options = options; self.input = input; self.store = store; self.facts = facts; self.credentials = credentials
    }
    var model: AppModel { delegate.model }
    static func validateSignature() throws {
        guard Bundle.main.bundleIdentifier == "org.openlxssh.OpenLXSSH", Bundle.main.bundleURL.pathExtension == "app",
              Bundle.main.object(forInfoDictionaryKey: "OpenLXSSHRealFixtureHostProbe") as? Bool == true else { throw AppRealIntegrationFailure.signature }
        var requirement: SecRequirement?, code: SecCode?
        guard SecRequirementCreateWithString("anchor apple generic and identifier \"org.openlxssh.OpenLXSSH\"" as CFString, [], &requirement) == errSecSuccess,
              SecCodeCopySelf([], &code) == errSecSuccess, let code, let requirement,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw AppRealIntegrationFailure.signature }
        _ = try BundledAskpassHelper.discover() // Production helper ID/same Team/Runtime/empty-entitlement checks.
    }
    func run() async {
        var failure: String?, removed = false
        do {
            try await wait { self.model.didLoad && !self.model.isLoading }
            try check("fresh-own-store-no-hosts-tabs-files", model.hosts.isEmpty && model.sessions.tabs.isEmpty && !model.files.visible && model.files.state == .disconnected)
            let initialAttempts = await facts.connectionAttempts; try check("no-sftp-at-start", initialAttempts == 0)
            var originalKey = try AppRealPrivateInput.read(input.contract.generation + "/id_ed25519", limit: 32768)
            let originalSHA = AppRealPrivateInput.sha(originalKey) // In-memory only, never report this private-key digest.
            originalKey.resetBytes(in: 0..<originalKey.count); originalKey.removeAll()
            let key = try await model.security.createKey(.importFile(URL(fileURLWithPath: input.contract.generation + "/id_ed25519")), protection: .unencrypted, rememberPassphrase: nil)
            try check("production-key-import-committed", !key.cleanupPending)
            let importedPublic = try await model.security.publicKey(key.id)
            let expectedPublic = try AppRealPrivateInput.read(input.contract.generation + "/id_ed25519.pub", limit: 4096)
            guard let publicText = String(data: expectedPublic, encoding: .utf8) else { throw AppRealIntegrationFailure.provenance }
            let publicFields = publicText.trimmingCharacters(in: .newlines).split(separator: " ")
            try check("imported-key-matches-current-public-export", importedPublic.algorithm == .ed25519 && publicFields.count >= 2 &&
                importedPublic.copyString == publicFields.prefix(2).joined(separator: " "))
            try check("fixture-key-source-unmodified", try AppRealPrivateInput.sha(AppRealPrivateInput.read(input.contract.generation + "/id_ed25519", limit: 32768)) == originalSHA)
            let host = HostConfiguration(name: "Local approved keyonly fixture", address: "127.0.0.1", port: 22221, username: "fixture", authentication: .privateKey, keyRef: key.id)
            try check("host-saved-no-password", await model.saveHostSecurely(host, isNew: true, password: .manual))
            try await doubleClickHost()
            try await wait { !self.model.sessions.tabs.isEmpty }
            let trustDeadline = ProcessInfo.processInfo.systemUptime + 90
            while self.model.sessions.tabs.first?.trust.count != 1 {
                guard let tab = self.model.sessions.tabs.first else { throw AppRealIntegrationFailure.failedCheck }
                if case .failed(let reason) = tab.state { throw AppRealSessionFailure(reason) }
                guard tab.authentication == nil else { throw AppRealIntegrationFailure.unexpectedAuthentication }
                guard ProcessInfo.processInfo.systemUptime < trustDeadline else { throw AppRealIntegrationFailure.timeout }
                try await Task.sleep(for: .milliseconds(25))
            }
            guard let tab = model.sessions.tabs.first else { throw AppRealIntegrationFailure.failedCheck }
            if case .failed(let reason) = tab.state { throw AppRealSessionFailure(reason) }
            guard tab.authentication == nil, let prompt = tab.trust.first, let driver = tab.driver as? DirectSessionDriver else { throw AppRealIntegrationFailure.unexpectedAuthentication }
            ssh = driver
            try check("actual-direct-driver", driver.session.token != nil)
            try check("exact-out-of-band-trust-match", input.contract.matchesTrust(host: prompt.host.address.value, port: Int(prompt.host.port.value), algorithm: prompt.algorithm, fingerprint: prompt.fingerprint))
            try await click("terminal.trust"); try await click("trust.verified"); try await click("trust.accept")
            let connectedDeadline = ProcessInfo.processInfo.systemUptime + 90
            while tab.state != .connected {
                if let pending = tab.trust.first, !input.contract.matchesTrust(host: pending.host.address.value, port: Int(pending.host.port.value), algorithm: pending.algorithm, fingerprint: pending.fingerprint) { throw AppRealIntegrationFailure.fingerprint }
                guard tab.authentication == nil else { throw AppRealIntegrationFailure.unexpectedAuthentication }
                if case .failed(let reason) = tab.state { throw AppRealSessionFailure(reason) }
                guard ProcessInfo.processInfo.systemUptime < connectedDeadline else { throw AppRealIntegrationFailure.timeout }
                try await Task.sleep(for: .milliseconds(25))
            }
            actualPID = driver.session.ownedProcessID
            try check("actual-outer-auth-and-owned-pid", tab.state == .connected && driver.session.state == .connected && actualPID != nil)
            let filesBefore = await facts.connectionAttempts
            try check("ssh-did-not-open-sftp", filesBefore == 0 && !model.files.visible)
            try await click("files.open")
            try await wait { self.model.files.visible && self.model.files.canConnect }
            try await type("files.initial.secret", "")
            try await click("files.connect")
            try await wait(seconds: 120) { self.model.files.state == .ready && !self.model.files.busy || self.model.files.state == .failed || self.model.files.trustPrompt != nil || self.model.files.keyboardPrompt != nil }
            try check("sftp-actual-ready-no-extra-trust-or-kbi", model.files.state == .ready && model.files.trustPrompt == nil && model.files.keyboardPrompt == nil)
            try await type("files.path", "/fixture/home"); try await click("files.go")
            try await wait { self.model.files.path.bytes == Data("/fixture/home".utf8) && !self.model.files.busy || self.model.files.state == .failed }
            let returned = await facts.returnedProductionServices, listed = await facts.lists
            try check("production-sftp-read-only-list", model.files.state == .ready && returned == 1 && listed >= 2)
            let manager = model.files.manager
            try await click("tab.close." + tab.id.uuidString)
            try await wait { self.model.sessions.tabs.isEmpty && driver.session.state == .closed && driver.session.ownedProcessID == nil }
            sshReleased = true
            try check("same-real-session-closed-pid-released", driver.session.state == .closed && driver.session.ownedProcessID == nil)
            guard let window = delegate.mainWindow else { throw AppRealIntegrationFailure.nativeControl }
            window.performClose(nil)
            try await wait { self.delegate.mainWindow == nil }
            let finalManager = await manager.snapshot(), closedFiles = await facts.closedServices
            try check("window-close-awaited-files", finalManager.isClosed && closedFiles == 1)
            _ = delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false)
            try await wait { self.delegate.mainWindow?.isVisible == true }
            let attemptsAfterReopen = await facts.connectionAttempts
            try check("reopen-no-restore", model.sessions.tabs.isEmpty && !model.files.visible && model.files.state == .disconnected && attemptsAfterReopen == 1)
            try await model.repository.apply([.deleteHost(host.id)])
            try await model.security.deleteKey(key.id)
            try await model.security.close(); try await model.repository.close()
            try check("no-keychain-access", await credentials.forbiddenCalls == 0)
            try store.cleanupEmptyStore(); removed = true
        } catch { failure = (error as? AppRealSessionFailure)?.code ?? (error as? AppRealIntegrationFailure)?.rawValue ?? "sanitized-native-integration-failure" }
        if failure != nil {
            _ = await model.lifecycle.closeConnections(cancelTransfers: true)
            if let ssh { sshReleased = ssh.session.state == .closed && ssh.session.ownedProcessID == nil }
            try? await model.security.close(); try? await model.repository.close()
        }
        let report = await Report(scanSeconds: options.scanSeconds, passed: failure == nil, failureCode: failure, checks: checks,
            actualOwnedSSHPID: actualPID, sshClosedAndPIDReleased: sshReleased, filesConnectionAttempts: facts.connectionAttempts,
            returnedProductionServices: facts.returnedProductionServices, actualLists: facts.lists, filesCloseAwaited: facts.closedServices,
            actualListRawNames: facts.latestListRawNames, forbiddenCredentialCalls: credentials.forbiddenCalls, localStoreRemoved: removed)
        let parent = String(options.contractPath!.dropLast("/app-real-integration.json".count))
        do {
            let fd = try AppRealPrivateInput.directory(parent); defer { Darwin.close(fd) }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try AppRealPrivateInput.write(encoder.encode(report), parent: fd, name: "app-result.json")
            print(report.passed ? "App real fixture finite case passed; see app-result.json" : "App real fixture finite case failed; own store retained; see app-result.json")
        } catch { exit(2) }
        let exitCode: Int32 = report.passed ? 0 : 1
        RunLoop.main.perform { MainActor.assumeIsolated { () -> Void in exit(exitCode) } }
    }
    private func check(_ name: String, _ condition: Bool) throws { checks.append(Check(name: name, passed: condition)); if !condition { throw AppRealIntegrationFailure.failedCheck } }
    private func wait(seconds: Double = 90, _ predicate: () -> Bool) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        while !predicate() { guard ProcessInfo.processInfo.systemUptime < deadline else { throw AppRealIntegrationFailure.timeout }; try await Task.sleep(for: .milliseconds(25)) }
    }
    private func find<T: NSView>(_ id: String, _ type: T.Type) -> T? {
        func visit(_ view: NSView) -> T? { if view.identifier?.rawValue == id, let typed = view as? T { return typed }; for child in view.subviews { if let result = visit(child) { return result } }; return nil }
        guard var window = delegate.mainWindow else { return nil }; while let sheet = window.attachedSheet { window = sheet }
        return window.contentView.flatMap(visit)
    }
    private func click(_ id: String) async throws {
        try await wait { self.find(id, NSButton.self)?.isEnabled == true }
        guard let control = find(id, NSButton.self) else { throw AppRealIntegrationFailure.nativeControl }
        control.performClick(nil); try await Task.sleep(for: .milliseconds(100))
    }
    private func type(_ id: String, _ text: String) async throws {
        try await wait { self.find(id, NSTextField.self) != nil }
        guard let field = find(id, NSTextField.self), let window = field.window else { throw AppRealIntegrationFailure.nativeControl }
        window.makeFirstResponder(field)
        guard let editor = window.fieldEditor(true, for: field) as? NSTextView else { throw AppRealIntegrationFailure.nativeControl }
        editor.selectAll(nil); editor.insertText(text, replacementRange: NSRange(location: NSNotFound, length: 0)); window.makeFirstResponder(nil)
        field.sendAction(field.action, to: field.target); try await Task.sleep(for: .milliseconds(100))
    }
    private func doubleClickHost() async throws {
        try await wait { self.find("hosts.table", NSTableView.self)?.numberOfRows == 1 }
        guard let table = find("hosts.table", NSTableView.self), let window = table.window else { throw AppRealIntegrationFailure.nativeControl }
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false); window.makeFirstResponder(table); table.layoutSubtreeIfNeeded()
        let point = table.convert(NSPoint(x: table.bounds.minX + 60, y: table.rect(ofRow: 0).midY), to: nil)
        let time = ProcessInfo.processInfo.systemUptime
        for count in 1...2 {
            guard let down = NSEvent.mouseEvent(with: .leftMouseDown, location: point, modifierFlags: [], timestamp: time + Double(count)*0.03,
                windowNumber: window.windowNumber, context: nil, eventNumber: count*2, clickCount: count, pressure: 1),
                let up = NSEvent.mouseEvent(with: .leftMouseUp, location: point, modifierFlags: [], timestamp: time + Double(count)*0.03+0.01,
                windowNumber: window.windowNumber, context: nil, eventNumber: count*2+1, clickCount: count, pressure: 0) else { throw AppRealIntegrationFailure.nativeControl }
            NSApp.postEvent(down, atStart: false); NSApp.postEvent(up, atStart: false); try await Task.sleep(for: .milliseconds(60))
        }
    }
}
#endif
