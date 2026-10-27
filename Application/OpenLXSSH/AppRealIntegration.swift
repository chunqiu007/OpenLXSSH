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
    private var writes: [Data: Bool] = [:]
    private(set) var peakOpenHandles = 0, successfulOpens = 0, successfulCloses = 0, shutdownClosedHandles = 0
    private var handles: Set<FileHandleID> = []
    func opened(_ id: FileHandleID, path: RemotePath, writing: Bool) {
        handles.insert(id); successfulOpens += 1; peakOpenHandles = max(peakOpenHandles, handles.count)
        if writing { writes[path.bytes] = false }
    }
    func closedHandle(_ id: FileHandleID) { if handles.remove(id) != nil { successfulCloses += 1 } }
    func madeDirectory(_ path: RemotePath) { writes[path.bytes] = true }
    func committed(_ source: RemotePath, _ destination: RemotePath) { if let kind = writes.removeValue(forKey: source.bytes) { writes[destination.bytes] = kind } }
    func removed(_ path: RemotePath) { writes[path.bytes] = nil }
    func ownedPaths() -> [Data: Bool] { writes }
    func openHandleCount() -> Int { handles.count }
    func shutdownHandles() { shutdownClosedHandles += handles.count; handles.removeAll() }
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
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        let id = try await native.open(path, mode: mode, token: token); await facts.opened(id, path: path, writing: mode == .exclusiveWrite); return id
    }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await native.read(handle, maxBytes: maxBytes, token: token) }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await native.write(handle, data: data, token: token) }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await native.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await native.closeHandle(handle); await facts.closedHandle(handle) }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { try await native.mkdir(path, token: token); await facts.madeDirectory(path) }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await native.rename(source, to: destination, mode: mode, token: token); await facts.committed(source, destination) }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await native.commit(source, to: destination, request: request, token: token); await facts.committed(source, destination) }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { try await native.remove(path, directory: directory, token: token); await facts.removed(path) }
    nonisolated func cancel() { native.cancel() }
    func close() async { await native.close(); if !closed { closed = true; await facts.shutdownHandles(); await facts.closed() } }
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
    private var transferSource: (name: String, device: dev_t, inode: ino_t, sha256: String)?
    func generateTransferSource(_ scope: AppRealTransferScope) throws -> URL {
        guard transferSource == nil else { throw AppRealIntegrationFailure.isolation }
        let name = scope.payloadName, fd = openat(held, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw AppRealIntegrationFailure.isolation }; defer { Darwin.close(fd) }
        try AppFileSecurity.regularFile(fd)
        let seed = Data(SHA256.hash(data: Data("OpenLXSSH non-secret native transfer fixture".utf8)))
        var block = Data(); for _ in 0..<(AppRealTransferScope.chunkBytes / seed.count) { block += seed }
        var total: UInt64 = 0, hash = SHA256()
        while total < AppRealTransferScope.sourceBytes {
            block.withUnsafeMutableBytes { $0.storeBytes(of: total.littleEndian, as: UInt64.self) }
            var offset = 0
            while offset < block.count {
                let count = block.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                if count < 0 && errno == EINTR { continue }; guard count > 0 else { throw AppRealIntegrationFailure.isolation }; offset += count
            }
            hash.update(data: block); total += UInt64(block.count)
        }
        var info = stat()
        guard fsync(fd) == 0, fstat(fd, &info) == 0, info.st_size == AppRealTransferScope.sourceBytes,
              UInt64(info.st_blocks) * 512 >= total else { throw AppRealIntegrationFailure.isolation }
        transferSource = (name, info.st_dev, info.st_ino, hash.finalize().map { String(format: "%02x", $0) }.joined())
        return url.appendingPathComponent(name)
    }
    func transferSourceSHA256() throws -> String {
        guard let transferSource else { throw AppRealIntegrationFailure.isolation }; return transferSource.sha256
    }
    func cleanupTransferSource() throws {
        guard let source = transferSource else { return }
        let fd = openat(held, source.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw AppRealIntegrationFailure.cleanup }; defer { Darwin.close(fd) }
        try AppFileSecurity.regularFile(fd)
        var info = stat(), named = stat(), hash = SHA256(), bytes: UInt64 = 0
        guard fstat(fd, &info) == 0, info.st_dev == source.device, info.st_ino == source.inode else { throw AppRealIntegrationFailure.cleanup }
        var buffer = [UInt8](repeating: 0, count: AppRealTransferScope.chunkBytes)
        while true {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n < 0 && errno == EINTR { continue }; guard n >= 0 else { throw AppRealIntegrationFailure.cleanup }
            if n == 0 { break }; bytes += UInt64(n); guard bytes <= AppRealTransferScope.sourceBytes else { throw AppRealIntegrationFailure.cleanup }; hash.update(data: Data(buffer.prefix(n)))
        }
        guard bytes == AppRealTransferScope.sourceBytes, hash.finalize().map({ String(format: "%02x", $0) }).joined() == source.sha256,
              fstatat(held, source.name, &named, AT_SYMLINK_NOFOLLOW) == 0, named.st_dev == source.device, named.st_ino == source.inode,
              unlinkat(held, source.name, 0) == 0 else { throw AppRealIntegrationFailure.cleanup }
        transferSource = nil
    }
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
    struct TransferEvidence: Encodable {
        let jobID: UUID, generation: UUID, serviceID: UUID, hostID: UUID
        let serverBinding: String, sourceBytes: UInt64, sourceSHA256: String, remoteSHA256: String
        let progressAtCloseAction: UInt64, progressAtHideAction: UInt64, finalProgress: UInt64
        let actualTemporaryBase64: String
        let sourcePicker = "HostProbe testSelection through rendered native upload button; NOT manual Finder/NSOpenPanel acceptance"
        let actualJobSucceeded: Bool, unchangedJobServiceHostGeneration: Bool, reconnects: Int
        let cleanedRemoteRoot: Bool, localSourceRemoved: Bool
    }
    struct WindowEvidence: Encodable {
        let jobID: UUID, generation: UUID, serviceID: UUID, hostID: UUID
        let serverBinding: String, sourceBytes: UInt64, sourceSHA256: String
        let progressAtFirstWindowClose: UInt64, progressAfterContinue: UInt64, progressAtSecondWindowClose: UInt64, progressAtCancelDecision: UInt64
        let cancelledState: String, managerClosed: Bool, allWorkDrained: Bool, windowClosed: Bool, sshClosedPIDNil: Bool
        let connectionAttempts: Int, closedServices: Int, publicHandlesAfterClose: Int
        let retainedTemporaryPathsBase64: [String], createdPathsBase64: [String]
        let remotePostcheck = "NOT PERFORMED after cancellation: original service may be disposed. External fixed-CID exact-ledger final absence/temp metadata check required; no automatic reconnect."
    }
    struct Report: Encodable {
        let taskID = "APP-REAL-KEYONLY-PREP-A", kind = "HostProbe-native-real-keyonly"
        let productRuntimeVerified = false, testMinimumOS = "15.0"
        let scanSeconds: Int, connectSeconds = 10
        let passed: Bool, failureCode: String?
        let checks: [Check], actualOwnedSSHPID: Int32?, sshClosedAndPIDReleased: Bool
        let filesConnectionAttempts: Int, returnedProductionServices: Int, actualLists: Int, filesCloseAwaited: Int
        let actualListRawNames: [String], forbiddenCredentialCalls: Int
        let localStoreRemoved: Bool
        let phase: String
        let transfer: TransferEvidence?
        let windowTransfer: WindowEvidence?
        let failedStage: AppRealTransferStage?
        let diagnostics: AppRealTransferDiagnostics?
        let remainingOwnedRemotePathsBase64: [String]
        let publicOpenHandles: Int, publicSuccessfulOpens: Int, publicSuccessfulCloses: Int, publicShutdownClosedHandles: Int
        let boundary = "Real App native controls and SFTP. Transfer-survives-close tests SSH close/hide; window-continue-cancel tests one real inflight window Continue then CancelAndClose. Cancellation remote absence/temp verification is EXTERNAL pending, never I/O on a closed service. Test picker is not manual Finder. No Quit/IME/macOS26/product PERF claim."
    }
    let delegate: AppDelegate, options: AppRealIntegrationArguments.Options, input: AppRealPublicMaterial, store: AppRealOwnedStore
    let facts: AppRealFilesFacts, credentials: AppRealNoCredentials
    private var checks: [Check] = []
    private var ssh: DirectSessionDriver?, actualPID: Int32?, sshReleased = false
    private var transferEvidence: TransferEvidence?
    private var windowEvidence: WindowEvidence?
    private var transferDiagnostics = AppRealTransferDiagnostics()
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
            if input.contract.selectedPhase.isTransfer {
                transferEvidence = try await transferSurvivesClose(tab: tab, driver: driver)
                sshReleased = driver.session.state == .closed && driver.session.ownedProcessID == nil
            } else {
                try await click("tab.close." + tab.id.uuidString)
                try await wait { self.model.sessions.tabs.isEmpty && driver.session.state == .closed && driver.session.ownedProcessID == nil }
                sshReleased = true
                try check("same-real-session-closed-pid-released", driver.session.state == .closed && driver.session.ownedProcessID == nil)
            }
            if input.contract.selectedPhase != .windowContinueCancel {
                guard let window = delegate.mainWindow else { throw AppRealIntegrationFailure.nativeControl }
                window.performClose(nil)
                try await wait { self.delegate.mainWindow == nil }
            }
            let finalManager = await manager.snapshot(), closedFiles = await facts.closedServices
            try check("window-close-awaited-files", finalManager.isClosed && closedFiles == 1)
            if input.contract.selectedPhase == .transferSurvivesClose {
                let open = await facts.openHandleCount(), forced = await facts.shutdownClosedHandles
                let opens = await facts.successfulOpens, closes = await facts.successfulCloses
                try check("transfer-public-handles-closed-without-shutdown-rescue", open == 0 && forced == 0 && opens == closes)
            }
            _ = delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false)
            try await wait { self.delegate.mainWindow?.isVisible == true }
            let attemptsAfterReopen = await facts.connectionAttempts
            try check("reopen-no-restore", model.sessions.tabs.isEmpty && !model.files.visible && model.files.state == .disconnected && attemptsAfterReopen == 1)
            try await model.repository.apply([.deleteHost(host.id)])
            try await model.security.deleteKey(key.id)
            try await model.security.close(); try await model.repository.close()
            try check("no-keychain-access", await credentials.forbiddenCalls == 0)
            if input.contract.selectedPhase == .windowContinueCancel { try store.cleanupTransferSource() }
            try store.cleanupEmptyStore(); removed = true
        } catch {
            if let guardName = error as? AppRealTransferGuard {
                transferDiagnostics.failed(guardName); failure = "transfer." + guardName.rawValue
            } else { failure = (error as? AppRealSessionFailure)?.code ?? (error as? AppRealIntegrationFailure)?.rawValue ?? "sanitized-native-integration-failure" }
        }
        if failure != nil, input.contract.selectedPhase.isTransfer {
            await captureTransferDiagnostic(stage: transferDiagnostics.stage, driver: ssh, job: nil)
        }
        if failure != nil {
            _ = await model.lifecycle.closeConnections(cancelTransfers: true)
            if let ssh { sshReleased = ssh.session.state == .closed && ssh.session.ownedProcessID == nil }
            try? await model.security.close(); try? await model.repository.close()
        }
        let report = await Report(scanSeconds: options.scanSeconds, passed: failure == nil, failureCode: failure, checks: checks,
            actualOwnedSSHPID: actualPID, sshClosedAndPIDReleased: sshReleased, filesConnectionAttempts: facts.connectionAttempts,
            returnedProductionServices: facts.returnedProductionServices, actualLists: facts.lists, filesCloseAwaited: facts.closedServices,
            actualListRawNames: facts.latestListRawNames, forbiddenCredentialCalls: credentials.forbiddenCalls, localStoreRemoved: removed,
            phase: input.contract.selectedPhase.rawValue, transfer: transferEvidence, windowTransfer: windowEvidence,
            failedStage: failure != nil && input.contract.selectedPhase.isTransfer ? transferDiagnostics.stage : nil,
            diagnostics: input.contract.selectedPhase.isTransfer ? transferDiagnostics : nil,
            remainingOwnedRemotePathsBase64: facts.ownedPaths().keys.map { $0.base64EncodedString() }.sorted(),
            publicOpenHandles: facts.openHandleCount(), publicSuccessfulOpens: facts.successfulOpens, publicSuccessfulCloses: facts.successfulCloses,
            publicShutdownClosedHandles: facts.shutdownClosedHandles)
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
    private func captureTransferDiagnostic(stage: AppRealTransferStage, driver: DirectSessionDriver?, job supplied: TransferJobSnapshot?) async {
        transferDiagnostics.enter(stage)
        guard let scope = try? AppRealTransferScope(runID: input.contract.runID) else { return }
        let job: TransferJobSnapshot?
        if let supplied { job = supplied } else { job = await model.files.manager.snapshot().jobs.first }
        var question: AppRealDiagnosticQuestion = .none, riskPath: Data?
        if let pending = job?.pendingDecision {
            switch pending.question {
            case .conflict: question = .conflict
            case .risk(let risk):
                switch risk {
                case .remotePathChecksAreNotAtomic(let path): question = .remotePathRisk; riskPath = path.bytes
                case .overwriteIsAtomicButNotCompareAndSwap(let path): question = .overwriteRisk; riskPath = path.bytes
                case .remoteFsyncUnavailable(let path): question = .fsyncRisk; riskPath = path.bytes
                case .deletionChecksAreNotCompareAndSwap(let path): question = .deletionRisk; riskPath = path.bytes
                }
            }
        }
        let state: AppRealDiagnosticSSHState
        switch driver?.session.state {
        case nil: state = .absent
        case .idle: state = .preparing
        case .preparing: state = .preparing
        case .awaitingTrust: state = .awaitingTrust
        case .authenticating: state = .authenticating
        case .connectionPending: state = .connectionPending
        case .connected: state = .connected
        case .disconnected: state = .disconnected
        case .failed: state = .failed
        case .closing: state = .closing
        case .closed: state = .closed
        }
        let owned = await facts.ownedPaths(), bindings = await facts.bindings, attempts = await facts.connectionAttempts
        let snapshot = AppRealTransferSnapshot(stage: stage, scope: scope, jobID: job?.id, generation: job?.generation,
            sourceServiceID: job?.request.source.serviceID, destinationServiceID: job?.request.destination.serviceID,
            sourcePath: job?.request.source.path.bytes, destinationPath: job?.request.destination.path.bytes,
            state: job?.state.rawValue ?? "absent", transferredBytes: job?.transferredBytes ?? 0,
            pendingQuestion: question, riskPath: riskPath, ownedPaths: Array(owned.keys), sshState: state,
            ownedSSHPIDPresent: driver?.session.ownedProcessID != nil, serverBinding: bindings.first.flatMap(UUID.init(uuidString:)), connectionAttempts: attempts, phase: input.contract.selectedPhase)
        transferDiagnostics.record(snapshot)
    }
    private nonisolated static func inspectOwnedTransfer(_ service: any RemoteFileService, scope: AppRealTransferScope, token: CancellationToken) async throws {
        var current = RemotePath.root
        for component in scope.remoteDirectory.dropFirst().split(separator: "/") {
            current = try current.appending(FileName(String(component)))
            guard try await service.lstat(current, token: token).kind == .directory else { throw AppRealIntegrationFailure.cleanup }
        }
    }
    private func transferSurvivesClose(tab: SessionTab, driver: DirectSessionDriver) async throws -> TransferEvidence? {
        transferDiagnostics.enter(.source)
        let scope = try AppRealTransferScope(runID: input.contract.runID)
        let sourceURL = try store.generateTransferSource(scope), expectedSHA = try store.transferSourceSHA256()
        try check("transfer-source-generated-16MiB", sourceURL.lastPathComponent == scope.payloadName)
        // Production mkdir UI: fixed home parent, one exact new UUID name, explicit remote-path risk.
        transferDiagnostics.enter(.mkdir)
        try check("transfer-mkdir-fixed-home", model.files.path.bytes == Data("/fixture/home".utf8))
        try await click("files.mkdir"); try await type("files.operation.name", scope.directoryName)
        try await click("files.mkdir.risk"); try await click("files.operation.confirm")
        try await wait { !self.model.files.busy && self.model.files.entries.contains { $0.name.bytes == Data(scope.directoryName.utf8) } || self.model.files.issue != nil }
        let remoteRoot = try RemotePath(scope.remoteDirectory), payload = try RemotePath(scope.remotePayload)
        let created = await facts.ownedPaths()
        try check("production-mkdir-owned-ledger", created[remoteRoot.bytes] == true && model.files.issue == nil)
        transferDiagnostics.enter(.enterOwnedRoot)
        try await type("files.path", scope.remoteDirectory); try await click("files.go")
        try await wait { self.model.files.path == remoteRoot && !self.model.files.busy }
        try check("owned-remote-directory-initially-empty", model.files.entries.isEmpty)
        // Never create a token here. All plan/approval/execution go through existing production controls.
        transferDiagnostics.enter(.probePrepare)
        try await click("files.probe.prepare")
        try await wait { self.model.files.probeReview != nil && !self.model.files.busy }
        guard let probe = model.files.probeReview else { throw AppRealIntegrationFailure.failedCheck }
        try check("probe-bound-to-current-owned-root", probe.plan.parent == remoteRoot && probe.plan.temporaryDirectory.parent == remoteRoot)
        transferDiagnostics.enter(.probeExecute)
        try await click("files.probe.review"); try await click("files.probe.approve"); try await click("files.probe.execute")
        try await wait(seconds: 120) { self.model.files.lastProbeResult != nil && !self.model.files.busy }
        guard let result = model.files.lastProbeResult, result.passed, result.retainedPaths.isEmpty else { throw AppRealTransferGuard.probeResult }
        transferDiagnostics.enter(.transferContext)
        let context = try model.files.transferContext(upload: true), bindings = await facts.bindings
        guard bindings.count == 1, let binding = bindings.first, context.confirmation?.serverBinding.uuidString == binding,
              context.hostID == tab.hostID, context.path == remoteRoot else { throw AppRealTransferGuard.serviceBinding }
        let manager = model.files.manager, before = await manager.snapshot()
        try check("new-transfer-phase-no-previous-jobs", before.jobs.isEmpty)
        transferDiagnostics.enter(.uploadControl)
        model.files.pathPicker.testSelection = [sourceURL]
        try await click("files.upload") // Actual rendered target/action → picker seam → production enqueue.
        transferDiagnostics.enter(.observeJob)
        var job: TransferJobSnapshot?
        let deadline = ProcessInfo.processInfo.systemUptime + 120
        while job == nil {
            let current = await manager.snapshot()
            guard current.jobs.count <= 1 else { throw AppRealTransferGuard.singleJob }
            if let item = current.jobs.first {
                if let question = item.pendingDecision {
                    await captureTransferDiagnostic(stage: .pendingDecision, driver: driver, job: item)
                    guard case .risk(.remotePathChecksAreNotAtomic(let path)) = question.question, path == payload else { throw AppRealTransferGuard.pendingRiskMismatch }
                    try await click("transfer.decision." + item.id.uuidString); try await click("transfer.risk.accept")
                    transferDiagnostics.enter(.observeJob)
                } else if AppRealTransferScope.isRealInflight(state: item.state.rawValue, transferred: item.transferredBytes, sourceBytes: AppRealTransferScope.sourceBytes) { job = item }
                else if !item.state.isActive { throw AppRealIntegrationFailure.transferCompletedBeforeLifecycleAction } // Too fast is NOT coverage.
            }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw AppRealIntegrationFailure.timeout }
            if job == nil { try await Task.sleep(for: .milliseconds(5)) }
        }
        await captureTransferDiagnostic(stage: .firstJobIdentity, driver: driver, job: job)
        guard let first = job, first.request.destination.path == payload, first.request.destination.serviceID == context.serviceID,
              first.request.hostID == context.hostID.uuidString else { throw AppRealTransferGuard.firstJobIdentity }
        transferDiagnostics.enter(.temporaryLedger)
        let actualCreated = await facts.ownedPaths()
        let temporaries = actualCreated.keys.filter { bytes in
            guard let path = try? RemotePath(bytes: bytes) else { return false }
            return path.parent == remoteRoot && path.name?.bytes.starts(with: Data(".openlxssh-transfer.".utf8)) == true && actualCreated[bytes] == false
        }
        guard temporaries.count == 1 else { throw AppRealTransferGuard.temporaryCount }
        if input.contract.selectedPhase == .windowContinueCancel {
            windowEvidence = try await windowContinueCancel(first: first, context: context, binding: binding, scope: scope,
                sourceSHA: expectedSHA, temporary: temporaries[0], manager: manager, driver: driver)
            return nil
        }
        transferDiagnostics.enter(.preCloseAction)
        // Wait for both native controls before the final action-time snapshot.
        try await wait { self.find("tab.close." + tab.id.uuidString, NSButton.self)?.isEnabled == true && self.find("files.hide", NSButton.self)?.isEnabled == true }
        await captureTransferDiagnostic(stage: .preCloseAction, driver: driver, job: nil)
        let actionSnapshot = await manager.snapshot()
        guard let atClose = actionSnapshot.jobs.first(where: { $0.id == first.id }) else { throw AppRealTransferGuard.preCloseIdentity }
        guard AppRealTransferScope.isRealInflight(state: atClose.state.rawValue, transferred: atClose.transferredBytes, sourceBytes: AppRealTransferScope.sourceBytes) else { throw AppRealTransferGuard.preCloseInflight }
        guard atClose.generation == first.generation, atClose.request == first.request else { throw AppRealTransferGuard.preCloseIdentity }
        guard driver.session.state == .connected, driver.session.ownedProcessID == actualPID else { throw AppRealTransferGuard.sessionConnected }
        guard let close = find("tab.close." + tab.id.uuidString, NSButton.self) else { throw AppRealTransferGuard.closeControl }
        close.performClick(nil)
        // Hide immediately; do not await SSH close before checking actual inflight for this action.
        transferDiagnostics.enter(.preHideAction)
        let hidingSnapshot = await manager.snapshot()
        guard let atHide = hidingSnapshot.jobs.first(where: { $0.id == first.id }) else { throw AppRealTransferGuard.preHideIdentity }
        guard AppRealTransferScope.isRealInflight(state: atHide.state.rawValue, transferred: atHide.transferredBytes, sourceBytes: AppRealTransferScope.sourceBytes) else { throw AppRealTransferGuard.preHideInflight }
        guard atHide.generation == first.generation, atHide.request == first.request else { throw AppRealTransferGuard.preHideIdentity }
        guard let hide = find("files.hide", NSButton.self), hide.isEnabled else { throw AppRealTransferGuard.hideControl }
        hide.performClick(nil)
        await captureTransferDiagnostic(stage: .awaitSSHClose, driver: driver, job: atHide)
        try await wait { !self.model.files.visible && self.model.sessions.tabs.isEmpty && driver.session.state == .closed && driver.session.ownedProcessID == nil }
        try check("native-ssh-close-and-panel-hide-during-real-inflight", !model.files.visible && driver.session.ownedProcessID == nil)
        transferDiagnostics.enter(.awaitTransfer)
        var final: TransferJobSnapshot?
        let finishDeadline = ProcessInfo.processInfo.systemUptime + 180
        while final == nil {
            let snap = await manager.snapshot()
            guard let current = snap.jobs.first(where: { $0.id == first.id }), current.generation == first.generation, current.request == first.request else { throw AppRealTransferGuard.finalJobIdentity }
            guard current.pendingDecision == nil else { throw AppRealTransferGuard.unexpectedFinalDecision }
            if !current.state.isActive { final = current; break }
            guard ProcessInfo.processInfo.systemUptime < finishDeadline else { throw AppRealIntegrationFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
        await captureTransferDiagnostic(stage: .finalSucceeded, driver: driver, job: final)
        guard let final, final.state == .succeeded, final.transferredBytes == AppRealTransferScope.sourceBytes,
              final.retainedTemporaryPaths.isEmpty, final.items.count == 1,
              final.items.first?.state == .succeeded(bytes: AppRealTransferScope.sourceBytes) else { throw AppRealTransferGuard.finalSucceeded }
        transferDiagnostics.enter(.sameServiceContext)
        let attempts = await facts.connectionAttempts, nowBindings = await facts.bindings
        try check("same-job-service-host-generation-no-reconnect", attempts == 1 && nowBindings == bindings && ObjectIdentifier(manager) == ObjectIdentifier(model.files.manager))
        let finalContext = try model.files.transferContext(upload: true)
        try check("same-current-service-context-after-hide", finalContext.serviceID == context.serviceID && finalContext.hostID == context.hostID && finalContext.lifetime == context.lifetime)
        // Exact same service lease, bounded 64KiB streaming SHA; no shell hash or reconnect.
        transferDiagnostics.enter(.remoteDigest)
        let digest = try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString) { service, token in
            try await Self.inspectOwnedTransfer(service, scope: scope, token: token)
            let listed = try await service.list(remoteRoot, token: token)
            guard listed.count == 1, listed[0].name.bytes == Data(scope.payloadName.utf8), listed[0].attributes.kind == .regular else { throw AppRealIntegrationFailure.cleanup }
            let before = try await service.lstat(payload, token: token)
            guard before.kind == .regular, before.size == AppRealTransferScope.sourceBytes else { throw AppRealIntegrationFailure.failedCheck }
            let handle = try await service.open(payload, mode: .read, token: token)
            do {
                var hash = SHA256(), total: UInt64 = 0
                while true {
                    let chunk = try await service.read(handle, maxBytes: AppRealTransferScope.chunkBytes, token: token)
                    if chunk.isEmpty { break }; total += UInt64(chunk.count)
                    guard total <= AppRealTransferScope.sourceBytes else { throw AppRealIntegrationFailure.failedCheck }; hash.update(data: chunk)
                }
                let after = try await service.lstat(payload, token: token)
                try await service.closeHandle(handle)
                guard total == AppRealTransferScope.sourceBytes, after == before else { throw AppRealIntegrationFailure.failedCheck }
                return hash.finalize().map { String(format: "%02x", $0) }.joined()
            } catch { try? await service.closeHandle(handle); throw error }
        }
        try check("actual-remote-payload-stream-sha256", digest == expectedSHA)
        transferDiagnostics.enter(.remoteCleanup)
        let owned = await facts.ownedPaths()
        try check("remote-owned-ledger-only-root-and-payload", owned.count == 2 && owned[remoteRoot.bytes] == true && owned[payload.bytes] == false)
        try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString) { service, token in
            try await Self.inspectOwnedTransfer(service, scope: scope, token: token)
            let entries = try await service.list(remoteRoot, token: token)
            guard entries.count == 1, entries[0].name.bytes == Data(scope.payloadName.utf8), entries[0].attributes.kind == .regular else { throw AppRealIntegrationFailure.cleanup }
            try await service.remove(payload, directory: false, token: token)
            guard try await service.list(remoteRoot, token: token).isEmpty else { throw AppRealIntegrationFailure.cleanup }
            try await service.remove(remoteRoot, directory: true, token: token)
            do { _ = try await service.lstat(remoteRoot, token: token); throw AppRealIntegrationFailure.cleanup }
            catch let error as FileServiceError where error.kind == .notFound { }
        }
        transferDiagnostics.enter(.localCleanup)
        try store.cleanupTransferSource()
        try check("only-known-remote-and-held-local-source-cleaned", await facts.ownedPaths().isEmpty)
        transferDiagnostics.enter(.complete)
        return TransferEvidence(jobID: first.id, generation: first.generation, serviceID: context.serviceID, hostID: context.hostID,
            serverBinding: binding, sourceBytes: AppRealTransferScope.sourceBytes, sourceSHA256: expectedSHA, remoteSHA256: digest,
            progressAtCloseAction: atClose.transferredBytes, progressAtHideAction: atHide.transferredBytes, finalProgress: final.transferredBytes,
            actualTemporaryBase64: temporaries[0].base64EncodedString(), actualJobSucceeded: true,
            unchangedJobServiceHostGeneration: true, reconnects: 0, cleanedRemoteRoot: true, localSourceRemoved: true)
    }
    private func windowContinueCancel(first: TransferJobSnapshot, context: FilesTransferContext, binding: String, scope: AppRealTransferScope,
                                      sourceSHA: String, temporary: Data, manager: TransferManager, driver: DirectSessionDriver) async throws -> WindowEvidence {
        guard let window = delegate.mainWindow else { throw AppRealTransferGuard.windowNotClosed }
        let expectedIdentity = [first.id.uuidString, first.generation.uuidString, first.request.source.serviceID.uuidString,
            first.request.destination.serviceID.uuidString, first.request.hostID]
        func same(_ job: TransferJobSnapshot) -> Bool {
            AppRealWindowTransferGate.sameIdentity(jobID: job.id, generation: job.generation, sourceServiceID: job.request.source.serviceID,
                destinationServiceID: job.request.destination.serviceID, host: job.request.hostID, expected: expectedIdentity) && job.request == first.request
        }
        func inflight(_ job: TransferJobSnapshot) -> Bool { AppRealTransferScope.isRealInflight(state: job.state.rawValue, transferred: job.transferredBytes, sourceBytes: AppRealTransferScope.sourceBytes) }
        func checkpoint(_ event: String, _ bytes: UInt64, _ attempts: Int, retained: [String] = []) throws {
            let record = AppRealWindowCheckpoint(runID: scope.runID, event: event, jobID: first.id, generation: first.generation,
                serviceID: context.serviceID, hostID: context.hostID, serverBinding: binding,
                sourceBytes: AppRealTransferScope.sourceBytes, progressBytes: bytes,
                remoteRootBase64: Data(scope.remoteDirectory.utf8).base64EncodedString(), payloadBase64: Data(scope.remotePayload.utf8).base64EncodedString(),
                temporaryBase64: temporary.base64EncodedString(), connectionAttempts: attempts, retainedTemporaryPathsBase64: retained)
            let parent = String(options.contractPath!.dropLast("/app-real-integration.json".count)), fd = try AppRealPrivateInput.directory(parent)
            defer { Darwin.close(fd) }
            try AppRealPrivateInput.write(JSONEncoder().encode(record), parent: fd, name: "window-" + event + ".json")
        }
        transferDiagnostics.enter(.windowFirstClose)
        try checkpoint("before-first-close", first.transferredBytes, await facts.connectionAttempts)
        await captureTransferDiagnostic(stage: .windowFirstClose, driver: driver, job: nil)
        guard let firstAction = await manager.snapshot().jobs.first(where: { $0.id == first.id }), same(firstAction), inflight(firstAction),
              driver.session.state == .connected, driver.session.ownedProcessID == actualPID else { throw AppRealTransferGuard.windowFirstInflight }
        window.performClose(nil)
        try checkpoint("first-close", firstAction.transferredBytes, await facts.connectionAttempts)
        try await wait { self.find("lifecycle.transfers.continue", NSButton.self)?.isEnabled == true }
        transferDiagnostics.enter(.windowContinue)
        guard let beforeContinue = await manager.snapshot().jobs.first(where: { $0.id == first.id }), same(beforeContinue), inflight(beforeContinue),
              let keep = find("lifecycle.transfers.continue", NSButton.self) else { throw AppRealTransferGuard.windowContinueIdentity }
        keep.performClick(nil)
        try await wait { !self.model.files.admissionFrozen }
        guard delegate.mainWindow === window, window.isVisible, !model.lifecycle.terminating,
              ObjectIdentifier(manager) == ObjectIdentifier(model.files.manager),
              let continued = await manager.snapshot().jobs.first(where: { $0.id == first.id }), same(continued), inflight(continued) else { throw AppRealTransferGuard.windowContinueAdmission }
        let attemptsAfterContinue = await facts.connectionAttempts, bindings = await facts.bindings
        guard attemptsAfterContinue == 1, bindings == [binding], model.files.state == .ready else { throw AppRealTransferGuard.windowContinueIdentity }
        try check("window-continue-keeps-real-window-same-running-job", true)
        try checkpoint("continued", continued.transferredBytes, attemptsAfterContinue)
        transferDiagnostics.enter(.windowSecondClose)
        await captureTransferDiagnostic(stage: .windowSecondClose, driver: driver, job: continued)
        guard let secondAction = await manager.snapshot().jobs.first(where: { $0.id == first.id }), same(secondAction), inflight(secondAction),
              delegate.mainWindow === window, driver.session.state == .connected, driver.session.ownedProcessID == actualPID else { throw AppRealTransferGuard.windowSecondInflight }
        window.performClose(nil)
        try checkpoint("second-close", secondAction.transferredBytes, attemptsAfterContinue)
        try await wait { self.find("lifecycle.transfers.cancelClose", NSButton.self)?.isEnabled == true }
        transferDiagnostics.enter(.windowCancelClose)
        guard let atCancel = await manager.snapshot().jobs.first(where: { $0.id == first.id }), same(atCancel), inflight(atCancel),
              let cancel = find("lifecycle.transfers.cancelClose", NSButton.self) else { throw AppRealTransferGuard.windowCancelIdentity }
        cancel.performClick(nil)
        try checkpoint("cancel-decision", atCancel.transferredBytes, attemptsAfterContinue)
        transferDiagnostics.enter(.windowAwaitClosed)
        // Production close owns cancellation, worker drain and service close. Never simulate
        // cancellation here or call a possibly disposed service to fake remote absence.
        let closeDeadline = ProcessInfo.processInfo.systemUptime + 120
        var retainedAcknowledged = false
        while delegate.mainWindow != nil {
            if !retainedAcknowledged, let acknowledge = find("lifecycle.transfers.retained.acknowledge", NSButton.self), acknowledge.isEnabled {
                let terminal = await manager.snapshot()
                guard terminal.isClosed, !terminal.hasActiveWork, let job = terminal.jobs.first(where: { $0.id == first.id }), same(job),
                      job.state == .cancelled else { throw AppRealTransferGuard.windowFinalCancelled }
                let paths = job.retainedTemporaryPaths.map { $0.bytes.base64EncodedString() }
                guard paths == [temporary.base64EncodedString()] else { throw AppRealTransferGuard.ownedCleanupLedger }
                try checkpoint("retained-before-ack", job.transferredBytes, await facts.connectionAttempts, retained: paths)
                acknowledge.performClick(nil); retainedAcknowledged = true
            }
            guard ProcessInfo.processInfo.systemUptime < closeDeadline else { throw AppRealIntegrationFailure.timeout }
            try await Task.sleep(for: .milliseconds(25))
        }
        let final = await manager.snapshot()
        guard let cancelled = final.jobs.first(where: { $0.id == first.id }), same(cancelled) else { throw AppRealTransferGuard.windowFinalCancelled }
        let closedServices = await facts.closedServices, handles = await facts.openHandleCount(), attempts = await facts.connectionAttempts
        guard AppRealWindowTransferGate.cancelledAndDrained(state: cancelled.state.rawValue, managerClosed: final.isClosed, activeWork: final.hasActiveWork,
            sshClosed: driver.session.state == .closed, pidPresent: driver.session.ownedProcessID != nil,
            windowPresent: delegate.mainWindow != nil, closedServices: closedServices, handles: handles), attempts == 1 else { throw AppRealTransferGuard.windowResources }
        await captureTransferDiagnostic(stage: .windowFinalCancelled, driver: driver, job: cancelled)
        try check("window-cancel-waits-real-worker-services-ssh", true)
        try checkpoint("closed", cancelled.transferredBytes, attempts)
        return WindowEvidence(jobID: first.id, generation: first.generation, serviceID: context.serviceID, hostID: context.hostID,
            serverBinding: binding, sourceBytes: AppRealTransferScope.sourceBytes, sourceSHA256: sourceSHA,
            progressAtFirstWindowClose: firstAction.transferredBytes, progressAfterContinue: continued.transferredBytes,
            progressAtSecondWindowClose: secondAction.transferredBytes, progressAtCancelDecision: atCancel.transferredBytes,
            cancelledState: cancelled.state.rawValue, managerClosed: final.isClosed, allWorkDrained: !final.hasActiveWork,
            windowClosed: delegate.mainWindow == nil, sshClosedPIDNil: driver.session.state == .closed && driver.session.ownedProcessID == nil,
            connectionAttempts: attempts, closedServices: closedServices, publicHandlesAfterClose: handles,
            retainedTemporaryPathsBase64: cancelled.retainedTemporaryPaths.map { $0.bytes.base64EncodedString() },
            createdPathsBase64: await facts.ownedPaths().keys.map { $0.base64EncodedString() }.sorted())
    }
    private func check(_ name: String, _ condition: Bool) throws { checks.append(Check(name: name, passed: condition)); if !condition { throw AppRealIntegrationFailure.failedCheck } }
    private func wait(seconds: Double = 90, _ predicate: () -> Bool) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        while !predicate() { guard ProcessInfo.processInfo.systemUptime < deadline else { throw AppRealIntegrationFailure.timeout }; try await Task.sleep(for: .milliseconds(25)) }
    }
    private func find<T: NSView>(_ id: String, _ type: T.Type) -> T? {
        func visit(_ view: NSView) -> T? { if view.identifier?.rawValue == id, let typed = view as? T { return typed }; for child in view.subviews { if let result = visit(child) { return result } }; return nil }
        if id.hasPrefix("lifecycle.transfers."), let panel = NSApp.windows.first(where: { $0.isVisible && $0 is NSPanel && $0.title.hasPrefix("OpenLXSSH ·") }), let content = panel.contentView { return visit(content) }
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
