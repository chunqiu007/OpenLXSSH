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
    func committed(_ source: RemotePath, _ destination: RemotePath) {
        let descendants = writes.filter { $0.key.starts(with: source.bytes + Data([47])) }
        if let kind = writes.removeValue(forKey: source.bytes) { writes[destination.bytes] = kind }
        for (path, kind) in descendants { writes[path] = nil; writes[destination.bytes + path.dropFirst(source.bytes.count)] = kind }
    }
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
    private var fileOperationsEntries: [String: (dev_t, ino_t, Bool)] = [:]
    func prepareFileOperations(_ scope: AppRealFileScope) throws -> (sources: [URL], downloads: URL, digests: [AppRealFileDigest]) {
        guard fileOperationsEntries.isEmpty else { throw AppRealIntegrationFailure.isolation }
        func mkdirOwned(_ name: String, parent: Int32, relative: String) throws -> Int32 {
            guard mkdirat(parent, name, 0o700) == 0 else { throw AppRealIntegrationFailure.isolation }
            let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw AppRealIntegrationFailure.isolation }
            try AppFileSecurity.directory(fd); var st = stat(); guard fstat(fd, &st) == 0 else { Darwin.close(fd); throw AppRealIntegrationFailure.isolation }
            fileOperationsEntries[relative] = (st.st_dev, st.st_ino, true); return fd
        }
        let source = try mkdirOwned("FileSources", parent: held, relative: "FileSources"); defer { Darwin.close(source) }
        let downloads = try mkdirOwned("FileDownloads", parent: held, relative: "FileDownloads"); Darwin.close(downloads)
        let folder = try mkdirOwned(scope.folder, parent: source, relative: "FileSources/" + scope.folder); defer { Darwin.close(folder) }
        var digests: [AppRealFileDigest] = []
        for (relative, size) in scope.payloads {
            let name = relative == scope.neighbor ? scope.neighbor : scope.child, parent = relative == scope.neighbor ? source : folder
            let block = Data(SHA256.hash(data: Data(relative.utf8)))
            var bytes = Data(); while bytes.count < size { bytes.append(block.prefix(min(block.count, size - bytes.count))) }
            try AppRealPrivateInput.write(bytes, parent: parent, name: name)
            let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); guard fd >= 0 else { throw AppRealIntegrationFailure.isolation }
            var st = stat(); guard fstat(fd, &st) == 0 else { Darwin.close(fd); throw AppRealIntegrationFailure.isolation }; Darwin.close(fd)
            fileOperationsEntries["FileSources/" + relative] = (st.st_dev, st.st_ino, false)
            digests.append(AppRealFileDigest(relativePathBase64: Data(relative.utf8).base64EncodedString(), bytes: size, sha256: AppRealPrivateInput.sha(bytes)))
        }
        return ([url.appendingPathComponent("FileSources/" + scope.neighbor), url.appendingPathComponent("FileSources/" + scope.folder, isDirectory: true)], url.appendingPathComponent("FileDownloads", isDirectory: true), digests)
    }
    func verifyDownloadedFiles(_ scope: AppRealFileScope, expected: [AppRealFileDigest]) throws -> [AppRealFileDigest] {
        let downloads = try AppRealPrivateInput.directory(url.appendingPathComponent("FileDownloads").path); defer { Darwin.close(downloads) }
        guard Set(try children(downloads).map { Data($0.utf8) }) == Set([Data(scope.neighbor.utf8), Data(scope.folder.utf8)]) else { throw AppRealIntegrationFailure.failedCheck }
        let folder = openat(downloads, scope.folder, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard folder >= 0 else { throw AppRealIntegrationFailure.failedCheck }; defer { Darwin.close(folder) }; try AppFileSecurity.directory(folder)
        guard try children(folder).map({ Data($0.utf8) }) == [Data(scope.child.utf8)] else { throw AppRealIntegrationFailure.failedCheck }
        var info = stat(); guard fstat(folder, &info) == 0 else { throw AppRealIntegrationFailure.failedCheck }
        fileOperationsEntries["FileDownloads/" + scope.folder] = (info.st_dev, info.st_ino, true)
        var actual: [AppRealFileDigest] = []
        for (relative, size) in scope.payloads {
            let parent = relative == scope.neighbor ? downloads : folder, name = relative == scope.neighbor ? scope.neighbor : scope.child
            let read = try AppRealPrivateInput.readKnownFileOperationLeaf(parent: parent, name: name, scope: scope)
            let digest = AppRealFileDigest(relativePathBase64: Data(relative.utf8).base64EncodedString(), bytes: read.bytes.count, sha256: AppRealPrivateInput.sha(read.bytes))
            guard read.bytes.count == size, expected.contains(digest) else { throw AppRealIntegrationFailure.failedCheck }
            fileOperationsEntries["FileDownloads/" + relative] = (read.device, read.inode, false); actual.append(digest)
        }
        return actual
    }
    func cleanupFileOperations() throws {
        let all = fileOperationsEntries
        for (relative, value) in all {
            let path = url.appendingPathComponent(relative)
            let fd: Int32
            if value.2 { fd = try AppRealPrivateInput.directory(path.path) }
            else {
                let parts = relative.split(separator: "/").map(String.init)
                let parent = try AppRealPrivateInput.directory(url.appendingPathComponent(parts.dropLast().joined(separator: "/")).path)
                defer { Darwin.close(parent) }
                fd = openat(parent, parts.last!, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            }
            guard fd >= 0 else { throw AppRealIntegrationFailure.cleanup }; defer { Darwin.close(fd) }
            var st = stat(); guard fstat(fd, &st) == 0, st.st_dev == value.0, st.st_ino == value.1 else { throw AppRealIntegrationFailure.cleanup }
            if value.2 {
                let expected = Set(all.keys.filter { URL(fileURLWithPath: $0).deletingLastPathComponent().path == URL(fileURLWithPath: relative).path }.map { URL(fileURLWithPath: $0).lastPathComponent })
                guard Set(try children(fd)) == expected else { throw AppRealIntegrationFailure.cleanup }
            } else { try AppFileSecurity.regularFile(fd) }
        }
        for relative in all.keys.sorted(by: { $0.split(separator: "/").count > $1.split(separator: "/").count }) {
            guard let value = all[relative] else { throw AppRealIntegrationFailure.cleanup }
            let parts = relative.split(separator: "/").map(String.init), name = parts.last!
            let parent = parts.count == 1 ? dup(held) : try AppRealPrivateInput.directory(url.appendingPathComponent(parts.dropLast().joined(separator: "/")).path)
            guard parent >= 0 else { throw AppRealIntegrationFailure.cleanup }; defer { Darwin.close(parent) }
            var st = stat(); guard fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) == 0, st.st_dev == value.0, st.st_ino == value.1,
                unlinkat(parent, name, value.2 ? AT_REMOVEDIR : 0) == 0 else { throw AppRealIntegrationFailure.cleanup }
        }
        fileOperationsEntries.removeAll()
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
    struct QuitEvidence: Encodable {
        let jobID: UUID, generation: UUID, serviceID: UUID
        let progressAtFirstTerminate: UInt64, progressAfterContinue: UInt64, progressAtSecondTerminate: UInt64, progressAtCancelDecision: UInt64
        let cancelledState: String, managerClosed: Bool, allWorkDrained: Bool, sshClosedPIDNil: Bool
        let beforeStoreCloseCalls: Int, afterStoreCloseCalls: Int
        let nativeReplyStillPending: Bool
        let retainedTemporaryPathsBase64: [String]
        let remotePostcheck = "External fixed-CID exact-ledger final absence/temp check pending. No second SFTP/autoreconnect."
    }
    struct FileOperationsEvidence: Encodable {
        let serviceID: UUID, hostID: UUID, serverBinding: String
        let uploadJobIDs: [UUID], downloadJobIDs: [UUID]
        let expectedDigests: [AppRealFileDigest], actualDownloadedDigests: [AppRealFileDigest]
        let renameSourceBase64: String, renameTargetBase64: String
        let approvedDeletePlanIDs: [UUID], deletedPathsBase64: [String]
        let unselectedNeighborSHA256Before: String, unselectedNeighborSHA256After: String
        let remoteRootAbsent: Bool, localKnownSourceAndDownloadsRemoved: Bool
        let picker = "HostProbe testSelection via native upload/download buttons, NOT manual Finder/NSOpenPanel"
    }
    struct TerminalEvidence: Encodable {
        let nonce: String, sessionID: UUID, sessionGeneration: UInt64
        let selectedRangeAfterNext: [Int], selectedRangeAfterPrevious: [Int]
        let nextMatchIndex: Int, previousMatchIndex: Int, totalMatches: Int
        let expectedPasteBytes: Int, capturedPasteBytes: Int, expectedPasteSHA256: String, capturedPasteSHA256: String
        let bracketModeReady: Bool, originalTermiosRestoredAndShellReturned: Bool, sameSessionAndPID: Bool
        let boundary = "Native search field/buttons verified via selection and match summary. Paste uses pasteFromApplication API only; NO global clipboard read/write/copy, not GUI clipboard or manual IME acceptance."
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
        let quitTransfer: QuitEvidence?
        let fileOperations: FileOperationsEvidence?
        let terminalOperations: TerminalEvidence?
        let failedStage: AppRealTransferStage?
        let diagnostics: AppRealTransferDiagnostics?
        let remainingOwnedRemotePathsBase64: [String]
        let publicOpenHandles: Int, publicSuccessfulOpens: Int, publicSuccessfulCloses: Int, publicShutdownClosedHandles: Int
        let boundary = "Real App native controls and SFTP. Quit phase receipt is fsynced before the original native termination reply; outer process exit still required. Cancelled remote absence/temp verification is EXTERNAL pending, never I/O on a closed service. Test picker is not manual Finder. No IME/macOS26/product PERF claim."
    }
    let delegate: AppDelegate, options: AppRealIntegrationArguments.Options, input: AppRealPublicMaterial, store: AppRealOwnedStore
    let facts: AppRealFilesFacts, credentials: AppRealNoCredentials
    private var checks: [Check] = []
    private var ssh: DirectSessionDriver?, actualPID: Int32?, sshReleased = false
    private var transferEvidence: TransferEvidence?
    private var windowEvidence: WindowEvidence?
    private var quitEvidence: QuitEvidence?
    private var fileOperationsEvidence: FileOperationsEvidence?
    private var terminalEvidence: TerminalEvidence?
    private var quitHooks = AppRealQuitHookGate()
    private var quitTimer: Timer?
    private var quitFailureRecorded = false
    private var quitHostID: UUID?, quitKeyID: UUID?
    var isQuitPhase: Bool { input.contract.selectedPhase == .quitContinueCancel }
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
            if isQuitPhase { quitHostID = host.id; quitKeyID = key.id }
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
            let terminalOnly = input.contract.selectedPhase == .terminalSearchPaste
            if terminalOnly {
                terminalEvidence = try await terminalSearchPaste(driver: driver)
            } else {
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
            }
            let manager = model.files.manager
            if input.contract.selectedPhase == .fileOperations { fileOperationsEvidence = try await fileOperations() }
            if input.contract.selectedPhase.isTransfer {
                transferEvidence = try await transferSurvivesClose(tab: tab, driver: driver)
                if isQuitPhase { return } // Native termination owns the only store closes and final reply.
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
            try check("window-close-awaited-files", finalManager.isClosed && closedFiles == (terminalOnly ? 0 : 1))
            if input.contract.selectedPhase == .transferSurvivesClose {
                let open = await facts.openHandleCount(), forced = await facts.shutdownClosedHandles
                let opens = await facts.successfulOpens, closes = await facts.successfulCloses
                try check("transfer-public-handles-closed-without-shutdown-rescue", open == 0 && forced == 0 && opens == closes)
            }
            _ = delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false)
            try await wait { self.delegate.mainWindow?.isVisible == true }
            let attemptsAfterReopen = await facts.connectionAttempts
            try check("reopen-no-restore", model.sessions.tabs.isEmpty && !model.files.visible && model.files.state == .disconnected && attemptsAfterReopen == (terminalOnly ? 0 : 1))
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
        if isQuitPhase, let failure {
            failQuit(failure)
            return // No exit() may masquerade as a native Quit outcome, including failures.
        }
        if failure != nil {
            _ = await model.lifecycle.closeConnections(cancelTransfers: true)
            if let ssh { sshReleased = ssh.session.state == .closed && ssh.session.ownedProcessID == nil }
            try? await model.security.close(); try? await model.repository.close()
        }
        do { try await persistReport(failure: failure, removed: removed) } catch { exit(2) }
        let exitCode: Int32 = failure == nil ? 0 : 1
        RunLoop.main.perform { MainActor.assumeIsolated { () -> Void in exit(exitCode) } }
    }
    private func terminalSearchPaste(driver: DirectSessionDriver) async throws -> TerminalEvidence {
        let nonce = input.contract.runID.replacingOccurrences(of: "-", with: ""), plan = try AppRealTerminalProtocol(nonce: nonce)
        guard let token = driver.session.token, driver.session.state == .connected, driver.session.ownedProcessID == actualPID else { throw AppRealIntegrationFailure.failedCheck }
        func current() throws {
            guard driver.session.token == token, driver.session.state == .connected, driver.session.ownedProcessID == actualPID else { throw AppRealIntegrationFailure.failedCheck }
        }
        func frame(_ stage: AppRealTerminalProtocol.Stage, seconds: Double = 15) async throws -> String {
            let deadline = ProcessInfo.processInfo.systemUptime + seconds
            while true {
                try current()
                if let value = try plan.frameValue(driver.terminal.text, stage: stage) { return value }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw AppRealIntegrationFailure.timeout }
                try await Task.sleep(for: .milliseconds(25))
            }
        }
        try driver.session.sendInput(plan.shellCommand)
        try check("terminal-independent-shell-ack", try await frame(.shell) == "ok")
        try driver.session.sendInput(plan.probeCommand())
        try check("terminal-owned-probe-ready", try await frame(.ready) == "ok")
        try check("terminal-actual-bracketed-mode-ready", driver.terminal.bracketedPaste)
        try await type("terminal.search", plan.marker)
        try await click("terminal.search.next")
        let nextRange = driver.terminal.selectedRange(), next = driver.terminal.searchMatchSummary(plan.marker, limit: 32)
        try check("native-terminal-search-next-selects-owned-marker", next.total == 24 && next.index > 0 && nextRange.location != NSNotFound && nextRange.length > 0)
        try await click("terminal.search.previous")
        let previousRange = driver.terminal.selectedRange(), previous = driver.terminal.searchMatchSummary(plan.marker, limit: 32)
        try check("native-terminal-search-previous-changes-selection", previous.total == 24 && previous.index > 0 && previous.index != next.index && previousRange != nextRange)
        try current()
        // Deliberately not terminal.paste button: it reads NSPasteboard.general. This memory-only
        // API exercises SwiftTerm framing without touching any user clipboard data.
        driver.terminal.pasteFromApplication(AppRealTerminalProtocol.sample)
        let capturedValue = try await frame(.captured), expectedHash = AppRealPrivateInput.sha(plan.expectedPaste)
        let captured = try? plan.parseCapture(capturedValue, expectedHash: expectedHash)
        try check("terminal-real-raw-bracketed-paste-count-and-sha", captured != nil)
        guard let captured else { throw AppRealIntegrationFailure.failedCheck }
        try check("terminal-probe-restored-original-termios", try await frame(.restored) == "ok")
        try check("terminal-probe-returned-to-outer-shell", try await frame(.returned) == "0")
        try current()
        try driver.session.sendInput(Data(("printf '\\101\\1241|" + nonce + "|outer|ok|END\\n'\r").utf8))
        try check("terminal-fresh-outer-shell-ack-after-restoration", try await frame(.outer) == "ok")
        let noSFTP = await facts.connectionAttempts
        try check("terminal-only-no-sftp-clipboard-or-credentials", noSFTP == 0 && !model.files.visible)
        return TerminalEvidence(nonce: nonce, sessionID: token.sessionID, sessionGeneration: token.generation,
            selectedRangeAfterNext: [nextRange.location, nextRange.length], selectedRangeAfterPrevious: [previousRange.location, previousRange.length],
            nextMatchIndex: next.index, previousMatchIndex: previous.index, totalMatches: next.total,
            expectedPasteBytes: plan.expectedPaste.count, capturedPasteBytes: captured.bytes,
            expectedPasteSHA256: expectedHash, capturedPasteSHA256: captured.sha256,
            bracketModeReady: true, originalTermiosRestoredAndShellReturned: true, sameSessionAndPID: true)
    }
    private func fileOperations() async throws -> FileOperationsEvidence {
        let scope = try AppRealFileScope(runID: input.contract.runID), dataset = try store.prepareFileOperations(scope)
        let root = try RemotePath(scope.root), home = try RemotePath("/fixture/home"), manager = model.files.manager
        let initialContext = try model.files.transferContext(upload: false), initialBindings = await facts.bindings
        var admitted: [UUID: (UUID, TransferRequest)] = [:]
        func sameService(_ context: FilesTransferContext) async throws {
            let current = try model.files.transferContext(upload: false), bindings = await facts.bindings
            guard current.serviceID == context.serviceID, current.hostID == context.hostID, current.lifetime == context.lifetime,
                  bindings.count == 1, bindings == initialBindings, await facts.connectionAttempts == 1 else { throw AppRealIntegrationFailure.failedCheck }
        }
        func browse(_ path: RemotePath) async throws {
            try await type("files.path", String(decoding: path.bytes, as: UTF8.self)); try await click("files.go")
            try await wait { self.model.files.path == path && !self.model.files.busy || self.model.files.issue != nil }
            guard model.files.issue == nil, model.files.state == .ready else { throw AppRealIntegrationFailure.failedCheck }
        }
        func select(_ names: [String]) async throws {
            try await wait { self.find("files.entries", NSTableView.self) != nil }
            guard let table = find("files.entries", NSTableView.self), table.numberOfRows == model.files.entries.count else { throw AppRealIntegrationFailure.nativeControl }
            let bytes = Set(names.map { Data($0.utf8) }), rows = IndexSet(model.files.entries.indices.filter { bytes.contains(model.files.entries[$0].name.bytes) })
            guard rows.count == names.count else { throw AppRealIntegrationFailure.failedCheck }
            table.selectRowIndexes(rows, byExtendingSelection: false)
            try await Task.sleep(for: .milliseconds(100))
            guard table.selectedRowIndexes == rows else { throw AppRealIntegrationFailure.nativeControl }
        }
        func terminalJobs(_ count: Int) async throws -> [TransferJobSnapshot] {
            let deadline = ProcessInfo.processInfo.systemUptime + 120
            while true {
                let jobs = await manager.snapshot().jobs
                guard jobs.count <= count else { throw AppRealIntegrationFailure.failedCheck }
                for job in jobs {
                    if let expected = admitted[job.id] {
                        guard expected.0 == job.generation, expected.1 == job.request else { throw AppRealIntegrationFailure.failedCheck }
                    } else {
                        guard job.request.hostID == initialContext.hostID.uuidString,
                              job.request.source.serviceID == initialContext.serviceID || job.request.destination.serviceID == initialContext.serviceID else { throw AppRealIntegrationFailure.failedCheck }
                        admitted[job.id] = (job.generation, job.request)
                    }
                }
                for job in jobs where job.state.isActive {
                    if let decision = job.pendingDecision {
                        guard case .risk(.remotePathChecksAreNotAtomic(let path)) = decision.question, scope.allowedRisk(path.bytes) else { throw AppRealIntegrationFailure.failedCheck }
                        try await click("transfer.decision." + job.id.uuidString); try await click("transfer.risk.accept")
                    }
                }
                if jobs.count == count && jobs.allSatisfy({ !$0.state.isActive }) {
                    guard jobs.allSatisfy({ $0.state == .succeeded && $0.retainedTemporaryPaths.isEmpty }) else { throw AppRealIntegrationFailure.failedCheck }
                    return jobs
                }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw AppRealIntegrationFailure.timeout }
                try await Task.sleep(for: .milliseconds(10))
            }
        }
        func remoteDigest(_ path: RemotePath, relative: String, size: Int, context: FilesTransferContext) async throws -> AppRealFileDigest {
            try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString) { service, token in
                var current = RemotePath.root
                for component in path.parent.bytes.dropFirst().split(separator: 47) {
                    current = try current.appending(FileName(bytes: Data(component)))
                    guard try await service.lstat(current, token: token).kind == .directory else { throw AppRealIntegrationFailure.failedCheck }
                }
                let attributes = try await service.lstat(path, token: token)
                guard attributes.kind == .regular, attributes.size == UInt64(size) else { throw AppRealIntegrationFailure.failedCheck }
                let handle = try await service.open(path, mode: .read, token: token)
                do {
                    var bytes = Data()
                    while true {
                        let chunk = try await service.read(handle, maxBytes: 16384, token: token)
                        if chunk.isEmpty { break }; bytes += chunk
                        guard bytes.count <= size else { throw AppRealIntegrationFailure.failedCheck }
                    }
                    try await service.closeHandle(handle)
                    guard bytes.count == size else { throw AppRealIntegrationFailure.failedCheck }
                    return AppRealFileDigest(relativePathBase64: Data(relative.utf8).base64EncodedString(), bytes: bytes.count, sha256: AppRealPrivateInput.sha(bytes))
                } catch { try? await service.closeHandle(handle); throw error }
            }
        }
        try check("file-operations-fixed-home-parent", model.files.path == home)
        try await click("files.mkdir"); try await type("files.operation.name", String(scope.root.split(separator: "/").last!))
        try await click("files.mkdir.risk"); try await click("files.operation.confirm")
        try await wait { !self.model.files.busy && self.model.files.entries.contains { $0.name.bytes == root.name?.bytes } || self.model.files.issue != nil }
        guard await facts.ownedPaths()[root.bytes] == true, model.files.issue == nil else { throw AppRealIntegrationFailure.failedCheck }
        try await browse(root)
        try check("file-operations-owned-root-empty", model.files.entries.isEmpty)
        try await click("files.probe.prepare"); try await wait { self.model.files.probeReview != nil && !self.model.files.busy }
        guard let probe = model.files.probeReview, probe.plan.parent == root else { throw AppRealIntegrationFailure.failedCheck }
        try await click("files.probe.review"); try await click("files.probe.approve"); try await click("files.probe.execute")
        try await wait { self.model.files.lastProbeResult != nil && !self.model.files.busy }
        guard let result = model.files.lastProbeResult, result.passed, result.retainedPaths.isEmpty else { throw AppRealIntegrationFailure.failedCheck }
        let context = try model.files.transferContext(upload: true), bindings = await facts.bindings
        guard bindings.count == 1, let binding = bindings.first, context.confirmation?.serverBinding.uuidString == binding else { throw AppRealIntegrationFailure.failedCheck }
        model.files.pathPicker.testSelection = dataset.sources
        try await click("files.upload")
        let uploads = try await terminalJobs(2)
        try check("native-batch-upload-two-selections", uploads.count == 2 && uploads.allSatisfy { $0.request.destination.serviceID == context.serviceID })
        try await click("files.refresh"); try await wait { !self.model.files.busy && self.model.files.entries.count == 2 }
        guard Set(model.files.entries.map { $0.name.bytes }) == Set([Data(scope.neighbor.utf8), Data(scope.folder.utf8)]) else { throw AppRealIntegrationFailure.failedCheck }
        try await select([scope.neighbor, scope.folder])
        model.files.pathPicker.testSelection = [dataset.downloads]
        try await click("files.download")
        let allJobs = try await terminalJobs(4), downloads = Array(allJobs.dropFirst(2))
        let actual = try store.verifyDownloadedFiles(scope, expected: dataset.digests)
        try check("native-download-exact-original-names-size-sha", actual.count == 2)
        try await sameService(context)
        let neighborPath = try root.appending(FileName(scope.neighbor))
        let neighborBefore = try await remoteDigest(neighborPath, relative: scope.neighbor, size: 4096, context: context)
        try await select([scope.folder]); try await click("files.rename"); try await type("files.operation.name", scope.renamed)
        try await click("files.operation.confirm")
        try await wait { self.model.files.pendingRisk != nil || !self.model.files.busy }
        guard case .remotePathChecksAreNotAtomic(let renameRisk)? = model.files.pendingRisk,
              renameRisk.bytes == Data((scope.root + "/" + scope.folder).utf8) else { throw AppRealIntegrationFailure.failedCheck }
        try await click("files.risk.open"); try await click("files.risk.accept")
        try await wait { !self.model.files.busy }
        try check("native-rename-old-absent-new-listed", !model.files.entries.contains { $0.name.bytes == Data(scope.folder.utf8) } && model.files.entries.contains { $0.name.bytes == Data(scope.renamed.utf8) } && model.files.issue == nil)
        var plans: [UUID] = [], deleted: [String] = []
        func deleteNative(_ name: String, selection: String) async throws {
            try await select([selection]); try await click("files.delete"); try await click("files.delete.prepare")
            try await wait { self.model.files.deleteReview != nil && !self.model.files.busy }
            guard let review = model.files.deleteReview, review.serviceID == context.serviceID,
                  review.plan.root == (name == "root" ? root : try root.appending(FileName(selection))),
                  scope.exactDelete(review.plan.items.map { item in (item.path.bytes, item.action == .removeFile ? "file" : item.action == .removeEmptyDirectory ? "directory" : "link") }, name: name, issues: review.plan.issues.count),
                  review.plan.canExecute, review.plan.linkPolicy == .reject else { throw AppRealIntegrationFailure.cleanup }
            let planID = review.id
            plans.append(planID)
            try await click("files.delete.review"); try await click("files.delete.acknowledge"); try await click("files.delete.execute")
            try await wait { self.model.files.lastDeleteReport?.planID == planID && !self.model.files.busy }
            guard let report = model.files.lastDeleteReport, report.allSucceeded,
                  Set(report.items.map { $0.path.bytes }) == Set(review.plan.items.map { $0.path.bytes }) else { throw AppRealIntegrationFailure.cleanup }
            deleted += report.items.map { $0.path.bytes.base64EncodedString() }
        }
        try await deleteNative(scope.renamed, selection: scope.renamed)
        let neighborAfter = try await remoteDigest(neighborPath, relative: scope.neighbor, size: 4096, context: context)
        try check("native-delete-preserves-unselected-neighbor-sha", neighborBefore == neighborAfter && dataset.digests.contains(neighborAfter))
        try await deleteNative(scope.neighbor, selection: scope.neighbor)
        try check("owned-root-empty-before-root-delete", model.files.entries.isEmpty)
        try await browse(home)
        try await deleteNative("root", selection: String(scope.root.split(separator: "/").last!))
        try check("native-plan-deleted-empty-owned-root", !model.files.entries.contains { $0.name.bytes == root.name?.bytes })
        try await sameService(context)
        try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString) { service, token in
            do { _ = try await service.lstat(root, token: token); throw AppRealIntegrationFailure.cleanup }
            catch let error as FileServiceError where error.kind == .notFound { }
        }
        guard await facts.ownedPaths().isEmpty else { throw AppRealIntegrationFailure.cleanup }
        try store.cleanupFileOperations()
        return FileOperationsEvidence(serviceID: context.serviceID, hostID: context.hostID, serverBinding: binding,
            uploadJobIDs: uploads.map(\.id), downloadJobIDs: downloads.map(\.id), expectedDigests: dataset.digests, actualDownloadedDigests: actual,
            renameSourceBase64: Data((scope.root + "/" + scope.folder).utf8).base64EncodedString(), renameTargetBase64: Data((scope.root + "/" + scope.renamed).utf8).base64EncodedString(),
            approvedDeletePlanIDs: plans, deletedPathsBase64: deleted, unselectedNeighborSHA256Before: neighborBefore.sha256,
            unselectedNeighborSHA256After: neighborAfter.sha256, remoteRootAbsent: true, localKnownSourceAndDownloadsRemoved: true)
    }
    private func persistReport(failure: String?, removed: Bool) async throws {
        let report = await Report(scanSeconds: options.scanSeconds, passed: failure == nil, failureCode: failure, checks: checks,
            actualOwnedSSHPID: actualPID, sshClosedAndPIDReleased: sshReleased, filesConnectionAttempts: facts.connectionAttempts,
            returnedProductionServices: facts.returnedProductionServices, actualLists: facts.lists, filesCloseAwaited: facts.closedServices,
            actualListRawNames: facts.latestListRawNames, forbiddenCredentialCalls: credentials.forbiddenCalls, localStoreRemoved: removed,
            phase: input.contract.selectedPhase.rawValue, transfer: transferEvidence, windowTransfer: windowEvidence, quitTransfer: quitEvidence, fileOperations: fileOperationsEvidence, terminalOperations: terminalEvidence,
            failedStage: failure != nil && input.contract.selectedPhase.isTransfer ? transferDiagnostics.stage : nil,
            diagnostics: input.contract.selectedPhase.isTransfer ? transferDiagnostics : nil,
            remainingOwnedRemotePathsBase64: facts.ownedPaths().keys.map { $0.base64EncodedString() }.sorted(),
            publicOpenHandles: facts.openHandleCount(), publicSuccessfulOpens: facts.successfulOpens, publicSuccessfulCloses: facts.successfulCloses,
            publicShutdownClosedHandles: facts.shutdownClosedHandles)
        let fd = try AppRealPrivateInput.directory(String(options.contractPath!.dropLast("/app-real-integration.json".count)))
        defer { Darwin.close(fd) }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try AppRealPrivateInput.write(encoder.encode(report), parent: fd, name: "app-result.json")
    }
    private func failQuit(_ code: String) {
        guard !quitFailureRecorded else { return }
        quitFailureRecorded = true; quitTimer?.invalidate(); quitTimer = nil
        Task { @MainActor in
            _ = await model.lifecycle.closeConnections(cancelTransfers: true)
            if let ssh { sshReleased = ssh.session.state == .closed && ssh.session.ownedProcessID == nil }
            // Store ownership remains with AppDelegate; never close Security/Repository twice.
            try? await persistReport(failure: code, removed: false)
            let fd = try? AppRealPrivateInput.directory(String(options.contractPath!.dropLast("/app-real-integration.json".count)))
            if let fd {
                try? AppRealPrivateInput.write(Data(("{\"passed\":false,\"failureCode\":\"quit-preexit-failed\"}\n").utf8), parent: fd, name: "quit-failure.json")
                Darwin.close(fd)
            }
            // Leave native termination denied. Outer finite owner sees failure/missing success receipt.
        }
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
        if isQuitPhase {
            try await quitContinueCancel(first: first, context: context, binding: binding, scope: scope, temporary: temporaries[0], manager: manager, driver: driver)
            return nil
        }
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
    @MainActor private final class QuitDecisionState {
        var decision: AppRealQuitDecision = .continueTransfer
        var deadline = ProcessInfo.processInfo.systemUptime + 90
    }
    private func quitContinueCancel(first: TransferJobSnapshot, context: FilesTransferContext, binding: String, scope: AppRealTransferScope,
                                    temporary: Data, manager: TransferManager, driver: DirectSessionDriver) async throws {
        guard isQuitPhase, let originalWindow = delegate.mainWindow, delegate.realQuitBeforeStoresClose == nil,
              delegate.realQuitAfterStoresClose == nil else { throw AppRealTransferGuard.quitHookOrder }
        let same: @Sendable (TransferJobSnapshot) -> Bool = { $0.id == first.id && $0.generation == first.generation && $0.request == first.request }
        let inflight: @Sendable (TransferJobSnapshot) -> Bool = { AppRealTransferScope.isRealInflight(state: $0.state.rawValue, transferred: $0.transferredBytes, sourceBytes: AppRealTransferScope.sourceBytes) }
        let checkpoint: @MainActor @Sendable (String, UInt64, [String]) throws -> Void = { name, bytes, retained in
            let record = AppRealWindowCheckpoint(runID: scope.runID, event: name, jobID: first.id, generation: first.generation,
                serviceID: context.serviceID, hostID: context.hostID, serverBinding: binding, sourceBytes: AppRealTransferScope.sourceBytes,
                progressBytes: bytes, remoteRootBase64: Data(scope.remoteDirectory.utf8).base64EncodedString(),
                payloadBase64: Data(scope.remotePayload.utf8).base64EncodedString(), temporaryBase64: temporary.base64EncodedString(),
                connectionAttempts: 1, retainedTemporaryPathsBase64: retained, phase: .quitContinueCancel)
            let fd = try AppRealPrivateInput.directory(String(self.options.contractPath!.dropLast("/app-real-integration.json".count))); defer { Darwin.close(fd) }
            try AppRealPrivateInput.write(JSONEncoder().encode(record), parent: fd, name: "quit-" + name + ".json")
        }
        var firstBytes: UInt64 = 0, continuedBytes: UInt64 = 0, secondBytes: UInt64 = 0, cancelBytes: UInt64 = 0
        var kept = false, cancelClicked = false, retainedAcked = false
        let decisionState = QuitDecisionState()
        var timerTaskBusy = false
        delegate.realQuitFailure = { [weak self] in self?.failQuit("quit-hook-or-store-close-failed") }
        delegate.realQuitBeforeStoresClose = { [weak self] final in
            guard let self, !self.quitFailureRecorded else { throw AppRealTransferGuard.quitHookOrder }
            self.transferDiagnostics.enter(.quitBeforeStoresClose)
            try self.quitHooks.before(phase: self.input.contract.selectedPhase)
            guard cancelClicked, let job = final.jobs.first(where: { $0.id == first.id }), same(job),
                  AppRealQuitTransferGate.cancelledAndDrained(state: job.state.rawValue, managerClosed: final.isClosed, activeWork: final.hasActiveWork,
                    sshClosed: driver.session.state == .closed, pidPresent: driver.session.ownedProcessID != nil,
                    closedServices: await self.facts.closedServices, handles: await self.facts.openHandleCount(), attempts: await self.facts.connectionAttempts)
            else { throw AppRealTransferGuard.quitFinalCancelled }
            let paths = job.retainedTemporaryPaths.map { $0.bytes.base64EncodedString() }
            guard paths.isEmpty || paths == [temporary.base64EncodedString()] else { throw AppRealTransferGuard.ownedCleanupLedger }
            self.sshReleased = true
            try self.check("quit-native-continue-kept-same-window-job", kept && self.delegate.mainWindow === originalWindow)
            try self.check("quit-native-cancel-waits-worker-files-ssh", true)
            try checkpoint("before-stores-close", job.transferredBytes, paths)
            guard let host = self.quitHostID, let key = self.quitKeyID else { throw AppRealTransferGuard.quitHookOrder }
            try await self.model.repository.apply([.deleteHost(host)])
            try await self.model.security.deleteKey(key)
            try self.store.cleanupTransferSource()
            self.quitEvidence = QuitEvidence(jobID: first.id, generation: first.generation, serviceID: context.serviceID,
                progressAtFirstTerminate: firstBytes, progressAfterContinue: continuedBytes, progressAtSecondTerminate: secondBytes,
                progressAtCancelDecision: cancelBytes, cancelledState: job.state.rawValue, managerClosed: final.isClosed,
                allWorkDrained: !final.hasActiveWork, sshClosedPIDNil: true, beforeStoreCloseCalls: 1, afterStoreCloseCalls: 0,
                nativeReplyStillPending: true, retainedTemporaryPathsBase64: paths)
        }
        delegate.realQuitAfterStoresClose = { [weak self] in
            guard let self, !self.quitFailureRecorded else { throw AppRealTransferGuard.quitHookOrder }
            self.transferDiagnostics.enter(.quitAfterStoresClose); try self.quitHooks.after()
            try self.check("quit-stores-closed-once-before-native-reply", self.quitHooks.beforeCalls == 1 && self.quitHooks.afterCalls == 1)
            try self.check("quit-forbidden-credentials-zero", await self.credentials.forbiddenCalls == 0)
            guard let before = self.quitEvidence else { throw AppRealTransferGuard.quitHookOrder }
            self.quitEvidence = QuitEvidence(jobID: before.jobID, generation: before.generation, serviceID: before.serviceID,
                progressAtFirstTerminate: before.progressAtFirstTerminate, progressAfterContinue: before.progressAfterContinue,
                progressAtSecondTerminate: before.progressAtSecondTerminate, progressAtCancelDecision: before.progressAtCancelDecision,
                cancelledState: before.cancelledState, managerClosed: before.managerClosed, allWorkDrained: before.allWorkDrained,
                sshClosedPIDNil: before.sshClosedPIDNil, beforeStoreCloseCalls: self.quitHooks.beforeCalls,
                afterStoreCloseCalls: self.quitHooks.afterCalls, nativeReplyStillPending: true, retainedTemporaryPathsBase64: before.retainedTemporaryPathsBase64)
            try self.store.cleanupEmptyStore()
            self.quitTimer?.invalidate(); self.quitTimer = nil
            self.transferDiagnostics.enter(.quitReceipt)
            try await self.persistReport(failure: nil, removed: true) // Exclusive+fsync before native reply, never exit().
            try self.quitHooks.committedReceipt()
            guard self.quitHooks.mayReplyToNativeQuit else { throw AppRealTransferGuard.quitHookOrder }
        }
        let consumeSnapshot: @MainActor @Sendable (TransferManagerSnapshot) -> Void = { [weak self] snapshot in
            defer { timerTaskBusy = false }
            guard let self, !self.quitFailureRecorded else { return }
            do {
                guard ProcessInfo.processInfo.systemUptime < decisionState.deadline else { throw AppRealTransferGuard.quitTimeout }
                if let acknowledge = self.find("lifecycle.transfers.retained.acknowledge", NSButton.self), !retainedAcked {
                    guard snapshot.isClosed, !snapshot.hasActiveWork, let job = snapshot.jobs.first(where: { $0.id == first.id }), same(job), job.state == .cancelled,
                          job.retainedTemporaryPaths.map({ $0.bytes.base64EncodedString() }) == [temporary.base64EncodedString()] else { throw AppRealTransferGuard.ownedCleanupLedger }
                    try checkpoint("retained-before-ack", job.transferredBytes, [temporary.base64EncodedString()])
                    acknowledge.performClick(nil); retainedAcked = true
                } else if decisionState.decision == .continueTransfer, !kept, let button = self.find("lifecycle.transfers.continue", NSButton.self) {
                    self.transferDiagnostics.enter(.quitContinueDecision)
                    guard let job = snapshot.jobs.first(where: { $0.id == first.id }), same(job), inflight(job),
                          driver.session.state == .connected, driver.session.ownedProcessID == self.actualPID else { throw AppRealTransferGuard.quitContinueIdentity }
                    continuedBytes = job.transferredBytes; button.performClick(nil); kept = true
                    try checkpoint("continued", continuedBytes, [])
                } else if decisionState.decision == .cancelAndQuit, !cancelClicked, let button = self.find("lifecycle.transfers.cancelClose", NSButton.self) {
                    self.transferDiagnostics.enter(.quitCancelDecision)
                    guard let job = snapshot.jobs.first(where: { $0.id == first.id }), same(job), inflight(job),
                          driver.session.state == .connected, driver.session.ownedProcessID == self.actualPID else { throw AppRealTransferGuard.quitCancelIdentity }
                    cancelBytes = job.transferredBytes; button.performClick(nil); cancelClicked = true
                    try checkpoint("cancel-decision", cancelBytes, [])
                    self.transferDiagnostics.enter(.quitAwaitDrain)
                }
            } catch { self.failQuit((error as? AppRealTransferGuard).map { "transfer." + $0.rawValue } ?? "quit-control-failed") }
        }
        let timer = Timer(timeInterval: 0.025, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, !timerTaskBusy, !self.quitFailureRecorded else { return }
                timerTaskBusy = true
                // AppKit terminateLater can exclude main-queue Swift Tasks. Ask the actor
                // off-main, then synchronously validate/click in the active native run loop.
                Task.detached {
                    let snapshot = await manager.snapshot()
                    RunLoop.main.perform(inModes: [.common, .default, .eventTracking, .modalPanel]) {
                        MainActor.assumeIsolated { consumeSnapshot(snapshot) }
                    }
                }
            }
        }
        quitTimer = timer; RunLoop.main.add(timer, forMode: .common)
        transferDiagnostics.enter(.quitFirstTerminate)
        guard let firstAction = await manager.snapshot().jobs.first(where: { $0.id == first.id }), same(firstAction), inflight(firstAction),
              driver.session.state == .connected, driver.session.ownedProcessID == actualPID else { throw AppRealTransferGuard.quitFirstInflight }
        firstBytes = firstAction.transferredBytes; try checkpoint("before-first-terminate", firstBytes, [])
        RunLoop.main.perform { MainActor.assumeIsolated { NSApp.terminate(nil) } }
        try await wait { kept && !self.model.files.admissionFrozen && !self.model.lifecycle.terminating }
        guard !quitFailureRecorded, delegate.mainWindow === originalWindow, originalWindow.isVisible,
              let continued = await manager.snapshot().jobs.first(where: { $0.id == first.id }), same(continued), inflight(continued),
              await facts.connectionAttempts == 1, await facts.bindings == [binding] else { throw AppRealTransferGuard.quitContinueAdmission }
        decisionState.decision = .cancelAndQuit; decisionState.deadline = ProcessInfo.processInfo.systemUptime + 120
        transferDiagnostics.enter(.quitSecondTerminate)
        guard let second = await manager.snapshot().jobs.first(where: { $0.id == first.id }), same(second), inflight(second),
              driver.session.state == .connected, driver.session.ownedProcessID == actualPID else { throw AppRealTransferGuard.quitSecondInflight }
        secondBytes = second.transferredBytes; try checkpoint("before-second-terminate", secondBytes, [])
        RunLoop.main.perform { MainActor.assumeIsolated { NSApp.terminate(nil) } }
        // Return to run loop. Native AppDelegate hooks persist success before its one true reply.
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
