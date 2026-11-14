#if HOST_PROBE
import Foundation
import OpenLXSSHFiles

/// Explicit real-local backend for isolated App GUI verification, never SFTP emulation.
actor LocalFilesProbeConnector: FilesConnecting {
    let root: URL
    private(set) var count = 0
    private let control = LocalFilesProbeControl()
    init(root: URL) { self.root = root }
    func holdTransfer() async { await control.arm() }
    func waitForTransfer() async { await control.arrived() }
    func releaseTransfer() async { await control.release() }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        count += 1; try token.check()
        guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "local-gui-stale") }
        return try LocalFilesProbeService(root: root, control: control)
    }
}
private actor LocalFilesProbeControl {
    private var held = false, reached = false
    private var observers: [CheckedContinuation<Void, Never>] = []
    func arm() { held = true; reached = false }
    func wait(_ token: CancellationToken) async throws {
        if held { reached = true; let current = observers; observers = []; current.forEach { $0.resume() } }
        while held { try token.check(); try await Task.sleep(for: .milliseconds(5)) }
    }
    func arrived() async { if !reached { await withCheckedContinuation { observers.append($0) } } }
    func release() { held = false }
}
private actor LocalFilesProbeService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: LocalFileService
    let control: LocalFilesProbeControl
    init(root: URL, control: LocalFilesProbeControl) throws { base = try LocalFileService(root: root); self.control = control }
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(p, token: token) }
    func fstat(_ h: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(h, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await control.wait(token); return try await base.read(h, maxBytes: maxBytes, token: token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await control.wait(token); return try await base.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await base.mkdir(p, token: token) }
    func rename(_ a: RemotePath, to b: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(a, to: b, mode: mode, token: token) }
    func commit(_ a: RemotePath, to b: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await base.commit(a, to: b, request: request, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(p, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { await base.close() }
}
#endif
