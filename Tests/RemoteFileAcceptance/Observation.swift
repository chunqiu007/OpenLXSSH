import Darwin
import Foundation
import OpenLXSSHFiles
import RemoteFileMetrics
import StressMetrics

struct APICounters: Codable, Sendable {
    let openHandles: Int
    let peakHandles: Int
    let successfulOpens: Int
    let successfulCloses: Int
    let closedByServiceShutdown: Int
    let closeCallsFailed: Int
    let readBytes: UInt64
    let writtenBytes: UInt64
    let largestRead: Int
    let largestWrite: Int
}
actor Ledger {
    private var handles: Set<FileHandleID> = []
    private var peak = 0, opens = 0, closes = 0, shutdown = 0, failedClose = 0
    private var reads: UInt64 = 0, writes: UInt64 = 0
    private var maxRead = 0, maxWrite = 0
    func opened(_ h: FileHandleID) { handles.insert(h); opens += 1; peak = max(peak, handles.count) }
    func closed(_ h: FileHandleID) { if handles.remove(h) != nil { closes += 1 } }
    func failedCloseCall() { failedClose += 1 }
    func serviceClosed(_ remaining: [FileHandleID]) { for h in remaining where handles.remove(h) != nil { shutdown += 1 } }
    func read(_ count: Int) { reads += UInt64(count); maxRead = max(maxRead, count) }
    func wrote(_ count: Int) { writes += UInt64(count); maxWrite = max(maxWrite, count) }
    func snapshot() -> APICounters { APICounters(openHandles: handles.count, peakHandles: peak, successfulOpens: opens,
        successfulCloses: closes, closedByServiceShutdown: shutdown, closeCallsFailed: failedClose,
        readBytes: reads, writtenBytes: writes, largestRead: maxRead, largestWrite: maxWrite) }
}

/// Forwards every production call unchanged. It observes successful public API events only;
/// no fake bytes, capability, fstat, error, cancellation timing, rename result or confirmation.
actor ObservedService: RemoteFileService {
    nonisolated let backend: any RemoteFileService
    nonisolated let remoteRoot: RemotePath?
    nonisolated var capabilities: FileServiceCapabilities { backend.capabilities }
    nonisolated var serverBinding: UUID? { backend.serverBinding }
    let ledger: Ledger
    private var handles: Set<FileHandleID> = []
    private var owned: [RemotePath: Bool] = [:] // Only successful mkdir/exclusive open/rename/commit.
    private var temporaryHistory: Set<RemotePath> = []
    private var finishCalls = 0, finishUnsupported = 0
    private(set) var closeCompleted = false
    init(_ backend: any RemoteFileService, ledger: Ledger, remoteRoot: RemotePath? = nil, ownsLocalRoot: Bool = false) {
        self.backend = backend; self.ledger = ledger; self.remoteRoot = remoteRoot
        if ownsLocalRoot { owned[.root] = true }
    }
    nonisolated func checkWrite(_ path: RemotePath) throws {
        guard let remoteRoot else { return }
        guard path == remoteRoot || path.bytes.starts(with: remoteRoot.bytes + Data([47])) else {
            throw FileServiceError(.invalidPath, operation: "campaign-write-scope", path: path)
        }
    }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        let entries = try await backend.list(path, token: token)
        if remoteRoot != nil && (path.bytes == raw(Fixed.corpus) || path.bytes.starts(with: raw(Fixed.corpus + "/"))) {
            try checkCorpusListing(path: path, entries: entries)
        }
        return entries
    }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await backend.lstat(path, token: token) }
    func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await backend.fstat(handle, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        if mode == .exclusiveWrite { try checkWrite(path) }
        let h = try await backend.open(path, mode: mode, token: token)
        handles.insert(h); await ledger.opened(h)
        if mode == .exclusiveWrite {
            owned[path] = false
            if path.name?.bytes.starts(with: raw(".openlxssh-transfer.")) == true { temporaryHistory.insert(path) }
        }
        return h
    }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        let bytes = try await backend.read(handle, maxBytes: maxBytes, token: token)
        await ledger.read(bytes.count); return bytes
    }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        let count = try await backend.write(handle, data: data, token: token)
        await ledger.wrote(count); return count
    }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws {
        do { try await backend.finish(handle, token: token); finishCalls += 1 }
        catch let error as FileServiceError {
            if error.kind == .unsupported { finishUnsupported += 1 }
            throw error
        }
    }
    func finishEvidence() -> [String: String] { ["successfulActualFinishCalls": String(finishCalls), "actualUnsupportedErrors": String(finishUnsupported)] }
    func closeHandle(_ handle: FileHandleID) async throws {
        do { try await backend.closeHandle(handle); handles.remove(handle); await ledger.closed(handle) }
        catch { await ledger.failedCloseCall(); throw error }
    }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws {
        try checkWrite(path); try await backend.mkdir(path, token: token); owned[path] = true
    }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws {
        try checkWrite(source); try checkWrite(destination)
        try await backend.rename(source, to: destination, mode: mode, token: token)
        if let kind = owned.removeValue(forKey: source) { owned[destination] = kind }
    }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws {
        try checkWrite(source); try checkWrite(destination)
        try await backend.commit(source, to: destination, request: request, token: token)
        if let kind = owned.removeValue(forKey: source) { owned[destination] = kind }
    }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws {
        try checkWrite(path)
        // Engine/probe cleanup may mention an absent post-rename source; allow only within
        // the exact UUID namespace. Final cleanup below has stricter successful-creation gates.
        try await backend.remove(path, directory: directory, token: token); owned[path] = nil
    }
    nonisolated func cancel() { backend.cancel() }
    func close() async {
        await backend.close(); await ledger.serviceClosed(Array(handles)); handles.removeAll(); closeCompleted = true
    }
    func temporaryPaths() -> [String] { temporaryHistory.map { $0.bytes.base64EncodedString() }.sorted() }
    func ownedMetadata() -> [OwnedPath] { owned.map { OwnedPath(pathBase64: $0.key.bytes.base64EncodedString(), directory: $0.value) }.sorted { $0.pathBase64 < $1.pathBase64 } }
    func remainingTransferTemporaries() -> [RemotePath] { owned.keys.filter { $0.name?.bytes.starts(with: raw(".openlxssh-transfer.")) == true } }
    func cleanupOwned(root: RemotePath) async throws {
        guard owned[root] == true else { throw GateError.cleanup }
        let paths = owned.keys.filter { root == .root || $0 == root || $0.bytes.starts(with: root.bytes + Data([47])) }
        try require(paths.count == owned.count, .cleanup)
        // Preflight every known directory BEFORE deletion. Unknown/symlink children stop cleanup;
        // no recursive discovery or adoption of an unknown server path is permitted.
        for path in paths {
            try await inspect(backend, path)
            let a = try await backend.lstat(path, token: CancellationToken())
            try require(a.kind == (owned[path] == true ? .directory : .regular), .cleanup)
            if owned[path] == true {
                let listed = try await backend.list(path, token: CancellationToken())
                let expected = Set(paths.filter { $0 != path && $0.parent == path }.map { $0.name!.bytes })
                try require(Set(listed.map { $0.name.bytes }) == expected && listed.count == expected.count, .cleanup)
                try require(listed.allSatisfy { entry in
                    guard let child = try? path.appending(entry.name), let directory = owned[child] else { return false }
                    return entry.attributes.kind == (directory ? .directory : .regular)
                }, .cleanup)
            }
        }
        for path in paths.sorted(by: { $0.bytes.count > $1.bytes.count }) {
            guard let directory = owned[path] else { throw GateError.cleanup }
            try await inspect(backend, path)
            let a = try await backend.lstat(path, token: CancellationToken())
            try require(a.kind == (directory ? .directory : .regular), .cleanup)
            if directory { try require(try await backend.list(path, token: CancellationToken()).isEmpty, .cleanup) }
            if path == .root { continue } // Local descriptor root is unlinked by its retained parent/inode owner.
            try await backend.remove(path, directory: directory, token: CancellationToken()); owned[path] = nil
        }
    }
}
func checkCorpusListing(path: RemotePath, entries: [DirectoryEntry]) throws {
    let prefix = raw(Fixed.corpus)
    guard path.bytes == prefix || path.bytes.starts(with: prefix + Data([47])) else { throw GateError.corpus }
    let relative = path.bytes == prefix ? Data() : Data(path.bytes.dropFirst(prefix.count + 1))
    var expected: [Data: FileKind] = [:]
    for (item, _) in Fixed.specifications {
        let parts = Array(raw(item)).split(separator: UInt8(47)).map { Data($0) }
        let parent = parts.dropLast().reduce(Data()) { $0.isEmpty ? $1 : $0 + Data([47]) + $1 }
        if parent == relative { expected[parts.last!] = .regular }
    }
    if relative.isEmpty {
        expected[raw("manifest.json")] = .regular
        for dir in Fixed.directories { expected[raw(dir)] = .directory }
    }
    if relative == raw("links") { for name in Fixed.links { expected[raw(String(name.split(separator: "/").last!))] = .symbolicLink } }
    try require(entries.count == expected.count && Set(entries.map { $0.name.bytes }).count == expected.count &&
        entries.allSatisfy { expected[$0.name.bytes] == $0.attributes.kind }, .corpus)
}
struct OwnedPath: Codable, Sendable { let pathBase64: String; let directory: Bool }
struct Resource: Codable, Sendable {
    let elapsedSeconds: Double
    let phase: String
    let rssBytes: UInt64
    let processHighWaterRSSBytes: UInt64
    let userCPUSeconds: Double
    let systemCPUSeconds: Double
    let processFDs: Int32
    let ownedRootFDs: Int32
    let fixtureSockets: Int32
    let rssStatus: Int32
    let api: APICounters
}
actor Monitor {
    let root: String, ledger: Ledger, start: UInt64
    private var phase = "startup", samples: [Resource] = []
    init(root: String, ledger: Ledger) { self.root = root; self.ledger = ledger; start = DispatchTime.now().uptimeNanoseconds }
    func sample(_ label: String? = nil) async {
        if let label { phase = label }
        let label = phase, api = await ledger.snapshot(), metrics = root.withCString { stress_sample($0) }
        if samples.count < 20_000 { samples.append(Resource(elapsedSeconds: elapsed(start), phase: label,
            rssBytes: metrics.resident_bytes, processHighWaterRSSBytes: metrics.peak_resident_bytes,
            userCPUSeconds: metrics.user_cpu_seconds, systemCPUSeconds: metrics.system_cpu_seconds,
            processFDs: metrics.fd_count, ownedRootFDs: metrics.owned_fd_count, fixtureSockets: remote_file_fixture_sockets(),
            rssStatus: metrics.rss_status, api: api)) }
    }
    func result() -> [Resource] { samples }
}
