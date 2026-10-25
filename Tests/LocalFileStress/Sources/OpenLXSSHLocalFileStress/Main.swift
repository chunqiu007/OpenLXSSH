import CryptoKit
import Darwin
import Foundation
import OpenLXSSHFiles
import StressMetrics

private let chunkSize = 65_536
private let minimumFreeBytes: UInt64 = 12 * 1_024 * 1_024 * 1_024

private struct HarnessError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw HarnessError(message) }
}
private func seconds(_ start: UInt64) -> Double {
    Double(DispatchTime.now().uptimeNanoseconds - start) / 1e9
}
private func hex<D: Sequence>(_ bytes: D) -> String where D.Element == UInt8 {
    bytes.map { String(format: "%02x", $0) }.joined()
}
private func pathText(_ path: RemotePath) -> String { String(decoding: path.bytes, as: UTF8.self) }
private func remote(_ text: String) throws -> RemotePath { try RemotePath(text) }

private struct FileDigest: Codable, Equatable {
    let relativePathBase64: String
    let byteCount: UInt64
    let sha256: String
}
private struct Manifest: Codable {
    let label: String
    let files: [FileDigest]
}
private struct Phase: Codable {
    let name: String
    let durationSeconds: Double
    let streamedBytes: UInt64
    let bytesPerSecond: Double
    let outcome: String
    let detail: [String: String]
}
private struct APICounters: Codable, Sendable {
    let openHandles: Int
    let peakOpenHandles: Int
    let successfulOpens: Int
    let successfulCloses: Int
    let closedHandlesByServiceShutdown: Int
    let readBytes: UInt64
    let writtenBytes: UInt64
}
private struct ResourceSample: Codable, Sendable {
    let elapsedSeconds: Double
    let phase: String
    let rssBytes: UInt64
    let processHighWaterRSSBytes: UInt64
    let userCPUSeconds: Double
    let systemCPUSeconds: Double
    let rssStatus: Int32
    let processFDs: Int32
    let ownedRootFDs: Int32
    let api: APICounters
}
private struct Evidence: Encodable {
    let schemaVersion = 1
    let taskID = "P7-LOCAL-FILE-STRESS-A"
    let boundary = "Finite, local Release fixture using production LocalFileService + TransferManager/SafeTransferEngine. Not remote SFTP, network/disconnect, macOS 26 App, Instruments, 24-hour or product PERF acceptance."
    let mode: String
    let startedAt: String
    var endedAt: String?
    var actualDurationSeconds: Double = 0
    var status = "running"
    var error: String?
    let largeFileBytes: UInt64
    let smallFileCount: Int
    let chunkBytes = chunkSize
    let maxConcurrentChunks = 2
    let maxConcurrentJobs = 2
    let samplingIntervalMilliseconds = 100
    let measurement = "Self only, no children spawned: task_info resident_size; Darwin getrusage ru_maxrss bytes and cumulative user/system CPU; proc_pidinfo FD list and vnode paths under the exact owned root; successful public open/closeHandle calls tracked by a forwarding observer. API counters do not claim access to private backend internals."
    let dataPattern = "Fully written deterministic non-secret 64KiB SplitMix64 block, block index in first 8 bytes; no sparse/truncate/clone files. Incremental CryptoKit SHA256 with <=64KiB reads/writes."
    let environment: [String: String]
    let ownedRoot: String
    let ownedRootMode = "0700"
    let minimumFreeDiskBytes = minimumFreeBytes
    var freeDiskBytesAtStart: UInt64 = 0
    var phases: [Phase] = []
    var manifests: [Manifest] = []
    var resources: [ResourceSample] = []
    var cleanup = "not attempted"
    var limitations = ["Local filesystem/cache speed is not network or SFTP throughput.",
                       "Network disconnect, permissions/disk-full, Instruments and remote commit capability are not exercised.",
                       "Cancellation-only read pause is test timing control after actual 25% bytes; ordinary roundtrips are unthrottled."]
}

private actor HandleLedger {
    private var handles: Set<FileHandleID> = []
    private var peak = 0
    private var opens = 0
    private var closes = 0
    private var closedByShutdown = 0
    private var reads: UInt64 = 0
    private var writes: UInt64 = 0
    func opened(_ id: FileHandleID) { handles.insert(id); opens += 1; peak = max(peak, handles.count) }
    func closed(_ id: FileHandleID) { if handles.remove(id) != nil { closes += 1 } }
    func closedByServiceShutdown(_ id: FileHandleID) {
        if handles.remove(id) != nil { closedByShutdown += 1 }
    }
    func read(_ count: Int) { reads += UInt64(count) }
    func wrote(_ count: Int) { writes += UInt64(count) }
    func snapshot() -> APICounters {
        APICounters(openHandles: handles.count, peakOpenHandles: peak, successfulOpens: opens,
                    successfulCloses: closes, closedHandlesByServiceShutdown: closedByShutdown,
                    readBytes: reads, writtenBytes: writes)
    }
}

/// Observation uses only successful public API calls. All bytes/operations reach the real local backend.
private actor ObservedLocal: RemoteFileService {
    nonisolated let local: LocalFileService
    nonisolated var capabilities: FileServiceCapabilities { local.capabilities }
    private let ledger: HandleLedger
    private var handles: [FileHandleID: UInt64] = [:]
    private let pauseAtBytes: UInt64?
    init(root: URL, ledger: HandleLedger, pauseAtBytes: UInt64? = nil) throws {
        local = try LocalFileService(root: root); self.ledger = ledger; self.pauseAtBytes = pauseAtBytes
    }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await local.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await local.lstat(p, token: token) }
    func fstat(_ h: FileHandleID, token: CancellationToken) async throws -> FileAttributes? {
        try await local.fstat(h, token: token)
    }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        let id = try await local.open(p, mode: mode, token: token)
        handles[id] = 0; await ledger.opened(id); return id
    }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        if let pauseAtBytes, handles[h, default: 0] >= pauseAtBytes {
            // A real read produced these bytes. Hold the NEXT read so small mode cannot race to EOF.
            while true { try token.check(); try await Task.sleep(for: .milliseconds(1)) }
        }
        let bytes = try await local.read(h, maxBytes: maxBytes, token: token)
        handles[h, default: 0] += UInt64(bytes.count); await ledger.read(bytes.count); return bytes
    }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        let count = try await local.write(h, data: data, token: token); await ledger.wrote(count); return count
    }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await local.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws {
        try await local.closeHandle(h); handles[h] = nil; await ledger.closed(h)
    }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await local.mkdir(p, token: token) }
    func rename(_ s: RemotePath, to d: RemotePath, mode: RenameMode, token: CancellationToken) async throws {
        try await local.rename(s, to: d, mode: mode, token: token)
    }
    func commit(_ s: RemotePath, to d: RemotePath, request: CommitRequest, token: CancellationToken) async throws {
        try await local.commit(s, to: d, request: request, token: token)
    }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws {
        try await local.remove(p, directory: directory, token: token)
    }
    nonisolated func cancel() { local.cancel() }
    func close() async {
        await local.close()
        let remaining = Array(handles.keys); handles.removeAll()
        for h in remaining { await ledger.closedByServiceShutdown(h) }
    }
}

private actor ResourceMonitor {
    let root: String
    let ledger: HandleLedger
    let start = DispatchTime.now().uptimeNanoseconds
    private var phase = "startup"
    private var samples: [ResourceSample] = []
    init(root: String, ledger: HandleLedger) { self.root = root; self.ledger = ledger }
    func sample(_ label: String? = nil) async {
        if let label { phase = label }
        let measuredPhase = phase
        let api = await ledger.snapshot()
        let m = root.withCString { stress_sample($0) }
        if samples.count < 20_000 {
            samples.append(ResourceSample(elapsedSeconds: seconds(start), phase: measuredPhase,
                rssBytes: m.resident_bytes, processHighWaterRSSBytes: m.peak_resident_bytes,
                userCPUSeconds: m.user_cpu_seconds, systemCPUSeconds: m.system_cpu_seconds,
                rssStatus: m.rss_status, processFDs: m.fd_count, ownedRootFDs: m.owned_fd_count, api: api))
        }
    }
    func result() -> [ResourceSample] { samples }
}

private final class OwnedRoot {
    let url: URL
    private let device: dev_t
    private let inode: ino_t
    init() throws {
        let parent = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        let candidate = parent.appendingPathComponent("OpenLXSSH-LocalFileStress-\(UUID().uuidString)", isDirectory: true)
        guard mkdir(candidate.path, mode_t(0o700)) == 0 else { throw HarnessError("Cannot create exclusive owned UUID directory: \(errno)") }
        var canonical = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard realpath(candidate.path, &canonical) != nil else {
            throw HarnessError("Cannot canonicalize owned root at \(candidate.path)")
        }
        url = URL(fileURLWithPath: String(cString: canonical), isDirectory: true)
        var st = stat()
        guard lstat(url.path, &st) == 0, st.st_uid == getuid(), st.st_mode & mode_t(0o777) == mode_t(0o700) else {
            throw HarnessError("Owned root permission/identity check failed at \(url.path)")
        }
        device = st.st_dev; inode = st.st_ino
    }
    func cleanup() throws {
        var st = stat()
        try require(lstat(url.path, &st) == 0 && st.st_dev == device && st.st_ino == inode &&
                    st.st_uid == getuid() && st.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) &&
                    st.st_mode & mode_t(0o777) == mode_t(0o700), "Refusing cleanup: owned root identity changed")
        // Exact root only; FileManager unlinks symbolic links, it does not recursively follow them.
        try FileManager.default.removeItem(at: url)
        try require(!FileManager.default.fileExists(atPath: url.path), "Owned root still exists after cleanup")
    }
}
private func makeDirectory(_ url: URL) throws {
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                          attributes: [.posixPermissions: 0o700])
}
private func freeBytes(_ url: URL) throws -> UInt64 {
    var fs = statfs()
    try require(statfs(url.path, &fs) == 0, "statfs failed")
    return UInt64(fs.f_bavail) * UInt64(fs.f_bsize)
}
private func splitmix(_ state: inout UInt64) -> UInt64 {
    state &+= 0x9E3779B97F4A7C15
    var x = state; x = (x ^ (x >> 30)) &* 0xBF58476D1CE4E5B9
    x = (x ^ (x >> 27)) &* 0x94D049BB133111EB
    return x ^ (x >> 31)
}
private func generate(_ url: URL, bytes: UInt64, seed: UInt64) throws -> String {
    let fd = Darwin.open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
    try require(fd >= 0, "Exclusive generation open failed: \(errno)")
    defer { Darwin.close(fd) }
    var state = seed
    var block = Data(count: chunkSize)
    block.withUnsafeMutableBytes { raw in
        for offset in stride(from: 0, to: chunkSize, by: 8) {
            raw.storeBytes(of: splitmix(&state).littleEndian, toByteOffset: offset, as: UInt64.self)
        }
    }
    var digest = SHA256(), remaining = bytes, index: UInt64 = 0
    while remaining > 0 {
        block.withUnsafeMutableBytes { $0.storeBytes(of: index.littleEndian, as: UInt64.self) }
        let count = Int(min(remaining, UInt64(chunkSize)))
        let part = block.prefix(count)
        digest.update(data: part)
        var offset = 0
        while offset < count {
            let written = part.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), count - offset) }
            if written < 0 && errno == EINTR { continue }
            try require(written > 0, "Generation write failed: \(errno)"); offset += written
        }
        remaining -= UInt64(count); index += 1
    }
    try require(fsync(fd) == 0, "Generation fsync failed")
    return hex(digest.finalize())
}
private func digest(_ service: any RemoteFileService, _ path: RemotePath, relative: Data? = nil) async throws -> FileDigest {
    let token = CancellationToken()
    let h = try await service.open(path, mode: .read, token: token)
    do {
        var hash = SHA256(), count: UInt64 = 0
        while true {
            let part = try await service.read(h, maxBytes: chunkSize, token: token)
            if part.isEmpty { break }
            hash.update(data: part); count += UInt64(part.count)
        }
        try await service.closeHandle(h)
        return FileDigest(relativePathBase64: (relative ?? path.bytes).base64EncodedString(), byteCount: count, sha256: hex(hash.finalize()))
    } catch { try? await service.closeHandle(h); throw error }
}
private func treeManifest(_ service: any RemoteFileService, root: RemotePath) async throws -> [FileDigest] {
    var result: [FileDigest] = []
    func walk(_ path: RemotePath, _ relative: Data) async throws {
        let entries = try await service.list(path, token: CancellationToken())
        for entry in entries {
            let next = try path.appending(entry.name)
            let name = relative.isEmpty ? entry.name.bytes : relative + Data([47]) + entry.name.bytes
            switch entry.attributes.kind {
            case .directory: try await walk(next, name)
            case .regular: result.append(try await digest(service, next, relative: name))
            default: throw HarnessError("Unexpected non-regular manifest item: \(pathText(next))")
            }
        }
    }
    try await walk(root, Data())
    return result.sorted { $0.relativePathBase64 < $1.relativePathBase64 }
}
private func partialPaths(_ service: any RemoteFileService, root: RemotePath = .root) async throws -> [String] {
    var result: [String] = []
    for entry in try await service.list(root, token: CancellationToken()) {
        let path = try root.appending(entry.name)
        if entry.name.bytes.starts(with: Data(".openlxssh-transfer.".utf8)) { result.append(pathText(path)) }
        if entry.attributes.kind == .directory { result += try await partialPaths(service, root: path) }
    }
    return result
}
private func put(_ service: any RemoteFileService, _ path: RemotePath, bytes: Data) async throws {
    let token = CancellationToken(), h = try await service.open(path, mode: .exclusiveWrite, token: token)
    do {
        var offset = 0
        while offset < bytes.count {
            let n = try await service.write(h, data: Data(bytes.dropFirst(offset)), token: token)
            try require(n > 0, "Sentinel write made no progress"); offset += n
        }
        try await service.finish(h, token: token); try await service.closeHandle(h)
    } catch { try? await service.closeHandle(h); throw error }
}
private func countStates(_ items: [TransferItemResult]) -> [String: String] {
    var succeeded = 0, skipped = 0, failed = 0
    var details: [String: String] = [:]
    for item in items {
        switch item.state {
        case .succeeded: succeeded += 1
        case .skipped: skipped += 1
        case .failed(let e):
            failed += 1; details["failed:\(pathText(item.source))"] = "\(e.kind.rawValue)/\(e.operation)"
        }
    }
    details["succeededItems"] = String(succeeded); details["skippedItems"] = String(skipped); details["failedItems"] = String(failed)
    details["retainedTemporaryPaths"] = items.compactMap(\.retainedTemporary).map(pathText).joined(separator: "\n")
    return details
}

@MainActor private final class Run {
    let root: OwnedRoot
    let ledger = HandleLedger()
    let monitor: ResourceMonitor
    let engine = SafeTransferEngine(scheduler: TransferScheduler(maxConcurrentChunks: 2), chunkSize: chunkSize)
    private var managers: [TransferManager] = []
    private var services: [ObservedLocal] = []
    var evidence: Evidence
    init(mode: String, root: OwnedRoot, environment: [String: String]) {
        self.root = root; monitor = ResourceMonitor(root: root.url.path, ledger: ledger)
        evidence = Evidence(mode: mode, startedAt: ISO8601DateFormatter().string(from: Date()),
            largeFileBytes: mode == "full" ? 2 * 1_024 * 1_024 * 1_024 : 2 * 1_024 * 1_024,
            smallFileCount: mode == "full" ? 1_000 : 5, environment: environment, ownedRoot: root.url.path)
    }
    func newService(_ url: URL, pauseAt: UInt64? = nil) throws -> ObservedLocal {
        let service = try ObservedLocal(root: url, ledger: ledger, pauseAtBytes: pauseAt)
        services.append(service); return service
    }
    func newManager() -> TransferManager {
        let manager = TransferManager(engine: engine, maxConcurrentJobs: 2, idleTimeout: nil)
        managers.append(manager); return manager
    }
    func shutdown() async {
        for manager in managers { await manager.cancelAllAndWait() }
        for service in services { await service.close() }
    }
    func request(_ src: TransferServiceID, _ source: String, _ dst: TransferServiceID, _ destination: String,
                 kind: TransferKind = .file, host: String = "local-fixture") throws -> TransferRequest {
        TransferRequest(hostID: host, source: TransferLocation(serviceID: src, path: try remote(source)),
                        destination: TransferLocation(serviceID: dst, path: try remote(destination)), kind: kind)
    }
    func terminal(_ manager: TransferManager, id: TransferJobID, allowSkip: Bool = false) async throws -> TransferJobSnapshot {
        let deadline = DispatchTime.now().uptimeNanoseconds + 600_000_000_000
        while DispatchTime.now().uptimeNanoseconds < deadline {
            guard let job = await manager.snapshot().jobs.first(where: { $0.id == id }) else { throw HarnessError("Missing job") }
            if !job.state.isActive { return job }
            if let pending = job.pendingDecision {
                let answer: TransferDecisionAnswer
                switch pending.question {
                case .conflict where allowSkip: answer = .conflict(.skip, applyToBatch: false)
                default: throw HarnessError("Unexpected conflict/risk; no blanket acceptance")
                }
                try require(await manager.resolve(pending, answer: answer), "Decision resolution rejected")
            }
            try await Task.sleep(for: .milliseconds(1))
        }
        throw HarnessError("Timed out after 600 seconds waiting for local transfer")
    }
    func copy(_ manager: TransferManager, _ req: TransferRequest, label: String, bytes: UInt64,
              allowSkip: Bool = false, expected: TransferJobState = .succeeded) async throws -> TransferJobSnapshot {
        await monitor.sample(label)
        let start = DispatchTime.now().uptimeNanoseconds
        let id = try await manager.enqueue(req)
        let result = try await terminal(manager, id: id, allowSkip: allowSkip)
        let duration = seconds(start)
        evidence.phases.append(Phase(name: label, durationSeconds: duration, streamedBytes: result.transferredBytes,
            bytesPerSecond: Double(result.transferredBytes) / duration, outcome: result.state.rawValue, detail: countStates(result.items)))
        try require(result.state == expected, "\(label): expected \(expected.rawValue), got \(result.state.rawValue)")
        try require(result.transferredBytes == bytes, "\(label): incorrect cumulative byte progress")
        try require(result.retainedTemporaryPaths.isEmpty, "\(label): retained temporary files")
        return result
    }
    func execute() async throws {
        evidence.freeDiskBytesAtStart = try freeBytes(root.url)
        try require(evidence.freeDiskBytesAtStart >= minimumFreeBytes, "Less than 12 GiB available; full baseline NOT passed")
        await monitor.sample("before-services")
        let sourceURL = root.url.appendingPathComponent("source"), stageURL = root.url.appendingPathComponent("stage")
        let backURL = root.url.appendingPathComponent("roundtrip")
        for url in [sourceURL, stageURL, backURL] { try makeDirectory(url) }
        let generation = DispatchTime.now().uptimeNanoseconds
        await monitor.sample("dataset-generation")
        let expectedLarge = try generate(sourceURL.appendingPathComponent("large.bin"), bytes: evidence.largeFileBytes, seed: 0x4F70656E4C585353)
        let names = ["中文 空格 '引号\" 换行\n e\u{301}", "line\nbreak", "组合-e\u{301}", "quote'\" $;`[]", "emoji-🧪-尾空格 "]
        var smallBytes: UInt64 = 0
        for index in 0..<evidence.smallFileCount {
            let directory = sourceURL.appendingPathComponent("small/层 \(index % 10)")
            try makeDirectory(directory)
            let name = String(format: "%04d-", index) + names[index % names.count] + ".bin"
            let count = UInt64(1_024 + (index * 997) % 49_152); smallBytes += count
            _ = try generate(directory.appendingPathComponent(name), bytes: count, seed: UInt64(index) + 0xF17E)
        }
        evidence.phases.append(Phase(name: "dataset-generation", durationSeconds: seconds(generation),
            streamedBytes: evidence.largeFileBytes + smallBytes, bytesPerSecond: Double(evidence.largeFileBytes + smallBytes) / seconds(generation),
            outcome: "fully-written-and-fsynced", detail: ["smallBytes": String(smallBytes), "largeGenerationSHA256": expectedLarge]))
        let source = try newService(sourceURL), stage = try newService(stageURL), back = try newService(backURL)
        let manager = newManager()
        let src = try await manager.registerService(source), dst = try await manager.registerService(stage), returned = try await manager.registerService(back)
        let activeFDs = root.url.path.withCString { stress_sample($0) }
        try require(activeFDs.owned_fd_count >= 3, "Owned-FD measurement must observe three live local roots, not alias-mismatch zero")
        await monitor.sample("source-incremental-sha256")
        let sourceLarge = try await digest(source, remote("/large.bin"))
        try require(sourceLarge.byteCount == evidence.largeFileBytes && sourceLarge.sha256 == expectedLarge, "Source large generation hash mismatch")
        let sourceSmall = try await treeManifest(source, root: remote("/small"))
        try require(sourceSmall.count == evidence.smallFileCount && sourceSmall.reduce(0, { $0 + $1.byteCount }) == smallBytes, "Source small dataset count/size mismatch")
        evidence.manifests.append(Manifest(label: "large-source", files: [sourceLarge]))
        evidence.manifests.append(Manifest(label: "small-source-raw-filesystem-names", files: sourceSmall))
        _ = try await copy(manager, request(src, "/large.bin", dst, "/large.bin"), label: "large-outbound", bytes: evidence.largeFileBytes)
        _ = try await copy(manager, request(src, "/small", dst, "/small", kind: .tree), label: "small-outbound", bytes: smallBytes)
        await monitor.sample("outbound-incremental-sha256")
        let stageLarge = try await digest(stage, remote("/large.bin")), stageSmall = try await treeManifest(stage, root: remote("/small"))
        try require(stageLarge == sourceLarge && stageSmall == sourceSmall, "Outbound hash/name mismatch")
        evidence.manifests.append(Manifest(label: "large-outbound", files: [stageLarge]))
        evidence.manifests.append(Manifest(label: "small-outbound", files: stageSmall))
        _ = try await copy(manager, request(dst, "/large.bin", returned, "/large.bin"), label: "large-return", bytes: evidence.largeFileBytes)
        _ = try await copy(manager, request(dst, "/small", returned, "/small", kind: .tree), label: "small-return", bytes: smallBytes)
        await monitor.sample("return-incremental-sha256")
        let backLarge = try await digest(back, remote("/large.bin")), backSmall = try await treeManifest(back, root: remote("/small"))
        try require(backLarge == sourceLarge && backSmall == sourceSmall, "Return hash/name mismatch")
        evidence.manifests.append(Manifest(label: "large-return", files: [backLarge]))
        evidence.manifests.append(Manifest(label: "small-return", files: backSmall))

        // A separate complete tree copy gets a real looping symlink; baseline tree stays unchanged.
        _ = try await copy(manager, request(src, "/small", src, "/with-loop", kind: .tree), label: "prepare-separate-symlink-tree", bytes: smallBytes)
        try require(symlink(".", sourceURL.appendingPathComponent("with-loop/loop").path) == 0, "Cannot create owned symlink loop")
        let linked = try await copy(manager, request(src, "/with-loop", dst, "/with-loop", kind: .tree), label: "symlink-loop-explicit-failure", bytes: smallBytes, expected: .failed)
        let failures = linked.items.filter { if case .failed = $0.state { return true }; return false }
        try require(failures.count == 1 && failures.first?.state == .failed(FileServiceError(.symbolicLink, operation: "recursive-kind", path: try remote("/with-loop/loop"))), "Loop must be exactly one explicit symbolicLink failure")
        try require(try await treeManifest(stage, root: remote("/with-loop")) == sourceSmall, "Non-link items in failed tree changed")

        // Small mixed-result case, not a wasteful 1000-item all-skip rerun.
        try await source.mkdir(remote("/mixed"), token: CancellationToken())
        try await stage.mkdir(remote("/mixed"), token: CancellationToken())
        let original = Data("owned-original-not-secret".utf8), fresh = Data("owned-new-not-secret".utf8)
        try await put(source, remote("/mixed/collision"), bytes: fresh); try await put(source, remote("/mixed/new"), bytes: fresh)
        try await put(stage, remote("/mixed/collision"), bytes: original)
        let mixed = try await copy(manager, request(src, "/mixed", dst, "/mixed", kind: .tree), label: "completed-with-skips", bytes: UInt64(fresh.count), allowSkip: true, expected: .completedWithSkips)
        let allItemsSucceeded = mixed.items.allSatisfy { if case .succeeded = $0.state { return true }; return false }
        try require(mixed.items.filter { $0.state == .skipped }.count == 1 && !allItemsSucceeded, "Mixed report overstated success")
        try require(try await digest(stage, remote("/mixed/collision")).sha256 == hex(SHA256.hash(data: original)), "Skipped original changed")

        // Inject a real late target only after the production engine has written/closed its temp.
        await monitor.sample("late-competitor-no-replace")
        let raceStart = DispatchTime.now().uptimeNanoseconds
        let raceTarget = try remote("/late-competitor"), competing = Data("owned-late-competitor-not-secret".utf8)
        let race = try await engine.copy(hostID: "local-late-race", source: source, sourcePath: remote("/mixed/new"),
            destination: stage, destinationPath: raceTarget, token: CancellationToken(), hooks: TransferHooks(beforeCommit: { _, target in
                try require(target == raceTarget, "Unexpected race target")
                try await put(stage, target, bytes: competing)
            }))
        try require(race.items.count == 1 && !race.allSucceeded, "Late competitor falsely succeeded")
        guard case .failed(let raceError) = race.items[0].state, raceError.kind == .conflict else { throw HarnessError("Late competitor must fail no-replace") }
        try require(try await digest(stage, raceTarget).sha256 == hex(SHA256.hash(data: competing)), "Late competitor was overwritten")
        evidence.phases.append(Phase(name: "late-competitor-no-replace", durationSeconds: seconds(raceStart), streamedBytes: UInt64(fresh.count),
            bytesPerSecond: Double(fresh.count) / seconds(raceStart), outcome: "expected-conflict-competitor-preserved", detail: countStates(race.items)))
        try require(try await partialPaths(stage).isEmpty, "Unexpected transfer temp before cancellation scenario")
        await manager.cancelAllAndWait()
        await monitor.sample("main-manager-closed")

        // Two real big-file cancellations: absent final, and unchanged explicitly selected original.
        let cancelSource = try newService(sourceURL, pauseAt: evidence.largeFileBytes / 4)
        let cancelDestination = try newService(stageURL), cancelManager = newManager()
        let a = try await cancelManager.registerService(cancelSource), b = try await cancelManager.registerService(cancelDestination)
        let originalPath = try remote("/cancel-original"), newPath = try remote("/cancel-new")
        try await put(cancelDestination, originalPath, bytes: original)
        let originalDigest = try await digest(cancelDestination, originalPath)
        let originalAttributes = try await cancelDestination.lstat(originalPath, token: CancellationToken())
        let cancelStart = DispatchTime.now().uptimeNanoseconds
        let ids = try await cancelManager.enqueueBatch([
            request(a, "/large.bin", b, "/cancel-new", host: "local-cancel-new"),
            request(a, "/large.bin", b, "/cancel-original", host: "local-cancel-original")
        ])
        var conflictAccepted = false, riskAccepted = false
        var beforeCancel: [TransferJobSnapshot] = []
        let deadline = DispatchTime.now().uptimeNanoseconds + 600_000_000_000
        while true {
            let current = await cancelManager.snapshot().jobs
            for job in current {
                if let pending = job.pendingDecision {
                    switch pending.question {
                    case .conflict(let c) where c.destination == originalPath:
                        conflictAccepted = await cancelManager.resolve(pending, answer: .conflict(.overwrite, applyToBatch: false))
                    case .risk(.overwriteIsAtomicButNotCompareAndSwap(let p)) where p == originalPath:
                        // Explicitly local, single owned target only. NEVER authorizes a remote path/risk.
                        try require(cancelDestination.capabilities.traversal == .localDescriptorNoFollow, "Overwrite policy is local-only")
                        riskAccepted = await cancelManager.resolve(pending, answer: .risk(accepted: true))
                    default: throw HarnessError("Unexpected cancellation decision")
                    }
                }
                try require(job.state.isActive, "Cancellation job completed before 25% observation")
            }
            if current.count == 2 && current.allSatisfy({ $0.transferredBytes >= evidence.largeFileBytes / 4 }) { beforeCancel = current; break }
            try require(DispatchTime.now().uptimeNanoseconds < deadline, "Cancellation progress timed out")
            try await Task.sleep(for: .milliseconds(1))
        }
        try require(conflictAccepted && riskAccepted, "Missing explicit local overwrite decision/risk")
        try require(beforeCancel.allSatisfy { $0.transferredBytes > 0 && $0.transferredBytes <= evidence.largeFileBytes / 2 }, "Cancellation not within 10-50% real progress")
        let tempPathsBefore = try await partialPaths(cancelDestination)
        try require(tempPathsBefore.count == 2, "Expected two real partial temporary files before cancel")
        let cancellingFDs = root.url.path.withCString { stress_sample($0) }
        try require(cancellingFDs.owned_fd_count >= 6, "Must observe two local roots plus four real cancellation handles")
        await monitor.sample("cancel-at-25-percent-before-await")
        let waitStart = DispatchTime.now().uptimeNanoseconds
        await cancelManager.cancelAllAndWait()
        let waitDuration = seconds(waitStart)
        let cancelled = await cancelManager.snapshot()
        try require(cancelled.isClosed && !cancelled.hasActiveWork && cancelled.jobs.count == ids.count, "Manager did not actually finish cancellation")
        try require(cancelled.jobs.allSatisfy { $0.state == .cancelled && $0.cancellationRequested && $0.error?.kind == .cancelled && $0.retainedTemporaryPaths.isEmpty }, "Cancelled report or retained temp is incorrect")
        let verify = try newService(stageURL)
        let afterOriginal = try await digest(verify, originalPath)
        let afterAttributes = try await verify.lstat(originalPath, token: CancellationToken())
        try require(afterOriginal == originalDigest && afterAttributes == originalAttributes, "Cancellation altered original target")
        do {
            _ = try await verify.lstat(newPath, token: CancellationToken()); throw HarnessError("Cancellation left a final partial target")
        } catch let e as FileServiceError where e.kind == .notFound { }
        let retained = try await partialPaths(verify)
        try require(retained.isEmpty, "Cancellation left an unreported temporary")
        let total = cancelled.jobs.reduce(0) { $0 + $1.transferredBytes }
        evidence.phases.append(Phase(name: "large-cancel-and-await", durationSeconds: seconds(cancelStart), streamedBytes: total,
            bytesPerSecond: Double(total) / seconds(cancelStart), outcome: "both-cancelled-at-25-percent-original-and-absent-final-preserved",
            detail: ["progressBytesPerJob": beforeCancel.map { String($0.transferredBytes) }.joined(separator: ","),
                "progressFractionPerJob": beforeCancel.map { String(Double($0.transferredBytes) / Double(evidence.largeFileBytes)) }.joined(separator: ","),
                "cancelAllAndWaitSeconds": String(waitDuration), "temporaryFilesObservedBeforeCancel": tempPathsBefore.joined(separator: "\n"),
                "retainedTemporaryPaths": retained.joined(separator: "\n"), "newFinalExists": "false", "originalIdentityAndHashUnchanged": "true",
                "originalSHA256Before": originalDigest.sha256, "originalSHA256After": afterOriginal.sha256,
                "overwritePolicy": "explicit owned local-only overwriteIsAtomicButNotCompareAndSwap, only /cancel-original; not remote CAS safety",
                "acknowledgedRiskCount": String(cancelled.jobs.flatMap(\.items).flatMap(\.acknowledgedRisks).count)]))
        await shutdown()
        await monitor.sample("all-services-closed-before-cleanup")
        let counters = await ledger.snapshot()
        try require(counters.openHandles == 0 && counters.successfulOpens == counters.successfulCloses, "Public API file handles leaked")
        let final = root.url.path.withCString { stress_sample($0) }
        try require(final.rss_status == 0 && final.fd_count >= 0 && final.owned_fd_count == 0, "Process metrics unavailable or owned-root FDs remain")
    }
}

@main private struct LocalFileStressMain {
    @MainActor static func main() async {
        let args = CommandLine.arguments
        guard args.count == 3, ["small", "full"].contains(args[1]) else {
            print("Usage: OpenLXSSHLocalFileStress small|full /absolute/ignored/evidence.json"); exit(2)
        }
        let output = URL(fileURLWithPath: args[2]).resolvingSymlinksInPath()
        let fixtureRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let buildRoot = fixtureRoot.appendingPathComponent(".build").resolvingSymlinksInPath()
        guard args[2].hasPrefix("/"), output.path.hasPrefix(buildRoot.path + "/"),
              FileManager.default.fileExists(atPath: output.deletingLastPathComponent().path),
              !FileManager.default.fileExists(atPath: output.path) else {
            print("Evidence must be a new absolute path under this fixture's ignored .build directory"); exit(2)
        }
        let start = DispatchTime.now().uptimeNanoseconds
        do {
            let root = try OwnedRoot()
            FileHandle.standardOutput.write(Data("Owned dataset root (preserved on failure): \(root.url.path)\n".utf8))
            let environmentData = Data((ProcessInfo.processInfo.environment["OPENLXSSH_STRESS_CONTEXT"] ?? "{}").utf8)
            let environment = (try? JSONDecoder().decode([String: String].self, from: environmentData)) ?? [:]
            let run = Run(mode: args[1], root: root, environment: environment)
            let monitor = run.monitor
            let sampling = Task.detached {
                while !Task.isCancelled {
                    await monitor.sample()
                    do { try await Task.sleep(for: .milliseconds(100)) } catch { break }
                }
            }
            var code: Int32 = 0
            do {
                try await run.execute()
                try root.cleanup()
                run.evidence.cleanup = "exact owned UUID root identity checked, removed, absence verified"
                run.evidence.status = "passed-local-only"
            } catch {
                code = 1; await run.shutdown()
                run.evidence.status = "failed"
                run.evidence.error = String(describing: error)
                run.evidence.cleanup = "failure: data preserved for inspection at \(root.url.path); services closed, no broad cleanup attempted"
            }
            await run.monitor.sample("finished")
            sampling.cancel(); await sampling.value
            run.evidence.resources = await run.monitor.result()
            run.evidence.actualDurationSeconds = seconds(start)
            run.evidence.endedAt = ISO8601DateFormatter().string(from: Date())
            let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            try encoder.encode(run.evidence).write(to: output, options: [.withoutOverwriting])
            print("\(run.evidence.status) mode=\(args[1]) duration=\(run.evidence.actualDurationSeconds)s evidence=\(output.path)")
            print("cleanup=\(run.evidence.cleanup)")
            if let error = run.evidence.error { print("error=\(error)") }
            exit(code)
        } catch {
            print("Harness setup/evidence failure: \(error)"); exit(1)
        }
    }
}
