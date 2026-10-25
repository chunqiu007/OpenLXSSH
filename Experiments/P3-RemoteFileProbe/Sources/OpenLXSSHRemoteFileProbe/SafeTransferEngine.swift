import Foundation

private actor AsyncGate {
    let limit: Int
    private var active = 0
    private var waiting: [UUID] = []
    init(limit: Int) { self.limit = limit }
    func acquire(_ token: CancellationToken) async throws {
        guard waiting.count < 128 else { throw FileServiceError(.resourceLimit, operation: "queue") }
        let id = UUID(); waiting.append(id)
        do {
            while true {
                try token.check()
                if waiting.first == id && active < limit {
                    waiting.removeFirst(); active += 1; return
                }
                try await Task.sleep(for: .milliseconds(5))
            }
        } catch {
            waiting.removeAll { $0 == id }
            if error is CancellationError { throw FileServiceError(.cancelled, operation: "queue") }
            throw error
        }
    }
    func release() { precondition(active > 0); active -= 1 }
}
/// Inject one scheduler for the application lifetime. All default engines share this global scheduler.
public actor TransferScheduler {
    public static let shared = TransferScheduler(maxConcurrentChunks: 2)
    private let chunks: AsyncGate
    private var hosts: [String: AsyncGate] = [:]
    private var hostUsers: [String: Int] = [:]
    public init(maxConcurrentChunks: Int) {
        precondition((1...8).contains(maxConcurrentChunks)); chunks = AsyncGate(limit: maxConcurrentChunks)
    }
    fileprivate func onHost<T: Sendable>(_ host: String, token: CancellationToken,
                                         body: @Sendable () async throws -> T) async throws -> T {
        if hosts[host] == nil {
            guard hosts.count < 1024 else { throw FileServiceError(.resourceLimit, operation: "host-queue") }
            hosts[host] = AsyncGate(limit: 1)
        }
        let gate = hosts[host]!
        hostUsers[host, default: 0] += 1
        defer {
            hostUsers[host, default: 1] -= 1
            if hostUsers[host] == 0 { hostUsers[host] = nil; hosts[host] = nil }
        }
        try await gate.acquire(token)
        do { let value = try await body(); await gate.release(); return value }
        catch { await gate.release(); throw error }
    }
    // Internal visibility permits a direct scheduling test without a fake remote service.
    func chunk<T: Sendable>(_ token: CancellationToken,
                                        body: @Sendable () async throws -> T) async throws -> T {
        try await chunks.acquire(token)
        do { let value = try await body(); await chunks.release(); return value }
        catch { await chunks.release(); throw error }
    }
}
public enum ConflictDecision: Sendable { case fail, skip, overwrite }
public enum TransferItemState: Sendable, Equatable {
    case succeeded(bytes: UInt64)
    case skipped
    case failed(FileServiceError)
}
public struct TransferItemResult: Sendable, Equatable {
    public let source: RemotePath
    public let destination: RemotePath
    public let state: TransferItemState
    /// Present when cleanup could not remove this owned temporary file. Never auto-scanned/deleted later.
    public let retainedTemporary: RemotePath?
    public let acknowledgedRisks: [TransferRisk]
    public init(source: RemotePath, destination: RemotePath, state: TransferItemState,
                retainedTemporary: RemotePath?, acknowledgedRisks: [TransferRisk] = []) {
        self.source = source; self.destination = destination; self.state = state
        self.retainedTemporary = retainedTemporary; self.acknowledgedRisks = acknowledgedRisks
    }
}
public struct TransferReport: Sendable {
    public let items: [TransferItemResult]
    public var allSucceeded: Bool {
        !items.isEmpty && items.allSatisfy { if case .succeeded = $0.state { return true }; return false }
    }
}
public struct TransferHooks: Sendable {
    public let progress: (@Sendable (RemotePath, UInt64) async -> Void)?
    /// Fault/race injection for local integration tests; nil for normal use.
    public let beforeCommit: (@Sendable (RemotePath, RemotePath) async throws -> Void)?
    public init(progress: (@Sendable (RemotePath, UInt64) async -> Void)? = nil,
                beforeCommit: (@Sendable (RemotePath, RemotePath) async throws -> Void)? = nil) {
        self.progress = progress; self.beforeCommit = beforeCommit
    }
}
/// The same engine serves uploads and downloads by swapping source and destination services.
/// No shell or SFTP emulation. Each item has its own exclusive sibling temp; commits use
/// no-replace by default, or explicit risk-confirmed atomic replace with known-race checks.
public struct SafeTransferEngine: Sendable {
    public let scheduler: TransferScheduler
    public let chunkSize: Int
    public let maxDepth: Int
    public let maxItems: Int
    public init(scheduler: TransferScheduler = .shared, chunkSize: Int = 65536,
                maxDepth: Int = 32, maxItems: Int = 10000) {
        precondition((1...1024 * 1024).contains(chunkSize)); precondition(maxDepth >= 0 && maxItems > 0)
        self.scheduler = scheduler; self.chunkSize = chunkSize; self.maxDepth = maxDepth; self.maxItems = maxItems
    }
    public func copy(hostID: String, source: any RemoteFileService, sourcePath: RemotePath,
                     destination: any RemoteFileService, destinationPath: RemotePath,
                     conflict: ConflictDecision = .fail, token: CancellationToken,
                     policy: TransferPolicy = .init(), hooks: TransferHooks = .init()) async throws -> TransferReport {
        try await scheduler.onHost(hostID, token: token) {
            let result = await self.copyFile(source, sourcePath, destination, destinationPath, conflict, token, policy, hooks)
            return TransferReport(items: [result])
        }
    }
    private func failure(_ error: Error, source: RemotePath, destination: RemotePath,
                         retained: RemotePath? = nil, risks: [TransferRisk] = []) -> TransferItemResult {
        let typed = error as? FileServiceError ?? FileServiceError(error is CancellationError ? .cancelled : .io, operation: "transfer")
        return TransferItemResult(source: source, destination: destination, state: .failed(typed), retainedTemporary: retained, acknowledgedRisks: risks)
    }
    private func copyFile(_ source: any RemoteFileService, _ sourcePath: RemotePath,
                          _ destination: any RemoteFileService, _ destinationPath: RemotePath,
                          _ conflict: ConflictDecision, _ token: CancellationToken,
                          _ policy: TransferPolicy, _ hooks: TransferHooks) async -> TransferItemResult {
        var temporary: RemotePath?
        var sourceHandle: FileHandleID?
        var destinationHandle: FileHandleID?
        var risks: [TransferRisk] = []
        do {
            try token.check()
            for (service, path) in [(source, sourcePath), (destination, destinationPath)] where service.capabilities.traversal == .remoteComponentLstat {
                let risk = TransferRisk.remotePathChecksAreNotAtomic(path: path)
                try await policy.require(risk); risks.append(risk)
            }
            try await TransferChecks.inspect(source, path: sourcePath, includeLeaf: true, token: token)
            try await TransferChecks.inspect(destination, path: destinationPath, includeLeaf: false, token: token)
            let attr = try await source.lstat(sourcePath, token: token)
            guard attr.kind == .regular else {
                throw FileServiceError(attr.kind == .symbolicLink ? .symbolicLink : .unsupported, operation: "source-kind", path: sourcePath)
            }
            guard destinationPath.name != nil else { throw FileServiceError(.invalidPath, operation: "destination-root") }
            var expectedTarget: FileAttributes?
            var targetDigest: Data?
            do {
                let existing = try await destination.lstat(destinationPath, token: token)
                if conflict == .skip {
                    return TransferItemResult(source: sourcePath, destination: destinationPath, state: .skipped, retainedTemporary: nil)
                }
                guard conflict == .overwrite else { throw FileServiceError(.conflict, operation: "target-exists", path: destinationPath) }
                guard existing.kind == .regular, existing.size != nil, existing.modifiedSeconds != nil,
                      destination.capabilities.canAttemptAtomicReplace else {
                    throw FileServiceError(.unsupported, operation: "overwrite-preconditions", path: destinationPath)
                }
                let risk = TransferRisk.overwriteIsAtomicButNotCompareAndSwap(path: destinationPath)
                try await policy.require(risk); risks.append(risk)
                expectedTarget = existing
                targetDigest = try await TransferChecks.contentFingerprint(destination, path: destinationPath, token: token)
                guard try await destination.lstat(destinationPath, token: token) == existing else {
                    throw FileServiceError(.raceDetected, operation: "target-changed-during-fingerprint", path: destinationPath)
                }
            } catch let error as FileServiceError where error.kind == .notFound {
                if expectedTarget != nil { throw FileServiceError(.raceDetected, operation: "selected-target-disappeared", path: destinationPath) }
            }
            guard destination.capabilities.exclusiveCreate else { throw FileServiceError(.unsupported, operation: "exclusive-create-unavailable") }
            if expectedTarget == nil && destination.capabilities.noReplace == .needsServerConfirmation {
                guard let binding = destination.serverBinding, policy.serverCommit?.serverBinding == binding else {
                    throw FileServiceError(.needsCapabilityConfirmation, operation: "server-no-replace-unproven", path: destinationPath)
                }
            }
            sourceHandle = try await source.open(sourcePath, mode: .read, token: token)
            var owned = false
            for _ in 0..<3 {
                let candidate = try destinationPath.parent.appending(FileName(".openlxssh-p3.\(UUID().uuidString).part"))
                do {
                    destinationHandle = try await destination.open(candidate, mode: .exclusiveWrite, token: token)
                    temporary = candidate; owned = true; break
                } catch let error as FileServiceError where error.kind == .conflict { continue }
            }
            guard owned, let sh = sourceHandle, let dh = destinationHandle else {
                throw FileServiceError(.conflict, operation: "temporary-reservation", path: destinationPath)
            }
            var total: UInt64 = 0
            while true {
                let count: Int = try await scheduler.chunk(token) {
                    try token.check()
                    let data = try await source.read(sh, maxBytes: self.chunkSize, token: token)
                    guard data.count <= self.chunkSize else { throw FileServiceError(.integrity, operation: "oversized-read") }
                    var offset = 0
                    while offset < data.count {
                        try token.check()
                        let written = try await destination.write(dh, data: Data(data.dropFirst(offset)), token: token)
                        guard written > 0, written <= data.count - offset else { throw FileServiceError(.integrity, operation: "short-write") }
                        offset += written
                    }
                    return data.count
                }
                if count == 0 { break }
                total += UInt64(count)
                await hooks.progress?(sourcePath, total)
            }
            if let expected = attr.size, expected != total { throw FileServiceError(.integrity, operation: "source-size-changed", path: sourcePath) }
            try token.check()
            do { try await destination.finish(dh, token: token) }
            catch let error as FileServiceError where error.kind == .unsupported && destination.capabilities.traversal == .remoteComponentLstat {
                let risk = TransferRisk.remoteFsyncUnavailable(path: destinationPath)
                try await policy.require(risk); risks.append(risk)
            }
            try await source.closeHandle(sh); sourceHandle = nil
            try await destination.closeHandle(dh); destinationHandle = nil
            guard let temp = temporary else { throw FileServiceError(.integrity, operation: "missing-temporary") }
            try await hooks.beforeCommit?(temp, destinationPath)
            try token.check()
            try await TransferChecks.inspect(destination, path: destinationPath, includeLeaf: false, token: token)
            let request = CommitRequest(mode: expectedTarget == nil ? .noReplace : .replaceExisting,
                expectedTarget: expectedTarget, expectedContentSHA256: targetDigest,
                acceptNonCASOverwriteRisk: expectedTarget != nil, serverConfirmation: policy.serverCommit)
            try await destination.commit(temp, to: destinationPath, request: request, token: token)
            temporary = nil
            // Cancellation after the atomic commit cannot undo a completed item; report the actual outcome.
            return TransferItemResult(source: sourcePath, destination: destinationPath, state: .succeeded(bytes: total),
                                      retainedTemporary: nil, acknowledgedRisks: risks)
        } catch {
            if let sourceHandle { try? await source.closeHandle(sourceHandle) }
            if let destinationHandle { try? await destination.closeHandle(destinationHandle) }
            var retained: RemotePath?
            if let temporary {
                do {
                    let cleanup = CancellationToken()
                    try await TransferChecks.inspect(destination, path: temporary, includeLeaf: false, token: cleanup)
                    try await destination.remove(temporary, directory: false, token: cleanup)
                } catch { retained = temporary }
            }
            return failure(error, source: sourcePath, destination: destinationPath, retained: retained, risks: risks)
        }
    }
    /// Recursion is bounded; symlinks/unknown/special files are individual failures, never followed/skipped silently.
    /// Directories are merged; this is deliberately NOT a whole-tree transaction.
    public func copyTree(hostID: String, source: any RemoteFileService, sourcePath: RemotePath,
                         destination: any RemoteFileService, destinationPath: RemotePath,
                         conflict: ConflictDecision = .fail, token: CancellationToken,
                         policy: TransferPolicy = .init(), hooks: TransferHooks = .init()) async throws -> TransferReport {
        try await scheduler.onHost(hostID, token: token) {
            var results: [TransferItemResult] = []
            await self.walk(source, sourcePath, destination, destinationPath, conflict, token, policy, hooks, 0, &results)
            return TransferReport(items: results)
        }
    }
    private func walk(_ source: any RemoteFileService, _ sourcePath: RemotePath,
                      _ destination: any RemoteFileService, _ destinationPath: RemotePath,
                      _ conflict: ConflictDecision, _ token: CancellationToken, _ policy: TransferPolicy, _ hooks: TransferHooks,
                      _ depth: Int, _ results: inout [TransferItemResult]) async {
        do {
            try token.check()
            var risks: [TransferRisk] = []
            for (service, path) in [(source, sourcePath), (destination, destinationPath)] where service.capabilities.traversal == .remoteComponentLstat {
                let risk = TransferRisk.remotePathChecksAreNotAtomic(path: path)
                try await policy.require(risk); risks.append(risk)
            }
            try await TransferChecks.inspect(source, path: sourcePath, includeLeaf: true, token: token)
            try await TransferChecks.inspect(destination, path: destinationPath, includeLeaf: false, token: token)
            guard depth <= maxDepth, results.count < maxItems else { throw FileServiceError(.resourceLimit, operation: "recursive-bound", path: sourcePath) }
            let attr = try await source.lstat(sourcePath, token: token)
            if attr.kind == .regular {
                results.append(await copyFile(source, sourcePath, destination, destinationPath, conflict, token, policy, hooks)); return
            }
            guard attr.kind == .directory else {
                throw FileServiceError(attr.kind == .symbolicLink ? .symbolicLink : .unsupported, operation: "recursive-kind", path: sourcePath)
            }
            do {
                let existing = try await destination.lstat(destinationPath, token: token)
                guard existing.kind == .directory else { throw FileServiceError(.conflict, operation: "directory-conflict", path: destinationPath) }
            } catch let error as FileServiceError where error.kind == .notFound {
                try await destination.mkdir(destinationPath, token: token)
            }
            let entries = try await source.list(sourcePath, token: token)
            results.append(TransferItemResult(source: sourcePath, destination: destinationPath, state: .succeeded(bytes: 0), retainedTemporary: nil,
                                              acknowledgedRisks: risks))
            for (index, entry) in entries.enumerated() {
                try token.check()
                guard results.count < maxItems else { throw FileServiceError(.resourceLimit, operation: "recursive-item-bound", path: sourcePath) }
                // Name was validated as one raw component; destination service also rejects symlinked ancestors.
                await walk(source, try sourcePath.appending(entry.name), destination, try destinationPath.appending(entry.name),
                           conflict, token, policy, hooks, depth + 1, &results)
                if token.isCancelled && index + 1 < entries.count {
                    throw FileServiceError(.cancelled, operation: "recursive-cancelled-with-remaining-items", path: sourcePath)
                }
            }
        } catch { results.append(failure(error, source: sourcePath, destination: destinationPath)) }
    }
}
