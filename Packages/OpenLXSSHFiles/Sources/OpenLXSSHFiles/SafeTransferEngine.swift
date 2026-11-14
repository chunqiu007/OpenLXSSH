import CryptoKit
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
    func onHost<T: Sendable>(_ host: String, token: CancellationToken,
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
public enum ConflictDecision: Sendable, Equatable {
    case fail, skip, overwrite, autoRename
    /// Explicit single-item alternate name. It is never reused implicitly for every item in a tree.
    case renameTo(FileName)
}
private func conflictDestination(_ destination: RemotePath, _ conflict: ConflictDecision) throws -> RemotePath {
    if case .renameTo(let name) = conflict { return try destination.parent.appending(name) }
    return destination
}
public enum TransferItemState: Sendable, Equatable {
    case succeeded(bytes: UInt64)
    case skipped
    case failed(FileServiceError)
}
public struct TransferItemResult: Sendable, Equatable {
    public let source: RemotePath
    public let destination: RemotePath
    public let state: TransferItemState
    /// An owned cleanup failure or a create-acknowledgement-uncertain candidate. The error
    /// distinguishes uncertainty; this is never later authority to scan or delete the path.
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
/// A collision observed by the engine, before any temporary file is created.
/// Directory trees merge existing directories; callbacks resolve file collisions and directory/type conflicts.
public struct TransferConflict: Sendable, Equatable {
    public let source: RemotePath
    public let destination: RemotePath
    public let existing: FileAttributes
    /// The engine's validated source type. Legacy callers leave this unknown.
    public let sourceKind: FileKind
    public init(source: RemotePath, destination: RemotePath, existing: FileAttributes) {
        self.init(source: source, destination: destination, existing: existing, sourceKind: .unknown)
    }
    public init(source: RemotePath, destination: RemotePath, existing: FileAttributes, sourceKind: FileKind) {
        self.source = source; self.destination = destination; self.existing = existing; self.sourceKind = sourceKind
    }
}
public struct TransferHooks: Sendable {
    public let progress: (@Sendable (RemotePath, UInt64) async -> Void)?
    /// Fault/race injection for local integration tests; nil for normal use.
    public let beforeCommit: (@Sendable (RemotePath, RemotePath) async throws -> Void)?
    /// Used only when the initial decision is `.fail`. Alternate-name collisions fail safely,
    /// rather than recursively asking for more names or implicitly overwriting the alternate.
    public let resolveConflict: (@Sendable (TransferConflict) async throws -> ConflictDecision)?
    public init(progress: (@Sendable (RemotePath, UInt64) async -> Void)? = nil,
                beforeCommit: (@Sendable (RemotePath, RemotePath) async throws -> Void)? = nil,
                resolveConflict: (@Sendable (TransferConflict) async throws -> ConflictDecision)? = nil) {
        self.progress = progress; self.beforeCommit = beforeCommit; self.resolveConflict = resolveConflict
    }
}
/// The same engine serves uploads and downloads by swapping source and destination services.
/// No shell or SFTP emulation. Each item has its own exclusive sibling temp; commits use
/// no-replace by default, or explicit risk-confirmed atomic replace with known-race checks.
private actor ScopedCommitEvidenceCache {
    struct Key: Hashable { let server: UUID; let parent: RemotePath }
    struct Value { let confirmation: ServerCommitConfirmation; let expires: ContinuousClock.Instant }
    private var values: [Key: Value] = [:]
    func get(server: UUID, parent: RemotePath) -> ServerCommitConfirmation? {
        let key = Key(server: server, parent: parent)
        guard let value = values[key], value.expires > .now else { values[key] = nil; return nil }
        return value.confirmation
    }
    func put(_ confirmation: ServerCommitConfirmation, server: UUID, parent: RemotePath) {
        if values.count >= 256 { values = values.filter { $0.value.expires > .now }; if values.count >= 256 { values.removeAll() } }
        values[Key(server: server, parent: parent)] = Value(confirmation: confirmation, expires: .now + .seconds(300))
    }
}
public struct SafeTransferEngine: Sendable {
    private let commitEvidence = ScopedCommitEvidenceCache()
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
                     policy: TransferPolicy = .init(), hooks: TransferHooks = .init(),
                     sourceManifest: TransferSourceManifest? = nil) async throws -> TransferReport {
        try sourceManifest?.checkBinding(hostID: hostID, source: source, sourcePath: sourcePath, destination: destination, destinationPath: destinationPath)
        let target = try conflictDestination(destinationPath, conflict)
        let action: ConflictDecision = { if case .renameTo = conflict { return .fail }; return conflict }()
        return try await scheduler.onHost(hostID, token: token) {
            let result = await self.copyFile(source, sourcePath, destination, target, action, token, policy, hooks, manifest: sourceManifest)
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
                          _ policy: TransferPolicy, _ hooks: TransferHooks,
                          acknowledgedRisks: [TransferRisk] = [], manifest: TransferSourceManifest? = nil) async -> TransferItemResult {
        var temporary: RemotePath?
        var retainedProbeDirectory: RemotePath?
        var uncertainTemporary: RemotePath?
        var sourceHandle: FileHandleID?
        var destinationHandle: FileHandleID?
        var risks = acknowledgedRisks
        var attemptedNoReplaceCommit = false
        do {
            try token.check()
            for (service, path) in [(source, sourcePath), (destination, destinationPath)] where service.capabilities.traversal == .remoteComponentLstat {
                let risk = TransferRisk.remotePathChecksAreNotAtomic(path: path)
                try await policy.require(risk); risks.append(risk)
            }
            try await TransferChecks.inspect(source, path: sourcePath, includeLeaf: true, token: token)
            try await TransferChecks.inspect(destination, path: destinationPath, includeLeaf: false, token: token)
            let observed = try await source.lstat(sourcePath, token: token)
            try await manifest?.validateSource(source, path: sourcePath, token: token)
            let attr = try manifest?.entry(sourcePath).attributes ?? observed
            guard attr.kind == .regular else {
                throw FileServiceError(attr.kind == .symbolicLink ? .symbolicLink : .unsupported, operation: "source-kind", path: sourcePath)
            }
            guard destinationPath.name != nil else { throw FileServiceError(.invalidPath, operation: "destination-root") }
            var expectedTarget: FileAttributes?
            var targetDigest: Data?
            do {
                let existing = try await destination.lstat(destinationPath, token: token)
                var decision = conflict
                if decision == .fail, let resolveConflict = hooks.resolveConflict {
                    decision = try await resolveConflict(TransferConflict(source: sourcePath, destination: destinationPath, existing: existing, sourceKind: attr.kind))
                    try token.check()
                    try await manifest?.validateSource(source, path: sourcePath, token: token)
                }
                if decision == .autoRename {
                    return await copyWithAutomaticName(source, sourcePath, destination, destinationPath, token, policy, hooks, manifest: manifest)
                }
                if case .renameTo = decision {
                    let target = try conflictDestination(destinationPath, decision)
                    let alternateHooks = TransferHooks(progress: hooks.progress, beforeCommit: hooks.beforeCommit)
                    return await copyFile(source, sourcePath, destination, target, .fail, token, policy, alternateHooks, acknowledgedRisks: risks, manifest: manifest)
                }
                if decision == .skip {
                    return TransferItemResult(source: sourcePath, destination: destinationPath, state: .skipped, retainedTemporary: nil,
                                              acknowledgedRisks: risks)
                }
                guard decision == .overwrite else { throw FileServiceError(.conflict, operation: "target-exists", path: destinationPath) }
                guard existing.kind == .regular, existing.size != nil, existing.modifiedSeconds != nil,
                      destination.capabilities.canAttemptAtomicReplace else {
                    throw FileServiceError(.unsupported, operation: "overwrite-preconditions", path: destinationPath)
                }
                let risk = TransferRisk.overwriteIsAtomicButNotCompareAndSwap(path: destinationPath)
                try await policy.require(risk); risks.append(risk)
                try await manifest?.validateSource(source, path: sourcePath, token: token)
                expectedTarget = existing
                targetDigest = try await TransferChecks.contentFingerprint(destination, path: destinationPath, token: token)
                guard try await destination.lstat(destinationPath, token: token) == existing else {
                    throw FileServiceError(.raceDetected, operation: "target-changed-during-fingerprint", path: destinationPath)
                }
            } catch let error as FileServiceError where error.kind == .notFound {
                if expectedTarget != nil { throw FileServiceError(.raceDetected, operation: "selected-target-disappeared", path: destinationPath) }
            }
            guard destination.capabilities.exclusiveCreate else { throw FileServiceError(.unsupported, operation: "exclusive-create-unavailable") }
            var serverCommit = policy.serverCommit
            if policy.acceptsTechnicalLimits, destination.terminalFailure == nil, let binding = destination.serverBinding,
               let cached = await commitEvidence.get(server: binding, parent: destinationPath.parent) { serverCommit = cached }
            if expectedTarget == nil && destination.capabilities.noReplace == .needsServerConfirmation {
                let matches = destination.serverBinding != nil && serverCommit?.serverBinding == destination.serverBinding
                    && serverCommit?.parent == destinationPath.parent
                if !matches {
                    let result: NoReplaceProbeResult
                    do { result = try await ServerCommitProbe.verifyForTransfer(service: destination, parent: destinationPath.parent, token: token) }
                    catch let error as FileServiceError where error.kind == .needsCapabilityConfirmation {
                        throw FileServiceError(.unsupported, operation: "upload-safe-commit-unavailable", path: destinationPath, code: error.code)
                    }
                    if !result.retainedPaths.isEmpty { retainedProbeDirectory = result.directory }
                    guard let evidence = result.confirmation, result.error == nil else {
                        let failure = result.error ?? FileServiceError(.unsupported, operation: "upload-safe-commit-unavailable", path: destinationPath)
                        if failure.kind == .needsCapabilityConfirmation {
                            throw FileServiceError(.unsupported, operation: "upload-no-replace-check-failed", path: result.directory, code: failure.code)
                        }
                        throw failure
                    }
                    serverCommit = evidence
                    if policy.acceptsTechnicalLimits, let binding = destination.serverBinding {
                        await commitEvidence.put(evidence, server: binding, parent: destinationPath.parent)
                    }
                }
            }
            try await manifest?.validateSource(source, path: sourcePath, token: token)
            let openedSource = try await source.open(sourcePath, mode: .read, token: token)
            sourceHandle = openedSource
            let sourceCheck = try await SourceIntegrityCheck(service: source, path: sourcePath, handle: openedSource, expected: attr, token: token)
            var requiresSourceDigestRecheck = try await sourceCheck.validate(service: source, handle: openedSource, token: token)
            var owned = false
            for _ in 0..<3 {
                let candidate = try destinationPath.parent.appending(FileName(".openlxssh-transfer.\(UUID().uuidString).part"))
                do {
                    try await manifest?.validateSource(source, path: sourcePath, token: token)
                    destinationHandle = try await destination.open(candidate, mode: .exclusiveWrite, token: token)
                    temporary = candidate; owned = true; break
                } catch let error as FileServiceError where error.kind == .conflict { continue }
                catch let error as FileServiceError where [.timeout, .transport, .cancelled, .closed, .io].contains(error.kind) {
                    uncertainTemporary = candidate
                    throw FileServiceError(error.kind, operation: "transfer-file-create-outcome-uncertain", path: candidate, code: error.code)
                }
            }
            guard owned, let sh = sourceHandle, let dh = destinationHandle else {
                throw FileServiceError(.conflict, operation: "temporary-reservation", path: destinationPath)
            }
            var total: UInt64 = 0
            var sourceDigest = SHA256()
            try await manifest?.validateSource(source, path: sourcePath, token: token)
            while true {
                let data: Data = try await scheduler.chunk(token) {
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
                    return data
                }
                try token.check()
                if data.isEmpty { break }
                total += UInt64(data.count)
                sourceDigest.update(data: data)
                await hooks.progress?(sourcePath, total)
                try token.check()
                if let expected = attr.size, total > expected {
                    throw FileServiceError(.raceDetected, operation: "source-grew-during-read", path: sourcePath)
                }
            }
            try token.check()
            let weakAfterRead = try await sourceCheck.validate(service: source, handle: sh, token: token)
            requiresSourceDigestRecheck = requiresSourceDigestRecheck || weakAfterRead
            if let expected = attr.size, expected != total { throw FileServiceError(.raceDetected, operation: "source-size-changed", path: sourcePath) }
            try token.check()
            do { try await destination.finish(dh, token: token) }
            catch let error as FileServiceError where error.kind == .unsupported && destination.capabilities.traversal == .remoteComponentLstat {
                let risk = TransferRisk.remoteFsyncUnavailable(path: destinationPath)
                try await policy.require(risk); risks.append(risk)
            }
            try await destination.closeHandle(dh); destinationHandle = nil
            guard let temp = temporary else { throw FileServiceError(.integrity, operation: "missing-temporary") }
            try await hooks.beforeCommit?(temp, destinationPath)
            try token.check()
            try await TransferChecks.inspect(destination, path: destinationPath, includeLeaf: false, token: token)
            let weakBeforeCommit = try await sourceCheck.validate(service: source, handle: sh, token: token)
            if requiresSourceDigestRecheck || weakBeforeCommit {
                try await sourceCheck.verifyDigest(service: source, digest: Data(sourceDigest.finalize()), expectedBytes: total,
                                                   scheduler: scheduler, chunkSize: chunkSize, token: token)
                _ = try await sourceCheck.validate(service: source, handle: sh, token: token)
            }
            // Keep the original handle until final path/handle comparison and optional digest finish.
            try await source.closeHandle(sh); sourceHandle = nil
            try token.check()
            try await manifest?.validateSource(source, path: sourcePath, token: token)
            let request = CommitRequest(mode: expectedTarget == nil ? .noReplace : .replaceExisting,
                expectedTarget: expectedTarget, expectedContentSHA256: targetDigest,
                acceptNonCASOverwriteRisk: expectedTarget != nil, serverConfirmation: serverCommit)
            attemptedNoReplaceCommit = expectedTarget == nil
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
            // Resolve only a collision from the actual noReplace commit after its owned
            // temporary was cleaned. Initial rejections and raceDetected never ask again.
            if attemptedNoReplaceCommit, policy.acceptsTechnicalLimits,
               let conflictError = error as? FileServiceError, conflictError.kind == .conflict,
               retained == nil, retainedProbeDirectory == nil, uncertainTemporary == nil,
               !token.isCancelled, let resolve = hooks.resolveConflict {
                do {
                    let existing = try await destination.lstat(destinationPath, token: token)
                    let decision = try await resolve(TransferConflict(source: sourcePath, destination: destinationPath, existing: existing, sourceKind: .regular))
                    try token.check()
                    let once = TransferHooks(progress: hooks.progress, beforeCommit: hooks.beforeCommit)
                    switch decision {
                    case .skip:
                        return TransferItemResult(source: sourcePath, destination: destinationPath, state: .skipped, retainedTemporary: nil, acknowledgedRisks: risks)
                    case .autoRename:
                        return await copyWithAutomaticName(source, sourcePath, destination, destinationPath, token, policy, hooks, manifest: manifest)
                    case .renameTo(let name):
                        return await copyFile(source, sourcePath, destination, try destinationPath.parent.appending(name), .fail, token, policy, once, manifest: manifest)
                    case .overwrite:
                        return await copyFile(source, sourcePath, destination, destinationPath, .overwrite, token, policy, once, manifest: manifest)
                    case .fail: break
                    }
                } catch { return failure(error, source: sourcePath, destination: destinationPath, risks: risks) }
            }
            return failure(error, source: sourcePath, destination: destinationPath, retained: retained ?? retainedProbeDirectory ?? uncertainTemporary, risks: risks)
        }
    }
    /// Keep original filename bytes, including undecodable UTF-8, and add a familiar suffix.
    /// The destination is still committed with noReplace; an existence check grants no overwrite right.
    public static func automaticName(_ original: FileName, index: Int) throws -> FileName {
        guard (1...1000).contains(index) else { throw FileServiceError(.resourceLimit, operation: "automatic-name-index") }
        let bytes = original.bytes
        let dot = bytes.lastIndex(of: 46)
        let split = dot.flatMap { $0 > bytes.startIndex ? $0 : nil } ?? bytes.endIndex
        let suffix = Data(" (\(index))".utf8)
        return try FileName(bytes: Data(bytes[..<split]) + suffix + Data(bytes[split...]))
    }
    private func copyWithAutomaticName(_ source: any RemoteFileService, _ sourcePath: RemotePath,
        _ destination: any RemoteFileService, _ original: RemotePath, _ token: CancellationToken,
        _ policy: TransferPolicy, _ hooks: TransferHooks, manifest: TransferSourceManifest?) async -> TransferItemResult {
        do {
            guard let name = original.name else { throw FileServiceError(.invalidPath, operation: "automatic-name-root") }
            for index in 1...1000 {
                try token.check()
                let candidate = try original.parent.appending(Self.automaticName(name, index: index))
                do { _ = try await destination.lstat(candidate, token: token); continue }
                catch let error as FileServiceError where error.kind == .notFound { }
                let result = await copyFile(source, sourcePath, destination, candidate, .fail, token, policy,
                    TransferHooks(progress: hooks.progress, beforeCommit: hooks.beforeCommit), manifest: manifest)
                if case .failed(let error) = result.state, error.kind == .conflict, result.retainedTemporary == nil { continue }
                return result
            }
            throw FileServiceError(.conflict, operation: "automatic-name-limit", path: original)
        } catch { return failure(error, source: sourcePath, destination: original) }
    }
    /// Recursion is bounded; symlinks/unknown/special files are individual failures, never followed/skipped silently.
    /// Directories are merged; this is deliberately NOT a whole-tree transaction.
    public func copyTree(hostID: String, source: any RemoteFileService, sourcePath: RemotePath,
                         destination: any RemoteFileService, destinationPath: RemotePath,
                         conflict: ConflictDecision = .fail, token: CancellationToken,
                         policy: TransferPolicy = .init(), hooks: TransferHooks = .init(),
                         sourceManifest: TransferSourceManifest? = nil) async throws -> TransferReport {
        try sourceManifest?.checkBinding(hostID: hostID, source: source, sourcePath: sourcePath, destination: destination, destinationPath: destinationPath)
        let target = try conflictDestination(destinationPath, conflict)
        let action: ConflictDecision = { if case .renameTo = conflict { return .fail }; return conflict }()
        // Component prefixes include equality and root's empty prefix, without confusing siblings.
        guard !(ObjectIdentifier(source) == ObjectIdentifier(destination) &&
                target.components.starts(with: sourcePath.components)) else {
            throw FileServiceError(.invalidPath, operation: "copy-tree-into-itself", path: target)
        }
        return try await scheduler.onHost(hostID, token: token) {
            try token.check()
            try await sourceManifest?.validateSource(source, path: sourcePath, token: token)
            guard try await source.lstat(sourcePath, token: token).kind == .directory else {
                throw FileServiceError(.unsupported, operation: "tree-source-kind", path: sourcePath)
            }
            var target = target
            var rootDecision = conflict
            var rootAbsent = false
            if conflict == .fail, policy.acceptsTechnicalLimits, let resolve = hooks.resolveConflict {
                do {
                    let existing = try await destination.lstat(target, token: token)
                    rootDecision = try await resolve(TransferConflict(source: sourcePath, destination: target, existing: existing, sourceKind: .directory))
                    try token.check()
                } catch let error as FileServiceError where error.kind == .notFound { rootAbsent = true }
            }
            // Reserve a new root even when it originally appeared absent. A racing mkdir
            // must go through conflict policy, never turn into an unrequested merge.
            if rootAbsent && policy.acceptsTechnicalLimits {
                try await TransferChecks.inspect(destination, path: target, includeLeaf: false, token: token)
                do { try await destination.mkdir(target, token: token) }
                catch let error as FileServiceError where error.kind == .conflict {
                    let existing = try await destination.lstat(target, token: token)
                    if let resolve = hooks.resolveConflict {
                        rootDecision = try await resolve(TransferConflict(source: sourcePath, destination: target, existing: existing, sourceKind: .directory))
                    } else { throw error }
                }
            }
            if rootDecision == .skip {
                return TransferReport(items: [TransferItemResult(source: sourcePath, destination: target, state: .skipped, retainedTemporary: nil)])
            }
            if rootDecision == .autoRename {
                guard let name = target.name else { throw FileServiceError(.invalidPath, operation: "automatic-name-root") }
                var reserved = false
                for index in 1...1000 {
                    try token.check()
                    let candidate = try target.parent.appending(Self.automaticName(name, index: index))
                    try await TransferChecks.inspect(destination, path: candidate, includeLeaf: false, token: token)
                    do { try await destination.mkdir(candidate, token: token); target = candidate; reserved = true; break }
                    catch let error as FileServiceError where error.kind == .conflict { continue }
                }
                guard reserved else { throw FileServiceError(.conflict, operation: "automatic-name-limit", path: target) }
            }
            if case .renameTo = rootDecision {
                target = try conflictDestination(target, rootDecision)
                if destination.capabilities.traversal == .remoteComponentLstat {
                    try await policy.require(.remotePathChecksAreNotAtomic(path: target))
                }
                try await TransferChecks.inspect(destination, path: target, includeLeaf: false, token: token)
                do {
                    _ = try await destination.lstat(target, token: token)
                    return TransferReport(items: [self.failure(FileServiceError(.conflict, operation: "renamed-tree-target-exists", path: target),
                                                              source: sourcePath, destination: target)])
                } catch let error as FileServiceError where error.kind == .notFound { }
                try await sourceManifest?.validateSource(source, path: sourcePath, token: token)
                if try await source.lstat(sourcePath, token: token).kind == .directory {
                    // Reserve the new top-level name exclusively. A competing mkdir must fail,
                    // not silently convert rename-to into a merge of somebody else's directory.
                    try await destination.mkdir(target, token: token)
                }
            }
            var results: [TransferItemResult] = []
            // Carry the chosen overwrite into the root check; do not ask the same
            // directory/type conflict again. Alternate names are root-only.
            let walkAction: ConflictDecision = rootDecision == .overwrite ? .overwrite : action
            await self.walk(source, sourcePath, destination, target, walkAction, token, policy, hooks, 0, &results, manifest: sourceManifest)
            return TransferReport(items: results)
        }
    }
    private func walk(_ source: any RemoteFileService, _ sourcePath: RemotePath,
                      _ destination: any RemoteFileService, _ destinationPath: RemotePath,
                      _ conflict: ConflictDecision, _ token: CancellationToken, _ policy: TransferPolicy, _ hooks: TransferHooks,
                      _ depth: Int, _ results: inout [TransferItemResult], acknowledgedRisks: [TransferRisk] = [],
                      manifest: TransferSourceManifest? = nil) async {
        var risks = acknowledgedRisks
        do {
            try token.check()
            for (service, path) in [(source, sourcePath), (destination, destinationPath)] where service.capabilities.traversal == .remoteComponentLstat {
                let risk = TransferRisk.remotePathChecksAreNotAtomic(path: path)
                try await policy.require(risk); risks.append(risk)
            }
            try await TransferChecks.inspect(source, path: sourcePath, includeLeaf: true, token: token)
            try await TransferChecks.inspect(destination, path: destinationPath, includeLeaf: false, token: token)
            guard depth <= maxDepth, results.count < maxItems else { throw FileServiceError(.resourceLimit, operation: "recursive-bound", path: sourcePath) }
            let observed = try await source.lstat(sourcePath, token: token)
            try await manifest?.validateSource(source, path: sourcePath, token: token)
            let attr = try manifest?.entry(sourcePath).attributes ?? observed
            if attr.kind == .regular {
                results.append(await copyFile(source, sourcePath, destination, destinationPath, conflict, token, policy, hooks,
                                              acknowledgedRisks: risks, manifest: manifest)); return
            }
            guard attr.kind == .directory else {
                throw FileServiceError(attr.kind == .symbolicLink ? .symbolicLink : .unsupported, operation: "recursive-kind", path: sourcePath)
            }
            do {
                let existing = try await destination.lstat(destinationPath, token: token)
                if existing.kind != .directory {
                    let decision: ConflictDecision
                    if conflict == .fail, let resolveConflict = hooks.resolveConflict {
                        decision = try await resolveConflict(TransferConflict(source: sourcePath, destination: destinationPath, existing: existing, sourceKind: attr.kind))
                        try token.check()
                        try await manifest?.validateSource(source, path: sourcePath, token: token)
                    } else { decision = conflict }
                    if decision == .skip {
                        results.append(TransferItemResult(source: sourcePath, destination: destinationPath, state: .skipped, retainedTemporary: nil,
                                                          acknowledgedRisks: risks))
                        return
                    }
                    if case .renameTo = decision {
                        let target = try conflictDestination(destinationPath, decision)
                        if destination.capabilities.traversal == .remoteComponentLstat {
                            let risk = TransferRisk.remotePathChecksAreNotAtomic(path: target)
                            try await policy.require(risk); risks.append(risk)
                            try token.check()
                        }
                        try await TransferChecks.inspect(destination, path: target, includeLeaf: false, token: token)
                        // Reserve the alternate directory exclusively, just like copyTree(renameTo:).
                        try await manifest?.validateSource(source, path: sourcePath, token: token)
                        try await destination.mkdir(target, token: token)
                        await walk(source, sourcePath, destination, target, .fail, token, policy, hooks, depth, &results, acknowledgedRisks: risks, manifest: manifest)
                        return
                    }
                    throw FileServiceError(.conflict, operation: "directory-conflict", path: destinationPath)
                }
            } catch let error as FileServiceError where error.kind == .notFound {
                try await manifest?.validateSource(source, path: sourcePath, token: token)
                try await destination.mkdir(destinationPath, token: token)
            }
            try await manifest?.validateSource(source, path: sourcePath, token: token)
            let names: [FileName]
            if let manifest { names = try manifest.entry(sourcePath).children ?? [] }
            else { names = try await source.list(sourcePath, token: token).map(\.name) }
            results.append(TransferItemResult(source: sourcePath, destination: destinationPath, state: .succeeded(bytes: 0), retainedTemporary: nil,
                                              acknowledgedRisks: risks))
            for (index, name) in names.enumerated() {
                try token.check()
                guard results.count < maxItems else { throw FileServiceError(.resourceLimit, operation: "recursive-item-bound", path: sourcePath) }
                // Live lists only validate the approved set; they never supply new traversal work.
                try await manifest?.validateSource(source, path: sourcePath, token: token)
                await walk(source, try sourcePath.appending(name), destination, try destinationPath.appending(name),
                           conflict, token, policy, hooks, depth + 1, &results, manifest: manifest)
                if manifest != nil, case .failed(let error)? = results.last?.state, error.kind == .raceDetected { return }
                if token.isCancelled && index + 1 < names.count {
                    throw FileServiceError(.cancelled, operation: "recursive-cancelled-with-remaining-items", path: sourcePath)
                }
            }
        } catch { results.append(failure(error, source: sourcePath, destination: destinationPath, risks: risks)) }
    }
}
