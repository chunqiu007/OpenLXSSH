import Foundation

public typealias TransferServiceID = UUID
public typealias TransferJobID = UUID
public typealias TransferBatchID = UUID

public struct TransferLocation: Sendable, Equatable {
    public let serviceID: TransferServiceID
    public let path: RemotePath
    public init(serviceID: TransferServiceID, path: RemotePath) { self.serviceID = serviceID; self.path = path }
}
public enum TransferKind: String, Sendable { case file, tree }
/// Descriptors contain identity and paths only, never services, authentication or file contents.
public struct TransferRequest: Sendable, Equatable {
    public let hostID: String
    public let batchID: TransferBatchID
    public let source: TransferLocation
    public let destination: TransferLocation
    public let kind: TransferKind
    public init(hostID: String, batchID: TransferBatchID = UUID(), source: TransferLocation,
                destination: TransferLocation, kind: TransferKind = .file) {
        self.hostID = hostID; self.batchID = batchID; self.source = source; self.destination = destination; self.kind = kind
    }
}
public enum TransferJobState: String, Sendable {
    case queued, running, waitingConflict, waitingRisk, succeeded, skipped, failed, cancelled
    /// No failures, but at least one item was skipped and at least one succeeded (possibly a directory).
    /// Only a report in which every item succeeded is `.succeeded`.
    case completedWithSkips
    public var isActive: Bool {
        switch self {
        case .queued, .running, .waitingConflict, .waitingRisk: true
        case .succeeded, .completedWithSkips, .skipped, .failed, .cancelled: false
        }
    }
}
public enum TransferDecisionQuestion: Sendable, Equatable {
    case conflict(TransferConflict)
    case risk(TransferRisk)
}
/// A fresh ID for every question, bound to one immutable job generation.
public struct TransferDecisionRequest: Sendable, Equatable {
    public let id: UUID
    public let jobID: TransferJobID
    public let generation: UUID
    public let question: TransferDecisionQuestion
}
public enum TransferDecisionAnswer: Sendable, Equatable {
    /// Only overwrite/skip can be reused. A concrete renameTo is always a single-item name.
    case conflict(ConflictDecision, applyToBatch: Bool)
    /// Risk acknowledgement is never inferred from overwrite, nor applied to another risk.
    case risk(accepted: Bool)
}
public struct TransferJobSnapshot: Sendable, Equatable {
    public let id: TransferJobID
    public let generation: UUID
    public let retryOf: TransferJobID?
    public let request: TransferRequest
    public let state: TransferJobState
    /// Cumulative streamed bytes, including an incomplete item; not a claim of committed bytes.
    public let transferredBytes: UInt64
    public let cancellationRequested: Bool
    public let pendingDecision: TransferDecisionRequest?
    public let error: FileServiceError?
    public let items: [TransferItemResult]
    public var retainedTemporaryPaths: [RemotePath] { items.compactMap(\.retainedTemporary) }
}
public enum TransferServiceOperationScheduling: Sendable {
    /// Raw list/mkdir-style operations share the engine's per-host scheduler.
    case serialized
    /// Lifetime protection only. Use for SafeFileOperations/ServerCommitProbe, which acquire
    /// their own host gate. They must use the same scheduler as the manager's transfer engine.
    case callerScheduled
}
public struct TransferServiceOperationSnapshot: Sendable, Equatable {
    public let id: UUID
    public let serviceID: TransferServiceID
    public let hostID: String
    public let cancellationRequested: Bool
}
public struct TransferManagerSnapshot: Sendable, Equatable {
    public let jobs: [TransferJobSnapshot]
    public let isClosed: Bool
    public let serviceOperations: [TransferServiceOperationSnapshot]
    public init(jobs: [TransferJobSnapshot], isClosed: Bool, serviceOperations: [TransferServiceOperationSnapshot] = []) {
        self.jobs = jobs; self.isClosed = isClosed; self.serviceOperations = serviceOperations
    }
    public var hasActiveWork: Bool { !serviceOperations.isEmpty || jobs.contains { $0.state.isActive } }
}

private enum ServiceOperationContext {
    @TaskLocal static var managers: Set<ObjectIdentifier> = []
}

/// Application-owned transfer lifetime. Hold this actor in the application coordinator, NOT a
/// panel/terminal model. Dropping an AsyncStream subscription has no effect on jobs or services.
/// No SSH/terminal/UI dependency, automatic reconnect, persistent queue or pretend resume.
public actor TransferManager {
    private struct ServiceRecord {
        let service: any RemoteFileService
        let hostID: String?
        var users = 0
        var idleGeneration = UUID()
        var idleTask: Task<Void, Never>?
        var closing: Task<Void, Never>?
    }
    private struct JobRecord {
        let id: TransferJobID
        let generation = UUID()
        let retryOf: TransferJobID?
        let request: TransferRequest
        let serverConfirmation: ServerCommitConfirmation?
        let token = CancellationToken()
        var state: TransferJobState = .queued
        var bytes: UInt64 = 0
        var progress: [RemotePath: UInt64] = [:]
        var pending: TransferDecisionRequest?
        var reply: CheckedContinuation<TransferDecisionAnswer?, Never>?
        var error: FileServiceError?
        var items: [TransferItemResult] = []
        var snapshot: TransferJobSnapshot {
            TransferJobSnapshot(id: id, generation: generation, retryOf: retryOf, request: request, state: state,
                transferredBytes: bytes, cancellationRequested: token.isCancelled, pendingDecision: pending,
                error: error, items: items)
        }
    }
    private struct ServiceOperationRecord {
        let id: UUID
        let serviceID: TransferServiceID
        let hostID: String
        let token: CancellationToken
        /// Resolves only after the closure and its cleanup have actually returned.
        let drain: Task<Void, Never>
        var snapshot: TransferServiceOperationSnapshot {
            TransferServiceOperationSnapshot(id: id, serviceID: serviceID, hostID: hostID, cancellationRequested: token.isCancelled)
        }
    }
    private struct BatchKey: Hashable { let hostID: String; let batchID: TransferBatchID }
    private let engine: SafeTransferEngine
    private let maxConcurrentJobs: Int
    private let maxQueuedJobs: Int
    private let maxStoredJobs: Int
    private let idleTimeout: Duration?
    private let maxServiceOperations: Int
    private var services: [TransferServiceID: ServiceRecord] = [:]
    private var serviceIDs: [ObjectIdentifier: TransferServiceID] = [:]
    private var jobs: [TransferJobID: JobRecord] = [:]
    private var order: [TransferJobID] = []
    private var workers: [TransferJobID: Task<Void, Never>] = [:]
    private var batchDecisions: [BatchKey: ConflictDecision] = [:]
    private var observers: [UUID: AsyncStream<TransferManagerSnapshot>.Continuation] = [:]
    private var serviceOperations: [UUID: ServiceOperationRecord] = [:]
    private var serviceOperationOrder: [UUID] = []
    private var shutdownTask: Task<Void, Never>?
    private var closed = false

    public init(engine: SafeTransferEngine = .init(), maxConcurrentJobs: Int = 2, maxQueuedJobs: Int = 128,
                maxStoredJobs: Int = 512, idleTimeout: Duration? = .seconds(60), maxServiceOperations: Int = 128) {
        precondition((1...8).contains(maxConcurrentJobs) && (1...1024).contains(maxQueuedJobs))
        precondition(maxStoredJobs >= maxConcurrentJobs + maxQueuedJobs && maxStoredJobs <= 10_000)
        precondition(idleTimeout == nil || idleTimeout! > .zero)
        precondition((1...128).contains(maxServiceOperations))
        self.engine = engine; self.maxConcurrentJobs = maxConcurrentJobs; self.maxQueuedJobs = maxQueuedJobs
        self.maxStoredJobs = maxStoredJobs; self.idleTimeout = idleTimeout; self.maxServiceOperations = maxServiceOperations
    }

    /// Transfers service lifetime ownership to the manager. Remote services must be bound to their
    /// actual host ID; nil is intended for local roots. One object cannot be rebound to another host.
    /// Closing an idle service is terminal: reconnect explicitly and register a new service object.
    public func registerService(_ service: any RemoteFileService, hostID: String? = nil) throws -> TransferServiceID {
        guard !closed else { throw FileServiceError(.closed, operation: "transfer-manager") }
        if let hostID { try validateHost(hostID) }
        guard hostID != nil || service.capabilities.traversal == .localDescriptorNoFollow else {
            throw FileServiceError(.conflict, operation: "remote-service-requires-host-binding")
        }
        let identity = ObjectIdentifier(service)
        if let id = serviceIDs[identity], let existing = services[id] {
            guard existing.closing == nil, existing.hostID == hostID else {
                throw FileServiceError(.conflict, operation: "service-already-bound")
            }
            return id
        }
        guard services.count < 128 else { throw FileServiceError(.resourceLimit, operation: "managed-services") }
        let id = UUID()
        services[id] = ServiceRecord(service: service, hostID: hostID)
        serviceIDs[identity] = id
        scheduleIdle(id)
        return id
    }
    public var hasActiveWork: Bool { !serviceOperations.isEmpty || jobs.values.contains { $0.state.isActive } }
    public func snapshot() -> TransferManagerSnapshot {
        TransferManagerSnapshot(jobs: order.compactMap { jobs[$0]?.snapshot }, isClosed: closed,
            serviceOperations: serviceOperationOrder.compactMap { serviceOperations[$0]?.snapshot })
    }
    /// At most 16 subscriptions; each buffers only the newest complete metadata snapshot.
    public func updates() throws -> AsyncStream<TransferManagerSnapshot> {
        guard observers.count < 16 else { throw FileServiceError(.resourceLimit, operation: "transfer-observers") }
        let (stream, continuation) = AsyncStream<TransferManagerSnapshot>.makeStream(bufferingPolicy: .bufferingNewest(1))
        continuation.yield(snapshot())
        if closed { continuation.finish(); return stream }
        let id = UUID()
        observers[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.removeObserver(id) } }
        return stream
    }
    private func removeObserver(_ id: UUID) { observers[id] = nil }
    private func publish() { let value = snapshot(); for observer in observers.values { observer.yield(value) } }

    /// Owns the service through the closure's actual completion, including asynchronous cleanup.
    /// Use `.serialized` for raw list/mkdir operations. Use `.callerScheduled` for
    /// SafeFileOperations/ServerCommitProbe (same scheduler as this manager's engine): wrapping
    /// their own host gate with another serialized gate would deadlock.
    ///
    /// The closure must pass this token through all I/O and await all cleanup before returning;
    /// do not escape the service/token into unawaited background I/O or call service.cancel/close.
    /// Caller cancellation signals only this token, never Task.cancel() or service.cancel(). A
    /// late return after cancellation is rejected, but cannot roll back an already committed action.
    /// Same-manager nested operations are rejected. Do NOT call and await this manager's
    /// cancelAllAndWait() from the closure: shutdown must await this very operation's cleanup.
    /// Invoke shutdown from the outer application lifecycle coordinator instead.
    public func withServiceOperation<T: Sendable>(serviceID: TransferServiceID, hostID: String,
        scheduling: TransferServiceOperationScheduling = .serialized,
        _ operation: @escaping @Sendable (any RemoteFileService, CancellationToken) async throws -> T) async throws -> T {
        guard !closed else { throw FileServiceError(.closed, operation: "transfer-manager") }
        let managerID = ObjectIdentifier(self)
        guard !ServiceOperationContext.managers.contains(managerID) else {
            throw FileServiceError(.conflict, operation: "nested-service-operation")
        }
        try validateHost(hostID)
        let token = CancellationToken(); try token.check()
        guard let record = services[serviceID], record.closing == nil else {
            throw FileServiceError(.closed, operation: "service-operation-unavailable")
        }
        guard record.hostID == nil || record.hostID == hostID else {
            throw FileServiceError(.conflict, operation: "service-operation-host-mismatch")
        }
        guard serviceOperations.count < maxServiceOperations else {
            throw FileServiceError(.resourceLimit, operation: "service-operation-limit")
        }
        retainService(serviceID)
        let id = UUID(), service = record.service, scheduler = engine.scheduler
        let context = ServiceOperationContext.managers.union([managerID])
        let worker = Task<T, Error> {
            try await ServiceOperationContext.$managers.withValue(context) {
                try token.check()
                switch scheduling {
                case .serialized:
                    return try await scheduler.onHost(hostID, token: token) {
                        let value = try await operation(service, token)
                        try token.check(); return value
                    }
                case .callerScheduled:
                    let value = try await operation(service, token)
                    try token.check(); return value
                }
            }
        }
        let drain = Task {
            _ = await worker.result
            self.finishServiceOperation(id, token: token)
        }
        serviceOperations[id] = ServiceOperationRecord(id: id, serviceID: serviceID, hostID: hostID, token: token, drain: drain)
        serviceOperationOrder.append(id); publish()
        return try await withTaskCancellationHandler {
            let result = await worker.result
            await drain.value
            try token.check()
            return try result.get()
        } onCancel: {
            token.cancel()
            Task { await self.serviceOperationCancellationRequested(id, token: token) }
        }
    }
    private func serviceOperationCancellationRequested(_ id: UUID, token: CancellationToken) {
        guard serviceOperations[id]?.token === token else { return }
        publish()
    }
    private func finishServiceOperation(_ id: UUID, token: CancellationToken) {
        guard let record = serviceOperations[id], record.token === token else { return }
        serviceOperations[id] = nil; serviceOperationOrder.removeAll { $0 == id }
        releaseService(record.serviceID); publish()
    }

    @discardableResult public func enqueue(_ request: TransferRequest,
                                          serverConfirmation: ServerCommitConfirmation? = nil) throws -> TransferJobID {
        try enqueueBatch([request], serverConfirmations: serverConfirmation.map { [request.destination.serviceID: $0] } ?? [:])[0]
    }
    /// Admission is atomic: invalid descriptors or a full bounded queue enqueue nothing.
    /// Capability evidence is supplied by the caller/probe and checked against the actual service.
    /// No evidence is generated or inferred from a risk acknowledgement.
    @discardableResult public func enqueueBatch(_ requests: [TransferRequest],
        serverConfirmations: [TransferServiceID: ServerCommitConfirmation] = [:]) throws -> [TransferJobID] {
        try validateAdmission(requests, confirmations: serverConfirmations)
        let ids = requests.map { insert($0, confirmation: serverConfirmations[$0.destination.serviceID], retryOf: nil) }
        publish(); pump()
        return ids
    }
    /// A fresh job ID/generation, starting from byte zero. Services must still be registered/open;
    /// there is no implicit reconnect. The original job/report and original target are not altered.
    @discardableResult public func retry(_ jobID: TransferJobID, batchID: TransferBatchID = UUID()) throws -> TransferJobID {
        guard let previous = jobs[jobID], !previous.state.isActive,
              previous.state == .failed || previous.state == .cancelled else {
            throw FileServiceError(.conflict, operation: "retry-requires-failed-or-cancelled-job")
        }
        let old = previous.request
        let request = TransferRequest(hostID: old.hostID, batchID: batchID, source: old.source, destination: old.destination, kind: old.kind)
        try validateAdmission([request], confirmations: previous.serverConfirmation.map { [request.destination.serviceID: $0] } ?? [:])
        let id = insert(request, confirmation: previous.serverConfirmation, retryOf: jobID)
        publish(); pump(); return id
    }
    private func validateHost(_ host: String) throws {
        guard !host.isEmpty, host.utf8.count <= 1024, !host.utf8.contains(0) else {
            throw FileServiceError(.invalidPath, operation: "transfer-host-id")
        }
    }
    private func validateAdmission(_ requests: [TransferRequest],
                                   confirmations: [TransferServiceID: ServerCommitConfirmation]) throws {
        guard !closed else { throw FileServiceError(.closed, operation: "transfer-manager") }
        guard !requests.isEmpty, requests.count <= maxQueuedJobs + maxConcurrentJobs,
              jobs.count + requests.count <= maxStoredJobs else {
            throw FileServiceError(.resourceLimit, operation: "transfer-history-or-batch-limit")
        }
        // Reserve queue space even if all admitted jobs happen to target a busy host.
        let active = jobs.values.filter { $0.state.isActive }.count
        guard active + requests.count <= maxQueuedJobs + maxConcurrentJobs else {
            throw FileServiceError(.resourceLimit, operation: "transfer-queue-full")
        }
        let queued = jobs.values.filter { $0.state == .queued }.count
        var available = maxConcurrentJobs - workers.count
        var hosts = Set(workers.keys.compactMap { jobs[$0]?.request.hostID })
        var additionalQueued = 0
        for request in requests {
            try validateHost(request.hostID)
            for location in [request.source, request.destination] {
                guard let record = services[location.serviceID], record.closing == nil else {
                    throw FileServiceError(.closed, operation: "transfer-service-unavailable", path: location.path)
                }
                guard record.hostID == nil || record.hostID == request.hostID else {
                    throw FileServiceError(.conflict, operation: "transfer-service-host-mismatch", path: location.path)
                }
            }
            if let evidence = confirmations[request.destination.serviceID] {
                guard services[request.destination.serviceID]?.service.serverBinding == evidence.serverBinding else {
                    throw FileServiceError(.needsCapabilityConfirmation, operation: "transfer-evidence-binding-mismatch")
                }
            }
            if available > 0 && !hosts.contains(request.hostID) {
                available -= 1; hosts.insert(request.hostID)
            } else { additionalQueued += 1 }
        }
        guard queued + additionalQueued <= maxQueuedJobs else {
            throw FileServiceError(.resourceLimit, operation: "transfer-queue-full")
        }
    }
    private func insert(_ request: TransferRequest, confirmation: ServerCommitConfirmation?, retryOf: TransferJobID?) -> TransferJobID {
        let id = UUID()
        jobs[id] = JobRecord(id: id, retryOf: retryOf, request: request, serverConfirmation: confirmation)
        order.append(id)
        for serviceID in Set([request.source.serviceID, request.destination.serviceID]) { retainService(serviceID) }
        return id
    }
    private func pump() {
        guard !closed else { return }
        var busyHosts = Set(workers.keys.compactMap { jobs[$0]?.request.hostID })
        for id in order where workers.count < maxConcurrentJobs {
            guard var job = jobs[id], job.state == .queued, !busyHosts.contains(job.request.hostID) else { continue }
            job.state = .running; jobs[id] = job; busyHosts.insert(job.request.hostID)
            let request = job.request, generation = job.generation, token = job.token, evidence = job.serverConfirmation
            // Captured services and self are held through engine cleanup, independently of observers.
            let source = services[request.source.serviceID]!.service
            let destination = services[request.destination.serviceID]!.service
            let engine = self.engine
            workers[id] = Task {
                let hooks = TransferHooks(progress: { path, bytes in
                    await self.recordProgress(id, generation: generation, path: path, bytes: bytes)
                }, resolveConflict: { conflict in
                    try await self.conflict(id, generation: generation, conflict: conflict)
                })
                let policy = TransferPolicy(confirmRisk: { risk in
                    await self.risk(id, generation: generation, risk: risk)
                }, serverCommit: evidence)
                do {
                    let report: TransferReport
                    switch request.kind {
                    case .file:
                        report = try await engine.copy(hostID: request.hostID, source: source, sourcePath: request.source.path,
                            destination: destination, destinationPath: request.destination.path, token: token, policy: policy, hooks: hooks)
                    case .tree:
                        report = try await engine.copyTree(hostID: request.hostID, source: source, sourcePath: request.source.path,
                            destination: destination, destinationPath: request.destination.path, token: token, policy: policy, hooks: hooks)
                    }
                    self.complete(id, generation: generation, report: report, error: nil)
                } catch {
                    let typed = error as? FileServiceError ?? FileServiceError(error is CancellationError ? .cancelled : .io, operation: "transfer-job")
                    self.complete(id, generation: generation, report: nil, error: typed)
                }
            }
        }
        publish()
    }
    private func recordProgress(_ id: TransferJobID, generation: UUID, path: RemotePath, bytes: UInt64) {
        guard var job = jobs[id], job.generation == generation, job.state.isActive else { return }
        let old = job.progress[path, default: 0]
        guard bytes >= old else { return }
        job.bytes += bytes - old; job.progress[path] = bytes; jobs[id] = job; publish()
    }
    private func conflict(_ id: TransferJobID, generation: UUID, conflict: TransferConflict) async throws -> ConflictDecision {
        guard let job = jobs[id], job.generation == generation else { throw FileServiceError(.cancelled, operation: "stale-transfer") }
        try job.token.check()
        let key = BatchKey(hostID: job.request.hostID, batchID: job.request.batchID)
        if let decision = batchDecisions[key] { return decision }
        let answer = await ask(id, generation: generation, question: .conflict(conflict))
        try job.token.check()
        guard case .conflict(let decision, _)? = answer else { throw FileServiceError(.cancelled, operation: "transfer-decision") }
        return decision
    }
    private func risk(_ id: TransferJobID, generation: UUID, risk: TransferRisk) async -> Bool {
        guard let job = jobs[id], job.generation == generation, !job.token.isCancelled else { return false }
        let answer = await ask(id, generation: generation, question: .risk(risk))
        guard !job.token.isCancelled, case .risk(let accepted)? = answer else { return false }
        return accepted
    }
    private func ask(_ id: TransferJobID, generation: UUID, question: TransferDecisionQuestion) async -> TransferDecisionAnswer? {
        await withCheckedContinuation { continuation in
            guard var job = jobs[id], job.generation == generation, job.state.isActive, !job.token.isCancelled, !closed else {
                continuation.resume(returning: nil); return
            }
            precondition(job.reply == nil)
            job.pending = TransferDecisionRequest(id: UUID(), jobID: id, generation: generation, question: question)
            job.reply = continuation
            switch question { case .conflict: job.state = .waitingConflict; case .risk: job.state = .waitingRisk }
            jobs[id] = job; publish()
        }
    }
    /// Returns false without changing state for wrong types, stale IDs/generations, repeated answers,
    /// answers after cancellation, or an attempt to reuse one concrete alternate filename in a batch.
    @discardableResult public func resolve(_ request: TransferDecisionRequest, answer: TransferDecisionAnswer) -> Bool {
        guard !closed, var job = jobs[request.jobID], job.generation == request.generation,
              !job.token.isCancelled, job.pending == request, let continuation = job.reply else { return false }
        switch (request.question, answer) {
        case (.conflict, .conflict(let decision, let apply)):
            if apply {
                guard decision == .overwrite || decision == .skip else { return false }
                batchDecisions[BatchKey(hostID: job.request.hostID, batchID: job.request.batchID)] = decision
            }
        case (.risk, .risk): break
        default: return false
        }
        job.reply = nil; job.pending = nil; job.state = .running; jobs[job.id] = job
        continuation.resume(returning: answer); publish(); return true
    }
    private func complete(_ id: TransferJobID, generation: UUID, report: TransferReport?, error: FileServiceError?) {
        guard var job = jobs[id], job.generation == generation else { return }
        job.items = report?.items ?? []
        let failures = job.items.compactMap { item -> FileServiceError? in
            if case .failed(let error) = item.state { return error }; return nil
        }
        if let failure = error ?? failures.first(where: { $0.kind != .cancelled }) ?? failures.first {
            let cancelled = failure.kind == .cancelled || (job.token.isCancelled && failure.kind == .riskRejected)
            job.state = cancelled ? .cancelled : .failed
            job.error = cancelled ? FileServiceError(.cancelled, operation: "transfer-job") : failure
        } else if job.items.isEmpty {
            job.state = .failed; job.error = FileServiceError(.integrity, operation: "empty-transfer-report")
        } else if report?.allSucceeded == true {
            job.state = .succeeded
        } else {
            job.state = job.items.allSatisfy { $0.state == .skipped } ? .skipped : .completedWithSkips
        }
        job.reply?.resume(returning: nil); job.reply = nil; job.pending = nil; job.progress.removeAll()
        jobs[id] = job; workers[id] = nil
        releaseServices(job.request); clearBatchIfFinished(job.request)
        publish(); pump()
    }
    /// Queued jobs cancel immediately. Running/decision-waiting jobs remain active until the engine
    /// returns its real cleanup result; cancelling a job never cancels an unrelated service/host.
    @discardableResult public func cancel(_ id: TransferJobID) -> Bool {
        guard var job = jobs[id], job.state.isActive else { return false }
        job.token.cancel()
        job.reply?.resume(returning: nil); job.reply = nil; job.pending = nil
        if job.state == .queued {
            job.state = .cancelled; job.error = FileServiceError(.cancelled, operation: "queued-transfer")
            jobs[id] = job; releaseServices(job.request); clearBatchIfFinished(job.request)
        } else { job.state = .running; jobs[id] = job }
        publish(); pump(); return true
    }
    private func retainService(_ id: TransferServiceID) {
        precondition(services[id] != nil && services[id]!.closing == nil)
        services[id]!.idleTask?.cancel(); services[id]!.idleTask = nil
        services[id]!.idleGeneration = UUID(); services[id]!.users += 1
    }
    private func releaseService(_ id: TransferServiceID) {
        precondition(services[id] != nil && services[id]!.users > 0)
        services[id]!.users -= 1; scheduleIdle(id)
    }
    private func releaseServices(_ request: TransferRequest) {
        for id in Set([request.source.serviceID, request.destination.serviceID]) { releaseService(id) }
    }
    private func clearBatchIfFinished(_ request: TransferRequest) {
        if !jobs.values.contains(where: { $0.state.isActive && $0.request.hostID == request.hostID && $0.request.batchID == request.batchID }) {
            batchDecisions[BatchKey(hostID: request.hostID, batchID: request.batchID)] = nil
        }
    }
    /// History is bounded. The UI may explicitly dismiss terminal jobs after displaying errors and
    /// retained temps; removing history never deletes files or permits removing an active job.
    @discardableResult public func removeFinishedJobs(_ ids: [TransferJobID]) -> Int {
        var count = 0
        for id in ids where jobs[id]?.state.isActive == false { jobs[id] = nil; count += 1 }
        order.removeAll { jobs[$0] == nil }; publish(); return count
    }
    private func scheduleIdle(_ id: TransferServiceID) {
        guard !closed, var service = services[id], service.users == 0, service.closing == nil, let idleTimeout else { return }
        service.idleTask?.cancel()
        let generation = UUID(); service.idleGeneration = generation
        service.idleTask = Task { [weak self] in
            do { try await Task.sleep(for: idleTimeout) } catch { return }
            await self?.expireService(id, generation: generation)
        }
        services[id] = service
    }
    private func expireService(_ id: TransferServiceID, generation: UUID) async {
        guard let record = services[id], record.users == 0, record.idleGeneration == generation else { return }
        await closeServices([id])
    }
    /// Explicit idle release (e.g. window close with no work). Job AND service-operation users win.
    /// Hiding a panel or ending an observation is NOT a service-close operation.
    public func closeIdleServices() async { await closeServices(services.filter { $0.value.users == 0 }.map(\.key)) }
    /// Releases only these services if idle now; unknown/repeated IDs are harmless.
    /// Active job/operation users are skipped, not scheduled for a later close.
    /// Awaits actual close completion, sharing any in-progress release or shutdown close.
    public func closeIdleServices(_ ids: [TransferServiceID]) async { await closeServices(Array(Set(ids))) }
    private func closeServices(_ ids: [TransferServiceID]) async {
        var pending: [(TransferServiceID, Task<Void, Never>)] = []
        for id in ids {
            guard var record = services[id], record.users == 0 else { continue }
            record.idleTask?.cancel(); record.idleTask = nil
            let service = record.service
            let task = record.closing ?? Task { await service.close() }
            record.closing = task; services[id] = record; pending.append((id, task))
        }
        for (id, task) in pending {
            await task.value
            if let record = services.removeValue(forKey: id) { serviceIDs[ObjectIdentifier(record.service)] = nil }
        }
    }
    /// Terminal, idempotent shutdown. Stops admission first, resolves every pending decision,
    /// cancels job/operation tokens, awaits real closures and cleanup, then ALL service closes.
    /// Concurrent callers share this same completion point, even if their own task is cancelled.
    /// Do NOT await this method from a withServiceOperation closure owned by this manager:
    /// shutdown must wait for that closure itself. Call from the outer lifecycle coordinator.
    public func cancelAllAndWait() async {
        if let shutdownTask { await shutdownTask.value; return }
        closed = true
        let activeIDs = order.filter { jobs[$0]?.state.isActive == true }
        for id in activeIDs { cancel(id) }
        for operation in serviceOperations.values { operation.token.cancel() }
        let running = Array(workers.values)
        let operations = serviceOperations.values.map(\.drain)
        let task = Task {
            for worker in running { await worker.value }
            for operation in operations { await operation.value }
            await self.closeServices(Array(self.services.keys))
            self.publish()
            for observer in self.observers.values { observer.finish() }
            self.observers.removeAll()
        }
        shutdownTask = task; publish()
        await task.value
    }
}
