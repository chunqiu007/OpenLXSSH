import AppKit
import Combine
import Darwin
import Foundation
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTrust

enum FilesState: Equatable { case disconnected, preparing, awaitingTrust, authenticating, ready, closing, failed }
struct FilesTrustPrompt: Identifiable {
    let id = UUID()
    let request: FilesRequest
    let event: FileHostTrustEvent
}
struct FilesKeyboardPrompt: Identifiable {
    let id = UUID()
    let request: FilesRequest
    let name: String
    let instruction: String
    let prompts: [(text: String, echo: Bool)]
}
enum FilesAuthenticationPresentation { case trust(FilesTrustPrompt), keyboard(FilesKeyboardPrompt) }
struct FilesDeleteReview: Identifiable, Sendable {
    var id: UUID { plan.id }
    let generation: UInt64
    let serviceID: UUID
    let operations: SafeFileOperations
    let plan: DeletePlan
    let target: FilesOperationTarget
    let revision: UUID
}
struct FilesProbeReview: Identifiable, Sendable {
    var id: UUID { plan.id }
    let generation: UInt64
    let serviceID: UUID
    let plan: NoReplaceProbePlan
}

struct FilesConnectionChangeReview: Identifiable {
    let id = UUID()
    let generation: UInt64
    let selectedHost: HostConfiguration?
    let target: HostConfiguration?
    let disconnect: Bool
    let jobs: [TransferJobSnapshot]
}
struct FilesDeleteBatchReview: Identifiable, Sendable {
    var id: UUID { review.id }
    let generation: UInt64
    let serviceID: UUID
    let review: BrowserDeleteReview
    let revision: UUID
}

struct FilesHistoryRemovalReview: Identifiable, Sendable {
    let id = UUID()
    let managerLifetime: UUID
    let jobs: [TransferJobSnapshot]
    let labels: [TransferJobID: FilesTransferLabel]
}

/// Application owned. The panel is only an observer; terminal tabs never own a file service.
@MainActor final class FilesController: ObservableObject, FilesWindowLifecycle {
    @Published private(set) var visible = false
    /// Non-secret epoch only. View-owned initial input must not survive connection invalidation.
    @Published private(set) var initialInputEpoch = UUID()
    @Published private(set) var selectedHost: HostConfiguration?
    @Published private(set) var state: FilesState = .disconnected
    @Published private(set) var entries: [DirectoryEntry] = []
    @Published private(set) var path: RemotePath = .root
    @Published private(set) var navigationHistory = FilesNavigationHistory()
    @Published private(set) var readFailed = false
    private var browserRevision = UUID()
    private var parentAttributes: FileAttributes?
    private var pendingTargets: [UUID: FilesOperationTarget] = [:]
    @Published private(set) var deleteBatchReview: FilesDeleteBatchReview?
    @Published private(set) var lastDeleteReports: [DeleteReport] = []
    @Published private(set) var transferSpeeds: [TransferJobID: Double] = [:]
    let localBrowser: LocalBrowserModel
    private var transferSamples: [TransferJobID: (bytes: UInt64, time: ContinuousClock.Instant)] = [:]
    private var connectionChangeReview: FilesConnectionChangeReview?
    private let initialPath: @Sendable (any RemoteFileService, CancellationToken) async throws -> RemotePath
    @Published private(set) var busy = false
    @Published var issue: AppIssue?
    @Published private(set) var trustPrompt: FilesTrustPrompt?
    @Published private(set) var keyboardPrompt: FilesKeyboardPrompt?
    @Published private(set) var deleteReview: FilesDeleteReview?
    @Published private(set) var probeReview: FilesProbeReview?
    @Published private(set) var lastDeleteReport: DeleteReport?
    @Published private(set) var lastProbeResult: NoReplaceProbeResult?
    @Published private(set) var hasActiveTransfers = false
    @Published private(set) var hasPendingOperations = false
    @Published private(set) var transferSnapshot = TransferManagerSnapshot(jobs: [], isClosed: false)
    @Published private(set) var transferLabels: [TransferJobID: FilesTransferLabel] = [:]
    @Published var tasksVisible = false
    @Published private(set) var transferCompletionRevision = 0
    private(set) var latestCompletedBatchJobs: [TransferJobSnapshot] = []
    private var completedBatchIDs: Set<TransferBatchID> = []
    @Published private(set) var transferPreparationIssue: AppIssue?
    func dismissTransferPreparationIssue() { transferPreparationIssue = nil }
    private(set) var conflictPreference: FileConflictPreference = .ask
    func updateTransferPreference(_ preference: FileConflictPreference) {
        conflictPreference = preference
        let manager = manager
        Task { await manager.setConflictPolicy(TransferConflictPolicy(rawValue: preference.rawValue) ?? .ask) }
    }
    @Published private(set) var enqueueInFlight = 0
    @Published private(set) var admissionFrozen = false
    @Published private(set) var transferPlanReview: FilesTransferPlanReview?
    @Published private(set) var transferPlanPhase: FilesTransferPlanPhase?
    private struct TransferPlanOwner {
        let id: UUID
        let context: FilesTransferContext
        let token: CancellationToken
        var direction: FilesTransferDirection?
        var planID: UUID?
        var registeredLocalIDs: [TransferServiceID] = []
    }
    private var transferPlanOwner: TransferPlanOwner?
    private var retryOrigins: [TransferJobID: FilesTransferRetryOrigin] = [:]
    private var retrySelection: FilesTransferRetrySelection?
    private var transferPlanExpiry: Task<Void, Never>?
    private var transferPlanDrains: [UUID: Task<Void, Never>] = [:]
    private var deferWindowReset = false
    private var enqueues: [UUID: Task<[TransferJobID], Error>] = [:]
    private var metadataMutations: [UUID: Task<Bool, Never>] = [:]
    private var historyRemovalReview: FilesHistoryRemovalReview?
    private var historyRemovalEpoch = UUID()
    private let beforeHistoryRemovalSnapshot: (@Sendable () async -> Void)?
    let pathPicker = FilesPathPicker()
    private let localService: @Sendable (Int32) throws -> any RemoteFileService
    /// Nil in production; deterministic scheduling at the worker → MainActor mailbox boundary.
    private let beforeOperationRiskDelivery: (@Sendable () async -> Void)?
    let connector: any FilesConnecting
    var trustEnvironment: SessionEnvironment?
    let scheduler: TransferScheduler
    private(set) var manager: TransferManager
    private var observation: Task<Void, Never>?
    private var connection: Task<Void, Never>?
    private var operation: Task<Void, Never>?
    private var operationID: UUID?
    private var closeTask: Task<Void, Never>?
    private var windowTask: Task<Void, Never>?
    private var lifetime = UUID()
    private var generation: UInt64 = 0
    private var request: FilesRequest?
    private var token: CancellationToken?
    private(set) var serviceID: UUID?
    private var sessionLease: TransferServiceSessionLease?
    private var healthTask: Task<Void, Never>?
    private var healthToken: CancellationToken?
    private var serviceRegistrationRevision: UInt64?
    private var observedServiceRevision: UInt64 = 0
    private var observedServices: [TransferServiceID: TransferServiceSnapshot] = [:]
    private var trustReply: ChallengeReply<FileHostTrustAnswer>?
    private var keyboardReply: ChallengeReply<[Data]>?
    private var riskReply: CheckedContinuation<Bool, Never>?
    @Published private(set) var riskID: UUID?
    @Published private(set) var pendingRisk: TransferRisk?
    private var confirmation: ServerCommitConfirmation?
    private var pendingHostUpdate: HostConfiguration?
    private var terminating = false
    private var windowClosing = false
    private let idleTimeout: Duration?
    private let healthInterval: Duration?
    init(connector: any FilesConnecting, idleTimeout: Duration? = .seconds(60), healthInterval: Duration? = .seconds(30),
         localService: @escaping @Sendable (Int32) throws -> any RemoteFileService = { try LocalFileService(rootDirectoryDescriptor: $0) },
         beforeOperationRiskDelivery: (@Sendable () async -> Void)? = nil,
         beforeHistoryRemovalSnapshot: (@Sendable () async -> Void)? = nil,
         localBrowserRoot: URL? = nil,
         localBrowserValidation: (@Sendable () throws -> Void)? = nil,
         initialPath: @escaping @Sendable (any RemoteFileService, CancellationToken) async throws -> RemotePath = { service, token in try await service.initialDirectory(token: token) }) {
        precondition(healthInterval == nil || healthInterval! > .zero)
        self.connector = connector; self.idleTimeout = idleTimeout; self.healthInterval = healthInterval; self.localService = localService
        self.initialPath = initialPath
        localBrowser = LocalBrowserModel(root: localBrowserRoot, validateBoundary: localBrowserValidation)
        self.beforeOperationRiskDelivery = beforeOperationRiskDelivery
        self.beforeHistoryRemovalSnapshot = beforeHistoryRemovalSnapshot
        let scheduler = TransferScheduler(maxConcurrentChunks: 2); self.scheduler = scheduler
        manager = TransferManager(engine: SafeTransferEngine(scheduler: scheduler), idleTimeout: idleTimeout, executionMode: .direct)
    }
    func show(host: HostConfiguration?) {
        guard !terminating, !windowClosing, !admissionFrozen, windowTask == nil else { return }
        visible = true
        let sameConnection = selectedHost?.id == host?.id && selectedHost?.connectionIdentity == host?.connectionIdentity
        guard !sameConnection else {
            // Preserve the request, service and transfer manager for the same connection.
            selectedHost = host; pendingHostUpdate = nil
            if issue?.code == "files.hostChanged" { issue = nil }
            return
        }
        initialInputEpoch = UUID(); cancelTransferPlan(); cancelPathSelection()
        if serviceID != nil, selectedHost?.id == host?.id {
            // Configuration edits do not tear down a service possibly owned by
            // future transfer jobs. The connected snapshot stays explicit until
            // the user disconnects; the next manual connect uses the new Core row.
            pendingHostUpdate = host; pendingTargets = [:]; browserRevision = UUID()
            issue = AppIssue(code: "files.hostChanged", message: "主机配置已更改；当前文件连接保留原端点。请先显式断开，再手动连接以使用新配置，不会自动重连。")
            return
        }
        invalidateCallbacks(); discardDeleteBatch(); connectionChangeReview = nil
        let oldConnection = connection; oldConnection?.cancel(); token?.cancel()
        let oldOperation = operation; oldOperation?.cancel()
        let oldServiceID = serviceID, oldLease = sessionLease, oldHealth = stopHealth(), admitted = Array(enqueues.values)
        sessionLease = nil
        generation &+= 1; request = nil; selectedHost = host; pendingHostUpdate = nil; entries = []; path = .root; navigationHistory = .init()
        serviceID = nil; serviceRegistrationRevision = nil; confirmation = nil; deleteReview = nil; probeReview = nil; state = .disconnected
        self.connection = nil; self.operation = nil; operationID = nil
        let manager = manager
        let previous = closeTask, revision = generation, planDrains = Array(transferPlanDrains.values)
        closeTask = Task { [weak self] in
            await previous?.value; await oldHealth?.value; await oldConnection?.value; await oldOperation?.value
            for task in admitted { _ = await task.result }
            for task in planDrains { await task.value }
            if let oldLease { await manager.releaseSessionService(oldLease) }
            else if let oldServiceID { await manager.closeIdleServices([oldServiceID]) }
            if self?.generation == revision { self?.closeTask = nil; self?.busy = false; self?.hasPendingOperations = false }
        }
    }
    func prepareConnectionChange(host: HostConfiguration?, disconnect: Bool) -> FilesConnectionChangeReview? {
        guard !admissionFrozen, !terminating, !windowClosing else { return nil }
        guard enqueueInFlight == 0 else {
            issue = AppIssue(code: "files.admissionPending", message: "正在将已选择项目加入队列，请完成后再更改连接；当前连接和任务未改变。")
            return nil
        }
        if !disconnect, let host, selectedHost?.matchesConnection(of: host) == true { show(host: host); return nil }
        let jobs = transferSnapshot.jobs.filter { $0.state.isActive }
        if jobs.isEmpty { if disconnect { cancelCurrent() } else { show(host: host) }; return nil }
        let review = FilesConnectionChangeReview(generation: generation, selectedHost: selectedHost, target: host, disconnect: disconnect, jobs: jobs)
        connectionChangeReview = review
        return review
    }
    func discardConnectionChange(_ review: FilesConnectionChangeReview) { if connectionChangeReview?.id == review.id { connectionChangeReview = nil } }
    func confirmConnectionChange(_ review: FilesConnectionChangeReview) {
        guard connectionChangeReview?.id == review.id, review.generation == generation,
              selectedHost?.id == review.selectedHost?.id, selectedHost?.connectionIdentity == review.selectedHost?.connectionIdentity,
              !admissionFrozen, !terminating, !windowClosing else { return }
        connectionChangeReview = nil
        if review.disconnect { cancelCurrent() } else { show(host: review.target) }
    }
    func pendingAuthenticationPresentation(modalAvailable: Bool) -> FilesAuthenticationPresentation? {
        guard visible, modalAvailable else { return nil }
        if let trustPrompt { return .trust(trustPrompt) }
        if let keyboardPrompt { return .keyboard(keyboardPrompt) }
        return nil
    }
    func hide() {
        visible = false; pendingTargets = [:]; browserRevision = UUID(); cancelPathSelection()
        discardDeleteBatch(); discardDeleteReview() // Only unconfirmed plans, never an admitted mutation/service I/O.
    }
    func captureTarget(_ selected: [DirectoryEntry] = []) -> FilesOperationTarget? {
        guard state == .ready, !busy, !admissionFrozen, !terminating, !windowClosing,
              let id = serviceID, let host = selectedHost, let parentAttributes, selected.count <= 128, selected.allSatisfy(entries.contains) else { return nil }
        guard pendingTargets.count < 8 else {
            issue = .files(FileServiceError(.resourceLimit, operation: "files-pending-operation-targets")); return nil
        }
        let target = FilesOperationTarget(owner: .remote(lifetime: lifetime, generation: generation, serviceID: id, host: host, revision: browserRevision),
            endpoint: host.name + " · " + host.username + "@" + host.address + ":" + String(host.port), parent: path, parentAttributes: parentAttributes, entries: selected)
        pendingTargets[target.id] = target
        return target
    }
    func discardTarget(_ target: FilesOperationTarget) { pendingTargets[target.id] = nil }
    private func targetIsCurrent(_ target: FilesOperationTarget, checkRevision: Bool = true) -> Bool {
        guard case .remote(let expectedLifetime, let expectedGeneration, let id, let host, let revision) = target.owner else { return false }
        return expectedLifetime == lifetime && expectedGeneration == generation && id == serviceID
            && selectedHost?.matchesConnection(of: host) == true && target.parent == path
            && (!checkRevision || revision == browserRevision) && target.entries.allSatisfy(entries.contains)
            && state == .ready && !admissionFrozen && !terminating && !windowClosing
    }
    private func consumeTarget(_ target: FilesOperationTarget) -> Bool {
        let registered = pendingTargets.removeValue(forKey: target.id)
        guard registered != nil, targetIsCurrent(target), !busy, operation == nil, connection == nil, closeTask == nil, windowTask == nil else {
            issue = .files(FileServiceError(.raceDetected, operation: "files-operation-owner-stale", path: target.parent)); return false
        }
        return true
    }
    var canConnect: Bool { selectedHost != nil && state != .ready && state != .closing && connection == nil && closeTask == nil && windowTask == nil && !admissionFrozen && !terminating && !windowClosing }
    func connect(_ input: FilesConnectInput) {
        guard let host = selectedHost, connection == nil, operation == nil, windowTask == nil, !admissionFrozen, !terminating, !windowClosing, state != .ready, state != .closing else { return }
        generation &+= 1
        let current = FilesRequest(id: UUID(), generation: generation, host: host)
        let cancellation = CancellationToken(), manager = manager, connector = connector, managerLifetime = lifetime
        let close = closeTask; closeTask = nil
        invalidateCallbacks(); request = current; token = cancellation
        state = .preparing; busy = true; issue = nil; serviceID = nil; serviceRegistrationRevision = nil; confirmation = nil
        hasPendingOperations = true
        observeManager()
        connection = Task { [weak self] in
            guard let self else { return }
            defer {
                if request == current {
                    connection = nil; busy = false; hasPendingOperations = false
                    reconcileServiceState()
                }
            }
            var acquiredLease: TransferServiceSessionLease?
            do {
                await close?.value
                guard request == current, generation == current.generation, windowTask == nil, !windowClosing, !terminating else { return }
                try cancellation.check()
                guard isCurrent(current) else { return }
                let service = try await connector.connect(request: current, input: input, token: cancellation,
                    trust: { [weak self] event, reply in
                        Task { @MainActor in
                            guard let self else { reply.resolve(.reject); return }
                            self.receiveTrust(event, reply: reply, request: current, lifetime: managerLifetime)
                        }
                    }, keyboard: { [weak self] challenge, reply in
                        Task { @MainActor in
                            guard let self else { cancellation.cancel(); reply.cancel(); return }
                            self.receiveKeyboard(challenge, reply: reply, request: current, cancellation: cancellation)
                        }
                    }, isCurrent: { [weak self] in await self?.isCurrent(current) == true })
                guard isCurrent(current), !Task.isCancelled else { await service.close(); return }
                let registration: (id: TransferServiceID, lease: TransferServiceSessionLease, snapshot: TransferManagerSnapshot)
                do { registration = try await manager.registerSessionServiceWithSnapshot(service, hostID: host.id.uuidString) }
                catch { await service.close(); throw error }
                let id = registration.id
                acquiredLease = registration.lease
                guard isCurrent(current) else { await manager.releaseSessionService(registration.lease); return }
                sessionLease = registration.lease
                serviceRegistrationRevision = registration.snapshot.serviceRevision
                serviceID = id
                applySnapshot(registration.snapshot)
                let start = try await initialPath(service, cancellation)
                guard isCurrent(current) else { await manager.releaseSessionService(registration.lease); return }
                navigationHistory = .init()
                try await load(start, serviceID: id, hostID: host.id.uuidString, generation: current.generation)
                guard isCurrent(current), sessionLease == registration.lease else {
                    await manager.releaseSessionService(registration.lease); return
                }
                state = .ready
                startHealth(request: current, lease: registration.lease, manager: manager, lifetime: managerLifetime)
            } catch {
                if let acquiredLease { await manager.releaseSessionService(acquiredLease) }
                if ownsAttempt(current, lifetime: managerLifetime) {
                    if let change = (error as? FileServiceError)?.changedHostKey {
                        presentChanged(change, request: current, lifetime: managerLifetime)
                    }
                    invalidateCallbacks(preservingChanged: true)
                    guard ownsAttempt(current, lifetime: managerLifetime) else { return }
                    state = .failed; issue = .files(error); serviceID = nil; sessionLease = nil; serviceRegistrationRevision = nil
                }
            }
        }
    }
    /// The user connection, not the currently visible page, owns this lightweight check.
    /// It shares the manager's host gate and the backend's serial native queue with normal I/O.
    private func startHealth(request: FilesRequest, lease: TransferServiceSessionLease,
                             manager: TransferManager, lifetime: UUID) {
        guard let healthInterval else { return }
        healthTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: healthInterval) } catch { return }
                guard let self, self.healthIsCurrent(request, lease: lease, manager: manager, lifetime: lifetime) else { return }
                let checkToken = CancellationToken(); self.healthToken = checkToken
                do {
                    _ = try await manager.withServiceOperation(serviceID: lease.serviceID,
                        hostID: request.host.id.uuidString, token: checkToken) { service, token in
                        try await service.lstat(.root, token: token)
                    }
                } catch {
                    guard !Task.isCancelled, !checkToken.isCancelled,
                          self.healthIsCurrent(request, lease: lease, manager: manager, lifetime: lifetime) else { return }
                    if let failure = error as? FileServiceError, [.transport, .timeout, .closed].contains(failure.kind) {
                        // This task is already past its operation's drain. Do not await itself.
                        self.healthToken = nil; self.healthTask = nil
                        self.retireFailedSession(failure, serviceID: lease.serviceID, lease: lease,
                            manager: manager, lifetime: lifetime, generation: request.generation)
                        return
                    }
                    // Permission/not-found/unsupported are server replies, not lost connections.
                }
                if self.healthToken === checkToken { self.healthToken = nil }
            }
        }
    }
    /// Accept only a failure owned by this exact connected service. The asynchronous release
    /// drains health outside its own task; unrelated jobs and later sessions are never cancelled.
    @discardableResult private func retireFailedSession(_ failure: FileServiceError, serviceID: UUID,
        lease: TransferServiceSessionLease, manager: TransferManager, lifetime: UUID, generation: UInt64,
        backendTerminatedByCancellation: Bool = false) -> Bool {
        let terminalKind = [.transport, .timeout, .closed].contains(failure.kind)
            || (backendTerminatedByCancellation && failure.kind == .cancelled)
        guard terminalKind, self.manager === manager,
              self.lifetime == lifetime, self.generation == generation, self.serviceID == serviceID,
              self.sessionLease == lease, state == .ready, !windowClosing, !terminating,
              token?.isCancelled == false else { return false }
        let health = stopHealth(), previous = closeTask
        self.sessionLease = nil; self.serviceID = nil; self.serviceRegistrationRevision = nil
        self.generation &+= 1; self.request = nil
        cancelTransferPlan(); cancelPathSelection(); invalidateCallbacks()
        operation = nil; operationID = nil
        state = failure.kind == .cancelled ? .disconnected : .failed
        busy = false; hasPendingOperations = false
        issue = failure.kind == .cancelled
            ? .files(FileServiceError(.cancelled, operation: "session-closed-after-operation-cancel", path: failure.path, code: failure.code))
            : .files(failure)
        let retiredAt = self.generation
        closeTask = Task { @MainActor [weak self] in
            await previous?.value; await health?.value
            await manager.releaseSessionService(lease)
            if let self, self.manager === manager, self.lifetime == lifetime, self.generation == retiredAt {
                self.closeTask = nil
            }
        }
        return true
    }
    private func healthIsCurrent(_ request: FilesRequest, lease: TransferServiceSessionLease,
                                 manager: TransferManager, lifetime: UUID) -> Bool {
        self.manager === manager && self.lifetime == lifetime && self.sessionLease == lease
            && self.serviceID == lease.serviceID && self.state == .ready && self.isCurrent(request)
    }
    @discardableResult private func stopHealth() -> Task<Void, Never>? {
        healthToken?.cancel(); healthToken = nil
        let previous = healthTask; healthTask = nil; previous?.cancel()
        return previous
    }
    func isCurrent(_ supplied: FilesRequest) -> Bool {
        let rejected = trustPrompt.map { if case .changed = $0.event { return true }; return false } ?? false
        return !rejected && !terminating && !windowClosing && windowTask == nil && request == supplied
            && selectedHost?.matchesConnection(of: supplied.host) == true
            && token?.isCancelled == false && !Task.isCancelled
    }
    private func ownsAttempt(_ supplied: FilesRequest, lifetime: UUID) -> Bool {
        self.lifetime == lifetime && generation == supplied.generation && request == supplied
            && selectedHost?.matchesConnection(of: supplied.host) == true
            && !terminating && !windowClosing && windowTask == nil
    }
    private func presentChanged(_ change: ChangedHostKey, request: FilesRequest, lifetime: UUID) {
        guard ownsAttempt(request, lifetime: lifetime),
              change.host.address == (try? HostAddress(request.host.address)),
              change.host.port.value == request.host.port else { return }
        if let prompt = trustPrompt, prompt.request == request, case .changed = prompt.event { return }
        // Informational rejection only. No live answer mailbox can accept a changed key.
        trustReply?.cancel(); trustReply = nil; keyboardReply?.cancel(); keyboardReply = nil; keyboardPrompt = nil
        trustPrompt = FilesTrustPrompt(request: request, event: .changed(change))
        state = .failed; issue = .files(FileServiceError(.untrusted, operation: "host-key-changed", changedHostKey: change))
    }
    private func receiveTrust(_ event: FileHostTrustEvent, reply: ChallengeReply<FileHostTrustAnswer>, request: FilesRequest, lifetime: UUID) {
        guard ownsAttempt(request, lifetime: lifetime) else { reply.cancel(); return }
        switch event {
        case .pending(let pending):
            guard isCurrent(request), trustReply == nil, keyboardReply == nil else { reply.resolve(.reject); return }
            guard pending.host.address.value == (try? HostAddress(request.host.address).value), pending.host.port.value == request.host.port else { reply.resolve(.reject); return }
            trustReply = reply; trustPrompt = FilesTrustPrompt(request: request, event: event); state = .awaitingTrust
        case .changed(let change):
            reply.cancel()
            presentChanged(change, request: request, lifetime: lifetime)
        }
    }
    @discardableResult func answerTrust(_ prompt: FilesTrustPrompt, verified: Bool) -> Bool {
        guard verified else { return false }
        return answerTrust(prompt, once: false)
    }
    @discardableResult func answerTrust(_ prompt: FilesTrustPrompt, once: Bool) -> Bool {
        guard isCurrent(prompt.request), trustPrompt?.id == prompt.id, let reply = trustReply,
              case .pending(let decision) = prompt.event else { return false }
        trustReply = nil; trustPrompt = nil; state = .authenticating
        return reply.resolve(once ? .confirmOnce(displayedFingerprint: decision.fingerprint) : .confirm(displayedFingerprint: decision.fingerprint))
    }
    func cancelTrust(_ prompt: FilesTrustPrompt) {
        guard trustPrompt?.id == prompt.id, request == prompt.request else { return }
        cancelCurrent()
    }
    func cancelKeyboard(_ prompt: FilesKeyboardPrompt) {
        guard keyboardPrompt?.id == prompt.id, request == prompt.request else { return }
        cancelCurrent()
    }
    private func receiveKeyboard(_ challenge: FilesKeyboardChallenge, reply: ChallengeReply<[Data]>, request: FilesRequest, cancellation: CancellationToken) {
        guard isCurrent(request), keyboardReply == nil, trustReply == nil, challenge.prompts.count <= 32 else { cancellation.cancel(); reply.cancel(); return }
        keyboardReply = reply
        keyboardPrompt = FilesKeyboardPrompt(request: request, name: SafePrompt.display(String(decoding: challenge.name, as: UTF8.self)),
            instruction: SafePrompt.display(String(decoding: challenge.instruction, as: UTF8.self)),
            prompts: challenge.prompts.map { (SafePrompt.display(String(decoding: $0.bytes, as: UTF8.self)), $0.echo) })
        state = .authenticating
    }
    @discardableResult func answerKeyboard(_ prompt: FilesKeyboardPrompt, answers: [OpenLXSSHSecurity.SecretBytes]) -> Bool {
        guard isCurrent(prompt.request), keyboardPrompt?.id == prompt.id, let reply = keyboardReply,
              answers.count == prompt.prompts.count else { return false }
        let data = answers.map { $0.withUnsafeBytes { Data($0) } }
        guard data.allSatisfy({ $0.count <= 65536 }) else { return false }
        keyboardReply = nil; keyboardPrompt = nil
        return reply.resolve(data)
    }
    private func invalidateCallbacks(preservingChanged: Bool = false) {
        initialInputEpoch = UUID()
        pendingTargets = [:]; browserRevision = UUID()
        let changed = trustPrompt.flatMap { prompt -> FilesTrustPrompt? in
            if preservingChanged, case .changed = prompt.event { return prompt }; return nil
        }
        token?.cancel() // Revoke the operation before resolving either pending mailbox.
        trustReply?.cancel(); trustReply = nil; trustPrompt = changed
        keyboardReply?.cancel(); keyboardReply = nil; keyboardPrompt = nil
        resolveCurrentRisk(false)
    }
    func cancelCurrent() {
        guard !admissionFrozen else { return }
        cancelTransferPlan(); cancelPathSelection()
        let oldServiceID = serviceID, oldLease = sessionLease, oldHealth = stopHealth()
        sessionLease = nil
        let admitted = Array(enqueues.values), planDrains = Array(transferPlanDrains.values)
        discardDeleteBatch(); connectionChangeReview = nil
        invalidateCallbacks(); token?.cancel(); connection?.cancel(); operation?.cancel()
        request = nil; generation &+= 1; serviceID = nil; serviceRegistrationRevision = nil; confirmation = nil; deleteReview = nil; probeReview = nil
        state = .closing; busy = true
        let connection = connection, operation = operation, manager = manager, previous = closeTask, current = generation
        self.connection = nil; self.operation = nil; operationID = nil
        closeTask = Task { [weak self] in
            await previous?.value; await oldHealth?.value; await connection?.value; await operation?.value
            for task in admitted { _ = await task.result }
            for task in planDrains { await task.value }
            if let oldLease { await manager.releaseSessionService(oldLease) }
            else if let oldServiceID { await manager.closeIdleServices([oldServiceID]) }
            guard let self, generation == current else { return }
            closeTask = nil; state = .disconnected; busy = false; hasPendingOperations = false
            if let pendingHostUpdate { selectedHost = pendingHostUpdate; self.pendingHostUpdate = nil }
            issue = nil
        }
    }
    private func observeManager() {
        guard observation == nil else { return }
        let manager = manager, lifetime = lifetime
        observation = Task { [weak self] in
            guard let stream = try? await manager.updates() else { return }
            for await snapshot in stream {
                guard let self, self.lifetime == lifetime, !Task.isCancelled else { return }
                receiveManagerSnapshot(snapshot, manager: manager)
            }
        }
    }
    /// The observer's captured manager is part of delivery identity. A completed
    /// old manager cannot deliver lifecycle facts into a reopened window.
    func receiveManagerSnapshot(_ snapshot: TransferManagerSnapshot, manager observedManager: TransferManager) {
        guard manager === observedManager else { return }
        applySnapshot(snapshot)
    }
    func currentTransferSpeed(_ id: TransferJobID) -> Double? {
        guard let sample = transferSamples[id], sample.time.duration(to: .now) < .seconds(2) else { return nil }
        return transferSpeeds[id]
    }
    private func applySnapshot(_ snapshot: TransferManagerSnapshot) {
        guard snapshot.serviceRevision >= observedServiceRevision else { return }
        let now = ContinuousClock.now
        for job in snapshot.jobs {
            if let previous = transferSamples[job.id], job.transferredBytes >= previous.bytes {
                let duration = previous.time.duration(to: now).components
                let seconds = Double(duration.seconds) + Double(duration.attoseconds) / 1e18
                if seconds >= 0.05 { transferSpeeds[job.id] = job.state.isActive ? Double(job.transferredBytes - previous.bytes) / seconds : nil }
            }
            transferSamples[job.id] = (job.transferredBytes, now)
            if !job.state.isActive { transferSpeeds[job.id] = nil }
        }
        let ids = Set(snapshot.jobs.map(\.id)); transferSamples = transferSamples.filter { ids.contains($0.key) }; transferSpeeds = transferSpeeds.filter { ids.contains($0.key) }
        let batches = Dictionary(grouping: snapshot.jobs, by: { $0.request.batchID })
        let completed = batches.filter { !completedBatchIDs.contains($0.key) && !$0.value.contains { $0.state.isActive } }
        if !completed.isEmpty {
            completedBatchIDs.formUnion(completed.keys)
            completedBatchIDs.formIntersection(Set(batches.keys))
            latestCompletedBatchJobs = completed.values.flatMap { $0 }
            transferCompletionRevision &+= 1
        }
        transferSnapshot = snapshot
        observedServiceRevision = snapshot.serviceRevision
        observedServices = Dictionary(uniqueKeysWithValues: snapshot.services.map { ($0.id, $0) })
        hasActiveTransfers = snapshot.jobs.contains { $0.state.isActive }
        reconcileServiceState()
        hasPendingOperations = connection != nil || !snapshot.serviceOperations.isEmpty || !transferPlanDrains.isEmpty
            || transferPlanPhase == .preparing || transferPlanPhase == .confirming || (state == .closing && serviceID != nil)
    }
    private func reconcileServiceState() {
        guard connection == nil, closeTask == nil, windowTask == nil, !windowClosing, !terminating,
              state == .ready || state == .closing, let id = serviceID,
              let registeredAt = serviceRegistrationRevision, observedServiceRevision >= registeredAt else { return }
        if let failure = observedServices[id]?.terminalFailure, let lease = sessionLease,
           retireFailedSession(failure, serviceID: id, lease: lease, manager: manager, lifetime: lifetime, generation: generation,
                               backendTerminatedByCancellation: true) { return }
        if observedServices[id]?.state == .available { return }
        if state == .ready {
            stopHealth(); sessionLease = nil
            // No service operation/job lease can be active when the manager
            // starts closing this service. Revoke unadmitted browser targets,
            // not unrelated jobs or the manager that owns their lifetime.
            cancelTransferPlan(); cancelPathSelection(); discardDeleteBatch(); discardDeleteReview()
            invalidateCallbacks(); operation?.cancel(); operation = nil; operationID = nil
            generation &+= 1; request = nil; pendingTargets = [:]; browserRevision = UUID()
            confirmation = nil; probeReview = nil; connectionChangeReview = nil; initialInputEpoch = UUID()
        }
        if observedServices[id]?.state == .closing {
            state = .closing; busy = true; hasPendingOperations = true
        } else {
            serviceID = nil; serviceRegistrationRevision = nil
            state = .disconnected; busy = false; hasPendingOperations = false
            if let pendingHostUpdate { selectedHost = pendingHostUpdate; self.pendingHostUpdate = nil }
            issue = AppIssue(code: "files.connectionReleased", message: "文件连接已释放。请手动重新连接后继续。")
        }
    }
    var canTransfer: Bool { state == .ready && serviceID != nil && !busy && !admissionFrozen && !terminating && !windowClosing && transferPlanOwner == nil && transferPlanDrains.isEmpty }
    private func transferContextIsCurrent(_ context: FilesTransferContext) -> Bool {
        context.lifetime == lifetime && context.generation == generation
            && context.serviceID == serviceID && context.hostID == selectedHost?.id
            && context.connectionIdentity == selectedHost?.connectionIdentity
            && pendingHostUpdate == nil && state == .ready && !admissionFrozen && !terminating && !windowClosing
    }
    func transferContext(upload: Bool) throws -> FilesTransferContext {
        guard canTransfer, let serviceID, let host = selectedHost else { throw FileServiceError(.closed, operation: "files-transfer-not-ready") }
        return FilesTransferContext(lifetime: lifetime, generation: generation, revision: browserRevision,
            serviceID: serviceID, hostID: host.id, host: host,
            endpoint: host.username + "@" + host.address + ":" + String(host.port), path: path, confirmation: confirmation)
    }
    /// Admission is recorded synchronously, before a Task or Manager actor hop can suspend.
    func enqueueUploads(_ urls: [URL], context: FilesTransferContext) throws -> Task<[TransferJobID], Error> {
        try enqueue(context: context, uploads: urls, downloads: [], destination: nil)
    }
    func enqueueDownloads(_ selected: [DirectoryEntry], to directory: URL, context: FilesTransferContext) throws -> Task<[TransferJobID], Error> {
        guard selected.allSatisfy({ entries.contains($0) }), !selected.isEmpty else { throw FileServiceError(.conflict, operation: "stale-download-selection") }
        return try enqueue(context: context, uploads: [], downloads: selected, destination: directory)
    }
    private func enqueue(context: FilesTransferContext, uploads: [URL], downloads: [DirectoryEntry], destination: URL?) throws -> Task<[TransferJobID], Error> {
        guard transferPlanOwner == nil, transferPlanDrains.isEmpty else {
            throw FileServiceError(.conflict, operation: "files-transfer-review-busy")
        }
        guard transferContextIsCurrent(context),
              (!uploads.isEmpty || !downloads.isEmpty), uploads.count + downloads.count <= 128 else {
            throw FileServiceError(.closed, operation: "files-transfer-admission")
        }
        transferPreparationIssue = nil
        let slot = UUID(), manager = manager, localService = localService, planToken = CancellationToken()
        let actionConflictPolicy = TransferConflictPolicy(rawValue: conflictPreference.rawValue) ?? .ask
        // Even local descriptor registration can suspend: own the prospective review before
        // that hop so hide/navigation/freeze can revoke it before directory metadata begins.
        let direction: FilesTransferDirection = uploads.isEmpty ? .download : .upload
        transferPlanOwner = TransferPlanOwner(id: slot, context: context, token: planToken, direction: direction)
        transferPlanPhase = .preparing
        enqueueInFlight += 1; observeManager()
        let task = Task { @MainActor [self] () throws -> [TransferJobID] in
            var registered: [TransferServiceID] = []
            var admittedFiles = false
            defer {
                enqueues[slot] = nil; enqueueInFlight -= 1
                if transferPlanOwner?.id == slot, transferPlanReview == nil { clearTransferPlanOwner(slot) }
            }
            do {
                await manager.setConflictPolicy(TransferConflictPolicy(rawValue: conflictPreference.rawValue) ?? .ask)
                let batch = TransferBatchID()
                var requests: [TransferRequest] = []
                var totals: [UInt64?] = []
                var localRoots: [TransferServiceID: RemotePath] = [:]
                if !uploads.isEmpty {
                    var parents: [RemotePath: TransferServiceID] = [:]
                    for url in uploads {
                        let components = try FilesLocalPaths.components(url)
                        guard let name = components.last else { throw FileServiceError(.invalidPath, operation: "upload-filesystem-root") }
                        let parentParts = Array(components.dropLast()), parent = try FilesLocalPaths.rawPath(parentParts)
                        let fd = try FilesLocalPaths.openDirectory(parentParts)
                        let kind: TransferKind, localID: TransferServiceID
                        do {
                            kind = try FilesLocalPaths.inspect(name, parent: fd)
                            let attributes = try FilesLocalPaths.attributes(name, parent: fd)
                            totals.append(kind == .file ? attributes.size : nil)
                            if let existing = parents[parent] { localID = existing }
                            else {
                                let service = try localService(fd)
                                do { localID = try await manager.registerService(service) }
                                catch { await service.close(); throw error }
                                registered.append(localID); parents[parent] = localID; localRoots[localID] = parent
                            }
                            Darwin.close(fd)
                        } catch { Darwin.close(fd); throw error }
                        requests.append(TransferRequest(hostID: context.hostID.uuidString, batchID: batch,
                            source: .init(serviceID: localID, path: try RemotePath.root.appending(name)),
                            destination: .init(serviceID: context.serviceID, path: try context.path.appending(name)), kind: kind, conflictPolicy: actionConflictPolicy))
                    }
                } else {
                    guard let destination else { throw FileServiceError(.invalidPath, operation: "download-root") }
                    let components = try FilesLocalPaths.components(destination)
                    let fd = try FilesLocalPaths.openDirectory(components)
                    let service: any RemoteFileService
                    do { service = try localService(fd); Darwin.close(fd) }
                    catch { Darwin.close(fd); throw error }
                    let id: TransferServiceID
                    do { id = try await manager.registerService(service) }
                    catch { await service.close(); throw error }
                    registered.append(id); localRoots[id] = try FilesLocalPaths.rawPath(components)
                    for entry in downloads {
                        guard entry.attributes.kind == .regular || entry.attributes.kind == .directory else {
                            throw FileServiceError(entry.attributes.kind == .symbolicLink ? .symbolicLink : .unsupported, operation: "download-selection-kind")
                        }
                        totals.append(entry.attributes.kind == .regular ? entry.attributes.size : nil)
                        requests.append(TransferRequest(hostID: context.hostID.uuidString, batchID: batch,
                            source: .init(serviceID: context.serviceID, path: try context.path.appending(entry.name)),
                            destination: .init(serviceID: id, path: try RemotePath.root.appending(entry.name)),
                            kind: entry.attributes.kind == .directory ? .tree : .file, conflictPolicy: actionConflictPolicy))
                    }
                }
                let confirmations = context.confirmation.map { [context.serviceID: $0] } ?? [:]
                if requests.contains(where: { $0.kind == .tree }) {
                    try planToken.check()
                    guard transferPlanOwner?.id == slot, transferContextIsCurrent(context) else {
                        throw FileServiceError(.cancelled, operation: "files-transfer-plan-stale")
                    }
                    transferPlanOwner?.registeredLocalIDs = registered
                    let plan = try await manager.prepareBatch(requests, serverConfirmations: uploads.isEmpty ? [:] : confirmations, token: planToken)
                    guard transferPlanOwner?.id == slot, transferContextIsCurrent(context), !planToken.isCancelled else {
                        await manager.discardPreparedBatch(plan.id)
                        throw FileServiceError(.cancelled, operation: "files-transfer-plan-late")
                    }
                    let ids = try await submitPreparedTransfer(plan, ownerID: slot, context: context,
                        direction: direction, localRoots: localRoots, token: planToken)
                    admittedFiles = true
                    return ids
                }
                // Pure-file actions retain the already-admitted, frozen-target behavior. A later
                // hide/freeze revokes unconfirmed directory metadata, not these admitted files.
                admittedFiles = true
                clearTransferPlanOwner(slot)
                let ids = try await manager.enqueueBatch(requests, serverConfirmations: uploads.isEmpty ? [:] : confirmations)
                for (index, id) in ids.enumerated() {
                    transferLabels[id] = FilesTransferLabel(endpoint: context.endpoint, direction: uploads.isEmpty ? "下载" : "上传", localRoots: localRoots, totalBytes: totals.indices.contains(index) ? totals[index] : nil)
                    retryOrigins[id] = makeRetryOrigin(requests[index], context: context, direction: direction, localRoots: localRoots)
                }
                applySnapshot(await manager.snapshot())
                return ids
            } catch {
                await manager.closeIdleServices(registered)
                if !planToken.isCancelled, context.lifetime == lifetime,
                   transferPlanOwner?.id == slot || (admittedFiles && transferPlanOwner == nil) {
                    issue = .files(error); transferPreparationIssue = .files(error)
                }
                throw error
            }
        }
        enqueues[slot] = task; connectionChangeReview = nil
        return task
    }
    /// A click/drop is the execution intent. Preparation remains read-only and bounded,
    /// then the same immutable plan is admitted without a second UI decision.
    private func submitPreparedTransfer(_ plan: TransferBatchPlan, ownerID: UUID, context: FilesTransferContext,
        direction: FilesTransferDirection?, localRoots: [TransferServiceID: RemotePath], token: CancellationToken) async throws -> [TransferJobID] {
        guard transferPlanOwner?.id == ownerID, transferContextIsCurrent(context), !token.isCancelled else {
            await manager.discardPreparedBatch(plan.id)
            throw FileServiceError(.cancelled, operation: "transfer-preparation-stale")
        }
        transferPlanOwner?.planID = plan.id
        transferPlanPhase = .confirming
        let ids = try await manager.confirmPreparedBatch(plan.id, token: token)
        for (index, id) in ids.enumerated() {
            let request = plan.requests[index]
            transferLabels[id] = FilesTransferLabel(endpoint: context.endpoint, direction: direction?.title ?? "传输", localRoots: localRoots,
                totalBytes: request.sourceManifest?.totalBytes)
            if let direction { retryOrigins[id] = makeRetryOrigin(request, context: context, direction: direction, localRoots: localRoots) }
        }
        clearTransferPlanOwner(ownerID)
        applySnapshot(await manager.snapshot())
        return ids
    }
    private func publishTransferPlan(_ plan: TransferBatchPlan, ownerID: UUID, context: FilesTransferContext,
                                     direction: String, localRoots: [TransferServiceID: RemotePath], registered: [TransferServiceID]) {
        guard transferPlanOwner?.id == ownerID else { return }
        transferPlanOwner?.planID = plan.id; transferPlanOwner?.registeredLocalIDs = registered
        transferPlanReview = FilesTransferPlanReview(id: ownerID, plan: plan, context: context, direction: direction,
            localRoots: localRoots, registeredLocalIDs: registered)
        transferPlanPhase = .ready
        transferPlanExpiry?.cancel()
        let seconds = max(0, min(300, plan.expiresAt.timeIntervalSinceNow))
        transferPlanExpiry = Task { @MainActor [weak self] in
            do { try await Task.sleep(for: .seconds(seconds)) } catch { return }
            self?.cancelTransferPlan(ownerID: ownerID)
        }
    }
    private func clearTransferPlanOwner(_ expected: UUID) {
        guard transferPlanOwner?.id == expected else { return }
        transferPlanExpiry?.cancel(); transferPlanExpiry = nil
        transferPlanOwner = nil; transferPlanReview = nil; transferPlanPhase = nil
    }
    /// Cancels only this unsubmitted metadata/confirmation operation. Drains and closes only
    /// services registered for this review; existing retry services and unrelated jobs survive.
    func cancelTransferPlan(ownerID expected: UUID? = nil) {
        guard let owner = transferPlanOwner, expected == nil || expected == owner.id else { return }
        owner.token.cancel(); clearTransferPlanOwner(owner.id)
        let manager = manager, pending = enqueues[owner.id], slot = UUID()
        let drain = Task { @MainActor [self] in
            _ = await pending?.result
            if let planID = owner.planID { await manager.discardPreparedBatch(planID) }
            await manager.closeIdleServices(owner.registeredLocalIDs)
            transferPlanDrains[slot] = nil
            if owner.context.lifetime == lifetime { applySnapshot(await manager.snapshot()) }
        }
        transferPlanDrains[slot] = drain
    }
    func localTransferLocationChanged() { /* Already-admitted targets are independent of later browsing. */ }
    func waitUntilTransferPlanDrained() async {
        while !transferPlanDrains.isEmpty {
            for task in Array(transferPlanDrains.values) { await task.value }
        }
    }
    /// Synchronous one-shot phase transition; confirmation takes only the frozen plan ID.
    @discardableResult func confirmTransferPlan(_ review: FilesTransferPlanReview) -> Task<[TransferJobID], Error>? {
        guard let owner = transferPlanOwner, owner.id == review.id, owner.planID == review.plan.id,
              transferPlanReview?.id == review.id, transferPlanPhase == .ready, review.canConfirm,
              transferContextIsCurrent(review.context), !owner.token.isCancelled else { return nil }
        transferPlanPhase = .confirming
        let manager = manager, slot = owner.id, token = owner.token, direction = owner.direction
        enqueueInFlight += 1
        let task = Task { @MainActor [self] () throws -> [TransferJobID] in
            defer {
                enqueues[slot] = nil; enqueueInFlight -= 1
                clearTransferPlanOwner(slot)
            }
            do {
                let ids = try await manager.confirmPreparedBatch(review.plan.id, token: token)
                // Admission may already have won before hide; retain the actual job labels and
                // do not turn a confirmed transfer into a view-owned cancellable operation.
                if review.context.lifetime == lifetime {
                    let labels = review.labels
                    for (index, id) in ids.enumerated() {
                        transferLabels[id] = labels[index]
                        if let direction {
                            retryOrigins[id] = makeRetryOrigin(review.plan.requests[index], context: review.context,
                                direction: direction, localRoots: review.localRoots)
                        }
                    }
                    applySnapshot(await manager.snapshot())
                }
                return ids
            } catch {
                await manager.discardPreparedBatch(review.plan.id)
                await manager.closeIdleServices(review.registeredLocalIDs)
                if transferPlanOwner?.id == slot, !token.isCancelled { issue = .files(error) }
                throw error
            }
        }
        enqueues[slot] = task
        return task
    }
    func chooseUploads(window: NSWindow?) {
        do {
            let context = try transferContext(upload: true)
            pathPicker.choose(upload: true, window: window) { [weak self] urls in
                do { _ = try self?.enqueueUploads(urls, context: context) }
                catch { self?.issue = .files(error) }
            }
        } catch { issue = .files(error) }
    }
    func chooseDownloads(_ selected: [DirectoryEntry], window: NSWindow?) {
        do {
            let context = try transferContext(upload: false)
            pathPicker.choose(upload: false, window: window) { [weak self] urls in
                guard let directory = urls.first else { return }
                do { _ = try self?.enqueueDownloads(selected, to: directory, context: context) }
                catch { self?.issue = .files(error) }
            }
        } catch { issue = .files(error) }
    }
    func acceptFileDrop(_ pasteboard: NSPasteboard) -> Bool {
        guard let urls = FilesDrop.urls(pasteboard) else { return false }
        do { _ = try enqueueUploads(urls, context: transferContext(upload: true)); return true }
        catch { issue = .files(error); return false }
    }
    func freezeTransferAdmission() {
        admissionFrozen = true; historyRemovalEpoch = UUID(); historyRemovalReview = nil; browserRevision = UUID(); cancelPathSelection()
        cancelTransferPlan()
    }
    func resumeTransferAdmission() { if !terminating && !windowClosing { admissionFrozen = false } }
    func activeTransferSnapshot() async -> Bool {
        // No new enqueue/retry can enter after freeze. Wait every already-admitted actor hop.
        while !enqueues.isEmpty || !metadataMutations.isEmpty || !transferPlanDrains.isEmpty {
            for task in Array(enqueues.values) { _ = await task.result }
            for task in Array(metadataMutations.values) { _ = await task.value }
            await waitUntilTransferPlanDrained()
        }
        let value = await manager.snapshot(); applySnapshot(value)
        return value.jobs.contains { $0.state.isActive }
    }
    func displayedTransferPath(_ path: RemotePath, serviceID: UUID, jobID: UUID) -> String {
        guard let root = transferLabels[jobID]?.localRoots[serviceID] else { return FileDisplay.path(path) }
        return FileDisplay.bytes((root == .root ? Data() : root.bytes) + path.bytes)
    }
    func prepareHistoryRemoval() -> FilesHistoryRemovalReview? {
        guard !admissionFrozen, !terminating, !windowClosing else { return nil }
        let jobs = transferSnapshot.jobs.filter { !$0.state.isActive }
        guard !jobs.isEmpty else { return nil }
        let review = FilesHistoryRemovalReview(managerLifetime: lifetime, jobs: jobs,
            labels: transferLabels.filter { id, _ in jobs.contains { $0.id == id } })
        historyRemovalReview = review
        return review
    }
    func discardHistoryRemoval(_ review: FilesHistoryRemovalReview) {
        if historyRemovalReview?.id == review.id { historyRemovalReview = nil }
    }
    /// Only the immutable, already-displayed terminal report set may be removed. Newly
    /// completed jobs are never added, and cancellation/close freeze wins across every await.
    func removeFinishedTransfers(_ review: FilesHistoryRemovalReview) -> Task<Bool, Never> {
        guard !admissionFrozen, !terminating, !windowClosing, review.managerLifetime == lifetime,
              historyRemovalReview?.id == review.id else { return Task { false } }
        historyRemovalReview = nil
        let slot = UUID(), manager = manager, beforeSnapshot = beforeHistoryRemovalSnapshot, epoch = historyRemovalEpoch
        let task = Task { @MainActor [self] in
            defer { metadataMutations[slot] = nil }
            await beforeSnapshot?()
            let current = await manager.snapshot()
            guard !admissionFrozen, !terminating, !windowClosing, epoch == historyRemovalEpoch, review.managerLifetime == lifetime,
                  review.jobs.allSatisfy({ expected in
                      !expected.state.isActive && current.jobs.contains(expected)
                  }) else { return false }
            // The MainActor admission freeze and this dispatch are linearized here.
            // A close waits metadataMutations before observing its final report.
            let ids = review.jobs.map(\.id)
            let removed = await manager.removeFinishedJobs(ids)
            guard review.managerLifetime == lifetime else { return false }
            for id in ids { transferLabels[id] = nil; retryOrigins[id] = nil }
            if let retrySelection, ids.contains(retrySelection.jobID) { cancelPathSelection() }
            applySnapshot(await manager.snapshot())
            return removed == ids.count
        }
        metadataMutations[slot] = task
        return task
    }
    func cancelTransfer(_ id: TransferJobID) async { _ = await manager.cancel(id); applySnapshot(await manager.snapshot()) }
    @discardableResult func cancelTransferDecision(_ request: TransferDecisionRequest) async -> Bool {
        guard !terminating, !windowClosing else { return false }
        let result = await manager.cancelPendingDecision(request)
        applySnapshot(await manager.snapshot()); return result
    }
    func cancelBatch(_ id: TransferBatchID) async {
        let jobs = await manager.snapshot().jobs.filter { $0.request.batchID == id && $0.state.isActive }
        for job in jobs { _ = await manager.cancel(job.id) }
        applySnapshot(await manager.snapshot())
    }
    func locateTransfer(_ job: TransferJobSnapshot) {
        guard let current = transferSnapshot.jobs.first(where: { $0.id == job.id && $0.generation == job.generation }), current.state == .succeeded || current.state == .completedWithSkips else { return }
        let resolved = job.items.first(where: { if case .succeeded = $0.state { return true }; return false })?.destination ?? job.request.destination.path
        if let root = transferLabels[job.id]?.localRoots[job.request.destination.serviceID] {
            if let path = try? RemotePath(bytes: (root == .root ? Data() : root.bytes) + resolved.bytes) {
                NSWorkspace.shared.activateFileViewerSelecting([FilesLocalPaths.url(path)])
            }
        } else if job.request.destination.serviceID == serviceID, job.request.hostID == selectedHost?.id.uuidString {
            browse(resolved.parent)
        } else { issue = AppIssue(code: "files.locateOriginalConnection", message: "结果仍位于任务所示原端点；请手动选择该主机并连接后定位，不会自动认证。") }
    }
    @discardableResult func answerTransfer(_ decision: TransferDecisionRequest, answer: TransferDecisionAnswer) async -> Bool {
        guard !terminating, !windowClosing else { return false }
        let result = await manager.resolve(decision, answer: answer)
        applySnapshot(await manager.snapshot()); return result
    }
    func retryTransfer(_ id: TransferJobID) throws -> Task<[TransferJobID], Error> {
        transferPreparationIssue = nil
        guard !admissionFrozen, !terminating, !windowClosing else { throw FileServiceError(.closed, operation: "retry-admission") }
        if let job = transferSnapshot.jobs.first(where: { $0.id == id }), job.request.sourceManifest != nil || job.request.kind == .tree {
            return try prepareTransferRetry(job)
        }
        guard transferPlanOwner == nil, transferPlanDrains.isEmpty else { throw FileServiceError(.conflict, operation: "files-transfer-review-busy") }
        let slot = UUID(), manager = manager, label = transferLabels[id]
        enqueueInFlight += 1
        let task = Task { @MainActor [self] () throws -> [TransferJobID] in
            defer { enqueues[slot] = nil; enqueueInFlight -= 1 }
            do {
                let next = try await manager.retry(id)
                retryOrigins[next] = retryOrigins[id]
                transferLabels[next] = label; applySnapshot(await manager.snapshot()); return [next]
            } catch {
                issue = .files(error)
                if (error as? FileServiceError)?.kind != .cancelled, !(error is CancellationError) { transferPreparationIssue = issue }
                throw error
            }
        }
        enqueues[slot] = task; return task
    }
    private func prepareTransferRetry(_ job: TransferJobSnapshot) throws -> Task<[TransferJobID], Error> {
        transferPreparationIssue = nil
        guard transferPlanOwner == nil, transferPlanDrains.isEmpty else { throw FileServiceError(.conflict, operation: "files-transfer-review-busy") }
        let context = try transferContext(upload: false)
        guard job.request.hostID == context.hostID.uuidString,
              job.request.source.serviceID == context.serviceID || job.request.destination.serviceID == context.serviceID,
              let label = transferLabels[job.id] else { throw FileServiceError(.closed, operation: "retry-original-connection-required") }
        let slot = UUID(), manager = manager, token = CancellationToken()
        transferPlanOwner = TransferPlanOwner(id: slot, context: context, token: token, direction: retryOrigins[job.id]?.direction)
        transferPlanPhase = .preparing; enqueueInFlight += 1; observeManager()
        let task = Task { @MainActor [self] () throws -> [TransferJobID] in
            defer {
                enqueues[slot] = nil; enqueueInFlight -= 1
                if transferPlanOwner?.id == slot, transferPlanReview == nil { clearTransferPlanOwner(slot) }
            }
            do {
                let plan = try await manager.prepareRetry(job.id, token: token)
                guard transferPlanOwner?.id == slot, transferContextIsCurrent(context), !token.isCancelled else {
                    await manager.discardPreparedBatch(plan.id)
                    throw FileServiceError(.cancelled, operation: "files-retry-plan-late")
                }
                // Existing job services are borrowed, not newly registered resources owned by
                // this review. Cancelling a retry review must never close those services.
                return try await submitPreparedTransfer(plan, ownerID: slot, context: context,
                    direction: retryOrigins[job.id]?.direction, localRoots: label.localRoots, token: token)
            } catch {
                if transferPlanOwner?.id == slot, !token.isCancelled,
                   (error as? FileServiceError)?.kind != .cancelled, !(error is CancellationError) {
                    issue = .files(error); transferPreparationIssue = issue
                }
                throw error
            }
        }
        enqueues[slot] = task; return task
    }
    private func makeRetryOrigin(_ request: TransferRequest, context: FilesTransferContext,
                                 direction: FilesTransferDirection, localRoots: [TransferServiceID: RemotePath]) -> FilesTransferRetryOrigin? {
        let localID = direction == .upload ? request.source.serviceID : request.destination.serviceID
        let remoteID = direction == .upload ? request.destination.serviceID : request.source.serviceID
        guard request.hostID == context.hostID.uuidString, remoteID == context.serviceID, let root = localRoots[localID] else { return nil }
        return FilesTransferRetryOrigin(lifetime: context.lifetime, hostID: context.hostID, host: context.host,
            direction: direction, source: request.source, destination: request.destination, kind: request.kind, localRoot: root)
    }
    private func cancelPathSelection() { retrySelection = nil; pathPicker.cancel() }
    private static func retryIssue(_ error: Error) -> AppIssue { (error as? FilesRetryAuthorizationError)?.issue ?? .files(error) }
    func prepareTransferRetrySelection(_ id: TransferJobID) throws -> FilesTransferRetrySelection {
        guard transferPlanOwner == nil, transferPlanDrains.isEmpty, retrySelection == nil, !pathPicker.isChoosing, !busy else {
            throw FilesRetryAuthorizationError.busy
        }
        guard let job = transferSnapshot.jobs.first(where: { $0.id == id }), job.state == .failed || job.state == .cancelled,
              let origin = retryOrigins[id], origin.matches(job), origin.lifetime == lifetime else {
            throw FilesRetryAuthorizationError.originUnavailable
        }
        guard selectedHost?.id == origin.hostID, selectedHost?.connectionIdentity == origin.connectionIdentity,
              pendingHostUpdate == nil, state == .ready else { throw FilesRetryAuthorizationError.originalConnectionRequired }
        let context = try transferContext(upload: origin.direction == .upload)
        let request = FilesTransferRetrySelection(jobID: id, jobGeneration: job.generation, origin: origin, context: context)
        retrySelection = request
        return request
    }
    func cancelTransferRetrySelection(_ request: FilesTransferRetrySelection) {
        if retrySelection?.id == request.id { retrySelection = nil }
    }
    func chooseTransferRetry(_ id: TransferJobID, window: NSWindow?) {
        do {
            let request = try prepareTransferRetrySelection(id)
            let original = FilesLocalPaths.url(try request.origin.localSelectionPath())
            let started = pathPicker.chooseRetry(upload: request.origin.direction == .upload, original: original, window: window) { [weak self] urls in
                guard let self else { return }
                guard let urls else { cancelTransferRetrySelection(request); return }
                do { _ = try acceptTransferRetrySelection(request, urls: urls) }
                catch { issue = Self.retryIssue(error) }
            }
            if !started { cancelTransferRetrySelection(request); issue = FilesRetryAuthorizationError.busy.issue }
        } catch { issue = Self.retryIssue(error) }
    }
    /// Only a fresh, explicit picker result can authorize the local side. The
    /// original raw path is compared before any disk open; display text is unused.
    func acceptTransferRetrySelection(_ request: FilesTransferRetrySelection, urls: [URL]) throws -> Task<[TransferJobID], Error> {
        guard retrySelection?.id == request.id else { throw FilesRetryAuthorizationError.stale }
        retrySelection = nil
        guard transferPlanOwner == nil, transferPlanDrains.isEmpty,
              transferContextIsCurrent(request.context), request.origin.lifetime == lifetime,
              retryOrigins[request.jobID] == request.origin,
              transferSnapshot.jobs.contains(where: { $0.id == request.jobID && $0.generation == request.jobGeneration
                  && ($0.state == .failed || $0.state == .cancelled) && request.origin.matches($0) }) else {
            throw FilesRetryAuthorizationError.stale
        }
        guard urls.count == 1,
              try FilesLocalPaths.rawPath(FilesLocalPaths.components(urls[0])) == request.origin.localSelectionPath() else {
            throw FilesRetryAuthorizationError.originalSelectionRequired
        }
        transferPreparationIssue = nil
        let slot = UUID(), manager = manager, token = CancellationToken(), context = request.context, origin = request.origin
        let factory = localService
        transferPlanOwner = TransferPlanOwner(id: slot, context: context, token: token, direction: origin.direction)
        transferPlanPhase = .preparing; enqueueInFlight += 1; observeManager()
        let task = Task { @MainActor [self] () throws -> [TransferJobID] in
            var registered: [TransferServiceID] = [], planID: UUID?
            defer {
                enqueues[slot] = nil; enqueueInFlight -= 1
                if transferPlanOwner?.id == slot, transferPlanReview == nil { clearTransferPlanOwner(slot) }
            }
            do {
                try token.check()
                guard transferPlanOwner?.id == slot, transferContextIsCurrent(context) else { throw FilesRetryAuthorizationError.stale }
                let fd = try FilesLocalPaths.openDirectory(FilesLocalPaths.components(origin.localRoot))
                let service: any RemoteFileService
                do {
                    if origin.direction == .upload {
                        guard try FilesLocalPaths.components(origin.source.path).count == 1, let name = origin.source.path.name,
                              try FilesLocalPaths.inspect(name, parent: fd) == origin.kind else {
                            throw FilesRetryAuthorizationError.originalSelectionRequired
                        }
                    }
                    service = try factory(fd); Darwin.close(fd)
                } catch { Darwin.close(fd); throw error }
                let localID: TransferServiceID
                do { localID = try await manager.registerService(service) }
                catch { await service.close(); throw error }
                registered.append(localID)
                guard transferPlanOwner?.id == slot, transferContextIsCurrent(context), !token.isCancelled else {
                    throw FilesRetryAuthorizationError.stale
                }
                transferPlanOwner?.registeredLocalIDs = registered
                let plan = try await manager.prepareRetry(request.jobID,
                    sourceService: origin.direction == .upload ? localID : context.serviceID,
                    destinationService: origin.direction == .upload ? context.serviceID : localID,
                    serverConfirmation: origin.direction == .upload ? context.confirmation : nil, token: token)
                planID = plan.id
                guard transferPlanOwner?.id == slot, transferContextIsCurrent(context), !token.isCancelled else {
                    throw FilesRetryAuthorizationError.stale
                }
                return try await submitPreparedTransfer(plan, ownerID: slot, context: context,
                    direction: origin.direction, localRoots: [localID: origin.localRoot], token: token)
            } catch {
                if let planID { await manager.discardPreparedBatch(planID) }
                await manager.closeIdleServices(registered)
                if transferPlanOwner?.id == slot, !token.isCancelled,
                   (error as? FileServiceError)?.kind != .cancelled, !(error is CancellationError) {
                    issue = Self.retryIssue(error); transferPreparationIssue = issue
                }
                throw error
            }
        }
        enqueues[slot] = task
        return task
    }
    private func load(_ path: RemotePath, serviceID: UUID, hostID: String, generation: UInt64, historyIndex: Int? = nil) async throws {
        do {
            let snapshot = try await manager.withServiceOperation(serviceID: serviceID, hostID: hostID) { service, token in
                try await Self.inspectDirectory(service, path: path, token: token)
                let attr = try await service.lstat(path, token: token)
                guard attr.kind == .directory else { throw FileServiceError(attr.kind == .symbolicLink ? .symbolicLink : .conflict, operation: "browse-kind", path: path) }
                let rows = try await service.list(path, token: token)
                guard Set(rows.map(\.name)).count == rows.count else { throw FileServiceError(.protocolFailure, operation: "duplicate-listing") }
                return FilesDirectorySnapshot(attributes: attr, entries: rows.sorted { $0.name.bytes.lexicographicallyPrecedes($1.name.bytes) })
            }
            guard self.generation == generation, self.serviceID == serviceID, !Task.isCancelled else { throw FileServiceError(.cancelled, operation: "stale-list") }
            self.path = path; parentAttributes = snapshot.attributes; entries = snapshot.entries; navigationHistory.commit(path, index: historyIndex); readFailed = false
        } catch {
            if self.generation == generation, self.serviceID == serviceID, !Task.isCancelled { readFailed = true }
            throw error
        }
    }
    func go(manualUTF8: String) {
        do { browse(manualUTF8.isEmpty ? path : try RemotePath(manualUTF8)) }
        catch { issue = .files(error) }
    }
    func browse(_ path: RemotePath) { browse(path, historyIndex: nil) }
    private func browse(_ path: RemotePath, historyIndex: Int?) {
        cancelPathSelection()
        discardDeleteBatch(); discardDeleteReview()
        startOperation { [self] id, host, generation in try await load(path, serviceID: id, hostID: host, generation: generation, historyIndex: historyIndex) }
    }
    func back() { if let target = navigationHistory.backward { browse(target.path, historyIndex: target.index) } }
    func forward() { if let target = navigationHistory.forward { browse(target.path, historyIndex: target.index) } }
    func enter(_ entry: DirectoryEntry) {
        guard entries.contains(entry), entry.attributes.kind == .directory else {
            issue = .files(FileServiceError(.symbolicLink, operation: "enter-link-refused")); return
        }
        do { browse(try path.appending(entry.name)) } catch { issue = .files(error) }
    }
    private func startOperation(revision: UUID = UUID(), _ body: @escaping @MainActor (UUID, String, UInt64) async throws -> Void) {
        guard operation == nil, connection == nil, closeTask == nil, windowTask == nil, !admissionFrozen, !terminating, !windowClosing,
              let id = serviceID, let host = selectedHost, state == .ready else { return }
        let current = generation, slot = UUID(), managerLifetime = lifetime, manager = manager, lease = sessionLease
        operationID = slot
        browserRevision = revision; pendingTargets = [:]
        busy = true; hasPendingOperations = true; issue = nil
        operation = Task { [weak self] in
            guard let self else { return }
            defer {
                if generation == current && operationID == slot {
                    operation = nil; operationID = nil; busy = false; hasPendingOperations = false
                }
            }
            do {
                guard lifetime == managerLifetime, generation == current, operationID == slot, !windowClosing, !terminating else { return }
                try await body(id, host.id.uuidString, current)
            }
            catch {
                guard lifetime == managerLifetime, generation == current, operationID == slot, !Task.isCancelled else { return }
                issue = .files(error)
                if let failure = error as? FileServiceError, let lease {
                    retireFailedSession(failure, serviceID: id, lease: lease,
                        manager: manager, lifetime: managerLifetime, generation: current)
                }
            }
        }
    }
    func mkdir(_ name: FileName, acknowledgedRemoteRisk: Bool) {
        guard let target = captureTarget() else { return }
        mkdir(name, target: target, acknowledgedRemoteRisk: acknowledgedRemoteRisk)
    }
    func mkdir(_ name: FileName, target: FilesOperationTarget, acknowledgedRemoteRisk: Bool) {
        guard consumeTarget(target), target.entries.isEmpty else { return }
        let parent = target.parent, manager = manager
        startOperation { [self] id, host, current in
            let destination = try parent.appending(name)
            try await manager.withServiceOperation(serviceID: id, hostID: host) { service, token in
                try await Self.inspectDirectory(service, path: parent, token: token)
                guard try await service.lstat(parent, token: token) == target.parentAttributes else {
                    throw FileServiceError(.raceDetected, operation: "remote-mkdir-parent-changed", path: parent)
                }
                try await service.mkdir(destination, token: token)
            }
            try await load(parent, serviceID: id, hostID: host, generation: current)
        }
    }
    private static func inspectDirectory(_ service: any RemoteFileService, path: RemotePath, token: CancellationToken) async throws {
        var current = RemotePath.root
        for bytes in path.bytes.dropFirst().split(separator: 47) {
            current = try current.appending(FileName(bytes: Data(bytes)))
            let attributes = try await service.lstat(current, token: token)
            guard attributes.kind == .directory else { throw FileServiceError(attributes.kind == .symbolicLink ? .symbolicLink : .conflict, operation: "browse-component", path: current) }
        }
    }
    func rename(_ entry: DirectoryEntry, name: FileName, conflict: ConflictDecision) {
        guard let target = captureTarget([entry]) else { return }
        rename(name: name, conflict: conflict, target: target)
    }
    func rename(name: FileName, conflict: ConflictDecision, target: FilesOperationTarget) {
        guard consumeTarget(target), target.entries.count == 1, let entry = target.entries.first,
              let source = target.path(for: entry) else { return }
        let manager = manager, scheduler = scheduler, evidence = confirmation, parent = target.parent
        startOperation { [self] id, host, current in
            let result = try await manager.withServiceOperation(serviceID: id, hostID: host, scheduling: .callerScheduled) { service, token in
                guard try await service.lstat(parent, token: token) == target.parentAttributes,
                      try await service.lstat(source, token: token) == entry.attributes else {
                    throw FileServiceError(.raceDetected, operation: "remote-rename-selection-changed", path: source)
                }
                let policy = TransferPolicy(serverCommit: evidence, acceptsTechnicalLimits: true)
                let operations = SafeFileOperations(service: service, hostID: host, scheduler: scheduler)
                return try await operations.rename(source, to: name, conflict: conflict, policy: policy, token: token)
            }
            if case .failed(let failure) = result.state { throw failure }
            try await load(parent, serviceID: id, hostID: host, generation: current)
        }
    }
    private func askRisk(_ risk: TransferRisk, generation: UInt64) async -> Bool {
        guard operationRiskIsCurrent(generation), riskReply == nil else { return false }
        let id = UUID()
        pendingRisk = risk; riskID = id
        return await withTaskCancellationHandler {
            await withCheckedContinuation { reply in
                guard operationRiskIsCurrent(generation), riskID == id, riskReply == nil else {
                    if riskID == id { pendingRisk = nil; riskID = nil }
                    reply.resume(returning: false); return
                }
                riskReply = reply
            }
        } onCancel: {
            Task { @MainActor [weak self] in self?.answerRisk(false, id: id) }
        }
    }
    private func operationRiskIsCurrent(_ generation: UInt64) -> Bool {
        self.generation == generation && !Task.isCancelled && !windowClosing && windowTask == nil
            && !terminating && operation != nil && token?.isCancelled == false
    }
    func answerRisk(_ accepted: Bool, id: UUID) {
        guard riskID == id else { return }
        resolveCurrentRisk(accepted && !terminating && !windowClosing && operation != nil)
    }
    private func resolveCurrentRisk(_ accepted: Bool) {
        let reply = riskReply; riskReply = nil; pendingRisk = nil; riskID = nil; reply?.resume(returning: accepted)
    }
    func prepareDeleteBatch(_ selected: [DirectoryEntry], removeLinkOnly: Bool) {
        guard let target = captureTarget(selected) else { return }
        prepareDeleteBatch(target, removeLinkOnly: removeLinkOnly)
    }
    func prepareDeleteBatch(_ target: FilesOperationTarget, removeLinkOnly: Bool) {
        guard consumeTarget(target), !target.entries.isEmpty else { return }
        discardDeleteBatch()
        let manager = manager, scheduler = scheduler, parent = target.parent, selected = target.entries, revision = UUID()
        startOperation(revision: revision) { [self] id, host, current in
            let review = try await manager.withServiceOperation(serviceID: id, hostID: host, scheduling: .callerScheduled) { service, token in
                var items: [BrowserDeleteItem] = []
                do {
                    guard try await service.lstat(parent, token: token) == target.parentAttributes else {
                        throw FileServiceError(.raceDetected, operation: "remote-delete-parent-changed", path: parent)
                    }
                    for entry in selected {
                        let root = try parent.appending(entry.name)
                        guard try await service.lstat(root, token: token) == entry.attributes else { throw FileServiceError(.raceDetected, operation: "remote-delete-selection-changed", path: root) }
                        let operations = SafeFileOperations(service: service, hostID: host, scheduler: scheduler)
                        let plan = try await operations.prepareDelete(root, links: removeLinkOnly ? .removeLinkOnly : .reject, token: token)
                        items.append(BrowserDeleteItem(operations: operations, plan: plan))
                    }
                    return BrowserDeleteReview(revision: revision, parent: parent, items: items, target: target)
                } catch { for item in items { await item.operations.discardDeletePlan(item.plan) }; throw error }
            }
            guard generation == current, serviceID == id, browserRevision == revision, windowTask == nil, !Task.isCancelled else {
                for item in review.items { await item.operations.discardDeletePlan(item.plan) }
                return
            }
            deleteBatchReview = FilesDeleteBatchReview(generation: current, serviceID: id, review: review, revision: revision)
        }
    }
    func discardDeleteBatch(_ expected: FilesDeleteBatchReview? = nil) {
        if let expected, deleteBatchReview?.id != expected.id { return }
        if let batch = deleteBatchReview { Task { for item in batch.review.items { await item.operations.discardDeletePlan(item.plan) } } }
        deleteBatchReview = nil
    }
    func executeDeleteBatch(_ batch: FilesDeleteBatchReview) {
        guard deleteBatchReview?.id == batch.id, batch.generation == generation, batch.serviceID == serviceID,
              batch.revision == browserRevision, targetIsCurrent(batch.review.target, checkRevision: false),
              batch.review.parent == path, batch.review.canExecute, state == .ready, operation == nil, connection == nil,
              !windowClosing, !terminating else { return }
        deleteBatchReview = nil
        let manager = manager
        startOperation { [self] id, host, current in
            let outcome = try await manager.withServiceOperation(serviceID: id, hostID: host, scheduling: .callerScheduled) { service, token in
                var reports: [DeleteReport] = []
                do {
                    guard try await service.lstat(batch.review.parent, token: token) == batch.review.target.parentAttributes else {
                        throw FileServiceError(.raceDetected, operation: "remote-delete-parent-changed", path: batch.review.parent)
                    }
                    try await FilesDeletePreflight.validate(batch.review.items, token: token)
                    var confirmations: [DeleteConfirmation] = []
                    for item in batch.review.items {
                        confirmations.append(try await item.operations.confirmDelete(item.plan, displayedRoot: item.plan.root,
                            displayedItemCount: item.plan.items.count, acknowledgedRisks: item.plan.risks))
                    }
                    for (item, confirmation) in zip(batch.review.items, confirmations) {
                        let report = try await item.operations.executeDelete(item.plan, confirmation: confirmation, token: token)
                        reports.append(report)
                        if !report.allSucceeded { throw FileServiceError(.raceDetected, operation: "remote-delete-batch-stopped", path: item.plan.root) }
                    }
                    return BrowserDeleteOutcome(reports: reports, failure: nil)
                } catch {
                    for item in batch.review.items { await item.operations.discardDeletePlan(item.plan) }
                    return BrowserDeleteOutcome(reports: reports, failure: error as? FileServiceError ?? FileServiceError(.io, operation: "remote-delete-batch"))
                }
            }
            guard generation == current, serviceID == id else { return }
            lastDeleteReports = outcome.reports
            if let failure = outcome.failure { issue = .files(failure) }
            try await load(batch.review.parent, serviceID: id, hostID: host, generation: current)
        }
    }
    func prepareDelete(_ entry: DirectoryEntry, removeLinkOnly: Bool) {
        guard let target = captureTarget([entry]) else { return }
        prepareDelete(target, removeLinkOnly: removeLinkOnly)
    }
    func prepareDelete(_ target: FilesOperationTarget, removeLinkOnly: Bool) {
        guard consumeTarget(target), target.entries.count == 1, let entry = target.entries.first,
              let root = target.path(for: entry) else { return }
        let manager = manager, scheduler = scheduler, revision = UUID()
        startOperation(revision: revision) { [self] id, host, current in
            let review = try await manager.withServiceOperation(serviceID: id, hostID: host, scheduling: .callerScheduled) { service, token in
                guard try await service.lstat(target.parent, token: token) == target.parentAttributes,
                      try await service.lstat(root, token: token) == entry.attributes else {
                    throw FileServiceError(.raceDetected, operation: "remote-delete-selection-changed", path: root)
                }
                let operations = SafeFileOperations(service: service, hostID: host, scheduler: scheduler)
                let plan = try await operations.prepareDelete(root, links: removeLinkOnly ? .removeLinkOnly : .reject, token: token)
                return FilesDeleteReview(generation: current, serviceID: id, operations: operations, plan: plan, target: target, revision: revision)
            }
            guard generation == current, serviceID == id, browserRevision == revision, windowTask == nil, !Task.isCancelled else { await review.operations.discardDeletePlan(review.plan); return }; deleteReview = review
        }
    }
    func discardDeleteReview(_ expected: FilesDeleteReview? = nil) {
        if let expected, deleteReview?.id != expected.id { return }
        if let review = deleteReview { Task { await review.operations.discardDeletePlan(review.plan) } }
        deleteReview = nil
    }
    func executeDelete(_ review: FilesDeleteReview, confirmed: Bool) {
        guard confirmed, operation == nil, connection == nil, state == .ready, !windowClosing, !terminating,
              deleteReview?.id == review.id, review.generation == generation, review.serviceID == serviceID,
              review.revision == browserRevision, targetIsCurrent(review.target, checkRevision: false) else { return }
        deleteReview = nil
        let manager = manager, parent = review.target.parent
        startOperation { [self] id, host, current in
            let report = try await manager.withServiceOperation(serviceID: id, hostID: host, scheduling: .callerScheduled) { _, token in
                let confirmation = try await review.operations.confirmDelete(review.plan, displayedRoot: review.plan.root,
                    displayedItemCount: review.plan.items.count, acknowledgedRisks: review.plan.risks)
                return try await review.operations.executeDelete(review.plan, confirmation: confirmation, token: token)
            }
            guard generation == current, serviceID == id, windowTask == nil else { return }
            lastDeleteReport = report
            if !report.allSucceeded { issue = .files(FileServiceError(.raceDetected, operation: "delete-incomplete")) }
            try await load(parent, serviceID: id, hostID: host, generation: current)
        }
    }
    func prepareProbe() {
        let manager = manager, parent = path
        startOperation { [self] id, host, current in
            let plan = try await manager.withServiceOperation(serviceID: id, hostID: host) { service, _ in try ServerCommitProbe.prepare(service: service, parent: parent) }
            guard generation == current, serviceID == id, windowTask == nil else { return }; probeReview = FilesProbeReview(generation: current, serviceID: id, plan: plan)
        }
    }
    func discardProbeReview() { probeReview = nil }
    func executeProbe(_ review: FilesProbeReview, approved: Bool) {
        guard approved, operation == nil, connection == nil, state == .ready, !windowClosing, !terminating,
              probeReview?.id == review.id, review.generation == generation, review.serviceID == serviceID else { return }
        probeReview = nil
        let manager = manager, scheduler = scheduler
        startOperation { [self] id, host, current in
            let result = try await manager.withServiceOperation(serviceID: id, hostID: host, scheduling: .callerScheduled) { service, token in
                try await ServerCommitProbe.run(review.plan, service: service, hostID: host, approvedPlanID: review.id,
                    acknowledgedRisks: review.plan.requiredRisks, token: token, scheduler: scheduler)
            }
            guard generation == current, serviceID == id, windowTask == nil else { return }
            lastProbeResult = result
            if result.passed { confirmation = result.confirmation }
            else { issue = .files(result.error ?? FileServiceError(.needsCapabilityConfirmation, operation: "probe-failed")) }
        }
    }
    func beginWindowClose() {
        guard !windowClosing else { return }
        admissionFrozen = true; windowClosing = true; visible = false
        healthToken?.cancel(); healthTask?.cancel()
        cancelTransferPlan(); cancelPathSelection()
        discardDeleteBatch(); connectionChangeReview = nil
        invalidateCallbacks(); token?.cancel(); connection?.cancel(); operation?.cancel()
    }
    func deferResetUntilCloseAcknowledged() { deferWindowReset = true }
    func finishWindowCloseReset() {
        guard windowClosing else { return }
        stopHealth(); sessionLease = nil
        serviceID = nil; serviceRegistrationRevision = nil; observedServiceRevision = 0; observedServices = [:]
        selectedHost = nil; pendingHostUpdate = nil; entries = []; path = .root; navigationHistory = .init(); confirmation = nil; deleteReview = nil; probeReview = nil
        transferSamples = [:]; transferSpeeds = [:]; lastDeleteReports = []
        busy = false; hasPendingOperations = false; hasActiveTransfers = false; state = .disconnected
        lifetime = UUID()
        manager = TransferManager(engine: SafeTransferEngine(scheduler: scheduler), idleTimeout: idleTimeout, executionMode: .direct)
        transferSnapshot = TransferManagerSnapshot(jobs: [], isClosed: false); transferLabels = [:]; retryOrigins = [:]; retrySelection = nil
        tasksVisible = false; historyRemovalReview = nil
        windowClosing = false; admissionFrozen = terminating; deferWindowReset = false; windowTask = nil
    }
    func closeForWindow() async {
        if let windowTask { await windowTask.value; return }
        beginWindowClose()
        request = nil; generation &+= 1; state = .closing
        let connection = connection, operation = operation, previous = closeTask, manager = manager, health = stopHealth()
        let task = Task { [self] in
            _ = await activeTransferSnapshot()
            await previous?.value; await health?.value; await connection?.value; await operation?.value
            await manager.cancelAllAndWait()
            await localBrowser.close()
            observation?.cancel(); observation = nil; self.connection = nil; self.operation = nil; operationID = nil; closeTask = nil
            applySnapshot(await manager.snapshot())
            if !deferWindowReset { finishWindowCloseReset() }
        }
        windowTask = task; await task.value
    }
    func waitUntilCurrentWorkCompletes() async {
        await closeTask?.value
        await connection?.value
        await operation?.value
        await waitUntilTransferPlanDrained()
    }
    func beginTermination() {
        admissionFrozen = true; terminating = true; healthToken?.cancel(); healthTask?.cancel(); cancelTransferPlan(); cancelPathSelection()
        discardDeleteBatch(); connectionChangeReview = nil; localBrowser.cancel()
        invalidateCallbacks(); token?.cancel(); connection?.cancel(); operation?.cancel()
    }
}
