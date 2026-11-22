import AppKit
import Darwin
import Foundation
import Observation
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
@Observable @MainActor final class FilesController: FilesWindowLifecycle {
    struct TransferPlanOwner {
        let id: UUID
        let context: FilesTransferContext
        let token: CancellationToken
        var direction: FilesTransferDirection?
        var planID: UUID?
        var registeredLocalIDs: [TransferServiceID] = []
    }

    private(set) var visible = false
    /// Non-secret epoch only. View-owned initial input must not survive connection invalidation.
    private(set) var initialInputEpoch = UUID()
    private(set) var selectedHost: HostConfiguration?
    private(set) var state: FilesState = .disconnected
    var entries: [DirectoryEntry] = []
    var path: RemotePath = .root
    var navigationHistory = FilesNavigationHistory()
    var readFailed = false
    @ObservationIgnored var browserRevision = UUID()
    @ObservationIgnored var parentAttributes: FileAttributes?
    @ObservationIgnored var pendingTargets: [UUID: FilesOperationTarget] = [:]
    var deleteBatchReview: FilesDeleteBatchReview?
    var lastDeleteReports: [DeleteReport] = []
    var transferSpeeds: [TransferJobID: Double] = [:]
    let localBrowser: LocalBrowserModel
    @ObservationIgnored var transferSamples: [TransferJobID: (bytes: UInt64, time: ContinuousClock.Instant)] = [:]
    @ObservationIgnored var connectionChangeReview: FilesConnectionChangeReview?
    private let initialPath: @Sendable (any RemoteFileService, CancellationToken) async throws -> RemotePath
    var busy = false
    var issue: AppIssue?
    private(set) var trustPrompt: FilesTrustPrompt?
    private(set) var keyboardPrompt: FilesKeyboardPrompt?
    var deleteReview: FilesDeleteReview?
    var probeReview: FilesProbeReview?
    var lastDeleteReport: DeleteReport?
    var lastProbeResult: NoReplaceProbeResult?
    var hasActiveTransfers = false
    var hasPendingOperations = false
    var transferSnapshot = TransferManagerSnapshot(jobs: [], isClosed: false)
    var transferLabels: [TransferJobID: FilesTransferLabel] = [:]
    var tasksVisible = false
    var transferCompletionRevision = 0
    @ObservationIgnored var latestCompletedBatchJobs: [TransferJobSnapshot] = []
    @ObservationIgnored var completedBatchIDs: Set<TransferBatchID> = []
    var transferPreparationIssue: AppIssue?
    func dismissTransferPreparationIssue() { transferPreparationIssue = nil }
    @ObservationIgnored private(set) var conflictPreference: FileConflictPreference = .ask
    func updateTransferPreference(_ preference: FileConflictPreference) {
        conflictPreference = preference
        let manager = manager
        Task { await manager.setConflictPolicy(TransferConflictPolicy(rawValue: preference.rawValue) ?? .ask) }
    }
    var enqueueInFlight = 0
    var admissionFrozen = false
    var transferPlanReview: FilesTransferPlanReview?
    var transferPlanPhase: FilesTransferPlanPhase?
    var transferPlanOwner: TransferPlanOwner?
    @ObservationIgnored var retryOrigins: [TransferJobID: FilesTransferRetryOrigin] = [:]
    @ObservationIgnored var retrySelection: FilesTransferRetrySelection?
    @ObservationIgnored var transferPlanExpiry: Task<Void, Never>?
    var transferPlanDrains: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var deferWindowReset = false
    @ObservationIgnored var enqueues: [UUID: Task<[TransferJobID], Error>] = [:]
    @ObservationIgnored var metadataMutations: [UUID: Task<Bool, Never>] = [:]
    @ObservationIgnored var historyRemovalReview: FilesHistoryRemovalReview?
    @ObservationIgnored var historyRemovalEpoch = UUID()
    let beforeHistoryRemovalSnapshot: (@Sendable () async -> Void)?
    let pathPicker = FilesPathPicker()
    let localService: @Sendable (Int32) throws -> any RemoteFileService
    /// Nil in production; deterministic scheduling at the worker → MainActor mailbox boundary.
    private let beforeOperationRiskDelivery: (@Sendable () async -> Void)?
    let connector: any FilesConnecting
    @ObservationIgnored var trustEnvironment: SessionEnvironment?
    let scheduler: TransferScheduler
    @ObservationIgnored private(set) var manager: TransferManager
    @ObservationIgnored var observation: Task<Void, Never>?
    var connection: Task<Void, Never>?
    @ObservationIgnored var operation: Task<Void, Never>?
    @ObservationIgnored var operationID: UUID?
    var closeTask: Task<Void, Never>?
    var windowTask: Task<Void, Never>?
    @ObservationIgnored var lifetime = UUID()
    @ObservationIgnored var generation: UInt64 = 0
    @ObservationIgnored var request: FilesRequest?
    @ObservationIgnored var token: CancellationToken?
    var serviceID: UUID?
    @ObservationIgnored var sessionLease: TransferServiceSessionLease?
    @ObservationIgnored private var healthTask: Task<Void, Never>?
    @ObservationIgnored private var healthToken: CancellationToken?
    @ObservationIgnored var serviceRegistrationRevision: UInt64?
    @ObservationIgnored var observedServiceRevision: UInt64 = 0
    @ObservationIgnored var observedServices: [TransferServiceID: TransferServiceSnapshot] = [:]
    @ObservationIgnored private var trustReply: ChallengeReply<FileHostTrustAnswer>?
    @ObservationIgnored private var keyboardReply: ChallengeReply<[Data]>?
    @ObservationIgnored var riskReply: CheckedContinuation<Bool, Never>?
    var riskID: UUID?
    var pendingRisk: TransferRisk?
    @ObservationIgnored var confirmation: ServerCommitConfirmation?
    @ObservationIgnored var pendingHostUpdate: HostConfiguration?
    var terminating = false
    var windowClosing = false
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
    @discardableResult func retireFailedSession(_ failure: FileServiceError, serviceID: UUID,
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

    func reconcileServiceState() {
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
