import Combine
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
struct FilesDeleteReview: Identifiable, Sendable {
    var id: UUID { plan.id }
    let generation: UInt64
    let serviceID: UUID
    let operations: SafeFileOperations
    let plan: DeletePlan
}
struct FilesProbeReview: Identifiable, Sendable {
    var id: UUID { plan.id }
    let generation: UInt64
    let serviceID: UUID
    let plan: NoReplaceProbePlan
}

/// Application owned. The panel is only an observer; terminal tabs never own a file service.
@MainActor final class FilesController: ObservableObject, FilesWindowLifecycle {
    @Published private(set) var visible = false
    @Published private(set) var selectedHost: HostConfiguration?
    @Published private(set) var state: FilesState = .disconnected
    @Published private(set) var entries: [DirectoryEntry] = []
    @Published private(set) var path: RemotePath = .root
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
    let connector: any FilesConnecting
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
    private var serviceID: UUID?
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
    init(connector: any FilesConnecting, idleTimeout: Duration? = .seconds(60)) {
        self.connector = connector; self.idleTimeout = idleTimeout
        let scheduler = TransferScheduler(maxConcurrentChunks: 2); self.scheduler = scheduler
        manager = TransferManager(engine: SafeTransferEngine(scheduler: scheduler), idleTimeout: idleTimeout)
    }
    func show(host: HostConfiguration?) {
        guard !terminating, !windowClosing, windowTask == nil else { return }
        visible = true
        guard selectedHost != host else { return }
        if serviceID != nil, selectedHost?.id == host?.id {
            // Configuration edits do not tear down a service possibly owned by
            // future transfer jobs. The connected snapshot stays explicit until
            // the user disconnects; the next manual connect uses the new Core row.
            pendingHostUpdate = host
            issue = AppIssue(code: "files.hostChanged", message: "主机配置已更改；当前文件连接保留原端点。请先显式断开，再手动连接以使用新配置，不会自动重连。")
            return
        }
        invalidateCallbacks()
        let oldConnection = connection; oldConnection?.cancel(); token?.cancel()
        let oldOperation = operation; oldOperation?.cancel()
        generation &+= 1; request = nil; selectedHost = host; pendingHostUpdate = nil; entries = []; path = .root
        serviceID = nil; confirmation = nil; deleteReview = nil; probeReview = nil; state = .disconnected
        self.connection = nil; self.operation = nil; operationID = nil
        let manager = manager
        let previous = closeTask, revision = generation
        closeTask = Task { [weak self] in
            await previous?.value; await oldConnection?.value; await oldOperation?.value
            await manager.closeIdleServices()
            if self?.generation == revision { self?.closeTask = nil; self?.busy = false; self?.hasPendingOperations = false }
        }
    }
    func hide() { visible = false } // Never loses a waiting auth reply or cancels service I/O.
    var canConnect: Bool { selectedHost != nil && state != .ready && connection == nil && closeTask == nil && windowTask == nil && !terminating && !windowClosing }
    func connect(_ input: FilesConnectInput) {
        guard let host = selectedHost, connection == nil, operation == nil, windowTask == nil, !terminating, !windowClosing, state != .ready else { return }
        generation &+= 1
        let current = FilesRequest(id: UUID(), generation: generation, host: host)
        let cancellation = CancellationToken(), manager = manager, connector = connector
        let close = closeTask; closeTask = nil
        invalidateCallbacks(); request = current; token = cancellation
        state = .preparing; busy = true; issue = nil; serviceID = nil; confirmation = nil
        hasPendingOperations = true
        observeManager()
        connection = Task { [weak self] in
            guard let self else { return }
            defer {
                if request == current { connection = nil; busy = false; hasPendingOperations = false }
            }
            do {
                await close?.value
                guard request == current, generation == current.generation, windowTask == nil, !windowClosing, !terminating else { return }
                try cancellation.check()
                await manager.closeIdleServices()
                try cancellation.check()
                guard isCurrent(current) else { return }
                let service = try await connector.connect(request: current, input: input, token: cancellation,
                    trust: { [weak self] event, reply in
                        Task { @MainActor in
                            guard let self else { reply.resolve(.reject); return }
                            self.receiveTrust(event, reply: reply, request: current)
                        }
                    }, keyboard: { [weak self] challenge, reply in
                        Task { @MainActor in
                            guard let self else { reply.resolve([]); return }
                            self.receiveKeyboard(challenge, reply: reply, request: current)
                        }
                    }, isCurrent: { [weak self] in await self?.isCurrent(current) == true })
                guard isCurrent(current), !Task.isCancelled else { await service.close(); return }
                let id: UUID
                do { id = try await manager.registerService(service, hostID: host.id.uuidString) }
                catch { await service.close(); throw error }
                guard isCurrent(current) else { await manager.closeIdleServices(); return }
                serviceID = id; state = .ready; path = .root
                try await load(.root, serviceID: id, hostID: host.id.uuidString, generation: current.generation)
            } catch {
                if request == current, generation == current.generation, windowTask == nil {
                    invalidateCallbacks()
                    state = .failed; issue = .files(error); serviceID = nil
                }
            }
        }
    }
    func isCurrent(_ supplied: FilesRequest) -> Bool {
        !terminating && !windowClosing && windowTask == nil && request == supplied && selectedHost == supplied.host && token?.isCancelled == false && !Task.isCancelled
    }
    private func receiveTrust(_ event: FileHostTrustEvent, reply: ChallengeReply<FileHostTrustAnswer>, request: FilesRequest) {
        guard !terminating, !windowClosing, windowTask == nil, self.request == request, selectedHost == request.host else { reply.resolve(.reject); return }
        switch event {
        case .pending(let pending):
            guard isCurrent(request), trustReply == nil, keyboardReply == nil else { reply.resolve(.reject); return }
            guard pending.host.address.value == (try? HostAddress(request.host.address).value), pending.host.port.value == request.host.port else { reply.resolve(.reject); return }
            trustReply = reply; trustPrompt = FilesTrustPrompt(request: request, event: event); state = .awaitingTrust
        case .changed:
            reply.resolve(.reject); trustPrompt = FilesTrustPrompt(request: request, event: event)
            state = .failed; issue = .files(FileServiceError(.untrusted, operation: "changed-host-key"))
        }
    }
    @discardableResult func answerTrust(_ prompt: FilesTrustPrompt, verified: Bool) -> Bool {
        guard verified, isCurrent(prompt.request), trustPrompt?.id == prompt.id, let reply = trustReply,
              case .pending(let decision) = prompt.event else { return false }
        trustReply = nil; trustPrompt = nil; state = .authenticating
        return reply.resolve(.confirm(displayedFingerprint: decision.fingerprint))
    }
    private func receiveKeyboard(_ challenge: FilesKeyboardChallenge, reply: ChallengeReply<[Data]>, request: FilesRequest) {
        guard isCurrent(request), keyboardReply == nil, trustReply == nil, challenge.prompts.count <= 32 else { reply.resolve([]); return }
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
    private func invalidateCallbacks() {
        trustReply?.resolve(.reject); trustReply = nil; trustPrompt = nil
        keyboardReply?.resolve([]); keyboardReply = nil; keyboardPrompt = nil
        resolveCurrentRisk(false)
    }
    func cancelCurrent() {
        invalidateCallbacks(); token?.cancel(); connection?.cancel(); operation?.cancel()
        request = nil; generation &+= 1; serviceID = nil; confirmation = nil; deleteReview = nil; probeReview = nil
        state = .closing; busy = true
        let connection = connection, operation = operation, manager = manager, previous = closeTask, current = generation
        self.connection = nil; self.operation = nil; operationID = nil
        closeTask = Task { [weak self] in
            await previous?.value; await connection?.value; await operation?.value; await manager.closeIdleServices()
            guard let self, generation == current else { return }
            closeTask = nil; state = .disconnected; busy = false; hasPendingOperations = false
            if let pendingHostUpdate { selectedHost = pendingHostUpdate; self.pendingHostUpdate = nil }
            issue = .files(FileServiceError(.closed, operation: "cancelled-service-reconnect-required"))
        }
    }
    private func observeManager() {
        guard observation == nil else { return }
        let manager = manager, lifetime = lifetime
        observation = Task { [weak self] in
            guard let stream = try? await manager.updates() else { return }
            for await snapshot in stream {
                guard let self, self.lifetime == lifetime, !Task.isCancelled else { return }
                hasActiveTransfers = snapshot.jobs.contains { $0.state.isActive }
                hasPendingOperations = connection != nil || !snapshot.serviceOperations.isEmpty
            }
        }
    }
    private func load(_ path: RemotePath, serviceID: UUID, hostID: String, generation: UInt64) async throws {
        let rows = try await manager.withServiceOperation(serviceID: serviceID, hostID: hostID) { service, token in
            try await Self.inspectDirectory(service, path: path, token: token)
            let attr = try await service.lstat(path, token: token)
            guard attr.kind == .directory else { throw FileServiceError(attr.kind == .symbolicLink ? .symbolicLink : .conflict, operation: "browse-kind", path: path) }
            let rows = try await service.list(path, token: token)
            guard Set(rows.map(\.name)).count == rows.count else { throw FileServiceError(.protocolFailure, operation: "duplicate-listing") }
            return rows.sorted { $0.name.bytes.lexicographicallyPrecedes($1.name.bytes) }
        }
        guard self.generation == generation, self.serviceID == serviceID, !Task.isCancelled else { throw FileServiceError(.cancelled, operation: "stale-list") }
        self.path = path; entries = rows
    }
    func go(manualUTF8: String) {
        do { browse(manualUTF8.isEmpty ? path : try RemotePath(manualUTF8)) }
        catch { issue = .files(error) }
    }
    func browse(_ path: RemotePath) { startOperation { [self] id, host, generation in try await load(path, serviceID: id, hostID: host, generation: generation) } }
    func enter(_ entry: DirectoryEntry) {
        guard entries.contains(entry), entry.attributes.kind == .directory else {
            issue = .files(FileServiceError(.symbolicLink, operation: "enter-link-refused")); return
        }
        do { browse(try path.appending(entry.name)) } catch { issue = .files(error) }
    }
    private func startOperation(_ body: @escaping @MainActor (UUID, String, UInt64) async throws -> Void) {
        guard operation == nil, connection == nil, closeTask == nil, windowTask == nil, !terminating, !windowClosing,
              let id = serviceID, let host = selectedHost, state == .ready else { return }
        let current = generation, slot = UUID(), managerLifetime = lifetime; operationID = slot
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
                guard generation == current else { return }
                issue = .files(error)
                if let error = error as? FileServiceError, [.closed, .cancelled, .timeout, .transport].contains(error.kind) { serviceID = nil; state = .failed }
            }
        }
    }
    func mkdir(_ name: FileName, acknowledgedRemoteRisk: Bool) {
        let parent = path, manager = manager
        startOperation { [self] id, host, current in
            let destination = try parent.appending(name)
            try await manager.withServiceOperation(serviceID: id, hostID: host) { service, token in
                if service.capabilities.traversal == .remoteComponentLstat && !acknowledgedRemoteRisk { throw FileServiceError(.riskRejected, operation: "mkdir-remote-path-risk", path: destination) }
                try await Self.inspectDirectory(service, path: parent, token: token)
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
        guard entries.contains(entry), let source = try? path.appending(entry.name) else { return }
        let manager = manager, scheduler = scheduler, evidence = confirmation, parent = path
        startOperation { [self] id, host, current in
            let policy = TransferPolicy(confirmRisk: { [weak self] risk in await self?.askRisk(risk, generation: current) == true }, serverCommit: evidence)
            let result = try await manager.withServiceOperation(serviceID: id, hostID: host, scheduling: .callerScheduled) { service, token in
                let operations = SafeFileOperations(service: service, hostID: host, scheduler: scheduler)
                return try await operations.rename(source, to: name, conflict: conflict, policy: policy, token: token)
            }
            if case .failed(let failure) = result.state { throw failure }
            try await load(parent, serviceID: id, hostID: host, generation: current)
        }
    }
    private func askRisk(_ risk: TransferRisk, generation: UInt64) async -> Bool {
        guard self.generation == generation, !Task.isCancelled, windowTask == nil, !terminating, riskReply == nil else { return false }
        let id = UUID()
        pendingRisk = risk; riskID = id
        return await withTaskCancellationHandler {
            await withCheckedContinuation { reply in
                if Task.isCancelled || riskID != id { reply.resume(returning: false) }
                else { riskReply = reply }
            }
        } onCancel: {
            Task { @MainActor [weak self] in self?.answerRisk(false, id: id) }
        }
    }
    func answerRisk(_ accepted: Bool, id: UUID) {
        guard riskID == id else { return }
        resolveCurrentRisk(accepted && !terminating && !windowClosing && operation != nil)
    }
    private func resolveCurrentRisk(_ accepted: Bool) {
        let reply = riskReply; riskReply = nil; pendingRisk = nil; riskID = nil; reply?.resume(returning: accepted)
    }
    func prepareDelete(_ entry: DirectoryEntry, removeLinkOnly: Bool) {
        guard entries.contains(entry), let root = try? path.appending(entry.name) else { return }
        let manager = manager, scheduler = scheduler
        startOperation { [self] id, host, current in
            let review = try await manager.withServiceOperation(serviceID: id, hostID: host, scheduling: .callerScheduled) { service, token in
                let operations = SafeFileOperations(service: service, hostID: host, scheduler: scheduler)
                let plan = try await operations.prepareDelete(root, links: removeLinkOnly ? .removeLinkOnly : .reject, token: token)
                return FilesDeleteReview(generation: current, serviceID: id, operations: operations, plan: plan)
            }
            guard generation == current, serviceID == id, windowTask == nil else { await review.operations.discardDeletePlan(review.plan); return }; deleteReview = review
        }
    }
    func discardDeleteReview() {
        if let review = deleteReview { Task { await review.operations.discardDeletePlan(review.plan) } }
        deleteReview = nil
    }
    func executeDelete(_ review: FilesDeleteReview, confirmed: Bool) {
        guard confirmed, operation == nil, connection == nil, state == .ready, !windowClosing, !terminating,
              deleteReview?.id == review.id, review.generation == generation, review.serviceID == serviceID else { return }
        deleteReview = nil
        let manager = manager, parent = path
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
        windowClosing = true; visible = false
        invalidateCallbacks(); token?.cancel(); connection?.cancel(); operation?.cancel()
    }
    func closeForWindow() async {
        if let windowTask { await windowTask.value; return }
        beginWindowClose()
        request = nil; generation &+= 1; state = .closing
        let connection = connection, operation = operation, previous = closeTask, manager = manager
        let task = Task { [self] in
            await previous?.value; await connection?.value; await operation?.value
            await manager.closeIdleServices(); await manager.cancelAllAndWait()
            observation?.cancel(); observation = nil; self.connection = nil; self.operation = nil; operationID = nil; closeTask = nil
            serviceID = nil; selectedHost = nil; pendingHostUpdate = nil; entries = []; path = .root; confirmation = nil; deleteReview = nil; probeReview = nil
            busy = false; hasPendingOperations = false; hasActiveTransfers = false; state = .disconnected
            lifetime = UUID()
            self.manager = TransferManager(engine: SafeTransferEngine(scheduler: scheduler), idleTimeout: idleTimeout)
            windowClosing = false; windowTask = nil
        }
        windowTask = task; await task.value
    }
    func waitUntilCurrentWorkCompletes() async {
        await closeTask?.value
        await connection?.value
        await operation?.value
    }
    func beginTermination() { terminating = true; invalidateCallbacks(); token?.cancel(); connection?.cancel(); operation?.cancel() }
}
