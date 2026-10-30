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

struct FilesHistoryRemovalReview: Identifiable, Sendable {
    let id = UUID()
    let managerLifetime: UUID
    let jobs: [TransferJobSnapshot]
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
    @Published private(set) var transferSnapshot = TransferManagerSnapshot(jobs: [], isClosed: false)
    @Published private(set) var transferLabels: [TransferJobID: FilesTransferLabel] = [:]
    @Published var tasksVisible = false
    @Published private(set) var enqueueInFlight = 0
    @Published private(set) var admissionFrozen = false
    private var deferWindowReset = false
    private var enqueues: [UUID: Task<[TransferJobID], Error>] = [:]
    private var metadataMutations: [UUID: Task<Bool, Never>] = [:]
    private var historyRemovalReview: FilesHistoryRemovalReview?
    private var historyRemovalEpoch = UUID()
    private let beforeHistoryRemovalSnapshot: (@Sendable () async -> Void)?
    private var needsUploadConfirmation = false
    let pathPicker = FilesPathPicker()
    private let localService: @Sendable (Int32) throws -> any RemoteFileService
    /// Nil in production; deterministic scheduling at the worker → MainActor mailbox boundary.
    private let beforeOperationRiskDelivery: (@Sendable () async -> Void)?
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
    init(connector: any FilesConnecting, idleTimeout: Duration? = .seconds(60),
         localService: @escaping @Sendable (Int32) throws -> any RemoteFileService = { try LocalFileService(rootDirectoryDescriptor: $0) },
         beforeOperationRiskDelivery: (@Sendable () async -> Void)? = nil,
         beforeHistoryRemovalSnapshot: (@Sendable () async -> Void)? = nil) {
        self.connector = connector; self.idleTimeout = idleTimeout; self.localService = localService
        self.beforeOperationRiskDelivery = beforeOperationRiskDelivery
        self.beforeHistoryRemovalSnapshot = beforeHistoryRemovalSnapshot
        let scheduler = TransferScheduler(maxConcurrentChunks: 2); self.scheduler = scheduler
        manager = TransferManager(engine: SafeTransferEngine(scheduler: scheduler), idleTimeout: idleTimeout)
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
        let oldServiceID = serviceID, admitted = Array(enqueues.values)
        generation &+= 1; request = nil; selectedHost = host; pendingHostUpdate = nil; entries = []; path = .root
        serviceID = nil; confirmation = nil; deleteReview = nil; probeReview = nil; state = .disconnected
        self.connection = nil; self.operation = nil; operationID = nil
        let manager = manager
        let previous = closeTask, revision = generation
        closeTask = Task { [weak self] in
            await previous?.value; await oldConnection?.value; await oldOperation?.value
            for task in admitted { _ = await task.result }
            if let oldServiceID { await manager.closeIdleServices([oldServiceID]) }
            if self?.generation == revision { self?.closeTask = nil; self?.busy = false; self?.hasPendingOperations = false }
        }
    }
    func hide() { visible = false } // Never loses a waiting auth reply or cancels service I/O.
    var canConnect: Bool { selectedHost != nil && state != .ready && connection == nil && closeTask == nil && windowTask == nil && !admissionFrozen && !terminating && !windowClosing }
    func connect(_ input: FilesConnectInput) {
        guard let host = selectedHost, connection == nil, operation == nil, windowTask == nil, !admissionFrozen, !terminating, !windowClosing, state != .ready else { return }
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
                guard isCurrent(current) else { await manager.closeIdleServices([id]); return }
                needsUploadConfirmation = service.capabilities.noReplace == .needsServerConfirmation
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
        !terminating && !windowClosing && windowTask == nil && request == supplied
            && selectedHost?.matchesConnection(of: supplied.host) == true
            && token?.isCancelled == false && !Task.isCancelled
    }
    private func receiveTrust(_ event: FileHostTrustEvent, reply: ChallengeReply<FileHostTrustAnswer>, request: FilesRequest) {
        guard !terminating, !windowClosing, windowTask == nil, self.request == request,
              selectedHost?.matchesConnection(of: request.host) == true else { reply.resolve(.reject); return }
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
        guard !admissionFrozen else { return }
        let oldServiceID = serviceID, admitted = Array(enqueues.values)
        invalidateCallbacks(); token?.cancel(); connection?.cancel(); operation?.cancel()
        request = nil; generation &+= 1; serviceID = nil; confirmation = nil; deleteReview = nil; probeReview = nil
        state = .closing; busy = true
        let connection = connection, operation = operation, manager = manager, previous = closeTask, current = generation
        self.connection = nil; self.operation = nil; operationID = nil
        closeTask = Task { [weak self] in
            await previous?.value; await connection?.value; await operation?.value
            for task in admitted { _ = await task.result }
            if let oldServiceID { await manager.closeIdleServices([oldServiceID]) }
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
                applySnapshot(snapshot)
            }
        }
    }
    private func applySnapshot(_ snapshot: TransferManagerSnapshot) {
        transferSnapshot = snapshot
        hasActiveTransfers = snapshot.jobs.contains { $0.state.isActive }
        hasPendingOperations = connection != nil || !snapshot.serviceOperations.isEmpty
    }
    var canTransfer: Bool { state == .ready && serviceID != nil && !busy && !admissionFrozen && !terminating && !windowClosing }
    func transferContext(upload: Bool) throws -> FilesTransferContext {
        guard canTransfer, let serviceID, let host = selectedHost else { throw FileServiceError(.closed, operation: "files-transfer-not-ready") }
        if upload && needsUploadConfirmation && confirmation == nil {
            issue = .files(FileServiceError(.needsCapabilityConfirmation, operation: "upload-needs-explicit-probe"))
            throw FileServiceError(.needsCapabilityConfirmation, operation: "upload-needs-explicit-probe")
        }
        return FilesTransferContext(lifetime: lifetime, serviceID: serviceID, hostID: host.id,
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
        guard !admissionFrozen, !terminating, !windowClosing, context.lifetime == lifetime,
              context.serviceID == serviceID, context.hostID == selectedHost?.id,
              (!uploads.isEmpty || !downloads.isEmpty), uploads.count + downloads.count <= 128 else {
            throw FileServiceError(.closed, operation: "files-transfer-admission")
        }
        let slot = UUID(), manager = manager, localService = localService
        enqueueInFlight += 1; observeManager(); tasksVisible = true
        let task = Task { @MainActor [self] () throws -> [TransferJobID] in
            var registered: [TransferServiceID] = []
            defer { enqueues[slot] = nil; enqueueInFlight -= 1 }
            do {
                let batch = TransferBatchID()
                var requests: [TransferRequest] = []
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
                            destination: .init(serviceID: context.serviceID, path: try context.path.appending(name)), kind: kind))
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
                        requests.append(TransferRequest(hostID: context.hostID.uuidString, batchID: batch,
                            source: .init(serviceID: context.serviceID, path: try context.path.appending(entry.name)),
                            destination: .init(serviceID: id, path: try RemotePath.root.appending(entry.name)),
                            kind: entry.attributes.kind == .directory ? .tree : .file))
                    }
                }
                // Already admitted work is drained before a close snapshot; changing the panel
                // after this point cannot retarget these immutable service/host descriptors.
                let confirmations = context.confirmation.map { [context.serviceID: $0] } ?? [:]
                let ids = try await manager.enqueueBatch(requests, serverConfirmations: uploads.isEmpty ? [:] : confirmations)
                let label = FilesTransferLabel(endpoint: context.endpoint, direction: uploads.isEmpty ? "下载" : "上传", localRoots: localRoots)
                for id in ids { transferLabels[id] = label }
                applySnapshot(await manager.snapshot())
                return ids
            } catch {
                await manager.closeIdleServices(registered)
                issue = .files(error)
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
    func freezeTransferAdmission() { admissionFrozen = true; historyRemovalEpoch = UUID(); historyRemovalReview = nil; pathPicker.cancel() }
    func resumeTransferAdmission() { if !terminating && !windowClosing { admissionFrozen = false } }
    func activeTransferSnapshot() async -> Bool {
        // No new enqueue/retry can enter after freeze. Wait every already-admitted actor hop.
        while !enqueues.isEmpty || !metadataMutations.isEmpty {
            for task in Array(enqueues.values) { _ = await task.result }
            for task in Array(metadataMutations.values) { _ = await task.value }
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
        let review = FilesHistoryRemovalReview(managerLifetime: lifetime, jobs: jobs)
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
            for id in ids { transferLabels[id] = nil }
            applySnapshot(await manager.snapshot())
            return removed == ids.count
        }
        metadataMutations[slot] = task
        return task
    }
    func cancelTransfer(_ id: TransferJobID) async { _ = await manager.cancel(id); applySnapshot(await manager.snapshot()) }
    @discardableResult func answerTransfer(_ decision: TransferDecisionRequest, answer: TransferDecisionAnswer) async -> Bool {
        guard !terminating, !windowClosing else { return false }
        let result = await manager.resolve(decision, answer: answer)
        applySnapshot(await manager.snapshot()); return result
    }
    func retryTransfer(_ id: TransferJobID) throws -> Task<[TransferJobID], Error> {
        guard !admissionFrozen, !terminating, !windowClosing else { throw FileServiceError(.closed, operation: "retry-admission") }
        let slot = UUID(), manager = manager, label = transferLabels[id]
        enqueueInFlight += 1
        let task = Task { @MainActor [self] () throws -> [TransferJobID] in
            defer { enqueues[slot] = nil; enqueueInFlight -= 1 }
            do {
                let next = try await manager.retry(id)
                transferLabels[next] = label; applySnapshot(await manager.snapshot()); return [next]
            } catch { issue = .files(error); throw error }
        }
        enqueues[slot] = task; return task
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
        guard operation == nil, connection == nil, closeTask == nil, windowTask == nil, !admissionFrozen, !terminating, !windowClosing,
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
        let manager = manager, scheduler = scheduler, evidence = confirmation, parent = path, beforeRisk = beforeOperationRiskDelivery
        startOperation { [self] id, host, current in
            let policy = TransferPolicy(confirmRisk: { [weak self] risk in
                await beforeRisk?()
                return await self?.askRisk(risk, generation: current) == true
            }, serverCommit: evidence)
            let result = try await manager.withServiceOperation(serviceID: id, hostID: host, scheduling: .callerScheduled) { service, token in
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
        admissionFrozen = true; windowClosing = true; visible = false
        invalidateCallbacks(); token?.cancel(); connection?.cancel(); operation?.cancel()
    }
    func deferResetUntilCloseAcknowledged() { deferWindowReset = true }
    func finishWindowCloseReset() {
        guard windowClosing else { return }
        serviceID = nil; selectedHost = nil; pendingHostUpdate = nil; entries = []; path = .root; confirmation = nil; deleteReview = nil; probeReview = nil
        busy = false; hasPendingOperations = false; hasActiveTransfers = false; state = .disconnected
        lifetime = UUID()
        manager = TransferManager(engine: SafeTransferEngine(scheduler: scheduler), idleTimeout: idleTimeout)
        transferSnapshot = TransferManagerSnapshot(jobs: [], isClosed: false); transferLabels = [:]; tasksVisible = false; historyRemovalReview = nil
        windowClosing = false; admissionFrozen = terminating; deferWindowReset = false; windowTask = nil
    }
    func closeForWindow() async {
        if let windowTask { await windowTask.value; return }
        beginWindowClose()
        request = nil; generation &+= 1; state = .closing
        let connection = connection, operation = operation, previous = closeTask, manager = manager
        let task = Task { [self] in
            _ = await activeTransferSnapshot()
            await previous?.value; await connection?.value; await operation?.value
            await manager.cancelAllAndWait()
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
    }
    func beginTermination() { admissionFrozen = true; terminating = true; invalidateCallbacks(); token?.cancel(); connection?.cancel(); operation?.cancel() }
}
