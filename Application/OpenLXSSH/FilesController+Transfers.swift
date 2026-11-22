import AppKit
import Darwin
import Foundation
import OpenLXSSHCore
import OpenLXSSHFiles

extension FilesController {
    func observeManager() {
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

    func applySnapshot(_ snapshot: TransferManagerSnapshot) {
        guard snapshot.serviceRevision >= observedServiceRevision else { return }
        let now = ContinuousClock.now
        for job in snapshot.jobs {
            guard job.state.isActive else {
                transferSpeeds[job.id] = nil
                transferSamples[job.id] = nil
                continue
            }
            guard let previous = transferSamples[job.id] else {
                transferSamples[job.id] = (job.transferredBytes, now)
                continue
            }
            if job.transferredBytes < previous.bytes {
                transferSamples[job.id] = (job.transferredBytes, now)
                transferSpeeds[job.id] = nil
                continue
            }
            let duration = previous.time.duration(to: now).components
            let seconds = Double(duration.seconds) + Double(duration.attoseconds) / 1e18
            if seconds >= 0.05 {
                transferSpeeds[job.id] = Double(job.transferredBytes - previous.bytes) / seconds
                transferSamples[job.id] = (job.transferredBytes, now)
            }
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
                            destination: .init(serviceID: context.serviceID, path: try context.path.appending(name)), kind: kind, conflictPolicy: actionConflictPolicy,
                            preserveRelativeLinks: kind == .tree))
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
                            kind: entry.attributes.kind == .directory ? .tree : .file, conflictPolicy: actionConflictPolicy,
                            preserveRelativeLinks: entry.attributes.kind == .directory))
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
                    issue = .transferPreparation(error); transferPreparationIssue = issue
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
        hasPendingOperations = connection != nil || !transferSnapshot.serviceOperations.isEmpty || !transferPlanDrains.isEmpty
            || (state == .closing && serviceID != nil)
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

    func askRisk(_ risk: TransferRisk, generation: UInt64) async -> Bool {
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

    func resolveCurrentRisk(_ accepted: Bool) {
        let reply = riskReply; riskReply = nil; pendingRisk = nil; riskID = nil; reply?.resume(returning: accepted)
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
                    issue = .transferPreparation(error); transferPreparationIssue = issue
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

    func cancelPathSelection() { retrySelection = nil; pathPicker.cancel() }

    private static func retryIssue(_ error: Error) -> AppIssue { (error as? FilesRetryAuthorizationError)?.issue ?? .transferPreparation(error) }

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
}
