import Foundation
import OpenLXSSHCore
import OpenLXSSHFiles

extension FilesController {
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

    func targetIsCurrent(_ target: FilesOperationTarget, checkRevision: Bool = true) -> Bool {
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

    func load(_ path: RemotePath, serviceID: UUID, hostID: String, generation: UInt64, historyIndex: Int? = nil) async throws {
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
}
