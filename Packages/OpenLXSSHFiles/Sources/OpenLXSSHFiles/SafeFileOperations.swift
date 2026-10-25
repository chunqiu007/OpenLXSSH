import Foundation

public struct FileOperationResult: Sendable, Equatable {
    public enum State: Sendable, Equatable { case succeeded, skipped, failed(FileServiceError) }
    public let source: RemotePath
    public let destination: RemotePath
    public let state: State
    public let acknowledgedRisks: [TransferRisk]
}
public enum DeleteLinkPolicy: Sendable, Equatable { case reject, removeLinkOnly }
public struct DeleteItem: Sendable, Equatable {
    public enum Action: Sendable, Equatable { case removeFile, removeEmptyDirectory, removeSymbolicLink }
    public let path: RemotePath
    public let action: Action
    public let attributes: FileAttributes
    public let contentSHA256: Data?
    public let children: [FileName]
}
public struct DeletePlanIssue: Sendable, Equatable {
    public let path: RemotePath
    public let error: FileServiceError
}
/// Immutable, instance-bound plan. No destructive work occurs while preparing a plan.
public struct DeletePlan: Sendable, Equatable {
    public let id: UUID
    public let root: RemotePath
    public let linkPolicy: DeleteLinkPolicy
    /// Postorder, exact confirmed scope. A changed tree never expands this list during execution.
    public let items: [DeleteItem]
    public let issues: [DeletePlanIssue]
    public let risks: [TransferRisk]
    public var canExecute: Bool { issues.isEmpty && !items.isEmpty }
}
public struct DeleteConfirmation: Sendable {
    fileprivate let planID: UUID
    fileprivate let nonce: UUID
}
public struct DeleteItemResult: Sendable, Equatable {
    public enum State: Sendable, Equatable { case succeeded, failed(FileServiceError), notAttempted(FileServiceError) }
    public let path: RemotePath
    public let state: State
}
public struct DeleteReport: Sendable {
    public let planID: UUID
    public let items: [DeleteItemResult]
    public let acknowledgedRisks: [TransferRisk]
    public var allSucceeded: Bool {
        !items.isEmpty && items.allSatisfy { $0.state == .succeeded }
    }
}

/// Bounded UI-facing rename and plan -> explicit confirmation -> delete coordinator.
/// Shares the transfer scheduler, not terminal/UI lifetime. Raw RemoteFileService operations remain
/// available to infrastructure, but UI deletion should only use this exact-scope flow.
public actor SafeFileOperations {
    private let service: any RemoteFileService
    private let hostID: String
    private let scheduler: TransferScheduler
    private let maxDepth: Int
    private let maxItems: Int
    private var plans: [UUID: (DeletePlan, ContinuousClock.Instant)] = [:]
    private var confirmations: [UUID: UUID] = [:]
    public init(service: any RemoteFileService, hostID: String, scheduler: TransferScheduler = .shared,
                maxDepth: Int = 32, maxItems: Int = 10000) {
        precondition(maxDepth >= 0 && maxItems > 0)
        self.service = service; self.hostID = hostID; self.scheduler = scheduler
        self.maxDepth = maxDepth; self.maxItems = maxItems
    }
    public func rename(_ source: RemotePath, to name: FileName, conflict: ConflictDecision = .fail,
                       policy: TransferPolicy = .init(), token: CancellationToken) async throws -> FileOperationResult {
        guard source != .root else { throw FileServiceError(.invalidPath, operation: "rename-root") }
        let targetName: FileName = { if case .renameTo(let alternate) = conflict { return alternate }; return name }()
        let target = try source.parent.appending(targetName)
        let service = self.service
        return try await scheduler.onHost(hostID, token: token) {
            var risks: [TransferRisk] = []
            do {
                try token.check()
                guard target != source else { throw FileServiceError(.conflict, operation: "same-rename-target", path: target) }
                if service.capabilities.traversal == .remoteComponentLstat {
                    let risk = TransferRisk.remotePathChecksAreNotAtomic(path: source)
                    try await policy.require(risk); risks.append(risk)
                }
                try await TransferChecks.inspect(service, path: source, includeLeaf: true, token: token)
                let original = try await service.lstat(source, token: token)
                guard original.kind == .regular || original.kind == .directory else {
                    throw FileServiceError(original.kind == .symbolicLink ? .symbolicLink : .unsupported, operation: "rename-source-kind", path: source)
                }
                var expected: FileAttributes?
                var digest: Data?
                do {
                    let existing = try await service.lstat(target, token: token)
                    if conflict == .skip {
                        return FileOperationResult(source: source, destination: target, state: .skipped, acknowledgedRisks: risks)
                    }
                    guard conflict == .overwrite else { throw FileServiceError(.conflict, operation: "rename-target-exists", path: target) }
                    guard original.kind == .regular, existing.kind == .regular,
                          existing.size != nil, existing.modifiedSeconds != nil, service.capabilities.canAttemptAtomicReplace else {
                        throw FileServiceError(.unsupported, operation: "rename-overwrite-preconditions", path: target)
                    }
                    let risk = TransferRisk.overwriteIsAtomicButNotCompareAndSwap(path: target)
                    try await policy.require(risk); risks.append(risk)
                    expected = existing
                    digest = try await TransferChecks.contentFingerprint(service, path: target, token: token)
                } catch let error as FileServiceError where error.kind == .notFound {
                    if expected != nil { throw FileServiceError(.raceDetected, operation: "rename-target-disappeared", path: target) }
                }
                guard try await service.lstat(source, token: token) == original else {
                    throw FileServiceError(.raceDetected, operation: "rename-source-changed", path: source)
                }
                try await service.commit(source, to: target, request: CommitRequest(mode: expected == nil ? .noReplace : .replaceExisting,
                    expectedTarget: expected, expectedContentSHA256: digest, acceptNonCASOverwriteRisk: expected != nil,
                    serverConfirmation: policy.serverCommit), token: token)
                return FileOperationResult(source: source, destination: target, state: .succeeded, acknowledgedRisks: risks)
            } catch {
                return FileOperationResult(source: source, destination: target,
                    state: .failed(Self.error(error, operation: "rename", path: target)), acknowledgedRisks: risks)
            }
        }
    }
    public func prepareDelete(_ root: RemotePath, links: DeleteLinkPolicy = .reject,
                              token: CancellationToken) async throws -> DeletePlan {
        guard root != .root else { throw FileServiceError(.invalidPath, operation: "delete-host-root", path: root) }
        let plan = try await scheduler.onHost(hostID, token: token) {
            await self.collectPlan(root, links: links, token: token)
        }
        plans = plans.filter { ContinuousClock.now < $0.value.1 }
        confirmations = confirmations.filter { plans[$0.key] != nil }
        guard plans.count < 8 else { throw FileServiceError(.resourceLimit, operation: "pending-delete-plans") }
        plans[plan.id] = (plan, .now.advanced(by: .seconds(300)))
        return plan
    }
    /// Call only after the UI displayed the exact scope and obtained explicit user confirmation.
    /// No default acceptance or caller-supplied arbitrary list can authorize deletion.
    public func confirmDelete(_ plan: DeletePlan, displayedRoot: RemotePath, displayedItemCount: Int,
                              acknowledgedRisks: [TransferRisk]) throws -> DeleteConfirmation {
        guard let stored = plans[plan.id], stored.0 == plan, ContinuousClock.now < stored.1,
              plan.canExecute, displayedRoot == plan.root, displayedItemCount == plan.items.count,
              acknowledgedRisks == plan.risks else { throw FileServiceError(.riskRejected, operation: "delete-confirmation-mismatch", path: plan.root) }
        let nonce = UUID(); confirmations[plan.id] = nonce
        return DeleteConfirmation(planID: plan.id, nonce: nonce)
    }
    public func discardDeletePlan(_ plan: DeletePlan) { plans[plan.id] = nil; confirmations[plan.id] = nil }
    public func executeDelete(_ plan: DeletePlan, confirmation: DeleteConfirmation,
                              token: CancellationToken) async throws -> DeleteReport {
        let stored = plans.removeValue(forKey: plan.id)
        let issuedNonce = confirmations.removeValue(forKey: plan.id)
        guard let stored, stored.0 == plan, ContinuousClock.now < stored.1,
              plan.canExecute, confirmation.planID == plan.id, issuedNonce == confirmation.nonce else {
            throw FileServiceError(.riskRejected, operation: "delete-plan-expired-or-unconfirmed", path: plan.root)
        }
        return try await scheduler.onHost(hostID, token: token) {
            await self.deleteConfirmed(plan, token: token)
        }
    }
    private static func error(_ error: Error, operation: String, path: RemotePath) -> FileServiceError {
        error as? FileServiceError ?? FileServiceError(error is CancellationError ? .cancelled : .io, operation: operation, path: path)
    }
    private func collectPlan(_ root: RemotePath, links: DeleteLinkPolicy, token: CancellationToken) async -> DeletePlan {
        var items: [DeleteItem] = []
        var issues: [DeletePlanIssue] = []
        var visited = 0
        await collect(root, depth: 0, links: links, token: token, visited: &visited, items: &items, issues: &issues)
        var risks: [TransferRisk] = [.deletionChecksAreNotCompareAndSwap(path: root)]
        if service.capabilities.traversal == .remoteComponentLstat { risks.append(.remotePathChecksAreNotAtomic(path: root)) }
        return DeletePlan(id: UUID(), root: root, linkPolicy: links, items: items, issues: issues, risks: risks)
    }
    private func collect(_ path: RemotePath, depth: Int, links: DeleteLinkPolicy, token: CancellationToken,
                         visited: inout Int, items: inout [DeleteItem], issues: inout [DeletePlanIssue]) async {
        do {
            try token.check()
            guard depth <= maxDepth, visited < maxItems else { throw FileServiceError(.resourceLimit, operation: "delete-plan-bound", path: path) }
            visited += 1
            try await TransferChecks.inspect(service, path: path, includeLeaf: false, token: token)
            let attr = try await service.lstat(path, token: token)
            switch attr.kind {
            case .regular:
                let digest = try await TransferChecks.contentFingerprint(service, path: path, token: token)
                guard try await service.lstat(path, token: token) == attr else { throw FileServiceError(.raceDetected, operation: "delete-plan-file-changed", path: path) }
                items.append(DeleteItem(path: path, action: .removeFile, attributes: attr, contentSHA256: digest, children: []))
            case .symbolicLink:
                guard links == .removeLinkOnly else { throw FileServiceError(.symbolicLink, operation: "delete-links-rejected", path: path) }
                items.append(DeleteItem(path: path, action: .removeSymbolicLink, attributes: attr, contentSHA256: nil, children: []))
            case .directory:
                let entries = try await service.list(path, token: token) // A list failure aborts this subtree. Never parse or guess children.
                guard entries.count + visited <= maxItems else { throw FileServiceError(.resourceLimit, operation: "delete-plan-items", path: path) }
                let names = entries.map(\.name)
                guard Set(names).count == names.count else { throw FileServiceError(.protocolFailure, operation: "duplicate-directory-entry", path: path) }
                for name in names.sorted(by: { $0.bytes.lexicographicallyPrecedes($1.bytes) }) {
                    if token.isCancelled || visited >= maxItems { throw FileServiceError(token.isCancelled ? .cancelled : .resourceLimit, operation: "delete-plan-incomplete", path: path) }
                    await collect(try path.appending(name), depth: depth + 1, links: links, token: token,
                                  visited: &visited, items: &items, issues: &issues)
                }
                items.append(DeleteItem(path: path, action: .removeEmptyDirectory, attributes: attr, contentSHA256: nil, children: names))
            default: throw FileServiceError(.unsupported, operation: "delete-special-file-rejected", path: path)
            }
        } catch { issues.append(DeletePlanIssue(path: path, error: Self.error(error, operation: "delete-plan", path: path))) }
    }
    private func checkItem(_ item: DeleteItem, fullDirectory: Bool, token: CancellationToken) async throws {
        try token.check()
        try await TransferChecks.inspect(service, path: item.path, includeLeaf: false, token: token)
        let attr = try await service.lstat(item.path, token: token)
        if item.action == .removeEmptyDirectory && !fullDirectory {
            guard attr.kind == .directory, attr.permissions == item.attributes.permissions,
                  attr.identity == item.attributes.identity else { throw FileServiceError(.raceDetected, operation: "delete-directory-replaced", path: item.path) }
            guard try await service.list(item.path, token: token).isEmpty else { throw FileServiceError(.conflict, operation: "delete-unplanned-child", path: item.path) }
        } else {
            guard attr == item.attributes else { throw FileServiceError(.raceDetected, operation: "delete-item-changed", path: item.path) }
            if let digest = item.contentSHA256 {
                try await TransferChecks.requireUnchanged(service, path: item.path, expected: attr, digest: digest, token: token)
            }
            if item.action == .removeEmptyDirectory {
                let names = try await service.list(item.path, token: token).map(\.name)
                guard Set(names) == Set(item.children), names.count == item.children.count else {
                    throw FileServiceError(.raceDetected, operation: "delete-tree-scope-changed", path: item.path)
                }
            }
        }
    }
    private func deleteConfirmed(_ plan: DeletePlan, token: CancellationToken) async -> DeleteReport {
        // Read-only full revalidation before deleting anything. No new path is ever appended to the plan.
        do { for item in plan.items { try await checkItem(item, fullDirectory: true, token: token) } }
        catch {
            let failure = Self.error(error, operation: "delete-preflight", path: plan.root)
            return DeleteReport(planID: plan.id, items: plan.items.map { DeleteItemResult(path: $0.path, state: .notAttempted(failure)) }, acknowledgedRisks: plan.risks)
        }
        var results: [DeleteItemResult] = []
        let directoryPlan = Dictionary(uniqueKeysWithValues: plan.items.filter { $0.action == .removeEmptyDirectory }.map { ($0.path, $0) })
        var stopped: FileServiceError?
        for item in plan.items {
            if let stopped { results.append(DeleteItemResult(path: item.path, state: .notAttempted(stopped))); continue }
            do {
                // Revalidate every retained ancestor against its confirmed device/inode before
                // touching a descendant. Never wander into a replacement tree at the same name.
                var ancestor = item.path.parent
                while ancestor != .root {
                    if let parent = directoryPlan[ancestor] {
                        try await TransferChecks.inspect(service, path: ancestor, includeLeaf: false, token: token)
                        let observed = try await service.lstat(ancestor, token: token)
                        guard observed.kind == .directory, observed.identity == parent.attributes.identity else {
                            throw FileServiceError(.raceDetected, operation: "delete-ancestor-replaced", path: ancestor)
                        }
                    }
                    ancestor = ancestor.parent
                }
                try await checkItem(item, fullDirectory: false, token: token)
                try await service.remove(item.path, directory: item.action == .removeEmptyDirectory, token: token)
                results.append(DeleteItemResult(path: item.path, state: .succeeded))
            } catch {
                let failure = Self.error(error, operation: "delete-item", path: item.path)
                results.append(DeleteItemResult(path: item.path, state: .failed(failure))); stopped = failure
            }
        }
        return DeleteReport(planID: plan.id, items: results, acknowledgedRisks: plan.risks)
    }
}
