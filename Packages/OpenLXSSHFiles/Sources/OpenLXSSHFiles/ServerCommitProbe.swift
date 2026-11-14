import Foundation

public struct NoReplaceProbePlan: Sendable {
    public let id: UUID
    public let parent: RemotePath
    public let temporaryDirectory: RemotePath
    public let serverBinding: UUID
    public let requiredRisks: [TransferRisk]
    fileprivate let serviceIdentity: ObjectIdentifier
}
public struct NoReplaceProbeResult: Sendable {
    public let directory: RemotePath
    public let confirmation: ServerCommitConfirmation?
    public let error: FileServiceError?
    /// Owned cleanup failures or create-acknowledgement-uncertain candidates. These paths
    /// are diagnostic scope, never authorization to delete an object on a later connection.
    public let retainedPaths: [RemotePath]
    public var passed: Bool { confirmation != nil && error == nil }
}
/// Capability check confined to an exclusive UUID directory under the selected destination.
/// Never called during connect or read-only planning. Normal transfers invoke it inside their
/// already-held host gate; the diagnostic entry point retains its explicit approval contract.
/// A protocol result is evidence for this connected service, not a proof for all servers/future races.
public enum ServerCommitProbe {
    public static func prepare(service: any RemoteFileService, parent: RemotePath) throws -> NoReplaceProbePlan {
        guard let binding = service.serverBinding, service.capabilities.exclusiveCreate else {
            throw FileServiceError(.needsCapabilityConfirmation, operation: "probe-needs-bound-server")
        }
        let directory = try parent.appending(FileName(".openlxssh-capability.\(UUID().uuidString)"))
        let risks: [TransferRisk] = service.capabilities.traversal == .remoteComponentLstat ? [.remotePathChecksAreNotAtomic(path: parent)] : []
        return NoReplaceProbePlan(id: UUID(), parent: parent, temporaryDirectory: directory, serverBinding: binding,
                                  requiredRisks: risks, serviceIdentity: ObjectIdentifier(service))
    }
    /// The UI must show the directory/test action and obtain explicit approval before calling.
    public static func run(_ plan: NoReplaceProbePlan, service: any RemoteFileService, hostID: String,
                           approvedPlanID: UUID, acknowledgedRisks: [TransferRisk], token: CancellationToken,
                           scheduler: TransferScheduler = .shared) async throws -> NoReplaceProbeResult {
        guard approvedPlanID == plan.id, acknowledgedRisks == plan.requiredRisks,
              ObjectIdentifier(service) == plan.serviceIdentity, service.serverBinding == plan.serverBinding else {
            throw FileServiceError(.riskRejected, operation: "probe-not-explicitly-approved", path: plan.temporaryDirectory)
        }
        return try await scheduler.onHost(hostID, token: token) {
            await execute(plan, service: service, token: token)
        }
    }
    /// Called only from SafeTransferEngine while it already owns the host scheduler gate.
    /// Selection of the actual upload authorizes these owned temporary objects; no engineer
    /// dialog, extra connection, authentication, or unrelated directory scan is required.
    static func verifyForTransfer(service: any RemoteFileService, parent: RemotePath,
                                  token: CancellationToken) async throws -> NoReplaceProbeResult {
        try token.check()
        let plan = try prepare(service: service, parent: parent)
        return await execute(plan, service: service, token: token)
    }
    private static func execute(_ plan: NoReplaceProbePlan, service: any RemoteFileService,
                                token: CancellationToken) async -> NoReplaceProbeResult {
        var owned: [RemotePath] = []
        var uncertainDirectory: RemotePath?
        var failure: FileServiceError?
        var verified = false
        let directory = plan.temporaryDirectory
        do {
            try token.check()
            try await TransferChecks.inspect(service, path: directory, includeLeaf: false, token: token)
            do { try await service.mkdir(directory, token: token); owned.append(directory) }
            catch let error as FileServiceError where [.timeout, .transport, .cancelled, .closed, .io].contains(error.kind) {
                // An exclusive MKDIR may have reached the server before its reply was lost.
                // We cannot claim ownership or safely remove it; report only this candidate.
                uncertainDirectory = directory
                throw FileServiceError(error.kind, operation: "probe-directory-create-outcome-uncertain", path: directory, code: error.code)
            }
            let a = try directory.appending(FileName("source")); let b = try directory.appending(FileName("destination"))
            let first = Data(UUID().uuidString.utf8); let second = Data(UUID().uuidString.utf8)
            try await write(first, service: service, path: a, owned: &owned, token: token)
            try await write(second, service: service, path: b, owned: &owned, token: token)
            var rejected = false
            do { try await service.rename(a, to: b, mode: .noReplace, token: token) }
            catch let error as FileServiceError where [.conflict, .protocolFailure].contains(error.kind) { rejected = true }
            guard rejected else { throw FileServiceError(.needsCapabilityConfirmation, operation: "probe-rename-did-not-reject-existing-target", path: b) }
            guard try await read(service, path: a, token: token) == first,
                  try await read(service, path: b, token: token) == second else {
                throw FileServiceError(.integrity, operation: "probe-original-content-changed", path: directory)
            }
            // Also require an absent target to succeed, so a server rejecting every RENAME
            // cannot pass the collision test accidentally (permission/unsupported errors).
            let c = try directory.appending(FileName("absent-target"))
            do { _ = try await service.lstat(c, token: token); throw FileServiceError(.conflict, operation: "probe-target-not-absent", path: c) }
            catch let error as FileServiceError where error.kind == .notFound { }
            owned.append(c) // Directory is ours; record possible result before an uncertain network reply.
            try await service.rename(a, to: c, mode: .noReplace, token: token)
            guard try await read(service, path: c, token: token) == first,
                  try await read(service, path: b, token: token) == second else {
                throw FileServiceError(.integrity, operation: "probe-no-replace-success-content", path: directory)
            }
            do { _ = try await service.lstat(a, token: token); throw FileServiceError(.integrity, operation: "probe-source-still-exists", path: a) }
            catch let error as FileServiceError where error.kind == .notFound { }
            verified = true
        } catch {
            failure = error as? FileServiceError ?? FileServiceError(.io, operation: "server-commit-probe", path: directory)
        }
        var retained: [RemotePath] = uncertainDirectory.map { [$0] } ?? []
        for path in owned.reversed() {
            do {
                let cleanup = CancellationToken()
                try await TransferChecks.inspect(service, path: path, includeLeaf: false, token: cleanup)
                try await service.remove(path, directory: path == directory, token: cleanup)
            } catch let error as FileServiceError where error.kind == .notFound { }
            catch { retained.append(path) }
        }
        if !retained.isEmpty && failure == nil { failure = FileServiceError(.io, operation: "probe-cleanup-incomplete", path: directory) }
        let confirmation: ServerCommitConfirmation?
        if verified && failure == nil {
            confirmation = try? ServerCommitConfirmation(serverBinding: plan.serverBinding, parent: plan.parent,
                evidence: "no-replace probe \(plan.id.uuidString): existing destination rejected and both random original contents preserved")
        } else { confirmation = nil }
        return NoReplaceProbeResult(directory: directory, confirmation: confirmation, error: failure, retainedPaths: retained)
    }
    private static func write(_ data: Data, service: any RemoteFileService, path: RemotePath,
                              owned: inout [RemotePath], token: CancellationToken) async throws {
        let handle = try await service.open(path, mode: .exclusiveWrite, token: token)
        owned.append(path)
        do {
            var offset = 0
            while offset < data.count {
                let n = try await service.write(handle, data: Data(data.dropFirst(offset)), token: token)
                guard n > 0 && n <= data.count - offset else { throw FileServiceError(.integrity, operation: "probe-short-write", path: path) }
                offset += n
            }
            try await service.closeHandle(handle)
        } catch { try? await service.closeHandle(handle); throw error }
    }
    private static func read(_ service: any RemoteFileService, path: RemotePath, token: CancellationToken) async throws -> Data {
        let handle = try await service.open(path, mode: .read, token: token)
        do {
            var result = Data()
            while true {
                let bytes = try await service.read(handle, maxBytes: 128, token: token)
                if bytes.isEmpty { break }
                result.append(bytes)
                guard result.count <= 256 else { throw FileServiceError(.integrity, operation: "probe-content-too-large", path: path) }
            }
            try await service.closeHandle(handle); return result
        } catch { try? await service.closeHandle(handle); throw error }
    }
}
