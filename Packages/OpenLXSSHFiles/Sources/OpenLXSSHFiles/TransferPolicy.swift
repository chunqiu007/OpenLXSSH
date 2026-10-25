import CryptoKit
import Foundation

/// SFTP paths are owned by the authenticated server, unlike the local download root. These checks
/// reject known links, but cannot constrain a server changing its own tree after an lstat.
public enum TransferRisk: Sendable, Equatable {
    case remotePathChecksAreNotAtomic(path: RemotePath)
    case overwriteIsAtomicButNotCompareAndSwap(path: RemotePath)
    case remoteFsyncUnavailable(path: RemotePath)
    case deletionChecksAreNotCompareAndSwap(path: RemotePath)
}
public typealias TransferRiskHandler = @Sendable (TransferRisk) async -> Bool
public struct TransferPolicy: Sendable {
    public let confirmRisk: TransferRiskHandler?
    public let serverCommit: ServerCommitConfirmation?
    public init(confirmRisk: TransferRiskHandler? = nil, serverCommit: ServerCommitConfirmation? = nil) {
        self.confirmRisk = confirmRisk; self.serverCommit = serverCommit
    }
    func require(_ risk: TransferRisk) async throws {
        guard let confirmRisk else { throw FileServiceError(.riskRejected, operation: "explicit-risk-confirmation-required") }
        guard await confirmRisk(risk) else { throw FileServiceError(.riskRejected, operation: "risk-rejected") }
    }
}

enum TransferChecks {
    static func inspect(_ service: any RemoteFileService, path: RemotePath,
                        includeLeaf: Bool, token: CancellationToken) async throws {
        guard service.capabilities.traversal == .remoteComponentLstat else { return }
        var current = RemotePath.root
        let components = includeLeaf ? path.components : path.parent.components
        for (index, component) in components.enumerated() {
            try token.check(); current = try current.appending(component)
            let attr = try await service.lstat(current, token: token)
            if attr.kind == .symbolicLink { throw FileServiceError(.symbolicLink, operation: "component-lstat", path: current) }
            if index < components.count - 1 || !includeLeaf {
                guard attr.kind == .directory else { throw FileServiceError(.conflict, operation: "component-not-directory", path: current) }
            }
        }
    }
    /// Streaming content fingerprint (no remote command). Used only for an explicitly selected existing target.
    static func contentFingerprint(_ service: any RemoteFileService, path: RemotePath,
                                   token: CancellationToken) async throws -> Data {
        let handle = try await service.open(path, mode: .read, token: token)
        do {
            var digest = SHA256()
            while true {
                let chunk = try await TransferScheduler.shared.chunk(token) {
                    try await service.read(handle, maxBytes: 65536, token: token)
                }
                if chunk.isEmpty { break }
                digest.update(data: chunk)
            }
            try await service.closeHandle(handle)
            return Data(digest.finalize())
        } catch { try? await service.closeHandle(handle); throw error }
    }
    static func requireUnchanged(_ service: any RemoteFileService, path: RemotePath,
                                 expected: FileAttributes, digest: Data, token: CancellationToken) async throws {
        let before: FileAttributes
        do { before = try await service.lstat(path, token: token) }
        catch let error as FileServiceError where error.kind == .notFound {
            throw FileServiceError(.raceDetected, operation: "selected-target-disappeared", path: path)
        }
        guard before == expected, before.kind == .regular else { throw FileServiceError(.raceDetected, operation: "target-metadata-changed", path: path) }
        let observed = try await contentFingerprint(service, path: path, token: token)
        let after = try await service.lstat(path, token: token)
        guard after == expected, observed == digest else { throw FileServiceError(.raceDetected, operation: "target-fingerprint-changed", path: path) }
        // This is a known-race detector, not a CAS. A change after this check remains a disclosed risk.
    }
}

extension RemoteFileService {
    public var serverBinding: UUID? { nil }
    public func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest,
                       token: CancellationToken) async throws {
        if request.mode == .replaceExisting {
            guard capabilities.canAttemptAtomicReplace, request.acceptNonCASOverwriteRisk,
                  let expected = request.expectedTarget, let digest = request.expectedContentSHA256 else {
                throw FileServiceError(.unsupported, operation: "overwrite-preconditions", path: destination)
            }
            try await TransferChecks.requireUnchanged(self, path: destination, expected: expected, digest: digest, token: token)
        } else if capabilities.noReplace == .needsServerConfirmation {
            guard let binding = serverBinding, request.serverConfirmation?.serverBinding == binding else {
                throw FileServiceError(.needsCapabilityConfirmation, operation: "server-no-replace-unproven", path: destination)
            }
        }
        try await rename(source, to: destination, mode: request.mode, token: token)
    }
}
