import CryptoKit
import Foundation

/// Observed-change detection, NOT a source snapshot or a lock. Local fstat keeps device/inode and
/// nanosecond mtime tied to the opened FD. SFTP v3 usually has seconds only and no identity; a
/// missing/default fstat is explicitly weaker and gets ONE bounded streaming digest recheck.
/// A writer can still change a source after the final check, or restore all supplied metadata.
struct SourceIntegrityCheck: Sendable {
    let path: RemotePath
    let expected: FileAttributes
    let opened: FileAttributes?

    init(service: any RemoteFileService, path: RemotePath, handle: FileHandleID,
         expected: FileAttributes, token: CancellationToken) async throws {
        self.path = path; self.expected = expected
        opened = try await service.fstat(handle, token: token)
        try token.check()
        if let opened { try Self.compareAvailable(expected, opened, path: path, token: token) }
    }
    /// Preserve cancellation/closed/transport errors, rather than mislabelling them a source race.
    /// A known source disappearing or becoming a symlink during final traversal is a detected race.
    func validate(service: any RemoteFileService, handle: FileHandleID, token: CancellationToken) async throws -> Bool {
        try token.check()
        let currentPath: FileAttributes
        do {
            try await TransferChecks.inspect(service, path: path, includeLeaf: true, token: token)
            currentPath = try await service.lstat(path, token: token)
        } catch let error as FileServiceError where error.kind == .notFound || error.kind == .symbolicLink {
            try token.check()
            throw FileServiceError(.raceDetected, operation: "source-path-disappeared-or-link", path: path)
        }
        try token.check()
        guard currentPath == expected else { throw FileServiceError(.raceDetected, operation: "source-path-changed", path: path) }
        let currentHandle = try await service.fstat(handle, token: token)
        try token.check()
        if let currentHandle {
            try Self.compareAvailable(expected, currentHandle, path: path, token: token)
            if let opened { try Self.compareAvailable(opened, currentHandle, path: path, token: token) }
        }
        return !(Self.isStrong(expected) && opened == expected && currentHandle == expected)
    }
    private static func isStrong(_ a: FileAttributes) -> Bool {
        a.kind == .regular && a.size != nil && a.identity != nil && a.modifiedSeconds != nil && a.modifiedNanoseconds != nil
    }
    private static func compareAvailable(_ expected: FileAttributes, _ observed: FileAttributes,
                                         path: RemotePath, token: CancellationToken) throws {
        try token.check()
        func differs<T: Equatable>(_ a: T?, _ b: T?) -> Bool { if let a, let b { return a != b }; return false }
        guard (observed.kind == .unknown || observed.kind == expected.kind),
              !differs(expected.size, observed.size), !differs(expected.identity, observed.identity),
              !differs(expected.permissions, observed.permissions), !differs(expected.modifiedSeconds, observed.modifiedSeconds),
              !differs(expected.modifiedNanoseconds, observed.modifiedNanoseconds) else {
            throw FileServiceError(.raceDetected, operation: "source-handle-changed", path: path)
        }
    }
    /// At most expectedBytes plus one bounded read. A growing source fails once, never retries
    /// indefinitely. The already-open original handle remains retained by the caller throughout.
    func verifyDigest(service: any RemoteFileService, digest: Data, expectedBytes: UInt64,
                      scheduler: TransferScheduler, chunkSize: Int, token: CancellationToken) async throws {
        try token.check()
        try await TransferChecks.inspect(service, path: path, includeLeaf: true, token: token)
        let handle = try await service.open(path, mode: .read, token: token)
        do {
            let verification = try await SourceIntegrityCheck(service: service, path: path, handle: handle, expected: expected, token: token)
            _ = try await verification.validate(service: service, handle: handle, token: token)
            var hash = SHA256(), total: UInt64 = 0
            while true {
                let bytes = try await scheduler.chunk(token) {
                    try token.check()
                    return try await service.read(handle, maxBytes: chunkSize, token: token)
                }
                try token.check()
                guard bytes.count <= chunkSize else { throw FileServiceError(.integrity, operation: "oversized-source-recheck") }
                if bytes.isEmpty { break }
                guard UInt64(bytes.count) <= expectedBytes - total else {
                    throw FileServiceError(.raceDetected, operation: "source-grew-during-recheck", path: path)
                }
                total += UInt64(bytes.count); hash.update(data: bytes)
            }
            try token.check()
            _ = try await verification.validate(service: service, handle: handle, token: token)
            guard total == expectedBytes, Data(hash.finalize()) == digest else {
                throw FileServiceError(.raceDetected, operation: "source-content-changed", path: path)
            }
            try await service.closeHandle(handle)
        } catch {
            try? await service.closeHandle(handle)
            try token.check()
            throw error
        }
    }
}
