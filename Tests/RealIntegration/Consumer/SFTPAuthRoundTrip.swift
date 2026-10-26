import Foundation
import OpenLXSSHFiles
import RealIntegrationCore

/// Only one fresh own UUID directory and one exclusively-created regular file.
/// No overwrite, recursive cleanup, arbitrary caller path or pre-existing delete.
enum SFTPAuthRoundTrip {
    static func run(service: LibSSH2FileService, token: CancellationToken, id: UUID, report: inout SFTPAuthReport) async throws {
        let ownership = RemoteOwnership(id: id)
        let directory = try RemotePath(ownership.directory), payload = try RemotePath(ownership.payload)
        for parent in ["/", "/fixture", "/fixture/home"] {
            guard try await service.lstat(RemotePath(parent), token: token).kind == .directory else { throw SFTPAuthError.integrity }
            report.lstatChecks += 1
        }
        try await service.mkdir(directory, token: token)
        var payloadOwned = false, handle: FileHandleID?, bodyFailure: Error?
        let bytes = Data(("OpenLXSSH disposable tiny SFTP round trip " + id.uuidString + "\n").utf8)
        guard bytes.count == 79 else { throw SFTPAuthError.integrity }
        do {
            guard try await service.lstat(directory, token: token).kind == .directory else { throw SFTPAuthError.integrity }
            report.lstatChecks += 1
            try ownership.checkListing(try await service.list(directory, token: token).map { $0.name.bytes }, payloadOwned: false)
            report.listChecks += 1
            handle = try await service.open(payload, mode: .exclusiveWrite, token: token); payloadOwned = true
            var offset = 0
            while offset < bytes.count {
                let count = try await service.write(handle!, data: Data(bytes.dropFirst(offset)), token: token)
                guard count > 0, count <= bytes.count - offset else { throw SFTPAuthError.integrity }
                offset += count; report.bytesWritten += count
            }
            try await service.closeHandle(handle!); handle = nil
            let attributes = try await service.lstat(payload, token: token); report.lstatChecks += 1
            guard attributes.kind == .regular, attributes.size == 79 else { throw SFTPAuthError.integrity }
            try ownership.checkListing(try await service.list(directory, token: token).map { $0.name.bytes }, payloadOwned: true)
            report.listChecks += 1
            handle = try await service.open(payload, mode: .read, token: token)
            var received = Data()
            for _ in 0..<4 {
                let chunk = try await service.read(handle!, maxBytes: 1024, token: token)
                if chunk.isEmpty { break }
                guard received.count + chunk.count <= 1024 else { throw SFTPAuthError.integrity }
                received += chunk; report.bytesRead += chunk.count
            }
            guard received.count == 79, PrivateInput.sha256(received) == PrivateInput.sha256(bytes) else { throw SFTPAuthError.integrity }
            report.hashMatched = true
            try await service.closeHandle(handle!); handle = nil
        } catch { bodyFailure = error }
        do {
            if let handle { try await service.closeHandle(handle) }
            let cleanup = CancellationToken()
            guard try await service.lstat(directory, token: cleanup).kind == .directory else { throw SFTPAuthError.cleanupIncomplete }
            let children = try await service.list(directory, token: cleanup)
            try ownership.checkListing(children.map { $0.name.bytes }, payloadOwned: payloadOwned)
            if payloadOwned {
                guard children.count == 1, children[0].attributes.kind == .regular,
                      try await service.lstat(payload, token: cleanup).kind == .regular else { throw SFTPAuthError.cleanupIncomplete }
                try await service.remove(payload, directory: false, token: cleanup)
            }
            guard try await service.list(directory, token: cleanup).isEmpty else { throw SFTPAuthError.cleanupIncomplete }
            try await service.remove(directory, directory: true, token: cleanup)
            report.remoteCleanupCompleted = true
        } catch { throw SFTPAuthError.cleanupIncomplete }
        if let bodyFailure { throw bodyFailure }
    }
}
