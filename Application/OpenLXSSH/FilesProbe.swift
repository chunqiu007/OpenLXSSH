#if HOST_PROBE
import Foundation
import OpenLXSSHFiles

/// Explicit real-local backend for isolated App GUI verification, never SFTP emulation.
actor LocalFilesProbeConnector: FilesConnecting {
    let root: URL
    private(set) var count = 0
    init(root: URL) { self.root = root }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        count += 1; try token.check()
        guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "local-gui-stale") }
        return try LocalFileService(root: root)
    }
}
#endif
