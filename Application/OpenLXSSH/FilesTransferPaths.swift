import Darwin
import Foundation
import OpenLXSSHFiles

/// Local paths are never reconstructed from escaped UI strings or normalized Unicode.
enum FilesLocalPaths {
    static func components(_ url: URL) throws -> [FileName] {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost" else {
            throw FileServiceError(.invalidPath, operation: "local-file-url-required")
        }
        let bytes: Data = try url.withUnsafeFileSystemRepresentation { pointer in
            guard let pointer else { throw FileServiceError(.invalidPath, operation: "local-path-representation") }
            return Data(bytes: pointer, count: strlen(pointer))
        }
        guard bytes.first == 47, bytes.count <= 32768, !bytes.contains(0) else {
            throw FileServiceError(.invalidPath, operation: "local-absolute-path")
        }
        var parts = bytes.dropFirst().split(separator: 47, omittingEmptySubsequences: false)
        if parts.last?.isEmpty == true { parts.removeLast() } // URL directory trailing slash, not a name.
        guard !parts.isEmpty else { return [] }
        return try parts.map { try FileName(bytes: Data($0)) }
    }
    static func rawPath(_ components: [FileName]) throws -> RemotePath {
        try components.reduce(RemotePath.root) { try $0.appending($1) }
    }
    /// Anchors each openat in the current directory FD, then retains the final root FD.
    /// No check-then-reopen by pathname and no claim to retain all ancestor FDs.
    static func openDirectory(_ components: [FileName]) throws -> Int32 {
        var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw FileServiceError(.io, operation: "local-root-open") }
        do {
            for name in components {
                let next = cString(name) { openat(fd, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) }
                guard next >= 0 else { throw localError("local-parent-no-follow") }
                Darwin.close(fd); fd = next
            }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    static func inspect(_ name: FileName, parent: Int32) throws -> TransferKind {
        var value = stat()
        guard cString(name, { fstatat(parent, $0, &value, AT_SYMLINK_NOFOLLOW) }) == 0 else { throw localError("local-selection-stat") }
        switch value.st_mode & S_IFMT {
        case S_IFREG: return .file
        case S_IFDIR: return .tree
        case S_IFLNK: throw FileServiceError(.symbolicLink, operation: "local-selection-link")
        default: throw FileServiceError(.unsupported, operation: "local-selection-special")
        }
    }
    private static func cString<T>(_ name: FileName, _ body: (UnsafePointer<CChar>) -> T) -> T {
        (name.bytes.map { CChar(bitPattern: $0) } + [0]).withUnsafeBufferPointer { body($0.baseAddress!) }
    }
    private static func localError(_ operation: String) -> FileServiceError {
        let kind: FileServiceError.Kind
        switch errno {
        case ELOOP, ENOTDIR: kind = .symbolicLink
        case ENOENT: kind = .notFound
        case EACCES, EPERM: kind = .permissionDenied
        default: kind = .io
        }
        return FileServiceError(kind, operation: operation, code: Int64(errno))
    }
}

struct FilesTransferContext: Sendable {
    let lifetime: UUID
    let serviceID: TransferServiceID
    let hostID: UUID
    let endpoint: String
    let path: RemotePath
    let confirmation: ServerCommitConfirmation?
}
struct FilesTransferLabel: Sendable {
    let endpoint: String
    let direction: String
    let localRoots: [TransferServiceID: RemotePath]
}
