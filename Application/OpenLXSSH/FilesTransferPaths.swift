import AppKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHCore

/// Local paths are never reconstructed from escaped UI strings or normalized Unicode.
enum FilesLocalPaths {
    static func components(_ url: URL) throws -> [FileName] {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost" else {
            throw FileServiceError(.invalidPath, operation: "local-file-url-required")
        }
        guard let value = URLComponents(url: url, resolvingAgainstBaseURL: true),
              value.user == nil, value.password == nil, value.port == nil,
              value.query == nil, value.fragment == nil else {
            throw FileServiceError(.invalidPath, operation: "local-file-url-components")
        }
        // Foundation's filesystem-representation initializer replaces invalid UTF-8.
        // Decode percent escapes as bytes instead of passing through a Swift String path.
        let encoded = Array(value.percentEncodedPath.utf8)
        var bytes = Data(), index = 0
        while index < encoded.count {
            if encoded[index] == 37 {
                guard index + 2 < encoded.count, let high = hex(encoded[index + 1]), let low = hex(encoded[index + 2]) else {
                    throw FileServiceError(.invalidPath, operation: "local-path-escape")
                }
                let byte = high * 16 + low
                guard byte != 47 else { throw FileServiceError(.invalidPath, operation: "local-path-escaped-separator") }
                bytes.append(byte); index += 3
            } else { bytes.append(encoded[index]); index += 1 }
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
    static func url(_ path: RemotePath) -> URL {
        // Encode every name byte, including invalid UTF-8, without Unicode conversion.
        // Separators remain literal so URL and our decoder agree about path boundaries.
        let digits = Array("0123456789ABCDEF".utf8)
        var encoded = Array("file://".utf8)
        for byte in path.bytes {
            if byte == 47 { encoded.append(byte) }
            else { encoded.append(37); encoded.append(digits[Int(byte >> 4)]); encoded.append(digits[Int(byte & 15)]) }
        }
        return URL(string: String(decoding: encoded, as: UTF8.self))!
    }
    private static func hex(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 48...57: byte - 48
        case 65...70: byte - 55
        case 97...102: byte - 87
        default: nil
        }
    }
    static func components(_ path: RemotePath) throws -> [FileName] {
        try path.bytes.dropFirst().split(separator: 47).map { try FileName(bytes: Data($0)) }
    }
    static func attributes(_ name: FileName, parent: Int32) throws -> FileAttributes {
        var value = stat()
        guard cString(name, { fstatat(parent, $0, &value, AT_SYMLINK_NOFOLLOW) }) == 0 else { throw localError("local-selection-stat") }
        let kind: FileKind = value.st_mode & S_IFMT == S_IFREG ? .regular : value.st_mode & S_IFMT == S_IFDIR ? .directory : value.st_mode & S_IFMT == S_IFLNK ? .symbolicLink : .other
        return FileAttributes(kind: kind, size: UInt64(max(0, value.st_size)), permissions: UInt32(value.st_mode),
            modifiedSeconds: UInt64(max(0, value.st_mtimespec.tv_sec)), modifiedNanoseconds: UInt32(value.st_mtimespec.tv_nsec), identity: "\(value.st_dev):\(value.st_ino)")
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
    let generation: UInt64
    let revision: UUID
    let serviceID: TransferServiceID
    let hostID: UUID
    let host: HostConfiguration
    var connectionIdentity: HostConnectionIdentity { host.connectionIdentity }
    let endpoint: String
    let path: RemotePath
    let confirmation: ServerCommitConfirmation?
}
struct FilesTransferLabel: Sendable {
    let endpoint: String
    let direction: String
    let localRoots: [TransferServiceID: RemotePath]
    let totalBytes: UInt64?
    init(endpoint: String, direction: String, localRoots: [TransferServiceID: RemotePath], totalBytes: UInt64? = nil) {
        self.endpoint = endpoint; self.direction = direction; self.localRoots = localRoots; self.totalBytes = totalBytes
    }
}
enum FilesTransferDirection: Sendable, Equatable { case upload, download
    var title: String { self == .upload ? "上传" : "下载" }
}
/// Immutable admission facts, not a pathname-based grant or a display label.
/// A released local service requires a fresh explicit selection and a new FD.
struct FilesTransferRetryOrigin: Sendable, Equatable {
    let lifetime: UUID
    let hostID: UUID
    let host: HostConfiguration
    var connectionIdentity: HostConnectionIdentity { host.connectionIdentity }
    let direction: FilesTransferDirection
    let source: TransferLocation
    let destination: TransferLocation
    let kind: TransferKind
    let localRoot: RemotePath
    func matches(_ job: TransferJobSnapshot) -> Bool {
        job.request.hostID == hostID.uuidString && job.request.source == source
            && job.request.destination == destination && job.request.kind == kind
    }
    func localSelectionPath() throws -> RemotePath {
        guard direction == .upload else { return localRoot }
        return try RemotePath(bytes: (localRoot == .root ? Data() : localRoot.bytes) + source.path.bytes)
    }
}
struct FilesTransferRetrySelection: Identifiable, Sendable {
    let id = UUID()
    let jobID: TransferJobID
    let jobGeneration: UUID
    let origin: FilesTransferRetryOrigin
    let context: FilesTransferContext
}
enum FilesRetryAuthorizationError: Error {
    case originUnavailable, originalConnectionRequired, originalSelectionRequired, stale, busy
    var issue: AppIssue {
        switch self {
        case .originUnavailable: AppIssue(code: "files.retry.originUnavailable", message: "此任务缺少原始授权信息，请按原目标重新发起传输。")
        case .originalConnectionRequired: AppIssue(code: "files.retry.originalConnectionRequired", message: "请先手动连接此任务原来的主机，并保持原连接配置，再重试。")
        case .originalSelectionRequired: AppIssue(code: "files.retry.originalSelectionRequired", message: "请选择任务原来的本地来源或目标目录；如需更换位置，请重新发起传输。")
        case .stale: AppIssue(code: "files.retry.stale", message: "任务、连接或目录已变化，请重新发起重试。")
        case .busy: AppIssue(code: "files.retry.busy", message: "请先完成或取消当前的文件选择与传输审核。")
        }
    }
}
struct FilesNavigationHistory: Equatable {
    private(set) var paths: [RemotePath] = []
    private(set) var index = -1
    var backward: (path: RemotePath, index: Int)? { index > 0 ? (paths[index - 1], index - 1) : nil }
    var forward: (path: RemotePath, index: Int)? { index >= 0 && index + 1 < paths.count ? (paths[index + 1], index + 1) : nil }
    mutating func commit(_ path: RemotePath, index supplied: Int? = nil) {
        if let supplied, paths.indices.contains(supplied), paths[supplied] == path { index = supplied; return }
        guard index < 0 || paths[index] != path else { return }
        paths = Array(paths.prefix(index + 1)); paths.append(path); index = paths.count - 1
    }
}
struct FilesSort: Equatable {
    enum Column: String, CaseIterable { case name, modified, size, kind, permissions }
    var column: Column = .name
    var ascending = true
    func apply(_ entries: [DirectoryEntry]) -> [DirectoryEntry] {
        entries.sorted { left, right in
            let order: ComparisonResult
            switch column {
            case .name: order = FileDisplay.name(left.name).localizedStandardCompare(FileDisplay.name(right.name))
            case .modified: order = compare(left.attributes.modifiedSeconds, right.attributes.modifiedSeconds)
            case .size: order = compare(left.attributes.size, right.attributes.size)
            case .kind: order = left.attributes.kind.rawValue.compare(right.attributes.kind.rawValue)
            case .permissions: order = compare(left.attributes.permissions, right.attributes.permissions)
            }
            if order == .orderedSame { return left.name.bytes.lexicographicallyPrecedes(right.name.bytes) }
            return ascending ? order == .orderedAscending : order == .orderedDescending
        }
    }
    private func compare<T: Comparable>(_ left: T?, _ right: T?) -> ComparisonResult {
        if left == right { return .orderedSame }
        guard let left else { return .orderedAscending }; guard let right else { return .orderedDescending }
        return left < right ? .orderedAscending : .orderedDescending
    }
}
enum FilesMetadataDisplay {
    static func size(_ attributes: FileAttributes) -> String {
        guard attributes.kind == .regular, let size = attributes.size else { return "—" }
        return ByteCountFormatter.string(fromByteCount: Int64(clamping: size), countStyle: .file)
    }
    static func permissions(_ attributes: FileAttributes) -> String { attributes.permissions.map { String(format: "%04o", $0 & 0o7777) } ?? "未知" }
    static func modified(_ attributes: FileAttributes) -> String {
        attributes.modifiedSeconds.map { Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .numeric, time: .shortened) } ?? "未知"
    }
    static func kind(_ kind: FileKind) -> String { switch kind { case .directory: "文件夹"; case .regular: "文件"; case .symbolicLink: "符号链接"; case .other: "特殊文件"; case .unknown: "未知" } }
}

enum FilesPaneDrag {
    static let remoteType = NSPasteboard.PasteboardType("org.openlxssh.remote-file-selection")
    private struct Payload: Codable {
        let lifetime: UUID
        let generation: UInt64
        let revision: UUID
        let service: UUID
        let host: UUID
        let path: Data
        let names: [Data]
    }
    static func local(rows: [DirectoryEntry], parent: RemotePath) -> [NSPasteboardWriting] {
        rows.compactMap { entry in (try? parent.appending(entry.name)).map { FilesLocalPaths.url($0) as NSURL } }
    }
    static func remote(rows: [DirectoryEntry], context: FilesTransferContext) -> NSPasteboardWriting {
        let item = NSPasteboardItem()
        let payload = Payload(lifetime: context.lifetime, generation: context.generation, revision: context.revision,
            service: context.serviceID, host: context.hostID, path: context.path.bytes, names: rows.map { $0.name.bytes })
        if let data = try? JSONEncoder().encode(payload) { item.setData(data, forType: remoteType) }
        return item
    }
    @MainActor static func remoteNames(_ pasteboard: NSPasteboard, controller: FilesController) -> Set<FileName>? {
        guard let data = pasteboard.data(forType: remoteType), data.count <= 65536,
              let payload = try? JSONDecoder().decode(Payload.self, from: data),
              !payload.names.isEmpty, payload.names.count <= 128,
              let context = try? controller.transferContext(upload: false),
              payload.lifetime == context.lifetime, payload.generation == context.generation, payload.revision == context.revision,
              payload.service == context.serviceID,
              payload.host == context.hostID, payload.path == context.path.bytes,
              let names = try? payload.names.map({ try FileName(bytes: $0) }), Set(names).count == names.count else { return nil }
        return Set(names)
    }
}

enum FilesExactClipboard {
    static let rawPathType = NSPasteboard.PasteboardType("org.openlxssh.raw-posix-path")
    static func copy(_ path: RemotePath) { copy([path]) }
    static func copy(_ paths: [RemotePath]) {
        guard !paths.isEmpty else { return }
        let items: [NSPasteboardItem] = paths.map { path in
            let item = NSPasteboardItem(); item.setData(path.bytes, forType: rawPathType)
            if let text = String(data: path.bytes, encoding: .utf8) { item.setString(text, forType: .string) }
            return item
        }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents(); pasteboard.writeObjects(items)
    }
}
