import COpenLXSSHFiles
import Foundation
import OpenLXSSHTrust

/// Protocol paths are raw POSIX bytes, rooted at `/`. No Unicode normalization or shell parsing.
/// Noncanonical components are rejected rather than silently rewritten.
public struct RemotePath: Hashable, Sendable {
    public let bytes: Data
    public init(bytes: Data) throws {
        guard bytes.first == 47, bytes.count <= 32_768, !bytes.contains(0) else {
            throw FileServiceError(.invalidPath, operation: "path")
        }
        if bytes.count > 1 {
            for component in bytes.dropFirst().split(separator: 47, omittingEmptySubsequences: false) {
                _ = try FileName(bytes: Data(component))
            }
        }
        self.bytes = bytes
    }
    public init(_ utf8: String) throws { try self.init(bytes: Data(utf8.utf8)) }
    public static let root = try! RemotePath("/")
    public func appending(_ name: FileName) throws -> RemotePath {
        try RemotePath(bytes: bytes + (bytes.count == 1 ? Data() : Data([47])) + name.bytes)
    }
    public var parent: RemotePath {
        guard bytes.count > 1, let i = bytes.lastIndex(of: 47), i > 0 else { return .root }
        return try! RemotePath(bytes: bytes.prefix(i))
    }
    public var name: FileName? {
        bytes.count > 1 ? try? FileName(bytes: Data(bytes.suffix(from: bytes.lastIndex(of: 47)! + 1))) : nil
    }
    var components: [FileName] {
        bytes.dropFirst().split(separator: 47).map { try! FileName(bytes: Data($0)) }
    }
    func withCString<T>(_ body: (UnsafePointer<CChar>, UInt32) throws -> T) rethrows -> T {
        try (Array(bytes) + [0]).withUnsafeBytes { ptr in
            try body(ptr.baseAddress!.assumingMemoryBound(to: CChar.self), UInt32(bytes.count))
        }
    }
}
public struct FileName: Hashable, Sendable {
    public let bytes: Data
    public init(bytes: Data) throws {
        guard !bytes.isEmpty, bytes.count <= 255, !bytes.contains(0), !bytes.contains(47),
              bytes != Data([46]), bytes != Data([46, 46]) else {
            throw FileServiceError(.invalidPath, operation: "name")
        }
        self.bytes = bytes
    }
    public init(_ utf8: String) throws { try self.init(bytes: Data(utf8.utf8)) }
    var cBytes: [CChar] { bytes.map { CChar(bitPattern: $0) } + [0] }
}
public enum FileKind: String, Sendable { case regular, directory, symbolicLink, other, unknown }
public struct FileAttributes: Equatable, Sendable {
    public let kind: FileKind
    public let size: UInt64?
    public let permissions: UInt32?
    public let modifiedSeconds: UInt64?
    public let modifiedNanoseconds: UInt32?
    public let identity: String? // Local device/inode; SFTP v3 does not provide an inode identity.
    public init(kind: FileKind, size: UInt64? = nil, permissions: UInt32? = nil,
                modifiedSeconds: UInt64? = nil, modifiedNanoseconds: UInt32? = nil, identity: String? = nil) {
        self.kind = kind; self.size = size; self.permissions = permissions
        self.modifiedSeconds = modifiedSeconds; self.modifiedNanoseconds = modifiedNanoseconds; self.identity = identity
    }
}
public struct DirectoryEntry: Equatable, Sendable {
    public let name: FileName
    public let attributes: FileAttributes
    public init(name: FileName, attributes: FileAttributes) { self.name = name; self.attributes = attributes }
}
public struct FileServiceError: Error, Equatable, Sendable {
    public enum Kind: String, Sendable {
        case invalidPath, notFound, permissionDenied, conflict, symbolicLink, unsupported
        case cancelled, timeout, untrusted, authentication, transport, protocolFailure, closed
        case resourceLimit, integrity, io, needsCapabilityConfirmation, riskRejected, raceDetected
    }
    public let kind: Kind
    public let operation: String
    public let path: RemotePath?
    public let code: Int64?
    /// An observed rejection bound to this handshake's endpoint and exact presented key.
    public let changedHostKey: ChangedHostKey?
    public init(_ kind: Kind, operation: String, path: RemotePath? = nil, code: Int64? = nil) {
        self.init(kind, operation: operation, path: path, code: code, changedHostKey: nil)
    }
    public init(_ kind: Kind, operation: String, path: RemotePath? = nil, code: Int64? = nil,
                changedHostKey: ChangedHostKey?) {
        self.kind = kind; self.operation = operation; self.path = path; self.code = code
        self.changedHostKey = changedHostKey
    }
}
public final class CancellationToken: @unchecked Sendable {
    let native: OpaquePointer
    private let lock = NSLock()
    private var observers: [UUID: @Sendable () -> Void] = [:]
    public init() { native = rf_cancel_create()! }
    deinit { rf_cancel_destroy(native) }
    public func cancel() {
        rf_cancel_set(native)
        let handlers: [@Sendable () -> Void] = lock.withLock {
            let values = Array(observers.values)
            observers.removeAll()
            return values
        }
        for handler in handlers { handler() }
    }
    public var isCancelled: Bool { rf_cancelled(native) != 0 }
    public func check() throws {
        if isCancelled || Task<Never, Never>.isCancelled { throw FileServiceError(.cancelled, operation: "cancel") }
    }
    /// Registers a one-shot callback fired when `cancel()` is invoked. If already cancelled,
    /// invokes `handler` immediately and returns `nil`.
    func addCancelObserver(_ handler: @escaping @Sendable () -> Void) -> UUID? {
        let id: UUID? = lock.withLock {
            if rf_cancelled(native) != 0 { return nil }
            let token = UUID()
            observers[token] = handler
            return token
        }
        if id == nil { handler() }
        return id
    }
    func removeCancelObserver(_ id: UUID) {
        lock.withLock { _ = observers.removeValue(forKey: id) }
    }
}
public struct FileHandleID: Hashable, Sendable {
    let value: UUID
    public init() { value = UUID() }
}
public enum OpenMode: Sendable { case read, exclusiveWrite }
public enum RenameMode: Sendable { case noReplace, replaceExisting }
public struct FileServiceCapabilities: Sendable {
    public enum Traversal: Sendable { case localDescriptorNoFollow, remoteComponentLstat }
    public enum NoReplace: Sendable { case atomicLocal, needsServerConfirmation }
    public let traversal: Traversal
    public let exclusiveCreate: Bool
    public let noReplace: NoReplace
    /// Backend has an atomic-replace API to attempt; remote support is checked by that API,
    /// and an unsupported extension is a failure, never a fallback.
    public let canAttemptAtomicReplace: Bool
    public init(traversal: Traversal, exclusiveCreate: Bool, noReplace: NoReplace, canAttemptAtomicReplace: Bool) {
        self.traversal = traversal; self.exclusiveCreate = exclusiveCreate
        self.noReplace = noReplace; self.canAttemptAtomicReplace = canAttemptAtomicReplace
    }
}
/// Evidence must be scoped to the actual backend/server implementation. It does not authorize overwrite.
public struct ServerCommitConfirmation: Sendable {
    public let serverBinding: UUID
    /// Evidence covers only the tested destination directory on this connected backend.
    public let parent: RemotePath
    public let evidence: String
    public init(serverBinding: UUID, parent: RemotePath = .root, evidence: String) throws {
        guard !evidence.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, evidence.utf8.count <= 1024 else {
            throw FileServiceError(.needsCapabilityConfirmation, operation: "empty-server-evidence")
        }
        self.serverBinding = serverBinding; self.parent = parent; self.evidence = evidence
    }
}
public struct CommitRequest: Sendable {
    public let mode: RenameMode
    public let expectedTarget: FileAttributes?
    public let expectedContentSHA256: Data?
    public let acceptNonCASOverwriteRisk: Bool
    public let serverConfirmation: ServerCommitConfirmation?
    public init(mode: RenameMode, expectedTarget: FileAttributes? = nil, expectedContentSHA256: Data? = nil,
                acceptNonCASOverwriteRisk: Bool = false, serverConfirmation: ServerCommitConfirmation? = nil) {
        self.mode = mode; self.expectedTarget = expectedTarget; self.expectedContentSHA256 = expectedContentSHA256
        self.acceptNonCASOverwriteRisk = acceptNonCASOverwriteRisk; self.serverConfirmation = serverConfirmation
    }
}
/// Each concrete service serializes native calls; streams are bounded pull/write chunks, not full-file Data.
/// Callers must not infer safe commit capabilities from the presence of a raw rename API.
public protocol RemoteFileService: AnyObject, Sendable {
    var capabilities: FileServiceCapabilities { get }
    var serverBinding: UUID? { get }
    /// A backend-owned terminal disposition, never inferred from a job's other endpoint.
    /// Implementations synchronize this read. Cancelled means this backend really terminated,
    /// not merely that a queued caller was cancelled; it is not a network-failure classification.
    var terminalFailure: FileServiceError? { get }
    /// Resolves the session's login directory to an absolute, canonical raw-byte path.
    /// This is independent of a terminal's working directory. Unsupported backends must
    /// throw, never substitute `/` or infer a home directory from the username.
    func initialDirectory(token: CancellationToken) async throws -> RemotePath
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry]
    /// Transfers only the raw link text. The manifest owns containment and target policy.
    func readSymbolicLink(_ path: RemotePath, token: CancellationToken) async throws -> Data
    /// Creates the link itself and fails if any object already occupies its name.
    func createSymbolicLink(_ path: RemotePath, target: Data, token: CancellationToken) async throws
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes
    /// Metadata of the actual opened handle, without moving its read offset. nil explicitly means
    /// unsupported (the source-compatible default), not a substitute path stat or snapshot guarantee.
    func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes?
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws
    func closeHandle(_ handle: FileHandleID) async throws
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws
    func cancel()
    func close() async
}
enum SymbolicLinkBytes {
    static let limit = 32_768
    static func validate(_ target: Data, at path: RemotePath) throws {
        guard !target.isEmpty, target.count <= limit, !target.contains(0) else {
            throw FileServiceError(.invalidPath, operation: "link-target-bytes", path: path)
        }
    }
}
extension RemoteFileService {
    public func readSymbolicLink(_ path: RemotePath, token: CancellationToken) async throws -> Data {
        try token.check()
        throw FileServiceError(.unsupported, operation: "readlink", path: path)
    }
    public func createSymbolicLink(_ path: RemotePath, target: Data, token: CancellationToken) async throws {
        try token.check()
        throw FileServiceError(.unsupported, operation: "symlink", path: path)
    }
    public func initialDirectory(token: CancellationToken) async throws -> RemotePath {
        try token.check()
        throw FileServiceError(.unsupported, operation: "initial-directory")
    }
    public func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? {
        try token.check(); return nil
    }
}
public enum NativeDiagnostics {
    public static var libssh2: String { String(cString: rf_libssh2_version()) }
    public static var openssl: String { String(cString: rf_openssl_version()) }
    public static var architecture: String { String(cString: rf_architecture()) }
    public static func smoke() -> Int32 { rf_library_smoke() }
}

/// A typed, single-answer mailbox for bounded host-key / keyboard-interactive UI callbacks.
/// The handler is dispatched off the native owner queue; absent/late answers cannot enable trust.
public final class ChallengeReply<Value: Sendable>: @unchecked Sendable {
    private let condition = NSCondition()
    private var answer: Value?
    private var resolved = false
    public init() {}
    @discardableResult public func resolve(_ answer: Value) -> Bool {
        condition.lock(); defer { condition.unlock() }
        guard !resolved else { return false }
        resolved = true; self.answer = answer; condition.broadcast(); return true
    }
    /// Revokes this reply, including a resolved answer not yet consumed by its single waiter.
    /// Cancellation of an interaction must also cancel its operation token; an empty answer is
    /// still a successful answer (notably for zero-prompt notifications), never cancellation.
    public func cancel() {
        condition.lock(); resolved = true; answer = nil; condition.broadcast(); condition.unlock()
    }
    private func snapshot() -> (Bool, Value?) {
        condition.lock(); defer { condition.unlock() }; return (resolved, answer)
    }
    private func expire() { condition.lock(); resolved = true; answer = nil; condition.unlock() }
    func waitAsync(token: CancellationToken, deadline: ContinuousClock.Instant) async throws -> Value {
        while true {
            do { try token.check() } catch { expire(); throw error }
            guard ContinuousClock.now < deadline else { expire(); throw FileServiceError(.timeout, operation: "challenge") }
            let (resolved, answer) = snapshot()
            if resolved {
                guard let answer else { throw FileServiceError(.cancelled, operation: "challenge") }
                return answer
            }
            do { try await Task.sleep(for: .milliseconds(5)) }
            catch { expire(); throw FileServiceError(.cancelled, operation: "challenge") }
        }
    }
    func wait(token: CancellationToken, deadline: Date) throws -> Value {
        condition.lock(); defer { condition.unlock() }
        while !resolved {
            if token.isCancelled { resolved = true; throw FileServiceError(.cancelled, operation: "challenge") }
            if Date() >= deadline { resolved = true; throw FileServiceError(.timeout, operation: "challenge") }
            _ = condition.wait(until: min(deadline, Date().addingTimeInterval(0.02)))
        }
        if token.isCancelled { resolved = true; answer = nil; throw FileServiceError(.cancelled, operation: "challenge") }
        if Date() >= deadline { resolved = true; answer = nil; throw FileServiceError(.timeout, operation: "challenge") }
        guard let answer else { throw FileServiceError(.cancelled, operation: "challenge") }
        return answer
    }
}
public struct ServerIdentity: Hashable, Sendable {
    public let host: String
    public let port: UInt16
    public init(host: String, port: UInt16) throws {
        guard !host.isEmpty, host.utf8.count <= 255, !host.utf8.contains(where: { $0 <= 32 || $0 == 127 }), port > 0 else {
            throw FileServiceError(.invalidPath, operation: "identity")
        }
        self.host = host; self.port = port
    }
}
public struct HostKey: Sendable {
    public let identity: ServerIdentity
    public let rawKey: Data
    public let algorithmCode: Int32
}
public enum HostKeyPolicy {
    /// No default trust. A caller must bind its known-hosts decision to identity AND exact raw key.
    public static func verify(_ key: HostKey, token: CancellationToken, timeout: TimeInterval,
                              handler: (@Sendable (HostKey, ChallengeReply<Bool>) -> Void)?) throws {
        try token.check()
        guard let handler else { throw FileServiceError(.untrusted, operation: "host-key") }
        let reply = ChallengeReply<Bool>()
        DispatchQueue.global().async { handler(key, reply) }
        let accepted = try reply.wait(token: token, deadline: Date().addingTimeInterval(timeout))
        try token.check()
        guard accepted else { throw FileServiceError(.untrusted, operation: "host-key") }
    }
}
