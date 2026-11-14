import Darwin
import Foundation
import OpenLXSSHCore

enum AppStorageFailure: Error, Sendable { case committedStorageUnsafe }

struct AppSnapshot: Sendable {
    var hosts: [HostConfiguration]
    var folders: [HostFolder]
    var keys: [ManagedKeyReference]
    var settings: AppSettings
    var allHosts: [HostConfiguration]? = nil
    var folderPaths: [HostFolderPath] = []
    var tags: [HostTag] = []
    /// Filtered metadata follows hosts; the full catalog is never scoped to the current search/group/tags.
    var hostMetadata: [HostMetadata] = []
    var allHostMetadata: [HostMetadata]? = nil

    var catalog: [HostMetadata] { allHostMetadata ?? hostMetadata }
    var hostTagIDs: [UUID: Set<UUID>] { Dictionary(uniqueKeysWithValues: catalog.map { ($0.id, $0.tagIDs) }) }
    var keyHostReferenceCounts: [UUID: Int] { counts((allHosts ?? hosts).compactMap(\.keyRef)) }
    var credentialHostReferenceCounts: [UUID: Int] { counts((allHosts ?? hosts).compactMap(\.credentialRef)) }
    var credentialKeyReferenceCounts: [UUID: Int] { counts(keys.compactMap(\.passphraseCredentialRef)) }
    var tagHostReferenceCounts: [UUID: Int] { counts(catalog.flatMap { $0.tagIDs }) }

    private func counts(_ ids: [UUID]) -> [UUID: Int] {
        ids.reduce(into: [:]) { $0[$1, default: 0] += 1 }
    }
}

protocol AppRepositoryProtocol: Sendable {
    func snapshot(query: HostQuery) async throws -> AppSnapshot
    /// A single-direction invalidation channel. Reads never publish, including refreshes by consumers.
    func metadataChanges() async -> AsyncStream<Void>
    func vaultMetadata(query: HostQuery) async throws -> VaultMetadataSnapshot
    func folderDeletionImpact(id: UUID) async throws -> FolderDeletionImpact
    func tagDeletionImpact(id: UUID) async throws -> TagDeletionImpact
    func updateKeyLabel(keyID: UUID, label: String) async throws
    func apply(_ changes: [RepositoryChange]) async throws
    func copyHost(id: UUID) async throws -> HostConfiguration
    func copyFolder(id: UUID) async throws -> HostFolder
    func close() async throws
    func securityMetadata() async throws -> SecurityMetadata
    func completeCleanup(_ id: UUID) async throws
    func recordCleanupFailure(_ id: UUID, failure: CleanupFailure) async throws
}

struct SecurityMetadata: Sendable {
    var hosts: [HostConfiguration]
    var keys: [ManagedKeyReference]
    var credentials: [OpenLXSSHCore.CredentialReference]
    var tickets: [CleanupTicket]
    var completedTickets: [CleanupTicket] = []
}

extension AppRepositoryProtocol {
    // Older test repositories need not implement the new metadata surface. Unsupported operations
    // fail explicitly instead of fabricating an empty catalog, a zero impact, or a successful save.
    func metadataChanges() async -> AsyncStream<Void> { AsyncStream { $0.finish() } }
    func vaultMetadata(query: HostQuery) async throws -> VaultMetadataSnapshot { throw RepositoryError.notFound }
    func folderDeletionImpact(id: UUID) async throws -> FolderDeletionImpact { throw RepositoryError.notFound }
    func tagDeletionImpact(id: UUID) async throws -> TagDeletionImpact { throw RepositoryError.notFound }
    func updateKeyLabel(keyID: UUID, label: String) async throws { throw RepositoryError.notFound }
    func securityMetadata() async throws -> SecurityMetadata { throw RepositoryError.notFound }
    func completeCleanup(_ id: UUID) async throws { throw RepositoryError.notFound }
    func recordCleanupFailure(_ id: UUID, failure: CleanupFailure) async throws { throw RepositoryError.notFound }
}

enum AppDataLocation: Sendable {
    case applicationSupport
    /// Test callers must supply an existing, exclusively owned temporary directory.
    case isolated(URL)
    #if LOCAL_CANDIDATE
    /// Only a validated portable-trial bootstrap can authorize the independent persistent root.
    case localTrial(LocalCandidateBootstrap)
    #endif
    #if PREVIEW_ISOLATED
    /// Only a freshly issued capability can authorize engineering-preview storage.
    case engineeringPreview(EngineeringPreviewRoot)
    #endif

    func databaseDirectory() throws -> URL {
        switch self {
        case .applicationSupport:
            guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
                throw RepositoryError.unsafeDatabaseLocation
            }
            // Do not chmod Library or Application Support. Only create/secure our own child.
            let base = support.resolvingSymlinksInPath()
            let fd = open(base.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
            defer { Darwin.close(fd) }
            try Self.ensureAppParent(in: fd)
            return base.appendingPathComponent("OpenLXSSH", isDirectory: true).appendingPathComponent("Data", isDirectory: true)
        case .isolated(let supplied):
            let temporary = try Self.canonical(FileManager.default.temporaryDirectory)
            let parent = try Self.canonical(supplied.deletingLastPathComponent())
            let name = supplied.lastPathComponent
            guard supplied.isFileURL, parent == temporary,
                  name.hasPrefix("OpenLXSSH-AppSmoke-") || name.hasPrefix("OpenLXSSH-AppTests-") else {
                throw RepositoryError.unsafeDatabaseLocation
            }
            let fd = open(supplied.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
            defer { Darwin.close(fd) }
            try AppFileSecurity.directory(fd)
            return supplied.appendingPathComponent("Data", isDirectory: true)
        #if LOCAL_CANDIDATE
        case .localTrial(let bootstrap): return try bootstrap.trialDatabaseDirectory()
        #endif
        #if PREVIEW_ISOLATED
        case .engineeringPreview(let root):
            return try root.databaseDirectory()
        #endif
        }
    }

    static func canonical(_ url: URL) throws -> URL {
        guard let path = realpath(url.path, nil) else { throw RepositoryError.unsafeDatabaseLocation }
        defer { free(path) }
        return URL(fileURLWithPath: String(cString: path), isDirectory: true)
    }

    static func ensureAppParent(in parent: Int32) throws {
        try AppFileSecurity.applicationSupportParent(parent)
        if mkdirat(parent, "OpenLXSSH", 0o700) != 0 && errno != EEXIST { throw RepositoryError.unsafeDatabaseLocation }
        let fd = openat(parent, "OpenLXSSH", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw RepositoryError.unsafeDatabaseLocation }
        defer { Darwin.close(fd) }
        // Check ACL before chmod: never silently repair access policy supplied by a user.
        try AppFileSecurity.directory(fd, mode: nil)
        guard fchmod(fd, 0o700) == 0 else { throw RepositoryError.unsafeDatabaseLocation }
        try AppFileSecurity.directory(fd)
        try AppFileSecurity.applicationSupportParent(parent)
    }
}

/// This actor owns initialization, reads, writes and closure of the synchronous Core boundary.
/// Nothing in this type is MainActor-isolated, and no database work runs in a SwiftUI body.
actor AppRepository: AppRepositoryProtocol {
    private let location: AppDataLocation
    private var database: OpenLXSSHDatabase?
    private let afterCommit: @Sendable () throws -> Void
    private var metadataObservers: [UUID: AsyncStream<Void>.Continuation] = [:]
    func metadataChanges() async -> AsyncStream<Void> {
        let id = UUID()
        return AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            metadataObservers[id] = continuation
            continuation.onTermination = { [weak self] _ in Task { await self?.removeObserver(id) } }
        }
    }
    private func removeObserver(_ id: UUID) { metadataObservers[id] = nil }
    private func metadataDidCommit() { for observer in metadataObservers.values { observer.yield(()) } }
    init(location: AppDataLocation = .applicationSupport, afterCommit: @escaping @Sendable () throws -> Void = {}) {
        self.location = location; self.afterCommit = afterCommit
    }

    private func opened() throws -> OpenLXSSHDatabase {
        let directory = try location.databaseDirectory()
        if let database { return database }
        let value = try OpenLXSSHDatabase(directory: directory)
        #if PREVIEW_ISOLATED
        if case .engineeringPreview(let root) = location {
            do { try root.recordDatabaseOpen(value.databaseURL) }
            catch { try? value.close(); throw error }
        }
        #endif
        database = value
        return value
    }

    func snapshot(query: HostQuery) throws -> AppSnapshot {
        let db = try opened()
        let filtered = try db.vaultMetadata(query)
        let catalog = try db.hostsMetadata()
        let snapshot = AppSnapshot(hosts: filtered.hosts.map(\.host), folders: filtered.folders.compactMap { $0.components.last },
            keys: try db.keys(), settings: try db.settings(), allHosts: catalog.map(\.host),
            folderPaths: filtered.folders, tags: filtered.tags, hostMetadata: filtered.hosts, allHostMetadata: catalog)
        _ = try location.databaseDirectory()
        return snapshot
    }

    func vaultMetadata(query: HostQuery) async throws -> VaultMetadataSnapshot {
        let value = try opened().vaultMetadata(query)
        _ = try location.databaseDirectory()
        return value
    }
    func folderDeletionImpact(id: UUID) async throws -> FolderDeletionImpact {
        let value = try opened().folderDeletionImpact(id: id)
        _ = try location.databaseDirectory()
        return value
    }
    func tagDeletionImpact(id: UUID) async throws -> TagDeletionImpact {
        let value = try opened().tagDeletionImpact(id: id)
        _ = try location.databaseDirectory()
        return value
    }
    func updateKeyLabel(keyID: UUID, label: String) async throws {
        try apply([.updateKeyLabel(keyID: keyID, label: label)])
    }

    private func validateCommittedStorage() throws {
        // Commit is irrevocable even if post-commit access verification fails.
        metadataDidCommit()
        do { try afterCommit(); _ = try location.databaseDirectory() }
        catch { throw AppStorageFailure.committedStorageUnsafe }
    }
    func apply(_ changes: [RepositoryChange]) throws {
        #if PREVIEW_ISOLATED
        if case .engineeringPreview = location {
            for change in changes {
                switch change {
                case .insertHost(let host), .updateHost(let host), .updateHostIfUnchanged(let host, _):
                    guard host.keyRef == nil, host.credentialRef == nil, !host.savePasswordAuthorized else { throw EngineeringPreviewFailure.unavailable }
                case .registerCredential, .registerKey, .updateKeyPassphrase, .deleteCredential, .deleteKey, .scheduleOrphanCleanup:
                    throw EngineeringPreviewFailure.unavailable
                default: break
                }
            }
        }
        #endif
        try opened().apply(changes)
        try validateCommittedStorage()
    }

    func copyHost(id: UUID) throws -> HostConfiguration {
        let db = try opened()
        guard let original = try db.host(id: id) else { throw RepositoryError.notFound }
        let copy = try db.copyHost(id: id, name: Self.copyName(original.name))
        try validateCommittedStorage()
        return copy
    }

    /// Recursively copies the subtree in Core's single SQLite transaction, not a read/apply
    /// sequence that could resurrect another process's revoked authorization snapshot.
    func copyFolder(id: UUID) throws -> HostFolder {
        let db = try opened()
        guard let original = try db.folder(id: id) else { throw RepositoryError.notFound }
        let copy = try db.copyFolder(id: id, name: Self.copyName(original.name))
        try validateCommittedStorage()
        return copy
    }

    private static func copyName(_ name: String) -> String {
        let suffix = " 副本"
        var prefix = name
        while prefix.utf8.count + suffix.utf8.count > 256 { prefix.removeLast() }
        return prefix + suffix
    }

    func securityMetadata() async throws -> SecurityMetadata {
        let db = try opened()
        let tickets = try db.cleanupTickets(includeCompleted: true)
        let metadata = SecurityMetadata(hosts: try db.hosts(), keys: try db.keys(), credentials: try db.credentials(),
                                        tickets: tickets.filter { $0.state == .pending }, completedTickets: tickets.filter { $0.state == .completed })
        _ = try location.databaseDirectory()
        return metadata
    }
    func completeCleanup(_ id: UUID) async throws { try opened().completeCleanup(ticketID: id); try validateCommittedStorage() }
    func recordCleanupFailure(_ id: UUID, failure: CleanupFailure) async throws { try opened().recordCleanupFailure(ticketID: id, failure: failure); try validateCommittedStorage() }

    func close() throws {
        try database?.close()
        database = nil
    }
}

// This parser is deliberately available in every build: unsupported preview flags
// must be refused before any AppKit, preferences, stores or contract file exists.
enum EngineeringPreviewFailure: Error, Equatable {
    case arguments, contract, unsafeStorage, offline, unavailable
}
enum EngineeringPreviewArguments {
    enum BuildMode: Equatable { case shipping, hostProbe, isolatedPreview }
    struct Options: Equatable, Sendable {
        let runID: String
        let contractPath: String
    }
    static let bundleID = "org.openlxssh.OpenLXSSH.EngineeringPreview"
    static let inputRoot = "/Users/liuwenshuo/Desktop/OpenLXSSH/DerivedData/UXPreview/Engineering-R2/Inputs"
    static func canonicalID(_ text: String) -> Bool {
        UUID(uuidString: text)?.uuidString.lowercased() == text
    }
    static func contractPath(runID: String) -> String { inputRoot + "/run-" + runID + "/preview-contract.txt" }
    static func parse(_ arguments: [String], mode: BuildMode) throws -> Options? {
        if mode != .isolatedPreview {
            guard !arguments.contains(where: { $0.hasPrefix("--isolated-preview") || $0.hasPrefix("--contract") }) else {
                throw EngineeringPreviewFailure.arguments
            }
            return nil
        }
        guard arguments.count == 3, arguments[0] == "--isolated-preview", arguments[1] == "--contract" else {
            throw EngineeringPreviewFailure.arguments
        }
        let path = arguments[2], prefix = inputRoot + "/run-", suffix = "/preview-contract.txt"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw EngineeringPreviewFailure.arguments }
        let id = String(path.dropFirst(prefix.count).dropLast(suffix.count))
        guard canonicalID(id), path == contractPath(runID: id) else { throw EngineeringPreviewFailure.arguments }
        return Options(runID: id, contractPath: path)
    }
    static func contractBytes(runID: String) -> Data {
        Data(("OpenLXSSH Engineering-R2 isolated preview v1\nrunID=" + runID + "\nmode=offline\nseed=none\n").utf8)
    }
}

#if PREVIEW_ISOLATED && HOST_PROBE
#error("PREVIEW_ISOLATED and HOST_PROBE are mutually exclusive")
#endif
#if PREVIEW_ISOLATED && !DEBUG
#error("Engineering preview is a Debug-only build")
#endif

#if PREVIEW_ISOLATED
/// FDs and identity snapshots are immutable. The lock protects only bounded public
/// diagnostic counters; it is not an authority or a replacement for on-disk checks.
final class EngineeringPreviewRoot: @unchecked Sendable {
    static let prefix = "OpenLXSSH-EngineeringPreview-R2-"
    static let markerName = ".openlxssh-engineering-preview-r2"
    let runID: String
    let url: URL
    let localURL: URL
    private let parentFD: Int32
    private let rootFD: Int32
    private let markerFD: Int32
    private let localFD: Int32
    private let parentIdentity: Identity
    private let rootIdentity: Identity
    private let markerIdentity: Identity
    private let localIdentity: Identity
    private let markerBytes: Data
    private let lock = NSLock()
    private var admissionCount = 0
    private var databaseOpenedURL: URL?
    struct Facts: Sendable { let admissions: Int; let databaseURL: URL? }
    private struct Identity: Equatable, Sendable {
        let device: dev_t
        let inode: ino_t
        init(_ value: stat) { device = value.st_dev; inode = value.st_ino }
    }
    private init(runID: String, url: URL, parent: Int32, root: Int32, marker: Int32, local: Int32,
                 parentIdentity: Identity, rootIdentity: Identity, markerIdentity: Identity, localIdentity: Identity) {
        self.runID = runID; self.url = url; localURL = url.appendingPathComponent("LocalPreview", isDirectory: true)
        parentFD = parent; rootFD = root; markerFD = marker; localFD = local
        self.parentIdentity = parentIdentity; self.rootIdentity = rootIdentity
        self.markerIdentity = markerIdentity; self.localIdentity = localIdentity
        markerBytes = EngineeringPreviewArguments.contractBytes(runID: runID)
    }
    deinit { Darwin.close(localFD); Darwin.close(markerFD); Darwin.close(rootFD); Darwin.close(parentFD) }

    /// confstr is supplied by Darwin, not a caller-controlled HOME/TMPDIR override.
    static func temporaryBase() throws -> URL {
        let count = confstr(_CS_DARWIN_USER_TEMP_DIR, nil, 0)
        guard count > 1, count <= 32768 else { throw EngineeringPreviewFailure.unsafeStorage }
        var bytes = [CChar](repeating: 0, count: count)
        guard confstr(_CS_DARWIN_USER_TEMP_DIR, &bytes, count) == count else { throw EngineeringPreviewFailure.unsafeStorage }
        let path = bytes.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        return try AppDataLocation.canonical(URL(fileURLWithPath: path, isDirectory: true))
    }
    static func createFresh(runID: String) throws -> EngineeringPreviewRoot {
        guard EngineeringPreviewArguments.canonicalID(runID) else { throw EngineeringPreviewFailure.arguments }
        let base = try temporaryBase(), name = prefix + runID
        let parent = open(base.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard parent >= 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        var root: Int32 = -1, marker: Int32 = -1, local: Int32 = -1, transferred = false
        defer {
            if !transferred {
                if local >= 0 { Darwin.close(local) }; if marker >= 0 { Darwin.close(marker) }
                if root >= 0 { Darwin.close(root) }; Darwin.close(parent)
            }
        }
        try AppFileSecurity.directory(parent)
        let parentIdentity = try identity(parent)
        // Never adopt even our own previous root, never chmod or remove unknown paths.
        guard mkdirat(parent, name, 0o700) == 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        root = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard root >= 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        try AppFileSecurity.directory(root)
        let rootIdentity = try identity(root)
        try requireNamed(name, parent: parent, held: root, expected: rootIdentity)
        marker = openat(root, markerName, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard marker >= 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        try AppFileSecurity.regularFile(marker)
        let payload = EngineeringPreviewArguments.contractBytes(runID: runID)
        var offset = 0
        while offset < payload.count {
            let written = payload.withUnsafeBytes { Darwin.write(marker, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if written < 0 && errno == EINTR { continue }
            guard written > 0 else { throw EngineeringPreviewFailure.unsafeStorage }; offset += written
        }
        guard fsync(marker) == 0, mkdirat(root, "LocalPreview", 0o700) == 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        local = openat(root, "LocalPreview", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard local >= 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        try AppFileSecurity.directory(local)
        let value = EngineeringPreviewRoot(runID: runID, url: base.appendingPathComponent(name, isDirectory: true),
            parent: parent, root: root, marker: marker, local: local, parentIdentity: parentIdentity,
            rootIdentity: rootIdentity, markerIdentity: try identity(marker), localIdentity: try identity(local))
        transferred = true // From this point a throwing validation is owned by value.deinit.
        try value.validate()
        return value
    }
    func validate() throws {
        try AppFileSecurity.directory(parentFD); try AppFileSecurity.directory(rootFD)
        try AppFileSecurity.regularFile(markerFD); try AppFileSecurity.directory(localFD)
        guard try Self.identity(parentFD) == parentIdentity else { throw EngineeringPreviewFailure.unsafeStorage }
        let namedParent = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard namedParent >= 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        defer { Darwin.close(namedParent) }
        guard try Self.identity(namedParent) == parentIdentity else { throw EngineeringPreviewFailure.unsafeStorage }
        try Self.requireNamed(Self.prefix + runID, parent: parentFD, held: rootFD, expected: rootIdentity)
        try Self.requireNamed(Self.markerName, parent: rootFD, held: markerFD, expected: markerIdentity)
        try Self.requireNamed("LocalPreview", parent: rootFD, held: localFD, expected: localIdentity)
        guard try Self.readStable(markerFD, maximum: 512) == markerBytes else { throw EngineeringPreviewFailure.unsafeStorage }
        lock.withLock { admissionCount += 1 }
    }
    func databaseDirectory() throws -> URL {
        try validate()
        return url.appendingPathComponent("Data", isDirectory: true)
    }
    func validateLocalBoundary() throws { try validate() }
    func displayPath() throws -> String { try validate(); return url.path }
    func recordDatabaseOpen(_ actual: URL) throws {
        try validate()
        guard actual.isFileURL else { throw EngineeringPreviewFailure.unsafeStorage }
        // Core's Foundation URL normalization may spell Darwin's physical
        // /private/var tree as /var. Compare the exact real path, without opening
        // another SQLite descriptor (which could disturb its POSIX locks).
        let physical = try AppDataLocation.canonical(actual)
        guard physical.path == url.appendingPathComponent("Data/OpenLXSSH.sqlite").path else { throw EngineeringPreviewFailure.unsafeStorage }
        lock.withLock { databaseOpenedURL = URL(fileURLWithPath: physical.path, isDirectory: false) }
    }
    var facts: Facts { lock.withLock { Facts(admissions: admissionCount, databaseURL: databaseOpenedURL) } }

    private static func identity(_ fd: Int32) throws -> Identity {
        var value = stat()
        guard fstat(fd, &value) == 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        return Identity(value)
    }
    private static func requireNamed(_ name: String, parent: Int32, held: Int32, expected: Identity) throws {
        var named = stat()
        guard fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_mode & S_IFMT != S_IFLNK, Identity(named) == expected,
              try identity(held) == expected else { throw EngineeringPreviewFailure.unsafeStorage }
    }
    static func readStable(_ fd: Int32, maximum: Int) throws -> Data {
        try AppFileSecurity.regularFile(fd)
        var before = stat(), after = stat()
        guard fstat(fd, &before) == 0, before.st_size > 0, before.st_size <= off_t(maximum) else { throw EngineeringPreviewFailure.contract }
        var bytes = [UInt8](repeating: 0, count: maximum + 1), offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { pread(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset, off_t(offset)) }
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw EngineeringPreviewFailure.contract }
            if count == 0 { break }; offset += count
        }
        try AppFileSecurity.regularFile(fd)
        guard fstat(fd, &after) == 0, Identity(before) == Identity(after),
              before.st_size == after.st_size, off_t(offset) == before.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw EngineeringPreviewFailure.contract
        }
        return Data(bytes.prefix(offset))
    }
}

/// Opens a single fixed public contract, holding every no-follow ancestor through
/// the bounded read. Private policy begins at Engineering-R2, not at system /Users.
enum EngineeringPreviewContract {
    static func validate(_ payload: Data, runID: String) throws {
        guard EngineeringPreviewArguments.canonicalID(runID), payload.count <= 512,
              payload == EngineeringPreviewArguments.contractBytes(runID: runID) else { throw EngineeringPreviewFailure.contract }
    }
    static func load(_ options: EngineeringPreviewArguments.Options) throws {
        let reparsed = try EngineeringPreviewArguments.parse(["--isolated-preview", "--contract", options.contractPath], mode: .isolatedPreview)
        guard reparsed == options else { throw EngineeringPreviewFailure.contract }
        let components = options.contractPath.split(separator: "/").map(String.init)
        var held: [(Int32, String, Int32)] = [], descriptors: [Int32] = []
        let first = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard first >= 0 else { throw EngineeringPreviewFailure.contract }
        descriptors.append(first)
        defer { for fd in descriptors.reversed() { Darwin.close(fd) } }
        var parent = first, privateTail = false
        for component in components.dropLast() {
            let child = openat(parent, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard child >= 0 else { throw EngineeringPreviewFailure.contract }
            descriptors.append(child); held.append((parent, component, child))
            if component == "Engineering-R2" { privateTail = true }
            if privateTail { try AppFileSecurity.directory(child) }
            else {
                var info = stat()
                guard fstat(child, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                      info.st_uid == 0 || info.st_uid == geteuid(), info.st_mode & 0o022 == 0 else {
                    throw EngineeringPreviewFailure.contract
                }
            }
            parent = child
        }
        let file = openat(parent, "preview-contract.txt", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard file >= 0 else { throw EngineeringPreviewFailure.contract }
        descriptors.append(file); held.append((parent, "preview-contract.txt", file))
        let payload = try EngineeringPreviewRoot.readStable(file, maximum: 512)
        try validate(payload, runID: options.runID)
        for (owner, name, fd) in held {
            var named = stat(), opened = stat()
            guard fstatat(owner, name, &named, AT_SYMLINK_NOFOLLOW) == 0, fstat(fd, &opened) == 0,
                  named.st_dev == opened.st_dev, named.st_ino == opened.st_ino,
                  named.st_mode & S_IFMT != S_IFLNK else { throw EngineeringPreviewFailure.contract }
        }
        // Check the complete tail again after reading, not only before decoding.
        for fd in descriptors.suffix(4).dropLast() { try AppFileSecurity.directory(fd) }
        try AppFileSecurity.regularFile(file)
    }
}
#endif
