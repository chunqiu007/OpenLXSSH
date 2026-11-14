import Darwin
import Foundation

#if LOCAL_CANDIDATE && (!DEBUG || HOST_PROBE || PREVIEW_ISOLATED)
#error("LOCAL_CANDIDATE requires Debug and excludes HostProbe and the offline preview")
#endif

#if LOCAL_CANDIDATE
/// Prepared local candidates retain their strict temporary-root contract.
/// Explicit portable trials create a clean private root once and reuse it across launches.
struct LocalCandidateBootstrap: Sendable {
    enum Failure: Error { case metadata, storage }
    static let schemaKey = "OpenLXSSHLocalCandidateSchema"
    static let namespaceKey = "OpenLXSSHLocalCandidateNamespace"
    static let bundlePrefix = "org.openlxssh.OpenLXSSH.LocalCandidate."
    static let rootPrefix = "OpenLXSSH-AppSmoke-LocalCandidate-"
    static let markerName = ".openlxssh-local-candidate"
    static let trialStorageKey = "OpenLXSSHTrialStorage"
    static let trialStorageValue = "application-support-v1"
    static let trialDirectoryName = "OpenLXSSH Trial"
    let namespace: UUID
    let root: URL
    private let trialSupport: URL?
    var isPortableTrial: Bool { trialSupport != nil }
    var location: AppDataLocation { isPortableTrial ? .localTrial(self) : .isolated(root) }
    private init(namespace: UUID, root: URL, trialSupport: URL? = nil) {
        self.namespace = namespace; self.root = root; self.trialSupport = trialSupport
    }

    static func namespace(bundleID: String?, schema: Any?, value: Any?, arguments: [String]) throws -> UUID {
        guard arguments.isEmpty, schema as? String == "1", let text = value as? String,
              let id = UUID(uuidString: text), id.uuidString.lowercased() == text,
              bundleID == bundlePrefix + text else { throw Failure.metadata }
        return id
    }
    static func rootURL(namespace: UUID) throws -> URL {
        let count = confstr(_CS_DARWIN_USER_TEMP_DIR, nil, 0)
        guard count > 1, count <= 32768 else { throw Failure.storage }
        var bytes = [CChar](repeating: 0, count: count)
        guard confstr(_CS_DARWIN_USER_TEMP_DIR, &bytes, count) == count else { throw Failure.storage }
        let path = bytes.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        return try AppDataLocation.canonical(URL(fileURLWithPath: path, isDirectory: true))
            .appendingPathComponent(rootPrefix + namespace.uuidString.lowercased(), isDirectory: true)
    }
    static func markerBytes(namespace: UUID) -> Data {
        Data(("OpenLXSSH local experience candidate v1\nnamespace=" + namespace.uuidString.lowercased() + "\n").utf8)
    }
    static func load(bundle: Bundle = .main, arguments: [String]) throws -> Self {
        try load(bundleID: bundle.bundleIdentifier, schema: bundle.object(forInfoDictionaryKey: schemaKey),
                 value: bundle.object(forInfoDictionaryKey: namespaceKey),
                 trialStorage: bundle.object(forInfoDictionaryKey: trialStorageKey), arguments: arguments)
    }
    static func load(bundleID: String?, schema: Any?, value: Any?, trialStorage: Any? = nil, arguments: [String]) throws -> Self {
        let id = try namespace(bundleID: bundleID, schema: schema, value: value, arguments: arguments)
        if try portableStorage(trialStorage) {
            guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { throw Failure.storage }
            return try loadPortable(namespace: id, supportDirectory: support)
        }
        let root = try rootURL(namespace: id)
        try validateRoot(root, expected: markerBytes(namespace: id))
        let result = Self(namespace: id, root: root)
        _ = try result.location.databaseDirectory()
        return result
    }
    static func portableStorage(_ value: Any?) throws -> Bool {
        guard let value else { return false }
        guard value as? String == trialStorageValue else { throw Failure.metadata }
        return true
    }
    private static func validateRoot(_ root: URL, expected: Data) throws {
        let directory = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else { throw Failure.storage }
        defer { Darwin.close(directory) }
        try AppFileSecurity.directory(directory)
        let marker = openat(directory, markerName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard marker >= 0 else { throw Failure.storage }
        defer { Darwin.close(marker) }
        try AppFileSecurity.regularFile(marker)
        var before = stat(), after = stat(), actual = Data(count: expected.count + 1), offset = 0
        guard fstat(marker, &before) == 0 else { throw Failure.storage }
        while offset < actual.count {
            let count = actual.withUnsafeMutableBytes { pread(marker, $0.baseAddress!.advanced(by: offset), $0.count - offset, off_t(offset)) }
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw Failure.storage }
            if count == 0 { break }; offset += count
        }
        guard actual.prefix(offset) == expected, fstat(marker, &after) == 0,
              before.st_size == off_t(expected.count), before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw Failure.storage }
        try AppFileSecurity.regularFile(marker)
        var named = stat(), held = stat()
        guard lstat(root.path, &named) == 0, fstat(directory, &held) == 0,
              named.st_mode & S_IFMT == S_IFDIR, named.st_dev == held.st_dev, named.st_ino == held.st_ino,
              fstatat(directory, markerName, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_mode & S_IFMT == S_IFREG, named.st_dev == after.st_dev, named.st_ino == after.st_ino else { throw Failure.storage }
        let local = openat(directory, "LocalFilesFixture", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard local >= 0 else { throw Failure.storage }
        defer { Darwin.close(local) }
        try AppFileSecurity.directory(local)
    }
    /// The production caller derives Application Support from Foundation. This internal
    /// seam permits isolated tests without a startup argument or environment override.
    static func loadPortable(namespace: UUID, supportDirectory: URL) throws -> Self {
        guard supportDirectory.isFileURL else { throw Failure.storage }
        let support = try AppDataLocation.canonical(supportDirectory)
        let parent = open(support.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard parent >= 0 else { throw Failure.storage }
        defer { Darwin.close(parent) }
        try AppFileSecurity.applicationSupportParent(parent)
        if mkdirat(parent, trialDirectoryName, 0o700) != 0 && errno != EEXIST { throw Failure.storage }
        let trials = openat(parent, trialDirectoryName, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard trials >= 0 else { throw Failure.storage }
        defer { Darwin.close(trials) }
        try AppFileSecurity.directory(trials)
        try requireNamed(trialDirectoryName, parent: parent, held: trials)
        let name = namespace.uuidString.lowercased()
        var info = stat()
        if fstatat(trials, name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw Failure.storage }
            try createPortable(namespace: namespace, in: trials)
        }
        let root = support.appendingPathComponent(trialDirectoryName, isDirectory: true).appendingPathComponent(name, isDirectory: true)
        let result = Self(namespace: namespace, root: root, trialSupport: support)
        _ = try result.trialDatabaseDirectory()
        return result
    }
    private static func trialMarkerBytes(namespace: UUID) -> Data {
        Data(("OpenLXSSH portable trial v1\nnamespace=" + namespace.uuidString.lowercased() + "\n").utf8)
    }
    private static func createPortable(namespace: UUID, in parent: Int32) throws {
        // Publish a complete empty root atomically. Interrupted initialization never
        // makes an incomplete final root eligible for repair or silent adoption.
        let stagingName = ".initializing-" + UUID().uuidString.lowercased()
        guard mkdirat(parent, stagingName, 0o700) == 0 else { throw Failure.storage }
        let staging = openat(parent, stagingName, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard staging >= 0 else { throw Failure.storage }
        var local: Int32 = -1, marker: Int32 = -1, published = false
        defer {
            if !published {
                if marker >= 0 { removeOwned(markerName, parent: staging, held: marker, directory: false) }
                if local >= 0 { removeOwned("LocalFilesFixture", parent: staging, held: local, directory: true) }
                removeOwned(stagingName, parent: parent, held: staging, directory: true)
            }
            if marker >= 0 { Darwin.close(marker) }; if local >= 0 { Darwin.close(local) }; Darwin.close(staging)
        }
        try AppFileSecurity.directory(staging)
        try requireNamed(stagingName, parent: parent, held: staging)
        guard mkdirat(staging, "LocalFilesFixture", 0o700) == 0 else { throw Failure.storage }
        local = openat(staging, "LocalFilesFixture", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard local >= 0 else { throw Failure.storage }
        try AppFileSecurity.directory(local)
        marker = openat(staging, markerName, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard marker >= 0 else { throw Failure.storage }
        try AppFileSecurity.regularFile(marker)
        let bytes = trialMarkerBytes(namespace: namespace)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(marker, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw Failure.storage }; offset += count
        }
        guard fsync(marker) == 0, fsync(staging) == 0 else { throw Failure.storage }
        try requireNamed(markerName, parent: staging, held: marker)
        try requireNamed("LocalFilesFixture", parent: staging, held: local)
        try requireNamed(stagingName, parent: parent, held: staging)
        let name = namespace.uuidString.lowercased()
        if renameatx_np(parent, stagingName, parent, name, UInt32(RENAME_EXCL)) == 0 { published = true }
        else if errno != EEXIST { throw Failure.storage }
        guard fsync(parent) == 0 else { throw Failure.storage }
    }
    private static func requireNamed(_ name: String, parent: Int32, held: Int32) throws {
        var named = stat(), opened = stat()
        guard fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0, fstat(held, &opened) == 0,
              named.st_dev == opened.st_dev, named.st_ino == opened.st_ino,
              named.st_mode & S_IFMT == opened.st_mode & S_IFMT else { throw Failure.storage }
    }
    private static func removeOwned(_ name: String, parent: Int32, held: Int32, directory: Bool) {
        do { try requireNamed(name, parent: parent, held: held) } catch { return }
        _ = unlinkat(parent, name, directory ? AT_REMOVEDIR : 0)
    }
    func trialDatabaseDirectory() throws -> URL {
        guard let support = trialSupport,
              root == support.appendingPathComponent(Self.trialDirectoryName, isDirectory: true)
                .appendingPathComponent(namespace.uuidString.lowercased(), isDirectory: true) else { throw Failure.storage }
        let parent = open(support.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard parent >= 0 else { throw Failure.storage }
        defer { Darwin.close(parent) }
        try AppFileSecurity.applicationSupportParent(parent)
        let trials = openat(parent, Self.trialDirectoryName, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard trials >= 0 else { throw Failure.storage }
        defer { Darwin.close(trials) }
        try AppFileSecurity.directory(trials)
        try Self.requireNamed(Self.trialDirectoryName, parent: parent, held: trials)
        let directory = openat(trials, namespace.uuidString.lowercased(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else { throw Failure.storage }
        defer { Darwin.close(directory) }
        try AppFileSecurity.directory(directory)
        try Self.requireNamed(namespace.uuidString.lowercased(), parent: trials, held: directory)
        try Self.validateRoot(root, expected: Self.trialMarkerBytes(namespace: namespace))
        var namedSupport = stat(), heldSupport = stat(), namedRoot = stat(), heldRoot = stat()
        guard lstat(support.path, &namedSupport) == 0, fstat(parent, &heldSupport) == 0,
              namedSupport.st_dev == heldSupport.st_dev, namedSupport.st_ino == heldSupport.st_ino,
              lstat(root.path, &namedRoot) == 0, fstat(directory, &heldRoot) == 0,
              namedRoot.st_dev == heldRoot.st_dev, namedRoot.st_ino == heldRoot.st_ino else { throw Failure.storage }
        return root.appendingPathComponent("Data", isDirectory: true)
    }
    @MainActor func makeModel(preferencesDefaults: UserDefaults? = .standard) -> AppModel {
        let repository = AppRepository(location: location)
        let security = SecurityCoordinator(repository: repository, location: location, credentials: SystemCredentials(testNamespace: namespace))
        return AppModel(repository: repository, security: security, location: location, preferencesDefaults: preferencesDefaults)
    }
    var dataDescription: String {
        let introduction = isPortableTrial
            ? "跨机试用版：使用真实连接与文件传输功能。\n配置、密钥副本、信任及恢复记录独立保存在：\n"
            : "本地体验候选：使用真实连接与文件传输功能。\n本轮配置、密钥副本、信任及恢复记录：\n"
        let persistence = isPortableTrial
            ? "窗口与界面偏好属于此试用版的独立 bundle。退出和重新安装不会清空试用数据；不读取旧安装的数据，也不自动恢复连接。"
            : "窗口与界面偏好属于此候选的独立 bundle。重开保留本轮配置，不自动恢复连接；临时数据可能被系统清理。"
        let credentialScope = isPortableTrial ? "\n\n记住的凭据使用此试用版的独立命名空间：\n" : "\n\n记住的凭据仅使用本轮测试命名空间：\n"
        return introduction + root.path + credentialScope + "org.openlxssh.credentials.test." + namespace.uuidString +
        "\n\n" + persistence
    }
}
#endif
