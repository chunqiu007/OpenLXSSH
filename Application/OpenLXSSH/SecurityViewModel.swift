import AppKit
import Combine
import CryptoKit
import Foundation
import OpenLXSSHCore
import OpenLXSSHSecurity
import OpenLXSSHTrust

extension AppIssue {
    static func security(_ error: Error) -> AppIssue {
        if error is JournalWriteFailure { return security(SecurityUIFailure.journal) }
        if error is AppStorageFailure { return .sanitized(error) }
        if let repository = error as? RepositoryError { return .sanitized(repository) }
        if let failure = error as? KeyOperationFailure { return security(SecurityUIFailure.key(failure.primary)) }
        if let failure = error as? KeyFailure { return security(SecurityUIFailure.key(failure)) }
        guard let error = error as? SecurityUIFailure else {
            return AppIssue(code: "security.failed", message: "安全资源操作失败。未展示系统详细错误或秘密，请重试或取消。")
        }
        switch error {
        case .credential(let reason):
            let code: String
            switch reason {
            case .cancelled: code = "cancelled"
            case .denied, .interactionNotAllowed: code = "lockedOrDenied"
            case .duplicate: code = "duplicate"
            default: code = "unavailable"
            }
            return AppIssue(code: "keychain." + code, message: "本机 Keychain 未能完成操作。不会降级到明文保存；可取消“记住”，保存不含密码的主机配置，连接时人工输入。若为口令保存失败，可取消记住口令后重新导入/生成。")
        case .key(let reason):
            let message: String
            switch reason {
            case .passphraseRequired: message = "该私钥已加密，请输入正确口令后重试，或取消。"
            case .keygenRejected, .invalidPassphraseInput: message = "私钥或口令未通过系统 ssh-keygen 校验。请检查口令后重试，或取消；源文件未改动。"
            case .duplicateKey: message = "该密钥 UUID 已存在，未覆盖已有文件。"
            case .unsafePermissions, .symbolicLinkOrEscape: message = "私钥文件或目录权限、扩展 ACL／类型不安全或无法核验，操作已拒绝。请自行核实源文件及 App 专属副本；仅 chmod 不能移除 ACL，App 不会静默修改 ACL。"
            case .cancelled: message = "密钥操作已取消。未提交配置的文件按精确 UUID 清理，失败项可重试。"
            default: message = "密钥操作失败。仅支持标准 OpenSSH 格式 RSA/Ed25519 私钥；源文件不会被修改。"
            }
            return AppIssue(code: "key.operationFailed", message: message)
        case .busy: return AppIssue(code: "security.busy", message: "安全资源正在处理，请稍后重试。")
        case .journal: return AppIssue(code: "security.recoveryUnavailable", message: "安全恢复目录／记录的权限、扩展 ACL 或类型不安全／无法核验。已停止创建与清理；请核实专属目录权限，App 不会静默删除 ACL、扫描用户文件或绕过恢复校验。")
        case .notAuthorized: return AppIssue(code: "credential.notAuthorized", message: "保存秘密需要明确授权和非空输入。OTP 不可保存。")
        case .pendingCleanup: return AppIssue(code: "security.cleanupPending", message: "配置已更新，但精确资源清理尚未完成。请在密钥与凭据管理中重试清理。")
        case .preparedIntent: return AppIssue(code: "security.uncertainIntent", message: "上次操作在确认创建前中断；记录不证明资源存在或归属，不能自动删除外部资源。可核对并仅丢弃非秘密恢复记录。")
        case .staleRecoveryReview: return AppIssue(code: "security.staleRecoveryReview", message: "恢复记录或关联已变化，此确认已失效。请刷新并重新核对；未删除任何文件或 Keychain 项目。")
        }
    }
}

@MainActor final class SecurityViewModel: ObservableObject {
    let coordinator: SecurityCoordinator
    @Published private(set) var metadata = SecurityMetadata(hosts: [], keys: [], credentials: [], tickets: [])
    @Published private(set) var publicKeys: [UUID: String] = [:]
    @Published private(set) var fingerprints: [UUID: String] = [:]
    @Published private(set) var publicKeyBits: [UUID: Int] = [:]
    @Published private(set) var pendingCount = 0
    @Published private(set) var uncertainCount = 0
    @Published private(set) var recoveryReviews: [RecoveryReview] = []
    @Published private(set) var lastCreatedKey: KeyCreationOutcome?
    @Published private(set) var lastCreatedKeyLabel = ""
    @Published private(set) var busy = false
    @Published var issue: AppIssue?
    @Published var copied = false
    @Published private(set) var copyNotice: String?
    private var loadGeneration: UInt64 = 0
    private var copyTask: Task<Void, Never>?
    init(coordinator: SecurityCoordinator) { self.coordinator = coordinator }
    func load() async {
        loadGeneration &+= 1
        let generation = loadGeneration
        do {
            let overview = try await coordinator.overview()
            var values: [UUID: String] = [:], prints: [UUID: String] = [:], bits: [UUID: Int] = [:]
            for key in overview.metadata.keys {
                if let value = try? await coordinator.publicKey(key.id) {
                    values[key.id] = value.copyString
                    if let info = Self.publicInformation(value.copyString) { prints[key.id] = info.fingerprint; bits[key.id] = info.bits }
                }
            }
            guard generation == loadGeneration else { return }
            metadata = overview.metadata; pendingCount = overview.pendingCount; uncertainCount = overview.uncertainCount
            recoveryReviews = overview.recoveryReviews
            publicKeys = values; fingerprints = prints; publicKeyBits = bits
        } catch { if generation == loadGeneration { issue = .security(error) } }
    }
    func label(for key: ManagedKeyReference) -> String { key.label.isEmpty ? key.algorithm.rawValue.uppercased() + " · " + key.id.uuidString.prefix(8) : key.label }
    func hostReferences(_ keyID: UUID) -> [HostConfiguration] { metadata.hosts.filter { $0.keyRef == keyID } }
    func filteredKeys(search: String, descending: Bool = false) -> [ManagedKeyReference] {
        let needle = search.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "en_US_POSIX"))
        return metadata.keys.filter { key in
            needle.isEmpty || [label(for: key), key.algorithm.rawValue, fingerprints[key.id] ?? ""].contains {
                $0.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "en_US_POSIX")).contains(needle)
            }
        }.sorted { left, right in
            let a = label(for: left).folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "en_US_POSIX"))
            let b = label(for: right).folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "en_US_POSIX"))
            if a != b { return descending ? a > b : a < b }
            return left.id.uuidString < right.id.uuidString
        }
    }
    func updateLabel(_ keyID: UUID, label: String) async -> Bool {
        guard !busy else { return false }
        busy = true; defer { busy = false }
        do {
            try await coordinator.repository.updateKeyLabel(keyID: keyID, label: label)
            issue = nil
        } catch is AppStorageFailure {
            // The label transaction has committed even if its post-commit access check
            // failed. Do not present the old label or invite another resource creation.
            issue = .sanitized(AppStorageFailure.committedStorageUnsafe)
        } catch { issue = .security(error); await load(); return false }
        if lastCreatedKey?.id == keyID { lastCreatedKeyLabel = label }
        await load()
        return true
    }
    /// Metadata only. The confirmation must explicitly explain the change to password authentication;
    /// no password is introduced and no key/credential is deleted by unlinking these hosts.
    func unlinkKey(_ keyID: UUID, hostIDs: Set<UUID>) async -> Bool {
        await perform {
            let current = try await coordinator.repository.securityMetadata()
            let hosts = current.hosts.filter { hostIDs.contains($0.id) }
            guard hosts.count == hostIDs.count, hosts.allSatisfy({ $0.keyRef == keyID }) else { throw RepositoryError.notFound }
            let changes: [RepositoryChange] = hosts.map { source in
                var host = source
                host.keyRef = nil; host.authentication = .passwordWithMFA
                host.credentialRef = nil; host.savePasswordAuthorized = false
                return .updateHostIfUnchanged(host, expected: .init(host: source))
            }
            try await coordinator.repository.apply(changes)
        }
    }
    /// Hash only the validated public SSH blob. This is display metadata, never private-key parsing.
    static func publicInformation(_ text: String) -> (fingerprint: String, bits: Int)? {
        guard (try? PublicKey(text)) != nil,
              let encoded = text.split(separator: " ").last, let blob = Data(base64Encoded: String(encoded)) else { return nil }
        let digest = Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
        var offset = 0
        func field() -> Data? {
            guard offset + 4 <= blob.count else { return nil }
            let count = blob[offset..<(offset + 4)].reduce(0) { ($0 << 8) | Int($1) }
            offset += 4
            guard count >= 0, count <= blob.count - offset else { return nil }
            defer { offset += count }
            return Data(blob[offset..<(offset + count)])
        }
        guard let algorithm = field() else { return nil }
        if String(data: algorithm, encoding: .utf8) == "ssh-ed25519" { return ("SHA256:" + digest, 256) }
        guard field() != nil, let modulus = field(), let first = modulus.first(where: { $0 != 0 }) else { return nil }
        let significant = modulus.drop(while: { $0 == 0 })
        return ("SHA256:" + digest, (significant.count - 1) * 8 + (8 - first.leadingZeroBitCount))
    }
    @discardableResult func perform(_ operation: () async throws -> Void) async -> Bool {
        guard !busy else { return false }
        busy = true; defer { busy = false }
        do { try await operation(); issue = nil; await load(); return true }
        catch { issue = .security(error); await load(); return false }
    }
    func clearCreationResult() { lastCreatedKey = nil; lastCreatedKeyLabel = "" }
    /// Return the committed result directly to its editor, never infer it from a later
    /// global lastCreatedKey after another presentation may have started.
    func createKey(_ creation: KeyCreation, protection: KeyProtection, remember: SecretBytes?) async -> KeyCreationOutcome? {
        guard !busy else { return nil }
        busy = true; clearCreationResult()
        defer { busy = false }
        do {
            let outcome = try await coordinator.createKey(creation, protection: protection, rememberPassphrase: remember)
            lastCreatedKey = outcome
            issue = outcome.cleanupPending ? AppIssue(code: "security.keyCommittedCleanupPending", message: "密钥已创建并保存配置；仅恢复记录清理待重试。请勿重复生成/导入，在管理页重试精确清理即可。") : nil
            await load()
            return outcome
        } catch { issue = .security(error); await load(); return nil }
    }
    func create(_ creation: KeyCreation, protection: KeyProtection, remember: SecretBytes?) async -> Bool {
        await createKey(creation, protection: protection, remember: remember) != nil
    }
    func publishCreatedKey(_ outcome: KeyCreationOutcome, label: String) {
        lastCreatedKey = outcome; lastCreatedKeyLabel = label
    }
    func forgetKeyPassphrase(_ id: UUID) async -> Bool {
        guard !busy else { return false }
        busy = true; defer { busy = false }
        do {
            let outcome = try await coordinator.forgetKeyPassphrase(id)
            issue = nil
            if case .savedWithCleanupPending = outcome { issue = .security(SecurityUIFailure.pendingCleanup) }
            await load(); return true
        } catch { issue = .security(error); await load(); return false }
    }
    func discardPrepared(_ review: RecoveryReview) async -> Bool {
        await perform { try await coordinator.discardPreparedRecord(review) }
    }
    func deleteKey(_ id: UUID) async -> Bool { await perform { try await coordinator.deleteKey(id) } }
    func forget(_ id: UUID) async -> Bool { await perform { try await coordinator.forgetHostPassword(id) } }
    func deleteCredential(_ id: UUID) async -> Bool { await perform { try await coordinator.deleteUnusedCredential(id) } }
    func retry() async { _ = await perform { try await coordinator.retryCleanup() } }
    func copyPublicKey(_ id: UUID, to pasteboard: NSPasteboard = .general) -> Bool {
        guard let text = publicKeys[id], !text.contains("PRIVATE") else {
            issue = .security(SecurityUIFailure.key(.missing)); return false
        }
        return copyPublicMetadata(text, notice: "公钥已复制。", to: pasteboard)
    }
    func copyFingerprint(_ id: UUID, to pasteboard: NSPasteboard = .general) -> Bool {
        guard let value = fingerprints[id] else { issue = .security(SecurityUIFailure.key(.missing)); return false }
        return copyPublicMetadata(value, notice: "公钥指纹已复制。", to: pasteboard)
    }
    private func copyPublicMetadata(_ text: String, notice: String, to pasteboard: NSPasteboard) -> Bool {
        pasteboard.clearContents()
        copied = pasteboard.setString(text, forType: .string)
        if !copied { issue = AppIssue(code: "publicKey.copyFailed", message: "无法写入系统剪贴板；未复制任何私钥或秘密。") }
        else {
            copyTask?.cancel(); copyNotice = notice
            copyTask = Task { [weak self] in
                try? await Task.sleep(for: .seconds(3))
                if !Task.isCancelled { self?.copied = false; self?.copyNotice = nil }
            }
        }
        return copied
    }
}

/// Public label editing has its own selection epoch, separate from background security work.
/// An A -> B -> A switch or new typing cannot be overwritten by A's suspended save callback.
@MainActor final class KeyLabelSelectionModel: ObservableObject {
    struct Save: Equatable {
        let keyID: UUID
        let label: String
        fileprivate let epoch: UUID
        fileprivate let draftEpoch: UUID
    }
    @Published private(set) var selectedKeyID: UUID?
    @Published private(set) var labelDraft = ""
    private var epoch = UUID()
    private var draftEpoch = UUID()
    private var baseline = ""
    func select(_ key: ManagedKeyReference) { select(id: key.id, label: key.label) }
    func select(id: UUID, label: String) {
        epoch = UUID(); draftEpoch = UUID(); selectedKeyID = id; labelDraft = label; baseline = label
    }
    func edit(_ value: String) { draftEpoch = UUID(); labelDraft = value }
    func captureSave() -> Save? { selectedKeyID.map { Save(keyID: $0, label: labelDraft, epoch: epoch, draftEpoch: draftEpoch) } }
    func complete(_ save: Save, succeeded: Bool) {
        guard succeeded, selectedKeyID == save.keyID, epoch == save.epoch else { return }
        baseline = save.label
        if draftEpoch == save.draftEpoch { labelDraft = save.label }
    }
    var hasChanges: Bool { labelDraft != baseline }
}

/// Per-editor non-secret completion state. Once Core commits, submit only retries the
/// label on that immutable UUID. It can never re-enter generation/import in this editor.
@MainActor final class KeyCreationEditorState: ObservableObject {
    @Published private(set) var created: KeyCreationOutcome?
    @Published private(set) var savedLabel = ""
    @Published private(set) var labelPending = false
    @Published private(set) var busy = false
    @Published private(set) var active = true
    private var epoch = UUID()

    func close() { active = false; epoch = UUID() }
    func submit(model: SecurityViewModel, creation: KeyCreation, protection: KeyProtection, remember: SecretBytes?,
                label: String, ownsPresentation: @MainActor () -> Bool) async -> Bool {
        guard active, !busy, !model.busy, ownsPresentation(), !Task.isCancelled else { return false }
        let owner = epoch
        busy = true; defer { busy = false }
        if created == nil {
            guard let outcome = await model.createKey(creation, protection: protection, remember: remember) else { return false }
            // Keep the exact committed result even if this editor was closed while awaiting.
            // Do not begin a label write or publish UI selection for an expired owner.
            created = outcome
            guard active, epoch == owner, ownsPresentation(), !Task.isCancelled else { return false }
        }
        guard let outcome = created, active, epoch == owner, ownsPresentation(), !Task.isCancelled else { return false }
        if label == savedLabel { labelPending = false; return true }
        labelPending = true
        let saved = await model.updateLabel(outcome.id, label: label)
        guard active, epoch == owner, ownsPresentation(), !Task.isCancelled else { return false }
        if saved {
            savedLabel = label; labelPending = false
            if outcome.cleanupPending { model.issue = .security(SecurityUIFailure.pendingCleanup) }
        } else {
            // load() intentionally preserves issue. Explain the committed-key distinction
            // here rather than claiming that a metadata refresh erased the original error.
            model.issue = AppIssue(code: "key.labelPending", message: "密钥已创建，但公开标签未保存。可只重试此密钥的标签，或保留已创建密钥并完成；不会再次生成或导入，也不会修改其他密钥。")
        }
        return saved
    }
    func publishCompletion(to model: SecurityViewModel, ownsPresentation: @MainActor () -> Bool) -> Bool {
        guard active, !busy, ownsPresentation(), let created else { return false }
        model.publishCreatedKey(created, label: savedLabel)
        return true
    }
}

/// A management-only adapter over the one authoritative App trust store. Tests can suspend
/// individual calls while still forwarding every read/write to an isolated HostTrustStore.
protocol TrustManagementStoring: Sendable {
    func records() async throws -> [TrustedHostKey]
    func prepareReplacement(host: HostIdentity, key: HostPublicKey, expectedCurrentFingerprint: String) async throws -> PendingTrustDecision
    func confirm(_ decision: PendingTrustDecision, displayedFingerprint: String) async throws
    func remove(_ expected: TrustedHostKey) async throws
    func cancel(_ decision: PendingTrustDecision) async
}

struct AppTrustManagementStore: TrustManagementStoring {
    let store: HostTrustStore
    func records() async throws -> [TrustedHostKey] { try await store.records() }
    func prepareReplacement(host: HostIdentity, key: HostPublicKey, expectedCurrentFingerprint: String) async throws -> PendingTrustDecision {
        try await store.prepareReplacement(host: host, key: key, expectedCurrentFingerprint: expectedCurrentFingerprint)
    }
    func confirm(_ decision: PendingTrustDecision, displayedFingerprint: String) async throws {
        _ = try await store.confirm(decision, displayedFingerprint: displayedFingerprint)
    }
    func remove(_ expected: TrustedHostKey) async throws { try await store.remove(expected) }
    func cancel(_ decision: PendingTrustDecision) async { await store.cancel(decision) }
}

struct TrustRemovalReview: Equatable, Identifiable {
    let id = UUID()
    let record: TrustedHostKey
    let ownerEpoch: UUID
}

@MainActor final class TrustManagementModel: ObservableObject {
    @Published private(set) var records: [TrustedHostKey] = []
    @Published var search = ""
    @Published private(set) var loading = false
    @Published private(set) var hasLoaded = false
    @Published private(set) var refreshRequired = false
    @Published private(set) var loadIssue: AppIssue?
    @Published var issue: AppIssue?
    @Published private(set) var pending: PendingTrustDecision?
    @Published private(set) var replacementRecord: TrustedHostKey?
    @Published private(set) var removalReview: TrustRemovalReview?
    @Published private(set) var busy = false
    @Published private(set) var notice: String?
    private let storeProvider: @Sendable () async throws -> any TrustManagementStoring
    private var pendingStore: (any TrustManagementStoring)?
    private var active = true
    private var ownerEpoch = UUID()
    private var operation: UUID?
    private var loadOperation: UUID?
    private var loadTask: Task<Void, Never>?
    private var committedRevision: UInt64 = 0
    private var noticeTask: Task<Void, Never>?
    private var reviewCancellation: Task<Void, Never>?

    init(environment: SessionEnvironment) {
        storeProvider = { AppTrustManagementStore(store: try await environment.trustStore()) }
    }
    init(store: any TrustManagementStoring) { storeProvider = { store } }
    init(storeProvider: @escaping @Sendable () async throws -> any TrustManagementStoring) { self.storeProvider = storeProvider }

    static func endpoint(_ record: TrustedHostKey) -> String {
        let address = record.host.address.value
        return (address.contains(":") ? "[" + address + "]" : address) + ":" + String(record.host.port.value)
    }
    var filteredRecords: [TrustedHostKey] {
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return records.filter { record in
            needle.isEmpty || [Self.endpoint(record), record.key.algorithm, record.key.fingerprint].contains {
                $0.range(of: needle, options: [.caseInsensitive, .diacriticInsensitive]) != nil
            }
        }.sorted { left, right in
            let a = Self.endpoint(left), b = Self.endpoint(right)
            return a == b ? left.key.algorithm < right.key.algorithm : a < b
        }
    }
    func open() {
        guard !active else { return }
        active = true; ownerEpoch = UUID()
    }
    func close() {
        active = false; invalidateReview()
        noticeTask?.cancel(); notice = nil
    }
    func load() async {
        guard active, !busy else { return }
        // Explicit refresh joins an already-running read instead of silently returning
        // while its old data/error/loading state is still visible.
        await readRecords(owner: ownerEpoch)
    }
    private func readRecords(owner: UUID) async {
        while isCurrent(owner) {
            let task = loadTask ?? startRead(owner: owner)
            await task.value
            guard isCurrent(owner), refreshRequired, loadIssue == nil else { return }
            // If a commit arrived during the read, also await the fresh tracked read
            // that settles it. No polling, delay or duplicate store request is needed.
        }
    }
    private func startRead(owner: UUID) -> Task<Void, Never> {
        let token = UUID(), revision = committedRevision
        loadOperation = token; loading = true
        let task = Task { [weak self] in
            guard let self else { return }
            await self.performRead(owner: owner, token: token, revision: revision)
        }
        loadTask = task
        return task
    }
    private func performRead(owner: UUID, token: UUID, revision: UInt64) async {
        defer {
            if loadOperation == token { loadOperation = nil; loadTask = nil; loading = false }
            scheduleCommittedRefresh()
        }
        do {
            let store = try await storeProvider()
            guard isCurrent(owner), loadOperation == token else { return }
            let values = try await store.records()
            guard isCurrent(owner), loadOperation == token else { return }
            // A read begun before an observed commit cannot settle its refresh request.
            // Drop that snapshot and let the tracked follow-up read obtain current data.
            guard revision == committedRevision else { return }
            records = values; hasLoaded = true; loadIssue = nil; refreshRequired = false
        } catch {
            guard isCurrent(owner), loadOperation == token else { return }
            loadIssue = AppIssue(code: "trust.readFailed", message: "无法读取 App 专属已知主机库。上次成功读取的记录仍保留；请检查专属目录的访问权限与可用空间后重试。不会将读取失败当作空库。")
        }
    }
    @discardableResult func reviewRemoval(_ record: TrustedHostKey) -> Bool {
        guard active, !busy, !loading, records.contains(record) else { return false }
        invalidateReview()
        removalReview = TrustRemovalReview(record: record, ownerEpoch: ownerEpoch)
        return true
    }
    @discardableResult func beginReplacement(_ record: TrustedHostKey) -> Bool {
        guard active, !busy, !loading, records.contains(record) else { return false }
        invalidateReview(); replacementRecord = record
        return true
    }
    func cancelReview(_ review: TrustRemovalReview? = nil) {
        guard !busy, review == nil || removalReview == review else { return }
        invalidateReview()
    }
    private func invalidateReview() {
        ownerEpoch = UUID(); operation = nil; busy = false
        // Review cancellation can occur while a refresh is reading. Its late result
        // belongs to the previous epoch and must not keep the new owner loading.
        loadTask?.cancel(); loadTask = nil; loadOperation = nil; loading = false
        removalReview = nil; replacementRecord = nil
        cancelPending()
    }
    private func cancelPending() {
        let decision = pending, store = pendingStore
        pending = nil; pendingStore = nil
        if let decision, let store {
            let previous = reviewCancellation
            reviewCancellation = Task { await previous?.value; await store.cancel(decision) }
        }
    }
    private func isCurrent(_ owner: UUID, operation token: UUID? = nil) -> Bool {
        active && ownerEpoch == owner && (token == nil || operation == token)
    }
    private func finish(_ token: UUID) {
        if operation == token { operation = nil; busy = false }
        scheduleCommittedRefresh()
    }
    private func mutationCommitted() { committedRevision &+= 1; refreshRequired = true }
    private func scheduleCommittedRefresh() {
        guard active, refreshRequired, !busy, loadTask == nil, loadIssue == nil else { return }
        // Register the operation before yielding. A concurrent explicit refresh can
        // now await this exact read instead of being swallowed by a loading guard.
        _ = startRead(owner: ownerEpoch)
    }

    func remove(_ review: TrustRemovalReview) async -> Bool {
        guard active, !busy, !loading, removalReview == review, ownerEpoch == review.ownerEpoch else { return false }
        let token = UUID(), owner = ownerEpoch
        operation = token; busy = true
        defer { finish(token) }
        do {
            await reviewCancellation?.value
            guard isCurrent(owner, operation: token), !Task.isCancelled else { return false }
            let store = try await storeProvider()
            guard isCurrent(owner, operation: token), removalReview == review, !Task.isCancelled else { return false }
            // Host + algorithm + public blob are frozen in the review. The store performs
            // the exact comparison and atomic removal; never filter/persist a UI snapshot.
            try await store.remove(review.record)
            mutationCommitted()
            // Closing a page cannot undo a transaction already accepted by the store.
            // Return its real outcome, but only re-read for the new owner; never apply
            // this old operation's notice, review dismissal or record snapshot to it.
            guard isCurrent(owner, operation: token) else { scheduleCommittedRefresh(); return true }
            removalReview = nil; issue = nil
            showNotice("已移除此条信任记录；下次连接需要重新确认。")
            await readRecords(owner: owner)
            return true
        } catch {
            guard isCurrent(owner, operation: token) else { return false }
            removalReview = nil
            issue = AppIssue(code: "trust.removalRejected", message: "无法移除此条记录：记录可能已变化或不可读取。未删除其他端点或算法；请刷新并重新核对后再移除。")
            await readRecords(owner: owner)
            return false
        }
    }
    func prepare(_ record: TrustedHostKey, line: String) async {
        guard active, !busy, !loading, replacementRecord == record else { return }
        cancelPending()
        let token = UUID(), owner = ownerEpoch
        operation = token; busy = true
        defer { finish(token) }
        do {
            await reviewCancellation?.value
            guard isCurrent(owner, operation: token), !Task.isCancelled else { return }
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: line) }.value
            guard isCurrent(owner, operation: token), !Task.isCancelled else { return }
            guard key.algorithm == record.key.algorithm else { throw HostTrustError.invalidPublicKey }
            let store = try await storeProvider()
            guard isCurrent(owner, operation: token), !Task.isCancelled else { return }
            let decision = try await store.prepareReplacement(host: record.host, key: key, expectedCurrentFingerprint: record.key.fingerprint)
            guard isCurrent(owner, operation: token), !Task.isCancelled else { await store.cancel(decision); return }
            pending = decision; pendingStore = store; issue = nil
        } catch {
            guard isCurrent(owner, operation: token) else { return }
            issue = AppIssue(code: "trust.replacementRejected", message: "替换公钥无效、算法不一致或当前信任已变化。未修改信任库；请重新独立核实。")
        }
    }
    func confirm(_ decision: PendingTrustDecision) async -> Bool {
        guard active, !busy, !loading, pending == decision, let store = pendingStore else { return false }
        let token = UUID(), owner = ownerEpoch
        operation = token; busy = true
        defer { finish(token) }
        do {
            guard !Task.isCancelled else { return false }
            try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
            mutationCommitted()
            guard isCurrent(owner, operation: token) else { scheduleCommittedRefresh(); return true }
            pending = nil; pendingStore = nil; replacementRecord = nil; issue = nil
            showNotice("已精确替换核实过的主机公钥。")
            await readRecords(owner: owner)
            return true
        } catch {
            guard isCurrent(owner, operation: token) else { return false }
            pending = nil; pendingStore = nil
            issue = AppIssue(code: "trust.confirmationRejected", message: "此替换确认已失效或无法写入。连接仍会阻止变化的密钥；请刷新并重新独立核实，不会自动覆盖。")
            return false
        }
    }
    @discardableResult func copyEndpoint(_ record: TrustedHostKey, to pasteboard: NSPasteboard = .general) -> Bool {
        copy(Self.endpoint(record), notice: "端点已复制。", to: pasteboard)
    }
    @discardableResult func copyFingerprint(_ record: TrustedHostKey, to pasteboard: NSPasteboard = .general) -> Bool {
        copy(record.key.fingerprint, notice: "完整公钥指纹已复制。", to: pasteboard)
    }
    private func copy(_ text: String, notice: String, to pasteboard: NSPasteboard) -> Bool {
        guard active else { return false }
        pasteboard.clearContents()
        guard pasteboard.setString(text, forType: .string) else {
            issue = AppIssue(code: "trust.copyFailed", message: "无法写入剪贴板。此动作只复制公开的端点或指纹，不读取私钥或 Keychain。")
            return false
        }
        showNotice(notice); return true
    }
    private func showNotice(_ text: String) {
        noticeTask?.cancel(); notice = text
        noticeTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            if !Task.isCancelled { self?.notice = nil }
        }
    }
    deinit { noticeTask?.cancel() }
}
