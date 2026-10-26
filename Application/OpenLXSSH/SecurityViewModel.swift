import AppKit
import Combine
import Foundation
import OpenLXSSHCore
import OpenLXSSHSecurity

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
    @Published private(set) var pendingCount = 0
    @Published private(set) var uncertainCount = 0
    @Published private(set) var recoveryReviews: [RecoveryReview] = []
    @Published private(set) var lastCreatedKey: KeyCreationOutcome?
    @Published private(set) var busy = false
    @Published var issue: AppIssue?
    @Published var copied = false
    init(coordinator: SecurityCoordinator) { self.coordinator = coordinator }
    func load() async {
        do {
            let overview = try await coordinator.overview()
            metadata = overview.metadata; pendingCount = overview.pendingCount; uncertainCount = overview.uncertainCount
            recoveryReviews = overview.recoveryReviews
            var values: [UUID: String] = [:]
            for key in metadata.keys {
                if let value = try? await coordinator.publicKey(key.id) { values[key.id] = value.copyString }
            }
            publicKeys = values
        } catch { issue = .security(error) }
    }
    @discardableResult func perform(_ operation: () async throws -> Void) async -> Bool {
        guard !busy else { return false }
        busy = true; defer { busy = false }
        do { try await operation(); issue = nil; await load(); return true }
        catch { issue = .security(error); await load(); return false }
    }
    func create(_ creation: KeyCreation, protection: KeyProtection, remember: SecretBytes?) async -> Bool {
        guard !busy else { return false }
        busy = true; lastCreatedKey = nil
        defer { busy = false }
        do {
            let outcome = try await coordinator.createKey(creation, protection: protection, rememberPassphrase: remember)
            lastCreatedKey = outcome
            issue = outcome.cleanupPending ? AppIssue(code: "security.keyCommittedCleanupPending", message: "密钥已创建并保存配置；仅恢复记录清理待重试。请勿重复生成/导入，在管理页重试精确清理即可。") : nil
            await load()
            return true // Always dismiss the creation editor once Core has committed.
        } catch { issue = .security(error); await load(); return false }
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
    func copyPublicKey(_ id: UUID) -> Bool {
        guard let text = publicKeys[id], !text.contains("PRIVATE") else {
            issue = .security(SecurityUIFailure.key(.missing)); return false
        }
        NSPasteboard.general.clearContents()
        copied = NSPasteboard.general.setString(text, forType: .string)
        if !copied { issue = AppIssue(code: "publicKey.copyFailed", message: "无法写入系统剪贴板；未复制任何私钥或秘密。") }
        return copied
    }
}
