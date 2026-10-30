import Foundation
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTrust

struct FilesRequest: Equatable, Sendable {
    let id: UUID
    let generation: UInt64
    let host: HostConfiguration

    /// A request keeps the display snapshot for prompts and diagnostics, but its
    /// authorization identity deliberately excludes mutable presentation metadata.
    /// This lets a repository refresh name/folder/favorite/history without
    /// invalidating an in-flight request or prepared authentication plan.
    static func == (lhs: FilesRequest, rhs: FilesRequest) -> Bool {
        lhs.id == rhs.id && lhs.generation == rhs.generation
            && lhs.host.id == rhs.host.id
            && lhs.host.connectionIdentity == rhs.host.connectionIdentity
    }
}
enum FilesInitialSecret: Sendable {
    case manual(OpenLXSSHSecurity.SecretBytes)
    case saved
}
struct FilesConnectInput: Sendable {
    let primary: FilesInitialSecret
    let keyboardOnly: Bool
    init(primary: FilesInitialSecret, keyboardOnly: Bool = false) { self.primary = primary; self.keyboardOnly = keyboardOnly }
}

struct FilesKeyboardChallenge: Sendable {
    let name: Data
    let instruction: Data
    let prompts: [(bytes: Data, echo: Bool)]
}
typealias FilesKeyboardHandler = @Sendable (FilesKeyboardChallenge, ChallengeReply<[Data]>) -> Void

protocol FilesConnecting: Sendable {
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService
}

/// Metadata only: binds prepared memory material to the exact request and authorization actually used.
/// Deliberately not Codable and contains no key bytes, passphrase or password.
fileprivate struct FilesAuthenticationAuthorization: Sendable {
    let request: FilesRequest
    let key: ManagedKeyReference?
    let credential: OpenLXSSHCore.CredentialReference?
}
struct FilesAuthenticationPlan: Sendable {
    let connection: SSHConnection
    let methods: [FileAuthentication]
    fileprivate let authorization: FilesAuthenticationAuthorization
}

actor LibSSH2FilesConnector: FilesConnecting {
    let repository: any AppRepositoryProtocol
    let security: SecurityCoordinator
    let environment: SessionEnvironment
    init(repository: any AppRepositoryProtocol, security: SecurityCoordinator, environment: SessionEnvironment) {
        self.repository = repository; self.security = security; self.environment = environment
    }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        let plan = try await prepareAuthentication(request: request, input: input, token: token, keyboard: keyboard, isCurrent: isCurrent)
        let store = try await environment.sharedTrustStore()
        try await validatePreparedPlan(plan, request: request, token: token, isCurrent: isCurrent)
        return try await LibSSH2FileService.connect(configuration: plan.connection, authentication: plan.methods,
            trustStore: store, trustHandler: trust, connectionTimeout: 10, operationTimeout: 120, token: token)
    }
    /// The production TCP path uses this same memory-only plan; tests stop here.
    /// It has no Codable/logging/export route and never accepts an arbitrary FD.
    func prepareAuthentication(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                               keyboard: @escaping FilesKeyboardHandler,
                               isCurrent: @escaping @Sendable () async -> Bool) async throws -> FilesAuthenticationPlan {
        let metadata = try await validate(request, token: token, isCurrent: isCurrent)
        let host = request.host
        let connection = SSHConnection(host: HostIdentity(address: try HostAddress(host.address), port: try SSHPort(host.port)), user: try SSHUser(host.username))
        let usedKey: ManagedKeyReference?
        if !input.keyboardOnly && host.authentication.needsKey {
            guard let id = host.keyRef, let key = metadata.keys.first(where: { $0.id == id }) else {
                throw FileServiceError(.cancelled, operation: "key-authorization-changed")
            }
            usedKey = key
        } else { usedKey = nil }
        var usedCredential: OpenLXSSHCore.CredentialReference?
        var authentication: [FileAuthentication] = []
        if !input.keyboardOnly {
            if host.authentication.needsKey {
                let bytes = try await security.privateKeyForFileAuthentication(host: host, authorized: true)
                try token.check(); guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "stale-files-material") }
                try token.check()
                let phrase = try await initialSecret(input.primary, request: request, key: usedKey, privateKey: true, token: token, isCurrent: isCurrent)
                usedCredential = phrase.credential
                authentication.append(.publicKey(publicKey: nil, privateKey: bytes.withUnsafeBytes { Data($0) }, passphrase: phrase.secret.withUnsafeBytes { Data($0) }))
            } else {
                let password = try await initialSecret(input.primary, request: request, key: nil, privateKey: false, token: token, isCurrent: isCurrent)
                usedCredential = password.credential
                authentication.append(.password(password.secret.withUnsafeBytes { Data($0) }))
            }
        }
        if input.keyboardOnly || host.authentication == .passwordWithMFA || host.authentication == .privateKeyWithMFA {
            authentication.append(.keyboardInteractive { challenge, reply in
                keyboard(FilesKeyboardChallenge(name: challenge.name, instruction: challenge.instruction,
                    prompts: challenge.prompts.map { ($0.bytes, $0.echo) }), reply)
            })
        }
        let plan = FilesAuthenticationPlan(connection: connection, methods: authentication,
            authorization: FilesAuthenticationAuthorization(request: request, key: usedKey, credential: usedCredential))
        try await validatePreparedPlan(plan, request: request, token: token, isCurrent: isCurrent)
        return plan
    }
    /// Shared production pre-TCP seam. Regression tests stop here without opening a socket.
    func validatePreparedPlan(_ plan: FilesAuthenticationPlan, request: FilesRequest, token: CancellationToken,
                              isCurrent: @escaping @Sendable () async -> Bool) async throws {
        try token.check()
        guard plan.authorization.request == request else { throw FileServiceError(.cancelled, operation: "prepared-plan-request-changed") }
        let metadata = try await validate(request, token: token, isCurrent: isCurrent)
        try token.check()
        try validateAuthorization(plan.authorization, metadata: metadata)
    }
    @discardableResult private func validate(_ request: FilesRequest, token: CancellationToken,
                          isCurrent: @escaping @Sendable () async -> Bool) async throws -> SecurityMetadata {
        try token.check()
        guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "stale-files-request") }
        try token.check()
        let metadata = try await repository.securityMetadata()
        try token.check()
        guard await isCurrent(), metadata.hosts.contains(where: { $0.matchesConnection(of: request.host) }) else { throw FileServiceError(.cancelled, operation: "host-authorization-changed") }
        try token.check()
        return metadata
    }
    private func validateAuthorization(_ authorization: FilesAuthenticationAuthorization, metadata: SecurityMetadata) throws {
        let host = authorization.request.host
        guard metadata.hosts.contains(where: { $0.matchesConnection(of: host) }) else { throw FileServiceError(.cancelled, operation: "host-authorization-changed") }
        if let key = authorization.key {
            guard host.authentication.needsKey, host.keyRef == key.id,
                  let currentKey = metadata.keys.first(where: { $0.id == key.id }), currentKey.algorithm == key.algorithm else {
                throw FileServiceError(.cancelled, operation: "key-authorization-changed")
            }
        }
        if let credential = authorization.credential {
            let referenced: Bool
            switch credential.purpose {
            case .password:
                referenced = !host.authentication.needsKey && host.savePasswordAuthorized && host.credentialRef == credential.id
            case .privateKeyPassphrase:
                referenced = authorization.key?.passphraseCredentialRef == credential.id
                    && metadata.keys.first(where: { $0.id == host.keyRef })?.passphraseCredentialRef == credential.id
            }
            guard referenced, credential.isSavingAuthorized, metadata.credentials.contains(credential) else {
                throw FileServiceError(.cancelled, operation: "secret-authorization-changed")
            }
        }
    }
    private func initialSecret(_ source: FilesInitialSecret, request: FilesRequest, key: ManagedKeyReference?, privateKey: Bool,
                               token: CancellationToken, isCurrent: @escaping @Sendable () async -> Bool) async throws -> (secret: OpenLXSSHSecurity.SecretBytes, credential: OpenLXSSHCore.CredentialReference?) {
        try token.check(); guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "stale-secret-authorization") }
        try token.check()
        switch source {
        case .manual(let secret): return (secret, nil)
        case .saved:
            let metadata = try await validate(request, token: token, isCurrent: isCurrent)
            let host = request.host
            let ref: UUID
            let kind: OpenLXSSHSecurity.CredentialReference.Kind
            let purpose: OpenLXSSHCore.CredentialPurpose
            if privateKey {
                guard let key, host.keyRef == key.id, metadata.keys.contains(key), let value = key.passphraseCredentialRef else {
                    throw FileServiceError(.authentication, operation: "saved-passphrase-unavailable")
                }
                ref = value; kind = .privateKeyPassphrase; purpose = .privateKeyPassphrase
            } else {
                guard host.savePasswordAuthorized, let value = host.credentialRef else { throw FileServiceError(.authentication, operation: "saved-password-not-authorized") }
                ref = value; kind = .password; purpose = .password
            }
            guard let credential = metadata.credentials.first(where: { $0.id == ref && $0.purpose == purpose && $0.isSavingAuthorized }) else {
                throw FileServiceError(.authentication, operation: "saved-secret-not-authorized")
            }
            let authorization = FilesAuthenticationAuthorization(request: request, key: key, credential: credential)
            try token.check(); guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "stale-secret-authorization") }
            try token.check()
            let result = await security.credentials.read(.init(id: ref, kind: kind))
            try token.check(); guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "stale-secret-answer") }
            try token.check()
            guard case .available(let secret) = result else { throw FileServiceError(.authentication, operation: "saved-secret-unavailable") }
            let after = try await validate(request, token: token, isCurrent: isCurrent)
            try token.check()
            try validateAuthorization(authorization, metadata: after)
            return (secret, credential)
        }
    }
}

enum FileDisplay {
    /// Display only; the original RemotePath/FileName remains the operation identity.
    static func bytes(_ bytes: Data) -> String {
        if let value = String(data: bytes, encoding: .utf8) {
            return SafePrompt.display(value).replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "\t", with: "\\t")
        }
        return bytes.map { String(format: "\\x%02X", $0) }.joined()
    }
    static func path(_ path: RemotePath) -> String { bytes(path.bytes) }
    static func name(_ name: FileName) -> String { bytes(name.bytes) }
    static func risk(_ risk: TransferRisk) -> String {
        switch risk {
        case .remotePathChecksAreNotAtomic(let path): "远端逐段 lstat 不是原子 no-follow；服务器仍可能改变树：" + self.path(path)
        case .overwriteIsAtomicButNotCompareAndSwap(let path): "覆盖虽尝试原子提交，但不是比较交换；最终复核后仍有竞争窗口：" + self.path(path)
        case .remoteFsyncUnavailable(let path): "远端无法确认 fsync 持久性：" + self.path(path)
        case .deletionChecksAreNotCompareAndSwap(let path): "删除前逐项核验不是比较交换；最终检查后仍可能变化：" + self.path(path)
        }
    }
}
extension AppIssue {
    static func files(_ error: Error) -> AppIssue {
        if let repository = error as? RepositoryError { return .sanitized(repository) }
        guard let typed = error as? FileServiceError else { return .security(error) }
        let message: String
        switch typed.kind {
        case .closed: message = "文件连接已关闭或已闲置释放。请手动重新连接；不会自动触发认证。"
        case .cancelled: message = "文件操作已取消；已提交的文件变更不会被伪称回滚。"
        case .authentication: message = "SFTP 认证未完成，或已保存凭据不可用。请手动输入重试；不会猜测挑战或保存 OTP。"
        case .untrusted: message = "SFTP 主机身份未获信任或已变化，连接已拒绝。请独立核实后在可信主机管理处理。"
        case .conflict: message = "文件名已存在或类型冲突。可明确选择跳过、其他名称或经风险确认的覆盖。"
        case .symbolicLink: message = "符号链接被拒绝，不会进入或跟随。删除链接本身必须明确选择。"
        case .invalidPath: message = "路径或名称无效。名称不得为空、含斜杠、NUL、. 或 ..；操作始终保留原始字节。"
        case .needsCapabilityConfirmation: message = "此连接尚无非覆盖 rename 能力证据。请显式核对并运行自有临时目录能力检查，不能假定服务器支持。"
        case .riskRejected: message = "所需风险未明确确认、确认已过期或范围已变化；未继续操作。"
        case .raceDetected: message = "文件或目录在计划后发生变化，已停止操作。请刷新并重新准备计划。"
        case .permissionDenied: message = "文件服务拒绝权限；请检查目标权限，不会自动提权。"
        case .timeout, .transport: message = "SFTP 连接或操作超时／断开。请手动重连；不会自动重试认证。"
        case .unsupported: message = "服务器或对象不支持此安全操作；不会回退到危险删除或非原子覆盖。"
        default: message = "文件操作未完成。请查看逐项结果并核对目标；不会解析系统详细错误或假称成功。"
        }
        return AppIssue(code: "files." + typed.kind.rawValue, message: message)
    }
}
