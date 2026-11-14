import AppKit
import Combine
import Foundation
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHTransport
import OpenLXSSHTrust
import OpenLXSSHSecurity

struct SessionTrustPrompt: Identifiable, Equatable {
    let token: SessionToken
    let id: UUID
    let host: HostIdentity
    let algorithm: String
    let fingerprint: String
    let source: String
    let transport: SessionTrustChallenge?
    var changed: ChangedHostKey? = nil
}
struct SessionKeyboardField: Equatable, Sendable {
    let text: String
    let echo: Bool
}
enum SessionAuthenticationPayload: Equatable, Sendable {
    case legacyAskpass(AuthenticationChallengeKind, String)
    case initialPassword
    case privateKeyPassphrase
    case keyboard(name: String, instruction: String, prompts: [SessionKeyboardField])
}
struct SessionAuthenticationPrompt: Identifiable, Equatable {
    let token: SessionToken
    let id: UUID
    let payload: SessionAuthenticationPayload
    init(token: SessionToken, id: UUID, kind: AuthenticationChallengeKind, text: String) {
        self.token = token; self.id = id; payload = .legacyAskpass(kind, SafePrompt.display(text))
    }
    init(token: SessionToken, id: UUID, payload: SessionAuthenticationPayload) {
        self.token = token; self.id = id; self.payload = payload
    }
    var kind: AuthenticationChallengeKind {
        if case .legacyAskpass(let kind, _) = payload { return kind }
        if case .keyboard(_, _, let fields) = payload, fields.isEmpty { return .notification }
        return .unknownMasked
    }
    var text: String { if case .legacyAskpass(_, let text) = payload { return text }; return "" }
}
enum SessionAuthenticationAnswer {
    case legacy(AuthenticationResponse)
    case answers([OpenLXSSHSecurity.SecretBytes])
    case cancel
}
enum SessionPrimaryPurpose: Equatable, Sendable { case password, privateKeyPassphrase }
struct SessionPrimaryRequest: Sendable {
    let token: SessionToken
    let id: UUID
    let nativeSessionID: UUID
    let purpose: SessionPrimaryPurpose
    let key: ManagedKeyReference?
}
struct SessionPrimaryMaterial: Sendable {
    let secret: OpenLXSSHSecurity.SecretBytes
    let credential: OpenLXSSHCore.CredentialReference?
}
typealias SessionPrimaryProvider = @Sendable (SessionPrimaryRequest) async throws -> SessionPrimaryMaterial?
@MainActor final class SessionPrimaryAuthorization {
    private var providerAction: SessionPrimaryProvider?
    private var revokeAction: (() -> Void)?
    init(provider: @escaping SessionPrimaryProvider, revoke: @escaping () -> Void = {}) {
        providerAction = provider; revokeAction = revoke
    }
    func acquire(_ request: SessionPrimaryRequest) async throws -> SessionPrimaryMaterial? {
        guard let action = providerAction else { throw CancellationError() }
        let material = try await action(request)
        guard providerAction != nil, !Task.isCancelled else { throw CancellationError() }
        return material
    }
    func revoke() { providerAction = nil; let action = revokeAction; revokeAction = nil; action?() }
}

/// Only this small revocable reader crosses repository/credential awaits. Its validity
/// callback captures controller/tab weakly, so a held credential provider cannot retain UI.
@MainActor private final class SessionCredentialReadOwner {
    let host: HostConfiguration
    let repository: any AppRepositoryProtocol
    let credentials: any CredentialAccess
    private var intent: VaultTransientConnectionIntent?
    private var active = true
    private var requestID: UUID?
    let isCurrent: @MainActor (SessionToken) -> Bool
    let claim: @MainActor (UUID) -> Bool
    init(host: HostConfiguration, repository: any AppRepositoryProtocol, credentials: any CredentialAccess,
         intent: VaultTransientConnectionIntent?, isCurrent: @escaping @MainActor (SessionToken) -> Bool,
         claim: @escaping @MainActor (UUID) -> Bool) {
        self.host = host; self.repository = repository; self.credentials = credentials; self.intent = intent
        self.isCurrent = isCurrent; self.claim = claim
    }
    func revoke() { active = false; intent?.cancel(); intent = nil }
    func read(_ request: SessionPrimaryRequest) async throws -> SessionPrimaryMaterial? {
        guard current(request), requestID == nil, claim(request.id),
              request.purpose == (host.authentication.needsKey ? .privateKeyPassphrase : .password) else { throw SecurityUIFailure.notAuthorized }
        requestID = request.id
        let before = try await repository.securityMetadata()
        guard current(request), before.hosts.contains(where: { $0.matchesConnection(of: host) }) else { throw SecurityUIFailure.notAuthorized }
        if let intent {
            guard request.purpose == .password else { throw SecurityUIFailure.notAuthorized }
            try intent.bindPrimaryRequest(request.id, token: request.token, host: host)
            let value = try intent.take(for: host, token: request.token, primaryRequestID: request.id)
            self.intent = nil
            return value.map { SessionPrimaryMaterial(secret: $0, credential: nil) }
        }
        let ref: UUID, purpose: OpenLXSSHCore.CredentialPurpose, kind: OpenLXSSHSecurity.CredentialReference.Kind
        switch request.purpose {
        case .password:
            guard host.savePasswordAuthorized, let value = host.credentialRef else { return nil }
            ref = value; purpose = .password; kind = .password
        case .privateKeyPassphrase:
            guard let key = request.key, host.keyRef == key.id,
                  before.keys.contains(where: { $0.authenticationIdentity == key.authenticationIdentity }) else { throw SecurityUIFailure.notAuthorized }
            guard let value = key.passphraseCredentialRef else { return nil }
            ref = value; purpose = .privateKeyPassphrase; kind = .privateKeyPassphrase
        }
        guard current(request), let credential = before.credentials.first(where: { $0.id == ref && $0.purpose == purpose && $0.isSavingAuthorized }) else { return nil }
        let result = await credentials.read(.init(id: ref, kind: kind))
        guard current(request) else { throw CancellationError() }
        let after = try await repository.securityMetadata()
        guard current(request), after.hosts.contains(where: { $0.matchesConnection(of: host) }), after.credentials.contains(credential),
              request.key.map({ key in after.keys.contains { $0.authenticationIdentity == key.authenticationIdentity } }) ?? true else { throw SecurityUIFailure.notAuthorized }
        guard case .available(let secret) = result else { return nil }
        return SessionPrimaryMaterial(secret: secret, credential: credential)
    }
    private func current(_ request: SessionPrimaryRequest) -> Bool {
        active && !Task.isCancelled && isCurrent(request.token) && (requestID == nil || requestID == request.id)
    }
}

struct SessionDialog: Identifiable, Equatable {
    enum Content: Equatable { case trust(SessionTrustPrompt), authentication(SessionAuthenticationPrompt) }
    let id = UUID() // A fresh editor even when the same pending request is reopened.
    let content: Content
    static func trust(_ prompt: SessionTrustPrompt) -> Self { Self(content: .trust(prompt)) }
    static func authentication(_ prompt: SessionAuthenticationPrompt) -> Self { Self(content: .authentication(prompt)) }
}

/// Fixed local initiating path only, never an inferred server/network diagnosis.
enum SessionCloseOrigin: String, Equatable, Sendable {
    case setupFailure, receiveFailure, writeFailure, controlFailure, remoteExit, userDisconnect, userClose
}
struct SessionFailureDetail: Equatable, Sendable {
    enum Category: String, Sendable {
        case networkTimeout, networkUnavailable, connectionLost, interactionTimeout, authenticationTimeout
        case localNetworkAccessRequired
        case authenticationRejected, trustRejected, unsupported, unknown
    }
    let category: Category
    /// Fixed operation identifier only, never error.description, host input or server bytes.
    let operation: String
    let code: Int64?
    let stages: [String]
    let closeOrigin: SessionCloseOrigin?
    let connectedSeconds: Int?
    let tcpKeepalive: NativeTCPKeepaliveSnapshot?
    init(category: Category, operation: String, code: Int64?, stages: [String],
         closeOrigin: SessionCloseOrigin? = nil, connectedSeconds: Int? = nil,
         tcpKeepalive: NativeTCPKeepaliveSnapshot? = nil) {
        self.category = category; self.operation = operation; self.code = code; self.stages = stages
        self.closeOrigin = closeOrigin; self.connectedSeconds = connectedSeconds; self.tcpKeepalive = tcpKeepalive
    }
    var title: String {
        switch category {
        case .networkTimeout: "网络连接或操作超时"
        case .networkUnavailable: "无法建立网络连接"
        case .localNetworkAccessRequired: "本地网络访问尚未获准"
        case .connectionLost: "连接已中断"
        case .interactionTimeout: "等待人工认证超时"
        case .authenticationTimeout: "总体认证等待超时"
        case .authenticationRejected: "服务器拒绝认证或所选方式不可用"
        case .trustRejected: "主机身份未通过核验"
        case .unsupported: "服务器或候选后端不支持此连接"
        case .unknown: "连接失败，原因尚不能确定"
        }
    }
    var summary: String {
        if category == .localNetworkAccessRequired {
            return "本地网络访问尚未获准。请在 macOS“系统设置 → 隐私与安全性 → 本地网络”检查此 App 的访问权限，然后手动重试；尚未进行 SSH 握手或认证。"
        }
        if category == .connectionLost { return "连接已中断，当前标签的输出已保留。请检查连接后手动重连。" }
        return title + "。可检查配置并手动重试；不会自动重连或猜测密码错误。"
    }
    var issue: AppIssue { AppIssue(code: "session.native." + category.rawValue, message: summary) }
    var diagnostic: String {
        var lines: [String] = ["类别：" + category.rawValue, "阶段：" + operation]
        if category == .connectionLost { lines.append("连接阶段：此前已连接") }
        if let code { lines.append("错误码：" + String(code)) }
        if let closeOrigin { lines.append("关闭发起路径：" + closeOrigin.rawValue) }
        if let connectedSeconds { lines.append("已连接时长：" + String(connectedSeconds) + " 秒") }
        if let tcpKeepalive {
            let keepaliveLine: String
            if tcpKeepalive.enabled {
                keepaliveLine = "TCP 保活实际值：空闲 \(tcpKeepalive.idleSeconds) 秒；重试 \(tcpKeepalive.retrySeconds) 秒；失败探测 \(tcpKeepalive.failedProbes) 次"
            } else { keepaliveLine = "TCP 保活：已关闭" }
            lines.append(keepaliveLine)
        }
        if !stages.isEmpty { lines.append("认证事实：" + stages.joined(separator: " → ")) }
        return lines.joined(separator: "\n")
    }
}

@MainActor protocol SessionResultClosing: AnyObject {
    func closeResult(deadline: ContinuousClock.Instant) async -> SessionCloseResult
}
struct SessionCloseBatchResult: Equatable, Sendable {
    struct Entry: Equatable, Sendable { let tabID: UUID; let result: SessionCloseResult }
    let entries: [Entry]
    var complete: Bool { entries.allSatisfy { $0.result.permitsRemoval } }
}

/// Logic-test doubles implement this boundary, never a second SSH/PTY implementation.
@MainActor protocol SessionDriving: AnyObject {
    var terminal: NativeTerminalView { get }
    var token: SessionToken? { get }
    var state: SSHSessionState { get }
    var canReconnect: Bool { get }
    var failureDetail: SessionFailureDetail? { get }
    var onState: ((SessionToken?, SSHSessionState) -> Void)? { get set }
    var onTrust: (([SessionTrustPrompt]) -> Void)? { get set }
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)? { get set }
    func connect(_ configuration: SSHSessionConfiguration, savedPassword: SavedPasswordAuthorization?) throws -> SessionToken
    func accept(_ prompt: SessionTrustPrompt) async throws
    func respond(_ response: AuthenticationResponse, to prompt: SessionAuthenticationPrompt) throws
    func cancel()
    func closeTab()
    var usesTypedAuthentication: Bool { get }
    var automaticallyPresentsChallenges: Bool { get }
    func updateHost(_ host: HostConfiguration)
    func connect(_ configuration: SSHSessionConfiguration, primary: SessionPrimaryAuthorization) throws -> SessionToken
    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) async throws
    func respond(_ answer: SessionAuthenticationAnswer, to prompt: SessionAuthenticationPrompt) throws
}
extension SessionDriving {
    var failureDetail: SessionFailureDetail? { nil }
    var usesTypedAuthentication: Bool { false }
    var automaticallyPresentsChallenges: Bool { false }
    func updateHost(_ host: HostConfiguration) {}
    func connect(_ configuration: SSHSessionConfiguration, primary: SessionPrimaryAuthorization) throws -> SessionToken {
        throw TransportError.invalidConfiguration // Never silently turn typed material into Askpass text.
    }
    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) async throws {
        guard persistence == .persistent else { throw TransportError.invalidConfiguration }
        try await accept(prompt)
    }
    func respond(_ answer: SessionAuthenticationAnswer, to prompt: SessionAuthenticationPrompt) throws {
        switch answer {
        case .legacy(let response): try respond(response, to: prompt)
        case .cancel: cancel()
        case .answers: throw TransportError.invalidConfiguration
        }
    }
}

@MainActor final class DirectSessionDriver: SessionDriving, SessionResultClosing {
    let session: DirectSSHSession
    var terminal: NativeTerminalView { session.terminal }
    var token: SessionToken? { session.token }
    var state: SSHSessionState { session.state }
    var canReconnect: Bool { session.canReconnect }
    var onState: ((SessionToken?, SSHSessionState) -> Void)?
    var onTrust: (([SessionTrustPrompt]) -> Void)?
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)?
    init(_ session: DirectSSHSession) {
        self.session = session
        session.onStateChange = { [weak self] in self?.onState?($0, $1) }
        session.onTrustRequired = { [weak self] values in
            self?.onTrust?(values.map { value in
                SessionTrustPrompt(token: value.token, id: value.decision.id, host: value.candidate.host,
                    algorithm: value.candidate.key.algorithm, fingerprint: value.candidate.key.fingerprint,
                    source: "系统 ssh-keyscan 未认证预扫；必须通过独立可信渠道核实", transport: value)
            })
        }
        session.onAuthenticationRequest = { [weak self] token, request in
            self?.onAuthentication?(SessionAuthenticationPrompt(token: token, id: request.id, kind: request.kind,
                                                               text: SafePrompt.display(request.prompt)))
        }
    }
    func connect(_ configuration: SSHSessionConfiguration, savedPassword: SavedPasswordAuthorization?) throws -> SessionToken {
        try session.connect(configuration, savedPassword: savedPassword)
    }
    var automaticallyPresentsChallenges: Bool { true }
    func accept(_ prompt: SessionTrustPrompt) async throws { try await accept(prompt, persistence: .persistent) }
    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) async throws {
        guard let challenge = prompt.transport, token == prompt.token else { throw TransportError.stale }
        try await session.acceptTrust(challenge, displayedFingerprint: prompt.fingerprint, persistence: persistence)
    }
    func respond(_ response: AuthenticationResponse, to prompt: SessionAuthenticationPrompt) throws {
        try session.respond(response, requestID: prompt.id, token: prompt.token)
    }
    func cancel() { session.cancel() }
    func closeTab() { session.closeTab() }
    func closeResult(deadline: ContinuousClock.Instant) async -> SessionCloseResult {
        session.closeTab()
        while session.state != .closed, .now < deadline { try? await Task.sleep(for: .milliseconds(10)) }
        return session.state == .closed ? .closed : .incomplete(.init(token: token, reason: .legacyPending, drain: nil))
    }
}

/// Plain untrusted text only; no Markdown, link activation, terminal escapes or unbounded UI text.
enum SafePrompt {
    static func display(_ input: String) -> String {
        var result = "", count = 0
        for scalar in input.unicodeScalars {
            guard count < 4096 else { result += "\n[提示已截断]"; break }
            count += 1
            if scalar == "\n" || scalar == "\t" { result.unicodeScalars.append(scalar) }
            else if CharacterSet.controlCharacters.contains(scalar) || CharacterSet.illegalCharacters.contains(scalar)
                        || CharacterSet(charactersIn: "\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}").contains(scalar) {
                result += String(format: "\\u{%04X}", scalar.value)
            } else { result.unicodeScalars.append(scalar) }
        }
        return result
    }
}

struct ReadySession {
    let host: HostConfiguration
    let configuration: SSHSessionConfiguration
    let driver: any SessionDriving
}
@MainActor protocol SessionBuilding: AnyObject {
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration)
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession
}

/// Current catalog presentation is deliberately separate from SessionTab.host, the
/// actual connection snapshot used by reuse, reconnect and credential authorization.
struct SessionTabDisplayMetadata: Equatable {
    var currentName: String?
    var isFavorite = false
    var isDeleted = false
    var currentConnectionIdentity: HostConnectionIdentity?
    func configurationNotice(actual: HostConfiguration?) -> String {
        if isDeleted { return "保存配置已删除；本标签仍保留实际连接快照。" }
        guard let currentConnectionIdentity else { return "尚未读取当前保存配置；下列内容仅表示本标签实际连接快照。" }
        if currentConnectionIdentity != actual?.connectionIdentity { return "当前保存的连接配置已更改；本标签仍使用下列实际连接快照，只有显式重连才读取新配置。" }
        return "当前保存配置的连接参数与本标签实际快照一致。"
    }
}

struct SessionBatchCloseReview: Identifiable, Equatable {
    enum Scope: Equatable {
        case otherSessions(UUID), sessionsToRight(UUID)
        var title: String {
            switch self { case .otherSessions: "关闭其他会话"; case .sessionsToRight: "关闭右侧会话" }
        }
    }
    struct Entry: Identifiable, Equatable {
        let id: UUID
        let title: String
        let endpoint: String
        let state: SSHSessionState
        let status: String
    }
    let id = UUID()
    let scope: Scope
    let entries: [Entry]
    var tabIDs: [UUID] { entries.map(\.id) }
}

/// This UUID authorizes only one immutable list, never a later menu invocation.
/// The synchronous begin fence runs before any Task is scheduled or tab close awaits.
@MainActor final class SessionBatchCloseOwner: ObservableObject {
    @Published private(set) var review: SessionBatchCloseReview?
    @Published private(set) var inFlight = false
    func present(_ value: SessionBatchCloseReview) {
        guard review == nil, !inFlight, !value.entries.isEmpty else { return }
        review = value
    }
    @discardableResult func cancel(_ id: UUID) -> Bool {
        guard !inFlight, review?.id == id else { return false }
        review = nil; return true
    }
    func beginConfirmation(_ id: UUID) -> [UUID]? {
        guard !inFlight, let review, review.id == id else { return nil }
        inFlight = true; return review.tabIDs
    }
    func finish(_ id: UUID) {
        guard inFlight, review?.id == id else { return }
        inFlight = false; review = nil
    }
}

@MainActor final class SessionTab: ObservableObject, Identifiable {
    let id: UUID
    let hostID: UUID
    @Published var title: String
    @Published var displayMetadata = SessionTabDisplayMetadata()
    var displayName: String { customTitle ?? displayMetadata.currentName ?? title }
    var configurationChanged: Bool { displayMetadata.currentConnectionIdentity.map { $0 != host?.connectionIdentity } ?? false }
    @Published var state: SSHSessionState = .preparing
    @Published var issue: AppIssue?
    @Published var trust: [SessionTrustPrompt] = []
    @Published var authentication: SessionAuthenticationPrompt?
    @Published var searchText = "" { didSet { if searchText != oldValue { searchFound = nil; searchMatchIndex = 0; searchMatchCount = 0 } } }
    @Published private(set) var searchFound: Bool?
    @Published private(set) var searchMatchIndex = 0
    @Published private(set) var searchMatchCount = 0
    @Published var fontSizeOverride: Double?
    @Published private(set) var searchVisible = false
    @Published private(set) var searchFocusRequest: UUID?
    @Published private(set) var terminalFocusRequest: UUID?
    @Published var dialog: SessionDialog?
    var driver: (any SessionDriving)?
    var builder: (any SessionBuilding)?
    var primaryRequestID: UUID?
    var host: HostConfiguration?
    var configuration: SSHSessionConfiguration?
    var preparation: Task<Void, Never>?
    var operation = UUID()
    var lastActivity: UInt64 = 0
    var markedGeneration: UInt64?
    var customTitle: String?
    init(id: UUID = UUID(), host: HostConfiguration) {
        self.id = id; hostID = host.id; title = host.name; self.host = host
        displayMetadata = .init(currentName: host.name, isFavorite: host.isFavorite, currentConnectionIdentity: host.connectionIdentity)
    }
    func showSearch() { searchVisible = true; searchFocusRequest = UUID() }
    func closeSearch() { searchVisible = false; focusTerminal() }
    func focusTerminal() { terminalFocusRequest = UUID() }
    func searchHistory(backwards: Bool = false) {
        guard !searchText.isEmpty else { searchFound = nil; searchMatchIndex = 0; searchMatchCount = 0; return }
        searchFound = driver?.terminal.search(searchText, backwards: backwards) ?? false
        let summary = driver?.terminal.searchMatchSummary(searchText, limit: 1000)
        searchMatchIndex = summary?.index ?? 0; searchMatchCount = summary?.total ?? 0
    }
    func reconcileDialog() {
        switch dialog?.content {
        case .trust(let prompt): if (state != .awaitingTrust && prompt.changed == nil) || !trust.contains(prompt) || driver?.token != prompt.token { dialog = nil }
        case .authentication(let prompt): if state != .authenticating || authentication != prompt || driver?.token != prompt.token { dialog = nil }
        case nil: break
        }
    }
    var isReusable: Bool {
        switch state {
        case .preparing, .awaitingTrust, .authenticating, .connectionPending, .connected: true
        default: false
        }
    }
    var canReconnect: Bool {
        guard preparation == nil else { return false }
        if let driver { return driver.canReconnect }
        if case .failed = state { return true }
        return state == .disconnected(nil)
    }
    var status: String {
        if let detail = driver?.failureDetail { return detail.title + "；可手动重试" }
        return legacyStatus
    }
    private var legacyStatus: String {
        switch state {
        case .idle: "未连接"
        case .preparing: "准备连接"
        case .awaitingTrust: "等待主机身份核实"
        case .authenticating: "等待认证输入"
        case .connectionPending: "连接中／尚未确认认证"
        case .connected: "已连接"
        case .disconnected: "已断开；输出仅保留在此标签"
        case .failed(.trustRejected): "主机密钥被拒绝或已变化；连接已阻止"
        case .failed(.trustScanFailed): "无法取得主机公钥；连接未建立"
        case .failed(.authenticationTimeout): "认证超时；可手动重试"
        case .failed(.authenticationFailed): "认证未完成或被拒绝"
        case .failed: "连接失败／未认证；可手动重试"
        case .closing: "正在取消并释放连接"
        case .closed: "已关闭"
        }
    }
}

@MainActor private final class SessionCloseObservation<Value> { var result: Value? }

@MainActor final class SessionController: ObservableObject {
    @Published private(set) var tabs: [SessionTab] = []
    @Published private(set) var selectedTabID: UUID?
    @Published private(set) var closingAll = false
    @Published private(set) var terminating = false
    @Published var issue: AppIssue?
    private var closeAllTask: Task<SessionCloseBatchResult, Never>?
    private var tabCloseTasks: [UUID: Task<SessionCloseResult, Never>] = [:]
    private var tabCloseObservations: [UUID: SessionCloseObservation<SessionCloseResult>] = [:]
    private var closeAllObservation: SessionCloseObservation<SessionCloseBatchResult>?
    var closeJoinObserverCount: Int { closeAllJoinObservers + tabCloseJoinObservers }
    private var closeAllJoinObservers = 0
    private var tabCloseJoinObservers = 0
    private(set) var lastCloseBatch = SessionCloseBatchResult(entries: [])
    private var windowCleanupAdmissionClosed = false
    private let repository: any AppRepositoryProtocol
    private let credentials: any CredentialAccess
    private let builder: any SessionBuilding
    private var transientIntents: [UUID: VaultTransientConnectionIntent] = [:]
    private var primaryAuthorizations: [UUID: SessionPrimaryAuthorization] = [:]
    private var preparedCandidates: [UUID: (ReadySession, VaultTransientConnectionIntent)] = [:]
    private var preparationEpoch = UUID()
    private var settings = AppSettings()
    private var activity: UInt64 = 0
    @Published private(set) var workspaceVisible = true
    var onSelectionChanged: ((UUID?) -> Void)?
    var onAuthenticatedMetadata: (() -> Void)?
    var onShowConfiguration: ((UUID) -> Void)?
    var trustEnvironment: SessionEnvironment?
    init(repository: any AppRepositoryProtocol, credentials: any CredentialAccess, builder: any SessionBuilding) {
        self.repository = repository; self.credentials = credentials; self.builder = builder
    }
    var selectedTab: SessionTab? { tabs.first { $0.id == selectedTabID } }
    @discardableResult func open(_ host: HostConfiguration, mode: SessionOpenMode) -> UUID? {
        guard !closingAll, !terminating, !windowCleanupAdmissionClosed else { return nil }
        if mode == .reuse, let existing = tabs.filter({ $0.hostID == host.id && $0.host?.connectionIdentity == host.connectionIdentity && $0.isReusable }).max(by: { $0.lastActivity < $1.lastActivity }) {
            select(existing.id); return existing.id
        }
        let tab = SessionTab(host: host); tab.builder = builder
        tabs.append(tab); select(tab.id)
        prepare(tab)
        return tab.id
    }
    /// Does not allocate a visible tab, select a page, start TCP, or consume the secret.
    func prepareTransient(_ host: HostConfiguration, intent: VaultTransientConnectionIntent,
                          candidateBuilder: any SessionBuilding,
                          route: @escaping @MainActor (UUID) -> Bool) async throws -> VaultPreparedConnection {
        guard !closingAll, !terminating, !windowCleanupAdmissionClosed else { intent.cancel(); throw TransportError.closed }
        let epoch = preparationEpoch, id = UUID()
        let ready: ReadySession
        do { ready = try await candidateBuilder.prepare(hostID: host.id, sessionID: id) }
        catch { intent.cancel(); throw error }
        guard !Task.isCancelled, epoch == preparationEpoch, !closingAll, !terminating, !windowCleanupAdmissionClosed,
              ready.host.matchesConnection(of: host), ready.driver.usesTypedAuthentication else {
            intent.cancel(); ready.driver.closeTab(); throw TransportError.stale
        }
        if let native = ready.driver as? NativeSessionDriver {
            do { try native.reserveForPreparation() }
            catch { intent.cancel(); native.closeTab(); throw error }
        }
        preparedCandidates[id] = (ready, intent)
        return VaultPreparedConnection(commit: { [weak self] in
            guard let self, epoch == self.preparationEpoch, !self.closingAll, !self.terminating, !self.windowCleanupAdmissionClosed,
                  let prepared = self.preparedCandidates.removeValue(forKey: id) else { throw TransportError.stale }
            let tab = SessionTab(id: id, host: prepared.0.host); tab.builder = candidateBuilder
            tab.driver = prepared.0.driver; tab.configuration = prepared.0.configuration
            self.transientIntents[id] = prepared.1; self.tabs.append(tab)
            do {
                self.installCallbacks(tab); try self.applySettings(to: prepared.0.driver.terminal, tab: tab)
                self.installTerminalActions(tab)
                try self.start(tab, configuration: prepared.0.configuration)
                guard route(id) else { throw TransportError.stale }
            } catch {
                self.revokePrimary(id); prepared.0.driver.closeTab()
                self.tabs.removeAll { $0 === tab }
                if self.selectedTabID == id { self.selectedTabID = nil; self.onSelectionChanged?(nil) }
                throw error
            }
        }, cancel: { [weak self] in
            intent.cancel()
            if let prepared = self?.preparedCandidates.removeValue(forKey: id) { prepared.0.driver.closeTab() }
        })
    }
    private func revokePrimary(_ id: UUID) {
        transientIntents.removeValue(forKey: id)?.cancel()
        primaryAuthorizations.removeValue(forKey: id)?.revoke()
    }
    private func revokePreparedCandidates() {
        preparationEpoch = UUID()
        let pending = preparedCandidates; preparedCandidates.removeAll()
        for (_, value) in pending { value.1.cancel(); value.0.driver.closeTab() }
    }
    private func start(_ tab: SessionTab, configuration: SSHSessionConfiguration) throws {
        guard let driver = tab.driver, let host = tab.host else { throw TransportError.invalidConfiguration }
        driver.updateHost(host)
        tab.primaryRequestID = nil
        if driver.usesTypedAuthentication {
            let intent = transientIntents[tab.id]
            let reader = SessionCredentialReadOwner(host: host, repository: repository, credentials: credentials, intent: intent,
                isCurrent: { [weak self, weak tab] token in self?.isCurrent(token, tab: tab, host: host) == true },
                claim: { [weak tab] id in
                    guard let tab, tab.primaryRequestID == nil else { return false }
                    tab.primaryRequestID = id; return true
                })
            let authorization = SessionPrimaryAuthorization(provider: { request in try await reader.read(request) },
                revoke: { [weak self, weak intent, weak tab] in
                    reader.revoke(); intent?.cancel()
                    if let tab { self?.transientIntents[tab.id] = nil }
                })
            primaryAuthorizations[tab.id] = authorization
            do {
                let token = try driver.connect(configuration, primary: authorization)
                try intent?.bind(to: token, host: host)
            } catch { revokePrimary(tab.id); driver.cancel(); throw error }
        } else { _ = try driver.connect(configuration, savedPassword: authorization(for: tab)) }
    }
    func select(_ id: UUID) {
        guard tabs.contains(where: { $0.id == id }) else { return }
        selectedTabID = id; activity &+= 1
        for tab in tabs {
            tab.driver?.terminal.setVisible(workspaceVisible && tab.id == id)
            if tab.id == id { tab.lastActivity = activity } else { tab.dialog = nil }
        }
        onSelectionChanged?(id)
    }
    func setWorkspaceVisible(_ visible: Bool) {
        workspaceVisible = visible
        for tab in tabs {
            tab.driver?.terminal.setVisible(visible && tab.id == selectedTabID)
            // Dismiss only the presentation, not the pending transport request.
            // Reopening requires a fresh, empty editor for that exact request.
            if !visible { tab.dialog = nil }
        }
    }
    @discardableResult func showSearchInSelectedTab() -> Bool {
        guard workspaceVisible, let selectedTab, selectedTab.driver != nil else { return false }
        selectedTab.showSearch(); return true
    }
    @discardableResult func present(_ dialog: SessionDialog, tabID: UUID) -> Bool {
        guard workspaceVisible, selectedTabID == tabID, let tab = selectedTab else { return false }
        tab.dialog = dialog; tab.reconcileDialog()
        return tab.dialog == dialog
    }
    /// Native sheets call this only when their owning window has no current sheet/modal.
    /// Background tabs keep their pending request and badge; they never replace an editor.
    @discardableResult func presentPendingChallenge(tabID: UUID, modalAvailable: Bool) -> Bool {
        guard modalAvailable, workspaceVisible, selectedTabID == tabID,
              let tab = selectedTab, tab.dialog == nil, tab.driver?.automaticallyPresentsChallenges == true else { return false }
        if let trust = tab.trust.first { return present(.trust(trust), tabID: tabID) }
        if let authentication = tab.authentication { return present(.authentication(authentication), tabID: tabID) }
        return false
    }
    func dismissDialog(_ id: UUID, tabID: UUID) {
        guard let tab = tabs.first(where: { $0.id == tabID }), tab.dialog?.id == id else { return }
        tab.dialog = nil
    }
    func cancelChallenge(_ prompt: SessionAuthenticationPrompt, tabID: UUID) {
        guard let tab = tabs.first(where: { $0.id == tabID }), tab.authentication == prompt, tab.driver?.token == prompt.token else { return }
        disconnect(tabID)
    }
    func cancelTrust(_ prompt: SessionTrustPrompt, tabID: UUID) {
        guard let tab = tabs.first(where: { $0.id == tabID }), tab.trust.contains(prompt), tab.driver?.token == prompt.token else { return }
        disconnect(tabID)
    }
    func moveTab(_ id: UUID, before target: UUID?) {
        guard !closingAll, !terminating, id != target,
              let source = tabs.firstIndex(where: { $0.id == id }), target == nil || tabs.contains(where: { $0.id == target }) else { return }
        let tab = tabs.remove(at: source)
        guard let target else { tabs.append(tab); return }
        guard let destination = tabs.firstIndex(where: { $0.id == target }) else { return }
        tabs.insert(tab, at: destination)
    }
    func renameTab(_ id: UUID, title: String) {
        let value = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.utf8.count <= 256,
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              let tab = tabs.first(where: { $0.id == id }) else { return }
        tab.customTitle = value; tab.title = value
        objectWillChange.send() // Duplicate-name suffixes on the other tabs also changed.
    }
    func displayTitle(for tab: SessionTab) -> String {
        let same = tabs.filter { $0.displayName == tab.displayName }
        guard same.count > 1, let index = same.firstIndex(where: { $0 === tab }) else { return tab.displayName }
        return tab.displayName + " · " + String(index + 1)
    }
    /// Presentation only: never assign tab.host/configuration or invoke any driver.
    func updateDisplayMetadata(hosts: [HostConfiguration]) {
        let catalog = Dictionary(hosts.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        for tab in tabs {
            let current = catalog[tab.hostID]
            tab.displayMetadata = SessionTabDisplayMetadata(currentName: current?.name ?? tab.displayMetadata.currentName, isFavorite: current?.isFavorite ?? false,
                isDeleted: current == nil, currentConnectionIdentity: current?.connectionIdentity)
        }
        objectWillChange.send()
    }
    func connectionInfo(for tab: SessionTab) -> String {
        let snapshot = tab.host.map { "实际连接快照：\n" + $0.username + "@" + $0.vaultEndpoint + "\n" + $0.authentication.displayName } ?? "实际连接快照不可用"
        return snapshot + "\n" + tab.status + "\n\n" + tab.displayMetadata.configurationNotice(actual: tab.host)
    }
    func batchCloseReview(scope: SessionBatchCloseReview.Scope) -> SessionBatchCloseReview? {
        let targets: [SessionTab]
        switch scope {
        case .otherSessions(let anchor):
            guard tabs.contains(where: { $0.id == anchor }) else { return nil }
            targets = tabs.filter { $0.id != anchor }
        case .sessionsToRight(let anchor):
            guard let index = tabs.firstIndex(where: { $0.id == anchor }) else { return nil }
            targets = Array(tabs.dropFirst(index + 1))
        }
        guard !targets.isEmpty else { return nil }
        return SessionBatchCloseReview(scope: scope, entries: targets.map {
            .init(id: $0.id, title: displayTitle(for: $0), endpoint: $0.host.map { $0.username + "@" + $0.vaultEndpoint } ?? "实际端点不可用", state: $0.state, status: $0.status)
        })
    }
    func currentBatchCloseStatus(_ id: UUID) -> String { tabs.first { $0.id == id }?.status ?? "标签已关闭；确认时跳过" }
    func currentActiveCount(in review: SessionBatchCloseReview) -> Int {
        let ids = Set(review.tabIDs)
        return tabs.filter { ids.contains($0.id) && $0.isReusable }.count
    }
    private func prepare(_ tab: SessionTab) {
        let operation = UUID(); tab.operation = operation; tab.state = .preparing; tab.issue = nil
        tab.preparation = Task { [weak self, weak tab] in
            guard let self, let tab else { return }
            defer { tab.preparation = nil; tab.objectWillChange.send() }
            do {
                let ready = try await (tab.builder ?? builder).prepare(hostID: tab.hostID, sessionID: tab.id)
                guard !Task.isCancelled, tab.operation == operation, tabs.contains(where: { $0 === tab }) else {
                    ready.driver.closeTab(); return
                }
                tab.driver = ready.driver; tab.host = ready.host; tab.title = tab.customTitle ?? ready.host.name; tab.configuration = ready.configuration
                installCallbacks(tab)
                try applySettings(to: ready.driver.terminal, tab: tab)
                installTerminalActions(tab)
                ready.driver.terminal.setVisible(workspaceVisible && selectedTabID == tab.id)
                try start(tab, configuration: ready.configuration)
            } catch {
                guard tab.operation == operation, tab.state != .closing else { return }
                tab.state = .failed(.invalidConfiguration); tab.issue = .session(error)
            }
        }
    }
    private func installCallbacks(_ tab: SessionTab) {
        guard let driver = tab.driver else { return }
        driver.onState = { [weak self, weak tab, weak driver] token, state in
            guard let self, let tab, let driver, tab.driver === driver,
                  token == nil || token == driver.token else { return }
            tab.state = state
            if let detail = driver.failureDetail { tab.issue = detail.issue }
            driver.terminal.inputEnabled = Self.acceptsTerminalInput(state)
            if state != .awaitingTrust && !tab.trust.contains(where: { $0.changed != nil }) { tab.trust = [] }
            if state == .closing || state == .closed || !tab.isReusable { self.revokePrimary(tab.id) }
            if state != .authenticating { tab.authentication = nil }
            tab.reconcileDialog()
            if state == .connected, let token, tab.markedGeneration != token.generation {
                tab.markedGeneration = token.generation
                let hostID = tab.hostID
                Task { [weak self, repository] in
                    do { try await repository.apply([.markConnected(hostID, Date())]); self?.onAuthenticatedMetadata?() }
                    catch { self?.issue = .session(error) }
                }
            }
            self.objectWillChange.send()
        }
        driver.onTrust = { [weak tab, weak driver] prompts in
            guard let tab, let driver, tab.driver === driver,
                  tab.state == .awaitingTrust || prompts.contains(where: { $0.changed != nil }) else { return }
            tab.trust = prompts.filter { $0.token == driver.token }; tab.reconcileDialog()
        }
        driver.onAuthentication = { [weak tab, weak driver] prompt in
            guard let tab, let driver, tab.driver === driver, prompt.token == driver.token, tab.state == .authenticating else { return }
            tab.authentication = prompt; tab.reconcileDialog()
        }
    }
    /// Called only by a native typed primary provider, after actual trust/method discovery.
    /// KI mailboxes have no reference to this function or the credential store.
    func readTypedPrimary(_ request: SessionPrimaryRequest, tabID: UUID, expectedHost host: HostConfiguration) async throws -> SessionPrimaryMaterial? {
        guard let tab = tabs.first(where: { $0.id == tabID }), isCurrent(request.token, tab: tab, host: host),
              !Task.isCancelled, tab.primaryRequestID == nil,
              request.purpose == (host.authentication.needsKey ? .privateKeyPassphrase : .password) else { throw SecurityUIFailure.notAuthorized }
        tab.primaryRequestID = request.id // Once, before the first suspension.
        func current() -> Bool { !Task.isCancelled && tab.primaryRequestID == request.id && isCurrent(request.token, tab: tab, host: host) }
        let before = try await repository.securityMetadata()
        guard current(), before.hosts.contains(where: { $0.matchesConnection(of: host) }) else { throw SecurityUIFailure.notAuthorized }
        if let intent = transientIntents[tabID] {
            guard request.purpose == .password else { throw SecurityUIFailure.notAuthorized }
            try intent.bindPrimaryRequest(request.id, token: request.token, host: host)
            let value = try intent.take(for: host, token: request.token, primaryRequestID: request.id)
            transientIntents[tabID] = nil
            return value.map { SessionPrimaryMaterial(secret: $0, credential: nil) }
        }
        let ref: UUID
        let purpose: OpenLXSSHCore.CredentialPurpose
        let kind: OpenLXSSHSecurity.CredentialReference.Kind
        switch request.purpose {
        case .password:
            guard !host.authentication.needsKey, host.savePasswordAuthorized, let value = host.credentialRef else { return nil }
            ref = value; purpose = .password; kind = .password
        case .privateKeyPassphrase:
            guard let key = request.key, host.keyRef == key.id,
                  before.keys.contains(where: { $0.authenticationIdentity == key.authenticationIdentity }) else { throw SecurityUIFailure.notAuthorized }
            guard let value = key.passphraseCredentialRef else { return nil }
            ref = value; purpose = .privateKeyPassphrase; kind = .privateKeyPassphrase
        }
        guard current(), let credential = before.credentials.first(where: { $0.id == ref && $0.purpose == purpose && $0.isSavingAuthorized }) else { return nil }
        let result = await credentials.read(.init(id: ref, kind: kind))
        guard current() else { throw CancellationError() }
        let after = try await repository.securityMetadata()
        guard current(), after.hosts.contains(where: { $0.matchesConnection(of: host) }), after.credentials.contains(credential),
              request.key.map({ key in after.keys.contains { $0.authenticationIdentity == key.authenticationIdentity } }) ?? true else { throw SecurityUIFailure.notAuthorized }
        guard case .available(let secret) = result else { return nil }
        return SessionPrimaryMaterial(secret: secret, credential: credential)
    }
    func metadataDidRefresh(_ metadata: SecurityMetadata) {
        for tab in tabs where transientIntents[tab.id] != nil {
            guard let host = tab.host, metadata.hosts.contains(where: { $0.matchesConnection(of: host) }) else {
                revokePrimary(tab.id); tab.driver?.cancel(); continue
            }
        }
        for (id, value) in Array(preparedCandidates) where !metadata.hosts.contains(where: { $0.matchesConnection(of: value.0.host) }) {
            value.1.cancel(); value.0.driver.closeTab(); preparedCandidates[id] = nil
        }
    }
    private func authorization(for tab: SessionTab) -> SavedPasswordAuthorization? {
        guard let host = tab.host, host.authentication == .password, host.savePasswordAuthorized, host.credentialRef != nil else { return nil }
        let id = tab.id
        return SavedPasswordAuthorization { [weak self] token in
            try await self?.readSavedPassword(token, tabID: id, expectedHost: host)
        }
    }
    /// Testable authorization boundary; the caller never supplies a free-form credential UUID.
    func readSavedPassword(_ token: SessionToken, tabID: UUID, expectedHost host: HostConfiguration) async throws -> AuthenticationSecret? {
        guard !Task.isCancelled, host.authentication == .password, host.savePasswordAuthorized, let ref = host.credentialRef,
              isCurrent(token, tab: tabs.first { $0.id == tabID }, host: host) else { return nil }
        let before = try await repository.securityMetadata()
        // Cancellation and tab/generation checks must precede accessing Keychain,
        // not merely dropping a secret after the asynchronous read completed.
        guard !Task.isCancelled, isCurrent(token, tab: tabs.first { $0.id == tabID }, host: host),
              before.hosts.contains(where: { $0.id == host.id && $0.connectionIdentity == host.connectionIdentity }), before.credentials.contains(where: { $0.id == ref && $0.purpose == .password && $0.isSavingAuthorized }) else { return nil }
        let result = await credentials.read(.init(id: ref, kind: .password))
        guard !Task.isCancelled, isCurrent(token, tab: tabs.first { $0.id == tabID }, host: host),
              case .available(let secret) = result else { return nil }
        let after = try await repository.securityMetadata()
        guard !Task.isCancelled, after.hosts.contains(where: { $0.id == host.id && $0.connectionIdentity == host.connectionIdentity }), after.credentials.contains(where: { $0.id == ref && $0.purpose == .password && $0.isSavingAuthorized }),
              isCurrent(token, tab: tabs.first { $0.id == tabID }, host: host) else { return nil }
        return try secret.withUnsafeBytes { try AuthenticationSecret(Data($0)) }
    }
    private func isCurrent(_ token: SessionToken, tab: SessionTab?, host: HostConfiguration) -> Bool {
        guard !closingAll, !terminating, let tab, tabs.contains(where: { $0 === tab }), tab.host?.id == host.id, tab.host?.connectionIdentity == host.connectionIdentity, tab.driver?.token == token else { return false }
        return tab.isReusable
    }
    func reconnect(_ id: UUID) {
        guard !closingAll, !terminating, !windowCleanupAdmissionClosed, let tab = tabs.first(where: { $0.id == id }), tab.canReconnect else { return }
        guard tab.driver != nil else { prepare(tab); return }
        // Keep the same driver/view, but refresh Core configuration and authorization before a new generation.
        let operation = UUID(); tab.operation = operation; tab.state = .preparing; tab.issue = nil
        tab.preparation = Task { [weak self, weak tab] in
            guard let self, let tab else { return }
            defer { tab.preparation = nil; tab.objectWillChange.send() }
            do {
                let (host, configuration) = try await (tab.builder ?? builder).configuration(hostID: tab.hostID)
                guard tab.operation == operation, !Task.isCancelled else { throw TransportError.stale }
                tab.host = host; tab.title = tab.customTitle ?? host.name; tab.configuration = configuration
                revokePrimary(id)
                try start(tab, configuration: configuration)
            } catch { if tab.operation == operation { tab.state = .failed(.invalidConfiguration); tab.issue = .session(error) } }
        }
    }
    func disconnect(_ id: UUID) {
        guard let tab = tabs.first(where: { $0.id == id }) else { return }
        guard tab.state != .closing && tab.state != .closed else { return }
        tab.operation = UUID(); tab.preparation?.cancel()
        revokePrimary(id)
        tab.driver?.terminal.inputEnabled = false
        tab.trust = []; tab.authentication = nil; tab.dialog = nil
        if let driver = tab.driver { driver.cancel() } else { tab.state = .disconnected(nil) }
    }
    func closeTab(_ id: UUID) async { _ = await closeTabResult(id, deadline: .now + .seconds(2)) }
    func closeTabResult(_ id: UUID, deadline: ContinuousClock.Instant) async -> SessionCloseResult {
        if tabCloseTasks[id] != nil, let observation = tabCloseObservations[id] {
            tabCloseJoinObservers += 1
            defer { tabCloseJoinObservers -= 1 }
            while observation.result == nil, .now < deadline {
                if Task.isCancelled { return cancelledCloseObservation(tabID: id) }
                do { try await Task.sleep(for: .milliseconds(10)) }
                catch { return cancelledCloseObservation(tabID: id) }
            }
            return observation.result ?? .incomplete(.init(token: tabs.first { $0.id == id }?.driver?.token, reason: .legacyPending, drain: nil))
        }
        guard let tab = tabs.first(where: { $0.id == id }) else { return .closed }
        tab.operation = UUID(); tab.preparation?.cancel(); revokePrimary(id)
        tab.state = .closing; tab.driver?.terminal.inputEnabled = false; tab.trust = []; tab.authentication = nil; tab.dialog = nil
        let observation = SessionCloseObservation<SessionCloseResult>()
        tabCloseObservations[id] = observation
        let task = Task { @MainActor [self, tab] in
            // Preparation owns its eventual driver and rejects a late result by operation.
            // Do not join an uncooperative builder beyond the shared deadline.
            while tab.preparation != nil, .now < deadline { try? await Task.sleep(for: .milliseconds(10)) }
            let result: SessionCloseResult
            if tab.preparation != nil {
                result = .incomplete(.init(token: tab.driver?.token, reason: .preparing, drain: nil))
            } else if let driver = tab.driver {
                if let closer = driver as? any SessionResultClosing { result = await closer.closeResult(deadline: deadline) }
                else {
                    driver.closeTab()
                    while driver.state != .closed, .now < deadline { try? await Task.sleep(for: .milliseconds(10)) }
                    result = driver.state == .closed ? .closed : .incomplete(.init(token: driver.token, reason: .legacyPending, drain: nil))
                }
            } else { result = .closed }
            if result.permitsRemoval {
                tab.driver?.onState = nil; tab.driver?.onTrust = nil; tab.driver?.onAuthentication = nil
                let index = tabs.firstIndex(where: { $0 === tab }) ?? 0
                tabs.removeAll { $0 === tab }
                if selectedTabID == id {
                    selectedTabID = nil
                    if !tabs.isEmpty { select(tabs[min(index, tabs.count - 1)].id) }
                    else { onSelectionChanged?(nil) }
                }
                if case .retired = result {
                    issue = AppIssue(code: "session.retired", message: "连接的原生资源已关闭并封口；仍有已撤销的认证工作等待实际返回。标签已移除，未声称全部任务消失。")
                }
            } else {
                tab.issue = Self.incompleteCloseIssue
                issue = Self.incompleteCloseIssue
            }
            observation.result = result
            tabCloseTasks[id] = nil; tabCloseObservations[id] = nil
            return result
        }
        tabCloseTasks[id] = task
        // A cancelled observer cannot cancel this resource owner's cleanup.
        return await task.value
    }
    private func cancelledCloseObservation(tabID: UUID) -> SessionCloseResult {
        .incomplete(.init(token: tabs.first { $0.id == tabID }?.driver?.token, reason: .observationCancelled, drain: nil))
    }
    static var incompleteCloseIssue: AppIssue {
        AppIssue(code: "session.closeIncomplete", message: "部分连接尚未证明原生关闭或交互封口，本次关闭已停止。已撤销输入和认证回答；仍保留清理所属对象，可稍后再次明确关闭。不会强杀未知任务或假称资源已释放。")
    }
    func setWindowCleanupAdmissionClosed(_ closed: Bool) { windowCleanupAdmissionClosed = closed }
    /// Permanent process-lifetime admission revocation. Window close does not
    /// call this; quit does, before its first asynchronous cleanup boundary.
    func beginTermination() {
        terminating = true; revokePreparedCandidates()
        for tab in tabs { revokePrimary(tab.id); tab.driver?.terminal.inputEnabled = false; tab.trust = []; tab.authentication = nil; tab.dialog = nil; tab.driver?.cancel() }
    }
    func closeAll() async { _ = await closeAllResult(deadline: .now + .seconds(2)) }
    func closeAllResult(deadline: ContinuousClock.Instant) async -> SessionCloseBatchResult {
        if closeAllTask != nil, let observation = closeAllObservation {
            closeAllJoinObservers += 1
            defer { closeAllJoinObservers -= 1 }
            while observation.result == nil, .now < deadline {
                if Task.isCancelled { return SessionCloseBatchResult(entries: tabs.map { .init(tabID: $0.id, result: cancelledCloseObservation(tabID: $0.id)) }) }
                do { try await Task.sleep(for: .milliseconds(10)) }
                catch { return SessionCloseBatchResult(entries: tabs.map { .init(tabID: $0.id, result: cancelledCloseObservation(tabID: $0.id)) }) }
            }
            if let result = observation.result { return result }
            return SessionCloseBatchResult(entries: tabs.map { .init(tabID: $0.id, result: .incomplete(.init(token: $0.driver?.token, reason: .legacyPending, drain: nil))) })
        }
        closingAll = true; revokePreparedCandidates()
        let ids = tabs.map(\.id)
        for tab in tabs {
            tab.operation = UUID(); tab.preparation?.cancel(); revokePrimary(tab.id)
            tab.state = .closing; tab.driver?.terminal.inputEnabled = false; tab.trust = []; tab.authentication = nil; tab.dialog = nil
        }
        let observation = SessionCloseObservation<SessionCloseBatchResult>()
        closeAllObservation = observation
        let task = Task { @MainActor [self] in
            // Start all exact owners before waiting for A, so B can close under the same
            // monotonic deadline. No task-group race joins an uncooperative loser.
            let work = ids.map { id in Task { @MainActor in
                SessionCloseBatchResult.Entry(tabID: id, result: await self.closeTabResult(id, deadline: deadline))
            } }
            var entries: [SessionCloseBatchResult.Entry] = []
            for task in work { entries.append(await task.value) }
            let result = SessionCloseBatchResult(entries: entries)
            lastCloseBatch = result; observation.result = result
            closeAllTask = nil; closeAllObservation = nil; closingAll = false
            return result
        }
        closeAllTask = task
        return await task.value
    }
    func accept(_ prompt: SessionTrustPrompt, tabID: UUID, persistence: SessionTrustPersistence = .persistent) async -> Bool {
        guard !closingAll, !terminating, workspaceVisible, selectedTabID == tabID,
              let tab = tabs.first(where: { $0.id == tabID }), tab.state == .awaitingTrust,
              tab.trust.contains(prompt), tab.driver?.token == prompt.token, let driver = tab.driver else { return false }
        do { try await driver.accept(prompt, persistence: persistence); return true }
        catch { if tab.driver?.token == prompt.token { tab.issue = .session(error) }; return false }
    }
    func respond(_ response: AuthenticationResponse, to prompt: SessionAuthenticationPrompt, tabID: UUID) -> Bool {
        guard !closingAll, !terminating, workspaceVisible, selectedTabID == tabID,
              let tab = tabs.first(where: { $0.id == tabID }), tab.authentication == prompt,
              tab.state == .authenticating, tab.driver?.token == prompt.token, let driver = tab.driver else { return false }
        do { try driver.respond(response, to: prompt); tab.authentication = nil; return true }
        catch { tab.issue = .session(error); return false }
    }
    func respond(_ answer: SessionAuthenticationAnswer, to prompt: SessionAuthenticationPrompt, tabID: UUID) -> Bool {
        guard !closingAll, !terminating, workspaceVisible, selectedTabID == tabID,
              let tab = tabs.first(where: { $0.id == tabID }), tab.authentication == prompt,
              tab.state == .authenticating, tab.driver?.token == prompt.token, let driver = tab.driver else { return false }
        do {
            try driver.respond(answer, to: prompt)
            if tab.authentication == prompt { tab.authentication = nil }
            return true
        } catch { tab.issue = .session(error); return false }
    }
    private static func acceptsTerminalInput(_ state: SSHSessionState) -> Bool {
        switch state { case .connected, .connectionPending: true; default: false }
    }
    func showConfiguration(tabID: UUID) {
        guard workspaceVisible, selectedTabID == tabID, let tab = selectedTab else { return }
        onShowConfiguration?(tab.hostID)
    }
    private func installTerminalActions(_ tab: SessionTab) {
        guard let terminal = tab.driver?.terminal else { return }
        terminal.inputEnabled = Self.acceptsTerminalInput(tab.state)
        terminal.canPerformDesktopAction = { [weak self, weak tab] action in
            guard let self, let tab else { return false }
            return self.canPerformTerminalAction(action, tabID: tab.id)
        }
        terminal.onDesktopAction = { [weak self, weak tab] action in
            guard let self, let tab else { return }
            _ = self.performTerminalAction(action, tabID: tab.id)
        }
    }
    func canPerformTerminalAction(_ action: TerminalDesktopAction, tabID: UUID? = nil) -> Bool {
        guard workspaceVisible, !closingAll, !terminating,
              let tab = tabs.first(where: { $0.id == (tabID ?? selectedTabID) }), tab.id == selectedTabID,
              let terminal = tab.driver?.terminal, terminal.window?.attachedSheet == nil else { return false }
        switch action {
        case .copy: return terminal.getSelection()?.isEmpty == false
        case .paste: return terminal.inputEnabled
        case .increaseFont: return terminal.font.pointSize < 72
        case .decreaseFont: return terminal.font.pointSize > 6
        case .disconnect: return tab.isReusable
        case .reconnect: return tab.canReconnect
        default: return true
        }
    }
    @discardableResult func performTerminalAction(_ action: TerminalDesktopAction, tabID: UUID? = nil) -> Bool {
        guard canPerformTerminalAction(action, tabID: tabID), let tab = selectedTab, let terminal = tab.driver?.terminal else { return false }
        switch action {
        case .copy: terminal.copy(NSNull())
        case .paste: terminal.paste(NSNull())
        case .selectAll: terminal.selectAll(nil)
        case .search: tab.showSearch()
        case .clearHistory:
            terminal.clearLocalHistory()
            if tab.searchVisible { tab.searchHistory() }
        case .scrollToBottom: terminal.scrollToLiveBottom(); tab.focusTerminal()
        case .increaseFont, .decreaseFont, .resetFont:
            let size = action == .resetFont ? settings.fontSize : min(72, max(6, terminal.font.pointSize + (action == .increaseFont ? 1 : -1)))
            do { try terminal.setFont(name: terminal.font.fontName, size: size); tab.fontSizeOverride = action == .resetFont ? nil : size }
            catch { tab.issue = .session(error); return false }
        case .connectionInfo:
            guard let window = terminal.window else { return false }
            let alert = NSAlert(); alert.messageText = displayTitle(for: tab)
            alert.informativeText = connectionInfo(for: tab)
            alert.addButton(withTitle: "关闭"); NativeSheetCloseRouting.register(alert); alert.beginSheetModal(for: window)
        case .disconnect: disconnect(tab.id)
        case .reconnect: reconnect(tab.id)
        }
        return true
    }

    func updateSettings(_ settings: AppSettings) {
        let fontChanged = self.settings.fontName != settings.fontName || self.settings.fontSize != settings.fontSize
        let cursorChanged = self.settings.cursorShape != settings.cursorShape || self.settings.cursorBlink != settings.cursorBlink
        self.settings = settings
        for tab in tabs {
            if fontChanged { tab.fontSizeOverride = nil }
            if let terminal = tab.driver?.terminal {
                do { try TerminalPreferences.apply(settings, to: terminal, size: tab.fontSizeOverride, updateCursor: cursorChanged) }
                catch { tab.issue = .session(error) }
            }
        }
    }
    private func applySettings(to terminal: NativeTerminalView, tab: SessionTab) throws {
        try TerminalPreferences.apply(settings, to: terminal, size: tab.fontSizeOverride)
    }
}

extension NSColor {
    convenience init(sessionHex: String) {
        let value = UInt32(sessionHex.dropFirst(), radix: 16) ?? 0
        self.init(srgbRed: Double((value >> 16) & 255) / 255, green: Double((value >> 8) & 255) / 255, blue: Double(value & 255) / 255, alpha: 1)
    }
}
extension AppIssue {
    static func session(_ error: Error) -> AppIssue {
        if let error = error as? RepositoryError { return .sanitized(error) }
        if let key = error as? KeyFailure, key == .unsafePermissions || key == .symbolicLinkOrEscape { return unsafeSessionStorage }
        if let operation = error as? KeyOperationFailure, operation.primary == .unsafePermissions || operation.primary == .symbolicLinkOrEscape { return unsafeSessionStorage }
        if let trust = error as? HostTrustError {
            if case .unsafeStorage = trust { return unsafeSessionStorage }
        }
        return AppIssue(code: "session.unavailable", message: "连接无法准备或已失败。请检查配置、受管理私钥及已签名的 App/helper；不会忽略主机身份、改用明文或自动重试。")
    }
    private static var unsafeSessionStorage: AppIssue {
        AppIssue(code: "session.unsafeStorage", message: "会话、信任或受管理私钥存储的权限／扩展 ACL 不安全或无法核验。已拒绝连接；仅 chmod 不足以消除 ACL，请自行核实专属目录与文件，App 不会改写或删除 ACL。")
    }
}

/// Files UI later implements this app-level seam; terminal ownership stays independent.
@MainActor protocol TransferLifecycle: AnyObject {
    var hasActiveTransfers: Bool { get }
    func cancelAllAndWait() async
}
@MainActor final class NoTransfers: TransferLifecycle {
    var hasActiveTransfers: Bool { false }
    func cancelAllAndWait() async {}
}
@MainActor protocol FilesWindowLifecycle: AnyObject {
    var hasActiveTransfers: Bool { get }
    var hasPendingOperations: Bool { get }
    func beginWindowClose()
    func closeForWindow() async
    func beginTermination()
    func freezeTransferAdmission()
    func resumeTransferAdmission()
    func activeTransferSnapshot() async -> Bool
}
extension FilesWindowLifecycle {
    func freezeTransferAdmission() {}
    func resumeTransferAdmission() {}
    func activeTransferSnapshot() async -> Bool { hasActiveTransfers }
}
struct AppConnectionCloseResult: Equatable, Sendable {
    let sessions: SessionCloseBatchResult
    let transferDecisionRequired: Bool
    var complete: Bool { !transferDecisionRequired && sessions.complete }
}
@MainActor final class AppLifecycleCoordinator {
    let sessions: SessionController
    var transfers: any TransferLifecycle
    var files: (any FilesWindowLifecycle)?
    private var closeTask: Task<AppConnectionCloseResult, Never>?
    private(set) var lastCloseResult: AppConnectionCloseResult?
    init(sessions: SessionController, transfers: any TransferLifecycle = NoTransfers()) { self.sessions = sessions; self.transfers = transfers }
    var requiresTransferDecision: Bool { transfers.hasActiveTransfers || files?.hasActiveTransfers == true }
    var terminating: Bool { sessions.terminating }
    func beginTermination() { sessions.beginTermination(); files?.beginTermination() }
    func freezeCloseAdmission() { sessions.setWindowCleanupAdmissionClosed(true); files?.freezeTransferAdmission() }
    /// Only the presentation decision is awaited here. No transfer snapshot,
    /// cancellation, credential read, or admission mutation happens on refusal.
    func freezeAfterCloseReview(_ request: WindowCloseReviewRequest, isCurrent: @MainActor () -> Bool) async -> Bool {
        guard await request.wait(), !Task.isCancelled, isCurrent() else { return false }
        freezeCloseAdmission()
        return true
    }
    func resumeAfterContinue() { if !terminating { sessions.setWindowCleanupAdmissionClosed(false); files?.resumeTransferAdmission() } }
    func activeTransferSnapshot() async -> Bool {
        let fileJobs = await files?.activeTransferSnapshot() == true
        return transfers.hasActiveTransfers || fileJobs
    }
    func closeConnections(cancelTransfers: Bool = false, retainAdmissionFreeze: Bool = false) async -> Bool {
        await closeConnectionsResult(cancelTransfers: cancelTransfers, retainAdmissionFreeze: retainAdmissionFreeze).complete
    }
    func closeConnectionsResult(cancelTransfers: Bool = false, retainAdmissionFreeze: Bool = false) async -> AppConnectionCloseResult {
        if let closeTask { return await closeTask.value }
        freezeCloseAdmission()
        let task = Task { @MainActor [self] in
            if await activeTransferSnapshot() && !cancelTransfers {
                resumeAfterContinue(); closeTask = nil
                return AppConnectionCloseResult(sessions: .init(entries: []), transferDecisionRequired: true)
            }
            files?.beginWindowClose()
            // One 2-second monotonic SSH cleanup budget, never reset per tab or phase.
            // Existing transfer/Files cleanup has its original semantics, not a new claim
            // that arbitrary file operations can be force-completed in this budget.
            let deadline = ContinuousClock.now + .seconds(2)
            let sessionClose = Task { @MainActor in await sessions.closeAllResult(deadline: deadline) }
            if cancelTransfers { await transfers.cancelAllAndWait() }
            let sessionResult = await sessionClose.value
            await files?.closeForWindow()
            let result = AppConnectionCloseResult(sessions: sessionResult, transferDecisionRequired: false)
            lastCloseResult = result
            if !result.complete { sessions.issue = SessionController.incompleteCloseIssue }
            if !retainAdmissionFreeze || !result.complete { resumeAfterContinue() }
            else { freezeCloseAdmission() }
            closeTask = nil
            return result
        }
        closeTask = task
        return await task.value
    }
}
