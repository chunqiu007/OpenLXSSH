import AppKit
import Combine
import Foundation
import OpenLXSSHCore
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
}
struct SessionAuthenticationPrompt: Identifiable, Equatable {
    let token: SessionToken
    let id: UUID
    let kind: AuthenticationChallengeKind
    let text: String
}

/// Logic-test doubles implement this boundary, never a second SSH/PTY implementation.
@MainActor protocol SessionDriving: AnyObject {
    var terminal: NativeTerminalView { get }
    var token: SessionToken? { get }
    var state: SSHSessionState { get }
    var canReconnect: Bool { get }
    var onState: ((SessionToken?, SSHSessionState) -> Void)? { get set }
    var onTrust: (([SessionTrustPrompt]) -> Void)? { get set }
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)? { get set }
    func connect(_ configuration: SSHSessionConfiguration, savedPassword: SavedPasswordAuthorization?) throws -> SessionToken
    func accept(_ prompt: SessionTrustPrompt) async throws
    func respond(_ response: AuthenticationResponse, to prompt: SessionAuthenticationPrompt) throws
    func cancel()
    func closeTab()
}

@MainActor final class DirectSessionDriver: SessionDriving {
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
    func accept(_ prompt: SessionTrustPrompt) async throws {
        guard let challenge = prompt.transport, token == prompt.token else { throw TransportError.stale }
        try await session.acceptTrust(challenge, displayedFingerprint: prompt.fingerprint)
    }
    func respond(_ response: AuthenticationResponse, to prompt: SessionAuthenticationPrompt) throws {
        try session.respond(response, requestID: prompt.id, token: prompt.token)
    }
    func cancel() { session.cancel() }
    func closeTab() { session.closeTab() }
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

@MainActor final class SessionTab: ObservableObject, Identifiable {
    let id: UUID
    let hostID: UUID
    @Published var title: String
    @Published var state: SSHSessionState = .preparing
    @Published var issue: AppIssue?
    @Published var trust: [SessionTrustPrompt] = []
    @Published var authentication: SessionAuthenticationPrompt?
    var driver: (any SessionDriving)?
    var host: HostConfiguration?
    var configuration: SSHSessionConfiguration?
    var preparation: Task<Void, Never>?
    var operation = UUID()
    var lastActivity: UInt64 = 0
    var markedGeneration: UInt64?
    init(id: UUID = UUID(), host: HostConfiguration) { self.id = id; hostID = host.id; title = host.name }
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
        switch state {
        case .idle: "未连接"
        case .preparing: "准备连接"
        case .awaitingTrust: "等待主机身份核实"
        case .authenticating: "等待认证输入"
        case .connectionPending: "连接中／尚未确认认证"
        case .connected: "外层已认证（不证明 shell 就绪）"
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

@MainActor final class SessionController: ObservableObject {
    @Published private(set) var tabs: [SessionTab] = []
    @Published private(set) var selectedTabID: UUID?
    @Published private(set) var closingAll = false
    @Published private(set) var terminating = false
    @Published var issue: AppIssue?
    private var closeAllTask: Task<Void, Never>?
    private var tabCloseTasks: [UUID: Task<Void, Never>] = [:]
    private let repository: any AppRepositoryProtocol
    private let credentials: any CredentialAccess
    private let builder: any SessionBuilding
    private var settings = AppSettings()
    private var activity: UInt64 = 0
    var onAuthenticatedMetadata: (() -> Void)?
    init(repository: any AppRepositoryProtocol, credentials: any CredentialAccess, builder: any SessionBuilding) {
        self.repository = repository; self.credentials = credentials; self.builder = builder
    }
    var selectedTab: SessionTab? { tabs.first { $0.id == selectedTabID } }
    @discardableResult func open(_ host: HostConfiguration, mode: SessionOpenMode) -> UUID? {
        guard !closingAll, !terminating else { return nil }
        if mode == .reuse, let existing = tabs.filter({ $0.hostID == host.id && $0.isReusable }).max(by: { $0.lastActivity < $1.lastActivity }) {
            select(existing.id); return existing.id
        }
        let tab = SessionTab(host: host)
        tabs.append(tab); select(tab.id)
        prepare(tab)
        return tab.id
    }
    func select(_ id: UUID) {
        guard tabs.contains(where: { $0.id == id }) else { return }
        selectedTabID = id; activity &+= 1
        for tab in tabs { tab.driver?.terminal.setVisible(tab.id == id); if tab.id == id { tab.lastActivity = activity } }
    }
    private func prepare(_ tab: SessionTab) {
        let operation = UUID(); tab.operation = operation; tab.state = .preparing; tab.issue = nil
        tab.preparation = Task { [weak self, weak tab] in
            guard let self, let tab else { return }
            defer { tab.preparation = nil; tab.objectWillChange.send() }
            do {
                let ready = try await builder.prepare(hostID: tab.hostID, sessionID: tab.id)
                guard !Task.isCancelled, tab.operation == operation, tabs.contains(where: { $0 === tab }) else {
                    ready.driver.closeTab(); return
                }
                tab.driver = ready.driver; tab.host = ready.host; tab.title = ready.host.name; tab.configuration = ready.configuration
                installCallbacks(tab)
                try applySettings(to: ready.driver.terminal)
                ready.driver.terminal.setVisible(selectedTabID == tab.id)
                _ = try ready.driver.connect(ready.configuration, savedPassword: authorization(for: tab))
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
            if state != .awaitingTrust { tab.trust = [] }
            if state != .authenticating { tab.authentication = nil }
            if state == .connected, let token, tab.markedGeneration != token.generation {
                tab.markedGeneration = token.generation
                Task { [weak self, repository] in
                    do { try await repository.apply([.markConnected(tab.hostID, Date())]); self?.onAuthenticatedMetadata?() }
                    catch { self?.issue = .session(error) }
                }
            }
            self.objectWillChange.send()
        }
        driver.onTrust = { [weak tab, weak driver] prompts in
            guard let tab, let driver, tab.driver === driver, tab.state == .awaitingTrust else { return }
            tab.trust = prompts.filter { $0.token == driver.token }
        }
        driver.onAuthentication = { [weak tab, weak driver] prompt in
            guard let tab, let driver, tab.driver === driver, prompt.token == driver.token, tab.state == .authenticating else { return }
            tab.authentication = prompt
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
              before.hosts.contains(where: { $0 == host }), before.credentials.contains(where: { $0.id == ref && $0.purpose == .password && $0.isSavingAuthorized }) else { return nil }
        let result = await credentials.read(.init(id: ref, kind: .password))
        guard !Task.isCancelled, isCurrent(token, tab: tabs.first { $0.id == tabID }, host: host),
              case .available(let secret) = result else { return nil }
        let after = try await repository.securityMetadata()
        guard !Task.isCancelled, after.hosts.contains(where: { $0 == host }), after.credentials.contains(where: { $0.id == ref && $0.purpose == .password && $0.isSavingAuthorized }),
              isCurrent(token, tab: tabs.first { $0.id == tabID }, host: host) else { return nil }
        return try secret.withUnsafeBytes { try AuthenticationSecret(Data($0)) }
    }
    private func isCurrent(_ token: SessionToken, tab: SessionTab?, host: HostConfiguration) -> Bool {
        guard !closingAll, !terminating, let tab, tabs.contains(where: { $0 === tab }), tab.host == host, tab.driver?.token == token else { return false }
        return tab.isReusable
    }
    func reconnect(_ id: UUID) {
        guard !closingAll, !terminating, let tab = tabs.first(where: { $0.id == id }), tab.canReconnect else { return }
        guard let driver = tab.driver else { prepare(tab); return }
        // Keep the same driver/view, but refresh Core configuration and authorization before a new generation.
        let operation = UUID(); tab.operation = operation; tab.state = .preparing; tab.issue = nil
        tab.preparation = Task { [weak self, weak tab] in
            guard let self, let tab else { return }
            defer { tab.preparation = nil; tab.objectWillChange.send() }
            do {
                let (host, configuration) = try await builder.configuration(hostID: tab.hostID)
                guard tab.operation == operation, !Task.isCancelled else { throw TransportError.stale }
                tab.host = host; tab.title = host.name; tab.configuration = configuration
                _ = try driver.connect(configuration, savedPassword: authorization(for: tab))
            } catch { if tab.operation == operation { tab.state = .failed(.invalidConfiguration); tab.issue = .session(error) } }
        }
    }
    func disconnect(_ id: UUID) {
        guard let tab = tabs.first(where: { $0.id == id }) else { return }
        guard tab.state != .closing && tab.state != .closed else { return }
        tab.operation = UUID(); tab.preparation?.cancel()
        tab.trust = []; tab.authentication = nil
        if let driver = tab.driver { driver.cancel() } else { tab.state = .disconnected(nil) }
    }
    func closeTab(_ id: UUID) async {
        if let task = tabCloseTasks[id] { await task.value; return }
        guard let tab = tabs.first(where: { $0.id == id }) else { return }
        // Revoke admission/requests synchronously before the cleanup task can
        // suspend. Every caller awaits this exact tab object's single cleanup.
        tab.operation = UUID(); let preparation = tab.preparation; preparation?.cancel()
        tab.state = .closing; tab.trust = []; tab.authentication = nil
        let task = Task { @MainActor in
            await preparation?.value
            tab.preparation = nil; tab.driver?.closeTab()
            while let driver = tab.driver, driver.state != .closed { try? await Task.sleep(for: .milliseconds(20)) }
            tab.driver?.onState = nil; tab.driver?.onTrust = nil; tab.driver?.onAuthentication = nil
            tabs.removeAll { $0 === tab }
            if selectedTabID == id {
                selectedTabID = nil
                if let next = tabs.max(by: { $0.lastActivity < $1.lastActivity }) { select(next.id) }
            }
            tabCloseTasks[id] = nil
        }
        tabCloseTasks[id] = task
        await task.value
    }
    /// Permanent process-lifetime admission revocation. Window close does not
    /// call this; quit does, before its first asynchronous cleanup boundary.
    func beginTermination() {
        terminating = true
        for tab in tabs { tab.trust = []; tab.authentication = nil }
    }
    func closeAll() async {
        if let task = closeAllTask { await task.value; return }
        closingAll = true
        let ids = tabs.map(\.id)
        for tab in tabs {
            tab.operation = UUID(); tab.preparation?.cancel()
            tab.state = .closing; tab.trust = []; tab.authentication = nil
        }
        let task = Task { @MainActor in
            for id in ids { await closeTab(id) }
            selectedTabID = nil
            closeAllTask = nil
            closingAll = false
        }
        closeAllTask = task
        // Waiter cancellation must not cancel the app-owned resource cleanup.
        await task.value
    }
    func accept(_ prompt: SessionTrustPrompt, tabID: UUID) async -> Bool {
        guard !closingAll, !terminating, let tab = tabs.first(where: { $0.id == tabID }), tab.state == .awaitingTrust,
              tab.trust.contains(prompt), tab.driver?.token == prompt.token, let driver = tab.driver else { return false }
        do { try await driver.accept(prompt); return true }
        catch { tab.issue = .session(error); return false }
    }
    func respond(_ response: AuthenticationResponse, to prompt: SessionAuthenticationPrompt, tabID: UUID) -> Bool {
        guard !closingAll, !terminating, let tab = tabs.first(where: { $0.id == tabID }), tab.authentication == prompt,
              tab.state == .authenticating, tab.driver?.token == prompt.token, let driver = tab.driver else { return false }
        do { try driver.respond(response, to: prompt); tab.authentication = nil; return true }
        catch { tab.issue = .session(error); return false }
    }
    func updateSettings(_ settings: AppSettings) {
        self.settings = settings
        for tab in tabs { if let terminal = tab.driver?.terminal { do { try applySettings(to: terminal) } catch { tab.issue = .session(error) } } }
    }
    private func applySettings(to terminal: NativeTerminalView) throws {
        let fontName = settings.fontName == "SFMono-Regular" ? NSFont.monospacedSystemFont(ofSize: settings.fontSize, weight: .regular).fontName : settings.fontName
        try terminal.setFont(name: fontName, size: settings.fontSize)
        terminal.setHistoryLimit(settings.historyLines)
        terminal.appearance = settings.theme == .system ? nil : NSAppearance(named: settings.theme == .dark ? .darkAqua : .aqua)
        if ColorPreset.matching(settings) == .nord {
            terminal.setColorMode(.system)
        } else {
            terminal.setColors(foreground: NSColor(sessionHex: settings.foregroundColor), background: NSColor(sessionHex: settings.backgroundColor), cursor: NSColor(sessionHex: settings.cursorColor))
        }
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
@MainActor final class AppLifecycleCoordinator {
    let sessions: SessionController
    var transfers: any TransferLifecycle
    init(sessions: SessionController, transfers: any TransferLifecycle = NoTransfers()) { self.sessions = sessions; self.transfers = transfers }
    var requiresTransferDecision: Bool { transfers.hasActiveTransfers }
    var terminating: Bool { sessions.terminating }
    func beginTermination() { sessions.beginTermination() }
    func closeConnections(cancelTransfers: Bool = false) async -> Bool {
        if transfers.hasActiveTransfers && !cancelTransfers { return false }
        if cancelTransfers { await transfers.cancelAllAndWait() }
        await sessions.closeAll(); return true
    }
}
