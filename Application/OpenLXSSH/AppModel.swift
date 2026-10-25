import Combine
import Foundation
import OpenLXSSHCore

enum SessionOpenMode: String, Sendable { case reuse, newSession }
struct SessionRequest: Equatable, Sendable {
    let hostID: UUID
    let mode: SessionOpenMode
}
enum SessionRouteResult: Equatable, Sendable {
    case transportUnavailable(SessionRequest)
}

@MainActor protocol SessionRouting: AnyObject {
    func open(_ request: SessionRequest) -> SessionRouteResult
    func closeAll()
}

/// Replacement seam for the later real SSH SessionController. This does not create a session,
/// spawn a process, authenticate, or record a successful connection.
@MainActor final class UnavailableSessionRouter: SessionRouting {
    func open(_ request: SessionRequest) -> SessionRouteResult { .transportUnavailable(request) }
    func closeAll() {}
}

enum SidebarSelection: Hashable {
    case all, favorites, ungrouped, folder(UUID)
    func query(search: String) -> HostQuery {
        switch self {
        case .all: HostQuery(search: search)
        case .favorites: HostQuery(search: search, favoritesOnly: true, sort: .favorites)
        case .ungrouped: HostQuery(search: search, folder: .ungrouped)
        case .folder(let id): HostQuery(search: search, folder: .folder(id))
        }
    }
}

struct AppIssue: Identifiable, Equatable {
    let id = UUID()
    let code: String
    let message: String
    static func sanitized(_ error: Error) -> AppIssue {
        guard let error = error as? RepositoryError else {
            // GRDB/Cocoa descriptions may contain SQL arguments, user paths or external data.
            return AppIssue(code: "storage.failed", message: "无法读取或保存本地数据。请检查 App 专属目录的可用空间与访问权限后重试；不会自动清空数据库。")
        }
        switch error {
        case .invalidField(let field):
            let labels = ["name": "名称", "address": "地址", "username": "用户名", "port": "端口（1–65535）", "folderName": "文件夹名称", "keepalive": "保活（间隔 0–3600 秒，次数 1–10）", "fontName": "字体", "fontSize": "字号（6–72）", "historyLines": "历史行数（0–50000）", "color": "颜色（#RRGGBB）", "authenticationReferences": "认证关联"]
            return AppIssue(code: "validation.invalid", message: "请检查" + (labels[field] ?? "输入字段") + "。")
        case .unsafeDatabaseLocation:
            return AppIssue(code: "storage.unsafeLocation", message: "App 数据目录不安全或不可访问。请检查 Application Support/OpenLXSSH 的所有权与目录类型；不会写入其他位置。")
        case .databaseBusy: return AppIssue(code: "storage.busy", message: "本地数据正在被使用，请稍后重试。")
        case .unsupportedSchema: return AppIssue(code: "storage.newerSchema", message: "数据库来自较新版本。请使用匹配的 App 版本；不会降级或删除数据。")
        case .notFound: return AppIssue(code: "storage.notFound", message: "该记录已不存在，请刷新列表后重试。")
        case .savingNotAuthorized: return AppIssue(code: "credential.notAuthorized", message: "尚未获得安全保存凭据的授权。此版本不会保存密码。")
        default: return AppIssue(code: "storage.referenceConflict", message: "记录存在冲突或仍被其他配置引用，请刷新后检查关联。")
        }
    }
}

@MainActor final class AppModel: ObservableObject {
    let repository: any AppRepositoryProtocol
    private let sessionRouter: any SessionRouting
    @Published private(set) var hosts: [HostConfiguration] = []
    @Published private(set) var folders: [HostFolder] = []
    @Published private(set) var keys: [ManagedKeyReference] = []
    @Published private(set) var settings = AppSettings()
    @Published private(set) var isLoading = false
    @Published private(set) var isWriting = false
    @Published private(set) var didLoad = false
    @Published var issue: AppIssue?
    @Published var selection: SidebarSelection = .all
    @Published var search = ""
    @Published var selectedHostID: UUID?
    @Published private(set) var connectionNotice: SessionRouteResult?
    private var generation = 0

    init(repository: any AppRepositoryProtocol, sessionRouter: any SessionRouting = UnavailableSessionRouter()) {
        self.repository = repository; self.sessionRouter = sessionRouter
    }

    var selectedHost: HostConfiguration? { hosts.first { $0.id == selectedHostID } }

    @discardableResult func reload() async -> Bool {
        generation += 1
        let token = generation
        isLoading = true
        defer { if generation == token { isLoading = false } }
        do {
            let snapshot = try await repository.snapshot(query: selection.query(search: search))
            guard token == generation else { return false }
            hosts = snapshot.hosts; folders = snapshot.folders; keys = snapshot.keys; settings = snapshot.settings
            if let selectedHostID, !hosts.contains(where: { $0.id == selectedHostID }) { self.selectedHostID = nil }
            didLoad = true
            issue = nil
            return true
        } catch {
            guard token == generation else { return false }
            issue = .sanitized(error)
            return false
        }
    }

    @discardableResult private func write(_ operation: () async throws -> Void) async -> Bool {
        guard !isWriting else { return false }
        isWriting = true
        defer { isWriting = false }
        do {
            try await operation()
            return await reload()
        } catch {
            issue = .sanitized(error)
            return false
        }
    }

    @discardableResult func saveHost(_ host: HostConfiguration, isNew: Bool) async -> Bool {
        await write { try await repository.apply([isNew ? .insertHost(host) : .updateHost(host)]) }
    }
    @discardableResult func deleteHost(_ id: UUID) async -> Bool {
        await write { try await repository.apply([.deleteHost(id)]) }
    }
    @discardableResult func copyHost(_ id: UUID) async -> Bool {
        await write { _ = try await repository.copyHost(id: id) }
    }
    @discardableResult func favorite(_ host: HostConfiguration) async -> Bool {
        await write { try await repository.apply([.setFavorite(host.id, !host.isFavorite, order: host.favoriteOrder)]) }
    }
    @discardableResult func saveFolder(_ folder: HostFolder) async -> Bool {
        await write { try await repository.apply([.saveFolder(folder)]) }
    }
    @discardableResult func deleteFolder(_ id: UUID) async -> Bool {
        let success = await write { try await repository.apply([.deleteFolder(id)]) }
        if success, selection == .folder(id) { selection = .all; _ = await reload() }
        return success
    }
    @discardableResult func copyFolder(_ id: UUID) async -> Bool {
        await write { _ = try await repository.copyFolder(id: id) }
    }
    @discardableResult func saveSettings(_ value: AppSettings) async -> Bool {
        guard (0...50_000).contains(value.historyLines) else {
            issue = .sanitized(RepositoryError.invalidField("historyLines")); return false
        }
        return await write { try await repository.apply([.saveSettings(value)]) }
    }

    func requestSession(hostID: UUID, mode: SessionOpenMode) {
        guard hosts.contains(where: { $0.id == hostID }) else { issue = .sanitized(RepositoryError.notFound); return }
        connectionNotice = sessionRouter.open(SessionRequest(hostID: hostID, mode: mode))
    }

    func windowClosed() {
        generation += 1
        sessionRouter.closeAll()
        connectionNotice = nil; selectedHostID = nil; search = ""; selection = .all
        isLoading = false
    }
}

struct HostDraft {
    var configuration: HostConfiguration
    var port: String
    var interval: String
    var count: String
    let isNew: Bool
    init(host: HostConfiguration? = nil, settings: AppSettings, folderID: UUID? = nil) {
        let value = host ?? HostConfiguration(name: "", address: "", username: "", folderID: folderID,
                                             keepaliveInterval: settings.keepaliveInterval, keepaliveCountMax: settings.keepaliveCountMax)
        configuration = value; port = String(value.port); interval = String(value.keepaliveInterval); count = String(value.keepaliveCountMax)
        isNew = host == nil
    }
    mutating func changeAuthentication(_ kind: AuthenticationKind) {
        guard kind != configuration.authentication else { return }
        configuration.authentication = kind
        configuration.credentialRef = nil; configuration.savePasswordAuthorized = false; configuration.keyRef = nil
    }
    func value() throws -> HostConfiguration {
        var result = configuration
        guard let port = Int(port) else { throw RepositoryError.invalidField("port") }
        guard let interval = Int(interval), let count = Int(count) else { throw RepositoryError.invalidField("keepalive") }
        result.port = port; result.keepaliveInterval = interval; result.keepaliveCountMax = count
        return result
    }
}

struct SettingsDraft {
    var value: AppSettings
    var history: String
    var size: String
    var interval: String
    var count: String
    init(_ value: AppSettings) {
        self.value = value; history = String(value.historyLines); size = String(value.fontSize)
        interval = String(value.keepaliveInterval); count = String(value.keepaliveCountMax)
    }
    func validated() throws -> AppSettings {
        var result = value
        guard let history = Int(history), (0...50_000).contains(history) else { throw RepositoryError.invalidField("historyLines") }
        guard let size = Double(size) else { throw RepositoryError.invalidField("fontSize") }
        guard let interval = Int(interval), let count = Int(count) else { throw RepositoryError.invalidField("keepalive") }
        result.historyLines = history; result.fontSize = size; result.keepaliveInterval = interval; result.keepaliveCountMax = count
        return result
    }
}

extension AuthenticationKind {
    var displayName: String {
        switch self {
        case .password: "用户名与密码"
        case .passwordWithMFA: "密码与手机验证码 / MFA"
        case .privateKey: "SSH 私钥"
        case .privateKeyWithMFA: "私钥与手机验证码 / MFA"
        }
    }
    var needsKey: Bool { self == .privateKey || self == .privateKeyWithMFA }
    static var choices: [AuthenticationKind] { [.password, .passwordWithMFA, .privateKey, .privateKeyWithMFA] }
}

enum ColorPreset: String, CaseIterable {
    case nord = "Nord", solarized = "Solarized", classic = "Classic", custom = "自定义"
    var colors: (String, String, String) {
        switch self {
        case .nord: ("#D8DEE9", "#20242C", "#D8DEE9")
        case .solarized: ("#839496", "#002B36", "#93A1A1")
        case .classic: ("#E5E5E5", "#000000", "#00FF00")
        case .custom: ("#D8DEE9", "#20242C", "#D8DEE9")
        }
    }
    static func matching(_ value: AppSettings) -> ColorPreset {
        allCases.first { $0 != .custom && $0.colors == (value.foregroundColor, value.backgroundColor, value.cursorColor) } ?? .custom
    }
}
