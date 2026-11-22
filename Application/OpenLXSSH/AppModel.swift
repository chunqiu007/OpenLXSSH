import AppKit
import Foundation
import Observation
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHTransport

enum SessionOpenMode: String, Sendable { case reuse, newSession }
struct VaultHostFocusRequest: Identifiable, Equatable, Sendable {
    let id = UUID()
    let hostID: UUID
}
struct SessionRequest: Equatable, Sendable {
    let hostID: UUID
    let mode: SessionOpenMode
}
enum SessionRouteResult: Equatable, Sendable {
    case opened(SessionRequest, UUID)
    /// A recording-only boundary for unit tests; not used by the production App.
    case transportUnavailable(SessionRequest)
}

@MainActor protocol SessionRouting: AnyObject {
    func open(_ request: SessionRequest) -> SessionRouteResult
    func closeAll()
}

enum WorkspacePage: Equatable {
    case vault, sftp, session(UUID)
    var sessionID: UUID? { if case .session(let id) = self { id } else { nil } }
}
struct WorkspaceInteractionContext: Equatable {
    var hasAttachedSheet = false
    var hasModalWindow = false
    var hasOtherKeyWindow = false
    var isEditingText = false
    var allowsWorkspaceActions: Bool { !hasAttachedSheet && !hasModalWindow && !hasOtherKeyWindow }
    var allowsWorkspaceSearch: Bool { allowsWorkspaceActions && !isEditingText }
    func allowsWorkspaceFind(hasMarkedText: Bool) -> Bool { allowsWorkspaceActions && !hasMarkedText }
}

/// Geometry reported by the horizontal session ScrollView, in its content coordinates.
/// Navigation uses real tab edges, never an assumed tab width or a window-wide offset.
struct WorkspaceTabViewport: Equatable {
    let visibleRect: CGRect
    let contentWidth: CGFloat
    var canGoBack: Bool { visibleRect.minX > 0 }
    var canGoForward: Bool { visibleRect.maxX < contentWidth }
    func navigationTarget(in orderedIDs: [UUID], frames: [UUID: CGRect], forwards: Bool) -> UUID? {
        guard forwards ? canGoForward : canGoBack else { return nil }
        if forwards { return orderedIDs.first { frames[$0].map { $0.maxX > visibleRect.maxX } ?? false } }
        return orderedIDs.reversed().first { frames[$0].map { $0.minX < visibleRect.minX } ?? false }
    }
    func contains(_ frame: CGRect) -> Bool { frame.minX >= visibleRect.minX && frame.maxX <= visibleRect.maxX }
}

/// A tab-local transparent hit target. All primary/right/modifier events fall through
/// to the existing SwiftUI buttons, drag and context menu. No event monitor is installed.
@MainActor final class WorkspaceTabMiddleClickView: NSView {
    var closeAction: (() -> Void)?
    private var pressed = false
    func owns(_ event: NSEvent) -> Bool {
        guard event.type == .otherMouseDown || event.type == .otherMouseUp,
              event.buttonNumber == 2, event.modifierFlags.intersection([.command, .control, .option, .shift]).isEmpty,
              let window, event.window === window, window.attachedSheet == nil,
              NSApp.modalWindow == nil, !isHiddenOrHasHiddenAncestor else { return false }
        return bounds.contains(convert(event.locationInWindow, from: nil))
    }
    override func hitTest(_ point: NSPoint) -> NSView? {
        guard let event = NSApp.currentEvent, owns(event), bounds.contains(convert(point, from: superview)) else { return nil }
        return self
    }
    override func otherMouseDown(with event: NSEvent) { pressed = owns(event) }
    override func otherMouseUp(with event: NSEvent) {
        let closes = pressed && owns(event)
        pressed = false
        if closes { closeAction?() }
    }
    override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); pressed = false }
    override var acceptsFirstResponder: Bool { false }
}

/// Only NSWindow's built-in non-secret frame autosave is persisted. Screen recovery
/// is pure geometry so missing displays and malformed frames can be tested in isolation.
enum MainWindowFramePreferences {
    static let autosaveName = "OpenLXSSH.MainWindow.v1"
    static let minimumSize = NSSize(width: 920, height: 580)
    static func recoveredFrame(_ saved: NSRect, visibleFrames: [NSRect]) -> NSRect {
        func usable(_ rect: NSRect) -> Bool {
            [rect.origin.x, rect.origin.y, rect.width, rect.height].allSatisfy(\.isFinite) && rect.width > 0 && rect.height > 0
        }
        let screens = visibleFrames.filter(usable)
        guard let first = screens.first else { return NSRect(origin: .zero, size: minimumSize) }
        let valid = usable(saved)
        let screen = valid ? (screens.max { a, b in
            let aa = a.intersection(saved), bb = b.intersection(saved)
            return (aa.isNull ? 0 : aa.width * aa.height) < (bb.isNull ? 0 : bb.width * bb.height)
        } ?? first) : first
        let intersects = valid && screens.contains { $0.intersects(saved) }
        let size = NSSize(width: min(screen.width, max(minimumSize.width, valid ? saved.width : 1120)),
                          height: min(screen.height, max(minimumSize.height, valid ? saved.height : 720)))
        let proposed = intersects ? saved.origin : NSPoint(x: screen.midX - size.width / 2, y: screen.midY - size.height / 2)
        return NSRect(x: min(max(proposed.x, screen.minX), screen.maxX - size.width),
                      y: min(max(proposed.y, screen.minY), screen.maxY - size.height), width: size.width, height: size.height)
    }
}

enum WorkspaceCommand: Equatable { case newConnection, newHost, newFilesHost, settings, diagnostics, search, connectionInfo }
struct WorkspaceCommandRequest: Identifiable, Equatable {
    let id = UUID()
    let command: WorkspaceCommand
    let page: WorkspacePage
}

enum AppCloseIntent: Equatable, Sendable { case window, quit }

/// Intent coalescing only. AppDelegate's existing closeFlow and the lifecycle closeTask
/// remain the sole owners of resource cleanup.
struct AppCloseRequestState {
    private(set) var id: UUID?
    private(set) var intent: AppCloseIntent?
    private(set) var approved = false
    @discardableResult mutating func request(_ intent: AppCloseIntent) -> Bool {
        if id != nil {
            if intent == .quit { self.intent = .quit }
            return false
        }
        id = UUID(); self.intent = intent; approved = false
        return true
    }
    mutating func approve() { if id != nil { approved = true } }
    mutating func reset() { id = nil; intent = nil; approved = false }
}

/// Single-resolution MainActor signal shared by close reviews and overlay dismissal.
@MainActor private final class WindowCloseReviewSignal {
    private(set) var result: Bool?
    private var waiters: [CheckedContinuation<Bool, Never>] = []

    func resolve(_ value: Bool) {
        guard result == nil else { return }
        result = value
        let pending = waiters
        waiters.removeAll()
        for waiter in pending {
            waiter.resume(returning: value)
        }
    }

    func wait() async -> Bool {
        if let result { return result }
        if Task.isCancelled {
            resolve(false)
            return false
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if let result {
                    continuation.resume(returning: result)
                } else if Task.isCancelled {
                    resolve(false)
                    continuation.resume(returning: false)
                } else {
                    waiters.append(continuation)
                }
            }
        } onCancel: {
            Task { @MainActor in self.resolve(false) }
        }
    }

    isolated deinit {
        resolve(false)
    }
}

/// One close attempt, not a reusable permission. Owners install a weak validation
/// checkpoint so a late answer cannot authorize a later form or workspace generation.
@MainActor final class WindowCloseReviewRequest {
    let id = UUID()
    private let signal = WindowCloseReviewSignal()
    private var validations: [@MainActor () -> Bool] = []
    var result: Bool? { signal.result }
    var isApprovedAndCurrent: Bool { result == true && validations.allSatisfy { $0() } }
    func validateApproval(_ action: @escaping @MainActor () -> Bool) { validations.append(action) }
    func resolve(_ allowed: Bool) { signal.resolve(allowed) }
    func cancel() { signal.resolve(false) }
    func wait() async -> Bool { await signal.wait() }
    isolated deinit { signal.resolve(false) }
}

@MainActor final class WindowCloseReviewRegistry {
    private struct Registration {
        let owner: UUID
        let begin: @MainActor (WindowCloseReviewRequest) -> Void
        let cancel: @MainActor () -> Void
    }
    private var registration: Registration?
    private var preferencesRegistration: Registration?
    private var preferencesReview: (owner: UUID, request: WindowCloseReviewRequest, removed: WindowCloseReviewSignal)?
    private var chainTask: Task<Void, Never>?
    private var revision = UUID()
    private var pending: (revision: UUID, request: WindowCloseReviewRequest)?
    func register(owner: UUID, begin: @escaping @MainActor (WindowCloseReviewRequest) -> Void,
                  cancel: @escaping @MainActor () -> Void) {
        if registration?.owner != owner { cancelAttempt() }
        registration = Registration(owner: owner, begin: begin, cancel: cancel)
    }
    func clear(owner: UUID) {
        guard registration?.owner == owner else { return }
        cancelAttempt()
        registration = nil
    }
    /// Settings is an overlay, not a replacement for the mounted Vault editor guard.
    func registerPreferences(owner: UUID, begin: @escaping @MainActor (WindowCloseReviewRequest) -> Void,
                             cancel: @escaping @MainActor () -> Void) {
        if preferencesRegistration?.owner != owner { cancelAttempt() }
        preferencesRegistration = Registration(owner: owner, begin: begin, cancel: cancel)
    }
    func clearPreferences(owner: UUID) {
        guard preferencesRegistration?.owner == owner else { return }
        preferencesRegistration = nil
        if let review = preferencesReview, review.owner == owner, review.request.isApprovedAndCurrent {
            // The exact approved sheet has actually left the hierarchy. Only now may
            // the underlying owner present its own Save / Discard / Cancel review.
            review.removed.resolve(true)
        } else {
            cancelAttempt()
        }
    }
    func request() -> WindowCloseReviewRequest {
        if let pending, pending.request.result == nil { return pending.request }
        let request = WindowCloseReviewRequest()
        pending = (revision, request)
        if let overlay = preferencesRegistration {
            let child = WindowCloseReviewRequest()
            let removed = WindowCloseReviewSignal()
            preferencesReview = (overlay.owner, child, removed)
            request.validateApproval { child.isApprovedAndCurrent }
            chainTask = Task { @MainActor [weak self] in
                guard await child.wait(), await removed.wait(), !Task.isCancelled,
                      let self, self.pending?.request === request,
                      self.pending?.revision == self.revision, child.isApprovedAndCurrent else {
                    request.resolve(false)
                    return
                }
                if let registration = self.registration {
                    registration.begin(request)
                } else {
                    request.resolve(true)
                }
            }
            overlay.begin(child)
        } else if let registration {
            registration.begin(request)
        } else {
            request.resolve(true)
        }
        return request
    }
    func isCurrent(_ request: WindowCloseReviewRequest) -> Bool {
        pending?.request === request && pending?.revision == revision && request.isApprovedAndCurrent
    }
    func finishAttempt() { cancelAttempt() }
    private func cancelAttempt() {
        revision = UUID()
        pending?.request.cancel()
        pending = nil
        preferencesReview?.request.cancel()
        preferencesReview?.removed.resolve(false)
        preferencesReview = nil
        chainTask?.cancel()
        chainTask = nil
        registration?.cancel()
        preferencesRegistration?.cancel()
    }
    func invalidate() {
        cancelAttempt()
        registration = nil
        preferencesRegistration = nil
    }
    isolated deinit {
        pending?.request.cancel()
        preferencesReview?.request.cancel()
        preferencesReview?.removed.resolve(false)
        chainTask?.cancel()
    }
}

struct HostConnectionIdentity: Equatable {
    let address: String
    let port: Int
    let username: String
    let authentication: AuthenticationKind
    let keyRef: UUID?
    let credentialRef: UUID?
    let savePasswordAuthorized: Bool
    let keepaliveInterval: Int
    let keepaliveCountMax: Int
}
extension HostConfiguration {
    var connectionIdentity: HostConnectionIdentity {
        HostConnectionIdentity(address: address, port: port, username: username, authentication: authentication,
            keyRef: keyRef, credentialRef: credentialRef, savePasswordAuthorized: savePasswordAuthorized,
            keepaliveInterval: keepaliveInterval, keepaliveCountMax: keepaliveCountMax)
    }

    /// Request/authorization comparisons include the stable row identity and
    /// connection parameters, but intentionally ignore display-only metadata.
    func matchesConnection(of other: HostConfiguration) -> Bool {
        id == other.id && connectionIdentity == other.connectionIdentity
    }
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
        if error is AppStorageFailure {
            return AppIssue(code: "storage.committedUnsafe", message: "配置已提交，但提交后的专属目录权限／ACL 核验失败。请勿重复新建；先自行核实权限，App 不会删除 ACL 或回滚已提交资源。")
        }
        guard let error = error as? RepositoryError else {
            // GRDB/Cocoa descriptions may contain SQL arguments, user paths or external data.
            return AppIssue(code: "storage.failed", message: "无法读取或保存本地数据。请检查 App 专属目录的可用空间与访问权限后重试；不会自动清空数据库。")
        }
        switch error {
        case .invalidField(let field):
            let labels = ["name": "名称", "address": "地址", "username": "用户名", "port": "端口（1–65535）", "folderName": "文件夹名称", "keepalive": "TCP 保活（空闲/重试间隔 0–3600 秒，失败探测次数 1–10）", "fontName": "字体", "fontSize": "字号（6–72）", "historyLines": "历史行数（0–50000）", "color": "颜色（#RRGGBB）", "authenticationReferences": "认证关联"]
            return AppIssue(code: "validation.invalid", message: "请检查" + (labels[field] ?? "输入字段") + "。")
        case .unsafeDatabaseLocation:
            return AppIssue(code: "storage.unsafeLocation", message: "App 专属数据目录或文件的所有权、权限或扩展 ACL 不安全／无法核验。已拒绝操作；请在 Finder 信息或系统权限工具中核实，App 不会静默删除 ACL、清空数据或写入其他位置。")
        case .databaseBusy: return AppIssue(code: "storage.busy", message: "本地数据正在被使用，请稍后重试。")
        case .unsupportedSchema: return AppIssue(code: "storage.newerSchema", message: "数据库来自较新版本。请使用匹配的 App 版本；不会降级或删除数据。")
        case .notFound: return AppIssue(code: "storage.notFound", message: "该记录已不存在，请刷新列表后重试。")
        case .staleRecord: return AppIssue(code: "storage.staleRecord", message: "原记录或标签关联已变化，未覆盖当前配置。请重新载入当前记录后再编辑；已解除的认证或凭据授权不会恢复。")
        case .savingNotAuthorized: return AppIssue(code: "credential.notAuthorized", message: "尚未获得安全保存凭据的授权。此版本不会保存密码。")
        default: return AppIssue(code: "storage.referenceConflict", message: "记录存在冲突或仍被其他配置引用，请刷新后检查关联。")
        }
    }
}

@Observable @MainActor final class AppModel {
    let repository: any AppRepositoryProtocol
    let security: SecurityCoordinator
    let sessions: SessionController
    let files: FilesController
    let lifecycle: AppLifecycleCoordinator
    let sessionEnvironment: SessionEnvironment
    let sessionBuilders: AppSessionBuilders
    private let sessionRouter: (any SessionRouting)?
    private let nativeCandidateBuilder: any SessionBuilding
    private let preferencesDefaults: UserDefaults?
    @ObservationIgnored private var didRestoreManagementPage = false
    private(set) var hosts: [HostConfiguration] = []
    private(set) var folders: [HostFolder] = []
    private(set) var keys: [ManagedKeyReference] = []
    private(set) var settings = AppSettings()
    private(set) var isLoading = false
    private(set) var isWriting = false
    private(set) var didLoad = false
    var issue: AppIssue?
    var selection: SidebarSelection = .all
    var search = ""
    var selectedHostID: UUID?
    private(set) var connectionHosts: [HostConfiguration] = []
    private(set) var connectionNotice: SessionRouteResult?
    private(set) var workspacePage: WorkspacePage = .vault
    private(set) var workspaceCommand: WorkspaceCommandRequest?
    private(set) var hostSearchFocusRequest: UUID?
    private(set) var vaultHostFocusRequest: VaultHostFocusRequest? {
        didSet {
            guard let request = vaultHostFocusRequest else { return }
            vaultHostFocusObservers = vaultHostFocusObservers.filter { $0(request) }
        }
    }
    @ObservationIgnored private var vaultHostFocusObservers: [@MainActor (VaultHostFocusRequest) -> Bool] = []
    func observeVaultHostFocus(_ deliver: @escaping @MainActor (VaultHostFocusRequest) -> Bool) {
        if let request = vaultHostFocusRequest {
            guard deliver(request) else { return }
        }
        vaultHostFocusObservers.append(deliver)
    }
    // Window lifetime is independent of repeated refreshes of the same query.
    @ObservationIgnored private var generation = 0
    private struct ReloadFlight: Sendable {
        let id: UUID
        let query: HostQuery
        let lifetime: Int
        var requested: UInt64
        let task: Task<Bool, Never>
    }
    @ObservationIgnored private var reloadFlight: ReloadFlight?
    @ObservationIgnored private var reloadSequence: UInt64 = 0
    @ObservationIgnored private var metadataObservation: Task<Void, Never>?
    @ObservationIgnored private var observingMetadata = false
    @ObservationIgnored private var workspaceNavigationGuard: (owner: UUID, action: @MainActor () -> Bool)?
    private let windowCloseReviews = WindowCloseReviewRegistry()
    func registerWindowCloseReview(owner: UUID, begin: @escaping @MainActor (WindowCloseReviewRequest) -> Void,
                                   cancel: @escaping @MainActor () -> Void) {
        windowCloseReviews.register(owner: owner, begin: begin, cancel: cancel)
    }
    func clearWindowCloseReview(owner: UUID) { windowCloseReviews.clear(owner: owner) }
    func registerPreferencesCloseReview(owner: UUID, begin: @escaping @MainActor (WindowCloseReviewRequest) -> Void,
                                       cancel: @escaping @MainActor () -> Void) {
        windowCloseReviews.registerPreferences(owner: owner, begin: begin, cancel: cancel)
    }
    func clearPreferencesCloseReview(owner: UUID) { windowCloseReviews.clearPreferences(owner: owner) }
    func requestWindowCloseReview() -> WindowCloseReviewRequest { windowCloseReviews.request() }
    func isWindowCloseReviewCurrent(_ request: WindowCloseReviewRequest) -> Bool { windowCloseReviews.isCurrent(request) }
    func finishWindowCloseReview() { windowCloseReviews.finishAttempt() }
    func registerWorkspaceNavigationGuard(owner: UUID, action: @escaping @MainActor () -> Bool) {
        workspaceNavigationGuard = (owner, action)
    }
    func clearWorkspaceNavigationGuard(owner: UUID) {
        if workspaceNavigationGuard?.owner == owner { workspaceNavigationGuard = nil }
    }
    deinit { metadataObservation?.cancel(); reloadFlight?.task.cancel() }

    init(repository: any AppRepositoryProtocol, sessionRouter: (any SessionRouting)? = nil, security suppliedSecurity: SecurityCoordinator? = nil,
         sessionEnvironment suppliedEnvironment: SessionEnvironment? = nil,
         location: AppDataLocation = .applicationSupport, sessionBuilder: (any SessionBuilding)? = nil,
         nativeCandidateBuilder suppliedCandidate: (any SessionBuilding)? = nil,
         filesConnector: (any FilesConnecting)? = nil, preferencesDefaults: UserDefaults? = nil,
         filesLocalService: @escaping @Sendable (Int32) throws -> any RemoteFileService = { try LocalFileService(rootDirectoryDescriptor: $0) }) {
        self.repository = repository
        self.sessionRouter = sessionRouter; self.preferencesDefaults = preferencesDefaults
        let security = suppliedSecurity ?? SecurityCoordinator(repository: repository, location: location)
        self.security = security
        let environment = suppliedEnvironment ?? SessionEnvironment(location: location); sessionEnvironment = environment
        let selection = AppSessionBuilders(repository: repository, security: security, environment: environment,
                                           ordinary: sessionBuilder, prepared: suppliedCandidate)
        sessionBuilders = selection
        let builder = selection.ordinary
        nativeCandidateBuilder = selection.prepared
        let connector = filesConnector ?? LibSSH2FilesConnector(repository: repository, security: security, environment: environment)
        sessions = SessionController(repository: repository, credentials: security.credentials, builder: builder)
        let localBrowserRoot: URL?
        switch location {
        case .isolated(let root): localBrowserRoot = root.appendingPathComponent("LocalFilesFixture", isDirectory: true)
        case .applicationSupport: localBrowserRoot = nil
        }
        files = FilesController(connector: connector, localService: filesLocalService, localBrowserRoot: localBrowserRoot)
        sessions.trustEnvironment = environment
        files.trustEnvironment = environment
        lifecycle = AppLifecycleCoordinator(sessions: sessions)
        lifecycle.files = files
        sessions.setWorkspaceVisible(false)
        sessions.onSelectionChanged = { [weak self] id in
            guard let self, case .session = workspacePage else { return }
            workspacePage = id.map(WorkspacePage.session) ?? .vault
            sessions.setWorkspaceVisible(id != nil)
        }
        sessions.onAuthenticatedMetadata = { [weak self] in Task { await self?.reload() } }
        sessions.onShowConfiguration = { [weak self] id in self?.showConnectionConfiguration(id) }
    }

    var selectedHost: HostConfiguration? { hosts.first { $0.id == selectedHostID } }
    /// Isolated probe/model owners never touch the process-wide NSWindow autosave domain.
    var mainWindowFrameAutosaveName: String? {
        guard let preferencesDefaults else { return nil }
        return preferencesDefaults === UserDefaults.standard ? MainWindowFramePreferences.autosaveName : nil
    }
    var desktopPreferencesDefaults: UserDefaults? { preferencesDefaults }

    @discardableResult func reload() async -> Bool {
        let query = selection.query(search: search), lifetime = generation
        if !observingMetadata {
            observingMetadata = true
            let stream = await repository.metadataChanges()
            metadataObservation = Task { [weak self] in
                for await _ in stream {
                    guard !Task.isCancelled else { return }
                    guard let lifetime = self?.generation else { return }
                    let metadata = try? await self?.repository.securityMetadata()
                    guard !Task.isCancelled else { return }
                    guard let self, lifetime == generation else { continue }
                    if let metadata { sessions.metadataDidRefresh(metadata) }
                    // Current-window revocation is never queued behind a GUI read. Keep
                    // observing while the single current-query worker drains.
                    _ = requestReload(query: selection.query(search: search), lifetime: lifetime)
                }
            }
        }
        guard generation == lifetime, query == selection.query(search: search), !Task.isCancelled else { return false }
        let task = requestReload(query: query, lifetime: lifetime)
        let result = await task.value
        return result && !Task.isCancelled && generation == lifetime && query == selection.query(search: search)
    }
    /// Every request requires a read started at or after that request. Requests
    /// arriving during a read mark this flight dirty instead of invalidating its
    /// waiters or starting a competing reader for the same query.
    private func requestReload(query: HostQuery, lifetime: Int) -> Task<Bool, Never> {
        reloadSequence += 1
        if var flight = reloadFlight, flight.query == query, flight.lifetime == lifetime, !flight.task.isCancelled {
            flight.requested = reloadSequence; reloadFlight = flight
            return flight.task
        }
        reloadFlight?.task.cancel()
        let id = UUID()
        let task = Task { @MainActor [weak self] in
            guard let self else { return false }
            return await performReload(id: id, query: query, lifetime: lifetime)
        }
        reloadFlight = ReloadFlight(id: id, query: query, lifetime: lifetime, requested: reloadSequence, task: task)
        isLoading = true
        return task
    }
    private func reloadIsCurrent(id: UUID, query: HostQuery, lifetime: Int) -> Bool {
        reloadFlight?.id == id && generation == lifetime && query == selection.query(search: search) && !Task.isCancelled
    }
    private func performReload(id: UUID, query: HostQuery, lifetime: Int) async -> Bool {
        defer {
            if reloadFlight?.id == id { reloadFlight = nil; isLoading = false }
        }
        while let flight = reloadFlight, flight.id == id {
            let requested = flight.requested
            do {
                let snapshot = try await repository.snapshot(query: query)
                guard reloadIsCurrent(id: id, query: query, lifetime: lifetime) else { return false }
                guard reloadFlight?.requested == requested else { continue }
                applyReload(snapshot)
                return true
            } catch {
                guard reloadIsCurrent(id: id, query: query, lifetime: lifetime) else { return false }
                guard reloadFlight?.requested == requested else { continue }
                issue = .sanitized(error)
                return false
            }
        }
        return false
    }
    private func applyReload(_ snapshot: AppSnapshot) {
        hosts = snapshot.hosts; connectionHosts = snapshot.allHosts ?? snapshot.hosts; folders = snapshot.folders; keys = snapshot.keys; settings = snapshot.settings
        sessions.updateDisplayMetadata(hosts: connectionHosts)
        sessions.updateSettings(settings)
        files.updateTransferPreference(settings.fileConflictPolicy)
        if let selectedHostID, !hosts.contains(where: { $0.id == selectedHostID }) { self.selectedHostID = nil }
        if files.selectedHost != nil {
            // The selected row can be an intentionally retained live-connection
            // snapshot. Only the current Core catalog may update/revert it.
            let wasVisible = files.visible
            files.show(host: currentFilesHost(allowVaultSelection: false))
            if !wasVisible { files.hide() }
        }
        didLoad = true
        if !didRestoreManagementPage {
            didRestoreManagementPage = true
            if preferencesDefaults != nil { showWorkspace(ManagementPagePreferences.startup(settings.startupPage, defaults: preferencesDefaults)) }
        }
        issue = nil
    }

    @discardableResult private func write(_ operation: () async throws -> Void) async -> Bool {
        guard !isWriting else { return false }
        isWriting = true
        defer { isWriting = false }
        do {
            try await operation()
            _ = await reload()
            return true // The mutation committed even if the later read cannot refresh UI.
        } catch is AppStorageFailure {
            issue = .sanitized(AppStorageFailure.committedStorageUnsafe)
            return true
        } catch {
            issue = .sanitized(error)
            return false
        }
    }

    @discardableResult func saveHost(_ host: HostConfiguration, isNew: Bool) async -> Bool {
        await write { try await repository.apply([isNew ? .insertHost(host) : .updateHost(host)]) }
    }
    @discardableResult func saveHostSecurely(_ host: HostConfiguration, isNew: Bool, password: PasswordChoice) async -> Bool {
        guard !isWriting else { return false }
        isWriting = true; defer { isWriting = false }
        do {
            let outcome = try await security.saveHost(host, isNew: isNew, password: password)
            _ = await reload()
            if case .savedWithCleanupPending = outcome { issue = .security(SecurityUIFailure.pendingCleanup) }
            return true // SecurityCoordinator only returns after the host transaction committed.
        } catch { issue = .security(error); return false }
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
    static func mergedSettings(edited: AppSettings, base: AppSettings, onto latest: AppSettings) -> AppSettings {
        var result = latest
        if edited.historyLines != base.historyLines { result.historyLines = edited.historyLines }
        if edited.fontName != base.fontName { result.fontName = edited.fontName }
        if edited.fontSize != base.fontSize { result.fontSize = edited.fontSize }
        if edited.theme != base.theme { result.theme = edited.theme }
        if edited.foregroundColor != base.foregroundColor { result.foregroundColor = edited.foregroundColor }
        if edited.backgroundColor != base.backgroundColor { result.backgroundColor = edited.backgroundColor }
        if edited.cursorColor != base.cursorColor { result.cursorColor = edited.cursorColor }
        if edited.keepaliveInterval != base.keepaliveInterval { result.keepaliveInterval = edited.keepaliveInterval }
        if edited.keepaliveCountMax != base.keepaliveCountMax { result.keepaliveCountMax = edited.keepaliveCountMax }
        if edited.cursorShape != base.cursorShape { result.cursorShape = edited.cursorShape }
        if edited.cursorBlink != base.cursorBlink { result.cursorBlink = edited.cursorBlink }
        if edited.startupPage != base.startupPage { result.startupPage = edited.startupPage }
        if edited.fileConflictPolicy != base.fileConflictPolicy { result.fileConflictPolicy = edited.fileConflictPolicy }
        return result
    }

    @discardableResult func saveSettings(_ value: AppSettings, base: AppSettings? = nil) async -> Bool {
        guard (0...50_000).contains(value.historyLines) else {
            issue = .sanitized(RepositoryError.invalidField("historyLines")); return false
        }
        guard value.fontSize.isFinite, (6...72).contains(value.fontSize) else {
            issue = .sanitized(RepositoryError.invalidField("fontSize")); return false
        }
        guard TerminalPreferences.font(name: value.fontName, size: value.fontSize) != nil else {
            issue = .sanitized(RepositoryError.invalidField("fontName")); return false
        }
        guard !isWriting else { return false }
        isWriting = true
        defer { isWriting = false }
        var committed = value
        do {
            if let base {
                let latest = try await repository.loadSettings()
                committed = Self.mergedSettings(edited: value, base: base, onto: latest)
            }
            try await repository.apply([.saveSettings(committed)])
            // A committed preference is usable even if the later catalog refresh fails.
            settings = committed; sessions.updateSettings(committed); files.updateTransferPreference(committed.fileConflictPolicy)
            _ = await reload()
            return true
        } catch is AppStorageFailure {
            // The preference transaction committed; repeating Save cannot repair ACL.
            settings = committed; sessions.updateSettings(committed); files.updateTransferPreference(committed.fileConflictPolicy)
            issue = .sanitized(AppStorageFailure.committedStorageUnsafe)
            return true
        } catch {
            issue = .sanitized(error)
            return false
        }
    }

    func showConnectionConfiguration(_ id: UUID) {
        guard connectionHosts.contains(where: { $0.id == id }) else {
            issue = AppIssue(code: "session.configurationUnavailable", message: "此会话的保存配置已不存在。会话历史保留，不会恢复已删除的主机或自动连接。")
            return
        }
        showWorkspace(.vault)
        guard workspacePage == .vault else { return }
        vaultHostFocusRequest = VaultHostFocusRequest(hostID: id)
        issue = AppIssue(code: "session.configurationSelected", message: "已返回保险箱并请求定位此会话的保存配置。可使用主机的编辑入口；不会自动连接或修改当前会话。")
    }
    func prepareTransientConnection(_ host: HostConfiguration, intent: VaultTransientConnectionIntent) async throws -> VaultPreparedConnection {
        do {
            return try await sessions.prepareTransient(host, intent: intent, candidateBuilder: nativeCandidateBuilder) { [weak self] id in
                guard let self else { return false }
                // Runs after exact editor dismissal. Never bypass the navigation guard.
                self.showWorkspace(.session(id))
                guard self.workspacePage == .session(id) else { return false }
                self.connectionNotice = .opened(SessionRequest(hostID: host.id, mode: .newSession), id)
                return true
            }
        } catch { intent.cancel(); issue = .session(error); throw error }
    }
    func requestSession(hostID: UUID, mode: SessionOpenMode) {
        guard let host = connectionHosts.first(where: { $0.id == hostID }) else { issue = .sanitized(RepositoryError.notFound); return }
        // Ask before router/open allocates or selects a tab, not after a hidden session exists.
        if workspacePage == .vault, workspaceNavigationGuard?.action() == false { return }
        let request = SessionRequest(hostID: hostID, mode: mode)
        if let sessionRouter { connectionNotice = sessionRouter.open(request) }
        else if let id = sessions.open(host, mode: mode) {
            connectionNotice = .opened(request, id)
            showWorkspace(.session(id))
        }
    }

    func showWorkspace(_ page: WorkspacePage) {
        if page != workspacePage, workspacePage == .vault, workspaceNavigationGuard?.action() == false { return }
        if case .session(let id) = page {
            guard sessions.tabs.contains(where: { $0.id == id }) else { return }
            sessions.select(id)
        }
        if workspacePage == .sftp, page != .sftp { files.hide() }
        workspacePage = page
        ManagementPagePreferences.record(page, defaults: preferencesDefaults)
        sessions.setWorkspaceVisible(page.sessionID != nil)
        if page == .sftp { files.show(host: currentFilesHost(allowVaultSelection: true)) }
    }
    private func currentFilesHost(allowVaultSelection: Bool) -> HostConfiguration? {
        if let id = files.selectedHost?.id {
            // A missing/deleted row means no current host, not fallback to the
            // old connection snapshot or an unrelated Vault selection.
            return connectionHosts.first { $0.id == id }
        }
        guard allowVaultSelection, let id = selectedHostID else { return nil }
        return connectionHosts.first { $0.id == id }
    }
    var canSearchWorkspace: Bool {
        switch workspacePage {
        case .vault: true
        case .sftp: true
        case .session(let id): sessions.selectedTabID == id && sessions.selectedTab?.driver != nil
        }
    }
    @discardableResult func sendWorkspaceCommand(_ command: WorkspaceCommand) -> Bool {
        if command == .search {
            guard canSearchWorkspace else { return false }
            switch workspacePage {
            case .vault: break // The current Vault subpage consumes this command.
            case .sftp: break // The visible Files page owns its active pane and filter.
            case .session: guard sessions.showSearchInSelectedTab() else { return false }
            }
        }
        workspaceCommand = WorkspaceCommandRequest(command: command, page: workspacePage)
        return true
    }
    @discardableResult func focusHostSearch(for request: WorkspaceCommandRequest) -> Bool {
        guard workspacePage == .vault, request.page == .vault, request.command == .search, workspaceCommand == request else { return false }
        hostSearchFocusRequest = UUID(); return true
    }
    func showTransferTasks() { files.tasksVisible = true }
    func returnToVaultFromFiles() {
        files.hide() // Presentation only; the service, manager and jobs stay alive.
        showWorkspace(.vault)
    }
    func switchWorkspace(by offset: Int) {
        let pages: [WorkspacePage] = [.vault, .sftp] + sessions.tabs.map { .session($0.id) }
        guard let index = pages.firstIndex(of: workspacePage) else { showWorkspace(.vault); return }
        showWorkspace(pages[(index + offset % pages.count + pages.count) % pages.count])
    }
    func closeCurrentWorkspace() async -> Bool {
        guard let id = workspacePage.sessionID else { return false }
        return await sessions.closeTabResult(id, deadline: .now + .seconds(2)).permitsRemoval
    }

    func windowClosed() {
        windowCloseReviews.invalidate()
        workspaceNavigationGuard = nil
        generation += 1
        reloadFlight?.task.cancel(); reloadFlight = nil
        sessionRouter?.closeAll()
        connectionNotice = nil; vaultHostFocusRequest = nil; selectedHostID = nil; search = ""; selection = .all
        workspacePage = .vault; workspaceCommand = nil; sessions.setWorkspaceVisible(false)
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

struct SettingsDraft: Equatable {
    var value: AppSettings
    var history: String
    var size: String
    var interval: String
    var count: String
    init(_ value: AppSettings) {
        self.value = value; history = String(value.historyLines); size = String(value.fontSize)
        interval = String(value.keepaliveInterval); count = String(value.keepaliveCountMax)
        // Show the effective default palette, not the legacy stored sentinel colors.
        // Distinct user colors stay byte-for-byte unchanged, including during preview.
        if ColorPreset.matching(value) == .nord {
            (self.value.foregroundColor, self.value.backgroundColor, self.value.cursorColor) = ColorPreset.nord.colors
        }
    }
    @MainActor func validated() throws -> AppSettings {
        var result = value
        guard let history = Int(history), (0...50_000).contains(history) else { throw RepositoryError.invalidField("historyLines") }
        guard let size = Double(size), size.isFinite, (6...72).contains(size) else { throw RepositoryError.invalidField("fontSize") }
        guard let interval = Int(interval), let count = Int(count), (0...3600).contains(interval), (1...10).contains(count) else { throw RepositoryError.invalidField("keepalive") }
        guard TerminalPreferences.font(name: value.fontName, size: size) != nil else { throw RepositoryError.invalidField("fontName") }
        for color in [value.foregroundColor, value.backgroundColor, value.cursorColor] {
            guard color.utf8.count == 7, color.first == "#", color.dropFirst().allSatisfy({ $0.isASCII && $0.isHexDigit }) else {
                throw RepositoryError.invalidField("color")
            }
        }
        result.historyLines = history; result.fontSize = size; result.keepaliveInterval = interval; result.keepaliveCountMax = count
        return result
    }
    mutating func reset(_ category: PreferencesCategory) {
        let defaults = AppSettings()
        switch category {
        case .general:
            value.theme = defaults.theme; value.startupPage = defaults.startupPage
        case .terminal:
            value.fontName = defaults.fontName; size = String(defaults.fontSize); history = String(defaults.historyLines)
            (value.foregroundColor, value.backgroundColor, value.cursorColor) = ColorPreset.nord.colors
            value.cursorShape = defaults.cursorShape; value.cursorBlink = defaults.cursorBlink
        case .connection:
            interval = String(defaults.keepaliveInterval); count = String(defaults.keepaliveCountMax)
        case .files: value.fileConflictPolicy = defaults.fileConflictPolicy
        case .privacy, .about: break
        }
    }
}

enum PreferencesCategory: String, CaseIterable, Identifiable {
    case general, terminal, connection, files, privacy, about
    var id: String { rawValue }
    var title: String {
        switch self {
        case .general: "通用与外观"
        case .terminal: "终端"
        case .connection: "连接"
        case .files: "文件传输"
        case .privacy: "隐私与诊断"
        case .about: "快捷键与关于"
        }
    }
    var symbol: String {
        switch self {
        case .general: "paintbrush"
        case .terminal: "terminal"
        case .connection: "network"
        case .files: "folder"
        case .privacy: "hand.raised"
        case .about: "info.circle"
        }
    }
    var canReset: Bool { self == .general || self == .terminal || self == .connection || self == .files }
}

enum ManagementPagePreferences {
    static let key = "OpenLXSSH.ManagementPage.v1"
    static func startup(_ preference: StartupManagementPage, defaults: UserDefaults?) -> WorkspacePage {
        switch preference {
        case .vault: .vault
        case .sftp: .sftp
        case .lastManagement: defaults?.string(forKey: key) == "sftp" ? .sftp : .vault
        }
    }
    static func record(_ page: WorkspacePage, defaults: UserDefaults?) {
        switch page {
        case .vault: defaults?.set("vault", forKey: key)
        case .sftp: defaults?.set("sftp", forKey: key)
        case .session: break
        }
    }
}

/// The picker, in-sheet terminal and existing tabs use exactly the same resolution.
@MainActor enum TerminalPreferences {
    static func font(name: String, size: Double) -> NSFont? {
        guard size.isFinite, (6...72).contains(size) else { return nil }
        let font = name == "SFMono-Regular" ? NSFont.monospacedSystemFont(ofSize: size, weight: .regular) : NSFont(name: name, size: size)
        guard let font, NativeTerminalView.isMonospaced(font) else { return nil }
        return font
    }
    static func availableFonts() -> [(name: String, title: String)] {
        var names = Set(NSFontManager.shared.availableFontNames(with: .fixedPitchFontMask) ?? [])
        names.formUnion(NSFontManager.shared.availableFonts.filter { font(name: $0, size: 13) != nil })
        names.remove("SFMono-Regular")
        let entries = names.compactMap { name -> (name: String, title: String)? in
            guard let font = font(name: name, size: 13) else { return nil }
            return (name, font.displayName ?? name)
        }.sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
        return [("SFMono-Regular", "系统等宽（默认）")] + entries
    }
    static func apply(_ settings: AppSettings, to terminal: NativeTerminalView, size: Double? = nil, updateCursor: Bool = true) throws {
        guard let font = font(name: settings.fontName, size: size ?? settings.fontSize),
              let shape = DesktopCursorShape(rawValue: settings.cursorShape.rawValue) else { throw TransportError.invalidConfiguration }
        try terminal.setFont(name: font.fontName, size: font.pointSize)
        terminal.setHistoryLimit(settings.historyLines)
        if updateCursor { terminal.setDesktopCursor(shape: shape, blinking: settings.cursorBlink) }
        terminal.appearance = settings.theme == .system ? nil : NSAppearance(named: settings.theme == .dark ? .darkAqua : .aqua)
        if ColorPreset.matching(settings) == .nord { terminal.setColorMode(.system) }
        else {
            terminal.setColors(foreground: NSColor(sessionHex: settings.foregroundColor), background: NSColor(sessionHex: settings.backgroundColor), cursor: NSColor(sessionHex: settings.cursorColor))
        }
    }
}

struct PreferencesResetReview: Identifiable {
    let id = UUID()
    let category: PreferencesCategory?
}
struct SettingsClosePrompt: Identifiable { let id = UUID() }
/// Contains preferences only. No host, terminal input, credential or authentication answer.
@Observable @MainActor final class SettingsEditorModel {
    let id = UUID()
    var draft: SettingsDraft {
        didSet {
            if !isWriting, !normalizingDraft, draft != oldValue {
                closeApproval = false
                closeRequest?.resolve(false); closeRequest = nil; prompt = nil
            }
        }
    }
    var selectedCategory: PreferencesCategory
    private(set) var isWriting = false
    private(set) var isActive = true
    private(set) var prompt: SettingsClosePrompt?
    var resetReview: PreferencesResetReview?
    var issue: AppIssue?
    private var baseline: SettingsDraft
    @ObservationIgnored private var normalizingDraft = false
    @ObservationIgnored private var closeRequest: WindowCloseReviewRequest?
    private(set) var closeApproval = false
    init(_ settings: AppSettings, category: PreferencesCategory = .general) {
        let initial = SettingsDraft(settings)
        draft = initial; baseline = initial; selectedCategory = category
    }
    /// Snapshot of the normalized baseline settings captured when this editor opened (or last synced).
    var initial: AppSettings { baseline.value }
    var isDirty: Bool { draft != baseline }
    var canEdit: Bool { isActive && !isWriting && !closeApproval }
    /// Syncs externally committed settings when the user has no unsaved edits in progress.
    func syncExternal(_ latest: AppSettings) {
        guard canEdit, !isDirty, resetReview == nil else { return }
        let updated = SettingsDraft(latest)
        guard updated != baseline else { return }
        normalizingDraft = true
        draft = updated
        baseline = updated
        normalizingDraft = false
    }
    func attemptClose() -> Bool {
        guard canEdit, resetReview == nil else { return false }
        if !isDirty { return true }
        if prompt == nil { prompt = SettingsClosePrompt() }
        return false
    }
    func beginCloseReview(_ request: WindowCloseReviewRequest, dismiss: () -> Void) {
        guard canEdit, resetReview == nil, closeRequest == nil else { request.resolve(false); return }
        closeRequest = request
        if isDirty { if prompt == nil { prompt = SettingsClosePrompt() } }
        else { approveClose(); dismiss() }
    }
    func cancelClose(_ id: UUID? = nil) {
        guard !isWriting, id == nil || prompt?.id == id else { return }
        prompt = nil; closeRequest?.resolve(false); closeRequest = nil
    }
    func discard(_ id: UUID) -> Bool {
        guard canEdit, prompt?.id == id else { return false }
        normalizingDraft = true; draft = baseline; normalizingDraft = false
        approveClose(); return true
    }
    func save(reviewID: UUID? = nil, using operation: @MainActor (AppSettings) async -> Bool) async -> Bool {
        guard canEdit, resetReview == nil, prompt?.id == reviewID else { return false }
        let saved: AppSettings
        do { saved = try draft.validated() } catch { issue = .sanitized(error); return false }
        isWriting = true // Synchronous, before the first suspension or repository mutation.
        defer { isWriting = false }
        guard await operation(saved), isActive else { return false }
        draft = SettingsDraft(saved); baseline = draft
        approveClose(); return true
    }
    private func approveClose() {
        closeApproval = true; prompt = nil
        if let closeRequest {
            closeRequest.validateApproval { [self] in closeApproval && !isWriting }
            closeRequest.resolve(true); self.closeRequest = nil
        }
    }
    func deactivate() {
        isActive = false
        if !closeApproval { closeRequest?.resolve(false) }
        closeRequest = nil; prompt = nil; resetReview = nil
    }
    isolated deinit { closeRequest?.cancel() }
}

enum DiagnosticCategory: String, CaseIterable, Identifiable {
    case version, operatingSystem, counts, terminalPreferences
    var id: String { rawValue }
    var title: String {
        switch self {
        case .version: "版本与构建号"
        case .operatingSystem: "系统版本与架构"
        case .counts: "泛化数量（主机 / 密钥 / SSH 标签）"
        case .terminalPreferences: "终端及连接默认参数（不含字体名或路径）"
        }
    }
}

/// An allowlisted value, not a log collector. No host/session strings or file URLs
/// are accepted. The exact preview is also the exact clipboard payload.
struct PublicDiagnosticSnapshot: Equatable {
    let version: String
    let build: String
    let operatingSystem: String
    let hostCount: Int
    let keyCount: Int
    let sessionCount: Int
    let settings: AppSettings
    init(version: String, build: String, operatingSystem: String, hostCount: Int, keyCount: Int, sessionCount: Int, settings: AppSettings) {
        self.version = version; self.build = build; self.operatingSystem = operatingSystem
        self.hostCount = hostCount; self.keyCount = keyCount; self.sessionCount = sessionCount; self.settings = settings
    }
    @MainActor init(model: AppModel) {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        self.init(version: DesktopHelp.version, build: DesktopHelp.build,
            operatingSystem: "macOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion) · arm64",
            hostCount: model.connectionHosts.count, keyCount: model.keys.count, sessionCount: model.sessions.tabs.count, settings: model.settings)
    }
    func preview(categories: Set<DiagnosticCategory>) -> String {
        guard !categories.isEmpty else { return "未选择任何诊断项目。" }
        var lines = ["OpenLXSSH · 本地非秘密诊断"]
        if categories.contains(.version) { lines += ["版本：\(version)", "构建：\(build)"] }
        if categories.contains(.operatingSystem) { lines += ["系统：\(operatingSystem)"] }
        if categories.contains(.counts) { lines += ["数量：主机 \(max(0, hostCount)) · 密钥 \(max(0, keyCount)) · SSH 标签 \(max(0, sessionCount))"] }
        if categories.contains(.terminalPreferences) {
            lines += ["管理外观：\(settings.theme.rawValue) · 启动页：\(settings.startupPage.rawValue)",
                      "终端：字号 \(settings.fontSize) · 历史 \(settings.historyLines) · 光标 \(settings.cursorShape.rawValue) · 闪烁 \(settings.cursorBlink ? "开" : "关")",
                      "新主机默认 TCP 保活：空闲/重试间隔 \(settings.keepaliveInterval) 秒；失败探测 \(settings.keepaliveCountMax) 次（间隔 0 关闭；非 SSH 应用响应截止时间）"]
        }
        return lines.joined(separator: "\n")
    }
    @MainActor @discardableResult static func copy(_ preview: String, to pasteboard: NSPasteboard) -> Bool {
        pasteboard.clearContents()
        return pasteboard.setString(preview, forType: .string)
    }
}

struct DesktopLicense: Identifiable, Sendable {
    let id: String
    let title: String
    let resource: String
}

enum DesktopHelp {
    static var version: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "未提供" }
    static var build: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "未提供" }
    static func versionDescription() -> String { "OpenLXSSH \(version)（构建 \(build)）" }
    static let localDataDescription = """
        本 App 使用本机单个保险箱，没有云账号、同步或独立 Vault 锁。
        配置数据库位于用户资料库的 Application Support / OpenLXSSH / Data（OpenLXSSH.sqlite）；私钥副本位于 App 专属受限目录，密码与私钥口令使用本机 Keychain，不云同步；OTP 不保存。已知主机是 App 自有信任库，不修改系统 SSH 配置。
        窗口/列表等非秘密偏好由 macOS 偏好存储管理。终端输出与搜索只保留在当前标签内存，不录制、不在重启后恢复；不自动连接或重用旧认证回答。诊断预览不枚举这些目录、不读取文件内容或 Keychain。
        """
    static let shortcuts = """
        ⌘T 新连接；⌘N 新建窗口；⌘, 设置。
        ⌘W 关闭当前 SSH；在固定管理页关闭窗口。表单有未保存改动时先审核，固定标签不会被删除。
        ⌘1 保险箱；⌘2 SFTP；⌘⇧[ / ⌘⇧] 前一个 / 后一个标签。
        ⌘F 查找当前页：保险箱当前子页搜索、SFTP 当前栏筛选或当前终端查找。
        输入框中的 ⌘A/C/V 优先编辑文本。终端中 ⌘C 复制选区、⌘V 精确粘贴、⌘A 全选；Ctrl-C/D/Z、Tab、方向及功能键交给终端。
        终端 ⌘+ / ⌘− 放大 / 缩小，⌘0 还原设置字号；查找中 Enter / Shift-Enter 下一处 / 上一处，Escape 关闭。
        终端分屏：⌘D 左右分屏（新建同主机会话），⇧⌘D 上下分屏，⌥⌘] 切换分屏焦点，⇧⌥⌘D 取消分屏。
        拖动选择，双击选词，三击选行。TUI 鼠标模式下按 Shift 使用本地选择（远端捕获 Shift 时除外）。
        多行粘贴不确认、不补回车，远端仍可能执行内容。清除滚动历史只影响当前标签内存、保留当前屏幕，不发送远端命令。
        """
    static let licenses: [DesktopLicense] = [
        .init(id: "notice", title: "OpenLXSSH · 依赖说明", resource: "NOTICE.txt"),
        .init(id: "grdb", title: "GRDB.swift · MIT", resource: "GRDB-LICENSE.txt"),
        .init(id: "swiftterm", title: "SwiftTerm · MIT", resource: "SwiftTerm-LICENSE"),
        .init(id: "argumentparser", title: "swift-argument-parser · Apache-2.0", resource: "ArgumentParser-LICENSE"),
        .init(id: "swiftpng", title: "swift-png · License", resource: "SwiftPNG-LICENSE"),
        .init(id: "swiftpng-notice", title: "swift-png · Notice", resource: "SwiftPNG-NOTICE"),
        .init(id: "h", title: "h · License", resource: "H-LICENSE"),
        .init(id: "h-notice", title: "h · Notice", resource: "H-NOTICE"),
        .init(id: "libssh2", title: "libssh2 · BSD-3-Clause", resource: "FilesNativeLicenses/libssh2/COPYING"),
        .init(id: "libssh2-notice", title: "libssh2 · 源文件说明", resource: "FilesNativeLicenses/libssh2/SOURCE-NOTICES.txt"),
        .init(id: "openssl", title: "OpenSSL · Apache-2.0", resource: "FilesNativeLicenses/openssl/LICENSE.txt"),
        .init(id: "openssl-notice", title: "OpenSSL · 源文件说明", resource: "FilesNativeLicenses/openssl/SOURCE-NOTICES.txt")
    ]
    static func licenseText(_ license: DesktopLicense, bundle: Bundle = .main) -> String {
        guard licenses.contains(where: { $0.id == license.id && $0.resource == license.resource }), let root = bundle.resourceURL else {
            return "当前 App 未提供此许可资源；不会从网络补取。"
        }
        let url = root.appendingPathComponent(license.resource)
        guard let stream = try? FileHandle(forReadingFrom: url) else {
            return "当前 App 未打包或无法读取此许可（\(license.resource)）。请使用完整构建；不会从网络补取。"
        }
        defer { try? stream.close() }
        guard let data = try? stream.read(upToCount: 2 * 1024 * 1024 + 1), data.count <= 2 * 1024 * 1024,
              let text = String(data: data, encoding: .utf8), !text.isEmpty else {
            return "当前 App 未打包或无法读取此许可（\(license.resource)）。请使用完整构建；不会从网络补取。"
        }
        return text
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
    case nord = "深海夜色（默认）"
    case termiusNight = "Termius Night"
    case macOSPro = "macOS Pro"
    case tokyoNight = "Tokyo Night"
    case dracula = "Dracula"
    case oneDark = "One Dark"
    case solarized = "Solarized"
    case classic = "Classic"
    case custom = "自定义"
    var colors: (String, String, String) {
        switch self {
        case .nord: ("#D6D6CC", "#101010", "#D6D6CC")
        case .termiusNight: ("#E2E8F0", "#161B26", "#4DA3FF")
        case .macOSPro: ("#F2F2F2", "#141414", "#9AA5B4")
        case .tokyoNight: ("#C0CAF5", "#1A1B26", "#7AA2F7")
        case .dracula: ("#F8F8F2", "#282A36", "#BD93F9")
        case .oneDark: ("#ABB2BF", "#1E222A", "#528BFF")
        case .solarized: ("#839496", "#002B36", "#93A1A1")
        case .classic: ("#E5E5E5", "#000000", "#00FF00")
        case .custom: ("#D8DEE9", "#20242C", "#D8DEE9")
        }
    }
    var previewColors: (foreground: String, background: String, cursor: String) {
        switch self {
        case .nord: ("#E2E8F0", "#141821", "#E2E8F0")
        default: colors
        }
    }
    static func matching(_ value: AppSettings) -> ColorPreset {
        // Existing schema stores three colors, not whether the preset was chosen.
        // Exact legacy-default triples therefore migrate as default; all distinct
        // explicit custom triples keep their exact values.
        if (value.foregroundColor, value.backgroundColor, value.cursorColor) == ("#D8DEE9", "#20242C", "#D8DEE9") { return .nord }
        return allCases.first { $0 != .custom && $0.colors == (value.foregroundColor, value.backgroundColor, value.cursorColor) } ?? .custom
    }
}
