import AppKit
import Combine
import Foundation
import OpenLXSSHCore
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust

enum VaultSection: Equatable {
    case all, favorites, ungrouped, folder(UUID)
    var folderID: UUID? { if case .folder(let id) = self { id } else { nil } }
}
enum VaultDisplayMode: String, CaseIterable { case list, cards }
enum VaultOrdering: String, CaseIterable { case name, recent }
enum VaultManagementPage: String, Codable, CaseIterable { case hosts, keys, trust }

/// A separate additive key leaves the existing view/order/inspector preference format
/// unchanged. Only enum cases and record UUIDs are encoded, never labels or query text.
struct VaultNavigationPreferences: Codable, Equatable {
    enum Section: String, Codable { case all, favorites, ungrouped, folder }
    var page: VaultManagementPage = .hosts
    var section: Section = .all
    var folderID: UUID?
    var selectedIDs: Set<UUID> = []
    var focusedID: UUID?
    var vaultSection: VaultSection {
        switch section {
        case .all: .all
        case .favorites: .favorites
        case .ungrouped: .ungrouped
        case .folder: folderID.map(VaultSection.folder) ?? .all
        }
    }
    init() {}
    init(page: VaultManagementPage, section: VaultSection, selectedIDs: Set<UUID>, focusedID: UUID?) {
        self.page = page; self.selectedIDs = selectedIDs; self.focusedID = focusedID
        switch section {
        case .all: self.section = .all
        case .favorites: self.section = .favorites
        case .ungrouped: self.section = .ungrouped
        case .folder(let id): self.section = .folder; folderID = id
        }
    }
}

/// Only non-secret UI preferences. Search text, credentials and terminal contents are never encoded.
struct VaultPreferences: Codable, Equatable {
    var view = VaultDisplayMode.list.rawValue
    var order = VaultOrdering.name.rawValue
    var descending = false
    var inspector = true
    var expandedFolders: Set<UUID> = []
}

/// Short-lived and single-consumer. Never put this object in ObservableObject/Codable state.
/// A session owner must bind consumption to the exact saved host and its new authentication request.
@MainActor final class VaultTransientConnectionIntent {
    let hostID: UUID
    let identity: HostConnectionIdentity
    private var secret: SecretBytes?
    private(set) var consumed = false
    init(host: HostConfiguration, secret: SecretBytes?) {
        hostID = host.id; identity = host.connectionIdentity; self.secret = secret
    }
    private var boundToken: SessionToken?
    private var boundRequest: UUID?
    func bind(to token: SessionToken, host: HostConfiguration) throws {
        guard !consumed, boundToken == nil, host.id == hostID, host.connectionIdentity == identity else { throw SecurityUIFailure.notAuthorized }
        boundToken = token
    }
    func bindPrimaryRequest(_ id: UUID, token: SessionToken, host: HostConfiguration) throws {
        guard !consumed, boundToken == token, boundRequest == nil, host.id == hostID, host.connectionIdentity == identity else { throw SecurityUIFailure.notAuthorized }
        boundRequest = id
    }
    func take(for host: HostConfiguration, token: SessionToken, primaryRequestID: UUID) throws -> SecretBytes? {
        guard !consumed, boundToken == token, boundRequest == primaryRequestID,
              host.id == hostID, host.connectionIdentity == identity else { throw SecurityUIFailure.notAuthorized }
        consumed = true
        let value = secret; secret = nil
        return value
    }
    func cancel() { consumed = true; secret = nil; boundToken = nil; boundRequest = nil }
}
/// A prepared owner is invisible and has not begun a handshake. Commit is synchronous,
/// single-use and occurs only after the exact editor dismisses. Every other exit revokes it.
@MainActor final class VaultPreparedConnection {
    private var commitAction: (@MainActor () throws -> Void)?
    private var cancelAction: (@MainActor () -> Void)?
    init(commit: @escaping @MainActor () throws -> Void, cancel: @escaping @MainActor () -> Void) {
        commitAction = commit; cancelAction = cancel
    }
    func commit() throws {
        guard let action = commitAction else { throw SecurityUIFailure.notAuthorized }
        commitAction = nil
        do { try action(); cancelAction = nil }
        catch { cancel(); throw error }
    }
    func cancel() { commitAction = nil; let action = cancelAction; cancelAction = nil; action?() }
    isolated deinit { cancelAction?() }
}
typealias VaultTransientConnectionHandler = @MainActor (HostConfiguration, VaultTransientConnectionIntent) async throws -> VaultPreparedConnection

struct VaultBatchConfirmation: Identifiable {
    let id = UUID()
    let title: String
    let detail: String
    let hostIDs: [UUID]
    let changes: [RepositoryChange]
}

@MainActor final class VaultDesktopModel: ObservableObject {
    let repository: any AppRepositoryProtocol
    private let defaults: UserDefaults?
    private let preferenceKey: String
    private let synchronize: @MainActor () async -> Void
    private let selectAppHost: @MainActor (UUID?) -> Void
    @Published private(set) var snapshot: AppSnapshot?
    @Published private(set) var isLoading = false
    @Published private(set) var isWriting = false
    @Published private(set) var didLoad = false
    @Published var issue: AppIssue?
    @Published var notice: String?
    @Published var search = ""
    @Published var managementPage: VaultManagementPage = .hosts { didSet { persistNavigation() } }
    @Published var section: VaultSection = .all { didSet { persistNavigation() } }
    @Published var tagFilter: Set<UUID> = []
    @Published private(set) var selectedIDs: Set<UUID> = []
    @Published private(set) var focusedID: UUID?
    @Published var preferences: VaultPreferences { didSet { persistPreferences() } }
    private var navigationToRestore: VaultNavigationPreferences?
    private var didRestoreNavigation = false
    private var correctingNavigation = false
    private var anchorID: UUID?
    private var generation: UInt64 = 0
    private var searchTask: Task<Void, Never>?
    private var noticeTask: Task<Void, Never>?
    private var metadataObservation: Task<Void, Never>?
    private var observingMetadata = false
    private var appFocusObservation: AnyCancellable?
    private var focusTask: Task<Void, Never>?
    private var pendingFocus: (request: VaultHostFocusRequest, selectionEpoch: UUID)?
    private var selectionEpoch = UUID()
    private var managementNavigationGuard: (owner: UUID, action: @MainActor () -> Bool)?
    func registerManagementNavigationGuard(owner: UUID, action: @escaping @MainActor () -> Bool) { managementNavigationGuard = (owner, action) }
    func clearManagementNavigationGuard(owner: UUID) { if managementNavigationGuard?.owner == owner { managementNavigationGuard = nil } }
    @discardableResult func performManagementNavigation(_ action: () -> Void) -> Bool {
        guard managementNavigationGuard?.action() != false else {
            showNotice("先处理当前编辑的保存／放弃／取消；完成后请再次选择目标页面。")
            return false
        }
        action(); return true
    }

    init(repository: any AppRepositoryProtocol, defaults: UserDefaults? = .standard,
         preferenceKey: String = "OpenLXSSH.Vault.Desktop.v1",
         synchronize: @escaping @MainActor () async -> Void = {},
         selectAppHost: @escaping @MainActor (UUID?) -> Void = { _ in }) {
        self.repository = repository; self.defaults = defaults; self.preferenceKey = preferenceKey
        self.synchronize = synchronize; self.selectAppHost = selectAppHost
        let data = defaults?.data(forKey: preferenceKey)
        preferences = data.flatMap { try? JSONDecoder().decode(VaultPreferences.self, from: $0) } ?? VaultPreferences()
        let navigationKey = preferenceKey + ".navigation.v1"
        if let data = defaults?.data(forKey: navigationKey) {
            navigationToRestore = try? JSONDecoder().decode(VaultNavigationPreferences.self, from: data)
            if navigationToRestore == nil { defaults?.removeObject(forKey: navigationKey) }
        }
        if let navigationToRestore { managementPage = navigationToRestore.page; section = navigationToRestore.vaultSection }
    }
    convenience init(app: AppModel) {
        self.init(repository: app.repository, defaults: app.desktopPreferencesDefaults, synchronize: { [weak app] in _ = await app?.reload() },
                  selectAppHost: { [weak app] in app?.selectedHostID = $0 })
        appFocusObservation = app.$vaultHostFocusRequest.compactMap { $0 }.sink { [weak self] request in
            self?.requestFocus(request)
        }
    }
    func requestFocus(_ request: VaultHostFocusRequest) {
        guard pendingFocus?.request.id != request.id else { return }
        guard performManagementNavigation({}) else { return }
        selectionEpoch = UUID(); pendingFocus = (request, selectionEpoch)
        searchTask?.cancel(); managementPage = .hosts; section = .all; search = ""; tagFilter = []
        focusTask?.cancel()
        focusTask = Task { [weak self] in
            guard let self else { return }
            _ = await self.load()
        }
    }
    private func applyPendingFocus() {
        guard let pending = pendingFocus else { return }
        guard pending.selectionEpoch == selectionEpoch else { pendingFocus = nil; return }
        guard hosts.contains(where: { $0.id == pending.request.hostID }) else {
            pendingFocus = nil
            issue = AppIssue(code: "session.configurationUnavailable", message: "请求的主机配置已不存在或无法定位。未恢复记录，也未启动连接。")
            return
        }
        pendingFocus = nil
        choose(pending.request.hostID)
    }
    var hosts: [HostConfiguration] { snapshot?.hosts ?? [] }
    var catalog: [HostConfiguration] { snapshot?.allHosts ?? hosts }
    var folders: [HostFolder] { snapshot?.folders ?? [] }
    var tags: [HostTag] { snapshot?.tags ?? [] }
    var selectedHost: HostConfiguration? { catalog.first { $0.id == focusedID } }
    var selectedHosts: [HostConfiguration] { catalog.filter { selectedIDs.contains($0.id) } }
    var displayMode: VaultDisplayMode { VaultDisplayMode(rawValue: preferences.view) ?? .list }
    var ordering: VaultOrdering { VaultOrdering(rawValue: preferences.order) ?? .name }
    var query: HostQuery {
        let folder: FolderFilter
        switch section {
        case .ungrouped: folder = .ungrouped
        case .folder(let id): folder = .folderAndDescendants(id)
        default: folder = .all
        }
        return HostQuery(search: search, favoritesOnly: section == .favorites, folder: folder,
                         sort: ordering == .name ? .name : .recentlyConnected,
                         sortDirection: preferences.descending ? .descending : .ascending, tagIDs: tagFilter)
    }
    var title: String {
        switch section {
        case .all: "所有主机"
        case .favorites: "收藏"
        case .ungrouped: "未分组"
        case .folder(let id): folders.first { $0.id == id }?.name ?? "分组"
        }
    }
    func metadata(for id: UUID) -> HostMetadata? { snapshot?.catalog.first { $0.id == id } }
    func path(for id: UUID) -> String { snapshot?.folderPaths.first { $0.id == id }?.displayName ?? "未分组" }
    func folderLabel(_ folder: HostFolder) -> String {
        let duplicate = folders.filter { $0.name == folder.name }.count > 1
        return path(for: folder.id) + (duplicate ? " · " + folder.id.uuidString.prefix(6) : "")
    }
    func children(of parent: UUID?) -> [HostFolder] { folders.filter { $0.parentID == parent } }
    func canMoveFolder(_ id: UUID, to parent: UUID?) -> Bool {
        guard let parent else { return true }
        guard parent != id, folders.contains(where: { $0.id == parent }) else { return false }
        return snapshot?.folderPaths.first { $0.id == parent }?.folderIDs.contains(id) != true
    }
    func importHostDrag(_ providers: [NSItemProvider], to folderID: UUID?, confirm: @escaping @MainActor (VaultBatchConfirmation) -> Void) -> Bool {
        guard !isWriting, let provider = providers.first, provider.canLoadObject(ofClass: NSString.self) else { return false }
        provider.loadObject(ofClass: NSString.self) { [weak self] value, _ in
            guard let text = value as? NSString else { return }
            let string = text as String
            guard string.hasPrefix("OpenLXSSH.hosts.v1:"),
                  let data = String(string.dropFirst("OpenLXSSH.hosts.v1:".count)).data(using: .utf8),
                  let ids = try? JSONDecoder().decode([UUID].self, from: data), !ids.isEmpty else { return }
            Task { @MainActor in
                guard let self, !self.isWriting, Set(ids).isSubset(of: Set(self.catalog.map(\.id))),
                      folderID == nil || self.folders.contains(where: { $0.id == folderID }) else { return }
                confirm(self.moveConfirmation(ids: Array(Set(ids)).sorted { $0.uuidString < $1.uuidString }, folderID: folderID))
            }
        }
        return true
    }
    func toggleExpanded(_ id: UUID) {
        if preferences.expandedFolders.contains(id) { preferences.expandedFolders.remove(id) }
        else { preferences.expandedFolders.insert(id) }
    }
    func scheduleLoad() {
        searchTask?.cancel()
        // Invalidate an already suspended query immediately, not only after debounce expires.
        generation &+= 1
        searchTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(120))
            guard !Task.isCancelled else { return }
            _ = await self?.load()
        }
    }
    @discardableResult func load() async -> Bool {
        if !observingMetadata {
            observingMetadata = true
            let stream = await repository.metadataChanges()
            metadataObservation = Task { [weak self] in
                for await _ in stream {
                    guard !Task.isCancelled else { return }
                    _ = await self?.load()
                }
            }
        }
        generation &+= 1
        let token = generation
        isLoading = true
        defer { if token == generation { isLoading = false } }
        do {
            var currentQuery = query
            var value = try await repository.snapshot(query: currentQuery)
            guard token == generation, !Task.isCancelled else { return false }
            // A deleted filter cannot leave an empty snapshot obtained using a now-invalid query.
            // Re-query before publishing; a failed corrective read retains the previous success.
            while true {
                if let id = section.folderID, !value.folders.contains(where: { $0.id == id }) {
                    correctingNavigation = true; section = .all; correctingNavigation = false
                }
                tagFilter.formIntersection(Set(value.tags.map(\.id)))
                guard query != currentQuery else { break }
                currentQuery = query
                value = try await repository.snapshot(query: currentQuery)
                guard token == generation, !Task.isCancelled else { return false }
            }
            snapshot = value; didLoad = true; issue = nil
            if !didRestoreNavigation {
                didRestoreNavigation = true
                if let saved = navigationToRestore, pendingFocus == nil {
                    let valid = Set(value.hosts.map(\.id))
                    selectedIDs = saved.selectedIDs.intersection(valid)
                    focusedID = saved.focusedID.flatMap { selectedIDs.contains($0) ? $0 : nil }
                    anchorID = focusedID
                }
                navigationToRestore = nil
            }
            applyPendingFocus()
            let visible = Set(value.hosts.map(\.id))
            selectedIDs.formIntersection(visible)
            if let id = focusedID, !visible.contains(id) { focusedID = nil }
            if focusedID == nil { focusedID = value.hosts.first { selectedIDs.contains($0.id) }?.id }
            persistNavigation()
            await synchronize()
            guard token == generation else { return false }
            selectAppHost(focusedID)
            return true
        } catch {
            guard token == generation else { return false }
            issue = .sanitized(error) // Keep the last successful snapshot, selection and catalog.
            return false
        }
    }
    func choose(_ id: UUID, command: Bool = false, shift: Bool = false) {
        guard hosts.contains(where: { $0.id == id }) else { return }
        selectionEpoch = UUID(); pendingFocus = nil
        if shift, let anchorID, let from = hosts.firstIndex(where: { $0.id == anchorID }), let to = hosts.firstIndex(where: { $0.id == id }) {
            let range = Set(hosts[min(from, to)...max(from, to)].map(\.id))
            selectedIDs = command ? selectedIDs.union(range) : range
        } else if command {
            if selectedIDs.contains(id) { selectedIDs.remove(id) } else { selectedIDs.insert(id) }
            anchorID = id
        } else { selectedIDs = [id]; anchorID = id }
        focusedID = selectedIDs.contains(id) ? id : hosts.first { selectedIDs.contains($0.id) }?.id
        persistNavigation(); selectAppHost(focusedID)
    }
    func setSelection(_ ids: Set<UUID>, focused: UUID?) {
        selectionEpoch = UUID(); pendingFocus = nil
        selectedIDs = ids.intersection(Set(hosts.map(\.id)))
        focusedID = focused.flatMap { selectedIDs.contains($0) ? $0 : nil } ?? hosts.first { selectedIDs.contains($0.id) }?.id
        anchorID = focusedID; persistNavigation(); selectAppHost(focusedID)
    }
    func selectAll() { setSelection(Set(hosts.map(\.id)), focused: focusedID ?? hosts.first?.id) }
    func moveSelection(by offset: Int, extend: Bool = false) {
        guard !hosts.isEmpty else { return }
        let start = hosts.firstIndex { $0.id == focusedID } ?? (offset > 0 ? -1 : hosts.count)
        let next = max(0, min(hosts.count - 1, start + offset))
        choose(hosts[next].id, shift: extend)
    }
    func actionIDs(for clicked: UUID? = nil) -> [UUID] {
        if let clicked, !selectedIDs.contains(clicked) { return [clicked] }
        return hosts.filter { selectedIDs.contains($0.id) }.map(\.id)
    }
    func clearFilters() { search = ""; section = .all; tagFilter = []; scheduleLoad() }
    @discardableResult func apply(_ changes: [RepositoryChange], success: String? = nil) async -> Bool {
        guard !isWriting, !changes.isEmpty else { return false }
        isWriting = true; defer { isWriting = false }
        do {
            try await repository.apply(changes)
            _ = await load()
            if let success { showNotice(success) }
            return true
        } catch is AppStorageFailure {
            issue = .sanitized(AppStorageFailure.committedStorageUnsafe)
            await synchronize()
            return true // Committed; do not invite duplicate insertion.
        } catch { issue = .sanitized(error); return false }
    }
    func favoriteConfirmation(ids: [UUID], value: Bool) -> VaultBatchConfirmation {
        VaultBatchConfirmation(title: value ? "收藏 \(ids.count) 台主机？" : "取消收藏 \(ids.count) 台主机？",
            detail: "仅更新所列主机的本地收藏，不启动连接。", hostIDs: ids,
            changes: ids.map { id in .setFavorite(id, value, order: catalog.first(where: { $0.id == id })?.favoriteOrder ?? 0) })
    }
    func moveConfirmation(ids: [UUID], folderID: UUID?) -> VaultBatchConfirmation {
        VaultBatchConfirmation(title: "移动 \(ids.count) 台主机？", detail: "目标：" + (folderID.map(path(for:)) ?? "未分组") + "。不会改变认证、秘密或现有会话。",
            hostIDs: ids, changes: ids.map { .moveHost($0, folderID: folderID) })
    }
    func deleteConfirmation(ids: [UUID]) -> VaultBatchConfirmation {
        VaultBatchConfirmation(title: "删除 \(ids.count) 台主机配置？", detail: "不会删除共享密钥、已保存凭据或远端数据。已有会话保留连接时的配置快照。此操作不能撤销。",
                               hostIDs: ids, changes: ids.map { .deleteHost($0) })
    }
    func tagsConfirmation(ids: [UUID], tagID: UUID, assign: Bool) -> VaultBatchConfirmation {
        VaultBatchConfirmation(title: "为 \(ids.count) 台主机" + (assign ? "添加标签？" : "移除标签关联？"),
            detail: tags.first { $0.id == tagID }?.name ?? "标签已不存在", hostIDs: ids,
            changes: ids.map { assign ? .assignTag(hostID: $0, tagID: tagID) : .unassignTag(hostID: $0, tagID: tagID) })
    }
    @discardableResult func duplicate(_ id: UUID) async -> Bool {
        guard !isWriting else { return false }
        isWriting = true; defer { isWriting = false }
        do {
            let host = try await repository.copyHost(id: id)
            _ = await load(); choose(host.id); showNotice("配置已复制；密钥与凭据引用保持共享。")
            return true
        } catch { issue = .sanitized(error); return false }
    }
    func showNotice(_ text: String) {
        noticeTask?.cancel(); notice = text
        noticeTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            if !Task.isCancelled { self?.notice = nil }
        }
    }
    deinit { metadataObservation?.cancel(); searchTask?.cancel(); noticeTask?.cancel(); focusTask?.cancel() }
    private func persistNavigation() {
        guard !correctingNavigation else { return }
        guard didRestoreNavigation, let snapshot else {
            if let pending = navigationToRestore {
                navigationToRestore = VaultNavigationPreferences(page: managementPage, section: section, selectedIDs: pending.selectedIDs, focusedID: pending.focusedID)
            }
            return // Do not rewrite saved UUIDs before a successful catalog read validates them.
        }
        let validSection: VaultSection
        if let id = section.folderID, !snapshot.folders.contains(where: { $0.id == id }) { validSection = .all }
        else { validSection = section }
        let ids = selectedIDs.intersection(Set(snapshot.hosts.map(\.id)))
        let value = VaultNavigationPreferences(page: managementPage, section: validSection, selectedIDs: ids, focusedID: focusedID.flatMap { ids.contains($0) ? $0 : nil })
        if let data = try? JSONEncoder().encode(value) { defaults?.set(data, forKey: preferenceKey + ".navigation.v1") }
    }
    private func persistPreferences() {
        if let value = try? JSONEncoder().encode(preferences) { defaults?.set(value, forKey: preferenceKey) }
    }
}

/// A presentation and every suspended callback share this exact owner/epoch. A nil presentation
/// still has an epoch, so a late impact query/drop cannot replace a later form or resurrect a page.
struct OwnedPresentation<Content>: Identifiable {
    let id = UUID()
    let content: Content
}
@MainActor final class PresentationOwner<Content>: ObservableObject {
    struct Ticket: Equatable, Sendable { fileprivate let epoch: UUID; fileprivate let owner: UUID? }
    @Published var item: OwnedPresentation<Content>? {
        didSet {
            if item?.id != oldValue?.id {
                epoch = UUID(); closeHandler = nil
                if reviewDismissal != oldValue?.id || item != nil { cancelWindowCloseReview() }
                reviewHandler = nil
            }
        }
    }
    private var epoch = UUID()
    private var active = true
    private var closeHandler: (id: UUID, action: @MainActor () -> Bool)?
    private var reviewHandler: (id: UUID, begin: @MainActor (WindowCloseReviewRequest) -> Void, cancel: @MainActor () -> Void)?
    private var review: (request: WindowCloseReviewRequest, ticket: Ticket)?
    private var reviewDismissal: UUID?
    func capture() -> Ticket { Ticket(epoch: epoch, owner: item?.id) }
    func owns(_ id: UUID) -> Bool { active && item?.id == id }
    func isCurrent(_ ticket: Ticket) -> Bool { active && ticket == capture() }
    @discardableResult func present(_ content: Content, ifCurrent ticket: Ticket? = nil) -> Bool {
        guard active, ticket.map(isCurrent) ?? true else { return false }
        item = OwnedPresentation(content: content); return true
    }
    func dismiss(_ id: UUID) { if owns(id) { item = nil } }
    func setActive(_ value: Bool) {
        guard active != value else { return }
        cancelWindowCloseReview()
        active = value; epoch = UUID()
        if !value { item = nil; closeHandler = nil; reviewHandler = nil }
    }
    func invalidate() { cancelWindowCloseReview(); epoch = UUID(); item = nil; closeHandler = nil; reviewHandler = nil }
    func registerClose(_ id: UUID, action: @escaping @MainActor () -> Bool) {
        guard owns(id) else { return }; closeHandler = (id, action)
    }
    func clearClose(_ id: UUID) { if closeHandler?.id == id { closeHandler = nil } }
    func attemptClose() -> Bool {
        guard let handler = closeHandler, owns(handler.id) else { return true }
        return handler.action()
    }
    func registerWindowCloseReview(_ id: UUID, begin: @escaping @MainActor (WindowCloseReviewRequest) -> Void,
                                  cancel: @escaping @MainActor () -> Void) {
        guard owns(id) else { return }; reviewHandler = (id, begin, cancel)
    }
    func clearWindowCloseReview(_ id: UUID) {
        guard reviewHandler?.id == id else { return }
        if review?.request.result == nil { cancelWindowCloseReview() }
        reviewHandler = nil
    }
    func beginWindowCloseReview(_ request: WindowCloseReviewRequest) {
        if review != nil { cancelWindowCloseReview() }
        guard active || item == nil else { request.resolve(false); return }
        review = (request, capture())
        let requestID = request.id
        request.validateApproval { [weak self] in
            guard let self, let review = self.review, review.request.id == requestID else { return false }
            return self.capture() == review.ticket && (self.active || self.item == nil)
        }
        guard let item else { request.resolve(true); return }
        guard let handler = reviewHandler, handler.id == item.id else {
            // A form still mounting or an unsupported child is not permission to drop it.
            request.resolve(false); return
        }
        handler.begin(request)
    }
    /// Explicit Save/Discard is the only dismissal allowed to transfer approval to
    /// the empty presentation epoch. Arbitrary dismiss/replacement cancels instead.
    func completeWindowCloseReview(_ request: WindowCloseReviewRequest, dismissing id: UUID) {
        guard review?.request === request, request.result == nil, owns(id) else { request.resolve(false); return }
        reviewDismissal = id
        item = nil
        reviewDismissal = nil
        review?.ticket = capture()
        request.resolve(true)
    }
    func cancelWindowCloseReview() {
        review?.request.cancel(); review = nil
        reviewHandler?.cancel()
    }
    deinit { review?.request.cancel() }
}

extension HostConfiguration {
    var vaultAuthenticationLabel: String { authentication.needsKey ? "SSH 密钥" : "密码" }
    var vaultEndpoint: String { (address.contains(":") && !address.hasPrefix("[") ? "[" + address + "]" : address) + ":" + String(port) }
}

/// Non-secret draft. Choosing the same primary method preserves legacy MFA values and references.
struct VaultHostDraft: Equatable, Identifiable {
    var configuration: HostConfiguration
    var port: String
    var interval: String
    var count: String
    var tagIDs: Set<UUID>
    private(set) var original: HostConfiguration?
    private var originalTags: Set<UUID>
    var id: UUID { configuration.id }
    var isNew: Bool { original == nil }
    var editPrecondition: HostEditPrecondition? { original.map { .init(host: $0, tagIDs: originalTags) } }
    var primaryMethod: String { configuration.authentication.needsKey ? "key" : "password" }
    init(host: HostConfiguration? = nil, settings: AppSettings, folderID: UUID? = nil, tagIDs: Set<UUID> = []) {
        let value = host ?? HostConfiguration(name: "", address: "", username: "", folderID: folderID,
            keepaliveInterval: settings.keepaliveInterval, keepaliveCountMax: settings.keepaliveCountMax)
        configuration = value; original = host; port = String(value.port)
        interval = String(value.keepaliveInterval); count = String(value.keepaliveCountMax)
        self.tagIDs = tagIDs; originalTags = tagIDs
    }
    var isDirty: Bool {
        guard let original else { return true }
        return configuration != original || port != String(original.port) || interval != String(original.keepaliveInterval)
            || count != String(original.keepaliveCountMax) || tagIDs != originalTags
    }
    mutating func changePrimaryMethod(_ value: String) {
        guard value != primaryMethod else { return }
        configuration.authentication = value == "key" ? .privateKeyWithMFA : .passwordWithMFA
        configuration.credentialRef = nil; configuration.savePasswordAuthorized = false; configuration.keyRef = nil
    }
    var fieldErrors: [String: String] {
        var errors: [String: String] = [:]
        if !Self.validText(configuration.name, limit: 256) { errors["name"] = "请输入名称（最多 256 UTF-8 字节，不含控制字符）。" }
        if (try? HostAddress(configuration.address)) == nil { errors["address"] = "输入 DNS、IPv4 或 IPv6；端口请填在端口栏，不含 ssh:// 或用户名。" }
        if (try? SSHUser(configuration.username)) == nil { errors["username"] = "请输入有效 SSH 用户名；大小写保持原样，不含空白。" }
        if let number = Int(port), (1...65535).contains(number), String(number) == port {} else { errors["port"] = "端口必须是 1–65535 的整数。" }
        if let number = Int(interval), (0...3600).contains(number) {} else { errors["interval"] = "TCP 保活间隔为 0–3600 秒；0 表示关闭。" }
        if let number = Int(count), (1...10).contains(number) {} else { errors["count"] = "TCP 失败探测次数为 1–10；实际失联时间由系统调度。" }
        if configuration.authentication.needsKey && configuration.keyRef == nil { errors["key"] = "请选择一个已登记 SSH 密钥。" }
        return errors
    }
    func value() throws -> HostConfiguration {
        guard fieldErrors.isEmpty else { throw RepositoryError.invalidField(fieldErrors.keys.sorted().first ?? "name") }
        var value = configuration
        value.port = Int(port)!; value.keepaliveInterval = Int(interval)!; value.keepaliveCountMax = Int(count)!
        return value
    }
    mutating func markCommitted(_ value: HostConfiguration) {
        configuration = value; original = value; originalTags = tagIDs
        port = String(value.port); interval = String(value.keepaliveInterval); count = String(value.keepaliveCountMax)
    }
    static func validText(_ value: String, limit: Int) -> Bool {
        !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && value.utf8.count <= limit
            && !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

/// Per-editor, non-Codable input owner used by the real View. Never shared with AppModel.
@MainActor final class VaultHostEditorModel: ObservableObject {
    @Published var draft: VaultHostDraft
    @Published var password = ""
    @Published var remember = false
    @Published var forgetExisting = false
    @Published var showPassword = false
    @Published private(set) var writing = false
    @Published private(set) var committedAwaitingRefresh = false
    @Published var issue: AppIssue?
    private(set) var cleanupPending = false
    private var active = true
    private var saveToken: UUID?
    private let ownsPresentation: @MainActor () -> Bool
    init(draft: VaultHostDraft, ownsPresentation: @escaping @MainActor () -> Bool = { true }) {
        self.draft = draft; self.ownsPresentation = ownsPresentation
    }
    var isCurrent: Bool { active && ownsPresentation() }
    var canEdit: Bool { isCurrent && !writing && !committedAwaitingRefresh }
    var canClose: Bool { isCurrent && !writing }
    var dirty: Bool { draft.isDirty || !password.isEmpty || remember || forgetExisting }
    var validForSave: Bool { draft.fieldErrors.isEmpty && (!remember || !password.isEmpty) }
    var hasTransientInput: Bool { !draft.configuration.authentication.needsKey && !password.isEmpty }
    func edit(_ change: (VaultHostEditorModel) -> Void) { if canEdit { change(self) } }
    func clearInput() { password = ""; showPassword = false; remember = false; forgetExisting = false }
    func deactivate() { active = false; saveToken = nil; writing = false; clearInput() }
    private func owns(_ token: UUID) -> Bool { isCurrent && saveToken == token }
    @discardableResult func reloadCurrent(vault: VaultDesktopModel) async -> Bool {
        guard canClose else { return false }
        let token = UUID(); saveToken = token; writing = true
        defer { if saveToken == token { writing = false; saveToken = nil } }
        return await refresh(vault: vault, token: token)
    }
    private func refresh(vault: VaultDesktopModel, token: UUID) async -> Bool {
        let loaded = await vault.load()
        guard owns(token) else { return false }
        guard loaded, let host = vault.catalog.first(where: { $0.id == draft.id }) else {
            issue = committedAwaitingRefresh
                ? AppIssue(code: "host.committedAwaitingRefresh", message: "已保存，待刷新。授权已提交；仅重读恢复，不会重复保存或撤销新凭据。")
                : (vault.issue ?? .sanitized(RepositoryError.notFound))
            return false
        }
        draft = VaultHostDraft(host: host, settings: vault.snapshot?.settings ?? AppSettings(),
                              tagIDs: vault.snapshot?.hostTagIDs[host.id] ?? [])
        clearInput()
        committedAwaitingRefresh = false; issue = nil
        if cleanupPending { vault.showNotice("配置已保存；精确秘密清理仍待重试，请勿重复新建。") }
        return true
    }
    /// Real View completion path: release the exact editor only after save/refresh has completed,
    /// then route. Otherwise AppModel's dirty-navigation guard correctly refuses the connection.
    func saveAndFinish(security: SecurityCoordinator, vault: VaultDesktopModel,
                       connect: (@MainActor (HostConfiguration, SecretBytes?) async throws -> Void)? = nil,
                       prepareConnection: (@MainActor (HostConfiguration, SecretBytes?) async throws -> VaultPreparedConnection)? = nil,
                       dismiss: @MainActor () -> Void,
                       afterDismiss: (@MainActor (HostConfiguration) -> Void)? = nil) async -> Bool {
        var prepared: VaultPreparedConnection?
        let preparation: (@MainActor (HostConfiguration, SecretBytes?) async throws -> Void)?
        if let prepareConnection { preparation = { host, secret in prepared = try await prepareConnection(host, secret) } }
        else { preparation = connect }
        let success = await save(security: security, vault: vault, connect: preparation)
        guard success, isCurrent else { prepared?.cancel(); return false }
        let saved = draft.configuration
        dismiss()
        if let prepared {
            // A dismiss refusal or a newly replaced form must not start a hidden handshake.
            guard !ownsPresentation() else { prepared.cancel(); return false }
            do { try prepared.commit() }
            catch { prepared.cancel(); issue = .security(error); return false }
        }
        afterDismiss?(saved)
        return true
    }
    func save(security: SecurityCoordinator, vault: VaultDesktopModel,
              connect: (@MainActor (HostConfiguration, SecretBytes?) async throws -> Void)? = nil) async -> Bool {
        // A repeated Save after a committed/read failure is exclusively a read retry.
        if committedAwaitingRefresh { _ = await reloadCurrent(vault: vault); return false }
        guard canEdit, validForSave else { return false }
        let token = UUID(); saveToken = token; writing = true
        defer { if saveToken == token { writing = false; saveToken = nil } }
        do {
            let supplied = try draft.value()
            let material = hasTransientInput ? SecretBytes(utf8: password) : nil
            let choice: PasswordChoice = remember ? .remember(SecretBytes(utf8: password))
                : (forgetExisting ? .forget : (supplied.credentialRef == nil ? .manual : .preserve))
            let result = try await security.saveHostCommitted(supplied, isNew: draft.isNew, password: choice,
                tagIDs: draft.tagIDs, expected: draft.editPrecondition)
            guard owns(token) else { return false }
            draft.markCommitted(result.host) // Includes the *new* committed credentialRef.
            cleanupPending = { if case .savedWithCleanupPending = result.outcome { return true }; return false }()
            committedAwaitingRefresh = true; clearInput()
            guard await refresh(vault: vault, token: token), owns(token) else { return false }
            if let connect {
                try await connect(draft.configuration, material)
                guard owns(token) else { return false }
            }
            return true
        } catch {
            guard owns(token) else { return false }
            issue = .security(error); return false // A pre-commit failure keeps the editable draft/input.
        }
    }
}

/// The real editor and global window/quit preflight share one decision. This owns
/// no connections, transfer jobs, or credential reader; Cancel is presentation-only.
@MainActor final class VaultHostCloseReview: ObservableObject {
    struct Prompt: Identifiable, Equatable {
        enum Kind: Equatable { case dirty, writing, committed }
        let id = UUID()
        let kind: Kind
    }
    @Published private(set) var prompt: Prompt?
    @Published private(set) var saving = false
    private weak var editor: VaultHostEditorModel?
    private var request: WindowCloseReviewRequest?
    private var invalidated = false
    private let dismiss: @MainActor () -> Void
    private let complete: (@MainActor (WindowCloseReviewRequest) -> Void)?
    init(editor: VaultHostEditorModel, dismiss: @escaping @MainActor () -> Void,
         complete: (@MainActor (WindowCloseReviewRequest) -> Void)? = nil) {
        self.editor = editor; self.dismiss = dismiss; self.complete = complete
    }
    func begin(_ request: WindowCloseReviewRequest? = nil) {
        guard let editor, editor.isCurrent else { request?.resolve(false); return }
        editor.showPassword = false
        if let pending = self.request, pending !== request {
            guard pending.result != nil else { request?.resolve(false); return }
            prompt = nil; self.request = nil
        }
        if let request { self.request = request }
        invalidated = false
        if prompt != nil { return }
        if editor.writing {
            editor.issue = AppIssue(code: "host.closeWriting", message: "正在保存或刷新当前主机。本次关闭已取消；请等待完成后再关闭，或继续查看当前编辑。不会重复保存或断开连接。")
            prompt = Prompt(kind: .writing)
            request?.resolve(false)
        } else if editor.committedAwaitingRefresh {
            prompt = Prompt(kind: .committed)
        } else if editor.dirty {
            prompt = Prompt(kind: .dirty)
        } else {
            finish()
        }
    }
    func matches(_ id: UUID) -> Bool { !invalidated && prompt?.id == id && editor?.isCurrent == true }
    @discardableResult func cancel(_ id: UUID) -> Bool {
        guard matches(id), !saving else { return false }
        request?.resolve(false); request = nil; prompt = nil
        return true // Keep every field, secret, and save authorization choice unchanged.
    }
    func discard(_ id: UUID) {
        guard matches(id), !saving, editor?.canClose == true else { return }
        finish()
    }
    @discardableResult func save(_ id: UUID, security: SecurityCoordinator, vault: VaultDesktopModel) async -> Bool {
        guard matches(id), !saving, let editor, editor.canClose, prompt?.kind != .writing else { return false }
        saving = true
        let success: Bool
        if editor.committedAwaitingRefresh { success = await editor.reloadCurrent(vault: vault) }
        else { success = await editor.save(security: security, vault: vault) }
        saving = false
        guard !invalidated else { prompt = nil; return false }
        guard matches(id), success else { return false }
        finish(); return true
    }
    private func finish() {
        guard let editor, editor.canClose, !invalidated, request?.result != false else { request?.resolve(false); return }
        let request = self.request
        self.request = nil; prompt = nil
        editor.clearInput()
        if let request, let complete { complete(request) }
        else { dismiss(); request?.resolve(true) }
    }
    func cancelPending() {
        invalidated = true; request?.resolve(false); request = nil
        if !saving { prompt = nil }
    }
    deinit { request?.cancel() }
}

