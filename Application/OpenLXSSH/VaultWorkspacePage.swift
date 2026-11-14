import AppKit
import SwiftUI
import OpenLXSSHCore

private struct VaultPresentation: Identifiable {
    enum Content {
        case host(HostConfiguration?), folder(HostFolder?, UUID?), tag(HostTag?), newHostInFolder(UUID)
        case batch(VaultBatchConfirmation), deleteFolder(FolderDeletionImpact), deleteTag(TagDeletionImpact)
    }
    let id = UUID()
    let content: Content
}

/// Retain this page in NativeWorkspacePage, just like the existing workspace consumer.
/// The optional handler is mandatory for using an editor's unsaved password in a new connection;
/// without it, the editor disables that action rather than silently dropping the supplied password.
struct VaultWorkspacePage: View {
    @ObservedObject var app: AppModel
    @StateObject private var model: VaultDesktopModel
    private var page: VaultManagementPage {
        get { model.managementPage }
        nonmutating set { model.managementPage = newValue }
    }
    @StateObject private var presentations = PresentationOwner<VaultPresentation.Content>()
    @State private var compactInspector = false
    @State private var navigationOwnerID = UUID()
    @State private var keySearchFocusRequest: UUID?
    @State private var trustSearchFocusRequest: UUID?
    private let transientConnection: VaultTransientConnectionHandler?
    init(app: AppModel, transientConnection: VaultTransientConnectionHandler? = nil) {
        self.app = app; self.transientConnection = transientConnection
        _model = StateObject(wrappedValue: VaultDesktopModel(app: app))
    }
    var body: some View {
        lifecycleContent
        .nativeSheet(item: $presentations.item, isEnabled: app.workspacePage == .vault,
                     allowsTerminationReview: allowsHostTerminationReview, onAttemptDismiss: {
            presentations.attemptClose()
        }) { item in presentationContent(item) }
    }
    private var allowsHostTerminationReview: Bool {
        guard let content = presentations.item?.content else { return false }
        switch content {
        case .host(_), .newHostInFolder(_): return true
        default: return false
        }
    }
    private var queryObservedContent: some View {
        workspaceContent
            .background(DesktopStyle.background)
            .onChange(of: model.search) { _, _ in model.scheduleLoad() }
            .onChange(of: model.section) { _, _ in model.scheduleLoad() }
            .onChange(of: model.tagFilter) { _, _ in model.scheduleLoad() }
            .onChange(of: model.preferences.order) { _, _ in model.scheduleLoad() }
            .onChange(of: model.preferences.descending) { _, _ in model.scheduleLoad() }
            .onChange(of: model.focusedID) { _, id in if id != nil { compactInspector = true } }
    }
    private var lifecycleContent: some View {
        queryObservedContent
            .task { presentations.setActive(app.workspacePage == .vault); if !model.didLoad { _ = await model.load() } }
            .onChange(of: app.workspacePage) { _, value in presentations.setActive(value == .vault) }
            .onChange(of: page) { _, value in if value != .hosts { presentations.invalidate() } }
            .onAppear(perform: registerNavigationGuard)
            .onDisappear {
                app.clearWorkspaceNavigationGuard(owner: navigationOwnerID)
                app.clearWindowCloseReview(owner: navigationOwnerID)
                model.clearManagementNavigationGuard(owner: navigationOwnerID)
                presentations.setActive(false)
            }
            .onChange(of: app.workspaceCommand) { _, request in consumeCommand(request) }
    }
    private func registerNavigationGuard() {
        let owner = presentations
        model.registerManagementNavigationGuard(owner: navigationOwnerID) { [weak owner] in
            guard let owner, owner.item != nil else { return true }
            _ = owner.attemptClose(); return false
        }
        app.registerWorkspaceNavigationGuard(owner: navigationOwnerID) { [weak owner] in
            guard let owner, owner.item != nil else { return true }
            _ = owner.attemptClose(); return false
        }
        app.registerWindowCloseReview(owner: navigationOwnerID, begin: { [weak owner] request in
            guard let owner else { request.resolve(false); return }
            owner.beginWindowCloseReview(request)
        }, cancel: { [weak owner] in owner?.cancelWindowCloseReview() })
    }
    private func consumeCommand(_ request: WorkspaceCommandRequest?) {
        guard app.workspacePage == .vault, let request, request == app.workspaceCommand else { return }
        if request.command == .search {
            guard request.page == .vault, NSApp.modalWindow == nil, NSApp.mainWindow?.attachedSheet == nil else { return }
        }
        if presentations.item != nil {
            if request.command != .search { _ = presentations.attemptClose() }
            return
        }
        switch request.command {
        case .newHost: page = .hosts; presentHost(nil)
        case .search:
            switch page {
            case .hosts: _ = app.focusHostSearch(for: request)
            case .keys: keySearchFocusRequest = UUID()
            case .trust: trustSearchFocusRequest = UUID()
            }
        default: break
        }
    }
    private var workspaceContent: some View {
        GeometryReader { geometry in
            HSplitView {
                sidebar.frame(minWidth: 180, idealWidth: 215, maxWidth: 240)
                if page == .keys {
                    SecurityManagerView(app: app, embedded: true, searchFocusRequest: keySearchFocusRequest) { page = .hosts }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if page == .trust {
                    TrustManagementView(environment: app.sessionEnvironment, embedded: true, searchFocusRequest: trustSearchFocusRequest) { page = .hosts }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    HSplitView {
                        hostContent.frame(minWidth: 300, maxWidth: .infinity, maxHeight: .infinity)
                        if model.preferences.inspector && geometry.size.width >= 1100 {
                            inspector.frame(minWidth: 340, idealWidth: 360, maxWidth: 380)
                        }
                    }
                    .overlay(alignment: .trailing) {
                        if model.preferences.inspector, geometry.size.width < 1100, compactInspector, model.selectedHost != nil {
                            ZStack(alignment: .trailing) {
                                Color.black.opacity(0.12).contentShape(Rectangle()).onTapGesture { compactInspector = false }
                                inspector.frame(width: min(380, max(300, geometry.size.width - 220)))
        .background(DesktopStyle.background).shadow(radius: 8)
                            }
                        }
                    }
                }
            }
        }
    }
    @ViewBuilder private func presentationContent(_ item: OwnedPresentation<VaultPresentation.Content>) -> some View {
            switch item.content {
            case .host(let host):
                VaultHostEditor(app: app, vault: model, host: host, folderID: model.section.folderID,
                    transientConnection: transientConnection, ownsPresentation: { presentations.owns(item.id) },
                    registerClose: { presentations.registerClose(item.id, action: $0) }, clearClose: { presentations.clearClose(item.id) },
                    registerWindowCloseReview: { begin, cancel in presentations.registerWindowCloseReview(item.id, begin: begin, cancel: cancel) },
                    clearWindowCloseReview: { presentations.clearWindowCloseReview(item.id) },
                    completeWindowCloseReview: { presentations.completeWindowCloseReview($0, dismissing: item.id) }) { presentations.dismiss(item.id) }
            case .newHostInFolder(let id):
                VaultHostEditor(app: app, vault: model, host: nil, folderID: id,
                    transientConnection: transientConnection, ownsPresentation: { presentations.owns(item.id) },
                    registerClose: { presentations.registerClose(item.id, action: $0) }, clearClose: { presentations.clearClose(item.id) },
                    registerWindowCloseReview: { begin, cancel in presentations.registerWindowCloseReview(item.id, begin: begin, cancel: cancel) },
                    clearWindowCloseReview: { presentations.clearWindowCloseReview(item.id) },
                    completeWindowCloseReview: { presentations.completeWindowCloseReview($0, dismissing: item.id) }) { presentations.dismiss(item.id) }
            case .folder(let folder, let parent):
                VaultFolderEditor(vault: model, folder: folder, parentID: parent, ownsPresentation: { presentations.owns(item.id) }) { presentations.dismiss(item.id) }
            case .tag(let tag): VaultTagEditor(vault: model, tag: tag, ownsPresentation: { presentations.owns(item.id) }) { presentations.dismiss(item.id) }
            case .batch(let confirmation):
                VaultConfirmationView(title: confirmation.title, detail: confirmation.detail,
                    targets: model.catalog.filter { confirmation.hostIDs.contains($0.id) }.map { $0.name + " · " + $0.vaultEndpoint }, model: model) {
                        guard presentations.owns(item.id) else { return }
                        if await model.apply(confirmation.changes, success: "已更新 \(confirmation.hostIDs.count) 台主机。") { presentations.dismiss(item.id) }
                    } cancel: { presentations.dismiss(item.id) }
            case .deleteFolder(let impact):
                VaultConfirmationView(title: "删除分组“\(impact.folder.name)”？",
                    detail: "\(impact.directHostCount) 台直接主机与 \(impact.directChildFolderCount) 个直接子组将移到" + (impact.folder.parentID.map(model.path(for:)) ?? "未分组") + "。不删除任何主机或子组。",
                    targets: [model.path(for: impact.folder.id)], model: model) {
                        guard presentations.owns(item.id) else { return }
                        if await model.apply([.deleteFolder(impact.folder.id)]) { presentations.dismiss(item.id) }
                    } cancel: { presentations.dismiss(item.id) }
            case .deleteTag(let impact):
                VaultConfirmationView(title: "删除标签“\(impact.tag.name)”？", detail: "将移除 \(impact.hostCount) 台主机上的这个标签关联，不删除任何主机。仅从单台主机移除标签请使用主机菜单。",
                    targets: [impact.tag.name], model: model) {
                        guard presentations.owns(item.id) else { return }
                        if await model.apply([.deleteTag(impact.tag.id)]) { presentations.dismiss(item.id) }
                    } cancel: { presentations.dismiss(item.id) }
            }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("本地保险箱").font(.headline).padding(.horizontal, 10).padding(.vertical, 12)
            navigation("主机", icon: "server.rack", active: page == .hosts) { page = .hosts }
            navigation("密钥与凭据", icon: "key", active: page == .keys) { page = .keys }
            navigation("已知主机", icon: "checkmark.shield", active: page == .trust) { page = .trust }
            Divider().padding(.vertical, 8)
            ScrollView {
                VStack(alignment: .leading, spacing: 3) {
                    navigation("所有主机", icon: "square.stack", active: page == .hosts && model.section == .all) { select(.all) }
                    navigation("收藏", icon: "star", active: page == .hosts && model.section == .favorites) { select(.favorites) }
                    navigation("未分组", icon: "tray", active: page == .hosts && model.section == .ungrouped) { select(.ungrouped) }
                    HStack {
                        Text("分组").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button { _ = presentations.present(.folder(nil, nil)) } label: { Image(systemName: "plus") }
                            .buttonStyle(.plain).help("新建根分组").accessibilityLabel("新建根分组")
                    }.padding(.horizontal, 10).padding(.top, 14).padding(.bottom, 5)
                    VaultFolderTree(model: model, parentID: nil, depth: 0, select: { select(.folder($0)) },
                        edit: { _ = presentations.present(.folder($0, $0?.parentID)) },
                        add: { _ = presentations.present(.folder(nil, $0)) },
                        newHost: { _ = presentations.present(.newHostInFolder($0)) },
                        importMove: importMove, remove: deleteFolder)
                    HStack {
                        Text("标签 · 多选同时匹配").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button { _ = presentations.present(.tag(nil)) } label: { Image(systemName: "plus") }
                            .buttonStyle(.plain).help("新建标签").accessibilityLabel("新建标签")
                    }.padding(.horizontal, 10).padding(.top, 14).padding(.bottom, 5)
                    ForEach(model.tags) { tag in
                        Button {
                            _ = model.performManagementNavigation {
                                page = .hosts
                                if model.tagFilter.contains(tag.id) { model.tagFilter.remove(tag.id) } else { model.tagFilter.insert(tag.id) }
                            }
                        } label: {
                            HStack { Image(systemName: model.tagFilter.contains(tag.id) ? "checkmark.circle.fill" : "tag"); Text(tag.name).lineLimit(1); Spacer() }
                                .padding(.horizontal, 10).padding(.vertical, 6).contentShape(Rectangle())
                        }.buttonStyle(.plain)
                        .contextMenu {
                            Button("重命名标签…") { _ = presentations.present(.tag(tag)) }
                            Button("删除全局标签…", role: .destructive) { deleteTag(tag.id) }
                        }
                    }
                }.padding(.horizontal, 6)
            }
            Divider()
            navigation("设置…", icon: "gearshape", active: false) { _ = app.sendWorkspaceCommand(.settings) }
            Text("仅本机配置与系统 Keychain；无云同步或独立保险箱锁。").font(.caption2).foregroundStyle(.secondary).padding(10)
        }.background(DesktopStyle.background)
    }
    private func navigation(_ title: String, icon: String, active: Bool, action: @escaping () -> Void) -> some View {
        Button(action: {
            if presentations.item != nil { _ = presentations.attemptClose(); return }
            _ = model.performManagementNavigation(action)
        }) {
            Label(title, systemImage: icon).frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 10).padding(.vertical, 8)
                .background(active ? Color.primary.opacity(0.08) : .clear, in: RoundedRectangle(cornerRadius: 7))
                .contentShape(Rectangle())
        }.buttonStyle(.plain).padding(.horizontal, 6).accessibilityAddTraits(active ? .isSelected : [])
    }
    private func select(_ section: VaultSection) {
        _ = model.performManagementNavigation { page = .hosts; model.section = section }
    }

    private var hostContent: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                NativeField(placeholder: "搜索名称、地址、用户、分组或标签", id: "vault.hosts.search", text: $model.search, focusRequest: app.hostSearchFocusRequest)
                    .frame(height: 28)
                if !model.search.isEmpty { Button { model.search = "" } label: { Image(systemName: "xmark.circle.fill") }.buttonStyle(.plain).accessibilityLabel("清除搜索") }
            }.padding(16)
            HStack(spacing: 10) {
                Menu {
                    Button("新建主机…") { presentHost(nil) }
                    Button("新建分组…") { _ = presentations.present(.folder(nil, model.section.folderID)) }
                } label: { Label("新建", systemImage: "plus") }.fixedSize()
                Text(model.title).font(.headline).lineLimit(1)
                Spacer(minLength: 4)
                Menu {
                    Button("名称") { model.preferences.order = VaultOrdering.name.rawValue }
                    Button("最近连接") { model.preferences.order = VaultOrdering.recent.rawValue }
                    Divider()
                    Button(model.preferences.descending ? "改为升序 ↑" : "改为降序 ↓") { model.preferences.descending.toggle() }
                } label: { Label(model.ordering == .name ? "名称" : "最近连接", systemImage: model.preferences.descending ? "arrow.down" : "arrow.up") }.fixedSize()
                Picker("显示方式", selection: Binding(get: { model.preferences.view }, set: { model.preferences.view = $0 })) {
                    Image(systemName: "list.bullet").tag(VaultDisplayMode.list.rawValue)
                    Image(systemName: "rectangle.grid.1x2").accessibilityLabel("卡片").tag(VaultDisplayMode.cards.rawValue)
                }.pickerStyle(.segmented).labelsHidden().frame(width: 72)
                Button { model.preferences.inspector.toggle(); compactInspector = model.preferences.inspector } label: { Image(systemName: "sidebar.right") }
                    .help("显示或收起检查器").accessibilityLabel("主机检查器")
            }.padding(.horizontal, 16).padding(.bottom, 12)
            if !model.tagFilter.isEmpty {
                ScrollView(.horizontal) {
                    HStack {
                        ForEach(model.tags.filter { model.tagFilter.contains($0.id) }) { tag in
                            Button { model.tagFilter.remove(tag.id) } label: { Label(tag.name, systemImage: "xmark") }.buttonStyle(.bordered).controlSize(.small)
                        }
                        Button("清除筛选") { model.clearFilters() }.font(.caption)
                    }
                }.padding(.horizontal, 16).padding(.bottom, 8)
            }
            if let issue = model.issue {
                HStack { IssueView(issue: issue) { model.issue = nil }; Button("重试") { Task { _ = await model.load() } } }.padding(.horizontal, 12)
            }
            if model.hosts.isEmpty {
                emptyState.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VaultHostList(model: model, action: perform, menu: menuItems)
            }
            if model.selectedIDs.count > 1 {
                HStack {
                    Text("已选择 \(model.selectedIDs.count) 台").font(.caption)
                    Menu("批量操作") { VaultHostMenu(items: batchMenu(model.actionIDs()), action: perform) }
                    Spacer()
                    Text("连接仅作用于当前行").font(.caption2).foregroundStyle(.secondary)
                }.padding(10).background(DesktopStyle.panel)
            }
            Divider()
            HStack {
                Text("\(model.hosts.count) 台主机").font(.caption).foregroundStyle(.secondary)
                if model.isLoading || model.isWriting { ProgressView().controlSize(.small) }
                if let notice = model.notice { Text(notice).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                Spacer()
                Button("刷新") { Task { _ = await model.load() } }.disabled(model.isLoading)
            }.padding(12)
        }
    }
    private var emptyState: some View {
        ContentUnavailableView {
            Label(!model.didLoad && model.issue != nil ? "无法读取本地配置" : (!model.didLoad ? "正在加载…" : (model.catalog.isEmpty ? "尚无主机" : "没有匹配的主机")), systemImage: "server.rack")
        } description: {
            Text(model.issue != nil ? "已有数据不会因读取失败被清除。请检查后重试。" : (model.catalog.isEmpty ? "添加一台主机，或先导入 SSH 密钥。" : "尝试其他关键词，或清除分组和标签筛选。"))
        } actions: {
            if model.issue != nil { Button("重试") { Task { _ = await model.load() } } }
            else if model.catalog.isEmpty { Button("新建主机") { presentHost(nil) }; Button("导入密钥") { page = .keys } }
            else { Button("清除筛选") { model.clearFilters() } }
        }
    }
    private var inspector: some View {
        VStack(spacing: 0) {
            HStack {
                Text("主机详情").font(.headline)
                Spacer()
                if let host = model.selectedHost {
                    Button { presentHost(host) } label: { Image(systemName: "pencil") }.help("编辑主机").accessibilityLabel("编辑主机")
                    Menu { VaultHostMenu(items: menuItems(host.id), action: perform) } label: { Image(systemName: "ellipsis") }.menuStyle(.borderlessButton).fixedSize()
                }
                Button { model.preferences.inspector = false; compactInspector = false } label: { Image(systemName: "xmark") }.accessibilityLabel("收起检查器")
            }.padding(16)
            Divider()
            if let host = model.selectedHost {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        Text(host.name).font(.title2).bold().textSelection(.enabled)
                        detailSection("地址") { Text(host.vaultEndpoint).textSelection(.enabled) }
                        detailSection("常规") {
                            LabeledContent("分组", value: host.folderID.map(model.path(for:)) ?? "未分组")
                            Text((model.metadata(for: host.id)?.tags ?? []).map { "#" + $0.name }.joined(separator: "  ")).font(.caption).foregroundStyle(.secondary)
                        }
                        detailSection("SSH") { LabeledContent("用户名", value: host.username); LabeledContent("端口", value: String(host.port)) }
                        detailSection("凭据") {
                            Text(host.vaultAuthenticationLabel)
                            if let key = model.snapshot?.keys.first(where: { $0.id == host.keyRef }) { Text(key.label.isEmpty ? key.algorithm.rawValue.uppercased() + " · " + key.id.uuidString.prefix(8) : key.label).font(.caption) }
                            else if host.credentialRef != nil { Text("已保存密码 · 不读取或显示内容").font(.caption).foregroundStyle(.secondary) }
                        }
                        DisclosureGroup("高级") {
                            LabeledContent("TCP 空闲/重试间隔", value: host.keepaliveInterval == 0 ? "已关闭（0 秒）" : "\(host.keepaliveInterval) 秒")
                            LabeledContent("TCP 失败探测次数", value: "\(host.keepaliveCountMax) 次")
                            if host.keepaliveInterval > 0 {
                                Text("系统 TCP 保活，不开额外 SSH 通道；实际失联判断时间由系统调度，不是 SSH 程序响应保证。")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Text("TCP 保活不申请额外 SSH 通道或执行命令；不能保证远端任务在断线后继续。").font(.caption).foregroundStyle(.secondary)
                            Text("最近认证成功：" + (host.lastConnectedAt?.formatted() ?? "从未连接")).font(.caption).foregroundStyle(.secondary)
                        }
                    }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                }
                Divider()
                HStack {
                    Button("编辑") { presentHost(host) }
                    Spacer()
                    Button("连接") { perform(.connect(host.id, .reuse)) }.buttonStyle(.borderedProminent)
                }.padding(16)
            } else {
                ContentUnavailableView("选择一台主机", systemImage: "rectangle.and.text.magnifyingglass", description: Text("单击查看配置，双击或 Enter 才连接。"))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }.frame(maxHeight: .infinity).background(DesktopStyle.panel)
    }
    private func detailSection<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) { Text(title).font(.caption).foregroundStyle(.secondary); content() }
            .padding(12).frame(maxWidth: .infinity, alignment: .leading).background(DesktopStyle.background, in: RoundedRectangle(cornerRadius: 8))
    }
    private func presentHost(_ host: HostConfiguration?) { _ = presentations.present(.host(host)) }
    private func menuItems(_ id: UUID) -> [VaultHostMenuItem] {
        let ids = model.actionIDs(for: id)
        return [.init(title: "连接", command: .connect(id, .reuse)), .init(title: "在新会话打开", command: .connect(id, .newSession)), .separator,
            .init(title: "编辑…", command: .edit(id)), .init(title: "复制配置", command: .duplicate(id)), .separator]
            + batchMenu(ids) + [.separator, .init(title: "复制端点", command: .copyEndpoint(id))]
    }
    private func batchMenu(_ ids: [UUID]) -> [VaultHostMenuItem] {
        let allFavorite = !ids.isEmpty && ids.allSatisfy { id in model.catalog.first { $0.id == id }?.isFavorite == true }
        return [.init(title: allFavorite ? "取消收藏" : "收藏", command: .favorite(ids, !allFavorite)),
            .init(title: "移动到分组", children: [.init(title: "未分组", command: .move(ids, nil))] + model.folders.map { .init(title: model.folderLabel($0), command: .move(ids, $0.id)) }),
            .init(title: "添加标签", children: model.tags.map { .init(title: $0.name, command: .tag(ids, $0.id, true)) }),
            .init(title: "移除标签关联", children: model.tags.map { .init(title: $0.name, command: .tag(ids, $0.id, false)) }),
            .separator, .init(title: "删除主机配置…", command: .delete(ids), destructive: true)]
    }
    private func perform(_ command: VaultHostCommand) {
        guard !model.isWriting else { return }
        switch command {
        case .connect(let id, let mode):
            guard model.catalog.contains(where: { $0.id == id }) else { return }
            app.requestSession(hostID: id, mode: mode) // Never opens all selected rows.
        case .edit(let id): presentHost(model.catalog.first { $0.id == id })
        case .duplicate(let id): Task { _ = await model.duplicate(id) }
        case .copyEndpoint(let id):
            guard let host = model.catalog.first(where: { $0.id == id }) else { return }
            NSPasteboard.general.clearContents()
            if NSPasteboard.general.setString(host.vaultEndpoint, forType: .string) { model.showNotice("端点已复制。") }
        case .favorite(let ids, let value): presentBatch(model.favoriteConfirmation(ids: ids, value: value))
        case .move(let ids, let folder): presentBatch(model.moveConfirmation(ids: ids, folderID: folder))
        case .tag(let ids, let tag, let assign): presentBatch(model.tagsConfirmation(ids: ids, tagID: tag, assign: assign))
        case .delete(let ids): presentBatch(model.deleteConfirmation(ids: ids))
        }
    }
    private func presentBatch(_ value: VaultBatchConfirmation) { if !value.hostIDs.isEmpty { _ = presentations.present(.batch(value)) } }
    private func importMove(_ providers: [NSItemProvider], to folderID: UUID?) -> Bool {
        let ticket = presentations.capture()
        return model.importHostDrag(providers, to: folderID) { value in
            guard !value.hostIDs.isEmpty else { return }
            _ = presentations.present(.batch(value), ifCurrent: ticket)
        }
    }
    private func deleteFolder(_ id: UUID) {
        let ticket = presentations.capture()
        Task {
            do {
                let impact = try await model.repository.folderDeletionImpact(id: id)
                _ = presentations.present(.deleteFolder(impact), ifCurrent: ticket)
            } catch { if presentations.isCurrent(ticket) { model.issue = .sanitized(error) } }
        }
    }
    private func deleteTag(_ id: UUID) {
        let ticket = presentations.capture()
        Task {
            do {
                let impact = try await model.repository.tagDeletionImpact(id: id)
                _ = presentations.present(.deleteTag(impact), ifCurrent: ticket)
            } catch { if presentations.isCurrent(ticket) { model.issue = .sanitized(error) } }
        }
    }
}

private struct VaultFolderTree: View {
    @ObservedObject var model: VaultDesktopModel
    let parentID: UUID?
    let depth: Int
    let select: (UUID) -> Void
    let edit: (HostFolder?) -> Void
    let add: (UUID?) -> Void
    let newHost: (UUID) -> Void
    let importMove: ([NSItemProvider], UUID?) -> Bool
    let remove: (UUID) -> Void
    var body: some View {
        ForEach(model.children(of: parentID)) { folder in
            VStack(spacing: 0) {
                HStack(spacing: 5) {
                    Button { model.toggleExpanded(folder.id) } label: { Image(systemName: model.preferences.expandedFolders.contains(folder.id) ? "chevron.down" : "chevron.right").font(.caption2).frame(width: 12) }
                        .buttonStyle(.plain).accessibilityLabel("展开或折叠“\(folder.name)”")
                    Button { select(folder.id) } label: {
                        Label(folder.name + (model.folders.filter { $0.name == folder.name }.count > 1 ? " · " + folder.id.uuidString.prefix(6) : ""), systemImage: "folder")
                            .lineLimit(1).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                    }.buttonStyle(.plain)
                }.padding(.vertical, 7).padding(.leading, CGFloat(depth * 12 + 6)).padding(.trailing, 6)
                    .background(model.section == .folder(folder.id) ? Color.primary.opacity(0.08) : .clear, in: RoundedRectangle(cornerRadius: 7))
                    .help(model.folderLabel(folder))
                    .onDrop(of: [.text], isTargeted: nil) { providers in importMove(providers, folder.id) }
                    .contextMenu {
                        Button("新建主机…") { newHost(folder.id) }
                        Button("新建子组…") { add(folder.id) }
                        Button("重命名或移动…") { edit(folder) }
                        Button("删除分组…", role: .destructive) { remove(folder.id) }
                    }
                if model.preferences.expandedFolders.contains(folder.id) {
                    AnyView(VaultFolderTree(model: model, parentID: folder.id, depth: depth + 1, select: select, edit: edit, add: add, newHost: newHost, importMove: importMove, remove: remove))
                }
            }
        }
    }
}

private struct VaultConfirmationView: View {
    let title: String
    let detail: String
    let targets: [String]
    @ObservedObject var model: VaultDesktopModel
    let confirm: () async -> Void
    let cancel: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title).font(.title3).bold()
            Text(detail).fixedSize(horizontal: false, vertical: true)
            ScrollView { VStack(alignment: .leading, spacing: 6) { ForEach(targets.indices, id: \.self) { Text(targets[$0]).font(.caption).textSelection(.enabled) } }.frame(maxWidth: .infinity, alignment: .leading) }.frame(maxHeight: 160)
            IssueView(issue: model.issue) { model.issue = nil }
            HStack { Spacer(); Button("取消", action: cancel).keyboardShortcut(.cancelAction).disabled(model.isWriting); Button("确认") { Task { await confirm() } }.disabled(model.isWriting) }
        }.padding(24).frame(width: 480)
    }
}

private struct VaultTagEditor: View {
    @ObservedObject var vault: VaultDesktopModel
    let tag: HostTag?
    @State private var name: String
    let dismiss: () -> Void
    private let ownsPresentation: @MainActor () -> Bool
    init(vault: VaultDesktopModel, tag: HostTag?, ownsPresentation: @escaping @MainActor () -> Bool = { true }, dismiss: @escaping () -> Void) {
        self.vault = vault; self.tag = tag; self.dismiss = dismiss; self.ownsPresentation = ownsPresentation
        _name = State(initialValue: tag?.name ?? "")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(tag == nil ? "新建标签" : "重命名标签").font(.title3).bold()
            NativeField(placeholder: "标签名称", id: "vault.tag.name", text: $name, onSubmit: { _ in save() }).frame(height: 28)
            if !VaultHostDraft.validText(name, limit: 256) { Text("名称必填，最多 256 UTF-8 字节，不含控制字符。").font(.caption).foregroundStyle(.secondary) }
            Text("标签只用于本地组织，不改变主机凭据。保存标签不会自动关联主机。").font(.caption).foregroundStyle(.secondary)
            IssueView(issue: vault.issue) { vault.issue = nil }
            HStack {
                Spacer(); Button("取消", action: dismiss).keyboardShortcut(.cancelAction)
                Button("保存", action: save).disabled(vault.isWriting || !VaultHostDraft.validText(name, limit: 256))
            }
        }.padding(24).frame(width: 420)
    }
    private func save() {
        guard !vault.isWriting, VaultHostDraft.validText(name, limit: 256), ownsPresentation() else { return }
        Task {
            guard ownsPresentation() else { return }
            let value = HostTag(id: tag?.id ?? UUID(), name: name)
            if await vault.apply([.saveTag(value)]), ownsPresentation() { dismiss() }
        }
    }
}
