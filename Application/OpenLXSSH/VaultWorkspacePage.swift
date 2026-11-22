import AppKit
import SwiftUI
import OpenLXSSHCore

private struct VaultPresentation: Identifiable {
    enum Content {
        case host(HostConfiguration?, forFiles: Bool = false), folder(HostFolder?, UUID?), tag(HostTag?), newHostInFolder(UUID)
        case batch(VaultBatchConfirmation), deleteFolder(FolderDeletionImpact), deleteTag(TagDeletionImpact)
    }
    let id = UUID()
    let content: Content
}

/// Retain this page in NativeWorkspacePage, just like the existing workspace consumer.
/// The optional handler is mandatory for using an editor's unsaved password in a new connection;
/// without it, the editor disables that action rather than silently dropping the supplied password.
struct VaultWorkspacePage: View {
    let app: AppModel
    @State private var model: VaultDesktopModel
    private var page: VaultManagementPage {
        get { model.managementPage }
        nonmutating set { model.managementPage = newValue }
    }
    @State private var presentations = PresentationOwner<VaultPresentation.Content>()
    @State private var compactInspector = false
    @State private var hasCompletedInitialLoad = false
    @State private var navigationOwnerID = UUID()
    @State private var keySearchFocusRequest: UUID?
    @State private var trustSearchFocusRequest: UUID?
    private let transientConnection: VaultTransientConnectionHandler?

    init(app: AppModel, transientConnection: VaultTransientConnectionHandler? = nil) {
        self.app = app; self.transientConnection = transientConnection
        _model = State(initialValue: VaultDesktopModel(app: app))
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
        case .host, .newHostInFolder: return true
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
            .onChange(of: model.focusedID) { _, id in if id == nil { compactInspector = false } }
    }

    private var lifecycleContent: some View {
        queryObservedContent
            .task {
                presentations.setActive(app.workspacePage == .vault)
                if !model.didLoad {
                    _ = await model.load()
                }
                hasCompletedInitialLoad = true
            }
            .onChange(of: app.workspacePage) { _, value in
                presentations.setActive(value == .vault)
                if value != .vault { compactInspector = false }
            }
            .onChange(of: page) { _, value in
                if value != .hosts { compactInspector = false; presentations.invalidate() }
            }
            .onChange(of: presentations.item?.id) { _, id in if id != nil { compactInspector = false } }
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
            guard request.page == .vault, NSApp.modalWindow == nil, (NSApp.keyWindow ?? NSApp.mainWindow)?.attachedSheet == nil else { return }
        }
        if presentations.item != nil {
            if request.command != .search { _ = presentations.attemptClose() }
            return
        }
        switch request.command {
        case .newHost: page = .hosts; presentHost(nil)
        case .newFilesHost: page = .hosts; _ = presentations.present(.host(nil, forFiles: true))
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
            let inlineInspector = geometry.size.width >= 940
            HSplitView {
                VaultSidebarView(
                    app: app,
                    model: model,
                    onNavigate: { action in
                        if presentations.item != nil { _ = presentations.attemptClose(); return }
                        _ = model.performManagementNavigation(action)
                    },
                    onSelectSection: select,
                    onNewRootFolder: { _ = presentations.present(.folder(nil, nil)) },
                    onEditFolder: { _ = presentations.present(.folder($0, $0?.parentID)) },
                    onAddChildFolder: { _ = presentations.present(.folder(nil, $0)) },
                    onNewHostInFolder: { _ = presentations.present(.newHostInFolder($0)) },
                    onImportMove: importMove,
                    onDeleteFolder: deleteFolder,
                    onNewTag: { _ = presentations.present(.tag(nil)) },
                    onRenameTag: { _ = presentations.present(.tag($0)) },
                    onDeleteTag: deleteTag
                )
                .frame(minWidth: 160, idealWidth: 176, maxWidth: min(210, max(176, geometry.size.width * 0.19)))
                if page == .keys {
                    SecurityManagerView(app: app, embedded: true, searchFocusRequest: keySearchFocusRequest) { page = .hosts }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if page == .trust {
                    TrustManagementView(environment: app.sessionEnvironment, embedded: true, searchFocusRequest: trustSearchFocusRequest) { page = .hosts }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    HSplitView {
                        hostContent(inlineInspector: inlineInspector, pageHeight: geometry.size.height)
                            .frame(minWidth: 340, maxWidth: .infinity, maxHeight: .infinity)
                        if inlineInspector, model.preferences.inspector, let host = model.selectedHost {
                            VaultInspectorView(
                                model: model,
                                host: host,
                                menuItems: menuItems(host.id),
                                onCommand: perform,
                                onEdit: { presentHost(host) },
                                onClose: { model.preferences.inspector = false }
                            )
                            .frame(minWidth: 245, idealWidth: 270, maxWidth: min(336, max(270, geometry.size.width * 0.28)))
                        }
                    }
                }
            }
            .onChange(of: inlineInspector) { _, _ in compactInspector = false }
        }
    }

    @ViewBuilder private func presentationContent(_ item: OwnedPresentation<VaultPresentation.Content>) -> some View {
            switch item.content {
            case .host(let host, let forFiles):
                VaultHostEditor(app: app, vault: model, host: host, folderID: model.section.folderID, forFiles: forFiles,
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

    private func select(_ section: VaultSection) {
        _ = model.performManagementNavigation { page = .hosts; model.section = section }
    }

    private func hostContent(inlineInspector: Bool, pageHeight: CGFloat) -> some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    Text(model.title)
                        .font(.system(size: 24, weight: .semibold)).lineLimit(1)
                        .help(model.title)
                    Spacer(minLength: 4)
                    Menu {
                        Button("新建主机…") { presentHost(nil) }
                        Button("新建分组…") { _ = presentations.present(.folder(nil, model.section.folderID)) }
                    } label: {
                        Label("新建主机", systemImage: "plus")
                    } primaryAction: {
                        presentHost(nil)
                    }
                    .menuStyle(.button).buttonStyle(.borderedProminent).fixedSize()
                    Button {
                        if inlineInspector { model.preferences.inspector.toggle() }
                        else { compactInspector.toggle() }
                    } label: {
                        Image(systemName: "sidebar.right")
                            .foregroundStyle((inlineInspector ? model.preferences.inspector : compactInspector) && model.selectedHost != nil ? Color.accentColor : .secondary)
                            .frame(width: 22, height: 22)
                    }
                    .buttonStyle(.borderless)
                    .disabled(model.selectedHost == nil)
                    .help("显示或收起主机详情").accessibilityLabel("主机检查器")
                    .popover(isPresented: $compactInspector) {
                        if !inlineInspector, let host = model.selectedHost {
                            VaultInspectorView(
                                model: model,
                                host: host,
                                menuItems: menuItems(host.id),
                                onCommand: perform,
                                onEdit: { presentHost(host) },
                                onClose: { compactInspector = false }
                            )
                            .frame(width: 300, height: min(500, max(180, pageHeight - 50)))
                        }
                    }
                }
                HStack(spacing: 10) {
                    DesktopSearchField(placeholder: "搜索主机", id: "vault.hosts.search", text: $model.search, focusRequest: app.hostSearchFocusRequest)
                        .help("搜索名称、地址、用户、分组或标签")
                    Menu {
                        Picker("排序方式", selection: $model.preferences.order) {
                            Text("名称").tag(VaultOrdering.name.rawValue)
                            Text("最近连接").tag(VaultOrdering.recent.rawValue)
                        }
                        Divider()
                        Picker("顺序", selection: $model.preferences.descending) {
                            Text("升序").tag(false)
                            Text("降序").tag(true)
                        }
                    } label: { Image(systemName: "arrow.up.arrow.down") }
                    .menuStyle(.borderlessButton).fixedSize()
                    .help("排序：" + (model.ordering == .name ? "名称" : "最近连接") + (model.preferences.descending ? "降序" : "升序"))
                    .accessibilityLabel("主机排序")
                    Picker("显示方式", selection: $model.preferences.view) {
                        Label("列表", systemImage: "list.bullet").tag(VaultDisplayMode.list.rawValue)
                        Label("卡片", systemImage: "rectangle.grid.1x2").tag(VaultDisplayMode.cards.rawValue)
                    }.labelStyle(.iconOnly).pickerStyle(.segmented).labelsHidden().frame(width: 65)
                }
            }
            .padding(.horizontal, 18).padding(.top, 18).padding(.bottom, 12)
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
                HStack {
                    IssueView(issue: issue) { model.issue = nil }
                    if model.didLoad { Button("重试") { Task { _ = await model.load() } } }
                }.padding(.horizontal, 16)
            }
            if model.hosts.isEmpty {
                emptyState.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VaultHostList(model: model, action: perform, menu: menuItems)
                    .padding(.horizontal, 12).padding(.bottom, 8)
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
                if model.didLoad { Text("\(model.hosts.count) 台主机").font(.caption).foregroundStyle(.secondary) }
                if model.isLoading || model.isWriting { ProgressView().controlSize(.small) }
                if let notice = model.notice { Text(notice).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                Spacer()
                Button { Task { _ = await model.load() } } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.borderless).disabled(model.isLoading)
                    .help("刷新主机列表").accessibilityLabel("刷新")
            }.padding(.horizontal, 18).padding(.vertical, 7)
        }
    }

    @ViewBuilder private var emptyState: some View {
        if !model.didLoad {
            if model.isLoading || !hasCompletedInitialLoad {
                ProgressView("正在读取主机…").controlSize(.small)
            } else {
                ContentUnavailableView {
                    Label("无法读取本地主机", systemImage: "exclamationmark.triangle")
                } description: {
                    Text("本地配置暂时不可用。")
                } actions: {
                    Button("重新读取") { Task { _ = await model.load() } }
                }
            }
        } else if !model.search.isEmpty || !model.tagFilter.isEmpty {
            ContentUnavailableView {
                Label("没有匹配的主机", systemImage: "magnifyingglass")
            } description: {
                Text("试试其他关键词，或清除搜索和标签筛选。")
            } actions: {
                Button("清除搜索和标签") { model.search = ""; model.tagFilter = [] }
            }
        } else {
            switch model.section {
            case .all:
                ContentUnavailableView {
                    Label("添加第一台主机", systemImage: "server.rack")
                } description: {
                    Text("新建主机以保存连接地址和登录方式。")
                } actions: {
                    Button("新建主机") { presentHost(nil) }.buttonStyle(.borderedProminent)
                    Button("导入密钥…") { page = .keys }
                }
            case .favorites:
                ContentUnavailableView {
                    Label("还没有收藏的主机", systemImage: "star")
                } description: {
                    Text("在主机的快捷菜单中选择“收藏”，即可在这里找到它。")
                } actions: {
                    Button("查看所有主机") { select(.all) }
                }
            case .ungrouped, .folder:
                ContentUnavailableView {
                    Label("此分组中还没有主机", systemImage: "folder")
                } description: {
                    Text("在这里新建主机，或从其他分组移入主机。")
                } actions: {
                    Button("新建主机") { presentHost(nil) }
                }
            }
        }
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

private struct VaultConfirmationView: View {
    let title: String
    let detail: String
    let targets: [String]
    let model: VaultDesktopModel
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
    let vault: VaultDesktopModel
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
