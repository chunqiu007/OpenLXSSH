import AppKit
import SwiftUI
import OpenLXSSHCore

private struct EditorPresentation: Identifiable {
    enum Content { case host(HostConfiguration?), folder(HostFolder?), settings, security, trust, deletion(DeletionTarget) }
    let id = UUID()
    let content: Content
}
private enum DeletionTarget { case host(HostConfiguration), folder(HostFolder) }
private struct ConnectionChooserPresentation: Identifiable { let id = UUID() }

struct MainView: View {
    @ObservedObject var model: AppModel
    @ObservedObject private var files: FilesController
    init(model: AppModel) { self.model = model; files = model.files }
    var body: some View {
        VStack(spacing: 0) {
            WorkspaceTabBar(model: model)
            Divider()
            ZStack {
                NativeWorkspacePage(id: "workspace.page.vault", isVisible: model.workspacePage == .vault) { VaultWorkspaceView(model: model) }
                NativeWorkspacePage(id: "workspace.page.sftp", isVisible: model.workspacePage == .sftp) { SFTPWorkspaceView(model: model) }
                NativeWorkspacePage(id: "workspace.page.sessions", isVisible: model.workspacePage.sessionID != nil) { SessionWorkspaceView(controller: model.sessions) }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
            FilesApplicationUI(model: files, showsTasks: model.workspacePage == .sftp)
        }
        .frame(minWidth: 920, minHeight: 580)
        .preferredColorScheme(model.settings.theme == .system ? nil : (model.settings.theme == .dark ? .dark : .light))
        .task { if !model.didLoad { await model.reload() } }
    }
}

private struct VaultWorkspaceView: View {
    @ObservedObject var model: AppModel
    @ObservedObject private var sessions: SessionController
    @ObservedObject private var files: FilesController
    @State private var editor: EditorPresentation?
    @State private var page = "hosts"
    @State private var showsDetail = true
    init(model: AppModel) { self.model = model; sessions = model.sessions; files = model.files }
    private var title: String {
        switch model.selection {
        case .all: "所有主机"
        case .favorites: "收藏"
        case .ungrouped: "未分组"
        case .folder(let id): model.folders.first(where: { $0.id == id })?.name ?? "文件夹"
        }
    }
    private var selectedFolder: HostFolder? {
        if case .folder(let id) = model.selection { return model.folders.first { $0.id == id } }
        return nil
    }
    var body: some View {
        GeometryReader { geometry in
            HSplitView {
                sidebar.frame(minWidth: 190, idealWidth: 215, maxWidth: 240)
                if page == "keys" {
                    SecurityManagerView(app: model, embedded: true) { page = "hosts" }.frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if page == "trust" {
                    TrustManagementView(environment: model.sessionEnvironment, embedded: true) { page = "hosts" }.frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    HSplitView {
                        VStack(spacing: 0) {
                            HStack(spacing: 12) {
                                Text(title).font(.title2).bold()
                                Spacer()
                                NativeButton(title: "添加主机", id: "host.add", enabled: !model.isWriting) { editor = EditorPresentation(content: .host(nil)) }.fixedSize()
                                Button { showsDetail.toggle() } label: { Image(systemName: "sidebar.right") }
                                    .help("显示或收起主机详情").accessibilityLabel("主机详情")
                            }.padding(20)
                            HStack {
                                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                                NativeField(placeholder: "搜索名称、地址或用户名", id: "hosts.search", text: $model.search, focusRequest: model.hostSearchFocusRequest).frame(height: 28)
                                if !model.search.isEmpty { Button("清除") { model.search = "" } }
                            }.padding(.horizontal, 20).padding(.bottom, 16)
                            if model.hosts.isEmpty {
                                ContentUnavailableView {
                                    Label(model.didLoad ? (model.search.isEmpty ? "尚无主机" : "没有匹配的主机") : "正在加载本地数据…", systemImage: "server.rack")
                                } description: {
                                    Text(model.search.isEmpty ? "添加主机，开始一次 SSH 连接。" : "尝试其他关键词，或清除筛选。")
                                } actions: {
                                    if model.search.isEmpty { Button("添加主机") { editor = EditorPresentation(content: .host(nil)) } }
                                    else { Button("清除搜索") { model.search = "" } }
                                }
                            } else {
                                HostTable(hosts: model.hosts, selectedID: $model.selectedHostID) { model.requestSession(hostID: $0, mode: .reuse) }
                            }
                            Divider()
                            HStack {
                                Text("\(model.hosts.count) 台主机").font(.caption).foregroundStyle(.secondary)
                                if model.isLoading || model.isWriting { ProgressView().controlSize(.small) }
                                Spacer()
                                NativeButton(title: "刷新", id: "hosts.refresh") { Task { await model.reload() } }.fixedSize()
                            }.padding(12)
                        }.frame(minWidth: 300, maxWidth: .infinity, maxHeight: .infinity)
                        if showsDetail && geometry.size.width >= 1100 {
                            ScrollView { detail }.frame(minWidth: 300, idealWidth: 340, maxWidth: 380)
                        }
                    }
                }
            }
            .overlay(alignment: .trailing) {
                if page == "hosts", showsDetail, geometry.size.width < 1100, model.selectedHost != nil {
                    ScrollView { detail }
                        .frame(width: min(360, geometry.size.width - 240))
                        .frame(maxHeight: .infinity).background(.regularMaterial)
                        .overlay(alignment: .leading) { Divider() }
                }
            }
        }
        .onChange(of: model.search) { _, _ in Task { await model.reload() } }
        .onChange(of: model.selection) { _, _ in Task { await model.reload() } }
        .onChange(of: model.selectedHostID) { _, id in if id != nil { showsDetail = true } }
        .onChange(of: model.workspaceCommand) { _, request in
            guard let request else { return }
            switch request.command {
            case .newHost: page = "hosts"; editor = EditorPresentation(content: .host(nil))
            case .settings: editor = EditorPresentation(content: .settings)
            case .search where model.workspacePage == .vault: page = "hosts"
            default: break
            }
        }
        .nativeSheet(item: $editor) { presentation in
            switch presentation.content {
            case .host(let host):
                HostEditor(model: model, host: host, folderID: selectedFolder?.id) { editor = nil }
            case .folder(let folder): FolderEditor(model: model, folder: folder) { editor = nil }
            case .settings: SettingsEditor(model: model) { editor = nil }
            case .security: SecurityManagerView(app: model) { editor = nil }
            case .trust: TrustManagementView(environment: model.sessionEnvironment) { editor = nil }
            case .deletion(let target): HostDeletionView(model: model, target: target) { editor = nil }
            }
        }
        .overlay(alignment: .bottom) {
            if editor == nil, let issue = model.issue {
                IssueView(issue: issue) { model.issue = nil }.padding().background(.regularMaterial).padding()
            }
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("OpenLXSSH").font(.headline).padding(.bottom, 12)
            sidebarButton("所有主机", id: "sidebar.all", selection: .all)
            sidebarButton("收藏", id: "sidebar.favorites", selection: .favorites)
            sidebarButton("未分组", id: "sidebar.ungrouped", selection: .ungrouped)
            Divider().padding(.vertical, 8)
            HStack {
                Text("文件夹").font(.caption).foregroundStyle(.secondary)
                Spacer()
                NativeButton(title: "+", id: "folder.add", enabled: !model.isWriting) { editor = EditorPresentation(content: .folder(nil)) }.fixedSize()
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(model.folders) { folder in sidebarButton(folder.name, id: "folder." + folder.id.uuidString, selection: .folder(folder.id)) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if let folder = selectedFolder {
                NativeButton(title: "重命名文件夹", id: "folder.edit", enabled: !model.isWriting) { editor = EditorPresentation(content: .folder(folder)) }.fixedSize()
                NativeButton(title: "复制文件夹及主机", id: "folder.copy", enabled: !model.isWriting) { Task { await model.copyFolder(folder.id) } }.fixedSize()
                NativeButton(title: "删除文件夹", id: "folder.delete", enabled: !model.isWriting) { editor = EditorPresentation(content: .deletion(.folder(folder))) }.fixedSize()
            }
            Spacer(minLength: 8)
            Divider()
            NativeButton(title: "SFTP 文件", id: "files.open", enabled: model.didLoad) { model.showWorkspace(.sftp) }.fixedSize()
            NativeButton(title: "传输任务（\(files.transferSnapshot.jobs.filter { $0.state.isActive }.count)）", id: "transfers.open") { model.showTransferTasks() }.fixedSize()
            NativeButton(title: "密钥与凭据", id: "security.open", enabled: model.didLoad) { page = "keys" }.fixedSize()
            NativeButton(title: "已知主机", id: "trust.manage", enabled: model.didLoad) { page = "trust" }.fixedSize()
            NativeButton(title: "设置…", id: "settings.open", enabled: model.didLoad) { editor = EditorPresentation(content: .settings) }.fixedSize()
            Text("系统 OpenSSH · 仅直接连接").font(.caption2).foregroundStyle(.secondary)
        }.padding(16).background(Color(nsColor: .windowBackgroundColor))
    }
    private func sidebarButton(_ label: String, id: String, selection: SidebarSelection) -> some View {
        NativeButton(title: (model.selection == selection && page == "hosts" ? "• " : "") + label, id: id) { page = "hosts"; model.selection = selection }
            .fixedSize(horizontal: false, vertical: true).frame(maxWidth: .infinity, alignment: .leading)
    }
    private var detail: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("主机详情").font(.headline)
                Spacer()
                Button { showsDetail = false } label: { Image(systemName: "xmark") }.buttonStyle(.plain).accessibilityLabel("收起主机详情")
            }
            if let host = model.selectedHost {
                Image(systemName: "server.rack").font(.largeTitle).foregroundStyle(.secondary)
                Text(host.name).font(.title2).bold().textSelection(.enabled)
                Text(host.username + "@" + host.address + ":" + String(host.port)).textSelection(.enabled)
                Text(host.authentication.displayName).foregroundStyle(.secondary)
                Text("最近连接：" + (host.lastConnectedAt?.formatted() ?? "从未连接")).font(.caption).foregroundStyle(.secondary)
                Divider()
                NativeButton(title: "打开会话", id: "session.reuse") { model.requestSession(hostID: host.id, mode: .reuse) }.fixedSize()
                NativeButton(title: "新建独立会话", id: "session.new") { model.requestSession(hostID: host.id, mode: .newSession) }.fixedSize()
                Divider()
                HStack {
                    NativeButton(title: "编辑", id: "host.edit", enabled: !model.isWriting) { editor = EditorPresentation(content: .host(host)) }.fixedSize()
                    NativeButton(title: "复制", id: "host.copy", enabled: !model.isWriting) { Task { await model.copyHost(host.id) } }.fixedSize()
                    NativeButton(title: host.isFavorite ? "取消收藏" : "收藏", id: "host.favorite", enabled: !model.isWriting) { Task { await model.favorite(host) } }.fixedSize()
                }
                NativeButton(title: "删除主机…", id: "host.delete", enabled: !model.isWriting) { editor = EditorPresentation(content: .deletion(.host(host))) }.fixedSize()
            } else {
                Spacer()
                Image(systemName: "rectangle.and.text.magnifyingglass").font(.largeTitle).foregroundStyle(.secondary)
                Text("选择一台主机").font(.title3)
                Text("这里只显示配置。启动与重新打开窗口均不会恢复会话。").foregroundStyle(.secondary)
            }
            if let notice = model.connectionNotice {
                switch notice {
                case .opened:
                    Text("标签独立保留会话。外层认证状态请以终端标签为准，进程启动不代表连接成功。").font(.caption).foregroundStyle(.secondary)
                case .transportUnavailable:
                    Text("逻辑测试路由：未建立 SSH 连接").font(.caption)
                }
            }
            Spacer()
        }.padding(20).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

enum DesktopStyle {
    static let barHeight: CGFloat = 48
    static let spacing: CGFloat = 8
    static let cornerRadius: CGFloat = 8
    static let panel = Color(nsColor: .controlBackgroundColor)
    static let background = Color(nsColor: .windowBackgroundColor)
}

private struct WorkspaceTabBar: View {
    @ObservedObject var model: AppModel
    @ObservedObject private var sessions: SessionController
    @ObservedObject private var files: FilesController
    @State private var chooser: ConnectionChooserPresentation?
    @State private var closeTargets: [UUID] = []
    @State private var dragging: UUID?
    init(model: AppModel) { self.model = model; sessions = model.sessions; files = model.files }
    var body: some View {
        HStack(spacing: 4) {
            fixedTab("保险箱", icon: "tray.full", page: .vault, id: "workspace.vault")
            fixedTab("SFTP", icon: "folder", page: .sftp, id: "workspace.sftp")
            Divider().padding(.vertical, 10)
            ScrollViewReader { proxy in
                ScrollView(.horizontal) {
                    HStack(spacing: 4) {
                        ForEach(sessions.tabs) { tab in
                            WorkspaceSessionTab(tab: tab, controller: sessions, active: model.workspacePage == .session(tab.id), select: { model.showWorkspace(.session(tab.id)) }, close: { Task { await sessions.closeTab(tab.id) } })
                                .id(tab.id)
                                .contextMenu {
                                    Button("连接信息") { showConnectionInfo(tab) }
                                    Button("重命名当前标签…") { rename(tab) }
                                    Divider()
                                    Button("断开") { sessions.disconnect(tab.id) }.disabled(!tab.isReusable)
                                    Button("重新连接") { sessions.reconnect(tab.id) }.disabled(!tab.canReconnect)
                                    Divider()
                                    Button("关闭") { Task { await sessions.closeTab(tab.id) } }
                                    Button("关闭其他会话…") { requestClose(sessions.tabs.filter { $0.id != tab.id }.map(\.id)) }.disabled(sessions.tabs.count < 2)
                                    Button("关闭右侧会话…") { if let index = sessions.tabs.firstIndex(where: { $0.id == tab.id }) { requestClose(Array(sessions.tabs.dropFirst(index + 1)).map(\.id)) } }.disabled(sessions.tabs.last?.id == tab.id)
                                }
                                .onDrag { dragging = tab.id; return NSItemProvider(object: tab.id.uuidString as NSString) }
                                .onDrop(of: [.text], isTargeted: nil) { _ in
                                    guard let dragging else { return false }
                                    sessions.moveTab(dragging, before: tab.id); self.dragging = nil; return true
                                }
                        }
                    }.padding(.horizontal, 4)
                }.scrollIndicators(.hidden)
                .onChange(of: model.workspacePage) { _, page in if let id = page.sessionID { proxy.scrollTo(id) } }
            }
            Button { chooser = ConnectionChooserPresentation() } label: { Image(systemName: "plus").frame(width: 30, height: 30) }
                .buttonStyle(.plain).help("新连接（⌘T）").accessibilityLabel("新连接").accessibilityIdentifier("workspace.new")
            if files.hasActiveTransfers || !files.transferSnapshot.jobs.isEmpty {
                Button { model.showTransferTasks() } label: {
                    Label("\(files.transferSnapshot.jobs.filter { $0.state.isActive }.count)", systemImage: "arrow.up.arrow.down")
                }.buttonStyle(.borderless).help("传输任务").accessibilityIdentifier("workspace.transfers")
            }
        }
        .padding(.horizontal, 8).frame(height: DesktopStyle.barHeight).background(DesktopStyle.background)
        .nativeSheet(item: $chooser) { _ in ConnectionChooser(model: model) { chooser = nil } }
        .onChange(of: model.workspaceCommand) { _, request in
            guard let request else { return }
            if request.command == .newConnection { chooser = ConnectionChooserPresentation() }
            if request.command == .connectionInfo, let tab = sessions.selectedTab, model.workspacePage.sessionID == tab.id { showConnectionInfo(tab) }
        }
        .confirmationDialog("关闭 \(closeTargets.count) 个会话？", isPresented: Binding(get: { !closeTargets.isEmpty }, set: { if !$0 { closeTargets = [] } }), titleVisibility: .visible) {
            Button("关闭这些会话", role: .destructive) { let ids = closeTargets; closeTargets = []; Task { for id in ids { await sessions.closeTab(id) } } }
            Button("取消", role: .cancel) { closeTargets = [] }
        } message: { Text("将断开选中的外层 SSH；不会关闭保险箱、SFTP 或取消传输。远端任务是否继续由远端程序决定。") }
    }
    private func fixedTab(_ title: String, icon: String, page: WorkspacePage, id: String) -> some View {
        Button { model.showWorkspace(page) } label: {
            Label(title, systemImage: icon).font(.system(size: 13, weight: model.workspacePage == page ? .semibold : .regular))
                .frame(minWidth: 90, minHeight: 34).background(model.workspacePage == page ? DesktopStyle.panel : .clear, in: RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius))
        }.buttonStyle(.plain).accessibilityIdentifier(id).accessibilityAddTraits(model.workspacePage == page ? .isSelected : [])
    }
    private func requestClose(_ ids: [UUID]) {
        guard !ids.isEmpty else { return }
        if sessions.tabs.contains(where: { ids.contains($0.id) && $0.isReusable }) { closeTargets = ids }
        else { Task { for id in ids { await sessions.closeTab(id) } } }
    }
    private func showConnectionInfo(_ tab: SessionTab) {
        let alert = NSAlert(); alert.messageText = sessions.displayTitle(for: tab)
        alert.informativeText = (tab.host.map { $0.username + "@" + $0.address + ":" + String($0.port) + "\n" + $0.authentication.displayName } ?? "配置不可用") + "\n" + tab.status
        alert.addButton(withTitle: "关闭")
        if let window = NSApp.mainWindow { alert.beginSheetModal(for: window) }
    }
    private func rename(_ tab: SessionTab) {
        let alert = NSAlert(); alert.messageText = "重命名当前标签"; alert.informativeText = "仅修改本次标签，不修改保存的主机。"
        let field = NSTextField(string: tab.title); field.frame = NSRect(x: 0, y: 0, width: 300, height: 26); alert.accessoryView = field
        alert.addButton(withTitle: "保存"); alert.addButton(withTitle: "取消")
        if let window = NSApp.mainWindow { alert.beginSheetModal(for: window) { response in if response == .alertFirstButtonReturn { sessions.renameTab(tab.id, title: field.stringValue) } } }
    }
}

private struct WorkspaceSessionTab: View {
    @ObservedObject var tab: SessionTab
    @ObservedObject var controller: SessionController
    let active: Bool
    let select: () -> Void
    let close: () -> Void
    var body: some View {
        HStack(spacing: 6) {
            Button(action: select) {
                HStack(spacing: 6) {
                    Image(systemName: tab.authentication != nil || !tab.trust.isEmpty ? "exclamationmark.bubble" : (tab.isReusable ? "terminal" : "stop.circle"))
                    Text(controller.displayTitle(for: tab)).lineLimit(1).truncationMode(.middle)
                }.frame(minWidth: 94, maxWidth: 180, minHeight: 34, alignment: .leading)
            }.buttonStyle(.plain).accessibilityIdentifier("tab.select." + tab.id.uuidString)
            Button(action: close) { Image(systemName: "xmark").font(.system(size: 10, weight: .semibold)).frame(width: 24, height: 28) }
                .buttonStyle(.plain).accessibilityLabel("关闭 " + tab.title).accessibilityIdentifier("tab.close." + tab.id.uuidString)
        }.padding(.leading, 10).padding(.trailing, 2)
        .background(active ? DesktopStyle.panel : .clear, in: RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius))
        .help((tab.host.map { $0.username + "@" + $0.address + ":" + String($0.port) + "\n" } ?? "") + tab.status)
        .accessibilityValue(tab.status)
    }
}

private struct ConnectionChooser: View {
    @ObservedObject var model: AppModel
    @State private var search = ""
    let dismiss: () -> Void
    private var hosts: [HostConfiguration] {
        model.connectionHosts.filter { search.isEmpty || [$0.name, $0.address, $0.username].contains(where: { $0.localizedStandardContains(search) }) }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { Text("新连接").font(.title2).bold(); Spacer(); Button("新建主机…") { dismiss(); model.showWorkspace(.vault); model.sendWorkspaceCommand(.newHost) } }
            TextField("搜索已有主机", text: $search).textFieldStyle(.roundedBorder).accessibilityIdentifier("connection.search")
            if model.connectionHosts.isEmpty { ContentUnavailableView("尚无主机", systemImage: "server.rack", description: Text("先创建主机配置，再建立连接。")) }
            else if hosts.isEmpty { ContentUnavailableView.search(text: search) }
            else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(hosts) { host in
                            HStack {
                                Image(systemName: "server.rack").foregroundStyle(.secondary)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(host.name).font(.headline).lineLimit(1)
                                    Text(host.username + "@" + host.address + ":" + String(host.port)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                }
                                Spacer()
                                Button("连接") { model.requestSession(hostID: host.id, mode: .reuse); dismiss() }
                                Button("新会话") { model.requestSession(hostID: host.id, mode: .newSession); dismiss() }
                            }.padding(12).background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius))
                        }
                    }
                }
            }
            HStack { Spacer(); Button("关闭", action: dismiss).keyboardShortcut(.cancelAction) }
        }.padding(24).frame(width: 600, height: 440)
    }
}

private struct SFTPWorkspaceView: View {
    @ObservedObject var model: AppModel
    @ObservedObject private var files: FilesController
    @State private var selectedHost = ""
    init(model: AppModel) { self.model = model; files = model.files }
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Label("SFTP", systemImage: "folder").font(.headline)
                Spacer()
                NativePopup(id: "files.host", items: [PopupItem(value: "", title: "选择主机")] + model.connectionHosts.map { PopupItem(value: $0.id.uuidString, title: $0.name) }, selection: $selectedHost).frame(width: 240, height: 28)
                Button(files.tasksVisible ? "收起任务" : "传输任务") { files.tasksVisible.toggle() }
            }.padding(16)
            Divider()
            if files.selectedHost == nil {
                ContentUnavailableView("选择主机", systemImage: "server.rack", description: Text("选择保险箱中的主机，建立独立的 SFTP 连接。"))
            } else {
                ScrollView { FilesPanelView(model: files, returnToVault: { model.returnToVaultFromFiles() }).frame(maxWidth: .infinity, alignment: .leading) }
            }
        }
        .onChange(of: selectedHost) { _, value in files.show(host: model.connectionHosts.first { $0.id.uuidString == value }) }
        .onChange(of: files.selectedHost?.id) { _, id in selectedHost = id?.uuidString ?? "" }
    }
}

private struct HostDeletionView: View {
    @ObservedObject var model: AppModel
    let target: DeletionTarget
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("确认删除").font(.title2).bold()
            switch target {
            case .host(let host): Text("删除主机“\(host.name)”的配置？共享的私钥与凭据不会被删除。")
            case .folder(let folder): Text("删除文件夹“\(folder.name)”？其中主机会移至未分组，不会删除主机。")
            }
            HStack {
                Spacer()
                NativeButton(title: "取消", id: "delete.cancel") { dismiss() }.fixedSize()
                NativeButton(title: "删除", id: "delete.confirm", enabled: !model.isWriting) {
                    Task {
                        let success: Bool
                        switch target {
                        case .host(let host): success = await model.deleteHost(host.id)
                        case .folder(let folder): success = await model.deleteFolder(folder.id)
                        }
                        if success { dismiss() }
                    }
                }.fixedSize()
            }
            IssueView(issue: model.issue) { model.issue = nil }
        }.padding(24).frame(width: 430)
    }
}

struct IssueView: View {
    let issue: AppIssue?
    var dismiss: () -> Void
    var body: some View {
        if let issue {
            HStack(alignment: .top) {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 4) {
                    Text(issue.message)
                    Text(issue.code).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Spacer()
                NativeButton(title: "关闭", id: "issue.dismiss", action: dismiss).fixedSize()
            }.accessibilityIdentifier("app.error")
        }
    }
}
