import AppKit
import SwiftUI
import OpenLXSSHCore

private struct EditorPresentation: Identifiable {
    enum Content { case host(HostConfiguration?), folder(HostFolder?), settings, security, deletion(DeletionTarget) }
    let id = UUID()
    let content: Content
}
private enum DeletionTarget { case host(HostConfiguration), folder(HostFolder) }

struct MainView: View {
    @ObservedObject var model: AppModel
    @State private var editor: EditorPresentation?
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
        HSplitView {
            sidebar.frame(minWidth: 190, idealWidth: 215, maxWidth: 280)
            VStack(spacing: 0) {
                HStack {
                    Text(title).font(.title2).bold()
                    Spacer()
                    NativeButton(title: "添加主机", id: "host.add", enabled: !model.isWriting) { editor = EditorPresentation(content: .host(nil)) }.fixedSize()
                    NativeButton(title: "刷新", id: "hosts.refresh") { Task { await model.reload() } }.fixedSize()
                }.padding()
                HStack {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    NativeField(placeholder: "搜索名称、地址或用户名", id: "hosts.search", text: $model.search).frame(height: 25)
                }.padding(.horizontal).padding(.bottom, 12)
                HSplitView {
                    VStack(spacing: 0) {
                        if model.hosts.isEmpty {
                            VStack(spacing: 10) {
                                Image(systemName: "server.rack").font(.system(size: 36)).foregroundStyle(.secondary)
                                Text(model.didLoad ? "没有匹配的主机" : "正在加载本地数据…").font(.headline)
                                Text("添加主机只保存配置，不会发起连接。").foregroundStyle(.secondary)
                            }.frame(maxWidth: .infinity, maxHeight: .infinity)
                        } else {
                            HostTable(hosts: model.hosts, selectedID: $model.selectedHostID) { model.requestSession(hostID: $0, mode: .reuse) }
                        }
                        Divider()
                        Text("\(model.hosts.count) 台主机 · " + (model.isLoading || model.isWriting ? "正在处理本地数据" : "未建立任何连接"))
                            .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(10)
                    }.frame(minWidth: 340)
                    detail.frame(minWidth: 290, idealWidth: 330, maxWidth: 430)
                }
            }.frame(minWidth: 690)
        }
        .frame(minWidth: 920, minHeight: 580)
        .preferredColorScheme(model.settings.theme == .system ? nil : (model.settings.theme == .dark ? .dark : .light))
        .task { if !model.didLoad { await model.reload() } }
        .onChange(of: model.search) { _, _ in Task { await model.reload() } }
        .onChange(of: model.selection) { _, _ in Task { await model.reload() } }
        .nativeSheet(item: $editor) { presentation in
            switch presentation.content {
            case .host(let host):
                HostEditor(model: model, host: host, folderID: selectedFolder?.id) { editor = nil }
            case .folder(let folder): FolderEditor(model: model, folder: folder) { editor = nil }
            case .settings: SettingsEditor(model: model) { editor = nil }
            case .security: SecurityManagerView(app: model) { editor = nil }
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
            NativeButton(title: "密钥与凭据…", id: "security.open", enabled: model.didLoad) { editor = EditorPresentation(content: .security) }.fixedSize()
            NativeButton(title: "设置…", id: "settings.open", enabled: model.didLoad) { editor = EditorPresentation(content: .settings) }.fixedSize()
            Text("本地配置 · SSH 尚未集成").font(.caption2).foregroundStyle(.secondary)
        }.padding(16).background(Color(nsColor: .windowBackgroundColor))
    }
    private func sidebarButton(_ label: String, id: String, selection: SidebarSelection) -> some View {
        NativeButton(title: (model.selection == selection ? "• " : "") + label, id: id) { model.selection = selection }
            .fixedSize(horizontal: false, vertical: true).frame(maxWidth: .infinity, alignment: .leading)
    }
    private var detail: some View {
        VStack(alignment: .leading, spacing: 16) {
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
                case .transportUnavailable(let request):
                    VStack(alignment: .leading, spacing: 8) {
                        Label("SSH transport 未集成，未建立连接", systemImage: "info.circle").font(.headline)
                        Text(request.mode == .reuse ? "已收到打开/复用请求。没有启动 SSH、认证或终端。" : "已收到独立会话请求。没有创建会话或写入最近连接时间。")
                        Text("状态：transport.unavailable").font(.caption.monospaced())
                    }.padding(12).background(.quaternary).clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }
            Spacer()
        }.padding(20).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
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
