import AppKit
import SwiftUI
import OpenLXSSHCore
import OpenLXSSHFiles
import Combine

enum FilesSearchPane { case local, remote }

/// The application keeps this view mounted; page visibility only activates local metadata once.
struct DualPaneFilesView: View {
    @ObservedObject private var app: AppModel
    @ObservedObject private var files: FilesController
    @StateObject private var local: LocalBrowserModel
    @State private var remoteSelection: Set<FileName> = []
    @State private var remoteFilter = ""
    @State private var remoteHidden = false
    @State private var remoteSort = FilesSort()
    @State private var dialog: DualFilesDialog?
    @State private var hostSearch = ""
    @State private var hostFilter = "all"
    @StateObject private var initialInput = FilesInitialInputOwner()
    @State private var pendingChange: FilesConnectionChangeReview?
    @State private var operationDialog: FilesDialog?
    @State private var showingLocalReports = false
    @State private var showingRemoteReports = false
    @State private var activeSearchPane: FilesSearchPane = .local
    @State private var localSearchFocusRequest: UUID?
    @State private var remoteSearchFocusRequest: UUID?
    init(model: AppModel, localRoot: URL? = nil) {
        app = model; files = model.files
        _local = StateObject(wrappedValue: localRoot.map { LocalBrowserModel(root: $0) } ?? model.files.localBrowser)
    }
    var body: some View {
        reviewedContent
            .nativeSheet(item: $dialog, onAttemptDismiss: { if let dialog { cancelDialog(dialog) }; return true }) { value in dialogView(value) }
            .nativeSheet(item: $operationDialog) { value in
                switch value.content {
                case .mkdir: FilesNameEditor(model: files, entry: nil) { operationDialog = nil }
                case .rename(let entry): FilesNameEditor(model: files, entry: entry) { operationDialog = nil }
                case .probe(let review): FilesProbeView(model: files, review: review) { operationDialog = nil }
                case .transferDecision(let request): FilesTransferDecisionView(model: files, request: request) { operationDialog = nil }
                default: EmptyView()
                }
            }
            .alert("更改文件连接", isPresented: Binding(get: { pendingChange != nil }, set: { if !$0 { pendingChange = nil } })) {
                Button("取消", role: .cancel) { if let pendingChange { files.discardConnectionChange(pendingChange) }; pendingChange = nil }
                Button("继续（可能影响共享任务）") { if let pendingChange { files.confirmConnectionChange(pendingChange) }; pendingChange = nil }
            } message: {
                Text("仍有 \(files.transferSnapshot.jobs.filter { $0.state.isActive }.count) 个传输任务。更改连接可能中止这些任务，是否继续？")
            }
    }
    private var toolbar: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.left.arrow.right")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(Color.accentColor)
            Text("文件传输").font(.system(size: 18, weight: .semibold))
            Spacer()
            if files.selectedHost != nil {
                Button { dialog = DualFilesDialog(content: .host) } label: {
                    Label("更换主机", systemImage: "server.rack")
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("files.host.choose")
            }
            let activeTransferCount = files.transferSnapshot.jobs.filter { $0.state.isActive }.count
            Button { files.tasksVisible = true } label: {
                Label(activeTransferCount > 0 ? "传输中心 · \(activeTransferCount)" : "传输中心",
                      systemImage: "arrow.up.arrow.down")
            }
            .modifier(ProminentIfModifier(prominent: activeTransferCount > 0))
            .accessibilityIdentifier("transfers.open")
        }.padding(.horizontal, 18).padding(.vertical, 10)
            .foregroundStyle(.primary).background(DesktopStyle.panel)
    }
    private var workspace: some View {
        VStack(spacing: 0) {
            toolbar
            Divider().overlay(DesktopStyle.border)
            FilesPaneSplit(left: localPane, right: remotePane, defaults: app.desktopPreferencesDefaults)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(DesktopStyle.background).foregroundStyle(.primary)
        .preferredColorScheme(app.settings.theme == .system ? nil : (app.settings.theme == .dark ? .dark : .light))
    }
    private var routedContent: some View {
        workspace
            .onAppear { activateIfVisible() }
            .onChange(of: app.workspacePage) { _, page in
                if page != .sftp { if let dialog { cancelDialog(dialog) }; dialog = nil }
                activateIfVisible()
            }
            .onChange(of: app.workspaceCommand) { _, request in
                guard app.workspacePage == .sftp, request?.page == .sftp, request?.command == .search,
                      request == app.workspaceCommand,
                      dialog == nil, operationDialog == nil, pendingChange == nil,
                      NSApp.modalWindow == nil, NSApp.mainWindow?.attachedSheet == nil else { return }
                if activeSearchPane == .remote, files.state == .ready { remoteSearchFocusRequest = UUID() }
                else { localSearchFocusRequest = UUID() }
            }
            .onChange(of: files.path) { _, _ in remoteSelection = [] }
            .onChange(of: local.path) { _, _ in files.localTransferLocationChanged() }
            .onChange(of: local.loading) { _, loading in if loading { files.localTransferLocationChanged() } }
    }
    private var credentialContent: some View {
        routedContent
            .onChange(of: files.selectedHost) { _, _ in remoteSelection = [] }
            .onChange(of: inputContext) { _, current in initialInput.update(current) }
    }
    private var reviewedContent: some View {
        credentialContent
            .onChange(of: local.deleteReview?.id) { _, _ in
                if let review = local.deleteReview, app.workspacePage == .sftp { dialog = DualFilesDialog(content: .localDelete(review)) }
            }
            .onChange(of: files.transferCompletionRevision) { _, _ in refreshCompletedTransfers() }
            .onChange(of: files.deleteBatchReview?.id) { _, _ in
                if let review = files.deleteBatchReview, app.workspacePage == .sftp { dialog = DualFilesDialog(content: .remoteDelete(review)) }
            }
            .onChange(of: files.probeReview?.id) { _, _ in if let review = files.probeReview { operationDialog = FilesDialog(content: .probe(review)) } }
            .onDisappear { initialInput.clear(); files.cancelTransferPlan(); if let dialog { cancelDialog(dialog) }; dialog = nil; local.deactivate() }
    }
    private func refreshCompletedTransfers() {
        let jobs = files.latestCompletedBatchJobs
        if files.state == .ready, !files.busy, jobs.contains(where: { job in
            job.request.destination.serviceID == files.serviceID && job.request.hostID == files.selectedHost?.id.uuidString
                && (job.request.destination.path.parent == files.path || job.items.contains { $0.destination.parent == files.path })
        }) { files.browse(files.path) }
        guard let current = local.path else { return }
        if jobs.contains(where: { job in
            guard let root = files.transferLabels[job.id]?.localRoots[job.request.destination.serviceID] else { return false }
            let targetParentBytes = (root == .root ? Data() : root.bytes) + (job.request.destination.path.parent == .root ? Data() : job.request.destination.path.parent.bytes)
            if (try? RemotePath(bytes: targetParentBytes)) == current { return true }
            return job.items.contains { item in
                let bytes = (root == .root ? Data() : root.bytes) + (item.destination.parent == .root ? Data() : item.destination.parent.bytes)
                return (try? RemotePath(bytes: bytes)) == current
            }
        }) { local.refreshPreservingSelection() }
    }
    private func activateIfVisible() {
        initialInput.update(inputContext)
        if app.workspacePage == .sftp { local.activate() } else { local.deactivate() }
    }
    private var inputContext: FilesInitialInputOwner.Context {
        .init(visible: app.workspacePage == .sftp && files.visible,
              host: files.selectedHost, keys: app.keys, epoch: files.initialInputEpoch)
    }
    private var remoteRows: [DirectoryEntry] {
        remoteSort.apply(files.entries.filter { (remoteHidden || $0.name.bytes.first != 46) && (remoteFilter.isEmpty || FileDisplay.name($0.name).localizedStandardContains(remoteFilter)) })
    }
    private var selectedRemote: [DirectoryEntry] { remoteRows.filter { remoteSelection.contains($0.name) } }
    private var localPane: some View {
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                paneHeader(title: "本地文件", subtitle: nil, filter: $local.filter, hidden: $local.showsHidden, localSide: true)
                FilesNavigationBar(path: local.path, back: local.history.backward != nil, forward: local.history.forward != nil,
                    up: local.canGoUp, enabled: !local.loading, prefix: "files.local", go: local.go, backward: local.back,
                    forwardAction: local.forward, parent: local.up, refresh: local.refresh, navigate: { local.navigate($0) },
                    onActivate: { activeSearchPane = .local })
            }.background(DesktopStyle.panel)
            Divider().overlay(DesktopStyle.border)
            browserTable(localSide: true)
            browserFooter(localSide: true)
        }.background(DesktopStyle.background)
    }
    private var remotePane: some View {
        VStack(spacing: 0) {
            if files.state == .ready {
                VStack(spacing: 0) {
                    paneHeader(title: files.selectedHost?.name ?? "远端文件",
                        subtitle: files.selectedHost.map { $0.username + "@" + $0.vaultEndpoint },
                        filter: $remoteFilter, hidden: $remoteHidden, localSide: false)
                    FilesNavigationBar(path: files.path, back: files.navigationHistory.backward != nil, forward: files.navigationHistory.forward != nil,
                        up: files.path != .root, enabled: !files.busy, prefix: "files.remote", go: files.go,
                        backward: files.back, forwardAction: files.forward, parent: { files.browse(files.path.parent) },
                        refresh: { files.browse(files.path) }, navigate: files.browse, onActivate: { activeSearchPane = .remote })
                }.background(DesktopStyle.panel)
                Divider().overlay(DesktopStyle.border)
                browserTable(localSide: false)
            } else {
                ScrollView {
                    connectionPanel
                        .padding(16)
                        .frame(maxWidth: .infinity)
                }
                .defaultScrollAnchor(.center, for: .alignment)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            if files.state == .ready || files.issue != nil || files.transferPreparationIssue != nil || !files.lastDeleteReports.isEmpty {
                browserFooter(localSide: false)
            }
        }.background(DesktopStyle.background)
    }
    private var connectionPanel: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "externaldrive.connected.to.line.below")
                    .font(.system(size: 20, weight: .medium))
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 40, height: 40)
                    .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 4) {
                    Text(files.selectedHost?.name ?? "连接远端主机")
                        .font(.system(size: 17, weight: .semibold))
                        .lineLimit(2)
                    if let host = files.selectedHost {
                        let endpoint = host.username + "@" + host.vaultEndpoint
                        Text(verbatim: endpoint).font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(endpoint)
                    }
                }
            }
            if files.selectedHost == nil {
                Text("从保险箱选择主机，浏览远端文件。").font(.callout).foregroundStyle(.secondary)
                Button("选择主机") { dialog = DualFilesDialog(content: .host) }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("files.remote.empty.choose")
            } else if let host = files.selectedHost {
                Divider()
                if files.state == .failed {
                    Label(status, systemImage: "exclamationmark.circle")
                        .font(.callout.weight(.medium)).foregroundStyle(DesktopStyle.statusRed)
                }
                if files.canConnect {
                    connectionForm(host)
                } else {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        if files.state != .failed { Text(status).font(.callout) }
                        Spacer(minLength: 4)
                        if files.busy && files.state != .closing {
                            Button("取消连接") { requestChange(nil, disconnect: true) }
                        }
                    }
                }
            }
        }
        .padding(20)
        .frame(maxWidth: 360, alignment: .leading)
        .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 12))
        .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(DesktopStyle.border) }
    }
    private var requiresKeyPassphrase: Bool {
        files.state == .failed && files.selectedHost?.authentication.needsKey == true
            && files.issue?.code == "files.keyPassphraseRequired"
    }
    private func connectionForm(_ host: HostConfiguration) -> some View {
        let displayed = inputContext
        let key = host.authentication.needsKey
        let hasSavedCredential = displayed.savedCredentialID != nil
        let needsPassphrase = requiresKeyPassphrase
        let canUseConfigured = key || hasSavedCredential
        let showField = !canUseConfigured || initialInput.useTemporaryCredential || needsPassphrase
        return VStack(alignment: .leading, spacing: 10) {
            if showField {
                SecureField(key ? "本次私钥口令" : "本次密码", text: $initialInput.secret)
                    .textFieldStyle(.roundedBorder).controlSize(.large)
                    .onSubmit { connectInitial(displayed) }
                    .accessibilityIdentifier("files.initial.secret")
                if !key {
                    Text("留空时按服务器提示认证。").font(.caption).foregroundStyle(.secondary)
                }
                if canUseConfigured && !needsPassphrase {
                    Button("使用主机配置") { initialInput.clear() }.buttonStyle(.link)
                }
            } else {
                Label(key ? (hasSavedCredential ? "SSH 密钥 · 已保存口令" : "SSH 密钥") : "使用已保存的密码",
                      systemImage: key ? "key" : "lock")
                    .font(.callout).foregroundStyle(.secondary)
                Button(key ? "输入本次私钥口令…" : "输入本次密码…") {
                    initialInput.useTemporaryCredential = true
                }.buttonStyle(.link)
            }
            NativeButton(title: files.state == .failed ? "重新连接 SFTP" : "连接 SFTP", id: "files.connect",
                         enabled: files.canConnect && !files.busy && !(needsPassphrase && initialInput.secret.isEmpty),
                         isProminent: true) { connectInitial(displayed) }
                .fixedSize()
        }
    }
    private func paneHeader(title: String, subtitle: String?, filter: Binding<String>, hidden: Binding<Bool>, localSide: Bool) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: localSide ? "desktopcomputer" : "server.rack")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 24, height: 24)
                    .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 6))
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                        if !localSide {
                            DesktopBadge(
                                text: "已连接", color: DesktopStyle.statusGreen,
                                fill: DesktopStyle.statusGreen.opacity(0.13)
                            )
                        }
                    }
                    if let subtitle {
                        Text(verbatim: subtitle).font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(subtitle)
                    }
                }
                Spacer(minLength: 4)
                Menu {
                    Button(localSide ? "上传所选" : "下载到左侧当前目录") { transfer(localSide: localSide) }.disabled(!files.canTransfer || (localSide ? local.selectedEntries.isEmpty : selectedRemote.isEmpty) || local.path == nil)
                    Divider()
                    Button("新建目录…") { newDirectory(localSide) }.disabled(localSide ? local.loading : files.state != .ready || files.busy)
                    Button("刷新") { if localSide { local.refresh() } else { files.browse(files.path) } }
                    if localSide { Button("选择本地目录…") { chooseLocalDirectory() } }
                    else {
                        Button("更换主机…") { dialog = DualFilesDialog(content: .host) }
                        Button("断开连接") { requestChange(nil, disconnect: true) }.disabled(files.state == .disconnected)
                        Divider()
                        Button("高级：检查非覆盖提交能力…") { files.prepareProbe() }.disabled(files.state != .ready || files.busy)
                    }
                } label: {
                    Label("操作", systemImage: "ellipsis.circle")
                        .font(.system(size: 12))
                }.menuStyle(.borderlessButton).fixedSize()
            }.frame(minHeight: 32)
            HStack(spacing: 8) {
                DesktopSearchField(
                    placeholder: "筛选当前目录",
                    id: localSide ? "files.local.filter" : "files.remote.filter",
                    text: filter,
                    focusRequest: localSide ? localSearchFocusRequest : remoteSearchFocusRequest,
                    onFocus: { activeSearchPane = localSide ? .local : .remote },
                    clearLabel: "清除筛选"
                )
                Toggle("隐藏项", isOn: hidden)
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize()
            }
        }.padding(.horizontal, 12).padding(.top, 10).padding(.bottom, 8)
    }
    private func browserTable(localSide: Bool) -> some View {
        let entries = localSide ? local.visibleEntries : remoteRows
        let loading = localSide ? local.loading : files.busy
        let content = localSide ? local.contentState : FilesBrowserContentState.resolve(loading: loading,
            hasSnapshot: !files.navigationHistory.paths.isEmpty, readFailed: files.readFailed, total: files.entries.count, visible: entries.count)
        return ZStack {
            DualFilesEntryTable(entries: entries, selected: localSide ? $local.selection : $remoteSelection,
                sort: localSide ? $local.sort : $remoteSort, identifier: localSide ? "files.local.entries" : "files.remote.entries",
                drag: { rows in makeDrag(rows, localSide: localSide) }, drop: { acceptDrop($0, localSide: localSide) },
                canDrop: { canDrop($0, localSide: localSide) }, activate: { activate($0, localSide: localSide) },
                menu: { row in menuActions(row, localSide: localSide) },
                layoutDefaults: app.desktopPreferencesDefaults, layoutSide: localSide ? .local : .remote,
                onFocus: { activeSearchPane = localSide ? .local : .remote })
            if entries.isEmpty && !loading {
                VStack(spacing: 8) {
                    switch content {
                    case .failed(let hasSnapshot):
                        Image(systemName: "exclamationmark.folder").font(.title)
                        Text("目录读取失败")
                        if hasSnapshot { Text("已保留上次打开的位置。").font(.caption).foregroundStyle(.secondary) }
                        Button("重试读取") { if localSide { local.refresh() } else { files.browse(files.path) } }
                    case .notLoaded:
                        Text("尚未读取目录")
                        Button("读取目录") { if localSide { local.refresh() } else { files.browse(files.path) } }
                    case .empty, .filteredEmpty:
                        Image(systemName: "folder").font(.title)
                        Text(content == .empty ? "空目录" : "没有匹配项")
                        if content == .filteredEmpty { Button("显示全部项目") { if localSide { local.filter = ""; local.showsHidden = true } else { remoteFilter = ""; remoteHidden = true } } }
                        Button("刷新") { if localSide { local.refresh() } else { files.browse(files.path) } }
                    default: EmptyView()
                    }
                }.padding(12)
            }
            if loading { ProgressView().padding(12).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8)).allowsHitTesting(false) }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    private func browserFooter(localSide: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider().overlay(DesktopStyle.border)
            if localSide || files.state == .ready {
                selectionFooter(localSide: localSide)
            }
            if (localSide ? local.readFailed : files.readFailed) && (localSide ? !local.visibleEntries.isEmpty : files.state == .ready && !remoteRows.isEmpty) {
                Text("读取失败，正在显示上次读取的内容。").font(.caption).foregroundStyle(DesktopStyle.statusAmber)
            }
            let reports = localSide ? local.deleteReports : files.lastDeleteReports
            if !reports.isEmpty {
                DisclosureGroup("最近删除：\(reports.reduce(0) { $0 + $1.items.count }) 项实际结果", isExpanded: localSide ? $showingLocalReports : $showingRemoteReports) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(reports.indices, id: \.self) { report in
                                ForEach(reports[report].items.indices, id: \.self) { index in
                                    let item = reports[report].items[index]
                                    Text(verbatim: FileDisplay.path(item.path) + " · " + deleteResult(item.state)).font(.caption2)
                                }
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(maxHeight: 85)
                }.font(.caption)
            }
            IssueView(issue: localSide ? local.issue : (files.transferPreparationIssue ?? files.issue)) {
                if localSide { local.issue = nil }
                else { files.issue = nil; files.dismissTransferPreparationIssue() }
            }
        }.padding(.horizontal, 12).padding(.vertical, 8).background(DesktopStyle.panel)
    }
    private func selectionFooter(localSide: Bool) -> some View {
        let visible = localSide ? local.visibleEntries : remoteRows
        let selection = localSide ? local.selection : remoteSelection
        let selectedCount = visible.count { selection.contains($0.name) }
        let readyToTransfer = files.canTransfer && selectedCount > 0 && local.path != nil
        return HStack(spacing: 8) {
            Text(selectedCount == 0 ? "\(visible.count) 项" : "已选 \(selectedCount) / \(visible.count) 项")
                .font(.system(size: 11).monospacedDigit()).foregroundStyle(.secondary)
            Spacer()
            Button(localSide ? "上传 →" : "← 下载") { transfer(localSide: localSide) }
                .modifier(ProminentIfModifier(prominent: readyToTransfer))
                .controlSize(.small)
                .disabled(!readyToTransfer)
                .accessibilityIdentifier(localSide ? "files.upload.selected" : "files.download.selected")
        }
    }
    private func deleteResult(_ state: DeleteItemResult.State) -> String {
        switch state { case .succeeded: "已删除"; case .failed(let error): "失败 · " + error.kind.rawValue; case .notAttempted(let error): "未执行 · " + error.kind.rawValue }
    }
    private func requestChange(_ host: HostConfiguration?, disconnect: Bool) {
        if let review = files.prepareConnectionChange(host: host, disconnect: disconnect) { pendingChange = review }
    }
    private func connectInitial(_ displayed: FilesInitialInputOwner.Context) {
        guard displayed == inputContext, files.canConnect, !files.busy,
              !(requiresKeyPassphrase && initialInput.secret.isEmpty),
              let input = initialInput.take(for: displayed) else { return }
        files.connect(input)
    }
    private func chooseLocalDirectory() {
        let panel = NSOpenPanel(); panel.canChooseFiles = false; panel.canChooseDirectories = true; panel.resolvesAliases = false
        panel.begin { response in if response == .OK, let url = panel.url { Task { @MainActor in do { local.navigate(try FilesLocalPaths.rawPath(FilesLocalPaths.components(url))) } catch { local.issue = .files(error) } } } }
    }
    private func newDirectory(_ localSide: Bool) { presentName(nil, localSide: localSide) }
    private func capture(_ entries: [DirectoryEntry], localSide: Bool) -> FilesOperationTarget? {
        localSide ? local.captureTarget(entries) : files.captureTarget(entries)
    }
    private func presentName(_ entry: DirectoryEntry?, localSide: Bool) {
        guard let target = capture(entry.map { [$0] } ?? [], localSide: localSide) else { return }
        dialog = DualFilesDialog(content: .name(target, localSide))
    }
    private func activate(_ entry: DirectoryEntry, localSide: Bool) {
        if entry.attributes.kind == .directory { if localSide { local.enter(entry) } else { files.enter(entry) } }
        else { showDetails(entry, localSide: localSide) }
    }
    private func showDetails(_ entry: DirectoryEntry, localSide: Bool) {
        guard let target = capture([entry], localSide: localSide) else { return }
        dialog = DualFilesDialog(content: .details(target, localSide))
    }
    private func transfer(localSide: Bool) {
        do {
            if localSide {
                guard let path = local.path else { return }
                let urls = try local.selectedEntries.map { FilesLocalPaths.url(try path.appending($0.name)) }
                _ = try files.enqueueUploads(urls, context: files.transferContext(upload: true))
            } else {
                guard let path = local.path else { return }
                _ = try files.enqueueDownloads(selectedRemote, to: FilesLocalPaths.url(path), context: files.transferContext(upload: false))
            }
        } catch { files.issue = .files(error) }
    }
    private func makeDrag(_ rows: [DirectoryEntry], localSide: Bool) -> [NSPasteboardWriting] {
        guard !rows.isEmpty else { return [] }
        if localSide, let parent = local.path { return FilesPaneDrag.local(rows: rows, parent: parent) }
        guard let context = try? files.transferContext(upload: false) else { return [] }
        return [FilesPaneDrag.remote(rows: rows, context: context)]
    }
    private func canDrop(_ pasteboard: NSPasteboard, localSide: Bool) -> Bool {
        localSide ? local.path != nil && files.canTransfer && FilesPaneDrag.remoteNames(pasteboard, controller: files) != nil : files.canTransfer && FilesDrop.urls(pasteboard) != nil
    }
    private func acceptDrop(_ pasteboard: NSPasteboard, localSide: Bool) -> Bool {
        do {
            if localSide {
                guard let parent = local.path, let names = FilesPaneDrag.remoteNames(pasteboard, controller: files) else { return false }
                let rows = files.entries.filter { names.contains($0.name) }
                guard rows.count == names.count else { return false }
                _ = try files.enqueueDownloads(rows, to: FilesLocalPaths.url(parent), context: files.transferContext(upload: false))
            } else {
                guard let urls = FilesDrop.urls(pasteboard) else { return false }
                _ = try files.enqueueUploads(urls, context: files.transferContext(upload: true))
            }
            return true
        } catch { files.issue = .files(error); return false }
    }
    private func menuActions(_ row: DirectoryEntry?, localSide: Bool) -> [FilesPaneMenuAction] {
        let selected = localSide ? local.selectedEntries : selectedRemote
        let active = localSide ? !local.loading : files.state == .ready && !files.busy
        let current = selected.count == 1 ? selected.first : row
        var actions: [FilesPaneMenuAction] = [
            .init(title: localSide ? "上传所选到右侧当前目录" : "下载所选到左侧当前目录", enabled: active && files.canTransfer && !selected.isEmpty && local.path != nil, perform: { transfer(localSide: localSide) }),
            .init(title: "进入目录 / 查看详情", enabled: selected.count == 1 && current != nil, perform: { if let current { activate(current, localSide: localSide) } }),
            .separator,
            .init(title: "新建目录…", enabled: active, perform: { newDirectory(localSide) }),
            .init(title: "重命名…", enabled: active && selected.count == 1, perform: { if let current { presentName(current, localSide: localSide) } }),
            .init(title: "复制完整路径", enabled: !selected.isEmpty, perform: { if let parent = localSide ? local.path : Optional(files.path) { FilesExactClipboard.copy(selected.compactMap { try? parent.appending($0.name) }) } }),
            .init(title: "详情…", enabled: selected.count == 1 && current != nil, perform: { if let current { showDetails(current, localSide: localSide) } }),
            .init(title: "刷新", enabled: active, perform: { if localSide { local.refresh() } else { files.browse(files.path) } })
        ]
        if localSide { actions.append(.init(title: "在 Finder 中显示", enabled: current != nil, perform: {
            if let current, let parent = local.path, let path = try? parent.appending(current.name) { NSWorkspace.shared.activateFileViewerSelecting([FilesLocalPaths.url(path)]) }
        })) }
        actions += [.separator, .init(title: "删除所选…", enabled: active && !selected.isEmpty, perform: {
            if let target = capture(selected, localSide: localSide) {
                if localSide { local.prepareDelete(target, linkOnly: true) }
                else { files.prepareDeleteBatch(target, removeLinkOnly: true) }
            }
        })]
        return actions
    }
    private func dismissDialog(_ value: DualFilesDialog) { if dialog?.id == value.id { dialog = nil } }
    private func discardTarget(_ target: FilesOperationTarget, localSide: Bool) {
        if localSide { local.discardTarget(target) } else { files.discardTarget(target) }
    }
    private func cancelDialog(_ value: DualFilesDialog) {
        switch value.content {
        case .name(let target, let localSide), .details(let target, let localSide), .deleteOptions(let target, let localSide): discardTarget(target, localSide: localSide)
        case .localDelete(let review): local.discardDelete(review)
        case .remoteDelete(let review): files.discardDeleteBatch(review)
        case .host: break
        }
    }
    @ViewBuilder private func dialogView(_ value: DualFilesDialog) -> some View {
        Group {
            switch value.content {
            case .host:
                hostChooserDialog
            case .name(let target, let localSide):
                if localSide {
                    DualFilesNameEditor(target: target) { name in
                        if target.entries.isEmpty { local.mkdir(name, target: target) } else { local.rename(to: name, target: target) }
                        dismissDialog(value)
                    } cancel: { cancelDialog(value); dismissDialog(value) }
                } else {
                    FilesNameEditor(model: files, entry: target.entries.first, target: target) { dismissDialog(value) }
                }
            case .details(let target, let localSide):
                if let entry = target.entries.first, let path = target.path(for: entry) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("文件详情").font(.title2)
                        FilesTargetSummary(target: target)
                        Text(FilesMetadataDisplay.kind(entry.attributes.kind) + " · " + FilesMetadataDisplay.size(entry.attributes))
                        Text("权限 " + FilesMetadataDisplay.permissions(entry.attributes) + " · 修改 " + FilesMetadataDisplay.modified(entry.attributes))
                        Text("仅显示打开时的元数据，不执行、打开或自动下载文件。").font(.caption).foregroundStyle(.secondary)
                        HStack { Button("复制精确路径") { FilesExactClipboard.copy(path) }; Spacer(); Button("关闭") { discardTarget(target, localSide: localSide); dismissDialog(value) } }
                    }.padding(22).frame(width: 550)
                }
            case .deleteOptions(let target, let localSide):
                DualFilesDeleteOptions(target: target) { linkOnly in
                    if localSide { local.prepareDelete(target, linkOnly: linkOnly) } else { files.prepareDeleteBatch(target, removeLinkOnly: linkOnly) }
                    dismissDialog(value)
                } cancel: { cancelDialog(value); dismissDialog(value) }
            case .localDelete(let review):
                DualFilesDeleteReview(review: review) { local.executeDelete(review); dismissDialog(value) } cancel: { local.discardDelete(review); dismissDialog(value) }
            case .remoteDelete(let review):
                DualFilesDeleteReview(review: review.review) { files.executeDeleteBatch(review); dismissDialog(value) } cancel: { files.discardDeleteBatch(review); dismissDialog(value) }
            }
        }
        .onDisappear { cancelDialog(value) }
    }

    private var hostChooserDialog: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("选择远端主机").font(.title2.weight(.semibold))
            DesktopSearchField(placeholder: "搜索名称、地址或用户名", id: "files.host.search", text: $hostSearch)
            Picker("范围", selection: $hostFilter) { Text("全部").tag("all"); Text("收藏").tag("favorites"); Text("最近").tag("recent") }.pickerStyle(.segmented)
            let matches = filteredHosts
            Group {
                if !app.didLoad && app.isLoading {
                    ProgressView("正在读取主机")
                } else if !app.didLoad && app.issue != nil {
                    VStack(spacing: 8) {
                        Text("无法读取主机列表").font(.headline)
                        Button("重试") { Task { _ = await app.reload() } }
                    }
                } else if matches.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: app.connectionHosts.isEmpty ? "server.rack" : "magnifyingglass")
                            .font(.title2).foregroundStyle(.secondary)
                        Text(app.connectionHosts.isEmpty ? "保险箱中尚无主机" : "没有匹配的主机").font(.headline)
                        if app.connectionHosts.isEmpty {
                            Text("在保险箱中新建主机后，即可在这里选择。").font(.caption).foregroundStyle(.secondary)
                        } else {
                            Button("显示所有主机") { hostFilter = "all"; hostSearch = "" }
                        }
                    }
                } else {
                    ScrollView {
                        LazyVStack(spacing: 4) {
                            ForEach(matches, id: \.id) { host in hostChooserRow(host) }
                        }
                    }
                }
            }.frame(maxWidth: .infinity).frame(height: 250)
            HStack { Spacer(); Button("取消") { dialog = nil }.keyboardShortcut(.cancelAction) }
        }.padding(22).frame(width: 480).background(DesktopStyle.background)
    }

    private func hostChooserRow(_ host: HostConfiguration) -> some View {
        let isCurrent = files.selectedHost?.id == host.id
        return Button { requestChange(host, disconnect: false); dialog = nil } label: {
            HStack(spacing: 10) {
                Image(systemName: host.isFavorite ? "star.fill" : "server.rack")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(host.isFavorite ? DesktopStyle.statusAmber : Color.accentColor)
                    .frame(width: 32, height: 32)
                    .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 2) {
                    Text(host.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                    Text(verbatim: host.username + "@" + host.vaultEndpoint)
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                if isCurrent {
                    DesktopBadge(text: "当前", color: Color.accentColor, fill: DesktopStyle.iconSurface)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(isCurrent ? DesktopStyle.selection : DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(isCurrent ? Color.accentColor.opacity(0.6) : DesktopStyle.border))
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }
    private var filteredHosts: [HostConfiguration] {
        let hosts = app.connectionHosts.filter { host in
            (hostFilter != "favorites" || host.isFavorite) && (hostFilter != "recent" || host.lastConnectedAt != nil) &&
            (hostSearch.isEmpty || [host.name, host.address, host.username].contains { $0.localizedStandardContains(hostSearch) })
        }
        return hostFilter == "recent" ? hosts.sorted { ($0.lastConnectedAt ?? .distantPast) > ($1.lastConnectedAt ?? .distantPast) } : hosts
    }
    private var status: String {
        switch files.state { case .disconnected: "未连接"; case .preparing: "准备连接"; case .awaitingTrust: "等待主机身份确认"; case .authenticating: "正在认证"; case .ready: "已连接"; case .closing: "正在断开连接"; case .failed: "连接失败" }
    }
}


private struct ProminentIfModifier: ViewModifier {
    let prominent: Bool
    @ViewBuilder func body(content: Content) -> some View {
        if prominent { content.buttonStyle(.borderedProminent) }
        else { content.buttonStyle(.bordered) }
    }
}

private struct FilesNavigationBar: View {
    let path: RemotePath?
    let back: Bool
    let forward: Bool
    let up: Bool
    let enabled: Bool
    let prefix: String
    let go: (String) -> Void
    let backward: () -> Void
    let forwardAction: () -> Void
    let parent: () -> Void
    let refresh: () -> Void
    let navigate: (RemotePath) -> Void
    var onActivate: () -> Void = {}
    @State private var editing = false
    @State private var draft = ""
    var body: some View {
        HStack(spacing: 8) {
            HStack(spacing: 4) {
                Button { onActivate(); backward() } label: { Image(systemName: "chevron.left").frame(width: 22, height: 22) }.disabled(!enabled || !back).accessibilityLabel("后退").accessibilityIdentifier(prefix + ".back")
                Button { onActivate(); forwardAction() } label: { Image(systemName: "chevron.right").frame(width: 22, height: 22) }.disabled(!enabled || !forward).accessibilityLabel("前进")
                Button { onActivate(); parent() } label: { Image(systemName: "arrow.up").frame(width: 22, height: 22) }.disabled(!enabled || !up).accessibilityLabel("上级")
                Button { onActivate(); refresh() } label: { Image(systemName: "arrow.clockwise").frame(width: 22, height: 22) }.disabled(!enabled).accessibilityLabel("刷新")
            }.buttonStyle(.borderless).font(.system(size: 11, weight: .medium))

            if editing {
                NativeField(placeholder: "绝对路径", id: prefix + ".path", text: $draft,
                    onSubmit: { _ in go(draft); editing = false }, onCancel: { draft = ""; editing = false }, onFocus: onActivate, borderless: true)
                    .frame(height: 24)
                    .padding(.horizontal, 8)
                    .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 7))
                    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.accentColor.opacity(0.6)))
            } else {
                ScrollViewReader { proxy in
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 3) {
                            Button("/") { onActivate(); navigate(.root) }.disabled(!enabled)
                            ForEach(Array(crumbs.enumerated()), id: \.offset) { _, value in
                                Image(systemName: "chevron.right").font(.system(size: 9)).foregroundStyle(.secondary)
                                Button(FileDisplay.name(value.name!)) { onActivate(); navigate(value) }.disabled(!enabled).help(FileDisplay.path(value))
                            }
                            Color.clear.frame(width: 1, height: 1).id("crumb-end")
                        }.buttonStyle(.borderless).font(.system(size: 11, design: .monospaced))
                            .padding(.horizontal, 8)
                    }
                    .onAppear { proxy.scrollTo("crumb-end", anchor: .trailing) }
                    .onChange(of: crumbs.count) { _, _ in proxy.scrollTo("crumb-end", anchor: .trailing) }
                    .onChange(of: path) { _, _ in proxy.scrollTo("crumb-end", anchor: .trailing) }
                }
                .frame(height: 24)
                .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(DesktopStyle.border))
            }

            Button {
                onActivate()
                if editing { editing = false }
                else { draft = path.flatMap { String(data: $0.bytes, encoding: .utf8) } ?? ""; editing = true }
            } label: {
                Image(systemName: editing ? "xmark" : "pencil").frame(width: 22, height: 22)
            }
            .buttonStyle(.borderless).font(.system(size: 11))
            .disabled(path == nil).accessibilityLabel("编辑绝对路径")
        }.padding(.horizontal, 12).padding(.bottom, 8)
    }
    private var crumbs: [RemotePath] {
        guard let path else { return [] }
        var current = RemotePath.root, values: [RemotePath] = []
        for name in (try? FilesLocalPaths.components(path)) ?? [] { if let next = try? current.appending(name) { current = next; values.append(next) } }
        return values
    }
}

private struct FilesPaneSplit<Left: View, Right: View>: NSViewRepresentable {
    let left: Left
    let right: Right
    let defaults: UserDefaults?
    func makeNSView(context: Context) -> FilesNativeSplitView<Left, Right> {
        FilesNativeSplitView(left: left, right: right, defaults: defaults)
    }
    func updateNSView(_ view: FilesNativeSplitView<Left, Right>, context: Context) { view.update(left: left, right: right) }
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: FilesNativeSplitView<Left, Right>, context: Context) -> CGSize? {
        CGSize(width: proposal.width ?? 600, height: proposal.height ?? 400)
    }
}

struct FilesPaneMenuAction {
    let title: String
    var enabled = true
    let perform: () -> Void
    var isSeparator = false
    static var separator: FilesPaneMenuAction { .init(title: "", perform: {}, isSeparator: true) }
}
struct DualFilesEntryTable: NSViewRepresentable {
    let entries: [DirectoryEntry]
    @Binding var selected: Set<FileName>
    @Binding var sort: FilesSort
    let identifier: String
    let drag: ([DirectoryEntry]) -> [NSPasteboardWriting]
    let drop: (NSPasteboard) -> Bool
    let canDrop: (NSPasteboard) -> Bool
    let activate: (DirectoryEntry) -> Void
    let menu: (DirectoryEntry?) -> [FilesPaneMenuAction]
    var layoutDefaults: UserDefaults? = nil
    var layoutSide: FilesLayoutSide? = nil
    var onFocus: () -> Void = {}
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true; scroll.autohidesScrollers = true
        let table = DualFilesNativeTable(); table.identifier = NSUserInterfaceItemIdentifier(identifier)
        context.coordinator.configureColumns(in: table)
        table.rowHeight = 29; table.usesAlternatingRowBackgroundColors = false; table.allowsMultipleSelection = true; table.allowsEmptySelection = true
        table.backgroundColor = NSColor(DesktopStyle.background)
        scroll.drawsBackground = true; scroll.backgroundColor = NSColor(DesktopStyle.background)
        table.delegate = context.coordinator; table.dataSource = context.coordinator; table.target = context.coordinator; table.doubleAction = #selector(Coordinator.open(_:))
        table.contextMenu = { [weak coordinator = context.coordinator] table, event in coordinator?.makeMenu(table, event: event) }
        table.openSelection = { [weak coordinator = context.coordinator] table in coordinator?.open(table) }
        table.onFocus = { [weak coordinator = context.coordinator] in coordinator?.parent.onFocus() }
        table.registerForDraggedTypes([.fileURL, FilesPaneDrag.remoteType]); table.setDraggingSourceOperationMask(.copy, forLocal: true); table.setDraggingSourceOperationMask(.copy, forLocal: false)
        scroll.documentView = table
        return scroll
    }
    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let table = scroll.documentView as? NSTableView else { return }
        context.coordinator.parent = self
        context.coordinator.updateColumnBounds()
        if context.coordinator.rows != entries { context.coordinator.rows = entries; table.reloadData() }
        let indexes = IndexSet(entries.indices.filter { selected.contains(entries[$0].name) })
        if table.selectedRowIndexes != indexes { table.selectRowIndexes(indexes, byExtendingSelection: false) }
    }
    @MainActor final class Coordinator: FilesTableLayoutOwner, @MainActor NSTableViewDataSource {
        var parent: DualFilesEntryTable
        var rows: [DirectoryEntry] = []
        private var actions: [FilesPaneMenuAction] = []
        init(_ parent: DualFilesEntryTable) {
            self.parent = parent
            super.init(defaults: parent.layoutDefaults, side: parent.layoutSide)
        }
        func numberOfRows(in tableView: NSTableView) -> Int { rows.count }
        func tableView(_ tableView: NSTableView, viewFor column: NSTableColumn?, row: Int) -> NSView? {
            guard rows.indices.contains(row) else { return nil }
            let entry = rows[row], id = column?.identifier.rawValue ?? "name"
            if id == "name" {
                let displayName = FileDisplay.name(entry.name)
                let (symbol, tint) = iconStyle(for: entry, displayName: displayName)
                let image = NSImageView(image: NSImage(systemSymbolName: symbol, accessibilityDescription: FilesMetadataDisplay.kind(entry.attributes.kind)) ?? NSImage())
                image.contentTintColor = tint
                image.translatesAutoresizingMaskIntoConstraints = false; image.widthAnchor.constraint(equalToConstant: 18).isActive = true
                let text = NSTextField(labelWithString: displayName)
                text.font = .systemFont(ofSize: 12.5, weight: entry.attributes.kind == .directory ? .medium : .regular)
                text.lineBreakMode = .byTruncatingMiddle
                let stack = NSStackView(views: [image, text]); stack.spacing = 7
                stack.toolTip = displayName + "\n原始名称字节(base64)：" + entry.name.bytes.base64EncodedString()
                return stack
            }
            let value = id == "modified" ? FilesMetadataDisplay.modified(entry.attributes) : id == "size" ? FilesMetadataDisplay.size(entry.attributes) : id == "kind" ? FilesMetadataDisplay.kind(entry.attributes.kind) : FilesMetadataDisplay.permissions(entry.attributes)
            let field = NSTextField(labelWithString: value)
            field.font = id == "permissions" ? .monospacedSystemFont(ofSize: 11.5, weight: .regular) : .monospacedDigitSystemFont(ofSize: 12, weight: .regular)
            field.textColor = .secondaryLabelColor
            return field
        }
        private func iconStyle(for entry: DirectoryEntry, displayName: String) -> (String, NSColor) {
            switch entry.attributes.kind {
            case .directory: return ("folder.fill", .systemBlue)
            case .symbolicLink: return ("link", .systemTeal)
            default:
                let ext = (displayName as NSString).pathExtension.lowercased()
                switch ext {
                case "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "dmg":
                    return ("doc.zipper", .systemOrange)
                case "png", "jpg", "jpeg", "gif", "webp", "svg", "heic", "ico":
                    return ("photo", .systemPurple)
                case "swift", "py", "js", "ts", "tsx", "json", "yaml", "yml", "toml", "sh", "zsh", "md", "txt", "log", "conf", "ini", "xml":
                    return ("doc.text", .systemIndigo)
                default:
                    return ("doc", .secondaryLabelColor)
                }
            }
        }
        func tableViewSelectionDidChange(_ notification: Notification) {
            guard let table = notification.object as? NSTableView else { return }
            parent.selected = Set(table.selectedRowIndexes.filter(rows.indices.contains).map { rows[$0].name })
        }
        func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
            guard let value = tableView.sortDescriptors.first, let key = value.key, let column = FilesSort.Column(rawValue: key) else { return }
            parent.sort = FilesSort(column: column, ascending: value.ascending)
        }
        @objc func open(_ table: NSTableView) {
            let row = table.clickedRow >= 0 ? table.clickedRow : table.selectedRow
            if rows.indices.contains(row) { parent.activate(rows[row]) }
        }
        func makeMenu(_ table: NSTableView, event: NSEvent) -> NSMenu {
            let row = table.row(at: table.convert(event.locationInWindow, from: nil))
            if row >= 0 && !table.selectedRowIndexes.contains(row) { table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false) }
            actions = parent.menu(rows.indices.contains(row) ? rows[row] : nil)
            let menu = NSMenu()
            for (index, action) in actions.enumerated() {
                if action.isSeparator { menu.addItem(.separator()); continue }
                let item = NSMenuItem(title: action.title, action: #selector(runMenu(_:)), keyEquivalent: ""); item.target = self; item.tag = index; item.isEnabled = action.enabled; menu.addItem(item)
            }
            menu.autoenablesItems = false
            return menu
        }
        @objc private func runMenu(_ item: NSMenuItem) { if actions.indices.contains(item.tag), actions[item.tag].enabled { actions[item.tag].perform() } }
        func tableView(_ tableView: NSTableView, writeRowsWith rowIndexes: IndexSet, to pasteboard: NSPasteboard) -> Bool {
            let items = parent.drag(rowIndexes.filter(rows.indices.contains).map { rows[$0] })
            guard !items.isEmpty else { return false }
            pasteboard.clearContents(); return pasteboard.writeObjects(items)
        }
        func tableView(_ tableView: NSTableView, validateDrop info: any NSDraggingInfo, proposedRow row: Int, proposedDropOperation operation: NSTableView.DropOperation) -> NSDragOperation {
            guard parent.canDrop(info.draggingPasteboard) else { return [] }; tableView.setDropRow(-1, dropOperation: .on); return .copy
        }
        func tableView(_ tableView: NSTableView, acceptDrop info: any NSDraggingInfo, row: Int, dropOperation: NSTableView.DropOperation) -> Bool { parent.drop(info.draggingPasteboard) }
    }
}
private final class DualFilesNativeTable: NSTableView {
    var contextMenu: ((NSTableView, NSEvent) -> NSMenu?)?
    var openSelection: ((NSTableView) -> Void)?
    var onFocus: (() -> Void)?
    override func becomeFirstResponder() -> Bool {
        let accepted = super.becomeFirstResponder()
        if accepted { onFocus?() }
        return accepted
    }
    override func menu(for event: NSEvent) -> NSMenu? { contextMenu?(self, event) }
    override func keyDown(with event: NSEvent) {
        if event.keyCode == 36 || event.keyCode == 76 { openSelection?(self); return }
        super.keyDown(with: event)
    }
}

private struct DualFilesNameEditor: View {
    let target: FilesOperationTarget
    let confirm: (FileName) -> Void
    let cancel: () -> Void
    @State private var name = ""
    @State private var error = ""
    @State private var submitted = false
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(target.entries.isEmpty ? "新建本地目录" : "重命名本地项目").font(.title2)
            FilesTargetSummary(target: target)
            TextField("新的单个名称", text: $name).textFieldStyle(.roundedBorder).onSubmit(submit)
            if let value = try? FileName(name), let path = try? target.parent.appending(value) {
                Text(verbatim: "目标：" + FileDisplay.path(path)).font(.caption.monospaced())
                DisclosureGroup("技术详情（目标路径）") {
                    Text(verbatim: "目标原始字节(base64)：" + path.bytes.base64EncodedString()).font(.caption2.monospaced()).textSelection(.enabled)
                }.font(.caption)
            }
            Text("已有同名项目时停止，不自动覆盖。").font(.caption).foregroundStyle(.secondary)
            if !error.isEmpty { Text(error).foregroundStyle(.red) }
            HStack { Button("取消", action: cancel); Spacer(); Button("确认", action: submit).disabled(submitted) }
        }.padding(22).frame(width: 540)
    }
    private func submit() {
        guard !submitted else { return }
        do { let value = try FileName(name); submitted = true; confirm(value) }
        catch { self.error = "名称不能为空、含斜杠、NUL、. 或 ..。" }
    }
}
private struct DualFilesDeleteOptions: View {
    let target: FilesOperationTarget
    let prepare: (Bool) -> Void
    let cancel: () -> Void
    @State private var linkOnly = false
    @State private var submitted = false
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("准备删除 \(target.entries.count) 个选中项目").font(.title2)
            Text("先只读收集全部精确范围，下一步统一确认；本步不会删除文件。").font(.caption)
            ScrollView { FilesTargetSummary(target: target).frame(maxWidth: .infinity, alignment: .leading) }.frame(maxHeight: 220)
            if target.entries.contains(where: { $0.attributes.kind == .symbolicLink }) { Toggle("仅删除符号链接自身，绝不跟随", isOn: $linkOnly) }
            HStack { Button("取消", action: cancel); Spacer(); Button("生成全部计划") { guard !submitted else { return }; submitted = true; prepare(linkOnly) }.disabled(submitted) }
        }.padding(22).frame(width: 560)
    }
}
private struct DualFilesDeleteReview: View {
    let review: BrowserDeleteReview
    let execute: () -> Void
    let cancel: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("删除这些项目？").font(.title2)
            ScrollView { FilesTargetSummary(target: review.target) }.frame(maxHeight: 150)
            Text("\(review.items.count) 个根项目，\(review.itemCount) 个实际项目；任何计划有问题均不会开始。")
            ScrollView { VStack(alignment: .leading, spacing: 5) {
                ForEach(review.items.indices, id: \.self) { index in
                    let plan = review.items[index].plan
                    Text(verbatim: review.displayedPath(plan.root)).font(.headline)
                    ForEach(plan.items.indices, id: \.self) { item in
                        Text(verbatim: review.displayedPath(plan.items[item].path)).font(.caption.monospaced())
                    }
                    ForEach(plan.issues.indices, id: \.self) { issue in Text(verbatim: review.displayedPath(plan.issues[issue].path) + " · " + AppIssue.files(plan.issues[issue].error).message).foregroundStyle(.red) }
                    DisclosureGroup("技术详情（计划路径）") {
                        ForEach(plan.items.indices, id: \.self) { item in
                            Text(verbatim: review.displayedPath(plan.items[item].path) + "\n原始路径字节(base64)：" + review.pathBytes(plan.items[item].path).base64EncodedString()).font(.caption2.monospaced()).textSelection(.enabled)
                        }
                        ForEach(plan.issues.indices, id: \.self) { issue in
                            let error = plan.issues[issue].error
                            Text(verbatim: error.kind.rawValue + " · " + error.operation).font(.caption2.monospaced())
                        }
                    }.font(.caption)
                }
            }.frame(maxWidth: .infinity, alignment: .leading) }.frame(height: 230)
            Text("删除后无法撤销。符号链接仅删除链接自身。").font(.caption).foregroundStyle(.secondary)
            HStack { Button("取消全部计划", action: cancel); Spacer(); Button("删除此次范围", role: .destructive, action: execute).disabled(!review.canExecute) }
        }.padding(22).frame(width: 620)
    }
}
