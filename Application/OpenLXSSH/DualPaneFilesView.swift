import AppKit
import SwiftUI
import OpenLXSSHCore
import OpenLXSSHFiles

enum FilesSearchPane { case local, remote }

/// The application keeps this view mounted; page visibility only activates local metadata once.
struct DualPaneFilesView: View {
    private let app: AppModel
    private let files: FilesController
    @State private var local: LocalBrowserModel
    @State private var remoteSelection: Set<FileName> = []
    @State private var remoteFilter = ""
    @State private var remoteHidden = false
    @State private var remoteSort = FilesSort()
    @State private var dialog: DualFilesDialog?
    @State private var initialInput = FilesInitialInputOwner()
    @State private var pendingChange: FilesConnectionChangeReview?
    @State private var operationDialog: FilesDialog?
    @State private var showingLocalReports = false
    @State private var showingRemoteReports = false
    @State private var activeSearchPane: FilesSearchPane = .local
    @State private var localSearchFocusRequest: UUID?
    @State private var remoteSearchFocusRequest: UUID?

    init(model: AppModel, localRoot: URL? = nil) {
        app = model; files = model.files
        _local = State(initialValue: localRoot.map { LocalBrowserModel(root: $0) } ?? model.files.localBrowser)
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
            DesktopGlyph(systemName: "arrow.left.arrow.right", size: 30)
            Text("文件传输").font(.system(size: 20, weight: .semibold))
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
                      NSApp.modalWindow == nil, (NSApp.keyWindow ?? NSApp.mainWindow)?.attachedSheet == nil else { return }
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

    private var requiresKeyPassphrase: Bool {
        files.state == .failed && files.selectedHost?.authentication.needsKey == true
            && files.issue?.code == "files.keyPassphraseRequired"
    }

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
                    FilesConnectionPanelView(
                        files: files,
                        initialInput: initialInput,
                        inputContext: inputContext,
                        needsFirstHost: app.didLoad && app.connectionHosts.isEmpty,
                        onCreateHost: createHost,
                        onChooseHost: { dialog = DualFilesDialog(content: .host) },
                        onCancelConnection: { requestChange(nil, disconnect: true) },
                        onConnect: connectInitial
                    )
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

    private func paneHeader(title: String, subtitle: String?, filter: Binding<String>, hidden: Binding<Bool>, localSide: Bool) -> some View {
        FilesPaneHeaderView(
            title: title, subtitle: subtitle, filter: filter, hidden: hidden, localSide: localSide,
            focusRequest: localSide ? localSearchFocusRequest : remoteSearchFocusRequest,
            canTransferSelected: files.canTransfer && !(localSide ? local.selectedEntries.isEmpty : selectedRemote.isEmpty) && local.path != nil,
            canNewDirectory: localSide ? !local.loading : (files.state == .ready && !files.busy),
            canDisconnect: files.state != .disconnected,
            canProbe: files.state == .ready && !files.busy,
            onTransfer: { transfer(localSide: localSide) },
            onNewDirectory: { newDirectory(localSide) },
            onRefresh: { if localSide { local.refresh() } else { files.browse(files.path) } },
            onChooseLocalDirectory: chooseLocalDirectory,
            onChooseHost: { dialog = DualFilesDialog(content: .host) },
            onDisconnect: { requestChange(nil, disconnect: true) },
            onPrepareProbe: { files.prepareProbe() },
            onFocus: { activeSearchPane = localSide ? .local : .remote }
        )
    }

    private func browserTable(localSide: Bool) -> some View {
        let entries = localSide ? local.visibleEntries : remoteRows
        let loading = localSide ? local.loading : files.busy
        let content = localSide ? local.contentState : FilesBrowserContentState.resolve(loading: loading,
            hasSnapshot: !files.navigationHistory.paths.isEmpty, readFailed: files.readFailed, total: files.entries.count, visible: entries.count)
        return FilesBrowserTableView(
            entries: entries,
            selected: localSide ? $local.selection : $remoteSelection,
            sort: localSide ? $local.sort : $remoteSort,
            localSide: localSide,
            loading: loading,
            contentState: content,
            layoutDefaults: app.desktopPreferencesDefaults,
            drag: { rows in makeDrag(rows, localSide: localSide) },
            drop: { acceptDrop($0, localSide: localSide) },
            canDrop: { canDrop($0, localSide: localSide) },
            activate: { activate($0, localSide: localSide) },
            menu: { row in menuActions(row, localSide: localSide) },
            onFocus: { activeSearchPane = localSide ? .local : .remote },
            onRefresh: { if localSide { local.refresh() } else { files.browse(files.path) } },
            onShowAll: { if localSide { local.filter = ""; local.showsHidden = true } else { remoteFilter = ""; remoteHidden = true } }
        )
    }

    private func browserFooter(localSide: Bool) -> some View {
        let visible = localSide ? local.visibleEntries : remoteRows
        let selection = localSide ? local.selection : remoteSelection
        let selectedCount = visible.count { selection.contains($0.name) }
        return FilesBrowserFooterView(
            localSide: localSide,
            showSelectionBar: localSide || files.state == .ready,
            visibleCount: visible.count,
            selectedCount: selectedCount,
            readyToTransfer: files.canTransfer && selectedCount > 0 && local.path != nil,
            showStaleReadWarning: (localSide ? local.readFailed : files.readFailed) && (localSide ? !local.visibleEntries.isEmpty : files.state == .ready && !remoteRows.isEmpty),
            deleteReports: localSide ? local.deleteReports : files.lastDeleteReports,
            showingReports: localSide ? $showingLocalReports : $showingRemoteReports,
            issue: localSide ? local.issue : (files.transferPreparationIssue ?? files.issue),
            onTransfer: { transfer(localSide: localSide) },
            onDismissIssue: {
                if localSide { local.issue = nil }
                else { files.issue = nil; files.dismissTransferPreparationIssue() }
            }
        )
    }

    private func createHost() {
        guard app.workspacePage == .sftp else { return }
        app.showWorkspace(.vault)
        app.sendWorkspaceCommand(.newFilesHost)
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
        panel.prompt = "选择文件夹"
        panel.directoryURL = local.path.map(FilesLocalPaths.url)
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
                FilesHostChooserSheet(
                    app: app, files: files,
                    onCreateHost: { dismissDialog(value); createHost() },
                    onSelect: { host in requestChange(host, disconnect: false); dialog = nil },
                    onCancel: { dialog = nil }
                )
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
