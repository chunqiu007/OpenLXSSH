import AppKit
import SwiftUI
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTrust

struct FilesDialog: Identifiable {
    enum Content { case mkdir, rename(DirectoryEntry), delete(DirectoryEntry), trust(FilesTrustPrompt), keyboard(FilesKeyboardPrompt), deletion(FilesDeleteReview), probe(FilesProbeReview), risk(TransferRisk, UUID), transferDecision(TransferDecisionRequest) }
    let id = UUID()
    let content: Content
}
struct FilesPanelView: View {
    @ObservedObject var model: FilesController
    var returnToVault: (() -> Void)? = nil
    @State private var dialog: FilesDialog?
    @State private var selected: Set<FileName> = []
    @State private var address = ""
    @State private var initialSecret = ""
    @State private var useSaved = false
    @State private var keyboardOnly = false
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("SFTP 文件").font(.headline)
                Spacer()
                if let returnToVault {
                    NativeButton(title: "返回保险箱", id: "files.hide") { initialSecret = ""; returnToVault() }.fixedSize()
                }
            }
            Text(model.selectedHost.map { $0.username + "@" + $0.address + ":" + String($0.port) } ?? "请先在主机列表选择主机")
                .font(.caption).lineLimit(2)
            Text("独立直连认证；不使用终端当前目录或内层 SSH。符号链接默认不跟随。").font(.caption2).foregroundStyle(.secondary)
            if model.state != .ready {
                NativeSecureField(id: "files.initial.secret", placeholder: model.selectedHost?.authentication.needsKey == true ? "本次私钥口令（无口令留空）" : "本次密码", text: $initialSecret,
                                  onSubmit: { _ in connectInitial() }).frame(height: 26)
                NativeButton(title: useSaved ? "本次明确使用已保存秘密 · 点击取消" : "本次使用已保存密码／私钥口令", id: "files.initial.saved", enabled: !model.busy) { useSaved.toggle() }.fixedSize()
                if model.selectedHost?.authentication.needsKey == false {
                    NativeButton(title: keyboardOnly ? "仅交互认证 · 点击改初始密码" : "改为仅交互认证", id: "files.initial.keyboardOnly", enabled: !model.busy) { keyboardOnly.toggle() }.fixedSize()
                }
                NativeButton(title: "连接 SFTP", id: "files.connect", enabled: model.canConnect && !model.busy, isProminent: true) { connectInitial() }.fixedSize()
            }
            HStack {
                Text(status).font(.caption)
                Spacer()
                NativeButton(title: "取消／断开", id: "files.cancel", enabled: model.busy || model.state == .ready) { initialSecret = ""; model.cancelCurrent() }.fixedSize()
            }
            Text(verbatim: "当前位置：" + FileDisplay.path(model.path)).font(.caption.monospaced()).textSelection(.enabled)
            HStack {
                NativeButton(title: "上级", id: "files.parent", enabled: model.state == .ready && !model.busy && model.path != .root) { model.browse(model.path.parent) }.fixedSize()
                NativeField(placeholder: "手工 UTF-8 绝对路径（空白保留原路径）", id: "files.path", text: $address).frame(height: 25)
                NativeButton(title: "前往", id: "files.go", enabled: model.state == .ready && !model.busy) {
                    model.go(manualUTF8: address); address = ""
                }.fixedSize()
                NativeButton(title: "刷新", id: "files.refresh", enabled: model.state == .ready && !model.busy) { model.browse(model.path) }.fixedSize()
            }
            FilesEntryTable(entries: model.entries, selected: $selected, dropEnabled: model.canTransfer,
                drop: { model.acceptFileDrop($0) }, enter: { model.enter($0) }).frame(minHeight: 180)
            HStack {
                NativeButton(title: "上传文件／目录…", id: "files.upload", enabled: model.canTransfer) { model.chooseUploads(window: NSApp.mainWindow) }.fixedSize()
                NativeButton(title: "下载所选…", id: "files.download", enabled: model.canTransfer && !selected.isEmpty) { model.chooseDownloads(model.entries.filter { selected.contains($0.name) }, window: NSApp.mainWindow) }.fixedSize()
            }
            Text("可将 Finder 文件／目录拖入列表。取消远端 I/O 可能关闭共享 SFTP 服务，使使用该服务的其他任务失败；不自动重连或续传。").font(.caption2).foregroundStyle(.secondary)
            HStack {
                NativeButton(title: "建目录…", id: "files.mkdir", enabled: model.state == .ready && !model.busy) { dialog = FilesDialog(content: .mkdir) }.fixedSize()
                NativeButton(title: "重命名…", id: "files.rename", enabled: currentEntry != nil && model.state == .ready && !model.busy) { if let entry = currentEntry { dialog = FilesDialog(content: .rename(entry)) } }.fixedSize()
                NativeButton(title: "删除计划…", id: "files.delete", enabled: currentEntry != nil && model.state == .ready && !model.busy) { if let entry = currentEntry { dialog = FilesDialog(content: .delete(entry)) } }.fixedSize()
            }
            NativeButton(title: "检查非覆盖提交能力…", id: "files.probe.prepare", enabled: model.state == .ready && !model.busy) { model.prepareProbe() }.fixedSize()
            if let review = model.deleteReview { NativeButton(title: "核对精确删除范围…", id: "files.delete.review") { dialog = FilesDialog(content: .deletion(review)) }.fixedSize() }
            if let review = model.probeReview { NativeButton(title: "批准能力探测计划…", id: "files.probe.review") { dialog = FilesDialog(content: .probe(review)) }.fixedSize() }
            if let report = model.lastDeleteReport {
                Text(report.allSucceeded ? "删除计划全部完成" : "删除未全部完成；以下为逐项事实").font(.caption)
                ScrollView { VStack(alignment: .leading) { ForEach(Array(report.items.enumerated()), id: \.offset) { _, item in Text(verbatim: FileDisplay.path(item.path) + " · " + deleteState(item.state)).font(.caption2) } } }.frame(maxHeight: 90)
            }
            if let probe = model.lastProbeResult {
                Text(probe.passed ? "当前服务实例非覆盖能力检查通过" : "能力检查失败；没有生成可用证据").font(.caption)
                ForEach(probe.retainedPaths, id: \.self) { Text(verbatim: "待人工核对的自有残留：" + FileDisplay.path($0)).font(.caption2) }
            }
            IssueView(issue: model.issue) { model.issue = nil }
        }.padding(12).frame(minWidth: 410, maxWidth: .infinity)
        .onChange(of: model.path) { _, _ in address = "" }
        .onChange(of: model.selectedHost) { oldHost, newHost in
            guard oldHost?.id != newHost?.id || oldHost?.connectionIdentity != newHost?.connectionIdentity else { return }
            initialSecret = ""; selected = []; dialog = nil; address = ""; useSaved = false; keyboardOnly = false
        }
        .onChange(of: model.state) { _, _ in
            switch dialog?.content {
            case .trust(let p): if model.trustPrompt?.id != p.id { dialog = nil }
            case .keyboard(let p): if model.keyboardPrompt?.id != p.id { dialog = nil }
            default: break
            }
        }
        .onChange(of: model.riskID) { _, id in
            if case .risk(_, let shown)? = dialog?.content, shown != id { dialog = nil }
        }
        .onChange(of: model.trustPrompt?.id) { _, id in
            if case .trust(let shown)? = dialog?.content, shown.id != id { dialog = nil }
        }
        .onChange(of: model.keyboardPrompt?.id) { _, id in
            if case .keyboard(let shown)? = dialog?.content, shown.id != id { dialog = nil }
        }
        .onDisappear { initialSecret = "" }
        .nativeSheet(item: $dialog) { item in
            switch item.content {
            case .mkdir: FilesNameEditor(model: model, entry: nil) { dialog = nil }
            case .rename(let entry): FilesNameEditor(model: model, entry: entry) { dialog = nil }
            case .delete(let entry): FilesDeleteOptions(model: model, entry: entry) { dialog = nil }
            case .trust(let prompt): FilesTrustView(model: model, prompt: prompt) { dialog = nil }
            case .keyboard(let prompt): FilesKeyboardView(model: model, prompt: prompt) { dialog = nil }
            case .deletion(let review): FilesDeletePlanView(model: model, review: review) { dialog = nil }
            case .probe(let review): FilesProbeView(model: model, review: review) { dialog = nil }
            case .risk(let risk, let id): FilesRiskView(model: model, risk: risk, requestID: id) { dialog = nil }
            case .transferDecision: EmptyView()
            }
        }
    }
    private var currentEntry: DirectoryEntry? { selected.count == 1 ? model.entries.first { selected.contains($0.name) } : nil }
    private func connectInitial() {
        guard model.canConnect, !model.busy else { return }
        let secret: FilesInitialSecret = useSaved ? .saved : .manual(.init(utf8: initialSecret))
        initialSecret = ""
        model.connect(FilesConnectInput(primary: secret, keyboardOnly: keyboardOnly))
    }
    private var status: String {
        switch model.state {
        case .disconnected: "未连接（手动连接）"
        case .preparing: "准备独立 SFTP 连接"
        case .awaitingTrust: "等待主机指纹核实"
        case .authenticating: "等待认证"
        case .ready: model.busy ? "文件操作中" : "已就绪 · 活动传输 \(model.transferSnapshot.jobs.filter { $0.state.isActive }.count)"
        case .closing: "正在取消并清理"
        case .failed: "未连接／操作失败，需手动重连"
        }
    }
    private func deleteState(_ state: DeleteItemResult.State) -> String { switch state { case .succeeded: "成功"; case .failed(let e): "失败：" + e.kind.rawValue; case .notAttempted(let e): "未执行：" + e.kind.rawValue } }
}

struct FilesEntryTable: NSViewRepresentable {
    let entries: [DirectoryEntry]
    @Binding var selected: Set<FileName>
    let dropEnabled: Bool
    let drop: (NSPasteboard) -> Bool
    let enter: (DirectoryEntry) -> Void
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true
        let table = NSTableView(); table.identifier = NSUserInterfaceItemIdentifier("files.entries")
        for (id, title, width) in [("name", "名称", 280.0), ("kind", "类型", 100.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id)); column.title = title; column.width = width; table.addTableColumn(column)
        }
        table.rowHeight = 25; table.usesAlternatingRowBackgroundColors = true; table.allowsEmptySelection = true; table.allowsMultipleSelection = true
        table.registerForDraggedTypes([.fileURL]); table.setDraggingSourceOperationMask(.copy, forLocal: false)
        table.delegate = context.coordinator; table.dataSource = context.coordinator; table.target = context.coordinator
        table.doubleAction = #selector(Coordinator.doubleClick(_:)); scroll.documentView = table
        return scroll
    }
    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let table = scroll.documentView as? NSTableView else { return }
        context.coordinator.parent = self
        if context.coordinator.entries != entries { context.coordinator.entries = entries; table.reloadData() }
        let indexes = IndexSet(entries.indices.filter { selected.contains(entries[$0].name) })
        if table.selectedRowIndexes != indexes { table.selectRowIndexes(indexes, byExtendingSelection: false) }
    }
    @MainActor final class Coordinator: NSObject, NSTableViewDelegate, NSTableViewDataSource {
        var parent: FilesEntryTable; var entries: [DirectoryEntry] = []
        init(_ parent: FilesEntryTable) { self.parent = parent }
        func numberOfRows(in tableView: NSTableView) -> Int { entries.count }
        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
            guard entries.indices.contains(row) else { return nil }
            let entry = entries[row]
            return NSTextField(labelWithString: tableColumn?.identifier.rawValue == "name" ? FileDisplay.name(entry.name) : entry.attributes.kind.rawValue)
        }
        func tableViewSelectionDidChange(_ notification: Notification) {
            guard let table = notification.object as? NSTableView else { return }
            parent.selected = Set(table.selectedRowIndexes.filter { entries.indices.contains($0) }.map { entries[$0].name })
        }
        func tableView(_ tableView: NSTableView, validateDrop info: any NSDraggingInfo, proposedRow row: Int, proposedDropOperation dropOperation: NSTableView.DropOperation) -> NSDragOperation {
            guard parent.dropEnabled, FilesDrop.urls(info.draggingPasteboard) != nil else { return [] }
            tableView.setDropRow(-1, dropOperation: .on); return .copy
        }
        func tableView(_ tableView: NSTableView, acceptDrop info: any NSDraggingInfo, row: Int, dropOperation: NSTableView.DropOperation) -> Bool {
            parent.dropEnabled && parent.drop(info.draggingPasteboard)
        }
        @objc func doubleClick(_ sender: NSTableView) { if entries.indices.contains(sender.clickedRow) { parent.enter(entries[sender.clickedRow]) } }
    }
}
