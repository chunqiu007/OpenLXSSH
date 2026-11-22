import AppKit
import SwiftUI
import OpenLXSSHCore
import OpenLXSSHFiles

struct ProminentIfModifier: ViewModifier {
    let prominent: Bool
    @ViewBuilder func body(content: Content) -> some View {
        if prominent { content.buttonStyle(.borderedProminent) }
        else { content.buttonStyle(.bordered) }
    }
}

struct FilesPaneHeaderView: View {
    let title: String
    let subtitle: String?
    @Binding var filter: String
    @Binding var hidden: Bool
    let localSide: Bool
    let focusRequest: UUID?
    let canTransferSelected: Bool
    let canNewDirectory: Bool
    let canDisconnect: Bool
    let canProbe: Bool
    let onTransfer: () -> Void
    let onNewDirectory: () -> Void
    let onRefresh: () -> Void
    let onChooseLocalDirectory: () -> Void
    let onChooseHost: () -> Void
    let onDisconnect: () -> Void
    let onPrepareProbe: () -> Void
    let onFocus: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: localSide ? "desktopcomputer" : "externaldrive.connected.to.line.below")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundStyle(DesktopStyle.brand)
                    .frame(width: 23)
                    .accessibilityHidden(true)
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
                if localSide {
                    Button("选择文件夹…", action: onChooseLocalDirectory)
                        .controlSize(.small)
                        .accessibilityIdentifier("files.local.chooseDirectory")
                }
                Menu {
                    Button(localSide ? "上传所选" : "下载到左侧当前目录", action: onTransfer).disabled(!canTransferSelected)
                    Divider()
                    Button("新建目录…", action: onNewDirectory).disabled(!canNewDirectory)
                    Button("刷新", action: onRefresh)
                    if !localSide {
                        Button("更换主机…", action: onChooseHost)
                        Button("断开连接", action: onDisconnect).disabled(!canDisconnect)
                        Divider()
                        Button("高级：检查非覆盖提交能力…", action: onPrepareProbe).disabled(!canProbe)
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
                    text: $filter,
                    focusRequest: focusRequest,
                    onFocus: onFocus,
                    clearLabel: "清除筛选"
                )
                Toggle("显示隐藏文件", isOn: $hidden)
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize()
            }
        }.padding(.horizontal, 12).padding(.top, 10).padding(.bottom, 8)
    }
}

struct FilesBrowserTableView: View {
    let entries: [DirectoryEntry]
    @Binding var selected: Set<FileName>
    @Binding var sort: FilesSort
    let localSide: Bool
    let loading: Bool
    let contentState: FilesBrowserContentState
    let layoutDefaults: UserDefaults?
    let drag: ([DirectoryEntry]) -> [NSPasteboardWriting]
    let drop: (NSPasteboard) -> Bool
    let canDrop: (NSPasteboard) -> Bool
    let activate: (DirectoryEntry) -> Void
    let menu: (DirectoryEntry?) -> [FilesPaneMenuAction]
    let onFocus: () -> Void
    let onRefresh: () -> Void
    let onShowAll: () -> Void

    var body: some View {
        ZStack {
            DualFilesEntryTable(entries: entries, selected: $selected,
                sort: $sort, identifier: localSide ? "files.local.entries" : "files.remote.entries",
                drag: drag, drop: drop, canDrop: canDrop, activate: activate, menu: menu,
                layoutDefaults: layoutDefaults, layoutSide: localSide ? .local : .remote,
                onFocus: onFocus)
            if entries.isEmpty && !loading {
                VStack(spacing: 8) {
                    switch contentState {
                    case .failed(let hasSnapshot):
                        Image(systemName: "exclamationmark.folder").font(.title)
                        Text("目录读取失败")
                        if hasSnapshot { Text("已保留上次打开的位置。").font(.caption).foregroundStyle(.secondary) }
                        Button("重试读取", action: onRefresh)
                    case .notLoaded:
                        Text("尚未读取目录")
                        Button("读取目录", action: onRefresh)
                    case .empty, .filteredEmpty:
                        Image(systemName: "folder").font(.title)
                        Text(contentState == .empty ? "空目录" : "没有匹配项")
                        if contentState == .filteredEmpty { Button("显示全部项目", action: onShowAll) }
                        Button("刷新", action: onRefresh)
                    default: EmptyView()
                    }
                }.padding(12)
            }
            if loading { ProgressView().padding(12).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8)).allowsHitTesting(false) }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct FilesBrowserFooterView: View {
    let localSide: Bool
    let showSelectionBar: Bool
    let visibleCount: Int
    let selectedCount: Int
    let readyToTransfer: Bool
    let showStaleReadWarning: Bool
    let deleteReports: [DeleteReport]
    @Binding var showingReports: Bool
    let issue: AppIssue?
    let onTransfer: () -> Void
    let onDismissIssue: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider().overlay(DesktopStyle.border)
            if showSelectionBar {
                HStack(spacing: 8) {
                    Text(selectedCount == 0 ? "\(visibleCount) 项" : "已选 \(selectedCount) / \(visibleCount) 项")
                        .font(.system(size: 11).monospacedDigit()).foregroundStyle(.secondary)
                    Spacer()
                    Button(localSide ? "上传 →" : "← 下载", action: onTransfer)
                        .modifier(ProminentIfModifier(prominent: readyToTransfer))
                        .controlSize(.small)
                        .disabled(!readyToTransfer)
                        .accessibilityIdentifier(localSide ? "files.upload.selected" : "files.download.selected")
                }
            }
            if showStaleReadWarning {
                Text("读取失败，正在显示上次读取的内容。").font(.caption).foregroundStyle(DesktopStyle.statusAmber)
            }
            if !deleteReports.isEmpty {
                DisclosureGroup("最近删除：\(deleteReports.reduce(0) { $0 + $1.items.count }) 项实际结果", isExpanded: $showingReports) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(deleteReports.indices, id: \.self) { report in
                                ForEach(deleteReports[report].items.indices, id: \.self) { index in
                                    let item = deleteReports[report].items[index]
                                    Text(verbatim: FileDisplay.path(item.path) + " · " + deleteResult(item.state)).font(.caption2)
                                }
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(maxHeight: 85)
                }.font(.caption)
            }
            IssueView(issue: issue, dismiss: onDismissIssue)
        }.padding(.horizontal, 12).padding(.vertical, 8).background(DesktopStyle.panel)
    }

    private func deleteResult(_ state: DeleteItemResult.State) -> String {
        switch state {
        case .succeeded: "已删除"
        case .failed(let error): "失败 · " + error.kind.rawValue
        case .notAttempted(let error): "未执行 · " + error.kind.rawValue
        }
    }
}

struct FilesNavigationBar: View {
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
    @State private var pathFocusRequest: UUID?
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
                NativeField(placeholder: "绝对路径", id: prefix + ".path", text: $draft, focusRequest: pathFocusRequest,
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
                else { draft = path.flatMap { String(data: $0.bytes, encoding: .utf8) } ?? ""; pathFocusRequest = UUID(); editing = true }
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
