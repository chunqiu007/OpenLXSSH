import AppKit
import SwiftUI
import OpenLXSSHCore

enum VaultHostCommand: Equatable {
    case connect(UUID, SessionOpenMode), edit(UUID), duplicate(UUID), copyEndpoint(UUID)
    case favorite([UUID], Bool), move([UUID], UUID?), tag([UUID], UUID, Bool), delete([UUID])
}
struct VaultHostMenuItem {
    let title: String
    var command: VaultHostCommand?
    var children: [VaultHostMenuItem] = []
    var destructive = false
    static var separator: Self { Self(title: "") }
}

/// Both list and card presentation use the same native selection, keyboard and action consumer.
/// No overlay gestures intercept field-editor shortcuts or send Enter to a background terminal.
struct VaultHostList: NSViewRepresentable {
    @ObservedObject var model: VaultDesktopModel
    let action: (VaultHostCommand) -> Void
    let menu: (UUID) -> [VaultHostMenuItem]
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeNSView(context: Context) -> NSScrollView {
        let table = VaultNativeHostTable()
        table.identifier = NSUserInterfaceItemIdentifier("vault.hosts.table")
        table.addTableColumn(NSTableColumn(identifier: .init("host")))
        table.headerView = nil; table.allowsMultipleSelection = true; table.allowsEmptySelection = true
        table.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        table.intercellSpacing = NSSize(width: 0, height: 6)
        table.backgroundColor = .clear; table.selectionHighlightStyle = .none
        table.setDraggingSourceOperationMask(.move, forLocal: true)
        table.setDraggingSourceOperationMask([], forLocal: false)
        table.delegate = context.coordinator; table.dataSource = context.coordinator
        table.openRow = { [weak coordinator = context.coordinator] row in coordinator?.open(row) }
        table.focusedRow = { [weak coordinator = context.coordinator] in
            guard let coordinator, let id = coordinator.parent.model.focusedID else { return nil }
            return coordinator.parent.model.hosts.firstIndex { $0.id == id }
        }
        table.selectionChanged = { [weak coordinator = context.coordinator] in coordinator?.syncSelection() }
        table.menuBuilder = { [weak coordinator = context.coordinator] row in coordinator?.buildMenu(row: row) }
        let scroll = NSScrollView()
        scroll.identifier = NSUserInterfaceItemIdentifier("vault.hosts.scroll")
        scroll.hasVerticalScroller = true; scroll.drawsBackground = false; scroll.documentView = table
        context.coordinator.table = table
        return scroll
    }
    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let coordinator = context.coordinator
        coordinator.parent = self; coordinator.updating = true
        guard let table = coordinator.table else { return }
        table.rowHeight = model.displayMode == .cards ? 112 : 84
        table.reloadData()
        table.selectRowIndexes(IndexSet(model.hosts.indices.filter { model.selectedIDs.contains(model.hosts[$0].id) }), byExtendingSelection: false)
        coordinator.updating = false
    }
    @MainActor final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        var parent: VaultHostList
        weak var table: VaultNativeHostTable?
        var updating = false
        init(_ parent: VaultHostList) { self.parent = parent }
        func numberOfRows(in tableView: NSTableView) -> Int { parent.model.hosts.count }
        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
            guard parent.model.hosts.indices.contains(row) else { return nil }
            let host = parent.model.hosts[row]
            let view = NSHostingView(rootView: VaultHostRow(host: host, metadata: parent.model.metadata(for: host.id),
                selected: parent.model.selectedIDs.contains(host.id), card: parent.model.displayMode == .cards))
            view.identifier = NSUserInterfaceItemIdentifier("vault.host." + host.id.uuidString)
            return view
        }
        func tableView(_ tableView: NSTableView, pasteboardWriterForRow row: Int) -> NSPasteboardWriting? {
            guard parent.model.hosts.indices.contains(row) else { return nil }
            let id = parent.model.hosts[row].id
            let ids = parent.model.actionIDs(for: id)
            guard let data = try? JSONEncoder().encode(ids), let text = String(data: data, encoding: .utf8) else { return nil }
            let item = NSPasteboardItem()
            item.setString("OpenLXSSH.hosts.v1:" + text, forType: .string)
            return item
        }
        func tableViewSelectionDidChange(_ notification: Notification) { syncSelection() }
        func syncSelection() {
            guard !updating, let table else { return }
            let ids = Set(table.selectedRowIndexes.compactMap { parent.model.hosts.indices.contains($0) ? parent.model.hosts[$0].id : nil })
            let row = table.clickedRow >= 0 ? table.clickedRow : table.selectedRow
            let focused = parent.model.hosts.indices.contains(row) ? parent.model.hosts[row].id : nil
            parent.model.setSelection(ids, focused: focused)
        }
        func open(_ row: Int) {
            guard parent.model.hosts.indices.contains(row) else { return }
            parent.action(.connect(parent.model.hosts[row].id, .reuse))
        }
        func buildMenu(row: Int) -> NSMenu? {
            guard parent.model.hosts.indices.contains(row) else { return nil }
            let host = parent.model.hosts[row]
            if !parent.model.selectedIDs.contains(host.id) { parent.model.choose(host.id) }
            return nativeMenu(parent.menu(host.id))
        }
        private func nativeMenu(_ items: [VaultHostMenuItem]) -> NSMenu {
            let menu = NSMenu()
            for value in items {
                if value.title.isEmpty { menu.addItem(.separator()); continue }
                let item = NSMenuItem(title: value.title, action: value.command == nil ? nil : #selector(performCommand(_:)), keyEquivalent: "")
                item.target = self
                if let command = value.command { item.representedObject = CommandBox(command) }
                if !value.children.isEmpty { item.submenu = nativeMenu(value.children) }
                menu.addItem(item)
            }
            return menu
        }
        @objc private func performCommand(_ item: NSMenuItem) {
            guard let box = item.representedObject as? CommandBox else { return }
            parent.action(box.command)
        }
    }
}

@MainActor private final class CommandBox: NSObject {
    let command: VaultHostCommand
    init(_ command: VaultHostCommand) { self.command = command }
}
@MainActor final class VaultNativeHostTable: NSTableView {
    var openRow: ((Int) -> Void)?
    var focusedRow: (() -> Int?)?
    var selectionChanged: (() -> Void)?
    var menuBuilder: ((Int) -> NSMenu?)?
    override func mouseDown(with event: NSEvent) {
        let row = row(at: convert(event.locationInWindow, from: nil))
        if event.clickCount == 2, row >= 0, row < numberOfRows {
            selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            selectionChanged?(); openRow?(row); return
        }
        super.mouseDown(with: event)
        selectionChanged?()
    }
    override func keyDown(with event: NSEvent) {
        if event.keyCode == 36 || event.keyCode == 76 {
            if let row = focusedRow?(), row >= 0 { openRow?(row) }
            else if selectedRow >= 0 { openRow?(selectedRow) }
            return
        }
        super.keyDown(with: event)
        selectionChanged?()
    }
    override func menu(for event: NSEvent) -> NSMenu? { menuBuilder?(row(at: convert(event.locationInWindow, from: nil))) }
}

private struct VaultHostRow: View {
    let host: HostConfiguration
    let metadata: HostMetadata?
    let selected: Bool
    let card: Bool
    @State private var hovered = false
    private var endpoint: String { host.username + "@" + host.vaultEndpoint }
    private var visibleTags: [HostTag] { Array((metadata?.tags ?? []).prefix(3)) }
    private var remainingTagCount: Int { max(0, (metadata?.tags.count ?? 0) - visibleTags.count) }
    private var rowBackground: Color { selected ? DesktopStyle.selection : (hovered ? DesktopStyle.panelElevated : (card ? DesktopStyle.panel : .clear)) }
    private var borderColor: Color { selected ? Color.accentColor.opacity(0.65) : ((card || hovered) ? DesktopStyle.border : .clear) }
    private var helpText: String { host.name + "\n" + endpoint + "\n" + (metadata?.folderPath?.displayName ?? "未分组") }
    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "server.rack").font(.system(size: card ? 22 : 19, weight: .medium))
                .foregroundStyle(Color.accentColor).frame(width: card ? 48 : 40, height: card ? 48 : 40)
                .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 10))
            VStack(alignment: .leading, spacing: 5) {
                heading
                Text(endpoint).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                organization
            }
        }
        .padding(.horizontal, 12).padding(.vertical, card ? 14 : 8)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .background(rowBackground)
        .clipShape(RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius))
        .overlay { RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius).strokeBorder(borderColor, lineWidth: 1) }
        .padding(.horizontal, 4)
        .onHover { hovered = $0 }
        .help(helpText)
        .accessibilityElement(children: .combine)
    }
    private var heading: some View {
        HStack {
            Text(host.name).font(.system(size: 13, weight: .semibold)).lineLimit(1).layoutPriority(1)
            if host.isFavorite { Image(systemName: "star.fill").foregroundStyle(.orange).accessibilityLabel("已收藏") }
            Spacer(minLength: 4)
            Text(host.vaultAuthenticationLabel).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                .padding(.horizontal, 7).padding(.vertical, 3)
                .background(DesktopStyle.separator, in: Capsule())
        }
    }
    private var organization: some View {
        HStack(spacing: 6) {
            if let path = metadata?.folderPath { Label(path.displayName, systemImage: "folder").lineLimit(1) }
            ForEach(visibleTags) { tag in
                Text(tag.name).lineLimit(1).padding(.horizontal, 5).padding(.vertical, 2)
                    .background(DesktopStyle.separator, in: RoundedRectangle(cornerRadius: 4))
            }
            if remainingTagCount > 0 { Text("+\(remainingTagCount)") }
        }.font(.caption2).foregroundStyle(.secondary)
    }
}

struct VaultHostMenu: View {
    let items: [VaultHostMenuItem]
    let action: (VaultHostCommand) -> Void
    var body: some View {
        ForEach(items.indices, id: \.self) { index in
            let item = items[index]
            if item.title.isEmpty { Divider() }
            else if !item.children.isEmpty {
                Menu(item.title) { AnyView(VaultHostMenu(items: item.children, action: action)) }
            } else if let command = item.command {
                Button(item.title, role: item.destructive ? .destructive : nil) { action(command) }
            }
        }
    }
}
