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
    let model: VaultDesktopModel
    let action: (VaultHostCommand) -> Void
    let menu: (UUID) -> [VaultHostMenuItem]
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeNSView(context: Context) -> NSScrollView {
        let table = VaultNativeHostTable()
        table.identifier = NSUserInterfaceItemIdentifier("vault.hosts.table")
        table.addTableColumn(NSTableColumn(identifier: .init("host")))
        table.headerView = nil; table.allowsMultipleSelection = true; table.allowsEmptySelection = true
        table.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        table.style = .plain
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
        let card = model.displayMode == .cards
        table.intercellSpacing = NSSize(width: 0, height: card ? 7 : 2)
        table.rowHeight = card ? 88 : 54
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
    private var folderName: String { metadata?.folderPath?.displayName ?? "未分组" }
    private var tags: [HostTag] { metadata?.tags ?? [] }

    private var rowBackground: Color {
        if selected { return DesktopStyle.selection }
        if hovered { return DesktopStyle.panelElevated }
        return card ? DesktopStyle.panel : .clear
    }

    var body: some View {
        Group {
            if card { cardContent }
            else { listContent }
        }
        .padding(.horizontal, card ? 14 : 10)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .background(rowBackground, in: RoundedRectangle(cornerRadius: card ? 10 : 6))
        .overlay {
            if card {
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(selected ? Color.accentColor : DesktopStyle.border, lineWidth: selected ? 1.5 : 1)
            }
        }
        .overlay(alignment: .leading) {
            if selected && !card {
                Capsule().fill(Color.accentColor).frame(width: 3, height: 24)
            }
        }
        .onHover { hovered = $0 }
        .help(([host.name, endpoint, host.vaultAuthenticationLabel, folderName] + tags.map(\.name)).joined(separator: "\n"))
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var listContent: some View {
        HStack(spacing: 10) {
            Image(systemName: "server.rack")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(selected ? Color.accentColor : .secondary)
                .frame(width: 22).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                name
                endpointLabel
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            VStack(alignment: .trailing, spacing: 4) {
                Label(folderName, systemImage: "folder").lineLimit(1).truncationMode(.middle)
                Text(host.vaultAuthenticationLabel).lineLimit(1)
            }
            .font(.system(size: 11)).foregroundStyle(.secondary)
            .frame(maxWidth: 112, alignment: .trailing)
        }
    }

    private var cardContent: some View {
        HStack(spacing: 12) {
            Image(systemName: "server.rack").font(.system(size: 20, weight: .medium))
                .foregroundStyle(Color.accentColor).frame(width: 40, height: 40)
                .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 10))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    name
                    Spacer(minLength: 4)
                    DesktopBadge(text: host.vaultAuthenticationLabel)
                }
                endpointLabel
                HStack(spacing: 6) {
                    Label(folderName, systemImage: "folder").lineLimit(1).truncationMode(.middle)
                    ForEach(tags.prefix(2)) { tag in
                        DesktopBadge(text: tag.name, color: .secondary)
                    }
                    if tags.count > 2 { Text("+\(tags.count - 2)").fixedSize() }
                }
                .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
    }

    private var name: some View {
        HStack(spacing: 5) {
            Text(verbatim: host.name).font(.system(size: card ? 15 : 13, weight: .semibold))
                .lineLimit(1).truncationMode(.tail)
            if host.isFavorite {
                Image(systemName: "star.fill").font(.caption2)
                    .foregroundStyle(.orange).accessibilityLabel("已收藏")
            }
        }
    }

    private var endpointLabel: some View {
        Text(verbatim: endpoint).font(.system(size: 11, design: .monospaced))
            .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
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
