import AppKit
import SwiftUI
import OpenLXSSHCore

/// Small native controls expose identifiers for the in-process smoke harness. The harness
/// uses the actual target/action and text-editing paths; it does not require Accessibility.
struct NativeButton: NSViewRepresentable {
    let title: String
    let id: String
    var enabled = true
    var action: () -> Void
    func makeCoordinator() -> Coordinator { Coordinator(action) }
    func makeNSView(context: Context) -> NSButton {
        let view = NSButton(title: title, target: context.coordinator, action: #selector(Coordinator.clicked))
        view.bezelStyle = .rounded; view.identifier = NSUserInterfaceItemIdentifier(id)
        view.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        return view
    }
    func updateNSView(_ view: NSButton, context: Context) {
        context.coordinator.action = action; view.title = title; view.isEnabled = enabled
    }
    @MainActor final class Coordinator: NSObject {
        var action: () -> Void
        init(_ action: @escaping () -> Void) { self.action = action }
        @objc func clicked() { action() }
    }
}

struct NativeField: NSViewRepresentable {
    let placeholder: String
    let id: String
    @Binding var text: String
    func makeCoordinator() -> Coordinator { Coordinator($text) }
    func makeNSView(context: Context) -> NSTextField {
        let view = NSTextField(string: text)
        view.identifier = NSUserInterfaceItemIdentifier(id); view.placeholderString = placeholder
        view.delegate = context.coordinator; view.target = context.coordinator; view.action = #selector(Coordinator.committed(_:))
        view.lineBreakMode = .byTruncatingTail
        view.setContentHuggingPriority(.defaultLow, for: .horizontal)
        return view
    }
    func updateNSView(_ view: NSTextField, context: Context) {
        context.coordinator.text = $text
        if view.stringValue != text { view.stringValue = text }
    }
    @MainActor final class Coordinator: NSObject, NSTextFieldDelegate {
        var text: Binding<String>
        init(_ text: Binding<String>) { self.text = text }
        func controlTextDidChange(_ notification: Notification) {
            if let field = notification.object as? NSTextField { text.wrappedValue = field.stringValue }
        }
        @objc func committed(_ sender: NSTextField) { text.wrappedValue = sender.stringValue }
    }
}

struct PopupItem { let value: String; let title: String }
struct NativePopup: NSViewRepresentable {
    let id: String
    let items: [PopupItem]
    @Binding var selection: String
    func makeCoordinator() -> Coordinator { Coordinator($selection) }
    func makeNSView(context: Context) -> NSPopUpButton {
        let view = NSPopUpButton(frame: .zero, pullsDown: false)
        view.identifier = NSUserInterfaceItemIdentifier(id); view.target = context.coordinator
        view.action = #selector(Coordinator.selected(_:))
        return view
    }
    func updateNSView(_ view: NSPopUpButton, context: Context) {
        context.coordinator.selection = $selection
        if view.itemArray.map(\.title) != items.map(\.title) || view.itemArray.map({ $0.representedObject as? String }) != items.map({ Optional($0.value) }) {
            view.removeAllItems()
            for item in items { view.addItem(withTitle: item.title); view.lastItem?.representedObject = item.value }
        }
        if let index = items.firstIndex(where: { $0.value == selection }) { view.selectItem(at: index) }
    }
    @MainActor final class Coordinator: NSObject {
        var selection: Binding<String>
        init(_ selection: Binding<String>) { self.selection = selection }
        @objc func selected(_ sender: NSPopUpButton) {
            if let value = sender.selectedItem?.representedObject as? String { selection.wrappedValue = value }
        }
    }
}

struct HostTable: NSViewRepresentable {
    let hosts: [HostConfiguration]
    @Binding var selectedID: UUID?
    var open: (UUID) -> Void
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true; scroll.borderType = .noBorder
        let table = NSTableView()
        table.identifier = NSUserInterfaceItemIdentifier("hosts.table")
        for (id, title, width) in [("name", "主机", 200.0), ("address", "地址 / 用户", 230.0), ("favorite", "收藏", 55.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id)); column.title = title; column.width = width
            table.addTableColumn(column)
        }
        table.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle; table.rowHeight = 44
        table.delegate = context.coordinator; table.dataSource = context.coordinator
        table.target = context.coordinator; table.doubleAction = #selector(Coordinator.doubleClicked(_:))
        table.allowsEmptySelection = true; table.usesAlternatingRowBackgroundColors = true
        scroll.documentView = table
        return scroll
    }
    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let table = scroll.documentView as? NSTableView else { return }
        context.coordinator.parent = self
        if context.coordinator.displayedHosts != hosts {
            context.coordinator.displayedHosts = hosts; table.reloadData()
        }
        let row = hosts.firstIndex { $0.id == selectedID }
        let indexes = row.map { IndexSet(integer: $0) } ?? IndexSet()
        if table.selectedRowIndexes != indexes { table.selectRowIndexes(indexes, byExtendingSelection: false) }
    }
    @MainActor final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        var parent: HostTable
        var displayedHosts: [HostConfiguration] = []
        init(_ parent: HostTable) { self.parent = parent }
        func numberOfRows(in tableView: NSTableView) -> Int { displayedHosts.count }
        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
            guard displayedHosts.indices.contains(row) else { return nil }
            let host = displayedHosts[row]
            let text: String
            switch tableColumn?.identifier.rawValue {
            case "name": text = host.name
            case "favorite": text = host.isFavorite ? "★" : ""
            default: text = host.username + "@" + host.address + ":" + String(host.port)
            }
            let field = NSTextField(labelWithString: text)
            field.lineBreakMode = .byTruncatingTail; field.toolTip = text
            return field
        }
        func tableViewSelectionDidChange(_ notification: Notification) {
            guard let table = notification.object as? NSTableView else { return }
            parent.selectedID = displayedHosts.indices.contains(table.selectedRow) ? displayedHosts[table.selectedRow].id : nil
        }
        @objc func doubleClicked(_ sender: NSTableView) {
            guard displayedHosts.indices.contains(sender.clickedRow) else { return }
            parent.open(displayedHosts[sender.clickedRow].id)
        }
    }
}
