import AppKit
import SwiftUI
import OpenLXSSHCore

/// Own one AppKit sheet per presentation anchor. SwiftUI still owns the item and
/// editor state, while the coordinator closes only the NSWindow it presented.
/// This avoids losing nested sheet dismissal after an observed model reload.
extension View {
    func nativeSheet<Item: Identifiable, Content: View>(item: Binding<Item?>,
                                                       @ViewBuilder content: @escaping (Item) -> Content) -> some View {
        background(NativeSheetPresenter(item: item, content: content).frame(width: 0, height: 0))
    }
}

private struct NativeSheetPresenter<Item: Identifiable, Content: View>: NSViewRepresentable {
    @Binding var item: Item?
    let content: (Item) -> Content
    func makeCoordinator() -> Coordinator { Coordinator() }
    func makeNSView(context: Context) -> SheetAnchorView {
        let view = SheetAnchorView()
        view.windowChanged = { [weak coordinator = context.coordinator] window in coordinator?.setParent(window) }
        return view
    }
    func updateNSView(_ view: SheetAnchorView, context: Context) {
        // Read the item during SwiftUI's update so presentation-only state changes
        // invalidate this representable even when no observed model property changes.
        context.coordinator.update(value: item, item: $item, content: content, parent: view.window)
    }
    static func dismantleNSView(_ view: SheetAnchorView, coordinator: Coordinator) {
        view.windowChanged = nil
        coordinator.close()
    }
    @MainActor final class Coordinator {
        private var item: Binding<Item?>?
        private var value: Item?
        private var content: ((Item) -> Content)?
        private weak var parent: NSWindow?
        private var sheet: NSWindow?
        private var hosting: NSHostingController<Content>?
        private var presentedID: Item.ID?
        private var scheduled = false
        private var active = true
        private var dismissing = false
        func update(value: Item?, item: Binding<Item?>, content: @escaping (Item) -> Content, parent: NSWindow?) {
            self.value = value; self.item = item; self.content = content; self.parent = parent
            schedule()
        }
        func setParent(_ parent: NSWindow?) { self.parent = parent; schedule() }
        private func schedule() {
            guard active, !scheduled else { return }
            scheduled = true
            // Present outside SwiftUI's update/dismantle traversal.
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.scheduled = false
                self.reconcile()
            }
        }
        private func reconcile() {
            guard active else { return }
            guard let value, let content else {
                dismissOwnedSheet(); return
            }
            if sheet != nil {
                // An item ID denotes a fixed editor. Its Observed/StateObject updates
                // in place; replacing the root would reset that editor's local state.
                if presentedID != value.id { dismissOwnedSheet() }
                return
            }
            guard let parent, parent.isVisible else { return }
            let hosting = NSHostingController(rootView: content(value))
            let sheet = NSWindow(contentViewController: hosting)
            sheet.styleMask = [.titled]
            sheet.title = "OpenLXSSH"
            sheet.isReleasedWhenClosed = false
            self.hosting = hosting; self.sheet = sheet; presentedID = value.id
            parent.beginSheet(sheet) { [weak self, weak sheet] _ in
                guard let self, let sheet, self.sheet === sheet else { return }
                let id = self.presentedID
                self.sheet = nil; self.hosting = nil; self.presentedID = nil; self.dismissing = false
                sheet.orderOut(nil)
                if self.active {
                    if self.item?.wrappedValue?.id == id { self.item?.wrappedValue = nil }
                    self.schedule()
                }
            }
        }
        private func dismissOwnedSheet() {
            guard let sheet, !dismissing else { return }
            dismissing = true
            if let parent = sheet.sheetParent { parent.endSheet(sheet) }
            else {
                sheet.orderOut(nil)
                self.sheet = nil; hosting = nil; presentedID = nil; dismissing = false
                schedule()
            }
        }
        func close() {
            active = false
            dismissOwnedSheet()
            item = nil; value = nil; content = nil
        }
    }
}

@MainActor private final class SheetAnchorView: NSView {
    var windowChanged: ((NSWindow?) -> Void)?
    override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); windowChanged?(window) }
}

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
        view.identifier = NSUserInterfaceItemIdentifier(id)
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

struct NativeSecureField: NSViewRepresentable {
    let id: String
    let placeholder: String
    @Binding var text: String
    func makeCoordinator() -> NativeField.Coordinator { NativeField.Coordinator($text) }
    func makeNSView(context: Context) -> NSSecureTextField {
        let view = NSSecureTextField(string: "")
        view.identifier = NSUserInterfaceItemIdentifier(id); view.placeholderString = placeholder
        view.delegate = context.coordinator; view.target = context.coordinator
        view.action = #selector(NativeField.Coordinator.committed(_:))
        return view
    }
    func updateNSView(_ view: NSSecureTextField, context: Context) {
        context.coordinator.text = $text
        if view.stringValue != text { view.stringValue = text }
    }
    static func dismantleNSView(_ view: NSSecureTextField, coordinator: NativeField.Coordinator) {
        // View State is cleared by the owning editor before dismissal/onDisappear. Writing
        // a Binding while SwiftUI tears its graph down violates exclusive access.
        view.stringValue = ""
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

@MainActor private final class HostNativeTableView: NSTableView {
    var openRow: ((Int) -> Void)?
    override func mouseDown(with event: NSEvent) {
        let row = row(at: convert(event.locationInWindow, from: nil))
        if event.clickCount == 2, row >= 0, row < numberOfRows {
            // Route the row under this event, never an unrelated retained selection.
            // NSTableView's target/doubleAction can be suppressed by its cell tracking
            // after sheet/field-editor transitions on the HostProbe OS.
            selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            openRow?(row)
            return
        }
        super.mouseDown(with: event)
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
        let table = HostNativeTableView()
        table.identifier = NSUserInterfaceItemIdentifier("hosts.table")
        for (id, title, width) in [("name", "主机", 200.0), ("address", "地址 / 用户", 230.0), ("favorite", "收藏", 55.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id)); column.title = title; column.width = width
            table.addTableColumn(column)
        }
        table.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle; table.rowHeight = 44
        table.delegate = context.coordinator; table.dataSource = context.coordinator
        table.openRow = { [weak coordinator = context.coordinator] row in coordinator?.open(row: row) }
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
        func open(row: Int) {
            guard displayedHosts.indices.contains(row) else { return }
            parent.open(displayedHosts[row].id)
        }
    }
}
