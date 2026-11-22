import AppKit
import SwiftUI
import OpenLXSSHCore

private struct ConnectionChooserPresentation: Identifiable { let id = UUID() }

/// One bounded local lease. Only the source's captured mouse press holds its data;
/// there is no system pasteboard or asynchronous drag protocol.
@MainActor final class WorkspaceTabDragOwner: ObservableObject {
    struct Lease: Codable, Equatable { let id: UUID; let tabID: UUID; let order: [UUID] }
    @Published private(set) var isDragging = false
    private var active: Lease?
    private var teardownPublication: UUID?
    var activeLeaseID: UUID? { active?.id }
    private let targets = NSHashTable<WorkspaceTabDropView>.weakObjects()
    var registeredTargets: [WorkspaceTabDropView] { targets.allObjects.filter { $0.owner === self } }
    fileprivate func register(_ target: WorkspaceTabDropView) { targets.add(target) }
    fileprivate func unregister(_ target: WorkspaceTabDropView) { targets.remove(target) }
    func target(at point: NSPoint, in window: NSWindow) -> WorkspaceTabDropView? {
        guard let active, window.attachedSheet == nil, NSApp.modalWindow == nil else { return nil }
        let matches = registeredTargets.filter {
            $0.window === window && !$0.isHiddenOrHasHiddenAncestor && $0.move != nil
                && $0.order?() == active.order && $0.bounds.intersection($0.visibleRect).contains($0.convert(point, from: nil))
        }
        return matches.count == 1 ? matches[0] : nil
    }
    func begin(tabID: UUID, order: [UUID]) -> Data? {
        invalidate()
        guard order.contains(tabID) else { return nil }
        let lease = Lease(id: UUID(), tabID: tabID, order: order)
        guard let data = try? JSONEncoder().encode(lease), data.count <= 64 * 1024 else { return nil }
        active = lease; isDragging = true; return data
    }
    func canAccept(_ data: Data?, leaseID: UUID, order: [UUID], before target: UUID?) -> Bool {
        guard let active, active.id == leaseID, let data, data.count <= 64 * 1024,
              let decoded = try? JSONDecoder().decode(Lease.self, from: data), decoded == active,
              active.order == order, active.tabID != target,
              target == nil || order.contains(where: { $0 == target }) else { return false }
        return true
    }
    func consume(_ data: Data?, leaseID: UUID, order: [UUID], before target: UUID?) -> UUID? {
        guard canAccept(data, leaseID: leaseID, order: order, before: target), let active else { return nil }
        invalidate(); return active.tabID
    }
    func sessionEnded(_ id: UUID?, duringTeardown: Bool = false) {
        guard let id, active?.id == id else { return }
        if duringTeardown { invalidateForTeardown() } else { invalidate() }
    }
    func invalidate() {
        teardownPublication = nil; active = nil
        if isDragging { isDragging = false }
    }
    /// Revoke the capability now, but never notify a hosting graph while its
    /// representables are being dismantled. A later begin cancels this UI update.
    func invalidateForTeardown() {
        active = nil
        guard isDragging, teardownPublication == nil else { return }
        let publication = UUID(); teardownPublication = publication
        DispatchQueue.main.async { [weak self] in
            guard let self, self.teardownPublication == publication, self.active == nil else { return }
            self.teardownPublication = nil
            if self.isDragging { self.isDragging = false }
        }
    }
}

/// The original SwiftUI button remains the accessibility action. This overlay
/// only owns the title's unmodified primary mouse sequence.
@MainActor private struct WorkspaceTabNativeDragSource: NSViewRepresentable {
    let tabID: UUID
    let owner: WorkspaceTabDragOwner
    let order: () -> [UUID]
    let select: () -> Void
    func makeNSView(context: Context) -> WorkspaceTabDragSourceView { let view = WorkspaceTabDragSourceView(); update(view); return view }
    func updateNSView(_ view: WorkspaceTabDragSourceView, context: Context) { update(view) }
    private func update(_ view: WorkspaceTabDragSourceView) { view.tabID = tabID; view.owner = owner; view.order = order; view.select = select }
    static func dismantleNSView(_ view: WorkspaceTabDragSourceView, coordinator: ()) { view.dispose() }
}

@MainActor final class WorkspaceTabDragSourceView: NSView {
    var tabID: UUID? { didSet { if oldValue != tabID { cancelTracking(duringTeardown: true) } } }
    weak var owner: WorkspaceTabDragOwner? { didSet { if oldValue !== owner { cancelTracking(duringTeardown: true) } } }
    var order: (() -> [UUID])?
    var select: (() -> Void)?
    private var pressedAt: NSPoint?
    private weak var pressWindow: NSWindow?
    private weak var pressOwner: WorkspaceTabDragOwner?
    private var pressTabID: UUID?
    private var pressOrder: [UUID] = []
    private var pressSelect: (() -> Void)?
    private var payload: Data?
    private(set) var dragLeaseID: UUID?
    private var pressIdentity = UUID()
    private var ownsDragFocus = false
    private weak var previousResponder: NSResponder?
    private var pendingFocusRestore: (identity: UUID, action: @MainActor () -> Void)?
    private weak var highlightedTarget: WorkspaceTabDropView?
    private var windowResignObserver: NSObjectProtocol?
    override var acceptsFirstResponder: Bool { dragLeaseID != nil }
    private func ownsPrimary(_ event: NSEvent) -> Bool {
        guard [.leftMouseDown, .leftMouseDragged, .leftMouseUp].contains(event.type),
              let window, event.window === window, window.attachedSheet == nil,
              NSApp.modalWindow == nil, !isHiddenOrHasHiddenAncestor else { return false }
        return true
    }
    private func pressIsCurrent(_ event: NSEvent) -> Bool {
        guard pressedAt != nil, ownsPrimary(event), let pressWindow, window === pressWindow,
              let pressOwner, owner === pressOwner, tabID == pressTabID, order?() == pressOrder else { return false }
        return dragLeaseID == nil || pressOwner.activeLeaseID == dragLeaseID
    }
    override func hitTest(_ point: NSPoint) -> NSView? {
        guard owner != nil, tabID != nil, let event = NSApp.currentEvent, ownsPrimary(event),
              event.modifierFlags.intersection([.command, .control, .option, .shift]).isEmpty,
              bounds.intersection(visibleRect).contains(convert(point, from: superview)) else { return nil }
        return self
    }
    override func mouseDown(with event: NSEvent) {
        // Settle the prior input before a new drag can mistake this source for it.
        let pendingRestore = pendingFocusRestore?.action
        pendingRestore?()
        cancelTracking()
        pressIdentity = UUID()
        guard ownsPrimary(event), event.modifierFlags.intersection([.command, .control, .option, .shift]).isEmpty,
              bounds.intersection(visibleRect).contains(convert(event.locationInWindow, from: nil)),
              let window, let owner, let tabID, let order = order?(), order.contains(tabID) else {
            return
        }
        pressedAt = event.locationInWindow; pressWindow = window; pressOwner = owner
        pressTabID = tabID; pressOrder = order; pressSelect = select
    }
    override func mouseDragged(with event: NSEvent) {
        guard pressIsCurrent(event), let start = pressedAt, let window = pressWindow, let owner = pressOwner, let tabID = pressTabID else {
            cancelTracking(); return
        }
        if dragLeaseID == nil {
            guard hypot(event.locationInWindow.x - start.x, event.locationInWindow.y - start.y) >= 4 else { return }
            guard event.modifierFlags.intersection([.command, .control, .option, .shift]).isEmpty,
                  (window.firstResponder as? any NSTextInputClient)?.hasMarkedText() != true,
                  let data = owner.begin(tabID: tabID, order: pressOrder), let leaseID = owner.activeLeaseID else {
                cancelTracking(); return
            }
            payload = data; dragLeaseID = leaseID; previousResponder = window.firstResponder
            let acquired = window.makeFirstResponder(self), responderIsSource = window.firstResponder === self
            guard acquired, responderIsSource, dragLeaseID == leaseID else { cancelTracking(); return }
            ownsDragFocus = true
            windowResignObserver = NotificationCenter.default.addObserver(forName: NSWindow.didResignKeyNotification, object: window, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.cancelTracking(leaseID: leaseID, duringTeardown: true)
                }
            }
        }
        guard let leaseID = dragLeaseID else { return }
        let target = owner.target(at: event.locationInWindow, in: window)
        setHighlight(target.flatMap { owner.canAccept(payload, leaseID: leaseID, order: pressOrder, before: $0.before) ? $0 : nil })
    }
    override func mouseUp(with event: NSEvent) {
        guard pressedAt != nil else { return }
        if dragLeaseID == nil {
            let action = pressIsCurrent(event) && event.modifierFlags.intersection([.command, .control, .option, .shift]).isEmpty
                && bounds.intersection(visibleRect).contains(convert(event.locationInWindow, from: nil)) ? pressSelect : nil
            clearTracking(duringTeardown: false); action?(); return
        }
        guard pressIsCurrent(event), let owner = pressOwner, let window = pressWindow, let leaseID = dragLeaseID,
              let payload, let target = owner.target(at: event.locationInWindow, in: window), let move = target.move,
              owner.canAccept(payload, leaseID: leaseID, order: pressOrder, before: target.before) else {
            cancelTracking(); return
        }
        let before = target.before, originalOrder = pressOrder, originalTab = pressTabID, responder = previousResponder, identity = pressIdentity
        clearTracking(duringTeardown: false)
        defer { if pressIdentity == identity { restoreFocus(in: window, previous: responder) } }
        let consumed = owner.consume(payload, leaseID: leaseID, order: originalOrder, before: before)
        guard let id = consumed,
              self.owner === owner, self.window === window, self.tabID == originalTab, order?() == originalOrder,
              window.attachedSheet == nil, NSApp.modalWindow == nil else { return }
        move(id, before)
    }
    override func keyDown(with event: NSEvent) {
        guard dragLeaseID != nil else { super.keyDown(with: event); return }
        if event.keyCode == 53 { cancelOperation(nil) }
    }
    override func cancelOperation(_ sender: Any?) { cancelTracking() }
    override func resignFirstResponder() -> Bool {
        cancelTracking(duringTeardown: true)
        return super.resignFirstResponder()
    }
    func cancelTracking(leaseID expected: UUID? = nil, duringTeardown: Bool = false) {
        if let expected, dragLeaseID != expected { return }
        let owner = pressOwner, leaseID = dragLeaseID, window = pressWindow, responder = previousResponder
        let identity = pressIdentity, restoresFocus = ownsDragFocus && window?.firstResponder === self
        clearTracking(duringTeardown: duringTeardown)
        owner?.sessionEnded(leaseID, duringTeardown: duringTeardown)
        if restoresFocus, let window, pressIdentity == identity {
            if duringTeardown {
                let restore: @MainActor () -> Void = { [weak self, weak window, weak responder] in
                    guard let self, self.pressIdentity == identity, self.pendingFocusRestore?.identity == identity else { return }
                    self.pendingFocusRestore = nil
                    guard let window, self.pressedAt == nil, self.dragLeaseID == nil else { return }
                    self.restoreFocus(in: window, previous: responder)
                }
                pendingFocusRestore = (identity, restore)
                DispatchQueue.main.async { [weak self] in
                    guard let self, self.pendingFocusRestore?.identity == identity else { return }
                    let action = self.pendingFocusRestore?.action
                    action?()
                }
            } else { restoreFocus(in: window, previous: responder) }
        }
    }
    private func setHighlight(_ target: WorkspaceTabDropView?) {
        if highlightedTarget === target { return }
        highlightedTarget?.setHighlighted(false); highlightedTarget = target; target?.setHighlighted(true)
    }
    private func clearTracking(duringTeardown: Bool) {
        highlightedTarget?.setHighlighted(false, redraw: !duringTeardown); highlightedTarget = nil
        if let windowResignObserver { NotificationCenter.default.removeObserver(windowResignObserver) }
        windowResignObserver = nil
        pressedAt = nil; pressWindow = nil; pressOwner = nil; pressTabID = nil; pressOrder = []; pressSelect = nil
        payload = nil; dragLeaseID = nil; ownsDragFocus = false; previousResponder = nil
    }
    private func restoreFocus(in window: NSWindow, previous: NSResponder?) {
        guard self.window === window, window.firstResponder === self, window.attachedSheet == nil, NSApp.modalWindow == nil else { return }
        if let view = previous as? NSView, view !== self, view.window === window, !view.isHiddenOrHasHiddenAncestor { _ = window.makeFirstResponder(view) }
        else { _ = window.makeFirstResponder(nil) }
    }
    override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); if window !== pressWindow { cancelTracking(duringTeardown: true) } }
    func dispose() { cancelTracking(duringTeardown: true); owner = nil; order = nil; select = nil }
}

@MainActor private struct WorkspaceTabNativeDropTarget: NSViewRepresentable {
    let owner: WorkspaceTabDragOwner
    let before: UUID?
    let order: () -> [UUID]
    let move: (UUID, UUID?) -> Void
    func makeNSView(context: Context) -> WorkspaceTabDropView { let view = WorkspaceTabDropView(); update(view); return view }
    func updateNSView(_ view: WorkspaceTabDropView, context: Context) { update(view) }
    private func update(_ view: WorkspaceTabDropView) { view.owner = owner; view.before = before; view.order = order; view.move = move }
    static func dismantleNSView(_ view: WorkspaceTabDropView, coordinator: ()) { view.dispose() }
}

/// Passive geometry only: never intercept a click or register an OS drag type.
@MainActor final class WorkspaceTabDropView: NSView {
    weak var owner: WorkspaceTabDragOwner? {
        didSet { if oldValue !== owner { oldValue?.unregister(self); owner?.register(self) } }
    }
    var before: UUID?
    var order: (() -> [UUID])?
    var move: ((UUID, UUID?) -> Void)?
    private(set) var isHighlighted = false
    override var acceptsFirstResponder: Bool { false }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
    fileprivate func setHighlighted(_ value: Bool, redraw: Bool = true) {
        guard isHighlighted != value else { return }
        isHighlighted = value
        if redraw { needsDisplay = true }
    }
    override func draw(_ dirtyRect: NSRect) {
        guard isHighlighted else { return }
        NSColor.controlAccentColor.setFill()
        NSBezierPath(rect: NSRect(x: bounds.minX, y: bounds.minY + 4, width: 2, height: max(0, bounds.height - 8))).fill()
    }
    fileprivate func dispose() { owner = nil; order = nil; move = nil; setHighlighted(false, redraw: false) }
}

struct WorkspaceTabBar: View {
    let model: AppModel
    private let sessions: SessionController
    private let files: FilesController
    @State private var chooser: ConnectionChooserPresentation?
    @State private var batchClose = SessionBatchCloseOwner()
    @State private var renamePresentation: TabRenamePresentation?
    @StateObject private var tabDrag = WorkspaceTabDragOwner()
    @State private var tabContentWidth: CGFloat?
    @State private var viewport: WorkspaceTabViewport?
    @State private var tabFrames: [UUID: CGRect] = [:]
    @State private var hoveredFixedID: String?
    @FocusState private var focusedFixedID: String?
    private let windowChrome: WorkspaceWindowChromeState
    init(model: AppModel, windowChrome: WorkspaceWindowChromeState? = nil) {
        self.model = model; sessions = model.sessions; files = model.files
        self.windowChrome = windowChrome ?? WorkspaceWindowChromeState()
    }
    var body: some View {
        HStack(spacing: 4) {
            fixedTab("保险箱", icon: "tray.full", page: .vault, id: "workspace.vault")
            fixedTab("SFTP", icon: "folder", page: .sftp, id: "workspace.sftp")
            Divider().padding(.vertical, 10)
            GeometryReader { space in
                HStack(spacing: 4) {
                    if !sessions.tabs.isEmpty {
                        sessionStrip(maximumWidth: max(0, space.size.width - newConnectionSize - 4))
                    }
                    Button { chooser = ConnectionChooserPresentation() } label: {
                        Image(systemName: "plus")
                            .frame(width: newConnectionSize, height: newConnectionSize)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain).help("新连接（⌘T）").accessibilityLabel("新连接")
                    .accessibilityIdentifier("workspace.new").workspaceChromeControl()
                }
                .frame(maxHeight: .infinity)
            }
            if files.hasActiveTransfers || !files.transferSnapshot.jobs.isEmpty {
                Button { model.showTransferTasks() } label: {
                    Label("\(files.transferSnapshot.jobs.filter { $0.state.isActive }.count)", systemImage: "arrow.up.arrow.down")
                }.buttonStyle(.borderless).help("传输任务").accessibilityIdentifier("workspace.transfers").workspaceChromeControl()
            }
        }
        .padding(.leading, windowChrome.leadingInset).padding(.trailing, 8).frame(height: DesktopStyle.barHeight)
        .foregroundStyle(DesktopStyle.barForeground)
        .background(model.workspacePage.sessionID != nil ? DesktopStyle.terminalChrome : DesktopStyle.managementBar)
        .coordinateSpace(name: "workspace.window.chrome")
        .onPreferenceChange(WorkspaceChromeInteractiveFrames.self) { windowChrome.interactiveFrames = $0 }
        .overlay(WorkspaceWindowDragRegion(state: windowChrome).accessibilityHidden(true))
        .onDisappear { tabDrag.invalidateForTeardown() }
        .onChange(of: sessions.tabs.map(\.id)) { _, _ in tabDrag.invalidate() }
        .nativeSheet(item: $chooser) { _ in ConnectionChooser(model: model) { chooser = nil } }
        .nativeSheet(item: $renamePresentation) { value in
            TabRenameView(controller: sessions, presentation: value) { if renamePresentation?.id == value.id { renamePresentation = nil } }
        }
        .nativeSheet(item: Binding(get: { batchClose.review }, set: { if $0 == nil, let id = batchClose.review?.id { batchClose.cancel(id) } }),
                     onAttemptDismiss: { !batchClose.inFlight }) { review in
            SessionBatchCloseView(controller: sessions, owner: batchClose, review: review)
        }
        .onChange(of: model.workspaceCommand) { _, request in
            guard let request else { return }
            if request.command == .newConnection { chooser = ConnectionChooserPresentation() }
            if request.command == .connectionInfo, let tab = sessions.selectedTab, model.workspacePage.sessionID == tab.id { showConnectionInfo(tab) }
        }
    }
    private let newConnectionSize: CGFloat = 30
    private func sessionStrip(maximumWidth: CGFloat) -> some View {
        // Measure the entire row inside the scroll view so showing the arrows
        // does not reduce the width used to decide whether they are needed.
        let needsArrows = (tabContentWidth ?? .infinity) > maximumWidth
        return ScrollViewReader { proxy in
            HStack(spacing: 2) {
                if needsArrows { overflowButton(forwards: false, proxy: proxy) }
                ScrollView(.horizontal) {
                    HStack(spacing: 4) {
                        ForEach(sessions.tabs) { tab in
                            WorkspaceSessionTab(tab: tab, controller: sessions, dragOwner: tabDrag, order: { sessions.tabs.map(\.id) }, active: model.workspacePage == .session(tab.id), terminalTheme: model.workspacePage.sessionID != nil, splitAxis: sessions.split?.contains(tab.id) == true ? sessions.split?.axis : nil, splitActive: sessions.activeSplit?.contains(tab.id) == true, select: { model.showWorkspace(.session(tab.id)); if sessions.isSplitActive { tab.focusTerminal() } }, close: { Task { await sessions.closeTab(tab.id) } })
                                .workspaceChromeControl()
                                .id(tab.id)
                                .background(GeometryReader { geometry in Color.clear.preference(key: WorkspaceTabFrames.self, value: [tab.id: geometry.frame(in: .named("workspace.session.strip"))]) })
                                .overlay(tabDropTarget(before: tab.id))
                                .contextMenu {
                                    Button("连接信息") { showConnectionInfo(tab) }
                                    Button("重命名当前标签…") { renamePresentation = TabRenamePresentation(tab: tab) }
                                    Divider()
                                    Button("左右分屏显示") { splitFromTabMenu(tab, axis: .horizontal) }
                                        .disabled(tab.id == sessions.selectedTabID && tab.host == nil)
                                    Button("上下分屏显示") { splitFromTabMenu(tab, axis: .vertical) }
                                        .disabled(tab.id == sessions.selectedTabID && tab.host == nil)
                                    if sessions.isSplitActive {
                                        Button("取消分屏") { sessions.unsplit() }
                                    }
                                    Divider()
                                    Button("断开") { sessions.disconnect(tab.id) }.disabled(!tab.isReusable)
                                    Button("重新连接") { sessions.reconnect(tab.id) }.disabled(!tab.canReconnect)
                                    Divider()
                                    Button("关闭") { Task { await sessions.closeTab(tab.id) } }
                                    Button("关闭其他会话…") { requestClose(.otherSessions(tab.id)) }.disabled(sessions.tabs.count < 2 || batchClose.review != nil)
                                    Button("关闭右侧会话…") { requestClose(.sessionsToRight(tab.id)) }.disabled(sessions.tabs.last?.id == tab.id || batchClose.review != nil)
                                }
                        }
                        Text(tabDrag.isDragging ? "末尾" : "").font(.caption)
                            .frame(width: tabDrag.isDragging ? 54 : 18, height: 34)
                            .background(tabDrag.isDragging ? DesktopStyle.managementActive : .clear, in: RoundedRectangle(cornerRadius: 8))
                            .contentShape(Rectangle()).accessibilityHidden(true)
                            .overlay(tabDropTarget(before: nil))
                    }
                    .coordinateSpace(name: "workspace.session.strip")
                    .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { tabContentWidth = $0 }
                }
                .scrollIndicators(.hidden)
                .onScrollGeometryChange(for: WorkspaceTabViewport.self) { geometry in
                    WorkspaceTabViewport(visibleRect: geometry.visibleRect, contentWidth: geometry.contentSize.width)
                } action: { _, value in viewport = value }
                .onPreferenceChange(WorkspaceTabFrames.self) { value in tabFrames = value; revealActive(using: proxy, frames: value) }
                .onChange(of: model.workspacePage) { _, _ in revealActive(using: proxy) }
                .onChange(of: sessions.tabs.map(\.id)) { _, _ in revealActive(using: proxy) }
                .onChange(of: viewport?.visibleRect.size) { _, _ in revealActive(using: proxy) }
                .frame(maxWidth: .infinity)
                if needsArrows { overflowButton(forwards: true, proxy: proxy) }
            }
        }
        .frame(width: min(maximumWidth, tabContentWidth ?? maximumWidth))
    }
    private func fixedTab(_ title: String, icon: String, page: WorkspacePage, id: String) -> some View {
        Button { model.showWorkspace(page) } label: {
            Label(title, systemImage: icon).font(.system(size: 13, weight: model.workspacePage == page ? .semibold : .regular))
                .frame(minWidth: 90, minHeight: 34)
                .background(model.workspacePage == page ? DesktopStyle.activeTab(terminal: model.workspacePage.sessionID != nil)
                            : (hoveredFixedID == id ? DesktopStyle.hoverTab(terminal: model.workspacePage.sessionID != nil) : .clear),
                            in: RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius))
                .overlay(RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius).stroke(focusedFixedID == id ? DesktopStyle.barForeground : .clear, lineWidth: 1).allowsHitTesting(false))
        }.buttonStyle(.plain).fixedSize(horizontal: true, vertical: false).focused($focusedFixedID, equals: id)
            .onHover { hoveredFixedID = $0 ? id : (hoveredFixedID == id ? nil : hoveredFixedID) }
            .accessibilityIdentifier(id).accessibilityAddTraits(model.workspacePage == page ? .isSelected : []).workspaceChromeControl()
    }
    private func tabDropTarget(before target: UUID?) -> some View {
        WorkspaceTabNativeDropTarget(owner: tabDrag, before: target, order: { sessions.tabs.map(\.id) }, move: { sessions.moveTab($0, before: $1) })
            .accessibilityHidden(true)
    }
    private func overflowButton(forwards: Bool, proxy: ScrollViewProxy) -> some View {
        WorkspaceOverflowButton(forwards: forwards, enabled: forwards ? viewport?.canGoForward == true : viewport?.canGoBack == true) {
            if let id = viewport?.navigationTarget(in: sessions.tabs.map(\.id), frames: tabFrames, forwards: forwards) {
                proxy.scrollTo(id, anchor: forwards ? .trailing : .leading)
            }
        }.frame(width: 24, height: 32).workspaceChromeControl()
    }
    private func revealActive(using proxy: ScrollViewProxy, frames: [UUID: CGRect]? = nil) {
        guard let id = model.workspacePage.sessionID, let viewport, let frame = (frames ?? tabFrames)[id], !viewport.contains(frame) else { return }
        proxy.scrollTo(id, anchor: frame.minX < viewport.visibleRect.minX ? .leading : .trailing)
    }
    private func requestClose(_ scope: SessionBatchCloseReview.Scope) {
        guard batchClose.review == nil, let review = sessions.batchCloseReview(scope: scope) else { return }
        if sessions.currentActiveCount(in: review) > 0 { batchClose.present(review) }
        else { Task { for id in review.tabIDs { await sessions.closeTab(id) } } }
    }
    private func splitFromTabMenu(_ tab: SessionTab, axis: TerminalSplitAxis) {
        if model.workspacePage.sessionID == nil, let anchor = sessions.selectedTabID ?? Optional(tab.id) {
            model.showWorkspace(.session(anchor))
        }
        guard model.workspacePage.sessionID != nil else { return }
        if tab.id != sessions.selectedTabID {
            sessions.splitWithTab(tab.id, axis: axis)
        } else {
            sessions.splitCurrentSession(axis: axis)
        }
    }
    private func showConnectionInfo(_ tab: SessionTab) {
        guard let window = NSApp.mainWindow, window.attachedSheet == nil else { return }
        let alert = NSAlert(); alert.messageText = sessions.displayTitle(for: tab)
        alert.informativeText = sessions.connectionInfo(for: tab)
        alert.addButton(withTitle: "关闭"); NativeSheetCloseRouting.register(alert); alert.beginSheetModal(for: window)
    }
}

private struct WorkspaceChromeInteractiveFrames: PreferenceKey {
    static let defaultValue: [CGRect] = []
    static func reduce(value: inout [CGRect], nextValue: () -> [CGRect]) { value.append(contentsOf: nextValue()) }
}
private extension View {
    func workspaceChromeControl() -> some View {
        background(GeometryReader { geometry in
            Color.clear.preference(key: WorkspaceChromeInteractiveFrames.self,
                                   value: [geometry.frame(in: .named("workspace.window.chrome"))])
        })
    }
}

private struct WorkspaceOverflowButton: NSViewRepresentable {
    let forwards: Bool
    let enabled: Bool
    let action: () -> Void
    func makeCoordinator() -> Coordinator { Coordinator(action: action) }
    func makeNSView(context: Context) -> NSButton {
        let button = NSButton(image: NSImage(systemSymbolName: forwards ? "chevron.right" : "chevron.left", accessibilityDescription: nil)!, target: context.coordinator, action: #selector(Coordinator.press))
        button.isBordered = false; button.imagePosition = .imageOnly
        button.contentTintColor = NSColor(sessionHex: "#E4E8ED")
        update(button, coordinator: context.coordinator); return button
    }
    func updateNSView(_ button: NSButton, context: Context) { update(button, coordinator: context.coordinator) }
    private func update(_ button: NSButton, coordinator: Coordinator) {
        coordinator.action = action; button.isEnabled = enabled
        button.identifier = NSUserInterfaceItemIdentifier(forwards ? "workspace.tabs.forward" : "workspace.tabs.back")
        button.toolTip = forwards ? "向右浏览会话标签" : "向左浏览会话标签"
        button.setAccessibilityLabel(button.toolTip); button.setAccessibilityIdentifier(button.identifier?.rawValue)
    }
    @MainActor final class Coordinator: NSObject {
        var action: () -> Void
        init(action: @escaping () -> Void) { self.action = action }
        @objc func press() { action() }
    }
}

private struct WorkspaceTabFrames: PreferenceKey {
    static let defaultValue: [UUID: CGRect] = [:]
    static func reduce(value: inout [UUID: CGRect], nextValue: () -> [UUID: CGRect]) { value.merge(nextValue(), uniquingKeysWith: { _, new in new }) }
}
private struct TabMiddleClickTarget: NSViewRepresentable {
    let tabID: UUID
    let close: () -> Void
    func makeNSView(context: Context) -> WorkspaceTabMiddleClickView {
        let view = WorkspaceTabMiddleClickView(); view.closeAction = close
        view.identifier = NSUserInterfaceItemIdentifier("tab.middle." + tabID.uuidString)
        return view
    }
    func updateNSView(_ view: WorkspaceTabMiddleClickView, context: Context) { view.closeAction = close }
}

private struct WorkspaceSessionTab: View {
    let tab: SessionTab
    let controller: SessionController
    let dragOwner: WorkspaceTabDragOwner
    let order: () -> [UUID]
    let active: Bool
    let terminalTheme: Bool
    let splitAxis: TerminalSplitAxis?
    let splitActive: Bool
    let select: () -> Void
    let close: () -> Void
    @State private var hovered = false
    @FocusState private var focusedAction: FocusAction?
    private enum FocusAction: Hashable { case select, close }
    private var shortStatus: String {
        switch tab.state {
        case .preparing, .connectionPending: "连接中"
        case .awaitingTrust: "核对身份"
        case .authenticating: "等待认证"
        case .connected: "已连接"
        case .closing: "关闭中"
        case .failed: "连接失败"
        default: "已断开"
        }
    }
    private var statusLabel: String {
        shortStatus + (tab.displayMetadata.isDeleted ? " · 配置已删" : (tab.configurationChanged ? " · 配置已改" : ""))
    }
    private var helpText: String {
        let endpoint = tab.host.map { $0.username + "@" + $0.vaultEndpoint } ?? ""
        return [controller.displayTitle(for: tab), endpoint, tab.status,
                tab.displayMetadata.configurationNotice(actual: tab.host), "中键关闭此标签"].joined(separator: "\n")
    }
    private var statusDotColor: Color {
        switch tab.state {
        case .connected: DesktopStyle.statusGreen
        case .preparing, .connectionPending, .awaitingTrust, .authenticating: DesktopStyle.statusAmber
        case .failed: DesktopStyle.statusRed
        default: DesktopStyle.barSecondary.opacity(0.55)
        }
    }
    private var titleContent: some View {
        HStack(spacing: 7) {
            Image(systemName: tab.authentication != nil || !tab.trust.isEmpty ? "exclamationmark.bubble" : (tab.isReusable ? "terminal" : "stop.circle"))
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(tab.authentication != nil || !tab.trust.isEmpty ? DesktopStyle.statusAmber : DesktopStyle.barForeground.opacity(0.9))
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 3) {
                    if tab.displayMetadata.isFavorite { Image(systemName: "star.fill").font(.caption2).foregroundStyle(DesktopStyle.statusAmber).accessibilityLabel("收藏") }
                    Text(controller.displayTitle(for: tab))
                        .font(.system(size: 12, weight: active ? .semibold : .medium))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if let splitAxis {
                        Image(systemName: splitAxis == .horizontal ? "rectangle.split.2x1" : "rectangle.split.1x2")
                            .font(.system(size: 10, weight: .medium))
                            .foregroundStyle(splitActive ? Color.accentColor : DesktopStyle.barSecondary.opacity(0.75))
                            .accessibilityLabel("已分屏")
                    }
                }
                HStack(spacing: 4) {
                    Circle()
                        .fill(statusDotColor)
                        .frame(width: 5, height: 5)
                    Text(statusLabel)
                        .font(.system(size: 9))
                        .foregroundStyle(DesktopStyle.barSecondary.opacity(0.9))
                        .lineLimit(1)
                }
            }
        }.frame(width: 174, height: 34, alignment: .leading)
    }
    var body: some View {
        HStack(spacing: 6) {
            Button(action: select) { titleContent }
                .buttonStyle(.plain).focused($focusedAction, equals: .select).accessibilityIdentifier("tab.select." + tab.id.uuidString)
                .accessibilityAddTraits(active ? .isSelected : [])
                .overlay(WorkspaceTabNativeDragSource(tabID: tab.id, owner: dragOwner, order: order, select: select).accessibilityHidden(true))
            Button(action: close) { Image(systemName: "xmark").font(.system(size: 10, weight: .semibold)).frame(width: 24, height: 28) }
                .buttonStyle(.plain).focused($focusedAction, equals: .close).accessibilityLabel("关闭 " + controller.displayTitle(for: tab)).accessibilityIdentifier("tab.close." + tab.id.uuidString)
        }.padding(.leading, 10).padding(.trailing, 2).fixedSize()
        .background(active ? DesktopStyle.activeTab(terminal: terminalTheme) : (hovered ? DesktopStyle.hoverTab(terminal: terminalTheme) : .clear), in: RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius))
        .overlay(
            RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius)
                .stroke(focusedAction != nil ? DesktopStyle.barForeground : (active ? Color.white.opacity(0.14) : (hovered ? Color.white.opacity(0.08) : .clear)), lineWidth: 1)
                .allowsHitTesting(false)
        )
        .onHover { hovered = $0 }
        .overlay(TabMiddleClickTarget(tabID: tab.id, close: close).accessibilityHidden(true))
        .help(helpText)
        .accessibilityValue(tab.status + (tab.displayMetadata.isDeleted ? "；保存配置已删除" : ""))
    }
}

@MainActor private struct TabRenamePresentation: Identifiable {
    let id = UUID()
    let tabID: UUID
    let originalTitle: String
    let endpoint: String
    init(tab: SessionTab) {
        tabID = tab.id; originalTitle = tab.displayName
        endpoint = tab.host.map { $0.username + "@" + $0.vaultEndpoint } ?? "实际端点不可用"
    }
}
private struct TabRenameView: View {
    let controller: SessionController
    let presentation: TabRenamePresentation
    let dismiss: () -> Void
    @State private var title: String
    @FocusState private var focused: Bool
    init(controller: SessionController, presentation: TabRenamePresentation, dismiss: @escaping () -> Void) {
        self.controller = controller; self.presentation = presentation; self.dismiss = dismiss
        _title = State(initialValue: presentation.originalTitle)
    }
    private var exists: Bool { controller.tabs.contains { $0.id == presentation.tabID } }
    private var valid: Bool { VaultHostDraft.validText(title.trimmingCharacters(in: .whitespacesAndNewlines), limit: 256) }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("重命名当前标签").font(.title3).bold()
            Text(presentation.originalTitle + " · " + presentation.endpoint).font(.caption).textSelection(.enabled)
            Text("仅修改这一个标签，不修改保存主机、实际连接或其他同名会话。").font(.caption).foregroundStyle(.secondary)
            TextField("标签名称", text: $title).textFieldStyle(.roundedBorder).focused($focused).onSubmit(save)
                .accessibilityIdentifier("tab.rename.name")
            if !valid { Text("名称必填，最多 256 UTF-8 字节，不含控制字符。").font(.caption).foregroundStyle(.secondary) }
            if !exists { Text("原标签已关闭；不会重命名其他标签。").font(.caption).foregroundStyle(.secondary) }
            HStack { Spacer(); Button("取消", action: dismiss).keyboardShortcut(.cancelAction); Button("保存", action: save).disabled(!valid || !exists).keyboardShortcut(.defaultAction) }
        }.padding(24).frame(width: 440).onAppear { focused = true }
    }
    private func save() { guard valid, exists else { return }; controller.renameTab(presentation.tabID, title: title); dismiss() }
}
private struct SessionBatchCloseView: View {
    let controller: SessionController
    let owner: SessionBatchCloseOwner
    let review: SessionBatchCloseReview
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(review.scope.title + "（\(review.entries.count) 个）？").font(.title3).bold()
            Text("范围在打开审核时已锁定为下面的 SSH 标签。后来新建或移动的标签不会加入；已关闭的目标会跳过。保险箱、SFTP 与传输不受影响。").fixedSize(horizontal: false, vertical: true)
            Text("当前仍有 \(controller.currentActiveCount(in: review)) 个目标处于连接中、等待输入或已连接；状态会实时更新。").font(.caption).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(review.entries) { entry in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(entry.title).bold()
                            Text(entry.endpoint).textSelection(.enabled)
                            Text("审核时：" + entry.status)
                            Text("现在：" + controller.currentBatchCloseStatus(entry.id))
                            Text("标签 ID：" + entry.id.uuidString).font(.caption2).foregroundStyle(.secondary)
                        }.font(.caption).frame(maxWidth: .infinity, alignment: .leading)
                        Divider()
                    }
                }
            }.frame(maxHeight: 220)
            Text("确认仅断开所列外层 SSH；远端任务是否继续由远端程序决定。").font(.caption).foregroundStyle(.secondary)
            HStack {
                if owner.inFlight { ProgressView().controlSize(.small); Text("正在关闭所列标签…").font(.caption) }
                Spacer()
                Button("取消") { owner.cancel(review.id) }.keyboardShortcut(.cancelAction).disabled(owner.inFlight)
                Button("关闭所列会话", role: .destructive) {
                    guard let ids = owner.beginConfirmation(review.id) else { return }
                    Task { for id in ids { await controller.closeTab(id) }; owner.finish(review.id) }
                }.disabled(owner.inFlight || owner.review?.id != review.id)
            }
        }.padding(24).frame(width: 560)
    }
}

private struct ConnectionChooser: View {
    let model: AppModel
    @State private var search = ""
    let dismiss: () -> Void
    private var hosts: [HostConfiguration] {
        model.connectionHosts.filter { search.isEmpty || [$0.name, $0.address, $0.username].contains(where: { $0.localizedStandardContains(search) }) }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "bolt.horizontal.circle.fill")
                    .font(.system(size: 18))
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 34, height: 34)
                    .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 9))
                VStack(alignment: .leading, spacing: 2) {
                    Text("新连接").font(.title3).bold()
                    Text("选择已有主机快速建立终端会话").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("新建主机…") { dismiss(); model.showWorkspace(.vault); model.sendWorkspaceCommand(.newHost) }
            }
            DesktopSearchField(placeholder: "搜索已有主机", id: "connection.search", text: $search)
            if model.connectionHosts.isEmpty {
                ContentUnavailableView("尚无主机", systemImage: "server.rack", description: Text("先创建主机配置，再建立连接。"))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if hosts.isEmpty {
                ContentUnavailableView.search(text: search)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(hosts) { host in hostRow(host) }
                    }
                }
            }
            HStack { Spacer(); Button("关闭", action: dismiss).keyboardShortcut(.cancelAction) }
        }.padding(24).frame(width: 620, height: 460).background(DesktopStyle.background)
    }

    private func hostRow(_ host: HostConfiguration) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "server.rack")
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(Color.accentColor)
                .frame(width: 32, height: 32)
                .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 3) {
                Text(host.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Text("\(host.username)@\(host.address):\(host.port)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Button("新会话") { model.requestSession(hostID: host.id, mode: .newSession); dismiss() }
            Button("连接") { model.requestSession(hostID: host.id, mode: .reuse); dismiss() }
                .buttonStyle(.borderedProminent)
        }
        .padding(12)
        .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.border))
    }
}
