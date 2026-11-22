import AppKit
import Observation
import SwiftUI
import OpenLXSSHCore

/// The native titlebar owns the real window buttons. The single content tab strip
/// draws through the transparent titlebar without an empty accessory intercepting it.
@MainActor enum WorkspaceWindowChrome {
    static func configure(_ window: NSWindow) {
        window.styleMask.insert(.fullSizeContentView)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.isMovableByWindowBackground = false
        window.backgroundColor = background(terminal: false)
    }

    static func background(terminal: Bool) -> NSColor {
        NSColor(sessionHex: terminal ? "#1B212E" : "#252D3D")
    }
}

@Observable @MainActor final class WorkspaceWindowChromeState {
    private(set) var leadingInset: CGFloat = 8
    private(set) var topSafeInset: CGFloat = 0
    private(set) var isIntegrated = false
    @ObservationIgnored var interactiveFrames: [CGRect] = []

    func update(leading: CGFloat, top: CGFloat) {
        if abs(leadingInset - leading) > 0.25 {
            leadingInset = leading
        }
        if abs(topSafeInset - top) > 0.25 {
            topSafeInset = top
        }
        if !isIntegrated {
            isIntegrated = true
        }
    }

    func canDrag(at point: NSPoint, in bounds: NSRect) -> Bool {
        isIntegrated
            && bounds.contains(point)
            && point.x >= leadingInset
            && !interactiveFrames.contains(where: { $0.contains(point) })
    }
}

struct WorkspaceWindowChromeAnchor: NSViewRepresentable {
    let state: WorkspaceWindowChromeState
    let terminal: Bool

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> WorkspaceChromeAnchorView {
        let view = WorkspaceChromeAnchorView()
        view.windowChanged = { [weak coordinator = context.coordinator] in
            coordinator?.schedule()
        }
        context.coordinator.anchor = view
        return view
    }

    func updateNSView(_ view: WorkspaceChromeAnchorView, context: Context) {
        context.coordinator.state = state
        context.coordinator.terminal = terminal
        context.coordinator.schedule()
    }

    static func dismantleNSView(_ view: WorkspaceChromeAnchorView, coordinator: Coordinator) {
        view.windowChanged = nil
        coordinator.close()
    }

    @MainActor final class Coordinator {
        weak var anchor: WorkspaceChromeAnchorView?
        weak var state: WorkspaceWindowChromeState?
        var terminal = false
        private weak var observedWindow: NSWindow?
        private var observers: [NSObjectProtocol] = []
        private var layoutObservation: NSKeyValueObservation?
        private var scheduled = false
        private var active = true

        func schedule() {
            guard active, !scheduled else { return }
            scheduled = true
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.scheduled = false
                guard self.active else { return }
                self.refresh()
            }
        }

        private func refresh() {
            guard let window = anchor?.window,
                  window.styleMask.contains(.fullSizeContentView),
                  window.titleVisibility == .hidden,
                  window.titlebarAppearsTransparent,
                  let content = window.contentView,
                  let state else { return }

            if observedWindow !== window {
                stopObserving()
                observedWindow = window
                let notifications: [Notification.Name] = [
                    NSWindow.didResizeNotification,
                    NSWindow.didBecomeKeyNotification,
                    NSWindow.didResignKeyNotification,
                    NSWindow.didEnterFullScreenNotification,
                    NSWindow.didExitFullScreenNotification,
                    NSWindow.didChangeScreenNotification
                ]
                for name in notifications {
                    let observer = NotificationCenter.default.addObserver(
                        forName: name,
                        object: window,
                        queue: .main
                    ) { [weak self] _ in
                        MainActor.assumeIsolated {
                            self?.schedule()
                        }
                    }
                    observers.append(observer)
                }
                layoutObservation = window.observe(\.contentLayoutRect, options: [.new]) { [weak self] _, _ in
                    Task { @MainActor [weak self] in
                        self?.schedule()
                    }
                }
            }

            let background = WorkspaceWindowChrome.background(terminal: terminal)
            if window.backgroundColor != background {
                window.backgroundColor = background
            }

            let fullScreen = window.styleMask.contains(.fullScreen)
            let topInset = fullScreen ? (window.screen?.safeAreaInsets.top ?? 0) : 0
            let contentRect = content.convert(content.bounds, to: nil)
            let buttons = [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton]
                .compactMap { window.standardWindowButton($0) }

            // Public standard buttons retain their native parent/actions/tracking.
            // Align them with the single content tab strip after native layout.
            if !fullScreen {
                for button in buttons {
                    guard let parent = button.superview else { continue }
                    let current = button.convert(button.bounds, to: nil)
                    let target = NSRect(
                        x: current.minX,
                        y: contentRect.maxY - DesktopStyle.barHeight / 2 - current.height / 2,
                        width: current.width,
                        height: current.height
                    )
                    let frame = parent.convert(target, from: nil)
                    if abs(frame.minY - button.frame.minY) > 0.25 {
                        button.setFrameOrigin(frame.origin)
                    }
                }
            }

            let controlsRight = buttons.map { $0.convert($0.bounds, to: nil).maxX - contentRect.minX }.max() ?? 0
            let safeLeft = content.safeAreaInsets.left
            state.update(leading: max(8 + safeLeft, controlsRight + 12), top: topInset)
        }

        private func stopObserving() {
            observers.forEach { NotificationCenter.default.removeObserver($0) }
            observers = []
            layoutObservation = nil
        }

        func close() {
            active = false
            stopObserving()
            observedWindow = nil
            anchor = nil
            state = nil
        }

        isolated deinit {
            stopObserving()
        }
    }
}

@MainActor final class WorkspaceChromeAnchorView: NSView {
    var windowChanged: (() -> Void)?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        windowChanged?()
    }

    override func layout() {
        super.layout()
        windowChanged?()
    }
}

struct WorkspaceWindowDragRegion: NSViewRepresentable {
    let state: WorkspaceWindowChromeState

    func makeNSView(context: Context) -> WorkspaceChromeDragView {
        let view = WorkspaceChromeDragView()
        view.state = state
        return view
    }

    func updateNSView(_ view: WorkspaceChromeDragView, context: Context) {
        view.state = state
    }

    static func dismantleNSView(_ view: WorkspaceChromeDragView, coordinator: ()) {
        view.state = nil
    }
}

@MainActor final class WorkspaceChromeDragView: NSView {
    weak var state: WorkspaceWindowChromeState?
    override var isFlipped: Bool { true }
    override var acceptsFirstResponder: Bool { false }

    override func hitTest(_ point: NSPoint) -> NSView? {
        guard NSApp.currentEvent?.type == .leftMouseDown,
              let window,
              window.attachedSheet == nil,
              NSApp.modalWindow == nil,
              state?.canDrag(at: convert(point, from: superview), in: bounds.intersection(visibleRect)) == true else {
            return nil
        }
        return self
    }

    override func mouseDown(with event: NSEvent) {
        guard event.type == .leftMouseDown,
              window?.attachedSheet == nil,
              NSApp.modalWindow == nil else { return }
        window?.performDrag(with: event)
    }
}

enum DesktopStyle {
    static let barHeight: CGFloat = 48
    static let spacing: CGFloat = 8
    static let cornerRadius: CGFloat = 8
    static let panel = adaptive(light: "#FFFFFF", dark: "#222936")
    static let panelElevated = adaptive(light: "#F8FAFC", dark: "#2A3342")
    static let well = adaptive(light: "#EEF1F6", dark: "#141922")
    static let background = adaptive(light: "#F5F7FA", dark: "#1A202B")
    static let sidebar = adaptive(light: "#ECEFF4", dark: "#151B24")
    static let border = adaptive(light: "#E2E6EE", dark: "#2F394A")
    static let borderStrong = adaptive(light: "#CFD6E3", dark: "#3D495E")
    static let separator = Color.primary.opacity(0.08)
    static let selection = Color.accentColor.opacity(0.13)
    static let iconSurface = Color.accentColor.opacity(0.11)
    static let managementBar = Color(nsColor: NSColor(sessionHex: "#252D3D"))
    static let managementActive = Color(nsColor: NSColor(sessionHex: "#434F65"))
    static let terminalBackground = Color(nsColor: NSColor(sessionHex: "#141821"))
    static let terminalChrome = Color(nsColor: NSColor(sessionHex: "#1B212E"))
    static let terminalActive = Color(nsColor: NSColor(sessionHex: "#2D374B"))
    static let barSecondary = Color(nsColor: NSColor(sessionHex: "#BBC3D6"))
    static let barForeground = Color(nsColor: NSColor(sessionHex: "#E4E8ED"))
    static let statusGreen = Color(nsColor: .systemGreen)
    static let statusAmber = Color(nsColor: .systemOrange)
    static let statusRed = Color(nsColor: .systemRed)

    private static func adaptive(light: String, dark: String) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            NSColor(sessionHex: appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light)
        })
    }

    static func activeTab(terminal: Bool) -> Color {
        terminal ? terminalActive : managementActive
    }

    static func hoverTab(terminal: Bool) -> Color {
        activeTab(terminal: terminal).opacity(0.55)
    }
}

struct DesktopSearchField: View {
    let placeholder: String
    let id: String
    @Binding var text: String
    var focusRequest: UUID? = nil
    var onFocus: (() -> Void)? = nil
    var clearLabel = "清除搜索"

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.secondary)
            NativeField(
                placeholder: placeholder,
                id: id,
                text: $text,
                focusRequest: focusRequest,
                onFocus: onFocus,
                borderless: true
            )
            .frame(height: 24)
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(clearLabel)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(DesktopStyle.border))
    }
}

struct DesktopKeyValueRow: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .foregroundStyle(.secondary)
                .layoutPriority(1)
            Spacer(minLength: 8)
            Text(verbatim: value)
                .font(monospaced ? .system(size: 12, design: .monospaced) : .system(size: 13))
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }
}

struct DesktopBadge: View {
    let text: String
    var color: Color = .secondary
    var fill: Color = DesktopStyle.separator

    var body: some View {
        Text(verbatim: text)
            .font(.system(size: 10, weight: .medium))
            .foregroundStyle(color)
            .lineLimit(1)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(fill, in: Capsule())
    }
}

struct IssueView: View {
    let issue: AppIssue?
    var dismiss: () -> Void

    var body: some View {
        if let issue {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 14))
                    .foregroundStyle(DesktopStyle.statusAmber)
                    .padding(.top, 1)
                VStack(alignment: .leading, spacing: 4) {
                    Text(issue.message)
                        .font(.system(size: 12, weight: .medium))
                        .fixedSize(horizontal: false, vertical: true)
                    DisclosureGroup("详情") {
                        Text(issue.code)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    .font(.caption)
                }
                Spacer(minLength: 8)
                NativeButton(title: "关闭", id: "issue.dismiss", action: dismiss).fixedSize()
            }
            .padding(10)
            .background(DesktopStyle.statusAmber.opacity(0.09), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(DesktopStyle.statusAmber.opacity(0.28)))
            .accessibilityIdentifier("app.error")
        }
    }
}

/// Own one AppKit sheet per presentation anchor. SwiftUI still owns the item and
/// editor state, while the coordinator closes only the NSWindow it presented.
/// This avoids losing nested sheet dismissal after an observed model reload.
extension View {
    func nativeSheet<Item: Identifiable, Content: View>(
        item: Binding<Item?>,
        isEnabled: Bool = true,
        allowsTerminationReview: Bool = false,
        onAttemptDismiss: (@MainActor () -> Bool)? = nil,
        @ViewBuilder content: @escaping (Item) -> Content
    ) -> some View {
        background(
            NativeSheetPresenter(
                item: item,
                isEnabled: isEnabled,
                allowsTerminationReview: allowsTerminationReview,
                onAttemptDismiss: onAttemptDismiss,
                content: content
            )
            .frame(width: 0, height: 0)
        )
    }
}

struct NativeSheetPresenter<Item: Identifiable, Content: View>: NSViewRepresentable {
    @Binding var item: Item?
    let isEnabled: Bool
    let allowsTerminationReview: Bool
    let onAttemptDismiss: (@MainActor () -> Bool)?
    let content: (Item) -> Content

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> SheetAnchorView {
        let view = SheetAnchorView()
        context.coordinator.attach(view)
        view.windowChanged = { [weak coordinator = context.coordinator] in
            coordinator?.windowChanged()
        }
        return view
    }

    func updateNSView(_ view: SheetAnchorView, context: Context) {
        // Read the item during SwiftUI's update so presentation-only state changes
        // invalidate this representable even when no observed model property changes.
        context.coordinator.update(
            value: item,
            item: $item,
            isEnabled: isEnabled,
            allowsTerminationReview: allowsTerminationReview,
            onAttemptDismiss: onAttemptDismiss,
            content: content
        )
    }

    static func dismantleNSView(_ view: SheetAnchorView, coordinator: Coordinator) {
        view.windowChanged = nil
        coordinator.close()
    }

    @MainActor final class Coordinator {
        private var item: Binding<Item?>?
        private var value: Item?
        private var content: ((Item) -> Content)?
        private weak var anchor: SheetAnchorView?
        private var sheet: NSWindow?
        private var hosting: NSHostingController<Content>?
        private var presentedID: Item.ID?
        private var scheduled = false
        private var active = true
        private var isEnabled = true
        private var allowsTerminationReview = false
        private var onAttemptDismiss: (@MainActor () -> Bool)?
        private var dismissing = false

        func update(
            value: Item?,
            item: Binding<Item?>,
            isEnabled: Bool,
            allowsTerminationReview: Bool = false,
            onAttemptDismiss: (@MainActor () -> Bool)?,
            content: @escaping (Item) -> Content
        ) {
            guard active else { return }
            self.value = value
            self.item = item
            self.isEnabled = isEnabled
            self.onAttemptDismiss = onAttemptDismiss
            self.content = content
            self.allowsTerminationReview = allowsTerminationReview
            schedule()
        }

        func attach(_ anchor: SheetAnchorView) {
            guard active else { return }
            self.anchor = anchor
            schedule()
        }

        func windowChanged() {
            schedule()
        }

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
            guard isEnabled, let value, let content else {
                dismissOwnedSheet()
                return
            }
            if sheet != nil {
                // An item ID denotes a fixed editor. Its Observed/StateObject updates
                // in place; replacing the root would reset that editor's local state.
                if presentedID != value.id {
                    dismissOwnedSheet()
                }
                return
            }
            // Focus/KVO can synchronously update a representable while its old
            // NSWindow is already deallocating. Never register a weak window
            // reference there. Resolve the living anchor's window only after the
            // existing MainActor turn has unwound that destruction traversal.
            guard let anchor, let parent = anchor.window, parent.isVisible else { return }
            let hosting = NSHostingController(rootView: content(value))
            let sheet = NativeOwnedSheetWindow(contentViewController: hosting)
            // Only presentations enrolled in the app's global review or cancellation flow opt in.
            // Other owned sheets retain AppKit's default termination protection.
            if allowsTerminationReview {
                sheet.preventsApplicationTerminationWhenModal = false
            }
            sheet.appearance = anchor.effectiveAppearance
            sheet.onAttemptDismiss = { [weak self] in
                guard let self, self.active, !self.dismissing else { return false }
                // Resolve the most recent closure, without replacing rootView or
                // the editor's State merely because its draft changed.
                return self.onAttemptDismiss?() ?? true
            }
            sheet.styleMask = [.titled]
            sheet.title = "OpenLXSSH"
            sheet.isReleasedWhenClosed = false
            self.hosting = hosting
            self.sheet = sheet
            self.presentedID = value.id

            parent.beginSheet(sheet) { [weak self, weak sheet] _ in
                guard let self, let sheet, self.sheet === sheet else { return }
                let id = self.presentedID
                self.sheet = nil
                self.hosting = nil
                self.presentedID = nil
                self.dismissing = false
                sheet.orderOut(nil)
                if self.active {
                    if self.item?.wrappedValue?.id == id {
                        self.item?.wrappedValue = nil
                    }
                    self.schedule()
                }
            }
        }

        private func dismissOwnedSheet() {
            guard let sheet, !dismissing else { return }
            dismissing = true
            if let parent = sheet.sheetParent {
                parent.endSheet(sheet)
            } else {
                sheet.orderOut(nil)
                self.sheet = nil
                hosting = nil
                presentedID = nil
                dismissing = false
                schedule()
            }
        }

        func close() {
            active = false
            dismissOwnedSheet()
            // A detached representable/coordinator can outlive its page in AppKit.
            // Permanent teardown must release every closure that captured that page,
            // including its dismiss handler, rather than awaiting coordinator deinit.
            sheet?.contentViewController = nil
            hosting = nil
            item = nil
            value = nil
            content = nil
            onAttemptDismiss = nil
            anchor = nil
        }
    }
}

@MainActor final class NativeOwnedSheetWindow: NSWindow {
    /// Return false to retain the editor. An async save/discard/cancel flow may
    /// be requested by this hook, then finish by clearing the owning item.
    var onAttemptDismiss: (@MainActor () -> Bool)?

    @discardableResult func attemptClose() -> Bool {
        guard onAttemptDismiss?() ?? true else { return false }
        if let sheetParent {
            sheetParent.endSheet(self, returnCode: .cancel)
        } else {
            super.performClose(nil)
        }
        return true
    }

    override func performClose(_ sender: Any?) {
        _ = attemptClose()
    }

    override func cancelOperation(_ sender: Any?) {
        _ = attemptClose()
    }
}

/// Only registered, app-owned NSAlerts may be ended by workspace commands.
/// Unknown sheets (including system authorization/open panels) are not touched.
@MainActor enum NativeSheetCloseRouting {
    private static let ownedAlertIdentifier = NSUserInterfaceItemIdentifier("OpenLXSSH.ownedAlert")
    private static let ownedAlertCancelCode: NSApplication.ModalResponse = .cancel

    static func register(_ alert: NSAlert) {
        alert.window.identifier = ownedAlertIdentifier
    }

    @discardableResult static func attemptClose(_ window: NSWindow) -> Bool {
        if let owned = window as? NativeOwnedSheetWindow {
            return owned.attemptClose()
        }
        guard window.identifier == ownedAlertIdentifier, let parent = window.sheetParent else { return false }
        parent.endSheet(window, returnCode: ownedAlertCancelCode)
        window.orderOut(nil)
        return true
    }
}

/// A page is mounted once. AppKit, rather than opacity, owns visibility and
/// responder isolation for native controls (including the shared field editor).
struct NativeWorkspacePage: NSViewRepresentable {
    let id: String
    let isVisible: Bool
    let appearance: NSAppearance.Name?
    let content: AnyView

    init<Content: View>(
        id: String,
        isVisible: Bool,
        appearance: NSAppearance.Name? = nil,
        @ViewBuilder content: () -> Content
    ) {
        self.id = id
        self.isVisible = isVisible
        self.appearance = appearance
        self.content = AnyView(content())
    }

    func makeNSView(context: Context) -> NativeWorkspacePageView {
        let view = NativeWorkspacePageView(content: content, appearance: appearance)
        view.identifier = NSUserInterfaceItemIdentifier(id)
        view.setPageVisible(isVisible)
        return view
    }

    func updateNSView(_ view: NativeWorkspacePageView, context: Context) {
        // Do not replace rootView on routing updates: its State and native views
        // belong to this page. ObservedObject subscriptions update it in place.
        view.setPageAppearance(appearance)
        view.setPageVisible(isVisible)
    }

    static func dismantleNSView(_ view: NativeWorkspacePageView, coordinator: ()) {
        view.dismantle()
    }
}

@Observable @MainActor private final class RetainedPageAppearance {
    var scheme: ColorScheme?

    init(_ appearance: NSAppearance.Name?) {
        scheme = appearance == .darkAqua ? .dark : appearance == .aqua ? .light : nil
    }
}

private struct RetainedPageRoot: View {
    let appearance: RetainedPageAppearance
    @Environment(\.colorScheme) private var inherited
    let content: AnyView

    var body: some View {
        content.environment(\.colorScheme, appearance.scheme ?? inherited)
    }
}

@MainActor final class NativeWorkspacePageView: NSView {
    private(set) var pageVisible = true
    private(set) var hostingView: NSHostingView<AnyView>?
    private(set) var isDismantled = false
    private var pageAppearance: RetainedPageAppearance?

    init(content: AnyView, appearance: NSAppearance.Name? = nil) {
        super.init(frame: .zero)
        self.appearance = appearance.flatMap { NSAppearance(named: $0) }
        let owner = RetainedPageAppearance(appearance)
        pageAppearance = owner
        let root = AnyView(RetainedPageRoot(appearance: owner, content: content))
        let hosting = NSHostingView(rootView: root)
        hostingView = hosting
        addSubview(hosting)
        hosting.autoresizingMask = [.width, .height]
        clipsToBounds = true
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
    }

    required init?(coder: NSCoder) {
        fatalError("Use init(content:) or init(frame:)")
    }

    override func layout() {
        super.layout()
        hostingView?.frame = bounds
    }

    func setPageAppearance(_ name: NSAppearance.Name?) {
        appearance = name.flatMap { NSAppearance(named: $0) }
        let scheme: ColorScheme? = name == .darkAqua ? .dark : name == .aqua ? .light : nil
        if pageAppearance?.scheme != scheme {
            pageAppearance?.scheme = scheme
        }
    }

    func setPageVisible(_ visible: Bool) {
        guard !isDismantled, visible != pageVisible else { return }
        if !visible {
            resignPageFocus()
        }
        pageVisible = visible
        isHidden = !visible
        setAccessibilityHidden(!visible)
    }

    func dismantle() {
        guard !isDismantled else { return }
        resignPageFocus()
        isDismantled = true
        pageVisible = false
        isHidden = true
        setAccessibilityHidden(true)
        // Hiding keeps this root and its native terminal intact. Only permanent
        // representable removal severs the hosted View's model/driver ownership.
        hostingView?.rootView = AnyView(EmptyView())
        hostingView?.removeFromSuperview()
        hostingView = nil
        pageAppearance = nil
    }

    private func resignPageFocus() {
        guard let window else { return }
        let responder = window.firstResponder
        let nativeView = responder as? NSView
        // A field editor is window-owned, not a descendant of its NSTextField.
        let editingField = allDescendants
            .compactMap { $0 as? NSTextField }
            .first { $0.currentEditor() === responder && responder != nil }
        if nativeView?.isDescendant(of: self) == true || editingField != nil {
            window.endEditing(for: editingField ?? self)
            if window.firstResponder === responder {
                _ = window.makeFirstResponder(nil)
            }
        }
    }

    private var allDescendants: [NSView] {
        func descendants(_ view: NSView) -> [NSView] {
            [view] + view.subviews.flatMap(descendants)
        }
        return descendants(self)
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        guard pageVisible, !isHiddenOrHasHiddenAncestor else { return nil }
        return super.hitTest(point)
    }

    override var acceptsFirstResponder: Bool {
        pageVisible && !isHiddenOrHasHiddenAncestor
    }

    override func becomeFirstResponder() -> Bool {
        acceptsFirstResponder && super.becomeFirstResponder()
    }
}

@MainActor final class SheetAnchorView: NSView {
    var windowChanged: (() -> Void)?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        windowChanged?()
    }
}

/// Small native controls expose identifiers for the in-process smoke harness. The harness
/// uses the actual target/action and text-editing paths; it does not require Accessibility.
struct NativeButton: View {
    let title: String
    let id: String
    var enabled = true
    var isDefault = false
    var isProminent = false
    var action: () -> Void

    var body: some View {
        NativeButtonControl(
            title: title,
            id: id,
            enabled: enabled,
            isDefault: isDefault,
            isProminent: isProminent,
            action: action
        )
        .disabled(!enabled)
    }
}

private struct NativeButtonControl: NSViewRepresentable {
    @Environment(\.colorScheme) private var colorScheme
    let title: String
    let id: String
    let enabled: Bool
    let isDefault: Bool
    let isProminent: Bool
    let action: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(action)
    }

    func makeNSView(context: Context) -> NSButton {
        let view = NativeActionButton(title: title, target: context.coordinator, action: #selector(Coordinator.clicked))
        view.bezelStyle = .rounded
        view.identifier = NSUserInterfaceItemIdentifier(id)
        view.isEnabled = enabled
        view.appearance = NSAppearance(named: colorScheme == .dark ? .darkAqua : .aqua)
        configureDefaultAction(view)
        view.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        return view
    }

    func updateNSView(_ view: NSButton, context: Context) {
        context.coordinator.action = action
        view.title = title
        view.isEnabled = enabled
        view.appearance = NSAppearance(named: colorScheme == .dark ? .darkAqua : .aqua)
        view.identifier = NSUserInterfaceItemIdentifier(id)
        configureDefaultAction(view)
    }

    private func configureDefaultAction(_ view: NSButton) {
        view.keyEquivalent = isDefault ? "\r" : ""
        view.keyEquivalentModifierMask = []
        view.bezelColor = isDefault || isProminent ? .controlAccentColor : nil
    }

    @MainActor final class Coordinator: NSObject {
        var action: () -> Void

        init(_ action: @escaping () -> Void) {
            self.action = action
        }

        @objc func clicked() {
            action()
        }
    }
}

@MainActor final class NativeActionButton: NSButton {
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        guard !isHiddenOrHasHiddenAncestor else { return false }
        // Return must first commit a marked-text composition through the input
        // system. It must not accept a server challenge while choosing IME text.
        if event.charactersIgnoringModifiers == "\r",
           let input = window?.firstResponder as? any NSTextInputClient,
           input.hasMarkedText() {
            return false
        }
        return super.performKeyEquivalent(with: event)
    }
}

struct NativeField: NSViewRepresentable {
    let placeholder: String
    let id: String
    @Binding var text: String
    var focusRequest: UUID? = nil
    var onSubmit: ((Bool) -> Void)? = nil
    var onCancel: (() -> Void)? = nil
    var onFocus: (() -> Void)? = nil
    var borderless = false

    func makeCoordinator() -> Coordinator {
        let value = Coordinator($text)
        value.onSubmit = onSubmit
        value.onCancel = onCancel
        value.onFocus = onFocus
        return value
    }

    func makeNSView(context: Context) -> NSTextField {
        let view = FocusableNativeTextField(string: text)
        view.identifier = NSUserInterfaceItemIdentifier(id)
        view.placeholderString = placeholder
        view.delegate = context.coordinator
        view.target = context.coordinator
        view.action = #selector(Coordinator.committed(_:))
        view.lineBreakMode = .byTruncatingTail
        if borderless {
            view.isBezeled = false
            view.isBordered = false
            view.drawsBackground = false
            view.focusRingType = .none
        }
        view.setContentHuggingPriority(.defaultLow, for: .horizontal)
        return view
    }

    func updateNSView(_ view: NSTextField, context: Context) {
        context.coordinator.text = $text
        context.coordinator.onSubmit = onSubmit
        context.coordinator.onCancel = onCancel
        context.coordinator.onFocus = onFocus
        if view.stringValue != text {
            view.stringValue = text
        }
        (view as? FocusableNativeTextField)?.requestFocus(focusRequest)
    }

    static func dismantleNSView(_ view: NSTextField, coordinator: Coordinator) {
        view.delegate = nil
        view.target = nil
        coordinator.onSubmit = nil
        coordinator.onCancel = nil
        coordinator.onFocus = nil
    }

    @MainActor final class Coordinator: NSObject, NSTextFieldDelegate {
        var text: Binding<String>
        var onSubmit: ((Bool) -> Void)?
        var onCancel: (() -> Void)?
        var onFocus: (() -> Void)?

        init(_ text: Binding<String>) {
            self.text = text
        }

        func controlTextDidChange(_ notification: Notification) {
            if let field = notification.object as? NSTextField {
                text.wrappedValue = field.stringValue
            }
        }

        func controlTextDidBeginEditing(_ notification: Notification) {
            onFocus?()
        }

        @objc func committed(_ sender: NSTextField) {
            text.wrappedValue = sender.stringValue
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
            // Leave marked text and ordinary editing commands to the field editor.
            guard !textView.hasMarkedText() else { return false }
            if commandSelector == #selector(NSResponder.cancelOperation(_:)), let onCancel {
                onCancel()
                return true
            }
            if commandSelector == #selector(NSResponder.insertNewline(_:))
                || commandSelector == #selector(NSResponder.insertNewlineIgnoringFieldEditor(_:)),
               let onSubmit {
                onSubmit(NSApp.currentEvent?.modifierFlags.contains(.shift) == true)
                return true
            }
            return false
        }
    }
}

@MainActor private final class FocusableNativeTextField: NSTextField {
    private var requestedFocus: UUID?
    private var appliedFocus: UUID?
    private var focusScheduled = false

    func requestFocus(_ request: UUID?) {
        requestedFocus = request
        scheduleFocus()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        scheduleFocus()
    }

    override func viewDidUnhide() {
        super.viewDidUnhide()
        scheduleFocus()
    }

    override func layout() {
        super.layout()
        scheduleFocus()
    }

    private func scheduleFocus() {
        guard requestedFocus != nil, requestedFocus != appliedFocus, !focusScheduled else { return }
        focusScheduled = true
        Task { @MainActor [weak self] in
            guard let self else { return }
            focusScheduled = false
            guard let request = requestedFocus,
                  request != appliedFocus,
                  let window,
                  !isHiddenOrHasHiddenAncestor,
                  window.attachedSheet == nil,
                  NSApp.modalWindow == nil,
                  NSApp.keyWindow == nil || NSApp.keyWindow === window else { return }
            if window.makeFirstResponder(self) {
                appliedFocus = request
            }
        }
    }
}

struct NativeSecureField: NSViewRepresentable {
    let id: String
    let placeholder: String
    @Binding var text: String
    var onSubmit: ((Bool) -> Void)? = nil

    func makeCoordinator() -> NativeField.Coordinator {
        let coordinator = NativeField.Coordinator($text)
        coordinator.onSubmit = onSubmit
        return coordinator
    }

    func makeNSView(context: Context) -> NSSecureTextField {
        let view = NSSecureTextField(string: "")
        view.identifier = NSUserInterfaceItemIdentifier(id)
        view.placeholderString = placeholder
        view.delegate = context.coordinator
        view.target = context.coordinator
        view.action = #selector(NativeField.Coordinator.committed(_:))
        return view
    }

    func updateNSView(_ view: NSSecureTextField, context: Context) {
        context.coordinator.text = $text
        context.coordinator.onSubmit = onSubmit
        if view.stringValue != text {
            view.stringValue = text
        }
    }

    static func dismantleNSView(_ view: NSSecureTextField, coordinator: NativeField.Coordinator) {
        // View State is cleared by the owning editor before dismissal/onDisappear. Writing
        // a Binding while SwiftUI tears its graph down violates exclusive access.
        view.stringValue = ""
        coordinator.onSubmit = nil
    }
}

struct PopupItem {
    let value: String
    let title: String
}

struct NativePopup: NSViewRepresentable {
    let id: String
    let items: [PopupItem]
    @Binding var selection: String

    func makeCoordinator() -> Coordinator {
        Coordinator($selection)
    }

    func makeNSView(context: Context) -> NSPopUpButton {
        let view = NSPopUpButton(frame: .zero, pullsDown: false)
        view.identifier = NSUserInterfaceItemIdentifier(id)
        view.target = context.coordinator
        view.action = #selector(Coordinator.selected(_:))
        return view
    }

    func updateNSView(_ view: NSPopUpButton, context: Context) {
        context.coordinator.selection = $selection
        let titlesDiffer = view.itemArray.map(\.title) != items.map(\.title)
        let valuesDiffer = view.itemArray.map { $0.representedObject as? String } != items.map { Optional($0.value) }
        if titlesDiffer || valuesDiffer {
            view.removeAllItems()
            for item in items {
                view.addItem(withTitle: item.title)
                view.lastItem?.representedObject = item.value
            }
        }
        if let index = items.firstIndex(where: { $0.value == selection }) {
            view.selectItem(at: index)
        }
    }

    @MainActor final class Coordinator: NSObject {
        var selection: Binding<String>

        init(_ selection: Binding<String>) {
            self.selection = selection
        }

        @objc func selected(_ sender: NSPopUpButton) {
            if let value = sender.selectedItem?.representedObject as? String {
                selection.wrappedValue = value
            }
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

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .noBorder

        let table = HostNativeTableView()
        table.identifier = NSUserInterfaceItemIdentifier("hosts.table")
        for (id, title, width) in [("name", "主机", 200.0), ("address", "地址 / 用户", 230.0), ("favorite", "收藏", 55.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id))
            column.title = title
            column.width = width
            table.addTableColumn(column)
        }
        table.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        table.rowHeight = 44
        table.delegate = context.coordinator
        table.dataSource = context.coordinator
        table.openRow = { [weak coordinator = context.coordinator] row in
            coordinator?.open(row: row)
        }
        table.allowsEmptySelection = true
        table.usesAlternatingRowBackgroundColors = true
        scroll.documentView = table
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let table = scroll.documentView as? NSTableView else { return }
        context.coordinator.parent = self
        if context.coordinator.displayedHosts != hosts {
            context.coordinator.displayedHosts = hosts
            table.reloadData()
        }
        let row = hosts.firstIndex { $0.id == selectedID }
        let indexes = row.map { IndexSet(integer: $0) } ?? IndexSet()
        if table.selectedRowIndexes != indexes {
            table.selectRowIndexes(indexes, byExtendingSelection: false)
        }
    }

    @MainActor final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        var parent: HostTable
        var displayedHosts: [HostConfiguration] = []

        init(_ parent: HostTable) {
            self.parent = parent
        }

        func numberOfRows(in tableView: NSTableView) -> Int {
            displayedHosts.count
        }

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
            field.lineBreakMode = .byTruncatingTail
            field.toolTip = text
            return field
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard let table = notification.object as? NSTableView else { return }
            parent.selectedID = displayedHosts.indices.contains(table.selectedRow)
                ? displayedHosts[table.selectedRow].id
                : nil
        }

        func open(row: Int) {
            guard displayedHosts.indices.contains(row) else { return }
            parent.open(displayedHosts[row].id)
        }
    }
}
