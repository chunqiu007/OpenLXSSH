import AppKit
import SwiftUI
import OpenLXSSHTransport
import OpenLXSSHSecurity

struct SessionWorkspaceView: View {
    let controller: SessionController
    private var splitPair: (axis: TerminalSplitAxis, primary: SessionTab, secondary: SessionTab)? {
        guard let activeSplit = controller.activeSplit,
              let primary = controller.tabs.first(where: { $0.id == activeSplit.primaryTabID }),
              let secondary = controller.tabs.first(where: { $0.id == activeSplit.secondaryTabID }) else { return nil }
        return (activeSplit.axis, primary, secondary)
    }
    private var singleTabs: [SessionTab] {
        guard let pair = splitPair else { return controller.tabs }
        return controller.tabs.filter { $0.id != pair.primary.id && $0.id != pair.secondary.id }
    }
    var body: some View {
        VStack(spacing: 0) {
            IssueView(issue: controller.issue) { controller.issue = nil }.padding(.horizontal, 10)
            ZStack {
                if controller.tabs.isEmpty {
                    VStack(spacing: 12) {
                        RoundedRectangle(cornerRadius: 14)
                            .fill(DesktopStyle.terminalChrome)
                            .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(DesktopStyle.border))
                            .frame(width: 52, height: 52)
                            .overlay {
                                Image(systemName: "terminal")
                                    .font(.system(size: 22, weight: .semibold))
                                    .foregroundStyle(Color.accentColor)
                            }
                        Text("暂无打开的终端会话")
                            .font(.system(size: 16, weight: .semibold))
                        Text("从保险箱选择主机点击连接，或通过新标签开启 SSH 终端。不会自动恢复上次关闭前的会话。")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: 360)
                    }
                    .padding(32)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(DesktopStyle.terminalBackground)
                    .environment(\.colorScheme, .dark)
                }
                ForEach(singleTabs) { tab in
                    NativeWorkspacePage(id: "workspace.session." + tab.id.uuidString,
                                        isVisible: controller.workspaceVisible && controller.selectedTabID == tab.id, appearance: .darkAqua) {
                        SessionDetailView(tab: tab, controller: controller, isFocused: controller.selectedTabID == tab.id)
                    }
                }
                if let pair = splitPair {
                    SessionSplitContainerView(controller: controller, axis: pair.axis, primary: pair.primary, secondary: pair.secondary)
                }
            }
        }
    }
}

private struct SessionSplitContainerView: View {
    let controller: SessionController
    let axis: TerminalSplitAxis
    let primary: SessionTab
    let secondary: SessionTab
    var body: some View {
        Group {
            if axis == .horizontal {
                HSplitView {
                    SessionSplitPaneView(tab: primary, controller: controller, axis: axis)
                        .id(primary.id)
                    SessionSplitPaneView(tab: secondary, controller: controller, axis: axis)
                        .id(secondary.id)
                }
            } else {
                VSplitView {
                    SessionSplitPaneView(tab: primary, controller: controller, axis: axis)
                        .id(primary.id)
                    SessionSplitPaneView(tab: secondary, controller: controller, axis: axis)
                        .id(secondary.id)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(DesktopStyle.terminalBackground)
        .environment(\.colorScheme, .dark)
    }
}

private struct SessionSplitPaneView: View {
    let tab: SessionTab
    let controller: SessionController
    let axis: TerminalSplitAxis
    private var isActive: Bool { controller.selectedTabID == tab.id }
    private var statusDotColor: Color {
        switch tab.state {
        case .connected: DesktopStyle.statusGreen
        case .awaitingTrust, .authenticating, .preparing, .connectionPending: DesktopStyle.statusAmber
        case .failed: DesktopStyle.statusRed
        case .idle, .disconnected, .closing, .closed: .secondary
        }
    }
    private func activate() {
        if controller.selectedTabID != tab.id {
            controller.select(tab.id)
        }
        tab.focusTerminal()
    }
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(statusDotColor)
                        .frame(width: 7, height: 7)
                    Text(controller.displayTitle(for: tab))
                        .font(.system(size: 11, weight: isActive ? .semibold : .medium))
                        .foregroundStyle(isActive ? DesktopStyle.barForeground : DesktopStyle.barSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: 4)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
                .contentShape(Rectangle())
                .onTapGesture { activate() }

                HStack(spacing: 2) {
                    SplitHeaderIconButton(
                        symbol: axis == .horizontal ? "rectangle.split.1x2" : "rectangle.split.2x1",
                        help: axis == .horizontal ? "切换为上下分屏" : "切换为左右分屏",
                        id: "split.toggleAxis." + tab.id.uuidString
                    ) { controller.toggleSplitAxis() }
                    SplitHeaderIconButton(
                        symbol: "arrow.left.arrow.right",
                        help: "交换分屏位置",
                        id: "split.swap." + tab.id.uuidString
                    ) { controller.swapSplitPanes() }
                    SplitHeaderIconButton(
                        symbol: "rectangle",
                        help: "取消分屏（保留两个标签）",
                        id: "split.unsplit." + tab.id.uuidString
                    ) { controller.unsplit() }
                    SplitHeaderIconButton(
                        symbol: "xmark",
                        help: "关闭此会话",
                        id: "split.close." + tab.id.uuidString
                    ) { Task { await controller.closeTab(tab.id) } }
                }
            }
            .padding(.horizontal, 8)
            .frame(height: 28)
            .background(DesktopStyle.terminalChrome)
            .overlay(alignment: .top) {
                Rectangle()
                    .fill(isActive ? Color.accentColor : Color.clear)
                    .frame(height: 2)
            }
            .overlay(alignment: .bottom) {
                Rectangle()
                    .fill(DesktopStyle.border)
                    .frame(height: 1)
            }

            SessionDetailView(tab: tab, controller: controller, isFocused: isActive)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .overlay {
                    if !isActive {
                        UnfocusedPaneClickOverlay(onActivate: activate)
                            .accessibilityHidden(true)
                    }
                }
        }
        .frame(minWidth: 240, maxWidth: .infinity, minHeight: 160, maxHeight: .infinity)
        .overlay(
            Rectangle()
                .strokeBorder(isActive ? Color.accentColor.opacity(0.65) : DesktopStyle.border, lineWidth: 1)
                .allowsHitTesting(false)
        )
        .accessibilityIdentifier("split.pane." + tab.id.uuidString)
    }
}

private struct SplitHeaderIconButton: View {
    let symbol: String
    let help: String
    let id: String
    let action: () -> Void
    @State private var hovered = false
    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 10.5, weight: .medium))
                .foregroundStyle(hovered ? DesktopStyle.barForeground : DesktopStyle.barSecondary.opacity(0.85))
                .frame(width: 22, height: 20)
                .background(hovered ? Color.white.opacity(0.08) : Color.clear, in: RoundedRectangle(cornerRadius: 4))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .help(help)
        .accessibilityLabel(help)
        .accessibilityIdentifier(id)
    }
}

private struct UnfocusedPaneClickOverlay: NSViewRepresentable {
    let onActivate: () -> Void
    func makeNSView(context: Context) -> UnfocusedPaneClickView {
        let view = UnfocusedPaneClickView()
        view.onActivate = onActivate
        return view
    }
    func updateNSView(_ view: UnfocusedPaneClickView, context: Context) {
        view.onActivate = onActivate
    }
    static func dismantleNSView(_ view: UnfocusedPaneClickView, coordinator: ()) {
        view.onActivate = nil
    }
}

@MainActor private final class UnfocusedPaneClickView: NSView {
    var onActivate: (() -> Void)?
    override var acceptsFirstResponder: Bool { false }
    override func hitTest(_ point: NSPoint) -> NSView? {
        guard onActivate != nil,
              let event = NSApp.currentEvent,
              event.type == .leftMouseDown || event.type == .rightMouseDown,
              let window, event.window === window,
              window.attachedSheet == nil, NSApp.modalWindow == nil,
              !isHiddenOrHasHiddenAncestor,
              bounds.contains(convert(point, from: superview)) else { return nil }
        return self
    }
    override func mouseDown(with event: NSEvent) {
        onActivate?()
    }
    override func rightMouseDown(with event: NSEvent) {
        onActivate?()
    }
}
private struct SessionTabButton: View {
    let tab: SessionTab
    let controller: SessionController
    var body: some View {
        HStack(spacing: 2) {
            NativeButton(title: (controller.selectedTabID == tab.id ? "● " : "") + tab.title,
                         id: "tab.select." + tab.id.uuidString) { controller.select(tab.id) }.fixedSize()
            NativeButton(title: "×", id: "tab.close." + tab.id.uuidString) { Task { await controller.closeTab(tab.id) } }.fixedSize()
        }.help(tab.status)
    }
}
private struct SessionDetailView: View {
    @Bindable var tab: SessionTab
    let controller: SessionController
    var isFocused: Bool = true
    @State private var ownerWindow: NSWindow?
    @State private var showsDiagnostic = false
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if tab.state != .connected {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 10) {
                        if tab.state == .preparing || tab.state == .connectionPending {
                            ProgressView().controlSize(.small)
                        } else {
                            Circle()
                                .fill(statusDotColor)
                                .frame(width: 8, height: 8)
                        }
                        VStack(alignment: .leading, spacing: 1) {
                            Text(tab.status)
                                .font(.system(size: 12, weight: .medium))
                                .lineLimit(1)
                            if let endpoint = tab.host?.vaultEndpoint {
                                Text(verbatim: endpoint)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                        Spacer(minLength: 8)
                        if let prompt = tab.trust.first {
                            NativeButton(title: "核实主机身份…", id: "terminal.trust") { controller.present(.trust(prompt), tabID: tab.id) }.fixedSize()
                        }
                        if let prompt = tab.authentication {
                            NativeButton(title: "继续认证…", id: "terminal.authenticate") { controller.present(.authentication(prompt), tabID: tab.id) }.fixedSize()
                        }
                        if tab.canReconnect {
                            Button("手动重连") { controller.performTerminalAction(.reconnect, tabID: tab.id) }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.small)
                            Button("查看配置") { controller.showConfiguration(tabID: tab.id) }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                        }
                        if tab.isReusable {
                            Button("取消连接") { controller.disconnect(tab.id) }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                        }
                        Button { controller.performTerminalAction(.connectionInfo, tabID: tab.id) } label: {
                            Image(systemName: "info.circle")
                                .font(.system(size: 13))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .help("连接信息")
                        .accessibilityLabel("连接信息")
                    }
                    if tab.state == .preparing || tab.state == .connectionPending {
                        Text("如果 macOS 询问本地网络访问，请允许后继续；也可随时取消连接。")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(DesktopStyle.terminalChrome)
                .overlay(alignment: .bottom) {
                    Rectangle().fill(DesktopStyle.border).frame(height: 1)
                }
            }
            if tab.searchVisible {
                HStack(spacing: 8) {
                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                        NativeField(placeholder: "搜索当前标签历史", id: "terminal.search", text: $tab.searchText,
                                    focusRequest: tab.searchFocusRequest,
                                    onSubmit: { tab.searchHistory(backwards: $0) }, onCancel: { tab.closeSearch() }, borderless: true)
                            .frame(height: 22)
                    }
                    .padding(.horizontal, 9).padding(.vertical, 3)
                    .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 7))
                    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(DesktopStyle.border))
                    .frame(maxWidth: 340)
                    NativeButton(title: "上一处", id: "terminal.search.previous", enabled: !tab.searchText.isEmpty) { tab.searchHistory(backwards: true) }.fixedSize()
                    NativeButton(title: "下一处", id: "terminal.search.next", enabled: !tab.searchText.isEmpty) { tab.searchHistory() }.fixedSize()
                    if tab.searchFound == false {
                        Text("无结果").font(.caption).foregroundStyle(.secondary)
                    } else if tab.searchFound == true {
                        Text("\(tab.searchMatchIndex) / \(tab.searchMatchCount)\(tab.searchMatchCount == 1000 ? "+" : "")")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 0)
                    NativeButton(title: "关闭搜索", id: "terminal.search.close") { tab.closeSearch() }.fixedSize()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(DesktopStyle.terminalChrome)
                .overlay(alignment: .bottom) {
                    Rectangle().fill(DesktopStyle.border).frame(height: 1)
                }
            }
            if tab.issue != nil {
                VStack(alignment: .leading, spacing: 6) {
                    IssueView(issue: tab.issue) { tab.issue = nil }
                    if let detail = tab.driver?.failureDetail {
                        Button {
                            showsDiagnostic.toggle()
                        } label: {
                            Label(showsDiagnostic ? "收起脱敏详情" : "查看脱敏详情",
                                  systemImage: showsDiagnostic ? "chevron.up" : "chevron.down")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .padding(.top, 2)
                        if showsDiagnostic {
                            Text(verbatim: detail.diagnostic)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                                .padding(10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 8))
                                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(DesktopStyle.border))
                        }
                    }
                }
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(DesktopStyle.terminalChrome)
            }
            if let driver = tab.driver {
                RetainedTerminalView(terminal: driver.terminal, focusRequest: tab.terminalFocusRequest, isFocused: isFocused)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
            } else if tab.state == .preparing {
                VStack(spacing: 10) {
                    ProgressView()
                    Text("准备连接…")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 12) {
                    RoundedRectangle(cornerRadius: 14)
                        .fill(DesktopStyle.terminalChrome)
                        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(DesktopStyle.border))
                        .frame(width: 50, height: 50)
                        .overlay {
                            Image(systemName: "terminal")
                                .font(.system(size: 20, weight: .semibold))
                                .foregroundStyle(.secondary)
                        }
                    Text("连接尚未启动")
                        .font(.system(size: 16, weight: .semibold))
                    Text("检查配置或网络连通性后可点击下方按钮重试。")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                    if tab.canReconnect {
                        HStack(spacing: 8) {
                            Button("立即重连") { controller.performTerminalAction(.reconnect, tabID: tab.id) }
                                .buttonStyle(.borderedProminent)
                            Button("查看配置") { controller.showConfiguration(tabID: tab.id) }
                                .buttonStyle(.bordered)
                        }
                        .padding(.top, 4)
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(tab.driver.map { Color(nsColor: $0.terminal.nativeBackgroundColor) } ?? DesktopStyle.terminalBackground)
        .environment(\.colorScheme, .dark)
        .background(ChallengeWindowObserver { ownerWindow = $0; presentPending() }.frame(width: 0, height: 0))
        .onChange(of: tab.trust) { _, _ in presentPending() }
        .onChange(of: tab.authentication) { _, _ in presentPending() }
        .onChange(of: controller.selectedTabID) { _, _ in presentPending() }
        .onChange(of: controller.workspaceVisible) { _, _ in presentPending() }
        .nativeSheet(item: $tab.dialog, isEnabled: controller.workspaceVisible && controller.selectedTabID == tab.id,
                     allowsTerminationReview: true,
                     onAttemptDismiss: { cancelPresented(); return true }) { value in
            switch value.content {
            case .trust(let prompt): TrustChallengeView(tab: tab, controller: controller, prompt: prompt) { controller.dismissDialog(value.id, tabID: tab.id) }
            case .authentication(let prompt): AuthenticationChallengeView(tab: tab, controller: controller, prompt: prompt) { controller.dismissDialog(value.id, tabID: tab.id) }
            }
        }
    }
    private func presentPending() {
        _ = controller.presentPendingChallenge(tabID: tab.id, modalAvailable: ChallengeWindowObserver.isAvailable(ownerWindow))
    }
    private func cancelPresented() {
        switch tab.dialog?.content {
        case .trust(let prompt): controller.cancelTrust(prompt, tabID: tab.id)
        case .authentication(let prompt): controller.cancelChallenge(prompt, tabID: tab.id)
        case nil: break
        }
    }
    private var statusDotColor: Color {
        switch tab.state {
        case .connected: return DesktopStyle.statusGreen
        case .awaitingTrust, .authenticating, .preparing, .connectionPending: return DesktopStyle.statusAmber
        case .failed: return DesktopStyle.statusRed
        case .idle, .disconnected, .closing, .closed: return .secondary
        }
    }
}

/// Read only its actual owning window. Waiting behind another modal does not queue an
/// AppKit sheet or steal its input. didEndSheet makes a still-pending owner reachable.
struct ChallengeWindowObserver: NSViewRepresentable {
    let changed: @MainActor (NSWindow?) -> Void
    static func isAvailable(_ window: NSWindow?) -> Bool {
        guard let window, window.isVisible, window.attachedSheet == nil, NSApp.modalWindow == nil else { return false }
        return NSApp.keyWindow == nil || NSApp.keyWindow === window
    }
    func makeNSView(context: Context) -> ChallengeWindowAnchor {
        let view = ChallengeWindowAnchor(); view.setChanged(changed); return view
    }
    func updateNSView(_ view: ChallengeWindowAnchor, context: Context) { view.setChanged(changed) }
    static func dismantleNSView(_ view: ChallengeWindowAnchor, coordinator: ()) { view.dismantle() }
}
@MainActor final class ChallengeWindowAnchor: NSView {
    private var changed: (@MainActor (NSWindow?) -> Void)?
    private var observations: [NSObjectProtocol] = []
    private var active = true
    private var observationGeneration: UInt64 = 0
    func setChanged(_ changed: @escaping @MainActor (NSWindow?) -> Void) {
        guard active else { return }
        self.changed = changed
    }
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow(); stopObservingWindow()
        guard active else { return }
        if let window {
            for name in [NSWindow.didEndSheetNotification, NSWindow.didBecomeKeyNotification] {
                observations.append(NotificationCenter.default.addObserver(forName: name, object: window, queue: .main) { [weak self] _ in
                    MainActor.assumeIsolated { self?.notify() }
                })
            }
        }
        notify()
    }
    private func notify() {
        guard active else { return }
        let generation = observationGeneration
        Task { @MainActor [weak self] in
            guard let self, self.active, self.observationGeneration == generation else { return }
            self.changed?(self.window)
        }
    }
    private func stopObservingWindow() {
        observationGeneration &+= 1
        for observer in observations { NotificationCenter.default.removeObserver(observer) }
        observations = []
    }
    func dismantle() {
        active = false; changed = nil; stopObservingWindow()
    }
}

/// Coordinates sole active container ownership when a transport-owned NativeTerminalView
/// moves between single-tab NativeWorkspacePage and HSplitView/VSplitView containers.
/// Prevents a retiring container's late updateNSView or dismantleNSView from reclaiming
/// or detaching a terminal already claimed by the new container.
@MainActor private final class TerminalAttachmentRegistry {
    static let shared = TerminalAttachmentRegistry()
    private struct WeakContainer { weak var view: TerminalContainerView? }
    private var owners: [ObjectIdentifier: WeakContainer] = [:]

    func claim(_ terminal: NativeTerminalView, for container: TerminalContainerView) {
        owners = owners.filter { $0.value.view != nil }
        if let previous = container.terminal, previous !== terminal {
            release(previous, from: container)
        }
        let key = ObjectIdentifier(terminal)
        owners[key] = WeakContainer(view: container)
        container.terminal = terminal
        attachIfOwned(terminal, to: container)
    }

    func attachIfOwned(_ terminal: NativeTerminalView, to container: TerminalContainerView) {
        let key = ObjectIdentifier(terminal)
        guard owners[key]?.view === container else { return }
        container.terminal = terminal
        if terminal.superview !== container {
            terminal.removeFromSuperview()
            terminal.autoresizingMask = [.width, .height]
            terminal.frame = container.bounds
            container.addSubview(terminal)
            terminal.needsLayout = true
            terminal.needsDisplay = true
        } else if terminal.frame != container.bounds {
            terminal.frame = container.bounds
        }
    }

    func release(_ terminal: NativeTerminalView, from container: TerminalContainerView) {
        let key = ObjectIdentifier(terminal)
        if owners[key]?.view === container {
            owners.removeValue(forKey: key)
            if terminal.superview === container {
                terminal.removeFromSuperview()
            }
        }
    }
}

/// Each page keeps the same transport-owned NSView mounted until the tab closes,
/// and safely reparents it when moving between single-tab and split-pane containers.
struct RetainedTerminalView: NSViewRepresentable {
    let terminal: NativeTerminalView
    var focusRequest: UUID? = nil
    var isFocused: Bool = true
    func makeNSView(context: Context) -> TerminalContainerView {
        let container = TerminalContainerView()
        container.clipsToBounds = true
        TerminalAttachmentRegistry.shared.claim(terminal, for: container)
        container.requestFocus(focusRequest, active: isFocused)
        return container
    }
    func updateNSView(_ view: TerminalContainerView, context: Context) {
        if view.terminal !== terminal {
            TerminalAttachmentRegistry.shared.claim(terminal, for: view)
        } else {
            TerminalAttachmentRegistry.shared.attachIfOwned(terminal, to: view)
        }
        view.requestFocus(focusRequest, active: isFocused)
    }
    static func dismantleNSView(_ view: TerminalContainerView, coordinator: ()) {
        if let terminal = view.terminal {
            TerminalAttachmentRegistry.shared.release(terminal, from: view)
        }
        view.terminal = nil
    }
}
@MainActor final class TerminalContainerView: NSView {
    weak var terminal: NativeTerminalView?
    private var requestedFocus: UUID?
    private var appliedFocus: UUID?
    private var focusScheduled = false

    override func layout() {
        super.layout()
        if let terminal {
            TerminalAttachmentRegistry.shared.attachIfOwned(terminal, to: self)
        }
        scheduleFocus()
    }
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window != nil, let terminal {
            TerminalAttachmentRegistry.shared.attachIfOwned(terminal, to: self)
        }
        scheduleFocus()
    }
    override func viewDidUnhide() {
        super.viewDidUnhide()
        scheduleFocus()
    }
    func requestFocus(_ request: UUID?, active: Bool) {
        guard active else {
            requestedFocus = request
            appliedFocus = request
            return
        }
        requestedFocus = request
        scheduleFocus()
    }
    private func scheduleFocus() {
        guard requestedFocus != nil, requestedFocus != appliedFocus, !focusScheduled else { return }
        focusScheduled = true
        Task { @MainActor [weak self] in
            guard let self else { return }
            self.focusScheduled = false
            guard let request = self.requestedFocus, request != self.appliedFocus,
                  let terminal = self.terminal, terminal.superview === self,
                  !terminal.isHiddenOrHasHiddenAncestor,
                  let window = terminal.window, window.attachedSheet == nil,
                  NSApp.modalWindow == nil,
                  NSApp.keyWindow == nil || NSApp.keyWindow === window else { return }
            if window.makeFirstResponder(terminal) {
                self.appliedFocus = request
            }
        }
    }
}

private struct TrustChallengeView: View {
    let tab: SessionTab
    let controller: SessionController
    let prompt: SessionTrustPrompt
    @State private var submitting = false
    @State private var management = false
    @State private var copiedFingerprint = false
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                RoundedRectangle(cornerRadius: 10)
                    .fill((prompt.changed == nil ? DesktopStyle.statusAmber : DesktopStyle.statusRed).opacity(0.14))
                    .frame(width: 40, height: 40)
                    .overlay {
                        Image(systemName: prompt.changed == nil ? "shield.lefthalf.filled" : "exclamationmark.shield.fill")
                            .font(.system(size: 18, weight: .semibold))
                            .foregroundStyle(prompt.changed == nil ? DesktopStyle.statusAmber : DesktopStyle.statusRed)
                    }
                VStack(alignment: .leading, spacing: 2) {
                    Text(prompt.changed == nil ? "首次连接主机身份" : "主机密钥已变化，连接已阻止")
                        .font(.system(size: 18, weight: .semibold))
                    Text(verbatim: "\(tab.title) · \(prompt.host.address.value):\(prompt.host.port.value) · \(prompt.algorithm)")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            if let changed = prompt.changed {
                VStack(alignment: .leading, spacing: 6) {
                    Text("已知指纹").font(.caption).foregroundStyle(.secondary)
                    Text(verbatim: changed.expectedFingerprint)
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(DesktopStyle.border))
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(prompt.changed == nil ? "服务器指纹" : "本次指纹").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button(copiedFingerprint ? "已复制指纹" : "复制指纹", systemImage: copiedFingerprint ? "checkmark" : "doc.on.doc") {
                        NSPasteboard.general.clearContents()
                        copiedFingerprint = NSPasteboard.general.setString(prompt.fingerprint, forType: .string)
                    }.buttonStyle(.borderless).accessibilityIdentifier("trust.copyFingerprint")
                }
                Text(verbatim: prompt.fingerprint)
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(DesktopStyle.border))
            }
            Text(prompt.changed == nil ? "请核对服务器指纹。仅此次继续不会保存；添加后，后续连接可使用此密钥。" : "服务器身份与保存记录不一致。请核实后在已知主机中处理，当前连接已阻止。")
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            DisclosureGroup("连接详情") {
                Text(verbatim: prompt.source).font(.caption).foregroundStyle(.secondary)
            }.font(.caption)
            IssueView(issue: tab.issue) { tab.issue = nil }
            Spacer(minLength: 0)
            HStack {
                NativeButton(title: "关闭", id: "trust.cancel", enabled: !submitting) { controller.cancelTrust(prompt, tabID: tab.id); dismiss() }.fixedSize()
                Spacer(minLength: 8)
                if prompt.changed == nil {
                    NativeButton(title: "仅此次继续", id: "trust.once", enabled: !submitting) { accept(.once) }.fixedSize()
                    NativeButton(title: "添加并继续", id: "trust.accept", enabled: !submitting, isDefault: true) { accept(.persistent) }.fixedSize()
                } else if controller.trustEnvironment != nil {
                    Button("打开已知主机管理…") { management = true }
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .padding(24)
        .frame(width: 650)
        .background(DesktopStyle.background)
        .sheet(isPresented: $management) {
            if let environment = controller.trustEnvironment { TrustManagementView(environment: environment) { management = false } }
        }
    }
    private func accept(_ persistence: SessionTrustPersistence) {
        guard !submitting else { return }; submitting = true
        Task { if await controller.accept(prompt, tabID: tab.id, persistence: persistence) { dismiss() }; submitting = false }
    }
}

struct AuthenticationChallengeView: View {
    let tab: SessionTab
    let controller: SessionController
    let prompt: SessionAuthenticationPrompt
    @State private var answers: [String]
    @State private var presentationHeight: CGFloat
    @FocusState private var focusedIndex: Int?
    var dismiss: () -> Void
    init(tab: SessionTab, controller: SessionController, prompt: SessionAuthenticationPrompt, dismiss: @escaping () -> Void) {
        self.tab = tab; self.controller = controller; self.prompt = prompt; self.dismiss = dismiss
        let parentHeight = (NSApp.keyWindow?.sheetParent ?? NSApp.keyWindow ?? NSApp.mainWindow)?.contentView?.bounds.height ?? 720
        let expanded: Bool
        if case .keyboard(_, _, let fields) = prompt.payload { expanded = fields.count > 2 } else { expanded = false }
        _presentationHeight = State(initialValue: expanded ? min(680, max(420, parentHeight - 60)) : 320)
        let count: Int
        switch prompt.payload {
        case .keyboard(_, _, let fields): count = fields.count
        case .initialPassword, .privateKeyPassphrase: count = 1
        }
        _answers = State(initialValue: Array(repeating: "", count: count))
    }
    private var title: String {
        switch prompt.payload {
        case .initialPassword: "输入本次连接密码"
        case .privateKeyPassphrase: "解锁受管理 SSH 私钥"
        case .keyboard(_, _, let fields): fields.isEmpty ? "服务器认证通知" : "服务器要求进一步验证"
        }
    }
    private var explanation: String {
        switch prompt.payload {
        case .initialPassword: "密码仅用于当前连接，不会保存。"
        case .privateKeyPassphrase: "口令仅用于解锁本次连接使用的密钥，不会保存。"
        case .keyboard: "请按服务器提示完成本轮验证。附加回答不会保存。"
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                RoundedRectangle(cornerRadius: 10)
                    .fill(DesktopStyle.iconSurface)
                    .frame(width: 40, height: 40)
                    .overlay {
                        Image(systemName: "key.fill")
                            .font(.system(size: 18, weight: .semibold))
                            .foregroundStyle(Color.accentColor)
                    }
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: 18, weight: .semibold))
                    Text(tab.title + " · " + (tab.host?.vaultEndpoint ?? "当前会话"))
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            Text(explanation).font(.system(size: 12)).foregroundStyle(.secondary)
            ScrollView {
                fields
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(14)
                    .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.border))
            }
            .frame(minHeight: 100, maxHeight: .infinity)
            .accessibilityIdentifier("authentication.fields.viewport")
            IssueView(issue: tab.issue) { tab.issue = nil }
            HStack {
                NativeButton(title: "取消本次连接", id: "authentication.cancel") { clear(); controller.cancelChallenge(prompt, tabID: tab.id); dismiss() }.fixedSize()
                Spacer(minLength: 8)
                NativeButton(title: answers.isEmpty ? "已阅，继续" : "继续", id: "authentication.submit", isDefault: true) { sendAnswers() }.fixedSize()
            }
        }
        .padding(24)
        .frame(width: 610, height: presentationHeight)
        .background(DesktopStyle.background)
        .onAppear { focusedIndex = answers.isEmpty ? nil : 0 }
        .onDisappear { clear() }
    }
    @ViewBuilder private var fields: some View {
        VStack(alignment: .leading, spacing: 12) {
            switch prompt.payload {
            case .keyboard(let name, let instruction, let fields):
                Text(verbatim: name); Text(verbatim: instruction)
                if fields.isEmpty { Text("本轮没有输入项。可确认通知后继续，或取消连接。") }
                ForEach(fields.indices, id: \.self) { index in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(verbatim: fields[index].text)
                        if fields[index].echo { TextField("第 \(index + 1) 项回答（服务器要求回显）", text: $answers[index]).focused($focusedIndex, equals: index).accessibilityIdentifier("authentication.answer.\(index)") }
                        else { SecureField("第 \(index + 1) 项回答（不回显）", text: $answers[index]).focused($focusedIndex, equals: index).accessibilityIdentifier("authentication.answer.\(index)") }
                    }
                }
            case .initialPassword, .privateKeyPassphrase:
                SecureField("仅本次使用，不保存", text: $answers[0]).focused($focusedIndex, equals: 0).accessibilityIdentifier("authentication.answer.0")
            }
        }.textFieldStyle(.roundedBorder)
            // The native text input system commits marked text before onSubmit;
            // no raw Return monitor or global shortcut bypasses that handling.
            .onSubmit { sendAnswers() }
    }
    private func clear() { answers = Array(repeating: "", count: answers.count) }
    private func sendAnswers() {
        guard answers.allSatisfy({ $0.utf8.count <= 65536 }) else { clear(); tab.issue = AppIssue(code: "authentication.inputBounds", message: "每个回答最多 65536 UTF-8 字节；未发送。"); return }
        let values = answers.map { OpenLXSSHSecurity.SecretBytes(utf8: $0) }; clear(); submit(.answers(values))
    }
    private func submit(_ answer: SessionAuthenticationAnswer) {
        clear(); if controller.respond(answer, to: prompt, tabID: tab.id) { dismiss() }
    }
}
