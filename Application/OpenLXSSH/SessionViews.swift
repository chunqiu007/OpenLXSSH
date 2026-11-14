import AppKit
import SwiftUI
import OpenLXSSHTransport
import OpenLXSSHSecurity

struct SessionWorkspaceView: View {
    @ObservedObject var controller: SessionController
    var body: some View {
        VStack(spacing: 0) {
            IssueView(issue: controller.issue) { controller.issue = nil }.padding(.horizontal, 10)
            ZStack {
                if controller.tabs.isEmpty { Text("选择主机并打开 SSH。不会恢复先前会话。").frame(maxWidth: .infinity, maxHeight: .infinity) }
                ForEach(controller.tabs) { tab in
                    NativeWorkspacePage(id: "workspace.session." + tab.id.uuidString,
                                        isVisible: controller.workspaceVisible && controller.selectedTabID == tab.id, appearance: .darkAqua) {
                        SessionDetailView(tab: tab, controller: controller)
                    }
                }
            }
        }
    }
}
private struct SessionTabButton: View {
    @ObservedObject var tab: SessionTab
    @ObservedObject var controller: SessionController
    var body: some View {
        HStack(spacing: 2) {
            NativeButton(title: (controller.selectedTabID == tab.id ? "● " : "") + tab.title,
                         id: "tab.select." + tab.id.uuidString) { controller.select(tab.id) }.fixedSize()
            NativeButton(title: "×", id: "tab.close." + tab.id.uuidString) { Task { await controller.closeTab(tab.id) } }.fixedSize()
        }.help(tab.status)
    }
}
private struct SessionDetailView: View {
    @ObservedObject var tab: SessionTab
    @ObservedObject var controller: SessionController
    @State private var ownerWindow: NSWindow?
    @State private var showsDiagnostic = false
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if tab.state != .connected {
                HStack(spacing: 8) {
                    if tab.state == .preparing || tab.state == .connectionPending { ProgressView().controlSize(.small) }
                    Text(tab.status).font(.caption).lineLimit(1)
                    Spacer(minLength: 8)
                    if let prompt = tab.trust.first {
                        NativeButton(title: "核实主机身份…", id: "terminal.trust") { controller.present(.trust(prompt), tabID: tab.id) }.fixedSize()
                    }
                    if let prompt = tab.authentication {
                        NativeButton(title: "继续认证…", id: "terminal.authenticate") { controller.present(.authentication(prompt), tabID: tab.id) }.fixedSize()
                    }
                    if tab.canReconnect {
                        Button("手动重连") { controller.performTerminalAction(.reconnect, tabID: tab.id) }
                        Button("在保险箱查看此配置") { controller.showConfiguration(tabID: tab.id) }
                    }
                    if tab.isReusable { Button("取消连接") { controller.disconnect(tab.id) } }
                    Button { controller.performTerminalAction(.connectionInfo, tabID: tab.id) } label: { Image(systemName: "info.circle") }
                        .buttonStyle(.plain).help("连接信息").accessibilityLabel("连接信息")
                }.padding(.horizontal, 12).padding(.vertical, 6).background(DesktopStyle.terminalChrome)
                if tab.state == .preparing || tab.state == .connectionPending {
                    Text("如果 macOS 询问本地网络访问，请允许后继续；也可取消连接。")
                        .font(.caption2).foregroundStyle(.secondary).padding(.horizontal, 12).padding(.bottom, 6)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if tab.searchVisible {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    NativeField(placeholder: "搜索当前标签历史", id: "terminal.search", text: $tab.searchText,
                                focusRequest: tab.searchFocusRequest,
                                onSubmit: { tab.searchHistory(backwards: $0) }, onCancel: { tab.closeSearch() })
                        .frame(maxWidth: 360).frame(height: 25)
                    NativeButton(title: "上一处", id: "terminal.search.previous", enabled: !tab.searchText.isEmpty) { tab.searchHistory(backwards: true) }.fixedSize()
                    NativeButton(title: "下一处", id: "terminal.search.next", enabled: !tab.searchText.isEmpty) { tab.searchHistory() }.fixedSize()
                    if tab.searchFound == false { Text("无结果").font(.caption).foregroundStyle(.secondary) }
                    else if tab.searchFound == true { Text("\(tab.searchMatchIndex) / \(tab.searchMatchCount)\(tab.searchMatchCount == 1000 ? "+" : "")").font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
                    Spacer(minLength: 0)
                    NativeButton(title: "关闭搜索", id: "terminal.search.close") { tab.closeSearch() }.fixedSize()
                }.padding(.horizontal, 10).padding(.vertical, 6).background(DesktopStyle.terminalChrome)
            }
            if tab.issue != nil {
                VStack(alignment: .leading, spacing: 6) {
                    IssueView(issue: tab.issue) { tab.issue = nil }
                    if let detail = tab.driver?.failureDetail {
                        Button(showsDiagnostic ? "收起脱敏详情" : "查看脱敏详情") { showsDiagnostic.toggle() }.font(.caption)
                        if showsDiagnostic { Text(verbatim: detail.diagnostic).font(.caption.monospaced()).textSelection(.enabled) }
                    }
                }.padding(8).background(DesktopStyle.terminalChrome)
            }
            if let driver = tab.driver {
                RetainedTerminalView(terminal: driver.terminal, focusRequest: tab.terminalFocusRequest).frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(.horizontal, 4).padding(.vertical, 2)
            } else if tab.state == .preparing {
                ProgressView("准备连接…").frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView("连接尚未启动", systemImage: "terminal", description: Text("检查配置后手动重试。"))
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

/// Each page keeps the same transport-owned NSView mounted until the tab closes.
struct RetainedTerminalView: NSViewRepresentable {
    let terminal: NativeTerminalView
    var focusRequest: UUID? = nil
    func makeCoordinator() -> Coordinator { Coordinator() }
    func makeNSView(context: Context) -> NSView {
        let container = TerminalContainerView()
        container.clipsToBounds = true
        terminal.removeFromSuperview()
        terminal.frame = container.bounds; terminal.autoresizingMask = [.width, .height]
        container.addSubview(terminal)
        return container
    }
    func updateNSView(_ view: NSView, context: Context) {
        if terminal.superview !== view { terminal.removeFromSuperview(); view.addSubview(terminal) }
        terminal.frame = view.bounds
        if let focusRequest, context.coordinator.focusRequest != focusRequest {
            context.coordinator.focusRequest = focusRequest
            Task { @MainActor [weak terminal] in
                guard let terminal, !terminal.isHiddenOrHasHiddenAncestor,
                      let window = terminal.window, window.attachedSheet == nil else { return }
                _ = window.makeFirstResponder(terminal)
            }
        }
    }
    final class Coordinator { var focusRequest: UUID? }
}
@MainActor private final class TerminalContainerView: NSView {
    override func layout() { super.layout(); subviews.first?.frame = bounds }
}

private struct TrustChallengeView: View {
    @ObservedObject var tab: SessionTab
    let controller: SessionController
    let prompt: SessionTrustPrompt
    @State private var submitting = false
    @State private var management = false
    @State private var copiedFingerprint = false
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(prompt.changed == nil ? "首次连接主机身份" : "主机密钥已变化，连接已阻止").font(.title2).bold()
            Text(tab.title).font(.headline)
            Text(verbatim: prompt.host.address.value + ":" + String(prompt.host.port.value)).textSelection(.enabled)
            Text(verbatim: prompt.algorithm).font(.system(.body, design: .monospaced))
            if let changed = prompt.changed {
                Text("已知指纹").font(.caption).foregroundStyle(.secondary)
                Text(verbatim: changed.expectedFingerprint).font(.body.monospaced()).textSelection(.enabled)
            }
            HStack {
                Text(prompt.changed == nil ? "服务器指纹" : "本次指纹").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button(copiedFingerprint ? "已复制指纹" : "复制指纹", systemImage: copiedFingerprint ? "checkmark" : "doc.on.doc") {
                    NSPasteboard.general.clearContents()
                    copiedFingerprint = NSPasteboard.general.setString(prompt.fingerprint, forType: .string)
                }.buttonStyle(.borderless).accessibilityIdentifier("trust.copyFingerprint")
            }
            Text(verbatim: prompt.fingerprint).font(.body.monospaced()).textSelection(.enabled)
            Text(prompt.changed == nil ? "请核对服务器指纹。仅此次继续不会保存；添加后，后续连接可使用此密钥。" : "服务器身份与保存记录不一致。请核实后在已知主机中处理，当前连接已阻止。")
            DisclosureGroup("连接详情") { Text(verbatim: prompt.source).font(.caption).foregroundStyle(.secondary) }
            IssueView(issue: tab.issue) { tab.issue = nil }
            HStack {
                NativeButton(title: "关闭", id: "trust.cancel", enabled: !submitting) { controller.cancelTrust(prompt, tabID: tab.id); dismiss() }.fixedSize()
                if prompt.changed == nil {
                    NativeButton(title: "仅此次继续", id: "trust.once", enabled: !submitting) { accept(.once) }.fixedSize()
                    NativeButton(title: "添加并继续", id: "trust.accept", enabled: !submitting, isDefault: true) { accept(.persistent) }.fixedSize()
                } else if controller.trustEnvironment != nil {
                    Button("打开已知主机管理…") { management = true }
                }
            }
        }.padding(24).frame(width: 650)
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
    @ObservedObject var tab: SessionTab
    let controller: SessionController
    let prompt: SessionAuthenticationPrompt
    @State private var answers: [String]
    @State private var presentationHeight: CGFloat
    @FocusState private var focusedIndex: Int?
    var dismiss: () -> Void
    init(tab: SessionTab, controller: SessionController, prompt: SessionAuthenticationPrompt, dismiss: @escaping () -> Void) {
        self.tab = tab; self.controller = controller; self.prompt = prompt; self.dismiss = dismiss
        let parentHeight = NSApplication.shared.mainWindow?.contentView?.bounds.height ?? 720
        let expanded: Bool
        if case .keyboard(_, _, let fields) = prompt.payload { expanded = fields.count > 2 } else { expanded = false }
        _presentationHeight = State(initialValue: expanded ? min(680, max(420, parentHeight - 60)) : 320)
        let count: Int
        switch prompt.payload {
        case .keyboard(_, _, let fields): count = fields.count
        case .legacyAskpass(let kind, _): count = kind == .unknownMasked ? 1 : 0
        case .initialPassword, .privateKeyPassphrase: count = 1
        }
        _answers = State(initialValue: Array(repeating: "", count: count))
    }
    private var title: String {
        switch prompt.payload {
        case .initialPassword: "输入本次连接密码"
        case .privateKeyPassphrase: "解锁受管理 SSH 私钥"
        case .keyboard(_, _, let fields): fields.isEmpty ? "服务器认证通知" : "服务器要求进一步验证"
        case .legacyAskpass: prompt.kind == .notification ? "认证通知" : (prompt.kind == .confirmation ? "认证确认" : "人工认证输入")
        }
    }
    private var explanation: String {
        switch prompt.payload {
        case .initialPassword: "密码仅用于当前连接，不会保存。"
        case .privateKeyPassphrase: "口令仅用于解锁本次连接使用的密钥，不会保存。"
        case .keyboard: "请按服务器提示完成本轮验证。附加回答不会保存。"
        case .legacyAskpass: "请按服务器提示完成当前连接的验证。本次回答不会保存。"
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title).font(.title2).bold()
            Text(tab.title + " · " + (tab.host?.vaultEndpoint ?? "当前会话")).font(.caption)
            Text(explanation).font(.caption).foregroundStyle(.secondary)
            ScrollView { fields.frame(maxWidth: .infinity, alignment: .leading) }
                .frame(minHeight: 100, maxHeight: .infinity)
                .accessibilityIdentifier("authentication.fields.viewport")
            IssueView(issue: tab.issue) { tab.issue = nil }
            HStack {
                NativeButton(title: "取消本次连接", id: "authentication.cancel") { clear(); controller.cancelChallenge(prompt, tabID: tab.id); dismiss() }.fixedSize()
                if case .legacyAskpass(let kind, _) = prompt.payload, kind == .confirmation {
                    NativeButton(title: "拒绝", id: "authentication.decline") { submit(.legacy(.confirm(false))) }.fixedSize()
                    NativeButton(title: "确认", id: "authentication.confirm", isDefault: true) { submit(.legacy(.confirm(true))) }.fixedSize()
                } else {
                    NativeButton(title: answers.isEmpty ? "已阅，继续" : "继续", id: "authentication.submit", isDefault: true) { sendAnswers() }.fixedSize()
                }
            }
        }.padding(24).frame(width: 610, height: presentationHeight)
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
            case .legacyAskpass(_, let text):
                Text(verbatim: text).textSelection(.enabled)
                if !answers.isEmpty { SecureField("仅本次回答", text: $answers[0]).focused($focusedIndex, equals: 0) }
            }
        }.textFieldStyle(.roundedBorder)
            // The native text input system commits marked text before onSubmit;
            // no raw Return monitor or global shortcut bypasses that handling.
            .onSubmit { sendAnswers() }
    }
    private func clear() { answers = Array(repeating: "", count: answers.count) }
    private func sendAnswers() {
        if case .legacyAskpass(let kind, _) = prompt.payload {
            if kind == .notification { submit(.legacy(.acknowledge)); return }
            do { let secret = try AuthenticationSecret(Data((answers.first ?? "").utf8)); clear(); submit(.legacy(.manual(secret))) }
            catch { clear(); tab.issue = AppIssue(code: "authentication.inputBounds", message: "旧 Askpass 输入最多 1023 字节且不含 NUL 或换行；未发送。") }
        } else {
            guard answers.allSatisfy({ $0.utf8.count <= 65536 }) else { clear(); tab.issue = AppIssue(code: "authentication.inputBounds", message: "每个回答最多 65536 UTF-8 字节；未发送。"); return }
            let values = answers.map { OpenLXSSHSecurity.SecretBytes(utf8: $0) }; clear(); submit(.answers(values))
        }
    }
    private func submit(_ answer: SessionAuthenticationAnswer) {
        clear(); if controller.respond(answer, to: prompt, tabID: tab.id) { dismiss() }
    }
}
