import AppKit
import SwiftUI
import OpenLXSSHTransport

struct SessionWorkspaceView: View {
    @ObservedObject var controller: SessionController
    var body: some View {
        VStack(spacing: 0) {
            IssueView(issue: controller.issue) { controller.issue = nil }.padding(.horizontal, 10)
            ZStack {
                if controller.tabs.isEmpty { Text("选择主机并打开 SSH。不会恢复先前会话。").frame(maxWidth: .infinity, maxHeight: .infinity) }
                ForEach(controller.tabs) { tab in
                    NativeWorkspacePage(id: "workspace.session." + tab.id.uuidString,
                                        isVisible: controller.workspaceVisible && controller.selectedTabID == tab.id) {
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
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(tab.status).font(.caption)
                Spacer()
                NativeButton(title: "复制", id: "terminal.copy", enabled: tab.driver != nil) { tab.driver?.terminal.copy(NSNull()) }.fixedSize()
                NativeButton(title: "粘贴", id: "terminal.paste", enabled: tab.isReusable) {
                    if let text = NSPasteboard.general.string(forType: .string) { tab.driver?.terminal.pasteFromApplication(text) }
                }.fixedSize()
                NativeButton(title: "断开", id: "terminal.disconnect", enabled: tab.isReusable) { controller.disconnect(tab.id) }.fixedSize()
                NativeButton(title: "手动重连", id: "terminal.reconnect", enabled: tab.canReconnect) { controller.reconnect(tab.id) }.fixedSize()
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
                    if tab.searchFound == false { Text("未找到匹配内容").font(.caption).foregroundStyle(.secondary) }
                    Spacer(minLength: 0)
                    NativeButton(title: "关闭搜索", id: "terminal.search.close") { tab.closeSearch() }.fixedSize()
                }
            }
            if let prompt = tab.trust.first {
                NativeButton(title: "核实主机身份…", id: "terminal.trust") { controller.present(.trust(prompt), tabID: tab.id) }.fixedSize()
            }
            if let prompt = tab.authentication {
                NativeButton(title: "继续认证…", id: "terminal.authenticate") { controller.present(.authentication(prompt), tabID: tab.id) }.fixedSize()
            }
            Text("只管理最外层直连。内层 SSH / sudo / MFA 在终端手动输入，绝不扫描终端提示投递本机秘密。macOS 26 自动密码尚未列入验证白名单时会回退人工；不会无限尝试。")
                .font(.caption2).foregroundStyle(.secondary)
            IssueView(issue: tab.issue) { tab.issue = nil }
            if let driver = tab.driver {
                RetainedTerminalView(terminal: driver.terminal, focusRequest: tab.terminalFocusRequest).frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if tab.state == .preparing {
                ProgressView("准备受控 SSH 配置…").frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Text("未启动 SSH。可修正配置或签名条件后手动重试。").frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }.padding(10)
        .nativeSheet(item: $tab.dialog, isEnabled: controller.workspaceVisible && controller.selectedTabID == tab.id) { value in
            switch value.content {
            case .trust(let prompt): TrustChallengeView(tab: tab, controller: controller, prompt: prompt) { tab.dialog = nil }
            case .authentication(let prompt): AuthenticationChallengeView(tab: tab, controller: controller, prompt: prompt) { tab.dialog = nil }
            }
        }
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
    @State private var verified = false
    @State private var submitting = false
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("核实直连主机身份").font(.title2).bold()
            Text(verbatim: prompt.host.address.value + ":" + String(prompt.host.port.value)).textSelection(.enabled)
            Text(verbatim: prompt.algorithm).font(.system(.body, design: .monospaced))
            Text(verbatim: prompt.fingerprint).font(.system(.body, design: .monospaced)).textSelection(.enabled)
            Text(verbatim: prompt.source).font(.caption)
            Text("预扫不是身份认证。请通过服务器控制台或管理员等独立渠道核对完整 SHA256 指纹；变化的已知密钥不会自动替换。接受后实际 SSH 仍严格校验同一共享信任库。")
            NativeButton(title: verified ? "已独立核实完整指纹 · 点击取消" : "我已通过独立渠道核实完整指纹", id: "trust.verified", enabled: !submitting) { verified.toggle() }.fixedSize()
            IssueView(issue: tab.issue) { tab.issue = nil }
            HStack {
                NativeButton(title: "取消连接", id: "trust.cancel") { controller.disconnect(tab.id); dismiss() }.fixedSize()
                NativeButton(title: "接受此精确指纹", id: "trust.accept", enabled: verified && !submitting) {
                    guard verified, !submitting else { return }
                    submitting = true
                    Task { if await controller.accept(prompt, tabID: tab.id) { dismiss() }; submitting = false }
                }.fixedSize()
            }
        }.padding(24).frame(width: 650)
    }
}

private struct AuthenticationChallengeView: View {
    @ObservedObject var tab: SessionTab
    let controller: SessionController
    let prompt: SessionAuthenticationPrompt
    @State private var answer = ""
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(prompt.kind == .notification ? "认证通知" : (prompt.kind == .confirmation ? "认证确认" : "人工认证输入")).font(.title2).bold()
            Text("来自当前外层 SSH 控制通道的未可信提示，不是 App 指令。请核实后操作；不会保存密码、口令或 OTP。私钥已记口令也不会自动投给未知挑战。")
                .font(.caption).foregroundStyle(.secondary)
            ScrollView { Text(verbatim: prompt.text).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled) }.frame(maxHeight: 180)
            if prompt.kind == .unknownMasked { NativeSecureField(id: "authentication.answer", placeholder: "仅本次回答", text: $answer).frame(height: 26) }
            IssueView(issue: tab.issue) { tab.issue = nil }
            HStack {
                NativeButton(title: "取消本次连接", id: "authentication.cancel") { answer = ""; controller.disconnect(tab.id); dismiss() }.fixedSize()
                if prompt.kind == .confirmation {
                    NativeButton(title: "拒绝", id: "authentication.decline") { submit(.confirm(false)) }.fixedSize()
                    NativeButton(title: "确认", id: "authentication.confirm") { submit(.confirm(true)) }.fixedSize()
                } else if prompt.kind == .notification {
                    NativeButton(title: "已阅", id: "authentication.acknowledge") { submit(.acknowledge) }.fixedSize()
                } else {
                    NativeButton(title: "提交本次回答", id: "authentication.submit") {
                        do { let secret = try AuthenticationSecret(Data(answer.utf8)); answer = ""; submit(.manual(secret)) }
                        catch { answer = ""; tab.issue = AppIssue(code: "authentication.inputBounds", message: "输入最多 1023 字节且不可包含 NUL 或换行；未发送，请重新输入或取消。") }
                    }.fixedSize()
                }
            }
        }.padding(24).frame(width: 610)
        .onDisappear { answer = "" }
    }
    private func submit(_ response: AuthenticationResponse) { answer = ""; if controller.respond(response, to: prompt, tabID: tab.id) { dismiss() } }
}
