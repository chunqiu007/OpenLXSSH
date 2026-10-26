import AppKit
import SwiftUI
import OpenLXSSHTransport

struct SessionWorkspaceView: View {
    @ObservedObject var controller: SessionController
    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal) {
                HStack(spacing: 6) {
                    ForEach(controller.tabs) { tab in
                        SessionTabButton(tab: tab, controller: controller)
                    }
                }.padding(6)
            }.frame(height: 44)
            Divider()
            IssueView(issue: controller.issue) { controller.issue = nil }.padding(.horizontal, 10)
            if let tab = controller.selectedTab {
                SessionDetailView(tab: tab, controller: controller).id(tab.id)
            } else { Text("选择主机并打开 SSH。不会恢复先前会话。").frame(maxWidth: .infinity, maxHeight: .infinity) }
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
private enum SessionDialog: Identifiable {
    case trust(SessionTrustPrompt), authentication(SessionAuthenticationPrompt)
    var id: UUID { switch self { case .trust(let p): p.id; case .authentication(let p): p.id } }
}
private struct SessionDetailView: View {
    @ObservedObject var tab: SessionTab
    @ObservedObject var controller: SessionController
    @State private var search = ""
    @State private var found: Bool?
    @State private var dialog: SessionDialog?
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(tab.status).font(.caption)
                Spacer()
                NativeButton(title: "断开", id: "terminal.disconnect", enabled: tab.isReusable) { controller.disconnect(tab.id) }.fixedSize()
                NativeButton(title: "手动重连", id: "terminal.reconnect", enabled: tab.canReconnect) { controller.reconnect(tab.id) }.fixedSize()
            }
            HStack {
                NativeButton(title: "复制", id: "terminal.copy", enabled: tab.driver != nil) { tab.driver?.terminal.copy(NSNull()) }.fixedSize()
                NativeButton(title: "粘贴", id: "terminal.paste", enabled: tab.isReusable) {
                    if let text = NSPasteboard.general.string(forType: .string) { tab.driver?.terminal.pasteFromApplication(text) }
                }.fixedSize()
                NativeField(placeholder: "当前标签历史搜索（不持久化）", id: "terminal.search", text: $search).frame(height: 25)
                NativeButton(title: "上一处", id: "terminal.search.previous", enabled: !search.isEmpty) { found = tab.driver?.terminal.search(search, backwards: true) }.fixedSize()
                NativeButton(title: "下一处", id: "terminal.search.next", enabled: !search.isEmpty) { found = tab.driver?.terminal.search(search) }.fixedSize()
            }
            if found == false { Text("未找到匹配内容").font(.caption).foregroundStyle(.secondary) }
            if let prompt = tab.trust.first {
                NativeButton(title: "核实主机身份…", id: "terminal.trust") { dialog = .trust(prompt) }.fixedSize()
            }
            if let prompt = tab.authentication {
                NativeButton(title: "继续认证…", id: "terminal.authenticate") { dialog = .authentication(prompt) }.fixedSize()
            }
            Text("只管理最外层直连。内层 SSH / sudo / MFA 在终端手动输入，绝不扫描终端提示投递本机秘密。macOS 26 自动密码尚未列入验证白名单时会回退人工；不会无限尝试。")
                .font(.caption2).foregroundStyle(.secondary)
            IssueView(issue: tab.issue) { tab.issue = nil }
            if let driver = tab.driver {
                RetainedTerminalView(terminal: driver.terminal).frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if tab.state == .preparing {
                ProgressView("准备受控 SSH 配置…").frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Text("未启动 SSH。可修正配置或签名条件后手动重试。").frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }.padding(10)
        .nativeSheet(item: $dialog) { value in
            switch value {
            case .trust(let prompt): TrustChallengeView(tab: tab, controller: controller, prompt: prompt) { dialog = nil }
            case .authentication(let prompt): AuthenticationChallengeView(tab: tab, controller: controller, prompt: prompt) { dialog = nil }
            }
        }
        .onChange(of: tab.state) { _, _ in
            switch dialog {
            case .trust(let prompt): if !tab.trust.contains(prompt) { dialog = nil }
            case .authentication(let prompt): if tab.authentication != prompt { dialog = nil }
            case nil: break
            }
        }
    }
}

/// The same transport-owned NSView is reattached, not reconstructed, on tab switching.
struct RetainedTerminalView: NSViewRepresentable {
    let terminal: NativeTerminalView
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
    }
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
