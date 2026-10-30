import Combine
import Foundation
import SwiftUI
import OpenLXSSHTrust

@MainActor final class TrustManagementModel: ObservableObject {
    let environment: SessionEnvironment
    @Published var records: [TrustedHostKey] = []
    @Published var issue: AppIssue?
    @Published var pending: PendingTrustDecision?
    @Published var busy = false
    private var closed = false
    private var operation = UUID()
    init(environment: SessionEnvironment) { self.environment = environment }
    func load() async {
        do { let store = try await environment.trustStore(); records = try await store.records() }
        catch { issue = .session(error) }
    }
    func prepare(_ record: TrustedHostKey, line: String) async {
        guard !busy, !closed else { return }; busy = true; defer { busy = false }
        await cancel()
        let current = operation
        do {
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: line) }.value
            guard key.algorithm == record.key.algorithm else { throw HostTrustError.invalidPublicKey }
            let store = try await environment.trustStore()
            guard !closed, current == operation else { return }
            let decision = try await store.prepareReplacement(host: record.host, key: key, expectedCurrentFingerprint: record.key.fingerprint)
            guard !closed, current == operation else { await store.cancel(decision); return }
            pending = decision
            issue = nil
        } catch { issue = AppIssue(code: "trust.replacementRejected", message: "替换公钥无效、算法不一致或当前信任已变化。未修改信任库；请重新独立核实。") }
    }
    func confirm(_ decision: PendingTrustDecision) async -> Bool {
        guard !busy, !closed, pending == decision else { return false }
        busy = true; defer { busy = false }
        do {
            let store = try await environment.trustStore()
            _ = try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
            pending = nil; await load(); return true
        } catch { pending = nil; issue = .session(error); return false }
    }
    func cancel() async {
        operation = UUID()
        let old = pending; pending = nil
        if let old, let store = try? await environment.trustStore() { await store.cancel(old) }
    }
    func close() async { closed = true; await cancel() }
}

struct TrustManagementView: View {
    @StateObject private var model: TrustManagementModel
    @State private var selected: TrustedHostKey?
    @State private var replacement = ""
    @State private var verified = false
    var dismiss: () -> Void
    let embedded: Bool
    init(environment: SessionEnvironment, embedded: Bool = false, dismiss: @escaping () -> Void) {
        _model = StateObject(wrappedValue: TrustManagementModel(environment: environment)); self.dismiss = dismiss; self.embedded = embedded
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("可信主机管理").font(.title2).bold()
            Text("SSH 与后续 SFTP 共用这一份 App 专属信任库，不读取或改写 ~/.ssh。已知密钥变化会阻止连接；只有独立人工核实后才能精确替换。当前共享库不提供删除 API，不会另写 known_hosts 绕过。")
                .font(.caption).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if model.records.isEmpty { Text("暂无已信任记录。") }
                    ForEach(model.records, id: \.self) { record in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(verbatim: record.host.address.value + ":" + String(record.host.port.value))
                            Text(verbatim: record.key.algorithm + " · " + record.key.fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                            NativeButton(title: "人工核实后替换…", id: "trust.manage.replace." + record.key.fingerprint, enabled: !model.busy) {
                                Task { await model.cancel(); selected = record; replacement = ""; verified = false }
                            }.fixedSize()
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(height: 200)
            if let selected {
                Text("仅替换 " + selected.host.knownHostsName + " 的 " + selected.key.algorithm).font(.headline)
                NativeField(placeholder: "从独立可信渠道取得的新公钥：algorithm base64", id: "trust.replacement.public", text: $replacement).frame(height: 26)
                NativeButton(title: "核对新指纹", id: "trust.replacement.prepare", enabled: !model.busy) { verified = false; Task { await model.prepare(selected, line: replacement) } }.fixedSize()
            }
            if let pending = model.pending {
                Text(verbatim: "当前：" + (model.records.first { $0.host == pending.host && $0.key.algorithm == pending.algorithm }?.key.fingerprint ?? "已变化"))
                Text(verbatim: "新指纹：" + pending.fingerprint).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                NativeButton(title: verified ? "已独立核实 · 点击取消" : "确认已独立核实新指纹", id: "trust.replacement.verified") { verified.toggle() }.fixedSize()
                NativeButton(title: "精确替换此主机与算法", id: "trust.replacement.confirm", enabled: verified && !model.busy) {
                    guard verified, !model.busy else { return }
                    Task { if await model.confirm(pending) { selected = nil; replacement = ""; verified = false } }
                }.fixedSize()
            }
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                NativeButton(title: "刷新", id: "trust.manage.refresh", enabled: !model.busy) { Task { await model.load() } }.fixedSize()
                Spacer()
                NativeButton(title: "完成", id: "trust.manage.done", enabled: !model.busy) { Task { await model.close(); dismiss() } }.fixedSize()
            }
        }.padding(24).frame(width: embedded ? nil : 720).frame(maxWidth: embedded ? .infinity : nil)
        .task { await model.load() }
        .onDisappear { Task { await model.close() } }
    }
}
