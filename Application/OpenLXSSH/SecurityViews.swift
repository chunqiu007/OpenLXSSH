import AppKit
import SwiftUI
import OpenLXSSHCore
import OpenLXSSHSecurity

struct KeychainPolicyNotice: View {
    var body: some View {
        Text("秘密仅保存在当前 Mac 的系统 file-based Keychain，不同步。Keychain 锁定/ACL 拒绝时需人工输入；屏幕锁定不等于 Keychain 已锁定。不提供 OTP 保存入口，也不承诺 Swift 临时输入副本彻底擦除。")
            .font(.caption).foregroundStyle(.secondary)
    }
}

private struct SecurityPresentation: Identifiable {
    enum Content { case creation(KeyCreation), deletion(UUID), recovery(RecoveryReview), publicKey(UUID) }
    let id = UUID()
    let content: Content
}

struct SecurityManagerView: View {
    @ObservedObject var app: AppModel
    @StateObject private var model: SecurityViewModel
    @State private var presentation: SecurityPresentation?
    var dismiss: () -> Void
    let embedded: Bool
    init(app: AppModel, embedded: Bool = false, dismiss: @escaping () -> Void) {
        self.app = app; self.dismiss = dismiss; self.embedded = embedded
        _model = StateObject(wrappedValue: SecurityViewModel(coordinator: app.security))
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("密钥与凭据").font(.title2).bold()
            KeychainPolicyNotice()
            HStack {
                NativeButton(title: "生成 Ed25519…", id: "keys.generate", enabled: !model.busy) { presentation = SecurityPresentation(content: .creation(.generate)) }.fixedSize()
                NativeButton(title: "导入 RSA / Ed25519…", id: "keys.import", enabled: !model.busy) { chooseImport() }.fixedSize()
                Spacer()
                NativeButton(title: "刷新", id: "security.refresh", enabled: !model.busy) { Task { await model.load() } }.fixedSize()
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text("App 管理的私钥").font(.headline)
                    if model.metadata.keys.isEmpty { Text("尚无密钥。导入使用 App 专属副本，原文件不会改动。").foregroundStyle(.secondary) }
                    ForEach(model.metadata.keys) { key in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(key.algorithm.rawValue.uppercased() + " · " + key.id.uuidString.prefix(8)).font(.headline)
                            Text("主机引用 \(model.metadata.hosts.filter { $0.keyRef == key.id }.count) · " + (key.passphraseCredentialRef == nil ? "口令未记住" : "口令已关联 Keychain"))
                                .font(.caption).foregroundStyle(.secondary)
                            HStack {
                                NativeButton(title: "查看公钥", id: "key.public." + key.id.uuidString) { presentation = SecurityPresentation(content: .publicKey(key.id)) }.fixedSize()
                                NativeButton(title: "复制公钥", id: "key.copy." + key.id.uuidString) { _ = model.copyPublicKey(key.id) }.fixedSize()
                                NativeButton(title: "删除…", id: "key.delete." + key.id.uuidString, enabled: !model.busy) { presentation = SecurityPresentation(content: .deletion(key.id)) }.fixedSize()
                            }
                            if key.passphraseCredentialRef != nil {
                                NativeButton(title: "忘记已记住口令", id: "key.forgetPassphrase." + key.id.uuidString, enabled: !model.busy) {
                                    Task { _ = await model.forgetKeyPassphrase(key.id); await app.reload() }
                                }.fixedSize()
                            }
                        }.padding(12).frame(maxWidth: .infinity, alignment: .leading).background(.quaternary).clipShape(RoundedRectangle(cornerRadius: 6))
                    }
                    Divider()
                    Text("密码关联").font(.headline)
                    ForEach(model.metadata.hosts.filter { $0.credentialRef != nil }) { host in
                        HStack {
                            Text(host.name)
                            Spacer()
                            NativeButton(title: "忘记此主机密码", id: "credential.forget." + host.id.uuidString, enabled: !model.busy) {
                                Task { _ = await model.forget(host.id); await app.reload() }
                            }.fixedSize()
                        }
                    }
                    Text("删除主机不会删除共享秘密。下方只允许删除未被任何主机/密钥引用的凭据；在用记录会被 Core 拒绝。")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(model.metadata.credentials) { credential in
                        HStack {
                            Text((credential.purpose == .password ? "密码" : "私钥口令") + " · " + credential.id.uuidString.prefix(8)).font(.caption)
                            Spacer()
                            NativeButton(title: "删除未使用凭据", id: "credential.delete." + credential.id.uuidString, enabled: !model.busy) { Task { _ = await model.deleteCredential(credential.id) } }.fixedSize()
                        }
                    }
                    recoveryRecords
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(minHeight: 220, maxHeight: 390)
            if model.pendingCount > 0 {
                HStack {
                    Text("待恢复/清理 \(model.pendingCount) 项（创建结果待核实 \(model.uncertainCount) 项）。").font(.caption)
                    NativeButton(title: "重试精确清理", id: "security.cleanup", enabled: !model.busy) { Task { await model.retry() } }.fixedSize()
                }
            }
            if model.copied { Text("仅公钥已复制到剪贴板。").font(.caption).foregroundStyle(.secondary) }
            IssueView(issue: model.issue) { model.issue = nil }
            HStack { Spacer(); NativeButton(title: "完成", id: "security.done", enabled: !model.busy) { dismiss() }.fixedSize() }
        }.padding(24).frame(width: embedded ? nil : 660).frame(maxWidth: embedded ? .infinity : nil)
        .task { await model.retry(); await model.load() }
        // The AppKit presenter owns the exact child window throughout async refreshes.
        .nativeSheet(item: $presentation) { value in
            switch value.content {
            case .creation(let creation):
                KeyCreationEditor(model: model, creation: creation) {
                    presentation = nil
                    Task { await app.reload() }
                }
            case .deletion(let id):
                SecurityKeyDeletionView(app: app, model: model, keyID: id) { presentation = nil }
            case .recovery(let review):
                SecurityRecoveryView(model: model, review: review) { presentation = nil }
            case .publicKey(let id):
                SecurityPublicKeyView(model: model, keyID: id) { presentation = nil }
            }
        }
    }
    @ViewBuilder private var recoveryRecords: some View {
        if !model.recoveryReviews.isEmpty {
            Divider()
            Text("恢复记录核对").font(.headline)
            Text("prepared 只表示创建确认前中断，不证明资源存在或归属，因此不会自动删除文件或 Keychain。这里只核对已知配置与精确 UUID，不扫描外部资源。")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(model.recoveryReviews) { review in
                VStack(alignment: .leading, spacing: 6) {
                    Text(review.intent.kind.rawValue + " · " + review.id.uuidString).font(.caption.monospaced()).textSelection(.enabled)
                    Text(recoveryStatus(review)).font(.caption).foregroundStyle(.secondary)
                    NativeButton(title: "核对恢复记录…", id: "recovery.review." + review.id.uuidString, enabled: !model.busy) { presentation = SecurityPresentation(content: .recovery(review)) }.fixedSize()
                }
            }
        }
    }
    private func chooseImport() {
        let panel = NSOpenPanel()
        panel.title = "选择标准 OpenSSH 私钥（仅创建 App 副本）"
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.begin { response in
            if response == .OK, let url = panel.url { presentation = SecurityPresentation(content: .creation(.importFile(url))) }
        }
    }
}

private func recoveryStatus(_ review: RecoveryReview) -> String {
    "状态：" + review.intent.state.rawValue + "；Core 引用：" + (review.metadataRegistered ? "有" : "无") + "；清理票据：" + (review.hasCoreTicket ? "有" : "无")
}

private struct SecurityKeyDeletionView: View {
    @ObservedObject var app: AppModel
    @ObservedObject var model: SecurityViewModel
    let keyID: UUID
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("删除 App 管理的私钥？").font(.headline)
            Text("只删除所选 UUID 的 App 副本及不再共享的口令。仍被主机引用时拒绝删除；导入源文件不受影响。")
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                NativeButton(title: "取消", id: "key.delete.cancel") { dismiss() }.fixedSize()
                NativeButton(title: "删除", id: "key.delete.confirm", enabled: !model.busy) {
                    Task { if await model.deleteKey(keyID) { dismiss(); await app.reload() } }
                }.fixedSize()
            }
        }.padding(24).frame(width: 430)
    }
}

private struct SecurityPublicKeyView: View {
    @ObservedObject var model: SecurityViewModel
    let keyID: UUID
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("公钥").font(.title2)
            Text(model.publicKeys[keyID] ?? "无法读取该公钥").font(.system(.body, design: .monospaced)).textSelection(.enabled)
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                NativeButton(title: "复制公钥", id: "public.copy") { _ = model.copyPublicKey(keyID) }.fixedSize()
                NativeButton(title: "关闭", id: "public.close") { dismiss() }.fixedSize()
            }
        }.padding(24).frame(width: 620)
    }
}

private struct SecurityRecoveryView: View {
    @ObservedObject var model: SecurityViewModel
    let review: RecoveryReview
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("核对非秘密恢复记录").font(.title2).bold()
            Text(review.intent.kind.rawValue + " · " + review.id.uuidString).font(.caption.monospaced()).textSelection(.enabled)
            Text(recoveryStatus(review))
            Text("此记录不证明对应资源存在，也不证明属于本次创建。丢弃仅停止显示这条非秘密恢复记录，不删除任何文件、Keychain 项或已保存配置；可能存在的外部资源仍会保留。")
            if !review.canDiscard { Text("仅未关联 Core 引用或票据的 prepared 记录可丢弃。created/deleting 必须走精确清理。请刷新核对。").font(.caption).foregroundStyle(.secondary) }
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                NativeButton(title: "取消", id: "recovery.cancel") { dismiss() }.fixedSize()
                NativeButton(title: "仅丢弃恢复记录，不删除任何文件/Keychain", id: "recovery.discard", enabled: !model.busy && review.canDiscard) {
                    Task { if await model.discardPrepared(review) { dismiss() } }
                }.fixedSize()
            }
        }.padding(24).frame(width: 620)
    }
}

struct KeyCreationEditor: View {
    @ObservedObject var model: SecurityViewModel
    let creation: KeyCreation
    @State private var encrypted = true
    @State private var remember = false
    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var operation: Task<Void, Never>?
    @State private var cancelRequested = false
    var dismiss: () -> Void
    private var generating: Bool { if case .generate = creation { return true }; return false }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(generating ? "生成 Ed25519" : "导入私钥副本").font(.title2).bold()
            if !generating { Text("源文件：" + sourceName).lineLimit(1).truncationMode(.middle) }
            NativeButton(title: encrypted ? "使用口令 · 点击选择无口令" : "明确选择无口令（磁盘私钥不加密）", id: "key.protection", enabled: !model.busy) {
                encrypted.toggle(); passphrase = ""; confirm = ""; remember = false
            }.fixedSize()
            if encrypted {
                NativeSecureField(id: "key.passphrase", placeholder: "私钥口令", text: $passphrase).frame(height: 26)
                if generating { NativeSecureField(id: "key.confirm", placeholder: "再次输入口令", text: $confirm).frame(height: 26) }
                NativeButton(title: remember ? "已授权记住口令 · 点击取消" : "记住口令（默认不保存）", id: "key.remember", enabled: !model.busy) { remember.toggle() }.fixedSize()
            }
            Text("只支持 OpenSSH RSA/Ed25519。加密导入口令错误可重输或取消。公钥可查看/复制；不提供私钥导出或备份。")
                .font(.caption).foregroundStyle(.secondary)
            KeychainPolicyNotice()
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                Spacer()
                NativeButton(title: "取消", id: "key.editor.cancel") {
                    cancelRequested = true; operation?.cancel(); passphrase = ""; confirm = ""
                    if !model.busy { dismiss() }
                }.fixedSize()
                NativeButton(title: generating ? "生成" : "导入", id: "key.create", enabled: !model.busy) {
                    guard !encrypted || (!passphrase.isEmpty && (!generating || passphrase == confirm)) else {
                        model.issue = AppIssue(code: "key.inputMismatch", message: "请输入非空口令，并确保两次输入一致。"); return
                    }
                    let secret = encrypted ? SecretBytes(utf8: passphrase) : nil
                    let protection: KeyProtection = secret.map { .passphrase($0) } ?? .unencrypted
                    let saved = remember ? secret : nil
                    passphrase = ""; confirm = ""
                    cancelRequested = false
                    operation = Task {
                        let success = await model.create(creation, protection: protection, remember: saved)
                        if success || cancelRequested { dismiss() }
                    }
                }.fixedSize()
            }
        }.padding(24).frame(width: 530)
        .onDisappear { passphrase = ""; confirm = ""; operation?.cancel() }
    }
    private var sourceName: String { if case .importFile(let url) = creation { return url.lastPathComponent }; return "" }
}
