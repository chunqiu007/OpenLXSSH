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
    enum Content { case creation(KeyCreation), deletion(UUID), recovery(RecoveryReview), publicKey(UUID), unlink(UUID) }
    let id = UUID()
    let content: Content
}

struct SecurityManagerView: View {
    @ObservedObject var app: AppModel
    @StateObject private var model: SecurityViewModel
    @StateObject private var presentations = PresentationOwner<SecurityPresentation.Content>()
    @State private var search = ""
    @State private var descending = false
    @StateObject private var selection = KeyLabelSelectionModel()
    var dismiss: () -> Void
    let embedded: Bool
    let searchFocusRequest: UUID?
    init(app: AppModel, embedded: Bool = false, searchFocusRequest: UUID? = nil, dismiss: @escaping () -> Void) {
        self.app = app; self.dismiss = dismiss; self.embedded = embedded
        self.searchFocusRequest = searchFocusRequest
        _model = StateObject(wrappedValue: SecurityViewModel(coordinator: app.security))
    }
    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("密钥与凭据").font(.system(size: 23, weight: .semibold))
                        Text("\(model.metadata.keys.count) 个已管理密钥 · \(model.metadata.credentials.count) 条凭据关联")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Menu {
                        Button("生成 Ed25519…") { presentCreation(.generate) }
                        Button("导入 RSA / Ed25519…") { chooseImport() }
                    } label: { Label("添加密钥", systemImage: "plus") }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.busy || app.isEngineeringPreview)
                    Button { Task { await model.load() } } label: { Image(systemName: "arrow.clockwise") }.help("刷新").disabled(model.busy)
                    if !embedded { Button("完成", action: dismiss).disabled(model.busy) }
                }
                HStack(spacing: 10) {
                    DesktopSearchField(placeholder: "搜索标签、算法或公钥指纹", id: "security.search", text: $search, focusRequest: searchFocusRequest, clearLabel: "清除密钥搜索")
                    Button { descending.toggle() } label: { Label("名称", systemImage: descending ? "arrow.down" : "arrow.up") }.fixedSize()
                }
            }.padding(.horizontal, 20).padding(.top, 18).padding(.bottom, 14)
            if app.isEngineeringPreview { Text(AppModel.engineeringPreviewUnavailableIssue.message).font(.caption).foregroundStyle(.secondary).padding(12) }
            if model.busy { ProgressView().controlSize(.small).padding(.bottom, 8) }
            if model.metadata.keys.isEmpty && model.metadata.credentials.isEmpty {
                ContentUnavailableView {
                    Label("添加密钥与凭据", systemImage: "key")
                } description: { Text(app.isEngineeringPreview ? "隔离预览未加载任何真实密钥或系统凭据；导入与生成不可用。" : "导入或生成 SSH 密钥。配置只保存在本机，秘密由系统 Keychain 按明确授权管理。") }
                actions: {
                    Button("生成 Ed25519…") { presentCreation(.generate) }.disabled(app.isEngineeringPreview)
                    Button("导入密钥…") { chooseImport() }.disabled(app.isEngineeringPreview)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HSplitView {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            if model.filteredKeys(search: search).isEmpty { Text("没有匹配的密钥").foregroundStyle(.secondary).padding() }
                            ForEach(model.filteredKeys(search: search, descending: descending)) { key in
                                let isSelected = selection.selectedKeyID == key.id
                                Button { selection.select(key) } label: {
                                    HStack(spacing: 12) {
                                        Image(systemName: "key.fill")
                                            .font(.system(size: 14, weight: .medium))
                                            .foregroundStyle(isSelected ? Color.accentColor : .secondary)
                                            .frame(width: 34, height: 34)
                                            .background(isSelected ? DesktopStyle.iconSurface : DesktopStyle.well, in: RoundedRectangle(cornerRadius: 8))
                                        VStack(alignment: .leading, spacing: 4) {
                                            HStack(spacing: 6) {
                                                Text(model.label(for: key))
                                                    .font(.system(size: 13, weight: .semibold))
                                                    .lineLimit(1)
                                                DesktopBadge(
                                                    text: key.algorithm.rawValue.uppercased() + (model.publicKeyBits[key.id].map { " · \($0) 位" } ?? ""),
                                                    color: isSelected ? .accentColor : .secondary,
                                                    fill: isSelected ? DesktopStyle.iconSurface : DesktopStyle.separator
                                                )
                                            }
                                            Text(model.fingerprints[key.id] ?? "公钥指纹不可用")
                                                .font(.caption2.monospaced())
                                                .foregroundStyle(.secondary)
                                                .lineLimit(1)
                                                .truncationMode(.middle)
                                        }
                                        Spacer(minLength: 4)
                                        DesktopBadge(text: "\(model.hostReferences(key.id).count) 台主机")
                                    }.padding(12).contentShape(Rectangle())
                                }.buttonStyle(.plain)
                                .background(isSelected ? DesktopStyle.selection : DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 10))
                                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(isSelected ? Color.accentColor.opacity(0.6) : DesktopStyle.border))
                                .contextMenu {
                                    Button("复制公钥") { _ = model.copyPublicKey(key.id) }
                                    Button("复制公钥指纹") { _ = model.copyFingerprint(key.id) }
                                    Button("查看引用") { selection.select(key) }
                                    Divider()
                                    Button("删除…", role: .destructive) { guard app.allowSensitivePreviewAction() else { return }; _ = presentations.present(.deletion(key.id)) }.disabled(app.isEngineeringPreview)
                                }
                            }
                            savedCredentials
                            recoveryRecords
                        }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(minWidth: 270, maxWidth: .infinity)
                    if let key = model.metadata.keys.first(where: { $0.id == selection.selectedKeyID }) {
                        Divider()
                        keyDetail(key).frame(minWidth: 310, idealWidth: 350, maxWidth: 390)
                    }
                }
            }
            if model.pendingCount > 0 {
                HStack {
                    Text("待恢复或清理 \(model.pendingCount) 项，其中创建结果待核实 \(model.uncertainCount) 项。").font(.caption)
                    Spacer()
                    Button("重试精确清理") { guard app.allowSensitivePreviewAction() else { return }; Task { await model.retry() } }.disabled(model.busy || app.isEngineeringPreview)
                }.padding(12)
            }
            if let notice = model.copyNotice { Text(notice).font(.caption).foregroundStyle(.secondary).padding(8) }
            IssueView(issue: model.issue) { model.issue = nil }.padding(.horizontal, 16)
        }.frame(width: embedded ? nil : 850).frame(minHeight: embedded ? 0 : 470, maxHeight: .infinity)
        .background(DesktopStyle.background)
        .task { presentations.setActive(app.workspacePage == .vault || !embedded); await model.load() }
        .onChange(of: app.workspacePage) { _, value in presentations.setActive(value == .vault || !embedded) }
        .onDisappear { presentations.setActive(false) }
        .nativeSheet(item: $presentations.item) { value in
            switch value.content {
            case .creation(let creation):
                KeyCreationEditor(model: model, creation: creation, ownsPresentation: { presentations.owns(value.id) }) {
                    guard presentations.owns(value.id) else { return }
                    presentations.dismiss(value.id)
                    if let outcome = model.lastCreatedKey { selection.select(id: outcome.id, label: model.lastCreatedKeyLabel) }
                    Task { _ = await app.reload() }
                }
            case .deletion(let id): SecurityKeyDeletionView(app: app, model: model, keyID: id, ownsPresentation: { presentations.owns(value.id) }) { presentations.dismiss(value.id) }
            case .recovery(let review): SecurityRecoveryView(model: model, review: review) { presentations.dismiss(value.id) }
            case .publicKey(let id): SecurityPublicKeyView(model: model, keyID: id, ownsPresentation: { presentations.owns(value.id) }) { presentations.dismiss(value.id) }
            case .unlink(let id): SecurityKeyUnlinkView(app: app, model: model, keyID: id, ownsPresentation: { presentations.owns(value.id) }) { presentations.dismiss(value.id) }
            }
        }
    }
    private func presentCreation(_ creation: KeyCreation) {
        guard app.allowSensitivePreviewAction() else { return }
        model.clearCreationResult(); _ = presentations.present(.creation(creation))
    }
    private func keyDetail(_ key: ManagedKeyReference) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "key.fill")
                        .font(.system(size: 16, weight: .medium))
                        .foregroundStyle(Color.accentColor)
                        .frame(width: 36, height: 36)
                        .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 9))
                    VStack(alignment: .leading, spacing: 2) {
                        Text("密钥详情").font(.headline)
                        Text(key.algorithm.rawValue.uppercased() + (model.publicKeyBits[key.id].map { " · \($0) 位" } ?? ""))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("公开标签").font(.caption).foregroundStyle(.secondary)
                    TextField("公开标签", text: Binding(get: { selection.labelDraft }, set: { selection.edit($0) }))
                        .textFieldStyle(.roundedBorder).accessibilityIdentifier("key.label")
                    Button("保存标签") {
                        guard let save = selection.captureSave(), save.keyID == key.id else { return }
                        Task {
                            let saved = await model.updateLabel(save.keyID, label: save.label)
                            selection.complete(save, succeeded: saved)
                            if saved { _ = await app.reload() }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(model.busy || !selection.hasChanges || (!selection.labelDraft.isEmpty && !VaultHostDraft.validText(selection.labelDraft, limit: 256)))
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(DesktopStyle.background, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.border))

                VStack(alignment: .leading, spacing: 8) {
                    Text("公钥指纹").font(.caption).foregroundStyle(.secondary)
                    Text(model.fingerprints[key.id] ?? "公钥指纹不可用")
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(DesktopStyle.border))
                    HStack(spacing: 8) {
                        Button("复制公钥") { _ = model.copyPublicKey(key.id) }
                        Button("复制指纹") { _ = model.copyFingerprint(key.id) }
                    }
                    Button("查看公钥正文…") { _ = presentations.present(.publicKey(key.id)) }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(DesktopStyle.background, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.border))

                VStack(alignment: .leading, spacing: 8) {
                    Text("引用主机（\(model.hostReferences(key.id).count)）").font(.headline)
                    if model.hostReferences(key.id).isEmpty {
                        Text("暂无主机引用此密钥").font(.caption).foregroundStyle(.secondary)
                    } else {
                        ForEach(model.hostReferences(key.id)) { host in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(host.name).font(.system(size: 13, weight: .medium))
                                Text(host.username + "@" + host.vaultEndpoint).font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 2)
                        }
                    }
                    if !model.hostReferences(key.id).isEmpty {
                        Button("处理并解除主机引用…") { guard app.allowSensitivePreviewAction() else { return }; _ = presentations.present(.unlink(key.id)) }.disabled(model.busy || app.isEngineeringPreview)
                    }
                    if key.passphraseCredentialRef != nil {
                        Button("忘记已记住口令") { guard app.allowSensitivePreviewAction() else { return }; Task { _ = await model.forgetKeyPassphrase(key.id); _ = await app.reload() } }.disabled(model.busy || app.isEngineeringPreview)
                    }
                    Button("删除密钥…", role: .destructive) { guard app.allowSensitivePreviewAction() else { return }; _ = presentations.present(.deletion(key.id)) }.disabled(model.busy || app.isEngineeringPreview)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(DesktopStyle.background, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.border))

                Text("标签不参与认证身份。公钥可复制；没有私钥复制或导出入口。").font(.caption).foregroundStyle(.secondary)
            }.padding(18).frame(maxWidth: .infinity, alignment: .leading)
        }.background(DesktopStyle.panel)
    }
    private var savedCredentials: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider(); Text("密码与口令关联").font(.headline)
            ForEach(model.metadata.hosts.filter { $0.credentialRef != nil }) { host in
                HStack { Text(host.name).lineLimit(1); Spacer(); Button("忘记此主机密码") { guard app.allowSensitivePreviewAction() else { return }; Task { _ = await model.forget(host.id); _ = await app.reload() } }.disabled(model.busy || app.isEngineeringPreview) }
            }
            ForEach(model.metadata.credentials) { credential in
                let hostCount = model.metadata.hosts.filter { $0.credentialRef == credential.id }.count
                let keyCount = model.metadata.keys.filter { $0.passphraseCredentialRef == credential.id }.count
                HStack {
                    VStack(alignment: .leading) {
                        Text((credential.purpose == .password ? "密码" : "私钥口令") + " · " + credential.id.uuidString.prefix(8)).font(.caption)
                        Text("\(hostCount) 台主机 · \(keyCount) 个密钥引用").font(.caption2).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("删除未使用关联") { guard app.allowSensitivePreviewAction() else { return }; Task { _ = await model.deleteCredential(credential.id) } }.disabled(model.busy || app.isEngineeringPreview || hostCount + keyCount > 0)
                }
            }
            Text("这里只列 App 拥有的引用，不枚举系统 Keychain。忘记共享凭据时只解除当前主机或密钥的授权。").font(.caption).foregroundStyle(.secondary)
        }
    }
    @ViewBuilder private var recoveryRecords: some View {
        if !model.recoveryReviews.isEmpty {
            Divider(); Text("恢复记录核对").font(.headline)
            ForEach(model.recoveryReviews) { review in
                VStack(alignment: .leading, spacing: 6) {
                    Text(review.intent.kind.rawValue + " · " + review.id.uuidString.prefix(8)).font(.caption.monospaced())
                    Text(recoveryStatus(review)).font(.caption).foregroundStyle(.secondary)
                    Button("核对恢复记录…") { guard app.allowSensitivePreviewAction() else { return }; _ = presentations.present(.recovery(review)) }.disabled(model.busy || app.isEngineeringPreview)
                }
            }
        }
    }
    private func chooseImport() {
        guard app.allowSensitivePreviewAction() else { return }
        let panel = NSOpenPanel(); panel.title = "选择标准 OpenSSH 私钥（创建 App 副本）"
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        let ticket = presentations.capture()
        panel.begin { response in
            guard presentations.isCurrent(ticket), response == .OK, let url = panel.url else { return }
            presentCreation(.importFile(url))
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
    var ownsPresentation: @MainActor () -> Bool = { true }
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("删除 App 管理的私钥？").font(.headline)
            Text("只删除所选 UUID 的 App 副本及不再共享的口令。导入源文件不受影响。")
            if !model.hostReferences(keyID).isEmpty {
                Text("仍有 \(model.hostReferences(keyID).count) 台主机引用，默认阻止删除。请先在详情中明确处理认证方式并解除关联。").foregroundStyle(.secondary)
                ForEach(model.hostReferences(keyID)) { host in Text(host.name + " · " + host.vaultEndpoint).font(.caption) }
            }
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                NativeButton(title: "取消", id: "key.delete.cancel") { dismiss() }.fixedSize()
                NativeButton(title: "删除", id: "key.delete.confirm", enabled: !model.busy && model.hostReferences(keyID).isEmpty) {
                    Task { guard app.allowSensitivePreviewAction(), ownsPresentation() else { return }; if await model.deleteKey(keyID) { if ownsPresentation() { dismiss() }; await app.reload() } }
                }.fixedSize()
            }
        }.padding(24).frame(width: 430)
    }
}

private struct SecurityKeyUnlinkView: View {
    @ObservedObject var app: AppModel
    @ObservedObject var model: SecurityViewModel
    let keyID: UUID
    var ownsPresentation: @MainActor () -> Bool = { true }
    let dismiss: () -> Void
    @State private var selected: Set<UUID> = []
    @State private var acknowledged = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("解除主机的密钥关联").font(.title3).bold()
            Text("所选主机将明确改为密码主认证，清除保存密码授权并在下次连接时人工输入。不会删除密钥、口令或现有会话。此操作不是自动寻找替代凭据。")
            ForEach(model.hostReferences(keyID)) { host in
                Toggle(host.name + " · " + host.vaultEndpoint, isOn: Binding(get: { selected.contains(host.id) }, set: {
                    if $0 { selected.insert(host.id) } else { selected.remove(host.id) }
                })).toggleStyle(.checkbox)
            }
            Toggle("我确认更改以上主机的主认证方式为密码", isOn: $acknowledged).toggleStyle(.checkbox)
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                Spacer(); Button("取消", action: dismiss).keyboardShortcut(.cancelAction).disabled(model.busy)
                Button("更改认证并解除 \(selected.count) 项关联") {
                    Task { guard app.allowSensitivePreviewAction(), ownsPresentation() else { return }; if await model.unlinkKey(keyID, hostIDs: selected) { _ = await app.reload(); if ownsPresentation() { dismiss() } } }
                }.disabled(model.busy || selected.isEmpty || !acknowledged)
            }
        }.padding(24).frame(width: 540)
    }
}

private struct SecurityPublicKeyView: View {
    @ObservedObject var model: SecurityViewModel
    let keyID: UUID
    var ownsPresentation: @MainActor () -> Bool = { true }
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
                    Task { guard !AppModel.engineeringPreviewBuild else { model.issue = AppModel.engineeringPreviewUnavailableIssue; return }; if await model.discardPrepared(review) { dismiss() } }
                }.fixedSize()
            }
        }.padding(24).frame(width: 620)
    }
}

struct KeyCreationEditor: View {
    @ObservedObject var model: SecurityViewModel
    let creation: KeyCreation
    var ownsPresentation: @MainActor () -> Bool = { true }
    @StateObject private var editor = KeyCreationEditorState()
    @State private var label = ""
    @State private var encrypted = true
    @State private var remember = false
    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var operation: Task<Void, Never>?
    @State private var cancelRequested = false
    var dismiss: () -> Void
    private var generating: Bool { if case .generate = creation { return true }; return false }
    private var working: Bool { model.busy || editor.busy }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(editor.created == nil ? (generating ? "生成 Ed25519" : "导入私钥副本") : "密钥已创建")
                .font(.title2).bold()
            if editor.created != nil {
                createdNotice
            } else {
                if !generating { Text("源文件：" + sourceName).lineLimit(1).truncationMode(.middle) }
            }
            if let review = editor.importReview, !review.candidates.isEmpty {
                duplicateNotice(review)
            } else {
                TextField("公开标签（可选）", text: $label).textFieldStyle(.roundedBorder)
                    .disabled(working).accessibilityIdentifier("key.creation.label")
                if editor.created == nil { protectionFields }
            }
            Text("只支持 OpenSSH RSA/Ed25519。公钥可查看/复制；不提供私钥导出或备份。")
                .font(.caption).foregroundStyle(.secondary)
            KeychainPolicyNotice()
            IssueView(issue: model.issue) { model.issue = nil }
            if working { ProgressView(editor.created == nil ? "正在创建密钥…" : "正在保存此密钥的标签…").controlSize(.small) }
            editorActions
        }.padding(24).frame(width: 530)
        .onAppear { if editor.created == nil { model.clearCreationResult() } }
        .onDisappear {
            editor.close(); passphrase = ""; confirm = ""; operation?.cancel()
            Task { await editor.cancelImport(model: model) }
        }
    }
    private func duplicateNotice(_ review: SecurityKeyImportReview) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("相同公钥已存在").font(.headline).accessibilityIdentifier("key.import.duplicate")
            Text("请选择复用已有密钥，或取消。本次输入的口令和“记住口令”不会保存，也不会修改已有密钥的标签或保存授权。复用不会读取已记住口令。")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(review.candidates) { key in
                VStack(alignment: .leading, spacing: 5) {
                    Text(model.label(for: key)).fontWeight(.semibold)
                    Text(key.algorithm.rawValue.uppercased()).font(.caption)
                    Text(SecurityViewModel.publicInformation(review.publicKey.copyString)?.fingerprint ?? "指纹不可用")
                        .font(.caption.monospaced()).textSelection(.enabled)
                    Text("密钥 ID：" + key.id.uuidString).font(.caption2.monospaced()).foregroundStyle(.secondary)
                    Button("复用此密钥") {
                        operation = Task {
                            let completed = await editor.reuse(key.id, model: model, ownsPresentation: ownsPresentation)
                            guard ownsPresentation(), editor.active else { return }
                            if cancelRequested {
                                await editor.cancelImport(model: model); model.clearCreationResult(); dismiss()
                            } else if completed { finishCreated() }
                        }
                    }.disabled(working).accessibilityIdentifier("key.import.reuse." + key.id.uuidString)
                }
            }
        }.fixedSize(horizontal: false, vertical: true)
    }
    private var createdNotice: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("此密钥已经保存。重试只更新下面这一把密钥的公开标签，不会再次生成或导入。完成或取消均保留已创建密钥。")
                .font(.caption).foregroundStyle(.secondary)
            if let outcome = editor.created {
                Text(verbatim: "密钥 ID：" + outcome.id.uuidString).font(.caption.monospaced()).textSelection(.enabled)
            }
            if editor.labelPending { Text("标签尚未保存，可修改标签后重试，或保留当前标签并完成。").font(.caption) }
        }.fixedSize(horizontal: false, vertical: true).accessibilityIdentifier("key.creation.committed")
    }
    private var protectionFields: some View {
        VStack(alignment: .leading, spacing: 12) {
            Toggle("使用口令保护私钥", isOn: $encrypted).toggleStyle(.checkbox).disabled(working)
                .onChange(of: encrypted) { _, _ in passphrase = ""; confirm = ""; remember = false }
            if encrypted {
                NativeSecureField(id: "key.passphrase", placeholder: "私钥口令", text: $passphrase).frame(height: 26).disabled(working)
                if generating { NativeSecureField(id: "key.confirm", placeholder: "再次输入口令", text: $confirm).frame(height: 26).disabled(working) }
                Toggle("记住口令", isOn: $remember).toggleStyle(.checkbox).disabled(working).accessibilityIdentifier("key.remember")
            }
        }.disabled(AppModel.engineeringPreviewBuild)
    }
    private var editorActions: some View {
        HStack {
            Spacer()
            NativeButton(title: editor.created == nil ? "取消" : "保留密钥并完成", id: "key.editor.cancel", enabled: !editor.busy || editor.created == nil) {
                if editor.created != nil { finishCreated(); return }
                cancelRequested = true; operation?.cancel(); passphrase = ""; confirm = ""
                if !working {
                    Task { await editor.cancelImport(model: model); model.clearCreationResult(); if ownsPresentation() { dismiss() } }
                }
            }.fixedSize()
            if editor.importReview == nil || editor.created != nil {
                NativeButton(title: editor.created == nil ? (generating ? "生成" : "导入") : "保存标签并完成",
                             id: "key.create", enabled: !working && (label.isEmpty || VaultHostDraft.validText(label, limit: 256))) {
                    submit()
                }.fixedSize()
            }
        }
    }
    private func submit() {
        guard !AppModel.engineeringPreviewBuild else { model.issue = AppModel.engineeringPreviewUnavailableIssue; return }
        guard ownsPresentation(), !working else { return }
        let alreadyCreated = editor.created != nil
        guard alreadyCreated || !encrypted || (!passphrase.isEmpty && (!generating || passphrase == confirm)) else {
            model.issue = AppIssue(code: "key.inputMismatch", message: "请输入非空口令，并确保两次输入一致。"); return
        }
        let secret = !alreadyCreated && encrypted ? SecretBytes(utf8: passphrase) : nil
        let protection: KeyProtection = secret.map { .passphrase($0) } ?? .unencrypted
        let saved = remember ? secret : nil
        let requestedLabel = label
        passphrase = ""; confirm = ""; cancelRequested = false
        operation = Task {
            guard ownsPresentation(), editor.active else { return }
            let completed = await editor.submit(model: model, creation: creation, protection: protection, remember: saved,
                                                label: requestedLabel, ownsPresentation: ownsPresentation)
            guard ownsPresentation(), editor.active else { return }
            if completed { finishCreated() }
            else if cancelRequested {
                if editor.created != nil { finishCreated() }
                else { await editor.cancelImport(model: model); model.clearCreationResult(); dismiss() }
            }
        }
    }
    private func finishCreated() {
        guard editor.publishCompletion(to: model, ownsPresentation: ownsPresentation) else { return }
        passphrase = ""; confirm = ""; dismiss()
    }
    private var sourceName: String { if case .importFile(let url) = creation { return url.lastPathComponent }; return "" }
}
