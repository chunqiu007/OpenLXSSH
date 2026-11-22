import AppKit
import SwiftUI
import OpenLXSSHCore
import OpenLXSSHSecurity

private struct VaultEditorSheet: Identifiable {
    enum Content { case keys, create(KeyCreation) }
    let id = UUID()
    let content: Content
}

/// Short-lived editor state owns all sensitive input; neither draft nor VaultDesktopModel stores it.
struct VaultHostEditor: View {
    let app: AppModel
    let vault: VaultDesktopModel
    @State private var security: SecurityViewModel
    @State private var editor: VaultHostEditorModel
    @State private var closeReview: VaultHostCloseReview
    @State private var advanced = false
    @State private var sheets = PresentationOwner<VaultEditorSheet.Content>()
    @State private var showsValidationErrors = false
    @State private var editedFields: Set<String> = []
    @FocusState private var focusedField: String?
    @Binding private var closeRequest: (@MainActor () -> Bool)?
    private let registerClose: ((@escaping @MainActor () -> Bool) -> Void)?
    private let clearClose: (() -> Void)?
    private let registerWindowCloseReview: ((@escaping @MainActor (WindowCloseReviewRequest) -> Void, @escaping @MainActor () -> Void) -> Void)?
    private let clearWindowCloseReview: (() -> Void)?
    @State private var fallbackCloseOwner = UUID()
    @State private var presentationHeight: CGFloat
    private let transientConnection: VaultTransientConnectionHandler?
    let dismiss: () -> Void
    init(app: AppModel, vault: VaultDesktopModel, host: HostConfiguration?, folderID: UUID?,
         transientConnection: VaultTransientConnectionHandler? = nil,
         closeRequest: Binding<(@MainActor () -> Bool)?> = .constant(nil),
         ownsPresentation: @escaping @MainActor () -> Bool = { true },
         registerClose: ((@escaping @MainActor () -> Bool) -> Void)? = nil, clearClose: (() -> Void)? = nil,
         registerWindowCloseReview: ((@escaping @MainActor (WindowCloseReviewRequest) -> Void, @escaping @MainActor () -> Void) -> Void)? = nil,
         clearWindowCloseReview: (() -> Void)? = nil,
         completeWindowCloseReview: (@MainActor (WindowCloseReviewRequest) -> Void)? = nil,
         dismiss: @escaping () -> Void) {
        self.app = app; self.vault = vault; self.transientConnection = transientConnection; self.dismiss = dismiss
        self.registerClose = registerClose; self.clearClose = clearClose
        self.registerWindowCloseReview = registerWindowCloseReview; self.clearWindowCloseReview = clearWindowCloseReview
        _closeRequest = closeRequest
        // Capture once per presentation. Reading window geometry from body would
        // feed sheet fitting back into itself while fields and errors update.
        let parentHeight = (NSApp.keyWindow?.sheetParent ?? NSApp.keyWindow ?? NSApp.mainWindow)?.contentView?.bounds.height ?? 720
        _presentationHeight = State(initialValue: min(680, max(420, parentHeight - 60)))
        _security = State(initialValue: SecurityViewModel(coordinator: app.security))
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: host, settings: app.settings, folderID: folderID,
            tagIDs: host.flatMap { vault.snapshot?.hostTagIDs[$0.id] } ?? []), ownsPresentation: ownsPresentation)
        _editor = State(initialValue: editor)
        _closeReview = State(initialValue: VaultHostCloseReview(editor: editor, dismiss: { dismiss() }, complete: completeWindowCloseReview))
    }
    private var canConnect: Bool { !editor.hasTransientInput || transientConnection != nil }
    private func input<Value>(_ key: ReferenceWritableKeyPath<VaultHostEditorModel, Value>) -> Binding<Value> {
        Binding(get: { editor[keyPath: key] }, set: { value in editor.edit { $0[keyPath: key] = value } })
    }
    private var draftInput: Binding<VaultHostDraft> { input(\.draft) }
    private var draft: VaultHostDraft {
        get { editor.draft }
        nonmutating set { editor.edit { $0.draft = newValue } }
    }
    private var password: String { get { editor.password } nonmutating set { editor.edit { $0.password = newValue } } }
    private var remember: Bool { get { editor.remember } nonmutating set { editor.edit { $0.remember = newValue } } }
    private var forgetExisting: Bool { get { editor.forgetExisting } nonmutating set { editor.edit { $0.forgetExisting = newValue } } }
    private var showPassword: Bool { get { editor.showPassword } nonmutating set { editor.edit { $0.showPassword = newValue } } }
    private var writing: Bool { editor.writing }
    private var issue: AppIssue? { get { editor.issue } nonmutating set { editor.issue = newValue } }
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "server.rack")
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 34, height: 34)
                    .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 9))
                VStack(alignment: .leading, spacing: 2) {
                    Text(draft.isNew ? "新建主机" : "编辑主机").font(.title3).bold()
                    Text("配置 SSH 地址、认证方式与保活选项").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button { requestClose() } label: { Image(systemName: "xmark") }.accessibilityLabel("关闭主机编辑")
            }.padding(.horizontal, 20).padding(.vertical, 16)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    section("地址", icon: "network") { field("服务器地址", key: "address", text: draftInput.configuration.address) }
                    section("常规", icon: "server.rack") {
                        field("名称", key: "name", text: draftInput.configuration.name)
                        Text("父分组").font(.caption).foregroundStyle(.secondary)
                        NativePopup(id: "host.folder", items: [PopupItem(value: "", title: "未分组")] + vault.folders.map { PopupItem(value: $0.id.uuidString, title: vault.folderLabel($0)) },
                            selection: Binding(get: { draft.configuration.folderID?.uuidString ?? "" }, set: { draft.configuration.folderID = UUID(uuidString: $0) })).frame(height: 28)
                        if !vault.tags.isEmpty {
                            Text("标签").font(.caption).foregroundStyle(.secondary)
                            LazyVGrid(columns: [GridItem(.adaptive(minimum: 110))], alignment: .leading) {
                                ForEach(vault.tags) { tag in
                                    Toggle(tag.name, isOn: Binding(get: { draft.tagIDs.contains(tag.id) }, set: { if $0 { draft.tagIDs.insert(tag.id) } else { draft.tagIDs.remove(tag.id) } }))
                                        .toggleStyle(.checkbox).font(.caption)
                                }
                            }
                        }
                        Toggle("收藏", isOn: draftInput.configuration.isFavorite).toggleStyle(.checkbox)
                    }
                    section("SSH", icon: "terminal") {
                        field("端口", key: "port", text: draftInput.port)
                        field("用户名", key: "username", text: draftInput.configuration.username)
                    }
                    section("凭据", icon: "key") {
                        Picker("主认证方式", selection: Binding(get: { draft.primaryMethod }, set: {
                            draft.changePrimaryMethod($0); clearPassword(); remember = false; forgetExisting = false
                        })) {
                            Text("密码").tag("password"); Text("SSH 密钥").tag("key")
                        }.pickerStyle(.segmented)
                        if draft.configuration.authentication.needsKey {
                            let key = vault.snapshot?.keys.first { $0.id == draft.configuration.keyRef } ?? security.metadata.keys.first { $0.id == draft.configuration.keyRef }
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(key.map { $0.label.isEmpty ? $0.algorithm.rawValue.uppercased() + " · " + $0.id.uuidString.prefix(8) : $0.label } ?? "未选择密钥")
                                    if let key, let fingerprint = security.fingerprints[key.id] { Text(fingerprint).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(2) }
                                }
                                Spacer()
                                Button("选择或添加…") { _ = sheets.present(.keys) }
                                    .accessibilityIdentifier("host.key.choose")
                            }
                            fieldError("key")
                        } else {
                            if draft.configuration.credentialRef != nil && !forgetExisting {
                                HStack {
                                    Label("已保存密码", systemImage: "checkmark.shield").font(.caption)
                                    Spacer()
                                    Button("保存时忘记此关联") { forgetExisting = true }.font(.caption)
                                }
                                Text("不会读取或填入已保存密码；输入新密码时，明确勾选记住才替换保存。").font(.caption).foregroundStyle(.secondary)
                            } else if forgetExisting {
                                HStack { Text("保存时将仅解除此主机的密码关联。").font(.caption); Button("保留") { forgetExisting = false }.font(.caption) }
                            }
                            HStack {
                                Group {
                                    if showPassword { TextField("本次密码", text: input(\.password)) }
                                    else { SecureField("本次密码", text: input(\.password)) }
                                }.textFieldStyle(.roundedBorder).focused($focusedField, equals: "password").accessibilityIdentifier("host.password")
                                    .onSubmit { Task { _ = await save(connect: false) } }
                                Button { showPassword.toggle(); focusedField = "password" } label: { Image(systemName: showPassword ? "eye.slash" : "eye") }
                                    .buttonStyle(.plain).accessibilityLabel(showPassword ? "隐藏密码" : "临时显示密码")
                            }
                            Toggle("记住密码", isOn: input(\.remember)).toggleStyle(.checkbox).accessibilityIdentifier("host.remember")
                            if remember && password.isEmpty { Text("记住新密码需要输入非空密码。").font(.caption).foregroundStyle(.red) }
                            Text("仅保存且不记住：关闭后丢弃输入。保存并连接：本次密码只交给新会话，重连不会复用。").font(.caption).foregroundStyle(.secondary)
                        }
                        Text("附加验证按服务器实际提示人工回答；不会把本次密码自动填入附加问题。").font(.caption2).foregroundStyle(.secondary)
                    }
                    DisclosureGroup(isExpanded: $advanced) {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(spacing: 6) {
                                Text("快速预设").font(.caption).foregroundStyle(.secondary)
                                ForEach([("高稳 15 秒", "15", "3"), ("标准 30 秒", "30", "3"), ("省电 60 秒", "60", "3"), ("关闭", "0", "3")], id: \.0) { label, iv, cnt in
                                    let active = draftInput.interval.wrappedValue == iv && draftInput.count.wrappedValue == cnt
                                    Button(label) {
                                        draftInput.interval.wrappedValue = iv
                                        draftInput.count.wrappedValue = cnt
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.small)
                                    .tint(active ? .accentColor : .secondary)
                                }
                            }
                            field("TCP 保活间隔（秒）", key: "interval", text: draftInput.interval)
                            field("TCP 失败探测次数", key: "count", text: draftInput.count)
                            Text("系统使用此空闲/重试间隔及失败探测次数检测 TCP 失联，不申请额外 SSH 通道。实际时刻由系统调度；TCP 仍响应时不代表 SSH 程序正常。间隔 0 关闭；修改只影响新连接。").font(.caption).foregroundStyle(.secondary)
                            Text("TCP 保活不执行远端命令；不能保证远端任务在断线后继续。").font(.caption).foregroundStyle(.secondary)
                        }.padding(.top, 10)
                    } label: {
                        HStack(spacing: 8) {
                            Text("高级 · 长连接保活")
                            Spacer()
                            DesktopBadge(
                                text: draft.configuration.keepaliveInterval == 0 ? "保活已关闭" : "保活 \(draft.configuration.keepaliveInterval) 秒",
                                color: draft.configuration.keepaliveInterval == 0 ? .secondary : DesktopStyle.statusGreen,
                                fill: draft.configuration.keepaliveInterval == 0 ? DesktopStyle.separator : DesktopStyle.statusGreen.opacity(0.14)
                            )
                        }
                    }.padding(16)
                        .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.border))
                    if !canConnect { Text("当前编辑器暂时无法发起连接。可先保存配置后从主机列表连接；未记住的本次输入会在关闭后清除。").font(.caption).foregroundStyle(.secondary) }
                    IssueView(issue: issue) { issue = nil }
                }.padding(20).disabled(!editor.canEdit)
            }.frame(minHeight: 0, maxHeight: .infinity)
            if editor.committedAwaitingRefresh {
                Text("已保存，待刷新。当前表单只读；重试只读取已提交配置，不会再次保存密码。")
                    .font(.caption).foregroundStyle(.secondary).padding(.horizontal, 20)
                Button("重试刷新已保存配置") { Task { _ = await editor.reloadCurrent(vault: vault) } }.disabled(writing)
            } else if issue?.code == "storage.staleRecord" {
                Button("重新载入当前记录（放弃此草稿）") { Task { _ = await editor.reloadCurrent(vault: vault) } }.disabled(writing)
            }
            Divider()
            HStack {
                Button("取消") { requestClose() }.keyboardShortcut(.cancelAction).disabled(writing)
                Spacer()
                if writing { ProgressView().controlSize(.small) }
                Button("保存") { Task { _ = await save(connect: false) } }.disabled(writing || !validForSave)
                Button("保存并连接") { Task { _ = await save(connect: true) } }.buttonStyle(.borderedProminent)
                    .disabled(writing || !validForSave || !canConnect)
            }.padding(16)
        }.frame(width: 500, height: presentationHeight)
        .background(DesktopStyle.background)
        .task { await security.load() }
        .onAppear {
            let close: @MainActor () -> Bool = { [weak review = closeReview, weak sheets] in
                guard sheets?.item == nil else { return false }
                review?.begin(); return false
            }
            if let registerClose { registerClose(close) }
            else { closeRequest = close }
            let begin: @MainActor (WindowCloseReviewRequest) -> Void = { [weak review = closeReview, weak sheets] request in
                // Do not replace a key picker, key creation editor, or a system panel.
                guard let review, sheets?.item == nil else { request.resolve(false); return }
                review.begin(request)
            }
            let cancel: @MainActor () -> Void = { [weak review = closeReview] in review?.cancelPending() }
            if let registerWindowCloseReview { registerWindowCloseReview(begin, cancel) }
            else { app.registerWindowCloseReview(owner: fallbackCloseOwner, begin: begin, cancel: cancel) }
        }
        .onChange(of: focusedField) { _, field in if field != "password" { editor.showPassword = false } }
        .onDisappear {
            closeReview.cancelPending(); editor.deactivate(); sheets.invalidate()
            if let clearClose { clearClose() } else { closeRequest = nil }
            if let clearWindowCloseReview { clearWindowCloseReview() }
            else { app.clearWindowCloseReview(owner: fallbackCloseOwner) }
        }
        .nativeSheet(item: Binding(get: { closeReview.prompt }, set: { value in
            if value == nil, let prompt = closeReview.prompt { _ = closeReview.cancel(prompt.id) }
        }), onAttemptDismiss: {
            guard let prompt = closeReview.prompt else { return true }
            return closeReview.cancel(prompt.id)
        }) { prompt in closePrompt(prompt) }
        .nativeSheet(item: $sheets.item, onAttemptDismiss: { editor.canClose }) { value in
            switch value.content {
            case .keys:
                VaultKeyPicker(model: security, app: app, selectedID: draft.configuration.keyRef,
                    ownsPresentation: { editor.canEdit && sheets.owns(value.id) }) { id in
                    guard editor.canEdit, sheets.owns(value.id) else { return }
                    draft.configuration.keyRef = id; sheets.dismiss(value.id)
                    Task { _ = await vault.load() }
                } dismiss: { sheets.dismiss(value.id) }
            case .create: EmptyView()
            }
        }
    }
    private var validForSave: Bool {
        editor.validForSave && !editor.committedAwaitingRefresh
    }
    private func requestClose() {
        guard sheets.item == nil else { return }
        closeReview.begin()
    }
    private func closePrompt(_ prompt: VaultHostCloseReview.Prompt) -> some View {
        VaultHostClosePrompt(prompt: prompt, editor: editor, review: closeReview, security: app.security, vault: vault)
    }
    private func clearPassword() { editor.clearInput() }
    @MainActor private func save(connect: Bool) async -> Bool {
        guard editor.canEdit, !connect || canConnect else { return false }
        guard validForSave else {
            showsValidationErrors = true
            focusedField = ["address", "name", "port", "username", "key", "interval", "count"].first { draft.fieldErrors[$0] != nil }
            return false
        }
        let usesTransient = editor.hasTransientInput
        let prepareConnection: (@MainActor (HostConfiguration, SecretBytes?) async throws -> VaultPreparedConnection)?
        if connect && usesTransient {
            prepareConnection = { saved, material in
                guard editor.isCurrent, let material, let transientConnection else { throw SecurityUIFailure.notAuthorized }
                let intent = VaultTransientConnectionIntent(host: saved, secret: material)
                do { return try await transientConnection(saved, intent) }
                catch { intent.cancel(); throw error }
            }
        } else { prepareConnection = nil }
        let afterDismiss: (@MainActor (HostConfiguration) -> Void)?
        if connect && !usesTransient { afterDismiss = { saved in app.requestSession(hostID: saved.id, mode: .newSession) } }
        else { afterDismiss = nil }
        return await editor.saveAndFinish(security: app.security, vault: vault, prepareConnection: prepareConnection,
            dismiss: { closeReview.cancelPending(); dismiss() }, afterDismiss: afterDismiss)
    }
    private func section<Content: View>(_ title: String, icon: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: icon)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.border))
    }
    private func field(_ title: String, key: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            TextField(title, text: text)
                .textFieldStyle(.roundedBorder)
                .focused($focusedField, equals: key)
                .accessibilityIdentifier("host." + key)
                .onChange(of: text.wrappedValue) { _, _ in editedFields.insert(key) }
                .onSubmit { Task { _ = await save(connect: false) } }
            fieldError(key)
        }
    }
    @ViewBuilder private func fieldError(_ key: String) -> some View {
        if let error = draft.fieldErrors[key] {
            let showUrgent = !draft.isNew || showsValidationErrors || editedFields.contains(key)
            Text(error)
                .font(.caption)
                .foregroundStyle(showUrgent ? DesktopStyle.statusRed : .secondary)
            if key == "address", VaultHostDraft.parsedSSHCommand(draft.configuration.address) != nil {
                Button("识别到 SSH 连接命令，点击自动填入地址、端口与用户名") {
                    _ = draft.applySSHCommand(draft.configuration.address)
                }
                .buttonStyle(.bordered).controlSize(.small)
            } else if key == "username", VaultHostDraft.parsedSSHCommand(draft.configuration.username) != nil {
                Button("识别到 SSH 连接命令，点击自动填入地址、端口与用户名") {
                    _ = draft.applySSHCommand(draft.configuration.username)
                }
                .buttonStyle(.bordered).controlSize(.small)
            }
        }
    }
}

private struct VaultHostClosePrompt: View {
    let prompt: VaultHostCloseReview.Prompt
    let editor: VaultHostEditorModel
    let review: VaultHostCloseReview
    let security: SecurityCoordinator
    let vault: VaultDesktopModel
    private var title: String {
        if prompt.kind == .writing { return "正在保存主机" }
        return editor.committedAwaitingRefresh ? "主机已保存，待刷新" : "保存对主机的更改？"
    }
    private var detail: String {
        if prompt.kind == .writing { return "本次关闭已取消。请等待当前保存或刷新完成后再关闭；不会重复保存，也不会断开连接或取消传输。" }
        if editor.committedAwaitingRefresh { return "配置与凭据授权已经提交。可仅重读恢复后继续关闭，或直接关闭已保存的表单；不会再次写入或撤销新凭据。取消仅取消本次关闭。" }
        return "放弃会清除本次密码与未保存字段。取消将完整保留草稿并继续编辑，不会断开连接或取消传输。"
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title).font(.headline)
            Text(detail).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button(prompt.kind == .writing ? "继续查看" : "取消") { _ = review.cancel(prompt.id) }
                    .keyboardShortcut(.cancelAction).disabled(review.saving)
                    .accessibilityIdentifier("host.close.cancel")
                if prompt.kind != .writing {
                    Button(editor.committedAwaitingRefresh ? "关闭已保存表单" : "放弃更改", role: .destructive) { review.discard(prompt.id) }
                        .disabled(editor.writing || review.saving).accessibilityIdentifier("host.close.discard")
                    Spacer()
                    Button(editor.committedAwaitingRefresh ? "刷新后继续关闭" : "保存") {
                        Task {
                            _ = await review.save(prompt.id, security: security, vault: vault)
                        }
                    }.disabled(editor.writing || review.saving || (!editor.committedAwaitingRefresh && !editor.validForSave))
                        .accessibilityIdentifier("host.close.save")
                }
            }
            if review.saving { ProgressView("正在保存或刷新…").controlSize(.small) }
            IssueView(issue: editor.issue) { editor.issue = nil }
        }.padding(24).frame(width: 450)
    }
}

struct VaultFolderEditor: View {
    let vault: VaultDesktopModel
    let original: HostFolder?
    @State private var name: String
    @State private var parent: UUID?
    let dismiss: () -> Void
    private let ownsPresentation: @MainActor () -> Bool
    init(vault: VaultDesktopModel, folder: HostFolder?, parentID: UUID?, ownsPresentation: @escaping @MainActor () -> Bool = { true }, dismiss: @escaping () -> Void) {
        self.vault = vault; original = folder; self.dismiss = dismiss; self.ownsPresentation = ownsPresentation
        _name = State(initialValue: folder?.name ?? ""); _parent = State(initialValue: folder?.parentID ?? parentID)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(original == nil ? "新建分组" : "重命名或移动分组").font(.title3).bold()
            NativeField(placeholder: "分组名称", id: "folder.name", text: $name, onSubmit: { _ in save() }).frame(height: 28)
            Text("父分组").font(.caption).foregroundStyle(.secondary)
            NativePopup(id: "folder.parent", items: [PopupItem(value: "", title: "根分组")] + vault.folders.filter { original == nil || vault.canMoveFolder(original!.id, to: $0.id) }.map { PopupItem(value: $0.id.uuidString, title: vault.folderLabel($0)) },
                selection: Binding(get: { parent?.uuidString ?? "" }, set: { parent = UUID(uuidString: $0) })).frame(height: 28)
            Text("仅本地组织，不继承协议或凭据。不能移动到自身或后代；删除时主机与子组会保留并移到原父组。").font(.caption).foregroundStyle(.secondary)
            IssueView(issue: vault.issue) { vault.issue = nil }
            HStack {
                Spacer(); Button("取消", action: dismiss).keyboardShortcut(.cancelAction).disabled(vault.isWriting)
                Button("保存", action: save).disabled(vault.isWriting || !VaultHostDraft.validText(name, limit: 256))
            }
        }.padding(24).frame(width: 450)
    }
    private func save() {
        guard !vault.isWriting, VaultHostDraft.validText(name, limit: 256), ownsPresentation() else { return }
        Task {
            guard ownsPresentation() else { return }
            var folder = original ?? HostFolder(name: name)
            folder.name = name; folder.parentID = parent
            if await vault.apply([.saveFolder(folder)]), ownsPresentation() { dismiss() }
        }
    }
}

struct VaultKeyPicker: View {
    let model: SecurityViewModel
    let app: AppModel
    let selectedID: UUID?
    var ownsPresentation: @MainActor () -> Bool = { true }
    let select: (UUID) -> Void
    let dismiss: () -> Void
    @State private var search = ""
    @State private var active = true
    @State private var creations = PresentationOwner<KeyCreation>()
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Text("选择 SSH 密钥").font(.title3).bold(); Spacer(); Button("关闭", action: dismiss).keyboardShortcut(.cancelAction) }
            NativeField(placeholder: "搜索标签、类型或指纹", id: "vault.key.search", text: $search).frame(height: 28)
            HStack {
                Button("生成 Ed25519…") { if active && ownsPresentation() { model.clearCreationResult(); _ = creations.present(.generate) } }
                Button("导入…") { chooseImport() }
            }
            ScrollView {
                VStack(spacing: 8) {
                    ForEach(model.filteredKeys(search: search)) { key in
                        Button { if active && ownsPresentation() { select(key.id) } } label: {
                            HStack {
                                Image(systemName: selectedID == key.id ? "checkmark.circle.fill" : "key")
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(model.label(for: key))
                                    Text(key.algorithm.rawValue.uppercased() + " · \(model.hostReferences(key.id).count) 台主机").font(.caption).foregroundStyle(.secondary)
                                    Text(model.fingerprints[key.id] ?? "指纹暂不可用").font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(2)
                                }
                                Spacer()
                            }.padding(10).contentShape(Rectangle())
                        }.buttonStyle(.plain).background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 7))
                            .accessibilityIdentifier("vault.key.select." + key.id.uuidString)
                    }
                }
            }.frame(minHeight: 160, maxHeight: 360)
            IssueView(issue: model.issue) { model.issue = nil }
        }.padding(20).frame(width: 510)
        .task { active = true; await model.load() }
        .onDisappear { active = false; creations.invalidate() }
        .nativeSheet(item: $creations.item) { value in
            KeyCreationEditor(model: model, creation: value.content, ownsPresentation: { active && ownsPresentation() && creations.owns(value.id) }) {
                guard active, ownsPresentation(), creations.owns(value.id) else { return }
                let created = model.lastCreatedKey?.id
                creations.dismiss(value.id)
                let ticket = creations.capture()
                Task {
                    await model.load(); _ = await app.reload()
                    guard active, ownsPresentation(), creations.isCurrent(ticket) else { return }
                    if let created { select(created) }
                }
            }
        }
    }
    private func chooseImport() {
        let ticket = creations.capture()
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.title = "导入标准 OpenSSH 私钥"
        panel.begin { response in
            guard active, ownsPresentation(), creations.isCurrent(ticket), response == .OK, let url = panel.url else { return }
            model.clearCreationResult(); _ = creations.present(.importFile(url), ifCurrent: ticket)
        }
    }
}
struct VaultKeyCreationPresentation: Identifiable {
    let id = UUID()
    let creation: KeyCreation
}
