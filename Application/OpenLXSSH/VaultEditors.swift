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
    @State private var organizing = false
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
    private let forFiles: Bool
    init(app: AppModel, vault: VaultDesktopModel, host: HostConfiguration?, folderID: UUID?, forFiles: Bool = false,
         transientConnection: VaultTransientConnectionHandler? = nil,
         closeRequest: Binding<(@MainActor () -> Bool)?> = .constant(nil),
         ownsPresentation: @escaping @MainActor () -> Bool = { true },
         registerClose: ((@escaping @MainActor () -> Bool) -> Void)? = nil, clearClose: (() -> Void)? = nil,
         registerWindowCloseReview: ((@escaping @MainActor (WindowCloseReviewRequest) -> Void, @escaping @MainActor () -> Void) -> Void)? = nil,
         clearWindowCloseReview: (() -> Void)? = nil,
         completeWindowCloseReview: (@MainActor (WindowCloseReviewRequest) -> Void)? = nil,
         dismiss: @escaping () -> Void) {
        self.forFiles = forFiles
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
        _closeReview = State(initialValue: VaultHostCloseReview(editor: editor, dismiss: {
            dismiss()
            if forFiles { app.showWorkspace(.sftp) }
        }, complete: completeWindowCloseReview))
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
                DesktopGlyph(systemName: "server.rack", size: 36, prominent: true)
                Text(draft.isNew ? "新建主机" : "编辑主机").font(.system(size: 21, weight: .semibold))
                Spacer()
                Button { requestClose() } label: { Image(systemName: "xmark").frame(width: 22, height: 22) }
                    .buttonStyle(.borderless).help("关闭").accessibilityLabel("关闭主机编辑")
            }.padding(.horizontal, 20).padding(.vertical, 14).background(DesktopStyle.panel)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    section("连接信息", icon: "terminal") {
                        HStack(alignment: .top, spacing: 12) {
                            field("服务器地址", key: "address", text: draftInput.configuration.address,
                                  placeholder: "主机名、IP 或 SSH 连接命令", next: "port")
                            field("端口", key: "port", text: draftInput.port, next: "username").frame(width: 96)
                        }
                        HStack(alignment: .top, spacing: 12) {
                            field("用户名", key: "username", text: draftInput.configuration.username, placeholder: "SSH 登录用户", next: "name")
                            field("主机名称", key: "name", text: draftInput.configuration.name, placeholder: "在保险箱中显示的名称",
                                  next: draft.configuration.authentication.needsKey ? "key" : (forFiles && !remember ? "remember" : "password"))
                        }
                    }
                    section("身份认证", icon: "key") {
                        Picker("主认证方式", selection: Binding(get: { draft.primaryMethod }, set: {
                            draft.changePrimaryMethod($0); clearPassword(); remember = false; forgetExisting = false
                        })) {
                            Text("密码").tag("password"); Text("SSH 密钥").tag("key")
                        }.pickerStyle(.segmented).labelsHidden()
                        if draft.configuration.authentication.needsKey {
                            let key = vault.snapshot?.keys.first { $0.id == draft.configuration.keyRef } ?? security.metadata.keys.first { $0.id == draft.configuration.keyRef }
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(key.map { $0.label.isEmpty ? $0.algorithm.rawValue.uppercased() + " · " + $0.id.uuidString.prefix(8) : $0.label } ?? "未选择密钥")
                                    if let key, let fingerprint = security.fingerprints[key.id] { Text(fingerprint).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(2) }
                                }
                                Spacer()
                                Button("选择或添加…") { _ = sheets.present(.keys) }
                                    .focused($focusedField, equals: "key")
                                    .accessibilityIdentifier("host.key.choose")
                            }
                            fieldError("key")
                        } else {
                            if draft.configuration.credentialRef != nil && !forgetExisting {
                                HStack {
                                    Label("已保存密码", systemImage: "checkmark.shield").font(.caption)
                                    Spacer()
                                    Button("解除密码关联") { forgetExisting = true }.font(.caption)
                                }
                                Text("要更换已保存的密码，请输入新密码并勾选“记住密码”。").font(.caption).foregroundStyle(.secondary)
                            } else if forgetExisting {
                                HStack { Text("保存时将仅解除此主机的密码关联。").font(.caption); Button("保留") { forgetExisting = false }.font(.caption) }
                            }
                            if forFiles { rememberToggle }
                            if !forFiles || remember { passwordField }
                            if !forFiles { rememberToggle }
                            if remember && password.isEmpty { Text("记住新密码需要输入非空密码。").font(.caption).foregroundStyle(.red) }
                            if forFiles && !remember {
                                Text("本次连接的密码可在 SFTP 页面输入。").font(.caption).foregroundStyle(.secondary)
                            } else if !password.isEmpty && !remember {
                                Text("本次密码仅用于“保存并连接”，单独保存主机时会丢弃。").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Text("如需验证码或其他验证，连接时会提示。").font(.caption).foregroundStyle(.secondary)
                    }
                    VStack(spacing: 0) {
                        organizationSection
                        Divider().padding(.leading, 16)
                        keepaliveSection
                    }
                    .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 12))
                    .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(DesktopStyle.border).allowsHitTesting(false) }
                    if !canConnect { Text("当前编辑器暂时无法发起连接。可先保存配置后从主机列表连接；未记住的本次输入会在关闭后清除。").font(.caption).foregroundStyle(.secondary) }
                }.padding(20).disabled(!editor.canEdit)
            }.frame(minHeight: 0, maxHeight: .infinity)
            if let issue { IssueView(issue: issue) { editor.issue = nil }.padding(.horizontal, 16) }
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
                if forFiles {
                    Button("保存并返回 SFTP") { Task { _ = await save(connect: false) } }
                        .buttonStyle(.borderedProminent).keyboardShortcut("s", modifiers: .command)
                        .disabled(writing || !validForSave)
                } else {
                    Button("保存") { Task { _ = await save(connect: false) } }
                        .keyboardShortcut("s", modifiers: .command).disabled(writing || !validForSave)
                    Button("保存并连接") { Task { _ = await save(connect: true) } }.buttonStyle(.borderedProminent)
                        .disabled(writing || !validForSave || !canConnect)
                }
            }.padding(.horizontal, 20).padding(.vertical, 14).background(DesktopStyle.panel)
        }.frame(width: 500, height: presentationHeight)
        .background(DesktopStyle.background)
        .defaultFocus($focusedField, "address")
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
    private var rememberToggle: some View {
        Toggle("记住密码", isOn: Binding(get: { remember }, set: { enabled in
            remember = enabled
            if forFiles && !enabled { password = ""; showPassword = false }
        }))
        .toggleStyle(.checkbox).focused($focusedField, equals: "remember").accessibilityIdentifier("host.remember")
    }

    private var passwordField: some View {
        HStack {
            let prompt = remember ? "要保存的密码" : "本次密码（可留空）"
            Group {
                if showPassword { TextField(prompt, text: input(\.password)) }
                else { SecureField(prompt, text: input(\.password)) }
            }
            .textFieldStyle(.roundedBorder).focused($focusedField, equals: "password").accessibilityIdentifier("host.password")
            .onSubmit { Task { _ = await save(connect: false) } }
            Button { showPassword.toggle(); focusedField = "password" } label: {
                Image(systemName: showPassword ? "eye.slash" : "eye")
            }.buttonStyle(.plain).accessibilityLabel(showPassword ? "隐藏密码" : "临时显示密码")
        }
    }

    private var organizationSection: some View {
        DisclosureGroup(isExpanded: $organizing) {
            VStack(alignment: .leading, spacing: 10) {
                Text("分组").font(.caption).foregroundStyle(.secondary)
                NativePopup(id: "host.folder", items: [PopupItem(value: "", title: "未分组")] + vault.folders.map {
                    PopupItem(value: $0.id.uuidString, title: vault.folderLabel($0))
                }, selection: Binding(get: { draft.configuration.folderID?.uuidString ?? "" }, set: {
                    draft.configuration.folderID = UUID(uuidString: $0)
                })).frame(height: 28)
                if !vault.tags.isEmpty {
                    Text("标签").font(.caption).foregroundStyle(.secondary)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 110))], alignment: .leading) {
                        ForEach(vault.tags) { tag in
                            Toggle(tag.name, isOn: Binding(get: { draft.tagIDs.contains(tag.id) }, set: {
                                if $0 { draft.tagIDs.insert(tag.id) } else { draft.tagIDs.remove(tag.id) }
                            })).toggleStyle(.checkbox).font(.caption)
                        }
                    }
                }
                Toggle("收藏", isOn: draftInput.configuration.isFavorite).toggleStyle(.checkbox)
            }.padding(.top, 8)
        } label: {
            HStack {
                Text("分组、标签与收藏")
                Spacer()
                Text(draft.configuration.folderID.map(vault.path(for:)) ?? "未分组")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                if draft.configuration.isFavorite {
                    Image(systemName: "star.fill").foregroundStyle(.orange).accessibilityLabel("已收藏")
                }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }

    private var keepaliveSection: some View {
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
                field("TCP 保活间隔（秒）", key: "interval", text: draftInput.interval, next: "count")
                field("TCP 失败探测次数", key: "count", text: draftInput.count)
                Text("设置仅对新连接生效。间隔为 0 时关闭 TCP 保活。").font(.caption).foregroundStyle(.secondary)
            }.padding(.top, 10)
        } label: {
            HStack(spacing: 8) {
                Text("高级 · 长连接保活")
                Spacer()
                Text(keepaliveSummary).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }

    private var keepaliveSummary: String {
        guard draft.fieldErrors["interval"] == nil, draft.fieldErrors["count"] == nil else { return "检查保活设置" }
        return Int(draft.interval) == 0 ? "已关闭" : "间隔 \(draft.interval) 秒"
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
            let first = ["address", "port", "username", "name", "key", "interval", "count"].first { draft.fieldErrors[$0] != nil }
            if first == "interval" || first == "count" { advanced = true }
            focusedField = first ?? "password"
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
        else if forFiles {
            afterDismiss = { saved in
                vault.choose(saved.id)
                app.selectedHostID = saved.id
                app.showWorkspace(.sftp)
            }
        }
        else if !connect && draft.isNew { afterDismiss = { saved in vault.choose(saved.id) } }
        else { afterDismiss = nil }
        return await editor.saveAndFinish(security: app.security, vault: vault, prepareConnection: prepareConnection,
            dismiss: { closeReview.cancelPending(); dismiss() }, afterDismiss: afterDismiss)
    }
    private func section<Content: View>(_ title: String, icon: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: icon).foregroundStyle(DesktopStyle.brand).accessibilityHidden(true)
                Text(title)
            }.font(.system(size: 13, weight: .semibold))
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.border))
    }
    private func field(_ title: String, key: String, text: Binding<String>, placeholder: String? = nil, next: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary)
            TextField(title, text: text, prompt: Text(placeholder ?? title))
                .textFieldStyle(.roundedBorder)
                .focused($focusedField, equals: key)
                .accessibilityIdentifier("host." + key)
                .onChange(of: text.wrappedValue) { _, _ in editedFields.insert(key) }
                .onSubmit {
                    editedFields.insert(key)
                    guard draft.fieldErrors[key] == nil else { return }
                    if let next { focusedField = next }
                    else { Task { _ = await save(connect: false) } }
                }
            fieldError(key)
        }
    }
    @ViewBuilder private func fieldError(_ key: String) -> some View {
        let raw = key == "address" ? draft.configuration.address : draft.configuration.username
        if (key == "address" || key == "username"), VaultHostDraft.parsedSSHCommand(raw) != nil {
            Button("从 SSH 命令填入连接信息") { _ = draft.applySSHCommand(raw) }
                .buttonStyle(.link)
        } else if let error = draft.fieldErrors[key],
                  !draft.isNew || showsValidationErrors || editedFields.contains(key) {
            Text(error).font(.caption).foregroundStyle(DesktopStyle.statusRed)
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
