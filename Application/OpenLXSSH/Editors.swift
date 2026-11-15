import AppKit
import SwiftUI
import OpenLXSSHCore
import OpenLXSSHTransport
import OpenLXSSHSecurity

/// Kept for existing callers; the desktop editor owns a stable non-secret draft and short-lived input.
struct HostEditor: View {
    @ObservedObject var model: AppModel
    @StateObject private var vault: VaultDesktopModel
    let host: HostConfiguration?
    let folderID: UUID?
    let dismiss: () -> Void
    init(model: AppModel, host: HostConfiguration?, folderID: UUID?, dismiss: @escaping () -> Void) {
        self.model = model; self.host = host; self.folderID = folderID; self.dismiss = dismiss
        _vault = StateObject(wrappedValue: VaultDesktopModel(app: model))
    }
    var body: some View {
        Group {
            if vault.didLoad {
                VaultHostEditor(app: model, vault: vault, host: host, folderID: folderID, dismiss: dismiss)
            } else {
                VStack(spacing: 16) {
                    ProgressView("读取本地主机元数据…")
                    IssueView(issue: vault.issue) { vault.issue = nil }
                    HStack { Button("取消", action: dismiss); Button("重试") { Task { _ = await vault.load() } } }
                }.padding(24).frame(width: 430)
            }
        }.task { _ = await vault.load() }
    }
}

struct FolderEditor: View {
    @ObservedObject var model: AppModel
    @StateObject private var vault: VaultDesktopModel
    let folder: HostFolder?
    let dismiss: () -> Void
    init(model: AppModel, folder: HostFolder?, dismiss: @escaping () -> Void) {
        self.model = model; self.folder = folder; self.dismiss = dismiss
        _vault = StateObject(wrappedValue: VaultDesktopModel(app: model))
    }
    var body: some View {
        VaultFolderEditor(vault: vault, folder: folder, parentID: folder?.parentID, dismiss: dismiss)
            .task { _ = await vault.load() }
    }
}

struct SettingsEditor: View {
    @ObservedObject var model: AppModel
    @ObservedObject var editor: SettingsEditorModel
    @State private var category: PreferencesCategory = .general
    @State private var diagnosticCategories: Set<DiagnosticCategory> = [.version]
    @State private var diagnosticSnapshot: PublicDiagnosticSnapshot?
    @State private var copied = false
    private let fonts = TerminalPreferences.availableFonts()
    private let presentationHeight: CGFloat
    var dismiss: () -> Void
    init(model: AppModel, editor: SettingsEditorModel, initialCategory: PreferencesCategory = .general, dismiss: @escaping () -> Void) {
        self.model = model; self.editor = editor; self.dismiss = dismiss
        _category = State(initialValue: initialCategory)
        let parentHeight = NSApplication.shared.mainWindow?.contentView?.bounds.height ?? 680
        presentationHeight = min(620, max(420, parentHeight - 60))
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "gearshape.fill")
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 34, height: 34)
                    .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 9))
                VStack(alignment: .leading, spacing: 2) {
                    Text("设置").font(.title3).bold()
                    Text("仅非秘密偏好 · 外观、终端行为与连接默认项").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }.padding(.horizontal, 20).padding(.vertical, 16)
            Divider()
            HStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(PreferencesCategory.allCases) { item in
                            let selected = category == item
                            Button { category = item } label: {
                                Label(item.title, systemImage: item.symbol)
                                    .font(.system(size: 13, weight: selected ? .semibold : .regular))
                                    .foregroundStyle(selected ? Color.accentColor : .primary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(.horizontal, 10).padding(.vertical, 8)
                                    .background(selected ? DesktopStyle.selection : .clear, in: RoundedRectangle(cornerRadius: 8))
                                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(selected ? Color.accentColor.opacity(0.28) : .clear))
                                    .contentShape(Rectangle())
                            }.buttonStyle(.plain).accessibilityIdentifier("settings.category." + item.rawValue)
                                .accessibilityAddTraits(selected ? .isSelected : [])
                        }
                    }.padding(12)
                }.frame(width: 186).background(DesktopStyle.sidebar).disabled(!editor.canEdit)
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        Text(category.title).font(.headline)
                        categoryContent
                        if category.canReset {
                            Button("重置此类别…") { editor.resetReview = PreferencesResetReview(category: category) }
                                .accessibilityIdentifier("settings.reset.category")
                        }
                    }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
                }.disabled(!editor.canEdit)
            }.frame(maxHeight: .infinity)
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                IssueView(issue: editor.issue ?? model.issue) { editor.issue = nil; model.issue = nil }
                HStack {
                    Button("重置本页全部设置…") { editor.resetReview = PreferencesResetReview(category: nil) }.disabled(!editor.canEdit)
                    Spacer()
                    if editor.isWriting { ProgressView().controlSize(.small); Text("正在保存…").font(.caption) }
                    Button("取消") { if editor.attemptClose() { dismiss() } }.keyboardShortcut(.cancelAction).disabled(!editor.canEdit)
                        .accessibilityIdentifier("editor.cancel")
                    Button("保存设置") { save() }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).disabled(!editor.canEdit || model.isWriting)
                        .accessibilityIdentifier("settings.save")
                }
            }.padding(16)
        }
        .frame(width: 800, height: presentationHeight)
        .background(DesktopStyle.background).foregroundStyle(.primary)
        .preferredColorScheme(editor.draft.value.theme == .system ? nil : (editor.draft.value.theme == .dark ? .dark : .light))
        .onAppear {
            model.registerPreferencesCloseReview(owner: editor.id, begin: { [weak editor] request in
                guard let editor, editor.resetReview == nil else { request.resolve(false); return }
                editor.beginCloseReview(request, dismiss: dismiss)
            }, cancel: { [weak editor] in editor?.cancelClose() })
        }
        .onDisappear {
            editor.deactivate()
            model.clearPreferencesCloseReview(owner: editor.id)
        }
        .nativeSheet(item: closePrompt, onAttemptDismiss: { editor.cancelClose(); return !editor.isWriting }) { prompt in
            VStack(alignment: .leading, spacing: 16) {
                Text("保存设置改动？").font(.headline)
                Text("仅处理此设置草稿；不会更改主机、私钥、已知主机或保存密码。取消会保留全部改动。")
                IssueView(issue: editor.issue ?? model.issue) { editor.issue = nil; model.issue = nil }
                HStack {
                    Button("取消") { editor.cancelClose(prompt.id) }.keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("放弃改动", role: .destructive) { if editor.discard(prompt.id) { dismiss() } }
                    Button("保存") { save(reviewID: prompt.id) }.keyboardShortcut(.defaultAction)
                }.disabled(editor.isWriting)
            }.padding(24).frame(width: 470)
        }
        .nativeSheet(item: $editor.resetReview) { review in
            VStack(alignment: .leading, spacing: 16) {
                Text(review.category.map { "重置“" + $0.title + "”？" } ?? "重置设置中的全部偏好？").font(.headline)
                Text("只修改本设置页草稿，保存后才生效。主机、分组、密钥、信任、保存密码，以及 Vault/文件列表和窗口的独立布局偏好都不受影响。取消不改变草稿。")
                HStack {
                    Button("取消") { if editor.resetReview?.id == review.id { editor.resetReview = nil } }.keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("重置草稿", role: .destructive) {
                        guard editor.canEdit, editor.resetReview?.id == review.id else { return }
                        if let category = review.category { editor.draft.reset(category) }
                        else { editor.draft = SettingsDraft(AppSettings()) }
                        editor.resetReview = nil
                    }
                }
            }.padding(24).frame(width: 470)
        }
    }
    private var closePrompt: Binding<SettingsClosePrompt?> {
        Binding(get: { editor.prompt }, set: { if $0 == nil { editor.cancelClose() } })
    }
    @ViewBuilder private var categoryContent: some View {
        switch category {
        case .general:
            Picker("管理界面外观", selection: $editor.draft.value.theme) {
                Text("跟随系统（默认）").tag(TerminalTheme.system)
                Text("浅色").tag(TerminalTheme.light)
                Text("深色").tag(TerminalTheme.dark)
            }.accessibilityIdentifier("settings.theme")
            Picker("启动管理页", selection: $editor.draft.value.startupPage) {
                Text("保险箱（默认）").tag(StartupManagementPage.vault)
                Text("SFTP").tag(StartupManagementPage.sftp)
                Text("上次固定管理页").tag(StartupManagementPage.lastManagement)
            }.accessibilityIdentifier("settings.startup")
            note("外观在本窗口即时预览，保存后应用管理界面与所有终端。默认终端始终近黑底浅字，不因系统外观变白；显式自定义色保持不变。")
            note("启动页下次启动生效。上次管理页仅指保险箱或 SFTP；不恢复 SSH 标签、自动连接、认证回答、终端内容或搜索文本。保险箱列表/卡片及排序在主机页选择并独立记忆。")
        case .terminal:
            Picker("等宽字体", selection: $editor.draft.value.fontName) {
                if !fonts.contains(where: { $0.name == editor.draft.value.fontName }) {
                    Text("不可用：" + editor.draft.value.fontName).tag(editor.draft.value.fontName)
                }
                ForEach(fonts, id: \.name) { font in Text(font.title).tag(font.name) }
            }.accessibilityIdentifier("settings.font")
            if TerminalPreferences.font(name: editor.draft.value.fontName, size: 13) == nil {
                Text("此字体不可用或不是等宽字体。请选择“系统等宽（默认）”后保存；不会静默替换。")
                    .font(.caption).foregroundStyle(.orange)
            }
            field("字号", range: "6–72 pt；默认 13", id: "settings.size", binding: $editor.draft.size)
            Picker("终端配色", selection: Binding(get: { ColorPreset.matching(editor.draft.value) }, set: { choice in
                if choice != .custom { (editor.draft.value.foregroundColor, editor.draft.value.backgroundColor, editor.draft.value.cursorColor) = choice.colors }
            })) {
                ForEach(ColorPreset.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }.accessibilityIdentifier("settings.preset")
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(ColorPreset.allCases.filter { $0 != .custom }, id: \.self) { preset in
                        let selected = ColorPreset.matching(editor.draft.value) == preset
                        let swatch = preset.previewColors
                        Button {
                            (editor.draft.value.foregroundColor, editor.draft.value.backgroundColor, editor.draft.value.cursorColor) = preset.colors
                        } label: {
                            HStack(spacing: 6) {
                                ZStack {
                                    RoundedRectangle(cornerRadius: 4)
                                        .fill(Color(nsColor: NSColor(sessionHex: swatch.background)))
                                        .frame(width: 22, height: 16)
                                        .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(Color.white.opacity(0.18)))
                                    Text("A_")
                                        .font(.system(size: 8, weight: .bold, design: .monospaced))
                                        .foregroundStyle(Color(nsColor: NSColor(sessionHex: swatch.foreground)))
                                }
                                Text(preset.rawValue)
                                    .font(.system(size: 11, weight: selected ? .semibold : .regular))
                                    .lineLimit(1)
                            }
                            .padding(.horizontal, 8).padding(.vertical, 5)
                            .background(selected ? DesktopStyle.selection : DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 7))
                            .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(selected ? Color.accentColor.opacity(0.7) : DesktopStyle.border))
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            field("前景色", range: "#RRGGBB", id: "settings.foreground", binding: $editor.draft.value.foregroundColor)
            field("背景色", range: "#RRGGBB", id: "settings.background", binding: $editor.draft.value.backgroundColor)
            field("光标色", range: "#RRGGBB", id: "settings.cursor", binding: $editor.draft.value.cursorColor)
            Picker("光标形状", selection: $editor.draft.value.cursorShape) {
                Text("方块（默认）").tag(TerminalCursorShape.block)
                Text("下划线").tag(TerminalCursorShape.underline)
                Text("竖线").tag(TerminalCursorShape.bar)
            }.accessibilityIdentifier("settings.cursorShape")
            Toggle("光标闪烁（默认开启）", isOn: $editor.draft.value.cursorBlink).accessibilityIdentifier("settings.cursorBlink")
            field("历史行数", range: "0–50000 行；默认 10000", id: "settings.history", binding: $editor.draft.history)
            note("保存后字体、配色、光标和历史容量立即应用所有现有标签，不重连。降低历史容量会清掉超出上限的内存历史；远端 TUI 仍可按终端协议改变光标。")
            HStack {
                Text("实际终端预览").font(.subheadline).bold()
                Spacer()
                Text(ColorPreset.matching(editor.draft.value).rawValue)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            let previewBg = previewSettings.map {
                let hex = ColorPreset.matching($0) == .nord ? ColorPreset.nord.previewColors.background : $0.backgroundColor
                return Color(nsColor: NSColor(sessionHex: hex))
            } ?? DesktopStyle.terminalBackground
            VStack(spacing: 0) {
                HStack(spacing: 6) {
                    Circle().fill(Color(nsColor: .systemRed).opacity(0.8)).frame(width: 8, height: 8)
                    Circle().fill(Color(nsColor: .systemYellow).opacity(0.8)).frame(width: 8, height: 8)
                    Circle().fill(Color(nsColor: .systemGreen).opacity(0.8)).frame(width: 8, height: 8)
                    Text("ssh prod-app · zsh")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Color.white.opacity(0.55))
                        .padding(.leading, 4)
                    Spacer()
                }
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(Color.white.opacity(0.04))
                PreferencesTerminalPreview(settings: previewSettings)
                    .padding(.horizontal, 8).padding(.vertical, 6)
                    .frame(height: 118)
                    .accessibilityIdentifier("settings.preview")
            }
            .background(previewBg, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.borderStrong))
            .clipped()
            if previewSettings == nil { note("当前输入无效，预览保留上一次有效值（首次为终端默认）；请修正后保存。") }
            Divider()
            Text("粘贴策略：精确原字节（当前固定策略）").font(.subheadline)
            note("多行不额外确认、不补回车；保留 UTF-8 与 Bracketed Paste，含包装总计最多 256 KiB。远端仍可能执行粘贴内容。可选多行确认尚未提供，不显示未接线开关。")
        case .connection:
            HStack(spacing: 8) {
                Text("快速预设").font(.caption).foregroundStyle(.secondary)
                ForEach([("高稳 15 秒", "15", "3"), ("标准 30 秒", "30", "3"), ("省电 60 秒", "60", "3"), ("关闭", "0", "3")], id: \.0) { label, iv, cnt in
                    let active = editor.draft.interval == iv && editor.draft.count == cnt
                    Button(label) {
                        editor.draft.interval = iv
                        editor.draft.count = cnt
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .tint(active ? .accentColor : .secondary)
                }
            }
            field("新主机默认 TCP 保活间隔", range: "0–3600 秒；默认 30，0 关闭", id: "settings.interval", binding: $editor.draft.interval)
            field("新主机默认 TCP 失败探测次数", range: "1–10 次；默认 3", id: "settings.count", binding: $editor.draft.count)
            note("连接空闲后由系统发送 TCP 保活；未响应时按相同间隔重试，到达失败次数后由系统判定连接失效。实际时刻由系统调度，不是固定的 SSH 响应截止时间。间隔 0 关闭；只用于以后新建的主机，已有主机和打开的连接不变。")
            note("保活不申请额外 SSH 通道或执行命令；TCP 仍响应时不能据此判断远端 SSH 程序是否卡住。保活不能保证远端任务在断线后继续。")
            note("连接超时按连接与认证阶段的安全策略处理。默认不自动重连、不执行启动命令，不支持自动跳板或端口转发。")
        case .files:
            Picker("同名文件", selection: $editor.draft.value.fileConflictPolicy) {
                Text("每次询问（默认）").tag(FileConflictPreference.ask)
                Text("总是都保留（自动改名）").tag(FileConflictPreference.autoRename)
                Text("总是替换").tag(FileConflictPreference.overwrite)
                Text("总是跳过").tag(FileConflictPreference.skip)
            }.accessibilityIdentifier("settings.files.conflict")
            note("无同名时直接传输。同名时默认选择取消、替换或都保留；都保留会自动生成新名称。")
            DisclosureGroup("传输说明") {
                note("传输不会自动重连或续传。远端路径检查、持久化与覆盖受服务器协议能力限制，详情可在任务中查看。")
            }
        case .privacy:
            note(DesktopHelp.localDataDescription)
            Divider()
            Text("本地诊断预览").font(.subheadline).bold()
            note("仅包含下方明确选择的非秘密项目。不会读取或收集密码、私钥、Keychain、主机名/端点、文件内容、用户路径、终端历史或认证提示；不会上传。")
            ForEach(DiagnosticCategory.allCases) { item in
                Toggle(item.title, isOn: Binding(get: { diagnosticCategories.contains(item) }, set: { selected in
                    if selected { diagnosticCategories.insert(item) } else { diagnosticCategories.remove(item) }
                    copied = false
                })).accessibilityIdentifier("diagnostics.category." + item.rawValue)
            }
            Text("目的地：本机剪贴板。不会创建文件或发送网络请求。复制后其他本机应用可能读取剪贴板。")
                .font(.caption).foregroundStyle(.secondary)
            Text(diagnosticText).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading).padding(12).background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 6))
                .accessibilityIdentifier("diagnostics.preview")
            HStack {
                Button("刷新预览") { diagnosticSnapshot = PublicDiagnosticSnapshot(model: model); copied = false }
                Button("复制以上预览") { copied = PublicDiagnosticSnapshot.copy(diagnosticText, to: .general) }
                    .disabled(diagnosticCategories.isEmpty).accessibilityIdentifier("diagnostics.copy")
                if copied { Text("已复制").font(.caption) }
            }.onAppear { if diagnosticSnapshot == nil { diagnosticSnapshot = PublicDiagnosticSnapshot(model: model) } }
        case .about:
            Text(DesktopHelp.versionDescription()).font(.subheadline)
            Button("关于 OpenLXSSH…") { NSApp.orderFrontStandardAboutPanel(nil) }
            Text(DesktopHelp.shortcuts).font(.callout).textSelection(.enabled)
            Divider()
            Text("本地数据").font(.subheadline).bold()
            note(DesktopHelp.localDataDescription)
            Divider()
            Text("第三方许可").font(.subheadline).bold()
            note("只读取当前 App bundle 中已打包的许可，不访问网络。完整文本与缺失状态可在帮助菜单的“第三方许可”中查看。")
            ForEach(DesktopHelp.licenses) { license in
                DisclosureGroup(license.title) {
                    Text(DesktopHelp.licenseText(license)).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }
    private var previewSettings: AppSettings? { try? editor.draft.validated() }
    private var diagnosticText: String {
        (diagnosticSnapshot ?? PublicDiagnosticSnapshot(model: model)).preview(categories: diagnosticCategories)
    }
    private func save(reviewID: UUID? = nil) {
        Task { if await editor.save(reviewID: reviewID, using: { await model.saveSettings($0) }) { dismiss() } }
    }
    private func field(_ title: String, range: String, id: String, binding: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(title).frame(width: 165, alignment: .leading)
                TextField(range, text: binding).textFieldStyle(.roundedBorder).accessibilityIdentifier(id)
            }
            Text(range).font(.caption).foregroundStyle(.secondary)
        }
    }
    private func note(_ text: String) -> some View { Text(text).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
}

/// A real isolated renderer: no connection, input relay, pasteboard read or remote I/O.
private struct PreferencesTerminalPreview: NSViewRepresentable {
    let settings: AppSettings?
    func makeNSView(context: Context) -> NativeTerminalView {
        let terminal = NativeTerminalView()
        terminal.inputEnabled = false
        terminal.toolTip = "设置预览；不会连接服务器或发送输入。"
        terminal.feed(text: "\u{1b}[32mdeploy@prod\u{1b}[0m \u{1b}[34m~/app\u{1b}[0m \u{1b}[35mmain\u{1b}[0m % ls -la\r\n\u{1b}[34mdrwxr-xr-x\u{1b}[0m  deploy  \u{1b}[36mreleases/\u{1b}[0m   \u{1b}[33mconfig.yml\u{1b}[0m\r\nOpenLXSSH · Aa 0123456789 中文 🙂\r\n\u{1b}[32m✓\u{1b}[0m Ready $ ")
        if let settings { try? TerminalPreferences.apply(settings, to: terminal) }
        return terminal
    }
    func updateNSView(_ terminal: NativeTerminalView, context: Context) {
        if let settings { try? TerminalPreferences.apply(settings, to: terminal) }
    }
    static func dismantleNSView(_ terminal: NativeTerminalView, coordinator: ()) { terminal.releaseResources() }
}
