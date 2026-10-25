import AppKit
import SwiftUI
import OpenLXSSHCore

struct HostEditor: View {
    @ObservedObject var model: AppModel
    @State private var draft: HostDraft
    var dismiss: () -> Void
    init(model: AppModel, host: HostConfiguration?, folderID: UUID?, dismiss: @escaping () -> Void) {
        self.model = model; self.dismiss = dismiss
        _draft = State(initialValue: HostDraft(host: host, settings: model.settings, folderID: folderID))
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(draft.isNew ? "添加主机" : "编辑主机").font(.title2).bold()
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 12) {
                field("名称", "host.name", $draft.configuration.name)
                field("地址", "host.address", $draft.configuration.address)
                field("端口", "host.port", $draft.port)
                field("用户名", "host.username", $draft.configuration.username)
                GridRow {
                    Text("认证方式")
                    NativePopup(id: "host.authentication", items: AuthenticationKind.choices.map { PopupItem(value: $0.rawValue, title: $0.displayName) }, selection: Binding(get: { draft.configuration.authentication.rawValue }, set: { if let kind = AuthenticationKind(rawValue: $0) { draft.changeAuthentication(kind) } })).frame(height: 26)
                }
                GridRow {
                    Text("文件夹")
                    NativePopup(id: "host.folder", items: [PopupItem(value: "", title: "未分组")] + model.folders.map { PopupItem(value: $0.id.uuidString, title: $0.name) }, selection: Binding(get: { draft.configuration.folderID?.uuidString ?? "" }, set: { draft.configuration.folderID = UUID(uuidString: $0) })).frame(height: 26)
                }
                if draft.configuration.authentication.needsKey {
                    GridRow {
                        Text("私钥关联")
                        NativePopup(id: "host.key", items: [PopupItem(value: "", title: "未选择私钥")] + model.keys.map { PopupItem(value: $0.id.uuidString, title: $0.algorithm.rawValue.uppercased() + " · " + $0.id.uuidString.prefix(8)) }, selection: Binding(get: { draft.configuration.keyRef?.uuidString ?? "" }, set: { draft.configuration.keyRef = UUID(uuidString: $0) })).frame(height: 26)
                    }
                }
                field("保活间隔（秒）", "host.interval", $draft.interval)
                field("保活失败次数", "host.count", $draft.count)
            }
            if draft.configuration.authentication.needsKey {
                Text(model.keys.isEmpty ? "暂无已登记私钥。密钥管理尚未集成；可先保存配置，连接前必须选择有效私钥。" : "仅列出已登记的密钥引用；本页不读取、导入或复制私钥内容。")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Toggle("记住密码（尚缺安全保存授权条件）", isOn: .constant(false)).disabled(true)
                Text(draft.configuration.credentialRef == nil ? "本版本只保存主机元数据，不收集或保存密码。认证与 Keychain 将独立集成。" : "此配置已有凭据引用，本页仅保留引用，不读取或重新保存秘密。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text("保活 0 表示禁用；间隔最多 3600 秒，失败次数 1–10。保存配置不代表已通过连接边界校验。").font(.caption).foregroundStyle(.secondary)
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                Spacer()
                NativeButton(title: "取消", id: "editor.cancel") { dismiss() }.fixedSize()
                NativeButton(title: "保存", id: "host.save", enabled: !model.isWriting) {
                    Task {
                        do { if await model.saveHost(try draft.value(), isNew: draft.isNew) { dismiss() } }
                        catch { model.issue = .sanitized(error) }
                    }
                }.fixedSize()
            }
        }.padding(24).frame(width: 530)
    }
    private func field(_ label: String, _ id: String, _ binding: Binding<String>) -> some View {
        GridRow { Text(label); NativeField(placeholder: label, id: id, text: binding).frame(height: 25) }
    }
}

struct FolderEditor: View {
    @ObservedObject var model: AppModel
    let original: HostFolder?
    @State private var name: String
    var dismiss: () -> Void
    init(model: AppModel, folder: HostFolder?, dismiss: @escaping () -> Void) {
        self.model = model; original = folder; _name = State(initialValue: folder?.name ?? ""); self.dismiss = dismiss
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(original == nil ? "添加文件夹" : "重命名文件夹").font(.title2).bold()
            NativeField(placeholder: "文件夹名称", id: "folder.name", text: $name).frame(height: 26)
            Text("文件夹只有一层。删除文件夹不会删除其中主机。").font(.caption).foregroundStyle(.secondary)
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                Spacer()
                NativeButton(title: "取消", id: "editor.cancel") { dismiss() }.fixedSize()
                NativeButton(title: "保存", id: "folder.save", enabled: !model.isWriting) {
                    Task {
                        var folder = original ?? HostFolder(name: name)
                        folder.name = name
                        if await model.saveFolder(folder) { dismiss() }
                    }
                }.fixedSize()
            }
        }.padding(24).frame(width: 430)
    }
}

struct SettingsEditor: View {
    @ObservedObject var model: AppModel
    @State private var draft: SettingsDraft
    @State private var preset: ColorPreset
    var dismiss: () -> Void
    init(model: AppModel, dismiss: @escaping () -> Void) {
        self.model = model; self.dismiss = dismiss
        _draft = State(initialValue: SettingsDraft(model.settings)); _preset = State(initialValue: .matching(model.settings))
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("设置").font(.title2).bold()
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                field("字体 PostScript 名", "settings.font", $draft.value.fontName)
                field("字号（6–72）", "settings.size", $draft.size)
                GridRow {
                    Text("外观")
                    NativePopup(id: "settings.theme", items: [PopupItem(value: "system", title: "跟随系统"), PopupItem(value: "light", title: "浅色"), PopupItem(value: "dark", title: "深色")], selection: Binding(get: { draft.value.theme.rawValue }, set: { if let theme = TerminalTheme(rawValue: $0) { draft.value.theme = theme } })).frame(height: 26)
                }
                GridRow {
                    Text("终端配色")
                    NativePopup(id: "settings.preset", items: ColorPreset.allCases.map { PopupItem(value: $0.rawValue, title: $0.rawValue) }, selection: Binding(get: { preset.rawValue }, set: { value in
                        guard let choice = ColorPreset(rawValue: value) else { return }
                        preset = choice
                        if choice != .custom { (draft.value.foregroundColor, draft.value.backgroundColor, draft.value.cursorColor) = choice.colors }
                    })).frame(height: 26)
                }
                colorField("前景色", "settings.foreground", $draft.value.foregroundColor)
                colorField("背景色", "settings.background", $draft.value.backgroundColor)
                colorField("光标色", "settings.cursor", $draft.value.cursorColor)
                field("历史行数（0–50000）", "settings.history", $draft.history)
                field("默认保活间隔（秒）", "settings.interval", $draft.interval)
                field("默认保活失败次数", "settings.count", $draft.count)
            }
            Text("历史默认 10000 行，当前终端上限为 50000；超过上限会报错，不会静默截断。默认保活只用于新主机，已有主机保持各自设置。")
                .font(.caption).foregroundStyle(.secondary)
            Text("Aa 中文 0123456789 — 字体与配色预览")
                .font(Font(NSFont(name: draft.value.fontName, size: previewSize) ?? NSFont.monospacedSystemFont(ofSize: previewSize, weight: .regular)))
                .foregroundStyle(Color(hex: draft.value.foregroundColor)).padding(12).frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(hex: draft.value.backgroundColor)).clipShape(RoundedRectangle(cornerRadius: 6))
            Text("这是设置预览，不是终端；SSH/终端尚未集成。").font(.caption).foregroundStyle(.secondary)
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                Spacer()
                NativeButton(title: "取消", id: "editor.cancel") { dismiss() }.fixedSize()
                NativeButton(title: "保存设置", id: "settings.save", enabled: !model.isWriting) {
                    Task {
                        do { if await model.saveSettings(try draft.validated()) { dismiss() } }
                        catch { model.issue = .sanitized(error) }
                    }
                }.fixedSize()
            }
        }.padding(24).frame(width: 590)
    }
    private func field(_ label: String, _ id: String, _ binding: Binding<String>) -> some View {
        GridRow { Text(label); NativeField(placeholder: label, id: id, text: binding).frame(height: 25) }
    }
    private var previewSize: Double {
        guard let size = Double(draft.size), size.isFinite, (6...72).contains(size) else { return 13 }
        return size
    }
    private func colorField(_ label: String, _ id: String, _ binding: Binding<String>) -> some View {
        field(label + " #RRGGBB", id, Binding(get: { binding.wrappedValue }, set: { binding.wrappedValue = $0; preset = .custom }))
    }
}

private extension Color {
    init(hex: String) {
        let value = UInt32(hex.dropFirst(), radix: 16) ?? 0
        self.init(red: Double((value >> 16) & 255) / 255, green: Double((value >> 8) & 255) / 255, blue: Double(value & 255) / 255)
    }
}
