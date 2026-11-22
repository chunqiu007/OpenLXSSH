import Observation
import SwiftUI
import OpenLXSSHCore
import OpenLXSSHFiles

/// Short-lived, view-owned input. Routing invalidation does not touch the controller/service/jobs.
@Observable @MainActor final class FilesInitialInputOwner {
    struct Context: Equatable {
        let visible: Bool
        let hostID: UUID?
        let identity: HostConnectionIdentity?
        let epoch: UUID
        let savedCredentialID: UUID?

        init(visible: Bool, host: HostConfiguration?, keys: [ManagedKeyReference], epoch: UUID) {
            self.visible = visible
            hostID = host?.id
            identity = host?.connectionIdentity
            self.epoch = epoch
            if let host, host.authentication.needsKey {
                savedCredentialID = keys.first { $0.id == host.keyRef }?.passphraseCredentialRef
            } else {
                savedCredentialID = host?.savePasswordAuthorized == true ? host?.credentialRef : nil
            }
        }
    }
    var secret = ""
    var useTemporaryCredential = false
    @ObservationIgnored private var context: Context?
    func update(_ value: Context) {
        if context != value || !value.visible { clear() }
        context = value
    }
    func clear() { secret = ""; useTemporaryCredential = false }
    func take(for displayed: Context) -> FilesConnectInput? {
        guard displayed == context, displayed.visible, displayed.hostID != nil, let identity = displayed.identity else { return nil }
        defer { clear() }
        if !useTemporaryCredential, secret.isEmpty, let id = displayed.savedCredentialID {
            return FilesConnectInput(primary: .configuredCredential(id))
        }
        return FilesConnectInput(primary: .manual(.init(utf8: secret)),
                                 keyboardOnly: !identity.authentication.needsKey && secret.isEmpty)
    }
}

struct FilesConnectionPanelView: View {
    let files: FilesController
    @Bindable var initialInput: FilesInitialInputOwner
    let inputContext: FilesInitialInputOwner.Context
    let needsFirstHost: Bool
    let onCreateHost: () -> Void
    let onChooseHost: () -> Void
    let onCancelConnection: () -> Void
    let onConnect: (FilesInitialInputOwner.Context) -> Void

    private var status: String {
        switch files.state {
        case .disconnected: "未连接"
        case .preparing: "准备连接"
        case .awaitingTrust: "等待主机身份确认"
        case .authenticating: "正在认证"
        case .ready: "已连接"
        case .closing: "正在断开连接"
        case .failed: "连接失败"
        }
    }

    private var requiresKeyPassphrase: Bool {
        files.state == .failed && files.selectedHost?.authentication.needsKey == true
            && files.issue?.code == "files.keyPassphraseRequired"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let host = files.selectedHost {
                HStack(spacing: 12) {
                    DesktopGlyph(systemName: "server.rack", size: 40, prominent: true)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(verbatim: host.name).font(.system(size: 18, weight: .semibold)).lineLimit(2)
                        let endpoint = host.username + "@" + host.vaultEndpoint
                        Text(verbatim: endpoint).font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(endpoint)
                    }
                }
                Divider()
                if files.state == .failed {
                    Label(status, systemImage: "exclamationmark.circle")
                        .font(.callout.weight(.medium)).foregroundStyle(DesktopStyle.statusRed)
                }
                if files.canConnect {
                    connectionForm(host)
                } else {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        if files.state != .failed { Text(status).font(.callout) }
                        Spacer(minLength: 4)
                        if files.busy && files.state != .closing {
                            Button("取消连接", action: onCancelConnection)
                        }
                    }
                }
            } else {
                HStack(spacing: 9) {
                    DesktopGlyph(systemName: "folder", size: 34)
                    Image(systemName: "arrow.left.arrow.right")
                        .font(.system(size: 12, weight: .medium)).foregroundStyle(DesktopStyle.brand)
                    DesktopGlyph(systemName: "server.rack", size: 34, prominent: true)
                }.accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 6) {
                    Text("连接远端主机").font(.system(size: 20, weight: .semibold))
                    Text(needsFirstHost ? "先在保险箱中保存一台主机，即可在这里浏览和传输文件。" : "选择已保存的主机，浏览远端文件。")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Button(needsFirstHost ? "新建主机…" : "选择主机…", action: needsFirstHost ? onCreateHost : onChooseHost)
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier(needsFirstHost ? "files.remote.empty.create" : "files.remote.empty.choose")
            }
        }
        .padding(22)
        .frame(maxWidth: 344, alignment: .leading)
        .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 16))
        .overlay { RoundedRectangle(cornerRadius: 16).strokeBorder(DesktopStyle.border).allowsHitTesting(false) }
        .shadow(color: .black.opacity(0.045), radius: 10, y: 3)
    }

    private func connectionForm(_ host: HostConfiguration) -> some View {
        let displayed = inputContext
        let key = host.authentication.needsKey
        let hasSavedCredential = displayed.savedCredentialID != nil
        let needsPassphrase = requiresKeyPassphrase
        let canUseConfigured = key || hasSavedCredential
        let showField = !canUseConfigured || initialInput.useTemporaryCredential || needsPassphrase
        return VStack(alignment: .leading, spacing: 10) {
            if showField {
                SecureField(key ? "本次私钥口令" : "本次密码", text: $initialInput.secret)
                    .textFieldStyle(.roundedBorder).controlSize(.large)
                    .onSubmit { onConnect(displayed) }
                    .accessibilityIdentifier("files.initial.secret")
                if !key {
                    Text("留空时按服务器提示认证。").font(.caption).foregroundStyle(.secondary)
                }
                if canUseConfigured && !needsPassphrase {
                    Button("使用主机配置") { initialInput.clear() }.buttonStyle(.link)
                }
            } else {
                Label(key ? (hasSavedCredential ? "SSH 密钥 · 已保存口令" : "SSH 密钥") : "使用已保存的密码",
                      systemImage: key ? "key" : "lock")
                    .font(.callout).foregroundStyle(.secondary)
                Button(key ? "输入本次私钥口令…" : "输入本次密码…") {
                    initialInput.useTemporaryCredential = true
                }.buttonStyle(.link)
            }
            NativeButton(title: files.state == .failed ? "重新连接 SFTP" : "连接 SFTP", id: "files.connect",
                         enabled: files.canConnect && !files.busy && !(needsPassphrase && initialInput.secret.isEmpty),
                         isProminent: true) { onConnect(displayed) }
                .fixedSize()
        }
    }
}

struct FilesHostChooserSheet: View {
    let app: AppModel
    let files: FilesController
    @State private var hostSearch = ""
    @State private var hostFilter = "all"
    @State private var focusRequest = UUID()
    let onCreateHost: () -> Void
    let onSelect: (HostConfiguration) -> Void
    let onCancel: () -> Void

    private var filteredHosts: [HostConfiguration] {
        let hosts = app.connectionHosts.filter { host in
            (hostFilter != "favorites" || host.isFavorite) && (hostFilter != "recent" || host.lastConnectedAt != nil) &&
            (hostSearch.isEmpty || [host.name, host.address, host.username].contains { $0.localizedStandardContains(hostSearch) })
        }
        return hostFilter == "recent" ? hosts.sorted { ($0.lastConnectedAt ?? .distantPast) > ($1.lastConnectedAt ?? .distantPast) } : hosts
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("选择远端主机").font(.title2.weight(.semibold))
            DesktopSearchField(placeholder: "搜索名称、地址或用户名", id: "files.host.search", text: $hostSearch, focusRequest: focusRequest)
            Picker("范围", selection: $hostFilter) { Text("全部").tag("all"); Text("收藏").tag("favorites"); Text("最近").tag("recent") }.pickerStyle(.segmented)
            let matches = filteredHosts
            Group {
                if !app.didLoad && app.isLoading {
                    ProgressView("正在读取主机")
                } else if !app.didLoad && app.issue != nil {
                    VStack(spacing: 8) {
                        Text("无法读取主机列表").font(.headline)
                        Button("重试") { Task { _ = await app.reload() } }
                    }
                } else if matches.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: app.connectionHosts.isEmpty ? "server.rack" : "magnifyingglass")
                            .font(.title2).foregroundStyle(.secondary)
                        Text(app.connectionHosts.isEmpty ? "保险箱中尚无主机" : "没有匹配的主机").font(.headline)
                        if app.connectionHosts.isEmpty {
                            Button("在保险箱新建主机…", action: onCreateHost)
                        } else {
                            Button("显示所有主机") { hostFilter = "all"; hostSearch = "" }
                        }
                    }
                } else {
                    ScrollView {
                        LazyVStack(spacing: 4) {
                            ForEach(matches, id: \.id) { host in hostChooserRow(host) }
                        }
                    }
                }
            }.frame(maxWidth: .infinity).frame(height: 250)
            HStack { Spacer(); Button("取消", action: onCancel).keyboardShortcut(.cancelAction) }
        }.padding(22).frame(width: 480).background(DesktopStyle.background)
    }

    private func hostChooserRow(_ host: HostConfiguration) -> some View {
        let isCurrent = files.selectedHost?.id == host.id
        return Button { onSelect(host) } label: {
            HStack(spacing: 10) {
                Image(systemName: host.isFavorite ? "star.fill" : "server.rack")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(host.isFavorite ? DesktopStyle.statusAmber : Color.accentColor)
                    .frame(width: 32, height: 32)
                    .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 2) {
                    Text(host.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                    Text(verbatim: host.username + "@" + host.vaultEndpoint)
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                if isCurrent {
                    DesktopBadge(text: "当前", color: Color.accentColor, fill: DesktopStyle.iconSurface)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(isCurrent ? DesktopStyle.selection : DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(isCurrent ? Color.accentColor.opacity(0.6) : DesktopStyle.border))
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }
}
