import SwiftUI
import OpenLXSSHCore

struct VaultInspectorView: View {
    let model: VaultDesktopModel
    let host: HostConfiguration
    let menuItems: [VaultHostMenuItem]
    let onCommand: (VaultHostCommand) -> Void
    let onEdit: () -> Void
    let onClose: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text("主机详情").font(.system(size: 13, weight: .semibold))
                Spacer()
                Menu { VaultHostMenu(items: menuItems, action: onCommand) } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton).fixedSize()
                .help("主机操作").accessibilityLabel("主机操作")
                Button(action: onClose) { Image(systemName: "xmark").frame(width: 20, height: 20) }
                    .buttonStyle(.borderless).help("收起检查器").accessibilityLabel("收起检查器")
            }.padding(.horizontal, 16).padding(.vertical, 12)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(spacing: 10) {
                        Image(systemName: "server.rack")
                            .font(.system(size: 18, weight: .medium))
                            .foregroundStyle(Color.accentColor)
                            .frame(width: 36, height: 36)
                            .background(DesktopStyle.iconSurface, in: RoundedRectangle(cornerRadius: 9))
                        Text(host.name)
                            .font(.system(size: 18, weight: .semibold))
                            .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        if host.isFavorite {
                            Image(systemName: "star.fill").font(.caption)
                                .foregroundStyle(.orange).accessibilityLabel("已收藏")
                        }
                    }
                    detailSection("地址") {
                        HStack(spacing: 6) {
                            Text(verbatim: host.vaultEndpoint).font(.system(size: 12, design: .monospaced))
                                .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                            Button { onCommand(.copyEndpoint(host.id)) } label: {
                                Image(systemName: "doc.on.doc").frame(width: 20, height: 20)
                            }
                            .buttonStyle(.borderless).help("复制端点").accessibilityLabel("复制端点")
                        }
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 7))
                    }
                    Divider()
                    detailSection("SSH") {
                        DesktopKeyValueRow(label: "用户名", value: host.username, monospaced: true)
                        DesktopKeyValueRow(label: "端口", value: String(host.port), monospaced: true)
                        DesktopKeyValueRow(label: "认证方式", value: host.vaultAuthenticationLabel)
                        if let key = model.snapshot?.keys.first(where: { $0.id == host.keyRef }) {
                            DesktopKeyValueRow(label: "密钥", value: key.label.isEmpty ? key.algorithm.rawValue.uppercased() + " · " + key.id.uuidString.prefix(8) : key.label)
                        } else if host.credentialRef != nil {
                            DesktopKeyValueRow(label: "凭据", value: "已保存密码")
                        }
                    }
                    Divider()
                    detailSection("常规") {
                        DesktopKeyValueRow(label: "分组", value: host.folderID.map(model.path(for:)) ?? "未分组")
                        if let tags = model.metadata(for: host.id)?.tags, !tags.isEmpty {
                            HStack(spacing: 8) {
                                Text("标签").foregroundStyle(.secondary)
                                ScrollView(.horizontal) {
                                    HStack(spacing: 5) {
                                        ForEach(tags) { tag in
                                            DesktopBadge(text: tag.name, color: .accentColor, fill: DesktopStyle.iconSurface)
                                        }
                                    }
                                    .frame(maxWidth: .infinity, alignment: .trailing)
                                }
                                .defaultScrollAnchor(.trailing, for: .alignment)
                            }
                        }
                    }
                    Divider()
                    DisclosureGroup("高级") {
                        VStack(alignment: .leading, spacing: 8) {
                            DesktopKeyValueRow(label: "TCP 空闲/重试间隔", value: host.keepaliveInterval == 0 ? "已关闭" : "\(host.keepaliveInterval) 秒")
                            DesktopKeyValueRow(label: "TCP 失败探测次数", value: "\(host.keepaliveCountMax) 次")
                            Text("系统按 TCP 保活设置判断失联。远端任务能否在断线后继续，取决于服务器。")
                                .font(.caption).foregroundStyle(.secondary)
                            DesktopKeyValueRow(label: "最近认证成功", value: host.lastConnectedAt?.formatted() ?? "从未连接")
                        }.padding(.top, 8)
                    }.font(.system(size: 12, weight: .medium))
                }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            HStack(spacing: 8) {
                Button(action: onEdit) { Label("编辑", systemImage: "pencil") }
                    .accessibilityLabel("编辑主机")
                Spacer(minLength: 4)
                Button { onCommand(.connect(host.id, .reuse)) } label: { Label("连接", systemImage: "terminal") }
                    .buttonStyle(.borderedProminent)
            }.padding(.horizontal, 16).padding(.vertical, 12)
        }.frame(maxHeight: .infinity).background(DesktopStyle.panel)
    }

    private func detailSection<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
            content().font(.system(size: 12))
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}
