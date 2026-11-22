import AppKit
import SwiftUI
import OpenLXSSHCore

struct VaultSidebarView: View {
    let app: AppModel
    let model: VaultDesktopModel
    let onNavigate: (@escaping () -> Void) -> Void
    let onSelectSection: (VaultSection) -> Void
    let onNewRootFolder: () -> Void
    let onEditFolder: (HostFolder?) -> Void
    let onAddChildFolder: (UUID?) -> Void
    let onNewHostInFolder: (UUID) -> Void
    let onImportMove: ([NSItemProvider], UUID?) -> Bool
    let onDeleteFolder: (UUID) -> Void
    let onNewTag: () -> Void
    let onRenameTag: (HostTag) -> Void
    let onDeleteTag: (UUID) -> Void

    private var page: VaultManagementPage {
        get { model.managementPage }
        nonmutating set { model.managementPage = newValue }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                DesktopGlyph(systemName: "terminal", size: 36, prominent: true)
                VStack(alignment: .leading, spacing: 3) {
                    Text("OpenLXSSH").font(.system(size: 16, weight: .semibold, design: .rounded)).fixedSize()
                    Text("本地保险箱").font(.caption).foregroundStyle(.secondary)
                }
            }.padding(.horizontal, 15).padding(.top, 20).padding(.bottom, 11)
            Divider().padding(.horizontal, 15).padding(.bottom, 7)
            ScrollView {
                VStack(alignment: .leading, spacing: 3) {
                    Text("主机").font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                        .padding(.horizontal, 16).padding(.top, 4).padding(.bottom, 6)
                    navigation("所有主机", icon: "server.rack", count: model.catalog.count, active: page == .hosts && model.section == .all) { onSelectSection(.all) }
                    navigation("收藏", icon: "star", count: model.catalog.filter(\.isFavorite).count, active: page == .hosts && model.section == .favorites) { onSelectSection(.favorites) }
                    navigation("未分组", icon: "tray", count: model.catalog.filter { $0.folderID == nil }.count, active: page == .hosts && model.section == .ungrouped) { onSelectSection(.ungrouped) }
                    HStack {
                        Text("分组").font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                        Spacer()
                        Button(action: onNewRootFolder) { Image(systemName: "plus").frame(width: 20, height: 20).contentShape(Rectangle()) }
                            .buttonStyle(.plain).help("新建根分组").accessibilityLabel("新建根分组")
                    }.padding(.horizontal, 16).padding(.top, 10).padding(.bottom, 2)
                    VaultFolderTree(model: model, parentID: nil, depth: 0, select: { onSelectSection(.folder($0)) },
                        edit: onEditFolder, add: onAddChildFolder, newHost: onNewHostInFolder,
                        importMove: onImportMove, remove: onDeleteFolder).padding(.horizontal, 6)
                    HStack {
                        Text("标签").help("多选标签时，同时匹配所选标签").font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                        Spacer()
                        Button(action: onNewTag) { Image(systemName: "plus").frame(width: 20, height: 20).contentShape(Rectangle()) }
                            .buttonStyle(.plain).help("新建标签").accessibilityLabel("新建标签")
                    }.padding(.horizontal, 16).padding(.top, 10).padding(.bottom, 2)
                    ForEach(model.tags) { tag in
                        Button {
                            _ = model.performManagementNavigation {
                                page = .hosts
                                if model.tagFilter.contains(tag.id) { model.tagFilter.remove(tag.id) } else { model.tagFilter.insert(tag.id) }
                            }
                        } label: {
                            HStack { Image(systemName: model.tagFilter.contains(tag.id) ? "checkmark.circle.fill" : "tag"); Text(tag.name).lineLimit(1); Spacer() }
                                .font(.system(size: 12)).padding(.horizontal, 10).padding(.vertical, 7)
                                .background(model.tagFilter.contains(tag.id) ? DesktopStyle.brandSurface : .clear, in: RoundedRectangle(cornerRadius: 7))
                                .contentShape(Rectangle())
                        }.buttonStyle(.plain).padding(.horizontal, 6)
                        .contextMenu {
                            Button("重命名标签…") { onRenameTag(tag) }
                            Button("删除全局标签…", role: .destructive) { onDeleteTag(tag.id) }
                        }
                    }
                }
            }
            Divider().padding(.horizontal, 12).padding(.vertical, 6)
            navigation("密钥与凭据", icon: "key", active: page == .keys) { page = .keys }
            navigation("已知主机", icon: "checkmark.shield", active: page == .trust) { page = .trust }
            navigation("设置…", icon: "gearshape", active: false) { _ = app.sendWorkspaceCommand(.settings) }
            Label("配置保存在此 Mac", systemImage: "internaldrive")
                .font(.system(size: 10)).foregroundStyle(.secondary)
                .help("配置仅保存在本机，凭据使用系统 Keychain；无云同步或独立保险箱锁。")
                .padding(.horizontal, 16).padding(.top, 4).padding(.bottom, 14)
        }.background(DesktopStyle.sidebar)
    }

    private func navigation(_ title: String, icon: String, count: Int? = nil, active: Bool, action: @escaping () -> Void) -> some View {
        VaultSidebarNavButton(title: title, icon: icon, count: count, active: active) {
            onNavigate(action)
        }
    }
}

private struct VaultFolderTree: View {
    let model: VaultDesktopModel
    let parentID: UUID?
    let depth: Int
    let select: (UUID) -> Void
    let edit: (HostFolder?) -> Void
    let add: (UUID?) -> Void
    let newHost: (UUID) -> Void
    let importMove: ([NSItemProvider], UUID?) -> Bool
    let remove: (UUID) -> Void

    var body: some View {
        ForEach(model.children(of: parentID)) { folder in
            VStack(spacing: 0) {
                HStack(spacing: 5) {
                    Button { model.toggleExpanded(folder.id) } label: { Image(systemName: model.preferences.expandedFolders.contains(folder.id) ? "chevron.down" : "chevron.right").font(.caption2).frame(width: 12) }
                        .buttonStyle(.plain).accessibilityLabel("展开或折叠“\(folder.name)”")
                    Button { select(folder.id) } label: {
                        Label(folder.name + (model.folders.filter { $0.name == folder.name }.count > 1 ? " · " + folder.id.uuidString.prefix(6) : ""), systemImage: "folder")
                            .lineLimit(1).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                    }.buttonStyle(.plain)
                }.padding(.vertical, 7).padding(.leading, CGFloat(depth * 12 + 6)).padding(.trailing, 6)
                    .background(model.section == .folder(folder.id) ? DesktopStyle.brandSurface : .clear, in: RoundedRectangle(cornerRadius: 7))
                    .help(model.folderLabel(folder))
                    .onDrop(of: [.text], isTargeted: nil) { providers in importMove(providers, folder.id) }
                    .contextMenu {
                        Button("新建主机…") { newHost(folder.id) }
                        Button("新建子组…") { add(folder.id) }
                        Button("重命名或移动…") { edit(folder) }
                        Button("删除分组…", role: .destructive) { remove(folder.id) }
                    }
                if model.preferences.expandedFolders.contains(folder.id) {
                    AnyView(VaultFolderTree(model: model, parentID: folder.id, depth: depth + 1, select: select, edit: edit, add: add, newHost: newHost, importMove: importMove, remove: remove))
                }
            }
        }
    }
}

private struct VaultSidebarNavButton: View {
    let title: String
    let icon: String
    let count: Int?
    let active: Bool
    let action: () -> Void
    @State private var hovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: active ? .semibold : .regular))
                    .frame(width: 18)
                    .foregroundStyle(active ? DesktopStyle.brand : .secondary)
                Text(title)
                    .font(.system(size: 13, weight: active ? .semibold : .regular))
                    .lineLimit(1)
                Spacer(minLength: 4)
                if let count, count > 0 {
                    Text("\(count)")
                        .font(.system(size: 11, weight: .medium).monospacedDigit())
                        .foregroundStyle(active ? DesktopStyle.brand : .secondary)
                        .padding(.trailing, 2)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 10).padding(.vertical, 8)
            .background(active ? DesktopStyle.brandSurface : (hovered ? DesktopStyle.panelElevated : .clear), in: RoundedRectangle(cornerRadius: 8))
            .overlay(alignment: .leading) {
                if active {
                    Capsule().fill(DesktopStyle.brand).frame(width: 3, height: 15)
                        .accessibilityHidden(true).allowsHitTesting(false)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 6)
        .onHover { hovered = $0 }
        .accessibilityAddTraits(active ? .isSelected : [])
    }
}
