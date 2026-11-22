import AppKit
import SwiftUI
import OpenLXSSHCore

@MainActor private struct SettingsPresentation: Identifiable {
    let id = UUID()
    let editor: SettingsEditorModel
    let category: PreferencesCategory
    init(_ settings: AppSettings, category: PreferencesCategory = .general) { editor = SettingsEditorModel(settings); self.category = category }
}

struct MainView: View {
    let model: AppModel
    private let files: FilesController
    @State private var settingsPresentation: SettingsPresentation?
    @State private var windowChrome = WorkspaceWindowChromeState()
    init(model: AppModel) { self.model = model; files = model.files }
    private var managementAppearance: NSAppearance.Name? {
        switch model.settings.theme { case .system: nil; case .light: .aqua; case .dark: .darkAqua }
    }
    var body: some View {
        VStack(spacing: 0) {
            WorkspaceTabBar(model: model, windowChrome: windowChrome)
            IssueView(issue: model.issue) { model.issue = nil }.padding(.horizontal, 10)
            Divider()
            ZStack {
                NativeWorkspacePage(id: "workspace.page.vault", isVisible: model.workspacePage == .vault, appearance: managementAppearance) {
                    VaultWorkspacePage(app: model, transientConnection: { host, intent in
                        try await model.prepareTransientConnection(host, intent: intent)
                    })
                }
                NativeWorkspacePage(id: "workspace.page.sftp", isVisible: model.workspacePage == .sftp, appearance: managementAppearance) { DualPaneFilesView(model: model) }
                NativeWorkspacePage(id: "workspace.page.sessions", isVisible: model.workspacePage.sessionID != nil, appearance: .darkAqua) { SessionWorkspaceView(controller: model.sessions) }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(DesktopStyle.background).foregroundStyle(.primary)
            FilesApplicationUI(model: files, showsTasks: false)
            FilesTransferStatus(model: files)
        }
        .padding(.top, windowChrome.topSafeInset)
        .background(DesktopStyle.background).foregroundStyle(.primary)
        .background(WorkspaceWindowChromeAnchor(state: windowChrome, terminal: model.workspacePage.sessionID != nil).frame(width: 0, height: 0))
        .ignoresSafeArea(.container, edges: windowChrome.isIntegrated ? .top : [])
        .frame(minWidth: 920, minHeight: 580)
        .preferredColorScheme(model.settings.theme == .system ? nil : (model.settings.theme == .dark ? .dark : .light))
        .task { if !model.didLoad { await model.reload() } }
        .onChange(of: model.workspaceCommand) { _, request in
            if request?.command == .settings, settingsPresentation == nil { settingsPresentation = SettingsPresentation(model.settings) }
            if request?.command == .diagnostics, settingsPresentation == nil { settingsPresentation = SettingsPresentation(model.settings, category: .privacy) }
        }
        .nativeSheet(item: $settingsPresentation, onAttemptDismiss: { settingsPresentation?.editor.attemptClose() ?? true }) { presentation in
            SettingsEditor(model: model, editor: presentation.editor, initialCategory: presentation.category) { settingsPresentation = nil }
        }
    }
}
