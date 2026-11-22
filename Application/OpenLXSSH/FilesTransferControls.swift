import AppKit
import Foundation
import OpenLXSSHFiles

/// A single application-owned picker flow. Closing/hiding the file panel never owns its lifetime.
@MainActor final class FilesPathPicker {
    private var active: NSOpenPanel?
    private var generation = UUID()
    var isChoosing: Bool { active != nil }
    func choose(upload: Bool, window: NSWindow?, completion: @escaping ([URL]) -> Void) {
        guard active == nil, let window else { return }
        let panel = NSOpenPanel(), id = UUID(); generation = id; active = panel
        panel.title = upload ? "选择上传的文件或文件夹" : "选择下载目标目录"
        panel.canChooseFiles = upload; panel.canChooseDirectories = true
        panel.allowsMultipleSelection = upload; panel.resolvesAliases = false
        panel.canCreateDirectories = !upload
        panel.beginSheetModal(for: window) { [weak self, weak panel] response in
            MainActor.assumeIsolated {
                guard let self, self.generation == id, self.active === panel else { return }
                self.active = nil
                if response == .OK, let panel { completion(panel.urls) }
            }
        }
    }
    func cancel() {
        generation = UUID()
        if let panel = active { panel.cancel(nil) }
        active = nil
    }
    /// A new user selection, never a silent reopening of a remembered URL.
    @discardableResult func chooseRetry(upload: Bool, original: URL, window: NSWindow?,
                                       completion: @escaping ([URL]?) -> Void) -> Bool {
        guard active == nil, let window else { return false }
        let panel = NSOpenPanel(), id = UUID(); generation = id; active = panel
        panel.title = upload ? "重新选择任务原来的上传来源" : "重新选择任务原来的下载目标目录"
        panel.message = "位置必须与原任务一致；选择后将重新核对传输清单，不会自动覆盖。"
        panel.directoryURL = upload ? original.deletingLastPathComponent() : original
        panel.canChooseFiles = upload; panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false; panel.resolvesAliases = false; panel.canCreateDirectories = false
        panel.beginSheetModal(for: window) { [weak self, weak panel] response in
            MainActor.assumeIsolated {
                guard let self, self.generation == id, self.active === panel else { return }
                self.active = nil
                completion(response == .OK ? panel?.urls : nil)
            }
        }
        return true
    }
}

/// The NSTableView is registered for file URL objects, not text, promises, shell or HTTP payloads.
@MainActor enum FilesDrop {
    static func urls(_ pasteboard: NSPasteboard) -> [URL]? {
        guard let items = pasteboard.pasteboardItems, !items.isEmpty,
              items.allSatisfy({ $0.types.contains(.fileURL) }),
              let values = pasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL],
              values.count == items.count, values.count <= 128, values.allSatisfy(\.isFileURL) else { return nil }
        return values
    }
}
