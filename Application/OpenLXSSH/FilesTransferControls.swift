import AppKit
import Foundation
import OpenLXSSHFiles

/// A single application-owned picker flow. Closing/hiding the file panel never owns its lifetime.
@MainActor final class FilesPathPicker {
    private var active: NSOpenPanel?
    private var generation = UUID()
    #if HOST_PROBE
    var testSelection: [URL]?
    #endif
    func choose(upload: Bool, window: NSWindow?, completion: @escaping ([URL]) -> Void) {
        guard active == nil, let window else { return }
        let panel = NSOpenPanel(), id = UUID(); generation = id; active = panel
        panel.title = upload ? "选择上传的文件或文件夹" : "选择下载目标目录"
        panel.canChooseFiles = upload; panel.canChooseDirectories = true
        panel.allowsMultipleSelection = upload; panel.resolvesAliases = false
        panel.canCreateDirectories = !upload
        #if HOST_PROBE
        if let urls = testSelection {
            testSelection = nil
            // The actual rendered button target/action reaches this picker, but only the
            // isolated HostProbe replaces user selection. Product always presents NSOpenPanel.
            active = nil
            completion(urls)
            return
        }
        #endif
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
