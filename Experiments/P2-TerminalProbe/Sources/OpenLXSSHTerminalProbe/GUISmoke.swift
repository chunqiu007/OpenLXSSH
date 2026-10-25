import AppKit
import OpenLXSSHTerminalCore

/// Controlled in-process native AppKit smoke, not Accessibility automation.
/// Sends events only to this window, never changes system permissions or IME.
@MainActor
final class GUISmoke {
    private let window: NSWindow
    private let session: ProbeSession
    private let directory: URL
    private let completion: (Int32) -> Void
    private let vim: Bool
    private var timer: Timer?
    private var phase = 0
    private var hiddenFrames = 0
    private var checks = [String: Bool]()
    private let deadline = ProcessInfo.processInfo.systemUptime + 30
    private var began = ProcessInfo.processInfo.systemUptime
    private let started = ProcessInfo.processInfo.systemUptime
    private let holdSeconds = min(max(Double(ProcessInfo.processInfo.environment["P2_SMOKE_HOLD_SECONDS"] ?? "0") ?? 0, 0), 10)
    private let sample = "中文 e\u{301} 😀\nline two"

    init(window: NSWindow, session: ProbeSession, directory: URL, vim: Bool = false, completion: @escaping (Int32) -> Void) {
        self.window = window; self.session = session; self.directory = directory; self.vim = vim; self.completion = completion
    }
    func start() {
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.step() }
        }
    }
    private func event(_ characters: String, key: UInt16, modifiers: NSEvent.ModifierFlags = []) {
        let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: modifiers,
                                    timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber,
                                    context: nil, characters: characters,
                                    charactersIgnoringModifiers: modifiers.contains(.control) ? "c" : characters,
                                    isARepeat: false, keyCode: key)!
        window.sendEvent(event)
    }
    private func step() {
        if ProcessInfo.processInfo.systemUptime > deadline { checks["deadline"] = false; finish(); return }
        let text = session.terminal.text
        if vim { stepVim(text); return }
        switch phase {
        case 0:
            guard text.contains("READY"), ProcessInfo.processInfo.systemUptime - started >= holdSeconds else { return }
            checks["nativeWindowVisible"] = window.isVisible && window.windowNumber > 0
            checks["unicode"] = text.contains(ProbeSettings.unicodeSample)
            checks["search"] = session.terminal.findNext("中文") && session.terminal.getSelection() == "中文"
            session.terminal.selectNone()
            window.makeFirstResponder(session.terminal)
            event("\u{3}", key: 8, modifiers: .control)
            event("\u{f700}", key: 126)
            event("\t", key: 48)
            phase = 1
        case 1:
            guard text.contains("03"), text.contains("1b5b41"), text.contains("09") else { return }
            checks["controlArrowTabEvents"] = true
            session.terminal.pasteTextFromApp(sample)
            phase = 2
        case 2:
            guard text.contains("1b5b3230307e"), text.contains("1b5b3230317e") else { return }
            checks["bracketedMultilinePaste"] = true
            window.setContentSize(NSSize(width: 980, height: 620))
            phase = 3
        case 3:
            guard text.contains("SIZE \(session.terminal.columns)x\(session.terminal.rows)") else { return }
            checks["resizePTY"] = true
            session.terminal.font = .monospacedSystemFont(ofSize: 16, weight: .regular)
            window.appearance = NSAppearance(named: .darkAqua)
            session.terminal.applyColors(for: window.effectiveAppearance)
            checks["fontTheme"] = session.terminal.font.pointSize == 16
            session.terminal.isHidden = true
            hiddenFrames = session.terminal.renderedFrames ?? 0
            session.terminal.send(txt: "h")
            phase = 4
        case 4:
            guard text.contains("HISTORY-END") else { return }
            checks["hiddenOutputRetained"] = true
            if let current = session.terminal.renderedFrames { checks["hiddenRedrawSuspended"] = current - hiddenFrames <= 1 }
            checks["bounded10000History"] = session.terminal.retainedRowCount <= 10_000 + session.terminal.rows
            session.terminal.isHidden = false
            // Leave visible, Unicode history for a reproducible native window capture.
            session.terminal.send(txt: "u")
            began = ProcessInfo.processInfo.systemUptime
            phase = 5
        case 5:
            guard ProcessInfo.processInfo.systemUptime - began > 0.5 else { return }
            capture()
            checks["windowCloseWithLiveChild"] = session.isRunning
            phase = 6
            finish()
        default: break
        }
    }
    private func stepVim(_ text: String) {
        switch phase {
        case 0:
            guard text.contains("OpenLXSSH local Vim fixture") else { return }
            checks["nativeVimWindow"] = window.isVisible && window.windowNumber > 0
            checks["vimInitialUnicode"] = text.contains(ProbeSettings.unicodeSample)
            if checks["vimInitialUnicode"] == false { print("VIM-INITIAL-TEXT \(text.debugDescription)") }
            window.makeFirstResponder(session.terminal)
            session.terminal.send(txt: "Go")
            began = ProcessInfo.processInfo.systemUptime
            phase = 1
        case 1:
            guard ProcessInfo.processInfo.systemUptime - began > 0.2 else { return }
            session.terminal.pasteTextFromApp("VIM-PASTE 中文 é 😀")
            phase = 2
        case 2:
            guard text.contains("VIM-PASTE 中文 é 😀") else { return }
            checks["vimUnicodePaste"] = true
            event("\u{1b}", key: 53)
            event("\u{3}", key: 8, modifiers: .control)
            window.setContentSize(NSSize(width: 990, height: 640))
            began = ProcessInfo.processInfo.systemUptime
            phase = 3
        case 3:
            guard ProcessInfo.processInfo.systemUptime - began > 0.4 else { return }
            checks["vimResizeContentRetained"] = text.contains("VIM-PASTE 中文 é 😀")
            capture()
            session.terminal.send(txt: ":wq\r")
            phase = 4
        case 4:
            guard session.result != nil else { return }
            let saved = (try? String(contentsOf: directory.appendingPathComponent("local-vim.txt"), encoding: .utf8)) ?? ""
            checks["vimSavedExactUnicode"] = saved.contains("VIM-PASTE 中文 é 😀")
            checks["vimExitZero"] = session.result?.exitCode == 0
            checks["reaped"] = kill(session.childPID, 0) == -1 && errno == ESRCH
            phase = 6
            finish()
        default: break
        }
    }
    private func capture() {
        if ProcessInfo.processInfo.environment["P2_WINDOWSERVER_CAPTURE"] == "1", let path = ProcessInfo.processInfo.environment["P2_EVIDENCE_DIR"] {
            let capture = Process()
            capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            capture.arguments = ["-x", "-o", "-l", String(window.windowNumber), URL(fileURLWithPath: path).appendingPathComponent("windowserver.png").path]
            do {
                try capture.run(); capture.waitUntilExit()
                checks["windowServerCapture"] = capture.terminationStatus == 0
            } catch { checks["windowServerCapture"] = false }
        }
        if let path = ProcessInfo.processInfo.environment["P2_EVIDENCE_DIR"],
           let terminalBitmap = session.terminal.bitmapImageRepForCachingDisplay(in: session.terminal.bounds) {
            session.terminal.cacheDisplay(in: session.terminal.bounds, to: terminalBitmap)
            if let png = terminalBitmap.representation(using: .png, properties: [:]) {
                try? png.write(to: URL(fileURLWithPath: path).appendingPathComponent("terminal-only.png"))
                checks["terminalDrawCapture"] = true
            }
        }
        guard let path = ProcessInfo.processInfo.environment["P2_EVIDENCE_DIR"], let view = window.contentView,
              let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        if let png = bitmap.representation(using: .png, properties: [:]) {
            try? png.write(to: URL(fileURLWithPath: path).appendingPathComponent("native-window.png"))
            checks["windowCapture"] = true
        }
    }
    private func finish() {
        timer?.invalidate(); timer = nil
        var data: [String: Any] = ["candidate": ProbeSettings.candidate, "checks": checks, "scenario": vim ? "vim" : "fixture",
                                   "terminalFrame": NSStringFromRect(session.terminal.frame),
                                   "terminalBounds": NSStringFromRect(session.terminal.bounds),
                                   "visibleRect": NSStringFromRect(session.terminal.visibleRect),
                                   "renderedFrames": session.terminal.renderedFrames ?? -1,
                                   "windowNumber": window.windowNumber, "pid": getpid(), "childPID": session.childPID,
                                   "rows": session.terminal.retainedRowCount, "bytesReceived": session.bytesReceived,
                                   "seconds": ProcessInfo.processInfo.systemUptime - (deadline - 30)]
        if checks["deadline"] == false { data["fixtureTail"] = String(session.terminal.text.suffix(4096)) }
        if let json = try? JSONSerialization.data(withJSONObject: data, options: [.prettyPrinted, .sortedKeys]) {
            FileHandle.standardOutput.write(json); FileHandle.standardOutput.write(Data([10]))
            if let path = ProcessInfo.processInfo.environment["P2_EVIDENCE_DIR"] {
                try? json.write(to: URL(fileURLWithPath: path).appendingPathComponent("gui-smoke.json"))
            }
        }
        completion(checks.values.allSatisfy { $0 } && phase == 6 ? 0 : 1)
    }
}
