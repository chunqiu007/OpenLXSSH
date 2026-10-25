import AppKit
import Darwin
import SwiftTerm

public enum ProbeSettings {
    public static let defaultHistory = 10_000
    public static let maximumHistory = 50_000
    public static let maximumInputBytes = 256 * 1024
    public static let unicodeSample = "中文 / UTF-8 / 😀 👩🏽‍💻 / e\u{301} / 组合字符"
    public static func history(_ value: Int) -> Int { min(max(value, 0), maximumHistory) }

    public static var options: TerminalOptions {
        #if P2_PREVIEW_API
        TerminalOptions(cols: 80, rows: 24, scrollback: defaultHistory,
                        enableSixelReported: false,
                        kittyGraphics: .init(storageLimitBytesPerScreen: 0, localMediaPolicy: []))
        #else
        TerminalOptions(cols: 80, rows: 24, scrollback: defaultHistory,
                        enableSixelReported: false, kittyImageCacheLimitBytes: 0)
        #endif
    }

    public static var candidate: String {
        #if P2_PREVIEW_API
        return "1.99.1-preview"
        #else
        return "1.20.0"
        #endif
    }
}

/// Only value reads cross this compatibility boundary; no upstream parser internals.
@MainActor
public final class ProbeTerminalView: TerminalView {
    public var columns: Int {
        #if P2_PREVIEW_API
        return terminalDimensions.cols
        #else
        return getTerminal().cols
        #endif
    }
    public var rows: Int {
        #if P2_PREVIEW_API
        return terminalDimensions.rows
        #else
        return getTerminal().rows
        #endif
    }
    public var text: String {
        #if P2_PREVIEW_API
        return String(decoding: getBufferAsData(), as: UTF8.self)
        #else
        // Stable getBufferAsData omits its Character provider and includes
        // wide-cell NULs. Use its public line+character APIs, exactly as its
        // search/selection implementation does; never alter received bytes.
        let terminal = getTerminal()
        let start = terminal.buffer.totalLinesTrimmed
        var lines = [String]()
        for index in 0..<(ProbeSettings.maximumHistory + rows) {
            guard let line = terminal.getScrollInvariantLine(row: start + index) else { break }
            lines.append(line.translateToString(trimRight: true, skipNullCellsFollowingWide: true,
                                                characterProvider: terminal.getCharacter(for:)))
        }
        return lines.joined(separator: "\n")
        #endif
    }
    public var retainedRowCount: Int {
        #if P2_PREVIEW_API
        return terminalContentSnapshot(region: .history(maximumScrollbackRows: ProbeSettings.maximumHistory))?.rows.count ?? -1
        #else
        return getTerminal().getBufferAsData().filter { $0 == 10 }.count
        #endif
    }
    public var renderedFrames: Int? {
        #if P2_PREVIEW_API
        return diagnostics.frames
        #else
        return nil
        #endif
    }
    public var bracketedPaste: Bool {
        #if P2_PREVIEW_API
        return terminalStateSnapshot().bracketedPasteMode
        #else
        return getTerminal().bracketedPasteMode
        #endif
    }

    public init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 900, height: 520),
                   font: .monospacedSystemFont(ofSize: 14, weight: .regular), options: ProbeSettings.options)
        setAccessibilityIdentifier("OpenLXSSH.localTerminal")
        setAccessibilityLabel("Local fixture terminal — no SSH connection")
    }
    public required init?(coder: NSCoder) { fatalError("Use init()") }

    public func applyColors(for appearance: NSAppearance) {
        // SwiftTerm converts NSColor to RGB immediately. Resolve dynamic
        // system colors in this window's appearance, not NSAppearance.current
        // (which can still be light during a programmatic dark-mode change).
        appearance.performAsCurrentDrawingAppearance {
            nativeForegroundColor = NSColor.textColor.usingColorSpace(.deviceRGB) ?? .white
            nativeBackgroundColor = NSColor.textBackgroundColor.usingColorSpace(.deviceRGB) ?? .black
        }
    }
    public override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        applyColors(for: effectiveAppearance)
    }
    public func releaseUI() {
        #if P2_PREVIEW_API
        precondition(updateUiClosed(), "CoreGraphics probe has no active Metal work")
        #endif
    }

    /// App-provided paste uses the same upstream paste path as Cmd+V. The
    /// stable API only exposes that path through a pasteboard. Preserve it.
    public func pasteTextFromApp(_ text: String) {
        #if P2_PREVIEW_API
        pasteText(text)
        #else
        let board = NSPasteboard.general
        let saved: [[NSPasteboard.PasteboardType: Data]] = (board.pasteboardItems ?? []).map { item in
            Dictionary(uniqueKeysWithValues: item.types.compactMap { type in item.data(forType: type).map { (type, $0) } })
        }
        board.clearContents()
        board.setString(text, forType: .string)
        paste(self)
        board.clearContents()
        let restored = saved.map { values -> NSPasteboardItem in
            let item = NSPasteboardItem()
            for (type, data) in values { item.setData(data, forType: type) }
            return item
        }
        board.writeObjects(restored)
        #endif
    }
}
