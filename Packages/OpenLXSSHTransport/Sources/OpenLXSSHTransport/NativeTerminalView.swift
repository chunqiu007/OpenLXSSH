import AppKit
import SwiftTerm

public enum TerminalSettings {
    public static let defaultHistory = 10_000
    public static let maximumHistory = 50_000
    public static let maximumInputBytes = 256 * 1024
    public static func history(_ value: Int) -> Int { min(max(value, 0), maximumHistory) }
    static var options: TerminalOptions {
        TerminalOptions(cols: 80, rows: 24, scrollback: defaultHistory, enableSixelReported: false,
                        kittyGraphics: .init(storageLimitBytesPerScreen: 0, localMediaPolicy: []))
    }
}

public enum TerminalColorMode {
    case system
    case custom(foreground: NSColor, background: NSColor, cursor: NSColor)
}

/// Retain one view per tab; hiding/unhiding must not create a new session.
/// No output scanning, OSC clipboard, URL opening or local image-file access.
@MainActor
public final class NativeTerminalView: TerminalView {
    public private(set) var explicitColorMode: TerminalColorMode = .system
    /// SwiftTerm exposes its native cursor through the public caretColor API.
    /// Assigning a cursor explicitly preserves all three colors as custom.
    public var cursorColor: NSColor {
        get { caretColor }
        set { setColors(foreground: nativeForegroundColor, background: nativeBackgroundColor, cursor: newValue) }
    }
    public var columns: Int { terminalDimensions.cols }
    public var rows: Int { terminalDimensions.rows }
    public var text: String { String(decoding: getBufferAsData(), as: UTF8.self) }
    public var retainedRowCount: Int { terminalContentSnapshot(region: .history(maximumScrollbackRows: TerminalSettings.maximumHistory))?.rows.count ?? 0 }
    public var bracketedPaste: Bool { terminalStateSnapshot().bracketedPasteMode }
    public init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 900, height: 520),
                   font: .monospacedSystemFont(ofSize: 14, weight: .regular), options: TerminalSettings.options)
        setAccessibilityIdentifier("OpenLXSSH.terminal")
        applySystemColors(for: effectiveAppearance)
    }
    public required init?(coder: NSCoder) { fatalError("Use init()") }
    public func setHistoryLimit(_ lines: Int) { changeScrollback(TerminalSettings.history(lines)) }
    public func setVisible(_ visible: Bool) { isHidden = !visible }
    public func pasteFromApplication(_ text: String) { pasteText(text) }
    public func search(_ text: String, backwards: Bool = false) -> Bool { backwards ? findPrevious(text) : findNext(text) }
    public func setFont(name: String, size: CGFloat) throws {
        guard size.isFinite, (6...72).contains(size), let selected = NSFont(name: name, size: size) else { throw TransportError.invalidConfiguration }
        font = selected
    }
    public func setColors(foreground: NSColor, background: NSColor, cursor: NSColor? = nil) {
        setColorMode(.custom(foreground: foreground, background: background, cursor: cursor ?? foreground))
    }
    public func setColorMode(_ mode: TerminalColorMode) {
        switch mode {
        case .system: applySystemColors(for: effectiveAppearance)
        case .custom(let foreground, let background, let cursor):
            // Freeze dynamic NSColors at the user's explicit selection rather
            // than allowing a later system appearance change to reinterpret it.
            effectiveAppearance.performAsCurrentDrawingAppearance {
                explicitColorMode = .custom(foreground: foreground.usingColorSpace(.deviceRGB) ?? foreground,
                                            background: background.usingColorSpace(.deviceRGB) ?? background,
                                            cursor: cursor.usingColorSpace(.deviceRGB) ?? cursor)
            }
            applySelectedColors(for: effectiveAppearance)
        }
    }
    /// Explicitly returns to system mode; ordinary appearance callbacks do not.
    public func applySystemColors(for appearance: NSAppearance) {
        explicitColorMode = .system
        applySelectedColors(for: appearance)
    }
    private func applySelectedColors(for appearance: NSAppearance) {
        switch explicitColorMode {
        case .system:
            appearance.performAsCurrentDrawingAppearance {
                let foreground = NSColor.textColor.usingColorSpace(.deviceRGB) ?? .white
                nativeForegroundColor = foreground
                nativeBackgroundColor = NSColor.textBackgroundColor.usingColorSpace(.deviceRGB) ?? .black
                caretColor = foreground
            }
        case .custom(let foreground, let background, let cursor):
            nativeForegroundColor = foreground; nativeBackgroundColor = background; caretColor = cursor
        }
    }
    public override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance(); applySelectedColors(for: effectiveAppearance)
    }
    /// Call only for permanent tab removal, never for hide/disconnect/reconnect.
    public func releaseResources() { _ = updateUiClosed() }
}
