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

public enum DesktopCursorShape: String, CaseIterable, Sendable { case block, underline, bar }

public enum TerminalColorMode {
    case system
    case custom(foreground: NSColor, background: NSColor, cursor: NSColor)
}

public enum TerminalDesktopAction: String, CaseIterable {
    case copy, paste, selectAll, search, clearHistory, scrollToBottom, increaseFont, decreaseFont, resetFont, connectionInfo, disconnect, reconnect
    public var title: String {
        switch self {
        case .copy: "复制"
        case .paste: "粘贴"
        case .selectAll: "全选"
        case .search: "查找…"
        case .clearHistory: "清除滚动历史（保留当前屏幕）"
        case .scrollToBottom: "回到实时底部"
        case .increaseFont: "放大字号"
        case .decreaseFont: "缩小字号"
        case .resetFont: "还原设置字号"
        case .connectionInfo: "连接信息"
        case .disconnect: "断开"
        case .reconnect: "手动重连"
        }
    }
}

/// Retain one view per tab; hiding/unhiding must not create a new session.
/// No output scanning, OSC clipboard, URL opening or local image-file access.
@MainActor
public final class NativeTerminalView: TerminalView {
    public private(set) var explicitColorMode: TerminalColorMode = .system
    public static let desktopBackground = NSColor(srgbRed: 16.0 / 255, green: 16.0 / 255, blue: 16.0 / 255, alpha: 1)
    public static let desktopForeground = NSColor(srgbRed: 214.0 / 255, green: 214.0 / 255, blue: 204.0 / 255, alpha: 1)
    public var inputEnabled = true { didSet { updateInputEventMonitor() } }
    private var inputEventMonitor: Any?
    public var onDesktopAction: ((TerminalDesktopAction) -> Void)?
    public var canPerformDesktopAction: ((TerminalDesktopAction) -> Bool)?
    private var applicationRelay: ApplicationTerminalRelay?
    /// Alternative to a transport delegate, never a second delegate/reader. The input
    /// callback runs synchronously, so the owner can admit bytes before copying/Task creation.
    public func installApplicationRelay(input: @escaping @MainActor (ArraySlice<UInt8>) -> Void,
                                        resize: @escaping @MainActor (Int, Int) -> Void) throws {
        guard terminalDelegate == nil, applicationRelay == nil else { throw TransportError.busy }
        let relay = ApplicationTerminalRelay(input: input, resize: resize)
        applicationRelay = relay; terminalDelegate = relay
    }
    public func removeApplicationRelay() {
        if let applicationRelay, terminalDelegate === applicationRelay { terminalDelegate = nil }
        applicationRelay = nil
    }
    /// Bounded output from the sole application pull consumer; no text decoding/rewrite.
    public func feedApplicationOutput(_ bytes: Data) throws {
        guard bytes.count <= 64 * 1024 else { throw TransportError.inputFull }
        feed(byteArray: Array(bytes)[...])
    }
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
    /// Public SwiftTerm 1.99.1 API, local presentation only. Remote applications may
    /// subsequently request their own cursor style through normal terminal sequences.
    public func setDesktopCursor(shape: DesktopCursorShape, blinking: Bool) {
        let style: CursorStyle
        switch (shape, blinking) {
        case (.block, true): style = .blinkBlock
        case (.block, false): style = .steadyBlock
        case (.underline, true): style = .blinkUnderline
        case (.underline, false): style = .steadyUnderline
        case (.bar, true): style = .blinkBar
        case (.bar, false): style = .steadyBar
        }
        setCursorStyle(style)
    }
    public func setVisible(_ visible: Bool) { isHidden = !visible }
    /// Exact UTF-8 user paste. The fixed upstream pasteText normalizes LF and
    /// control bytes, so use its public bounded transport input path instead.
    /// No remote clipboard read, implicit newline, shell command or confirmation.
    public func pasteFromApplication(_ text: String) {
        if !pasteUserText(text) { NSSound.beep() }
    }
    @discardableResult public func pasteUserText(_ text: String) -> Bool {
        guard inputEnabled, text.utf8.count <= TerminalSettings.maximumInputBytes else { return false }
        var bytes = Array(text.utf8)
        if bracketedPaste { bytes = Array("\u{1b}[200~".utf8) + bytes + Array("\u{1b}[201~".utf8) }
        guard bytes.count <= TerminalSettings.maximumInputBytes else { return false }
        scrollToLiveBottom()
        send(data: bytes[...])
        return true
    }
    public override func paste(_ sender: Any) {
        guard inputEnabled, let text = NSPasteboard.general.string(forType: .string) else { return }
        pasteFromApplication(text)
    }
    public override func copy(_ sender: Any) {
        guard let text = getSelection(), !text.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
    public override func validateUserInterfaceItem(_ item: NSValidatedUserInterfaceItem) -> Bool {
        if item.action == #selector(copy(_:)) { return getSelection()?.isEmpty == false }
        if item.action == #selector(paste(_:)) { return inputEnabled }
        if item.action == #selector(selectAll(_:)) { return true }
        return super.validateUserInterfaceItem(item)
    }
    public override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        updateInputEventMonitor()
    }
    private func updateInputEventMonitor() {
        if let inputEventMonitor { NSEvent.removeMonitor(inputEventMonitor); self.inputEventMonitor = nil }
        guard !inputEnabled, window != nil else { return }
        // SwiftTerm.keyDown is public but not open. Use AppKit's legal local
        // event filter only for this disconnected first responder; never rewrite
        // events, inspect other fields, or intercept Command menu/edit shortcuts.
        inputEventMonitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .keyUp]) { [weak self] event in
            // Local monitors run synchronously on AppKit's main event thread.
            // Return only a Sendable decision across the isolation assertion;
            // the NSEvent itself never leaves this callback or actor context.
            let suppress = MainActor.assumeIsolated { () -> Bool in
                guard let self, !self.inputEnabled, let window = self.window else { return false }
                return event.window === window && window.firstResponder === self && !event.modifierFlags.contains(.command)
            }
            return suppress ? nil : event
        }
    }
    public override func insertText(_ string: Any, replacementRange: NSRange) {
        guard inputEnabled else { return }
        super.insertText(string, replacementRange: replacementRange)
    }
    public override func setMarkedText(_ string: Any, selectedRange: NSRange, replacementRange: NSRange) {
        guard inputEnabled else { return }
        super.setMarkedText(string, selectedRange: selectedRange, replacementRange: replacementRange)
    }
    public func scrollToLiveBottom() { scrollTo(row: Int.max) }
    public func clearLocalHistory() { clearScrollback(); clearSearch() }
    public override func menu(for event: NSEvent) -> NSMenu? {
        // SwiftTerm's rightMouseDown invokes this only when it is not reporting
        // that button to the remote TUI. Do not intercept remote mouse events.
        let menu = NSMenu(title: "终端")
        for action in TerminalDesktopAction.allCases {
            if [.clearHistory, .increaseFont, .connectionInfo].contains(action) { menu.addItem(.separator()) }
            let item = menu.addItem(withTitle: action.title, action: #selector(desktopMenuAction(_:)), keyEquivalent: "")
            item.target = self; item.representedObject = action.rawValue
            item.identifier = NSUserInterfaceItemIdentifier("terminal." + action.rawValue)
            item.isEnabled = canPerformDesktopAction?(action) ?? false
        }
        menu.autoenablesItems = false
        return menu
    }
    @objc private func desktopMenuAction(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let action = TerminalDesktopAction(rawValue: raw),
              canPerformDesktopAction?(action) == true else { return }
        onDesktopAction?(action)
    }
    public func search(_ text: String, backwards: Bool = false) -> Bool { backwards ? findPrevious(text) : findNext(text) }
    public func setFont(name: String, size: CGFloat) throws {
        guard size.isFinite, (6...72).contains(size), let selected = NSFont(name: name, size: size),
              Self.isMonospaced(selected) else { throw TransportError.invalidConfiguration }
        font = selected
    }
    public static func isMonospaced(_ font: NSFont) -> Bool {
        NSFontManager.shared.traits(of: font).contains(.fixedPitchFontMask) || font.fontDescriptor.symbolicTraits.contains(.monoSpace)
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
    /// The source-compatible `.system` mode now means the desktop default,
    /// deliberately dark in either macOS appearance. Explicit custom stays fixed.
    public func applySystemColors(for appearance: NSAppearance) {
        explicitColorMode = .system
        applySelectedColors(for: appearance)
    }
    private func applySelectedColors(for appearance: NSAppearance) {
        switch explicitColorMode {
        case .system:
            nativeForegroundColor = Self.desktopForeground
            nativeBackgroundColor = Self.desktopBackground
            caretColor = Self.desktopForeground
        case .custom(let foreground, let background, let cursor):
            nativeForegroundColor = foreground; nativeBackgroundColor = background; caretColor = cursor
        }
    }
    public override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance(); applySelectedColors(for: effectiveAppearance)
    }
    /// Call only for permanent tab removal, never for hide/disconnect/reconnect.
    @discardableResult public func releaseResources() -> Bool {
        removeApplicationRelay()
        if let inputEventMonitor { NSEvent.removeMonitor(inputEventMonitor); self.inputEventMonitor = nil }
        return updateUiClosed()
    }
}

@MainActor private final class ApplicationTerminalRelay: TerminalViewDelegate {
    let input: @MainActor (ArraySlice<UInt8>) -> Void
    let resize: @MainActor (Int, Int) -> Void
    init(input: @escaping @MainActor (ArraySlice<UInt8>) -> Void, resize: @escaping @MainActor (Int, Int) -> Void) {
        self.input = input; self.resize = resize
    }
    func send(source: TerminalView, data: ArraySlice<UInt8>) { input(data) }
    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) { resize(newCols, newRows) }
    func setTerminalTitle(source: TerminalView, title: String) {}
    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    func scrolled(source: TerminalView, position: Double) {}
    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    func clipboardRead(source: TerminalView) -> Data? { nil }
    func clipboardCopy(source: TerminalView, content: Data) {}
    func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {}
}
