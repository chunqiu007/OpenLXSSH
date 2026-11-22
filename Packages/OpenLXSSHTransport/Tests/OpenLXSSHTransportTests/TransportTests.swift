import AppKit
import Foundation
import OpenLXSSHTrust
@testable import OpenLXSSHTransport
import SwiftTerm
import XCTest

@MainActor private final class DesktopInputRecorder: TerminalViewDelegate {
    var data = Data()
    func send(source: TerminalView, data: ArraySlice<UInt8>) { self.data.append(contentsOf: data) }
    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {}
    func setTerminalTitle(source: TerminalView, title: String) {}
    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    func scrolled(source: TerminalView, position: Double) {}
    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {}
    func bell(source: TerminalView) {}
}

@MainActor
final class TransportTests: XCTestCase {
    override func setUp() async throws {
        _ = NSApplication.shared
    }

    private func sampleConnection(port: Int = 22) throws -> SSHConnection {
        let host = HostIdentity(address: try HostAddress("server.example"), port: try SSHPort(port))
        return SSHConnection(host: host, user: try SSHUser("fixture"))
    }

    func testSessionConfigurationValidationBoundaries() throws {
        let connection = try sampleConnection()
        for interval in [0, 15, 3600] {
            let configuration = try SSHSessionConfiguration(connection: connection, serverAliveInterval: interval)
            XCTAssertEqual(configuration.serverAliveInterval, interval)
            XCTAssertEqual(configuration.connectTimeout, 10)
            XCTAssertEqual(configuration.serverAliveCountMax, 3)
        }
        for interval in [-1, 3601] {
            XCTAssertThrowsError(try SSHSessionConfiguration(connection: connection, serverAliveInterval: interval)) {
                XCTAssertEqual($0 as? TransportError, .invalidConfiguration)
            }
        }
        for timeout in [0, 61] {
            XCTAssertThrowsError(try SSHSessionConfiguration(connection: connection, connectTimeout: timeout)) {
                XCTAssertEqual($0 as? TransportError, .invalidConfiguration)
            }
        }
        for timeout in [1, 60] {
            XCTAssertNoThrow(try SSHSessionConfiguration(connection: connection, connectTimeout: timeout))
        }
        for count in [0, 11] {
            XCTAssertThrowsError(try SSHSessionConfiguration(connection: connection, serverAliveCountMax: count)) {
                XCTAssertEqual($0 as? TransportError, .invalidConfiguration)
            }
        }
        for count in [1, 10] {
            XCTAssertNoThrow(try SSHSessionConfiguration(connection: connection, serverAliveCountMax: count))
        }
        let token = SessionToken(sessionID: UUID(), generation: 7)
        XCTAssertEqual(token.generation, 7)
        XCTAssertEqual(TerminalSettings.history(-10), 0)
        XCTAssertEqual(TerminalSettings.history(TerminalSettings.maximumHistory + 100), TerminalSettings.maximumHistory)
    }

    func testDesktopCursorPreferenceUsesPublicRendererAPIWithoutSendingInput() throws {
        let terminal = NativeTerminalView(), recorder = DesktopInputRecorder()
        terminal.terminalDelegate = recorder
        defer { terminal.terminalDelegate = nil; terminal.releaseResources() }
        let cases: [(DesktopCursorShape, Bool, String)] = [
            (.block, true, "blinkBlock"), (.block, false, "steadyBlock"),
            (.underline, true, "blinkUnderline"), (.underline, false, "steadyUnderline"),
            (.bar, true, "blinkBar"), (.bar, false, "steadyBar")
        ]
        for (shape, blinking, expected) in cases {
            terminal.setDesktopCursor(shape: shape, blinking: blinking)
            XCTAssertEqual(terminal.terminalStateSnapshot().cursorStyle.tagName, expected)
            XCTAssertTrue(recorder.data.isEmpty)
        }
        XCTAssertTrue(terminal.pasteUserText("line one\n中文\n"))
        XCTAssertEqual(recorder.data, Data("line one\n中文\n".utf8))
    }

    func testFontBoundsMatchCoreAndRejectInvalidWithoutFallback() throws {
        let view = NativeTerminalView()
        defer { view.releaseResources() }
        for size: CGFloat in [6, 72] {
            try view.setFont(name: "Menlo", size: size)
            XCTAssertEqual(view.font.pointSize, size)
            XCTAssertEqual(view.font.fontName, "Menlo-Regular")
        }
        let selected = view.font
        for size: CGFloat in [5.9, 72.1, .infinity] {
            XCTAssertThrowsError(try view.setFont(name: "Menlo", size: size)) { XCTAssertEqual($0 as? TransportError, .invalidConfiguration) }
            XCTAssertEqual(view.font, selected)
        }
        XCTAssertThrowsError(try view.setFont(name: "OpenLXSSH-Nonexistent-Font-\(UUID().uuidString)", size: 14)) {
            XCTAssertEqual($0 as? TransportError, .invalidConfiguration)
        }
        XCTAssertEqual(view.font, selected)
    }

    func testCustomColorsAndCursorSurviveEffectiveAppearanceChanges() async throws {
        let view = NativeTerminalView()
        defer { view.releaseResources() }
        let dark = try XCTUnwrap(NSAppearance(named: .darkAqua)), light = try XCTUnwrap(NSAppearance(named: .aqua))
        let foreground = NSColor(srgbRed: 0.21, green: 0.46, blue: 0.73, alpha: 1)
        let background = NSColor(srgbRed: 0.08, green: 0.12, blue: 0.17, alpha: 1)
        let cursor = NSColor(srgbRed: 0.91, green: 0.32, blue: 0.15, alpha: 1)
        view.setColors(foreground: foreground, background: background, cursor: cursor)
        guard case .custom = view.explicitColorMode else { return XCTFail("custom mode not retained") }
        for appearance in [dark, light, dark] {
            view.appearance = appearance
            view.viewDidChangeEffectiveAppearance()
            try? await Task.sleep(nanoseconds: 10_000_000)
            try assertRGB(view.nativeForegroundColor, equals: foreground)
            try assertRGB(view.nativeBackgroundColor, equals: background)
            try assertRGB(view.cursorColor, equals: cursor)
        }
        let updatedCursor = NSColor(srgbRed: 0.62, green: 0.24, blue: 0.81, alpha: 1)
        view.cursorColor = updatedCursor
        view.appearance = light; view.viewDidChangeEffectiveAppearance()
        try assertRGB(view.cursorColor, equals: updatedCursor)
        try assertRGB(view.nativeForegroundColor, equals: foreground)
        try assertRGB(view.nativeBackgroundColor, equals: background)
    }

    func testSystemColorsStayDesktopDarkAfterLeavingCustomMode() async throws {
        let view = NativeTerminalView()
        defer { view.releaseResources() }
        let dark = try XCTUnwrap(NSAppearance(named: .darkAqua)), light = try XCTUnwrap(NSAppearance(named: .aqua))
        view.setColors(foreground: .red, background: .green, cursor: .blue)
        view.appearance = light; view.setColorMode(.system)
        guard case .system = view.explicitColorMode else { return XCTFail("default mode not restored") }
        for appearance in [dark, light, dark] {
            view.appearance = appearance
            view.viewDidChangeEffectiveAppearance()
            try? await Task.sleep(nanoseconds: 10_000_000)
            try assertRGB(view.nativeForegroundColor, equals: NativeTerminalView.desktopForeground)
            try assertRGB(view.nativeBackgroundColor, equals: NativeTerminalView.desktopBackground)
            try assertRGB(view.cursorColor, equals: NativeTerminalView.desktopForeground)
        }
    }

    func testNativeRendererPreservesANSIAttributesUnicodeAndResetWithoutKeywordColoring() throws {
        let view = NativeTerminalView(), baseline = NativeTerminalView()
        defer { view.releaseResources(); baseline.releaseResources() }
        baseline.feed(text: "D")
        let baselineAttribute = try XCTUnwrap(baseline.terminalContentSnapshot(region: .viewport)?.rows.first?.cells.first?.attribute)
        view.feed(text: "error stderr\r\n\u{1b}[31mR\u{1b}[38;5;196mP\u{1b}[38;2;1;2;3mT\u{1b}[1mB\u{1b}[7mI\u{1b}[0mD\r\n中文 🙂 e\u{301}\r\n")
        let snapshot = try XCTUnwrap(view.terminalContentSnapshot(region: .history(maximumScrollbackRows: 100)))
        let plain = try XCTUnwrap(snapshot.rows.first { $0.text.contains("error stderr") })
        XCTAssertTrue(plain.cells.prefix(12).allSatisfy { $0.attribute.fg == .defaultColor })
        let styled = try XCTUnwrap(snapshot.rows.first { $0.text.hasPrefix("RPTBID") })
        XCTAssertEqual(styled.cells[0].attribute.fg, .ansi256(code: 1))
        XCTAssertEqual(styled.cells[1].attribute.fg, .ansi256(code: 196))
        XCTAssertEqual(styled.cells[2].attribute.fg, .trueColor(red: 1, green: 2, blue: 3))
        XCTAssertTrue(styled.cells[3].attribute.style.contains(.bold))
        XCTAssertTrue(styled.cells[4].attribute.style.contains(.inverse))
        XCTAssertEqual(styled.cells[5].attribute, baselineAttribute)
        XCTAssertEqual(baselineAttribute.fg, .defaultColor)
        XCTAssertEqual(baselineAttribute.bg, .defaultColor)
        XCTAssertEqual(baselineAttribute.style, .none)
        XCTAssertTrue(snapshot.rows.contains { $0.text.contains("中文 🙂 e\u{301}") })
        view.feed(text: "\u{1b}[?1049hALT\u{1b}[?1049l")
        XCTAssertFalse(try XCTUnwrap(view.terminalInputStateSnapshot()).isAlternateBuffer)
        XCTAssertTrue(view.text.contains("error stderr"))
    }

    func testExactBoundedPasteCompositionAndDisconnectedInputUseNativeRenderer() throws {
        let view = NativeTerminalView(), input = DesktopInputRecorder()
        defer { view.terminalDelegate = nil; view.releaseResources() }
        view.terminalDelegate = input
        let text = "printf '中文🙂 e\u{301}'\nsecond\r\n\t\u{03}"
        XCTAssertTrue(view.pasteUserText(text))
        XCTAssertEqual(input.data, Data(text.utf8))
        input.data = Data(); view.feed(text: "\u{1b}[?2004h")
        XCTAssertTrue(view.pasteUserText(text))
        XCTAssertEqual(input.data, Data("\u{1b}[200~".utf8) + Data(text.utf8) + Data("\u{1b}[201~".utf8))
        input.data = Data()
        XCTAssertFalse(view.pasteUserText(String(repeating: "x", count: TerminalSettings.maximumInputBytes)))
        XCTAssertTrue(input.data.isEmpty)
        view.feed(text: "\u{1b}[?2004l")
        XCTAssertTrue(view.pasteUserText(String(repeating: "x", count: TerminalSettings.maximumInputBytes)))
        XCTAssertEqual(input.data.count, TerminalSettings.maximumInputBytes)
        input.data = Data()
        XCTAssertFalse(view.pasteUserText(String(repeating: "x", count: TerminalSettings.maximumInputBytes + 1)))
        XCTAssertTrue(input.data.isEmpty)
        view.setMarkedText("中", selectedRange: NSRange(location: 1, length: 0), replacementRange: NSRange(location: NSNotFound, length: 0))
        XCTAssertTrue(view.hasMarkedText()); XCTAssertTrue(input.data.isEmpty)
        view.insertText("中文🙂 e\u{301}", replacementRange: NSRange(location: NSNotFound, length: 0))
        XCTAssertEqual(input.data, Data("中文🙂 e\u{301}".utf8))
        view.unmarkText(); input.data = Data(); view.inputEnabled = false
        XCTAssertFalse(view.pasteUserText("blocked"))
        view.insertText("blocked", replacementRange: NSRange(location: NSNotFound, length: 0))
        XCTAssertTrue(input.data.isEmpty)
    }

    func testSearchCountsClearHistoryAndScrolledOutputDoNotSendShellInput() throws {
        let view = NativeTerminalView(), input = DesktopInputRecorder()
        defer { view.terminalDelegate = nil; view.releaseResources() }
        view.terminalDelegate = input; view.setHistoryLimit(100)
        for index in 0..<80 { view.feed(text: "history-\(index) marker\r\n") }
        XCTAssertTrue(view.search("marker"))
        var summary = view.searchMatchSummary("marker", limit: 1000)
        XCTAssertEqual(summary.total, 80); XCTAssertGreaterThan(summary.index, 0)
        XCTAssertTrue(view.search("marker", backwards: true))
        summary = view.searchMatchSummary("marker", limit: 1000)
        XCTAssertEqual(summary.total, 80)
        view.scrollTo(row: 2)
        let viewport = view.terminalStateSnapshot().viewportRow
        view.feed(text: "new output\r\n")
        XCTAssertEqual(view.terminalStateSnapshot().viewportRow, viewport)
        view.scrollToLiveBottom()
        XCTAssertGreaterThan(view.terminalStateSnapshot().viewportRow, viewport)
        let live = try XCTUnwrap(view.terminalContentSnapshot(region: .viewport)).rows.map(\.text)
        view.clearLocalHistory()
        XCTAssertEqual(try XCTUnwrap(view.terminalContentSnapshot(region: .viewport)).rows.map(\.text), live)
        XCTAssertFalse(view.search("history-0 marker"))
        XCTAssertTrue(input.data.isEmpty)
    }

    private func assertRGB(_ actual: NSColor, equals expected: NSColor, file: StaticString = #filePath, line: UInt = #line) throws {
        let actual = try XCTUnwrap(actual.usingColorSpace(.deviceRGB), file: file, line: line)
        let expected = try XCTUnwrap(expected.usingColorSpace(.deviceRGB), file: file, line: line)
        XCTAssertEqual(actual.redComponent, expected.redComponent, accuracy: 0.001, file: file, line: line)
        XCTAssertEqual(actual.greenComponent, expected.greenComponent, accuracy: 0.001, file: file, line: line)
        XCTAssertEqual(actual.blueComponent, expected.blueComponent, accuracy: 0.001, file: file, line: line)
    }
}
