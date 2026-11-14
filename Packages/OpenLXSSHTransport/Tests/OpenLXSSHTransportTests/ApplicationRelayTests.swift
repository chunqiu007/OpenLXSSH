import AppKit
import Foundation
import SwiftTerm
import XCTest
@testable import OpenLXSSHTransport

/// Native view/application relay only. No windows, clipboard, subprocess, SSH,
/// network, Keychain or App driver are exercised by this offline consumer gate.
@MainActor final class ApplicationRelayTests: XCTestCase {
    func testRelayHasSingleDelegateSynchronousExactPasteAndResizeDelivery() throws {
        let view = NativeTerminalView()
        defer { view.releaseResources() }
        var received = Data(), sizes: [(Int, Int)] = [], returnedFromPaste = false
        try view.installApplicationRelay(input: { bytes in
            XCTAssertFalse(returnedFromPaste, "Admission callback must be synchronous, before a caller creates work")
            received.append(contentsOf: bytes)
        }, resize: { sizes.append(($0, $1)) })
        let relay = try XCTUnwrap(view.terminalDelegate)
        XCTAssertThrowsError(try view.installApplicationRelay(input: { _ in XCTFail("Second relay must not receive input") }, resize: { _, _ in })) {
            XCTAssertEqual($0 as? TransportError, .busy)
        }
        XCTAssertTrue(view.terminalDelegate === relay)
        let text = "中文🙂 e\u{301}\n\r\t\u{03}"
        XCTAssertTrue(view.pasteUserText(text)); returnedFromPaste = true
        XCTAssertEqual(received, Data(text.utf8))
        // The mature renderer delegates dimensions; no second terminal delegate is added.
        relay.sizeChanged(source: view, newCols: 137, newRows: 43)
        XCTAssertEqual(sizes.count, 1); XCTAssertEqual(sizes.first?.0, 137); XCTAssertEqual(sizes.first?.1, 43)
        view.removeApplicationRelay(); XCTAssertNil(view.terminalDelegate)
    }
    func testExistingDelegateIsNeverReplacedAndRemovingRelayPreservesForeignOwner() throws {
        let view = NativeTerminalView(), existing = RelayExistingOwner()
        defer { view.terminalDelegate = nil; view.releaseResources() }
        view.terminalDelegate = existing
        XCTAssertThrowsError(try view.installApplicationRelay(input: { _ in }, resize: { _, _ in })) {
            XCTAssertEqual($0 as? TransportError, .busy)
        }
        view.removeApplicationRelay(); XCTAssertTrue(view.terminalDelegate === existing)
        view.terminalDelegate = nil
        try view.installApplicationRelay(input: { _ in }, resize: { _, _ in })
        view.terminalDelegate = existing
        view.removeApplicationRelay(); XCTAssertTrue(view.terminalDelegate === existing)
    }
    func testRelayPasteRetainsBracketedBytesAndBoundsAndDisconnectedInput() throws {
        let view = NativeTerminalView()
        defer { view.releaseResources() }
        var received = Data()
        try view.installApplicationRelay(input: { received.append(contentsOf: $0) }, resize: { _, _ in })
        try view.feedApplicationOutput(Data("\u{1b}[?2004h".utf8))
        let text = "one\ntwo\r\n中文"
        XCTAssertTrue(view.pasteUserText(text))
        XCTAssertEqual(received, Data("\u{1b}[200~".utf8) + Data(text.utf8) + Data("\u{1b}[201~".utf8))
        received = Data()
        XCTAssertFalse(view.pasteUserText(String(repeating: "x", count: TerminalSettings.maximumInputBytes)))
        XCTAssertTrue(received.isEmpty)
        try view.feedApplicationOutput(Data("\u{1b}[?2004l".utf8))
        XCTAssertTrue(view.pasteUserText(String(repeating: "x", count: TerminalSettings.maximumInputBytes)))
        XCTAssertEqual(received.count, TerminalSettings.maximumInputBytes)
        received = Data(); view.inputEnabled = false
        XCTAssertFalse(view.pasteUserText("do not deliver"))
        view.insertText("do not deliver", replacementRange: NSRange(location: NSNotFound, length: 0))
        XCTAssertTrue(received.isEmpty)
    }
    func testBoundedRawOutputRetainsANSIAndHistoryWithoutInjectingInput() throws {
        let view = NativeTerminalView()
        defer { view.releaseResources() }
        var sent = Data()
        try view.installApplicationRelay(input: { sent.append(contentsOf: $0) }, resize: { _, _ in })
        try view.feedApplicationOutput(Data("history 中文\r\n\u{1b}[31mR\u{1b}[0m\r\n".utf8))
        XCTAssertTrue(view.text.contains("history 中文"))
        let snapshot = try XCTUnwrap(view.terminalContentSnapshot(region: .viewport))
        let styled = try XCTUnwrap(snapshot.rows.first { $0.text.hasPrefix("R") })
        XCTAssertEqual(styled.cells.first?.attribute.fg, .ansi256(code: 1))
        XCTAssertTrue(sent.isEmpty)
        let before = view.text
        XCTAssertThrowsError(try view.feedApplicationOutput(Data(repeating: 65, count: 64 * 1024 + 1))) {
            XCTAssertEqual($0 as? TransportError, .inputFull)
        }
        XCTAssertEqual(view.text, before)
        try view.feedApplicationOutput(Data(repeating: 0, count: 64 * 1024))
        XCTAssertTrue(sent.isEmpty)
    }
    func testReleaseRemovesRelayAndItsCapturedOwnerWithoutClosingOnHide() throws {
        let view = NativeTerminalView()
        weak var owner: RelayCapture?
        do {
            let value = RelayCapture(); owner = value
            try view.installApplicationRelay(input: { [value] _ in value.received += 1 }, resize: { _, _ in })
        }
        XCTAssertNotNil(owner)
        view.setVisible(false); XCTAssertNotNil(view.terminalDelegate); XCTAssertNotNil(owner)
        view.setVisible(true)
        view.releaseResources()
        XCTAssertNil(view.terminalDelegate); XCTAssertNil(owner)
    }
}

@MainActor private final class RelayCapture { var received = 0 }
@MainActor private final class RelayExistingOwner: TerminalViewDelegate {
    func send(source: TerminalView, data: ArraySlice<UInt8>) {}
    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {}
    func setTerminalTitle(source: TerminalView, title: String) {}
    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    func scrolled(source: TerminalView, position: Double) {}
    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    func clipboardRead(source: TerminalView) -> Data? { nil }
    func clipboardCopy(source: TerminalView, content: Data) {}
    func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {}
}
