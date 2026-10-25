import AppKit
import Darwin
import SwiftTerm
import XCTest
@testable import OpenLXSSHTerminalCore

@MainActor
final class TerminalProbeTests: XCTestCase {
    private var directory: URL!
    private var sessions = [ProbeSession]()

    override func setUp() async throws {
        _ = NSApplication.shared
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-P2-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    override func tearDown() async throws {
        for session in sessions where session.isRunning { session.close() }
        for session in sessions { _ = await until { !session.isRunning }; session.terminal.releaseUI() }
        sessions.removeAll()
        try FileManager.default.removeItem(at: directory)
    }
    private var fixture: String {
        // SwiftPM places executable products beside the .xctest bundle.
        Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("openlxssh-terminal-fixture").path
    }
    private func start(_ args: [String] = []) throws -> ProbeSession {
        let session = ProbeSession(); sessions.append(session)
        try session.start(executable: fixture, arguments: args, directory: directory.path)
        return session
    }
    private func until(timeout: TimeInterval = 8, _ predicate: () -> Bool) async -> Bool {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while !predicate() && ProcessInfo.processInfo.systemUptime < deadline {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        return predicate()
    }
    private func close(_ session: ProbeSession) async {
        let pid = session.childPID
        session.close(); session.close()
        let done = await until { session.result != nil }
        XCTAssertTrue(done)
        XCTAssertNil(session.process)
        XCTAssertEqual(session.ownedTimerCount, 0)
        XCTAssertEqual(session.pendingInputBytes, 0)
        XCTAssertEqual(kill(pid, 0), -1)
        XCTAssertEqual(errno, ESRCH)
    }
    private func preservingPasteboard(_ body: () throws -> Void) rethrows {
        let board = NSPasteboard.general
        let saved = (board.pasteboardItems ?? []).map { item in
            Dictionary(uniqueKeysWithValues: item.types.compactMap { type in item.data(forType: type).map { (type, $0) } })
        }
        defer {
            board.clearContents()
            board.writeObjects(saved.map { values -> NSPasteboardItem in
                let item = NSPasteboardItem(); for (type, value) in values { item.setData(value, forType: type) }; return item
            })
        }
        try body()
    }

    func testAppearanceFontAndUIShutdown() {
        let view = ProbeTerminalView()
        view.applyColors(for: NSAppearance(named: .darkAqua)!)
        let darkBackground = view.nativeBackgroundColor.usingColorSpace(.deviceRGB)!
        let darkForeground = view.nativeForegroundColor.usingColorSpace(.deviceRGB)!
        XCTAssertGreaterThan(darkForeground.redComponent, darkBackground.redComponent)
        view.applyColors(for: NSAppearance(named: .aqua)!)
        let lightBackground = view.nativeBackgroundColor.usingColorSpace(.deviceRGB)!
        XCTAssertGreaterThan(lightBackground.redComponent, darkBackground.redComponent)
        view.font = NSFont(name: "Menlo", size: 18)!
        XCTAssertEqual(view.font.pointSize, 18)
        view.releaseUI(); view.releaseUI()
    }

    func testUnicodeSplitAtEveryUTF8ByteAndCombiningSearch() {
        let view = ProbeTerminalView()
        for byte in ProbeSettings.unicodeSample.utf8 { view.feed(byteArray: [byte][...]) }
        XCTAssertTrue(view.text.contains(ProbeSettings.unicodeSample), view.text.debugDescription)
        XCTAssertTrue(view.findNext("中文"))
        XCTAssertEqual(view.getSelection(), "中文")
        XCTAssertTrue(view.findNext("e\u{301}"))
        XCTAssertEqual(view.getSelection(), "e\u{301}")
        XCTAssertFalse(view.findNext("not present"))
    }

    func testHistoryDefaultsCapTrimAndSearch() {
        XCTAssertEqual(ProbeSettings.options.scrollback, 10_000)
        XCTAssertEqual(ProbeSettings.history(Int.max), 50_000)
        XCTAssertEqual(ProbeSettings.history(-1), 0)
        let view = ProbeTerminalView()
        for row in 0..<10_100 { view.feed(text: String(format: "ROW-%05d 中文\r\n", row)) }
        XCTAssertGreaterThanOrEqual(view.retainedRowCount, view.rows)
        XCTAssertLessThanOrEqual(view.retainedRowCount, 10_000 + view.rows)
        XCTAssertFalse(view.findNext("ROW-00000"))
        XCTAssertTrue(view.findNext("ROW-10099"))
        view.changeScrollback(100)
        XCTAssertLessThanOrEqual(view.retainedRowCount, 100 + view.rows)
    }

    func testSearchCopyAndClipboardPolicy() {
        let session = ProbeSession()
        session.terminal.feed(text: "first 中文 é 😀\r\nsecond 中文\r\n")
        XCTAssertTrue(session.terminal.findNext("中文"))
        let first = session.terminal.getSelection()
        XCTAssertEqual(first, "中文")
        XCTAssertTrue(session.terminal.findPrevious("中文"))
        preservingPasteboard {
            session.terminal.copy(self)
            XCTAssertEqual(NSPasteboard.general.string(forType: .string), "中文")
        }
        XCTAssertNil(session.clipboardRead(source: session.terminal))
        session.clipboardCopy(source: session.terminal, content: Data("OSC must not change clipboard".utf8))
    }

    func testBracketedPasteEncodingUsesUpstreamPath() async throws {
        let view = ProbeTerminalView()
        let capture = InputCapture()
        view.terminalDelegate = capture
        let sample = "中文 e\u{301} 😀\nline two"
        view.feed(text: "\u{1b}[?2004h")
        XCTAssertTrue(view.bracketedPaste)
        view.pasteTextFromApp(sample)
        let bracketed = Array(("\u{1b}[200~" + sample + "\u{1b}[201~").utf8)
        let firstPaste = await until { capture.bytes.count >= bracketed.count }
        XCTAssertTrue(firstPaste)
        XCTAssertEqual(capture.bytes, bracketed)
        capture.bytes.removeAll()
        view.feed(text: "\u{1b}[?2004l")
        view.pasteTextFromApp(sample)
        let secondPaste = await until { capture.bytes.count >= sample.utf8.count }
        XCTAssertTrue(secondPaste)
        // The preview API normalizes line endings before non-bracketed paste.
        XCTAssertEqual(String(decoding: capture.bytes, as: UTF8.self).replacingOccurrences(of: "\r", with: "\n"), sample)
    }

    func testLocalPTYControlUnicodePasteExactBytes() async throws {
        let sample = "中文 e\u{301} 😀\nline two"
        let expected = Array(("\u{1b}[200~" + sample + "\u{1b}[201~").utf8)
        let session = try start(["--capture", String(expected.count)])
        let ready = await until { session.terminal.text.contains("CAPTURE-READY") }
        XCTAssertTrue(ready)
        session.terminal.pasteTextFromApp(sample)
        let complete = await until { session.result != nil }
        XCTAssertTrue(complete)
        let hex = expected.map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(session.terminal.text.replacingOccurrences(of: "\n", with: "").contains("CAPTURE " + hex))
        XCTAssertEqual(session.result?.exitCode, 0)
    }

    func testResizeReachesPTY() async throws {
        let session = try start()
        let ready = await until { session.terminal.text.contains("READY") }; XCTAssertTrue(ready)
        session.terminal.resize(cols: 93, rows: 31)
        let resized = await until { session.terminal.text.contains("SIZE 93x31") }; XCTAssertTrue(resized)
        XCTAssertEqual(session.terminal.columns, 93); XCTAssertEqual(session.terminal.rows, 31)
        await close(session)
    }

    func testControlsArrowsAndTabReachLocalFixture() async throws {
        let sequence: [UInt8] = [3, 27, 91, 65, 9]
        let session = try start(["--capture", String(sequence.count)])
        let ready = await until { session.terminal.text.contains("CAPTURE-READY") }; XCTAssertTrue(ready)
        try session.enqueue(sequence[...])
        let done = await until { session.result != nil }; XCTAssertTrue(done)
        XCTAssertTrue(session.terminal.text.contains("CAPTURE 031b5b4109"))
    }

    func testHiddenViewConsumesBurstWithoutLosingTail() async throws {
        let session = try start()
        let ready = await until { session.terminal.text.contains("READY") }; XCTAssertTrue(ready)
        session.terminal.isHidden = true
        try session.enqueue([104][...])
        let done = await until(timeout: 20) { session.terminal.text.contains("HISTORY-END") }; XCTAssertTrue(done)
        XCTAssertLessThanOrEqual(session.terminal.retainedRowCount, 10_000 + session.terminal.rows)
        XCTAssertFalse(session.terminal.text.contains("HISTORY-00000"))
        XCTAssertTrue(session.terminal.findNext("HISTORY-10049"))
        session.terminal.isHidden = false
        await close(session)
    }

    func testBoundedInputRejectsWholeBlock() async throws {
        let session = try start()
        let input = [UInt8](repeating: 65, count: ProbeSettings.maximumInputBytes + 1)
        XCTAssertThrowsError(try session.enqueue(input[...]))
        XCTAssertEqual(session.pendingInputBytes, 0)
        XCTAssertNotNil(session.inputError)
        await close(session)
    }

    func testCloseReapsTERMResistantChildAndIsIdempotent() async throws {
        let session = try start(["--ignore-term"])
        let ready = await until { session.terminal.text.contains("READY") }; XCTAssertTrue(ready)
        await close(session)
        XCTAssertEqual(session.result?.escalated, true)
    }

    func testNaturalExitAndFinalUnicodeTail() async throws {
        let session = try start(["--exit", "7"])
        let done = await until { session.result != nil }; XCTAssertTrue(done)
        XCTAssertEqual(session.result?.exitCode, 7)
        XCTAssertTrue(session.terminal.text.contains("FINAL-TAIL " + ProbeSettings.unicodeSample), session.terminal.text.debugDescription)
        XCTAssertEqual(kill(session.childPID, 0), -1); XCTAssertEqual(errno, ESRCH)
    }

    func testTwentyCreateCloseCyclesReleaseViewsProcessesFDs() async throws {
        // Warm AppKit/SwiftTerm's process-wide caches before counting.
        let warm = try start(); let ready = await until { warm.terminal.text.contains("READY") }; XCTAssertTrue(ready)
        await close(warm); warm.terminal.releaseUI(); sessions.removeAll()
        try? await Task.sleep(nanoseconds: 150_000_000)
        let before = fdCount()
        var pids = [pid_t]()
        var weakViews = [WeakView]()
        for _ in 0..<20 {
            var session: ProbeSession? = try start()
            let ready = await until { session!.terminal.text.contains("READY") }; XCTAssertTrue(ready)
            pids.append(session!.childPID)
            weakViews.append(WeakView(session!.terminal))
            await close(session!)
            session!.terminal.releaseUI()
            sessions.removeAll(); session = nil
        }
        let released = await until { weakViews.allSatisfy { $0.value == nil } }; XCTAssertTrue(released)
        try? await Task.sleep(nanoseconds: 150_000_000)
        let after = fdCount()
        print("RESOURCE-BASELINE candidate=\(ProbeSettings.candidate) cycles=20 fdBefore=\(before) fdAfter=\(after) weakViewsAlive=\(weakViews.filter { $0.value != nil }.count) pids=\(pids)")
        XCTAssertLessThanOrEqual(after, before + 2)
        for pid in pids { XCTAssertEqual(kill(pid, 0), -1); XCTAssertEqual(errno, ESRCH) }
    }

    func testThirtyImmediateExitTailsAreNotDropped() async throws {
        for index in 0..<30 {
            let session = try start(["--exit", "7"])
            let done = await until { session.result != nil }
            XCTAssertTrue(done)
            XCTAssertEqual(session.result?.exitCode, 7)
            XCTAssertTrue(session.terminal.text.contains("FINAL-TAIL " + ProbeSettings.unicodeSample), "lost tail cycle \(index)")
            session.terminal.releaseUI()
            sessions.removeAll()
        }
    }

    func testFastProducerBackpressurePreservesTail() async throws {
        let session = try start(["--stream", "30000"])
        // Deliberately stall the main-queue parser while PTY buffers fill. The
        // producer must block, not trigger unlimited copied output queues.
        usleep(150_000)
        let done = await until(timeout: 20) { session.result != nil }
        XCTAssertTrue(done)
        XCTAssertTrue(session.terminal.text.contains("STREAM-029999"))
        XCTAssertTrue(session.terminal.text.contains("STREAM-END"))
        XCTAssertGreaterThan(session.bytesReceived, 900_000)
        XCTAssertLessThanOrEqual(session.terminal.retainedRowCount, 10_000 + session.terminal.rows)
    }

    func testInvalidExecutableAndNoImplicitRelaunch() async throws {
        let session = ProbeSession()
        XCTAssertThrowsError(try session.start(executable: "/not/a/real/executable", directory: directory.path))
        XCTAssertFalse(session.isRunning)
        let active = try start()
        XCTAssertThrowsError(try active.start(executable: fixture, directory: directory.path))
        await close(active)
        XCTAssertThrowsError(try active.start(executable: fixture, directory: directory.path))
    }

    private func fdCount() -> Int {
        (0..<Int32(getdtablesize())).reduce(0) { $0 + (fcntl($1, F_GETFD) >= 0 ? 1 : 0) }
    }
}

@MainActor
private final class InputCapture: NSObject, @MainActor TerminalViewDelegate {
    var bytes = [UInt8]()
    func send(source: TerminalView, data: ArraySlice<UInt8>) { bytes.append(contentsOf: data) }
    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {}
    func setTerminalTitle(source: TerminalView, title: String) {}
    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    func scrolled(source: TerminalView, position: Double) {}
    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
}
private final class WeakView {
    weak var value: NSView?
    init(_ value: NSView) { self.value = value }
}
