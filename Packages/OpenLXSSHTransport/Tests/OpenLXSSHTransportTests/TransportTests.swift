import AppKit
import Darwin
import Foundation
import OpenLXSSHAskpass
import OpenLXSSHTrust
import COpenLXSSHAskpass
@testable import OpenLXSSHTransport
import SwiftTerm
import XCTest

private let publicEd = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg"
private let changedEd = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C"

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

private struct FixtureScanner: HostKeyScanning {
    let key: HostPublicKey
    let delay: UInt64
    func scan(_ host: HostIdentity) async throws -> [HostKeyCandidate] {
        if delay > 0 { try? await Task.sleep(nanoseconds: delay) }
        return [HostKeyCandidate(host: host, key: key, source: .systemSSHKeyscan)]
    }
}

@MainActor
final class TransportTests: XCTestCase {
    var directory: URL!
    var sessions = [DirectSSHSession]()
    override func setUp() async throws {
        _ = NSApplication.shared
        let package = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let scratch = package.appendingPathComponent(".build/test-runtime")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        directory = scratch.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    override func tearDown() async throws {
        for session in sessions { session.closeTab() }
        for session in sessions { let stopped = await until { session.state == .closed }; XCTAssertTrue(stopped) }
        sessions.removeAll()
        try FileManager.default.removeItem(at: directory)
    }
    private func store() throws -> HostTrustStore { try HostTrustStore(directory: AbsolutePath(directory.appendingPathComponent("trust").path)) }
    private func host(port: Int = 22) throws -> HostIdentity { HostIdentity(address: try HostAddress("server.example"), port: try SSHPort(port)) }
    private func config() throws -> SSHSessionConfiguration { try SSHSessionConfiguration(connection: SSHConnection(host: host(), user: SSHUser("fixture"))) }
    private func session(scanner: (any HostKeyScanning)? = nil) throws -> DirectSSHSession {
        let session = try DirectSSHSession(probeStore: store(), directory: AbsolutePath(directory.path), scanner: scanner ?? FixtureScanner(key: HostPublicKey(openSSHPublicKey: publicEd), delay: 0))
        sessions.append(session); return session
    }
    private var fixture: String { Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("openlxssh-transport-fixture").path }
    private func start(_ args: [String] = []) throws -> DirectSSHSession {
        let s = try session()
        _ = try s.startProbe(DirectSSHInvocation(executable: fixture, arguments: args, environment: ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "TERM": "xterm-256color"]), directory: directory.path)
        return s
    }
    private func until(timeout: Double = 10, _ condition: () -> Bool) async -> Bool {
        let end = ProcessInfo.processInfo.systemUptime + timeout
        while !condition() && ProcessInfo.processInfo.systemUptime < end { try? await Task.sleep(nanoseconds: 5_000_000) }
        return condition()
    }
    func testConfigRealSSHGNoNetworkAndDisabledFeatures() throws {
        let trust = try store()
        let config = try DirectSSHConfiguration(configuration: config(), trustStore: trust, trustedKeys: [HostPublicKey(openSSHPublicKey: publicEd)])
        let workspace = try SessionWorkspace(root: AbsolutePath(directory.path), text: config.text)
        let invocation = workspace.invocation(preview: true)
        XCTAssertEqual(invocation.executable, "/usr/bin/ssh")
        XCTAssertEqual(invocation.arguments.suffix(2), ["--", "openlxssh-direct"])
        let result = try BoundedTool.run(invocation.executable, invocation.arguments, seconds: 3)
        XCTAssertEqual(result.status, 0)
        let text = String(decoding: result.output, as: UTF8.self)
        for expected in ["stricthostkeychecking true", "forwardagent no", "identityagent none", "controlmaster false", "controlpersist no", "permitlocalcommand no", "clearallforwardings yes", "hostkeyalgorithms ssh-ed25519", "connecttimeout 10", "serveraliveinterval 15", "serveralivecountmax 3", "numberofpasswordprompts 1"] {
            XCTAssertTrue(text.contains(expected), expected)
        }
        XCTAssertTrue(text.contains("userknownhostsfile \(trust.knownHostsPath.value)"))
        XCTAssertFalse(config.text.contains("Include")); XCTAssertFalse(text.contains("proxycommand /"))
    }
    func testDesktopCursorPreferenceUsesPublicRendererAPIWithoutSendingInput() throws {
        let terminal = NativeTerminalView(), recorder = DesktopInputRecorder()
        terminal.terminalDelegate = recorder
        defer { terminal.terminalDelegate = nil; terminal.releaseResources() }
        let cases: [(DesktopCursorShape, Bool, String)] = [(.block, true, "blinkBlock"), (.block, false, "steadyBlock"),
            (.underline, true, "blinkUnderline"), (.underline, false, "steadyUnderline"), (.bar, true, "blinkBar"), (.bar, false, "steadyBar")]
        for (shape, blinking, expected) in cases {
            terminal.setDesktopCursor(shape: shape, blinking: blinking)
            XCTAssertEqual(terminal.terminalStateSnapshot().cursorStyle.tagName, expected)
            XCTAssertTrue(recorder.data.isEmpty)
        }
        // The preference changes no paste/input policy or dimensions.
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
    func testKeepaliveIntervalBoundariesMatchRealSSHG() throws {
        let connection = try config().connection, trust = try store()
        let key = try HostPublicKey(openSSHPublicKey: publicEd)
        for interval in [0, 3600] {
            let configuration = try SSHSessionConfiguration(connection: connection, serverAliveInterval: interval)
            let controlled = try DirectSSHConfiguration(configuration: configuration, trustStore: trust, trustedKeys: [key])
            let workspace = try SessionWorkspace(root: AbsolutePath(directory.path), text: controlled.text)
            let invocation = workspace.invocation(preview: true)
            let result = try BoundedTool.run(invocation.executable, invocation.arguments, seconds: 3)
            XCTAssertEqual(result.status, 0)
            let lines = String(decoding: result.output, as: UTF8.self).split(separator: "\n")
            XCTAssertTrue(lines.contains(Substring("serveraliveinterval \(interval)")))
            XCTAssertTrue(lines.contains("connecttimeout 10"))
        }
        for interval in [-1, 3601] {
            XCTAssertThrowsError(try SSHSessionConfiguration(connection: connection, serverAliveInterval: interval))
        }
        for timeout in [0, 61] { XCTAssertThrowsError(try SSHSessionConfiguration(connection: connection, connectTimeout: timeout)) }
        for timeout in [1, 60] { XCTAssertNoThrow(try SSHSessionConfiguration(connection: connection, connectTimeout: timeout)) }
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
        // SGR 0 restores the attributes of normally rendered default text;
        // Attribute.empty is an uninitialized-cell sentinel, not that baseline.
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
    func testKeyscanStrictParsingPortAlgorithmsAndMaliciousInput() throws {
        let h = try host(port: 2222)
        let line = h.knownHostsName + " " + publicEd + "\n"
        let candidates = try SystemHostKeyScanner.parse(Data(("# banner ignored\n" + line + line).utf8), for: h)
        XCTAssertEqual(candidates.count, 1); XCTAssertEqual(candidates[0].source, .systemSSHKeyscan)
        for text in ["evil.example " + publicEd + "\n", "@cert-authority " + line, line.replacingOccurrences(of: " ssh-ed25519", with: "\tssh-ed25519"), line + h.knownHostsName + " " + changedEd + "\n", line.trimmingCharacters(in: .newlines)] {
            XCTAssertThrowsError(try SystemHostKeyScanner.parse(Data(text.utf8), for: h))
        }
        XCTAssertThrowsError(try SystemHostKeyScanner.parse(Data("# only banner\n".utf8), for: h))
        for bad in ["-x", "host\nProxyCommand touch /tmp/x", "host;id", "a b", "user@host", "$(id)"] { XCTAssertThrowsError(try HostAddress(bad)) }
        XCTAssertThrowsError(try SystemHostKeyScanner(timeoutSeconds: 0))
    }
    func testTrustPreflightNeedsExplicitFingerprintAndCancelInvalidates() async throws {
        let s = try session(); let token = try s.connect(config())
        let waiting = await until { s.state == .awaitingTrust }; XCTAssertTrue(waiting)
        let challenge = try XCTUnwrap(s.trustChallenges.first)
        XCTAssertEqual(challenge.token, token)
        let records = try await store().records(); XCTAssertTrue(records.isEmpty)
        s.cancel(); XCTAssertTrue(s.canReconnect)
        do { try await s.acceptTrust(challenge, displayedFingerprint: challenge.decision.fingerprint); XCTFail("stale trust accepted") } catch {}
        let recordsAfter = try await store().records(); XCTAssertTrue(recordsAfter.isEmpty)
    }
    func testUnknownMaskedAndSecretRedactionBoundsReplayAndExpiry() throws {
        XCTAssertEqual(AuthenticationChallengeKind(hint: "password"), .unknownMasked)
        XCTAssertEqual(AuthenticationChallengeKind(hint: nil), .unknownMasked)
        let secret = try SecretBytes(Data("synthetic-only".utf8))
        XCTAssertEqual(String(describing: secret), "<redacted>"); XCTAssertFalse(String(reflecting: AuthenticationResponse.manual(secret)).contains("synthetic-only"))
        for bytes in [Data([0]), Data([10]), Data([13]), Data(repeating: 65, count: 1024)] { XCTAssertThrowsError(try SecretBytes(bytes)) }
        let grant = SessionGrant(generation: 1, nonce: String(repeating: "a", count: 64))
        let request = Request(grant: grant, prompt: "Password: no method proof", hint: nil)
        var auth = AuthenticationState(grant: grant, now: 0)
        try auth.begin(request, now: 0)
        XCTAssertThrowsError(try auth.finish(request.id, generation: 2, now: 0))
        try auth.finish(request.id, generation: 1, now: 1)
        XCTAssertThrowsError(try auth.begin(request, now: 2))
        auth.close(.cancelled); XCTAssertThrowsError(try auth.begin(Request(grant: grant, prompt: "", hint: nil), now: 2))
    }
    func testRealPTYControlsUnicodeBracketedPasteAndEOF() async throws {
        let sample = "中文 e\u{301} 😀\nsecond"
        let expected = Data(("\u{1b}[200~" + sample + "\u{1b}[201~").utf8)
        let s = try start(["--capture", String(expected.count)])
        let ready = await until { s.terminal.text.contains("CAPTURE-READY") }; XCTAssertTrue(ready)
        XCTAssertEqual(s.state, .connectionPending)
        s.terminal.pasteUserText(sample)
        let done = await until { s.canReconnect }; XCTAssertTrue(done); XCTAssertEqual(s.lastExitCode, 0)
        XCTAssertTrue(s.terminal.text.replacingOccurrences(of: "\n", with: "").contains("CAPTURE " + expected.map { String(format: "%02x", $0) }.joined()))
        let keys = try start(["--capture", "5"])
        let keyReady = await until { keys.terminal.text.contains("CAPTURE-READY") }; XCTAssertTrue(keyReady)
        try keys.sendInput(Data([3, 27, 91, 65, 9]))
        let keyDone = await until { keys.canReconnect }; XCTAssertTrue(keyDone)
        XCTAssertTrue(keys.terminal.text.contains("CAPTURE 031b5b4109"))
    }
    func testBoundedInputHiddenHistorySearchThemeResize() async throws {
        let s = try start()
        let ready = await until { s.terminal.text.contains("READY") }; XCTAssertTrue(ready)
        XCTAssertThrowsError(try s.sendInput(Data(repeating: 65, count: TerminalSettings.maximumInputBytes + 1)))
        XCTAssertEqual(s.pendingInputBytes, 0)
        s.terminal.setHistoryLimit(100); s.terminal.setVisible(false)
        try s.sendInput(Data([104]))
        let historyDone = await until(timeout: 20) { s.terminal.text.contains("HISTORY-END") }; XCTAssertTrue(historyDone)
        XCTAssertLessThanOrEqual(s.terminal.retainedRowCount, 100 + s.terminal.rows)
        XCTAssertFalse(s.terminal.search("HISTORY-00000")); XCTAssertTrue(s.terminal.search("HISTORY-10049"))
        s.terminal.setVisible(true); s.terminal.resize(cols: 93, rows: 31)
        let resized = await until { s.terminal.text.contains("SIZE 93x31") }; XCTAssertTrue(resized)
        try s.terminal.setFont(name: "Menlo", size: 18); XCTAssertEqual(s.terminal.font.pointSize, 18)
        XCTAssertThrowsError(try s.terminal.setFont(name: "Menlo", size: .infinity))
        XCTAssertEqual(TerminalSettings.history(Int.max), 50_000)
    }
    func testFastOutputDrainAndNoFalseConnected() async throws {
        let s = try start(["--stream", "30000"])
        usleep(100_000)
        let done = await until(timeout: 20) { s.canReconnect }; XCTAssertTrue(done)
        XCTAssertTrue(s.terminal.text.contains("STREAM-029999")); XCTAssertTrue(s.terminal.text.contains("STREAM-END"))
        XCTAssertEqual(s.state, .disconnected(0)); XCTAssertLessThanOrEqual(s.terminal.retainedRowCount, 10_000 + s.terminal.rows)
        XCTAssertFalse(s.state == .connected)
    }
    func testCancelReapsOnlyOwnedChildMultiSessionAndGenerationRejectsOldOutput() async throws {
        let a = try start(["--ignore-term"]), b = try start()
        let ready = await until { a.terminal.text.contains("READY") && b.terminal.text.contains("READY") }; XCTAssertTrue(ready)
        let old = try XCTUnwrap(a.token), pid = try XCTUnwrap(a.ownedProcessID)
        a.cancel(); a.cancel()
        let done = await until { a.canReconnect }; XCTAssertTrue(done)
        XCTAssertEqual(kill(pid, 0), -1); XCTAssertEqual(errno, ESRCH)
        XCTAssertEqual(b.state, .connectionPending)
        let new = try a.startProbe(DirectSSHInvocation(executable: fixture, arguments: [], environment: ["PATH": "/usr/bin:/bin"]), directory: directory.path)
        XCTAssertEqual(new.generation, old.generation + 1)
        a.deliverProbeOutput(Data("STALE-OUTPUT-MUST-NOT-APPEAR".utf8), token: old)
        XCTAssertFalse(a.terminal.text.contains("STALE-OUTPUT-MUST-NOT-APPEAR"))
        try b.sendInput(Data([117])); let output = await until { b.terminal.text.contains("组合字符") }; XCTAssertTrue(output)
    }
    func testCancellationDuringSlowPreflightRejectsLateCandidates() async throws {
        let s = try session(scanner: FixtureScanner(key: HostPublicKey(openSSHPublicKey: publicEd), delay: 150_000_000))
        _ = try s.connect(config()); s.cancel()
        XCTAssertThrowsError(try s.reconnect())
        let done = await until { s.canReconnect }; XCTAssertTrue(done)
        XCTAssertTrue(s.trustChallenges.isEmpty); XCTAssertNil(s.ownedProcessID)
    }
    func testHostKeyScannerDefaultAndExplicitBounds() throws {
        XCTAssertEqual(try SystemHostKeyScanner().timeoutSeconds, 10)
        for seconds in [1, 5, 10, 15] {
            XCTAssertEqual(try SystemHostKeyScanner(timeoutSeconds: seconds).timeoutSeconds, seconds)
        }
        for seconds in [-1, 0, 16] {
            XCTAssertThrowsError(try SystemHostKeyScanner(timeoutSeconds: seconds)) {
                XCTAssertEqual($0 as? HostScanError, .timeout)
            }
        }
    }
    func testBoundedToolTimeoutCancelOverflowAndNonProtocolOutput() throws {
        XCTAssertThrowsError(try BoundedTool.run(fixture, ["--sleep"], seconds: 0.05)) { XCTAssertEqual($0 as? HostScanError, .timeout) }
        let cancelled = ToolCancellation(); cancelled.cancel()
        XCTAssertThrowsError(try BoundedTool.run(fixture, ["--sleep"], seconds: 1, cancellation: cancelled)) { XCTAssertEqual($0 as? HostScanError, .cancelled) }
        XCTAssertThrowsError(try BoundedTool.run(fixture, ["--stream", "10000"], seconds: 3)) { XCTAssertEqual($0 as? HostScanError, .outputLimit) }
        let output = try BoundedTool.run(fixture, ["--invalid-scan"], seconds: 1)
        XCTAssertThrowsError(try SystemHostKeyScanner.parse(output.output, for: host()))
        let h = try host()
        XCTAssertThrowsError(try SystemHostKeyScanner.parse(Data((h.knownHostsName + " " + publicEd + "\n" + h.knownHostsName + " " + changedEd + "\n").utf8), for: h))
    }
    func testOwnerDeinitReleasesLiveChildAndViewWithoutExplicitClose() async throws {
        weak var weakSession: DirectSSHSession?
        weak var weakView: NativeTerminalView?
        var pid: pid_t = 0
        do {
            let s = try start(["--ignore-term"])
            let ready = await until { s.terminal.text.contains("READY") }; XCTAssertTrue(ready)
            pid = try XCTUnwrap(s.ownedProcessID); weakSession = s; weakView = s.terminal
            sessions.removeLast()
        }
        let released = await until { weakSession == nil && weakView == nil && kill(pid, 0) == -1 && errno == ESRCH }
        XCTAssertTrue(released)
    }
    func testStrictPasswordPolicySSHGAndOneTimeBudget() async throws {
        let strict = try SSHSessionConfiguration(connection: config().connection, authentication: SSHAuthentication(method: .passwordOnly))
        let controlled = try DirectSSHConfiguration(configuration: strict, trustStore: store(), trustedKeys: [HostPublicKey(openSSHPublicKey: publicEd)])
        let workspace = try SessionWorkspace(root: AbsolutePath(directory.path), text: controlled.text)
        let invocation = workspace.invocation(preview: true)
        let output = try BoundedTool.run(invocation.executable, invocation.arguments, seconds: 3)
        let text = String(decoding: output.output, as: UTF8.self)
        for expected in ["preferredauthentications password", "passwordauthentication yes", "kbdinteractiveauthentication no", "pubkeyauthentication false", "gssapiauthentication no", "hostbasedauthentication no", "identityfile none", "certificatefile none", "batchmode no", "numberofpasswordprompts 1"] {
            XCTAssertTrue(text.contains(expected), expected)
        }
        // Apple ssh -G omits both fields (readconf dump subset), but accepts the
        // explicit directives; assert the immutable source config as well.
        XCTAssertEqual(output.status, 0)
        XCTAssertTrue(controlled.text.contains("PKCS11Provider none\n"))
        XCTAssertTrue(controlled.text.contains("UseKeychain no\n"))
        XCTAssertNil(invocation.environment["SSH_ASKPASS_PROMPT"]); XCTAssertNil(invocation.environment["ENV"]); XCTAssertNil(invocation.environment["BASH_ENV"])
        XCTAssertEqual(invocation.environment["SHELL"], "/bin/sh")
        let grant = SessionGrant(generation: 1, nonce: String(repeating: "a", count: 64))
        let request = Request(grant: grant, prompt: "No prompt text type proof", hint: nil)
        var eligible = SavedPasswordBudget(eligible: true)
        XCTAssertTrue(eligible.claim(request)); XCTAssertFalse(eligible.claim(Request(grant: grant, prompt: "change password", hint: nil)))
        var hinted = SavedPasswordBudget(eligible: true)
        XCTAssertFalse(hinted.claim(Request(grant: grant, prompt: "password", hint: "unknown"))); XCTAssertFalse(hinted.claim(request))
        var unknownOS = SavedPasswordBudget(eligible: false)
        XCTAssertFalse(unknownOS.claim(request))
        let version = try BoundedTool.run("/usr/bin/ssh", ["-V"], seconds: 3, includeStandardError: true)
        XCTAssertEqual(version.status, 0)
        let expected = PasswordAutomationGate.matchesReviewedSystem(
            build: PasswordAutomationGate.operatingSystemBuild(),
            versionOutput: String(decoding: version.output, as: UTF8.self),
            signatureValid: ap_system_ssh_signed() == 0)
        let gate = await PasswordAutomationGate.evaluate()
        XCTAssertEqual(gate, expected, "Runtime must match the exact reviewed OS/SSH/signature policy; unknown hosts remain manual")
    }
    func testPasswordAutomationCompatibilityRequiresExactReviewedPairAndSignature() {
        let reviewed = [
            ("24H32", "OpenSSH_9.9p2, LibreSSL 3.3.6\n"),
            ("25G241", "OpenSSH_10.3p1, LibreSSL 3.3.6\n")
        ]
        for (build, version) in reviewed {
            XCTAssertTrue(PasswordAutomationGate.matchesReviewedSystem(build: build, versionOutput: version, signatureValid: true))
            XCTAssertFalse(PasswordAutomationGate.matchesReviewedSystem(build: build, versionOutput: version, signatureValid: false))
            XCTAssertFalse(PasswordAutomationGate.matchesReviewedSystem(build: build, versionOutput: String(version.dropLast()), signatureValid: true))
            XCTAssertFalse(PasswordAutomationGate.matchesReviewedSystem(build: build, versionOutput: version + "\n", signatureValid: true))
            XCTAssertFalse(PasswordAutomationGate.matchesReviewedSystem(build: build, versionOutput: version.replacingOccurrences(of: "3.3.6", with: "3.3.7"), signatureValid: true))
        }
        XCTAssertFalse(PasswordAutomationGate.matchesReviewedSystem(build: reviewed[0].0, versionOutput: reviewed[1].1, signatureValid: true))
        XCTAssertFalse(PasswordAutomationGate.matchesReviewedSystem(build: reviewed[1].0, versionOutput: reviewed[0].1, signatureValid: true))
        for unknown in [nil, "", "25G242", "25G241 ", "24H33"] as [String?] {
            XCTAssertFalse(PasswordAutomationGate.matchesReviewedSystem(build: unknown, versionOutput: reviewed[1].1, signatureValid: true))
        }
    }
    func testAuthenticatedEventCommandQuotesOnlyFixedBundlePath() throws {
        let command = try AuthenticatedEventCommand.quoteExecutable("/private/app 'quote' % value/Contents/Helpers/openlxssh-askpass")
        XCTAssertEqual(command, "exec '/private/app '\\''quote'\\'' %% value/Contents/Helpers/openlxssh-askpass' --authenticated-event v1")
        for invalid in ["relative", "/a\ncommand", "/a\r", "/a\u{0}"] { XCTAssertThrowsError(try AuthenticatedEventCommand.quoteExecutable(invalid)) }
        XCTAssertFalse(command.contains("%h")); XCTAssertFalse(command.contains("%r")); XCTAssertFalse(command.contains("%n"))
    }
    func testChangedTrustedKeyPreflightFailsWithoutStartingProcess() async throws {
        let trust = try store(), endpoint = try host()
        let original = try HostPublicKey(openSSHPublicKey: publicEd)
        guard case .pending(let decision) = try await trust.evaluate(host: endpoint, key: original) else { return XCTFail("expected pending") }
        _ = try await trust.confirm(decision, displayedFingerprint: decision.fingerprint)
        let s = try DirectSSHSession(probeStore: trust, directory: AbsolutePath(directory.path), scanner: FixtureScanner(key: HostPublicKey(openSSHPublicKey: changedEd), delay: 0))
        sessions.append(s); _ = try s.connect(config())
        let rejected = await until { s.state == .failed(.trustRejected) }; XCTAssertTrue(rejected)
        XCTAssertNil(s.ownedProcessID); XCTAssertTrue(s.trustChallenges.isEmpty)
        let records = try await trust.records(); XCTAssertEqual(records.map(\.key), [original])
    }
    func testWrongDisplayedFingerprintNeverWritesTrust() async throws {
        let s = try session(); _ = try s.connect(config())
        let waiting = await until { s.state == .awaitingTrust }; XCTAssertTrue(waiting)
        let challenge = try XCTUnwrap(s.trustChallenges.first)
        do { try await s.acceptTrust(challenge, displayedFingerprint: "SHA256:not-verified"); XCTFail("wrong fingerprint accepted") } catch {}
        XCTAssertEqual(s.state, .failed(.trustRejected))
        let records = try await store().records(); XCTAssertTrue(records.isEmpty)
    }
    func testSynchronousStateCallbackCancelCannotLaunchOrReenterGeneration() async throws {
        let s = try session(), configuration = try config()
        var reentrantAccepted = false
        s.onStateChange = { [weak s] _, state in
            guard state == .preparing, let s else { return }
            s.cancel()
            do { _ = try s.connect(configuration); reentrantAccepted = true } catch {}
        }
        _ = try s.connect(configuration)
        let done = await until { s.canReconnect }; XCTAssertTrue(done)
        XCTAssertFalse(reentrantAccepted); XCTAssertEqual(s.token?.generation, 1)
        XCTAssertNil(s.ownedProcessID); XCTAssertTrue(s.trustChallenges.isEmpty)
    }
    func testSynchronousFailureCallbackCancelCompletesCleanupWithoutStartingProcess() async throws {
        let s = try session(); let token = try s.connect(config())
        let waiting = await until { s.state == .awaitingTrust }; XCTAssertTrue(waiting)
        let challenge = try XCTUnwrap(s.trustChallenges.first)
        var states: [SSHSessionState] = []
        s.onStateChange = { [weak s] _, state in
            states.append(state)
            if case .failed = state { s?.cancel() }
        }
        do { try await s.acceptTrust(challenge, displayedFingerprint: "SHA256:not-verified"); XCTFail("wrong fingerprint accepted") } catch {}
        XCTAssertEqual(states, [.preparing, .failed(.trustRejected), .closing, .disconnected(nil)])
        XCTAssertEqual(s.state, .disconnected(nil)); XCTAssertTrue(s.canReconnect)
        XCTAssertEqual(s.token, token); XCTAssertNil(s.ownedProcessID)
        XCTAssertTrue(s.trustChallenges.isEmpty)
        let records = try await store().records(); XCTAssertTrue(records.isEmpty)
        do { try await s.acceptTrust(challenge, displayedFingerprint: challenge.decision.fingerprint); XCTFail("late trust accepted") } catch {}
        XCTAssertEqual(s.state, .disconnected(nil))
    }
    func testPreflightFailureCallbackCancelWaitsForCleanupBeforeReconnect() async throws {
        let trust = try store(), endpoint = try host(), original = try HostPublicKey(openSSHPublicKey: publicEd)
        guard case .pending(let decision) = try await trust.evaluate(host: endpoint, key: original) else { return XCTFail("expected pending") }
        _ = try await trust.confirm(decision, displayedFingerprint: decision.fingerprint)
        let s = try DirectSSHSession(probeStore: trust, directory: AbsolutePath(directory.path), scanner: FixtureScanner(key: HostPublicKey(openSSHPublicKey: changedEd), delay: 0))
        sessions.append(s)
        var states: [SSHSessionState] = []
        var reconnectDuringCleanup = false
        s.onStateChange = { [weak s] _, state in
            states.append(state)
            guard case .failed = state, let s else { return }
            s.cancel(); reconnectDuringCleanup = s.canReconnect
        }
        _ = try s.connect(config())
        let done = await until { s.canReconnect }; XCTAssertTrue(done)
        XCTAssertEqual(states, [.preparing, .failed(.trustRejected), .closing, .disconnected(nil)])
        XCTAssertFalse(reconnectDuringCleanup); XCTAssertNil(s.ownedProcessID)
        XCTAssertTrue(s.trustChallenges.isEmpty)
    }
    func testTwentyCyclesFDAndUIResourceRelease() async throws {
        let warm = try start(); let ready = await until { warm.terminal.text.contains("READY") }; XCTAssertTrue(ready)
        warm.closeTab(); let stopped = await until { warm.state == .closed }; XCTAssertTrue(stopped)
        let before = ap_fd_count()
        var pids: [pid_t] = []
        for _ in 0..<20 {
            do {
                let s = try start(["--exit", "7"])
                if let pid = s.ownedProcessID { pids.append(pid) }
                let done = await until { s.canReconnect }; XCTAssertTrue(done); XCTAssertEqual(s.lastExitCode, 7)
                XCTAssertTrue(s.terminal.text.contains("FINAL-TAIL")); s.closeTab()
                sessions.removeLast()
            }
        }
        try? await Task.sleep(nanoseconds: 150_000_000)
        let after = ap_fd_count(); print("Transport cycles=20 FD before=\(before) after=\(after)")
        XCTAssertLessThanOrEqual(after, before + 2)
        for pid in pids { XCTAssertEqual(kill(pid, 0), -1); XCTAssertEqual(errno, ESRCH) }
    }
}
