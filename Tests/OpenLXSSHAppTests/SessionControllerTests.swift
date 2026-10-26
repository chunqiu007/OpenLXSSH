import AppKit
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHTransport
import OpenLXSSHTrust

@MainActor final class SessionControllerTests: XCTestCase {
    private func fixture() throws -> (AppRepository, SessionController, LogicSessionBuilder, URL) {
        let directory = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let repo = AppRepository(location: .isolated(directory))
        let builder = LogicSessionBuilder(repository: repo)
        return (repo, SessionController(repository: repo, credentials: FakeCredentials(), builder: builder), builder, directory)
    }
    private func wait(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while !condition() { guard ContinuousClock.now < deadline else { XCTFail("Timed out"); return }; try await Task.sleep(for: .milliseconds(10)) }
    }
    private func host() -> HostConfiguration { HostConfiguration(name: "logic only", address: "never-connected.invalid", username: "fixture") }

    func testReuseNewMostRecentAndDisconnectedNeverAutoReconnect() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let first = try XCTUnwrap(controller.open(host, mode: .reuse))
        let same = controller.open(host, mode: .reuse)
        XCTAssertEqual(first, same)
        try await wait { builder.drivers.count == 1 && controller.tabs[0].preparation == nil }
        let second = try XCTUnwrap(controller.open(host, mode: .newSession))
        try await wait { builder.drivers.count == 2 && controller.tabs[1].preparation == nil }
        controller.select(first)
        XCTAssertEqual(controller.open(host, mode: .reuse), first)
        controller.disconnect(first)
        XCTAssertEqual(controller.open(host, mode: .reuse), second)
        controller.disconnect(second)
        let third = controller.open(host, mode: .reuse)
        XCTAssertNotEqual(third, first); XCTAssertNotEqual(third, second)
        XCTAssertEqual(builder.drivers[0].connectCount, 1)
        await controller.closeAll(); try await repo.close()
    }

    func testSwitchVisibilityKeepsDriverAndReconnectIncrementsGeneration() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let first = try XCTUnwrap(controller.open(host, mode: .reuse))
        try await wait { builder.drivers.count == 1 && controller.tabs[0].preparation == nil }
        let driver = builder.drivers[0], view = builder.drivers[0].terminal
        let second = try XCTUnwrap(controller.open(host, mode: .newSession))
        try await wait { builder.drivers.count == 2 }
        XCTAssertTrue(view.isHidden)
        controller.select(first); XCTAssertFalse(view.isHidden)
        controller.select(second); XCTAssertTrue(view.isHidden)
        controller.disconnect(first); controller.reconnect(first)
        try await wait { driver.token?.generation == 2 }
        XCTAssertTrue(controller.tabs[0].driver === driver)
        XCTAssertTrue(controller.tabs[0].driver?.terminal === view)
        await controller.closeAll(); XCTAssertTrue(controller.tabs.isEmpty)
        XCTAssertTrue(builder.drivers.allSatisfy { $0.state == .closed })
        try await repo.close()
    }

    func testCloseDuringPreparationCannotResurrectTab() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)]); builder.delay = true
        let id = try XCTUnwrap(controller.open(host, mode: .reuse))
        await controller.closeTab(id)
        XCTAssertTrue(controller.tabs.isEmpty)
        XCTAssertTrue(builder.drivers.allSatisfy { $0.state == .closed && $0.connectCount == 0 })
        try await repo.close()
    }

    func testPreparationFailureAllowsExplicitRetryAndReconnectRefreshesHost() async throws {
        let (repo, controller, builder, _) = try fixture(); var host = host()
        try await repo.apply([.insertHost(host)]); builder.fail = true
        let id = try XCTUnwrap(controller.open(host, mode: .reuse))
        try await wait { controller.tabs[0].preparation == nil }
        XCTAssertTrue(controller.tabs[0].canReconnect)
        XCTAssertNotNil(controller.tabs[0].issue)
        builder.fail = false; controller.reconnect(id)
        try await wait { builder.drivers.count == 1 && controller.tabs[0].preparation == nil }
        controller.disconnect(id)
        host.username = "updated"; host.port = 2223
        try await repo.apply([.updateHost(host)])
        controller.reconnect(id)
        try await wait { builder.drivers[0].token?.generation == 2 }
        XCTAssertEqual(builder.drivers[0].lastConfiguration?.connection.user.value, "updated")
        XCTAssertEqual(builder.drivers[0].lastConfiguration?.connection.host.port.value, 2223)
        await controller.closeAll(); try await repo.close()
    }

    func testOnlyCurrentAuthenticatedEventMarksHistoryOnce() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        _ = controller.open(host, mode: .reuse)
        try await wait { builder.drivers.count == 1 && controller.tabs[0].preparation == nil }
        let initialHistory = try await repo.securityMetadata().hosts[0].lastConnectedAt
        XCTAssertNil(initialHistory)
        let driver = builder.drivers[0]
        driver.onState?(SessionToken(sessionID: driver.id, generation: 90), .connected)
        let staleHistory = try await repo.securityMetadata().hosts[0].lastConnectedAt
        XCTAssertNil(staleHistory)
        driver.set(.connected)
        try await Task.sleep(for: .milliseconds(50))
        let firstDate = try await repo.securityMetadata().hosts[0].lastConnectedAt
        XCTAssertNotNil(firstDate)
        driver.set(.connected)
        try await Task.sleep(for: .milliseconds(50))
        let repeatedHistory = try await repo.securityMetadata().hosts[0].lastConnectedAt
        XCTAssertEqual(repeatedHistory, firstDate)
        await controller.closeAll(); try await repo.close()
    }

    func testStaleAuthenticationAfterCancelRejectedWithoutAnswer() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let id = try XCTUnwrap(controller.open(host, mode: .reuse))
        try await wait { builder.drivers.count == 1 && controller.tabs[0].preparation == nil }
        let driver = builder.drivers[0]
        driver.set(.authenticating)
        let prompt = SessionAuthenticationPrompt(token: try XCTUnwrap(driver.token), id: UUID(), kind: .unknownMasked, text: "logic-only")
        driver.onAuthentication?(prompt)
        controller.disconnect(id)
        XCTAssertFalse(controller.respond(.acknowledge, to: prompt, tabID: id))
        XCTAssertEqual(driver.responseCount, 0)
        await controller.closeAll(); try await repo.close()
    }

    func testTypedMappingAndPromptSanitizing() throws {
        var host = host(); host.port = 2222; host.keepaliveInterval = 0
        let password = try SessionEnvironment.configuration(host: host, keyPath: nil)
        XCTAssertEqual(password.authentication.method, .passwordOnly)
        XCTAssertEqual(password.connection.host.port.value, 2222)
        XCTAssertEqual(password.serverAliveInterval, 0)
        host.authentication = .passwordWithMFA
        let mfa = try SessionEnvironment.configuration(host: host, keyPath: nil)
        XCTAssertEqual(mfa.authentication.method, .passwordAndKeyboardInteractive)
        host.authentication = .privateKeyWithMFA
        XCTAssertEqual(try SessionEnvironment.configuration(host: host, keyPath: "/private/test/key.openssh").authentication.method,
                       .privateKey(try AbsolutePath("/private/test/key.openssh"), keyboardInteractive: true))
        host.authentication = .privateKey
        XCTAssertThrowsError(try SessionEnvironment.configuration(host: host, keyPath: nil))
        XCTAssertEqual(try SessionEnvironment.configuration(host: host, keyPath: "/private/test/key.openssh").authentication.method,
                       .privateKey(try AbsolutePath("/private/test/key.openssh"), keyboardInteractive: false))
        host.address = "host;touch /tmp/no"
        XCTAssertThrowsError(try SessionEnvironment.configuration(host: host, keyPath: "/private/test/key.openssh"))
        let sanitized = SafePrompt.display("https://untrusted.invalid/\u{1B}[31m\u{202E}\n" + String(repeating: "x", count: 9000))
        XCTAssertTrue(sanitized.contains("\\u{001B}")); XCTAssertTrue(sanitized.contains("\\u{202E}"))
        XCTAssertFalse(sanitized.contains("\u{1B}")); XCTAssertTrue(sanitized.contains("[提示已截断]"))
    }

    func testSavedPasswordChecksHostAuthorizationAndCurrentGeneration() async throws {
        let (repo, _, builder, _) = try fixture()
        let credentials = FakeCredentials()
        let controller = SessionController(repository: repo, credentials: credentials, builder: builder)
        var host = host(); let reference = UUID()
        host.credentialRef = reference; host.savePasswordAuthorized = true
        try await repo.apply([.registerCredential(.init(id: reference, purpose: .password, isSavingAuthorized: true)), .insertHost(host)])
        _ = await credentials.save(.init(utf8: UUID().uuidString), as: .init(id: reference, kind: .password), authorization: .granted)
        let id = try XCTUnwrap(controller.open(host, mode: .reuse))
        try await wait { builder.drivers.count == 1 && controller.tabs[0].preparation == nil }
        let token = try XCTUnwrap(builder.drivers[0].token)
        let available = try await controller.readSavedPassword(token, tabID: id, expectedHost: host)
        XCTAssertNotNil(available)
        var altered = host; altered.address = "changed.invalid"
        try await repo.apply([.updateHost(altered)])
        let changed = try await controller.readSavedPassword(token, tabID: id, expectedHost: host)
        XCTAssertNil(changed)
        try await repo.apply([.updateHost(host)])
        controller.disconnect(id)
        let cancelled = try await controller.readSavedPassword(token, tabID: id, expectedHost: host)
        XCTAssertNil(cancelled)
        controller.reconnect(id)
        try await wait { builder.drivers[0].token?.generation == 2 }
        let stale = try await controller.readSavedPassword(token, tabID: id, expectedHost: host)
        XCTAssertNil(stale)
        var mfa = host; mfa.authentication = .passwordWithMFA
        let mixed = try await controller.readSavedPassword(try XCTUnwrap(builder.drivers[0].token), tabID: id, expectedHost: mfa)
        XCTAssertNil(mixed)
        let reads = await credentials.readCount
        XCTAssertEqual(reads, 1)
        await controller.closeAll(); try await repo.close()
    }

    func testSettingsApplyToExistingTerminalAndRemainDuringSwitch() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        _ = controller.open(host, mode: .reuse)
        try await wait { builder.drivers.count == 1 && controller.tabs[0].preparation == nil }
        let terminal = builder.drivers[0].terminal
        var settings = AppSettings(); settings.fontName = "Menlo-Regular"; settings.fontSize = 72
        settings.historyLines = 50_000; settings.theme = .light
        settings.foregroundColor = "#AABBCC"; settings.backgroundColor = "#112233"; settings.cursorColor = "#778899"
        controller.updateSettings(settings)
        XCTAssertEqual(terminal.font.pointSize, 72)
        XCTAssertEqual(terminal.caretColor.usingColorSpace(.deviceRGB), NSColor(sessionHex: "#778899").usingColorSpace(.deviceRGB))
        XCTAssertTrue(controller.tabs[0].driver?.terminal === terminal)
        await controller.closeAll(); try await repo.close()
    }

    func testSystemAppearanceChangesTerminalButCustomColorsStayFixed() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        _ = controller.open(host, mode: .reuse)
        try await wait { builder.drivers.count == 1 && controller.tabs[0].preparation == nil }
        let terminal = builder.drivers[0].terminal
        var settings = AppSettings(); settings.theme = .light
        controller.updateSettings(settings)
        terminal.viewDidChangeEffectiveAppearance()
        let light = terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB)
        settings.theme = .dark; controller.updateSettings(settings); terminal.viewDidChangeEffectiveAppearance()
        let dark = terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB)
        XCTAssertNotEqual(light, dark)
        if case .system = terminal.explicitColorMode {} else { XCTFail("Expected system mode") }
        settings.theme = .system; controller.updateSettings(settings)
        terminal.appearance = NSAppearance(named: .aqua); terminal.viewDidChangeEffectiveAppearance()
        XCTAssertEqual(terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB), light)
        terminal.appearance = NSAppearance(named: .darkAqua); terminal.viewDidChangeEffectiveAppearance()
        XCTAssertEqual(terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB), dark)
        settings.backgroundColor = "#123456"; settings.cursorColor = "#ABCDEF"
        controller.updateSettings(settings)
        let custom = terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB)
        terminal.appearance = NSAppearance(named: .aqua); terminal.viewDidChangeEffectiveAppearance()
        terminal.appearance = NSAppearance(named: .darkAqua); terminal.viewDidChangeEffectiveAppearance()
        XCTAssertEqual(terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB), custom)
        XCTAssertEqual(terminal.caretColor.usingColorSpace(.deviceRGB), NSColor(sessionHex: "#ABCDEF").usingColorSpace(.deviceRGB))
        await controller.closeAll(); try await repo.close()
    }

    func testLifecycleTransferSeamDoesNotCancelWithoutDecision() async throws {
        let (_, controller, _, _) = try fixture()
        let transfers = LogicTransfers()
        let lifecycle = AppLifecycleCoordinator(sessions: controller, transfers: transfers)
        let withoutDecision = await lifecycle.closeConnections()
        XCTAssertFalse(withoutDecision)
        XCTAssertEqual(transfers.cancelCount, 0)
        let withDecision = await lifecycle.closeConnections(cancelTransfers: true)
        XCTAssertTrue(withDecision)
        XCTAssertEqual(transfers.cancelCount, 1)
    }
}

/// These test drivers are logical substitutes, not SSH protocol or process tests.
@MainActor private final class LogicSessionBuilder: SessionBuilding {
    let repository: any AppRepositoryProtocol
    var drivers: [LogicSessionDriver] = []
    var delay = false
    var fail = false
    init(repository: any AppRepositoryProtocol) { self.repository = repository }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        guard let host = try await repository.securityMetadata().hosts.first(where: { $0.id == hostID }) else { throw RepositoryError.notFound }
        return (host, try SessionEnvironment.configuration(host: host, keyPath: nil))
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        if fail { throw TransportError.invalidConfiguration }
        if delay { try await Task.sleep(for: .milliseconds(100)) }
        let (host, configuration) = try await configuration(hostID: hostID)
        let driver = LogicSessionDriver(id: sessionID); drivers.append(driver)
        return ReadySession(host: host, configuration: configuration, driver: driver)
    }
}
@MainActor private final class LogicSessionDriver: SessionDriving {
    let id: UUID
    let terminal = NativeTerminalView()
    var token: SessionToken?
    var state: SSHSessionState = .idle
    var canReconnect: Bool { state == .idle || state == .disconnected(nil) }
    var onState: ((SessionToken?, SSHSessionState) -> Void)?
    var onTrust: (([SessionTrustPrompt]) -> Void)?
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)?
    var connectCount = 0, responseCount = 0
    var lastConfiguration: SSHSessionConfiguration?
    init(id: UUID) { self.id = id }
    func set(_ next: SSHSessionState) { state = next; onState?(token, next) }
    func connect(_ configuration: SSHSessionConfiguration, savedPassword: SavedPasswordAuthorization?) throws -> SessionToken {
        lastConfiguration = configuration
        connectCount += 1; token = SessionToken(sessionID: id, generation: UInt64(connectCount)); set(.connectionPending); return token!
    }
    func accept(_ prompt: SessionTrustPrompt) async throws { set(.connectionPending) }
    func respond(_ response: AuthenticationResponse, to prompt: SessionAuthenticationPrompt) throws { responseCount += 1; set(.connectionPending) }
    func cancel() { set(.disconnected(nil)) }
    func closeTab() { set(.closed); terminal.releaseResources() }
}
@MainActor private final class LogicTransfers: TransferLifecycle {
    var hasActiveTransfers = true
    var cancelCount = 0
    func cancelAllAndWait() async { cancelCount += 1; hasActiveTransfers = false }
}
