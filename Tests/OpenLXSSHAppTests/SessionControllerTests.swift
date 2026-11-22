import AppKit
import Darwin
import Foundation
import SwiftUI
import XCTest
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHSecurity
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

    func testNativeLocalNetworkPolicyDeadlineIsDistinctFromOrdinaryNetworkErrors() async throws {
        let (repo, _, _, directory) = try fixture(), host = host()
        let credentials = FakeCredentials()
        let security = SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials)
        let cases: [(FileServiceError, SessionFailureDetail.Category)] = [
            (.init(.timeout, operation: "local-network-access"), .localNetworkAccessRequired),
            (.init(.transport, operation: "connect", code: Int64(EHOSTUNREACH)), .networkUnavailable),
            (.init(.timeout, operation: "connect"), .networkTimeout),
            (.init(.transport, operation: "dns", code: -2), .networkUnavailable)
        ]
        for (error, category) in cases {
            let driver = try NativeSessionDriver(sessionID: UUID(), host: host, repository: repo, security: security,
                connector: LocalNetworkFailureConnector(error: error))
            driver.onTrust = { _ in XCTFail("A pre-TCP failure cannot fabricate a host-key prompt") }
            driver.onAuthentication = { _ in XCTFail("A pre-TCP failure cannot ask for authentication") }
            _ = try driver.connect(SessionEnvironment.configuration(host: host, keyPath: nil),
                primary: SessionPrimaryAuthorization(provider: { _ in XCTFail("Pre-TCP error cannot ask for credentials"); return nil }))
            try await wait { driver.failureDetail != nil }
            XCTAssertEqual(driver.failureDetail?.category, category)
            XCTAssertEqual(driver.failureDetail?.operation, error.operation)
            XCTAssertEqual(driver.failureDetail?.code, error.code)
            let closed = await driver.closeResult(deadline: .now + .seconds(2))
            XCTAssertTrue(closed.permitsRemoval)
            XCTAssertTrue(driver.snapshot.nativeCloseCompleted); XCTAssertTrue(driver.snapshot.interactionsDrained)
        }
        let detail = SessionFailureDetail(category: .localNetworkAccessRequired, operation: "local-network-access", code: nil, stages: [])
        XCTAssertTrue(detail.summary.contains("本地网络")); XCTAssertTrue(detail.summary.contains("尚未进行 SSH 握手或认证"))
        let reads = await credentials.readCount; XCTAssertEqual(reads, 0)
        try await security.close(); try await repo.close()
    }

    func testSFTPOnlyExplicitNetworkPolicyDeadlineGetsSystemAccessGuidance() throws {
        let policy = AppIssue.files(FileServiceError(.timeout, operation: "local-network-access"))
        XCTAssertEqual(policy.code, "files.localNetworkAccessRequired")
        XCTAssertTrue(policy.message.contains("本地网络")); XCTAssertTrue(policy.message.contains("尚未进行 SSH 握手或认证"))
        let ordinary = AppIssue.files(FileServiceError(.permissionDenied, operation: "lstat"))
        XCTAssertEqual(ordinary.code, "files.permissionDenied")
        XCTAssertFalse(ordinary.message.contains("系统设置"))
        let network = AppIssue.files(FileServiceError(.transport, operation: "connect", code: Int64(EHOSTUNREACH)))
        XCTAssertEqual(network.code, "files.transport")
    }

    func testVaultNavigationRefusalPrecedesSessionSelectionAndNewSessionAllocation() async throws {
        let (repo, _, builder, directory) = try fixture(), host = host()
        try await repo.apply([.insertHost(host)])
        let credentials = FakeCredentials(), security = SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials)
        let model = AppModel(repository: repo, security: security, location: .isolated(directory), sessionBuilder: builder)
        _ = await model.reload()
        model.requestSession(hostID: host.id, mode: .newSession)
        let first = try XCTUnwrap(model.sessions.selectedTabID)
        await model.sessions.selectedTab?.preparation?.value
        model.requestSession(hostID: host.id, mode: .newSession)
        let second = try XCTUnwrap(model.sessions.selectedTabID)
        await model.sessions.selectedTab?.preparation?.value
        model.showWorkspace(.vault)
        let owner = UUID()
        model.registerWorkspaceNavigationGuard(owner: owner) { false }
        model.showWorkspace(.session(first))
        XCTAssertEqual(model.workspacePage, .vault); XCTAssertEqual(model.sessions.selectedTabID, second)
        model.requestSession(hostID: host.id, mode: .newSession)
        XCTAssertEqual(model.sessions.tabs.count, 2); XCTAssertEqual(builder.drivers.count, 2)
        XCTAssertEqual(model.sessions.selectedTabID, second); XCTAssertEqual(model.workspacePage, .vault)
        model.clearWorkspaceNavigationGuard(owner: owner)
        model.showWorkspace(.session(first)); XCTAssertEqual(model.sessions.selectedTabID, first)
        await model.sessions.closeAll(); await model.files.closeForWindow(); try await security.close(); try await repo.close()
    }
    func testWorkspaceVisibilityAndOrderingDoNotRecreateOwners() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let first = try XCTUnwrap(controller.open(host, mode: .newSession))
        let second = try XCTUnwrap(controller.open(host, mode: .newSession))
        let third = try XCTUnwrap(controller.open(host, mode: .newSession))
        try await wait { builder.drivers.count == 3 && controller.tabs.allSatisfy { $0.preparation == nil } }
        let view = try XCTUnwrap(controller.tabs.first?.driver?.terminal)
        for _ in 0..<20 {
            controller.setWorkspaceVisible(false)
            XCTAssertTrue(builder.drivers.allSatisfy { $0.terminal.isHidden })
            controller.select(first)
            controller.setWorkspaceVisible(true)
            XCTAssertFalse(view.isHidden)
        }
        controller.moveTab(third, before: first)
        XCTAssertEqual(controller.tabs.map(\.id), [third, first, second])
        controller.moveTab(first, before: nil)
        XCTAssertEqual(controller.tabs.map(\.id), [third, second, first])
        XCTAssertEqual(controller.selectedTabID, first)
        controller.moveTab(UUID(), before: nil)
        controller.moveTab(third, before: UUID())
        XCTAssertEqual(controller.tabs.map(\.id), [third, second, first], "Stale source or target must not reorder a live strip")
        XCTAssertEqual(controller.tabs.first(where: { $0.id == first })?.driver?.terminal, view)
        XCTAssertTrue(builder.drivers.allSatisfy { $0.connectCount == 1 })
        controller.renameTab(first, title: "临时标签")
        XCTAssertEqual(controller.tabs.first(where: { $0.id == first })?.title, "临时标签")
        let savedName = try await repo.securityMetadata().hosts.first?.name
        XCTAssertEqual(savedName, host.name)
        await controller.closeTab(first)
        XCTAssertEqual(controller.selectedTabID, second)
        await controller.closeAll(); try await repo.close()
    }

    func testPerSessionSearchSurvivesTabAndFixedPageRoutingWithoutRebuildingTerminal() async throws {
        let (repo, _, builder, directory) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let model = AppModel(repository: repo, location: .isolated(directory), sessionBuilder: builder)
        let loaded = await model.reload(); XCTAssertTrue(loaded)
        model.requestSession(hostID: host.id, mode: .newSession)
        let a = try XCTUnwrap(model.sessions.selectedTab); await a.preparation?.value
        let driver = try XCTUnwrap(a.driver), terminal = driver.terminal, token = driver.token
        terminal.feed(text: "R5-A-MATCH\r\n")
        XCTAssertTrue(model.sendWorkspaceCommand(.search))
        a.searchText = "R5-A-MATCH"; a.searchHistory()
        XCTAssertEqual(a.searchFound, true)
        model.requestSession(hostID: host.id, mode: .newSession)
        let b = try XCTUnwrap(model.sessions.selectedTab); await b.preparation?.value
        XCTAssertFalse(b.searchVisible); XCTAssertTrue(b.searchText.isEmpty); XCTAssertNil(b.searchFound)
        XCTAssertTrue(model.sendWorkspaceCommand(.search))
        b.searchText = "missing-B"; b.searchHistory(); XCTAssertEqual(b.searchFound, false)
        model.showWorkspace(.vault); model.showWorkspace(.sftp); model.showWorkspace(.session(a.id))
        XCTAssertTrue(a.searchVisible); XCTAssertEqual(a.searchText, "R5-A-MATCH"); XCTAssertEqual(a.searchFound, true)
        XCTAssertEqual(b.searchText, "missing-B"); XCTAssertEqual(b.searchFound, false)
        XCTAssertTrue(a.driver === driver); XCTAssertTrue(a.driver?.terminal === terminal); XCTAssertEqual(a.driver?.token, token)
        XCTAssertTrue(builder.drivers.allSatisfy { $0.connectCount == 1 })
        a.closeSearch(); XCTAssertFalse(a.searchVisible); XCTAssertNotNil(a.terminalFocusRequest)
        await model.sessions.closeTab(b.id)
        XCTAssertEqual(model.workspacePage, .session(a.id))
        await model.sessions.closeTab(a.id)
        XCTAssertEqual(model.workspacePage, .vault); XCTAssertFalse(model.sessions.workspaceVisible)
        await model.files.closeForWindow(); try await repo.close()
    }

    func testDialogPresentationCannotCrossTabOrReplayExpiredRequest() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let aID = try XCTUnwrap(controller.open(host, mode: .newSession))
        let a = try XCTUnwrap(controller.selectedTab); await a.preparation?.value
        let bID = try XCTUnwrap(controller.open(host, mode: .newSession))
        await controller.selectedTab?.preparation?.value
        let driver = builder.drivers[0], token = try XCTUnwrap(builder.drivers[0].token)
        driver.set(.authenticating)
        let prompt = SessionAuthenticationPrompt(token: token, id: UUID(), payload: .initialPassword)
        driver.onAuthentication?(prompt)
        XCTAssertFalse(controller.present(.authentication(prompt), tabID: aID))
        XCTAssertFalse(controller.respond(.answers([]), to: prompt, tabID: aID))
        controller.select(aID)
        XCTAssertTrue(controller.present(.authentication(prompt), tabID: aID))
        let presentation = a.dialog?.id
        controller.select(bID); XCTAssertNil(a.dialog); XCTAssertEqual(a.authentication, prompt)
        controller.select(aID); XCTAssertNil(a.dialog)
        XCTAssertTrue(controller.present(.authentication(prompt), tabID: aID))
        XCTAssertNotEqual(a.dialog?.id, presentation)
        let replacement = SessionAuthenticationPrompt(token: token, id: UUID(), payload: .keyboard(name: "", instruction: "new request", prompts: []))
        driver.onAuthentication?(replacement)
        XCTAssertNil(a.dialog)
        XCTAssertFalse(controller.respond(.answers([]), to: prompt, tabID: aID))
        XCTAssertTrue(controller.present(.authentication(replacement), tabID: aID))
        controller.setWorkspaceVisible(false)
        XCTAssertNil(a.dialog)
        XCTAssertFalse(controller.respond(.answers([]), to: replacement, tabID: aID))
        controller.setWorkspaceVisible(true)
        XCTAssertNil(a.dialog)
        XCTAssertTrue(controller.respond(.answers([]), to: replacement, tabID: aID))
        XCTAssertEqual(driver.responseCount, 1)
        driver.set(.awaitingTrust)
        let trust = SessionTrustPrompt(token: token, id: UUID(), host: try XCTUnwrap(a.configuration?.connection.host),
            algorithm: "ssh-ed25519", fingerprint: "SHA256:LOGIC-ONLY", source: "logic")
        driver.onTrust?([trust]); XCTAssertTrue(controller.present(.trust(trust), tabID: aID))
        driver.onTrust?([]); XCTAssertNil(a.dialog)
        let rejectedTrust = await controller.accept(trust, tabID: aID); XCTAssertFalse(rejectedTrust)
        await controller.closeAll(); try await repo.close()
    }

    func testReuseRequiresConnectionSnapshotButIgnoresPresentationMetadata() async throws {
        let (repo, controller, builder, _) = try fixture(); var host = host()
        try await repo.apply([.insertHost(host)])
        let original = try XCTUnwrap(controller.open(host, mode: .reuse))
        try await wait { builder.drivers.count == 1 && controller.tabs[0].preparation == nil }
        host.name = "renamed"; host.isFavorite = true; host.lastConnectedAt = Date()
        try await repo.apply([.updateHost(host)])
        XCTAssertEqual(controller.open(host, mode: .reuse), original)
        host.username = "another-user"
        try await repo.apply([.updateHost(host)])
        let updated = try XCTUnwrap(controller.open(host, mode: .reuse))
        XCTAssertNotEqual(updated, original)
        try await wait { builder.drivers.count == 2 && controller.tabs.allSatisfy { $0.preparation == nil } }
        XCTAssertEqual(controller.tabs.first(where: { $0.id == original })?.host?.username, "fixture")
        XCTAssertEqual(controller.tabs.first(where: { $0.id == updated })?.host?.username, "another-user")
        XCTAssertEqual(builder.drivers[0].connectCount, 1)
        await controller.closeAll(); try await repo.close()
    }

    func testConnectionIdentityCoversAuthorizationAndKeepaliveNotDisplayFields() {
        let original = host()
        var changed = original; changed.name = "new name"; changed.folderID = UUID(); changed.isFavorite = true; changed.favoriteOrder = 8; changed.lastConnectedAt = Date()
        XCTAssertEqual(changed.connectionIdentity, original.connectionIdentity)
        changed = original; changed.address = "other.invalid"; XCTAssertNotEqual(changed.connectionIdentity, original.connectionIdentity)
        changed = original; changed.port = 2222; XCTAssertNotEqual(changed.connectionIdentity, original.connectionIdentity)
        changed = original; changed.username = "other"; XCTAssertNotEqual(changed.connectionIdentity, original.connectionIdentity)
        changed = original; changed.authentication = .privateKey; XCTAssertNotEqual(changed.connectionIdentity, original.connectionIdentity)
        changed = original; changed.keyRef = UUID(); XCTAssertNotEqual(changed.connectionIdentity, original.connectionIdentity)
        changed = original; changed.credentialRef = UUID(); XCTAssertNotEqual(changed.connectionIdentity, original.connectionIdentity)
        changed = original; changed.savePasswordAuthorized = true; XCTAssertNotEqual(changed.connectionIdentity, original.connectionIdentity)
        changed = original; changed.keepaliveInterval = 9; XCTAssertNotEqual(changed.connectionIdentity, original.connectionIdentity)
        changed = original; changed.keepaliveCountMax = 1; XCTAssertNotEqual(changed.connectionIdentity, original.connectionIdentity)
    }

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
        let prompt = SessionAuthenticationPrompt(token: try XCTUnwrap(driver.token), id: UUID(), payload: .initialPassword)
        driver.onAuthentication?(prompt)
        controller.disconnect(id)
        XCTAssertFalse(controller.respond(.answers([]), to: prompt, tabID: id))
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
        let available = try await controller.readTypedPrimary(
            SessionPrimaryRequest(token: token, id: UUID(), nativeSessionID: id, purpose: .password, key: nil), tabID: id, expectedHost: host)
        XCTAssertNotNil(available)
        // Single-use per generation: second read on same generation must fail without touching Keychain.
        do {
            _ = try await controller.readTypedPrimary(
                SessionPrimaryRequest(token: token, id: UUID(), nativeSessionID: id, purpose: .password, key: nil), tabID: id, expectedHost: host)
            XCTFail("Primary password read must be single-use per generation")
        } catch {}
        // Reconnect for a fresh generation, then alter host in repository and verify mismatch rejects.
        controller.disconnect(id)
        do {
            _ = try await controller.readTypedPrimary(
                SessionPrimaryRequest(token: token, id: UUID(), nativeSessionID: id, purpose: .password, key: nil), tabID: id, expectedHost: host)
            XCTFail("Disconnected tab must reject primary read")
        } catch {}
        controller.reconnect(id)
        try await wait { builder.drivers[0].token?.generation == 2 }
        let token2 = try XCTUnwrap(builder.drivers[0].token)
        do {
            _ = try await controller.readTypedPrimary(
                SessionPrimaryRequest(token: token, id: UUID(), nativeSessionID: id, purpose: .password, key: nil), tabID: id, expectedHost: host)
            XCTFail("Stale generation token must reject primary read")
        } catch {}
        var altered = host; altered.address = "changed.invalid"
        try await repo.apply([.updateHost(altered)])
        do {
            _ = try await controller.readTypedPrimary(
                SessionPrimaryRequest(token: token2, id: UUID(), nativeSessionID: id, purpose: .password, key: nil), tabID: id, expectedHost: host)
            XCTFail("Altered host must reject primary read")
        } catch {}
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

    func testSystemAppearanceKeepsDefaultTerminalDarkButCustomColorsStayFixed() async throws {
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
        XCTAssertEqual(light, dark)
        XCTAssertEqual(dark, NativeTerminalView.desktopBackground.usingColorSpace(.deviceRGB))
        XCTAssertEqual(terminal.nativeForegroundColor.usingColorSpace(.deviceRGB), NativeTerminalView.desktopForeground.usingColorSpace(.deviceRGB))
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

    func testDesktopActionsKeepPerTabFontAndSearchCountWithoutRecreatingOwner() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let aID = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let a = try XCTUnwrap(controller.selectedTab), terminal = try XCTUnwrap(a.driver?.terminal), token = a.driver?.token
        terminal.feed(text: "match-A match-A\r\n")
        XCTAssertTrue(controller.performTerminalAction(.search))
        a.searchText = "match-A"; a.searchHistory()
        XCTAssertEqual(a.searchMatchCount, 2); XCTAssertEqual(a.searchMatchIndex, 1)
        a.searchHistory(); XCTAssertEqual(a.searchMatchIndex, 2)
        a.searchHistory(backwards: true); XCTAssertEqual(a.searchMatchIndex, 1)
        let originalSize = terminal.font.pointSize
        XCTAssertTrue(controller.performTerminalAction(.increaseFont)); XCTAssertEqual(terminal.font.pointSize, originalSize + 1)
        controller.updateSettings(AppSettings())
        XCTAssertEqual(terminal.font.pointSize, originalSize + 1) // Unrelated reload must not reset local zoom.
        let bID = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let b = try XCTUnwrap(controller.selectedTab)
        XCTAssertEqual(b.driver?.terminal.font.pointSize, originalSize)
        XCTAssertFalse(controller.performTerminalAction(.increaseFont, tabID: aID))
        controller.select(aID); XCTAssertEqual(terminal.font.pointSize, originalSize + 1)
        XCTAssertTrue(controller.performTerminalAction(.resetFont)); XCTAssertEqual(terminal.font.pointSize, originalSize)
        for _ in 0..<100 { _ = controller.performTerminalAction(.increaseFont) }
        XCTAssertEqual(terminal.font.pointSize, 72); XCTAssertFalse(controller.canPerformTerminalAction(.increaseFont))
        for _ in 0..<100 { _ = controller.performTerminalAction(.decreaseFont) }
        XCTAssertEqual(terminal.font.pointSize, 6); XCTAssertFalse(controller.canPerformTerminalAction(.decreaseFont))
        controller.disconnect(aID)
        XCTAssertFalse(terminal.inputEnabled); XCTAssertFalse(controller.canPerformTerminalAction(.paste))
        XCTAssertTrue(terminal.text.contains("match-A")); XCTAssertTrue(controller.canPerformTerminalAction(.reconnect))
        XCTAssertEqual(a.driver?.token, token); XCTAssertTrue(a.driver?.terminal === terminal)
        XCTAssertEqual(controller.tabs.map(\.id), [aID, bID]); XCTAssertTrue(builder.drivers.allSatisfy { $0.connectCount == 1 })
        await controller.closeAll(); try await repo.close()
    }

    func testCursorPreferencesAndPreviewApplyToEveryExistingOwnerWithoutReconnect() async throws {
        let (repo, controller, builder, _) = try fixture(), host = host()
        addTeardownBlock { await controller.closeAll(); try await repo.close() }
        try await repo.apply([.insertHost(host)])
        let first = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let second = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let terminals = builder.drivers.map(\.terminal), tokens = builder.drivers.map(\.token)
        let preview = NativeTerminalView(); defer { preview.releaseResources() }
        terminals[0].feed(text: "preserved preference output\r\n")
        var settings = AppSettings(); settings.cursorShape = .underline; settings.cursorBlink = false; settings.fontSize = 18
        settings.backgroundColor = "#102030"; settings.foregroundColor = "#ABCDEF"; settings.cursorColor = "#778899"
        controller.updateSettings(settings); try TerminalPreferences.apply(settings, to: preview)
        for terminal in terminals {
            XCTAssertEqual(terminal.terminalStateSnapshot().cursorStyle.tagName, "steadyUnderline")
            XCTAssertEqual(terminal.font, preview.font)
            XCTAssertEqual(terminal.nativeBackgroundColor.usingColorSpace(.deviceRGB), preview.nativeBackgroundColor.usingColorSpace(.deviceRGB))
            XCTAssertEqual(terminal.caretColor.usingColorSpace(.deviceRGB), preview.caretColor.usingColorSpace(.deviceRGB))
        }
        terminals[0].setDesktopCursor(shape: .bar, blinking: true) // A remote TUI may override cursor style.
        controller.updateSettings(settings) // Unrelated metadata refresh must not overwrite that request.
        XCTAssertEqual(terminals[0].terminalStateSnapshot().cursorStyle.tagName, "blinkBar")
        XCTAssertEqual(builder.drivers.map(\.token), tokens); XCTAssertTrue(builder.drivers.allSatisfy { $0.connectCount == 1 })
        XCTAssertTrue(terminals[0].text.contains("preserved preference output"))
        controller.select(first); controller.moveTab(second, before: first)
        XCTAssertTrue(controller.selectedTab?.driver?.terminal === terminals[0])
        XCTAssertEqual(controller.tabs.map(\.id), [second, first])
        await controller.closeAll(); try await repo.close()
    }

    func testGlobalCloseCancelBeforeFreezeKeepsOriginalSSHTokenAndTransferOwner() async throws {
        let (repo, _, builder, directory) = try fixture(), host = host()
        try await repo.apply([.insertHost(host)])
        let credentials = FakeCredentials(), security = SecurityCoordinator(repository: repo, location: .isolated(directory), credentials: credentials)
        let app = AppModel(repository: repo, security: security, location: .isolated(directory), sessionBuilder: builder)
        _ = await app.reload(); app.requestSession(hostID: host.id, mode: .newSession)
        let tab = try XCTUnwrap(app.sessions.selectedTab); await tab.preparation?.value
        let driver = try XCTUnwrap(tab.driver), token = driver.token, terminal = driver.terminal
        let files = ControlledFilesLifecycle(); files.hasActiveTransfers = true; app.lifecycle.files = files
        app.registerWindowCloseReview(owner: UUID(), begin: { _ in }, cancel: {})
        let request = app.requestWindowCloseReview()
        request.resolve(false)
        let admitted = await app.lifecycle.freezeAfterCloseReview(request, isCurrent: { app.isWindowCloseReviewCurrent(request) })
        XCTAssertFalse(admitted); XCTAssertEqual(files.freezeCount, 0); XCTAssertEqual(files.closeCount, 0)
        XCTAssertEqual(files.beginCloseCount, 0); XCTAssertTrue(files.hasActiveTransfers)
        XCTAssertEqual(tab.driver?.token, token); XCTAssertTrue(tab.driver === driver); XCTAssertTrue(tab.driver?.terminal === terminal)
        XCTAssertEqual(app.sessions.tabs.map(\.id), [tab.id]); XCTAssertEqual(app.sessions.selectedTabID, tab.id)
        XCTAssertFalse(app.sessions.closingAll); XCTAssertFalse(app.lifecycle.terminating)
        XCTAssertEqual(driver.state, .connectionPending)
        let reads = await credentials.readCount; XCTAssertEqual(reads, 0)
        app.finishWindowCloseReview()
        await app.sessions.closeAll(); try await security.close(); try await repo.close()
    }

    func testGlobalCloseWindowToQuitUpgradeSharesOriginalReviewAndLifecycleCleanup() async throws {
        let (repo, sessions, builder, _) = try fixture(), host = host()
        try await repo.apply([.insertHost(host)])
        _ = sessions.open(host, mode: .newSession); await sessions.selectedTab?.preparation?.value
        let files = ControlledFilesLifecycle(), lifecycle = AppLifecycleCoordinator(sessions: sessions)
        lifecycle.files = files
        var requestState = AppCloseRequestState()
        XCTAssertTrue(requestState.request(.window))
        let registry = WindowCloseReviewRegistry(), review = registry.request()
        let approved = await lifecycle.freezeAfterCloseReview(review, isCurrent: { registry.isCurrent(review) })
        XCTAssertTrue(approved); requestState.approve()
        let window = Task { await lifecycle.closeConnections(cancelTransfers: true, retainAdmissionFreeze: true) }
        await files.waitForClose()
        XCTAssertFalse(requestState.request(.quit)); XCTAssertTrue(requestState.approved); XCTAssertEqual(requestState.intent, .quit)
        lifecycle.beginTermination()
        let quit = Task { await lifecycle.closeConnections(cancelTransfers: true, retainAdmissionFreeze: true) }
        files.releaseClose()
        let windowResult = await window.value, quitResult = await quit.value
        XCTAssertTrue(windowResult); XCTAssertTrue(quitResult); XCTAssertEqual(files.closeCount, 1); XCTAssertEqual(files.beginCloseCount, 1)
        XCTAssertTrue(sessions.tabs.isEmpty); XCTAssertTrue(builder.drivers.allSatisfy { $0.state == .closed })
        XCTAssertTrue(lifecycle.terminating); XCTAssertNil(sessions.open(host, mode: .newSession))
        registry.finishAttempt(); try await repo.close()
    }

    func testWholeLifecycleKeepsSSHAdmissionClosedWhileFilesAreStillClosing() async throws {
        let (repo, sessions, _, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let files = ControlledFilesLifecycle(), lifecycle = AppLifecycleCoordinator(sessions: sessions)
        lifecycle.files = files
        let first = Task { await lifecycle.closeConnections() }
        await files.waitForClose()
        XCTAssertNil(sessions.open(host, mode: .newSession))
        let second = Task { await lifecycle.closeConnections() }
        files.releaseClose()
        let firstResult = await first.value, secondResult = await second.value
        XCTAssertTrue(firstResult); XCTAssertTrue(secondResult)
        XCTAssertEqual(files.closeCount, 1)
        XCTAssertTrue(sessions.tabs.isEmpty)
        XCTAssertNotNil(sessions.open(host, mode: .newSession))
        await sessions.tabs.first?.preparation?.value
        await sessions.closeAll(); try await repo.close()
    }
    func testRetirementCloseAllUsesOneDeadlineAndDoesNotLetIncompleteABlockClosedB() async throws {
        let (repo, controller, builder, _) = try fixture(), host = host()
        try await repo.apply([.insertHost(host)])
        let a = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let b = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        builder.drivers[0].holdClose = true
        let start = ContinuousClock.now
        let result = await controller.closeAllResult(deadline: .now + .milliseconds(40))
        XCTAssertLessThan(start.duration(to: .now), .seconds(1)); XCTAssertFalse(result.complete)
        XCTAssertEqual(result.entries.first { $0.tabID == b }?.result, .closed)
        guard case .incomplete? = result.entries.first(where: { $0.tabID == a })?.result else { return XCTFail("A must remain incomplete") }
        XCTAssertEqual(controller.tabs.map(\.id), [a]); XCTAssertEqual(builder.drivers[1].closeCount, 1)
        XCTAssertEqual(controller.issue?.code, "session.closeIncomplete")
        builder.drivers[0].finishClose()
        let completed = await controller.closeTabResult(a, deadline: .now + .milliseconds(40))
        XCTAssertEqual(completed, .closed)
        try await repo.close()
    }
    func testRetirementLifecycleBoolReflectsIncompleteWithoutPermanentTermination() async throws {
        let (repo, controller, builder, _) = try fixture(), host = host()
        try await repo.apply([.insertHost(host)])
        _ = controller.open(host, mode: .newSession); await controller.selectedTab?.preparation?.value
        builder.drivers[0].holdClose = true
        let lifecycle = AppLifecycleCoordinator(sessions: controller)
        let result = await lifecycle.closeConnections(cancelTransfers: true, retainAdmissionFreeze: true)
        XCTAssertFalse(result); XCTAssertFalse(lifecycle.terminating)
        XCTAssertFalse(try XCTUnwrap(lifecycle.lastCloseResult).complete)
        XCTAssertEqual(controller.issue?.code, "session.closeIncomplete"); XCTAssertEqual(controller.tabs.count, 1)
        builder.drivers[0].finishClose(); await controller.closeAll(); try await repo.close()
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

extension SessionControllerTests {
    func testWindowTabsCurrentDisplayMetadataDoesNotChangeConnectionOwnerOrSnapshot() async throws {
        let (repo, controller, builder, _) = try fixture(), original = host()
        try await repo.apply([.insertHost(original)])
        let id = try XCTUnwrap(controller.open(original, mode: .newSession))
        let tab = try XCTUnwrap(controller.selectedTab); await tab.preparation?.value
        let driver = try XCTUnwrap(tab.driver), token = driver.token, configuration = tab.configuration
        var current = original; current.name = "current display label"; current.isFavorite = true; current.folderID = UUID()
        controller.updateDisplayMetadata(hosts: [current])
        XCTAssertEqual(controller.displayTitle(for: tab), current.name); XCTAssertTrue(tab.displayMetadata.isFavorite)
        XCTAssertFalse(tab.displayMetadata.isDeleted); XCTAssertFalse(tab.configurationChanged)
        XCTAssertEqual(tab.host, original); XCTAssertEqual(tab.configuration, configuration)
        XCTAssertTrue(tab.driver === driver); XCTAssertEqual(driver.token, token); XCTAssertEqual(controller.selectedTabID, id)
        XCTAssertEqual(builder.drivers[0].connectCount, 1)
        await controller.closeAll(); try await repo.close()
    }

    func testWindowTabsCustomRenameAndDeletedBadgeKeepActualConnectionInfo() async throws {
        let (repo, controller, _, _) = try fixture()
        var original = host(); original.address = "2001:db8::42"
        try await repo.apply([.insertHost(original)])
        let id = try XCTUnwrap(controller.open(original, mode: .newSession))
        let tab = try XCTUnwrap(controller.selectedTab); await tab.preparation?.value
        controller.renameTab(id, title: "custom session only")
        var changed = original; changed.name = "new catalog label"; changed.address = "changed.invalid"; changed.username = "changed-user"
        controller.updateDisplayMetadata(hosts: [changed])
        XCTAssertEqual(controller.displayTitle(for: tab), "custom session only"); XCTAssertTrue(tab.configurationChanged)
        let info = controller.connectionInfo(for: tab)
        XCTAssertTrue(info.contains("fixture@[2001:db8::42]:22")); XCTAssertTrue(info.contains("连接配置已更改"))
        XCTAssertFalse(info.contains(changed.address)); XCTAssertFalse(info.contains(changed.username))
        controller.updateDisplayMetadata(hosts: [])
        XCTAssertTrue(tab.displayMetadata.isDeleted); XCTAssertEqual(controller.displayTitle(for: tab), "custom session only")
        XCTAssertTrue(controller.connectionInfo(for: tab).contains("保存配置已删除")); XCTAssertEqual(tab.host, original)
        await controller.closeAll(); try await repo.close()
    }

    func testWindowTabsDuplicateCurrentNamesAndReorderNeverRebuildTerminal() async throws {
        let (repo, controller, builder, _) = try fixture(), first = host()
        var second = host(); second.name = "other original"
        try await repo.apply([.insertHost(first), .insertHost(second)])
        let a = try XCTUnwrap(controller.open(first, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let b = try XCTUnwrap(controller.open(second, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let aTab = try XCTUnwrap(controller.tabs.first { $0.id == a }), terminal = aTab.driver?.terminal
        var currentA = first, currentB = second; currentA.name = "same current"; currentB.name = "same current"
        controller.updateDisplayMetadata(hosts: [currentA, currentB])
        XCTAssertEqual(controller.displayTitle(for: aTab), "same current · 1")
        controller.select(a); controller.moveTab(b, before: a)
        XCTAssertEqual(controller.displayTitle(for: aTab), "same current · 2"); XCTAssertEqual(controller.selectedTabID, a)
        XCTAssertTrue(aTab.driver?.terminal === terminal); XCTAssertTrue(builder.drivers.allSatisfy { $0.connectCount == 1 })
        controller.updateDisplayMetadata(hosts: [currentB])
        XCTAssertEqual(aTab.displayName, "same current"); XCTAssertTrue(aTab.displayMetadata.isDeleted)
        await controller.closeAll(); try await repo.close()
    }

    func testWindowTabsBatchReviewKeepsOriginalIDsNamesEndpointsAndLiveState() async throws {
        let (repo, controller, builder, _) = try fixture(), host = host()
        try await repo.apply([.insertHost(host)])
        let a = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let b = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let c = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let review = try XCTUnwrap(controller.batchCloseReview(scope: .sessionsToRight(a)))
        XCTAssertEqual(review.tabIDs, [b, c]); XCTAssertEqual(review.entries[0].state, .connectionPending)
        let captured = review.entries
        let new = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        controller.moveTab(c, before: a); controller.renameTab(b, title: "renamed after review")
        builder.drivers[1].set(.authenticating); builder.drivers[2].set(.disconnected(nil))
        XCTAssertEqual(controller.currentActiveCount(in: review), 1)
        XCTAssertTrue(controller.currentBatchCloseStatus(b).contains("等待认证输入"))
        XCTAssertEqual(review.entries, captured); XCTAssertFalse(review.tabIDs.contains(new))
        await controller.closeTab(b)
        XCTAssertTrue(controller.currentBatchCloseStatus(b).contains("已关闭")); XCTAssertEqual(controller.currentActiveCount(in: review), 0)
        for id in review.tabIDs { await controller.closeTab(id) }
        XCTAssertEqual(controller.tabs.map(\.id), [a, new]); XCTAssertEqual(builder.drivers[3].connectCount, 1)
        XCTAssertNil(controller.batchCloseReview(scope: .sessionsToRight(new)))
        XCTAssertNil(controller.batchCloseReview(scope: .otherSessions(UUID())))
        await controller.closeAll(); try await repo.close()
    }

    func testWindowTabsBatchOwnerCancelStaleAndDoubleConfirmationFence() throws {
        let tabID = UUID(), entry = SessionBatchCloseReview.Entry(id: tabID, title: "synthetic", endpoint: "fixture@batch.invalid:22", state: .connected, status: "已连接")
        let first = SessionBatchCloseReview(scope: .otherSessions(UUID()), entries: [entry])
        let next = SessionBatchCloseReview(scope: .sessionsToRight(UUID()), entries: [entry])
        let owner = SessionBatchCloseOwner()
        owner.present(first); XCTAssertTrue(owner.cancel(first.id)); XCTAssertNil(owner.review)
        XCTAssertNil(owner.beginConfirmation(first.id)); XCTAssertFalse(owner.inFlight)
        owner.present(next); XCTAssertFalse(owner.cancel(first.id)); XCTAssertNil(owner.beginConfirmation(first.id))
        XCTAssertEqual(owner.beginConfirmation(next.id), [tabID]); XCTAssertTrue(owner.inFlight)
        XCTAssertNil(owner.beginConfirmation(next.id)); XCTAssertFalse(owner.cancel(next.id))
        owner.present(first); XCTAssertEqual(owner.review?.id, next.id)
        owner.finish(first.id); XCTAssertTrue(owner.inFlight)
        owner.finish(next.id); XCTAssertFalse(owner.inFlight); XCTAssertNil(owner.review)
    }

    func testWindowTabsRenameValidationAndClosedTargetNeverChangeSavedHost() async throws {
        let (repo, controller, _, _) = try fixture(), host = host()
        try await repo.apply([.insertHost(host)])
        let id = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        let tab = try XCTUnwrap(controller.selectedTab)
        for invalid in ["   ", String(repeating: "中", count: 86), "bad\nname"] { controller.renameTab(id, title: invalid); XCTAssertNil(tab.customTitle) }
        controller.renameTab(id, title: "  temporary  "); XCTAssertEqual(tab.customTitle, "temporary")
        await controller.closeTab(id)
        let replacement = try XCTUnwrap(controller.open(host, mode: .newSession)); await controller.selectedTab?.preparation?.value
        controller.renameTab(id, title: "stale target")
        XCTAssertEqual(controller.selectedTabID, replacement); XCTAssertNil(controller.selectedTab?.customTitle)
        let saved = try await repo.securityMetadata().hosts.first
        XCTAssertEqual(saved, host)
        await controller.closeAll(); try await repo.close()
    }
}

extension SessionControllerTests {
    func testDefaultFactoryPreparesTypedNativeForAllFourStoredMethodsUsingOneSharedBuilder() async throws {
        let (repository, _, _, directory) = try fixture(), credentials = FakeCredentials()
        let security = SecurityCoordinator(repository: repository, location: .isolated(directory), credentials: credentials)
        let app = AppModel(repository: repository, security: security, location: .isolated(directory), preferencesDefaults: nil)
        addTeardownBlock {
            await app.sessions.closeAll(); await app.files.closeForWindow()
            try await security.close(); try await repository.close()
        }
        let ordinary = try XCTUnwrap(app.sessionBuilders.ordinary as? NativeSessionBuilder)
        let prepared = try XCTUnwrap(app.sessionBuilders.prepared as? NativeSessionBuilder)
        XCTAssertTrue(ordinary === prepared); XCTAssertTrue(ordinary.environment === app.sessionEnvironment)
        XCTAssertTrue((ordinary.repository as? AppRepository) === repository); XCTAssertTrue(ordinary.security === security)
        // A new disposable key is generated by the existing KeyStore. Tests never read
        // or print its private bytes; prepare creates no SSH socket or authenticated run.
        let key = try await security.createKey(.generate, protection: .unencrypted, rememberPassphrase: nil)
        XCTAssertFalse(key.cleanupPending)
        let keyPath = try AbsolutePath(try await security.validatedPrivateKeyPath(key.id))
        let cases: [(AuthenticationKind, SSHAuthentication.Method)] = [
            (.password, .passwordOnly), (.passwordWithMFA, .passwordAndKeyboardInteractive),
            (.privateKey, .privateKey(keyPath, keyboardInteractive: false)),
            (.privateKeyWithMFA, .privateKey(keyPath, keyboardInteractive: true))
        ]
        for (method, expected) in cases {
            let host = HostConfiguration(name: "default typed factory", address: "never-connected.invalid", username: "fixture",
                                         authentication: method, keyRef: method.needsKey ? key.id : nil)
            try await repository.apply([.insertHost(host)])
            let ready = try await ordinary.prepare(hostID: host.id, sessionID: UUID())
            let driver = try XCTUnwrap(ready.driver as? NativeSessionDriver)
            XCTAssertEqual(ready.host, host); XCTAssertEqual(ready.configuration.authentication.method, expected)
            XCTAssertNil(driver.token)
            let closed = await driver.closeResult(deadline: .now + .seconds(1))
            XCTAssertEqual(closed, .closed)
        }
        XCTAssertTrue(app.sessions.tabs.isEmpty)
        let reads = await credentials.readCount, saves = await credentials.saveCount
        XCTAssertEqual(reads, 0); XCTAssertEqual(saves, 0)
    }

    func testDefaultPreparedPasswordUsesSameNativeFactoryAndCanCancelBeforeAnyConnection() async throws {
        let (repository, _, _, directory) = try fixture(), credentials = FakeCredentials(), host = host()
        let security = SecurityCoordinator(repository: repository, location: .isolated(directory), credentials: credentials)
        let app = AppModel(repository: repository, security: security, location: .isolated(directory), preferencesDefaults: nil)
        addTeardownBlock {
            await app.sessions.closeAll(); await app.files.closeForWindow()
            try await security.close(); try await repository.close()
        }
        try await repository.apply([.insertHost(host)])
        let loaded = await app.reload(); XCTAssertTrue(loaded)
        let ordinary = try XCTUnwrap(app.sessionBuilders.ordinary as? NativeSessionBuilder)
        let preparedBuilder = try XCTUnwrap(app.sessionBuilders.prepared as? NativeSessionBuilder)
        XCTAssertTrue(ordinary === preparedBuilder); XCTAssertTrue(preparedBuilder.environment === app.sessionEnvironment)
        let intent = VaultTransientConnectionIntent(host: host, secret: .init(utf8: UUID().uuidString))
        let prepared = try await app.prepareTransientConnection(host, intent: intent)
        XCTAssertTrue(app.sessions.tabs.isEmpty); XCTAssertNil(app.sessions.selectedTabID)
        XCTAssertEqual(app.workspacePage, .vault); XCTAssertNil(app.connectionNotice); XCTAssertFalse(intent.consumed)
        prepared.cancel()
        XCTAssertTrue(intent.consumed); XCTAssertTrue(app.sessions.tabs.isEmpty)
        XCTAssertThrowsError(try prepared.commit())
        let reads = await credentials.readCount, saves = await credentials.saveCount
        XCTAssertEqual(reads, 0); XCTAssertEqual(saves, 0)
    }
}

// Explicitly injected legacy-boundary coverage; it does not describe the production default.
// Real AppModel/controller/editor consumers deliberately receive distinct logical builders here.
// No socket, process, real credential store, visible window or private-key file is opened.
extension SessionControllerTests {
    private func entryRoutingFixture(authentication: AuthenticationKind = .password, savedPassword: Bool = false) async throws -> EntryRoutingFixture {
        let (repository, _, ordinary, directory) = try fixture(), credentials = FakeCredentials()
        let security = SecurityCoordinator(repository: repository, location: .isolated(directory), credentials: credentials)
        let candidate = LogicSessionBuilder(repository: repository)
        ordinary.syntheticKeyPath = entryRoutingSyntheticKeyPath; candidate.syntheticKeyPath = entryRoutingSyntheticKeyPath
        let key = ManagedKeyReference(algorithm: .ed25519), reference = UUID()
        let host = HostConfiguration(name: "entry routing", address: "never-connected.invalid", username: "Fixture",
            authentication: authentication, credentialRef: savedPassword ? reference : nil,
            keyRef: authentication.needsKey ? key.id : nil, savePasswordAuthorized: savedPassword)
        var changes: [RepositoryChange] = []
        if authentication.needsKey { changes.append(.registerKey(key)) }
        if savedPassword { changes.append(.registerCredential(.init(id: reference, purpose: .password, isSavingAuthorized: true))) }
        changes.append(.insertHost(host)); try await repository.apply(changes)
        let app = AppModel(repository: repository, security: security, location: .isolated(directory),
            sessionBuilder: ordinary, nativeCandidateBuilder: candidate, preferencesDefaults: nil)
        addTeardownBlock {
            await app.sessions.closeAll(); await app.files.closeForWindow()
            try await security.close(); try await repository.close()
        }
        let loaded = await app.reload(); XCTAssertTrue(loaded)
        return EntryRoutingFixture(host: host, repository: repository, credentials: credentials, app: app, ordinary: ordinary, candidate: candidate)
    }

    func testInjectedLegacyBoundaryOrdinaryRequestsPreserveAllFourStoredMethodConfigurations() async throws {
        let keyPath = try AbsolutePath(entryRoutingSyntheticKeyPath)
        let cases: [(AuthenticationKind, SSHAuthentication.Method)] = [
            (.password, .passwordOnly), (.passwordWithMFA, .passwordAndKeyboardInteractive),
            (.privateKey, .privateKey(keyPath, keyboardInteractive: false)),
            (.privateKeyWithMFA, .privateKey(keyPath, keyboardInteractive: true))
        ]
        for (method, expected) in cases {
            let f = try await entryRoutingFixture(authentication: method)
            f.app.requestSession(hostID: f.host.id, mode: .reuse)
            let first = try XCTUnwrap(f.app.sessions.selectedTab); await first.preparation?.value
            let driver = try XCTUnwrap(first.driver as? LogicSessionDriver), token = try XCTUnwrap(driver.token)
            XCTAssertTrue(first.builder === f.ordinary)
            XCTAssertEqual(driver.lastConfiguration?.authentication.method, expected)
            XCTAssertEqual(driver.typedConnectCount, 1)
            f.app.showWorkspace(.vault)
            f.app.requestSession(hostID: f.host.id, mode: .reuse)
            XCTAssertEqual(f.app.sessions.selectedTabID, first.id); XCTAssertEqual(driver.token, token)
            XCTAssertEqual(f.ordinary.preparedHostIDs, [f.host.id]); XCTAssertEqual(driver.connectCount, 1)
            f.app.showWorkspace(.vault)
            f.app.requestSession(hostID: f.host.id, mode: .newSession)
            let second = try XCTUnwrap(f.app.sessions.selectedTab); await second.preparation?.value
            let secondDriver = try XCTUnwrap(second.driver as? LogicSessionDriver)
            XCTAssertNotEqual(first.id, second.id); XCTAssertFalse(first.driver === second.driver)
            XCTAssertFalse(driver.terminal === secondDriver.terminal); XCTAssertNotEqual(token, secondDriver.token)
            XCTAssertTrue(second.builder === f.ordinary)
            XCTAssertEqual(secondDriver.lastConfiguration?.authentication.method, expected)
            f.app.showWorkspace(.vault); f.app.requestSession(hostID: f.host.id, mode: .reuse)
            XCTAssertEqual(f.app.sessions.selectedTabID, second.id, "List reuse selects the most recently active matching tab")
            f.app.showWorkspace(.session(first.id)); f.app.showWorkspace(.vault)
            f.app.requestSession(hostID: f.host.id, mode: .reuse)
            XCTAssertEqual(f.app.workspacePage, .session(first.id))
            XCTAssertEqual(f.app.connectionNotice, .opened(.init(hostID: f.host.id, mode: .reuse), first.id))
            XCTAssertEqual(f.ordinary.preparedHostIDs, [f.host.id, f.host.id])
            XCTAssertEqual(f.ordinary.drivers.map(\.connectCount), [1, 1])
            XCTAssertTrue(f.candidate.preparedHostIDs.isEmpty); XCTAssertTrue(f.candidate.configuredHostIDs.isEmpty)
            let reads = await f.credentials.readCount; XCTAssertEqual(reads, 0)
        }
    }

    func testInjectedLegacyBoundarySaveWithoutFreshPasswordDismissesThenUsesOrdinaryBuilderOnce() async throws {
        let cases: [(AuthenticationKind, Bool)] = [(.password, false), (.password, true), (.passwordWithMFA, true), (.privateKey, false), (.privateKeyWithMFA, false)]
        for (method, savedPassword) in cases {
            let f = try await entryRoutingFixture(authentication: method, savedPassword: savedPassword)
            let vault = VaultDesktopModel(app: f.app); _ = await vault.load()
            let owner = PresentationOwner<String>(); owner.present("no fresh secret editor")
            let ownerID = try XCTUnwrap(owner.item?.id)
            let editor = VaultHostEditorModel(draft: VaultHostDraft(host: f.host, settings: AppSettings()), ownsPresentation: { owner.owns(ownerID) })
            editor.draft.configuration.name = "saved without fresh input"
            XCTAssertFalse(editor.hasTransientInput)
            f.app.registerWorkspaceNavigationGuard(owner: ownerID) { owner.item == nil }
            f.app.requestSession(hostID: f.host.id, mode: .newSession)
            XCTAssertTrue(f.app.sessions.tabs.isEmpty)
            var dismisses = 0, routes = 0
            // Matches VaultHostEditor.save's no-fresh-input branch: no candidate preparation.
            let result = await editor.saveAndFinish(security: f.app.security, vault: vault,
                dismiss: { dismisses += 1; owner.dismiss(ownerID) }, afterDismiss: { saved in
                    routes += 1; XCTAssertFalse(editor.writing); XCTAssertNil(owner.item)
                    XCTAssertEqual(f.app.workspacePage, .vault); XCTAssertTrue(f.app.sessions.tabs.isEmpty)
                    XCTAssertEqual(f.app.connectionHosts.first?.name, saved.name)
                    f.app.requestSession(hostID: saved.id, mode: .newSession)
                })
            XCTAssertTrue(result); XCTAssertEqual(dismisses, 1); XCTAssertEqual(routes, 1)
            let tab = try XCTUnwrap(f.app.sessions.selectedTab); await tab.preparation?.value
            XCTAssertTrue(tab.builder === f.ordinary); XCTAssertTrue(tab.driver === f.ordinary.drivers.first)
            XCTAssertEqual(tab.host?.name, "saved without fresh input")
            XCTAssertEqual(tab.host?.authentication, method); XCTAssertEqual(tab.host?.keyRef, f.host.keyRef)
            XCTAssertEqual(tab.host?.credentialRef, f.host.credentialRef); XCTAssertEqual(tab.host?.savePasswordAuthorized, savedPassword)
            XCTAssertEqual(f.app.workspacePage, .session(tab.id))
            let duplicate = await editor.saveAndFinish(security: f.app.security, vault: vault,
                dismiss: { dismisses += 1 }, afterDismiss: { _ in routes += 1 })
            XCTAssertFalse(duplicate); XCTAssertEqual(dismisses, 1); XCTAssertEqual(routes, 1)
            XCTAssertEqual(f.ordinary.preparedHostIDs, [f.host.id]); XCTAssertEqual(f.ordinary.drivers.first?.connectCount, 1)
            XCTAssertTrue(f.candidate.preparedHostIDs.isEmpty); XCTAssertTrue(f.candidate.configuredHostIDs.isEmpty)
            let reads = await f.credentials.readCount, saves = await f.credentials.saveCount
            XCTAssertEqual(reads, 0); XCTAssertEqual(saves, 0)
        }
    }

    func testInjectedLegacyBoundaryFreshPasswordPreparesTypedBuilderAndCommitsAfterDismissOnce() async throws {
        let f = try await entryRoutingFixture(), vault = VaultDesktopModel(app: f.app); _ = await vault.load()
        let owner = PresentationOwner<String>(); owner.present("fresh password editor")
        let ownerID = try XCTUnwrap(owner.item?.id)
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: f.host, settings: AppSettings()), ownsPresentation: { owner.owns(ownerID) })
        let input = UUID().uuidString; editor.password = input
        f.app.registerWorkspaceNavigationGuard(owner: ownerID) { owner.item == nil }
        var prepared: VaultPreparedConnection?, intent: VaultTransientConnectionIntent?, dismisses = 0
        let result = await editor.saveAndFinish(security: f.app.security, vault: vault, prepareConnection: { saved, material in
            XCTAssertTrue(editor.writing); XCTAssertTrue(owner.owns(ownerID))
            let nextIntent = VaultTransientConnectionIntent(host: saved, secret: try XCTUnwrap(material)); intent = nextIntent
            let next = try await f.app.prepareTransientConnection(saved, intent: nextIntent); prepared = next
            XCTAssertTrue(f.app.sessions.tabs.isEmpty); XCTAssertNil(f.app.sessions.selectedTabID)
            XCTAssertEqual(f.app.workspacePage, .vault); XCTAssertNil(f.app.connectionNotice)
            XCTAssertEqual(f.candidate.preparedHostIDs, [saved.id]); XCTAssertEqual(f.candidate.drivers.first?.connectCount, 0)
            XCTAssertTrue(f.ordinary.preparedHostIDs.isEmpty); XCTAssertFalse(nextIntent.consumed)
            return next
        }, dismiss: {
            dismisses += 1; XCTAssertFalse(editor.writing); XCTAssertTrue(f.app.sessions.tabs.isEmpty)
            XCTAssertEqual(f.app.workspacePage, .vault); XCTAssertEqual(f.candidate.drivers.first?.connectCount, 0)
            owner.dismiss(ownerID)
        })
        XCTAssertTrue(result); XCTAssertEqual(dismisses, 1); XCTAssertNil(owner.item); XCTAssertTrue(editor.password.isEmpty)
        let preparedOwner = try XCTUnwrap(prepared), pendingIntent = try XCTUnwrap(intent)
        let tab = try XCTUnwrap(f.app.sessions.selectedTab), driver = try XCTUnwrap(tab.driver as? LogicSessionDriver)
        XCTAssertTrue(tab.builder === f.candidate); XCTAssertEqual(driver.typedConnectCount, 1)
        XCTAssertEqual(f.app.workspacePage, .session(tab.id)); XCTAssertEqual(f.app.sessions.tabs.count, 1)
        XCTAssertEqual(f.app.connectionNotice, .opened(.init(hostID: f.host.id, mode: .newSession), tab.id))
        XCTAssertFalse(pendingIntent.consumed, "Commit binds the intent; only the exact typed primary request consumes it")
        XCTAssertThrowsError(try preparedOwner.commit()); XCTAssertEqual(driver.connectCount, 1)
        let authorization = try XCTUnwrap(driver.primaryAuthorization)
        let request = SessionPrimaryRequest(token: try XCTUnwrap(driver.token), id: UUID(), nativeSessionID: UUID(), purpose: .password, key: nil)
        let material = try await authorization.acquire(request)
        XCTAssertTrue(try XCTUnwrap(material).secret.matches(.init(utf8: input))); XCTAssertNil(material?.credential)
        XCTAssertTrue(pendingIntent.consumed)
        do { _ = try await authorization.acquire(request); XCTFail("The initial primary material is single-use") } catch {}
        let duplicate = await editor.saveAndFinish(security: f.app.security, vault: vault,
            dismiss: { dismisses += 1 }, afterDismiss: { _ in XCTFail("Dismissed editor routed twice") })
        XCTAssertFalse(duplicate); XCTAssertEqual(dismisses, 1)
        f.app.showWorkspace(.vault); f.app.requestSession(hostID: f.host.id, mode: .reuse)
        XCTAssertEqual(f.app.sessions.selectedTabID, tab.id); XCTAssertEqual(driver.connectCount, 1)
        XCTAssertTrue(f.ordinary.preparedHostIDs.isEmpty, "Reuse preserves the existing candidate owner; it does not reselect a backend")
        f.app.showWorkspace(.vault); f.app.requestSession(hostID: f.host.id, mode: .newSession)
        let ordinaryTab = try XCTUnwrap(f.app.sessions.selectedTab); await ordinaryTab.preparation?.value
        XCTAssertNotEqual(ordinaryTab.id, tab.id); XCTAssertTrue(ordinaryTab.builder === f.ordinary)
        XCTAssertEqual(f.ordinary.drivers.first?.typedConnectCount, 1); XCTAssertEqual(f.candidate.drivers.count, 1)
        XCTAssertEqual(driver.connectCount, 1)
        let reads = await f.credentials.readCount, saves = await f.credentials.saveCount
        XCTAssertEqual(reads, 0); XCTAssertEqual(saves, 0)
    }

    func testInjectedLegacyBoundaryCancelledIntentCannotReachManualReconnectGeneration() async throws {
        let f = try await entryRoutingFixture()
        let intent = VaultTransientConnectionIntent(host: f.host, secret: .init(utf8: UUID().uuidString))
        let prepared = try await f.app.prepareTransientConnection(f.host, intent: intent)
        try prepared.commit()
        let tab = try XCTUnwrap(f.app.sessions.selectedTab), driver = try XCTUnwrap(tab.driver as? LogicSessionDriver)
        let firstToken = try XCTUnwrap(driver.token), terminal = driver.terminal
        let oldAuthorization = try XCTUnwrap(driver.primaryAuthorization)
        let oldRequest = SessionPrimaryRequest(token: firstToken, id: UUID(), nativeSessionID: UUID(), purpose: .password, key: nil)
        XCTAssertFalse(intent.consumed); XCTAssertEqual(driver.connectCount, 1)
        f.app.sessions.disconnect(tab.id)
        XCTAssertTrue(intent.consumed); XCTAssertTrue(tab.canReconnect); XCTAssertEqual(driver.state, .disconnected(nil))
        do { _ = try await oldAuthorization.acquire(oldRequest); XCTFail("Cancelled generation retained its primary authorization") } catch {}
        XCTAssertEqual(driver.connectCount, 1, "Cancellation never automatically reconnects")
        f.app.sessions.reconnect(tab.id); await tab.preparation?.value
        let nextToken = try XCTUnwrap(driver.token), nextAuthorization = try XCTUnwrap(driver.primaryAuthorization)
        XCTAssertEqual(nextToken.sessionID, firstToken.sessionID); XCTAssertEqual(nextToken.generation, firstToken.generation + 1)
        XCTAssertTrue(tab.driver === driver); XCTAssertTrue(driver.terminal === terminal); XCTAssertTrue(tab.builder === f.candidate)
        XCTAssertFalse(nextAuthorization === oldAuthorization); XCTAssertEqual(driver.typedConnectCount, 2)
        XCTAssertEqual(f.candidate.preparedHostIDs, [f.host.id]); XCTAssertEqual(f.candidate.configuredHostIDs, [f.host.id, f.host.id])
        XCTAssertTrue(f.ordinary.preparedHostIDs.isEmpty); XCTAssertTrue(f.ordinary.configuredHostIDs.isEmpty)
        let request = SessionPrimaryRequest(token: nextToken, id: UUID(), nativeSessionID: UUID(), purpose: .password, key: nil)
        let material = try await nextAuthorization.acquire(request)
        XCTAssertNil(material, "An unsaved once password is not material for a manually reconnected generation")
        XCTAssertEqual(tab.primaryRequestID, request.id)
        do { _ = try await oldAuthorization.acquire(oldRequest); XCTFail("Old generation revived after manual reconnect") } catch {}
        XCTAssertThrowsError(try intent.bind(to: nextToken, host: f.host)); XCTAssertThrowsError(try prepared.commit())
        XCTAssertEqual(f.app.sessions.tabs.map(\.id), [tab.id]); XCTAssertEqual(f.app.workspacePage, .session(tab.id))
        let reads = await f.credentials.readCount, saves = await f.credentials.saveCount
        XCTAssertEqual(reads, 0); XCTAssertEqual(saves, 0)
    }

    func testSplitCurrentSessionHorizontalAndVerticalCreatesPairedSecondTab() async throws {
        let (repo, _, builder, directory) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let model = AppModel(repository: repo, location: .isolated(directory), sessionBuilder: builder)
        _ = await model.reload()
        XCTAssertNil(model.sessions.splitCurrentSession(axis: .horizontal))

        model.requestSession(hostID: host.id, mode: .newSession)
        let first = try XCTUnwrap(model.sessions.selectedTab)
        await first.preparation?.value
        let firstTerminal = try XCTUnwrap(first.driver?.terminal)
        firstTerminal.feed(text: "SPLIT-PRIMARY-KEEP\r\n")

        let second = try XCTUnwrap(model.sessions.splitCurrentSession(axis: .horizontal))
        await second.preparation?.value
        let secondTerminal = try XCTUnwrap(second.driver?.terminal)
        XCTAssertNotEqual(first.id, second.id)
        XCTAssertEqual(model.sessions.tabs.map(\.id), [first.id, second.id])
        XCTAssertEqual(model.sessions.selectedTabID, second.id)
        XCTAssertEqual(model.workspacePage, .session(second.id))
        XCTAssertEqual(model.sessions.activeSplit, TerminalSplitState(primaryTabID: first.id, secondaryTabID: second.id, axis: .horizontal))
        XCTAssertTrue(model.sessions.isSplitActive)
        XCTAssertNotNil(second.terminalFocusRequest)
        XCTAssertFalse(firstTerminal.isHidden)
        XCTAssertFalse(secondTerminal.isHidden)
        XCTAssertTrue(first.driver?.terminal === firstTerminal)
        XCTAssertTrue(firstTerminal.text.contains("SPLIT-PRIMARY-KEEP"))

        let third = try XCTUnwrap(model.sessions.splitCurrentSession(axis: .vertical))
        await third.preparation?.value
        let thirdTerminal = try XCTUnwrap(third.driver?.terminal)
        XCTAssertEqual(model.sessions.tabs.map(\.id), [first.id, second.id, third.id])
        XCTAssertEqual(model.sessions.selectedTabID, third.id)
        XCTAssertEqual(model.workspacePage, .session(third.id))
        XCTAssertEqual(model.sessions.activeSplit, TerminalSplitState(primaryTabID: second.id, secondaryTabID: third.id, axis: .vertical))
        XCTAssertTrue(firstTerminal.isHidden)
        XCTAssertFalse(secondTerminal.isHidden)
        XCTAssertFalse(thirdTerminal.isHidden)
        XCTAssertEqual(builder.drivers.count, 3)

        await model.sessions.closeAll(); await model.files.closeForWindow(); try await repo.close()
    }

    func testSplitWithExistingTabFocusesSecondaryToggleSwapAndUnsplitKeepBothTabs() async throws {
        let (repo, _, builder, directory) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let model = AppModel(repository: repo, location: .isolated(directory), sessionBuilder: builder)
        _ = await model.reload()
        model.requestSession(hostID: host.id, mode: .newSession)
        let first = try XCTUnwrap(model.sessions.selectedTab); await first.preparation?.value
        model.requestSession(hostID: host.id, mode: .newSession)
        let second = try XCTUnwrap(model.sessions.selectedTab); await second.preparation?.value
        let firstTerminal = try XCTUnwrap(first.driver?.terminal)
        let secondTerminal = try XCTUnwrap(second.driver?.terminal)
        firstTerminal.feed(text: "PANE-ONE\r\n")
        secondTerminal.feed(text: "PANE-TWO\r\n")

        model.showWorkspace(.session(first.id))
        model.sessions.splitWithTab(first.id, axis: .horizontal)
        XCTAssertNil(model.sessions.split, "Splitting a tab with itself must be a no-op")
        model.sessions.splitWithTab(UUID(), axis: .horizontal)
        XCTAssertNil(model.sessions.split, "Splitting with a missing tab must be a no-op")

        model.sessions.splitWithTab(second.id, axis: .horizontal)
        XCTAssertEqual(model.sessions.activeSplit, TerminalSplitState(primaryTabID: first.id, secondaryTabID: second.id, axis: .horizontal))
        XCTAssertEqual(model.sessions.selectedTabID, second.id)
        XCTAssertEqual(model.workspacePage, .session(second.id))
        XCTAssertNotNil(second.terminalFocusRequest)
        XCTAssertFalse(firstTerminal.isHidden)
        XCTAssertFalse(secondTerminal.isHidden)

        model.sessions.toggleSplitAxis()
        XCTAssertEqual(model.sessions.activeSplit?.axis, .vertical)
        model.sessions.toggleSplitAxis()
        XCTAssertEqual(model.sessions.activeSplit?.axis, .horizontal)

        model.sessions.swapSplitPanes()
        XCTAssertEqual(model.sessions.activeSplit, TerminalSplitState(primaryTabID: second.id, secondaryTabID: first.id, axis: .horizontal))
        XCTAssertEqual(model.sessions.selectedTabID, second.id)

        let previousFirstFocus = first.terminalFocusRequest
        model.sessions.focusOtherSplitPane()
        XCTAssertEqual(model.sessions.selectedTabID, first.id)
        XCTAssertEqual(model.workspacePage, .session(first.id))
        XCTAssertNotEqual(first.terminalFocusRequest, previousFirstFocus)
        XCTAssertNotNil(first.terminalFocusRequest)

        model.sessions.unsplit()
        XCTAssertNil(model.sessions.split)
        XCTAssertNil(model.sessions.activeSplit)
        XCTAssertFalse(model.sessions.isSplitActive)
        XCTAssertEqual(model.sessions.tabs.map(\.id), [first.id, second.id])
        XCTAssertEqual(model.sessions.selectedTabID, first.id)
        XCTAssertEqual(model.workspacePage, .session(first.id))
        XCTAssertFalse(firstTerminal.isHidden)
        XCTAssertTrue(secondTerminal.isHidden)
        XCTAssertTrue(first.driver?.terminal === firstTerminal)
        XCTAssertTrue(second.driver?.terminal === secondTerminal)
        XCTAssertTrue(firstTerminal.text.contains("PANE-ONE"))
        XCTAssertTrue(secondTerminal.text.contains("PANE-TWO"))
        XCTAssertTrue(builder.drivers.allSatisfy { $0.connectCount == 1 })

        await model.sessions.closeAll(); await model.files.closeForWindow(); try await repo.close()
    }

    func testClosingSplitTabClearsSplitAndSelectsSurvivingPane() async throws {
        let (repo, _, builder, directory) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let model = AppModel(repository: repo, location: .isolated(directory), sessionBuilder: builder)
        _ = await model.reload()
        model.requestSession(hostID: host.id, mode: .newSession)
        let first = try XCTUnwrap(model.sessions.selectedTab); await first.preparation?.value
        model.requestSession(hostID: host.id, mode: .newSession)
        let middle = try XCTUnwrap(model.sessions.selectedTab); await middle.preparation?.value
        model.requestSession(hostID: host.id, mode: .newSession)
        let last = try XCTUnwrap(model.sessions.selectedTab); await last.preparation?.value

        // Pair first and last (non-adjacent) so closing last must select first, not middle.
        model.showWorkspace(.session(first.id))
        model.sessions.splitWithTab(last.id, axis: .horizontal)
        XCTAssertEqual(model.sessions.selectedTabID, last.id)
        XCTAssertTrue(model.sessions.isSplitActive)

        await model.sessions.closeTab(last.id)
        XCTAssertNil(model.sessions.split)
        XCTAssertFalse(model.sessions.isSplitActive)
        XCTAssertEqual(model.sessions.selectedTabID, first.id)
        XCTAssertEqual(model.workspacePage, .session(first.id))
        XCTAssertFalse(try XCTUnwrap(first.driver?.terminal.isHidden))
        XCTAssertTrue(try XCTUnwrap(middle.driver?.terminal.isHidden))

        // Pair first and middle, then close the unfocused pane (first); middle stays selected and split clears.
        model.sessions.splitWithTab(middle.id, axis: .vertical)
        XCTAssertEqual(model.sessions.selectedTabID, middle.id)
        await model.sessions.closeTab(first.id)
        XCTAssertNil(model.sessions.split)
        XCTAssertEqual(model.sessions.selectedTabID, middle.id)
        XCTAssertEqual(model.workspacePage, .session(middle.id))
        XCTAssertFalse(try XCTUnwrap(middle.driver?.terminal.isHidden))

        await model.sessions.closeAll(); await model.files.closeForWindow(); try await repo.close()
    }

    func testSelectingThirdTabTemporarilyHidesSplitAndReturningRestoresIt() async throws {
        let (repo, _, builder, directory) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let model = AppModel(repository: repo, location: .isolated(directory), sessionBuilder: builder)
        _ = await model.reload()
        model.requestSession(hostID: host.id, mode: .newSession)
        let first = try XCTUnwrap(model.sessions.selectedTab); await first.preparation?.value
        model.requestSession(hostID: host.id, mode: .newSession)
        let second = try XCTUnwrap(model.sessions.selectedTab); await second.preparation?.value
        model.requestSession(hostID: host.id, mode: .newSession)
        let third = try XCTUnwrap(model.sessions.selectedTab); await third.preparation?.value
        let firstTerminal = try XCTUnwrap(first.driver?.terminal)
        let secondTerminal = try XCTUnwrap(second.driver?.terminal)
        let thirdTerminal = try XCTUnwrap(third.driver?.terminal)

        model.showWorkspace(.session(first.id))
        model.sessions.splitWithTab(second.id, axis: .horizontal)
        XCTAssertTrue(model.sessions.isSplitActive)
        XCTAssertFalse(firstTerminal.isHidden)
        XCTAssertFalse(secondTerminal.isHidden)
        XCTAssertTrue(thirdTerminal.isHidden)

        // Switching to the third tab temporarily hides the split while retaining the pairing.
        model.showWorkspace(.session(third.id))
        XCTAssertNotNil(model.sessions.split)
        XCTAssertNil(model.sessions.activeSplit)
        XCTAssertFalse(model.sessions.isSplitActive)
        XCTAssertTrue(firstTerminal.isHidden)
        XCTAssertTrue(secondTerminal.isHidden)
        XCTAssertFalse(thirdTerminal.isHidden)

        // Returning to either paired tab restores the split view and shows both panes again.
        model.showWorkspace(.session(first.id))
        XCTAssertEqual(model.sessions.activeSplit, TerminalSplitState(primaryTabID: first.id, secondaryTabID: second.id, axis: .horizontal))
        XCTAssertTrue(model.sessions.isSplitActive)
        XCTAssertFalse(firstTerminal.isHidden)
        XCTAssertFalse(secondTerminal.isHidden)
        XCTAssertTrue(thirdTerminal.isHidden)

        await model.sessions.closeAll(); await model.files.closeForWindow(); try await repo.close()
    }

    func testCloseAllClearsSplitState() async throws {
        let (repo, controller, builder, _) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let firstID = try XCTUnwrap(controller.open(host, mode: .newSession))
        await controller.selectedTab?.preparation?.value
        let second = try XCTUnwrap(controller.splitCurrentSession(axis: .horizontal))
        await second.preparation?.value
        XCTAssertEqual(controller.activeSplit, TerminalSplitState(primaryTabID: firstID, secondaryTabID: second.id, axis: .horizontal))
        XCTAssertEqual(builder.drivers.count, 2)

        await controller.closeAll()
        XCTAssertNil(controller.split)
        XCTAssertNil(controller.activeSplit)
        XCTAssertFalse(controller.isSplitActive)
        XCTAssertTrue(controller.tabs.isEmpty)
        XCTAssertNil(controller.selectedTabID)
        try await repo.close()
    }

    func testSplitPaneLiveWindowReparentsRetainedTerminalsWithoutRecreation() async throws {
        _ = NSApplication.shared
        let (repo, _, builder, directory) = try fixture(); let host = host()
        try await repo.apply([.insertHost(host)])
        let suite = "OpenLXSSH.SplitPaneLive.Tests." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = AppModel(repository: repo, location: .isolated(directory), sessionBuilder: builder, preferencesDefaults: defaults)
        _ = await model.reload()

        let window = NSWindow(contentRect: NSRect(x: -5000, y: -5000, width: 1120, height: 720),
                              styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: MainView(model: model))
        window.orderFront(nil)
        defer { window.orderOut(nil); window.contentView = nil }

        func settleUntil(_ label: String, _ condition: () -> Bool) async throws {
            let deadline = ContinuousClock.now + .seconds(3)
            while ContinuousClock.now < deadline {
                window.contentView?.layoutSubtreeIfNeeded()
                if condition() { return }
                try await Task.sleep(for: .milliseconds(15))
            }
            window.contentView?.layoutSubtreeIfNeeded()
            XCTAssertTrue(condition(), "Timed out at \(label)")
        }

        model.requestSession(hostID: host.id, mode: .newSession)
        let first = try XCTUnwrap(model.sessions.selectedTab)
        await first.preparation?.value
        let firstTerminal = try XCTUnwrap(first.driver?.terminal)
        firstTerminal.feed(text: "LIVE-SPLIT-A\r\n")
        try await settleUntil("initial single pane (w=\(firstTerminal.window === window), hid=\(firstTerminal.isHiddenOrHasHiddenAncestor), frame=\(firstTerminal.frame))") {
            firstTerminal.window === window && !firstTerminal.isHiddenOrHasHiddenAncestor && firstTerminal.frame.width > 400
        }

        // Enter horizontal split (HSplitView)
        let second = try XCTUnwrap(model.sessions.splitCurrentSession(axis: .horizontal))
        await second.preparation?.value
        let secondTerminal = try XCTUnwrap(second.driver?.terminal)
        secondTerminal.feed(text: "LIVE-SPLIT-B\r\n")
        try await settleUntil("horizontal split") {
            firstTerminal.window === window && secondTerminal.window === window
                && !firstTerminal.isHiddenOrHasHiddenAncestor && !secondTerminal.isHiddenOrHasHiddenAncestor
                && firstTerminal.frame.width >= 200 && secondTerminal.frame.width >= 200
                && firstTerminal.frame.height >= 120 && secondTerminal.frame.height >= 120
        }
        XCTAssertTrue(first.driver?.terminal === firstTerminal)
        XCTAssertTrue(second.driver?.terminal === secondTerminal)
        XCTAssertTrue(firstTerminal.text.contains("LIVE-SPLIT-A"))
        XCTAssertTrue(secondTerminal.text.contains("LIVE-SPLIT-B"))

        // Toggle to vertical split (VSplitView)
        model.sessions.toggleSplitAxis()
        try await settleUntil("vertical split") {
            firstTerminal.window === window && secondTerminal.window === window
                && !firstTerminal.isHiddenOrHasHiddenAncestor && !secondTerminal.isHiddenOrHasHiddenAncestor
                && firstTerminal.frame.width >= 400 && secondTerminal.frame.width >= 400
                && firstTerminal.frame.height >= 100 && secondTerminal.frame.height >= 100
        }

        // Swap panes & focus other pane
        model.sessions.swapSplitPanes()
        model.sessions.focusOtherSplitPane()
        XCTAssertEqual(model.sessions.selectedTabID, first.id)
        XCTAssertEqual(model.workspacePage, .session(first.id))
        try await settleUntil("swap+focus") {
            firstTerminal.window === window && secondTerminal.window === window
                && !firstTerminal.isHiddenOrHasHiddenAncestor && !secondTerminal.isHiddenOrHasHiddenAncestor
        }

        // Unsplit back to single-tab NativeWorkspacePage
        model.sessions.unsplit()
        try await settleUntil("unsplit") {
            firstTerminal.window === window && !firstTerminal.isHiddenOrHasHiddenAncestor
                && firstTerminal.frame.width > 600 && secondTerminal.isHiddenOrHasHiddenAncestor
        }
        XCTAssertTrue(first.driver?.terminal === firstTerminal)
        XCTAssertTrue(second.driver?.terminal === secondTerminal)
        XCTAssertTrue(firstTerminal.text.contains("LIVE-SPLIT-A"))
        XCTAssertTrue(secondTerminal.text.contains("LIVE-SPLIT-B"))
        XCTAssertEqual(builder.drivers.count, 2)

        await model.sessions.closeAll(); await model.files.closeForWindow(); try await repo.close()
    }
}

private let entryRoutingSyntheticKeyPath = "/private/entry-routing-contract/key-not-opened.openssh"
@MainActor private struct EntryRoutingFixture {
    let host: HostConfiguration
    let repository: AppRepository
    let credentials: FakeCredentials
    let app: AppModel
    let ordinary: LogicSessionBuilder
    let candidate: LogicSessionBuilder
}

/// These test drivers are logical substitutes, not SSH protocol or process tests.
@MainActor private final class LogicSessionBuilder: SessionBuilding {
    let repository: any AppRepositoryProtocol
    var drivers: [LogicSessionDriver] = []
    var delay = false
    var fail = false
    var syntheticKeyPath: String?
    private(set) var preparedHostIDs: [UUID] = []
    private(set) var configuredHostIDs: [UUID] = []
    init(repository: any AppRepositoryProtocol) { self.repository = repository }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        configuredHostIDs.append(hostID)
        guard let host = try await repository.securityMetadata().hosts.first(where: { $0.id == hostID }) else { throw RepositoryError.notFound }
        return (host, try SessionEnvironment.configuration(host: host, keyPath: syntheticKeyPath))
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        preparedHostIDs.append(hostID)
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
    private(set) var typedConnectCount = 0
    private(set) var primaryAuthorization: SessionPrimaryAuthorization?
    var holdClose = false
    var closeCount = 0
    var lastConfiguration: SSHSessionConfiguration?
    init(id: UUID) { self.id = id }
    func set(_ next: SSHSessionState) { state = next; onState?(token, next) }
    func connect(_ configuration: SSHSessionConfiguration, primary: SessionPrimaryAuthorization) throws -> SessionToken {
        primaryAuthorization = primary; typedConnectCount += 1
        return beginConnection(configuration)
    }
    private func beginConnection(_ configuration: SSHSessionConfiguration) -> SessionToken {
        lastConfiguration = configuration
        connectCount += 1; token = SessionToken(sessionID: id, generation: UInt64(connectCount)); set(.connectionPending); return token!
    }
    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) async throws { set(.connectionPending) }
    func respond(_ answer: SessionAuthenticationAnswer, to prompt: SessionAuthenticationPrompt) throws { responseCount += 1; set(.connectionPending) }
    func cancel() { set(.disconnected(nil)) }
    func closeTab() {
        closeCount += 1
        if holdClose { set(.closing) } else { finishClose() }
    }
    func finishClose() { holdClose = false; set(.closed); terminal.releaseResources() }
}
@MainActor private final class ControlledFilesLifecycle: FilesWindowLifecycle {
    var hasActiveTransfers = false
    var hasPendingOperations = true
    var closeCount = 0
    var freezeCount = 0, beginCloseCount = 0
    private var continuation: CheckedContinuation<Void, Never>?
    private var arrived: CheckedContinuation<Void, Never>?
    func freezeTransferAdmission() { freezeCount += 1 }
    func beginWindowClose() { beginCloseCount += 1 }
    func beginTermination() {}
    func closeForWindow() async {
        closeCount += 1
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            arrived?.resume(); arrived = nil
        }
        hasPendingOperations = false
    }
    func waitForClose() async { if continuation == nil { await withCheckedContinuation { arrived = $0 } } }
    func releaseClose() { continuation?.resume(); continuation = nil }
}

@MainActor private final class LogicTransfers: TransferLifecycle {
    var hasActiveTransfers = true
    var cancelCount = 0
    func cancelAllAndWait() async { cancelCount += 1; hasActiveTransfers = false }
}

private struct LocalNetworkFailureConnector: NativeSessionConnecting {
    let error: FileServiceError
    func connect(_ request: NativeSessionConnect) async throws -> any NativeSessionTransport {
        throw NativeSessionConnectionFailure(failure: error, drain: nil, noNativeOwnerCreated: true)
    }
}
