import AppKit
import Foundation
import SwiftUI
import Combine
import XCTest
import Darwin
import OpenLXSSHCore
@testable import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust

/// These tests exercise real App driver/controller/editor consumers with a virtual
/// transport boundary and fake credentials. They are NOT real SSH/shell/Keychain gates.
@MainActor final class NativeSessionAdapterTests: XCTestCase {
    private func fixture(saved: Bool = false) throws -> AdapterFixture {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let reference = UUID()
        let host = HostConfiguration(name: "native logical boundary", address: "never-connected.invalid", username: "fixture",
            credentialRef: saved ? reference : nil, savePasswordAuthorized: saved)
        let repository = AdapterRepository(hosts: [host], credentials: saved ? [.init(id: reference, purpose: .password, isSavingAuthorized: true)] : [])
        let credentials = AdapterCredentials()
        let security = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        let connector = AdapterConnector()
        let builder = NativeSessionBuilder(repository: repository, security: security,
            environment: SessionEnvironment(location: .isolated(root)), connector: connector)
        let controller = SessionController(repository: repository, credentials: credentials, builder: builder)
        addTeardownBlock {
            await repository.markConnectedGate.release()
            await repository.metadataGate.release(); await repository.snapshotGate.release(); await credentials.gate.release(); await connector.cancelAll()
            await controller.closeAll(); try await security.close(); try FileManager.default.removeItem(at: root)
        }
        return AdapterFixture(host: host, repository: repository, credentials: credentials, security: security,
            connector: connector, builder: builder, controller: controller)
    }
    private func opened(_ f: AdapterFixture) async throws -> (SessionTab, NativeSessionDriver, NativeSessionConnect, Int) {
        let before = await f.connector.count
        _ = try XCTUnwrap(f.controller.open(f.host, mode: .newSession))
        let tab = try XCTUnwrap(f.controller.selectedTab); await tab.preparation?.value
        let request = try await f.connector.request(before)
        return (tab, try XCTUnwrap(tab.driver as? NativeSessionDriver), request, before)
    }
    private func primary(_ request: NativeSessionConnect, id: UUID = UUID(), nativeID: UUID = UUID()) -> NativeSessionPrimaryRequest {
        NativeSessionPrimaryRequest(sessionID: nativeID, requestID: id, method: request.method, token: request.token)
    }
    private func challenge(_ count: Int) -> FilesKeyboardChallenge {
        FilesKeyboardChallenge(name: Data("untrusted\u{1B}[31m".utf8), instruction: Data("manual only".utf8),
            prompts: (0..<count).map { (Data("field-\($0)".utf8), $0 % 2 == 0) })
    }
    private func nextPrompt(_ tab: SessionTab) async throws -> SessionAuthenticationPrompt {
        let deadline = ContinuousClock.now + .seconds(3)
        while tab.authentication == nil {
            guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
        return try XCTUnwrap(tab.authentication)
    }
    private func nextState(_ driver: NativeSessionDriver, _ expected: SSHSessionState) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while driver.state != expected {
            guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    private func wait(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while !condition() {
            guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    func testTCPKeepalivePolicyMapsEveryLegacyHostValueWithoutClamping() throws {
        let host = HostConfiguration(name: "liveness mapping", address: "never-connected.invalid", username: "fixture")
        let base = try SessionEnvironment.configuration(host: host, keyPath: nil)
        var checked = 0
        for interval in 0...3600 {
            for count in 1...10 {
                let configuration = try SSHSessionConfiguration(connection: base.connection,
                    serverAliveInterval: interval, serverAliveCountMax: count)
                let policy = try NativeSessionDriver.makeKeepalivePolicy(configuration)
                if interval == 0 { XCTAssertNil(policy) }
                else {
                    let mapped = try XCTUnwrap(policy)
                    XCTAssertEqual(mapped.interval, interval)
                    XCTAssertEqual(mapped.failedProbes, count)
                }
                checked += 1
            }
        }
        XCTAssertEqual(checked, 36010)
    }
    func testTCPKeepaliveConnectorCapturesDisabledDefaultAndMaximumOptions() async throws {
        for (interval, count) in [(0, 10), (30, 3), (3600, 10)] {
            let f = try fixture()
            var host = f.host; host.keepaliveInterval = interval; host.keepaliveCountMax = count
            try await f.repository.apply([.updateHost(host)])
            _ = try XCTUnwrap(f.controller.open(host, mode: .newSession))
            let tab = try XCTUnwrap(f.controller.selectedTab); await tab.preparation?.value
            let driver = try XCTUnwrap(tab.driver as? NativeSessionDriver)
            let request = try await f.connector.request(0)
            XCTAssertEqual(request.options.operationTimeout, 10); XCTAssertEqual(request.options.interactionTimeout, 120)
            XCTAssertEqual(request.options.authenticationTimeout, 300)
            if interval == 0 { XCTAssertNil(request.options.keepalive) }
            else {
                let policy = try XCTUnwrap(request.options.keepalive)
                XCTAssertEqual(policy.interval, interval); XCTAssertEqual(policy.failedProbes, count)
            }
            let reads = await f.credentials.readCount; XCTAssertEqual(reads, 0)
            driver.cancel(); await f.connector.fail(0); await driver.waitForCleanup()
            XCTAssertTrue(driver.snapshot.nativeCloseCompleted); XCTAssertTrue(driver.snapshot.interactionsDrained)
            XCTAssertEqual(driver.snapshot.pendingInputBytes, 0)
            await f.controller.closeAll()
        }
    }
    func testActualAuthenticationViewHasBoundedHeightForPrimaryManyPromptsAndZero() async throws {
        let f = try fixture(), tab = SessionTab(host: f.host), token = SessionToken(sessionID: tab.id, generation: 1)
        let payloads: [SessionAuthenticationPayload] = [.initialPassword,
            .keyboard(name: "32 fields", instruction: "manual", prompts: (0..<32).map { SessionKeyboardField(text: "Field \($0)", echo: $0 % 2 == 0) }),
            .keyboard(name: "notice", instruction: "continue or cancel", prompts: [])]
        for payload in payloads {
            let prompt = SessionAuthenticationPrompt(token: token, id: UUID(), payload: payload)
            let hosting = NSHostingController(rootView: AuthenticationChallengeView(tab: tab, controller: f.controller, prompt: prompt, dismiss: {}))
            let size = hosting.view.fittingSize
            print("ActualAuthenticationView fitting width=\(size.width) height=\(size.height)")
            XCTAssertEqual(size.width, 610, accuracy: 1)
            XCTAssertGreaterThanOrEqual(size.height, 260); XCTAssertLessThanOrEqual(size.height, 680)
            hosting.view.frame = NSRect(origin: .zero, size: size)
            let window = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.titled], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.contentViewController = hosting
            defer { window.contentViewController = nil; window.close() }
            hosting.view.layoutSubtreeIfNeeded()
            // Exact test-owned window is never ordered front or activated. No user window,
            // system permissions, external AX traversal, or GUI automation is used.
            let root = hosting.view
            let deadline = ContinuousClock.now + .seconds(3)
            while descendants(root).compactMap({ $0 as? NSButton }).filter({ $0.identifier?.rawValue == "authentication.submit" }).isEmpty {
                guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
                try await Task.sleep(for: .milliseconds(10)); root.layoutSubtreeIfNeeded()
            }
            let footer = descendants(root).compactMap { $0 as? NSButton }.filter { ["authentication.cancel", "authentication.submit"].contains($0.identifier?.rawValue ?? "") }
            XCTAssertEqual(footer.count, 2)
            for button in footer {
                XCTAssertGreaterThan(button.visibleRect.width, 0); XCTAssertGreaterThan(button.visibleRect.height, 0)
                XCTAssertTrue(root.bounds.contains(button.convert(button.bounds, to: root)), "Footer must fit without being pushed out by prompt fields")
            }
            let scroll = try XCTUnwrap(descendants(root).compactMap { $0 as? NSScrollView }.first)
            XCTAssertGreaterThan(scroll.contentView.bounds.height, 80)
            let inputFields = descendants(root).compactMap { $0 as? NSTextField }.filter { $0.isEditable }
            switch payload {
            case .initialPassword:
                let field = try XCTUnwrap(inputFields.first)
                XCTAssertGreaterThan(field.visibleRect.height, 0); XCTAssertGreaterThan(field.visibleRect.width, 0)
                XCTAssertTrue(root.bounds.intersects(field.convert(field.bounds, to: root)))
                XCTAssertLessThanOrEqual(size.height, 360, "A short primary prompt remains compact")
            case .keyboard(_, _, let prompts) where prompts.isEmpty:
                XCTAssertTrue(inputFields.isEmpty); XCTAssertLessThanOrEqual(size.height, 360, "A short zero-input notice remains compact")
            case .keyboard:
                XCTAssertEqual(inputFields.count, 32)
                let exactLast = inputFields.filter { $0.placeholderString == "第 32 项回答（不回显）" }
                XCTAssertEqual(exactLast.count, 1, "A unique public placeholder binds this native field to the final protocol prompt")
                let last = try XCTUnwrap(exactLast.first)
                let content = inputFields.map { $0.convert($0.bounds, to: scroll.contentView) }.reduce(NSRect.null) { $0.union($1) }
                XCTAssertGreaterThan(content.height, scroll.contentView.bounds.height, "Real laid-out prompt content exceeds the viewport")
                _ = last.scrollToVisible(last.bounds); scroll.reflectScrolledClipView(scroll.contentView)
                try await wait { scroll.contentView.bounds.intersects(last.convert(last.bounds, to: scroll.contentView)) }
                root.layoutSubtreeIfNeeded()
                XCTAssertGreaterThan(last.visibleRect.height, 0, "The final prompt can be reached by scrolling")
                XCTAssertTrue(scroll.contentView.bounds.intersects(last.convert(last.bounds, to: scroll.contentView)))
            default: break
            }
        }
    }
    private func descendants(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(descendants) }
    func testRetirementKnownClosedPendingReturnsTicketWithoutFakingDrain() async throws {
        let f = try fixture(), registry = SessionRetirementRegistry(), transport = AdapterTransport()
        transport.holdDrain = true
        let driver = try NativeSessionDriver(sessionID: UUID(), host: f.host, repository: f.repository, security: f.security,
            connector: f.connector, retirementRegistry: registry)
        _ = try driver.connect(SessionEnvironment.configuration(host: f.host, keyPath: nil), primary: SessionPrimaryAuthorization(provider: { _ in nil }))
        _ = try await f.connector.request(0); await f.connector.succeed(0, transport: transport)
        try await nextState(driver, .connected)
        let result = await driver.closeResult(deadline: .now + .milliseconds(30))
        guard case .retired(let ticket) = result else { return XCTFail("Expected known native closure with pending provider to retire") }
        XCTAssertEqual(ticket.token, driver.token); XCTAssertEqual(ticket.snapshot.pendingTasks, 1)
        XCTAssertTrue(ticket.snapshot.safeToRetire); XCTAssertFalse(ticket.snapshot.drained)
        XCTAssertFalse(driver.snapshot.interactionsDrained); XCTAssertNotEqual(driver.state, .closed)
        XCTAssertEqual(registry.retiredCount, 1); transport.holdDrain = false
        try await wait { registry.retiredCount == 0 }
    }
    func testRetirementUnknownNativeRemainsIncompleteAndOwnerIsRetained() async throws {
        let f = try fixture(), (_, driver, _, index) = try await opened(f)
        let drain = RetirementTestDrain()
        drain.update(.init(pendingTasks: 1, pendingProviders: 1, revoked: true, nativeClosed: false, producersSealed: true))
        await f.connector.fail(index, error: NativeSessionConnectionFailure(failure: NativeShellError(.timeout, operation: "connect"), drain: drain, noNativeOwnerCreated: false))
        try await wait { driver.state == .closing }
        let result = await driver.closeResult(deadline: .now + .milliseconds(20))
        guard case .incomplete(let context) = result else { return XCTFail("Unknown native close cannot retire") }
        XCTAssertEqual(context.reason, .nativeUnknown); XCTAssertFalse(driver.canReconnect)
        XCTAssertFalse(driver.snapshot.nativeCloseCompleted); XCTAssertNotEqual(driver.state, .closed)
        drain.complete(); _ = await driver.closeResult(deadline: .now + .milliseconds(50))
    }
    func testRetirementSetupFailureUsesCanonicalReceiptAndLaterCompletionClearsFence() async throws {
        let f = try fixture(), (_, driver, _, index) = try await opened(f), drain = RetirementTestDrain()
        drain.setClosed(pending: 1)
        await f.connector.fail(index, error: NativeSessionConnectionFailure(failure: NativeShellError(.authentication, operation: "primary-authentication", pendingInteractionTasks: 1), drain: drain, noNativeOwnerCreated: false))
        _ = try await f.connector.request(index)
        try await Task.sleep(for: .milliseconds(20))
        let result = await driver.closeResult(deadline: .now + .milliseconds(40))
        guard case .retired(let ticket) = result else { return XCTFail("Expected receipt from failed setup") }
        XCTAssertEqual(ticket.handleID, drain.id); XCTAssertFalse(driver.canReconnect)
        drain.complete(); try await wait { driver.snapshot.interactionsDrained }
        XCTAssertEqual(driver.closeDisposition, .closed)
    }
    func testRetirementDisconnectPendingRejectsReconnectThenOnlyExplicitFreshGeneration() async throws {
        let f = try fixture(), (_, driver, _, index) = try await opened(f), transport = AdapterTransport()
        transport.holdDrain = true; transport.drain.maximumObservers = 1
        await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
        let old = try XCTUnwrap(driver.token)
        driver.cancel(); await driver.waitForCleanup()
        XCTAssertFalse(driver.canReconnect)
        XCTAssertThrowsError(try driver.connect(SessionEnvironment.configuration(host: f.host, keyPath: nil), primary: SessionPrimaryAuthorization(provider: { _ in nil })))
        let count = await f.connector.count; XCTAssertEqual(count, 1)
        transport.holdDrain = false; try await wait { driver.canReconnect }
        let next = try driver.connect(SessionEnvironment.configuration(host: f.host, keyPath: nil), primary: SessionPrimaryAuthorization(provider: { _ in nil }))
        XCTAssertEqual(next.generation, old.generation + 1); XCTAssertNotEqual(next, old)
        let request = try await f.connector.request(index + 1); XCTAssertFalse(request.token.isCancelled)
        driver.cancel(); await f.connector.fail(index + 1); await driver.waitForCleanup()
    }
    func testRetirementPrimaryHeldGateDoesNotRetainDriverOrTerminalAndLateMaterialRejected() async throws {
        let f = try fixture(), registry = SessionRetirementRegistry(), gate = AdapterGate()
        await gate.arm()
        var driver: NativeSessionDriver? = try NativeSessionDriver(sessionID: UUID(), host: f.host, repository: f.repository,
            security: f.security, connector: f.connector, retirementRegistry: registry)
        weak var weakDriver = driver, weakTerminal = driver?.terminal
        let authorization = SessionPrimaryAuthorization(provider: { _ in
            try await gate.wait()
            return SessionPrimaryMaterial(secret: .init(utf8: "late-logical-only"), credential: nil)
        })
        _ = try driver!.connect(SessionEnvironment.configuration(host: f.host, keyPath: nil), primary: authorization)
        let request = try await f.connector.request(0)
        let provider = Task { try await request.primary(primary(request)) }
        try await gate.arrived()
        let drain = RetirementTestDrain(); drain.setClosed(pending: 1)
        await f.connector.fail(0, error: NativeSessionConnectionFailure(failure: NativeShellError(.cancelled, operation: "connect"), drain: drain, noNativeOwnerCreated: false))
        try await wait { driver?.state == .closing }
        let result = await driver!.closeResult(deadline: .now + .milliseconds(40))
        guard case .retired = result else { return XCTFail("Expected retired provider owner") }
        driver = nil
        try await wait { weakDriver == nil && weakTerminal == nil }
        XCTAssertFalse(drain.snapshot.drained); XCTAssertEqual(registry.retiredCount, 1)
        await gate.release()
        do { _ = try await provider.value; XCTFail("Revoked material forwarded") } catch {}
        drain.complete(); try await wait { registry.retiredCount == 0 }
        weakDriver = nil; weakTerminal = nil
        try await heldCredentialReadReleasesActualControllerConsumer()
    }
    private func heldCredentialReadReleasesActualControllerConsumer() async throws {
        let f = try fixture(saved: true)
        let id = try XCTUnwrap(f.controller.open(f.host, mode: .newSession))
        var tab: SessionTab? = try XCTUnwrap(f.controller.selectedTab)
        await tab?.preparation?.value
        var actual: NativeSessionDriver? = try XCTUnwrap(tab?.driver as? NativeSessionDriver)
        weak var weakDriver = actual, weakView = actual?.terminal
        let request = try await f.connector.request(0)
        await f.credentials.gate.arm()
        let provider = Task { try await request.primary(primary(request)) }
        try await f.credentials.gate.arrived()
        let reads = await f.credentials.readCount; XCTAssertEqual(reads, 1)
        XCTAssertNotNil(tab?.primaryRequestID, "Production reader claimed this primary exactly once")
        let drain = RetirementTestDrain(); drain.setClosed(pending: 1)
        await f.connector.fail(0, error: NativeSessionConnectionFailure(failure: NativeShellError(.cancelled, operation: "connect"), drain: drain, noNativeOwnerCreated: false))
        try await wait { actual?.state == .closing }
        let result = await f.controller.closeTabResult(id, deadline: .now + .milliseconds(40))
        guard case .retired = result else { return XCTFail("Held actual credential read must retire only after native facts") }
        actual = nil; tab = nil
        try await wait { weakDriver == nil && weakView == nil }
        XCTAssertFalse(drain.snapshot.drained)
        await f.credentials.gate.release()
        do { _ = try await provider.value; XCTFail("Actual production reader forwarded late saved credential") } catch {}
        let finalReads = await f.credentials.readCount; XCTAssertEqual(finalReads, 1)
        drain.complete(); weakDriver = nil; weakView = nil
    }
    func testRetirementRegistryAAndBCompleteInReverseOrderWithoutCrossRelease() async throws {
        let registry = SessionRetirementRegistry(), a = RetirementTestDrain(), b = RetirementTestDrain()
        a.setClosed(pending: 1); b.setClosed(pending: 1)
        let ar = try registry.reserve(), br = try registry.reserve()
        let at = SessionRetirementTicket(token: .init(sessionID: UUID(), generation: 1), drain: a)
        let bt = SessionRetirementTicket(token: .init(sessionID: UUID(), generation: 1), drain: b)
        try registry.retire(ar, ticket: at); try registry.retire(br, ticket: bt)
        XCTAssertEqual(registry.retiredCount, 2)
        b.complete(); try await wait { registry.retiredCount == 1 }; XCTAssertFalse(at.snapshot.drained)
        a.complete(); try await wait { registry.retiredCount == 0 }
    }
    func testRetirementAdmissionReservesBeforeConnectAndSecretRead() async throws {
        let f = try fixture(), registry = SessionRetirementRegistry(maximumActive: 1, maximumTotal: 2)
        let slot = try registry.reserve()
        let driver = try NativeSessionDriver(sessionID: UUID(), host: f.host, repository: f.repository, security: f.security,
            connector: f.connector, retirementRegistry: registry)
        XCTAssertThrowsError(try driver.connect(SessionEnvironment.configuration(host: f.host, keyPath: nil), primary: SessionPrimaryAuthorization(provider: { _ in XCTFail("Capacity must reject before material"); return nil }))) {
            XCTAssertEqual(($0 as? NativeShellError)?.kind, .resourceLimit)
        }
        let count = await f.connector.count, reads = await f.credentials.readCount
        XCTAssertEqual(count, 0); XCTAssertEqual(reads, 0); XCTAssertNil(driver.token)
        registry.release(slot); driver.closeTab()
    }
    func testRetirementTotalCapacityIncludesRetiredTicketsAndReturnsOnCompletion() async throws {
        let registry = SessionRetirementRegistry(maximumActive: 1, maximumTotal: 2), a = RetirementTestDrain(), b = RetirementTestDrain()
        a.setClosed(pending: 1); b.setClosed(pending: 1)
        try registry.retire(registry.reserve(), ticket: .init(token: .init(sessionID: UUID(), generation: 1), drain: a))
        try registry.retire(registry.reserve(), ticket: .init(token: .init(sessionID: UUID(), generation: 1), drain: b))
        XCTAssertThrowsError(try registry.reserve())
        a.complete(); try await wait { registry.retiredCount == 1 }
        let next = try registry.reserve(); registry.release(next); b.complete()
        try await wait { registry.retiredCount == 0 }
    }
    func testRetirementPreparedReservationReleaseIsSynchronousWithoutStartingTransport() throws {
        let f = try fixture(), registry = SessionRetirementRegistry(maximumActive: 1, maximumTotal: 1)
        let driver = try NativeSessionDriver(sessionID: UUID(), host: f.host, repository: f.repository, security: f.security,
            connector: f.connector, retirementRegistry: registry)
        try driver.reserveForPreparation(); XCTAssertEqual(registry.activeCount, 1)
        driver.closeTab(); XCTAssertEqual(registry.activeCount, 0)
    }
    func testRetirementMissingReceiptCannotTurnPendingFailureIntoClosed() async throws {
        let failures: [any Error] = [NativeShellError(.transport, operation: "connect", pendingInteractionTasks: 1),
            CancellationError(), FileServiceError(.transport, operation: "connect")]
        for failure in failures {
            let f = try fixture(), (_, driver, _, index) = try await opened(f)
            await f.connector.fail(index, error: NativeSessionConnectionFailure(failure: failure, drain: nil, noNativeOwnerCreated: false))
            try await wait { driver.state == .closing }
            let result = await driver.closeResult(deadline: .now + .milliseconds(30))
            guard case .incomplete(let context) = result else { return XCTFail("An explicit unknown native owner must remain incomplete regardless of inner error type") }
            XCTAssertEqual(context.reason, .nativeUnknown); XCTAssertNil(context.drain)
            XCTAssertFalse(driver.canReconnect); XCTAssertFalse(driver.snapshot.nativeCloseCompleted)
            XCTAssertFalse(driver.snapshot.interactionsDrained); XCTAssertNotEqual(driver.state, .closed)
        }
    }
    func testRetirementGenericConnectorErrorsWithoutOwnerProofRemainIncomplete() async throws {
        for failure in [CancellationError() as any Error, FileServiceError(.timeout, operation: "connect") as any Error] {
            let f = try fixture(), (_, driver, _, index) = try await opened(f)
            await f.connector.failUnclassified(index, error: failure)
            try await wait { driver.state == .closing }
            let result = await driver.closeResult(deadline: .now + .milliseconds(30))
            guard case .incomplete(let context) = result else { return XCTFail("An arbitrary connector's unwrapped error is not proof of native closure") }
            XCTAssertEqual(context.reason, .nativeUnknown); XCTAssertNil(context.drain)
            XCTAssertFalse(driver.snapshot.nativeCloseCompleted); XCTAssertFalse(driver.snapshot.interactionsDrained)
        }
    }
    func testRetirementCancelledNativeCloseObservationYieldsAndKeepsCleanupOwner() async throws {
        let f = try fixture(), (_, driver, _, index) = try await opened(f), transport = AdapterTransport()
        transport.holdDrain = true
        await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
        driver.closeTab(); try await transport.waitForClose()
        let observer = Task { await driver.closeResult(deadline: .now + .seconds(2)) }
        // closeTab's app-owned cleanup is already active. Let this distinct caller enter
        // settle's suspension, then cancel only it while the canonical receipt is pending.
        try await wait { driver.closeObservationCount == 1 }
        let start = ContinuousClock.now; observer.cancel()
        let heartbeat = Task { @MainActor in
            try await Task.sleep(for: .milliseconds(10))
            transport.holdDrain = false
            return ContinuousClock.now
        }
        let heartbeatAt = try await heartbeat.value
        XCTAssertLessThan(start.duration(to: heartbeatAt), .milliseconds(500))
        let result = await observer.value
        guard case .incomplete(let context) = result else { return XCTFail("Cancellation must only stop this observer") }
        XCTAssertEqual(context.reason, .observationCancelled)
        await driver.waitForCleanup()
        XCTAssertEqual(driver.state, .closed); XCTAssertTrue(driver.snapshot.interactionsDrained)
    }
    func testRetirementChangedPromptIsKeptWhileProviderPendingAndNoCredentialRead() async throws {
        let f = try fixture(saved: true), (tab, driver, request, index) = try await opened(f)
        let changed = try await changedFact(request.configuration.host), drain = RetirementTestDrain()
        drain.setClosed(pending: 1)
        await f.connector.fail(index, error: NativeSessionConnectionFailure(failure: NativeShellError(.untrusted, operation: "host-key", changedHostKey: changed), drain: drain, noNativeOwnerCreated: false))
        let prompt = try await nextTrust(tab)
        driver.cancel(); await driver.waitForCleanup()
        XCTAssertEqual(tab.trust.first?.id, prompt.id); XCTAssertEqual(prompt.changed, changed)
        XCTAssertFalse(driver.canReconnect); let reads = await f.credentials.readCount; XCTAssertEqual(reads, 0)
        drain.complete(); try await wait { driver.canReconnect }
    }
    func testRetirementReadyCanonicalClosedResultDoesNotWaitForFullBudget() async throws {
        let f = try fixture(), (_, driver, _, index) = try await opened(f), transport = AdapterTransport()
        await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
        let start = ContinuousClock.now
        let result = await driver.closeResult(deadline: .now + .seconds(2))
        XCTAssertEqual(result, .closed); XCTAssertLessThan(start.duration(to: .now), .seconds(1))
        XCTAssertTrue(driver.snapshot.interactionsDrained); XCTAssertTrue(driver.snapshot.nativeCloseCompleted)
    }
    func testDroppedPreparedOwnerRevokesControllerIntentAndActionsAreOnce() async throws {
        let f = try fixture(), intent = VaultTransientConnectionIntent(host: f.host, secret: .init(utf8: UUID().uuidString))
        var prepared: VaultPreparedConnection? = try await f.controller.prepareTransient(f.host, intent: intent, candidateBuilder: f.builder) { _ in XCTFail("Dropped preparation cannot route"); return true }
        weak var released = prepared
        XCTAssertNotNil(prepared); XCTAssertFalse(intent.consumed)
        prepared = nil
        XCTAssertNil(released); released = nil; XCTAssertTrue(intent.consumed); XCTAssertTrue(f.controller.tabs.isEmpty)
        let count = await f.connector.count; XCTAssertEqual(count, 0)
        var cancelled = 0, committed = 0
        do { let value = VaultPreparedConnection(commit: { committed += 1 }, cancel: { cancelled += 1 }); value.cancel(); value.cancel() }
        XCTAssertEqual(cancelled, 1)
        do { let value = VaultPreparedConnection(commit: { committed += 1 }, cancel: { cancelled += 1 }); try value.commit() }
        XCTAssertEqual(committed, 1); XCTAssertEqual(cancelled, 1)
    }
    func testNetworkTimeoutDNSUnsupportedPrimaryRejectionAndCancellationRemainDistinct() async throws {
        let errors: [FileServiceError] = [.init(.timeout, operation: "connect"), .init(.transport, operation: "dns", code: -2),
            .init(.unsupported, operation: "channel-open"), .init(.authentication, operation: "primary-authentication"), .init(.cancelled, operation: "connect")]
        let expected: [SessionFailureDetail.Category?] = [.networkTimeout, .networkUnavailable, .unsupported, .authenticationRejected, nil]
        for (error, category) in zip(errors, expected) {
            let f = try fixture(), (tab, driver, _, index) = try await opened(f)
            await f.connector.fail(index, error: error)
            try await wait { driver.canReconnect }
            XCTAssertEqual(driver.failureDetail?.category, category)
            if let category {
                XCTAssertEqual(tab.issue?.code, "session.native." + category.rawValue)
                XCTAssertEqual(tab.status, driver.failureDetail!.title + "；可手动重试")
                XCTAssertEqual(driver.failureDetail?.operation, error.operation)
                if category == .networkTimeout || category == .networkUnavailable { XCTAssertNotEqual(driver.state, .failed(.authenticationFailed)) }
            } else { XCTAssertNil(tab.issue); XCTAssertEqual(driver.state, .disconnected(nil)) }
            let connections = await f.connector.count
            XCTAssertEqual(connections, 1, "A failure never silently retries or opens a second socket")
        }
        let f = try fixture(), (tab, driver, _, index) = try await opened(f)
        await f.connector.fail(index, error: NSError(domain: "MUST-NOT-DISPLAY-user-password", code: 99))
        try await wait { driver.canReconnect }
        XCTAssertEqual(driver.failureDetail?.category, .unknown); XCTAssertEqual(driver.failureDetail?.operation, "unknown")
        XCTAssertFalse(driver.failureDetail?.diagnostic.contains("MUST-NOT-DISPLAY") ?? true)
        XCTAssertTrue(tab.status.contains("原因尚不能确定"))
    }
    func testReadFailureDiagnosticsKeepTCPReadbackElapsedAndCloseOriginWithoutRemoteText() async throws {
        let actual = NativeTCPKeepaliveSnapshot(enabled: true, idleSeconds: 30, retrySeconds: 30, failedProbes: 3)
        for operation in ["read", "poll", "read-window-adjust"] {
            let f = try fixture(), (tab, driver, _, index) = try await opened(f), transport = AdapterTransport(keepalive: actual)
            await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
            try await transport.waitForReceive(); transport.releaseResize()
            transport.failReceive(NativeShellError(.transport, operation: operation, code: -43, stages: [.authenticated, .shellReady]))
            try await wait { driver.canReconnect }
            let detail = try XCTUnwrap(driver.failureDetail)
            XCTAssertEqual(detail.category, .connectionLost); XCTAssertEqual(detail.operation, operation); XCTAssertEqual(detail.code, -43)
            XCTAssertEqual(detail.closeOrigin, .receiveFailure); XCTAssertEqual(detail.tcpKeepalive, actual)
            XCTAssertGreaterThanOrEqual(try XCTUnwrap(detail.connectedSeconds), 0)
            XCTAssertTrue(detail.diagnostic.contains("关闭发起路径：receiveFailure"))
            XCTAssertTrue(detail.diagnostic.contains("TCP 保活实际值：空闲 30 秒；重试 30 秒；失败探测 3 次"))
            XCTAssertFalse(detail.diagnostic.contains(f.host.address)); XCTAssertFalse(detail.diagnostic.contains(f.host.username))
            XCTAssertEqual(driver.snapshot.lastCloseOrigin, .receiveFailure); XCTAssertEqual(driver.snapshot.tcpKeepalive, actual)
            let connects = await f.connector.count; XCTAssertEqual(connects, 1, "Diagnostics must never reconnect or reauthenticate")
            await f.controller.closeTab(tab.id)
        }
        let f = try fixture(), (_, driver, _, index) = try await opened(f)
        await f.connector.fail(index, error: NativeShellError(.unsupported, operation: "tcp-keepalive-configure", code: 45))
        try await wait { driver.canReconnect }
        XCTAssertEqual(driver.failureDetail?.category, .unsupported)
        XCTAssertEqual(driver.failureDetail?.operation, "tcp-keepalive-configure"); XCTAssertEqual(driver.failureDetail?.code, 45)
        XCTAssertEqual(driver.failureDetail?.closeOrigin, .setupFailure)
        XCTAssertNil(driver.failureDetail?.connectedSeconds); XCTAssertNil(driver.failureDetail?.tcpKeepalive)
    }
    func testExplicitDisconnectAndRemoteExitRetainDistinctCloseOrigins() async throws {
        for remote in [false, true] {
            let f = try fixture(), (tab, driver, _, index) = try await opened(f), transport = AdapterTransport()
            await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
            try await transport.waitForReceive(); transport.releaseResize()
            if remote { transport.releaseReceive(.exit(NativeShellExit(reportedStatus: 7, signal: nil))) }
            else { driver.cancel() }
            try await wait { driver.canReconnect }
            XCTAssertNil(driver.failureDetail)
            XCTAssertEqual(driver.snapshot.lastCloseOrigin, remote ? .remoteExit : .userDisconnect)
            XCTAssertEqual(driver.state, .disconnected(remote ? 7 : nil))
            let connects = await f.connector.count; XCTAssertEqual(connects, 1)
            await f.controller.closeTab(tab.id)
        }
    }
    func testEstablishedReceiveFailurePreservesHistoryAndRequiresExplicitReconnect() async throws {
        let failures: [any Error] = [
            NativeShellError(.transport, operation: "read", code: -43, stages: [.authenticated, .shellReady]),
            NativeShellError(.transport, operation: "read", code: -43),
            NativeShellError(.timeout, operation: "ssh-round-trip"),
            FileServiceError(.transport, operation: "read", code: -43)
        ]
        for failure in failures {
            let f = try fixture(), (tab, driver, _, index) = try await opened(f), transport = AdapterTransport()
            await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
            XCTAssertEqual(tab.status, "已连接")
            let oldToken = try XCTUnwrap(driver.token), terminalID = ObjectIdentifier(driver.terminal)
            try driver.terminal.feedApplicationOutput(Data("synthetic output before connection interruption\r\n".utf8))
            try await transport.waitForReceive()
            transport.failReceive(failure)
            try await wait { driver.canReconnect }
            XCTAssertEqual(driver.failureDetail?.category, .connectionLost)
            XCTAssertEqual(tab.issue?.code, "session.native.connectionLost")
            XCTAssertTrue(tab.status.contains("连接已中断")); XCTAssertFalse(tab.status.contains("域名"))
            XCTAssertTrue(driver.terminal.text.contains("synthetic output before connection interruption"))
            XCTAssertFalse(driver.terminal.inputEnabled); XCTAssertFalse(driver.terminalResourcesReleased)
            XCTAssertNotEqual(driver.state, .failed(.authenticationFailed))
            await Task.yield()
            let beforeManualRetry = await f.connector.count
            XCTAssertEqual(beforeManualRetry, 1, "A connected IO failure cannot silently reconnect")

            f.controller.reconnect(tab.id)
            let retry = try await f.connector.request(index + 1)
            XCTAssertFalse(retry.token.isCancelled)
            let replacement = AdapterTransport()
            await f.connector.succeed(index + 1, transport: replacement); try await nextState(driver, .connected)
            XCTAssertEqual(driver.token?.generation, oldToken.generation + 1); XCTAssertNil(driver.failureDetail)
            XCTAssertEqual(ObjectIdentifier(driver.terminal), terminalID)
            XCTAssertTrue(driver.terminal.text.contains("synthetic output before connection interruption"))
            XCTAssertEqual(tab.status, "已连接")
            await f.controller.closeTab(tab.id)
        }
    }
    func testNativeSetupNetworkFailuresRespectTheTypedShellReadyFact() async throws {
        let failures: [(NativeShellError, SessionFailureDetail.Category)] = [
            (.init(.transport, operation: "dns", code: -2), .networkUnavailable),
            (.init(.timeout, operation: "handshake", stages: [.authenticated]), .networkTimeout),
            (.init(.transport, operation: "read", code: -43, stages: [.authenticated, .shellReady]), .connectionLost)
        ]
        for (failure, expected) in failures {
            let f = try fixture(), (_, driver, _, index) = try await opened(f)
            await f.connector.fail(index, error: failure)
            try await wait { driver.canReconnect }
            XCTAssertEqual(driver.failureDetail?.category, expected)
            XCTAssertEqual(driver.failureDetail?.operation, failure.operation)
            XCTAssertEqual(driver.failureDetail?.stages.contains("shellReady"), failure.authenticationStages.contains(.shellReady))
            let count = await f.connector.count; XCTAssertEqual(count, 1)
        }
    }
    func testEstablishedCancellationAndNaturalExitRemainSeparateFromConnectionLoss() async throws {
        let cancellations: [any Error] = [CancellationError(), NativeShellError(.cancelled, operation: "read"),
            FileServiceError(.cancelled, operation: "read"), NativeShellError(.closed, operation: "close")]
        for cancellation in cancellations {
            let f = try fixture(), (_, driver, _, index) = try await opened(f), transport = AdapterTransport()
            await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
            try await transport.waitForReceive(); transport.failReceive(cancellation)
            try await wait { driver.canReconnect }
            XCTAssertNil(driver.failureDetail); XCTAssertEqual(driver.state, .disconnected(nil))
            let count = await f.connector.count; XCTAssertEqual(count, 1)
        }
        let f = try fixture(), (_, driver, _, index) = try await opened(f), transport = AdapterTransport()
        await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
        try await transport.waitForReceive()
        transport.releaseReceive(.exit(NativeShellExit(reportedStatus: 7, signal: nil)))
        try await wait { driver.canReconnect }
        XCTAssertEqual(driver.state, .disconnected(7)); XCTAssertNil(driver.failureDetail)
    }
    func testEstablishedWriteAndResizeNetworkFailuresUseConnectionLostCategory() async throws {
        for operation in ["write", "control"] {
            let f = try fixture(), (_, driver, _, index) = try await opened(f), transport = AdapterTransport()
            await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
            try await transport.waitForResize()
            if operation == "write" {
                transport.releaseResize()
                XCTAssertTrue(driver.admitInput(Array("synthetic input".utf8)[...]))
                try await transport.waitForWrite()
                transport.failWrites(NativeShellError(.transport, operation: operation, code: -43))
            } else { transport.failResize(NativeShellError(.transport, operation: operation, code: -43)) }
            try await wait { driver.canReconnect }
            XCTAssertEqual(driver.failureDetail?.category, .connectionLost)
            XCTAssertEqual(driver.failureDetail?.operation, operation)
            let count = await f.connector.count; XCTAssertEqual(count, 1)
        }
    }
    func testExplicitVaultRequestClearsFiltersLocatesHostAndNeverConnects() async throws {
        let f = try fixture(), app = AppModel(repository: f.repository, security: f.security,
            sessionBuilder: f.builder, nativeCandidateBuilder: f.builder)
        _ = await app.reload()
        let vault = VaultDesktopModel(app: app)
        vault.section = .favorites; vault.search = "unmatched"; vault.tagFilter = [UUID()]
        app.showConnectionConfiguration(f.host.id)
        try await wait { vault.focusedID == f.host.id }
        XCTAssertEqual(vault.section, .all); XCTAssertEqual(vault.search, ""); XCTAssertTrue(vault.tagFilter.isEmpty)
        XCTAssertEqual(app.workspacePage, .vault); XCTAssertEqual(app.selectedHostID, f.host.id)
        XCTAssertTrue(app.sessions.tabs.isEmpty)
        let count = await f.connector.count; XCTAssertEqual(count, 0)
        XCTAssertNotNil(app.vaultHostFocusRequest)
    }
    func testLateVaultFocusCannotReplaceNewerUserSelection() async throws {
        let f = try fixture(), other = HostConfiguration(name: "other", address: "other.invalid", username: "fixture")
        try await f.repository.apply([.insertHost(other)])
        let vault = VaultDesktopModel(repository: f.repository, preferenceKey: UUID().uuidString)
        _ = await vault.load(); await f.repository.snapshotGate.arm()
        vault.requestFocus(VaultHostFocusRequest(hostID: f.host.id))
        try await f.repository.snapshotGate.arrived()
        vault.choose(other.id)
        await f.repository.snapshotGate.release()
        try await wait { !vault.isLoading }
        XCTAssertEqual(vault.focusedID, other.id); XCTAssertEqual(vault.selectedIDs, [other.id])
    }
    func testDeletedVaultFocusShowsUnavailableAndNeverCreatesRow() async throws {
        let f = try fixture(), app = AppModel(repository: f.repository, security: f.security,
            sessionBuilder: f.builder, nativeCandidateBuilder: f.builder)
        _ = await app.reload()
        let vault = VaultDesktopModel(app: app); _ = await vault.load()
        await f.repository.delete(f.host.id)
        app.showConnectionConfiguration(f.host.id)
        try await wait { vault.issue?.code == "session.configurationUnavailable" }
        XCTAssertTrue(vault.hosts.isEmpty); XCTAssertNil(vault.focusedID)
        XCTAssertTrue(app.sessions.tabs.isEmpty)
        let metadata = try await f.repository.securityMetadata(); XCTAssertTrue(metadata.hosts.isEmpty)
        _ = await app.reload(); app.showConnectionConfiguration(f.host.id)
        XCTAssertEqual(app.issue?.code, "session.configurationUnavailable")
    }
    func testCandidatePrepareDoesNotStartOrSelectAndCommitRequiresExplicitRoute() async throws {
        let f = try fixture(), secret = OpenLXSSHSecurity.SecretBytes(utf8: UUID().uuidString)
        let intent = VaultTransientConnectionIntent(host: f.host, secret: secret)
        var routeCount = 0
        let prepared = try await f.controller.prepareTransient(f.host, intent: intent, candidateBuilder: f.builder) { id in
            routeCount += 1; f.controller.select(id); return true
        }
        XCTAssertTrue(f.controller.tabs.isEmpty); XCTAssertNil(f.controller.selectedTabID)
        let count = await f.connector.count; XCTAssertEqual(count, 0); XCTAssertFalse(intent.consumed)
        try prepared.commit()
        let request = try await f.connector.request(0)
        let tab = try XCTUnwrap(f.controller.selectedTab)
        let value = try await request.primary(primary(request))
        guard case .password(let bytes) = value else { return XCTFail("Expected typed password") }
        XCTAssertTrue(secret.withUnsafeBytes { Data($0) } == bytes)
        XCTAssertTrue(intent.consumed); XCTAssertEqual(routeCount, 1)
        XCTAssertThrowsError(try prepared.commit())
        do { _ = try await request.primary(primary(request)); XCTFail("Double primary request accepted") } catch {}
        let transport = AdapterTransport(); await f.connector.succeed(0, transport: transport)
        try await nextState(try XCTUnwrap(tab.driver as? NativeSessionDriver), .connected)
        let reads = await f.credentials.readCount; XCTAssertEqual(reads, 0)
    }
    func testRejectedRouteCancelsCandidateWithoutHiddenTabOrReusableIntent() async throws {
        let f = try fixture(), intent = VaultTransientConnectionIntent(host: f.host, secret: .init(utf8: UUID().uuidString))
        let prepared = try await f.controller.prepareTransient(f.host, intent: intent, candidateBuilder: f.builder) { _ in false }
        XCTAssertThrowsError(try prepared.commit())
        XCTAssertTrue(f.controller.tabs.isEmpty); XCTAssertTrue(intent.consumed)
        // The virtual connector may still see the cancelled setup Task; release it if entered.
        await f.connector.cancelAll()
    }
    func testIntentBindsHostTokenGenerationRequestAndMetadataOnlyRename() throws {
        let host = HostConfiguration(name: "A", address: "never-connected.invalid", username: "fixture")
        let token = SessionToken(sessionID: UUID(), generation: 1), request = UUID()
        let intent = VaultTransientConnectionIntent(host: host, secret: .init(utf8: UUID().uuidString))
        var renamed = host; renamed.name = "metadata rename"; renamed.isFavorite = true
        try intent.bind(to: token, host: renamed)
        XCTAssertThrowsError(try intent.bind(to: token, host: host))
        XCTAssertThrowsError(try intent.bindPrimaryRequest(request, token: .init(sessionID: token.sessionID, generation: 2), host: host))
        try intent.bindPrimaryRequest(request, token: token, host: renamed)
        XCTAssertThrowsError(try intent.take(for: host, token: token, primaryRequestID: UUID()))
        var changed = host; changed.port += 1
        XCTAssertThrowsError(try intent.take(for: changed, token: token, primaryRequestID: request))
        XCTAssertNotNil(try intent.take(for: renamed, token: token, primaryRequestID: request))
        XCTAssertThrowsError(try intent.take(for: host, token: token, primaryRequestID: request))
        let cancelled = VaultTransientConnectionIntent(host: host, secret: .init(utf8: UUID().uuidString)); cancelled.cancel()
        XCTAssertThrowsError(try cancelled.bind(to: token, host: host))
    }
    func testSavedCredentialAwaitRevocationNeverReturnsMaterialOrReadsAgain() async throws {
        let f = try fixture(saved: true), (_, driver, request, index) = try await opened(f)
        await f.credentials.gate.arm()
        let task = Task { try await request.primary(primary(request)) }
        try await f.credentials.gate.arrived()
        await f.repository.revokePassword(f.host.id)
        await f.credentials.gate.release()
        do { _ = try await task.value; XCTFail("Revoked saved password returned") } catch {}
        let reads = await f.credentials.readCount; XCTAssertEqual(reads, 1)
        driver.cancel(); await f.connector.fail(index); await driver.waitForCleanup()
        XCTAssertTrue(driver.snapshot.interactionsDrained)
    }
    func testSavedMetadataRenameDuringAwaitRetainsExactAuthorization() async throws {
        let f = try fixture(saved: true), (_, driver, request, index) = try await opened(f)
        await f.credentials.gate.arm()
        let task = Task { try await request.primary(primary(request)) }
        try await f.credentials.gate.arrived(); await f.repository.rename(f.host.id); await f.credentials.gate.release()
        guard case .password(let bytes) = try await task.value else { return XCTFail("Expected password") }
        XCTAssertFalse(bytes.isEmpty)
        driver.cancel(); await f.connector.fail(index); await driver.waitForCleanup()
    }
    func testInitialPasswordAutoPromptIsTypedAndCancellationDoesNotAcknowledge() async throws {
        let f = try fixture(), (tab, driver, request, index) = try await opened(f)
        let query = primary(request)
        let task = Task { try await request.primary(query) }
        let prompt = try await nextPrompt(tab)
        XCTAssertEqual(prompt.payload, .initialPassword); XCTAssertEqual(prompt.id, query.requestID)
        XCTAssertEqual(prompt.token, driver.token)
        XCTAssertEqual(request.options.operationTimeout, 10); XCTAssertEqual(request.options.interactionTimeout, 120)
        XCTAssertEqual(request.options.authenticationTimeout, 300); XCTAssertEqual(request.options.keepalive, try NativeTCPKeepalivePolicy(interval: 30, failedProbes: 3))
        f.controller.cancelChallenge(prompt, tabID: tab.id)
        do { _ = try await task.value; XCTFail("Cancelled primary returned material") } catch {}
        XCTAssertTrue(request.token.isCancelled)
        let reads = await f.credentials.readCount; XCTAssertEqual(reads, 0)
        await f.connector.fail(index); await driver.waitForCleanup()
        XCTAssertEqual(driver.state, .disconnected(nil))
    }
    func testTypedPrimaryWrongGenerationIsRejectedBeforeCredentialAccess() async throws {
        let f = try fixture(saved: true), (tab, driver, _, index) = try await opened(f)
        let token = try XCTUnwrap(driver.token)
        let request = SessionPrimaryRequest(token: SessionToken(sessionID: token.sessionID, generation: token.generation + 1),
            id: UUID(), nativeSessionID: UUID(), purpose: .password, key: nil)
        do { _ = try await f.controller.readTypedPrimary(request, tabID: tab.id, expectedHost: f.host); XCTFail("Wrong generation read a credential") } catch {}
        let reads = await f.credentials.readCount; XCTAssertEqual(reads, 0)
        driver.cancel(); await f.connector.fail(index); await driver.waitForCleanup()
    }
    func testSavedRevocationDuringDriverFinalMetadataAwaitRejectsReturnedMaterial() async throws {
        let f = try fixture(saved: true), (_, driver, request, index) = try await opened(f)
        await f.repository.pauseMetadataRead(5)
        let task = Task { try await request.primary(primary(request)) }
        try await f.repository.metadataGate.arrived()
        await f.repository.revokePassword(f.host.id)
        await f.repository.metadataGate.release()
        do { _ = try await task.value; XCTFail("Final native-provider revalidation missed revocation") } catch {}
        let reads = await f.credentials.readCount; XCTAssertEqual(reads, 1)
        driver.cancel(); await f.connector.fail(index); await driver.waitForCleanup()
    }
    func testPreparedIntentMetadataRefreshPreservesButTrueConfigurationChangeRevokes() async throws {
        let f = try fixture(), intent = VaultTransientConnectionIntent(host: f.host, secret: .init(utf8: UUID().uuidString))
        let prepared = try await f.controller.prepareTransient(f.host, intent: intent, candidateBuilder: f.builder) { _ in true }
        await f.repository.rename(f.host.id)
        f.controller.metadataDidRefresh(try await f.repository.securityMetadata())
        XCTAssertFalse(intent.consumed)
        await f.repository.changeEndpoint(f.host.id)
        f.controller.metadataDidRefresh(try await f.repository.securityMetadata())
        XCTAssertTrue(intent.consumed); XCTAssertThrowsError(try prepared.commit())
        XCTAssertTrue(f.controller.tabs.isEmpty)
    }
    func testTwoSessionsManualMultiEchoZeroAndCancelAOnlyNeverReadsSaved() async throws {
        let f = try fixture(saved: true)
        let (a, ad, ar, ai) = try await opened(f), (b, bd, br, bi) = try await opened(f)
        let aReply = ChallengeReply<[Data]>(), bReply = ChallengeReply<[Data]>()
        ar.keyboard(challenge(2), aReply); br.keyboard(challenge(3), bReply)
        let ap = try await nextPrompt(a), bp = try await nextPrompt(b)
        XCTAssertNotEqual(ap.id, bp.id); XCTAssertNotEqual(ap.token.sessionID, bp.token.sessionID)
        if case .keyboard(let name, _, let fields) = bp.payload {
            XCTAssertTrue(name.contains("\\u{001B}")); XCTAssertEqual(fields.map(\.echo), [true, false, true])
        } else { XCTFail("Expected typed KI") }
        XCTAssertFalse(f.controller.respond(.answers([]), to: ap, tabID: b.id))
        f.controller.cancelChallenge(ap, tabID: a.id)
        XCTAssertTrue(ar.token.isCancelled); XCTAssertFalse(br.token.isCancelled); XCTAssertEqual(b.authentication, bp)
        XCTAssertFalse(aReply.resolve([]), "Cancel is not a successful empty notification answer")
        XCTAssertTrue(f.controller.respond(.answers([.init(utf8: "visible"), .init(utf8: "masked"), .init(utf8: "third")]), to: bp, tabID: b.id))
        XCTAssertFalse(bReply.resolve([]), "The exact round was already answered once")
        let zero = ChallengeReply<[Data]>(); br.keyboard(challenge(0), zero)
        let notice = try await nextPrompt(b)
        XCTAssertNotEqual(notice.id, bp.id)
        XCTAssertTrue(f.controller.respond(.answers([]), to: notice, tabID: b.id)); XCTAssertFalse(br.token.isCancelled)
        XCTAssertFalse(zero.resolve([]))
        let reads = await f.credentials.readCount; XCTAssertEqual(reads, 0)
        bd.cancel(); await f.connector.fail(ai); await f.connector.fail(bi)
        await ad.waitForCleanup(); await bd.waitForCleanup()
    }
    func testAutomaticPresentationOnlyCurrentOwnerAndLateDismissCannotCloseNewSheet() async throws {
        let f = try fixture(), (a, ad, ar, ai) = try await opened(f), (b, bd, br, bi) = try await opened(f)
        ar.keyboard(challenge(1), ChallengeReply<[Data]>())
        let ap = try await nextPrompt(a)
        XCTAssertFalse(f.controller.presentPendingChallenge(tabID: a.id, modalAvailable: true))
        f.controller.select(a.id)
        XCTAssertFalse(f.controller.presentPendingChallenge(tabID: a.id, modalAvailable: false)); XCTAssertNil(a.dialog)
        XCTAssertTrue(f.controller.presentPendingChallenge(tabID: a.id, modalAvailable: true))
        let old = try XCTUnwrap(a.dialog?.id)
        f.controller.select(b.id); br.keyboard(challenge(1), ChallengeReply<[Data]>()); _ = try await nextPrompt(b)
        XCTAssertTrue(f.controller.presentPendingChallenge(tabID: b.id, modalAvailable: true))
        let current = b.dialog?.id
        f.controller.dismissDialog(old, tabID: a.id); XCTAssertEqual(b.dialog?.id, current)
        XCTAssertEqual(a.authentication, ap)
        ad.cancel(); bd.cancel(); await f.connector.fail(ai); await f.connector.fail(bi)
        await ad.waitForCleanup(); await bd.waitForCleanup()
    }
    func testNativeTrustOnceReplyConsumesExactOwnerWithoutPersistingAtAppMailbox() async throws {
        let f = try fixture(), (tab, driver, request, index) = try await opened(f)
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("Trust").path))
        let key = try adapterHostKey(7), identity = request.configuration.host
        guard case .pending(let pending) = try await store.evaluate(host: identity, key: key) else { return XCTFail("Expected real Store pending decision") }
        let reply = ChallengeReply<FileHostTrustAnswer>()
        request.trust(.pending(pending), reply)
        let prompt = try await nextTrust(tab)
        try await driver.accept(prompt, persistence: .once)
        XCTAssertFalse(reply.resolve(.reject)); XCTAssertEqual(prompt.id, pending.id)
        guard case .pending = try await store.evaluate(host: identity, key: key) else { return XCTFail("Logical mailbox must not itself persist trust") }
        do { try await driver.accept(prompt, persistence: .persistent); XCTFail("Double trust answer accepted") } catch {}
        driver.cancel(); await f.connector.fail(index); await driver.waitForCleanup()
    }
    func testAppChangedEventRecordSurvivesImmediateTransportCleanupWithoutAcceptPath() async throws {
        let f = try fixture(), (tab, driver, request, index) = try await opened(f)
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("Trust").path))
        let identity = request.configuration.host
        guard case .pending(let first) = try await store.evaluate(host: identity, key: adapterHostKey(8)) else { return XCTFail("Expected initial trust") }
        _ = try await store.confirm(first, displayedFingerprint: first.fingerprint)
        guard case .rejected(let change) = try await store.evaluate(host: identity, key: adapterHostKey(9)) else { return XCTFail("Expected actual Store changed metadata") }
        let reply = ChallengeReply<FileHostTrustAnswer>()
        request.trust(.changed(change), reply)
        // Virtual consumer delivers a changed event before closing. This does not
        // prove the frozen native runtime always delivers its asynchronous callback.
        await f.connector.fail(index)
        let prompt = try await nextTrust(tab)
        await driver.waitForCleanup()
        XCTAssertEqual(prompt.changed, change); XCTAssertEqual(tab.trust.first?.changed, change)
        XCTAssertEqual(prompt.token, driver.token); XCTAssertEqual(driver.state, .failed(.trustRejected))
        XCTAssertFalse(reply.resolve(.confirm(displayedFingerprint: change.presentedFingerprint)))
        let accepted = await f.controller.accept(prompt, tabID: tab.id, persistence: .once)
        XCTAssertFalse(accepted)
        XCTAssertTrue(f.controller.presentPendingChallenge(tabID: tab.id, modalAvailable: true))
        f.controller.cancelTrust(prompt, tabID: tab.id); XCTAssertTrue(tab.trust.isEmpty)
    }
    private func changedFact(_ identity: HostIdentity) async throws -> ChangedHostKey {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("Trust").path))
        guard case .pending(let first) = try await store.evaluate(host: identity, key: adapterHostKey(21)) else { throw AdapterWaitFailure.timeout }
        try await store.confirm(first, displayedFingerprint: first.fingerprint)
        guard case .rejected(let changed) = try await store.evaluate(host: identity, key: adapterHostKey(22)) else { throw AdapterWaitFailure.timeout }
        return changed
    }
    func testTypedChangedErrorOnlySurvivesNativeTokenCancellationWithoutCredentialRead() async throws {
        let f = try fixture(saved: true), (tab, driver, request, index) = try await opened(f)
        let changed = try await changedFact(request.configuration.host)
        await f.connector.failAfterNativeCleanup(index, error: NativeShellError(.untrusted, operation: "host-key", changedHostKey: changed))
        let prompt = try await nextTrust(tab)
        try await wait { driver.canReconnect }
        XCTAssertTrue(request.token.isCancelled); XCTAssertEqual(prompt.changed, changed)
        XCTAssertEqual(prompt.host, request.configuration.host); XCTAssertEqual(prompt.token, driver.token)
        XCTAssertEqual(driver.state, .failed(.trustRejected)); XCTAssertEqual(driver.failureDetail?.category, .trustRejected)
        let accepted = await f.controller.accept(prompt, tabID: tab.id, persistence: .persistent)
        XCTAssertFalse(accepted)
        let reads = await f.credentials.readCount, count = await f.connector.count
        XCTAssertEqual(reads, 0); XCTAssertEqual(count, 1)
    }
    func testTypedChangedErrorFirstDelayedCallbackCannotReplaceOrReviveDismissedPrompt() async throws {
        let f = try fixture(), (tab, driver, request, index) = try await opened(f)
        let changed = try await changedFact(request.configuration.host)
        await f.connector.fail(index, error: NativeShellError(.untrusted, operation: "host-key", changedHostKey: changed))
        let prompt = try await nextTrust(tab)
        try await wait { driver.canReconnect }
        let reply = ChallengeReply<FileHostTrustAnswer>()
        request.trust(.changed(changed), reply)
        await Task.yield()
        XCTAssertEqual(tab.trust.first?.id, prompt.id)
        f.controller.cancelTrust(prompt, tabID: tab.id)
        request.trust(.changed(changed), ChallengeReply<FileHostTrustAnswer>())
        await Task.yield()
        XCTAssertTrue(tab.trust.isEmpty); XCTAssertNil(tab.dialog)
        XCTAssertFalse(reply.resolve(.confirmOnce(displayedFingerprint: changed.presentedFingerprint)))
    }
    func testTypedChangedCallbackFirstKeepsOnePromptUntilActualSetupCatch() async throws {
        let f = try fixture(), (tab, driver, request, index) = try await opened(f)
        let changed = try await changedFact(request.configuration.host), reply = ChallengeReply<FileHostTrustAnswer>()
        request.trust(.changed(changed), reply)
        let prompt = try await nextTrust(tab)
        XCTAssertFalse(driver.canReconnect)
        await f.connector.failAfterNativeCleanup(index, error: NativeShellError(.untrusted, operation: "host-key", changedHostKey: changed))
        try await wait { driver.canReconnect }
        XCTAssertEqual(tab.trust.first?.id, prompt.id); XCTAssertEqual(tab.trust.count, 1)
        XCTAssertEqual(driver.state, .failed(.trustRejected)); XCTAssertTrue(driver.snapshot.interactionsDrained)
        XCTAssertFalse(reply.resolve(.confirm(displayedFingerprint: changed.presentedFingerprint)))
    }
    func testTypedChangedAfterOwnerCancelOrTabCloseNeverResurrectsPresentation() async throws {
        for closeTab in [false, true] {
            let f = try fixture(), (tab, driver, request, index) = try await opened(f)
            let changed = try await changedFact(request.configuration.host)
            await f.connector.holdFailure(index, error: NativeShellError(.untrusted, operation: "host-key", changedHostKey: changed))
            try await f.connector.failureHeld(index)
            if closeTab { driver.closeTab() } else { driver.cancel() }
            await f.connector.releaseFailure(index)
            await driver.waitForCleanup()
            let reply = ChallengeReply<FileHostTrustAnswer>()
            request.trust(.changed(changed), reply)
            await Task.yield()
            XCTAssertTrue(tab.trust.isEmpty); XCTAssertNil(tab.dialog)
            XCTAssertEqual(driver.state, closeTab ? .closed : .disconnected(nil))
            XCTAssertFalse(reply.resolve(.confirmOnce(displayedFingerprint: changed.presentedFingerprint)))
        }
    }
    func testTypedChangedOldGenerationCannotReappearDuringExplicitReconnectOrGenericFailure() async throws {
        let f = try fixture(), (tab, driver, old, index) = try await opened(f)
        let changed = try await changedFact(old.configuration.host)
        await f.connector.fail(index, error: NativeShellError(.untrusted, operation: "host-key", changedHostKey: changed))
        let oldPrompt = try await nextTrust(tab); try await wait { driver.canReconnect }
        f.controller.cancelTrust(oldPrompt, tabID: tab.id)
        let previous = driver.token
        f.controller.reconnect(tab.id); await tab.preparation?.value
        let current = try await f.connector.request(index + 1)
        XCTAssertNotEqual(driver.token, previous)
        old.trust(.changed(changed), ChallengeReply<FileHostTrustAnswer>())
        await Task.yield()
        XCTAssertTrue(tab.trust.isEmpty); XCTAssertFalse(current.token.isCancelled)
        await f.connector.fail(index + 1, error: NativeShellError(.transport, operation: "connect"))
        try await wait { driver.canReconnect }
        XCTAssertTrue(tab.trust.isEmpty); XCTAssertEqual(driver.failureDetail?.category, .networkUnavailable)
    }
    func testTypedChangedWrongEndpointFailsClosedAndValidARejectionDoesNotAffectConnectedB() async throws {
        let f = try fixture(), (a, ad, ar, ai) = try await opened(f), (b, bd, br, bi) = try await opened(f)
        let transport = AdapterTransport()
        await f.connector.succeed(bi, transport: transport); try await nextState(bd, .connected)
        let wrongHost = HostIdentity(address: ar.configuration.host.address, port: try SSHPort(Int(ar.configuration.host.port.value) + 1))
        let wrong = try await changedFact(wrongHost)
        await f.connector.fail(ai, error: NativeShellError(.untrusted, operation: "host-key", changedHostKey: wrong))
        try await wait { ad.canReconnect }
        XCTAssertTrue(a.trust.isEmpty); XCTAssertEqual(ad.state, .failed(.trustRejected))
        f.controller.reconnect(a.id); await a.preparation?.value
        let nextIndex = await f.connector.count - 1, next = try await f.connector.request(nextIndex)
        let changed = try await changedFact(next.configuration.host)
        await f.connector.failAfterNativeCleanup(nextIndex, error: NativeShellError(.untrusted, operation: "host-key", changedHostKey: changed))
        _ = try await nextTrust(a); try await wait { ad.canReconnect }
        XCTAssertEqual(bd.state, .connected); XCTAssertTrue(b.trust.isEmpty); XCTAssertFalse(br.token.isCancelled)
        XCTAssertFalse(transport.closed)
        bd.cancel(); await bd.waitForCleanup()
    }
    private func nextTrust(_ tab: SessionTab) async throws -> SessionTrustPrompt {
        let deadline = ContinuousClock.now + .seconds(3)
        while tab.trust.isEmpty {
            guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
        return try XCTUnwrap(tab.trust.first)
    }
    func testCancelledReadyCannotResurrectAndExplicitReconnectUsesFreshNativeBoundary() async throws {
        let f = try fixture(), (_, driver, _, index) = try await opened(f)
        let view = driver.terminal, oldToken = driver.token
        driver.cancel()
        let late = AdapterTransport(); await f.connector.succeed(index, transport: late); await driver.waitForCleanup()
        XCTAssertEqual(driver.state, .disconnected(nil)); XCTAssertTrue(driver.terminal === view)
        XCTAssertTrue(late.closed); XCTAssertTrue(driver.canReconnect)
        f.controller.reconnect(try XCTUnwrap(oldToken?.sessionID)); await f.controller.selectedTab?.preparation?.value
        let request = try await f.connector.request(index + 1)
        XCTAssertNotEqual(driver.token, oldToken); XCTAssertFalse(request.token.isCancelled)
        driver.cancel(); await f.connector.fail(index + 1); await driver.waitForCleanup()
    }
    func testDriverPullInputResizeAndCloseWaitActualDrainRetainView() async throws {
        let f = try fixture(), (tab, driver, _, index) = try await opened(f), transport = AdapterTransport()
        addTeardownBlock { await MainActor.run { transport.holdDrain = false; transport.cancel() } }
        await f.connector.succeed(index, transport: transport); try await nextState(driver, .connected)
        try await transport.waitForReceive()
        XCTAssertEqual(transport.receiveLimits, [64 * 1024]); XCTAssertEqual(transport.maximumConcurrentReceives, 1)
        let bytes = Array(repeating: UInt8(65), count: 256 * 1024)
        XCTAssertTrue(driver.admitInput(bytes[...]))
        XCTAssertFalse(driver.admitInput([66][...])); XCTAssertEqual(driver.snapshot.pendingInputBytes, 256 * 1024)
        try await transport.waitForWrite(); transport.releaseWrites()
        try await wait { driver.snapshot.pendingInputBytes == 0 }
        for _ in 0..<128 { XCTAssertTrue(driver.admitInput([67][...])) }
        XCTAssertFalse(driver.admitInput([68][...])); XCTAssertEqual(driver.snapshot.pendingInputItems, 128)
        try await transport.waitForResize()
        driver.resize(columns: 100, rows: 30); driver.resize(columns: 120, rows: 40); driver.resize(columns: 140, rows: 50)
        transport.releaseResize()
        try await transport.waitForResizeCount(2)
        XCTAssertEqual(transport.sizes.last, try NativeShellSize(columns: 140, rows: 50)); XCTAssertEqual(transport.maximumConcurrentResizes, 1)
        transport.releaseReceive(.bytes(Data("retained-history\r\n".utf8)))
        try await transport.waitForReceiveCount(2)
        XCTAssertTrue(driver.terminal.text.contains("retained-history")); XCTAssertEqual(transport.maximumConcurrentReceives, 1)
        let terminal = driver.terminal
        transport.holdDrain = true
        driver.closeTab(); try await transport.waitForClose()
        XCTAssertNotEqual(driver.state, .closed); XCTAssertFalse(driver.snapshot.interactionsDrained)
        XCTAssertTrue(driver.snapshot.nativeCloseCompleted || driver.state == .closing)
        transport.holdDrain = false; await driver.waitForCleanup()
        XCTAssertEqual(driver.state, .closed); XCTAssertTrue(driver.snapshot.nativeCloseCompleted); XCTAssertTrue(driver.snapshot.interactionsDrained)
        XCTAssertNil(driver.snapshot.ownedPID); XCTAssertTrue(driver.terminal === terminal)
        await f.controller.closeTab(tab.id)
    }
    func testSaveAndFinishTransientPreparesWhileWritingButCommitsOnlyAfterExactDismiss() async throws {
        let f = try fixture(), vault = VaultDesktopModel(repository: f.repository, preferenceKey: UUID().uuidString)
        _ = await vault.load()
        let owner = PresentationOwner<String>(); owner.present("editor"); let ownerID = try XCTUnwrap(owner.item?.id)
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: f.host, settings: AppSettings()), ownsPresentation: { owner.owns(ownerID) })
        editor.password = UUID().uuidString; editor.draft.configuration.name = "saved before candidate"
        var started = 0, prepared = 0
        let result = await editor.saveAndFinish(security: f.security, vault: vault, prepareConnection: { saved, secret in
            prepared += 1; XCTAssertTrue(editor.writing); XCTAssertTrue(owner.owns(ownerID)); XCTAssertNotNil(secret)
            return VaultPreparedConnection(commit: {
                XCTAssertFalse(editor.writing); XCTAssertNil(owner.item); started += 1
                XCTAssertEqual(saved.name, "saved before candidate")
            }, cancel: { XCTFail("Current successful preparation unexpectedly cancelled") })
        }, dismiss: { owner.dismiss(ownerID) })
        XCTAssertTrue(result); XCTAssertEqual(prepared, 1); XCTAssertEqual(started, 1); XCTAssertTrue(editor.password.isEmpty)
        let metadata = try await f.repository.securityMetadata(); XCTAssertNil(metadata.hosts.first?.credentialRef)
        let saves = await f.credentials.saveCount; XCTAssertEqual(saves, 0, "Save-only without remember never persists input")
    }
    func testRealAppConsumerRememberCommitRoutesFreshCandidateAfterDirtyOwnerDismiss() async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let repository = AppRepository(location: .isolated(root)), credentials = FakeCredentials()
        let security = SecurityCoordinator(repository: repository, location: .isolated(root), credentials: credentials)
        let connector = AdapterConnector(), environment = SessionEnvironment(location: .isolated(root))
        let candidate = NativeSessionBuilder(repository: repository, security: security, environment: environment, connector: connector)
        let app = AppModel(repository: repository, security: security, location: .isolated(root), nativeCandidateBuilder: candidate)
        addTeardownBlock { await connector.cancelAll(); await app.sessions.closeAll(); try await security.close(); try await repository.close(); try FileManager.default.removeItem(at: root) }
        let host = HostConfiguration(name: "App consumer", address: "never-connected.invalid", username: "fixture")
        try await repository.apply([.insertHost(host)])
        let vault = VaultDesktopModel(app: app); _ = await vault.load()
        let owner = PresentationOwner<String>(); owner.present("editor"); let ownerID = try XCTUnwrap(owner.item?.id)
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: host, settings: AppSettings()), ownsPresentation: { owner.owns(ownerID) })
        let secret = UUID().uuidString; editor.password = secret; editor.remember = true
        app.registerWorkspaceNavigationGuard(owner: ownerID) { owner.item == nil }
        let completed = await editor.saveAndFinish(security: security, vault: vault, prepareConnection: { saved, material in
            XCTAssertTrue(editor.writing); XCTAssertEqual(app.workspacePage, .vault); XCTAssertTrue(app.sessions.tabs.isEmpty)
            return try await app.prepareTransientConnection(saved, intent: VaultTransientConnectionIntent(host: saved, secret: material))
        }, dismiss: { owner.dismiss(ownerID) })
        XCTAssertTrue(completed); XCTAssertNil(owner.item); XCTAssertEqual(app.sessions.tabs.count, 1)
        let tab = try XCTUnwrap(app.sessions.selectedTab)
        XCTAssertEqual(app.workspacePage, .session(tab.id)); XCTAssertTrue(tab.driver is NativeSessionDriver)
        let storedMetadata = try await repository.securityMetadata()
        let stored = try XCTUnwrap(storedMetadata.hosts.first)
        XCTAssertNotNil(stored.credentialRef); XCTAssertTrue(stored.savePasswordAuthorized)
        XCTAssertEqual(tab.host?.credentialRef, stored.credentialRef)
        XCTAssertEqual(app.connectionNotice, .opened(SessionRequest(hostID: host.id, mode: .newSession), tab.id))
        let request = try await connector.request(0)
        guard case .password(let bytes) = try await request.primary(primary(request)) else { return XCTFail("Expected typed one-time password") }
        XCTAssertEqual(bytes, Data(secret.utf8))
        let reads = await credentials.readCount, saves = await credentials.saveCount
        XCTAssertEqual(reads, 0, "Explicit once material wins without rereading newly saved credential"); XCTAssertEqual(saves, 1)
        let driver = try XCTUnwrap(tab.driver as? NativeSessionDriver)
        driver.cancel(); await connector.fail(0); await driver.waitForCleanup()
        app.sessions.reconnect(tab.id); await tab.preparation?.value
        let next = try await connector.request(1)
        _ = try await next.primary(primary(next))
        let reconnectedReads = await credentials.readCount
        XCTAssertEqual(reconnectedReads, 1, "New generation may use exact saved authorization, never the consumed intent")
        XCTAssertEqual(driver.token?.generation, 2); XCTAssertTrue(tab.driver === driver)
        driver.cancel(); await connector.fail(1); await driver.waitForCleanup()
    }
    func testSaveAndFinishLatePreparedOwnerCannotStartOrDismissReplacement() async throws {
        let f = try fixture(), vault = VaultDesktopModel(repository: f.repository, preferenceKey: UUID().uuidString), gate = AdapterGate()
        _ = await vault.load(); await gate.arm()
        let owner = PresentationOwner<String>(); owner.present("old"); let id = try XCTUnwrap(owner.item?.id)
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: f.host, settings: AppSettings()), ownsPresentation: { owner.owns(id) })
        editor.password = UUID().uuidString; editor.draft.configuration.name = "saved old"
        var cancelled = 0, starts = 0, dismisses = 0
        let save = Task { await editor.saveAndFinish(security: f.security, vault: vault, prepareConnection: { _, _ in
            try await gate.wait()
            return VaultPreparedConnection(commit: { starts += 1 }, cancel: { cancelled += 1 })
        }, dismiss: { dismisses += 1; owner.dismiss(id) }) }
        try await gate.arrived(); owner.present("new"); let next = owner.item?.id; editor.deactivate()
        await gate.release(); let completed = await save.value
        XCTAssertFalse(completed); XCTAssertEqual(starts, 0); XCTAssertEqual(cancelled, 1); XCTAssertEqual(dismisses, 0)
        XCTAssertEqual(owner.item?.id, next)
        let metadata = try await f.repository.securityMetadata(); XCTAssertEqual(metadata.hosts.first?.name, "saved old")
    }
    func testSaveAndFinishDismissRefusalCancelsPreparedAndPreservesCommittedConfiguration() async throws {
        let f = try fixture(), vault = VaultDesktopModel(repository: f.repository, preferenceKey: UUID().uuidString)
        _ = await vault.load()
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: f.host, settings: AppSettings()))
        editor.draft.configuration.name = "commit is not rollback"; editor.password = UUID().uuidString
        var cancelled = 0, started = 0
        let result = await editor.saveAndFinish(security: f.security, vault: vault,
            prepareConnection: { _, _ in VaultPreparedConnection(commit: { started += 1 }, cancel: { cancelled += 1 }) }, dismiss: {})
        XCTAssertFalse(result); XCTAssertEqual(cancelled, 1); XCTAssertEqual(started, 0)
        let metadata = try await f.repository.securityMetadata(); XCTAssertEqual(metadata.hosts.first?.name, "commit is not rollback")
        XCTAssertFalse(editor.draft.isDirty); XCTAssertTrue(editor.password.isEmpty)
    }
}

private func adapterHostKey(_ byte: UInt8) throws -> HostPublicKey {
    var blob = Data()
    for part in [Data("ssh-ed25519".utf8), Data(repeating: byte, count: 32)] {
        var length = UInt32(part.count).bigEndian
        withUnsafeBytes(of: &length) { blob.append(contentsOf: $0) }; blob.append(part)
    }
    return try HostPublicKey(algorithm: "ssh-ed25519", base64: blob.base64EncodedString())
}

@MainActor private struct AdapterFixture {
    let host: HostConfiguration
    let repository: AdapterRepository
    let credentials: AdapterCredentials
    let security: SecurityCoordinator
    let connector: AdapterConnector
    let builder: NativeSessionBuilder
    let controller: SessionController
}
private enum AdapterWaitFailure: Error { case timeout }
private actor AdapterGate {
    private var armed = false, reached = false
    func arm() { armed = true; reached = false }
    func wait() async throws {
        guard armed else { return }; reached = true
        let deadline = ContinuousClock.now + .seconds(3)
        while armed {
            guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    func arrived() async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while !reached {
            guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    func release() { armed = false }
}
private actor AdapterCredentials: CredentialAccess {
    let gate = AdapterGate()
    private(set) var readCount = 0, saveCount = 0
    func read(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialReadResult {
        readCount += 1
        do { try await gate.wait() } catch { return .manualEntryRequired(.unavailable) }
        return .available(.init(utf8: UUID().uuidString))
    }
    func save(_ secret: OpenLXSSHSecurity.SecretBytes, as reference: OpenLXSSHSecurity.CredentialReference, authorization: RememberAuthorization) -> CredentialSaveResult { saveCount += 1; return .saved(reference) }
    func deleteExact(_ reference: OpenLXSSHSecurity.CredentialReference) -> CredentialDeleteResult { .deleted }
    func close() {}
}
private actor AdapterRepository: AppRepositoryProtocol {
    let metadataGate = AdapterGate()
    let snapshotGate = AdapterGate()
    let markConnectedGate = AdapterMarkConnectedGate()
    private(set) var markConnectedCommits = 0
    private var metadataReadCount = 0
    private var metadataPause: Int?
    var hosts: [HostConfiguration]
    var credentials: [OpenLXSSHCore.CredentialReference]
    init(hosts: [HostConfiguration], credentials: [OpenLXSSHCore.CredentialReference]) { self.hosts = hosts; self.credentials = credentials }
    func delete(_ id: UUID) { hosts.removeAll { $0.id == id } }
    func revokePassword(_ id: UUID) { if let index = hosts.firstIndex(where: { $0.id == id }) { hosts[index].credentialRef = nil; hosts[index].savePasswordAuthorized = false } }
    func rename(_ id: UUID) { if let index = hosts.firstIndex(where: { $0.id == id }) { hosts[index].name = "metadata renamed"; hosts[index].isFavorite = true } }
    func changeEndpoint(_ id: UUID) { if let index = hosts.firstIndex(where: { $0.id == id }) { hosts[index].port += 1 } }
    func pauseMetadataRead(_ offset: Int) async { metadataPause = metadataReadCount + offset; await metadataGate.arm() }
    func securityMetadata() async throws -> SecurityMetadata {
        metadataReadCount += 1
        if metadataReadCount == metadataPause { metadataPause = nil; try await metadataGate.wait() }
        return SecurityMetadata(hosts: hosts, keys: [], credentials: credentials, tickets: [])
    }
    func snapshot(query: HostQuery) async throws -> AppSnapshot {
        try await snapshotGate.wait()
        return AppSnapshot(hosts: hosts, folders: [], keys: [], settings: AppSettings())
    }
    func apply(_ changes: [RepositoryChange]) async throws {
        for change in changes {
            switch change {
            case .markConnected(let hostID, let date):
                try await markConnectedGate.wait()
                guard let index = hosts.firstIndex(where: { $0.id == hostID }) else { throw RepositoryError.notFound }
                hosts[index].lastConnectedAt = date; markConnectedCommits += 1
            case .insertHost(let host): hosts.append(host)
            case .updateHost(let host), .updateHostIfUnchanged(let host, _):
                guard let index = hosts.firstIndex(where: { $0.id == host.id }) else { throw RepositoryError.notFound }; hosts[index] = host
            case .registerCredential(let credential): credentials.append(credential)
            default: break
            }
        }
    }
    func copyHost(id: UUID) throws -> HostConfiguration { throw RepositoryError.notFound }
    func copyFolder(id: UUID) throws -> HostFolder { throw RepositoryError.notFound }
    func close() {}
}
private actor AdapterConnector: NativeSessionConnecting {
    private var requests: [NativeSessionConnect] = []
    private var results: [Int: Result<any NativeSessionTransport, any Error>] = [:]
    private var heldFailures: [Int: any Error] = [:]
    private var enteredFailures = Set<Int>()
    private var releasedFailures = Set<Int>()
    private var unclassifiedFailures = Set<Int>()
    var count: Int { requests.count }
    func connect(_ request: NativeSessionConnect) async throws -> any NativeSessionTransport {
        try request.token.check()
        let index = requests.count; requests.append(request)
        do {
            // This fake never creates a native owner. A cancellation of its polling
            // is therefore an explicit fixture fact, not a production error-type rule.
            try request.token.check()
            let deadline = ContinuousClock.now + .seconds(3)
            while results[index] == nil {
                if let failure = heldFailures[index] {
                    enteredFailures.insert(index)
                    while !releasedFailures.contains(index) {
                        guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
                        await withCheckedContinuation { continuation in
                            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(10)) { continuation.resume() }
                        }
                    }
                    heldFailures[index] = nil; throw failure
                }
                try request.token.check()
                guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
                try await Task.sleep(for: .milliseconds(10))
            }
            return try results.removeValue(forKey: index)!.get()
        } catch {
            if unclassifiedFailures.remove(index) != nil || error is NativeSessionConnectionFailure { throw error }
            throw NativeSessionConnectionFailure(failure: error, drain: nil, noNativeOwnerCreated: true)
        }
    }
    func request(_ index: Int) async throws -> NativeSessionConnect {
        let deadline = ContinuousClock.now + .seconds(3)
        while !requests.indices.contains(index) {
            guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
        return requests[index]
    }
    func succeed(_ index: Int, transport: AdapterTransport) async {
        if requests.indices.contains(index), requests[index].token.isCancelled { await transport.close() }
        else { results[index] = .success(transport) }
    }
    func fail(_ index: Int, error: any Error = CancellationError()) { results[index] = .failure(error) }
    func failUnclassified(_ index: Int, error: any Error) {
        unclassifiedFailures.insert(index); results[index] = .failure(error)
    }
    func failAfterNativeCleanup(_ index: Int, error: any Error) {
        results[index] = .failure(error); requests[index].token.cancel()
    }
    func holdFailure(_ index: Int, error: any Error) { heldFailures[index] = error }
    func failureHeld(_ index: Int) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while !enteredFailures.contains(index) {
            guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    func releaseFailure(_ index: Int) { releasedFailures.insert(index) }
    func cancelAll() {
        for request in requests { request.token.cancel() }
        releasedFailures.formUnion(heldFailures.keys); results = [:]
    }
}
/// Logical event-driven receipt only. It cannot create a native session or prove SSH.
private final class RetirementTestDrain: SessionDrainObserving, @unchecked Sendable {
    let id = UUID()
    var maximumObservers = 64
    private let lock = NSLock()
    private var value = SessionDrainSnapshot(pendingTasks: 1, pendingProviders: 1, revoked: false, nativeClosed: false, producersSealed: false)
    private var observers: [UUID: @Sendable (SessionDrainSnapshot) -> Void] = [:]
    var snapshot: SessionDrainSnapshot { lock.withLock { value } }
    func setClosed(pending: Int) {
        update(.init(pendingTasks: pending, pendingProviders: pending, revoked: true, nativeClosed: true, producersSealed: true))
    }
    func complete() { setClosed(pending: 0) }
    func update(_ value: SessionDrainSnapshot) {
        let callbacks = lock.withLock { () -> [@Sendable (SessionDrainSnapshot) -> Void] in
            self.value = value
            guard value.drained else { return [] }
            let result = Array(observers.values); observers = [:]; return result
        }
        for callback in callbacks { callback(value) }
    }
    func observeCompletion(_ callback: @escaping @Sendable (SessionDrainSnapshot) -> Void) throws -> UUID {
        let id = UUID()
        let immediate = try lock.withLock { () throws -> SessionDrainSnapshot? in
            if value.drained { return value }
            guard observers.count < maximumObservers else { throw NativeShellError(.resourceLimit, operation: "test-observer-capacity") }
            observers[id] = callback; return nil
        }
        if let immediate { callback(immediate) }
        return id
    }
    func removeCompletionObserver(_ id: UUID) { lock.withLock { _ = observers.removeValue(forKey: id) } }
}

/// MainActor virtual IO only; thread-safe nonisolated token checks are not a real socket.
@MainActor private final class AdapterTransport: NativeSessionTransport {
    nonisolated let transportKeepalive: NativeTCPKeepaliveSnapshot?
    init(keepalive: NativeTCPKeepaliveSnapshot? = nil) { transportKeepalive = keepalive }
    private(set) var closed = false
    private(set) var closeCalls = 0
    private(set) var closeEntered = false
    var holdClose = false
    private var closeReply: CheckedContinuation<Void, Never>?
    let drain = RetirementTestDrain()
    nonisolated var retirementDrain: any SessionDrainObserving { drain }
    var holdDrain = false {
        didSet { if closed && !holdDrain { drain.complete() } }
    }
    var interactionsDrained: Bool { drain.snapshot.drained }
    private(set) var receiveLimits: [Int] = []
    private(set) var maximumConcurrentReceives = 0
    private var receiveReply: CheckedContinuation<NativeShellReceive, any Error>?
    private(set) var sizes: [NativeShellSize] = []
    private(set) var maximumConcurrentResizes = 0
    private var resizeReplies: [CheckedContinuation<Void, any Error>] = []
    private var writeReplies: [CheckedContinuation<Void, any Error>] = []
    func receive(maxBytes: Int, wait: TimeInterval, token: CancellationToken) async throws -> NativeShellReceive {
        try token.check(); receiveLimits.append(maxBytes); maximumConcurrentReceives = max(maximumConcurrentReceives, receiveReply == nil ? 1 : 2)
        return try await withCheckedThrowingContinuation { reply in
            receiveReply = reply
        }
    }
    func write(_ bytes: Data, token: CancellationToken) async throws {
        try token.check()
        try await withCheckedThrowingContinuation { (reply: CheckedContinuation<Void, any Error>) in writeReplies.append(reply) }
    }
    func resize(_ size: NativeShellSize, token: CancellationToken) async throws {
        try token.check(); sizes.append(size); maximumConcurrentResizes = max(maximumConcurrentResizes, resizeReplies.count + 1)
        try await withCheckedThrowingContinuation { (reply: CheckedContinuation<Void, any Error>) in
            resizeReplies.append(reply)
        }
    }
    func releaseReceive(_ value: NativeShellReceive) { let reply = receiveReply; receiveReply = nil; reply?.resume(returning: value) }
    func failReceive(_ failure: any Error) { let reply = receiveReply; receiveReply = nil; reply?.resume(throwing: failure) }
    func releaseResize() { let values = resizeReplies; resizeReplies = []; for value in values { value.resume() } }
    func releaseWrites() { let values = writeReplies; writeReplies = []; for value in values { value.resume() } }
    func failWrites(_ failure: any Error) { let values = writeReplies; writeReplies = []; for value in values { value.resume(throwing: failure) } }
    func failResize(_ failure: any Error) { let values = resizeReplies; resizeReplies = []; for value in values { value.resume(throwing: failure) } }
    func waitForReceive() async throws { try await waitForReceiveCount(1) }
    func waitForReceiveCount(_ count: Int) async throws { try await wait { self.receiveLimits.count >= count } }
    func waitForWrite() async throws { try await wait { !self.writeReplies.isEmpty } }
    func waitForResize() async throws { try await waitForResizeCount(1) }
    func waitForResizeCount(_ count: Int) async throws { try await wait { self.sizes.count >= count } }
    func waitForClose() async throws { try await wait { self.closed } }
    private func wait(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while !condition() {
            guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    nonisolated func cancel() { Task { @MainActor in cancelOnMain() } }
    private func cancelOnMain() {
        let read = receiveReply; receiveReply = nil; read?.resume(throwing: CancellationError())
        let writes = writeReplies; writeReplies = []; for write in writes { write.resume(throwing: CancellationError()) }
        let resizes = resizeReplies; resizeReplies = []; for resize in resizes { resize.resume(throwing: CancellationError()) }
    }
    func close() async {
        closeCalls += 1; closeEntered = true
        if holdClose { await withCheckedContinuation { closeReply = $0 } }
        cancelOnMain(); closed = true
        drain.setClosed(pending: holdDrain ? 1 : 0)
    }
    func releaseClose() {
        holdClose = false
        let reply = closeReply; closeReply = nil; reply?.resume()
    }
}

/// This gate delays only the logical acknowledgement after invoking the real UI
/// release API. It does not create GPU work or claim to prove a real Metal drain.
@MainActor private final class GPUCloseReleaseGate {
    var ready = false
    private(set) var calls = 0
    private(set) var realReleaseCompletions = 0
    func release(_ terminal: NativeTerminalView) -> Bool {
        calls += 1
        let actual = terminal.releaseResources()
        if actual { realReleaseCompletions += 1 }
        return actual && ready
    }
}

extension NativeSessionAdapterTests {
    private func gpuCloseDriver(_ gate: GPUCloseReleaseGate, holdDrain: Bool = false, holdClose: Bool = false) async throws
        -> (AdapterFixture, NativeSessionDriver, AdapterTransport, SessionRetirementRegistry) {
        let f = try fixture(), registry = SessionRetirementRegistry(), transport = AdapterTransport()
        transport.holdDrain = holdDrain; transport.holdClose = holdClose
        let driver = try NativeSessionDriver(sessionID: UUID(), host: f.host, repository: f.repository, security: f.security,
            connector: f.connector, retirementRegistry: registry, terminalRelease: { gate.release($0) })
        addTeardownBlock {
            await MainActor.run { gate.ready = true; transport.releaseClose(); transport.holdDrain = false }
            _ = await driver.closeResult(deadline: .now + .seconds(1))
            await driver.waitForCleanup()
        }
        _ = try driver.connect(SessionEnvironment.configuration(host: f.host, keyPath: nil), primary: SessionPrimaryAuthorization(provider: { _ in nil }))
        _ = try await f.connector.request(0)
        await f.connector.succeed(0, transport: transport)
        try await nextState(driver, .connected)
        try await transport.waitForReceive(); try await transport.waitForResize(); transport.releaseResize()
        return (f, driver, transport, registry)
    }
    func testGPUCloseWaitsForRealReleaseAcknowledgementAndRepeatedCloseIsIdempotent() async throws {
        let gate = GPUCloseReleaseGate(), (_, driver, transport, _) = try await gpuCloseDriver(gate)
        let deadline = ContinuousClock.now + .seconds(1)
        let closing = Task { @MainActor in await driver.closeResult(deadline: deadline) }
        try await wait { gate.calls > 0 }
        XCTAssertTrue(transport.closed); XCTAssertTrue(driver.snapshot.nativeCloseCompleted)
        XCTAssertFalse(driver.terminalResourcesReleased); XCTAssertFalse(driver.closeDisposition?.permitsRemoval ?? true)
        XCTAssertNotEqual(driver.state, .closed)
        try await Task.sleep(for: .milliseconds(20))
        gate.ready = true
        let result = await closing.value
        XCTAssertEqual(result, .closed)
        XCTAssertTrue(driver.terminalResourcesReleased); XCTAssertGreaterThan(gate.realReleaseCompletions, 0)
        let calls = gate.calls
        let repeated = await driver.closeResult(deadline: .now + .milliseconds(10))
        XCTAssertEqual(repeated, .closed)
        XCTAssertEqual(gate.calls, calls); XCTAssertEqual(transport.closeCalls, 1)
    }
    func testGPUCloseTimeoutRetainsIncompleteAndLateCompletionNeedsExplicitRetry() async throws {
        let gate = GPUCloseReleaseGate(), (_, driver, transport, _) = try await gpuCloseDriver(gate)
        let started = ContinuousClock.now
        let result = await driver.closeResult(deadline: started + .milliseconds(80))
        guard case .incomplete(let context) = result else { return XCTFail("UI pending must not be reported as complete native-only closure") }
        XCTAssertEqual(context.reason, .terminalPending); XCTAssertFalse(result.permitsRemoval)
        XCTAssertTrue(transport.closed); XCTAssertFalse(driver.terminalResourcesReleased); XCTAssertNotEqual(driver.state, .closed)
        XCTAssertLessThan(started.duration(to: .now), .milliseconds(500))
        await driver.waitForCleanup()
        let calls = gate.calls
        gate.ready = true
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(gate.calls, calls, "Native cleanup must not start a separate unbounded UI retry task")
        XCTAssertFalse(driver.terminalResourcesReleased); XCTAssertNotEqual(driver.state, .closed)
        let retried = await driver.closeResult(deadline: .now + .milliseconds(100))
        XCTAssertEqual(retried, .closed)
        XCTAssertEqual(transport.closeCalls, 1)
    }
    func testGPUCloseUsesRemainingNativeDeadlineWithoutStartingAnotherBudget() async throws {
        let gate = GPUCloseReleaseGate(), (_, driver, transport, _) = try await gpuCloseDriver(gate, holdClose: true)
        let deadline = ContinuousClock.now + .milliseconds(220)
        let closing = Task { @MainActor in await driver.closeResult(deadline: deadline) }
        try await wait { transport.closeEntered }
        let lateGPU = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(300)); gate.ready = true
        }
        try await Task.sleep(for: .milliseconds(160)); transport.releaseClose()
        let result = await closing.value
        guard case .incomplete(let context) = result else { return XCTFail("UI must not get a fresh budget after native close consumes the original one") }
        XCTAssertEqual(context.reason, .terminalPending); XCTAssertFalse(driver.terminalResourcesReleased)
        XCTAssertFalse(gate.ready, "The original deadline expires before the scheduled GPU acknowledgement")
        await lateGPU.value
        let retried = await driver.closeResult(deadline: .now + .milliseconds(100))
        XCTAssertEqual(retried, .closed)
    }
    func testGPUCloseCancellingOneObserverYieldsWithoutCancellingAnotherOwner() async throws {
        let gate = GPUCloseReleaseGate(), (_, driver, transport, _) = try await gpuCloseDriver(gate)
        let deadline = ContinuousClock.now + .seconds(1)
        let first = Task { @MainActor in await driver.closeResult(deadline: deadline) }
        try await wait { gate.calls > 0 }
        let second = Task { @MainActor in await driver.closeResult(deadline: deadline) }
        try await wait { driver.closeObservationCount == 2 }
        first.cancel()
        let cancelled = await first.value
        guard case .incomplete(let context) = cancelled else { return XCTFail("Cancelled observation must remain incomplete") }
        XCTAssertEqual(context.reason, .observationCancelled); XCTAssertEqual(driver.closeObservationCount, 1)
        var heartbeat = 0
        await Task { @MainActor in heartbeat += 1 }.value
        XCTAssertEqual(heartbeat, 1); XCTAssertFalse(driver.terminalResourcesReleased)
        gate.ready = true
        let completed = await second.value
        XCTAssertEqual(completed, .closed)
        XCTAssertEqual(transport.closeCalls, 1); XCTAssertEqual(driver.closeObservationCount, 0)
    }
    func testGPUClosePendingCannotPermitRemovalWithNativeRetirementTicket() async throws {
        let gate = GPUCloseReleaseGate(), (_, driver, transport, registry) = try await gpuCloseDriver(gate, holdDrain: true)
        let pending = await driver.closeResult(deadline: .now + .milliseconds(60))
        guard case .incomplete(let context) = pending else { return XCTFail("A native retirement ticket is insufficient while UI resources remain pending") }
        XCTAssertEqual(context.reason, .terminalPending); XCTAssertFalse(pending.permitsRemoval)
        XCTAssertEqual(registry.retiredCount, 1); XCTAssertTrue(driver.snapshot.nativeCloseCompleted)
        XCTAssertFalse(driver.snapshot.interactionsDrained); XCTAssertFalse(driver.terminalResourcesReleased)
        gate.ready = true
        let released = await driver.closeResult(deadline: .now + .milliseconds(100))
        guard case .retired(let ticket) = released else { return XCTFail("A real pending provider must stay retired after UI release, rather than become closed") }
        XCTAssertTrue(released.permitsRemoval); XCTAssertFalse(ticket.snapshot.drained)
        XCTAssertTrue(driver.terminalResourcesReleased); XCTAssertNotEqual(driver.state, .closed)
        transport.holdDrain = false
        try await wait { registry.retiredCount == 0 && driver.closeDisposition == .closed }
        XCTAssertTrue(driver.snapshot.interactionsDrained); XCTAssertEqual(driver.state, .closed)
    }
    func testGPUCloseNaturalDisconnectPreservesTerminalHistoryAndExplicitReconnect() async throws {
        let gate = GPUCloseReleaseGate(), (f, driver, transport, _) = try await gpuCloseDriver(gate)
        let terminalID = ObjectIdentifier(driver.terminal), old = try XCTUnwrap(driver.token)
        try driver.terminal.feedApplicationOutput(Data("synthetic history survives native exit\r\n".utf8))
        transport.releaseReceive(.exit(NativeShellExit(reportedStatus: 7, signal: nil)))
        try await wait { driver.canReconnect }
        XCTAssertEqual(driver.state, .disconnected(7)); XCTAssertEqual(gate.calls, 0)
        XCTAssertFalse(driver.terminalResourcesReleased); XCTAssertTrue(driver.terminal.text.contains("synthetic history survives native exit"))
        let next = try driver.connect(SessionEnvironment.configuration(host: f.host, keyPath: nil), primary: SessionPrimaryAuthorization(provider: { _ in nil }))
        XCTAssertEqual(next.generation, old.generation + 1)
        let reconnected = AdapterTransport()
        _ = try await f.connector.request(1); await f.connector.succeed(1, transport: reconnected)
        try await nextState(driver, .connected)
        XCTAssertEqual(ObjectIdentifier(driver.terminal), terminalID)
        XCTAssertTrue(driver.terminal.text.contains("synthetic history survives native exit")); XCTAssertEqual(gate.calls, 0)
        gate.ready = true
        let result = await driver.closeResult(deadline: .now + .seconds(1))
        XCTAssertEqual(result, .closed)
    }
}


// R3 reproduction only: these roots use the production container and session views.
// The placeholder preserves Vault routing, not an assertion that MainView is exercised.
@MainActor private struct WeakHostedSessionRoot: View {
    let app: AppModel
    var includeTabBar = false
    var body: some View {
        VStack(spacing: 0) {
            if includeTabBar { WorkspaceTabBar(model: app) }
            ZStack {
                NativeWorkspacePage(id: "workspace.page.vault", isVisible: app.workspacePage == .vault) {
                    Color.clear.accessibilityIdentifier("weak-repro.vault-placeholder")
                }
                NativeWorkspacePage(id: "workspace.page.sessions", isVisible: app.workspacePage.sessionID != nil) {
                    SessionWorkspaceView(controller: app.sessions)
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
@MainActor private final class WeakHostedObject<Value: AnyObject> {
    weak var value: Value?
    let identity: ObjectIdentifier
    init(_ value: Value) { self.value = value; identity = ObjectIdentifier(value) }
}
@MainActor private final class DisposalCapture {
    let label = "synthetic permanent page disposal"
    var calls = 0
}
private struct DisposalSheetItem: Identifiable { let id = UUID() }
@MainActor private struct DisposalCaptureView: View {
    let capture: DisposalCapture
    let terminal: NativeTerminalView
    var body: some View { RetainedTerminalView(terminal: terminal).accessibilityLabel(capture.label) }
}
@MainActor private struct NativePageAppearanceProbe: View {
    @Environment(\.colorScheme) private var scheme
    let terminal: NativeTerminalView
    var body: some View {
        VStack(spacing: 0) {
            NativePageSchemeIndicator(scheme: scheme).frame(width: 1, height: 1)
            RetainedTerminalView(terminal: terminal)
        }
    }
}
private struct NativePageSchemeIndicator: NSViewRepresentable {
    let scheme: ColorScheme
    func makeNSView(context: Context) -> NSView { let view = NSView(); updateNSView(view, context: context); return view }
    func updateNSView(_ view: NSView, context: Context) {
        view.identifier = NSUserInterfaceItemIdentifier(scheme == .dark ? "test.pageScheme.dark" : "test.pageScheme.light")
    }
}
/// Real AppKit-owned sheet levels using the production presenter. The public draft
/// is synthetic; this does not import a key, touch Keychain, or create a connection.
@MainActor private struct NestedKeyEditorSheetRoot: View {
    @Bindable var parent: PresentationOwner<UUID>
    let picker: PresentationOwner<UUID>
    let creation: PresentationOwner<UUID>
    let editor: VaultHostEditorModel
    let vault: VaultDesktopModel
    var body: some View {
        Text("synthetic catalog \(vault.hosts.count)")
            .nativeSheet(item: $parent.item) { _ in
                NestedKeyEditorSheetParent(picker: picker, creation: creation, editor: editor)
            }
    }
}
@MainActor private struct NestedKeyEditorSheetParent: View {
    @Bindable var picker: PresentationOwner<UUID>
    let creation: PresentationOwner<UUID>
    @Bindable var editor: VaultHostEditorModel
    var body: some View {
        VStack {
            Text("synthetic dirty host editor")
            TextField("synthetic host name", text: $editor.draft.configuration.name)
            TextField("synthetic host address", text: $editor.draft.configuration.address)
        }.padding(20).frame(width: 500, height: 420)
        .onDisappear { editor.deactivate() }
        .nativeSheet(item: $picker.item) { _ in
            NestedKeyPickerSheetChild(creation: creation)
        }
    }
}
@MainActor private struct NestedKeyPickerSheetChild: View {
    @Bindable var creation: PresentationOwner<UUID>
    @State private var search = ""
    var body: some View {
        VStack { Text("synthetic key picker"); TextField("synthetic key filter", text: $search) }
            .padding(20).frame(width: 430, height: 260)
            // A nil inner presenter remains mounted, like the real picker's
            // import/generate presenter during its window's focus teardown.
            .nativeSheet(item: $creation.item) { _ in
                TextField("synthetic creation label", text: .constant("label")).padding(20).frame(width: 350, height: 200)
            }
    }
}
@MainActor private struct WeakHostedExerciseReceipt {
    let tab: WeakHostedObject<SessionTab>
    let driver: WeakHostedObject<NativeSessionDriver>
    let terminal: WeakHostedObject<NativeTerminalView>
    let connected: Bool
    let exitSeven: Bool
    let closed: Bool
    let nativeClosed: Bool
    let canonicalDrained: Bool
    let queuesEmpty: Bool
    let tabsAfterClose: Int
    let pageIsVault: Bool
    let registryActiveDelta: Int
    let registryRetiredDelta: Int
}

extension NativeSessionAdapterTests {
    func testActualSessionAuthenticationAndTrustSheetsAllowCloseReviewAndRevokeOnClose() async throws {
        _ = NSApplication.shared
        for requiresTrust in [false, true] {
            let f = try fixture(), (tab, driver, request, _) = try await opened(f)
            let hosting = NSHostingController(rootView: SessionWorkspaceView(controller: f.controller))
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 720),
                styleMask: [.titled], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.setFrameOrigin(NSPoint(x: -5000, y: -5000))
            window.contentViewController = hosting; window.makeKeyAndOrderFront(nil)
            defer { window.orderOut(nil); window.contentViewController = nil; window.close() }
            var primaryTask: Task<FileAuthentication, any Error>?
            var trustReply: ChallengeReply<FileHostTrustAnswer>?
            if requiresTrust {
                let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
                    .appendingPathComponent("OpenLXSSH-AppTests-AuthQuitTrust-" + UUID().uuidString)
                try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                addTeardownBlock { try FileManager.default.removeItem(at: root) }
                let store = try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("Trust").path))
                guard case .pending(let pending) = try await store.evaluate(host: request.configuration.host, key: adapterHostKey(68)) else {
                    return XCTFail("Expected isolated Store trust prompt")
                }
                let reply = ChallengeReply<FileHostTrustAnswer>(); trustReply = reply
                addTeardownBlock { reply.cancel() }
                request.trust(.pending(pending), reply)
                _ = try await nextTrust(tab)
            } else {
                let query = primary(request)
                let task = Task { try await request.primary(query) }; primaryTask = task
                addTeardownBlock { task.cancel(); _ = await task.result }
                let prompt = try await nextPrompt(tab)
                XCTAssertEqual(prompt.payload, .initialPassword)
            }
            try await wait { hosting.view.layoutSubtreeIfNeeded(); return window.attachedSheet is NativeOwnedSheetWindow }
            let sheet = try XCTUnwrap(window.attachedSheet as? NativeOwnedSheetWindow)
            XCTAssertTrue(sheet.sheetParent === window)
            XCTAssertFalse(sheet.preventsApplicationTerminationWhenModal,
                "The actual SessionWorkspace prompt must allow the existing app close flow to revoke its owner")
            XCTAssertNotNil(tab.dialog)
            let result = await f.controller.closeTabResult(tab.id, deadline: .now + .seconds(2))
            XCTAssertTrue(result.permitsRemoval); XCTAssertTrue(request.token.isCancelled)
            try await wait { window.attachedSheet == nil }
            XCTAssertTrue(f.controller.tabs.isEmpty); XCTAssertNil(f.controller.selectedTabID)
            XCTAssertNil(tab.authentication); XCTAssertTrue(tab.trust.isEmpty); XCTAssertNil(tab.dialog)
            if let task = primaryTask {
                do { _ = try await task.value; XCTFail("Closed prompt returned primary material") } catch {}
            }
            if let reply = trustReply { XCTAssertFalse(reply.resolve(.reject), "Closing must already revoke the exact trust reply") }
            let reads = await f.credentials.readCount; XCTAssertEqual(reads, 0)
            XCTAssertTrue(driver.snapshot.nativeCloseCompleted)
        }
    }

    func testFilesRootTerminationPolicyKeepsRiskTransferAndOtherDialogsProtected() throws {
        let risk = TransferRisk.overwriteIsAtomicButNotCompareAndSwap(path: try RemotePath("/target"))
        let decision = TransferDecisionRequest(id: UUID(), jobID: UUID(), generation: UUID(), question: .risk(risk))
        let entry = DirectoryEntry(name: try FileName("entry"), attributes: FileAttributes(kind: .regular))
        let contents: [FilesDialog.Content] = [.mkdir, .rename(entry), .delete(entry), .risk(risk, UUID()), .transferDecision(decision)]
        XCTAssertFalse(FilesApplicationUI.allowsTerminationReview(for: nil))
        for content in contents { XCTAssertFalse(FilesApplicationUI.allowsTerminationReview(for: content)) }
    }

    func testNativeSheetFactoryPreservesDefaultTerminationProtection() async throws {
        _ = NSApplication.shared
        let hosting = NSHostingController(rootView: Text("synthetic factory parent")
            .nativeSheet(item: .constant(DisposalSheetItem())) { _ in
                Text("synthetic non-host sheet").frame(width: 300, height: 140)
            })
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 500, height: 300),
            styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.setFrameOrigin(NSPoint(x: -5000, y: -5000))
        window.contentViewController = hosting; window.orderFront(nil)
        defer { window.orderOut(nil); window.contentViewController = nil; window.close() }
        try await wait { window.attachedSheet is NativeOwnedSheetWindow }
        let sheet = try XCTUnwrap(window.attachedSheet as? NativeOwnedSheetWindow)
        XCTAssertTrue(sheet.sheetParent === window)
        XCTAssertTrue(sheet.preventsApplicationTerminationWhenModal,
            "An ordinary caller must retain AppKit's default; the new permission is explicit")
    }

    func testVaultNewHostSheetOptsIntoGlobalReviewWithoutWeakeningNestedPrompt() async throws {
        _ = NSApplication.shared
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-HostQuitReview-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let f = try fixture(), app = AppModel(repository: f.repository, security: f.security,
            location: .isolated(root), sessionBuilder: f.builder, nativeCandidateBuilder: f.builder, preferencesDefaults: nil)
        addTeardownBlock {
            await app.sessions.closeAll(); await app.files.closeForWindow()
            try FileManager.default.removeItem(at: root)
        }
        let before = try await f.repository.securityMetadata()
        let hosting = NSHostingController(rootView: VaultWorkspacePage(app: app))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 720),
            styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.setFrameOrigin(NSPoint(x: -5000, y: -5000))
        window.contentViewController = hosting; window.orderFront(nil)
        defer {
            app.finishWindowCloseReview()
            window.orderOut(nil); window.contentViewController = nil; window.close()
        }
        try await wait {
            hosting.view.layoutSubtreeIfNeeded()
            return self.descendants(hosting.view).contains { $0.identifier?.rawValue == "vault.hosts.search" }
        }
        XCTAssertTrue(app.sendWorkspaceCommand(.newHost))
        try await wait {
            guard let sheet = window.attachedSheet as? NativeOwnedSheetWindow, let content = sheet.contentView else { return false }
            content.layoutSubtreeIfNeeded()
            return self.descendants(content).contains { ($0 as? NSTextField)?.isEditable == true }
        }
        let hostSheet = try XCTUnwrap(window.attachedSheet as? NativeOwnedSheetWindow)
        XCTAssertFalse(hostSheet.preventsApplicationTerminationWhenModal,
            "The production Host presentation must allow the app's registered draft review to run")
        let sheetContent = try XCTUnwrap(hostSheet.contentView)
        let addressField = try XCTUnwrap(descendants(sheetContent).compactMap { $0 as? NSTextField }.first { $0.isEditable })
        XCTAssertTrue(hostSheet.makeFirstResponder(addressField))
        let fieldEditor = try XCTUnwrap(addressField.currentEditor())
        fieldEditor.insertText("draft.invalid")
        let request = app.requestWindowCloseReview()
        XCTAssertNil(request.result, "A dirty new Host draft must wait for registered review")
        try await wait { hostSheet.attachedSheet is NativeOwnedSheetWindow }
        let prompt = try XCTUnwrap(hostSheet.attachedSheet as? NativeOwnedSheetWindow)
        XCTAssertTrue(prompt.sheetParent === hostSheet)
        XCTAssertTrue(prompt.preventsApplicationTerminationWhenModal,
            "The opt-in is exact to the Host sheet and is not inherited by its nested prompt")
        app.finishWindowCloseReview()
        let approved = await request.wait()
        XCTAssertFalse(approved)
        try await wait { hostSheet.attachedSheet == nil }
        XCTAssertTrue(window.attachedSheet === hostSheet, "Cancelling global review must retain the exact Host draft")
        XCTAssertFalse(hostSheet.preventsApplicationTerminationWhenModal)
        let after = try await f.repository.securityMetadata()
        XCTAssertEqual(after.hosts, before.hosts)
        let connections = await f.connector.count, reads = await f.credentials.readCount, saves = await f.credentials.saveCount
        XCTAssertEqual(connections, 0); XCTAssertEqual(reads, 0); XCTAssertEqual(saves, 0)
        XCTAssertTrue(app.sessions.tabs.isEmpty)
    }

    func testNativeDefaultButtonRejectsHiddenSelfAndHiddenPage() throws {
        let capture = DisposalCapture()
        let hosting = NSHostingView(rootView: NativeButton(title: "继续", id: "test.hidden.return", isDefault: true) { capture.calls += 1 })
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 500, height: 300), styleMask: [.titled], backing: .buffered, defer: false)
        let windowBox = WeakHostedObject(window)
        window.isReleasedWhenClosed = false; window.contentView = hosting
        defer { windowBox.value?.contentView = nil; windowBox.value?.close() }
        hosting.frame = NSRect(x: 0, y: 0, width: 500, height: 300); hosting.layoutSubtreeIfNeeded()
        let button = try XCTUnwrap(descendants(hosting).compactMap { $0 as? NativeActionButton }.first { $0.identifier?.rawValue == "test.hidden.return" })
        let event = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
            windowNumber: window.windowNumber, context: nil, characters: "\r", charactersIgnoringModifiers: "\r", isARepeat: false, keyCode: 36))
        XCTAssertTrue(button.performKeyEquivalent(with: event)); XCTAssertEqual(capture.calls, 1)
        button.isHidden = true
        XCTAssertFalse(button.performKeyEquivalent(with: event)); XCTAssertEqual(capture.calls, 1)
        button.isHidden = false; hosting.isHidden = true
        XCTAssertTrue(button.isHiddenOrHasHiddenAncestor)
        XCTAssertFalse(button.performKeyEquivalent(with: event)); XCTAssertEqual(capture.calls, 1)
        hosting.isHidden = false
        XCTAssertTrue(button.performKeyEquivalent(with: event)); XCTAssertEqual(capture.calls, 2)
    }

    func testProminentInlineButtonDoesNotRegisterWindowReturn() throws {
        let capture = DisposalCapture()
        let hosting = NSHostingView(rootView: NativeButton(title: "连接", id: "test.prominent.inline", isProminent: true) { capture.calls += 1 })
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 500, height: 300), styleMask: [.titled], backing: .buffered, defer: false)
        let windowBox = WeakHostedObject(window)
        window.isReleasedWhenClosed = false; window.contentView = hosting
        defer { windowBox.value?.contentView = nil; windowBox.value?.close() }
        hosting.frame = NSRect(x: 0, y: 0, width: 500, height: 300); hosting.layoutSubtreeIfNeeded()
        let button = try XCTUnwrap(descendants(hosting).compactMap { $0 as? NativeActionButton }.first { $0.identifier?.rawValue == "test.prominent.inline" })
        XCTAssertEqual(button.keyEquivalent, ""); XCTAssertNotNil(button.bezelColor)
        let event = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
            windowNumber: window.windowNumber, context: nil, characters: "\r", charactersIgnoringModifiers: "\r", isARepeat: false, keyCode: 36))
        XCTAssertFalse(button.performKeyEquivalent(with: event)); XCTAssertEqual(capture.calls, 0)
        button.performClick(nil); XCTAssertEqual(capture.calls, 1)
    }

    func testNativeSecureReturnOnlySubmitsItsOwnFieldAndPreservesMarkedText() throws {
        let firstCapture = DisposalCapture(), secondCapture = DisposalCapture(), pathCapture = DisposalCapture()
        let hosting = NSHostingView(rootView: VStack {
            NativeSecureField(id: "test.secure.first", placeholder: "first", text: .constant(""), onSubmit: { _ in firstCapture.calls += 1 })
            NativeSecureField(id: "test.secure.second", placeholder: "second", text: .constant(""), onSubmit: { _ in secondCapture.calls += 1 })
            NativeSecureField(id: "test.secure.noSubmit", placeholder: "ordinary secure field", text: .constant(""))
            NativeField(placeholder: "path", id: "test.path.submit", text: .constant(""), onSubmit: { _ in pathCapture.calls += 1 })
        })
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 500, height: 300), styleMask: [.titled], backing: .buffered, defer: false)
        let windowBox = WeakHostedObject(window)
        window.isReleasedWhenClosed = false; window.contentView = hosting
        defer { windowBox.value?.contentView = nil; windowBox.value?.close() }
        hosting.frame = NSRect(x: 0, y: 0, width: 500, height: 300); hosting.layoutSubtreeIfNeeded()
        let fields = descendants(hosting).compactMap { $0 as? NSTextField }
        let first = try XCTUnwrap(fields.first { $0.identifier?.rawValue == "test.secure.first" } as? NSSecureTextField)
        let second = try XCTUnwrap(fields.first { $0.identifier?.rawValue == "test.secure.second" })
        let noSubmit = try XCTUnwrap(fields.first { $0.identifier?.rawValue == "test.secure.noSubmit" })
        let path = try XCTUnwrap(fields.first { $0.identifier?.rawValue == "test.path.submit" })
        let firstDelegate = try XCTUnwrap(first.delegate as? NativeField.Coordinator)
        let secondDelegate = try XCTUnwrap(second.delegate as? NativeField.Coordinator)
        let noSubmitDelegate = try XCTUnwrap(noSubmit.delegate as? NativeField.Coordinator)
        let pathDelegate = try XCTUnwrap(path.delegate as? NativeField.Coordinator)
        let editor = NSTextView(frame: NSRect(x: 0, y: 0, width: 100, height: 40))
        hosting.addSubview(editor)
        let command = #selector(NSResponder.insertNewline(_:))
        XCTAssertTrue(firstDelegate.control(first, textView: editor, doCommandBy: command))
        XCTAssertEqual(firstCapture.calls, 1); XCTAssertEqual(secondCapture.calls, 0); XCTAssertEqual(pathCapture.calls, 0)
        XCTAssertTrue(pathDelegate.control(path, textView: editor, doCommandBy: command))
        XCTAssertEqual(firstCapture.calls, 1); XCTAssertEqual(secondCapture.calls, 0); XCTAssertEqual(pathCapture.calls, 1)
        XCTAssertTrue(secondDelegate.control(second, textView: editor, doCommandBy: command))
        XCTAssertEqual(firstCapture.calls, 1); XCTAssertEqual(secondCapture.calls, 1)
        XCTAssertFalse(noSubmitDelegate.control(noSubmit, textView: editor, doCommandBy: command))
        editor.setMarkedText("测", selectedRange: NSRange(location: 1, length: 0), replacementRange: NSRange(location: NSNotFound, length: 0))
        XCTAssertTrue(editor.hasMarkedText())
        XCTAssertFalse(firstDelegate.control(first, textView: editor, doCommandBy: command))
        XCTAssertEqual(firstCapture.calls, 1)
        editor.unmarkText()
        XCTAssertTrue(firstDelegate.control(first, textView: editor, doCommandBy: command)); XCTAssertEqual(firstCapture.calls, 2)
        XCTAssertEqual(secondCapture.calls, 1); XCTAssertEqual(pathCapture.calls, 1)
        NativeSecureField.dismantleNSView(first, coordinator: firstDelegate)
        XCTAssertFalse(firstDelegate.control(first, textView: editor, doCommandBy: command))
        XCTAssertEqual(firstCapture.calls, 2, "A retained delegate cannot submit after its secure field is dismantled")
    }

    func testNestedKeyPickerSelectionAndCancellationKeepDirtyParentThroughRefresh() async throws {
        try await nestedKeyPickerTeardownExercise(withCreation: false)
    }
    func testNestedKeyCreationReturnThenSelectionKeepsOriginalEditorOwner() async throws {
        try await nestedKeyPickerTeardownExercise(withCreation: true)
    }
    private func nestedKeyPickerTeardownExercise(withCreation: Bool) async throws {
        let f = try fixture(), app = AppModel(repository: f.repository, security: f.security,
            sessionBuilder: f.builder, nativeCandidateBuilder: f.builder)
        let vault = VaultDesktopModel(app: app)
        _ = await vault.load()
        let parent = PresentationOwner<UUID>(), picker = PresentationOwner<UUID>(), creation = PresentationOwner<UUID>()
        let editor = VaultHostEditorModel(draft: VaultHostDraft(host: f.host, settings: AppSettings()))
        editor.edit {
            $0.draft.configuration.name = "synthetic dirty key draft"
            $0.draft.configuration.port = 22221; $0.draft.port = "22221"
            $0.draft.configuration.authentication = .privateKey
        }
        let expectedName = editor.draft.configuration.name, expectedAddress = editor.draft.configuration.address
        let hosting = NSHostingController(rootView: NestedKeyEditorSheetRoot(parent: parent, picker: picker,
            creation: creation, editor: editor, vault: vault))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.contentViewController = hosting; window.orderFront(nil)
        defer { creation.invalidate(); picker.invalidate(); parent.invalidate(); window.close() }
        parent.present(UUID())
        try await wait { window.attachedSheet is NativeOwnedSheetWindow }
        let parentBox = WeakHostedObject(try XCTUnwrap(window.attachedSheet))
        let parentID = try XCTUnwrap(parent.item?.id)
        for selectsKey in [false, true] {
            picker.present(UUID())
            try await wait { parentBox.value?.attachedSheet is NativeOwnedSheetWindow }
            let childBox = WeakHostedObject(try XCTUnwrap(parentBox.value?.attachedSheet))
            let pickerID = try XCTUnwrap(picker.item?.id)
            try focusNestedKeyField(in: XCTUnwrap(childBox.value))
            if withCreation {
                creation.present(UUID())
                try await wait { childBox.value?.attachedSheet is NativeOwnedSheetWindow }
                let creationBox = WeakHostedObject(try XCTUnwrap(childBox.value?.attachedSheet))
                let creationID = try XCTUnwrap(creation.item?.id)
                try focusNestedKeyField(in: XCTUnwrap(creationBox.value))
                creation.dismiss(creationID)
                _ = await vault.load()
                try await wait { creationBox.value == nil && childBox.value?.attachedSheet == nil }
                XCTAssertTrue(picker.owns(pickerID)); XCTAssertTrue(parent.owns(parentID)); XCTAssertTrue(editor.canEdit)
            }
            let chosenKey = UUID()
            if selectsKey { editor.edit { $0.draft.configuration.keyRef = chosenKey } }
            picker.dismiss(pickerID) // Production selection/cancellation uses this same owner operation.
            _ = await vault.load() // Catalog/App refresh while the outgoing window loses focus.
            try await wait { childBox.value == nil && parentBox.value?.attachedSheet == nil }
            XCTAssertTrue(window.attachedSheet === parentBox.value)
            XCTAssertTrue(parentBox.value?.isVisible == true); XCTAssertTrue(parent.owns(parentID))
            XCTAssertTrue(editor.canEdit); XCTAssertTrue(editor.dirty)
            XCTAssertEqual(editor.draft.configuration.name, expectedName)
            XCTAssertEqual(editor.draft.configuration.address, expectedAddress)
            XCTAssertEqual(editor.draft.port, "22221")
            if selectsKey { XCTAssertEqual(editor.draft.configuration.keyRef, chosenKey) }
            else { XCTAssertNil(editor.draft.configuration.keyRef) }
        }
        parent.dismiss(parentID)
        try await wait { parentBox.value == nil && window.attachedSheet == nil }
        XCTAssertFalse(editor.isCurrent, "Final parent removal still performs permanent editor teardown")
        let connections = await f.connector.count; XCTAssertEqual(connections, 0)
        let reads = await f.credentials.readCount; XCTAssertEqual(reads, 0)
    }
    private func focusNestedKeyField(in window: NSWindow) throws {
        let root = try XCTUnwrap(window.contentView)
        root.layoutSubtreeIfNeeded()
        let field = try XCTUnwrap(descendants(root).compactMap { $0 as? NSTextField }.first { $0.isEditable })
        XCTAssertTrue(window.makeFirstResponder(field))
        XCTAssertNotNil(field.currentEditor(), "Exercise the real outgoing field-editor/focus teardown")
    }

    func testNativeDefaultButtonHandlesReturnOnceAndLeavesMarkedTextToInputSystem() throws {
        let capture = DisposalCapture()
        let hosting = NSHostingView(rootView: NativeButton(title: "继续", id: "test.default.return", isDefault: true) { capture.calls += 1 })
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 500, height: 300), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.contentView = hosting
        defer { window.close() }
        hosting.frame = NSRect(x: 0, y: 0, width: 500, height: 300); hosting.layoutSubtreeIfNeeded()
        let button = try XCTUnwrap(descendants(hosting).compactMap { $0 as? NativeActionButton }.first { $0.identifier?.rawValue == "test.default.return" })
        XCTAssertEqual(button.keyEquivalent, "\r"); XCTAssertEqual(button.keyEquivalentModifierMask, [])
        XCTAssertNotNil(button.bezelColor)
        let event = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
            windowNumber: window.windowNumber, context: nil, characters: "\r", charactersIgnoringModifiers: "\r", isARepeat: false, keyCode: 36))
        XCTAssertTrue(button.performKeyEquivalent(with: event)); XCTAssertEqual(capture.calls, 1)
        button.isEnabled = false
        XCTAssertFalse(button.performKeyEquivalent(with: event)); XCTAssertEqual(capture.calls, 1)
        button.isEnabled = true

        let input = NSTextView(frame: NSRect(x: 0, y: 0, width: 100, height: 40))
        hosting.addSubview(input)
        XCTAssertTrue(window.makeFirstResponder(input)); XCTAssertTrue(window.firstResponder === input)
        input.setMarkedText("测", selectedRange: NSRange(location: 1, length: 0), replacementRange: NSRange(location: NSNotFound, length: 0))
        XCTAssertTrue(input.hasMarkedText())
        XCTAssertFalse(button.performKeyEquivalent(with: event), "Return during composition belongs to the input system")
        XCTAssertEqual(capture.calls, 1)
        input.unmarkText()
        XCTAssertTrue(button.performKeyEquivalent(with: event)); XCTAssertEqual(capture.calls, 2)
    }
    func testRetainedSessionPageUsesDarkNativeAndSwiftUIAppearanceUnderLightWindow() throws {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.appearance = NSAppearance(named: .aqua)
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 1000, height: 650)); window.contentView = root
        let terminal = NativeTerminalView()
        let page = NativeWorkspacePageView(content: AnyView(NativePageAppearanceProbe(terminal: terminal)), appearance: .darkAqua)
        let management = NativeWorkspacePageView(content: AnyView(Text("synthetic management page")))
        defer { terminal.releaseResources(); page.dismantle(); management.dismantle(); window.close() }
        page.frame = NSRect(x: 0, y: 0, width: 500, height: 600)
        management.frame = NSRect(x: 500, y: 0, width: 500, height: 600)
        root.addSubview(page); root.addSubview(management); root.layoutSubtreeIfNeeded()
        let choices: [NSAppearance.Name] = [.aqua, .darkAqua]
        XCTAssertEqual(window.effectiveAppearance.bestMatch(from: choices), .aqua)
        XCTAssertEqual(management.effectiveAppearance.bestMatch(from: choices), .aqua)
        XCTAssertEqual(page.effectiveAppearance.bestMatch(from: choices), .darkAqua)
        XCTAssertEqual(terminal.effectiveAppearance.bestMatch(from: choices), .darkAqua)
        XCTAssertTrue(descendants(page).contains { $0.identifier?.rawValue == "test.pageScheme.dark" })
        XCTAssertFalse(descendants(page).contains { $0.identifier?.rawValue == "test.pageScheme.light" })
        let hostingID = ObjectIdentifier(try XCTUnwrap(page.hostingView))
        let containerID = ObjectIdentifier(try XCTUnwrap(terminal.superview))
        try terminal.feedApplicationOutput(Data("synthetic appearance history\r\n".utf8))
        let text = terminal.text
        page.setPageVisible(false); page.setPageVisible(true); root.layoutSubtreeIfNeeded()
        XCTAssertEqual(page.hostingView.map(ObjectIdentifier.init), hostingID)
        XCTAssertEqual(terminal.superview.map(ObjectIdentifier.init), containerID)
        XCTAssertEqual(terminal.text, text)
        XCTAssertEqual(terminal.effectiveAppearance.bestMatch(from: choices), .darkAqua)
    }
    func testPermanentSheetCoordinatorDisposalReleasesCapturedPageWhileCoordinatorIsHeld() throws {
        let coordinator = NativeSheetPresenter<DisposalSheetItem, Text>.Coordinator()
        var capture: DisposalCapture? = DisposalCapture()
        let captureBox = WeakHostedObject(try XCTUnwrap(capture))
        configureDisposalSheet(coordinator, capture: try XCTUnwrap(capture))
        capture = nil
        XCTAssertNotNil(captureBox.value, "The live coordinator owns its actual View callbacks")
        coordinator.close()
        XCTAssertNil(captureBox.value, "Permanent close must release the dismiss callback before coordinator deinit")

        var lateCapture: DisposalCapture? = DisposalCapture()
        let lateCaptureBox = WeakHostedObject(try XCTUnwrap(lateCapture))
        configureDisposalSheet(coordinator, capture: try XCTUnwrap(lateCapture))
        lateCapture = nil
        XCTAssertNil(lateCaptureBox.value, "A stale update must not repopulate a permanently closed coordinator")
        withExtendedLifetime(coordinator) {}
    }
    private func configureDisposalSheet(_ coordinator: NativeSheetPresenter<DisposalSheetItem, Text>.Coordinator,
                                        capture: DisposalCapture) {
        coordinator.update(value: nil, item: .constant(nil), isEnabled: true,
            onAttemptDismiss: { capture.calls += 1; return true },
            content: { _ in Text(capture.label) })
    }
    func testPermanentChallengeAnchorDisposalReleasesCaptureAndRejectsQueuedNotification() async throws {
        let anchor = ChallengeWindowAnchor(), deliveries = DisposalCapture()
        var capture: DisposalCapture? = DisposalCapture()
        let captureBox = WeakHostedObject(try XCTUnwrap(capture))
        configureDisposalAnchor(anchor, capture: try XCTUnwrap(capture), deliveries: deliveries)
        anchor.viewDidMoveToWindow() // Queues the same delivery used by a real window transition.
        capture = nil
        XCTAssertNotNil(captureBox.value)
        ChallengeWindowObserver.dismantleNSView(anchor, coordinator: ())
        XCTAssertNil(captureBox.value, "A cached detached anchor must not retain its old page")
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(deliveries.calls, 0, "A notification queued before dismantle must not call the old page")

        var lateCapture: DisposalCapture? = DisposalCapture()
        let lateCaptureBox = WeakHostedObject(try XCTUnwrap(lateCapture))
        configureDisposalAnchor(anchor, capture: try XCTUnwrap(lateCapture), deliveries: deliveries)
        lateCapture = nil
        XCTAssertNil(lateCaptureBox.value, "A stale representable update cannot restore a dismantled callback")
        withExtendedLifetime(anchor) {}
    }
    private func configureDisposalAnchor(_ anchor: ChallengeWindowAnchor, capture: DisposalCapture, deliveries: DisposalCapture) {
        anchor.setChanged { _ in capture.calls += 1; deliveries.calls += 1 }
    }
    func testChallengeAnchorTemporaryWindowMovePreservesCallbackAndRebindsObservers() async throws {
        let first = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 80, height: 60), styleMask: [.titled], backing: .buffered, defer: false)
        let second = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 80, height: 60), styleMask: [.titled], backing: .buffered, defer: false)
        first.isReleasedWhenClosed = false; second.isReleasedWhenClosed = false
        let anchor = ChallengeWindowAnchor()
        defer { anchor.dismantle(); first.close(); second.close() }
        var windows: [ObjectIdentifier] = []
        anchor.setChanged { if let window = $0 { windows.append(ObjectIdentifier(window)) } }
        try XCTUnwrap(first.contentView).addSubview(anchor)
        try await wait { windows.contains(ObjectIdentifier(first)) }

        windows = []
        anchor.removeFromSuperview(); try XCTUnwrap(second.contentView).addSubview(anchor)
        try await wait { windows.last == ObjectIdentifier(second) }
        XCTAssertTrue(windows.allSatisfy { $0 == ObjectIdentifier(second) })
        let afterMove = windows.count
        NotificationCenter.default.post(name: NSWindow.didBecomeKeyNotification, object: first)
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(windows.count, afterMove, "The previous window's observation must be removed")
        NotificationCenter.default.post(name: NSWindow.didBecomeKeyNotification, object: second)
        try await wait { windows.count > afterMove }
        XCTAssertEqual(windows.last, ObjectIdentifier(second))
    }
    func testWorkspacePagePermanentDisposalReleasesHostedOwnerAndHideShowPreservesTerminal() async throws {
        var capture: DisposalCapture? = DisposalCapture()
        var terminal: NativeTerminalView? = NativeTerminalView()
        let captureBox = WeakHostedObject(try XCTUnwrap(capture))
        let terminalBox = WeakHostedObject(try XCTUnwrap(terminal))
        try terminal?.feedApplicationOutput(Data("synthetic retained terminal\r\n".utf8))
        let terminalID = ObjectIdentifier(try XCTUnwrap(terminal))
        let page = NativeWorkspacePageView(content: AnyView(DisposalCaptureView(capture: try XCTUnwrap(capture), terminal: try XCTUnwrap(terminal))))
        page.frame = NSRect(x: 0, y: 0, width: 500, height: 300)
        page.layoutSubtreeIfNeeded()
        let text = terminal?.text
        let hostingID = ObjectIdentifier(try XCTUnwrap(page.hostingView))
        let hostingBox = WeakHostedObject(try XCTUnwrap(page.hostingView))
        capture = nil; terminal = nil
        XCTAssertNotNil(captureBox.value); XCTAssertNotNil(terminalBox.value?.superview)
        page.setPageVisible(false); page.setPageVisible(true)
        XCTAssertEqual(page.hostingView.map(ObjectIdentifier.init), hostingID)
        XCTAssertEqual(terminalBox.value.map(ObjectIdentifier.init), terminalID)
        XCTAssertEqual(terminalBox.value?.text, text, "Temporary page routing must preserve terminal contents")
        XCTAssertNotNil(captureBox.value)

        terminalBox.value?.releaseResources()
        NativeWorkspacePage.dismantleNSView(page, coordinator: ())
        try await wait { captureBox.value == nil && terminalBox.value == nil && hostingBox.value == nil }
        XCTAssertNil(page.hostingView); XCTAssertTrue(page.subviews.isEmpty)
        XCTAssertTrue(page.isDismantled); XCTAssertFalse(page.pageVisible)
        page.setPageVisible(true)
        XCTAssertFalse(page.pageVisible, "A stale routing update must not remount a permanently removed page")
        withExtendedLifetime(page) {}
    }
    func testWeakReleaseHeadlessAppModelAfterExerciseTaskCompleted() async throws {
        try await weakHostedReproduction(hosted: false)
    }
    func testWeakReleaseProductionSessionWorkspaceAfterHiddenRouteAndTaskCompleted() async throws {
        try await weakHostedReproduction(hosted: true)
    }
    func testWeakReleaseWithActualWorkspaceTabBarAndProductionSessionWorkspace() async throws {
        try await weakHostedReproduction(hosted: true, includeTabBar: true)
    }
    private func weakHostedReproduction(hosted: Bool, includeTabBar: Bool = false) async throws {
        let fixture = try fixture()
        let app = AppModel(repository: fixture.repository, security: fixture.security,
            sessionBuilder: fixture.builder, nativeCandidateBuilder: fixture.builder)
        _ = await app.reload()
        let transport = AdapterTransport()
        let window: NSWindow?
        let hosting: NSHostingController<WeakHostedSessionRoot>?
        if hosted {
            let controller = NSHostingController(rootView: WeakHostedSessionRoot(app: app, includeTabBar: includeTabBar))
            let owner = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650),
                styleMask: [.titled], backing: .buffered, defer: false)
            owner.isReleasedWhenClosed = false
            owner.contentViewController = controller
            controller.view.frame = NSRect(x: 0, y: 0, width: 1000, height: 650)
            controller.view.layoutSubtreeIfNeeded()
            hosting = controller; window = owner
        } else { hosting = nil; window = nil }
        addTeardownBlock {
            await MainActor.run { transport.holdDrain = false; transport.cancel() }
            await fixture.connector.cancelAll()
            await app.sessions.closeAll()
            await MainActor.run { window?.close() }
        }
        // The task only captures the still-legitimate App/catalog/transport owners. Its
        // result has weak object references and scalars, never tab/driver/view/task handles.
        let receipt = try await Task { @MainActor in
            try await self.weakHostedExercise(app: app, fixture: fixture, transport: transport,
                hosting: hosting, hosted: hosted)
        }.value
        XCTAssertTrue(receipt.connected); XCTAssertTrue(receipt.exitSeven); XCTAssertTrue(receipt.closed)
        XCTAssertTrue(receipt.nativeClosed); XCTAssertTrue(receipt.canonicalDrained); XCTAssertTrue(receipt.queuesEmpty)
        XCTAssertEqual(receipt.tabsAfterClose, 0); XCTAssertTrue(receipt.pageIsVault)
        XCTAssertEqual(receipt.registryActiveDelta, 0); XCTAssertEqual(receipt.registryRetiredDelta, 0)
        weakHostedDiagnostic("exercise-task-returned", receipt: receipt, app: app, root: hosting?.view, window: window)
        let deadline = ContinuousClock.now + .seconds(3)
        while !weakHostedReleased(receipt), .now < deadline {
            hosting?.view.layoutSubtreeIfNeeded()
            try await Task.sleep(for: .milliseconds(10))
        }
        weakHostedDiagnostic("three-second-observation-ended", receipt: receipt, app: app, root: hosting?.view, window: window)
        XCTAssertNil(receipt.tab.value, "Tab retained after the exercise task returned")
        XCTAssertNil(receipt.driver.value, "Driver retained after closed/drained and the exercise task returned")
        XCTAssertNil(receipt.terminal.value, "Terminal retained after tab removal and the exercise task returned")
        XCTAssertEqual(app.workspacePage, .vault); XCTAssertTrue(app.sessions.tabs.isEmpty)
        if let root = hosting?.view {
            let containers = descendants(root).compactMap { $0 as? NativeWorkspacePageView }
                .filter { $0.identifier?.rawValue == "workspace.page.sessions" }
            XCTAssertEqual(containers.count, 1)
            XCTAssertTrue(try XCTUnwrap(containers.first).isHidden, "The actual fixed sessions container follows the Vault route")
        }
        // Keep the legitimate App/root/window alive until AFTER the weak assertions.
        withExtendedLifetime((app, hosting, window)) {}
    }
    private func weakHostedExercise(app: AppModel, fixture: AdapterFixture, transport: AdapterTransport,
                                    hosting: NSHostingController<WeakHostedSessionRoot>?, hosted: Bool) async throws -> WeakHostedExerciseReceipt {
        let activeBefore = SessionRetirementRegistry.shared.activeCount
        let retiredBefore = SessionRetirementRegistry.shared.retiredCount
        app.requestSession(hostID: fixture.host.id, mode: .newSession)
        let tab = try XCTUnwrap(app.sessions.selectedTab)
        await tab.preparation?.value
        let driver = try XCTUnwrap(tab.driver as? NativeSessionDriver)
        let weakTab = WeakHostedObject(tab), weakDriver = WeakHostedObject(driver), weakTerminal = WeakHostedObject(driver.terminal)
        _ = try await fixture.connector.request(0)
        await fixture.connector.succeed(0, transport: transport)
        try await nextState(driver, .connected)
        if hosted {
            let root = try XCTUnwrap(hosting?.view)
            try await wait {
                root.layoutSubtreeIfNeeded()
                return driver.terminal.window != nil && driver.terminal.isDescendant(of: root)
            }
            XCTAssertTrue(driver.terminal.window === hosting?.view.window)
        }
        let connected = driver.state == .connected
        weakHostedDiagnostic("connected", receipt: WeakHostedExerciseReceipt(tab: weakTab, driver: weakDriver, terminal: weakTerminal,
            connected: connected, exitSeven: false, closed: false, nativeClosed: false, canonicalDrained: false,
            queuesEmpty: false, tabsAfterClose: app.sessions.tabs.count, pageIsVault: false,
            registryActiveDelta: 0, registryRetiredDelta: 0), app: app, root: hosting?.view, window: hosting?.view.window)
        try await transport.waitForReceive()
        transport.releaseReceive(.exit(NativeShellExit(reportedStatus: 7, signal: nil)))
        try await nextState(driver, .disconnected(7))
        let exitSeven = tab.state == .disconnected(7)
        let result = await app.sessions.closeTabResult(tab.id, deadline: .now + .seconds(2))
        let snapshot = driver.snapshot
        let receipt = WeakHostedExerciseReceipt(tab: weakTab, driver: weakDriver, terminal: weakTerminal,
            connected: connected, exitSeven: exitSeven, closed: result == .closed,
            nativeClosed: snapshot.nativeCloseCompleted, canonicalDrained: transport.drain.snapshot.drained,
            queuesEmpty: snapshot.pendingInputBytes == 0 && snapshot.pendingInputItems == 0 && !snapshot.receiveInFlight &&
                !snapshot.resizeInFlight && !snapshot.hasLatestResize && snapshot.interactionsDrained,
            tabsAfterClose: app.sessions.tabs.count, pageIsVault: app.workspacePage == .vault,
            registryActiveDelta: SessionRetirementRegistry.shared.activeCount - activeBefore,
            registryRetiredDelta: SessionRetirementRegistry.shared.retiredCount - retiredBefore)
        weakHostedDiagnostic("close-result-before-helper-return", receipt: receipt, app: app, root: hosting?.view, window: hosting?.view.window)
        return receipt
    }
    private func weakHostedReleased(_ receipt: WeakHostedExerciseReceipt) -> Bool {
        receipt.tab.value == nil && receipt.driver.value == nil && receipt.terminal.value == nil
    }
    private func weakHostedDiagnostic(_ stage: String, receipt: WeakHostedExerciseReceipt, app: AppModel,
                                      root: NSView?, window: NSWindow?) {
        let terminal = receipt.terminal.value
        let containers = root.map { descendants($0).compactMap { $0 as? NativeWorkspacePageView } } ?? []
        let fixedSessions = containers.first { $0.identifier?.rawValue == "workspace.page.sessions" }
        let retainedChildren = containers.filter { $0.identifier?.rawValue.hasPrefix("workspace.session.") == true }.count
        let terminalID = terminal.map { String(describing: ObjectIdentifier($0)) } ?? "nil"
        let superID = terminal?.superview.map { String(describing: ObjectIdentifier($0)) } ?? "nil"
        let windowID = terminal?.window.map { String(describing: ObjectIdentifier($0)) } ?? "nil"
        let ownedViews = root.map { descendants($0) } ?? []
        let exactCloseID = receipt.tab.value.map { "tab.close." + $0.id.uuidString }
        let nativeCloseChildren = ownedViews.filter { $0.identifier?.rawValue == exactCloseID && exactCloseID != nil }.count
        let exactCloseLabels = ownedViews.compactMap { $0 as? NSButton }.filter { $0.accessibilityIdentifier() == exactCloseID && exactCloseID != nil }.count
        let exactMiddleChildren = ownedViews.filter { $0.identifier?.rawValue.hasPrefix("tab.middle.") == true }.count
        print("weak-hosted-repro stage=\(stage) tabID=\(receipt.tab.identity) driverID=\(receipt.driver.identity) terminalID=\(receipt.terminal.identity) tabAlive=\(receipt.tab.value != nil) driverAlive=\(receipt.driver.value != nil) terminalAlive=\(terminal != nil) actualTerminalID=\(terminalID) terminalSuperview=\(superID) terminalWindow=\(windowID) exactOwnedWindow=\(terminal?.window === window && window != nil) fixedSessionsHidden=\(fixedSessions?.isHidden == true) retainedChildPages=\(retainedChildren) exactNativeCloseChildren=\(nativeCloseChildren) exactCloseLabels=\(exactCloseLabels) actualTabMiddleChildren=\(exactMiddleChildren) actualTabs=\(app.sessions.tabs.count) pageVault=\(app.workspacePage == .vault)")
    }
}


// R5 source preparation. These two tests intentionally require the coordinator to run
// a real self-owned visible AppKit window. They are not hidden-parent sheet substitutes.
@MainActor private struct WeakTrustSheetReceipt {
    let resources: WeakHostedExerciseReceipt
    let sheet: WeakHostedObject<NativeOwnedSheetWindow>?
    let sheetController: WeakHostedObject<NSViewController>?
    let observedRealSheet: Bool
    let observedExactSheetParent: Bool
    let observedSheetDismissal: Bool
}

// Cold control records only current-process fstat/F_GETFL scalars. No names, paths,
// contents, native SSH, credential acquisition, or inferred ownership enter the receipt.
private enum ColdUIFDStage: String, Codable, CaseIterable {
    case beforeDriver, afterDriver, mounted, afterTrustEvaluate, actualSheetAttached
    case afterDismiss, closed, helperTaskReturned, weakEnd
    case checkDeadline // Check-only callback, never sampled or emitted as a stage.
}
private struct ColdUIFDIdentity: Codable, Equatable {
    let fd: Int32, mode: UInt32, dev: Int64, ino: UInt64, accessMode: Int32
}
private struct ColdUIFDUnknown: Codable {
    enum Reason: String, Codable { case systemError, changedDuringProbe, changedBetweenPasses, deadline }
    let fd: Int32, errorCode: Int32
    let reason: Reason
}
private struct ColdUIFDValues: Codable {
    let elapsedMilliseconds: Double
    let scanUpperExclusive: Int32, limitComplete: Bool, complete: Bool
    let identities: [ColdUIFDIdentity], unknown: [ColdUIFDUnknown]
}
private struct ColdUIFDSnapshot: Codable {
    let stage: ColdUIFDStage, elapsedMilliseconds: Double
    let scanUpperExclusive: Int32, limitComplete: Bool, complete: Bool
    let identities: [ColdUIFDIdentity], unknown: [ColdUIFDUnknown]
}
private struct ColdUIFDReceipt: Codable {
    let schema: Int, maximumMilliseconds: Int, descriptorCap: Int32
    let exerciseReturned: Bool, complete: Bool
    let snapshots: [ColdUIFDSnapshot]
}
@MainActor private final class ColdUIFDTimeline {
    private let started = ContinuousClock.now
    private var snapshots: [ColdUIFDSnapshot] = []
    private var deadline: ContinuousClock.Instant { started + .seconds(16) }
    func checkpoint() throws {
        try Task.checkCancellation()
        guard ContinuousClock.now < deadline else { throw AdapterWaitFailure.timeout }
    }
    func record(_ stage: ColdUIFDStage) throws {
        try checkpoint()
        guard stage != .checkDeadline, !snapshots.contains(where: { $0.stage == stage }) else {
            throw AdapterWaitFailure.timeout
        }
        let values = sampleValues()
        snapshots.append(.init(stage: stage, elapsedMilliseconds: values.elapsedMilliseconds,
            scanUpperExclusive: values.scanUpperExclusive, limitComplete: values.limitComplete, complete: values.complete,
            identities: values.identities, unknown: values.unknown))
        try checkpoint()
    }
    // Shared scalar sampling only; callers own their stage labels and receipt schema.
    func sampleValues() -> ColdUIFDValues {
        let limit = getdtablesize(), upper = max(0, min(limit, 4096))
        var first: [Int32: ColdUIFDIdentity] = [:], firstUnknown = Set<Int32>()
        var unknown: [ColdUIFDUnknown] = [], identities: [ColdUIFDIdentity] = []
        for pass in 0..<2 {
            for fd in Int32(0)..<upper {
                if fd % 64 == 0, ContinuousClock.now >= deadline {
                    unknown.append(.init(fd: fd, errorCode: 0, reason: .deadline))
                    break
                }
                let value = probe(fd)
                if let failure = value.1 { unknown.append(failure) }
                if pass == 0 {
                    if let identity = value.0 { first[fd] = identity }
                    if value.1 != nil { firstUnknown.insert(fd) }
                } else if !firstUnknown.contains(fd), value.1 == nil {
                    if first[fd] == value.0 {
                        if let identity = value.0 { identities.append(identity) }
                    } else {
                        unknown.append(.init(fd: fd, errorCode: 0, reason: .changedBetweenPasses))
                    }
                }
            }
            if unknown.contains(where: { $0.reason == .deadline }) { break }
        }
        let duration = started.duration(to: .now).components
        let elapsed = Double(duration.seconds) * 1000 + Double(duration.attoseconds) / 1e15
        let limitComplete = limit > 0 && limit <= 4096
        return .init(elapsedMilliseconds: elapsed, scanUpperExclusive: upper,
            limitComplete: limitComplete, complete: limitComplete && unknown.isEmpty,
            identities: identities, unknown: unknown)
    }
    private func probe(_ fd: Int32) -> (ColdUIFDIdentity?, ColdUIFDUnknown?) {
        var a = stat(), b = stat()
        errno = 0
        guard fstat(fd, &a) == 0 else {
            let code = errno
            guard code == EBADF else { return (nil, .init(fd: fd, errorCode: code, reason: .systemError)) }
            // Stable absence needs both checks to be EBADF. A changing slot is unknown,
            // never evidence that an earlier identity was closed or safely released.
            errno = 0
            let flags = fcntl(fd, F_GETFL), flagsError = errno
            errno = 0
            let repeated = fstat(fd, &b), repeatedError = errno
            if flags == -1 && flagsError == EBADF && repeated == -1 && repeatedError == EBADF { return (nil, nil) }
            return (nil, .init(fd: fd, errorCode: repeated == -1 ? repeatedError : 0, reason: .changedDuringProbe))
        }
        errno = 0
        let flags = fcntl(fd, F_GETFL), flagsError = errno
        guard flags >= 0 else { return (nil, .init(fd: fd, errorCode: flagsError, reason: .changedDuringProbe)) }
        errno = 0
        guard fstat(fd, &b) == 0 else { return (nil, .init(fd: fd, errorCode: errno, reason: .changedDuringProbe)) }
        errno = 0
        let repeatedFlags = fcntl(fd, F_GETFL), repeatedError = errno
        guard repeatedFlags >= 0 else { return (nil, .init(fd: fd, errorCode: repeatedError, reason: .changedDuringProbe)) }
        let first = ColdUIFDIdentity(fd: fd, mode: UInt32(a.st_mode & mode_t(S_IFMT)), dev: Int64(a.st_dev),
            ino: UInt64(a.st_ino), accessMode: flags & O_ACCMODE)
        let second = ColdUIFDIdentity(fd: fd, mode: UInt32(b.st_mode & mode_t(S_IFMT)), dev: Int64(b.st_dev),
            ino: UInt64(b.st_ino), accessMode: repeatedFlags & O_ACCMODE)
        guard first == second else { return (nil, .init(fd: fd, errorCode: 0, reason: .changedDuringProbe)) }
        return (first, nil)
    }
    func emit(exerciseReturned: Bool) {
        let expected = ColdUIFDStage.allCases.filter { $0 != .checkDeadline }
        let receipt = ColdUIFDReceipt(schema: 1, maximumMilliseconds: 16_000, descriptorCap: 4096,
            exerciseReturned: exerciseReturned,
            complete: exerciseReturned && snapshots.map(\.stage) == expected && snapshots.allSatisfy(\.complete),
            snapshots: snapshots)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        if let data = try? encoder.encode(receipt) {
            print("cold-ui-fd-timeline-json " + String(decoding: data, as: UTF8.self))
        } else { XCTFail("Scalar FD timeline could not be encoded") }
    }
}
@MainActor private final class ColdUIFDSessionBuilder: SessionBuilding {
    private let fixture: AdapterFixture
    private let stage: @MainActor (ColdUIFDStage) throws -> Void
    init(fixture: AdapterFixture, stage: @escaping @MainActor (ColdUIFDStage) throws -> Void) {
        self.fixture = fixture; self.stage = stage
    }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        try await fixture.builder.configuration(hostID: hostID)
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        let (host, configuration) = try await configuration(hostID: hostID)
        try stage(.beforeDriver)
        let driver = try NativeSessionDriver(sessionID: sessionID, host: host, repository: fixture.repository,
            security: fixture.security, connector: fixture.connector)
        try stage(.afterDriver)
        return ReadySession(host: host, configuration: configuration, driver: driver)
    }
}

extension NativeSessionAdapterTests {
    func testWeakReleaseVisibleActualWorkspaceWithoutTrustSheetControl() async throws {
        try await weakVisibleTrustReproduction(requiresTrust: false)
    }
    func testWeakReleaseVisibleActualWorkspaceAfterRealTrustOnceSheetDismissal() async throws {
        try await weakVisibleTrustReproduction(requiresTrust: true)
    }
    private func weakVisibleTrustReproduction(
        terminalExercise: (@MainActor (NativeSessionDriver, AdapterTransport) async throws -> Void)? = nil,
        requiresTrust: Bool, stage: (@MainActor (ColdUIFDStage) throws -> Void)? = nil) async throws {
        let fixture = try fixture()
        try stage?(.checkDeadline)
        let builder: any SessionBuilding
        if let stage { builder = ColdUIFDSessionBuilder(fixture: fixture, stage: stage) }
        else { builder = fixture.builder }
        let app = AppModel(repository: fixture.repository, security: fixture.security,
            sessionBuilder: builder, nativeCandidateBuilder: builder)
        _ = await app.reload()
        try stage?(.checkDeadline)
        let transport = AdapterTransport()
        let hosting = NSHostingController(rootView: WeakHostedSessionRoot(app: app, includeTabBar: true))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650),
            styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentViewController = hosting
        hosting.view.frame = NSRect(x: 0, y: 0, width: 1000, height: 650)
        let application = NSApplication.shared, originalPolicy = NSApplication.shared.activationPolicy()
        defer {
            window.close() // Exact owned window only, after success/failure assertions.
            if terminalExercise != nil { _ = application.setActivationPolicy(originalPolicy) }
        }
        addTeardownBlock {
            await MainActor.run { transport.holdDrain = false; transport.cancel() }
            await fixture.connector.cancelAll()
            await app.sessions.closeAll()
        }
        // The ACK/frame test needs a normally active test App and its exact owned
        // window genuinely unobscured. This does not override visibility, force a
        // terminal frame, or touch another application's window or permissions.
        if terminalExercise != nil {
            XCTAssertTrue(application.setActivationPolicy(.regular))
            window.makeKeyAndOrderFront(nil); application.activate()
            try await wait { application.isActive && window.isKeyWindow && window.occlusionState.contains(.visible) }
        } else { window.orderFront(nil) }
        hosting.view.layoutSubtreeIfNeeded()
        weakVisibleTrustWindowDiagnostic("owned-window-ordered", window: window, receipt: nil, app: app)
        XCTAssertTrue(window.isVisible)
        try stage?(.checkDeadline)
        let receipt = try await Task { @MainActor in
            try await self.weakVisibleTrustExercise(app: app, fixture: fixture, transport: transport,
                hosting: hosting, window: window, requiresTrust: requiresTrust, terminalExercise: terminalExercise, stage: stage)
        }.value
        try stage?(.helperTaskReturned)
        let resources = receipt.resources
        XCTAssertTrue(resources.connected); XCTAssertTrue(resources.exitSeven); XCTAssertTrue(resources.closed)
        XCTAssertTrue(resources.nativeClosed); XCTAssertTrue(resources.canonicalDrained); XCTAssertTrue(resources.queuesEmpty)
        XCTAssertEqual(resources.tabsAfterClose, 0); XCTAssertTrue(resources.pageIsVault)
        XCTAssertEqual(resources.registryActiveDelta, 0); XCTAssertEqual(resources.registryRetiredDelta, 0)
        if requiresTrust {
            XCTAssertTrue(receipt.observedRealSheet); XCTAssertTrue(receipt.observedExactSheetParent)
            XCTAssertTrue(receipt.observedSheetDismissal)
        } else { XCTAssertFalse(receipt.observedRealSheet) }
        weakVisibleTrustWindowDiagnostic("exercise-task-returned", window: window, receipt: receipt, app: app)
        weakHostedDiagnostic("visible-trust-exercise-task-returned", receipt: resources, app: app, root: hosting.view, window: window)
        let deadline = ContinuousClock.now + .seconds(3)
        while (!weakHostedReleased(resources) || receipt.sheet?.value != nil || receipt.sheetController?.value != nil), .now < deadline {
            try stage?(.checkDeadline)
            hosting.view.layoutSubtreeIfNeeded()
            try await Task.sleep(for: .milliseconds(10))
        }
        try stage?(.weakEnd)
        weakVisibleTrustWindowDiagnostic("three-second-weak-observation-ended", window: window, receipt: receipt, app: app)
        weakHostedDiagnostic("visible-trust-three-second-ended", receipt: resources, app: app, root: hosting.view, window: window)
        XCTAssertNil(receipt.sheet?.value, "Real trust sheet still retained after dismissal/task completion")
        XCTAssertNil(receipt.sheetController?.value, "Real trust sheet content controller still retained after dismissal/task completion")
        XCTAssertNil(resources.tab.value, "Tab retained after trust sheet dismissed and exercise task returned")
        XCTAssertNil(resources.driver.value, "Driver retained after trust sheet dismissed and exercise task returned")
        XCTAssertNil(resources.terminal.value, "Terminal retained after trust sheet dismissed and exercise task returned")
        XCTAssertNil(window.attachedSheet)
        XCTAssertTrue(app.sessions.tabs.isEmpty); XCTAssertEqual(app.workspacePage, .vault)
        withExtendedLifetime((app, hosting, window)) {}
    }
    private func weakVisibleTrustExercise(app: AppModel, fixture: AdapterFixture, transport: AdapterTransport,
        hosting: NSHostingController<WeakHostedSessionRoot>, window: NSWindow, requiresTrust: Bool,
        terminalExercise: (@MainActor (NativeSessionDriver, AdapterTransport) async throws -> Void)? = nil,
        stage: (@MainActor (ColdUIFDStage) throws -> Void)? = nil) async throws -> WeakTrustSheetReceipt {
        let activeBefore = SessionRetirementRegistry.shared.activeCount
        let retiredBefore = SessionRetirementRegistry.shared.retiredCount
        app.requestSession(hostID: fixture.host.id, mode: .newSession)
        let tab = try XCTUnwrap(app.sessions.selectedTab)
        await tab.preparation?.value
        let driver = try XCTUnwrap(tab.driver as? NativeSessionDriver)
        let weakTab = WeakHostedObject(tab), weakDriver = WeakHostedObject(driver), weakTerminal = WeakHostedObject(driver.terminal)
        let request = try await fixture.connector.request(0)
        try stage?(.checkDeadline)
        if stage != nil {
            // Observe actual mounting before delivering the trust event; do not force presentation.
            try await wait {
                hosting.view.layoutSubtreeIfNeeded()
                return driver.terminal.window === window && driver.terminal.isDescendant(of: hosting.view)
            }
            try stage?(.mounted)
        }
        try stage?(.checkDeadline)
        var sheetBox: WeakHostedObject<NativeOwnedSheetWindow>?
        var controllerBox: WeakHostedObject<NSViewController>?
        var exactParent = false, dismissed = false
        if requiresTrust {
            let trustRoot = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
                .appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: trustRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: trustRoot) }
            let store = try HostTrustStore(directory: AbsolutePath(trustRoot.appendingPathComponent("Trust").path))
            guard case .pending(let pending) = try await store.evaluate(host: request.configuration.host, key: adapterHostKey(31)) else {
                throw AdapterWaitFailure.timeout
            }
            try stage?(.afterTrustEvaluate)
            request.trust(.pending(pending), ChallengeReply<FileHostTrustAnswer>())
            _ = try await nextTrust(tab)
            try stage?(.checkDeadline)
            weakVisibleTrustWindowDiagnostic("real-challenge-delivered", window: window, receipt: nil, app: app)
            do {
                // Actual automatic presentation. Never call presentPendingChallenge or set
                // tab.dialog here; failure to satisfy the real availability guard remains red.
                try await wait { hosting.view.layoutSubtreeIfNeeded(); return window.attachedSheet is NativeOwnedSheetWindow }
            } catch {
                weakVisibleTrustWindowDiagnostic("automatic-sheet-not-presented", window: window, receipt: nil, app: app)
                throw error
            }
            let boxes = try captureExactTrustSheet(window: window)
            sheetBox = boxes.sheet; controllerBox = boxes.controller
            exactParent = boxes.exactParent
            try stage?(.actualSheetAttached)
            let prompt = try XCTUnwrap(tab.trust.first)
            XCTAssertEqual(prompt.id, pending.id)
            XCTAssertNotNil(tab.dialog, "Production automatic sheet must own this exact request")
            let accepted = await app.sessions.accept(prompt, tabID: tab.id, persistence: .once)
            XCTAssertTrue(accepted)
            await fixture.connector.succeed(0, transport: transport)
            try await nextState(driver, .connected)
            try stage?(.checkDeadline)
            try await wait { hosting.view.layoutSubtreeIfNeeded(); return window.attachedSheet == nil }
            dismissed = true
            XCTAssertTrue(tab.trust.isEmpty); XCTAssertNil(tab.dialog)
            try stage?(.afterDismiss)
            let records = try await store.records(); XCTAssertTrue(records.isEmpty, "The UI boundary itself does not persist a once trust choice")
            try stage?(.checkDeadline)
        } else {
            await fixture.connector.succeed(0, transport: transport)
            try await nextState(driver, .connected)
        }
        try await wait {
            hosting.view.layoutSubtreeIfNeeded()
            return driver.terminal.window === window && driver.terminal.isDescendant(of: hosting.view)
        }
        let connected = driver.state == .connected
        try stage?(.checkDeadline)
        try await transport.waitForReceive()
        try stage?(.checkDeadline)
        if terminalExercise != nil {
            try await wait { NSApplication.shared.isActive && window.isKeyWindow && window.occlusionState.contains(.visible) }
        }
        try await terminalExercise?(driver, transport)
        try stage?(.checkDeadline)
        transport.releaseReceive(.exit(NativeShellExit(reportedStatus: 7, signal: nil)))
        try await nextState(driver, .disconnected(7))
        try stage?(.checkDeadline)
        let exitSeven = tab.state == .disconnected(7)
        let result = await app.sessions.closeTabResult(tab.id, deadline: .now + .seconds(2))
        try stage?(.checkDeadline)
        let snapshot = driver.snapshot
        let resources = WeakHostedExerciseReceipt(tab: weakTab, driver: weakDriver, terminal: weakTerminal,
            connected: connected, exitSeven: exitSeven, closed: result == .closed,
            nativeClosed: snapshot.nativeCloseCompleted, canonicalDrained: transport.drain.snapshot.drained,
            queuesEmpty: snapshot.pendingInputBytes == 0 && snapshot.pendingInputItems == 0 && !snapshot.receiveInFlight &&
                !snapshot.resizeInFlight && !snapshot.hasLatestResize && snapshot.interactionsDrained,
            tabsAfterClose: app.sessions.tabs.count, pageIsVault: app.workspacePage == .vault,
            registryActiveDelta: SessionRetirementRegistry.shared.activeCount - activeBefore,
            registryRetiredDelta: SessionRetirementRegistry.shared.retiredCount - retiredBefore)
        let receipt = WeakTrustSheetReceipt(resources: resources, sheet: sheetBox, sheetController: controllerBox,
            observedRealSheet: sheetBox != nil, observedExactSheetParent: exactParent, observedSheetDismissal: dismissed)
        try stage?(.closed)
        weakVisibleTrustWindowDiagnostic("closed-before-exercise-helper-return", window: window, receipt: receipt, app: app)
        return receipt
    }
    private func captureExactTrustSheet(window: NSWindow) throws -> (sheet: WeakHostedObject<NativeOwnedSheetWindow>, controller: WeakHostedObject<NSViewController>, exactParent: Bool) {
        let sheet = try XCTUnwrap(window.attachedSheet as? NativeOwnedSheetWindow)
        let controller = try XCTUnwrap(sheet.contentViewController)
        XCTAssertTrue(sheet.sheetParent === window); XCTAssertTrue(window.attachedSheet === sheet)
        return (WeakHostedObject(sheet), WeakHostedObject(controller), sheet.sheetParent === window)
    }
    private func weakVisibleTrustWindowDiagnostic(_ phase: String, window: NSWindow,
        receipt: WeakTrustSheetReceipt?, app: AppModel) {
        print("weak-trust-repro phase=\(phase) ownedWindowVisible=\(window.isVisible) ownedWindowKey=\(window.isKeyWindow) ownedWindowMain=\(window.isMainWindow) keyWindowIsOwned=\(NSApp.keyWindow === window) anotherKeyWindowPresent=\(NSApp.keyWindow != nil && NSApp.keyWindow !== window) modalPresent=\(NSApp.modalWindow != nil) actualAttachedSheet=\(window.attachedSheet != nil) sheetAlive=\(receipt?.sheet?.value != nil) sheetControllerAlive=\(receipt?.sheetController?.value != nil) tabAlive=\(receipt?.resources.tab.value != nil) driverAlive=\(receipt?.resources.driver.value != nil) terminalAlive=\(receipt?.resources.terminal.value != nil) actualTabCount=\(app.sessions.tabs.count) pageVault=\(app.workspacePage == .vault)")
    }
}


/// Separate from metadata/credential read gates. Only apply(.markConnected) may enter.
/// The held writer ignores cancellation, never silently times out or commits before release;
/// observing arrival/completion is bounded independently by the test's existing 3-second gate.
private actor AdapterMarkConnectedGate {
    private var held = false
    private(set) var entered = false
    private(set) var returned = false
    private(set) var cancelledAtReturn = false
    func arm() { held = true; entered = false; returned = false; cancelledAtReturn = false }
    func wait() async throws {
        guard held else { return }
        entered = true
        while held {
            await withCheckedContinuation { continuation in
                DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(10)) { continuation.resume() }
            }
        }
        cancelledAtReturn = Task.isCancelled; returned = true
    }
    func waitForArrival() async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while !entered {
            guard .now < deadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    func release() { held = false }
}
@MainActor private final class MarkConnectedCompletionCount { var value = 0 }

extension NativeSessionAdapterTests {
    func testBlockedMarkConnectedWriteDoesNotRetainClosedSessionUI() async throws {
        let fixture = try fixture(saved: true)
        let app = AppModel(repository: fixture.repository, security: fixture.security,
            sessionBuilder: fixture.builder, nativeCandidateBuilder: fixture.builder)
        _ = await app.reload()
        let transport = AdapterTransport(), completion = MarkConnectedCompletionCount()
        app.sessions.onAuthenticatedMetadata = { [weak completion] in completion?.value += 1 }
        await fixture.repository.markConnectedGate.arm()
        addTeardownBlock { await fixture.repository.markConnectedGate.release() }
        let receipt = try await Task { @MainActor in
            try await self.blockedMarkConnectedExercise(app: app, fixture: fixture, transport: transport)
        }.value
        XCTAssertTrue(receipt.connected); XCTAssertTrue(receipt.closed); XCTAssertTrue(receipt.nativeClosed)
        XCTAssertTrue(receipt.canonicalDrained); XCTAssertTrue(receipt.queuesEmpty)
        XCTAssertEqual(receipt.tabsAfterClose, 0); XCTAssertTrue(receipt.pageIsVault)
        let before = try await fixture.repository.securityMetadata()
        XCTAssertNil(before.hosts.first?.lastConnectedAt)
        let earlyCommits = await fixture.repository.markConnectedCommits
        XCTAssertEqual(earlyCommits, 0); XCTAssertEqual(completion.value, 0)
        let returnedBefore = await fixture.repository.markConnectedGate.returned
        XCTAssertFalse(returnedBefore, "The DB writer remains held while weak UI ownership is checked")
        let deadline = ContinuousClock.now + .seconds(3)
        while !weakHostedReleased(receipt), .now < deadline { try await Task.sleep(for: .milliseconds(10)) }
        weakHostedDiagnostic("blocked-mark-write-after-task-return", receipt: receipt, app: app, root: nil, window: nil)
        XCTAssertNil(receipt.tab.value, "A pending markConnected write must not retain its old tab")
        XCTAssertNil(receipt.driver.value, "A pending markConnected write must not retain its closed driver")
        XCTAssertNil(receipt.terminal.value, "A pending markConnected write must not retain its closed terminal")
        let stillPending = await fixture.repository.markConnectedGate.returned
        XCTAssertFalse(stillPending)
        await fixture.repository.markConnectedGate.release()
        try await wait { completion.value == 1 }
        let after = try await fixture.repository.securityMetadata()
        let committed = try XCTUnwrap(after.hosts.first)
        XCTAssertNotNil(committed.lastConnectedAt)
        XCTAssertEqual(committed.id, fixture.host.id); XCTAssertEqual(committed.connectionIdentity, fixture.host.connectionIdentity)
        XCTAssertEqual(after.credentials, before.credentials)
        let commits = await fixture.repository.markConnectedCommits
        let cancelled = await fixture.repository.markConnectedGate.cancelledAtReturn
        let connections = await fixture.connector.count, reads = await fixture.credentials.readCount
        XCTAssertEqual(commits, 1); XCTAssertFalse(cancelled, "Closing a tab must not cancel the metadata transaction")
        XCTAssertEqual(connections, 1); XCTAssertEqual(reads, 0)
        XCTAssertTrue(app.sessions.tabs.isEmpty); XCTAssertEqual(app.workspacePage, .vault)
        withExtendedLifetime((app, completion)) {}
    }
    private func blockedMarkConnectedExercise(app: AppModel, fixture: AdapterFixture,
        transport: AdapterTransport) async throws -> WeakHostedExerciseReceipt {
        let activeBefore = SessionRetirementRegistry.shared.activeCount
        let retiredBefore = SessionRetirementRegistry.shared.retiredCount
        app.requestSession(hostID: fixture.host.id, mode: .newSession)
        let tab = try XCTUnwrap(app.sessions.selectedTab)
        await tab.preparation?.value
        let driver = try XCTUnwrap(tab.driver as? NativeSessionDriver)
        let weakTab = WeakHostedObject(tab), weakDriver = WeakHostedObject(driver), weakTerminal = WeakHostedObject(driver.terminal)
        _ = try await fixture.connector.request(0)
        await fixture.connector.succeed(0, transport: transport)
        try await nextState(driver, .connected)
        try await fixture.repository.markConnectedGate.waitForArrival()
        let result = await app.sessions.closeTabResult(tab.id, deadline: .now + .seconds(2))
        let snapshot = driver.snapshot
        return WeakHostedExerciseReceipt(tab: weakTab, driver: weakDriver, terminal: weakTerminal,
            connected: true, exitSeven: false, closed: result == .closed,
            nativeClosed: snapshot.nativeCloseCompleted, canonicalDrained: transport.drain.snapshot.drained,
            queuesEmpty: snapshot.pendingInputBytes == 0 && snapshot.pendingInputItems == 0 && !snapshot.receiveInFlight &&
                !snapshot.resizeInFlight && !snapshot.hasLatestResize && snapshot.interactionsDrained,
            tabsAfterClose: app.sessions.tabs.count, pageIsVault: app.workspacePage == .vault,
            registryActiveDelta: SessionRetirementRegistry.shared.activeCount - activeBefore,
            registryRetiredDelta: SessionRetirementRegistry.shared.retiredCount - retiredBefore)
    }
}


@MainActor private struct RealRepoWeakReceipt {
    let resources: WeakHostedExerciseReceipt
    let persistedConnectionDate: Bool
    let appCatalogRefreshed: Bool
    let appReloadIdle: Bool
    let observerMetadataRefreshed: Bool
    let terminalWasFirstResponderWhileConnected: Bool
    let terminalWasFirstResponderAfterClose: Bool
}

extension NativeSessionAdapterTests {
    func testWeakReleaseRealSQLiteRepositoryAfterMetadataRefreshAndTaskCompleted() async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let location = AppDataLocation.isolated(root)
        let repository = AppRepository(location: location), credentials = AdapterCredentials(), connector = AdapterConnector()
        let security = SecurityCoordinator(repository: repository, location: location, credentials: credentials)
        let environment = SessionEnvironment(location: location)
        let builder = NativeSessionBuilder(repository: repository, security: security, environment: environment, connector: connector)
        let app = AppModel(repository: repository, security: security, location: location,
            sessionBuilder: builder, nativeCandidateBuilder: builder, preferencesDefaults: nil)
        let host = HostConfiguration(name: "synthetic real SQLite weak fixture", address: "never-connected.invalid", username: "fixture", authentication: .password)
        try await repository.apply([.insertHost(host)])
        _ = await app.reload() // Installs the production metadataChanges observer and default onAuthenticatedMetadata callback.
        let initial = try await repository.securityMetadata()
        XCTAssertNil(initial.hosts.first?.lastConnectedAt); XCTAssertTrue(initial.credentials.isEmpty)
        let transport = AdapterTransport()
        let hosting = NSHostingController(rootView: WeakHostedSessionRoot(app: app, includeTabBar: true))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650),
            styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.contentViewController = hosting
        hosting.view.frame = NSRect(x: 0, y: 0, width: 1000, height: 650)
        hosting.view.layoutSubtreeIfNeeded()
        addTeardownBlock {
            await MainActor.run { transport.holdDrain = false; transport.cancel() }
            await connector.cancelAll(); await app.sessions.closeAll(); await app.files.closeForWindow()
            await MainActor.run { window.close() }
            try await security.close(); try await repository.close()
            try FileManager.default.removeItem(at: root)
        }
        let receipt = try await Task { @MainActor in
            try await self.realRepoWeakExercise(app: app, host: host, repository: repository, connector: connector,
                transport: transport, hosting: hosting, window: window)
        }.value
        let resources = receipt.resources
        XCTAssertTrue(resources.connected); XCTAssertTrue(resources.exitSeven); XCTAssertTrue(resources.closed)
        XCTAssertTrue(resources.nativeClosed); XCTAssertTrue(resources.canonicalDrained); XCTAssertTrue(resources.queuesEmpty)
        XCTAssertEqual(resources.tabsAfterClose, 0); XCTAssertTrue(resources.pageIsVault)
        XCTAssertEqual(resources.registryActiveDelta, 0); XCTAssertEqual(resources.registryRetiredDelta, 0)
        XCTAssertTrue(receipt.persistedConnectionDate); XCTAssertTrue(receipt.appCatalogRefreshed)
        XCTAssertTrue(receipt.appReloadIdle); XCTAssertTrue(receipt.observerMetadataRefreshed)
        realRepoWeakDiagnostic("exercise-task-returned", receipt: receipt, app: app, window: window)
        weakHostedDiagnostic("real-sqlite-task-returned", receipt: resources, app: app, root: hosting.view, window: window)
        let deadline = ContinuousClock.now + .seconds(3)
        while !weakHostedReleased(resources), .now < deadline {
            hosting.view.layoutSubtreeIfNeeded()
            try await Task.sleep(for: .milliseconds(10))
        }
        realRepoWeakDiagnostic("three-second-weak-observation-ended", receipt: receipt, app: app, window: window)
        weakHostedDiagnostic("real-sqlite-three-second-ended", receipt: resources, app: app, root: hosting.view, window: window)
        XCTAssertNil(resources.tab.value, "Actual SQLite/metadata observer retained the closed tab")
        XCTAssertNil(resources.driver.value, "Actual SQLite/metadata observer retained the closed driver")
        XCTAssertNil(resources.terminal.value, "Actual SQLite/metadata observer retained the closed terminal")
        let final = try await repository.securityMetadata()
        let stored = try XCTUnwrap(final.hosts.first)
        XCTAssertNotNil(stored.lastConnectedAt); XCTAssertEqual(stored.connectionIdentity, host.connectionIdentity)
        XCTAssertNil(stored.credentialRef); XCTAssertFalse(stored.savePasswordAuthorized); XCTAssertTrue(final.credentials.isEmpty)
        let connections = await connector.count, reads = await credentials.readCount, saves = await credentials.saveCount
        XCTAssertEqual(connections, 1); XCTAssertEqual(reads, 0); XCTAssertEqual(saves, 0)
        XCTAssertFalse(window.isVisible); XCTAssertEqual(app.workspacePage, .vault); XCTAssertTrue(app.sessions.tabs.isEmpty)
        withExtendedLifetime((app, hosting, window, repository)) {}
    }
    private func realRepoWeakExercise(app: AppModel, host: HostConfiguration, repository: AppRepository,
        connector: AdapterConnector, transport: AdapterTransport, hosting: NSHostingController<WeakHostedSessionRoot>,
        window: NSWindow) async throws -> RealRepoWeakReceipt {
        let activeBefore = SessionRetirementRegistry.shared.activeCount
        let retiredBefore = SessionRetirementRegistry.shared.retiredCount
        app.requestSession(hostID: host.id, mode: .newSession)
        let tab = try XCTUnwrap(app.sessions.selectedTab)
        await tab.preparation?.value
        let driver = try XCTUnwrap(tab.driver as? NativeSessionDriver)
        let weakTab = WeakHostedObject(tab), weakDriver = WeakHostedObject(driver), weakTerminal = WeakHostedObject(driver.terminal)
        _ = try await connector.request(0)
        await connector.succeed(0, transport: transport); try await nextState(driver, .connected)
        try await wait {
            hosting.view.layoutSubtreeIfNeeded()
            return driver.terminal.window === window && driver.terminal.isDescendant(of: hosting.view)
        }
        // Observe real SQLite mutation and the default AppModel reload, without replacing
        // onAuthenticatedMetadata or clearing/changing its metadataChanges subscription.
        let metadataDeadline = ContinuousClock.now + .seconds(3)
        var storedDate: Date?
        repeat {
            storedDate = try await repository.securityMetadata().hosts.first { $0.id == host.id }?.lastConnectedAt
            if let storedDate, app.connectionHosts.first(where: { $0.id == host.id })?.lastConnectedAt == storedDate, !app.isLoading { break }
            guard .now < metadataDeadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        } while true
        let persisted = storedDate != nil
        let catalogRefreshed = app.connectionHosts.first { $0.id == host.id }?.lastConnectedAt == storedDate
        let reloadIdle = !app.isLoading
        // A second unrelated metadata mutation proves the production stream observer is
        // active independently of the authenticated callback; it never changes auth identity.
        let renamed = "real SQLite metadata observer refreshed"
        let metadataBeforeRename = try await repository.securityMetadata()
        var metadataHost = try XCTUnwrap(metadataBeforeRename.hosts.first { $0.id == host.id })
        metadataHost.name = renamed
        try await repository.apply([.updateHost(metadataHost)])
        try await wait { app.connectionHosts.first { $0.id == host.id }?.name == renamed && !app.isLoading }
        let observerRefreshed = app.connectionHosts.first { $0.id == host.id }?.name == renamed
        let focusedBefore = window.firstResponder === driver.terminal
        try await transport.waitForReceive()
        transport.releaseReceive(.exit(NativeShellExit(reportedStatus: 7, signal: nil)))
        try await nextState(driver, .disconnected(7))
        let exitSeven = tab.state == .disconnected(7)
        let result = await app.sessions.closeTabResult(tab.id, deadline: .now + .seconds(2))
        let snapshot = driver.snapshot
        let resources = WeakHostedExerciseReceipt(tab: weakTab, driver: weakDriver, terminal: weakTerminal,
            connected: true, exitSeven: exitSeven, closed: result == .closed,
            nativeClosed: snapshot.nativeCloseCompleted, canonicalDrained: transport.drain.snapshot.drained,
            queuesEmpty: snapshot.pendingInputBytes == 0 && snapshot.pendingInputItems == 0 && !snapshot.receiveInFlight &&
                !snapshot.resizeInFlight && !snapshot.hasLatestResize && snapshot.interactionsDrained,
            tabsAfterClose: app.sessions.tabs.count, pageIsVault: app.workspacePage == .vault,
            registryActiveDelta: SessionRetirementRegistry.shared.activeCount - activeBefore,
            registryRetiredDelta: SessionRetirementRegistry.shared.retiredCount - retiredBefore)
        let receipt = RealRepoWeakReceipt(resources: resources, persistedConnectionDate: persisted,
            appCatalogRefreshed: catalogRefreshed, appReloadIdle: reloadIdle, observerMetadataRefreshed: observerRefreshed,
            terminalWasFirstResponderWhileConnected: focusedBefore, terminalWasFirstResponderAfterClose: window.firstResponder === driver.terminal)
        realRepoWeakDiagnostic("closed-before-exercise-helper-return", receipt: receipt, app: app, window: window)
        return receipt
    }
    private func realRepoWeakDiagnostic(_ phase: String, receipt: RealRepoWeakReceipt, app: AppModel, window: NSWindow) {
        let liveTerminalMatchesResponder = receipt.resources.terminal.value.map { window.firstResponder === $0 } ?? false
        print("real-sqlite-weak phase=\(phase) sqliteMarkDate=\(receipt.persistedConnectionDate) appCatalogRefreshed=\(receipt.appCatalogRefreshed) appReloadIdle=\(receipt.appReloadIdle) observerRefresh=\(receipt.observerMetadataRefreshed) connectedFirstResponderWasTerminal=\(receipt.terminalWasFirstResponderWhileConnected) closedFirstResponderWasTerminal=\(receipt.terminalWasFirstResponderAfterClose) currentFirstResponderMatchesTerminal=\(liveTerminalMatchesResponder) tabAlive=\(receipt.resources.tab.value != nil) driverAlive=\(receipt.resources.driver.value != nil) terminalAlive=\(receipt.resources.terminal.value != nil) actualTabCount=\(app.sessions.tabs.count) pageVault=\(app.workspacePage == .vault)")
    }
}


/// Reject every credential operation. Generated unencrypted keys must never consult
/// or mutate a credential store; this owner does not instantiate Keychain at all.
private actor KeyPrimaryDenyCredentials: CredentialAccess {
    private(set) var calls = 0
    func save(_ secret: OpenLXSSHSecurity.SecretBytes, as reference: OpenLXSSHSecurity.CredentialReference,
              authorization: RememberAuthorization) async -> CredentialSaveResult { calls += 1; return .notAuthorized }
    func read(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialReadResult {
        calls += 1; return .manualEntryRequired(.denied)
    }
    func deleteExact(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialDeleteResult {
        calls += 1; return .retryRequired(.denied)
    }
    func close() async throws {}
}
@MainActor private final class KeyPrimaryCleanupIdentity { var keyID: UUID? }
@MainActor private struct KeyPrimaryWeakReceipt {
    let resources: WeakHostedExerciseReceipt
    let requestWasPublicKey: Bool
    let primaryInvoked: Bool
    let primaryReturnedPublicKey: Bool
    let primaryHadNoPassphrase: Bool
    let primaryScopeFinishedBeforeConnected: Bool
    let realMarkDateAndCatalogObserved: Bool
    let terminalWasOwnedFirstResponder: Bool
}

extension NativeSessionAdapterTests {
    func testGeneratedKeyWeakReleaseWithoutInvokingTypedPrimaryControl() async throws {
        try await generatedKeyPrimaryWeakReproduction(invokePrimary: false)
    }
    func testGeneratedKeyWeakReleaseAfterRealTypedPrimaryAcquire() async throws {
        try await generatedKeyPrimaryWeakReproduction(invokePrimary: true)
    }
    private func generatedKeyPrimaryWeakReproduction(invokePrimary: Bool) async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let location = AppDataLocation.isolated(root), repository = AppRepository(location: .isolated(root))
        let credentials = KeyPrimaryDenyCredentials(), connector = AdapterConnector(), transport = AdapterTransport()
        let security = SecurityCoordinator(repository: repository, location: location, credentials: credentials)
        let builder = NativeSessionBuilder(repository: repository, security: security,
            environment: SessionEnvironment(location: location), connector: connector)
        let app = AppModel(repository: repository, security: security, location: location,
            sessionBuilder: builder, nativeCandidateBuilder: builder, preferencesDefaults: nil)
        let hostID = UUID(), cleanupIdentity = KeyPrimaryCleanupIdentity()
        let hosting = NSHostingController(rootView: WeakHostedSessionRoot(app: app, includeTabBar: true))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650),
            styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.contentViewController = hosting
        hosting.view.frame = NSRect(x: 0, y: 0, width: 1000, height: 650)
        hosting.view.layoutSubtreeIfNeeded()
        addTeardownBlock {
            await MainActor.run { transport.holdDrain = false; transport.cancel() }
            await connector.cancelAll(); await app.sessions.closeAll(); await app.files.closeForWindow()
            await MainActor.run { window.close() }
            // Delete the exact synthetic host before the generated key's production cleanup.
            let metadata = try await repository.securityMetadata()
            if metadata.hosts.contains(where: { $0.id == hostID }) { try await repository.apply([.deleteHost(hostID)]) }
            let keyID = await MainActor.run { cleanupIdentity.keyID }
            if let keyID {
                let afterHost = try await repository.securityMetadata()
                if afterHost.keys.contains(where: { $0.id == keyID }) { try await security.deleteKey(keyID) }
            }
            try await security.close(); try await repository.close()
            try FileManager.default.removeItem(at: root)
        }
        // Mature KeyStore/ssh-keygen generates a fresh one-time key under this exact root.
        // Neither its private bytes nor any private digest/description leave the reader scope.
        let generated = try await security.createKey(.generate, protection: .unencrypted, rememberPassphrase: nil)
        cleanupIdentity.keyID = generated.id
        XCTAssertFalse(generated.cleanupPending)
        let host = HostConfiguration(id: hostID, name: "generated key primary ownership A/B", address: "never-connected.invalid",
            username: "fixture", authentication: .privateKey, keyRef: generated.id)
        try await repository.apply([.insertHost(host)])
        let initial = try await repository.securityMetadata()
        XCTAssertEqual(initial.keys.first { $0.id == generated.id }?.algorithm, .ed25519)
        XCTAssertNil(initial.keys.first { $0.id == generated.id }?.passphraseCredentialRef)
        XCTAssertTrue(initial.credentials.isEmpty)
        _ = await app.reload() // Keep the actual callback and metadataChanges observer installed.
        let receipt = try await Task { @MainActor in
            try await self.generatedKeyPrimaryExercise(app: app, host: host, repository: repository, connector: connector,
                transport: transport, hosting: hosting, window: window, invokePrimary: invokePrimary)
        }.value
        let resources = receipt.resources
        XCTAssertTrue(receipt.requestWasPublicKey)
        XCTAssertEqual(receipt.primaryInvoked, invokePrimary)
        XCTAssertEqual(receipt.primaryReturnedPublicKey, invokePrimary)
        XCTAssertEqual(receipt.primaryHadNoPassphrase, invokePrimary)
        XCTAssertTrue(receipt.primaryScopeFinishedBeforeConnected); XCTAssertTrue(receipt.realMarkDateAndCatalogObserved)
        XCTAssertTrue(resources.connected); XCTAssertTrue(resources.exitSeven); XCTAssertTrue(resources.closed)
        XCTAssertTrue(resources.nativeClosed); XCTAssertTrue(resources.canonicalDrained); XCTAssertTrue(resources.queuesEmpty)
        XCTAssertEqual(resources.registryActiveDelta, 0); XCTAssertEqual(resources.registryRetiredDelta, 0)
        XCTAssertEqual(resources.tabsAfterClose, 0); XCTAssertTrue(resources.pageIsVault)
        keyPrimaryWeakDiagnostic("exercise-task-returned", receipt: receipt, invokePrimary: invokePrimary)
        weakHostedDiagnostic("key-primary-task-returned", receipt: resources, app: app, root: hosting.view, window: window)
        let deadline = ContinuousClock.now + .seconds(3)
        while !weakHostedReleased(resources), .now < deadline {
            hosting.view.layoutSubtreeIfNeeded()
            try await Task.sleep(for: .milliseconds(10))
        }
        keyPrimaryWeakDiagnostic("three-second-weak-observation-ended", receipt: receipt, invokePrimary: invokePrimary)
        weakHostedDiagnostic("key-primary-three-second-ended", receipt: resources, app: app, root: hosting.view, window: window)
        XCTAssertNil(resources.tab.value, "Generated-key A/B path retained the closed tab")
        XCTAssertNil(resources.driver.value, "Generated-key A/B path retained the closed driver")
        XCTAssertNil(resources.terminal.value, "Generated-key A/B path retained the closed terminal")
        let metadata = try await repository.securityMetadata()
        XCTAssertEqual(metadata.hosts.first { $0.id == hostID }?.connectionIdentity, host.connectionIdentity)
        XCTAssertTrue(metadata.credentials.isEmpty)
        let credentialCalls = await credentials.calls, connections = await connector.count
        XCTAssertEqual(credentialCalls, 0); XCTAssertEqual(connections, 1)
        XCTAssertFalse(window.isVisible); XCTAssertTrue(app.sessions.tabs.isEmpty); XCTAssertEqual(app.workspacePage, .vault)
        withExtendedLifetime((app, hosting, window, repository)) {}
    }
    private func generatedKeyPrimaryExercise(app: AppModel, host: HostConfiguration, repository: AppRepository,
        connector: AdapterConnector, transport: AdapterTransport, hosting: NSHostingController<WeakHostedSessionRoot>,
        window: NSWindow, invokePrimary: Bool) async throws -> KeyPrimaryWeakReceipt {
        let activeBefore = SessionRetirementRegistry.shared.activeCount, retiredBefore = SessionRetirementRegistry.shared.retiredCount
        app.requestSession(hostID: host.id, mode: .newSession)
        let tab = try XCTUnwrap(app.sessions.selectedTab)
        await tab.preparation?.value
        let driver = try XCTUnwrap(tab.driver as? NativeSessionDriver)
        let weakTab = WeakHostedObject(tab), weakDriver = WeakHostedObject(driver), weakTerminal = WeakHostedObject(driver.terminal)
        let request = try await connector.request(0)
        XCTAssertEqual(request.method, .publicKey)
        let primaryFacts: (publicKey: Bool, noPassphrase: Bool)
        if invokePrimary { primaryFacts = try await consumeGeneratedKeyPrimaryWithinScope(request) }
        else { primaryFacts = (false, false) }
        // The helper that owned FileAuthentication has returned; no material or primary Task
        // handle is retained across succeed/connected/UI close. Both A/B retain request equally.
        let primaryScopeFinished = true
        await connector.succeed(0, transport: transport); try await nextState(driver, .connected)
        try await wait {
            hosting.view.layoutSubtreeIfNeeded()
            return driver.terminal.window === window && driver.terminal.isDescendant(of: hosting.view)
        }
        let metadataDeadline = ContinuousClock.now + .seconds(3)
        var marked = false
        repeat {
            let metadata = try await repository.securityMetadata()
            if let date = metadata.hosts.first(where: { $0.id == host.id })?.lastConnectedAt,
               app.connectionHosts.first(where: { $0.id == host.id })?.lastConnectedAt == date, !app.isLoading { marked = true; break }
            guard .now < metadataDeadline else { throw AdapterWaitFailure.timeout }
            try await Task.sleep(for: .milliseconds(10))
        } while true
        let firstResponder = window.firstResponder === driver.terminal
        try await transport.waitForReceive()
        transport.releaseReceive(.exit(NativeShellExit(reportedStatus: 7, signal: nil)))
        try await nextState(driver, .disconnected(7))
        let exitSeven = tab.state == .disconnected(7)
        let result = await app.sessions.closeTabResult(tab.id, deadline: .now + .seconds(2)), snapshot = driver.snapshot
        let resources = WeakHostedExerciseReceipt(tab: weakTab, driver: weakDriver, terminal: weakTerminal,
            connected: true, exitSeven: exitSeven, closed: result == .closed, nativeClosed: snapshot.nativeCloseCompleted,
            canonicalDrained: transport.drain.snapshot.drained,
            queuesEmpty: snapshot.pendingInputBytes == 0 && snapshot.pendingInputItems == 0 && !snapshot.receiveInFlight &&
                !snapshot.resizeInFlight && !snapshot.hasLatestResize && snapshot.interactionsDrained,
            tabsAfterClose: app.sessions.tabs.count, pageIsVault: app.workspacePage == .vault,
            registryActiveDelta: SessionRetirementRegistry.shared.activeCount - activeBefore,
            registryRetiredDelta: SessionRetirementRegistry.shared.retiredCount - retiredBefore)
        let receipt = KeyPrimaryWeakReceipt(resources: resources, requestWasPublicKey: request.method == .publicKey,
            primaryInvoked: invokePrimary, primaryReturnedPublicKey: primaryFacts.publicKey,
            primaryHadNoPassphrase: primaryFacts.noPassphrase, primaryScopeFinishedBeforeConnected: primaryScopeFinished,
            realMarkDateAndCatalogObserved: marked, terminalWasOwnedFirstResponder: firstResponder)
        keyPrimaryWeakDiagnostic("closed-before-helper-task-return", receipt: receipt, invokePrimary: invokePrimary)
        return receipt
    }
    private func consumeGeneratedKeyPrimaryWithinScope(_ request: NativeSessionConnect) async throws -> (publicKey: Bool, noPassphrase: Bool) {
        let material = try await request.primary(NativeSessionPrimaryRequest(sessionID: UUID(), requestID: UUID(),
            method: .publicKey, token: request.token))
        guard case .publicKey(_, _, let passphrase) = material else {
            XCTFail("Actual unencrypted managed key acquisition must return typed publicKey")
            return (false, false)
        }
        XCTAssertNil(passphrase, "The generated key is unencrypted; no passphrase provider is needed")
        return (true, passphrase == nil) // Booleans only; no private bytes escape this scope.
    }
    private func keyPrimaryWeakDiagnostic(_ phase: String, receipt: KeyPrimaryWeakReceipt, invokePrimary: Bool) {
        print("key-primary-weak phase=\(phase) caseInvokesPrimary=\(invokePrimary) requestPublicKey=\(receipt.requestWasPublicKey) primaryInvoked=\(receipt.primaryInvoked) primaryReturnedPublicKey=\(receipt.primaryReturnedPublicKey) noPassphrase=\(receipt.primaryHadNoPassphrase) primaryScopeEndedBeforeConnected=\(receipt.primaryScopeFinishedBeforeConnected) realMarkDateCatalog=\(receipt.realMarkDateAndCatalogObserved) terminalFirstResponder=\(receipt.terminalWasOwnedFirstResponder) tabAlive=\(receipt.resources.tab.value != nil) driverAlive=\(receipt.resources.driver.value != nil) terminalAlive=\(receipt.resources.terminal.value != nil)")
    }
}

extension NativeSessionAdapterTests {
    func testWorkspaceTabInactiveNilEndAndRepeatedInvalidationDoNotPublish() throws {
        _ = NSApplication.shared
        let owner = WorkspaceTabDragOwner(), source = WorkspaceTabDragSourceView(), updates = DisposalCapture()
        let subscription = owner.objectWillChange.sink { _ in updates.calls += 1 }
        defer { subscription.cancel() }
        owner.sessionEnded(nil); owner.sessionEnded(nil, duringTeardown: true)
        owner.invalidate(); owner.invalidateForTeardown()
        source.owner = owner; source.dispose()
        source.owner = owner; source.viewDidMoveToWindow()
        XCTAssertEqual(updates.calls, 0, "Inactive nil cleanup must not notify a hosting graph")
        let tab = UUID()
        _ = try XCTUnwrap(owner.begin(tabID: tab, order: [tab]))
        let lease = try XCTUnwrap(owner.activeLeaseID)
        XCTAssertEqual(updates.calls, 1)
        owner.sessionEnded(nil)
        XCTAssertEqual(owner.activeLeaseID, lease); XCTAssertEqual(updates.calls, 1)
        owner.sessionEnded(lease)
        XCTAssertFalse(owner.isDragging); XCTAssertEqual(updates.calls, 2, "Normal end still publishes synchronously once")
        owner.sessionEnded(lease); owner.sessionEnded(nil); owner.invalidate()
        source.dispose()
        XCTAssertEqual(updates.calls, 2, "Repeated inactive cleanup must remain a no-op")
    }
    func testWorkspaceTabTeardownRevokesImmediatelyAndLatePublicationCannotClearNewDrag() async throws {
        let owner = WorkspaceTabDragOwner(), a = UUID(), b = UUID(), updates = DisposalCapture()
        let order = [a, b], oldData = try XCTUnwrap(owner.begin(tabID: a, order: order))
        let oldLease = try XCTUnwrap(owner.activeLeaseID)
        let subscription = owner.objectWillChange.sink { _ in updates.calls += 1 }
        defer { subscription.cancel() }
        owner.sessionEnded(oldLease, duringTeardown: true)
        XCTAssertNil(owner.activeLeaseID)
        XCTAssertFalse(owner.canAccept(oldData, leaseID: oldLease, order: order, before: nil))
        XCTAssertTrue(owner.isDragging); XCTAssertEqual(updates.calls, 0, "Teardown revokes the lease without synchronous publication")
        _ = try XCTUnwrap(owner.begin(tabID: b, order: order))
        let newLease = try XCTUnwrap(owner.activeLeaseID), newBeginUpdates = updates.calls
        owner.sessionEnded(oldLease, duringTeardown: true)
        await tabTeardownPublicationTurn()
        XCTAssertEqual(owner.activeLeaseID, newLease); XCTAssertTrue(owner.isDragging)
        XCTAssertEqual(updates.calls, newBeginUpdates, "A deferred old false must not publish over the new drag")
        owner.sessionEnded(newLease, duringTeardown: true)
        XCTAssertNil(owner.activeLeaseID); XCTAssertEqual(updates.calls, newBeginUpdates)
        await tabTeardownPublicationTurn()
        XCTAssertFalse(owner.isDragging); XCTAssertEqual(updates.calls, newBeginUpdates + 1)
        owner.sessionEnded(nil, duringTeardown: true); owner.invalidate()
        XCTAssertEqual(updates.calls, newBeginUpdates + 1)
    }
    func testWorkspaceTabProductionHostingTeardownRevokesOwnedActiveDrag() async throws {
        _ = NSApplication.shared
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-TabTeardown-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let f = try fixture(), app = AppModel(repository: f.repository, security: f.security,
            location: .isolated(root), sessionBuilder: f.builder, nativeCandidateBuilder: f.builder, preferencesDefaults: nil)
        addTeardownBlock { await app.sessions.closeAll(); await app.files.closeForWindow(); try FileManager.default.removeItem(at: root) }
        _ = await app.reload(); app.requestSession(hostID: f.host.id, mode: .newSession)
        await app.sessions.selectedTab?.preparation?.value
        let tabID = try XCTUnwrap(app.sessions.selectedTabID)
        let (owner, leaseID, payload) = try await exerciseActiveTabStripTeardown(app: app, tabID: tabID)
        try await wait { owner.activeLeaseID == nil }
        XCTAssertFalse(owner.canAccept(payload, leaseID: leaseID, order: [tabID], before: nil))
        await tabTeardownPublicationTurn()
        XCTAssertFalse(owner.isDragging)
        XCTAssertEqual(app.sessions.tabs.map(\.id), [tabID], "Only the tab strip is torn down; its session remains owned by the App")
    }
    private func exerciseActiveTabStripTeardown(app: AppModel, tabID: UUID) async throws -> (WorkspaceTabDragOwner, UUID, Data) {
        let hosting = NSHostingView(rootView: WorkspaceTabBar(model: app))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650),
            styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.setFrameOrigin(NSPoint(x: -5000, y: -5000))
        window.contentView = hosting; window.orderFront(nil)
        defer { window.orderOut(nil); window.contentView = nil; window.close() }
        try await wait { hosting.layoutSubtreeIfNeeded(); return !descendants(hosting).compactMap { $0 as? WorkspaceTabDragSourceView }.isEmpty }
        let source = try XCTUnwrap(descendants(hosting).compactMap { $0 as? WorkspaceTabDragSourceView }.first)
        let owner = try XCTUnwrap(source.owner)
        let destination = try XCTUnwrap(descendants(hosting).compactMap { $0 as? WorkspaceTabDropView }.first { $0.before == nil })
        let start = source.convert(NSPoint(x: source.bounds.midX, y: source.bounds.midY), to: nil)
        let release = destination.convert(NSPoint(x: destination.bounds.midX, y: destination.bounds.midY), to: nil)
        source.mouseDown(with: try workspaceTabMouseEvent(.leftMouseDown, window: window, at: start))
        source.mouseDragged(with: try workspaceTabMouseEvent(.leftMouseDragged, window: window, at: release))
        let leaseID = try XCTUnwrap(source.dragLeaseID)
        let payload = try JSONEncoder().encode(WorkspaceTabDragOwner.Lease(id: leaseID, tabID: tabID, order: [tabID]))
        XCTAssertTrue(owner.canAccept(payload, leaseID: leaseID, order: [tabID], before: nil))
        // Only the owned lease escapes. Hosting graph deinit must dismantle its
        // production source with a real local mouse sequence still active.
        return (owner, leaseID, payload)
    }
    private func tabTeardownPublicationTurn() async {
        await withCheckedContinuation { continuation in DispatchQueue.main.async { continuation.resume() } }
    }
    private func tabTrackingFixture() async throws -> WorkspaceTabTrackingFixture {
        _ = NSApplication.shared
        let f = try fixture()
        for _ in 0..<3 {
            _ = f.controller.open(f.host, mode: .newSession)
            await f.controller.selectedTab?.preparation?.value
        }
        let tracking = WorkspaceTabTrackingFixture(controller: f.controller)
        addTeardownBlock { await MainActor.run { tracking.close() } }
        return tracking
    }
    func testWorkspaceTabLocalMouseReleaseMovesForwardAndReverseWithoutRebuildingSessions() async throws {
        let f = try await tabTrackingFixture(), initial = f.ids, tabs = f.controller.tabs
        let terminals = try Dictionary(uniqueKeysWithValues: tabs.map { tab in
            (tab.id, ObjectIdentifier(try XCTUnwrap((tab.driver as? NativeSessionDriver)?.terminal)))
        })
        let source = try XCTUnwrap(f.sources[initial[0]]), start = f.center(of: source)
        try f.send(.leftMouseDown, to: source, at: start)
        XCTAssertTrue(f.window.firstResponder === f.input)
        try f.send(.leftMouseDragged, to: source, at: NSPoint(x: start.x + 2, y: start.y))
        XCTAssertNil(f.owner.activeLeaseID)
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        XCTAssertEqual(f.ids, initial, "Dragging alone must never reorder")
        XCTAssertTrue(f.end.isHighlighted); XCTAssertTrue(f.window.firstResponder === source)
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        XCTAssertEqual(f.ids, [initial[1], initial[2], initial[0]])
        XCTAssertTrue(f.window.firstResponder === f.input); XCTAssertFalse(f.end.isHighlighted)
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: try XCTUnwrap(f.targets[initial[1]])))
        XCTAssertEqual(f.ids, [initial[1], initial[2], initial[0]])
        try f.send(.leftMouseUp, to: source, at: f.center(of: try XCTUnwrap(f.targets[initial[1]])))
        XCTAssertEqual(f.ids, initial)
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        try f.send(.leftMouseUp, to: source, at: f.center(of: try XCTUnwrap(f.targets[initial[2]])))
        XCTAssertEqual(f.ids, [initial[1], initial[0], initial[2]], "The release target, not the last drag hint, decides the move")
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        try f.send(.leftMouseUp, to: source, at: f.center(of: try XCTUnwrap(f.targets[initial[1]])))
        XCTAssertEqual(f.ids, initial)
        for tab in tabs {
            XCTAssertTrue(f.controller.tabs.first(where: { $0.id == tab.id }) === tab)
            XCTAssertEqual(ObjectIdentifier(try XCTUnwrap((tab.driver as? NativeSessionDriver)?.terminal)), try XCTUnwrap(terminals[tab.id]))
        }
        let clicked = try XCTUnwrap(f.sources[initial[1]])
        try f.send(.leftMouseDown, to: clicked, at: f.center(of: clicked))
        try f.send(.leftMouseUp, to: clicked, at: f.center(of: clicked))
        XCTAssertEqual(f.controller.selectedTabID, initial[1]); XCTAssertFalse(f.owner.isDragging)
        XCTAssertTrue(f.window.firstResponder === f.input, "A normal click never takes the drag responder")
    }
    func testWorkspaceTabLocalTrackingRejectsOutsideChangedOrderOwnerTargetAndWindow() async throws {
        let f = try await tabTrackingFixture(), initial = f.ids, source = try XCTUnwrap(f.sources[f.ids[0]])
        func begin() throws {
            try f.send(.leftMouseDown, to: source, at: f.center(of: source))
            try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
            XCTAssertNotNil(source.dragLeaseID)
        }
        try begin(); try f.send(.leftMouseUp, to: source, at: NSPoint(x: -25, y: -20))
        XCTAssertEqual(f.ids, initial); XCTAssertFalse(f.owner.isDragging)
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        f.controller.moveTab(initial[2], before: initial[0]); f.layoutTabs()
        let changedBeforeThreshold = f.ids
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        XCTAssertNil(f.owner.activeLeaseID); XCTAssertEqual(f.ids, changedBeforeThreshold, "The order is frozen on mouseDown, not at the threshold")
        f.controller.moveTab(initial[2], before: nil); f.layoutTabs(); XCTAssertEqual(f.ids, initial)
        try begin(); f.controller.moveTab(initial[2], before: initial[0]); f.layoutTabs()
        let reordered = f.ids
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        XCTAssertEqual(f.ids, reordered, "An external order change invalidates the frozen press")
        let otherOwner = WorkspaceTabDragOwner()
        try begin(); f.end.owner = otherOwner
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        XCTAssertEqual(f.ids, reordered); f.end.owner = f.owner
        try begin(); f.end.before = UUID()
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        XCTAssertEqual(f.ids, reordered); f.end.before = nil
        let ambiguous = WorkspaceTabDropView(frame: f.end.frame)
        ambiguous.owner = f.owner; ambiguous.before = initial[1]; ambiguous.order = { reordered }; ambiguous.move = { _, _ in XCTFail("Ambiguous geometry must not commit") }
        f.root.addSubview(ambiguous)
        try begin(); try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        XCTAssertEqual(f.ids, reordered); ambiguous.owner = nil; ambiguous.removeFromSuperview()
        let otherWindow = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 760, height: 150), styleMask: [], backing: .buffered, defer: false)
        otherWindow.isReleasedWhenClosed = false
        defer { otherWindow.contentView = nil; otherWindow.close() }
        let otherRoot = NSView(frame: NSRect(x: 0, y: 0, width: 760, height: 150)); otherWindow.contentView = otherRoot
        try begin(); f.end.removeFromSuperview(); otherRoot.addSubview(f.end)
        try f.send(.leftMouseUp, to: source, at: NSPoint(x: 700, y: 107))
        XCTAssertEqual(f.ids, reordered, "A same-owner target in another window cannot receive the release")
        f.end.removeFromSuperview(); f.root.addSubview(f.end); f.layoutTabs()
        try begin()
        source.mouseUp(with: try workspaceTabMouseEvent(.leftMouseUp, window: otherWindow, at: f.center(of: f.end)))
        XCTAssertEqual(f.ids, reordered, "The release event must belong to the press window")
        try begin(); f.end.isHidden = true
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        XCTAssertEqual(f.ids, reordered); f.end.isHidden = false
        try begin(); await f.controller.closeTab(initial[0]); f.layoutTabs()
        let remaining = f.ids
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        let removed = !remaining.contains(initial[0]), leaseRevoked = f.owner.activeLeaseID == nil, uiDraggingBeforePublication = f.owner.isDragging
        print("local-track close facts removed=\(removed) leaseRevoked=\(leaseRevoked) uiDraggingBeforePublication=\(uiDraggingBeforePublication)")
        XCTAssertEqual(f.ids, remaining)
        XCTAssertFalse(remaining.contains(initial[0]), "The closed source tab must actually be removed")
        XCTAssertNil(f.owner.activeLeaseID, "The drag lease must be revoked immediately when the source disappears")
        await tabTeardownPublicationTurn()
        XCTAssertFalse(f.owner.isDragging, "The teardown indicator must clear after its documented publication turn")
    }
    func testWorkspaceTabLocalDeferredFocusRestoreKeepsPriorInputAndRejectsOldPress() async throws {
        let f = try await tabTrackingFixture(), initial = f.ids, source = try XCTUnwrap(f.sources[f.ids[0]])
        func begin() throws {
            try f.send(.leftMouseDown, to: source, at: f.center(of: source))
            try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
            XCTAssertTrue(f.window.firstResponder === source)
        }
        try begin(); source.cancelTracking(duringTeardown: true)
        XCTAssertNil(f.owner.activeLeaseID)
        XCTAssertTrue(f.window.firstResponder === source, "Focus restoration is still queued")
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        XCTAssertTrue(f.window.firstResponder === f.input, "A new press must settle the real prior input before acquiring focus")
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        source.cancelTracking(duringTeardown: true)
        await tabTeardownPublicationTurn()
        XCTAssertTrue(f.window.firstResponder === f.input)
        XCTAssertFalse(f.owner.isDragging); XCTAssertEqual(f.ids, initial)

        // Real drag A queues restoration of input A, then a new press captures B.
        // Both queued callbacks see an idle source, so identity (not idle state) must fence A.
        try begin(); source.cancelTracking(duringTeardown: true)
        let inputB = NSTextView(frame: NSRect(x: 180, y: 10, width: 120, height: 40)); f.root.addSubview(inputB)
        XCTAssertTrue(f.window.makeFirstResponder(inputB))
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        XCTAssertTrue(f.window.firstResponder === inputB, "Settling A must not steal the new input B")
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        source.cancelTracking(duringTeardown: true)
        await tabTeardownPublicationTurn()
        XCTAssertTrue(f.window.firstResponder === inputB, "An old drag restoration cannot overtake a newer press")
        XCTAssertFalse(f.owner.isDragging); XCTAssertEqual(f.ids, initial)
    }
    func testWorkspaceTabLocalTrackingPreservesCompositionAndFocusOwnership() async throws {
        let f = try await tabTrackingFixture(), initial = f.ids, source = try XCTUnwrap(f.sources[f.ids[0]])
        f.input.setMarkedText("测", selectedRange: NSRange(location: 1, length: 0), replacementRange: NSRange(location: NSNotFound, length: 0))
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        XCTAssertNil(f.owner.activeLeaseID); XCTAssertTrue(f.input.hasMarkedText()); XCTAssertTrue(f.window.firstResponder === f.input)
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end)); f.input.unmarkText()
        f.input.refusesResign = true
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        XCTAssertNil(f.owner.activeLeaseID); XCTAssertTrue(f.window.firstResponder === f.input)
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end)); f.input.refusesResign = false
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        let otherInput = NSTextView(frame: NSRect(x: 180, y: 10, width: 120, height: 40)); f.root.addSubview(otherInput)
        XCTAssertTrue(f.window.makeFirstResponder(otherInput))
        XCTAssertNil(f.owner.activeLeaseID)
        await tabTeardownPublicationTurn()
        XCTAssertTrue(f.window.firstResponder === otherInput, "Deferred cleanup must not steal focus from its new owner")
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        XCTAssertEqual(f.ids, initial); XCTAssertFalse(f.owner.isDragging)
    }
    func testWorkspaceTabLocalTrackingCancelsOnFocusLossDetachAndDispose() async throws {
        let f = try await tabTrackingFixture(), initial = f.ids, source = try XCTUnwrap(f.sources[f.ids[0]])
        func begin() throws {
            XCTAssertTrue(f.window.makeFirstResponder(f.input))
            try f.send(.leftMouseDown, to: source, at: f.center(of: source))
            try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
            XCTAssertNotNil(source.dragLeaseID)
        }
        try begin(); NotificationCenter.default.post(name: NSWindow.didResignKeyNotification, object: f.window)
        try await wait { f.owner.activeLeaseID == nil }
        await tabTeardownPublicationTurn()
        XCTAssertFalse(f.owner.isDragging); XCTAssertTrue(f.window.firstResponder === f.input)
        try begin(); source.removeFromSuperview()
        XCTAssertNil(f.owner.activeLeaseID)
        await tabTeardownPublicationTurn()
        XCTAssertFalse(f.owner.isDragging); XCTAssertEqual(f.ids, initial)
        f.root.addSubview(source); f.layoutTabs()
        try begin(); source.dispose()
        XCTAssertNil(f.owner.activeLeaseID)
        await tabTeardownPublicationTurn()
        XCTAssertFalse(f.owner.isDragging); XCTAssertEqual(f.ids, initial)
    }
    func testWorkspaceTabDropRejectsPointsBeyondBoundsWhenVisibleRectCoversStrip() throws {
        _ = NSApplication.shared
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 705, height: 34), styleMask: [], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.setFrameOrigin(NSPoint(x: -5000, y: -5000))
        let strip = NSView(frame: NSRect(x: 0, y: 0, width: 705, height: 34)); strip.clipsToBounds = true
        let end = WorkspaceTabDropView(frame: NSRect(x: 660, y: 0, width: 54, height: 34)); end.clipsToBounds = false
        let owner = WorkspaceTabDragOwner(), a = UUID()
        end.owner = owner; end.order = { [a] }; end.move = { _, _ in }
        strip.addSubview(end); window.contentView = strip; window.orderFront(nil); strip.layoutSubtreeIfNeeded()
        defer { owner.invalidate(); window.orderOut(nil); window.contentView = nil; window.close() }
        _ = try XCTUnwrap(owner.begin(tabID: a, order: [a]))
        let elsewhereInStrip = NSPoint(x: 200, y: 17), insideEnd = NSPoint(x: 670, y: 17), clippedEnd = NSPoint(x: 710, y: 17)
        XCTAssertTrue(end.visibleRect.contains(end.convert(elsewhereInStrip, from: strip)), "Reproduce the observed wider visibleRect")
        XCTAssertFalse(end.bounds.contains(end.convert(elsewhereInStrip, from: strip)))
        XCTAssertNil(owner.target(at: elsewhereInStrip, in: window), "The end geometry cannot claim another tab")
        XCTAssertNil(end.hitTest(elsewhereInStrip), "The passive target must never swallow clicks")
        XCTAssertTrue(owner.target(at: insideEnd, in: window) === end)
        XCTAssertNil(end.hitTest(insideEnd), "Even a valid target leaves click routing untouched")
        XCTAssertTrue(end.bounds.contains(end.convert(clippedEnd, from: strip)))
        XCTAssertNil(owner.target(at: clippedEnd, in: window), "A clipped part of the target cannot accept a release")
        owner.invalidate()
        XCTAssertNil(owner.target(at: insideEnd, in: window)); XCTAssertNil(end.hitTest(insideEnd))
    }
    func testWorkspaceTabDestinationEndClearsOnlyCapturedSequenceAndLease() async throws {
        // The former OS sequence fence is now the source's captured local press lease.
        let f = try await tabTrackingFixture(), initial = f.ids, source = try XCTUnwrap(f.sources[f.ids[0]])
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        let oldLease = try XCTUnwrap(source.dragLeaseID)
        source.cancelTracking(leaseID: UUID())
        XCTAssertEqual(f.owner.activeLeaseID, oldLease)
        let escape = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
            windowNumber: f.window.windowNumber, context: nil, characters: "\u{1b}", charactersIgnoringModifiers: "\u{1b}", isARepeat: false, keyCode: 53))
        source.keyDown(with: escape)
        XCTAssertFalse(f.owner.isDragging); XCTAssertEqual(f.ids, initial)
        XCTAssertTrue(f.window.firstResponder === f.input)
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        try f.send(.leftMouseUp, to: source, at: f.center(of: source))
        XCTAssertEqual(f.ids, initial, "A release onto the source is invalid even after a valid end hint")
        XCTAssertFalse(f.owner.isDragging)
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        let newLease = try XCTUnwrap(source.dragLeaseID); XCTAssertNotEqual(newLease, oldLease)
        source.cancelTracking(leaseID: oldLease)
        XCTAssertEqual(f.owner.activeLeaseID, newLease, "A late old end cannot clear a new press")
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        XCTAssertEqual(f.ids, [initial[1], initial[2], initial[0]])
        XCTAssertFalse(f.owner.isDragging); XCTAssertNil(source.dragLeaseID)
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        let thirdLease = try XCTUnwrap(source.dragLeaseID)
        source.cancelTracking(leaseID: newLease)
        XCTAssertEqual(f.owner.activeLeaseID, thirdLease, "A repeated end cannot clear a third press")
        XCTAssertEqual(f.ids, [initial[1], initial[2], initial[0]], "Repeated end is idempotent")
        source.cancelOperation(nil)
    }
    func testWorkspaceTabDestinationEndUsesCapturedOwnerAfterViewRebind() async throws {
        // The source, rather than an asynchronous OS destination callback, owns the frozen origin.
        let f = try await tabTrackingFixture(), initial = f.ids, source = try XCTUnwrap(f.sources[f.ids[0]])
        let replacement = WorkspaceTabDragOwner()
        _ = try XCTUnwrap(replacement.begin(tabID: initial[0], order: initial))
        let replacementLease = try XCTUnwrap(replacement.activeLeaseID)
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        source.owner = replacement
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        XCTAssertNil(f.owner.activeLeaseID); XCTAssertEqual(replacement.activeLeaseID, replacementLease, "A pre-threshold rebind cannot adopt the replacement owner")
        source.owner = f.owner
        try f.send(.leftMouseDown, to: source, at: f.center(of: source))
        try f.send(.leftMouseDragged, to: source, at: f.center(of: f.end))
        let originalLease = try XCTUnwrap(source.dragLeaseID)
        source.owner = replacement
        XCTAssertNil(f.owner.activeLeaseID, "Rebinding revokes the original owner immediately")
        try f.send(.leftMouseUp, to: source, at: f.center(of: f.end))
        source.cancelTracking(leaseID: originalLease)
        await tabTeardownPublicationTurn()
        XCTAssertFalse(f.owner.isDragging); XCTAssertEqual(f.ids, initial)
        XCTAssertEqual(replacement.activeLeaseID, replacementLease, "Cleanup must not use the current replacement owner")
        XCTAssertTrue(f.window.firstResponder === f.input)
        replacement.invalidate()
    }
    func testWorkspaceTabNativeDragTargetsHaveProductionOwnedWindowGeometry() async throws {
        _ = NSApplication.shared
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-TabGeometry-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let f = try fixture(), app = AppModel(repository: f.repository, security: f.security,
            location: .isolated(root), sessionBuilder: f.builder, nativeCandidateBuilder: f.builder, preferencesDefaults: nil)
        _ = await app.reload()
        for _ in 0..<3 {
            app.requestSession(hostID: f.host.id, mode: .newSession)
            await app.sessions.selectedTab?.preparation?.value
        }
        let ids = app.sessions.tabs.map(\.id)
        XCTAssertEqual(ids.count, 3)
        app.showWorkspace(.session(try XCTUnwrap(ids.first)))
        let hosting = NSHostingView(rootView: VStack(spacing: 0) { WorkspaceTabBar(model: app); Spacer(minLength: 0) })
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650),
            styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.setFrameOrigin(NSPoint(x: -5000, y: -5000)); window.contentView = hosting; window.orderFront(nil)
        defer { window.orderOut(nil); window.contentView = nil; window.close() }
        addTeardownBlock { await app.sessions.closeAll(); await app.files.closeForWindow(); try FileManager.default.removeItem(at: root) }
        func nativeViews() -> ([WorkspaceTabDragSourceView], [WorkspaceTabDropView]) {
            let views = descendants(hosting)
            return (views.compactMap { $0 as? WorkspaceTabDragSourceView }, views.compactMap { $0 as? WorkspaceTabDropView })
        }
        func settle() async throws {
            var previous: [CGRect] = [], stable = 0
            try await wait {
                hosting.layoutSubtreeIfNeeded()
                let (sources, drops) = nativeViews()
                guard sources.count == 3, drops.count == 4 else { return false }
                let rects = (sources.map { $0.convert($0.bounds, to: nil) } + drops.map { $0.convert($0.bounds, to: nil) })
                stable = rects == previous ? stable + 1 : 0; previous = rects
                return stable >= 3 // Stable zero geometry still fails the assertions below.
            }
        }
        func assertGeometry(dragging: Bool) throws {
            let (sources, drops) = nativeViews()
            XCTAssertEqual(sources.count, 3); XCTAssertEqual(drops.count, 4)
            for id in ids {
                let source = try XCTUnwrap(sources.first { $0.tabID == id })
                let drop = try XCTUnwrap(drops.first { $0.before == id })
                let tab = try XCTUnwrap(descendants(hosting).compactMap { $0 as? WorkspaceTabMiddleClickView }
                    .first { $0.identifier?.rawValue == "tab.middle." + id.uuidString })
                XCTAssertTrue(source.window === window); XCTAssertTrue(drop.window === window)
                let titleRect = source.convert(source.bounds, to: nil), tabRect = tab.convert(tab.bounds, to: nil)
                let dropRect = drop.convert(drop.bounds, to: nil)
                XCTAssertEqual(titleRect.width, 174, accuracy: 1); XCTAssertEqual(titleRect.height, 34, accuracy: 1)
                XCTAssertGreaterThan(source.visibleRect.width, 0); XCTAssertGreaterThan(source.visibleRect.height, 0)
                XCTAssertTrue(tabRect.insetBy(dx: -1, dy: -1).contains(titleRect), "Native source must cover this production title")
                XCTAssertEqual(titleRect.minX, tabRect.minX + 10, accuracy: 1)
                XCTAssertEqual(dropRect.minX, tabRect.minX, accuracy: 1); XCTAssertEqual(dropRect.maxX, tabRect.maxX, accuracy: 1)
                XCTAssertEqual(dropRect.minY, tabRect.minY, accuracy: 1); XCTAssertEqual(dropRect.maxY, tabRect.maxY, accuracy: 1)
                XCTAssertTrue(drop.owner?.registeredTargets.contains(where: { $0 === drop }) == true)
            }
            let end = try XCTUnwrap(drops.first { $0.before == nil })
            let last = try XCTUnwrap(drops.first { $0.before == ids.last })
            let endRect = end.convert(end.bounds, to: nil), lastRect = last.convert(last.bounds, to: nil)
            XCTAssertTrue(end.window === window)
            XCTAssertEqual(endRect.width, dragging ? 54 : 18, accuracy: 1); XCTAssertEqual(endRect.height, 34, accuracy: 1)
            XCTAssertEqual(endRect.minX, lastRect.maxX + 4, accuracy: 1)
            XCTAssertGreaterThan(end.visibleRect.width, 0); XCTAssertGreaterThan(end.visibleRect.height, 0)
            XCTAssertTrue(end.owner?.registeredTargets.contains(where: { $0 === end }) == true)
            print("Tab drag production geometry dragging=\(dragging) sources=\(sources.map { NSStringFromRect($0.convert($0.bounds, to: nil)) }) end=\(NSStringFromRect(endRect)) visible=\(NSStringFromRect(end.visibleRect))")
        }
        try await settle(); try assertGeometry(dragging: false)
        let owner = try XCTUnwrap(nativeViews().0.first?.owner)
        _ = try XCTUnwrap(owner.begin(tabID: try XCTUnwrap(ids.first), order: ids))
        try await settle(); try assertGeometry(dragging: true)
        owner.invalidate()
        try await settle(); try assertGeometry(dragging: false)
        XCTAssertEqual(app.sessions.tabs.map(\.id), ids, "Geometry observation must not move or replace sessions")
    }
    func testWorkspaceTabDragLeaseSupportsEndDropAndConsumesOnlyItsOwnPayloadOnce() throws {
        let owner = WorkspaceTabDragOwner(), a = UUID(), b = UUID(), c = UUID()
        let order = [a, b, c]
        let data = try XCTUnwrap(owner.begin(tabID: a, order: order))
        let lease = try XCTUnwrap(owner.activeLeaseID)
        XCTAssertTrue(owner.isDragging)
        XCTAssertTrue(owner.canAccept(data, leaseID: lease, order: order, before: nil))
        XCTAssertTrue(owner.canAccept(data, leaseID: lease, order: order, before: b))
        XCTAssertFalse(owner.canAccept(data, leaseID: lease, order: order, before: a))
        XCTAssertFalse(owner.canAccept(data, leaseID: lease, order: order, before: UUID()))
        XCTAssertEqual(owner.consume(data, leaseID: lease, order: order, before: nil), a)
        owner.sessionEnded(lease)
        XCTAssertFalse(owner.isDragging)
        XCTAssertNil(owner.consume(data, leaseID: lease, order: order, before: nil))
        XCTAssertNil(owner.activeLeaseID)
    }
    func testWorkspaceTabDragRejectsExternalStaleAndCancelledLeasesWithoutTouchingNewDrag() throws {
        let owner = WorkspaceTabDragOwner(), a = UUID(), b = UUID(), c = UUID()
        let order = [a, b, c]
        let oldData = try XCTUnwrap(owner.begin(tabID: a, order: order))
        let oldLease = try XCTUnwrap(owner.activeLeaseID)
        _ = try XCTUnwrap(owner.begin(tabID: b, order: order))
        let newLease = try XCTUnwrap(owner.activeLeaseID)
        XCTAssertNil(owner.consume(oldData, leaseID: oldLease, order: order, before: c))
        owner.sessionEnded(oldLease)
        XCTAssertEqual(owner.activeLeaseID, newLease, "A late old end callback cannot revoke the next drag")
        XCTAssertNil(owner.consume(Data("external generic text".utf8), leaseID: newLease, order: order, before: a))
        owner.sessionEnded(newLease)
        XCTAssertFalse(owner.isDragging)
        let changedData = try XCTUnwrap(owner.begin(tabID: a, order: order))
        let changedLease = try XCTUnwrap(owner.activeLeaseID)
        XCTAssertNil(owner.consume(changedData, leaseID: changedLease, order: [b, a, c], before: c))
        let cancelledData = try XCTUnwrap(owner.begin(tabID: c, order: order))
        let cancelled = try XCTUnwrap(owner.activeLeaseID)
        owner.sessionEnded(cancelled)
        XCTAssertNil(owner.consume(cancelledData, leaseID: cancelled, order: order, before: nil)); XCTAssertFalse(owner.isDragging)
        XCTAssertNil(owner.begin(tabID: UUID(), order: order))
    }
    func testWorkspaceTabDragRejectsAnotherStripPayloadWithTheSameTabOrder() throws {
        let owner = WorkspaceTabDragOwner(), other = WorkspaceTabDragOwner(), a = UUID(), b = UUID()
        let order = [a, b]
        let data = try XCTUnwrap(owner.begin(tabID: a, order: order))
        let otherData = try XCTUnwrap(other.begin(tabID: a, order: order))
        let lease = try XCTUnwrap(owner.activeLeaseID)
        XCTAssertFalse(owner.canAccept(otherData, leaseID: lease, order: order, before: b))
        XCTAssertNil(owner.consume(otherData, leaseID: lease, order: order, before: b))
        XCTAssertTrue(owner.canAccept(data, leaseID: lease, order: order, before: b))
        owner.sessionEnded(lease)
        XCTAssertFalse(owner.isDragging)
        XCTAssertFalse(owner.canAccept(data, leaseID: lease, order: order, before: b))
        XCTAssertTrue(other.isDragging, "Ending one strip's drag cannot end another strip's lease")
        other.invalidate()
    }
    func testTransferTaskContextActionStatesPreserveCancellationRetryAndHistoryBoundaries() {
        let active: [TransferJobState] = [.queued, .running, .waitingConflict, .waitingRisk]
        let terminal: [TransferJobState] = [.succeeded, .completedWithSkips, .skipped, .failed, .cancelled]
        for state in active + terminal {
            let waiting = state == .waitingConflict || state == .waitingRisk
            let value = FilesTaskActionAvailability(state: state, hasDecision: waiting, frozen: false, planInProgress: false,
                hasFinishedJobs: true, batchActiveCount: active.contains(state) ? 1 : 0)
            XCTAssertTrue(value.allows(.details))
            XCTAssertEqual(value.allows(.cancel), active.contains(state))
            XCTAssertEqual(value.allows(.retry), state == .failed || state == .cancelled)
            XCTAssertEqual(value.allows(.locate), state == .succeeded || state == .completedWithSkips)
            XCTAssertEqual(value.allows(.decision), waiting)
            XCTAssertTrue(value.allows(.clearFinished), "This command opens the existing all-finished review; it does not remove the active row")
            let frozen = FilesTaskActionAvailability(state: state, hasDecision: waiting, frozen: true, planInProgress: false,
                hasFinishedJobs: true, batchActiveCount: 2)
            for action in [FilesTaskAction.cancel, .cancelBatch, .decision, .retry, .locate, .clearFinished] { XCTAssertFalse(frozen.allows(action)) }
            XCTAssertTrue(frozen.allows(.details))
        }
        let reviewPending = FilesTaskActionAvailability(state: .failed, hasDecision: false, frozen: false, planInProgress: true,
            hasFinishedJobs: false, batchActiveCount: 0)
        XCTAssertFalse(reviewPending.allows(.retry)); XCTAssertFalse(reviewPending.allows(.clearFinished))
        let openHistory = FilesTaskActionAvailability(state: .succeeded, hasDecision: false, frozen: false, planInProgress: false,
            hasFinishedJobs: true, batchActiveCount: 0, historyReviewOpen: true)
        XCTAssertFalse(openHistory.allows(.clearFinished), "A task menu cannot replace an existing immutable removal review")
    }
    func testTransferBatchGroupingUsesRealBatchIdentityAndKeepsEveryJobWithinVisibleScope() {
        let a = UUID(), b = UUID(), c = UUID()
        let a1 = interactionJob(batch: a, state: .running), b1 = interactionJob(batch: b, state: .succeeded)
        let a2 = interactionJob(batch: a, state: .queued), c1 = interactionJob(batch: c, state: .failed)
        let b2 = interactionJob(batch: b, state: .completedWithSkips)
        let jobs = [a1, b1, a2, c1, b2], groups = FilesTaskBatchGroup.groups(jobs)
        XCTAssertEqual(groups.count, 3); XCTAssertEqual(groups.first?.id, a)
        XCTAssertEqual(groups.first?.activeCount, 2)
        XCTAssertEqual(groups.first?.jobs.map(\.id), [a1.id, a2.id])
        XCTAssertEqual(groups.first(where: { $0.id == b })?.jobs.map(\.id), [b1.id, b2.id])
        XCTAssertEqual(Set(groups.flatMap { $0.jobs.map(\.id) }), Set(jobs.map(\.id)))
        XCTAssertTrue(groups.allSatisfy { group in group.jobs.allSatisfy { $0.request.batchID == group.id } })
        let expanded = FilesTaskBatchGroup.groups(jobs + [interactionJob(batch: a, state: .queued)])
        XCTAssertEqual(expanded.first?.activeCount, 3)
        XCTAssertEqual(expanded.first(where: { $0.id == b })?.number, groups.first(where: { $0.id == b })?.number)
    }
    func testTransferBatchPrioritizesPendingThenActiveBeforeLongReportsWithStableTies() throws {
        let batch = UUID()
        let longReport = interactionJob(batch: batch, state: .succeeded, reportItems: 64)
        let activeFirst = interactionJob(batch: batch, state: .running)
        let pendingFirst = interactionJob(batch: batch, state: .waitingRisk, pending: true)
        let finishedSecond = interactionJob(batch: batch, state: .skipped)
        let pendingSecond = interactionJob(batch: batch, state: .waitingRisk, pending: true)
        let activeSecond = interactionJob(batch: batch, state: .queued)
        let finishedThird = interactionJob(batch: batch, state: .succeeded)
        let jobs = [longReport, activeFirst, pendingFirst, finishedSecond, pendingSecond, activeSecond, finishedThird]
        let group = try XCTUnwrap(FilesTaskBatchGroup.groups(jobs).first)
        XCTAssertEqual(group.id, batch); XCTAssertEqual(group.number, 1); XCTAssertEqual(group.activeCount, 4)
        XCTAssertEqual(group.jobs.map(\.id), [pendingFirst.id, pendingSecond.id, activeFirst.id, activeSecond.id,
            longReport.id, finishedSecond.id, finishedThird.id])
        XCTAssertEqual(group.jobs.first(where: { $0.id == longReport.id })?.items.count, 64)
        XCTAssertEqual(Set(group.jobs.map(\.id)), Set(jobs.map(\.id)))
    }
    private func interactionJob(batch: TransferBatchID, state: TransferJobState, pending: Bool = false, reportItems: Int = 0) -> TransferJobSnapshot {
        let request = TransferRequest(hostID: "synthetic batch", batchID: batch,
            source: TransferLocation(serviceID: UUID(), path: .root), destination: TransferLocation(serviceID: UUID(), path: .root),
            kind: reportItems > 1 ? .tree : .file)
        let id = UUID(), generation = UUID()
        let decision = pending ? TransferDecisionRequest(id: UUID(), jobID: id, generation: generation,
            question: .risk(.remoteFsyncUnavailable(path: .root))) : nil
        let items = Array(repeating: TransferItemResult(source: .root, destination: .root, state: .succeeded(bytes: 1), retainedTemporary: nil), count: reportItems)
        return TransferJobSnapshot(id: id, generation: generation, retryOf: nil, request: request, state: state,
            transferredBytes: UInt64(reportItems), cancellationRequested: false, pendingDecision: decision, error: nil, items: items)
    }
}

@MainActor private final class WorkspaceTabTrackingTextView: NSTextView {
    var refusesResign = false
    override func resignFirstResponder() -> Bool { !refusesResign && super.resignFirstResponder() }
}

/// A small owned AppKit layout around the real source/target classes and the real
/// SessionController. It sends public mouse events directly to production handlers;
/// it does not simulate a second drag protocol or implement sorting itself.
@MainActor private final class WorkspaceTabTrackingFixture {
    let controller: SessionController
    let owner = WorkspaceTabDragOwner()
    let window: NSWindow
    let root: NSView
    let input = WorkspaceTabTrackingTextView(frame: NSRect(x: 10, y: 10, width: 120, height: 40))
    let end = WorkspaceTabDropView()
    private(set) var sources: [UUID: WorkspaceTabDragSourceView] = [:]
    private(set) var targets: [UUID: WorkspaceTabDropView] = [:]
    var ids: [UUID] { controller.tabs.map(\.id) }
    init(controller: SessionController) {
        _ = NSApplication.shared
        self.controller = controller
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 760, height: 150), styleMask: [.titled], backing: .buffered, defer: false)
        root = NSView(frame: NSRect(x: 0, y: 0, width: 760, height: 150)); root.clipsToBounds = true
        window.isReleasedWhenClosed = false; window.setFrameOrigin(NSPoint(x: -5000, y: -5000)); window.contentView = root
        root.addSubview(input)
        for tab in controller.tabs {
            let id = tab.id, source = WorkspaceTabDragSourceView(), target = WorkspaceTabDropView()
            source.tabID = id; source.owner = owner; source.order = { [weak controller] in controller?.tabs.map(\.id) ?? [] }
            source.select = { [weak controller] in controller?.select(id) }
            target.before = id; target.owner = owner; target.order = { [weak controller] in controller?.tabs.map(\.id) ?? [] }
            target.move = { [weak self] id, before in self?.controller.moveTab(id, before: before); self?.layoutTabs() }
            sources[id] = source; targets[id] = target; root.addSubview(source); root.addSubview(target)
        }
        end.owner = owner; end.order = { [weak controller] in controller?.tabs.map(\.id) ?? [] }
        end.move = { [weak self] id, before in self?.controller.moveTab(id, before: before); self?.layoutTabs() }
        root.addSubview(end); layoutTabs(); window.orderFront(nil); _ = window.makeFirstResponder(input)
    }
    func layoutTabs() {
        for (id, source) in sources { source.isHidden = !ids.contains(id); targets[id]?.isHidden = source.isHidden }
        for (index, tab) in controller.tabs.enumerated() {
            let x = 20 + CGFloat(index) * 220
            sources[tab.id]?.frame = NSRect(x: x + 10, y: 90, width: 174, height: 34)
            targets[tab.id]?.frame = NSRect(x: x, y: 90, width: 216, height: 34)
        }
        end.frame = NSRect(x: 20 + CGFloat(controller.tabs.count) * 220, y: 90, width: 54, height: 34)
        root.layoutSubtreeIfNeeded()
    }
    func center(of view: NSView) -> NSPoint { view.convert(NSPoint(x: view.bounds.midX, y: view.bounds.midY), to: nil) }
    func send(_ type: NSEvent.EventType, to source: WorkspaceTabDragSourceView, at point: NSPoint) throws {
        let event = try workspaceTabMouseEvent(type, window: window, at: point)
        switch type {
        case .leftMouseDown: source.mouseDown(with: event)
        case .leftMouseDragged: source.mouseDragged(with: event)
        case .leftMouseUp: source.mouseUp(with: event)
        default: XCTFail("Only the real primary mouse sequence belongs to this fixture")
        }
    }
    func close() {
        input.refusesResign = false; input.unmarkText()
        for source in sources.values { source.dispose() }
        for target in targets.values { target.owner = nil }
        end.owner = nil; window.orderOut(nil); window.contentView = nil; window.close()
    }
}

@MainActor private func workspaceTabMouseEvent(_ type: NSEvent.EventType, window: NSWindow, at point: NSPoint) throws -> NSEvent {
    try XCTUnwrap(NSEvent.mouseEvent(with: type, location: point, modifierFlags: [], timestamp: 0,
        windowNumber: window.windowNumber, context: nil, eventNumber: 1, clickCount: 1, pressure: type == .leftMouseUp ? 0 : 1))
}

extension NativeSessionAdapterTests {
    func testUnifiedWindowChromeKeepsNativeButtonsAndMeasuredGutterAtThreeSizes() async throws {
        _ = NSApplication.shared
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-WindowChrome-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let f = try fixture(), app = AppModel(repository: f.repository, security: f.security,
            location: .isolated(root), sessionBuilder: f.builder, nativeCandidateBuilder: f.builder, preferencesDefaults: nil)
        _ = await app.reload()
        addTeardownBlock { await app.sessions.closeAll(); await app.files.closeForWindow(); try FileManager.default.removeItem(at: root) }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1120, height: 720),
            styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.title = "Synthetic chrome window title"
        WorkspaceWindowChrome.configure(window)
        let buttonTypes: [NSWindow.ButtonType] = [.closeButton, .miniaturizeButton, .zoomButton]
        let buttons = try buttonTypes.map { try XCTUnwrap(window.standardWindowButton($0)) }
        let parents = try buttons.map { ObjectIdentifier(try XCTUnwrap($0.superview)) }
        let hosting = NSHostingView(rootView: MainView(model: app))
        window.contentView = hosting; window.setFrameOrigin(NSPoint(x: -5000, y: -5000)); window.orderFront(nil)
        defer { window.orderOut(nil); window.contentView = nil; window.close() }
        for size in [NSSize(width: 1000, height: 650), NSSize(width: 1280, height: 800), NSSize(width: 1440, height: 900)] {
            window.setFrame(NSRect(origin: window.frame.origin, size: size), display: true)
            var previousGeometry: [NSRect]?
            try await wait {
                hosting.layoutSubtreeIfNeeded()
                guard let drag = self.descendants(hosting).compactMap({ $0 as? WorkspaceChromeDragView }).first,
                      let state = drag.state, state.isIntegrated, state.leadingInset > 8,
                      state.interactiveFrames.count == 3,
                      let plus = state.interactiveFrames.first(where: { abs($0.width - 30) < 1 && abs($0.height - 30) < 1 }) else { return false }
                let contentRect = hosting.convert(hosting.bounds, to: nil), stripRect = drag.convert(drag.bounds, to: nil)
                let buttonFrames = buttons.map { $0.convert($0.bounds, to: nil) }
                let fixed = state.interactiveFrames.filter { abs($0.width - 90) < 1 && abs($0.height - 34) < 1 }.sorted { $0.minX < $1.minX }
                let currentSize = abs(window.frame.width - size.width) < 1 && abs(window.frame.height - size.height) < 1
                let stripAtContentTop = abs(stripRect.maxY - contentRect.maxY) < 1 && abs(stripRect.minX - contentRect.minX) < 1
                    && abs(stripRect.width - contentRect.width) < 1 && abs(stripRect.height - DesktopStyle.barHeight) < 1
                let controlsAligned = buttonFrames.allSatisfy { abs($0.midY - stripRect.midY) < 1 }
                let fixedAligned = fixed.count == 2 && fixed.allSatisfy { frame in
                    frame.minX >= state.leadingInset - 1 && abs(drag.convert(frame, to: nil).midY - stripRect.midY) < 1
                }
                let geometry = [window.frame, contentRect, stripRect, plus] + buttonFrames + fixed
                    + [NSRect(x: state.leadingInset, y: state.topSafeInset, width: 0, height: 0)]
                let stable = previousGeometry == geometry
                previousGeometry = geometry
                // The existing 3s wait yields between samples. An already true
                // isIntegrated flag is not evidence that this resize has settled.
                return currentSize && stripAtContentTop && controlsAligned && fixedAligned && stable
            }
            let drag = try XCTUnwrap(descendants(hosting).compactMap { $0 as? WorkspaceChromeDragView }.first)
            let state = try XCTUnwrap(drag.state), contentRect = hosting.convert(hosting.bounds, to: nil)
            let stripRect = drag.convert(drag.bounds, to: nil)
            XCTAssertTrue(window.styleMask.contains(.fullSizeContentView)); XCTAssertTrue(window.titlebarAppearsTransparent)
            XCTAssertEqual(window.titleVisibility, .hidden); XCTAssertEqual(window.title, "Synthetic chrome window title")
            XCTAssertFalse(window.isMovableByWindowBackground)
            // An empty top accessory intercepts the underlying content's pointer
            // targets even when its own hitTest returns nil. The real bar is content.
            XCTAssertTrue(window.titlebarAccessoryViewControllers.isEmpty)
            XCTAssertEqual(drag.bounds.height, DesktopStyle.barHeight, accuracy: 1)
            XCTAssertEqual(stripRect.maxY, contentRect.maxY, accuracy: 1)
            XCTAssertEqual(stripRect.minX, contentRect.minX, accuracy: 1)
            XCTAssertEqual(stripRect.width, contentRect.width, accuracy: 1)
            for (index, button) in buttons.enumerated() {
                XCTAssertTrue(window.standardWindowButton(buttonTypes[index]) === button)
                XCTAssertEqual(ObjectIdentifier(try XCTUnwrap(button.superview)), parents[index], "Native buttons must never be reparented")
                XCTAssertFalse(button.isHiddenOrHasHiddenAncestor)
                let visible = button.bounds.intersection(button.visibleRect)
                XCTAssertEqual(visible.minX, button.bounds.minX, accuracy: 1)
                XCTAssertEqual(visible.maxX, button.bounds.maxX, accuracy: 1)
                XCTAssertEqual(visible.minY, button.bounds.minY, accuracy: 1)
                XCTAssertEqual(visible.maxY, button.bounds.maxY, accuracy: 1)
                var ancestor = button.superview
                while let view = ancestor {
                    if view === button.superview || view.clipsToBounds {
                        let frame = view.convert(button.bounds, from: button)
                        XCTAssertGreaterThanOrEqual(frame.minX, view.bounds.minX - 1, "Native button exceeds ancestor \(type(of: view))")
                        XCTAssertLessThanOrEqual(frame.maxX, view.bounds.maxX + 1, "Native button exceeds ancestor \(type(of: view))")
                        XCTAssertGreaterThanOrEqual(frame.minY, view.bounds.minY - 1, "Native button exceeds ancestor \(type(of: view))")
                        XCTAssertLessThanOrEqual(frame.maxY, view.bounds.maxY + 1, "Native button exceeds ancestor \(type(of: view))")
                    }
                    ancestor = view.superview
                }
                let frame = button.convert(button.bounds, to: nil)
                XCTAssertEqual(frame.midY, stripRect.midY, accuracy: 1)
                XCTAssertGreaterThanOrEqual(state.leadingInset, frame.maxX - contentRect.minX + 11)
            }
            let fixed = state.interactiveFrames.filter { abs($0.width - 90) < 1 && abs($0.height - 34) < 1 }
            XCTAssertEqual(fixed.count, 2)
            for frame in fixed {
                XCTAssertGreaterThanOrEqual(frame.minX, state.leadingInset - 1)
                XCTAssertEqual(frame.midY, DesktopStyle.barHeight / 2, accuracy: 1)
                let fixedFrame = drag.convert(frame, to: nil)
                for button in buttons {
                    let buttonFrame = button.convert(button.bounds, to: nil)
                    XCTAssertEqual(fixedFrame.midY, buttonFrame.midY, accuracy: 1)
                    XCTAssertFalse(fixedFrame.intersects(buttonFrame), "Fixed tabs must clear the real native controls")
                }
                XCTAssertFalse(state.canDrag(at: NSPoint(x: frame.midX, y: frame.midY), in: drag.bounds))
            }
            let plus = try XCTUnwrap(state.interactiveFrames.first { abs($0.width - 30) < 1 && abs($0.height - 30) < 1 })
            let lastFixed = try XCTUnwrap(fixed.max(by: { $0.maxX < $1.maxX }))
            XCTAssertGreaterThanOrEqual(plus.minX, lastFixed.maxX)
            XCTAssertLessThan(plus.minX - lastFixed.maxX, 16, "New connection belongs immediately after the fixed tabs")
            XCTAssertTrue(state.canDrag(at: NSPoint(x: plus.maxX + 20, y: plus.midY), in: drag.bounds))
            var root = hosting as NSView
            while let parent = root.superview { root = parent }
            for frame in fixed + [plus] {
                let point = drag.convert(NSPoint(x: frame.midX, y: frame.midY), to: nil)
                let hit = try XCTUnwrap(root.hitTest(root.superview?.convert(point, from: nil) ?? point))
                XCTAssertTrue(hit === hosting || hit.isDescendant(of: hosting), "The full window must route real tab/plus points into production content")
                XCTAssertFalse(hit === drag || hit.isDescendant(of: drag), "The drag overlay must leave controls reachable")
            }
        }
    }

    func testUnifiedWindowChromeTracksWorkspaceThemeAndOnlyDragsEmptyTopSpace() async throws {
        _ = NSApplication.shared
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-ChromeTheme-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let f = try fixture(), app = AppModel(repository: f.repository, security: f.security,
            location: .isolated(root), sessionBuilder: f.builder, nativeCandidateBuilder: f.builder, preferencesDefaults: nil)
        _ = await app.reload()
        addTeardownBlock { await app.sessions.closeAll(); await app.files.closeForWindow(); try FileManager.default.removeItem(at: root) }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650),
            styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; WorkspaceWindowChrome.configure(window)
        let hosting = NSHostingView(rootView: MainView(model: app))
        window.contentView = hosting; window.setFrameOrigin(NSPoint(x: -5000, y: -5000)); window.orderFront(nil)
        defer { window.orderOut(nil); window.contentView = nil; window.close() }
        try await wait {
            hosting.layoutSubtreeIfNeeded()
            return self.descendants(hosting).compactMap { $0 as? WorkspaceChromeDragView }.first?.state?.isIntegrated == true
        }
        XCTAssertEqual(window.backgroundColor, WorkspaceWindowChrome.background(terminal: false))
        app.showWorkspace(.sftp)
        try await wait { window.backgroundColor == WorkspaceWindowChrome.background(terminal: false) }
        app.requestSession(hostID: f.host.id, mode: .newSession); await app.sessions.selectedTab?.preparation?.value
        let session = try XCTUnwrap(app.sessions.selectedTab); app.showWorkspace(.session(session.id))
        try await wait { window.backgroundColor == WorkspaceWindowChrome.background(terminal: true) }
        let drag = try XCTUnwrap(descendants(hosting).compactMap { $0 as? WorkspaceChromeDragView }.first)
        let state = try XCTUnwrap(drag.state)
        try await wait {
            hosting.layoutSubtreeIfNeeded()
            return state.interactiveFrames.count == 4 && state.interactiveFrames.contains { $0.width > 180 && $0.height >= 34 }
        }
        let sessionFrame = try XCTUnwrap(state.interactiveFrames.first { $0.width > 180 && $0.height >= 34 })
        let plus = try XCTUnwrap(state.interactiveFrames.first { abs($0.width - 30) < 1 && abs($0.height - 30) < 1 })
        XCTAssertGreaterThanOrEqual(plus.minX, sessionFrame.maxX)
        XCTAssertLessThan(plus.minX - sessionFrame.maxX, 32, "Leave space for the end-drop target before the adjacent add button")
        XCTAssertFalse(state.canDrag(at: NSPoint(x: 10, y: 24), in: drag.bounds), "The actual native-controls gutter is never a content drag target")
        for frame in state.interactiveFrames where !frame.isEmpty {
            XCTAssertFalse(state.canDrag(at: NSPoint(x: frame.midX, y: frame.midY), in: drag.bounds), "Tabs, close/overflow and new-connection controls keep their own gestures")
        }
        let blank = stride(from: state.leadingInset, to: drag.bounds.maxX, by: CGFloat(4))
            .map { NSPoint(x: $0, y: DesktopStyle.barHeight / 2) }
            .first { state.canDrag(at: $0, in: drag.bounds) }
        XCTAssertNotNil(blank, "The unused part of this real top strip remains a native window-drag region")
        app.showWorkspace(.vault)
        try await wait { window.backgroundColor == WorkspaceWindowChrome.background(terminal: false) }
        XCTAssertEqual(app.sessions.tabs.map(\.id), [session.id], "Changing the top theme must preserve the real session owner")
    }
}


extension NativeSessionAdapterTests {
    func testUnifiedWindowChromeWindowRootKeepsControlsInRealContentHierarchy() async throws {
        _ = NSApplication.shared
        let directory = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-ChromeRootRouting-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let f = try fixture(), app = AppModel(repository: f.repository, security: f.security,
            location: .isolated(directory), sessionBuilder: f.builder, nativeCandidateBuilder: f.builder, preferencesDefaults: nil)
        _ = await app.reload()
        addTeardownBlock { await app.sessions.closeAll(); await app.files.closeForWindow(); try FileManager.default.removeItem(at: directory) }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 650),
            styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; WorkspaceWindowChrome.configure(window)
        let hosting = NSHostingView(rootView: MainView(model: app)); window.contentView = hosting
        window.setFrameOrigin(NSPoint(x: -5000, y: -5000))
        window.setFrame(NSRect(origin: window.frame.origin, size: NSSize(width: 1000, height: 650)), display: true)
        window.orderFront(nil)
        defer { window.orderOut(nil); window.contentView = nil; window.close() }
        try await wait {
            hosting.layoutSubtreeIfNeeded()
            guard let drag = self.descendants(hosting).compactMap({ $0 as? WorkspaceChromeDragView }).first,
                  let state = drag.state else { return false }
            return state.isIntegrated && state.interactiveFrames.filter { abs($0.width - 90) < 1 && abs($0.height - 34) < 1 }.count == 2
                && state.interactiveFrames.contains { abs($0.width - 30) < 1 && abs($0.height - 30) < 1 }
                && abs(drag.convert(drag.bounds, to: nil).maxY - hosting.convert(hosting.bounds, to: nil).maxY) < 1
        }
        let drag = try XCTUnwrap(descendants(hosting).compactMap { $0 as? WorkspaceChromeDragView }.first)
        let state = try XCTUnwrap(drag.state)
        let fixed = state.interactiveFrames.filter { abs($0.width - 90) < 1 && abs($0.height - 34) < 1 }.sorted { $0.minX < $1.minX }
        let plus = try XCTUnwrap(state.interactiveFrames.first { abs($0.width - 30) < 1 && abs($0.height - 30) < 1 })
        let nativeButtons = [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton].compactMap { window.standardWindowButton($0) }
        XCTAssertEqual(nativeButtons.count, 3); XCTAssertTrue(window.titlebarAccessoryViewControllers.isEmpty)
        var root = hosting as NSView
        while let parent = root.superview { root = parent }
        for (index, frame) in (fixed + [plus]).enumerated() {
            for y in [frame.midY, frame.maxY - 3] {
                let point = drag.convert(NSPoint(x: frame.midX, y: y), to: nil)
                let rootHit = try XCTUnwrap(root.hitTest(root.superview?.convert(point, from: nil) ?? point))
                let contentHit = try XCTUnwrap(hosting.hitTest(hosting.superview?.convert(point, from: nil) ?? point))
                XCTAssertTrue(rootHit === hosting || rootHit.isDescendant(of: hosting), "A control hit must stay in the real production content hierarchy")
                XCTAssertTrue(rootHit === contentHit, "Native titlebar siblings must not replace the content's actual hit target")
                XCTAssertFalse(rootHit === drag || rootHit.isDescendant(of: drag), "Window dragging must not claim fixed-tab or plus points")
                XCTAssertFalse(nativeButtons.contains { rootHit === $0 || rootHit.isDescendant(of: $0) }, "Native buttons must not swallow adjacent tab controls")
                print("WindowChromeRootRegression control=\(index) y=\(y) rootTarget=\(String(describing: type(of: rootHit))) insideRealContent=true targetMatchesContent=\(rootHit === contentHit)")
            }
        }
    }
}
