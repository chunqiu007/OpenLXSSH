import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHSecurity
import OpenLXSSHTransport

/// Deterministic scheduling only. No Keychain, SSH, network or timing sleeps.
@MainActor final class SessionConcurrencyTests: XCTestCase {
    private func fixture() -> (HostConfiguration, R2Repository, R2Credentials, R2Builder, SessionController) {
        let ref = UUID()
        let host = HostConfiguration(name: "R2 logical fixture", address: "never-connected.invalid", username: "fixture", credentialRef: ref, savePasswordAuthorized: true)
        let repository = R2Repository(metadata: SecurityMetadata(hosts: [host], keys: [], credentials: [.init(id: ref, purpose: .password, isSavingAuthorized: true)], tickets: []))
        let credentials = R2Credentials()
        let builder = R2Builder(host: host)
        return (host, repository, credentials, builder, SessionController(repository: repository, credentials: credentials, builder: builder))
    }
    private func connected(_ controller: SessionController, host: HostConfiguration) async throws -> SessionTab {
        let id = try XCTUnwrap(controller.open(host, mode: .reuse))
        let tab = try XCTUnwrap(controller.tabs.first { $0.id == id })
        await tab.preparation?.value
        XCTAssertNotNil(tab.driver?.token)
        return tab
    }

    func testRetirementCancelledDuplicateBatchObserverYieldsWithoutCancellingCleanup() async throws {
        try await cancelledDuplicateObserver(batch: true)
    }
    func testRetirementCancelledDuplicateTabObserverYieldsWithoutCancellingCleanup() async throws {
        try await cancelledDuplicateObserver(batch: false)
    }
    private func cancelledDuplicateObserver(batch: Bool) async throws {
        let (host, _, _, builder, controller) = fixture()
        let tab = try await connected(controller, host: host)
        controller.disconnect(tab.id)
        await builder.configurationPause.arm(); controller.reconnect(tab.id)
        await builder.configurationPause.waitForArrival()
        addTeardownBlock { await builder.configurationPause.release(); await controller.closeAll() }
        let deadline = ContinuousClock.now + .seconds(2)
        let close: @MainActor () async -> SessionCloseBatchResult = {
            if batch { return await controller.closeAllResult(deadline: deadline) }
            return SessionCloseBatchResult(entries: [.init(tabID: tab.id, result: await controller.closeTabResult(tab.id, deadline: deadline))])
        }
        let original = Task { await close() }
        // The creator has installed the real app-owned cleanup before either join starts.
        try await waitForCondition { tab.state == .closing }
        let duplicate = Task { await close() }
        try await waitForCondition { controller.closeJoinObserverCount >= 1 }
        let other = Task { await close() }
        try await waitForCondition { controller.closeJoinObserverCount >= 2 }
        let cancellationStart = ContinuousClock.now
        duplicate.cancel()
        // This MainActor heartbeat/release must execute while the original deadline is
        // still pending. A swallowed sleep CancellationError previously busy-spun here.
        let heartbeat = Task { @MainActor in
            try await Task.sleep(for: .milliseconds(10))
            await builder.configurationPause.release()
            return ContinuousClock.now
        }
        let observedAt = try await heartbeat.value
        XCTAssertLessThan(cancellationStart.duration(to: observedAt), .milliseconds(500))
        let cancelled = await duplicate.value
        guard case .incomplete(let context) = cancelled.entries.first?.result else { return XCTFail("Only the duplicate observation should stop") }
        XCTAssertEqual(context.reason, .observationCancelled)
        let a = await original.value, b = await other.value
        XCTAssertTrue(a.complete); XCTAssertEqual(a, b)
        XCTAssertTrue(controller.tabs.isEmpty); XCTAssertEqual(builder.driver?.closeCount, 1)
    }
    private func waitForCondition(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while !condition() {
            guard .now < deadline else { throw CocoaError(.executableRuntimeMismatch) }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    func testRetirementCancelledResultWaiterCannotCancelOwnedCleanupOrSecondWaiter() async throws {
        let (host, _, _, builder, controller) = fixture()
        let tab = try await connected(controller, host: host)
        controller.disconnect(tab.id)
        await builder.configurationPause.arm(); controller.reconnect(tab.id)
        await builder.configurationPause.waitForArrival()
        let started = R2Event()
        let deadline = ContinuousClock.now + .seconds(2)
        let first = Task { started.signal(); return await controller.closeAllResult(deadline: deadline) }
        await started.wait()
        let second = Task { await controller.closeAllResult(deadline: deadline) }
        first.cancel()
        XCTAssertTrue(controller.closingAll); XCTAssertNil(controller.open(host, mode: .newSession))
        let shortStart = ContinuousClock.now
        let short = await controller.closeAllResult(deadline: .now + .milliseconds(30))
        XCTAssertFalse(short.complete); XCTAssertLessThan(shortStart.duration(to: .now), .seconds(1))
        XCTAssertTrue(controller.closingAll, "A short observer must not cancel the shared cleanup owner")
        await builder.configurationPause.release()
        let a = await first.value, b = await second.value
        XCTAssertTrue(a.complete); XCTAssertEqual(a, b); XCTAssertTrue(controller.tabs.isEmpty)
        XCTAssertEqual(builder.driver?.closeCount, 1)
    }
    func testOverlappingCloseAllSharesOneBatchAndRejectsAdmissionDuringDuplicateCleanup() async throws {
        let (host, _, _, builder, controller) = fixture()
        let tab = try await connected(controller, host: host)
        let driver = try XCTUnwrap(builder.driver)
        controller.disconnect(tab.id)
        await builder.configurationPause.arm()
        controller.reconnect(tab.id)
        await builder.configurationPause.waitForArrival()
        let firstStarted = R2Event(), secondStarted = R2Event()
        let firstFinished = R2Event()
        let first = Task {
            firstStarted.signal()
            await controller.closeAll()
            firstFinished.signal()
        }
        await firstStarted.wait()
        let second = Task {
            secondStarted.signal()
            await controller.closeAll()
            firstFinished.signal()
        }
        await secondStarted.wait()
        XCTAssertTrue(controller.closingAll)
        XCTAssertNil(controller.open(host, mode: .newSession))
        await builder.configurationPause.release()
        await firstFinished.wait()
        // The broken implementation closes the same driver twice: its second
        // close is deliberately held pending so the admission bug is observable.
        if driver.closeCount > 1 {
            XCTAssertTrue(controller.closingAll)
            let admitted = controller.open(host, mode: .newSession)
            XCTAssertNil(admitted)
            driver.finishClose()
        }
        await first.value; await second.value
        XCTAssertEqual(driver.closeCount, 1)
        XCTAssertTrue(controller.tabs.isEmpty)
        XCTAssertNil(controller.selectedTabID)
        // Ordinary window cleanup is reusable after the complete batch.
        _ = controller.open(host, mode: .newSession)
        await controller.tabs.last?.preparation?.value
        await controller.closeAll()
    }

    func testConcurrentCloseTabIsIdempotentWhilePreparationIsSuspended() async throws {
        let (host, _, _, builder, controller) = fixture()
        let tab = try await connected(controller, host: host)
        let driver = try XCTUnwrap(builder.driver)
        controller.disconnect(tab.id)
        await builder.configurationPause.arm(); controller.reconnect(tab.id)
        await builder.configurationPause.waitForArrival()
        let started = R2Event(), alsoStarted = R2Event(), firstDone = R2Event()
        let a = Task { started.signal(); await controller.closeTab(tab.id); firstDone.signal() }
        await started.wait()
        let b = Task { alsoStarted.signal(); await controller.closeTab(tab.id); firstDone.signal() }
        await alsoStarted.wait()
        await builder.configurationPause.release()
        await firstDone.wait()
        if driver.closeCount > 1 { driver.finishClose() }
        await a.value; await b.value
        XCTAssertEqual(driver.closeCount, 1)
        XCTAssertTrue(controller.tabs.isEmpty)
    }

    func testWindowCloseOverlapsQuitAndTerminationNeverReopensAdmission() async throws {
        let (host, _, _, builder, controller) = fixture()
        let tab = try await connected(controller, host: host)
        let driver = try XCTUnwrap(builder.driver)
        controller.disconnect(tab.id)
        await builder.configurationPause.arm(); controller.reconnect(tab.id)
        await builder.configurationPause.waitForArrival()
        let lifecycle = AppLifecycleCoordinator(sessions: controller)
        let windowStarted = R2Event(), quitStarted = R2Event(), firstDone = R2Event()
        let window = Task { windowStarted.signal(); _ = await lifecycle.closeConnections(); firstDone.signal() }
        await windowStarted.wait()
        lifecycle.beginTermination()
        let quit = Task { quitStarted.signal(); _ = await lifecycle.closeConnections(); firstDone.signal() }
        await quitStarted.wait()
        XCTAssertNil(controller.open(host, mode: .newSession))
        await builder.configurationPause.release()
        await firstDone.wait()
        if driver.closeCount > 1 { driver.finishClose() }
        await window.value; await quit.value
        XCTAssertTrue(lifecycle.terminating)
        XCTAssertTrue(controller.tabs.isEmpty)
        XCTAssertEqual(driver.closeCount, 1)
        XCTAssertNil(controller.open(host, mode: .reuse))
        XCTAssertNil(controller.open(host, mode: .newSession))
    }

    func testCancellingCloseWaiterCannotReopenAdmissionBeforeOwnedCleanupFinishes() async throws {
        let (host, _, _, builder, controller) = fixture()
        let tab = try await connected(controller, host: host)
        let driver = try XCTUnwrap(builder.driver)
        controller.disconnect(tab.id)
        await builder.configurationPause.arm(); controller.reconnect(tab.id)
        await builder.configurationPause.waitForArrival()
        let started = R2Event()
        let close = Task { started.signal(); await controller.closeAll() }
        await started.wait()
        close.cancel()
        XCTAssertTrue(controller.closingAll)
        XCTAssertNil(controller.open(host, mode: .newSession))
        await builder.configurationPause.release()
        await close.value
        XCTAssertTrue(controller.tabs.isEmpty)
        XCTAssertEqual(driver.closeCount, 1)
    }

    func testProviderCancelledAndTabClosedDuringFirstMetadataNeverReadsCredential() async throws {
        try await cancelledDuringMetadata(.closeTab)
    }
    func testProviderOldGenerationDuringFirstMetadataNeverReadsCredential() async throws {
        try await cancelledDuringMetadata(.newGeneration)
    }
    func testProviderTaskOnlyCancellationDuringFirstMetadataNeverReadsCredential() async throws {
        try await cancelledDuringMetadata(.taskOnly)
    }
    private enum Invalidation { case closeTab, newGeneration, taskOnly }
    private func primaryRequest(token: SessionToken, tabID: UUID) -> SessionPrimaryRequest {
        SessionPrimaryRequest(token: token, id: UUID(), nativeSessionID: tabID, purpose: .password, key: nil)
    }
    private func cancelledDuringMetadata(_ invalidation: Invalidation) async throws {
        let (host, repository, credentials, builder, controller) = fixture()
        let tab = try await connected(controller, host: host)
        let token = try XCTUnwrap(tab.driver?.token)
        await repository.pause.arm()
        let request = primaryRequest(token: token, tabID: tab.id)
        let provider = Task { try await controller.readTypedPrimary(request, tabID: tab.id, expectedHost: host) }
        await repository.pause.waitForArrival()
        switch invalidation {
        case .closeTab:
            provider.cancel(); await controller.closeTab(tab.id)
        case .newGeneration:
            try builder.driver?.advanceGeneration()
        case .taskOnly: provider.cancel()
        }
        await repository.pause.release()
        do {
            _ = try await provider.value
            XCTFail("Invalidated primary read must throw")
        } catch {}
        let reads = await credentials.readCount
        XCTAssertEqual(reads, 0)
        await controller.closeAll()
    }

    func testProviderCancelledBeforeEntryDoesNotReadMetadataOrCredential() async throws {
        let (host, repository, credentials, _, controller) = fixture()
        let tab = try await connected(controller, host: host)
        let token = try XCTUnwrap(tab.driver?.token)
        let entry = R2Pause(); await entry.arm()
        let request = primaryRequest(token: token, tabID: tab.id)
        let provider = Task {
            await entry.suspendIfArmed()
            return try await controller.readTypedPrimary(request, tabID: tab.id, expectedHost: host)
        }
        await entry.waitForArrival(); provider.cancel(); await entry.release()
        do {
            _ = try await provider.value
            XCTFail("Cancelled primary read must throw")
        } catch {}
        let metadataReads = await repository.metadataReads, credentialReads = await credentials.readCount
        XCTAssertEqual(metadataReads, 0); XCTAssertEqual(credentialReads, 0)
        await controller.closeAll()
    }

    func testProviderCancelledDuringFinalMetadataDoesNotReturnSecret() async throws {
        let (host, repository, credentials, _, controller) = fixture()
        let tab = try await connected(controller, host: host)
        let token = try XCTUnwrap(tab.driver?.token)
        await credentials.pause.arm()
        let request = primaryRequest(token: token, tabID: tab.id)
        let provider = Task { try await controller.readTypedPrimary(request, tabID: tab.id, expectedHost: host) }
        await credentials.pause.waitForArrival()
        await repository.pause.arm()
        await credentials.pause.release()
        await repository.pause.waitForArrival()
        provider.cancel()
        await repository.pause.release()
        do {
            _ = try await provider.value
            XCTFail("Cancelled primary read during final metadata must throw")
        } catch {}
        let reads = await credentials.readCount
        XCTAssertEqual(reads, 1)
        await controller.closeAll()
    }

    func testProviderCancelledDuringCredentialAwaitDoesNotPerformSecondMetadataOrReturnSecret() async throws {
        let (host, repository, credentials, _, controller) = fixture()
        let tab = try await connected(controller, host: host)
        let token = try XCTUnwrap(tab.driver?.token)
        await credentials.pause.arm()
        let request = primaryRequest(token: token, tabID: tab.id)
        let provider = Task { try await controller.readTypedPrimary(request, tabID: tab.id, expectedHost: host) }
        await credentials.pause.waitForArrival()
        provider.cancel()
        await credentials.pause.release()
        do {
            _ = try await provider.value
            XCTFail("Cancelled primary read during credential await must throw")
        } catch {}
        let metadataReads = await repository.metadataReads
        XCTAssertEqual(metadataReads, 1)
        await controller.closeAll()
    }
}

private actor R2Pause {
    private var blocked = false
    private var arrivals = 0
    private var waiting: CheckedContinuation<Void, Never>?
    private var arrivalWaiters: [CheckedContinuation<Void, Never>] = []
    func arm() { blocked = true; arrivals = 0 }
    func suspendIfArmed() async {
        guard blocked else { return }
        arrivals += 1
        let observers = arrivalWaiters; arrivalWaiters = []; observers.forEach { $0.resume() }
        await withCheckedContinuation { waiting = $0 }
    }
    func waitForArrival() async {
        if arrivals > 0 { return }
        await withCheckedContinuation { arrivalWaiters.append($0) }
    }
    func release() { blocked = false; let value = waiting; waiting = nil; value?.resume() }
}
@MainActor private final class R2Event {
    private var done = false
    private var waiter: CheckedContinuation<Void, Never>?
    func signal() { done = true; let value = waiter; waiter = nil; value?.resume() }
    func wait() async { if !done { await withCheckedContinuation { waiter = $0 } } }
}
private actor R2Repository: AppRepositoryProtocol {
    let pause = R2Pause()
    let metadata: SecurityMetadata
    private(set) var metadataReads = 0
    init(metadata: SecurityMetadata) { self.metadata = metadata }
    func securityMetadata() async throws -> SecurityMetadata { metadataReads += 1; await pause.suspendIfArmed(); return metadata }
    func snapshot(query: HostQuery) throws -> AppSnapshot { AppSnapshot(hosts: metadata.hosts, folders: [], keys: [], settings: AppSettings()) }
    func apply(_ changes: [RepositoryChange]) throws {}
    func copyHost(id: UUID) throws -> HostConfiguration { throw RepositoryError.notFound }
    func copyFolder(id: UUID) throws -> HostFolder { throw RepositoryError.notFound }
    func close() {}
}
private actor R2Credentials: CredentialAccess {
    let pause = R2Pause()
    private(set) var readCount = 0
    func read(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialReadResult {
        readCount += 1; await pause.suspendIfArmed(); return .available(.init(utf8: UUID().uuidString))
    }
    func save(_ secret: OpenLXSSHSecurity.SecretBytes, as reference: OpenLXSSHSecurity.CredentialReference, authorization: RememberAuthorization) -> CredentialSaveResult { .notAuthorized }
    func deleteExact(_ reference: OpenLXSSHSecurity.CredentialReference) -> CredentialDeleteResult { .alreadyAbsent }
    func close() {}
}
@MainActor private final class R2Builder: SessionBuilding {
    let host: HostConfiguration
    let configurationPause = R2Pause()
    var driver: R2Driver?
    init(host: HostConfiguration) { self.host = host }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        await configurationPause.suspendIfArmed()
        return (host, try SessionEnvironment.configuration(host: host, keyPath: nil))
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        let (_, config) = try await configuration(hostID: hostID)
        let driver = R2Driver(id: sessionID, configuration: config); self.driver = driver
        return ReadySession(host: host, configuration: config, driver: driver)
    }
}
@MainActor private final class R2Driver: SessionDriving {
    let id: UUID
    let terminal = NativeTerminalView()
    let configuration: SSHSessionConfiguration
    var token: SessionToken?
    var state: SSHSessionState = .idle
    var canReconnect: Bool { state == .idle || state == .disconnected(nil) }
    var onState: ((SessionToken?, SSHSessionState) -> Void)?
    var onTrust: (([SessionTrustPrompt]) -> Void)?
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)?
    var closeCount = 0
    init(id: UUID, configuration: SSHSessionConfiguration) { self.id = id; self.configuration = configuration }
    func connect(_ configuration: SSHSessionConfiguration, primary: SessionPrimaryAuthorization) throws -> SessionToken {
        token = SessionToken(sessionID: id, generation: (token?.generation ?? 0) + 1)
        state = .connectionPending; onState?(token, state); return token!
    }
    func advanceGeneration() throws { _ = try connect(configuration, primary: SessionPrimaryAuthorization(provider: { _ in nil })) }
    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) async throws {}
    func respond(_ answer: SessionAuthenticationAnswer, to prompt: SessionAuthenticationPrompt) throws {}
    func cancel() { state = .disconnected(nil); onState?(token, state) }
    func closeTab() {
        closeCount += 1
        if closeCount == 1 { finishClose() }
        else { state = .closing; onState?(token, state) }
    }
    func finishClose() { state = .closed; terminal.releaseResources(); onState?(token, state) }
}
