import AppKit
import Combine
import CryptoKit
import Darwin
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust

@MainActor final class FilesTransferTests: XCTestCase {
    private func fixture() throws -> (URL, URL, URL, FilesController, TransferPause) {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        let local = root.appendingPathComponent("local"), remote = root.appendingPathComponent("remote")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: local, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: remote, withIntermediateDirectories: true)
        addTeardownBlock { try FileManager.default.removeItem(at: root) }
        let pause = TransferPause()
        let controller = FilesController(connector: TransferLocalConnector(root: remote), idleTimeout: nil,
            localService: { try TransferLocalService(fd: $0, pause: pause) })
        return (root, local, remote, controller, pause)
    }
    private func connect(_ model: FilesController, host: HostConfiguration? = nil) async {
        model.show(host: host ?? .init(name: "real Local, not SFTP", address: "never-connected.invalid", username: "fixture"))
        await model.waitUntilCurrentWorkCompletes()
        model.connect(.init(primary: .manual(.init(utf8: "")))); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
    }
    private func terminal(_ model: FilesController, _ ids: [UUID]) async throws -> [TransferJobSnapshot] {
        let stream = try await model.manager.updates()
        for await value in stream {
            let jobs = value.jobs.filter { ids.contains($0.id) }
            if jobs.count == ids.count && jobs.allSatisfy({ !$0.state.isActive }) { return jobs }
        }
        throw FileServiceError(.closed, operation: "test-stream-closed")
    }
    private func pending(_ model: FilesController, _ id: UUID, risk: Bool = false) async throws -> TransferDecisionRequest {
        for await snapshot in try await model.manager.updates() {
            if let question = snapshot.jobs.first(where: { $0.id == id })?.pendingDecision {
                if case .risk = question.question { if risk { return question } }
                else if !risk { return question }
            }
        }
        throw FileServiceError(.closed, operation: "test-decision-closed")
    }
    private func sha(_ url: URL) throws -> SHA256.Digest { SHA256.hash(data: try Data(contentsOf: url)) }
    func testControllerUploadsMultipleParentsAndTreeThenDownloadsExactNames() async throws {
        let (root, local, remote, model, _) = try fixture()
        let other = root.appendingPathComponent("other"); try FileManager.default.createDirectory(at: other, withIntermediateDirectories: false)
        let names = ["中文 e\u{301} line\nfile", "space ' % "]
        try Data("first".utf8).write(to: local.appendingPathComponent(names[0]))
        try Data("second".utf8).write(to: other.appendingPathComponent(names[1]))
        let tree = local.appendingPathComponent("树 folder")
        try FileManager.default.createDirectory(at: tree.appendingPathComponent("子 目录"), withIntermediateDirectories: true)
        try Data(repeating: 123, count: 180000).write(to: tree.appendingPathComponent("子 目录/special\nname"))
        await connect(model)
        let context = try model.transferContext(upload: true)
        let ids = try await model.enqueueUploads([local.appendingPathComponent(names[0]), other.appendingPathComponent(names[1]), tree], context: context).value
        let jobs = try await terminal(model, ids)
        XCTAssertTrue(jobs.allSatisfy { $0.state == .succeeded })
        XCTAssertEqual(Set(jobs.map(\.request.batchID)).count, 1)
        XCTAssertEqual(try sha(local.appendingPathComponent(names[0])), try sha(remote.appendingPathComponent(names[0])))
        XCTAssertEqual(try sha(other.appendingPathComponent(names[1])), try sha(remote.appendingPathComponent(names[1])))
        XCTAssertEqual(try sha(tree.appendingPathComponent("子 目录/special\nname")), try sha(remote.appendingPathComponent("树 folder/子 目录/special\nname")))
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        let download = root.appendingPathComponent("download"); try FileManager.default.createDirectory(at: download, withIntermediateDirectories: false)
        let down = try await model.enqueueDownloads(model.entries, to: download, context: model.transferContext(upload: false)).value
        let downJobs = try await terminal(model, down)
        XCTAssertTrue(downJobs.allSatisfy { $0.state == .succeeded })
        XCTAssertEqual(try sha(download.appendingPathComponent(names[0])), try sha(local.appendingPathComponent(names[0])))
        XCTAssertEqual(try sha(download.appendingPathComponent("树 folder/子 目录/special\nname")), try sha(tree.appendingPathComponent("子 目录/special\nname")))
        await model.closeForWindow()
    }
    func testRealQuarterCancellationPreservesExistingTargetAndRejectsLateRiskAnswer() async throws {
        let (_, local, remote, model, pause) = try fixture()
        let size = 4 * 1024 * 1024
        try Data(repeating: 63, count: size).write(to: local.appendingPathComponent("large"))
        try Data("old-target".utf8).write(to: remote.appendingPathComponent("large"))
        let old = try sha(remote.appendingPathComponent("large"))
        var before = stat(); XCTAssertEqual(lstat(remote.appendingPathComponent("large").path, &before), 0)
        await connect(model); await pause.arm(afterBytes: UInt64(size / 4))
        let ids = try await model.enqueueUploads([local.appendingPathComponent("large")], context: model.transferContext(upload: true)).value
        let id = try XCTUnwrap(ids.first)
        let conflict = try await pending(model, id)
        assertTrueValue(await model.answerTransfer(conflict, answer: .conflict(.overwrite, applyToBatch: false)))
        let risk = try await pending(model, id, risk: true)
        assertTrueValue(await model.answerTransfer(risk, answer: .risk(accepted: true)))
        await pause.arrived()
        let progress = await model.manager.snapshot().jobs.first { $0.id == id }
        XCTAssertEqual(progress?.transferredBytes, UInt64(size / 4))
        await model.cancelTransfer(id); await pause.release()
        let results = try await terminal(model, [id])
        let result = try XCTUnwrap(results.first)
        XCTAssertEqual(result.state, .cancelled)
        XCTAssertEqual(try sha(remote.appendingPathComponent("large")), old)
        var after = stat(); XCTAssertEqual(lstat(remote.appendingPathComponent("large").path, &after), 0)
        XCTAssertEqual(after.st_ino, before.st_ino)
        XCTAssertTrue(result.retainedTemporaryPaths.isEmpty)
        assertFalseValue(await model.answerTransfer(risk, answer: .risk(accepted: true)))
        await model.closeForWindow()
    }
    func testHideHostSwitchAndCloseIndependentTabNeverRetargetsAdmittedJobs() async throws {
        let (_, local, remote, model, pause) = try fixture()
        try Data(repeating: 51, count: 262144).write(to: local.appendingPathComponent("keep"))
        await connect(model)
        let host = try XCTUnwrap(model.selectedHost)
        let repository = AppRepository(location: .isolated(local.deletingLastPathComponent()))
        try await repository.apply([.insertHost(host)])
        let builder = TransferSessionBuilder(host: host)
        let sessions = SessionController(repository: repository, credentials: TransferNoCredentials(), builder: builder)
        let firstTab = try XCTUnwrap(sessions.open(host, mode: .newSession))
        let first = try XCTUnwrap(sessions.tabs.first { $0.id == firstTab }); await first.preparation?.value
        let secondTab = try XCTUnwrap(sessions.open(host, mode: .newSession)); await sessions.tabs.last?.preparation?.value
        await pause.arm(afterBytes: 0)
        let ids = try await model.enqueueUploads([local.appendingPathComponent("keep")], context: model.transferContext(upload: true)).value
        let id = try XCTUnwrap(ids.first)
        await pause.arrived()
        sessions.select(secondTab); await sessions.closeTab(firstTab)
        XCTAssertEqual(sessions.selectedTabID, secondTab); XCTAssertFalse(sessions.tabs.contains { $0.id == firstTab })
        model.hide()
        model.show(host: .init(name: "next", address: "another-never.invalid", username: "next"))
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertTrue(model.tasksVisible)
        let snapshot = await model.manager.snapshot()
        let job = try XCTUnwrap(snapshot.jobs.first { $0.id == id })
        XCTAssertEqual(job.request.hostID, host.id.uuidString)
        XCTAssertTrue(job.state.isActive)
        await pause.release()
        let finished = try await terminal(model, [id])
        XCTAssertEqual(finished.first?.state, .succeeded)
        XCTAssertEqual(try sha(local.appendingPathComponent("keep")), try sha(remote.appendingPathComponent("keep")))
        await model.closeForWindow(); await sessions.closeAll(); try await repository.close()
    }
    func testBatchSkipRenameMixedTreeAndIndependentOverwriteRisk() async throws {
        let (_, local, remote, model, _) = try fixture()
        for name in ["a", "b"] {
            try Data(("new-" + name).utf8).write(to: local.appendingPathComponent(name))
            try Data(("old-" + name).utf8).write(to: remote.appendingPathComponent(name))
        }
        await connect(model)
        let batch = try await model.enqueueUploads([local.appendingPathComponent("a"), local.appendingPathComponent("b")], context: model.transferContext(upload: true)).value
        let decision = try await pending(model, batch[0])
        assertFalseValue(await model.answerTransfer(decision, answer: .risk(accepted: true)))
        assertTrueValue(await model.answerTransfer(decision, answer: .conflict(.skip, applyToBatch: true)))
        let skipped = try await terminal(model, batch)
        XCTAssertTrue(skipped.allSatisfy { $0.state == .skipped })
        assertFalseValue(await model.answerTransfer(decision, answer: .conflict(.overwrite, applyToBatch: true)))
        let renameIDs = try await model.enqueueUploads([local.appendingPathComponent("a")], context: model.transferContext(upload: true)).value
        let rename = try await pending(model, renameIDs[0])
        assertFalseValue(await model.answerTransfer(rename, answer: .conflict(.renameTo(try FileName("alternate")), applyToBatch: true)))
        assertTrueValue(await model.answerTransfer(rename, answer: .conflict(.renameTo(try FileName("alternate")), applyToBatch: false)))
        let renamed = try await terminal(model, renameIDs)
        XCTAssertEqual(renamed.first?.state, .succeeded)
        XCTAssertEqual(try sha(local.appendingPathComponent("a")), try sha(remote.appendingPathComponent("alternate")))
        let riskIDs = try await model.enqueueUploads([local.appendingPathComponent("a")], context: model.transferContext(upload: true)).value
        let overwrite = try await pending(model, riskIDs[0])
        assertTrueValue(await model.answerTransfer(overwrite, answer: .conflict(.overwrite, applyToBatch: true)))
        let risk = try await pending(model, riskIDs[0], risk: true)
        model.hide(); XCTAssertTrue(model.tasksVisible)
        await model.cancelTransfer(riskIDs[0])
        assertFalseValue(await model.answerTransfer(risk, answer: .risk(accepted: true)))
        _ = try await terminal(model, riskIDs)
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("a")), Data("old-a".utf8))
        let tree = local.appendingPathComponent("mixed")
        try FileManager.default.createDirectory(at: tree, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: remote.appendingPathComponent("mixed"), withIntermediateDirectories: false)
        try Data([1]).write(to: tree.appendingPathComponent("skip")); try Data([2]).write(to: tree.appendingPathComponent("ok"))
        try Data([3]).write(to: remote.appendingPathComponent("mixed/skip"))
        let mixedIDs = try await model.enqueueUploads([tree], context: model.transferContext(upload: true)).value
        let mixedDecision = try await pending(model, mixedIDs[0])
        assertTrueValue(await model.answerTransfer(mixedDecision, answer: .conflict(.skip, applyToBatch: false)))
        let mixed = try await terminal(model, mixedIDs)
        XCTAssertEqual(mixed.first?.state, .completedWithSkips)
        XCTAssertTrue(mixed.first?.items.contains { $0.state == .skipped } == true)
        try FileManager.default.createSymbolicLink(at: tree.appendingPathComponent("link"), withDestinationURL: local.appendingPathComponent("a"))
        let failureIDs = try await model.enqueueUploads([tree], context: model.transferContext(upload: true)).value
        let failedDecision = try await pending(model, failureIDs[0])
        assertTrueValue(await model.answerTransfer(failedDecision, answer: .conflict(.skip, applyToBatch: true)))
        let failed = try await terminal(model, failureIDs)
        XCTAssertEqual(failed.first?.state, .failed)
        XCTAssertTrue(failed.first?.items.contains { if case .failed(let e) = $0.state { return e.kind == .symbolicLink }; return false } == true)
        await model.closeForWindow()
    }
    func testQueuedCancellationRetryNewGenerationAndClosedIdleRefusesRetry() async throws {
        let (_, local, _, model, pause) = try fixture()
        try Data(repeating: 7, count: 65536).write(to: local.appendingPathComponent("file"))
        await connect(model); await pause.arm(afterBytes: 0)
        let ids = try await model.enqueueUploads([local.appendingPathComponent("file"), local.appendingPathComponent("file")], context: model.transferContext(upload: true)).value
        await pause.arrived()
        await model.cancelTransfer(ids[1])
        let cancelled = try await terminal(model, [ids[1]])
        XCTAssertEqual(cancelled.first?.transferredBytes, 0)
        let retriedIDs = try await model.retryTransfer(ids[1]).value
        let snapshot = await model.manager.snapshot()
        let fresh = try XCTUnwrap(snapshot.jobs.first { $0.id == retriedIDs[0] })
        XCTAssertNotEqual(fresh.id, ids[1]); XCTAssertNotEqual(fresh.generation, cancelled.first?.generation)
        XCTAssertEqual(fresh.retryOf, ids[1]); XCTAssertEqual(fresh.transferredBytes, 0)
        await model.cancelTransfer(retriedIDs[0]); await model.cancelTransfer(ids[0]); await pause.release()
        _ = try await terminal(model, [ids[0], retriedIDs[0]])
        await model.manager.closeIdleServices()
        do { _ = try await model.retryTransfer(ids[0]).value; XCTFail("Idle-closed service was implicitly reconnected") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .closed) }
        await model.closeForWindow()
    }
    func testRawRootsRejectLinksAndFailedAdmissionsReleaseOnlyNewLocalServices() async throws {
        let (root, local, _, model, _) = try fixture()
        try Data([1]).write(to: local.appendingPathComponent("file"))
        let link = root.appendingPathComponent("parent-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: local)
        await connect(model)
        do { _ = try await model.enqueueUploads([link.appendingPathComponent("file")], context: model.transferContext(upload: true)).value; XCTFail("Linked parent accepted") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .symbolicLink) }
        try FileManager.default.createSymbolicLink(at: local.appendingPathComponent("link"), withDestinationURL: local.appendingPathComponent("file"))
        for _ in 0..<130 {
            do { _ = try await model.enqueueUploads([local.appendingPathComponent("file"), local.appendingPathComponent("link")], context: model.transferContext(upload: true)).value; XCTFail("Link accepted") }
            catch let e as FileServiceError { XCTAssertEqual(e.kind, .symbolicLink) }
        }
        // If failed registration leaked a slot, this final job would hit managed-services=128.
        let ids = try await model.enqueueUploads([local.appendingPathComponent("file")], context: model.transferContext(upload: true)).value
        let result = try await terminal(model, ids); XCTAssertEqual(result.first?.state, .succeeded)
        model.browse(.root); await model.waitUntilCurrentWorkCompletes(); XCTAssertEqual(model.state, .ready)
        await model.closeForWindow()
    }
    func testImmediateFreezeWaitsAdmittedEnqueueBeforeAuthoritativeSnapshot() async throws {
        let (_, local, _, model, pause) = try fixture()
        try Data(repeating: 8, count: 65536).write(to: local.appendingPathComponent("file"))
        await connect(model); await pause.arm(afterBytes: 0)
        let admission = try model.enqueueUploads([local.appendingPathComponent("file")], context: model.transferContext(upload: true))
        XCTAssertEqual(model.enqueueInFlight, 1)
        XCTAssertFalse(model.hasActiveTransfers) // Manager mirror has not delivered yet.
        model.freezeTransferAdmission()
        let active = await model.activeTransferSnapshot(); XCTAssertTrue(active)
        XCTAssertEqual(model.enqueueInFlight, 0)
        XCTAssertThrowsError(try model.enqueueUploads([local.appendingPathComponent("file")], context: model.transferContext(upload: true)))
        model.resumeTransferAdmission()
        let ids = try await admission.value
        await model.cancelTransfer(ids[0]); await pause.release(); _ = try await terminal(model, ids)
        await model.closeForWindow()
    }
    func testExplicitHistoryRemovalKeepsActiveJobsAndDoesNotDeleteCompletedFiles() async throws {
        let (_, local, remote, model, pause) = try fixture()
        try Data(repeating: 1, count: 65536).write(to: local.appendingPathComponent("first"))
        try Data(repeating: 2, count: 65536).write(to: local.appendingPathComponent("second"))
        await connect(model)
        let first = try await model.enqueueUploads([local.appendingPathComponent("first")], context: model.transferContext(upload: true)).value
        _ = try await terminal(model, first)
        let displayed = model.displayedTransferPath(try RemotePath("/first"), serviceID: model.transferSnapshot.jobs[0].request.source.serviceID, jobID: first[0])
        XCTAssertEqual(displayed, FileDisplay.bytes(try FilesLocalPaths.rawPath(FilesLocalPaths.components(local.appendingPathComponent("first"))).bytes))
        await pause.arm(afterBytes: 0)
        let active = try await model.enqueueUploads([local.appendingPathComponent("second")], context: model.transferContext(upload: true)).value
        await pause.arrived()
        _ = await model.activeTransferSnapshot() // Review only the state actually displayed by the controller.
        let review = try XCTUnwrap(model.prepareHistoryRemoval())
        assertTrueValue(await model.removeFinishedTransfers(review).value)
        let snapshot = await model.manager.snapshot()
        XCTAssertNil(snapshot.jobs.first { $0.id == first[0] }); XCTAssertTrue(snapshot.jobs.contains { $0.id == active[0] && $0.state.isActive })
        XCTAssertTrue(FileManager.default.fileExists(atPath: remote.appendingPathComponent("first").path))
        await model.cancelTransfer(active[0]); await pause.release(); _ = try await terminal(model, active)
        await model.closeForWindow()
    }
    func testRetainedTemporaryIsVisibleAndExplicitHistoryRemovalNeverDeletesIt() async throws {
        let (_, local, remote, original, _) = try fixture()
        await original.closeForWindow()
        let service = try TransferDisconnectingService(root: remote)
        let model = FilesController(connector: TransferFixedConnector(service: service), idleTimeout: nil)
        try Data(repeating: 39, count: 120000).write(to: local.appendingPathComponent("partial"))
        await connect(model)
        let ids = try await model.enqueueUploads([local.appendingPathComponent("partial")], context: model.transferContext(upload: true)).value
        let result = try await terminal(model, ids)
        XCTAssertEqual(result.first?.state, .failed)
        let path = try XCTUnwrap(result.first?.retainedTemporaryPaths.first)
        let retained = remote.appendingPathComponent(String(decoding: path.bytes.dropFirst(), as: UTF8.self))
        XCTAssertTrue(FileManager.default.fileExists(atPath: retained.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: remote.appendingPathComponent("partial").path))
        _ = await model.activeTransferSnapshot() // Review only the state actually displayed by the controller.
        let review = try XCTUnwrap(model.prepareHistoryRemoval())
        assertTrueValue(await model.removeFinishedTransfers(review).value)
        XCTAssertTrue(FileManager.default.fileExists(atPath: retained.path))
        let snapshot = await model.manager.snapshot(); XCTAssertTrue(snapshot.jobs.isEmpty)
        // A separate failed task verifies that actual close drains first but retains
        // the exact report/labels until the application-level acknowledgement finishes.
        let secondService = try TransferDisconnectingService(root: remote)
        let closing = FilesController(connector: TransferFixedConnector(service: secondService), idleTimeout: nil)
        await connect(closing)
        let secondIDs = try await closing.enqueueUploads([local.appendingPathComponent("partial")], context: closing.transferContext(upload: true)).value
        let secondResult = try await terminal(closing, secondIDs)
        let previous = closing.manager
        closing.deferResetUntilCloseAcknowledged(); await closing.closeForWindow()
        XCTAssertTrue(previous === closing.manager)
        XCTAssertEqual(closing.transferSnapshot.jobs.first?.retainedTemporaryPaths, secondResult.first?.retainedTemporaryPaths)
        XCTAssertNotNil(closing.transferLabels[secondIDs[0]])
        XCTAssertTrue(closing.admissionFrozen)
        closing.finishWindowCloseReset()
        XCTAssertFalse(previous === closing.manager); XCTAssertTrue(closing.transferSnapshot.jobs.isEmpty)
        await model.closeForWindow(); await closing.closeForWindow()
    }
    func testDownloadRootRefusesLinkedAncestorAndKnownRemoteNeedsExplicitProbe() async throws {
        let (root, local, remote, original, _) = try fixture()
        await original.closeForWindow()
        try Data([4]).write(to: remote.appendingPathComponent("file"))
        let service = try TransferNeedsProbeService(root: remote)
        let model = FilesController(connector: TransferFixedConnector(service: service), idleTimeout: nil)
        await connect(model)
        XCTAssertThrowsError(try model.transferContext(upload: true))
        XCTAssertEqual(model.issue?.code, "files.needsCapabilityConfirmation")
        let before = await model.manager.snapshot(); XCTAssertTrue(before.jobs.isEmpty)
        let link = root.appendingPathComponent("download-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: local)
        do { _ = try await model.enqueueDownloads(model.entries, to: link, context: model.transferContext(upload: false)).value; XCTFail("Linked download root accepted") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .symbolicLink) }
        let after = await model.manager.snapshot(); XCTAssertTrue(after.jobs.isEmpty)
        await model.closeForWindow()
    }
    func testLateOperationRiskAfterWindowCloseCannotInstallMailboxWhileSSHCleanupWaits() async throws {
        let (root, _, remote, original, _) = try fixture()
        await original.closeForWindow()
        try Data("unchanged".utf8).write(to: remote.appendingPathComponent("source"))
        let delivery = TransferR1Gate()
        let service = try TransferNeedsProbeService(root: remote)
        let model = FilesController(connector: TransferFixedConnector(service: service), idleTimeout: nil,
            beforeOperationRiskDelivery: { await delivery.suspend() })
        await connect(model)
        let host = try XCTUnwrap(model.selectedHost)
        let repository = AppRepository(location: .isolated(root))
        try await repository.apply([.insertHost(host)])
        let builder = TransferSessionBuilder(host: host); builder.holdClose = true
        let sessions = SessionController(repository: repository, credentials: TransferNoCredentials(), builder: builder)
        _ = sessions.open(host, mode: .newSession); await sessions.tabs.first?.preparation?.value
        let driver = try XCTUnwrap(builder.drivers.first)
        let lifecycle = AppLifecycleCoordinator(sessions: sessions); lifecycle.files = model
        let source = try XCTUnwrap(model.entries.first { $0.name.bytes == Data("source".utf8) })
        let previous = model.manager
        model.rename(source, name: try FileName("renamed"), conflict: .fail)
        await delivery.arrived()
        let close = Task { await lifecycle.closeConnections() }
        await driver.closeStarted.wait() // beginWindowClose has run, closeForWindow has not.
        XCTAssertTrue(model.admissionFrozen); XCTAssertNil(model.pendingRisk)
        let delivered = TransferR1Event()
        var riskObservation: AnyCancellable? = model.$riskID.sink { if $0 != nil { delivered.signal() } }
        var operationObservation: AnyCancellable? = model.$busy.sink { if !$0 { delivered.signal() } }
        await delivery.release(); await delivered.wait()
        riskObservation?.cancel(); riskObservation = nil; operationObservation?.cancel(); operationObservation = nil
        XCTAssertNil(model.riskID, "Closing file operations must reject a late cross-actor risk request")
        XCTAssertNil(model.pendingRisk)
        // On the broken implementation this is a genuine red result. Do not answer
        // the new risk or force cleanup to make the blocked close appear to complete.
        guard model.riskID == nil else { return }
        driver.releaseClose()
        let closed = await close.value; XCTAssertTrue(closed)
        let final = await previous.snapshot()
        XCTAssertTrue(final.isClosed); XCTAssertFalse(final.hasActiveWork)
        XCTAssertNil(model.pendingRisk)
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("source")), Data("unchanged".utf8))
        try await repository.close()
    }
    func testHistoryReviewNeverExpandsToNewlyFailedRetainedReport() async throws {
        let (_, local, remote, original, _) = try fixture(); await original.closeForWindow()
        try Data("new".utf8).write(to: local.appendingPathComponent("A"))
        try Data("old".utf8).write(to: remote.appendingPathComponent("A"))
        try Data(repeating: 8, count: 65536).write(to: local.appendingPathComponent("B"))
        let failure = TransferR1Gate()
        let service = try TransferDisconnectingService(root: remote, beforeFailure: failure)
        let model = FilesController(connector: TransferFixedConnector(service: service), idleTimeout: nil)
        await connect(model)
        let ids = try await model.enqueueUploads([local.appendingPathComponent("A"), local.appendingPathComponent("B")], context: model.transferContext(upload: true)).value
        let conflict = try await pending(model, ids[0])
        assertTrueValue(await model.answerTransfer(conflict, answer: .conflict(.skip, applyToBatch: false)))
        await failure.arrived()
        _ = await model.activeTransferSnapshot()
        let reviewed = try XCTUnwrap(model.prepareHistoryRemoval())
        XCTAssertEqual(reviewed.jobs.map(\.id), [ids[0]])
        await failure.release()
        let failed = try await terminal(model, [ids[1]])
        let retained = try XCTUnwrap(failed.first?.retainedTemporaryPaths.first)
        let retainedURL = remote.appendingPathComponent(String(decoding: retained.bytes.dropFirst(), as: UTF8.self))
        assertTrueValue(await model.removeFinishedTransfers(reviewed).value)
        let final = await model.manager.snapshot()
        XCTAssertNil(final.jobs.first { $0.id == ids[0] })
        XCTAssertEqual(final.jobs.first { $0.id == ids[1] }, failed.first)
        XCTAssertNotNil(model.transferLabels[ids[1]])
        XCTAssertTrue(FileManager.default.fileExists(atPath: retainedURL.path))
        assertFalseValue(await model.removeFinishedTransfers(reviewed).value) // Once-only review.
        await model.closeForWindow()
    }
    func testHistoryRemovalSuspendedAcrossFreezeCannotRemoveCloseReport() async throws {
        let (_, local, remote, original, _) = try fixture(); await original.closeForWindow()
        try Data(repeating: 17, count: 65536).write(to: local.appendingPathComponent("failed"))
        let gate = TransferR1Gate()
        let service = try TransferDisconnectingService(root: remote)
        let model = FilesController(connector: TransferFixedConnector(service: service), idleTimeout: nil,
            beforeHistoryRemovalSnapshot: { await gate.suspend() })
        await connect(model)
        let ids = try await model.enqueueUploads([local.appendingPathComponent("failed")], context: model.transferContext(upload: true)).value
        let failed = try await terminal(model, ids)
        _ = await model.activeTransferSnapshot() // Review only the state actually displayed by the controller.
        let review = try XCTUnwrap(model.prepareHistoryRemoval())
        let removal = model.removeFinishedTransfers(review)
        await gate.arrived()
        model.freezeTransferAdmission(); model.deferResetUntilCloseAcknowledged()
        let began = TransferR1Event()
        let close = Task { began.signal(); await model.closeForWindow() }
        await began.wait()
        await gate.release()
        assertFalseValue(await removal.value)
        await close.value
        XCTAssertEqual(model.transferSnapshot.jobs.first, failed.first)
        XCTAssertNotNil(model.transferLabels[ids[0]])
        let retained = try XCTUnwrap(failed.first?.retainedTemporaryPaths.first)
        XCTAssertTrue(FileManager.default.fileExists(atPath: remote.appendingPathComponent(String(decoding: retained.bytes.dropFirst(), as: UTF8.self)).path))
        model.finishWindowCloseReset()
        assertFalseValue(await model.removeFinishedTransfers(review).value) // Prior manager lifetime.
    }
    func testHistoryRemovalFreezeRevocationSurvivesAdmissionResume() async throws {
        let (_, local, _, original, _) = try fixture(); await original.closeForWindow()
        let gate = TransferR1Gate()
        let model = FilesController(connector: TransferLocalConnector(root: local), idleTimeout: nil,
            beforeHistoryRemovalSnapshot: { await gate.suspend() })
        await connect(model)
        try Data([7]).write(to: local.appendingPathComponent("item"))
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        let target = local.appendingPathComponent("output"); try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
        let ids = try await model.enqueueDownloads(model.entries, to: target, context: model.transferContext(upload: false)).value
        _ = try await terminal(model, ids); _ = await model.activeTransferSnapshot()
        let review = try XCTUnwrap(model.prepareHistoryRemoval())
        let removal = model.removeFinishedTransfers(review)
        await gate.arrived()
        model.freezeTransferAdmission(); model.resumeTransferAdmission()
        await gate.release()
        assertFalseValue(await removal.value)
        let snapshot = await model.manager.snapshot(); XCTAssertTrue(snapshot.jobs.contains { $0.id == ids[0] })
        XCTAssertNotNil(model.transferLabels[ids[0]])
        await model.closeForWindow()
    }
}

private actor TransferLocalConnector: FilesConnecting {
    let root: URL
    init(root: URL) { self.root = root }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken, trust: @escaping FileHostTrustHandler,
                 keyboard: @escaping FilesKeyboardHandler, isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        try token.check(); return try LocalFileService(root: root)
    }
}
private actor TransferPause {
    private var threshold: UInt64?
    private var bytes: UInt64 = 0
    private var waiting: CheckedContinuation<Void, Never>?
    private var observers: [CheckedContinuation<Void, Never>] = []
    func arm(afterBytes: UInt64) { threshold = afterBytes; bytes = 0 }
    func beforeRead() async { if let threshold, bytes >= threshold { await block() } }
    func record(_ count: Int) { bytes += UInt64(count) }
    private func block() async { observers.forEach { $0.resume() }; observers = []; await withCheckedContinuation { waiting = $0 } }
    func arrived() async { if waiting == nil { await withCheckedContinuation { observers.append($0) } } }
    func release() { threshold = nil; waiting?.resume(); waiting = nil }
}
private actor TransferLocalService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: LocalFileService
    let pause: TransferPause
    init(fd: Int32, pause: TransferPause) throws { base = try LocalFileService(rootDirectoryDescriptor: fd); self.pause = pause }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(p, token: token) }
    func fstat(_ h: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(h, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { await pause.beforeRead(); let data = try await base.read(h, maxBytes: maxBytes, token: token); await pause.record(data.count); return data }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await base.mkdir(p, token: token) }
    func rename(_ a: RemotePath, to b: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(a, to: b, mode: mode, token: token) }
    func commit(_ a: RemotePath, to b: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await base.commit(a, to: b, request: request, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(p, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { await base.close() }
}
private actor TransferFixedConnector: FilesConnecting {
    let service: any RemoteFileService
    init(service: any RemoteFileService) { self.service = service }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken, trust: @escaping FileHostTrustHandler,
                 keyboard: @escaping FilesKeyboardHandler, isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService { service }
}
private actor TransferNeedsProbeService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .remoteComponentLstat, exclusiveCreate: true, noReplace: .needsServerConfirmation, canAttemptAtomicReplace: true)
    nonisolated let serverBinding: UUID? = UUID()
    let base: LocalFileService
    init(root: URL) throws { base = try LocalFileService(root: root) }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(p, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(h, maxBytes: maxBytes, token: token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await base.mkdir(p, token: token) }
    func rename(_ a: RemotePath, to b: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(a, to: b, mode: mode, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(p, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { await base.close() }
}
private actor TransferDisconnectingService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: LocalFileService
    let beforeFailure: TransferR1Gate?
    init(root: URL, beforeFailure: TransferR1Gate? = nil) throws { base = try LocalFileService(root: root); self.beforeFailure = beforeFailure }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(p, token: token) }
    func fstat(_ h: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(h, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(h, maxBytes: maxBytes, token: token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        _ = try await base.write(h, data: data, token: token)
        await beforeFailure?.suspend()
        base.cancel()
        throw FileServiceError(.transport, operation: "real-local-disconnected-after-write")
    }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await base.mkdir(p, token: token) }
    func rename(_ a: RemotePath, to b: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(a, to: b, mode: mode, token: token) }
    func commit(_ a: RemotePath, to b: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await base.commit(a, to: b, request: request, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(p, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { await base.close() }
}
@MainActor private final class TransferSessionBuilder: SessionBuilding {
    let host: HostConfiguration
    var holdClose = false
    var drivers: [TransferSessionDriver] = []
    init(host: HostConfiguration) { self.host = host }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) { (host, try SessionEnvironment.configuration(host: host, keyPath: nil)) }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        let (_, value) = try await configuration(hostID: hostID)
        let driver = TransferSessionDriver(id: sessionID); driver.holdClose = holdClose; drivers.append(driver)
        return ReadySession(host: host, configuration: value, driver: driver)
    }
}
@MainActor private final class TransferSessionDriver: SessionDriving {
    let terminal = NativeTerminalView()
    let id: UUID
    var token: SessionToken?
    var state: SSHSessionState = .idle
    var canReconnect: Bool { false }
    var holdClose = false
    let closeStarted = TransferR1Event()
    var onState: ((SessionToken?, SSHSessionState) -> Void)?
    var onTrust: (([SessionTrustPrompt]) -> Void)?
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)?
    init(id: UUID) { self.id = id }
    func connect(_ configuration: SSHSessionConfiguration, savedPassword: SavedPasswordAuthorization?) throws -> SessionToken {
        let value = SessionToken(sessionID: id, generation: 1); token = value; state = .connectionPending; return value
    }
    func accept(_ prompt: SessionTrustPrompt) async throws {}
    func respond(_ response: AuthenticationResponse, to prompt: SessionAuthenticationPrompt) throws {}
    func cancel() { state = .disconnected(nil) }
    func closeTab() {
        state = .closing; closeStarted.signal()
        if !holdClose { releaseClose() }
    }
    func releaseClose() { holdClose = false; terminal.releaseResources(); state = .closed }
}
@MainActor private final class TransferR1Event {
    private var signalled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func signal() { signalled = true; let values = waiters; waiters = []; values.forEach { $0.resume() } }
    func wait() async { if !signalled { await withCheckedContinuation { waiters.append($0) } } }
}
private actor TransferR1Gate {
    private var reached = false
    private var waiting: CheckedContinuation<Void, Never>?
    private var observers: [CheckedContinuation<Void, Never>] = []
    func suspend() async {
        reached = true; let values = observers; observers = []; values.forEach { $0.resume() }
        await withCheckedContinuation { waiting = $0 }
    }
    func arrived() async { if !reached { await withCheckedContinuation { observers.append($0) } } }
    func release() { waiting?.resume(); waiting = nil }
}
private actor TransferNoCredentials: CredentialAccess {
    func save(_ secret: OpenLXSSHSecurity.SecretBytes, as reference: OpenLXSSHSecurity.CredentialReference, authorization: OpenLXSSHSecurity.RememberAuthorization) -> OpenLXSSHSecurity.CredentialSaveResult { .notAuthorized }
    func read(_ reference: OpenLXSSHSecurity.CredentialReference) -> OpenLXSSHSecurity.CredentialReadResult { .manualEntryRequired(.unavailable) }
    func deleteExact(_ reference: OpenLXSSHSecurity.CredentialReference) -> OpenLXSSHSecurity.CredentialDeleteResult { .alreadyAbsent }
    func close() {}
}
private extension XCTestCase {
    func assertTrueValue(_ value: Bool, file: StaticString = #filePath, line: UInt = #line) { XCTAssertTrue(value, file: file, line: line) }
    func assertFalseValue(_ value: Bool, file: StaticString = #filePath, line: UInt = #line) { XCTAssertFalse(value, file: file, line: line) }
}
