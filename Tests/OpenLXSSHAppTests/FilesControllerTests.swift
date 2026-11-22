import AppKit
import Darwin
import Foundation
import Observation
import os
import SwiftUI
import XCTest
import OpenLXSSHCore
@testable import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTrust

@MainActor final class FilesControllerTests: XCTestCase {
    private func root() throws -> URL {
        let url = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: url) }
        return url
    }
    private func host() -> HostConfiguration { .init(name: "Local Files fixture (not SFTP)", address: "never-connected.invalid", username: "fixture") }
    private func input() -> FilesConnectInput { .init(primary: .manual(.init(utf8: UUID().uuidString))) }
    private func local() throws -> (URL, LocalFilesTestConnector, FilesController) {
        let root = try root(); let connector = LocalFilesTestConnector(root: root)
        return (root, connector, FilesController(connector: connector, idleTimeout: nil))
    }
    private func connect(_ model: FilesController) async {
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
    }
    private func refreshedMetadata(_ host: HostConfiguration) -> HostConfiguration {
        var refreshed = host
        refreshed.name = "updated display name"
        refreshed.isFavorite = true; refreshed.favoriteOrder = 4
        refreshed.lastConnectedAt = Date(timeIntervalSince1970: 123)
        return refreshed
    }
    private func waitForBoundary(_ condition: @MainActor () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "files-controller-test-boundary") }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    private func waitForScriptedPrompt(_ model: FilesController, _ connector: ScriptedFilesConnector) async throws {
        try await waitForBoundary {
            let waiting = await connector.isWaitingForRound()
            return waiting && (model.keyboardPrompt != nil || model.trustPrompt != nil)
        }
    }
    private func scripted(_ script: ScriptedFilesConnector.Script) async throws -> (FilesController, ScriptedFilesConnector, HostConfiguration) {
        let root = try root(), connector = ScriptedFilesConnector(root: root, script: script)
        let model = FilesController(connector: connector, idleTimeout: nil), original = host()
        addTeardownBlock {
            await MainActor.run { model.cancelCurrent() }
            await connector.releaseRound()
            await model.closeForWindow()
        }
        model.show(host: original); await model.waitUntilCurrentWorkCompletes()
        model.connect(input())
        return (model, connector, original)
    }
    func testDirectDefaultTreeAndBatchStartWithoutReviewAndSurvivePageHide() async throws {
        let remote = try root(), localRoot = try root()
        try Data("direct-file".utf8).write(to: localRoot.appendingPathComponent("small.txt"))
        try FileManager.default.createDirectory(at: localRoot.appendingPathComponent("目录"), withIntermediateDirectories: false)
        try Data("中文".utf8).write(to: localRoot.appendingPathComponent("目录/子项.txt"))
        let model = FilesController(connector: LocalFilesTestConnector(root: remote), idleTimeout: nil)
        addTeardownBlock { await model.closeForWindow() }
        await connect(model)
        let action = try model.enqueueUploads([localRoot.appendingPathComponent("small.txt"), localRoot.appendingPathComponent("目录")], context: model.transferContext(upload: true))
        model.hide()
        let ids = try await action.value
        XCTAssertEqual(ids.count, 2); XCTAssertNil(model.transferPlanReview); XCTAssertNil(model.transferPlanPhase)
        XCTAssertFalse(model.tasksVisible, "User action does not open a large task view")
        let deadline = ContinuousClock.now + .seconds(5)
        while true {
            let jobs = await model.manager.snapshot().jobs.filter { ids.contains($0.id) }
            XCTAssertTrue(jobs.allSatisfy { $0.pendingDecision == nil && $0.state != .waitingRisk })
            if jobs.count == 2 && jobs.allSatisfy({ !$0.state.isActive }) { XCTAssertTrue(jobs.allSatisfy { $0.state == .succeeded }); break }
            guard .now < deadline else { XCTFail("Direct batch must not wait for confirmation"); break }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("small.txt")), Data("direct-file".utf8))
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("目录/子项.txt")), Data("中文".utf8))
    }
    func testDefaultConflictKeepBothAndCancelPreserveOriginalAndRejectLateAnswers() async throws {
        let remote = try root(), localRoot = try root(), original = Data("original".utf8), incoming = Data("incoming".utf8)
        let source = localRoot.appendingPathComponent("report.zip")
        try incoming.write(to: source); try original.write(to: remote.appendingPathComponent("report.zip"))
        let model = FilesController(connector: LocalFilesTestConnector(root: remote), idleTimeout: nil)
        addTeardownBlock { await model.closeForWindow() }; await connect(model)
        XCTAssertEqual(model.conflictPreference, .ask)
        let firstIDs = try await model.enqueueUploads([source], context: model.transferContext(upload: true)).value
        let firstID = try XCTUnwrap(firstIDs.first)
        try await waitForBoundary { await model.manager.snapshot().jobs.first { $0.id == firstID }?.pendingDecision != nil }
        var snapshot = await model.manager.snapshot()
        let first = try XCTUnwrap(snapshot.jobs.first { $0.id == firstID }?.pendingDecision)
        XCTAssertEqual(snapshot.jobs.first { $0.id == firstID }?.state, .waitingConflict)
        XCTAssertNil(model.pendingRisk); XCTAssertNil(model.transferPlanReview)
        let accepted = await model.answerTransfer(first, answer: .conflict(.autoRename, applyToBatch: false)); XCTAssertTrue(accepted)
        let lateCancel = await model.cancelTransferDecision(first); XCTAssertFalse(lateCancel)
        try await waitForBoundary { await model.manager.snapshot().jobs.first { $0.id == firstID }?.state == .succeeded }
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("report.zip")), original)
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("report (1).zip")), incoming)
        let nextIDs = try await model.enqueueUploads([source], context: model.transferContext(upload: true)).value
        let nextID = try XCTUnwrap(nextIDs.first)
        try await waitForBoundary { await model.manager.snapshot().jobs.first { $0.id == nextID }?.pendingDecision != nil }
        snapshot = await model.manager.snapshot()
        let next = try XCTUnwrap(snapshot.jobs.first { $0.id == nextID }?.pendingDecision)
        let stale = await model.answerTransfer(first, answer: .conflict(.overwrite, applyToBatch: true)); XCTAssertFalse(stale)
        let cancelled = await model.cancelTransferDecision(next); XCTAssertTrue(cancelled)
        try await waitForBoundary { await model.manager.snapshot().jobs.first { $0.id == nextID }?.state == .cancelled }
        let late = await model.answerTransfer(next, answer: .conflict(.overwrite, applyToBatch: true)); XCTAssertFalse(late)
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("report.zip")), original)
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("report (1).zip")), incoming)
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: remote.path)), ["report.zip", "report (1).zip"])
        XCTAssertNil(model.pendingRisk)
    }
    func testExplicitKeepBothAndRememberedSkipOverwrite() async throws {
        let remote = try root(), localRoot = try root()
        let source = localRoot.appendingPathComponent("report.zip")
        try Data("incoming".utf8).write(to: source); try Data("original".utf8).write(to: remote.appendingPathComponent("report.zip"))
        let model = FilesController(connector: LocalFilesTestConnector(root: remote), idleTimeout: nil)
        addTeardownBlock { await model.closeForWindow() }; await connect(model)
        for preference in [FileConflictPreference.autoRename, .skip, .overwrite] {
            model.updateTransferPreference(preference)
            let ids = try await model.enqueueUploads([source], context: model.transferContext(upload: true)).value
            let deadline = ContinuousClock.now + .seconds(5)
            while true {
                let snapshots = await model.manager.snapshot().jobs
                let job = try XCTUnwrap(snapshots.first { ids.contains($0.id) })
                XCTAssertNil(job.pendingDecision)
                if !job.state.isActive { XCTAssertEqual(job.state, preference == .skip ? .skipped : .succeeded); break }
                guard .now < deadline else { XCTFail("Remembered conflict preference must not wait"); break }
                try await Task.sleep(for: .milliseconds(5))
            }
            if preference != .overwrite { XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("report.zip")), Data("original".utf8)) }
        }
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("report (1).zip")), Data("incoming".utf8))
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("report.zip")), Data("incoming".utf8))
    }
    func testDirectDownloadExplicitKeepBothPreservesExistingLocalTarget() async throws {
        let remote = try root(), destination = try root()
        try Data("download".utf8).write(to: remote.appendingPathComponent("sample.txt"))
        try Data("original".utf8).write(to: destination.appendingPathComponent("sample.txt"))
        let model = FilesController(connector: LocalFilesTestConnector(root: remote), idleTimeout: nil)
        addTeardownBlock { await model.closeForWindow() }; await connect(model)
        model.updateTransferPreference(.autoRename)
        let entries = model.entries.filter { $0.name == (try? FileName("sample.txt")) }
        let ids = try await model.enqueueDownloads(entries, to: destination, context: model.transferContext(upload: false)).value
        XCTAssertEqual(ids.count, 1); XCTAssertNil(model.transferPlanReview); XCTAssertFalse(model.tasksVisible)
        let deadline = ContinuousClock.now + .seconds(5)
        while true {
            let values = await model.manager.snapshot().jobs
            let job = try XCTUnwrap(values.first { ids.contains($0.id) }); XCTAssertNil(job.pendingDecision)
            if !job.state.isActive { XCTAssertEqual(job.state, .succeeded); break }
            guard .now < deadline else { XCTFail("Direct download must not wait"); break }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertEqual(try Data(contentsOf: destination.appendingPathComponent("sample.txt")), Data("original".utf8))
        XCTAssertEqual(try Data(contentsOf: destination.appendingPathComponent("sample (1).txt")), Data("download".utf8))
    }
    func testCancelledTreeRetryPreparationFailureIsGloballyVisibleWithoutNewJob() async throws {
        let remote = try root(), localRoot = try root(), tree = localRoot.appendingPathComponent("tree")
        try FileManager.default.createDirectory(at: tree, withIntermediateDirectories: false)
        try Data("source".utf8).write(to: tree.appendingPathComponent("file"))
        try FileManager.default.createDirectory(at: remote.appendingPathComponent("tree"), withIntermediateDirectories: false)
        let model = FilesController(connector: LocalFilesTestConnector(root: remote), idleTimeout: nil)
        addTeardownBlock { await model.closeForWindow() }; model.updateTransferPreference(.ask); await connect(model)
        let ids = try await model.enqueueUploads([tree], context: model.transferContext(upload: true)).value
        let id = try XCTUnwrap(ids.first)
        try await waitForBoundary { await model.manager.snapshot().jobs.first { $0.id == id }?.pendingDecision != nil }
        await model.cancelTransfer(id)
        try await waitForBoundary { await model.manager.snapshot().jobs.first { $0.id == id }?.state == .cancelled }
        try FileManager.default.removeItem(at: tree)
        do { _ = try await model.retryTransfer(id).value; XCTFail("Missing retry source admitted") }
        catch { XCTAssertNotNil(model.transferPreparationIssue) }
        let snapshot = await model.manager.snapshot()
        XCTAssertEqual(snapshot.jobs.count, 1); XCTAssertEqual(snapshot.jobs.first?.state, .cancelled)
        XCTAssertNil(model.transferPlanPhase); XCTAssertNil(model.transferPlanReview)
        XCTAssertEqual(model.transferPreparationIssue?.code, model.issue?.code)
    }
    func testFilesPreferenceResetReturnsAskAndKeepsOtherDraftFields() {
        var settings = AppSettings(); settings.fileConflictPolicy = .overwrite; settings.startupPage = .sftp
        var draft = SettingsDraft(settings); draft.reset(.files)
        XCTAssertEqual(draft.value.fileConflictPolicy, .ask); XCTAssertEqual(draft.value.startupPage, .sftp)
    }
    func testActualRootTrustAndKeyboardSheetsAllowCloseReviewAndCancelTheirOwner() async throws {
        _ = NSApplication.shared
        for script in [ScriptedFilesConnector.Script.trust, .keyboard] {
            let (model, connector, _) = try await scripted(script)
            try await waitForScriptedPrompt(model, connector)
            let trust = model.trustPrompt, keyboard = model.keyboardPrompt
            let hosting = NSHostingController(rootView: FilesApplicationUI(model: model, showsTasks: false))
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 700, height: 500),
                styleMask: [.titled], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.setFrameOrigin(NSPoint(x: -5000, y: -5000))
            window.contentViewController = hosting; window.makeKeyAndOrderFront(nil)
            defer { window.orderOut(nil); window.contentViewController = nil; window.close() }
            try await waitForBoundary {
                hosting.view.layoutSubtreeIfNeeded()
                return window.attachedSheet is NativeOwnedSheetWindow
            }
            let sheet = try XCTUnwrap(window.attachedSheet as? NativeOwnedSheetWindow)
            XCTAssertTrue(sheet.sheetParent === window)
            XCTAssertFalse(sheet.preventsApplicationTerminationWhenModal,
                "The production FilesApplicationUI must opt in only its current authentication sheet")
            XCTAssertTrue(sheet.attemptClose())
            await model.waitUntilCurrentWorkCompletes()
            try await waitForBoundary { window.attachedSheet == nil }
            XCTAssertNil(model.trustPrompt); XCTAssertNil(model.keyboardPrompt)
            XCTAssertEqual(model.state, .disconnected); XCTAssertFalse(model.hasPendingOperations)
            if let prompt = trust { XCTAssertFalse(model.answerTrust(prompt, once: true)) }
            if let prompt = keyboard { XCTAssertFalse(model.answerKeyboard(prompt, answers: prompt.prompts.map { _ in .init(utf8: "late") })) }
            let resolved = await connector.repliesAlreadyResolved
            XCTAssertEqual(resolved, [true], "The exact unanswered callback must be revoked before a late reply")
        }
    }
    func testStartsHiddenAndRepeatedShowDoesNotConnect() async throws {
        let (_, connector, model) = try local()
        XCTAssertFalse(model.visible)
        XCTAssertEqual(awaited: await connector.count, 0)
        model.show(host: host()); model.show(host: host()); model.hide(); model.show(host: host())
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(awaited: await connector.count, 0)
        model.connect(input()); model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(awaited: await connector.count, 1)
        model.hide(); XCTAssertEqual(model.state, .ready)
        await model.closeForWindow(); XCTAssertFalse(model.visible)
    }
    // 2026-11-04 user-session retention supersedes the former automatic idle disconnect.
    // Original strategy test is preserved in sftp91/before; background idle tests remain active.
    func testUserHeldIdleConnectionSurvivesHideAndBrowseThenExplicitDisconnectCloses() async throws {
        let root = try root(), connector = LocalFilesTestConnector(root: root)
        let folder = root.appendingPathComponent("kept")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        try Data("public original".utf8).write(to: folder.appendingPathComponent("original"))
        let model = FilesController(connector: connector, idleTimeout: .milliseconds(40), healthInterval: .milliseconds(20))
        await connect(model)
        model.browse(try RemotePath("/kept")); await model.waitUntilCurrentWorkCompletes()
        let path = model.path, entries = model.entries
        model.hide(); try await Task.sleep(for: .milliseconds(160))
        XCTAssertEqual(model.state, .ready); XCTAssertEqual(model.path, path); XCTAssertEqual(model.entries, entries)
        model.show(host: model.selectedHost); await model.waitUntilCurrentWorkCompletes()
        XCTAssertTrue(model.canTransfer); XCTAssertFalse(model.canConnect)
        model.browse(path); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready); XCTAssertEqual(model.entries, entries)
        let idleCount = await connector.count; XCTAssertEqual(idleCount, 1)
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .disconnected); XCTAssertTrue(model.canConnect); XCTAssertFalse(model.canTransfer)
        let closed = await model.manager.snapshot(); XCTAssertTrue(closed.services.isEmpty)
        XCTAssertEqual(try Data(contentsOf: folder.appendingPathComponent("original")), Data("public original".utf8))
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
        let reconnectCount = await connector.count; XCTAssertEqual(reconnectCount, 2)
        await model.closeForWindow()
    }
    func testSFTPHealthChecksDistinguishServerReplyFromTransportAndStopOnExplicitClose() async throws {
        let root = try root(), wrapped = try HealthFilesTestService(root: root)
        let model = FilesController(connector: FixedFilesConnector(service: wrapped), idleTimeout: .milliseconds(20), healthInterval: .milliseconds(20))
        await connect(model)
        await wrapped.setHealthFailure(.permissionDenied)
        try await waitForBoundary { await wrapped.healthCount >= 2 }
        XCTAssertEqual(model.state, .ready)
        await wrapped.setHealthFailure(.transport)
        try await waitForBoundary {
            let counts = await wrapped.counts, snapshot = await model.manager.snapshot()
            return model.state == .failed && counts.closes == 1 && snapshot.services.isEmpty
        }
        XCTAssertEqual(model.issue?.code, "files.transport"); XCTAssertFalse(model.canTransfer)
        let counts = await wrapped.counts
        XCTAssertEqual(counts.closes, 1)
        let released = await model.manager.snapshot(); XCTAssertTrue(released.services.isEmpty)
        await model.closeForWindow()
        let final = await wrapped.counts; XCTAssertEqual(final.closes, 1)
    }
    func testExplicitDisconnectCancelsQueuedHealthAndLateTransportReplyCannotBecomeFailure() async throws {
        let root = try root(), pause = FilesTestPause()
        let wrapped = try HealthFilesTestService(root: root, pause: pause)
        let model = FilesController(connector: FixedFilesConnector(service: wrapped), healthInterval: .milliseconds(20))
        await connect(model)
        await pause.arm(); await wrapped.setHealthFailure(.transport)
        await pause.waitForArrival()
        model.cancelCurrent()
        XCTAssertEqual(model.state, .closing)
        await pause.release(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .disconnected)
        XCTAssertNil(model.issue, "Explicit disconnect is a normal state; a late health failure must not manufacture an error")
        let counts = await wrapped.counts, snapshot = await model.manager.snapshot()
        XCTAssertEqual(counts.closes, 1); XCTAssertTrue(snapshot.services.isEmpty)
        await model.closeForWindow()
    }
    func testUncertainRemoteCreateGuidanceDoesNotClaimOwnershipOrRequireEngineerProbe() throws {
        for operation in ["probe-directory-create-outcome-uncertain", "transfer-file-create-outcome-uncertain"] {
            let issue = AppIssue.files(FileServiceError(.timeout, operation: operation, path: try RemotePath("/.openlxssh-owned-candidate"), code: 7191))
            XCTAssertEqual(issue.code, "files.timeout")
            XCTAssertTrue(issue.message.contains("可能已创建成功")); XCTAssertTrue(issue.message.contains("人工核实"))
            XCTAssertFalse(issue.message.contains("手动能力")); XCTAssertFalse(issue.message.contains("已清理"))
        }
    }
    func testBrowseNetworkFailureReleasesExactUserLeaseButPermissionKeepsReady() async throws {
        let root = try root(), remote = try HealthFilesTestService(root: root)
        let model = FilesController(connector: FixedFilesConnector(service: remote), healthInterval: nil)
        await connect(model)
        await remote.setListFailure(.permissionDenied)
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready); XCTAssertEqual(model.issue?.code, "files.permissionDenied")
        await remote.setListFailure(.transport)
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        try await waitForBoundary { await model.manager.snapshot().services.isEmpty }
        XCTAssertEqual(model.state, .failed); XCTAssertEqual(model.issue?.code, "files.transport")
        let closed = await remote.counts; XCTAssertEqual(closed.closes, 1)
        await model.closeForWindow()
    }
    func testLateBrowseFailureAfterHostChangeCannotFailNewConnection() async throws {
        let root = try root(), pause = FilesTestPause()
        let old = try HealthFilesTestService(root: root, pause: pause), fresh = try HealthFilesTestService(root: root)
        let connector = SequentialFilesTestConnector(services: [old, fresh])
        let model = FilesController(connector: connector, healthInterval: nil)
        await connect(model)
        await old.setListFailure(.transport); await pause.arm()
        model.browse(.root); await pause.waitForArrival()
        let next = host()
        model.show(host: next); model.connect(input())
        await pause.release(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready); XCTAssertNil(model.issue)
        let oldCount = await old.counts, newCount = await fresh.counts
        XCTAssertEqual(oldCount.closes, 1); XCTAssertEqual(newCount.closes, 0)
        XCTAssertEqual(awaited: await connector.count, 2)
        await model.closeForWindow()
    }
    func testTransferBackendTerminalFactRetiresRemoteButLocalSourceErrorDoesNot() async throws {
        let failures: [FileServiceError.Kind?] = [nil, .transport, .cancelled]
        for remoteFailure in failures {
            let remoteFails = remoteFailure != nil
            let root = try root(), remoteRoot = root.appendingPathComponent("remote"), sourceRoot = root.appendingPathComponent("source")
            try FileManager.default.createDirectory(at: remoteRoot, withIntermediateDirectories: false)
            try FileManager.default.createDirectory(at: sourceRoot, withIntermediateDirectories: false)
            let bytes = Data("owned transfer bytes".utf8), source = sourceRoot.appendingPathComponent("file")
            try bytes.write(to: source)
            let remote = try HealthFilesTestService(root: remoteRoot)
            let model = FilesController(connector: FixedFilesConnector(service: remote), healthInterval: nil,
                localService: { fd in try FaultingFilesUploadSource(fd: fd, failRead: !remoteFails) })
            await connect(model)
            if let remoteFailure { await remote.setWriteFailure(remoteFailure) }
            let ids = try await model.enqueueUploads([source], context: model.transferContext(upload: true)).value
            let id = try XCTUnwrap(ids.first)
            try await waitForBoundary { await model.manager.snapshot().jobs.contains { $0.id == id && !$0.state.isActive } }
            let snapshot = await model.manager.snapshot(), job = try XCTUnwrap(snapshot.jobs.first { $0.id == id })
            XCTAssertEqual(job.state, remoteFailure == .cancelled ? .cancelled : .failed)
            XCTAssertEqual(job.error?.kind, remoteFailure ?? .transport)
            if remoteFails {
                let expected: FilesState = remoteFailure == .cancelled ? .disconnected : .failed
                try await waitForBoundary {
                    let count = await remote.counts
                    return model.state == expected && count.closes == 1
                }
                XCTAssertEqual(model.issue?.code, remoteFailure == .cancelled ? "files.cancelled" : "files.transport")
                XCTAssertFalse(model.canTransfer)
            } else {
                XCTAssertEqual(model.state, .ready); XCTAssertTrue(model.canTransfer)
                let count = await remote.counts; XCTAssertEqual(count.closes, 0)
                XCTAssertNil(remote.terminalFailure)
            }
            XCTAssertEqual(try Data(contentsOf: source), bytes)
            let remaining = try FileManager.default.contentsOfDirectory(atPath: remoteRoot.path)
            if remoteFails {
                XCTAssertEqual(remaining.count, 1)
                let retained = try XCTUnwrap(job.retainedTemporaryPaths.first)
                XCTAssertEqual(retained.parent, .root)
                XCTAssertTrue(retained.name?.bytes.starts(with: Data(".openlxssh-transfer.".utf8)) == true)
                XCTAssertTrue(FileManager.default.fileExists(atPath: remoteRoot.path + FileDisplay.path(retained)))
            } else { XCTAssertTrue(remaining.isEmpty) }
            XCTAssertFalse(FileManager.default.fileExists(atPath: remoteRoot.appendingPathComponent("file").path))
            await model.closeForWindow()
        }
    }
    func testServiceSnapshotVersionAndManagerIdentityRejectStaleClosureOfNewConnection() async throws {
        let (root, connector, model) = try local()
        await connect(model)
        let manager = model.manager
        model.receiveManagerSnapshot(.init(jobs: [], isClosed: false), manager: manager)
        XCTAssertEqual(model.state, .ready); XCTAssertTrue(model.canTransfer)
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
        let released = await manager.snapshot()
        // A newest-only stream may deliver just this final snapshot, without closing.
        model.receiveManagerSnapshot(released, manager: manager)
        XCTAssertEqual(model.state, .disconnected); XCTAssertTrue(model.canConnect)
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
        model.receiveManagerSnapshot(released, manager: manager)
        XCTAssertEqual(model.state, .ready); XCTAssertTrue(model.canTransfer)
        let unrelated = try LocalFileService(root: root)
        let unrelatedID = try await manager.registerService(unrelated, hostID: "unrelated")
        await manager.closeIdleServices([unrelatedID])
        model.receiveManagerSnapshot(await manager.snapshot(), manager: manager)
        XCTAssertEqual(model.state, .ready); XCTAssertTrue(model.canTransfer)
        let beforeWindowClose = await connector.count; XCTAssertEqual(beforeWindowClose, 2)
        await model.closeForWindow()
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready); XCTAssertFalse(manager === model.manager)
        model.receiveManagerSnapshot(.init(jobs: [], isClosed: true, serviceRevision: .max), manager: manager)
        XCTAssertEqual(model.state, .ready); XCTAssertTrue(model.canTransfer)
        await model.closeForWindow()
    }
    func testLocalRawNameBrowseGoMkdirRenameConflictAndDeletePlanChange() async throws {
        let (root, _, model) = try local()
        let special = "中文 e\u{301} line\nname"
        try FileManager.default.createDirectory(at: root.appendingPathComponent(special), withIntermediateDirectories: false)
        try Data("original".utf8).write(to: root.appendingPathComponent("source"))
        try Data("existing".utf8).write(to: root.appendingPathComponent("existing"))
        await connect(model)
        let firstNames = Set(model.entries.map(\.name.bytes))
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(Set(model.entries.map(\.name.bytes)), firstNames)
        let entry = try XCTUnwrap(model.entries.first { $0.name.bytes == Data(special.utf8) })
        model.enter(entry); await model.waitUntilCurrentWorkCompletes()
        let raw = try RemotePath.root.appending(entry.name)
        XCTAssertEqual(model.path.bytes, raw.bytes)
        XCTAssertTrue(FileDisplay.path(raw).contains("\\n")) // escaped display is never re-parsed
        model.go(manualUTF8: ""); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.path.bytes, raw.bytes)
        model.mkdir(try FileName("created"), acknowledgedRemoteRisk: true); await model.waitUntilCurrentWorkCompletes()
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent(special).appendingPathComponent("created").path))
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        let source = try XCTUnwrap(model.entries.first { $0.name == (try? FileName("source")) })
        model.rename(source, name: try FileName("existing"), conflict: .fail); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.issue?.code, "files.conflict")
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("existing")), Data("existing".utf8))
        model.rename(source, name: try FileName("renamed"), conflict: .fail); await model.waitUntilCurrentWorkCompletes()
        let renamed = try XCTUnwrap(model.entries.first { $0.name == (try? FileName("renamed")) })
        model.prepareDelete(renamed, removeLinkOnly: false); await model.waitUntilCurrentWorkCompletes()
        let review = try XCTUnwrap(model.deleteReview)
        XCTAssertEqual(review.plan.items.count, 1)
        try Data("changed-after-plan".utf8).write(to: root.appendingPathComponent("renamed"))
        model.executeDelete(review, confirmed: true); await model.waitUntilCurrentWorkCompletes()
        XCTAssertFalse(try XCTUnwrap(model.lastDeleteReport).allSucceeded)
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent("renamed").path))
        await model.closeForWindow()
    }
    func testSymbolicLinkDoesNotEnterAndOnlyLinkDeleteIsExplicit() async throws {
        let (root, _, model) = try local()
        try Data("keep".utf8).write(to: root.appendingPathComponent("target"))
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("link"), withDestinationURL: root.appendingPathComponent("target"))
        await connect(model)
        let link = try XCTUnwrap(model.entries.first { $0.attributes.kind == .symbolicLink })
        model.enter(link); XCTAssertEqual(model.issue?.code, "files.symbolicLink")
        model.prepareDelete(link, removeLinkOnly: false); await model.waitUntilCurrentWorkCompletes()
        XCTAssertFalse(try XCTUnwrap(model.deleteReview).plan.canExecute)
        model.discardDeleteReview()
        model.prepareDelete(link, removeLinkOnly: true); await model.waitUntilCurrentWorkCompletes()
        let review = try XCTUnwrap(model.deleteReview)
        model.executeDelete(review, confirmed: true); await model.waitUntilCurrentWorkCompletes()
        XCTAssertTrue(try XCTUnwrap(model.lastDeleteReport).allSucceeded)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("target")), Data("keep".utf8))
        await model.closeForWindow()
    }
    func testSameIDHostEditOnlyManualReconnectUsesNewSnapshot() async throws {
        let (_, connector, model) = try local()
        await connect(model)
        var edited = try XCTUnwrap(model.selectedHost); edited.port = 2228; edited.username = "changed"
        model.show(host: edited); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(awaited: await connector.count, 1)
        XCTAssertEqual(model.state, .ready)
        XCTAssertEqual(model.issue?.code, "files.hostChanged")
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.selectedHost, edited)
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(awaited: await connector.lastHost?.port, 2228)
        XCTAssertEqual(awaited: await connector.lastHost?.username, "changed")
        await model.closeForWindow()
    }
    func testReadyMetadataRefreshPreservesConnectorServiceManagerAndJobIdentity() async throws {
        let (remote, connector, model) = try local(), source = try root()
        addTeardownBlock { await model.closeForWindow() }
        try Data("new".utf8).write(to: source.appendingPathComponent("report"))
        try Data("existing".utf8).write(to: remote.appendingPathComponent("report"))
        await connect(model)
        model.updateTransferPreference(.ask) // Hold an actual conflict to inspect metadata/owner identity.
        let original = try XCTUnwrap(model.selectedHost), manager = model.manager
        let context = try model.transferContext(upload: true), entries = model.entries
        let ids = try await model.enqueueUploads([source.appendingPathComponent("report")], context: context).value
        let id = try XCTUnwrap(ids.first)
        try await waitForBoundary { await manager.snapshot().jobs.first { $0.id == id }?.state == .waitingConflict }
        let before = await manager.snapshot(), labels = model.transferLabels[id]
        let unrelated = AppIssue(code: "files.permissionDenied", message: "fixture permission failure")
        model.issue = unrelated

        let refreshed = refreshedMetadata(original)
        model.show(host: refreshed)
        XCTAssertEqual(model.selectedHost, refreshed)
        XCTAssertEqual(model.state, .ready)
        XCTAssertEqual(model.entries, entries)
        XCTAssertEqual(model.issue, unrelated)
        XCTAssertTrue(model.manager === manager)
        let afterContext = try model.transferContext(upload: false)
        XCTAssertEqual(afterContext.serviceID, context.serviceID)
        XCTAssertEqual(afterContext.lifetime, context.lifetime)
        XCTAssertEqual(afterContext.hostID, context.hostID)
        let after = await manager.snapshot(), count = await connector.count
        XCTAssertEqual(count, 1)
        XCTAssertEqual(after.jobs, before.jobs)
        XCTAssertEqual(model.transferLabels[id]?.endpoint, labels?.endpoint)
        XCTAssertEqual(model.transferLabels[id]?.localRoots, labels?.localRoots)
    }
    func testRevertingSameIDConnectionEditClearsPendingUpdateWithoutClearingOtherIssues() async throws {
        for preserveOtherIssue in [false, true] {
            let (_, connector, model) = try local()
            addTeardownBlock { await model.closeForWindow() }
            await connect(model)
            let original = try XCTUnwrap(model.selectedHost), manager = model.manager
            let context = try model.transferContext(upload: false)
            var edited = original; edited.port += 1
            model.show(host: edited)
            XCTAssertEqual(model.issue?.code, "files.hostChanged")
            let unrelated = AppIssue(code: "files.permissionDenied", message: "fixture permission failure")
            if preserveOtherIssue { model.issue = unrelated }

            let reverted = refreshedMetadata(original)
            model.show(host: reverted)
            XCTAssertEqual(model.selectedHost, reverted)
            XCTAssertEqual(model.issue, preserveOtherIssue ? unrelated : nil)
            XCTAssertEqual(model.state, .ready)
            XCTAssertTrue(model.manager === manager)
            XCTAssertEqual(try model.transferContext(upload: false).serviceID, context.serviceID)
            model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
            XCTAssertEqual(model.selectedHost, reverted)
            model.connect(input()); await model.waitUntilCurrentWorkCompletes()
            let count = await connector.count, connectedHost = await connector.lastHost
            XCTAssertEqual(count, 2)
            XCTAssertEqual(connectedHost, reverted)
        }
    }
    func testPendingKeyboardMetadataRefreshKeepsCurrentAnswerAuthorized() async throws {
        let (model, connector, original) = try await scripted(.keyboard)
        try await waitForScriptedPrompt(model, connector)
        let first = try XCTUnwrap(model.keyboardPrompt)
        let refreshed = refreshedMetadata(original)
        model.show(host: refreshed)
        XCTAssertEqual(model.selectedHost, refreshed)
        XCTAssertEqual(model.keyboardPrompt?.id, first.id)
        XCTAssertTrue(model.isCurrent(first.request))
        XCTAssertTrue(model.answerKeyboard(first, answers: [.init(utf8: "one"), .init(utf8: "two")]))
        await connector.releaseRound()
        try await waitForScriptedPrompt(model, connector)
        let zero = try XCTUnwrap(model.keyboardPrompt)
        XCTAssertTrue(zero.prompts.isEmpty)
        XCTAssertTrue(model.answerKeyboard(zero, answers: []))
        await connector.releaseRound()
        try await waitForBoundary { model.canTransfer }
        let resolved = await connector.repliesAlreadyResolved
        XCTAssertEqual(resolved, [true, true])
        XCTAssertEqual(model.selectedHost, refreshed)
    }
    func testPendingKeyboardEndpointOrAuthenticationChangeRejectsOldAnswer() async throws {
        for authenticationChange in [false, true] {
            let (model, connector, original) = try await scripted(.keyboard)
            try await waitForScriptedPrompt(model, connector)
            let prompt = try XCTUnwrap(model.keyboardPrompt)
            var changed = original
            if authenticationChange { changed.authentication = .passwordWithMFA }
            else { changed.port += 1 }
            model.show(host: changed)
            XCTAssertFalse(model.isCurrent(prompt.request))
            XCTAssertFalse(model.answerKeyboard(prompt, answers: [.init(utf8: "one"), .init(utf8: "two")]))
            XCTAssertNil(model.keyboardPrompt)
            await connector.releaseRound()
            try await waitForBoundary { model.canConnect }
            XCTAssertEqual(model.selectedHost, changed)
            XCTAssertEqual(model.state, .disconnected)
            let resolved = await connector.repliesAlreadyResolved
            XCTAssertEqual(resolved, [true])
        }
    }
    func testPendingTrustMetadataRefreshKeepsCurrentAnswerAuthorized() async throws {
        let (model, connector, original) = try await scripted(.trust)
        try await waitForScriptedPrompt(model, connector)
        let prompt = try XCTUnwrap(model.trustPrompt)
        let refreshed = refreshedMetadata(original)
        model.show(host: refreshed)
        XCTAssertEqual(model.selectedHost, refreshed)
        XCTAssertEqual(model.trustPrompt?.id, prompt.id)
        XCTAssertTrue(model.isCurrent(prompt.request))
        XCTAssertTrue(model.answerTrust(prompt, verified: true))
        await connector.releaseRound()
        try await waitForBoundary { model.canTransfer }
        let resolved = await connector.repliesAlreadyResolved
        XCTAssertEqual(resolved, [true])
        XCTAssertEqual(model.selectedHost, refreshed)
    }
    func testPendingTrustEndpointOrAuthenticationChangeRejectsOldAnswer() async throws {
        for authenticationChange in [false, true] {
            let (model, connector, original) = try await scripted(.trust)
            try await waitForScriptedPrompt(model, connector)
            let prompt = try XCTUnwrap(model.trustPrompt)
            var changed = original
            if authenticationChange { changed.authentication = .passwordWithMFA }
            else { changed.port += 1 }
            model.show(host: changed)
            XCTAssertFalse(model.isCurrent(prompt.request))
            XCTAssertFalse(model.answerTrust(prompt, verified: true))
            XCTAssertNil(model.trustPrompt)
            await connector.releaseRound()
            try await waitForBoundary { model.canConnect }
            XCTAssertEqual(model.selectedHost, changed)
            XCTAssertEqual(model.state, .disconnected)
            let resolved = await connector.repliesAlreadyResolved
            XCTAssertEqual(resolved, [true])
        }
    }
    func testWindowCloseCancelsPreparationAndReopenCreatesFreshManager() async throws {
        let root = try root(), pause = FilesTestPause()
        let connector = LocalFilesTestConnector(root: root, pause: pause)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        let previous = model.manager
        await pause.arm(); model.connect(input()); await pause.waitForArrival()
        let started = FilesTestEvent()
        let close = Task { started.signal(); await model.closeForWindow() }
        await started.wait(); await pause.release(); await close.value
        XCTAssertFalse(model.visible); XCTAssertNil(model.selectedHost)
        XCTAssertEqual(model.state, .disconnected)
        XCTAssertFalse(previous === model.manager)
        let previousSnapshot = await previous.snapshot()
        XCTAssertTrue(previousSnapshot.isClosed)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
        await model.closeForWindow()
    }
    func testExplicitRenameOverwriteDoesNotAskTechnicalRiskAndAdvancedProbeStaysScoped() async throws {
        let root = try root()
        try Data("source-data".utf8).write(to: root.appendingPathComponent("source"))
        try Data("target-data".utf8).write(to: root.appendingPathComponent("target"))
        let service = try BoundLocalFilesService(root: root), model = FilesController(connector: FixedFilesConnector(service: service), idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes(); model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        let source = try XCTUnwrap(model.entries.first { $0.name.bytes == Data("source".utf8) })
        model.rename(source, name: try FileName("target"), conflict: .overwrite)
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertNil(model.pendingRisk); XCTAssertNil(model.riskID)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("target")), Data("source-data".utf8))
        model.prepareProbe(); await model.waitUntilCurrentWorkCompletes()
        let review = try XCTUnwrap(model.probeReview)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.path + FileDisplay.path(review.plan.temporaryDirectory)))
        model.executeProbe(review, approved: false)
        XCTAssertNil(model.lastProbeResult)
        model.executeProbe(review, approved: true); await model.waitUntilCurrentWorkCompletes()
        XCTAssertTrue(try XCTUnwrap(model.lastProbeResult).passed)
        XCTAssertTrue(try XCTUnwrap(model.lastProbeResult).retainedPaths.isEmpty)
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: root.path)), ["target"])
        await model.closeForWindow()
    }
    private func waitForObserved<T>(_ read: @escaping @MainActor () -> T?) async -> T {
        while true {
            if let value = read() { return value }
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let resumed = OSAllocatedUnfairLock(initialState: false)
                let trigger: @Sendable () -> Void = {
                    let shouldResume = resumed.withLock { state -> Bool in
                        if state { return false }
                        state = true
                        return true
                    }
                    if shouldResume { continuation.resume() }
                }
                let value = withObservationTracking {
                    read()
                } onChange: {
                    trigger()
                }
                if value != nil { trigger() }
            }
        }
    }
    private func nextRisk(_ model: FilesController) async -> UUID {
        await waitForObserved { model.riskID }
    }
    func testManagerLeaseKeepsBlockedBrowseAliveAndHostChangeAwaitsOldCleanup() async throws {
        let root = try root(), pause = FilesTestPause()
        let wrapped = try BrowsePauseService(root: root, pause: pause)
        let connector = FixedFilesConnector(service: wrapped)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        model.connect(input()); await model.waitUntilCurrentWorkCompletes()
        await pause.arm(); model.browse(.root); await pause.waitForArrival()
        XCTAssertTrue(model.busy)
        let pending = await model.manager.snapshot()
        XCTAssertFalse(pending.serviceOperations.isEmpty)
        XCTAssertTrue(pending.hasActiveWork)
        XCTAssertFalse(model.hasActiveTransfers)
        await model.manager.closeIdleServices()
        let closesWhileBusy = await wrapped.closeCount
        XCTAssertEqual(closesWhileBusy, 0)
        var next = host(); next.id = UUID()
        model.show(host: next)
        model.connect(input()) // This is queued behind the owned old cleanup, not admitted early.
        let connectBeforeRelease = await connector.count
        XCTAssertEqual(connectBeforeRelease, 1)
        await pause.release(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertFalse(model.busy)
        XCTAssertFalse(model.hasPendingOperations)
        await model.closeForWindow()
    }
    func testSyntheticCallbackCancellationAtWindowCloseDoesNotBecomeTransferDecision() async throws {
        let root = try root(), connector = KeyboardFilesTestConnector(root: root)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        let wait = Task { @MainActor in await self.nextKeyboard(model) }
        await Task.yield(); model.connect(input()); _ = await wait.value
        XCTAssertTrue(model.hasPendingOperations); XCTAssertFalse(model.hasActiveTransfers)
        await model.closeForWindow()
        XCTAssertFalse(model.hasPendingOperations); XCTAssertNil(model.keyboardPrompt); XCTAssertFalse(model.visible)
    }
    func testMultiRoundKeyboardAndZeroPromptRemainBoundAndSingleAnswer() async throws {
        let root = try root(), connector = ScriptedFilesConnector(root: root, script: .keyboard)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        let firstWait = Task { @MainActor in await self.nextKeyboard(model) }
        await Task.yield()
        model.connect(input())
        let first = await firstWait.value
        XCTAssertEqual(first.prompts.count, 2)
        XCTAssertFalse(first.prompts[0].echo); XCTAssertTrue(first.prompts[1].echo)
        XCTAssertTrue(first.instruction.contains("\\u{001B}"))
        model.hide(); XCTAssertNotNil(model.keyboardPrompt)
        let zeroWait = Task { @MainActor in await self.nextKeyboard(model, excluding: first.id) }
        await Task.yield()
        XCTAssertFalse(model.answerKeyboard(first, answers: [.init(utf8: "wrong-count")]))
        XCTAssertTrue(model.answerKeyboard(first, answers: [.init(utf8: "one"), .init(utf8: "two")]))
        XCTAssertFalse(model.answerKeyboard(first, answers: [.init(utf8: "one"), .init(utf8: "two")]))
        await connector.advanceRound()
        let zero = await zeroWait.value
        XCTAssertTrue(zero.prompts.isEmpty)
        XCTAssertTrue(model.answerKeyboard(zero, answers: []))
        await connector.advanceRound()
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
        let resolved = await connector.repliesAlreadyResolved
        XCTAssertEqual(resolved, [true, true])
        await model.closeForWindow()
    }
    func testRootPendingTrustAutomaticPresentationWaitsForVisibleOwnerAndOnceConsumesOnlyIt() async throws {
        let root = try root(), connector = ScriptedFilesConnector(root: root, script: .trust)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        let promptWait = Task { @MainActor in await self.nextTrust(model) }
        await Task.yield(); model.connect(input()); let prompt = await promptWait.value
        XCTAssertNil(model.pendingAuthenticationPresentation(modalAvailable: false))
        if case .trust(let shown) = model.pendingAuthenticationPresentation(modalAvailable: true) { XCTAssertEqual(shown.id, prompt.id) }
        else { XCTFail("Visible SFTP trust must be automatically reachable") }
        model.hide(); XCTAssertNil(model.pendingAuthenticationPresentation(modalAvailable: true))
        model.show(host: prompt.request.host)
        XCTAssertTrue(model.answerTrust(prompt, once: true)); XCTAssertFalse(model.answerTrust(prompt, once: false))
        XCTAssertNil(model.trustPrompt)
        await connector.advanceRound(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
        await model.closeForWindow()
    }
    func testSyntheticTrustRequiresExplicitFingerprintAndChangedIsRejected() async throws {
        let root = try root(), connector = ScriptedFilesConnector(root: root, script: .trust)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        let promptWait = Task { @MainActor in await self.nextTrust(model) }
        await Task.yield(); model.connect(input())
        let prompt = await promptWait.value
        XCTAssertFalse(model.answerTrust(prompt, verified: false))
        XCTAssertTrue(model.answerTrust(prompt, verified: true))
        XCTAssertFalse(model.answerTrust(prompt, verified: true))
        await connector.advanceRound()
        await model.waitUntilCurrentWorkCompletes(); XCTAssertEqual(model.state, .ready)
        await model.closeForWindow()
        let changedConnector = ScriptedFilesConnector(root: root, script: .changed)
        let changed = FilesController(connector: changedConnector, idleTimeout: nil)
        changed.show(host: host()); await changed.waitUntilCurrentWorkCompletes()
        changed.connect(input()); await changed.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(changed.state, .failed)
        XCTAssertEqual(changed.issue?.code, "files.untrusted")
        if let prompt = changed.trustPrompt { XCTAssertFalse(changed.answerTrust(prompt, verified: true)) }
        await changed.closeForWindow()
    }
    private func changedFact(_ identity: HostIdentity) async throws -> ChangedHostKey {
        let directory = try root(), store = try HostTrustStore(directory: AbsolutePath(directory.appendingPathComponent("changed-consumer-trust").path))
        let first = try filesChangedKey(31), next = try filesChangedKey(32)
        guard case .pending(let pending) = try await store.evaluate(host: identity, key: first) else {
            throw FileServiceError(.untrusted, operation: "test-changed-pending")
        }
        try await store.confirm(pending, displayedFingerprint: pending.fingerprint)
        guard case .rejected(let changed) = try await store.evaluate(host: identity, key: next) else {
            throw FileServiceError(.untrusted, operation: "test-changed-rejected")
        }
        return changed
    }
    private func changedConsumer() async throws -> (FilesController, ChangedFilesConnector) {
        let connector = ChangedFilesConnector(root: try root()), model = FilesController(connector: connector, idleTimeout: nil)
        addTeardownBlock { await connector.cancelAll(); await model.closeForWindow() }
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes(); model.connect(input())
        _ = try await connector.request(0)
        return (model, connector)
    }
    func testTypedChangedErrorOnlyAfterRuntimeCancellationPreservesFailedPromptAndRejectsAcceptance() async throws {
        let (model, connector) = try await changedConsumer(), request = try await connector.request(0)
        let changed = try await changedFact(HostIdentity(address: HostAddress(request.host.address), port: SSHPort(request.host.port)))
        await connector.fail(0, error: FileServiceError(.untrusted, operation: "host-key", changedHostKey: changed), cancelRuntime: true)
        await model.waitUntilCurrentWorkCompletes()
        let prompt = try XCTUnwrap(model.trustPrompt)
        guard case .changed(let fact) = prompt.event else { return XCTFail("typed changed fact") }
        XCTAssertEqual(fact, changed); XCTAssertEqual(prompt.request, request)
        XCTAssertEqual(model.state, .failed); XCTAssertEqual(model.issue?.code, "files.untrusted")
        XCTAssertFalse(model.answerTrust(prompt, once: true)); XCTAssertFalse(model.answerTrust(prompt, once: false))
        XCTAssertNotNil(model.pendingAuthenticationPresentation(modalAvailable: true))
        let count = await connector.count; XCTAssertEqual(count, 1)
    }
    func testTypedChangedCallbackAndErrorBothOrdersKeepOnePromptAndDismissalCannotReviveIt() async throws {
        for callbackFirst in [false, true] {
            let (model, connector) = try await changedConsumer(), request = try await connector.request(0)
            let changed = try await changedFact(HostIdentity(address: HostAddress(request.host.address), port: SSHPort(request.host.port)))
            var originalID: UUID?
            if callbackFirst {
                _ = await connector.emit(0, changed: changed)
                try await waitForBoundary { model.trustPrompt != nil }
                originalID = model.trustPrompt?.id
            }
            await connector.fail(0, error: FileServiceError(.untrusted, operation: "host-key", changedHostKey: changed), cancelRuntime: true)
            await model.waitUntilCurrentWorkCompletes()
            let prompt = try XCTUnwrap(model.trustPrompt)
            if let originalID { XCTAssertEqual(prompt.id, originalID) }
            let reply = await connector.emit(0, changed: changed)
            XCTAssertEqual(model.trustPrompt?.id, prompt.id)
            XCTAssertFalse(reply.resolve(.confirm(displayedFingerprint: changed.presentedFingerprint)))
            model.cancelTrust(prompt); await model.waitUntilCurrentWorkCompletes()
            _ = await connector.emit(0, changed: changed)
            XCTAssertNil(model.trustPrompt); XCTAssertEqual(model.state, .disconnected)
        }
    }
    func testTypedChangedWrongEndpointAndGenericFailuresNeverManufactureChangedPrompt() async throws {
        for typedWrongEndpoint in [false, true] {
            let (model, connector) = try await changedConsumer(), request = try await connector.request(0)
            let wrong = try await changedFact(HostIdentity(address: HostAddress(request.host.address), port: SSHPort(request.host.port + 1)))
            if typedWrongEndpoint { _ = await connector.emit(0, changed: wrong); XCTAssertNil(model.trustPrompt) }
            let error = typedWrongEndpoint
                ? FileServiceError(.untrusted, operation: "host-key", changedHostKey: wrong)
                : FileServiceError(.transport, operation: "connect")
            await connector.fail(0, error: error)
            await model.waitUntilCurrentWorkCompletes()
            XCTAssertEqual(model.state, .failed); XCTAssertNil(model.trustPrompt)
            XCTAssertEqual(model.issue?.code, typedWrongEndpoint ? "files.untrusted" : "files.transport")
        }
    }
    func testTypedChangedOldRequestNewGenerationAndClosedWindowRejectLateFacts() async throws {
        let (model, connector) = try await changedConsumer(), old = try await connector.request(0)
        let changed = try await changedFact(HostIdentity(address: HostAddress(old.host.address), port: SSHPort(old.host.port)))
        await connector.holdFailure(0, error: FileServiceError(.untrusted, operation: "host-key", changedHostKey: changed))
        try await connector.failureHeld(0)
        model.cancelCurrent(); await connector.releaseFailure(0); await model.waitUntilCurrentWorkCompletes()
        XCTAssertNil(model.trustPrompt); XCTAssertEqual(model.state, .disconnected)
        model.connect(input()); let current = try await connector.request(1)
        XCTAssertNotEqual(current.generation, old.generation)
        _ = await connector.emit(0, changed: changed); XCTAssertNil(model.trustPrompt)
        try await connector.succeed(1); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
        let previousManager = model.manager
        await model.closeForWindow()
        _ = await connector.emit(0, changed: changed); _ = await connector.emit(1, changed: changed)
        XCTAssertNil(model.trustPrompt); XCTAssertFalse(model.visible); XCTAssertEqual(model.state, .disconnected)
        XCTAssertFalse(model.manager === previousManager)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        _ = await connector.emit(1, changed: changed); XCTAssertNil(model.trustPrompt)
    }
    private func nextKeyboard(_ model: FilesController, excluding: UUID? = nil) async -> FilesKeyboardPrompt {
        await waitForObserved {
            guard let value = model.keyboardPrompt, value.id != excluding else { return nil }
            return value
        }
    }
    private func nextTrust(_ model: FilesController) async -> FilesTrustPrompt {
        await waitForObserved { model.trustPrompt }
    }
    func testCallbackCancelAndHostSwitchRejectOldKeyboardAnswers() async throws {
        let root = try root(), connector = KeyboardFilesTestConnector(root: root)
        let model = FilesController(connector: connector, idleTimeout: nil)
        model.show(host: host()); await model.waitUntilCurrentWorkCompletes()
        model.connect(input())
        _ = await waitForObserved { model.keyboardPrompt }
        let old = try XCTUnwrap(model.keyboardPrompt)
        model.hide(); XCTAssertNotNil(model.keyboardPrompt)
        var next = host(); next.id = UUID(); next.username = "next"
        model.show(host: next)
        XCTAssertFalse(model.answerKeyboard(old, answers: [.init(utf8: UUID().uuidString)]))
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertNil(model.keyboardPrompt)
        await model.closeForWindow()
    }

    func testHighFrequencyTransferSnapshotsAccumulateSpeedAcrossSub50msIntervals() async throws {
        let (_, _, model) = try local()
        addTeardownBlock { await model.closeForWindow() }

        let jobID = TransferJobID()
        let generation = UUID()
        let request = TransferRequest(
            hostID: UUID().uuidString,
            batchID: TransferBatchID(),
            source: .init(serviceID: UUID(), path: try RemotePath("/source.bin")),
            destination: .init(serviceID: UUID(), path: try RemotePath("/dest.bin")),
            kind: .file,
            conflictPolicy: .ask,
            preserveRelativeLinks: false
        )

        func push(bytes: UInt64, state: TransferJobState = .running) {
            let job = TransferJobSnapshot(
                id: jobID,
                generation: generation,
                retryOf: nil,
                request: request,
                state: state,
                transferredBytes: bytes,
                cancellationRequested: false,
                pendingDecision: nil,
                error: nil,
                items: []
            )
            model.applySnapshot(TransferManagerSnapshot(jobs: [job], isClosed: false))
        }

        // Send rapid snapshots every 15ms (< 50ms each) over ~120ms.
        let chunkBytes: UInt64 = 262_144
        push(bytes: 0)
        XCTAssertNil(model.currentTransferSpeed(jobID))

        var accumulated: UInt64 = 0
        for _ in 0..<8 {
            try await Task.sleep(for: .milliseconds(15))
            accumulated += chunkBytes
            push(bytes: accumulated)
        }

        let speed = try XCTUnwrap(model.currentTransferSpeed(jobID), "Rapid <50ms snapshots must still produce a valid transfer speed")
        // Expected rate is ~256 KiB / 15ms (~17 MB/s); verify it is in a sensible positive range.
        XCTAssertGreaterThan(speed, 1_000_000)
        XCTAssertLessThan(speed, 200_000_000)

        // Completion clears speed and sample state cleanly.
        push(bytes: accumulated, state: .succeeded)
        XCTAssertNil(model.currentTransferSpeed(jobID))
        XCTAssertNil(model.transferSpeeds[jobID])
        XCTAssertNil(model.transferSamples[jobID])
    }
}

/// Virtual failure delivery into the real FilesController consumer; never contacts SSH/SFTP,
/// invokes saved credentials, or treats these logical outcomes as interoperability evidence.
private actor ChangedFilesConnector: FilesConnecting {
    private struct Attempt {
        let request: FilesRequest
        let token: CancellationToken
        let trust: FileHostTrustHandler
    }
    let root: URL
    private var attempts: [Attempt] = []
    private var results: [Int: Result<any RemoteFileService, any Error>] = [:]
    private var held: [Int: any Error] = [:]
    private var entered = Set<Int>(), released = Set<Int>()
    var count: Int { attempts.count }
    init(root: URL) { self.root = root }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        let index = attempts.count; attempts.append(Attempt(request: request, token: token, trust: trust))
        let deadline = ContinuousClock.now + .seconds(3)
        while results[index] == nil {
            if let failure = held[index] {
                entered.insert(index)
                while !released.contains(index) {
                    guard .now < deadline else { throw FileServiceError(.timeout, operation: "test-held-changed") }
                    await withCheckedContinuation { continuation in
                        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(10)) { continuation.resume() }
                    }
                }
                held[index] = nil; throw failure
            }
            try token.check()
            guard .now < deadline else { throw FileServiceError(.timeout, operation: "test-changed-result") }
            try await Task.sleep(for: .milliseconds(10))
        }
        return try results.removeValue(forKey: index)!.get()
    }
    func request(_ index: Int) async throws -> FilesRequest {
        let deadline = ContinuousClock.now + .seconds(3)
        while !attempts.indices.contains(index) {
            guard .now < deadline else { throw FileServiceError(.timeout, operation: "test-changed-request") }
            try await Task.sleep(for: .milliseconds(10))
        }
        return attempts[index].request
    }
    func emit(_ index: Int, changed: ChangedHostKey) async -> ChallengeReply<FileHostTrustAnswer> {
        let reply = ChallengeReply<FileHostTrustAnswer>()
        attempts[index].trust(.changed(changed), reply)
        // receiveTrust is queued on MainActor. An event queued on the same main dispatch
        // executor afterwards is a delivery fence, without importing an internal mailbox wait.
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
        XCTAssertFalse(reply.resolve(.confirm(displayedFingerprint: changed.presentedFingerprint)),
            "Changed informational reply must already be cancelled by its consumer")
        return reply
    }
    func fail(_ index: Int, error: any Error, cancelRuntime: Bool = false) {
        results[index] = .failure(error)
        if cancelRuntime { attempts[index].token.cancel() }
    }
    func succeed(_ index: Int) throws { results[index] = .success(try LocalFileService(root: root)) }
    func holdFailure(_ index: Int, error: any Error) { held[index] = error }
    func failureHeld(_ index: Int) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        while !entered.contains(index) {
            guard .now < deadline else { throw FileServiceError(.timeout, operation: "test-changed-held") }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    func releaseFailure(_ index: Int) { released.insert(index) }
    func cancelAll() {
        for attempt in attempts { attempt.token.cancel() }
        released.formUnion(held.keys)
    }
}
private func filesChangedKey(_ byte: UInt8) throws -> HostPublicKey {
    var blob = Data()
    for part in [Data("ssh-ed25519".utf8), Data(repeating: byte, count: 32)] {
        var length = UInt32(part.count).bigEndian
        withUnsafeBytes(of: &length) { blob.append(contentsOf: $0) }; blob.append(part)
    }
    return try HostPublicKey(algorithm: "ssh-ed25519", base64: blob.base64EncodedString())
}

private actor BoundLocalFilesService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    nonisolated let serverBinding: UUID? = UUID()
    let base: LocalFileService
    init(root: URL) throws { base = try LocalFileService(root: root) }
    // Explicit forwarding for this local I/O test substitute, not remote login evidence.
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(path, token: token) }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(path, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(path, mode: mode, token: token) }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(handle, maxBytes: maxBytes, token: token) }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(handle, data: data, token: token) }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await base.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await base.closeHandle(handle) }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { try await base.mkdir(path, token: token) }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(source, to: destination, mode: mode, token: token) }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await base.commit(source, to: destination, request: request, token: token) }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(path, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { await base.close() }
}

private actor FixedFilesConnector: FilesConnecting {
    let service: any RemoteFileService
    private(set) var count = 0
    init(service: any RemoteFileService) { self.service = service }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService { count += 1; try token.check(); return service }
}
private actor BrowsePauseService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: LocalFileService
    let pause: FilesTestPause
    private(set) var closeCount = 0
    init(root: URL, pause: FilesTestPause) throws { base = try LocalFileService(root: root); self.pause = pause }
    // Explicit forwarding for this local I/O test substitute, not remote login evidence.
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { await pause.suspendIfArmed(); return try await base.list(path, token: token) }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(path, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(path, mode: mode, token: token) }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(handle, maxBytes: maxBytes, token: token) }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(handle, data: data, token: token) }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await base.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await base.closeHandle(handle) }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { try await base.mkdir(path, token: token) }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(source, to: destination, mode: mode, token: token) }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(path, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { closeCount += 1; await base.close() }
}

private actor LocalFilesTestConnector: FilesConnecting {
    let root: URL
    let pause: FilesTestPause?
    private(set) var count = 0
    private(set) var lastHost: HostConfiguration?
    init(root: URL, pause: FilesTestPause? = nil) { self.root = root; self.pause = pause }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        count += 1; lastHost = request.host
        await pause?.suspendIfArmed(); try token.check()
        guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "local-fixture-stale") }
        return try LocalFileService(root: root)
    }
}
private actor FilesTestPause {
    private var armed = false, arrived = false
    private var waiter: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    func arm() { armed = true; arrived = false }
    func suspendIfArmed() async { guard armed else { return }; arrived = true; observer?.resume(); observer = nil; await withCheckedContinuation { waiter = $0 } }
    func suspendIfArmed(token: CancellationToken) async throws {
        guard armed else { return }
        arrived = true; observer?.resume(); observer = nil
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while armed {
            try token.check()
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "scripted-files-test-round") }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func waitForArrival() async { if !arrived { await withCheckedContinuation { observer = $0 } } }
    func release() { armed = false; waiter?.resume(); waiter = nil }
    var isWaiting: Bool { arrived && armed }
}
@MainActor private final class FilesTestEvent {
    private var arrived = false
    private var waiter: CheckedContinuation<Void, Never>?
    func signal() { arrived = true; waiter?.resume(); waiter = nil }
    func wait() async { if !arrived { await withCheckedContinuation { waiter = $0 } } }
}
private actor FilesCallbackEvent {
    private var arrived = false
    private var waiter: CheckedContinuation<Void, Never>?
    func signal() { arrived = true; waiter?.resume(); waiter = nil }
    func wait() async { if !arrived { await withCheckedContinuation { waiter = $0 } } }
}
private actor KeyboardFilesTestConnector: FilesConnecting {
    let root: URL
    let sent = FilesCallbackEvent()
    init(root: URL) { self.root = root }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        let reply = ChallengeReply<[Data]>()
        keyboard(FilesKeyboardChallenge(name: Data("fixture".utf8), instruction: Data("manual only".utf8), prompts: [(Data("unknown".utf8), false)]), reply)
        await sent.signal()
        while !token.isCancelled { try await Task.sleep(for: .milliseconds(5)) }
        throw FileServiceError(.cancelled, operation: "keyboard-fixture")
    }
}
private actor ScriptedFilesConnector: FilesConnecting {
    enum Script { case keyboard, trust, changed }
    let root: URL
    let script: Script
    private(set) var repliesAlreadyResolved: [Bool] = []
    init(root: URL, script: Script) { self.root = root; self.script = script }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        switch script {
        case .keyboard:
            for prompts: [(Data, Bool)] in [[(Data("unknown".utf8), false), (Data("visible".utf8), true)], []] {
                await round.arm()
                let reply = ChallengeReply<[Data]>()
                keyboard(FilesKeyboardChallenge(name: Data("name".utf8), instruction: Data("instruction\u{1B}".utf8), prompts: prompts.map { ($0.0, $0.1) }), reply)
                defer { repliesAlreadyResolved.append(!reply.resolve([])) }
                try await round.suspendIfArmed(token: token)
                try token.check()
            }
        case .trust, .changed:
            let store = try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("trust-fixture").path))
            let identity = HostIdentity(address: try HostAddress(request.host.address), port: try SSHPort(request.host.port))
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg") }.value
            guard case .pending(let decision) = try await store.evaluate(host: identity, key: key) else { throw FileServiceError(.untrusted, operation: "fixture") }
            if script == .trust {
                await round.arm()
                let reply = ChallengeReply<FileHostTrustAnswer>()
                trust(.pending(decision), reply)
                defer { repliesAlreadyResolved.append(!reply.resolve(.reject)) }
                try await round.suspendIfArmed(token: token)
                try token.check()
            } else {
                _ = try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
                let next = try await Task.detached { try HostPublicKey(openSSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C") }.value
                if case .rejected(let change) = try await store.evaluate(host: identity, key: next) { trust(.changed(change), ChallengeReply<FileHostTrustAnswer>()) }
                throw FileServiceError(.untrusted, operation: "changed-fixture")
            }
        }
        guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "fixture-stale") }
        return try LocalFileService(root: root)
    }
    private let round = FilesTestPause()
    func advanceRound() async { await round.waitForArrival(); await round.release() }
    func releaseRound() async { await round.release() }
    func isWaitingForRound() async -> Bool { await round.isWaiting }
}

private func XCTAssertEqual<T: Equatable>(awaited value: T, _ expected: T, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertEqual(value, expected, file: file, line: line)
}

private actor HealthFilesTestService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: LocalFileService
    private var failure: FileServiceError.Kind?
    private var listFailure: FileServiceError.Kind?
    private var writeFailure: FileServiceError.Kind?
    nonisolated private let terminalState = FilesFailureFact()
    nonisolated var terminalFailure: FileServiceError? { terminalState.snapshot() }
    private var checkingHealth = false
    private(set) var healthCount = 0
    private var closes = 0
    private let pause: FilesTestPause?
    var counts: (health: Int, closes: Int) { (healthCount, closes) }
    init(root: URL, pause: FilesTestPause? = nil) throws { base = try LocalFileService(root: root); self.pause = pause }
    func setHealthFailure(_ kind: FileServiceError.Kind) { checkingHealth = true; failure = kind; healthCount = 0 }
    func setListFailure(_ kind: FileServiceError.Kind) { listFailure = kind }
    func setWriteFailure(_ kind: FileServiceError.Kind) { writeFailure = kind }
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        await pause?.suspendIfArmed()
        if let listFailure { throw FileServiceError(listFailure, operation: "fixture-list", path: p) }
        return try await base.list(p, token: token)
    }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes {
        if checkingHealth && p == .root {
            healthCount += 1
            await pause?.suspendIfArmed()
            if let failure { throw FileServiceError(failure, operation: "fixture-sftp-health", path: p) }
        }
        return try await base.lstat(p, token: token)
    }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(h, maxBytes: maxBytes, token: token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        if let writeFailure {
            let error = FileServiceError(writeFailure, operation: "fixture-remote-write")
            await base.close() // Publish a terminal fact only after this fixture's native FD really closes.
            terminalState.record(error); throw error
        }
        return try await base.write(h, data: data, token: token)
    }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await base.mkdir(p, token: token) }
    func rename(_ a: RemotePath, to b: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(a, to: b, mode: mode, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(p, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { closes += 1; await base.close() }
}

private final class FilesFailureFact: @unchecked Sendable {
    private let lock = NSLock()
    private var value: FileServiceError?
    func record(_ error: FileServiceError) { lock.lock(); value = error; lock.unlock() }
    func snapshot() -> FileServiceError? { lock.lock(); defer { lock.unlock() }; return value }
}
private actor SequentialFilesTestConnector: FilesConnecting {
    let services: [any RemoteFileService]
    private(set) var count = 0
    init(services: [any RemoteFileService]) { self.services = services }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        try token.check(); guard count < services.count else { throw FileServiceError(.closed, operation: "test-no-next-service") }
        let next = services[count]; count += 1; return next
    }
}
private actor FaultingFilesUploadSource: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: LocalFileService
    let failRead: Bool
    init(fd: Int32, failRead: Bool) throws { base = try LocalFileService(rootDirectoryDescriptor: fd); self.failRead = failRead }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(p, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        if failRead { throw FileServiceError(.transport, operation: "fixture-local-source-read") }
        return try await base.read(h, maxBytes: maxBytes, token: token)
    }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await base.mkdir(p, token: token) }
    func rename(_ a: RemotePath, to b: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(a, to: b, mode: mode, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(p, directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { await base.close() }
}
