import AppKit
import CryptoKit
import Darwin
import Foundation
import SwiftUI
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
        controller.updateTransferPreference(.ask) // These cases explicitly exercise the opt-in question path.
        return (root, local, remote, controller, pause)
    }
    private func connect(_ model: FilesController, host: HostConfiguration? = nil) async {
        model.show(host: host ?? .init(name: "real Local, not SFTP", address: "never-connected.invalid", username: "fixture"))
        await model.waitUntilCurrentWorkCompletes()
        model.connect(.init(primary: .manual(.init(utf8: "")))); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
    }
    private func terminal(_ model: FilesController, _ ids: [UUID]) async throws -> [TransferJobSnapshot] {
        let deadline = ContinuousClock.now + .seconds(5)
        while true {
            try Task.checkCancellation()
            let snapshot = await model.manager.snapshot(), jobs = snapshot.jobs.filter { ids.contains($0.id) }
            if jobs.count == ids.count && jobs.allSatisfy({ !$0.state.isActive }) { return jobs }
            guard !snapshot.isClosed else { throw FileServiceError(.closed, operation: "test-terminal-manager-closed") }
            guard .now < deadline else { throw FileServiceError(.timeout, operation: "test-terminal-deadline") }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    private func pending(_ model: FilesController, _ id: UUID, risk: Bool = false) async throws -> TransferDecisionRequest {
        let deadline = ContinuousClock.now + .seconds(5)
        while true {
            try Task.checkCancellation()
            let snapshot = await model.manager.snapshot()
            if let job = snapshot.jobs.first(where: { $0.id == id }) {
                if let question = job.pendingDecision {
                    if case .risk = question.question { if risk { return question } }
                    else if !risk { return question }
                }
                guard job.state.isActive else { throw FileServiceError(.conflict, operation: "test-expected-decision-but-job-terminal") }
            }
            guard !snapshot.isClosed else { throw FileServiceError(.closed, operation: "test-decision-manager-closed") }
            guard .now < deadline else { throw FileServiceError(.timeout, operation: "test-decision-deadline") }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    private func sha(_ url: URL) throws -> SHA256.Digest { SHA256.hash(data: try Data(contentsOf: url)) }
    func testLegacyConflictInitializerPreservesUnknownSourceKind() throws {
        let conflict = TransferConflict(source: try RemotePath("/source"), destination: try RemotePath("/target"),
            existing: FileAttributes(kind: .regular))
        XCTAssertEqual(conflict.sourceKind, .unknown)
    }
    func testRealConflictTypesGateNativeOverwriteAndPreserveOriginalNodes() async throws {
        _ = NSApplication.shared
        let (_, local, remote, model, _) = try fixture()
        addTeardownBlock { await model.closeForWindow() }
        await connect(model)
        func descendants(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(descendants) }
        func inode(_ url: URL) throws -> ino_t {
            var value = stat()
            guard lstat(url.path, &value) == 0 else { throw FileServiceError(.io, operation: "test-lstat") }
            return value.st_ino
        }
        let cases: [(String, FileKind, FileKind)] = [
            ("files", .regular, .regular), ("file-to-directory", .regular, .directory), ("directory-to-file", .directory, .regular)
        ]
        for (name, sourceKind, targetKind) in cases {
            let source = local.appendingPathComponent(name), target = remote.appendingPathComponent(name)
            if sourceKind == .directory { try FileManager.default.createDirectory(at: source, withIntermediateDirectories: false) }
            if targetKind == .directory { try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false) }
            let sourcePayload = sourceKind == .directory ? source.appendingPathComponent("child") : source
            let targetPayload = targetKind == .directory ? target.appendingPathComponent("child") : target
            let sourceBytes = Data("source original".utf8), targetBytes = Data("target original".utf8)
            try sourceBytes.write(to: sourcePayload); try targetBytes.write(to: targetPayload)
            let nodes = try [source, target, sourcePayload, targetPayload].map { ($0, try inode($0)) }
            let ids = try await model.enqueueUploads([source], context: model.transferContext(upload: true)).value
            XCTAssertFalse(ids.isEmpty); XCTAssertNil(model.transferPlanReview)
            let id = try XCTUnwrap(ids.first), request = try await pending(model, id)
            guard case .conflict(let conflict) = request.question else { return XCTFail("Expected real engine conflict metadata") }
            XCTAssertEqual(conflict.sourceKind, sourceKind); XCTAssertEqual(conflict.existing.kind, targetKind)
            let canOverwrite = sourceKind == .regular && targetKind == .regular
            let hosting = NSHostingView(rootView: FilesTransferDecisionView(model: model, request: request, dismiss: {}))
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 650, height: 500),
                styleMask: [.titled], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.contentView = hosting
            defer { window.contentView = nil; window.close() }
            hosting.frame = NSRect(x: 0, y: 0, width: 650, height: 500); hosting.layoutSubtreeIfNeeded()
            let buttons = descendants(hosting).compactMap { $0 as? NSButton }
            let overwrite = try XCTUnwrap(buttons.first { $0.identifier?.rawValue == "transfer.conflict.overwrite" })
            XCTAssertEqual(overwrite.isEnabled, canOverwrite)
            XCTAssertEqual(overwrite.title, "替换")
            for action in ["keepBoth", "batch"] {
                XCTAssertTrue(try XCTUnwrap(buttons.first { $0.identifier?.rawValue == "transfer.conflict." + action }).isEnabled)
            }
            let cancel = try XCTUnwrap(buttons.first { $0.identifier?.rawValue == "transfer.decision.cancel" })
            XCTAssertTrue(cancel.isEnabled); XCTAssertEqual(cancel.title, "取消")
            XCTAssertEqual(try XCTUnwrap(buttons.first { $0.identifier?.rawValue == "transfer.conflict.keepBoth" }).title, "都保留")
            XCTAssertFalse(buttons.contains { ["transfer.conflict.skip", "transfer.conflict.rename"].contains($0.identifier?.rawValue ?? "") })
            XCTAssertFalse(descendants(hosting).contains { $0.identifier?.rawValue == "transfer.conflict.name" })
            // A direct API answer still exercises the engine's existing protection behind the disabled UI.
            assertTrueValue(await model.answerTransfer(request, answer: .conflict(canOverwrite || (sourceKind == .directory && targetKind == .directory) ? .skip : .overwrite, applyToBatch: false)))
            let finished = try await terminal(model, ids)
            let job = try XCTUnwrap(finished.first)
            if canOverwrite || (sourceKind == .directory && targetKind == .directory) { XCTAssertEqual(job.state, .skipped) }
            else {
                XCTAssertEqual(job.state, .failed)
                XCTAssertEqual(job.error?.kind, sourceKind == .regular ? .unsupported : .conflict)
            }
            XCTAssertTrue(job.retainedTemporaryPaths.isEmpty)
            XCTAssertEqual(try Data(contentsOf: sourcePayload), sourceBytes)
            XCTAssertEqual(try Data(contentsOf: targetPayload), targetBytes)
            for (url, originalInode) in nodes { XCTAssertEqual(try inode(url), originalInode) }
            if sourceKind == .directory { XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: source.path), ["child"]) }
            if targetKind == .directory { XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: target.path), ["child"]) }
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: remote.path).sorted(), cases.map { $0.0 }.sorted())
    }
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
        XCTAssertEqual(ids.count, 3); XCTAssertNil(model.transferPlanReview)
        let jobs = try await terminal(model, ids)
        XCTAssertTrue(jobs.allSatisfy { $0.state == .succeeded })
        XCTAssertEqual(Set(jobs.map(\.request.batchID)).count, 1)
        XCTAssertEqual(try sha(local.appendingPathComponent(names[0])), try sha(remote.appendingPathComponent(names[0])))
        XCTAssertEqual(try sha(other.appendingPathComponent(names[1])), try sha(remote.appendingPathComponent(names[1])))
        XCTAssertEqual(try sha(tree.appendingPathComponent("子 目录/special\nname")), try sha(remote.appendingPathComponent("树 folder/子 目录/special\nname")))
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        let download = root.appendingPathComponent("download"); try FileManager.default.createDirectory(at: download, withIntermediateDirectories: false)
        let down = try await model.enqueueDownloads(model.entries, to: download, context: model.transferContext(upload: false)).value
        XCTAssertEqual(down.count, 3); XCTAssertNil(model.transferPlanReview)
        let downJobs = try await terminal(model, down)
        XCTAssertTrue(downJobs.allSatisfy { $0.state == .succeeded })
        XCTAssertEqual(try sha(download.appendingPathComponent(names[0])), try sha(local.appendingPathComponent(names[0])))
        XCTAssertEqual(try sha(download.appendingPathComponent("树 folder/子 目录/special\nname")), try sha(tree.appendingPathComponent("子 目录/special\nname")))
        await model.closeForWindow()
    }
    func testRealQuarterCancellationPreservesExistingTargetAndRejectsLateConflictAnswer() async throws {
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
        XCTAssertNil(model.pendingRisk)
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
        assertFalseValue(await model.answerTransfer(conflict, answer: .conflict(.overwrite, applyToBatch: false)))
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
        XCTAssertFalse(model.tasksVisible, "Admitted jobs keep running while task details stay collapsed")
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
    func testOptInBatchSkipRenameAndOverwriteExecuteWithoutSecondRiskQuestion() async throws {
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
        let skipped = try await terminal(model, batch); XCTAssertTrue(skipped.allSatisfy { $0.state == .skipped })
        assertFalseValue(await model.answerTransfer(decision, answer: .conflict(.overwrite, applyToBatch: true)))
        let renames = try await model.enqueueUploads([local.appendingPathComponent("a")], context: model.transferContext(upload: true)).value
        let rename = try await pending(model, renames[0])
        assertFalseValue(await model.answerTransfer(rename, answer: .conflict(.renameTo(try FileName("alternate")), applyToBatch: true)))
        assertTrueValue(await model.answerTransfer(rename, answer: .conflict(.renameTo(try FileName("alternate")), applyToBatch: false)))
        let renamed = try await terminal(model, renames); XCTAssertEqual(renamed.first?.state, .succeeded)
        XCTAssertEqual(try sha(local.appendingPathComponent("a")), try sha(remote.appendingPathComponent("alternate")))
        let overwrites = try await model.enqueueUploads([local.appendingPathComponent("a")], context: model.transferContext(upload: true)).value
        let overwrite = try await pending(model, overwrites[0])
        assertTrueValue(await model.answerTransfer(overwrite, answer: .conflict(.overwrite, applyToBatch: true)))
        let done = try await terminal(model, overwrites); XCTAssertEqual(done.first?.state, .succeeded)
        XCTAssertNil(model.pendingRisk); XCTAssertTrue(done.allSatisfy { $0.pendingDecision == nil })
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("a")), Data("new-a".utf8))
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("b")), Data("old-b".utf8))
        await model.closeForWindow()
    }
    func testQueuedCancellationRetryNewGenerationAndExplicitDisconnectRefusesRetry() async throws {
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
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
        await model.manager.closeIdleServices() // Unowned local roots may now close as well.
        do { _ = try await model.retryTransfer(ids[0]).value; XCTFail("Explicitly disconnected service was implicitly reconnected") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .closed) }
        await model.closeForWindow()
    }
    func testManualReconnectRetryReauthorizesOriginalTreeDownloadAndSingleFileUploadWithoutRetargeting() async throws {
        for treeDownload in [true, false] {
            let (_, local, remote, model, _) = try fixture()
            let sourceDirectory = remote.appendingPathComponent("origin"), elsewhere = remote.appendingPathComponent("elsewhere")
            try FileManager.default.createDirectory(at: sourceDirectory, withIntermediateDirectories: false)
            try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: false)
            let bytes = Data("public fresh transfer bytes".utf8), before = Data("original target".utf8)
            let selection: URL, destination: URL, renamed: URL
            if treeDownload {
                let source = sourceDirectory.appendingPathComponent("tree Ω/nested")
                let target = local.appendingPathComponent("tree Ω/nested")
                try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
                try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
                try bytes.write(to: source.appendingPathComponent("line.txt")); destination = target.appendingPathComponent("line.txt")
                try before.write(to: destination); selection = local; renamed = target.appendingPathComponent("retried.txt")
            } else {
                selection = local.appendingPathComponent("file Ω.txt"); try bytes.write(to: selection)
                destination = sourceDirectory.appendingPathComponent("file Ω.txt"); try before.write(to: destination)
                renamed = sourceDirectory.appendingPathComponent("retried.txt")
            }
            await connect(model); model.browse(try RemotePath("/origin")); await model.waitUntilCurrentWorkCompletes()
            let host = try XCTUnwrap(model.selectedHost)
            let ids: [UUID]
            if treeDownload {
                let rows = model.entries.filter { $0.name.bytes == Data("tree Ω".utf8) }
                ids = try await model.enqueueDownloads(rows, to: local, context: model.transferContext(upload: false)).value
                XCTAssertNil(model.transferPlanReview)
            } else { ids = try await model.enqueueUploads([selection], context: model.transferContext(upload: true)).value }
            let id = try XCTUnwrap(ids.first); _ = try await pending(model, id)
            await model.cancelTransfer(id)
            let originalValues = try await terminal(model, [id])
            let original = try XCTUnwrap(originalValues.first)
            model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
            await model.manager.closeIdleServices()
            model.receiveManagerSnapshot(await model.manager.snapshot(), manager: model.manager)
            XCTAssertEqual(model.state, .disconnected)
            XCTAssertThrowsError(try model.prepareTransferRetrySelection(id))
            let connector = try XCTUnwrap(model.connector as? TransferLocalConnector)
            let beforeReconnect = await connector.count; XCTAssertEqual(beforeReconnect, 1)
            await connect(model, host: host)
            model.browse(try RemotePath("/elsewhere")); await model.waitUntilCurrentWorkCompletes()
            let request = try model.prepareTransferRetrySelection(id)
            let nextIDs = try await model.acceptTransferRetrySelection(request, urls: [selection]).value
            XCTAssertNil(model.transferPlanReview)
            let nextID = try XCTUnwrap(nextIDs.first), question = try await pending(model, nextID)
            let waiting = await model.manager.snapshot()
            let fresh = try XCTUnwrap(waiting.jobs.first { $0.id == nextID })
            XCTAssertEqual(fresh.retryOf, id); XCTAssertNotEqual(fresh.generation, original.generation)
            XCTAssertNotEqual(fresh.request.batchID, original.request.batchID); XCTAssertEqual(fresh.transferredBytes, 0)
            let resolved = await model.answerTransfer(question, answer: .conflict(.renameTo(try FileName(treeDownload ? "retried tree" : "retried.txt")), applyToBatch: false))
            XCTAssertTrue(resolved)
            let doneValues = try await terminal(model, [nextID])
            let done = try XCTUnwrap(doneValues.first)
            XCTAssertEqual(done.state, .succeeded); XCTAssertEqual(done.transferredBytes, UInt64(bytes.count))
            let actualRenamed = treeDownload ? local.appendingPathComponent("retried tree/nested/line.txt") : renamed
            XCTAssertEqual(try Data(contentsOf: actualRenamed), bytes); XCTAssertEqual(try Data(contentsOf: destination), before)
            XCTAssertEqual(model.path, try RemotePath("/elsewhere"))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: elsewhere.path), [])
            let afterReconnect = await connector.count; XCTAssertEqual(afterReconnect, 2)
            let final = await model.manager.snapshot(); XCTAssertEqual(final.jobs.first { $0.id == id }, original)
            await model.closeForWindow()
        }
    }
    func testRetryFreshSelectionRejectsCancelWrongPathChangedConnectionSymlinkAndOldManager() async throws {
        let (root, local, remote, model, _) = try fixture()
        let source = local.appendingPathComponent("file"), target = remote.appendingPathComponent("file")
        try Data("public source".utf8).write(to: source); try Data("original target".utf8).write(to: target)
        await connect(model); let originalHost = try XCTUnwrap(model.selectedHost)
        let ids = try await model.enqueueUploads([source], context: model.transferContext(upload: true)).value
        let id = try XCTUnwrap(ids.first); _ = try await pending(model, id)
        await model.cancelTransfer(id); _ = try await terminal(model, [id])
        let initialSnapshot = await model.manager.snapshot()
        let cancelled = try model.prepareTransferRetrySelection(id); model.cancelTransferRetrySelection(cancelled)
        XCTAssertThrowsError(try model.acceptTransferRetrySelection(cancelled, urls: [source]))
        let wrong = try model.prepareTransferRetrySelection(id)
        XCTAssertThrowsError(try model.acceptTransferRetrySelection(wrong, urls: [target]))
        let stale = try model.prepareTransferRetrySelection(id)
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        XCTAssertThrowsError(try model.acceptTransferRetrySelection(stale, urls: [source]))
        var changed = originalHost; changed.port += 1
        model.show(host: changed); XCTAssertThrowsError(try model.prepareTransferRetrySelection(id))
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes(); await connect(model, host: changed)
        XCTAssertThrowsError(try model.prepareTransferRetrySelection(id))
        await connectAfterDisconnect(model, host: .init(name: "different host", address: "other.invalid", username: "fixture"))
        XCTAssertThrowsError(try model.prepareTransferRetrySelection(id))
        await connectAfterDisconnect(model, host: originalHost)
        let moved = root.appendingPathComponent("original-local"), outside = root.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        try Data("must remain".utf8).write(to: outside.appendingPathComponent("file"))
        try FileManager.default.moveItem(at: local, to: moved)
        try FileManager.default.createSymbolicLink(at: local, withDestinationURL: outside)
        let linkRequest = try model.prepareTransferRetrySelection(id)
        do {
            _ = try await model.acceptTransferRetrySelection(linkRequest, urls: [source]).value
            XCTFail("A newly selected symlink root must never authorize traversal")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .symbolicLink) }
        try FileManager.default.removeItem(at: local); try FileManager.default.moveItem(at: moved, to: local)
        XCTAssertEqual(try Data(contentsOf: outside.appendingPathComponent("file")), Data("must remain".utf8))
        XCTAssertEqual(try Data(contentsOf: target), Data("original target".utf8))
        let after = await model.manager.snapshot(); XCTAssertEqual(after.jobs, initialSnapshot.jobs)
        XCTAssertEqual(after.services.filter { $0.hostID == nil }.map(\.id), initialSnapshot.services.filter { $0.hostID == nil }.map(\.id))
        XCTAssertNil(model.transferPlanReview)
        let oldManager = try model.prepareTransferRetrySelection(id)
        await model.closeForWindow(); await connect(model, host: originalHost)
        XCTAssertThrowsError(try model.acceptTransferRetrySelection(oldManager, urls: [source]))
        XCTAssertThrowsError(try model.prepareTransferRetrySelection(id))
        let reopened = await model.manager.snapshot(); XCTAssertTrue(reopened.jobs.isEmpty)
        await model.closeForWindow()
    }
    private func connectAfterDisconnect(_ model: FilesController, host: HostConfiguration) async {
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes(); await connect(model, host: host)
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
    func testDownloadRootRefusesLinkedAncestorAndUploadUsesAutomaticCapabilityCheck() async throws {
        let (root, local, remote, original, _) = try fixture()
        await original.closeForWindow()
        try Data([4]).write(to: remote.appendingPathComponent("file"))
        let service = try TransferNeedsProbeService(root: remote)
        let model = FilesController(connector: TransferFixedConnector(service: service), idleTimeout: nil)
        await connect(model)
        let context = try model.transferContext(upload: true)
        XCTAssertNil(model.issue)
        let before = await model.manager.snapshot(); XCTAssertTrue(before.jobs.isEmpty)
        let source = local.appendingPathComponent("直接上传 中文.txt"), bytes = Data("first upload without engineer action".utf8)
        try bytes.write(to: source)
        let uploaded = try await model.enqueueUploads([source], context: context).value
        XCTAssertNil(model.pendingRisk)
        let done = try await terminal(model, uploaded)
        XCTAssertEqual(done.first?.state, .succeeded)
        XCTAssertNil(model.probeReview); XCTAssertNil(model.lastProbeResult)
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("直接上传 中文.txt")), bytes)
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: remote.path)), ["file", "直接上传 中文.txt"])
        let link = root.appendingPathComponent("download-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: local)
        do { _ = try await model.enqueueDownloads(model.entries, to: link, context: model.transferContext(upload: false)).value; XCTFail("Linked download root accepted") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .symbolicLink) }
        let after = await model.manager.snapshot(); XCTAssertEqual(after.jobs.count, before.jobs.count + 1)
        await model.closeForWindow()
    }
    func testNormalRenameHasNoTechnicalMailboxAndWindowCloseStillDrainsOwnedServices() async throws {
        let (_, _, remote, original, _) = try fixture(); await original.closeForWindow()
        try Data("unchanged".utf8).write(to: remote.appendingPathComponent("source"))
        let service = try TransferNeedsProbeService(root: remote)
        let model = FilesController(connector: TransferFixedConnector(service: service), idleTimeout: nil)
        await connect(model)
        let source = try XCTUnwrap(model.entries.first { $0.name.bytes == Data("source".utf8) })
        let manager = model.manager
        model.rename(source, name: try FileName("renamed"), conflict: .fail)
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertNil(model.pendingRisk); XCTAssertNil(model.riskID)
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("renamed")), Data("unchanged".utf8))
        await model.closeForWindow()
        let closed = await manager.snapshot(); XCTAssertTrue(closed.isClosed); XCTAssertFalse(closed.hasActiveWork)
        XCTAssertNil(model.pendingRisk); XCTAssertNil(model.riskID)
    }
    func testHistoryReviewNeverExpandsToNewlyFailedRetainedReport() async throws {
        let (_, local, remote, original, _) = try fixture(); await original.closeForWindow()
        try Data("new".utf8).write(to: local.appendingPathComponent("A"))
        try Data("old".utf8).write(to: remote.appendingPathComponent("A"))
        try Data(repeating: 8, count: 65536).write(to: local.appendingPathComponent("B"))
        let failure = TransferR1Gate()
        let service = try TransferDisconnectingService(root: remote, beforeFailure: failure)
        let model = FilesController(connector: TransferFixedConnector(service: service), idleTimeout: nil)
        model.updateTransferPreference(.ask) // This test intentionally waits on A before B fails.
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
    func testConnectionChangeReviewCancelPreservesActiveJobAndCapturedUploadTarget() async throws {
        let (_, local, remote, model, _) = try fixture()
        addTeardownBlock { await model.closeForWindow() }
        try Data("new".utf8).write(to: local.appendingPathComponent("file"))
        try Data("old".utf8).write(to: remote.appendingPathComponent("file"))
        try FileManager.default.createDirectory(at: remote.appendingPathComponent("other"), withIntermediateDirectories: false)
        await connect(model)
        let original = try XCTUnwrap(model.selectedHost), manager = model.manager
        let context = try model.transferContext(upload: true)
        let ids = try await model.enqueueUploads([local.appendingPathComponent("file")], context: context).value
        let id = try XCTUnwrap(ids.first)
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while model.transferSnapshot.jobs.first(where: { $0.id == id })?.state != .waitingConflict {
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "review-job-test") }
            try await Task.sleep(for: .milliseconds(5))
        }
        let before = await manager.snapshot()
        let next = HostConfiguration(name: "next fixture", address: "another-never.invalid", username: "next")
        let review = try XCTUnwrap(model.prepareConnectionChange(host: next, disconnect: false))
        XCTAssertEqual(review.jobs.map(\.id), [id]); XCTAssertEqual(model.selectedHost, original)
        model.discardConnectionChange(review); model.confirmConnectionChange(review)
        let after = await manager.snapshot()
        XCTAssertEqual(after.jobs, before.jobs); XCTAssertEqual(model.selectedHost, original); XCTAssertTrue(model.manager === manager)
        await model.cancelTransfer(id)
        _ = try await terminal(model, [id])
        model.browse(try RemotePath("/other")); await model.waitUntilCurrentWorkCompletes()
        let captured = await manager.snapshot().jobs.first { $0.id == id }
        XCTAssertEqual(captured?.request.destination.path, try RemotePath("/file"))
        XCTAssertEqual(model.transferLabels[id]?.totalBytes, 3)
        XCTAssertEqual(context.path, .root)
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

private actor FilesAppPlanGate {
    private(set) var arrivals = 0
    private var released = false
    func wait(_ token: CancellationToken, ignoreCancellation: Bool) async throws {
        arrivals += 1
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !released {
            if !ignoreCancellation { try token.check() }
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "app-plan-test-gate") }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    func release() { released = true }
}
private final class FilesAppPlanCounts: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Int] = [:]
    func add(_ key: String) { lock.lock(); defer { lock.unlock() }; values[key, default: 0] += 1 }
    func value(_ key: String) -> Int { lock.lock(); defer { lock.unlock() }; return values[key, default: 0] }
    var mutations: Int { ["writeOpen", "write", "mkdir", "commit", "rename", "remove", "symlink"].reduce(0) { $0 + value($1) } }
}
private actor FilesAppPlanService: RemoteFileService {
    nonisolated let capabilities: FileServiceCapabilities
    nonisolated let counts = FilesAppPlanCounts()
    private let base: LocalFileService
    private var listGate: FilesAppPlanGate?
    private var ignoreCancellation = false
    private var failRead = false
    private var unknownSizes = false
    init(root: URL, remoteRisk: Bool = false) throws {
        base = try LocalFileService(root: root)
        capabilities = .init(traversal: remoteRisk ? .remoteComponentLstat : .localDescriptorNoFollow,
            exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    }
    init(fd: Int32) throws {
        base = try LocalFileService(rootDirectoryDescriptor: fd)
        capabilities = base.capabilities
    }
    func configure(gate: FilesAppPlanGate? = nil, ignoreCancellation: Bool = false, failRead: Bool = false, unknownSizes: Bool = false) {
        listGate = gate; self.ignoreCancellation = ignoreCancellation; self.failRead = failRead; self.unknownSizes = unknownSizes
    }
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
    private func attrs(_ value: FileAttributes) -> FileAttributes {
        guard unknownSizes && value.kind == .regular else { return value }
        return FileAttributes(kind: value.kind, permissions: value.permissions, modifiedSeconds: value.modifiedSeconds,
            modifiedNanoseconds: value.modifiedNanoseconds, identity: value.identity)
    }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        if let gate = listGate { listGate = nil; try await gate.wait(token, ignoreCancellation: ignoreCancellation) }
        return try await base.list(path, token: token).map { DirectoryEntry(name: $0.name, attributes: attrs($0.attributes)) }
    }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes { attrs(try await base.lstat(path, token: token)) }
    func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(handle, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        switch mode { case .read: counts.add("readOpen"); case .exclusiveWrite: counts.add("writeOpen") }
        return try await base.open(path, mode: mode, token: token)
    }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        counts.add("read")
        if failRead { throw FileServiceError(.io, operation: "app-plan-injected-read") }
        return try await base.read(handle, maxBytes: maxBytes, token: token)
    }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { counts.add("write"); return try await base.write(handle, data: data, token: token) }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await base.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await base.closeHandle(handle) }
    func readSymbolicLink(_ path: RemotePath, token: CancellationToken) async throws -> Data {
        try await base.readSymbolicLink(path, token: token)
    }
    func createSymbolicLink(_ path: RemotePath, target: Data, token: CancellationToken) async throws {
        counts.add("symlink")
        try await base.createSymbolicLink(path, target: target, token: token)
    }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { counts.add("mkdir"); try await base.mkdir(path, token: token) }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws { counts.add("rename"); try await base.rename(source, to: destination, mode: mode, token: token) }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws { counts.add("commit"); try await base.commit(source, to: destination, request: request, token: token) }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { counts.add("remove"); try await base.remove(path, directory: directory, token: token) }
    nonisolated func cancel() { counts.add("cancel"); base.cancel() }
    func close() async { counts.add("close"); await base.close() }
}
private final class FilesAppPlanLocalFactory: @unchecked Sendable {
    private let lock = NSLock()
    private var services: [FilesAppPlanService] = []
    func make(_ fd: Int32) throws -> any RemoteFileService {
        let value = try FilesAppPlanService(fd: fd)
        lock.lock(); services.append(value); lock.unlock(); return value
    }
    func all() -> [FilesAppPlanService] { lock.lock(); defer { lock.unlock() }; return services }
}
@MainActor final class FilesTransferPlanAppTests: XCTestCase {
    private struct Fixture {
        let root: URL
        let local: URL
        let remote: URL
        let service: FilesAppPlanService
        let factory: FilesAppPlanLocalFactory
        let model: FilesController
    }
    private func fixture(remoteRisk: Bool = false) async throws -> Fixture {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-PlanApp-" + UUID().uuidString)
        let local = root.appendingPathComponent("local"), remote = root.appendingPathComponent("remote")
        try FileManager.default.createDirectory(at: local, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: remote, withIntermediateDirectories: true)
        let service = try FilesAppPlanService(root: remote, remoteRisk: remoteRisk), factory = FilesAppPlanLocalFactory()
        let model = FilesController(connector: TransferFixedConnector(service: service), idleTimeout: nil, localService: { try factory.make($0) })
        addTeardownBlock { await model.closeForWindow(); try FileManager.default.removeItem(at: root) }
        model.show(host: HostConfiguration(name: "local fixture, not SSH", address: "never-connected.invalid", username: "fixture"))
        await model.waitUntilCurrentWorkCompletes(); model.connect(.init(primary: .manual(.init(utf8: ""))))
        await model.waitUntilCurrentWorkCompletes(); XCTAssertEqual(model.state, .ready)
        return Fixture(root: root, local: local, remote: remote, service: service, factory: factory, model: model)
    }
    private func tree(_ f: Fixture, remote: Bool = false) throws -> URL {
        let result = (remote ? f.remote : f.local).appendingPathComponent("tree")
        try FileManager.default.createDirectory(at: result, withIntermediateDirectories: true)
        try Data("abc".utf8).write(to: result.appendingPathComponent(".hidden"))
        try Data("defgh".utf8).write(to: result.appendingPathComponent("e\u{301} line\n"))
        return result
    }
    private func wait(_ condition: @MainActor () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while await !condition() {
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "app-plan-test-wait") }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    private func terminal(_ model: FilesController, _ id: UUID) async throws -> TransferJobSnapshot {
        try await wait { await model.manager.snapshot().jobs.contains { $0.id == id && !$0.state.isActive } }
        let job = await model.manager.snapshot().jobs.first { $0.id == id }; return try XCTUnwrap(job)
    }
    private func zero(_ f: Fixture) async {
        let snapshot = await f.model.manager.snapshot(); XCTAssertTrue(snapshot.jobs.isEmpty)
        XCTAssertEqual(f.service.counts.mutations, 0); XCTAssertEqual(f.service.counts.value("readOpen"), 0)
        XCTAssertEqual(f.service.counts.value("writeOpen"), 0); XCTAssertEqual(f.service.counts.value("write"), 0); XCTAssertEqual(f.service.counts.value("read"), 0)
        for service in f.factory.all() {
            XCTAssertEqual(service.counts.mutations, 0); XCTAssertEqual(service.counts.value("readOpen"), 0)
            XCTAssertEqual(service.counts.value("writeOpen"), 0); XCTAssertEqual(service.counts.value("write"), 0); XCTAssertEqual(service.counts.value("read"), 0)
        }
    }
    func testDirectFinderDropContinuesAcrossLocalNavigationWithoutReview() async throws {
        let f = try await fixture(), url = try tree(f), pasteboard = NSPasteboard.withUniqueName()
        pasteboard.writeObjects([url as NSURL]); XCTAssertTrue(f.model.acceptFileDrop(pasteboard))
        f.model.localTransferLocationChanged(); f.model.hide()
        try await wait { await f.model.manager.snapshot().jobs.contains { !$0.state.isActive } }
        let values = await f.model.manager.snapshot().jobs
        let job = try XCTUnwrap(values.first); XCTAssertEqual(job.state, .succeeded)
        XCTAssertNil(job.pendingDecision); XCTAssertNil(f.model.transferPlanReview)
        XCTAssertEqual(try Data(contentsOf: f.remote.appendingPathComponent("tree/.hidden")), Data("abc".utf8))
    }
    func testUploadRepositoryPreservesRelativeLinkToFileTransferredLater() async throws {
        let f = try await fixture(remoteRisk: true)
        let repo = f.local.appendingPathComponent("FlagGems-vllm")
        let github = repo.appendingPathComponent(".github")
        try FileManager.default.createDirectory(at: github, withIntermediateDirectories: true)
        try Data("repo instructions".utf8).write(to: repo.appendingPathComponent("AGENTS.md"))
        let leaf = ".github/copilot-instructions.md"
        try FileManager.default.createSymbolicLink(atPath: repo.appendingPathComponent("CLAUDE.md").path, withDestinationPath: "AGENTS.md")
        try FileManager.default.createSymbolicLink(atPath: repo.appendingPathComponent(leaf).path, withDestinationPath: "../CLAUDE.md")
        let ids = try await f.model.enqueueUploads([repo], context: f.model.transferContext(upload: true)).value
        let job = try await terminal(f.model, XCTUnwrap(ids.first))
        XCTAssertEqual(job.state, .succeeded, String(describing: job.error))
        let output = f.remote.appendingPathComponent("FlagGems-vllm").appendingPathComponent(leaf)
        let claudeOutput = f.remote.appendingPathComponent("FlagGems-vllm/CLAUDE.md")
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: claudeOutput.path), "AGENTS.md")
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: output.path), "../CLAUDE.md")
        XCTAssertEqual(try Data(contentsOf: output), Data("repo instructions".utf8))
        XCTAssertEqual(f.service.counts.value("symlink"), 2)

        // Round-trip download of a remote repository containing preserved relative symlinks.
        f.model.browse(.root); await f.model.waitUntilCurrentWorkCompletes()
        let downloadDir = f.root.appendingPathComponent("downloaded-repo")
        try FileManager.default.createDirectory(at: downloadDir, withIntermediateDirectories: true)
        let downloadIDs = try await f.model.enqueueDownloads(f.model.entries, to: downloadDir, context: f.model.transferContext(upload: false)).value
        let downloadJob = try await terminal(f.model, XCTUnwrap(downloadIDs.first))
        XCTAssertEqual(downloadJob.state, .succeeded, String(describing: downloadJob.error))
        let downloadedLeaf = downloadDir.appendingPathComponent("FlagGems-vllm").appendingPathComponent(leaf)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: downloadedLeaf.path), "../CLAUDE.md")
        XCTAssertEqual(try Data(contentsOf: downloadedLeaf), Data("repo instructions".utf8))

        // Re-uploading into existing tree with overwrite preference succeeds when identical relative links exist.
        f.model.updateTransferPreference(.overwrite)
        let overwriteIDs = try await f.model.enqueueUploads([repo], context: f.model.transferContext(upload: true)).value
        let overwriteJob = try await terminal(f.model, XCTUnwrap(overwriteIDs.first))
        XCTAssertEqual(overwriteJob.state, .succeeded, String(describing: overwriteJob.error))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: output.path), "../CLAUDE.md")
    }
    func testDirectTreeWithEscapingLinkIsRejectedBeforeJobsOrWrites() async throws {
        let f = try await fixture(), url = try tree(f)
        let linkName = "link\nname"
        try FileManager.default.createSymbolicLink(atPath: url.appendingPathComponent(linkName).path, withDestinationPath: "../outside")
        do { _ = try await f.model.enqueueUploads([url], context: f.model.transferContext(upload: true)).value; XCTFail("Linked tree admitted") }
        catch let error as FileServiceError {
            XCTAssertEqual(error.kind, .symbolicLink)
            XCTAssertEqual(error.path?.bytes, Data(("/tree/" + linkName).utf8))
        }
        let issue = try XCTUnwrap(f.model.transferPreparationIssue)
        XCTAssertEqual(issue.code, "files.symbolicLink")
        XCTAssertTrue(issue.message.contains("/tree/link\\nname"))
        XCTAssertFalse(issue.message.contains("\n"))
        XCTAssertEqual(issue, f.model.issue)
        XCTAssertFalse(f.model.hasPendingOperations)
        await zero(f); XCTAssertNil(f.model.transferPlanReview)
    }
    func testPreparationIssueExplainsUnsafeLinkTargets() throws {
        let path = try RemotePath(bytes: Data("/tree/.github/link".utf8))
        for (operation, reason) in [("manifest-link-outside-tree", "文件夹以外"), ("manifest-link-unsafe-target", "安全相对路径")] {
            let issue = AppIssue.transferPreparation(FileServiceError(.symbolicLink, operation: operation, path: path))
            XCTAssertEqual(issue.code, "files.symbolicLink")
            XCTAssertTrue(issue.message.contains(reason))
            XCTAssertTrue(issue.message.contains("/tree/.github/link"))
        }
    }
    func testPureFileStillEnqueuesAutomaticallyAndRetainsActualBytesLabel() async throws {
        let f = try await fixture(), file = f.local.appendingPathComponent("file")
        try Data("actual".utf8).write(to: file)
        let ids = try await f.model.enqueueUploads([file], context: f.model.transferContext(upload: true)).value
        XCTAssertEqual(ids.count, 1); XCTAssertNil(f.model.transferPlanReview)
        let job = try await terminal(f.model, ids[0]); XCTAssertEqual(job.state, .succeeded)
        XCTAssertEqual(f.model.transferLabels[ids[0]]?.totalBytes, 6)
        XCTAssertEqual(try Data(contentsOf: f.remote.appendingPathComponent("file")), Data("actual".utf8))
    }






    func testFreezeWaitsActualPreparationDrainAndDoesNotWaitForUIAnswer() async throws {
        let f = try await fixture(); _ = try tree(f, remote: true)
        f.model.browse(.root); await f.model.waitUntilCurrentWorkCompletes()
        let target = f.root.appendingPathComponent("download"); try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
        let gate = FilesAppPlanGate(); addTeardownBlock { await gate.release() }
        await f.service.configure(gate: gate, ignoreCancellation: true)
        let prepare = try f.model.enqueueDownloads(f.model.entries, to: target, context: f.model.transferContext(upload: false))
        try await wait { await gate.arrivals == 1 }
        f.model.freezeTransferAdmission()
        var drained = false
        let snapshot = Task { @MainActor in let active = await f.model.activeTransferSnapshot(); drained = true; return active }
        try await Task.sleep(for: .milliseconds(20)); XCTAssertFalse(drained)
        XCTAssertEqual(f.factory.all().first?.counts.value("close"), 0)
        await gate.release()
        do { _ = try await prepare.value; XCTFail("Cancelled prepare published") } catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        let active = await snapshot.value; XCTAssertFalse(active); XCTAssertTrue(drained)
        XCTAssertNil(f.model.transferPlanReview); XCTAssertEqual(f.factory.all().first?.counts.value("close"), 1)
        await zero(f)
    }




}

private actor TransferLocalConnector: FilesConnecting {
    let root: URL
    private(set) var count = 0
    init(root: URL) { self.root = root }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken, trust: @escaping FileHostTrustHandler,
                 keyboard: @escaping FilesKeyboardHandler, isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        try token.check(); count += 1; return try LocalFileService(root: root)
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
    // Explicit forwarding for this local I/O test substitute, not remote login evidence.
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
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
    // Explicit forwarding for this local I/O test substitute, not remote login evidence.
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
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
    // Explicit forwarding for this local I/O test substitute, not remote login evidence.
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
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
    func connect(_ configuration: SSHSessionConfiguration, primary: SessionPrimaryAuthorization) throws -> SessionToken {
        let value = SessionToken(sessionID: id, generation: 1); token = value; state = .connectionPending; return value
    }
    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) async throws {}
    func respond(_ answer: SessionAuthenticationAnswer, to prompt: SessionAuthenticationPrompt) throws {}
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


@MainActor final class AppModelFilesFactoryTests: XCTestCase {
    func testAppModelDefersInjectedLocalFactoryUntilPrepareAndKeepsDefaultCallCompatible() async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppFactory-" + UUID().uuidString)
        let remote = root.appendingPathComponent("Remote"), source = root.appendingPathComponent("Source"), tree = source.appendingPathComponent("tree")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: remote, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: tree, withIntermediateDirectories: true)
        try Data("factory source".utf8).write(to: tree.appendingPathComponent(".hidden"))
        let location = AppDataLocation.isolated(root), repository = AppRepository(location: location)
        let service = try FilesAppPlanService(root: remote), factory = FilesAppPlanLocalFactory()
        let model = AppModel(repository: repository, security: SecurityCoordinator(repository: repository, location: location, credentials: TransferNoCredentials()),
            location: location, filesConnector: TransferFixedConnector(service: service), preferencesDefaults: nil,
            filesLocalService: { try factory.make($0) })
        addTeardownBlock {
            await model.files.closeForWindow(); try await model.security.close(); try await repository.close()
            try FileManager.default.removeItem(at: root)
        }
        XCTAssertTrue(factory.all().isEmpty)
        model.files.show(host: HostConfiguration(name: "local factory fixture", address: "never-connected.invalid", username: "fixture"))
        await model.files.waitUntilCurrentWorkCompletes()
        model.files.connect(.init(primary: .manual(.init(utf8: "")))); await model.files.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.files.state, .ready); XCTAssertTrue(factory.all().isEmpty)
        let admitted = try await model.files.enqueueUploads([tree], context: model.files.transferContext(upload: true)).value
        XCTAssertEqual(admitted.count, 1); XCTAssertEqual(factory.all().count, 1); XCTAssertNil(model.files.transferPlanReview)
        let deadline = ContinuousClock.now + .seconds(5)
        while await model.files.manager.snapshot().jobs.contains(where: { $0.state.isActive }) {
            guard .now < deadline else { return XCTFail("Factory direct transfer stalled") }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("tree/.hidden")), Data("factory source".utf8))
        let defaultRoot = root.appendingPathComponent("Default")
        try FileManager.default.createDirectory(at: defaultRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let defaultRepository = AppRepository(location: .isolated(defaultRoot))
        let defaultModel = AppModel(repository: defaultRepository, location: .isolated(defaultRoot), preferencesDefaults: nil)
        XCTAssertEqual(defaultModel.files.state, .disconnected); XCTAssertFalse(defaultModel.files.visible)
        XCTAssertTrue(defaultModel.files.transferSnapshot.jobs.isEmpty)
        await defaultModel.files.closeForWindow(); try await defaultModel.security.close(); try await defaultRepository.close()
    }
}


@MainActor final class FilesManifestConflictAppTests: XCTestCase {
    func testTwoDirectTreeUploadsRenameRootAndRememberedSkipPreservesSeed() async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-direct-tree-" + UUID().uuidString)
        let source = root.appendingPathComponent("Source/tree"), remote = root.appendingPathComponent("Remote")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: remote, withIntermediateDirectories: true)
        try Data("seed".utf8).write(to: source.appendingPathComponent("file"))
        let model = FilesController(connector: TransferLocalConnector(root: remote), idleTimeout: nil)
        model.updateTransferPreference(.autoRename) // Explicit keep-both preference, not the default collision policy.
        addTeardownBlock { await model.closeForWindow(); try FileManager.default.removeItem(at: root) }
        model.show(host: HostConfiguration(name: "direct fixture", address: "never-connected.invalid", username: "fixture"))
        await model.waitUntilCurrentWorkCompletes(); model.connect(.init(primary: .manual(.init(utf8: "")))); await model.waitUntilCurrentWorkCompletes()
        for step in 0...2 {
            if step == 1 { try Data("new".utf8).write(to: source.appendingPathComponent("file")) }
            if step == 2 { model.updateTransferPreference(.skip) }
            let ids = try await model.enqueueUploads([source], context: model.transferContext(upload: true)).value
            XCTAssertEqual(ids.count, 1); XCTAssertNil(model.transferPlanReview)
            let deadline = ContinuousClock.now + .seconds(5)
            while true {
                let values = await model.manager.snapshot().jobs
                let job = try XCTUnwrap(values.first { ids.contains($0.id) }); XCTAssertNil(job.pendingDecision)
                if !job.state.isActive { XCTAssertEqual(job.state, step == 2 ? .skipped : .succeeded); break }
                guard .now < deadline else { return XCTFail("Direct tree stalled") }
                try await Task.sleep(for: .milliseconds(5))
            }
        }
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("tree/file")), Data("seed".utf8))
        XCTAssertEqual(try Data(contentsOf: remote.appendingPathComponent("tree (1)/file")), Data("new".utf8))
    }
}
