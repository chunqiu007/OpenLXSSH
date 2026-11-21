import AppKit
import Darwin
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHFiles

@MainActor final class DualPaneFilesTests: XCTestCase {
    private func fixture() throws -> URL {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-DualPaneTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: root) }
        return root
    }
    private func model(_ root: URL) -> LocalBrowserModel {
        let model = LocalBrowserModel(root: root)
        addTeardownBlock { await model.close() }
        return model
    }
    func testLocalBrowserIsLazyAndListsOnlyInjectedRootMetadata() async throws {
        let root = try fixture(), reads = DualPaneReadCounter()
        let name = "中文 e\u{301} space\nname"
        try Data("synthetic".utf8).write(to: root.appendingPathComponent(name))
        try Data().write(to: root.appendingPathComponent(".hidden"))
        let model = LocalBrowserModel(root: root, beforeList: { await reads.read() })
        addTeardownBlock { await model.close() }
        XCTAssertNil(model.path); XCTAssertTrue(model.entries.isEmpty)
        let before = await reads.count; XCTAssertEqual(before, 0)
        model.activate(); await model.waitUntilIdle()
        let path = try FilesLocalPaths.rawPath(FilesLocalPaths.components(root))
        XCTAssertEqual(model.path, path)
        XCTAssertEqual(Set(model.entries.map(\.name.bytes)), [Data(name.utf8), Data(".hidden".utf8)])
        XCTAssertEqual(model.visibleEntries.count, 1)
        model.showsHidden = true; XCTAssertEqual(model.visibleEntries.count, 2)
        model.filter = "absent"; XCTAssertTrue(model.visibleEntries.isEmpty); XCTAssertEqual(model.entries.count, 2)
        model.filter = "中文"; XCTAssertEqual(model.visibleEntries.first?.name.bytes, Data(name.utf8))
        model.activate(); await model.waitUntilIdle()
        let after = await reads.count; XCTAssertEqual(after, 1)
        XCTAssertEqual(try FilesLocalPaths.rawPath(FilesLocalPaths.components(FilesLocalPaths.url(path))), path)
    }
    func testLocalFirstReadFailureRefreshRetriesAndLoadingPreventsDuplicateReads() async throws {
        let root = try fixture(), fault = ReliabilityLocalReadFault()
        try Data("synthetic".utf8).write(to: root.appendingPathComponent("file"))
        let model = LocalBrowserModel(root: root, beforeList: { try await fault.read() })
        addTeardownBlock { await model.close() }
        model.activate(); model.activate(); model.refresh(); await model.waitUntilIdle()
        XCTAssertNil(model.path); XCTAssertNotNil(model.issue); XCTAssertTrue(model.history.paths.isEmpty)
        let firstCount = await fault.count; XCTAssertEqual(firstCount, 1)
        model.refresh(); model.refresh(); model.activate(); await model.waitUntilIdle()
        XCTAssertNotNil(model.path); XCTAssertNil(model.issue); XCTAssertEqual(model.entries.count, 1)
        let finalCount = await fault.count; XCTAssertEqual(finalCount, 2)
        XCTAssertEqual(model.history.paths, [try XCTUnwrap(model.path)])
    }
    func testLocalCancelledOrHiddenInitialReadCannotPublishAndRefreshRecovers() async throws {
        for closing in [false, true] {
            let root = try fixture(), gate = ReliabilityGate()
            try Data("synthetic".utf8).write(to: root.appendingPathComponent("file"))
            let model = LocalBrowserModel(root: root, beforeList: { await gate.suspend() })
            model.activate(); await gate.waitForArrival()
            let close = closing ? Task { await model.close() } : nil
            if !closing { model.deactivate() }
            await Task.yield(); await gate.release(); await close?.value; await model.waitUntilIdle()
            XCTAssertNil(model.path); XCTAssertTrue(model.entries.isEmpty); XCTAssertTrue(model.history.paths.isEmpty)
            XCTAssertNil(model.issue)
            await model.close()
        }
        let root = try fixture(), gate = ReliabilityOneShotLocalGate()
        let model = LocalBrowserModel(root: root, beforeList: { await gate.read() })
        addTeardownBlock { await model.close() }
        model.activate(); await gate.gate.waitForArrival(); model.cancel(); await gate.gate.release(); await model.waitUntilIdle()
        model.refresh(); await model.waitUntilIdle(); XCTAssertNotNil(model.path)
    }
    func testInitialInputOwnerClearsOnRouteIdentityAndEpochWithoutCancellingConnection() async throws {
        let root = try fixture(), gate = ReliabilityGate()
        let service = try DualPaneInitialDirectoryService(root: root) { _ in await gate.suspend(); return .root }
        let model = await initialDirectoryController(root, services: [service]), input = FilesInitialInputOwner()
        let host = try XCTUnwrap(model.selectedHost)
        var visible = true
        func context() -> FilesInitialInputOwner.Context {
            .init(visible: visible, host: model.selectedHost, keys: [], epoch: model.initialInputEpoch)
        }
        input.update(context()); input.secret = UUID().uuidString; input.useTemporaryCredential = true
        visible = false; model.hide(); input.update(context())
        XCTAssertTrue(input.secret.isEmpty); XCTAssertFalse(input.useTemporaryCredential)
        XCTAssertNil(input.take(for: context())); XCTAssertEqual(model.state, .disconnected)
        visible = true; model.show(host: host); input.update(context()); input.secret = UUID().uuidString
        let supplied = try XCTUnwrap(input.take(for: context())); XCTAssertTrue(input.secret.isEmpty)
        model.connect(supplied); await gate.waitForArrival()
        input.update(context()); input.secret = UUID().uuidString; input.useTemporaryCredential = true
        let epoch = model.initialInputEpoch
        visible = false; model.hide(); input.update(context())
        XCTAssertTrue(input.secret.isEmpty); XCTAssertFalse(input.useTemporaryCredential)
        XCTAssertEqual(model.initialInputEpoch, epoch); XCTAssertEqual(model.state, .preparing)
        await gate.release(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready, "Hiding clears only UI input; an accepted connection continues")
        visible = true; input.update(context()); input.secret = UUID().uuidString
        var renamed = host; renamed.name = "display only"
        model.show(host: renamed); input.update(context()); XCTAssertFalse(input.secret.isEmpty)
        model.cancelCurrent(); input.update(context()); XCTAssertTrue(input.secret.isEmpty)
        await model.waitUntilCurrentWorkCompletes()
        input.secret = UUID().uuidString; input.useTemporaryCredential = true
        var changed = host; changed.port = 2222
        model.show(host: changed); input.update(context())
        XCTAssertTrue(input.secret.isEmpty); XCTAssertFalse(input.useTemporaryCredential)
        input.secret = UUID().uuidString; await model.closeForWindow(); input.update(context()); XCTAssertTrue(input.secret.isEmpty)
    }
    func testConnectionFormUsesConfiguredCredentialAndScopesTemporaryOverridesToOneAttempt() throws {
        let input = FilesInitialInputOwner(), epoch = UUID(), ref = UUID()
        var host = HostConfiguration(name: "Test", address: "example.invalid", username: "fixture",
                                     credentialRef: ref, savePasswordAuthorized: true)
        func context(_ keys: [ManagedKeyReference] = []) -> FilesInitialInputOwner.Context {
            .init(visible: true, host: host, keys: keys, epoch: epoch)
        }
        let password = context()
        input.update(password)
        guard case .configuredCredential(ref)? = input.take(for: password)?.primary else { return XCTFail("Expected saved host password") }
        input.useTemporaryCredential = true
        input.secret = UUID().uuidString
        let supplied = input.secret
        let override = try XCTUnwrap(input.take(for: password))
        guard case .manual(let bytes) = override.primary else { return XCTFail("Expected one-time override") }
        XCTAssertTrue(bytes.matches(.init(utf8: supplied))); XCTAssertFalse(override.keyboardOnly)
        XCTAssertFalse(input.useTemporaryCredential); XCTAssertTrue(input.secret.isEmpty)
        guard case .configuredCredential(ref)? = input.take(for: password)?.primary else { return XCTFail("Expected configuration on next click") }
        input.useTemporaryCredential = true
        XCTAssertTrue(try XCTUnwrap(input.take(for: password)).keyboardOnly)

        host.savePasswordAuthorized = false
        let unsaved = context()
        input.update(unsaved)
        XCTAssertNil(input.take(for: password))
        XCTAssertTrue(try XCTUnwrap(input.take(for: unsaved)).keyboardOnly)
        input.secret = UUID().uuidString
        XCTAssertFalse(try XCTUnwrap(input.take(for: unsaved)).keyboardOnly)

        let key = ManagedKeyReference(algorithm: .ed25519, passphraseCredentialRef: UUID())
        host.authentication = .privateKey; host.keyRef = key.id; host.credentialRef = nil
        let savedKey = context([key])
        input.update(savedKey)
        guard case .configuredCredential(let phrase)? = input.take(for: savedKey)?.primary else { return XCTFail("Expected saved key passphrase") }
        XCTAssertEqual(phrase, key.passphraseCredentialRef)
        input.useTemporaryCredential = true; input.secret = UUID().uuidString
        let plainKey = context([.init(id: key.id, algorithm: key.algorithm)])
        input.update(plainKey)
        XCTAssertNil(input.take(for: savedKey)); XCTAssertTrue(input.secret.isEmpty)
        let keyInput = try XCTUnwrap(input.take(for: plainKey))
        guard case .manual(let empty) = keyInput.primary else { return XCTFail("Expected key without saved passphrase") }
        XCTAssertTrue(empty.withUnsafeBytes { $0.isEmpty }); XCTAssertFalse(keyInput.keyboardOnly)
        host.id = UUID()
        input.update(context())
        XCTAssertNil(input.take(for: plainKey))
    }
    func testLeavingRetainedPageDoesNotCancelConfirmedLocalMutationsOrLoseDeleteReports() async throws {
        let root = try fixture(), refreshGate = ReliabilityLocalRefreshGate()
        let model = LocalBrowserModel(root: root, beforeList: { await refreshGate.read() })
        addTeardownBlock { await model.close() }
        model.activate(); await model.waitUntilIdle()
        let original = try XCTUnwrap(model.path)
        model.mkdir(try FileName("created")); await refreshGate.gate.waitForArrival()
        model.deactivate(); XCTAssertTrue(model.loading)
        await refreshGate.gate.release(); await model.waitUntilIdle()
        XCTAssertNil(model.issue); XCTAssertEqual(model.path, original)
        XCTAssertEqual(model.entries.map(\.name), [try FileName("created")])
        model.rename(try XCTUnwrap(model.entries.first), to: try FileName("renamed")); model.deactivate()
        await model.waitUntilIdle()
        XCTAssertEqual(model.entries.map(\.name), [try FileName("renamed")]); XCTAssertNil(model.issue)
        model.prepareDelete(model.entries, linkOnly: false); await model.waitUntilIdle()
        let review = try XCTUnwrap(model.deleteReview)
        model.executeDelete(review); model.deactivate(); await model.waitUntilIdle()
        XCTAssertEqual(model.deleteReports.count, 1); XCTAssertTrue(model.deleteReports.allSatisfy(\.allSucceeded))
        XCTAssertTrue(model.entries.isEmpty); XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }
    func testLocalNavigationHistoryAndFailedPathsKeepLastSuccessfulSnapshot() async throws {
        let root = try fixture()
        for name in ["first", "second"] { try FileManager.default.createDirectory(at: root.appendingPathComponent(name), withIntermediateDirectories: false) }
        let model = model(root); model.activate(); await model.waitUntilIdle()
        let originalPath = try XCTUnwrap(model.path), originalEntries = model.entries
        let first = try XCTUnwrap(model.entries.first { $0.name.bytes == Data("first".utf8) })
        model.enter(first); await model.waitUntilIdle()
        XCTAssertEqual(model.path, try originalPath.appending(first.name)); XCTAssertNotNil(model.history.backward)
        model.back(); await model.waitUntilIdle(); XCTAssertEqual(model.path, originalPath); XCTAssertNotNil(model.history.forward)
        model.go("/does-not-exist-in-marked-root"); await model.waitUntilIdle()
        XCTAssertNotNil(model.issue); XCTAssertEqual(model.path, originalPath); XCTAssertEqual(model.entries, originalEntries)
        XCTAssertNotNil(model.history.forward)
        model.forward(); await model.waitUntilIdle(); XCTAssertEqual(model.path, try originalPath.appending(first.name))
        model.up(); await model.waitUntilIdle(); XCTAssertEqual(model.path, originalPath)
        XCTAssertFalse(model.canGoUp)
    }
    func testLocalLinksCannotBeEnteredAndDeleteCancellationChangesNothing() async throws {
        let root = try fixture(), outside = try fixture()
        try Data("keep".utf8).write(to: outside.appendingPathComponent("keep"))
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("link"), withDestinationURL: outside)
        let model = model(root); model.activate(); await model.waitUntilIdle()
        let entry = try XCTUnwrap(model.entries.first)
        model.enter(entry); await model.waitUntilIdle()
        XCTAssertEqual(model.issue?.code, "files.symbolicLink")
        model.prepareDelete([entry], linkOnly: false); await model.waitUntilIdle()
        XCTAssertFalse(try XCTUnwrap(model.deleteReview).canExecute)
        model.discardDelete(); XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent("link").path))
        model.prepareDelete([entry], linkOnly: true); await model.waitUntilIdle()
        let review = try XCTUnwrap(model.deleteReview); XCTAssertTrue(review.canExecute)
        model.executeDelete(review); await model.waitUntilIdle()
        XCTAssertTrue(model.deleteReports.allSatisfy(\.allSucceeded))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("link").path))
        XCTAssertEqual(try Data(contentsOf: outside.appendingPathComponent("keep")), Data("keep".utf8))
    }
    func testLocalMkdirRenameAndMultiRootDeleteAreRealAndPrecise() async throws {
        let root = try fixture(), model = model(root)
        model.activate(); await model.waitUntilIdle()
        model.mkdir(try FileName("new folder")); await model.waitUntilIdle()
        let created = try XCTUnwrap(model.entries.first)
        model.rename(created, to: try FileName("renamed")); await model.waitUntilIdle()
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent("renamed").path))
        for name in ["first", "second", "keep"] { try Data(name.utf8).write(to: root.appendingPathComponent(name)) }
        model.refresh(); await model.waitUntilIdle()
        let rows = model.entries.filter { [Data("first".utf8), Data("second".utf8)].contains($0.name.bytes) }
        model.prepareDelete(rows, linkOnly: false); await model.waitUntilIdle()
        let cancelled = try XCTUnwrap(model.deleteReview); XCTAssertEqual(cancelled.items.count, 2)
        model.discardDelete()
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent("first").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent("second").path))
        model.executeDelete(cancelled); await model.waitUntilIdle()
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent("first").path))
        model.prepareDelete(rows, linkOnly: false); await model.waitUntilIdle()
        let review = try XCTUnwrap(model.deleteReview)
        model.executeDelete(review); await model.waitUntilIdle()
        XCTAssertEqual(model.deleteReports.count, 2); XCTAssertTrue(model.deleteReports.allSatisfy(\.allSucceeded))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("first").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("second").path))
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("keep")), Data("keep".utf8))
    }
    func testAggregateDeleteRevalidatesAllRootsBeforeDeletingAny() async throws {
        let root = try fixture()
        for name in ["first", "second"] { try Data("original".utf8).write(to: root.appendingPathComponent(name)) }
        let model = model(root); model.activate(); await model.waitUntilIdle()
        model.prepareDelete(model.entries, linkOnly: false); await model.waitUntilIdle()
        let review = try XCTUnwrap(model.deleteReview)
        try Data("changed".utf8).write(to: root.appendingPathComponent("second"))
        model.executeDelete(review); await model.waitUntilIdle()
        XCTAssertEqual(model.issue?.code, "files.raceDetected")
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("first")), Data("original".utf8))
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("second")), Data("changed".utf8))
    }
    private func remote(_ root: URL, initial: RemotePath = .root) async throws -> FilesController {
        let model = FilesController(connector: DualPaneLocalConnector(root: root), idleTimeout: nil, localBrowserRoot: root,
            initialPath: { _, token in try token.check(); return initial })
        addTeardownBlock { await model.closeForWindow() }
        model.show(host: HostConfiguration(name: "synthetic direct endpoint", address: "never-connected.invalid", username: "fixture"))
        await model.waitUntilCurrentWorkCompletes()
        model.connect(.init(primary: .manual(.init(utf8: ""))))
        await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .ready)
        return model
    }
    func testRemoteInitialPathSeamHistoryAndFailureKeepSuccessfulLocation() async throws {
        let root = try fixture()
        try FileManager.default.createDirectory(at: root.appendingPathComponent("login/child"), withIntermediateDirectories: true)
        let login = try RemotePath("/login"), model = try await remote(root, initial: login)
        XCTAssertEqual(model.path, login); XCTAssertEqual(model.navigationHistory.paths, [login])
        let child = try XCTUnwrap(model.entries.first)
        model.enter(child); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.path, try login.appending(child.name))
        model.back(); await model.waitUntilCurrentWorkCompletes(); XCTAssertEqual(model.path, login)
        let rows = model.entries
        model.go(manualUTF8: "/missing"); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.path, login); XCTAssertEqual(model.entries, rows); XCTAssertNotNil(model.issue)
        model.forward(); await model.waitUntilCurrentWorkCompletes(); XCTAssertEqual(model.path, try login.appending(child.name))
    }
    func testRemoteAggregateDeleteCancellationAndStaleRootPreflightDoNotPartiallyDelete() async throws {
        let root = try fixture()
        for name in ["first", "second"] { try Data("original".utf8).write(to: root.appendingPathComponent(name)) }
        let model = try await remote(root)
        model.prepareDeleteBatch(model.entries, removeLinkOnly: false); await model.waitUntilCurrentWorkCompletes()
        let cancelled = try XCTUnwrap(model.deleteBatchReview)
        XCTAssertEqual(cancelled.review.items.count, 2)
        model.discardDeleteBatch(); model.executeDeleteBatch(cancelled); await model.waitUntilCurrentWorkCompletes()
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appendingPathComponent("first").path))
        model.prepareDeleteBatch(model.entries, removeLinkOnly: false); await model.waitUntilCurrentWorkCompletes()
        let changed = try XCTUnwrap(model.deleteBatchReview)
        try Data("changed".utf8).write(to: root.appendingPathComponent("second"))
        model.executeDeleteBatch(changed); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.issue?.code, "files.raceDetected")
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("first")), Data("original".utf8))
        model.prepareDeleteBatch(model.entries, removeLinkOnly: false); await model.waitUntilCurrentWorkCompletes()
        let current = try XCTUnwrap(model.deleteBatchReview)
        model.executeDeleteBatch(current); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.lastDeleteReports.count, 2); XCTAssertTrue(model.lastDeleteReports.allSatisfy(\.allSucceeded))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }
    func testRemoteDragPayloadRejectsNavigationAndDifferentServiceGenerations() async throws {
        let root = try fixture()
        try Data("keep".utf8).write(to: root.appendingPathComponent("file"))
        try FileManager.default.createDirectory(at: root.appendingPathComponent("child"), withIntermediateDirectories: false)
        let model = try await remote(root)
        let context = try model.transferContext(upload: false)
        let rows = model.entries
        let pasteboard = NSPasteboard.withUniqueName(); defer { pasteboard.releaseGlobally() }
        pasteboard.writeObjects([FilesPaneDrag.remote(rows: rows, context: context)])
        XCTAssertEqual(FilesPaneDrag.remoteNames(pasteboard, controller: model), Set(rows.map(\.name)))
        model.browse(try RemotePath("/child")); await model.waitUntilCurrentWorkCompletes()
        XCTAssertNil(FilesPaneDrag.remoteNames(pasteboard, controller: model))
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
        model.connect(.init(primary: .manual(.init(utf8: "")))); await model.waitUntilCurrentWorkCompletes()
        XCTAssertNil(FilesPaneDrag.remoteNames(pasteboard, controller: model))
    }
    func testRawFileURLBridgePreservesBytesAndRejectsAmbiguousComponents() throws {
        let paths: [RemotePath] = [.root, try RemotePath("/space #?%/中文 e\u{301}\n"),
            try RemotePath(bytes: Data([47, 255, 65, 47, 128, 37]))]
        for path in paths {
            let url = FilesLocalPaths.url(path)
            XCTAssertTrue(url.isFileURL)
            XCTAssertEqual(try FilesLocalPaths.rawPath(FilesLocalPaths.components(url)), path)
            let restored = try XCTUnwrap(URL(string: url.absoluteString))
            XCTAssertEqual(try FilesLocalPaths.rawPath(FilesLocalPaths.components(restored)), path)
        }
        for text in ["https://example.invalid/file", "file://remote.invalid/tmp/file", "file://user@localhost/tmp/file",
                     "file://localhost:22/tmp/file", "file:///tmp/file?query", "file:///tmp/file#fragment",
                     "file:///tmp/%2Fescape", "file:///tmp/%00", "file:///tmp/%2E%2E/escape"] {
            let url = try XCTUnwrap(URL(string: text))
            XCTAssertThrowsError(try FilesLocalPaths.components(url), text)
        }
    }
    func testRawHistorySortAndPermissionFormattingDoNotRewriteIdentity() throws {
        var history = FilesNavigationHistory()
        let first = try RemotePath("/first"), second = try RemotePath("/second"), third = try RemotePath("/third")
        history.commit(first); history.commit(second); history.commit(first, index: 0); history.commit(third)
        XCTAssertEqual(history.paths, [first, third]); XCTAssertNil(history.forward)
        let raw = try FileName(bytes: Data([255, 65]))
        let small = DirectoryEntry(name: raw, attributes: .init(kind: .regular, size: 1, permissions: 0o100600))
        let large = DirectoryEntry(name: try FileName("large"), attributes: .init(kind: .regular, size: 12))
        XCTAssertEqual(FilesSort(column: .size, ascending: true).apply([large, small]).first?.name.bytes, raw.bytes)
        XCTAssertEqual(FilesMetadataDisplay.permissions(small.attributes), "0600")
        let path = try RemotePath.root.appending(raw)
        XCTAssertEqual(try FilesLocalPaths.rawPath(FilesLocalPaths.components(FilesLocalPaths.url(path))), path)
    }
}
private actor ReliabilityLocalReadFault {
    private(set) var count = 0
    func read() throws { count += 1; if count == 1 { throw FileServiceError(.io, operation: "injected-first-list") } }
}
private actor ReliabilityLocalRefreshGate {
    let gate = ReliabilityGate()
    private var reads = 0
    func read() async { reads += 1; if reads == 2 { await gate.suspend() } }
}
private actor ReliabilityOneShotLocalGate {
    let gate = ReliabilityGate()
    private var first = true
    func read() async { if first { first = false; await gate.suspend() } }
}
private struct DualPaneLocalConnector: FilesConnecting {
    let root: URL
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        try token.check()
        guard await isCurrent() else { throw FileServiceError(.cancelled, operation: "dual-pane-fixture-stale") }
        return try LocalFileService(root: root)
    }
}
private actor DualPaneReadCounter {
    private(set) var count = 0
    func read() { count += 1 }
}

// These tests use explicit local substitutes through the production default initialPath
// closure. They prove consumer state/identity handling, NOT real SFTP realpath behavior.
extension DualPaneFilesTests {
    private func initialDirectoryController(_ root: URL, services: [any RemoteFileService]) async -> FilesController {
        let model = FilesController(connector: DualPaneInitialDirectoryConnector(services: services),
            idleTimeout: nil, localBrowserRoot: root)
        addTeardownBlock { await model.closeForWindow() }
        model.show(host: HostConfiguration(name: "local login substitute, not SFTP", address: "never-connected.invalid", username: "fixture"))
        await model.waitUntilCurrentWorkCompletes()
        return model
    }
    private func connectInitialDirectory(_ model: FilesController) async {
        model.connect(.init(primary: .manual(.init(utf8: ""))))
        await model.waitUntilCurrentWorkCompletes()
    }
    func testDefaultInitialPathCallsServiceCapabilityAndPreservesLoginPathBytes() async throws {
        let root = try fixture(), login = try RemotePath("/login/中文 e\u{301} space\n")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("login/中文 e\u{301} space\n/child"), withIntermediateDirectories: true)
        let service = try DualPaneInitialDirectoryService(root: root) { token in try token.check(); return login }
        let model = await initialDirectoryController(root, services: [service])
        await connectInitialDirectory(model)
        XCTAssertEqual(model.state, .ready)
        XCTAssertEqual(model.path.bytes, login.bytes)
        XCTAssertEqual(model.navigationHistory.paths, [login])
        XCTAssertEqual(model.entries.map(\.name), [try FileName("child")])
        let calls = await service.initialCalls, listings = await service.listings
        XCTAssertEqual(calls, 1); XCTAssertEqual(listings, [login], "The default must not list root before/after resolving login")
    }
    func testDefaultInitialPathFailureDoesNotGuessRootOrReplaceLastSuccessfulListing() async throws {
        let root = try fixture(), login = try RemotePath("/login")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("login/keep"), withIntermediateDirectories: true)
        let first = try DualPaneInitialDirectoryService(root: root) { _ in login }
        let failure = try DualPaneInitialDirectoryService(root: root) { _ in
            throw FileServiceError(.unsupported, operation: "local-substitute-realpath-unavailable")
        }
        let model = await initialDirectoryController(root, services: [first, failure])
        await connectInitialDirectory(model)
        XCTAssertEqual(model.state, .ready)
        let successfulPath = model.path, rows = model.entries, history = model.navigationHistory
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
        await connectInitialDirectory(model)
        XCTAssertEqual(model.state, .failed); XCTAssertEqual(model.issue?.code, "files.unsupported")
        XCTAssertEqual(model.path, successfulPath); XCTAssertEqual(model.entries, rows)
        XCTAssertEqual(model.navigationHistory.paths, history.paths)
        let calls = await failure.initialCalls, listings = await failure.listings, closes = await failure.closes
        XCTAssertEqual(calls, 1); XCTAssertTrue(listings.isEmpty); XCTAssertEqual(closes, 1)
        XCTAssertFalse(model.canTransfer)
    }
    func testResolvedLoginListingErrorKeepsLastSuccessfulPathAndRows() async throws {
        let root = try fixture(), login = try RemotePath("/login"), missing = try RemotePath("/missing-login")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("login/keep"), withIntermediateDirectories: true)
        let first = try DualPaneInitialDirectoryService(root: root) { _ in login }
        let missingService = try DualPaneInitialDirectoryService(root: root) { _ in missing }
        let model = await initialDirectoryController(root, services: [first, missingService])
        await connectInitialDirectory(model)
        let rows = model.entries
        XCTAssertEqual(model.state, .ready)
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
        await connectInitialDirectory(model)
        XCTAssertEqual(model.state, .failed); XCTAssertEqual(model.issue?.code, "files.notFound")
        XCTAssertEqual(model.path, login); XCTAssertEqual(model.entries, rows)
        let listings = await missingService.listings
        XCTAssertTrue(listings.isEmpty, "Failed login inspection must not trigger a root listing fallback")
    }
    func testCancelledLoginResolutionCannotPublishLatePathOrReplaceSuccessfulRows() async throws {
        let root = try fixture(), login = try RemotePath("/login"), late = try RemotePath("/late"), gate = DualPaneInitialDirectoryGate()
        try FileManager.default.createDirectory(at: root.appendingPathComponent("login/keep"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("late/wrong"), withIntermediateDirectories: true)
        let first = try DualPaneInitialDirectoryService(root: root) { _ in login }
        let pending = try DualPaneInitialDirectoryService(root: root) { _ in
            await gate.suspend(); return late // Intentionally late success tests the consumer's generation guard.
        }
        let model = await initialDirectoryController(root, services: [first, pending])
        await connectInitialDirectory(model)
        XCTAssertEqual(model.state, .ready)
        let rows = model.entries
        model.cancelCurrent(); await model.waitUntilCurrentWorkCompletes()
        model.connect(.init(primary: .manual(.init(utf8: ""))))
        await gate.waitForArrival()
        model.cancelCurrent(); await gate.release(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.state, .disconnected); XCTAssertEqual(model.path, login); XCTAssertEqual(model.entries, rows)
        let listings = await pending.listings, closes = await pending.closes
        XCTAssertTrue(listings.isEmpty); XCTAssertEqual(closes, 1)
    }
    func testHostChangeRejectsOldLoginResolutionAndOnlyListsFreshServicePath() async throws {
        let root = try fixture(), old = try RemotePath("/old"), fresh = try RemotePath("/fresh"), gate = DualPaneInitialDirectoryGate()
        try FileManager.default.createDirectory(at: root.appendingPathComponent("old/wrong"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("fresh/right"), withIntermediateDirectories: true)
        let first = try DualPaneInitialDirectoryService(root: root) { _ in await gate.suspend(); return old }
        let second = try DualPaneInitialDirectoryService(root: root) { token in try token.check(); return fresh }
        let model = await initialDirectoryController(root, services: [first, second])
        model.connect(.init(primary: .manual(.init(utf8: ""))))
        await gate.waitForArrival()
        let next = HostConfiguration(name: "fresh local substitute", address: "another-never.invalid", username: "next")
        model.show(host: next); model.connect(.init(primary: .manual(.init(utf8: ""))))
        await gate.release(); await model.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.selectedHost, next); XCTAssertEqual(model.state, .ready)
        XCTAssertEqual(model.path, fresh); XCTAssertEqual(model.navigationHistory.paths, [fresh])
        XCTAssertEqual(model.entries.map(\.name), [try FileName("right")])
        let oldListings = await first.listings, freshListings = await second.listings, oldCloses = await first.closes
        XCTAssertTrue(oldListings.isEmpty); XCTAssertEqual(freshListings, [fresh]); XCTAssertEqual(oldCloses, 1)
    }
}
private actor DualPaneInitialDirectoryConnector: FilesConnecting {
    private var services: [any RemoteFileService]
    init(services: [any RemoteFileService]) { self.services = services }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        try token.check()
        guard await isCurrent(), !services.isEmpty else { throw FileServiceError(.cancelled, operation: "local-login-substitute-stale") }
        return services.removeFirst()
    }
}
private actor DualPaneInitialDirectoryService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow,
        exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: LocalFileService
    let resolve: @Sendable (CancellationToken) async throws -> RemotePath
    private(set) var initialCalls = 0
    private(set) var listings: [RemotePath] = []
    private(set) var closes = 0
    init(root: URL, resolve: @escaping @Sendable (CancellationToken) async throws -> RemotePath) throws {
        base = try LocalFileService(root: root); self.resolve = resolve
    }
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { initialCalls += 1; return try await resolve(token) }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { listings.append(p); return try await base.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(p, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(h, maxBytes: maxBytes, token: token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await base.mkdir(p, token: token) }
    func rename(_ s: RemotePath, to d: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(s, to: d, mode: mode, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(p, directory: directory, token: token) }
    nonisolated func cancel() { base.cancel() }
    func close() async { closes += 1; await base.close() }
}
private actor DualPaneInitialDirectoryGate {
    private var arrived = false
    private var pending: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    func suspend() async {
        arrived = true; observer?.resume(); observer = nil
        await withCheckedContinuation { pending = $0 }
    }
    func waitForArrival() async { if !arrived { await withCheckedContinuation { observer = $0 } } }
    func release() { pending?.resume(); pending = nil }
}

/// Real temporary filesystem consumers with an explicit local service substitute, not SFTP evidence.
@MainActor final class FilesReviewOwnerTests: XCTestCase {
    private func root() throws -> URL {
        let url = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-FilesOwners-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: url) }
        return url
    }
    private func boundary(_ condition: @MainActor () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "files-owner-test-boundary") }
            await Task.yield()
        }
    }
    private func idle(_ model: LocalBrowserModel) async throws { try await boundary { !model.loading } }
    private func idle(_ model: FilesController) async throws { try await boundary { !model.busy } }
    private func local(_ root: URL, beforeList: (@Sendable () async throws -> Void)? = nil) async throws -> LocalBrowserModel {
        let model = LocalBrowserModel(root: root, beforeList: beforeList)
        addTeardownBlock { await model.close() }
        model.activate(); try await idle(model); return model
    }
    private func remote(_ root: URL, services: [any RemoteFileService], riskGate: FilesOwnersGate? = nil,
                        historyGate: FilesOwnersGate? = nil) async throws -> FilesController {
        let model = FilesController(connector: FilesOwnersConnector(services: services), idleTimeout: nil,
            beforeOperationRiskDelivery: { if let riskGate { try? await riskGate.suspend() } },
            beforeHistoryRemovalSnapshot: { if let historyGate { try? await historyGate.suspend() } },
            localBrowserRoot: root)
        addTeardownBlock {
            await riskGate?.release(); await historyGate?.release()
            await model.closeForWindow()
        }
        model.show(host: HostConfiguration(name: "original local substitute", address: "never-connected.invalid", username: "fixture"))
        try await idle(model)
        model.connect(.init(primary: .manual(.init(utf8: "")))); try await idle(model)
        XCTAssertEqual(model.state, .ready); return model
    }
    private func entry(_ name: String, _ rows: [DirectoryEntry]) throws -> DirectoryEntry {
        try XCTUnwrap(rows.first { $0.name.bytes == Data(name.utf8) })
    }
    private func noMutations(_ service: FilesOwnersService) async {
        let count = await service.mutations; XCTAssertEqual(count, 0)
    }
    private func completedDownload(_ model: FilesController, root: URL, name: String) async throws -> UUID {
        let output = root.appendingPathComponent("output-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false)
        model.browse(.root); try await idle(model)
        let admission = try model.enqueueDownloads([entry(name, model.entries)], to: output, context: model.transferContext(upload: false))
        try await boundary { model.enqueueInFlight == 0 }
        let ids = try await admission.value, id = try XCTUnwrap(ids.first)
        try await boundary { await model.manager.snapshot().jobs.contains { $0.id == id && !$0.state.isActive } }
        try await boundary { model.transferSnapshot.jobs.contains { $0.id == id && !$0.state.isActive } }
        XCTAssertEqual(model.transferSnapshot.jobs.first { $0.id == id }?.state, .succeeded)
        return id
    }
    /// Foundation Data/URL I/O cannot reopen invalid UTF-8 names. Keep fixture I/O on the
    /// same descriptor-backed raw-byte service that the actual browser consumer uses.
    private func rawService(_ root: URL) throws -> LocalFileService {
        let fd = try FilesLocalPaths.openDirectory(FilesLocalPaths.components(root))
        defer { Darwin.close(fd) }
        let service = try LocalFileService(rootDirectoryDescriptor: fd)
        addTeardownBlock { await service.close() }
        return service
    }
    private func writeRaw(_ data: Data, at path: RemotePath, service: LocalFileService) async throws {
        let token = CancellationToken(), handle = try await service.open(path, mode: .exclusiveWrite, token: token)
        do {
            var offset = 0
            while offset < data.count {
                let count = try await service.write(handle, data: Data(data.dropFirst(offset)), token: token)
                guard count > 0 else { throw FileServiceError(.io, operation: "files-owner-fixture-write-stalled", path: path) }
                offset += count
            }
            try await service.finish(handle, token: token)
            try await service.closeHandle(handle)
        } catch { try? await service.closeHandle(handle); throw error }
    }
    private func readRaw(_ path: RemotePath, service: LocalFileService) async throws -> Data {
        let handle = try await service.open(path, mode: .read, token: CancellationToken())
        do {
            let data = try await readRawHandle(handle, service: service)
            try await service.closeHandle(handle); return data
        } catch { try? await service.closeHandle(handle); throw error }
    }
    private func readRawHandle(_ handle: FileHandleID, service: LocalFileService) async throws -> Data {
        let token = CancellationToken()
        var data = Data()
        while true {
            let chunk = try await service.read(handle, maxBytes: 4096, token: token)
            if chunk.isEmpty { return data }
            data.append(chunk)
            guard data.count <= 65536 else { throw FileServiceError(.resourceLimit, operation: "files-owner-fixture-read-bound") }
        }
    }
    func testPresentationUUIDAndExactRawTargetSnapshotNeverFollowCurrentPath() async throws {
        let root = try root(), raw = try FileName(bytes: Data([255, 32, 65, 10]))
        let parent = try FilesLocalPaths.rawPath(FilesLocalPaths.components(root)), exact = try parent.appending(raw)
        XCTAssertEqual(try FilesLocalPaths.rawPath(FilesLocalPaths.components(FilesLocalPaths.url(exact))).bytes, exact.bytes)
        // This APFS host rejects physical FF names (EILSEQ). Real local I/O uses a valid,
        // complex UTF-8 name; the separate remote namespace below retains exact FF bytes.
        let physical = try FileName("中文 e\u{301} space\nname"), physicalPath = try RemotePath.root.appending(physical)
        let service = try rawService(root)
        try await writeRaw(Data("original".utf8), at: physicalPath, service: service)
        let held = try await service.open(physicalPath, mode: .read, token: CancellationToken())
        let model = try await local(root), row = try XCTUnwrap(model.entries.first)
        let target = try XCTUnwrap(model.captureTarget([row])), second = try XCTUnwrap(model.captureTarget([row]))
        let details = DualFilesDialog(content: .details(target, true)), another = DualFilesDialog(content: .details(target, true))
        for content in [DualFilesDialog.Content.name(target, true), .deleteOptions(target, true)] {
            XCTAssertNotEqual(DualFilesDialog(content: content).id, DualFilesDialog(content: content).id)
        }
        XCTAssertNotEqual(target.id, second.id); XCTAssertNotEqual(details.id, another.id)
        XCTAssertEqual(target.parent, parent); XCTAssertEqual(target.path(for: row)?.bytes, try parent.appending(physical).bytes)
        XCTAssertEqual(target.entries, [row]); XCTAssertEqual(target.endpoint, "本地 · 此 Mac")
        var targets = [target, second]
        for _ in 0..<6 { targets.append(try XCTUnwrap(model.captureTarget([row]))) }
        XCTAssertNil(model.captureTarget([row])); XCTAssertEqual(model.issue?.code, "files.resourceLimit")
        model.discardTarget(targets.removeLast())
        XCTAssertNotNil(model.captureTarget([row]), "Exact discard releases one bounded presentation slot")
        model.filter = "no match"; model.deactivate()
        XCTAssertEqual(target.path(for: row)?.bytes, try parent.appending(physical).bytes)
        model.rename(to: try FileName("wrong"), target: target); try await idle(model)
        let unchanged = try await readRaw(physicalPath, service: service), heldBytes = try await readRawHandle(held, service: service)
        XCTAssertEqual(unchanged, Data("original".utf8)); XCTAssertEqual(heldBytes, Data("original".utf8))
        try await service.closeHandle(held)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("wrong").path))

        let rawRoot = try self.root(), rawService = try RawNameRemoteFileService(root: rawRoot, rawName: raw)
        addTeardownBlock { await rawService.close() }
        try await rawService.install(Data("original raw backing".utf8))
        let remote = try await remote(rawRoot, services: [rawService]), rawRow = try XCTUnwrap(remote.entries.first)
        let rawTarget = try XCTUnwrap(remote.captureTarget([rawRow])), rawSecond = try XCTUnwrap(remote.captureTarget([rawRow]))
        XCTAssertNotEqual(rawTarget.id, rawSecond.id)
        XCTAssertNotEqual(DualFilesDialog(content: .details(rawTarget, false)).id, DualFilesDialog(content: .details(rawTarget, false)).id)
        XCTAssertEqual(rawTarget.entries, [rawRow]); XCTAssertEqual(rawRow.name.bytes, raw.bytes)
        XCTAssertEqual(rawTarget.parent, .root); XCTAssertEqual(rawTarget.path(for: rawRow)?.bytes, Data([47]) + raw.bytes)
        remote.hide(); remote.rename(name: try FileName("wrong"), conflict: .fail, target: rawTarget); try await idle(remote)
        let rawBytes = try await rawService.readCurrent(), trace = await rawService.trace()
        XCTAssertEqual(rawBytes, Data("original raw backing".utf8)); XCTAssertEqual(trace.mutations, 0)
        XCTAssertEqual(trace.listResponses, [[raw.bytes]])
        XCTAssertEqual(trace.lstatRequests, [RemotePath.root.bytes])
    }
    func testLocalCapturedCreateRenameAndDeleteRejectNavigationWhileListIsSuspended() async throws {
        let root = try root(), gate = FilesOwnersGate(), reads = FilesOwnersReadGate(gate: gate)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("other"), withIntermediateDirectories: false)
        try Data("original".utf8).write(to: root.appendingPathComponent("same"))
        try Data("other".utf8).write(to: root.appendingPathComponent("other/same"))
        let model = try await local(root, beforeList: { try await reads.read() })
        addTeardownBlock { await gate.release(); await model.close() }
        let row = try entry("same", model.entries), parent = try XCTUnwrap(model.path)
        let create = try XCTUnwrap(model.captureTarget()), rename = try XCTUnwrap(model.captureTarget([row]))
        let deletion = try XCTUnwrap(model.captureTarget([row]))
        model.navigate(try parent.appending(FileName("other"))); try await boundary { await gate.hasArrived }
        model.mkdir(try FileName("wrong"), target: create)
        model.rename(to: try FileName("wrong"), target: rename); model.prepareDelete(deletion, linkOnly: false)
        await gate.release(); try await idle(model)
        XCTAssertNil(model.deleteReview)
        model.navigate(parent); try await idle(model)
        model.rename(to: try FileName("wrong"), target: rename); try await idle(model)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("same")), Data("original".utf8))
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("other/same")), Data("other".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("other/wrong").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("wrong").path))
    }
    func testLocalSameNameReplacementCannotRenameOrPrepareDeleteNewObject() async throws {
        // APFS physical I/O covers a valid complex name; FF identity is covered by the explicit remote namespace.
        let root = try root(), name = "中文 e\u{301} space\nsame", url = root.appendingPathComponent(name)
        let path = try RemotePath.root.appending(FileName(name)), fixture = try rawService(root)
        try Data("old".utf8).write(to: url)
        let originalHandle = try await fixture.open(path, mode: .read, token: CancellationToken())
        let model = try await local(root), row = try entry(name, model.entries)
        let rename = try XCTUnwrap(model.captureTarget([row])), deletion = try XCTUnwrap(model.captureTarget([row]))
        try Data("replacement with different bytes".utf8).write(to: url, options: .atomic)
        model.rename(to: try FileName("wrong"), target: rename); try await idle(model)
        XCTAssertEqual(model.issue?.code, "files.raceDetected")
        model.prepareDelete(deletion, linkOnly: false); try await idle(model)
        XCTAssertNil(model.deleteReview)
        model.refresh(); try await idle(model)
        let fresh = try XCTUnwrap(model.captureTarget([entry(name, model.entries)]))
        let replacedHandle = try await fixture.open(path, mode: .read, token: CancellationToken())
        try Data("second replacement".utf8).write(to: url, options: .atomic)
        model.prepareDelete(fresh, linkOnly: false); try await idle(model)
        XCTAssertEqual(model.issue?.code, "files.raceDetected"); XCTAssertNil(model.deleteReview)
        XCTAssertEqual(try Data(contentsOf: url), Data("second replacement".utf8))
        let originalBytes = try await readRawHandle(originalHandle, service: fixture)
        let replacedBytes = try await readRawHandle(replacedHandle, service: fixture)
        XCTAssertEqual(originalBytes, Data("old".utf8)); XCTAssertEqual(replacedBytes, Data("replacement with different bytes".utf8))
        try await fixture.closeHandle(originalHandle); try await fixture.closeHandle(replacedHandle)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("wrong").path))
    }
    func testLocalAndRemoteCreateRejectSamePathReplacedParentWithZeroRemoteMutations() async throws {
        let root = try root(), parentURL = root.appendingPathComponent("parent"), service = try FilesOwnersService(root: root)
        try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: false)
        let local = try await local(root), remote = try await remote(root, services: [service])
        local.navigate(try FilesLocalPaths.rawPath(FilesLocalPaths.components(parentURL))); try await idle(local)
        remote.browse(try RemotePath("/parent")); try await idle(remote)
        let localTarget = try XCTUnwrap(local.captureTarget()), remoteTarget = try XCTUnwrap(remote.captureTarget())
        try FileManager.default.moveItem(at: parentURL, to: root.appendingPathComponent("old-parent"))
        try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: false)
        local.mkdir(try FileName("wrong"), target: localTarget); try await idle(local)
        remote.mkdir(try FileName("wrong"), target: remoteTarget, acknowledgedRemoteRisk: true); try await idle(remote)
        XCTAssertEqual(local.issue?.code, "files.raceDetected"); XCTAssertEqual(remote.issue?.code, "files.raceDetected")
        await noMutations(service)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: parentURL.path).isEmpty)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("old-parent").path).isEmpty)
    }
    func testLocalCancelIsZeroMutationAndConfirmedTargetIsOnceOnly() async throws {
        let root = try root(), model = try await local(root)
        let cancelled = try XCTUnwrap(model.captureTarget()); model.discardTarget(cancelled)
        model.mkdir(try FileName("cancelled"), target: cancelled); try await idle(model)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
        let target = try XCTUnwrap(model.captureTarget())
        model.mkdir(try FileName("confirmed"), target: target); model.deactivate(); try await idle(model)
        model.mkdir(try FileName("second"), target: target); try await idle(model)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), ["confirmed"])
    }
    func testLocalContentConsumerSeparatesFirstErrorEmptyFilteredAndLastSuccessfulError() async throws {
        let root = try root(), fault = FilesOwnersReadFault(), model = try await local(root, beforeList: { try await fault.read() })
        XCTAssertEqual(model.contentState, .failed(hasSnapshot: false)); XCTAssertNil(model.path)
        model.issue = nil; XCTAssertEqual(model.contentState, .failed(hasSnapshot: false))
        model.refresh(); try await idle(model)
        let parent = try XCTUnwrap(model.path)
        XCTAssertEqual(model.contentState, .empty)
        try Data("keep".utf8).write(to: root.appendingPathComponent("keep")); model.refresh(); try await idle(model)
        model.filter = "absent"; XCTAssertEqual(model.contentState, .filteredEmpty)
        model.go("/outside-root-invalid"); try await idle(model)
        XCTAssertEqual(model.contentState, .failed(hasSnapshot: true)); XCTAssertEqual(model.path, parent)
        XCTAssertEqual(model.entries.count, 1)
        model.refresh(); try await idle(model); XCTAssertEqual(model.contentState, .filteredEmpty)
        model.filter = ""; XCTAssertEqual(model.contentState, .populated)
    }
    func testRemoteNavigationGateRejectsAllOldOperationTargetsWithZeroMutations() async throws {
        let root = try root(), gate = FilesOwnersGate(), service = try FilesOwnersService(root: root)
        try Data("original".utf8).write(to: root.appendingPathComponent("same"))
        try FileManager.default.createDirectory(at: root.appendingPathComponent("other"), withIntermediateDirectories: false)
        try Data("other".utf8).write(to: root.appendingPathComponent("other/same"))
        let model = try await remote(root, services: [service]), row = try entry("same", model.entries)
        addTeardownBlock { await gate.release(); await model.closeForWindow() }
        let create = try XCTUnwrap(model.captureTarget()), rename = try XCTUnwrap(model.captureTarget([row]))
        let deletion = try XCTUnwrap(model.captureTarget([row]))
        await service.pauseNextList(gate); model.browse(try RemotePath("/other")); try await boundary { await gate.hasArrived }
        model.mkdir(try FileName("wrong"), target: create, acknowledgedRemoteRisk: true)
        model.rename(name: try FileName("wrong"), conflict: .fail, target: rename)
        model.prepareDeleteBatch(deletion, removeLinkOnly: false)
        await gate.release(); try await idle(model)
        model.browse(.root); try await idle(model)
        model.rename(name: try FileName("wrong"), conflict: .fail, target: rename); try await idle(model)
        await noMutations(service); XCTAssertNil(model.deleteBatchReview)
        XCTAssertEqual(rename.parent, .root); XCTAssertEqual(rename.path(for: row), try RemotePath("/same"))
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("same")), Data("original".utf8))
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("other/same")), Data("other".utf8))
    }
    func testRemoteHostConfigurationAndReconnectionRevokeOldTargetsWithoutRetargeting() async throws {
        let root = try root(), first = try FilesOwnersService(root: root), second = try FilesOwnersService(root: root)
        try Data("original".utf8).write(to: root.appendingPathComponent("same"))
        let model = try await remote(root, services: [first, second]), row = try entry("same", model.entries)
        let old = try XCTUnwrap(model.captureTarget([row])), create = try XCTUnwrap(model.captureTarget())
        var changed = try XCTUnwrap(model.selectedHost); changed.port += 1
        model.show(host: changed) // Old service stays connected, but its unconfirmed presentation is revoked.
        model.rename(name: try FileName("wrong"), conflict: .fail, target: old); try await idle(model)
        await noMutations(first)
        model.cancelCurrent(); try await idle(model)
        var next = changed; next.id = UUID(); next.name = "new host"
        model.show(host: next); try await idle(model)
        model.connect(.init(primary: .manual(.init(utf8: "")))); try await idle(model)
        model.mkdir(try FileName("wrong"), target: create, acknowledgedRemoteRisk: true)
        model.prepareDeleteBatch(old, removeLinkOnly: false); try await idle(model)
        await noMutations(second); XCTAssertNil(model.deleteBatchReview)
        XCTAssertTrue(old.endpoint.contains("original local substitute")); XCTAssertFalse(old.endpoint.contains("new host"))
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("same")), Data("original".utf8))
    }
    func testRemoteMetadataOnlyRenameKeepsConnectionAndFrozenDisplayOwner() async throws {
        let root = try root(), service = try FilesOwnersService(root: root)
        try Data("original".utf8).write(to: root.appendingPathComponent("same"))
        let model = try await remote(root, services: [service]), row = try entry("same", model.entries)
        let target = try XCTUnwrap(model.captureTarget([row])), manager = model.manager
        var held = [target]
        for _ in 0..<7 { held.append(try XCTUnwrap(model.captureTarget([row]))) }
        XCTAssertNil(model.captureTarget([row])); XCTAssertEqual(model.issue?.code, "files.resourceLimit")
        model.discardTarget(held.removeLast()); XCTAssertNotNil(model.captureTarget([row]))
        var metadata = try XCTUnwrap(model.selectedHost); metadata.name = "display-only renamed"; metadata.isFavorite = true
        metadata.lastConnectedAt = Date(timeIntervalSince1970: 123)
        model.show(host: metadata)
        XCTAssertTrue(model.manager === manager); XCTAssertTrue(target.endpoint.contains("original local substitute"))
        XCTAssertFalse(target.endpoint.contains("display-only renamed"))
        model.rename(name: try FileName("renamed"), conflict: .fail, target: target); model.hide(); try await idle(model)
        let count = await service.mutations; XCTAssertEqual(count, 1)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("renamed")), Data("original".utf8))
        XCTAssertNil(model.issue)
    }
    func testRemoteSameNameReplacementBeforeConfirmNeverMutatesNewObject() async throws {
        let root = try root(), raw = try FileName(bytes: Data([255, 32, 65, 10]))
        let source = try RemotePath.root.appending(raw), service = try RawNameRemoteFileService(root: root, rawName: raw)
        addTeardownBlock { await service.close() }
        let exact = try FilesLocalPaths.rawPath(FilesLocalPaths.components(root)).appending(raw)
        XCTAssertEqual(try FilesLocalPaths.rawPath(FilesLocalPaths.components(FilesLocalPaths.url(exact))).bytes, exact.bytes)
        try await service.install(Data("original".utf8))
        let originalHandle = try await service.holdCurrent()
        let model = try await remote(root, services: [service]), target = try XCTUnwrap(model.captureTarget(model.entries))
        XCTAssertEqual(target.entries.first?.name.bytes, raw.bytes); XCTAssertEqual(target.path(for: model.entries[0]), source)
        try await service.replaceWithNewBacking(Data("replacement".utf8))
        model.rename(name: try FileName("wrong"), conflict: .fail, target: target); try await idle(model)
        let afterRename = await service.trace()
        XCTAssertEqual(afterRename.mutations, 0); XCTAssertEqual(model.issue?.code, "files.raceDetected")
        let originalBytes = try await service.readHeld(originalHandle), replacementBytes = try await service.readCurrent()
        XCTAssertEqual(originalBytes, Data("original".utf8)); XCTAssertEqual(replacementBytes, Data("replacement".utf8))
        model.browse(.root); try await idle(model)
        let deletion = try XCTUnwrap(model.captureTarget(model.entries))
        let replacedHandle = try await service.holdCurrent()
        try await service.replaceWithNewBacking(Data("another replacement".utf8))
        model.prepareDeleteBatch(deletion, removeLinkOnly: false); try await idle(model)
        XCTAssertNil(model.deleteBatchReview)
        let trace = await service.trace(), replacedBytes = try await service.readHeld(replacedHandle), newestBytes = try await service.readCurrent()
        XCTAssertEqual(trace.mutations, 0)
        XCTAssertEqual(replacedBytes, Data("replacement".utf8)); XCTAssertEqual(newestBytes, Data("another replacement".utf8))
        XCTAssertEqual(trace.listResponses, [[raw.bytes], [raw.bytes]])
        XCTAssertEqual(trace.lstatRequests, [RemotePath.root.bytes, RemotePath.root.bytes, source.bytes, RemotePath.root.bytes, RemotePath.root.bytes, source.bytes])
        XCTAssertEqual(trace.lstatRequests.filter { $0 == source.bytes }.count, 2, "Both stale operations consumed the exact raw source, never a rewritten display name")
    }
    func testRemoteRiskDeliverySuspendedAcrossHostSwitchCannotCommitOldRename() async throws {
        let root = try root(), gate = FilesOwnersGate(), service = try FilesOwnersService(root: root, remoteRisks: true)
        try Data("original".utf8).write(to: root.appendingPathComponent("same"))
        let model = try await remote(root, services: [service], riskGate: gate)
        let target = try XCTUnwrap(model.captureTarget([entry("same", model.entries)]))
        model.rename(name: try FileName("wrong"), conflict: .fail, target: target)
        try await boundary { await gate.hasArrived }
        model.show(host: HostConfiguration(name: "new", address: "another-never.invalid", username: "next"))
        await gate.release(); try await idle(model)
        await noMutations(service); XCTAssertNil(model.pendingRisk); XCTAssertNil(model.riskID)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("same")), Data("original".utf8))
    }
    func testRemoteLateDeletePlanAfterHostSwitchCannotPublishOrMutate() async throws {
        let root = try root(), gate = FilesOwnersGate(), service = try FilesOwnersService(root: root)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("tree"), withIntermediateDirectories: false)
        try Data("keep".utf8).write(to: root.appendingPathComponent("tree/keep"))
        let model = try await remote(root, services: [service])
        addTeardownBlock { await gate.release(); await model.closeForWindow() }
        let target = try XCTUnwrap(model.captureTarget([entry("tree", model.entries)]))
        await service.pauseNextList(gate); model.prepareDeleteBatch(target, removeLinkOnly: false)
        try await boundary { await gate.hasArrived }
        model.show(host: HostConfiguration(name: "new", address: "another-never.invalid", username: "next"))
        await gate.release(); try await idle(model)
        XCTAssertNil(model.deleteBatchReview); await noMutations(service)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("tree/keep")), Data("keep".utf8))
    }
    func testConfirmedRemotePartialDeleteSurvivesHideAndFailedRefreshWithTrueReport() async throws {
        let root = try root(), gate = FilesOwnersGate(), service = try FilesOwnersService(root: root)
        for name in ["first", "second"] { try Data(name.utf8).write(to: root.appendingPathComponent(name)) }
        let model = try await remote(root, services: [service])
        addTeardownBlock { await gate.release(); await model.closeForWindow() }
        model.prepareDeleteBatch(model.entries, removeLinkOnly: false); try await idle(model)
        let review = try XCTUnwrap(model.deleteBatchReview)
        XCTAssertTrue(review.review.target.endpoint.contains("original local substitute"))
        await service.configurePartialDelete(gate: gate)
        model.executeDeleteBatch(review); try await boundary { await gate.hasArrived }
        model.hide(); await gate.release(); try await idle(model)
        XCTAssertEqual(model.lastDeleteReports.count, 2)
        XCTAssertTrue(model.lastDeleteReports[0].allSucceeded); XCTAssertFalse(model.lastDeleteReports[1].allSucceeded)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("first").path))
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("second")), Data("second".utf8))
        XCTAssertTrue(model.readFailed); XCTAssertEqual(model.path, .root)
        let counts = await service.mutations
        model.executeDeleteBatch(review); try await idle(model)
        let after = await service.mutations; XCTAssertEqual(after, counts)
        XCTAssertEqual(model.lastDeleteReports.count, 2, "A late repeat must not erase a real partial report")
    }
    func testHistoryOwnerCancelBeforeSubmissionLeavesExactRecordsAndFiles() async throws {
        let root = try root(), service = try FilesOwnersService(root: root)
        try Data("keep".utf8).write(to: root.appendingPathComponent("file"))
        let model = try await remote(root, services: [service]), owner = FilesHistoryRemovalOwner()
        let id = try await completedDownload(model, root: root, name: "file")
        owner.prepare(using: model); let review = try XCTUnwrap(owner.review)
        XCTAssertEqual(review.jobs.map(\.id), [id]); XCTAssertNotNil(review.labels[id])
        owner.cancel(using: model); XCTAssertNil(owner.confirm(using: model)); XCTAssertNil(owner.review)
        let snapshot = await model.manager.snapshot(); XCTAssertTrue(snapshot.jobs.contains { $0.id == id })
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("file")), Data("keep".utf8))
    }
    func testHistoryViewOwnerRejectsDoubleConfirmAndOldCompletionCannotClearNewReview() async throws {
        let root = try root(), service = try FilesOwnersService(root: root), gate = FilesOwnersGate()
        for name in ["first", "second"] { try Data(name.utf8).write(to: root.appendingPathComponent(name)) }
        let model = try await remote(root, services: [service], historyGate: gate), owner = FilesHistoryRemovalOwner()
        let first = try await completedDownload(model, root: root, name: "first")
        owner.prepare(using: model); let old = try XCTUnwrap(owner.review)
        let submitted = try XCTUnwrap(owner.confirm(using: model))
        XCTAssertTrue(owner.isInFlight); XCTAssertNil(owner.confirm(using: model))
        try await boundary { await gate.hasArrived }
        owner.cancel(using: model)
        let second = try await completedDownload(model, root: root, name: "second")
        owner.prepare(using: model); let fresh = try XCTUnwrap(owner.review)
        XCTAssertNotEqual(old.id, fresh.id); XCTAssertEqual(Set(fresh.jobs.map(\.id)), [first, second])
        await gate.release(); try await boundary { !owner.inFlightIDs.contains(old.id) }
        let removed = await submitted.value; XCTAssertTrue(removed)
        XCTAssertEqual(owner.review?.id, fresh.id); XCTAssertFalse(owner.isInFlight)
        XCTAssertNotNil(old.labels[first], "Reviewed display survives removal of live labels")
        XCTAssertNil(model.transferLabels[first])
        let snapshot = await model.manager.snapshot()
        XCTAssertFalse(snapshot.jobs.contains { $0.id == first }); XCTAssertTrue(snapshot.jobs.contains { $0.id == second })
        owner.cancel(using: model); XCTAssertNil(owner.review)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("first")), Data("first".utf8))
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("second")), Data("second".utf8))
    }
}

private actor FilesOwnersGate {
    private(set) var hasArrived = false
    private var released = false
    private var pending: CheckedContinuation<Void, Error>?
    func suspend() async throws {
        hasArrived = true
        if released { return }
        let deadline = Task { try await Task.sleep(for: .seconds(5)); expire() }
        defer { deadline.cancel() }
        try await withCheckedThrowingContinuation { pending = $0 }
    }
    private func expire() {
        let reply = pending; pending = nil
        reply?.resume(throwing: FileServiceError(.timeout, operation: "files-owner-test-gate"))
    }
    func release() { released = true; let reply = pending; pending = nil; reply?.resume() }
}
private actor FilesOwnersReadGate {
    let gate: FilesOwnersGate
    private var count = 0
    init(gate: FilesOwnersGate) { self.gate = gate }
    func read() async throws { count += 1; if count == 2 { try await gate.suspend() } }
}
private actor FilesOwnersReadFault {
    private var first = true
    func read() throws { if first { first = false; throw FileServiceError(.permissionDenied, operation: "files-owner-first-read") } }
}
private actor FilesOwnersConnector: FilesConnecting {
    private var services: [any RemoteFileService]
    init(services: [any RemoteFileService]) { self.services = services }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        try token.check()
        guard await isCurrent(), !services.isEmpty else { throw FileServiceError(.closed, operation: "files-owner-local-substitute") }
        return services.removeFirst()
    }
}
/// Explicit logical remote namespace only: FF bytes are protocol names, never physical APFS names.
/// Contents/attributes/held handles use actual UUID-named temporary files via LocalFileService.
/// This is not real SFTP interoperability or proof that the local filesystem stores invalid UTF-8.
private actor RawNameRemoteFileService: RemoteFileService {
    struct Trace: Sendable {
        let listResponses: [[Data]]
        let lstatRequests: [Data]
        let mutations: Int
    }
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow,
        exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    private let base: LocalFileService
    private let rawName: FileName
    private let rawPath: RemotePath
    private var backing: RemotePath?
    private var rootAttributes: FileAttributes?
    private var listResponses: [[Data]] = []
    private var lstatRequests: [Data] = []
    private var mutations = 0
    init(root: URL, rawName: FileName) throws {
        let fd = try FilesLocalPaths.openDirectory(FilesLocalPaths.components(root))
        defer { Darwin.close(fd) }
        base = try LocalFileService(rootDirectoryDescriptor: fd)
        self.rawName = rawName; rawPath = try RemotePath.root.appending(rawName)
    }
    private func mapped(_ path: RemotePath) throws -> RemotePath {
        if path == .root { return .root }
        guard path == rawPath, let backing else {
            throw FileServiceError(.notFound, operation: "raw-namespace-unmapped", path: path)
        }
        return backing
    }
    /// Fixture setup deliberately bypasses protocol mutation counts; replacement preserves the
    /// logical parent while swapping an actual backing object, just as a remote namespace may.
    func install(_ data: Data) async throws {
        let next = try RemotePath.root.appending(FileName(UUID().uuidString)), token = CancellationToken()
        let handle = try await base.open(next, mode: .exclusiveWrite, token: token)
        do {
            var offset = 0
            while offset < data.count {
                let count = try await base.write(handle, data: Data(data.dropFirst(offset)), token: token)
                guard count > 0 else { throw FileServiceError(.io, operation: "raw-backing-write-stalled") }
                offset += count
            }
            try await base.finish(handle, token: token); try await base.closeHandle(handle)
            backing = next
            if rootAttributes == nil { rootAttributes = try await base.lstat(.root, token: token) }
        } catch { try? await base.closeHandle(handle); throw error }
    }
    func replaceWithNewBacking(_ data: Data) async throws { try await install(data) }
    func holdCurrent() async throws -> FileHandleID {
        try await base.open(mapped(rawPath), mode: .read, token: CancellationToken())
    }
    func readHeld(_ handle: FileHandleID) async throws -> Data {
        let token = CancellationToken()
        var result = Data()
        while true {
            let chunk = try await base.read(handle, maxBytes: 4096, token: token)
            if chunk.isEmpty { return result }
            result.append(chunk)
            guard result.count <= 65536 else { throw FileServiceError(.resourceLimit, operation: "raw-backing-read-bound") }
        }
    }
    func readCurrent() async throws -> Data {
        let handle = try await holdCurrent()
        do { let bytes = try await readHeld(handle); try await base.closeHandle(handle); return bytes }
        catch { try? await base.closeHandle(handle); throw error }
    }
    func trace() -> Trace { Trace(listResponses: listResponses, lstatRequests: lstatRequests, mutations: mutations) }
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try token.check(); return .root }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        try token.check()
        guard path == .root, let backing else { throw FileServiceError(.notFound, operation: "raw-namespace-list", path: path) }
        let attributes = try await base.lstat(backing, token: token)
        listResponses.append([rawName.bytes])
        return [DirectoryEntry(name: rawName, attributes: attributes)]
    }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes {
        try token.check(); lstatRequests.append(path.bytes)
        if path == .root, let rootAttributes { return rootAttributes }
        return try await base.lstat(mapped(path), token: token)
    }
    func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(handle, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(mapped(path), mode: mode, token: token) }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(handle, maxBytes: maxBytes, token: token) }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(handle, data: data, token: token) }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await base.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await base.closeHandle(handle) }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { mutations += 1; try await base.mkdir(mapped(path), token: token) }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws {
        mutations += 1; try await base.rename(mapped(source), to: mapped(destination), mode: mode, token: token)
    }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws {
        mutations += 1; try await base.commit(mapped(source), to: mapped(destination), request: request, token: token)
    }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { mutations += 1; try await base.remove(mapped(path), directory: directory, token: token) }
    nonisolated func cancel() { base.cancel() }
    func close() async { await base.close() }
}

private actor FilesOwnersService: RemoteFileService {
    nonisolated let capabilities: FileServiceCapabilities
    private let base: LocalFileService
    private var listGate: FilesOwnersGate?
    private var removeGate: FilesOwnersGate?
    private var partialDelete = false
    private var didRemove = false
    private(set) var mutations = 0
    init(root: URL, remoteRisks: Bool = false) throws {
        base = try LocalFileService(root: root)
        capabilities = .init(traversal: remoteRisks ? .remoteComponentLstat : .localDescriptorNoFollow,
            exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    }
    func pauseNextList(_ gate: FilesOwnersGate) { listGate = gate }
    func configurePartialDelete(gate: FilesOwnersGate) { partialDelete = true; removeGate = gate }
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        if let gate = listGate { listGate = nil; try await gate.suspend() }
        if partialDelete && didRemove { throw FileServiceError(.io, operation: "files-owner-refresh-after-partial") }
        return try await base.list(p, token: token)
    }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(p, token: token) }
    func fstat(_ h: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(h, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(h, maxBytes: maxBytes, token: token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { mutations += 1; try await base.mkdir(p, token: token) }
    func rename(_ s: RemotePath, to d: RemotePath, mode: RenameMode, token: CancellationToken) async throws { mutations += 1; try await base.rename(s, to: d, mode: mode, token: token) }
    func commit(_ s: RemotePath, to d: RemotePath, request: CommitRequest, token: CancellationToken) async throws { mutations += 1; try await base.commit(s, to: d, request: request, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws {
        mutations += 1
        if let gate = removeGate { removeGate = nil; try await gate.suspend() }
        if partialDelete && p == (try? RemotePath("/second")) { throw FileServiceError(.permissionDenied, operation: "files-owner-partial-delete", path: p) }
        try await base.remove(p, directory: directory, token: token); didRemove = true
    }
    nonisolated func cancel() {}
    func close() async { await base.close() }
}
import SwiftUI

/// Owned, never-fronted AppKit views and unique preference suites; not physical drag/GUI evidence.
@MainActor final class FilesLayoutPreferencesTests: XCTestCase {
    private func preferences() throws -> (String, UserDefaults) {
        let suite = "OpenLXSSH.Files.Layout.Tests." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        return (suite, defaults)
    }
    private func layout(_ width: Double, reversed: Bool = false) -> FilesTableLayout {
        let ids = reversed ? Array(FilesLayoutColumn.allCases.reversed()) : FilesLayoutColumn.allCases
        return .init(columns: ids.map { .init(id: $0, width: $0 == .name ? width : $0.defaultWidth) })
    }
    private func column(_ id: FilesLayoutColumn, in table: NSTableView) throws -> NSTableColumn {
        try XCTUnwrap(table.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier(id.rawValue)))
    }
    private func resize(_ column: NSTableColumn, in table: NSTableView, to width: Double) {
        let old = column.width; column.width = width
        NotificationCenter.default.post(name: NSTableView.columnDidResizeNotification, object: table,
            userInfo: ["NSTableColumn": column, "NSOldWidth": old])
    }
    private func split(defaults: UserDefaults?, width: CGFloat = 1000) -> FilesNativeSplitView<Color, Color> {
        let view = FilesNativeSplitView(left: Color.clear, right: Color.clear, defaults: defaults)
        view.setFrameSize(NSSize(width: width, height: 300)); view.adjustSubviews(); view.layoutSubtreeIfNeeded()
        return view
    }
    private func settle(_ window: NSWindow, until condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(3)
        repeat {
            window.contentView?.layoutSubtreeIfNeeded()
            if condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        } while ContinuousClock.now < deadline
        throw FileServiceError(.timeout, operation: "files-layout-owned-host-render")
    }

    func testLayoutSuitesRoundTripIndependentLocalAndRemoteWidthsAndOrder() throws {
        let (suite, defaults) = try preferences(), store = FilesLayoutPreferences(defaults: defaults)
        XCTAssertEqual(store.columns(.local), .standard); XCTAssertEqual(store.splitFraction(), 0.5)
        XCTAssertNil(defaults.persistentDomain(forName: suite), "A default layout read does not write")
        let local = layout(780, reversed: true), remote = layout(340)
        XCTAssertTrue(store.saveColumns(local, side: .local)); XCTAssertTrue(store.saveColumns(remote, side: .remote))
        XCTAssertTrue(store.saveSplitFraction(0.62))
        let reopened = FilesLayoutPreferences(defaults: try XCTUnwrap(UserDefaults(suiteName: suite)))
        XCTAssertEqual(reopened.columns(.local), local); XCTAssertEqual(reopened.columns(.remote), remote)
        XCTAssertEqual(reopened.splitFraction(), 0.62)
        XCTAssertEqual(Set(try XCTUnwrap(defaults.persistentDomain(forName: suite)).keys),
            Set([FilesLayoutPreferences.columnsKey(.local), FilesLayoutPreferences.columnsKey(.remote), FilesLayoutPreferences.splitKey]))
    }

    func testMalformedColumnsRecoverOnlyTheirKeyWithoutResettingOtherPreferences() throws {
        let (_, defaults) = try preferences(), store = FilesLayoutPreferences(defaults: defaults)
        let remote = layout(420, reversed: true)
        XCTAssertTrue(store.saveColumns(remote, side: .remote)); XCTAssertTrue(store.saveSplitFraction(0.6))
        defaults.set("sftp", forKey: "unrelated.workspace.selection")
        let ids = FilesLayoutColumn.allCases.map(\.rawValue)
        let widths: [String: Any] = Dictionary(uniqueKeysWithValues: FilesLayoutColumn.allCases.map { ($0.rawValue, $0.defaultWidth as Any) })
        var invalid: [Any] = ["not-layout", true, [], [:], ["order": [], "widths": widths],
            ["order": Array(ids.dropLast()), "widths": widths], ["order": ["name", "name", "size", "kind", "permissions"], "widths": widths],
            ["order": ["unknown", "modified", "size", "kind", "permissions"], "widths": widths],
            ["order": ids, "widths": ["name": 200]], ["order": ids, "widths": widths, "extra": 1]]
        for bad: Any in [true, "240", Double.nan, Double.infinity, -Double.infinity, -1.0, 54.0, 4097.0] {
            var changed = widths; changed["name"] = bad
            invalid.append(["order": ids, "widths": changed])
        }
        for bad in invalid {
            defaults.set(bad, forKey: FilesLayoutPreferences.columnsKey(.local))
            XCTAssertEqual(store.columns(.local), .standard)
            XCTAssertNil(defaults.object(forKey: FilesLayoutPreferences.columnsKey(.local)))
            XCTAssertEqual(store.columns(.remote), remote); XCTAssertEqual(store.splitFraction(), 0.6)
            XCTAssertEqual(defaults.string(forKey: "unrelated.workspace.selection"), "sftp")
        }
        XCTAssertFalse(store.saveColumns(.init(columns: [.init(id: .name, width: 240)]), side: .local))
    }

    func testMalformedSplitRecoversAndGeometryHandlesNonfiniteAndNarrowWidths() throws {
        let (_, defaults) = try preferences(), store = FilesLayoutPreferences(defaults: defaults)
        let local = layout(510); XCTAssertTrue(store.saveColumns(local, side: .local))
        for bad: Any in [true, "0.5", [0.5], ["fraction": 0.5], Double.nan, Double.infinity, -Double.infinity, -1.0, 0.0, 1.0, 20.0] {
            defaults.set(bad, forKey: FilesLayoutPreferences.splitKey)
            XCTAssertEqual(store.splitFraction(), 0.5); XCTAssertNil(defaults.object(forKey: FilesLayoutPreferences.splitKey))
            XCTAssertEqual(store.columns(.local), local)
        }
        for width in [0.0, 100.0, 599.0, 600.0, 900.0, 2400.0] {
            for fraction in [Double.nan, Double.infinity, -1, 0, 0.01, 0.5, 0.99, 1, 10] {
                let left = FilesSplitLayout.leftWidth(fraction: fraction, availableWidth: width)
                XCTAssertTrue(left.isFinite); XCTAssertGreaterThanOrEqual(left, min(300, width / 2))
                XCTAssertGreaterThanOrEqual(width - left, min(300, width / 2))
            }
        }
        XCTAssertEqual(FilesSplitLayout.leftWidth(fraction: 0.7, availableWidth: .infinity), 0)
        XCTAssertEqual(FilesSplitLayout.leftWidth(fraction: 0.7, availableWidth: .nan), 0)
        XCTAssertFalse(store.saveSplitFraction(.nan)); XCTAssertFalse(store.saveSplitFraction(1))
        XCTAssertEqual(FilesTableLayout.maximumWidth(onVisibleWidth: 480), 480)
        XCTAssertEqual(FilesTableLayout.maximumWidth(onVisibleWidth: .nan), 1440)
    }

    func testSerializationWhitelistAndNilIsolationUseNoImplicitNativeAutosave() throws {
        let (suite, defaults) = try preferences(), store = FilesLayoutPreferences(defaults: defaults)
        let fixtureName = "fixture-name-must-not-persist", fixturePath = "/fixture/path-must-not-persist", secret = "synthetic-not-a-real-secret"
        let rows = FilesLayoutRowsSource(entries: [DirectoryEntry(name: try FileName(fixtureName), attributes: .init(kind: .regular, size: 11))])
        let owned = FilesLayoutOwnedTable(defaults: defaults, side: .local)
        owned.table.dataSource = rows; owned.table.reloadData()
        resize(try column(.name, in: owned.table), in: owned.table, to: 640)
        XCTAssertTrue(store.saveColumns(layout(460, reversed: true), side: .remote)); XCTAssertTrue(store.saveSplitFraction(0.58))
        let domain = try XCTUnwrap(defaults.persistentDomain(forName: suite))
        let encoded = try PropertyListSerialization.data(fromPropertyList: domain, format: .xml, options: 0)
        let text = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        for forbidden in [fixtureName, fixturePath, secret, "sortDescriptor", "selected", "host", "filter"] { XCTAssertFalse(text.contains(forbidden)) }
        let nilStore = FilesLayoutPreferences(defaults: nil)
        XCTAssertFalse(nilStore.saveColumns(layout(700), side: .local)); XCTAssertFalse(nilStore.saveSplitFraction(0.7))
        let isolated = FilesLayoutOwnedTable(defaults: nil, side: .remote), isolatedSplit = split(defaults: nil)
        resize(try column(.name, in: isolated.table), in: isolated.table, to: 800); isolated.table.moveColumn(0, toColumn: 4)
        isolatedSplit.setPosition(550, ofDividerAt: 0)
        XCTAssertNil(isolated.table.autosaveName); XCTAssertFalse(isolated.table.autosaveTableColumns); XCTAssertNil(isolatedSplit.autosaveName)
        XCTAssertEqual(nilStore.columns(.remote), .standard); XCTAssertEqual(nilStore.splitFraction(), 0.5)
        XCTAssertEqual(try XCTUnwrap(defaults.persistentDomain(forName: suite)) as NSDictionary, domain as NSDictionary)
    }

    func testOwnedTablePublicResizeAndMoveNotificationsPersistEachSideIndependently() throws {
        let (_, defaults) = try preferences(), store = FilesLayoutPreferences(defaults: defaults)
        let local = FilesLayoutOwnedTable(defaults: defaults, side: .local), remote = FilesLayoutOwnedTable(defaults: defaults, side: .remote)
        resize(try column(.name, in: local.table), in: local.table, to: 720)
        local.table.moveColumn(0, toColumn: 3)
        resize(try column(.size, in: remote.table), in: remote.table, to: 180)
        remote.table.moveColumn(2, toColumn: 0)
        XCTAssertEqual(store.columns(.local).columns.map(\.id), [.modified, .size, .kind, .name, .permissions])
        XCTAssertEqual(store.columns(.remote).columns.map(\.id), [.size, .name, .modified, .kind, .permissions])
        XCTAssertEqual(store.columns(.local).columns.first { $0.id == .name }?.width, 720)
        XCTAssertEqual(store.columns(.remote).columns.first { $0.id == .name }?.width, 240)
        XCTAssertEqual(store.columns(.remote).columns.first { $0.id == .size }?.width, 180)
        let recreated = FilesLayoutOwnedTable(defaults: defaults, side: .local)
        XCTAssertEqual(recreated.table.tableColumns.map { $0.identifier.rawValue }, local.table.tableColumns.map { $0.identifier.rawValue })
        XCTAssertEqual(try column(.name, in: recreated.table).width, 720)
        let before = store.columns(.local), other = NSTableView()
        local.owner.tableViewColumnDidResize(Notification(name: NSTableView.columnDidResizeNotification, object: other))
        XCTAssertEqual(store.columns(.local), before, "A different table cannot write this owner's layout")
    }

    func testOwnedTableRestorationBoundsKeepMetadataSelectionSortAndHorizontalAccess() throws {
        let (_, defaults) = try preferences(), store = FilesLayoutPreferences(defaults: defaults)
        XCTAssertTrue(store.saveColumns(layout(4096, reversed: true), side: .local))
        let owned = FilesLayoutOwnedTable(defaults: defaults, side: .local)
        let raw = try FileName(bytes: Data([255, 65])), attrs = FileAttributes(kind: .regular, size: 123, permissions: 0o100600)
        let rows = FilesLayoutRowsSource(entries: [.init(name: raw, attributes: attrs), .init(name: try FileName("second"), attributes: .init(kind: .directory))])
        owned.table.dataSource = rows; owned.table.reloadData(); owned.table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
        let sort = NSSortDescriptor(key: "size", ascending: false); owned.table.sortDescriptors = [sort]
        let name = try column(.name, in: owned.table)
        XCTAssertEqual(name.width, 1440); XCTAssertEqual(name.minWidth, 55); XCTAssertEqual(name.maxWidth, 1440)
        resize(name, in: owned.table, to: 900); owned.table.moveColumn(0, toColumn: 2)
        owned.owner.configureColumns(in: owned.table); owned.owner.updateColumnBounds()
        XCTAssertEqual(rows.entries.first?.name.bytes, raw.bytes); XCTAssertEqual(rows.entries.first?.attributes, attrs)
        XCTAssertEqual(owned.table.selectedRowIndexes, IndexSet(integer: 1)); XCTAssertEqual(owned.table.sortDescriptors, [sort])
        XCTAssertTrue(owned.table.dataSource === rows); XCTAssertTrue(owned.table.delegate === owned.owner)
        XCTAssertEqual(owned.table.columnAutoresizingStyle, .noColumnAutoresizing)
        XCTAssertTrue(owned.scroll.hasHorizontalScroller); XCTAssertTrue(name.resizingMask.contains(.userResizingMask))
        owned.scroll.tile(); owned.table.tile()
        XCTAssertGreaterThan(owned.table.frame.width, owned.scroll.contentView.bounds.width)
        owned.scroll.contentView.scroll(to: NSPoint(x: 120, y: 0)); owned.scroll.reflectScrolledClipView(owned.scroll.contentView)
        XCTAssertGreaterThan(owned.scroll.contentView.bounds.minX, 0)
        XCTAssertEqual(owned.table.selectedRowIndexes, IndexSet(integer: 1)); XCTAssertEqual(owned.table.sortDescriptors, [sort])
    }

    func testOwnedSplitRestoresMinimaAndResizesWithinAvailableWidthWithoutWriting() throws {
        let (suite, defaults) = try preferences(), store = FilesLayoutPreferences(defaults: defaults)
        XCTAssertTrue(store.saveSplitFraction(0.02))
        let before = try XCTUnwrap(defaults.persistentDomain(forName: suite)), view = split(defaults: defaults)
        XCTAssertTrue(view.isVertical); XCTAssertEqual(view.dividerStyle, .paneSplitter); XCTAssertNil(view.autosaveName)
        XCTAssertEqual(view.leftHost.frame.width, 300, accuracy: 0.5)
        for width: CGFloat in [400, 600, 607, 920, 1600, 0, 1000] {
            view.setFrameSize(NSSize(width: width, height: 240)); view.layoutSubtreeIfNeeded()
            let available = max(0, width - view.dividerThickness), minimum = min(300, available / 2)
            XCTAssertGreaterThanOrEqual(view.leftHost.frame.width + 0.5, minimum)
            XCTAssertGreaterThanOrEqual(view.rightHost.frame.width + 0.5, minimum)
            XCTAssertEqual(view.leftHost.frame.width + view.rightHost.frame.width + min(width, view.dividerThickness), width, accuracy: 0.5)
            XCTAssertGreaterThanOrEqual(view.rightHost.frame.minX, 0); XCTAssertLessThanOrEqual(view.rightHost.frame.maxX, width + 0.5)
        }
        XCTAssertEqual(store.splitFraction(), 0.02, "Temporary small geometry does not overwrite the preferred ratio")
        XCTAssertEqual(try XCTUnwrap(defaults.persistentDomain(forName: suite)) as NSDictionary, before as NSDictionary)
    }

    func testOwnedSplitPublicDividerPositionPersistsClampsAndRestoresAcrossInstances() throws {
        let (_, defaults) = try preferences(), store = FilesLayoutPreferences(defaults: defaults), view = split(defaults: defaults)
        let available = view.bounds.width - view.dividerThickness
        view.setPosition(available * 0.63, ofDividerAt: 0)
        XCTAssertEqual(store.splitFraction(), Double(view.leftHost.frame.width / available), accuracy: 0.001)
        let fraction = store.splitFraction(); XCTAssertEqual(fraction, 0.63, accuracy: 0.002)
        view.update(left: Color.red, right: Color.blue)
        XCTAssertEqual(store.splitFraction(), fraction)
        let recreated = split(defaults: defaults)
        XCTAssertEqual(recreated.leftHost.frame.width, view.leftHost.frame.width, accuracy: 1)
        view.setPosition(-5000, ofDividerAt: 0); XCTAssertEqual(view.leftHost.frame.width, 300, accuracy: 1)
        view.setPosition(5000, ofDividerAt: 0); XCTAssertEqual(view.rightHost.frame.width, 300, accuracy: 1)
        XCTAssertFalse(view.splitView(view, canCollapseSubview: view.leftHost))
        XCTAssertFalse(view.splitView(view, shouldHideDividerAt: 0))
    }

    func testStableHostingValueUpdatesRetainSwiftUIStateAndReleaseOwnedHosts() async throws {
        _ = NSApplication.shared
        let leftID = UUID(), rightID = UUID()
        var leftReports: [(UUID, Int)] = [], rightReports: [(UUID, Int)] = []
        var view: FilesNativeSplitView<FilesLayoutStatePane, FilesLayoutStatePane>? = FilesNativeSplitView(
            left: .init(seed: leftID, revision: 0) { leftReports.append(($0, $1)) },
            right: .init(seed: rightID, revision: 0) { rightReports.append(($0, $1)) }, defaults: nil)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 260), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.contentView = nil; window.close() }
        window.contentView = view
        weak var leftHost = view?.leftHost
        weak var rightHost = view?.rightHost
        try await settle(window) { !leftReports.isEmpty && !rightReports.isEmpty }
        XCTAssertEqual(leftReports.last?.0, leftID); XCTAssertEqual(rightReports.last?.0, rightID)
        view?.update(left: .init(seed: UUID(), revision: 1) { leftReports.append(($0, $1)) },
                     right: .init(seed: UUID(), revision: 1) { rightReports.append(($0, $1)) })
        try await settle(window) { leftReports.last?.1 == 1 && rightReports.last?.1 == 1 }
        XCTAssertEqual(leftReports.last?.0, leftID, "The existing @State survives a rootView value update")
        XCTAssertEqual(rightReports.last?.0, rightID)
        XCTAssertTrue(leftHost === view?.leftHost); XCTAssertTrue(rightHost === view?.rightHost)
        XCTAssertFalse(window.isVisible, "The owned rendering fixture must never order a window front")
        window.contentView = nil; view = nil
        try await settle(window) { leftHost == nil && rightHost == nil }
        XCTAssertNil(leftHost); XCTAssertNil(rightHost)
        leftHost = nil; rightHost = nil
    }

    func testLayoutRestorationDoesNotReadNavigateCancelOrReinstateHiddenInput() async throws {
        let (_, defaults) = try preferences(), reads = DualPaneReadCounter(), gate = DualPaneInitialDirectoryGate()
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-Layout-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let local = LocalBrowserModel(root: root, beforeList: { await reads.read() })
        let service = try DualPaneInitialDirectoryService(root: root) { _ in await gate.suspend(); return .root }
        let files = FilesController(connector: DualPaneInitialDirectoryConnector(services: [service]), idleTimeout: nil, localBrowserRoot: root)
        addTeardownBlock { await gate.release(); await files.closeForWindow(); await local.close(); try FileManager.default.removeItem(at: root) }
        files.show(host: HostConfiguration(name: "layout local substitute", address: "never-connected.invalid", username: "fixture"))
        await files.waitUntilCurrentWorkCompletes()
        files.connect(.init(primary: .manual(.init(utf8: "")))); await gate.waitForArrival()
        let input = FilesInitialInputOwner()
        input.update(.init(visible: true, host: files.selectedHost, keys: [], epoch: files.initialInputEpoch))
        input.secret = UUID().uuidString; input.useTemporaryCredential = true
        let hidden = FilesInitialInputOwner.Context(visible: false, host: files.selectedHost, keys: [], epoch: files.initialInputEpoch)
        input.update(hidden)
        let owned = FilesLayoutOwnedTable(defaults: defaults, side: .remote), view = split(defaults: defaults)
        resize(try column(.name, in: owned.table), in: owned.table, to: 650); view.setPosition(600, ofDividerAt: 0)
        _ = FilesLayoutPreferences(defaults: defaults).columns(.remote)
        XCTAssertEqual(files.state, .preparing); XCTAssertNil(local.path); XCTAssertTrue(local.entries.isEmpty)
        let readCount = await reads.count, closeCount = await service.closes
        XCTAssertEqual(readCount, 0); XCTAssertEqual(closeCount, 0)
        XCTAssertTrue(input.secret.isEmpty); XCTAssertFalse(input.useTemporaryCredential); XCTAssertNil(input.take(for: hidden))
        await gate.release(); await files.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(files.state, .ready); XCTAssertTrue(files.transferSnapshot.jobs.isEmpty)
        XCTAssertTrue(input.secret.isEmpty); XCTAssertEqual(files.navigationHistory.paths, [.root])
    }
}

@MainActor private final class FilesLayoutOwnedTable {
    let owner: FilesTableLayoutOwner
    let table = NSTableView()
    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 320, height: 180))
    init(defaults: UserDefaults?, side: FilesLayoutSide) {
        owner = FilesTableLayoutOwner(defaults: defaults, side: side)
        scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true; scroll.autohidesScrollers = true
        owner.configureColumns(in: table)
        table.allowsMultipleSelection = true; table.allowsEmptySelection = true
        scroll.documentView = table
        scroll.tile(); table.tile()
    }
}
@MainActor private final class FilesLayoutRowsSource: NSObject, NSTableViewDataSource {
    let entries: [DirectoryEntry]
    init(entries: [DirectoryEntry]) { self.entries = entries }
    func numberOfRows(in tableView: NSTableView) -> Int { entries.count }
}
private struct FilesLayoutStatePane: View {
    @State private var token: UUID
    let revision: Int
    let report: @MainActor (UUID, Int) -> Void
    init(seed: UUID, revision: Int, report: @escaping @MainActor (UUID, Int) -> Void) {
        _token = State(initialValue: seed); self.revision = revision; self.report = report
    }
    var body: some View {
        Color.clear.onAppear { report(token, revision) }.onChange(of: revision) { _, value in report(token, value) }
    }
}

// Uses the existing logical raw-name service backed by real UUID-named files. This is not a
// physical invalid-UTF8 APFS filename or real SFTP claim, and the original 44 tests stay intact.
@MainActor final class FilesTransferPlanRawAppTests: XCTestCase {
    func testRawDirectoryDownloadReviewPreservesInvalidUTF8RootAndCancelIsZeroMutation() async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-PlanRaw-" + UUID().uuidString)
        let remote = root.appendingPathComponent("remote"), target = root.appendingPathComponent("target")
        try FileManager.default.createDirectory(at: remote, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        let raw = try FileName(bytes: Data([255, 32, 65, 10])), backing = try RawNameRemoteFileService(root: remote, rawName: raw)
        try await backing.install(Data("backing".utf8))
        let service = FilesPlanRawTreeService(base: backing)
        let model = FilesController(connector: FilesPlanRawConnector(service: service), idleTimeout: nil)
        addTeardownBlock { await model.closeForWindow(); try FileManager.default.removeItem(at: root) }
        model.show(host: HostConfiguration(name: "logical raw, not SSH", address: "never-connected.invalid", username: "fixture"))
        await model.waitUntilCurrentWorkCompletes(); model.connect(.init(primary: .manual(.init(utf8: ""))))
        await model.waitUntilCurrentWorkCompletes(); XCTAssertEqual(model.state, .ready)
        let context = try model.transferContext(upload: false)
        let prepared = try await model.enqueueDownloads(model.entries, to: target, context: context).value
        XCTAssertTrue(prepared.isEmpty)
        let review = try XCTUnwrap(model.transferPlanReview)
        XCTAssertTrue(review.canConfirm)
        XCTAssertTrue(review.plan.requests[0].sourceManifest?.entries.contains { $0.path.name?.bytes == raw.bytes } == true)
        let before = await backing.trace(); XCTAssertEqual(before.mutations, 0)
        let snapshot = await model.manager.snapshot(); XCTAssertTrue(snapshot.jobs.isEmpty)
        model.cancelTransferPlan(ownerID: review.id); await model.waitUntilTransferPlanDrained()
        model.browse(.root); await model.waitUntilCurrentWorkCompletes()
        XCTAssertThrowsError(try model.enqueueDownloads(model.entries, to: target, context: context))
        let after = await backing.trace(); XCTAssertEqual(after.mutations, 0)
        XCTAssertTrue(after.lstatRequests.contains(try RemotePath.root.appending(raw).bytes))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: target.path).isEmpty)
    }
}
private actor FilesPlanRawTreeService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .localDescriptorNoFollow, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: RawNameRemoteFileService
    private let tree = try! RemotePath("/tree")
    private let directory = FileAttributes(kind: .directory, permissions: 0o700, modifiedSeconds: 1, identity: "logical-tree")
    init(base: RawNameRemoteFileService) { self.base = base }
    private func mapped(_ path: RemotePath) throws -> RemotePath {
        let components = try FilesLocalPaths.components(path)
        guard components.first == (try? FileName("tree")) else { throw FileServiceError(.notFound, operation: "raw-tree-boundary") }
        return try components.dropFirst().reduce(RemotePath.root) { try $0.appending($1) }
    }
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try token.check(); return .root }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        if path == .root { return [DirectoryEntry(name: try FileName("tree"), attributes: directory)] }
        return try await base.list(mapped(path), token: token)
    }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes {
        try token.check(); if path == .root || path == tree { return directory }
        return try await base.lstat(mapped(path), token: token)
    }
    func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(handle, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(mapped(path), mode: mode, token: token) }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(handle, maxBytes: maxBytes, token: token) }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(handle, data: data, token: token) }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { try await base.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws { try await base.closeHandle(handle) }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { try await base.mkdir(mapped(path), token: token) }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(mapped(source), to: mapped(destination), mode: mode, token: token) }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await base.commit(mapped(source), to: mapped(destination), request: request, token: token) }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(mapped(path), directory: directory, token: token) }
    nonisolated func cancel() {}
    func close() async { await base.close() }
}
private actor FilesPlanRawConnector: FilesConnecting {
    let service: any RemoteFileService
    init(service: any RemoteFileService) { self.service = service }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken, trust: @escaping FileHostTrustHandler,
                 keyboard: @escaping FilesKeyboardHandler, isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        try token.check(); return service
    }
}

@MainActor final class FilesPlanPanelHeightTests: XCTestCase {
    private func fixture(issue: Bool) async throws -> FilesController {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-PlanHeight-" + UUID().uuidString)
        let source = root.appendingPathComponent("source"), target = root.appendingPathComponent("target")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        let service = try LocalFileService(root: target)
        let model = FilesController(connector: FilesPlanRawConnector(service: service), idleTimeout: nil)
        addTeardownBlock { await model.closeForWindow(); try FileManager.default.removeItem(at: root) }
        model.show(host: HostConfiguration(name: "owned panel fixture", address: String(repeating: "long-endpoint-", count: 16) + ".invalid", username: "fixture"))
        await model.waitUntilCurrentWorkCompletes(); model.connect(.init(primary: .manual(.init(utf8: ""))))
        await model.waitUntilCurrentWorkCompletes(); XCTAssertEqual(model.state, .ready)
        var urls: [URL] = []
        for index in 0..<6 {
            let url = source.appendingPathComponent("root-\(index)-" + String(repeating: "long-name-", count: 18))
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
            if issue { try FileManager.default.createSymbolicLink(atPath: url.appendingPathComponent("rejected-" + String(repeating: "link-", count: 35)).path, withDestinationPath: ".") }
            urls.append(url)
        }
        let result = try await model.enqueueUploads(urls, context: model.transferContext(upload: true)).value
        XCTAssertTrue(result.isEmpty)
        let review = try XCTUnwrap(model.transferPlanReview)
        XCTAssertEqual(review.plan.requests.count, 6); XCTAssertEqual(review.canConfirm, !issue)
        if issue { XCTAssertEqual(review.plan.issues.count, 6) }
        return model
    }
    private func verify(model: FilesController, expanded: Bool, issue: Bool) async throws {
        _ = NSApplication.shared
        let window = NSWindow(contentRect: NSRect(x: 50, y: 50, width: 920, height: 580), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 920, height: 580))
        var observedFrames: [String: CGRect] = [:]
        let controller = NSHostingController(rootView: FilesTransferPlanPanel(model: model, initiallyExpanded: expanded) { observedFrames = $0 })
        let panel = controller.view
        panel.translatesAutoresizingMaskIntoConstraints = false
        // Use the product's exact native split host, without pretending these empty contents
        // cover the full local/remote browser page, App root or task UI.
        let split = FilesNativeSplitView(left: Color.clear, right: Color.clear, defaults: nil)
        split.translatesAutoresizingMaskIntoConstraints = false
        let tasks = NSView(); tasks.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(panel); container.addSubview(split); container.addSubview(tasks)
        window.contentView = container
        defer { window.contentView = nil; window.close() }
        NSLayoutConstraint.activate([
            panel.leadingAnchor.constraint(equalTo: container.leadingAnchor), panel.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            panel.topAnchor.constraint(equalTo: container.topAnchor, constant: 49),
            split.leadingAnchor.constraint(equalTo: container.leadingAnchor), split.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            split.topAnchor.constraint(equalTo: panel.bottomAnchor),
            tasks.leadingAnchor.constraint(equalTo: container.leadingAnchor), tasks.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            tasks.topAnchor.constraint(equalTo: split.bottomAnchor), tasks.heightAnchor.constraint(equalToConstant: 250),
            tasks.bottomAnchor.constraint(equalTo: container.bottomAnchor)
        ])
        let height = panel.heightAnchor.constraint(equalToConstant: 250); height.isActive = true
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        repeat {
            container.layoutSubtreeIfNeeded(); panel.layoutSubtreeIfNeeded()
            height.constant = controller.sizeThatFits(in: NSSize(width: 920, height: 580)).height
            container.layoutSubtreeIfNeeded(); panel.layoutSubtreeIfNeeded(); split.layoutSubtreeIfNeeded()
            if observedFrames["summary"] != nil && observedFrames["cancel"] != nil && observedFrames["confirm"] != nil { break }
            try await Task.sleep(for: .milliseconds(10))
        } while ContinuousClock.now < deadline
        print("PLAN_PANEL_MEASURE expanded=\(expanded) issue=\(issue) fitting=\(panel.fittingSize) panel=\(panel.frame) split=\(split.frame) regions=\(observedFrames)")
        XCTAssertEqual(container.bounds.size, NSSize(width: 920, height: 580))
        XCTAssertFalse(window.isVisible)
        XCTAssertLessThanOrEqual(panel.frame.height, 180, "Inline plan must leave a usable split viewport with the 250-point task reservation")
        XCTAssertGreaterThanOrEqual(split.frame.height, 100)
        XCTAssertGreaterThanOrEqual(split.leftHost.frame.height, 100); XCTAssertGreaterThanOrEqual(split.rightHost.frame.height, 100)
        let panelScreen = window.convertToScreen(panel.convert(panel.bounds, to: nil))
        let contentScreen = window.convertToScreen(container.convert(container.bounds, to: nil))
        for id in ["summary", "cancel", "confirm"] {
            let frame = try XCTUnwrap(observedFrames[id], "Actual SwiftUI layout region \(id) must exist")
            XCTAssertGreaterThan(frame.width, 0); XCTAssertGreaterThan(frame.height, 0)
            XCTAssertTrue(panel.bounds.insetBy(dx: -1, dy: -1).contains(frame), "\(id) must remain inside the actual panel: \(frame) / \(panel.bounds)")
            XCTAssertTrue(panelScreen.width <= contentScreen.width && panelScreen.height <= contentScreen.height)
            XCTAssertTrue(container.bounds.contains(panel.convert(frame, to: container)), "\(id) must remain inside the 580-point owned content")
        }
        let viewport = try XCTUnwrap(observedFrames["detailsViewport"])
        XCTAssertGreaterThan(viewport.height, 0); XCTAssertLessThanOrEqual(viewport.height, 80)
        XCTAssertTrue(panel.bounds.contains(viewport))
        let content = try XCTUnwrap(observedFrames["detailsContent"])
        if expanded { XCTAssertGreaterThan(content.height, viewport.height, "Long roots/issues must scroll instead of growing the panel") }
    }
    func testActualPanelCollapsedAndExpandedLongRootsKeepsSummaryAndActionsIn580Window() async throws {
        let model = try await fixture(issue: false)
        try await verify(model: model, expanded: false, issue: false)
        try await verify(model: model, expanded: true, issue: false)
        XCTAssertEqual(model.transferPlanPhase, .ready)
        XCTAssertTrue(model.transferSnapshot.jobs.isEmpty)
    }
    func testActualPanelExpandedLongIssuesIsBoundedWithDisabledConfirmationAndNoJobs() async throws {
        let model = try await fixture(issue: true)
        try await verify(model: model, expanded: false, issue: true)
        try await verify(model: model, expanded: true, issue: true)
        XCTAssertFalse(try XCTUnwrap(model.transferPlanReview).canConfirm)
        XCTAssertTrue(model.transferSnapshot.jobs.isEmpty)
    }
}

