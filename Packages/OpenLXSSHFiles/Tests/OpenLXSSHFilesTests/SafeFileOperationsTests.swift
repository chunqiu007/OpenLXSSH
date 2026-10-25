import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

private final class OperationFixture: @unchecked Sendable {
    let root: URL
    let service: LocalFileService
    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSHFiles-ops-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        service = try LocalFileService(root: root)
    }
    func put(_ relative: String, _ text: String = UUID().uuidString) throws {
        try Data(text.utf8).write(to: root.appendingPathComponent(relative))
    }
    func cleanup() async { await service.close(); try? FileManager.default.removeItem(at: root) }
}
final class SafeFileOperationsTests: XCTestCase, @unchecked Sendable {
    private func confirm(_ plan: DeletePlan, _ ops: SafeFileOperations) async throws -> DeleteConfirmation {
        try await ops.confirmDelete(plan, displayedRoot: plan.root, displayedItemCount: plan.items.count, acknowledgedRisks: plan.risks)
    }
    func testRenameConflictSkipAlternateAndExplicitOverwrite() async throws {
        let f = try OperationFixture(); try f.put("source", "new"); try f.put("target", "original")
        let ops = SafeFileOperations(service: f.service, hostID: "local")
        let conflict = try await ops.rename(RemotePath("/source"), to: FileName("target"), token: CancellationToken())
        guard case .failed(let e) = conflict.state else { return XCTFail("conflict expected") }; XCTAssertEqual(e.kind, .conflict)
        let skip = try await ops.rename(RemotePath("/source"), to: FileName("target"), conflict: .skip, token: CancellationToken())
        XCTAssertEqual(skip.state, .skipped)
        let renamed = try await ops.rename(RemotePath("/source"), to: FileName("target"), conflict: .renameTo(FileName("中文 '$ renamed")), token: CancellationToken())
        XCTAssertEqual(renamed.state, .succeeded); XCTAssertEqual(renamed.destination, try RemotePath("/中文 '$ renamed"))
        let rejected = try await ops.rename(RemotePath("/中文 '$ renamed"), to: FileName("target"), conflict: .overwrite, token: CancellationToken())
        guard case .failed(let refusal) = rejected.state else { return XCTFail("risk required") }; XCTAssertEqual(refusal.kind, .riskRejected)
        let overwritten = try await ops.rename(RemotePath("/中文 '$ renamed"), to: FileName("target"), conflict: .overwrite,
            policy: TransferPolicy(confirmRisk: { _ in true }), token: CancellationToken())
        XCTAssertEqual(overwritten.state, .succeeded)
        XCTAssertEqual(try String(contentsOf: f.root.appendingPathComponent("target"), encoding: .utf8), "new")
        await f.cleanup()
    }
    func testTransferRenameToDoesNotOverwriteAndTreeOnlyRenamesTopLevel() async throws {
        let f = try OperationFixture()
        try FileManager.default.createDirectory(at: f.root.appendingPathComponent("source"), withIntermediateDirectories: false)
        try f.put("source/child", "content"); try f.put("occupied", "original")
        let engine = SafeTransferEngine()
        let copied = try await engine.copy(hostID: "local", source: f.service, sourcePath: RemotePath("/source/child"),
            destination: f.service, destinationPath: RemotePath("/occupied"), conflict: .renameTo(FileName("alternate")), token: CancellationToken())
        XCTAssertTrue(copied.allSucceeded); XCTAssertEqual(copied.items.first?.destination, try RemotePath("/alternate"))
        let conflict = try await engine.copy(hostID: "local", source: f.service, sourcePath: RemotePath("/source/child"),
            destination: f.service, destinationPath: RemotePath("/occupied"), conflict: .renameTo(FileName("alternate")), token: CancellationToken())
        guard case .failed(let e)? = conflict.items.first?.state else { return XCTFail("conflict") }; XCTAssertEqual(e.kind, .conflict)
        let tree = try await engine.copyTree(hostID: "local", source: f.service, sourcePath: RemotePath("/source"),
            destination: f.service, destinationPath: RemotePath("/unused"), conflict: .renameTo(FileName("tree-renamed")), token: CancellationToken())
        XCTAssertTrue(tree.allSucceeded)
        XCTAssertEqual(try String(contentsOf: f.root.appendingPathComponent("tree-renamed/child"), encoding: .utf8), "content")
        XCTAssertEqual(try String(contentsOf: f.root.appendingPathComponent("occupied"), encoding: .utf8), "original")
        await f.cleanup()
    }
    func testPrepareDoesNotDeleteAndWrongConfirmationCannotAuthorize() async throws {
        let f = try OperationFixture(); try f.put("file", "preserve")
        let ops = SafeFileOperations(service: f.service, hostID: "local")
        let plan = try await ops.prepareDelete(RemotePath("/file"), token: CancellationToken())
        XCTAssertTrue(plan.canExecute); XCTAssertEqual(plan.items.count, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.root.appendingPathComponent("file").path))
        do { _ = try await ops.confirmDelete(plan, displayedRoot: plan.root, displayedItemCount: 2, acknowledgedRisks: plan.risks); XCTFail("wrong count") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .riskRejected) }
        do { _ = try await ops.confirmDelete(plan, displayedRoot: plan.root, displayedItemCount: 1, acknowledgedRisks: []); XCTFail("missing risks") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .riskRejected) }
        await ops.discardDeletePlan(plan)
        do { _ = try await confirm(plan, ops); XCTFail("discarded") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .riskRejected) }
        XCTAssertEqual(try String(contentsOf: f.root.appendingPathComponent("file"), encoding: .utf8), "preserve")
        await f.cleanup()
    }
    func testRecursiveDeleteExactPostorderWithLinkOnlyNeverFollowsOutside() async throws {
        let f = try OperationFixture()
        try FileManager.default.createDirectory(at: f.root.appendingPathComponent("tree/子 folder"), withIntermediateDirectories: true)
        try f.put("tree/子 folder/中文 $'\n", "inside"); try f.put("outside", "must-survive")
        XCTAssertEqual(symlink("../../outside", f.root.appendingPathComponent("tree/子 folder/link").path), 0)
        XCTAssertEqual(symlink("..", f.root.appendingPathComponent("tree/cycle").path), 0)
        let ops = SafeFileOperations(service: f.service, hostID: "local")
        let rejected = try await ops.prepareDelete(RemotePath("/tree"), links: .reject, token: CancellationToken())
        XCTAssertFalse(rejected.canExecute); XCTAssertTrue(rejected.issues.contains { $0.error.kind == .symbolicLink })
        do { _ = try await confirm(rejected, ops); XCTFail("link reject") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .riskRejected) }
        let plan = try await ops.prepareDelete(RemotePath("/tree"), links: .removeLinkOnly, token: CancellationToken())
        XCTAssertTrue(plan.canExecute); XCTAssertEqual(plan.items.last?.path, try RemotePath("/tree"))
        XCTAssertEqual(plan.items.filter { $0.action == .removeSymbolicLink }.count, 2)
        let confirmation = try await confirm(plan, ops)
        let result = try await ops.executeDelete(plan, confirmation: confirmation, token: CancellationToken())
        XCTAssertTrue(result.allSucceeded); XCTAssertEqual(result.items.count, plan.items.count)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.root.appendingPathComponent("tree").path))
        XCTAssertEqual(try String(contentsOf: f.root.appendingPathComponent("outside"), encoding: .utf8), "must-survive")
        do { _ = try await ops.executeDelete(plan, confirmation: confirmation, token: CancellationToken()); XCTFail("one use") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .riskRejected) }
        await f.cleanup()
    }
    func testNewUnplannedChildPreventsAnyDeleteAndNeverExpandsConfirmedScope() async throws {
        let f = try OperationFixture()
        try FileManager.default.createDirectory(at: f.root.appendingPathComponent("tree"), withIntermediateDirectories: false)
        try f.put("tree/original", "old")
        let ops = SafeFileOperations(service: f.service, hostID: "local")
        let plan = try await ops.prepareDelete(RemotePath("/tree"), token: CancellationToken())
        let confirmation = try await confirm(plan, ops); try f.put("tree/newcomer", "unknown")
        let result = try await ops.executeDelete(plan, confirmation: confirmation, token: CancellationToken())
        XCTAssertFalse(result.allSucceeded)
        XCTAssertTrue(result.items.allSatisfy { if case .notAttempted = $0.state { return true }; return false })
        XCTAssertFalse(result.items.contains { $0.path == (try? RemotePath("/tree/newcomer")) })
        XCTAssertEqual(try String(contentsOf: f.root.appendingPathComponent("tree/original"), encoding: .utf8), "old")
        XCTAssertEqual(try String(contentsOf: f.root.appendingPathComponent("tree/newcomer"), encoding: .utf8), "unknown")
        await f.cleanup()
    }
    func testEqualLengthChangedFileDetectedBeforeDeletion() async throws {
        let f = try OperationFixture(); try f.put("file", "before")
        let ops = SafeFileOperations(service: f.service, hostID: "local")
        let plan = try await ops.prepareDelete(RemotePath("/file"), token: CancellationToken())
        let confirmation = try await confirm(plan, ops); try f.put("file", "racing")
        let result = try await ops.executeDelete(plan, confirmation: confirmation, token: CancellationToken())
        XCTAssertFalse(result.allSucceeded)
        XCTAssertEqual(try String(contentsOf: f.root.appendingPathComponent("file"), encoding: .utf8), "racing")
        await f.cleanup()
    }
    func testRootBoundsPermissionAndCancellationProduceNoExecutablePlan() async throws {
        let f = try OperationFixture()
        try FileManager.default.createDirectory(at: f.root.appendingPathComponent("tree/deep"), withIntermediateDirectories: true)
        try f.put("tree/deep/file")
        let ops = SafeFileOperations(service: f.service, hostID: "local", maxDepth: 0, maxItems: 2)
        do { _ = try await ops.prepareDelete(.root, token: CancellationToken()); XCTFail("host root") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .invalidPath) }
        let bounded = try await ops.prepareDelete(RemotePath("/tree"), token: CancellationToken())
        XCTAssertFalse(bounded.canExecute); XCTAssertTrue(bounded.issues.contains { $0.error.kind == .resourceLimit })
        let token = CancellationToken(); token.cancel()
        do { _ = try await ops.prepareDelete(RemotePath("/tree"), token: token); XCTFail("cancel") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .cancelled) }
        let locked = f.root.appendingPathComponent("tree/deep"); XCTAssertEqual(chmod(locked.path, 0), 0)
        let permissions = SafeFileOperations(service: f.service, hostID: "local")
        let denied = try await permissions.prepareDelete(RemotePath("/tree"), token: CancellationToken())
        XCTAssertEqual(chmod(locked.path, 0o700), 0)
        XCTAssertFalse(denied.canExecute); XCTAssertTrue(denied.issues.contains { $0.error.kind == .permissionDenied })
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.root.appendingPathComponent("tree/deep/file").path))
        await f.cleanup()
    }
    func testCopyTreeIntoItselfIsRejectedBeforeCreatingDestination() async throws {
        let f = try OperationFixture()
        try FileManager.default.createDirectory(at: f.root.appendingPathComponent("tree"), withIntermediateDirectories: false)
        try f.put("tree/file", "original")
        do {
            _ = try await SafeTransferEngine().copyTree(hostID: "local", source: f.service, sourcePath: RemotePath("/tree"),
                destination: f.service, destinationPath: RemotePath("/tree/child"), token: CancellationToken())
            XCTFail("cannot recurse into own destination")
        } catch let e as FileServiceError { XCTAssertEqual(e.kind, .invalidPath) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.root.appendingPathComponent("tree/child").path))
        await f.cleanup()
    }
    func testCancelledExecutionLeavesAllOriginals() async throws {
        let f = try OperationFixture(); try f.put("file", "preserve")
        let ops = SafeFileOperations(service: f.service, hostID: "local")
        let plan = try await ops.prepareDelete(RemotePath("/file"), token: CancellationToken())
        let confirmation = try await confirm(plan, ops); let token = CancellationToken(); token.cancel()
        do { _ = try await ops.executeDelete(plan, confirmation: confirmation, token: token); XCTFail("cancel") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .cancelled) }
        XCTAssertEqual(try String(contentsOf: f.root.appendingPathComponent("file"), encoding: .utf8), "preserve")
        await f.cleanup()
    }
}
