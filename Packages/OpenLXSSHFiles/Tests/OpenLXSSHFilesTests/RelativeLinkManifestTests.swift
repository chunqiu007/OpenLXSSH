import Foundation
import XCTest
@testable import OpenLXSSHFiles

final class RelativeLinkManifestTests: XCTestCase, @unchecked Sendable {
    private struct Fixture {
        let root: URL
        let service: LocalFileService
        let request: TransferRequest

        func scan(preserve: Bool = true, capturedTarget: Data? = nil) async throws -> TransferSourceManifest {
            var scan = TransferManifestScan(maxEntries: 100, maxDepth: 8, maxBytes: 64 * 1024)
            scan.preserveRelativeLinks = preserve
            try await scan.run(service, request: request, token: CancellationToken())
            if let capturedTarget {
                let index = try XCTUnwrap(scan.entries.firstIndex { $0.linkTarget != nil })
                let original = scan.entries[index]
                scan.entries[index] = .init(path: original.path, attributes: original.attributes, children: nil, linkTarget: capturedTarget)
            }
            return TransferSourceManifest(planID: UUID(), managerIdentity: UUID(), request: request,
                sourceIdentity: ObjectIdentifier(service), destinationIdentity: ObjectIdentifier(service),
                scan: scan, destinationAnchors: [], destinationIssue: nil, metadataBytes: scan.metadataBytes)
        }
        func setLink(_ target: String) throws {
            try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("repo/.github/instructions").path,
                                                       withDestinationPath: target)
        }
    }

    private func fixture() throws -> Fixture {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("repo/.github"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("repo/docs"), withIntermediateDirectories: true)
        try Data("guide".utf8).write(to: root.appendingPathComponent("repo/guide"))
        let service = try LocalFileService(root: root)
        addTeardownBlock {
            await service.close()
            try FileManager.default.removeItem(at: root)
        }
        let request = TransferRequest(hostID: "fixture", source: .init(serviceID: UUID(), path: try RemotePath("/repo")),
                                      destination: .init(serviceID: UUID(), path: try RemotePath("/dest")), kind: .tree)
        return Fixture(root: root, service: service, request: request)
    }

    func testKeepsRawTargetAndValidatesDirectoriesBeforeDotDot() async throws {
        let f = try fixture(), target = "../docs//./../guide"
        try f.setLink(target)
        let manifest = try await f.scan()
        XCTAssertTrue(manifest.enumerationComplete)
        XCTAssertEqual(manifest.rejectedCount, 0)
        XCTAssertEqual(manifest.totalBytes, 5)
        let link = try manifest.entry(RemotePath("/repo/.github/instructions"))
        XCTAssertEqual(link.linkTarget, Data(target.utf8))
        XCTAssertEqual(try manifest.linkTargetEntries(for: link).map(\.path.bytes), [
            "/repo/.github", "/repo", "/repo/docs", "/repo/guide"
        ].map { Data($0.utf8) })
        try await manifest.revalidate(f.service, token: CancellationToken())
        let strict = try await f.scan(preserve: false)
        XCTAssertFalse(strict.enumerationComplete)
        XCTAssertEqual(strict.issues.first?.kind, .symbolicLink)
    }

    func testRejectsEscapesDanglingTargetsAndNonDirectoryTraversal() async throws {
        for (target, reason) in [
            ("/absolute", "manifest-link-outside-tree"),
            ("../../repo/guide", "manifest-link-outside-tree"),
            ("../missing", "manifest-link-unsafe-target"),
            ("../guide/", "manifest-link-unsafe-target"),
            ("../guide/../guide", "manifest-link-unsafe-target"),
            ("instructions", "manifest-link-unsafe-target"),
            ("..", "manifest-link-unsafe-target")
        ] {
            let f = try fixture()
            try f.setLink(target)
            let manifest = try await f.scan()
            XCTAssertFalse(manifest.enumerationComplete, target)
            XCTAssertEqual(manifest.issues.first, FileServiceError(.symbolicLink, operation: reason,
                path: try RemotePath("/repo/.github/instructions")), target)
            XCTAssertEqual(manifest.rejectedCount, 1, target)
        }
    }

    func testRejectsRelativeTargetTraversingAnotherLinkBeforeDotDot() async throws {
        let f = try fixture()
        try FileManager.default.createSymbolicLink(atPath: f.root.appendingPathComponent("repo/alias").path,
                                                   withDestinationPath: "docs")
        try f.setLink("../alias/../guide")
        let manifest = try await f.scan()
        XCTAssertFalse(manifest.enumerationComplete)
        XCTAssertEqual(manifest.issues.first?.path, try RemotePath("/repo/.github/instructions"))
        XCTAssertEqual(manifest.issues.first?.operation, "manifest-link-unsafe-target")
    }

    func testDirectoryLinksRejectCyclesAcrossSiblings() async throws {
        let f = try fixture()
        try f.setLink("../docs")
        let safe = try await f.scan()
        XCTAssertTrue(safe.enumerationComplete)
        try FileManager.default.createSymbolicLink(atPath: f.root.appendingPathComponent("repo/docs/alias").path,
                                                   withDestinationPath: "../.github")
        let cycle = try await f.scan()
        XCTAssertFalse(cycle.enumerationComplete)
        let issue = try XCTUnwrap(cycle.issues.first)
        XCTAssertEqual(issue.operation, "manifest-link-unsafe-target")
        XCTAssertTrue(try [RemotePath("/repo/.github/instructions"), RemotePath("/repo/docs/alias")].contains(issue.path))
    }

    func testBothRevalidationPathsCheckLinkBytesEvenWhenAttributesAreIdentical() async throws {
        let f = try fixture(), path = try RemotePath("/repo/.github/instructions")
        try f.setLink("../guide")
        // Model a backend with unchanged identity/timestamps across a different raw target.
        let manifest = try await f.scan(capturedTarget: Data("../other".utf8))
        for fullScan in [true, false] {
            do {
                if fullScan { try await manifest.revalidate(f.service, token: CancellationToken()) }
                else { try await manifest.validateSource(f.service, path: path, token: CancellationToken()) }
                XCTFail("Accepted changed target bytes")
            } catch let error as FileServiceError {
                XCTAssertEqual(error, FileServiceError(.raceDetected, operation: "manifest-link-target-changed", path: path))
            }
        }
    }

    func testChainedLeafLinksResolveInOrderAndRejectMutualLinkCycles() async throws {
        let f = try fixture()
        try FileManager.default.createSymbolicLink(atPath: f.root.appendingPathComponent("repo/CLAUDE.md").path,
                                                   withDestinationPath: "guide")
        try f.setLink("../CLAUDE.md")
        let manifest = try await f.scan()
        XCTAssertTrue(manifest.enumerationComplete)
        XCTAssertEqual(manifest.rejectedCount, 0)
        let chained = try manifest.entry(RemotePath("/repo/.github/instructions"))
        XCTAssertEqual(try manifest.linkTargetEntries(for: chained).map(\.path.bytes), [
            "/repo/.github", "/repo", "/repo/CLAUDE.md", "/repo/guide"
        ].map { Data($0.utf8) })

        let cycleFixture = try fixture()
        try FileManager.default.createSymbolicLink(atPath: cycleFixture.root.appendingPathComponent("repo/CLAUDE.md").path,
                                                   withDestinationPath: ".github/instructions")
        try cycleFixture.setLink("../CLAUDE.md")
        let cycle = try await cycleFixture.scan()
        XCTAssertFalse(cycle.enumerationComplete)
        XCTAssertEqual(cycle.issues.first?.operation, "manifest-link-unsafe-target")
    }

    func testRaceDuringWalkAbortsDeferredLinksAndSubdirectoryAutoRenameWorks() async throws {
        let f = try fixture()
        try f.setLink("../guide")
        try Data("later".utf8).write(to: f.root.appendingPathComponent("repo/z-later"))
        let manifest = try await f.scan()
        XCTAssertTrue(manifest.enumerationComplete)
        let engine = SafeTransferEngine()
        let report = try await engine.copyTree(hostID: "fixture", source: f.service, sourcePath: try RemotePath("/repo"),
            destination: f.service, destinationPath: try RemotePath("/dest"), token: CancellationToken(),
            hooks: TransferHooks(beforeCommit: { _, path in
                if path.name == (try? FileName("z-later")) {
                    try Data("mutated".utf8).write(to: f.root.appendingPathComponent("repo/z-later"))
                }
            }), sourceManifest: manifest)
        XCTAssertFalse(report.allSucceeded)
        XCTAssertTrue(report.items.contains { if case .failed(let e) = $0.state { return e.kind == .raceDetected }; return false })
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.root.appendingPathComponent("dest/.github/instructions").path))

        // Subdirectory conflict with an existing regular file resolves cleanly when user chooses .autoRename ("都保留").
        let subRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let srcDir = subRoot.appendingPathComponent("src/tree/sub"), dstDir = subRoot.appendingPathComponent("dst/tree")
        try FileManager.default.createDirectory(at: srcDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: dstDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: subRoot) }
        try Data("sub-child".utf8).write(to: srcDir.appendingPathComponent("item.txt"))
        try Data("blocking-file".utf8).write(to: dstDir.appendingPathComponent("sub"))
        let srcService = try LocalFileService(root: subRoot.appendingPathComponent("src"))
        let dstService = try LocalFileService(root: subRoot.appendingPathComponent("dst"))
        let subReport = try await engine.copyTree(hostID: "fixture", source: srcService, sourcePath: try RemotePath("/tree"),
            destination: dstService, destinationPath: try RemotePath("/tree"), conflict: .overwrite, token: CancellationToken(),
            policy: TransferPolicy(acceptsTechnicalLimits: true))
        XCTAssertFalse(subReport.allSucceeded)

        let autoReport = try await engine.copyTree(hostID: "fixture", source: srcService, sourcePath: try RemotePath("/tree"),
            destination: dstService, destinationPath: try RemotePath("/tree"), token: CancellationToken(),
            policy: TransferPolicy(acceptsTechnicalLimits: true),
            hooks: TransferHooks(resolveConflict: { conflict in
                conflict.destination == (try? RemotePath("/tree")) ? .overwrite : .autoRename
            }))
        XCTAssertTrue(autoReport.allSucceeded)
        XCTAssertEqual(try Data(contentsOf: dstDir.appendingPathComponent("sub")), Data("blocking-file".utf8))
        XCTAssertEqual(try Data(contentsOf: dstDir.appendingPathComponent("sub (1)/item.txt")), Data("sub-child".utf8))
        await srcService.close(); await dstService.close()
    }
}
