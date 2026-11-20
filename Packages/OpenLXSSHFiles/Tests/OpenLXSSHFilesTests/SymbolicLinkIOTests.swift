import Foundation
import XCTest
@testable import OpenLXSSHFiles

final class SymbolicLinkIOTests: XCTestCase {
    func testLinkBytesArePreservedAndExistingLeafIsNeverReplaced() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let service: any RemoteFileService = try LocalFileService(root: folder)
        let path = try RemotePath("/link"), token = CancellationToken()
        let target = Data("../共享/./file with spaces".utf8) + Data([0xff])
        try await service.createSymbolicLink(path, target: target, token: token)
        let observed = try await service.readSymbolicLink(path, token: token)
        XCTAssertEqual(observed, target)
        let attributes = try await service.lstat(path, token: token)
        XCTAssertEqual(attributes.kind, .symbolicLink)
        do {
            try await service.createSymbolicLink(path, target: Data("other".utf8), token: token)
            XCTFail("Replaced an existing dangling link")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .conflict) }
        let unchanged = try await service.readSymbolicLink(path, token: token)
        XCTAssertEqual(unchanged, target)
        await service.close()
    }

    func testLinkedAncestorInvalidTargetAndCancellationDoNotCreateFiles() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let selected = root.appendingPathComponent("selected"), outside = root.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: selected, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(atPath: selected.appendingPathComponent("ancestor").path, withDestinationPath: outside.path)
        let service = try LocalFileService(root: selected)
        let leaf = try RemotePath("/ancestor/leaf"), link = try RemotePath("/link")
        let token = CancellationToken(), text = Data("relative".utf8)
        do {
            try await service.createSymbolicLink(leaf, target: text, token: token)
            XCTFail("Created through a symlinked ancestor")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .symbolicLink) }
        do {
            _ = try await service.readSymbolicLink(leaf, token: token)
            XCTFail("Read through a symlinked ancestor")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .symbolicLink) }
        for invalid in [Data(), Data([97, 0, 98]), Data(repeating: 97, count: 32_769)] {
            do {
                try await service.createSymbolicLink(link, target: invalid, token: token)
                XCTFail("Created an invalid link")
            } catch let error as FileServiceError { XCTAssertEqual(error.kind, .invalidPath) }
        }
        token.cancel()
        do {
            try await service.createSymbolicLink(link, target: text, token: token)
            XCTFail("Ran a cancelled creation")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: outside.path), [])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: selected.path), ["ancestor"])
        await service.close()
    }
}
