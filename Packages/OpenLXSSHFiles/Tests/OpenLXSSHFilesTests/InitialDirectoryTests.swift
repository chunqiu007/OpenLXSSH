import COpenLXSSHFiles
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

/// Offline byte/cancellation/ownership checks only. LocalFileService is a confined local
/// substitute, not a real SFTP peer or evidence that a server resolves its login directory.
final class InitialDirectoryTests: XCTestCase, @unchecked Sendable {
    private func path(_ bytes: Data) throws -> RemotePath {
        let buffer = (Array(bytes) + [0]).map { CChar(bitPattern: $0) }
        return try LibSSH2FileService.initialDirectoryPath(buffer: buffer, length: Int32(bytes.count))
    }
    private func root() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-initial-directory-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        addTeardownBlock { try FileManager.default.removeItem(at: root) }
        return root
    }
    private func assertFailure<T>(_ kind: FileServiceError.Kind,
        file: StaticString = #filePath, line: UInt = #line, _ body: () async throws -> T) async {
        do { _ = try await body(); XCTFail("Expected explicit failure, not a guessed directory", file: file, line: line) }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, kind, file: file, line: line) }
        catch { XCTFail("Unexpected error: \(error)", file: file, line: line) }
    }
    func testSourceCompatibleDefaultIsExplicitlyUnsupportedNeverRoot() async throws {
        let service: any RemoteFileService = InitialDirectoryUnsupportedService()
        do {
            _ = try await service.initialDirectory(token: CancellationToken())
            XCTFail("A conformer without this capability must not invent a login directory")
        } catch let error as FileServiceError {
            XCTAssertEqual(error, FileServiceError(.unsupported, operation: "initial-directory"))
            XCTAssertNil(error.path)
        }
    }
    func testDefaultChecksTokenAndTaskCancellationBeforeUnsupported() async {
        let service: any RemoteFileService = InitialDirectoryUnsupportedService(), token = CancellationToken()
        token.cancel()
        await assertFailure(.cancelled) { try await service.initialDirectory(token: token) }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await service.initialDirectory(token: CancellationToken())
        }
        await assertFailure(.cancelled) { try await task.value }
    }
    func testNativeResultPreservesNonUTF8ControlsAndUnicodeByteIdentity() throws {
        let raw = Data([47, 255, 65, 47, 128, 32, 37, 39, 10, 27])
        XCTAssertEqual(try path(raw).bytes, raw)
        let decomposed = Data("/中文/e\u{301}".utf8), composed = Data("/中文/é".utf8)
        XCTAssertEqual(try path(decomposed).bytes, decomposed)
        XCTAssertEqual(try path(composed).bytes, composed)
        XCTAssertNotEqual(try path(decomposed), try path(composed))
        // Ignore bytes beyond the returned count; do not reinterpret the buffer as a C string.
        let buffer = [CChar(47), 65, 0, 66]
        XCTAssertEqual(try LibSSH2FileService.initialDirectoryPath(buffer: buffer, length: 2).bytes, Data([47, 65]))
    }
    func testRootAndExactMaximumPathFitWithOneTerminatingByte() throws {
        XCTAssertEqual(Int(RF_SFTP_REALPATH_CAPACITY), 32_769)
        XCTAssertEqual(try path(Data([47])), .root)
        var maximum = Data()
        for _ in 0..<128 { maximum.append(47); maximum.append(Data(repeating: 65, count: 255)) }
        XCTAssertEqual(maximum.count, 32_768)
        XCTAssertEqual(try path(maximum).bytes, maximum)
        XCTAssertThrowsError(try path(maximum + Data([47, 66]))) { error in
            XCTAssertEqual((error as? FileServiceError)?.kind, .invalidPath)
        }
    }
    func testNativeCountAndBufferBoundsRejectWithoutOutOfBoundsReads() {
        let invalid: [([CChar], Int32)] = [([], 0), ([47], 1), ([47, 0], -1), ([47, 0], 0),
            ([47, 0], 2), ([47, 0], 3), ([47, 0], Int32.max),
            ([CChar](repeating: 47, count: Int(RF_SFTP_REALPATH_CAPACITY) + 1), 1),
            ([CChar](repeating: 47, count: Int(RF_SFTP_REALPATH_CAPACITY)), Int32(RF_SFTP_REALPATH_CAPACITY))]
        for (buffer, length) in invalid {
            XCTAssertThrowsError(try LibSSH2FileService.initialDirectoryPath(buffer: buffer, length: length)) { error in
                XCTAssertEqual(error as? FileServiceError, FileServiceError(.invalidPath, operation: "sftp-realpath-length"))
            }
        }
    }
    func testMalformedServerPathsAreRejectedByRemotePathWithoutRepair() {
        let invalid = [Data(), Data(".".utf8), Data("relative/login".utf8), Data("/a//b".utf8), Data("/a/".utf8),
            Data("/a/./b".utf8), Data("/a/../b".utf8), Data([47, 65, 0, 66]), Data([47]) + Data(repeating: 65, count: 256)]
        for bytes in invalid {
            XCTAssertThrowsError(try path(bytes)) { error in
                XCTAssertEqual((error as? FileServiceError)?.kind, .invalidPath)
            }
        }
    }
    func testCancellationBeforeNativeAwaitNeverInvokesResolver() async {
        let token = CancellationToken(); token.cancel()
        await assertFailure(.cancelled) {
            try await LibSSH2FileService.resolveInitialDirectory(token: token) {
                XCTFail("A cancelled request must not enter the native owner")
                return .root
            }
        }
    }
    func testTokenCancellationDuringNativeAwaitRejectsLateRawPathSuccess() async throws {
        let gate = InitialDirectoryGate(), token = CancellationToken(), login = try path(Data([47, 255]))
        let task = Task {
            try await LibSSH2FileService.resolveInitialDirectory(token: token) {
                await gate.suspend()
                return login
            }
        }
        await gate.waitForArrival(); token.cancel(); await gate.release()
        await assertFailure(.cancelled) { try await task.value }
    }
    func testTaskCancellationDuringNativeAwaitRejectsLateSuccess() async throws {
        let gate = InitialDirectoryGate(), token = CancellationToken(), login = try RemotePath("/login")
        let task = Task {
            try await LibSSH2FileService.resolveInitialDirectory(token: token) {
                await gate.suspend()
                return login
            }
        }
        await gate.waitForArrival(); task.cancel(); await gate.release()
        await assertFailure(.cancelled) { try await task.value }
    }
    func testResolutionErrorsPropagateWithoutFallbackAndCancellationWinsLateFailure() async {
        for kind: FileServiceError.Kind in [.unsupported, .notFound, .permissionDenied, .protocolFailure, .timeout, .closed, .transport] {
            let expected = FileServiceError(kind, operation: "offline-native-result", code: 7)
            do {
                _ = try await LibSSH2FileService.resolveInitialDirectory(token: CancellationToken()) { throw expected }
                XCTFail("Resolution error must not become root success")
            } catch { XCTAssertEqual(error as? FileServiceError, expected) }
        }
        let token = CancellationToken()
        await assertFailure(.cancelled) {
            try await LibSSH2FileService.resolveInitialDirectory(token: token) {
                token.cancel()
                throw FileServiceError(.protocolFailure, operation: "offline-late-result")
            }
        }
    }
    func testLocalSubstituteInitialDirectoryIsConfinedRootNotHostHome() async throws {
        let root = try root(), local = try LocalFileService(root: root)
        addTeardownBlock { await local.close() }
        let initial = try await local.initialDirectory(token: CancellationToken())
        XCTAssertEqual(initial, .root)
        XCTAssertNotEqual(initial.bytes, Data(root.path.utf8))
        try await local.mkdir(RemotePath("/selected-child"), token: CancellationToken())
        let entries = try await local.list(initial, token: CancellationToken())
        XCTAssertEqual(entries.map(\.name), [try FileName("selected-child")])
        let again = try await local.initialDirectory(token: CancellationToken())
        XCTAssertEqual(again, .root)
    }
    func testLocalSubstituteInitialDirectoryHonorsCancellationAndClose() async throws {
        let root = try root(), local = try LocalFileService(root: root), token = CancellationToken()
        token.cancel()
        await assertFailure(.cancelled) { try await local.initialDirectory(token: token) }
        local.cancel()
        await assertFailure(.cancelled) { try await local.initialDirectory(token: CancellationToken()) }
        await local.close()
        await assertFailure(.closed) { try await local.initialDirectory(token: CancellationToken()) }
    }
    func testNativeBridgeRejectsInvalidBoundsAndClosedOwnerWithoutWritingBytes() {
        let token = CancellationToken()
        var bytes: [CChar] = [65, 66]
        for capacity in [0, 1, Int(RF_SFTP_REALPATH_CAPACITY) + 1] {
            XCTAssertEqual(rf_sftp_initial_directory(nil, &bytes, capacity, token.native, 1), Int32(RF_INVALID))
        }
        for timeout: Double in [0, -1, .nan, .infinity, 301] {
            XCTAssertEqual(rf_sftp_initial_directory(nil, &bytes, bytes.count, token.native, timeout), Int32(RF_INVALID))
        }
        XCTAssertEqual(rf_sftp_initial_directory(nil, nil, 2, token.native, 1), Int32(RF_INVALID))
        XCTAssertEqual(rf_sftp_initial_directory(nil, &bytes, bytes.count, token.native, 1), Int32(RF_CLOSED))
        XCTAssertEqual(bytes, [65, 66])
    }
    func testNativeOwnerWithoutSFTPDoesNotResolveOrSendAnyBytes() async throws {
        var sockets: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else {
            throw FileServiceError(.io, operation: "offline-socketpair", code: Int64(errno))
        }
        defer { sockets.forEach { Darwin.close($0) } }
        let service = try LibSSH2FileService(connectedSocket: sockets[0])
        let token = CancellationToken(); token.cancel()
        await assertFailure(.cancelled) { try await service.initialDirectory(token: token) }
        await assertFailure(.closed) { try await service.initialDirectory(token: CancellationToken()) }
        var byte: UInt8 = 0
        XCTAssertEqual(recv(sockets[1], &byte, 1, MSG_DONTWAIT), -1)
        XCTAssertEqual(errno, EAGAIN, "No handshake, authentication or SFTP packet may have been sent")
        await service.close()
        await assertFailure(.cancelled) { try await service.initialDirectory(token: CancellationToken()) }
    }
    func testManagerInitialDirectoryRejectsStaleServiceIDWithoutRetargetingLocalSubstitute() async throws {
        let root = try root(), first = try LocalFileService(root: root), second = try LocalFileService(root: root)
        let manager = TransferManager(idleTimeout: nil)
        addTeardownBlock { await manager.cancelAllAndWait(); await first.close(); await second.close() }
        let oldID = try await manager.registerService(first, hostID: "offline-local")
        let initial = try await manager.withServiceOperation(serviceID: oldID, hostID: "offline-local") { service, token in
            try await service.initialDirectory(token: token)
        }
        XCTAssertEqual(initial, .root)
        await manager.closeIdleServices([oldID])
        let freshID = try await manager.registerService(second, hostID: "offline-local")
        XCTAssertNotEqual(oldID, freshID)
        await assertFailure(.closed) {
            try await manager.withServiceOperation(serviceID: oldID, hostID: "offline-local") { _, _ in
                XCTFail("A stale service ID must not execute against the new service")
                return RemotePath.root
            }
        }
        let fresh = try await manager.withServiceOperation(serviceID: freshID, hostID: "offline-local") { service, token in
            try await service.initialDirectory(token: token)
        }
        XCTAssertEqual(fresh, .root)
    }
}

/// Deliberately omits initialDirectory to prove source compatibility AND unsupported behavior.
private final class InitialDirectoryUnsupportedService: RemoteFileService {
    let capabilities = FileServiceCapabilities(traversal: .remoteComponentLstat, exclusiveCreate: true,
        noReplace: .needsServerConfirmation, canAttemptAtomicReplace: false)
    private func unused() -> FileServiceError { FileServiceError(.unsupported, operation: "unused-offline-substitute") }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { throw unused() }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes { throw unused() }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { throw unused() }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { throw unused() }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { throw unused() }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { throw unused() }
    func closeHandle(_ handle: FileHandleID) async throws { throw unused() }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws { throw unused() }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws { throw unused() }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws { throw unused() }
    func cancel() {}
    func close() async {}
}
private actor InitialDirectoryGate {
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
