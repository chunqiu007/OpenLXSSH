import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

// Local directory/file/pipe/socketpair descriptors only. No network peer or SSH interoperability.
private final class DirectoryDescriptorFixture {
    let root: URL
    let selected: URL
    let outside: URL
    let contents = Data("original directory bytes".utf8)
    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-directory-descriptor-\(UUID().uuidString)")
        selected = root.appendingPathComponent("selected"); outside = root.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: selected, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try contents.write(to: selected.appendingPathComponent("file"))
        try Data("outside directory bytes".utf8).write(to: outside.appendingPathComponent("file"))
        try Data().write(to: outside.appendingPathComponent("outside-only"))
    }
    deinit { try? FileManager.default.removeItem(at: root) }
}

final class RootDirectoryDescriptorTests: XCTestCase, @unchecked Sendable {
    private func openDirectory(_ url: URL, closeOnExec: Bool = true) throws -> Int32 {
        let fd = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | (closeOnExec ? O_CLOEXEC : 0))
        guard fd >= 0 else { throw FileServiceError(.io, operation: "test-open-directory", code: Int64(errno)) }
        return fd
    }
    private func openDescriptors() throws -> Set<Int32> {
        // The enumerator's own FD has closed before filtering; do not count that transient FD.
        Set(try FileManager.default.contentsOfDirectory(atPath: "/dev/fd").compactMap(Int32.init).filter {
            fcntl($0, F_GETFD) >= 0
        })
    }
    private func directoryDescriptors(matching fd: Int32) throws -> Set<Int32> {
        var expected = stat()
        guard Darwin.fstat(fd, &expected) == 0 else { throw FileServiceError(.io, operation: "test-stat-directory") }
        return try openDescriptors().filter { candidate in
            var actual = stat()
            return Darwin.fstat(candidate, &actual) == 0 && actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino
                && actual.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
        }
    }
    private func readFile(_ path: RemotePath, from service: LocalFileService) async throws -> Data {
        let token = CancellationToken(), handle = try await service.open(path, mode: .read, token: CancellationToken())
        do {
            var result = Data()
            while true {
                let chunk = try await service.read(handle, maxBytes: 7, token: token)
                if chunk.isEmpty { break }; result.append(chunk)
            }
            try await service.closeHandle(handle); return result
        } catch { try? await service.closeHandle(handle); throw error }
    }

    func testCopiedRootSurvivesCallerCloseWithCloexecAndIndependentRootListings() async throws {
        let f = try DirectoryDescriptorFixture()
        for name in ["中文 空格", "quote'$\n"] { try Data(name.utf8).write(to: f.selected.appendingPathComponent(name)) }
        var caller = try openDirectory(f.selected, closeOnExec: false)
        defer { if caller >= 0 { Darwin.close(caller) } }
        let originalFDs = try directoryDescriptors(matching: caller)
        XCTAssertEqual(fcntl(caller, F_GETFD) & FD_CLOEXEC, 0)
        let service = try LocalFileService(rootDirectoryDescriptor: caller)
        let copiedFDs = try directoryDescriptors(matching: caller).subtracting(originalFDs)
        XCTAssertEqual(copiedFDs.count, 1)
        let copy = try XCTUnwrap(copiedFDs.first)
        XCTAssertNotEqual(copy, caller); XCTAssertNotEqual(fcntl(copy, F_GETFD) & FD_CLOEXEC, 0)
        XCTAssertEqual(fcntl(caller, F_GETFD) & FD_CLOEXEC, 0, "Copying must not mutate the caller's FD flags")
        XCTAssertEqual(Darwin.close(caller), 0); caller = -1
        let expected = Set(try ["file", "中文 空格", "quote'$\n"].map(FileName.init))
        for _ in 0..<4 {
            let names = try await service.list(.root, token: CancellationToken()).map(\.name)
            XCTAssertEqual(names.count, expected.count); XCTAssertEqual(Set(names), expected)
        }
        try await withThrowingTaskGroup(of: [FileName].self) { group in
            for _ in 0..<8 { group.addTask { try await service.list(.root, token: CancellationToken()).map(\.name) } }
            for try await names in group { XCTAssertEqual(names.count, expected.count); XCTAssertEqual(Set(names), expected) }
        }
        let bytes = try await readFile(RemotePath("/file"), from: service); XCTAssertEqual(bytes, f.contents)
        await service.close()
        XCTAssertEqual(fcntl(copy, F_GETFD), -1); XCTAssertEqual(errno, EBADF)
    }

    func testServiceCloseAndDeinitPreserveCallerAndReusedDescriptor() async throws {
        let f = try DirectoryDescriptorFixture(), caller = try openDirectory(f.selected)
        defer { Darwin.close(caller) }
        let originalFDs = try directoryDescriptors(matching: caller)
        var service: LocalFileService? = try LocalFileService(rootDirectoryDescriptor: caller)
        let copiedFDs = try directoryDescriptors(matching: caller).subtracting(originalFDs)
        XCTAssertEqual(copiedFDs.count, 1)
        let copy = try XCTUnwrap(copiedFDs.first)
        await service?.close(); await service?.close()
        XCTAssertEqual(fcntl(copy, F_GETFD), -1); XCTAssertEqual(errno, EBADF)
        XCTAssertGreaterThanOrEqual(fcntl(caller, F_GETFD), 0)
        let replacement = fcntl(caller, F_DUPFD_CLOEXEC, copy)
        guard replacement >= 0 else { throw FileServiceError(.io, operation: "test-reuse-fd", code: Int64(errno)) }
        defer { Darwin.close(replacement) }
        XCTAssertEqual(replacement, copy, "The closed service's FD slot must be reusable")
        await service?.close(); service = nil
        XCTAssertGreaterThanOrEqual(fcntl(replacement, F_GETFD), 0, "Repeated close/deinit must not close a new owner of the old slot")
        XCTAssertGreaterThanOrEqual(fcntl(caller, F_GETFD), 0)
        let next = try LocalFileService(rootDirectoryDescriptor: caller)
        let bytes = try await readFile(RemotePath("/file"), from: next); XCTAssertEqual(bytes, f.contents)
        await next.close()
        XCTAssertGreaterThanOrEqual(fcntl(caller, F_GETFD), 0); XCTAssertGreaterThanOrEqual(fcntl(replacement, F_GETFD), 0)
    }

    func testInvalidFilePipeAndSocketDescriptorsRejectWithoutLeaksOrTakingOwnership() throws {
        let f = try DirectoryDescriptorFixture()
        let file = Darwin.open(f.selected.appendingPathComponent("file").path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard file >= 0 else { throw FileServiceError(.io, operation: "test-open-file") }
        defer { Darwin.close(file) }
        var pipes: [Int32] = [-1, -1], sockets: [Int32] = [-1, -1]
        guard pipe(&pipes) == 0 else { throw FileServiceError(.io, operation: "test-pipe") }
        defer { pipes.forEach { Darwin.close($0) } }
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else { throw FileServiceError(.io, operation: "test-socketpair") }
        defer { sockets.forEach { Darwin.close($0) } }
        let originals = [file] + pipes + sockets, before = try openDescriptors()
        let flags = originals.map { fcntl($0, F_GETFD) }
        for _ in 0..<64 {
            for fd in [Int32(-1)] + originals {
                XCTAssertThrowsError(try LocalFileService(rootDirectoryDescriptor: fd)) { error in
                    guard let typed = error as? FileServiceError else { XCTFail("Expected typed error, got \(error)"); return }
                    XCTAssertEqual(typed.kind, fd == -1 ? .io : .unsupported)
                    XCTAssertEqual(typed.code, Int64(fd == -1 ? EBADF : ENOTDIR))
                    XCTAssertEqual(typed.operation, fd == -1 ? "duplicate-local-root" : "local-root-not-directory")
                }
            }
        }
        XCTAssertEqual(try openDescriptors(), before, "Every rejected duplicate must be closed exactly once")
        XCTAssertEqual(originals.map { fcntl($0, F_GETFD) }, flags, "Rejected caller descriptors must remain untouched")
        var sent: UInt8 = 0xA5, received: UInt8 = 0
        XCTAssertEqual(Darwin.write(pipes[1], &sent, 1), 1); XCTAssertEqual(Darwin.read(pipes[0], &received, 1), 1); XCTAssertEqual(received, sent)
        XCTAssertEqual(Darwin.write(sockets[0], &sent, 1), 1); XCTAssertEqual(Darwin.read(sockets[1], &received, 1), 1); XCTAssertEqual(received, sent)
    }

    func testRepeatedInitializationAndCloseDoesNotLeakDirectoryCopies() async throws {
        let f = try DirectoryDescriptorFixture(), caller = try openDirectory(f.selected)
        defer { Darwin.close(caller) }
        let originalFDs = try directoryDescriptors(matching: caller)
        for _ in 0..<64 {
            let service = try LocalFileService(rootDirectoryDescriptor: caller)
            let copies = try directoryDescriptors(matching: caller).subtracting(originalFDs)
            XCTAssertEqual(copies.count, 1)
            let copy = try XCTUnwrap(copies.first)
            XCTAssertNotEqual(fcntl(copy, F_GETFD) & FD_CLOEXEC, 0)
            let entries = try await service.list(.root, token: CancellationToken()); XCTAssertEqual(entries.map(\.name), [try FileName("file")])
            await service.close(); await service.close()
            XCTAssertEqual(try directoryDescriptors(matching: caller), originalFDs)
        }
    }

    func testOpenedDirectoryStaysAnchoredWhenPathIsRenamedAndReplacedBySymlink() async throws {
        let f = try DirectoryDescriptorFixture(), parent = try openDirectory(f.root)
        defer { Darwin.close(parent) }
        var caller = openat(parent, "selected", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard caller >= 0 else { throw FileServiceError(.io, operation: "test-openat-selected") }
        defer { if caller >= 0 { Darwin.close(caller) } }
        let moved = f.root.appendingPathComponent("moved")
        XCTAssertEqual(Darwin.rename(f.selected.path, moved.path), 0)
        XCTAssertEqual(symlink(f.outside.path, f.selected.path), 0)
        // This is the caller-side selection contract: a fresh no-follow traversal rejects the link.
        let unsafeReplacement = openat(parent, "selected", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if unsafeReplacement >= 0 { Darwin.close(unsafeReplacement); XCTFail("Caller traversal must reject replacement symlinks") }
        else { XCTAssertTrue([ELOOP, ENOTDIR].contains(errno)) }
        let service = try LocalFileService(rootDirectoryDescriptor: caller)
        XCTAssertEqual(Darwin.close(caller), 0); caller = -1
        let entries = try await service.list(.root, token: CancellationToken()); XCTAssertEqual(entries.map(\.name), [try FileName("file")])
        let bytes = try await readFile(RemotePath("/file"), from: service); XCTAssertEqual(bytes, f.contents)
        let token = CancellationToken(), handle = try await service.open(RemotePath("/created"), mode: .exclusiveWrite, token: CancellationToken())
        let created = Data("anchored write".utf8), count = try await service.write(handle, data: Data("anchored write".utf8), token: token)
        XCTAssertEqual(count, created.count)
        try await service.finish(handle, token: token); try await service.closeHandle(handle)
        XCTAssertEqual(try Data(contentsOf: moved.appendingPathComponent("created")), created)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.outside.appendingPathComponent("created").path))
        XCTAssertEqual(try Data(contentsOf: f.outside.appendingPathComponent("file")), Data("outside directory bytes".utf8))
        await service.close()
    }

    func testCopiedRootRetainsNoFollowComponentTraversal() async throws {
        let f = try DirectoryDescriptorFixture(), caller = try openDirectory(f.selected)
        defer { Darwin.close(caller) }
        XCTAssertEqual(symlink(f.outside.path, f.selected.appendingPathComponent("escape").path), 0)
        XCTAssertEqual(symlink(f.outside.appendingPathComponent("file").path, f.selected.appendingPathComponent("linked-file").path), 0)
        let service = try LocalFileService(rootDirectoryDescriptor: caller)
        XCTAssertEqual(service.capabilities.traversal, .localDescriptorNoFollow)
        let link = try await service.lstat(RemotePath("/escape"), token: CancellationToken()); XCTAssertEqual(link.kind, .symbolicLink)
        do { _ = try await service.list(RemotePath("/escape"), token: CancellationToken()); XCTFail("Directory link must not be followed") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .symbolicLink) }
        for path in [try RemotePath("/escape/file"), try RemotePath("/linked-file")] {
            do { _ = try await service.open(path, mode: .read, token: CancellationToken()); XCTFail("Read must not traverse a link") }
            catch let error as FileServiceError { XCTAssertEqual(error.kind, .symbolicLink) }
        }
        do {
            _ = try await service.open(RemotePath("/escape/new"), mode: .exclusiveWrite, token: CancellationToken())
            XCTFail("Write must not traverse a directory link")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .symbolicLink) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.outside.appendingPathComponent("new").path))
        let bytes = try await readFile(RemotePath("/file"), from: service); XCTAssertEqual(bytes, f.contents)
        await service.close(); XCTAssertGreaterThanOrEqual(fcntl(caller, F_GETFD), 0)
    }
}
