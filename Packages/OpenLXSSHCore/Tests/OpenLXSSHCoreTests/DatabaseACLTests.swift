import Darwin
import Foundation
import GRDB
import XCTest
@testable import OpenLXSSHCore

final class DatabaseACLTests: XCTestCase {
    private var parent: URL!
    private let metadataNames = ["OpenLXSSH.sqlite", "OpenLXSSH.lock", "OpenLXSSH.sqlite-wal", "OpenLXSSH.sqlite-shm", "OpenLXSSH.sqlite-journal"]
    private let inheritedAccess = "everyone allow list,search,read,write,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit"

    override func setUpWithError() throws {
        parent = FileManager.default.temporaryDirectory.appendingPathComponent("openlxssh-core-acl-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }

    override func tearDownWithError() throws {
        if let parent { try FileManager.default.removeItem(at: parent) }
        parent = nil
    }

    func testNewRootInheritedACLRejectedBeforeDatabaseMetadataCreation() throws {
        try addACL(inheritedAccess, to: parent)
        let originalACL = try aclText(parent)
        let root = parent.appendingPathComponent("Data", isDirectory: true)
        expectUnsafe {
            let database = try OpenLXSSHDatabase(directory: root)
            try database.close()
        }
        XCTAssertEqual(try aclText(parent), originalACL, "The caller's ACL must not be cleared or rewritten")
        if FileManager.default.fileExists(atPath: root.path) {
            for name in metadataNames {
                XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent(name).path), name)
            }
            XCTAssertTrue(try aclText(root).contains("inherited"), "Rejection must not strip inherited ACLs")
        }
    }

    func testExistingRootACLRejectedWithoutChangingACLOrMode() throws {
        let root = try makeRoot()
        XCTAssertEqual(chmod(root.path, 0o755), 0)
        try addACL("everyone allow list,search", to: root)
        let originalACL = try aclText(root)
        expectUnsafe {
            let database = try OpenLXSSHDatabase(directory: root)
            try database.close()
        }
        XCTAssertEqual(try aclText(root), originalACL)
        XCTAssertEqual(try mode(root), 0o755, "Reject ACLs before permission repair")
        for name in metadataNames {
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent(name).path), name)
        }
    }

    func testExistingDatabaseLockAndSidecarACLRejectedWithoutPermissionRepair() throws {
        for name in metadataNames {
            let root = try makeRoot()
            let file = root.appendingPathComponent(name)
            XCTAssertTrue(FileManager.default.createFile(atPath: file.path, contents: Data(), attributes: [.posixPermissions: 0o644]))
            XCTAssertEqual(chmod(file.path, 0o644), 0)
            try addACL("everyone allow read,write", to: file)
            let originalACL = try aclText(file)
            expectUnsafe {
                let database = try OpenLXSSHDatabase(directory: root)
                try database.close()
            }
            XCTAssertEqual(try aclText(file), originalACL, name)
            XCTAssertEqual(try mode(file), 0o644, "Reject \(name) ACL before permission repair")
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: file.path)[.size] as? NSNumber, 0, name)
        }
    }

    func testDenyOnlyACLIsConservativelyRejectedAndPreserved() throws {
        for isDirectory in [true, false] {
            let root = try makeRoot()
            let target = isDirectory ? root : root.appendingPathComponent("OpenLXSSH.sqlite")
            if !isDirectory {
                XCTAssertTrue(FileManager.default.createFile(atPath: target.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
            }
            try addACL("everyone deny writeextattr", to: target)
            let originalACL = try aclText(target)
            expectUnsafe {
                let database = try OpenLXSSHDatabase(directory: root)
                try database.close()
            }
            XCTAssertEqual(try aclText(target), originalACL)
        }
    }

    func testRuntimeDirectoryDatabaseLockAndSidecarACLBlocksReadsAndWrites() throws {
        for name in ["."] + metadataNames {
            let root = try makeRoot()
            let database = try OpenLXSSHDatabase(directory: root)
            defer { try? database.close() }
            let baseline = HostConfiguration(name: "baseline", address: "test.invalid", username: "fixture")
            try database.addHost(baseline)
            let target = name == "." ? root : root.appendingPathComponent(name)
            if !FileManager.default.fileExists(atPath: target.path) {
                XCTAssertTrue(FileManager.default.createFile(atPath: target.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
            }
            try addACL("everyone allow read,write", to: target)
            let originalACL = try aclText(target)
            expectUnsafe { _ = try database.hosts() }
            expectUnsafe { try database.addHost(HostConfiguration(name: "must not insert", address: "blocked.invalid", username: "fixture")) }
            XCTAssertEqual(try aclText(target), originalACL, name)
            // The direct queue is test-only: prove a rejected public write did not reach SQL.
            XCTAssertEqual(try database.queue.read { try Int.fetchOne($0, sql: "SELECT count(*) FROM hosts") }, 1, name)
            try database.close()
        }
    }

    func testACLAddedInsideTransactionPreventsCommit() throws {
        let root = try makeRoot()
        let database = try OpenLXSSHDatabase(directory: root)
        defer { try? database.close() }
        let host = HostConfiguration(name: "must roll back", address: "test.invalid", username: "fixture")
        let file = database.databaseURL
        expectUnsafe {
            try database.applyTransaction([.insertHost(host)], beforeCommit: {
                try addACL("everyone allow read,write", to: file)
            })
        }
        XCTAssertTrue(try aclText(file).contains("allow"))
        XCTAssertEqual(try database.queue.read { try Int.fetchOne($0, sql: "SELECT count(*) FROM hosts") }, 0)
    }

    func testACLQueryErrorsFailClosedAndSuccessfulQueriesIgnoreStaleErrno() throws {
        let root = try makeRoot()
        let file = root.appendingPathComponent("OpenLXSSH.sqlite")
        XCTAssertTrue(FileManager.default.createFile(atPath: file.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
        var info = stat()
        XCTAssertEqual(lstat(file.path, &info), 0)
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { Darwin.close(fd) }
        errno = EIO
        XCTAssertNoThrow(try DatabaseFileACL.requireNoExtendedACL(at: "OpenLXSSH.sqlite", in: fd, matching: info))
        var rootInfo = stat()
        XCTAssertEqual(fstat(fd, &rootInfo), 0)
        errno = EIO
        XCTAssertNoThrow(try DatabaseFileACL.requireNoExtendedACL(fd: fd, matching: rootInfo))
        expectUnsafe { try DatabaseFileACL.requireNoExtendedACL(fd: -1, matching: rootInfo) }
        expectUnsafe { try DatabaseFileACL.requireNoExtendedACL(at: "OpenLXSSH.sqlite", in: -1, matching: info) }
        try FileManager.default.removeItem(at: file)
        // ENOENT from the ACL query is not the Darwin acl_get_fd_np "no ACL" case.
        expectUnsafe { try DatabaseFileACL.requireNoExtendedACL(at: "OpenLXSSH.sqlite", in: fd, matching: info) }
    }

    func testExplicitEmptyACLIsConservativelyRejectedAndPreserved() throws {
        for isDirectory in [true, false] {
            let root = try makeRoot()
            let file = root.appendingPathComponent("OpenLXSSH.sqlite")
            XCTAssertTrue(FileManager.default.createFile(atPath: file.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
            let target = isDirectory ? root : file
            let acl = try XCTUnwrap(acl_init(0))
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            XCTAssertEqual(acl_set_link_np(target.path, ACL_TYPE_EXTENDED, acl), 0)
            let originalACL = try extendedSecurity(target)
            expectUnsafe {
                let database = try OpenLXSSHDatabase(directory: root)
                try database.close()
            }
            XCTAssertEqual(try extendedSecurity(target), originalACL)
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: file.path)[.size] as? NSNumber, 0)
        }
    }

    func testUnrelatedACLIsNotInspectedOrRewritten() throws {
        let root = try makeRoot()
        let unrelated = root.appendingPathComponent("unrelated.txt")
        XCTAssertTrue(FileManager.default.createFile(atPath: unrelated.path, contents: Data(), attributes: [.posixPermissions: 0o644]))
        try addACL("everyone allow read", to: unrelated)
        let originalACL = try aclText(unrelated)
        let database = try OpenLXSSHDatabase(directory: root)
        defer { try? database.close() }
        XCTAssertTrue(try database.hosts().isEmpty)
        XCTAssertEqual(try aclText(unrelated), originalACL)
        XCTAssertEqual(try mode(unrelated), 0o644)
    }

    private func makeRoot() throws -> URL {
        let root = parent.appendingPathComponent("Data-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return root
    }

    private func addACL(_ entry: String, to url: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", entry, url.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0, "Installing an isolated test ACL must succeed")
        guard process.terminationStatus == 0 else { throw POSIXError(.EIO) }
    }

    private func aclText(_ url: URL) throws -> String {
        guard let acl = acl_get_link_np(url.path, ACL_TYPE_EXTENDED) else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard let text = acl_to_text(acl, nil) else { throw POSIXError(.EIO) }
        defer { acl_free(text) }
        return String(cString: text)
    }

    private func extendedSecurity(_ url: URL) throws -> Data {
        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.commonattr = UInt32(ATTR_CMN_EXTENDED_SECURITY)
        var buffer = [UInt8](repeating: 0, count: Int(ATTR_MAX_BUFFER))
        let result = buffer.withUnsafeMutableBytes {
            getattrlist(url.path, &attributes, $0.baseAddress, $0.count, numericCast(FSOPT_NOFOLLOW | FSOPT_REPORT_FULLSIZE))
        }
        guard result == 0 else { throw POSIXError(.EIO) }
        let size = buffer.withUnsafeBytes { Int($0.loadUnaligned(as: UInt32.self)) }
        guard size <= buffer.count else { throw POSIXError(.EIO) }
        return Data(buffer.prefix(size))
    }

    private func mode(_ url: URL) throws -> mode_t {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { throw POSIXError(.EIO) }
        return info.st_mode & 0o777
    }

    private func expectUnsafe(_ body: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? RepositoryError, .unsafeDatabaseLocation, file: file, line: line)
        }
    }
}
