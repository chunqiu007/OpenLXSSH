import Darwin
import Foundation
import OpenLXSSHTrust
import COpenLXSSHAskpass
@testable import OpenLXSSHTransport
import XCTest

@MainActor
final class SessionWorkspaceACLTests: XCTestCase {
    private var fixture: URL!
    private let inheritableEveryone = "everyone allow read,write,execute,append,delete,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,writesecurity,chown,file_inherit,directory_inherit"

    override func setUp() async throws {
        let package = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let scratch = package.appendingPathComponent(".build/acl-test-runtime")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        fixture = scratch.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: fixture, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }

    override func tearDown() async throws {
        try FileManager.default.removeItem(at: fixture)
    }

    private func chmodACL(_ path: String, entry: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", entry, path]
        try process.run(); process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
    }

    private func hasExtendedEntry(_ path: String) throws -> Bool {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw TransportError.invalidConfiguration }
        defer { Darwin.close(descriptor) }
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else { throw TransportError.invalidConfiguration }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        return acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == 0
    }

    func testInheritedEveryoneACLRejectsRootBeforeCreatingSession() throws {
        try chmodACL(fixture.path, entry: inheritableEveryone)
        let root = fixture.appendingPathComponent("Sessions")
        XCTAssertEqual(mkdir(root.path, 0o700), 0)
        var metadata = stat()
        XCTAssertEqual(lstat(root.path, &metadata), 0)
        XCTAssertEqual(metadata.st_mode & 0o7777, 0o700)
        XCTAssertTrue(try hasExtendedEntry(root.path))
        let original = "Host openlxssh-direct\n    HostName server.example\n    StrictHostKeyChecking yes\n    ProxyCommand none\n"
        do {
            let workspace = try SessionWorkspace(root: AbsolutePath(root.path), text: original)
            // Failure diagnostics use only the owned synthetic configuration and
            // ssh -G: no connection is made and no ProxyCommand is executed.
            let file = workspace.directory + "/ssh_config"
            XCTAssertTrue(try hasExtendedEntry(workspace.directory))
            XCTAssertTrue(try hasExtendedEntry(file))
            XCTAssertEqual(lstat(file, &metadata), 0)
            XCTAssertEqual(metadata.st_mode & 0o7777, 0o600)
            let modified = original.replacingOccurrences(of: "StrictHostKeyChecking yes", with: "StrictHostKeyChecking no")
                .replacingOccurrences(of: "ProxyCommand none", with: "ProxyCommand /usr/bin/true")
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: file))
            try handle.truncate(atOffset: 0); try handle.write(contentsOf: Data(modified.utf8)); try handle.close()
            let invocation = workspace.invocation(preview: true)
            let result = try BoundedTool.run(invocation.executable, invocation.arguments, seconds: 3)
            XCTAssertEqual(result.status, 0)
            let text = String(decoding: result.output, as: UTF8.self)
            XCTAssertTrue(text.contains("stricthostkeychecking false"))
            XCTAssertTrue(text.contains("proxycommand /usr/bin/true"))
            XCTFail("Inherited everyone ACE accepted despite mode0700/0600; real offline ssh -G reports stricthostkeychecking false and proxycommand /usr/bin/true")
        } catch {
            XCTAssertEqual(error as? TransportError, .invalidConfiguration)
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [])
        XCTAssertTrue(try hasExtendedEntry(root.path), "Reject without clearing the caller's ACL")
    }

    private func expectInvalid(file: StaticString = #filePath, line: UInt = #line, _ operation: () throws -> Void) {
        XCTAssertThrowsError(try operation(), file: file, line: line) {
            XCTAssertEqual($0 as? TransportError, .invalidConfiguration, file: file, line: line)
        }
    }

    private func makeDirectory(_ name: String) throws -> URL {
        let path = fixture.appendingPathComponent(name)
        guard mkdir(path.path, 0o700) == 0 else { throw TransportError.invalidConfiguration }
        return path
    }

    func testAnyRootACEIsRejectedWithoutChangingExistingConfigOrACL() throws {
        for (index, entry) in ["everyone allow read", "everyone deny writeextattr", inheritableEveryone].enumerated() {
            let root = try makeDirectory("root-\(index)")
            let existing = root.appendingPathComponent("ssh_config")
            let original = Data("owned pre-existing config\n".utf8)
            try original.write(to: existing)
            try chmodACL(root.path, entry: entry)
            expectInvalid { _ = try SessionWorkspace(root: AbsolutePath(root.path), text: "must-not-be-written") }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), ["ssh_config"])
            XCTAssertEqual(try Data(contentsOf: existing), original)
            XCTAssertTrue(try hasExtendedEntry(root.path))
        }
    }

    func testDirectoryACLAddedAfterRootCheckRejectsBeforeConfigCreation() throws {
        var reachedDirectory = false
        expectInvalid {
            _ = try SessionWorkspace(probeRoot: AbsolutePath(fixture.path), text: "must-not-be-written") { phase, path in
                guard phase == .directoryOpened else { return }
                reachedDirectory = true
                try self.chmodACL(path, entry: self.inheritableEveryone)
                XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: path), [])
            }
        }
        XCTAssertTrue(reachedDirectory)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: fixture.path), [])
    }

    func testFileACLAddedBeforeWriteRejectsWithoutWritingOneByte() throws {
        var retained: FileHandle?
        defer { try? retained?.close() }
        expectInvalid {
            _ = try SessionWorkspace(probeRoot: AbsolutePath(fixture.path), text: "must-not-be-written") { phase, path in
                guard phase == .fileOpened else { return }
                let file = path + "/ssh_config"
                retained = try FileHandle(forReadingFrom: URL(fileURLWithPath: file))
                try self.chmodACL(file, entry: "everyone allow read,write")
                XCTAssertTrue(try self.hasExtendedEntry(file))
            }
        }
        let handle = try XCTUnwrap(retained)
        var metadata = stat()
        XCTAssertEqual(fstat(handle.fileDescriptor, &metadata), 0)
        XCTAssertEqual(metadata.st_mode & 0o7777, 0o600)
        XCTAssertEqual(metadata.st_size, 0)
        XCTAssertEqual(metadata.st_nlink, 0, "Rejected owned file is unlinked")
        XCTAssertNil(try handle.readToEnd(), "An empty file is already at EOF")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: fixture.path), [])
    }

    func testRootAndDirectoryAreRecheckedBeforeWrite() throws {
        for target in ["root", "directory"] {
            let root = try makeDirectory(target)
            var retained: FileHandle?
            defer { try? retained?.close() }
            expectInvalid {
                _ = try SessionWorkspace(probeRoot: AbsolutePath(root.path), text: "must-not-be-written") { phase, path in
                    guard phase == .fileOpened else { return }
                    retained = try FileHandle(forReadingFrom: URL(fileURLWithPath: path + "/ssh_config"))
                    try self.chmodACL(target == "root" ? root.path : path, entry: "everyone allow read,write")
                }
            }
            let handle = try XCTUnwrap(retained)
            var metadata = stat()
            XCTAssertEqual(fstat(handle.fileDescriptor, &metadata), 0)
            XCTAssertEqual(metadata.st_size, 0)
            XCTAssertNil(try handle.readToEnd(), "An empty file is already at EOF")
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [])
        }
    }

    func testACLAddedAfterWriteRejectsAndReleasesOwnedResources() throws {
        let original = Data("Host openlxssh-direct\n    StrictHostKeyChecking yes\n".utf8)
        for target in ["root", "directory", "file"] {
            let root = try makeDirectory("post-write-" + target)
            var retained: FileHandle?
            defer { try? retained?.close() }
            expectInvalid {
                _ = try SessionWorkspace(probeRoot: AbsolutePath(root.path), text: String(decoding: original, as: UTF8.self)) { phase, path in
                    guard phase == .fileWritten else { return }
                    retained = try FileHandle(forReadingFrom: URL(fileURLWithPath: path + "/ssh_config"))
                    let unsafePath = target == "root" ? root.path : (target == "directory" ? path : path + "/ssh_config")
                    try self.chmodACL(unsafePath, entry: "everyone allow read,write")
                }
            }
            XCTAssertEqual(try XCTUnwrap(retained).readToEnd(), original)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [])
        }
    }

    func testLaunchValidationRejectsRuntimeRootDirectoryAndFileACLWithoutChangingConfig() throws {
        let original = Data("Host openlxssh-direct\n    HostName server.example\n    StrictHostKeyChecking yes\n    ProxyCommand none\n".utf8)
        for target in ["root", "directory", "file"] {
            let root = try makeDirectory("launch-" + target)
            var workspace: SessionWorkspace? = try SessionWorkspace(root: AbsolutePath(root.path), text: String(decoding: original, as: UTF8.self))
            let path = try XCTUnwrap(workspace).directory
            let file = URL(fileURLWithPath: path + "/ssh_config")
            try XCTUnwrap(workspace).validateForLaunch()
            let unsafePath = target == "root" ? root.path : (target == "directory" ? path : file.path)
            try chmodACL(unsafePath, entry: "everyone allow read,write")
            expectInvalid { try XCTUnwrap(workspace).validateForLaunch() }
            XCTAssertEqual(try Data(contentsOf: file), original)
            XCTAssertTrue(try hasExtendedEntry(unsafePath), "Launch validation must not clear ACLs")
            workspace = nil
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [])
        }
    }

    func testLaunchValidationRejectsReplacedConfig() throws {
        let workspace = try SessionWorkspace(root: AbsolutePath(fixture.path), text: "original controlled config\n")
        let original = workspace.directory + "/ssh_config", moved = workspace.directory + "/original"
        XCTAssertEqual(rename(original, moved), 0)
        defer { _ = unlink(moved) }
        let replacement = open(original, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(replacement, 0)
        if replacement >= 0 { Darwin.close(replacement) }
        expectInvalid { try workspace.validateForLaunch() }
    }

    func testFilesecNoACLSuccessIgnoresStaleErrnoAndAllQueryErrorsFailClosed() throws {
        let descriptor = open(fixture.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { Darwin.close(descriptor) }
        errno = EINVAL
        XCTAssertNoThrow(try TransportFileSecurity.directory(descriptor))
        expectInvalid { _ = try TransportFileSecurity.metadataWithoutACL(-1) }
        let security = try XCTUnwrap(filesec_init())
        defer { filesec_free(security) }
        expectInvalid { try TransportFileSecurity.requireNoACL(in: security) }
        for failingProperty in [FILESEC_MODE, FILESEC_ACL] {
            expectInvalid {
                try TransportFileSecurity.requireNoACL(in: security) { _, property, present in
                    if property == failingProperty { errno = EIO; return -1 }
                    present.pointee = property == FILESEC_MODE ? 16 : 0
                    return 0
                }
            }
        }
        expectInvalid {
            try TransportFileSecurity.requireNoACL(in: security) { _, property, present in
                present.pointee = property == FILESEC_MODE ? 16 : 32
                return 0
            }
        }
    }

    func testManagedKeyRuntimeACLIsRejectedByFinalLaunchCheckWithoutReadingKeyContents() throws {
        let path = fixture.appendingPathComponent("synthetic-managed-key")
        // Deliberately empty: the transport boundary checks metadata only, and
        // must neither parse nor read the user's real private-key contents.
        let descriptor = open(path.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        if descriptor >= 0 { Darwin.close(descriptor) }
        let authentication = try SSHAuthentication(method: .privateKey(AbsolutePath(path.path), keyboardInteractive: true))
        let workspace = try SessionWorkspace(root: AbsolutePath(fixture.path), text: "synthetic controlled config\n")
        XCTAssertNoThrow(try TransportFileSecurity.validateAuthentication(authentication))
        XCTAssertNoThrow(try workspace.validateForLaunch(authentication: authentication))
        try chmodACL(path.path, entry: "everyone allow read")
        expectInvalid { try TransportFileSecurity.validateAuthentication(authentication) }
        expectInvalid { try workspace.validateForLaunch(authentication: authentication) }
        var metadata = stat()
        XCTAssertEqual(lstat(path.path, &metadata), 0)
        XCTAssertEqual(metadata.st_size, 0)
        XCTAssertEqual(metadata.st_mode & 0o7777, 0o600)
        XCTAssertTrue(try hasExtendedEntry(path.path))
    }

    func testManagedKeyMetadataPolicyStillRejectsModeSymlinkHardlinkAndSpecialFile() throws {
        let key = fixture.appendingPathComponent("synthetic-key"), link = fixture.appendingPathComponent("key-link")
        let descriptor = open(key.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        if descriptor >= 0 { Darwin.close(descriptor) }
        let authentication = try SSHAuthentication(method: .privateKey(AbsolutePath(key.path), keyboardInteractive: false))
        XCTAssertNoThrow(try TransportFileSecurity.validateAuthentication(authentication))
        XCTAssertEqual(chmod(key.path, 0o640), 0)
        expectInvalid { try TransportFileSecurity.validateAuthentication(authentication) }
        XCTAssertEqual(chmod(key.path, 0o600), 0)
        XCTAssertEqual(Darwin.link(key.path, link.path), 0)
        expectInvalid { try TransportFileSecurity.validateAuthentication(authentication) }
        XCTAssertEqual(unlink(link.path), 0)
        XCTAssertEqual(symlink(key.path, link.path), 0)
        let linkedAuthentication = try SSHAuthentication(method: .privateKey(AbsolutePath(link.path), keyboardInteractive: false))
        expectInvalid { try TransportFileSecurity.validateAuthentication(linkedAuthentication) }
        XCTAssertEqual(unlink(link.path), 0)
        XCTAssertEqual(mkfifo(link.path, 0o600), 0)
        expectInvalid { try TransportFileSecurity.validateAuthentication(linkedAuthentication) }
    }

    func testNormalWorkspaceOfflineSSHGAndRepeatedCleanupKeepDescriptorsBounded() throws {
        let before = ap_fd_count()
        for _ in 0..<20 {
            do {
                let workspace = try SessionWorkspace(root: AbsolutePath(fixture.path), text: "Host openlxssh-direct\n    HostName server.example\n    StrictHostKeyChecking yes\n    ProxyCommand none\n")
                try workspace.validateForLaunch()
                let invocation = workspace.invocation(preview: true)
                let result = try BoundedTool.run(invocation.executable, invocation.arguments, seconds: 3)
                XCTAssertEqual(result.status, 0)
                let output = String(decoding: result.output, as: UTF8.self)
                XCTAssertTrue(output.contains("stricthostkeychecking true"))
                XCTAssertFalse(output.contains("proxycommand /"))
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: fixture.path), [])
        }
        let after = ap_fd_count()
        XCTAssertLessThanOrEqual(after, before + 1)
    }
}
