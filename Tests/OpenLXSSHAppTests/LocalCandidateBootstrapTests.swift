import Darwin
import Foundation
import XCTest
import OpenLXSSHCore

#if LOCAL_CANDIDATE
@MainActor final class LocalCandidateBootstrapTests: XCTestCase {
    private func fixture() throws -> (UUID, URL) {
        let id = UUID(), root = try LocalCandidateBootstrap.rootURL(namespace: id)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock {
            var info = stat()
            if lstat(root.path, &info) == 0 { try FileManager.default.removeItem(at: root) }
        }
        let marker = root.appendingPathComponent(LocalCandidateBootstrap.markerName)
        try LocalCandidateBootstrap.markerBytes(namespace: id).write(to: marker, options: .withoutOverwriting)
        XCTAssertEqual(chmod(marker.path, 0o600), 0)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("LocalFilesFixture"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return (id, root)
    }
    private func load(_ id: UUID, arguments: [String] = []) throws -> LocalCandidateBootstrap {
        let text = id.uuidString.lowercased()
        return try LocalCandidateBootstrap.load(bundleID: LocalCandidateBootstrap.bundlePrefix + text,
                                                schema: "1", value: text, arguments: arguments)
    }
    private func portableSupport() throws -> URL {
        let support = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
            .appendingPathComponent("OpenLXSSH-AppTests-PortableSupport-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: support) }
        return support
    }
    func testPortableStorageRequiresAnExplicitExactModeWithoutRelaxingExistingMetadata() throws {
        XCTAssertFalse(try LocalCandidateBootstrap.portableStorage(nil))
        XCTAssertTrue(try LocalCandidateBootstrap.portableStorage("application-support-v1"))
        let rejectedModes: [Any] = ["", "2", "Application-Support-v1", "/tmp/other", 1, true, NSNull()]
        for mode in rejectedModes {
            XCTAssertThrowsError(try LocalCandidateBootstrap.portableStorage(mode))
        }
        let id = UUID(), text = id.uuidString.lowercased(), bundle = LocalCandidateBootstrap.bundlePrefix + text
        let invalidModes: [Any] = ["", "unknown", 1, true, NSNull()]
        for mode in invalidModes {
            XCTAssertThrowsError(try LocalCandidateBootstrap.load(bundleID: bundle, schema: "1", value: text,
                trialStorage: mode, arguments: []))
        }
        XCTAssertThrowsError(try LocalCandidateBootstrap.load(bundleID: bundle, schema: "2", value: text,
            trialStorage: "application-support-v1", arguments: []))
        XCTAssertThrowsError(try LocalCandidateBootstrap.load(bundleID: bundle, schema: "1", value: text,
            trialStorage: "application-support-v1", arguments: ["--data-dir", "/tmp/other"]))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try LocalCandidateBootstrap.rootURL(namespace: id).path))
    }
    func testPortableFirstLaunchPublishesOnlyCleanPrivateStorageAndReopensWithoutTemporaryRoot() throws {
        let support = try portableSupport(), id = UUID()
        let first = try LocalCandidateBootstrap.loadPortable(namespace: id, supportDirectory: support)
        let root = support.appendingPathComponent("OpenLXSSH Trial", isDirectory: true).appendingPathComponent(id.uuidString.lowercased(), isDirectory: true)
        XCTAssertEqual(first.root, root); XCTAssertTrue(first.isPortableTrial)
        XCTAssertEqual(try first.location.databaseDirectory(), root.appendingPathComponent("Data", isDirectory: true))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path).sorted(),
            [LocalCandidateBootstrap.markerName, "LocalFilesFixture"].sorted())
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("LocalFilesFixture").path).isEmpty)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.deletingLastPathComponent().path), [id.uuidString.lowercased()])
        for directory in [root.deletingLastPathComponent(), root, root.appendingPathComponent("LocalFilesFixture")] {
            let mode = try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber
            XCTAssertEqual(mode?.intValue, 0o700)
        }
        let marker = root.appendingPathComponent(LocalCandidateBootstrap.markerName)
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: marker.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let original = try Data(contentsOf: marker)
        let second = try LocalCandidateBootstrap.loadPortable(namespace: id, supportDirectory: support)
        XCTAssertEqual(second.root, first.root); XCTAssertEqual(try Data(contentsOf: marker), original)
        XCTAssertTrue(first.dataDescription.contains("退出和重新安装不会清空试用数据"))
        XCTAssertFalse(first.dataDescription.contains("临时数据可能被系统清理"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: try LocalCandidateBootstrap.rootURL(namespace: id).path))
        // A persistent root must not weaken the old temp-only location capability.
        XCTAssertThrowsError(try AppDataLocation.isolated(root).databaseDirectory())
    }
    func testPortableModelsKeepSavedConfigurationAndNamespaceAcrossReopenWithoutConnecting() async throws {
        let support = try portableSupport(), id = UUID()
        let bootstrap = try LocalCandidateBootstrap.loadPortable(namespace: id, supportDirectory: support)
        let first = bootstrap.makeModel(preferencesDefaults: nil)
        let initiallyLoaded = await first.reload(); XCTAssertTrue(initiallyLoaded)
        XCTAssertTrue(first.hosts.isEmpty); XCTAssertTrue(first.keys.isEmpty); XCTAssertTrue(first.sessions.tabs.isEmpty)
        let metadata = try await first.repository.securityMetadata()
        XCTAssertTrue(metadata.credentials.isEmpty)
        XCTAssertEqual((first.security.credentials as? SystemCredentials)?.testNamespace, id)
        let host = HostConfiguration(name: "Portable trial persistence", address: "never-connected.invalid", username: "fixture")
        let saved = await first.saveHostSecurely(host, isNew: true, password: .manual); XCTAssertTrue(saved)
        // The trial uses normal local browsing, rather than locking the user inside
        // the bootstrap's empty fixture directory. Inspect only this test-owned sibling.
        first.files.localBrowser.go(support.path)
        let deadline = ContinuousClock.now + .seconds(3)
        while first.files.localBrowser.loading {
            guard ContinuousClock.now < deadline else { return XCTFail("Portable local browsing did not finish") }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(first.files.localBrowser.path.map(FileDisplay.path), support.path)
        XCTAssertNil(first.files.localBrowser.issue)
        await first.sessions.closeAll(); await first.files.closeForWindow(); try await first.security.close(); try await first.repository.close()
        let secondBootstrap = try LocalCandidateBootstrap.loadPortable(namespace: id, supportDirectory: support)
        let second = secondBootstrap.makeModel(preferencesDefaults: nil)
        let reloaded = await second.reload(); XCTAssertTrue(reloaded)
        XCTAssertEqual(secondBootstrap.root, bootstrap.root); XCTAssertEqual(second.hosts.map(\.id), [host.id])
        XCTAssertTrue(second.sessions.tabs.isEmpty)
        XCTAssertEqual((second.security.credentials as? SystemCredentials)?.testNamespace, id)
        await second.sessions.closeAll(); await second.files.closeForWindow(); try await second.security.close(); try await second.repository.close()
    }
    func testPortableExistingUnknownOrIncompleteRootsAreNeverAdoptedOrRepaired() throws {
        let support = try portableSupport(), id = UUID(), trials = support.appendingPathComponent("OpenLXSSH Trial", isDirectory: true)
        try FileManager.default.createDirectory(at: trials, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let root = trials.appendingPathComponent(id.uuidString.lowercased(), isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let sentinel = root.appendingPathComponent("unknown-owner")
        try Data("preserve original".utf8).write(to: sentinel)
        XCTAssertThrowsError(try LocalCandidateBootstrap.loadPortable(namespace: id, supportDirectory: support))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), ["unknown-owner"])
        XCTAssertEqual(try Data(contentsOf: sentinel), Data("preserve original".utf8))
        for missing in [LocalCandidateBootstrap.markerName, "LocalFilesFixture"] {
            let value = try LocalCandidateBootstrap.loadPortable(namespace: UUID(), supportDirectory: support)
            let removed = value.root.appendingPathComponent(missing)
            try FileManager.default.removeItem(at: removed)
            XCTAssertThrowsError(try value.location.databaseDirectory())
            XCTAssertThrowsError(try LocalCandidateBootstrap.loadPortable(namespace: value.namespace, supportDirectory: support))
            XCTAssertFalse(FileManager.default.fileExists(atPath: removed.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: value.root.appendingPathComponent("Data").path))
        }
        for bytes in [Data(), Data("unknown marker".utf8), Data(repeating: 65, count: 4096)] {
            let value = try LocalCandidateBootstrap.loadPortable(namespace: UUID(), supportDirectory: support)
            let marker = value.root.appendingPathComponent(LocalCandidateBootstrap.markerName)
            try bytes.write(to: marker)
            XCTAssertThrowsError(try value.location.databaseDirectory())
            XCTAssertThrowsError(try LocalCandidateBootstrap.loadPortable(namespace: value.namespace, supportDirectory: support))
            XCTAssertEqual(try Data(contentsOf: marker), bytes)
        }
    }
    func testPortableSymlinkedRootsMarkersLocalDirectoriesAndHardlinkedMarkersReject() throws {
        for name in ["parent", "root", LocalCandidateBootstrap.markerName, "LocalFilesFixture", "hardlink"] {
            let support = try portableSupport(), id = UUID()
            let value = try LocalCandidateBootstrap.loadPortable(namespace: id, supportDirectory: support)
            if name == "hardlink" {
                XCTAssertEqual(link(value.root.appendingPathComponent(LocalCandidateBootstrap.markerName).path, value.root.appendingPathComponent("marker-copy").path), 0)
            } else {
                let original = name == "parent" ? value.root.deletingLastPathComponent() : name == "root" ? value.root : value.root.appendingPathComponent(name)
                let moved = original.appendingPathExtension("owned-original")
                try FileManager.default.moveItem(at: original, to: moved)
                try FileManager.default.createSymbolicLink(at: original, withDestinationURL: moved)
            }
            XCTAssertThrowsError(try value.location.databaseDirectory())
            XCTAssertThrowsError(try LocalCandidateBootstrap.loadPortable(namespace: id, supportDirectory: support))
        }
    }
    func testPortableUnsafeModesRejectWithoutChmodOrCreatingReplacementData() throws {
        for name in ["parent", "root", LocalCandidateBootstrap.markerName, "LocalFilesFixture"] {
            let support = try portableSupport(), value = try LocalCandidateBootstrap.loadPortable(namespace: UUID(), supportDirectory: support)
            let url = name == "parent" ? value.root.deletingLastPathComponent() : name == "root" ? value.root : value.root.appendingPathComponent(name)
            let mode: mode_t = name == LocalCandidateBootstrap.markerName ? 0o644 : 0o750
            XCTAssertEqual(chmod(url.path, mode), 0)
            XCTAssertThrowsError(try value.location.databaseDirectory())
            XCTAssertThrowsError(try LocalCandidateBootstrap.loadPortable(namespace: value.namespace, supportDirectory: support))
            XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.intValue, Int(mode))
            XCTAssertFalse(FileManager.default.fileExists(atPath: value.root.appendingPathComponent("Data").path))
        }
    }
    func testPortableACLsRejectWithoutRemovingAccessRules() throws {
        for name in ["parent", "root", LocalCandidateBootstrap.markerName, "LocalFilesFixture"] {
            let support = try portableSupport(), value = try LocalCandidateBootstrap.loadPortable(namespace: UUID(), supportDirectory: support)
            let url = name == "parent" ? value.root.deletingLastPathComponent() : name == "root" ? value.root : value.root.appendingPathComponent(name)
            var acl = acl_init(1), entry: acl_entry_t?, permissions: acl_permset_t?, principal = UUID().uuid
            guard acl != nil else { throw LocalCandidateBootstrap.Failure.storage }
            defer { if let acl { acl_free(UnsafeMutableRawPointer(acl)) } }
            guard acl_create_entry(&acl, &entry) == 0, let entry,
                  acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0, acl_set_qualifier(entry, &principal) == 0,
                  acl_get_permset(entry, &permissions) == 0, let permissions,
                  acl_add_perm(permissions, ACL_READ_DATA) == 0, acl_set_file(url.path, ACL_TYPE_EXTENDED, acl) == 0 else { throw LocalCandidateBootstrap.Failure.storage }
            addTeardownBlock {
                guard let empty = acl_init(0) else { throw LocalCandidateBootstrap.Failure.storage }
                defer { acl_free(UnsafeMutableRawPointer(empty)) }
                guard acl_set_file(url.path, ACL_TYPE_EXTENDED, empty) == 0 else { throw LocalCandidateBootstrap.Failure.storage }
            }
            XCTAssertThrowsError(try value.location.databaseDirectory())
            XCTAssertThrowsError(try LocalCandidateBootstrap.loadPortable(namespace: value.namespace, supportDirectory: support))
            let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw LocalCandidateBootstrap.Failure.storage }
            defer { Darwin.close(fd) }
            XCTAssertThrowsError(try AppFileSecurity.requireNoACL(fd))
        }
    }
    func testMetadataRequiresExactCanonicalNamespaceAndMatchingBundleWithoutArguments() throws {
        let id = UUID(), text = id.uuidString.lowercased(), bundle = LocalCandidateBootstrap.bundlePrefix + text
        XCTAssertEqual(try LocalCandidateBootstrap.namespace(bundleID: bundle, schema: "1", value: text, arguments: []), id)
        let schemas: [Any?] = [nil, "2", 1, true, NSNull()]
        for schema in schemas {
            XCTAssertThrowsError(try LocalCandidateBootstrap.namespace(bundleID: bundle, schema: schema, value: text, arguments: []))
        }
        let namespaces: [Any?] = [nil, "", text.uppercased(), "../" + text, UUID().uuidString.lowercased(), NSNull()]
        for namespace in namespaces {
            XCTAssertThrowsError(try LocalCandidateBootstrap.namespace(bundleID: bundle, schema: "1", value: namespace, arguments: []))
        }
        for wrongBundle in ["org.openlxssh.OpenLXSSH", "org.openlxssh.OpenLXSSH.EngineeringPreview", bundle + ".extra"] {
            XCTAssertThrowsError(try LocalCandidateBootstrap.namespace(bundleID: wrongBundle, schema: "1", value: text, arguments: []))
        }
    }
    func testEveryOldFixtureAndCandidateArgumentRejectsBeforeCreatingStorage() throws {
        let id = UUID(), root = try LocalCandidateBootstrap.rootURL(namespace: id)
        for arguments in [["--local-candidate"], ["--local-candidate-help"], ["--isolated-preview"], ["--contract", "/tmp/unknown"],
                          ["--self-test-data-dir", "/tmp/unknown"], ["--real-fixture-help"], ["--native-app-fixture-help"],
                          ["--native-password-fixture-help"], ["--native-mfa-fixture-help"], ["--native-files-fixture-help"],
                          ["--native-files-conflict-help"], ["--native-files-cancel-help"], ["--native-trust-fixture-help"],
                          ["--native-concurrent-fixture-help"], ["--authorized-local-fixture"]] {
            XCTAssertThrowsError(try load(id, arguments: arguments))
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.path))
        }
    }
    func testMissingRootFailsWithoutCreatingIt() throws {
        let id = UUID(), root = try LocalCandidateBootstrap.rootURL(namespace: id)
        XCTAssertThrowsError(try load(id))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.path))
    }
    func testMissingLocalDirectoryFailsWithoutCreatingOrRepairingIt() throws {
        let (id, root) = try fixture(), local = root.appendingPathComponent("LocalFilesFixture")
        try FileManager.default.removeItem(at: local)
        XCTAssertThrowsError(try load(id))
        XCTAssertFalse(FileManager.default.fileExists(atPath: local.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("Data").path))
    }
    func testPreparedRootLoadsWithoutChangingContentsAndCanBeReopened() throws {
        let (id, root) = try fixture(), before = try FileManager.default.contentsOfDirectory(atPath: root.path).sorted()
        let first = try load(id), second = try load(id)
        XCTAssertEqual(first.namespace, id); XCTAssertEqual(first.root, root); XCTAssertEqual(second.root, root)
        XCTAssertEqual(try first.location.databaseDirectory(), root.appendingPathComponent("Data", isDirectory: true))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path).sorted(), before)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("Data").path))
    }
    func testMissingWrongAndOversizedMarkerFailWithoutRepair() throws {
        for bytes in [Data(), Data("unknown owner\n".utf8), Data(repeating: 65, count: 4096)] {
            let (id, root) = try fixture(), marker = root.appendingPathComponent(LocalCandidateBootstrap.markerName)
            try bytes.write(to: marker)
            XCTAssertThrowsError(try load(id)); XCTAssertEqual(try Data(contentsOf: marker), bytes)
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("Data").path))
        }
        let (id, root) = try fixture(), marker = root.appendingPathComponent(LocalCandidateBootstrap.markerName)
        try FileManager.default.removeItem(at: marker)
        XCTAssertThrowsError(try load(id)); XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }
    func testRootMarkerAndLocalSymlinksAndMarkerHardlinkReject() throws {
        for name in ["root", LocalCandidateBootstrap.markerName, "LocalFilesFixture", "hardlink"] {
            let (id, root) = try fixture()
            if name == "hardlink" {
                XCTAssertEqual(link(root.appendingPathComponent(LocalCandidateBootstrap.markerName).path, root.appendingPathComponent("marker-copy").path), 0)
            } else {
                let original = name == "root" ? root : root.appendingPathComponent(name)
                let moved = original.appendingPathExtension("owned-original")
                try FileManager.default.moveItem(at: original, to: moved)
                if name == "root" { addTeardownBlock { try FileManager.default.removeItem(at: moved) } }
                try FileManager.default.createSymbolicLink(at: original, withDestinationURL: moved)
            }
            XCTAssertThrowsError(try load(id))
        }
    }
    func testUnsafeRootMarkerAndLocalModesRemainUnchangedAfterRefusal() throws {
        for name in ["root", LocalCandidateBootstrap.markerName, "LocalFilesFixture"] {
            let (id, root) = try fixture(), url = name == "root" ? root : root.appendingPathComponent(name)
            let unsafe: mode_t = name == LocalCandidateBootstrap.markerName ? 0o644 : 0o750
            XCTAssertEqual(chmod(url.path, unsafe), 0)
            XCTAssertThrowsError(try load(id))
            let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
            XCTAssertEqual(mode?.intValue, Int(unsafe))
        }
    }
    func testExtendedACLOnRootMarkerOrLocalDirectoryIsRejectedWithoutStripping() throws {
        for name in ["root", LocalCandidateBootstrap.markerName, "LocalFilesFixture"] {
            let (id, root) = try fixture(), url = name == "root" ? root : root.appendingPathComponent(name)
            var acl = acl_init(1), entry: acl_entry_t?, permissions: acl_permset_t?, principal = UUID().uuid
            guard acl != nil else { throw LocalCandidateBootstrap.Failure.storage }
            defer { if let acl { acl_free(UnsafeMutableRawPointer(acl)) } }
            guard acl_create_entry(&acl, &entry) == 0, let entry,
                  acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0, acl_set_qualifier(entry, &principal) == 0,
                  acl_get_permset(entry, &permissions) == 0, let permissions,
                  acl_add_perm(permissions, ACL_READ_DATA) == 0, acl_set_file(url.path, ACL_TYPE_EXTENDED, acl) == 0 else { throw LocalCandidateBootstrap.Failure.storage }
            addTeardownBlock {
                guard let empty = acl_init(0) else { throw LocalCandidateBootstrap.Failure.storage }
                defer { acl_free(UnsafeMutableRawPointer(empty)) }
                guard acl_set_file(url.path, ACL_TYPE_EXTENDED, empty) == 0 else { throw LocalCandidateBootstrap.Failure.storage }
            }
            XCTAssertThrowsError(try load(id))
            let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw LocalCandidateBootstrap.Failure.storage }
            defer { Darwin.close(fd) }
            XCTAssertThrowsError(try AppFileSecurity.requireNoACL(fd))
        }
    }
    func testModelsUseOnlyTheNamespaceAndSameRealRepositoryAcrossReopenWithoutConnecting() async throws {
        let (id, root) = try fixture(), first = try load(id).makeModel(preferencesDefaults: nil)
        let credentials = try XCTUnwrap(first.security.credentials as? SystemCredentials)
        XCTAssertEqual(credentials.testNamespace, id)
        let ordinary = try XCTUnwrap(first.sessionBuilders.ordinary as? NativeSessionBuilder)
        let prepared = try XCTUnwrap(first.sessionBuilders.prepared as? NativeSessionBuilder)
        XCTAssertTrue(ordinary === prepared); XCTAssertTrue(ordinary.environment === first.sessionEnvironment)
        let files = try XCTUnwrap(first.files.connector as? LibSSH2FilesConnector)
        XCTAssertTrue(files.environment === first.sessionEnvironment)
        XCTAssertNil(first.desktopPreferencesDefaults); XCTAssertFalse(first.isEngineeringPreview)
        XCTAssertTrue(first.sessions.tabs.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("Data").path))
        let loaded = await first.reload(); XCTAssertTrue(loaded)
        let host = HostConfiguration(name: "Public local candidate", address: "fixture.invalid", username: "fixture")
        let saved = await first.saveHostSecurely(host, isNew: true, password: .manual); XCTAssertTrue(saved)
        await first.sessions.closeAll(); await first.files.closeForWindow(); try await first.security.close(); try await first.repository.close()
        let second = try load(id).makeModel(preferencesDefaults: nil)
        let reloaded = await second.reload(); XCTAssertTrue(reloaded)
        XCTAssertEqual(second.hosts.map(\.id), [host.id]); XCTAssertTrue(second.sessions.tabs.isEmpty)
        XCTAssertEqual((second.security.credentials as? SystemCredentials)?.testNamespace, id)
        await second.sessions.closeAll(); await second.files.closeForWindow(); try await second.security.close(); try await second.repository.close()
    }
}
#endif
