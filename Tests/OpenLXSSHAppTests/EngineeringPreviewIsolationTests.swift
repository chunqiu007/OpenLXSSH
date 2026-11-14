import Darwin
import Foundation
import XCTest
import OpenLXSSHCore
#if PREVIEW_ISOLATED
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust
#endif

/// Source-only additions for the next separately released verification window.
/// Never opens Application Support, a real Keychain, a fixture or an App window.
@MainActor final class EngineeringPreviewIsolationTests: XCTestCase {
    private let id = "11111111-2222-4333-8444-555555555555"
    func testExactArgumentsAndPublicContractArePureClosedValues() throws {
        let path = EngineeringPreviewArguments.contractPath(runID: id)
        let options = try XCTUnwrap(EngineeringPreviewArguments.parse(["--isolated-preview", "--contract", path], mode: .isolatedPreview))
        XCTAssertEqual(options.runID, id); XCTAssertEqual(options.contractPath, path)
        XCTAssertEqual(EngineeringPreviewArguments.contractBytes(runID: id), Data(("OpenLXSSH Engineering-R2 isolated preview v1\nrunID=" + id + "\nmode=offline\nseed=none\n").utf8))
        for args in [[], ["--isolated-preview"], ["--isolated-preview", "--contract"],
                     ["--contract", path, "--isolated-preview"], ["--isolated-preview", "--contract", path, "--contract", path],
                     ["--isolated-preview", "--contract", path + "/.."], ["--isolated-preview", "--contract", "/tmp/preview-contract.txt"],
                     ["--isolated-preview", "--contract", path.replacingOccurrences(of: id, with: id.uppercased() + "x")]] {
            XCTAssertThrowsError(try EngineeringPreviewArguments.parse(args, mode: .isolatedPreview))
        }
        XCTAssertNil(try EngineeringPreviewArguments.parse([], mode: .shipping))
        XCTAssertNil(try EngineeringPreviewArguments.parse([], mode: .hostProbe))
    }
    func testEveryOldFamilyAndUnsupportedPreviewModeRejectBeforeAnyIO() throws {
        let args = ["--isolated-preview", "--contract", EngineeringPreviewArguments.contractPath(runID: id)]
        for mode in [EngineeringPreviewArguments.BuildMode.shipping, .hostProbe] {
            XCTAssertThrowsError(try EngineeringPreviewArguments.parse(args, mode: mode))
            XCTAssertThrowsError(try EngineeringPreviewArguments.parse(["--contract"], mode: mode))
            XCTAssertThrowsError(try EngineeringPreviewArguments.parse(["--isolated-preview-help"], mode: mode))
        }
        for family in ["--self-test-data-dir", "--real-fixture-help", "--native-app-fixture-help", "--native-password-fixture-help",
                       "--native-mfa-fixture-help", "--native-files-fixture-help", "--native-files-conflict-help", "--native-files-cancel-help",
                       "--native-trust-fixture-help", "--native-concurrent-fixture-help", "--authorized-local-fixture", "--primary-released"] {
            XCTAssertThrowsError(try EngineeringPreviewArguments.parse([family], mode: .isolatedPreview))
            XCTAssertThrowsError(try EngineeringPreviewArguments.parse(args + [family], mode: .isolatedPreview))
        }
    }
    func testSourceGatesPrecedeNSAppAndDoNotAlterShippingBuildSettings() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let entry = try String(contentsOf: root.appendingPathComponent("Application/OpenLXSSH/OpenLXSSHApp.swift"), encoding: .utf8)
        let gate = try XCTUnwrap(entry.range(of: "EngineeringPreviewArguments.parse")), app = try XCTUnwrap(entry.range(of: "let application = NSApplication.shared"))
        XCTAssertLessThan(gate.lowerBound, app.lowerBound)
        XCTAssertTrue(entry.contains("try EngineeringPreviewContract.load(options)")); XCTAssertTrue(entry.contains("exit(64)"))
        XCTAssertTrue(entry.contains("model = AppModel(repository: AppRepository(), preferencesDefaults: .standard)"))
        let repository = try String(contentsOf: root.appendingPathComponent("Application/OpenLXSSH/AppRepository.swift"), encoding: .utf8)
        XCTAssertTrue(repository.contains("#if PREVIEW_ISOLATED && HOST_PROBE")); XCTAssertTrue(repository.contains("#if PREVIEW_ISOLATED && !DEBUG"))
        let project = try String(contentsOf: root.appendingPathComponent("OpenLXSSH.xcodeproj/project.pbxproj"), encoding: .utf8)
        XCTAssertFalse(project.contains("SWIFT_ACTIVE_COMPILATION_CONDITIONS = \"DEBUG PREVIEW_ISOLATED"))
        XCTAssertFalse(project.contains("PRODUCT_BUNDLE_IDENTIFIER = org.openlxssh.OpenLXSSH.EngineeringPreview"))
    }

    #if PREVIEW_ISOLATED
    private func root() throws -> EngineeringPreviewRoot {
        let value = try EngineeringPreviewRoot.createFresh(runID: UUID().uuidString.lowercased())
        // Cleanup is only this test's newly created tree, not an application cleanup feature.
        let url = value.url
        addTeardownBlock { try FileManager.default.removeItem(at: url) }
        return value
    }
    private func expectRefused(_ operation: () async throws -> Void, file: StaticString = #filePath, line: UInt = #line) async {
        do { try await operation(); XCTFail("Expected explicit refusal", file: file, line: line) } catch {}
    }
    private func setSyntheticACL(_ url: URL) throws {
        var acl = acl_init(1)
        guard acl != nil else { throw EngineeringPreviewFailure.unsafeStorage }
        defer { if let acl { acl_free(UnsafeMutableRawPointer(acl)) } }
        var entry: acl_entry_t?, permissions: acl_permset_t?, identity = UUID().uuid
        // A synthetic principal avoids name-service lookup and text ACL syntax.
        guard acl_create_entry(&acl, &entry) == 0, let entry,
              acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0,
              acl_set_qualifier(entry, &identity) == 0,
              acl_get_permset(entry, &permissions) == 0, let permissions,
              acl_add_perm(permissions, ACL_READ_DATA) == 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        guard acl_set_file(url.path, ACL_TYPE_EXTENDED, acl) == 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        addTeardownBlock {
            guard let empty = acl_init(0) else { throw EngineeringPreviewFailure.unsafeStorage }
            defer { acl_free(UnsafeMutableRawPointer(empty)) }
            guard acl_set_file(url.path, ACL_TYPE_EXTENDED, empty) == 0 else { throw EngineeringPreviewFailure.unsafeStorage }
        }
    }
    func testContractBytesRejectUnknownLinesWrongRunAndSecretFields() throws {
        let bytes = EngineeringPreviewArguments.contractBytes(runID: id)
        XCTAssertNoThrow(try EngineeringPreviewContract.validate(bytes, runID: id))
        for changed in [bytes + Data("password=public-dummy\n".utf8), Data(bytes.dropLast()),
                        Data(repeating: 65, count: 513), EngineeringPreviewArguments.contractBytes(runID: UUID().uuidString.lowercased())] {
            XCTAssertThrowsError(try EngineeringPreviewContract.validate(changed, runID: id))
        }
        // The same bounded no-follow file reader is used by contracts and markers.
        let value = try root(), marker = value.url.appendingPathComponent(EngineeringPreviewRoot.markerName)
        let fd = open(marker.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { Darwin.close(fd) }
        XCTAssertNoThrow(try EngineeringPreviewContract.validate(EngineeringPreviewRoot.readStable(fd, maximum: 512), runID: value.runID))
    }
    func testFreshRootUsesDarwinTempAndRefusesExistingEvenAfterOwnerRelease() throws {
        var value: EngineeringPreviewRoot? = try root()
        let runID: String
        do {
            let first = try XCTUnwrap(value); runID = first.runID
            XCTAssertEqual(first.url.deletingLastPathComponent(), try EngineeringPreviewRoot.temporaryBase())
            XCTAssertTrue(first.url.lastPathComponent.hasPrefix(EngineeringPreviewRoot.prefix))
            XCTAssertThrowsError(try AppDataLocation.isolated(first.url).databaseDirectory())
            XCTAssertThrowsError(try EngineeringPreviewRoot.createFresh(runID: runID))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: first.localURL.path), [])
        }
        value = nil
        XCTAssertThrowsError(try EngineeringPreviewRoot.createFresh(runID: runID))
    }
    func testUnknownExistingRootAndSymlinkAreNeverAdoptedOrRepaired() throws {
        let base = try EngineeringPreviewRoot.temporaryBase(), target = try root()
        for isLink in [false, true] {
            let runID = UUID().uuidString.lowercased(), unknown = base.appendingPathComponent(EngineeringPreviewRoot.prefix + runID)
            if isLink { try FileManager.default.createSymbolicLink(at: unknown, withDestinationURL: target.url) }
            else { try FileManager.default.createDirectory(at: unknown, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o750]) }
            defer { try? FileManager.default.removeItem(at: unknown) }
            let before = try FileManager.default.attributesOfItem(atPath: unknown.path)
            XCTAssertThrowsError(try EngineeringPreviewRoot.createFresh(runID: runID))
            let after = try FileManager.default.attributesOfItem(atPath: unknown.path)
            XCTAssertEqual(before[.posixPermissions] as? NSNumber, after[.posixPermissions] as? NSNumber)
            XCTAssertEqual(before[.systemFileNumber] as? NSNumber, after[.systemFileNumber] as? NSNumber)
        }
    }
    func testMarkerHardlinkReplacementAndUnsafeModeRejectWithoutRepair() throws {
        let value = try root(), marker = value.url.appendingPathComponent(EngineeringPreviewRoot.markerName)
        let link = value.url.appendingPathComponent("marker-link")
        XCTAssertEqual(Darwin.link(marker.path, link.path), 0)
        XCTAssertThrowsError(try value.validate()); XCTAssertEqual(unlink(link.path), 0)
        try value.validate()
        XCTAssertEqual(chmod(value.url.path, 0o750), 0)
        XCTAssertThrowsError(try value.validate())
        let mode = try FileManager.default.attributesOfItem(atPath: value.url.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o750); XCTAssertEqual(chmod(value.url.path, 0o700), 0)
        try FileManager.default.moveItem(at: marker, to: value.url.appendingPathComponent("old-marker"))
        try EngineeringPreviewArguments.contractBytes(runID: value.runID).write(to: marker)
        XCTAssertEqual(chmod(marker.path, 0o600), 0)
        XCTAssertThrowsError(try value.validate())
    }
    func testRootAndLocalACLFailClosedWithoutStrippingPolicy() throws {
        for local in [false, true] {
            let value = try root(), url = local ? value.localURL : value.url
            try setSyntheticACL(url)
            XCTAssertThrowsError(try value.validate())
            let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            defer { Darwin.close(fd) }
            XCTAssertThrowsError(try AppFileSecurity.requireNoACL(fd))
        }
    }
    func testRootRenameAndSamePathReplacementRejectsRepositoryBeforeOpeningDatabase() async throws {
        let value = try root(), moved = value.url.appendingPathExtension("moved")
        try FileManager.default.moveItem(at: value.url, to: moved)
        addTeardownBlock { try FileManager.default.removeItem(at: moved) }
        try FileManager.default.createDirectory(at: value.url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let repository = AppRepository(location: .engineeringPreview(value))
        await expectRefused { _ = try await repository.snapshot(query: HostQuery()) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: value.url.appendingPathComponent("Data").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: moved.appendingPathComponent("Data").path))
        try await repository.close()
    }
    func testDatabaseAdmissionAcceptsPhysicalAliasAndRejectsOtherRootOrFilename() throws {
        let value = try root(), other = try root()
        let database = try OpenLXSSHDatabase(directory: value.databaseDirectory())
        defer { try? database.close() }
        let otherDatabase = try OpenLXSSHDatabase(directory: other.databaseDirectory())
        defer { try? otherDatabase.close() }
        try value.recordDatabaseOpen(database.databaseURL)
        let expected = value.url.appendingPathComponent("Data/OpenLXSSH.sqlite")
        XCTAssertEqual(value.facts.databaseURL, expected)
        XCTAssertThrowsError(try value.recordDatabaseOpen(otherDatabase.databaseURL))
        let otherName = value.url.appendingPathComponent("Data/other.sqlite")
        try Data("public synthetic bytes".utf8).write(to: otherName)
        XCTAssertThrowsError(try value.recordDatabaseOpen(otherName))
        XCTAssertEqual(value.facts.databaseURL, expected)
    }
    func testRealRepositoryModelSettingsSecurityAndTrustShareOnlyTheNewRoot() async throws {
        let value = try root(), model = AppModel(engineeringPreview: value)
        let repository = try XCTUnwrap(model.repository as? AppRepository)
        XCTAssertTrue(model.isEngineeringPreview); XCTAssertNil(model.desktopPreferencesDefaults); XCTAssertNil(model.mainWindowFrameAutosaveName)
        let loaded = await model.reload(); XCTAssertTrue(loaded)
        XCTAssertTrue(model.hosts.isEmpty); XCTAssertTrue(model.keys.isEmpty); XCTAssertTrue(model.sessions.tabs.isEmpty)
        XCTAssertEqual(value.facts.databaseURL, value.url.appendingPathComponent("Data/OpenLXSSH.sqlite"))
        let host = HostConfiguration(name: "Public fictional preview", address: "preview.invalid", username: "fictional")
        let saved = await model.saveHostSecurely(host, isNew: true, password: .manual); XCTAssertTrue(saved)
        var settings = model.settings; settings.fontSize = 17
        let settingsSaved = await model.saveSettings(settings); XCTAssertTrue(settingsSaved)
        let snapshot = try await repository.snapshot(query: HostQuery())
        XCTAssertEqual(snapshot.hosts.map(\.id), [host.id]); XCTAssertEqual(snapshot.settings.fontSize, 17)
        let overview = try await model.security.overview(); XCTAssertTrue(overview.metadata.keys.isEmpty); XCTAssertTrue(overview.metadata.credentials.isEmpty)
        let trust = try await model.sessionEnvironment.sharedTrustStore()
        let secondTrust = try await model.sessionEnvironment.sharedTrustStore()
        XCTAssertTrue(trust === secondTrust)
        let ordinary = try XCTUnwrap(model.engineeringPreviewOrdinary?.underlying as? NativeSessionBuilder)
        let candidate = try XCTUnwrap(model.engineeringPreviewCandidate?.underlying as? NativeSessionBuilder)
        let files = try XCTUnwrap(model.engineeringPreviewFiles?.underlying as? LibSSH2FilesConnector)
        XCTAssertTrue(ordinary === candidate)
        XCTAssertTrue(ordinary === model.sessionBuilders.ordinary); XCTAssertTrue(candidate === model.sessionBuilders.prepared)
        XCTAssertTrue(ordinary.environment === model.sessionEnvironment); XCTAssertTrue(candidate.environment === model.sessionEnvironment)
        let filesEnvironment = files.environment; XCTAssertTrue(filesEnvironment === model.sessionEnvironment)
        for name in ["Data", "Keys", "Recovery", "Trust", "Sessions", "LocalPreview"] {
            let fd = open(value.url.appendingPathComponent(name).path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            XCTAssertGreaterThanOrEqual(fd, 0); if fd >= 0 { XCTAssertNoThrow(try AppFileSecurity.directory(fd)); Darwin.close(fd) }
        }
        let calls = await model.engineeringPreviewCredentials?.calls
        XCTAssertEqual(calls?.reads, 0); XCTAssertEqual(calls?.saves, 0); XCTAssertEqual(calls?.deletes, 0)
        XCTAssertGreaterThan(value.facts.admissions, 0)
        await model.sessions.closeAll(); await model.files.closeForWindow(); try await model.security.close(); try await repository.close()
    }
    func testNoAccessProviderExplicitlyRefusesReadSaveDeleteWithoutCaching() async throws {
        let credentials = PreviewNoAccessCredentials(), ref = OpenLXSSHSecurity.CredentialReference(id: UUID(), kind: .password)
        guard case .notAuthorized = await credentials.save(.init(utf8: "public-dummy-not-a-credential"), as: ref, authorization: .granted) else { return XCTFail("Save must refuse") }
        guard case .manualEntryRequired(.denied) = await credentials.read(ref) else { return XCTFail("Read must refuse") }
        guard case .retryRequired(.denied) = await credentials.deleteExact(ref) else { return XCTFail("Delete must refuse") }
        try await credentials.close()
        let calls = await credentials.calls
        XCTAssertEqual(calls, .init(reads: 1, saves: 1, deletes: 1, closes: 1))
    }
    func testNegativeDecoratorsNeverForwardAnyConfigurationPreparationOrConnect() async throws {
        let builder = PreviewNeverSessionBuilder(), connector = PreviewNeverFilesConnector(), admission = EngineeringPreviewAdmission()
        let ordinary = EngineeringPreviewSessionAdmission(underlying: builder, admission: admission, role: .ordinary)
        let candidate = EngineeringPreviewSessionAdmission(underlying: builder, admission: admission, role: .candidate)
        for wrapper in [ordinary, candidate] {
            await expectRefused { _ = try await wrapper.configuration(hostID: UUID()) }
            await expectRefused { _ = try await wrapper.prepare(hostID: UUID(), sessionID: UUID()) }
        }
        let files = EngineeringPreviewFilesAdmission(underlying: connector, admission: admission)
        let request = FilesRequest(id: UUID(), generation: 1, host: .init(name: "Fiction", address: "preview.invalid", username: "fictional"))
        await expectRefused {
            _ = try await files.connect(request: request, input: .init(primary: .manual(.init(utf8: "public-dummy"))), token: .init(),
                trust: { _, reply in reply.cancel() }, keyboard: { _, reply in reply.cancel() }, isCurrent: { true })
        }
        XCTAssertEqual(builder.calls, 0); let connectorCalls = await connector.calls; XCTAssertEqual(connectorCalls, 0)
        XCTAssertEqual(admission.facts, .init(ordinary: 2, candidate: 2, files: 1))
    }
    func testPreviewModelRejectsSessionsTransientSecretsAndCredentialMetadata() async throws {
        let value = try root(), model = AppModel(engineeringPreview: value)
        let loaded = await model.reload(); XCTAssertTrue(loaded)
        let host = HostConfiguration(name: "Public fiction", address: "preview.invalid", username: "fictional")
        let saved = await model.saveHostSecurely(host, isNew: true, password: .manual); XCTAssertTrue(saved)
        model.requestSession(hostID: host.id, mode: .newSession); XCTAssertTrue(model.sessions.tabs.isEmpty)
        let intent = VaultTransientConnectionIntent(host: host, secret: .init(utf8: "public-dummy"))
        await expectRefused { _ = try await model.prepareTransientConnection(host, intent: intent) }
        XCTAssertTrue(intent.consumed); XCTAssertTrue(model.sessions.tabs.isEmpty)
        let blockedTabID = try XCTUnwrap(model.sessions.open(host, mode: .newSession))
        let blockedTab = try XCTUnwrap(model.sessions.tabs.first { $0.id == blockedTabID })
        await blockedTab.preparation?.value
        XCTAssertNil(blockedTab.driver)
        model.sessions.reconnect(blockedTabID); await blockedTab.preparation?.value; XCTAssertNil(blockedTab.driver)
        model.files.show(host: host)
        model.files.connect(.init(primary: .manual(.init(utf8: "public-dummy"))))
        await model.files.waitUntilCurrentWorkCompletes()
        XCTAssertEqual(model.files.state, .failed)
        let facts = try XCTUnwrap(model.engineeringPreviewAdmission).facts
        XCTAssertEqual(facts.ordinary, 2); XCTAssertEqual(facts.files, 1)
        let remember = await model.saveHostSecurely(host, isNew: false, password: .remember(.init(utf8: "public-dummy")))
        let forget = await model.saveHostSecurely(host, isNew: false, password: .forget)
        XCTAssertFalse(remember); XCTAssertFalse(forget)
        await expectRefused { try await model.repository.apply([.registerCredential(.init(purpose: .password, isSavingAuthorized: true))]) }
        let calls = await model.engineeringPreviewCredentials?.calls
        XCTAssertEqual(calls?.reads, 0); XCTAssertEqual(calls?.saves, 0); XCTAssertEqual(calls?.deletes, 0)
        await model.sessions.closeAll(); await model.files.closeForWindow(); try await model.security.close(); try await model.repository.close()
    }
    func testLocalBrowserConfinesUpManualRawPathsAndSymlinksToEmptyLocalPreview() async throws {
        let value = try root(), model = AppModel(engineeringPreview: value), local = model.files.localBrowser
        local.activate(); await local.waitUntilIdle()
        let expected = try FilesLocalPaths.rawPath(FilesLocalPaths.components(value.localURL))
        XCTAssertEqual(local.path, expected); XCTAssertTrue(local.entries.isEmpty); XCTAssertFalse(local.canGoUp)
        local.up(); await local.waitUntilIdle(); XCTAssertEqual(local.path, expected)
        local.go(value.url.path); await local.waitUntilIdle(); XCTAssertNotNil(local.issue); XCTAssertEqual(local.path, expected)
        local.navigate(try FilesLocalPaths.rawPath(FilesLocalPaths.components(value.url.appendingPathComponent("Data"))))
        await local.waitUntilIdle(); XCTAssertNotNil(local.issue); XCTAssertEqual(local.path, expected)
        try FileManager.default.createSymbolicLink(at: value.localURL.appendingPathComponent("escape"), withDestinationURL: value.url)
        local.go(value.localURL.appendingPathComponent("escape").path); await local.waitUntilIdle()
        XCTAssertNotNil(local.issue); XCTAssertEqual(local.path, expected)
        local.refresh(); await local.waitUntilIdle(); local.mkdir(try FileName("Public folder")); await local.waitUntilIdle()
        XCTAssertTrue(FileManager.default.fileExists(atPath: value.localURL.appendingPathComponent("Public folder").path))
        await model.files.closeForWindow(); try await model.security.close(); try await model.repository.close()
    }
    func testFirstLocalReadRejectsReplacedSubrootWithoutAdoptingUnknownDirectory() async throws {
        let value = try root(), model = AppModel(engineeringPreview: value), moved = value.url.appendingPathComponent("OriginalLocal")
        try FileManager.default.moveItem(at: value.localURL, to: moved)
        try FileManager.default.createDirectory(at: value.localURL, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        model.files.localBrowser.activate(); await model.files.localBrowser.waitUntilIdle()
        XCTAssertNil(model.files.localBrowser.path); XCTAssertNotNil(model.files.localBrowser.issue)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: value.localURL.path), [])
        await model.files.closeForWindow(); try await model.security.close(); try await model.repository.close()
    }
    func testCachedLocalServiceRevalidatesSubrootBeforeRenameAndMkdir() async throws {
        let value = try root(), model = AppModel(engineeringPreview: value), local = model.files.localBrowser
        try Data("public synthetic bytes".utf8).write(to: value.localURL.appendingPathComponent("original"))
        local.activate(); await local.waitUntilIdle()
        let entry = try XCTUnwrap(local.entries.first { $0.name.bytes == Data("original".utf8) })
        let moved = value.url.appendingPathComponent("OriginalLocal")
        try FileManager.default.moveItem(at: value.localURL, to: moved)
        try FileManager.default.createDirectory(at: value.localURL, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        local.rename(entry, to: try FileName("renamed")); await local.waitUntilIdle(); XCTAssertNotNil(local.issue)
        local.mkdir(try FileName("new-folder")); await local.waitUntilIdle(); XCTAssertNotNil(local.issue)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: value.localURL.path), [])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: moved.path), ["original"])
        XCTAssertEqual(try Data(contentsOf: moved.appendingPathComponent("original")), Data("public synthetic bytes".utf8))
        await model.files.closeForWindow(); try await model.security.close(); try await model.repository.close()
    }
    #endif
}

#if PREVIEW_ISOLATED
@MainActor private final class PreviewNeverSessionBuilder: SessionBuilding {
    private(set) var calls = 0
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) { calls += 1; throw EngineeringPreviewFailure.unavailable }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession { calls += 1; throw EngineeringPreviewFailure.unavailable }
}
private actor PreviewNeverFilesConnector: FilesConnecting {
    private(set) var calls = 0
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken,
                 trust: @escaping FileHostTrustHandler, keyboard: @escaping FilesKeyboardHandler,
                 isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService { calls += 1; throw EngineeringPreviewFailure.unavailable }
}
#endif
