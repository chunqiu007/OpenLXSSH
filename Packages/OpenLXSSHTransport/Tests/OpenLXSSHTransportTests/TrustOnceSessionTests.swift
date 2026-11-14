import AppKit
import Darwin
import Foundation
import OpenLXSSHTrust
import COpenLXSSHAskpass
@testable import OpenLXSSHTransport
import XCTest

private let trustOnceEd = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg"
private let trustOnceChangedEd = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C"
private let trustOnceRSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtEucvt1w5resIpf/BvuuR1zddYXDeUVM0LOZt8mis3XGozl6xpF3V3jkVOfXM1oaq0faq2MKnzxCZx4GmlofE4qdcMqa4cbL7QTNvO/Z6ACTTb92kpNp9DS/4BSLsIebvMM0UVWivxmj3Mq3REqIThBXQVwqkhmWj6bzfSKqsstCjjRmRuzi/IDCUL8lIbJGzpYek4/cp5VhUyB2kIYqz/Fpg5+eJTa2x/7qYEKNKg4dXebuExQYe3Z47D8o1i9pDXWpYw/KlBn8LA/K89h7BkEsdY4ePPGroTS+lepAKqItDWwMm4wf6gDJSoNbCt6T+L5U7gjpbA3kEZd89PxvJ"

@MainActor
final class TrustOnceSessionTests: XCTestCase {
    private var fixture: URL!
    private var sessions: [DirectSSHSession] = []

    override func setUp() async throws {
        _ = NSApplication.shared
        fixture = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("OpenLXSSH-TrustOnce-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: fixture, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    override func tearDown() async throws {
        for session in sessions { session.closeTab() }
        for session in sessions { try await wait { session.state == .closed } }
        sessions.removeAll()
        let result = try BoundedTool.run("/bin/chmod", ["-RN", fixture.path], seconds: 3)
        XCTAssertEqual(result.status, 0)
        try FileManager.default.removeItem(at: fixture)
    }
    private func host(_ address: String = "never-connected.invalid", port: Int = 2222) throws -> HostIdentity {
        HostIdentity(address: try HostAddress(address), port: try SSHPort(port))
    }
    private func configuration(_ host: HostIdentity? = nil) throws -> SSHSessionConfiguration {
        try SSHSessionConfiguration(connection: SSHConnection(host: host ?? self.host(), user: SSHUser("fixture")))
    }
    private func store() throws -> HostTrustStore {
        try HostTrustStore(directory: AbsolutePath(fixture.appendingPathComponent("trust").path))
    }
    private func sessionRoot(_ name: String = UUID().uuidString) throws -> AbsolutePath {
        let root = fixture.appendingPathComponent("sessions-" + name)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return try AbsolutePath(root.path)
    }
    private func temporaryRecord(_ store: HostTrustStore, host: HostIdentity? = nil, key: HostPublicKey? = nil) async throws -> TrustedHostKey {
        let endpoint = try host ?? self.host(), key = try key ?? HostPublicKey(openSSHPublicKey: trustOnceEd)
        guard case .pending(let decision) = try await store.evaluate(host: endpoint, key: key) else { throw TransportError.invalidConfiguration }
        return try await store.confirmOnce(decision, displayedFingerprint: decision.fingerprint)
    }
    private func session(_ store: HostTrustStore, root: AbsolutePath, keys: [HostPublicKey]) -> DirectSSHSession {
        let session = DirectSSHSession(probeStore: store, directory: root, scanner: TrustOnceScanner(keys: keys))
        sessions.append(session)
        return session
    }
    private func wait(_ condition: @MainActor () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw HostScanError.timeout }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    private func metadata(_ path: String) throws -> stat {
        var value = stat()
        guard lstat(path, &value) == 0 else { throw TransportError.invalidConfiguration }
        return value
    }
    private func addACL(_ path: String) throws {
        let result = try BoundedTool.run("/bin/chmod", ["+a", "everyone allow read,write", path], seconds: 3)
        XCTAssertEqual(result.status, 0)
        guard result.status == 0 else { throw TransportError.invalidConfiguration }
    }
    private func expectInvalid(_ operation: () throws -> Void) {
        XCTAssertThrowsError(try operation()) { XCTAssertEqual($0 as? TransportError, .invalidConfiguration) }
    }
    private func expectExpired(_ store: HostTrustStore, _ decision: PendingTrustDecision) async {
        do { _ = try await store.confirmOnce(decision, displayedFingerprint: decision.fingerprint); XCTFail("Reused trust decision") }
        catch { XCTAssertEqual(error as? HostTrustError, .expiredDecision) }
    }

    func testOneTimeWorkspaceUsesOnlyExactAcceptedEndpointKeyAndStrictOfflineConfiguration() async throws {
        let store = try store(), root = try sessionRoot()
        let ed = try HostPublicKey(openSSHPublicKey: trustOnceEd), rsa = try HostPublicKey(openSSHPublicKey: trustOnceRSA)
        let other = try host("other.invalid", port: 22)
        guard case .pending(let saved) = try await store.evaluate(host: other, key: rsa) else { return XCTFail("Expected pending") }
        _ = try await store.confirm(saved, displayedFingerprint: saved.fingerprint)
        let before = try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value))
        for key in [ed, rsa] {
            let endpoint = try host("2001:db8::5", port: 2222)
            let accepted = try await temporaryRecord(store, host: endpoint, key: key)
            var workspace: SessionWorkspace? = try SessionWorkspace(root: root, configuration: configuration(endpoint), temporaryTrust: accepted)
            let path = try XCTUnwrap(workspace).directory
            try XCTUnwrap(workspace).validateForLaunch()
            let snapshot = try Data(contentsOf: URL(fileURLWithPath: path + "/known_hosts"))
            XCTAssertEqual(snapshot, Data((endpoint.knownHostsName + " " + key.openSSH + "\n").utf8))
            let text = try String(contentsOfFile: path + "/ssh_config", encoding: .utf8)
            XCTAssertTrue(text.contains("StrictHostKeyChecking yes"))
            XCTAssertTrue(text.contains("GlobalKnownHostsFile /dev/null"))
            XCTAssertTrue(text.contains("UserKnownHostsFile \"" + path + "/known_hosts\""))
            XCTAssertFalse(text.contains(store.knownHostsPath.value))
            let invocation = try XCTUnwrap(workspace).invocation(preview: true)
            XCTAssertEqual(invocation.arguments.first, "-G")
            let result = try BoundedTool.run(invocation.executable, invocation.arguments, seconds: 3)
            XCTAssertEqual(result.status, 0)
            let output = String(decoding: result.output, as: UTF8.self)
            let algorithms = key.algorithm == "ssh-rsa" ? "rsa-sha2-256,rsa-sha2-512" : "ssh-ed25519"
            for expected in ["stricthostkeychecking true", "hostkeyalgorithms " + algorithms,
                "userknownhostsfile " + path + "/known_hosts", "globalknownhostsfile /dev/null", "updatehostkeys false"] {
                XCTAssertTrue(output.contains(expected), expected)
            }
            for (file, mode): (String, mode_t) in [(path, 0o700), (path + "/known_hosts", 0o600), (path + "/ssh_config", 0o600)] {
                let value = try metadata(file)
                XCTAssertEqual(value.st_uid, getuid()); XCTAssertEqual(value.st_mode & 0o7777, mode)
            }
            workspace = nil
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value)), before)
        let records = try await store.records()
        XCTAssertEqual(records.map(\.host), [other])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.value), [])
    }

    func testPersistentConfigurationStillUsesAuthoritativeKnownHostsPath() async throws {
        let store = try store(), root = try sessionRoot(), endpoint = try host()
        let key = try HostPublicKey(openSSHPublicKey: trustOnceEd)
        let controlled = try DirectSSHConfiguration(configuration: configuration(endpoint), trustStore: store, trustedKeys: [key])
        var workspace: SessionWorkspace? = try SessionWorkspace(root: root, text: controlled.text)
        let path = try XCTUnwrap(workspace).directory
        try XCTUnwrap(workspace).validateForLaunch()
        XCTAssertTrue(controlled.text.contains("UserKnownHostsFile \"" + store.knownHostsPath.value + "\""))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: path), ["ssh_config"])
        workspace = nil
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    func testDirectSessionOneTimeChoiceCancelsOtherAlgorithmsAndCannotSurviveReconnect() async throws {
        let store = try store(), root = try sessionRoot()
        let keys = try [HostPublicKey(openSSHPublicKey: trustOnceEd), HostPublicKey(openSSHPublicKey: trustOnceRSA)]
        let session = session(store, root: root, keys: keys)
        var prepared: (SessionToken, String)?
        session.onProbeTrustWorkspacePrepared = { prepared = ($0, $1) }
        let before = try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value))
        let first = try session.connect(configuration())
        try await wait { session.state == .awaitingTrust }
        XCTAssertEqual(session.trustChallenges.count, 2)
        let chosen = try XCTUnwrap(session.trustChallenges.first { $0.candidate.key.algorithm == "ssh-ed25519" })
        let other = try XCTUnwrap(session.trustChallenges.first { $0.candidate.key.algorithm == "ssh-rsa" })
        try await session.acceptTrust(chosen, displayedFingerprint: chosen.decision.fingerprint, persistence: .once)
        let (preparedToken, path) = try XCTUnwrap(prepared)
        XCTAssertEqual(preparedToken, first)
        XCTAssertNil(session.ownedProcessID)
        XCTAssertTrue(session.trustChallenges.isEmpty)
        XCTAssertEqual(try String(contentsOfFile: path + "/known_hosts", encoding: .utf8), chosen.candidate.host.knownHostsName + " " + keys[0].openSSH + "\n")
        await expectExpired(store, other.decision)
        await expectExpired(store, chosen.decision)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value)), before)
        session.cancel()
        try await wait { session.canReconnect }
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        let second = try session.reconnect()
        XCTAssertEqual(second.generation, first.generation + 1)
        try await wait { session.state == .awaitingTrust }
        XCTAssertEqual(session.trustChallenges.count, 2)
        XCTAssertTrue(session.trustChallenges.allSatisfy { $0.token == second && $0.decision.id != chosen.decision.id })
        do { try await session.acceptTrust(chosen, displayedFingerprint: chosen.decision.fingerprint, persistence: .once); XCTFail("Old generation accepted") }
        catch { XCTAssertEqual(error as? TransportError, .stale) }
        session.closeTab()
        try await wait { session.state == .closed }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.value), [])
    }

    func testOneTimeWrongFingerprintFailsWithoutWorkspaceOrPersistentTrust() async throws {
        let store = try store(), root = try sessionRoot(), key = try HostPublicKey(openSSHPublicKey: trustOnceEd)
        let session = session(store, root: root, keys: [key])
        _ = try session.connect(configuration())
        try await wait { session.state == .awaitingTrust }
        let challenge = try XCTUnwrap(session.trustChallenges.first)
        do { try await session.acceptTrust(challenge, displayedFingerprint: "SHA256:wrong", persistence: .once); XCTFail("Wrong fingerprint accepted") }
        catch { XCTAssertEqual(error as? HostTrustError, .fingerprintMismatch) }
        XCTAssertEqual(session.state, .failed(.trustRejected))
        XCTAssertNil(session.ownedProcessID)
        let records = try await store.records()
        XCTAssertTrue(records.isEmpty)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.value), [])
        await expectExpired(store, challenge.decision)
    }

    func testKnownChangedAlgorithmStillRejectsEvenWhenAnotherAlgorithmIsTrusted() async throws {
        let store = try store(), root = try sessionRoot(), endpoint = try host()
        let ed = try HostPublicKey(openSSHPublicKey: trustOnceEd), rsa = try HostPublicKey(openSSHPublicKey: trustOnceRSA)
        for key in [ed, rsa] {
            guard case .pending(let pending) = try await store.evaluate(host: endpoint, key: key) else { return XCTFail("Expected pending") }
            _ = try await store.confirm(pending, displayedFingerprint: pending.fingerprint)
        }
        let before = try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value))
        let session = session(store, root: root, keys: [rsa, try HostPublicKey(openSSHPublicKey: trustOnceChangedEd)])
        _ = try session.connect(configuration())
        try await wait { session.state == .failed(.trustRejected) }
        XCTAssertNil(session.ownedProcessID)
        XCTAssertTrue(session.trustChallenges.isEmpty)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value)), before)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.value), [])
    }

    func testCancellationAndCloseDiscardLateCreatedOneTimeWorkspace() async throws {
        for close in [false, true] {
            let store = try store(), root = try sessionRoot(), key = try HostPublicKey(openSSHPublicKey: trustOnceEd)
            let session = session(store, root: root, keys: [key]), gate = TrustOnceDeliveryGate()
            session.beforeProbeTrustWorkspaceDelivery = { try await gate.pause($0) }
            _ = try session.connect(configuration())
            try await wait { session.state == .awaitingTrust }
            let challenge = try XCTUnwrap(session.trustChallenges.first)
            let acceptance = Task { try await session.acceptTrust(challenge, displayedFingerprint: challenge.decision.fingerprint, persistence: .once) }
            do {
                try await wait { await gate.path != nil }
                let deliveredPath = await gate.path
                let path = try XCTUnwrap(deliveredPath)
                XCTAssertTrue(FileManager.default.fileExists(atPath: path + "/known_hosts"))
                if close { session.closeTab() } else { session.cancel() }
                XCTAssertEqual(session.state, .closing)
                XCTAssertThrowsError(try session.reconnect())
                await gate.release()
                do { try await acceptance.value; XCTFail("Cancelled workspace was delivered") }
                catch { XCTAssertEqual(error as? TransportError, .stale) }
                try await wait { close ? session.state == .closed : session.canReconnect }
                XCTAssertFalse(FileManager.default.fileExists(atPath: path))
                XCTAssertNil(session.ownedProcessID)
                let records = try await store.records()
                XCTAssertTrue(records.isEmpty)
            } catch {
                await gate.release(); _ = await acceptance.result
                throw error
            }
        }
    }

    func testTemporaryTrustRejectsWrongEndpointBeforeCreatingWorkspace() async throws {
        let store = try store(), root = try sessionRoot()
        let accepted = try await temporaryRecord(store)
        expectInvalid {
            _ = try SessionWorkspace(root: root, configuration: configuration(host("other.invalid")), temporaryTrust: accepted)
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.value), [])
    }

    func testTemporaryTrustLaunchRejectsReplacementWithoutDeletingForeignInode() async throws {
        let store = try store(), accepted = try await temporaryRecord(store)
        for name in ["known_hosts", "ssh_config"] {
            let root = try sessionRoot()
            var workspace: SessionWorkspace? = try SessionWorkspace(root: root, configuration: configuration(), temporaryTrust: accepted)
            let path = try XCTUnwrap(workspace).directory
            let file = path + "/" + name, moved = path + "/owned-original"
            XCTAssertEqual(rename(file, moved), 0)
            let marker = Data("foreign replacement must remain\n".utf8)
            XCTAssertTrue(FileManager.default.createFile(atPath: file, contents: marker, attributes: [.posixPermissions: 0o600]))
            expectInvalid { try XCTUnwrap(workspace).validateForLaunch() }
            workspace = nil
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file)), marker)
        }
    }

    func testTemporaryTrustLaunchRejectsInPlaceDataChangesAndUnsafeFileMetadata() async throws {
        let store = try store(), accepted = try await temporaryRecord(store)
        for target in ["known_hosts", "ssh_config"] {
            let root = try sessionRoot()
            var workspace: SessionWorkspace? = try SessionWorkspace(root: root, configuration: configuration(), temporaryTrust: accepted)
            let path = try XCTUnwrap(workspace).directory + "/" + target
            let before = try metadata(path)
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
            try handle.write(contentsOf: Data("X".utf8)); try handle.close()
            XCTAssertEqual(try metadata(path).st_ino, before.st_ino)
            expectInvalid { try XCTUnwrap(workspace).validateForLaunch() }
            workspace = nil
        }
        for attack in ["permissions", "symlink", "hardlink", "fifo"] {
            let root = try sessionRoot()
            var workspace: SessionWorkspace? = try SessionWorkspace(root: root, configuration: configuration(), temporaryTrust: accepted)
            let path = try XCTUnwrap(workspace).directory, file = path + "/known_hosts", alias = path + "/alias"
            if attack == "permissions" { XCTAssertEqual(chmod(file, 0o644), 0) }
            else if attack == "hardlink" { XCTAssertEqual(link(file, alias), 0) }
            else {
                XCTAssertEqual(rename(file, alias), 0)
                if attack == "symlink" { XCTAssertEqual(symlink(alias, file), 0) }
                else { XCTAssertEqual(mkfifo(file, 0o600), 0) }
            }
            expectInvalid { try XCTUnwrap(workspace).validateForLaunch() }
            workspace = nil
        }
    }

    func testTemporaryTrustACLBeforeWriteAndAfterCreationFailsClosedAndCleansUp() async throws {
        let store = try store(), accepted = try await temporaryRecord(store)
        for phase in [SessionWorkspace.Checkpoint.trustFileOpened, .trustFileWritten] {
            let root = try sessionRoot()
            var retained: FileHandle?
            defer { try? retained?.close() }
            expectInvalid {
                _ = try SessionWorkspace(probeRoot: root, configuration: configuration(), temporaryTrust: accepted) { checkpoint, directory in
                    guard checkpoint == phase else { return }
                    let path = directory + "/known_hosts"
                    retained = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
                    try self.addACL(path)
                }
            }
            let handle = try XCTUnwrap(retained)
            var value = stat()
            XCTAssertEqual(fstat(handle.fileDescriptor, &value), 0)
            XCTAssertEqual(value.st_nlink, 0)
            if phase == .trustFileOpened { XCTAssertEqual(value.st_size, 0) }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.value), [])
        }
        for target in ["root", "directory", "known_hosts", "ssh_config"] {
            let root = try sessionRoot()
            var workspace: SessionWorkspace? = try SessionWorkspace(root: root, configuration: configuration(), temporaryTrust: accepted)
            let path = try XCTUnwrap(workspace).directory
            let unsafe = target == "root" ? root.value : (target == "directory" ? path : path + "/" + target)
            try addACL(unsafe)
            expectInvalid { try XCTUnwrap(workspace).validateForLaunch() }
            workspace = nil
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.value), [])
        }
    }

    func testRepeatedOneTimeWorkspaceCleanupReleasesDescriptorsAndFiles() async throws {
        let store = try store(), accepted = try await temporaryRecord(store), root = try sessionRoot()
        let before = ap_fd_count()
        for _ in 0..<20 {
            do {
                let workspace = try SessionWorkspace(root: root, configuration: configuration(), temporaryTrust: accepted)
                try workspace.validateForLaunch()
                XCTAssertTrue(FileManager.default.fileExists(atPath: workspace.directory + "/known_hosts"))
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.value), [])
        }
        XCTAssertLessThanOrEqual(ap_fd_count(), before + 1)
    }
}

private struct TrustOnceScanner: HostKeyScanning {
    let keys: [HostPublicKey]
    func scan(_ host: HostIdentity) async throws -> [HostKeyCandidate] {
        keys.map { HostKeyCandidate(host: host, key: $0, source: .systemSSHKeyscan) }
    }
}
private actor TrustOnceDeliveryGate {
    private(set) var path: String?
    private var released = false
    func pause(_ path: String) async throws {
        self.path = path
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !released {
            guard ContinuousClock.now < deadline else { throw HostScanError.timeout }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func release() { released = true }
}
