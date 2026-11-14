import CryptoKit
import Darwin
import Foundation
import OpenLXSSHTrust
import XCTest
import OpenLXSSHFiles

/// Explicit finite live tests for the already-approved disposable loopback fixture.
/// No live permission means an error, never a skipped or pretend-passed test.
/// The normal package verification must select its own offline classes explicitly.
final class ScopedTrialLiveTests: XCTestCase, @unchecked Sendable {
    func testUX97FirstUploadTreeRoundTripConflictsCancellationAndDeniedTarget() async throws {
        let run = try UX97Run(name: "sftp-small-roundtrip")
        addTeardownBlock { try await run.cleanup() }
        let remote = try await run.connectFiles()
        try await run.createRemoteRoot(remote)
        let local = try LocalFileService(root: run.localRoot)
        run.retainLocal(local)
        let first = Data("UX97 first upload 中文\n".utf8)
        let replacement = Data("UX97 explicit replacement\n".utf8)
        try first.write(to: run.localRoot.appendingPathComponent("first.txt"))
        try replacement.write(to: run.localRoot.appendingPathComponent("replacement.txt"))
        let tree = run.localRoot.appendingPathComponent("目录/子目录", isDirectory: true)
        try FileManager.default.createDirectory(at: tree, withIntermediateDirectories: true)
        try Data("第一项\n".utf8).write(to: run.localRoot.appendingPathComponent("目录/中文.txt"))
        let binary = Data((0..<1024).map { UInt8(truncatingIfNeeded: $0 * 7) })
        try binary.write(to: tree.appendingPathComponent("中 文.bin"))
        let engine = SafeTransferEngine(), file = try run.remoteRoot.appending(FileName("first.txt"))
        let renamed = try run.remoteRoot.appending(FileName("renamed 中文.txt"))
        let remoteTree = try run.remoteRoot.appending(FileName("副本目录"))
        run.addCleanupFile(file); run.addCleanupFile(renamed)
        run.addCleanupDirectory(remoteTree)
        run.addCleanupDirectory(try remoteTree.appending(FileName("子目录")))
        run.addCleanupFile(try remoteTree.appending(FileName("中文.txt")))
        run.addCleanupFile(try remoteTree.appending(FileName("子目录")).appending(FileName("中 文.bin")))
        let policy = run.policy()
        let uploaded = try await engine.copy(hostID: run.hostID, source: local, sourcePath: RemotePath("/first.txt"),
            destination: remote, destinationPath: file, token: run.token, policy: policy)
        try run.require(uploaded.allSucceeded, "first-upload-without-manual-probe")
        try await run.assertRemoteNames(remote, expected: ["first.txt"])

        let copiedTree = try await engine.copyTree(hostID: run.hostID, source: local, sourcePath: RemotePath("/目录"),
            destination: remote, destinationPath: remoteTree, token: run.token, policy: policy)
        try run.require(copiedTree.allSucceeded, "small-chinese-tree-upload")
        let downloaded = try await engine.copyTree(hostID: run.hostID, source: remote, sourcePath: remoteTree,
            destination: local, destinationPath: RemotePath("/下载副本"), token: run.token, policy: policy)
        try run.require(downloaded.allSucceeded, "small-chinese-tree-download")
        try run.require(SHA256.hash(data: Data(contentsOf: run.localRoot.appendingPathComponent("下载副本/中文.txt"))) ==
            SHA256.hash(data: Data("第一项\n".utf8)), "chinese-file-hash")
        try run.require(SHA256.hash(data: Data(contentsOf: run.localRoot.appendingPathComponent("下载副本/子目录/中 文.bin"))) ==
            SHA256.hash(data: binary), "binary-file-hash")

        let skipped = try await engine.copy(hostID: run.hostID, source: local, sourcePath: RemotePath("/replacement.txt"),
            destination: remote, destinationPath: file, token: run.token, policy: policy,
            hooks: TransferHooks(resolveConflict: { conflict in
                guard conflict.destination == file else { throw UX97Failure.check("unexpected-skip-target") }
                return .skip
            }))
        try run.require(skipped.items.first?.state == .skipped, "same-name-explicit-skip")
        try await run.verifyFile(file, bytes: first, remote: remote, local: local, engine: engine, name: "skip-back.txt")
        let alternate = try await engine.copy(hostID: run.hostID, source: local, sourcePath: RemotePath("/replacement.txt"),
            destination: remote, destinationPath: file, token: run.token, policy: policy,
            hooks: TransferHooks(resolveConflict: { conflict in
                guard conflict.destination == file else { throw UX97Failure.check("unexpected-rename-target") }
                return .renameTo(try FileName("renamed 中文.txt"))
            }))
        try run.require(alternate.allSucceeded, "same-name-explicit-rename")
        try await run.verifyFile(file, bytes: first, remote: remote, local: local, engine: engine, name: "rename-original.txt")
        let overwritten = try await engine.copy(hostID: run.hostID, source: local, sourcePath: RemotePath("/replacement.txt"),
            destination: remote, destinationPath: file, token: run.token, policy: policy,
            hooks: TransferHooks(resolveConflict: { conflict in
                guard conflict.destination == file else { throw UX97Failure.check("unexpected-overwrite-target") }
                return .overwrite
            }))
        try run.require(overwritten.allSucceeded, "same-name-explicit-overwrite")
        try await run.verifyFile(file, bytes: replacement, remote: remote, local: local, engine: engine, name: "overwrite-back.txt")

        let cancel = CancellationToken()
        let cancelled = try await engine.copy(hostID: run.hostID, source: local, sourcePath: RemotePath("/first.txt"),
            destination: remote, destinationPath: file, token: cancel, policy: policy,
            hooks: TransferHooks(beforeCommit: { temporary, target in
                guard target == file, temporary.parent == run.remoteRoot else { throw UX97Failure.check("cancel-owner") }
                run.recordCancelledPart(temporary); cancel.cancel()
            }, resolveConflict: { _ in .overwrite }))
        guard case .failed(let cancellation)? = cancelled.items.first?.state else { throw UX97Failure.check("cancel-result") }
        try run.require(cancellation.kind == .cancelled && cancelled.items.first?.retainedTemporary == nil, "cancel-cleanup")
        try await run.verifyFile(file, bytes: replacement, remote: remote, local: local, engine: engine, name: "cancel-original.txt")
        try await run.assertRemoteNames(remote, expected: ["first.txt", "renamed 中文.txt", "副本目录"])

        let denied = try await engine.copy(hostID: run.hostID, source: local, sourcePath: RemotePath("/first.txt"),
            destination: remote, destinationPath: RemotePath("/fixture/protected/denied-directory/ux97-never-created.txt"),
            token: run.token, policy: policy)
        guard case .failed(let permission)? = denied.items.first?.state else { throw UX97Failure.check("denied-result") }
        try run.require(permission.kind == .permissionDenied, "real-server-permission-error")
        try run.require(denied.items.first?.retainedTemporary == nil, "denied-no-fake-owned-temp")
        run.record("verified-first-upload-tree-hashes-skip-rename-overwrite-cancel-denied")
    }

    func testUX97TwoNativeShellsAndUserHeldSFTPSurvive150SecondsAndIndependentCloses() async throws {
        let run = try UX97Run(name: "two-shells-and-sftp-idle")
        addTeardownBlock { try await run.cleanup() }
        let remote = try await run.connectFiles()
        try await run.createRemoteRoot(remote)
        let manager = TransferManager(idleTimeout: .seconds(60))
        let registration = try await manager.registerSessionServiceWithSnapshot(remote, hostID: run.hostID)
        run.retainManager(manager)
        let a = try await run.connectShell(), b = try await run.connectShell()
        try run.require(a.sessionID != b.sessionID, "independent-shell-owners")
        for shell in [a, b] {
            guard let tcp = shell.tcpKeepalive else { throw UX97Failure.check("missing-real-tcp-receipt") }
            run.record("real-tcp-snapshot=enabled:\(tcp.enabled),idle:\(tcp.idleSeconds),retry:\(tcp.retrySeconds),failed:\(tcp.failedProbes)")
            try run.require(tcp.enabled && tcp.idleSeconds == 30 && tcp.retrySeconds == 30 && tcp.failedProbes == 3,
                "actual-socket-keepalive-configuration")
        }
        try await run.shellACK(a, label: "A_BEFORE")
        try await run.shellACK(b, label: "B_BEFORE")
        let began = ContinuousClock.now, end = began + .seconds(150)
        // Explicit bounded test command; this is not a product-generated keepalive command.
        try await b.write(Data("i=0; while [ \"$i\" -lt 31 ]; do printf 'UX97_TICK_%s\\n' \"$i\"; i=$((i+1)); sleep 5; done; printf 'UX97_LOOP_DONE\\n'\n".utf8), token: run.token)
        var quietBytes = 0, outputBytes = 0, tickLines = 0
        var outputTail = Data()
        while ContinuousClock.now < end {
            try run.token.check()
            for (shell, idle) in [(a, true), (b, false)] {
                switch try await shell.receive(maxBytes: 4096, wait: 0.2, token: run.token) {
                case .wouldBlock: break
                case .bytes(let data):
                    if idle { quietBytes += data.count } else {
                        outputBytes += data.count; outputTail.append(data)
                        try run.require(outputTail.count <= 32768, "finite-test-output-bound")
                    }
                case .eof, .exit: throw UX97Failure.check("healthy-shell-ended-before150s")
                }
            }
            try run.require(quietBytes <= 4096 && outputBytes <= 32768, "bounded-public-test-output")
        }
        // PTY CRLF is one Swift Character; split bounded raw bytes at LF instead.
        tickLines = outputTail.split(separator: UInt8(10)).filter {
            String(decoding: $0, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                .range(of: "^UX97_TICK_[0-9]+$", options: .regularExpression) != nil
        }.count
        run.record("actual-idle-seconds=" + String(run.elapsedSeconds(since: began)))
        run.record("observed-output-tick-lines=" + String(tickLines) + ";output-bytes=" + String(outputBytes) + ";idle-prompt-bytes=" + String(quietBytes))
        try run.require(tickLines >= 25 && tickLines <= 31, "finite-real-periodic-output")
        try run.require(began.duration(to: .now) >= .seconds(150), "actual-idle-window")
        let snapshot = await manager.snapshot()
        try run.require(snapshot.services.contains { $0.id == registration.id && $0.state == .available }, "user-lease-beyond60s")
        let listing = try await manager.withServiceOperation(serviceID: registration.id, hostID: run.hostID, token: run.token) { service, token in
            try await service.list(run.remoteRoot, token: token)
        }
        try run.require(listing.isEmpty, "sftp-directory-after150s")
        try await run.shellACK(a, label: "A_AFTER150")
        try await run.shellACK(b, label: "B_AFTER150")
        await a.close()
        try run.require(a.interactionSnapshot().drained, "closed-A-drained")
        try await run.shellACK(b, label: "B_AFTER_A_CLOSE")
        try await run.removeRemoteRootBeforeRelease(remote)
        await manager.releaseSessionService(registration.lease)
        let closedFiles = await manager.snapshot()
        try run.require(!closedFiles.services.contains { $0.id == registration.id }, "explicit-sftp-release")
        try await run.shellACK(b, label: "B_AFTER_SFTP_CLOSE")
        await b.close()
        try run.require(b.interactionSnapshot().drained, "closed-B-drained")
        run.record("verified150s-policy30x3-two-shell-input-and-independent-SFTP-close; not-application-blackhole-proof")
    }
}

private enum UX97Failure: Error {
    case notAuthorized, boundary, check(String), cleanupRetained
}

/// A small per-test owner, not a new transport or test platform. It owns only this test's
/// unique local root, acknowledged remote root, exact fixed endpoint, and finite sessions.
private final class UX97Run: @unchecked Sendable {
    static let authorization = "8bb07b49-8cad-4326-90b4-098aba029cce"
    private static let suiteStarted = ContinuousClock.now
    static let fingerprint = "SHA256:d2G+w7lBrjYDFHHd6c6GxIhk7qzFs6df1i7EVJfeUYs"
    let token = CancellationToken()
    let localRoot: URL
    let remoteRoot: RemotePath
    let hostID: String
    private let marker: Data
    private let trust: HostTrustStore
    private let primary: FileAuthentication
    private let config: SSHConnection
    private let name: String
    private let began = ContinuousClock.now
    private let lock = NSLock()
    private var files: LibSSH2FileService?
    private var shells: [LibSSH2ShellSession] = []
    private var local: LocalFileService?
    private var manager: TransferManager?
    private var rootConfirmed = false
    private var rootPossible = false
    private var cleanupFiles: [RemotePath] = []
    private var cleanupDirectories: [RemotePath] = []
    private var facts: [String] = []
    private var watchdog: Task<Void, Never>?

    init(name: String) throws {
        guard ProcessInfo.processInfo.environment["OPENLXSSH_UX97_AUTHORIZED"] == Self.authorization else {
            throw UX97Failure.notAuthorized
        }
        let nonce = UUID().uuidString.lowercased()
        let ownedRoot = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("OpenLXSSH-UX97-" + nonce, isDirectory: true)
        let ownedMarker = Data(("OpenLXSSH UX97 disposable live test\n" + nonce + "\n").utf8)
        let key = URL(fileURLWithPath: "/Users/liuwenshuo/Desktop/OpenLXSSH/Tests/IntegrationEnvironment/.runtime/keyonly/credentials-198f6f0d9584/id_ed25519")
        let attributes = try FileManager.default.attributesOfItem(atPath: key.path)
        guard key.resolvingSymlinksInPath() == key, attributes[.type] as? FileAttributeType == .typeRegular,
              attributes[.posixPermissions] as? Int == 0o600,
              attributes[.ownerAccountID] as? Int == Int(getuid()), attributes[.referenceCount] as? Int == 1 else {
            throw UX97Failure.boundary
        }
        let privateKey = try Data(contentsOf: key)
        guard !privateKey.isEmpty && privateKey.count <= 16384 else { throw UX97Failure.boundary }
        let configuration = SSHConnection(host: HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22221)), user: try SSHUser("fixture"))
        let remaining = ContinuousClock.now.duration(to: Self.suiteStarted + .seconds(225))
        let minimumBudget: Duration = name == "two-shells-and-sftp-idle" ? .seconds(165) : .seconds(20)
        guard remaining > minimumBudget else { throw UX97Failure.check("finite-suite-budget") }
        try FileManager.default.createDirectory(at: ownedRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var initialized = false
        defer {
            if !initialized {
                // This exact directory was just created exclusively by this initializer.
                try? FileManager.default.removeItem(at: ownedRoot)
            }
        }
        try ownedMarker.write(to: ownedRoot.appendingPathComponent(".ux97-owner"), options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: ownedRoot.appendingPathComponent(".ux97-owner").path)
        let store = try HostTrustStore(directory: AbsolutePath(ownedRoot.appendingPathComponent("Trust").path))
        self.name = name; hostID = "ux97-" + nonce
        localRoot = ownedRoot; marker = ownedMarker
        remoteRoot = try RemotePath("/fixture/home/ux97-" + nonce)
        primary = .publicKey(publicKey: nil, privateKey: privateKey, passphrase: nil)
        config = configuration; trust = store
        initialized = true
        watchdog = Task { [weak self] in
            do { try await Task.sleep(for: min(.seconds(210), remaining)) } catch { return }
            self?.cancelOwned()
        }
    }

    func require(_ passed: Bool, _ label: String) throws { guard passed else { throw UX97Failure.check(label) } }
    func record(_ fact: String) { lock.withLock { facts.append(fact) } }
    func retainLocal(_ value: LocalFileService) { lock.withLock { local = value } }
    func retainManager(_ value: TransferManager) { lock.withLock { manager = value } }
    func addCleanupFile(_ path: RemotePath) { lock.withLock { cleanupFiles.append(path) } }
    func addCleanupDirectory(_ path: RemotePath) { lock.withLock { cleanupDirectories.append(path) } }
    func recordCancelledPart(_ path: RemotePath) { record("cancel-before-commit-part=" + String(decoding: path.bytes, as: UTF8.self)) }
    private var trustHandler: FileHostTrustHandler {
        { event, reply in
            guard case .pending(let pending) = event,
                  pending.host.address.value == "127.0.0.1", pending.host.port.value == 22221,
                  pending.algorithm == "ssh-ed25519", pending.fingerprint == Self.fingerprint else {
                reply.resolve(.reject); return
            }
            reply.resolve(.confirmOnce(displayedFingerprint: Self.fingerprint))
        }
    }
    func connectFiles() async throws -> LibSSH2FileService {
        let service = try await LibSSH2FileService.connect(configuration: config, authentication: [primary],
            trustStore: trust, trustHandler: trustHandler, connectionTimeout: 5, operationTimeout: 10, token: token)
        lock.withLock { files = service }
        return service
    }
    func connectShell() async throws -> LibSSH2ShellSession {
        let policy = try NativeTCPKeepalivePolicy(interval: 30, failedProbes: 3)
        let options = try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: 10,
            interactionTimeout: 15, authenticationTimeout: 15, keepalive: policy)
        let shell = try await LibSSH2ShellSession.connect(configuration: config, primary: primary,
            trustStore: trust, trustHandler: trustHandler, options: options, connectionTimeout: 5, token: token)
        lock.withLock { shells.append(shell) }
        return shell
    }
    func createRemoteRoot(_ remote: LibSSH2FileService) async throws {
        do { try await remote.mkdir(remoteRoot, token: token); lock.withLock { rootConfirmed = true } }
        catch {
            if let typed = error as? FileServiceError, [.timeout, .transport, .cancelled, .closed].contains(typed.kind) {
                lock.withLock { rootPossible = true }
            }
            throw error
        }
    }
    func policy() -> TransferPolicy {
        let root = remoteRoot.bytes
        return TransferPolicy(confirmRisk: { risk in
            let path: RemotePath
            switch risk {
            case .remotePathChecksAreNotAtomic(let p), .overwriteIsAtomicButNotCompareAndSwap(let p), .remoteFsyncUnavailable(let p): path = p
            case .deletionChecksAreNotCompareAndSwap: return false
            }
            return path.bytes == root || path.bytes.starts(with: root + Data([47]))
                || path.bytes == Data("/fixture/protected/denied-directory/ux97-never-created.txt".utf8)
        })
    }
    func assertRemoteNames(_ remote: LibSSH2FileService, expected: Set<String>) async throws {
        let names = Set(try await remote.list(remoteRoot, token: token).map { String(decoding: $0.name.bytes, as: UTF8.self) })
        try require(names == expected, "only-expected-own-remote-objects")
    }
    func verifyFile(_ remotePath: RemotePath, bytes: Data, remote: LibSSH2FileService,
                    local: LocalFileService, engine: SafeTransferEngine, name: String) async throws {
        let report = try await engine.copy(hostID: hostID, source: remote, sourcePath: remotePath,
            destination: local, destinationPath: RemotePath("/" + name), token: token, policy: policy())
        try require(report.allSucceeded, "verify-download")
        try require(SHA256.hash(data: Data(contentsOf: localRoot.appendingPathComponent(name))) == SHA256.hash(data: bytes),
            "download-content-hash")
    }
    func shellACK(_ shell: LibSSH2ShellSession, label: String) async throws {
        let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let expected = Data(("UX97_" + label + "_" + nonce).utf8)
        let input = "n='" + nonce + "'; printf 'UX97_" + label + "_%s\\n' \"$n\"\n"
        try await shell.write(Data(input.utf8), token: token)
        let deadline = ContinuousClock.now + .seconds(12)
        var output = Data()
        while ContinuousClock.now < deadline {
            try token.check()
            switch try await shell.receive(maxBytes: 4096, wait: 0.2, token: token) {
            case .wouldBlock: break
            case .bytes(let bytes):
                output.append(bytes)
                try require(output.count <= 65536, "shell-ack-output-bound")
                if output.range(of: expected) != nil { record("real-shell-ack=" + label); return }
            case .eof, .exit: throw UX97Failure.check("shell-ended-before-ack")
            }
        }
        throw UX97Failure.check("shell-ack-deadline")
    }
    func removeRemoteRootBeforeRelease(_ remote: LibSSH2FileService) async throws {
        try require(lock.withLock { rootConfirmed }, "remote-root-confirmed-before-remove")
        try await remote.remove(remoteRoot, directory: true, token: token)
        lock.withLock { rootConfirmed = false }
    }
    private func cancelOwned() {
        token.cancel()
        let values = lock.withLock { (files, shells) }
        values.0?.cancel(); values.1.forEach { $0.cancel() }
    }
    func cleanup() async throws {
        watchdog?.cancel(); watchdog = nil
        let owned = lock.withLock { (files, shells, local, manager, rootConfirmed, rootPossible, cleanupFiles, cleanupDirectories, facts) }
        var retained: [String] = []
        if let remote = owned.0, owned.4 {
            for path in owned.6 {
                do { try await remote.remove(path, directory: false, token: CancellationToken()) }
                catch let error as FileServiceError where error.kind == .notFound { }
                catch { retained.append(String(decoding: path.bytes, as: UTF8.self)) }
            }
            for path in owned.7.reversed() {
                do { try await remote.remove(path, directory: true, token: CancellationToken()) }
                catch let error as FileServiceError where error.kind == .notFound { }
                catch { retained.append(String(decoding: path.bytes, as: UTF8.self)) }
            }
            do { try await remote.remove(remoteRoot, directory: true, token: CancellationToken()) }
            catch let error as FileServiceError where error.kind == .notFound { }
            catch { retained.append(String(decoding: remoteRoot.bytes, as: UTF8.self)) }
        } else if owned.5 { retained.append(String(decoding: remoteRoot.bytes, as: UTF8.self)) }
        if let manager = owned.3 { await manager.cancelAllAndWait() }
        for shell in owned.1 { await shell.close() }
        if let remote = owned.0 { await remote.close() }
        if let local = owned.2 { await local.close() }
        let receipt: [String: Any] = ["case": name, "elapsedSeconds": seconds(began.duration(to: .now)),
            "testFacts": owned.8, "retainedRemotePaths": retained, "privateMaterialsLogged": false,
            "network": "real-approved-loopback-only", "notProven": ["user-server-root-cause", "application-blackhole"],
            "allOwnedShellInteractionsDrained": owned.1.allSatisfy { $0.interactionSnapshot().drained },
            "caseBodyReachedSuccess": owned.8.contains { $0.hasPrefix("verified") },
            "runWatchdogSeconds": 210, "suiteCancelDeadlineSeconds": 225]
        let evidence = URL(fileURLWithPath: "/Users/liuwenshuo/Desktop/OpenLXSSH/DerivedData/CodexTakeover/20261104/four-fixes/live97")
            .appendingPathComponent("receipt-" + UUID().uuidString.lowercased(), isDirectory: true)
        try FileManager.default.createDirectory(at: evidence, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys, .prettyPrinted])
            .write(to: evidence.appendingPathComponent("result.json"), options: .withoutOverwriting)
        guard try Data(contentsOf: localRoot.appendingPathComponent(".ux97-owner")) == marker else { throw UX97Failure.boundary }
        try FileManager.default.removeItem(at: localRoot)
        if !retained.isEmpty { throw UX97Failure.cleanupRetained }
        try require(owned.1.allSatisfy { $0.interactionSnapshot().drained }, "final-owned-shell-drain")
    }
    func elapsedSeconds(since instant: ContinuousClock.Instant) -> Double { seconds(instant.duration(to: .now)) }
    private func seconds(_ value: Duration) -> Double {
        let c = value.components
        return Double(c.seconds) + Double(c.attoseconds) / 1e18
    }
}
