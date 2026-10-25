import Darwin
import Foundation
@testable import OpenLXSSHHostTrustProbe
import XCTest

@MainActor
final class StorageTests: XCTestCase {
    func testFilesAndDirectoryUseMinimumPermissionsAndAtomicReplacement() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        var metadata = stat()
        for (path, mode): (String, mode_t) in [(directory.url.path, 0o700),
                                               (store.knownHostsPath.value, 0o600),
                                               (directory.file("trust.lock").path, 0o600)] {
            XCTAssertEqual(lstat(path, &metadata), 0)
            XCTAssertEqual(metadata.st_mode & 0o7777, mode)
            XCTAssertEqual(metadata.st_uid, geteuid())
        }
        let originalInode = metadataFor(store.knownHostsPath.value).st_ino
        let lockInode = metadataFor(directory.file("trust.lock").path).st_ino
        let oldFD = open(store.knownHostsPath.value, O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(oldFD, 0)
        defer { close(oldFD) }
        let oldData = try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value))
        try await accept(store, try host(), try HostPublicKey(openSSHPublicKey: ed25519Fixture))
        XCTAssertNotEqual(metadataFor(store.knownHostsPath.value).st_ino, originalInode)
        XCTAssertEqual(metadataFor(directory.file("trust.lock").path).st_ino, lockInode)
        var buffer = [UInt8](repeating: 0, count: 4096)
        let count = read(oldFD, &buffer, buffer.count)
        XCTAssertEqual(Data(buffer.prefix(count)), oldData)
        let children = try FileManager.default.contentsOfDirectory(atPath: directory.url.path)
        XCTAssertEqual(Set(children), Set(["known_hosts", "trust.lock"]))
    }

    func testCorruptAndMaliciousFilesFailClosedWithoutErasing() async throws {
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let validHeader = "# OpenLXSSH-host-trust-v1 00000000-0000-0000-0000-000000000001\n"
        let line = "server.example " + key.openSSH + "\n"
        let cases = [Data(), Data([0xff, 0xfe]), Data("unrecognized\n".utf8),
                     Data((validHeader + "broken row\n").utf8), Data((validHeader + line + line).utf8),
                     Data((validHeader + "*.example " + key.openSSH + "\n").utf8),
                     Data((validHeader + "@cert-authority server.example " + key.openSSH + "\n").utf8),
                     Data((validHeader + "server.example ssh-ed25519 aW52YWxpZA==\n").utf8),
                     Data((validHeader + line + "\0\n").utf8), Data(repeating: 65, count: 1_048_577)]
        for bytes in cases {
            let directory = try TemporaryDirectory()
            let store = try HostTrustStore(directory: directory.path)
            let decision = try pendingDecision(try await store.evaluate(host: host(), key: key))
            try bytes.write(to: directory.file("known_hosts"))
            XCTAssertEqual(chmod(store.knownHostsPath.value, 0o600), 0)
            do { _ = try await store.records(); XCTFail("Corrupt storage must not load") } catch {}
            do {
                _ = try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
                XCTFail("Pending decision must not erase corrupt data")
            } catch {}
            XCTAssertThrowsError(try HostTrustStore(directory: directory.path))
            XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), bytes)
        }
    }

    func testMissingFileAfterInitializationIsNotRecreated() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        try FileManager.default.removeItem(atPath: store.knownHostsPath.value)
        await assertAsyncError(.corruptStorage) { try await store.records() }
        XCTAssertThrowsError(try HostTrustStore(directory: directory.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.knownHostsPath.value))
    }

    func testSymlinksHardlinksAndUnsafePermissionsAreRejected() async throws {
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        for target in ["known_hosts", "trust.lock"] {
            for attack in ["symlink", "hardlink", "permissions", "fifo"] {
                let directory = try TemporaryDirectory()
                let outside = try TemporaryDirectory()
                let store = try HostTrustStore(directory: directory.path)
                try await accept(store, try host(), key)
                let targetURL = directory.file(target)
                let bytes = try Data(contentsOf: targetURL)
                let external = outside.file("untouched")
                try bytes.write(to: external)
                XCTAssertEqual(chmod(external.path, 0o600), 0)
                if attack == "permissions" {
                    XCTAssertEqual(chmod(targetURL.path, 0o644), 0)
                } else {
                    try FileManager.default.removeItem(at: targetURL)
                    if attack == "symlink" {
                        XCTAssertEqual(symlink(external.path, targetURL.path), 0)
                    } else if attack == "hardlink" {
                        XCTAssertEqual(link(external.path, targetURL.path), 0)
                    } else {
                        XCTAssertEqual(mkfifo(targetURL.path, 0o600), 0)
                    }
                }
                do { _ = try await store.records(); XCTFail("Unsafe \(target)/\(attack) must fail") } catch {}
                XCTAssertThrowsError(try HostTrustStore(directory: directory.path))
                XCTAssertEqual(try Data(contentsOf: external), bytes)
            }
        }
        let directory = try TemporaryDirectory()
        XCTAssertEqual(chmod(directory.url.path, 0o755), 0)
        XCTAssertThrowsError(try HostTrustStore(directory: directory.path))
        XCTAssertEqual(chmod(directory.url.path, 0o700), 0)
        let alias = try TemporaryDirectory()
        let symlinkPath = alias.file("directory-link").path
        XCTAssertEqual(symlink(directory.url.path, symlinkPath), 0)
        XCTAssertThrowsError(try HostTrustStore(directory: AbsolutePath(symlinkPath)))
    }

    func testDeletedOrReplacedStableLockAndDirectoryAreRejected() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let lock = directory.file("trust.lock")
        try FileManager.default.moveItem(at: lock, to: directory.file("old-lock"))
        do { _ = try await store.records(); XCTFail("Missing lock must fail") } catch {}
        XCTAssertFalse(FileManager.default.fileExists(atPath: lock.path))
        XCTAssertTrue(FileManager.default.createFile(atPath: lock.path, contents: Data(),
                                                   attributes: [.posixPermissions: 0o600]))
        do { _ = try await store.records(); XCTFail("Replaced lock must fail") } catch {}
        let moved = directory.url.appendingPathExtension("moved")
        try FileManager.default.moveItem(at: directory.url, to: moved)
        defer { try? FileManager.default.removeItem(at: moved) }
        try FileManager.default.createDirectory(at: directory.url, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        do { _ = try await store.records(); XCTFail("Replaced directory must fail") } catch {}
    }

    func testPendingRequestCannotOverrideExternalSafeModification() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let decision = try pendingDecision(try await store.evaluate(host: host(), key: key))
        let text = try String(contentsOfFile: store.knownHostsPath.value, encoding: .utf8)
        let changed = text + "other.example " + key.openSSH + "\n"
        try Data(changed.utf8).write(to: directory.file("known_hosts"))
        await assertAsyncError(.storageChanged) {
            try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
        }
        let records = try await store.records()
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].host, try host("other.example"))
    }

    func testConcurrentStoresPreserveRecordsAndOnlyOneOldDecisionWins() async throws {
        let directory = try TemporaryDirectory()
        let path = try directory.path
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let first = try HostTrustStore(directory: path)
        let second = try HostTrustStore(directory: path)
        let a = try pendingDecision(try await first.evaluate(host: host(), key: key))
        let b = try pendingDecision(try await second.evaluate(host: host(), key: key))
        async let resultA = Self.attemptConfirm(first, a)
        async let resultB = Self.attemptConfirm(second, b)
        let results = await [resultA, resultB]
        XCTAssertEqual(results.filter { $0 }.count, 1)
        let original = try await first.records()
        XCTAssertEqual(original.count, 1)
        // Retrying must re-evaluate and re-present the decision, never replay an old acceptance.
        // An OpenSSH reader never sees a partial in-place edit, even while other stores write.
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                for _ in 0..<80 {
                    let data = try Data(contentsOf: URL(fileURLWithPath: path.value + "/known_hosts"))
                    guard let text = String(data: data, encoding: .utf8), text.hasSuffix("\n"),
                          text.hasPrefix("# OpenLXSSH-host-trust-v1 ") else {
                        throw HostTrustError.corruptStorage
                    }
                    for line in text.split(whereSeparator: { $0.isNewline }).dropFirst() {
                        guard line.split(separator: " ").count == 3 else { throw HostTrustError.corruptStorage }
                    }
                    try await Task.sleep(for: .milliseconds(2))
                }
            }
            for index in 0..<8 {
                group.addTask {
                    let writer = try HostTrustStore(directory: path)
                    let identity = try host("server-\(index).example", port: 2200 + index)
                    for _ in 0..<32 {
                        let decision = try pendingDecision(try await writer.evaluate(host: identity, key: key))
                        do {
                            try await writer.confirm(decision, displayedFingerprint: decision.fingerprint)
                            return
                        } catch HostTrustError.storageChanged { continue }
                    }
                    throw HostTrustError.storageChanged
                }
            }
            try await group.waitForAll()
        }
        let records = try await first.records()
        XCTAssertEqual(records.count, 9)
        XCTAssertEqual(Set(records.map { $0.host }).count, 9)
    }

    func testIndependentProcessesSerializeThroughStableFileLock() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        // SwiftPM places the executable alongside the .xctest bundle in both configurations.
        let executable = Bundle(for: StorageTests.self).bundleURL.deletingLastPathComponent()
            .appendingPathComponent("p1-host-trust-probe")
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: executable.path))
        var processes: [Process] = []
        defer {
            for process in processes where process.isRunning {
                process.terminate()
                process.waitUntilExit()
            }
        }
        for index in 0..<4 {
            let process = Process()
            process.executableURL = executable
            process.arguments = ["--test-only-store-writer", directory.url.path, "process-\(index).example"]
            process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            processes.append(process)
        }
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while processes.contains(where: { $0.isRunning }), ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(10))
        }
        for process in processes {
            XCTAssertFalse(process.isRunning, "Local writer exceeded deadline")
            if process.isRunning {
                process.terminate()
                process.waitUntilExit()
            } else {
                process.waitUntilExit()
                XCTAssertEqual(process.terminationStatus, 0)
            }
        }
        let records = try await store.records()
        XCTAssertEqual(records.count, 4)
        XCTAssertEqual(Set(records.map { $0.host.address.value }),
                       Set((0..<4).map { "process-\($0).example" }))
    }

    private nonisolated static func attemptConfirm(_ store: HostTrustStore, _ decision: PendingTrustDecision) async -> Bool {
        do {
            try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
            return true
        } catch { return false }
    }

    private func metadataFor(_ path: String) -> stat {
        var metadata = stat()
        XCTAssertEqual(lstat(path, &metadata), 0)
        return metadata
    }
}
