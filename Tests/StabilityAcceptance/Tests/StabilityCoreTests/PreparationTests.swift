import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import StabilityCore
import StabilityPOSIX

final class PreparationTests: XCTestCase {
    private var root: URL!
    override func setUpWithError() throws {
        let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let parent = here.appendingPathComponent(".build", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        root = parent.appendingPathComponent("offline-unit-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    override func tearDownWithError() throws {
        // Only this test-created exact UUID directory; no fixture/runtime cleanup.
        if let root { try FileManager.default.removeItem(at: root) }
    }
    private func put(_ path: URL, _ bytes: Data) throws {
        XCTAssertTrue(FileManager.default.createFile(atPath: path.path, contents: bytes, attributes: [.posixPermissions: 0o600]))
    }
    private func put(_ path: URL, _ text: String) throws { try put(path, Data(text.utf8)) }

    func testDefaultHelpAndReadonlyValidate() throws {
        XCTAssertEqual(try Options.parse([]).action, .help)
        XCTAssertEqual(try Options.parse(["validate"]).action, .validate)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }
    func testExactLoopbackRefusal() throws {
        for host in ["localhost", "127.1", "127.0.0.2", "127.0.0.1.", "2130706433", "::1", "[::1]", "::ffff:127.0.0.1", "0.0.0.0", "example.com", "127.0.0.1\n", " 127.0.0.1", "127.000.000.001", "192.0.2.1"] {
            XCTAssertThrowsError(try Options.parse(["validate", "--host", host]), host)
        }
        XCTAssertThrowsError(try Options.parse(["validate", "--port", "22"]))
        XCTAssertNoThrow(try Options.parse(["validate", "--host", "127.0.0.1", "--port", "22221"]))
    }
    func testMissingFlagRefusesBeforeMaterialChecksOrWrites() throws {
        // A forbidden/nonexistent/symlink path must never be inspected first.
        XCTAssertThrowsError(try Options.parse(["run", "--credentials", "/forbidden/symlink/private-key", "--output-parent", root.path])) {
            XCTAssertEqual($0 as? StabilityError, .authorizationRequired)
        }
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }
    func testNoShorteningOrUnboundedLoops() throws {
        for duration in ["0", "1", "86399", "604801", "-1", "nan", "86400.0", "086400"] {
            XCTAssertThrowsError(try Options.parse(["validate", "--mode", "soak", "--duration-seconds", duration]))
        }
        XCTAssertThrowsError(try Options.parse(["validate", "--cycles", "199"]))
        XCTAssertThrowsError(try Options.parse(["validate", "--sessions", "6"]))
        XCTAssertThrowsError(try Options.parse(["validate", "--duration-seconds", "604800", "--sample-seconds", "5"]))
        XCTAssertNoThrow(try Options.parse(["validate", "--duration-seconds", "604800", "--sample-seconds", "30"]))
        XCTAssertThrowsError(try Options.parse(["validate", "--time-scale", "1000"]))
        XCTAssertThrowsError(try Options.parse(["validate", "--host", "127.0.0.1", "--host", "127.0.0.1"]))
        XCTAssertNoThrow(try Options.parse(["validate", "--duration-seconds", "86400"]))
    }
    func testPrivatePathsPermissionsSymlinksHardlinksAndSpecialFiles() throws {
        let publicFile = root.appendingPathComponent("public.txt")
        try put(publicFile, "public-only")
        try PrivateMaterial.check(root.path, directory: true)
        XCTAssertEqual(try PrivateMaterial.readPublic(publicFile.path), Data("public-only".utf8))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: publicFile.path)
        XCTAssertThrowsError(try PrivateMaterial.readPublic(publicFile.path))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: publicFile.path)
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: publicFile)
        XCTAssertThrowsError(try PrivateMaterial.readPublic(link.path))
        let alias = root.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: root)
        XCTAssertThrowsError(try PrivateMaterial.readPublic(alias.appendingPathComponent("public.txt").path))
        let hard = root.appendingPathComponent("hard")
        try FileManager.default.linkItem(at: publicFile, to: hard)
        XCTAssertThrowsError(try PrivateMaterial.readPublic(hard.path))
        XCTAssertThrowsError(try PrivateMaterial.readPublic(publicFile.path))
        let fifo = root.appendingPathComponent("fifo")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        XCTAssertThrowsError(try PrivateMaterial.check(fifo.path, directory: false))
        for path in [root.path + "/../key", root.path + "//key", root.path + "/$KEY", root.path + "/key\n"] {
            XCTAssertThrowsError(try PrivateMaterial.validateSyntax(path))
        }
    }
    func testExtendedACLRejectedRatherThanStripped() throws {
        let path = root.appendingPathComponent("public.txt")
        try put(path, "nonsecret ACL fixture")
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", "everyone allow read", path.path]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertThrowsError(try PrivateMaterial.readPublic(path.path))
        let remove = Process(); remove.executableURL = URL(fileURLWithPath: "/bin/chmod")
        remove.arguments = ["-N", path.path]; remove.standardOutput = FileHandle.nullDevice; remove.standardError = FileHandle.nullDevice
        try remove.run(); remove.waitUntilExit()
        XCTAssertEqual(remove.terminationStatus, 0)
        XCTAssertNoThrow(try PrivateMaterial.readPublic(path.path))
    }
    private func fixture() throws -> (Options, String) {
        var directory = root!
        for name in ["Tests", "IntegrationEnvironment", ".runtime", "keyonly", "credentials-0123456789ab"] {
            directory.appendPathComponent(name, isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
        // Non-secret synthetic public bytes only, not a private key or SSH server.
        let bytes = Data([0,0,0,11] + Array("ssh-ed25519".utf8) + [0,0,0,32] + Array(repeating: UInt8(1), count: 32))
        let base64 = bytes.base64EncodedString()
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: bytes)).base64EncodedString().replacingOccurrences(of: "=", with: "")
        try put(directory.appendingPathComponent("known_hosts"), "[127.0.0.1]:22221 ssh-ed25519 " + base64 + "\n")
        try put(directory.appendingPathComponent("fingerprint.txt"), "256 " + fingerprint + " offline-public-only (ED25519)\n")
        try put(directory.appendingPathComponent("id_ed25519.pub"), "ssh-ed25519 " + base64 + " offline-public-only\n")
        // This deliberately is NOT a private key. inspect() must be metadata-only.
        try put(directory.appendingPathComponent("id_ed25519"), "OFFLINE METADATA SENTINEL; NOT KEY MATERIAL")
        try put(directory.appendingPathComponent("provenance.json"), "{\"service\":\"keyonly\",\"base_image\":\"docker.io/library/ubuntu:24.04@sha256:" + String(repeating: "a", count: 64) + "\",\"built_image_id\":\"sha256:" + String(repeating: "b", count: 64) + "\",\"collected_at\":1000}")
        return (try Options.parse(["validate", "--credentials", directory.path, "--verified-host-fingerprint", fingerprint]), directory.path)
    }
    func testPublicFixtureChecksOOBFingerprintAndNoPrivateReads() throws {
        let (options, directory) = try fixture()
        let value = try FixturePublic.inspect(options)
        XCTAssertEqual(value.hostFingerprint, options.verifiedFingerprint)
        var wrong = options; wrong.verifiedFingerprint = "SHA256:" + String(repeating: "A", count: 43)
        XCTAssertThrowsError(try FixturePublic.inspect(wrong))
        // Password/passphrase files are not present: neither is needed or opened.
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory + "/password.txt"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory + "/key-passphrase.txt"))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: directory + "/id_ed25519")
        XCTAssertThrowsError(try FixturePublic.inspect(options))
    }
    func testEvidenceContainsAllowlistedMetadataNoMaterialPathsOrContents() throws {
        let (options, _) = try fixture()
        let value = try FixturePublic.inspect(options)
        let metadata = EvidenceMetadata(options: options, fixture: value, signedAppPath: "/reviewed/OpenLXSSHStability.app", sourceRevision: String(repeating: "c", count: 40))
        let path = root.appendingPathComponent("evidence.jsonl").path
        do {
            let writer = try BoundedEvidence(exclusivePath: path)
            try writer.append(EvidenceRow(event: .start, metadata: metadata))
        }
        let text = String(decoding: try PrivateMaterial.readPublic(path), as: UTF8.self)
        XCTAssertTrue(text.contains(value.hostFingerprint))
        for denied in ["OFFLINE METADATA SENTINEL", "credentials-", "id_ed25519", ".runtime", "password.txt", "key-passphrase", "known_hosts", value.clientPublicKeyLine] {
            XCTAssertFalse(text.contains(denied), denied)
        }
        XCTAssertThrowsError(try BoundedEvidence(exclusivePath: path))
    }
    func testEvidenceBoundedRows() throws {
        let writer = try BoundedEvidence(exclusivePath: root.appendingPathComponent("bounded.jsonl").path)
        let row = EvidenceRow(event: .sample, clock: ClockReading(wallUnix: 0, monotonic: 0, continuous: 0))
        for _ in 0..<BoundedEvidence.maximumRows { try writer.append(row) }
        XCTAssertThrowsError(try writer.append(row)) { XCTAssertEqual($0 as? StabilityError, .evidenceLimit) }
    }
    func testOwnedScopeExcludesForeignAndRecycledPIDs() throws {
        let own = ProcessIdentity(pid: 100, parentPID: 1, uid: 501, startSeconds: 1, startMicroseconds: 0)
        var scope = OwnedProcessScope(owner: own)
        let ssh = ProcessIdentity(pid: 101, parentPID: 100, uid: 501, startSeconds: 2, startMicroseconds: 0)
        try scope.registerSSH(ssh, sessionOwnedPID: 101)
        let foreign = ProcessIdentity(pid: 102, parentPID: 1, uid: 501, startSeconds: 2, startMicroseconds: 0)
        XCTAssertThrowsError(try scope.registerSSH(foreign, sessionOwnedPID: 102))
        XCTAssertThrowsError(try scope.registerSSH(ssh, sessionOwnedPID: 102))
        let helper = ProcessIdentity(pid: 103, parentPID: 101, uid: 501, startSeconds: 3, startMicroseconds: 0)
        try scope.registerHelper(helper, parent: ssh)
        XCTAssertThrowsError(try scope.registerHelper(foreign, parent: ssh))
        XCTAssertFalse(scope.contains(foreign))
        XCTAssertFalse(scope.contains(ProcessIdentity(pid: 101, parentPID: 100, uid: 501, startSeconds: 99, startMicroseconds: 0)))
        XCTAssertTrue(scope.contains(helper))
        XCTAssertTrue(scope.contains(ProcessIdentity(pid: 103, parentPID: 1, uid: 501, startSeconds: 3, startMicroseconds: 0)), "observed helper lifetime stays owned after reparenting")
    }
    func testTimingEvidenceUsesActualReadingsAndExactCleanupRefusesNonemptyOrAliasedRoots() throws {
        let start = ClockReading(wallUnix: 10, monotonic: 20, continuous: 30)
        let end = ClockReading(wallUnix: 41, monotonic: 50, continuous: 61)
        let timing = TimingEvidence(start: start, end: end)
        XCTAssertEqual(timing.monotonicElapsedSeconds, 30)
        XCTAssertEqual(timing.wallElapsedSeconds, 31)
        XCTAssertEqual(timing.continuousElapsedSeconds, 31)
        let runRoot = root.appendingPathComponent("stability-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: runRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let sessions = runRoot.appendingPathComponent("sessions", isDirectory: true)
        try FileManager.default.createDirectory(at: sessions, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let leftover = sessions.appendingPathComponent("leftover")
        try put(leftover, "nonsecret leftover")
        XCTAssertThrowsError(try ExactWorkspaceCleanup.removeEmptySessions(inExactRunRoot: runRoot.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: leftover.path))
        try FileManager.default.removeItem(at: leftover)
        try ExactWorkspaceCleanup.removeEmptySessions(inExactRunRoot: runRoot.path)
        XCTAssertFalse(FileManager.default.fileExists(atPath: sessions.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: runRoot.path))
        XCTAssertThrowsError(try ExactWorkspaceCleanup.removeEmptySessions(inExactRunRoot: root.path))
    }
    func testLocalSelfMetricsOnly() throws {
        let sampler = try ResourceSampler(exactHelper: "/nonexistent/offline-helper")
        let samples = try sampler.sample(sessionOwnedPIDs: [])
        XCTAssertEqual(samples.count, 1); XCTAssertEqual(samples[0].identity.pid, getpid())
        XCTAssertEqual(samples[0].role, .driver)
        XCTAssertGreaterThan(samples[0].rssBytes, 0)
        XCTAssertGreaterThan(samples[0].fdDescriptors, 0)
        XCTAssertGreaterThan(samples[0].kernelThreads, 0)
        XCTAssertTrue(try sampler.observedChildrenStillAlive().isEmpty)
    }
}

final class ContinuityTests: XCTestCase {
    private let start = ClockReading(wallUnix: 1000, monotonic: 2000, continuous: 3000)
    private func reading(_ elapsed: Double, wall: Double = 0, sleep: Double = 0) -> ClockReading {
        ClockReading(wallUnix: 1000 + elapsed + wall, monotonic: 2000 + elapsed, continuous: 3000 + elapsed + sleep)
    }
    func testMinimum24HoursAndNoFastForward() throws {
        XCTAssertThrowsError(try ContinuityGuard(start: start, requiredSeconds: 86399, maximumGap: 35))
        var guardClock = try ContinuityGuard(start: start, requiredSeconds: 86400, maximumGap: 35)
        try guardClock.observe(reading(30), connectedSessions: 5, sleepObserved: false)
        XCTAssertFalse(guardClock.completed)
        XCTAssertThrowsError(try guardClock.observe(reading(86400), connectedSessions: 5, sleepObserved: false))
        XCTAssertFalse(guardClock.completed)
    }
    func testSyntheticSequenceOnlyProvesVerdictPredicateNotElapsedRuntime() throws {
        var guardClock = try ContinuityGuard(start: start, requiredSeconds: 86400, maximumGap: 35)
        for elapsed in stride(from: 30, through: 86400, by: 30) {
            try guardClock.observe(reading(Double(elapsed)), connectedSessions: 5, sleepObserved: false)
        }
        XCTAssertEqual(guardClock.elapsedSeconds, 86400)
        XCTAssertTrue(guardClock.completed) // Synthetic unit assertion, never writes acceptance JSONL.
    }
    func testDisconnectSleepClockJumpAndBackwardTimeFail() throws {
        for (value, count, slept) in [(reading(30), 4, false), (reading(30), 5, true), (reading(30, sleep: 8), 5, false), (reading(30, wall: 8), 5, false), (reading(-1), 5, false)] {
            var clock = try ContinuityGuard(start: start, requiredSeconds: 86400, maximumGap: 35)
            XCTAssertThrowsError(try clock.observe(value, connectedSessions: count, sleepObserved: slept))
            XCTAssertFalse(clock.completed)
        }
    }
}

@MainActor private final class OfflineSession: AcceptanceSession {
    var phase = SessionPhase.pending
    var ownedPID: Int32?
    var authenticated = false
    var failure: StabilityError?
    var cancellationEligible: Bool { phase == .pending && failure == nil && !authenticated }
    var connectError = false, neverClose = false
    var canAuthenticate: () -> Bool = { true }
    var ticks = 0, closes = 0, cancels = 0
    func connect() throws { if connectError { throw StabilityError.invalidLifecycle }; ownedPID = 100 }
    func cancel() { cancels += 1; phase = .closing }
    func close() { closes += 1; phase = .closing }
    func tick() {
        ticks += 1
        if (phase == .closing || (phase == .closed && ownedPID != nil)) && !neverClose {
            if ticks % 2 == 0 { phase = .closed } // Closed without nil owner is insufficient.
            if ticks % 3 == 0 { ownedPID = nil; phase = .closed }
        } else if phase == .pending && canAuthenticate() && ticks >= 2 { phase = .connected; authenticated = true }
    }
}

final class FiniteLifecycleTests: XCTestCase {
    @MainActor func test200AuthenticatedAnd20SeparateCancellationsAllClosedBeforeNext() async throws {
        var sessions: [OfflineSession] = []
        let totals = try await FiniteLifecycle.cycles(cancelEvery: 10, stopped: { false }, make: {
            XCTAssertTrue(sessions.allSatisfy({ $0.phase == .closed && $0.ownedPID == nil }))
            let next = OfflineSession(); sessions.append(next); return next
        }, wait: { sessions.last?.tick() })
        XCTAssertEqual(totals.authenticatedCycles, 200)
        XCTAssertEqual(totals.cancelledAttempts, 20)
        XCTAssertEqual(totals.closedSessions, 220)
        XCTAssertEqual(sessions.count, 220)
        XCTAssertEqual(sessions.filter({ $0.authenticated }).count, 200)
        XCTAssertTrue(sessions.allSatisfy({ $0.phase == .closed && $0.ownedPID == nil && $0.closes >= 1 }))
    }
    @MainActor func testExternalStopClosesCurrentBeforeReturnAndNoNext() async throws {
        var sessions: [OfflineSession] = [], stopped = false
        do {
            _ = try await FiniteLifecycle.cycles(cancelEvery: 0, stopped: { stopped }, make: {
                let next = OfflineSession(); next.canAuthenticate = { false }; sessions.append(next); return next
            }, wait: { stopped = true; sessions.last?.tick() })
            XCTFail("expected cancellation")
        } catch { XCTAssertEqual(error as? StabilityError, .cancelled) }
        XCTAssertEqual(sessions.count, 1)
        XCTAssertEqual(sessions[0].phase, .closed); XCTAssertNil(sessions[0].ownedPID)
    }
    @MainActor func testStopDuringInterleavedCancelDoesNotStartNextSuccessfulSession() async throws {
        var sessions: [OfflineSession] = [], stopped = false
        do {
            _ = try await FiniteLifecycle.cycles(cancelEvery: 1, stopped: { stopped }, make: {
                let next = OfflineSession(); sessions.append(next); return next
            }, wait: { stopped = true; sessions.last?.tick() })
            XCTFail("expected cancellation")
        } catch { XCTAssertEqual(error as? StabilityError, .cancelled) }
        XCTAssertEqual(sessions.count, 1)
        XCTAssertFalse(sessions[0].authenticated)
        XCTAssertEqual(sessions[0].phase, .closed); XCTAssertNil(sessions[0].ownedPID)
    }
    @MainActor func testHungCleanupFiniteAndNoNewSession() async throws {
        var sessions: [OfflineSession] = [], waits = 0
        do {
            _ = try await FiniteLifecycle.cycles(cancelEvery: 0, stopped: { false }, make: {
                let next = OfflineSession(); next.neverClose = true; sessions.append(next); return next
            }, wait: { waits += 1; sessions.last?.tick() })
            XCTFail("expected cleanup failure")
        } catch { XCTAssertEqual(error as? StabilityError, .cleanupIncomplete) }
        XCTAssertEqual(sessions.count, 1); XCTAssertLessThanOrEqual(waits, 242)
    }
    @MainActor func testAuthenticationTimeoutCleanupAndConnectFailureCleanup() async throws {
        for failingConnect in [false, true] {
            var sessions: [OfflineSession] = [], waits = 0
            do {
                _ = try await FiniteLifecycle.cycles(cancelEvery: 0, stopped: { false }, make: {
                    let next = OfflineSession(); next.connectError = failingConnect; next.canAuthenticate = { false }
                    sessions.append(next); return next
                }, wait: { waits += 1; sessions.last?.tick() })
                XCTFail("expected failure")
            } catch { XCTAssertEqual(error as? StabilityError, failingConnect ? .invalidLifecycle : .timeout) }
            XCTAssertEqual(sessions.count, 1); XCTAssertLessThanOrEqual(waits, 603)
            XCTAssertEqual(sessions[0].phase, .closed); XCTAssertNil(sessions[0].ownedPID)
        }
    }
}
