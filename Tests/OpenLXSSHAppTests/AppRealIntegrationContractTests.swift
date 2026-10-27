import Darwin
import Foundation
import XCTest

final class AppRealIntegrationContractTests: XCTestCase {
    private let id = "12345678-1234-1234-1234-123456789abc"
    private var path: String { AppRealIntegrationContract.inputRoot + "/run-" + id + "/app-real-integration.json" }
    private func object() -> [String: Any] {
        ["schema": 1, "runID": id, "host": "127.0.0.1", "port": 22221, "user": "fixture", "service": "keyonly",
         "generation": AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-012345abcdef",
         "expectedBase": AppRealIntegrationContract.base, "expectedImage": AppRealIntegrationContract.image,
         "expectedProject": AppRealIntegrationContract.project, "expectedContainer": AppRealIntegrationContract.container,
         "expectedFingerprint": AppRealIntegrationContract.fingerprint, "collectedAt": 1000.0, "preparedAt": 1100.0,
         "provenanceSHA256": String(repeating: "a", count: 64), "knownHostsSHA256": String(repeating: "b", count: 64),
         "generationPublicKeySHA256": String(repeating: "c", count: 64)]
    }
    private func decode(_ value: [String: Any]) throws -> AppRealIntegrationContract {
        try AppRealIntegrationContract.decodeStrict(JSONSerialization.data(withJSONObject: value))
    }
    func testClosedPhaseDefaultsToOldReadOnlyAndRejectsUnknownPhase() throws {
        XCTAssertEqual(try decode(object()).selectedPhase, .readOnly)
        for phase in ["read-only", "transfer-survives-close"] {
            var value = object(); value["phase"] = phase
            XCTAssertEqual(try decode(value).selectedPhase.rawValue, phase)
        }
        let invalidValues: [Any] = ["quit-all", "arbitrary-command", NSNull(), 1]
        for invalid in invalidValues {
            var value = object(); value["phase"] = invalid
            XCTAssertThrowsError(try decode(value))
        }
        var remote = object(); remote["remotePath"] = "/arbitrary"
        XCTAssertThrowsError(try decode(remote))
    }
    func testTransferScopeIsFixedUUIDRootAndBounded16MiB() throws {
        let scope = try AppRealTransferScope(runID: id)
        XCTAssertEqual(scope.remoteDirectory, "/fixture/home/openlxssh-app-transfer-" + id)
        XCTAssertEqual(scope.remotePayload, scope.remoteDirectory + "/payload-16MiB.bin")
        XCTAssertEqual(AppRealTransferScope.sourceBytes, 16 * 1024 * 1024)
        XCTAssertEqual(AppRealTransferScope.chunkBytes, 65536)
        XCTAssertTrue(scope.permitsRemote(Data(scope.remoteDirectory.utf8)))
        XCTAssertTrue(scope.permitsRemote(Data(scope.remotePayload.utf8)))
        for path in ["/fixture/home", scope.remoteDirectory + "-other", scope.remoteDirectory + "/unknown", "/etc/passwd"] {
            XCTAssertFalse(scope.permitsRemote(Data(path.utf8)))
        }
        XCTAssertThrowsError(try AppRealTransferScope(runID: "latest"))
    }
    func testRealInflightGateRejectsCompletedZeroAndDecisionWaitStates() {
        XCTAssertTrue(AppRealTransferScope.isRealInflight(state: "running", transferred: 65536, sourceBytes: 16 * 1024 * 1024))
        for state in ["queued", "waitingRisk", "waitingConflict", "succeeded", "cancelled", "failed"] {
            XCTAssertFalse(AppRealTransferScope.isRealInflight(state: state, transferred: 65536, sourceBytes: 16 * 1024 * 1024))
        }
        for count: UInt64 in [0, 16 * 1024 * 1024, 16 * 1024 * 1024 + 1] {
            XCTAssertFalse(AppRealTransferScope.isRealInflight(state: "running", transferred: count, sourceBytes: 16 * 1024 * 1024))
        }
        XCTAssertFalse(AppRealTransferScope.isRealInflight(state: "running", transferred: 65536, sourceBytes: 32 * 1024 * 1024))
    }
    func testTransferDiagnosticsOnlyExportsKnownRawPathsAndClosedStates() throws {
        let scope = try AppRealTransferScope(runID: id), temp = Data((scope.remoteDirectory + "/.openlxssh-transfer.01234567-89AB-CDEF-0123-456789ABCDEF.part").utf8)
        let sample = AppRealTransferSnapshot(stage: .pendingDecision, scope: scope, jobID: UUID(), generation: UUID(), sourceServiceID: UUID(), destinationServiceID: UUID(),
            sourcePath: Data("/unrelated-secret-name".utf8), destinationPath: Data(scope.remotePayload.utf8), state: "untrusted-state-text", transferredBytes: 65536,
            pendingQuestion: .remotePathRisk, riskPath: Data("/unrelated-risk".utf8), ownedPaths: [Data(scope.remoteDirectory.utf8), temp, Data("/outside".utf8)],
            sshState: .connected, ownedSSHPIDPresent: true, serverBinding: UUID(), connectionAttempts: 1)
        let encoded = try JSONEncoder().encode(sample), text = String(decoding: encoded, as: UTF8.self)
        XCTAssertNil(sample.sourcePathBase64); XCTAssertNil(sample.riskPathBase64)
        XCTAssertEqual(sample.state, .unknown); XCTAssertEqual(sample.ownedPathsBase64.count, 2); XCTAssertEqual(sample.rejectedPaths, 3)
        for forbidden in ["unrelated-secret-name", "untrusted-state-text", "unrelated-risk", "password", "privateKey", "terminal", "errorDescription"] { XCTAssertFalse(text.contains(forbidden)) }
        XCTAssertEqual(try JSONDecoder().decode(AppRealTransferSnapshot.self, from: encoded).stage, .pendingDecision)
        XCTAssertFalse(scope.permitsDiagnosticPath(Data((scope.remoteDirectory + "/.openlxssh-transfer.latest.part").utf8)))
        XCTAssertFalse(scope.permitsDiagnosticPath(Data((scope.remoteDirectory + "/other").utf8)))
    }
    func testTransferDiagnosticRingKeepsAtMostEightNewestMetadataSnapshots() throws {
        let scope = try AppRealTransferScope(runID: id)
        var ring = AppRealTransferDiagnostics()
        for count in 0..<25 {
            let sample = AppRealTransferSnapshot(stage: .observeJob, scope: scope, jobID: nil, generation: nil, sourceServiceID: nil, destinationServiceID: nil,
                sourcePath: nil, destinationPath: nil, state: "running", transferredBytes: UInt64(count), pendingQuestion: .none, riskPath: nil, ownedPaths: [],
                sshState: .connected, ownedSSHPIDPresent: true, serverBinding: nil, connectionAttempts: 1)
            ring.record(sample)
        }
        ring.enter(.preCloseAction); ring.failed(.preCloseInflight)
        XCTAssertEqual(ring.snapshots.count, 8); XCTAssertEqual(ring.snapshots.first?.transferredBytes, 17); XCTAssertEqual(ring.snapshots.last?.transferredBytes, 24)
        XCTAssertEqual(ring.stage, .preCloseAction); XCTAssertEqual(ring.failedGuard, .preCloseInflight)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(ring)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["stage", "failedGuard", "snapshots"])
    }
    func testDefaultValidateAndHelpArePureParsingWithoutExistingFiles() throws {
        XCTAssertEqual(try AppRealIntegrationArguments.parse([], hostProbe: true).action, .none)
        XCTAssertEqual(try AppRealIntegrationArguments.parse([], hostProbe: false).action, .none)
        XCTAssertEqual(try AppRealIntegrationArguments.parse(["--real-fixture-help"], hostProbe: true).action, .help)
        let options = try AppRealIntegrationArguments.parse(["--real-fixture-validate", "--real-fixture-contract", "/does/not/exist/app-real-integration.json"], hostProbe: true)
        XCTAssertEqual(options.action, .validate)
        XCTAssertEqual(options.scanSeconds, 5)
    }
    func testShippingRejectsEveryRealFixtureFlagIncludingHelpValidateAndAuthorization() {
        for flag in AppRealIntegrationArguments.flagNames.union(["--real-fixture-unknown"]) {
            XCTAssertThrowsError(try AppRealIntegrationArguments.parse([flag], hostProbe: false))
        }
    }
    func testBothAuthorizationGatesRequiredAndNoUnknownOrMixedSmokeFlags() throws {
        let base = ["--real-fixture-test", "--real-fixture-contract", path]
        for suffix in [[], ["--authorized-local-fixture"], ["--primary-released"]] {
            XCTAssertThrowsError(try AppRealIntegrationArguments.parse(base + suffix, hostProbe: true))
        }
        let valid = base + ["--authorized-local-fixture", "--primary-released"]
        XCTAssertEqual(try AppRealIntegrationArguments.parse(valid, hostProbe: true).action, .live)
        XCTAssertEqual(try AppRealIntegrationArguments.parse(valid, hostProbe: true).scanSeconds, 5)
        XCTAssertEqual(try AppRealIntegrationArguments.parse(valid + ["--real-fixture-scan-seconds", "15"], hostProbe: true).scanSeconds, 15)
        for suffix in [["--self-test-data-dir", "/tmp/other"], ["--host", "example.com"], ["--password", "synthetic"],
                       ["--real-fixture-scan-seconds", "20"], ["--authorized-local-fixture"], ["--real-fixture-contract", path]] {
            XCTAssertThrowsError(try AppRealIntegrationArguments.parse(valid + suffix, hostProbe: true))
        }
    }
    func testStrictSchemaRejectsAdditionalAndMissingFields() throws {
        XCTAssertNoThrow(try decode(object()))
        var extra = object(); extra["password"] = "synthetic-not-used"
        XCTAssertThrowsError(try decode(extra))
        var missing = object(); missing["expectedFingerprint"] = nil
        XCTAssertThrowsError(try decode(missing))
    }
    func testExactBindingAndGenerationGate() throws {
        let value = try decode(object())
        XCTAssertNoThrow(try value.validate(path: path, now: 1200, buildEpoch: 999))
        for (key, wrong) in [("host", "example.com"), ("user", "root"), ("service", "passwordonly"), ("expectedImage", "sha256:unreviewed"),
                             ("expectedContainer", String(repeating: "0", count: 64)), ("expectedProject", "other"),
                             ("expectedFingerprint", "SHA256:unverified"), ("generation", AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-latest"),
                             ("generation", AppRealIntegrationContract.fixtureRoot + "/.runtime/passwordonly/credentials-012345abcdef")] {
            var bad = object(); bad[key] = wrong
            XCTAssertThrowsError(try decode(bad).validate(path: path, now: 1200, buildEpoch: 999))
        }
        var port = object(); port["port"] = 22222
        XCTAssertThrowsError(try decode(port).validate(path: path, now: 1200, buildEpoch: 999))
    }
    func testFreshnessRunIDAndTraversalAreNotRelaxed() throws {
        let value = try decode(object())
        for (now, build) in [(1099.0, 999.0), (2900.1, 999), (1200, 1001), (.nan, 999)] {
            XCTAssertThrowsError(try value.validate(path: path, now: now, buildEpoch: build))
        }
        for bad in ["relative", "/a/../app-real-integration.json", "/a//b", "/a/./b", "/a/$b", "/a/\nb", path.replacingOccurrences(of: id, with: "latest"), "/etc/passwd"] {
            XCTAssertThrowsError(try AppRealIntegrationContract.validateContractPath(bad))
        }
    }
    func testTrustRequiresEndpointAlgorithmAndWholeFingerprint() throws {
        let value = try decode(object())
        XCTAssertTrue(value.matchesTrust(host: "127.0.0.1", port: 22221, algorithm: "ssh-ed25519", fingerprint: AppRealIntegrationContract.fingerprint))
        XCTAssertFalse(value.matchesTrust(host: "localhost", port: 22221, algorithm: "ssh-ed25519", fingerprint: AppRealIntegrationContract.fingerprint))
        XCTAssertFalse(value.matchesTrust(host: "127.0.0.1", port: 22222, algorithm: "ssh-ed25519", fingerprint: AppRealIntegrationContract.fingerprint))
        XCTAssertFalse(value.matchesTrust(host: "127.0.0.1", port: 22221, algorithm: "ssh-rsa", fingerprint: AppRealIntegrationContract.fingerprint))
        XCTAssertFalse(value.matchesTrust(host: "127.0.0.1", port: 22221, algorithm: "ssh-ed25519", fingerprint: String(AppRealIntegrationContract.fingerprint.dropLast())))
    }
    #if HOST_PROBE
    func testPrivateMetadataRejectsPermissionLinksFIFOAndOversizeWithoutSecrets() throws {
        let temporary = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
        let root = temporary.appendingPathComponent("OpenLXSSH-AppTests-real-contract-" + UUID().uuidString)
        XCTAssertEqual(mkdir(root.path, 0o700), 0)
        let fd = try AppRealPrivateInput.directory(root.path)
        defer {
            for name in ["metadata", "hard", "link", "fifo"] { _ = unlinkat(fd, name, 0) }
            Darwin.close(fd); _ = rmdir(root.path)
        }
        try AppRealPrivateInput.write(Data("synthetic-only\n".utf8), parent: fd, name: "metadata")
        let path = root.appendingPathComponent("metadata").path
        XCTAssertEqual(try AppRealPrivateInput.read(path, limit: 128), Data("synthetic-only\n".utf8))
        XCTAssertThrowsError(try AppRealPrivateInput.read(path, limit: 2))
        XCTAssertEqual(chmod(path, 0o644), 0); XCTAssertThrowsError(try AppRealPrivateInput.read(path, limit: 128))
        XCTAssertEqual(chmod(path, 0o600), 0)
        XCTAssertEqual(linkat(fd, "metadata", fd, "hard", 0), 0); XCTAssertThrowsError(try AppRealPrivateInput.read(path, limit: 128)); XCTAssertEqual(unlinkat(fd, "hard", 0), 0)
        XCTAssertEqual(symlinkat("metadata", fd, "link"), 0); XCTAssertThrowsError(try AppRealPrivateInput.read(root.appendingPathComponent("link").path, limit: 128))
        XCTAssertEqual(mkfifoat(fd, "fifo", 0o600), 0); XCTAssertThrowsError(try AppRealPrivateInput.read(root.appendingPathComponent("fifo").path, limit: 128))
        var acl = acl_init(1), entry: acl_entry_t?
        XCTAssertNotNil(acl); defer { acl_free(UnsafeMutableRawPointer(acl!)) }
        XCTAssertEqual(acl_create_entry(&acl, &entry), 0)
        XCTAssertEqual(acl_set_tag_type(entry!, ACL_EXTENDED_ALLOW), 0)
        var identity = UUID().uuid
        XCTAssertEqual(acl_set_qualifier(entry!, &identity), 0) // Synthetic ACL principal only; never queries user/group directories.
        var permissions: acl_permset_t?; XCTAssertEqual(acl_get_permset(entry!, &permissions), 0)
        XCTAssertEqual(acl_add_perm(permissions!, ACL_READ_DATA), 0)
        XCTAssertEqual(acl_set_file(path, ACL_TYPE_EXTENDED, acl), 0)
        XCTAssertThrowsError(try AppRealPrivateInput.read(path, limit: 128))
    }
    #endif
}
