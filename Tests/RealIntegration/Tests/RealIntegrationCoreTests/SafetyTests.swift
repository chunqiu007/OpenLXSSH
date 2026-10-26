import CryptoKit
import Darwin
import Foundation
import XCTest
import RealIntegrationPOSIX
@testable import RealIntegrationCore

final class SafetyTests: XCTestCase {
    let fixtureRoot = "/workspace/Tests/IntegrationEnvironment"
    var generation: String { fixtureRoot + "/.runtime/passwordonly/credentials-012345abcdef" }
    func contract(service: String = "passwordonly", mode: String = "ssh", testCase: String = "positive", plan: String = "single-manual-password") throws -> Contract {
        let directory = fixtureRoot + "/.runtime/" + service + "/credentials-012345abcdef"
        var response: [String: Any] = ["kind": plan]
        if plan == "single-manual-password" { response["expectedPromptSHA256"] = PrivateInput.sha256(Data("exact coordinator reviewed request".utf8)) }
        let object: [String: Any] = ["schema": 1, "fixtureLabel": "env-fixture-a", "mode": mode, "testCase": testCase,
            "service": service, "host": "127.0.0.1", "port": service == "keyonly" ? 22221 : 22222, "user": "fixture",
            "credentialDirectory": directory, "expectedFingerprint": "SHA256:" + Data(repeating: 1, count: 32).base64EncodedString().dropLast(),
            "expectedBaseImage": "docker.io/library/ubuntu:24.04@sha256:" + String(repeating: "a", count: 64),
            "expectedBuiltImageID": "sha256:" + String(repeating: "b", count: 64), "responsePlan": response]
        return try JSONDecoder().decode(Contract.self, from: JSONSerialization.data(withJSONObject: object))
    }
    func testDefaultHelpValidateAndMissingAuthorizationArePureParsing() throws {
        XCTAssertEqual(try Options.parse([]).action, .help)
        XCTAssertEqual(try Options.parse(["--help"]).action, .help)
        let nonexistent = "/this/does/not/exist/real-integration.json"
        XCTAssertEqual(try Options.parse(["validate", "--contract", nonexistent]).action, .validate)
        for args in [["--live", "--contract", nonexistent],
                     ["--live", "--authorized-local-fixture", "--contract", nonexistent],
                     ["--live", "--engine-ready", "--contract", nonexistent]] {
            XCTAssertThrowsError(try Options.parse(args)) { XCTAssertEqual($0 as? SmokeError, .authorizationRequired) }
        }
        XCTAssertEqual(try Options.parse(["--live", "--authorized-local-fixture", "--engine-ready", "--contract", nonexistent]).action, .live)
        for bad in [["--host", "example.com"], ["--live", "--password", "not-a-supported-argument"],
                    ["validate", "--contract", nonexistent, "--contract", nonexistent], ["validate", "--contract", "relative/real-integration.json"]] {
            XCTAssertThrowsError(try Options.parse(bad))
        }
    }
    func testFixedServicePortGenerationAndResponsePlan() throws {
        let valid = try contract()
        XCTAssertNoThrow(try valid.validate(contractPath: generation + "/real-integration.json", fixtureRoot: fixtureRoot))
        for path in [generation.replacingOccurrences(of: "012345abcdef", with: "latest") + "/real-integration.json",
                     generation.replacingOccurrences(of: "012345abcdef", with: "ffffffffffff") + "/real-integration.json",
                     generation.replacingOccurrences(of: "passwordonly", with: "keyonly") + "/real-integration.json"] {
            XCTAssertThrowsError(try valid.validate(contractPath: path, fixtureRoot: fixtureRoot))
        }
        for invalid in [try contract(service: "keyonly", testCase: "bad-password", plan: "none"),
                        try contract(testCase: "unregistered-key"), try contract(plan: "none"),
                        try contract(mode: "sftp")] {
            XCTAssertThrowsError(try invalid.validate(contractPath: invalid.credentialDirectory + "/real-integration.json", fixtureRoot: fixtureRoot))
        }
        // No file exists and arbitrary files are refused before the first open.
        XCTAssertThrowsError(try FixtureInput.load(contractPath: "/etc/passwd", fixtureRoot: fixtureRoot)) { XCTAssertEqual($0 as? SmokeError, .invalidContract) }
    }
    func testUnknownPromptExtraAnswerAndKindFailClosed() throws {
        var budget = ResponseBudget(plan: try contract().responsePlan)
        XCTAssertThrowsError(try budget.claim(prompt: "Password:", masked: true, hasHint: false)) { XCTAssertEqual($0 as? SmokeError, .unknownPrompt) }
        XCTAssertEqual(budget.requestCount, 1); XCTAssertEqual(budget.answerCount, 0); XCTAssertEqual(budget.refusedCount, 1)
        XCTAssertThrowsError(try budget.claim(prompt: "exact coordinator reviewed request", masked: true, hasHint: false))
        var correct = ResponseBudget(plan: try contract().responsePlan)
        try correct.claim(prompt: "exact coordinator reviewed request", masked: true, hasHint: false)
        XCTAssertNoThrow(try correct.requireConsumed()); XCTAssertEqual(correct.answerCount, 1)
        XCTAssertThrowsError(try correct.claim(prompt: "exact coordinator reviewed request", masked: true, hasHint: false)) { XCTAssertEqual($0 as? SmokeError, .extraAnswer) }
        for pair in [(false, false), (true, true)] {
            var kind = ResponseBudget(plan: try contract().responsePlan)
            XCTAssertThrowsError(try kind.claim(prompt: "exact coordinator reviewed request", masked: pair.0, hasHint: pair.1))
        }
        var key = ResponseBudget(plan: try contract(service: "keyonly", plan: "none").responsePlan)
        XCTAssertNoThrow(try key.requireConsumed())
        XCTAssertThrowsError(try key.claim(prompt: "anything", masked: true, hasHint: false))
    }
    func testTimeoutCancelAndTickCounters() throws {
        XCTAssertEqual(Contract.hostKeyScanSeconds, 15)
        XCTAssertEqual(Contract.connectionSeconds, 20)
        XCTAssertEqual(Contract.operationSeconds, 20)
        XCTAssertEqual(Contract.operationSeconds, TimeInterval(Contract.connectionSeconds))
        XCTAssertEqual(Contract.caseSeconds, 30)
        XCTAssertEqual(Contract.drainSeconds, 12)
        XCTAssertLessThan(TimeInterval(Contract.hostKeyScanSeconds), Contract.caseSeconds)
        XCTAssertLessThan(TimeInterval(Contract.connectionSeconds), Contract.caseSeconds)
        // API limits apply to each stage, not a reserved serial sum.
        XCTAssertLessThan(Contract.operationSeconds, Contract.caseSeconds)
        // The outer cap remains absolute, not the sum of per-stage allowances.
        var wholeCase = try WaitBudget(start: 100, seconds: Contract.caseSeconds, maximumTicks: 600)
        try wholeCase.tick(now: 129.95)
        XCTAssertThrowsError(try wholeCase.tick(now: 130)) { XCTAssertEqual($0 as? SmokeError, .timeout) }
        var drain = try WaitBudget(start: 100, seconds: Contract.drainSeconds, maximumTicks: 240)
        try drain.tick(now: 111.95)
        XCTAssertThrowsError(try drain.tick(now: 112)) { XCTAssertEqual($0 as? SmokeError, .timeout) }
        var deadline = try WaitBudget(start: 100, seconds: 3, maximumTicks: 2)
        try deadline.tick(now: 100); try deadline.tick(now: 101)
        XCTAssertEqual(deadline.ticks, 2)
        XCTAssertThrowsError(try deadline.tick(now: 102)) { XCTAssertEqual($0 as? SmokeError, .timeout) }
        var time = try WaitBudget(start: 100, seconds: 3, maximumTicks: 20)
        XCTAssertThrowsError(try time.tick(now: 103)) { XCTAssertEqual($0 as? SmokeError, .timeout) }
        XCTAssertThrowsError(try time.tick(now: 101, stopped: true)) { XCTAssertEqual($0 as? SmokeError, .cancelled) }
        XCTAssertThrowsError(try time.tick(now: .nan))
    }
    func testRemoteCleanupRejectsUnknownAndTraversal() throws {
        let remote = RemoteOwnership(id: UUID(uuidString: "12345678-1234-1234-1234-123456789abc")!)
        XCTAssertEqual(remote.directory, "/fixture/home/openlxssh-real-12345678-1234-1234-1234-123456789abc")
        XCTAssertEqual(remote.payload, remote.directory + "/tiny-payload.bin")
        XCTAssertNoThrow(try remote.checkListing([], payloadOwned: false))
        XCTAssertNoThrow(try remote.checkListing([Data("tiny-payload.bin".utf8)], payloadOwned: true))
        for names in [[Data("unknown".utf8)], [Data("../tiny-payload.bin".utf8)], [Data("tiny-payload.bin".utf8), Data("extra".utf8)]] {
            XCTAssertThrowsError(try remote.checkListing(names, payloadOwned: true))
        }
        XCTAssertThrowsError(try remote.checkListing([Data("tiny-payload.bin".utf8)], payloadOwned: false))
    }
    func testPrivateInputRealFilesystemRefusals() throws {
        // Under this task's own .build only; no shared temp/cache mutations.
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent(".build/unit-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) } // Only synthetic test-owned UUID.
        try PrivateInput.checkDirectory(root.path)
        let file = root.appendingPathComponent("synthetic.txt").path
        try PrivateInput.writeExclusive(Data("synthetic-only\n".utf8), to: file)
        XCTAssertEqual(try PrivateInput.read(file, limit: 128), Data("synthetic-only\n".utf8))
        XCTAssertThrowsError(try PrivateInput.read(file, limit: 2))
        XCTAssertThrowsError(try PrivateInput.writeExclusive(Data(), to: file))
        XCTAssertEqual(chmod(file, 0o644), 0)
        XCTAssertThrowsError(try PrivateInput.read(file, limit: 128))
        XCTAssertEqual(chmod(file, 0o600), 0)
        let hard = root.appendingPathComponent("hard").path
        XCTAssertEqual(link(file, hard), 0); XCTAssertThrowsError(try PrivateInput.read(file, limit: 128)); XCTAssertEqual(unlink(hard), 0)
        let symlinkPath = root.appendingPathComponent("link").path
        XCTAssertEqual(symlink(file, symlinkPath), 0); XCTAssertThrowsError(try PrivateInput.read(symlinkPath, limit: 128))
        let parentLink = root.appendingPathComponent("parent-link").path
        XCTAssertEqual(symlink(root.path, parentLink), 0); XCTAssertThrowsError(try PrivateInput.read(parentLink + "/synthetic.txt", limit: 128))
        let fifo = root.appendingPathComponent("fifo").path
        XCTAssertEqual(mkfifo(fifo, 0o600), 0); XCTAssertThrowsError(try PrivateInput.read(fifo, limit: 128))
        var acl: acl_t? = acl_init(1)
        XCTAssertNotNil(acl)
        defer { acl_free(UnsafeMutableRawPointer(acl!)) }
        var entry: acl_entry_t?
        XCTAssertEqual(acl_create_entry(&acl, &entry), 0)
        if let entry {
            XCTAssertEqual(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW), 0)
            var identity = UUID().uuid
            XCTAssertEqual(mbr_uid_to_uuid(getuid(), &identity), 0)
            XCTAssertEqual(acl_set_qualifier(entry, &identity), 0)
            var permissions: acl_permset_t?
            XCTAssertEqual(acl_get_permset(entry, &permissions), 0)
            XCTAssertEqual(acl_add_perm(permissions!, ACL_READ_DATA), 0)
            XCTAssertEqual(acl_set_file(file, ACL_TYPE_EXTENDED, acl), 0)
            XCTAssertThrowsError(try PrivateInput.read(file, limit: 128))
        }
    }
    func testExactSyntheticExportFingerprintAndProvenance() throws {
        // Public key is an existing PUBLIC test fixture; private/password bytes
        // below are synthetic, never a connection or substitute interoperability.
        let base = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent(".build/export-" + UUID().uuidString)
        let root = base.appendingPathComponent("Tests/IntegrationEnvironment")
        let generation = root.appendingPathComponent(".runtime/keyonly/credentials-012345abcdef")
        try FileManager.default.createDirectory(at: generation, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: base) }
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg"
        let raw = Data(base64Encoded: String(line.split(separator: " ")[1]))!
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: raw)).base64EncodedString().dropLast()
        let template = try contract(service: "keyonly", plan: "none")
        var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(template)) as! [String: Any]
        object["credentialDirectory"] = generation.path; object["expectedFingerprint"] = fingerprint
        let provenance: [String: Any] = ["base_image": template.expectedBaseImage, "built_image_id": template.expectedBuiltImageID, "service": "keyonly", "collected_at": 1.0]
        for (name, bytes) in ["real-integration.json": try JSONSerialization.data(withJSONObject: object),
            "provenance.json": try JSONSerialization.data(withJSONObject: provenance),
            "known_hosts": Data(("[127.0.0.1]:22221 " + line + "\n").utf8),
            "fingerprint.txt": Data(("256 " + fingerprint + " synthetic-public (ED25519)\n").utf8),
            "id_ed25519.pub": Data((line + " synthetic-public\n").utf8),
            "id_ed25519": Data("SYNTHETIC-NOT-A-PRIVATE-KEY".utf8)] {
            try PrivateInput.writeExclusive(bytes, to: generation.appendingPathComponent(name).path)
        }
        let path = generation.appendingPathComponent("real-integration.json").path
        let loaded = try FixtureInput.load(contractPath: path, fixtureRoot: root.path)
        XCTAssertEqual(loaded.fingerprint, fingerprint)
        XCTAssertEqual(loaded.hostKeyLine, line)
        XCTAssertEqual(String(reflecting: loaded), "<redacted fixture input>")
        let provenancePath = generation.appendingPathComponent("provenance.json").path
        XCTAssertEqual(unlink(provenancePath), 0)
        var wrong = provenance; wrong["service"] = "passwordonly"
        try PrivateInput.writeExclusive(JSONSerialization.data(withJSONObject: wrong), to: provenancePath)
        XCTAssertThrowsError(try FixtureInput.load(contractPath: path, fixtureRoot: root.path)) { XCTAssertEqual($0 as? SmokeError, .provenanceMismatch) }
        XCTAssertEqual(unlink(provenancePath), 0)
        try PrivateInput.writeExclusive(JSONSerialization.data(withJSONObject: provenance), to: provenancePath)
        let fingerprintPath = generation.appendingPathComponent("fingerprint.txt").path
        XCTAssertEqual(unlink(fingerprintPath), 0)
        try PrivateInput.writeExclusive(Data("256 SHA256:wrong synthetic-public\n".utf8), to: fingerprintPath)
        XCTAssertThrowsError(try FixtureInput.load(contractPath: path, fixtureRoot: root.path)) { XCTAssertEqual($0 as? SmokeError, .fingerprintMismatch) }
    }
    func testSyntaxAndSecretNewlineLimits() throws {
        for path in ["relative", "/", "/a//b", "/a/../b", "/a/./b", "/a/", "/a/$b", "/a/\nb"] { XCTAssertThrowsError(try PrivateInput.validateSyntax(path)) }
        XCTAssertEqual(try PrivateInput.secretLine(Data("synthetic\n".utf8)), Data("synthetic".utf8))
        for bytes in [Data(), Data([10]), Data("a\nb\n".utf8), Data([0, 10]), Data("not-terminated".utf8)] { XCTAssertThrowsError(try PrivateInput.secretLine(bytes)) }
    }
}
