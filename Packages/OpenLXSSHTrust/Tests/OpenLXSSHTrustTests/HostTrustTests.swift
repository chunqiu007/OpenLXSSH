import Foundation
@testable import OpenLXSSHTrust
import XCTest

@MainActor
final class HostTrustTests: XCTestCase {
    func testFirstKeyRequiresExplicitAcceptanceAndPersistsExactMatch() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let before = try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value))
        let decision = try pendingDecision(try await store.evaluate(host: identity, key: key))
        XCTAssertEqual(decision.host, identity)
        XCTAssertEqual(decision.algorithm, "ssh-ed25519")
        XCTAssertEqual(decision.fingerprint, key.fingerprint)
        XCTAssertEqual(decision.reason, .firstKey)
        let empty = try await store.records()
        XCTAssertTrue(empty.isEmpty)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value)), before)
        try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
        let evaluation = try await store.evaluate(host: identity, key: key)
        XCTAssertEqual(evaluation, .trusted(TrustedHostKey(host: identity, key: key)))
        let reopened = try HostTrustStore(directory: directory.path)
        let persisted = try await reopened.evaluate(host: identity, key: key)
        XCTAssertEqual(persisted, evaluation)
    }

    func testCancellationWrongFingerprintAndOneUseTokens() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let identity = try host()
        let cancelled = try pendingDecision(try await store.evaluate(host: identity, key: key))
        await store.cancel(cancelled)
        await assertAsyncError(.expiredDecision) {
            try await store.confirm(cancelled, displayedFingerprint: cancelled.fingerprint)
        }
        let wrong = try pendingDecision(try await store.evaluate(host: identity, key: key))
        await assertAsyncError(.fingerprintMismatch) {
            try await store.confirm(wrong, displayedFingerprint: "SHA256:wrong")
        }
        await assertAsyncError(.expiredDecision) {
            try await store.confirm(wrong, displayedFingerprint: wrong.fingerprint)
        }
        let accepted = try pendingDecision(try await store.evaluate(host: identity, key: key))
        try await store.confirm(accepted, displayedFingerprint: accepted.fingerprint)
        await assertAsyncError(.expiredDecision) {
            try await store.confirm(accepted, displayedFingerprint: accepted.fingerprint)
        }
    }

    func testKnownAlgorithmChangeIsRejectedWithoutMutation() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let changed = try HostPublicKey(openSSHPublicKey: changedFixture)
        try await accept(store, identity, key)
        let before = try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value))
        let result = try await store.evaluate(host: identity, key: changed)
        XCTAssertEqual(result, .rejected(ChangedHostKey(host: identity, algorithm: key.algorithm,
            expectedFingerprint: key.fingerprint, presentedFingerprint: changed.fingerprint)))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: store.knownHostsPath.value)), before)
        let unchanged = try await store.evaluate(host: identity, key: key)
        XCTAssertEqual(unchanged, .trusted(TrustedHostKey(host: identity, key: key)))
    }

    func testAdditionalAlgorithmRequiresNewExplicitDecision() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host(port: 2222)
        let first = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let second = try HostPublicKey(openSSHPublicKey: rsaFixture)
        try await accept(store, identity, first)
        let decision = try pendingDecision(try await store.evaluate(host: identity, key: second))
        XCTAssertEqual(decision.reason, .additionalAlgorithm)
        let initialRecords = try await store.records()
        XCTAssertEqual(initialRecords.count, 1)
        try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
        for key in [first, second] {
            let evaluation = try await store.evaluate(host: identity, key: key)
            XCTAssertEqual(evaluation, .trusted(TrustedHostKey(host: identity, key: key)))
        }
        let records = try await store.records()
        XCTAssertEqual(records.count, 2)
    }

    func testPortsAddressesAndLoginUserDoNotAliasIncorrectly() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let original = try host("Server.Example.")
        try await accept(store, original, key)
        for identity in [try host(port: 2222), try host("192.0.2.1"), try host("2001:db8::1") ] {
            let decision = try pendingDecision(try await store.evaluate(host: identity, key: key))
            XCTAssertEqual(decision.reason, .firstKey)
            await store.cancel(decision)
        }
        let firstUser = SSHConnection(host: original, user: try SSHUser("alice"))
        let secondUser = SSHConnection(host: try host("server.example"), user: try SSHUser("bob"))
        XCTAssertNotEqual(firstUser, secondUser)
        XCTAssertEqual(firstUser.host, secondUser.host)
        let sameServer = try await store.evaluate(host: secondUser.host, key: key)
        XCTAssertEqual(sameServer, .trusted(TrustedHostKey(host: original, key: key)))
        let outstanding = try pendingDecision(try await store.evaluate(host: try host("new.example"), key: key))
        await store.cancelAllPendingDecisions()
        await assertAsyncError(.expiredDecision) {
            try await store.confirm(outstanding, displayedFingerprint: outstanding.fingerprint)
        }
    }

    func testManualReplacementRequiresExpectedOldAndNewFingerprints() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let old = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let new = try HostPublicKey(openSSHPublicKey: changedFixture)
        try await accept(store, identity, old)
        await assertAsyncError(.fingerprintMismatch) {
            try await store.prepareReplacement(host: identity, key: new, expectedCurrentFingerprint: "SHA256:wrong")
        }
        let decision = try await store.prepareReplacement(host: identity, key: new,
                                                           expectedCurrentFingerprint: old.fingerprint)
        XCTAssertEqual(decision.reason, .manuallyVerifiedReplacement(previousFingerprint: old.fingerprint))
        try await store.confirm(decision, displayedFingerprint: new.fingerprint)
        let accepted = try await store.evaluate(host: identity, key: new)
        XCTAssertEqual(accepted, .trusted(TrustedHostKey(host: identity, key: new)))
        guard case .rejected = try await store.evaluate(host: identity, key: old) else {
            return XCTFail("Old key must not remain trusted after explicit replacement")
        }
    }

    func testOldAndOtherInstanceConfirmationsCannotOverwrite() async throws {
        let directory = try TemporaryDirectory()
        let first = try HostTrustStore(directory: directory.path)
        let second = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let old = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let new = try HostPublicKey(openSSHPublicKey: changedFixture)
        let oldDecision = try pendingDecision(try await first.evaluate(host: identity, key: old))
        await assertAsyncError(.expiredDecision) {
            try await second.confirm(oldDecision, displayedFingerprint: old.fingerprint)
        }
        try await accept(second, identity, new)
        await assertAsyncError(.storageChanged) {
            try await first.confirm(oldDecision, displayedFingerprint: old.fingerprint)
        }
        let result = try await first.evaluate(host: identity, key: new)
        XCTAssertEqual(result, .trusted(TrustedHostKey(host: identity, key: new)))
        let stale = try await first.prepareReplacement(host: identity, key: old,
                                                       expectedCurrentFingerprint: new.fingerprint)
        try await accept(second, try host("other.example"), old)
        await assertAsyncError(.storageChanged) {
            try await first.confirm(stale, displayedFingerprint: old.fingerprint)
        }
    }

    func testOpenSSHFindsDNSIPv4IPv6DefaultAndNonDefaultPorts() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let ed = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let rsa = try HostPublicKey(openSSHPublicKey: rsaFixture)
        let identities = try [host(), host(port: 2222), host("192.0.2.5"), host("192.0.2.5", port: 2200),
                              host("2001:db8::1"), host("2001:db8::1", port: 2200), host("fe80::1%en0", port: 2200)]
        for identity in identities {
            try await accept(store, identity, ed)
            try await accept(store, identity, rsa)
            let result = try runTool("/usr/bin/ssh-keygen", ["-F", identity.knownHostsName, "-f", store.knownHostsPath.value])
            XCTAssertEqual(result.status, 0, result.error)
            XCTAssertTrue(result.output.contains(identity.knownHostsName + " " + ed.openSSH))
            XCTAssertTrue(result.output.contains(identity.knownHostsName + " " + rsa.openSSH))
        }
        let absent = try runTool("/usr/bin/ssh-keygen", ["-F", "[server.example]:2201", "-f", store.knownHostsPath.value])
        XCTAssertEqual(absent.status, 1)
    }
}
