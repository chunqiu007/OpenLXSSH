import COpenLXSSHFiles
import CryptoKit
import Foundation
import OpenLXSSHTrust
import XCTest
@testable import OpenLXSSHFiles

private final class OnceReplyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: ChallengeReply<FileHostTrustAnswer>?
    func set(_ value: ChallengeReply<FileHostTrustAnswer>) { lock.withLock { stored = value } }
    var value: ChallengeReply<FileHostTrustAnswer>? { lock.withLock { stored } }
}
/// Exact actual-key binding policy only. Fresh ephemeral public keys, private temporary store;
/// no SSH endpoint, real credentials, production known_hosts, or UI acceptance claim.
final class SharedHostTrustOnceTests: XCTestCase, @unchecked Sendable {
    private func key(host: String = "127.0.0.1", port: UInt16 = 2222) throws -> HostKey {
        let publicBytes = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        var blob = Data()
        for field in [Data("ssh-ed25519".utf8), publicBytes] {
            var size = UInt32(field.count).bigEndian
            withUnsafeBytes(of: &size) { blob.append(contentsOf: $0) }; blob.append(field)
        }
        return HostKey(identity: try ServerIdentity(host: host, port: port), rawKey: blob,
                       algorithmCode: Int32(LIBSSH2_HOSTKEY_TYPE_ED25519))
    }
    private func store() throws -> (URL, HostTrustStore) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("NativeOnce-" + UUID().uuidString)
        return (root, try HostTrustStore(directory: AbsolutePath(root.path)))
    }
    private func host(_ port: Int = 2222) throws -> HostIdentity {
        HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(port))
    }
    func testOnceApprovesExactHandshakeWithoutChangingPersistentBytes() async throws {
        let (root, trust) = try store(); defer { try? FileManager.default.removeItem(at: root) }
        let actual = try key(), identity = try host()
        let before = try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value))
        try await SharedHostTrust.verify(actual, identity: identity, store: trust, timeout: 1, token: CancellationToken()) { event, reply in
            guard case .pending(let pending) = event else { return XCTFail("pending") }
            reply.resolve(.confirmOnce(displayedFingerprint: pending.fingerprint))
        }
        let after = try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value))
        XCTAssertEqual(before, after)
        let records = try await trust.records(); XCTAssertTrue(records.isEmpty)
        let parsed = try SharedHostTrust.parse(actual)
        guard case .pending(let fresh) = try await trust.evaluate(host: identity, key: parsed) else { return XCTFail("new handshake must prompt") }
        await trust.cancel(fresh)
    }
    func testOnceCannotApproveWrongEndpointOrRawAlgorithmAndChangedAlwaysRejects() async throws {
        let (root, trust) = try store(); defer { try? FileManager.default.removeItem(at: root) }
        let actual = try key(), identity = try host()
        do {
            try await SharedHostTrust.verify(actual, identity: host(2223), store: trust, timeout: 1, token: CancellationToken()) { _, _ in
                XCTFail("endpoint mismatch must not prompt")
            }
            XCTFail("wrong endpoint")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .untrusted) }
        let invalid = HostKey(identity: actual.identity, rawKey: actual.rawKey, algorithmCode: Int32(LIBSSH2_HOSTKEY_TYPE_RSA))
        do {
            try await SharedHostTrust.verify(invalid, identity: identity, store: trust, timeout: 1, token: CancellationToken()) { _, _ in
                XCTFail("wrong raw algorithm")
            }
            XCTFail("wrong raw algorithm")
        } catch { }
        let parsed = try SharedHostTrust.parse(actual)
        guard case .pending(let pending) = try await trust.evaluate(host: identity, key: parsed) else { return XCTFail("pending") }
        try await trust.confirm(pending, displayedFingerprint: parsed.fingerprint)
        let before = try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value))
        do {
            try await SharedHostTrust.verify(key(), identity: identity, store: trust, timeout: 1, token: CancellationToken()) { event, reply in
                guard case .changed(let changed) = event else { return XCTFail("changed must reject") }
                reply.resolve(.confirmOnce(displayedFingerprint: changed.presentedFingerprint))
            }
            XCTFail("changed key")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .untrusted) }
        XCTAssertEqual(before, try Data(contentsOf: URL(fileURLWithPath: trust.knownHostsPath.value)))
    }
    func testWrongFingerprintExpiredReplyAndCancelledGenerationNeverPersist() async throws {
        let (root, trust) = try store(); defer { try? FileManager.default.removeItem(at: root) }
        let actual = try key(), identity = try host()
        do {
            try await SharedHostTrust.verify(actual, identity: identity, store: trust, timeout: 1, token: CancellationToken()) { _, reply in
                reply.resolve(.confirmOnce(displayedFingerprint: "wrong"))
            }
            XCTFail("wrong fingerprint")
        } catch let error as HostTrustError { XCTAssertEqual(error, .fingerprintMismatch) }
        let expired = OnceReplyBox()
        do {
            try await SharedHostTrust.verify(actual, identity: identity, store: trust, timeout: 0.03, token: CancellationToken()) { _, reply in
                expired.set(reply)
            }
            XCTFail("expired")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .timeout) }
        XCTAssertFalse(try XCTUnwrap(expired.value).resolve(.confirmOnce(displayedFingerprint: SharedHostTrust.parse(actual).fingerprint)))
        let token = CancellationToken(), cancelled = OnceReplyBox()
        do {
            try await SharedHostTrust.verify(actual, identity: identity, store: trust, timeout: 1, token: token) { _, reply in
                cancelled.set(reply); token.cancel(); reply.cancel()
            }
            XCTFail("cancelled")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        XCTAssertFalse(try XCTUnwrap(cancelled.value).resolve(.confirmOnce(displayedFingerprint: SharedHostTrust.parse(actual).fingerprint)))
        let records = try await trust.records(); XCTAssertTrue(records.isEmpty)
    }
    func testCancellingOnePendingDoesNotCancelAnotherSession() async throws {
        let (root, trust) = try store(); defer { try? FileManager.default.removeItem(at: root) }
        let otherKey = try key(port: 2223), otherHost = try host(2223)
        let parsedOther = try SharedHostTrust.parse(otherKey)
        guard case .pending(let other) = try await trust.evaluate(host: otherHost, key: parsedOther) else { return XCTFail("pending") }
        let token = CancellationToken()
        do {
            try await SharedHostTrust.verify(key(), identity: host(), store: trust, timeout: 1, token: token) { _, reply in
                token.cancel(); reply.cancel()
            }
            XCTFail("cancel")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        let accepted = try await trust.confirmOnce(other, displayedFingerprint: other.fingerprint)
        XCTAssertEqual(accepted.host, otherHost); XCTAssertEqual(accepted.key.blob, otherKey.rawKey)
        let records = try await trust.records(); XCTAssertTrue(records.isEmpty)
    }
    func testOldPendingReplyCannotAnswerCurrentHandshake() async throws {
        let (root, trust) = try store(); defer { try? FileManager.default.removeItem(at: root) }
        let old = OnceReplyBox(), actual = try key(), identity = try host()
        do {
            try await SharedHostTrust.verify(actual, identity: identity, store: trust, timeout: 0.02, token: CancellationToken()) { _, reply in old.set(reply) }
            XCTFail("timeout")
        } catch { }
        try await SharedHostTrust.verify(actual, identity: identity, store: trust, timeout: 1, token: CancellationToken()) { event, reply in
            guard case .pending(let pending) = event else { return XCTFail("pending") }
            XCTAssertFalse(old.value?.resolve(.confirmOnce(displayedFingerprint: pending.fingerprint)) ?? true)
            reply.resolve(.confirmOnce(displayedFingerprint: pending.fingerprint))
        }
        let records = try await trust.records(); XCTAssertTrue(records.isEmpty)
    }
}
