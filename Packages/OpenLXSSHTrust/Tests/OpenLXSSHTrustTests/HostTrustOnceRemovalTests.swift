import Darwin
import Foundation
@testable import OpenLXSSHTrust
import XCTest

@MainActor
final class HostTrustOnceRemovalTests: XCTestCase {
    func testConfirmOnceReturnsExactFirstKeyWithoutChangingStorageOrOtherDecisions() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host(port: 2222)
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let decision = try pendingDecision(try await store.evaluate(host: identity, key: key))
        let other = try pendingDecision(try await store.evaluate(host: identity, key: key))
        let before = try Data(contentsOf: directory.file("known_hosts"))
        let inode = try metadata(directory.file("known_hosts")).st_ino

        let accepted = try await store.confirmOnce(decision, displayedFingerprint: decision.fingerprint)
        XCTAssertEqual(accepted, TrustedHostKey(host: identity, key: key))
        XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), before)
        XCTAssertEqual(try metadata(directory.file("known_hosts")).st_ino, inode)
        let records = try await store.records()
        XCTAssertTrue(records.isEmpty)
        let reopened = try HostTrustStore(directory: directory.path)
        let again = try pendingDecision(try await reopened.evaluate(host: identity, key: key))
        XCTAssertEqual(again.reason, .firstKey)
        await assertAsyncError(.expiredDecision) {
            try await store.confirmOnce(decision, displayedFingerprint: decision.fingerprint)
        }
        await assertAsyncError(.expiredDecision) {
            try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
        }
        let persisted = try await store.confirm(other, displayedFingerprint: other.fingerprint)
        XCTAssertEqual(persisted, accepted)
        let trusted = try await reopened.evaluate(host: identity, key: key)
        XCTAssertEqual(trusted, .trusted(accepted))
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: directory.url.path)),
                       Set(["known_hosts", "trust.lock"]))
    }

    func testConfirmOnceAdditionalAlgorithmDoesNotExpandPersistentTrust() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let first = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let second = try HostPublicKey(openSSHPublicKey: rsaFixture)
        let changed = try HostPublicKey(openSSHPublicKey: changedFixture)
        let original = try await accept(store, identity, first)
        let decision = try pendingDecision(try await store.evaluate(host: identity, key: second))
        XCTAssertEqual(decision.reason, .additionalAlgorithm)
        let before = try Data(contentsOf: directory.file("known_hosts"))
        let accepted = try await store.confirmOnce(decision, displayedFingerprint: second.fingerprint)
        XCTAssertEqual(accepted, TrustedHostKey(host: identity, key: second))
        XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), before)
        let records = try await store.records()
        XCTAssertEqual(records, [original])
        let again = try pendingDecision(try await store.evaluate(host: identity, key: second))
        XCTAssertEqual(again.reason, .additionalAlgorithm)
        let result = try await store.evaluate(host: identity, key: changed)
        XCTAssertEqual(result, .rejected(ChangedHostKey(host: identity, algorithm: first.algorithm,
            expectedFingerprint: first.fingerprint, presentedFingerprint: changed.fingerprint)))
    }

    func testConfirmOnceWrongFingerprintCancellationAndCancelAllConsumeDecisions() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let before = try Data(contentsOf: directory.file("known_hosts"))
        let wrong = try pendingDecision(try await store.evaluate(host: identity, key: key))
        await assertAsyncError(.fingerprintMismatch) {
            try await store.confirmOnce(wrong, displayedFingerprint: "SHA256:wrong")
        }
        await assertAsyncError(.expiredDecision) {
            try await store.confirmOnce(wrong, displayedFingerprint: wrong.fingerprint)
        }
        await assertAsyncError(.expiredDecision) {
            try await store.confirm(wrong, displayedFingerprint: wrong.fingerprint)
        }
        let cancelled = try pendingDecision(try await store.evaluate(host: identity, key: key))
        await store.cancel(cancelled)
        await assertAsyncError(.expiredDecision) {
            try await store.confirmOnce(cancelled, displayedFingerprint: cancelled.fingerprint)
        }
        let all = try pendingDecision(try await store.evaluate(host: identity, key: key))
        await store.cancelAllPendingDecisions()
        await assertAsyncError(.expiredDecision) {
            try await store.confirmOnce(all, displayedFingerprint: all.fingerprint)
        }
        XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), before)
        let records = try await store.records()
        XCTAssertTrue(records.isEmpty)
    }

    func testConfirmOnceRejectsForgedDisplayAndOtherStoreReplay() async throws {
        let directory = try TemporaryDirectory()
        let first = try HostTrustStore(directory: directory.path)
        let second = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let before = try Data(contentsOf: directory.file("known_hosts"))
        for field in 0..<4 {
            let original = try pendingDecision(try await first.evaluate(host: identity, key: key))
            let forged = PendingTrustDecision(id: original.id,
                host: field == 0 ? try host("forged.example") : original.host,
                algorithm: field == 1 ? "ssh-rsa" : original.algorithm,
                fingerprint: field == 2 ? "SHA256:forged" : original.fingerprint,
                reason: field == 3 ? .additionalAlgorithm : original.reason)
            await assertAsyncError(.expiredDecision) {
                try await first.confirmOnce(forged, displayedFingerprint: original.fingerprint)
            }
            await assertAsyncError(.expiredDecision) {
                try await first.confirmOnce(original, displayedFingerprint: original.fingerprint)
            }
        }
        let original = try pendingDecision(try await first.evaluate(host: identity, key: key))
        await assertAsyncError(.expiredDecision) {
            try await second.confirmOnce(original, displayedFingerprint: original.fingerprint)
        }
        let accepted = try await first.confirmOnce(original, displayedFingerprint: original.fingerprint)
        XCTAssertEqual(accepted, TrustedHostKey(host: identity, key: key))
        XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), before)
    }

    func testConfirmOnceExpiryUsesSameDeadlineAndConsumptionAsPersistentConfirmation() async throws {
        let directory = try TemporaryDirectory()
        let clock = TrustDecisionTestClock()
        let store = try HostTrustStore(directory: directory.path, now: { clock.now() })
        let identity = try host()
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let before = try Data(contentsOf: directory.file("known_hosts"))
        let current = try pendingDecision(try await store.evaluate(host: identity, key: key))
        clock.advance(by: .seconds(299))
        let accepted = try await store.confirmOnce(current, displayedFingerprint: current.fingerprint)
        XCTAssertEqual(accepted, TrustedHostKey(host: identity, key: key))
        for persistent in [false, true] {
            let expired = try pendingDecision(try await store.evaluate(host: identity, key: key))
            clock.advance(by: .seconds(300))
            await assertAsyncError(.expiredDecision) {
                if persistent { return try await store.confirm(expired, displayedFingerprint: expired.fingerprint) }
                return try await store.confirmOnce(expired, displayedFingerprint: expired.fingerprint)
            }
            await assertAsyncError(.expiredDecision) {
                try await store.confirmOnce(expired, displayedFingerprint: expired.fingerprint)
            }
        }
        XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), before)
    }

    func testConfirmOnceRejectsIndependentWriteEvenAfterRecordsAreRestored() async throws {
        let directory = try TemporaryDirectory()
        let first = try HostTrustStore(directory: directory.path)
        let second = try HostTrustStore(directory: directory.path)
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let identity = try host()
        let stale = try pendingDecision(try await first.evaluate(host: identity, key: key))
        let restored = try pendingDecision(try await first.evaluate(host: identity, key: key))
        let other = try await accept(second, try host("other.example"), key)
        let changed = try Data(contentsOf: directory.file("known_hosts"))
        await assertAsyncError(.storageChanged) {
            try await first.confirmOnce(stale, displayedFingerprint: stale.fingerprint)
        }
        await assertAsyncError(.expiredDecision) {
            try await first.confirmOnce(stale, displayedFingerprint: stale.fingerprint)
        }
        XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), changed)
        try await second.remove(other)
        await assertAsyncError(.storageChanged) {
            try await first.confirmOnce(restored, displayedFingerprint: restored.fingerprint)
        }
        await assertAsyncError(.expiredDecision) {
            try await first.confirm(restored, displayedFingerprint: restored.fingerprint)
        }
        let records = try await first.records()
        XCTAssertTrue(records.isEmpty)
    }

    func testConfirmOnceNeverAcceptsManuallyVerifiedReplacement() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let old = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let new = try HostPublicKey(openSSHPublicKey: changedFixture)
        let trusted = try await accept(store, identity, old)
        let decision = try await store.prepareReplacement(host: identity, key: new,
                                                          expectedCurrentFingerprint: old.fingerprint)
        let before = try Data(contentsOf: directory.file("known_hosts"))
        await assertAsyncError(.temporaryReplacementNotAllowed) {
            try await store.confirmOnce(decision, displayedFingerprint: new.fingerprint)
        }
        await assertAsyncError(.expiredDecision) {
            try await store.confirm(decision, displayedFingerprint: new.fingerprint)
        }
        XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), before)
        let records = try await store.records()
        XCTAssertEqual(records, [trusted])
        let result = try await store.evaluate(host: identity, key: new)
        XCTAssertEqual(result, .rejected(ChangedHostKey(host: identity, algorithm: old.algorithm,
            expectedFingerprint: old.fingerprint, presentedFingerprint: new.fingerprint)))
    }

    func testExactRemovalPreservesOtherEndpointsAlgorithmsPermissionsAndAtomicity() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let ed = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let rsa = try HostPublicKey(openSSHPublicKey: rsaFixture)
        let target = try await accept(store, identity, ed)
        let keepAlgorithm = try await accept(store, identity, rsa)
        let keepPort = try await accept(store, try host(port: 2222), ed)
        let keepAddress = try await accept(store, try host("other.example"), ed)
        let before = try Data(contentsOf: directory.file("known_hosts"))
        let oldInode = try metadata(directory.file("known_hosts")).st_ino
        let lockInode = try metadata(directory.file("trust.lock")).st_ino
        let descriptor = open(store.knownHostsPath.value, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { close(descriptor) }

        try await store.remove(target)
        let records = try await store.records()
        XCTAssertEqual(Set(records), Set([keepAlgorithm, keepPort, keepAddress]))
        XCTAssertNotEqual(try Data(contentsOf: directory.file("known_hosts")), before)
        XCTAssertNotEqual(try metadata(directory.file("known_hosts")).st_ino, oldInode)
        XCTAssertEqual(try metadata(directory.file("trust.lock")).st_ino, lockInode)
        let oldHandle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        XCTAssertEqual(try oldHandle.readToEnd(), before)
        for (file, mode): (URL, mode_t) in [(directory.url, 0o700),
            (directory.file("known_hosts"), 0o600), (directory.file("trust.lock"), 0o600)] {
            let value = try metadata(file)
            XCTAssertEqual(value.st_mode & 0o7777, mode)
            XCTAssertEqual(value.st_uid, geteuid())
        }
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: directory.url.path)),
                       Set(["known_hosts", "trust.lock"]))
        let reopened = try HostTrustStore(directory: directory.path)
        let persisted = try await reopened.records()
        XCTAssertEqual(Set(persisted), Set(records))
        let next = try pendingDecision(try await reopened.evaluate(host: identity, key: ed))
        XCTAssertEqual(next.reason, .additionalAlgorithm)
    }

    func testExactRemovalRejectsMissingWrongFingerprintAndStaleReplacement() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let other = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let old = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let new = try HostPublicKey(openSSHPublicKey: changedFixture)
        let trusted = try await accept(store, identity, old)
        let before = try Data(contentsOf: directory.file("known_hosts"))
        await assertAsyncError(.recordNotFound) {
            try await store.remove(TrustedHostKey(host: host(port: 2222), key: old))
        }
        await assertAsyncError(.recordNotFound) {
            try await store.remove(TrustedHostKey(host: identity, key: HostPublicKey(openSSHPublicKey: rsaFixture)))
        }
        await assertAsyncError(.storageChanged) {
            try await store.remove(TrustedHostKey(host: identity, key: new))
        }
        XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), before)
        let replacement = try await other.prepareReplacement(host: identity, key: new,
                                                             expectedCurrentFingerprint: old.fingerprint)
        let updated = try await other.confirm(replacement, displayedFingerprint: new.fingerprint)
        let after = try Data(contentsOf: directory.file("known_hosts"))
        await assertAsyncError(.storageChanged) { try await store.remove(trusted) }
        XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), after)
        try await store.remove(updated)
        await assertAsyncError(.recordNotFound) { try await store.remove(updated) }
        let pending = try pendingDecision(try await store.evaluate(host: identity, key: new))
        XCTAssertEqual(pending.reason, .firstKey)
    }

    func testRemovalInvalidatesLocalAndIndependentDecisionsWithoutRevival() async throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        let other = try HostTrustStore(directory: directory.path)
        let identity = try host()
        let ed = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let rsa = try HostPublicKey(openSSHPublicKey: rsaFixture)
        let changed = try HostPublicKey(openSSHPublicKey: changedFixture)
        let trusted = try await accept(store, identity, ed)
        let local = try pendingDecision(try await store.evaluate(host: identity, key: rsa))
        let remote = try pendingDecision(try await other.evaluate(host: identity, key: rsa))
        let replacement = try await other.prepareReplacement(host: identity, key: changed,
                                                             expectedCurrentFingerprint: ed.fingerprint)
        try await store.remove(trusted)
        let next = try pendingDecision(try await store.evaluate(host: identity, key: ed))
        XCTAssertEqual(next.reason, .firstKey)
        try await store.confirm(next, displayedFingerprint: ed.fingerprint)
        await assertAsyncError(.expiredDecision) {
            try await store.confirmOnce(local, displayedFingerprint: local.fingerprint)
        }
        await assertAsyncError(.storageChanged) {
            try await other.confirmOnce(remote, displayedFingerprint: remote.fingerprint)
        }
        await assertAsyncError(.expiredDecision) {
            try await other.confirm(remote, displayedFingerprint: remote.fingerprint)
        }
        await assertAsyncError(.storageChanged) {
            try await other.confirm(replacement, displayedFingerprint: replacement.fingerprint)
        }
        let records = try await store.records()
        XCTAssertEqual(records, [trusted])
    }

    func testConcurrentExactRemovalAndReplacementCannotBothSucceed() async throws {
        let old = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        let new = try HostPublicKey(openSSHPublicKey: changedFixture)
        let identity = try host()
        for _ in 0..<6 {
            let directory = try TemporaryDirectory()
            let first = try HostTrustStore(directory: directory.path)
            let second = try HostTrustStore(directory: directory.path)
            let trusted = try await accept(first, identity, old)
            let decision = try await second.prepareReplacement(host: identity, key: new,
                                                               expectedCurrentFingerprint: old.fingerprint)
            async let removed = Self.attemptRemoval(first, trusted)
            async let replaced = Self.attemptReplacement(second, decision)
            let results = await [removed, replaced]
            XCTAssertEqual(results.filter { $0 }.count, 1)
            let records = try await first.records()
            XCTAssertEqual(records, results[0] ? [] : [TrustedHostKey(host: identity, key: new)])
        }
    }

    func testConfirmOnceAndRemovalFailClosedForMissingOrCorruptStorage() async throws {
        let key = try HostPublicKey(openSSHPublicKey: ed25519Fixture)
        for missing in [false, true] {
            let directory = try TemporaryDirectory()
            let store = try HostTrustStore(directory: directory.path)
            let trusted = try await accept(store, try host(), key)
            let decision = try pendingDecision(try await store.evaluate(host: host("new.example"), key: key))
            let corrupt = Data("not a known-hosts store\n".utf8)
            if missing { try FileManager.default.removeItem(at: directory.file("known_hosts")) }
            else { try corrupt.write(to: directory.file("known_hosts")) }
            await assertAsyncError(.corruptStorage) {
                try await store.confirmOnce(decision, displayedFingerprint: decision.fingerprint)
            }
            await assertAsyncError(.expiredDecision) {
                try await store.confirmOnce(decision, displayedFingerprint: decision.fingerprint)
            }
            await assertAsyncError(.corruptStorage) { try await store.remove(trusted) }
            if missing { XCTAssertFalse(FileManager.default.fileExists(atPath: store.knownHostsPath.value)) }
            else { XCTAssertEqual(try Data(contentsOf: directory.file("known_hosts")), corrupt) }
        }
    }

    private func metadata(_ file: URL) throws -> stat {
        var value = stat()
        guard lstat(file.path, &value) == 0 else { throw HostTrustError.systemOperation("test lstat", errno) }
        return value
    }

    private nonisolated static func attemptRemoval(_ store: HostTrustStore, _ expected: TrustedHostKey) async -> Bool {
        do { try await store.remove(expected); return true }
        catch { return false }
    }

    private nonisolated static func attemptReplacement(_ store: HostTrustStore, _ decision: PendingTrustDecision) async -> Bool {
        do { try await store.confirm(decision, displayedFingerprint: decision.fingerprint); return true }
        catch { return false }
    }
}

private final class TrustDecisionTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    func now() -> ContinuousClock.Instant { lock.withLock { instant } }
    func advance(by duration: Duration) { lock.withLock { instant = instant.advanced(by: duration) } }
}
