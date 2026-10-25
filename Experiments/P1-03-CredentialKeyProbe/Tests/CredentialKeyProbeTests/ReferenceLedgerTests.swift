import Foundation
import XCTest
@testable import OpenLXSSHCredentialKeyProbe

private enum MetadataTestFailure: Error { case injected }

@MainActor
private final class LedgerHarness {
    var commits = 0
    var deleted: [StoredResource] = []
    var failAllCommits = false
    var failCommitNumbers: Set<Int> = []
    var deletionFailure: CleanupFailure?
    func makeLedger() -> ReferenceLedger {
        ReferenceLedger(commit: { [self] _ in
            commits += 1
            if failAllCommits || failCommitNumbers.contains(commits) { throw MetadataTestFailure.injected }
        }, delete: { [self] resource in
            deleted.append(resource)
            return deletionFailure.map { .retryRequired($0) } ?? .deleted
        })
    }
}

@MainActor
final class ReferenceLedgerTests: XCTestCase {
    func testSharedHostRemovalRetainsBothResourcesUntilLastReference() async {
        let a = UUID(), b = UUID()
        let credential = StoredResource.credential(.init(kind: .password))
        let key = StoredResource.key(UUID())
        let harness = LedgerHarness(), ledger: ReferenceLedger
        ledger = harness.makeLedger()
        let credentialCreated = await ledger.registerCreated(credential, host: a)
        let keyCreated = await ledger.registerCreated(key, host: a)
        XCTAssertEqual(credentialCreated, .committed)
        XCTAssertEqual(keyCreated, .committed)
        XCTAssertEqual(ledger.attach(credential, host: b), .committed)
        XCTAssertEqual(ledger.attach(key, host: b), .committed)
        let first = await ledger.removeHost(a)
        XCTAssertEqual(first, .committed)
        XCTAssertTrue(harness.deleted.isEmpty)
        XCTAssertEqual(ledger.snapshot.resources, [credential, key])
        let second = await ledger.removeHost(b)
        XCTAssertEqual(second, .committed)
        XCTAssertEqual(Set(harness.deleted), [credential, key])
        XCTAssertTrue(ledger.snapshot.resources.isEmpty)
        XCTAssertTrue(ledger.snapshot.pendingDeletion.isEmpty)
    }

    func testMetadataCreateFailureCompensatesOnlyNewExactResource() async {
        let new = StoredResource.key(UUID())
        let harness = LedgerHarness()
        harness.failAllCommits = true
        let ledger = harness.makeLedger()
        let result = await ledger.registerCreated(new, host: UUID())
        XCTAssertEqual(result, .metadataFailed)
        XCTAssertEqual(harness.deleted, [new])
        XCTAssertTrue(ledger.snapshot.hosts.isEmpty)
        XCTAssertTrue(ledger.snapshot.resources.isEmpty)
    }

    func testFailedCompensationReturnsUnjournaledExactRetryTicket() async {
        let resource = StoredResource.credential(.init(kind: .privateKeyPassphrase))
        let harness = LedgerHarness()
        harness.failAllCommits = true
        harness.deletionFailure = .credential(.unavailable)
        let ledger = harness.makeLedger()
        let result = await ledger.registerCreated(resource, host: UUID())
        XCTAssertEqual(result, .cleanupPending([.init(resource: resource, failure: .credential(.unavailable))], journaled: false))
        XCTAssertEqual(harness.deleted.count, 1)
        XCTAssertTrue(ledger.snapshot.hosts.isEmpty)
        XCTAssertEqual(ledger.attach(resource, host: UUID()), .unknownResource)
        harness.failAllCommits = false
        harness.deletionFailure = nil
        let retry = await ledger.retryCleanup()
        XCTAssertEqual(retry, .committed)
        XCTAssertEqual(harness.deleted.count, 2)
        XCTAssertTrue(ledger.snapshot.resources.isEmpty)
    }

    func testHostCommitFailurePreservesReferencesAndDoesNotDelete() async {
        let host = UUID(), resource = StoredResource.key(UUID())
        let harness = LedgerHarness()
        let ledger = harness.makeLedger()
        _ = await ledger.registerCreated(resource, host: host)
        harness.failAllCommits = true
        let result = await ledger.removeHost(host)
        XCTAssertEqual(result, .metadataFailed)
        XCTAssertTrue(harness.deleted.isEmpty)
        XCTAssertEqual(ledger.snapshot.hosts[host], [resource])
    }

    func testDeleteFailureLeavesJournaledPendingAndRetryIsBounded() async {
        let host = UUID(), resource = StoredResource.key(UUID())
        let harness = LedgerHarness()
        harness.deletionFailure = .key(.unsafePermissions)
        let ledger = harness.makeLedger()
        _ = await ledger.registerCreated(resource, host: host)
        let result = await ledger.removeHost(host)
        XCTAssertEqual(result, .cleanupPending([.init(resource: resource, failure: .key(.unsafePermissions))], journaled: true))
        XCTAssertEqual(harness.deleted.count, 1)
        XCTAssertEqual(ledger.snapshot.pendingDeletion, [resource])
        harness.deletionFailure = nil
        let retry = await ledger.retryCleanup()
        XCTAssertEqual(retry, .committed)
        XCTAssertEqual(harness.deleted.count, 2)
    }

    func testPostDeleteMetadataFailureRetainsIdempotentRetryTicket() async {
        let host = UUID(), resource = StoredResource.key(UUID())
        let harness = LedgerHarness()
        harness.failCommitNumbers = [3]
        let ledger = harness.makeLedger()
        _ = await ledger.registerCreated(resource, host: host)
        let result = await ledger.removeHost(host)
        XCTAssertEqual(result, .cleanupPending([.init(resource: resource, failure: .metadataCommit)], journaled: true))
        XCTAssertEqual(ledger.snapshot.pendingDeletion, [resource])
        let retry = await ledger.retryCleanup()
        XCTAssertEqual(retry, .committed)
        XCTAssertEqual(harness.deleted.count, 2)
    }

    func testSaveFailureAndNoRememberDoNotCommitMetadata() async throws {
        let backend = StubKeychainBackend()
        let store = CredentialStore(namespace: UUID(), backend: backend)
        let harness = LedgerHarness()
        let ledger = harness.makeLedger()
        let secret = try SecretBytes.random()
        let reference = CredentialReference(kind: .password)
        let noRemember = await ledger.createCredential(secret, reference: reference, host: UUID(), authorization: .notGranted, store: store)
        XCTAssertEqual(noRemember, .notAuthorized)
        backend.addStatus = -25291
        let saveFailure = await ledger.createCredential(secret, reference: reference, host: UUID(), authorization: .granted, store: store)
        XCTAssertEqual(saveFailure, .credentialSaveFailed(.unavailable))
        XCTAssertEqual(harness.commits, 0)
        XCTAssertTrue(harness.deleted.isEmpty)
        XCTAssertTrue(backend.deletes.isEmpty)
    }

    func testAuthorizedCredentialCreateAndSharedDeleteUseExactStoreReference() async throws {
        let backend = StubKeychainBackend()
        let store = CredentialStore(namespace: UUID(), backend: backend)
        let reference = CredentialReference(kind: .password)
        let hostA = UUID(), hostB = UUID()
        let ledger = ReferenceLedger(commit: { _ in }, delete: { resource in
            guard case .credential(let item) = resource else { return .retryRequired(.key(.missing)) }
            switch store.delete(item) {
            case .deleted, .alreadyAbsent: return .deleted
            case .retryRequired(let failure): return .retryRequired(.credential(failure))
            }
        })
        let result = await ledger.createCredential(try .random(), reference: reference, host: hostA,
                                                   authorization: .granted, store: store)
        XCTAssertEqual(result, .committed)
        XCTAssertEqual(backend.adds.count, 1)
        XCTAssertEqual(ledger.attach(.credential(reference), host: hostB), .committed)
        let firstRemoval = await ledger.removeHost(hostA)
        XCTAssertEqual(firstRemoval, .committed)
        XCTAssertTrue(backend.deletes.isEmpty)
        let lastRemoval = await ledger.removeHost(hostB)
        XCTAssertEqual(lastRemoval, .committed)
        XCTAssertEqual(backend.deletes.count, 1)
        XCTAssertEqual(backend.deletes.first?["acct"] as? String, reference.account)
    }

    func testRealManagedKeySharedReferencesAndMetadataFailureCompensation() async throws {
        let store = try KeyStore()
        do {
            let key = try await store.generateEd25519(protection: .unencrypted)
            let hostA = UUID(), hostB = UUID()
            let harness = LedgerHarness()
            let ledger = ReferenceLedger(commit: { _ in
                if harness.failAllCommits { throw MetadataTestFailure.injected }
            }, delete: { resource in
                guard case .key(let id) = resource else { return .retryRequired(.credential(.invalidData)) }
                do { try await store.delete(id); return .deleted }
                catch let failure as KeyFailure { return .retryRequired(.key(failure)) }
                catch { return .retryRequired(.key(.systemCall("unexpected", 0))) }
            })
            _ = await ledger.registerCreated(.key(key.id), host: hostA)
            XCTAssertEqual(ledger.attach(.key(key.id), host: hostB), .committed)
            let first = await ledger.removeHost(hostA)
            XCTAssertEqual(first, .committed)
            let retained = try await store.publicKey(for: key.id)
            XCTAssertEqual(retained, key.publicKey)
            let last = await ledger.removeHost(hostB)
            XCTAssertEqual(last, .committed)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: store.rootURL.path).isEmpty)
            let another = try await store.generateEd25519(protection: .unencrypted)
            harness.failAllCommits = true
            let compensated = await ledger.registerCreated(.key(another.id), host: UUID())
            XCTAssertEqual(compensated, .metadataFailed)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: store.rootURL.path).isEmpty)
        } catch {
            try await store.destroy()
            throw error
        }
        try await store.destroy()
    }

    func testReRegisterExistingCannotDeleteSharedResourceOnCommitFailure() async {
        let resource = StoredResource.key(UUID())
        let harness = LedgerHarness()
        let ledger = harness.makeLedger()
        _ = await ledger.registerCreated(resource, host: UUID())
        harness.failAllCommits = true
        let result = await ledger.registerCreated(resource, host: UUID())
        XCTAssertEqual(result, .alreadyRegistered)
        XCTAssertTrue(harness.deleted.isEmpty)
    }
}
