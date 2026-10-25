import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHCredentialKeyProbe

private final class HandoffMemoryStore: CredentialStorage {
    var items: [CredentialReference: SecretBytes] = [:]
    var saveFailure: CredentialFailure?
    var readFailure: CredentialFailure?
    var deleteFailure: CredentialFailure?
    var deleted: [CredentialReference] = []

    func save(_ secret: SecretBytes, as reference: CredentialReference,
              authorization: RememberAuthorization) -> CredentialSaveResult {
        guard authorization == .granted else { return .notAuthorized }
        if let saveFailure { return .failed(saveFailure) }
        items[reference] = secret
        return .saved(reference)
    }
    func replace(_ secret: SecretBytes, at reference: CredentialReference,
                 authorization: RememberAuthorization) -> CredentialUpdateResult {
        guard authorization == .granted else { return .notAuthorized }
        guard items[reference] != nil else { return .missing }
        items[reference] = secret
        return .updated(reference)
    }
    func read(_ reference: CredentialReference) -> CredentialReadResult {
        if let readFailure { return .manualEntryRequired(readFailure) }
        return items[reference].map { .available($0) } ?? .missing
    }
    func delete(_ reference: CredentialReference) -> CredentialDeleteResult {
        deleted.append(reference)
        if let deleteFailure { return .retryRequired(deleteFailure) }
        return items.removeValue(forKey: reference) == nil ? .alreadyAbsent : .deleted
    }
}

final class LiveKeychainHandoffTests: XCTestCase {
    private func withTicket(_ body: (URL) throws -> Void) throws {
        let directory = try PrivateDirectory()
        let url = directory.url.appendingPathComponent("handoff.json")
        defer { _ = unlink(url.path); _ = rmdir(directory.url.path) }
        try body(url)
    }

    func testNonsecretTicketAndProofRoundtripDeleteExactItem() throws {
        try withTicket { url in
            let store = HandoffMemoryStore()
            var namespace: UUID?
            let first = try LiveKeychainHandoff.create(ticketURL: url) { value in namespace = value; return store }
            let data = try Data(contentsOf: url)
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            XCTAssertEqual(Set(json?.keys.map { $0 } ?? []), ["version", "namespace", "credentialID"])
            XCTAssertEqual(json?["namespace"] as? String, namespace?.uuidString)
            XCTAssertEqual(store.items.count, 1)
            XCTAssertEqual(String(describing: first), "<redacted proof>")
            XCTAssertTrue(Mirror(reflecting: first).children.isEmpty)
            let second = try LiveKeychainHandoff.readAndDelete(ticketURL: url) { value in
                XCTAssertEqual(value, namespace)
                return store
            }
            XCTAssertTrue(first.bytes == second.bytes, "Proofs differ; do not print secret-derived bytes")
            XCTAssertEqual(first.bytes.count, 32)
            XCTAssertTrue(store.items.isEmpty)
            XCTAssertEqual(store.deleted.count, 1)
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        }
    }

    func testReadFailureDefersDeletionAndRetainsTicketWhenAbsenceCannotBeVerified() throws {
        try withTicket { url in
            let store = HandoffMemoryStore()
            _ = try LiveKeychainHandoff.create(ticketURL: url) { _ in store }
            store.readFailure = .interactionNotAllowed
            XCTAssertThrowsError(try LiveKeychainHandoff.readAndDelete(ticketURL: url) { _ in store })
            XCTAssertEqual(store.deleted.count, 1)
            XCTAssertTrue(store.items.isEmpty)
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
            store.readFailure = nil
            try LiveKeychainHandoff.cleanup(ticketURL: url) { _ in store }
            XCTAssertEqual(store.deleted.count, 2)
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        }
    }

    func testDeleteFailureRetainsExactRetryTicketAndCleanupIsExplicit() throws {
        try withTicket { url in
            let store = HandoffMemoryStore()
            _ = try LiveKeychainHandoff.create(ticketURL: url) { _ in store }
            let before = try Data(contentsOf: url)
            store.deleteFailure = .unavailable
            XCTAssertThrowsError(try LiveKeychainHandoff.readAndDelete(ticketURL: url) { _ in store })
            XCTAssertEqual(store.deleted.count, 1)
            XCTAssertTrue(store.items.count == 1)
            XCTAssertTrue(try Data(contentsOf: url) == before)
            store.deleteFailure = nil
            try LiveKeychainHandoff.cleanup(ticketURL: url) { _ in store }
            XCTAssertTrue(store.items.isEmpty)
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        }
    }

    func testFailedSaveCompensatesAndDoesNotLeaveSuccessfulFixture() throws {
        try withTicket { url in
            let store = HandoffMemoryStore()
            store.saveFailure = .unavailable
            XCTAssertThrowsError(try LiveKeychainHandoff.create(ticketURL: url) { _ in store }) { error in
                XCTAssertEqual((error as? LiveKeychainLimitation)?.failure, .unavailable)
            }
            XCTAssertTrue(store.items.isEmpty)
            XCTAssertEqual(store.deleted.count, 1)
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        }
    }

    func testExistingTicketAndSymlinkNeverAuthorizeAnUnrelatedStore() throws {
        try withTicket { url in
            let store = HandoffMemoryStore()
            _ = try LiveKeychainHandoff.create(ticketURL: url) { _ in store }
            var extraStoreRequested = false
            XCTAssertThrowsError(try LiveKeychainHandoff.create(ticketURL: url) { _ in extraStoreRequested = true; return store })
            XCTAssertFalse(extraStoreRequested)
            let link = url.appendingPathExtension("link")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: url)
            defer { try? FileManager.default.removeItem(at: link) }
            XCTAssertThrowsError(try LiveKeychainHandoff.cleanup(ticketURL: link) { _ in extraStoreRequested = true; return store })
            XCTAssertFalse(extraStoreRequested)
            try LiveKeychainHandoff.cleanup(ticketURL: url) { _ in store }
        }
    }

    func testSelfSigningDiagnosticsReturnOnlyBooleansWithoutAccessingKeychain() {
        let summary = LiveSigningDiagnostics.summary()
        XCTAssertEqual(summary["self_task_available"], true)
        XCTAssertEqual(summary["provisioning_authorization_proven_by_sectask_value"], false)
        XCTAssertNotNil(summary["runtime_app_id_present"])
        XCTAssertNotNil(summary["runtime_explicit_access_groups_present"])
    }

    func testProofCanOnlyBeWrittenToDedicatedPipe() throws {
        try withTicket { url in
            let store = HandoffMemoryStore()
            let proof = try LiveKeychainHandoff.create(ticketURL: url) { _ in store }
            XCTAssertThrowsError(try proof.write(to: STDOUT_FILENO))
            let descriptor = open("/dev/null", O_WRONLY)
            defer { _ = Darwin.close(descriptor) }
            XCTAssertThrowsError(try proof.write(to: descriptor))
            var descriptors = [Int32](repeating: -1, count: 2)
            XCTAssertEqual(pipe(&descriptors), 0)
            defer { _ = Darwin.close(descriptors[0]); _ = Darwin.close(descriptors[1]) }
            try proof.write(to: descriptors[1])
            var received = Data(count: 32)
            let count = received.withUnsafeMutableBytes { Darwin.read(descriptors[0], $0.baseAddress, $0.count) }
            XCTAssertEqual(count, 32)
            XCTAssertTrue(received == proof.bytes)
            try LiveKeychainHandoff.cleanup(ticketURL: url) { _ in store }
        }
    }
}
