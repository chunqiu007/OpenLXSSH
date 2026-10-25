import Darwin
import Foundation
import OpenLXSSHCredentialKeyProbe
import Security
import XCTest
@testable import FileKeychainCandidate

private final class FileStub: FileCandidateBackend {
    var addStatus: OSStatus = errSecSuccess
    var readStatus: OSStatus = errSecItemNotFound
    var updateStatus: OSStatus = errSecSuccess
    var deleteStatus: OSStatus = errSecSuccess
    var data: Data?
    var queries: [[String: Any]] = []
    var updates: [[String: Any]] = []
    func add(_ query: [String: Any]) -> OSStatus { queries.append(query); return addStatus }
    func copy(_ query: [String: Any]) -> (OSStatus, Any?) { queries.append(query); return (readStatus, data) }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        queries.append(query); updates.append(attributes); return updateStatus
    }
    func delete(_ query: [String: Any]) -> OSStatus { queries.append(query); return deleteStatus }
}

final class FileKeychainCandidateTests: XCTestCase {
    func testUnapprovedSaveAndReplaceNeverCallBackend() throws {
        let stub = FileStub(), reference = CredentialReference(kind: .password)
        let store = FileKeychainCandidate(namespace: UUID(), backend: stub)
        XCTAssertEqual(store.save(try .random(), as: reference, authorization: .notGranted), .notAuthorized)
        XCTAssertEqual(store.replace(try .random(), at: reference, authorization: .notGranted), .notAuthorized)
        XCTAssertTrue(stub.queries.isEmpty)
    }

    func testExplicitFileQueriesNeverClaimDPClassesOrCustomACL() throws {
        let stub = FileStub(), reference = CredentialReference(kind: .privateKeyPassphrase)
        let store = FileKeychainCandidate(namespace: UUID(), backend: stub)
        _ = store.save(try .random(), as: reference, authorization: .granted)
        _ = store.read(reference)
        _ = store.replace(try .random(), at: reference, authorization: .granted)
        _ = store.delete(reference)
        for query in stub.queries {
            XCTAssertEqual(query[kSecAttrSynchronizable as String] as? Bool, false)
            XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, false)
            XCTAssertNil(query[kSecAttrAccessible as String])
            XCTAssertNil(query[kSecAttrAccess as String])
            XCTAssertNil(query[kSecAttrAccessControl as String])
            XCTAssertNil(query[kSecAttrAccessGroup as String])
            XCTAssertNil(query[kSecUseAuthenticationContext as String])
            XCTAssertEqual(query[kSecAttrService as String] as? String, store.service)
            XCTAssertEqual(query[kSecAttrAccount as String] as? String, "privateKeyPassphrase:\(reference.id.uuidString)")
        }
        XCTAssertNotNil(stub.queries[0][kSecUseKeychain as String])
        XCTAssertNil(stub.queries[0][kSecMatchSearchList as String])
        XCTAssertNotNil(stub.queries[1][kSecMatchSearchList as String])
        XCTAssertEqual(stub.updates[0].count, 1)
    }

    func testLockedUnavailableCancelAndDeniedAreMockOnlyManualFallback() throws {
        let stub = FileStub(), reference = CredentialReference(kind: .password)
        let store = FileKeychainCandidate(namespace: UUID(), backend: stub)
        for (status, expected): (OSStatus, CredentialFailure) in [
            (errSecInteractionNotAllowed, .interactionNotAllowed), (errSecNotAvailable, .unavailable),
            (errSecUserCanceled, .cancelled), (errSecAuthFailed, .denied)
        ] {
            stub.readStatus = status
            stub.addStatus = status
            stub.updateStatus = status
            stub.deleteStatus = status
            let count = stub.queries.count
            guard case .manualEntryRequired(let failure) = store.read(reference) else { return XCTFail("No manual fallback") }
            XCTAssertEqual(failure, expected)
            XCTAssertEqual(store.save(try .random(), as: reference, authorization: .granted), .failed(expected))
            XCTAssertEqual(store.replace(try .random(), at: reference, authorization: .granted), .failed(expected))
            XCTAssertEqual(store.delete(reference), .retryRequired(expected))
            XCTAssertEqual(stub.queries.count, count + 4)
        }
    }

    func testMissingDuplicateInvalidDataAndNoOverwrite() throws {
        let stub = FileStub(), reference = CredentialReference(kind: .password)
        let store = FileKeychainCandidate(namespace: UUID(), backend: stub)
        guard case .missing = store.read(reference) else { return XCTFail("Missing not preserved") }
        stub.addStatus = errSecDuplicateItem
        XCTAssertEqual(store.save(try .random(), as: reference, authorization: .granted), .failed(.duplicate))
        XCTAssertTrue(stub.updates.isEmpty)
        XCTAssertEqual(store.save(.init(Data()), as: reference, authorization: .granted), .failed(.invalidData))
        stub.updateStatus = errSecItemNotFound
        XCTAssertEqual(store.replace(try .random(), at: reference, authorization: .granted), .missing)
        stub.deleteStatus = errSecItemNotFound
        XCTAssertEqual(store.delete(reference), .alreadyAbsent)
        stub.readStatus = errSecSuccess
        stub.data = Data()
        guard case .manualEntryRequired(.invalidData) = store.read(reference) else { return XCTFail("Empty result not rejected") }
    }

    func testNonsecretTicketRejectsOverwriteSymlinksAndInsecurePermissions() throws {
        guard let parent = realpath(FileManager.default.temporaryDirectory.path, nil) else { return XCTFail("No temp parent") }
        defer { free(parent) }
        let directory = URL(fileURLWithPath: String(cString: parent)).appendingPathComponent("OpenLXSSH-FileCandidate-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("ticket.json")
        let ticket = FileCandidateTicket()
        try ticket.write(url)
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        XCTAssertEqual(Set(json?.keys.map { $0 } ?? []), ["namespace", "passwordID", "unapprovedID"])
        XCTAssertEqual(try FileCandidateTicket.load(url).namespace, ticket.namespace)
        XCTAssertThrowsError(try FileCandidateTicket().write(url))
        let link = directory.appendingPathComponent("linked.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: url)
        XCTAssertThrowsError(try FileCandidateTicket.load(link))
        guard chmod(url.path, 0o644) == 0 else { return XCTFail("chmod failed") }
        XCTAssertThrowsError(try FileCandidateTicket.load(url))
    }

    func testUUIDNamespacesAndKindsCannotCrossMatchAndSecretsAreRedacted() throws {
        let a = FileKeychainCandidate(namespace: UUID(), backend: FileStub())
        let b = FileKeychainCandidate(namespace: UUID(), backend: FileStub())
        XCTAssertNotEqual(a.service, b.service)
        let secret = try FileCandidateSecret.random()
        XCTAssertEqual(String(describing: secret), "<redacted>")
        XCTAssertEqual(String(reflecting: secret), "<redacted>")
        XCTAssertTrue(Mirror(reflecting: secret).children.isEmpty)
    }
}
