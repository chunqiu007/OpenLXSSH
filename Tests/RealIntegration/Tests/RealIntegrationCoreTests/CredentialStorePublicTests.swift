import Foundation
import XCTest
@testable import RealIntegrationCore

/// Pure state/contract tests only: does not import/instantiate CredentialStore,
/// touch SecItem/default Keychain or invoke a live consumer.
final class CredentialStorePublicTests: XCTestCase {
    func fresh() -> CredentialStorePublicState { CredentialStorePublicState(namespace: UUID(), referenceID: UUID(), runID: UUID()) }
    func owned() throws -> CredentialStorePublicState {
        var state = fresh(); try state.preparedWasDurable(); try state.beginSave(); try state.finishSave(.saved); return state
    }
    func contract(_ changes: [String: Any] = [:]) throws -> CredentialStorePublicContract {
        var value: [String: Any] = ["schema": 1, "taskID": "PUBLIC-CREDENTIAL-STORE-A", "testCase": "save-read-provider-forget",
            "keychainScope": CredentialStorePublicContract.scope, "savingAuthorized": true, "service": "passwordonly", "host": "127.0.0.1", "port": 22222,
            "user": "fixture", "credentialDirectory": "/fixture/.runtime/passwordonly/credentials-012345abcdef",
            "expectedFingerprint": "SHA256:" + Data(repeating: 1, count: 32).base64EncodedString().dropLast(), "baseImage": MinaContract.base,
            "imageID": "sha256:" + String(repeating: "a", count: 64), "containerID": String(repeating: "b", count: 64),
            "project": "openlxssh-fixture-012345abcdef", "networkID": String(repeating: "c", count: 64), "context": "desktop-linux",
            "endpoint": "unix:///Users/test/.docker/run/docker.sock"]
        changes.forEach { value[$0.key] = $0.value }
        return try JSONDecoder().decode(CredentialStorePublicContract.self, from: JSONSerialization.data(withJSONObject: value))
    }
    func testInertSyntaxAndSeparateExplicitKeychainAccidentGate() throws {
        XCTAssertEqual(try CredentialStorePublicOptions.parse([]).action, .help)
        XCTAssertEqual(try CredentialStorePublicOptions.parse(["validate", "--contract", "/missing/credential-store-public.json"]).action, .validate)
        for args in [["--live", "--contract", "/missing/credential-store-public.json"],
                     ["--live", "--authorized-local-fixture", "--engine-ready", "--contract", "/missing/credential-store-public.json"],
                     ["--live", "--authorized-test-keychain", "--contract", "/missing/credential-store-public.json"]] {
            XCTAssertThrowsError(try CredentialStorePublicOptions.parse(args)) { XCTAssertEqual($0 as? SmokeError, .authorizationRequired) }
        }
        XCTAssertEqual(try CredentialStorePublicOptions.parse(["--live", "--authorized-local-fixture", "--engine-ready", "--authorized-test-keychain", "--contract", "/missing/credential-store-public.json"]).action, .live)
        XCTAssertThrowsError(try CredentialStorePublicOptions.parse(["validate", "--authorized-test-keychain", "--contract", "/missing/credential-store-public.json"]))
        XCTAssertThrowsError(try CredentialStorePublicInput.load(path: "/etc/passwd", buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
    }
    func testFixedContractCannotSelectProductionNamespaceOrPhysicalKeychain() throws {
        let path = "/build/credential-store-case-012345abcdef/credential-store-public.json"
        XCTAssertNoThrow(try contract().validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        for change: [String: Any] in [["savingAuthorized": false], ["keychainScope": "isolated-keychain"], ["host": "localhost"], ["service": "password-kbd"],
            ["port": 22224], ["user": "root"], ["endpoint": "tcp://127.0.0.1:2375"], ["credentialDirectory": "/fixture/.runtime/passwordonly/credentials-latest"]] {
            XCTAssertThrowsError(try contract(change).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        }
        XCTAssertThrowsError(try CredentialStorePublicContract.checkPath("/build/credential-store-case-latest/credential-store-public.json", buildRoot: "/build"))
        let state = fresh()
        XCTAssertEqual(state.service, "org.openlxssh.credentials.test." + state.namespace.uuidString)
        XCTAssertNotEqual(state.service, "org.openlxssh.credentials")
    }
    func testSaveRequiresDurablePreparedRecordAndExplicitSavedOwnership() throws {
        var state = fresh()
        XCTAssertThrowsError(try state.beginSave()); XCTAssertFalse(state.mayAttemptExactDelete)
        try state.preparedWasDurable(); try state.beginSave()
        XCTAssertThrowsError(try state.beginSave())
        XCTAssertFalse(state.ownsExactItem); XCTAssertFalse(state.mayAttemptExactDelete)
        XCTAssertThrowsError(try state.beginExactDelete()) // Unconfirmed prepared after kill cannot adopt.
        try state.finishSave(.saved)
        XCTAssertTrue(state.ownsExactItem); XCTAssertTrue(state.mayAttemptExactDelete)
        XCTAssertThrowsError(try state.finishSave(.saved))
    }
    func testDuplicateDeniedAndUnknownFailedSaveNeverReplaceOrDelete() throws {
        for reason in [CredentialStorePublicFailure.duplicate, .denied, .interactionNotAllowed, .cancelled, .unavailable, .otherStatus] {
            var state = fresh(); try state.preparedWasDurable(); try state.beginSave(); try state.finishSave(.failed(reason))
            XCTAssertFalse(state.ownsExactItem); XCTAssertFalse(state.mayAttemptExactDelete)
            XCTAssertThrowsError(try state.beginExactDelete()); XCTAssertEqual(state.deleteAttempts, 0)
            XCTAssertEqual(state.credentialFailure, reason)
            XCTAssertEqual(state.failure, reason == .duplicate ? .duplicateNotOwned : .saveFailed)
            XCTAssertThrowsError(try state.requireSuccessfulLifecycle())
        }
        var notGranted = fresh(); try notGranted.preparedWasDurable(); try notGranted.beginSave(); try notGranted.finishSave(.notAuthorized)
        XCTAssertEqual(notGranted.failure, .saveNotAuthorized); XCTAssertFalse(notGranted.mayAttemptExactDelete)
    }
    func testOwnedDeleteIsOneExactAttemptMissingAndRestoredCloseAreMandatory() throws {
        var state = try owned()
        XCTAssertThrowsError(try state.requireSuccessfulLifecycle())
        try state.beginExactDelete(); XCTAssertThrowsError(try state.beginExactDelete())
        try state.finishDelete(.deleted)
        XCTAssertFalse(state.ownsExactItem); XCTAssertFalse(state.mayAttemptExactDelete)
        XCTAssertThrowsError(try state.requireSuccessfulLifecycle())
        try state.recordMissing(true); XCTAssertThrowsError(try state.requireSuccessfulLifecycle())
        state.recordClose(restored: true)
        XCTAssertNoThrow(try state.requireSuccessfulLifecycle())
        XCTAssertEqual(state.phase, .closed); XCTAssertEqual(state.deleteAttempts, 1)
        var absent = try owned(); try absent.beginExactDelete(); try absent.finishDelete(.alreadyAbsent); try absent.recordMissing(true); absent.recordClose(restored: true)
        XCTAssertNoThrow(try absent.requireSuccessfulLifecycle())
    }
    func testDeleteRetryRestoreFailureAndReceiptFailureStayNonSuccessWithExactIDs() throws {
        var retry = try owned(); let reference = retry.referenceID
        try retry.beginExactDelete(); try retry.finishDelete(.retryRequired(.interactionNotAllowed))
        XCTAssertEqual(retry.failure, .deleteRetryRequired); XCTAssertTrue(retry.ownsExactItem); XCTAssertEqual(retry.referenceID, reference)
        XCTAssertFalse(retry.mayAttemptExactDelete); XCTAssertThrowsError(try retry.requireSuccessfulLifecycle())
        var restore = try owned(); try restore.beginExactDelete(); try restore.finishDelete(.deleted); try restore.recordMissing(true); restore.recordClose(restored: false)
        XCTAssertEqual(restore.failure, .interactionRestoreFailed); XCTAssertThrowsError(try restore.requireSuccessfulLifecycle())
        var receipt = try owned(); receipt.fail(.recoveryRecordFailed)
        XCTAssertTrue(receipt.mayAttemptExactDelete) // In-process confirmed .saved may still compensate exact own item.
        try receipt.beginExactDelete(); try receipt.finishDelete(.deleted); try receipt.recordMissing(true); receipt.recordClose(restored: true)
        XCTAssertThrowsError(try receipt.requireSuccessfulLifecycle())
        var unreadable = try owned(); try unreadable.beginExactDelete(); try unreadable.finishDelete(.deleted); try unreadable.recordMissing(false)
        XCTAssertEqual(unreadable.failure, .missingNotVerified)
    }
    func testRecoveryAndReportAreNonsecretAndNeverAuthorizeAutomaticAdoption() throws {
        var state = fresh(); try state.preparedWasDurable()
        let receipt = CredentialStorePublicRecoveryRecord(event: "prepared", state: state)
        let encoded = try JSONEncoder().encode(receipt)
        XCTAssertLessThan(encoded.count, 8192)
        let value = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        XCTAssertEqual(value["automaticRecoveryDeletionAllowed"] as? Bool, false)
        XCTAssertEqual(value["physicalKeychainIsolation"] as? Bool, false)
        let report = CredentialStorePublicReport(state: state)
        XCTAssertFalse(report.physicalKeychainIsolation); XCTAssertFalse(report.appUISaveForgetVerified)
        XCTAssertFalse(report.sandboxAcceptance); XCTAssertFalse(report.lifecycleVerified)
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as! [String: Any]
        for key in ["password", "secret", "answer", "secretHash", "fixturePassword", "keychainPath"] { XCTAssertNil(object[key]) }
    }
}
