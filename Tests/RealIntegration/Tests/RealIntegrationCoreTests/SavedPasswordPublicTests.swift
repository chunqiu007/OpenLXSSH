import Foundation
import XCTest
@testable import RealIntegrationCore

final class SavedPasswordPublicTests: XCTestCase {
    let prompt = "exact independently reviewed fixture password prompt"
    func contract(testCase: SavedPasswordPublicCase = .authorized, changes: [String: Any] = [:]) throws -> SavedPasswordPublicContract {
        var value: [String: Any] = ["schema": 1, "taskID": "SAVED-PASSWORD-PUBLIC-A", "testCase": testCase.rawValue,
            "service": "passwordonly", "host": "127.0.0.1", "port": 22222, "user": "fixture",
            "manualPromptSHA256": testCase == .authorized ? NSNull() : PrivateInput.sha256(Data(prompt.utf8)) as Any,
            "credentialDirectory": "/fixture/.runtime/passwordonly/credentials-012345abcdef",
            "expectedFingerprint": "SHA256:" + Data(repeating: 1, count: 32).base64EncodedString().dropLast(), "baseImage": MinaContract.base,
            "imageID": "sha256:" + String(repeating: "a", count: 64), "containerID": String(repeating: "b", count: 64),
            "project": "openlxssh-fixture-012345abcdef", "networkID": String(repeating: "c", count: 64), "context": "desktop-linux",
            "endpoint": "unix:///Users/test/.docker/run/docker.sock"]
        changes.forEach { value[$0.key] = $0.value }
        return try JSONDecoder().decode(SavedPasswordPublicContract.self, from: JSONSerialization.data(withJSONObject: value))
    }
    func testStrictSeparateSyntaxAndNoAuthorizationRuntimeGate() throws {
        XCTAssertEqual(try SavedPasswordPublicOptions.parse([]).action, .help)
        XCTAssertEqual(try SavedPasswordPublicOptions.parse(["validate", "--contract", "/missing/saved-password-public.json"]).action, .validate)
        XCTAssertThrowsError(try SavedPasswordPublicOptions.parse(["--live", "--contract", "/missing/saved-password-public.json"]))
        XCTAssertThrowsError(try SavedPasswordPublicOptions.parse(["validate", "--contract", "/missing/openssh-auth.json"]))
        XCTAssertThrowsError(try SavedPasswordPublicInput.load(path: "/etc/passwd", buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        let path = "/build/saved-password-case-012345abcdef/saved-password-public.json"
        for testCase in [SavedPasswordPublicCase.authorized, .manualFallback] {
            XCTAssertNoThrow(try contract(testCase: testCase).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        }
        for change: [String: Any] in [["host": "localhost"], ["port": 22224], ["service": "password-kbd"], ["user": "root"],
            ["endpoint": "tcp://127.0.0.1:2375"], ["credentialDirectory": "/fixture/.runtime/passwordonly/credentials-latest"],
            ["manualPromptSHA256": String(repeating: "a", count: 64)]] {
            XCTAssertThrowsError(try contract(changes: change).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        }
        XCTAssertThrowsError(try contract(testCase: .manualFallback, changes: ["manualPromptSHA256": NSNull()]).validate(path: path, buildRoot: "/build", fixtureRoot: "/fixture", home: "/Users/test"))
        XCTAssertEqual(SavedPasswordPublicContract.activeSeconds, 45); XCTAssertEqual(SavedPasswordPublicContract.fullSeconds, 85)
    }
    func testExplicitProviderOnceCurrentGenerationAndNoManualCounts() throws {
        let session = UUID()
        var budget = SavedPasswordPublicBudget(testCase: .authorized, manualHash: nil)
        try budget.bind(session: session, generation: 1)
        try budget.beginProvider(session: session, generation: 1, cancelled: false)
        try budget.claimProviderRead(session: session, generation: 1, cancelled: false)
        try budget.finishProvider(session: session, generation: 1, cancelled: false)
        XCTAssertNoThrow(try budget.requireExpected(connectedEvents: 1))
        XCTAssertEqual(budget.providerCalls, 1); XCTAssertEqual(budget.providerReturns, 1); XCTAssertEqual(budget.manualRequests, 0)
        XCTAssertThrowsError(try budget.beginProvider(session: session, generation: 1, cancelled: false))
        XCTAssertEqual(budget.providerSecretReads, 1); XCTAssertThrowsError(try budget.requireExpected(connectedEvents: 1))
    }
    func testUnsupportedGateCannotBecomeSuccessByManualFallbackOrConnectedOnly() throws {
        let session = UUID()
        var budget = SavedPasswordPublicBudget(testCase: .authorized, manualHash: nil)
        try budget.bind(session: session, generation: 1)
        XCTAssertThrowsError(try budget.requireExpected(connectedEvents: 1))
        XCTAssertThrowsError(try budget.claimManual(id: UUID(), session: session, generation: 1, prompt: prompt, kind: "unknownMasked", hasHint: false)) {
            XCTAssertEqual($0 as? SavedPasswordPublicError, .gateNotCovered)
        }
        XCTAssertTrue(budget.gateNotCovered); XCTAssertEqual(budget.manualSecretReads, 0); XCTAssertEqual(budget.providerCalls, 0)
        XCTAssertThrowsError(try budget.requireExpected(connectedEvents: 1))
    }
    func testNoAuthorizationManualOnlyExactHashKindHintAndOneReply() throws {
        let session = UUID(), id = UUID(), hash = PrivateInput.sha256(Data(prompt.utf8))
        var budget = SavedPasswordPublicBudget(testCase: .manualFallback, manualHash: hash)
        try budget.bind(session: session, generation: 1)
        try budget.claimManual(id: id, session: session, generation: 1, prompt: prompt, kind: "unknownMasked", hasHint: false)
        try budget.finishManual(id: id, session: session, generation: 1, cancelled: false)
        XCTAssertNoThrow(try budget.requireExpected(connectedEvents: 1))
        XCTAssertEqual(budget.providerCalls, 0); XCTAssertEqual(budget.manualRequests, 1); XCTAssertEqual(budget.manualReplies, 1)
        XCTAssertThrowsError(try budget.claimManual(id: id, session: session, generation: 1, prompt: prompt, kind: "unknownMasked", hasHint: false))
        for tuple in [("Password:", "unknownMasked", false), (prompt, "confirmation", false), (prompt, "unknownMasked", true)] {
            var wrong = SavedPasswordPublicBudget(testCase: .manualFallback, manualHash: hash); try wrong.bind(session: session, generation: 1)
            XCTAssertThrowsError(try wrong.claimManual(id: UUID(), session: session, generation: 1, prompt: tuple.0, kind: tuple.1, hasHint: tuple.2))
            XCTAssertEqual(wrong.manualSecretReads, 0)
        }
        var noAuthorization = SavedPasswordPublicBudget(testCase: .manualFallback, manualHash: hash)
        try noAuthorization.bind(session: session, generation: 1)
        XCTAssertThrowsError(try noAuthorization.beginProvider(session: session, generation: 1, cancelled: false))
        XCTAssertEqual(noAuthorization.providerSecretReads, 0)
    }
    func testCancellationOrStaleTokenBeforeReadAndAfterAwaitNeverReturnsSecret() throws {
        let session = UUID()
        for invalidation in 0..<4 {
            var budget = SavedPasswordPublicBudget(testCase: .authorized, manualHash: nil); try budget.bind(session: session, generation: 1)
            if invalidation == 0 {
                XCTAssertThrowsError(try budget.beginProvider(session: session, generation: 1, cancelled: true))
                XCTAssertEqual(budget.providerSecretReads, 0)
            } else {
                try budget.beginProvider(session: session, generation: 1, cancelled: false)
                if invalidation == 1 {
                    budget.close(); XCTAssertThrowsError(try budget.claimProviderRead(session: session, generation: 1, cancelled: false))
                    XCTAssertEqual(budget.providerSecretReads, 0)
                } else {
                    try budget.claimProviderRead(session: session, generation: 1, cancelled: false)
                    if invalidation == 2 { budget.close() }
                    XCTAssertThrowsError(try budget.finishProvider(session: session, generation: invalidation == 3 ? 2 : 1, cancelled: invalidation == 2))
                    XCTAssertEqual(budget.providerReturns, 0)
                }
            }
        }
        var foreign = SavedPasswordPublicBudget(testCase: .authorized, manualHash: nil); try foreign.bind(session: session, generation: 1)
        XCTAssertThrowsError(try foreign.beginProvider(session: UUID(), generation: 1, cancelled: false))
        XCTAssertThrowsError(try foreign.bind(session: session, generation: 2))
    }
    func testReportExplicitlyDoesNotClaimPersistenceOrKeychain() throws {
        let report = SavedPasswordPublicReport(testCase: .authorized)
        XCTAssertFalse(report.keychainAccess); XCTAssertFalse(report.persistenceVerified)
        XCTAssertFalse(report.providerHasPromptParameter); XCTAssertFalse(report.productionGateExercised)
        XCTAssertEqual(report.result, "failed")
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as! [String: Any]
        for forbidden in ["password", "secret", "prompt", "answer", "credentialDirectory", "secretHash"] { XCTAssertNil(object[forbidden]) }
    }
}
