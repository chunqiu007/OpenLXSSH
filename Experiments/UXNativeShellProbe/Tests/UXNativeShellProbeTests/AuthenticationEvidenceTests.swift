import Foundation
import OpenLXSSHFiles
import XCTest
@testable import UXNativeShellProbeSupport

final class AuthenticationEvidenceTests: XCTestCase {
    private func stages(_ fixture: ShellProbeFixture) -> [NativeShellAuthenticationStage] {
        let primary: NativeShellPrimaryMethod = fixture.usesKey ? .publicKey : .password
        let mfa = fixture == .keyKbd || fixture == .passwordKbd
        return [.advertised(password: !fixture.usesKey, publicKey: fixture.usesKey, keyboardInteractive: false),
                .primaryStarted(primary), .primaryResult(primary, code: mfa ? -18 : 0, authenticated: !mfa)] +
            (mfa ? [.keyboardStarted, .keyboardResult(code: 0, authenticated: true)] : []) + [.authenticated, .shellReady]
    }
    func testFourActualStageSequencesRequireOnePrimaryAndActualShellReady() throws {
        for fixture in ShellProbeFixture.allCases {
            let evidence = try ShellProbeAuthenticationEvidence(stages: stages(fixture), fixture: fixture)
            XCTAssertEqual(evidence.primaryStarted, 1); XCTAssertEqual(evidence.primaryResults, 1)
            XCTAssertEqual(evidence.shellReadyEvents, 1); XCTAssertEqual(evidence.authenticatedEvents, 1)
            XCTAssertEqual(evidence.keyboardStarted, fixture == .keyKbd || fixture == .passwordKbd ? 1 : 0)
        }
    }
    func testRepeatedMissingReorderedAndWrongMethodFactsCannotTurnGreen() {
        let original = stages(.passwordKbd)
        for bad in [Array(original.dropLast()), original + [.shellReady], original + [.primaryStarted(.password)],
                    original.reversed().map { $0 }, stages(.keyKbd),
                    [.primaryStarted(.password), .primaryResult(.password, code: -18, authenticated: false)],
                    [.advertised(password: true, publicKey: false, keyboardInteractive: true), .primaryStarted(.password),
                     .primaryResult(.password, code: -18, authenticated: false), .keyboardStarted,
                     .keyboardResult(code: -10002, authenticated: false), .authenticated, .shellReady]] {
            XCTAssertThrowsError(try ShellProbeAuthenticationEvidence(stages: bad, fixture: .passwordKbd))
        }
    }
    func testReportContainsFactsNotClaimedPartialAcceptanceOrSecrets() throws {
        let evidence = try ShellProbeAuthenticationEvidence(stages: stages(.passwordKbd), fixture: .passwordKbd)
        let data = try JSONEncoder().encode(evidence), text = String(decoding: data, as: UTF8.self)
        XCTAssertFalse(text.contains("partial")); XCTAssertFalse(text.contains("primaryAccepted"))
        XCTAssertFalse(text.contains("prompt")); XCTAssertFalse(text.contains("secret"))
        XCTAssertEqual(evidence.primaryCode, -18); XCTAssertFalse(evidence.primaryAuthenticated)
    }
}
