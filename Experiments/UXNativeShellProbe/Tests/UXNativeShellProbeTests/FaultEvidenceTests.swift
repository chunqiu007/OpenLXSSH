import Foundation
import OpenLXSSHFiles
import XCTest
@testable import UXNativeShellProbeSupport

/// Evidence-validator regressions, not real authentication or failure injection claims.
final class FaultEvidenceTests: XCTestCase {
    private let methods = NativeShellAuthenticationStage.advertised(password: true, publicKey: false, keyboardInteractive: false)
    private var rejected: [NativeShellAuthenticationStage] {
        [methods, .primaryStarted(.password), .primaryResult(.password, code: -18, authenticated: false)]
    }
    private func require(_ testCase: ShellProbeCase, stages: [NativeShellAuthenticationStage],
                         kind: NativeShellError.Kind?, code: Int32?, cancelled: Bool = false,
                         changed: Bool = false, validated: Bool = false, callbacks: Int = 0,
                         replies: Int = 0, reads: Int = 0, closed: Bool = true,
                         timedOut: Bool = false) throws {
        try ShellProbeAttemptFacts(stages: stages).requireExpected(testCase, nativeKind: kind, nativeCode: code,
            cancelled: cancelled, changedKeyRejected: changed, firstChallengeValidated: validated,
            callbackCount: callbacks, replies: replies, managementReads: reads, inputCalls: 0,
            closeCompleted: closed, timedOut: timedOut, stopped: false)
    }
    func testWrongPasswordRequiresExactlyOneNativePasswordRefusal() throws {
        try require(.wrongPrimary, stages: rejected, kind: .authentication, code: -18)
        for kind in [NativeShellError.Kind.timeout, .cancelled, .transport] {
            XCTAssertThrowsError(try require(.wrongPrimary, stages: rejected, kind: kind, code: -18))
        }
        XCTAssertThrowsError(try require(.wrongPrimary, stages: rejected + [.primaryStarted(.password)], kind: .authentication, code: -18))
        XCTAssertThrowsError(try require(.wrongPrimary, stages: rejected, kind: .authentication, code: -18, timedOut: true))
    }
    func testChangedHostKeyRequiresNoDiscoveryOrPrimary() throws {
        try require(.hostkeyMismatch, stages: [], kind: .untrusted, code: nil, changed: true)
        XCTAssertThrowsError(try require(.hostkeyMismatch, stages: [methods], kind: .untrusted, code: nil, changed: true))
        XCTAssertThrowsError(try require(.hostkeyMismatch, stages: [], kind: .untrusted, code: nil))
    }
    func testKICancelNeverAcceptsEmptyReplyOrManagementRead() throws {
        let stages = rejected + [.keyboardStarted, .keyboardResult(code: -10001, authenticated: false)]
        try require(.cancelKI, stages: stages, kind: .cancelled, code: -10001, cancelled: true, validated: true, callbacks: 1)
        XCTAssertThrowsError(try require(.cancelKI, stages: stages, kind: .cancelled, code: -10001,
            cancelled: true, validated: true, callbacks: 1, replies: 1))
        XCTAssertThrowsError(try require(.cancelKI, stages: stages, kind: .cancelled, code: -10001,
            cancelled: true, validated: true, callbacks: 1, reads: 1))
        XCTAssertThrowsError(try require(.cancelKI, stages: stages, kind: .timeout, code: -10002,
            cancelled: true, validated: true, callbacks: 1))
    }
    func testCancelReadyRequiresActualAuthenticatedShellAndClose() throws {
        let ready: [NativeShellAuthenticationStage] = [methods, .primaryStarted(.password),
            .primaryResult(.password, code: 0, authenticated: true), .authenticated, .shellReady]
        try require(.cancelAfterReady, stages: ready, kind: nil, code: nil, cancelled: true)
        XCTAssertThrowsError(try require(.cancelAfterReady, stages: Array(ready.dropLast()), kind: nil, code: nil, cancelled: true))
        XCTAssertThrowsError(try require(.cancelAfterReady, stages: ready, kind: nil, code: nil, cancelled: true, closed: false))
    }
    func testAllFaultAndKeyCasesAreFixedAndNoRetryMaterial() throws {
        try ShellProbeCase.encryptedEd.validate(fixture: .keyonly, key: "edencrypted")
        for key in ["rsaplain", "rsaencrypted"] { try ShellProbeCase.rsa.validate(fixture: .keyonly, key: key) }
        XCTAssertThrowsError(try ShellProbeCase.encryptedEd.validate(fixture: .keyKbd, key: "edencrypted"))
        XCTAssertThrowsError(try ShellProbeCase.cancelKI.validate(fixture: .passwordonly, key: "none"))
        let input = Data([17, 23]); let changed = try ShellProbeCase.wrongPrimary(input)
        XCTAssertEqual(input, Data([17, 23])); XCTAssertNotEqual(changed, input); XCTAssertEqual(changed.count, input.count)
        XCTAssertThrowsError(try ShellProbeCase.wrongPrimary(Data()))
    }
    func testCasesRequireExistingExplicitLiveAuthorizationAndRejectUnknown() throws {
        let root = "/offline/probe/.build", path = root + "/sftp-auth-case-012345abcdef/sftp-auth.json"
        for selected in ShellProbeCase.allCases {
            XCTAssertEqual(try ShellProbeCommand.parse(["validate", "--contract", path, "--case", selected.rawValue], buildRoot: root),
                .validateCase(contractPath: path, testCase: selected))
            XCTAssertThrowsError(try ShellProbeCommand.parse(["--live", "--contract", path, "--case", selected.rawValue], buildRoot: root))
        }
        XCTAssertThrowsError(try ShellProbeCommand.parse(["validate", "--contract", path, "--case", "retry"], buildRoot: root))
    }
}
