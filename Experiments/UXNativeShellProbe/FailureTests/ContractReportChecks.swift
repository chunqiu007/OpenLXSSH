import Foundation
import OpenLXSSHFiles
import UXNativeFailureSupport
import UXNativeShellProbeSupport

/// Fourteen named PURE checks. No file reader, fixture owner, actual session or socket is
/// constructed. Synthetic reports validate rejection rules, never count as real SSH evidence.
public enum NativeFailureOfflineChecks {
    public static let names = [
        "default-help-inert", "explicit-case-and-review", "closed-argv", "exact-contract-path",
        "fixed-case-service-key", "freshness-finite-120", "native-changed-typed-facts",
        "changed-requires-no-auth", "cancel-pending-survives-close", "cancel-later-drain-required",
        "sftp-typed-without-invented-instrumentation", "key-ki-real-evidence-schema",
        "password-ki-real-evidence-schema", "closed-report-resources-and-no-payload"
    ]
    public static func run() throws -> Int {
        func require(_ value: @autoclosure () throws -> Bool) throws {
            guard try value() else { throw NativeFailureCheckError.evidence }
        }
        func refuses(_ body: () throws -> Void) throws {
            do { try body() } catch { return }; throw NativeFailureCheckError.evidence
        }
        let root = "/offline/probe/.build", path = root + "/sftp-auth-case-012345abcdef/sftp-auth.json"
        let valid = ["--live", "--authorized-local-fixture", "--engine-ready", "--primary-reviewed",
                     "--contract", path, "--case", "nativeChangedNoHandler"]
        // 1
        try require(try NativeFailureCommand.parse([], buildRoot: root) == .help)
        try require(try NativeFailureCommand.parse(["--help"], buildRoot: root) == .help)
        // 2
        try require(try NativeFailureCommand.parse(valid, buildRoot: root) == .live(contractPath: path, testCase: .nativeChangedNoHandler))
        try require(try NativeFailureCommand.parse(["validate", "--contract", path, "--case", "nativeChangedNoHandler"], buildRoot: root) ==
            .validate(contractPath: path, testCase: .nativeChangedNoHandler))
        for flag in ["--authorized-local-fixture", "--engine-ready", "--primary-reviewed"] {
            try refuses { _ = try NativeFailureCommand.parse(valid.filter { $0 != flag }, buildRoot: root) }
        }
        try refuses { _ = try NativeFailureCommand.parse(Array(valid.dropLast(2)), buildRoot: root) }
        // 3
        for extra in [["--host", "127.0.0.1"], ["--exec", "true"], ["--password", "forbidden"],
                      ["--primary-reviewed"], ["--contract", path], ["--case", "nativeCancelledProvider"]] {
            try refuses { _ = try NativeFailureCommand.parse(valid + extra, buildRoot: root) }
        }
        try refuses { _ = try NativeFailureCommand.parse(["validate"] + Array(valid.dropFirst()), buildRoot: root) }
        // 4
        for bad in ["/etc/passwd", path + "\n", path.replacingOccurrences(of: "012345abcdef", with: "latest"),
                    path.replacingOccurrences(of: "012345abcdef", with: "012345ABCDEF"),
                    path.replacingOccurrences(of: "/sftp-auth.json", with: "/../sftp-auth.json")] {
            try refuses { _ = try NativeFailureCommand.parse(["validate", "--contract", bad, "--case", "nativeChangedNoHandler"], buildRoot: root) }
        }
        // 5
        try require(NativeFailureCase.allCases.count == 5)
        for testCase in NativeFailureCase.allCases {
            try testCase.validate(service: testCase.fixture.rawValue, key: testCase.key)
            try refuses { try testCase.validate(service: "passwordonly", key: "none") }
            try refuses { try testCase.validate(service: testCase.fixture.rawValue, key: "edencrypted") }
        }
        // 6
        try NativeFailureFreshness.validate(collectedAt: 100, now: 220)
        for (collected, now) in [(100.0, 220.001), (100, 99.9), (0, 100), (.nan, 100), (100, .infinity)] {
            try refuses { try NativeFailureFreshness.validate(collectedAt: collected, now: now) }
        }
        // 7
        try changed(.nativeChangedNoHandler).requireExpected()
        var altered = changed(.nativeChangedNoHandler); altered.presentedFingerprintMatchesOutOfBand = false
        try refuses { try altered.requireExpected() }
        altered = changed(.nativeChangedNoHandler); altered.handleFromTypedError = false
        try refuses { try altered.requireExpected() }
        // 8
        altered = changed(.nativeChangedNoHandler); altered.primaryProviderCalls = 1
        try refuses { try altered.requireExpected() }
        altered = changed(.nativeChangedNoHandler); altered.stages = NativeFailureStages([.primaryStarted(.publicKey)])
        try refuses { try altered.requireExpected() }
        altered = changed(.nativeChangedNoHandler); altered.knownHostsInodeUnchanged = false
        try refuses { try altered.requireExpected() }
        // 9
        try cancelled().requireExpected()
        altered = cancelled(); altered.afterShortWait = drained()
        try refuses { try altered.requireExpected() }
        altered = cancelled(); altered.referencesDroppedBeforeWait = false
        try refuses { try altered.requireExpected() }
        altered = cancelled(); altered.closeAfterCancellationSeconds = 0.1
        try refuses { try altered.requireExpected() }
        // 10
        altered = cancelled(); altered.afterRelease = pending()
        try refuses { try altered.requireExpected() }
        altered = cancelled(); altered.providerReturnedAfterCancellation = false
        try refuses { try altered.requireExpected() }
        altered = cancelled(); altered.laterDrainSeconds = 2.1
        try refuses { try altered.requireExpected() }
        // 11
        try changed(.sftpChangedNoHandler).requireExpected()
        altered = changed(.sftpChangedNoHandler); altered.primaryProviderCalls = 0
        try refuses { try altered.requireExpected() }
        // 12
        try positive(.keyKIPositive).requireExpected()
        altered = try positive(.keyKIPositive); altered.ack = false
        try refuses { try altered.requireExpected() }
        altered = try positive(.keyKIPositive); altered.managementResponseReads = 2
        try refuses { try altered.requireExpected() }
        // 13
        try positive(.passwordKIPositive).requireExpected()
        altered = try positive(.passwordKIPositive); altered.exitStatus = 0
        try refuses { try altered.requireExpected() }
        altered = try positive(.passwordKIPositive); altered.serverSessionFileRemoved = false
        try refuses { try altered.requireExpected() }
        // 14
        altered = changed(.nativeChangedNoHandler); altered.descriptorCountAfter = 99
        try refuses { try altered.requireExpected() }
        altered = changed(.nativeChangedNoHandler); altered.ownedTestRootRemoved = false
        try refuses { try altered.requireExpected() }
        let bytes = try JSONEncoder().encode(changed(.nativeChangedNoHandler))
        guard let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { throw NativeFailureCheckError.evidence }
        try require(object["taskID"] as? String == NativeFailureReport.taskIdentifier)
        try require(object["rawHandshakeBytesExposed"] as? Bool == false)
        try require(object["service"] as? String == "keyonly" && object["key"] as? String == "edplain")
        try require(Set(object.keys).isDisjoint(with: ["error", "description", "stderr", "stdout", "payload", "password", "privateKey", "transcript"]))
        // Same fourteenth pure check also verifies R2 diagnostics survive a rejected capture and
        // cannot serialize arbitrary operation text. No live failure is synthesized as success.
        var diagnosticReport = changed(.nativeChangedNoHandler)
        diagnosticReport.typedError = NativeFailureTypedDiagnostic(NativeShellError(.timeout, operation: "handshake", code: -10002))
        diagnosticReport.validationFailure = .nativeChangedCapture
        diagnosticReport.failure = .nativeOrEvidence
        try refuses { try diagnosticReport.requireExpected() }
        let diagnosticBytes = try JSONEncoder().encode(diagnosticReport)
        guard let diagnostic = try JSONSerialization.jsonObject(with: diagnosticBytes) as? [String: Any],
              let typed = diagnostic["typedError"] as? [String: Any] else { throw NativeFailureCheckError.evidence }
        try require(typed["kind"] as? String == "timeout" && typed["operation"] as? String == "handshake")
        try require(typed["code"] as? Int == -10002 && typed["pendingInteractionTasks"] as? Int == 0)
        try require(typed["interactionDrainPresent"] as? Bool == false)
        try require(diagnostic["validationFailure"] as? String == "nativeChangedCapture")
        let unknown = NativeFailureTypedDiagnostic(NativeShellError(.transport, operation: "forbidden-secret-operation"))
        let unknownBytes = try JSONEncoder().encode(unknown)
        try require(unknown.operation == .otherPublicOperation)
        try require(!String(decoding: unknownBytes, as: UTF8.self).contains("forbidden-secret-operation"))
        return names.count
    }
    private static func drained() -> NativeFailureDrain {
        NativeFailureDrain(pending: 0, providers: 0, revoked: true, nativeClosed: true, sealed: true)
    }
    private static func pending() -> NativeFailureDrain {
        NativeFailureDrain(pending: 1, providers: 1, revoked: true, nativeClosed: true, sealed: true)
    }
    private static func base(_ testCase: NativeFailureCase) -> NativeFailureReport {
        var value = NativeFailureReport(testCase: testCase)
        value.sessionAttempts = 1; value.fixedIdentityVerified = true; value.policyVerified = true
        value.freshWithin120Seconds = true; value.activeSeconds = 2; value.cleanupSeconds = 0.1
        value.closeCompleted = true; value.resourcesReturnedToBaseline = true; value.ownedTestRootRemoved = true
        value.publicFixtureKnownHostsUnchanged = true; value.managementChildrenReaped = true
        value.serverSessionFileRemoved = true; value.descriptorCountBefore = 8; value.descriptorCountAfter = 8
        value.childCountBefore = 0; value.childCountAfter = 0; value.processIDBefore = 123; value.processIDAfter = 123
        return value
    }
    private static func changed(_ testCase: NativeFailureCase) -> NativeFailureReport {
        var value = base(testCase)
        value.observation = testCase == .nativeChangedNoHandler ? .nativeUntrusted : .sftpUntrusted
        value.changedEndpointExact = true; value.changedAlgorithmExact = true
        value.expectedFingerprintMatchesSeed = true; value.presentedFingerprintMatchesOutOfBand = true
        value.knownHostsBytesUnchanged = true; value.knownHostsInodeUnchanged = true
        if testCase == .nativeChangedNoHandler {
            value.primaryProviderCalls = 0; value.stages = NativeFailureStages([])
            value.handleFromTypedError = true; value.handleIdentityStable = true; value.afterRelease = drained()
        }
        return value
    }
    private static func cancelled() -> NativeFailureReport {
        var value = base(.nativeCancelledProvider)
        value.observation = .nativeCancelled; value.primaryProviderCalls = 1; value.providerEntered = true
        value.providerReturnedAfterCancellation = true; value.providerFinished = true; value.referencesDroppedBeforeWait = true
        value.providerGateReleasedDuringTeardown = true; value.handleFromTypedError = true; value.handleIdentityStable = true
        value.stages = NativeFailureStages([.advertised(password: false, publicKey: true, keyboardInteractive: false)])
        value.beforeRelease = pending(); value.afterShortWait = pending(); value.afterRelease = drained()
        value.closeAfterCancellationSeconds = 0.55; value.heldAfterCloseSeconds = 0.051; value.laterDrainSeconds = 0.01
        return value
    }
    private static func positive(_ testCase: NativeFailureCase) throws -> NativeFailureReport {
        var value = base(testCase)
        let method: NativeShellPrimaryMethod = testCase == .keyKIPositive ? .publicKey : .password
        let code: Int32 = testCase == .keyKIPositive ? -19 : -18
        let stages: [NativeShellAuthenticationStage] = [
            .advertised(password: method == .password, publicKey: method == .publicKey, keyboardInteractive: true),
            .primaryStarted(method), .primaryResult(method, code: code, authenticated: false),
            .keyboardStarted, .keyboardResult(code: 0, authenticated: true), .authenticated, .shellReady
        ]
        value.authentication = try ShellProbeAuthenticationEvidence(stages: stages, fixture: testCase.fixture)
        value.observation = .positiveShell; value.stages = NativeFailureStages(stages)
        value.ack = true; value.remotePTY = true; value.resized37x113 = true; value.remoteEOF = true
        value.exitStatus = 7; value.inputCalls = 1; value.callbackCount = 4; value.replyCount = 4
        value.managementResponseReads = 3; value.terminalZeroReplies = 1
        return value
    }
}
