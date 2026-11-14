import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore
import UXNativeShellProbeSupport

struct NativeShellMaterialContract {
    static let keys: Set<String> = ["schema", "taskID", "service", "host", "port", "user", "key", "credentialDirectory",
        "expectedFingerprint", "baseImage", "imageID", "containerID", "project", "networkID", "context", "endpoint"]
    static func decode(_ data: Data, path: String, buildRoot: String, fixtureRoot: String, home: String) throws -> SFTPAuthContract {
        _ = try MinaJSON.object(data, keys: keys)
        let value = try JSONDecoder().decode(SFTPAuthContract.self, from: data)
        try value.validate(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: home)
        return value
    }
    static func readPublic(path: String) throws -> SFTPAuthContract {
        try ShellProbeCommand.checkContractPath(path, buildRoot: ShellProbeBuildContext.buildRoot)
        try StableFixtureFiles.checkMarker(directory: ShellProbeBuildContext.buildRoot,
            file: ".native-shell-probe-owner", expected: "OpenLXSSH-U0-NativeShellProbe-v1\n")
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        try StableFixtureFiles.checkMarker(directory: parent, file: ".native-shell-case-owner", expected: "U0-NATIVE-SHELL-LIVE-A\n")
        return try decode(StableFixtureFiles.read(path, limit: 8192), path: path, buildRoot: ShellProbeBuildContext.buildRoot,
            fixtureRoot: ShellProbeBuildContext.fixtureRoot, home: NSHomeDirectory())
    }
    static func selectedInput(path: String, contract: SFTPAuthContract) throws -> SFTPAuthInput {
        // Mature SFTPAuthInput enforces exact generation, state/provenance, fingerprint and selected
        // material names. It is used as a MATERIAL reader only, never as old SFTP success evidence.
        let held = try StableFixtureFiles.holdSelectedInput(contract, path: path, fixtureRoot: ShellProbeBuildContext.fixtureRoot)
        let input = try SFTPAuthInput.load(path: path, buildRoot: ShellProbeBuildContext.buildRoot,
            fixtureRoot: ShellProbeBuildContext.fixtureRoot, home: NSHomeDirectory())
        let original = try JSONEncoder().encode(contract), reread = try JSONEncoder().encode(input.contract)
        // Encoder key ordering is not stable; compare typed JSON objects rather than encoded bytes.
        guard try JSONSerialization.jsonObject(with: original) as? NSDictionary ==
                  JSONSerialization.jsonObject(with: reread) as? NSDictionary else { throw SFTPAuthError.provenanceMismatch }
        // Compare each returned selected material with a separately stable bounded descriptor read.
        // No secret metadata/hash or content is emitted, nor handed to argv/env/files.
        func matches(_ value: Data?, file: String, limit: Int, line: Bool = false) throws {
            guard let value else { throw SFTPAuthError.unsafeMaterial }
            var raw = try StableFixtureFiles.read(contract.credentialDirectory + "/" + file, limit: limit)
            defer { raw.resetBytes(in: 0..<raw.count) }
            let expected = line ? try PrivateInput.secretLine(raw) : raw
            guard value == expected else { throw SFTPAuthError.unsafeMaterial }
        }
        if let key = contract.key.file {
            try matches(input.privateKey, file: key, limit: 32768)
            try matches(input.publicKey, file: key + ".pub", limit: 4096)
            if contract.key.encrypted { try matches(input.passphrase, file: "key-passphrase.txt", limit: 1024, line: true) }
        } else { try matches(input.password, file: "password.txt", limit: 1024, line: true) }
        try held.check()
        return input
    }
}

/// Minimal bounded signal owner adapted from the reviewed StopMonitor. Instantiated ONLY after
/// live flags and marked contract validation. It never runs on inert help/validate paths.
private final class NativeShellStopMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    private var sources: [DispatchSourceSignal] = []
    var requested: Bool { lock.withLock { stopped } }
    init() {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global(qos: .userInitiated))
            source.setEventHandler { [weak self] in self?.mark() }
            source.resume(); sources.append(source)
        }
    }
    private func mark() { lock.withLock { stopped = true } }
    func dispose() { sources.forEach { $0.cancel() }; sources.removeAll() }
}
private final class NativeShellDeadline: @unchecked Sendable {
    private let lock = NSLock()
    private var expired = false
    var timedOut: Bool { lock.withLock { expired } }
    func mark() { lock.withLock { expired = true } }
}
private final class NativeShellStageBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: [NativeShellAuthenticationStage] = []
    func store(_ stages: [NativeShellAuthenticationStage]) { lock.withLock { value = stages } }
    func snapshot() -> [NativeShellAuthenticationStage] { lock.withLock { value } }
}
private struct NativeShellLiveReport: Encodable {
    let taskID: String
    let inputMaterialSchema = "REAL-SFTP-COMBINED-AUTH-A (material only)"
    let callbackContract = "test-only-root-pam-three-secrets-terminal-zero-v1"
    let testOnly = true
    let productAcceptance = false
    let minimumOS = "26.0"
    let helperUsed = false
    let signatureIdentityGateRequired = false // No signed helper/IPC; not a same-Team claim.
    let service: String
    let key: String
    let testCase: String
    let sessionAttemptLimit = 1
    var sessionAttempts = 0
    var policyVerified = false
    var primaryStarted = 0
    var primaryResults = 0
    var keyboardStarted = 0
    var keyboardResults = 0
    var authenticatedEvents = 0
    var shellReadyEvents = 0
    var authentication: ShellProbeAuthenticationEvidence?
    var faultFacts: ShellProbeAttemptFacts?
    var primaryProviderCalls = 0
    var pendingInteractionTasks = 0
    var deliberatelyMutatedPrimary = false
    var changedHostKeyRejected = false
    var firstChallengeValidated = false
    var cancellationRequested = false
    var inputCalls = 0
    var expectedNegative = false
    var callbackCount = 0
    var replyCount = 0
    var secretResponseCount = 0
    var managementResponseReads = 0
    var terminalZeroReplyCount = 0
    var lateReplyCount = 0
    var ack = false
    var remotePTY = false
    var resized37x113 = false
    var remoteEOF = false
    var exitStatus: Int32?
    var exitSignalPresent = false
    var closeCompleted = false
    var managementChildrenReaped = false
    var serverSessionFileRemoved = false
    var failure: String?
    var validationFailure: String?
    var nativeErrorKind: String?
    var nativeCode: Int32?
    var result = "failed"
    mutating func recordStages(_ stages: [NativeShellAuthenticationStage]) {
        for stage in stages {
            switch stage {
            case .primaryStarted: primaryStarted += 1
            case .primaryResult: primaryResults += 1
            case .keyboardStarted: keyboardStarted += 1
            case .keyboardResult: keyboardResults += 1
            case .authenticated: authenticatedEvents += 1
            case .shellReady: shellReadyEvents += 1
            case .advertised: break
            }
        }
    }
    mutating func record(_ budget: SFTPAuthBudget) {
        callbackCount = budget.callbacks; replyCount = budget.replies; secretResponseCount = budget.secretResponses
        managementResponseReads = budget.managementReads; terminalZeroReplyCount = budget.terminalZeroReplies
        lateReplyCount = budget.lateReplies
    }
}

public enum NativeShellFixtureConsumer {
    /// Called only by a separately compiled test artifact, with all three explicit authorization
    /// flags. One selected fixed fixture/session; no discovery/reconnect/fallback/loop/parallelism.
    public static func execute(contractPath: String, testCase: ShellProbeCase = .positive) async -> Int32 {
        var report: NativeShellLiveReport?
        do {
            let started = ProcessInfo.processInfo.systemUptime
            let fullDeadline = started + SFTPAuthContract.fullSeconds // Original 85, not expanded to 180.
            let contract = try await Task.detached { try NativeShellMaterialContract.readPublic(path: contractPath) }.value
            guard let fixture = ShellProbeFixture(rawValue: contract.service.rawValue) else { throw SFTPAuthError.invalidContract }
            try testCase.validate(fixture: fixture, key: contract.key.rawValue)
            report = NativeShellLiveReport(taskID: testCase == .positive ? "NATIVE-READINESS-R1-POSITIVE" : "NATIVE-READINESS-R1-" + testCase.rawValue,
                service: fixture.rawValue, key: contract.key.rawValue, testCase: testCase.rawValue)
            let stop = NativeShellStopMonitor(); defer { stop.dispose() }
            let token = CancellationToken(), expired = NativeShellDeadline()
            let management = try OpenSSHManagement(contract: contract.rootManagementIdentity(),
                deadline: fullDeadline - SFTPAuthContract.drainSeconds)
            let watchdog = Task.detached {
                while !Task.isCancelled {
                    if stop.requested || ProcessInfo.processInfo.systemUptime >= fullDeadline - SFTPAuthContract.drainSeconds {
                        if !stop.requested { expired.mark() }
                        token.cancel(); management.cancel(); return
                    }
                    do { try await Task.sleep(for: .milliseconds(20)) } catch { return }
                }
            }
            var owner: SFTPAuthCallbacks?
            var faultOwner: NativeShellFaultCallbacks?
            var faultNative: NativeShellFaultResult?
            let stageBox = NativeShellStageBox()
            do {
                // Verify exact context endpoint/container/image/internal-network/readonly policy BEFORE
                // opening selected disposable password/private-key files. No system keyscan.
                try await Task.detached { try management.verify() }.value
                report?.policyVerified = true
                try token.check()
                let input = try await Task.detached { try NativeShellMaterialContract.selectedInput(path: contractPath, contract: contract) }.value
                try token.check()
                let run = ShellProbeBuildContext.buildRoot + "/native-shell-live-" + UUID().uuidString.lowercased()
                guard mkdir(run, 0o700) == 0 else { throw SFTPAuthError.unsafeMaterial }
                let trust = try await Task.detached { try HostTrustStore(directory: AbsolutePath(run + "/trust")) }.value
                let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(fixture.port))
                let hostKey = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
                guard hostKey.fingerprint == contract.expectedFingerprint,
                      case .pending(let pending) = try await trust.evaluate(host: host, key: hostKey) else {
                    throw SFTPAuthError.fingerprintMismatch
                }
                let trustedKey = testCase == .hostkeyMismatch ? try NativeShellFaultCase.mismatchKey(actual: hostKey) : hostKey
                guard case .pending(let selected) = try await trust.evaluate(host: host, key: trustedKey) else {
                    throw SFTPAuthError.integrity
                }
                await trust.cancel(pending)
                _ = try await trust.confirm(selected, displayedFingerprint: trustedKey.fingerprint)
                if testCase.isNegative {
                    let callbacks = try NativeShellFaultCallbacks(testCase: testCase, token: token)
                    faultOwner = callbacks
                    let activeWatch = Task.detached {
                        do { try await Task.sleep(for: .seconds(SFTPAuthContract.activeSeconds)) }
                        catch { return }
                        expired.mark(); token.cancel()
                    }
                    defer { activeWatch.cancel() }
                    guard let password = input.password else { throw SFTPAuthError.invalidContract }
                    let selectedPassword = testCase == .wrongPrimary ? try ShellProbeCase.wrongPrimary(password) : password
                    report?.deliberatelyMutatedPrimary = testCase == .wrongPrimary
                    report?.sessionAttempts = 1
                    let observation = NativeShellChangedKeyObservation()
                    let result = try await NativeShellFaultCase.run(testCase: testCase, fixture: fixture,
                        primary: .password(selectedPassword), trust: trust, changedKey: observation,
                        callbacks: callbacks, token: token)
                    activeWatch.cancel(); await activeWatch.value
                    faultNative = result
                    report?.recordStages(result.stages)
                    report?.faultFacts = try ShellProbeAttemptFacts(stages: result.stages)
                    report?.nativeErrorKind = result.kind?.rawValue; report?.nativeCode = result.code
                    report?.primaryProviderCalls = result.providerCalls; report?.pendingInteractionTasks = result.pendingInteractionTasks
                    report?.changedHostKeyRejected = observation.exactChangedRejection
                    report?.closeCompleted = result.closed
                    report?.cancellationRequested = token.isCancelled
                    report?.expectedNegative = true
                } else {
                let callbacks = try SFTPAuthCallbacks(mfa: contract.service.mfa, management: management, token: token)
                owner = callbacks
                let activeWatch = Task.detached {
                    do { try await Task.sleep(for: .seconds(SFTPAuthContract.activeSeconds)) }
                    catch { return }
                    expired.mark(); callbacks.cancel(.timeout)
                }
                do {
                    let primary: FileAuthentication
                    if let privateKey = input.privateKey {
                        primary = .publicKey(publicKey: input.publicKey, privateKey: privateKey, passphrase: input.passphrase)
                    } else if let password = input.password { primary = .password(password) }
                    else { throw SFTPAuthError.invalidContract }
                    // Pass the exact test-only handler even for non-MFA, so an unexpected challenge
                    // is rejected by the no-callback budget; no unknown challenge is auto-answered.
                    report?.sessionAttempts = 1
                    let result = try await ReleasedShellProbeCase.run(fixture: fixture, primary: primary,
                        manualKeyboardHandler: { challenge, reply in callbacks.handle(challenge, reply: reply) },
                        trustStore: trust, token: token, recordAuthenticatedStages: { stageBox.store($0) })
                    report?.recordStages(result.authentication)
                    report?.authentication = try ShellProbeAuthenticationEvidence(stages: result.authentication, fixture: fixture)
                    report?.ack = result.ack; report?.remotePTY = result.remotePTY; report?.resized37x113 = result.resized
                    report?.remoteEOF = result.remoteEOF; report?.exitStatus = result.exit.reportedStatus
                    report?.exitSignalPresent = result.exit.signal != nil; report?.closeCompleted = result.localCloseCompleted
                    callbacks.closeReplies(); try await callbacks.drain(); try callbacks.snapshot().requireComplete()
                } catch {
                    activeWatch.cancel(); await activeWatch.value
                    throw error
                }
                activeWatch.cancel(); await activeWatch.value
                }
            } catch let error as NativeShellError {
                report?.recordStages(stageBox.snapshot().isEmpty ? error.authenticationStages : stageBox.snapshot())
                report?.nativeErrorKind = error.kind.rawValue; report?.nativeCode = error.code
                report?.pendingInteractionTasks = error.pendingInteractionTasks
                report?.failure = stop.requested ? "cancelled" : (expired.timedOut ? "timeout" : "native-" + error.kind.rawValue)
                report?.closeCompleted = true // Public connect/finitecase error paths explicitly await close.
            } catch let error as SFTPAuthError {
                if report?.primaryStarted == 0 { report?.recordStages(stageBox.snapshot()) }
                report?.failure = error.rawValue
            } catch {
                if report?.primaryStarted == 0 { report?.recordStages(stageBox.snapshot()) }
                report?.failure = stop.requested ? "cancelled" : (expired.timedOut ? "timeout" : "fixture-or-evidence-failed")
            }
            watchdog.cancel(); await watchdog.value
            owner?.closeReplies()
            if let owner {
                do { try await owner.drain(); report?.managementChildrenReaped = true }
                catch { report?.failure = "cleanupIncomplete" }
                let budget = owner.snapshot(); report?.record(budget)
                if let failure = budget.failure { report?.failure = failure.rawValue }
                if let session = budget.sessionID {
                    do {
                        // Fresh bounded manager for cleanup because cancellation of the active manager
                        // is terminal. Does not start a second SSH connection or read another response.
                        let cleanup = try OpenSSHManagement(contract: contract.rootManagementIdentity(), deadline: fullDeadline)
                        report?.serverSessionFileRemoved = try await Task.detached { try cleanup.sessionRemoved(session) }.value
                    } catch { report?.failure = "cleanupIncomplete" }
                } else { report?.serverSessionFileRemoved = !contract.service.mfa }
            }
            if let faultOwner {
                faultOwner.close()
                do { try await faultOwner.drain(); report?.managementChildrenReaped = true }
                catch { report?.failure = "cleanupIncomplete" }
                let snapshot = faultOwner.snapshot()
                report?.callbackCount = snapshot.callbacks; report?.replyCount = snapshot.replies
                report?.firstChallengeValidated = snapshot.firstChallengeValidated
                if let failure = snapshot.failure { report?.failure = failure.rawValue }
                if let session = snapshot.sessionID {
                    do {
                        let cleanup = try OpenSSHManagement(contract: contract.rootManagementIdentity(), deadline: fullDeadline)
                        report?.serverSessionFileRemoved = try await Task.detached { try cleanup.sessionRemoved(session) }.value
                    } catch { report?.failure = "cleanupIncomplete" }
                } else { report?.serverSessionFileRemoved = !contract.service.mfa }
            }
            management.cancel()
            guard var final = report else { throw SFTPAuthError.invalidContract }
            var validationStage = "negative-preconditions"
            do {
            if final.failure == nil, testCase.isNegative {
                guard final.policyVerified, final.sessionAttempts == 1, final.managementChildrenReaped,
                      final.serverSessionFileRemoved, let facts = final.faultFacts, let native = faultNative,
                      !native.returnedUnexpectedShell, native.pendingInteractionTasks == 0,
                      native.providerCalls == (testCase == .hostkeyMismatch ? 0 : 1) else { throw SFTPAuthError.integrity }
                validationStage = "negative-facts"
                try facts.requireExpected(testCase, nativeKind: native.kind, nativeCode: native.code,
                    cancelled: final.cancellationRequested, changedKeyRejected: final.changedHostKeyRejected,
                    firstChallengeValidated: final.firstChallengeValidated, callbackCount: final.callbackCount,
                    replies: final.replyCount, managementReads: final.managementResponseReads, inputCalls: final.inputCalls,
                    closeCompleted: final.closeCompleted, timedOut: expired.timedOut, stopped: stop.requested)
                final.result = "expected-native-negative-" + testCase.rawValue
            } else if final.failure == nil {
                validationStage = "positive-evidence"
                guard final.policyVerified, final.primaryStarted == 1, final.primaryResults == 1,
                      final.shellReadyEvents == 1, final.authenticatedEvents == 1, final.ack, final.remotePTY,
                      final.resized37x113, final.remoteEOF, final.exitStatus == 7, !final.exitSignalPresent,
                      final.closeCompleted, final.managementChildrenReaped, final.serverSessionFileRemoved else {
                    throw SFTPAuthError.integrity
                }
                final.result = "expected-native-shell-pty-resize-exit"
            }
            } catch {
                // Keep original typed/fault/cleanup facts, even when strict validation fails.
                // Static stage only: never serialize arbitrary error text, prompts or material.
                final.validationFailure = validationStage
                if final.failure == nil { final.failure = "validationFailure" }
                final.result = "failed-validation"
            }
            let data = try JSONEncoder().encode(final)
            print(String(decoding: data, as: UTF8.self))
            return final.failure == nil ? 0 : 1
        } catch {
            // Never stringify arbitrary errors, prompt text, material, paths or management stdout.
            fputs("Native shell fixture refused; no captured details emitted.\n", stderr)
            return 1
        }
    }
}
