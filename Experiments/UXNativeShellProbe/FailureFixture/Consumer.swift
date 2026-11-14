import CNativeFailureResources
import CNativeLivenessTest
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore
import UXNativeFailureSupport
import UXNativeShellProbeSupport

private struct NativeFailureCapture: Sendable {
    let kind: NativeShellError.Kind?
    let diagnostic: NativeFailureTypedDiagnostic?
    let stages: [NativeShellAuthenticationStage]
    let changed: ChangedHostKey?
    let pending: Int
    let handle: NativeShellDrainHandle?
    let unexpectedSession: Bool
}

/// A real PUBLIC consumer. No @testable, internal establish/socket seam, runtime remapping,
/// system trust path, user-selected endpoint/command, or replacement acceptance path.
public enum NativeFailureFixtureConsumer {
    public static func execute(contractPath: String, testCase: NativeFailureCase) async -> Int32 {
        var report = NativeFailureReport(testCase: testCase)
        let gate = NativeFailureProviderGate(), token = CancellationToken(), stop = NativeFailureStop()
        defer { gate.release(); stop.close() }
        var manager: OpenSSHManagement?, callbacks: SFTPAuthCallbacks?, root: NativeFailureRunRoot?
        var trust: HostTrustStore?, publicKnown: NativeFailurePublicFile?
        var watchdog: Task<Void, Never>?
        let started = ProcessInfo.processInfo.systemUptime
        let fullDeadline = started + SFTPAuthContract.fullSeconds
        var activeStart: Double?, cleanupStart: Double?
        do {
            let contract = try await Task.detached { try NativeShellMaterialContract.readPublic(path: contractPath) }.value
            try testCase.validate(service: contract.service.rawValue, key: contract.key.rawValue)
            let approved = NativeFailureBuildContext.identity(for: testCase)
            guard approved.matches(containerID: contract.containerID, fingerprint: contract.expectedFingerprint,
                networkID: contract.networkID, imageID: contract.imageID, project: contract.project,
                context: contract.context, endpoint: contract.endpoint) else { throw NativeFailureCheckError.contract }
            report.fixedIdentityVerified = true
            let management = try OpenSSHManagement(contract: contract.rootManagementIdentity(), deadline: fullDeadline - 12)
            manager = management
            // Exact identity/policy and public provenance are checked BEFORE approved secret files.
            try await Task.detached { try management.verify(); try freshness(contract) }.value
            report.policyVerified = true; report.freshWithin120Seconds = true
            guard !stop.requested, ProcessInfo.processInfo.systemUptime - started <= 28 else {
                throw NativeFailureCheckError.deadline
            }
            let input = try await Task.detached {
                try NativeShellMaterialContract.selectedInput(path: contractPath, contract: contract)
            }.value
            try freshness(contract)
            publicKnown = try NativeFailurePublicFile(contract.credentialDirectory + "/known_hosts")
            let primary: FileAuthentication
            if testCase.fixture.usesKey {
                guard let privateKey = input.privateKey, let publicKey = input.publicKey, input.passphrase == nil else {
                    throw NativeFailureCheckError.contract
                }
                primary = .publicKey(publicKey: publicKey, privateKey: privateKey, passphrase: nil)
            } else {
                guard let password = input.password else { throw NativeFailureCheckError.contract }
                primary = .password(password)
            }
            // Parse public input with the mature system parser; no credential or raw payload logs.
            let actual = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            guard actual.fingerprint == contract.expectedFingerprint else { throw NativeFailureCheckError.contract }
            report.descriptorCountBefore = Int(ns_test_descriptor_count())
            report.childCountBefore = Int(nf_test_child_count()); report.processIDBefore = Int(getpid())
            let owned = try NativeFailureRunRoot(buildRoot: ShellProbeBuildContext.buildRoot)
            root = owned
            let trustPath = owned.path + "/trust"
            let store = try await Task.detached { try HostTrustStore(directory: AbsolutePath(trustPath)) }.value
            trust = store
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(testCase.fixture.port))
            let seed = testCase.changed ? try NativeShellFaultCase.mismatchKey(actual: actual) : actual
            guard case .pending(let pending) = try await store.evaluate(host: host, key: seed) else {
                throw NativeFailureCheckError.evidence
            }
            _ = try await store.confirm(pending, displayedFingerprint: seed.fingerprint)
            let original = try NativeFailurePublicFile(owned.path + "/trust/known_hosts")
            activeStart = ProcessInfo.processInfo.systemUptime
            let activeDeadline = min(activeStart! + testCase.activeLimit, fullDeadline - 12)
            watchdog = Task.detached {
                while !Task.isCancelled {
                    if stop.requested || ProcessInfo.processInfo.systemUptime >= activeDeadline {
                        token.cancel(); gate.release(); management.cancel(); return
                    }
                    do { try await Task.sleep(for: .milliseconds(5)) } catch { return }
                }
            }
            report.sessionAttempts = 1
            switch testCase {
            case .nativeChangedNoHandler:
                try await nativeChanged(primary: primary, store: store, host: host, seed: seed,
                    actual: actual, token: token, report: &report)
            case .nativeCancelledProvider:
                try await cancelledProvider(primary: primary, store: store, host: host, gate: gate,
                    token: token, deadline: activeDeadline, report: &report)
            case .sftpChangedNoHandler:
                try await sftpChanged(primary: primary, store: store, host: host, seed: seed,
                    actual: actual, token: token, report: &report)
            case .keyKIPositive, .passwordKIPositive:
                let owner = try SFTPAuthCallbacks(mfa: true, management: management, token: token)
                callbacks = owner
                // EXACT original finite protocol: same public session, manual fixture KI budget,
                // real ACK/PTY/37x113/EOF/exit7/close. No protocol copy or static shell substitute.
                let result = try await ReleasedShellProbeCase.run(fixture: testCase.fixture, primary: primary,
                    manualKeyboardHandler: { challenge, reply in owner.handle(challenge, reply: reply) },
                    trustStore: store, token: token)
                report.authentication = try ShellProbeAuthenticationEvidence(stages: result.authentication, fixture: testCase.fixture)
                report.stages = NativeFailureStages(result.authentication)
                report.observation = .positiveShell; report.inputCalls = 1
                report.ack = result.ack; report.remotePTY = result.remotePTY; report.resized37x113 = result.resized
                report.remoteEOF = result.remoteEOF; report.exitStatus = result.exit.reportedStatus
                report.exitSignalPresent = result.exit.signal != nil; report.closeCompleted = result.localCloseCompleted
            }
            report.activeSeconds = ProcessInfo.processInfo.systemUptime - activeStart!
            if stop.requested { report.failure = .interrupted }
            else if report.activeSeconds > testCase.activeLimit { report.failure = .activeDeadline }
            let unchanged = try original.compare()
            report.knownHostsBytesUnchanged = unchanged.bytes; report.knownHostsInodeUnchanged = unchanged.inode
        } catch {
            // Keep captured typed facts even when an expectation guard rejects them. All labels
            // below are closed enums; no arbitrary thrown description reaches the report.
            if report.typedError == nil {
                if let typed = error as? NativeShellError { report.typedError = NativeFailureTypedDiagnostic(typed) }
                else if let typed = error as? FileServiceError { report.typedError = NativeFailureTypedDiagnostic(typed) }
            }
            if activeStart != nil {
                report.validationFailure = (error as? NativeFailureValidationFailure) ?? .caseExecution
            }
            report.failure = stop.requested ? .interrupted : (activeStart == nil ? .preparation : .nativeOrEvidence)
            if let activeStart { report.activeSeconds = ProcessInfo.processInfo.systemUptime - activeStart }
        }
        // Every branch releases the deliberate noncooperation BEFORE any cleanup awaits.
        gate.release(); report.providerGateReleasedDuringTeardown = gate.snapshot.3
        watchdog?.cancel(); await watchdog?.value; watchdog = nil
        cleanupStart = ProcessInfo.processInfo.systemUptime
        callbacks?.closeReplies()
        if let callbacks {
            do {
                try await callbacks.drain(); try callbacks.snapshot().requireComplete()
                let budget = callbacks.snapshot()
                report.callbackCount = budget.callbacks; report.replyCount = budget.replies
                report.managementResponseReads = budget.managementReads; report.terminalZeroReplies = budget.terminalZeroReplies
                report.lateReplies = budget.lateReplies; report.managementChildrenReaped = true
                if let session = budget.sessionID, let manager {
                    // Public state-only check; never deletes or edits server challenge material.
                    report.serverSessionFileRemoved = try await Task.detached { try manager.sessionRemoved(session) }.value
                }
            } catch { report.failure = .cleanup }
        } else {
            // verify() is a synchronous bounded owner and reaps its children before returning.
            report.managementChildrenReaped = report.policyVerified
            report.serverSessionFileRemoved = !testCase.positive
        }
        manager?.cancel(); manager = nil
        if let publicKnown {
            do { let unchanged = try publicKnown.compare(); report.publicFixtureKnownHostsUnchanged = unchanged.bytes && unchanged.inode }
            catch { report.failure = .cleanup }
        }
        trust = nil
        // Actor release and the public connection helper's return have happened before observation.
        // owned cleanup is synchronous raw-file cleanup, never FileManager.removeItem recursion.
        if let owned = root {
            do { try owned.cleanup(); report.ownedTestRootRemoved = true }
            catch { report.failure = .cleanup }
        }
        root = nil
        let resourceDeadline = min(ProcessInfo.processInfo.systemUptime + 2, cleanupStart! + 12)
        repeat {
            report.descriptorCountAfter = Int(ns_test_descriptor_count())
            report.childCountAfter = Int(nf_test_child_count()); report.processIDAfter = Int(getpid())
            report.resourcesReturnedToBaseline = report.descriptorCountBefore == report.descriptorCountAfter &&
                report.childCountBefore == report.childCountAfter && report.processIDBefore == report.processIDAfter
            if report.resourcesReturnedToBaseline { break }
            do { try await Task.sleep(for: .milliseconds(10)) } catch { break }
        } while ProcessInfo.processInfo.systemUptime < resourceDeadline
        report.cleanupSeconds = ProcessInfo.processInfo.systemUptime - cleanupStart!
        do { try report.requireExpected(); report.result = "expected-real-public-consumer-facts" }
        catch {
            if report.validationFailure == nil { report.validationFailure = .finalReport }
            if report.failure == nil { report.failure = .validation }
        }
        // Encoding contains only the closed schema; arbitrary caught error descriptions are discarded.
        do { print(String(decoding: try JSONEncoder().encode(report), as: UTF8.self)) }
        catch { fputs("Native failure report encoding refused.\n", stderr); return 1 }
        _ = trust // Explicit ownership boundary; never a second connection or trust source.
        return report.failure == nil ? 0 : 1
    }

    private static func freshness(_ contract: SFTPAuthContract) throws {
        let bytes = try StableFixtureFiles.read(contract.credentialDirectory + "/provenance.json", limit: 4096)
        let object = try MinaJSON.object(bytes, keys: ["base_image", "built_image_id", "service", "collected_at"])
        guard object["base_image"] as? String == contract.baseImage,
              object["built_image_id"] as? String == contract.imageID,
              object["service"] as? String == contract.service.rawValue,
              let collected = object["collected_at"] as? Double else { throw NativeFailureCheckError.contract }
        try NativeFailureFreshness.validate(collectedAt: collected, now: Date().timeIntervalSince1970)
    }
    private static func record(_ changed: ChangedHostKey?, host: HostIdentity, seed: HostPublicKey,
                               actual: HostPublicKey, report: inout NativeFailureReport) {
        guard let changed else { return }
        report.changedEndpointExact = changed.host == host
        report.changedAlgorithmExact = changed.algorithm == actual.algorithm && changed.algorithm == seed.algorithm
        report.expectedFingerprintMatchesSeed = changed.expectedFingerprint == seed.fingerprint
        report.presentedFingerprintMatchesOutOfBand = changed.presentedFingerprint == actual.fingerprint
    }
    private static func options() throws -> NativeShellOptions {
        try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: 10,
            interactionTimeout: 10, authenticationTimeout: 12)
    }
    private static func capture(primary: FileAuthentication, store: HostTrustStore, host: HostIdentity,
                                token: CancellationToken, calls: NativeFailureCallCount,
                                gate: NativeFailureProviderGate? = nil) async -> NativeFailureCapture {
        do {
            let session = try await LibSSH2ShellSession.connect(configuration: SSHConnection(host: host, user: SSHUser("fixture")),
                primaryMethod: .publicKey, primaryProvider: { request in
                    calls.increment(); try request.token.check()
                    if let gate {
                        try await gate.hold()
                        // Intentional test noncooperation: return APPROVED previously prepared in-memory
                        // fixture material after cancellation. Product must discard it, not authenticate.
                        gate.recordReturn(cancelled: request.token.isCancelled)
                    }
                    return primary
                }, trustStore: store, trustHandler: nil, options: options(), connectionTimeout: 3, token: token)
            session.cancel(); await session.close()
            return NativeFailureCapture(kind: nil, diagnostic: nil, stages: await session.authenticationStages(), changed: nil,
                pending: session.interactionSnapshot().pendingTasks, handle: session.interactionDrain, unexpectedSession: true)
        } catch let error as NativeShellError {
            // Copy only immutable facts + canonical read-only handle. No error/session reference
            // escapes this helper or the connect Task; the handle alone outlives the connect owner.
            return NativeFailureCapture(kind: error.kind, diagnostic: NativeFailureTypedDiagnostic(error),
                stages: error.authenticationStages, changed: error.changedHostKey,
                pending: error.pendingInteractionTasks, handle: error.interactionDrain, unexpectedSession: false)
        } catch {
            return NativeFailureCapture(kind: nil, diagnostic: (error as? FileServiceError).map(NativeFailureTypedDiagnostic.init),
                stages: [], changed: nil, pending: 0, handle: nil, unexpectedSession: false)
        }
    }
    private static func nativeChanged(primary: FileAuthentication, store: HostTrustStore, host: HostIdentity,
                                      seed: HostPublicKey, actual: HostPublicKey, token: CancellationToken,
                                      report: inout NativeFailureReport) async throws {
        let calls = NativeFailureCallCount()
        let result = await capture(primary: primary, store: store, host: host, token: token, calls: calls)
        report.primaryProviderCalls = calls.value; report.stages = NativeFailureStages(result.stages)
        report.typedError = result.diagnostic
        record(result.changed, host: host, seed: seed, actual: actual, report: &report)
        guard result.kind == .untrusted, !result.unexpectedSession, let handle = result.handle else {
            throw NativeFailureValidationFailure.nativeChangedCapture
        }
        report.observation = .nativeUntrusted; report.handleFromTypedError = true
        let id = handle.id, final = try await handle.wait(timeout: 2)
        report.afterRelease = NativeFailureDrain(final); report.handleIdentityStable = handle.id == id
        report.closeCompleted = final.nativeClosed && final.producersSealed
    }
    private static func cancelledProvider(primary: FileAuthentication, store: HostTrustStore, host: HostIdentity,
                                          gate: NativeFailureProviderGate, token: CancellationToken,
                                          deadline: Double, report: inout NativeFailureReport) async throws {
        let calls = NativeFailureCallCount()
        var connect: Task<NativeFailureCapture, Never>? = Task.detached {
            await capture(primary: primary, store: store, host: host, token: token, calls: calls, gate: gate)
        }
        // The watchdog releases on every timeout/stop, and the outer teardown always releases too.
        defer { token.cancel(); gate.release(); connect?.cancel() }
        while !gate.entered, !token.isCancelled, ProcessInfo.processInfo.systemUptime < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        guard gate.entered, !token.isCancelled else {
            token.cancel(); gate.release()
            let result = await connect?.value; connect = nil
            report.typedError = result?.diagnostic; report.primaryProviderCalls = calls.value
            if let result { report.stages = NativeFailureStages(result.stages) }
            throw NativeFailureValidationFailure.providerEntry
        }
        report.providerEntered = true
        let cancelledAt = ProcessInfo.processInfo.systemUptime
        token.cancel()
        var result = await connect?.value
        connect = nil // The finished task cannot retain a session/error/other facts across waits.
        report.closeAfterCancellationSeconds = ProcessInfo.processInfo.systemUptime - cancelledAt
        report.primaryProviderCalls = calls.value
        report.stages = NativeFailureStages(result?.stages ?? [])
        report.typedError = result?.diagnostic
        guard result?.kind == .cancelled, result?.unexpectedSession == false,
              let pending = result?.pending, pending > 0, let handle = result?.handle else {
            gate.release(); result = nil; throw NativeFailureValidationFailure.providerCancellationCapture
        }
        report.observation = .nativeCancelled; report.handleFromTypedError = true
        report.beforeRelease = NativeFailureDrain(handle.snapshot)
        let id = handle.id
        result = nil; report.referencesDroppedBeforeWait = true
        let heldAt = ProcessInfo.processInfo.systemUptime
        report.afterShortWait = NativeFailureDrain(try await handle.wait(timeout: 0.05))
        report.heldAfterCloseSeconds = ProcessInfo.processInfo.systemUptime - heldAt
        gate.release()
        let releasedAt = ProcessInfo.processInfo.systemUptime
        report.afterRelease = NativeFailureDrain(try await handle.wait(timeout: 2))
        report.laterDrainSeconds = ProcessInfo.processInfo.systemUptime - releasedAt
        let state = gate.snapshot
        report.providerReturnedAfterCancellation = state.1 && state.2
        report.providerFinished = report.afterRelease?.drained == true && state.1
        report.handleIdentityStable = handle.id == id
        report.closeCompleted = report.afterRelease?.nativeClosed == true && report.afterRelease?.sealed == true
    }
    private static func sftpChanged(primary: FileAuthentication, store: HostTrustStore, host: HostIdentity,
                                    seed: HostPublicKey, actual: HostPublicKey, token: CancellationToken,
                                    report: inout NativeFailureReport) async throws {
        do {
            let service = try await LibSSH2FileService.connect(configuration: SSHConnection(host: host, user: SSHUser("fixture")),
                authentication: [primary], trustStore: store, trustHandler: nil,
                connectionTimeout: 3, operationTimeout: 10, token: token)
            await service.close(); throw NativeFailureValidationFailure.unexpectedSFTPConnection
        } catch let error as FileServiceError {
            report.typedError = NativeFailureTypedDiagnostic(error)
            record(error.changedHostKey, host: host, seed: seed, actual: actual, report: &report)
            guard error.kind == .untrusted else { throw NativeFailureValidationFailure.sftpChangedCapture }
            report.observation = .sftpUntrusted
            // Public connect awaits close before typed failure. FD/child baseline independently
            // checks actual release; do not invent an SFTP drain registry or primary-start count.
            report.closeCompleted = true
        }
    }
}
