import AppKit
import Darwin
import Foundation
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

/// FUTURE LIVE ONLY. Never constructed by help/validate/offline tests/build.
/// Public CredentialStore selects current default file Keychain; UUID service is
/// logical isolation only. No SecItem/default/search-list/ACL/UI bypass is used.
@MainActor enum CredentialStorePublicConsumer {
    static func execute(path: String, fixtureRoot: String, buildRoot: String) async -> Int32 {
        var report: CredentialStorePublicReport?
        var output: String?
        var state = CredentialStorePublicState(namespace: UUID(), referenceID: UUID(), runID: UUID())
        var recovery: CredentialStorePublicRecovery?
        var store: CredentialStore?
        var connectionCleanupDrained = true // No session/provider exists until run starts.
        let stop = StopMonitor(); defer { stop.dispose() }
        let stopGuard = CredentialStorePublicStopGuard(isStopRequested: { stop.requested })
        let deadline = ProcessInfo.processInfo.systemUptime + CredentialStorePublicContract.fullSeconds
        func persist(_ event: String) throws {
            guard let recovery else { throw CredentialStorePublicError.recoveryRecordFailed }
            do { try recovery.persist(event, state: state) }
            catch { state.fail(.recoveryRecordFailed); throw CredentialStorePublicError.recoveryRecordFailed }
        }
        do {
            try stopGuard.check()
            let input = try await Task.detached { try CredentialStorePublicInput.load(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: NSHomeDirectory()) }.value
            try stopGuard.check()
            try PrivateInput.checkDirectory(buildRoot); _ = umask(0o077)
            let run = buildRoot + "/credential-store-live-" + state.runID.uuidString.lowercased()
            guard mkdir(run, 0o700) == 0, mkdir(run + "/trust", 0o700) == 0, mkdir(run + "/sessions", 0o700) == 0 else { throw CredentialStorePublicError.unsafeMaterial }
            output = run + "/result.json"; report = CredentialStorePublicReport(state: state)
            recovery = try CredentialStorePublicRecovery(directory: run, parentDirectory: buildRoot)
            try state.preparedWasDurable()
            try persist("prepared") // MUST be fsynced before store construction or saving.
            report?.preparedRecordDurable = true
            let management = try OpenSSHManagement(contract: input.contract.rootManagementIdentity(), deadline: deadline - 20)
            let watch = Task { @MainActor in
                while !Task.isCancelled {
                    if stop.requested { management.cancel(); return }
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
            }
            do { try await Task.detached { try management.verify() }.value }
            catch { watch.cancel(); await watch.value; throw error }
            watch.cancel(); await watch.value
            try stopGuard.check()
            let publicKey = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            try stopGuard.check()
            guard publicKey.fingerprint == input.contract.expectedFingerprint else { throw CredentialStorePublicError.invalidContract }
            let trust = try await Task.detached { try HostTrustStore(directory: AbsolutePath(run + "/trust")) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22222))
            guard case .pending(let pending) = try await trust.evaluate(host: host, key: publicKey) else { throw CredentialStorePublicError.invalidContract }
            _ = try await trust.confirm(pending, displayedFingerprint: input.contract.expectedFingerprint)
            let reference = OpenLXSSHSecurity.CredentialReference(id: state.referenceID, kind: .password)
            // UUID-only public constructor. It disables/verifies process legacy
            // Keychain interaction via its production coordinator. Any denied,
            // locked, unavailable or UI-required result is failure, not a UI retry.
            let namespace = state.namespace
            try stopGuard.check() // No store-open side effect is admitted after stop.
            store = try await Task.detached { try CredentialStore(testNamespace: namespace) }.value
            // Keep the opened handle for exact close even if stop arrived during await.
            try stopGuard.check()
            guard let currentStore = store, currentStore.service == state.service else { throw CredentialStorePublicError.credentialStoreUnavailable }
            report?.storeOpened = true
            try stopGuard.check()
            guard ProcessInfo.processInfo.systemUptime < deadline - 20 else { throw CredentialStorePublicError.timeout }
            var fixturePassword = try await stopGuard.checkedValue {
                try await Task.detached { try input.fixturePasswordForExplicitSave() }.value
            }
            defer { fixturePassword.resetBytes(in: 0..<fixturePassword.count) }
            try state.beginSave(); try persist("save-attempted")
            try stopGuard.check()
            let saveResult = await currentStore.save(OpenLXSSHSecurity.SecretBytes(fixturePassword), as: reference, authorization: .granted)
            fixturePassword.resetBytes(in: 0..<fixturePassword.count)
            if case .saved(let savedReference) = saveResult {
                guard savedReference == reference else { throw CredentialStorePublicError.ownershipUnconfirmed }
            }
            // A completed .saved result establishes ownership BEFORE honoring a
            // stop that arrived during save; cleanup must not lose the exact item.
            try state.finishSave(CredentialStorePublicStatus.save(saveResult))
            report?.saveConfirmedOwned = state.ownsExactItem
            try persist("save-result")
            try stopGuard.check()
            guard state.ownsExactItem, state.failure == nil else { throw state.failure ?? .ownershipUnconfirmed }
            let configuration = try SSHSessionConfiguration(connection: SSHConnection(host: host, user: SSHUser("fixture")),
                authentication: SSHAuthentication(method: .passwordOnly), connectTimeout: 20, serverAliveInterval: 5, serverAliveCountMax: 1)
            let owner = try CredentialStorePublicOwner(store: currentStore, reference: reference, trust: trust, sessions: run + "/sessions",
                helper: BundledAskpassHelper.discover(), stopGuard: stopGuard)
            guard var currentReport = report else { throw CredentialStorePublicError.invalidContract }
            try stopGuard.check()
            connectionCleanupDrained = false
            await owner.run(configuration: configuration, deadline: deadline - 15, report: &currentReport)
            connectionCleanupDrained = currentReport.closeCompleted && currentReport.ownedPIDReleased && currentReport.providerTasksDrained
            report = currentReport
            if let failure = currentReport.failure { state.fail(failure) }
            try persist("connection-result")
        } catch {
            let stopReason: CredentialStorePublicError?
            do { try stopGuard.check(); stopReason = nil } catch { stopReason = .cancelled }
            let reason = stopReason ?? CredentialStorePublicErrorMap.classify(error, fallback: .invalidContract)
            state.fail(reason); report?.failure = reason
            if let typed = error as? CredentialFailure {
                let mapped = CredentialStorePublicStatus.failure(typed); state.recordCredentialFailure(mapped); report?.credentialFailure = mapped
            }
        }
        // Cleanup is limited to this process's EXPLICIT .saved result. A duplicate,
        // failed/unconfirmed save or any prior prepared receipt is NEVER adopted.
        if let store {
            let reference = OpenLXSSHSecurity.CredentialReference(id: state.referenceID, kind: .password)
            if state.mayAttemptExactDelete && connectionCleanupDrained {
                do {
                    try state.beginExactDelete(); report?.deleteAttempted = true
                    // Keep attempting exact owned cleanup even if a later receipt
                    // cannot be written; the durable prepared ID remains evidence.
                    do { try persist("delete-attempted") } catch { report?.failure = .recoveryRecordFailed }
                    let outcome = await store.deleteExact(reference)
                    try state.finishDelete(CredentialStorePublicStatus.delete(outcome))
                    report?.exactDeleteConfirmed = !state.ownsExactItem
                    do { try persist("delete-result") } catch { report?.failure = .recoveryRecordFailed }
                    if state.phase == .deleted {
                        let result = await store.read(reference)
                        let missing: Bool
                        if case .missing = result { missing = true } else { missing = false }
                        if case .manualEntryRequired(let reason) = result { state.recordCredentialFailure(CredentialStorePublicStatus.failure(reason)) }
                        try state.recordMissing(missing); report?.postForgetReadMissing = missing
                        do { try persist("missing-result") } catch { report?.failure = .recoveryRecordFailed }
                    }
                } catch { state.fail((error as? CredentialStorePublicError) ?? .cleanupIncomplete); report?.failure = (error as? CredentialStorePublicError) ?? .cleanupIncomplete }
            }
            if state.ownsExactItem && !connectionCleanupDrained {
                state.fail(.cleanupIncomplete); report?.failure = .cleanupIncomplete
                try? persist("failed") // Retain owned receipt, never race a live provider with deletion.
            }
            do {
                try await store.close(); state.recordClose(restored: true); report?.storeCloseRestoredInteraction = true
            } catch {
                state.recordClose(restored: false); report?.failure = .interactionRestoreFailed
                if let reason = error as? CredentialFailure { state.recordCredentialFailure(CredentialStorePublicStatus.failure(reason)) }
            }
            do { try persist("store-closed") } catch { report?.failure = .recoveryRecordFailed }
        }
        if let failure = state.failure, report?.failure == nil { report?.failure = failure }
        if let reason = state.credentialFailure { report?.credentialFailure = reason }
        do {
            try stopGuard.check()
            try state.requireSuccessfulLifecycle()
            guard report?.connectedEvents == 1, report?.providerCalls == 1, report?.providerReadCount == 1, report?.providerReturns == 1,
                  report?.manualRequests == 0, report?.productionGateExercised == true, report?.closeCompleted == true,
                  report?.ownedPIDReleased == true, report?.providerTasksDrained == true, report?.failure == nil else { throw CredentialStorePublicError.connectionFailed }
            try stopGuard.check()
            report?.lifecycleVerified = true; report?.result = "expected-public-credential-save-provider-forget"
        } catch {
            let reason = CredentialStorePublicErrorMap.classify(error, fallback: .cleanupIncomplete)
            if reason == .cancelled || report?.failure == nil { report?.failure = reason }
        }
        if report?.failure != nil { report?.result = "failed"; try? persist("failed") }
        guard let report, let output else { fputs("Credential public fixture refused; no captured details emitted.\n", stderr); return 1 }
        do {
            let data = try JSONEncoder().encode(report); try PrivateInput.writeExclusive(data + Data([10]), to: output)
            print(String(decoding: data, as: UTF8.self))
        } catch { fputs("Credential public recovery/result write failed; retain exact run for review.\n", stderr); return 1 }
        return report.failure == nil ? 0 : 1
    }
}
