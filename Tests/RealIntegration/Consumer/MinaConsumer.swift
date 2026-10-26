import AppKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTransport
import OpenLXSSHTrust
import RealIntegrationCore

/// Serializes the single typed callback/reply and stops any late result before
/// it can resolve. Not a generic KBI responder and not App saved-secret logic.
final class MinaCallbackOwner: @unchecked Sendable {
    private let lock = NSLock()
    private var budget: MinaCallbackBudget
    private var asyncEvidence = MinaAsyncEvidence()
    private var activeHandlers = 0
    private let management: MinaManagement
    private let token: CancellationToken
    init(testCase: MinaCase, management: MinaManagement, token: CancellationToken) throws {
        budget = try MinaCallbackBudget(testCase: testCase, start: ProcessInfo.processInfo.systemUptime)
        self.management = management; self.token = token
    }
    func handle(_ challenge: KeyboardChallenge, reply: ChallengeReply<[Data]>) {
        lock.lock(); activeHandlers += 1; lock.unlock()
        defer { lock.lock(); activeHandlers -= 1; lock.unlock() }
        do {
            lock.lock()
            let attempt: String
            do {
                attempt = try budget.claim(name: challenge.name, instruction: challenge.instruction,
                    prompts: challenge.prompts.map { $0.bytes }, echo: challenge.prompts.map { $0.echo }, now: ProcessInfo.processInfo.systemUptime)
                if budget.testCase == .twoCorrect { try budget.claimManagementRead() }
                lock.unlock()
            } catch { lock.unlock(); throw error }
            let values = challenge.prompts.isEmpty ? [] : try management.responses(attempt: attempt).values
            lock.lock()
            do {
                try token.check()
                let beforeResolve = ProcessInfo.processInfo.systemUptime
                try budget.claimReply(responseCount: values.count, now: beforeResolve)
                let resolved = reply.resolve(values) // Lock makes close/reply ordering explicit.
                budget.resolved(resolved)
                if resolved, budget.testCase.isAsync { try asyncEvidence.recordReply(at: beforeResolve) }
                lock.unlock()
            } catch { lock.unlock(); throw error }
        } catch {
            lock.lock(); budget.fail((error as? MinaError) ?? .cancelled); lock.unlock()
            token.cancel(); management.cancel() // Never send dummy/partial/empty answers on refusal.
        }
    }
    func cancel(_ reason: MinaError) {
        lock.lock(); budget.fail(reason); budget.close(); lock.unlock()
        token.cancel(); management.cancel()
    }
    func evidenceSnapshot() -> MinaAsyncEvidence {
        lock.lock(); defer { lock.unlock() }; return asyncEvidence
    }
    func policyVerified() { lock.lock(); asyncEvidence.recordPolicyVerified(); lock.unlock() }
    func backendReturned() throws {
        lock.lock(); defer { lock.unlock() }
        try asyncEvidence.recordBackend(at: ProcessInfo.processInfo.systemUptime)
    }
    func recordPending(_ status: MinaStatus, before: MinaStatus, attempt: String) throws {
        lock.lock(); defer { lock.unlock() }
        try asyncEvidence.recordPending(status, before: before, attempt: attempt, now: ProcessInfo.processInfo.systemUptime)
    }
    func cancelExpectedWait() throws {
        lock.lock(); defer { lock.unlock() }
        guard budget.failure == nil, budget.replyCount == 1 else { throw MinaError.statusMismatch }
        try asyncEvidence.recordCancellation(at: ProcessInfo.processInfo.systemUptime)
        budget.close()
        token.cancel(); management.cancel() // Expected local cancellation is not a budget failure.
    }
    func attemptSnapshot() -> String? { lock.lock(); defer { lock.unlock() }; return budget.attemptID }
    func beginCase() throws {
        lock.lock(); defer { lock.unlock() }
        try token.check()
        if let failure = budget.failure { throw failure }
        budget = try MinaCallbackBudget(testCase: budget.testCase, start: ProcessInfo.processInfo.systemUptime)
    }
    func isDrained() -> Bool {
        lock.lock(); defer { lock.unlock() }; return activeHandlers == 0
    }
    func closeReplies() { lock.lock(); budget.close(); lock.unlock() }
    func snapshotAndClose() -> MinaCallbackBudget {
        lock.lock(); defer { lock.unlock() }; budget.close(); return budget
    }
    func drain() async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + MinaContract.drainSeconds
        for _ in 0..<600 {
            if isDrained() { return }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw MinaError.cleanupIncomplete }
            try await Task.sleep(for: .milliseconds(20))
        }
        throw MinaError.cleanupIncomplete
    }
}

@MainActor enum MinaConsumer {
    static func execute(path: String, fixtureRoot: String, buildRoot: String) async -> Int32 {
        var report: MinaReport?, output: String?
        do {
            let input = try await Task.detached { try MinaInput.load(path: path, buildRoot: buildRoot, fixtureRoot: fixtureRoot, home: NSHomeDirectory()) }.value
            report = MinaReport(testCase: input.contract.testCase)
            try PrivateInput.checkDirectory(buildRoot)
            _ = umask(0o077)
            let run = buildRoot + "/mina-live-" + UUID().uuidString.lowercased()
            guard mkdir(run, 0o700) == 0, mkdir(run + "/trust", 0o700) == 0 else { throw MinaError.unsafeMaterial }
            output = run + "/result.json"
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            guard key.algorithm == "ssh-rsa", key.fingerprint == input.contract.expectedFingerprint else { throw MinaError.fingerprintMismatch }
            let trust = try await Task.detached { try HostTrustStore(directory: AbsolutePath(run + "/trust")) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22225))
            guard case .pending(let pending) = try await trust.evaluate(host: host, key: key) else { throw MinaError.invalidContract }
            _ = try await trust.confirm(pending, displayedFingerprint: input.contract.expectedFingerprint)
            let management = try MinaManagement(contract: input.contract)
            let token = CancellationToken(), stop = StopMonitor()
            defer { stop.dispose() }
            let owner = try MinaCallbackOwner(testCase: input.contract.testCase, management: management, token: token)
            let preparationWatch = Task { @MainActor in
                while !Task.isCancelled {
                    if stop.requested { owner.cancel(.cancelled); return }
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
            }
            do {
                try await Task.detached { try management.verify() }.value
                if input.contract.testCase.isAsync {
                    try await Task.detached { try management.verifyPolicy() }.value
                    owner.policyVerified()
                }
                let before = try await Task.detached { try management.status() }.value
                try before.requireIdle(); report?.before = before
                preparationWatch.cancel(); await preparationWatch.value
                try owner.beginCase()
                let start = ProcessInfo.processInfo.systemUptime
                let watchdog = Task { @MainActor in
                    while !Task.isCancelled {
                        if stop.requested { owner.cancel(.cancelled); return }
                        if ProcessInfo.processInfo.systemUptime >= start + MinaContract.caseSeconds { owner.cancel(.timeout); return }
                        do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                    }
                }
                // A separate read-only owner remains usable after the connection
                // owner is cancelled; no response bytes ever pass through it.
                let statusManagement = input.contract.testCase == .cancelWait ? try MinaManagement(contract: input.contract) : management
                let cancelTask: Task<Void, Error>? = input.contract.testCase == .cancelWait ? Task { @MainActor in
                    var reply: Double?
                    for _ in 0..<600 {
                        try Task.checkCancellation()
                        if let time = owner.evidenceSnapshot().replyAt { reply = time; break }
                        guard ProcessInfo.processInfo.systemUptime < start + MinaContract.caseSeconds else { throw MinaError.timeout }
                        try await Task.sleep(for: .milliseconds(50))
                    }
                    guard let reply, let attempt = owner.attemptSnapshot() else { throw MinaError.statusMismatch }
                    let deadline = reply + MinaContract.providerDelaySeconds
                    var found = false
                    for _ in 0..<3 {
                        try Task.checkCancellation()
                        let current = try await Task.detached { try statusManagement.status(deadline: deadline) }.value
                        if (try? current.requireRespondedCancellation(attempt: attempt, before: before)) != nil {
                            try owner.recordPending(current, before: before, attempt: attempt); found = true; break
                        }
                        guard ProcessInfo.processInfo.systemUptime + 0.2 < deadline else { break }
                        try await Task.sleep(for: .milliseconds(100))
                    }
                    guard found else { throw MinaError.statusMismatch }
                    while ProcessInfo.processInfo.systemUptime < reply + MinaContract.cancelAfterReplySeconds {
                        try Task.checkCancellation(); try await Task.sleep(for: .milliseconds(20))
                    }
                    try owner.cancelExpectedWait()
                } : nil
                var observation = MinaBackendObservation.unexpectedFailure
                do {
                    let connection = SSHConnection(host: host, user: try SSHUser("fixture"))
                    let service = try await LibSSH2FileService.connect(configuration: connection,
                        authentication: [.keyboardInteractive { challenge, reply in owner.handle(challenge, reply: reply) }],
                        trustStore: trust, trustHandler: { _, reply in owner.cancel(.unknownTrust); reply.resolve(.reject) },
                        connectionTimeout: MinaContract.connectionSeconds, operationTimeout: MinaContract.operationSeconds, token: token)
                    service.cancel(); await service.close()
                    observation = .unexpectedSuccess // MINA deliberately has NO SFTP subsystem.
                    report?.closeCompleted = true
                } catch let error as FileServiceError {
                    observation = MinaBackendObservation.classify(kind: error.kind.rawValue, operation: error.operation, code: error.code)
                    report?.closeCompleted = true // Public connect's error path awaits close.
                } catch { observation = .unexpectedFailure }
                if input.contract.testCase.isAsync, owner.evidenceSnapshot().replyAt != nil { try owner.backendReturned() }
                watchdog.cancel(); await watchdog.value
                report?.backend = observation
                if input.contract.testCase.isAsync { report?.asyncEvidence = owner.evidenceSnapshot() }
                if let cancelTask {
                    if owner.evidenceSnapshot().cancelRequestedAt == nil { cancelTask.cancel(); statusManagement.cancel() }
                    do { try await cancelTask.value }
                    catch { throw (error as? MinaError) ?? MinaError.statusMismatch }
                }
                owner.closeReplies()
                try await owner.drain()
                let budget = owner.snapshotAndClose(); report?.record(budget); report?.backend = observation
                if input.contract.testCase.isAsync { report?.asyncEvidence = owner.evidenceSnapshot() }
                try budget.requireComplete(); try observation.requireExpected(input.contract.testCase)
                // Only after native close and the single callback has returned. Fixed
                // status reads contain counters, never response values or prompts.
                var after: MinaStatus?
                let statusDeadline = ProcessInfo.processInfo.systemUptime + MinaContract.drainSeconds
                for _ in 0..<4 {
                    let current = try await Task.detached { try statusManagement.status(deadline: statusDeadline) }.value
                    if current.sessions == 0 && current.scheduler_queue == 0 && current.pending.isEmpty { after = current; break }
                    guard ProcessInfo.processInfo.systemUptime + 0.2 < statusDeadline else { break }
                    try await Task.sleep(for: .milliseconds(100))
                }
                guard let after else { throw MinaError.statusMismatch }
                report?.after = after
                try after.requireExactDelta(from: before, testCase: input.contract.testCase)
                if input.contract.testCase.isAsync {
                    var timing = owner.evidenceSnapshot()
                    if input.contract.testCase == .cancelWait {
                        guard let pendingAt = timing.pendingObservedAt else { throw MinaError.statusMismatch }
                        // The timer is scheduled before pending.responded=true is
                        // published. Waiting 8s AFTER observing that state passes
                        // the original decision due conservatively, not just reply+8.
                        let postDue = pendingAt + MinaContract.providerDelaySeconds
                        let bound = postDue + MinaContract.drainSeconds
                        for _ in 0..<400 {
                            if ProcessInfo.processInfo.systemUptime >= postDue { break }
                            guard !stop.requested, ProcessInfo.processInfo.systemUptime < bound else { throw MinaError.cancelled }
                            try await Task.sleep(for: .milliseconds(50))
                        }
                        guard ProcessInfo.processInfo.systemUptime >= postDue else { throw MinaError.timeout }
                        let late = try await Task.detached { try statusManagement.status(deadline: bound) }.value
                        try late.requireExactDelta(from: before, testCase: .cancelWait)
                        try timing.recordPostDecisionStatus(at: ProcessInfo.processInfo.systemUptime)
                        report?.postDecisionStatus = late; report?.postDecisionStatusVerified = true
                    }
                    try timing.requireExpected(input.contract.testCase)
                    report?.asyncEvidence = timing
                }
                report?.statusDeltaVerified = true; report?.managementChildrenReaped = true
                report?.result = "expected-auth-only-outcome"
            } catch {
                preparationWatch.cancel(); await preparationWatch.value
                owner.cancel((error as? MinaError) ?? .backendMismatch)
                do { try await owner.drain(); report?.managementChildrenReaped = true }
                catch { report?.failure = .cleanupIncomplete }
                report?.record(owner.snapshotAndClose())
                throw error
            }
            guard let report, let output else { throw MinaError.invalidContract }
            try PrivateInput.writeExclusive(JSONEncoder().encode(report) + Data([10]), to: output)
            print(String(decoding: try JSONEncoder().encode(report), as: UTF8.self))
            return 0
        } catch {
            let reason = (error as? MinaError) ?? .invalidContract
            if var report, let output {
                report.failure = report.failure ?? reason; report.result = "failed"
                if let bytes = try? JSONEncoder().encode(report) { try? PrivateInput.writeExclusive(bytes + Data([10]), to: output) }
                if let bytes = try? JSONEncoder().encode(report) { print(String(decoding: bytes, as: UTF8.self)) }
            } else { fputs("AUTH-ONLY refused: \(reason.rawValue). No captured details emitted.\n", stderr) }
            return 1
        }
    }
}
