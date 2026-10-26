import Foundation
import OpenLXSSHFiles
import RealIntegrationCore

/// Negative-only single-shot callback owner. C is fetched while valid exactly
/// once, held in memory, then mutated or submitted after real expiry. No reread.
final class SFTPOTPNegativeCallbacks: @unchecked Sendable {
    private let lock = NSLock()
    private var budget: SFTPOTPNegativeBudget
    private var unexpected: UnexpectedChallengeShape?
    private var active = 0
    private let management: OpenSSHManagement
    private let token: CancellationToken
    init(testCase: SFTPOTPNegativeCase, management: OpenSSHManagement, token: CancellationToken) throws {
        self.management = management; self.token = token
        budget = try SFTPOTPNegativeBudget(testCase: testCase, start: ProcessInfo.processInfo.systemUptime)
    }
    func handle(_ challenge: KeyboardChallenge, reply: ChallengeReply<[Data]>) {
        lock.lock(); active += 1; lock.unlock()
        defer { lock.lock(); active -= 1; lock.unlock() }
        do {
            let claim: (String, Int)
            lock.lock()
            do {
                claim = try budget.claim(name: challenge.name, instruction: challenge.instruction,
                    prompts: challenge.prompts.map { $0.bytes }, echo: challenge.prompts.map { $0.echo }, now: ProcessInfo.processInfo.systemUptime)
                lock.unlock()
            } catch {
                if unexpected == nil {
                    unexpected = UnexpectedChallengeShape(ordinal: max(1, budget.callbacks), name: challenge.name,
                        instruction: challenge.instruction, prompts: challenge.prompts.map { $0.bytes }, echo: challenge.prompts.map { $0.echo })
                }
                lock.unlock(); throw error // Never guess an informational/zero response.
            }
            // Existing reader still refuses expired/unknown session/index metadata.
            let fetched = try management.response(session: claim.0, index: claim.1)
            var answer = fetched.value
            defer { answer.resetBytes(in: 0..<answer.count) }
            lock.lock()
            do {
                try budget.recordRead(index: claim.1, expiry: fetched.expiresAt,
                    wall: Date().timeIntervalSince1970, uptime: ProcessInfo.processInfo.systemUptime)
                if claim.1 == 2 && budget.testCase == .badOTP {
                    let wrong = try SFTPOTPNegativeBudget.mutateOneDigit(answer)
                    try budget.recordWrongC(original: answer, wrong: wrong)
                    answer = wrong // No secret/hash is logged or written.
                }
                lock.unlock()
            } catch { lock.unlock(); throw error }
            if claim.1 == 2 && snapshot().testCase == .expiredOTP {
                // This worker owns this callback until completion; sleep is only
                // polling, not evidence. Both actual wall + monotonic clocks gate submit.
                while true {
                    try token.check()
                    if try snapshot().expiryReached(wall: Date().timeIntervalSince1970, uptime: ProcessInfo.processInfo.systemUptime) { break }
                    Thread.sleep(forTimeInterval: 0.05)
                }
            }
            lock.lock()
            do {
                try token.check()
                try budget.consume(index: claim.1, wall: Date().timeIntervalSince1970, uptime: ProcessInfo.processInfo.systemUptime)
                try budget.resolved(reply.resolve([answer]))
                lock.unlock()
            } catch { lock.unlock(); throw error }
        } catch { cancel((error as? SFTPOTPNegativeError) ?? .managementFailed) }
    }
    func cancel(_ reason: SFTPOTPNegativeError) {
        lock.lock(); budget.fail(reason); lock.unlock()
        token.cancel(); management.cancel()
    }
    func closeReplies() { lock.lock(); budget.close(); lock.unlock() }
    func snapshot() -> SFTPOTPNegativeBudget { lock.lock(); defer { lock.unlock() }; return budget }
    func unexpectedSnapshot() -> UnexpectedChallengeShape? { lock.lock(); defer { lock.unlock() }; return unexpected }
    private func drained() -> Bool { lock.lock(); defer { lock.unlock() }; return active == 0 }
    func drain() async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + SFTPOTPNegativeContract.drainSeconds
        for _ in 0..<600 {
            if drained() { return }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SFTPOTPNegativeError.cleanupIncomplete }
            try await Task.sleep(for: .milliseconds(20))
        }
        throw SFTPOTPNegativeError.cleanupIncomplete
    }
}
