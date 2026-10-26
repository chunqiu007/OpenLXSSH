import Foundation
import OpenLXSSHFiles
import RealIntegrationCore

/// Fixed root reader reuse only: no system prompt hashes or OpenSSH decisions.
final class SFTPAuthCallbacks: @unchecked Sendable {
    private let lock = NSLock()
    private var budget: SFTPAuthBudget
    private var unexpectedShape: UnexpectedChallengeShape?
    private var active = 0
    private let management: OpenSSHManagement
    private let token: CancellationToken
    init(mfa: Bool, management: OpenSSHManagement, token: CancellationToken) throws {
        self.management = management; self.token = token
        budget = try SFTPAuthBudget(mfa: mfa, start: ProcessInfo.processInfo.systemUptime)
    }
    func handle(_ challenge: KeyboardChallenge, reply: ChallengeReply<[Data]>) {
        lock.lock(); active += 1; lock.unlock()
        defer { lock.lock(); active -= 1; lock.unlock() }
        do {
            let claim: SFTPAuthPhase
            lock.lock()
            do {
                claim = try budget.claim(name: challenge.name, instruction: challenge.instruction,
                    prompts: challenge.prompts.map { $0.bytes }, echo: challenge.prompts.map { $0.echo }, now: ProcessInfo.processInfo.systemUptime)
                lock.unlock()
            } catch {
                // Diagnostic only, under the same lock and only once. Do not
                // resolve, read a response or replace the original claim error.
                if unexpectedShape == nil {
                    unexpectedShape = UnexpectedChallengeShape(ordinal: max(1, budget.callbacks), name: challenge.name,
                        instruction: challenge.instruction, prompts: challenge.prompts.map { $0.bytes }, echo: challenge.prompts.map { $0.echo })
                }
                lock.unlock(); throw error
            }
            var answer: Data?
            if case .secret(let session, let index) = claim {
                answer = try management.response(session: session, index: index).value
            }
            defer { if var bytes = answer { bytes.resetBytes(in: 0..<bytes.count) }; answer = nil }
            lock.lock()
            do {
                try token.check()
                try budget.consume(phase: claim, now: ProcessInfo.processInfo.systemUptime)
                switch claim {
                case .secret:
                    guard let answer else { throw SFTPAuthError.managementFailed }
                    budget.resolved(reply.resolve([answer]))
                case .terminalZero:
                    budget.resolved(reply.resolve([])) // Protocol tail, no secret read/answer.
                }
                try budget.requireResolutionAccepted()
                lock.unlock()
            } catch { lock.unlock(); throw error }
        } catch { cancel((error as? SFTPAuthError) ?? .managementFailed) }
    }
    func cancel(_ reason: SFTPAuthError) {
        lock.lock(); budget.fail(reason); lock.unlock()
        token.cancel(); management.cancel()
    }
    func closeReplies() { lock.lock(); budget.close(); lock.unlock() }
    func snapshot() -> SFTPAuthBudget { lock.lock(); defer { lock.unlock() }; return budget }
    func unexpectedChallengeSnapshot() -> UnexpectedChallengeShape? { lock.lock(); defer { lock.unlock() }; return unexpectedShape }
    private func drained() -> Bool { lock.lock(); defer { lock.unlock() }; return active == 0 }
    func drain() async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + SFTPAuthContract.drainSeconds
        for _ in 0..<600 {
            if drained() { return }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SFTPAuthError.cleanupIncomplete }
            try await Task.sleep(for: .milliseconds(20))
        }
        throw SFTPAuthError.cleanupIncomplete
    }
}
