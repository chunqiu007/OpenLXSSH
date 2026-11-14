import Foundation
import OpenLXSSHFiles
import RealIntegrationCore
import UXNativeShellProbeSupport

/// Owns no primary credential and no OpenSSHManagement object. It is physically incapable of
/// reading an OTP. Only the first actual, exact approved fixture A challenge permits cancellation.
/// Unknown shapes trigger terminal rejection; no reply (including empty/partial) is submitted.
final class NativeShellFaultCallbacks: @unchecked Sendable {
    struct Snapshot: Sendable {
        let callbacks: Int
        let replies: Int
        let firstChallengeValidated: Bool
        let sessionID: String?
        let failure: SFTPAuthError?
    }
    private let lock = NSLock()
    private let token: CancellationToken
    private let testCase: ShellProbeCase
    private var budget: SFTPAuthBudget
    private var callbacks = 0
    private var active = 0
    private var closed = false
    private var validated = false
    private var sessionID: String?
    private var failure: SFTPAuthError?
    init(testCase: ShellProbeCase, token: CancellationToken) throws {
        self.testCase = testCase; self.token = token
        budget = try SFTPAuthBudget(mfa: testCase == .cancelKI, start: ProcessInfo.processInfo.systemUptime)
    }
    func handle(_ challenge: KeyboardChallenge, reply: ChallengeReply<[Data]>) {
        lock.lock(); active += 1
        do {
            defer { active -= 1; lock.unlock() }
            guard !closed else { throw SFTPAuthError.staleReply }
            callbacks += 1
            guard testCase == .cancelKI, callbacks == 1 else { throw SFTPAuthError.unknownChallenge }
            let phase = try budget.claim(name: challenge.name, instruction: challenge.instruction,
                prompts: challenge.prompts.map(\.bytes), echo: challenge.prompts.map(\.echo), now: ProcessInfo.processInfo.systemUptime)
            guard case .secret(let id, let index) = phase, index == 0 else { throw SFTPAuthError.unknownChallenge }
            validated = true; sessionID = id
            budget.close(); closed = true
        } catch {
            // The defer above releases the same lock even on validation errors.
            lock.withLock { if failure == nil { failure = (error as? SFTPAuthError) ?? .unknownChallenge }; closed = true }
        }
        token.cancel(); reply.cancel()
    }
    func snapshot() -> Snapshot {
        lock.withLock { Snapshot(callbacks: callbacks, replies: 0, firstChallengeValidated: validated,
                                 sessionID: sessionID, failure: failure) }
    }
    func close() { lock.withLock { closed = true; budget.close() } }
    func drain() async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + SFTPAuthContract.drainSeconds
        while lock.withLock({ active > 0 }) {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SFTPAuthError.cleanupIncomplete }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
}

final class NativeShellChangedKeyObservation: @unchecked Sendable {
    private let lock = NSLock()
    private var changed = false
    private var unexpected = false
    func handle(_ event: FileHostTrustEvent, _ reply: ChallengeReply<FileHostTrustAnswer>) {
        lock.withLock {
            if case .changed = event { changed = true } else { unexpected = true }
        }
        reply.resolve(.reject)
    }
    var exactChangedRejection: Bool { lock.withLock { changed && !unexpected } }
}
