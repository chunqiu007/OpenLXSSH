import Foundation
import StabilityPOSIX

public struct ClockReading: Codable, Equatable, Sendable {
    public let wallUnix: Double
    public let monotonic: Double
    public let continuous: Double
    public init(wallUnix: Double, monotonic: Double, continuous: Double) {
        self.wallUnix = wallUnix; self.monotonic = monotonic; self.continuous = continuous
    }
    public static func now() -> Self {
        Self(wallUnix: Date().timeIntervalSince1970, monotonic: stability_monotonic_seconds(), continuous: stability_continuous_seconds())
    }
}

/// No injectable clock in the signed executable. Unit tests feed readings here
/// solely to verify the predicate; they never produce acceptance evidence.
public struct ContinuityGuard: Sendable {
    public let start: ClockReading
    public private(set) var latest: ClockReading
    public let requiredSeconds: Double
    public let maximumGap: Double
    public init(start: ClockReading, requiredSeconds: Double, maximumGap: Double) throws {
        guard start.wallUnix.isFinite, start.wallUnix > 0, start.monotonic.isFinite, start.monotonic >= 0,
              start.continuous.isFinite, start.continuous >= 0,
              requiredSeconds.isFinite, (86_400...604_800).contains(requiredSeconds),
              maximumGap.isFinite, (5...65).contains(maximumGap) else { throw StabilityError.invalidArguments }
        self.start = start; latest = start; self.requiredSeconds = requiredSeconds; self.maximumGap = maximumGap
    }
    public mutating func observe(_ current: ClockReading, connectedSessions: Int, sleepObserved: Bool) throws {
        guard connectedSessions == 5 else { throw StabilityError.connectionLost }
        let awake = current.monotonic - latest.monotonic
        let elapsed = current.monotonic - start.monotonic
        guard !sleepObserved, current.wallUnix.isFinite, current.monotonic.isFinite, current.continuous.isFinite,
              awake >= 0, awake <= maximumGap,
              current.continuous >= latest.continuous,
              abs((current.continuous - start.continuous) - elapsed) <= 2,
              abs((current.wallUnix - start.wallUnix) - elapsed) <= 5,
              abs((current.wallUnix - latest.wallUnix) - awake) <= 5 else { throw StabilityError.timerDiscontinuity }
        latest = current
    }
    public var elapsedSeconds: Double { latest.monotonic - start.monotonic }
    public var completed: Bool {
        elapsedSeconds >= requiredSeconds && latest.wallUnix - start.wallUnix >= requiredSeconds && latest.continuous - start.continuous >= requiredSeconds
    }
}

public enum SessionPhase: String, Codable, Sendable { case pending, connected, failed, closing, closed }

/// Contract for the real DirectSSHSession adapter, not a substitute SSH client.
@MainActor public protocol AcceptanceSession: AnyObject {
    var phase: SessionPhase { get }
    var ownedPID: Int32? { get }
    var authenticated: Bool { get } // Only a real Transport .connected event may set this.
    var failure: StabilityError? { get } // Read-only, latched independently of phase.
    var cancellationEligible: Bool { get } // Adapter must bind to the real backend state.
    func connect() throws
    func cancel()
    func close()
}

public struct CycleTotals: Codable, Equatable, Sendable {
    public internal(set) var authenticatedCycles = 0
    public internal(set) var cancelledAttempts = 0
    public internal(set) var closedSessions = 0
    public init() {}
}

@MainActor public enum FiniteLifecycle {
    /// Bounds are finite even if a backend never transitions. The production
    /// waiter is an ordinary 50 ms Task.sleep, not a fake clock or fast-forward.
    public static func closeAndDrain(_ session: any AcceptanceSession,
                                    wait: () async -> Void) async throws {
        session.close()
        for _ in 0..<240 {
            if session.phase == .closed && session.ownedPID == nil { return }
            await wait()
        }
        throw StabilityError.cleanupIncomplete
    }

    public static func cycles(cancelEvery: Int,
                              stopped: () -> Bool,
                              make: () throws -> any AcceptanceSession,
                              wait: () async -> Void,
                              authenticatedCheckpoint: () throws -> Void = {},
                              checkpoint: (CycleTotals) throws -> Void = { _ in }) async throws -> CycleTotals {
        guard (0...200).contains(cancelEvery) else { throw StabilityError.invalidArguments }
        var totals = CycleTotals()
        for cycle in 1...200 {
            if stopped() { throw StabilityError.cancelled }
            if cancelEvery > 0 && cycle % cancelEvery == 0 {
                let session = try make()
                do {
                    try session.connect()
                    await wait() // Give preparation a turn; no trust accept or credentials sent here.
                    guard session.phase == .pending, session.failure == nil,
                          !session.authenticated, session.cancellationEligible else {
                        throw StabilityError.invalidLifecycle
                    }
                    session.cancel()
                } catch {
                    try await closeAndDrain(session, wait: wait); throw error
                }
                try await closeAndDrain(session, wait: wait)
                totals.cancelledAttempts += 1; totals.closedSessions += 1
                try checkpoint(totals)
            }
            if stopped() { throw StabilityError.cancelled }
            let session = try make()
            do {
                try session.connect()
                var connected = false
                for _ in 0..<600 {
                    if stopped() { throw StabilityError.cancelled }
                    if session.failure != nil || session.phase == .failed || session.phase == .closing || session.phase == .closed {
                        throw StabilityError.connectionLost
                    }
                    if session.phase == .connected && session.authenticated && session.ownedPID != nil { connected = true; break }
                    await wait()
                }
                guard connected else { throw StabilityError.timeout }
                try authenticatedCheckpoint()
            } catch {
                try await closeAndDrain(session, wait: wait); throw error
            }
            try await closeAndDrain(session, wait: wait)
            // Count only after authenticated event AND closed + nil owner. No next
            // session is created before both cleanup predicates have succeeded.
            totals.authenticatedCycles += 1; totals.closedSessions += 1
            try checkpoint(totals)
        }
        if stopped() { throw StabilityError.cancelled }
        return totals
    }
}
