import COpenLXSSHFiles
import Foundation
import OpenLXSSHTrust

/// A real remote PTY size, in character cells. No local process or command is created.
public struct NativeShellSize: Equatable, Sendable {
    public let columns: Int32
    public let rows: Int32
    public init(columns: Int, rows: Int) throws {
        guard (1...65535).contains(columns), (1...65535).contains(rows) else {
            throw NativeShellError(.invalidConfiguration, operation: "pty-size")
        }
        self.columns = Int32(columns); self.rows = Int32(rows)
    }
}
public struct NativeShellOptions: Sendable {
    public let size: NativeShellSize
    /// Network time only; human/provider waits have a separate budget.
    public let operationTimeout: TimeInterval
    public let interactionTimeout: TimeInterval
    public let authenticationTimeout: TimeInterval
    /// Explicit experimental round-trip policy. Nil preserves the existing disabled default.
    public let liveness: NativeShellLivenessCandidate?
    public init(size: NativeShellSize, operationTimeout: TimeInterval = 10,
                interactionTimeout: TimeInterval? = nil, authenticationTimeout: TimeInterval? = nil,
                liveness: NativeShellLivenessCandidate? = nil) throws {
        let interaction = interactionTimeout ?? min(operationTimeout, 120)
        let authentication = authenticationTimeout ?? operationTimeout
        guard operationTimeout.isFinite, operationTimeout > 0, operationTimeout <= 300,
              interaction.isFinite, interaction > 0, interaction <= 120,
              authentication.isFinite, authentication > 0, authentication <= 300 else {
            throw NativeShellError(.invalidConfiguration, operation: "authentication-budgets")
        }
        self.size = size; self.operationTimeout = operationTimeout
        self.interactionTimeout = interaction; self.authenticationTimeout = authentication
        self.liveness = liveness
    }
}
/// Not OpenSSH's N independent ServerAlive requests: one pending auxiliary session-channel open
/// has a continuous interval * maxUnresponsivePeriods deadline. Uses a remote MaxSessions slot
/// briefly, may be audited/rate-limited, and never requests a PTY, shell, command or subsystem.
public struct NativeShellLivenessCandidate: Equatable, Sendable {
    public let interval: TimeInterval
    public let maxUnresponsivePeriods: Int
    public var responseTimeout: TimeInterval { interval * Double(maxUnresponsivePeriods) }
    public init(interval: TimeInterval, maxUnresponsivePeriods: Int) throws {
        guard interval.isFinite, interval >= 0.05, interval <= 3600,
              (1...100).contains(maxUnresponsivePeriods),
              interval * Double(maxUnresponsivePeriods) <= 36000 else {
            throw NativeShellError(.invalidConfiguration, operation: "liveness-candidate")
        }
        self.interval = interval; self.maxUnresponsivePeriods = maxUnresponsivePeriods
    }
}
public enum NativeShellPrimaryMethod: String, Equatable, Sendable { case password, publicKey }
/// The caller must validate its current presentation/session generation and credential purpose
/// before and after its own awaits. Native additionally verifies this one request's token/lifetime.
public struct NativeShellPrimaryRequest: Sendable {
    public let sessionID: UUID
    public let requestID: UUID
    public let method: NativeShellPrimaryMethod
    public let token: CancellationToken
}
public typealias NativeShellPrimaryProvider = @Sendable (NativeShellPrimaryRequest) async throws -> FileAuthentication
/// A noncooperative external provider cannot be forcibly stopped by Swift. Native closes the
/// socket and revokes every reply, then drains for a bounded time. Callers must inspect pending
/// tasks before claiming their own UI/credential owner was released, and implement cancellation.
public struct NativeShellInteractionSnapshot: Equatable, Sendable {
    public let pendingTasks: Int
    public let pendingProviders: Int
    public let revoked: Bool
    public let nativeClosed: Bool
    public let producersSealed: Bool
    /// A terminal fact, not a momentary zero before another producer can start.
    public var drained: Bool { nativeClosed && producersSealed && pendingTasks == 0 }
}
/// Canonical, read-only receipt for one session. It owns only interaction accounting, never the
/// session, socket, native pointers, credentials, or the right to resume an authentication reply.
public final class NativeShellDrainHandle: Equatable, Sendable {
    public let id = UUID()
    private let tasks: NativeShellInteractionTasks
    init(tasks: NativeShellInteractionTasks) { self.tasks = tasks }
    public static func == (lhs: NativeShellDrainHandle, rhs: NativeShellDrainHandle) -> Bool { lhs.id == rhs.id }
    public var snapshot: NativeShellInteractionSnapshot { tasks.snapshot }
    /// Event-driven and monotonic. Only finite budgets in 0...5 seconds are accepted. Timeout
    /// returns the actual snapshot; task cancellation removes only this waiter and throws.
    public func wait(timeout: TimeInterval = 0.5) async throws -> NativeShellInteractionSnapshot {
        try await tasks.wait(timeout: timeout)
    }
    /// Once-only asynchronous notification on a bounded non-native queue, including late
    /// subscriptions. The cap includes queued/running deliveries; exhaustion throws. Drained is
    /// an interaction/resource fact, not proof an external observer has returned. Removal can
    /// suppress a queued delivery but cannot stop one already running; it keeps its slot until return.
    @discardableResult
    public func observeCompletion(_ observer: @escaping @Sendable (NativeShellInteractionSnapshot) -> Void) throws -> UUID {
        try tasks.observeCompletion(observer)
    }
    public func removeCompletionObserver(_ id: UUID) { tasks.removeCompletionObserver(id) }
}
public struct NativeShellLivenessSnapshot: Equatable, Sendable {
    public internal(set) var probesStarted = 0
    public internal(set) var confirmations = 0
    public internal(set) var remoteRejections = 0
    public internal(set) var helpersFreed = 0
    public internal(set) var pending = false
    public internal(set) var helperChannels = 0
}
/// Facts from public libssh2 APIs only. In particular, -18/-19 never means "primary accepted".
public enum NativeShellAuthenticationStage: Equatable, Sendable {
    case advertised(password: Bool, publicKey: Bool, keyboardInteractive: Bool)
    case primaryStarted(NativeShellPrimaryMethod)
    case primaryResult(NativeShellPrimaryMethod, code: Int32, authenticated: Bool)
    case keyboardStarted
    case keyboardResult(code: Int32, authenticated: Bool)
    case authenticated
    case shellReady
}
public struct NativeShellError: Error, Equatable, Sendable {
    public enum Kind: String, Sendable {
        case invalidConfiguration, resourceLimit, busy, cancelled, timeout, untrusted
        case authentication, transport, closed, protocolFailure, unsupported
    }
    public let kind: Kind
    public let operation: String
    public let code: Int32?
    public let authenticationStages: [NativeShellAuthenticationStage]
    /// Pending caller-supplied/interaction tasks after bounded close drain, never secret data.
    public let pendingInteractionTasks: Int
    public let changedHostKey: ChangedHostKey?
    /// Same canonical handle as the session; equality uses its immutable identity, not live counts.
    public let interactionDrain: NativeShellDrainHandle?
    public init(_ kind: Kind, operation: String, code: Int32? = nil,
                stages: [NativeShellAuthenticationStage] = [], pendingInteractionTasks: Int = 0,
                changedHostKey: ChangedHostKey? = nil, interactionDrain: NativeShellDrainHandle? = nil) {
        self.kind = kind; self.operation = operation; self.code = code; authenticationStages = stages
        self.pendingInteractionTasks = pendingInteractionTasks; self.changedHostKey = changedHostKey
        self.interactionDrain = interactionDrain
    }
}
public struct NativeShellExit: Equatable, Sendable {
    /// This is libssh2's reported value, NOT proof the server sent exit-status.
    /// The public API returns zero also when the server omitted that request.
    public let reportedStatus: Int32
    public let signal: Data?
}
public enum NativeShellReceive: Equatable, Sendable {
    case bytes(Data)
    /// No output before this receive's deadline. An idle terminal is not a dead connection.
    case wouldBlock
    /// Remote EOF, after all previously buffered output was pulled. Does not imply exit-status.
    case eof
    /// Channel closure, separate from EOF. Native/socket cleanup has completed before delivery.
    case exit(NativeShellExit)
}

enum NativeShellProbePhase: Equatable { case idle, opening, closing, freeing }
/// Pure queue-owned scheduling policy. Only the bridge's actual matching open result advances
/// to confirmed/rejected. Ordinary output may delay an idle probe, never settle a pending one.
struct NativeShellLivenessState {
    let policy: NativeShellLivenessCandidate
    private(set) var phase: NativeShellProbePhase = .idle
    private(set) var nextProbe: ContinuousClock.Instant
    private(set) var deadline: ContinuousClock.Instant?
    private(set) var facts = NativeShellLivenessSnapshot()
    init(policy: NativeShellLivenessCandidate, now: ContinuousClock.Instant = .now) {
        self.policy = policy; nextProbe = now.advanced(by: .seconds(policy.interval))
    }
    mutating func applicationRead(now: ContinuousClock.Instant = .now) {
        if phase == .idle { nextProbe = now.advanced(by: .seconds(policy.interval)) }
    }
    mutating func beginIfDue(now: ContinuousClock.Instant = .now) -> Bool {
        guard phase == .idle, now >= nextProbe else { return false }
        phase = .opening; deadline = now.advanced(by: .seconds(policy.responseTimeout))
        facts.probesStarted += 1; facts.pending = true
        return true
    }
    func checkDeadline(now: ContinuousClock.Instant = .now) throws {
        if let deadline, now >= deadline {
            throw NativeShellError(.timeout, operation: phase == .opening ? "ssh-round-trip" : "ssh-probe-cleanup")
        }
    }
    mutating func confirmed(cleanupTimeout: TimeInterval, now: ContinuousClock.Instant = .now) {
        precondition(phase == .opening)
        phase = .closing; deadline = now.advanced(by: .seconds(cleanupTimeout))
        facts.confirmations += 1; facts.helperChannels = 1
    }
    mutating func rejected(now: ContinuousClock.Instant = .now) {
        precondition(phase == .opening)
        facts.remoteRejections += 1; settle(now: now)
    }
    mutating func closed() { precondition(phase == .closing); phase = .freeing }
    mutating func freed(now: ContinuousClock.Instant = .now) {
        precondition(phase == .freeing)
        facts.helpersFreed += 1; facts.helperChannels = 0; settle(now: now)
    }
    mutating func disposed() { facts.helperChannels = 0; facts.pending = false; deadline = nil }
    private mutating func settle(now: ContinuousClock.Instant) {
        phase = .idle; deadline = nil; facts.pending = false
        nextProbe = now.advanced(by: .seconds(policy.interval))
    }
}

/// Bounds BEFORE dispatching closures, including concurrent callers. No unbounded input backlog.
final class NativeShellAdmission: @unchecked Sendable {
    static let maximumInputBytes = 256 * 1024
    private let lock = NSLock()
    private var bytes = 0
    private var writes = 0
    private var receiving = false
    private var controlling = false
    private var closed = false
    var pendingInputBytes: Int { lock.withLock { bytes } }
    func reserveWrite(_ count: Int) throws {
        try lock.withLock {
            guard !closed else { throw NativeShellError(.closed, operation: "write") }
            guard count > 0, count <= Self.maximumInputBytes, bytes <= Self.maximumInputBytes - count,
                  writes < 128 else { throw NativeShellError(.resourceLimit, operation: "input-backpressure") }
            bytes += count; writes += 1
        }
    }
    func releaseWrite(_ count: Int) { lock.withLock { bytes -= count; writes -= 1 } }
    func reserveReceive() throws {
        try lock.withLock {
            guard !closed else { throw NativeShellError(.closed, operation: "receive") }
            guard !receiving else { throw NativeShellError(.busy, operation: "single-consumer") }
            receiving = true
        }
    }
    func releaseReceive() { lock.withLock { receiving = false } }
    func reserveControl() throws {
        try lock.withLock {
            guard !closed else { throw NativeShellError(.closed, operation: "control") }
            guard !controlling else { throw NativeShellError(.busy, operation: "pending-control") }
            controlling = true
        }
    }
    func releaseControl() { lock.withLock { controlling = false } }
    func close() { lock.withLock { closed = true } }
}

/// libssh2 requires the exact same pointer/length across EAGAIN. Data.withUnsafeBytes on a
/// later turn does not promise that. This owner keeps one stable allocation until completion.
final class NativeShellWriteBuffer {
    let pointer: UnsafeMutablePointer<CChar>
    let count: Int
    private(set) var offset = 0
    private(set) var stepLength: Int
    init(_ data: Data) {
        count = data.count; stepLength = min(data.count, Int(RF_SHELL_MAX_WRITE))
        pointer = .allocate(capacity: max(1, data.count))
        data.withUnsafeBytes { bytes in
            if let base = bytes.baseAddress { UnsafeMutableRawPointer(pointer).copyMemory(from: base, byteCount: data.count) }
        }
    }
    var stepPointer: UnsafePointer<CChar> { UnsafePointer(pointer.advanced(by: offset)) }
    func advance(_ bytes: Int) {
        precondition(bytes > 0 && bytes <= stepLength)
        offset += bytes; stepLength = min(count - offset, Int(RF_SHELL_MAX_WRITE))
    }
    var complete: Bool { offset == count }
    deinit { rf_wipe(pointer, count); pointer.deallocate() }
}

struct NativeShellAuthenticationSource: Sendable {
    let method: NativeShellPrimaryMethod
    let provider: NativeShellPrimaryProvider
    let keyboard: KeyboardHandler?
    init(method: NativeShellPrimaryMethod, provider: @escaping NativeShellPrimaryProvider, keyboard: KeyboardHandler?) {
        self.method = method; self.provider = provider; self.keyboard = keyboard
    }
    init(plan: NativeShellAuthenticationPlan) {
        method = plan.method; keyboard = plan.keyboard
        provider = { _ in plan.primary }
    }
}

struct NativeShellAuthenticationPlan: Sendable {
    let primary: FileAuthentication
    let method: NativeShellPrimaryMethod
    let keyboard: KeyboardHandler?
    init(primary: FileAuthentication, keyboard: KeyboardHandler?) throws {
        switch primary {
        case .password(let data):
            guard data.count <= 65536 else { throw NativeShellError(.resourceLimit, operation: "password-size") }
            method = .password
        case .publicKey(let publicKey, let privateKey, let passphrase):
            guard !privateKey.isEmpty, privateKey.count <= 4 * 1024 * 1024,
                  (publicKey?.count ?? 0) <= 65536, (passphrase?.count ?? 0) <= 65536,
                  !(passphrase?.contains(0) ?? false) else {
                throw NativeShellError(.invalidConfiguration, operation: "key-material")
            }
            method = .publicKey
        case .keyboardInteractive:
            throw NativeShellError(.invalidConfiguration, operation: "typed-primary-required")
        }
        self.primary = primary; self.keyboard = keyboard
    }
    /// Only a distinct, explicitly manual KI method may follow these ambiguous outcomes.
    static func mayContinueToKeyboard(code: Int32, authenticated: Bool, hasHandler: Bool) -> Bool {
        !authenticated && hasHandler && [Int32(LIBSSH2_ERROR_AUTHENTICATION_FAILED),
                                         Int32(LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED)].contains(code)
    }
}
