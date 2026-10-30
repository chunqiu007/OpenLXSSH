import COpenLXSSHFiles
import Foundation

/// One keyboard API invocation may contain many real rounds, including zero-prompt notifications.
/// The native adapter already bounds individual fields/replies; additionally bound the complete
/// transaction before dispatching manual handlers. No password material is stored here.
struct NativeShellKeyboardBudget {
    private(set) var rounds = 0
    private(set) var promptCount = 0
    private(set) var displayedBytes = 0
    mutating func claim(prompts: Int, bytes: Int) throws {
        guard prompts >= 0, prompts <= 32, bytes >= 0, rounds < 16,
              promptCount <= 128 - prompts, bytes <= 1024 * 1024,
              displayedBytes <= 1024 * 1024 - bytes else {
            throw FileServiceError(.resourceLimit, operation: "shell-keyboard-budget")
        }
        rounds += 1; promptCount += prompts; displayedBytes += bytes
    }
}
/// One monotonic deadline spans trust, method discovery, provider and all KI rounds.
/// Legacy options use operationTimeout as this budget; callers must explicitly opt into 120/300s.
struct NativeShellAuthenticationBudget: Sendable {
    let deadline: ContinuousClock.Instant
    let interactionTimeout: TimeInterval
    init(options: NativeShellOptions, now: ContinuousClock.Instant = .now) {
        deadline = now.advanced(by: .seconds(options.authenticationTimeout))
        interactionTimeout = options.interactionTimeout
    }
    func remaining(now: ContinuousClock.Instant = .now) throws -> TimeInterval {
        let parts = now.duration(to: deadline).components
        let seconds = Double(parts.seconds) + Double(parts.attoseconds) / 1e18
        guard seconds > 0 else { throw NativeShellError(.timeout, operation: "authentication-deadline") }
        return seconds
    }
    func networkTimeout(_ maximum: TimeInterval) throws -> TimeInterval { min(maximum, try remaining()) }
    func interactionDeadline(now: ContinuousClock.Instant = .now) throws -> ContinuousClock.Instant {
        _ = try remaining(now: now)
        return min(deadline, now.advanced(by: .seconds(interactionTimeout)))
    }
}

/// Every producer registers before creating a task/dispatch item. Revocation and sealing share
/// that admission lock; cancellation is not completion, and only the producer's defer removes it.
/// This owner may outlive the session through a read-only drain handle.
final class NativeShellInteractionTasks: @unchecked Sendable {
    static let maximumProducers = 256
    static let maximumWaiters = 64
    static let maximumObservers = 64
    private static let notificationDelivery = NativeShellCompletionNotifications()
    private struct Entry {
        let provider: Bool
        var cancel: (@Sendable () -> Void)?
        var installed = false
    }
    private struct Observer {
        var callback: (@Sendable (NativeShellInteractionSnapshot) -> Void)?
        var scheduled = false
        var running = false
        var removed = false
        let slotID: UUID
    }
    private struct Waiter {
        let continuation: CheckedContinuation<NativeShellInteractionSnapshot, any Error>
        let timer: DispatchSourceTimer
    }
    private let lock = NSLock()
    private var entries: [UUID: Entry] = [:]
    // A task can return before its cancellation handle is installed. Keep only those small
    // unfinished installations, not all completed entries or their closures.
    private var finishedBeforeInstall = Set<UUID>()
    private var waiters: [UUID: Waiter] = [:]
    private var observers: [UUID: Observer] = [:]
    private var revoked = false
    private var nativeClosed = false
    private var producersSealed = false

    func begin(provider: Bool) throws -> UUID {
        try lock.withLock {
            guard !revoked, !producersSealed else { throw NativeShellError(.cancelled, operation: "interaction-producer-sealed") }
            guard entries.count + finishedBeforeInstall.count < Self.maximumProducers else {
                throw NativeShellError(.resourceLimit, operation: "interaction-producer-capacity")
            }
            let id = UUID(); entries[id] = Entry(provider: provider); return id
        }
    }
    /// At most one installation per live entry. A duplicate is explicitly rejected without
    /// retaining/invoking its closure; the original installation remains authoritative.
    @discardableResult
    func install(_ id: UUID, cancel: @escaping @Sendable () -> Void) -> Bool {
        let action: (accepted: Bool, invoke: Bool) = lock.withLock {
            guard var entry = entries[id] else {
                guard finishedBeforeInstall.remove(id) != nil else { return (false, false) }
                return (true, revoked || producersSealed)
            }
            guard !entry.installed else { return (false, false) }
            entry.installed = true
            if revoked || producersSealed { entries[id] = entry; return (true, true) }
            entry.cancel = cancel; entries[id] = entry; return (true, false)
        }
        if action.invoke { cancel() }
        return action.accepted
    }
    @discardableResult
    func dispatch(using dispatcher: FileTrustCallbackDispatcher = .global,
                  cancel: @escaping @Sendable () -> Void,
                  work: @escaping @Sendable () -> Void) throws -> UUID {
        let id = try begin(provider: false)
        install(id, cancel: cancel)
        dispatcher.submit { [self] in
            defer { finish(id) }
            guard lock.withLock({ !revoked && !producersSealed }) else { return }
            work()
        }
        return id
    }
    func finish(_ id: UUID) {
        lock.withLock {
            if let entry = entries.removeValue(forKey: id), !entry.installed { finishedBeforeInstall.insert(id) }
        }
        notifyIfDrained()
    }
    func isPending(_ id: UUID) -> Bool { lock.withLock { entries[id] != nil } }
    func revoke() {
        let callbacks: [@Sendable () -> Void] = lock.withLock {
            guard !revoked else { return [] }
            revoked = true
            let callbacks = entries.values.compactMap(\.cancel)
            for id in Array(entries.keys) { entries[id]?.cancel = nil }
            return callbacks
        }
        callbacks.forEach { $0() }
    }
    func seal() { lock.withLock { producersSealed = true }; notifyIfDrained() }
    /// Called only after the native resource owner's synchronous dispose actually returns.
    func markNativeClosed() { lock.withLock { nativeClosed = true }; notifyIfDrained() }
    private var lockedSnapshot: NativeShellInteractionSnapshot {
        NativeShellInteractionSnapshot(pendingTasks: entries.count,
            pendingProviders: entries.values.filter(\.provider).count, revoked: revoked,
            nativeClosed: nativeClosed, producersSealed: producersSealed)
    }
    var snapshot: NativeShellInteractionSnapshot { lock.withLock { lockedSnapshot } }

    private func notifyIfDrained() {
        let deliveries: (NativeShellInteractionSnapshot, [Waiter], [UUID])? = lock.withLock {
            let value = lockedSnapshot
            guard value.drained else { return nil }
            let waiting = Array(waiters.values)
            waiters.removeAll()
            let observing: [UUID] = observers.compactMap { $0.value.scheduled ? nil : $0.key }
            for id in observing { observers[id]?.scheduled = true }
            return (value, waiting, observing)
        }
        guard let (value, waiting, observing) = deliveries else { return }
        for waiter in waiting { waiter.timer.cancel(); waiter.continuation.resume(returning: value) }
        for id in observing { enqueueObserver(id, snapshot: value) }
    }
    private func enqueueObserver(_ id: UUID, snapshot: NativeShellInteractionSnapshot) {
        // External notifications are not interaction producers. Their bounded queued/running
        // lifetime is separate from drained, and can never hold the native close queue hostage.
        Self.notificationDelivery.submit { [self] in
            let callback: (@Sendable (NativeShellInteractionSnapshot) -> Void)? = lock.withLock {
                guard var observer = observers[id], !observer.running else { return nil }
                observer.running = true; observers[id] = observer
                return observer.removed ? nil : observer.callback
            }
            defer { releaseObserver(id) }
            callback?(snapshot)
        }
    }
    @discardableResult
    func observeCompletion(_ observer: @escaping @Sendable (NativeShellInteractionSnapshot) -> Void) throws -> UUID {
        let id = UUID()
        let completed: NativeShellInteractionSnapshot? = try lock.withLock {
            guard observers.count < Self.maximumObservers else {
                throw NativeShellError(.resourceLimit, operation: "interaction-observer-capacity")
            }
            let slotID = try Self.notificationDelivery.reserve()
            let value = lockedSnapshot
            observers[id] = Observer(callback: observer, scheduled: value.drained, slotID: slotID)
            return value.drained ? value : nil
        }
        if let completed { enqueueObserver(id, snapshot: completed) }
        return id
    }
    func removeCompletionObserver(_ id: UUID) {
        let released: UUID? = lock.withLock {
            guard var observer = observers[id], !observer.running else { return nil }
            if observer.scheduled {
                // Keep the queue slot until its actual closure runs, even if removed repeatedly.
                observer.removed = true; observer.callback = nil; observers[id] = observer; return nil
            }
            observers.removeValue(forKey: id); return observer.slotID
        }
        if let released { Self.notificationDelivery.release(released) }
    }
    private func releaseObserver(_ id: UUID) {
        let released = lock.withLock { observers.removeValue(forKey: id)?.slotID }
        if let released { Self.notificationDelivery.release(released) }
    }
    deinit {
        // Scheduled deliveries retain this registry through their actual return.
        for observer in observers.values { Self.notificationDelivery.release(observer.slotID) }
    }
    /// Test-visible counts also prove that a timeout/cancellation removes the waiter, not entries.
    var subscriptionCounts: (waiters: Int, observers: Int) { lock.withLock { (waiters.count, observers.count) } }
    var pendingInstallations: Int { lock.withLock { finishedBeforeInstall.count } }

    func wait(timeout: TimeInterval) async throws -> NativeShellInteractionSnapshot {
        guard timeout.isFinite, (0...5).contains(timeout) else {
            throw NativeShellError(.invalidConfiguration, operation: "interaction-drain-timeout")
        }
        let id = UUID(), cancellation = NativeShellDrainWaitCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let timer = DispatchSource.makeTimerSource(queue: .global())
                timer.schedule(deadline: .now() + timeout, leeway: .milliseconds(1))
                timer.setEventHandler { [weak self] in self?.completeWaiter(id, cancelled: false) }
                let immediate: Result<NativeShellInteractionSnapshot, any Error>? = lock.withLock {
                    if cancellation.isCancelled || Task<Never, Never>.isCancelled {
                        return .failure(CancellationError())
                    }
                    let value = lockedSnapshot
                    if value.drained || timeout == 0 { return .success(value) }
                    guard waiters.count < Self.maximumWaiters else {
                        return .failure(NativeShellError(.resourceLimit, operation: "interaction-waiter-capacity"))
                    }
                    waiters[id] = Waiter(continuation: continuation, timer: timer)
                    return nil
                }
                // A suspended dispatch source must always be activated, including early exits.
                if let immediate { timer.cancel(); timer.activate(); continuation.resume(with: immediate) }
                else { timer.activate() }
            }
        } onCancel: {
            cancellation.cancel()
            self.completeWaiter(id, cancelled: true)
        }
    }
    private func completeWaiter(_ id: UUID, cancelled: Bool) {
        let completed: (Waiter, NativeShellInteractionSnapshot)? = lock.withLock {
            guard let waiter = waiters.removeValue(forKey: id) else { return nil }
            return (waiter, lockedSnapshot)
        }
        guard let (waiter, value) = completed else { return }
        waiter.timer.cancel()
        if cancelled { waiter.continuation.resume(throwing: CancellationError()) }
        else { waiter.continuation.resume(returning: value) }
    }
    /// Legacy internal cleanup entry. Session callers use a fixed valid budget and still receive
    /// actual counts when their task is already cancelled; cancellation does not fake completion.
    func drain(timeout: TimeInterval = 0.5) async -> NativeShellInteractionSnapshot {
        do { return try await wait(timeout: timeout) }
        catch { return snapshot }
    }
}
/// Process-wide bound as well as each registry's observer bound. Even an observer that never
/// returns cannot spawn an unlimited queue by repeatedly subscribing to already-drained handles.
private final class NativeShellCompletionNotifications: @unchecked Sendable {
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "OpenLXSSH.NativeShell.drain-notifications", attributes: .concurrent)
    private var slots = Set<UUID>()
    func reserve() throws -> UUID {
        try lock.withLock {
            guard slots.count < 256 else { throw NativeShellError(.resourceLimit, operation: "interaction-notification-capacity") }
            let id = UUID(); slots.insert(id); return id
        }
    }
    func release(_ id: UUID) { lock.withLock { _ = slots.remove(id) } }
    func submit(_ work: @escaping @Sendable () -> Void) { queue.async(execute: work) }
}
private final class NativeShellDrainWaitCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    var isCancelled: Bool { lock.withLock { cancelled } }
    func cancel() { lock.withLock { cancelled = true } }
}

private final class NativeShellWaitResult<Value: Sendable>: @unchecked Sendable {
    private let condition = NSCondition()
    private var value: Result<Value, any Error>?
    func complete(_ result: Result<Value, any Error>) {
        condition.lock(); value = result; condition.broadcast(); condition.unlock()
    }
    func poll() -> Result<Value, any Error>? {
        condition.lock(); defer { condition.unlock() }
        if value == nil { _ = condition.wait(until: Date().addingTimeInterval(0.005)) }
        return value
    }
    func pause() {
        condition.lock(); _ = condition.wait(until: Date().addingTimeInterval(0.005)); condition.unlock()
    }
}
/// Adapts the existing single-waiter async mailbox to a native synchronous callback. Date is
/// only a wakeup hint; cancellation and every security budget use ContinuousClock. No second
/// waiter consumes the mailbox. On timeout/cancel both the reply and operation token are revoked.
enum NativeShellInteraction {
    static func wait<Value: Sendable>(_ reply: ChallengeReply<Value>, token: CancellationToken,
                                     lifetime: CancellationToken, deadline: ContinuousClock.Instant,
                                     tasks: NativeShellInteractionTasks = NativeShellInteractionTasks()) throws -> Value {
        let result = NativeShellWaitResult<Value>()
        let taskID = try tasks.begin(provider: false)
        let waiter = Task.detached {
            defer { tasks.finish(taskID) }
            do { result.complete(.success(try await reply.waitAsync(token: token, deadline: deadline))) }
            catch { result.complete(.failure(error)) }
        }
        tasks.install(taskID) { reply.cancel(); waiter.cancel() }
        defer {
            reply.cancel(); waiter.cancel()
            // The internal waiter cooperates; confirm completion without an unbounded join.
            let drainDeadline = ContinuousClock.now.advanced(by: .milliseconds(100))
            while tasks.isPending(taskID), .now < drainDeadline { result.pause() }
        }
        do {
            while true {
                try lifetime.check(); try token.check()
                guard .now < deadline else { throw NativeShellError(.timeout, operation: "interaction-deadline") }
                if let value = result.poll() {
                    try lifetime.check(); try token.check()
                    guard .now < deadline else { throw NativeShellError(.timeout, operation: "interaction-deadline") }
                    return try value.get()
                }
            }
        } catch { token.cancel(); reply.cancel(); throw error }
    }
}

/// One acquisition per actual handshake, only after trust and advertised method validation.
/// This seam tests acquisition policy offline; it cannot authenticate or create a shell.
final class NativeShellPrimaryGate {
    private var used = false // Native owner queue only.
    func acquire(source: NativeShellAuthenticationSource, sessionID: UUID, trusted: Bool,
                 methods: Set<String>, token: CancellationToken, lifetime: CancellationToken,
                 budget: NativeShellAuthenticationBudget,
                 tasks: NativeShellInteractionTasks = NativeShellInteractionTasks()) throws -> FileAuthentication {
        try lifetime.check(); try token.check()
        guard trusted else { throw NativeShellError(.untrusted, operation: "primary-before-trust") }
        let required = source.method == .password ? "password" : "publickey"
        guard methods.contains(required) else { throw NativeShellError(.authentication, operation: "primary-method-unavailable") }
        guard !used else { throw NativeShellError(.authentication, operation: "primary-already-requested") }
        let deadline = try budget.interactionDeadline()
        used = true
        let request = NativeShellPrimaryRequest(sessionID: sessionID, requestID: UUID(), method: source.method, token: token)
        let reply = ChallengeReply<Result<FileAuthentication, any Error>>()
        let taskID = try tasks.begin(provider: true)
        let providerFunction = source.provider // Do not retain the unrelated KI handler in the provider task.
        let provider = Task.detached {
            defer { tasks.finish(taskID) }
            do {
                try lifetime.check(); try token.check()
                let material = try await providerFunction(request)
                try lifetime.check(); try token.check()
                guard .now < deadline else { throw NativeShellError(.timeout, operation: "primary-provider-deadline") }
                reply.resolve(.success(material))
            } catch { reply.resolve(.failure(error)) }
        }
        tasks.install(taskID) { reply.cancel(); provider.cancel() }
        defer { provider.cancel(); reply.cancel() }
        let material = try NativeShellInteraction.wait(reply, token: token, lifetime: lifetime, deadline: deadline, tasks: tasks).get()
        try lifetime.check(); try token.check(); _ = try budget.remaining()
        let plan = try NativeShellAuthenticationPlan(primary: material, keyboard: nil)
        guard plan.method == source.method else { throw NativeShellError(.authentication, operation: "primary-method-mismatch") }
        return material
    }
}

final class NativeShellKeyboardOwner {
    let connection: OpaquePointer
    let handler: KeyboardHandler
    let token: CancellationToken
    let lifetime: CancellationToken
    let authenticationBudget: NativeShellAuthenticationBudget
    let tasks: NativeShellInteractionTasks
    var budget = NativeShellKeyboardBudget()
    var failure: (any Error)?
    init(connection: OpaquePointer, handler: @escaping KeyboardHandler, token: CancellationToken,
         lifetime: CancellationToken, authenticationBudget: NativeShellAuthenticationBudget,
         tasks: NativeShellInteractionTasks = NativeShellInteractionTasks()) {
        self.connection = connection; self.handler = handler; self.token = token
        self.lifetime = lifetime; self.authenticationBudget = authenticationBudget; self.tasks = tasks
    }
    /// Shared by actual callback and offline notification tests. No primary/saved reader exists.
    func answer(_ challenge: KeyboardChallenge) throws -> [Data] {
        try lifetime.check(); try token.check()
        let bytes = challenge.name.count + challenge.instruction.count + challenge.prompts.reduce(0) { $0 + $1.bytes.count }
        try budget.claim(prompts: challenge.prompts.count, bytes: bytes)
        let deadline = try authenticationBudget.interactionDeadline()
        let reply = ChallengeReply<[Data]>()
        let handler = handler, tasks = tasks, token = token, lifetime = lifetime
        try tasks.dispatch(cancel: { reply.cancel() }) {
            guard !token.isCancelled, !lifetime.isCancelled else { reply.cancel(); return }
            handler(challenge, reply)
        }
        let answers = try NativeShellInteraction.wait(reply, token: token, lifetime: lifetime, deadline: deadline, tasks: tasks)
        try lifetime.check(); try token.check(); _ = try authenticationBudget.remaining()
        guard answers.count == challenge.prompts.count, answers.allSatisfy({ $0.count <= 65536 }) else {
            throw FileServiceError(.authentication, operation: "shell-keyboard-answer-shape")
        }
        return answers // [] is success ONLY for an actual zero-prompt notification.
    }
    func answer(name: UnsafePointer<CChar>?, nameLength: Int32,
                instruction: UnsafePointer<CChar>?, instructionLength: Int32, count: Int32,
                prompts: UnsafePointer<LIBSSH2_USERAUTH_KBDINT_PROMPT>?,
                responses: UnsafeMutablePointer<LIBSSH2_USERAUTH_KBDINT_RESPONSE>?) -> Int32 {
        do {
            try lifetime.check(); try token.check()
            guard count >= 0, count <= 32, nameLength >= 0, nameLength <= 65536,
                  instructionLength >= 0, instructionLength <= 65536,
                  nameLength == 0 || name != nil, instructionLength == 0 || instruction != nil,
                  count == 0 || responses != nil else {
                throw FileServiceError(.resourceLimit, operation: "shell-keyboard-fields")
            }
            var items: [KeyboardPrompt] = []
            for index in 0..<Int(count) {
                guard let prompt = prompts?[index], prompt.length <= 65536,
                      prompt.length == 0 || prompt.text != nil else {
                    throw FileServiceError(.resourceLimit, operation: "shell-keyboard-prompt")
                }
                items.append(KeyboardPrompt(bytes: prompt.text.map { Data(bytes: $0, count: prompt.length) } ?? Data(), echo: prompt.echo != 0))
            }
            let challenge = KeyboardChallenge(name: name.map { Data(bytes: $0, count: Int(nameLength)) } ?? Data(),
                instruction: instruction.map { Data(bytes: $0, count: Int(instructionLength)) } ?? Data(), prompts: items)
            let answers = try answer(challenge)
            try lifetime.check(); try token.check()
            for (index, answer) in answers.enumerated() {
                let rc = answer.withUnsafeBytes {
                    rf_keyboard_set_response(connection, responses, Int32(index), $0.bindMemory(to: UInt8.self).baseAddress, answer.count)
                }
                guard rc == 0 else { throw FileServiceError(.authentication, operation: "shell-keyboard-response", code: Int64(rc)) }
            }
            return 0
        } catch { failure = error; token.cancel(); return -1 }
    }
}
let nativeShellKeyboardCallback: rf_keyboard_responder = { ctx, name, nlen, instruction, ilen, count, prompts, responses in
    guard let ctx else { return -1 }
    return Unmanaged<NativeShellKeyboardOwner>.fromOpaque(ctx).takeUnretainedValue().answer(
        name: name, nameLength: nlen, instruction: instruction, instructionLength: ilen,
        count: count, prompts: prompts, responses: responses)
}
