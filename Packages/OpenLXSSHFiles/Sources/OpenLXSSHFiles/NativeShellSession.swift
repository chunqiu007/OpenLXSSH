import COpenLXSSHFiles
import Darwin
import Foundation
import OpenLXSSHTrust

/// Internal, per-instance I/O-result seam for offline pump regressions only. No SSH peer,
/// authentication, packet API or native cleanup is replaced. Every callback must be nonblocking.
struct NativeShellPumpSteps: Sendable {
    typealias Step = @Sendable (OpaquePointer, OpaquePointer) -> Int32
    let now: @Sendable () -> ContinuousClock.Instant
    let poll: Step
    let write: @Sendable (OpaquePointer, UnsafePointer<CChar>, Int, OpaquePointer) -> Int32
    let read: @Sendable (OpaquePointer, UnsafeMutablePointer<CChar>, Int, OpaquePointer) -> Int32
    let exit: @Sendable (OpaquePointer, UnsafeMutablePointer<rf_shell_exit>, OpaquePointer) -> Int32
    let eof: Step
    let resize: @Sendable (OpaquePointer, Int32, Int32, OpaquePointer) -> Int32
    let sendEOF: Step
}
struct NativeShellPumpSnapshot: Sendable {
    let queuedWrites: Int
    let hasReader: Bool
    let hasControl: Bool
    let readBufferBytes: Int
    let pendingOutbound: Bool
    let nativePresent: Bool
    let nativeDisposals: Int
    let failure: NativeShellError?
}

private final class WatchFDGuard: @unchecked Sendable {
    private var fd: Int32
    private var remaining: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []
    init(fd: Int32, sources: Int) {
        self.fd = fd
        self.remaining = sources
    }
    /// Must run on the owning serial queue.
    func oneSourceCancelled() {
        remaining -= 1
        guard remaining == 0 else { return }
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
        let continuations = waiters
        waiters.removeAll()
        continuations.forEach { $0.resume() }
    }
    /// Must run on the owning serial queue.
    func waitClosed(_ continuation: CheckedContinuation<Void, Never>) {
        if remaining == 0 {
            continuation.resume()
        } else {
            waiters.append(continuation)
        }
    }
    deinit {
        if fd >= 0 { Darwin.close(fd) }
    }
}

/// Queue-owned kqueue-backed I/O & deadline driver for LibSSH2ShellSession.
/// Always owns an independent duplicated FD so `rf_connection_destroy` closing the primary
/// socket FD never races with kqueue registration.
private final class NativeShellEventDriver: @unchecked Sendable {
    private let fdGuard: WatchFDGuard
    private var readSource: (any DispatchSourceRead)?
    private var writeSource: (any DispatchSourceWrite)?
    private var timerSource: (any DispatchSourceTimer)?
    private var readActive = false
    private var writeActive = false
    private var timerActive = false
    private var closing = false

    init?(duplicating rawFD: Int32, queue: DispatchQueue, onEvent: @escaping @Sendable () -> Void) {
        guard rawFD >= 0 else { return nil }
        let dupFD = fcntl(rawFD, F_DUPFD_CLOEXEC, 0)
        guard dupFD >= 0 else { return nil }

        let guardBox = WatchFDGuard(fd: dupFD, sources: 3)
        self.fdGuard = guardBox

        let rSource = DispatchSource.makeReadSource(fileDescriptor: dupFD, queue: queue)
        let wSource = DispatchSource.makeWriteSource(fileDescriptor: dupFD, queue: queue)
        let tSource = DispatchSource.makeTimerSource(queue: queue)
        self.readSource = rSource
        self.writeSource = wSource
        self.timerSource = tSource

        let eventCallback: @Sendable () -> Void = { [weak self] in
            guard let self, !self.closing else { return }
            self.disarm()
            onEvent()
        }
        rSource.setEventHandler(handler: eventCallback)
        wSource.setEventHandler(handler: eventCallback)
        tSource.setEventHandler(handler: eventCallback)

        let cancelCallback: @Sendable () -> Void = {
            guardBox.oneSourceCancelled()
        }
        rSource.setCancelHandler(handler: cancelCallback)
        wSource.setCancelHandler(handler: cancelCallback)
        tSource.setCancelHandler(handler: cancelCallback)
    }

    func disarm() {
        guard !closing else { return }
        if readActive, let source = readSource {
            source.suspend()
            readActive = false
        }
        if writeActive, let source = writeSource {
            source.suspend()
            writeActive = false
        }
        if timerActive, let source = timerSource {
            source.suspend()
            timerActive = false
        }
    }

    func arm(read: Bool, write: Bool, deadline: ContinuousClock.Instant?, now: ContinuousClock.Instant) {
        guard !closing else { return }
        if read {
            if !readActive, let source = readSource {
                readActive = true
                source.resume()
            }
        } else if readActive, let source = readSource {
            source.suspend()
            readActive = false
        }

        if write {
            if !writeActive, let source = writeSource {
                writeActive = true
                source.resume()
            }
        } else if writeActive, let source = writeSource {
            source.suspend()
            writeActive = false
        }

        if let deadline, let source = timerSource {
            let remaining = now.duration(to: deadline)
            let (secs, attoseconds) = remaining.components
            let nanos: Int64
            if secs < 0 || (secs == 0 && attoseconds <= 0) {
                nanos = 0
            } else if secs > 3600 {
                nanos = 3600 * 1_000_000_000
            } else {
                nanos = secs * 1_000_000_000 + attoseconds / 1_000_000_000
            }
            let leeway: DispatchTimeInterval = nanos >= 1_000_000_000 ? .milliseconds(5) : .microseconds(500)
            source.schedule(deadline: .now() + .nanoseconds(Int(clamping: nanos)), repeating: .never, leeway: leeway)
            if !timerActive {
                timerActive = true
                source.resume()
            }
        } else if timerActive, let source = timerSource {
            source.suspend()
            timerActive = false
        }
    }

    func teardown() {
        guard !closing else { return }
        closing = true
        if let source = readSource {
            readSource = nil
            source.cancel()
            if !readActive {
                readActive = true
                source.resume()
            }
        }
        if let source = writeSource {
            writeSource = nil
            source.cancel()
            if !writeActive {
                writeActive = true
                source.resume()
            }
        }
        if let source = timerSource {
            timerSource = nil
            source.cancel()
            if !timerActive {
                timerActive = true
                source.resume()
            }
        }
    }

    func waitDrained(_ continuation: CheckedContinuation<Void, Never>) {
        fdGuard.waitClosed(continuation)
    }
}

private final class NativeShellResources: @unchecked Sendable {
    // Native calls are queue-owned. Only the bridge's atomic cancel may cross queues.
    private let lock = NSLock()
    private var storage: OpaquePointer?
    private var disposals = 0
    var connection: OpaquePointer? { lock.withLock { storage } }
    var disposalCount: Int { lock.withLock { disposals } }
    init(_ connection: OpaquePointer) { storage = connection }
    func cancel() { lock.withLock { if let storage { rf_connection_cancel(storage) } } }
    func dispose() {
        let owned = lock.withLock { let owned = storage; storage = nil; return owned }
        if let owned {
            rf_connection_destroy(owned)
            lock.withLock { disposals += 1 }
        }
    }
    deinit { dispose() }
}
private final class NativeShellWriteRequest {
    let bytes: NativeShellWriteBuffer
    let token: CancellationToken
    let deadline: ContinuousClock.Instant
    let continuation: CheckedContinuation<Void, any Error>
    init(_ data: Data, token: CancellationToken, timeout: TimeInterval, now: ContinuousClock.Instant,
         continuation: CheckedContinuation<Void, any Error>) {
        bytes = NativeShellWriteBuffer(data); self.token = token
        deadline = now.advanced(by: .seconds(timeout)); self.continuation = continuation
    }
}
private struct NativeShellReadRequest {
    let limit: Int
    let token: CancellationToken
    let deadline: ContinuousClock.Instant
    let continuation: CheckedContinuation<NativeShellReceive, any Error>
}
private enum NativeShellControl {
    case resize(NativeShellSize)
    case eof
}
private struct NativeShellControlRequest {
    let kind: NativeShellControl
    let token: CancellationToken
    let deadline: ContinuousClock.Instant
    let continuation: CheckedContinuation<Void, any Error>
}

/// Candidate shell transport, independent of AppKit/SwiftTerm and entirely separate from SFTP.
/// One private TCP connection, one actual handshake key, one typed primary attempt, at most one
/// distinct KI method, one session channel + xterm-256color PTY + shell. Never sends startup commands.
/// All native state has one serial queue; bounded async pull is the only output delivery mechanism.
public final class LibSSH2ShellSession: @unchecked Sendable {
    public static let maximumInputBytes = 256 * 1024
    public static let maximumOutputChunk = 64 * 1024
    public let sessionID = UUID()
    public let options: NativeShellOptions
    private let queue = DispatchQueue(label: "OpenLXSSH.NativeShell.libssh2", qos: .userInitiated)
    private let resources: NativeShellResources
    private let pumpSteps: NativeShellPumpSteps?
    private let useEventDrivenPump: Bool
    private func pumpNow() -> ContinuousClock.Instant { pumpSteps?.now() ?? .now }
    private let lifetime = CancellationToken()
    private let interactionTasks: NativeShellInteractionTasks
    /// One immutable-identity receipt shared by every failure from this session.
    public let interactionDrain: NativeShellDrainHandle
    private let trustAttempt: FileHostTrustAttempt
    private let activeLock = NSLock()
    private var activeSetupToken: CancellationToken?
    private let admission = NativeShellAdmission()
    // Everything below is queue-owned, never read directly from a UI/caller.
    private var ready = false
    private var established = false
    private var stages: [NativeShellAuthenticationStage] = []
    private var writes: [NativeShellWriteRequest] = []
    private var reader: NativeShellReadRequest?
    private var control: NativeShellControlRequest?
    private enum PendingOutbound { case write, read, control, exit }
    private var pendingOutbound: PendingOutbound?
    /// Only production creation configures a TCP socket. Offline pump seams have no receipt.
    public let tcpKeepalive: NativeTCPKeepaliveSnapshot?
    private var pumpTurn = 0
    private var readBuffer: UnsafeMutablePointer<CChar>?
    private var readLength = 0
    private var readProtocolDeadline: ContinuousClock.Instant?
    private var eofDelivered = false
    private var inputEOF = false
    private var pumping = false
    private var eventDriver: NativeShellEventDriver?
    private var terminalError: NativeShellError?

    convenience init(connectedSocket: Int32, options: NativeShellOptions,
                     interactionTasks: NativeShellInteractionTasks = NativeShellInteractionTasks(),
                     trustAttempt: FileHostTrustAttempt = FileHostTrustAttempt()) throws {
        try self.init(ownedSocket: connectedSocket, options: options, interactionTasks: interactionTasks,
                      trustAttempt: trustAttempt, pumpSteps: nil, useEventDrivenPump: true)
    }
    /// Only module-internal tests can select this local I/O state. It makes no authentication or
    /// shellReady claim, never handshakes, and retains real native/socket ownership for teardown.
    convenience init(offlinePumpSocket: Int32, options: NativeShellOptions, steps: NativeShellPumpSteps) throws {
        try self.init(ownedSocket: offlinePumpSocket, options: options, interactionTasks: NativeShellInteractionTasks(),
                      trustAttempt: FileHostTrustAttempt(), pumpSteps: steps, useEventDrivenPump: false)
        ready = true
    }
    /// Internal test seam exercising the real kqueue DispatchSource event driver over a local socketpair.
    convenience init(offlineEventDrivenPumpSocket: Int32, options: NativeShellOptions, steps: NativeShellPumpSteps) throws {
        try self.init(ownedSocket: offlineEventDrivenPumpSocket, options: options, interactionTasks: NativeShellInteractionTasks(),
                      trustAttempt: FileHostTrustAttempt(), pumpSteps: steps, useEventDrivenPump: true)
        ready = true
    }
    private init(ownedSocket: Int32, options: NativeShellOptions, interactionTasks: NativeShellInteractionTasks,
                 trustAttempt: FileHostTrustAttempt, pumpSteps: NativeShellPumpSteps?, useEventDrivenPump: Bool) throws {
        if pumpSteps == nil {
            var actual = rf_tcp_keepalive(), systemError: Int32 = 0
            let code = rf_tcp_keepalive_configure(ownedSocket, Int32(options.keepalive?.interval ?? 0),
                Int32(options.keepalive?.failedProbes ?? 1), &actual, &systemError)
            guard code == 0 else {
                throw NativeShellError(code == Int32(RF_INVALID) ? .invalidConfiguration : .unsupported,
                    operation: "tcp-keepalive-configure", code: systemError == 0 ? code : systemError)
            }
            tcpKeepalive = NativeTCPKeepaliveSnapshot(actual)
        } else { tcpKeepalive = nil }
        guard let connection = rf_connection_create(ownedSocket) else {
            throw NativeShellError(.transport, operation: "adopt-socket")
        }
        resources = NativeShellResources(connection); self.options = options; self.pumpSteps = pumpSteps
        self.useEventDrivenPump = useEventDrivenPump
        let tasks = interactionTasks
        self.interactionTasks = tasks; interactionDrain = NativeShellDrainHandle(tasks: tasks)
        self.trustAttempt = trustAttempt
    }
    func pumpSnapshot() async -> NativeShellPumpSnapshot {
        await withCheckedContinuation { continuation in
            queue.async {
                continuation.resume(returning: NativeShellPumpSnapshot(queuedWrites: self.writes.count,
                    hasReader: self.reader != nil, hasControl: self.control != nil, readBufferBytes: self.readLength,
                    pendingOutbound: self.pendingOutbound != nil,
                    nativePresent: self.resources.connection != nil, nativeDisposals: self.resources.disposalCount,
                    failure: self.terminalError))
            }
        }
    }
    deinit {
        lifetime.cancel(); interactionTasks.revoke(); interactionTasks.seal()
        // Destruction never blocks MainActor. Only these independent owners outlive the session.
        let resources = resources, tasks = interactionTasks, driver = eventDriver
        queue.async { driver?.teardown(); resources.dispose(); tasks.markNativeClosed() }
        readBuffer?.deallocate()
    }
    public var pendingInputBytes: Int { admission.pendingInputBytes }
    /// Terminal cancellation; no reconnect/reuse of interrupted libssh2 state.
    public func cancel() {
        lifetime.cancel(); admission.close(); resources.cancel(); interactionTasks.revoke(); interactionTasks.seal()
        activeLock.withLock { activeSetupToken?.cancel() }
        queue.async { self.fail(NativeShellError(.cancelled, operation: "cancel", stages: self.stages)) }
    }
    /// Returns only once queued work is revoked and native session/socket resources are released.
    /// Cancellation is checked during waits; cleanup itself must finish even if the caller is cancelled.
    public func close() async {
        cancel()
        await withCheckedContinuation { continuation in
            queue.async {
                self.fail(NativeShellError(.closed, operation: "close", stages: self.stages))
                self.disposeNative()
                if let driver = self.eventDriver {
                    driver.teardown()
                    driver.waitDrained(continuation)
                } else {
                    continuation.resume()
                }
            }
        }
        _ = await interactionTasks.drain()
    }
    /// Socket/session close is unconditional; a noncooperative caller-supplied provider may
    /// still be pending after bounded drain. Never report it released solely because close returned.
    public func interactionSnapshot() -> NativeShellInteractionSnapshot { interactionTasks.snapshot }
    public func authenticationStages() async -> [NativeShellAuthenticationStage] {
        await withCheckedContinuation { continuation in queue.async { continuation.resume(returning: self.stages) } }
    }
    public static func connect(configuration: SSHConnection, primary: FileAuthentication,
                               keyboardHandler: KeyboardHandler? = nil,
                               trustStore: HostTrustStore, trustHandler: FileHostTrustHandler?,
                               options: NativeShellOptions, connectionTimeout: TimeInterval = 10,
                               token: CancellationToken) async throws -> LibSSH2ShellSession {
        let plan = try NativeShellAuthenticationPlan(primary: primary, keyboard: keyboardHandler)
        return try await connect(configuration: configuration, primaryMethod: plan.method,
            primaryProvider: { _ in plan.primary }, keyboardHandler: keyboardHandler,
            trustStore: trustStore, trustHandler: trustHandler, options: options,
            connectionTimeout: connectionTimeout, token: token)
    }
    /// The provider is invoked once, only AFTER the actual handshake key is trusted and the
    /// selected method is advertised. It must validate its own current caller generation.
    public static func connect(configuration: SSHConnection, primaryMethod: NativeShellPrimaryMethod,
                               primaryProvider: @escaping NativeShellPrimaryProvider,
                               keyboardHandler: KeyboardHandler? = nil,
                               trustStore: HostTrustStore, trustHandler: FileHostTrustHandler?,
                               options: NativeShellOptions, connectionTimeout: TimeInterval = 10,
                               token: CancellationToken) async throws -> LibSSH2ShellSession {
        let source = NativeShellAuthenticationSource(method: primaryMethod, provider: primaryProvider, keyboard: keyboardHandler)
        try token.check()
        let socket = try await TCPConnector.connect(configuration.host, timeout: connectionTimeout, token: token)
        defer { socket.close() }
        let session = try LibSSH2ShellSession(connectedSocket: socket.descriptor, options: options)
        do {
            let identity = try ServerIdentity(host: configuration.host.address.value, port: configuration.host.port.value)
            let tasks = session.interactionTasks, lifetime = session.lifetime, attempt = session.trustAttempt
            try await session.establish(identity: identity, username: Data(configuration.user.value.utf8), source: source,
                hostKeyHandler: { key, reply in
                    SharedHostTrust.respond(to: key, reply: reply, identity: configuration.host, store: trustStore,
                        timeout: min(options.interactionTimeout, options.authenticationTimeout), token: token,
                        attempt: attempt, tasks: tasks, lifetime: lifetime, handler: trustHandler)
                }, token: token)
            return session
        } catch {
            await session.close()
            throw session.failureAfterClose(error, operation: "connect")
        }
    }
    /// Internal offline seam only. Public callers cannot bypass the shared-store same-handshake path.
    func establish(identity: ServerIdentity, username: Data, plan: NativeShellAuthenticationPlan,
                   hostKeyHandler: (@Sendable (HostKey, ChallengeReply<Bool>) -> Void)?,
                   token: CancellationToken) async throws {
        try await establish(identity: identity, username: username, source: NativeShellAuthenticationSource(plan: plan),
                            hostKeyHandler: hostKeyHandler, token: token)
    }
    func establish(identity: ServerIdentity, username: Data, source: NativeShellAuthenticationSource,
                   hostKeyHandler: (@Sendable (HostKey, ChallengeReply<Bool>) -> Void)?,
                   token: CancellationToken) async throws {
        guard pumpSteps == nil else { throw NativeShellError(.invalidConfiguration, operation: "offline-pump-establish") }
        guard !username.isEmpty, username.count <= 1024, !username.contains(0) else {
            throw NativeShellError(.invalidConfiguration, operation: "username")
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                queue.async {
                    do {
                        try self.checkTokens(token)
                        guard !self.established, let c = self.resources.connection else {
                            throw NativeShellError(.closed, operation: "already-established")
                        }
                        self.established = true
                        self.activeLock.withLock { self.activeSetupToken = token }
                        defer { self.activeLock.withLock { self.activeSetupToken = nil } }
                        try self.checkTokens(token)
                        try self.check(rf_handshake(c, token.native, self.options.operationTimeout), operation: "handshake")
                        var length = 0; var algorithm: Int32 = 0
                        guard let bytes = rf_hostkey(c, &length, &algorithm), length > 0, length <= 65536 else {
                            throw NativeShellError(.untrusted, operation: "handshake-host-key")
                        }
                        let budget = NativeShellAuthenticationBudget(options: self.options)
                        let key = HostKey(identity: identity, rawKey: Data(bytes: bytes, count: length), algorithmCode: algorithm)
                        guard let hostKeyHandler else { throw NativeShellError(.untrusted, operation: "host-key") }
                        let reply = ChallengeReply<Bool>()
                        let tasks = self.interactionTasks, lifetime = self.lifetime
                        try tasks.dispatch(cancel: { reply.cancel() }) {
                            guard !token.isCancelled, !lifetime.isCancelled else { reply.cancel(); return }
                            hostKeyHandler(key, reply)
                        }
                        let accepted = try NativeShellInteraction.wait(reply, token: token, lifetime: self.lifetime,
                                                                      deadline: budget.interactionDeadline(), tasks: tasks)
                        guard accepted else { throw NativeShellError(.untrusted, operation: "host-key") }
                        try self.checkTokens(token); _ = try budget.remaining()
                        try self.check(rf_trust_hostkey(c, 1), operation: "host-key")
                        let packetTimeout = Int32(ceil(try budget.remaining())) + 2
                        guard rf_shell_packet_read_timeout(c, packetTimeout) == packetTimeout else {
                            throw NativeShellError(.unsupported, operation: "packet-read-timeout")
                        }
                        try self.authenticate(c, username: username, source: source, budget: budget, token: token)
                        try self.checkTokens(token)
                        let setupReadTimeout = Int32(ceil(self.options.operationTimeout)) + 2
                        guard rf_shell_packet_read_timeout(c, setupReadTimeout) == setupReadTimeout else {
                            throw NativeShellError(.unsupported, operation: "shell-packet-read-timeout")
                        }
                        try self.check(rf_shell_open(c, token.native, self.options.operationTimeout), operation: "channel-open")
                        try self.check(rf_shell_request_pty(c, self.options.size.columns, self.options.size.rows,
                            token.native, self.options.operationTimeout), operation: "request-pty")
                        try self.check(rf_shell_start(c, token.native, self.options.operationTimeout), operation: "shell-start")
                        try self.checkTokens(token)
                        self.ready = true; self.stages.append(.shellReady)
                        continuation.resume()
                    } catch {
                        let typed = self.convert(error, operation: "establish")
                        self.fail(typed); continuation.resume(throwing: typed)
                    }
                }
            }
        } onCancel: { token.cancel(); self.cancel() }
    }
    private func authenticate(_ c: OpaquePointer, username: Data, source: NativeShellAuthenticationSource,
                              budget: NativeShellAuthenticationBudget, token: CancellationToken) throws {
        var methodBytes = [CChar](repeating: 0, count: 4096); var length = 0
        let discoveryTimeout = try budget.networkTimeout(options.operationTimeout)
        try username.withUnsafeBytes { user in
            // Only this initial none request. Never send another none after primary: that could
            // reset a server's partial chain. All retries below are only native EAGAIN continuation.
            try check(rf_auth_methods(c, user.baseAddress!.assumingMemoryBound(to: CChar.self), UInt32(username.count),
                &methodBytes, methodBytes.count, &length, token.native, discoveryTimeout), operation: "auth-methods")
        }
        try checkTokens(token); _ = try budget.remaining()
        let methods = Set(String(decoding: methodBytes.prefix(length).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            .split(separator: ",").map(String.init))
        stages.append(.advertised(password: methods.contains("password"), publicKey: methods.contains("publickey"),
                                  keyboardInteractive: methods.contains("keyboard-interactive")))
        // A server accepting none is not proof the explicitly selected primary was authenticated.
        guard rf_authenticated(c) == 0 else { throw NativeShellError(.unsupported, operation: "none-authentication", stages: stages) }
        let material = try NativeShellPrimaryGate().acquire(source: source, sessionID: sessionID, trusted: true,
            methods: methods, token: token, lifetime: lifetime, budget: budget, tasks: interactionTasks)
        try checkTokens(token)
        stages.append(.primaryStarted(source.method))
        let code = try primary(c, username: username, authentication: material,
                               timeout: budget.networkTimeout(options.operationTimeout), token: token)
        try checkTokens(token); _ = try budget.remaining()
        var authenticated = rf_authenticated(c) != 0
        stages.append(.primaryResult(source.method, code: code, authenticated: authenticated))
        if !authenticated {
            guard NativeShellAuthenticationPlan.mayContinueToKeyboard(code: code, authenticated: authenticated,
                                                                      hasHandler: source.keyboard != nil) else {
                try check(code, operation: "primary-authentication")
                throw NativeShellError(.authentication, operation: "primary-authentication", code: code, stages: stages)
            }
            try checkTokens(token)
            stages.append(.keyboardStarted)
            let keyboardOwner = NativeShellKeyboardOwner(connection: c, handler: source.keyboard!, token: token,
                lifetime: lifetime, authenticationBudget: budget, tasks: interactionTasks)
            let remaining = try budget.remaining()
            let keyboardCode = username.withUnsafeBytes { user in
                withExtendedLifetime(keyboardOwner) {
                    rf_shell_keyboard(c, user.baseAddress!.assumingMemoryBound(to: CChar.self), UInt32(username.count),
                        nativeShellKeyboardCallback, Unmanaged.passUnretained(keyboardOwner).toOpaque(), token.native,
                        options.operationTimeout, remaining)
                }
            }
            authenticated = rf_authenticated(c) != 0
            stages.append(.keyboardResult(code: keyboardCode, authenticated: authenticated))
            if let error = keyboardOwner.failure { throw error }
            try checkTokens(token); _ = try budget.remaining()
            try check(keyboardCode, operation: "keyboard-authentication")
        } else { try check(code, operation: "primary-authentication") }
        guard authenticated else { throw NativeShellError(.authentication, operation: "authentication", stages: stages) }
        stages.append(.authenticated)
    }
    private func primary(_ c: OpaquePointer, username: Data, authentication: FileAuthentication,
                         timeout: TimeInterval, token: CancellationToken) throws -> Int32 {
        username.withUnsafeBytes { user in
            let u = user.baseAddress!.assumingMemoryBound(to: CChar.self)
            switch authentication {
            case .password(let password):
                return withCStringBytes(password) { p in
                    rf_password(c, u, UInt32(username.count), p, UInt32(password.count), token.native, timeout)
                }
            case .publicKey(let publicKey, let privateKey, let passphrase):
                // Existing mature frommemory API handles encrypted PEM/OpenSSH formats supported
                // by the fixed libssh2/OpenSSL build. No custom key decoding or temporary files.
                return withCStringBytes(publicKey ?? Data()) { pub in
                    withCStringBytes(privateKey) { priv in withCStringBytes(passphrase ?? Data()) { pass in
                        rf_publickey(c, u, username.count, publicKey == nil ? nil : pub, publicKey?.count ?? 0,
                            priv, privateKey.count, pass, token.native, timeout)
                    } }
                }
            case .keyboardInteractive: return Int32(RF_INVALID)
            }
        }
    }
    private func withCStringBytes<T>(_ data: Data, _ body: (UnsafePointer<CChar>) -> T) -> T {
        var bytes = Array(data) + [0]
        defer { bytes.withUnsafeMutableBytes { rf_wipe($0.baseAddress, $0.count) } }
        return bytes.withUnsafeBytes { body($0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
    }

    /// Writes all supplied bytes or throws. Concurrent pending calls share a strict 256KiB/128-call
    /// admission bound. No startup text, prompt scanning, local shell or implicit retry on failure.
    public func write(_ data: Data, token: CancellationToken) async throws {
        try admission.reserveWrite(data.count)
        defer { admission.releaseWrite(data.count) }
        let cancelObserver = token.addCancelObserver { [weak self] in self?.wakePump() }
        defer { if let cancelObserver { token.removeCancelObserver(cancelObserver) } }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                queue.async {
                    do {
                        try self.requireReady(token)
                        self.writes.append(NativeShellWriteRequest(data, token: token, timeout: self.options.operationTimeout,
                                                                  now: self.pumpNow(), continuation: continuation))
                        self.schedulePump()
                    } catch { continuation.resume(throwing: self.convert(error, operation: "write")) }
                }
            }
        } onCancel: { token.cancel(); self.cancel() }
    }
    /// Exactly one outstanding consumer. Only allocates/reads when explicitly requested. Idle
    /// deadline returns wouldBlock without killing an otherwise quiet shell; each chunk <=64KiB.
    public func receive(maxBytes: Int = maximumOutputChunk, wait: TimeInterval = 0.25,
                        token: CancellationToken) async throws -> NativeShellReceive {
        guard maxBytes > 0, maxBytes <= Self.maximumOutputChunk, wait.isFinite, wait >= 0, wait <= 300 else {
            throw NativeShellError(.invalidConfiguration, operation: "receive-bounds")
        }
        try admission.reserveReceive(); defer { admission.releaseReceive() }
        let cancelObserver = token.addCancelObserver { [weak self] in self?.wakePump() }
        defer { if let cancelObserver { token.removeCancelObserver(cancelObserver) } }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    do {
                        try self.requireReady(token)
                        self.reader = NativeShellReadRequest(limit: maxBytes, token: token,
                            deadline: self.pumpNow().advanced(by: .seconds(wait)), continuation: continuation)
                        self.readBuffer = .allocate(capacity: maxBytes); self.readLength = maxBytes
                        self.schedulePump()
                    } catch { continuation.resume(throwing: self.convert(error, operation: "receive")) }
                }
            }
        } onCancel: { token.cancel(); self.cancel() }
    }
    public func resize(_ size: NativeShellSize, token: CancellationToken) async throws {
        try await submitControl(.resize(size), token: token)
    }
    /// SSH channel EOF is not the same as typing Ctrl-D into a remote PTY. No hidden input bytes.
    public func sendEOF(token: CancellationToken) async throws { try await submitControl(.eof, token: token) }
    private func submitControl(_ kind: NativeShellControl, token: CancellationToken) async throws {
        try admission.reserveControl(); defer { admission.releaseControl() }
        let cancelObserver = token.addCancelObserver { [weak self] in self?.wakePump() }
        defer { if let cancelObserver { token.removeCancelObserver(cancelObserver) } }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                queue.async {
                    do {
                        try self.requireReady(token)
                        self.control = NativeShellControlRequest(kind: kind, token: token,
                            deadline: self.pumpNow().advanced(by: .seconds(self.options.operationTimeout)), continuation: continuation)
                        self.schedulePump()
                    } catch { continuation.resume(throwing: self.convert(error, operation: "control")) }
                }
            }
        } onCancel: { token.cancel(); self.cancel() }
    }
    private func wakePump() {
        queue.async { self.schedulePump() }
    }
    private func schedulePump() {
        guard !pumping else { return }; pumping = true
        eventDriver?.disarm()
        queue.async { self.pump() }
    }
    private func ensureEventDriver(_ c: OpaquePointer) throws -> NativeShellEventDriver {
        if let driver = eventDriver { return driver }
        let rawFD = rf_connection_socket(c)
        guard let driver = NativeShellEventDriver(duplicating: rawFD, queue: queue, onEvent: { [weak self] in
            guard let self, !self.pumping else { return }
            self.pump()
        }) else {
            throw NativeShellError(.transport, operation: "poll", stages: stages)
        }
        eventDriver = driver
        return driver
    }
    private func earliestDeadline() -> ContinuousClock.Instant? {
        var earliest: ContinuousClock.Instant?
        func consider(_ candidate: ContinuousClock.Instant) {
            if let current = earliest {
                if candidate < current { earliest = candidate }
            } else {
                earliest = candidate
            }
        }
        for request in writes { consider(request.deadline) }
        if let control { consider(control.deadline) }
        if let readProtocolDeadline { consider(readProtocolDeadline) }
        if pendingOutbound == nil, let reader { consider(reader.deadline) }
        return earliest
    }
    private func pump() {
        pumping = false
        guard ready, let c = resources.connection else { return }
        do {
            try checkTokens(lifetime)
            for request in writes {
                try checkTokens(request.token)
                guard pumpNow() < request.deadline else { throw NativeShellError(.timeout, operation: "write", stages: stages) }
            }
            if let reader { try checkTokens(reader.token) }
            if let deadline = readProtocolDeadline, pumpNow() >= deadline {
                throw NativeShellError(.timeout, operation: "read-window-adjust", stages: stages)
            }
            if let control {
                try checkTokens(control.token)
                guard pumpNow() < control.deadline else { throw NativeShellError(.timeout, operation: "control", stages: stages) }
            }
            var madeProgress = false
            var readReturnedEAGAIN = false
            // A pending transport packet must resume the same API with stable arguments before
            // any other outbound operation (including read's receive-window adjustment).
            if let pending = pendingOutbound {
                switch pending {
                case .write: madeProgress = try pumpWrite(c)
                case .read, .exit:
                    let outcome = try pumpRead(c)
                    madeProgress = outcome.progressed
                    readReturnedEAGAIN = outcome.eagain
                case .control: madeProgress = try pumpControl(c)
                }
            } else {
                // Each class gets at most one bounded API step per tick. Rotate first priority
                // so continuous shell input cannot indefinitely starve resize/read.
                let first = pumpTurn; pumpTurn = (pumpTurn + 1) % 3
                for offset in 0..<3 where ready && pendingOutbound == nil {
                    switch (first + offset) % 3 {
                    case 0:
                        if !writes.isEmpty, try pumpWrite(c) { madeProgress = true }
                    case 1:
                        if control != nil, try pumpControl(c) { madeProgress = true }
                    default:
                        if reader != nil {
                            let outcome = try pumpRead(c)
                            if outcome.progressed { madeProgress = true }
                            if outcome.eagain { readReturnedEAGAIN = true }
                        }
                    }
                }
            }
            if ready && (!writes.isEmpty || reader != nil || control != nil) {
                if !useEventDrivenPump {
                    pumping = true
                    // Offline scripted pump tests advance virtual clocks without real socket I/O.
                    queue.asyncAfter(deadline: .now() + .milliseconds(5)) { [weak self] in self?.pump() }
                } else if madeProgress {
                    pumping = true
                    queue.async { self.pump() }
                } else {
                    let events = pumpSteps?.poll(c, lifetime.native) ?? rf_shell_poll(c, lifetime.native)
                    try check(events, operation: "poll")
                    if !readReturnedEAGAIN && pendingOutbound == nil && reader != nil && !eofDelivered
                        && (events & Int32(RF_SHELL_POLL_BUFFERED)) != 0 {
                        pumping = true
                        queue.async { self.pump() }
                    } else {
                        var wantRead = (events & Int32(RF_SHELL_POLL_INBOUND)) != 0
                        let wantWrite = (events & Int32(RF_SHELL_POLL_OUTBOUND)) != 0
                        if !wantRead && !wantWrite { wantRead = true }
                        let now = pumpNow()
                        let deadline = earliestDeadline()
                        if let deadline, deadline <= now {
                            pumping = true
                            queue.async { self.pump() }
                        } else {
                            // Kernel TCP keepalive runs independently; no app idle timer kills a quiet shell.
                            let driver = try ensureEventDriver(c)
                            driver.arm(read: wantRead, write: wantWrite, deadline: deadline, now: now)
                        }
                    }
                }
            }
        } catch { fail(convert(error, operation: "io")) }
    }
    private func outboundBlocked(_ c: OpaquePointer) throws -> Bool {
        let events = pumpSteps?.poll(c, lifetime.native) ?? rf_shell_poll(c, lifetime.native); try check(events, operation: "poll")
        return events & Int32(RF_SHELL_POLL_OUTBOUND) != 0
    }
    private func pumpWrite(_ c: OpaquePointer) throws -> Bool {
        guard let request = writes.first else { return false }
        guard !inputEOF else { throw NativeShellError(.closed, operation: "input-eof", stages: stages) }
        let rc = pumpSteps?.write(c, request.bytes.stepPointer, request.bytes.stepLength, lifetime.native)
            ?? rf_shell_write_step(c, request.bytes.stepPointer, request.bytes.stepLength, lifetime.native)
        if rc == Int32(LIBSSH2_ERROR_EAGAIN) || rc == 0 {
            // Preserve exact pointer/length even if EAGAIN was inbound-only (remote window).
            pendingOutbound = try outboundBlocked(c) ? .write : nil
            return false
        }
        pendingOutbound = nil; try check(rc, operation: "write")
        guard Int(rc) <= request.bytes.stepLength else { throw NativeShellError(.protocolFailure, operation: "write-count") }
        request.bytes.advance(Int(rc))
        if request.bytes.complete { writes.removeFirst(); request.continuation.resume() }
        return true
    }
    private func finishRead(_ value: NativeShellReceive) {
        let request = reader; reader = nil
        readBuffer?.deallocate(); readBuffer = nil; readLength = 0
        request?.continuation.resume(returning: value)
    }
    private func pumpRead(_ c: OpaquePointer) throws -> (progressed: Bool, eagain: Bool) {
        guard let request = reader, let buffer = readBuffer else { return (false, false) }
        if eofDelivered {
            var result = rf_shell_exit()
            let rc = pumpSteps?.exit(c, &result, lifetime.native) ?? rf_shell_exit_step(c, &result, lifetime.native)
            if rc == Int32(LIBSSH2_ERROR_EAGAIN) {
                if try outboundBlocked(c) {
                    pendingOutbound = .exit
                    if readProtocolDeadline == nil { readProtocolDeadline = pumpNow().advanced(by: .seconds(options.operationTimeout)) }
                    return (false, true)
                }
                pendingOutbound = nil; readProtocolDeadline = nil
                if pumpNow() >= request.deadline { finishRead(.wouldBlock); return (true, false) }
                return (false, true)
            }
            pendingOutbound = nil; readProtocolDeadline = nil
            try check(rc, operation: "exit-status")
            let signal: Data? = withUnsafeBytes(of: &result.signal) { raw in
                result.signal_length == 0 ? nil : Data(raw.prefix(result.signal_length))
            }
            let exit = NativeShellExit(reportedStatus: Int32(result.status), signal: signal)
            // No exit continuation until local native resources have actually gone away.
            ready = false; admission.close(); disposeNative()
            finishRead(.exit(exit))
            fail(NativeShellError(.closed, operation: "remote-exit", stages: stages))
            return (true, false)
        }
        let rc = pumpSteps?.read(c, buffer, readLength, lifetime.native) ?? rf_shell_read_step(c, buffer, readLength, lifetime.native)
        if rc == Int32(LIBSSH2_ERROR_EAGAIN) {
            if try outboundBlocked(c) {
                pendingOutbound = .read
                if readProtocolDeadline == nil { readProtocolDeadline = pumpNow().advanced(by: .seconds(options.operationTimeout)) }
                return (false, true)
            }
            pendingOutbound = nil; readProtocolDeadline = nil
            if pumpNow() >= request.deadline { finishRead(.wouldBlock); return (true, false) }
            return (false, true)
        }
        pendingOutbound = nil; readProtocolDeadline = nil; try check(rc, operation: "read")
        if rc > 0 {
            finishRead(.bytes(Data(bytes: buffer, count: Int(rc)))); return (true, false)
        }
        let eof = pumpSteps?.eof(c, lifetime.native) ?? rf_shell_eof(c, lifetime.native); try check(eof, operation: "eof")
        if eof != 0 { eofDelivered = true; finishRead(.eof); return (true, false) }
        if pumpNow() >= request.deadline { finishRead(.wouldBlock); return (true, false) }
        return (false, false)
    }
    private func pumpControl(_ c: OpaquePointer) throws -> Bool {
        guard let request = control else { return false }
        let rc: Int32
        switch request.kind {
        case .resize(let size):
            rc = pumpSteps?.resize(c, size.columns, size.rows, lifetime.native)
                ?? rf_shell_resize_step(c, size.columns, size.rows, lifetime.native)
        case .eof: rc = pumpSteps?.sendEOF(c, lifetime.native) ?? rf_shell_send_eof_step(c, lifetime.native)
        }
        if rc == Int32(LIBSSH2_ERROR_EAGAIN) { pendingOutbound = .control; return false }
        pendingOutbound = nil; try check(rc, operation: "control")
        if case .eof = request.kind { inputEOF = true }
        control = nil; request.continuation.resume()
        return true
    }
    private func requireReady(_ token: CancellationToken) throws {
        try checkTokens(token)
        guard ready, resources.connection != nil else {
            throw terminalError ?? NativeShellError(.closed, operation: "shell-not-ready", stages: stages)
        }
    }
    private func checkTokens(_ token: CancellationToken) throws { try lifetime.check(); try token.check() }
    private func check(_ code: Int32, operation: String) throws {
        guard code < 0 else { return }
        let kind: NativeShellError.Kind
        switch code {
        case Int32(RF_CANCELLED): kind = .cancelled
        case Int32(RF_TIMEOUT), Int32(LIBSSH2_ERROR_TIMEOUT): kind = .timeout
        case Int32(RF_CLOSED): kind = .closed
        case Int32(RF_UNTRUSTED): kind = .untrusted
        case Int32(RF_INVALID): kind = .invalidConfiguration
        case Int32(LIBSSH2_ERROR_AUTHENTICATION_FAILED), Int32(LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED),
             Int32(LIBSSH2_ERROR_KEYFILE_AUTH_FAILED), Int32(LIBSSH2_ERROR_PASSWORD_EXPIRED): kind = .authentication
        default: kind = .transport
        }
        throw NativeShellError(kind, operation: operation, code: code, stages: stages)
    }
    /// Snapshot-only enrichment after close: reads no native state and never retains the session
    /// through the returned error. Also used by offline Bool-bridge regression tests.
    func failureAfterClose(_ error: any Error, operation: String) -> NativeShellError {
        let typed = Self.convert(error, operation: operation, stages: [])
        return NativeShellError(typed.kind, operation: typed.operation, code: typed.code,
            stages: typed.authenticationStages, pendingInteractionTasks: interactionTasks.snapshot.pendingTasks,
            changedHostKey: typed.changedHostKey ?? trustAttempt.changedHostKey, interactionDrain: interactionDrain)
    }
    private static func convert(_ error: any Error, operation: String,
                                stages: [NativeShellAuthenticationStage]) -> NativeShellError {
        if let typed = error as? NativeShellError {
            return NativeShellError(typed.kind, operation: typed.operation, code: typed.code,
                stages: typed.authenticationStages.isEmpty ? stages : typed.authenticationStages,
                pendingInteractionTasks: typed.pendingInteractionTasks, changedHostKey: typed.changedHostKey,
                interactionDrain: typed.interactionDrain)
        }
        if let typed = error as? FileServiceError {
            let kind: NativeShellError.Kind
            switch typed.kind {
            case .cancelled: kind = .cancelled
            case .timeout: kind = .timeout
            case .untrusted: kind = .untrusted
            case .authentication: kind = .authentication
            case .closed: kind = .closed
            case .resourceLimit: kind = .resourceLimit
            default: kind = .transport
            }
            return NativeShellError(kind, operation: typed.operation, code: typed.code.flatMap(Int32.init(exactly:)),
                                    stages: stages, changedHostKey: typed.changedHostKey)
        }
        return NativeShellError(.transport, operation: operation, stages: stages)
    }
    private func convert(_ error: any Error, operation: String) -> NativeShellError {
        let typed = Self.convert(error, operation: operation, stages: stages)
        return NativeShellError(typed.kind, operation: typed.operation, code: typed.code,
            stages: typed.authenticationStages, pendingInteractionTasks: interactionTasks.snapshot.pendingTasks,
            changedHostKey: typed.changedHostKey ?? trustAttempt.changedHostKey,
            interactionDrain: typed.interactionDrain ?? interactionDrain)
    }
    private func disposeNative() {
        eventDriver?.teardown()
        resources.dispose()
        interactionTasks.markNativeClosed()
    }
    private func fail(_ error: NativeShellError) {
        lifetime.cancel()
        activeLock.withLock { activeSetupToken?.cancel() }
        ready = false; admission.close(); pendingOutbound = nil; readProtocolDeadline = nil
        interactionTasks.revoke(); interactionTasks.seal(); disposeNative()
        let failure = convert(error, operation: error.operation)
        if terminalError == nil { terminalError = failure }
        let pendingWrites = writes; writes.removeAll()
        let pendingReader = reader; reader = nil
        let pendingControl = control; control = nil
        readBuffer?.deallocate(); readBuffer = nil; readLength = 0
        pendingWrites.forEach { $0.continuation.resume(throwing: failure) }
        pendingReader?.continuation.resume(throwing: failure)
        pendingControl?.continuation.resume(throwing: failure)
    }
}
