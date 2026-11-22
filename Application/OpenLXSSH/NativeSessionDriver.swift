import AppKit
import Foundation
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust

/// A test substitution boundary, not a second SSH implementation. Production is always
/// LibSSH2ShellSession. Logical tests must not claim real SSH/shell interoperability.
protocol NativeSessionTransport: AnyObject, Sendable {
    func receive(maxBytes: Int, wait: TimeInterval, token: CancellationToken) async throws -> NativeShellReceive
    func write(_ bytes: Data, token: CancellationToken) async throws
    func resize(_ size: NativeShellSize, token: CancellationToken) async throws
    func cancel()
    func close() async
    @MainActor var interactionsDrained: Bool { get }
    var retirementDrain: any SessionDrainObserving { get }
    var transportKeepalive: NativeTCPKeepaliveSnapshot? { get }
}
extension NativeSessionTransport {
    var transportKeepalive: NativeTCPKeepaliveSnapshot? { nil }
}
extension LibSSH2ShellSession: NativeSessionTransport {
    var transportKeepalive: NativeTCPKeepaliveSnapshot? { tcpKeepalive }
    var interactionsDrained: Bool { interactionSnapshot().drained }
    var retirementDrain: any SessionDrainObserving { CanonicalSessionDrain(handle: interactionDrain) }
}

struct SessionDrainSnapshot: Equatable, Sendable {
    let pendingTasks: Int
    let pendingProviders: Int
    let revoked: Bool
    let nativeClosed: Bool
    let producersSealed: Bool
    var drained: Bool { nativeClosed && producersSealed && pendingTasks == 0 }
    var safeToRetire: Bool { nativeClosed && revoked && producersSealed }

    init(_ value: NativeShellInteractionSnapshot) {
        pendingTasks = value.pendingTasks
        pendingProviders = value.pendingProviders
        revoked = value.revoked
        nativeClosed = value.nativeClosed
        producersSealed = value.producersSealed
    }

    init(pendingTasks: Int, pendingProviders: Int, revoked: Bool, nativeClosed: Bool, producersSealed: Bool) {
        self.pendingTasks = pendingTasks
        self.pendingProviders = pendingProviders
        self.revoked = revoked
        self.nativeClosed = nativeClosed
        self.producersSealed = producersSealed
    }
}

/// Only this read-only observation seam is substituted by App logic tests. Production
/// always wraps the session/error's canonical handle, never an App-created native fact.
protocol SessionDrainObserving: Sendable {
    var id: UUID { get }
    var snapshot: SessionDrainSnapshot { get }
    func observeCompletion(_ callback: @escaping @Sendable (SessionDrainSnapshot) -> Void) throws -> UUID
    func removeCompletionObserver(_ id: UUID)
}

struct CanonicalSessionDrain: SessionDrainObserving {
    let handle: NativeShellDrainHandle
    var id: UUID { handle.id }
    var snapshot: SessionDrainSnapshot { SessionDrainSnapshot(handle.snapshot) }
    func observeCompletion(_ callback: @escaping @Sendable (SessionDrainSnapshot) -> Void) throws -> UUID {
        try handle.observeCompletion { callback(SessionDrainSnapshot($0)) }
    }
    func removeCompletionObserver(_ id: UUID) { handle.removeCompletionObserver(id) }
}

struct SessionRetirementTicket: Equatable, Sendable {
    let token: SessionToken
    let drain: any SessionDrainObserving
    var handleID: UUID { drain.id }
    var snapshot: SessionDrainSnapshot { drain.snapshot }
    static func == (lhs: Self, rhs: Self) -> Bool { lhs.token == rhs.token && lhs.handleID == rhs.handleID }
}

struct SessionCloseContext: Equatable, Sendable {
    enum Reason: String, Sendable {
        case preparing, setupPending, nativeUnknown, producerUnsealed
        case interactionTrackingUnavailable, legacyPending, observationCancelled, terminalPending
    }
    let token: SessionToken?
    let reason: Reason
    let drain: SessionDrainSnapshot?
}

enum SessionCloseResult: Equatable, Sendable {
    case closed
    case retired(SessionRetirementTicket)
    case incomplete(SessionCloseContext)
    var permitsRemoval: Bool {
        if case .incomplete = self { return false }
        return true
    }
}

struct SessionTrackingReservation: Hashable, Sendable { let id = UUID() }

/// Bounded accounting, not a host catalog limit. Retired entries contain no Run, view,
/// transport, primary reader or cancellation/reply capability.
@MainActor final class SessionRetirementRegistry {
    static let shared = SessionRetirementRegistry()
    let maximumActive: Int
    let maximumTotal: Int
    private var active = Set<SessionTrackingReservation>()
    private var retired: [SessionTrackingReservation: (ticket: SessionRetirementTicket, observer: UUID)] = [:]

    init(maximumActive: Int = 64, maximumTotal: Int = 128) {
        self.maximumActive = maximumActive
        self.maximumTotal = maximumTotal
    }

    var activeCount: Int { active.count }
    var retiredCount: Int { retired.count }

    func reserve() throws -> SessionTrackingReservation {
        guard active.count < maximumActive, active.count + retired.count < maximumTotal else {
            throw NativeShellError(.resourceLimit, operation: "app-cleanup-capacity")
        }
        let value = SessionTrackingReservation()
        active.insert(value)
        return value
    }

    func release(_ value: SessionTrackingReservation) {
        active.remove(value)
        if let entry = retired.removeValue(forKey: value) {
            entry.ticket.drain.removeCompletionObserver(entry.observer)
        }
    }

    func retire(_ value: SessionTrackingReservation, ticket: SessionRetirementTicket) throws {
        if let existing = retired[value] {
            guard existing.ticket == ticket else { throw TransportError.stale }
            return
        }
        guard active.contains(value), ticket.snapshot.safeToRetire else { throw TransportError.stale }
        let token = ticket.token
        let handleID = ticket.handleID
        let observer = try ticket.drain.observeCompletion { [weak self] snapshot in
            guard snapshot.drained else { return }
            Task { @MainActor [weak self] in
                self?.completed(value, token: token, handleID: handleID)
            }
        }
        active.remove(value)
        retired[value] = (ticket, observer)
        if ticket.snapshot.drained {
            completed(value, token: ticket.token, handleID: ticket.handleID)
        }
    }

    private func completed(_ value: SessionTrackingReservation, token: SessionToken, handleID: UUID) {
        guard let entry = retired[value],
              entry.ticket.token == token,
              entry.ticket.handleID == handleID,
              entry.ticket.snapshot.drained else { return }
        release(value)
    }

    isolated deinit {
        for entry in retired.values {
            entry.ticket.drain.removeCompletionObserver(entry.observer)
        }
    }
}
struct NativeSessionPrimaryRequest: Sendable {
    let sessionID: UUID
    let requestID: UUID
    let method: NativeShellPrimaryMethod
    let token: CancellationToken
}
typealias NativeSessionPrimaryProvider = @Sendable (NativeSessionPrimaryRequest) async throws -> FileAuthentication
struct NativeSessionConnect: Sendable {
    let configuration: SSHConnection
    let method: NativeShellPrimaryMethod
    let primary: NativeSessionPrimaryProvider
    let keyboard: FilesKeyboardHandler
    let trust: FileHostTrustHandler
    let options: NativeShellOptions
    let connectionTimeout: TimeInterval
    let token: CancellationToken
}
protocol NativeSessionConnecting: Sendable {
    func connect(_ request: NativeSessionConnect) async throws -> any NativeSessionTransport
}
struct NativeSessionConnectionFailure: Error {
    let failure: any Error
    let drain: (any SessionDrainObserving)?
    /// Only the connection boundary that actually knows no native owner was created
    /// may assert this. A missing handle or a zero pending count is not that proof.
    let noNativeOwnerCreated: Bool
}
struct NativeLibraryConnector: NativeSessionConnecting {
    let store: HostTrustStore
    func connect(_ request: NativeSessionConnect) async throws -> any NativeSessionTransport {
        do {
            return try await LibSSH2ShellSession.connect(configuration: request.configuration, primaryMethod: request.method,
                primaryProvider: { value in
                    try await request.primary(NativeSessionPrimaryRequest(sessionID: value.sessionID, requestID: value.requestID,
                        method: value.method, token: value.token))
                }, keyboardHandler: { challenge, reply in
                    request.keyboard(FilesKeyboardChallenge(name: challenge.name, instruction: challenge.instruction,
                        prompts: challenge.prompts.map { ($0.bytes, $0.echo) }), reply)
                }, trustStore: store,
                trustHandler: request.trust, options: request.options, connectionTimeout: request.connectionTimeout,
                token: request.token)
        } catch is CancellationError {
            // At this exact public library boundary token/TCP errors precede session
            // adoption. After adoption connect catches every error and returns a typed
            // NativeShellError with its canonical receipt. Do not infer this for arbitrary
            // NativeSessionConnecting implementations, or for adopt failures without a handle.
            throw NativeSessionConnectionFailure(failure: CancellationError(), drain: nil, noNativeOwnerCreated: true)
        } catch let error as FileServiceError {
            throw NativeSessionConnectionFailure(failure: error, drain: nil, noNativeOwnerCreated: true)
        }
    }
}

/// No child process exists on this backend. nil ownedPID is a fact, not evidence that
/// native resources or asynchronous interaction providers have drained.
struct NativeSessionDriverSnapshot: Equatable {
    let token: SessionToken?
    let ownedPID: Int32? = nil
    let pendingInputBytes: Int
    let pendingInputItems: Int
    let receiveInFlight: Bool
    let resizeInFlight: Bool
    let hasLatestResize: Bool
    let nativeCloseCompleted: Bool
    let interactionsDrained: Bool
    let lastCloseOrigin: SessionCloseOrigin?
    let connectedSeconds: Int?
    let tcpKeepalive: NativeTCPKeepaliveSnapshot?
}

/// A cancellation-aware single response for a typed primary prompt. The exact protocol
/// bytes never pass through a UI string; only a manually entered answer is encoded.
@MainActor private final class NativePrimaryReply {
    private var result: Result<OpenLXSSHSecurity.SecretBytes, any Error>?
    private var waiter: CheckedContinuation<OpenLXSSHSecurity.SecretBytes, any Error>?

    func resolve(_ result: Result<OpenLXSSHSecurity.SecretBytes, any Error>) {
        guard self.result == nil else { return }
        self.result = result
        let continuation = waiter
        waiter = nil
        continuation?.resume(with: result)
    }

    func cancel() {
        resolve(.failure(CancellationError()))
    }

    func wait() async throws -> OpenLXSSHSecurity.SecretBytes {
        if let result { return try result.get() }
        if Task.isCancelled {
            cancel()
            throw CancellationError()
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if let result {
                    continuation.resume(with: result)
                } else if Task.isCancelled {
                    cancel()
                    continuation.resume(throwing: CancellationError())
                } else {
                    waiter = continuation
                }
            }
        } onCancel: {
            Task { @MainActor in self.cancel() }
        }
    }

    isolated deinit {
        cancel()
    }
}

/// This object physically owns only manual KI and trust mailboxes, never a primary
/// authorization/provider, saved-credential reader, key material, or transient intent.
@MainActor private final class NativeSessionChallenges {
    let token: SessionToken
    let cancellation: CancellationToken
    private(set) var active = true
    private var trust: (SessionTrustPrompt, ChallengeReply<FileHostTrustAnswer>)?
    private var keyboard: (SessionAuthenticationPrompt, ChallengeReply<[Data]>)?
    var onTrust: ((SessionTrustPrompt) -> Void)?
    var onChanged: ((ChangedHostKey) -> Void)?
    var onKeyboard: ((SessionAuthenticationPrompt) -> Void)?

    init(token: SessionToken, cancellation: CancellationToken) {
        self.token = token
        self.cancellation = cancellation
    }

    func receiveTrust(_ event: FileHostTrustEvent, reply: ChallengeReply<FileHostTrustAnswer>, host: HostIdentity) {
        // A verified rejection remains a fact after native cleanup cancels its token. Owner
        // revocation still wins through active, and the driver revalidates run/token/endpoint.
        if case .changed(let change) = event {
            reply.cancel()
            guard active, change.host == host else { return }
            onChanged?(change)
            return
        }
        guard active, !cancellation.isCancelled, trust == nil, keyboard == nil else {
            reply.cancel()
            return
        }
        let prompt: SessionTrustPrompt
        switch event {
        case .pending(let decision):
            guard decision.host == host else {
                cancellation.cancel()
                reply.cancel()
                return
            }
            prompt = SessionTrustPrompt(
                token: token,
                id: decision.id,
                host: decision.host,
                algorithm: decision.algorithm,
                fingerprint: decision.fingerprint,
                source: "当前 libssh2 同一握手实际公钥；不是预扫"
            )
            trust = (prompt, reply)
        case .changed:
            return
        }
        onTrust?(prompt)
    }

    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) throws {
        guard active, !cancellation.isCancelled, let pending = trust, pending.0 == prompt,
              prompt.token == token, prompt.changed == nil else { throw TransportError.stale }
        trust = nil
        let answer: FileHostTrustAnswer = persistence == .once
            ? .confirmOnce(displayedFingerprint: prompt.fingerprint)
            : .confirm(displayedFingerprint: prompt.fingerprint)
        guard pending.1.resolve(answer) else { throw TransportError.stale }
    }

    func receiveKeyboard(_ challenge: FilesKeyboardChallenge, reply: ChallengeReply<[Data]>) {
        guard active, !cancellation.isCancelled, trust == nil, keyboard == nil, challenge.prompts.count <= 32 else {
            cancellation.cancel()
            reply.cancel()
            return
        }
        let prompt = SessionAuthenticationPrompt(
            token: token,
            id: UUID(),
            payload: .keyboard(
                name: SafePrompt.display(String(decoding: challenge.name, as: UTF8.self)),
                instruction: SafePrompt.display(String(decoding: challenge.instruction, as: UTF8.self)),
                prompts: challenge.prompts.map {
                    SessionKeyboardField(text: SafePrompt.display(String(decoding: $0.bytes, as: UTF8.self)), echo: $0.echo)
                }
            )
        )
        keyboard = (prompt, reply)
        onKeyboard?(prompt)
    }

    func answer(_ values: [OpenLXSSHSecurity.SecretBytes], prompt: SessionAuthenticationPrompt) throws {
        guard active, !cancellation.isCancelled, let pending = keyboard, pending.0 == prompt,
              prompt.token == token, case .keyboard(_, _, let fields) = prompt.payload,
              fields.count == values.count, values.count <= 32,
              values.allSatisfy({ $0.withUnsafeBytes { $0.count <= 65536 } }) else { throw TransportError.stale }
        let bytes = values.map { $0.withUnsafeBytes { Data($0) } }
        keyboard = nil
        guard pending.1.resolve(bytes) else { throw TransportError.stale }
    }

    func revoke() {
        active = false
        // Empty answers are valid for a zero-prompt notification, never cancellation.
        cancellation.cancel()
        trust?.1.cancel()
        keyboard?.1.cancel()
        trust = nil
        keyboard = nil
        onTrust = nil
        onChanged = nil
        onKeyboard = nil
    }
}

private final class NativeTrustEventRecord: @unchecked Sendable {
    private let lock = NSLock()
    private var change: ChangedHostKey?
    func record(_ event: FileHostTrustEvent) {
        if case .changed(let value) = event {
            lock.withLock { change = value }
        }
    }
    var changed: ChangedHostKey? { lock.withLock { change } }
}

/// Revocable authentication work may outlive its UI while an external reader ignores
/// cancellation. It never owns a driver, Run, terminal or transport; UI delivery is weak.
@MainActor private final class NativePrimaryOwner {
    let token: SessionToken
    let cancellation: CancellationToken
    let host: HostConfiguration
    let repository: any AppRepositoryProtocol
    let security: SecurityCoordinator
    let authorization: SessionPrimaryAuthorization
    private(set) var active = true
    private(set) var pending = 0
    private var requestID: UUID?
    private var nativeID: UUID?
    private var reply: NativePrimaryReply?
    private var prompt: SessionAuthenticationPrompt?
    var present: ((SessionAuthenticationPrompt) -> Void)?

    init(token: SessionToken, cancellation: CancellationToken, host: HostConfiguration,
         repository: any AppRepositoryProtocol, security: SecurityCoordinator, authorization: SessionPrimaryAuthorization) {
        self.token = token
        self.cancellation = cancellation
        self.host = host
        self.repository = repository
        self.security = security
        self.authorization = authorization
    }

    func revoke() {
        active = false
        authorization.revoke()
        reply?.cancel()
        reply = nil
        prompt = nil
        present = nil
    }

    func discardAuthorization() {
        authorization.revoke()
    }

    func respond(_ values: [OpenLXSSHSecurity.SecretBytes], to prompt: SessionAuthenticationPrompt) throws -> Bool {
        guard self.prompt == prompt, let reply else { return false }
        guard active, values.count == 1, values[0].withUnsafeBytes({ $0.count <= 65536 }) else {
            throw TransportError.inputFull
        }
        self.reply = nil
        self.prompt = nil
        reply.resolve(.success(values[0]))
        return true
    }

    private func validate(key: ManagedKeyReference? = nil) async throws -> SecurityMetadata {
        try cancellation.check()
        guard active else { throw CancellationError() }
        let metadata = try await repository.securityMetadata()
        try cancellation.check()
        let keyMatches = key.map { expected in
            metadata.keys.contains { $0.authenticationIdentity == expected.authenticationIdentity }
        } ?? true
        guard active, metadata.hosts.contains(where: { $0.matchesConnection(of: host) }), keyMatches else {
            throw SecurityUIFailure.notAuthorized
        }
        return metadata
    }

    func acquire(_ request: NativeSessionPrimaryRequest) async throws -> FileAuthentication {
        guard active, !request.token.isCancelled, requestID == nil,
              request.method == (host.authentication.needsKey ? .publicKey : .password) else {
            throw CancellationError()
        }
        requestID = request.requestID
        nativeID = request.sessionID
        pending += 1
        defer { pending -= 1 }

        let metadata = try await validate()
        let key: ManagedKeyReference?
        if host.authentication.needsKey {
            guard let id = host.keyRef, let reference = metadata.keys.first(where: { $0.id == id }) else {
                throw SecurityUIFailure.notAuthorized
            }
            key = reference
        } else {
            key = nil
        }

        let material: SecurityKeyAuthenticationMaterial?
        if let key {
            material = try await security.keyAuthenticationMaterial(host: host, expectedKey: key)
        } else {
            material = nil
        }
        _ = try await validate(key: key)

        let purpose: SessionPrimaryPurpose = host.authentication.needsKey ? .privateKeyPassphrase : .password
        let typed = SessionPrimaryRequest(
            token: token,
            id: request.requestID,
            nativeSessionID: request.sessionID,
            purpose: purpose,
            key: key
        )
        let supplied = material?.encrypted == false ? nil : try await authorization.acquire(typed)
        _ = try await validate(key: key)

        let answer: OpenLXSSHSecurity.SecretBytes?
        if material?.encrypted == false {
            answer = nil
        } else if let supplied {
            answer = supplied.secret
        } else {
            guard active, reply == nil else { throw CancellationError() }
            let mailbox = NativePrimaryReply()
            let prompt = SessionAuthenticationPrompt(
                token: token,
                id: request.requestID,
                payload: purpose == .password ? .initialPassword : .privateKeyPassphrase
            )
            reply = mailbox
            self.prompt = prompt
            present?(prompt)
            defer {
                if self.prompt == prompt {
                    self.reply = nil
                    self.prompt = nil
                }
            }
            answer = try await mailbox.wait()
        }

        let final = try await validate(key: key)
        if let credential = supplied?.credential {
            let passwordAuthorized = purpose == .password
                && credential.purpose == .password
                && host.savePasswordAuthorized
                && host.credentialRef == credential.id
            let passphraseAuthorized = purpose == .privateKeyPassphrase
                && credential.purpose == .privateKeyPassphrase
                && key?.passphraseCredentialRef == credential.id
            guard final.credentials.contains(credential),
                  credential.isSavingAuthorized,
                  passwordAuthorized || passphraseAuthorized else {
                throw SecurityUIFailure.notAuthorized
            }
        }
        guard active, !request.token.isCancelled, requestID == request.requestID, nativeID == request.sessionID else {
            throw CancellationError()
        }
        authorization.revoke()
        if let material {
            return .publicKey(
                publicKey: nil,
                privateKey: material.bytes.withUnsafeBytes { Data($0) },
                passphrase: answer?.withUnsafeBytes { Data($0) }
            )
        }
        guard let answer else { throw SecurityUIFailure.notAuthorized }
        return .password(answer.withUnsafeBytes { Data($0) })
    }
}

@MainActor final class NativeSessionDriver: SessionDriving, SessionResultClosing {
    let terminal: NativeTerminalView
    let sessionID: UUID
    private let repository: any AppRepositoryProtocol
    private let security: SecurityCoordinator
    private let connector: any NativeSessionConnecting
    private var host: HostConfiguration
    private(set) var token: SessionToken?
    private(set) var state: SSHSessionState = .idle
    private(set) var failureDetail: SessionFailureDetail?
    var automaticallyPresentsChallenges: Bool { true }
    var onState: ((SessionToken?, SSHSessionState) -> Void)?
    var onTrust: (([SessionTrustPrompt]) -> Void)?
    var onAuthentication: ((SessionAuthenticationPrompt) -> Void)?
    var canReconnect: Bool {
        !tabClosed && run == nil && cleanup == nil && (retiredTicket == nil || retiredTicket?.snapshot.drained == true) && state != .closed
    }
    private var tabClosed = false
    private var run: Run?
    private var cleanup: Task<Void, Never>?
    private var lastCloseCompleted = true
    private var lastInteractionsDrained = true
    private(set) var lastCloseOrigin: SessionCloseOrigin?
    private var lastConnectedSeconds: Int?
    private var lastAppliedKeepalive: NativeTCPKeepaliveSnapshot?
    private let retirementRegistry: SessionRetirementRegistry
    private var reservation: SessionTrackingReservation?
    private var retiredTicket: SessionRetirementTicket?
    private var retiredObserver: UUID?
    private var nativeCloseDisposition: SessionCloseResult?
    private(set) var closeDisposition: SessionCloseResult?
    private(set) var terminalResourcesReleased = false
    // A scheduling-test seam only. Production always asks the actual terminal's
    // updateUiClosed result; a native drain receipt cannot substitute for UI release.
    private let terminalRelease: @MainActor (NativeTerminalView) -> Bool
    @MainActor private final class Run {
        let token: SessionToken
        let cancellation = CancellationToken()
        let primary: NativePrimaryOwner
        let challenges: NativeSessionChallenges
        var active = true
        var connectionEstablished = false
        var connectedAt: ContinuousClock.Instant?
        var appliedKeepalive: NativeTCPKeepaliveSnapshot?
        var transport: (any NativeSessionTransport)?
        var setup: Task<Void, Never>?
        var output: Task<Void, Never>?
        var writes: [UUID: Task<Void, Never>] = [:]
        var lastWrite: Task<Void, Never>?
        var resize: Task<Void, Never>?
        var latestSize: NativeShellSize?
        var pendingInputBytes = 0
        var receiveInFlight = false
        var changedPrompt: SessionTrustPrompt?
        var setupCompleted = false
        var setupFailureWithoutNative = false
        var drain: (any SessionDrainObserving)?
        var closeStarted = false
        var closeReturned = false
        var finalState: SSHSessionState = .disconnected(nil)
        init(token: SessionToken, host: HostConfiguration, repository: any AppRepositoryProtocol,
             security: SecurityCoordinator, authorization: SessionPrimaryAuthorization) {
            self.token = token
            primary = NativePrimaryOwner(token: token, cancellation: cancellation, host: host,
                repository: repository, security: security, authorization: authorization)
            challenges = NativeSessionChallenges(token: token, cancellation: cancellation)
        }
        func revoke() {
            active = false
            cancellation.cancel()
            primary.revoke()
            challenges.revoke()
            transport?.cancel()
            setup?.cancel()
            output?.cancel()
            resize?.cancel()
            for task in writes.values { task.cancel() }
            latestSize = nil
        }
    }

    init(sessionID: UUID, host: HostConfiguration, repository: any AppRepositoryProtocol,
         security: SecurityCoordinator, connector: any NativeSessionConnecting,
         retirementRegistry: SessionRetirementRegistry = .shared,
         terminalRelease: @escaping @MainActor (NativeTerminalView) -> Bool = { $0.releaseResources() }) throws {
        self.sessionID = sessionID
        self.host = host
        self.repository = repository
        self.security = security
        self.connector = connector
        self.retirementRegistry = retirementRegistry
        self.terminalRelease = terminalRelease
        terminal = NativeTerminalView()
        terminal.inputEnabled = false
        try terminal.installApplicationRelay(
            input: { [weak self] bytes in
                guard self?.admitInput(bytes) == true else {
                    NSSound.beep()
                    return
                }
            },
            resize: { [weak self] columns, rows in
                self?.resize(columns: columns, rows: rows)
            }
        )
    }

    func updateHost(_ host: HostConfiguration) { self.host = host }

    /// Preserve host values as exact kernel TCP controls. Zero disables; there is no SSH probe channel.
    static func makeKeepalivePolicy(_ configuration: SSHSessionConfiguration) throws -> NativeTCPKeepalivePolicy? {
        guard configuration.serverAliveInterval != 0 else { return nil }
        return try NativeTCPKeepalivePolicy(
            interval: configuration.serverAliveInterval,
            failedProbes: configuration.serverAliveCountMax
        )
    }

    func connect(_ configuration: SSHSessionConfiguration, primary: SessionPrimaryAuthorization) throws -> SessionToken {
        if let retiredTicket, retiredTicket.snapshot.drained {
            retirementFinished(retiredTicket)
        }
        guard canReconnect else { throw TransportError.busy }
        let options = try NativeShellOptions(
            size: NativeShellSize(columns: terminal.columns, rows: terminal.rows),
            operationTimeout: 10,
            interactionTimeout: 120,
            authenticationTimeout: 300,
            keepalive: Self.makeKeepalivePolicy(configuration)
        )
        if reservation == nil {
            reservation = try retirementRegistry.reserve()
        }
        let current = SessionToken(sessionID: sessionID, generation: (token?.generation ?? 0) + 1)
        let run = Run(token: current, host: host, repository: repository, security: security, authorization: primary)
        self.run = run
        token = current
        failureDetail = nil
        lastCloseOrigin = nil
        lastConnectedSeconds = nil
        lastAppliedKeepalive = nil
        nativeCloseDisposition = nil
        closeDisposition = nil
        lastCloseCompleted = false
        lastInteractionsDrained = false

        run.primary.present = { [weak self, weak run] prompt in
            guard let self, let run, self.isCurrent(run) else { return }
            self.setState(.authenticating, run: run)
            self.onAuthentication?(prompt)
        }
        setState(.preparing, run: run)

        let host = host
        let connector = connector
        let mailbox = run.challenges
        let identity = configuration.connection.host
        let trustEvents = NativeTrustEventRecord()
        mailbox.onTrust = { [weak self, weak run] prompt in
            guard let self, let run, self.isCurrent(run) else { return }
            self.setState(.awaitingTrust, run: run)
            self.onTrust?([prompt])
        }
        mailbox.onChanged = { [weak self, weak run] change in
            guard let self, let run else { return }
            self.presentChanged(change, run: run, host: host, identity: identity)
            // SharedHostTrust rejects changed keys and connect must throw. Keep setup owned
            // until that actual catch so callback-first cannot discard its typed failure facts.
        }
        mailbox.onKeyboard = { [weak self, weak run] prompt in
            guard let self, let run, self.isCurrent(run) else { return }
            self.setState(.authenticating, run: run)
            self.onAuthentication?(prompt)
        }
        // Capture only the manual mailbox here, not self/run/primary/credentials.
        let keyboard: FilesKeyboardHandler = { challenge, reply in
            Task { @MainActor in mailbox.receiveKeyboard(challenge, reply: reply) }
        }
        let trust: FileHostTrustHandler = { event, reply in
            trustEvents.record(event)
            Task { @MainActor in mailbox.receiveTrust(event, reply: reply, host: identity) }
        }
        let request = NativeSessionConnect(
            configuration: configuration.connection,
            method: host.authentication.needsKey ? .publicKey : .password,
            primary: { [owner = run.primary] request in try await owner.acquire(request) },
            keyboard: keyboard,
            trust: trust,
            options: options,
            connectionTimeout: TimeInterval(configuration.connectTimeout),
            token: run.cancellation
        )
        run.setup = Task { [weak self, run] in
            guard run.active, !Task.isCancelled else {
                run.setupCompleted = true
                run.setupFailureWithoutNative = true
                return
            }
            do {
                let transport = try await connector.connect(request)
                run.transport = transport
                run.drain = transport.retirementDrain
                run.setupCompleted = true
                guard let self else {
                    run.revoke()
                    await transport.close()
                    return
                }
                guard run.changedPrompt == nil else {
                    finish(run, state: .failed(.trustRejected))
                    return
                }
                guard isCurrent(run), !Task.isCancelled else {
                    if self.run === run { beginNativeClose(run) }
                    return
                }
                // The production connector returns only after its typed shellReady
                // stage. Keep this generation's fact when a later IO error arrives.
                run.connectionEstablished = true
                run.connectedAt = .now
                run.appliedKeepalive = transport.transportKeepalive
                lastAppliedKeepalive = run.appliedKeepalive
                run.primary.discardAuthorization()
                setState(.connected, run: run)
                terminal.inputEnabled = true
                resize(columns: terminal.columns, rows: terminal.rows)
                startOutput(run)
            } catch {
                run.setupCompleted = true
                let wrapper = error as? NativeSessionConnectionFailure
                let failure = wrapper?.failure ?? error
                if let drain = wrapper?.drain {
                    run.drain = drain
                } else if let handle = (failure as? NativeShellError)?.interactionDrain {
                    run.drain = CanonicalSessionDrain(handle: handle)
                } else if wrapper?.noNativeOwnerCreated == true {
                    // An explicit boundary fact is authoritative. In particular an
                    // explicit false must not be overridden by the inner error's type.
                    run.setupFailureWithoutNative = true
                }
                guard let self, self.run === run, token == run.token else { return }
                guard run.active, !tabClosed else {
                    beginNativeClose(run)
                    return
                }
                let typedChange = (failure as? NativeShellError)?.changedHostKey ?? (failure as? FileServiceError)?.changedHostKey
                if let change = typedChange ?? trustEvents.changed {
                    presentChanged(change, run: run, host: host, identity: identity)
                }
                let finalState: SSHSessionState = run.changedPrompt == nil
                    ? failureState(failure, run: run, origin: .setupFailure)
                    : .failed(.trustRejected)
                finish(run, state: finalState)
            }
        }
        return current
    }

    private func presentChanged(_ change: ChangedHostKey, run: Run, host: HostConfiguration, identity: HostIdentity) {
        guard self.run === run, token == run.token, run.active, !tabClosed,
              self.host.matchesConnection(of: host), change.host == identity else { return }
        guard run.changedPrompt == nil else { return } // Callback/error share one immutable prompt.
        let prompt = SessionTrustPrompt(
            token: run.token,
            id: UUID(),
            host: change.host,
            algorithm: change.algorithm,
            fingerprint: change.presentedFingerprint,
            source: "当前握手密钥与已知主机记录不符；连接已阻止",
            changed: change
        )
        run.changedPrompt = prompt
        terminal.inputEnabled = false
        run.primary.revoke()
        failureDetail = SessionFailureDetail(category: .trustRejected, operation: "host-key-changed", code: nil, stages: [])
        // Native has already revoked its token on failure. Only owner revocation above, not
        // token.isCancelled or Task cancellation, determines whether this fact can be displayed.
        state = .failed(.trustRejected)
        onState?(run.token, state)
        onTrust?([prompt])
    }

    private func isCurrent(_ run: Run) -> Bool {
        self.run === run && token == run.token && run.active && run.changedPrompt == nil && !run.cancellation.isCancelled && !tabClosed
    }

    private func startOutput(_ run: Run) {
        guard run.output == nil, let transport = run.transport else { return }
        run.output = Task { [weak self, run] in
            while run.active, !Task.isCancelled {
                do {
                    run.receiveInFlight = true
                    let received = try await transport.receive(maxBytes: 64 * 1024, wait: 60.0, token: run.cancellation)
                    run.receiveInFlight = false
                    guard let self, self.isCurrent(run), !Task.isCancelled else { return }
                    switch received {
                    case .bytes(let bytes):
                        try self.terminal.feedApplicationOutput(bytes)
                    case .wouldBlock:
                        break
                    case .eof:
                        self.terminal.inputEnabled = false
                    case .exit(let exit):
                        self.finish(run, state: .disconnected(exit.reportedStatus), origin: .remoteExit)
                        return
                    }
                } catch {
                    run.receiveInFlight = false
                    if let self, self.run === run, run.active {
                        self.finish(run, state: self.failureState(error, run: run, origin: .receiveFailure))
                    }
                    return
                }
            }
        }
    }

    /// Synchronous, before Data construction or Task creation. Aggregate <=256KiB/128 items.
    @discardableResult func admitInput(_ bytes: ArraySlice<UInt8>) -> Bool {
        guard let run, isCurrent(run), state == .connected, let transport = run.transport,
              !bytes.isEmpty, bytes.count <= 256 * 1024 - run.pendingInputBytes, run.writes.count < 128 else { return false }
        let id = UUID()
        let count = bytes.count
        let previous = run.lastWrite
        run.pendingInputBytes += count
        let data = Data(bytes)
        let task = Task { [weak self, run] in
            defer {
                run.pendingInputBytes -= count
                run.writes[id] = nil
                if run.writes.isEmpty { run.lastWrite = nil }
            }
            await previous?.value // Preserve exact user input order, including queued pastes.
            guard run.active, !Task.isCancelled else { return }
            do {
                try await transport.write(data, token: run.cancellation)
            } catch {
                if let self, self.isCurrent(run) {
                    self.finish(run, state: self.inputFailureState(error, run: run, origin: .writeFailure))
                }
            }
        }
        run.writes[id] = task
        run.lastWrite = task
        return true
    }

    func resize(columns: Int, rows: Int) {
        guard let size = try? NativeShellSize(columns: columns, rows: rows), let run, isCurrent(run) else { return }
        run.latestSize = size
        guard run.resize == nil, let transport = run.transport else { return }
        run.resize = Task { [weak self, run] in
            defer { run.resize = nil }
            do {
                while run.active, !Task.isCancelled, let size = run.latestSize {
                    run.latestSize = nil
                    try await transport.resize(size, token: run.cancellation)
                }
            } catch {
                if let self, self.isCurrent(run) {
                    self.finish(run, state: self.inputFailureState(error, run: run, origin: .controlFailure))
                }
            }
        }
    }

    func accept(_ prompt: SessionTrustPrompt, persistence: SessionTrustPersistence) async throws {
        guard let run, isCurrent(run), prompt.token == run.token else { throw TransportError.stale }
        try run.challenges.accept(prompt, persistence: persistence)
        setState(.preparing, run: run)
    }

    func respond(_ answer: SessionAuthenticationAnswer, to prompt: SessionAuthenticationPrompt) throws {
        guard let run, isCurrent(run), prompt.token == run.token else { throw TransportError.stale }
        switch answer {
        case .cancel:
            cancel()
        case .answers(let answers):
            if !(try run.primary.respond(answers, to: prompt)) {
                try run.challenges.answer(answers, prompt: prompt)
            }
            setState(.preparing, run: run)
        }
    }

    func cancel() {
        guard let run else { return }
        finish(run, state: .disconnected(nil), origin: .userDisconnect)
    }

    func closeTab() {
        guard !tabClosed else { return }
        tabClosed = true
        terminal.inputEnabled = false
        if let run {
            finish(run, state: .closed, origin: .userClose)
        } else {
            if let reservation, retiredTicket == nil {
                retirementRegistry.release(reservation)
                self.reservation = nil
            }
            nativeCloseDisposition = retiredTicket.map(SessionCloseResult.retired) ?? .closed
            _ = publishPermanentCloseDisposition()
        }
    }

    func reserveForPreparation() throws {
        guard reservation == nil, run == nil else { return }
        reservation = try retirementRegistry.reserve()
    }

    private(set) var closeObservationCount = 0

    func closeResult(deadline: ContinuousClock.Instant) async -> SessionCloseResult {
        closeObservationCount += 1
        defer { closeObservationCount -= 1 }
        closeTab()
        let native = await settle(until: deadline)
        guard native.permitsRemoval else { return native }
        // Native cleanup and UI teardown share the caller's original deadline.
        // The existing background native owner does not receive a new UI budget.
        while true {
            if Task.isCancelled { return cancelledTerminalObservation() }
            if !terminalResourcesReleased, ContinuousClock.now >= deadline {
                return publishPermanentCloseDisposition(attemptRelease: false)
            }
            if releaseTerminal() {
                if let retiredTicket, retiredTicket.snapshot.drained {
                    retirementFinished(retiredTicket)
                }
                return publishPermanentCloseDisposition()
            }
            guard ContinuousClock.now < deadline else {
                return publishPermanentCloseDisposition(attemptRelease: false)
            }
            do {
                try await Task.sleep(for: min(.milliseconds(10), ContinuousClock.now.duration(to: deadline)))
            } catch {
                return cancelledTerminalObservation()
            }
        }
    }

    private func finish(_ run: Run, state finalState: SSHSessionState, origin: SessionCloseOrigin? = nil) {
        guard self.run === run else { return }
        if run.active {
            if let origin { lastCloseOrigin = origin }
            lastConnectedSeconds = Self.connectedSeconds(run)
            lastAppliedKeepalive = run.appliedKeepalive
            run.finalState = finalState
            run.revoke()
        } else if finalState == .closed {
            run.finalState = .closed
        }
        terminal.inputEnabled = false
        state = .closing
        onState?(run.token, state)
        beginNativeClose(run)
        guard cleanup == nil else { return }
        cleanup = Task { [weak self] in
            guard let self else { return }
            _ = await settle(until: ContinuousClock.now + .seconds(2))
            cleanup = nil
        }
    }

    private func beginNativeClose(_ run: Run) {
        guard run.setupCompleted, !run.closeStarted else { return }
        run.closeStarted = true
        if let transport = run.transport {
            Task { [weak self, run, transport] in
                await transport.close()
                run.closeReturned = true
                // Completion does not retain the UI owner during native/provider waits.
                self?.completeIfDrained(run)
            }
        } else {
            run.closeReturned = true
        }
    }

    private func completeIfDrained(_ run: Run) {
        guard self.run === run, !run.active, token == run.token else { return }
        if run.drain?.snapshot.drained == true
            || (run.setupCompleted && run.setupFailureWithoutNative && run.primary.pending == 0) {
            finalize(run, result: .closed)
        }
    }

    private func settle(until deadline: ContinuousClock.Instant) async -> SessionCloseResult {
        if let retiredTicket {
            if retiredTicket.snapshot.drained {
                retirementFinished(retiredTicket)
                return .closed
            }
            return .retired(retiredTicket)
        }
        guard let run else { return nativeCloseDisposition ?? .closed }
        guard !run.active else {
            return .incomplete(.init(token: run.token, reason: .nativeUnknown, drain: run.drain?.snapshot))
        }
        while self.run === run {
            if Task.isCancelled {
                return .incomplete(.init(token: run.token, reason: .observationCancelled, drain: run.drain?.snapshot))
            }
            beginNativeClose(run)
            completeIfDrained(run)
            if self.run !== run { return nativeCloseDisposition ?? .closed }
            if .now >= deadline { break }
            do {
                try await Task.sleep(for: .milliseconds(10))
            } catch {
                return .incomplete(.init(token: run.token, reason: .observationCancelled, drain: run.drain?.snapshot))
            }
        }
        guard self.run === run else { return nativeCloseDisposition ?? .closed }
        if let drain = run.drain {
            let snapshot = drain.snapshot
            lastCloseCompleted = snapshot.nativeClosed
            lastInteractionsDrained = snapshot.drained
            if snapshot.drained {
                finalize(run, result: .closed)
                return .closed
            }
            if snapshot.safeToRetire, let reservation {
                let ticket = SessionRetirementTicket(token: run.token, drain: drain)
                do {
                    try retirementRegistry.retire(reservation, ticket: ticket)
                    finalize(run, result: .retired(ticket))
                    return .retired(ticket)
                } catch {
                    return reportIncomplete(.init(token: run.token, reason: .interactionTrackingUnavailable, drain: snapshot))
                }
            }
            return reportIncomplete(.init(
                token: run.token,
                reason: snapshot.producersSealed ? .nativeUnknown : .producerUnsealed,
                drain: snapshot
            ))
        }
        return reportIncomplete(.init(
            token: run.token,
            reason: run.setupCompleted ? .nativeUnknown : .setupPending,
            drain: nil
        ))
    }

    private func reportIncomplete(_ context: SessionCloseContext) -> SessionCloseResult {
        let result = SessionCloseResult.incomplete(context)
        nativeCloseDisposition = result
        closeDisposition = result
        state = .failed(.launchFailed)
        onState?(token, state)
        return result // Keep the exact Run/cleanup owner; no claimed native disposal.
    }

    private func finalize(_ run: Run, result: SessionCloseResult) {
        guard self.run === run else { return }
        run.primary.revoke()
        run.challenges.revoke()
        self.run = nil
        nativeCloseDisposition = result
        if case .retired(let ticket) = result {
            retiredTicket = ticket
            lastCloseCompleted = true
            lastInteractionsDrained = false
            let ticketToken = ticket.token
            let handleID = ticket.handleID
            retiredObserver = try? ticket.drain.observeCompletion { [weak self] snapshot in
                guard snapshot.drained else { return }
                Task { @MainActor [weak self] in
                    guard let self, let current = self.retiredTicket,
                          current.token == ticketToken, current.handleID == handleID else { return }
                    self.retirementFinished(current)
                }
            }
        } else {
            if let reservation {
                retirementRegistry.release(reservation)
                self.reservation = nil
            }
            lastCloseCompleted = true
            lastInteractionsDrained = true
        }
        if tabClosed {
            _ = publishPermanentCloseDisposition()
        } else {
            closeDisposition = result
            state = run.finalState
            onState?(run.token, state)
        }
    }

    private func retirementFinished(_ ticket: SessionRetirementTicket) {
        guard retiredTicket == ticket, token == ticket.token, ticket.snapshot.drained else { return }
        if let retiredObserver {
            ticket.drain.removeCompletionObserver(retiredObserver)
        }
        retiredObserver = nil
        retiredTicket = nil
        reservation = nil
        nativeCloseDisposition = .closed
        lastInteractionsDrained = true
        if tabClosed {
            _ = publishPermanentCloseDisposition()
        } else {
            closeDisposition = .closed
            onState?(token, state)
        }
        // Only releases a fence; never starts another generation.
    }

    @discardableResult private func releaseTerminal() -> Bool {
        guard !terminalResourcesReleased else { return true }
        terminal.removeApplicationRelay()
        terminalResourcesReleased = terminalRelease(terminal)
        return terminalResourcesReleased
    }

    private func cancelledTerminalObservation() -> SessionCloseResult {
        .incomplete(.init(token: token, reason: .observationCancelled, drain: retiredTicket?.snapshot))
    }

    @discardableResult private func publishPermanentCloseDisposition(attemptRelease: Bool = true) -> SessionCloseResult {
        let previousState = state
        let result: SessionCloseResult
        if terminalResourcesReleased || (attemptRelease && releaseTerminal()) {
            result = nativeCloseDisposition ?? .closed
            state = result == .closed ? .closed : .disconnected(nil)
        } else {
            result = .incomplete(.init(token: token, reason: .terminalPending, drain: retiredTicket?.snapshot))
            state = .closing
        }
        let changed = closeDisposition != result
        closeDisposition = result
        if changed || state != previousState {
            onState?(token, state)
        }
        return result
    }

    private func setState(_ next: SSHSessionState, run: Run) {
        guard isCurrent(run) else { return }
        state = next
        onState?(run.token, next)
    }

    private func inputFailureState(_ error: any Error, run: Run, origin: SessionCloseOrigin) -> SSHSessionState {
        if error is CancellationError { return failureState(error, run: run, origin: origin) }
        if let native = error as? NativeShellError,
           [.transport, .timeout, .cancelled, .closed].contains(native.kind) {
            return failureState(error, run: run, origin: origin)
        }
        if let file = error as? FileServiceError,
           [.transport, .timeout, .cancelled, .closed].contains(file.kind) {
            return failureState(error, run: run, origin: origin)
        }
        return .failed(.inputFailed)
    }

    private static func connectedSeconds(_ run: Run) -> Int? {
        guard let start = run.connectedAt else { return nil }
        let seconds = start.duration(to: .now).components.seconds
        return Int(max(0, min(seconds, 31_536_000)))
    }

    private func failureState(_ error: any Error, run: Run, origin: SessionCloseOrigin) -> SSHSessionState {
        lastCloseOrigin = origin
        lastConnectedSeconds = Self.connectedSeconds(run)
        lastAppliedKeepalive = run.appliedKeepalive
        if error is CancellationError {
            failureDetail = nil
            return .disconnected(nil)
        }
        let category: SessionFailureDetail.Category
        let operation: String
        let code: Int64?
        let stages: [String]
        if let native = error as? NativeShellError {
            let wasConnected = run.connectionEstablished || native.authenticationStages.contains(.shellReady)
            operation = Self.safeOperation(native.operation)
            code = native.code.map(Int64.init)
            stages = native.authenticationStages.map(Self.stageFact)
            switch native.kind {
            case .cancelled, .closed:
                failureDetail = nil
                return .disconnected(nil)
            case .untrusted: category = .trustRejected
            case .authentication: category = .authenticationRejected
            case .unsupported: category = .unsupported
            case .timeout:
                if native.operation == "local-network-access" {
                    category = .localNetworkAccessRequired
                } else if ["interaction-deadline", "primary-provider-deadline"].contains(native.operation) {
                    category = .interactionTimeout
                } else if native.operation == "authentication-deadline" {
                    category = .authenticationTimeout
                } else {
                    category = wasConnected ? .connectionLost : .networkTimeout
                }
            case .transport: category = wasConnected ? .connectionLost : .networkUnavailable
            default: category = .unknown
            }
        } else if let file = error as? FileServiceError {
            operation = Self.safeOperation(file.operation)
            code = file.code
            stages = []
            switch file.kind {
            case .cancelled, .closed:
                failureDetail = nil
                return .disconnected(nil)
            case .timeout:
                category = file.operation == "local-network-access"
                    ? .localNetworkAccessRequired
                    : (run.connectionEstablished ? .connectionLost : .networkTimeout)
            case .transport: category = run.connectionEstablished ? .connectionLost : .networkUnavailable
            case .authentication: category = .authenticationRejected
            case .untrusted: category = .trustRejected
            case .unsupported: category = .unsupported
            default: category = .unknown
            }
        } else {
            operation = "unknown"
            code = nil
            stages = []
            category = .unknown
        }
        failureDetail = SessionFailureDetail(
            category: category,
            operation: operation,
            code: code,
            stages: stages,
            closeOrigin: origin,
            connectedSeconds: Self.connectedSeconds(run),
            tcpKeepalive: run.appliedKeepalive
        )
        switch category {
        case .trustRejected: return .failed(.trustRejected)
        case .authenticationRejected: return .failed(.authenticationFailed)
        case .interactionTimeout, .authenticationTimeout: return .failed(.authenticationTimeout)
        default: return .failed(.launchFailed)
        }
    }

    private static func safeOperation(_ value: String) -> String {
        let allowed: Set<String> = [
            "dns", "dns-no-address", "connect", "connect-timeout", "connect-poll", "connect-status", "socket", "socket-flags",
            "local-network-access",
            "handshake", "host-key", "handshake-host-key", "host-key-changed", "auth-methods", "primary-authentication", "primary-method-unavailable",
            "primary-before-trust", "primary-already-requested", "primary-method-mismatch", "none-authentication", "primary-provider-deadline",
            "interaction-deadline", "authentication-deadline", "keyboard-authentication", "authentication", "channel-open", "request-pty", "shell-start",
            "packet-read-timeout", "shell-packet-read-timeout", "tcp-keepalive-policy", "tcp-keepalive-configure",
            "liveness-packet-read-timeout", "ssh-round-trip", "ssh-probe-cleanup", "ssh-probe", "ssh-probe-result",
            "poll", "read-window-adjust", "eof", "input-eof", "remote-exit",
            "write", "read", "control", "io", "establish", "exit-status", "cancel", "close", "interaction-drain"
        ]
        return allowed.contains(value) ? value : "unknown"
    }

    private static func stageFact(_ stage: NativeShellAuthenticationStage) -> String {
        switch stage {
        case .advertised(let password, let key, let keyboard): "advertised(password=\(password),publicKey=\(key),KI=\(keyboard))"
        case .primaryStarted(let method): "primaryStarted(\(method.rawValue))"
        case .primaryResult(let method, let code, let authenticated): "primaryResult(\(method.rawValue),code=\(code),authenticated=\(authenticated))"
        case .keyboardStarted: "keyboardStarted"
        case .keyboardResult(let code, let authenticated): "keyboardResult(code=\(code),authenticated=\(authenticated))"
        case .authenticated: "authenticated"
        case .shellReady: "shellReady"
        }
    }

    var snapshot: NativeSessionDriverSnapshot {
        NativeSessionDriverSnapshot(
            token: token,
            pendingInputBytes: run?.pendingInputBytes ?? 0,
            pendingInputItems: run?.writes.count ?? 0,
            receiveInFlight: run?.receiveInFlight ?? false,
            resizeInFlight: run?.resize != nil,
            hasLatestResize: run?.latestSize != nil,
            nativeCloseCompleted: lastCloseCompleted,
            interactionsDrained: lastInteractionsDrained,
            lastCloseOrigin: lastCloseOrigin,
            connectedSeconds: run.flatMap(Self.connectedSeconds) ?? lastConnectedSeconds,
            tcpKeepalive: run?.appliedKeepalive ?? lastAppliedKeepalive
        )
    }

    func waitForCleanup() async { await cleanup?.value }

    isolated deinit {
        run?.revoke()
        if let retiredTicket, let retiredObserver {
            retiredTicket.drain.removeCompletionObserver(retiredObserver)
        }
        if let reservation, retiredTicket == nil, run == nil {
            retirementRegistry.release(reservation)
        }
        terminal.removeApplicationRelay()
        terminal.releaseResources()
    }
}
