import Foundation
import Darwin
import AskpassPOSIX

// Synchronous, single-owner prototype coordinator. It owns only children it spawns.
// No arbitrary PID adoption, SSH network, Keychain, or terminal-output scanning.
public final class FixtureBroker {
    enum ParentKind { case fixture, systemKeygen }
    public struct Pending: Sendable {
        public let request: Request
        public let parentPID: Int32
    }
    final class Session {
        var state: AuthenticationState
        let parent: ap_identity
        let output: Int32
        let kind: ParentKind
        var result = Data()
        var status: Int32?
        var pending: (Request, ReplyRight, ap_identity, audit_token_t)?
        var helpers: [ap_identity] = []
        var stopAt: TimeInterval?
        var exitObserved = false
        var killed = false
        var outputClosed = false
        var cleanupFailed = false
        init(grant: SessionGrant, parent: ap_identity, output: Int32, kind: ParentKind = .fixture) {
            state = AuthenticationState(grant: grant, now: now()); self.parent = parent; self.output = output; self.kind = kind
        }
        func validateParent() throws {
            guard same(try identity(parent.pid), parent) else { throw ProbeError.identity }
            if kind == .fixture { try signed(parent) }
            else {
                var value = parent
                guard ap_signed_keygen(&value) == 0, ap_process_has_ctty(parent.pid) != 0 else { throw ProbeError.identity }
            }
        }
    }
    let image: String
    let own: ap_identity
    let listener: UInt32
    public let serviceName: String
    var sessions: [UUID: Session] = [:]
    var generation: UInt64 = 0
    public private(set) var rejected: [ProbeError: Int] = [:]
    public private(set) var acceptedKinds: [ChallengeKind] = []
    // Test-only scheduling hook delays consumption, not identity policy.
    var queuedExecFixture = false
    public private(set) var queuedExecRejected = false
    public var pending: [Pending] {
        sessions.values.compactMap { session in
            session.pending.map { Pending(request: $0.0, parentPID: session.parent.pid) }
        }
    }
    public init(image: String) throws {
        guard ap_self_signed() == 0 else { throw ProbeError.identity }
        self.image = image; own = try identity(getpid())
        var name = [CChar](repeating: 0, count: 128), port: UInt32 = 0
        guard ap_mach_start(&name, name.count, &port) == 0 else { throw ProbeError.unavailable }
        serviceName = String(decoding: name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self); listener = port
    }
    deinit {
        for session in sessions.values { stop(session, reason: .cancelled) }
        let end = now() + 1
        while now() < end && sessions.values.contains(where: { $0.status == nil }) { tick(); usleep(5_000) }
        for session in sessions.values {
            if session.status == nil {
                // Still our unreaped child: retain PID through the last escalation.
                _ = ap_signal_group(session.parent.pid, SIGKILL)
                var status: Int32 = 0
                for _ in 0..<100 {
                    if ap_wait(session.parent.pid, &status) == 1 { session.status = status; break }
                    usleep(5_000)
                }
            }
            session.pending = nil
            if !session.outputClosed { Darwin.close(session.output) }
        }
        _ = ap_mach_stop(listener, serviceName)
    }
    // The helper gets correlation metadata only. No response enters argv or env.
    func environment(_ grant: SessionGrant) -> [String: String] {
        ["PATH": "/usr/bin:/bin", "AP_SERVICE": serviceName,
         "AP_BROKER_PID": String(own.pid), "AP_BROKER_SECONDS": String(own.seconds),
         "AP_BROKER_MICROS": String(own.microseconds), "AP_SESSION": grant.session.uuidString,
         "AP_GENERATION": String(grant.generation), "AP_NONCE": grant.nonce]
    }
    @discardableResult
    public func launchFixture(mode: String = "normal", expectedAnswer: Data = Data(), helperImage: String? = nil,
                              presentedGrant: SessionGrant? = nil) throws -> UUID {
        guard sessions.count < Limits.sessions, generation < UInt64.max else { throw ProbeError.bounds }
        generation += 1
        let grant = SessionGrant(generation: generation, nonce: try nonce())
        let helper = helperImage ?? URL(fileURLWithPath: image).deletingLastPathComponent().appendingPathComponent("openlxssh-askpass-helper").path
        let child = try spawn(path: image, arguments: ["--fixture", mode, helper], environment: environment(presentedGrant ?? grant), suspended: true)
        var admitted = false
        var inputOpen = true
        defer {
            if !admitted {
                _ = ap_signal_group(child.0, SIGKILL); _ = ap_resume(child.0)
                if inputOpen { Darwin.close(child.1) }; Darwin.close(child.2)
                var status: Int32 = 0
                for _ in 0..<100 { if ap_wait(child.0, &status) == 1 { break }; usleep(5_000) }
            }
        }
        let parent = try identity(child.0)
        guard parent.ppid == own.pid, parent.uid == getuid(), parent.ruid == getuid() else { throw ProbeError.identity }
        try signed(parent)
        let session = Session(grant: grant, parent: parent, output: child.2)
        // Only anonymous parent stdin receives the runtime-generated expected bytes.
        try Limits.validateAnswer(expectedAnswer)
        if !expectedAnswer.isEmpty { try writePipe(expectedAnswer, fd: child.1) }
        Darwin.close(child.1); inputOpen = false
        guard ap_resume(child.0) == 0 else { throw ProbeError.unavailable }
        sessions[grant.session] = session
        admitted = true
        return grant.session
    }
    @discardableResult
    public func launchSystemKeygen(key: URL, helper: URL) throws -> UUID {
        guard sessions.count < Limits.sessions, generation < UInt64.max, key.isFileURL,
              key.path.hasPrefix("/"), !key.path.utf8.contains(0), helper.isFileURL,
              ap_signed_bundled_helper(helper.path) == 0 else { throw ProbeError.identity }
        var attributes = stat()
        guard lstat(key.path, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_uid == getuid(), attributes.st_mode & 0o777 == 0o600 else { throw ProbeError.identity }
        generation += 1
        let grant = SessionGrant(generation: generation, nonce: try nonce())
        var environment = environment(grant)
        environment["SSH_ASKPASS"] = helper.path; environment["SSH_ASKPASS_REQUIRE"] = "force"
        guard environment["DISPLAY"] == nil, environment["SSH_ASKPASS_PROMPT"] == nil else { throw ProbeError.protocolViolation }
        // No inherited DISPLAY/hint/credential environment. The caller-supplied
        // key path is a data argument to one literal system executable only.
        let envp = environment.sorted(by: { $0.key < $1.key }).map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { envp.forEach { free($0) } }
        var pid: pid_t = -1, master: Int32 = -1
        let error = key.path.withCString { path in envp.withUnsafeBufferPointer {
            ap_keygen_pty(UnsafeMutablePointer(mutating: $0.baseAddress!), path, &pid, &master)
        } }
        guard error == 0 else { throw ProbeError.unavailable }
        var admitted = false
        defer {
            if !admitted {
                _ = ap_signal_group(pid, SIGKILL); _ = kill(pid, SIGKILL); _ = ap_resume(pid); Darwin.close(master)
                var status: Int32 = 0
                for _ in 0..<100 { if ap_wait(pid, &status) == 1 { break }; usleep(5_000) }
            }
        }
        let end = now() + 1
        while ap_process_stopped(pid) == 0 && now() < end { usleep(5_000) }
        let parent = try identity(pid)
        guard ap_process_stopped(pid) != 0, ap_process_has_ctty(pid) != 0,
              parent.ppid == own.pid, parent.uid == getuid() else { throw ProbeError.identity }
        sessions[grant.session] = Session(grant: grant, parent: parent, output: master, kind: .systemKeygen)
        guard ap_resume(pid) == 0 else { sessions.removeValue(forKey: grant.session); throw ProbeError.unavailable }
        // Keep the fork-recorded birth identity; only after the literal exec has
        // completed may the strict system-code requirement authorize any request.
        let ready = now() + 1
        while now() < ready {
            var expected = parent
            if ap_signed_keygen(&expected) == 0, ap_process_has_ctty(pid) != 0 { admitted = true; return grant.session }
            usleep(5_000)
        }
        sessions.removeValue(forKey: grant.session); throw ProbeError.identity
    }
    public func systemKeygenOutput(_ id: UUID) -> Data? {
        guard let session = sessions[id], session.kind == .systemKeygen, session.status != nil else { return nil }
        return session.result
    }
    public func cancel(_ id: UUID) { if let session = sessions[id] { stop(session, reason: .cancelled) } }
    public func phase(_ id: UUID) -> AuthenticationState.Phase? { sessions[id]?.state.phase }
    public func exitCode(_ id: UUID) -> Int32? { sessions[id]?.status.map { ap_exit_status($0) } }
    public func fixturePassed(_ id: UUID) -> Bool { sessions[id]?.result == Data("fixture-ok".utf8) && exitCode(id) == 0 }
    public var allReaped: Bool { sessions.values.allSatisfy { $0.status != nil && !$0.cleanupFailed } }
    public var helpersReleased: Bool {
        sessions.values.allSatisfy { session in
            session.helpers.allSatisfy { helper in
                guard let current = try? identity(helper.pid) else { return true }
                return !same(current, helper)
            }
        }
    }
    public var openRequests: Int { sessions.values.filter { $0.pending != nil }.count }

    public func pump(milliseconds: Int32 = 10) {
        do { accept(try receiveMach(listener, reply: false, timeout: milliseconds)) }
        catch ProbeError.timeout { }
        catch { rejected[(error as? ProbeError) ?? .protocolViolation, default: 0] += 1 }
        tick()
    }
    private func accept(_ envelope: MachEnvelope) {
        do {
            if queuedExecFixture {
                var token = envelope.token
                let end = now() + 1
                while now() < end && ap_mach_test_current_broker(&token) == 0 { usleep(5_000) }
                let currentIsBroker = ap_mach_test_current_broker(&token) != 0
                queuedExecRejected = currentIsBroker && (try? requestPeer(envelope.token)) == nil
                queuedExecFixture = false
            }
            let helper = try requestPeer(envelope.token)
            guard let session = sessions.values.first(where: { $0.parent.pid == helper.ppid }),
                  session.status == nil, session.stopAt == nil,
                  same(try identity(session.parent.pid), session.parent), session.parent.ppid == own.pid,
                  let right = envelope.reply else { throw ProbeError.identity }
            try session.validateParent()
            let request = try envelope.decode(Request.self)
            try session.state.begin(request, now: now())
            session.pending = (request, right, helper, envelope.token); session.helpers.append(helper)
            acceptedKinds.append(request.kind)
        } catch {
            rejected[(error as? ProbeError) ?? .protocolViolation, default: 0] += 1
        }
    }
    public func submit(_ decision: Decision, session id: UUID, requestID: UUID, generation: UInt64) throws {
        guard let session = sessions[id], let pending = session.pending,
              pending.0.id == requestID, session.state.grant.generation == generation else { throw ProbeError.stale }
        do {
            guard same(try requestPeer(pending.3), pending.2) else { throw ProbeError.identity }
            guard same(try identity(session.parent.pid), session.parent) else { throw ProbeError.parentExited }
            try session.validateParent()
            let reply = try Reply(request: pending.0, decision: decision)
            try session.state.finish(requestID, generation: generation, now: now())
            if case .cancel = decision { stop(session, reason: .cancelled); return }
            try pending.1.send(reply)
            session.pending = nil
        } catch {
            stop(session, reason: (error as? ProbeError) ?? .helperFailed)
            throw error
        }
    }
    private func stop(_ session: Session, reason: ProbeError) {
        guard session.stopAt == nil else { return }
        session.state.close(reason)
        session.pending = nil
        guard session.status == nil else { return }
        if !session.outputClosed { Darwin.close(session.output); session.outputClosed = true }
        // Parent is our unreaped child, so its PID cannot be recycled. Its dedicated
        // process group contains only the controlled fixture and its helpers.
        _ = ap_signal_group(session.parent.pid, SIGTERM)
        session.stopAt = now()
    }
    private func tick() {
        for session in sessions.values {
            if !session.outputClosed {
                do { try readAvailable(session.output, into: &session.result, limit: session.kind == .systemKeygen ? 4096 : 64, pty: session.kind == .systemKeygen) }
                catch { stop(session, reason: .bounds) }
            }
            if session.status == nil && !session.exitObserved && ap_exited(session.parent.pid) == 1 {
                // waitid(WNOWAIT) keeps the zombie child PID reserved until the
                // controlled group is dead. Never signal a recycled/reaped PGID.
                session.exitObserved = true
                if session.stopAt == nil { stop(session, reason: .parentExited) }
            }
            if session.status == nil && session.stopAt == nil {
                if now() >= session.state.expires || (session.state.deadline.map { now() >= $0 } ?? false) {
                    stop(session, reason: .timeout)
                } else if let pending = session.pending {
                    let current = try? requestPeer(pending.3)
                    if ap_mach_reply_alive(pending.1.raw) == 0 || current.map({ !same($0, pending.2) }) ?? true {
                        stop(session, reason: .helperFailed)
                    }
                }
            }
            if let stopped = session.stopAt, session.status == nil {
                if !session.killed && now() - stopped > 0.2 {
                    _ = ap_signal_group(session.parent.pid, SIGKILL); session.killed = true
                }
                if session.exitObserved {
                    let groupAlive = ap_group_alive(session.parent.pid) != 0
                    if !groupAlive || now() - stopped > 0.7 {
                        session.cleanupFailed = groupAlive
                        var status: Int32 = 0
                        if ap_wait(session.parent.pid, &status) == 1 {
                            session.status = status
                            if !session.outputClosed {
                                try? readAvailable(session.output, into: &session.result, limit: session.kind == .systemKeygen ? 4096 : 64, pty: session.kind == .systemKeygen)
                                Darwin.close(session.output); session.outputClosed = true
                            }
                        }
                    }
                }
            }
        }
    }
}
