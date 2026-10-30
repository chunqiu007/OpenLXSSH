import Foundation
import Darwin
import COpenLXSSHAskpass
import OpenLXSSHAskpass

public typealias AuthenticationRequest = OpenLXSSHAskpass.Request
public typealias AuthenticationResponse = OpenLXSSHAskpass.Decision
public typealias AuthenticationChallengeKind = OpenLXSSHAskpass.ChallengeKind
public typealias AuthenticationSecret = OpenLXSSHAskpass.SecretBytes

/// The helper must live in the embedding app, not in a user-supplied PATH.
public struct BundledAskpassHelper: Sendable {
    public let url: URL
    public static func discover(in bundle: Bundle = .main) throws -> Self {
        guard bundle.bundleIdentifier == "org.openlxssh.OpenLXSSH" else { throw AskpassError.identity }
        let url = bundle.bundleURL.appendingPathComponent("Contents/Helpers/openlxssh-askpass")
        var attributes = stat()
        guard url.isFileURL, lstat(url.path, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_uid == getuid(), attributes.st_mode & 0o022 == 0,
              ap_signed_bundled_helper(url.path) == 0 else { throw AskpassError.identity }
        return Self(url: url)
    }
}

/// One service/grant per direct-session generation. Receives only on main;
/// LocalProcess remains the only PTY/process owner and sole reaper.
@MainActor
package final class AskpassBroker {
    private let own: ap_identity
    private var parent: ap_identity?
    private var listener: UInt32
    package let serviceName: String
    private var auth: AuthenticationState
    private var pending: (Request, ReplyRight, ap_identity, audit_token_t)?
    private var timer: Timer?
    private var closed = false
    private let validateImage: (ap_identity) -> Bool
    private var eventConsumed = false
    package var onAuthenticated: (() -> Void)?
    package var onRequest: ((AuthenticationRequest) -> Void)?
    package var onFailure: ((AskpassError) -> Void)?
    package private(set) var acceptedRequests = 0
    package private(set) var rejectedRequests = 0
    package private(set) var authenticatedEvents = 0
    private var validatedHelperCount = 0
    #if TRANSPORT_HOST_PROBE
    package private(set) var helperIdentities: [ap_identity] = []
    #endif

    package init(token: SessionToken, validateImage: @escaping (ap_identity) -> Bool = { expected in
        var expected = expected
        return ap_signed_ssh(&expected) == 0 && ap_process_has_ctty(expected.pid) != 0
    }) throws {
        guard ap_self_signed() == 0 else { throw AskpassError.identity }
        own = try identity(getpid())
        self.validateImage = validateImage
        auth = AuthenticationState(grant: SessionGrant(session: token.sessionID, generation: token.generation, nonce: try nonce()), now: now())
        var name = [CChar](repeating: 0, count: 128), port: UInt32 = 0
        guard ap_mach_start(&name, name.count, &port) == 0 else { throw AskpassError.unavailable }
        guard let end = name.firstIndex(of: 0),
              let service = String(bytes: name[..<end].map { UInt8(bitPattern: $0) }, encoding: .utf8) else {
            // The bridge creates a bounded ASCII service name. If that contract is
            // ever violated, drop this newly owned receive/send right before failing.
            name[name.count - 1] = 0
            _ = name.withUnsafeBufferPointer { ap_mach_stop(port, $0.baseAddress!) }
            throw AskpassError.unavailable
        }
        serviceName = service; listener = port
    }

    package func environment(helper: BundledAskpassHelper) -> [String: String] {
        ["AP_SERVICE": serviceName, "AP_BROKER_PID": String(own.pid), "AP_BROKER_SECONDS": String(own.seconds),
         "AP_BROKER_MICROS": String(own.microseconds), "AP_SESSION": auth.grant.session.uuidString,
         "AP_GENERATION": String(auth.grant.generation), "AP_NONCE": auth.grant.nonce,
         "SSH_ASKPASS": helper.url.path, "SSH_ASKPASS_REQUIRE": "force"]
    }

    // Module-internal, invoked synchronously ONLY with this session's newly-created
    // LocalProcess.shellPid, before the main queue can consume helper requests.
    func registerCreatedProcess(_ pid: pid_t) throws {
        guard !closed, parent == nil else { throw AskpassError.stale }
        let child = try identity(pid)
        guard child.ppid == own.pid, child.uid == getuid(), child.ruid == getuid() else { throw AskpassError.identity }
        parent = child
        timer = Timer.scheduledTimer(withTimeInterval: 0.02, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.pump() }
        }
        if let timer { RunLoop.main.add(timer, forMode: .common) }
    }
    private func checkParent() throws {
        guard !closed, let parent, same(try identity(parent.pid), parent), validateImage(parent) else { throw AskpassError.parentExited }
    }
    private func pump() {
        guard !closed, parent != nil else { return }
        for _ in 0..<8 {
            do {
                let message = try receiveMach(listener, reply: false, timeout: 0)
                do {
                    let helper = try requestPeer(message.token)
                    guard let parent, helper.ppid == parent.pid, let right = message.reply else { throw AskpassError.identity }
                    try checkParent()
                    guard validatedHelperCount < 16 else { throw AskpassError.bounds }
                    validatedHelperCount += 1
                    if let event = try? message.decode(ControlEvent.self) {
                        guard !eventConsumed, pending == nil, event.event == "authenticated-v1",
                              event.session == auth.grant.session, event.generation == auth.grant.generation,
                              event.nonce == auth.grant.nonce else { throw AskpassError.stale }
                        // Before signalling state, acknowledge only to this exact
                        // audited peer. A stale/replayed event cannot reconnect.
                        guard same(try requestPeer(message.token), helper) else { throw AskpassError.identity }
                        try right.send(ControlAcknowledgement(session: event.session, generation: event.generation, id: event.id))
                        eventConsumed = true; authenticatedEvents += 1
                        auth.close(.cancelled) // no more readpass/automatic answers
                        onAuthenticated?()
                        continue
                    }
                    guard !eventConsumed else { throw AskpassError.stale }
                    let request = try message.decode(Request.self)
                    try auth.begin(request, now: now())
                    pending = (request, right, helper, message.token)
                    #if TRANSPORT_HOST_PROBE
                    helperIdentities.append(helper)
                    #endif
                    acceptedRequests += 1
                    onRequest?(request)
                } catch { rejectedRequests += 1 }
            } catch AskpassError.timeout { break }
            catch { rejectedRequests += 1; break }
        }
        guard !closed else { return }
        if !eventConsumed, now() >= auth.expires { fail(.timeout); return }
        if let pending {
            do {
                try checkParent()
                guard now() < (auth.deadline ?? 0) else { throw AskpassError.timeout }
                guard ap_mach_reply_alive(pending.1.raw) != 0, same(try requestPeer(pending.3), pending.2) else { throw AskpassError.helperFailed }
            } catch { fail((error as? AskpassError) ?? .helperFailed) }
        }
    }
    func submit(_ response: AuthenticationResponse, requestID: UUID, token: SessionToken) throws {
        guard !closed, token.sessionID == auth.grant.session, token.generation == auth.grant.generation,
              let pending, pending.0.id == requestID else { throw AskpassError.stale }
        do {
            try checkParent()
            guard same(try requestPeer(pending.3), pending.2) else { throw AskpassError.helperFailed }
            let reply = try Reply(request: pending.0, decision: response)
            try auth.finish(requestID, generation: token.generation, now: now())
            if case .cancel = response { fail(.cancelled); return }
            try pending.1.send(reply)
            self.pending = nil
        } catch {
            fail((error as? AskpassError) ?? .helperFailed)
            throw error
        }
    }
    #if TRANSPORT_HOST_PROBE
    package func revokeProbeReplyPort() { pending = nil }
    #endif
    private func fail(_ reason: AskpassError) {
        guard !closed else { return }
        close(reason)
        onFailure?(reason)
    }
    func close(_ reason: AskpassError = .cancelled) {
        guard !closed else { return }
        closed = true; auth.close(reason)
        // Destroying send-once right wakes the helper receive; no PID kill.
        pending = nil
        timer?.invalidate(); timer = nil
        _ = ap_mach_stop(listener, serviceName); listener = 0
        parent = nil; onRequest = nil
    }
    isolated deinit {
        timer?.invalidate()
        if listener != 0 { _ = ap_mach_stop(listener, serviceName) }
    }
}
