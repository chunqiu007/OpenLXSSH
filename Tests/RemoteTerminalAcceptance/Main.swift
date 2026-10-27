import AppKit
import Darwin
import Foundation
import OpenLXSSHTransport
import OpenLXSSHTrust
import RemoteTerminalCore
import Security

@MainActor final class StopFlag {
    private(set) var requested = false
    private var sources: [DispatchSourceSignal] = []
    init() {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in self?.requested = true }
            source.resume(); sources.append(source)
        }
    }
    func close() { sources.forEach { $0.cancel() }; sources.removeAll() }
}

enum SignedConsumer {
    static func check() throws {
        guard Bundle.main.bundleIdentifier == "org.openlxssh.OpenLXSSH", Bundle.main.bundleURL.pathExtension == "app",
              Bundle.main.object(forInfoDictionaryKey: "OpenLXSSHRemoteTerminalTestOnly") as? Bool == true,
              Bundle.main.bundleURL.path.hasPrefix(BuildLocation.buildRoot + "/host-"),
              Bundle.main.bundleURL.lastPathComponent == "OpenLXSSHRemoteTerminal.app" else { throw TerminalCheckError.signature }
        var requirement: SecRequirement?, code: SecCode?
        guard SecRequirementCreateWithString("anchor apple generic and identifier \"org.openlxssh.OpenLXSSH\" and certificate leaf[subject.OU] = \"" + BuildLocation.team + "\"" as CFString, [], &requirement) == errSecSuccess,
              SecCodeCopySelf([], &code) == errSecSuccess, let code, let requirement,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw TerminalCheckError.signature }
        // discover and the production Mach broker separately require the fixed helper ID,
        // same Team, Hardened Runtime, and no helper entitlements. No ad-hoc fallback.
    }
}

@MainActor final class TerminalCase {
    let session: DirectSSHSession
    private var report = TerminalReport()
    private var ended = false
    private var failure: TerminalCheckError?
    init(store: HostTrustStore, sessionDirectory: String) throws {
        session = DirectSSHSession(trustStore: store, sessionDirectory: try AbsolutePath(sessionDirectory),
                                   helper: try BundledAskpassHelper.discover(), scanner: try SystemHostKeyScanner(timeoutSeconds: TerminalContract.scanSeconds))
        session.terminal.setHistoryLimit(100)
        session.onStateChange = { [weak self] token, state in
            guard let self, token == self.session.token else { return }
            self.recordStateChange(state)
        }
        session.onAuthenticationRequest = { [weak self] _, _ in
            guard let self else { return }
            self.report.authenticationRequests += 1
            if self.report.connectedEvents > 0 { self.report.postConnectedAuthenticationRequests += 1 }
            self.failure = .authRequest; self.session.cancel() // No respond/manual/Keychain API in this consumer.
        }
        session.onTrustRequired = { [weak self] _ in self?.failure = .trustRequest; self?.session.cancel() }
    }
    private func observation() -> SessionObservation {
        let state: ObservedSessionState
        var reason: ObservedSessionFailure?
        switch session.state {
        case .idle: state = .idle
        case .preparing: state = .preparing
        case .awaitingTrust: state = .awaitingTrust
        case .authenticating: state = .authenticating
        case .connectionPending: state = .connectionPending
        case .connected: state = .connected
        case .disconnected: state = .disconnected
        case .closing: state = .closing
        case .closed: state = .closed
        case .failed(let failure):
            state = .failed
            switch failure {
            case .invalidConfiguration: reason = .invalidConfiguration
            case .launchFailed: reason = .launchFailed
            case .trustRejected: reason = .trustRejected
            case .trustScanFailed: reason = .trustScanFailed
            case .authenticationFailed: reason = .authenticationFailed
            case .authenticationTimeout: reason = .authenticationTimeout
            case .inputFailed: reason = .inputFailed
            }
        }
        let input: ObservedInputError?
        switch session.inputError {
        case .busy?: input = .busy
        case .closed?: input = .closed
        case .stale?: input = .stale
        case .invalidConfiguration?: input = .invalidConfiguration
        case .inputFull?: input = .inputFull
        case .inactive?: input = .inactive
        case nil: input = nil
        }
        return SessionObservation(state: state, failure: reason, lastExitCode: session.lastExitCode,
                                  inputError: input, pendingInputBytes: session.pendingInputBytes, ownedPID: session.ownedProcessID)
    }
    private func recordStateChange(_ state: SSHSessionState) {
        let current = observation()
        report.postAuth?.lastObservedSession = current
        if let reason = current.failure { report.postAuth?.terminalFailure = reason }
        do {
            switch state {
            case .connected:
                report.connectedEvents += 1
                try report.postAuth?.mark(.connected, now: ProcessInfo.processInfo.systemUptime)
            case .failed, .disconnected:
                ended = true
                try report.postAuth?.mark(.sessionEnded, now: ProcessInfo.processInfo.systemUptime)
            default: break
            }
        } catch { failure = .integrity }
    }
    private func tick(_ stop: StopFlag, deadline: Double) throws {
        report.postAuth?.stopRequested = stop.requested
        report.postAuth?.lastObservedSession = observation()
        if stop.requested { throw TerminalCheckError.cancelled }
        if let failure { throw failure }
        guard ProcessInfo.processInfo.systemUptime < deadline else { throw TerminalCheckError.deadline }
        guard !ended else { throw TerminalCheckError.connection }
    }
    private func enqueue(_ data: Data, stage: PostAuthStage, event: PostAuthEvent, stop: StopFlag, deadline: Double) throws {
        report.postAuth?.stage = stage
        try tick(stop, deadline: deadline)
        let first = report.postAuth?.inputAttempts == 0
        if first {
            report.postAuth?.firstInputBefore = observation()
            try report.postAuth?.mark(.firstInputAttempt, now: ProcessInfo.processInfo.systemUptime)
        }
        report.postAuth?.inputAttempts += 1
        report.postAuth?.lastInputByteCount = data.count
        try session.sendInput(data)
        report.postAuth?.inputReturns += 1
        report.postAuth?.lastInputAfter = observation()
        if first {
            report.postAuth?.firstInputAfter = observation()
            try report.postAuth?.mark(.firstInputReturned, now: ProcessInfo.processInfo.systemUptime)
        }
        try report.postAuth?.mark(event, now: ProcessInfo.processInfo.systemUptime)
    }
    func run(input: LiveInput, stop: StopFlag, nonce: String) async -> TerminalReport {
        let started = ProcessInfo.processInfo.systemUptime
        let deadline = started + TerminalContract.fullSeconds
        var remoteStarted = false
        do {
            report.postAuth = try PostAuthDiagnostics(start: started)
            report.postAuth?.stage = .connecting
            try report.postAuth?.mark(.connectRequested, now: ProcessInfo.processInfo.systemUptime)
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22221))
            let configuration = try SSHSessionConfiguration(connection: SSHConnection(host: host, user: SSHUser("fixture")),
                authentication: SSHAuthentication(method: .privateKey(input.privateKeyPath, keyboardInteractive: false)),
                connectTimeout: TerminalContract.connectSeconds, serverAliveInterval: 5, serverAliveCountMax: 1)
            _ = try session.connect(configuration) // No savedPassword; key-only is fixed.
            while report.connectedEvents == 0 {
                try tick(stop, deadline: deadline); try await Task.sleep(for: .milliseconds(25))
            }
            guard report.connectedEvents == 1, let pid = session.ownedProcessID, pid > 0 else { throw TerminalCheckError.connection }
            report.ownedPID = pid // Connected and PID alone are deliberately NOT a shell-ready assertion.
            try tick(stop, deadline: deadline)
            var shortACK = try ShortShellACK(nonce: nonce, start: ProcessInfo.processInfo.systemUptime)
            try enqueue(shortACK.command(), stage: .shortACKEnqueue, event: .shortACKEnqueued, stop: stop, deadline: min(deadline, shortACK.deadline))
            try shortACK.didEnqueue(now: ProcessInfo.processInfo.systemUptime)
            report.postAuth?.stage = .waitingShortACK
            while !shortACK.acknowledged {
                try tick(stop, deadline: min(deadline, shortACK.deadline))
                if try shortACK.inspect(rendered: session.terminal.text, now: ProcessInfo.processInfo.systemUptime) {
                    report.shellACK = true
                    try report.postAuth?.mark(.shortACKReceived, now: ProcessInfo.processInfo.systemUptime)
                }
                if !shortACK.acknowledged { try await Task.sleep(for: .milliseconds(25)) }
            }
            try shortACK.requireAcknowledged() // No loader/source/credentials before the independent ACK.
            let source = Data(base64Encoded: BuildLocation.probeBase64)!
            guard Syntax.hash(source) == BuildLocation.probeSHA256 else { throw TerminalCheckError.integrity }
            var budget = try ProbeBudget(nonce: nonce, sourceCount: source.count, sourceSHA256: BuildLocation.probeSHA256, start: ProcessInfo.processInfo.systemUptime)
            try report.postAuth?.mark(.loaderAttempt, now: ProcessInfo.processInfo.systemUptime)
            try enqueue(ProbePlan.command(source: source, nonce: nonce), stage: .loaderEnqueue, event: .loaderEnqueued, stop: stop, deadline: min(deadline, budget.deadline))
            remoteStarted = true; report.postAuth?.remoteStarted = true
            report.postAuth?.stage = .waitingProbe
            var done = false
            while !done {
                try tick(stop, deadline: min(deadline, budget.deadline))
                let previousEvents = budget.events
                let action = try budget.inspect(session.terminal.text, now: ProcessInfo.processInfo.systemUptime)
                report.probeProcessACK = budget.remotePID != nil
                report.postAuth?.remotePID = budget.remotePID
                if budget.events > previousEvents {
                    try report.postAuth?.mark(.firstProbeFrame, now: ProcessInfo.processInfo.systemUptime)
                    try report.postAuth?.mark(.lastProbeFrame, now: ProcessInfo.processInfo.systemUptime)
                }
                report.probeEvents = budget.events
                report.remoteCleanup = budget.cleanupAcknowledged
                switch action {
                case .none: break
                case .source:
                    try enqueue(source, stage: .sourceEnqueue, event: .sourceEnqueued, stop: stop, deadline: min(deadline, budget.deadline))
                    report.postAuth?.stage = .waitingProbe
                case .sample:
                    try enqueue(ProbePlan.input, stage: .sampleEnqueue, event: .sampleEnqueued, stop: stop, deadline: min(deadline, budget.deadline))
                    report.postAuth?.stage = .waitingProbe
                case .interrupt:
                    report.inputByteHashMatched = true
                    try enqueue(Data([3]), stage: .interruptEnqueue, event: .interruptEnqueued, stop: stop, deadline: min(deadline, budget.deadline))
                    report.postAuth?.stage = .waitingProbe
                case .resize:
                    report.interruptObserved = true
                    report.postAuth?.stage = .resizeEnqueue
                    try tick(stop, deadline: min(deadline, budget.deadline))
                    session.terminal.resize(cols: ProbePlan.width, rows: ProbePlan.height)
                    try report.postAuth?.mark(.resizeApplied, now: ProcessInfo.processInfo.systemUptime)
                    try enqueue(Data("S\r".utf8), stage: .resizeEnqueue, event: .resizeApplied, stop: stop, deadline: min(deadline, budget.deadline))
                    report.postAuth?.stage = .waitingProbe
                case .vimKeys:
                    report.remoteSizeMatched = true
                    try enqueue(ProbePlan.vimKeys, stage: .vimEnqueue, event: .vimEnqueued, stop: stop, deadline: min(deadline, budget.deadline))
                    report.postAuth?.stage = .waitingProbe
                case .complete:
                    try budget.requireComplete(); report.vimBytesHashMatched = true
                    report.remoteCleanup = true; report.returnedToOuter = true; report.remoteProcessReleased = true; done = true
                    report.postAuth?.stage = .probeComplete
                    try report.postAuth?.mark(.probeComplete, now: ProcessInfo.processInfo.systemUptime)
                }
                try await Task.sleep(for: .milliseconds(25))
            }
            guard report.authenticationRequests == 0, report.postConnectedAuthenticationRequests == 0,
                  session.state == .connected, session.ownedProcessID == report.ownedPID else { throw TerminalCheckError.authRequest }
        } catch {
            report.failure = (error as? TerminalCheckError) ?? .input
            let failedStage = report.postAuth?.stage
            report.postAuth?.failureStage = failedStage
            report.postAuth?.failureSession = observation()
            report.postAuth?.stopRequested = stop.requested
            // During raw input/Vim, cancellation closes the PTY; remote finally/110s
            // alarm is the bounded fallback. Do not claim remote cleanup on failure.
            if remoteStarted { report.remoteProcessReleased = false; report.remoteCleanup = false }
        }
        report.postAuth?.preCloseSession = observation()
        report.postAuth?.stopRequested = stop.requested
        do { try report.postAuth?.mark(.cleanupStarted, now: ProcessInfo.processInfo.systemUptime) }
        catch { report.failure = .integrity }
        report.postAuth?.stage = .closing
        session.cancel(); session.closeTab()
        let closeDeadline = ProcessInfo.processInfo.systemUptime + TerminalContract.drainSeconds
        while session.state != .closed || session.ownedProcessID != nil {
            if ProcessInfo.processInfo.systemUptime >= closeDeadline { report.failure = .cleanup; break }
            try? await Task.sleep(for: .milliseconds(20))
        }
        report.closed = session.state == .closed
        if let pid = report.ownedPID {
            report.ownedPIDReleased = kill(pid, 0) == -1 && errno == ESRCH && session.ownedProcessID == nil
        }
        if !report.closed || !report.ownedPIDReleased { report.failure = .cleanup }
        report.postAuth?.stage = report.closed ? .closed : .closing
        report.postAuth?.lastObservedSession = observation()
        do { try report.postAuth?.mark(.cleanupEnded, now: ProcessInfo.processInfo.systemUptime) }
        catch { report.failure = .integrity }
        return report
    }
}

@main enum Main {
    @MainActor static func main() {
        do {
            let options = try TerminalOptions.parse(Array(CommandLine.arguments.dropFirst()))
            if options.action == .help { print("Remote terminal test-only: default/help/validate inert; --live requires explicit local-fixture and engine-ready flags. No nested auth/IME/mac26/all-tools acceptance."); return }
            if options.action == .validate { print("Syntax valid only; no files/generation/Docker/socket/signing/live."); return }
            try SignedConsumer.check()
            guard let path = options.contractPath else { throw TerminalCheckError.arguments }
            _ = NSApplication.shared; NSApp.setActivationPolicy(.prohibited)
            Task { @MainActor in exit(await execute(path: path)) }
            NSApp.run()
        } catch { fputs("Remote terminal consumer refused; no private details emitted.\n", stderr); exit(2) }
    }
    @MainActor static func execute(path: String) async -> Int32 {
        var result = TerminalReport()
        do {
            let input = try await Task.detached { try LiveInput.load(path: path) }.value
            try await Task.detached { try LiveMetadata.verify(input.contract) }.value
            _ = umask(0o077)
            let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            let root = BuildLocation.ownRoot + "/.runtime/run-" + nonce
            guard mkdir(root, 0o700) == 0, mkdir(root + "/trust", 0o700) == 0, mkdir(root + "/sessions", 0o700) == 0 else { throw TerminalCheckError.unsafeFile }
            let store = try await Task.detached { try HostTrustStore(directory: AbsolutePath(root + "/trust")) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22221))
            guard case .pending(let pending) = try await store.evaluate(host: host, key: input.key) else { throw TerminalCheckError.provenance }
            _ = try await store.confirm(pending, displayedFingerprint: input.contract.expectedFingerprint)
            let stop = StopFlag(); defer { stop.close() }
            let baseline = descriptorCount()
            var owner: TerminalCase? = try TerminalCase(store: store, sessionDirectory: root + "/sessions")
            result = await owner!.run(input: input, stop: stop, nonce: nonce)
            owner = nil
            let deadline = ProcessInfo.processInfo.systemUptime + 3
            while descriptorCount() > baseline && ProcessInfo.processInfo.systemUptime < deadline { try? await Task.sleep(for: .milliseconds(25)) }
            result.fdReturnedToBaseline = descriptorCount() <= baseline
            if !result.fdReturnedToBaseline { result.failure = .cleanup }
            let bytes = try JSONEncoder().encode(result)
            try OwnedInput.write(bytes + Data([10]), path: root + "/result.json")
            print(String(decoding: bytes, as: UTF8.self)) // Fixed metadata only, never terminal snapshots.
            return result.failure == nil ? 0 : 1
        } catch {
            result.failure = (error as? TerminalCheckError) ?? .connection
            if let bytes = try? JSONEncoder().encode(result) { print(String(decoding: bytes, as: UTF8.self)) }
            return 1
        }
    }
    static func descriptorCount() -> Int {
        var count = 0
        for fd: Int32 in 0..<4096 { if fcntl(fd, F_GETFD) != -1 { count += 1 } }
        return count
    }
}
