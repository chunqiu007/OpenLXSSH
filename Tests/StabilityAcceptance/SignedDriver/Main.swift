// This file is intentionally outside Package.swift. It is a real public-API
// consumer, not an ssh CLI wrapper or a replacement Transport implementation.
import AppKit
import Darwin
import Foundation
import OpenLXSSHTransport
import OpenLXSSHTrust
import Security
import StabilityCore

@MainActor final class TransportSession: AcceptanceSession {
    let session: DirectSSHSession
    let configuration: SSHSessionConfiguration
    private(set) var phase = SessionPhase.pending
    private(set) var authenticated = false
    private(set) var failure: StabilityError?
    var ownedPID: Int32? { session.ownedProcessID }
    var cancellationEligible: Bool {
        guard failure == nil, !authenticated else { return false }
        switch session.state {
        case .preparing, .connectionPending: return true
        default: return false // Never idle, awaiting trust/auth, closing or failed.
        }
    }
    var didChange: (() -> Void)?

    init(store: HostTrustStore, sessionDirectory: AbsolutePath, helper: BundledAskpassHelper,
         configuration: SSHSessionConfiguration) throws {
        self.configuration = configuration
        session = DirectSSHSession(trustStore: store, sessionDirectory: sessionDirectory,
                                   helper: helper, scanner: try SystemHostKeyScanner())
        session.terminal.setHistoryLimit(10_000)
        session.onStateChange = { [weak self] token, state in
            guard let self, token == self.session.token else { return }
            switch state {
            case .connected:
                // Only the official signed outer-auth path sets this. No PTY text,
                // process spawn, shell prompt, timeout, or keyscan success is counted.
                self.authenticated = true; self.phase = .connected
            case .failed, .disconnected:
                self.failure = .connectionLost; self.phase = .failed
            case .closing: self.phase = .closing
            case .closed: self.phase = .closed
            default: self.phase = .pending
            }
            self.didChange?()
        }
        session.onTrustRequired = { [weak self] _ in
            // The independently verified key was seeded before connecting.
            // Any new/changed identity is a failure; NEVER accept a keyscan result.
            self?.failure = .fingerprintMismatch; self?.session.cancel()
        }
        session.onAuthenticationRequest = { [weak self] _, _ in
            // No prompt-text guessing, Keychain, saved password, or unknown MFA.
            // Even an encrypted test key is unsupported in this first driver.
            self?.failure = .unsupportedAuthentication; self?.session.cancel()
        }
    }
    func connect() throws { _ = try session.connect(configuration) }
    func cancel() { session.cancel() }
    func close() { session.closeTab() }
    deinit { /* DirectSSHSession remains sole process owner/reaper. */ }
}

@MainActor final class StopMonitor {
    private(set) var requested = false
    private(set) var slept = false
    private var signals: [DispatchSourceSignal] = []
    private var observers: [NSObjectProtocol] = []
    init() {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in self?.requested = true }
            source.resume(); signals.append(source)
        }
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.slept = true; self?.requested = true }
            })
        }
    }
    func dispose() {
        signals.forEach { $0.cancel() }; signals.removeAll()
        let center = NSWorkspace.shared.notificationCenter
        observers.forEach { center.removeObserver($0) }; observers.removeAll()
    }
}

private enum SignatureGuard {
    // No Keychain, signing-identity enumeration, identity override or ad-hoc fallback.
    // Validation only occurs on a future explicitly requested run, never help/validate.
    static func validateCurrentApp() throws -> String {
        let bundle = Bundle.main
        guard bundle.bundleIdentifier == "org.openlxssh.OpenLXSSH", bundle.bundleURL.pathExtension == "app" else {
            throw StabilityError.signedAppRequired
        }
        let requirementText = "anchor apple generic and identifier \"org.openlxssh.OpenLXSSH\""
        var requirement: SecRequirement?, own: SecCode?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              SecCodeCopySelf([], &own) == errSecSuccess, let own, let requirement,
              SecCodeCheckValidity(own, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw StabilityError.signedAppRequired
        }
        // Production BundledAskpassHelper.discover + AskpassBroker perform the
        // same-team/Hardened Runtime/no-entitlements checks again before auth.
        return bundle.bundleURL.path
    }
}

@MainActor final class StabilityRun {
    let options: Options
    let stop: StopMonitor
    let writer: BoundedEvidence
    let sampler: ResourceSampler
    let store: HostTrustStore
    let root: URL
    let configuration: SSHSessionConfiguration
    let helper: BundledAskpassHelper
    var active: [TransportSession] = []
    var lastSample = 0.0
    var metricsIncomplete = false
    var soakStarted = false
    var continuityFailure: StabilityError?
    var connectedStart: ClockReading?
    var connectedEnd: ClockReading?
    var connectedTiming: TimingEvidence? {
        guard let connectedStart else { return nil }
        return TimingEvidence(start: connectedStart, end: connectedEnd ?? .now())
    }

    init(options: Options, fixture: FixturePublic, root: URL, store: HostTrustStore,
         writer: BoundedEvidence, helper: BundledAskpassHelper, stop: StopMonitor) throws {
        self.options = options; self.root = root; self.store = store; self.writer = writer
        self.helper = helper; self.stop = stop
        sampler = try ResourceSampler(exactHelper: helper.url.path)
        let host = HostIdentity(address: try HostAddress(options.host), port: try SSHPort(options.port))
        let connection = SSHConnection(host: host, user: try SSHUser("fixture"))
        guard let directory = options.credentials else { throw StabilityError.invalidArguments }
        configuration = try SSHSessionConfiguration(connection: connection,
            authentication: SSHAuthentication(method: .privateKey(try AbsolutePath(directory + "/id_ed25519"), keyboardInteractive: false)),
            connectTimeout: 10, serverAliveInterval: 15, serverAliveCountMax: 3)
    }
    func make() throws -> TransportSession {
        guard active.allSatisfy({ $0.phase == .closed && $0.ownedPID == nil }) || options.mode == .soak else {
            throw StabilityError.cleanupIncomplete
        }
        if options.mode == .cycles { active.removeAll() }
        let item = try TransportSession(store: store, sessionDirectory: try AbsolutePath(root.appendingPathComponent("sessions").path),
                                        helper: helper, configuration: configuration)
        item.didChange = { [weak self, weak item] in
            guard let self, let item else { return }
            if self.soakStarted, item.phase != .connected {
                self.continuityFailure = .connectionLost
                if self.connectedEnd == nil { self.connectedEnd = .now() }
            }
        }
        active.append(item)
        return item
    }
    func sample(event: EvidenceEvent = .sample, totals: CycleTotals? = nil) throws {
        let samples = try sampler.sample(sessionOwnedPIDs: active.compactMap(\.ownedPID))
        if samples.contains(where: { !$0.complete }) { metricsIncomplete = true }
        try writer.append(EvidenceRow(event: event, totals: totals, resources: samples,
            confirmedGoneHelpers: sampler.confirmedGoneHelpers > 0 ? sampler.confirmedGoneHelpers : nil))
        lastSample = ClockReading.now().monotonic
    }
    func wait() async {
        // Actual production sleep; no environment override, scale, injectable
        // clock, resume, power assertion, clock adjustment or keep-awake service.
        try? await Task.sleep(for: .milliseconds(50))
    }
    func runCycles() async throws -> CycleTotals {
        try sample(event: .start)
        let totals = try await FiniteLifecycle.cycles(cancelEvery: options.cancelEvery,
            stopped: { self.stop.requested || self.stop.slept }, make: { try self.make() },
            wait: {
                await self.wait()
                if ClockReading.now().monotonic - self.lastSample >= Double(self.options.sampleSeconds) {
                    do { try self.sample() } catch { self.continuityFailure = (error as? StabilityError) ?? .resourceUnavailable }
                }
            }, authenticatedCheckpoint: { try self.sample(event: .connected) }, checkpoint: { totals in
                if let failure = self.continuityFailure { throw failure }
                try self.sample(event: .cycleClosed, totals: totals)
            })
        guard totals.authenticatedCycles == 200 else { throw StabilityError.invalidLifecycle }
        return totals
    }
    func runSoak() async throws {
        for _ in 0..<5 { let session = try make(); try session.connect() }
        for _ in 0..<600 {
            if stop.requested { throw StabilityError.cancelled }
            if active.contains(where: { $0.phase == .failed || $0.failure != nil }) { throw StabilityError.connectionLost }
            if active.count == 5 && active.allSatisfy({ $0.phase == .connected && $0.authenticated && $0.ownedPID != nil }) { break }
            await wait()
        }
        guard active.count == 5, active.allSatisfy({ $0.phase == .connected && $0.authenticated && $0.ownedPID != nil }) else { throw StabilityError.timeout }
        soakStarted = true
        let started = ClockReading.now()
        connectedStart = started
        var clock = try ContinuityGuard(start: started, requiredSeconds: Double(options.durationSeconds), maximumGap: Double(options.sampleSeconds + 5))
        try sample(event: .connected)
        // At most 7 days, and the finite iteration budget prevents endless drift.
        let maximumTicks = options.durationSeconds * 20 + 1200
        for tick in 0..<maximumTicks {
            if stop.slept { throw StabilityError.timerDiscontinuity }
            if stop.requested { throw StabilityError.cancelled }
            if let continuityFailure { throw continuityFailure }
            guard active.allSatisfy({ $0.failure == nil && $0.ownedPID != nil }) else { throw StabilityError.connectionLost }
            try clock.observe(.now(), connectedSessions: active.filter({ $0.phase == .connected && $0.authenticated }).count, sleepObserved: stop.slept)
            if clock.completed {
                connectedEnd = clock.latest
                try writer.append(EvidenceRow(event: .end, clock: clock.latest, timing: connectedTiming))
                soakStarted = false
                return
            }
            if tick % (options.sampleSeconds * 20) == 0 { try sample() }
            await wait()
        }
        throw StabilityError.incompleteDuration
    }
    func cleanup() async throws {
        if connectedStart != nil && connectedEnd == nil { connectedEnd = .now() }
        soakStarted = false
        // Close all owned sessions before waiting for each; never signal enumerated PIDs.
        active.forEach { $0.cancel(); $0.close() }
        var failure: StabilityError?
        for session in active {
            do { try await FiniteLifecycle.closeAndDrain(session, wait: { await self.wait() }) }
            catch { failure = .cleanupIncomplete }
        }
        guard failure == nil, active.allSatisfy({ $0.phase == .closed && $0.ownedPID == nil }) else {
            throw StabilityError.cleanupIncomplete
        }
        do {
            guard try sampler.observedChildrenStillAlive().isEmpty else { throw StabilityError.cleanupIncomplete }
        } catch {
            metricsIncomplete = true // Unknown is not an empty/already-clean resource set.
            throw (error as? StabilityError) ?? .resourceUnavailable
        }
        active.removeAll() // release retained terminal/session objects before final self sample
        try ExactWorkspaceCleanup.removeEmptySessions(inExactRunRoot: root.path)
        try sample(event: .cleanup)
        // Keep JSONL, public trust and the exact UUID root for audit. Never remove
        // user material, fixture credentials, App data or unrelated resources.
    }
}

@main enum Main {
    @MainActor static func main() {
        do {
            let options = try Options.parse(Array(CommandLine.arguments.dropFirst()))
            if options.action == .help { print(Options.help); return }
            if options.action == .validate {
                if options.credentials != nil || options.verifiedFingerprint != nil {
                    let fixture = try FixturePublic.inspect(options)
                    print("Read-only fixture public metadata valid: " + fixture.hostFingerprint)
                }
                print("Read-only plan valid; no AppKit/network/writes, no acceptance claim.")
                return
            }
            // run parse has already rejected a missing authorization flag, before any I/O.
            guard #available(macOS 26, *), ProcessInfo.processInfo.operatingSystemVersion.majorVersion == 26 else {
                throw StabilityError.signedAppRequired
            }
            #if !arch(arm64)
            throw StabilityError.signedAppRequired
            #endif
            let fixture = try FixturePublic.inspect(options)
            let appPath = try SignatureGuard.validateCurrentApp()
            let helper = try BundledAskpassHelper.discover()
            guard let revision = Bundle.main.object(forInfoDictionaryKey: "StabilitySourceRevision") as? String,
                  revision.count == 40, revision.allSatisfy({ "0123456789abcdef".contains($0) }),
                  let output = options.outputParent else { throw StabilityError.invalidArguments }
            try PrivateMaterial.check(output, directory: true)
            print("Explicit isolated run: 127.0.0.1:22221 user fixture, keyonly; \(options.mode.rawValue); 200 authenticated cycles; 5 sessions; \(options.durationSeconds)s continuous.\nHost trust: \(fixture.hostFingerprint)\nSigned local App: \(appPath)\nNo upload; JSONL only. Ctrl+C stops owned sessions, never resumes a soak.")
            fflush(stdout)
            let root = URL(fileURLWithPath: output).appendingPathComponent("stability-" + UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try PrivateMaterial.check(root.path, directory: true)
            for name in ["trust", "sessions"] {
                let url = root.appendingPathComponent(name, isDirectory: true)
                try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                try PrivateMaterial.check(url.path, directory: true)
            }
            let writer = try BoundedEvidence(exclusivePath: root.appendingPathComponent("evidence.jsonl").path)
            try writer.append(EvidenceRow(event: .start, metadata: EvidenceMetadata(options: options, fixture: fixture, signedAppPath: appPath, sourceRevision: revision)))
            _ = NSApplication.shared
            NSApp.setActivationPolicy(.prohibited)
            // A real AppKit run loop is required: the official broker uses a
            // common-mode Timer. dispatchMain from async main is not a substitute.
            Task { @MainActor in
                let result = await execute(options: options, fixture: fixture, root: root, writer: writer, helper: helper)
                exit(result)
            }
            NSApp.run() // User-triggered foreground app only; no daemon/scheduling.
        } catch {
            let reason = (error as? StabilityError)?.rawValue ?? "preparationFailed"
            fputs("Stability driver refused/failed: \(reason). No secret details emitted.\n", stderr)
            exit(2)
        }
    }

    @MainActor private static func execute(options: Options, fixture: FixturePublic, root: URL,
                                          writer: BoundedEvidence, helper: BundledAskpassHelper) async -> Int32 {
        do {
            // Mature public-key validator runs off MainActor. Only the independently
            // verified out-of-band key is confirmed, never a keyscan candidate.
            let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: fixture.hostKeyLine) }.value
            guard key.fingerprint == fixture.hostFingerprint else { throw StabilityError.fingerprintMismatch }
            let store = try await Task.detached { try HostTrustStore(directory: AbsolutePath(root.appendingPathComponent("trust").path)) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22221))
            let evaluated = try await store.evaluate(host: host, key: key)
            guard case .pending(let decision) = evaluated else { throw StabilityError.invalidFixture }
            _ = try await store.confirm(decision, displayedFingerprint: fixture.hostFingerprint)
            let stop = StopMonitor()
            defer { stop.dispose() }
            let runner = try StabilityRun(options: options, fixture: fixture, root: root, store: store, writer: writer, helper: helper, stop: stop)
            var runFailure: StabilityError?, totals: CycleTotals?
            do {
                if options.mode == .cycles { totals = try await runner.runCycles() }
                else { try await runner.runSoak() }
            } catch { runFailure = (error as? StabilityError) ?? .resourceUnavailable }
            do { try await runner.cleanup() }
            catch { runFailure = (error as? StabilityError) ?? .cleanupIncomplete }
            if runner.metricsIncomplete && runFailure == nil { runFailure = .resourceUnavailable }
            let status: EvidenceStatus = runFailure == nil ? .completedDriverScope : (runFailure == .cancelled ? .incomplete : .failed)
            try writer.append(EvidenceRow(event: .end, status: status, totals: totals, failure: runFailure, timing: runner.connectedTiming))
            print("Driver result: \(status.rawValue). Evidence: \(writer.path). Not a whole-App/UI/PERF acceptance result.")
            return runFailure == nil ? 0 : 1
        } catch {
            let reason = (error as? StabilityError) ?? .resourceUnavailable
            try? writer.append(EvidenceRow(event: .end, status: .failed, failure: reason))
            fputs("Stability driver preparation failed: \(reason.rawValue). No secret details emitted.\n", stderr)
            return 2
        }
    }
}
