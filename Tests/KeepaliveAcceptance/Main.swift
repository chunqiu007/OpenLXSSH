import AppKit
import Darwin
import Foundation
import OpenLXSSHTransport
import OpenLXSSHTrust
import RemoteTerminalCore
import Security

enum SignedConsumer {
    static func check() throws {
        guard Bundle.main.bundleIdentifier == "org.openlxssh.OpenLXSSH", Bundle.main.bundleURL.pathExtension == "app",
              Bundle.main.object(forInfoDictionaryKey: "OpenLXSSHKeepaliveTestOnly") as? Bool == true,
              Bundle.main.bundleURL.path.hasPrefix(BuildLocation.buildRoot + "/host-"),
              Bundle.main.bundleURL.lastPathComponent == "OpenLXSSHKeepalive.app" else { throw KeepaliveError.provenance }
        var requirement: SecRequirement?, code: SecCode?
        guard SecRequirementCreateWithString("anchor apple generic and identifier \"org.openlxssh.OpenLXSSH\" and certificate leaf[subject.OU] = \"" + BuildLocation.team + "\"" as CFString,[],&requirement) == errSecSuccess,
              SecCodeCopySelf([],&code) == errSecSuccess, let code, let requirement,
              SecCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),requirement) == errSecSuccess else { throw KeepaliveError.provenance }
    }
}

/// Dedicated inherited FIFO stdin/stdout, owned by supervisor Popen, not SSH bytes.
struct PrivateControl {
    let owner: Int32
    init() throws {
        owner = getppid()
        guard owner > 1 else { throw KeepaliveError.control }
        for fd: Int32 in [0,1] {
            var info = stat()
            guard fstat(fd,&info) == 0, info.st_mode & S_IFMT == S_IFIFO, info.st_uid == getuid(),
                  fcntl(fd,F_SETFD,FD_CLOEXEC) == 0 else { throw KeepaliveError.control }
        }
        guard fcntl(0,F_SETFL,fcntl(0,F_GETFL)|O_NONBLOCK) == 0 else { throw KeepaliveError.control }
    }
    func send(_ object: [String: Any]) throws {
        guard getppid() == owner else { throw KeepaliveError.control }
        let data = try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys]) + Data([10])
        guard data.count < 2048 else { throw KeepaliveError.control }
        var offset = 0
        while offset < data.count {
            let n = data.withUnsafeBytes { Darwin.write(1,$0.baseAddress!.advanced(by:offset),$0.count-offset) }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw KeepaliveError.control };offset += n
        }
    }
    @MainActor func receive(op: String, run: String, role: KRole, seconds: Double) async throws -> [String: Any] {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        var data = Data(), buffer = [UInt8](repeating:0,count:2048)
        while ProcessInfo.processInfo.systemUptime < deadline {
            guard getppid() == owner else { throw KeepaliveError.control }
            let count = Darwin.read(0,&buffer,buffer.count)
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) { try await Task.sleep(for:.milliseconds(20));continue }
            guard count > 0 else { throw KeepaliveError.control }
            data.append(contentsOf:buffer.prefix(count))
            guard data.count < 2048 else { throw KeepaliveError.control }
            if data.last == 10 {
                return try KeepaliveControl.decode(data,op:op,run:run,role:role)
            }
        }
        throw KeepaliveError.deadline
    }
}

@MainActor final class StopFlag {
    private(set) var requested = false
    private var sources: [DispatchSourceSignal] = []
    init() {
        for number in [SIGINT,SIGTERM] {
            signal(number,SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal:number,queue:.main)
            source.setEventHandler { [weak self] in self?.requested = true };source.resume();sources.append(source)
        }
    }
    func close() { sources.forEach { $0.cancel() };sources.removeAll() }
}
@MainActor final class KeepaliveCase {
    let session: DirectSSHSession
    var report: KeepaliveReport
    private var callbackFailure = false, outputEvents = 0
    private let stop: StopFlag
    init(store: HostTrustStore,directory: String,role: KRole,stop: StopFlag) throws {
        self.stop = stop
        report = .init(role:role)
        session = DirectSSHSession(trustStore:store,sessionDirectory:try AbsolutePath(directory),helper:try BundledAskpassHelper.discover(),scanner:try SystemHostKeyScanner(timeoutSeconds:15))
        session.terminal.setHistoryLimit(100)
        session.onAuthenticationRequest = { [weak self] _,_ in self?.report.authenticationRequests += 1;self?.callbackFailure = true }
        session.onTrustRequired = { [weak self] _ in self?.report.trustRequests += 1;self?.callbackFailure = true }
        session.onOutput = { [weak self] _ in self?.outputEvents += 1 }
    }
    private func checkStop() throws {
        if stop.requested { report.stopBeforeResult = true;throw KeepaliveError.connection }
    }
    private func process() throws -> ProcessBirth {
        guard let pid = session.ownedProcessID,pid > 1 else { throw KeepaliveError.identity }
        var info = proc_bsdinfo();let size = MemoryLayout<proc_bsdinfo>.size
        guard proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,Int32(size)) == Int32(size),info.pbi_ppid == UInt32(getpid()),info.pbi_uid == getuid() else { throw KeepaliveError.identity }
        return .init(pid:pid,ppid:Int32(info.pbi_ppid),uid:info.pbi_uid,startSeconds:info.pbi_start_tvsec,startMicroseconds:info.pbi_start_tvusec)
    }
    private func current(_ birth: ProcessBirth,_ token: SessionToken) throws {
        try checkStop()
        guard !callbackFailure,session.state == .connected,session.token == token,try process() == birth else { throw KeepaliveError.connection }
    }
    private func ack(_ nonce: String) async throws {
        var budget = try ShortShellACK(nonce:nonce,start:ProcessInfo.processInfo.systemUptime)
        try session.sendInput(budget.command());try budget.didEnqueue(now:ProcessInfo.processInfo.systemUptime)
        while !budget.acknowledged {
            try checkStop()
            guard !callbackFailure,session.state == .connected else { throw KeepaliveError.connection }
            _ = try budget.inspect(rendered:session.terminal.text,now:ProcessInfo.processInfo.systemUptime)
            if !budget.acknowledged { try await Task.sleep(for:.milliseconds(20)) }
        }
    }
    func run(input: LiveInput,control: PrivateControl,run: String) async -> KeepaliveReport {
        var resultObserved = false
        do {
            let host = HostIdentity(address:try HostAddress("127.0.0.1"),port:try SSHPort(22221))
            let config = try SSHSessionConfiguration(connection:SSHConnection(host:host,user:SSHUser("fixture")),
                authentication:SSHAuthentication(method:.privateKey(input.privateKeyPath,keyboardInteractive:false)),connectTimeout:20,serverAliveInterval:2,serverAliveCountMax:2)
            let token = try session.connect(config), connectDeadline = ProcessInfo.processInfo.systemUptime + 90
            while session.state != .connected {
                try checkStop()
                guard !callbackFailure,ProcessInfo.processInfo.systemUptime < connectDeadline else { throw KeepaliveError.connection }
                if case .failed = session.state { throw KeepaliveError.connection }
                try await Task.sleep(for:.milliseconds(20))
            }
            let birth = try process();report.ssh = birth;report.sessionID = token.sessionID;report.generation = token.generation
            try await ack(run)
            // Drain only already buffered public shell prompt/output before the quiet interval.
            var lastOutput = outputEvents, stableAt = ProcessInfo.processInfo.systemUptime
            let settleDeadline = stableAt + 3
            while ProcessInfo.processInfo.systemUptime - stableAt < 0.3 {
                try current(birth,token)
                if outputEvents != lastOutput { lastOutput = outputEvents;stableAt = ProcessInfo.processInfo.systemUptime }
                guard ProcessInfo.processInfo.systemUptime < settleDeadline else { throw KeepaliveError.connection }
                try await Task.sleep(for:.milliseconds(20))
            }
            report.shellACK = true
            try current(birth,token)
            try control.send(["op":"shell-ready","run":run,"role":report.role.rawValue,"session":token.sessionID.uuidString.lowercased(),"generation":token.generation,
                "ssh":["pid":birth.pid,"ppid":birth.ppid,"uid":birth.uid,"startSeconds":birth.startSeconds,"startMicroseconds":birth.startMicroseconds]])
            if report.role == .normal {
                _ = try await control.receive(op:"normal-ready",run:run,role:.normal,seconds:10)
                let start = ProcessInfo.processInfo.systemUptime, quietOutputStart = outputEvents
                while ProcessInfo.processInfo.systemUptime - start < 12 {
                    try current(birth,token);report.quietSamples += 1
                    guard outputEvents == quietOutputStart else { throw KeepaliveError.connection }
                    try await Task.sleep(for:.milliseconds(50))
                }
                report.quietApplicationOutputEvents = outputEvents - quietOutputStart
                report.quietSeconds = ProcessInfo.processInfo.systemUptime - start;report.sameTokenPIDDuringQuiet = true
                // No application input was sent during the whole quiet interval.
                try await ack(KeepaliveNonce.fresh(from:run));report.freshACK = true
                try session.sendInput(Data("exit 0\r".utf8))
            } else {
                let arm = try await control.receive(op:"drop-confirmed",run:run,role:.blackhole,seconds:10)
                guard let armMono = arm["armedAt"] as? Double,let armWall = arm["armedWall"] as? Double,
                      let relayNow = arm["relayNow"] as? Double,let relayWall = arm["relayWall"] as? Double else { throw KeepaliveError.control }
                let localNow = ProcessInfo.processInfo.systemUptime, localWall = Date().timeIntervalSince1970
                let transit = localWall - relayWall
                let wallElapsed = localWall - armWall, relayElapsed = relayNow - armMono
                let offset = localNow - relayNow - transit
                let disagreement = abs((relayWall-armWall) - relayElapsed)
                guard transit >= 0,transit < 2,wallElapsed >= 0,wallElapsed < 10,relayElapsed >= 0,relayElapsed <= wallElapsed + 0.2,disagreement < 0.2 else { throw KeepaliveError.control }
                report.relayConsumerClockOffset = offset;report.relayConsumerClockDisagreement = disagreement
                report.armMetadata = "atomic-drop-established-bridge-alive"
                let deadline = localNow + max(0,15-wallElapsed)
                while session.ownedProcessID != nil {
                    try checkStop()
                    guard !callbackFailure else { throw KeepaliveError.authentication }
                    guard ProcessInfo.processInfo.systemUptime < deadline else { report.deadlineBeforeResult = true;throw KeepaliveError.deadline }
                    try await Task.sleep(for:.milliseconds(20))
                }
                report.dropToExitSeconds = wallElapsed + ProcessInfo.processInfo.systemUptime - localNow
            }
            let exitDeadline = ProcessInfo.processInfo.systemUptime + 15
            while session.ownedProcessID != nil {
                try checkStop()
                guard ProcessInfo.processInfo.systemUptime < exitDeadline else { throw KeepaliveError.deadline }
                try await Task.sleep(for:.milliseconds(20))
            }
            report.lastExitCode = session.lastExitCode
            if report.role == .normal {
                guard session.state == .disconnected(0),session.lastExitCode == 0 else { throw KeepaliveError.connection }
                report.naturalState = "disconnected0"
            } else {
                guard session.state == .failed(.launchFailed),session.lastExitCode == 255 else { throw KeepaliveError.connection }
                report.naturalState = "failed-launchFailed"
            }
            try checkStop()
            resultObserved = true
        } catch {
            if error as? KeepaliveError == .deadline { report.deadlineBeforeResult = true }
            report.stopBeforeResult = stop.requested
            report.failure = (error as? KeepaliveError) ?? .connection
        }
        if !resultObserved { report.cancelBeforeResult = true }
        // Report the genuine pre-close result before any cancellation/cleanup can run.
        let encoded = try? JSONEncoder().encode(report)
        if let encoded,let object = try? JSONSerialization.jsonObject(with:encoded) as? [String:Any] {
            try? control.send(["op":"case-result","run":run,"role":report.role.rawValue,"report":object])
        }
        _ = try? await control.receive(op:"result-recorded",run:run,role:report.role,seconds:10)
        if !resultObserved { report.cancelBeforeResult = true }
        session.closeTab()
        let closeDeadline = ProcessInfo.processInfo.systemUptime + 12
        while session.state != .closed || session.ownedProcessID != nil {
            if ProcessInfo.processInfo.systemUptime >= closeDeadline { report.failure = .cleanup;break }
            try? await Task.sleep(for:.milliseconds(20))
        }
        report.closed = session.state == .closed
        if let pid = report.ssh?.pid { report.pidGone = kill(pid,0) == -1 && errno == ESRCH }
        if !report.closed || !report.pidGone { report.failure = .cleanup }
        return report
    }
}

@main enum Main {
    @MainActor static func main() {
        do {
            let options = try KeepaliveOptions.parse(Array(CommandLine.arguments.dropFirst()))
            guard options.live else { print("Keepalive consumer inert. Source review/build/live are separate explicit gates.");return }
            try SignedConsumer.check()
            let control = try PrivateControl()
            _ = NSApplication.shared;NSApp.setActivationPolicy(.prohibited)
            Task { @MainActor in exit(await execute(options,control)) };NSApp.run()
        } catch { fputs("Keepalive consumer refused; no private details.\n",stderr);exit(2) }
    }
    @MainActor static func execute(_ options: KeepaliveOptions,_ control: PrivateControl) async -> Int32 {
        do {
            guard let path = options.contract,let role = options.role,let run = options.run else { throw KeepaliveError.arguments }
            let input = try await Task.detached { try LiveInput.load(path:path) }.value
            guard input.contract.containerID == "1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2",
                  input.contract.imageID == "sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363",
                  input.contract.networkID == "b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1",
                  input.contract.expectedFingerprint == "SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q" else { throw KeepaliveError.provenance }
            try await Task.detached { try LiveMetadata.verify(input.contract) }.value
            let root = BuildLocation.ownRoot + "/.runtime/run-" + run + "-" + role.rawValue
            _ = umask(0o077)
            guard mkdir(root,0o700) == 0,mkdir(root+"/trust",0o700) == 0,mkdir(root+"/sessions",0o700) == 0 else { throw KeepaliveError.provenance }
            let store = try await Task.detached { try HostTrustStore(directory:AbsolutePath(root+"/trust")) }.value
            let host = HostIdentity(address:try HostAddress("127.0.0.1"),port:try SSHPort(22221))
            guard case .pending(let pending) = try await store.evaluate(host:host,key:input.key) else { throw KeepaliveError.provenance }
            _ = try await store.confirm(pending,displayedFingerprint:input.contract.expectedFingerprint)
            let baseline = descriptorCount()
            let stop = StopFlag();defer { stop.close() }
            var owner: KeepaliveCase? = try KeepaliveCase(store:store,directory:root+"/sessions",role:role,stop:stop)
            var report = await owner!.run(input:input,control:control,run:run);owner = nil
            let deadline = ProcessInfo.processInfo.systemUptime + 3
            while descriptorCount()>baseline && ProcessInfo.processInfo.systemUptime<deadline { try? await Task.sleep(for:.milliseconds(20)) }
            report.fdReturnedToBaseline = descriptorCount()<=baseline
            if !report.fdReturnedToBaseline { report.failure = .cleanup }
            let bytes = try JSONEncoder().encode(report)
            try OwnedInput.write(bytes+Data([10]),path:root+"/result.json")
            try control.send(["op":"closed","run":run,"role":role.rawValue,"report":try JSONSerialization.jsonObject(with:bytes)])
            return report.failure == nil ? 0:1
        } catch { return 1 }
    }
    static func descriptorCount() -> Int { (0..<4096).reduce(0) { $0 + (fcntl(Int32($1),F_GETFD) == -1 ? 0:1) } }
}
