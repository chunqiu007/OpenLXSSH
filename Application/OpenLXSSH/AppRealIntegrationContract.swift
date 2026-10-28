import Foundation

/// Always compiled so shipping builds reject every real-fixture flag BEFORE AppKit/store setup.
/// Parsing/validate never opens a path, discovers a helper, reads Keychain or starts a connection.
enum AppRealIntegrationArguments {
    enum Action: Equatable { case none, help, validate, live }
    struct Options: Equatable {
        let action: Action
        let contractPath: String?
        let scanSeconds: Int
    }
    static let flagNames: Set<String> = ["--real-fixture-test", "--real-fixture-contract", "--real-fixture-validate",
        "--real-fixture-help", "--real-fixture-scan-seconds", "--authorized-local-fixture", "--primary-released"]
    static func parse(_ arguments: [String], hostProbe: Bool) throws -> Options {
        let requested = arguments.contains { $0.hasPrefix("--real-fixture") || flagNames.contains($0) }
        guard requested else { return Options(action: .none, contractPath: nil, scanSeconds: 5) }
        guard hostProbe else { throw AppRealIntegrationFailure.arguments }
        if arguments == ["--real-fixture-help"] { return Options(action: .help, contractPath: nil, scanSeconds: 5) }
        guard let first = arguments.first, ["--real-fixture-test", "--real-fixture-validate"].contains(first) else { throw AppRealIntegrationFailure.arguments }
        var contract: String?, scan = 5, hasScan = false, authorized = false, released = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--real-fixture-contract":
                guard contract == nil, index + 1 < arguments.count else { throw AppRealIntegrationFailure.arguments }
                index += 1; try AppRealIntegrationContract.pathSyntax(arguments[index]); contract = arguments[index]
            case "--real-fixture-scan-seconds":
                guard !hasScan, index + 1 < arguments.count, ["5", "15"].contains(arguments[index + 1]) else { throw AppRealIntegrationFailure.arguments }
                index += 1; hasScan = true; scan = Int(arguments[index])!
            case "--authorized-local-fixture": guard !authorized else { throw AppRealIntegrationFailure.arguments }; authorized = true
            case "--primary-released": guard !released else { throw AppRealIntegrationFailure.arguments }; released = true
            default: throw AppRealIntegrationFailure.arguments
            }
            index += 1
        }
        guard let contract, contract.hasSuffix("/app-real-integration.json") else { throw AppRealIntegrationFailure.arguments }
        if first == "--real-fixture-validate" {
            guard !authorized && !released && !hasScan else { throw AppRealIntegrationFailure.arguments }
            return Options(action: .validate, contractPath: contract, scanSeconds: 5)
        }
        guard authorized && released else { throw AppRealIntegrationFailure.authorization }
        return Options(action: .live, contractPath: contract, scanSeconds: scan)
    }
    static let help = """
    OpenLXSSH HostProbe-only native keyonly integration. Not macOS26 product acceptance.
    --real-fixture-help or --real-fixture-validate --real-fixture-contract /absolute/app-real-integration.json:
      parsing only, NO file/network I/O. Normal launch does not run any fixture test.
    Only after primary review/release and existing local-fixture authorization:
      --real-fixture-test --real-fixture-contract /exact/own/app-real-integration.json --authorized-local-fixture --primary-released
    Optional --real-fixture-scan-seconds 15 is test-only SYSTEM ssh-keyscan allowance;
    default scan5/connect10 stays unchanged. No fake scanner or automatic retry.
    Fixed keyonly fixture@127.0.0.1:22221, no password/OTP/Keychain operations.
    Shipping Debug/Release reject all these flags. Flags are NOT authorization.
    """
}
enum AppRealIntegrationFailure: String, Error {
    case arguments, authorization, contract, unsafeInput, provenance, fingerprint, signature, isolation, timeout, nativeControl, unexpectedAuthentication, failedCheck, cleanup, transferCompletedBeforeLifecycleAction
}
enum AppRealIntegrationPhase: String, Codable, Sendable {
    case readOnly = "read-only", transferSurvivesClose = "transfer-survives-close", windowContinueCancel = "window-continue-cancel", quitContinueCancel = "quit-continue-cancel", fileOperations = "file-operations", terminalSearchPaste = "terminal-search-paste", sessionsReconnect = "sessions-reconnect", batchConflicts = "batch-conflicts", batchOverwrite = "batch-overwrite"
    var isTransfer: Bool { self == .transferSurvivesClose || self == .windowContinueCancel || self == .quitContinueCancel }
    var isTerminalOnly: Bool { self == .terminalSearchPaste || self == .sessionsReconnect }
}
struct AppRealTransferScope: Sendable {
    static let sourceBytes: UInt64 = 16 * 1024 * 1024
    static let chunkBytes = 65_536
    let runID: String
    init(runID: String) throws {
        guard let id = UUID(uuidString: runID), id.uuidString.lowercased() == runID else { throw AppRealIntegrationFailure.contract }
        self.runID = runID
    }
    var directoryName: String { "openlxssh-app-transfer-" + runID }
    var remoteDirectory: String { "/fixture/home/" + directoryName }
    var payloadName: String { "payload-16MiB.bin" }
    var remotePayload: String { remoteDirectory + "/" + payloadName }
    static func isRealInflight(state: String, transferred: UInt64, sourceBytes: UInt64) -> Bool {
        state == "running" && sourceBytes == Self.sourceBytes && transferred > 0 && transferred < sourceBytes
    }
    func permitsRemote(_ path: Data) -> Bool { path == Data(remoteDirectory.utf8) || path == Data(remotePayload.utf8) }
}
struct AppRealTerminalProtocol: Sendable {
    enum Stage: String, Codable, Sendable { case shell, ready, captured, restored, returned, outer }
    let nonce: String
    static let sample = "native-paste 中文 e\u{301}\nsecond fixed line"
    static let maximumOutputBytes = 65536
    init(nonce: String) throws {
        guard AppRealIntegrationContract.hex(nonce, count: 32) else { throw AppRealIntegrationFailure.contract }
        self.nonce = nonce
    }
    var marker: String { "OPENLX-SEARCH-" + nonce }
    var expectedPaste: Data { Data(("\u{1b}[200~" + Self.sample + "\u{1b}[201~").utf8) }
    var shellCommand: Data { Data(("printf '\\101\\1241|" + nonce + "|shell|ok|END\\n'\r").utf8) }
    func frameValue(_ text: String, stage: Stage) throws -> String? {
        guard text.utf8.count <= Self.maximumOutputBytes else { throw AppRealIntegrationFailure.failedCheck }
        let compact = text.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        let prefix = "AT1|" + nonce + "|" + stage.rawValue + "|"
        guard let start = compact.range(of: prefix), let end = compact.range(of: "|END", range: start.upperBound..<compact.endIndex) else { return nil }
        guard compact.range(of: prefix, range: end.upperBound..<compact.endIndex) == nil else { throw AppRealIntegrationFailure.failedCheck }
        let value = String(compact[start.upperBound..<end.lowerBound])
        guard value.utf8.count <= 128 else { throw AppRealIntegrationFailure.failedCheck }; return value
    }
    struct Capture: Equatable, Sendable { let bytes: Int; let sha256: String }
    func parseCapture(_ value: String, expectedHash: String) throws -> Capture {
        guard value.utf8.count <= 69 else { throw AppRealIntegrationFailure.failedCheck }
        let fields = value.split(separator: ",", omittingEmptySubsequences: false)
        guard fields.count == 2, let count = Int(fields[0]), (1..<1024).contains(count), String(count) == fields[0],
              AppRealIntegrationContract.hex(String(fields[1]), count: 64), AppRealIntegrationContract.hex(expectedHash, count: 64),
              count == expectedPaste.count, fields[1] == expectedHash else { throw AppRealIntegrationFailure.failedCheck }
        return Capture(bytes: count, sha256: String(fields[1]))
    }
    func captureMatches(_ value: String, expectedHash: String) -> Bool { (try? parseCapture(value, expectedHash: expectedHash)) != nil }
    func probeCommand() throws -> Data {
        // Fixed public test program, never a generic command/registry. PTY bytes remain
        // memory-only and termios/bracket mode are restored even on bounded failure.
        let source = #"""
import hashlib,os,select,sys,termios,time,tty
n=sys.argv[1]
if len(n)!=32 or any(c not in '0123456789abcdef' for c in n):raise SystemExit(64)
def frame(k,v):
 print('\r\nAT1|'+n+'|'+k+'|'+v+'|END\r\n',flush=True)
original=termios.tcgetattr(0)
data=bytearray()
try:
 tty.setraw(0,termios.TCSANOW)
 for i in range(24):print('\r\nOPENLX-SEARCH-'+n+' row-%02d'%i,flush=True)
 os.write(1,b'\x1b[?2004h')
 frame('ready','ok')
 deadline=time.monotonic()+45
 while not data.endswith(b'\x1b[201~'):
  left=deadline-time.monotonic()
  if left<=0:raise SystemExit(65)
  if select.select([0],[],[],min(.1,left))[0]:
   block=os.read(0,1024-len(data))
   if not block:raise SystemExit(65)
   data.extend(block)
   if len(data)>=1024:raise SystemExit(65)
 frame('captured',str(len(data))+','+hashlib.sha256(data).hexdigest())
finally:
 os.write(1,b'\x1b[?2004l')
 termios.tcsetattr(0,termios.TCSANOW,original)
 if termios.tcgetattr(0)!=original:raise SystemExit(66)
frame('restored','ok')
"""#
        let encoded = Data(source.utf8).base64EncodedString()
        let command = "/usr/bin/python3 -c 'import base64;exec(compile(base64.b64decode(\"" + encoded + "\"),\"<fixed-native-terminal-probe>\",\"exec\"))' " + nonce + "; r=$?; printf '\\101\\1241|" + nonce + "|returned|%s|END\\n' \"$r\"\r"
        guard command.utf8.count < 4096 else { throw AppRealIntegrationFailure.contract }; return Data(command.utf8)
    }
}
struct AppRealSessionsProtocol: Sendable {
    enum Role: String, CaseIterable, Sendable { case aInitial = "a-first", bInitial = "b-first", aReconnected = "a-reconnected" }
    struct ProcessIdentity: Codable, Equatable, Sendable {
        let pid: Int32, parentPID: Int32
        let startSeconds: UInt64, startMicroseconds: UInt64
        var isValid: Bool { pid > 0 && parentPID > 0 && startSeconds > 0 && startMicroseconds < 1_000_000 }
    }
    struct Identity: Codable, Equatable, Sendable {
        let tabID: UUID, sessionID: UUID, generation: UInt64
        let process: ProcessIdentity
        var isValid: Bool { generation > 0 && process.isValid }
    }
    struct Observation: Codable, Sendable {
        private(set) var samples = 0
        private(set) var elapsedSeconds: Double = 0
        mutating func sample(elapsed: Double, disconnectedZero: Bool, tokenUnchanged: Bool, ownedPIDAbsent: Bool,
                             oldProcessGone: Bool, bUnchanged: Bool) throws {
            guard elapsed.isFinite, elapsed >= 0, elapsed <= 10, samples < 256,
                  (samples == 0 ? elapsed == 0 : elapsed > elapsedSeconds),
                  disconnectedZero && tokenUnchanged && ownedPIDAbsent && oldProcessGone && bUnchanged else { throw AppRealIntegrationFailure.failedCheck }
            samples += 1; elapsedSeconds = elapsed
        }
        var complete: Bool { samples >= 2 && elapsedSeconds >= AppRealSessionsProtocol.observationSeconds && elapsedSeconds <= 10 }
    }
    static let maximumOutputBytes = 65536
    static let observationSeconds: Double = 2
    static let keepaliveInterval = 7, keepaliveCountMax = 2
    let nonce: String
    init(nonce: String) throws {
        guard AppRealIntegrationContract.hex(nonce, count: 32) else { throw AppRealIntegrationFailure.contract }
        self.nonce = nonce
    }
    var historyMarker: String { "OPENLX-SESS-HISTORY-" + nonce }
    func ackCommand(_ role: Role) -> Data { Data(("printf '\\101\\1231|" + nonce + "|" + role.rawValue + "|ok|END\\n'\r").utf8) }
    var naturalExitCommand: Data { Data(("printf '\\117PENLX-SESS-HISTORY-" + nonce + "\\n'; exit 0\r").utf8) }
    func acknowledged(_ text: String, role: Role) throws -> Bool {
        guard text.utf8.count <= Self.maximumOutputBytes else { throw AppRealIntegrationFailure.failedCheck }
        let compact = text.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        let prefix = "AS1|" + nonce + "|" + role.rawValue + "|"
        guard let start = compact.range(of: prefix) else { return false }
        guard compact.range(of: prefix, range: start.upperBound..<compact.endIndex) == nil else { throw AppRealIntegrationFailure.failedCheck }
        guard let end = compact.range(of: "|END", range: start.upperBound..<compact.endIndex) else { return false }
        guard compact[start.upperBound..<end.lowerBound] == "ok" else { throw AppRealIntegrationFailure.failedCheck }
        return true
    }
    static func independent(_ a: Identity, _ b: Identity, distinctObjects: Bool) -> Bool {
        a.isValid && b.isValid && distinctObjects && a.tabID != b.tabID && a.sessionID != b.sessionID && a.process.pid != b.process.pid
    }
    static func reconnected(_ old: Identity, _ new: Identity, sameObjects: Bool, oldObservedGone: Bool) -> Bool {
        old.isValid && new.isValid && sameObjects && oldObservedGone && old.tabID == new.tabID && old.sessionID == new.sessionID
            && old.generation < UInt64.max && new.generation == old.generation + 1 && old.process != new.process
    }
    static func naturalDisconnect(disconnectedZero: Bool, lastExitCode: Int32?, ownedPID: Int32?, canReconnect: Bool, oldGone: Bool) -> Bool {
        disconnectedZero && lastExitCode == 0 && ownedPID == nil && canReconnect && oldGone
    }
}
struct AppRealFileScope: Sendable {
    let runID: String
    init(runID: String) throws {
        guard let id = UUID(uuidString: runID), id.uuidString.lowercased() == runID else { throw AppRealIntegrationFailure.contract }
        self.runID = runID
    }
    var root: String { "/fixture/home/openlxssh-app-files-" + runID }
    let neighbor = "保留 邻项.txt", folder = "子目录 空格", renamed = "已改名 目录"
    let child = "内容 e\u{301} [#; $].bin"
    var payloads: [(String, Int)] { [(neighbor, 4096), (folder + "/" + child, 8192)] }
    func allowedRisk(_ bytes: Data) -> Bool {
        [root, root + "/" + neighbor, root + "/" + folder, root + "/" + folder + "/" + child].contains { Data($0.utf8) == bytes }
    }
    func expectedDelete(_ name: String) -> [Data: String] {
        if Data(name.utf8) == Data(renamed.utf8) { return [Data((root + "/" + renamed + "/" + child).utf8): "file", Data((root + "/" + renamed).utf8): "directory"] }
        if Data(name.utf8) == Data(neighbor.utf8) { return [Data((root + "/" + neighbor).utf8): "file"] }
        if name == "root" { return [Data(root.utf8): "directory"] }
        return [:]
    }
    func exactDelete(_ entries: [(Data, String)], name: String, issues: Int) -> Bool {
        let expected = expectedDelete(name)
        return issues == 0 && !expected.isEmpty && entries.count <= 2 && entries.count == expected.count && Set(entries.map(\.0)).count == entries.count
            && entries.allSatisfy { expected[$0.0] == $0.1 }
    }
}
struct AppRealBatchScope: Sendable {
    enum Stage: String, Codable, Sendable { case seed, skip, rename, overwrite }
    let runID: String
    init(runID: String) throws {
        guard let id = UUID(uuidString: runID), id.uuidString.lowercased() == runID else { throw AppRealIntegrationFailure.contract }
        self.runID = runID
    }
    var root: String { "/fixture/home/openlxssh-app-batch-" + runID }
    static let names = ["a.bin", "b.bin"], alternate = "alternate-a.bin"
    static func size(_ name: String) throws -> Int {
        guard let index = names.firstIndex(of: name) else { throw AppRealIntegrationFailure.contract }; return (index + 1) * 4096
    }
    func payload(_ name: String, fresh: Bool) throws -> Data {
        let count = try Self.size(name), seed = Data(("OpenLXSSH batch " + runID + (fresh ? " Fresh/" : " Seed/") + name + "\n").utf8)
        var data = Data(); while data.count < count { data.append(seed.prefix(min(seed.count, count - data.count))) }; return data
    }
    func allowsRisk(_ path: Data) -> Bool { (Self.names + [Self.alternate]).contains { path == Data((root + "/" + $0).utf8) } }
    func exactOverwriteDelete(_ items: [(Data, String)], issues: Int) -> Bool {
        let expected = Dictionary(uniqueKeysWithValues: Self.names.map { (Data((root + "/" + $0).utf8), "file") } + [(Data(root.utf8), "directory")])
        return issues == 0 && items.count == 3 && Set(items.map(\.0)).count == 3 && items.allSatisfy { expected[$0.0] == $0.1 }
    }
    func exactDelete(_ items: [(Data, String)], issues: Int) -> Bool {
        let expected = Dictionary(uniqueKeysWithValues: (Self.names + [Self.alternate]).map { (Data((root + "/" + $0).utf8), "file") } + [(Data(root.utf8), "directory")])
        return issues == 0 && items.count == 4 && Set(items.map(\.0)).count == 4 && items.allSatisfy { expected[$0.0] == $0.1 }
    }
}
#if HOST_PROBE
import OpenLXSSHFiles

struct AppRealBatchGate: Sendable {
    struct Decision: Equatable, Sendable {
        let id: UUID, jobID: UUID, generation: UUID
        let question: TransferDecisionQuestion
        static func actual(_ value: TransferDecisionRequest) -> Self { .init(id: value.id, jobID: value.jobID, generation: value.generation, question: value.question) }
    }
    struct Snapshot: Sendable {
        let id: UUID, generation: UUID, retryOf: UUID?
        let request: TransferRequest, state: TransferJobState, transferredBytes: UInt64, cancellationRequested: Bool
        let pendingDecision: Decision?, error: FileServiceError?, items: [TransferItemResult]
        var retainedTemporaryPaths: [RemotePath] { items.compactMap(\.retainedTemporary) }
        static func actual(_ value: TransferJobSnapshot) -> Self {
            .init(id: value.id, generation: value.generation, retryOf: value.retryOf, request: value.request, state: value.state,
                transferredBytes: value.transferredBytes, cancellationRequested: value.cancellationRequested,
                pendingDecision: value.pendingDecision.map(Decision.actual), error: value.error, items: value.items)
        }
    }
    struct Job: Codable, Equatable, Sendable {
        let id: UUID, generation: UUID, batchID: UUID, sourceServiceID: UUID, destinationServiceID: UUID
        let hostID: String, sourceBase64: String, destinationBase64: String
        init(_ job: Snapshot) {
            id = job.id; generation = job.generation; batchID = job.request.batchID; hostID = job.request.hostID
            sourceServiceID = job.request.source.serviceID; destinationServiceID = job.request.destination.serviceID
            sourceBase64 = job.request.source.path.bytes.base64EncodedString(); destinationBase64 = job.request.destination.path.bytes.base64EncodedString()
        }
    }
    private(set) var jobs: [Job] = []
    private(set) var batches: [AppRealBatchScope.Stage: UUID] = [:]
    private(set) var decisions: Set<UUID> = []
    private(set) var overwriteConflictDecision: UUID?
    private(set) var overwritePathRiskJobs: Set<UUID> = []
    private(set) var overwriteRiskJobs: Set<UUID> = []
    mutating func overwriteDecision(_ request: Decision, job: Snapshot, scope: AppRealBatchScope) throws {
        guard batches[.overwrite] == job.request.batchID, current(job), job.pendingDecision == request,
              request.jobID == job.id, request.generation == job.generation, !decisions.contains(request.id),
              job.transferredBytes == 0, job.items.isEmpty, job.error == nil else { throw AppRealIntegrationFailure.failedCheck }
        switch request.question {
        case .conflict:
            guard overwriteConflictDecision == nil, overwritePathRiskJobs.contains(job.id) else { throw AppRealIntegrationFailure.failedCheck }
            try decision(request, job: job, stage: .overwrite, scope: scope, risk: false)
            overwriteConflictDecision = request.id
        case .risk(.remotePathChecksAreNotAtomic):
            guard !overwritePathRiskJobs.contains(job.id) else { throw AppRealIntegrationFailure.failedCheck }
            try decision(request, job: job, stage: .overwrite, scope: scope, risk: true)
            overwritePathRiskJobs.insert(job.id)
        case .risk(.overwriteIsAtomicButNotCompareAndSwap):
            guard overwriteConflictDecision != nil, overwritePathRiskJobs.contains(job.id), !overwriteRiskJobs.contains(job.id) else { throw AppRealIntegrationFailure.failedCheck }
            try decision(request, job: job, stage: .overwrite, scope: scope, risk: true)
            overwriteRiskJobs.insert(job.id)
        default: throw AppRealIntegrationFailure.failedCheck
        }
    }
    mutating func admit(_ values: [Snapshot], stage: AppRealBatchScope.Stage, scope: AppRealBatchScope, hostID: UUID, serviceID: UUID) throws {
        let names = stage == .rename ? [AppRealBatchScope.names[0]] : AppRealBatchScope.names
        guard batches[stage] == nil, values.count == names.count, Set(values.map(\.id)).count == values.count,
              Set(values.map(\.generation)).count == values.count, Set(values.map { $0.request.batchID }).count == 1,
              let first = values.first, !batches.values.contains(first.request.batchID),
              Set(values.map { $0.request.source.serviceID }).count == 1,
              Set(values.map { $0.request.source.path.bytes }) == Set(names.map { Data(("/" + $0).utf8) }),
              values.allSatisfy({ value in
                  !jobs.contains { $0.id == value.id || $0.generation == value.generation } && value.retryOf == nil &&
                  value.request.hostID == hostID.uuidString && value.request.destination.serviceID == serviceID &&
                  value.request.source.serviceID != serviceID && value.request.kind == .file &&
                  value.request.destination.path.bytes == Data(scope.root.utf8) + value.request.source.path.bytes
              }) else { throw AppRealIntegrationFailure.failedCheck }
        batches[stage] = first.request.batchID; jobs += values.map(Job.init)
    }
    func current(_ job: Snapshot) -> Bool { jobs.contains(Job(job)) && job.request.kind == .file && job.retryOf == nil && !job.cancellationRequested }
    mutating func decision(_ request: Decision, job: Snapshot, stage: AppRealBatchScope.Stage,
                           scope: AppRealBatchScope, risk: Bool) throws {
        guard current(job), batches[stage] == job.request.batchID, job.pendingDecision == request,
              request.jobID == job.id, request.generation == job.generation, !decisions.contains(request.id) else { throw AppRealIntegrationFailure.failedCheck }
        if risk {
            if case .risk(.overwriteIsAtomicButNotCompareAndSwap(let path)) = request.question {
                guard stage == .overwrite, job.state == .waitingRisk, path == job.request.destination.path,
                      job.transferredBytes == 0, job.items.isEmpty, job.error == nil, job.retainedTemporaryPaths.isEmpty else { throw AppRealIntegrationFailure.failedCheck }
            } else {
                guard job.state == .waitingRisk, case .risk(.remotePathChecksAreNotAtomic(let path)) = request.question,
                      path == job.request.destination.path || (stage == .rename && path.bytes == Data((scope.root + "/" + AppRealBatchScope.alternate).utf8)),
                      scope.allowsRisk(path.bytes) else { throw AppRealIntegrationFailure.failedCheck }
            }
        } else {
            guard stage != .seed, job.state == .waitingConflict, case .conflict(let conflict) = request.question,
                  conflict.source == job.request.source.path, conflict.destination == job.request.destination.path,
                  conflict.existing.kind == .regular, let name = job.request.source.path.name,
                  conflict.existing.size == UInt64(try AppRealBatchScope.size(String(decoding: name.bytes, as: UTF8.self))) else { throw AppRealIntegrationFailure.failedCheck }
        }
        decisions.insert(request.id)
    }
    func terminal(_ values: [Snapshot], stage: AppRealBatchScope.Stage, scope: AppRealBatchScope) -> Bool {
        if stage == .overwrite {
            let ids = Set(values.map(\.id))
            guard overwriteConflictDecision != nil, overwritePathRiskJobs == ids, overwriteRiskJobs == ids else { return false }
        }
        let expected = jobs.filter { $0.batchID == batches[stage] }
        guard values.count == (stage == .rename ? 1 : 2), values.count == expected.count,
              Set(values.map(\.id)) == Set(expected.map(\.id)) else { return false }
        return values.allSatisfy { job in
            guard current(job), job.pendingDecision == nil, job.error == nil, job.retainedTemporaryPaths.isEmpty, job.items.count == 1,
                  let item = job.items.first, item.source == job.request.source.path else { return false }
            if stage == .skip { return job.state == .skipped && job.transferredBytes == 0 && item.state == .skipped && item.destination == job.request.destination.path }
            if stage == .overwrite {
                guard item.acknowledgedRisks == [.remotePathChecksAreNotAtomic(path: job.request.destination.path),
                    .overwriteIsAtomicButNotCompareAndSwap(path: job.request.destination.path)] else { return false }
            }
            let target = stage == .rename ? Data((scope.root + "/" + AppRealBatchScope.alternate).utf8) : job.request.destination.path.bytes
            guard let name = job.request.source.path.name, let size = try? AppRealBatchScope.size(String(decoding: name.bytes, as: UTF8.self)) else { return false }
            return job.state == .succeeded && job.transferredBytes == UInt64(size) && item.state == .succeeded(bytes: UInt64(size)) && item.destination.bytes == target
        }
    }
}
#endif
struct AppRealFileDigest: Codable, Equatable, Sendable {
    let relativePathBase64: String
    let bytes: Int
    let sha256: String
}
struct AppRealWindowTransferGate {
    static func sameIdentity(jobID: UUID, generation: UUID, sourceServiceID: UUID, destinationServiceID: UUID, host: String,
                             expected: [String]) -> Bool {
        expected == [jobID.uuidString, generation.uuidString, sourceServiceID.uuidString, destinationServiceID.uuidString, host]
    }
    static func cancelledAndDrained(state: String, managerClosed: Bool, activeWork: Bool, sshClosed: Bool, pidPresent: Bool, windowPresent: Bool, closedServices: Int, handles: Int) -> Bool {
        state == "cancelled" && managerClosed && !activeWork && sshClosed && !pidPresent && !windowPresent && closedServices == 1 && handles == 0
    }
}
enum AppRealQuitDecision { case continueTransfer, cancelAndQuit }
struct AppRealQuitHookGate: Sendable {
    private(set) var beforeCalls = 0, afterCalls = 0
    private(set) var receiptWritten = false
    mutating func before(phase: AppRealIntegrationPhase) throws {
        guard phase == .quitContinueCancel, beforeCalls == 0, afterCalls == 0 else { throw AppRealTransferGuard.quitHookOrder }
        beforeCalls = 1
    }
    mutating func after() throws {
        guard beforeCalls == 1, afterCalls == 0 else { throw AppRealTransferGuard.quitHookOrder }
        afterCalls = 1
    }
    mutating func committedReceipt() throws {
        guard beforeCalls == 1, afterCalls == 1, !receiptWritten else { throw AppRealTransferGuard.quitHookOrder }
        receiptWritten = true
    }
    var mayReplyToNativeQuit: Bool { beforeCalls == 1 && afterCalls == 1 && receiptWritten }
}
struct AppRealQuitTransferGate {
    static func cancelledAndDrained(state: String, managerClosed: Bool, activeWork: Bool, sshClosed: Bool, pidPresent: Bool,
                                    closedServices: Int, handles: Int, attempts: Int) -> Bool {
        state == "cancelled" && managerClosed && !activeWork && sshClosed && !pidPresent && closedServices == 1 && handles == 0 && attempts == 1
    }
}
struct AppRealWindowCheckpoint: Encodable, Sendable {
    let runID: String, event: String
    let jobID: UUID, generation: UUID, serviceID: UUID, hostID: UUID
    let serverBinding: String, sourceBytes: UInt64, progressBytes: UInt64
    let remoteRootBase64: String, payloadBase64: String, temporaryBase64: String
    let connectionAttempts: Int
    let retainedTemporaryPathsBase64: [String]
    let phase: AppRealIntegrationPhase
    init(runID: String, event: String, jobID: UUID, generation: UUID, serviceID: UUID, hostID: UUID, serverBinding: String,
         sourceBytes: UInt64, progressBytes: UInt64, remoteRootBase64: String, payloadBase64: String, temporaryBase64: String,
         connectionAttempts: Int, retainedTemporaryPathsBase64: [String], phase: AppRealIntegrationPhase = .windowContinueCancel) {
        self.runID = runID; self.event = event; self.jobID = jobID; self.generation = generation; self.serviceID = serviceID; self.hostID = hostID
        self.serverBinding = serverBinding; self.sourceBytes = sourceBytes; self.progressBytes = progressBytes
        self.remoteRootBase64 = remoteRootBase64; self.payloadBase64 = payloadBase64; self.temporaryBase64 = temporaryBase64
        self.connectionAttempts = connectionAttempts; self.retainedTemporaryPathsBase64 = retainedTemporaryPathsBase64; self.phase = phase
    }
}
enum AppRealTransferStage: String, Codable, Sendable {
    case source, mkdir, enterOwnedRoot, probePrepare, probeExecute, transferContext, uploadControl, observeJob
    case pendingDecision, firstJobIdentity, temporaryLedger, preCloseAction, preHideAction, awaitSSHClose
    case windowFirstClose, windowContinue, windowSecondClose, windowCancelClose, windowAwaitClosed, windowFinalCancelled
    case quitFirstTerminate, quitContinueDecision, quitSecondTerminate, quitCancelDecision, quitAwaitDrain, quitBeforeStoresClose, quitAfterStoresClose, quitReceipt
    case awaitTransfer, finalSucceeded, sameServiceContext, remoteDigest, remoteCleanup, localCleanup, complete
}
enum AppRealTransferGuard: String, Codable, Error, Sendable {
    case mkdirContext, mkdirLedger, emptyOwnedRoot, probeScope, probeResult, serviceBinding, noPreviousJobs
    case singleJob, pendingRiskMismatch, firstJobIdentity, temporaryCount, preCloseInflight, preCloseIdentity
    case sessionConnected, closeControl, preHideInflight, preHideIdentity, hideControl, finalJobIdentity
    case windowFirstInflight, windowContinueIdentity, windowContinueAdmission, windowSecondInflight, windowCancelIdentity, windowFinalCancelled, windowNotClosed, windowResources
    case quitFirstInflight, quitContinueIdentity, quitContinueAdmission, quitSecondInflight, quitCancelIdentity, quitFinalCancelled, quitHookOrder, quitReceiptWrite, quitTimeout
    case unexpectedFinalDecision, finalSucceeded, sameConnection, sameServiceContext, remoteDigest, ownedCleanupLedger
}
enum AppRealDiagnosticJobState: String, Codable, Sendable {
    case absent, queued, running, waitingConflict, waitingRisk, succeeded, skipped, failed, cancelled, completedWithSkips, unknown
}
enum AppRealDiagnosticQuestion: String, Codable, Sendable { case none, remotePathRisk, overwriteRisk, fsyncRisk, deletionRisk, conflict }
enum AppRealDiagnosticSSHState: String, Codable, Sendable { case absent, preparing, awaitingTrust, authenticating, connectionPending, connected, disconnected, failed, closing, closed, unknown }
struct AppRealTransferSnapshot: Codable, Sendable {
    let stage: AppRealTransferStage
    let phase: AppRealIntegrationPhase
    let jobID: UUID?, generation: UUID?, sourceServiceID: UUID?, destinationServiceID: UUID?
    let sourcePathBase64: String?, destinationPathBase64: String?
    let state: AppRealDiagnosticJobState, transferredBytes: UInt64
    let pendingQuestion: AppRealDiagnosticQuestion, riskPathBase64: String?
    let ownedPathsBase64: [String], rejectedPaths: Int
    let sshState: AppRealDiagnosticSSHState, ownedSSHPIDPresent: Bool
    let serverBinding: UUID?, connectionAttempts: Int
    init(stage: AppRealTransferStage, scope: AppRealTransferScope, jobID: UUID?, generation: UUID?, sourceServiceID: UUID?, destinationServiceID: UUID?,
         sourcePath: Data?, destinationPath: Data?, state: String, transferredBytes: UInt64,
         pendingQuestion: AppRealDiagnosticQuestion, riskPath: Data?, ownedPaths: [Data], sshState: AppRealDiagnosticSSHState,
         ownedSSHPIDPresent: Bool, serverBinding: UUID?, connectionAttempts: Int, phase: AppRealIntegrationPhase = .transferSurvivesClose) {
        self.stage = stage; self.phase = phase; self.jobID = jobID; self.generation = generation
        self.sourceServiceID = sourceServiceID; self.destinationServiceID = destinationServiceID
        let localSource = Data(("/" + scope.payloadName).utf8)
        sourcePathBase64 = sourcePath == localSource ? sourcePath?.base64EncodedString() : nil
        destinationPathBase64 = destinationPath == Data(scope.remotePayload.utf8) ? destinationPath?.base64EncodedString() : nil
        self.state = AppRealDiagnosticJobState(rawValue: state) ?? .unknown; self.transferredBytes = transferredBytes
        self.pendingQuestion = pendingQuestion
        riskPathBase64 = riskPath.flatMap { scope.permitsDiagnosticPath($0) ? $0.base64EncodedString() : nil }
        let allowed = Array(Set(ownedPaths.filter { scope.permitsDiagnosticPath($0) })).sorted { $0.lexicographicallyPrecedes($1) }
        ownedPathsBase64 = allowed.prefix(8).map { $0.base64EncodedString() }
        rejectedPaths = ownedPaths.count - allowed.count + max(0, allowed.count - 8) + (sourcePath != nil && sourcePath != localSource ? 1 : 0)
            + (destinationPath != nil && destinationPath != Data(scope.remotePayload.utf8) ? 1 : 0)
            + (riskPath != nil && riskPathBase64 == nil ? 1 : 0)
        self.sshState = sshState; self.ownedSSHPIDPresent = ownedSSHPIDPresent; self.serverBinding = serverBinding
        self.connectionAttempts = connectionAttempts
    }
}
struct AppRealTransferDiagnostics: Encodable, Sendable {
    private(set) var stage: AppRealTransferStage = .source
    private(set) var failedGuard: AppRealTransferGuard?
    private(set) var snapshots: [AppRealTransferSnapshot] = []
    mutating func enter(_ stage: AppRealTransferStage) { self.stage = stage }
    mutating func failed(_ guardName: AppRealTransferGuard) { failedGuard = guardName }
    mutating func record(_ snapshot: AppRealTransferSnapshot) {
        if snapshots.count == 8 { snapshots.removeFirst() }
        snapshots.append(snapshot)
    }
}
extension AppRealTransferScope {
    func permitsDiagnosticPath(_ bytes: Data) -> Bool {
        if permitsRemote(bytes) { return true }
        let prefix = Data((remoteDirectory + "/.openlxssh-transfer.").utf8), suffix = Data(".part".utf8)
        guard bytes.starts(with: prefix), bytes.suffix(suffix.count) == suffix,
              let text = String(data: bytes.dropFirst(prefix.count).dropLast(suffix.count), encoding: .utf8),
              let id = UUID(uuidString: text), text == id.uuidString else { return false }
        return true
    }
}
struct AppRealIntegrationContract: Codable, Sendable {
    static let base = "docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d"
    static let image = "sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363"
    static let project = "openlxssh-fixture-61ed25328c13"
    static let container = "1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2"
    static let fingerprint = "SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q"
    static let fixtureRoot = "/Users/liuwenshuo/Desktop/OpenLXSSH/Tests/IntegrationEnvironment"
    static let inputRoot = "/Users/liuwenshuo/Desktop/OpenLXSSH/DerivedData/AppRealIntegration/Inputs"
    let schema: Int
    let phase: AppRealIntegrationPhase?
    var selectedPhase: AppRealIntegrationPhase { phase ?? .readOnly }
    let runID: String
    let host: String
    let port: Int
    let user: String
    let service: String
    let generation: String
    let expectedBase: String
    let expectedImage: String
    let expectedProject: String
    let expectedContainer: String
    let expectedFingerprint: String
    let collectedAt: Double
    let preparedAt: Double
    let provenanceSHA256: String
    let knownHostsSHA256: String
    let generationPublicKeySHA256: String

    static func pathSyntax(_ path: String) throws {
        guard path.hasPrefix("/"), path != "/", !path.hasSuffix("/"), path.utf8.count < 4096,
              !path.contains("$"), !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw AppRealIntegrationFailure.arguments }
    }
    static func hex(_ text: String, count: Int) -> Bool { text.utf8.count == count && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    static func validateContractPath(_ path: String) throws -> String {
        try pathSyntax(path)
        let prefix = inputRoot + "/run-", suffix = "/app-real-integration.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix),
              let id = UUID(uuidString: String(path.dropFirst(prefix.count).dropLast(suffix.count))),
              path == prefix + id.uuidString.lowercased() + suffix else { throw AppRealIntegrationFailure.contract }
        return id.uuidString.lowercased()
    }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let keys: Set<String> = ["schema", "runID", "host", "port", "user", "service", "generation", "expectedBase", "expectedImage",
            "expectedProject", "expectedContainer", "expectedFingerprint", "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"]
        guard bytes.count <= 8192, let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(object.keys) == keys || Set(object.keys) == keys.union(["phase"]), object["phase"] == nil || object["phase"] is String else { throw AppRealIntegrationFailure.contract }
        return try JSONDecoder().decode(Self.self, from: bytes)
    }
    func validate(path: String, now: Double, buildEpoch: Double) throws {
        guard try Self.validateContractPath(path) == runID, schema == 1, host == "127.0.0.1", port == 22221, user == "fixture", service == "keyonly",
              expectedBase == Self.base, expectedImage == Self.image, expectedProject == Self.project, expectedContainer == Self.container,
              expectedFingerprint == Self.fingerprint, [provenanceSHA256, knownHostsSHA256, generationPublicKeySHA256].allSatisfy({ Self.hex($0, count: 64) }),
              collectedAt.isFinite, preparedAt.isFinite, now.isFinite, buildEpoch.isFinite, buildEpoch > 0,
              collectedAt >= buildEpoch, preparedAt >= collectedAt, preparedAt - collectedAt <= 900, now >= preparedAt, now - preparedAt <= 1800 else { throw AppRealIntegrationFailure.contract }
        try Self.pathSyntax(generation)
        let prefix = Self.fixtureRoot + "/.runtime/keyonly/credentials-"
        guard generation.hasPrefix(prefix), Self.hex(String(generation.dropFirst(prefix.count)), count: 12) else { throw AppRealIntegrationFailure.contract }
    }
    func matchesTrust(host: String, port: Int, algorithm: String, fingerprint: String) -> Bool {
        host == self.host && port == self.port && algorithm == "ssh-ed25519" && fingerprint == expectedFingerprint
    }
}

#if HOST_PROBE
import CryptoKit
import Darwin

/// Uses the existing App no-ACL policy. Traverses upstream paths by FD/O_NOFOLLOW;
/// never resolves aliases into an otherwise forbidden path or opens .ssh/Keychain.
enum AppRealPrivateInput {
    static func directory(_ path: String) throws -> Int32 { try opened(path, directory: true) }
    private static func opened(_ path: String, directory: Bool) throws -> Int32 {
        try AppRealIntegrationContract.pathSyntax(path)
        let parts = path.dropFirst().split(separator: "/").map(String.init)
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw AppRealIntegrationFailure.unsafeInput }
        do {
            for (index, part) in parts.enumerated() {
                let last = index == parts.count - 1
                if last && !directory { try AppFileSecurity.directory(fd) }
                let next = openat(fd, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | ((!last || directory) ? O_DIRECTORY : 0))
                guard next >= 0 else { throw AppRealIntegrationFailure.unsafeInput }
                Darwin.close(fd); fd = next
            }
            if directory { try AppFileSecurity.directory(fd) } else { try AppFileSecurity.regularFile(fd) }
            return fd
        } catch { Darwin.close(fd); throw AppRealIntegrationFailure.unsafeInput }
    }
    static func read(_ path: String, limit: Int) throws -> Data {
        guard (1...1_048_576).contains(limit) else { throw AppRealIntegrationFailure.unsafeInput }
        let fd = try opened(path, directory: false); defer { Darwin.close(fd) }
        var before = stat(); guard fstat(fd, &before) == 0, before.st_size >= 0, before.st_size <= limit else { throw AppRealIntegrationFailure.unsafeInput }
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: min(limit + 1, 65536))
        while true {
            let count = Darwin.read(fd, &buffer, min(buffer.count, limit + 1 - bytes.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw AppRealIntegrationFailure.unsafeInput }
            if count == 0 { break }; bytes.append(contentsOf: buffer.prefix(count))
            guard bytes.count <= limit else { throw AppRealIntegrationFailure.unsafeInput }
        }
        var after = stat(); try AppFileSecurity.regularFile(fd)
        guard fstat(fd, &after) == 0, bytes.count == before.st_size, before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec, before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw AppRealIntegrationFailure.unsafeInput }
        return bytes
    }
    static func write(_ bytes: Data, parent: Int32, name: String) throws {
        guard !name.isEmpty, !name.contains("/"), name != ".", name != ".." else { throw AppRealIntegrationFailure.unsafeInput }
        let fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw AppRealIntegrationFailure.unsafeInput }; defer { Darwin.close(fd) }
        try AppFileSecurity.regularFile(fd)
        var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if n < 0 && errno == EINTR { continue }; guard n > 0 else { throw AppRealIntegrationFailure.unsafeInput }; offset += n
        }
        guard fsync(fd) == 0 else { throw AppRealIntegrationFailure.unsafeInput }; try AppFileSecurity.regularFile(fd)
    }
    /// Only the two closed file-operations fixture leaves are accepted. Parent is an already
    /// held, validated dataset directory FD; '$' is a literal POSIX byte, never shell/config text.
    static func readKnownFileOperationLeaf(parent: Int32, name: String, scope: AppRealFileScope) throws -> (bytes: Data, device: dev_t, inode: ino_t) {
        let expectedSize: Int
        if Data(name.utf8) == Data(scope.neighbor.utf8) { expectedSize = 4096 }
        else if Data(name.utf8) == Data(scope.child.utf8) { expectedSize = 8192 }
        else { throw AppRealIntegrationFailure.arguments }
        try AppFileSecurity.directory(parent)
        let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw AppRealIntegrationFailure.unsafeInput }; defer { Darwin.close(fd) }
        try AppFileSecurity.regularFile(fd)
        var before = stat()
        guard fstat(fd, &before) == 0, before.st_size == expectedSize, before.st_size <= 16384 else { throw AppRealIntegrationFailure.unsafeInput }
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(fd, &buffer, min(buffer.count, 16385 - bytes.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw AppRealIntegrationFailure.unsafeInput }
            if count == 0 { break }; bytes.append(contentsOf: buffer.prefix(count))
            guard bytes.count <= 16384 else { throw AppRealIntegrationFailure.unsafeInput }
        }
        var after = stat(), named = stat()
        try AppFileSecurity.regularFile(fd); try AppFileSecurity.directory(parent)
        guard fstat(fd, &after) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw AppRealIntegrationFailure.unsafeInput }
        func unchanged(_ value: stat) -> Bool {
            value.st_dev == before.st_dev && value.st_ino == before.st_ino && value.st_uid == before.st_uid && value.st_gid == before.st_gid &&
            value.st_mode == before.st_mode && value.st_nlink == before.st_nlink && value.st_size == before.st_size &&
            value.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec && value.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec &&
            value.st_ctimespec.tv_sec == before.st_ctimespec.tv_sec && value.st_ctimespec.tv_nsec == before.st_ctimespec.tv_nsec
        }
        guard unchanged(after), unchanged(named), bytes.count == expectedSize else { throw AppRealIntegrationFailure.unsafeInput }
        return (bytes, after.st_dev, after.st_ino)
    }
    static func sha(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}
struct AppRealPublicMaterial: Sendable {
    let contract: AppRealIntegrationContract
    let hostKeyLine: String
    static func load(_ path: String, buildEpoch: Double) throws -> Self {
        _ = try AppRealIntegrationContract.validateContractPath(path) // Reject arbitrary file BEFORE open.
        let bytes = try AppRealPrivateInput.read(path, limit: 8192), value = try AppRealIntegrationContract.decodeStrict(bytes)
        try value.validate(path: path, now: Date().timeIntervalSince1970, buildEpoch: buildEpoch)
        for p in [AppRealIntegrationContract.inputRoot, String(path.dropLast("/app-real-integration.json".count)),
            AppRealIntegrationContract.fixtureRoot + "/.runtime", AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly", value.generation] {
            let fd = try AppRealPrivateInput.directory(p); Darwin.close(fd)
        }
        let stateBytes = try AppRealPrivateInput.read(AppRealIntegrationContract.fixtureRoot + "/.runtime/state.json", limit: 4096)
        guard let state = try JSONSerialization.jsonObject(with: stateBytes) as? [String: Any], Set(state.keys) == ["version", "project", "image"],
              state["version"] as? Int == 1, state["project"] as? String == value.expectedProject, state["image"] as? String == value.expectedBase else { throw AppRealIntegrationFailure.provenance }
        let provenance = try AppRealPrivateInput.read(value.generation + "/provenance.json", limit: 4096)
        guard AppRealPrivateInput.sha(provenance) == value.provenanceSHA256,
              let object = try JSONSerialization.jsonObject(with: provenance) as? [String: Any], Set(object.keys) == ["base_image", "built_image_id", "service", "collected_at"],
              object["base_image"] as? String == value.expectedBase, object["built_image_id"] as? String == value.expectedImage,
              object["service"] as? String == "keyonly", object["collected_at"] as? Double == value.collectedAt else { throw AppRealIntegrationFailure.provenance }
        let known = try AppRealPrivateInput.read(value.generation + "/known_hosts", limit: 4096)
        guard AppRealPrivateInput.sha(known) == value.knownHostsSHA256, let text = String(data: known, encoding: .utf8), text.hasSuffix("\n"), !text.dropLast().contains("\n") else { throw AppRealIntegrationFailure.fingerprint }
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == "[127.0.0.1]:22221", fields[1] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51,
              "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast() == value.expectedFingerprint else { throw AppRealIntegrationFailure.fingerprint }
        let publicKey = try AppRealPrivateInput.read(value.generation + "/id_ed25519.pub", limit: 4096)
        guard AppRealPrivateInput.sha(publicKey) == value.generationPublicKeySHA256 else { throw AppRealIntegrationFailure.provenance }
        return Self(contract: value, hostKeyLine: "ssh-ed25519 " + fields[2])
    }
}
#endif
