import Darwin
import Foundation
import StabilityPOSIX

public struct ProcessIdentity: Codable, Hashable, Sendable {
    public let pid: Int32, parentPID: Int32
    public let uid: UInt32
    public let startSeconds: UInt64, startMicroseconds: UInt64
    public init(pid: Int32, parentPID: Int32, uid: UInt32, startSeconds: UInt64, startMicroseconds: UInt64) {
        self.pid = pid; self.parentPID = parentPID; self.uid = uid
        self.startSeconds = startSeconds; self.startMicroseconds = startMicroseconds
    }
    public func sameLifetime(as other: ProcessIdentity) -> Bool {
        pid == other.pid && uid == other.uid && startSeconds == other.startSeconds && startMicroseconds == other.startMicroseconds
    }
    fileprivate init(_ value: stability_process) {
        self.init(pid: value.pid, parentPID: value.ppid, uid: value.uid,
                  startSeconds: value.start_seconds, startMicroseconds: value.start_microseconds)
    }
}
public enum ProcessRole: String, Codable, Sendable { case driver, ssh, helper }
public struct ProcessSample: Codable, Sendable {
    public let role: ProcessRole
    public let identity: ProcessIdentity
    public let rssBytes: UInt64
    public let fdDescriptors: Int32
    public let ptyVnodeDescriptors: Int32
    public let kernelThreads: Int32
    public let complete: Bool
    /// Present only when a closed-FD race caused one verified fresh-list sample.
    /// Optional so existing schema-1 rows remain decodable without inventing data.
    public let fdListResamples: Int32?
    fileprivate init(role: ProcessRole, value: stability_process) {
        self.role = role; identity = ProcessIdentity(value); rssBytes = value.rss_bytes
        fdDescriptors = value.fd_count; ptyVnodeDescriptors = value.pty_fd_count
        kernelThreads = value.thread_count; complete = value.metrics_complete == 1
        fdListResamples = value.fd_list_resamples > 0 ? value.fd_list_resamples : nil
    }
}

public struct OwnedProcessScope: Sendable {
    public let owner: ProcessIdentity
    public private(set) var ssh = Set<ProcessIdentity>()
    public private(set) var helpers = Set<ProcessIdentity>()
    public init(owner: ProcessIdentity) { self.owner = owner }
    public mutating func registerSSH(_ identity: ProcessIdentity, sessionOwnedPID: Int32?) throws {
        guard let sessionOwnedPID, sessionOwnedPID > 0, identity.pid == sessionOwnedPID,
              identity.pid != owner.pid, identity.parentPID == owner.pid, identity.uid == owner.uid else {
            throw StabilityError.resourceUnavailable
        }
        ssh.insert(identity)
    }
    public mutating func registerHelper(_ identity: ProcessIdentity, parent: ProcessIdentity) throws {
        guard ssh.contains(parent), identity.parentPID == parent.pid, identity.uid == owner.uid,
              identity.pid > 0, identity.pid != parent.pid, identity.pid != owner.pid else { throw StabilityError.resourceUnavailable }
        helpers.insert(identity)
    }
    public func contains(_ identity: ProcessIdentity) -> Bool {
        // Reparenting after ssh exits does not make an observed helper unowned.
        // PID + uid + kernel start time remain the lifetime identity.
        identity.sameLifetime(as: owner) || ssh.contains(where: { $0.sameLifetime(as: identity) }) || helpers.contains(where: { $0.sameLifetime(as: identity) })
    }
}

public enum ObservedProcessState: Equatable, Sendable {
    case alive
    case confirmedGoneOrRecycled
    case unknown
}

public final class ResourceSampler {
    public private(set) var scope: OwnedProcessScope
    public private(set) var confirmedGoneHelpers = 0
    private let exactHelper: String
    private let cleanupRead: (Int32, inout stability_process) -> Int32
    public init(exactHelper: String) throws {
        var own = stability_process()
        guard stability_process_read(getpid(), &own) == 0 else { throw StabilityError.resourceUnavailable }
        scope = OwnedProcessScope(owner: ProcessIdentity(own)); self.exactHelper = exactHelper
        cleanupRead = { stability_identity_read($0, &$1) }
    }
    // Offline query-injection seam: no real PID is queried by cleanup tests.
    init(scope: OwnedProcessScope, cleanupRead: @escaping (Int32, inout stability_process) -> Int32) {
        self.scope = scope; exactHelper = ""; self.cleanupRead = cleanupRead
    }
    public func sample(sessionOwnedPIDs: [Int32]) throws -> [ProcessSample] {
        confirmedGoneHelpers = 0
        var values: [ProcessSample] = []
        var own = stability_process()
        guard stability_process_read(scope.owner.pid, &own) == 0, ProcessIdentity(own) == scope.owner else {
            throw StabilityError.resourceUnavailable
        }
        values.append(ProcessSample(role: .driver, value: own))
        for pid in Set(sessionOwnedPIDs) {
            var ssh = stability_process()
            guard stability_process_read(pid, &ssh) == 0 else { throw StabilityError.resourceUnavailable }
            try scope.registerSSH(ProcessIdentity(ssh), sessionOwnedPID: pid)
            values.append(ProcessSample(role: .ssh, value: ssh))
            var children = [stability_process](repeating: stability_process(), count: 16)
            var gone: Int32 = 0
            let count = children.withUnsafeMutableBufferPointer { stability_direct_helpers(pid, exactHelper, $0.baseAddress, Int32($0.count), &gone) }
            guard count >= 0 else { throw StabilityError.resourceUnavailable }
            confirmedGoneHelpers += Int(gone)
            var parentAfter = stability_process()
            guard stability_process_read(pid, &parentAfter) == 0, ProcessIdentity(parentAfter) == ProcessIdentity(ssh) else {
                throw StabilityError.resourceUnavailable
            }
            for child in children.prefix(Int(count)) {
                try scope.registerHelper(ProcessIdentity(child), parent: ProcessIdentity(ssh))
                values.append(ProcessSample(role: .helper, value: child))
            }
        }
        return values
    }
    /// Checks only identities actually observed as owned. A recycled PID is not
    /// this driver's child. Never sends signals; Transport is the sole owner/reaper.
    public func observedChildrenStillAlive() throws -> [ProcessIdentity] {
        var alive: [ProcessIdentity] = []
        for expected in scope.ssh.union(scope.helpers).sorted(by: { $0.pid < $1.pid }) {
            switch observedState(of: expected) {
            case .alive: alive.append(expected)
            case .confirmedGoneOrRecycled: continue
            case .unknown: throw StabilityError.resourceUnavailable
            }
        }
        return alive
    }
    private func observedState(of expected: ProcessIdentity) -> ObservedProcessState {
        var live = stability_process()
        let result = cleanupRead(expected.pid, &live)
        if result == STABILITY_IDENTITY_GONE { return .confirmedGoneOrRecycled }
        guard result == STABILITY_IDENTITY_PRESENT, live.pid == expected.pid,
              live.start_seconds > 0, live.start_microseconds < 1_000_000 else { return .unknown }
        // A UID change alone does not prove PID recycling. Compare the kernel
        // birth first, independent of owner UID or reparenting.
        if live.start_seconds != expected.startSeconds || live.start_microseconds != expected.startMicroseconds {
            return .confirmedGoneOrRecycled
        }
        guard live.uid == expected.uid else { return .unknown }
        return .alive // Incomplete RSS/FD metrics cannot hide a known lifetime.
    }
}

public struct EvidenceMetadata: Encodable, Sendable {
    public let schema = 1
    public let taskID = "P7-STABILITY-DRIVER-PREP-A"
    public let mode: RunMode
    public let endpoint: String
    public let requiredAuthenticatedCycles: Int
    public let requiredSessions: Int
    public let requiredDurationSeconds: Int
    public let sampleSeconds: Int
    public let historyRows: Int
    public let terminalColumns: Int
    public let terminalRows: Int
    public let hostFingerprint: String
    public let officialBaseImage: String
    public let fixtureImageID: String
    public let fixtureCollectedUnix: Double
    public let osVersion: String
    public let physicalMemoryBytes: UInt64
    public let architecture = "arm64"
    public let signedAppPath: String
    public let sourceRevision: String
    public let load = "idle ordinary remote login shells; no remote commands/input injection"
    public let scope = "Transport fixture, NOT product UI/AC-30/whole-App PERF or Instruments acceptance"
    public let metrics = "wall=Date UNIX; monotonic=CLOCK_UPTIME_RAW awake; continuous=mach_continuous_time includes sleep; point RSS sum, double-counts shared pages; known session-owned ssh + exact direct helper only; FD/PTY are descriptor counts, not unique devices; threads are kernel threads, NOT Swift task counts; helper point samples may miss short-lived helpers"
    public init(options: Options, fixture: FixturePublic, signedAppPath: String, sourceRevision: String) {
        mode = options.mode; endpoint = "127.0.0.1:22221"
        requiredAuthenticatedCycles = options.cycles; requiredSessions = options.sessions
        requiredDurationSeconds = options.durationSeconds; sampleSeconds = options.sampleSeconds
        historyRows = 10_000; terminalColumns = 80; terminalRows = 24
        hostFingerprint = fixture.hostFingerprint; officialBaseImage = fixture.baseImage
        fixtureImageID = fixture.builtImageID; fixtureCollectedUnix = fixture.collectedAt
        osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        physicalMemoryBytes = ProcessInfo.processInfo.physicalMemory
        self.signedAppPath = signedAppPath; self.sourceRevision = sourceRevision
    }
}
public enum EvidenceEvent: String, Codable, Sendable { case start, connected, sample, cycleClosed, cleanup, end }
public enum EvidenceStatus: String, Codable, Sendable { case running, completedDriverScope, incomplete, failed }
public struct EvidenceRow: Encodable, Sendable {
    public let event: EvidenceEvent
    public let clock: ClockReading
    public let status: EvidenceStatus
    public let metadata: EvidenceMetadata?
    public let totals: CycleTotals?
    public let resources: [ProcessSample]?
    public let failure: StabilityError?
    public let timing: TimingEvidence?
    public let confirmedGoneHelpers: Int?
    public init(event: EvidenceEvent, clock: ClockReading = .now(), status: EvidenceStatus = .running,
                metadata: EvidenceMetadata? = nil, totals: CycleTotals? = nil,
                resources: [ProcessSample]? = nil, failure: StabilityError? = nil, timing: TimingEvidence? = nil,
                confirmedGoneHelpers: Int? = nil) {
        self.event = event; self.clock = clock; self.status = status; self.metadata = metadata
        self.totals = totals; self.resources = resources; self.failure = failure; self.timing = timing
        self.confirmedGoneHelpers = confirmedGoneHelpers
    }
    public func encode(to encoder: Encoder) throws {
        var box = encoder.container(keyedBy: CodingKeys.self)
        try box.encode(event, forKey: .event); try box.encode(clock, forKey: .clock); try box.encode(status, forKey: .status)
        try box.encodeIfPresent(metadata, forKey: .metadata); try box.encodeIfPresent(totals, forKey: .totals)
        try box.encodeIfPresent(resources, forKey: .resources); try box.encodeIfPresent(failure?.rawValue, forKey: .failure)
        try box.encodeIfPresent(timing, forKey: .timing)
        try box.encodeIfPresent(confirmedGoneHelpers, forKey: .confirmedGoneHelpers)
    }
    private enum CodingKeys: String, CodingKey { case event, clock, status, metadata, totals, resources, failure, timing, confirmedGoneHelpers }
}

public final class BoundedEvidence {
    public static let maximumRows = 25_000
    public static let maximumBytes = 128 * 1024 * 1024
    public let path: String
    private let fd: Int32
    private var rows = 0, bytes = 0
    public init(exclusivePath: String) throws {
        try PrivateMaterial.validateSyntax(exclusivePath)
        let descriptor = stability_create_private_file(exclusivePath)
        guard descriptor >= 0 else { throw StabilityError.unsafePermissions }
        fd = descriptor; path = exclusivePath
    }
    public func append(_ row: EvidenceRow) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(row); data.append(10)
        guard data.count <= 16_384, rows < Self.maximumRows, bytes + data.count <= Self.maximumBytes else { throw StabilityError.evidenceLimit }
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw StabilityError.resourceUnavailable }; offset += count
            }
        }
        guard fsync(fd) == 0 else { throw StabilityError.resourceUnavailable }
        rows += 1; bytes += data.count
    }
    deinit { Darwin.close(fd) }
}
