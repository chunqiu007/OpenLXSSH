import CryptoKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore
import RealIntegrationPOSIX
import RemoteFileMetrics
import StressMetrics

func rp(_ text: String) throws -> RemotePath { try RemotePath(text) }
func join(_ root: RemotePath, _ relative: String) throws -> RemotePath { try RemotePath(bytes: root.bytes + (root == .root ? Data() : Data([47])) + raw(relative)) }
func freeBytes(_ path: String) throws -> UInt64 {
    var fs = statfs(); try require(statfs(path, &fs) == 0)
    return UInt64(fs.f_bavail) * UInt64(fs.f_bsize)
}
func inspect(_ service: any RemoteFileService, _ path: RemotePath, leaf: Bool = true) async throws {
    var current = RemotePath.root
    let components = (leaf ? path.bytes : path.parent.bytes).dropFirst().split(separator: 47)
    for (index, component) in components.enumerated() {
        current = try current.appending(FileName(bytes: Data(component)))
        let a = try await service.lstat(current, token: CancellationToken())
        try require(a.kind != .symbolicLink && a.kind != .unknown && a.kind != .other)
        if !leaf || index < components.count - 1 { try require(a.kind == .directory) }
    }
}
func readSmall(_ service: any RemoteFileService, _ path: RemotePath, limit: Int) async throws -> Data {
    try await inspect(service, path)
    let h = try await service.open(path, mode: .read, token: CancellationToken())
    do {
        var bytes = Data()
        while true {
            let part = try await service.read(h, maxBytes: min(Fixed.chunk, limit + 1 - bytes.count), token: CancellationToken())
            if part.isEmpty { break }
            bytes += part; try require(bytes.count <= limit)
        }
        try await service.closeHandle(h); return bytes
    } catch { try? await service.closeHandle(h); throw error }
}
func digest(_ service: any RemoteFileService, _ path: RemotePath, relative: String, expected: UInt64) async throws -> Payload {
    try await inspect(service, path)
    let before = try await service.lstat(path, token: CancellationToken())
    try require(before.kind == .regular && before.size == expected)
    let h = try await service.open(path, mode: .read, token: CancellationToken())
    do {
        let opened = try await service.fstat(h, token: CancellationToken())
        try require(opened?.kind == .regular && opened?.size == expected)
        var hash = SHA256(), total: UInt64 = 0
        while true {
            let part = try await service.read(h, maxBytes: Fixed.chunk, token: CancellationToken())
            if part.isEmpty { break }
            try require(total <= expected && UInt64(part.count) <= expected - total)
            total += UInt64(part.count); hash.update(data: part)
        }
        try require(total == expected)
        let after = try await service.lstat(path, token: CancellationToken())
        let finalHandle = try await service.fstat(h, token: CancellationToken())
        try require(after == before && finalHandle == opened)
        try await service.closeHandle(h)
        return Payload(path: relative, bytes: total, sha256: hex(hash.finalize()))
    } catch { try? await service.closeHandle(h); throw error }
}
func put(_ service: any RemoteFileService, _ path: RemotePath, bytes: Data) async throws {
    try await inspect(service, path, leaf: false)
    let h = try await service.open(path, mode: .exclusiveWrite, token: CancellationToken())
    do {
        var offset = 0
        while offset < bytes.count {
            let n = try await service.write(h, data: Data(bytes.dropFirst(offset)), token: CancellationToken())
            try require(n > 0 && n <= bytes.count - offset); offset += n
        }
        try await service.finish(h, token: CancellationToken()); try await service.closeHandle(h)
    } catch { try? await service.closeHandle(h); throw error }
}

final class OwnedLocal {
    let path: String
    private var parent: Int32, descriptor: Int32
    private let device: UInt64, inode: UInt64
    init(parentPath: String) throws {
        parent = ri_open_private(parentPath, 1); descriptor = -1
        guard parent >= 0 else { throw GateError.cleanup }
        path = parentPath + "/data"
        guard mkdirat(parent, "data", 0o700) == 0 else { Darwin.close(parent); throw GateError.cleanup }
        descriptor = ri_open_private(path, 1)
        var dev: UInt64 = 0, ino: UInt64 = 0
        guard descriptor >= 0, remote_file_identity(descriptor, &dev, &ino) == 0 else {
            if descriptor >= 0 { Darwin.close(descriptor) }; Darwin.close(parent); throw GateError.cleanup
        }
        device = dev; inode = ino
    }
    deinit { if descriptor >= 0 { Darwin.close(descriptor) }; if parent >= 0 { Darwin.close(parent) } }
    private(set) var directoryRemoved = false
    var identity: (UInt64, UInt64) { (device, inode) }
    func service() throws -> LocalFileService { try LocalFileService(rootDirectoryDescriptor: descriptor) }
    func allocatedLarge() throws -> UInt64 {
        let fd = ri_open_private(path + "/download/large-2GiB.bin", 0)
        guard fd >= 0 else { throw GateError.integrity }; defer { Darwin.close(fd) }
        var bytes: UInt64 = 0; try require(remote_file_allocated(fd, &bytes) == 0 && bytes >= Fixed.largeBytes)
        return bytes
    }
    func close(removeEmpty: Bool) throws {
        if removeEmpty {
            var now = stat(); try require(fstatat(parent, "data", &now, AT_SYMLINK_NOFOLLOW) == 0 &&
                UInt64(now.st_dev) == device && UInt64(now.st_ino) == inode && now.st_uid == getuid() &&
                now.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR), .cleanup)
            try require(unlinkat(parent, "data", AT_REMOVEDIR) == 0, .cleanup)
            directoryRemoved = true
        }
        if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 }
        if parent >= 0 { Darwin.close(parent); parent = -1 }
    }
}
struct ItemEvidence: Codable {
    let sourceBase64: String, destinationBase64: String, state: String
    let bytes: UInt64?
    let errorKind: String?, operation: String?, code: Int64?
    let retainedTemporaryBase64: String?
    let acknowledgedRisks: [String]
    init(_ item: TransferItemResult) {
        sourceBase64 = item.source.bytes.base64EncodedString(); destinationBase64 = item.destination.bytes.base64EncodedString()
        switch item.state {
        case .succeeded(let count): state = "succeeded"; bytes = count; errorKind = nil; operation = nil; code = nil
        case .skipped: state = "skipped"; bytes = nil; errorKind = nil; operation = nil; code = nil
        case .failed(let error): state = "failed"; bytes = nil; errorKind = error.kind.rawValue; operation = error.operation; code = error.code
        }
        retainedTemporaryBase64 = item.retainedTemporary?.bytes.base64EncodedString()
        acknowledgedRisks = item.acknowledgedRisks.map(riskName)
    }
}
func riskName(_ risk: TransferRisk) -> String {
    switch risk {
    case .remotePathChecksAreNotAtomic: "remotePathChecksAreNotAtomic"
    case .overwriteIsAtomicButNotCompareAndSwap: "overwriteIsAtomicButNotCompareAndSwap"
    case .remoteFsyncUnavailable: "remoteFsyncUnavailable"
    case .deletionChecksAreNotCompareAndSwap: "deletionChecksAreNotCompareAndSwap"
    }
}
struct Phase: Codable {
    let name: String, durationSeconds: Double, transferredBytes: UInt64, bytesPerSecond: Double, outcome: String
    let items: [ItemEvidence]
    let detail: [String: String]
}
struct ManifestEvidence: Codable { let label: String; let files: [Payload]; let rawNamesBase64: [String] }
struct Evidence: Encodable {
    let schema = 1, taskID = Fixed.task
    let testOnlyHostMinimum = "15.0", productAcceptance = false
    let measurement = "Self task_info RSS/getrusage high-water, proc_pidinfo FD/vnode and exact self TCP peer 127.0.0.1:22221, public successful handle calls. No SSH parent/relay/Docker VM memory attribution. Production Trust uses bounded short-lived system ssh-keygen public-key parser children, not SSH transport; their memory is NOT measured and 250ms may miss their lifetime. Directory handles are internal and not counted by public ledger. 250ms samples bounded to 20000. SFTP weak source metadata triggers production full streaming SHA recheck; throughput includes that overhead."
    let boundary = "Finite real production libssh2/TransferManager/SafeTransferEngine campaign over approved opaque relay. Not shipping macOS26 App, GUI, whole product PERF, network faults, disk-full, 24h or Instruments acceptance."
    let sourceGeneration: String, remoteRoot: String, localRoot: String
    let expectedBase = Fixed.base, expectedImage = Fixed.image, expectedProject = Fixed.project, expectedContainer = Fixed.container, fingerprint = Fixed.fingerprint
    let managementBoundary = "This consumer never queries Docker. Current CID/project/image/no-egress and allocated/free named-volume bytes MUST be independently verified by the primary's reviewed finite relay/wrapper campaign evidence. These expected IDs are not a claim of fresh management inspection."
    let largeBytes = Fixed.largeBytes, smallFiles = 1000, chunkBytes = Fixed.chunk, maxConcurrentChunks = 2, maxConcurrentJobs = 1
    let environment = ["operatingSystem": ProcessInfo.processInfo.operatingSystemVersionString,
        "physicalMemoryBytes": String(ProcessInfo.processInfo.physicalMemory), "architecture": NativeDiagnostics.architecture,
        "libssh2": NativeDiagnostics.libssh2, "openssl": NativeDiagnostics.openssl,
        "buildEvidence": BuildLocation.buildEvidence, "serverPackagesSHA256": "see campaign.json packagesSHA256"]
    let startedAt: Double
    var endedAt: Double = 0, status = "running", failure: String?
    var freeDiskBefore: UInt64 = 0, freeDiskAfter: UInt64 = 0, downloadedLargeAllocatedBytes: UInt64 = 0
    var corpusManifestSHA256: String?, localDirectoryDevice: UInt64?, localDirectoryInode: UInt64?
    var phases: [Phase] = [], manifests: [ManifestEvidence] = [], resources: [Resource] = []
    var capability: [String: String] = [:], retainedRemote: [OwnedPath] = [], retainedLocal: [OwnedPath] = []
    var observedTemporaryPathsBase64: [String] = []
    var serviceLeaseDrained = false, remoteCloseAwaited = false, localCloseAwaited = false
    var remoteCleanup = "not attempted", localCleanup = "not attempted"
    let limitations = ["Remote lstat is not atomic/no-follow and SFTP v3 does not expose inode or hardlink count; only owned UUID writes and exact immutable fixture input names, no arbitrary remote tree cleanup.",
        "Final overwrite checks are not CAS; acceptance applies only to explicitly owned sentinel targets.",
        "Source mutation after final checks cannot be excluded; no snapshot guarantee.",
        "Unsupported rename/fsync is recorded ONLY if this actual server returns it; no modified server or mock capability token.",
        "No network disconnect/packet loss/disk-full injection or App lifecycle/GUI evidence in this campaign."]
}

@MainActor final class CampaignRun {
    let directory: String, local: OwnedLocal, monitor: Monitor, ledger = Ledger()
    let scheduler = TransferScheduler(maxConcurrentChunks: 2)
    let remoteRoot: RemotePath
    let input: PublicMaterial, contract: Campaign, fixtureRoot: String
    var manager: TransferManager!
    var remote: ObservedService?, localService: ObservedService?
    var remoteID: TransferServiceID?, localID: TransferServiceID?
    var evidence: Evidence
    var stopRequested = false
    private var signalSources: [DispatchSourceSignal] = []
    private var connectingToken: CancellationToken?
    func requestStop() { stopRequested = true; connectingToken?.cancel(); remote?.cancel() }
    init(contract: Campaign, path: String, input: PublicMaterial, fixtureRoot: String) throws {
        self.contract = contract; self.input = input; self.fixtureRoot = fixtureRoot
        directory = String(path.dropLast("/campaign.json".count))
        try PrivateInput.writeExclusive(raw("single finite campaign claim\n"), to: directory + "/run.claim")
        local = try OwnedLocal(parentPath: directory)
        remoteRoot = try rp("/fixture/home/openlxssh-file-" + contract.id)
        monitor = Monitor(root: local.path, ledger: ledger)
        evidence = Evidence(sourceGeneration: contract.generation, remoteRoot: String(decoding: remoteRoot.bytes, as: UTF8.self),
            localRoot: local.path, startedAt: Date().timeIntervalSince1970)
        evidence.localDirectoryDevice = local.identity.0; evidence.localDirectoryInode = local.identity.1
        manager = TransferManager(engine: SafeTransferEngine(scheduler: scheduler, chunkSize: Fixed.chunk), maxConcurrentJobs: 1, idleTimeout: nil)
    }
    var engine: SafeTransferEngine { SafeTransferEngine(scheduler: scheduler, chunkSize: Fixed.chunk) }
    func request(_ source: TransferServiceID, _ sourcePath: RemotePath, _ destination: TransferServiceID, _ destinationPath: RemotePath, tree: Bool = false) -> TransferRequest {
        TransferRequest(hostID: "fixture-keyonly", source: TransferLocation(serviceID: source, path: sourcePath),
            destination: TransferLocation(serviceID: destination, path: destinationPath), kind: tree ? .tree : .file)
    }
    func allowed(_ risk: TransferRisk, overwrite: RemotePath? = nil) -> Bool {
        let allowedPath: (RemotePath) -> Bool = { path in
            path == self.remoteRoot || path.bytes.starts(with: self.remoteRoot.bytes + Data([47])) ||
            path.bytes == raw(Fixed.corpus) || path.bytes.starts(with: raw(Fixed.corpus + "/")) ||
            path.bytes == raw("/fixture/protected/denied.txt") || path.bytes == raw("/fixture/protected/denied-directory")
        }
        switch risk {
        case .remotePathChecksAreNotAtomic(let p): return allowedPath(p)
        case .overwriteIsAtomicButNotCompareAndSwap(let p): return p == overwrite
        // Do not auto-ack fsync unavailable. Exact actual failure remains visible for review.
        case .remoteFsyncUnavailable, .deletionChecksAreNotCompareAndSwap: return false
        }
    }
    func transfer(_ label: String, _ req: TransferRequest, confirmation: ServerCommitConfirmation? = nil,
                  expected: TransferJobState = .succeeded, bytes: UInt64? = nil) async throws -> TransferJobSnapshot {
        try require(!stopRequested, .stopped); await monitor.sample(label)
        let start = DispatchTime.now().uptimeNanoseconds
        let id = try await manager.enqueue(req, serverConfirmation: confirmation)
        while true {
            let snap = await manager.snapshot()
            guard let job = snap.jobs.first(where: { $0.id == id }) else { throw GateError.integrity }
            if !job.state.isActive {
                let duration = elapsed(start)
                evidence.phases.append(Phase(name: label, durationSeconds: duration, transferredBytes: job.transferredBytes,
                    bytesPerSecond: Double(job.transferredBytes) / max(duration, 0.000001), outcome: job.state.rawValue,
                    items: job.items.map(ItemEvidence.init), detail: [:]))
                try require(job.state == expected && (bytes == nil || bytes == job.transferredBytes))
                try require(job.retainedTemporaryPaths.isEmpty)
                return job
            }
            if let pending = job.pendingDecision {
                guard case .risk(let risk) = pending.question, allowed(risk) else { throw GateError.unexpectedDecision }
                try require(await manager.resolve(pending, answer: .risk(accepted: true)))
            }
            try require(!stopRequested && elapsed(start) < Fixed.maximumSeconds, .timeout)
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func manifest(_ label: String, service: any RemoteFileService, root: RemotePath, corpus: Corpus) async throws {
        await monitor.sample(label)
        let start = DispatchTime.now().uptimeNanoseconds
        // Obtain ORIGINAL BYTES from the destination readdir, never manufacture a
        // result-name manifest from requested names. No recursive unknown traversal.
        var actualNames: [Data] = []
        let top = try await service.list(root, token: CancellationToken())
        if root.bytes == raw(Fixed.corpus) { try checkCorpusListing(path: root, entries: top) }
        else {
            let expected: [Data: FileKind] = [raw("large-2GiB.bin"): .regular, raw("1000-small-files"): .directory, raw("目录 with spaces"): .directory]
            try require(top.count == expected.count && top.allSatisfy { expected[$0.name.bytes] == $0.attributes.kind })
        }
        guard let largeName = top.first(where: { $0.name.bytes == raw("large-2GiB.bin") }) else { throw GateError.integrity }
        actualNames.append(largeName.name.bytes)
        for name in ["1000-small-files", "目录 with spaces"] {
            let directory = try join(root, name)
            let entries = try await service.list(directory, token: CancellationToken())
            let expected = Set(corpus.files.filter { raw($0.path).starts(with: raw(name + "/")) }.map(\.rawKey))
            let observed = entries.map { raw(name) + Data([47]) + $0.name.bytes }
            try require(entries.allSatisfy { $0.attributes.kind == .regular } && entries.count == expected.count &&
                Set(observed.map { $0.base64EncodedString() }) == expected)
            actualNames += observed
        }
        let expected = Dictionary(uniqueKeysWithValues: corpus.files.map { ($0.rawKey, $0) })
        var observed: [Payload] = []
        for name in actualNames {
            try require(!stopRequested, .stopped)
            guard let item = expected[name.base64EncodedString()], let text = String(data: name, encoding: .utf8) else { throw GateError.integrity }
            observed.append(try await digest(service, join(root, text), relative: text, expected: item.bytes))
        }
        try corpus.compare(observed)
        evidence.manifests.append(ManifestEvidence(label: label, files: observed, rawNamesBase64: actualNames.map { $0.base64EncodedString() }))
        let count = observed.reduce(0) { $0 + $1.bytes }, duration = elapsed(start)
        evidence.phases.append(Phase(name: label, durationSeconds: duration, transferredBytes: count,
            bytesPerSecond: Double(count) / max(duration, 0.000001), outcome: "incremental-sha256-and-actual-readdir-bytes-match",
            items: [], detail: ["fileCount": String(observed.count), "chunkBytes": String(Fixed.chunk)]))
    }
    func startStopMonitor() {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in self?.requestStop() }
            source.resume(); signalSources.append(source)
        }
    }
    func shutdown() async {
        await manager.cancelAllAndWait()
        if let remote {
            await remote.close(); evidence.remoteCloseAwaited = await remote.closeCompleted
            for (key, value) in await remote.finishEvidence() { evidence.capability["remoteFsync-" + key] = value }
        }
        if let localService { await localService.close(); evidence.localCloseAwaited = await localService.closeCompleted }
        let snapshot = await manager.snapshot()
        evidence.serviceLeaseDrained = snapshot.isClosed && !snapshot.hasActiveWork && snapshot.serviceOperations.isEmpty
        signalSources.forEach { $0.cancel() }; signalSources.removeAll()
    }
    func execute() async throws {
        startStopMonitor()
        evidence.freeDiskBefore = try freeBytes(directory)
        try require(evidence.freeDiskBefore >= Fixed.minimumLocalFree)
        await monitor.sample("before-connect")
        // No NSApplication, Transport, broker, Keychain, terminal, helper or SSH child.
        let trustPath = directory + "/trust"
        try require(mkdir(trustPath, 0o700) == 0); try PrivateInput.checkDirectory(trustPath)
        let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22221))
        let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: self.input.hostKeyLine) }.value
        try require(key.fingerprint == Fixed.fingerprint, .fingerprint)
        let trust = try HostTrustStore(directory: AbsolutePath(trustPath))
        guard case .pending(let decision) = try await trust.evaluate(host: host, key: key) else { throw GateError.fingerprint }
        _ = try await trust.confirm(decision, displayedFingerprint: Fixed.fingerprint)
        // The only secret read in this driver; only reached on explicit live execution.
        var privateKey = try PrivateInput.read(contract.generation + "/id_ed25519", limit: 32768)
        let publicKey = try PrivateInput.read(contract.generation + "/id_ed25519.pub", limit: 4096)
        let connectToken = CancellationToken(); connectingToken = connectToken
        let backend = try await LibSSH2FileService.connect(configuration: SSHConnection(host: host, user: try SSHUser("fixture")),
            authentication: [.publicKey(publicKey: publicKey, privateKey: privateKey, passphrase: nil)],
            trustStore: trust, trustHandler: { _, reply in reply.resolve(.reject) }, connectionTimeout: 20, operationTimeout: 20, token: connectToken)
        privateKey.resetBytes(in: 0..<privateKey.count); privateKey.removeAll() // Swift/native copies cannot be guaranteed erased.
        let remote = ObservedService(backend, ledger: ledger, remoteRoot: remoteRoot)
        self.remote = remote
        let localService = ObservedService(try local.service(), ledger: ledger, ownsLocalRoot: true)
        self.localService = localService
        let r = try await manager.registerService(remote, hostID: "fixture-keyonly"), l = try await manager.registerService(localService)
        remoteID = r; localID = l
        await monitor.sample("connected")
        try require(remote_file_fixture_sockets() == 1)
        let corpusBytes = try await readSmall(remote, rp(Fixed.corpus + "/manifest.json"), limit: 262144)
        evidence.corpusManifestSHA256 = PrivateInput.sha256(corpusBytes)
        let corpus = try Corpus.parse(corpusBytes)
        for path in [Fixed.corpus] + Fixed.directories.map({ Fixed.corpus + "/" + $0 }) {
            let p = try rp(path); try await inspect(remote, p)
            try checkCorpusListing(path: p, entries: await remote.list(p, token: CancellationToken()))
        }
        try await inspect(remote, remoteRoot, leaf: false)
        try await remote.mkdir(remoteRoot, token: CancellationToken())
        try require(try await remote.list(remoteRoot, token: CancellationToken()).isEmpty)
        // Demonstrate the unconfirmed production gate against this ACTUAL service;
        // no hand-written ServerCommitConfirmation and no temporary write permitted.
        let gatedTarget = try join(remoteRoot, "unconfirmed-must-not-exist")
        let gated = try await transfer("actual-unconfirmed-no-replace-gate", request(r, rp(Fixed.corpus + "/目录 with spaces/Unicode e\u{301} 中文.txt"), r, gatedTarget), expected: .failed, bytes: 0)
        try require(gated.error?.kind == .needsCapabilityConfirmation)
        do { _ = try await remote.lstat(gatedTarget, token: CancellationToken()); throw GateError.integrity }
        catch let error as FileServiceError where error.kind == .notFound { }
        // Current SERVICE INSTANCE probe. This is the sole source of the no-replace confirmation.
        await monitor.sample("current-service-no-replace-probe")
        let scheduler = self.scheduler, parent = remoteRoot
        let probe = try await manager.withServiceOperation(serviceID: r, hostID: "fixture-keyonly", scheduling: .callerScheduled) { service, token in
            let plan = try ServerCommitProbe.prepare(service: service, parent: parent)
            return try await ServerCommitProbe.run(plan, service: service, hostID: "fixture-keyonly", approvedPlanID: plan.id,
                acknowledgedRisks: plan.requiredRisks, token: token, scheduler: scheduler)
        }
        evidence.capability = ["probeDirectoryBase64": probe.directory.bytes.base64EncodedString(), "passed": String(probe.passed),
            "errorKind": probe.error?.kind.rawValue ?? "none", "operation": probe.error?.operation ?? "none",
            "retainedPathsBase64": probe.retainedPaths.map { $0.bytes.base64EncodedString() }.joined(separator: ","),
            "binding": remote.serverBinding!.uuidString, "evidence": probe.confirmation?.evidence ?? "none"]
        try require(probe.confirmation?.serverBinding == remote.serverBinding)
        guard probe.passed, let confirmation = probe.confirmation else { throw GateError.integrity }
        try await manifest("remote-source-sha256", service: remote, root: rp(Fixed.corpus), corpus: corpus)
        let large = Fixed.largeBytes, smallBytes = corpus.files.filter { $0.path.hasPrefix("1000-small-files/") }.reduce(0) { $0 + $1.bytes }
        let down = try rp("/download"), up = try join(remoteRoot, "uploaded"), back = try rp("/roundtrip")
        try await localService.mkdir(down, token: CancellationToken()); try await remote.mkdir(up, token: CancellationToken())
        try await localService.mkdir(back, token: CancellationToken())
        for (label, source, sourceRoot, destination, destinationRoot, commit) in [
            ("download", r, try rp(Fixed.corpus), l, down, Optional<ServerCommitConfirmation>.none),
            ("upload", l, down, r, up, Optional(confirmation)),
            ("roundtrip-download", r, up, l, back, Optional<ServerCommitConfirmation>.none)] {
            _ = try await transfer(label + "-2GiB", request(source, join(sourceRoot, "large-2GiB.bin"), destination, join(destinationRoot, "large-2GiB.bin")), confirmation: commit, bytes: large)
            _ = try await transfer(label + "-1000-files", request(source, join(sourceRoot, "1000-small-files"), destination, join(destinationRoot, "1000-small-files"), tree: true), confirmation: commit, bytes: smallBytes)
            _ = try await transfer(label + "-unicode-directory", request(source, join(sourceRoot, "目录 with spaces"), destination, join(destinationRoot, "目录 with spaces"), tree: true), confirmation: commit, bytes: 4096)
            let service: any RemoteFileService = destination == r ? remote : localService
            try await manifest(label + "-sha256-raw-names", service: service, root: destinationRoot, corpus: corpus)
            if label == "download" { evidence.downloadedLargeAllocatedBytes = try local.allocatedLarge() }
        }
        // Deliberate links-only tree: all THREE are item failures, not silent skips or followed links.
        let linkJob = try await transfer("three-symlinks-explicit-rejection", request(r, rp(Fixed.corpus + "/links"), l, rp("/rejected-links"), tree: true), expected: .failed, bytes: 0)
        try require(linkJob.items.filter { if case .failed(let e) = $0.state { return e.kind == .symbolicLink }; return false }.count == 3)
        let denied = try await transfer("known-fixture-permission-denied-read", request(r, rp("/fixture/protected/denied.txt"), l, rp("/must-not-exist")), expected: .failed, bytes: 0)
        try require(denied.error?.kind == .permissionDenied)
        do { _ = try await localService.lstat(rp("/must-not-exist"), token: CancellationToken()); throw GateError.integrity }
        catch let error as FileServiceError where error.kind == .notFound { }
        // Real safe-replace attempt on two exclusively created OWNED sentinels only. This records
        // actual supported/unsupported outcome; there is no claim the server lacks an extension.
        try await safeReplace(remote: remote)
        try await cancelAtQuarter(source: remote, sourcePath: rp(Fixed.corpus + "/large-2GiB.bin"), destination: localService,
            destinationPath: rp("/cancel-download-existing"), label: "download-cancel-25-percent", confirmation: nil)
        try await cancelAtQuarter(source: localService, sourcePath: rp("/download/large-2GiB.bin"), destination: remote,
            destinationPath: join(remoteRoot, "cancel-upload-existing"), label: "upload-cancel-25-percent", confirmation: confirmation)
        let remoteTemps = await remote.remainingTransferTemporaries(), localTemps = await localService.remainingTransferTemporaries()
        try require(remoteTemps.isEmpty && localTemps.isEmpty)
        let remoteHistory = await remote.temporaryPaths(), localHistory = await localService.temporaryPaths()
        evidence.observedTemporaryPathsBase64 = remoteHistory + localHistory
        await monitor.sample("all-job-and-operation-leases-idle-before-cleanup")
        try await remote.cleanupOwned(root: remoteRoot); evidence.remoteCleanup = "successful-created known paths only; full allowlist checked, no unknown recursion; UUID absent verified"
        do { _ = try await remote.lstat(remoteRoot, token: CancellationToken()); throw GateError.cleanup }
        catch let e as FileServiceError where e.kind == .notFound { }
        try await localService.cleanupOwned(root: .root)
        await shutdown()
        try local.close(removeEmpty: true)
        try require(local.directoryRemoved)
        evidence.localCleanup = "known paths deleted through LocalFileService no-follow FDs; retained parent/dev/inode UUID directory removed"
        evidence.freeDiskAfter = try freeBytes(directory)
        await monitor.sample("all-services-and-local-root-closed")
        let counters = await ledger.snapshot()
        try require(counters.openHandles == 0 && counters.closedByServiceShutdown == 0 &&
            counters.successfulOpens == counters.successfulCloses && counters.largestRead <= Fixed.chunk && counters.largestWrite <= Fixed.chunk)
        let m = local.path.withCString { stress_sample($0) }
        try require(remote_file_fixture_sockets() == 0 && m.owned_fd_count == 0 && evidence.serviceLeaseDrained)
    }
    func safeReplace(remote: ObservedService) async throws {
        let first = raw("owned-safe-replace-source-not-secret"), second = raw("owned-safe-replace-destination-not-secret")
        let a = try join(remoteRoot, "replace-source"), b = try join(remoteRoot, "replace-destination")
        try await put(remote, a, bytes: first); try await put(remote, b, bytes: second)
        let attributes = try await remote.lstat(b, token: CancellationToken()), start = DispatchTime.now().uptimeNanoseconds
        var outcome = "supported-actual-posix-rename"
        do {
            try await remote.commit(a, to: b, request: CommitRequest(mode: .replaceExisting, expectedTarget: attributes,
                expectedContentSHA256: Data(SHA256.hash(data: second)), acceptNonCASOverwriteRisk: true), token: CancellationToken())
            try require(try await readSmall(remote, b, limit: 128) == first)
        } catch let e as FileServiceError where e.kind == .unsupported {
            outcome = "unsupported-actual-server-originals-preserved"
            try require(try await readSmall(remote, a, limit: 128) == first)
            try require(try await readSmall(remote, b, limit: 128) == second)
        }
        evidence.capability["posixRename"] = outcome
        evidence.phases.append(Phase(name: "actual-safe-replace-capability", durationSeconds: elapsed(start), transferredBytes: 0,
            bytesPerSecond: 0, outcome: outcome, items: [], detail: ["scope": "explicit owned sentinel targets; final check not CAS"]))
    }
    func cancelAtQuarter(source: any RemoteFileService, sourcePath: RemotePath, destination: any RemoteFileService,
                         destinationPath: RemotePath, label: String, confirmation: ServerCommitConfirmation?) async throws {
        let original = raw("owned-original-preserved-not-secret\n")
        try await put(destination, destinationPath, bytes: original)
        let before = try await destination.lstat(destinationPath, token: CancellationToken())
        let beforeDigest = try await digest(destination, destinationPath, relative: "sentinel", expected: UInt64(original.count))
        let token = CancellationToken(), start = DispatchTime.now().uptimeNanoseconds
        let progress = QuarterProgress(token: token)
        let remoteRoot = self.remoteRoot
        let policy = TransferPolicy(confirmRisk: { risk in
            switch risk {
            case .remotePathChecksAreNotAtomic(let path): return path.bytes.starts(with: raw(Fixed.corpus + "/")) || path.bytes.starts(with: remoteRoot.bytes + Data([47]))
            case .overwriteIsAtomicButNotCompareAndSwap(let path): return path == destinationPath
            default: return false
            }
        }, serverCommit: confirmation)
        await monitor.sample(label)
        let result = try await engine.copy(hostID: "fixture-keyonly", source: source, sourcePath: sourcePath,
            destination: destination, destinationPath: destinationPath, conflict: .overwrite, token: token, policy: policy,
            hooks: TransferHooks(progress: { _, bytes in await progress.update(bytes) }))
        let count = await progress.bytes
        try require(count >= Fixed.largeBytes / 4 && count < Fixed.largeBytes / 4 + UInt64(Fixed.chunk) && result.items.count == 1)
        guard case .failed(let error) = result.items[0].state, error.kind == .cancelled else { throw GateError.integrity }
        try require(result.items[0].retainedTemporary == nil)
        let afterDigest = try await digest(destination, destinationPath, relative: "sentinel", expected: UInt64(original.count))
        let after = try await destination.lstat(destinationPath, token: CancellationToken())
        try require(beforeDigest == afterDigest && after == before)
        // This cancellation is synchronous in engine progress AFTER its read/write
        // chunk returned, then engine token.check throws outside LibSSH2.perform.
        // closeHandle/temp cleanup use fresh tokens. A native I/O cancellation WOULD
        // dispose the connection; never reconnect or hide that here. Verify same
        // actual remote session remains live before any subsequent scenario.
        guard let liveRemote = remote else { throw GateError.integrity }
        let remoteStillLive = try await liveRemote.lstat(rp(Fixed.corpus + "/large-2GiB.bin"), token: CancellationToken())
        try require(remoteStillLive.kind == .regular && remoteStillLive.size == Fixed.largeBytes)
        evidence.phases.append(Phase(name: label, durationSeconds: elapsed(start), transferredBytes: count,
            bytesPerSecond: Double(count) / elapsed(start), outcome: "cancelled-at-first-real-chunk-crossing-25-percent-original-metadata-and-sha-preserved", items: result.items.map(ItemEvidence.init),
            detail: ["progressFraction": String(Double(count) / Double(Fixed.largeBytes)), "thresholdBytes": String(Fixed.largeBytes / 4),
                "maximumOvershootBytesExclusive": String(Fixed.chunk), "originalSHA256Before": beforeDigest.sha256, "originalSHA256After": afterDigest.sha256,
                "sameRemoteSessionLstatAfterCancel": "actual-success-no-reconnect",
                "method": "production TransferHooks progress after real write sets CancellationToken synchronously; no throttle/fake progress; no final commit"]))
    }
    func finish(failure: Error?) async throws -> Int32 {
        if let failure {
            await shutdown()
            evidence.retainedRemote = await remote?.ownedMetadata() ?? []
            evidence.retainedLocal = await localService?.ownedMetadata() ?? []
            try? local.close(removeEmpty: false)
            evidence.status = "failed-retained-for-review"
            if let e = failure as? GateError { evidence.failure = e.rawValue }
            else if let e = failure as? FileServiceError { evidence.failure = "file-" + e.kind.rawValue + "/" + e.operation + "/" + String(e.code ?? 0) }
            else { evidence.failure = "refused-no-details" }
            evidence.freeDiskAfter = (try? freeBytes(directory)) ?? 0
        } else { evidence.status = "passed-finite-remote-core-only" }
        evidence.endedAt = Date().timeIntervalSince1970
        await monitor.sample("finished")
        evidence.resources = await monitor.result()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try PrivateInput.writeExclusive(encoder.encode(evidence), to: directory + "/result.json")
        print("\(evidence.status) evidence=\(directory)/result.json")
        return failure == nil ? 0 : 1
    }
}
actor QuarterProgress {
    let token: CancellationToken
    private(set) var bytes: UInt64 = 0
    init(token: CancellationToken) { self.token = token }
    func update(_ count: UInt64) { bytes = count; if count >= Fixed.largeBytes / 4 { token.cancel() } }
}
