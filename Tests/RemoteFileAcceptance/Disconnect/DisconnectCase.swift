import CryptoKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore
import RealIntegrationPOSIX
import RemoteFileMetrics
import StressMetrics

struct DisconnectUploadResult: Codable, Sendable {
    let schema: Int
    let caseID: String
    let status: String
    let sourceBytes: UInt64
    let sourceSHA256: String
    let sourceAllocatedBytes: UInt64
    let targetBefore: DisconnectAttributes?
    let targetSHA256Before: String?
    let progressBytes: UInt64
    let failureKind: String?
    let failureOperation: String?
    let failureCode: Int64?
    let failureDetail: String?
    let items: [DisconnectItem]
    let ownedPaths: [DisconnectOwnedPath]
    let startedAt: Double
    let endedAt: Double
    let firstServerBinding: String?
    let firstConnectionCloseAwaited: Bool
    let managerLeaseDrained: Bool
    let resourcesAfterClose: APICounters
    let fixtureSocketsAfterClose: Int32
}
struct DisconnectVerification: Encodable {
    let schema = 1
    let caseID: String
    let status: String
    let uploadErrorKind: String
    let uploadErrorOperation: String
    let uploadErrorCode: Int64?
    let targetBefore: DisconnectAttributes
    let targetAfter: DisconnectAttributes
    let targetSHA256Before: String
    let targetSHA256After: String
    let firstServerBinding: String
    let explicitNewServerBinding: String
    let knownTemporaryPathsBase64: [String]
    let observedTemporaryPathsBase64: [String]
    let cleanedPathsBase64: [String]
    let localDataRemoved: Bool
    let newConnectionCloseAwaited: Bool
    let fixtureSocketsAfterClose: Int32
    let boundary = "Explicit operator-invoked second test connection, not product automatic reconnect. No source corpus benchmark repeated. Exact root/files only; no wildcard/temp-prefix discovery or recursive unknown cleanup."
}

@MainActor func disconnectConnect(contract: DisconnectContract, input: PublicMaterial, trustPath: String) async throws -> LibSSH2FileService {
    try require(mkdir(trustPath, 0o700) == 0); try PrivateInput.checkDirectory(trustPath)
    let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
    try require(key.fingerprint == Fixed.fingerprint, .fingerprint)
    let trust = try HostTrustStore(directory: AbsolutePath(trustPath))
    let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22221))
    guard case .pending(let pending) = try await trust.evaluate(host: host, key: key) else { throw DisconnectError.contract }
    _ = try await trust.confirm(pending, displayedFingerprint: Fixed.fingerprint)
    var privateKey = try PrivateInput.read(contract.generation + "/id_ed25519", limit: 32768)
    defer { privateKey.resetBytes(in: 0..<privateKey.count); privateKey.removeAll() }
    let publicKey = try PrivateInput.read(contract.generation + "/id_ed25519.pub", limit: 4096)
    return try await LibSSH2FileService.connect(configuration: SSHConnection(host: host, user: try SSHUser("fixture")),
        authentication: [.publicKey(publicKey: publicKey, privateKey: privateKey, passphrase: nil)],
        trustStore: trust, trustHandler: { _, reply in reply.resolve(.reject) },
        connectionTimeout: 20, operationTimeout: DisconnectFixed.operationSeconds, token: CancellationToken())
}
func generateDisconnectSource(_ owner: OwnedLocal) throws -> (String, UInt64) {
    let path = owner.path + "/source.bin"
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw DisconnectError.contract }; defer { Darwin.close(fd) }
    let seed = Data(SHA256.hash(data: raw("OpenLXSSH non-secret upload disconnect 16MiB")))
    var block = Data(); for _ in 0..<(Fixed.chunk / seed.count) { block += seed }
    var hash = SHA256(), total: UInt64 = 0
    while total < DisconnectFixed.bytes {
        block.withUnsafeMutableBytes { $0.storeBytes(of: total.littleEndian, as: UInt64.self) }
        var offset = 0
        while offset < block.count {
            let n = block.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if n < 0 && errno == EINTR { continue }
            try require(n > 0); offset += n
        }
        total += UInt64(block.count); hash.update(data: block)
    }
    var allocated: UInt64 = 0
    try require(total == DisconnectFixed.bytes && fsync(fd) == 0 && remote_file_allocated(fd, &allocated) == 0 && allocated >= total)
    return (hex(hash.finalize()), allocated)
}
actor DisconnectProgress {
    let directory: String, id: String, remote: ObservedService
    private(set) var bytes: UInt64 = 0
    private(set) var ready: DisconnectReady?
    private(set) var failure = false
    init(directory: String, id: String, remote: ObservedService) { self.directory = directory; self.id = id; self.remote = remote }
    func update(_ count: UInt64) async {
        bytes = count
        guard ready == nil, !failure, count >= DisconnectFixed.quarter else { return }
        do {
            guard let binding = remote.serverBinding else { throw DisconnectError.readiness }
            let event = DisconnectReady(schema: 1, caseID: id, event: "upload-real-progress-ready-to-terminate-owned-relay",
                progressBytes: count, sourceBytes: DisconnectFixed.bytes, at: Date().timeIntervalSince1970,
                serverBinding: binding.uuidString, createdPaths: await remote.ownedMetadata().map { DisconnectOwnedPath(pathBase64: $0.pathBase64, directory: $0.directory) })
            try event.validate(id: id)
            try writeDisconnectJSON(event, directory: directory, name: "ready.json")
            ready = event
            print("disconnect-ready event=upload-real-progress-ready-to-terminate-owned-relay caseID=" + id)
            // Continue to the NEXT real write. Never cancel token/service or fabricate I/O.
        } catch { failure = true }
    }
}

@MainActor enum DisconnectUpload {
    static func run(contract: DisconnectContract, input: PublicMaterial, directory: String) async throws -> Int32 {
        try PrivateInput.writeExclusive(raw("one upload attempt; no automatic retry\n"), to: directory + "/upload.claim")
        let start = Date().timeIntervalSince1970, owner = try OwnedLocal(parentPath: directory), ledger = Ledger()
        let source = ObservedService(try owner.service(), ledger: ledger, ownsLocalRoot: true)
        let generated = try generateDisconnectSource(owner)
        let sourceMeta: [String: String] = ["localRoot": owner.path, "device": String(owner.identity.0), "inode": String(owner.identity.1),
            "sourceSHA256": generated.0, "sourceBytes": String(DisconnectFixed.bytes), "sourceAllocatedBytes": String(generated.1)]
        try writeDisconnectJSON(sourceMeta, directory: directory, name: "local-owned.json")
        let scheduler = TransferScheduler(maxConcurrentChunks: 2)
        let engine = SafeTransferEngine(scheduler: scheduler, chunkSize: Fixed.chunk)
        let manager = TransferManager(engine: engine, maxConcurrentJobs: 1, idleTimeout: nil)
        var remote: ObservedService?, progress: DisconnectProgress?, report: TransferReport?
        var targetBefore: DisconnectAttributes?, targetHash: String?, topFailure: String?
        let root = try DisconnectFixed.root(contract.id), target = try join(root, "target.bin")
        do {
            let native = try await disconnectConnect(contract: contract, input: input, trustPath: directory + "/upload-trust")
            let wrapped = ObservedService(native, ledger: ledger, remoteRoot: root); remote = wrapped
            let remoteID = try await manager.registerService(wrapped, hostID: "fixture-disconnect")
            _ = try await manager.registerService(source)
            try await inspect(wrapped, root, leaf: false)
            try await wrapped.mkdir(root, token: CancellationToken())
            try require(try await wrapped.list(root, token: CancellationToken()).isEmpty)
            let original = DisconnectFixed.original(contract.id)
            try await put(wrapped, target, bytes: original)
            targetBefore = DisconnectAttributes(try await wrapped.lstat(target, token: CancellationToken()))
            targetHash = try await digest(wrapped, target, relative: "target.bin", expected: UInt64(original.count)).sha256
            let observed = DisconnectProgress(directory: directory, id: contract.id, remote: wrapped); progress = observed
            // The operation lease is closed only after the real engine and its cleanup return.
            // callerScheduled avoids nesting the same production host scheduler twice.
            report = try await manager.withServiceOperation(serviceID: remoteID, hostID: "fixture-disconnect", scheduling: .callerScheduled) { service, token in
                let policy = TransferPolicy(confirmRisk: { risk in
                    switch risk {
                    case .remotePathChecksAreNotAtomic(let path): return path == target
                    case .overwriteIsAtomicButNotCompareAndSwap(let path): return path == target
                    default: return false
                    }
                })
                return try await engine.copy(hostID: "fixture-disconnect", source: source, sourcePath: rp("/source.bin"),
                    destination: service, destinationPath: target, conflict: .overwrite, token: token, policy: policy,
                    hooks: TransferHooks(progress: { _, count in await observed.update(count) }))
            }
        } catch {
            if let e = error as? FileServiceError { topFailure = e.kind.rawValue + "/" + e.operation + "/" + String(e.code ?? 0) }
            else { topFailure = "setup-or-lease-refused" }
        }
        let count = await progress?.bytes ?? 0, ready = await progress?.ready, progressFailure = await progress?.failure ?? false
        let recorded = await remote?.ownedMetadata() ?? []
        let paths = recorded.map { DisconnectOwnedPath(pathBase64: $0.pathBase64, directory: $0.directory) }
        var typed: FileServiceError?
        if let report, report.items.count == 1, case .failed(let error) = report.items[0].state { typed = error }
        let valid = typed.map { expectedDisconnectFailure($0, progress: count, sourceBytes: DisconnectFixed.bytes) } ?? false
        // NO attempt to re-stat/hash on the possibly disposed original remote service.
        await manager.cancelAllAndWait()
        if let remote { await remote.close() }
        await source.close(); try owner.close(removeEmpty: false)
        let snap = await manager.snapshot(), closed = await remote?.closeCompleted ?? false
        let result = DisconnectUploadResult(schema: 1, caseID: contract.id,
            status: valid && ready != nil && !progressFailure && topFailure == nil ? "typed-failure-await-external-proof-and-new-connection" : "failed-not-accepted-no-retry",
            sourceBytes: DisconnectFixed.bytes, sourceSHA256: generated.0, sourceAllocatedBytes: generated.1,
            targetBefore: targetBefore, targetSHA256Before: targetHash, progressBytes: count,
            failureKind: typed?.kind.rawValue, failureOperation: typed?.operation, failureCode: typed?.code,
            failureDetail: topFailure ?? (progressFailure ? "ready-file-failed" : nil), items: report?.items.map(DisconnectItem.init) ?? [],
            ownedPaths: paths, startedAt: start, endedAt: Date().timeIntervalSince1970,
            firstServerBinding: remote?.serverBinding?.uuidString, firstConnectionCloseAwaited: closed,
            managerLeaseDrained: snap.isClosed && !snap.hasActiveWork && snap.serviceOperations.isEmpty,
            resourcesAfterClose: await ledger.snapshot(), fixtureSocketsAfterClose: remote_file_fixture_sockets())
        try writeDisconnectJSON(result, directory: directory, name: "upload-result.json")
        print(result.status + " result=" + directory + "/upload-result.json")
        return result.status == "typed-failure-await-external-proof-and-new-connection" ? 0 : 1
    }
}

@MainActor enum DisconnectVerify {
    static func run(contract: DisconnectContract, input: PublicMaterial, directory: String, cleanup: Bool) async throws -> Int32 {
        try PrivateInput.writeExclusive(raw("one explicit verification connection\n"), to: directory + "/verify.claim")
        let readyData = try PrivateInput.read(directory + "/ready.json", limit: 8192)
        let ready = try JSONDecoder().decode(DisconnectReady.self, from: readyData); try ready.validate(id: contract.id)
        let receipt = try JSONDecoder().decode(RelayTermination.self, from: PrivateInput.read(directory + "/relay-termination.json", limit: 8192))
        try receipt.validate(ready: ready, readyData: readyData)
        let upload = try JSONDecoder().decode(DisconnectUploadResult.self, from: PrivateInput.read(directory + "/upload-result.json", limit: 32768))
        guard upload.schema == 1, upload.caseID == contract.id, upload.status == "typed-failure-await-external-proof-and-new-connection",
              ready.at >= upload.startedAt, ready.at <= upload.endedAt, receipt.requestedAt <= upload.endedAt,
              upload.sourceBytes == DisconnectFixed.bytes, upload.progressBytes >= DisconnectFixed.quarter,
              upload.progressBytes < DisconnectFixed.bytes, ["transport", "closed"].contains(upload.failureKind),
              upload.firstConnectionCloseAwaited, upload.managerLeaseDrained, upload.fixtureSocketsAfterClose == 0,
              let before = upload.targetBefore, let beforeHash = upload.targetSHA256Before,
              beforeHash == PrivateInput.sha256(DisconnectFixed.original(contract.id)),
              let firstBinding = upload.firstServerBinding, firstBinding == ready.serverBinding else { throw DisconnectError.notDisconnected }
        let readyTemps = try DisconnectLedger.validate(ready.createdPaths, id: contract.id)
        let remainingTemps = try DisconnectLedger.validate(upload.ownedPaths, id: contract.id)
        guard readyTemps.count == 1, remainingTemps.allSatisfy({ readyTemps.contains($0) }),
              upload.items.count == 1, upload.items[0].state == "failed",
              upload.items[0].errorKind == upload.failureKind else { throw DisconnectError.ledger }
        if let retained = upload.items[0].retainedTemporaryBase64 {
            guard remainingTemps.contains(where: { $0.bytes.base64EncodedString() == retained }) else { throw DisconnectError.ledger }
        }
        let root = try DisconnectFixed.root(contract.id), target = try join(root, "target.bin")
        let native = try await disconnectConnect(contract: contract, input: input, trustPath: directory + "/verification-trust")
        let newBinding = native.serverBinding!.uuidString
        guard newBinding != firstBinding else { await native.close(); throw DisconnectError.notDisconnected }
        var output: DisconnectVerification?
        do {
            try await inspect(native, root)
            let after = DisconnectAttributes(try await native.lstat(target, token: CancellationToken()))
            let hash = try await digest(native, target, relative: "target.bin", expected: UInt64(DisconnectFixed.original(contract.id).count)).sha256
            guard after == before, hash == beforeHash else { throw DisconnectError.originalChanged }
            let listing = try await native.list(root, token: CancellationToken())
            try DisconnectLedger.checkListing(listing, created: ready.createdPaths, id: contract.id)
            let observedTemps = try listing.filter { $0.name.bytes != raw("target.bin") }.map { try root.appending($0.name) }
            var deleted: [String] = []
            if cleanup {
                // No search for temp prefix; only paths from successful exclusive-open ledger.
                for path in observedTemps + [target] {
                    try await inspect(native, path)
                    try require(try await native.lstat(path, token: CancellationToken()).kind == .regular)
                    try await native.remove(path, directory: false, token: CancellationToken()); deleted.append(path.bytes.base64EncodedString())
                }
                try require(try await native.list(root, token: CancellationToken()).isEmpty)
                try await native.remove(root, directory: true, token: CancellationToken()); deleted.append(root.bytes.base64EncodedString())
                do { _ = try await native.lstat(root, token: CancellationToken()); throw DisconnectError.cleanup }
                catch let error as FileServiceError where error.kind == .notFound { }
            }
            await native.close()
            var localRemoved = false
            if cleanup { try cleanupDisconnectLocal(directory: directory, upload: upload); localRemoved = true }
            output = DisconnectVerification(caseID: contract.id, status: cleanup ? "verified-original-and-cleaned-exact-owned-paths" : "verified-original-retained-exact-owned-paths",
                uploadErrorKind: upload.failureKind!, uploadErrorOperation: upload.failureOperation ?? "unknown", uploadErrorCode: upload.failureCode,
                targetBefore: before, targetAfter: after, targetSHA256Before: beforeHash, targetSHA256After: hash,
                firstServerBinding: firstBinding, explicitNewServerBinding: newBinding,
                knownTemporaryPathsBase64: readyTemps.map { $0.bytes.base64EncodedString() }, observedTemporaryPathsBase64: observedTemps.map { $0.bytes.base64EncodedString() },
                cleanedPathsBase64: deleted, localDataRemoved: localRemoved, newConnectionCloseAwaited: true,
                fixtureSocketsAfterClose: remote_file_fixture_sockets())
        } catch {
            await native.close()
            let failure = ["status": "verification-failed-retain-known-paths", "caseID": contract.id,
                "reason": (error as? DisconnectError)?.rawValue ?? (error as? FileServiceError)?.kind.rawValue ?? "refused"]
            try writeDisconnectJSON(failure, directory: directory, name: "verification-failure.json"); throw error
        }
        guard let output, output.fixtureSocketsAfterClose == 0 else { throw DisconnectError.cleanup }
        try writeDisconnectJSON(output, directory: directory, name: "verification-result.json")
        print(output.status + " result=" + directory + "/verification-result.json"); return 0
    }
}
func cleanupDisconnectLocal(directory: String, upload: DisconnectUploadResult) throws {
    let data = try PrivateInput.read(directory + "/local-owned.json", limit: 4096)
    let meta = try JSONDecoder().decode([String: String].self, from: data)
    guard meta["localRoot"] == directory + "/data", let device = UInt64(meta["device"] ?? ""), let inode = UInt64(meta["inode"] ?? ""),
          meta["sourceSHA256"] == upload.sourceSHA256 else { throw DisconnectError.cleanup }
    let fd = ri_open_private(directory + "/data", 1)
    guard fd >= 0 else { throw DisconnectError.cleanup }; defer { Darwin.close(fd) }
    var dev: UInt64 = 0, ino: UInt64 = 0
    guard remote_file_identity(fd, &dev, &ino) == 0, dev == device, ino == inode else { throw DisconnectError.cleanup }
    // Enumerate only this retained fd; delete only the exact generated single-link source.
    let copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard copy >= 0, let stream = fdopendir(copy) else { throw DisconnectError.cleanup }
    var names: [Data] = []
    while let entry = readdir(stream) {
        let name = withUnsafeBytes(of: entry.pointee.d_name) { Data($0.prefix(Int(entry.pointee.d_namlen))) }
        if name != raw(".") && name != raw("..") { names.append(name) }
    }
    closedir(stream)
    guard names == [raw("source.bin")] else { throw DisconnectError.cleanup }
    let source = ri_open_private(directory + "/data/source.bin", 0)
    guard source >= 0 else { throw DisconnectError.cleanup }; defer { Darwin.close(source) }
    var hash = SHA256(), total: UInt64 = 0, chunk = [UInt8](repeating: 0, count: Fixed.chunk)
    while true {
        let n = Darwin.read(source, &chunk, chunk.count)
        if n < 0 && errno == EINTR { continue }
        guard n >= 0 else { throw DisconnectError.cleanup }
        if n == 0 { break }; total += UInt64(n); guard total <= DisconnectFixed.bytes else { throw DisconnectError.cleanup }
        hash.update(data: Data(chunk.prefix(n)))
    }
    guard total == DisconnectFixed.bytes, hex(hash.finalize()) == upload.sourceSHA256 else { throw DisconnectError.cleanup }
    var opened = stat(), pathInfo = stat()
    guard fstat(source, &opened) == 0, fstatat(fd, "source.bin", &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
          opened.st_dev == pathInfo.st_dev, opened.st_ino == pathInfo.st_ino,
          unlinkat(fd, "source.bin", 0) == 0 else { throw DisconnectError.cleanup }
    let parent = ri_open_private(directory, 1)
    guard parent >= 0 else { throw DisconnectError.cleanup }; defer { Darwin.close(parent) }
    var current = stat()
    guard fstatat(parent, "data", &current, AT_SYMLINK_NOFOLLOW) == 0,
          UInt64(current.st_dev) == device, UInt64(current.st_ino) == inode,
          unlinkat(parent, "data", AT_REMOVEDIR) == 0 else { throw DisconnectError.cleanup }
}
