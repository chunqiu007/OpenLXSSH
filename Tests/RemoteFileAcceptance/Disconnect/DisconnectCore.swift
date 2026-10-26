import CryptoKit
import Darwin
import Foundation
import OpenLXSSHFiles
import RealIntegrationCore

// Upload interruption ONLY. No mutation of the accepted full-campaign entry point.
enum DisconnectFixed {
    static let task = "REAL-SFTP-DISCONNECT-PREP-A"
    static let bytes: UInt64 = 16 * 1024 * 1024
    static let quarter: UInt64 = bytes / 4
    static let operationSeconds = 20.0
    static func root(_ id: String) throws -> RemotePath { try rp("/fixture/home/openlxssh-disconnect-" + id) }
    static func original(_ id: String) -> Data { raw("OpenLXSSH owned disconnect original " + id + "\n") }
}
enum DisconnectError: String, Error { case arguments, authorization, contract, ledger, readiness, notDisconnected, originalChanged, cleanup }
struct DisconnectOptions {
    enum Action { case help, validate, prepare, upload, verify }
    let action: Action
    let path: String?
    let cleanup: Bool
    static func parse(_ args: [String]) throws -> Self {
        if args.isEmpty || args == ["--help"] { return Self(action: .help, path: nil, cleanup: false) }
        guard let first = args.first, ["validate", "--prepare-disconnect-case", "--disconnect-case", "--verify-disconnect-case"].contains(first) else { throw DisconnectError.arguments }
        var path: String?, authorized = false, reviewed = false, cleanup = false, i = 1
        while i < args.count {
            switch args[i] {
            case first == "--prepare-disconnect-case" ? "--generation" : "--case":
                guard path == nil, i + 1 < args.count else { throw DisconnectError.arguments }
                i += 1; path = args[i]; try PrivateInput.validateSyntax(args[i])
            case "--authorized-local-fixture": guard !authorized else { throw DisconnectError.arguments }; authorized = true
            case "--primary-reviewed": guard !reviewed else { throw DisconnectError.arguments }; reviewed = true
            case "--cleanup-owned-paths": guard !cleanup else { throw DisconnectError.arguments }; cleanup = true
            default: throw DisconnectError.arguments
            }
            i += 1
        }
        guard let path else { throw DisconnectError.arguments }
        if first == "validate" {
            guard !authorized && !reviewed && !cleanup && path.hasSuffix("/case.json") else { throw DisconnectError.arguments }
            return Self(action: .validate, path: path, cleanup: false)
        }
        guard authorized && reviewed else { throw DisconnectError.authorization }
        guard !cleanup || first == "--verify-disconnect-case" else { throw DisconnectError.arguments }
        return Self(action: first == "--prepare-disconnect-case" ? .prepare : first == "--disconnect-case" ? .upload : .verify,
            path: path, cleanup: cleanup)
    }
    static let help = """
    OpenLXSSH host15 TEST-ONLY upload-disconnect case, not the accepted full corpus campaign.
    Default/--help or validate --case /absolute/path/case.json: no file/network I/O.
    Future, ONLY after primary source review, explicit authorization and root ports released:
      --prepare-disconnect-case --generation /exact/new/keyonly/credentials-<12hex> --authorized-local-fixture --primary-reviewed
      --disconnect-case --case /exact/own/.runtime/disconnect-<uuid>/case.json --authorized-local-fixture --primary-reviewed
    On actual >=25% of a real 16MiB upload: writes ready.json (non-secret metadata), continues I/O.
    An EXTERNAL coordinator must TERM/wait its exact own finite relay Popen, never the consumer.
    No token cancellation or artificial transport error simulates the network failure.
    A later EXPLICIT new test connection (never product autoreconnect):
      --verify-disconnect-case --case <same> --authorized-local-fixture --primary-reviewed [--cleanup-owned-paths]
    Requires external relay-termination.json and exact successful-creation ledger. No unknown recursion.
    Fixed keyonly CID/project/base/image and fixture@127.0.0.1:22221 pinned host key. Never stop/restart server.
    Flags are accident gates, NOT authorization. No live operation occurs during offline build/tests.
    """
}
struct DisconnectContract: Codable, Sendable {
    let schema: Int
    let id: String
    let generation: String
    let provenanceSHA256: String
    let knownHostsSHA256: String
    let fingerprintSHA256: String
    let packagesSHA256: String
    let collectedAt: Double
    let preparedAt: Double
    let project: String
    let container: String
    let base: String
    let image: String
    let fingerprint: String
    static func make(generation: String, input: PublicMaterial, now: Double) -> Self {
        Self(schema: 1, id: UUID().uuidString.lowercased(), generation: generation,
            provenanceSHA256: input.provenanceSHA256, knownHostsSHA256: input.knownHostsSHA256,
            fingerprintSHA256: input.fingerprintSHA256, packagesSHA256: input.packagesSHA256,
            collectedAt: input.collectedAt, preparedAt: now, project: Fixed.project, container: Fixed.container,
            base: Fixed.base, image: Fixed.image, fingerprint: Fixed.fingerprint)
    }
    static func validatePath(_ path: String, ownRoot: String) throws -> String {
        let prefix = ownRoot + "/.runtime/disconnect-", suffix = "/case.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix),
              let id = UUID(uuidString: String(path.dropFirst(prefix.count).dropLast(suffix.count))),
              path == prefix + id.uuidString.lowercased() + suffix else { throw DisconnectError.contract }
        return id.uuidString.lowercased()
    }
    func validate(path: String, ownRoot: String, fixtureRoot: String, now: Double, builtAt: Double) throws {
        guard try Self.validatePath(path, ownRoot: ownRoot) == id, schema == 1,
              project == Fixed.project, container == Fixed.container, base == Fixed.base, image == Fixed.image,
              fingerprint == Fixed.fingerprint, [provenanceSHA256, knownHostsSHA256, fingerprintSHA256, packagesSHA256].allSatisfy({ Contract.hex($0, count: 64) }),
              collectedAt.isFinite, preparedAt.isFinite, now.isFinite, collectedAt >= builtAt, preparedAt >= collectedAt,
              preparedAt - collectedAt <= 900, now >= preparedAt, now - preparedAt <= 1800 else { throw DisconnectError.contract }
        try PublicMaterial.validateGeneration(generation, fixtureRoot: fixtureRoot)
    }
    func check(_ input: PublicMaterial) throws {
        guard input.collectedAt == collectedAt, input.provenanceSHA256 == provenanceSHA256,
              input.knownHostsSHA256 == knownHostsSHA256, input.fingerprintSHA256 == fingerprintSHA256,
              input.packagesSHA256 == packagesSHA256 else { throw DisconnectError.contract }
    }
}
struct DisconnectAttributes: Codable, Equatable, Sendable {
    let kind: String
    let size: UInt64?
    let permissions: UInt32?
    let modifiedSeconds: UInt64?
    init(_ a: FileAttributes) { kind = a.kind.rawValue; size = a.size; permissions = a.permissions; modifiedSeconds = a.modifiedSeconds }
}
struct DisconnectOwnedPath: Codable, Sendable {
    let pathBase64: String
    let directory: Bool
}
struct DisconnectItem: Codable, Sendable {
    let sourceBase64: String
    let destinationBase64: String
    let state: String
    let bytes: UInt64?
    let errorKind: String?
    let operation: String?
    let code: Int64?
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
struct DisconnectReady: Codable, Sendable {
    let schema: Int
    let caseID: String
    let event: String
    let progressBytes: UInt64
    let sourceBytes: UInt64
    let at: Double
    let serverBinding: String
    let createdPaths: [DisconnectOwnedPath]
    func validate(id: String) throws {
        guard schema == 1, caseID == id, event == "upload-real-progress-ready-to-terminate-owned-relay",
              sourceBytes == DisconnectFixed.bytes, progressBytes >= DisconnectFixed.quarter,
              progressBytes < DisconnectFixed.quarter + UInt64(Fixed.chunk), at.isFinite,
              UUID(uuidString: serverBinding) != nil else { throw DisconnectError.readiness }
        let temp = try DisconnectLedger.validate(createdPaths, id: id)
        guard temp.count == 1 else { throw DisconnectError.ledger }
    }
}
enum DisconnectLedger {
    // Only root, original sentinel and SUCCESSFULLY EXCLUSIVE-OPENED temp names.
    static func validate(_ paths: [DisconnectOwnedPath], id: String) throws -> [RemotePath] {
        let root = try DisconnectFixed.root(id), target = try join(root, "target.bin")
        guard paths.count >= 2, paths.count <= 3 else { throw DisconnectError.ledger }
        var seen: Set<Data> = [], temps: [RemotePath] = []
        for item in paths {
            guard let bytes = Data(base64Encoded: item.pathBase64), bytes.base64EncodedString() == item.pathBase64,
                  seen.insert(bytes).inserted else { throw DisconnectError.ledger }
            let path = try RemotePath(bytes: bytes)
            if path == root { guard item.directory else { throw DisconnectError.ledger }; continue }
            if path == target { guard !item.directory else { throw DisconnectError.ledger }; continue }
            guard !item.directory, path.parent == root, let name = path.name,
                  let text = String(data: name.bytes, encoding: .utf8), text.hasPrefix(".openlxssh-transfer."), text.hasSuffix(".part"),
                  let uuid = UUID(uuidString: String(text.dropFirst(".openlxssh-transfer.".count).dropLast(".part".count))),
                  text == ".openlxssh-transfer." + uuid.uuidString + ".part" else { throw DisconnectError.ledger }
            temps.append(path)
        }
        guard seen.contains(root.bytes), seen.contains(target.bytes) else { throw DisconnectError.ledger }
        return temps
    }
    static func checkListing(_ entries: [DirectoryEntry], created: [DisconnectOwnedPath], id: String) throws {
        _ = try validate(created, id: id)
        let root = try DisconnectFixed.root(id)
        let known = Set(try created.compactMap { item -> Data? in
            let path = try RemotePath(bytes: Data(base64Encoded: item.pathBase64)!)
            return path == root ? nil : path.name!.bytes
        })
        guard entries.count <= known.count, Set(entries.map { $0.name.bytes }).count == entries.count,
              entries.allSatisfy({ known.contains($0.name.bytes) && $0.attributes.kind == .regular }),
              entries.contains(where: { $0.name.bytes == raw("target.bin") }) else { throw DisconnectError.ledger }
    }
}
struct RelayTermination: Codable {
    let schema: Int
    let caseID: String
    let reason: String
    let readySHA256: String
    let ownedRelayPID: Int32
    let requestedAt: Double
    let completedAt: Double
    let relayExitCode: Int32
    let accepted: Int
    let finished: Int
    let rejected: Int
    let cleanupFailed: Int
    func validate(ready: DisconnectReady, readyData: Data) throws {
        guard schema == 1, caseID == ready.caseID, reason == "SIGTERM-exact-owned-relay-after-ready",
              readySHA256 == PrivateInput.sha256(readyData), ownedRelayPID > 1,
              requestedAt.isFinite, completedAt.isFinite, requestedAt >= ready.at, completedAt >= requestedAt,
              completedAt - requestedAt <= 45, relayExitCode == 0, accepted == 1, finished == 1,
              rejected == 0, cleanupFailed == 0 else { throw DisconnectError.readiness }
    }
}
func expectedDisconnectFailure(_ error: FileServiceError, progress: UInt64, sourceBytes: UInt64) -> Bool {
    // Preserve operation/code in result; generic transport alone does NOT prove the cause.
    [.transport, .closed].contains(error.kind) && progress >= DisconnectFixed.quarter && progress < sourceBytes
}
func writeDisconnectJSON<T: Encodable>(_ value: T, directory: String, name: String) throws {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try PrivateInput.writeExclusive(encoder.encode(value), to: directory + "/" + name)
}
