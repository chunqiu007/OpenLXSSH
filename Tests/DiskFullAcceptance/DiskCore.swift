import CryptoKit
import Darwin
import Foundation
import OpenLXSSHFiles
import RealIntegrationCore

enum DiskFixed {
    static let task = "REAL-SFTP-DISKFULL-PREP-A"
    static let sourceBytes: UInt64 = 8 * 1024 * 1024
    static let sentinelBytes: UInt64 = 64 * 1024
    static let capacity: UInt64 = 64 * 1024 * 1024
    static let maxFill: UInt64 = 60 * 1024 * 1024
    static let seconds = 110.0
    static func root(_ id: String) throws -> RemotePath { try rp("/dev/shm/openlxssh-enospc-" + id) }
    static func original(_ id: String) -> Data {
        let seed = raw("OpenLXSSH PUBLIC disk-full sentinel " + id + "\n")
        var data = Data()
        while data.count < Int(sentinelBytes) { data += seed }
        return Data(data.prefix(Int(sentinelBytes)))
    }
}
enum DiskError: String, Error { case arguments, authorization, contract, helper, ledger, evidence, cleanup, originalChanged, timeout }
struct DiskOptions {
    enum Action { case help, validate, prepare, live }
    let action: Action
    let path: String?
    static func parse(_ args: [String]) throws -> Self {
        if args.isEmpty || args == ["--help"] { return Self(action: .help, path: nil) }
        guard let first = args.first, ["validate", "prepare", "--live"].contains(first) else { throw DiskError.arguments }
        var path: String?, authorized = false, reviewed = false, index = 1
        while index < args.count {
            switch args[index] {
            case first == "prepare" ? "--generation" : "--case":
                guard path == nil, index + 1 < args.count else { throw DiskError.arguments }
                index += 1; path = args[index]; try PrivateInput.validateSyntax(args[index])
            case "--authorized-local-fixture": guard !authorized else { throw DiskError.arguments }; authorized = true
            case "--primary-reviewed": guard !reviewed else { throw DiskError.arguments }; reviewed = true
            default: throw DiskError.arguments
            }
            index += 1
        }
        guard let path else { throw DiskError.arguments }
        if first == "validate" {
            guard !authorized && !reviewed && path.hasSuffix("/case.json") else { throw DiskError.arguments }
            return Self(action: .validate, path: path)
        }
        guard authorized && reviewed else { throw DiskError.authorization }
        return Self(action: first == "prepare" ? .prepare : .live, path: path)
    }
    static let help = """
    OpenLXSSH host15 TEST ONLY: one remote /dev/shm64MiB ENOSPC upload, NOT product/macOS26 acceptance.
    Default/--help/validate --case /not/opened/case.json: no file/subprocess/network I/O.
    Future, ONLY after primary independent review, exclusive runtime and explicit live release:
      prepare --generation /exact/new/keyonly/credentials-<12hex> --authorized-local-fixture --primary-reviewed
      --live --case /exact/own/.runtime/enospc-<uuid>/case.json --authorized-local-fixture --primary-reviewed
    Fixed CID/project/image/out-of-band host key; no arbitrary host, target, path, fill budget or retries.
    Existing /dev/shm only, real 8MiB source/64KiB sentinel, maximum60MiB filler, helperTTL120s.
    Helper uses fixed Docker argv and pre-held private pipes. Must have NO other service users/new admissions.
    On actual SFTP write failure, sample real errno28 BEFORE engine cleanup; release filler FIRST.
    Generic FX4/transport/cancel/timeout alone never counts as ENOSPC success.
    Flags are accident gates, NOT authorization. No live operation occurs during offline build/tests.
    """
}
struct DiskContract: Codable, Sendable {
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
        let prefix = ownRoot + "/.runtime/enospc-", suffix = "/case.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix),
              let id = UUID(uuidString: String(path.dropFirst(prefix.count).dropLast(suffix.count))),
              path == prefix + id.uuidString.lowercased() + suffix else { throw DiskError.contract }
        return id.uuidString.lowercased()
    }
    func validate(path: String, now: Double) throws {
        guard try Self.validatePath(path, ownRoot: BuildLocation.ownRoot) == id, schema == 1,
              project == Fixed.project, container == Fixed.container, base == Fixed.base, image == Fixed.image,
              fingerprint == Fixed.fingerprint,
              [provenanceSHA256, knownHostsSHA256, fingerprintSHA256, packagesSHA256].allSatisfy({ Contract.hex($0, count: 64) }),
              collectedAt.isFinite, preparedAt.isFinite, now.isFinite, collectedAt >= BuildLocation.offlinePreparedAt,
              preparedAt >= collectedAt, preparedAt-collectedAt <= 900, now >= preparedAt, now-preparedAt <= 900 else { throw DiskError.contract }
        try PublicMaterial.validateGeneration(generation, fixtureRoot: BuildLocation.fixtureRoot)
    }
    func check(_ input: PublicMaterial) throws {
        guard input.collectedAt == collectedAt, input.provenanceSHA256 == provenanceSHA256,
              input.knownHostsSHA256 == knownHostsSHA256, input.fingerprintSHA256 == fingerprintSHA256,
              input.packagesSHA256 == packagesSHA256 else { throw DiskError.contract }
    }
}
struct DiskAttributes: Codable, Equatable {
    let kind: String
    let size: UInt64?
    let permissions: UInt32?
    let modifiedSeconds: UInt64?
    init(_ value: FileAttributes) { kind = value.kind.rawValue; size = value.size; permissions = value.permissions; modifiedSeconds = value.modifiedSeconds }
}
struct HelperEvent: Codable, Sendable {
    let schema: Int
    let caseID: String
    let event: String
    let uid: Int
    let filledBytes: UInt64
    let totalBytes: UInt64?
    let availableBytes: UInt64
    let blockBytes: UInt64?
    let errno: Int?
    let realENOSPC: Bool?
    let beforeAvailableBytes: UInt64?
    let afterAvailableBytes: UInt64?
    var memoryEventsBefore: String? = nil
    var memoryEventsAfter: String? = nil
    var memoryBefore: UInt64? = nil
    var memoryAfter: UInt64? = nil
    var directoryRemoved: Bool? = nil
    func validate(id: String, event expected: String) throws {
        guard schema == 1, caseID == id, event == expected, uid == 10000,
              filledBytes <= DiskFixed.maxFill, availableBytes <= DiskFixed.capacity else { throw DiskError.helper }
        if expected != "released" {
            guard totalBytes == DiskFixed.capacity, blockBytes == 4096 else { throw DiskError.helper }
        }
        if expected == "ready" { guard availableBytes == DiskFixed.capacity && filledBytes == 0 else { throw DiskError.helper } }
        if expected == "filled" { guard filledBytes == DiskFixed.maxFill-4096 && availableBytes < DiskFixed.sourceBytes else { throw DiskError.helper } }
        if expected == "released" { guard filledBytes == 0 && availableBytes >= DiskFixed.maxFill-4096 else { throw DiskError.helper } }
    }
    var provesFull: Bool { event == "sampled" && errno == 28 && realENOSPC == true && beforeAvailableBytes == 0 && afterAvailableBytes == 0 && availableBytes == 0 }
}
func memorySafe(_ before: HelperEvent, _ after: HelperEvent) -> Bool {
    func events(_ value: String?) -> [String: UInt64]? {
        guard let value else { return nil }
        var result: [String: UInt64] = [:]
        for line in value.split(separator:"\n") {
            let fields=line.split(separator:" ")
            guard fields.count==2,let number=UInt64(fields[1]),result[String(fields[0])]==nil else { return nil }
            result[String(fields[0])]=number
        }
        return result
    }
    guard let initial=events(before.memoryEventsBefore),let final=events(after.memoryEventsAfter),
          let used=before.memoryBefore,used+DiskFixed.capacity+96*1024*1024<=384*1024*1024,
          let end=after.memoryAfter,end<384*1024*1024 else { return false }
    return ["oom","oom_kill","oom_group_kill"].allSatisfy { initial[$0] != nil && initial[$0]==final[$0] }
}
func diskFailureAccepted(_ error: FileServiceError, sample: HelperEvent?) -> Bool {
    error.kind == .protocolFailure && error.operation == "write" && error.code == 4 && sample?.provesFull == true
}
func diskJSON<T: Encodable>(_ value: T, directory: String, name: String) throws {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try PrivateInput.writeExclusive(encoder.encode(value), to: directory + "/" + name)
}
func diskLedger(_ values: [OwnedPath], root: RemotePath) throws {
    var seen: Set<Data> = []
    guard values.count <= 3 else { throw DiskError.ledger }
    for item in values {
        guard let bytes = Data(base64Encoded: item.pathBase64), bytes.base64EncodedString() == item.pathBase64,
              seen.insert(bytes).inserted else { throw DiskError.ledger }
        let path = try RemotePath(bytes: bytes)
        if path == root { guard item.directory else { throw DiskError.ledger }; continue }
        guard !item.directory, path.parent == root else { throw DiskError.ledger }
        if path.name?.bytes == raw("target.bin") { continue }
        guard let name = path.name, let text = String(data: name.bytes, encoding: .utf8),
              text.hasPrefix(".openlxssh-transfer."), text.hasSuffix(".part"),
              let id = UUID(uuidString: String(text.dropFirst(".openlxssh-transfer.".count).dropLast(".part".count))),
              text == ".openlxssh-transfer." + id.uuidString + ".part" else { throw DiskError.ledger }
    }
}
