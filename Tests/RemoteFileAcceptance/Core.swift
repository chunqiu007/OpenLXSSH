import CryptoKit
import Darwin
import Foundation
import RealIntegrationCore

// These are test infrastructure bindings, not product defaults or credentials.
enum Fixed {
    static let task = "REAL-SFTP-FILE-ACCEPTANCE-A"
    static let base = "docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d"
    static let image = "sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363"
    static let project = "openlxssh-fixture-61ed25328c13"
    static let container = "2db5bbb3cb75a3253d9b02af5ca52cbdc8095230464f82c18d37eca9ac1fc837"
    static let fingerprint = "SHA256:oCBbJaAjOZMzrKEnj+Z4iHSn74Qc+0tTu9bOzfpwJ5w"
    static let corpus = "/fixture/home/corpus"
    static let largeBytes: UInt64 = 2 * 1024 * 1024 * 1024
    static let chunk = 65_536
    static let minimumLocalFree: UInt64 = 8 * 1024 * 1024 * 1024
    static let maximumSeconds = 3300.0 // Leaves a bounded drain before the 3600s relay ends.
    static let links = ["links/relative-file", "links/cycle", "links/outside-corpus"]
    static let directories = ["1000-small-files", "目录 with spaces", "links"]
    static var specifications: [(String, UInt64)] {
        [("large-2GiB.bin", largeBytes)] + (0..<1000).map {
            (String(format: "1000-small-files/文件 %04d [#; $].txt", $0), UInt64(1024 + $0 % 3072))
        } + [("目录 with spaces/Unicode e\u{301} 中文.txt", 4096)]
    }
}
enum GateError: String, Error { case arguments, authorization, contract, provenance, fingerprint, corpus, integrity, cleanup, timeout, stopped, unexpectedDecision }
func require(_ value: Bool, _ error: GateError = .integrity) throws {
    if !value { throw error }
}
func raw(_ text: String) -> Data { Data(text.utf8) }
func hex<D: Sequence>(_ bytes: D) -> String where D.Element == UInt8 { bytes.map { String(format: "%02x", $0) }.joined() }
func elapsed(_ start: UInt64) -> Double { Double(DispatchTime.now().uptimeNanoseconds - start) / 1e9 }

struct Arguments {
    enum Action { case help, validate, prepare, live }
    let action: Action
    let path: String?
    static func parse(_ args: [String]) throws -> Self {
        if args.isEmpty || args == ["--help"] { return Self(action: .help, path: nil) }
        guard let first = args.first, ["validate", "prepare", "--live"].contains(first) else { throw GateError.arguments }
        var path: String?, authorized = false, reviewed = false
        var index = 1
        while index < args.count {
            switch args[index] {
            case first == "prepare" ? "--generation" : "--campaign":
                guard path == nil, index + 1 < args.count else { throw GateError.arguments }
                index += 1; path = args[index]; try PrivateInput.validateSyntax(args[index])
            case "--authorized-local-fixture":
                guard !authorized else { throw GateError.arguments }; authorized = true
            case "--primary-reviewed":
                guard !reviewed else { throw GateError.arguments }; reviewed = true
            default: throw GateError.arguments
            }
            index += 1
        }
        guard let path else { throw GateError.arguments }
        if first == "validate" {
            guard !authorized && !reviewed, path.hasSuffix("/campaign.json") else { throw GateError.arguments }
            return Self(action: .validate, path: path)
        }
        guard authorized && reviewed else { throw GateError.authorization }
        return Self(action: first == "prepare" ? .prepare : .live, path: path)
    }
    static let help = """
    OpenLXSSH finite remote-file acceptance, host15 TEST ONLY.
    Default/--help and validate --campaign /absolute/path/campaign.json: syntax only, NO file/network I/O.
    Only after independent primary review and explicit live release:
      prepare --authorized-local-fixture --primary-reviewed --generation /exact/new/keyonly/credentials-<12hex>
      --live --authorized-local-fixture --primary-reviewed --campaign /exact/own/.runtime/campaign-<uuid>/campaign.json
    Fixed fixture@127.0.0.1:22221, exact out-of-band host key/base/image/project/container.
    prepare reads only public export metadata; live reads the single private-key file into memory.
    No Docker/relay/server/data generation, host overrides, credential arguments, retry or shell commands.
    Flags prevent accidents; they are NOT authorization. Full 2GiB/1000 corpus required, no reduced mode.
    """
}

struct Campaign: Codable, Sendable {
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
    func validate(path: String, ownRoot: String, fixtureRoot: String, now: Double) throws {
        guard schema == 1, let uuid = UUID(uuidString: id), uuid.uuidString.lowercased() == id,
              path == ownRoot + "/.runtime/campaign-" + id + "/campaign.json",
              project == Fixed.project, container == Fixed.container, base == Fixed.base,
              image == Fixed.image, fingerprint == Fixed.fingerprint,
              [provenanceSHA256, knownHostsSHA256, fingerprintSHA256, packagesSHA256].allSatisfy({ Contract.hex($0, count: 64) }),
              collectedAt.isFinite, preparedAt.isFinite, collectedAt > 0, preparedAt >= collectedAt,
              preparedAt - collectedAt <= 900, now.isFinite, now >= preparedAt, now - preparedAt <= 1800 else { throw GateError.contract }
        try PublicMaterial.validateGeneration(generation, fixtureRoot: fixtureRoot)
    }
}

struct PublicMaterial: Sendable {
    let hostKeyLine: String
    let collectedAt: Double
    let provenanceSHA256: String
    let knownHostsSHA256: String
    let fingerprintSHA256: String
    let packagesSHA256: String
    static func validateGeneration(_ directory: String, fixtureRoot: String) throws {
        try PrivateInput.validateSyntax(directory)
        let prefix = fixtureRoot + "/.runtime/keyonly/credentials-"
        guard directory.hasPrefix(prefix), Contract.hex(String(directory.dropFirst(prefix.count)), count: 12) else { throw GateError.contract }
    }
    // Pure parser factored for synthetic offline data. Live always passes Fixed.fingerprint.
    static func hostKey(known: Data, exported: Data, expected: String) throws -> String {
        let text = try PrivateInput.text(known)
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard text.hasSuffix("\n"), !text.dropLast().contains("\n"), fields.count == 3,
              fields[0] == "[127.0.0.1]:22221", fields[1] == "ssh-ed25519",
              let key = Data(base64Encoded: String(fields[2])), key.count == 51,
              key.base64EncodedString() == fields[2] else { throw GateError.fingerprint }
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: key)).base64EncodedString().dropLast()
        let parts = try PrivateInput.text(exported).split(whereSeparator: { $0.isWhitespace })
        guard fingerprint == expected, parts.count >= 2, parts[1] == Substring(expected) else { throw GateError.fingerprint }
        return "ssh-ed25519 " + fields[2]
    }
    static func provenance(_ data: Data, now: Double, fresh: Bool, minimumCollectedAt: Double) throws -> Double {
        let info = try object(data, keys: ["base_image", "built_image_id", "service", "collected_at"])
        guard info["base_image"] as? String == Fixed.base, info["built_image_id"] as? String == Fixed.image,
              info["service"] as? String == "keyonly", let time = info["collected_at"] as? Double,
              time.isFinite, time > 0, now.isFinite, now >= time,
              !fresh || (now - time <= 900 && time >= minimumCollectedAt) else { throw GateError.provenance }
        return time
    }
    static func load(directory: String, fixtureRoot: String, now: Double, fresh: Bool) throws -> Self {
        try validateGeneration(directory, fixtureRoot: fixtureRoot)
        for path in [fixtureRoot + "/.runtime", fixtureRoot + "/.runtime/keyonly", directory] { try PrivateInput.checkDirectory(path) }
        let state = try object(PrivateInput.read(fixtureRoot + "/.runtime/state.json", limit: 4096), keys: ["version", "project", "image"])
        guard state["version"] as? Int == 1, state["project"] as? String == Fixed.project,
              state["image"] as? String == Fixed.base else { throw GateError.provenance }
        let provenance = try PrivateInput.read(directory + "/provenance.json", limit: 4096)
        let time = try Self.provenance(provenance, now: now, fresh: fresh, minimumCollectedAt: BuildLocation.offlinePreparedAt)
        let known = try PrivateInput.read(directory + "/known_hosts", limit: 4096)
        let fingerprint = try PrivateInput.read(directory + "/fingerprint.txt", limit: 1024)
        let packages = try PrivateInput.read(directory + "/packages.txt", limit: 32768)
        guard !packages.isEmpty else { throw GateError.provenance }
        return Self(hostKeyLine: try hostKey(known: known, exported: fingerprint, expected: Fixed.fingerprint), collectedAt: time,
            provenanceSHA256: PrivateInput.sha256(provenance), knownHostsSHA256: PrivateInput.sha256(known),
            fingerprintSHA256: PrivateInput.sha256(fingerprint), packagesSHA256: PrivateInput.sha256(packages))
    }
    func matches(_ campaign: Campaign) throws {
        try require(collectedAt == campaign.collectedAt && provenanceSHA256 == campaign.provenanceSHA256 &&
            knownHostsSHA256 == campaign.knownHostsSHA256 && fingerprintSHA256 == campaign.fingerprintSHA256 &&
            packagesSHA256 == campaign.packagesSHA256, .provenance)
    }
}
func object(_ data: Data, keys: Set<String>) throws -> [String: Any] {
    guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(value.keys) == keys else { throw GateError.contract }
    return value
}

struct Payload: Codable, Equatable, Sendable {
    let path: String
    let bytes: UInt64
    let sha256: String
    var rawKey: String { raw(path).base64EncodedString() }
}
struct Corpus: Codable, Sendable {
    let format: Int
    let complete_ac31_size: Bool
    let large_bytes: UInt64
    let small_file_count: Int
    let files: [Payload]
    let symlinks: [String]
    static func parse(_ bytes: Data) throws -> Self {
        let value = try object(bytes, keys: ["format", "complete_ac31_size", "large_bytes", "small_file_count", "files", "symlinks"])
        guard let entries = value["files"] as? [[String: Any]], entries.count == 1002,
              entries.allSatisfy({ Set($0.keys) == Set(["path", "bytes", "sha256"]) }) else { throw GateError.corpus }
        let corpus = try JSONDecoder().decode(Self.self, from: bytes)
        let expected = Dictionary(uniqueKeysWithValues: Fixed.specifications.map { (raw($0.0).base64EncodedString(), $0.1) })
        guard corpus.format == 1, corpus.complete_ac31_size, corpus.large_bytes == Fixed.largeBytes, corpus.small_file_count == 1000,
              corpus.files.count == expected.count, Set(corpus.files.map(\.rawKey)).count == expected.count,
              corpus.files.allSatisfy({ expected[$0.rawKey] == $0.bytes && Contract.hex($0.sha256, count: 64) }),
              corpus.symlinks.map(raw) == Fixed.links.map(raw) else { throw GateError.corpus }
        return corpus
    }
    var sorted: [Payload] { files.sorted { $0.rawKey < $1.rawKey } }
    func compare(_ observed: [Payload]) throws {
        let expected = sorted, actual = observed.sorted { $0.rawKey < $1.rawKey }
        try require(expected.count == actual.count && zip(expected, actual).allSatisfy {
            raw($0.path) == raw($1.path) && $0.bytes == $1.bytes && $0.sha256 == $1.sha256
        }, .integrity)
    }
}
