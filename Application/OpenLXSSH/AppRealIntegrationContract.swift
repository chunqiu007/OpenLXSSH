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
    case readOnly = "read-only", transferSurvivesClose = "transfer-survives-close", windowContinueCancel = "window-continue-cancel"
    var isTransfer: Bool { self != .readOnly }
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
struct AppRealWindowTransferGate {
    static func sameIdentity(jobID: UUID, generation: UUID, sourceServiceID: UUID, destinationServiceID: UUID, host: String,
                             expected: [String]) -> Bool {
        expected == [jobID.uuidString, generation.uuidString, sourceServiceID.uuidString, destinationServiceID.uuidString, host]
    }
    static func cancelledAndDrained(state: String, managerClosed: Bool, activeWork: Bool, sshClosed: Bool, pidPresent: Bool, windowPresent: Bool, closedServices: Int, handles: Int) -> Bool {
        state == "cancelled" && managerClosed && !activeWork && sshClosed && !pidPresent && !windowPresent && closedServices == 1 && handles == 0
    }
}
struct AppRealWindowCheckpoint: Encodable, Sendable {
    let runID: String, event: String
    let jobID: UUID, generation: UUID, serviceID: UUID, hostID: UUID
    let serverBinding: String, sourceBytes: UInt64, progressBytes: UInt64
    let remoteRootBase64: String, payloadBase64: String, temporaryBase64: String
    let connectionAttempts: Int
    let retainedTemporaryPathsBase64: [String]
    let phase = AppRealIntegrationPhase.windowContinueCancel
}
enum AppRealTransferStage: String, Codable, Sendable {
    case source, mkdir, enterOwnedRoot, probePrepare, probeExecute, transferContext, uploadControl, observeJob
    case pendingDecision, firstJobIdentity, temporaryLedger, preCloseAction, preHideAction, awaitSSHClose
    case windowFirstClose, windowContinue, windowSecondClose, windowCancelClose, windowAwaitClosed, windowFinalCancelled
    case awaitTransfer, finalSucceeded, sameServiceContext, remoteDigest, remoteCleanup, localCleanup, complete
}
enum AppRealTransferGuard: String, Codable, Error, Sendable {
    case mkdirContext, mkdirLedger, emptyOwnedRoot, probeScope, probeResult, serviceBinding, noPreviousJobs
    case singleJob, pendingRiskMismatch, firstJobIdentity, temporaryCount, preCloseInflight, preCloseIdentity
    case sessionConnected, closeControl, preHideInflight, preHideIdentity, hideControl, finalJobIdentity
    case windowFirstInflight, windowContinueIdentity, windowContinueAdmission, windowSecondInflight, windowCancelIdentity, windowFinalCancelled, windowNotClosed, windowResources
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
