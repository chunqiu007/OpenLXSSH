import Darwin
import Foundation

/// This new consumer's independently reviewed binding, not a revision of any old case pin.
enum AppNativeFiniteIdentity {
    static let base = "docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d"
    static let image = "sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363"
    static let project = "openlxssh-fixture-61ed25328c13"
    static let container = "ed38148af68e2c6cdb70f18b9a716876754a393df2d530b168ddd2144d99021a"
    static let fingerprint = "SHA256:d2G+w7lBrjYDFHHd6c6GxIhk7qzFs6df1i7EVJfeUYs"
    static func validate(_ value: AppRealIntegrationContract, path: String, now: Double, buildEpoch: Double) throws {
        guard try AppRealIntegrationContract.validateContractPath(path) == value.runID,
              value.schema == 1, value.selectedPhase == .readOnly, value.host == "127.0.0.1", value.port == 22221,
              value.user == "fixture", value.service == "keyonly", value.expectedBase == base, value.expectedImage == image,
              value.expectedProject == project, value.expectedContainer == container, value.expectedFingerprint == fingerprint,
              [value.provenanceSHA256, value.knownHostsSHA256, value.generationPublicKeySHA256].allSatisfy({ AppRealIntegrationContract.hex($0, count: 64) }),
              value.collectedAt.isFinite, value.preparedAt.isFinite, now.isFinite, buildEpoch.isFinite, buildEpoch > 0,
              value.collectedAt >= buildEpoch, value.preparedAt >= value.collectedAt, now >= value.preparedAt,
              now - value.collectedAt <= 120 else { throw AppNativeFiniteFailure.staleMaterial }
        try AppRealIntegrationContract.pathSyntax(value.generation)
        let prefix = AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-"
        guard value.generation.hasPrefix(prefix), AppRealIntegrationContract.hex(String(value.generation.dropFirst(prefix.count)), count: 12) else {
            throw AppNativeFiniteFailure.contract
        }
    }
}

/// A separate, closed first-case entry. Shipping rejects it before AppKit or stores exist.
enum AppNativeFiniteArguments {
    enum Action: Equatable { case none, help, validate, live }
    struct Options: Equatable {
        let action: Action
        let contractPath: String?
    }
    static let help = """
    HostProbe-only App Native keyonly-controller-shell. No GUI acceptance or default backend change.
    --native-app-fixture-help
    --native-app-fixture-validate --native-app-fixture-contract <absolute/native-app-fixture.json>
      Syntax only: no files, credentials, AppKit, stores or network.
    --native-app-fixture-test --native-app-fixture-contract <exact owned path> --authorized-local-fixture --primary-released
      Requires separately reviewed existing local fixture/material; flags are not authorization.
    """
    static func parse(_ arguments: [String], hostProbe: Bool) throws -> Options {
        guard arguments.contains(where: { $0.hasPrefix("--native-app-fixture") }) else {
            return Options(action: .none, contractPath: nil)
        }
        guard hostProbe else { throw AppNativeFiniteFailure.arguments }
        if arguments == ["--native-app-fixture-help"] { return Options(action: .help, contractPath: nil) }
        guard let first = arguments.first, ["--native-app-fixture-test", "--native-app-fixture-validate"].contains(first) else {
            throw AppNativeFiniteFailure.arguments
        }
        var path: String?, authorized = false, released = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--native-app-fixture-contract":
                guard path == nil, index + 1 < arguments.count else { throw AppNativeFiniteFailure.arguments }
                index += 1; path = arguments[index]
                _ = try AppNativeFiniteContract.runID(at: arguments[index])
            case "--authorized-local-fixture":
                guard !authorized else { throw AppNativeFiniteFailure.arguments }; authorized = true
            case "--primary-released":
                guard !released else { throw AppNativeFiniteFailure.arguments }; released = true
            default: throw AppNativeFiniteFailure.arguments // Includes every old real/self-test flag.
            }
            index += 1
        }
        guard let path else { throw AppNativeFiniteFailure.arguments }
        if first == "--native-app-fixture-validate" {
            guard !authorized, !released else { throw AppNativeFiniteFailure.arguments }
            return Options(action: .validate, contractPath: path)
        }
        guard authorized, released else { throw AppNativeFiniteFailure.authorization }
        return Options(action: .live, contractPath: path)
    }
}

enum AppNativeFiniteFailure: String, Error, Codable {
    case arguments, authorization, contract, unsafeInput, staleMaterial, preparationDeadline, activeDeadline, fullDeadline
    case importFailed, hostSaveFailed, unexpectedSession, unexpectedAuthentication, trustMismatch, typedStages
    case terminalBudget, terminalEvidence, remoteExit, closeRetired, closeIncomplete, drainIncomplete, resources
    case sourceChanged, cleanup, beforeStoresClose, storesClose, afterStoresClose, quitOrder, reportWrite, cancelled, operation
}

/// No endpoint, command, backend, secret override, arbitrary generation or pin is accepted here.
struct AppNativeFiniteContract: Equatable, Sendable {
    static let inputRoot = "/Users/liuwenshuo/Desktop/OpenLXSSH/DerivedData/AppNativeFinite/Inputs"
    static let scenarioName = "keyonly-controller-shell"
    static let markerName = ".openlxssh-native-app-finite"
    static let marker = "OpenLXSSH Native App finite v1\n"
    static let maximumBytes = 4096
    let schema: Int
    let runID: String
    let scenario: String
    let materialContractPath: String

    static func canonicalID(_ value: String) -> Bool {
        guard let id = UUID(uuidString: value) else { return false }
        return id.uuidString.lowercased() == value
    }
    static func runID(at path: String) throws -> String {
        try AppRealIntegrationContract.pathSyntax(path)
        let prefix = inputRoot + "/run-", suffix = "/native-app-fixture.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw AppNativeFiniteFailure.contract }
        let id = String(path.dropFirst(prefix.count).dropLast(suffix.count))
        guard canonicalID(id), path == prefix + id + suffix else { throw AppNativeFiniteFailure.contract }
        return id
    }
    func validate(path: String) throws {
        guard schema == 1, scenario == Self.scenarioName, try Self.runID(at: path) == runID,
              try AppRealIntegrationContract.validateContractPath(materialContractPath) == runID else {
            throw AppNativeFiniteFailure.contract
        }
    }
    func requireMaterial(_ material: AppRealIntegrationContract) throws {
        guard material.runID == runID, material.selectedPhase == .readOnly else { throw AppNativeFiniteFailure.contract }
    }
    /// Closed ASCII JSON subset, NOT a general JSON parser: quoted/backslash/Unicode escapes
    /// and non-ASCII strings are intentionally refused. Escaped slash alone is permitted.
    /// Rejects duplicate keys, booleans/numeric coercion, unknown keys and oversized input.
    static func decodeStrict(_ bytes: Data) throws -> Self {
        guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw AppNativeFiniteFailure.contract }
        var cursor = Cursor(bytes: Array(bytes)), fields: [String: String] = [:]
        try cursor.punctuation(123)
        for ordinal in 0..<4 {
            if ordinal > 0 { try cursor.punctuation(44) }
            let key = try cursor.string()
            guard ["schema", "runID", "scenario", "materialContractPath"].contains(key), fields[key] == nil else {
                throw AppNativeFiniteFailure.contract
            }
            try cursor.punctuation(58)
            if key == "schema" { try cursor.punctuation(49); fields[key] = "1" }
            else { fields[key] = try cursor.string() }
        }
        try cursor.punctuation(125); cursor.whitespace()
        guard cursor.index == cursor.bytes.count, fields.count == 4, let id = fields["runID"],
              let scenario = fields["scenario"], let material = fields["materialContractPath"] else { throw AppNativeFiniteFailure.contract }
        return Self(schema: 1, runID: id, scenario: scenario, materialContractPath: material)
    }
    private struct Cursor {
        let bytes: [UInt8]
        var index = 0
        mutating func whitespace() { while index < bytes.count, [9, 10, 13, 32].contains(bytes[index]) { index += 1 } }
        mutating func punctuation(_ value: UInt8) throws {
            whitespace(); guard index < bytes.count, bytes[index] == value else { throw AppNativeFiniteFailure.contract }; index += 1
        }
        mutating func string() throws -> String {
            try punctuation(34); var value: [UInt8] = []
            while index < bytes.count {
                let byte = bytes[index]; index += 1
                if byte == 34 { return String(decoding: value, as: UTF8.self) }
                if byte == 92 {
                    guard index < bytes.count, bytes[index] == 47 else { throw AppNativeFiniteFailure.contract }
                    value.append(47); index += 1
                } else {
                    guard (32...126).contains(byte) else { throw AppNativeFiniteFailure.contract }; value.append(byte)
                }
            }
            throw AppNativeFiniteFailure.contract
        }
    }
}

/// All elapsed budgets use this one monotonic epoch. No fixture wall-clock expiry is extended.
struct AppNativeFiniteBudget: Sendable {
    static let preparationSeconds = 30, activeSeconds = 45, fullSeconds = 90, cleanupSeconds = 12
    let started: ContinuousClock.Instant
    init(started: ContinuousClock.Instant = .now) { self.started = started }
    var preparationDeadline: ContinuousClock.Instant { started + .seconds(Self.preparationSeconds) }
    var fullDeadline: ContinuousClock.Instant { started + .seconds(Self.fullSeconds) }
    func activeDeadline(start: ContinuousClock.Instant) -> ContinuousClock.Instant {
        min(start + .seconds(Self.activeSeconds), fullDeadline - .seconds(Self.cleanupSeconds))
    }
    func cleanupDeadline(start: ContinuousClock.Instant) -> ContinuousClock.Instant {
        min(start + .seconds(Self.cleanupSeconds), fullDeadline)
    }
    func elapsed(at now: ContinuousClock.Instant = .now) -> Double {
        let value = started.duration(to: now).components
        return Double(value.seconds) + Double(value.attoseconds) / 1e18
    }
}

struct AppNativeFiniteTerminalPlan: Sendable {
    static let maximumOutputBytes = 32 * 1024
    let nonce: String
    init(nonce: String) throws {
        guard AppRealIntegrationContract.hex(nonce, count: 32) else { throw AppNativeFiniteFailure.contract }; self.nonce = nonce
    }
    var command: String {
        "n='" + nonce + "'; printf '\\nAPP_ACK_%s\\n' \"$n\"; " +
        "if test -t 0; then printf 'APP_PTY_%s\\n' \"$n\"; fi; " +
        "printf 'APP_SIZE_%s ' \"$n\"; stty size; printf 'APP_DONE_%s\\n' \"$n\"\n"
    }
    struct Evidence: Equatable, Codable, Sendable {
        let ack: Bool, pty: Bool, resized113x37: Bool, completed: Bool
        let observedRows: Int?, observedColumns: Int?
        var complete: Bool { ack && pty && resized113x37 && completed }
    }
    func inspect(_ terminal: String) throws -> Evidence {
        guard terminal.utf8.count <= Self.maximumOutputBytes else { throw AppNativeFiniteFailure.terminalBudget }
        let lines = terminal.replacingOccurrences(of: "\r", with: "").split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        func count(_ marker: String) -> Int { lines.filter { $0 == marker }.count }
        let ack = count("APP_ACK_" + nonce), pty = count("APP_PTY_" + nonce), done = count("APP_DONE_" + nonce)
        let sizes = lines.filter { $0.hasPrefix("APP_SIZE_" + nonce + " ") }.map { $0.split(whereSeparator: \.isWhitespace).map(String.init) }
        guard ack <= 1, pty <= 1, done <= 1, sizes.count <= 1 else { throw AppNativeFiniteFailure.terminalEvidence }
        var observedRows: Int?, observedColumns: Int?
        if let size = sizes.first, size.count == 3 {
            func cellCount(_ value: String) -> Int? {
                guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
                      let count = Int(value), (1...65535).contains(count) else { return nil }
                return count
            }
            if let rows = cellCount(size[1]), let columns = cellCount(size[2]) {
                observedRows = rows; observedColumns = columns
            }
        }
        return Evidence(ack: ack == 1, pty: pty == 1, resized113x37: sizes == [["APP_SIZE_" + nonce, "37", "113"]], completed: done == 1,
                        observedRows: observedRows, observedColumns: observedColumns)
    }
}

/// Fixed observation vocabulary; stages do not infer that any awaited operation succeeded.
enum AppNativeFiniteActiveStage: String, Codable, CaseIterable, Sendable {
    case preparingHost, awaitingDriver, awaitingTrust, awaitingConnected, awaitingResize, awaitingTerminalEvidence, awaitingExit, closingTab
}
struct AppNativeFiniteInputQueueSnapshot: Codable, Equatable, Sendable {
    let pendingBytes: Int, pendingItems: Int
}
/// Only requested cells and existing public Driver/terminal observations; no second reader.
struct AppNativeFiniteActiveSnapshot: Codable, Equatable, Sendable {
    let activeStage: AppNativeFiniteActiveStage
    let terminalEvidence: AppNativeFiniteTerminalPlan.Evidence?
    let requestedRows: Int?, requestedColumns: Int?
    let driverHasLatestResize: Bool?, driverResizeInFlight: Bool?
    let terminalRows: Int?, terminalColumns: Int?
    let inputBeforeAdmission: AppNativeFiniteInputQueueSnapshot?, inputAfterAdmission: AppNativeFiniteInputQueueSnapshot?
}

/// Closed report vocabulary only. These values do not assert that a resource was released.
enum AppNativeFiniteCleanupStage: String, Codable, CaseIterable, Sendable {
    case exerciseRunning, exerciseReturned, closingTabs, weakWait, descriptorWait, sourceCheck, metadataDelete, ready, quit
}

/// Value-only diagnostics. No task, tab, driver, view, session text or object description escapes.
struct AppNativeFiniteCleanupSnapshot: Codable, Equatable, Sendable {
    let cleanupStage: AppNativeFiniteCleanupStage
    let weakTabAlive: Bool, weakDriverAlive: Bool, weakViewAlive: Bool
    let terminalHasSuperview: Bool, terminalHasWindow: Bool
    let currentSessionTabCount: Int, workspaceIsVault: Bool
    let descriptorObserved: Bool, knownHostsCheckPerformed: Bool
    let active: AppNativeFiniteActiveSnapshot
}

/// FD labels describe only an anchored pathname shape, never ownership or a pass exemption.
enum AppNativeFiniteDescriptorRole: String, Codable, CaseIterable, Sendable {
    case unknown, systemTZShape, systemICUShape, systemLocaleShape, systemFontShape
    static func classify(path: String?, mode: UInt32, uid: UInt32, access: Int32) -> Self {
        guard uid == 0, mode & UInt32(S_IFMT) == UInt32(S_IFREG), access == O_RDONLY,
              let path, path.utf8.count < 1024, path.hasPrefix("/"),
              path.utf8.allSatisfy({ (45...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 95 || $0 == 64 }),
              path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { return .unknown }
        guard !path.lowercased().contains("keychain"), !path.split(separator: "/").contains(where: { $0.lowercased() == "security" }) else { return .unknown }
        if path.hasPrefix("/usr/share/zoneinfo/") { return .systemTZShape }
        if path.hasPrefix("/usr/share/icu/") {
            let leaf = path.dropFirst("/usr/share/icu/".count)
            if leaf.hasPrefix("icudt"), leaf.hasSuffix("l.dat") || leaf.hasSuffix("b.dat") {
                let version = leaf.dropFirst(5).dropLast(5)
                if !version.isEmpty, version.utf8.allSatisfy({ (48...57).contains($0) }) { return .systemICUShape }
            }
        }
        if path.hasPrefix("/usr/share/locale/") {
            let parts = path.dropFirst("/usr/share/locale/".count).split(separator: "/")
            if parts.count == 2, ["LC_CTYPE", "LC_COLLATE", "LC_TIME", "LC_NUMERIC", "LC_MONETARY", "LC_MESSAGES", "LC_ALL"].contains(String(parts[1])) { return .systemLocaleShape }
        }
        for root in ["/System/Library/Fonts/", "/usr/share/fonts/", "/usr/share/system/fonts/"] where path.hasPrefix(root) {
            if [".ttf", ".ttc", ".otf", ".dfont"].contains(where: path.hasSuffix) { return .systemFontShape }
        }
        return .unknown
    }
}
enum AppNativeFiniteDescriptorProbeStatus: String, Codable, CaseIterable, Sendable { case stable, unavailable, changed }
/// Transient fstat/F_GETFL values. UID/full permissions are compared but never serialized.
struct AppNativeFiniteDescriptorValue: Equatable {
    let mode: UInt32, uid: UInt32, dev: Int32, ino: UInt64, access: Int32
}
struct AppNativeFiniteDescriptorEntry: Codable, Equatable, Sendable {
    let fd: Int32, type: UInt32?, dev: Int32?, ino: UInt64?, access: Int32?
    let probeStatus: AppNativeFiniteDescriptorProbeStatus, role: AppNativeFiniteDescriptorRole
    static func observed(fd: Int32, first: AppNativeFiniteDescriptorValue?, second: AppNativeFiniteDescriptorValue?, path: String?) -> Self {
        guard let first, let second else { return .init(fd: fd, type: nil, dev: nil, ino: nil, access: nil, probeStatus: .unavailable, role: .unknown) }
        guard first == second else { return .init(fd: fd, type: nil, dev: nil, ino: nil, access: nil, probeStatus: .changed, role: .unknown) }
        return .init(fd: fd, type: first.mode & UInt32(S_IFMT), dev: first.dev, ino: first.ino, access: first.access,
            probeStatus: .stable, role: .classify(path: path, mode: first.mode, uid: first.uid, access: first.access))
    }
}
struct AppNativeFiniteDescriptorSnapshot: Codable, Equatable, Sendable {
    let elapsedSeconds: Double, scanUpperExclusive: Int32, count: Int
    let truncated: Bool, complete: Bool
    let entries: [AppNativeFiniteDescriptorEntry]
    init(elapsedSeconds: Double, scanUpperExclusive: Int32, count: Int, entries: [AppNativeFiniteDescriptorEntry]) {
        self.elapsedSeconds = elapsedSeconds; self.scanUpperExclusive = scanUpperExclusive; self.count = count
        self.entries = Array(entries.prefix(AppNativeFiniteDescriptorSnapshots.entryLimit))
        truncated = count > self.entries.count
        complete = !truncated && self.entries.allSatisfy { $0.probeStatus == .stable }
    }
}
/// Three bounded value copies only. No second scan, object, raw path, path hash or continuity claim.
struct AppNativeFiniteDescriptorSnapshots: Codable, Equatable, Sendable {
    static let entryLimit = 32
    let schema: Int, maximumEntries: Int, atomic: Bool, continuousOpenProven: Bool
    var baseline: AppNativeFiniteDescriptorSnapshot?, cleanupFirst: AppNativeFiniteDescriptorSnapshot?, cleanupLatest: AppNativeFiniteDescriptorSnapshot?
    init() { schema = 1; maximumEntries = Self.entryLimit; atomic = false; continuousOpenProven = false }
    func validate() throws {
        guard schema == 1, maximumEntries == Self.entryLimit, !atomic, !continuousOpenProven,
              (cleanupFirst == nil) == (cleanupLatest == nil), cleanupFirst == nil || baseline != nil else { throw AppNativeFiniteFailure.contract }
        var previous = 0.0
        for snapshot in [baseline, cleanupFirst, cleanupLatest].compactMap({ $0 }) {
            guard snapshot.elapsedSeconds.isFinite, snapshot.elapsedSeconds >= previous,
                  snapshot.scanUpperExclusive > 0, snapshot.scanUpperExclusive <= 1_048_576,
                  snapshot.count >= 0, snapshot.count <= Int(snapshot.scanUpperExclusive),
                  snapshot.entries.count == min(snapshot.count, maximumEntries), snapshot.truncated == (snapshot.count > maximumEntries),
                  snapshot.complete == (!snapshot.truncated && snapshot.entries.allSatisfy { $0.probeStatus == .stable }) else { throw AppNativeFiniteFailure.contract }
            var last: Int32 = -1
            for row in snapshot.entries {
                guard row.fd > last, row.fd < snapshot.scanUpperExclusive else { throw AppNativeFiniteFailure.contract }; last = row.fd
                if row.probeStatus == .stable {
                    guard let type = row.type, type <= UInt32(S_IFMT), type & ~UInt32(S_IFMT) == 0,
                          row.dev != nil, row.ino != nil, let access = row.access, [O_RDONLY, O_WRONLY, O_RDWR].contains(access),
                          row.role == .unknown || (type == UInt32(S_IFREG) && access == O_RDONLY) else { throw AppNativeFiniteFailure.contract }
                } else if row.type != nil || row.dev != nil || row.ino != nil || row.access != nil || row.role != .unknown { throw AppNativeFiniteFailure.contract }
            }
            previous = snapshot.elapsedSeconds
        }
    }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let required: Set<String> = ["schema", "maximumEntries", "atomic", "continuousOpenProven"]
        let phases: Set<String> = ["baseline", "cleanupFirst", "cleanupLatest"]
        guard !bytes.isEmpty, bytes.count <= 14 * 1024,
              let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any], required.isSubset(of: Set(object.keys)),
              Set(object.keys).isSubset(of: required.union(phases)) else { throw AppNativeFiniteFailure.contract }
        for phase in phases where object[phase] != nil {
            guard let snapshot = object[phase] as? [String: Any], Set(snapshot.keys) == ["elapsedSeconds", "scanUpperExclusive", "count", "truncated", "complete", "entries"],
                  let entries = snapshot["entries"] as? [[String: Any]], entries.count <= entryLimit else { throw AppNativeFiniteFailure.contract }
            for row in entries {
                let keys = Set(row.keys), required: Set<String> = ["fd", "probeStatus", "role"]
                let expected = row["probeStatus"] as? String == "stable" ? required.union(["type", "dev", "ino", "access"]) : required
                guard keys == expected else { throw AppNativeFiniteFailure.contract }
            }
        }
        let value = try JSONDecoder().decode(Self.self, from: bytes); try value.validate(); return value
    }
}

/// A one-time point, NOT a lease on object lifetime. An external observer must revalidate
/// this exact run/process identity, no failure receipt and the original remaining cleanup
/// window; freed/reused addresses or an empty trace are unknown, never an ownership proof.
struct AppNativeFiniteWeakPoint: Codable, Equatable, Sendable {
    static let leaf = "native-weak-point.json"
    static let maximumBytes = 2048
    let schema: Int
    let runID: String, pid: Int32, cleanupStage: AppNativeFiniteCleanupStage
    let tabAddress: String, driverAddress: String, viewAddress: String
    let elapsedSeconds: Double, weakWaitRemainingSeconds: Double

    init(runID: String, pid: Int32, tabAddress: UInt, driverAddress: UInt, viewAddress: UInt,
         elapsedSeconds: Double, weakWaitRemainingSeconds: Double) throws {
        schema = 1; self.runID = runID; self.pid = pid; cleanupStage = .weakWait
        self.tabAddress = Self.address(tabAddress); self.driverAddress = Self.address(driverAddress); self.viewAddress = Self.address(viewAddress)
        self.elapsedSeconds = elapsedSeconds; self.weakWaitRemainingSeconds = weakWaitRemainingSeconds
        try validate()
    }
    static func address(_ value: UInt) -> String { "0x" + String(value, radix: 16) }
    private func validate() throws {
        func validAddress(_ value: String) -> Bool {
            guard value.hasPrefix("0x"), let raw = UInt(value.dropFirst(2), radix: 16), raw != 0 else { return false }
            return Self.address(raw) == value
        }
        guard schema == 1, AppNativeFiniteContract.canonicalID(runID), pid > 0, cleanupStage == .weakWait,
              [tabAddress, driverAddress, viewAddress].allSatisfy(validAddress),
              elapsedSeconds.isFinite, (0...Double(AppNativeFiniteBudget.fullSeconds)).contains(elapsedSeconds),
              weakWaitRemainingSeconds.isFinite, weakWaitRemainingSeconds > 0,
              weakWaitRemainingSeconds <= Double(AppNativeFiniteBudget.cleanupSeconds) else { throw AppNativeFiniteFailure.contract }
    }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let keys: Set<String> = ["schema", "runID", "pid", "cleanupStage", "tabAddress", "driverAddress", "viewAddress", "elapsedSeconds", "weakWaitRemainingSeconds"]
        guard !bytes.isEmpty, bytes.count <= maximumBytes,
              let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any], Set(object.keys) == keys else {
            throw AppNativeFiniteFailure.contract
        }
        let value = try JSONDecoder().decode(Self.self, from: bytes)
        try value.validate(); return value
    }
}

/// Audit only: it cannot initiate, approve or bypass production termination.
struct AppNativeFiniteQuitAudit: Equatable, Codable {
    private(set) var scheduled = false, dispatched = false, beforeStores = false, afterStores = false, willTerminate = false
    mutating func schedule() throws { guard !scheduled else { throw AppNativeFiniteFailure.quitOrder }; scheduled = true }
    mutating func dispatch() throws { guard scheduled, !dispatched else { throw AppNativeFiniteFailure.quitOrder }; dispatched = true }
    mutating func before() throws { guard dispatched, !beforeStores, !afterStores else { throw AppNativeFiniteFailure.quitOrder }; beforeStores = true }
    mutating func after() throws { guard beforeStores, !afterStores else { throw AppNativeFiniteFailure.quitOrder }; afterStores = true }
    mutating func terminating() throws { guard afterStores, !willTerminate else { throw AppNativeFiniteFailure.quitOrder }; willTerminate = true }
    var complete: Bool { scheduled && dispatched && beforeStores && afterStores && willTerminate }
}

#if HOST_PROBE
import OpenLXSSHFiles

struct AppNativeFiniteAuthentication: Encodable, Sendable {
    let primaryMethod = "publicKey"
    let primaryStarted: Int, primaryResults: Int, primaryCode: Int32
    let primaryAuthenticated: Bool, authenticatedEvents: Int, shellReadyEvents: Int
    init(_ stages: [NativeShellAuthenticationStage]) throws {
        guard stages.count == 5, case .advertised(_, let key, _) = stages[0], key,
              stages[1] == .primaryStarted(.publicKey), stages[2] == .primaryResult(.publicKey, code: 0, authenticated: true),
              stages[3] == .authenticated, stages[4] == .shellReady else { throw AppNativeFiniteFailure.typedStages }
        primaryStarted = 1; primaryResults = 1; primaryCode = 0; primaryAuthenticated = true
        authenticatedEvents = 1; shellReadyEvents = 1
    }
}
#endif

#if HOST_PROBE
import AppKit

/// HOST_PROBE consumer coordination only; production resize and its relay stay unchanged.
@MainActor enum AppNativeFiniteRendererGeometry {
    static func prepare(_ native: NativeSessionDriver, ownedWindow: NSWindow?,
                        checkpoint: @MainActor () throws -> Void,
                        send: @MainActor () throws -> Void) async throws {
        let terminal = native.terminal
        guard let ownedWindow, let content = ownedWindow.contentView else { throw AppNativeFiniteFailure.terminalEvidence }
        let minimum = ownedWindow.minSize, contentMinimum = ownedWindow.contentMinSize
        let maximum = ownedWindow.maxSize, contentMaximum = ownedWindow.contentMaxSize
        var adjustments = 0, stableRounds = 0
        var stableSince: ContinuousClock.Instant?, stableFrame: NSRect?, stableTerminalFrame: NSRect?
        while true {
            try checkpoint()
            guard native.state == .connected, terminal.window === ownedWindow,
                  ownedWindow.contentView === content, terminal.isDescendant(of: content),
                  ownedWindow.minSize == minimum, ownedWindow.contentMinSize == contentMinimum,
                  ownedWindow.maxSize == maximum, ownedWindow.contentMaxSize == contentMaximum,
                  ownedWindow.attachedSheet == nil, !ownedWindow.inLiveResize,
                  !ownedWindow.styleMask.contains(.fullScreen), let screen = ownedWindow.screen else {
                throw AppNativeFiniteFailure.terminalEvidence
            }
            content.layoutSubtreeIfNeeded()
            let visible = screen.visibleFrame
            let snapshot = native.snapshot
            if terminal.columns == 113, terminal.rows == 37, !snapshot.resizeInFlight, !snapshot.hasLatestResize {
                guard visible.contains(ownedWindow.frame), ownedWindow.frame.width >= minimum.width,
                      ownedWindow.frame.height >= minimum.height else { throw AppNativeFiniteFailure.terminalEvidence }
                if stableFrame != ownedWindow.frame || stableTerminalFrame != terminal.frame {
                    stableSince = .now; stableRounds = 0
                    stableFrame = ownedWindow.frame; stableTerminalFrame = terminal.frame
                }
                stableRounds += 1
                if let since = stableSince, stableRounds >= 2, since.duration(to: .now) >= .milliseconds(100) {
                    // The final checkpoint may itself service layout in a logical test. Revalidate
                    // afterward and call the original terminal.send closure without another await.
                    try checkpoint()
                    guard terminal.window === ownedWindow, ownedWindow.contentView === content,
                          terminal.isDescendant(of: content), native.state == .connected,
                          terminal.columns == 113, terminal.rows == 37,
                          !native.snapshot.resizeInFlight, !native.snapshot.hasLatestResize,
                          ownedWindow.minSize == minimum, ownedWindow.contentMinSize == contentMinimum,
                          ownedWindow.maxSize == maximum, ownedWindow.contentMaxSize == contentMaximum,
                          ownedWindow.attachedSheet == nil, !ownedWindow.inLiveResize,
                          !ownedWindow.styleMask.contains(.fullScreen),
                          ownedWindow.screen?.visibleFrame.contains(ownedWindow.frame) == true,
                          ownedWindow.frame == stableFrame, terminal.frame == stableTerminalFrame else {
                        stableSince = nil; stableRounds = 0; stableFrame = nil; stableTerminalFrame = nil
                        try await Task.sleep(for: .milliseconds(10))
                        continue
                    }
                    try send()
                    return
                }
            } else {
                stableSince = nil; stableRounds = 0; stableFrame = nil; stableTerminalFrame = nil
                if terminal.columns != 113 || terminal.rows != 37 {
                    guard adjustments < 8, terminal.columns > 0, terminal.rows > 0 else { throw AppNativeFiniteFailure.terminalEvidence }
                    let cell = terminal.caretFrame.size, optimal = terminal.getOptimalFrameSize().size
                    let reservedWidth = optimal.width - cell.width * CGFloat(terminal.columns)
                    guard cell.width.isFinite, cell.height.isFinite, cell.width > 0, cell.height > 0,
                          reservedWidth.isFinite, reservedWidth >= 0, reservedWidth <= 100 else {
                        throw AppNativeFiniteFailure.terminalEvidence
                    }
                    // Aim inside the cell interval, not at a floating-point floor boundary.
                    let terminalTarget = NSSize(width: reservedWidth + cell.width * 113.5, height: cell.height * 37.5)
                    let contentTarget = NSSize(width: content.frame.width + terminalTarget.width - terminal.frame.width,
                                               height: content.frame.height + terminalTarget.height - terminal.frame.height)
                    let targetFrame = ownedWindow.frameRect(forContentRect: NSRect(origin: .zero, size: contentTarget)).size
                    guard contentTarget.width.isFinite, contentTarget.height.isFinite,
                          contentTarget.width >= contentMinimum.width, contentTarget.height >= contentMinimum.height,
                          contentTarget.width <= contentMaximum.width, contentTarget.height <= contentMaximum.height,
                          targetFrame.width >= minimum.width, targetFrame.height >= minimum.height,
                          targetFrame.width <= maximum.width, targetFrame.height <= maximum.height,
                          targetFrame.width <= visible.width, targetFrame.height <= visible.height else {
                        throw AppNativeFiniteFailure.terminalEvidence
                    }
                    adjustments += 1
                    ownedWindow.setContentSize(contentTarget)
                    // setContentSize preserves the top edge. Keep this exact owned window within
                    // its current screen without changing its constraints or touching another UI.
                    let frame = ownedWindow.frame
                    let origin = NSPoint(x: min(max(frame.minX, visible.minX), visible.maxX - frame.width),
                                         y: min(max(frame.minY, visible.minY), visible.maxY - frame.height))
                    if frame.origin != origin { ownedWindow.setFrameOrigin(origin) }
                    content.layoutSubtreeIfNeeded()
                }
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}
#endif

// Password M1 is an independent, closed binding. Everything above remains byte-for-byte
// the original keyonly contract; neither its parser nor its historical pin is reused here.
enum AppNativePasswordArguments {
    enum Action: Equatable { case none, help, validate, live }
    struct Options: Equatable { let action: Action; let contractPath: String? }
    static let help = """
    HostProbe-only App Native passwordonly-transient-controller-shell. No GUI/default-switch acceptance.
    --native-password-fixture-help
    --native-password-fixture-validate --native-password-fixture-contract <exact/native-password-fixture.json>
      Syntax only; no file, credential, process, AppKit or network access.
    --native-password-fixture-test --native-password-fixture-contract <exact owned path> --authorized-local-fixture --primary-released
      Existing local-fixture authorization and separate primary review are required; flags grant neither.
    """
    static func parse(_ arguments: [String], hostProbe: Bool) throws -> Options {
        guard arguments.contains(where: { $0.hasPrefix("--native-password-fixture") }) else {
            return Options(action: .none, contractPath: nil)
        }
        guard hostProbe else { throw AppNativeFiniteFailure.arguments }
        if arguments == ["--native-password-fixture-help"] { return Options(action: .help, contractPath: nil) }
        guard let first = arguments.first,
              ["--native-password-fixture-test", "--native-password-fixture-validate"].contains(first) else {
            throw AppNativeFiniteFailure.arguments
        }
        var path: String?, authorized = false, released = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--native-password-fixture-contract":
                guard path == nil, index + 1 < arguments.count else { throw AppNativeFiniteFailure.arguments }
                index += 1; path = arguments[index]
                _ = try AppNativePasswordContract.runID(at: arguments[index])
            case "--authorized-local-fixture":
                guard !authorized else { throw AppNativeFiniteFailure.arguments }; authorized = true
            case "--primary-released":
                guard !released else { throw AppNativeFiniteFailure.arguments }; released = true
            default: throw AppNativeFiniteFailure.arguments
            }
            index += 1
        }
        guard let path else { throw AppNativeFiniteFailure.arguments }
        if first == "--native-password-fixture-validate" {
            guard !authorized, !released else { throw AppNativeFiniteFailure.arguments }
            return Options(action: .validate, contractPath: path)
        }
        guard authorized, released else { throw AppNativeFiniteFailure.authorization }
        return Options(action: .live, contractPath: path)
    }
}

enum AppNativeFiniteScenario: String, Codable, Sendable {
    case keyonly = "keyonly-controller-shell"
    case password = "passwordonly-transient-controller-shell"
}
enum AppNativeFiniteSourceKeyScope: String, Codable, Sendable { case notApplicablePassword }

/// Only flat ASCII string/JSON-number objects, for the two new password schemas below.
/// No escapes except slash, duplicate keys, coercion, nested objects, arrays, bools or null.
private enum AppNativePasswordJSON {
    enum Value { case string(String), number(String) }
    static func object(_ data: Data, keys: Set<String>, limit: Int) throws -> [String: Value] {
        guard !data.isEmpty, data.count <= limit else { throw AppNativeFiniteFailure.contract }
        var cursor = Cursor(bytes: Array(data)), result: [String: Value] = [:]
        try cursor.punctuation(123)
        for ordinal in 0..<keys.count {
            if ordinal > 0 { try cursor.punctuation(44) }
            let key = try cursor.string()
            guard keys.contains(key), !result.keys.contains(key) else { throw AppNativeFiniteFailure.contract }
            try cursor.punctuation(58); cursor.whitespace()
            if cursor.peek == 34 { result[key] = .string(try cursor.string()) }
            else { result[key] = .number(try cursor.number()) }
        }
        try cursor.punctuation(125); cursor.whitespace()
        guard cursor.index == cursor.bytes.count, result.count == keys.count else { throw AppNativeFiniteFailure.contract }
        return result
    }
    static func string(_ object: [String: Value], _ key: String) throws -> String {
        guard let item = object[key], case .string(let value) = item else { throw AppNativeFiniteFailure.contract }; return value
    }
    static func integer(_ object: [String: Value], _ key: String) throws -> Int {
        guard let item = object[key], case .number(let text) = item, let value = Int(text), String(value) == text else {
            throw AppNativeFiniteFailure.contract
        }
        return value
    }
    static func number(_ object: [String: Value], _ key: String) throws -> Double {
        guard let item = object[key], case .number(let text) = item, let value = Double(text), value.isFinite else {
            throw AppNativeFiniteFailure.contract
        }
        return value
    }
    private struct Cursor {
        let bytes: [UInt8]
        var index = 0
        var peek: UInt8? { index < bytes.count ? bytes[index] : nil }
        mutating func whitespace() { while let byte = peek, [9, 10, 13, 32].contains(byte) { index += 1 } }
        mutating func punctuation(_ byte: UInt8) throws {
            whitespace(); guard peek == byte else { throw AppNativeFiniteFailure.contract }; index += 1
        }
        mutating func string() throws -> String {
            try punctuation(34); var value: [UInt8] = []
            while let byte = peek {
                index += 1
                if byte == 34 { return String(decoding: value, as: UTF8.self) }
                if byte == 92 {
                    guard peek == 47 else { throw AppNativeFiniteFailure.contract }; index += 1; value.append(47)
                } else {
                    guard (32...126).contains(byte) else { throw AppNativeFiniteFailure.contract }; value.append(byte)
                }
            }
            throw AppNativeFiniteFailure.contract
        }
        mutating func digits() throws {
            let start = index
            while let byte = peek, (48...57).contains(byte) { index += 1 }
            guard index > start else { throw AppNativeFiniteFailure.contract }
        }
        mutating func number() throws -> String {
            let start = index
            if peek == 45 { index += 1 }
            if peek == 48 { index += 1 } else { try digits() }
            if peek == 46 { index += 1; try digits() }
            if peek == 69 || peek == 101 {
                index += 1
                if peek == 43 || peek == 45 { index += 1 }
                try digits()
            }
            guard index > start, index - start <= 64 else { throw AppNativeFiniteFailure.contract }
            return String(decoding: bytes[start..<index], as: UTF8.self)
        }
    }
}

struct AppNativePasswordContract: Equatable, Sendable {
    static let inputRoot = AppNativeFiniteContract.inputRoot
    static let scenarioName = AppNativeFiniteScenario.password.rawValue
    static let leaf = "native-password-fixture.json", materialLeaf = "native-password-material.json"
    static let maximumBytes = 4096
    let schema: Int
    let runID: String, scenario: String, materialContractPath: String
    static func runID(at path: String) throws -> String { try id(at: path, leaf: leaf) }
    static func id(at path: String, leaf: String) throws -> String {
        guard leaf == Self.leaf || leaf == Self.materialLeaf else { throw AppNativeFiniteFailure.contract }
        try AppRealIntegrationContract.pathSyntax(path)
        let prefix = inputRoot + "/run-", suffix = "/" + leaf
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw AppNativeFiniteFailure.contract }
        let value = String(path.dropFirst(prefix.count).dropLast(suffix.count))
        guard let id = UUID(uuidString: value), id.uuidString.lowercased() == value,
              path == prefix + value + suffix else { throw AppNativeFiniteFailure.contract }
        return value
    }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["schema", "runID", "scenario", "materialContractPath"], limit: maximumBytes)
        let schema = try AppNativePasswordJSON.integer(value, "schema")
        guard schema == 1 else { throw AppNativeFiniteFailure.contract }
        return Self(schema: schema, runID: try AppNativePasswordJSON.string(value, "runID"),
                    scenario: try AppNativePasswordJSON.string(value, "scenario"),
                    materialContractPath: try AppNativePasswordJSON.string(value, "materialContractPath"))
    }
    func validate(path: String) throws {
        guard schema == 1, scenario == Self.scenarioName, try Self.runID(at: path) == runID,
              try Self.id(at: materialContractPath, leaf: Self.materialLeaf) == runID else { throw AppNativeFiniteFailure.contract }
    }
    func requireMaterial(_ value: AppNativePasswordMaterialContract) throws {
        guard value.runID == runID else { throw AppNativeFiniteFailure.contract }
    }
}

/// New source binding approved for M1, from the already reviewed public passwordonly contract.
/// It does not revise/claim the old keyonly validator or authorize inspect/collect/live itself.
enum AppNativePasswordIdentity {
    static let base = "docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d"
    static let image = "sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363"
    static let project = "openlxssh-fixture-61ed25328c13"
    static let container = "ca01afad3e3b02e90369f29d153aceecd07ba6fced28befdf8b4163f7c27172c"
    static let fingerprint = "SHA256:YAP/B5jFVHLnyPzRrU3/CJune9REpBSMnm87wcirrJ8"
    static let network = "b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1"
    static let context = "desktop-linux", endpoint = "unix:///Users/liuwenshuo/.docker/run/docker.sock"
}
struct AppNativePasswordMaterialContract: Equatable, Sendable {
    static let keys: Set<String> = ["schema", "runID", "host", "port", "user", "service", "generation", "expectedBase", "expectedImage",
        "expectedProject", "expectedContainer", "expectedFingerprint", "networkID", "context", "endpoint", "collectedAt", "preparedAt",
        "provenanceSHA256", "knownHostsSHA256"]
    let schema: Int, runID: String, host: String, port: Int, user: String, service: String, generation: String
    let expectedBase: String, expectedImage: String, expectedProject: String, expectedContainer: String, expectedFingerprint: String
    let networkID: String, context: String, endpoint: String
    let collectedAt: Double, preparedAt: Double
    let provenanceSHA256: String, knownHostsSHA256: String
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let value = try AppNativePasswordJSON.object(bytes, keys: keys, limit: 8192)
        func text(_ key: String) throws -> String { try AppNativePasswordJSON.string(value, key) }
        return Self(schema: try AppNativePasswordJSON.integer(value, "schema"), runID: try text("runID"), host: try text("host"),
            port: try AppNativePasswordJSON.integer(value, "port"), user: try text("user"), service: try text("service"), generation: try text("generation"),
            expectedBase: try text("expectedBase"), expectedImage: try text("expectedImage"), expectedProject: try text("expectedProject"),
            expectedContainer: try text("expectedContainer"), expectedFingerprint: try text("expectedFingerprint"), networkID: try text("networkID"),
            context: try text("context"), endpoint: try text("endpoint"), collectedAt: try AppNativePasswordJSON.number(value, "collectedAt"),
            preparedAt: try AppNativePasswordJSON.number(value, "preparedAt"), provenanceSHA256: try text("provenanceSHA256"), knownHostsSHA256: try text("knownHostsSHA256"))
    }
    func validate(path: String, now: Double, buildEpoch: Double) throws {
        guard try AppNativePasswordContract.id(at: path, leaf: AppNativePasswordContract.materialLeaf) == runID,
              schema == 1, host == "127.0.0.1", port == 22222, user == "fixture", service == "passwordonly",
              expectedBase == AppNativePasswordIdentity.base, expectedImage == AppNativePasswordIdentity.image,
              expectedProject == AppNativePasswordIdentity.project, expectedContainer == AppNativePasswordIdentity.container,
              expectedFingerprint == AppNativePasswordIdentity.fingerprint, networkID == AppNativePasswordIdentity.network,
              context == AppNativePasswordIdentity.context, endpoint == AppNativePasswordIdentity.endpoint,
              [provenanceSHA256, knownHostsSHA256].allSatisfy({ AppRealIntegrationContract.hex($0, count: 64) }) else { throw AppNativeFiniteFailure.contract }
        guard collectedAt.isFinite, preparedAt.isFinite, now.isFinite, buildEpoch.isFinite, buildEpoch > 0,
              collectedAt >= buildEpoch, preparedAt >= collectedAt, now >= preparedAt, now - collectedAt <= 120 else {
            throw AppNativeFiniteFailure.staleMaterial
        }
        try AppRealIntegrationContract.pathSyntax(generation)
        let prefix = AppRealIntegrationContract.fixtureRoot + "/.runtime/passwordonly/credentials-"
        guard generation.hasPrefix(prefix), AppRealIntegrationContract.hex(String(generation.dropFirst(prefix.count)), count: 12) else {
            throw AppNativeFiniteFailure.contract
        }
    }
    func validateState(_ bytes: Data) throws {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["version", "project", "image"], limit: 4096)
        guard try AppNativePasswordJSON.integer(value, "version") == 1,
              try AppNativePasswordJSON.string(value, "project") == expectedProject,
              try AppNativePasswordJSON.string(value, "image") == expectedBase else { throw AppNativeFiniteFailure.contract }
    }
    func validateProvenance(_ bytes: Data) throws {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["base_image", "built_image_id", "service", "collected_at"], limit: 4096)
        guard try AppNativePasswordJSON.string(value, "base_image") == expectedBase,
              try AppNativePasswordJSON.string(value, "built_image_id") == expectedImage,
              try AppNativePasswordJSON.string(value, "service") == service,
              try AppNativePasswordJSON.number(value, "collected_at") == collectedAt else { throw AppNativeFiniteFailure.contract }
    }
    func matchesTrust(host: String, port: Int, algorithm: String, fingerprint: String) -> Bool {
        host == self.host && port == self.port && algorithm == "ssh-ed25519" && fingerprint == expectedFingerprint
    }
}

/// The only selected secret leaf is added by the future runtime branch, never a contract override.
enum AppNativePasswordSecret {
    static func payload(_ file: Data) throws -> Data {
        guard file.count >= 2, file.count <= 1024, file.last == 10 else { throw AppNativeFiniteFailure.unsafeInput }
        let value = Data(file.dropLast())
        guard !value.contains(0), !value.contains(10), !value.contains(13) else { throw AppNativeFiniteFailure.unsafeInput }
        return value
    }
}
struct AppNativePasswordTransientFacts: Codable, Equatable, Sendable {
    let preparedTabCount: Int, preparedConnectionAttempts: Int, preparedIntentConsumed: Bool
    let commitCount: Int, committedTabCount: Int, intentConsumed: Bool, primaryProviderCalls: Int
    init(preparedTabCount: Int, preparedConnectionAttempts: Int, preparedIntentConsumed: Bool,
         commitCount: Int, committedTabCount: Int, intentConsumed: Bool, primaryProviderCalls: Int) throws {
        guard preparedTabCount == 0, preparedConnectionAttempts == 0, !preparedIntentConsumed,
              commitCount == 1, committedTabCount == 1, intentConsumed, primaryProviderCalls == 1 else {
            throw AppNativeFiniteFailure.unexpectedAuthentication
        }
        self.preparedTabCount = preparedTabCount; self.preparedConnectionAttempts = preparedConnectionAttempts
        self.preparedIntentConsumed = preparedIntentConsumed; self.commitCount = commitCount
        self.committedTabCount = committedTabCount; self.intentConsumed = intentConsumed; self.primaryProviderCalls = primaryProviderCalls
    }
}
#if HOST_PROBE
struct AppNativeFiniteAuthFacts: Encodable, Sendable {
    let primaryMethod: String
    let primaryStarted: Int, primaryResults: Int, primaryCode: Int32
    let primaryAuthenticated: Bool, authenticatedEvents: Int, shellReadyEvents: Int
    init(keyonly value: AppNativeFiniteAuthentication) {
        primaryMethod = value.primaryMethod; primaryStarted = value.primaryStarted; primaryResults = value.primaryResults
        primaryCode = value.primaryCode; primaryAuthenticated = value.primaryAuthenticated
        authenticatedEvents = value.authenticatedEvents; shellReadyEvents = value.shellReadyEvents
    }
    init(passwordStages stages: [NativeShellAuthenticationStage]) throws {
        guard stages.count == 5, case .advertised(let password, _, _) = stages[0], password,
              stages[1] == .primaryStarted(.password), stages[2] == .primaryResult(.password, code: 0, authenticated: true),
              stages[3] == .authenticated, stages[4] == .shellReady else { throw AppNativeFiniteFailure.typedStages }
        primaryMethod = "password"; primaryStarted = 1; primaryResults = 1; primaryCode = 0; primaryAuthenticated = true
        authenticatedEvents = 1; shellReadyEvents = 1
    }
}
struct AppNativePasswordAuthenticationReceipt: Encodable, Sendable {
    static let leaf = "native-password-authentication.json"
    let schema = 1, kind = "HostProbe-App-Native-password-authentication"
    let scenario = AppNativeFiniteScenario.password
    let sourceKeyScope = AppNativeFiniteSourceKeyScope.notApplicablePassword
    let acceptanceScope = "authentication-only-resources-unverified"
    let guiVerified = false, productRuntimeVerified = false
    let runID: String, pid: Int32, authentication: AppNativeFiniteAuthFacts, transient: AppNativePasswordTransientFacts
    let credentialCalls: Int
}
#endif

/// Isolated fixture scenarios only; these are not product authentication-policy choices.
enum AppMFAFixture: String, Codable, CaseIterable, Sendable {
    case keyKI = "keyki-controller-shell"
    case passwordKI = "passwordki-transient-controller-shell"
    var usesKey: Bool { self == .keyKI }
    var service: String { usesKey ? "key-kbd" : "password-kbd" }
    var port: Int { usesKey ? 22223 : 22224 }
    var key: String { usesKey ? "edplain" : "none" }
    var container: String { usesKey ? "8fe5caf91cd453465d0c90c9c3c6607d7d37252b0a12756048296d26f076dee6" : "5dcc3e0f4cbdae036c7b45113d3b86f06bcf314f20ee6ef03d39a195e009c38c" }
    var fingerprint: String { usesKey ? "SHA256:zzZ9B7L8srAQFmIettj3r/r1XwuSSfvZFAs8K2SmWvE" : "SHA256:M89ZPAwqBO3k4+50seWt4j0oCpqAamqWCicE+q1hibc" }
}
enum AppMFAArguments {
    enum Action: Equatable { case none, help, validate, live }
    struct Options: Equatable { let action: Action; let contractPath: String? }
    static let help = """
    HostProbe-only fixed keyKI/passwordKI App consumer. No GUI/default/resource acceptance shortcut.
    --native-mfa-fixture-help
    --native-mfa-fixture-validate --native-mfa-fixture-contract <exact/native-mfa-fixture.json>
      Syntax only; no input, AppKit, credentials, management process or network access.
    --native-mfa-fixture-test --native-mfa-fixture-contract <exact owned path> --authorized-local-fixture --primary-released
      Existing fixture authorization and separate primary release required; flags grant neither.
    """
    static func parse(_ arguments: [String], hostProbe: Bool) throws -> Options {
        guard arguments.contains(where: { $0.hasPrefix("--native-mfa-fixture") }) else { return .init(action: .none, contractPath: nil) }
        guard hostProbe else { throw AppNativeFiniteFailure.arguments }
        if arguments == ["--native-mfa-fixture-help"] { return .init(action: .help, contractPath: nil) }
        guard let first = arguments.first, ["--native-mfa-fixture-test", "--native-mfa-fixture-validate"].contains(first) else { throw AppNativeFiniteFailure.arguments }
        var path: String?, authorized = false, released = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--native-mfa-fixture-contract":
                guard path == nil, index + 1 < arguments.count else { throw AppNativeFiniteFailure.arguments }
                index += 1; path = arguments[index]; _ = try AppMFAContract.runID(at: arguments[index])
            case "--authorized-local-fixture": guard !authorized else { throw AppNativeFiniteFailure.arguments }; authorized = true
            case "--primary-released": guard !released else { throw AppNativeFiniteFailure.arguments }; released = true
            default: throw AppNativeFiniteFailure.arguments
            }
            index += 1
        }
        guard let path else { throw AppNativeFiniteFailure.arguments }
        if first == "--native-mfa-fixture-validate" {
            guard !authorized, !released else { throw AppNativeFiniteFailure.arguments }; return .init(action: .validate, contractPath: path)
        }
        guard authorized, released else { throw AppNativeFiniteFailure.authorization }
        return .init(action: .live, contractPath: path)
    }
}
struct AppMFAContract: Equatable, Sendable {
    static let leaf = "native-mfa-fixture.json", materialLeaf = "native-mfa-material.json", policyLeaf = "native-mfa-policy.json"
    let schema: Int, runID: String, scenario: AppMFAFixture, materialContractPath: String
    static func runID(at path: String) throws -> String { try id(at: path, leaf: leaf) }
    static func id(at path: String, leaf: String) throws -> String {
        guard [Self.leaf, materialLeaf, policyLeaf].contains(leaf) else { throw AppNativeFiniteFailure.contract }
        try AppRealIntegrationContract.pathSyntax(path)
        let prefix = AppNativeFiniteContract.inputRoot + "/run-", suffix = "/" + leaf
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw AppNativeFiniteFailure.contract }
        let id = String(path.dropFirst(prefix.count).dropLast(suffix.count))
        guard AppNativeFiniteContract.canonicalID(id), path == prefix + id + suffix else { throw AppNativeFiniteFailure.contract }
        return id
    }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["schema", "runID", "scenario", "materialContractPath"], limit: 4096)
        guard try AppNativePasswordJSON.integer(value, "schema") == 1,
              let scenario = AppMFAFixture(rawValue: try AppNativePasswordJSON.string(value, "scenario")) else { throw AppNativeFiniteFailure.contract }
        return Self(schema: 1, runID: try AppNativePasswordJSON.string(value, "runID"), scenario: scenario,
                    materialContractPath: try AppNativePasswordJSON.string(value, "materialContractPath"))
    }
    func validate(path: String) throws {
        guard schema == 1, try Self.runID(at: path) == runID,
              try Self.id(at: materialContractPath, leaf: Self.materialLeaf) == runID else { throw AppNativeFiniteFailure.contract }
    }
}
struct AppMFAMaterialContract: Equatable, Sendable {
    static let commonKeys: Set<String> = ["schema", "runID", "host", "port", "user", "service", "key", "generation", "expectedBase", "expectedImage",
        "expectedProject", "expectedContainer", "expectedFingerprint", "networkID", "context", "endpoint", "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256", "policyProofSHA256"]
    let fixture: AppMFAFixture
    let schema: Int, runID: String, host: String, port: Int, user: String, service: String, key: String, generation: String
    let expectedBase: String, expectedImage: String, expectedProject: String, expectedContainer: String, expectedFingerprint: String
    let networkID: String, context: String, endpoint: String, provenanceSHA256: String, knownHostsSHA256: String, policyProofSHA256: String
    let collectedAt: Double, preparedAt: Double
    let generationPublicKeySHA256: String?
    static func decodeStrict(_ bytes: Data, fixture: AppMFAFixture) throws -> Self {
        let keys = fixture.usesKey ? commonKeys.union(["generationPublicKeySHA256"]) : commonKeys
        let value = try AppNativePasswordJSON.object(bytes, keys: keys, limit: 8192)
        func text(_ key: String) throws -> String { try AppNativePasswordJSON.string(value, key) }
        let publicDigest: String?
        if fixture.usesKey { publicDigest = try text("generationPublicKeySHA256") } else { publicDigest = nil }
        return Self(fixture: fixture, schema: try AppNativePasswordJSON.integer(value, "schema"), runID: try text("runID"), host: try text("host"),
            port: try AppNativePasswordJSON.integer(value, "port"), user: try text("user"), service: try text("service"), key: try text("key"), generation: try text("generation"),
            expectedBase: try text("expectedBase"), expectedImage: try text("expectedImage"), expectedProject: try text("expectedProject"), expectedContainer: try text("expectedContainer"),
            expectedFingerprint: try text("expectedFingerprint"), networkID: try text("networkID"), context: try text("context"), endpoint: try text("endpoint"),
            provenanceSHA256: try text("provenanceSHA256"), knownHostsSHA256: try text("knownHostsSHA256"), policyProofSHA256: try text("policyProofSHA256"),
            collectedAt: try AppNativePasswordJSON.number(value, "collectedAt"), preparedAt: try AppNativePasswordJSON.number(value, "preparedAt"),
            generationPublicKeySHA256: publicDigest)
    }
    func validate(path: String, now: Double, buildEpoch: Double) throws {
        guard try AppMFAContract.id(at: path, leaf: AppMFAContract.materialLeaf) == runID, schema == 1,
              host == "127.0.0.1", port == fixture.port, user == "fixture", service == fixture.service, key == fixture.key,
              expectedBase == AppNativePasswordIdentity.base, expectedImage == AppNativePasswordIdentity.image, expectedProject == AppNativePasswordIdentity.project,
              expectedContainer == fixture.container, expectedFingerprint == fixture.fingerprint, networkID == AppNativePasswordIdentity.network,
              context == AppNativePasswordIdentity.context, endpoint == AppNativePasswordIdentity.endpoint,
              [provenanceSHA256, knownHostsSHA256, policyProofSHA256].allSatisfy({ AppRealIntegrationContract.hex($0, count: 64) }),
              (fixture.usesKey ? generationPublicKeySHA256.map({ AppRealIntegrationContract.hex($0, count: 64) }) == true : generationPublicKeySHA256 == nil) else {
            throw AppNativeFiniteFailure.contract
        }
        guard collectedAt.isFinite, preparedAt.isFinite, now.isFinite, buildEpoch.isFinite, buildEpoch > 0,
              collectedAt >= buildEpoch, preparedAt >= collectedAt, now >= preparedAt, now - collectedAt <= 120 else { throw AppNativeFiniteFailure.staleMaterial }
        try AppRealIntegrationContract.pathSyntax(generation)
        let prefix = AppRealIntegrationContract.fixtureRoot + "/.runtime/" + fixture.service + "/credentials-"
        guard generation.hasPrefix(prefix), AppRealIntegrationContract.hex(String(generation.dropFirst(prefix.count)), count: 12) else { throw AppNativeFiniteFailure.contract }
    }
    func validateState(_ bytes: Data) throws {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["version", "project", "image"], limit: 4096)
        guard try AppNativePasswordJSON.integer(value, "version") == 1,
              try AppNativePasswordJSON.string(value, "project") == expectedProject,
              try AppNativePasswordJSON.string(value, "image") == expectedBase else { throw AppNativeFiniteFailure.contract }
    }
    func validateProvenance(_ bytes: Data) throws {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["base_image", "built_image_id", "service", "collected_at"], limit: 4096)
        guard try AppNativePasswordJSON.string(value, "base_image") == expectedBase,
              try AppNativePasswordJSON.string(value, "built_image_id") == expectedImage,
              try AppNativePasswordJSON.string(value, "service") == service,
              try AppNativePasswordJSON.number(value, "collected_at") == collectedAt else { throw AppNativeFiniteFailure.contract }
    }
    /// Public primary-produced observation, not a permission token or a secret-bearing Docker inspect dump.
    func validatePolicyProof(_ bytes: Data, now: Double, buildEpoch: Double) throws {
        let keys: Set<String> = ["schema", "runID", "service", "containerID", "imageID", "baseImage", "project", "networkID", "context", "endpoint",
            "port", "verifiedAt", "runningHealthy", "readonlyRoot", "notPrivileged", "logNone", "loopbackPortExact", "internalBridge", "noBindMounts", "rootPolicyMulti"]
        let value = try AppNativePasswordJSON.object(bytes, keys: keys, limit: 4096)
        for key in ["schema", "runningHealthy", "readonlyRoot", "notPrivileged", "logNone", "loopbackPortExact", "internalBridge", "noBindMounts", "rootPolicyMulti"] {
            guard try AppNativePasswordJSON.integer(value, key) == 1 else { throw AppNativeFiniteFailure.contract }
        }
        let pairs = [("runID", runID), ("service", service), ("containerID", expectedContainer), ("imageID", expectedImage), ("baseImage", expectedBase),
                     ("project", expectedProject), ("networkID", networkID), ("context", context), ("endpoint", endpoint)]
        for (key, expected) in pairs { guard try AppNativePasswordJSON.string(value, key) == expected else { throw AppNativeFiniteFailure.contract } }
        let verified = try AppNativePasswordJSON.number(value, "verifiedAt")
        guard try AppNativePasswordJSON.integer(value, "port") == port, verified >= buildEpoch, verified >= collectedAt,
              verified <= preparedAt, now >= verified, now - verified <= 120 else { throw AppNativeFiniteFailure.staleMaterial }
    }
}

/// Exact reply ownership identity; not Codable and never included in a receipt.
struct AppMFAReplyOwner: Equatable, Sendable {
    let tabID: UUID, sessionID: UUID, requestID: UUID, hostID: UUID
    let generation: UInt64, port: Int
    func validate(current: Self) throws {
        guard self == current, generation > 0, [22223, 22224].contains(port) else { throw AppNativeFiniteFailure.unexpectedAuthentication }
    }
}

/// An exact fixture protocol, never a product prompt classifier. Session identifiers stay memory-only.
struct AppMFAKIBudget: Sendable {
    enum Phase: Equatable, Sendable { case secret(session: String, index: Int), zero }
    let deadline: Double
    private(set) var rounds = 0, replies = 0, secretReplies = 0, zeroReplies = 0, managementReads = 0, lateReplies = 0
    private(set) var sessionID: String?, pending: Phase?, closed = false
    private var awaitingResolution = false
    private var accepted = 0
    private(set) var fieldCounts: [Int] = [], echoFlags: [[Bool]] = []
    init(deadline: Double) throws {
        guard deadline.isFinite, deadline > 0 else { throw AppNativeFiniteFailure.contract }; self.deadline = deadline
    }
    static func prompt(session: String, index: Int) throws -> String {
        guard AppRealIntegrationContract.hex(session, count: 24), (0..<3).contains(index) else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        return ["One-time response A", "Unclassified verification B", "Next-round response C"][index] + " [" + session + "]: "
    }
    mutating func claim(name: String, instruction: String, fields: [String], echo: [Bool], now: Double) throws -> Phase {
        guard !closed, now.isFinite, now < deadline, pending == nil, !awaitingResolution else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        rounds += 1
        guard rounds == replies + 1, rounds <= 4, name.isEmpty, instruction.isEmpty else { close(); throw AppNativeFiniteFailure.unexpectedAuthentication }
        if rounds == 4 {
            guard replies == 3, secretReplies == 3, accepted == 3, managementReads == 3, sessionID != nil,
                  fields.isEmpty, echo.isEmpty, zeroReplies == 0 else { close(); throw AppNativeFiniteFailure.unexpectedAuthentication }
            pending = .zero; fieldCounts.append(0); echoFlags.append([]); return .zero
        }
        guard fields.count == 1, echo == [false], secretReplies == replies, accepted == replies,
              let range = fields[0].range(of: " [", options: .backwards), fields[0].hasSuffix("]: ") else { close(); throw AppNativeFiniteFailure.unexpectedAuthentication }
        let session = String(fields[0][range.upperBound..<fields[0].index(fields[0].endIndex, offsetBy: -3)])
        guard AppRealIntegrationContract.hex(session, count: 24), fields[0] == (try Self.prompt(session: session, index: secretReplies)),
              sessionID == nil || sessionID == session else { close(); throw AppNativeFiniteFailure.unexpectedAuthentication }
        let phase = Phase.secret(session: session, index: secretReplies)
        sessionID = session; pending = phase; fieldCounts.append(1); echoFlags.append(echo); return phase
    }
    mutating func claimManagementRead(_ phase: Phase) throws {
        guard !closed, pending == phase, case .secret(_, let index) = phase, managementReads == index else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        managementReads += 1
    }
    mutating func consume(_ phase: Phase, now: Double) throws {
        guard !closed, now.isFinite, now < deadline, pending == phase, !awaitingResolution else {
            lateReplies += 1; close(); throw AppNativeFiniteFailure.unexpectedAuthentication
        }
        switch phase {
        case .secret(_, let index):
            guard index == secretReplies, managementReads == index + 1 else { close(); throw AppNativeFiniteFailure.unexpectedAuthentication }; secretReplies += 1
        case .zero: zeroReplies += 1
        }
        replies += 1; pending = nil; awaitingResolution = true
    }
    mutating func resolved(_ succeeded: Bool) throws {
        guard !closed, awaitingResolution, succeeded else { lateReplies += 1; close(); throw AppNativeFiniteFailure.unexpectedAuthentication }
        accepted += 1; awaitingResolution = false
    }
    mutating func close() { closed = true; pending = nil; awaitingResolution = false }
    func requireComplete() throws {
        guard !closed, pending == nil, !awaitingResolution, rounds == 4, replies == 4, accepted == 4,
              secretReplies == 3, zeroReplies == 1, managementReads == 3, lateReplies == 0,
              fieldCounts == [1, 1, 1, 0], echoFlags == [[false], [false], [false], []] else { throw AppNativeFiniteFailure.unexpectedAuthentication }
    }
}
struct AppMFAKIFacts: Encodable, Sendable {
    let rounds: Int, replies: Int, secretReplies: Int, zeroReplies: Int, managementReads: Int, lateReplies: Int
    let fieldCounts: [Int], echoFlags: [[Bool]]
    init(_ budget: AppMFAKIBudget) {
        rounds = budget.rounds; replies = budget.replies; secretReplies = budget.secretReplies; zeroReplies = budget.zeroReplies
        managementReads = budget.managementReads; lateReplies = budget.lateReplies; fieldCounts = budget.fieldCounts; echoFlags = budget.echoFlags
    }
}
enum AppMFAStatus: String, Codable, Sendable { case removed, present, unknown }
enum AppMFAOTP {
    static func decode(_ bytes: Data, session: String, index: Int, now: Double) throws -> Data {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["session", "index", "expires_at", "response"], limit: 4096)
        let expiry = try AppNativePasswordJSON.number(value, "expires_at"), answer = try AppNativePasswordJSON.string(value, "response")
        guard AppRealIntegrationContract.hex(session, count: 24), (0..<3).contains(index),
              try AppNativePasswordJSON.string(value, "session") == session,
              try AppNativePasswordJSON.integer(value, "index") == index,
              now.isFinite, expiry > now, expiry <= now + 75, answer.utf8.count == 8,
              answer.utf8.allSatisfy({ (48...57).contains($0) }) else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        return Data(answer.utf8)
    }
}
struct AppMFAManagementFacts: Encodable, Sendable {
    let calls: Int, returnedCalls: Int, successfulReapedCalls: Int, pendingCalls: Int
    let cancellationRequested: Bool, reapEvidenceComplete: Bool
}
#if HOST_PROBE
struct AppMFAAuthentication: Encodable, Sendable {
    let primaryMethod: String
    let primaryStarted = 1, primaryResults = 1
    let primaryCode: Int32
    let primaryAuthenticated = false
    let keyboardStarted = 1, keyboardResults = 1, keyboardCode: Int32 = 0
    let keyboardAuthenticated = true, authenticatedEvents = 1, shellReadyEvents = 1
    init(_ stages: [NativeShellAuthenticationStage], fixture: AppMFAFixture) throws {
        let method: NativeShellPrimaryMethod = fixture.usesKey ? .publicKey : .password
        let code: Int32 = fixture.usesKey ? -19 : -18
        guard stages.count == 7, case .advertised(let password, let key, _) = stages[0],
              (fixture.usesKey ? key : password),
              stages[1] == .primaryStarted(method), stages[2] == .primaryResult(method, code: code, authenticated: false),
              stages[3] == .keyboardStarted, stages[4] == .keyboardResult(code: 0, authenticated: true),
              stages[5] == .authenticated, stages[6] == .shellReady else { throw AppNativeFiniteFailure.typedStages }
        primaryMethod = method.rawValue; primaryCode = code
    }
}
struct AppMFAAuthenticationReceipt: Encodable, Sendable {
    static let leaf = "native-mfa-authentication.json"
    let schema = 1, kind = "HostProbe-App-Native-MFA-authentication", acceptanceScope = "authentication-only-resources-unverified"
    let guiVerified = false, productRuntimeVerified = false
    let runID: String, pid: Int32, scenario: AppMFAFixture, authentication: AppMFAAuthentication, keyboard: AppMFAKIFacts
    let primaryProviderCalls: Int, credentialCalls: Int, transient: AppNativePasswordTransientFacts?
    let externalPolicyProofValidated: Bool
}
struct AppMFACleanupReceipt: Encodable, Sendable {
    static let leaf = "native-mfa-cleanup.json"
    let schema = 1, kind = "HostProbe-App-Native-MFA-cleanup", acceptanceScope = "authentication-cleanup-only-resources-unverified"
    let runID: String, pid: Int32, scenario: AppMFAFixture
    let statusReads: Int, serverSessionStatus: AppMFAStatus, management: AppMFAManagementFacts
}
#endif

/// Observation only; this waiter cannot cancel the management owner or manufacture reap facts.
@MainActor enum AppMFACleanupWait {
    static func observe(deadline: ContinuousClock.Instant, pending: () -> Int) async -> Bool {
        while pending() > 0, .now < deadline {
            guard !Task.isCancelled else { return false }
            do { try await Task.sleep(for: .milliseconds(5)) }
            catch { return false }
        }
        return pending() == 0
    }
}


// Files R2 is a new closed consumer. The complete M2 contract prefix above is unchanged.
enum AppFilesManifestArguments {
    enum Action: Equatable { case none, help, validate, live }
    struct Options: Equatable { let action: Action; let contractPath: String? }
    static let help = """
    HostProbe-only keyonly direct SFTP manifest round trip. Logical App behavior, not GUI/Finder acceptance.
    --native-files-fixture-help
    --native-files-fixture-validate --native-files-fixture-contract <exact/native-files-fixture.json>
      Syntax only; no files, credentials, AppKit, processes or network.
    --native-files-fixture-test --native-files-fixture-contract <exact owned path> --authorized-local-fixture --primary-released
      Existing fixture authorization and separate primary release required; flags grant neither.
    """
    static func parse(_ arguments: [String], hostProbe: Bool) throws -> Options {
        guard arguments.contains(where: { $0.hasPrefix("--native-files-fixture") }) else { return .init(action: .none, contractPath: nil) }
        guard hostProbe else { throw AppNativeFiniteFailure.arguments }
        if arguments == ["--native-files-fixture-help"] { return .init(action: .help, contractPath: nil) }
        guard let first = arguments.first, ["--native-files-fixture-test", "--native-files-fixture-validate"].contains(first) else { throw AppNativeFiniteFailure.arguments }
        var path: String?, authorized = false, released = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--native-files-fixture-contract":
                guard path == nil, index + 1 < arguments.count else { throw AppNativeFiniteFailure.arguments }
                index += 1; path = arguments[index]; _ = try AppFilesManifestContract.runID(at: arguments[index])
            case "--authorized-local-fixture": guard !authorized else { throw AppNativeFiniteFailure.arguments }; authorized = true
            case "--primary-released": guard !released else { throw AppNativeFiniteFailure.arguments }; released = true
            default: throw AppNativeFiniteFailure.arguments
            }
            index += 1
        }
        guard let path else { throw AppNativeFiniteFailure.arguments }
        if first == "--native-files-fixture-validate" {
            guard !authorized, !released else { throw AppNativeFiniteFailure.arguments }; return .init(action: .validate, contractPath: path)
        }
        guard authorized, released else { throw AppNativeFiniteFailure.authorization }
        return .init(action: .live, contractPath: path)
    }
}
struct AppFilesManifestContract: Equatable, Sendable {
    static let leaf = "native-files-fixture.json", materialLeaf = "native-files-material.json"
    static let scenarioName = "keyonly-direct-sftp-manifest"
    let schema: Int, runID: String, scenario: String, materialContractPath: String
    static func runID(at path: String) throws -> String { try id(at: path, leaf: leaf) }
    static func id(at path: String, leaf: String) throws -> String {
        guard [Self.leaf, materialLeaf].contains(leaf) else { throw AppNativeFiniteFailure.contract }
        try AppRealIntegrationContract.pathSyntax(path)
        let prefix = AppNativeFiniteContract.inputRoot + "/run-", suffix = "/" + leaf
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw AppNativeFiniteFailure.contract }
        let id = String(path.dropFirst(prefix.count).dropLast(suffix.count))
        guard AppNativeFiniteContract.canonicalID(id), path == prefix + id + suffix else { throw AppNativeFiniteFailure.contract }
        return id
    }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["schema", "runID", "scenario", "materialContractPath"], limit: 4096)
        guard try AppNativePasswordJSON.integer(value, "schema") == 1 else { throw AppNativeFiniteFailure.contract }
        return Self(schema: 1, runID: try AppNativePasswordJSON.string(value, "runID"), scenario: try AppNativePasswordJSON.string(value, "scenario"),
                    materialContractPath: try AppNativePasswordJSON.string(value, "materialContractPath"))
    }
    func validate(path: String) throws {
        guard schema == 1, scenario == Self.scenarioName, try Self.runID(at: path) == runID,
              try Self.id(at: materialContractPath, leaf: Self.materialLeaf) == runID else { throw AppNativeFiniteFailure.contract }
    }
}
/// Independently closed schema/pin; no AppReal decoder, old phase, endpoint or secret override.
struct AppFilesManifestMaterial: Equatable, Sendable {
    static let keys: Set<String> = ["schema", "runID", "host", "port", "user", "service", "generation", "expectedBase", "expectedImage", "expectedProject",
        "expectedContainer", "expectedFingerprint", "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"]
    let schema: Int, runID: String, host: String, port: Int, user: String, service: String, generation: String
    let expectedBase: String, expectedImage: String, expectedProject: String, expectedContainer: String, expectedFingerprint: String
    let collectedAt: Double, preparedAt: Double
    let provenanceSHA256: String, knownHostsSHA256: String, generationPublicKeySHA256: String
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let value = try AppNativePasswordJSON.object(bytes, keys: keys, limit: 8192)
        func text(_ key: String) throws -> String { try AppNativePasswordJSON.string(value, key) }
        return Self(schema: try AppNativePasswordJSON.integer(value, "schema"), runID: try text("runID"), host: try text("host"),
            port: try AppNativePasswordJSON.integer(value, "port"), user: try text("user"), service: try text("service"), generation: try text("generation"),
            expectedBase: try text("expectedBase"), expectedImage: try text("expectedImage"), expectedProject: try text("expectedProject"),
            expectedContainer: try text("expectedContainer"), expectedFingerprint: try text("expectedFingerprint"),
            collectedAt: try AppNativePasswordJSON.number(value, "collectedAt"), preparedAt: try AppNativePasswordJSON.number(value, "preparedAt"),
            provenanceSHA256: try text("provenanceSHA256"), knownHostsSHA256: try text("knownHostsSHA256"), generationPublicKeySHA256: try text("generationPublicKeySHA256"))
    }
    func validate(path: String, now: Double, buildEpoch: Double) throws {
        guard try AppFilesManifestContract.id(at: path, leaf: AppFilesManifestContract.materialLeaf) == runID, schema == 1,
              host == "127.0.0.1", port == 22221, user == "fixture", service == "keyonly",
              expectedBase == AppNativeFiniteIdentity.base, expectedImage == AppNativeFiniteIdentity.image, expectedProject == AppNativeFiniteIdentity.project,
              expectedContainer == AppNativeFiniteIdentity.container, expectedFingerprint == AppNativeFiniteIdentity.fingerprint,
              [provenanceSHA256, knownHostsSHA256, generationPublicKeySHA256].allSatisfy({ AppRealIntegrationContract.hex($0, count: 64) }) else { throw AppNativeFiniteFailure.contract }
        guard collectedAt.isFinite, preparedAt.isFinite, now.isFinite, buildEpoch.isFinite, buildEpoch > 0,
              collectedAt >= buildEpoch, preparedAt >= collectedAt, now >= preparedAt, now - collectedAt <= 120 else { throw AppNativeFiniteFailure.staleMaterial }
        try AppRealIntegrationContract.pathSyntax(generation)
        let prefix = AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-"
        guard generation.hasPrefix(prefix), AppRealIntegrationContract.hex(String(generation.dropFirst(prefix.count)), count: 12) else { throw AppNativeFiniteFailure.contract }
    }
    func validateState(_ bytes: Data) throws {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["version", "project", "image"], limit: 4096)
        guard try AppNativePasswordJSON.integer(value, "version") == 1, try AppNativePasswordJSON.string(value, "project") == expectedProject,
              try AppNativePasswordJSON.string(value, "image") == expectedBase else { throw AppNativeFiniteFailure.contract }
    }
    func validateProvenance(_ bytes: Data) throws {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["base_image", "built_image_id", "service", "collected_at"], limit: 4096)
        guard try AppNativePasswordJSON.string(value, "base_image") == expectedBase, try AppNativePasswordJSON.string(value, "built_image_id") == expectedImage,
              try AppNativePasswordJSON.string(value, "service") == service, try AppNativePasswordJSON.number(value, "collected_at") == collectedAt else { throw AppNativeFiniteFailure.contract }
    }
    func matchesTrust(host: String, port: Int, algorithm: String, fingerprint: String) -> Bool {
        host == self.host && port == self.port && algorithm == "ssh-ed25519" && fingerprint == expectedFingerprint
    }
}
/// Nonce is generated inside the consumer, never accepted by arguments/material.
struct AppFilesManifestScope: Sendable {
    let nonce: String
    init(nonce: String) throws {
        guard AppRealIntegrationContract.hex(nonce, count: 32) else { throw AppNativeFiniteFailure.contract }; self.nonce = nonce
    }
    let home = "/fixture/home", tree = "树 folder", child = "子 e\u{301} [#; $]"
    var basename: String { "openlxssh-app-manifest-" + nonce }
    var root: String { home + "/" + basename }
    var payloads: [(relative: String, bytes: Int)] { [(".hidden [#; $].bin", 4096), (child + "/内容 空格.bin", 8192)] }
    var relativeDirectories: [String] { ["", child] }
    var relativeEntries: [String] { relativeDirectories + payloads.map { $0.relative } }
    func contains(_ bytes: Data) -> Bool {
        let root = Data(self.root.utf8)
        let parts = bytes.split(separator: 47, omittingEmptySubsequences: false)
        guard parts.first?.isEmpty == true, parts.dropFirst().allSatisfy({ !$0.isEmpty && !$0.elementsEqual([UInt8(46)]) && !$0.elementsEqual([UInt8(46), 46]) }) else { return false }
        return bytes == root || bytes.starts(with: root + Data([47]))
    }
    func exactTransferRisk(_ bytes: Data) -> Bool {
        relativeEntries.contains { Data((root + "/" + tree + ($0.isEmpty ? "" : "/" + $0)).utf8) == bytes }
    }
}
struct AppFilesManifestIO: Codable, Equatable, Sendable {
    var readOpen = 0, read = 0, writeOpen = 0, write = 0, mutations = 0
    var readBytes: UInt64 = 0, writeBytes: UInt64 = 0
    static let zero = Self()
    func delta(from before: Self) throws -> Self {
        guard readOpen >= before.readOpen, read >= before.read, writeOpen >= before.writeOpen, write >= before.write,
              mutations >= before.mutations, readBytes >= before.readBytes, writeBytes >= before.writeBytes else { throw AppNativeFiniteFailure.operation }
        return Self(readOpen: readOpen - before.readOpen, read: read - before.read, writeOpen: writeOpen - before.writeOpen,
            write: write - before.write, mutations: mutations - before.mutations, readBytes: readBytes - before.readBytes, writeBytes: writeBytes - before.writeBytes)
    }
}
struct AppFilesManifestDigest: Codable, Equatable, Sendable {
    let relativePathBase64: String, bytes: Int, sha256: String
}

extension AppFilesManifestScope {
    /// Inspect every raw component: a capability directory at any ancestor is special,
    /// not merely the final leaf/parent. Only the approved directory and its three direct
    /// probe leaves may mutate; even descendants of a whitelisted leaf are refused.
    func allowsRemoteMutation(_ bytes: Data, approvedProbe: Data?) -> Bool {
        guard contains(bytes) else { return false }
        let parts = bytes.split(separator: UInt8(47)).map { Data($0) }
        let rootParts = Data(root.utf8).split(separator: UInt8(47)).map { Data($0) }
        let prefix = Data(".openlxssh-capability.".utf8)
        guard let index = parts.firstIndex(where: { $0.starts(with: prefix) }) else { return true }
        guard index == rootParts.count, let approvedProbe, contains(approvedProbe) else { return false }
        let approvedParts = approvedProbe.split(separator: UInt8(47)).map { Data($0) }
        guard approvedParts.count == rootParts.count + 1, approvedParts.dropLast().elementsEqual(rootParts),
              approvedParts.last?.starts(with: prefix) == true, parts.prefix(index + 1).elementsEqual(approvedParts) else { return false }
        if parts.count == index + 1 { return true }
        return parts.count == index + 2 && ["source", "destination", "absent-target"].contains { Data($0.utf8) == parts[index + 1] }
    }
}

/// Shared by the runtime and its local failure-path test; each successful acquisition
/// immediately installs its own defer before the next acquisition can throw.
enum AppFilesManifestDescriptors {
    static func withPair<T>(source: () throws -> Int32, download: () throws -> Int32,
                            _ body: (Int32, Int32) throws -> T) rethrows -> T {
        let left = try source()
        defer { Darwin.close(left) }
        let right = try download()
        defer { Darwin.close(right) }
        return try body(left, right)
    }
}

#if HOST_PROBE
// Exact runtime receipt types shared with serialization tests, never substitute test wrappers.
struct AppFilesManifestStream: Encodable, Sendable {
    let side: String, pathBase64: String, writing: Bool, bytes: Int, sha256: String
    func encode(to encoder: any Encoder) throws {
        var row = encoder.unkeyedContainer()
        try row.encode(side); try row.encode(pathBase64); try row.encode(writing); try row.encode(bytes); try row.encode(sha256)
    }
}
struct AppFilesManifestServiceFacts: Encodable, Sendable {
    let remote: AppFilesManifestIO, local: AppFilesManifestIO
    let attempts: Int, remoteServices: Int, localServices: Int, closedRemote: Int, closedLocal: Int
    let liveHandles: Int, rescuedHandles: Int, handleCloseFailures: Int, observationFailed: Bool
    let bindings: [UUID]
    var drained: Bool { remoteServices == 1 && localServices == 2 && closedRemote == remoteServices && closedLocal == localServices && liveHandles == 0 && rescuedHandles == 0 && handleCloseFailures == 0 && !observationFailed }
}
struct AppFilesManifestPlanEvidence: Encodable, Sendable {
    let planID: UUID, reviewID: UUID, serviceID: UUID, hostID: UUID, lifetime: UUID, revision: UUID
    let direction: String, sourceBase64: String, destinationBase64: String
    let itemCount: Int, fileCount: Int, directoryCount: Int, totalBytes: UInt64
    let namesBase64: [String]
    let remoteDelta: AppFilesManifestIO, localDelta: AppFilesManifestIO
    let jobsBefore: Int, jobsAfter: Int, confirmCalls: Int
}
struct AppFilesManifestCapability: Encodable, Sendable {
    let planID: UUID, serverBinding: UUID, parentBase64: String, directoryBase64: String
    let acknowledgedRiskCount: Int, passed: Bool, retainedPathCount: Int, remoteDelta: AppFilesManifestIO
}
struct AppFilesManifestItemEvidence: Encodable, Sendable {
    let sourceBase64: String, destinationBase64: String, bytes: UInt64, acknowledgedRiskCount: Int
    func encode(to encoder: any Encoder) throws {
        var row = encoder.unkeyedContainer()
        try row.encode(sourceBase64); try row.encode(destinationBase64); try row.encode(bytes); try row.encode(acknowledgedRiskCount)
    }
}
struct AppFilesManifestJobEvidence: Encodable, Sendable {
    let id: UUID, generation: UUID, planID: UUID, batchID: UUID
    let transferredBytes: UInt64, succeededFiles: Int, succeededDirectories: Int
    let items: [AppFilesManifestItemEvidence]
    let remoteDelta: AppFilesManifestIO, localDelta: AppFilesManifestIO
    let streams: [AppFilesManifestStream]
}
struct AppFilesManifestReport: Encodable {
    let schema = 1, kind = "HostProbe-App-Files-manifest", scenario = AppFilesManifestContract.scenarioName
    let acceptanceScope = "logical-App-real-SFTP-not-dualPane-pixels-or-Finder"
    let guiVerified = false, productRuntimeVerified = false, shellSessions = 0, rescueAttempts = 0
    let runID: String, pid: Int32, checkpoint: String, elapsedSeconds: Double
    let passed: Bool, failureCode: AppNativeFiniteFailure?, transferOnly: Bool, closedAndClean: Bool, localStoreRemoved: Bool
    let nonce: String, sourceKeyUnchanged: Bool, fixtureKnownHostsUnchanged: Bool, trustMatchedOutOfBand: Bool
    let credentialCalls: Int, capabilityPassed: Bool, serverBinding: UUID?
    let capability: AppFilesManifestCapability?, plans: [AppFilesManifestPlanEvidence], jobs: [AppFilesManifestJobEvidence], source: [AppFilesManifestDigest], remote: [AppFilesManifestDigest], download: [AppFilesManifestDigest]
    let services: AppFilesManifestServiceFacts, managerClosed: Bool, managerDrained: Bool, managerJobs: Int, managerOperations: Int
    let managerPreparing: Int, managerReady: Int, managerConfirming: Int, managerReservedEntries: Int, managerReservedMetadataBytes: Int
    let remoteRootRemoved: Bool, localPayloadRemoved: Bool, deletePlanIDs: [UUID]
    let descriptors: AppFilesManifestDescriptorEvidence, descriptorIdentityMatched: Bool, quit: AppNativeFiniteQuitAudit
}
/// Files-only lossless scalar wire encoding. Original Native diagnostics and resource
/// gates stay unchanged; every row/unknown/null is retained, never truncated to fit.
struct AppFilesManifestDescriptorEvidence: Encodable {
    let snapshots: AppNativeFiniteDescriptorSnapshots
    // Wire v1 snapshot: [elapsed, upper, count, truncated, complete, entries].
    // Entry: [fd, type?, dev?, ino?, access?, statusCode, roleCode]. Codes are
    // status stable/unavailable/changed = 0/1/2; role unknown/TZ/ICU/locale/font = 0...4.
    private enum Key: String, CodingKey { case schema, wireVersion, maximumEntries, atomic, continuousOpenProven, baseline, cleanupFirst, cleanupLatest }
    init(_ snapshots: AppNativeFiniteDescriptorSnapshots) { self.snapshots = snapshots }
    func encode(to encoder: any Encoder) throws {
        var value = encoder.container(keyedBy: Key.self)
        try value.encode(1, forKey: .schema); try value.encode(1, forKey: .wireVersion); try value.encode(snapshots.maximumEntries, forKey: .maximumEntries)
        try value.encode(snapshots.atomic, forKey: .atomic); try value.encode(snapshots.continuousOpenProven, forKey: .continuousOpenProven)
        try value.encodeIfPresent(snapshots.baseline.map(CompactSnapshot.init), forKey: .baseline)
        try value.encodeIfPresent(snapshots.cleanupFirst.map(CompactSnapshot.init), forKey: .cleanupFirst)
        try value.encodeIfPresent(snapshots.cleanupLatest.map(CompactSnapshot.init), forKey: .cleanupLatest)
    }
    private struct CompactSnapshot: Encodable {
        let value: AppNativeFiniteDescriptorSnapshot
        init(_ value: AppNativeFiniteDescriptorSnapshot) { self.value = value }
        func encode(to encoder: any Encoder) throws {
            var row = encoder.unkeyedContainer()
            try row.encode(value.elapsedSeconds); try row.encode(value.scanUpperExclusive); try row.encode(value.count)
            try row.encode(value.truncated); try row.encode(value.complete); try row.encode(value.entries.map(CompactEntry.init))
        }
    }
    private struct CompactEntry: Encodable {
        let value: AppNativeFiniteDescriptorEntry
        init(_ value: AppNativeFiniteDescriptorEntry) { self.value = value }
        func encode(to encoder: any Encoder) throws {
            var row = encoder.unkeyedContainer()
            try row.encode(value.fd); try row.encode(value.type); try row.encode(value.dev); try row.encode(value.ino); try row.encode(value.access)
            let status: Int
            switch value.probeStatus { case .stable: status = 0; case .unavailable: status = 1; case .changed: status = 2 }
            let role: Int
            switch value.role { case .unknown: role = 0; case .systemTZShape: role = 1; case .systemICUShape: role = 2; case .systemLocaleShape: role = 3; case .systemFontShape: role = 4 }
            try row.encode(status); try row.encode(role)
        }
    }
}
#endif


// Conflict R5 is an independent closed entry. All passed round-trip contracts above stay unchanged.
enum AppFilesConflictArguments {
    enum Action: Equatable { case none, help, validate, live }
    struct Options: Equatable { let action: Action; let contractPath: String? }
    static let help = """
    HostProbe-only keyonly direct SFTP manifest conflict: Seed then Fresh rename+skip, no propagation claim.
    --native-files-conflict-help
    --native-files-conflict-validate --native-files-conflict-contract <exact/native-files-conflict.json>
    --native-files-conflict-test --native-files-conflict-contract <exact owned path> --authorized-local-fixture --primary-released
    Syntax validation performs no I/O. Flags are not authorization. No GUI/default/overwrite/cancel/retry scope.
    """
    static func parse(_ arguments: [String], hostProbe: Bool) throws -> Options {
        guard arguments.contains(where: { $0.hasPrefix("--native-files-conflict") }) else { return .init(action: .none, contractPath: nil) }
        guard hostProbe else { throw AppNativeFiniteFailure.arguments }
        if arguments == ["--native-files-conflict-help"] { return .init(action: .help, contractPath: nil) }
        guard let first = arguments.first, ["--native-files-conflict-test", "--native-files-conflict-validate"].contains(first) else { throw AppNativeFiniteFailure.arguments }
        var path: String?, authorized = false, released = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--native-files-conflict-contract":
                guard path == nil, index + 1 < arguments.count else { throw AppNativeFiniteFailure.arguments }
                index += 1; path = arguments[index]; _ = try AppFilesConflictContract.runID(at: arguments[index])
            case "--authorized-local-fixture": guard !authorized else { throw AppNativeFiniteFailure.arguments }; authorized = true
            case "--primary-released": guard !released else { throw AppNativeFiniteFailure.arguments }; released = true
            default: throw AppNativeFiniteFailure.arguments
            }
            index += 1
        }
        guard let path else { throw AppNativeFiniteFailure.arguments }
        if first == "--native-files-conflict-validate" {
            guard !authorized, !released else { throw AppNativeFiniteFailure.arguments }; return .init(action: .validate, contractPath: path)
        }
        guard authorized, released else { throw AppNativeFiniteFailure.authorization }; return .init(action: .live, contractPath: path)
    }
}
struct AppFilesConflictContract: Equatable, Sendable {
    static let leaf = "native-files-conflict.json", scenario = "keyonly-direct-sftp-manifest-conflict"
    let schema: Int, runID: String, materialContractPath: String
    static func runID(at path: String) throws -> String {
        try AppRealIntegrationContract.pathSyntax(path)
        let prefix = AppNativeFiniteContract.inputRoot + "/run-", suffix = "/" + leaf
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw AppNativeFiniteFailure.contract }
        let id = String(path.dropFirst(prefix.count).dropLast(suffix.count))
        guard AppNativeFiniteContract.canonicalID(id), path == prefix + id + suffix else { throw AppNativeFiniteFailure.contract }; return id
    }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["schema", "runID", "scenario", "materialContractPath"], limit: 4096)
        guard try AppNativePasswordJSON.integer(value, "schema") == 1, try AppNativePasswordJSON.string(value, "scenario") == scenario else { throw AppNativeFiniteFailure.contract }
        return Self(schema: 1, runID: try AppNativePasswordJSON.string(value, "runID"), materialContractPath: try AppNativePasswordJSON.string(value, "materialContractPath"))
    }
    func validate(path: String) throws {
        guard schema == 1, try Self.runID(at: path) == runID,
              try AppFilesManifestContract.id(at: materialContractPath, leaf: AppFilesManifestContract.materialLeaf) == runID else { throw AppNativeFiniteFailure.contract }
    }
}
enum AppFilesExerciseMode: Equatable, Sendable { case roundtrip, conflict }
extension AppFilesManifestScope {
    var conflictAlternate: String { "保留副本 [#; $].bin" }
    func conflictFinalPayloads() -> [(relative: String, bytes: Int, fresh: Bool)] {
        payloads.map { ($0.relative, $0.bytes, false) } + [(conflictAlternate, 4096, true)]
    }
    func allowsConflictRisk(_ bytes: Data) -> Bool {
        exactTransferRisk(bytes) || bytes == Data((root + "/" + tree + "/" + conflictAlternate).utf8)
    }
}
#if HOST_PROBE
/// A pre-admission phase may acquire handles before its returned job ID is available.
/// Binding is one-shot; each handle/stream carries its captured phase, never the latest label.
struct AppFilesConflictPhaseOwner: Equatable, Sendable {
    let phaseID: UUID, label: String
    let jobID: UUID?, generation: UUID?
}
struct AppFilesConflictPhaseLedger: Sendable {
    private(set) var owners: [AppFilesConflictPhaseOwner] = []
    private(set) var active: UUID?
    mutating func begin(_ label: String, liveHandles: Int) throws -> UUID {
        guard active == nil, liveHandles == 0, ["seed", "fresh", "verify"].contains(label), !owners.contains(where: { $0.label == label }) else { throw AppNativeFiniteFailure.operation }
        let id = UUID(); owners.append(.init(phaseID: id, label: label, jobID: nil, generation: nil)); active = id; return id
    }
    mutating func bind(_ id: UUID, jobID: UUID, generation: UUID) throws {
        guard active == id, let index = owners.firstIndex(where: { $0.phaseID == id && $0.label != "verify" }), owners[index].jobID == nil,
              !owners.contains(where: { $0.jobID == jobID }) else { throw AppNativeFiniteFailure.operation }
        owners[index] = .init(phaseID: id, label: owners[index].label, jobID: jobID, generation: generation)
    }
    mutating func finish(_ id: UUID, liveHandles: Int) throws {
        guard active == id, liveHandles == 0, let owner = owners.first(where: { $0.phaseID == id }),
              owner.label == "verify" || (owner.jobID != nil && owner.generation != nil) else { throw AppNativeFiniteFailure.operation }; active = nil
    }
}
struct AppFilesConflictStream: Encodable, Sendable {
    let phaseID: UUID, value: AppFilesManifestStream
    func encode(to encoder: any Encoder) throws {
        var row = encoder.unkeyedContainer(); try row.encode(phaseID); try row.encode(value)
    }
}
struct AppFilesConflictItem: Encodable, Sendable {
    let source: String, destination: String, state: String, bytes: UInt64, risks: Int
    func encode(to encoder: any Encoder) throws {
        var row = encoder.unkeyedContainer(); try row.encode(source); try row.encode(destination); try row.encode(state); try row.encode(bytes); try row.encode(risks)
    }
}
struct AppFilesConflictJob: Encodable, Sendable {
    let phaseID: UUID, id: UUID, generation: UUID, planID: UUID, batchID: UUID
    let state: String, transferredBytes: UInt64, items: [AppFilesConflictItem]
    let remoteDelta: AppFilesManifestIO, localDelta: AppFilesManifestIO, streams: [AppFilesConflictStream]
    // Conflict wire v1 fixed job columns retain the phase once for its immutable streams.
    func encode(to encoder: any Encoder) throws {
        guard streams.allSatisfy({ $0.phaseID == phaseID }) else { throw AppNativeFiniteFailure.reportWrite }
        var row = encoder.unkeyedContainer()
        try row.encode(phaseID); try row.encode(id); try row.encode(generation); try row.encode(planID); try row.encode(batchID)
        try row.encode(state); try row.encode(transferredBytes); try row.encode(items); try row.encode(remoteDelta); try row.encode(localDelta)
        try row.encode(streams.map { $0.value })
    }
}
struct AppFilesConflictDecision: Encodable, Sendable {
    let id: UUID, jobID: UUID, generation: UUID, batchID: UUID, phaseID: UUID
    let source: String, destination: String, strategy: String, applyToBatch: Bool
    func encode(to encoder: any Encoder) throws {
        var row = encoder.unkeyedContainer()
        try row.encode(id); try row.encode(jobID); try row.encode(generation); try row.encode(batchID); try row.encode(phaseID)
        try row.encode(source); try row.encode(destination); try row.encode(strategy); try row.encode(applyToBatch)
    }
}
struct AppFilesConflictPlan: Encodable {
    let value: AppFilesManifestPlanEvidence
    init(_ value: AppFilesManifestPlanEvidence) { self.value = value }
    func encode(to encoder: any Encoder) throws {
        var row = encoder.unkeyedContainer()
        try row.encode(value.planID); try row.encode(value.reviewID); try row.encode(value.serviceID); try row.encode(value.hostID)
        try row.encode(value.lifetime); try row.encode(value.revision); try row.encode(value.direction)
        try row.encode(value.sourceBase64); try row.encode(value.destinationBase64); try row.encode(value.itemCount)
        try row.encode(value.fileCount); try row.encode(value.directoryCount); try row.encode(value.totalBytes); try row.encode(value.namesBase64)
        try row.encode(value.remoteDelta); try row.encode(value.localDelta); try row.encode(value.jobsBefore); try row.encode(value.jobsAfter); try row.encode(value.confirmCalls)
    }
}
struct AppFilesConflictReport: Encodable {
    let schema = 1, wireVersion = 1, kind = "HostProbe-App-Files-manifest-conflict", scenario = AppFilesConflictContract.scenario
    let acceptanceScope = "logical-App-real-SFTP-conflict-not-GUI-or-batch-propagation"
    let guiVerified = false, batchPropagationVerified = false, shellSessions = 0, rescueAttempts = 0
    let runID: String, pid: Int32, checkpoint: String, elapsedSeconds: Double
    let passed: Bool, failureCode: AppNativeFiniteFailure?, transferOnly: Bool, closedAndClean: Bool, localStoreRemoved: Bool
    let nonce: String, sourceKeyUnchanged: Bool, fixtureKnownHostsUnchanged: Bool, trustMatchedOutOfBand: Bool, credentialCalls: Int
    let capability: AppFilesManifestCapability?, plans: [AppFilesConflictPlan], jobs: [AppFilesConflictJob], decisions: [AppFilesConflictDecision]
    let seed: [AppFilesManifestDigest], fresh: [AppFilesManifestDigest], remoteVerified: [AppFilesManifestDigest], verificationPhaseID: UUID?
    let verificationStreams: [AppFilesConflictStream]
    let services: AppFilesManifestServiceFacts, managerClosed: Bool, managerDrained: Bool, managerJobs: Int, managerOperations: Int
    let remoteRootRemoved: Bool, localPayloadRemoved: Bool, deletePlanIDs: [UUID]
    let descriptors: AppFilesManifestDescriptorEvidence, descriptorIdentityMatched: Bool, quit: AppNativeFiniteQuitAudit
}
#endif

#if HOST_PROBE
enum AppFilesConflictOutcome {
    static func validate(state: TransferJobState, bytes: UInt64, files: Int, directories: Int, skipped: Int, fresh: Bool) throws {
        guard state == (fresh ? .completedWithSkips : .succeeded), bytes == (fresh ? 4096 : 12288), files == (fresh ? 1 : 2),
              directories == 2, skipped == (fresh ? 1 : 0) else { throw AppNativeFiniteFailure.operation }
    }
}
#endif

#if HOST_PROBE
import CryptoKit
enum AppFilesConflictPayload {
    static func data(relative: String, size: Int) -> Data {
        let seed = Data(SHA256.hash(data: Data(("OpenLXSSH non-secret Files conflict Fresh " + relative).utf8)))
        var bytes = Data(); while bytes.count < size { bytes.append(seed.prefix(min(seed.count, size - bytes.count))) }; return bytes
    }
}
#endif


// Cancel/retry R6 is independent; all prior passed contracts and wire types stay byte-for-byte above.
enum AppFilesCancelArguments {
    enum Action: Equatable { case none, help, validate, live }
    struct Options: Equatable { let action: Action; let contractPath: String? }
    static let help = """
    HostProbe-only controlled-local-read cancellation then explicit manifest retry; no natural-speed/native-blocked-I/O claim.
    --native-files-cancel-help
    --native-files-cancel-validate --native-files-cancel-contract <exact/native-files-cancel.json>
    --native-files-cancel-test --native-files-cancel-contract <exact owned path> --authorized-local-fixture --primary-released
    No download/overwrite/outage/reconnect. Flags grant no authorization; validate is syntax-only.
    """
    static func parse(_ arguments: [String], hostProbe: Bool) throws -> Options {
        guard arguments.contains(where: { $0.hasPrefix("--native-files-cancel") }) else { return .init(action: .none, contractPath: nil) }
        guard hostProbe else { throw AppNativeFiniteFailure.arguments }
        if arguments == ["--native-files-cancel-help"] { return .init(action: .help, contractPath: nil) }
        guard let first = arguments.first, ["--native-files-cancel-test", "--native-files-cancel-validate"].contains(first) else { throw AppNativeFiniteFailure.arguments }
        var path: String?, authorized = false, released = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--native-files-cancel-contract":
                guard path == nil, index + 1 < arguments.count else { throw AppNativeFiniteFailure.arguments }
                index += 1; path = arguments[index]; _ = try AppFilesCancelContract.runID(at: arguments[index])
            case "--authorized-local-fixture": guard !authorized else { throw AppNativeFiniteFailure.arguments }; authorized = true
            case "--primary-released": guard !released else { throw AppNativeFiniteFailure.arguments }; released = true
            default: throw AppNativeFiniteFailure.arguments
            }
            index += 1
        }
        guard let path else { throw AppNativeFiniteFailure.arguments }
        if first == "--native-files-cancel-validate" {
            guard !authorized, !released else { throw AppNativeFiniteFailure.arguments }; return .init(action: .validate, contractPath: path)
        }
        guard authorized, released else { throw AppNativeFiniteFailure.authorization }; return .init(action: .live, contractPath: path)
    }
}
struct AppFilesCancelContract: Equatable, Sendable {
    static let leaf = "native-files-cancel.json", scenario = "keyonly-direct-sftp-manifest-cancel-retry"
    let schema: Int, runID: String, materialContractPath: String
    static func runID(at path: String) throws -> String {
        try AppRealIntegrationContract.pathSyntax(path)
        let prefix = AppNativeFiniteContract.inputRoot + "/run-", suffix = "/" + leaf
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw AppNativeFiniteFailure.contract }
        let id = String(path.dropFirst(prefix.count).dropLast(suffix.count))
        guard AppNativeFiniteContract.canonicalID(id), path == prefix + id + suffix else { throw AppNativeFiniteFailure.contract }; return id
    }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["schema", "runID", "scenario", "materialContractPath"], limit: 4096)
        guard try AppNativePasswordJSON.integer(value, "schema") == 1, try AppNativePasswordJSON.string(value, "scenario") == scenario else { throw AppNativeFiniteFailure.contract }
        return Self(schema: 1, runID: try AppNativePasswordJSON.string(value, "runID"), materialContractPath: try AppNativePasswordJSON.string(value, "materialContractPath"))
    }
    func validate(path: String) throws {
        guard schema == 1, try Self.runID(at: path) == runID,
              try AppFilesManifestContract.id(at: materialContractPath, leaf: AppFilesManifestContract.materialLeaf) == runID else { throw AppNativeFiniteFailure.contract }
    }
}
enum AppFilesRunMode: Equatable, Sendable { case roundtrip, conflict, cancelRetry }
extension AppFilesManifestScope {
    func payloads(for mode: AppFilesRunMode) -> [(relative: String, bytes: Int)] {
        mode == .cancelRetry ? [(payloads[0].relative, 4096), (payloads[1].relative, 262144)] : payloads
    }
}
#if HOST_PROBE
struct AppFilesCancelGateFacts: Encodable, Sendable {
    let phaseID: UUID?, readCalls: Int, forwardedReads: Int, arrived: Bool, waiting: Bool
    let localCancellationObserved: Bool, aborted: Bool
}
/// Consumer scheduling only, never a product pause. The exact second local read waits
/// before entering LocalFileService; cancellation throws locally, with the same token.
final class AppFilesCancelReadGate: @unchecked Sendable {
    private let lock = NSLock()
    private var phase: UUID?, path: Data?, deadline: ContinuousClock.Instant?
    private var reads = 0, forwarded = 0, arrived = false, waiting = false, cancelled = false, aborted = false
    private func held<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }
    func arm(phaseID: UUID, path: Data, deadline: ContinuousClock.Instant) throws {
        try held { guard phase == nil, !aborted else { throw AppNativeFiniteFailure.operation }; phase = phaseID; self.path = path; self.deadline = deadline }
    }
    func beforeRead(path: Data, phaseID: UUID?, token: CancellationToken) async throws {
        let pause = try held { () throws -> Bool in
            guard self.path == path, phase == phaseID, !cancelled else { return false }
            guard !aborted, reads < 2 else { throw FileServiceError(.cancelled, operation: "consumer-local-read-gate") }
            reads += 1
            if reads == 1 { forwarded += 1; return false }
            arrived = true; waiting = true; return true
        }
        guard pause else { return }
        defer { held { waiting = false } }
        while true {
            if token.isCancelled { held { cancelled = true }; try token.check() }
            let state = held { (aborted, deadline) }
            guard !state.0 else { throw FileServiceError(.cancelled, operation: "consumer-local-gate-aborted") }
            guard let deadline = state.1, ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "consumer-local-gate-deadline") }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func abortIfWaiting() { held { if waiting { aborted = true } } }
    func snapshot() -> AppFilesCancelGateFacts { held { .init(phaseID: phase, readCalls: reads, forwardedReads: forwarded, arrived: arrived, waiting: waiting, localCancellationObserved: cancelled, aborted: aborted) } }
}
struct AppFilesCancelPhaseLedger: Sendable {
    private(set) var owners: [AppFilesConflictPhaseOwner] = []
    private(set) var active: UUID?
    mutating func begin(_ label: String, liveHandles: Int) throws -> UUID {
        guard active == nil, liveHandles == 0, ["attempt", "retry", "verify"].contains(label), !owners.contains(where: { $0.label == label }) else { throw AppNativeFiniteFailure.operation }
        let id = UUID(); owners.append(.init(phaseID: id, label: label, jobID: nil, generation: nil)); active = id; return id
    }
    mutating func bind(_ id: UUID, jobID: UUID, generation: UUID) throws {
        guard active == id, let i = owners.firstIndex(where: { $0.phaseID == id && $0.label != "verify" }), owners[i].jobID == nil,
              !owners.contains(where: { $0.jobID == jobID || $0.generation == generation }) else { throw AppNativeFiniteFailure.operation }
        owners[i] = .init(phaseID: id, label: owners[i].label, jobID: jobID, generation: generation)
    }
    mutating func finish(_ id: UUID, liveHandles: Int) throws {
        guard active == id, liveHandles == 0, let owner = owners.first(where: { $0.phaseID == id }),
              owner.label == "verify" || (owner.jobID != nil && owner.generation != nil) else { throw AppNativeFiniteFailure.operation }; active = nil
    }
}
struct AppFilesCancelItem: Encodable, Sendable {
    let source: String, destination: String, state: String, bytes: UInt64, error: String?, risks: Int, retained: String?
    func encode(to encoder: any Encoder) throws {
        var row = encoder.unkeyedContainer(); try row.encode(source); try row.encode(destination); try row.encode(state); try row.encode(bytes)
        try row.encode(error); try row.encode(risks); try row.encode(retained)
    }
}
struct AppFilesCancelJob: Encodable, Sendable {
    let phaseID: UUID, id: UUID, generation: UUID, planID: UUID, batchID: UUID, retryOf: UUID?
    let state: String, bytes: UInt64, error: String?, items: [AppFilesCancelItem], retained: [String]
    let remoteDelta: AppFilesManifestIO, localDelta: AppFilesManifestIO, streams: [AppFilesConflictStream]
    func encode(to encoder: any Encoder) throws {
        guard streams.allSatisfy({ $0.phaseID == phaseID }) else { throw AppNativeFiniteFailure.reportWrite }
        var row = encoder.unkeyedContainer()
        try row.encode(phaseID); try row.encode(id); try row.encode(generation); try row.encode(planID); try row.encode(batchID); try row.encode(retryOf)
        try row.encode(state); try row.encode(bytes); try row.encode(error); try row.encode(items); try row.encode(retained)
        try row.encode(remoteDelta); try row.encode(localDelta); try row.encode(streams.map { $0.value })
    }
}
struct AppFilesCancelPoint: Encodable {
    let phaseID: UUID, jobID: UUID, generation: UUID, transferredBytes: UInt64, remoteWrittenBytes: UInt64, firstCommitted: Bool
}
struct AppFilesCancelReport: Encodable {
    let schema = 1, wireVersion = 1, kind = "HostProbe-App-Files-manifest-cancel-retry", scenario = AppFilesCancelContract.scenario
    let acceptanceScope = "controlled-local-read-scheduling-real-bytes-not-natural-catch-or-native-blocked-I/O"
    let guiVerified = false, nativeBlockedIOVerified = false, naturalCatchVerified = false, shellSessions = 0, rescueAttempts = 0
    let runID: String, pid: Int32, checkpoint: String, elapsedSeconds: Double
    let passed: Bool, failureCode: AppNativeFiniteFailure?, transferOnly: Bool, closedAndClean: Bool, localStoreRemoved: Bool
    let nonce: String, sourceKeyUnchanged: Bool, fixtureKnownHostsUnchanged: Bool, trustMatchedOutOfBand: Bool, credentialCalls: Int
    let capability: AppFilesManifestCapability?, plans: [AppFilesConflictPlan], jobs: [AppFilesCancelJob]
    let gate: AppFilesCancelGateFacts, cancelPoint: AppFilesCancelPoint?, partialVerified: AppFilesManifestDigest?, secondAbsentAfterCancel: Bool
    let source: [AppFilesManifestDigest], remoteVerified: [AppFilesManifestDigest], verificationPhaseID: UUID?, verificationStreams: [AppFilesConflictStream]
    let services: AppFilesManifestServiceFacts, managerClosed: Bool, managerDrained: Bool, managerJobs: Int, managerOperations: Int
    let remoteRootRemoved: Bool, localPayloadRemoved: Bool, deletePlanIDs: [UUID]
    let descriptors: AppFilesManifestDescriptorEvidence, descriptorIdentityMatched: Bool, quit: AppNativeFiniteQuitAudit
}
#endif

#if HOST_PROBE
/// Exact current mailbox guard shared by the real consumer and its regression.
enum AppFilesCurrentDecision {
    static func matches(_ jobs: [TransferJobSnapshot], jobID: UUID, generation: UUID, decision: TransferDecisionRequest) -> Bool {
        guard decision.jobID == jobID, decision.generation == generation, let current = jobs.first(where: { $0.id == jobID }) else { return false }
        return current.id == jobID && current.generation == generation && current.state.isActive && !current.cancellationRequested && current.pendingDecision == decision
    }
}
#endif

// Trust M3 is a separate closed consumer; no preceding case/parser/validator is widened.
enum AppTrustScenario: String, Codable, CaseIterable, Sendable {
    case once = "keyonly-trust-once2", persistent = "keyonly-trust-persist2", changed = "keyonly-trust-changed1"
    var attempts: Int { self == .changed ? 1 : 2 }
}
enum AppTrustArguments {
    enum Action: Equatable { case none, help, validate, live }
    struct Options: Equatable { let action: Action; let contractPath: String? }
    static let help = """
    HostProbe-only exact App trust once2/persist2/changed1. No GUI/EOF/default-backend acceptance.
    --native-trust-fixture-help
    --native-trust-fixture-validate --native-trust-fixture-contract <exact/native-trust-fixture.json>
      Syntax only; no file, AppKit, credential, process or network access.
    --native-trust-fixture-test --native-trust-fixture-contract <exact owned path> --authorized-local-fixture --primary-released
      Separately released existing keyonly fixture only. No rotation, replacement or secret override.
    """
    static func parse(_ arguments: [String], hostProbe: Bool) throws -> Options {
        guard arguments.contains(where: { $0.hasPrefix("--native-trust-fixture") }) else { return .init(action: .none, contractPath: nil) }
        guard hostProbe else { throw AppNativeFiniteFailure.arguments }
        if arguments == ["--native-trust-fixture-help"] { return .init(action: .help, contractPath: nil) }
        guard let first = arguments.first, ["--native-trust-fixture-test", "--native-trust-fixture-validate"].contains(first) else { throw AppNativeFiniteFailure.arguments }
        var path: String?, authorized = false, released = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--native-trust-fixture-contract":
                guard path == nil, index + 1 < arguments.count else { throw AppNativeFiniteFailure.arguments }
                index += 1; path = arguments[index]; _ = try AppTrustContract.runID(at: arguments[index])
            case "--authorized-local-fixture": guard !authorized else { throw AppNativeFiniteFailure.arguments }; authorized = true
            case "--primary-released": guard !released else { throw AppNativeFiniteFailure.arguments }; released = true
            default: throw AppNativeFiniteFailure.arguments
            }
            index += 1
        }
        guard let path else { throw AppNativeFiniteFailure.arguments }
        if first == "--native-trust-fixture-validate" {
            guard !authorized, !released else { throw AppNativeFiniteFailure.arguments }; return .init(action: .validate, contractPath: path)
        }
        guard authorized, released else { throw AppNativeFiniteFailure.authorization }; return .init(action: .live, contractPath: path)
    }
}
struct AppTrustContract: Equatable, Sendable {
    static let leaf = "native-trust-fixture.json", materialLeaf = "native-trust-material.json"
    let schema: Int, runID: String, scenario: AppTrustScenario, materialContractPath: String
    static func id(at path: String, leaf: String) throws -> String {
        try AppRealIntegrationContract.pathSyntax(path)
        let prefix = AppNativeFiniteContract.inputRoot + "/run-", suffix = "/" + leaf
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw AppNativeFiniteFailure.contract }
        let id = String(path.dropFirst(prefix.count).dropLast(suffix.count))
        guard AppNativeFiniteContract.canonicalID(id), path == prefix + id + suffix else { throw AppNativeFiniteFailure.contract }; return id
    }
    static func runID(at path: String) throws -> String { try id(at: path, leaf: leaf) }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["schema", "runID", "scenario", "materialContractPath"], limit: 4096)
        guard try AppNativePasswordJSON.integer(value, "schema") == 1,
              let scenario = AppTrustScenario(rawValue: try AppNativePasswordJSON.string(value, "scenario")) else { throw AppNativeFiniteFailure.contract }
        return Self(schema: 1, runID: try AppNativePasswordJSON.string(value, "runID"), scenario: scenario,
                    materialContractPath: try AppNativePasswordJSON.string(value, "materialContractPath"))
    }
    func validate(path: String) throws {
        guard schema == 1, try Self.runID(at: path) == runID,
              try Self.id(at: materialContractPath, leaf: Self.materialLeaf) == runID else { throw AppNativeFiniteFailure.contract }
    }
}
/// Reuse only the approved public keyonly schema, not another consumer's path/pin validator.
struct AppTrustMaterial: Equatable, Sendable {
    let binding: AppFilesManifestMaterial
    static func decodeStrict(_ bytes: Data) throws -> Self { Self(binding: try AppFilesManifestMaterial.decodeStrict(bytes)) }
    func validate(path: String, now: Double, buildEpoch: Double) throws {
        let value = binding
        guard try AppTrustContract.id(at: path, leaf: AppTrustContract.materialLeaf) == value.runID, value.schema == 1,
              value.host == "127.0.0.1", value.port == 22221, value.user == "fixture", value.service == "keyonly",
              value.expectedBase == AppNativeFiniteIdentity.base, value.expectedImage == AppNativeFiniteIdentity.image,
              value.expectedProject == AppNativeFiniteIdentity.project, value.expectedContainer == AppNativeFiniteIdentity.container,
              value.expectedFingerprint == AppNativeFiniteIdentity.fingerprint,
              [value.provenanceSHA256, value.knownHostsSHA256, value.generationPublicKeySHA256].allSatisfy({ AppRealIntegrationContract.hex($0, count: 64) }) else { throw AppNativeFiniteFailure.contract }
        guard value.collectedAt.isFinite, value.preparedAt.isFinite, now.isFinite, buildEpoch.isFinite, buildEpoch > 0,
              value.collectedAt >= buildEpoch, value.preparedAt >= value.collectedAt, now >= value.preparedAt,
              now - value.collectedAt <= 120 else { throw AppNativeFiniteFailure.staleMaterial }
        try AppRealIntegrationContract.pathSyntax(value.generation)
        let prefix = AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-"
        guard value.generation.hasPrefix(prefix), AppRealIntegrationContract.hex(String(value.generation.dropFirst(prefix.count)), count: 12) else { throw AppNativeFiniteFailure.contract }
    }
}

#if HOST_PROBE
enum AppTrustPublicPin {
    // Existing public test fixture only. No server/private-key generation or replacement.
    static let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C"
    static var fingerprint: String {
        let blob = Data(base64Encoded: String(line.split(separator: " ")[1]))!
        return "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}
/// Only public known_hosts bytes can enter this model. Missing has no fictitious empty digest.
struct AppTrustPublicBytes: Codable, Equatable, Sendable {
    let presence: String, bytes: Int?, sha256: String?
    static let missing = Self(presence: "missing", bytes: nil, sha256: nil)
    func validate() throws {
        if presence == "missing" { guard bytes == nil, sha256 == nil else { throw AppNativeFiniteFailure.trustMismatch }; return }
        guard presence == "present", let bytes, bytes > 0, bytes <= 16384, let sha256,
              AppRealIntegrationContract.hex(sha256, count: 64) else { throw AppNativeFiniteFailure.trustMismatch }
    }
}
struct AppTrustStorePoint: Codable, Equatable, Sendable {
    let label: String, records: Int, publicBytes: AppTrustPublicBytes
}
struct AppTrustOwner: Codable, Equatable, Sendable {
    let tabID: UUID, sessionID: UUID
    let generation: UInt64
}
struct AppTrustRequestPoint: Codable, Sendable {
    let stage: String
    let requestID: UUID?
}
struct AppTrustChangedFact: Codable, Equatable, Sendable {
    let expectedFingerprint: String, presentedFingerprint: String
    let exactEndpoint: Bool, exactAlgorithm: Bool
}
struct AppTrustPreAcceptance: Codable, Sendable {
    let primaryCalls: Int, keyboardCalls: Int, shellSessions: Int, pendingCalls: Int
    let pendingRequestID: UUID?
    func validate(promptID: UUID) throws {
        guard primaryCalls == 0, keyboardCalls == 0, shellSessions == 0, pendingCalls == 1,
              pendingRequestID == promptID else { throw AppNativeFiniteFailure.unexpectedAuthentication }
    }
}
struct AppTrustAttemptFacts: Encodable, Sendable {
    let attemptID: UUID, ordinal: Int
    var connectionCalls = 0, primaryCalls = 0, keyboardCalls = 0, pendingCalls = 0, changedCallbacks = 0, shellSessions = 0
    var primarySessionID: UUID?, primaryRequestID: UUID?, pendingRequestID: UUID?
    /// changed is exclusively the NativeShellError.changedHostKey fact, never a callback substitute.
    var authentication: AppNativeFiniteAuthFacts?, changed: AppTrustChangedFact?, callbackChanged: AppTrustChangedFact?
    var preAcceptanceProviderZero: AppTrustPreAcceptance?
    var stages: [String] = [], requests: [AppTrustRequestPoint] = [], errorKind: String?, errorOperation: String?
    var observationFailed = false
    mutating func capturePreAcceptance(promptID: UUID) throws {
        guard preAcceptanceProviderZero == nil, !observationFailed else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        let point = AppTrustPreAcceptance(primaryCalls: primaryCalls, keyboardCalls: keyboardCalls, shellSessions: shellSessions,
            pendingCalls: pendingCalls, pendingRequestID: pendingRequestID)
        preAcceptanceProviderZero = point // Preserve the actual failing sample too.
        try point.validate(promptID: promptID)
    }
    mutating func recordCallbackChange(_ fact: AppTrustChangedFact) {
        if callbackChanged != nil || (changed != nil && changed != fact) { observationFailed = true }
        callbackChanged = fact
    }
    mutating func recordTypedChange(_ fact: AppTrustChangedFact) {
        if changed != nil || (callbackChanged != nil && callbackChanged != fact) { observationFailed = true }
        changed = fact
    }
    mutating func primary(sessionID: UUID, requestID: UUID) {
        primaryCalls += 1; request(stage: "primary", id: requestID)
        if primarySessionID != nil || primaryRequestID != nil { observationFailed = true }
        primarySessionID = sessionID; primaryRequestID = requestID
    }
    mutating func request(stage: String, id: UUID?) {
        guard requests.count < 8 else { observationFailed = true; return }
        requests.append(.init(stage: stage, requestID: id))
    }
}
/// Prefix validation permits an early per-attempt receipt, never overall resource acceptance.
enum AppTrustAcceptance {
    static func validate(_ scenario: AppTrustScenario, facts: [AppTrustAttemptFacts], owners: [AppTrustOwner],
                         beforeInitialization: AppTrustPublicBytes, points: [AppTrustStorePoint]) throws {
        try beforeInitialization.validate()
        guard beforeInitialization == .missing, !facts.isEmpty, facts.count <= scenario.attempts, owners.count == facts.count,
              Set(facts.map(\.attemptID)).count == facts.count, Set(owners.map(\.tabID)).count == owners.count,
              Set(owners.map(\.sessionID)).count == owners.count,
              owners.allSatisfy({ $0.generation == 1 }), let initial = points.first, initial.label == "initialized", initial.records == 0 else { throw AppNativeFiniteFailure.trustMismatch }
        try initial.publicBytes.validate()
        guard initial.publicBytes.presence == "present" else { throw AppNativeFiniteFailure.trustMismatch }
        let offset = scenario == .changed ? 2 : 1
        guard points.count == facts.count + offset else { throw AppNativeFiniteFailure.trustMismatch }
        if scenario == .changed {
            guard points[1].label == "seeded-wrong-public-pin", points[1].records == 1,
                  points[1].publicBytes != initial.publicBytes else { throw AppNativeFiniteFailure.trustMismatch }
            try points[1].publicBytes.validate()
        }
        for (index, value) in facts.enumerated() {
            let point = points[index + offset]
            try point.publicBytes.validate()
            guard value.ordinal == index + 1, value.connectionCalls == 1, value.keyboardCalls == 0, !value.observationFailed,
                  point.label == "attempt-\(index + 1)", point.publicBytes.presence == "present" else { throw AppNativeFiniteFailure.unexpectedAuthentication }
            if scenario == .changed {
                guard value.pendingCalls == 0, value.pendingRequestID == nil, value.primaryCalls == 0,
                      value.primarySessionID == nil, value.primaryRequestID == nil, value.shellSessions == 0, value.authentication == nil,
                      value.errorKind == "untrusted", value.errorOperation == "host-key", value.stages.isEmpty,
                      (0...1).contains(value.changedCallbacks),
                      value.requests.map(\.stage) == Array(repeating: "changed", count: value.changedCallbacks),
                      value.requests.allSatisfy({ $0.requestID == nil }),
                      value.preAcceptanceProviderZero == nil, let changed = value.changed,
                      value.changedCallbacks == 0 ? value.callbackChanged == nil : value.callbackChanged == changed,
                      changed.exactEndpoint, changed.exactAlgorithm, changed.expectedFingerprint == AppTrustPublicPin.fingerprint,
                      changed.expectedFingerprint != changed.presentedFingerprint, changed.presentedFingerprint == AppNativeFiniteIdentity.fingerprint,
                      point.records == 1, point.publicBytes == points[1].publicBytes else { throw AppNativeFiniteFailure.trustMismatch }
            } else {
                let pending = scenario == .once || index == 0 ? 1 : 0
                guard value.pendingCalls == pending, (value.pendingRequestID != nil) == (pending == 1), value.changedCallbacks == 0,
                      value.changed == nil, value.callbackChanged == nil, value.primaryCalls == 1, value.primarySessionID != nil, value.primaryRequestID != nil,
                      value.shellSessions == 1, let auth = value.authentication, auth.primaryMethod == "publicKey",
                      auth.primaryStarted == 1, auth.primaryResults == 1, auth.primaryCode == 0, auth.primaryAuthenticated,
                      auth.authenticatedEvents == 1, auth.shellReadyEvents == 1, value.errorKind == nil, value.errorOperation == nil,
                      value.stages == ["advertised", "primaryStarted.publicKey", "primaryResult.publicKey", "authenticated", "shellReady"] else { throw AppNativeFiniteFailure.typedStages }
                if pending == 1 {
                    guard let point = value.preAcceptanceProviderZero, let promptID = value.pendingRequestID else { throw AppNativeFiniteFailure.unexpectedAuthentication }
                    try point.validate(promptID: promptID)
                } else { guard value.preAcceptanceProviderZero == nil else { throw AppNativeFiniteFailure.unexpectedAuthentication } }
                let requestStages = pending == 1 ? ["pending", "primary"] : ["primary"]
                guard value.requests.map(\.stage) == requestStages, value.requests.last?.requestID == value.primaryRequestID,
                      pending == 0 || value.requests.first?.requestID == value.pendingRequestID else { throw AppNativeFiniteFailure.unexpectedAuthentication }
                if scenario == .once {
                    guard point.records == 0, point.publicBytes == initial.publicBytes else { throw AppNativeFiniteFailure.trustMismatch }
                } else {
                    guard point.records == 1, point.publicBytes != initial.publicBytes,
                          index == 0 || point.publicBytes == points[offset].publicBytes else { throw AppNativeFiniteFailure.trustMismatch }
                }
            }
        }
        let primaryIDs = facts.compactMap(\.primaryRequestID), nativeIDs = facts.compactMap(\.primarySessionID), pendingIDs = facts.compactMap(\.pendingRequestID)
        guard Set(primaryIDs).count == primaryIDs.count, Set(nativeIDs).count == nativeIDs.count,
              Set(pendingIDs).count == pendingIDs.count else { throw AppNativeFiniteFailure.unexpectedAuthentication }
    }
    static func closeDeadline(now: ContinuousClock.Instant, active: ContinuousClock.Instant) -> ContinuousClock.Instant { min(now + .seconds(2), active) }
}
struct AppTrustWeakFacts: Encodable {
    let tabAlive: Bool, driverAlive: Bool, viewAlive: Bool
    var released: Bool { !tabAlive && !driverAlive && !viewAlive }
}
struct AppTrustAttemptReport: Encodable {
    let facts: AppTrustAttemptFacts, owner: AppTrustOwner?
    let terminal: AppNativeFiniteTerminalPlan.Evidence?, closeDisposition: String, canonicalDrained: Bool, queueEmpty: Bool
    let weakAfterClose: AppTrustWeakFacts?, weakNow: AppTrustWeakFacts?
}
struct AppTrustAuthenticationReceipt: Encodable {
    static func leaf(_ ordinal: Int) -> String { "native-trust-authentication-\(ordinal).json" }
    let schema = 1, kind = "HostProbe-App-trust-authentication", acceptanceScope = "trust-authentication-only-resources-unverified"
    let guiVerified = false, productRuntimeVerified = false
    let runID: String, pid: Int32, scenario: AppTrustScenario, ordinal: Int
    let beforeInitialization: AppTrustPublicBytes, points: [AppTrustStorePoint], facts: [AppTrustAttemptFacts], owners: [AppTrustOwner]
    let credentialCalls: Int
}
struct AppTrustReport: Encodable {
    let schema = 1, kind = "HostProbe-App-trust", acceptanceScope = "logical-App-trust-short-shell-not-GUI-EOF-or-default-backend"
    let guiVerified = false, productRuntimeVerified = false, eofEvidence = "notObserved", exitStatusEvidence = "notRequested"
    let runID: String, pid: Int32, scenario: AppTrustScenario, checkpoint: String, elapsedSeconds: Double
    let passed: Bool, failureCode: AppNativeFiniteFailure?, closedAndClean: Bool, localStoreRemoved: Bool, authenticationComplete: Bool
    let beforeInitialization: AppTrustPublicBytes?, points: [AppTrustStorePoint], attempts: [AppTrustAttemptReport]
    let sourceKeyScope: String, sourceKeyUnchanged: Bool?, fixtureKnownHostsUnchanged: Bool, credentialCalls: Int
    let descriptorBaseline: Int?, descriptorAfter: Int?, descriptorIdentityMatched: Bool, descriptors: AppFilesManifestDescriptorEvidence
    let registryBaselineActive: Int, registryBaselineRetired: Int, registryAfterActive: Int, registryAfterRetired: Int
    let quit: AppNativeFiniteQuitAudit
}
#endif

// Concurrent keyKI R1 is independent of every previously frozen single-case contract.
enum AppConcurrentArguments {
    enum Action: Equatable { case none, help, validate, live }
    struct Options: Equatable { let action: Action; let contractPath: String? }
    static let help = """
    HostProbe-only keyki-concurrent-cancel-a. Two exact App owners, no GUI/TUI/default/resource shortcut.
    --native-concurrent-fixture-help
    --native-concurrent-fixture-validate --native-concurrent-fixture-contract <exact/native-concurrent-fixture.json>
      Syntax only; no file, credentials, management, AppKit or network access.
    --native-concurrent-fixture-test --native-concurrent-fixture-contract <exact owned path> --authorized-local-fixture --primary-released
      Fixed approved key-kbd only. No fixture restart, unlink, sweep or authentication retry.
    """
    static func parse(_ arguments: [String], hostProbe: Bool) throws -> Options {
        guard arguments.contains(where: { $0.hasPrefix("--native-concurrent-fixture") }) else { return .init(action: .none, contractPath: nil) }
        guard hostProbe else { throw AppNativeFiniteFailure.arguments }
        if arguments == ["--native-concurrent-fixture-help"] { return .init(action: .help, contractPath: nil) }
        guard let first = arguments.first, ["--native-concurrent-fixture-test", "--native-concurrent-fixture-validate"].contains(first) else { throw AppNativeFiniteFailure.arguments }
        var path: String?, authorized = false, released = false, index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--native-concurrent-fixture-contract":
                guard path == nil, index + 1 < arguments.count else { throw AppNativeFiniteFailure.arguments }
                index += 1; path = arguments[index]; _ = try AppConcurrentContract.runID(at: arguments[index])
            case "--authorized-local-fixture": guard !authorized else { throw AppNativeFiniteFailure.arguments }; authorized = true
            case "--primary-released": guard !released else { throw AppNativeFiniteFailure.arguments }; released = true
            default: throw AppNativeFiniteFailure.arguments
            }
            index += 1
        }
        guard let path else { throw AppNativeFiniteFailure.arguments }
        if first == "--native-concurrent-fixture-validate" {
            guard !authorized, !released else { throw AppNativeFiniteFailure.arguments }; return .init(action: .validate, contractPath: path)
        }
        guard authorized, released else { throw AppNativeFiniteFailure.authorization }; return .init(action: .live, contractPath: path)
    }
}
struct AppConcurrentContract: Equatable, Sendable {
    static let leaf = "native-concurrent-fixture.json", materialLeaf = "native-concurrent-material.json", policyLeaf = "native-concurrent-policy.json"
    static let scenario = "keyki-concurrent-cancel-a"
    let schema: Int, runID: String, materialContractPath: String
    static func id(at path: String, leaf: String) throws -> String {
        guard [Self.leaf, materialLeaf, policyLeaf].contains(leaf) else { throw AppNativeFiniteFailure.contract }
        try AppRealIntegrationContract.pathSyntax(path)
        let prefix = AppNativeFiniteContract.inputRoot + "/run-", suffix = "/" + leaf
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw AppNativeFiniteFailure.contract }
        let id = String(path.dropFirst(prefix.count).dropLast(suffix.count))
        guard AppNativeFiniteContract.canonicalID(id), path == prefix + id + suffix else { throw AppNativeFiniteFailure.contract }; return id
    }
    static func runID(at path: String) throws -> String { try id(at: path, leaf: leaf) }
    static func decodeStrict(_ bytes: Data) throws -> Self {
        let value = try AppNativePasswordJSON.object(bytes, keys: ["schema", "runID", "scenario", "materialContractPath"], limit: 4096)
        guard try AppNativePasswordJSON.integer(value, "schema") == 1, try AppNativePasswordJSON.string(value, "scenario") == scenario else { throw AppNativeFiniteFailure.contract }
        return Self(schema: 1, runID: try AppNativePasswordJSON.string(value, "runID"), materialContractPath: try AppNativePasswordJSON.string(value, "materialContractPath"))
    }
    func validate(path: String) throws {
        guard schema == 1, try Self.runID(at: path) == runID,
              try Self.id(at: materialContractPath, leaf: Self.materialLeaf) == runID else { throw AppNativeFiniteFailure.contract }
    }
}
struct AppConcurrentMaterial: Equatable, Sendable {
    let binding: AppMFAMaterialContract
    static func decodeStrict(_ bytes: Data) throws -> Self { .init(binding: try AppMFAMaterialContract.decodeStrict(bytes, fixture: .keyKI)) }
    func validate(path: String, now: Double, buildEpoch: Double) throws {
        let value = binding
        guard try AppConcurrentContract.id(at: path, leaf: AppConcurrentContract.materialLeaf) == value.runID, value.fixture == .keyKI,
              value.schema == 1, value.host == "127.0.0.1", value.port == 22223, value.user == "fixture", value.service == "key-kbd", value.key == "edplain",
              value.expectedBase == AppNativePasswordIdentity.base, value.expectedImage == AppNativePasswordIdentity.image,
              value.expectedProject == AppNativePasswordIdentity.project, value.expectedContainer == AppMFAFixture.keyKI.container,
              value.expectedFingerprint == AppMFAFixture.keyKI.fingerprint, value.networkID == AppNativePasswordIdentity.network,
              value.context == AppNativePasswordIdentity.context, value.endpoint == AppNativePasswordIdentity.endpoint,
              [value.provenanceSHA256, value.knownHostsSHA256, value.policyProofSHA256].allSatisfy({ AppRealIntegrationContract.hex($0, count: 64) }),
              value.generationPublicKeySHA256.map({ AppRealIntegrationContract.hex($0, count: 64) }) == true else { throw AppNativeFiniteFailure.contract }
        guard value.collectedAt.isFinite, value.preparedAt.isFinite, now.isFinite, buildEpoch.isFinite, buildEpoch > 0,
              value.collectedAt >= buildEpoch, value.preparedAt >= value.collectedAt, now >= value.preparedAt, now - value.collectedAt <= 120 else { throw AppNativeFiniteFailure.staleMaterial }
        try AppRealIntegrationContract.pathSyntax(value.generation)
        let prefix = AppRealIntegrationContract.fixtureRoot + "/.runtime/key-kbd/credentials-"
        guard value.generation.hasPrefix(prefix), AppRealIntegrationContract.hex(String(value.generation.dropFirst(prefix.count)), count: 12) else { throw AppNativeFiniteFailure.contract }
    }
}
enum AppConcurrentRole: String, Codable, CaseIterable, Sendable { case a = "A", b = "B" }
struct AppConcurrentTicket: Equatable, Codable, Sendable {
    let id: UUID, hostID: UUID, appSessionID: UUID
}
/// Allocated by SessionBuilding.prepare(hostID:sessionID:), never connector arrival order/endpoint.
struct AppConcurrentTicketLedger: Sendable {
    private(set) var tickets: [AppConcurrentTicket] = []
    private var connected: Set<UUID> = [], primaryClaims: Set<UUID> = []
    mutating func prepare(hostID: UUID, appSessionID: UUID) throws -> AppConcurrentTicket {
        guard tickets.count < 2, !tickets.contains(where: { $0.appSessionID == appSessionID }),
              tickets.allSatisfy({ $0.hostID == hostID }) else { throw AppNativeFiniteFailure.unexpectedSession }
        let value = AppConcurrentTicket(id: UUID(), hostID: hostID, appSessionID: appSessionID); tickets.append(value); return value
    }
    mutating func connect(_ ticket: AppConcurrentTicket) throws {
        guard tickets.contains(ticket), !connected.contains(ticket.id) else { throw AppNativeFiniteFailure.unexpectedSession }
        connected.insert(ticket.id)
    }
    mutating func primary(_ ticket: AppConcurrentTicket) throws {
        guard tickets.contains(ticket), connected.contains(ticket.id), !primaryClaims.contains(ticket.id) else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        primaryClaims.insert(ticket.id)
    }
    func requireTwo() throws {
        guard tickets.count == 2, connected.count == 2, primaryClaims.count == 2 else { throw AppNativeFiniteFailure.unexpectedSession }
    }
}
struct AppConcurrentOwner: Equatable, Codable, Sendable {
    let role: AppConcurrentRole, ticketID: UUID, hostID: UUID, tabID: UUID, appSessionID: UUID, requestID: UUID
    let generation: UInt64
}
/// Only memory-only fixture identifiers bind these owners; no response/prompt/session text is Codable.
struct AppConcurrentFirstPair: Sendable {
    let a: AppConcurrentOwner, b: AppConcurrentOwner
    private let fixtureA: String, fixtureB: String
    private var replyB: AppConcurrentOwner?
    init(a: AppConcurrentOwner, b: AppConcurrentOwner, fixtureA: String, fixtureB: String) throws {
        guard a.role == .a, b.role == .b, a.hostID == b.hostID, a.ticketID != b.ticketID, a.tabID != b.tabID,
              a.appSessionID != b.appSessionID, a.requestID != b.requestID, a.generation == 1, b.generation == 1,
              a.tabID == a.appSessionID, b.tabID == b.appSessionID, fixtureA != fixtureB,
              AppRealIntegrationContract.hex(fixtureA, count: 24), AppRealIntegrationContract.hex(fixtureB, count: 24) else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        self.a = a; self.b = b; self.fixtureA = fixtureA; self.fixtureB = fixtureB
    }
    func requireB(_ owner: AppConcurrentOwner, fixture: String) throws {
        guard owner.role == .b, owner.ticketID == b.ticketID, owner.hostID == b.hostID, owner.tabID == b.tabID,
              owner.appSessionID == b.appSessionID, owner.generation == b.generation,
              fixture == fixtureB else { throw AppNativeFiniteFailure.unexpectedAuthentication }
    }
    mutating func beginB(_ owner: AppConcurrentOwner, fixture: String) throws {
        try requireB(owner, fixture: fixture)
        guard replyB == nil else { throw AppNativeFiniteFailure.unexpectedAuthentication }; replyB = owner
    }
    mutating func finishB(_ owner: AppConcurrentOwner, fixture: String) throws {
        try requireB(owner, fixture: fixture)
        guard replyB == owner else { throw AppNativeFiniteFailure.unexpectedAuthentication }; replyB = nil
    }
}
struct AppConcurrentManagementPlan: Sendable {
    let role: AppConcurrentRole
    private(set) var cancelled = false, responseReads = 0, statusReads = 0
    mutating func response(index: Int) throws {
        guard role == .b, !cancelled, responseReads == index, (0..<3).contains(index) else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        responseReads += 1
    }
    mutating func cancel() { cancelled = true }
    mutating func status() throws { guard cancelled, statusReads == 0 else { throw AppNativeFiniteFailure.cleanup }; statusReads = 1 }
}
struct AppConcurrentStatusFacts: Encodable, Sendable {
    let role: AppConcurrentRole, statusReads: Int, serverSessionStatus: AppMFAStatus, management: AppMFAManagementFacts
    func requireComplete() throws {
        let count = role == .a ? 1 : 4
        guard statusReads == 1, serverSessionStatus == .removed, management.calls == count,
              management.returnedCalls == count, management.successfulReapedCalls == count, management.pendingCalls == 0,
              management.cancellationRequested, management.reapEvidenceComplete else { throw AppNativeFiniteFailure.cleanup }
    }
}

#if HOST_PROBE
struct AppConcurrentNativeFacts: Encodable, Sendable {
    let ticket: AppConcurrentTicket
    var connectCalls = 0, primaryCalls = 0, keyboardCalls = 0, trustCallbacks = 0, shellSessions = 0
    var packageSessionID: UUID?, primaryRequestID: UUID?
    var stages: [String] = [], errorKind: String?, errorOperation: String?
    var aCancellation: AppConcurrentCancelledAuthentication?, bAuthentication: AppMFAAuthentication?
    var observationFailed = false
}
struct AppConcurrentCancelledAuthentication: Encodable, Sendable {
    let primaryMethod = "publicKey"
    let primaryCode: Int32 = -19
    let primaryAuthenticated = false
    let keyboardResultCode: Int32
    let keyboardAuthenticated = false, authenticatedEvents = 0, shellReadyEvents = 0
    init(_ stages: [NativeShellAuthenticationStage], errorKind: String?) throws {
        guard errorKind == "cancelled", stages.count == 5, case .advertised(_, let key, _) = stages[0], key,
              stages[1] == .primaryStarted(.publicKey), stages[2] == .primaryResult(.publicKey, code: -19, authenticated: false),
              stages[3] == .keyboardStarted, case .keyboardResult(let code, let authenticated) = stages[4], code != 0, !authenticated else { throw AppNativeFiniteFailure.typedStages }
        keyboardResultCode = code
    }
}
struct AppConcurrentIsolationFacts: Encodable, Sendable {
    let a: AppConcurrentOwner, b: AppConcurrentOwner
    let twoFirstPending: Bool, distinctDrivers: Bool, distinctPackageSessions: Bool, distinctFixtureSessions: Bool
    let tokensUncancelledAtFirstPair: Bool, aManagementReadsBeforeCancel: Int, bManagementReadsBeforeCancel: Int
    let crossReplyRejected: Bool, bPromptUnchangedAfterCross: Bool, lateReplyRejected: Bool, bOwnerUnchangedAfterACancel: Bool
    func requireComplete() throws {
        guard a.role == .a, b.role == .b, a.hostID == b.hostID, a.ticketID != b.ticketID, a.tabID != b.tabID,
              a.appSessionID != b.appSessionID, a.requestID != b.requestID, a.generation == 1, b.generation == 1,
              a.tabID == a.appSessionID, b.tabID == b.appSessionID,
              twoFirstPending, distinctDrivers, distinctPackageSessions, distinctFixtureSessions, tokensUncancelledAtFirstPair,
              aManagementReadsBeforeCancel == 0, bManagementReadsBeforeCancel == 0, crossReplyRejected, bPromptUnchangedAfterCross,
              lateReplyRejected, bOwnerUnchangedAfterACancel else { throw AppNativeFiniteFailure.unexpectedAuthentication }
    }
}
struct AppConcurrentAuthenticationReceipt: Encodable {
    static let leaf = "native-concurrent-authentication.json"
    let schema = 1, kind = "HostProbe-App-keyKI-concurrent-authentication", scenario = AppConcurrentContract.scenario
    let acceptanceScope = "two-App-owners-authentication-only-resources-unverified", guiVerified = false, productRuntimeVerified = false
    let runID: String, pid: Int32, isolation: AppConcurrentIsolationFacts, a: AppConcurrentNativeFacts, b: AppConcurrentNativeFacts
    let aKeyboard: AppMFAKIFacts, bKeyboard: AppMFAKIFacts, aBudgetClosed: Bool, credentialCalls: Int
}
struct AppConcurrentCleanupReceipt: Encodable {
    static let leaf = "native-concurrent-cleanup.json"
    let schema = 1, kind = "HostProbe-App-keyKI-concurrent-cleanup", scenario = AppConcurrentContract.scenario
    let acceptanceScope = "per-owner-management-status-only-resources-unverified"
    let runID: String, pid: Int32, a: AppConcurrentStatusFacts, b: AppConcurrentStatusFacts, passed: Bool
}
struct AppConcurrentLifecycle: Encodable {
    let role: AppConcurrentRole, owner: AppConcurrentOwner?, native: AppConcurrentNativeFacts
    let closeDisposition: String, canonicalDrained: Bool, queueEmpty: Bool, nativeClosed: Bool
    let weak: AppTrustWeakFacts?
}
struct AppConcurrentReport: Encodable {
    let schema = 1, kind = "HostProbe-App-keyKI-concurrent", scenario = AppConcurrentContract.scenario
    let acceptanceScope = "logical-App-two-owner-isolation-not-GUI-terminal-or-resource-shortcut"
    let guiVerified = false, productRuntimeVerified = false, terminalEvidence = "notExercised", eofEvidence = "notObserved"
    let runID: String, pid: Int32, checkpoint: String, elapsedSeconds: Double
    let passed: Bool, failureCode: AppNativeFiniteFailure?, authenticationComplete: Bool, cleanupComplete: Bool, closedAndClean: Bool, localStoreRemoved: Bool
    let a: AppConcurrentLifecycle?, b: AppConcurrentLifecycle?, isolation: AppConcurrentIsolationFacts?
    let aKeyboard: AppMFAKIFacts?, bKeyboard: AppMFAKIFacts?, managementA: AppConcurrentStatusFacts?, managementB: AppConcurrentStatusFacts?
    let sourceKeyUnchanged: Bool, fixtureKnownHostsUnchanged: Bool, approvedPinUnchanged: Bool, credentialCalls: Int
    let descriptors: AppFilesManifestDescriptorEvidence, descriptorIdentityMatched: Bool
    let registryBaselineActive: Int, registryBaselineRetired: Int, registryAfterActive: Int, registryAfterRetired: Int, quit: AppNativeFiniteQuitAudit
}
#endif
