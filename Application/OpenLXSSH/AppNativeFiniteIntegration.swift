#if HOST_PROBE
import AppKit
import CryptoKit
import Darwin
import Foundation
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTransport
import OpenLXSSHTrust

/// Adds held-FD identity checks around the unchanged App reader. No secret hash/description.
private final class AppNativeFiniteStableFile {
    let path: String
    private let fd: Int32
    private let original: stat
    init(_ path: String) throws {
        self.path = path
        let parent = try AppRealPrivateInput.directory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        defer { Darwin.close(parent) }
        fd = openat(parent, URL(fileURLWithPath: path).lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw AppNativeFiniteFailure.unsafeInput }
        var info = stat()
        do {
            try AppFileSecurity.regularFile(fd)
            guard fstat(fd, &info) == 0 else { throw AppNativeFiniteFailure.unsafeInput }
        } catch { Darwin.close(fd); throw error }
        original = info
    }
    deinit { Darwin.close(fd) }
    func check() throws {
        var current = stat()
        try AppFileSecurity.regularFile(fd)
        guard fstat(fd, &current) == 0, Self.same(original, current) else { throw AppNativeFiniteFailure.sourceChanged }
        let parent = try AppRealPrivateInput.directory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        defer { Darwin.close(parent) }
        let fresh = openat(parent, URL(fileURLWithPath: path).lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fresh >= 0 else { throw AppNativeFiniteFailure.sourceChanged }; defer { Darwin.close(fresh) }
        try AppFileSecurity.regularFile(fresh)
        var named = stat()
        guard fstat(fresh, &named) == 0, Self.same(original, named) else { throw AppNativeFiniteFailure.sourceChanged }
    }
    func read(limit: Int) throws -> Data {
        try check()
        var first = try AppRealPrivateInput.read(path, limit: limit)
        do {
            var second = try AppRealPrivateInput.read(path, limit: limit)
            defer { second.resetBytes(in: 0..<second.count) }
            try check()
            guard first == second else { throw AppNativeFiniteFailure.sourceChanged }
            return first
        } catch { first.resetBytes(in: 0..<first.count); throw error }
    }
    private static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid && a.st_gid == b.st_gid &&
        a.st_mode == b.st_mode && a.st_nlink == b.st_nlink && a.st_size == b.st_size &&
        a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
}

/// New consumer binding only. The old loader/validator/pins are untouched and are NOT called.
/// Public schema/path parsing and the mature FD reader are reused unchanged; no private digest.
fileprivate struct AppNativeFinitePublicMaterial {
    let contract: AppRealIntegrationContract
    let hostKeyLine: String
    static func load(_ path: String, buildEpoch: Double) throws -> Self {
        _ = try AppRealIntegrationContract.validateContractPath(path)
        let bytes = try AppRealPrivateInput.read(path, limit: 8192)
        let value = try AppRealIntegrationContract.decodeStrict(bytes)
        try AppNativeFiniteIdentity.validate(value, path: path, now: Date().timeIntervalSince1970, buildEpoch: buildEpoch)
        for directory in [AppRealIntegrationContract.inputRoot, URL(fileURLWithPath: path).deletingLastPathComponent().path,
                          AppRealIntegrationContract.fixtureRoot + "/.runtime", AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly", value.generation] {
            let fd = try AppRealPrivateInput.directory(directory); Darwin.close(fd)
        }
        func object(_ path: String, keys: Set<String>) throws -> [String: Any] {
            let data = try AppRealPrivateInput.read(path, limit: 4096)
            guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(result.keys) == keys else { throw AppNativeFiniteFailure.contract }
            return result
        }
        let state = try object(AppRealIntegrationContract.fixtureRoot + "/.runtime/state.json", keys: ["version", "project", "image"])
        guard state["version"] as? Int == 1, state["project"] as? String == value.expectedProject,
              state["image"] as? String == value.expectedBase else { throw AppNativeFiniteFailure.contract }
        let provenance = try AppRealPrivateInput.read(value.generation + "/provenance.json", limit: 4096)
        guard AppRealPrivateInput.sha(provenance) == value.provenanceSHA256,
              let origin = try JSONSerialization.jsonObject(with: provenance) as? [String: Any],
              Set(origin.keys) == ["base_image", "built_image_id", "service", "collected_at"],
              origin["base_image"] as? String == value.expectedBase, origin["built_image_id"] as? String == value.expectedImage,
              origin["service"] as? String == "keyonly", origin["collected_at"] as? Double == value.collectedAt else { throw AppNativeFiniteFailure.contract }
        let known = try AppRealPrivateInput.read(value.generation + "/known_hosts", limit: 4096)
        guard AppRealPrivateInput.sha(known) == value.knownHostsSHA256, let text = String(data: known, encoding: .utf8),
              text.hasSuffix("\n"), !text.dropLast().contains("\n") else { throw AppNativeFiniteFailure.trustMismatch }
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == "[127.0.0.1]:22221", fields[1] == "ssh-ed25519" else { throw AppNativeFiniteFailure.trustMismatch }
        let line = fields[1...2].joined(separator: " ")
        guard let blob = Data(base64Encoded: String(fields[2])), blob.count == 51,
              blob.base64EncodedString() == fields[2],
              "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast() == value.expectedFingerprint else {
            throw AppNativeFiniteFailure.trustMismatch
        }
        let publicKey = try AppRealPrivateInput.read(value.generation + "/id_ed25519.pub", limit: 4096)
        guard AppRealPrivateInput.sha(publicKey) == value.generationPublicKeySHA256 else { throw AppNativeFiniteFailure.contract }
        return Self(contract: value, hostKeyLine: line)
    }
}

fileprivate struct AppNativePasswordPublicMaterial {
    let contract: AppNativePasswordMaterialContract
    let hostKeyLine: String
    static func load(_ path: String, buildEpoch: Double) throws -> Self {
        _ = try AppNativePasswordContract.id(at: path, leaf: AppNativePasswordContract.materialLeaf)
        let held = try AppNativeFiniteStableFile(path)
        let value = try AppNativePasswordMaterialContract.decodeStrict(held.read(limit: 8192))
        try value.validate(path: path, now: Date().timeIntervalSince1970, buildEpoch: buildEpoch)
        for directory in [AppNativePasswordContract.inputRoot, URL(fileURLWithPath: path).deletingLastPathComponent().path,
                          AppRealIntegrationContract.fixtureRoot + "/.runtime", AppRealIntegrationContract.fixtureRoot + "/.runtime/passwordonly", value.generation] {
            let fd = try AppRealPrivateInput.directory(directory); Darwin.close(fd)
        }
        let state = try AppNativeFiniteStableFile(AppRealIntegrationContract.fixtureRoot + "/.runtime/state.json")
        try value.validateState(state.read(limit: 4096))
        let provenance = try AppNativeFiniteStableFile(value.generation + "/provenance.json")
        let provenanceBytes = try provenance.read(limit: 4096)
        guard AppRealPrivateInput.sha(provenanceBytes) == value.provenanceSHA256 else { throw AppNativeFiniteFailure.contract }
        try value.validateProvenance(provenanceBytes)
        let known = try AppNativeFiniteStableFile(value.generation + "/known_hosts")
        let bytes = try known.read(limit: 4096)
        guard AppRealPrivateInput.sha(bytes) == value.knownHostsSHA256, let text = String(data: bytes, encoding: .utf8),
              text.hasSuffix("\n"), !text.dropLast().contains("\n") else { throw AppNativeFiniteFailure.trustMismatch }
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == "[127.0.0.1]:22222", fields[1] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51, blob.base64EncodedString() == fields[2],
              "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast() == value.expectedFingerprint else {
            throw AppNativeFiniteFailure.trustMismatch
        }
        let line = fields[1...2].joined(separator: " ")
        guard try HostPublicKey(openSSHPublicKey: line).fingerprint == value.expectedFingerprint else { throw AppNativeFiniteFailure.trustMismatch }
        try held.check(); try state.check(); try provenance.check(); try known.check()
        return Self(contract: value, hostKeyLine: line)
    }
}

enum AppNativeFiniteRunScenario: Equatable, Sendable, Encodable {
    case keyonly, password, mfa(AppMFAFixture), files, filesConflict, filesCancel, trust(AppTrustScenario), concurrent
    var label: String {
        switch self { case .keyonly: AppNativeFiniteScenario.keyonly.rawValue; case .password: AppNativeFiniteScenario.password.rawValue; case .mfa(let fixture): fixture.rawValue; case .files: AppFilesManifestContract.scenarioName; case .filesConflict: AppFilesConflictContract.scenario; case .filesCancel: AppFilesCancelContract.scenario; case .trust(let value): value.rawValue; case .concurrent: AppConcurrentContract.scenario }
    }
    var fixture: AppMFAFixture? { if case .mfa(let value) = self { value } else { nil } }
    func encode(to encoder: any Encoder) throws { var value = encoder.singleValueContainer(); try value.encode(label) }
}

/// Closed material sources, not a configurable backend/endpoint registry.
fileprivate enum AppNativeFiniteSource {
    case keyonly(AppNativeFiniteContract, AppNativeFinitePublicMaterial)
    case password(AppNativePasswordContract, AppNativePasswordPublicMaterial)
    case mfa(AppMFAContract, AppMFAPublicMaterial)
    case files(AppFilesManifestContract, AppFilesManifestPublicMaterial)
    case filesConflict(AppFilesConflictContract, AppFilesManifestPublicMaterial)
    case filesCancel(AppFilesCancelContract, AppFilesManifestPublicMaterial)
    case trust(AppTrustContract, AppTrustPublicMaterial)
    case concurrent(AppConcurrentContract, AppConcurrentPublicMaterial)
    var isConcurrent: Bool { if case .concurrent = self { true } else { false } }
    var trustScenario: AppTrustScenario? { if case .trust(let value, _) = self { value.scenario } else { nil } }
    var filesMode: AppFilesRunMode { switch self { case .filesConflict: .conflict; case .filesCancel: .cancelRetry; default: .roundtrip } }
    var isFiles: Bool { switch self { case .files, .filesConflict, .filesCancel: true; default: false } }
    var runID: String { switch self { case .keyonly(let value, _): value.runID; case .password(let value, _): value.runID; case .mfa(let value, _): value.runID; case .files(let value, _): value.runID; case .filesConflict(let value, _): value.runID; case .filesCancel(let value, _): value.runID; case .trust(let value, _): value.runID; case .concurrent(let value, _): value.runID } }
    var scenario: AppNativeFiniteRunScenario { switch self { case .keyonly: .keyonly; case .password: .password; case .mfa(let value, _): .mfa(value.scenario); case .files: .files; case .filesConflict: .filesConflict; case .filesCancel: .filesCancel; case .trust(let value, _): .trust(value.scenario); case .concurrent: .concurrent } }
    var generation: String { switch self { case .keyonly(_, let value): value.contract.generation; case .password(_, let value): value.contract.generation; case .mfa(_, let value): value.contract.generation; case .files(_, let value): value.contract.generation; case .filesConflict(_, let value): value.contract.generation; case .filesCancel(_, let value): value.contract.generation; case .trust(_, let value): value.material.binding.generation; case .concurrent(_, let value): value.material.binding.generation } }
    func matchesTrust(_ prompt: SessionTrustPrompt) -> Bool {
        switch self {
        case .keyonly(_, let material): material.contract.matchesTrust(host: prompt.host.address.value, port: Int(prompt.host.port.value), algorithm: prompt.algorithm, fingerprint: prompt.fingerprint)
        case .password(_, let material): material.contract.matchesTrust(host: prompt.host.address.value, port: Int(prompt.host.port.value), algorithm: prompt.algorithm, fingerprint: prompt.fingerprint)
        case .trust(_, let material): material.material.binding.matchesTrust(host: prompt.host.address.value, port: Int(prompt.host.port.value), algorithm: prompt.algorithm, fingerprint: prompt.fingerprint)
        case .concurrent: false // Its independent helper preinstalls only the approved public key.
        case .files, .filesConflict, .filesCancel: false // Files owns its own exact handshake prompt; no shell trust is accepted.
        case .mfa(_, let material): prompt.host.address.value == "127.0.0.1" && Int(prompt.host.port.value) == material.contract.port &&
            prompt.algorithm == "ssh-ed25519" && prompt.fingerprint == material.contract.expectedFingerprint
        }
    }
    func revalidate(buildEpoch: Double) throws {
        switch self {
        case .concurrent(let wrapper, let material):
            let current = try AppConcurrentPublicMaterial.load(wrapper, buildEpoch: buildEpoch)
            guard current == material else { throw AppNativeFiniteFailure.staleMaterial }
        case .trust(let wrapper, let material):
            let current = try AppTrustPublicMaterial.load(wrapper, buildEpoch: buildEpoch)
            guard current == material else { throw AppNativeFiniteFailure.staleMaterial }
        case .keyonly(let wrapper, let material):
            let current = try AppNativeFinitePublicMaterial.load(wrapper.materialContractPath, buildEpoch: buildEpoch)
            try wrapper.requireMaterial(current.contract)
            guard current.contract.generation == material.contract.generation, current.hostKeyLine == material.hostKeyLine,
                  current.contract.collectedAt == material.contract.collectedAt else { throw AppNativeFiniteFailure.staleMaterial }
        case .password(let wrapper, let material):
            let current = try AppNativePasswordPublicMaterial.load(wrapper.materialContractPath, buildEpoch: buildEpoch)
            try wrapper.requireMaterial(current.contract)
            guard current.contract == material.contract, current.hostKeyLine == material.hostKeyLine else { throw AppNativeFiniteFailure.staleMaterial }
        case .filesCancel(let wrapper, let material):
            let current = try AppFilesManifestPublicMaterial.load(path: wrapper.materialContractPath, runID: wrapper.runID, buildEpoch: buildEpoch)
            guard current == material else { throw AppNativeFiniteFailure.staleMaterial }
        case .filesConflict(let wrapper, let material):
            let current = try AppFilesManifestPublicMaterial.load(path: wrapper.materialContractPath, runID: wrapper.runID, buildEpoch: buildEpoch)
            guard current == material else { throw AppNativeFiniteFailure.staleMaterial }
        case .files(let wrapper, let material):
            let current = try AppFilesManifestPublicMaterial.load(wrapper, buildEpoch: buildEpoch)
            guard current == material else { throw AppNativeFiniteFailure.staleMaterial }
        case .mfa(let wrapper, let material):
            let current = try AppMFAPublicMaterial.load(wrapper, buildEpoch: buildEpoch)
            guard current.contract == material.contract, current.hostKeyLine == material.hostKeyLine else { throw AppNativeFiniteFailure.staleMaterial }
        }
    }
}

/// Holds only the selected public input root. Receipts use exclusive fixed leaf writes.
fileprivate final class AppNativeFiniteInput {
    let source: AppNativeFiniteSource
    private let parent: Int32, directory: Int32, name: String, device: dev_t, inode: ino_t
    private let wrapper: AppNativeFiniteStableFile
    init(path: String, buildEpoch: Double) throws {
        let concurrent = path.hasSuffix("/" + AppConcurrentContract.leaf)
        let trust = path.hasSuffix("/" + AppTrustContract.leaf)
        let password = path.hasSuffix("/" + AppNativePasswordContract.leaf), mfa = path.hasSuffix("/" + AppMFAContract.leaf)
        let cancel = path.hasSuffix("/" + AppFilesCancelContract.leaf)
        let conflict = path.hasSuffix("/" + AppFilesConflictContract.leaf)
        let files = path.hasSuffix("/" + AppFilesManifestContract.leaf)
        let id: String
        if concurrent { id = try AppConcurrentContract.runID(at: path) }
        else if trust { id = try AppTrustContract.runID(at: path) }
        else if cancel { id = try AppFilesCancelContract.runID(at: path) }
        else if conflict { id = try AppFilesConflictContract.runID(at: path) }
        else if files { id = try AppFilesManifestContract.runID(at: path) }
        else if mfa { id = try AppMFAContract.runID(at: path) }
        else if password { id = try AppNativePasswordContract.runID(at: path) }
        else { id = try AppNativeFiniteContract.runID(at: path) }
        wrapper = try AppNativeFiniteStableFile(path)
        let bytes = try wrapper.read(limit: AppNativeFiniteContract.maximumBytes)
        let concurrentWrapper: AppConcurrentContract?
        if concurrent { let value = try AppConcurrentContract.decodeStrict(bytes); try value.validate(path: path); concurrentWrapper = value }
        else { concurrentWrapper = nil }
        let trustWrapper: AppTrustContract?
        if trust { let value = try AppTrustContract.decodeStrict(bytes); try value.validate(path: path); trustWrapper = value }
        else { trustWrapper = nil }
        let keyWrapper: AppNativeFiniteContract?, passwordWrapper: AppNativePasswordContract?, mfaWrapper: AppMFAContract?
        let filesWrapper: AppFilesManifestContract?
        let conflictWrapper: AppFilesConflictContract?
        let cancelWrapper: AppFilesCancelContract?
        if trust || concurrent {
            cancelWrapper = nil; conflictWrapper = nil; filesWrapper = nil; mfaWrapper = nil; passwordWrapper = nil; keyWrapper = nil
        } else if cancel {
            let value = try AppFilesCancelContract.decodeStrict(bytes); try value.validate(path: path)
            cancelWrapper = value; conflictWrapper = nil; filesWrapper = nil; mfaWrapper = nil; passwordWrapper = nil; keyWrapper = nil
        } else if conflict {
            cancelWrapper = nil
            let value = try AppFilesConflictContract.decodeStrict(bytes); try value.validate(path: path)
            conflictWrapper = value; filesWrapper = nil; mfaWrapper = nil; passwordWrapper = nil; keyWrapper = nil
        } else if files {
            cancelWrapper = nil
            conflictWrapper = nil
            let value = try AppFilesManifestContract.decodeStrict(bytes); try value.validate(path: path)
            filesWrapper = value; mfaWrapper = nil; passwordWrapper = nil; keyWrapper = nil
        } else if mfa {
            cancelWrapper = nil; conflictWrapper = nil; filesWrapper = nil
            let value = try AppMFAContract.decodeStrict(bytes); try value.validate(path: path)
            mfaWrapper = value; passwordWrapper = nil; keyWrapper = nil
        } else if password {
            cancelWrapper = nil; conflictWrapper = nil; filesWrapper = nil
            let value = try AppNativePasswordContract.decodeStrict(bytes); try value.validate(path: path)
            passwordWrapper = value; keyWrapper = nil; mfaWrapper = nil
        } else {
            cancelWrapper = nil; conflictWrapper = nil; filesWrapper = nil
            let value = try AppNativeFiniteContract.decodeStrict(bytes); try value.validate(path: path)
            keyWrapper = value; passwordWrapper = nil; mfaWrapper = nil
        }
        parent = try AppRealPrivateInput.directory(AppNativeFiniteContract.inputRoot)
        name = "run-" + id
        directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { Darwin.close(parent); throw AppNativeFiniteFailure.unsafeInput }
        var info = stat()
        do {
            try AppFileSecurity.directory(directory)
            guard fstat(directory, &info) == 0,
                  try AppRealPrivateInput.read(AppNativeFiniteContract.inputRoot + "/" + name + "/" + AppNativeFiniteContract.markerName, limit: 256) == Data((AppNativeFiniteContract.marker + id + "\n").utf8) else {
                throw AppNativeFiniteFailure.unsafeInput
            }
            var leaves = ["native-ready.json", "native-before-stores.json", "native-after-stores.json", "native-will-terminate.json", "native-failure.json", AppNativeFiniteWeakPoint.leaf]
            if password { leaves.append(AppNativePasswordAuthenticationReceipt.leaf) }
            if mfa { leaves += [AppMFAAuthenticationReceipt.leaf, AppMFACleanupReceipt.leaf] }
            if files { leaves.append("native-files-transfer.json") }
            if conflict { leaves.append("native-files-conflict-transfer.json") }
            if concurrent { leaves += [AppConcurrentAuthenticationReceipt.leaf, AppConcurrentCleanupReceipt.leaf] }
            if trust { leaves += (1...2).map(AppTrustAuthenticationReceipt.leaf) }
            if cancel { leaves.append("native-files-cancel-transfer.json") }
            for leaf in leaves {
                var named = stat()
                guard fstatat(directory, leaf, &named, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw AppNativeFiniteFailure.unsafeInput }
            }
            if let value = concurrentWrapper {
                source = .concurrent(value, try AppConcurrentPublicMaterial.load(value, buildEpoch: buildEpoch))
            } else if let value = trustWrapper {
                source = .trust(value, try AppTrustPublicMaterial.load(value, buildEpoch: buildEpoch))
            } else if let value = cancelWrapper {
                source = .filesCancel(value, try AppFilesManifestPublicMaterial.load(path: value.materialContractPath, runID: value.runID, buildEpoch: buildEpoch))
            } else if let value = conflictWrapper {
                source = .filesConflict(value, try AppFilesManifestPublicMaterial.load(path: value.materialContractPath, runID: value.runID, buildEpoch: buildEpoch))
            } else if let value = filesWrapper {
                source = .files(value, try AppFilesManifestPublicMaterial.load(value, buildEpoch: buildEpoch))
            } else if let value = mfaWrapper {
                source = .mfa(value, try AppMFAPublicMaterial.load(value, buildEpoch: buildEpoch))
            } else if let value = passwordWrapper {
                let material = try AppNativePasswordPublicMaterial.load(value.materialContractPath, buildEpoch: buildEpoch)
                try value.requireMaterial(material.contract); source = .password(value, material)
            } else if let value = keyWrapper {
                let material = try AppNativeFinitePublicMaterial.load(value.materialContractPath, buildEpoch: buildEpoch)
                try value.requireMaterial(material.contract); source = .keyonly(value, material)
            } else { throw AppNativeFiniteFailure.contract }
            try wrapper.check()
        } catch { Darwin.close(directory); Darwin.close(parent); throw error }
        device = info.st_dev; inode = info.st_ino
    }
    deinit { Darwin.close(directory); Darwin.close(parent) }
    func revalidateMaterial(buildEpoch: Double) throws {
        try wrapper.check()
        try source.revalidate(buildEpoch: buildEpoch)
    }
    func write<T: Encodable>(_ value: T, leaf: String) throws {
        let original = ["native-ready.json", "native-before-stores.json", "native-after-stores.json", "native-will-terminate.json", "native-failure.json", AppNativeFiniteWeakPoint.leaf]
        let mfaLeaf = source.scenario.fixture != nil && [AppMFAAuthenticationReceipt.leaf, AppMFACleanupReceipt.leaf].contains(leaf)
        let filesLeaf = (source.scenario == .files && leaf == "native-files-transfer.json") || (source.scenario == .filesConflict && leaf == "native-files-conflict-transfer.json") || (source.scenario == .filesCancel && leaf == "native-files-cancel-transfer.json")
        let trustLeaf = source.trustScenario != nil && (1...2).map(AppTrustAuthenticationReceipt.leaf).contains(leaf)
        let concurrentLeaf = source.isConcurrent && [AppConcurrentAuthenticationReceipt.leaf, AppConcurrentCleanupReceipt.leaf].contains(leaf)
        guard original.contains(leaf) || (source.scenario == .password && leaf == AppNativePasswordAuthenticationReceipt.leaf) || mfaLeaf || filesLeaf || trustLeaf || concurrentLeaf else { throw AppNativeFiniteFailure.reportWrite }
        var current = stat()
        guard fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0, current.st_dev == device, current.st_ino == inode else {
            throw AppNativeFiniteFailure.reportWrite
        }
        try AppFileSecurity.directory(directory)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(value)
        let limit = leaf == AppNativeFiniteWeakPoint.leaf ? AppNativeFiniteWeakPoint.maximumBytes : 16 * 1024
        guard bytes.count <= limit else { throw AppNativeFiniteFailure.reportWrite }
        try AppRealPrivateInput.write(bytes, parent: directory, name: leaf)
        let fd = openat(directory, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw AppNativeFiniteFailure.reportWrite }; defer { Darwin.close(fd) }
        guard fsync(fd) == 0, fsync(directory) == 0 else { throw AppNativeFiniteFailure.reportWrite }
    }
}

/// The production session is returned unchanged. No transport wrapper, second receive, direct
/// write/resize or credential source is installed. This owner keeps only a weak session and receipt.
fileprivate actor AppNativeFiniteConnectionFacts {
    private(set) var attempts = 0, productionSessions = 0, primaryProviderCalls = 0
    private(set) var authentication: AppNativeFiniteAuthFacts?
    private(set) var mfaAuthentication: AppMFAAuthentication?
    private(set) var drain: NativeShellDrainHandle?
    private weak var session: LibSSH2ShellSession?
    func attempted() throws { guard attempts == 0 else { throw AppNativeFiniteFailure.unexpectedSession }; attempts += 1 }
    func primaryRequested() throws {
        guard primaryProviderCalls == 0 else { throw AppNativeFiniteFailure.unexpectedAuthentication }; primaryProviderCalls += 1
    }
    func connected(_ session: LibSSH2ShellSession, scenario: AppNativeFiniteRunScenario) async throws {
        self.session = session; drain = session.interactionDrain; productionSessions += 1
        let stages = await session.authenticationStages()
        switch scenario {
        case .keyonly: authentication = AppNativeFiniteAuthFacts(keyonly: try AppNativeFiniteAuthentication(stages))
        case .password: authentication = try AppNativeFiniteAuthFacts(passwordStages: stages)
        case .files, .filesConflict, .filesCancel, .trust, .concurrent: throw AppNativeFiniteFailure.unexpectedSession
        case .mfa(let fixture): mfaAuthentication = try AppMFAAuthentication(stages, fixture: fixture)
        }
    }
    func nativeInputBytes() -> Int? { session?.pendingInputBytes }
    func cancel() { session?.cancel() }
}
private struct AppNativeFiniteObservedConnector: NativeSessionConnecting {
    let environment: SessionEnvironment
    let facts: AppNativeFiniteConnectionFacts
    let scenario: AppNativeFiniteRunScenario
    func connect(_ request: NativeSessionConnect) async throws -> any NativeSessionTransport {
        switch scenario {
        case .keyonly:
            guard request.method == .publicKey, request.configuration.host.address.value == "127.0.0.1",
                  request.configuration.host.port.value == 22221, request.configuration.user.value == "fixture" else {
                throw AppNativeFiniteFailure.unexpectedSession
            }
        case .files, .filesConflict, .filesCancel, .trust, .concurrent: throw AppNativeFiniteFailure.unexpectedSession
        case .password:
            guard request.method == .password, request.configuration.host.address.value == "127.0.0.1",
                  request.configuration.host.port.value == 22222, request.configuration.user.value == "fixture" else {
                throw AppNativeFiniteFailure.unexpectedSession
            }
        case .mfa(let fixture):
            guard request.method == (fixture.usesKey ? .publicKey : .password), request.configuration.host.address.value == "127.0.0.1",
                  Int(request.configuration.host.port.value) == fixture.port, request.configuration.user.value == "fixture" else { throw AppNativeFiniteFailure.unexpectedSession }
        }
        try await facts.attempted()
        let production = NativeLibraryConnector(store: try await environment.sharedTrustStore())
        let selected: NativeSessionConnect
        if scenario == .password || scenario.fixture != nil {
            // Observation only: call the exact production primary provider once, unchanged.
            // No credential source, alternate response or transport wrapper is installed.
            let primary = request.primary
            selected = NativeSessionConnect(configuration: request.configuration, method: request.method, primary: { [facts] value in
                try await facts.primaryRequested()
                return try await primary(value)
            }, keyboard: request.keyboard, trust: request.trust, options: request.options,
                connectionTimeout: request.connectionTimeout, token: request.token)
        } else { selected = request }
        let transport = try await production.connect(selected)
        guard let actual = transport as? LibSSH2ShellSession else { throw AppNativeFiniteFailure.unexpectedSession }
        do { try await facts.connected(actual, scenario: scenario) }
        catch {
            actual.cancel(); await actual.close()
            throw NativeSessionConnectionFailure(failure: error, drain: CanonicalSessionDrain(handle: actual.interactionDrain), noNativeOwnerCreated: false)
        }
        return transport
    }
}

@MainActor final class AppNativeFiniteIntegration {
    struct Bootstrap {
        let model: AppModel
        fileprivate let input: AppNativeFiniteInput, store: AppRealOwnedStore, credentials: AppRealNoCredentials
        fileprivate let environment: SessionEnvironment, facts: AppNativeFiniteConnectionFacts
        fileprivate var source: AppNativeFiniteSource { input.source }
        let budget: AppNativeFiniteBudget, buildEpoch: Double
        fileprivate let filesRuntime: AppFilesManifestRuntime?
        fileprivate let trustFacts: AppTrustFacts?
        fileprivate let concurrentRuntime: AppConcurrentRuntime?
    }
    struct Report: Encodable {
        let schema = 1, kind = "HostProbe-App-Native-finite"
        let scenario: AppNativeFiniteRunScenario
        let runID: String, pid: Int32, checkpoint: String
        let passed: Bool, failureCode: AppNativeFiniteFailure?, elapsedSeconds: Double
        let eofEvidence = "notDirectlyObservable"
        let guiVerified = false, productRuntimeVerified = false
        let authentication: AppNativeFiniteAuthFacts?
        let mfaAuthentication: AppMFAAuthentication?
        let mfaKeyboard: AppMFAKIFacts?
        let terminal: AppNativeFiniteTerminalPlan.Evidence?
        let exitStatus: Int32?, closeDisposition: String
        let canonicalDrained: Bool, nativeInputBytesAfterExit: Int?, nativeInputEvidence: String, driverQueueSnapshotEmpty: Bool
        let sourceKeyUnchanged: Bool?
        let sourceKeyScope: AppNativeFiniteSourceKeyScope?
        let transient: AppNativePasswordTransientFacts?
        let fixtureKnownHostsUnchanged: Bool, trustMatchedOutOfBand: Bool
        let credentialCalls: Int, connectionAttempts: Int, productionSessions: Int
        let filesVisible: Bool, transferJobs: Int, filesOperations: Int
        let descriptorBaseline: Int?, descriptorAfter: Int?, registryBaselineActive: Int, registryBaselineRetired: Int
        let registryAfterActive: Int, registryAfterRetired: Int, weakDriverReleased: Bool, weakViewReleased: Bool
        let localStoreRemoved: Bool, quit: AppNativeFiniteQuitAudit
        let cleanup: AppNativeFiniteCleanupSnapshot
        let weakPointWritten: Bool
        let descriptorSnapshots: AppNativeFiniteDescriptorSnapshots?
    }
    private unowned let delegate: AppDelegate
    private let bootstrap: Bootstrap
    private var model: AppModel { delegate.model }
    private var filesExercise: AppFilesManifestExercise?
    private var trustExercise: AppTrustExercise?
    private var concurrentExercise: AppConcurrentExercise?
    private var failure: AppNativeFiniteFailure?
    private var work: Task<Void, Never>?, watchdog: Timer?
    // Installed only inside the exercise helper; cleared before its task handle leaves scope.
    private var cancelExercise: (@MainActor () -> Void)?
    private var cleanupStage: AppNativeFiniteCleanupStage = .exerciseRunning
    private var activeStage: AppNativeFiniteActiveStage = .preparingHost
    private var requestedRows: Int?, requestedColumns: Int?
    private var inputBeforeAdmission: AppNativeFiniteInputQueueSnapshot?, inputAfterAdmission: AppNativeFiniteInputQueueSnapshot?
    private var failureCleanup: AppNativeFiniteCleanupSnapshot?
    private var descriptorSnapshots = AppNativeFiniteDescriptorSnapshots()
    private var failureDescriptorSnapshots: AppNativeFiniteDescriptorSnapshots?
    private var knownHostsCheckPerformed = false
    private var weakPointAttempted = false, weakPointWritten = false
    private var phaseDeadline: ContinuousClock.Instant
    private var phaseFailure = AppNativeFiniteFailure.preparationDeadline
    private var cleanupLimit: ContinuousClock.Instant?
    private var quitting = false, failureReceiptWritten = false, storeRemoved = false, storesFailed = false
    private var audit = AppNativeFiniteQuitAudit()
    private var authentication: AppNativeFiniteAuthFacts?, terminalEvidence: AppNativeFiniteTerminalPlan.Evidence?
    private var transient: AppNativePasswordTransientFacts?
    private var mfaAuthentication: AppMFAAuthentication?, mfaKeyboard: AppMFAKIFacts?, mfaCleanup: AppMFACleanupReceipt?
    private var mfaManager: AppMFAManagement?, mfaSessionID: String?
    private var transientIntent: VaultTransientConnectionIntent?
    private var preparedTabCount = 0, preparedConnectionAttempts = 0, preparedIntentConsumed = false
    private var commitCount = 0, committedTabCount = 0
    private var exitStatus: Int32?, closeDisposition = "notObserved"
    private var canonicalDrained = false, queuesEmpty = false
    private var nativeInputBytesAfterExit: Int?
    private var sourceUnchanged = false, knownUnchanged = false, trustMatched = false
    private var source: AppNativeFiniteStableFile?, known: AppNativeFiniteStableFile?, knownBytes: Data?
    private var keyID: UUID?, hostID: UUID?, descriptorBaseline: Int?, descriptorAfter: Int?
    private var registryActive = 0, registryRetired = 0
    private weak var sessionTab: SessionTab?
    private weak var driver: NativeSessionDriver?
    private weak var terminalView: NativeTerminalView?

    static func bootstrap(path: String) throws -> Bootstrap {
        let budget = AppNativeFiniteBudget()
        guard let epoch = Bundle.main.object(forInfoDictionaryKey: "OpenLXSSHRealFixtureBuildEpoch") as? Double else { throw AppNativeFiniteFailure.contract }
        try AppRealIntegration.validateSignature()
        let input = try AppNativeFiniteInput(path: path, buildEpoch: epoch)
        let store = try AppRealOwnedStore(runID: input.source.runID)
        let location = AppDataLocation.isolated(store.url), repository = AppRepository(location: location)
        let credentials = AppRealNoCredentials(namespace: UUID(uuidString: input.source.runID)!)
        let security = SecurityCoordinator(repository: repository, location: location, credentials: credentials)
        let environment = SessionEnvironment(location: location), facts = AppNativeFiniteConnectionFacts()
        let trustFacts = input.source.trustScenario.map { AppTrustFacts(scenario: $0) }
        let connector: any NativeSessionConnecting
        if let trustFacts { connector = AppTrustConnector(environment: environment, facts: trustFacts) }
        else { connector = AppNativeFiniteObservedConnector(environment: environment, facts: facts, scenario: input.source.scenario) }
        let concurrentRuntime = input.source.isConcurrent ? AppConcurrentRuntime() : nil
        let builder: any SessionBuilding
        if let concurrentRuntime {
            builder = AppConcurrentBuilder(repository: repository, security: security, environment: environment, runtime: concurrentRuntime)
        } else { builder = NativeSessionBuilder(repository: repository, security: security, environment: environment, connector: connector) }
        let filesRuntime: AppFilesManifestRuntime?
        let model: AppModel
        if input.source.isFiles {
            let runtime = try AppFilesManifestRuntime(environment: environment, mode: input.source.filesMode); filesRuntime = runtime
            let production = LibSSH2FilesConnector(repository: repository, security: security, environment: environment)
            model = AppModel(repository: repository, security: security, location: location, sessionBuilder: builder,
                nativeCandidateBuilder: builder, filesConnector: try AppFilesManifestConnector(production: production, runtime: runtime),
                preferencesDefaults: nil, filesLocalService: { try runtime.localService($0) })
        } else {
            filesRuntime = nil
            model = AppModel(repository: repository, security: security, location: location, sessionBuilder: builder,
                             nativeCandidateBuilder: builder, preferencesDefaults: nil)
        }
        return Bootstrap(model: model, input: input, store: store, credentials: credentials, environment: environment,
                         facts: facts, budget: budget, buildEpoch: epoch, filesRuntime: filesRuntime, trustFacts: trustFacts, concurrentRuntime: concurrentRuntime)
    }
    init(delegate: AppDelegate, bootstrap: Bootstrap) {
        self.delegate = delegate; self.bootstrap = bootstrap; phaseDeadline = bootstrap.budget.preparationDeadline
    }
    func start() {
        guard work == nil else { return }
        let timer = Timer(timeInterval: 0.1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.checkWatchdog() }
        }
        watchdog = timer; RunLoop.main.add(timer, forMode: .common)
        work = Task { [self] in
            // This coordinator never executes exercise() in its own async frame.
            await awaitExerciseScope()
            cleanupStage = .exerciseReturned
            // The exercise result and handle are out of scope before this awaited cleanup starts.
            // Watchdog cancels the exercise task, not this coordinator or cleanup's sleep state.
            await cleanupAndQuit()
        }
    }
    private func awaitExerciseScope() async {
        let exerciseTask = Task { [self] in try await exercise() }
        cancelExercise = { exerciseTask.cancel() }
        defer { cancelExercise = nil }
        switch await exerciseTask.result {
        case .success: break
        case .failure(let error): recordFailure(error)
        }
    }
    private func checkWatchdog() {
        let now = ContinuousClock.now
        let currentDeadline = quitting ? phaseDeadline : (concurrentExercise?.phaseDeadline ?? trustExercise?.phaseDeadline ?? filesExercise?.phaseDeadline ?? phaseDeadline)
        guard now >= currentDeadline || now >= bootstrap.budget.fullDeadline else { return }
        if failure == nil { failure = now >= bootstrap.budget.fullDeadline ? .fullDeadline : (concurrentExercise?.timeoutFailure ?? trustExercise?.timeoutFailure ?? filesExercise?.timeoutFailure ?? phaseFailure) }
        if failureCleanup == nil { failureCleanup = cleanupSnapshot(); failureDescriptorSnapshots = descriptorSnapshots }
        driver?.cancel(); cancelExercise?(); mfaManager?.cancel(); filesExercise?.cancel(); trustExercise?.cancel(); concurrentExercise?.cancel()
        Task { await bootstrap.facts.cancel() }
        if quitting { writeFailureReceipt() }
    }
    private func checkpoint() throws {
        try Task.checkCancellation()
        guard ContinuousClock.now < bootstrap.budget.fullDeadline else { throw AppNativeFiniteFailure.fullDeadline }
        guard ContinuousClock.now < phaseDeadline else { throw phaseFailure }
    }
    private func wait(_ condition: @MainActor () -> Bool) async throws {
        while !condition() { try checkpoint(); try await Task.sleep(for: .milliseconds(10)) }
        try checkpoint()
    }
    private func exercise() async throws {
        if case .concurrent(let wrapper, let material) = bootstrap.source, let runtime = bootstrap.concurrentRuntime {
            let helper = AppConcurrentExercise(model: model, input: bootstrap.input, store: bootstrap.store, environment: bootstrap.environment,
                runtime: runtime, wrapper: wrapper, material: material, budget: bootstrap.budget, buildEpoch: bootstrap.buildEpoch,
                credentials: bootstrap.credentials, descriptors: { [budget = bootstrap.budget] in try Self.descriptors(budget: budget) })
            concurrentExercise = helper; try await helper.exercise(); return
        }
        if case .trust(let wrapper, let material) = bootstrap.source, let facts = bootstrap.trustFacts {
            let helper = AppTrustExercise(model: model, input: bootstrap.input, store: bootstrap.store, environment: bootstrap.environment,
                facts: facts, wrapper: wrapper, material: material, budget: bootstrap.budget, buildEpoch: bootstrap.buildEpoch,
                credentials: bootstrap.credentials, window: delegate.mainWindow,
                descriptors: { [budget = bootstrap.budget] in try Self.descriptors(budget: budget) })
            trustExercise = helper; try await helper.exercise(); return
        }
        if let runtime = bootstrap.filesRuntime, bootstrap.source.isFiles {
            let material: AppFilesManifestPublicMaterial
            switch bootstrap.source { case .files(_, let value), .filesConflict(_, let value), .filesCancel(_, let value): material = value; default: throw AppNativeFiniteFailure.contract }
            let helper = try AppFilesManifestExercise(model: model, input: bootstrap.input, store: bootstrap.store, runtime: runtime,
                environment: bootstrap.environment, mode: bootstrap.source.filesMode,
                material: material, budget: bootstrap.budget, buildEpoch: bootstrap.buildEpoch, credentials: bootstrap.credentials,
                descriptors: { [budget = bootstrap.budget] in try Self.descriptors(budget: budget) })
            filesExercise = helper
            phaseDeadline = bootstrap.budget.activeDeadline(start: .now); phaseFailure = .activeDeadline
            try await helper.exercise(); return
        }
        activeStage = .preparingHost
        try await wait { self.model.didLoad && !self.model.isLoading }
        guard model.hosts.isEmpty, model.sessions.tabs.isEmpty, !model.files.visible else { throw AppNativeFiniteFailure.unexpectedSession }
        // This isolated fixture needs 113 real columns above the unchanged 920pt window minimum.
        // Use the normal persisted settings path before the FD baseline or any session exists.
        var fixtureSettings = model.settings
        fixtureSettings.fontSize = 14
        guard await model.saveSettings(fixtureSettings), model.settings.fontSize == 14 else { throw AppNativeFiniteFailure.operation }
        if case .mfa(_, let material) = bootstrap.source { mfaManager = try AppMFAManagement(material: material.contract) }
        known = try AppNativeFiniteStableFile(bootstrap.source.generation + "/known_hosts")
        knownBytes = try known?.read(limit: 4096)
        let host = try await prepareHost()
        let trust = try await bootstrap.environment.sharedTrustStore()
        guard try await trust.records().isEmpty else { throw AppNativeFiniteFailure.trustMismatch }
        try bootstrap.input.revalidateMaterial(buildEpoch: bootstrap.buildEpoch)
        try checkpoint()
        let baseline = try Self.descriptors(budget: bootstrap.budget)
        descriptorBaseline = baseline.count; descriptorSnapshots.baseline = baseline
        registryActive = SessionRetirementRegistry.shared.activeCount; registryRetired = SessionRetirementRegistry.shared.retiredCount
        phaseDeadline = bootstrap.budget.activeDeadline(start: .now); phaseFailure = .activeDeadline
        activeStage = .awaitingDriver
        try await openPreparedHost(host)
        try await wait { self.model.sessions.tabs.first?.driver != nil }
        guard model.sessions.tabs.count == 1, let tab = model.sessions.tabs.first, let native = tab.driver as? NativeSessionDriver else { throw AppNativeFiniteFailure.unexpectedSession }
        sessionTab = tab; driver = native; terminalView = native.terminal
        activeStage = .awaitingTrust
        try await wait { !tab.trust.isEmpty || tab.authentication != nil || tab.state == .connected || tab.canReconnect }
        guard tab.authentication == nil, tab.trust.count == 1, let prompt = tab.trust.first, prompt.changed == nil,
              bootstrap.source.matchesTrust(prompt) else {
            throw AppNativeFiniteFailure.trustMismatch
        }
        trustMatched = true
        activeStage = .awaitingConnected
        guard await model.sessions.accept(prompt, tabID: tab.id, persistence: .persistent) else { throw AppNativeFiniteFailure.trustMismatch }
        if let fixture = bootstrap.source.scenario.fixture {
            try await answerMFA(tab: tab, native: native, host: host, fixture: fixture)
            mfaAuthentication = await bootstrap.facts.mfaAuthentication
            let credentialCalls = await bootstrap.credentials.forbiddenCalls
            guard let mfaAuthentication, let mfaKeyboard, credentialCalls == 0 else { throw AppNativeFiniteFailure.typedStages }
            if !fixture.usesKey { transient = try await transientFacts() }
            let calls = await bootstrap.facts.primaryProviderCalls
            guard calls == 1 else { throw AppNativeFiniteFailure.unexpectedAuthentication }
            try bootstrap.input.write(AppMFAAuthenticationReceipt(runID: bootstrap.source.runID, pid: getpid(), scenario: fixture,
                authentication: mfaAuthentication, keyboard: mfaKeyboard, primaryProviderCalls: calls, credentialCalls: credentialCalls,
                transient: transient, externalPolicyProofValidated: true), leaf: AppMFAAuthenticationReceipt.leaf)
            transientIntent = nil
        } else {
            try await wait { tab.state == .connected || tab.authentication != nil || tab.canReconnect }
            guard tab.state == .connected, tab.authentication == nil, tab.trust.isEmpty else { throw AppNativeFiniteFailure.unexpectedAuthentication }
            authentication = await bootstrap.facts.authentication
            guard let authentication else { throw AppNativeFiniteFailure.typedStages }
            if bootstrap.source.scenario == .password {
                let credentialCalls = await bootstrap.credentials.forbiddenCalls
                guard let intent = transientIntent, credentialCalls == 0 else { throw AppNativeFiniteFailure.unexpectedAuthentication }
                let primaryCalls = await bootstrap.facts.primaryProviderCalls
                transient = try AppNativePasswordTransientFacts(preparedTabCount: preparedTabCount,
                    preparedConnectionAttempts: preparedConnectionAttempts, preparedIntentConsumed: preparedIntentConsumed,
                    commitCount: commitCount, committedTabCount: committedTabCount, intentConsumed: intent.consumed,
                    primaryProviderCalls: primaryCalls)
                guard let transient else { throw AppNativeFiniteFailure.unexpectedAuthentication }
                try bootstrap.input.write(AppNativePasswordAuthenticationReceipt(runID: bootstrap.source.runID, pid: getpid(),
                    authentication: authentication, transient: transient, credentialCalls: credentialCalls), leaf: AppNativePasswordAuthenticationReceipt.leaf)
                transientIntent = nil
            }
        }
        let plan = try AppNativeFiniteTerminalPlan(nonce: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())
        activeStage = .awaitingResize
        requestedRows = 37; requestedColumns = 113
        try await AppNativeFiniteRendererGeometry.prepare(native, ownedWindow: delegate.mainWindow, checkpoint: { try self.checkpoint() }) {
            // SwiftTerm.send -> existing ApplicationTerminalRelay.send -> NativeSessionDriver.admitInput
            // -> its ordered write task -> production transport. No delegate replacement/direct session I/O.
            let command = Array(plan.command.utf8)
            activeStage = .awaitingTerminalEvidence
            let beforeInput = native.snapshot
            inputBeforeAdmission = AppNativeFiniteInputQueueSnapshot(pendingBytes: beforeInput.pendingInputBytes, pendingItems: beforeInput.pendingInputItems)
            native.terminal.send(data: command[...])
            let afterInput = native.snapshot
            inputAfterAdmission = AppNativeFiniteInputQueueSnapshot(pendingBytes: afterInput.pendingInputBytes, pendingItems: afterInput.pendingInputItems)
        }
        while true {
            try checkpoint()
            let evidence = try plan.inspect(native.terminal.text)
            terminalEvidence = evidence // Retain the last bounded facts even when 37x113 never arrives.
            if evidence.complete { break }
            guard tab.state == .connected, tab.authentication == nil else { throw AppNativeFiniteFailure.terminalEvidence }
            try await Task.sleep(for: .milliseconds(10))
        }
        activeStage = .awaitingExit
        let exit = Array("exit 7\n".utf8); native.terminal.send(data: exit[...])
        try await wait { tab.state == .disconnected(7) || tab.canReconnect }
        guard tab.state == .disconnected(7) else { throw AppNativeFiniteFailure.remoteExit }
        exitStatus = 7 // Driver's actual received exit status, never inferred from echoed input.
        cleanupLimit = bootstrap.budget.cleanupDeadline(start: .now)
        phaseDeadline = cleanupLimit!; phaseFailure = .cleanup
        activeStage = .closingTab
        nativeInputBytesAfterExit = await bootstrap.facts.nativeInputBytes() // nil is unobserved, never zero.
        let result = await model.sessions.closeTabResult(tab.id, deadline: phaseDeadline)
        switch result {
        case .closed: closeDisposition = "closed"
        case .retired: closeDisposition = "retired"; throw AppNativeFiniteFailure.closeRetired
        case .incomplete: closeDisposition = "incomplete"; throw AppNativeFiniteFailure.closeIncomplete
        }
        let snapshot = native.snapshot
        queuesEmpty = snapshot.pendingInputBytes == 0 && snapshot.pendingInputItems == 0 && !snapshot.receiveInFlight &&
            !snapshot.resizeInFlight && !snapshot.hasLatestResize && snapshot.nativeCloseCompleted && snapshot.interactionsDrained
        canonicalDrained = await bootstrap.facts.drain?.snapshot.drained == true
        guard queuesEmpty, canonicalDrained, nativeInputBytesAfterExit == nil || nativeInputBytesAfterExit == 0,
              model.sessions.tabs.isEmpty else { throw AppNativeFiniteFailure.drainIncomplete }
    }
    private func prepareHost() async throws -> HostConfiguration {
        switch bootstrap.source {
        case .keyonly(_, let material):
            let generation = material.contract.generation
            source = try AppNativeFiniteStableFile(generation + "/id_ed25519")
            // Byte comparison is confined to mutable memory. Never hash/log the source private key.
            var original = try source!.read(limit: 32768)
            defer { original.resetBytes(in: 0..<original.count); original.removeAll() }
            let key = try await model.security.createKey(.importFile(URL(fileURLWithPath: generation + "/id_ed25519")), protection: .unencrypted, rememberPassphrase: nil)
            keyID = key.id
            guard !key.cleanupPending else { throw AppNativeFiniteFailure.importFailed }
            let imported = try await model.security.publicKey(key.id)
            let exported = try AppRealPrivateInput.read(generation + "/id_ed25519.pub", limit: 4096)
            let fields = String(decoding: exported, as: UTF8.self).trimmingCharacters(in: .newlines).split(separator: " ")
            guard fields.count >= 2, imported.copyString == fields.prefix(2).joined(separator: " ") else { throw AppNativeFiniteFailure.importFailed }
            var after = try source!.read(limit: 32768)
            sourceUnchanged = original == after
            after.resetBytes(in: 0..<after.count); after.removeAll()
            guard sourceUnchanged else { throw AppNativeFiniteFailure.sourceChanged }
            original.resetBytes(in: 0..<original.count); original.removeAll()
            let host = HostConfiguration(name: "Approved finite Native keyonly fixture", address: "127.0.0.1", port: 22221,
                                         username: "fixture", authentication: .privateKey, keyRef: key.id)
            guard await model.saveHostSecurely(host, isNew: true, password: .manual) else { throw AppNativeFiniteFailure.hostSaveFailed }
            hostID = host.id
            let metadata = try await model.repository.securityMetadata()
            guard metadata.credentials.isEmpty, let saved = metadata.hosts.first(where: { $0.id == host.id }),
                  saved.credentialRef == nil, !saved.savePasswordAuthorized,
                  metadata.keys.first(where: { $0.id == key.id })?.passphraseCredentialRef == nil else { throw AppNativeFiniteFailure.hostSaveFailed }
            return host
        case .mfa(_, let material):
            let value = material.contract, fixture = value.fixture
            let host: HostConfiguration
            if fixture.usesKey {
                source = try AppNativeFiniteStableFile(value.generation + "/id_ed25519")
                var before = try source!.read(limit: 32768)
                defer { before.resetBytes(in: 0..<before.count); before.removeAll() }
                let key = try await model.security.createKey(.importFile(URL(fileURLWithPath: value.generation + "/id_ed25519")), protection: .unencrypted, rememberPassphrase: nil)
                keyID = key.id
                guard !key.cleanupPending else { throw AppNativeFiniteFailure.importFailed }
                let publicKey = try await model.security.publicKey(key.id)
                let exported = try AppRealPrivateInput.read(value.generation + "/id_ed25519.pub", limit: 4096)
                let fields = String(decoding: exported, as: UTF8.self).trimmingCharacters(in: .newlines).split(separator: " ")
                guard fields.count >= 2, publicKey.copyString == fields.prefix(2).joined(separator: " ") else { throw AppNativeFiniteFailure.importFailed }
                var after = try source!.read(limit: 32768)
                sourceUnchanged = before == after; after.resetBytes(in: 0..<after.count); after.removeAll()
                guard sourceUnchanged else { throw AppNativeFiniteFailure.sourceChanged }
                host = HostConfiguration(name: "Approved finite Native keyKI fixture", address: "127.0.0.1", port: fixture.port,
                    username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id)
            } else {
                host = HostConfiguration(name: "Approved finite Native passwordKI fixture", address: "127.0.0.1", port: fixture.port,
                    username: "fixture", authentication: .passwordWithMFA)
            }
            guard await model.saveHostSecurely(host, isNew: true, password: .manual) else { throw AppNativeFiniteFailure.hostSaveFailed }
            hostID = host.id
            let metadata = try await model.repository.securityMetadata()
            guard metadata.credentials.isEmpty, let saved = metadata.hosts.first(where: { $0.id == host.id }), saved.matchesConnection(of: host),
                  saved.credentialRef == nil, !saved.savePasswordAuthorized,
                  (fixture.usesKey ? metadata.keys.first(where: { $0.id == keyID })?.passphraseCredentialRef == nil : metadata.keys.isEmpty) else {
                throw AppNativeFiniteFailure.hostSaveFailed
            }
            return host
        case .files, .filesConflict, .filesCancel, .trust, .concurrent: throw AppNativeFiniteFailure.unexpectedSession
        case .password:
            let host = HostConfiguration(name: "Approved finite Native passwordonly fixture", address: "127.0.0.1", port: 22222,
                                         username: "fixture", authentication: .password)
            guard await model.saveHostSecurely(host, isNew: true, password: .manual) else { throw AppNativeFiniteFailure.hostSaveFailed }
            hostID = host.id
            let metadata = try await model.repository.securityMetadata()
            guard metadata.credentials.isEmpty, metadata.keys.isEmpty, let saved = metadata.hosts.first(where: { $0.id == host.id }),
                  saved.matchesConnection(of: host), saved.keyRef == nil, saved.credentialRef == nil, !saved.savePasswordAuthorized else {
                throw AppNativeFiniteFailure.hostSaveFailed
            }
            return host
        }
    }
    private func openPreparedHost(_ host: HostConfiguration) async throws {
        switch bootstrap.source {
        case .files, .filesConflict, .filesCancel, .trust, .concurrent: throw AppNativeFiniteFailure.unexpectedSession
        case .keyonly:
            model.requestSession(hostID: host.id, mode: .newSession)
        case .mfa(_, let material):
            if material.contract.fixture.usesKey { model.requestSession(hostID: host.id, mode: .newSession) }
            else { try await openTransientPassword(host, generation: material.contract.generation) }
        case .password(_, let material):
            try await openTransientPassword(host, generation: material.contract.generation)
        }
    }
    private func openTransientPassword(_ host: HostConfiguration, generation: String) async throws {
        let held = try AppNativeFiniteStableFile(generation + "/password.txt")
        var file = try held.read(limit: 1024), payload = Data()
        defer { file.resetBytes(in: 0..<file.count); payload.resetBytes(in: 0..<payload.count) }
        payload = try AppNativePasswordSecret.payload(file)
        let intent = VaultTransientConnectionIntent(host: host, secret: SecretBytes(payload))
        file.resetBytes(in: 0..<file.count); file.removeAll(); payload.resetBytes(in: 0..<payload.count); payload.removeAll()
        transientIntent = intent
        let prepared = try await model.prepareTransientConnection(host, intent: intent)
        var committed = false
        defer { if !committed { prepared.cancel(); intent.cancel(); transientIntent = nil } }
        preparedTabCount = model.sessions.tabs.count; preparedConnectionAttempts = await bootstrap.facts.attempts; preparedIntentConsumed = intent.consumed
        guard preparedTabCount == 0, preparedConnectionAttempts == 0, !preparedIntentConsumed,
              model.workspacePage == .vault, model.sessions.selectedTabID == nil else { throw AppNativeFiniteFailure.unexpectedSession }
        try held.check(); try checkpoint(); try prepared.commit(); committed = true; commitCount += 1
        committedTabCount = model.sessions.tabs.count
        guard commitCount == 1, committedTabCount == 1, let tab = model.sessions.tabs.first, tab.hostID == host.id,
              tab.host?.connectionIdentity == host.connectionIdentity, tab.driver is NativeSessionDriver,
              model.sessions.selectedTabID == tab.id, model.workspacePage == .session(tab.id) else { throw AppNativeFiniteFailure.unexpectedSession }
    }
    private func transientFacts() async throws -> AppNativePasswordTransientFacts {
        guard let intent = transientIntent else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        let calls = await bootstrap.facts.primaryProviderCalls
        return try AppNativePasswordTransientFacts(preparedTabCount: preparedTabCount, preparedConnectionAttempts: preparedConnectionAttempts,
            preparedIntentConsumed: preparedIntentConsumed, commitCount: commitCount, committedTabCount: committedTabCount,
            intentConsumed: intent.consumed, primaryProviderCalls: calls)
    }
    private func answerMFA(tab: SessionTab, native: NativeSessionDriver, host: HostConfiguration, fixture: AppMFAFixture) async throws {
        guard let manager = mfaManager, let token = native.token else { throw AppNativeFiniteFailure.unexpectedSession }
        var budget = try AppMFAKIBudget(deadline: ProcessInfo.processInfo.systemUptime + max(0, remainingPhaseSeconds()))
        var pendingPrompt: SessionAuthenticationPrompt?
        var requestIDs: Set<UUID> = []
        defer {
            mfaSessionID = budget.sessionID; mfaKeyboard = AppMFAKIFacts(budget)
            if pendingPrompt != nil || tab.state != .connected {
                manager.cancel(); budget.close()
                if let prompt = pendingPrompt { model.sessions.cancelChallenge(prompt, tabID: tab.id) }
                native.cancel() // Revokes token and the production reply mailbox, never an empty answer.
            }
        }
        func current(_ prompt: SessionAuthenticationPrompt) -> Bool {
            model.sessions.tabs.count == 1 && model.sessions.tabs.first === tab && tab.driver === native && native.token == token &&
            prompt.token == token && tab.authentication == prompt && tab.state == .authenticating && tab.hostID == host.id &&
            tab.host?.connectionIdentity == host.connectionIdentity && model.sessions.selectedTabID == tab.id && model.sessions.workspaceVisible
        }
        for _ in 0..<4 {
            try await wait { tab.authentication != nil || tab.state == .connected || tab.canReconnect }
            guard let prompt = tab.authentication, current(prompt), requestIDs.insert(prompt.id).inserted,
                  case .keyboard(let name, let instruction, let fields) = prompt.payload else { throw AppNativeFiniteFailure.unexpectedAuthentication }
            pendingPrompt = prompt
            let owner = AppMFAReplyOwner(tabID: tab.id, sessionID: token.sessionID, requestID: prompt.id, hostID: host.id,
                generation: token.generation, port: fixture.port)
            let phase = try budget.claim(name: name, instruction: instruction, fields: fields.map(\.text), echo: fields.map(\.echo), now: ProcessInfo.processInfo.systemUptime)
            var answer = Data()
            defer { answer.resetBytes(in: 0..<answer.count); answer.removeAll() }
            switch phase {
            case .secret(let session, let index):
                mfaSessionID = session
                try budget.claimManagementRead(phase)
                let deadline = ProcessInfo.processInfo.systemUptime + max(0, remainingPhaseSeconds())
                answer = try await Task.detached { try manager.response(session: session, index: index, deadline: deadline) }.value
            case .zero: break // An explicit protocol acknowledgement, no management response read.
            }
            try checkpoint()
            guard current(prompt), let currentToken = native.token, let currentHost = tab.host else { throw AppNativeFiniteFailure.unexpectedAuthentication }
            try owner.validate(current: AppMFAReplyOwner(tabID: tab.id, sessionID: currentToken.sessionID, requestID: prompt.id,
                hostID: currentHost.id, generation: currentToken.generation, port: currentHost.port))
            try budget.consume(phase, now: ProcessInfo.processInfo.systemUptime)
            let values: [SecretBytes]
            switch phase { case .secret: values = [SecretBytes(answer)]; case .zero: values = [] }
            try budget.resolved(model.sessions.respond(.answers(values), to: prompt, tabID: tab.id))
            pendingPrompt = nil
        }
        try budget.requireComplete()
        try await wait { tab.state == .connected || tab.authentication != nil || tab.canReconnect }
        guard tab.state == .connected, tab.authentication == nil, native.token == token else { throw AppNativeFiniteFailure.unexpectedAuthentication }
    }
    private func remainingPhaseSeconds() -> Double {
        let value = ContinuousClock.now.duration(to: min(phaseDeadline, bootstrap.budget.fullDeadline)).components
        return Double(value.seconds) + Double(value.attoseconds) / 1e18
    }
    private func finishMFACleanup() async {
        guard mfaCleanup == nil, let fixture = bootstrap.source.scenario.fixture, let manager = mfaManager else { return }
        manager.cancel()
        // The shared cleanup deadline remains authoritative; this never grants a fresh 12 seconds.
        let observedDrained = await AppMFACleanupWait.observe(deadline: phaseDeadline, pending: { manager.snapshot.pendingCalls })
        var status = AppMFAStatus.unknown, reads = 0
        let nativeClosed = driver?.snapshot.nativeCloseCompleted == true || canonicalDrained
        if let session = mfaSessionID, observedDrained, nativeClosed, manager.snapshot.pendingCalls == 0, remainingPhaseSeconds() > 0 {
            reads = 1
            do {
                let deadline = ProcessInfo.processInfo.systemUptime + remainingPhaseSeconds()
                status = try await Task.detached { try manager.sessionStatus(session: session, deadline: deadline) }.value
            } catch { status = .unknown }
        }
        let facts = manager.snapshot
        let receipt = AppMFACleanupReceipt(runID: bootstrap.source.runID, pid: getpid(), scenario: fixture,
            statusReads: reads, serverSessionStatus: status, management: facts)
        mfaCleanup = receipt
        do { try bootstrap.input.write(receipt, leaf: AppMFACleanupReceipt.leaf) } catch { recordFailure(error) }
        if status != .removed || !facts.reapEvidenceComplete || facts.pendingCalls != 0 { recordFailure(AppNativeFiniteFailure.cleanup) }
        mfaManager = nil
    }
    private func cleanupAndQuit() async {
        if let concurrentExercise {
            cleanupLimit = bootstrap.budget.cleanupDeadline(start: .now); phaseDeadline = cleanupLimit!; phaseFailure = .cleanup
            do {
                try await concurrentExercise.prepareQuit(deadline: phaseDeadline)
                try await writeReport("native-ready.json", checkpoint: "ready-for-native-quit")
            } catch { recordFailure(error); writeFailureReceipt() }
            requestQuit(); return
        }
        if let trustExercise {
            cleanupLimit = bootstrap.budget.cleanupDeadline(start: .now); phaseDeadline = cleanupLimit!; phaseFailure = .cleanup
            do {
                try await trustExercise.prepareQuit(deadline: phaseDeadline)
                try await writeReport("native-ready.json", checkpoint: "ready-for-native-quit")
            } catch { recordFailure(error); writeFailureReceipt() }
            requestQuit(); return
        }
        if let filesExercise {
            cleanupLimit = bootstrap.budget.cleanupDeadline(start: .now); phaseDeadline = cleanupLimit!; phaseFailure = .cleanup
            filesExercise.beginCleanup(deadline: phaseDeadline)
            do { try await filesExercise.prepareQuit(); try await writeReport("native-ready.json", checkpoint: "ready-for-native-quit") }
            catch { recordFailure(error); writeFailureReceipt() }
            requestQuit(); return
        }
        transientIntent?.cancel(); transientIntent = nil
        if cleanupLimit == nil { cleanupLimit = bootstrap.budget.cleanupDeadline(start: .now) }
        phaseDeadline = cleanupLimit!; phaseFailure = .cleanup
        if !model.sessions.tabs.isEmpty {
            cleanupStage = .closingTabs
            let result = await model.sessions.closeAllResult(deadline: phaseDeadline)
            if !result.entries.allSatisfy({ $0.result == .closed }) { recordFailure(AppNativeFiniteFailure.drainIncomplete) }
        }
        await finishMFACleanup()
        do {
            cleanupStage = .weakWait
            writeWeakPointIfAlive()
            try await wait { self.sessionTab == nil && self.driver == nil && self.terminalView == nil }
            if descriptorBaseline != nil {
                cleanupStage = .descriptorWait
                repeat {
                    let after = try Self.descriptors(budget: bootstrap.budget)
                    descriptorAfter = after.count
                    if descriptorSnapshots.cleanupFirst == nil { descriptorSnapshots.cleanupFirst = after }
                    descriptorSnapshots.cleanupLatest = after
                    if descriptorAfter == descriptorBaseline { break }
                    try checkpoint(); try await Task.sleep(for: .milliseconds(20))
                } while true
            }
            guard SessionRetirementRegistry.shared.activeCount == registryActive,
                  SessionRetirementRegistry.shared.retiredCount == registryRetired else { throw AppNativeFiniteFailure.resources }
            cleanupStage = .sourceCheck
            try source?.check(); try known?.check()
            if let known, let knownBytes {
                knownUnchanged = try known.read(limit: 4096) == knownBytes
                knownHostsCheckPerformed = true
            }
            let sourceValid: Bool
            switch bootstrap.source {
            case .keyonly: sourceValid = sourceUnchanged
            case .password: sourceValid = source == nil && keyID == nil
            case .files, .filesConflict, .filesCancel, .trust, .concurrent: sourceValid = false // Independent helpers never enter this shell gate.
            case .mfa(_, let material): sourceValid = material.contract.fixture.usesKey ? sourceUnchanged : source == nil && keyID == nil
            }
            guard sourceValid, knownUnchanged else { throw AppNativeFiniteFailure.sourceChanged }
            cleanupStage = .metadataDelete
            if let hostID { try await model.repository.apply([.deleteHost(hostID)]); self.hostID = nil }
            if let keyID { try await model.security.deleteKey(keyID); self.keyID = nil }
            guard await bootstrap.credentials.forbiddenCalls == 0 else { throw AppNativeFiniteFailure.unexpectedAuthentication }
            cleanupStage = .ready
            try await writeReport("native-ready.json", checkpoint: "ready-for-native-quit")
        } catch { recordFailure(error); writeFailureReceipt() }
        requestQuit()
    }
    /// Synchronous, scalar-only point. Locals cannot escape this call or cross an await.
    /// It neither pauses cleanup nor keeps objects alive for a future external trace.
    private func writeWeakPointIfAlive() {
        guard !weakPointAttempted, cleanupStage == .weakWait, failure == nil,
              ContinuousClock.now < phaseDeadline,
              let tab = sessionTab, let actualDriver = driver, let view = terminalView else { return }
        weakPointAttempted = true
        let now = ContinuousClock.now
        let remaining = now.duration(to: phaseDeadline).components
        let seconds = Double(remaining.seconds) + Double(remaining.attoseconds) / 1e18
        do {
            let point = try AppNativeFiniteWeakPoint(runID: bootstrap.source.runID, pid: getpid(),
                tabAddress: UInt(bitPattern: Unmanaged.passUnretained(tab).toOpaque()),
                driverAddress: UInt(bitPattern: Unmanaged.passUnretained(actualDriver).toOpaque()),
                viewAddress: UInt(bitPattern: Unmanaged.passUnretained(view).toOpaque()),
                elapsedSeconds: bootstrap.budget.elapsed(at: now), weakWaitRemainingSeconds: seconds)
            try bootstrap.input.write(point, leaf: AppNativeFiniteWeakPoint.leaf)
            weakPointWritten = true
        } catch { /* Optional observation only. No retries, owner retention or claimed success. */ }
    }
    private func requestQuit() {
        guard !quitting else { return }; quitting = true
        cleanupStage = .quit
        phaseDeadline = bootstrap.budget.fullDeadline; phaseFailure = .fullDeadline
        do { try audit.schedule() } catch { recordFailure(error); writeFailureReceipt(); return }
        RunLoop.main.perform(inModes: [.common, .default, .eventTracking, .modalPanel]) { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                do { try self.audit.dispatch() }
                catch { self.recordFailure(error); self.writeFailureReceipt(); return }
                NSApp.terminate(nil) // Production delegate owns close admission, stores and the true reply.
            }
        }
    }
    func beforeStoresClose(_ transfers: TransferManagerSnapshot) async {
        do {
            try audit.before()
            guard quitting, model.sessions.tabs.isEmpty, transfers.isClosed, !transfers.hasActiveWork else { throw AppNativeFiniteFailure.beforeStoresClose }
            if let concurrentExercise { try concurrentExercise.beforeStoresClose(transfers) }
            if let trustExercise { try trustExercise.beforeStoresClose(transfers) }
            if let filesExercise { try await filesExercise.beforeStoresClose(transfers) }
            try await writeReport("native-before-stores.json", checkpoint: "before-stores-close")
        } catch { recordFailure(error); writeFailureReceipt() }
    }
    func storesCloseFailed() { storesFailed = true; recordFailure(AppNativeFiniteFailure.storesClose); writeFailureReceipt() }
    func afterStoresClose() async {
        guard !storesFailed else { writeFailureReceipt(); return } // No false after/cleanup fact after a thrown store close.
        do {
            try audit.after()
            guard model.sessions.tabs.isEmpty else { throw AppNativeFiniteFailure.afterStoresClose }
            // Only the existing exact-layout owner may remove this run. Unknown files retain it.
            if let concurrentExercise {
                guard concurrentExercise.closedAndClean else { throw AppNativeFiniteFailure.cleanup }
                try bootstrap.store.cleanupEmptyStore(); storeRemoved = true
            } else if let trustExercise {
                guard trustExercise.closedAndClean else { throw AppNativeFiniteFailure.cleanup }
                try bootstrap.store.cleanupEmptyStore(); storeRemoved = true
            } else if let filesExercise {
                guard filesExercise.closedAndClean else { throw AppNativeFiniteFailure.cleanup }
                try bootstrap.store.cleanupEmptyStore(); storeRemoved = true
            } else if hostID == nil, keyID == nil, canonicalDrained, driver == nil, terminalView == nil {
                try bootstrap.store.cleanupEmptyStore(); storeRemoved = true
            }
            try await writeReport("native-after-stores.json", checkpoint: "after-stores-close")
        } catch { recordFailure(error); writeFailureReceipt() }
    }
    func applicationWillTerminate() {
        watchdog?.invalidate(); watchdog = nil
        do {
            try audit.terminating()
            let receipt = TerminationReceipt(runID: bootstrap.source.runID, pid: getpid(), passed: failure == nil && storeRemoved,
                failureCode: failure, quit: audit)
            try bootstrap.input.write(receipt, leaf: "native-will-terminate.json")
        } catch { recordFailure(error); writeFailureReceipt() }
    }
    private struct TerminationReceipt: Encodable {
        let schema = 1
        let runID: String, pid: Int32, passed: Bool, failureCode: AppNativeFiniteFailure?, quit: AppNativeFiniteQuitAudit
    }
    private struct FailureReceipt: Encodable {
        let schema = 1
        let runID: String, pid: Int32
        let failureCode: AppNativeFiniteFailure, cleanup: AppNativeFiniteCleanupSnapshot
        let weakPointWritten: Bool
        let descriptorSnapshots: AppNativeFiniteDescriptorSnapshots?
    }
    private func writeFailureReceipt() {
        guard !failureReceiptWritten, let failure else { return }
        do {
            if let concurrentExercise {
                try concurrentExercise.writeReport(leaf: "native-failure.json", checkpoint: "failure", failure: failure, storeRemoved: storeRemoved, quit: audit)
                failureReceiptWritten = true; return
            }
            if let trustExercise {
                try trustExercise.writeReport(leaf: "native-failure.json", checkpoint: "failure", failure: failure, storeRemoved: storeRemoved, quit: audit)
                failureReceiptWritten = true; return
            }
            if let filesExercise {
                try filesExercise.writeReport(leaf: "native-failure.json", checkpoint: "failure", failure: failure, storeRemoved: storeRemoved, quit: audit)
                failureReceiptWritten = true; return
            }
            try bootstrap.input.write(FailureReceipt(runID: bootstrap.source.runID, pid: getpid(), failureCode: failure,
                cleanup: failureCleanup ?? cleanupSnapshot(), weakPointWritten: weakPointWritten,
                descriptorSnapshots: reportedDescriptorSnapshots), leaf: "native-failure.json")
            failureReceiptWritten = true
        } catch { /* Never expose paths, private input, or arbitrary errors. Outer receipt gate fails. */ }
    }
    private func recordFailure(_ error: any Error) {
        if failure == nil { failure = (error as? AppNativeFiniteFailure) ?? (error is CancellationError ? .cancelled : .operation) }
        if failureCleanup == nil { failureCleanup = cleanupSnapshot(); failureDescriptorSnapshots = descriptorSnapshots }
    }
    private var reportedDescriptorSnapshots: AppNativeFiniteDescriptorSnapshots? {
        let values = failureDescriptorSnapshots ?? descriptorSnapshots
        return values.baseline == nil ? nil : values
    }
    private func cleanupSnapshot() -> AppNativeFiniteCleanupSnapshot {
        let snapshot = driver?.snapshot
        let active = AppNativeFiniteActiveSnapshot(activeStage: activeStage, terminalEvidence: terminalEvidence,
            requestedRows: requestedRows, requestedColumns: requestedColumns,
            driverHasLatestResize: snapshot?.hasLatestResize, driverResizeInFlight: snapshot?.resizeInFlight,
            terminalRows: terminalView?.rows, terminalColumns: terminalView?.columns,
            inputBeforeAdmission: inputBeforeAdmission, inputAfterAdmission: inputAfterAdmission)
        return AppNativeFiniteCleanupSnapshot(cleanupStage: cleanupStage,
            weakTabAlive: sessionTab != nil, weakDriverAlive: driver != nil, weakViewAlive: terminalView != nil,
            terminalHasSuperview: terminalView?.superview != nil, terminalHasWindow: terminalView?.window != nil,
            currentSessionTabCount: model.sessions.tabs.count, workspaceIsVault: model.workspacePage == .vault,
            descriptorObserved: descriptorAfter != nil, knownHostsCheckPerformed: knownHostsCheckPerformed, active: active)
    }
    private func writeReport(_ leaf: String, checkpoint: String) async throws {
        if let concurrentExercise {
            guard await bootstrap.facts.attempts == 0 else { throw AppNativeFiniteFailure.unexpectedSession }
            try concurrentExercise.writeReport(leaf: leaf, checkpoint: checkpoint, failure: failure, storeRemoved: storeRemoved, quit: audit); return
        }
        if let trustExercise {
            guard await bootstrap.facts.attempts == 0 else { throw AppNativeFiniteFailure.unexpectedSession }
            try trustExercise.writeReport(leaf: leaf, checkpoint: checkpoint, failure: failure, storeRemoved: storeRemoved, quit: audit); return
        }
        if let filesExercise {
            guard await bootstrap.facts.attempts == 0, model.sessions.tabs.isEmpty else { throw AppNativeFiniteFailure.unexpectedSession }
            try filesExercise.writeReport(leaf: leaf, checkpoint: checkpoint, failure: failure, storeRemoved: storeRemoved, quit: audit)
            return
        }
        let filesSnapshot = await model.files.manager.snapshot()
        guard !model.files.visible, model.files.state == .disconnected, filesSnapshot.jobs.isEmpty,
              filesSnapshot.serviceOperations.isEmpty, !filesSnapshot.hasActiveWork else { throw AppNativeFiniteFailure.unexpectedSession }
        let report = await Report(scenario: bootstrap.source.scenario, runID: bootstrap.source.runID, pid: getpid(), checkpoint: checkpoint,
            passed: failure == nil, failureCode: failure, elapsedSeconds: bootstrap.budget.elapsed(), authentication: authentication,
            mfaAuthentication: mfaAuthentication, mfaKeyboard: mfaKeyboard,
            terminal: terminalEvidence, exitStatus: exitStatus, closeDisposition: closeDisposition,
            canonicalDrained: canonicalDrained, nativeInputBytesAfterExit: nativeInputBytesAfterExit,
            nativeInputEvidence: nativeInputBytesAfterExit == nil ? "notDirectlyObservableAfterRelease" : "observedWhileSessionAlive",
            driverQueueSnapshotEmpty: queuesEmpty,
            sourceKeyUnchanged: (bootstrap.source.scenario == .keyonly || bootstrap.source.scenario.fixture?.usesKey == true) ? sourceUnchanged : nil,
            sourceKeyScope: (bootstrap.source.scenario == .password || bootstrap.source.scenario.fixture == .passwordKI) ? .notApplicablePassword : nil, transient: transient,
            fixtureKnownHostsUnchanged: knownUnchanged, trustMatchedOutOfBand: trustMatched,
            credentialCalls: bootstrap.credentials.forbiddenCalls, connectionAttempts: bootstrap.facts.attempts, productionSessions: bootstrap.facts.productionSessions,
            filesVisible: model.files.visible, transferJobs: filesSnapshot.jobs.count, filesOperations: filesSnapshot.serviceOperations.count,
            descriptorBaseline: descriptorBaseline, descriptorAfter: descriptorAfter, registryBaselineActive: registryActive, registryBaselineRetired: registryRetired,
            registryAfterActive: SessionRetirementRegistry.shared.activeCount, registryAfterRetired: SessionRetirementRegistry.shared.retiredCount,
            weakDriverReleased: driver == nil, weakViewReleased: terminalView == nil, localStoreRemoved: storeRemoved, quit: audit,
            cleanup: failureCleanup ?? cleanupSnapshot(), weakPointWritten: weakPointWritten,
            descriptorSnapshots: reportedDescriptorSnapshots)
        try bootstrap.input.write(report, leaf: leaf)
    }
    private static func descriptors(budget: AppNativeFiniteBudget) throws -> AppNativeFiniteDescriptorSnapshot {
        let limit = getdtablesize()
        guard limit > 0, limit <= 1_048_576 else { throw AppNativeFiniteFailure.resources }
        let elapsed = budget.elapsed()
        var count = 0, entries: [AppNativeFiniteDescriptorEntry] = []
        for fd in 0..<limit {
            errno = 0
            if fcntl(fd, F_GETFD) != -1 {
                count += 1 // The original count never depends on optional diagnostic probes/cap.
                if entries.count < AppNativeFiniteDescriptorSnapshots.entryLimit { entries.append(descriptorEntry(fd)) }
            } else if errno != EBADF { throw AppNativeFiniteFailure.resources }
        }
        return .init(elapsedSeconds: elapsed, scanUpperExclusive: limit, count: count, entries: entries)
    }
    private static func descriptorEntry(_ fd: Int32) -> AppNativeFiniteDescriptorEntry {
        func value() -> AppNativeFiniteDescriptorValue? {
            var info = stat()
            guard fstat(fd, &info) == 0 else { return nil }
            let flags = fcntl(fd, F_GETFL)
            guard flags != -1 else { return nil }
            return .init(mode: UInt32(info.st_mode), uid: info.st_uid, dev: info.st_dev, ino: info.st_ino, access: flags & O_ACCMODE)
        }
        let first = value()
        var path: String?
        if let first, first.uid == 0, first.mode & UInt32(S_IFMT) == UInt32(S_IFREG), first.access == O_RDONLY {
            var bytes = [CChar](repeating: 0, count: 1024)
            if fcntl(fd, F_GETPATH, &bytes) == 0, let end = bytes.firstIndex(of: 0), end > 0 {
                path = String(bytes: bytes[..<end].map { UInt8(bitPattern: $0) }, encoding: .utf8)
            }
            _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
        }
        // A changed/closed slot remains counted and gets an unknown value, never a release fact.
        return .observed(fd: fd, first: first, second: value(), path: path)
    }
}
#endif

#if HOST_PROBE
import COpenLXSSHAskpass

fileprivate struct AppMFAPublicMaterial {
    let contract: AppMFAMaterialContract, hostKeyLine: String
    static func load(_ wrapper: AppMFAContract, buildEpoch: Double) throws -> Self {
        let path = wrapper.materialContractPath
        _ = try AppMFAContract.id(at: path, leaf: AppMFAContract.materialLeaf)
        let held = try AppNativeFiniteStableFile(path)
        let value = try AppMFAMaterialContract.decodeStrict(held.read(limit: 8192), fixture: wrapper.scenario)
        let now = Date().timeIntervalSince1970
        try value.validate(path: path, now: now, buildEpoch: buildEpoch)
        guard value.runID == wrapper.runID else { throw AppNativeFiniteFailure.contract }
        for directory in [AppNativeFiniteContract.inputRoot, URL(fileURLWithPath: path).deletingLastPathComponent().path,
                          AppRealIntegrationContract.fixtureRoot + "/.runtime", AppRealIntegrationContract.fixtureRoot + "/.runtime/" + value.service, value.generation] {
            let fd = try AppRealPrivateInput.directory(directory); Darwin.close(fd)
        }
        let policy = try AppNativeFiniteStableFile(URL(fileURLWithPath: path).deletingLastPathComponent().appendingPathComponent(AppMFAContract.policyLeaf).path)
        let proof = try policy.read(limit: 4096)
        guard AppRealPrivateInput.sha(proof) == value.policyProofSHA256 else { throw AppNativeFiniteFailure.contract }
        try value.validatePolicyProof(proof, now: now, buildEpoch: buildEpoch)
        let state = try AppNativeFiniteStableFile(AppRealIntegrationContract.fixtureRoot + "/.runtime/state.json")
        try value.validateState(state.read(limit: 4096))
        let provenance = try AppNativeFiniteStableFile(value.generation + "/provenance.json"), known = try AppNativeFiniteStableFile(value.generation + "/known_hosts")
        let origin = try provenance.read(limit: 4096), bytes = try known.read(limit: 4096)
        guard AppRealPrivateInput.sha(origin) == value.provenanceSHA256, AppRealPrivateInput.sha(bytes) == value.knownHostsSHA256 else { throw AppNativeFiniteFailure.contract }
        try value.validateProvenance(origin)
        guard let text = String(data: bytes, encoding: .utf8), text.hasSuffix("\n"), !text.dropLast().contains("\n") else { throw AppNativeFiniteFailure.trustMismatch }
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == Substring("[127.0.0.1]:" + String(value.port)), fields[1] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51, blob.base64EncodedString() == fields[2],
              "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast() == value.expectedFingerprint else { throw AppNativeFiniteFailure.trustMismatch }
        let line = fields[1...2].joined(separator: " ")
        guard try HostPublicKey(openSSHPublicKey: line).fingerprint == value.expectedFingerprint else { throw AppNativeFiniteFailure.trustMismatch }
        if value.fixture.usesKey {
            let publicKey = try AppNativeFiniteStableFile(value.generation + "/id_ed25519.pub")
            guard AppRealPrivateInput.sha(try publicKey.read(limit: 4096)) == value.generationPublicKeySHA256 else { throw AppNativeFiniteFailure.contract }
            try publicKey.check()
        }
        try held.check(); try policy.check(); try state.check(); try provenance.check(); try known.check()
        return Self(contract: value, hostKeyLine: line)
    }
}

/// Fixed reviewed root reader. Script bytes are constant; session/index are separate validated argv.
/// It never discovers endpoints/containers, evaluates shell input, or emits captured output.
fileprivate final class AppMFAManagement: @unchecked Sendable {
    private static let executable = "/Applications/Docker.app/Contents/Resources/bin/docker"
    private static let reader = #"""
import json,os,re,stat,sys,time
fds=[]
try:
    assert os.getuid()==0 and os.getgid()==0
    action,session,index=sys.argv[1:]
    assert action in ('policy','response','session-state')
    assert (action=='policy' and session=='none' and index=='none') or (action!='policy' and re.fullmatch(r'[0-9a-f]{24}',session) and index in ('0','1','2','none'))
    directory=os.open('/run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(directory)
    directory=os.open('openlxssh-fixture',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);fds.append(directory)
    info=os.fstat(directory);assert info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755
    if action!='policy':
        directory=os.open('sessions',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);fds.append(directory)
        info=os.fstat(directory);assert info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700
    name='config.json' if action=='policy' else session+'.json'
    try:fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=directory)
    except FileNotFoundError:
        assert action=='session-state'
        os.write(1,b'{"present":false}')
        raise SystemExit(0)
    fds.append(fd);before=os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=4096
    raw=bytearray()
    while len(raw)<=4096:
        part=os.read(fd,min(2048,4097-len(raw)))
        if not part:break
        raw.extend(part)
    after=os.fstat(fd)
    identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    assert len(raw)==before.st_size and identity(before)==identity(after)
    def unique(pairs):
        result={}
        for key,value in pairs:
            assert key not in result
            result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=unique)
    if action=='policy':
        assert set(value)=={'version','mode','scenario','delay'} and type(value['version']) is int and value['version']==1
        assert value['mode'] in ('keyonly','passwordonly','key-kbd','password-kbd') and value['scenario']=='multi' and type(value['delay']) is int and 1<=value['delay']<=60
        output=value
    elif action=='session-state':
        output={'present':True}
    else:
        assert index in ('0','1','2') and set(value)=={'session','expires_at','scenario','responses'}
        assert value['session']==session and value['scenario']=='multi' and type(value['expires_at']) in (int,float) and time.time()<value['expires_at']<=time.time()+75
        assert type(value['responses']) is list and len(value['responses'])==3 and all(type(x) is str and re.fullmatch(r'[0-9]{8}',x) for x in value['responses'])
        output={'session':session,'index':int(index),'expires_at':value['expires_at'],'response':value['responses'][int(index)]}
    encoded=json.dumps(output,separators=(',',':')).encode();assert len(encoded)<=4096
    view=memoryview(encoded)
    while view:
        n=os.write(1,view);assert n>0;view=view[n:]
except Exception:
    raise SystemExit(1)
finally:
    for fd in reversed(fds):os.close(fd)
"""#
    private let material: AppMFAMaterialContract
    private let lock = NSLock()
    private var activeCancellation: OpaquePointer?, cancelled = false
    private var calls = 0, returned = 0, successfulReaped = 0, pending = 0
    init(material: AppMFAMaterialContract) throws {
        self.material = material
        var info = stat()
        guard lstat(Self.executable, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o022 == 0 else { throw AppNativeFiniteFailure.unsafeInput }
    }
    func cancel() {
        lock.lock(); defer { lock.unlock() }
        cancelled = true; if let activeCancellation { ap_cancel_set(activeCancellation) }
    }
    var snapshot: AppMFAManagementFacts {
        lock.lock(); defer { lock.unlock() }
        return AppMFAManagementFacts(calls: calls, returnedCalls: returned, successfulReapedCalls: successfulReaped, pendingCalls: pending,
            cancellationRequested: cancelled, reapEvidenceComplete: pending == 0 && returned == calls && successfulReaped == calls)
    }
    private enum Operation { case response(String, Int), status(String) }
    private func run(_ operation: Operation, deadline: Double) throws -> Data {
        let session: String, index: String, action: String, limit: Int, statusOnly: Bool
        switch operation {
        case .response(let id, let number):
            guard (0..<3).contains(number) else { throw AppNativeFiniteFailure.contract }
            session = id; index = String(number); action = "response"; limit = 4096; statusOnly = false
        case .status(let id): session = id; index = "none"; action = "session-state"; limit = 256; statusOnly = true
        }
        guard AppRealIntegrationContract.hex(session, count: 24), deadline.isFinite,
              let cancellation = ap_cancel_create() else { throw AppNativeFiniteFailure.contract }
        defer { ap_cancel_free(cancellation) }
        lock.lock()
        guard pending == 0, statusOnly || !cancelled else { lock.unlock(); throw AppNativeFiniteFailure.cancelled }
        pending += 1; calls += 1; activeCancellation = cancellation
        lock.unlock()
        defer { lock.lock(); pending -= 1; returned += 1; activeCancellation = nil; lock.unlock() }
        let seconds = min(10, deadline - ProcessInfo.processInfo.systemUptime)
        guard seconds > 0 else { throw AppNativeFiniteFailure.cleanup }
        let args = [Self.executable, "--host", AppNativePasswordIdentity.endpoint, "exec", "--user", "0:0", material.fixture.container,
                    "/usr/bin/python3", "-c", Self.reader, action, session, index]
        let environment = ["PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=/var/empty", "DOCKER_CONFIG=/Users/liuwenshuo/.docker"]
        let argv = args.map { $0.withCString { strdup($0) } } + [nil]
        let env = environment.map { $0.withCString { strdup($0) } } + [nil]
        defer { (argv + env).forEach { free($0) } }
        guard (argv + env).compactMap({ $0 }).count == args.count + environment.count else { throw AppNativeFiniteFailure.operation }
        var output = Data(count: limit), count = 0, status: Int32 = -1
        let code = argv.withUnsafeBufferPointer { a in env.withUnsafeBufferPointer { e in output.withUnsafeMutableBytes { bytes in
            ap_tool(Self.executable, UnsafeMutablePointer(mutating: a.baseAddress!), UnsafeMutablePointer(mutating: e.baseAddress!), cancellation,
                seconds, 0, bytes.baseAddress, bytes.count, &count, &status)
        } } }
        if code == 0 { lock.lock(); successfulReaped += 1; lock.unlock() }
        guard code == 0, status == 0 else { output.resetBytes(in: 0..<output.count); throw AppNativeFiniteFailure.operation }
        output.count = count; return output
    }
    func response(session: String, index: Int, deadline: Double) throws -> Data {
        var bytes = try run(.response(session, index), deadline: deadline)
        defer { bytes.resetBytes(in: 0..<bytes.count); bytes.removeAll() }
        return try AppMFAOTP.decode(bytes, session: session, index: index, now: Date().timeIntervalSince1970)
    }
    func sessionStatus(session: String, deadline: Double) throws -> AppMFAStatus {
        let bytes = try run(.status(session), deadline: deadline)
        if bytes == Data("{\"present\":false}".utf8) { return .removed }
        if bytes == Data("{\"present\":true}".utf8) { return .present }
        throw AppNativeFiniteFailure.contract
    }
}
#endif


#if HOST_PROBE
/// Only public files are read at bootstrap. The private key is imported by exercise() at runtime.
fileprivate struct AppFilesManifestPublicMaterial: Equatable {
    let contract: AppFilesManifestMaterial
    let hostKeyLine: String
    static func load(_ wrapper: AppFilesManifestContract, buildEpoch: Double) throws -> Self {
        try load(path: wrapper.materialContractPath, runID: wrapper.runID, buildEpoch: buildEpoch)
    }
    static func load(path: String, runID: String, buildEpoch: Double) throws -> Self {
        let held = try AppNativeFiniteStableFile(path)
        let value = try AppFilesManifestMaterial.decodeStrict(held.read(limit: 8192))
        try value.validate(path: path, now: Date().timeIntervalSince1970, buildEpoch: buildEpoch)
        guard value.runID == runID else { throw AppNativeFiniteFailure.contract }
        let state = try AppNativeFiniteStableFile(AppRealIntegrationContract.fixtureRoot + "/.runtime/state.json")
        try value.validateState(state.read(limit: 4096))
        let origin = try AppNativeFiniteStableFile(value.generation + "/provenance.json")
        let provenance = try origin.read(limit: 4096)
        guard AppRealPrivateInput.sha(provenance) == value.provenanceSHA256 else { throw AppNativeFiniteFailure.contract }
        try value.validateProvenance(provenance)
        let known = try AppNativeFiniteStableFile(value.generation + "/known_hosts")
        let bytes = try known.read(limit: 4096)
        guard AppRealPrivateInput.sha(bytes) == value.knownHostsSHA256, let text = String(data: bytes, encoding: .utf8),
              text.hasSuffix("\n"), !text.dropLast().contains("\n") else { throw AppNativeFiniteFailure.trustMismatch }
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == "[127.0.0.1]:22221", fields[1] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51, blob.base64EncodedString() == fields[2] else { throw AppNativeFiniteFailure.trustMismatch }
        let line = fields[1...2].joined(separator: " ")
        guard try HostPublicKey(openSSHPublicKey: line).fingerprint == value.expectedFingerprint else { throw AppNativeFiniteFailure.trustMismatch }
        let publicKey = try AppNativeFiniteStableFile(value.generation + "/id_ed25519.pub")
        guard AppRealPrivateInput.sha(try publicKey.read(limit: 4096)) == value.generationPublicKeySHA256 else { throw AppNativeFiniteFailure.contract }
        try held.check(); try state.check(); try origin.check(); try known.check(); try publicKey.check()
        return Self(contract: value, hostKeyLine: line)
    }
}
/// Synchronous metadata accounting only. Payload bytes are hashed only when the production
/// caller already read/wrote them. No second read, alternate service, socket or retained service.
fileprivate final class AppFilesManifestFacts: @unchecked Sendable {
    private struct Handle {
        let side: String, path: RemotePath, writing: Bool, phaseID: UUID?
        var count = 0, hash = SHA256()
    }
    private let lock = NSLock()
    let scope: AppFilesManifestScope
    private var remote = AppFilesManifestIO(), local = AppFilesManifestIO()
    private var handles: [FileHandleID: Handle] = [:], streams: [AppFilesManifestStream] = []
    private var conflictStreams: [AppFilesConflictStream] = []
    private var phases = AppFilesConflictPhaseLedger()
    private var cancelPhases = AppFilesCancelPhaseLedger()
    let mode: AppFilesRunMode
    let cancelGate = AppFilesCancelReadGate()
    private var committedPaths: Set<Data> = []
    private var cancelledPartialPaths: Set<Data> = []
    private var remoteBytesByPath: [Data: UInt64] = [:]
    private var removedTemporaryPaths: Set<Data> = []
    private var openingHandles = 0
    private var attempts = 0, remoteServices = 0, localServices = 0, closedRemote = 0, closedLocal = 0
    private var rescued = 0, closeFailures = 0, invalid = false
    private var probeDirectory: RemotePath?
    private var bindings: [UUID] = []
    init(scope: AppFilesManifestScope, mode: AppFilesRunMode = .roundtrip) { self.scope = scope; self.mode = mode }
    private var activePhase: UUID? { mode == .cancelRetry ? cancelPhases.active : phases.active }
    private func held<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }
    func attempt() throws { try held { guard attempts == 0 else { invalid = true; throw AppNativeFiniteFailure.unexpectedSession }; attempts += 1 } }
    func created(side: String, binding: UUID?) throws {
        try held {
            if side == "remote" {
                guard remoteServices == 0, let binding else { invalid = true; throw AppNativeFiniteFailure.unexpectedSession }
                remoteServices += 1; bindings.append(binding)
            } else { localServices += 1; if localServices > 2 { invalid = true; throw AppNativeFiniteFailure.resources } }
        }
    }
    func approveProbe(_ path: RemotePath) throws {
        try held {
            guard probeDirectory == nil, path.parent.bytes == Data(scope.root.utf8),
                  path.name?.bytes.starts(with: Data(".openlxssh-capability.".utf8)) == true else { invalid = true; throw AppNativeFiniteFailure.operation }
            probeDirectory = path
        }
    }
    func checkMutation(_ path: RemotePath, side: String) throws {
        guard side != "source", side != "fresh" else { held { invalid = true }; throw AppNativeFiniteFailure.operation }
        guard side == "remote" else { return }
        try held {
            guard scope.allowsRemoteMutation(path.bytes, approvedProbe: probeDirectory?.bytes) else {
                invalid = true; throw AppNativeFiniteFailure.operation
            }
        }
    }
    func event(_ key: String, side: String) {
        held {
            var value = side == "remote" ? remote : local
            switch key {
            case "readOpen": value.readOpen += 1
            case "writeOpen": value.writeOpen += 1; value.mutations += 1
            case "read": value.read += 1
            case "write": value.write += 1; value.mutations += 1
            default: value.mutations += 1
            }
            if side == "remote" { remote = value } else { local = value }
        }
    }
    func openingPhase() -> UUID? { held { openingHandles += 1; return activePhase } }
    func openFailed() { held { openingHandles -= 1 } }
    func opened(_ id: FileHandleID, path: RemotePath, writing: Bool, side: String, phaseID: UUID?) {
        held { openingHandles -= 1; if handles[id] != nil { invalid = true }; handles[id] = Handle(side: side, path: path, writing: writing, phaseID: phaseID) }
    }
    func bytes(_ data: Data, handle: FileHandleID, writing: Bool) {
        held {
            guard var record = handles[handle], record.writing == writing, record.count <= (mode == .cancelRetry ? 262144 : 32768) - data.count else { invalid = true; return }
            record.count += data.count; record.hash.update(data: data); handles[handle] = record
            if record.side == "remote" {
                if writing { remote.writeBytes += UInt64(data.count); remoteBytesByPath[record.path.bytes, default: 0] += UInt64(data.count) } else { remote.readBytes += UInt64(data.count) }
            } else {
                if writing { local.writeBytes += UInt64(data.count) } else { local.readBytes += UInt64(data.count) }
            }
        }
    }
    func closed(_ id: FileHandleID) {
        held {
            guard let record = handles.removeValue(forKey: id), streams.count < 64 else { invalid = true; return }
            let value = AppFilesManifestStream(side: record.side, pathBase64: record.path.bytes.base64EncodedString(), writing: record.writing,
                bytes: record.count, sha256: record.hash.finalize().map { String(format: "%02x", $0) }.joined())
            streams.append(value)
            if let phaseID = record.phaseID { conflictStreams.append(.init(phaseID: phaseID, value: value)) }
        }
    }
    func failedHandleClose() { held { closeFailures += 1 } }
    func committed(_ from: RemotePath, to: RemotePath, side: String) {
        held {
            committedPaths.insert(to.bytes)
            conflictStreams = conflictStreams.map { record in
                guard record.phaseID == activePhase, record.value.side == side, record.value.writing,
                      record.value.pathBase64 == from.bytes.base64EncodedString() else { return record }
                let value = record.value
                return .init(phaseID: record.phaseID, value: .init(side: side, pathBase64: to.bytes.base64EncodedString(), writing: true, bytes: value.bytes, sha256: value.sha256))
            }
            streams = streams.map { record in
                guard record.side == side, record.writing, record.pathBase64 == from.bytes.base64EncodedString() else { return record }
                return AppFilesManifestStream(side: side, pathBase64: to.bytes.base64EncodedString(), writing: true, bytes: record.bytes, sha256: record.sha256)
            }
        }
    }
    func serviceClosed(side: String) {
        held {
            let abandoned = handles.filter { $0.value.side == side }.map(\.key)
            rescued += abandoned.count; for id in abandoned { handles[id] = nil }
            if side == "remote" { closedRemote += 1 } else { closedLocal += 1 }
        }
    }
    func snapshot() -> AppFilesManifestServiceFacts {
        held { .init(remote: remote, local: local, attempts: attempts, remoteServices: remoteServices, localServices: localServices,
            closedRemote: closedRemote, closedLocal: closedLocal, liveHandles: handles.count, rescuedHandles: rescued,
            handleCloseFailures: closeFailures, observationFailed: invalid, bindings: bindings) }
    }
    func observed(side: String, path: RemotePath, writing: Bool) -> [AppFilesManifestStream] {
        held { streams.filter { $0.side == side && $0.pathBase64 == path.bytes.base64EncodedString() && $0.writing == writing } }
    }
    func beginPhase(_ label: String) throws -> UUID {
        try held { mode == .cancelRetry ? try cancelPhases.begin(label, liveHandles: handles.count + openingHandles) : try phases.begin(label, liveHandles: handles.count + openingHandles) }
    }
    func bindPhase(_ id: UUID, job: TransferJobSnapshot) throws {
        try held { if mode == .cancelRetry { try cancelPhases.bind(id, jobID: job.id, generation: job.generation) } else { try phases.bind(id, jobID: job.id, generation: job.generation) } }
    }
    func finishPhase(_ id: UUID) throws {
        try held { if mode == .cancelRetry { try cancelPhases.finish(id, liveHandles: handles.count + openingHandles) } else { try phases.finish(id, liveHandles: handles.count + openingHandles) } }
    }
    func phaseRecords(_ id: UUID, side: String, path: RemotePath, writing: Bool) -> [AppFilesConflictStream] {
        held { conflictStreams.filter { $0.phaseID == id && $0.value.side == side && $0.value.pathBase64 == path.bytes.base64EncodedString() && $0.value.writing == writing } }
    }
    func beforeLocalRead(_ handle: FileHandleID, token: CancellationToken) async throws {
        guard mode == .cancelRetry else { return }
        let info = held { handles[handle].map { ($0.path.bytes, $0.phaseID) } }
        guard let info else { throw AppNativeFiniteFailure.operation }
        try await cancelGate.beforeRead(path: info.0, phaseID: info.1, token: token)
    }
    func hasCommitted(_ path: RemotePath) -> Bool { held { committedPaths.contains(path.bytes) } }
    func writtenTemporaryBytes() -> UInt64 { held { handles.values.filter { $0.side == "remote" && $0.writing && $0.phaseID == activePhase }.reduce(0) { $0 + remoteBytesByPath[$1.path.bytes, default: 0] } } }
    func captureCancelledTemporary(phaseID: UUID) throws {
        try held {
            let paths = handles.values.filter { $0.side == "remote" && $0.writing && $0.phaseID == phaseID }.map { $0.path }
            guard paths.count == 1, let path = paths.first, scope.contains(path.bytes), path.name?.bytes.starts(with: Data(".openlxssh-transfer.".utf8)) == true else { throw AppNativeFiniteFailure.operation }
            cancelledPartialPaths.insert(path.bytes)
        }
    }
    func removed(_ path: RemotePath) { held { _ = removedTemporaryPaths.insert(path.bytes) } }
    func allowedPartial(_ record: AppFilesConflictStream) -> Bool {
        held { guard let raw = Data(base64Encoded: record.value.pathBase64) else { return false }; return cancelledPartialPaths.contains(raw) && removedTemporaryPaths.contains(raw) }
    }
    func phaseStreams(_ id: UUID) -> [AppFilesConflictStream] { held { conflictStreams.filter { $0.phaseID == id } } }
}
fileprivate actor AppFilesManifestObservedService: RemoteFileService {
    nonisolated let capabilities: FileServiceCapabilities, serverBinding: UUID?
    private let base: any RemoteFileService, facts: AppFilesManifestFacts, side: String
    private var closed = false
    init(_ base: any RemoteFileService, facts: AppFilesManifestFacts, side: String) {
        self.base = base; self.facts = facts; self.side = side; capabilities = base.capabilities; serverBinding = base.serverBinding
    }
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(path, token: token) }
    func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(path, token: token) }
    func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(handle, token: token) }
    func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        if mode == .exclusiveWrite { try facts.checkMutation(path, side: side) }
        facts.event(mode == .read ? "readOpen" : "writeOpen", side: side)
        let phase = facts.openingPhase()
        do {
            let id = try await base.open(path, mode: mode, token: token)
            facts.opened(id, path: path, writing: mode == .exclusiveWrite, side: side, phaseID: phase); return id
        } catch { facts.openFailed(); throw error }
    }
    func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        if side == "source" { try await facts.beforeLocalRead(handle, token: token) }
        facts.event("read", side: side)
        let bytes = try await base.read(handle, maxBytes: maxBytes, token: token)
        facts.bytes(bytes, handle: handle, writing: false); return bytes
    }
    func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        facts.event("write", side: side)
        let count = try await base.write(handle, data: data, token: token)
        guard count >= 0, count <= data.count else { throw AppNativeFiniteFailure.operation }
        facts.bytes(Data(data.prefix(count)), handle: handle, writing: true); return count
    }
    func finish(_ handle: FileHandleID, token: CancellationToken) async throws { facts.event("finish", side: side); try await base.finish(handle, token: token) }
    func closeHandle(_ handle: FileHandleID) async throws {
        do { try await base.closeHandle(handle); facts.closed(handle) }
        catch { facts.failedHandleClose(); throw error }
    }
    func mkdir(_ path: RemotePath, token: CancellationToken) async throws {
        try facts.checkMutation(path, side: side); facts.event("mkdir", side: side); try await base.mkdir(path, token: token)
    }
    func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws {
        try facts.checkMutation(source, side: side); try facts.checkMutation(destination, side: side); facts.event("rename", side: side)
        try await base.rename(source, to: destination, mode: mode, token: token); facts.committed(source, to: destination, side: side)
    }
    func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws {
        try facts.checkMutation(source, side: side); try facts.checkMutation(destination, side: side); facts.event("commit", side: side)
        try await base.commit(source, to: destination, request: request, token: token); facts.committed(source, to: destination, side: side)
    }
    func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws {
        try facts.checkMutation(path, side: side); facts.event("remove", side: side); try await base.remove(path, directory: directory, token: token); facts.removed(path)
    }
    nonisolated func cancel() { base.cancel() }
    func close() async { guard !closed else { return }; closed = true; await base.close(); facts.serviceClosed(side: side) }
}
fileprivate struct AppFilesManifestConnector: FilesConnecting {
    let production: LibSSH2FilesConnector, facts: AppFilesManifestFacts
    init(production: LibSSH2FilesConnector, runtime: AppFilesManifestRuntime) throws {
        guard production.environment === runtime.environment else { throw AppNativeFiniteFailure.resources }
        self.production = production; facts = runtime.facts
    }
    func connect(request: FilesRequest, input: FilesConnectInput, token: CancellationToken, trust: @escaping FileHostTrustHandler,
                 keyboard: @escaping FilesKeyboardHandler, isCurrent: @escaping @Sendable () async -> Bool) async throws -> any RemoteFileService {
        guard request.host.address == "127.0.0.1", request.host.port == 22221, request.host.username == "fixture",
              request.host.authentication == .privateKey, !input.keyboardOnly else { throw AppNativeFiniteFailure.unexpectedSession }
        try facts.attempt()
        let service = try await production.connect(request: request, input: input, token: token, trust: trust, keyboard: keyboard, isCurrent: isCurrent)
        guard service is LibSSH2FileService else { await service.close(); throw AppNativeFiniteFailure.unexpectedSession }
        do { try facts.created(side: "remote", binding: service.serverBinding) }
        catch { await service.close(); throw error }
        return AppFilesManifestObservedService(service, facts: facts, side: "remote")
    }
}
/// Holds no service. Exactly two descriptor identities may reach the transparent local factory.
fileprivate final class AppFilesManifestRuntime: @unchecked Sendable {
    let scope: AppFilesManifestScope, facts: AppFilesManifestFacts
    let environment: SessionEnvironment
    private let lock = NSLock()
    private var roots: [String: String] = [:], used: Set<String> = []
    init(environment: SessionEnvironment, mode: AppFilesRunMode = .roundtrip) throws {
        self.environment = environment
        let scope = try AppFilesManifestScope(nonce: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())
        self.scope = scope; facts = AppFilesManifestFacts(scope: scope, mode: mode)
    }
    func setRoots(source: String, download: String, mode: AppFilesRunMode = .roundtrip) {
        lock.lock(); defer { lock.unlock() }; roots = [source: "source", download: mode == .conflict ? "fresh" : "download"]
    }
    func setSourceRoot(_ identity: String) { lock.lock(); defer { lock.unlock() }; roots = [identity: "source"] }
    func localService(_ fd: Int32) throws -> any RemoteFileService {
        var value = stat()
        guard fstat(fd, &value) == 0, value.st_mode & S_IFMT == S_IFDIR else { throw AppNativeFiniteFailure.unsafeInput }
        let identity = "\(value.st_dev):\(value.st_ino)"
        lock.lock()
        let side = roots[identity], fresh = used.insert(identity).inserted
        lock.unlock()
        guard let side, fresh else { throw AppNativeFiniteFailure.resources }
        let service = try LocalFileService(rootDirectoryDescriptor: fd)
        try facts.created(side: side, binding: nil)
        return AppFilesManifestObservedService(service, facts: facts, side: side)
    }
}
#endif


#if HOST_PROBE
/// Descriptor-owned physical payloads. Unknown/replaced entries retain the directory; no recursive purge.
fileprivate final class AppFilesManifestLocal {
    let source: URL, download: URL
    private let parent: Int32
    private var rootFD: Int32
    private let rootName = "ManifestFiles"
    private var owned: [String: (dev_t, ino_t, Bool)] = [:]
    private let scope: AppFilesManifestScope
    private let mode: AppFilesRunMode
    private var sourceParent: String { mode == .conflict ? "Seed" : "Source" }
    private var secondParent: String { mode == .conflict ? "Fresh" : "Download" }
    var freshSource: URL { download.appendingPathComponent(scope.tree, isDirectory: true) }
    init(store: URL, scope: AppFilesManifestScope, runtime: AppFilesManifestRuntime, mode: AppFilesRunMode = .roundtrip) throws {
        self.scope = scope; self.mode = mode
        parent = try FilesLocalPaths.openDirectory(FilesLocalPaths.components(store))
        guard mkdirat(parent, rootName, 0o700) == 0 else { Darwin.close(parent); throw AppNativeFiniteFailure.unsafeInput }
        rootFD = openat(parent, rootName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard rootFD >= 0 else { Darwin.close(parent); throw AppNativeFiniteFailure.unsafeInput }
        source = store.appendingPathComponent(rootName + (mode == .conflict ? "/Seed/" : "/Source/") + scope.tree, isDirectory: true)
        download = store.appendingPathComponent(rootName + (mode == .conflict ? "/Fresh" : "/Download"), isDirectory: true)
        do {
            try remember("", directory: true)
            var directories = [sourceParent, sourceParent + "/" + scope.tree, sourceParent + "/" + scope.tree + "/" + scope.child]
            if mode != .cancelRetry { directories.insert(secondParent, at: 1) }
            if mode == .conflict { directories += [secondParent + "/" + scope.tree, secondParent + "/" + scope.tree + "/" + scope.child] }
            for name in directories {
                let (fd, leaf) = try at(name); defer { Darwin.close(fd) }
                guard mkdirat(fd, leaf, 0o700) == 0 else { throw AppNativeFiniteFailure.unsafeInput }; try remember(name, directory: true)
            }
            for parent in mode == .conflict ? [sourceParent, secondParent] : [sourceParent] {
                for (relative, size) in scope.payloads(for: mode) {
                    let path = parent + "/" + scope.tree + "/" + relative, (fd, leaf) = try at(path); defer { Darwin.close(fd) }
                    try AppRealPrivateInput.write(Self.payload(relative, size, fresh: parent == "Fresh"), parent: fd, name: leaf); try remember(path, directory: false)
                }
            }
            if mode == .cancelRetry {
                let fd = try descriptor(sourceParent); defer { Darwin.close(fd) }; var a = stat()
                guard fstat(fd, &a) == 0 else { throw AppNativeFiniteFailure.unsafeInput }
                runtime.setSourceRoot("\(a.st_dev):\(a.st_ino)")
            } else {
                try AppFilesManifestDescriptors.withPair(source: { try descriptor(sourceParent) }, download: { try descriptor(secondParent) }) { left, right in
                    var a = stat(), b = stat()
                    guard fstat(left, &a) == 0, fstat(right, &b) == 0 else { throw AppNativeFiniteFailure.unsafeInput }
                    runtime.setRoots(source: "\(a.st_dev):\(a.st_ino)", download: "\(b.st_dev):\(b.st_ino)", mode: mode)
                }
            }
        } catch { Darwin.close(rootFD); rootFD = -1; Darwin.close(parent); throw error }
    }
    deinit { if rootFD >= 0 { Darwin.close(rootFD); Darwin.close(parent) } }
    static func payload(_ relative: String, _ size: Int, fresh: Bool = false) -> Data {
        if fresh { return AppFilesConflictPayload.data(relative: relative, size: size) }
        let seed = Data(SHA256.hash(data: Data(("OpenLXSSH non-secret Files R2 " + relative).utf8)))
        var value = Data(); while value.count < size { value.append(seed.prefix(min(seed.count, size - value.count))) }; return value
    }
    func expected(fresh: Bool = false) -> [AppFilesManifestDigest] {
        scope.payloads(for: mode).map { .init(relativePathBase64: Data($0.relative.utf8).base64EncodedString(), bytes: $0.bytes,
                                  sha256: AppRealPrivateInput.sha(Self.payload($0.relative, $0.bytes, fresh: fresh))) }
    }
    private func descriptor(_ relative: String) throws -> Int32 {
        var fd = openat(rootFD, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw AppNativeFiniteFailure.cleanup }
        do {
            for part in relative.split(separator: "/") {
                let next = openat(fd, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw AppNativeFiniteFailure.cleanup }; Darwin.close(fd); fd = next
            }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
    private func at(_ relative: String) throws -> (Int32, String) {
        let parts = relative.split(separator: "/").map(String.init)
        guard let leaf = parts.last else { throw AppNativeFiniteFailure.cleanup }
        return (try descriptor(parts.dropLast().joined(separator: "/")), leaf)
    }
    private func remember(_ path: String, directory: Bool) throws {
        var info = stat()
        if path.isEmpty { guard fstat(rootFD, &info) == 0 else { throw AppNativeFiniteFailure.cleanup } }
        else {
            let (fd, leaf) = try at(path); defer { Darwin.close(fd) }
            guard fstatat(fd, leaf, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw AppNativeFiniteFailure.cleanup }
        }
        guard info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG), info.st_uid == getuid(), directory || info.st_nlink == 1 else { throw AppNativeFiniteFailure.cleanup }
        if let previous = owned[path] { guard previous.0 == info.st_dev, previous.1 == info.st_ino, previous.2 == directory else { throw AppNativeFiniteFailure.cleanup } }
        else { owned[path] = (info.st_dev, info.st_ino, directory) }
    }
    private func names(_ fd: Int32) throws -> Set<Data> {
        let copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let directory = fdopendir(copy) else { if copy >= 0 { Darwin.close(copy) }; throw AppNativeFiniteFailure.cleanup }
        defer { closedir(directory) }
        var values: Set<Data> = []
        while true {
            errno = 0
            guard let entry = readdir(directory) else { guard errno == 0 else { throw AppNativeFiniteFailure.cleanup }; break }
            let name = withUnsafeBytes(of: entry.pointee.d_name) { Data($0.prefix(Int(entry.pointee.d_namlen))) }
            if name == Data(".".utf8) || name == Data("..".utf8) { continue }
            guard values.insert(name).inserted, values.count <= 8 else { throw AppNativeFiniteFailure.cleanup }
        }
        return values
    }
    func verify(downloaded: Bool) throws -> [AppFilesManifestDigest] {
        let fresh = downloaded && mode == .conflict
        let prefix = (downloaded ? secondParent : sourceParent) + "/" + scope.tree
        if downloaded && mode == .roundtrip { try remember(prefix, directory: true); try remember(prefix + "/" + scope.child, directory: true) }
        for relative in scope.relativeDirectories {
            let path = prefix + (relative.isEmpty ? "" : "/" + relative), fd = try descriptor(path); defer { Darwin.close(fd) }
            try remember(path, directory: true)
            let expected = relative.isEmpty ? [Data(scope.child.utf8), Data(scope.payloads[0].relative.utf8)] : [Data("内容 空格.bin".utf8)]
            guard try names(fd) == Set(expected) else { throw AppNativeFiniteFailure.cleanup }
        }
        var digests: [AppFilesManifestDigest] = []
        for (relative, size) in scope.payloads(for: mode) {
            let path = prefix + "/" + relative, (fd, leaf) = try at(path); defer { Darwin.close(fd) }
            if downloaded && mode == .roundtrip { try remember(path, directory: false) }
            let file = openat(fd, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard file >= 0 else { throw AppNativeFiniteFailure.cleanup }; defer { Darwin.close(file) }
            try AppFileSecurity.regularFile(file)
            var before = stat(), after = stat(), named = stat()
            guard fstat(file, &before) == 0, let identity = owned[path], before.st_dev == identity.0, before.st_ino == identity.1,
                  before.st_size == size else { throw AppNativeFiniteFailure.cleanup }
            var bytes = Data(), buffer = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = Darwin.read(file, &buffer, buffer.count)
                if count < 0 && errno == EINTR { continue }; guard count >= 0 else { throw AppNativeFiniteFailure.cleanup }
                if count == 0 { break }; bytes.append(contentsOf: buffer.prefix(count)); guard bytes.count <= size else { throw AppNativeFiniteFailure.cleanup }
            }
            guard bytes == Self.payload(relative, size, fresh: fresh), fstat(file, &after) == 0, fstatat(fd, leaf, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  before.st_dev == after.st_dev, before.st_ino == after.st_ino, before.st_size == after.st_size,
                  before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
                  after.st_dev == named.st_dev, after.st_ino == named.st_ino else { throw AppNativeFiniteFailure.cleanup }
            digests.append(.init(relativePathBase64: Data(relative.utf8).base64EncodedString(), bytes: bytes.count, sha256: AppRealPrivateInput.sha(bytes)))
        }
        guard digests == expected(fresh: fresh) else { throw AppNativeFiniteFailure.cleanup }; return digests
    }
    func cleanup() throws {
        _ = try verify(downloaded: false); if mode != .cancelRetry { _ = try verify(downloaded: true) }
        // Full known-layout validation precedes unlinkat; no discovered entry is adopted here.
        for (path, entry) in owned {
            try remember(path, directory: entry.2)
            if entry.2 {
                let fd = try descriptor(path); defer { Darwin.close(fd) }
                let expected = Set(owned.keys.filter { !$0.isEmpty && $0.split(separator: "/").dropLast().joined(separator: "/") == path }.map { Data($0.split(separator: "/").last!.utf8) })
                guard try names(fd) == expected else { throw AppNativeFiniteFailure.cleanup }
            }
        }
        var named = stat()
        guard let root = owned[""], fstatat(parent, rootName, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == root.0, named.st_ino == root.1 else { throw AppNativeFiniteFailure.cleanup }
        for path in owned.keys.filter({ !$0.isEmpty }).sorted(by: { $0.split(separator: "/").count > $1.split(separator: "/").count }) {
            let (fd, leaf) = try at(path); defer { Darwin.close(fd) }; try remember(path, directory: owned[path]!.2)
            guard unlinkat(fd, leaf, owned[path]!.2 ? AT_REMOVEDIR : 0) == 0 else { throw AppNativeFiniteFailure.cleanup }
        }
        guard try names(rootFD).isEmpty, fstatat(parent, rootName, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == root.0, named.st_ino == root.1, unlinkat(parent, rootName, AT_REMOVEDIR) == 0 else { throw AppNativeFiniteFailure.cleanup }
        Darwin.close(rootFD); Darwin.close(parent); rootFD = -1; owned.removeAll()
    }
}
@MainActor fileprivate final class AppFilesManifestExercise {
    private let model: AppModel, input: AppNativeFiniteInput, store: AppRealOwnedStore, runtime: AppFilesManifestRuntime
    private let material: AppFilesManifestPublicMaterial, budget: AppNativeFiniteBudget, buildEpoch: Double
    private let credentials: AppRealNoCredentials
    private let environment: SessionEnvironment
    private let mode: AppFilesRunMode
    private let descriptors: () throws -> AppNativeFiniteDescriptorSnapshot
    private let manager: TransferManager
    private let operationToken = CancellationToken()
    private var deadline: ContinuousClock.Instant
    private var cleanup = false, cancelled = false
    private var sourceKey: AppNativeFiniteStableFile?, known: AppNativeFiniteStableFile?, knownBytes: Data?
    private var local: AppFilesManifestLocal?, keyID: UUID?, hostID: UUID?, context: FilesTransferContext?
    private var baseline: AppNativeFiniteDescriptorSnapshot?, descriptorSnapshots = AppNativeFiniteDescriptorSnapshots()
    private var sourceUnchanged = false, knownUnchanged = false, trustMatched = false, capabilityPassed = false
    private var capability: AppFilesManifestCapability?
    private var transferOnly = false, remoteRemoved = false, localRemoved = false, fdMatched = false
    private var plans: [AppFilesManifestPlanEvidence] = [], jobs: [AppFilesManifestJobEvidence] = [], deleteIDs: [UUID] = []
    private var conflictJobs: [AppFilesConflictJob] = [], conflictDecisions: [AppFilesConflictDecision] = []
    private var freshDigests: [AppFilesManifestDigest] = [], verifiedRemote: [AppFilesManifestDigest] = []
    private var verificationPhaseID: UUID?
    private var verificationStreams: [AppFilesConflictStream] = []
    private var cancelJobs: [AppFilesCancelJob] = []
    private var cancelPoint: AppFilesCancelPoint?, partialVerified: AppFilesManifestDigest?
    private var retrySkipAnswered = false
    private var secondAbsentAfterCancel = false
    private var sourceDigests: [AppFilesManifestDigest] = [], remoteDigests: [AppFilesManifestDigest] = [], downloadDigests: [AppFilesManifestDigest] = []
    private var final = TransferManagerSnapshot(jobs: [], isClosed: false), credentialCalls = 0
    private(set) var closedAndClean = false
    init(model: AppModel, input: AppNativeFiniteInput, store: AppRealOwnedStore, runtime: AppFilesManifestRuntime,
         environment: SessionEnvironment, mode: AppFilesRunMode = .roundtrip, material: AppFilesManifestPublicMaterial, budget: AppNativeFiniteBudget, buildEpoch: Double, credentials: AppRealNoCredentials,
         descriptors: @escaping () throws -> AppNativeFiniteDescriptorSnapshot) throws {
        guard environment === runtime.environment else { throw AppNativeFiniteFailure.resources }
        self.environment = environment; self.mode = mode
        self.model = model; self.input = input; self.store = store; self.runtime = runtime; self.material = material
        self.budget = budget; self.buildEpoch = buildEpoch; self.credentials = credentials; self.descriptors = descriptors; manager = model.files.manager
        deadline = budget.preparationDeadline
    }
    func cancel() { cancelled = true; operationToken.cancel(); runtime.facts.cancelGate.abortIfWaiting(); model.files.beginWindowClose() }
    var phaseDeadline: ContinuousClock.Instant { deadline }
    var timeoutFailure: AppNativeFiniteFailure { cleanup ? .cleanup : (local == nil ? .preparationDeadline : .activeDeadline) }
    func beginCleanup(deadline: ContinuousClock.Instant) { cleanup = true; self.deadline = deadline }
    private func checkpoint() throws {
        guard model.sessions.tabs.isEmpty else { throw AppNativeFiniteFailure.unexpectedSession }
        if !cleanup { try Task.checkCancellation(); guard !cancelled else { throw AppNativeFiniteFailure.cancelled } }
        guard ContinuousClock.now < budget.fullDeadline else { throw AppNativeFiniteFailure.fullDeadline }
        guard ContinuousClock.now < deadline else { throw timeoutFailure }
    }
    private func wait(_ condition: () -> Bool) async throws {
        while !condition() { try checkpoint(); try await Task.sleep(for: .milliseconds(10)) }; try checkpoint()
    }
    private func settled() async throws {
        try await wait { !self.model.files.busy }
        guard model.files.issue == nil, model.files.state == .ready, model.files.keyboardPrompt == nil, model.files.trustPrompt == nil else { throw AppNativeFiniteFailure.operation }
        try sameBinding()
    }
    private func sameBinding() throws {
        let facts = runtime.facts.snapshot()
        guard facts.attempts == 1, facts.remoteServices == 1, facts.bindings.count == 1, !facts.observationFailed,
              let context, model.files.selectedHost?.id == context.hostID else { throw AppNativeFiniteFailure.resources }
        let current = try model.files.transferContext(upload: false)
        guard current.serviceID == context.serviceID, current.lifetime == context.lifetime, current.generation == context.generation,
              current.connectionIdentity == context.connectionIdentity else { throw AppNativeFiniteFailure.unexpectedSession }
    }
    private func browse(_ path: RemotePath) async throws { model.files.browse(path); try await settled(); guard model.files.path == path else { throw AppNativeFiniteFailure.operation } }
    func exercise() async throws {
        try await wait { self.model.didLoad && !self.model.isLoading }
        guard model.hosts.isEmpty, model.sessions.tabs.isEmpty, !model.files.visible else { throw AppNativeFiniteFailure.unexpectedSession }
        known = try AppNativeFiniteStableFile(material.contract.generation + "/known_hosts"); knownBytes = try known?.read(limit: 4096)
        sourceKey = try AppNativeFiniteStableFile(material.contract.generation + "/id_ed25519")
        var before = try sourceKey!.read(limit: 32768)
        defer { before.resetBytes(in: 0..<before.count); before.removeAll() }
        let key = try await model.security.createKey(.importFile(URL(fileURLWithPath: material.contract.generation + "/id_ed25519")), protection: .unencrypted, rememberPassphrase: nil)
        keyID = key.id
        guard !key.cleanupPending else { throw AppNativeFiniteFailure.importFailed }
        let publicKey = try await model.security.publicKey(key.id)
        let exported = try AppRealPrivateInput.read(material.contract.generation + "/id_ed25519.pub", limit: 4096)
        let fields = String(decoding: exported, as: UTF8.self).trimmingCharacters(in: .newlines).split(separator: " ")
        guard fields.count >= 2, publicKey.copyString == fields.prefix(2).joined(separator: " ") else { throw AppNativeFiniteFailure.importFailed }
        var after = try sourceKey!.read(limit: 32768)
        sourceUnchanged = before == after; after.resetBytes(in: 0..<after.count); after.removeAll()
        guard sourceUnchanged else { throw AppNativeFiniteFailure.sourceChanged }
        before.resetBytes(in: 0..<before.count); before.removeAll()
        let host = HostConfiguration(name: "Approved finite Files keyonly fixture", address: "127.0.0.1", port: 22221, username: "fixture", authentication: .privateKey, keyRef: key.id)
        guard await model.saveHostSecurely(host, isNew: true, password: .manual) else { throw AppNativeFiniteFailure.hostSaveFailed }; hostID = host.id
        let metadata = try await model.repository.securityMetadata()
        guard metadata.credentials.isEmpty, let saved = metadata.hosts.first(where: { $0.id == host.id }), saved.matchesConnection(of: host),
              saved.credentialRef == nil, !saved.savePasswordAuthorized, metadata.keys.first(where: { $0.id == key.id })?.passphraseCredentialRef == nil else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        // Warm the exact connector owner before the strict FD identity baseline, not
        // AppModel's separate presentation environment for the same on-disk directory.
        let trust = try await environment.sharedTrustStore()
        guard try await trust.records().isEmpty else { throw AppNativeFiniteFailure.trustMismatch }
        try input.revalidateMaterial(buildEpoch: buildEpoch)
        let baseline = try descriptors(); self.baseline = baseline; descriptorSnapshots.baseline = baseline
        // Incomplete ownership observation cannot pass close, but does not suppress transfer-only evidence.
        local = try AppFilesManifestLocal(store: store.url, scope: runtime.scope, runtime: runtime, mode: mode)
        deadline = budget.activeDeadline(start: .now)
        model.files.show(host: host); await model.files.waitUntilCurrentWorkCompletes()
        model.files.connect(.init(primary: .manual(.init(utf8: ""))))
        try await wait { self.model.files.trustPrompt != nil || self.model.files.keyboardPrompt != nil || self.model.files.state == .ready || self.model.files.state == .failed }
        guard let prompt = model.files.trustPrompt, case .pending(let decision) = prompt.event,
              material.contract.matchesTrust(host: decision.host.address.value, port: Int(decision.host.port.value), algorithm: decision.algorithm, fingerprint: decision.fingerprint),
              model.files.keyboardPrompt == nil else { throw AppNativeFiniteFailure.trustMismatch }
        guard model.files.answerTrust(prompt, once: false) else { throw AppNativeFiniteFailure.trustMismatch }; trustMatched = true
        try await wait { self.model.files.state == .ready || self.model.files.state == .failed || self.model.files.keyboardPrompt != nil }
        guard model.files.state == .ready, model.files.keyboardPrompt == nil else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        try await wait { !self.model.files.busy }
        context = try model.files.transferContext(upload: false)
        try await browse(RemotePath(runtime.scope.home))
        guard let target = model.files.captureTarget(), !model.files.entries.contains(where: { $0.name.bytes == Data(runtime.scope.basename.utf8) }) else { throw AppNativeFiniteFailure.operation }
        model.files.mkdir(try FileName(runtime.scope.basename), target: target, acknowledgedRemoteRisk: true); try await settled()
        let root = try RemotePath(runtime.scope.root); try await browse(root)
        guard model.files.entries.isEmpty else { throw AppNativeFiniteFailure.operation }
        model.files.prepareProbe(); try await settled()
        guard let probe = model.files.probeReview, probe.plan.parent == root, probe.plan.temporaryDirectory.parent == root,
              probe.plan.serverBinding == runtime.facts.snapshot().bindings.first,
              probe.plan.requiredRisks == [.remotePathChecksAreNotAtomic(path: root)] else { throw AppNativeFiniteFailure.operation }
        try runtime.facts.approveProbe(probe.plan.temporaryDirectory)
        let probeBefore = runtime.facts.snapshot()
        model.files.executeProbe(probe, approved: true); try await settled()
        guard let result = model.files.lastProbeResult, result.passed, result.retainedPaths.isEmpty,
              result.confirmation?.serverBinding == probe.plan.serverBinding else { throw AppNativeFiniteFailure.operation }
        capability = .init(planID: probe.plan.id, serverBinding: probe.plan.serverBinding, parentBase64: root.bytes.base64EncodedString(),
            directoryBase64: probe.plan.temporaryDirectory.bytes.base64EncodedString(), acknowledgedRiskCount: probe.plan.requiredRisks.count,
            passed: result.passed, retainedPathCount: result.retainedPaths.count, remoteDelta: try runtime.facts.snapshot().remote.delta(from: probeBefore.remote))
        capabilityPassed = result.passed
        guard let local else { throw AppNativeFiniteFailure.operation }
        sourceDigests = try local.verify(downloaded: false)
        if mode == .cancelRetry {
            try await transfer(upload: true, local: local)
            _ = await model.files.activeTransferSnapshot()
            try await verifyCancelledPartial()
            try await transfer(upload: true, local: local, retry: true)
            sourceDigests = try local.verify(downloaded: false)
            try await verifyRemoteTree()
            try await verifyCancelFinalContents()
        } else {
        try await transfer(upload: true, local: local)
        if mode == .conflict { _ = await model.files.activeTransferSnapshot() } // Flush this new case's terminal result into its App-owned history review.
        let removal = model.files.prepareHistoryRemoval()
        guard let removal, removal.jobs.count == 1, removal.jobs[0].id == (mode == .conflict ? conflictJobs[0].id : jobs[0].id) else { throw AppNativeFiniteFailure.operation }
        guard await model.files.removeFinishedTransfers(removal).value, await manager.snapshot().jobs.isEmpty else { throw AppNativeFiniteFailure.operation }
        try await browse(root)
        guard model.files.entries.count == 1, let tree = model.files.entries.first, tree.name.bytes == Data(runtime.scope.tree.utf8), tree.attributes.kind == .directory else { throw AppNativeFiniteFailure.operation }
        if mode == .conflict {
            freshDigests = try local.verify(downloaded: true)
            try await transfer(upload: true, local: local, fresh: true)
            sourceDigests = try local.verify(downloaded: false); freshDigests = try local.verify(downloaded: true)
            try await verifyRemoteTree()
            try await verifyConflictRemoteContents()
        } else {
            try await transfer(upload: false, local: local)
            sourceDigests = try local.verify(downloaded: false); downloadDigests = try local.verify(downloaded: true)
            guard sourceDigests == remoteDigests, sourceDigests == downloadDigests, sourceDigests.count == 2 else { throw AppNativeFiniteFailure.operation }
            try await verifyRemoteTree()
        }
        }
        credentialCalls = await credentials.forbiddenCalls
        guard credentialCalls == 0 else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        final = await manager.snapshot()
        transferOnly = true
        try writeReport(leaf: mode == .cancelRetry ? "native-files-cancel-transfer.json" : (mode == .conflict ? "native-files-conflict-transfer.json" : "native-files-transfer.json"),
            checkpoint: "transfer-only-resources-unverified", failure: nil, storeRemoved: false, quit: .init())
    }

    private func transfer(upload: Bool, local: AppFilesManifestLocal, fresh: Bool = false, retry: Bool = false) async throws {
        try checkpoint(); try sameBinding()
        let before = runtime.facts.snapshot(), beforeManager = await manager.snapshot()
        guard before.liveHandles == 0, before.rescuedHandles == 0, before.handleCloseFailures == 0, !before.observationFailed else { throw AppNativeFiniteFailure.resources }
        guard beforeManager.jobs.count == (retry ? 1 : 0), beforeManager.serviceOperations.isEmpty, !beforeManager.planResources.hasPendingPlans else { throw AppNativeFiniteFailure.operation }
        if retry { guard beforeManager.jobs.first?.id == cancelJobs.first?.id, beforeManager.jobs.first?.state == .cancelled else { throw AppNativeFiniteFailure.operation } }
        let task: Task<[TransferJobID], Error>
        if retry { guard let previous = cancelJobs.first else { throw AppNativeFiniteFailure.operation }; task = try model.files.retryTransfer(previous.id) }
        else if upload { task = try model.files.enqueueUploads([fresh ? local.freshSource : local.source], context: model.files.transferContext(upload: true)) }
        else { task = try model.files.enqueueDownloads(model.files.entries, to: local.download, context: model.files.transferContext(upload: false)) }
        let preparationIDs = try await task.value
        guard preparationIDs.isEmpty, let review = model.files.transferPlanReview, model.files.transferPlanPhase == .ready,
              review.canConfirm, review.plan.requests.count == 1, let request = review.plan.requests.first,
              request.kind == .tree, let manifest = request.sourceManifest, review.plan.enumerationComplete,
              review.plan.issues.isEmpty, review.plan.itemCount == 4, review.plan.fileCount == 2, review.plan.directoryCount == 2,
              review.plan.rejectedCount == 0, review.plan.totalBytes == (mode == .cancelRetry ? 266240 : 12288), model.files.enqueueInFlight == 0 else { throw AppNativeFiniteFailure.operation }
        let remoteTree = try RemotePath(runtime.scope.root + "/" + runtime.scope.tree), localTree = try RemotePath.root.appending(FileName(runtime.scope.tree))
        guard request.source.path == (upload ? localTree : remoteTree), request.destination.path == (upload ? remoteTree : localTree),
              (upload ? request.destination.serviceID : request.source.serviceID) == context?.serviceID,
              request.hostID == context?.hostID.uuidString else { throw AppNativeFiniteFailure.operation }
        let expectedPaths = Set(try runtime.scope.relativeEntries.map { relative in
            let root = upload ? localTree : remoteTree
            return try relative.split(separator: "/").reduce(root) { try $0.appending(FileName(String($1))) }.bytes
        })
        guard Set(manifest.entries.map { $0.path.bytes }) == expectedPaths, manifest.entries.count == expectedPaths.count else { throw AppNativeFiniteFailure.operation }
        for entry in manifest.entries {
            let relative = String(decoding: entry.path.bytes.dropFirst(request.source.path.bytes.count).drop(while: { $0 == 47 }), as: UTF8.self)
            if let payload = runtime.scope.payloads(for: mode).first(where: { Data($0.relative.utf8) == Data(relative.utf8) }) {
                guard entry.attributes.kind == .regular, entry.attributes.size == UInt64(payload.bytes), entry.children == nil else { throw AppNativeFiniteFailure.operation }
            } else {
                let childNames = relative.isEmpty ? [Data(runtime.scope.child.utf8), Data(runtime.scope.payloads[0].relative.utf8)] : [Data("内容 空格.bin".utf8)]
                guard runtime.scope.relativeDirectories.contains(where: { Data($0.utf8) == Data(relative.utf8) }), entry.attributes.kind == .directory,
                      let children = entry.children, children.count == childNames.count, Set(children.map { $0.bytes }) == Set(childNames) else { throw AppNativeFiniteFailure.operation }
            }
        }
        let after = runtime.facts.snapshot(), afterManager = await manager.snapshot()
        let remoteDelta = try after.remote.delta(from: before.remote), localDelta = try after.local.delta(from: before.local)
        guard remoteDelta == .zero, localDelta == .zero, afterManager.jobs.count == (retry ? 1 : 0), afterManager.serviceOperations.isEmpty,
              afterManager.planResources.ready == 1, after.liveHandles == 0, after.rescuedHandles == 0, after.handleCloseFailures == 0,
              !after.observationFailed else { throw AppNativeFiniteFailure.operation }
        let phaseID = mode == .cancelRetry ? try runtime.facts.beginPhase(retry ? "retry" : "attempt") : (mode == .conflict ? try runtime.facts.beginPhase(fresh ? "fresh" : "seed") : nil)
        if mode == .cancelRetry, !retry, let phaseID {
            try runtime.facts.cancelGate.arm(phaseID: phaseID, path: Data(("/" + runtime.scope.tree + "/" + runtime.scope.payloads[1].relative).utf8), deadline: deadline)
        }
        // Exactly one call; no second confirm is used to obtain IDs or re-enumerate the source.
        guard let admission = model.files.confirmTransferPlan(review) else { throw AppNativeFiniteFailure.operation }
        plans.append(AppFilesManifestPlanEvidence(planID: review.plan.id, reviewID: review.id, serviceID: review.context.serviceID,
            hostID: review.context.hostID, lifetime: review.context.lifetime, revision: review.context.revision, direction: upload ? "upload" : "download",
            sourceBase64: request.source.path.bytes.base64EncodedString(), destinationBase64: request.destination.path.bytes.base64EncodedString(),
            itemCount: review.plan.itemCount, fileCount: review.plan.fileCount, directoryCount: review.plan.directoryCount, totalBytes: review.plan.totalBytes!,
            namesBase64: manifest.entries.map { $0.path.bytes.base64EncodedString() }, remoteDelta: remoteDelta, localDelta: localDelta,
            jobsBefore: beforeManager.jobs.count, jobsAfter: afterManager.jobs.count, confirmCalls: 1))
        let ids = try await admission.value
        guard ids.count == 1, let id = ids.first else { throw AppNativeFiniteFailure.operation }
        var generation: UUID?
        var phaseBound = false
        var answered: Set<UUID> = []
        var finished: TransferJobSnapshot?
        while finished == nil {
            try checkpoint()
            let snapshot = await manager.snapshot()
            guard snapshot.jobs.count == (retry ? 2 : 1), let job = snapshot.jobs.first(where: { $0.id == id }), job.request == request,
                  job.request.sourceManifest === manifest, generation == nil || generation == job.generation else { throw AppNativeFiniteFailure.operation }
            generation = job.generation
            if let phaseID, !phaseBound {
                if retry { guard job.retryOf == cancelJobs.first?.id, job.generation != cancelJobs.first?.generation,
                    job.request.batchID != cancelJobs.first?.batchID, job.request.sourceManifest?.planID != cancelJobs.first?.planID else { throw AppNativeFiniteFailure.operation } }
                try runtime.facts.bindPhase(phaseID, job: job); phaseBound = true
            }
            if mode == .cancelRetry, !retry, let phaseID, cancelPoint == nil, runtime.facts.cancelGate.snapshot().arrived {
                let first = try RemotePath(runtime.scope.root + "/" + runtime.scope.tree + "/" + runtime.scope.payloads[0].relative)
                let written = runtime.facts.writtenTemporaryBytes()
                guard job.state == .running, job.transferredBytes > 4096, job.transferredBytes < 266240,
                      runtime.facts.hasCommitted(first), written == 65536 else { throw AppNativeFiniteFailure.operation }
                try runtime.facts.captureCancelledTemporary(phaseID: phaseID)
                cancelPoint = .init(phaseID: phaseID, jobID: job.id, generation: job.generation, transferredBytes: job.transferredBytes, remoteWrittenBytes: written, firstCommitted: true)
                await model.files.cancelTransfer(job.id)
                continue
            }
            if let decision = job.pendingDecision {
                guard answered.insert(decision.id).inserted, answered.count <= 16, decision.jobID == id, decision.generation == job.generation else { throw AppNativeFiniteFailure.operation }
                if case .conflict(let conflict) = decision.question {
                    if mode == .cancelRetry {
                        guard retry, let context, conflict.source.bytes == Data(("/" + runtime.scope.tree + "/" + runtime.scope.payloads[0].relative).utf8),
                              conflict.destination.bytes == Data((runtime.scope.root + "/" + runtime.scope.tree + "/" + runtime.scope.payloads[0].relative).utf8), conflict.existing.kind == .regular,
                              conflict.existing.size == 4096, job.request.destination.serviceID == context.serviceID, !retrySkipAnswered else { throw AppNativeFiniteFailure.operation }
                        let first = try RemotePath(runtime.scope.root + "/" + runtime.scope.tree + "/" + runtime.scope.payloads[0].relative)
                        let binding = runtime.facts.snapshot().bindings.first
                        try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString, scheduling: .callerScheduled, token: operationToken) { service, token in
                            guard service.serverBinding == binding, try await service.lstat(first, token: token) == conflict.existing else { throw AppNativeFiniteFailure.operation }
                        }
                        let current = await manager.snapshot().jobs.first(where: { $0.id == job.id })
                        guard current?.generation == job.generation, current?.pendingDecision == decision,
                              await model.files.answerTransfer(decision, answer: .conflict(.skip, applyToBatch: false)) else { throw AppNativeFiniteFailure.operation }
                        retrySkipAnswered = true
                        continue
                    }
                    guard mode == .conflict, fresh, let phaseID else { throw AppNativeFiniteFailure.operation }
                    try await answerConflict(decision, conflict: conflict, job: job, phaseID: phaseID)
                    continue
                }
                guard case .risk(let risk) = decision.question else { throw AppNativeFiniteFailure.operation }
                let path: RemotePath
                switch risk {
                case .remotePathChecksAreNotAtomic(let value): path = value
                case .remoteFsyncUnavailable(let value):
                    guard upload, (runtime.scope.payloads.map { $0.relative } + (mode == .conflict ? [runtime.scope.conflictAlternate] : [])).contains(where: { Data((runtime.scope.root + "/" + runtime.scope.tree + "/" + $0).utf8) == value.bytes }) else { throw AppNativeFiniteFailure.operation }
                    path = value
                default: throw AppNativeFiniteFailure.operation
                }
                guard (mode == .conflict ? runtime.scope.allowsConflictRisk(path.bytes) : runtime.scope.exactTransferRisk(path.bytes)), runtime.facts.snapshot().bindings == before.bindings else { throw AppNativeFiniteFailure.operation }
                let currentJobs = await manager.snapshot().jobs
                guard AppFilesCurrentDecision.matches(currentJobs, jobID: job.id, generation: job.generation, decision: decision),
                      await model.files.answerTransfer(decision, answer: .risk(accepted: true)) else { throw AppNativeFiniteFailure.operation }
            }
            if !job.state.isActive { finished = job; break }
            try await Task.sleep(for: .milliseconds(10))
        }
        if mode == .cancelRetry {
            guard let job = finished, let phaseID else { throw AppNativeFiniteFailure.operation }
            try recordCancelJob(job, planID: review.plan.id, phaseID: phaseID, retry: retry, before: after)
            return
        }
        guard let job = finished, job.state == (fresh ? .completedWithSkips : .succeeded), job.transferredBytes == (fresh ? 4096 : 12288), job.retainedTemporaryPaths.isEmpty,
              job.error == nil, job.items.count == 4 else { throw AppNativeFiniteFailure.operation }
        var fileCount = 0, directoryCount = 0, skipped = 0
        var items: [AppFilesManifestItemEvidence] = []
        for item in job.items {
            if item.state == .skipped { skipped += 1; continue }
            guard case .succeeded(let bytes) = item.state else { throw AppNativeFiniteFailure.operation }
            if bytes == 0 { directoryCount += 1 } else { fileCount += 1 }
            items.append(.init(sourceBase64: item.source.bytes.base64EncodedString(), destinationBase64: item.destination.bytes.base64EncodedString(),
                bytes: bytes, acknowledgedRiskCount: item.acknowledgedRisks.count))
        }
        if mode == .conflict { try AppFilesConflictOutcome.validate(state: job.state, bytes: job.transferredBytes, files: fileCount, directories: directoryCount, skipped: skipped, fresh: fresh) }
        else { guard fileCount == 2, directoryCount == 2, skipped == 0 else { throw AppNativeFiniteFailure.operation } }
        if let phaseID {
            let streams = try verifyConflictStreams(phaseID: phaseID, fresh: fresh, local: local)
            try runtime.facts.finishPhase(phaseID)
            let end = runtime.facts.snapshot()
            conflictJobs.append(.init(phaseID: phaseID, id: job.id, generation: job.generation, planID: review.plan.id, batchID: request.batchID,
                state: job.state.rawValue, transferredBytes: job.transferredBytes,
                items: try job.items.map { item in
                    let state: String, bytes: UInt64
                    switch item.state { case .succeeded(let count): state = "succeeded"; bytes = count; case .skipped: state = "skipped"; bytes = 0; default: throw AppNativeFiniteFailure.operation }
                    return .init(source: item.source.bytes.base64EncodedString(), destination: item.destination.bytes.base64EncodedString(), state: state, bytes: bytes, risks: item.acknowledgedRisks.count)
                }, remoteDelta: try end.remote.delta(from: after.remote), localDelta: try end.local.delta(from: after.local), streams: streams))
            return
        }
        let streams = try verifyStreams(upload: upload)
        let end = runtime.facts.snapshot()
        let remoteIO = try end.remote.delta(from: after.remote), localIO = try end.local.delta(from: after.local)
        guard end.liveHandles == 0, !end.observationFailed,
              (upload ? remoteIO.writeBytes : remoteIO.readBytes) >= 12288,
              (upload ? localIO.readBytes : localIO.writeBytes) >= 12288 else { throw AppNativeFiniteFailure.operation }
        jobs.append(.init(id: job.id, generation: job.generation, planID: review.plan.id, batchID: request.batchID, transferredBytes: job.transferredBytes,
            succeededFiles: fileCount, succeededDirectories: directoryCount, items: items, remoteDelta: remoteIO, localDelta: localIO, streams: streams))
    }
    private var servicesDrained: Bool {
        let value = runtime.facts.snapshot()
        if mode != .cancelRetry { return value.drained }
        return value.remoteServices == 1 && value.localServices == 1 && value.closedRemote == 1 && value.closedLocal == 1 && value.liveHandles == 0 && value.rescuedHandles == 0 && value.handleCloseFailures == 0 && !value.observationFailed
    }
    private func recordCancelJob(_ job: TransferJobSnapshot, planID: UUID, phaseID: UUID, retry: Bool, before: AppFilesManifestServiceFacts) throws {
        guard job.retainedTemporaryPaths.isEmpty, job.items.count == 4 else { throw AppNativeFiniteFailure.operation }
        let scope = runtime.scope, second = scope.payloads[1].relative
        let gate = runtime.facts.cancelGate.snapshot()
        if retry {
            guard job.state == .completedWithSkips, job.transferredBytes == 262144, job.retryOf == cancelJobs.first?.id,
                  job.items.filter({ $0.state == .skipped }).count == 1, job.error == nil, retrySkipAnswered else { throw AppNativeFiniteFailure.operation }
        } else {
            guard job.state == .cancelled, job.cancellationRequested, job.error?.kind == .cancelled,
                  job.transferredBytes == cancelPoint?.transferredBytes, job.transferredBytes > 4096, job.transferredBytes < 266240,
                  gate.localCancellationObserved, !gate.waiting, !gate.aborted, gate.readCalls == 2, gate.forwardedReads == 1 else { throw AppNativeFiniteFailure.operation }
        }
        var items: [AppFilesCancelItem] = []
        for item in job.items {
            let state: String, bytes: UInt64, error: String?
            switch item.state {
            case .succeeded(let count): state = "succeeded"; bytes = count; error = nil
            case .skipped: state = "skipped"; bytes = 0; error = nil
            case .failed(let value): state = "failed"; bytes = 0; error = value.kind.rawValue
            }
            items.append(.init(source: item.source.bytes.base64EncodedString(), destination: item.destination.bytes.base64EncodedString(), state: state, bytes: bytes, error: error, risks: item.acknowledgedRisks.count, retained: item.retainedTemporary?.bytes.base64EncodedString()))
        }
        let records = runtime.facts.phaseStreams(phaseID)
        for record in records {
            let value = record.value
            guard let raw = Data(base64Encoded: value.pathBase64) else { throw AppNativeFiniteFailure.operation }
            if value.side == "remote", value.writing, raw.range(of: Data(".openlxssh-transfer.".utf8)) != nil {
                guard !retry, value.bytes == 65536, runtime.facts.allowedPartial(record) else { throw AppNativeFiniteFailure.operation }
                continue
            }
            let matches = scope.payloads(for: mode).filter { payload in
                let prefix = value.side == "source" ? "/" + scope.tree : scope.root + "/" + scope.tree
                return Data((prefix + "/" + payload.relative).utf8) == raw
            }
            guard matches.count == 1, let payload = matches.first else { throw AppNativeFiniteFailure.operation }
            let expectedCount = !retry && payload.relative == second ? 65536 : payload.bytes
            let expected = Data(AppFilesManifestLocal.payload(payload.relative, payload.bytes).prefix(expectedCount))
            guard value.bytes == expectedCount, value.sha256 == AppRealPrivateInput.sha(expected) else { throw AppNativeFiniteFailure.operation }
        }
        let firstPath = try RemotePath("/" + scope.tree + "/" + scope.payloads[0].relative)
        if retry { guard runtime.facts.phaseRecords(phaseID, side: "source", path: firstPath, writing: false).isEmpty else { throw AppNativeFiniteFailure.operation } }
        guard records.count >= (retry ? 2 : 4) else { throw AppNativeFiniteFailure.operation }
        try runtime.facts.finishPhase(phaseID)
        let end = runtime.facts.snapshot()
        guard end.liveHandles == 0, end.rescuedHandles == 0, end.handleCloseFailures == 0, !end.observationFailed else { throw AppNativeFiniteFailure.resources }
        cancelJobs.append(.init(phaseID: phaseID, id: job.id, generation: job.generation, planID: planID, batchID: job.request.batchID, retryOf: job.retryOf,
            state: job.state.rawValue, bytes: job.transferredBytes, error: job.error?.kind.rawValue, items: items,
            retained: job.retainedTemporaryPaths.map { $0.bytes.base64EncodedString() }, remoteDelta: try end.remote.delta(from: before.remote), localDelta: try end.local.delta(from: before.local), streams: records))
    }
    private func readCancelPayloads(_ payloads: [(relative: String, bytes: Int)]) async throws -> [AppFilesManifestDigest] {
        guard let context else { throw AppNativeFiniteFailure.operation }
        let scope = runtime.scope, binding = runtime.facts.snapshot().bindings.first
        return try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString, token: operationToken) { service, token in
            guard service.serverBinding == binding else { throw AppNativeFiniteFailure.operation }
            var values: [AppFilesManifestDigest] = []
            for payload in payloads {
                let path = try RemotePath(scope.root + "/" + scope.tree + "/" + payload.relative)
                let before = try await service.lstat(path, token: token)
                guard before.kind == .regular, before.size == UInt64(payload.bytes) else { throw AppNativeFiniteFailure.operation }
                let handle = try await service.open(path, mode: .read, token: token)
                var hash = SHA256(), count = 0
                do {
                    while true {
                        let bytes = try await service.read(handle, maxBytes: 65536, token: token)
                        guard bytes.count <= 65536, count <= payload.bytes - bytes.count else { throw AppNativeFiniteFailure.operation }
                        if bytes.isEmpty { break }; hash.update(data: bytes); count += bytes.count
                    }
                    try await service.closeHandle(handle)
                } catch { try? await service.closeHandle(handle); throw error }
                let digest = hash.finalize().map { String(format: "%02x", $0) }.joined()
                guard count == payload.bytes, try await service.lstat(path, token: token) == before,
                      digest == AppRealPrivateInput.sha(AppFilesManifestLocal.payload(payload.relative, payload.bytes)) else { throw AppNativeFiniteFailure.operation }
                values.append(.init(relativePathBase64: Data(payload.relative.utf8).base64EncodedString(), bytes: count, sha256: digest))
            }
            return values
        }
    }
    private func verifyCancelledPartial() async throws {
        let first = runtime.scope.payloads(for: mode)[0]
        let values = try await readCancelPayloads([first]); guard values.count == 1, let context else { throw AppNativeFiniteFailure.operation }
        partialVerified = values[0]
        let second = try RemotePath(runtime.scope.root + "/" + runtime.scope.tree + "/" + runtime.scope.payloads[1].relative)
        try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString, token: operationToken) { service, token in
            do { _ = try await service.lstat(second, token: token); throw AppNativeFiniteFailure.operation }
            catch let value as FileServiceError where value.kind == .notFound { }
            guard try await service.list(second.parent, token: token).isEmpty else { throw AppNativeFiniteFailure.operation }
        }
        secondAbsentAfterCancel = true
    }
    private func verifyCancelFinalContents() async throws {
        let phase = try runtime.facts.beginPhase("verify"); verificationPhaseID = phase
        verifiedRemote = try await readCancelPayloads(runtime.scope.payloads(for: mode))
        verificationStreams = runtime.facts.phaseStreams(phase)
        guard verificationStreams.count == 2, verifiedRemote == sourceDigests else { throw AppNativeFiniteFailure.operation }
        try runtime.facts.finishPhase(phase)
    }
    private func answerConflict(_ decision: TransferDecisionRequest, conflict: TransferConflict, job: TransferJobSnapshot, phaseID: UUID) async throws {
        let scope = runtime.scope
        guard let context, job.request.hostID == context.hostID.uuidString, job.request.destination.serviceID == context.serviceID,
              conflict.existing.kind == .regular, conflictDecisions.count < 2 else { throw AppNativeFiniteFailure.operation }
        let index = conflictDecisions.count
        let relative = scope.payloads[index].relative
        guard conflict.source.bytes == Data(("/" + scope.tree + "/" + relative).utf8),
              conflict.destination.bytes == Data((scope.root + "/" + scope.tree + "/" + relative).utf8),
              conflict.existing.size == UInt64(scope.payloads[index].bytes) else { throw AppNativeFiniteFailure.operation }
        let binding = runtime.facts.snapshot().bindings.first
        let alternate = try RemotePath(scope.root + "/" + scope.tree + "/" + scope.conflictAlternate)
        // The job owns the scheduler host gate while its decision waits. Metadata lifetime
        // is leased, but must not reacquire that gate and deadlock the current decision.
        try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString, scheduling: .callerScheduled, token: operationToken) { service, token in
            guard service.serverBinding == binding, try await service.lstat(conflict.destination, token: token) == conflict.existing else { throw AppNativeFiniteFailure.operation }
            if index == 0 {
                do { _ = try await service.lstat(alternate, token: token); throw AppNativeFiniteFailure.operation }
                catch let failure as FileServiceError where failure.kind == .notFound { }
            }
        }
        let current = await manager.snapshot().jobs.first
        guard current?.id == job.id, current?.generation == job.generation, current?.pendingDecision == decision,
              runtime.facts.snapshot().bindings == [binding].compactMap({ $0 }) else { throw AppNativeFiniteFailure.operation }
        let answer: TransferDecisionAnswer = index == 0 ? .conflict(.renameTo(try FileName(scope.conflictAlternate)), applyToBatch: false) : .conflict(.skip, applyToBatch: true)
        guard await model.files.answerTransfer(decision, answer: answer) else { throw AppNativeFiniteFailure.operation }
        conflictDecisions.append(.init(id: decision.id, jobID: job.id, generation: job.generation, batchID: job.request.batchID, phaseID: phaseID,
            source: conflict.source.bytes.base64EncodedString(), destination: conflict.destination.bytes.base64EncodedString(),
            strategy: index == 0 ? "rename" : "skip", applyToBatch: index != 0))
    }
    private func verifyConflictStreams(phaseID: UUID, fresh: Bool, local: AppFilesManifestLocal) throws -> [AppFilesConflictStream] {
        var result: [AppFilesConflictStream] = []
        let expected = local.expected(fresh: fresh)
        for (index, digest) in expected.enumerated() {
            let relative = runtime.scope.payloads[index].relative
            let source = try RemotePath("/" + runtime.scope.tree + "/" + relative)
            if fresh && index == 1 {
                guard runtime.facts.phaseRecords(phaseID, side: "fresh", path: source, writing: false).isEmpty else { throw AppNativeFiniteFailure.operation }
                continue
            }
            let destinationRelative = fresh ? runtime.scope.conflictAlternate : relative
            let destination = try RemotePath(runtime.scope.root + "/" + runtime.scope.tree + "/" + destinationRelative)
            for (side, path, writing) in [(fresh ? "fresh" : "source", source, false), ("remote", destination, true)] {
                let values = runtime.facts.phaseRecords(phaseID, side: side, path: path, writing: writing)
                guard !values.isEmpty, values.allSatisfy({ $0.phaseID == phaseID && $0.value.bytes == digest.bytes && $0.value.sha256 == digest.sha256 }) else { throw AppNativeFiniteFailure.operation }
                result += values
            }
        }
        return result
    }
    private func verifyConflictRemoteContents() async throws {
        guard let context, conflictJobs.count == 2, conflictDecisions.count == 2 else { throw AppNativeFiniteFailure.operation }
        let phase = try runtime.facts.beginPhase("verify"); verificationPhaseID = phase
        let scope = runtime.scope, binding = runtime.facts.snapshot().bindings.first
        verifiedRemote = try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString, token: operationToken) { service, token in
            guard service.serverBinding == binding else { throw AppNativeFiniteFailure.operation }
            var values: [AppFilesManifestDigest] = []
            for payload in scope.conflictFinalPayloads() {
                let path = try RemotePath(scope.root + "/" + scope.tree + "/" + payload.relative)
                let before = try await service.lstat(path, token: token)
                guard before.kind == .regular, before.size == UInt64(payload.bytes) else { throw AppNativeFiniteFailure.operation }
                let handle = try await service.open(path, mode: .read, token: token)
                var bytes = Data()
                do {
                    while true {
                        let chunk = try await service.read(handle, maxBytes: 4096, token: token)
                        guard chunk.count <= 4096, bytes.count <= payload.bytes - chunk.count else { throw AppNativeFiniteFailure.operation }
                        if chunk.isEmpty { break }; bytes.append(chunk)
                    }
                    try await service.closeHandle(handle)
                } catch { try? await service.closeHandle(handle); throw error }
                let sourceName = payload.fresh ? scope.payloads[0].relative : payload.relative
                guard try await service.lstat(path, token: token) == before,
                      bytes == AppFilesManifestLocal.payload(sourceName, payload.bytes, fresh: payload.fresh) else { throw AppNativeFiniteFailure.operation }
                values.append(.init(relativePathBase64: Data(payload.relative.utf8).base64EncodedString(), bytes: bytes.count, sha256: AppRealPrivateInput.sha(bytes)))
            }
            return values
        }
        for payload in scope.conflictFinalPayloads() {
            let path = try RemotePath(scope.root + "/" + scope.tree + "/" + payload.relative)
            let records = runtime.facts.phaseRecords(phase, side: "remote", path: path, writing: false)
            guard records.count == 1, records[0].value.bytes == payload.bytes,
                  verifiedRemote.contains(where: { $0.relativePathBase64 == Data(payload.relative.utf8).base64EncodedString() && $0.sha256 == records[0].value.sha256 }) else { throw AppNativeFiniteFailure.operation }
            verificationStreams += records
        }
        try runtime.facts.finishPhase(phase)
    }
    private func verifyStreams(upload: Bool) throws -> [AppFilesManifestStream] {
        guard let local else { throw AppNativeFiniteFailure.operation }
        var streams: [AppFilesManifestStream] = [], remote: [AppFilesManifestDigest] = []
        for expected in local.expected() {
            guard let bytes = Data(base64Encoded: expected.relativePathBase64), let relative = String(data: bytes, encoding: .utf8) else { throw AppNativeFiniteFailure.operation }
            let remotePath = try RemotePath(runtime.scope.root + "/" + runtime.scope.tree + "/" + relative)
            let localPath = try RemotePath("/" + runtime.scope.tree + "/" + relative)
            let pairs: [(String, RemotePath, Bool)] = upload ? [("source", localPath, false), ("remote", remotePath, true)] : [("remote", remotePath, false), ("download", localPath, true)]
            for (side, path, writing) in pairs {
                let records = runtime.facts.observed(side: side, path: path, writing: writing)
                guard !records.isEmpty, records.allSatisfy({ $0.bytes == expected.bytes && $0.sha256 == expected.sha256 }) else { throw AppNativeFiniteFailure.operation }
                streams += records
            }
            guard let actual = runtime.facts.observed(side: "remote", path: remotePath, writing: upload).first else { throw AppNativeFiniteFailure.operation }
            remote.append(.init(relativePathBase64: expected.relativePathBase64, bytes: actual.bytes, sha256: actual.sha256))
        }
        if upload { remoteDigests = remote } else { guard remoteDigests == remote else { throw AppNativeFiniteFailure.operation } }
        return streams
    }
    private func verifyRemoteTree() async throws {
        guard let context else { throw AppNativeFiniteFailure.operation }
        let scope = runtime.scope, mode = mode
        try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString, token: operationToken) { service, token in
            let root = try RemotePath(scope.root), tree = try RemotePath(scope.root + "/" + scope.tree)
            guard try await service.list(root, token: token).map({ $0.name.bytes }) == [Data(scope.tree.utf8)] else { throw AppNativeFiniteFailure.cleanup }
            for relative in scope.relativeDirectories {
                let path = try RemotePath(scope.root + "/" + scope.tree + (relative.isEmpty ? "" : "/" + relative))
                guard try await service.lstat(path, token: token).kind == .directory else { throw AppNativeFiniteFailure.cleanup }
                let expected = relative.isEmpty ? Set(([scope.child, scope.payloads[0].relative] + (mode == .conflict ? [scope.conflictAlternate] : [])).map { Data($0.utf8) }) : Set([Data("内容 空格.bin".utf8)])
                let rows = try await service.list(path, token: token)
                guard rows.count == expected.count, Set(rows.map { $0.name.bytes }) == expected else { throw AppNativeFiniteFailure.cleanup }
            }
            let payloads = mode == .conflict ? scope.conflictFinalPayloads().map { ($0.relative, $0.bytes) } : scope.payloads(for: mode).map { ($0.relative, $0.bytes) }
            for (relative, size) in payloads {
                let path = try relative.split(separator: "/").reduce(tree) { try $0.appending(FileName(String($1))) }
                let attr = try await service.lstat(path, token: token)
                guard attr.kind == .regular, attr.size == UInt64(size) else { throw AppNativeFiniteFailure.cleanup }
            }
        }
    }
    private func deleteReviewed(_ entries: [DirectoryEntry], rootOnly: Bool) async throws {
        try checkpoint(); try sameBinding()
        guard let context, let target = model.files.captureTarget(entries) else { throw AppNativeFiniteFailure.cleanup }
        let parent = try RemotePath(rootOnly ? runtime.scope.home : runtime.scope.root)
        guard target.parent == parent else { throw AppNativeFiniteFailure.cleanup }
        model.files.prepareDeleteBatch(target, removeLinkOnly: false); try await settled()
        guard let batch = model.files.deleteBatchReview, batch.serviceID == context.serviceID,
              batch.review.target.id == target.id, batch.review.parent == parent, batch.review.canExecute,
              batch.review.items.count == 1, let item = batch.review.items.first else { throw AppNativeFiniteFailure.cleanup }
        let scope = runtime.scope
        let expected: [Data: DeleteItem.Action]
        if rootOnly { expected = [Data(scope.root.utf8): .removeEmptyDirectory] }
        else {
            let tree = scope.root + "/" + scope.tree
            var values: [Data: DeleteItem.Action] = [:]
            for relative in scope.relativeDirectories { values[Data((tree + (relative.isEmpty ? "" : "/" + relative)).utf8)] = .removeEmptyDirectory }
            for relative in scope.payloads.map({ $0.relative }) + (mode == .conflict ? [scope.conflictAlternate] : []) { values[Data((tree + "/" + relative).utf8)] = .removeFile }
            expected = values
        }
        guard item.plan.root.bytes == Data((rootOnly ? scope.root : scope.root + "/" + scope.tree).utf8),
              item.plan.canExecute, item.plan.linkPolicy == .reject, item.plan.issues.isEmpty, item.plan.items.count == expected.count,
              Set(item.plan.items.map { $0.path.bytes }).count == expected.count,
              item.plan.items.allSatisfy({ expected[$0.path.bytes] == $0.action && scope.contains($0.path.bytes) }),
              item.plan.risks == [.deletionChecksAreNotCompareAndSwap(path: item.plan.root), .remotePathChecksAreNotAtomic(path: item.plan.root)] else { throw AppNativeFiniteFailure.cleanup }
        for leaf in item.plan.items where leaf.action == .removeFile {
            let payloads = mode == .conflict ? scope.conflictFinalPayloads() : scope.payloads(for: mode).map { ($0.relative, $0.bytes, false) }
            guard let digest = leaf.contentSHA256, let match = payloads.first(where: { Data((scope.root + "/" + scope.tree + "/" + $0.0).utf8) == leaf.path.bytes }),
                  digest == Data(SHA256.hash(data: AppFilesManifestLocal.payload(match.2 ? scope.payloads[0].relative : match.0, match.1, fresh: match.2))), leaf.attributes.size == UInt64(match.1) else { throw AppNativeFiniteFailure.cleanup }
        }
        // Recheck the exact current target before destructive dispatch, including the final empty root.
        let plan = item.plan
        let binding = runtime.facts.snapshot().bindings.first
        try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString, token: operationToken) { service, token in
            guard service.serverBinding == binding,
                  try await service.lstat(target.parent, token: token) == target.parentAttributes else { throw AppNativeFiniteFailure.cleanup }
            for entry in target.entries {
                guard let path = target.path(for: entry), try await service.lstat(path, token: token) == entry.attributes else { throw AppNativeFiniteFailure.cleanup }
            }
            if rootOnly { guard plan.items.count == 1, try await service.list(plan.root, token: token).isEmpty else { throw AppNativeFiniteFailure.cleanup } }
        }
        deleteIDs.append(plan.id)
        model.files.executeDeleteBatch(batch); try await settled()
        guard let report = model.files.lastDeleteReports.first, model.files.lastDeleteReports.count == 1, report.planID == plan.id,
              report.allSucceeded, Set(report.items.map { $0.path.bytes }) == Set(expected.keys) else { throw AppNativeFiniteFailure.cleanup }
    }
    func prepareQuit() async throws {
        // Failure/partial never adopts a discovered tree for cleanup. Close only; leave nonce evidence.
        do {
            guard transferOnly else { throw AppNativeFiniteFailure.cleanup }
            try await verifyRemoteTree()
            try await browse(RemotePath(runtime.scope.root))
            guard model.files.entries.count == 1 else { throw AppNativeFiniteFailure.cleanup }
            try await deleteReviewed(model.files.entries, rootOnly: false)
            guard model.files.entries.isEmpty else { throw AppNativeFiniteFailure.cleanup }
            try await browse(RemotePath(runtime.scope.home))
            let rootEntries = model.files.entries.filter { $0.name.bytes == Data(runtime.scope.basename.utf8) }
            guard rootEntries.count == 1, rootEntries[0].attributes.kind == .directory else { throw AppNativeFiniteFailure.cleanup }
            try await deleteReviewed(rootEntries, rootOnly: true)
            guard !model.files.entries.contains(where: { $0.name.bytes == Data(runtime.scope.basename.utf8) }), let context else { throw AppNativeFiniteFailure.cleanup }
            let root = try RemotePath(runtime.scope.root)
            try await manager.withServiceOperation(serviceID: context.serviceID, hostID: context.hostID.uuidString, token: operationToken) { service, token in
                do { _ = try await service.lstat(root, token: token); throw AppNativeFiniteFailure.cleanup }
                catch let error as FileServiceError where error.kind == .notFound { }
            }
            remoteRemoved = true
        } catch {
            await closeServices(); throw error
        }
        await closeServices()
        guard final.isClosed, !final.hasActiveWork, final.serviceOperations.isEmpty, servicesDrained else { throw AppNativeFiniteFailure.drainIncomplete }
        guard let local else { throw AppNativeFiniteFailure.cleanup }
        try local.cleanup(); self.local = nil; localRemoved = true
        try sourceKey?.check(); try known?.check()
        if let known, let knownBytes { knownUnchanged = try known.read(limit: 4096) == knownBytes }
        guard sourceUnchanged, knownUnchanged else { throw AppNativeFiniteFailure.sourceChanged }
        credentialCalls = await credentials.forbiddenCalls
        guard credentialCalls == 0 else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        if let hostID { try await model.repository.apply([.deleteHost(hostID)]); self.hostID = nil }
        if let keyID { try await model.security.deleteKey(keyID); self.keyID = nil }
        repeat {
            try checkpoint()
            let after = try descriptors()
            if descriptorSnapshots.cleanupFirst == nil { descriptorSnapshots.cleanupFirst = after }; descriptorSnapshots.cleanupLatest = after
            // Unknown/unavailable/truncated ownership is failure, not a count-only exemption.
            if let baseline, baseline.complete, after.complete, baseline.count == after.count, baseline.entries == after.entries { fdMatched = true; break }
            try await Task.sleep(for: .milliseconds(20))
        } while true
        closedAndClean = remoteRemoved && localRemoved && fdMatched && servicesDrained
        guard closedAndClean else { throw AppNativeFiniteFailure.resources }
    }
    private func closeServices() async {
        runtime.facts.cancelGate.abortIfWaiting()
        model.files.freezeTransferAdmission(); model.files.cancelTransferPlan(); await model.files.waitUntilTransferPlanDrained()
        await model.files.closeForWindow() // Actual manager drain and ALL local/remote close awaits.
        final = await manager.snapshot()
    }
    func beforeStoresClose(_ snapshot: TransferManagerSnapshot) async throws {
        guard closedAndClean, snapshot.isClosed, !snapshot.hasActiveWork, final.isClosed, !final.hasActiveWork,
              snapshot.serviceOperations.isEmpty, servicesDrained else { throw AppNativeFiniteFailure.beforeStoresClose }
    }
    func writeReport(leaf: String, checkpoint: String, failure: AppNativeFiniteFailure?, storeRemoved: Bool, quit: AppNativeFiniteQuitAudit) throws {
        if mode == .roundtrip { try input.write(report(checkpoint: checkpoint, failure: failure, storeRemoved: storeRemoved, quit: quit), leaf: leaf); return }
        if mode == .cancelRetry {
            try input.write(AppFilesCancelReport(runID: input.source.runID, pid: getpid(), checkpoint: checkpoint, elapsedSeconds: budget.elapsed(),
                passed: failure == nil && closedAndClean, failureCode: failure, transferOnly: transferOnly, closedAndClean: closedAndClean, localStoreRemoved: storeRemoved,
                nonce: runtime.scope.nonce, sourceKeyUnchanged: sourceUnchanged, fixtureKnownHostsUnchanged: knownUnchanged, trustMatchedOutOfBand: trustMatched, credentialCalls: credentialCalls,
                capability: capability, plans: plans.map(AppFilesConflictPlan.init), jobs: cancelJobs, gate: runtime.facts.cancelGate.snapshot(), cancelPoint: cancelPoint,
                partialVerified: partialVerified, secondAbsentAfterCancel: secondAbsentAfterCancel, source: sourceDigests, remoteVerified: verifiedRemote,
                verificationPhaseID: verificationPhaseID, verificationStreams: verificationStreams, services: runtime.facts.snapshot(), managerClosed: final.isClosed,
                managerDrained: !final.hasActiveWork, managerJobs: final.jobs.count, managerOperations: final.serviceOperations.count,
                remoteRootRemoved: remoteRemoved, localPayloadRemoved: localRemoved, deletePlanIDs: deleteIDs, descriptors: .init(descriptorSnapshots), descriptorIdentityMatched: fdMatched, quit: quit), leaf: leaf)
            return
        }
        try input.write(AppFilesConflictReport(runID: input.source.runID, pid: getpid(), checkpoint: checkpoint, elapsedSeconds: budget.elapsed(),
            passed: failure == nil && closedAndClean, failureCode: failure, transferOnly: transferOnly, closedAndClean: closedAndClean, localStoreRemoved: storeRemoved,
            nonce: runtime.scope.nonce, sourceKeyUnchanged: sourceUnchanged, fixtureKnownHostsUnchanged: knownUnchanged, trustMatchedOutOfBand: trustMatched, credentialCalls: credentialCalls,
            capability: capability, plans: plans.map(AppFilesConflictPlan.init), jobs: conflictJobs, decisions: conflictDecisions, seed: sourceDigests, fresh: freshDigests,
            remoteVerified: verifiedRemote, verificationPhaseID: verificationPhaseID, verificationStreams: verificationStreams, services: runtime.facts.snapshot(), managerClosed: final.isClosed,
            managerDrained: !final.hasActiveWork, managerJobs: final.jobs.count, managerOperations: final.serviceOperations.count,
            remoteRootRemoved: remoteRemoved, localPayloadRemoved: localRemoved, deletePlanIDs: deleteIDs,
            descriptors: .init(descriptorSnapshots), descriptorIdentityMatched: fdMatched, quit: quit), leaf: leaf)
    }
    func report(checkpoint: String, failure: AppNativeFiniteFailure?, storeRemoved: Bool, quit: AppNativeFiniteQuitAudit) -> AppFilesManifestReport {
        .init(runID: input.source.runID, pid: getpid(), checkpoint: checkpoint, elapsedSeconds: budget.elapsed(),
            passed: failure == nil && closedAndClean, failureCode: failure, transferOnly: transferOnly, closedAndClean: closedAndClean, localStoreRemoved: storeRemoved,
            nonce: runtime.scope.nonce, sourceKeyUnchanged: sourceUnchanged, fixtureKnownHostsUnchanged: knownUnchanged, trustMatchedOutOfBand: trustMatched,
            credentialCalls: credentialCalls, capabilityPassed: capabilityPassed, serverBinding: runtime.facts.snapshot().bindings.first,
            capability: capability, plans: plans, jobs: jobs, source: sourceDigests, remote: remoteDigests, download: downloadDigests, services: runtime.facts.snapshot(),
            managerClosed: final.isClosed, managerDrained: !final.hasActiveWork, managerJobs: final.jobs.count, managerOperations: final.serviceOperations.count,
            managerPreparing: final.planResources.preparing, managerReady: final.planResources.ready, managerConfirming: final.planResources.confirming,
            managerReservedEntries: final.planResources.reservedEntries, managerReservedMetadataBytes: final.planResources.reservedMetadataBytes,
            remoteRootRemoved: remoteRemoved, localPayloadRemoved: localRemoved, deletePlanIDs: deleteIDs,
            descriptors: .init(descriptorSnapshots), descriptorIdentityMatched: fdMatched, quit: quit)
    }
}
#endif

#if HOST_PROBE
// Independent M3 implementation. No old exercise, fact owner or report type is repurposed.
fileprivate struct AppTrustPublicMaterial: Equatable {
    let material: AppTrustMaterial
    let hostKeyLine: String, clientPublicKeyLine: String
    static func load(_ wrapper: AppTrustContract, buildEpoch: Double) throws -> Self {
        let held = try AppNativeFiniteStableFile(wrapper.materialContractPath)
        let material = try AppTrustMaterial.decodeStrict(held.read(limit: 8192)), value = material.binding
        try material.validate(path: wrapper.materialContractPath, now: Date().timeIntervalSince1970, buildEpoch: buildEpoch)
        guard value.runID == wrapper.runID else { throw AppNativeFiniteFailure.contract }
        for path in [AppNativeFiniteContract.inputRoot, URL(fileURLWithPath: wrapper.materialContractPath).deletingLastPathComponent().path,
                     AppRealIntegrationContract.fixtureRoot + "/.runtime", AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly", value.generation] {
            let fd = try AppRealPrivateInput.directory(path); Darwin.close(fd)
        }
        let state = try AppNativeFiniteStableFile(AppRealIntegrationContract.fixtureRoot + "/.runtime/state.json")
        try value.validateState(state.read(limit: 4096))
        let provenance = try AppNativeFiniteStableFile(value.generation + "/provenance.json"), provenanceBytes = try provenance.read(limit: 4096)
        guard AppRealPrivateInput.sha(provenanceBytes) == value.provenanceSHA256 else { throw AppNativeFiniteFailure.contract }
        try value.validateProvenance(provenanceBytes)
        let known = try AppNativeFiniteStableFile(value.generation + "/known_hosts"), bytes = try known.read(limit: 4096)
        guard AppRealPrivateInput.sha(bytes) == value.knownHostsSHA256, let text = String(data: bytes, encoding: .utf8),
              text.hasSuffix("\n"), !text.dropLast().contains("\n") else { throw AppNativeFiniteFailure.trustMismatch }
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == "[127.0.0.1]:22221", fields[1] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51, blob.base64EncodedString() == fields[2],
              "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "") == value.expectedFingerprint else { throw AppNativeFiniteFailure.trustMismatch }
        let exported = try AppNativeFiniteStableFile(value.generation + "/id_ed25519.pub"), publicBytes = try exported.read(limit: 4096)
        guard AppRealPrivateInput.sha(publicBytes) == value.generationPublicKeySHA256, let publicText = String(data: publicBytes, encoding: .utf8) else { throw AppNativeFiniteFailure.contract }
        let publicFields = publicText.trimmingCharacters(in: .newlines).split(separator: " ")
        guard publicFields.count >= 2, publicFields[0] == "ssh-ed25519" else { throw AppNativeFiniteFailure.contract }
        try held.check(); try state.check(); try provenance.check(); try known.check(); try exported.check()
        return Self(material: material, hostKeyLine: fields[1...2].joined(separator: " "), clientPublicKeyLine: publicFields.prefix(2).joined(separator: " "))
    }
}

/// Fixed App-owned public path only. No creation, fallback, system known_hosts or private digest.
@MainActor fileprivate final class AppTrustStoreAudit {
    private let root: String, held: Int32, original: stat
    var path: String { root + "/Trust/known_hosts" }
    init(store: AppRealOwnedStore) throws {
        root = store.url.path; held = try AppRealPrivateInput.directory(root)
        var info = stat()
        guard fstat(held, &info) == 0 else { Darwin.close(held); throw AppNativeFiniteFailure.unsafeInput }
        original = info
    }
    deinit { Darwin.close(held) }
    private func checkRoot() throws {
        try AppFileSecurity.directory(held)
        let named = try AppRealPrivateInput.directory(root); defer { Darwin.close(named) }
        var a = stat(), b = stat()
        guard fstat(held, &a) == 0, fstat(named, &b) == 0,
              a.st_dev == original.st_dev, a.st_ino == original.st_ino, b.st_dev == a.st_dev, b.st_ino == a.st_ino else { throw AppNativeFiniteFailure.unsafeInput }
    }
    func publicBytes() throws -> AppTrustPublicBytes {
        try checkRoot()
        var info = stat()
        if fstatat(held, "Trust", &info, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw AppNativeFiniteFailure.unsafeInput }; return .missing
        }
        let trust = openat(held, "Trust", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard trust >= 0 else { throw AppNativeFiniteFailure.unsafeInput }; defer { Darwin.close(trust) }
        try AppFileSecurity.directory(trust)
        var opened = stat(), named = stat()
        guard fstat(trust, &opened) == 0, opened.st_dev == info.st_dev, opened.st_ino == info.st_ino else { throw AppNativeFiniteFailure.unsafeInput }
        if fstatat(trust, "known_hosts", &info, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw AppNativeFiniteFailure.unsafeInput }; return .missing
        }
        let file = try AppNativeFiniteStableFile(path), bytes = try file.read(limit: 16384)
        try file.check(); try AppFileSecurity.directory(trust); try checkRoot()
        guard fstatat(held, "Trust", &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == opened.st_dev, named.st_ino == opened.st_ino else { throw AppNativeFiniteFailure.unsafeInput }
        let result = AppTrustPublicBytes(presence: "present", bytes: bytes.count, sha256: AppRealPrivateInput.sha(bytes))
        try result.validate(); return result
    }
    func point(_ label: String, store: HostTrustStore, expectedFingerprint: String? = nil) async throws -> AppTrustStorePoint {
        guard store.knownHostsPath.value == path else { throw AppNativeFiniteFailure.trustMismatch }
        let records = try await store.records(), bytes = try publicBytes()
        if let expectedFingerprint {
            guard records.count == 1, records.allSatisfy({ $0.host.address.value == "127.0.0.1" && $0.host.port.value == 22221 &&
                $0.key.algorithm == "ssh-ed25519" && $0.key.fingerprint == expectedFingerprint }) else { throw AppNativeFiniteFailure.trustMismatch }
        } else { guard records.isEmpty else { throw AppNativeFiniteFailure.trustMismatch } }
        guard bytes.presence == "present" else { throw AppNativeFiniteFailure.trustMismatch }
        return .init(label: label, records: records.count, publicBytes: bytes)
    }
}

/// Synchronous callback observation: record before forwarding the original exact callback.
/// The observation has no UI, provider, secret, reply, receive or native write capability.
fileprivate final class AppTrustObservation: @unchecked Sendable {
    private let lock = NSLock()
    private var value: AppTrustAttemptFacts
    private var canonical: (any SessionDrainObserving)?
    init(id: UUID, ordinal: Int) { value = .init(attemptID: id, ordinal: ordinal) }
    private func held<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }
    var snapshot: AppTrustAttemptFacts { held { value } }
    var drained: Bool { held { canonical?.snapshot.drained == true } }
    func connection() throws { try held { guard value.connectionCalls == 0 else { throw AppNativeFiniteFailure.unexpectedSession }; value.connectionCalls += 1 } }
    func primary(_ request: NativeSessionPrimaryRequest) { held { value.primary(sessionID: request.sessionID, requestID: request.requestID) } }
    func beforeAcceptance(promptID: UUID) throws { try held { try value.capturePreAcceptance(promptID: promptID) } }
    func keyboard() { held { value.keyboardCalls += 1; value.request(stage: "keyboard", id: nil) } }
    func trust(_ event: FileHostTrustEvent) {
        held {
            switch event {
            case .pending(let decision):
                value.pendingCalls += 1; value.request(stage: "pending", id: decision.id)
                if value.pendingRequestID != nil { value.observationFailed = true }
                value.pendingRequestID = decision.id
                if decision.host.address.value != "127.0.0.1" || decision.host.port.value != 22221 || decision.algorithm != "ssh-ed25519" || decision.fingerprint != AppNativeFiniteIdentity.fingerprint { value.observationFailed = true }
            case .changed(let changed): value.changedCallbacks += 1; value.request(stage: "changed", id: nil); value.recordCallbackChange(Self.changedFact(changed))
            }
        }
    }
    private static func changedFact(_ changed: ChangedHostKey) -> AppTrustChangedFact {
        AppTrustChangedFact(expectedFingerprint: changed.expectedFingerprint, presentedFingerprint: changed.presentedFingerprint,
            exactEndpoint: changed.host.address.value == "127.0.0.1" && changed.host.port.value == 22221, exactAlgorithm: changed.algorithm == "ssh-ed25519")
    }
    private static func stages(_ values: [NativeShellAuthenticationStage]) -> [String] {
        values.map {
            switch $0 {
            case .advertised: "advertised"
            case .primaryStarted(let method): "primaryStarted." + method.rawValue
            case .primaryResult(let method, _, _): "primaryResult." + method.rawValue
            case .keyboardStarted: "keyboardStarted"
            case .keyboardResult: "keyboardResult"
            case .authenticated: "authenticated"
            case .shellReady: "shellReady"
            }
        }
    }
    func connected(stages: [NativeShellAuthenticationStage], drain: NativeShellDrainHandle) throws {
        held { value.shellSessions += 1; value.stages = Self.stages(stages); canonical = CanonicalSessionDrain(handle: drain) }
        let auth = try AppNativeFiniteAuthFacts(keyonly: AppNativeFiniteAuthentication(stages))
        held { value.authentication = auth }
    }
    func failed(_ error: any Error) {
        held {
            let wrapper = error as? NativeSessionConnectionFailure, typed = (wrapper?.failure ?? error) as? NativeShellError
            if let typed {
                value.errorKind = typed.kind.rawValue
                value.errorOperation = ["host-key", "host-key-changed", "handshake", "connect", "auth-methods", "primary-authentication"].contains(typed.operation) ? typed.operation : "other"
                value.stages = Self.stages(typed.authenticationStages)
                if let changed = typed.changedHostKey { value.recordTypedChange(Self.changedFact(changed)) }
                if let drain = typed.interactionDrain { canonical = CanonicalSessionDrain(handle: drain) }
            } else { value.errorKind = "other"; value.errorOperation = "other" }
            if let drain = wrapper?.drain { canonical = drain }
        }
    }
}
fileprivate actor AppTrustFacts {
    nonisolated let scenario: AppTrustScenario
    private var observations: [AppTrustObservation] = []
    private var pending: AppTrustObservation?
    init(scenario: AppTrustScenario) { self.scenario = scenario }
    func arm(id: UUID, ordinal: Int) throws -> AppTrustObservation {
        guard pending == nil, observations.count == ordinal - 1, ordinal <= scenario.attempts else { throw AppNativeFiniteFailure.unexpectedSession }
        let observation = AppTrustObservation(id: id, ordinal: ordinal); observations.append(observation); pending = observation; return observation
    }
    func claim() throws -> AppTrustObservation {
        guard let observation = pending else { throw AppNativeFiniteFailure.unexpectedSession }
        pending = nil; try observation.connection(); return observation
    }
}
fileprivate struct AppTrustConnector: NativeSessionConnecting {
    let environment: SessionEnvironment, facts: AppTrustFacts
    func connect(_ request: NativeSessionConnect) async throws -> any NativeSessionTransport {
        let scenario = facts.scenario
        guard request.configuration.host.address.value == "127.0.0.1", request.configuration.host.port.value == 22221,
              request.configuration.user.value == "fixture", request.method == (scenario == .changed ? .password : .publicKey) else { throw AppNativeFiniteFailure.unexpectedSession }
        let observation = try await facts.claim()
        let primary = request.primary, keyboard = request.keyboard, trust = request.trust
        let selected = NativeSessionConnect(configuration: request.configuration, method: request.method, primary: { [observation, primary] value in
            observation.primary(value); return try await primary(value)
        }, keyboard: { [observation, keyboard] challenge, reply in
            observation.keyboard(); keyboard(challenge, reply)
        }, trust: { [observation, trust] event, reply in
            observation.trust(event); trust(event, reply)
        }, options: request.options, connectionTimeout: request.connectionTimeout, token: request.token)
        let production = NativeLibraryConnector(store: try await environment.sharedTrustStore())
        do {
            let transport = try await production.connect(selected)
            guard let actual = transport as? LibSSH2ShellSession else { throw AppNativeFiniteFailure.unexpectedSession }
            do { try observation.connected(stages: await actual.authenticationStages(), drain: actual.interactionDrain) }
            catch {
                actual.cancel(); await actual.close()
                throw NativeSessionConnectionFailure(failure: error, drain: CanonicalSessionDrain(handle: actual.interactionDrain), noNativeOwnerCreated: false)
            }
            return transport // Production driver alone owns receive/send/resize/close.
        } catch { observation.failed(error); throw error }
    }
}

@MainActor fileprivate final class AppTrustWeakBox {
    let owner: AppTrustOwner
    weak var tab: SessionTab?
    weak var driver: NativeSessionDriver?
    weak var view: NativeTerminalView?
    init(tab: SessionTab, driver: NativeSessionDriver, token: SessionToken) {
        owner = .init(tabID: tab.id, sessionID: token.sessionID, generation: token.generation)
        self.tab = tab; self.driver = driver; view = driver.terminal
    }
    var snapshot: AppTrustWeakFacts { .init(tabAlive: tab != nil, driverAlive: driver != nil, viewAlive: view != nil) }
}
@MainActor fileprivate final class AppTrustAttempt {
    let observation: AppTrustObservation
    var weakBox: AppTrustWeakBox?
    var tabID: UUID?
    var terminal: AppNativeFiniteTerminalPlan.Evidence?
    var closeDisposition = "notObserved", queueEmpty = false
    var weakAfterClose: AppTrustWeakFacts?
    init(_ observation: AppTrustObservation) { self.observation = observation }
    var report: AppTrustAttemptReport {
        .init(facts: observation.snapshot, owner: weakBox?.owner, terminal: terminal, closeDisposition: closeDisposition,
            canonicalDrained: observation.drained, queueEmpty: queueEmpty, weakAfterClose: weakAfterClose, weakNow: weakBox?.snapshot)
    }
}

/// The only new exercise. Keeps scalar receipts/weak UI boxes, never a second transport owner.
@MainActor fileprivate final class AppTrustExercise {
    private let model: AppModel, input: AppNativeFiniteInput, store: AppRealOwnedStore, environment: SessionEnvironment
    private let facts: AppTrustFacts, wrapper: AppTrustContract, material: AppTrustPublicMaterial, budget: AppNativeFiniteBudget, buildEpoch: Double
    private let credentials: AppRealNoCredentials
    private weak var window: NSWindow?
    private let descriptors: @MainActor () throws -> AppNativeFiniteDescriptorSnapshot
    private var audit: AppTrustStoreAudit?, known: AppNativeFiniteStableFile?, sourceKey: AppNativeFiniteStableFile?
    private var knownBytes: Data?, beforeInitialization: AppTrustPublicBytes?, points: [AppTrustStorePoint] = []
    private var attempts: [AppTrustAttempt] = []
    private var hostID: UUID?, keyID: UUID?, sourceUnchanged: Bool?, knownUnchanged = false, credentialCalls = 0
    private var snapshots = AppNativeFiniteDescriptorSnapshots(), fdMatched = false
    private var registryActive = 0, registryRetired = 0
    private var authenticationComplete = false
    private(set) var closedAndClean = false
    private(set) var phaseDeadline: ContinuousClock.Instant
    private(set) var timeoutFailure = AppNativeFiniteFailure.preparationDeadline
    init(model: AppModel, input: AppNativeFiniteInput, store: AppRealOwnedStore, environment: SessionEnvironment, facts: AppTrustFacts,
         wrapper: AppTrustContract, material: AppTrustPublicMaterial, budget: AppNativeFiniteBudget, buildEpoch: Double,
         credentials: AppRealNoCredentials, window: NSWindow?, descriptors: @escaping @MainActor () throws -> AppNativeFiniteDescriptorSnapshot) {
        self.model = model; self.input = input; self.store = store; self.environment = environment; self.facts = facts
        self.wrapper = wrapper; self.material = material; self.budget = budget; self.buildEpoch = buildEpoch
        self.credentials = credentials; self.window = window; self.descriptors = descriptors; phaseDeadline = budget.preparationDeadline
    }
    private func checkpoint() throws {
        try Task.checkCancellation()
        guard ContinuousClock.now < budget.fullDeadline else { throw AppNativeFiniteFailure.fullDeadline }
        guard ContinuousClock.now < phaseDeadline else { throw timeoutFailure }
    }
    private func wait(_ condition: @MainActor () throws -> Bool) async throws {
        while !(try condition()) { try checkpoint(); try await Task.sleep(for: .milliseconds(10)) }; try checkpoint()
    }
    func cancel() {
        for attempt in attempts { if let tabID = attempt.tabID { model.sessions.disconnect(tabID) } }
    }
    private func prepareHost() async throws -> HostConfiguration {
        let value = material.material.binding, host: HostConfiguration
        if wrapper.scenario == .changed {
            // Reject at actual handshake trust. No client key import/read, password/intent or provider substitution.
            host = .init(name: "Approved App wrong public pin fixture", address: value.host, port: value.port, username: value.user, authentication: .password)
        } else {
            sourceKey = try AppNativeFiniteStableFile(value.generation + "/id_ed25519")
            var before = try sourceKey!.read(limit: 32768)
            defer { before.resetBytes(in: 0..<before.count); before.removeAll() }
            let key = try await model.security.createKey(.importFile(URL(fileURLWithPath: value.generation + "/id_ed25519")), protection: .unencrypted, rememberPassphrase: nil)
            keyID = key.id
            guard !key.cleanupPending else { throw AppNativeFiniteFailure.importFailed }
            let imported = try await model.security.publicKey(key.id)
            guard imported.copyString == material.clientPublicKeyLine else { throw AppNativeFiniteFailure.importFailed }
            var after = try sourceKey!.read(limit: 32768)
            sourceUnchanged = before == after; after.resetBytes(in: 0..<after.count); after.removeAll()
            guard sourceUnchanged == true else { throw AppNativeFiniteFailure.sourceChanged }
            host = .init(name: "Approved App trust keyonly fixture", address: value.host, port: value.port, username: value.user, authentication: .privateKey, keyRef: key.id)
        }
        guard await model.saveHostSecurely(host, isNew: true, password: .manual) else { throw AppNativeFiniteFailure.hostSaveFailed }
        hostID = host.id
        let metadata = try await model.repository.securityMetadata()
        guard metadata.credentials.isEmpty, metadata.hosts.count == 1, metadata.hosts.first?.matchesConnection(of: host) == true,
              metadata.hosts.first?.credentialRef == nil, metadata.hosts.first?.savePasswordAuthorized == false,
              metadata.keys.allSatisfy({ $0.passphraseCredentialRef == nil }), metadata.keys.count == (wrapper.scenario == .changed ? 0 : 1) else { throw AppNativeFiniteFailure.hostSaveFailed }
        return host
    }
    func exercise() async throws {
        try await wait { self.model.didLoad && !self.model.isLoading }
        guard model.hosts.isEmpty, model.sessions.tabs.isEmpty, !model.files.visible else { throw AppNativeFiniteFailure.unexpectedSession }
        var settings = model.settings; settings.fontSize = 14
        guard await model.saveSettings(settings), model.settings.fontSize == 14 else { throw AppNativeFiniteFailure.operation }
        let audit = try AppTrustStoreAudit(store: store); self.audit = audit
        beforeInitialization = try audit.publicBytes()
        guard beforeInitialization == AppTrustPublicBytes.missing else { throw AppNativeFiniteFailure.trustMismatch }
        let trust = try await environment.sharedTrustStore()
        points.append(try await audit.point("initialized", store: trust)) // HostTrustStore creates its own header; never fabricate an empty file.
        guard points[0].records == 0 else { throw AppNativeFiniteFailure.trustMismatch }
        if wrapper.scenario == .changed {
            let identity = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22221))
            let wrong = try await Task.detached { try HostPublicKey(openSSHPublicKey: AppTrustPublicPin.line) }.value
            guard wrong.algorithm == "ssh-ed25519", wrong.fingerprint != material.material.binding.expectedFingerprint,
                  case .pending(let decision) = try await trust.evaluate(host: identity, key: wrong) else { throw AppNativeFiniteFailure.trustMismatch }
            _ = try await trust.confirm(decision, displayedFingerprint: wrong.fingerprint)
            points.append(try await audit.point("seeded-wrong-public-pin", store: trust, expectedFingerprint: wrong.fingerprint))
        }
        known = try AppNativeFiniteStableFile(material.material.binding.generation + "/known_hosts"); knownBytes = try known?.read(limit: 4096)
        let host = try await prepareHost()
        try input.revalidateMaterial(buildEpoch: buildEpoch); try checkpoint()
        snapshots.baseline = try descriptors()
        registryActive = SessionRetirementRegistry.shared.activeCount; registryRetired = SessionRetirementRegistry.shared.retiredCount
        phaseDeadline = budget.activeDeadline(start: .now); timeoutFailure = .activeDeadline // Set once for ALL attempts, never renewed.
        for ordinal in 1...wrapper.scenario.attempts {
            try await freshAttempt(ordinal, host: host, trust: trust)
            // The freshAttempt frame has returned. A still-live first view is evidence, not an auth abort.
            if let last = attempts.last { last.weakAfterClose = last.weakBox?.snapshot }
        }
    }
    private func freshAttempt(_ ordinal: Int, host: HostConfiguration, trust: HostTrustStore) async throws {
        try checkpoint()
        guard model.sessions.tabs.isEmpty else { throw AppNativeFiniteFailure.unexpectedSession }
        let observation = try await facts.arm(id: UUID(), ordinal: ordinal), attempt = AppTrustAttempt(observation)
        attempts.append(attempt)
        model.requestSession(hostID: host.id, mode: .newSession)
        guard model.sessions.tabs.count == 1, let opened = model.sessions.tabs.first, opened.hostID == host.id else { throw AppNativeFiniteFailure.unexpectedSession }
        attempt.tabID = opened.id
        try await wait { self.model.sessions.tabs.first?.driver != nil || self.model.sessions.tabs.first?.canReconnect == true }
        guard model.sessions.tabs.count == 1, let tab = model.sessions.tabs.first, let driver = tab.driver as? NativeSessionDriver,
              let token = driver.token, token.generation == 1, tab.hostID == host.id,
              tab.host?.connectionIdentity == host.connectionIdentity, model.sessions.selectedTabID == tab.id,
              model.sessions.workspaceVisible, !attempts.dropLast().contains(where: { $0.weakBox?.driver === driver || $0.weakBox?.tab === tab }) else { throw AppNativeFiniteFailure.unexpectedSession }
        let box = AppTrustWeakBox(tab: tab, driver: driver, token: token); attempt.weakBox = box
        if wrapper.scenario == .changed {
            try await wait { observation.snapshot.errorKind != nil && tab.canReconnect }
            guard tab.state == .failed(.trustRejected), tab.authentication == nil, tab.trust.count == 1,
                  let changed = tab.trust.first?.changed, changed.host.address.value == "127.0.0.1", changed.host.port.value == 22221,
                  changed.algorithm == "ssh-ed25519",
                  changed.expectedFingerprint == AppTrustPublicPin.fingerprint,
                  changed.presentedFingerprint == material.material.binding.expectedFingerprint else { throw AppNativeFiniteFailure.trustMismatch }
        } else {
            let needsPrompt = wrapper.scenario == .once || ordinal == 1
            try await wait { !tab.trust.isEmpty || tab.authentication != nil || tab.state == .connected || tab.canReconnect }
            if needsPrompt {
                guard tab.state == .awaitingTrust, tab.authentication == nil, tab.trust.count == 1, let prompt = tab.trust.first,
                      prompt.changed == nil, prompt.token == token, observation.snapshot.pendingRequestID == prompt.id,
                      material.material.binding.matchesTrust(host: prompt.host.address.value,
                        port: Int(prompt.host.port.value), algorithm: prompt.algorithm, fingerprint: prompt.fingerprint) else { throw AppNativeFiniteFailure.trustMismatch }
                try observation.beforeAcceptance(promptID: prompt.id)
                guard await model.sessions.accept(prompt, tabID: tab.id, persistence: wrapper.scenario == .once ? .once : .persistent) else { throw AppNativeFiniteFailure.trustMismatch }
                try await wait { tab.state == .connected || tab.authentication != nil || tab.canReconnect }
            }
            guard tab.state == .connected, tab.authentication == nil, tab.trust.isEmpty, driver.token == token else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        }
        guard let audit, let beforeInitialization else { throw AppNativeFiniteFailure.trustMismatch }
        let expectedPin: String? = wrapper.scenario == .once ? nil : (wrapper.scenario == .changed ? AppTrustPublicPin.fingerprint : material.material.binding.expectedFingerprint)
        points.append(try await audit.point("attempt-\(ordinal)", store: trust, expectedFingerprint: expectedPin))
        credentialCalls = await credentials.forbiddenCalls
        let currentFacts = attempts.map { $0.observation.snapshot }, owners = attempts.compactMap { $0.weakBox?.owner }
        try AppTrustAcceptance.validate(wrapper.scenario, facts: currentFacts, owners: owners, beforeInitialization: beforeInitialization, points: points)
        guard credentialCalls == 0 else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        try input.write(AppTrustAuthenticationReceipt(runID: wrapper.runID, pid: getpid(), scenario: wrapper.scenario, ordinal: ordinal,
            beforeInitialization: beforeInitialization, points: points, facts: currentFacts, owners: owners, credentialCalls: credentialCalls),
            leaf: AppTrustAuthenticationReceipt.leaf(ordinal))
        authenticationComplete = ordinal == wrapper.scenario.attempts // Auth only; terminal/close/resources remain independent.
        if wrapper.scenario != .changed {
            let plan = try AppNativeFiniteTerminalPlan(nonce: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())
            try await AppNativeFiniteRendererGeometry.prepare(driver, ownedWindow: window, checkpoint: { try self.checkpoint() }) {
                let command = Array(plan.command.utf8); driver.terminal.send(data: command[...])
            }
            try await wait {
                let evidence = try plan.inspect(driver.terminal.text); attempt.terminal = evidence
                return evidence.complete || tab.state != .connected
            }
            guard attempt.terminal?.complete == true, tab.state == .connected else { throw AppNativeFiniteFailure.terminalEvidence }
        }
        let result = await model.sessions.closeTabResult(tab.id, deadline: AppTrustAcceptance.closeDeadline(now: .now, active: phaseDeadline))
        switch result {
        case .closed: attempt.closeDisposition = "closed"
        case .retired: attempt.closeDisposition = "retired"; throw AppNativeFiniteFailure.closeRetired
        case .incomplete: attempt.closeDisposition = "incomplete"; throw AppNativeFiniteFailure.closeIncomplete
        }
        let snapshot = driver.snapshot
        attempt.queueEmpty = snapshot.pendingInputBytes == 0 && snapshot.pendingInputItems == 0 && !snapshot.receiveInFlight &&
            !snapshot.resizeInFlight && !snapshot.hasLatestResize && snapshot.nativeCloseCompleted && snapshot.interactionsDrained
        guard attempt.queueEmpty, observation.drained, model.sessions.tabs.isEmpty else { throw AppNativeFiniteFailure.drainIncomplete }
    }
    func prepareQuit(deadline: ContinuousClock.Instant) async throws {
        phaseDeadline = min(deadline, budget.fullDeadline); timeoutFailure = .cleanup
        if !model.sessions.tabs.isEmpty {
            let result = await model.sessions.closeAllResult(deadline: phaseDeadline)
            guard result.entries.allSatisfy({ $0.result == .closed }) else { throw AppNativeFiniteFailure.drainIncomplete }
        }
        try await wait { self.attempts.allSatisfy { $0.weakBox?.snapshot.released == true && $0.observation.drained } }
        guard authenticationComplete, attempts.count == wrapper.scenario.attempts,
              attempts.allSatisfy({ $0.closeDisposition == "closed" && $0.queueEmpty && ($0.terminal?.complete == true || wrapper.scenario == .changed) }) else { throw AppNativeFiniteFailure.cleanup }
        guard let beforeInitialization else { throw AppNativeFiniteFailure.trustMismatch }
        try AppTrustAcceptance.validate(wrapper.scenario, facts: attempts.map { $0.observation.snapshot }, owners: attempts.compactMap { $0.weakBox?.owner }, beforeInitialization: beforeInitialization, points: points)
        try sourceKey?.check(); try known?.check()
        if let known, let knownBytes { knownUnchanged = try known.read(limit: 4096) == knownBytes }
        let trust = try await environment.sharedTrustStore()
        let expectedPin: String? = wrapper.scenario == .once ? nil : (wrapper.scenario == .changed ? AppTrustPublicPin.fingerprint : material.material.binding.expectedFingerprint)
        guard let audit, let last = points.last,
              try await audit.point(last.label, store: trust, expectedFingerprint: expectedPin) == last else { throw AppNativeFiniteFailure.trustMismatch }
        guard knownUnchanged, wrapper.scenario == .changed ? sourceKey == nil && keyID == nil : sourceUnchanged == true else { throw AppNativeFiniteFailure.sourceChanged }
        credentialCalls = await credentials.forbiddenCalls
        guard credentialCalls == 0, SessionRetirementRegistry.shared.activeCount == registryActive,
              SessionRetirementRegistry.shared.retiredCount == registryRetired else { throw AppNativeFiniteFailure.resources }
        if let hostID { try await model.repository.apply([.deleteHost(hostID)]); self.hostID = nil }
        if let keyID { try await model.security.deleteKey(keyID); self.keyID = nil }
        repeat {
            try checkpoint()
            let after = try descriptors()
            if snapshots.cleanupFirst == nil { snapshots.cleanupFirst = after }; snapshots.cleanupLatest = after
            if let baseline = snapshots.baseline, baseline.complete, after.complete, baseline.count == after.count, baseline.entries == after.entries { fdMatched = true; break }
            try await Task.sleep(for: .milliseconds(20))
        } while true
        closedAndClean = fdMatched && hostID == nil && keyID == nil
    }
    func beforeStoresClose(_ transfers: TransferManagerSnapshot) throws {
        guard closedAndClean, model.sessions.tabs.isEmpty, transfers.isClosed, !transfers.hasActiveWork,
              transfers.jobs.isEmpty, transfers.serviceOperations.isEmpty,
              attempts.allSatisfy({ $0.weakBox?.snapshot.released == true && $0.observation.drained }) else { throw AppNativeFiniteFailure.beforeStoresClose }
    }
    func writeReport(leaf: String, checkpoint: String, failure: AppNativeFiniteFailure?, storeRemoved: Bool, quit: AppNativeFiniteQuitAudit) throws {
        try input.write(AppTrustReport(runID: wrapper.runID, pid: getpid(), scenario: wrapper.scenario, checkpoint: checkpoint, elapsedSeconds: budget.elapsed(),
            passed: failure == nil && closedAndClean, failureCode: failure, closedAndClean: closedAndClean, localStoreRemoved: storeRemoved, authenticationComplete: authenticationComplete,
            beforeInitialization: beforeInitialization, points: points, attempts: attempts.map(\.report),
            sourceKeyScope: wrapper.scenario == .changed ? "notRead-password-manual-trust-rejection" : "fixture-client-key-memory-comparison-only",
            sourceKeyUnchanged: sourceUnchanged, fixtureKnownHostsUnchanged: knownUnchanged, credentialCalls: credentialCalls,
            descriptorBaseline: snapshots.baseline?.count, descriptorAfter: snapshots.cleanupLatest?.count, descriptorIdentityMatched: fdMatched, descriptors: .init(snapshots),
            registryBaselineActive: registryActive, registryBaselineRetired: registryRetired,
            registryAfterActive: SessionRetirementRegistry.shared.activeCount, registryAfterRetired: SessionRetirementRegistry.shared.retiredCount, quit: quit), leaf: leaf)
    }
}
#endif

#if HOST_PROBE
fileprivate struct AppConcurrentPublicMaterial: Equatable {
    let material: AppConcurrentMaterial, hostKeyLine: String, clientPublicKeyLine: String
    static func load(_ wrapper: AppConcurrentContract, buildEpoch: Double) throws -> Self {
        let held = try AppNativeFiniteStableFile(wrapper.materialContractPath)
        let material = try AppConcurrentMaterial.decodeStrict(held.read(limit: 8192)), value = material.binding
        let now = Date().timeIntervalSince1970
        try material.validate(path: wrapper.materialContractPath, now: now, buildEpoch: buildEpoch)
        guard value.runID == wrapper.runID else { throw AppNativeFiniteFailure.contract }
        for path in [AppNativeFiniteContract.inputRoot, URL(fileURLWithPath: wrapper.materialContractPath).deletingLastPathComponent().path,
                     AppRealIntegrationContract.fixtureRoot + "/.runtime", AppRealIntegrationContract.fixtureRoot + "/.runtime/key-kbd", value.generation] {
            let fd = try AppRealPrivateInput.directory(path); Darwin.close(fd)
        }
        let policy = try AppNativeFiniteStableFile(URL(fileURLWithPath: wrapper.materialContractPath).deletingLastPathComponent().appendingPathComponent(AppConcurrentContract.policyLeaf).path)
        let proof = try policy.read(limit: 4096)
        guard AppRealPrivateInput.sha(proof) == value.policyProofSHA256 else { throw AppNativeFiniteFailure.contract }
        try value.validatePolicyProof(proof, now: now, buildEpoch: buildEpoch)
        let state = try AppNativeFiniteStableFile(AppRealIntegrationContract.fixtureRoot + "/.runtime/state.json")
        try value.validateState(state.read(limit: 4096))
        let origin = try AppNativeFiniteStableFile(value.generation + "/provenance.json"), known = try AppNativeFiniteStableFile(value.generation + "/known_hosts")
        let provenance = try origin.read(limit: 4096), bytes = try known.read(limit: 4096)
        guard AppRealPrivateInput.sha(provenance) == value.provenanceSHA256, AppRealPrivateInput.sha(bytes) == value.knownHostsSHA256 else { throw AppNativeFiniteFailure.contract }
        try value.validateProvenance(provenance)
        guard let text = String(data: bytes, encoding: .utf8), text.hasSuffix("\n"), !text.dropLast().contains("\n") else { throw AppNativeFiniteFailure.trustMismatch }
        let fields = text.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == "[127.0.0.1]:22223", fields[1] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51, blob.base64EncodedString() == fields[2],
              "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "") == value.expectedFingerprint else { throw AppNativeFiniteFailure.trustMismatch }
        let exported = try AppNativeFiniteStableFile(value.generation + "/id_ed25519.pub"), publicBytes = try exported.read(limit: 4096)
        guard AppRealPrivateInput.sha(publicBytes) == value.generationPublicKeySHA256,
              let publicText = String(data: publicBytes, encoding: .utf8) else { throw AppNativeFiniteFailure.contract }
        let client = publicText.trimmingCharacters(in: .newlines).split(separator: " ")
        guard client.count >= 2, client[0] == "ssh-ed25519" else { throw AppNativeFiniteFailure.contract }
        try held.check(); try policy.check(); try state.check(); try origin.check(); try known.check(); try exported.check()
        return .init(material: material, hostKeyLine: fields[1...2].joined(separator: " "), clientPublicKeyLine: client.prefix(2).joined(separator: " "))
    }
}

fileprivate final class AppConcurrentObservation: @unchecked Sendable {
    private let lock = NSLock()
    private var value: AppConcurrentNativeFacts
    private var canonical: (any SessionDrainObserving)?
    private var cancellation: CancellationToken?
    init(ticket: AppConcurrentTicket) { value = .init(ticket: ticket) }
    private func held<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }
    var snapshot: AppConcurrentNativeFacts { held { value } }
    var drained: Bool { held { canonical?.snapshot.drained == true } }
    var nativeClosed: Bool { held { canonical?.snapshot.nativeClosed == true } }
    var uncancelled: Bool { held { cancellation?.isCancelled == false } }
    func connect(_ token: CancellationToken) { held { value.connectCalls += 1; cancellation = token } }
    func primary(_ request: NativeSessionPrimaryRequest) throws {
        try held {
            value.primaryCalls += 1
            if value.packageSessionID != nil || request.method != .publicKey || request.token !== cancellation { value.observationFailed = true }
            value.packageSessionID = request.sessionID; value.primaryRequestID = request.requestID
            guard !value.observationFailed else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        }
    }
    func keyboard() { held { value.keyboardCalls += 1 } }
    func trust() { held { value.trustCallbacks += 1; value.observationFailed = true } }
    func invalid() { held { value.observationFailed = true } }
    private static func stages(_ values: [NativeShellAuthenticationStage]) -> [String] {
        values.map {
            switch $0 {
            case .advertised: "advertised"
            case .primaryStarted(let method): "primaryStarted." + method.rawValue
            case .primaryResult(let method, _, _): "primaryResult." + method.rawValue
            case .keyboardStarted: "keyboardStarted"
            case .keyboardResult: "keyboardResult"
            case .authenticated: "authenticated"
            case .shellReady: "shellReady"
            }
        }
    }
    func connected(stages: [NativeShellAuthenticationStage], drain: NativeShellDrainHandle) throws {
        held { value.shellSessions += 1; value.stages = Self.stages(stages); canonical = CanonicalSessionDrain(handle: drain) }
        let authentication = try AppMFAAuthentication(stages, fixture: .keyKI)
        held { value.bAuthentication = authentication }
    }
    func failed(_ error: any Error) {
        held {
            let wrapped = error as? NativeSessionConnectionFailure, typed = (wrapped?.failure ?? error) as? NativeShellError
            if let typed {
                value.errorKind = typed.kind.rawValue
                value.errorOperation = ["cancel", "keyboard-interaction", "keyboard-authentication", "connect", "establish", "host-key", "primary-authentication", "authentication"].contains(typed.operation) ? typed.operation : "other"
                value.stages = Self.stages(typed.authenticationStages)
                value.aCancellation = try? AppConcurrentCancelledAuthentication(typed.authenticationStages, errorKind: typed.kind.rawValue)
                if let drain = typed.interactionDrain { canonical = CanonicalSessionDrain(handle: drain) }
            } else { value.errorKind = "other"; value.errorOperation = "other" }
            if let drain = wrapped?.drain { canonical = drain }
        }
    }
}
/// Shared only for ticket identity/accounting. It owns no driver, terminal, transport or secret.
fileprivate final class AppConcurrentRuntime: @unchecked Sendable {
    private let lock = NSLock()
    private var ledger = AppConcurrentTicketLedger()
    private var invalid = false
    private var values: [UUID: AppConcurrentObservation] = [:]
    private func held<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }
    func prepare(hostID: UUID, appSessionID: UUID) throws -> AppConcurrentObservation {
        try held {
            do {
                guard !invalid else { throw AppNativeFiniteFailure.unexpectedSession }
                let ticket = try ledger.prepare(hostID: hostID, appSessionID: appSessionID), observation = AppConcurrentObservation(ticket: ticket)
                values[appSessionID] = observation; return observation
            } catch { invalid = true; throw error }
        }
    }
    func requireTwo() throws { try held { guard !invalid else { throw AppNativeFiniteFailure.unexpectedSession }; try ledger.requireTwo() } }
    func observation(appSessionID: UUID) -> AppConcurrentObservation? { held { values[appSessionID] } }
    func connect(_ observation: AppConcurrentObservation, token: CancellationToken) throws {
        try held {
            do { try ledger.connect(observation.snapshot.ticket); observation.connect(token) }
            catch { observation.invalid(); throw error }
        }
    }
    func primary(_ observation: AppConcurrentObservation, request: NativeSessionPrimaryRequest) throws {
        do {
            try observation.primary(request)
            try held { try ledger.primary(observation.snapshot.ticket) }
        } catch { observation.invalid(); throw error }
    }
}
@MainActor fileprivate final class AppConcurrentBuilder: SessionBuilding {
    private let repository: any AppRepositoryProtocol, security: SecurityCoordinator, environment: SessionEnvironment, runtime: AppConcurrentRuntime
    init(repository: any AppRepositoryProtocol, security: SecurityCoordinator, environment: SessionEnvironment, runtime: AppConcurrentRuntime) {
        self.repository = repository; self.security = security; self.environment = environment; self.runtime = runtime
    }
    func configuration(hostID: UUID) async throws -> (HostConfiguration, SSHSessionConfiguration) {
        try await NativeSessionBuilder(repository: repository, security: security, environment: environment).configuration(hostID: hostID)
    }
    func prepare(hostID: UUID, sessionID: UUID) async throws -> ReadySession {
        let observation = try runtime.prepare(hostID: hostID, appSessionID: sessionID)
        let connector = AppConcurrentConnector(environment: environment, runtime: runtime, observation: observation)
        // sessionID here is the actual App tab/token session, not the package-generated UUID.
        return try await NativeSessionBuilder(repository: repository, security: security, environment: environment, connector: connector).prepare(hostID: hostID, sessionID: sessionID)
    }
}
fileprivate struct AppConcurrentConnector: NativeSessionConnecting {
    let environment: SessionEnvironment, runtime: AppConcurrentRuntime, observation: AppConcurrentObservation
    func connect(_ request: NativeSessionConnect) async throws -> any NativeSessionTransport {
        guard request.configuration.host.address.value == "127.0.0.1", request.configuration.host.port.value == 22223,
              request.configuration.user.value == "fixture", request.method == .publicKey else { observation.invalid(); throw AppNativeFiniteFailure.unexpectedSession }
        try runtime.connect(observation, token: request.token)
        let primary = request.primary, keyboard = request.keyboard, trust = request.trust
        let selected = NativeSessionConnect(configuration: request.configuration, method: request.method, primary: { [runtime, observation, primary] value in
            try runtime.primary(observation, request: value); return try await primary(value)
        }, keyboard: { [observation, keyboard] challenge, reply in observation.keyboard(); keyboard(challenge, reply) },
           trust: { [observation, trust] event, reply in observation.trust(); trust(event, reply) }, options: request.options,
           connectionTimeout: request.connectionTimeout, token: request.token)
        let actual = NativeLibraryConnector(store: try await environment.sharedTrustStore())
        do {
            let transport = try await actual.connect(selected)
            guard let native = transport as? LibSSH2ShellSession else { observation.invalid(); throw AppNativeFiniteFailure.unexpectedSession }
            do { try observation.connected(stages: await native.authenticationStages(), drain: native.interactionDrain) }
            catch {
                native.cancel(); await native.close()
                throw NativeSessionConnectionFailure(failure: error, drain: CanonicalSessionDrain(handle: native.interactionDrain), noNativeOwnerCreated: false)
            }
            return transport // Unwrapped: only production driver receives/sends/resizes/closes.
        } catch { observation.failed(error); throw error }
    }
}

@MainActor fileprivate final class AppConcurrentRun {
    let role: AppConcurrentRole, tabID: UUID, observation: AppConcurrentObservation
    var box: AppTrustWeakBox?, owner: AppConcurrentOwner?
    var keyboard: AppMFAKIBudget?
    var budgetClosed = false, closeDisposition = "notObserved", queueEmpty = false
    var managementPlan: AppConcurrentManagementPlan
    let manager: AppMFAManagement
    var status: AppConcurrentStatusFacts?
    init(role: AppConcurrentRole, tabID: UUID, observation: AppConcurrentObservation, manager: AppMFAManagement) {
        self.role = role; self.tabID = tabID; self.observation = observation; self.manager = manager; managementPlan = .init(role: role)
    }
    var lifecycle: AppConcurrentLifecycle {
        .init(role: role, owner: owner, native: observation.snapshot, closeDisposition: closeDisposition, canonicalDrained: observation.drained,
            queueEmpty: queueEmpty, nativeClosed: observation.nativeClosed, weak: box?.snapshot)
    }
    func cancelManagement() { managementPlan.cancel(); manager.cancel() }
}

@MainActor fileprivate final class AppConcurrentExercise {
    private let model: AppModel, input: AppNativeFiniteInput, store: AppRealOwnedStore, environment: SessionEnvironment, runtime: AppConcurrentRuntime
    private let wrapper: AppConcurrentContract, material: AppConcurrentPublicMaterial, budget: AppNativeFiniteBudget, buildEpoch: Double
    private let credentials: AppRealNoCredentials
    private let descriptors: @MainActor () throws -> AppNativeFiniteDescriptorSnapshot
    private var runs: [AppConcurrentRun] = []
    private var hostID: UUID?, keyID: UUID?, sourceKey: AppNativeFiniteStableFile?, known: AppNativeFiniteStableFile?, knownBytes: Data?
    private var trustAudit: AppTrustStoreAudit?, approvedBytes: AppTrustPublicBytes?
    private var sourceUnchanged = false, knownUnchanged = false, pinUnchanged = false, credentialCalls = 0
    private var isolation: AppConcurrentIsolationFacts?, authenticationComplete = false, cleanupComplete = false, cleanupWritten = false
    private var snapshots = AppNativeFiniteDescriptorSnapshots(), fdMatched = false, registryActive = 0, registryRetired = 0
    private(set) var phaseDeadline: ContinuousClock.Instant
    private(set) var timeoutFailure = AppNativeFiniteFailure.preparationDeadline
    private(set) var closedAndClean = false
    init(model: AppModel, input: AppNativeFiniteInput, store: AppRealOwnedStore, environment: SessionEnvironment, runtime: AppConcurrentRuntime,
         wrapper: AppConcurrentContract, material: AppConcurrentPublicMaterial, budget: AppNativeFiniteBudget, buildEpoch: Double,
         credentials: AppRealNoCredentials, descriptors: @escaping @MainActor () throws -> AppNativeFiniteDescriptorSnapshot) {
        self.model = model; self.input = input; self.store = store; self.environment = environment; self.runtime = runtime
        self.wrapper = wrapper; self.material = material; self.budget = budget; self.buildEpoch = buildEpoch
        self.credentials = credentials; self.descriptors = descriptors; phaseDeadline = budget.preparationDeadline
    }
    private func checkpoint() throws {
        try Task.checkCancellation()
        guard ContinuousClock.now < budget.fullDeadline else { throw AppNativeFiniteFailure.fullDeadline }
        guard ContinuousClock.now < phaseDeadline else { throw timeoutFailure }
    }
    private func wait(_ condition: @MainActor () throws -> Bool) async throws {
        while !(try condition()) { try checkpoint(); try await Task.sleep(for: .milliseconds(10)) }; try checkpoint()
    }
    private func remaining() -> Double {
        let value = ContinuousClock.now.duration(to: min(phaseDeadline, budget.fullDeadline)).components
        return max(0, Double(value.seconds) + Double(value.attoseconds) / 1e18)
    }
    func cancel() { for run in runs { run.cancelManagement(); model.sessions.disconnect(run.tabID) } }
    private func prepareHost() async throws -> HostConfiguration {
        let value = material.material.binding
        sourceKey = try AppNativeFiniteStableFile(value.generation + "/id_ed25519")
        var before = try sourceKey!.read(limit: 32768)
        defer { before.resetBytes(in: 0..<before.count); before.removeAll() }
        let key = try await model.security.createKey(.importFile(URL(fileURLWithPath: value.generation + "/id_ed25519")), protection: .unencrypted, rememberPassphrase: nil)
        keyID = key.id
        guard !key.cleanupPending else { throw AppNativeFiniteFailure.importFailed }
        let exported = try await model.security.publicKey(key.id)
        guard exported.copyString == material.clientPublicKeyLine else { throw AppNativeFiniteFailure.importFailed }
        var after = try sourceKey!.read(limit: 32768)
        sourceUnchanged = before == after; after.resetBytes(in: 0..<after.count); after.removeAll()
        guard sourceUnchanged else { throw AppNativeFiniteFailure.sourceChanged }
        let host = HostConfiguration(name: "Approved concurrent keyKI fixture", address: "127.0.0.1", port: 22223, username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id)
        guard await model.saveHostSecurely(host, isNew: true, password: .manual) else { throw AppNativeFiniteFailure.hostSaveFailed }
        hostID = host.id
        let metadata = try await model.repository.securityMetadata()
        guard metadata.hosts.count == 1, metadata.hosts.first?.matchesConnection(of: host) == true, metadata.credentials.isEmpty,
              metadata.hosts.first?.credentialRef == nil, metadata.hosts.first?.savePasswordAuthorized == false,
              metadata.keys.count == 1, metadata.keys.first?.passphraseCredentialRef == nil else { throw AppNativeFiniteFailure.hostSaveFailed }
        return host
    }
    func exercise() async throws {
        try await wait { self.model.didLoad && !self.model.isLoading }
        guard model.hosts.isEmpty, model.sessions.tabs.isEmpty, !model.files.visible else { throw AppNativeFiniteFailure.unexpectedSession }
        let trust = try await environment.sharedTrustStore(), audit = try AppTrustStoreAudit(store: store)
        trustAudit = audit
        guard try await trust.records().isEmpty, trust.knownHostsPath.value == audit.path else { throw AppNativeFiniteFailure.trustMismatch }
        let identity = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22223)), line = material.hostKeyLine
        let key = try await Task.detached { try HostPublicKey(openSSHPublicKey: line) }.value
        guard key.fingerprint == AppMFAFixture.keyKI.fingerprint, case .pending(let decision) = try await trust.evaluate(host: identity, key: key) else { throw AppNativeFiniteFailure.trustMismatch }
        _ = try await trust.confirm(decision, displayedFingerprint: key.fingerprint)
        approvedBytes = try audit.publicBytes()
        known = try AppNativeFiniteStableFile(material.material.binding.generation + "/known_hosts"); knownBytes = try known?.read(limit: 4096)
        let host = try await prepareHost()
        try input.revalidateMaterial(buildEpoch: buildEpoch); try checkpoint()
        snapshots.baseline = try descriptors(); registryActive = SessionRetirementRegistry.shared.activeCount; registryRetired = SessionRetirementRegistry.shared.retiredCount
        phaseDeadline = budget.activeDeadline(start: .now); timeoutFailure = .activeDeadline
        try await exercisePair(host)
    }
    private func open(_ role: AppConcurrentRole, host: HostConfiguration) async throws -> AppConcurrentRun {
        let before = Set(model.sessions.tabs.map(\.id))
        model.requestSession(hostID: host.id, mode: .newSession)
        let ids = Set(model.sessions.tabs.map(\.id)).subtracting(before)
        guard ids.count == 1, let id = ids.first, !runs.contains(where: { $0.tabID == id }) else { throw AppNativeFiniteFailure.unexpectedSession }
        try await wait { self.runtime.observation(appSessionID: id) != nil || self.model.sessions.tabs.first(where: { $0.id == id })?.canReconnect == true }
        guard let observation = runtime.observation(appSessionID: id) else { throw AppNativeFiniteFailure.unexpectedSession }
        let manager = try AppMFAManagement(material: material.material.binding)
        let run = AppConcurrentRun(role: role, tabID: id, observation: observation, manager: manager); runs.append(run)
        try await wait { self.model.sessions.tabs.first(where: { $0.id == id })?.driver != nil }
        guard let tab = model.sessions.tabs.first(where: { $0.id == id }), let driver = tab.driver as? NativeSessionDriver,
              let token = driver.token, token.sessionID == id, token.generation == 1, tab.hostID == host.id,
              observation.snapshot.ticket.appSessionID == id, observation.snapshot.ticket.hostID == host.id,
              !runs.dropLast().contains(where: { $0.box?.driver === driver }) else { throw AppNativeFiniteFailure.unexpectedSession }
        run.box = AppTrustWeakBox(tab: tab, driver: driver, token: token)
        return run
    }
    private func current(_ run: AppConcurrentRun, prompt: SessionAuthenticationPrompt, host: HostConfiguration, selected: Bool) -> Bool {
        guard let tab = run.box?.tab, let driver = run.box?.driver, let token = driver.token else { return false }
        return model.sessions.tabs.count == 2 && model.sessions.tabs.contains(where: { $0 === tab }) && tab.id == run.tabID && tab.driver === driver &&
            token.sessionID == run.tabID && token.generation == 1 && prompt.token == token && tab.authentication == prompt && tab.state == .authenticating &&
            tab.hostID == host.id && tab.host?.connectionIdentity == host.connectionIdentity && run.observation.uncancelled &&
            (!selected || (model.sessions.selectedTabID == tab.id && model.sessions.workspaceVisible))
    }
    private func owner(_ run: AppConcurrentRun, prompt: SessionAuthenticationPrompt, host: HostConfiguration) throws -> AppConcurrentOwner {
        guard let token = run.box?.driver?.token else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        return .init(role: run.role, ticketID: run.observation.snapshot.ticket.id, hostID: host.id, tabID: run.tabID,
            appSessionID: token.sessionID, requestID: prompt.id, generation: token.generation)
    }
    private func claim(_ run: AppConcurrentRun, prompt: SessionAuthenticationPrompt, host: HostConfiguration) throws -> AppMFAKIBudget.Phase {
        guard current(run, prompt: prompt, host: host, selected: false), case .keyboard(let name, let instruction, let fields) = prompt.payload,
              var keyboard = run.keyboard else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        let phase = try keyboard.claim(name: name, instruction: instruction, fields: fields.map(\.text), echo: fields.map(\.echo), now: ProcessInfo.processInfo.systemUptime)
        run.keyboard = keyboard; return phase
    }
    private func exercisePair(_ host: HostConfiguration) async throws {
        let a = try await open(.a, host: host), b = try await open(.b, host: host)
        guard a.manager !== b.manager else { throw AppNativeFiniteFailure.unexpectedSession }
        try await wait { (a.box?.tab?.authentication != nil && b.box?.tab?.authentication != nil) || a.box?.tab?.canReconnect == true || b.box?.tab?.canReconnect == true }
        guard let promptA = a.box?.tab?.authentication, let promptB = b.box?.tab?.authentication,
              current(a, prompt: promptA, host: host, selected: false), current(b, prompt: promptB, host: host, selected: false),
              a.observation.snapshot.primaryCalls == 1, b.observation.snapshot.primaryCalls == 1,
              a.observation.snapshot.keyboardCalls == 1, b.observation.snapshot.keyboardCalls == 1,
              let packageA = a.observation.snapshot.packageSessionID, let packageB = b.observation.snapshot.packageSessionID, packageA != packageB else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        try runtime.requireTwo()
        let deadline = ProcessInfo.processInfo.systemUptime + remaining()
        a.keyboard = try AppMFAKIBudget(deadline: deadline); b.keyboard = try AppMFAKIBudget(deadline: deadline)
        _ = try claim(a, prompt: promptA, host: host); let firstB = try claim(b, prompt: promptB, host: host)
        let managerA = a.manager, managerB = b.manager
        guard let fixtureA = a.keyboard?.sessionID, let fixtureB = b.keyboard?.sessionID,
              managerA.snapshot.calls == 0, managerB.snapshot.calls == 0 else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        let ownerA = try owner(a, prompt: promptA, host: host), ownerB = try owner(b, prompt: promptB, host: host)
        let pair = try AppConcurrentFirstPair(a: ownerA, b: ownerB, fixtureA: fixtureA, fixtureB: fixtureB)
        a.owner = ownerA; b.owner = ownerB
        // No suspension from the two-current-prompt checks through both negative replies.
        let tokensUncancelled = a.observation.uncancelled && b.observation.uncancelled
        let bothPending = current(a, prompt: promptA, host: host, selected: false) && current(b, prompt: promptB, host: host, selected: false)
        model.showWorkspace(.session(b.tabID))
        let cross = !model.sessions.respond(.answers([SecretBytes(utf8: "non-secret-cross-owner-negative")]), to: promptA, tabID: b.tabID)
        let bSame = b.box?.tab?.authentication == promptB && current(b, prompt: promptB, host: host, selected: true)
        model.showWorkspace(.session(a.tabID))
        guard model.sessions.selectedTabID == a.tabID, model.sessions.workspaceVisible else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        model.sessions.cancelChallenge(promptA, tabID: a.tabID); a.cancelManagement()
        a.keyboard?.close(); a.budgetClosed = a.keyboard?.closed == true
        let late = !model.sessions.respond(.answers([SecretBytes(utf8: "non-secret-late-negative")]), to: promptA, tabID: a.tabID) &&
            a.box?.tab?.authentication == nil && !a.observation.uncancelled && managerA.snapshot.cancellationRequested
        let bPreserved = current(b, prompt: promptB, host: host, selected: false) && b.box?.tab?.authentication == promptB && !managerB.snapshot.cancellationRequested
        let relation = AppConcurrentIsolationFacts(a: ownerA, b: ownerB, twoFirstPending: bothPending,
            distinctDrivers: a.box?.driver != nil && b.box?.driver != nil && a.box?.driver !== b.box?.driver, distinctPackageSessions: packageA != packageB, distinctFixtureSessions: fixtureA != fixtureB,
            tokensUncancelledAtFirstPair: tokensUncancelled, aManagementReadsBeforeCancel: managerA.snapshot.calls, bManagementReadsBeforeCancel: managerB.snapshot.calls,
            crossReplyRejected: cross, bPromptUnchangedAfterCross: bSame, lateReplyRejected: late, bOwnerUnchangedAfterACancel: bPreserved)
        try relation.requireComplete(); isolation = relation
        model.showWorkspace(.session(b.tabID))
        try await answerB(b, firstPrompt: promptB, firstPhase: firstB, host: host, pair: pair)
        try await wait { a.observation.snapshot.errorKind != nil && a.box?.tab?.canReconnect == true }
        let factsA = a.observation.snapshot, factsB = b.observation.snapshot
        guard factsA.aCancellation != nil, factsA.bAuthentication == nil, factsB.aCancellation == nil,
              factsA.connectCalls == 1, factsB.connectCalls == 1, factsA.primaryCalls == 1, factsB.primaryCalls == 1,
              factsA.primaryRequestID != nil, factsB.primaryRequestID != nil, factsA.primaryRequestID != factsB.primaryRequestID,
              factsA.packageSessionID != factsB.packageSessionID, factsB.errorKind == nil, factsB.errorOperation == nil,
              factsA.keyboardCalls == 1, factsB.keyboardCalls == 4, factsA.trustCallbacks == 0, factsB.trustCallbacks == 0,
              factsA.shellSessions == 0, factsB.shellSessions == 1, factsB.bAuthentication != nil,
              !factsA.observationFailed, !factsB.observationFailed, let budgetA = a.keyboard, let budgetB = b.keyboard,
              budgetA.closed, budgetA.rounds == 1, budgetA.replies == 0, budgetA.managementReads == 0 else { throw AppNativeFiniteFailure.typedStages }
        try budgetB.requireComplete(); try runtime.requireTwo(); credentialCalls = await credentials.forbiddenCalls
        guard credentialCalls == 0 else { throw AppNativeFiniteFailure.unexpectedAuthentication }
        try input.write(AppConcurrentAuthenticationReceipt(runID: wrapper.runID, pid: getpid(), isolation: relation, a: factsA, b: factsB,
            aKeyboard: AppMFAKIFacts(budgetA), bKeyboard: AppMFAKIFacts(budgetB), aBudgetClosed: a.budgetClosed, credentialCalls: credentialCalls), leaf: AppConcurrentAuthenticationReceipt.leaf)
        authenticationComplete = true
        try await close(a); try await close(b)
        guard runs.count == 2, model.sessions.tabs.isEmpty else { throw AppNativeFiniteFailure.drainIncomplete }
    }
    private func answerB(_ b: AppConcurrentRun, firstPrompt: SessionAuthenticationPrompt, firstPhase: AppMFAKIBudget.Phase,
                         host: HostConfiguration, pair: AppConcurrentFirstPair) async throws {
        var prompt = firstPrompt, phase = firstPhase, requestIDs: Set<UUID> = [], ownership = pair
        for round in 0..<4 {
            if round > 0 {
                try await wait { b.box?.tab?.authentication != nil || b.box?.tab?.canReconnect == true || b.box?.tab?.state == .connected }
                guard let next = b.box?.tab?.authentication else { throw AppNativeFiniteFailure.unexpectedAuthentication }
                prompt = next; phase = try claim(b, prompt: prompt, host: host)
            }
            guard current(b, prompt: prompt, host: host, selected: true), requestIDs.insert(prompt.id).inserted,
                  let fixture = b.keyboard?.sessionID else { throw AppNativeFiniteFailure.unexpectedAuthentication }
            let manager = b.manager
            let expectedOwner = try owner(b, prompt: prompt, host: host)
            try ownership.beginB(expectedOwner, fixture: fixture)
            var answer = Data(); defer { answer.resetBytes(in: 0..<answer.count); answer.removeAll() }
            switch phase {
            case .secret(let session, let index):
                try b.managementPlan.response(index: index); try b.keyboard?.claimManagementRead(phase)
                let deadline = ProcessInfo.processInfo.systemUptime + remaining()
                answer = try await Task.detached { try manager.response(session: session, index: index, deadline: deadline) }.value
            case .zero: break
            }
            try checkpoint()
            guard current(b, prompt: prompt, host: host, selected: true), try owner(b, prompt: prompt, host: host) == expectedOwner else { throw AppNativeFiniteFailure.unexpectedAuthentication }
            try ownership.finishB(expectedOwner, fixture: fixture)
            try b.keyboard?.consume(phase, now: ProcessInfo.processInfo.systemUptime)
            let values: [SecretBytes]
            switch phase { case .secret: values = [SecretBytes(answer)]; case .zero: values = [] }
            try b.keyboard?.resolved(model.sessions.respond(.answers(values), to: prompt, tabID: b.tabID))
        }
        try b.keyboard?.requireComplete()
        try await wait { b.box?.tab?.state == .connected || b.box?.tab?.authentication != nil || b.box?.tab?.canReconnect == true }
        guard b.box?.tab?.state == .connected, b.box?.tab?.authentication == nil else { throw AppNativeFiniteFailure.unexpectedAuthentication }
    }
    private func close(_ run: AppConcurrentRun) async throws {
        let heldDriver = run.box?.driver // Keep this exact owner only through close/snapshot, never through all-weak cleanup.
        let active = AppTrustAcceptance.closeDeadline(now: .now, active: phaseDeadline)
        let result = await model.sessions.closeTabResult(run.tabID, deadline: active)
        switch result {
        case .closed: run.closeDisposition = "closed"
        case .retired: run.closeDisposition = "retired"; throw AppNativeFiniteFailure.closeRetired
        case .incomplete: run.closeDisposition = "incomplete"; throw AppNativeFiniteFailure.closeIncomplete
        }
        if let snapshot = heldDriver?.snapshot {
            run.queueEmpty = snapshot.pendingInputBytes == 0 && snapshot.pendingInputItems == 0 && !snapshot.receiveInFlight && !snapshot.resizeInFlight &&
                !snapshot.hasLatestResize && snapshot.nativeCloseCompleted && snapshot.interactionsDrained
        }
        guard run.queueEmpty, run.observation.drained else { throw AppNativeFiniteFailure.drainIncomplete }
    }
    private func managementCleanup(_ run: AppConcurrentRun) async -> AppConcurrentStatusFacts {
        run.cancelManagement()
        var status = AppMFAStatus.unknown
        let manager = run.manager
        let returned = await AppMFACleanupWait.observe(deadline: phaseDeadline, pending: { manager.snapshot.pendingCalls })
        if let fixture = run.keyboard?.sessionID, returned, run.observation.nativeClosed, manager.snapshot.pendingCalls == 0, remaining() > 0 {
            do {
                try run.managementPlan.status()
                let deadline = ProcessInfo.processInfo.systemUptime + remaining()
                status = try await Task.detached { try manager.sessionStatus(session: fixture, deadline: deadline) }.value
            } catch { status = .unknown }
        }
        return .init(role: run.role, statusReads: run.managementPlan.statusReads, serverSessionStatus: status, management: manager.snapshot)
    }
    func prepareQuit(deadline: ContinuousClock.Instant) async throws {
        phaseDeadline = min(deadline, budget.fullDeadline); timeoutFailure = .cleanup
        for run in runs where run.closeDisposition != "closed" { do { try await close(run) } catch { /* Keep per-owner real close facts; management still gets one bounded observation. */ } }
        if !cleanupWritten, let a = runs.first(where: { $0.role == .a }), let b = runs.first(where: { $0.role == .b }) {
            a.status = await managementCleanup(a); b.status = await managementCleanup(b)
            if let statusA = a.status, let statusB = b.status {
                do { try statusA.requireComplete(); try statusB.requireComplete(); cleanupComplete = true }
                catch { cleanupComplete = false }
                try input.write(AppConcurrentCleanupReceipt(runID: wrapper.runID, pid: getpid(), a: statusA, b: statusB, passed: cleanupComplete), leaf: AppConcurrentCleanupReceipt.leaf)
                cleanupWritten = true
            }
        }
        guard authenticationComplete, cleanupComplete, runs.count == 2, model.sessions.tabs.isEmpty,
              runs.allSatisfy({ $0.closeDisposition == "closed" && $0.queueEmpty && $0.observation.drained }) else { throw AppNativeFiniteFailure.cleanup }
        try await wait { self.runs.allSatisfy { $0.box?.snapshot.released == true } }
        try sourceKey?.check(); try known?.check()
        if let known, let knownBytes { knownUnchanged = try known.read(limit: 4096) == knownBytes }
        if let trustAudit, let approvedBytes { pinUnchanged = try trustAudit.publicBytes() == approvedBytes }
        let recordsStore = try await environment.sharedTrustStore()
        let records = try await recordsStore.records()
        guard sourceUnchanged, knownUnchanged, pinUnchanged, records.count == 1,
              records.allSatisfy({ $0.host.address.value == "127.0.0.1" && $0.host.port.value == 22223 && $0.key.algorithm == "ssh-ed25519" && $0.key.fingerprint == AppMFAFixture.keyKI.fingerprint }) else { throw AppNativeFiniteFailure.sourceChanged }
        credentialCalls = await credentials.forbiddenCalls
        guard credentialCalls == 0, SessionRetirementRegistry.shared.activeCount == registryActive,
              SessionRetirementRegistry.shared.retiredCount == registryRetired else { throw AppNativeFiniteFailure.resources }
        if let hostID { try await model.repository.apply([.deleteHost(hostID)]); self.hostID = nil }
        if let keyID { try await model.security.deleteKey(keyID); self.keyID = nil }
        repeat {
            try checkpoint(); let after = try descriptors()
            if snapshots.cleanupFirst == nil { snapshots.cleanupFirst = after }; snapshots.cleanupLatest = after
            if let baseline = snapshots.baseline, baseline.complete, after.complete, baseline.count == after.count, baseline.entries == after.entries { fdMatched = true; break }
            try await Task.sleep(for: .milliseconds(20))
        } while true
        closedAndClean = fdMatched && hostID == nil && keyID == nil
    }
    func beforeStoresClose(_ transfers: TransferManagerSnapshot) throws {
        guard closedAndClean, model.sessions.tabs.isEmpty, transfers.isClosed, !transfers.hasActiveWork,
              transfers.jobs.isEmpty, transfers.serviceOperations.isEmpty,
              runs.allSatisfy({ $0.box?.snapshot.released == true && $0.observation.drained }) else { throw AppNativeFiniteFailure.beforeStoresClose }
    }
    func writeReport(leaf: String, checkpoint: String, failure: AppNativeFiniteFailure?, storeRemoved: Bool, quit: AppNativeFiniteQuitAudit) throws {
        let a = runs.first(where: { $0.role == .a }), b = runs.first(where: { $0.role == .b })
        try input.write(AppConcurrentReport(runID: wrapper.runID, pid: getpid(), checkpoint: checkpoint, elapsedSeconds: budget.elapsed(),
            passed: failure == nil && closedAndClean, failureCode: failure, authenticationComplete: authenticationComplete, cleanupComplete: cleanupComplete,
            closedAndClean: closedAndClean, localStoreRemoved: storeRemoved, a: a?.lifecycle, b: b?.lifecycle, isolation: isolation,
            aKeyboard: a?.keyboard.map(AppMFAKIFacts.init), bKeyboard: b?.keyboard.map(AppMFAKIFacts.init), managementA: a?.status, managementB: b?.status,
            sourceKeyUnchanged: sourceUnchanged, fixtureKnownHostsUnchanged: knownUnchanged, approvedPinUnchanged: pinUnchanged, credentialCalls: credentialCalls,
            descriptors: .init(snapshots), descriptorIdentityMatched: fdMatched, registryBaselineActive: registryActive, registryBaselineRetired: registryRetired,
            registryAfterActive: SessionRetirementRegistry.shared.activeCount, registryAfterRetired: SessionRetirementRegistry.shared.retiredCount, quit: quit), leaf: leaf)
    }
}
#endif
