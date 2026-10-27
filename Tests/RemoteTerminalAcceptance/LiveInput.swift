import CryptoKit
import Darwin
import Foundation
import OpenLXSSHTrust
import COpenLXSSHAskpass
import RealIntegrationPOSIX
import RemoteTerminalCore

// Reuse the reviewed descriptor/ACL reader as a read-only compiled dependency.
enum OwnedInput {
    static func openPrivate(_ path: String, directory: Bool) throws -> Int32 {
        try Syntax.path(path)
        let fd = ri_open_private(path, directory ? 1 : 0)
        guard fd >= 0 else { throw TerminalCheckError.unsafeFile }
        return fd
    }
    static func read(_ path: String, limit: Int) throws -> Data {
        guard (1...65536).contains(limit) else { throw TerminalCheckError.unsafeFile }
        let fd = try openPrivate(path, directory: false); defer { Darwin.close(fd) }
        var data = Data(count: limit + 1), total = 0
        while total < data.count {
            let count = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: total), $0.count - total) }
            if count == 0 { break }
            if count < 0 { if errno == EINTR { continue }; throw TerminalCheckError.unsafeFile }
            total += count
        }
        guard total <= limit else { throw TerminalCheckError.unsafeFile }; data.count = total; return data
    }
    static func write(_ data: Data, path: String) throws {
        try Syntax.path(path)
        let fd = ri_create_private(path)
        guard fd >= 0 else { throw TerminalCheckError.unsafeFile }; defer { Darwin.close(fd) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw TerminalCheckError.unsafeFile }; offset += count
        }
        guard fsync(fd) == 0 else { throw TerminalCheckError.unsafeFile }
    }
    static func directory(_ path: String) throws {
        let fd = try openPrivate(path, directory: true); Darwin.close(fd)
    }
}

struct LiveInput: Sendable {
    let contract: TerminalContract
    let key: HostPublicKey
    let privateKeyPath: AbsolutePath
    static func load(path: String) throws -> Self {
        // Syntax/fixed-generation path must be rejected before any caller-selected file opens.
        try Syntax.path(path)
        let prefix = BuildLocation.ownRoot + "/.runtime/case-", suffix = "/remote-terminal.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix), Syntax.hex(String(path.dropFirst(prefix.count).dropLast(suffix.count)), 12) else { throw TerminalCheckError.contract }
        let bytes = try OwnedInput.read(path, limit: 8192)
        _ = try Syntax.object(bytes, keys: TerminalContract.keys)
        let contract = try JSONDecoder().decode(TerminalContract.self, from: bytes)
        try contract.validate(path: path, ownRoot: BuildLocation.ownRoot, fixtureRoot: BuildLocation.fixtureRoot, home: NSHomeDirectory(), now: Date().timeIntervalSince1970)
        for folder in [BuildLocation.ownRoot + "/.runtime", (path as NSString).deletingLastPathComponent,
                       BuildLocation.fixtureRoot + "/.runtime", BuildLocation.fixtureRoot + "/.runtime/keyonly", contract.credentialDirectory] { try OwnedInput.directory(folder) }
        let state = try Syntax.object(OwnedInput.read(BuildLocation.fixtureRoot + "/.runtime/state.json", limit: 4096), keys: ["version", "project", "image"])
        guard state["version"] as? Int == 1, state["project"] as? String == contract.project, state["image"] as? String == contract.baseImage else { throw TerminalCheckError.provenance }
        let provenance = try Syntax.object(OwnedInput.read(contract.credentialDirectory + "/provenance.json", limit: 4096), keys: ["base_image", "built_image_id", "service", "collected_at"])
        guard provenance["base_image"] as? String == contract.baseImage, provenance["built_image_id"] as? String == contract.imageID,
              provenance["service"] as? String == "keyonly", provenance["collected_at"] as? Double == contract.collectedAt else { throw TerminalCheckError.provenance }
        let line = String(decoding: try OwnedInput.read(contract.credentialDirectory + "/known_hosts", limit: 4096), as: UTF8.self)
        let fields = line.dropLast().split(separator: " ", omittingEmptySubsequences: false)
        guard line.hasSuffix("\n"), !line.dropLast().contains("\n"), fields.count == 3, fields[0] == "[127.0.0.1]:22221", fields[1] == "ssh-ed25519" else { throw TerminalCheckError.contract }
        let key = try HostPublicKey(algorithm: String(fields[1]), base64: String(fields[2]))
        let exported = String(decoding: try OwnedInput.read(contract.credentialDirectory + "/fingerprint.txt", limit: 1024), as: UTF8.self).split(whereSeparator: { $0.isWhitespace })
        guard key.fingerprint == contract.expectedFingerprint, exported.count >= 2, exported[1] == Substring(key.fingerprint) else { throw TerminalCheckError.provenance }
        // Live-only: verify the exact disposable private key's safe path and non-empty bytes.
        // System OpenSSH opens this same stable path; no public-key-only authentication claim.
        var secret = try OwnedInput.read(contract.credentialDirectory + "/id_ed25519", limit: 32768)
        defer { secret.resetBytes(in: 0..<secret.count) }
        guard !secret.isEmpty else { throw TerminalCheckError.unsafeFile }
        _ = try OwnedInput.read(contract.credentialDirectory + "/id_ed25519.pub", limit: 4096)
        return Self(contract: contract, key: key, privateKeyPath: try AbsolutePath(contract.credentialDirectory + "/id_ed25519"))
    }
}

// Fixed management metadata only. Does not collect credentials or inspect terminal output.
enum LiveMetadata {
    static func verify(_ contract: TerminalContract) throws {
        let executable = "/Applications/Docker.app/Contents/Resources/bin/docker"
        for (args, kind) in [(["context", "inspect", contract.context], "context"),
                             (["--host", contract.endpoint, "inspect", contract.containerID], "container"),
                             (["--host", contract.endpoint, "image", "inspect", contract.imageID], "image"),
                             (["--host", contract.endpoint, "network", "inspect", contract.networkID], "network")] {
            let values = [executable] + args
            let environment = ["PATH=/usr/bin:/bin", "LC_ALL=C", "DOCKER_CONFIG=" + NSHomeDirectory() + "/.docker"]
            let argv = values.map { strdup($0) } + [nil], env = environment.map { strdup($0) } + [nil]
            defer { (argv + env).forEach { free($0) } }
            guard let cancel = ap_cancel_create() else { throw TerminalCheckError.provenance }
            defer { ap_cancel_free(cancel) }
            var output = Data(count: 131072), count = 0, status: Int32 = -1
            let rc = argv.withUnsafeBufferPointer { a in env.withUnsafeBufferPointer { e in output.withUnsafeMutableBytes { bytes in
                ap_tool(executable, UnsafeMutablePointer(mutating: a.baseAddress!), UnsafeMutablePointer(mutating: e.baseAddress!), cancel, 10, 0, bytes.baseAddress, bytes.count, &count, &status)
            } } }
            guard rc == 0, status == 0 else { throw TerminalCheckError.provenance }; output.count = count
            if kind == "image" { try Syntax.validateImage(output, contract: contract); continue }
            guard let objects = try JSONSerialization.jsonObject(with: output) as? [[String: Any]], objects.count == 1 else { throw TerminalCheckError.provenance }
            let item = objects[0]
            if kind == "context" {
                guard item["Name"] as? String == contract.context, let endpoints = item["Endpoints"] as? [String: [String: Any]], endpoints["docker"]?["Host"] as? String == contract.endpoint else { throw TerminalCheckError.provenance }
                continue
            }
            let config = item["Config"] as? [String: Any]
            guard let labels = (kind == "network" ? item["Labels"] : config?["Labels"]) as? [String: String],
                  labels["org.openlxssh.fixture"] == "env-fixture-a" else { throw TerminalCheckError.provenance }
            if kind != "image", labels["com.docker.compose.project"] != contract.project { throw TerminalCheckError.provenance }
            switch kind {
            case "container":
                guard item["Id"] as? String == contract.containerID, item["Image"] as? String == contract.imageID,
                      labels["com.docker.compose.service"] == "keyonly", let state = item["State"] as? [String: Any], state["Running"] as? Bool == true,
                      let health = state["Health"] as? [String: Any], health["Status"] as? String == "healthy",
                      let host = item["HostConfig"] as? [String: Any], host["ReadonlyRootfs"] as? Bool == true, host["Privileged"] as? Bool == false,
                      let log = host["LogConfig"] as? [String: Any], log["Type"] as? String == "none",
                      let ports = host["PortBindings"] as? [String: [[String: String]]], ports == ["2222/tcp": [["HostIp": "127.0.0.1", "HostPort": "22221"]]],
                      let net = item["NetworkSettings"] as? [String: Any], let networks = net["Networks"] as? [String: [String: Any]], networks.count == 1,
                      networks.values.first?["NetworkID"] as? String == contract.networkID else { throw TerminalCheckError.provenance }
                try Syntax.validateMounts(binds: host["Binds"], mounts: item["Mounts"], project: contract.project)
            case "image": guard item["Id"] as? String == contract.imageID, item["Architecture"] as? String == "arm64", item["Os"] as? String == "linux", labels["org.openlxssh.fixture.base"] == contract.baseImage else { throw TerminalCheckError.provenance }
            case "network": guard item["Id"] as? String == contract.networkID, item["Internal"] as? Bool == true, item["Driver"] as? String == "bridge",
                                  let containers = item["Containers"] as? [String: Any], containers[contract.containerID] != nil else { throw TerminalCheckError.provenance }
            default: throw TerminalCheckError.provenance
            }
        }
    }
}
