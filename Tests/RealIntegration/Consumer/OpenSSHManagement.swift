import COpenLXSSHAskpass
import Darwin
import Foundation
import RealIntegrationCore

/// Root fixture variant of MinaManagement. Same reviewed production tool owner;
/// only fixed UID0 management files/argv, no caller-selected commands or paths.
final class OpenSSHManagement: @unchecked Sendable {
    let contract: OpenSSHContract
    private let executable = "/Applications/Docker.app/Contents/Resources/bin/docker"
    private let cancellation: OpaquePointer
    private let deadline: Double
    init(contract: OpenSSHContract, deadline: Double) throws {
        self.contract = contract; self.deadline = deadline
        var info = stat()
        guard lstat(executable, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o022 == 0,
              let raw = ap_cancel_create() else { throw OpenSSHError.managementFailed }
        cancellation = raw
    }
    deinit { ap_cancel_free(cancellation) }
    func cancel() { ap_cancel_set(cancellation) }
    private func run(_ args: [String], limit: Int = 131072) throws -> Data {
        let seconds = min(OpenSSHContract.managementSeconds, deadline - ProcessInfo.processInfo.systemUptime)
        guard seconds > 0 else { throw OpenSSHError.managementTimeout }
        let values = [executable] + args
        let envValues = ["PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=/var/empty", "DOCKER_CONFIG=" + NSHomeDirectory() + "/.docker"]
        let argv = values.map { $0.withCString { strdup($0) } } + [nil]
        let env = envValues.map { $0.withCString { strdup($0) } } + [nil]
        defer { (argv + env).forEach { free($0) } }
        guard (argv + env).compactMap({ $0 }).count == values.count + envValues.count else { throw OpenSSHError.managementFailed }
        var data = Data(count: limit), count = 0, status: Int32 = -1
        let rc = argv.withUnsafeBufferPointer { a in env.withUnsafeBufferPointer { e in data.withUnsafeMutableBytes { buffer in
            ap_tool(executable, UnsafeMutablePointer(mutating: a.baseAddress!), UnsafeMutablePointer(mutating: e.baseAddress!), cancellation,
                    seconds, 0, buffer.baseAddress, buffer.count, &count, &status)
        } } }
        guard rc == 0, status == 0 else {
            data.resetBytes(in: 0..<data.count)
            if rc == ETIMEDOUT { throw OpenSSHError.managementTimeout }
            if rc == ECANCELED { throw OpenSSHError.cancelled }
            throw OpenSSHError.managementFailed
        }
        data.count = count; return data
    }
    func verify() throws {
        guard let contexts = try JSONSerialization.jsonObject(with: run(["context", "inspect", contract.context])) as? [[String: Any]], contexts.count == 1,
              contexts[0]["Name"] as? String == contract.context, let endpoints = contexts[0]["Endpoints"] as? [String: [String: Any]],
              endpoints["docker"]?["Host"] as? String == contract.endpoint else { throw OpenSSHError.provenanceMismatch }
        try OpenSSHManagementPolicy.validateContainer(run(["--host", contract.endpoint, "inspect", contract.containerID]), contract: contract)
        try OpenSSHManagementPolicy.validateImage(run(["--host", contract.endpoint, "image", "inspect", contract.imageID]), contract: contract)
        try OpenSSHManagementPolicy.validateNetwork(run(["--host", contract.endpoint, "network", "inspect", contract.networkID]), contract: contract)
        try OpenSSHManagementPolicy.validatePolicy(run(OpenSSHManagementPolicy.arguments(contract: contract, session: nil, index: nil), limit: 4096), contract: contract)
    }
    func response(session: String, index: Int) throws -> OpenSSHOTP {
        var data = try run(OpenSSHManagementPolicy.arguments(contract: contract, session: session, index: index), limit: 4096)
        defer { data.resetBytes(in: 0..<data.count) }
        return try OpenSSHOTP.decode(data, session: session, index: index, now: Date().timeIntervalSince1970)
    }
    func sessionRemoved(_ session: String) throws -> Bool {
        let data = try run(OpenSSHManagementPolicy.arguments(contract: contract, session: session, index: nil, stateOnly: true), limit: 256)
        let object = try MinaJSON.object(data, keys: ["present"])
        return object["present"] as? Bool == false
    }
}
