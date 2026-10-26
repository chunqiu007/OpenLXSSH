import COpenLXSSHAskpass
import Darwin
import Foundation
import RealIntegrationCore

/// Reuses the production bounded, sole-waiter/PID-safe tool owner, not Process
/// polling or a shell. Only fixed local Docker metadata/reader argv are exposed.
final class MinaManagement: @unchecked Sendable {
    let contract: MinaContract
    private let executable = "/Applications/Docker.app/Contents/Resources/bin/docker"
    private let cancellation: OpaquePointer
    init(contract: MinaContract) throws {
        self.contract = contract
        var info = stat()
        guard lstat(executable, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o022 == 0, info.st_mode & 0o111 != 0,
              let cancel = ap_cancel_create() else { throw MinaError.managementFailed }
        cancellation = cancel
    }
    deinit { ap_cancel_free(cancellation) }
    func cancel() { ap_cancel_set(cancellation) }
    private func run(_ arguments: [String], limit: Int = 131072, seconds: Double = MinaContract.managementSeconds) throws -> Data {
        guard seconds.isFinite, seconds > 0, seconds <= MinaContract.managementSeconds else { throw MinaError.managementTimeout }
        let argumentStrings = [executable] + arguments
        let environmentStrings = ["PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=/var/empty", "DOCKER_CONFIG=" + NSHomeDirectory() + "/.docker"]
        let argv = argumentStrings.map { $0.withCString { strdup($0) } } + [nil]
        let env = environmentStrings.map { $0.withCString { strdup($0) } } + [nil]
        defer { (argv + env).forEach { free($0) } }
        guard (argv + env).filter({ $0 != nil }).count == argumentStrings.count + environmentStrings.count else { throw MinaError.managementFailed }
        var bytes = Data(count: limit), count = 0, status: Int32 = -1
        let rc = argv.withUnsafeBufferPointer { args in env.withUnsafeBufferPointer { environment in
            bytes.withUnsafeMutableBytes { output in
                ap_tool(executable, UnsafeMutablePointer(mutating: args.baseAddress!), UnsafeMutablePointer(mutating: environment.baseAddress!),
                        cancellation, seconds, 0, output.baseAddress, output.count, &count, &status)
            }
        } }
        guard rc == 0, status == 0 else {
            bytes.resetBytes(in: 0..<bytes.count)
            if rc == ETIMEDOUT { throw MinaError.managementTimeout }
            if rc == ECANCELED { throw MinaError.managementCancelled }
            throw MinaError.managementFailed
        }
        bytes.count = count
        return bytes // stdout stays in memory only; stderr was /dev/null.
    }
    func verify() throws {
        let route = try run(["context", "inspect", contract.context])
        guard let contexts = try JSONSerialization.jsonObject(with: route) as? [[String: Any]], contexts.count == 1,
              contexts[0]["Name"] as? String == contract.context,
              let endpoints = contexts[0]["Endpoints"] as? [String: [String: Any]],
              endpoints["docker"]?["Host"] as? String == contract.endpoint else { throw MinaError.provenanceMismatch }
        try MinaManagementPolicy.validateContainer(run(["--host", contract.endpoint, "inspect", contract.containerID]), contract: contract)
        try MinaManagementPolicy.validateImage(run(["--host", contract.endpoint, "image", "inspect", contract.imageID]), contract: contract)
        try MinaManagementPolicy.validateNetwork(run(["--host", contract.endpoint, "network", "inspect", contract.networkID]), contract: contract)
    }
    func verifyPolicy() throws {
        try MinaManagementPolicy.validatePolicy(run(MinaManagementPolicy.policyArguments(contract: contract), limit: 128), testCase: contract.testCase)
    }
    func status(deadline: Double? = nil) throws -> MinaStatus {
        let remaining = deadline.map { $0 - ProcessInfo.processInfo.systemUptime } ?? MinaContract.managementSeconds
        return try MinaStatus.decode(run(MinaManagementPolicy.readerArguments(contract: contract, attempt: nil), limit: 8192,
                                         seconds: min(MinaContract.managementSeconds, remaining)))
    }
    func responses(attempt: String) throws -> MinaResponses {
        // Recheck exact ownership on this single secret-bearing read; no retry,
        // cross-attempt fallback, host temporary file, tar extraction or stdout.
        try MinaManagementPolicy.validateContainer(run(["--host", contract.endpoint, "inspect", contract.containerID]), contract: contract)
        var data = try run(MinaManagementPolicy.readerArguments(contract: contract, attempt: attempt), limit: 8192)
        defer { data.resetBytes(in: 0..<data.count) }
        return try MinaResponses.decode(data, attempt: attempt, now: Date().timeIntervalSince1970)
    }
}
