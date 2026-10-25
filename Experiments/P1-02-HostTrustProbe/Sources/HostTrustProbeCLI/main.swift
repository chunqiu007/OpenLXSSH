import Darwin
import Foundation
import OpenLXSSHHostTrustProbe

@main
struct HostTrustProbeCLI {
    static func main() async throws {
        // Used only by local multi-process storage tests; cannot connect to a server.
        if CommandLine.arguments.count == 4, CommandLine.arguments[1] == "--test-only-store-writer" {
            try await writeFixture(directory: AbsolutePath(CommandLine.arguments[2]),
                                   address: HostAddress(CommandLine.arguments[3]))
            return
        }
        guard CommandLine.arguments == [CommandLine.arguments[0], "--self-test"] else {
            print("Usage: p1-host-trust-probe --self-test (local files and ssh -G only; no connection)")
            return
        }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-P1-02-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try AbsolutePath(root.path)
        let store = try HostTrustStore(directory: directory)
        let host = HostIdentity(address: try HostAddress("2001:db8::1"), port: try SSHPort(2222))
        let key = try HostPublicKey(openSSHPublicKey:
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg")
        let changed = try HostPublicKey(openSSHPublicKey:
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C")
        guard case .pending(let cancelled) = try await store.evaluate(host: host, key: key) else {
            throw HostTrustError.corruptStorage
        }
        await store.cancel(cancelled)
        guard try await store.records().isEmpty else { throw HostTrustError.corruptStorage }
        guard case .pending(let decision) = try await store.evaluate(host: host, key: key) else {
            throw HostTrustError.corruptStorage
        }
        print("Synthetic explicit confirmation: \(decision.host.knownHostsName) \(decision.algorithm) \(decision.fingerprint)")
        try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
        guard case .trusted = try await store.evaluate(host: host, key: key),
              case .rejected = try await store.evaluate(host: host, key: changed) else {
            throw HostTrustError.corruptStorage
        }
        let configuration = ControlledSSHConfiguration(
            connection: SSHConnection(host: host, user: try SSHUser("probe-user")),
            trustStore: store)
        let prepared = try configuration.write(in: directory)
        let invocation = prepared.invocation(preview: true)
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: invocation.executable)
        process.arguments = invocation.arguments
        process.environment = invocation.environment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let result = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0,
              let text = String(data: result, encoding: .utf8),
              text.contains("hostname 2001:db8::1\n"), text.contains("port 2222\n"),
              text.contains("stricthostkeychecking true\n"), text.contains("forwardagent no\n") else {
            throw HostTrustError.publicKeyToolFailed
        }
        print("PASS: cancel leaves no record; explicit trust; exact match; changed key rejected; isolated ssh -G")
        print("Not verified: SSH/SFTP handshake, authentication, macOS 26 runtime or product AC-12")
    }

    private static func writeFixture(directory: AbsolutePath, address: HostAddress) async throws {
        let store = try HostTrustStore(directory: directory)
        let identity = HostIdentity(address: address, port: try SSHPort(2222))
        let key = try HostPublicKey(openSSHPublicKey:
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg")
        for _ in 0..<32 {
            guard case .pending(let decision) = try await store.evaluate(host: identity, key: key) else {
                throw HostTrustError.storageChanged
            }
            do {
                try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
                return
            } catch HostTrustError.storageChanged { continue }
        }
        throw HostTrustError.storageChanged
    }
}
