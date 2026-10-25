import Darwin
import Foundation
import OpenLXSSHTrust

/// XCTest-only executable. SwiftPM synthesizes a standalone product for executable targets,
/// but this target is not in the library product graph and must never be packaged in the App.
@main
struct OpenLXSSHTrustTestFixture {
    static func main() async throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        switch arguments.first {
        case "--test-only-store-writer" where arguments.count == 3:
            try await writeFixture(directory: AbsolutePath(arguments[1]), address: HostAddress(arguments[2]))
        case "--echo":
            try write(Data("fixture-ready\n".utf8))
            while true {
                var buffer = [UInt8](repeating: 0, count: 1024)
                let count = Darwin.read(STDIN_FILENO, &buffer, buffer.count)
                if count == 0 { break }
                if count < 0 {
                    if errno == EINTR { continue }
                    _exit(3)
                }
                try write(Data(buffer.prefix(count)))
            }
        case "--ignore-term" where arguments.count == 2:
            signal(SIGTERM, SIG_IGN)
            try recordPID(arguments[1])
            while true { usleep(10_000) }
        case "--flood" where arguments.count == 2:
            try recordPID(arguments[1])
            while true { try write(Data(repeating: 65, count: 4096)) }
        case "--close-input" where arguments.count == 2:
            close(STDIN_FILENO)
            try recordPID(arguments[1])
            while true { usleep(10_000) }
        case "--exit" where arguments.count == 2:
            try recordPID(arguments[1])
            _exit(7)
        default:
            _exit(64)
        }
    }

    private static func recordPID(_ path: String) throws {
        try Data(String(getpid()).utf8).write(to: URL(fileURLWithPath: path))
    }

    private static func write(_ data: Data) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(STDOUT_FILENO, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw HostTrustError.publicKeyToolFailed }
                offset += count
            }
        }
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
