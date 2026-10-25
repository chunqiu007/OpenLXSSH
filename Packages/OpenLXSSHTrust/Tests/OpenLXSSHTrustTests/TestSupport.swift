import Darwin
import Foundation
@testable import OpenLXSSHTrust
import XCTest

let ed25519Fixture = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg"
let changedFixture = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C"
let rsaFixture = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtEucvt1w5resIpf/BvuuR1zddYXDeUVM0LOZt8mis3XGozl6xpF3V3jkVOfXM1oaq0faq2MKnzxCZx4GmlofE4qdcMqa4cbL7QTNvO/Z6ACTTb92kpNp9DS/4BSLsIebvMM0UVWivxmj3Mq3REqIThBXQVwqkhmWj6bzfSKqsstCjjRmRuzi/IDCUL8lIbJGzpYek4/cp5VhUyB2kIYqz/Fpg5+eJTa2x/7qYEKNKg4dXebuExQYe3Z47D8o1i9pDXWpYw/KlBn8LA/K89h7BkEsdY4ePPGroTS+lepAKqItDWwMm4wf6gDJSoNbCt6T+L5U7gjpbA3kEZd89PxvJ"

final class TemporaryDirectory {
    let url: URL
    var path: AbsolutePath { get throws { try AbsolutePath(url.path) } }
    init(name: String = "OpenLXSSH-tests-") throws {
        url = FileManager.default.temporaryDirectory.appendingPathComponent(name + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
    }
    deinit { try? FileManager.default.removeItem(at: url) }
    func file(_ name: String) -> URL { url.appendingPathComponent(name) }
}

struct ToolResult {
    let status: Int32
    let output: String
    let error: String
}

func runTool(_ executable: String, _ arguments: [String], input: Data? = nil,
             environment: [String: String] = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]) throws -> ToolResult {
    let process = Process()
    let output = Pipe()
    let error = Pipe()
    let inputPipe = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.environment = environment
    process.standardInput = input == nil ? FileHandle.nullDevice : inputPipe
    process.standardOutput = output
    process.standardError = error
    try process.run()
    if let input {
        try inputPipe.fileHandleForWriting.write(contentsOf: input)
        try inputPipe.fileHandleForWriting.close()
    }
    let stdout = output.fileHandleForReading.readDataToEndOfFile()
    let stderr = error.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return ToolResult(status: process.terminationStatus,
                      output: String(decoding: stdout, as: UTF8.self),
                      error: String(decoding: stderr, as: UTF8.self))
}

func host(_ address: String = "server.example", port: Int = 22) throws -> HostIdentity {
    HostIdentity(address: try HostAddress(address), port: try SSHPort(port))
}

func pendingDecision(_ evaluation: HostTrustEvaluation, file: StaticString = #filePath,
                     line: UInt = #line) throws -> PendingTrustDecision {
    guard case .pending(let decision) = evaluation else {
        XCTFail("Expected an explicit pending decision", file: file, line: line)
        throw HostTrustError.expiredDecision
    }
    return decision
}

@discardableResult
func accept(_ store: HostTrustStore, _ host: HostIdentity, _ key: HostPublicKey) async throws -> TrustedHostKey {
    let decision = try pendingDecision(try await store.evaluate(host: host, key: key))
    return try await store.confirm(decision, displayedFingerprint: decision.fingerprint)
}

@MainActor
func assertAsyncError<T>(_ expected: HostTrustError, file: StaticString = #filePath, line: UInt = #line,
                         _ operation: @MainActor () async throws -> T) async {
    do {
        _ = try await operation()
        XCTFail("Expected \(expected)", file: file, line: line)
    } catch {
        XCTAssertEqual(error as? HostTrustError, expected, file: file, line: line)
    }
}
