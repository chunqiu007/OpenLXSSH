import Darwin
import Foundation
@testable import OpenLXSSHTrust
import XCTest

final class BoundedToolRunnerTests: XCTestCase {
    private var fixture: String {
        Bundle(for: BoundedToolRunnerTests.self).bundleURL.deletingLastPathComponent()
            .appendingPathComponent("OpenLXSSHTrustTestFixture").path
    }

    func testLargeInputAndOutputArePumpedWithoutPipeDeadlock() throws {
        let input = Data((0..<131_072).map { UInt8($0 % 251) })
        let result = try BoundedToolRunner.run(executable: fixture, arguments: ["--echo"],
            input: input, timeout: .seconds(3), outputLimit: input.count + 14)
        XCTAssertTrue(result.exitedSuccessfully)
        XCTAssertEqual(result.output, Data("fixture-ready\n".utf8) + input)
    }

    func testTimeoutEscalatesIgnoringTERMChildAndReapsIt() throws {
        let directory = try TemporaryDirectory()
        let pidFile = directory.file("pid")
        let start = ContinuousClock.now
        XCTAssertThrowsError(try BoundedToolRunner.run(executable: fixture,
            arguments: ["--ignore-term", pidFile.path], input: Data(), timeout: .milliseconds(200))) {
            XCTAssertEqual($0 as? BoundedToolRunner.Failure, .timedOut)
        }
        XCTAssertLessThan(start.duration(to: .now), .seconds(2))
        try assertAlreadyReaped(pidFile)
    }

    func testOutputLimitTerminatesAndReapsFloodingChild() throws {
        let directory = try TemporaryDirectory()
        let pidFile = directory.file("pid")
        let start = ContinuousClock.now
        XCTAssertThrowsError(try BoundedToolRunner.run(executable: fixture,
            arguments: ["--flood", pidFile.path], input: Data(), timeout: .seconds(2), outputLimit: 128)) {
            XCTAssertEqual($0 as? BoundedToolRunner.Failure, .outputLimit)
        }
        XCTAssertLessThan(start.duration(to: .now), .seconds(2))
        try assertAlreadyReaped(pidFile)
    }

    func testClosedInputReportsEPIPEWithoutSIGPIPEOrLeakedChild() throws {
        let directory = try TemporaryDirectory()
        let pidFile = directory.file("pid")
        XCTAssertThrowsError(try BoundedToolRunner.run(executable: fixture,
            arguments: ["--close-input", pidFile.path], input: Data(repeating: 65, count: 131_072),
            timeout: .seconds(2))) {
            XCTAssertEqual($0 as? BoundedToolRunner.Failure, .io(EPIPE))
        }
        try assertAlreadyReaped(pidFile)
    }

    func testNonzeroExitIsReturnedAfterSoleWaiterReap() throws {
        let directory = try TemporaryDirectory()
        let pidFile = directory.file("pid")
        let result = try BoundedToolRunner.run(executable: fixture,
            arguments: ["--exit", pidFile.path], input: Data())
        XCTAssertFalse(result.exitedSuccessfully)
        XCTAssertEqual(result.waitStatus, 7 << 8)
        try assertAlreadyReaped(pidFile)
    }

    func testLaunchFailureAndRepeatedTimeoutsReleaseDescriptors() throws {
        let directory = try TemporaryDirectory()
        let baseline = descriptors()
        XCTAssertThrowsError(try BoundedToolRunner.run(executable: "/OpenLXSSH-nonexistent-test-tool",
                                                     arguments: [], input: Data())) {
            XCTAssertEqual($0 as? BoundedToolRunner.Failure, .launch(ENOENT))
        }
        for index in 0..<12 {
            XCTAssertThrowsError(try BoundedToolRunner.run(executable: fixture,
                arguments: ["--ignore-term", directory.file("pid-\(index)").path], input: Data(),
                timeout: .milliseconds(40))) {
                XCTAssertEqual($0 as? BoundedToolRunner.Failure, .timedOut)
            }
        }
        XCTAssertEqual(descriptors(), baseline)
    }

    func testConcurrentSystemKeyParsesHaveIndependentWaitOwnership() async throws {
        try await withThrowingTaskGroup(of: HostPublicKey.self) { group in
            for _ in 0..<12 {
                group.addTask { try HostPublicKey(openSSHPublicKey: ed25519Fixture) }
            }
            for try await key in group {
                XCTAssertEqual(key.openSSH, ed25519Fixture)
            }
        }
    }

    func testMalformedRunnerInputIsRejectedBeforeSpawn() {
        for invocation in [("relative", []), ("/bin/true\0", []), ("/bin/true", ["bad\0argument"])] {
            XCTAssertThrowsError(try BoundedToolRunner.run(executable: invocation.0,
                arguments: invocation.1, input: Data())) {
                XCTAssertEqual($0 as? BoundedToolRunner.Failure, .invalidInput)
            }
        }
    }

    private func assertAlreadyReaped(_ file: URL, filePath: StaticString = #filePath, line: UInt = #line) throws {
        let pidText = try String(contentsOf: file, encoding: .utf8)
        guard let identifier = pid_t(pidText), identifier > 0 else { return XCTFail("Missing child PID") }
        var status: Int32 = 0
        errno = 0
        XCTAssertEqual(waitpid(identifier, &status, WNOHANG), -1, file: filePath, line: line)
        XCTAssertEqual(errno, ECHILD, "Runner must already have reaped its child", file: filePath, line: line)
        // Never signal/check liveness by PID here: it may already have been reused after reap.
    }

    private func descriptors() -> Set<Int32> {
        Set((0..<1024).compactMap { fcntl(Int32($0), F_GETFD) < 0 ? nil : Int32($0) })
    }
}
