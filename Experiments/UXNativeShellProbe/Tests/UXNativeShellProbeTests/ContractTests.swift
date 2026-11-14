import Foundation
import XCTest
@testable import UXNativeShellProbeSupport

final class ContractTests: XCTestCase {
    func testDefaultAndHelpAreInert() throws {
        XCTAssertEqual(try ShellProbeCommand.parse([]), .help)
        XCTAssertEqual(try ShellProbeCommand.parse(["--help"]), .help)
    }
    func testFourFixedFixtureTargetsValidateSyntaxOnly() throws {
        XCTAssertEqual(ShellProbeFixture.allCases.map(\.port), [22221, 22222, 22223, 22224])
        for fixture in ShellProbeFixture.allCases {
            XCTAssertEqual(try ShellProbeCommand.parse(["validate", "--fixture", fixture.rawValue]), .validate(fixture))
        }
    }
    func testNoLiveArbitraryEndpointCredentialsOrCommandsAccepted() {
        for arguments in [["live"], ["--run"], ["validate", "--host", "127.0.0.1"],
                          ["validate", "--fixture", "production"], ["validate", "--fixture", "keyonly", "--execute"],
                          ["--credentials", "/nonexistent"], ["validate", "--fixture", "keyonly;command"]] {
            XCTAssertThrowsError(try ShellProbeCommand.parse(arguments))
        }
    }
    func testLiveRequiresAllExplicitGatesAndExactPrivateGenerationPath() throws {
        let root = "/nonexistent/probe/.build", path = root + "/sftp-auth-case-012345abcdef/sftp-auth.json"
        let valid = ["--live", "--authorized-local-fixture", "--engine-ready", "--contract", path]
        XCTAssertEqual(try ShellProbeCommand.parse(valid, buildRoot: root), .live(contractPath: path))
        XCTAssertEqual(try ShellProbeCommand.parse(["validate", "--contract", path], buildRoot: root), .validateContract(path))
        for args in [["--live", "--contract", path], ["--live", "--engine-ready", "--contract", path],
                     ["--live", "--authorized-local-fixture", "--contract", path],
                     valid + ["--engine-ready"], valid + ["--contract", path], valid + ["--host", "127.0.0.1"],
                     ["validate", "--authorized-local-fixture", "--contract", path]] {
            XCTAssertThrowsError(try ShellProbeCommand.parse(args, buildRoot: root))
        }
        for bad in ["/etc/passwd", root + "/sftp-auth-case-latest/sftp-auth.json",
                    root + "/sftp-auth-case-012345ABCDEF/sftp-auth.json", root + "/sftp-auth-case-012345abcdef/../sftp-auth.json",
                    root + "/sftp-auth-case-012345abcdef/sftp-auth.json\n", root + "/sftp-auth-case-012345abcdef/other.json"] {
            XCTAssertThrowsError(try ShellProbeCommand.parse(["validate", "--contract", bad], buildRoot: root))
        }
    }
    func testStreamingEvidenceAcrossChunkBoundariesAndNoEchoFalsePositive() throws {
        let token = "0123456789abcdef"
        var evidence = ShellProbeEvidence(token: token)
        try evidence.consume(Data(("n='" + token + "'; printf 'NATIVE_ACK_%s\\n' \"$n\"\r\n").utf8))
        XCTAssertFalse(evidence.ack)
        try evidence.consume(Data("NATIVE_AC".utf8))
        try evidence.consume(Data(("K_" + token + "\r\nNATIVE_PTY_" + token + "\r\nNATIVE_SIZE_" + token + " 37 113\r\n").utf8))
        XCTAssertTrue(evidence.ack); XCTAssertTrue(evidence.pty); XCTAssertTrue(evidence.size)
    }
    func testOutputBytesAndChunkBoundsAreFinite() throws {
        var evidence = ShellProbeEvidence(token: "a")
        XCTAssertThrowsError(try evidence.consume(Data(count: 65537)))
        for _ in 0..<16 { try evidence.consume(Data(count: 65536)) }
        XCTAssertEqual(evidence.count, ShellProbeEvidence.maximumBytes)
        XCTAssertThrowsError(try evidence.consume(Data([1])))
    }
}
