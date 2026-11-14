import Foundation
import XCTest
@testable import UXNativeShellProbeSupport

/// Offline protocol refusal tests only; synthetic control/proof values never count as SSH proof.
final class LivenessControlTests: XCTestCase {
    func testDefaultAndExplicitCLIFlagsAreClosedAndInert() throws {
        let root = "/offline/.build", path = root + "/native-liveness-case-012345abcdef/liveness.json"
        XCTAssertNil(try NativeLivenessOptions.parse([], buildRoot: root).contractPath)
        let args = ["--live-native-liveness", "--authorized-local-fixture", "--primary-reviewed", "--contract", path,
                    "--owner-pid", "1234", "--private-pipes"]
        XCTAssertEqual(try NativeLivenessOptions.parse(args, buildRoot: root).ownerPID, 1234)
        for invalid in [Array(args.dropLast()), args + ["--host", "127.0.0.1"],
                        ["--live-native-liveness", "--contract", path], ["--key", "/etc/passwd"]] {
            XCTAssertThrowsError(try NativeLivenessOptions.parse(invalid, buildRoot: root))
        }
    }
    func testJSONRejectsDuplicateFieldsEscapesNestingAndBooleanIntegers() throws {
        let keys: Set<String> = ["op", "sequence", "ok"]
        let good = try NativeLivenessJSON.object(Data("{\"op\":\"ack\",\"sequence\":1,\"ok\":true}\n".utf8), keys: keys)
        XCTAssertEqual(NativeLivenessJSON.integer(good["sequence"]), 1)
        XCTAssertEqual(NativeLivenessJSON.boolean(good["ok"]), true)
        XCTAssertNil(NativeLivenessJSON.integer(good["ok"]))
        XCTAssertNil(NativeLivenessJSON.boolean(good["sequence"]))
        for text in ["{\"op\":\"ack\",\"sequence\":1,\"sequence\":2,\"ok\":true}",
                     "{\"op\":{\"value\":1},\"sequence\":1,\"ok\":true}",
                     "{\"op\":\"a\\u0063k\",\"sequence\":1,\"ok\":true}",
                     "{\"op\":\"ack\",\"sequence\":1,\"ok\":true}\n{}\n"] {
            XCTAssertThrowsError(try NativeLivenessJSON.object(Data(text.utf8), keys: keys))
        }
    }
    func testPrettyContractWhitespaceDoesNotRelaxPrivatePipeFrame() throws {
        let keys: Set<String> = ["op", "sequence", "ok"]
        let pretty = Data("{\n  \"op\": \"ack\",\n  \"sequence\": 1,\n  \"ok\": true\n}\n".utf8)
        XCTAssertEqual(try NativeLivenessJSON.object(pretty, keys: keys)["op"] as? String, "ack")
        XCTAssertThrowsError(try NativeLivenessJSON.frameObject(pretty, keys: keys))
        let frame = Data("{\"op\":\"ack\",\"sequence\":1,\"ok\":true}\n".utf8)
        XCTAssertEqual(try NativeLivenessJSON.frameObject(frame, keys: keys)["op"] as? String, "ack")
        XCTAssertThrowsError(try NativeLivenessJSON.frameObject(frame + Data([10]), keys: keys))
        XCTAssertThrowsError(try NativeLivenessJSON.frameObject(Data(frame.dropLast()), keys: keys))
    }
    func testProofRequiresEveryConfirmedHelperFreedAndRejectedStillAlive() {
        XCTAssertTrue(NativeLivenessProof(started: 2, confirmed: 2, rejected: 0, freed: 2, helpers: 0, pending: false).settled)
        XCTAssertTrue(NativeLivenessProof(started: 2, confirmed: 0, rejected: 2, freed: 0, helpers: 0, pending: false).settled)
        XCTAssertFalse(NativeLivenessProof(started: 2, confirmed: 2, rejected: 0, freed: 1, helpers: 1, pending: true).settled)
        XCTAssertFalse(NativeLivenessProof(started: 3, confirmed: 2, rejected: 0, freed: 2, helpers: 0, pending: false).settled)
    }
    func testReplySequenceIsBoundToRunRoleSessionAndMonotonicOrder() throws {
        let run = String(repeating: "a", count: 32), session = UUID().uuidString.lowercased()
        var sequence = NativeLivenessControlSequence(run: run, role: .blackhole, session: session)
        try sequence.accept(op: "binding-confirmed", sequence: 1, run: run, role: .blackhole, session: session, stamp: 100)
        XCTAssertThrowsError(try sequence.accept(op: "binding-confirmed", sequence: 1, run: run, role: .blackhole, session: session, stamp: 101))
        XCTAssertThrowsError(try sequence.accept(op: "drop-confirmed", sequence: 2, run: run, role: .blackhole, session: UUID().uuidString, stamp: 101))
        XCTAssertThrowsError(try sequence.accept(op: "drop-confirmed", sequence: 2, run: run, role: .blackhole, session: session, stamp: 99))
        try sequence.accept(op: "drop-confirmed", sequence: 2, run: run, role: .blackhole, session: session, stamp: 101)
        try sequence.accept(op: "result-recorded", sequence: 3, run: run, role: .blackhole, session: session, stamp: 102)
    }
    func testActualArmAgeUsesCausalBoundsAndRejectsStaleOrMissingOrder() throws {
        let evidence = try NativeLivenessArmAge(proofLower: 100, proofUpper: 100.01,
            consumerSent: 100.02, consumerACK: 100.2, relayArmed: 50.1, relayReply: 50.11)
        XCTAssertGreaterThanOrEqual(evidence.minimumAge, 0)
        XCTAssertLessThanOrEqual(evidence.maximumAge, 1.5)
        XCTAssertThrowsError(try NativeLivenessArmAge(proofLower: 98, proofUpper: 100.01,
            consumerSent: 100.02, consumerACK: 100.2, relayArmed: 50.1, relayReply: 50.11))
        XCTAssertThrowsError(try NativeLivenessArmAge(proofLower: 100.02, proofUpper: 100.01,
            consumerSent: 100.03, consumerACK: 100.2, relayArmed: 50.1, relayReply: 50.11))
        XCTAssertThrowsError(try NativeLivenessArmAge(proofLower: 100, proofUpper: 100.01,
            consumerSent: 100.02, consumerACK: 100.03, relayArmed: 50.1, relayReply: 51))
    }
    func testClockRejectsStaleACKWallDisagreementAndNegativeTransit() throws {
        let evidence = try NativeLivenessClockEvidence(armedAt: 100, armedWall: 1000, relayNow: 100.1,
            relayWall: 1000.1, localNow: 103.2, localWall: 1000.2)
        XCTAssertEqual(evidence.elapsedAtACK, 0.2, accuracy: 0.00001)
        XCTAssertThrowsError(try NativeLivenessClockEvidence(armedAt: 100, armedWall: 1000, relayNow: 100.1,
            relayWall: 1000.1, localNow: 103, localWall: 999))
        XCTAssertThrowsError(try NativeLivenessClockEvidence(armedAt: 100, armedWall: 1000, relayNow: 101,
            relayWall: 1000.1, localNow: 103, localWall: 1000.2))
        XCTAssertThrowsError(try NativeLivenessClockEvidence(armedAt: 100, armedWall: 1000, relayNow: 100.1,
            relayWall: 1000.1, localNow: 110, localWall: 1005))
    }
}
