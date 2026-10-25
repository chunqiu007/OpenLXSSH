import CRemoteFileBridge
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHRemoteFileProbe

/// These call only the actual callback adapter with memory structures, not a fake SSH session/server.
final class KeyboardCallbackTests: XCTestCase {
    private func withConnection<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        var sockets: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { sockets.forEach { Darwin.close($0) } }
        let c = try XCTUnwrap(rf_connection_create(sockets[0]))
        defer { rf_connection_destroy(c) }
        return try body(c)
    }
    func testMultiplePromptsPreserveBytesAndUseUserAnswersOnly() throws {
        try withConnection { c in
            let answers = [Data(UUID().uuidString.utf8), Data(UUID().uuidString.utf8) + Data([0])]
            let context = KeyboardContext(connection: c, handler: { challenge, reply in
                XCTAssertEqual(challenge.name, Data("fixture".utf8))
                XCTAssertEqual(challenge.instruction, Data("manual".utf8))
                XCTAssertEqual(challenge.prompts.map(\.bytes), [Data("Password?".utf8), Data("OTP?".utf8)])
                XCTAssertEqual(challenge.prompts.map(\.echo), [false, true])
                reply.resolve(answers)
            }, token: CancellationToken(), timeout: 0.3)
            let p1 = strdup("Password?")!; let p2 = strdup("OTP?")!
            defer { free(p1); free(p2) }
            let prompts = [
                LIBSSH2_USERAUTH_KBDINT_PROMPT(text: UnsafeMutableRawPointer(p1).assumingMemoryBound(to: UInt8.self), length: 9, echo: 0),
                LIBSSH2_USERAUTH_KBDINT_PROMPT(text: UnsafeMutableRawPointer(p2).assumingMemoryBound(to: UInt8.self), length: 4, echo: 1)
            ]
            var responses = [LIBSSH2_USERAUTH_KBDINT_RESPONSE(), LIBSSH2_USERAUTH_KBDINT_RESPONSE()]
            let rc = prompts.withUnsafeBufferPointer { promptPtr in responses.withUnsafeMutableBufferPointer { responsePtr in
                context.answer(name: "fixture", nameLength: 7, instruction: "manual", instructionLength: 6,
                               count: 2, prompts: promptPtr.baseAddress, responses: responsePtr.baseAddress)
            } }
            XCTAssertEqual(rc, 0)
            XCTAssertTrue(Data(bytes: try XCTUnwrap(responses[0].text), count: Int(responses[0].length)) == answers[0])
            XCTAssertTrue(Data(bytes: try XCTUnwrap(responses[1].text), count: Int(responses[1].length)) == answers[1])
            // Native tracked allocations are wiped/reclaimed by connection teardown. No credentials are logged.
        }
    }
    func testZeroPromptRoundIsShownAndRequiresExplicitEmptyReply() throws {
        try withConnection { c in
            let context = KeyboardContext(connection: c, handler: { challenge, reply in
                XCTAssertTrue(challenge.prompts.isEmpty)
                XCTAssertEqual(challenge.instruction, Data("approve on device".utf8))
                reply.resolve([])
            }, token: CancellationToken(), timeout: 0.3)
            XCTAssertEqual(context.answer(name: nil, nameLength: 0, instruction: "approve on device", instructionLength: 17,
                                          count: 0, prompts: nil, responses: nil), 0)
        }
    }
    func testNoAnswerTimesOutAndCancelIsNotAnEmptyAutomaticAnswer() throws {
        try withConnection { c in
            let timeout = KeyboardContext(connection: c, handler: { _, _ in }, token: CancellationToken(), timeout: 0.01)
            XCTAssertEqual(timeout.answer(name: nil, nameLength: 0, instruction: nil, instructionLength: 0,
                                          count: 0, prompts: nil, responses: nil), -1)
            XCTAssertEqual(timeout.failure?.kind, .timeout)
            let token = CancellationToken(); token.cancel()
            let cancelled = KeyboardContext(connection: c, handler: { _, _ in }, token: token, timeout: 0.2)
            XCTAssertEqual(cancelled.answer(name: nil, nameLength: 0, instruction: nil, instructionLength: 0,
                                            count: 0, prompts: nil, responses: nil), -1)
            XCTAssertEqual(cancelled.failure?.kind, .cancelled)
        }
    }
    func testMalformedCountDoesNotInvokeHandler() throws {
        try withConnection { c in
            let context = KeyboardContext(connection: c, handler: { _, _ in XCTFail("Malformed prompt count must not reach handler") },
                                          token: CancellationToken(), timeout: 0.1)
            XCTAssertEqual(context.answer(name: nil, nameLength: 0, instruction: nil, instructionLength: 0,
                                          count: 33, prompts: nil, responses: nil), -1)
        }
    }
}
