import XCTest
@testable import OpenLXSSHRemoteFileProbe

final class NativeAndPathTests: XCTestCase {
    func testRealNativeLibraryLink() {
        XCTAssertEqual(NativeDiagnostics.smoke(), 0)
        XCTAssertEqual(NativeDiagnostics.libssh2, "1.11.1")
        XCTAssertTrue(NativeDiagnostics.openssl.hasPrefix("OpenSSL 3.5.9 "))
        XCTAssertEqual(NativeDiagnostics.architecture, "arm64")
    }
    func testRawPathAndNonUTF8RoundTrip() throws {
        let raw = Data([47, 0xff, 32, 36, 39, 10])
        let path = try RemotePath(bytes: raw)
        XCTAssertEqual(path.bytes, raw)
        XCTAssertEqual(try path.parent.appending(XCTUnwrap(path.name)).bytes, raw)
        XCTAssertNotEqual(try RemotePath("/e\u{301}").bytes, try RemotePath("/é").bytes)
    }
    func testPathEscapeAndNoncanonicalNamesRejected() {
        for path in ["", "relative", "/../out", "/a/../../out", "/a//b", "/a/", "/a/./b", "/a\0b"] {
            XCTAssertThrowsError(try RemotePath(path), path)
        }
        for name in ["", ".", "..", "/a", "a/b", "a\0b"] {
            XCTAssertThrowsError(try FileName(name), name)
        }
    }
    func testNoDefaultTrustAndExplicitRejection() throws {
        let key = HostKey(identity: try ServerIdentity(host: "fixture.invalid", port: 2222), rawKey: Data([1, 2, 3]), algorithmCode: 6)
        XCTAssertThrowsError(try HostKeyPolicy.verify(key, token: CancellationToken(), timeout: 0.1, handler: nil)) { error in
            XCTAssertEqual((error as? FileServiceError)?.kind, .untrusted)
        }
        XCTAssertThrowsError(try HostKeyPolicy.verify(key, token: CancellationToken(), timeout: 0.1) { _, reply in reply.resolve(false) }) { error in
            XCTAssertEqual((error as? FileServiceError)?.kind, .untrusted)
        }
    }
    func testAlreadyResolvedReplyCannotBypassCancellationOrDeadline() {
        let token = CancellationToken()
        let reply = ChallengeReply<Bool>()
        XCTAssertTrue(reply.resolve(true)); token.cancel()
        XCTAssertThrowsError(try reply.wait(token: token, deadline: Date().addingTimeInterval(1))) { error in
            XCTAssertEqual((error as? FileServiceError)?.kind, .cancelled)
        }
        let expired = ChallengeReply<Bool>(); expired.resolve(true)
        XCTAssertThrowsError(try expired.wait(token: CancellationToken(), deadline: Date().addingTimeInterval(-1))) { error in
            XCTAssertEqual((error as? FileServiceError)?.kind, .timeout)
        }
    }
    func testChallengeTimeoutCancelAndLateReplyIsolation() throws {
        let reply = ChallengeReply<Bool>()
        XCTAssertThrowsError(try reply.wait(token: CancellationToken(), deadline: Date().addingTimeInterval(0.01))) { error in
            XCTAssertEqual((error as? FileServiceError)?.kind, .timeout)
        }
        XCTAssertFalse(reply.resolve(true))
        let token = CancellationToken(); token.cancel()
        let cancelled = ChallengeReply<Bool>()
        XCTAssertThrowsError(try cancelled.wait(token: token, deadline: Date().addingTimeInterval(1))) { error in
            XCTAssertEqual((error as? FileServiceError)?.kind, .cancelled)
        }
        XCTAssertFalse(cancelled.resolve(true))
    }
}
