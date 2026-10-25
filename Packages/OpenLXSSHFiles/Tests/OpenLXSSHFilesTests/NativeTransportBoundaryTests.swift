import COpenLXSSHFiles
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

/// socketpair peers never implement SSH, answer packets or authenticate. These tests exercise only
/// the real client's pre-trust guard, EAGAIN wait, timeout/cancel, and descriptor teardown.
final class NativeTransportBoundaryTests: XCTestCase, @unchecked Sendable {
    private func pair() throws -> [Int32] {
        var sockets: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else {
            throw FileServiceError(.io, operation: "socketpair", code: Int64(errno))
        }
        return sockets
    }
    func testCredentialCallsBeforeTrustRefusedWithoutSending() throws {
        let sockets = try pair(); defer { sockets.forEach { Darwin.close($0) } }
        let connection = try XCTUnwrap(rf_connection_create(sockets[0]))
        defer { rf_connection_destroy(connection) }
        let token = CancellationToken()
        let random = UUID().uuidString
        random.withCString { secret in
            XCTAssertEqual(rf_password(connection, "fixture", 7, secret, UInt32(random.utf8.count), token.native, 0.1), Int32(RF_UNTRUSTED))
            XCTAssertEqual(rf_publickey(connection, "fixture", 7, nil, 0, secret, random.utf8.count, nil, token.native, 0.1), Int32(RF_UNTRUSTED))
        }
        XCTAssertEqual(rf_trust_hostkey(connection, 1), Int32(RF_UNTRUSTED))
        var attributes = LIBSSH2_SFTP_ATTRIBUTES()
        XCTAssertEqual(rf_fstat(connection, nil, &attributes, token.native, 0.1), Int32(RF_CLOSED))
        var bytes = [UInt8](repeating: 0, count: 32)
        XCTAssertEqual(recv(sockets[1], &bytes, bytes.count, MSG_DONTWAIT), -1)
        XCTAssertEqual(errno, EAGAIN)
    }
    func testActualEAGAINHandshakeTimesOutWithoutPeerProtocol() async throws {
        let sockets = try pair(); defer { sockets.forEach { Darwin.close($0) } }
        let service = try LibSSH2FileService(connectedSocket: sockets[0], operationTimeout: 0.06)
        let started = Date()
        do {
            try await service.establish(identity: ServerIdentity(host: "fixture.invalid", port: 22), username: Data("fixture".utf8),
                authentication: [.password(Data(UUID().uuidString.utf8))], hostKeyHandler: nil, token: CancellationToken())
            XCTFail("No peer SSH implementation exists; handshake cannot succeed")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .timeout) }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1)
        await service.close(); await service.close()
        // The client owns a duplicate; callers still own their original FD, but the stream is shut down.
        var byte: UInt8 = 0
        XCTAssertEqual(recv(sockets[0], &byte, 1, MSG_DONTWAIT), 0)
    }
    func testCancelInterruptsNativeEAGAINWaitAndClosesDuplicate() async throws {
        let sockets = try pair(); defer { sockets.forEach { Darwin.close($0) } }
        let service = try LibSSH2FileService(connectedSocket: sockets[0], operationTimeout: 2)
        let task = Task {
            try await service.establish(identity: ServerIdentity(host: "fixture.invalid", port: 22), username: Data("fixture".utf8),
                authentication: [.password(Data(UUID().uuidString.utf8))], hostKeyHandler: nil, token: CancellationToken())
        }
        try await Task.sleep(for: .milliseconds(30))
        let started = Date(); task.cancel()
        do { try await task.value; XCTFail("cancelled") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1)
        await service.close()
    }
    func testPeerEOFIsTransportFailureNotSuccess() async throws {
        let sockets = try pair(); defer { Darwin.close(sockets[0]) }
        let service = try LibSSH2FileService(connectedSocket: sockets[0], operationTimeout: 0.2)
        Darwin.close(sockets[1])
        do {
            try await service.establish(identity: ServerIdentity(host: "fixture.invalid", port: 22), username: Data("fixture".utf8),
                authentication: [.password(Data(UUID().uuidString.utf8))], hostKeyHandler: nil, token: CancellationToken())
            XCTFail("EOF cannot establish SSH")
        } catch let error as FileServiceError { XCTAssertEqual(error.kind, .transport) }
        await service.close()
    }
}
