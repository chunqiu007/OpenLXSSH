import CRemoteFileBridge
import CryptoKit
import Darwin
import Foundation
import OpenLXSSHTrust
import XCTest
@testable import OpenLXSSHRemoteFileProbe

/// Loopback peer has no SSH implementation: it accepts TCP but never sends protocol/credentials.
private final class SilentTCPPeer: @unchecked Sendable {
    let fd: Int32
    let identity: HostIdentity
    init() throws {
        let descriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        fd = descriptor
        guard descriptor >= 0 else { throw FileServiceError(.io, operation: "test-socket") }
        var a = sockaddr_in(); a.sin_len = UInt8(MemoryLayout.size(ofValue: a)); a.sin_family = sa_family_t(AF_INET)
        a.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1")); a.sin_port = 0
        let bound = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        } }
        guard bound == 0, listen(fd, 8) == 0 else { Darwin.close(fd); throw FileServiceError(.io, operation: "test-bind") }
        _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        var len = socklen_t(MemoryLayout.size(ofValue: a))
        let rc = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &len) } }
        guard rc == 0 else { Darwin.close(fd); throw FileServiceError(.io, operation: "test-port") }
        identity = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(Int(UInt16(bigEndian: a.sin_port))))
    }
    deinit { Darwin.close(fd) }
    func acceptOne() async throws -> ConnectedSocket {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while ContinuousClock.now < deadline {
            let accepted = accept(fd, nil, nil)
            if accepted >= 0 { return ConnectedSocket(accepted) }
            guard errno == EWOULDBLOCK || errno == EINTR else { throw FileServiceError(.io, operation: "test-accept") }
            try await Task.sleep(for: .milliseconds(5))
        }
        throw FileServiceError(.timeout, operation: "test-accept")
    }
}
final class ConnectionAndTrustTests: XCTestCase, @unchecked Sendable {
    private func key() throws -> HostKey {
        let privateKey = Curve25519.Signing.PrivateKey()
        let fields = [Data("ssh-ed25519".utf8), privateKey.publicKey.rawRepresentation]
        var wire = Data()
        for field in fields {
            var len = UInt32(field.count).bigEndian
            withUnsafeBytes(of: &len) { wire.append(contentsOf: $0) }; wire.append(field)
        }
        return HostKey(identity: try ServerIdentity(host: "127.0.0.1", port: 2222), rawKey: wire,
                       algorithmCode: Int32(LIBSSH2_HOSTKEY_TYPE_ED25519))
    }
    private func store() throws -> (URL, HostTrustStore) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("P3-trust-\(UUID().uuidString)")
        return (root, try HostTrustStore(directory: AbsolutePath(root.path)))
    }
    func testLoopbackNonblockingTCPConnectAndClose() async throws {
        let peer = try SilentTCPPeer()
        var connection: ConnectedSocket? = try await TCPConnector.connect(peer.identity, timeout: 1, token: CancellationToken())
        let accepted = try await peer.acceptOne()
        XCTAssertNotEqual(fcntl(try XCTUnwrap(connection).descriptor, F_GETFL) & O_NONBLOCK, 0)
        XCTAssertNotEqual(fcntl(try XCTUnwrap(connection).descriptor, F_GETFD) & FD_CLOEXEC, 0)
        let ownedFD = try XCTUnwrap(connection).descriptor
        connection?.close(); connection = nil
        XCTAssertEqual(fcntl(ownedFD, F_GETFD), -1); XCTAssertEqual(errno, EBADF)
        // TCP FIN delivery is asynchronous; require actual EOF within a bounded interval.
        var b: UInt8 = 0
        var received = recv(accepted.descriptor, &b, 1, MSG_DONTWAIT)
        let deadline = ContinuousClock.now.advanced(by: .seconds(1))
        while received < 0 && (errno == EAGAIN || errno == EINTR) && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
            received = recv(accepted.descriptor, &b, 1, MSG_DONTWAIT)
        }
        XCTAssertEqual(received, 0)
    }
    func testProductEndpointEntryTimesOutWithNoSSHProtocol() async throws {
        let peer = try SilentTCPPeer(); let (root, trust) = try store()
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            _ = try await LibSSH2FileService.connect(configuration: SSHConnection(host: peer.identity, user: SSHUser("fixture")),
                authentication: [.password(Data(UUID().uuidString.utf8))], trustStore: trust, trustHandler: nil,
                connectionTimeout: 1, operationTimeout: 0.06, token: CancellationToken())
            XCTFail("TCP-only peer must never establish SSH")
        } catch let e as FileServiceError { XCTAssertEqual(e.kind, .timeout) }
        let records = try await trust.records(); XCTAssertTrue(records.isEmpty)
    }
    func testCancelDuringLoopbackHandshakeAndPeerEOF() async throws {
        let peer = try SilentTCPPeer(); let (root, trust) = try store()
        defer { try? FileManager.default.removeItem(at: root) }
        let task = Task {
            try await LibSSH2FileService.connect(configuration: SSHConnection(host: peer.identity, user: SSHUser("fixture")),
                authentication: [.password(Data(UUID().uuidString.utf8))], trustStore: trust, trustHandler: nil,
                operationTimeout: 2, token: CancellationToken())
        }
        let accepted = try await peer.acceptOne()
        task.cancel()
        do { _ = try await task.value; XCTFail("cancel") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .cancelled) }
        _ = accepted // Retain open peer during cancellation.
        let socket = try await TCPConnector.connect(peer.identity, timeout: 1, token: CancellationToken())
        var eofPeer: ConnectedSocket? = try await peer.acceptOne(); eofPeer?.close(); eofPeer = nil
        XCTAssertNil(eofPeer)
        let native = try LibSSH2FileService(connectedSocket: socket.descriptor, operationTimeout: 0.2)
        do {
            try await native.establish(identity: ServerIdentity(host: "127.0.0.1", port: peer.identity.port.value),
                username: Data("fixture".utf8), authentication: [.password(Data(UUID().uuidString.utf8))],
                hostKeyHandler: nil, token: CancellationToken()); XCTFail("EOF")
        } catch let e as FileServiceError { XCTAssertEqual(e.kind, .transport) }
        await native.close()
    }
    func testDNSDeadlineCancellationAndLateResultDiscarded() async throws {
        let identity = HostIdentity(address: try HostAddress("localhost"), port: try SSHPort(22))
        let slow = AddressResolver { _ in Thread.sleep(forTimeInterval: 0.15); return [] }
        let started = ContinuousClock.now
        do {
            _ = try await slow.resolve(identity, deadline: .now.advanced(by: .milliseconds(15)), token: CancellationToken()); XCTFail("timeout")
        } catch let e as FileServiceError { XCTAssertEqual(e.kind, .timeout) }
        XCTAssertLessThan(started.duration(to: .now), .milliseconds(100))
        let token = CancellationToken()
        let task = Task { try await slow.resolve(identity, deadline: .now.advanced(by: .seconds(2)), token: token) }
        try await Task.sleep(for: .milliseconds(10)); token.cancel()
        do { _ = try await task.value; XCTFail("cancel") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .cancelled) }
        try await Task.sleep(for: .milliseconds(160)) // Let bounded OS-worker substitutes drain.
    }
    func testSystemResolverUsesTypedLocalhostOnly() async throws {
        let identity = HostIdentity(address: try HostAddress("localhost"), port: try SSHPort(2222))
        let answer = try await AddressResolver.shared.resolve(identity, deadline: .now.advanced(by: .seconds(2)), token: CancellationToken())
        XCTAssertFalse(answer.isEmpty)
        XCTAssertTrue(answer.allSatisfy { $0.family == AF_INET || $0.family == AF_INET6 })
    }
    func testSharedStorePendingExplicitConfirmationTrustedThenChangedRejected() async throws {
        let (root, trust) = try store(); defer { try? FileManager.default.removeItem(at: root) }
        let identity = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(2222))
        let original = try key()
        try await SharedHostTrust.verify(original, identity: identity, store: trust, timeout: 1, token: CancellationToken()) { event, reply in
            guard case .pending(let pending) = event else { XCTFail("pending expected"); return }
            reply.resolve(.confirm(displayedFingerprint: pending.fingerprint))
        }
        try await SharedHostTrust.verify(original, identity: identity, store: trust, timeout: 1, token: CancellationToken()) { _, _ in
            XCTFail("Known exact key must not prompt")
        }
        let changed = try key()
        do {
            try await SharedHostTrust.verify(changed, identity: identity, store: trust, timeout: 1, token: CancellationToken()) { event, reply in
                guard case .changed = event else { XCTFail("change expected"); return }
                reply.resolve(.confirm(displayedFingerprint: "must-not-replace"))
            }
            XCTFail("Changed key must be rejected even if a callback attempts confirmation")
        } catch let e as FileServiceError { XCTAssertEqual(e.kind, .untrusted) }
        let records = try await trust.records(); XCTAssertEqual(records.count, 1); XCTAssertEqual(records.first?.key.blob, original.rawKey)
    }
    func testNoCallbackWrongFingerprintAndCancelledPendingNeverTrust() async throws {
        let (root, trust) = try store(); defer { try? FileManager.default.removeItem(at: root) }
        let identity = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(2222))
        let original = try key()
        do { try await SharedHostTrust.verify(original, identity: identity, store: trust, timeout: 1, token: CancellationToken(), handler: nil); XCTFail("no callback") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .untrusted) }
        do {
            try await SharedHostTrust.verify(original, identity: identity, store: trust, timeout: 1, token: CancellationToken()) { _, reply in
                reply.resolve(.confirm(displayedFingerprint: "wrong"))
            }; XCTFail("wrong fingerprint")
        } catch let e as HostTrustError { XCTAssertEqual(e, .fingerprintMismatch) }
        let token = CancellationToken()
        do {
            try await SharedHostTrust.verify(original, identity: identity, store: trust, timeout: 1, token: token) { _, reply in
                token.cancel(); reply.resolve(.confirm(displayedFingerprint: "never"))
            }; XCTFail("cancel")
        } catch let e as FileServiceError { XCTAssertEqual(e.kind, .cancelled) }
        let records = try await trust.records(); XCTAssertTrue(records.isEmpty)
    }
    func testTypedEndpointRejectsShellLikeInvalidInputs() {
        for host in ["-option", "127.0.0.1\ncommand", "host name", "$(command)", "a;command"] {
            XCTAssertThrowsError(try HostAddress(host))
        }
        XCTAssertThrowsError(try SSHPort(0)); XCTAssertThrowsError(try SSHPort(65536))
    }
    func testDNSBoundedWorkersRejectBacklogAndCancelledConnectorCreatesNoConnection() async throws {
        let identity = HostIdentity(address: try HostAddress("localhost"), port: try SSHPort(22))
        let slow = AddressResolver { _ in Thread.sleep(forTimeInterval: 0.2); return [] }
        for _ in 0..<4 {
            do { _ = try await slow.resolve(identity, deadline: .now.advanced(by: .milliseconds(3)), token: CancellationToken()); XCTFail("timeout") }
            catch let e as FileServiceError { XCTAssertEqual(e.kind, .timeout) }
        }
        do { _ = try await slow.resolve(identity, deadline: .now.advanced(by: .seconds(1)), token: CancellationToken()); XCTFail("bound") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .resourceLimit) }
        let token = CancellationToken(); token.cancel()
        do { _ = try await TCPConnector.connect(identity, timeout: 1, token: token); XCTFail("cancel") }
        catch let e as FileServiceError { XCTAssertEqual(e.kind, .cancelled) }
        try await Task.sleep(for: .milliseconds(220))
    }
    func testRawAlgorithmMismatchFailsSystemParser() throws {
        let original = try key()
        let invalid = HostKey(identity: original.identity, rawKey: original.rawKey, algorithmCode: Int32(LIBSSH2_HOSTKEY_TYPE_RSA))
        XCTAssertThrowsError(try SharedHostTrust.parse(invalid))
    }
}
