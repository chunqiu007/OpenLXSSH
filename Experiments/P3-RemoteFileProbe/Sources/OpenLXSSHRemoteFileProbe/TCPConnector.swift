import CRemoteFileBridge
import Darwin
import Foundation
import OpenLXSSHTrust

struct ResolvedAddress: Sendable {
    let bytes: Data
    let family: Int32
}
private final class ResolutionResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<[ResolvedAddress], FileServiceError>?
    func finish(_ value: Result<[ResolvedAddress], FileServiceError>) {
        lock.lock(); defer { lock.unlock() }; self.value = value
    }
    func snapshot() -> Result<[ResolvedAddress], FileServiceError>? {
        lock.lock(); defer { lock.unlock() }; return value
    }
}
/// Darwin getaddrinfo has no portable cancellation primitive. At most four calls can remain inside
/// the OS resolver; caller cancellation/deadline returns promptly, discards late answers, and opens no FD.
/// No unbounded worker/dispatch backlog is created when a resolver is stuck.
final class AddressResolver: @unchecked Sendable {
    static let shared = AddressResolver()
    private let lock = NSLock()
    private var active = 0
    private let lookup: @Sendable (HostIdentity) throws -> [ResolvedAddress]
    init(lookup: @escaping @Sendable (HostIdentity) throws -> [ResolvedAddress] = AddressResolver.systemLookup) {
        self.lookup = lookup
    }
    private func reserve() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard active < 4 else { return false }; active += 1; return true
    }
    private func release() { lock.lock(); active -= 1; lock.unlock() }
    func resolve(_ identity: HostIdentity, deadline: ContinuousClock.Instant,
                 token: CancellationToken) async throws -> [ResolvedAddress] {
        try token.check()
        guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "dns") }
        guard reserve() else { throw FileServiceError(.resourceLimit, operation: "dns-workers") }
        let result = ResolutionResult()
        DispatchQueue.global(qos: .utility).async {
            defer { self.release() }
            do { result.finish(.success(try self.lookup(identity))) }
            catch { result.finish(.failure(error as? FileServiceError ?? FileServiceError(.transport, operation: "dns"))) }
        }
        while true {
            try token.check()
            guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "dns") }
            if let answer = result.snapshot() { return try answer.get() }
            do { try await Task.sleep(for: .milliseconds(5)) }
            catch { throw FileServiceError(.cancelled, operation: "dns") }
        }
    }
    static func systemLookup(_ identity: HostIdentity) throws -> [ResolvedAddress] {
        var hints = addrinfo()
        hints.ai_flags = AI_NUMERICSERV
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var answer: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(identity.address.value, String(identity.port.value), &hints, &answer)
        guard rc == 0 else { throw FileServiceError(.transport, operation: "dns", code: Int64(rc)) }
        defer { if let answer { freeaddrinfo(answer) } }
        var cursor = answer
        var addresses: [ResolvedAddress] = []
        while let item = cursor {
            let a = item.pointee
            if (a.ai_family == AF_INET || a.ai_family == AF_INET6), let addr = a.ai_addr,
               a.ai_addrlen > 0, a.ai_addrlen <= MemoryLayout<sockaddr_storage>.size {
                addresses.append(ResolvedAddress(bytes: Data(bytes: addr, count: Int(a.ai_addrlen)), family: a.ai_family))
            }
            if addresses.count == 16 { break }
            cursor = a.ai_next
        }
        guard !addresses.isEmpty else { throw FileServiceError(.transport, operation: "dns-no-address") }
        return addresses
    }
}
/// Internal RAII owner, never part of the public connection API.
final class ConnectedSocket: @unchecked Sendable {
    let descriptor: Int32
    private let lock = NSLock()
    private var isOpen = true
    init(_ descriptor: Int32) { self.descriptor = descriptor }
    func close() {
        lock.lock(); defer { lock.unlock() }
        if isOpen { isOpen = false; Darwin.close(descriptor) }
    }
    deinit { close() }
}
enum TCPConnector {
    static func connect(_ identity: HostIdentity, timeout: TimeInterval, token: CancellationToken,
                        resolver: AddressResolver = .shared) async throws -> ConnectedSocket {
        guard timeout.isFinite, timeout > 0, timeout <= 300 else { throw FileServiceError(.invalidPath, operation: "connect-timeout") }
        let deadline = ContinuousClock.now.advanced(by: .seconds(timeout))
        return try await withTaskCancellationHandler {
            let addresses = try await resolver.resolve(identity, deadline: deadline, token: token)
            var lastError = FileServiceError(.transport, operation: "connect")
            for address in addresses {
                try token.check()
                guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "connect") }
                let fd = socket(address.family, SOCK_STREAM, IPPROTO_TCP)
                guard fd >= 0 else { lastError = FileServiceError(.transport, operation: "socket", code: Int64(errno)); continue }
                let owned = ConnectedSocket(fd)
                let flags = fcntl(fd, F_GETFL)
                var one: Int32 = 1
                guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
                      fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
                      setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
                    throw FileServiceError(.transport, operation: "socket-flags", code: Int64(errno))
                }
                let rc = address.bytes.withUnsafeBytes { ptr in
                    Darwin.connect(fd, ptr.baseAddress!.assumingMemoryBound(to: sockaddr.self), socklen_t(ptr.count))
                }
                if rc == 0 { try token.check(); return owned }
                guard errno == EINPROGRESS || errno == EWOULDBLOCK else {
                    lastError = FileServiceError(.transport, operation: "connect", code: Int64(errno)); continue
                }
                while true {
                    try token.check()
                    guard ContinuousClock.now < deadline else { throw FileServiceError(.timeout, operation: "connect") }
                    var watched = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    let ready = poll(&watched, 1, 0)
                    if ready < 0 && errno != EINTR { throw FileServiceError(.transport, operation: "connect-poll", code: Int64(errno)) }
                    if ready > 0 {
                        var code: Int32 = 0
                        var length = socklen_t(MemoryLayout.size(ofValue: code))
                        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &code, &length) == 0 else {
                            throw FileServiceError(.transport, operation: "connect-status", code: Int64(errno))
                        }
                        if code == 0 { try token.check(); return owned }
                        lastError = FileServiceError(.transport, operation: "connect", code: Int64(code)); break
                    }
                    do { try await Task.sleep(for: .milliseconds(5)) }
                    catch { throw FileServiceError(.cancelled, operation: "connect") }
                }
            }
            throw lastError
        } onCancel: { token.cancel() }
    }
}
