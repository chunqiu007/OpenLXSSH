import COpenLXSSHFiles
import Foundation

public struct KeyboardPrompt: Sendable {
    public let bytes: Data
    public let echo: Bool
}
public struct KeyboardChallenge: Sendable {
    public let name: Data
    public let instruction: Data
    public let prompts: [KeyboardPrompt]
}
public typealias KeyboardHandler = @Sendable (KeyboardChallenge, ChallengeReply<[Data]>) -> Void
public enum FileAuthentication: Sendable {
    /// In-memory only. Data/Swift/libssh2 copies cannot all be guaranteed zeroized.
    case password(Data)
    case publicKey(publicKey: Data?, privateKey: Data, passphrase: Data?)
    case keyboardInteractive(KeyboardHandler)
}
final class KeyboardContext {
    let handler: KeyboardHandler
    let token: CancellationToken
    let deadline: Date
    let connection: OpaquePointer
    var failure: FileServiceError?
    init(connection: OpaquePointer, handler: @escaping KeyboardHandler, token: CancellationToken, timeout: TimeInterval) {
        self.connection = connection
        self.handler = handler; self.token = token; deadline = Date().addingTimeInterval(timeout)
    }
    func answer(name: UnsafePointer<CChar>?, nameLength: Int32,
                instruction: UnsafePointer<CChar>?, instructionLength: Int32, count: Int32,
                prompts: UnsafePointer<LIBSSH2_USERAUTH_KBDINT_PROMPT>?,
                responses: UnsafeMutablePointer<LIBSSH2_USERAUTH_KBDINT_RESPONSE>?) -> Int32 {
        guard count >= 0, count <= 32, nameLength >= 0, nameLength <= 65536,
              instructionLength >= 0, instructionLength <= 65536 else { return -1 }
        if count == 0 {
            return answerZero(name: name, nameLength: nameLength,
                              instruction: instruction, instructionLength: instructionLength)
        }
        guard let responses else { return -1 }
        var items: [KeyboardPrompt] = []
        for i in 0..<Int(count) {
            guard let p = prompts?[i], p.length <= 65536, let text = p.text else { return -1 }
            items.append(KeyboardPrompt(bytes: Data(bytes: text, count: p.length), echo: p.echo != 0))
        }
        let challenge = KeyboardChallenge(name: name.map { Data(bytes: $0, count: Int(nameLength)) } ?? Data(),
            instruction: instruction.map { Data(bytes: $0, count: Int(instructionLength)) } ?? Data(), prompts: items)
        let reply = ChallengeReply<[Data]>()
        let handler = self.handler
        DispatchQueue.global().async { handler(challenge, reply) }
        do {
            let answers = try reply.wait(token: token, deadline: deadline)
            guard answers.count == Int(count), answers.allSatisfy({ $0.count <= 65536 }) else { return -1 }
            for (i, answer) in answers.enumerated() {
                let rc = answer.withUnsafeBytes { ptr in
                    rf_keyboard_set_response(connection, responses, Int32(i), ptr.bindMemory(to: UInt8.self).baseAddress, answer.count)
                }
                if rc != 0 { return -1 }
            }
            return 0
        } catch {
            if let typed = error as? FileServiceError { failure = typed }
            return -1
        }
    }
    private func answerZero(name: UnsafePointer<CChar>?, nameLength: Int32,
                            instruction: UnsafePointer<CChar>?, instructionLength: Int32) -> Int32 {
        guard nameLength >= 0, nameLength <= 65536, instructionLength >= 0, instructionLength <= 65536 else { return -1 }
        let challenge = KeyboardChallenge(name: name.map { Data(bytes: $0, count: Int(nameLength)) } ?? Data(),
            instruction: instruction.map { Data(bytes: $0, count: Int(instructionLength)) } ?? Data(), prompts: [])
        let reply = ChallengeReply<[Data]>()
        let handler = self.handler
        DispatchQueue.global().async { handler(challenge, reply) }
        do { return try reply.wait(token: token, deadline: deadline).isEmpty ? 0 : -1 }
        catch {
            if let typed = error as? FileServiceError { failure = typed }
            return -1
        }
    }
}
private let keyboardCallback: rf_keyboard_responder = { ctx, name, nlen, instruction, ilen, count, prompts, responses in
    guard let ctx else { return -1 }
    return Unmanaged<KeyboardContext>.fromOpaque(ctx).takeUnretainedValue().answer(
        name: name, nameLength: nlen, instruction: instruction, instructionLength: ilen,
        count: count, prompts: prompts, responses: responses)
}

/// Native SFTP session owned by a serial queue. Product callers use connect(configuration:...),
/// which creates its private TCP socket and verifies this same handshake key before authentication.
/// Real SSH/SFTP interoperability is not established by the local tests.
public final class LibSSH2FileService: RemoteFileService, @unchecked Sendable {
    public let capabilities = FileServiceCapabilities(traversal: .remoteComponentLstat, exclusiveCreate: true,
        noReplace: .needsServerConfirmation, canAttemptAtomicReplace: true)
    public let serverBinding: UUID? = UUID()
    private let queue = DispatchQueue(label: "OpenLXSSH.Files.libssh2")
    private let lifetime = CancellationToken()
    private let lock = NSLock()
    private var connection: OpaquePointer?
    private var activeToken: CancellationToken?
    private var handles: [FileHandleID: OpaquePointer] = [:]
    private var ready = false
    private let timeout: TimeInterval

    init(connectedSocket: Int32, operationTimeout: TimeInterval = 10) throws {
        guard operationTimeout.isFinite, operationTimeout > 0, operationTimeout <= 300,
              let connection = rf_connection_create(connectedSocket) else {
            throw FileServiceError(.transport, operation: "adopt-socket")
        }
        self.connection = connection; timeout = operationTimeout
    }
    deinit { if let connection { rf_connection_destroy(connection) } }
    public func cancel() {
        lifetime.cancel()
        lock.lock(); defer { lock.unlock() }
        activeToken?.cancel()
        if let connection { rf_connection_cancel(connection) }
    }
    private func dispose() {
        lock.lock(); defer { lock.unlock() }
        if let connection { rf_connection_destroy(connection); self.connection = nil }
        handles.removeAll(); ready = false
    }
    public func close() async {
        cancel()
        await withCheckedContinuation { continuation in
            queue.async { self.dispose(); continuation.resume() }
        }
    }
    private func perform<T: Sendable>(_ token: CancellationToken,
                                      _ body: @escaping @Sendable (OpaquePointer) throws -> T) async throws -> T {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    do {
                        try self.lifetime.check(); try token.check()
                        guard let c = self.connection else { throw FileServiceError(.closed, operation: "session") }
                        self.lock.lock(); self.activeToken = token; self.lock.unlock()
                        defer { self.lock.lock(); self.activeToken = nil; self.lock.unlock() }
                        continuation.resume(returning: try body(c))
                    } catch {
                        if let error = error as? FileServiceError,
                           [.cancelled, .timeout, .transport].contains(error.kind) { self.dispose() }
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: { token.cancel(); self.cancel() }
    }
    private func check(_ rc: Int32, _ c: OpaquePointer, operation: String, path: RemotePath? = nil) throws {
        guard rc < 0 else { return }
        let kind: FileServiceError.Kind
        switch rc {
        case Int32(RF_CANCELLED): kind = .cancelled
        case Int32(RF_TIMEOUT): kind = .timeout
        case Int32(RF_CLOSED): kind = .closed
        case Int32(RF_UNTRUSTED): kind = .untrusted
        case Int32(LIBSSH2_ERROR_METHOD_NOT_SUPPORTED): kind = .unsupported
        case Int32(RF_INVALID): kind = .invalidPath
        case Int32(LIBSSH2_ERROR_AUTHENTICATION_FAILED), Int32(LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED): kind = .authentication
        case Int32(LIBSSH2_ERROR_SFTP_PROTOCOL):
            switch rf_sftp_error(c) {
            case UInt64(LIBSSH2_FX_NO_SUCH_FILE), UInt64(LIBSSH2_FX_NO_SUCH_PATH): kind = .notFound
            case UInt64(LIBSSH2_FX_PERMISSION_DENIED): kind = .permissionDenied
            case UInt64(LIBSSH2_FX_FILE_ALREADY_EXISTS): kind = .conflict
            case UInt64(LIBSSH2_FX_OP_UNSUPPORTED): kind = .unsupported
            default: kind = .protocolFailure
            }
        default: kind = .transport
        }
        throw FileServiceError(kind, operation: operation, path: path,
                               code: rc == Int32(LIBSSH2_ERROR_SFTP_PROTOCOL) ? Int64(rf_sftp_error(c)) : Int64(rc))
    }
    /// Executes methods in caller-specified order, allowing public-key + interactive MFA.
    /// Never guesses a password from prompt text; every keyboard answer goes to a typed handler.
    func establish(identity: ServerIdentity, username: Data, authentication: [FileAuthentication],
                          hostKeyHandler: (@Sendable (HostKey, ChallengeReply<Bool>) -> Void)?,
                          token: CancellationToken) async throws {
        guard !username.isEmpty, username.count <= 1024, !username.contains(0),
              !authentication.isEmpty, authentication.count <= 3 else {
            throw FileServiceError(.authentication, operation: "username-or-plan")
        }
        var methods = Set<Int>()
        for method in authentication {
            let code: Int
            switch method { case .password: code = 0; case .publicKey: code = 1; case .keyboardInteractive: code = 2 }
            guard methods.insert(code).inserted else { throw FileServiceError(.authentication, operation: "repeated-auth-method") }
        }
        try await perform(token) { c in
            do {
                guard !self.ready else { throw FileServiceError(.unsupported, operation: "already-established") }
                try self.check(rf_handshake(c, token.native, self.timeout), c, operation: "handshake")
                var length = 0
                var algorithm: Int32 = 0
                guard let key = rf_hostkey(c, &length, &algorithm), length > 0 else {
                    throw FileServiceError(.untrusted, operation: "host-key")
                }
                try HostKeyPolicy.verify(HostKey(identity: identity, rawKey: Data(bytes: key, count: length),
                                                 algorithmCode: algorithm), token: token, timeout: self.timeout, handler: hostKeyHandler)
                try self.check(rf_trust_hostkey(c, 1), c, operation: "host-key")
                for auth in authentication {
                    try token.check()
                    if rf_authenticated(c) != 0 { break }
                    var keyboardFailure: FileServiceError?
                    let rc: Int32 = username.withUnsafeBytes { user in
                        let u = user.baseAddress!.assumingMemoryBound(to: CChar.self)
                        switch auth {
                        case .password(let password):
                            guard password.count <= 65536 else { return Int32(RF_INVALID) }
                            return (Array(password) + [0]).withUnsafeBytes { secret in
                                rf_password(c, u, UInt32(username.count), secret.baseAddress!.assumingMemoryBound(to: CChar.self),
                                            UInt32(password.count), token.native, self.timeout)
                            }
                        case .publicKey(let publicKey, let privateKey, let passphrase):
                            guard privateKey.count <= 4 * 1024 * 1024, !privateKey.isEmpty,
                                  (passphrase?.count ?? 0) <= 65536, !(passphrase?.contains(0) ?? false) else { return Int32(RF_INVALID) }
                            return (Array(publicKey ?? Data()) + [0]).withUnsafeBytes { pub in
                                (Array(privateKey) + [0]).withUnsafeBytes { priv in
                                    (Array(passphrase ?? Data()) + [0]).withUnsafeBytes { pass in
                                        rf_publickey(c, u, username.count,
                                            publicKey == nil ? nil : pub.baseAddress!.assumingMemoryBound(to: CChar.self), publicKey?.count ?? 0,
                                            priv.baseAddress!.assumingMemoryBound(to: CChar.self), privateKey.count,
                                            pass.baseAddress!.assumingMemoryBound(to: CChar.self), token.native, self.timeout)
                                    }
                                }
                            }
                        case .keyboardInteractive(let handler):
                            let context = KeyboardContext(connection: c, handler: handler, token: token, timeout: self.timeout)
                            return withExtendedLifetime(context) {
                                let result = rf_keyboard(c, u, UInt32(username.count), keyboardCallback,
                                                         Unmanaged.passUnretained(context).toOpaque(), token.native, self.timeout)
                                keyboardFailure = context.failure
                                return result
                            }
                        }
                    }
                    if let keyboardFailure { throw keyboardFailure }
                    // libssh2 1.11.1 does not surface SSH partial-success separately: password
                    // may return AUTHENTICATION_FAILED, signed publickey PUBLICKEY_UNVERIFIED.
                    // Only the explicit, distinct next method is attempted (at most three total).
                    if rc != Int32(LIBSSH2_ERROR_AUTHENTICATION_FAILED) && rc != Int32(LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED) {
                        try self.check(rc, c, operation: "authenticate")
                    }
                }
                guard rf_authenticated(c) != 0 else { throw FileServiceError(.authentication, operation: "authenticate") }
                try self.check(rf_start_sftp(c, token.native, self.timeout), c, operation: "sftp-init")
                self.ready = true
            } catch { token.cancel(); self.dispose(); throw error }
        }
    }
    private func requireReady() throws {
        guard ready else { throw FileServiceError(.closed, operation: "sftp-not-ready") }
    }
    private func attributes(_ a: LIBSSH2_SFTP_ATTRIBUTES) -> FileAttributes {
        let mode = UInt32(a.permissions)
        let hasPermissions = a.flags & UInt(LIBSSH2_SFTP_ATTR_PERMISSIONS) != 0
        let kind: FileKind
        switch hasPermissions ? mode & 0o170000 : 0 {
        case 0o100000: kind = .regular
        case 0o040000: kind = .directory
        case 0o120000: kind = .symbolicLink
        case 0: kind = .unknown
        default: kind = .other
        }
        return FileAttributes(kind: kind, size: a.flags & UInt(LIBSSH2_SFTP_ATTR_SIZE) == 0 ? nil : a.filesize,
                              permissions: hasPermissions ? mode : nil,
                              modifiedSeconds: a.flags & UInt(LIBSSH2_SFTP_ATTR_ACMODTIME) == 0 ? nil : UInt64(a.mtime))
    }
    public func lstat(_ path: RemotePath, token: CancellationToken) async throws -> FileAttributes {
        try await perform(token) { c in
            try self.requireReady()
            var a = LIBSSH2_SFTP_ATTRIBUTES()
            let rc = path.withCString { rf_lstat(c, $0, $1, &a, token.native, self.timeout) }
            try self.check(rc, c, operation: "lstat", path: path)
            return self.attributes(a)
        }
    }
    public func list(_ path: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] {
        try await perform(token) { c in
            try self.requireReady()
            var rc: Int32 = 0
            guard let handle = path.withCString({ rf_open(c, $0, $1, 2, &rc, token.native, self.timeout) }) else {
                try self.check(rc, c, operation: "opendir", path: path); throw FileServiceError(.io, operation: "opendir")
            }
            var needsClose = true
            do {
                var results: [DirectoryEntry] = []
                var buffer = [CChar](repeating: 0, count: 32768)
                while true {
                    var a = LIBSSH2_SFTP_ATTRIBUTES()
                    rc = rf_readdir(c, handle, &buffer, buffer.count, &a, token.native, self.timeout)
                    try self.check(rc, c, operation: "readdir", path: path)
                    if rc == 0 { break }
                    let bytes = Data(buffer.prefix(Int(rc)).map { UInt8(bitPattern: $0) })
                    if bytes == Data([46]) || bytes == Data([46, 46]) { continue }
                    guard results.count < 100000 else { throw FileServiceError(.resourceLimit, operation: "readdir", path: path) }
                    results.append(DirectoryEntry(name: try FileName(bytes: bytes), attributes: self.attributes(a)))
                }
                rc = rf_close_handle(c, handle, token.native, self.timeout)
                needsClose = false // C retains ownership on cancelled/timeout, and dispose drains it.
                try self.check(rc, c, operation: "closedir", path: path)
                return results
            } catch {
                let interrupted = (error as? FileServiceError).map { [.cancelled, .timeout, .transport].contains($0.kind) } ?? false
                if needsClose && !interrupted {
                    let cleanup = CancellationToken()
                    let closeRC = rf_close_handle(c, handle, cleanup.native, self.timeout)
                    if closeRC < 0 { self.dispose() }
                }
                throw error
            }
        }
    }
    public func open(_ path: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID {
        // Public raw streams expose SFTP semantics; SafeTransferEngine performs explicit
        // component lstat checks and obtains risk confirmation before using a remote path.
        try await perform(token) { c in
            try self.requireReady()
            var rc: Int32 = 0
            guard let handle = path.withCString({ rf_open(c, $0, $1, mode == .read ? 0 : 1, &rc, token.native, self.timeout) }) else {
                try self.check(rc, c, operation: "open", path: path); throw FileServiceError(.io, operation: "open")
            }
            let id = FileHandleID(); self.handles[id] = handle; return id
        }
    }
    private func handle(_ id: FileHandleID) throws -> OpaquePointer {
        guard let h = handles[id] else { throw FileServiceError(.closed, operation: "handle") }; return h
    }
    public func fstat(_ handle: FileHandleID, token: CancellationToken) async throws -> FileAttributes? {
        try await perform(token) { c in
            try self.requireReady()
            var a = LIBSSH2_SFTP_ATTRIBUTES()
            let rc = rf_fstat(c, try self.handle(handle), &a, token.native, self.timeout)
            // A server may explicitly reject FSTAT; nil declares the weaker path/digest fallback.
            if rc == Int32(LIBSSH2_ERROR_SFTP_PROTOCOL), rf_sftp_error(c) == UInt64(LIBSSH2_FX_OP_UNSUPPORTED) { return nil }
            try self.check(rc, c, operation: "fstat")
            return self.attributes(a)
        }
    }
    public func read(_ handle: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data {
        guard maxBytes > 0, maxBytes <= 1024 * 1024 else { throw FileServiceError(.resourceLimit, operation: "read") }
        return try await perform(token) { c in
            var bytes = [CChar](repeating: 0, count: maxBytes)
            let rc = rf_read(c, try self.handle(handle), &bytes, maxBytes, token.native, self.timeout)
            try self.check(rc, c, operation: "read")
            return Data(bytes.prefix(Int(rc)).map { UInt8(bitPattern: $0) })
        }
    }
    public func write(_ handle: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        guard !data.isEmpty, data.count <= 1024 * 1024 else { throw FileServiceError(.resourceLimit, operation: "write") }
        return try await perform(token) { c in
            let h = try self.handle(handle)
            let rc = data.withUnsafeBytes { rf_write(c, h, $0.baseAddress!.assumingMemoryBound(to: CChar.self), data.count, token.native, self.timeout) }
            try self.check(rc, c, operation: "write"); return Int(rc)
        }
    }
    public func finish(_ handle: FileHandleID, token: CancellationToken) async throws {
        try await perform(token) { c in
            try self.check(rf_fsync(c, try self.handle(handle), token.native, self.timeout), c, operation: "fsync")
        }
    }
    public func closeHandle(_ handle: FileHandleID) async throws {
        let token = CancellationToken()
        try await perform(token) { c in
            let rc = rf_close_handle(c, try self.handle(handle), token.native, self.timeout)
            self.handles[handle] = nil
            try self.check(rc, c, operation: "close-handle")
        }
    }
    public func mkdir(_ path: RemotePath, token: CancellationToken) async throws {
        try await perform(token) { c in
            try self.requireReady()
            try self.check(path.withCString { rf_mkdir(c, $0, $1, 0o700, token.native, self.timeout) }, c, operation: "mkdir", path: path)
        }
    }
    public func rename(_ source: RemotePath, to destination: RemotePath, mode: RenameMode, token: CancellationToken) async throws {
        guard mode == .noReplace else { throw FileServiceError(.unsupported, operation: "unsafe-replace", path: destination) }
        try await perform(token) { c in
            try self.requireReady()
            let rc = source.withCString { a, alen in destination.withCString { b, blen in
                rf_rename_no_replace(c, a, alen, b, blen, token.native, self.timeout)
            } }
            try self.check(rc, c, operation: "rename", path: destination)
        }
    }
    public func commit(_ source: RemotePath, to destination: RemotePath, request: CommitRequest, token: CancellationToken) async throws {
        if request.mode == .noReplace {
            guard request.serverConfirmation?.serverBinding == serverBinding else {
                throw FileServiceError(.needsCapabilityConfirmation, operation: "server-no-replace-unproven", path: destination)
            }
            try await TransferChecks.inspect(self, path: source, includeLeaf: true, token: token)
            try await TransferChecks.inspect(self, path: destination, includeLeaf: false, token: token)
            // SFTP v3 requires an existing destination to fail. Confirmation scopes this to tested
            // server behavior; a fresh lstat alone is not claimed to create the atomic guarantee.
            try await rename(source, to: destination, mode: .noReplace, token: token)
            return
        }
        guard request.acceptNonCASOverwriteRisk, let expected = request.expectedTarget,
              let digest = request.expectedContentSHA256, expected.size != nil, expected.modifiedSeconds != nil else {
            throw FileServiceError(.unsupported, operation: "overwrite-preconditions", path: destination)
        }
        try await TransferChecks.inspect(self, path: source, includeLeaf: true, token: token)
        try await TransferChecks.inspect(self, path: destination, includeLeaf: true, token: token)
        try await TransferChecks.requireUnchanged(self, path: destination, expected: expected, digest: digest, token: token)
        try await perform(token) { c in
            try self.requireReady()
            let rc = source.withCString { a, alen in destination.withCString { b, blen in
                rf_posix_replace(c, a, alen, b, blen, token.native, self.timeout)
            } }
            try self.check(rc, c, operation: "posix-rename-no-fallback", path: destination)
        }
    }
    public func remove(_ path: RemotePath, directory: Bool, token: CancellationToken) async throws {
        try await perform(token) { c in
            try self.requireReady()
            try self.check(path.withCString { rf_remove(c, $0, $1, directory ? 1 : 0, token.native, self.timeout) }, c, operation: "remove", path: path)
        }
    }
}
