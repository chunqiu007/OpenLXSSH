import CryptoKit
import Darwin
import Foundation

/// A SHA-256 proof of a fresh 256-bit random probe value. Never serialized to disk/logs.
/// The bundle harness compares two proofs in memory through a dedicated inherited pipe.
public struct LiveKeychainProof: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let bytes: Data
    public var description: String { "<redacted proof>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public func write(to descriptor: Int32) throws {
        var attributes = stat()
        guard descriptor > STDERR_FILENO, fstat(descriptor, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFIFO else { throw KeyFailure.invalidPath }
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw KeyFailure.systemCall("write proof pipe", errno) }
            offset += count
        }
    }
}

/// Short-lived cross-launch fixture, not a product persistence format. The ticket contains
/// only exact UUID cleanup coordinates; no secret or digest. The harness must run cleanup
/// in finally, including after a failed replacement/launch. Unresolved tickets are retained.
public enum LiveKeychainHandoff {
    struct Ticket: Codable, Equatable {
        let version: Int
        let namespace: UUID
        let credentialID: UUID
        var reference: CredentialReference { .init(id: credentialID, kind: .password) }
    }

    public static func create(ticketURL: URL) throws -> LiveKeychainProof {
        try create(ticketURL: ticketURL, makeStore: { CredentialStore(namespace: $0) })
    }

    static func create(ticketURL: URL, makeStore: (UUID) -> any CredentialStorage) throws -> LiveKeychainProof {
        let file = try TicketFile(ticketURL)
        let ticket = Ticket(version: 1, namespace: UUID(), credentialID: UUID())
        try file.write(ticket)
        let store = makeStore(ticket.namespace)
        var saveSucceeded = false
        do {
            let secret = try SecretBytes.random()
            switch store.save(secret, as: ticket.reference, authorization: .granted) {
            case .saved: saveSucceeded = true
            case .failed(let failure): throw LiveKeychainLimitation(operation: "handoff save", failure: failure)
            case .notAuthorized: throw LiveKeychainLimitation(operation: "handoff authorization", failure: .invalidData)
            }
            let read = try read(ticket, store: store)
            guard read.matches(secret) else { throw LiveKeychainLimitation(operation: "handoff initial mismatch", failure: .invalidData) }
            // Intentionally retain this one entry until the next launch, with its exact
            // cleanup ticket already fsynced before SecItemAdd. No secret leaves memory.
            return LiveKeychainProof(bytes: Data(SHA256.hash(data: read.bytes)))
        } catch {
            do { try cleanup(ticket, file: file, store: store) }
            catch let cleanupFailure as LiveKeychainLimitation {
                throw LiveKeychainCleanupFailure(failure: cleanupFailure.failure,
                                                 operationFailure: error as? LiveKeychainLimitation,
                                                 saveSucceeded: saveSucceeded, namespace: ticket.namespace,
                                                 references: [ticket.reference])
            }
            throw error
        }
    }

    public static func readAndDelete(ticketURL: URL) throws -> LiveKeychainProof {
        try readAndDelete(ticketURL: ticketURL, makeStore: { CredentialStore(namespace: $0) })
    }

    static func readAndDelete(ticketURL: URL, makeStore: (UUID) -> any CredentialStorage) throws -> LiveKeychainProof {
        let file = try TicketFile(ticketURL)
        let ticket = try file.read()
        let store = makeStore(ticket.namespace)
        var proof: LiveKeychainProof?
        var primary: (any Error)?
        // A real defer always attempts exact deletion, even if reading was denied/cancelled.
        var cleanupError: (any Error)?
        do {
            defer {
                do { try cleanup(ticket, file: file, store: store) }
                catch { cleanupError = error }
            }
            do { proof = LiveKeychainProof(bytes: Data(SHA256.hash(data: try read(ticket, store: store).bytes))) }
            catch { primary = error }
        }
        if let cleanupError { throw cleanupError }
        if let primary { throw primary }
        guard let proof else { throw LiveKeychainLimitation(operation: "handoff proof", failure: .invalidData) }
        return proof
    }

    public static func cleanup(ticketURL: URL) throws {
        try cleanup(ticketURL: ticketURL, makeStore: { CredentialStore(namespace: $0) })
    }

    static func cleanup(ticketURL: URL, makeStore: (UUID) -> any CredentialStorage) throws {
        let file = try TicketFile(ticketURL)
        let ticket = try file.read()
        try cleanup(ticket, file: file, store: makeStore(ticket.namespace))
    }

    private static func read(_ ticket: Ticket, store: any CredentialStorage) throws -> SecretBytes {
        switch store.read(ticket.reference) {
        case .available(let secret): return secret
        case .missing: throw LiveKeychainLimitation(operation: "handoff read missing", failure: .invalidData)
        case .manualEntryRequired(let failure): throw LiveKeychainLimitation(operation: "handoff read", failure: failure)
        }
    }

    private static func cleanup(_ ticket: Ticket, file: TicketFile, store: any CredentialStorage) throws {
        switch store.delete(ticket.reference) {
        case .deleted, .alreadyAbsent: break
        case .retryRequired(let failure): throw LiveKeychainLimitation(operation: "handoff cleanup", failure: failure)
        }
        guard case .missing = store.read(ticket.reference) else {
            throw LiveKeychainLimitation(operation: "handoff verify absent", failure: .invalidData)
        }
        try file.remove()
    }

    private final class TicketFile {
        let directory: Int32
        let name: String
        init(_ url: URL) throws {
            guard url.isFileURL, url.path.hasPrefix("/"), !url.path.utf8.contains(0),
                  !url.path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else {
                throw KeyFailure.invalidPath
            }
            name = url.lastPathComponent
            guard !name.isEmpty, name != ".", name != ".." else { throw KeyFailure.invalidPath }
            let opened = try PrivateDirectory.openDirectory(url.deletingLastPathComponent().path)
            var attributes = stat()
            guard fstat(opened, &attributes) == 0, attributes.st_uid == geteuid(),
                  attributes.st_mode & 0o777 == 0o700 else {
                _ = Darwin.close(opened)
                throw KeyFailure.unsafePermissions
            }
            directory = opened
        }
        deinit { _ = Darwin.close(directory) }

        func write(_ ticket: Ticket) throws {
            let bytes = try JSONEncoder().encode(ticket)
            let file = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard file >= 0 else { throw KeyFailure.systemCall("create cleanup ticket", errno) }
            defer { _ = Darwin.close(file) }
            var offset = 0
            while offset < bytes.count {
                let count = bytes.withUnsafeBytes { Darwin.write(file, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw KeyFailure.systemCall("write cleanup ticket", errno) }
                offset += count
            }
            guard fsync(file) == 0, fsync(directory) == 0 else { throw KeyFailure.systemCall("sync cleanup ticket", errno) }
        }

        func read() throws -> Ticket {
            let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard file >= 0 else { throw KeyFailure.systemCall("open cleanup ticket", errno) }
            defer { _ = Darwin.close(file) }
            var attributes = stat()
            guard fstat(file, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
                  attributes.st_mode & 0o777 == 0o600, attributes.st_uid == geteuid(),
                  attributes.st_nlink == 1, attributes.st_size > 0, attributes.st_size <= 1024 else {
                throw KeyFailure.unsafePermissions
            }
            var bytes = Data(count: Int(attributes.st_size))
            let count = bytes.withUnsafeMutableBytes { Darwin.read(file, $0.baseAddress, $0.count) }
            guard count == bytes.count, let ticket = try? JSONDecoder().decode(Ticket.self, from: bytes),
                  ticket.version == 1 else { throw KeyFailure.invalidPath }
            return ticket
        }

        func remove() throws {
            guard unlinkat(directory, name, 0) == 0, fsync(directory) == 0 else {
                throw KeyFailure.systemCall("remove cleanup ticket", errno)
            }
        }
    }
}
