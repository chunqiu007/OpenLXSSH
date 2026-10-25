import CryptoKit
import Darwin
import Foundation
import OpenLXSSHCredentialKeyProbe

/// Experiment-only: exactly two UUID references. Ticket coordinates contain no secret or
/// digest, and are fsynced before the first write. They allow recovery after a killed probe.
public struct FileCandidateTicket: Codable {
    public let namespace: UUID
    public let passwordID: UUID
    public let unapprovedID: UUID
    public init() { namespace = UUID(); passwordID = UUID(); unapprovedID = UUID() }
    var reference: CredentialReference { .init(id: passwordID, kind: .password) }
    var unapproved: CredentialReference { .init(id: unapprovedID, kind: .privateKeyPassphrase) }

    static func validateTicketURL(_ url: URL) throws {
        guard url.isFileURL, url.path.hasPrefix("/"), !url.path.utf8.contains(0),
              !url.path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else {
            throw FileCandidateFailure.invalidTicket
        }
        var current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw FileCandidateFailure.invalidTicket }
        defer { _ = Darwin.close(current) }
        for part in url.deletingLastPathComponent().path.split(separator: "/") {
            let next = openat(current, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw FileCandidateFailure.invalidTicket }
            _ = Darwin.close(current)
            current = next
        }
        var attributes = stat()
        guard fstat(current, &attributes) == 0, attributes.st_uid == geteuid(),
              attributes.st_mode & 0o777 == 0o700 else { throw FileCandidateFailure.invalidTicket }
    }

    public static func load(_ url: URL) throws -> FileCandidateTicket {
        try validateTicketURL(url)
        let file = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw FileCandidateFailure.invalidTicket }
        defer { _ = Darwin.close(file) }
        var attributes = stat()
        guard fstat(file, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_uid == geteuid(), attributes.st_mode & 0o777 == 0o600,
              attributes.st_nlink == 1, attributes.st_size > 0, attributes.st_size <= 1024 else {
            throw FileCandidateFailure.invalidTicket
        }
        var bytes = Data(count: Int(attributes.st_size))
        let count = bytes.withUnsafeMutableBytes { Darwin.read(file, $0.baseAddress, $0.count) }
        guard count == bytes.count, let ticket = try? JSONDecoder().decode(Self.self, from: bytes) else {
            throw FileCandidateFailure.invalidTicket
        }
        return ticket
    }

    public func write(_ url: URL) throws {
        try Self.validateTicketURL(url)
        let file = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw FileCandidateFailure.invalidTicket }
        defer { _ = Darwin.close(file) }
        let bytes = try JSONEncoder().encode(self)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(file, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw FileCandidateFailure.invalidTicket }
            offset += count
        }
        let parent = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw FileCandidateFailure.invalidTicket }
        defer { _ = Darwin.close(parent) }
        guard fsync(file) == 0, fsync(parent) == 0 else { throw FileCandidateFailure.invalidTicket }
    }
}

public enum FileCandidateFixture {
    public static func execute(_ mode: String, ticketURL: URL, proofFD: Int32?,
                               process: FileKeychainNoUIProcess) throws {
        let ticket: FileCandidateTicket
        if mode == "create" { ticket = FileCandidateTicket(); try ticket.write(ticketURL) }
        else { ticket = try FileCandidateTicket.load(ticketURL) }
        let store = try FileKeychainCandidate(namespace: ticket.namespace, noUIProcess: process)
        switch mode {
        case "create":
            do {
                let secret = try FileCandidateSecret.random()
                guard store.save(secret, as: ticket.unapproved, authorization: .notGranted) == .notAuthorized,
                      case .missing = store.read(ticket.unapproved) else { throw FileCandidateFailure.unexpectedPolicy }
                switch store.save(secret, as: ticket.reference, authorization: .granted) {
                case .saved: break
                case .failed(let failure): throw FileCandidateFailure.keychain(failure)
                case .notAuthorized: throw FileCandidateFailure.unexpectedPolicy
                }
                print("FILE CANDIDATE authorized_save_succeeded: true")
                guard store.save(try .random(), as: ticket.reference, authorization: .granted) == .failed(.duplicate) else {
                    throw FileCandidateFailure.unexpectedPolicy
                }
                let observed = try read(store, ticket.reference)
                guard observed.matches(secret) else { throw FileCandidateFailure.proofMismatch }
                let wrong = try FileKeychainCandidate(namespace: UUID(), noUIProcess: process)
                guard case .missing = wrong.read(ticket.reference),
                      case .missing = store.read(.init(kind: .password)) else { throw FileCandidateFailure.unexpectedPolicy }
                let replacement = try FileCandidateSecret.random()
                guard store.replace(replacement, at: ticket.reference, authorization: .notGranted) == .notAuthorized,
                      store.replace(replacement, at: ticket.reference, authorization: .granted) == .updated(ticket.reference),
                      try read(store, ticket.reference).matches(replacement) else { throw FileCandidateFailure.unexpectedPolicy }
                try inspect(store, ticket.reference)
                guard let proofFD else { throw FileCandidateFailure.invalidTicket }
                try writeProof(replacement, to: proofFD)
                print("FILE CANDIDATE CRUD_no_remember_duplicate_update_wrong_reference: PASS")
            } catch {
                // No new attempt on failure. Exact own entries only; never delete ticket until
                // absence is verified. A failed cleanup is explicit and recovery stays possible.
                do { try cleanup(store, ticket, ticketURL) }
                catch { print("FILE CANDIDATE cleanup_complete: false; exact ticket retained") }
                throw error
            }
        case "read":
            let observed = try read(store, ticket.reference)
            try inspect(store, ticket.reference)
            guard let proofFD else { throw FileCandidateFailure.invalidTicket }
            try writeProof(observed, to: proofFD)
            print("FILE CANDIDATE existing_secret_read: PASS")
        case "wrong-reference":
            let wrongNamespace = try FileKeychainCandidate(namespace: UUID(), noUIProcess: process)
            guard case .missing = wrongNamespace.read(ticket.reference),
                  case .missing = store.read(.init(kind: .password)) else { throw FileCandidateFailure.unexpectedPolicy }
            print("FILE CANDIDATE concurrent_wrong_namespace_and_reference_missing: PASS")
        case "deny":
            switch store.read(ticket.reference) {
            case .available: throw FileCandidateFailure.unexpectedPolicy
            case .missing: throw FileCandidateFailure.invalidItem // Do not accept a wrong query as denial evidence.
            case .manualEntryRequired(let failure):
                guard [.interactionNotAllowed, .denied, .cancelled].contains(failure) else {
                    throw FileCandidateFailure.keychain(failure)
                }
                print("FILE CANDIDATE different_code_read_denied: true; status=\(failure)")
            }
        case "cleanup":
            try cleanup(store, ticket, ticketURL)
            print("FILE CANDIDATE exact_cleanup_and_absence: PASS")
        default: throw FileCandidateFailure.invalidTicket
        }
    }

    private static func read(_ store: FileKeychainCandidate, _ reference: CredentialReference) throws -> FileCandidateSecret {
        switch store.read(reference) {
        case .available(let secret): return secret
        case .missing: throw FileCandidateFailure.invalidItem
        case .manualEntryRequired(let failure): throw FileCandidateFailure.keychain(failure)
        }
    }

    private static func inspect(_ store: FileKeychainCandidate, _ reference: CredentialReference) throws {
        let acl = try store.inspectOwnItem(reference)
        print("FILE CANDIDATE current_default_keychain_unlocked: \(try store.currentKeychainUnlocked())")
        print("FILE CANDIDATE item_in_selected_file_keychain: \(acl.belongsToSelectedFileKeychain)")
        print("FILE CANDIDATE synchronizable_attribute_present: \(acl.synchronizableAttributePresent)")
        print("FILE CANDIDATE synchronizable_attribute_false: \(acl.synchronizableAttributeIsFalse)")
        print("FILE CANDIDATE decrypt_acl_count: \(acl.decryptACLCount)")
        print("FILE CANDIDATE trusted_application_count: \(acl.trustedApplicationCount)")
        print("FILE CANDIDATE unrestricted_decrypt_acl_count: \(acl.unrestrictedDecryptACLCount)")
        print("FILE CANDIDATE uninspectable_decrypt_acl_count: \(acl.uninspectableDecryptACLCount)")
        print("FILE CANDIDATE creator_matches_trusted_application: \(acl.creatorMatchesTrustedApplication)")
        print("FILE CANDIDATE requires_passphrase_for_decrypt: \(acl.requiresPassphraseForDecrypt)")
        guard acl.belongsToSelectedFileKeychain, acl.decryptACLCount > 0,
              acl.trustedApplicationCount == 1, acl.unrestrictedDecryptACLCount == 0,
              acl.uninspectableDecryptACLCount == 0, acl.creatorMatchesTrustedApplication,
              !acl.requiresPassphraseForDecrypt, !acl.synchronizableAttributePresent || acl.synchronizableAttributeIsFalse else {
            throw FileCandidateFailure.unexpectedPolicy
        }
    }

    private static func cleanup(_ store: FileKeychainCandidate, _ ticket: FileCandidateTicket, _ url: URL) throws {
        for item in [ticket.reference, ticket.unapproved] {
            switch store.delete(item) {
            case .deleted, .alreadyAbsent: break
            case .retryRequired(let failure): throw FileCandidateFailure.keychain(failure)
            }
            guard case .missing = store.read(item) else { throw FileCandidateFailure.invalidItem }
        }
        guard store.delete(ticket.reference) == .alreadyAbsent else { throw FileCandidateFailure.invalidItem }
        guard unlink(url.path) == 0 else { throw FileCandidateFailure.invalidTicket }
    }

    private static func writeProof(_ secret: FileCandidateSecret, to descriptor: Int32) throws {
        var attributes = stat()
        guard descriptor > STDERR_FILENO, fstat(descriptor, &attributes) == 0,
              attributes.st_mode & S_IFMT == S_IFIFO else { throw FileCandidateFailure.invalidTicket }
        let proof = Data(SHA256.hash(data: secret.bytes))
        let count = proof.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
        guard count == proof.count else { throw FileCandidateFailure.invalidTicket }
    }
}
