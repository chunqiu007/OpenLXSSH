import Foundation

public struct LiveKeychainLimitation: Error, Equatable, Sendable {
    public let operation: String
    public let failure: CredentialFailure
}

public struct LiveKeychainCleanupFailure: Error, Equatable, Sendable {
    public let failure: CredentialFailure
    public let operationFailure: LiveKeychainLimitation?
    public let saveSucceeded: Bool
    /// Non-secret exact retry identifiers, retained if a future signed probe saves but cannot delete.
    public let namespace: UUID
    public let references: [CredentialReference]
}

/// Touches only two UUID account names in a newly generated UUID service namespace.
/// A failure is NOT treated as a passing CRUD test, and never triggers a weaker backend.
public enum LiveKeychainProbe {
    public static func run() throws {
        let namespace = UUID()
        let store = CredentialStore(namespace: namespace)
        let reference = CredentialReference(kind: .password)
        let unapproved = CredentialReference(kind: .privateKeyPassphrase)
        let secret = try SecretBytes.random()
        var cleanupFailure: CredentialFailure?
        var operationFailure: (any Error)?
        var saveSucceeded = false
        do {
            // A defer always attempts exact cleanup, even after partial add or read failures.
            defer {
                for item in [reference, unapproved] {
                    if case .retryRequired(let failure) = store.delete(item) { cleanupFailure = failure }
                }
            }
            guard store.save(secret, as: unapproved, authorization: .notGranted) == .notAuthorized else {
                throw LiveKeychainLimitation(operation: "authorization", failure: .invalidData)
            }
            // Continue to attempt the exact authorized write even if a missing-item read was
            // denied, so real CRUD evidence distinguishes lookup and save capabilities.
            var missingReadFailure: CredentialFailure?
            switch store.read(unapproved) {
            case .missing: break
            case .manualEntryRequired(let failure): missingReadFailure = failure
            case .available: throw LiveKeychainLimitation(operation: "unauthorized item unexpectedly present", failure: .invalidData)
            }
            switch store.save(secret, as: reference, authorization: .granted) {
            case .saved: saveSucceeded = true
            case .failed(let failure): throw LiveKeychainLimitation(operation: "save", failure: failure)
            case .notAuthorized: throw LiveKeychainLimitation(operation: "save", failure: .invalidData)
            }
            if let missingReadFailure { throw LiveKeychainLimitation(operation: "read missing", failure: missingReadFailure) }
            guard store.save(secret, as: reference, authorization: .granted) == .failed(.duplicate) else {
                throw LiveKeychainLimitation(operation: "duplicate guard", failure: .invalidData)
            }
            switch store.read(reference) {
            case .available(let read) where read.matches(secret): break
            case .manualEntryRequired(let failure): throw LiveKeychainLimitation(operation: "read", failure: failure)
            default: throw LiveKeychainLimitation(operation: "read mismatch", failure: .invalidData)
            }
            let replacement = try SecretBytes.random()
            switch store.replace(replacement, at: reference, authorization: .granted) {
            case .updated: break
            case .failed(let failure): throw LiveKeychainLimitation(operation: "explicit update", failure: failure)
            default: throw LiveKeychainLimitation(operation: "explicit update", failure: .invalidData)
            }
            switch store.read(reference) {
            case .available(let read) where read.matches(replacement): break
            case .manualEntryRequired(let failure): throw LiveKeychainLimitation(operation: "read updated", failure: failure)
            default: throw LiveKeychainLimitation(operation: "read updated mismatch", failure: .invalidData)
            }
            switch store.delete(reference) {
            case .deleted: break
            case .retryRequired(let failure): throw LiveKeychainLimitation(operation: "delete", failure: failure)
            case .alreadyAbsent: throw LiveKeychainLimitation(operation: "delete", failure: .invalidData)
            }
            guard store.delete(reference) == .alreadyAbsent else {
                throw LiveKeychainLimitation(operation: "idempotent delete", failure: .invalidData)
            }
            guard case .missing = store.read(reference) else {
                throw LiveKeychainLimitation(operation: "read after delete", failure: .invalidData)
            }
        } catch { operationFailure = error }
        if let cleanupFailure {
            throw LiveKeychainCleanupFailure(failure: cleanupFailure,
                                             operationFailure: operationFailure as? LiveKeychainLimitation,
                                             saveSucceeded: saveSucceeded, namespace: namespace,
                                             references: [reference, unapproved])
        }
        if let operationFailure { throw operationFailure }
    }
}
