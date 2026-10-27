import Foundation

/// Immutable credential-consumer-only stop policy. It never toggles a process or
/// store setting. All callers run on MainActor so stop and a same-tick success
/// are checked in a deterministic order; cleanup after confirmed save bypasses
/// this admission guard deliberately and remains exact-reference only.
@MainActor public struct CredentialStorePublicStopGuard {
    private let isStopRequested: @MainActor () -> Bool
    private let isCancelled: @MainActor () -> Bool
    public init(isStopRequested: @escaping @MainActor () -> Bool,
                isCancelled: @escaping @MainActor () -> Bool = { Task.isCancelled }) {
        self.isStopRequested = isStopRequested; self.isCancelled = isCancelled
    }
    public func check() throws {
        guard !isStopRequested(), !isCancelled(), !Task.isCancelled else { throw CredentialStorePublicError.cancelled }
    }
    public func checkCurrent(_ current: Bool) throws {
        try check() // STOP wins over stale-generation or already-connected checks.
        guard current else { throw CredentialStorePublicError.staleGeneration }
    }
    public func checkedValue<T>(_ operation: @MainActor () async throws -> T) async throws -> T {
        try check()
        let value = try await operation()
        try check() // Never release an awaited fixture/store secret after stop.
        return value
    }
}

/// Explicit whitelist for the existing SavedPasswordPublicBudget's typed errors.
/// Unknown external errors still fail closed without an Error.description dump.
public enum CredentialStorePublicErrorMap {
    public static func classify(_ error: Error, fallback: CredentialStorePublicError) -> CredentialStorePublicError {
        if let own = error as? CredentialStorePublicError { return own }
        if error is CancellationError { return .cancelled }
        guard let budget = error as? SavedPasswordPublicError else { return fallback }
        switch budget {
        case .invalidContract: return .invalidContract
        case .unsafeMaterial: return .unsafeMaterial
        case .provenanceMismatch: return .provenanceMismatch
        case .fingerprintMismatch: return .fingerprintMismatch
        case .staleGeneration: return .staleGeneration
        case .extraProviderCall: return .extraProviderCall
        case .extraManualRequest: return .extraManualRequest
        case .unknownManualRequest: return .unknownManualRequest
        case .gateNotCovered: return .gateNotCovered
        case .providerFailed: return .providerFailed
        case .cancelled: return .cancelled
        case .timeout: return .timeout
        case .connectionFailed: return .connectionFailed
        case .cleanupIncomplete: return .cleanupIncomplete
        }
    }
}

/// The recovery writer and pure injected tests share the same durability order.
/// Each closure must finish successfully; no later step or external admission
/// is reached after an identity/fsync failure.
public enum CredentialStorePublicDurability {
    public static func commit(validateIdentity: () throws -> Void, writeAndSyncFile: () throws -> Void,
                              syncRun: () throws -> Void, syncParent: () throws -> Void) throws {
        try validateIdentity()
        try writeAndSyncFile()
        try validateIdentity()
        try syncRun()
        try syncParent()
        try validateIdentity()
    }
}
