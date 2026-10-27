import Foundation
import OpenLXSSHSecurity
import RealIntegrationCore

/// Typed status mapping only; never print Error/OS dialogs or perform a UI retry.
enum CredentialStorePublicStatus {
    static func failure(_ value: CredentialFailure) -> CredentialStorePublicFailure {
        switch value {
        case .cancelled: return .cancelled
        case .interactionNotAllowed: return .interactionNotAllowed
        case .unavailable: return .unavailable
        case .denied: return .denied
        case .duplicate: return .duplicate
        case .invalidData: return .invalidData
        case .closed: return .closed
        case .interactionPolicyRestoreFailed: return .interactionPolicyRestoreFailed
        case .status: return .otherStatus
        }
    }
    static func save(_ value: CredentialSaveResult) -> CredentialStorePublicSaveOutcome {
        switch value {
        case .saved: return .saved
        case .notAuthorized: return .notAuthorized
        case .failed(let reason): return .failed(failure(reason))
        }
    }
    static func delete(_ value: CredentialDeleteResult) -> CredentialStorePublicDeleteOutcome {
        switch value {
        case .deleted: return .deleted
        case .alreadyAbsent: return .alreadyAbsent
        case .retryRequired(let reason): return .retryRequired(failure(reason))
        }
    }
}
