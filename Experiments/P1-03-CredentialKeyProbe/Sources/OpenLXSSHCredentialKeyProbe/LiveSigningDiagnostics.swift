import Foundation
import Security

/// Self-inspection only; no other processes, Keychain items or certificates are queried.
/// SecTask's returned values show presence, not provisioning authorization. The SDK does
/// not expose SecTaskEntitlementsValidated and marks SecTaskGetCodeSignStatus unavailable
/// on macOS; this experiment deliberately does not call either private/unavailable API.
public enum LiveSigningDiagnostics {
    public static func summary() -> [String: Bool] {
        var result = [String: Bool]()
        guard let task = SecTaskCreateFromSelf(nil) else { return ["self_task_available": false] }
        result["self_task_available"] = true
        var taskError: Unmanaged<CFError>?
        let appID = SecTaskCopyValueForEntitlement(task, "com.apple.application-identifier" as CFString, &taskError) as? String
        result["runtime_app_id_present"] = appID != nil
        result["runtime_app_id_query_error"] = taskError != nil
        _ = taskError?.takeRetainedValue()
        taskError = nil
        let groups = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, &taskError) as? [String]
        result["runtime_explicit_access_groups_present"] = groups != nil
        result["runtime_access_groups_query_error"] = taskError != nil
        _ = taskError?.takeRetainedValue()
        result["runtime_explicit_groups_match_private_default"] = groups != nil && groups == appID.map { [$0] }
        result["provisioning_authorization_proven_by_sectask_value"] = false
        result["embedded_provisioning_profile_present"] = Bundle.main.url(forResource: "embedded", withExtension: "provisionprofile") != nil

        var code: SecCode?
        let copyStatus = SecCodeCopySelf(SecCSFlags(), &code)
        result["self_code_available"] = copyStatus == errSecSuccess
        if let code {
            result["self_dynamic_signature_valid"] = SecCodeCheckValidity(code, SecCSFlags(), nil) == errSecSuccess
            var dictionary: CFDictionary?
            let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation)
            // SecCodeCopySigningInformation's public C header explicitly accepts a dynamic
            // SecCodeRef, but its nominal parameter is SecStaticCodeRef. Swift requires the
            // documented toll-free Security opaque-reference conversion at this boundary.
            let signingCode = unsafeBitCast(code, to: SecStaticCode.self)
            let status = SecCodeCopySigningInformation(signingCode, flags, &dictionary)
            result["self_signing_information_available"] = status == errSecSuccess
            if let info = dictionary as? [String: Any] {
                let team = info[kSecCodeInfoTeamIdentifier as String] as? String
                let identifier = info[kSecCodeInfoIdentifier as String] as? String
                result["runtime_app_id_matches_signature_team_and_identifier"] = team != nil && identifier != nil && appID == "\(team!).\(identifier!)"
                result["self_dynamic_status_available"] = info[kSecCodeInfoStatus as String] != nil
            }
        }
        return result
    }
}
