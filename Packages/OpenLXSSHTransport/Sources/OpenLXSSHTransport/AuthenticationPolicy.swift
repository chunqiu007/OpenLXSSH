import Foundation
import Darwin
import COpenLXSSHAskpass
import OpenLXSSHAskpass

/// Explicit per-connection authorization, supplied by the application. The
/// provider may consult its own credential store; transport never imports one.
/// This type is intentionally not Codable/Equatable and has no secret logging.
public struct SavedPasswordAuthorization: Sendable {
    let provider: @Sendable (SessionToken) async throws -> AuthenticationSecret?
    public init(provider: @escaping @Sendable (SessionToken) async throws -> AuthenticationSecret?) { self.provider = provider }
}

struct SavedPasswordBudget {
    let eligible: Bool
    private(set) var initialRequestObserved = false
    mutating func claim(_ request: AuthenticationRequest) -> Bool {
        // First authenticated control-plane request consumes the only potential
        // allowance, even when a hint disqualifies it. Never inspect prompt text.
        guard !initialRequestObserved else { return false }
        initialRequestObserved = true
        return eligible && request.hint == nil && request.kind == .unknownMasked
    }
}

enum PasswordAutomationGate {
    static func evaluate() async -> Bool {
        await Task.detached {
            guard operatingSystemBuild() == "24H32", ap_system_ssh_signed() == 0,
                  let result = try? BoundedTool.run("/usr/bin/ssh", ["-V"], seconds: 3, includeStandardError: true),
                  result.status == 0,
                  String(data: result.output, encoding: .utf8) == "OpenSSH_9.9p2, LibreSSL 3.3.6\n" else { return false }
            return true
        }.value
    }
    static func operatingSystemBuild() -> String? {
        var size = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0, size < 128 else { return nil }
        var value = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.osversion", &value, &size, nil, 0) == 0 else { return nil }
        return String(cString: value)
    }
}

/// Fixed LocalCommand only: no host/user/tokens/untrusted shell fragments.
/// ssh expands percent tokens before running $SHELL -c, so % must be doubled.
public enum AuthenticatedEventCommand {
    public static func make(helper: BundledAskpassHelper) throws -> String {
        try quoteExecutable(helper.url.path)
    }
    #if TRANSPORT_HOST_PROBE
    package static func quoteExecutableForProbe(_ path: String) throws -> String { try quoteExecutable(path) }
    #endif
    static func quoteExecutable(_ path: String) throws -> String {
        guard path.hasPrefix("/"), !path.unicodeScalars.contains(where: {
            CharacterSet.controlCharacters.contains($0) || CharacterSet.illegalCharacters.contains($0) || $0.value == 0x2028 || $0.value == 0x2029
        }) else { throw TransportError.invalidConfiguration }
        let escaped = path.replacingOccurrences(of: "%", with: "%%").replacingOccurrences(of: "'", with: "'\\''")
        // Two arguments cannot collide with a server-controlled one-argument
        // Askpass prompt, even when that prompt is literally --authenticated-event.
        return "exec '" + escaped + "' --authenticated-event v1"
    }
}
