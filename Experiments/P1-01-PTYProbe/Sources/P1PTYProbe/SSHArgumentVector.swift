import Foundation

/// P1-01 verifies argv boundaries only. This is NOT a product host/config validation policy.
public enum SSHArgumentVector {
    public static let executable = "/usr/bin/ssh"

    public static func inspectionArguments(host: String, port: UInt16 = 2222) throws -> [String] {
        guard !host.utf8.contains(0), port > 0 else { throw ProbeError.invalidConfiguration }
        // -G prints configuration and exits without DNS/connect; -F /dev/null excludes user config.
        // No ProxyCommand/Match directives, credentials, user config or known_hosts are involved.
        return ["-G", "-F", "/dev/null", "-o", "CanonicalizeHostname=no", "-p", String(port), "--", host]
    }
}
