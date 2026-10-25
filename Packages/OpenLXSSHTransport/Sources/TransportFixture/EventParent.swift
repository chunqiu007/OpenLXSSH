import Foundation
import Darwin
import OpenLXSSHTransport

// Host-only controlled parent; inherits grant, but no secret. The helper's
// immediate parent must be this LocalProcess child, not the test host.
func runEventParent(helper: String, mode: String) -> Int32 {
    func invoke() -> Int32 {
        // Match ssh's $SHELL -c then fixed exec path; exec preserves PPID.
        // Percent expansion is performed by ssh before the shell, simulated
        // here only for the quoted literal %% (never arbitrary tokens).
        guard let quoted = try? AuthenticatedEventCommand.quoteExecutableForProbe(helper) else { return 70 }
        let command = quoted.replacingOccurrences(of: "%%", with: "%")
        let argumentStrings: [String] = ["/bin/sh", "-c", command]
        let args: [UnsafeMutablePointer<CChar>?] = argumentStrings.map { strdup($0) } + [nil]
        let envStrings = ProcessInfo.processInfo.environment.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
        let env = envStrings.map { strdup($0) } + [nil]
        defer { (args + env).forEach { free($0) } }
        var pid: pid_t = 0
        let result = args.withUnsafeBufferPointer { argv in env.withUnsafeBufferPointer { environment in
            posix_spawn(&pid, "/bin/sh", nil, nil, UnsafeMutablePointer(mutating: argv.baseAddress!), UnsafeMutablePointer(mutating: environment.baseAddress!))
        } }
        guard result == 0 else { return 71 }
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
        return (status >> 8) & 0xff
    }
    if mode == "cancel" { usleep(500_000) }
    if mode == "wrong-parent" { usleep(300_000) }
    guard invoke() == 0 else { return 72 }
    if mode == "replay", invoke() == 0 { return 73 }
    usleep(100_000)
    return 0
}
