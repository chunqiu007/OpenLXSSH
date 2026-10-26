import Darwin
import Foundation
import StabilityCore

@main enum Preflight {
    static func main() {
        do {
            let options = try Options.parse(Array(CommandLine.arguments.dropFirst()))
            switch options.action {
            case .help: print(Options.help)
            case .run:
                // This offline executable is structurally incapable of connecting:
                // its package has no Transport/SSH implementation or sockets.
                throw StabilityError.signedAppRequired
            case .validate:
                if options.credentials != nil || options.verifiedFingerprint != nil {
                    let fixture = try FixturePublic.inspect(options)
                    print("Read-only public fixture validation passed: 127.0.0.1:22221, host " + fixture.hostFingerprint)
                } else {
                    print("Read-only options valid; no fixture files inspected. Provide collected public fixture metadata and an independently verified fingerprint for material checks.")
                }
                print("Plan: \(options.mode.rawValue), 200 authenticated cycles / 5 sessions, required continuous duration \(options.durationSeconds)s; no network or output files created.")
                print("Not a real connection, 200-cycle, 24-hour, target-OS, whole-App PERF or UI acceptance result.")
            }
        } catch {
            let code = (error as? StabilityError)?.rawValue ?? "validationFailed"
            // Never interpolate argv, file contents, authentication prompts or errors.
            fputs("Stability preparation refused: \(code). See help; no secret details emitted.\n", stderr)
            exit(2)
        }
    }
}
