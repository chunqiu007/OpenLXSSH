import Foundation
import RealIntegrationCore

@main enum Main {
    static func main() {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            if arguments.first == "--saved-password-public" {
                let options = try SavedPasswordPublicOptions.parse(Array(arguments.dropFirst()))
                if options.action == .help { print(SavedPasswordPublicOptions.help) }
                else if options.action == .validate { print("Saved-password public syntax valid; files NOT opened; no Keychain, Docker or connection.") }
                else { throw SmokeError.signedAppRequired }
                return
            }
            if arguments.first == "--sftp-otp-negative" {
                let options = try SFTPOTPNegativeOptions.parse(Array(arguments.dropFirst()))
                if options.action == .help { print(SFTPOTPNegativeOptions.help) }
                else if options.action == .validate { print("OTP negative syntax valid; files NOT opened; no Docker or connection.") }
                else { throw SmokeError.signedAppRequired }
                return
            }
            if arguments.first == "--sftp-auth" {
                let options = try SFTPAuthOptions.parse(Array(arguments.dropFirst()))
                if options.action == .help { print(SFTPAuthOptions.help) }
                else if options.action == .validate { print("SFTP auth syntax valid; files NOT opened; no Docker or connection.") }
                else { throw SmokeError.signedAppRequired }
                return
            }
            if arguments.first == "--openssh-auth" {
                let options = try OpenSSHOptions.parse(Array(arguments.dropFirst()))
                if options.action == .help { print(OpenSSHOptions.help) }
                else if options.action == .validate { print("OpenSSH auth syntax valid; files NOT opened; no Docker or connection.") }
                else { throw SmokeError.signedAppRequired }
                return
            }
            if arguments.first == "--auth-only" {
                let options = try MinaOptions.parse(Array(arguments.dropFirst()))
                if options.action == .help { print(MinaOptions.help) }
                else if options.action == .validate { print("AUTH-ONLY syntax valid; files NOT opened; no Docker or connection.") }
                else { throw SmokeError.signedAppRequired }
                return
            }
            let options = try Options.parse(arguments)
            if options.action == .help { print(Options.help) }
            else if options.action == .validate { print("Syntax valid; contract/credentials NOT opened; no connection or acceptance.") }
            else { throw SmokeError.signedAppRequired }
        } catch {
            fputs("Preflight refused: \((error as? SmokeError)?.rawValue ?? "invalidArguments").\n", stderr)
            exit(2)
        }
    }
}
