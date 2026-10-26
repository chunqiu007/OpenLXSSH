import Foundation
import RealIntegrationCore

@main enum Main {
    static func main() {
        do {
            let options = try Options.parse(Array(CommandLine.arguments.dropFirst()))
            if options.action == .help { print(Options.help) }
            else if options.action == .validate { print("Syntax valid; contract/credentials NOT opened; no connection or acceptance.") }
            else { throw SmokeError.signedAppRequired }
        } catch {
            fputs("Preflight refused: \((error as? SmokeError)?.rawValue ?? "invalidArguments").\n", stderr)
            exit(2)
        }
    }
}
