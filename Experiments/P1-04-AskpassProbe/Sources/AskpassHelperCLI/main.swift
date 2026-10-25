import Foundation
import Darwin
import OpenLXSSHAskpassProbe

let args = Array(CommandLine.arguments.dropFirst())
let environment = ProcessInfo.processInfo.environment
// Test-only modes are reachable only from explicit controlled fixture argv.
if args.count == 2 && args[0] == "--client-fixture" {
    if args[1] == "nested" { exit(runNestedFixture(environment: environment)) }
    exit(runClientFixture(mode: args[1], environment: environment))
}
// Ordinary Askpass invocation is exactly one display prompt; stdin is not read.
exit(runAskpassHelper(arguments: args, environment: environment))
