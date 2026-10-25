import Foundation
import Darwin
import OpenLXSSHAskpassProbe

let args = Array(CommandLine.arguments.dropFirst())
let environment = ProcessInfo.processInfo.environment
let code: Int32
switch args.first {
case "--lookup":
    code = args.count == 2 && temporaryMachServiceIsUnknown(args[1]) ? 0 : 1
    print("post_exit_service_unknown=\(code == 0)")
case "--standby": code = runStandbyFixture()
case "--fixture": code = runControlledFixture(arguments: Array(args.dropFirst()), environment: environment)
case "--client-fixture":
    if args.count == 2, args[1] == "nested" { code = runNestedFixture(environment: environment) }
    else if args.count == 2 { code = runClientFixture(mode: args[1], environment: environment) }
    else { code = 64 }
case "--self-test":
    do { try runSelfTest(image: executablePath(), adversary: args.count == 2 ? args[1] : nil); code = 0 }
    catch { print("FAIL self-test category=\((error as? ProbeError)?.rawValue ?? "assertion")"); code = 1 }
default:
    print("OpenLXSSH local askpass fixture. Use --self-test [adversary-path]. No SSH/network/Keychain integration.")
    code = 64
}
exit(code)
