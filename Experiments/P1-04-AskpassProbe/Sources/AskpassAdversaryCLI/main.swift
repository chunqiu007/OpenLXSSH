import Foundation
import Darwin
import OpenLXSSHAskpassProbe

// Deliberately different signed image. Same UID, protocol, and leaked correlation
// metadata must not authorize this process as helper or broker.
let args = Array(CommandLine.arguments.dropFirst())
if args == ["--fake-broker"] {
    exit(runFakeBrokerFixture(environment: ProcessInfo.processInfo.environment))
}
exit(runUntrustedClientFixture(environment: ProcessInfo.processInfo.environment))
