import Foundation
import OpenLXSSHAskpass
import Darwin

exit(runAskpassHelper(arguments: Array(CommandLine.arguments.dropFirst()), environment: ProcessInfo.processInfo.environment))
