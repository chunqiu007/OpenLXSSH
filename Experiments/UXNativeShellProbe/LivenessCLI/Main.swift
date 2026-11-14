import Darwin
import Foundation
import UXNativeShellProbeSupport
#if NATIVE_LIVENESS_FIXTURE
import UXNativeShellLivenessFixture
#endif

@main enum NativeLivenessMain {
    static func main() async {
        do {
            #if NATIVE_LIVENESS_FIXTURE
            let root = ShellProbeBuildContext.buildRoot
            #else
            let root = ShellProbeCommand.sourceBuildRoot
            #endif
            let options = try NativeLivenessOptions.parse(Array(CommandLine.arguments.dropFirst()), buildRoot: root)
            guard options.contractPath != nil else {
                print("Native liveness consumer inert. Private PIPE supervisor/source/build/live release required; no I/O performed.")
                return
            }
            #if NATIVE_LIVENESS_FIXTURE
            exit(await NativeLivenessFixtureConsumer.execute(options: options))
            #else
            throw NativeLivenessControlError.arguments
            #endif
        } catch {
            fputs("Native liveness arguments or unavailable consumer refused.\n", stderr)
            exit(64)
        }
    }
}
