import Darwin
import UXNativeShellProbeSupport
#if NATIVE_SHELL_LIVE_CONSUMER
import UXNativeShellFixture
#endif

@main enum UXNativeShellProbe {
    static func main() async {
        do {
            #if NATIVE_SHELL_LIVE_CONSUMER
            let buildRoot = ShellProbeBuildContext.buildRoot
            #else
            let buildRoot = ShellProbeCommand.sourceBuildRoot
            #endif
            switch try ShellProbeCommand.parse(Array(CommandLine.arguments.dropFirst()), buildRoot: buildRoot) {
            case .help: print(ShellProbeCommand.usage)
            case .validate(let fixture):
                print("VALID syntax only: fixture=\(fixture.rawValue) loopbackPort=\(fixture.port); no I/O performed.")
            case .validateContract, .validateCase:
                print("VALID contract path syntax only; no file was opened; no fixture/credential/endpoint checks performed.")
            case .live(let contractPath):
                #if NATIVE_SHELL_LIVE_CONSUMER
                exit(await NativeShellFixtureConsumer.execute(contractPath: contractPath))
                #else
                throw ShellProbeError.liveNotReleased
                #endif
            case .liveCase(let contractPath, let testCase):
                #if NATIVE_SHELL_LIVE_CONSUMER
                exit(await NativeShellFixtureConsumer.execute(contractPath: contractPath, testCase: testCase))
                #else
                throw ShellProbeError.liveNotReleased
                #endif
            }
        } catch {
            fputs("Arguments or unavailable live consumer refused. Use --help; no captured details emitted.\n", stderr)
            exit(64)
        }
    }
}
