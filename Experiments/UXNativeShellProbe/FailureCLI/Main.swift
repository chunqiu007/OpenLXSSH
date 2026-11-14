import Darwin
import UXNativeFailureFixture
import UXNativeFailureSupport

@main enum UXNativeFailureConsumer {
    static func main() async {
        let command: NativeFailureCommand
        do {
            // Generated public constant only. Malformed argv returns 64 BEFORE any I/O owner.
            command = try NativeFailureCommand.parse(Array(CommandLine.arguments.dropFirst()),
                buildRoot: NativeFailureBuildContext.buildRoot)
        } catch {
            fputs("Native failure consumer arguments refused.\n", stderr); exit(64)
        }
        switch command {
        case .help: print(NativeFailureCommand.usage)
        case .validate: print("Syntax only; no file, credential, management, process or connection access.")
        case .live(let path, let testCase):
            exit(await NativeFailureFixtureConsumer.execute(contractPath: path, testCase: testCase))
        }
    }
}
