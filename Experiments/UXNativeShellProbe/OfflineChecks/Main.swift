import Darwin
import UXNativeShellFixture

@main enum UXNativeShellFixtureOfflineChecks {
    static func main() {
        do {
            let count = try NativeShellFixtureOfflineChecks.run()
            print("Synthetic offline fixture contract/budget checks passed: \(count). No files, Docker, credentials or sockets.")
        } catch {
            fputs("Synthetic offline checks failed; no captured details emitted.\n", stderr)
            exit(1)
        }
    }
}
