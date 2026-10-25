import Darwin
import Foundation
import P1PTYProbe

@main
struct P1PTYProbeCLI {
    static func main() async {
        do {
            let hold: Duration = CommandLine.arguments.dropFirst() == ["--snapshot-hold"] ? .seconds(4) : .zero
            for line in try await runLocalSmoke(snapshotHold: hold) { print(line) }
            print("P1-01 LOCAL PROBE PASS (not SSH authentication or product acceptance)")
        } catch {
            FileHandle.standardError.write(Data("p1-pty-probe failed: \(error)\n".utf8))
            exit(1)
        }
    }
}
