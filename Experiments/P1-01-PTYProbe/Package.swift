// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "P1PTYProbe",
    platforms: [
        // Host-only experiment so it can run on the current macOS 15 machine.
        // The product remains Apple Silicon/macOS 26; this is not its package/target.
        .macOS(.v15)
    ],
    products: [
        .library(name: "P1PTYProbe", targets: ["P1PTYProbe"]),
        .executable(name: "p1-pty-probe", targets: ["P1PTYProbeCLI"])
    ],
    targets: [
        .target(name: "ProbePOSIX"),
        .target(
            name: "P1PTYProbe",
            dependencies: ["ProbePOSIX"]
        ),
        .executableTarget(
            name: "P1PTYProbeCLI",
            dependencies: ["P1PTYProbe"]
        ),
        .testTarget(
            name: "P1PTYProbeTests",
            dependencies: ["P1PTYProbe"]
        )
    ],
    swiftLanguageModes: [.v6]
)
