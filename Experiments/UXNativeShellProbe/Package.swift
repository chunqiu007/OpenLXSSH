// swift-tools-version: 6.2
import PackageDescription

// Isolated test consumer only. No changes to runtime package exports, pins or native inputs.
let package = Package(
    name: "UXNativeShellProbe",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(path: "../../Packages/OpenLXSSHFiles"),
        .package(path: "../../Packages/OpenLXSSHTrust")
    ],
    targets: [
        .target(name: "UXNativeShellProbeSupport", dependencies: [
            .product(name: "OpenLXSSHFiles", package: "OpenLXSSHFiles"),
            .product(name: "OpenLXSSHTrust", package: "OpenLXSSHTrust")
        ]),
        .executableTarget(name: "UXNativeShellProbe", dependencies: ["UXNativeShellProbeSupport"]),
        .testTarget(name: "UXNativeShellProbeTests", dependencies: ["UXNativeShellProbeSupport"])
    ],
    swiftLanguageModes: [.v6]
)
