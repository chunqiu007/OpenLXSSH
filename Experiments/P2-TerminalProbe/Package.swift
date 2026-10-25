// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "OpenLXSSHTerminalProbe",
    // This local experiment runs on the macOS 15 host. The product still targets macOS 26.
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "OpenLXSSHTerminalProbe", targets: ["OpenLXSSHTerminalProbe"]),
        .executable(name: "openlxssh-terminal-fixture", targets: ["TerminalFixture"])
    ],
    dependencies: [
        .package(url: "https://github.com/migueldeicaza/SwiftTerm.git", exact: "1.99.1")
    ],
    targets: [
        .target(name: "OpenLXSSHTerminalCore", dependencies: [
            .product(name: "SwiftTerm", package: "SwiftTerm")
        ], swiftSettings: [.define("P2_PREVIEW_API")]),
        .executableTarget(name: "OpenLXSSHTerminalProbe", dependencies: ["OpenLXSSHTerminalCore"]),
        .executableTarget(name: "TerminalFixture"),
        .testTarget(name: "OpenLXSSHTerminalProbeTests", dependencies: ["OpenLXSSHTerminalCore"])
    ],
    swiftLanguageModes: [.v5]
)
