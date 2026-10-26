// swift-tools-version: 6.2
import PackageDescription

// Deliberately offline: no dependency on the App, Transport graph, or a remote package.
// The separately reviewed SignedDriver source consumes the real public Transport API.
let package = Package(
    name: "OpenLXSSHStabilityAcceptancePreparation",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "StabilityCore", targets: ["StabilityCore"]),
        .executable(name: "stability-preflight", targets: ["StabilityPreflight"])
    ],
    targets: [
        .target(name: "StabilityPOSIX"),
        .target(name: "StabilityCore", dependencies: ["StabilityPOSIX"]),
        .executableTarget(name: "StabilityPreflight", dependencies: ["StabilityCore"]),
        .testTarget(name: "StabilityCoreTests", dependencies: ["StabilityCore", "StabilityPOSIX"])
    ],
    swiftLanguageModes: [.v6]
)
