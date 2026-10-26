// swift-tools-version: 6.2
import PackageDescription

// Offline safety tests only. The production-API consumer is compiled separately
// by build_host.py from reviewed existing sources, without package resolution.
let package = Package(
    name: "OpenLXSSHRealIntegrationOffline",
    platforms: [.macOS(.v15)],
    products: [.executable(name: "real-integration-preflight", targets: ["RealIntegrationPreflight"])],
    targets: [
        .target(name: "RealIntegrationPOSIX"),
        .target(name: "RealIntegrationCore", dependencies: ["RealIntegrationPOSIX"]),
        .executableTarget(name: "RealIntegrationPreflight", dependencies: ["RealIntegrationCore"]),
        .testTarget(name: "RealIntegrationCoreTests", dependencies: ["RealIntegrationCore", "RealIntegrationPOSIX"])
    ],
    swiftLanguageModes: [.v6]
)
