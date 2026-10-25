// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "OpenLXSSHHostTrustProbe",
    platforms: [
        // Local experiment only. The product deployment target remains macOS 26.
        .macOS(.v15)
    ],
    products: [
        .library(name: "OpenLXSSHHostTrustProbe", targets: ["OpenLXSSHHostTrustProbe"]),
        .executable(name: "p1-host-trust-probe", targets: ["HostTrustProbeCLI"])
    ],
    targets: [
        .target(name: "OpenLXSSHHostTrustProbe"),
        .executableTarget(name: "HostTrustProbeCLI", dependencies: ["OpenLXSSHHostTrustProbe"]),
        .testTarget(name: "HostTrustProbeTests", dependencies: ["OpenLXSSHHostTrustProbe"])
    ],
    swiftLanguageModes: [.v6]
)
