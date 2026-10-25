// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "OpenLXSSHSecurity",
    // The library can be exercised on the macOS 15 build host. The App remains macOS 26.
    platforms: [.macOS(.v15)],
    products: [.library(name: "OpenLXSSHSecurity", targets: ["OpenLXSSHSecurity"])],
    targets: [
        .target(name: "SecurityPOSIX"),
        .target(name: "OpenLXSSHSecurity", dependencies: ["SecurityPOSIX"]),
        // Local verification only, not an application helper or shipping CLI.
        .executableTarget(name: "OpenLXSSHSecurityFixture", dependencies: ["OpenLXSSHSecurity", "SecurityTestSupport"], path: "Tests/Fixtures"),
        .target(name: "SecurityTestSupport", dependencies: ["SecurityPOSIX"], path: "Tests/SecurityTestSupport"),
        .testTarget(name: "OpenLXSSHSecurityTests", dependencies: ["OpenLXSSHSecurity", "SecurityTestSupport"])
    ],
    swiftLanguageModes: [.v6]
)
