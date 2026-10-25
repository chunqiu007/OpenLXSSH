// swift-tools-version: 6.2
import PackageDescription

// Verification-only external consumer. Never rebuilds native inputs or changes the Files package.
let package = Package(
    name: "OpenLXSSHLocalFileStressFixture",
    platforms: [.macOS(.v15)], // Runs on the current host; this is not a macOS 26 App runtime test.
    dependencies: [.package(path: "../../Packages/OpenLXSSHFiles")],
    targets: [
        .target(name: "StressMetrics"),
        .executableTarget(name: "OpenLXSSHLocalFileStress", dependencies: [
            "StressMetrics", .product(name: "OpenLXSSHFiles", package: "OpenLXSSHFiles")
        ])
    ],
    swiftLanguageModes: [.v6]
)
