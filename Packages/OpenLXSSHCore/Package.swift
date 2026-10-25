// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "OpenLXSSHCore",
    platforms: [.macOS(.v15)], // Host-testable core; the App still requires macOS 26.
    products: [.library(name: "OpenLXSSHCore", targets: ["OpenLXSSHCore"])],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", exact: "7.11.1")
    ],
    targets: [
        .target(name: "OpenLXSSHCore", dependencies: [.product(name: "GRDB", package: "GRDB.swift")]),
        // Test-only process fixture. Not an App product or a production helper.
        .executableTarget(name: "OpenLXSSHDatabaseFixture", dependencies: ["OpenLXSSHCore", .product(name: "GRDB", package: "GRDB.swift")]),
        .testTarget(name: "OpenLXSSHCoreTests", dependencies: ["OpenLXSSHCore", .product(name: "GRDB", package: "GRDB.swift")], resources: [.copy("Fixtures")])
    ],
    swiftLanguageModes: [.v6]
)
