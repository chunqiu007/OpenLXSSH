// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "OpenLXSSHTrust",
    platforms: [.macOS(.v15)], // Host-testable library; the App still requires macOS 26.
    products: [.library(name: "OpenLXSSHTrust", targets: ["OpenLXSSHTrust"])],
    targets: [
        .target(name: "OpenLXSSHTrust"),
        // Only XCTest depends on this executable. It is not a library/App product or helper.
        .executableTarget(
            name: "OpenLXSSHTrustTestFixture",
            dependencies: ["OpenLXSSHTrust"],
            path: "Tests/Fixtures/OpenLXSSHTrustTestFixture"
        ),
        .testTarget(
            name: "OpenLXSSHTrustTests",
            dependencies: ["OpenLXSSHTrust", "OpenLXSSHTrustTestFixture"]
        )
    ],
    swiftLanguageModes: [.v6]
)
