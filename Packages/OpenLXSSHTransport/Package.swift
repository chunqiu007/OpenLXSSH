// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "OpenLXSSHTransport",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "OpenLXSSHTransport", targets: ["OpenLXSSHTransport"])
    ],
    dependencies: [
        .package(path: "../OpenLXSSHTrust"),
        .package(url: "https://github.com/migueldeicaza/SwiftTerm.git", exact: "1.99.1")
    ],
    targets: [
        .target(
            name: "OpenLXSSHTransport",
            dependencies: [
                .product(name: "OpenLXSSHTrust", package: "OpenLXSSHTrust"),
                .product(name: "SwiftTerm", package: "SwiftTerm")
            ]
        ),
        .testTarget(
            name: "OpenLXSSHTransportTests",
            dependencies: ["OpenLXSSHTransport"]
        )
    ],
    swiftLanguageModes: [.v6]
)
