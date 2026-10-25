// swift-tools-version: 6.2
import PackageDescription
import Foundation

// Explicit local verification only. Shipping clients always use the default macOS 26 graph.
let hostProbe = ProcessInfo.processInfo.environment["OPENLXSSH_TRANSPORT_HOST_PROBE"] == "1"
let package = Package(
    name: "OpenLXSSHTransport",
    platforms: [.macOS(hostProbe ? .v15 : .v26)],
    products: [
        .library(name: "OpenLXSSHTransport", targets: ["OpenLXSSHTransport"]),
        .executable(name: "openlxssh-askpass", targets: ["OpenLXSSHAskpassHelper"])
    ] + (hostProbe ? [.executable(name: "openlxssh-transport-fixture", targets: ["TransportFixture"])] : []),
    dependencies: [
        .package(path: "../OpenLXSSHTrust"),
        .package(url: "https://github.com/migueldeicaza/SwiftTerm.git", exact: "1.99.1")
    ],
    targets: [
        .target(name: "COpenLXSSHAskpass", cSettings: hostProbe ? [.define("TRANSPORT_HOST_PROBE")] : [], linkerSettings: [.linkedFramework("Security"), .linkedLibrary("bsm")]),
        .target(name: "OpenLXSSHAskpass", dependencies: ["COpenLXSSHAskpass"]),
        .target(name: "OpenLXSSHTransport", dependencies: ["OpenLXSSHAskpass", "COpenLXSSHAskpass", .product(name: "OpenLXSSHTrust", package: "OpenLXSSHTrust"), .product(name: "SwiftTerm", package: "SwiftTerm")], swiftSettings: hostProbe ? [.define("TRANSPORT_HOST_PROBE")] : []),
        .executableTarget(name: "OpenLXSSHAskpassHelper", dependencies: ["OpenLXSSHAskpass"])
    ] + (hostProbe ? [
        .testTarget(name: "OpenLXSSHTransportTests", dependencies: ["OpenLXSSHTransport", "OpenLXSSHAskpass", "COpenLXSSHAskpass"]),
        .executableTarget(name: "TransportFixture", dependencies: ["OpenLXSSHTransport", "OpenLXSSHAskpass", "COpenLXSSHAskpass"], swiftSettings: [.define("TRANSPORT_HOST_PROBE"), .unsafeFlags(["-Xcc", "-DTRANSPORT_HOST_PROBE"])])
    ] : []),
    swiftLanguageModes: [.v5]
)
