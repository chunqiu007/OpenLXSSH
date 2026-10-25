// swift-tools-version: 6.0
import PackageDescription
import Foundation

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let native = root + "/.build/native/install"
let nativeHeaders: [SwiftSetting] = [.unsafeFlags(["-Xcc", "-I" + native + "/include"])]
// SwiftPM rewrites --triple's minimum OS to the manifest platform. This explicit compile-only
// switch is required to actually obtain minos 26.0; default host builds remain macOS 15.
let deployment = ProcessInfo.processInfo.environment["OPENLXSSH_P3_TARGET26"] == "1" ? "26.0" : "15.0"
let package = Package(
    name: "OpenLXSSHRemoteFileProbe",
    platforms: [.macOS(deployment)],
    products: [
        .library(name: "OpenLXSSHRemoteFileProbe", targets: ["OpenLXSSHRemoteFileProbe"]),
        .executable(name: "OpenLXSSHRemoteFileSmoke", targets: ["OpenLXSSHRemoteFileSmoke"])
    ],
    dependencies: [.package(path: "../../Packages/OpenLXSSHTrust")],
    targets: [
        .target(name: "CRemoteFileBridge", cSettings: [.unsafeFlags(["-I" + native + "/include"])],
                linkerSettings: [.unsafeFlags([native + "/lib/libssh2.a", native + "/lib/libssl.a",
                                               native + "/lib/libcrypto.a"])]),
        .target(name: "OpenLXSSHRemoteFileProbe", dependencies: ["CRemoteFileBridge", .product(name: "OpenLXSSHTrust", package: "OpenLXSSHTrust")], swiftSettings: nativeHeaders),
        .executableTarget(name: "OpenLXSSHRemoteFileSmoke", dependencies: ["OpenLXSSHRemoteFileProbe"], swiftSettings: nativeHeaders),
        .testTarget(name: "OpenLXSSHRemoteFileProbeTests", dependencies: ["OpenLXSSHRemoteFileProbe"], swiftSettings: nativeHeaders)
    ],
    swiftLanguageModes: [.v6]
)
