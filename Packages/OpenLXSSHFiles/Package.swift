// swift-tools-version: 6.2
import PackageDescription
import Foundation

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let native = root + "/.build/native/install"
let nativeHeaders: [SwiftSetting] = [.unsafeFlags(["-Xcc", "-I" + native + "/include"])]
// Host tests use macOS 15. Product integration remains macOS 26; verify checks real load commands.
let deployment = ProcessInfo.processInfo.environment["OPENLXSSH_FILES_TARGET26"] == "1" ? "26.0" : "15.0"
let package = Package(
    name: "OpenLXSSHFiles",
    platforms: [.macOS(deployment)],
    products: [.library(name: "OpenLXSSHFiles", targets: ["OpenLXSSHFiles"])],
    dependencies: [.package(path: "../OpenLXSSHTrust")],
    targets: [
        .target(name: "COpenLXSSHFiles", cSettings: [.unsafeFlags(["-I" + native + "/include"])],
                linkerSettings: [.unsafeFlags([native + "/lib/libssh2.a", native + "/lib/libssl.a",
                                               native + "/lib/libcrypto.a"])]),
        .target(name: "OpenLXSSHFiles", dependencies: ["COpenLXSSHFiles", .product(name: "OpenLXSSHTrust", package: "OpenLXSSHTrust")],
                swiftSettings: nativeHeaders),
        .testTarget(name: "OpenLXSSHFilesTests", dependencies: ["OpenLXSSHFiles"], swiftSettings: nativeHeaders)
    ],
    swiftLanguageModes: [.v6]
)
