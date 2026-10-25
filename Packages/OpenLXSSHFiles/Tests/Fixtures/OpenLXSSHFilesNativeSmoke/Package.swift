// swift-tools-version: 6.2
import PackageDescription
import Foundation

// Standalone verification-only consumer. It is not a product/target of the runtime library package.
let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent().path
let deployment = ProcessInfo.processInfo.environment["OPENLXSSH_FILES_TARGET26"] == "1" ? "26.0" : "15.0"
let package = Package(
    name: "OpenLXSSHFilesNativeSmokeFixture",
    platforms: [.macOS(deployment)],
    dependencies: [.package(path: root)],
    targets: [.executableTarget(name: "OpenLXSSHFilesNativeSmoke",
        dependencies: [.product(name: "OpenLXSSHFiles", package: "OpenLXSSHFiles")], path: ".", exclude: ["Package.swift"])]
)
