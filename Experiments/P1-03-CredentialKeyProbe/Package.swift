// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "OpenLXSSHCredentialKeyProbe",
    // Host-only experiment. The shipping application still requires macOS 26.
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "OpenLXSSHCredentialKeyProbe", targets: ["OpenLXSSHCredentialKeyProbe"]),
        .executable(name: "openlxssh-credential-key-probe", targets: ["CredentialKeyProbeCLI"])
    ],
    targets: [
        .target(name: "CredentialKeyPOSIX"),
        .target(name: "OpenLXSSHCredentialKeyProbe", dependencies: ["CredentialKeyPOSIX"]),
        .executableTarget(name: "CredentialKeyProbeCLI", dependencies: ["OpenLXSSHCredentialKeyProbe"]),
        .testTarget(name: "CredentialKeyProbeTests", dependencies: ["OpenLXSSHCredentialKeyProbe"])
    ],
    swiftLanguageModes: [.v6]
)
