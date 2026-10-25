// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "OpenLXSSHCredentialKeyProbe",
    // Host-only experiment. The shipping application still requires macOS 26.
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "OpenLXSSHCredentialKeyProbe", targets: ["OpenLXSSHCredentialKeyProbe"]),
        .executable(name: "openlxssh-credential-key-probe", targets: ["CredentialKeyProbeCLI"]),
        .executable(name: "openlxssh-file-keychain-candidate", targets: ["FileKeychainCandidateCLI"])
    ],
    targets: [
        .target(name: "CredentialKeyPOSIX"),
        .target(name: "FileKeychainLegacy"),
        .target(name: "OpenLXSSHCredentialKeyProbe", dependencies: ["CredentialKeyPOSIX"]),
        .target(name: "FileKeychainCandidate", dependencies: ["OpenLXSSHCredentialKeyProbe", "FileKeychainLegacy"]),
        .executableTarget(name: "CredentialKeyProbeCLI", dependencies: ["OpenLXSSHCredentialKeyProbe"]),
        .executableTarget(name: "FileKeychainCandidateCLI", dependencies: ["FileKeychainCandidate"]),
        .testTarget(name: "CredentialKeyProbeTests", dependencies: ["OpenLXSSHCredentialKeyProbe"]),
        .testTarget(name: "FileKeychainCandidateTests", dependencies: ["FileKeychainCandidate"])
    ],
    swiftLanguageModes: [.v6]
)
