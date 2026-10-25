// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "OpenLXSSHAskpassProbe",
    // Host-only experiment. The application target remains Apple Silicon/macOS 26.
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "OpenLXSSHAskpassProbe", targets: ["OpenLXSSHAskpassProbe"]),
        .executable(name: "openlxssh-askpass-probe", targets: ["AskpassProbeCLI"]),
        .executable(name: "openlxssh-askpass-helper", targets: ["AskpassHelperCLI"]),
        .executable(name: "openlxssh-askpass-adversary", targets: ["AskpassAdversaryCLI"]),
        .executable(name: "OpenLXSSHAuthenticationProbe", targets: ["AuthenticationProbeApp"])
    ],
    dependencies: [.package(path: "../P1-03-CredentialKeyProbe")],
    targets: [
        .target(name: "AskpassPOSIX", linkerSettings: [
            .linkedFramework("Security"), .linkedFramework("CoreFoundation"), .linkedLibrary("bsm")
        ]),
        .target(name: "OpenLXSSHAskpassProbe", dependencies: ["AskpassPOSIX"]),
        .executableTarget(name: "AskpassProbeCLI", dependencies: ["OpenLXSSHAskpassProbe"]),
        .executableTarget(name: "AskpassHelperCLI", dependencies: ["OpenLXSSHAskpassProbe"]),
        .executableTarget(name: "AskpassAdversaryCLI", dependencies: ["OpenLXSSHAskpassProbe"]),
        .executableTarget(name: "AuthenticationProbeApp", dependencies: [
            "OpenLXSSHAskpassProbe",
            .product(name: "OpenLXSSHCredentialKeyProbe", package: "P1-03-CredentialKeyProbe")
        ]),
        .testTarget(name: "AskpassProbeTests", dependencies: ["OpenLXSSHAskpassProbe"])
    ],
    swiftLanguageModes: [.v6]
)
