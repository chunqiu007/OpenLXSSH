import Foundation
import UXNativeShellProbeSupport

public enum NativeFailureCheckError: Error { case arguments, contract, evidence, deadline, cleanup }
public enum NativeFailureCase: String, CaseIterable, Codable, Sendable {
    case nativeChangedNoHandler, nativeCancelledProvider, sftpChangedNoHandler
    case keyKIPositive, passwordKIPositive
    public var fixture: ShellProbeFixture {
        switch self {
        case .nativeChangedNoHandler, .nativeCancelledProvider, .sftpChangedNoHandler: .keyonly
        case .keyKIPositive: .keyKbd
        case .passwordKIPositive: .passwordKbd
        }
    }
    public var key: String { fixture.usesKey ? "edplain" : "none" }
    public var positive: Bool { self == .keyKIPositive || self == .passwordKIPositive }
    public var changed: Bool { self == .nativeChangedNoHandler || self == .sftpChangedNoHandler }
    public var activeLimit: Double { positive ? 45 : 15 }
    public func validate(service: String, key: String) throws {
        guard service == fixture.rawValue, key == self.key else { throw NativeFailureCheckError.contract }
    }
}

/// Closed syntax only. Parsing never opens the contract (even with all live flags).
public enum NativeFailureCommand: Equatable, Sendable {
    case help
    case validate(contractPath: String, testCase: NativeFailureCase)
    case live(contractPath: String, testCase: NativeFailureCase)
    public static let usage = """
    UXNativeFailureConsumer --help
    UXNativeFailureConsumer validate --contract <marked sftp-auth-case-12hex/sftp-auth.json> --case <case>
    Default/help/validate are inert; no file, credential, process, Keychain or socket access.
    MAIN SESSION ONLY, after source review and a separate live release:
      --live --authorized-local-fixture --engine-ready --primary-reviewed --contract <exact path> --case <case>
    Cases: nativeChangedNoHandler, nativeCancelledProvider, sftpChangedNoHandler, keyKIPositive, passwordKIPositive.
    One fixed fixture session; no endpoint, exec, credential, retry or environment override.
    """
    public static func parse(_ arguments: [String], buildRoot: String) throws -> Self {
        if arguments.isEmpty || arguments == ["--help"] { return .help }
        guard let first = arguments.first, first == "validate" || first == "--live" else {
            throw NativeFailureCheckError.arguments
        }
        var path: String?, selected: NativeFailureCase?, flags = Set<String>(), index = 1
        while index < arguments.count {
            let item = arguments[index]
            switch item {
            case "--contract":
                guard path == nil, index + 1 < arguments.count else { throw NativeFailureCheckError.arguments }
                index += 1; path = arguments[index]
            case "--case":
                guard selected == nil, index + 1 < arguments.count,
                      let value = NativeFailureCase(rawValue: arguments[index + 1]) else {
                    throw NativeFailureCheckError.arguments
                }
                selected = value; index += 1
            case "--authorized-local-fixture", "--engine-ready", "--primary-reviewed":
                guard flags.insert(item).inserted else { throw NativeFailureCheckError.arguments }
            default: throw NativeFailureCheckError.arguments
            }
            index += 1
        }
        guard let path, let selected else { throw NativeFailureCheckError.arguments }
        try ShellProbeCommand.checkContractPath(path, buildRoot: buildRoot)
        if first == "--live" {
            guard flags == ["--authorized-local-fixture", "--engine-ready", "--primary-reviewed"] else {
                throw NativeFailureCheckError.arguments
            }
            return .live(contractPath: path, testCase: selected)
        }
        guard flags.isEmpty else { throw NativeFailureCheckError.arguments }
        return .validate(contractPath: path, testCase: selected)
    }
}

public struct NativeFailureFixtureIdentity: Sendable {
    public let containerID: String, fingerprint: String, networkID: String
    public let imageID: String, project: String, context: String, endpoint: String
    public init(containerID: String, fingerprint: String, networkID: String, imageID: String,
                project: String, context: String, endpoint: String) {
        self.containerID = containerID; self.fingerprint = fingerprint; self.networkID = networkID
        self.imageID = imageID; self.project = project; self.context = context; self.endpoint = endpoint
    }
    public func matches(containerID: String, fingerprint: String, networkID: String, imageID: String,
                        project: String, context: String, endpoint: String) -> Bool {
        self.containerID == containerID && self.fingerprint == fingerprint && self.networkID == networkID &&
        self.imageID == imageID && self.project == project && self.context == context && self.endpoint == endpoint
    }
}

public enum NativeFailureFreshness {
    public static func validate(collectedAt: Double, now: Double) throws {
        guard collectedAt.isFinite, now.isFinite, collectedAt > 0,
              now >= collectedAt, now - collectedAt <= 120 else { throw NativeFailureCheckError.contract }
    }
}
