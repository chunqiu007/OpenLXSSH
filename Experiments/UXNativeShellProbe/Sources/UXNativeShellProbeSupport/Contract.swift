import Foundation

public enum ShellProbeError: Error, Equatable { case arguments, liveNotReleased, fixture, outputLimit, deadline, missingEvidence }
public enum ShellProbeFixture: String, CaseIterable, Sendable {
    case keyonly, passwordonly, keyKbd = "key-kbd", passwordKbd = "password-kbd"
    public var port: Int {
        switch self { case .keyonly: 22221; case .passwordonly: 22222; case .keyKbd: 22223; case .passwordKbd: 22224 }
    }
    public var usesKey: Bool { self == .keyonly || self == .keyKbd }
}
/// Parsing is deliberately syntax-only, including fully authorized live arguments. A build
/// without the private fixture consumer still refuses live execution after parsing.
public enum ShellProbeCommand: Equatable, Sendable {
    case help
    case validate(ShellProbeFixture)
    case validateContract(String)
    case validateCase(contractPath: String, testCase: ShellProbeCase)
    case live(contractPath: String)
    case liveCase(contractPath: String, testCase: ShellProbeCase)
    public static var sourceBuildRoot: String {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent(".build").path
    }
    public static let usage = """
    UXNativeShellProbe --help
    UXNativeShellProbe validate --fixture keyonly|passwordonly|key-kbd|password-kbd
    UXNativeShellProbe validate --contract <probe/.build/sftp-auth-case-12hex/sftp-auth.json>
    Default/help/validate are syntax-only: no files, credentials, Docker, relay or connections.
    Only after a separate main-session LIVE RELEASE, use the audited build_live.py artifact:
      --live --authorized-local-fixture --engine-ready --contract <exact marked case path> [--case <case>]
    Cases: positive (default), wrong-primary, hostkey-mismatch, cancel-ki, cancel-after-ready, encrypted-ed, rsa.
    Fixed fixture@127.0.0.1:22221..22224; one session attempt per invocation, no retries.
    Fault/key cases further restrict service/key combinations. --case is syntax-only during validate.
    The old SFTPAuthContract is input material only; success requires new shell/PTY/resize/exit evidence.
    """
    public static func checkContractPath(_ path: String, buildRoot: String) throws {
        guard path.hasPrefix("/"), path.utf8.count < 4096, !path.contains("$"),
              !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
                .allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw ShellProbeError.arguments }
        let prefix = buildRoot + "/sftp-auth-case-", suffix = "/sftp-auth.json"
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { throw ShellProbeError.arguments }
        let generation = path.dropFirst(prefix.count).dropLast(suffix.count)
        guard generation.utf8.count == 12,
              generation.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw ShellProbeError.arguments
        }
    }
    public static func parse(_ arguments: [String], buildRoot: String = sourceBuildRoot) throws -> Self {
        if arguments.isEmpty || arguments == ["--help"] { return .help }
        if arguments.count == 3, arguments[0] == "validate", arguments[1] == "--fixture",
           let fixture = ShellProbeFixture(rawValue: arguments[2]) { return .validate(fixture) }
        guard let first = arguments.first, ["validate", "--live"].contains(first) else { throw ShellProbeError.arguments }
        var path: String?, authorized = false, ready = false, index = 1
        var testCase: ShellProbeCase?
        while index < arguments.count {
            switch arguments[index] {
            case "--contract":
                guard path == nil, index + 1 < arguments.count else { throw ShellProbeError.arguments }
                index += 1; path = arguments[index]
            case "--case":
                guard testCase == nil, index + 1 < arguments.count,
                      let selected = ShellProbeCase(rawValue: arguments[index + 1]) else { throw ShellProbeError.arguments }
                index += 1; testCase = selected
            case "--authorized-local-fixture":
                guard !authorized else { throw ShellProbeError.arguments }; authorized = true
            case "--engine-ready":
                guard !ready else { throw ShellProbeError.arguments }; ready = true
            default: throw ShellProbeError.arguments
            }
            index += 1
        }
        guard let path else { throw ShellProbeError.arguments }
        try checkContractPath(path, buildRoot: buildRoot)
        if first == "--live" {
            guard authorized, ready else { throw ShellProbeError.arguments }
            return testCase.map { .liveCase(contractPath: path, testCase: $0) } ?? .live(contractPath: path)
        }
        guard !authorized, !ready else { throw ShellProbeError.arguments }
        return testCase.map { .validateCase(contractPath: path, testCase: $0) } ?? .validateContract(path)
    }
}

/// Streaming, bounded finite-case matcher. The token is assigned AFTER shell connect so echoed
/// input cannot contain complete expected output markers. Never logs terminal output or secrets.
struct ShellProbeEvidence {
    static let maximumBytes = 1024 * 1024
    static let tailBytes = 4096
    private var tail = Data()
    private(set) var count = 0
    private(set) var ack = false
    private(set) var pty = false
    private(set) var size = false
    let token: String
    init(token: String) { self.token = token }
    mutating func consume(_ bytes: Data) throws {
        guard bytes.count <= 65536, count <= Self.maximumBytes - bytes.count else { throw ShellProbeError.outputLimit }
        count += bytes.count; tail.append(bytes)
        if tail.range(of: Data(("NATIVE_ACK_" + token).utf8)) != nil { ack = true }
        if tail.range(of: Data(("NATIVE_PTY_" + token).utf8)) != nil { pty = true }
        if tail.range(of: Data(("NATIVE_SIZE_" + token + " 37 113").utf8)) != nil { size = true }
        if tail.count > Self.tailBytes { tail = Data(tail.suffix(Self.tailBytes)) }
    }
}
