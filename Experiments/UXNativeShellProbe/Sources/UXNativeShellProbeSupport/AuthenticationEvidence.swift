import Foundation
import OpenLXSSHFiles

/// Serializable fixed facts only. Never captures raw prompts, responses, key/password size/hash,
/// a transcript, or a claim that libssh2 exposed partial-success.
public struct ShellProbeAuthenticationEvidence: Encodable, Sendable {
    public let primaryMethod: String
    public let primaryStarted: Int
    public let primaryResults: Int
    public let primaryCode: Int32
    public let primaryAuthenticated: Bool
    public let keyboardStarted: Int
    public let keyboardResults: Int
    public let keyboardCode: Int32?
    public let keyboardAuthenticated: Bool?
    public let authenticatedEvents: Int
    public let shellReadyEvents: Int
    public init(stages: [NativeShellAuthenticationStage], fixture: ShellProbeFixture) throws {
        var starts = 0, results = 0, kStarts = 0, kResults = 0, auth = 0, shell = 0, advertised = 0
        var code: Int32?, primaryAuth: Bool?, kCode: Int32?, kAuth: Bool?
        let expected: NativeShellPrimaryMethod = fixture.usesKey ? .publicKey : .password
        var order: [String] = []
        for stage in stages {
            switch stage {
            case .advertised: advertised += 1; order.append("advertised")
            case .primaryStarted(let method):
                guard method == expected else { throw ShellProbeError.missingEvidence }
                starts += 1; order.append("primary-start")
            case .primaryResult(let method, let result, let authenticated):
                guard method == expected else { throw ShellProbeError.missingEvidence }
                results += 1; code = result; primaryAuth = authenticated; order.append("primary-result")
            case .keyboardStarted: kStarts += 1; order.append("keyboard-start")
            case .keyboardResult(let result, let authenticated):
                kResults += 1; kCode = result; kAuth = authenticated; order.append("keyboard-result")
            case .authenticated: auth += 1; order.append("authenticated")
            case .shellReady: shell += 1; order.append("shell-ready")
            }
        }
        let mfa = fixture == .keyKbd || fixture == .passwordKbd
        let expectedOrder = ["advertised", "primary-start", "primary-result"] +
            (mfa ? ["keyboard-start", "keyboard-result"] : []) + ["authenticated", "shell-ready"]
        guard order == expectedOrder, advertised == 1, starts == 1, results == 1, let code, let primaryAuth,
              kStarts == (mfa ? 1 : 0), kResults == kStarts, auth == 1, shell == 1,
              mfa ? (!primaryAuth && [-18, -19].contains(code) && kCode == 0 && kAuth == true)
                  : (primaryAuth && code == 0) else { throw ShellProbeError.missingEvidence }
        primaryMethod = expected.rawValue; primaryStarted = starts; primaryResults = results
        primaryCode = code; primaryAuthenticated = primaryAuth; keyboardStarted = kStarts; keyboardResults = kResults
        keyboardCode = kCode; keyboardAuthenticated = kAuth; authenticatedEvents = auth; shellReadyEvents = shell
    }
}
