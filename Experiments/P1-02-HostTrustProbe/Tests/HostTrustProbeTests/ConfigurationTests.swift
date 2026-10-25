import Darwin
import Foundation
@testable import OpenLXSSHHostTrustProbe
import XCTest

final class ConfigurationTests: XCTestCase {
    func testAddressPortAndUserValidation() throws {
        XCTAssertEqual(try HostAddress("Example.COM.").value, "example.com")
        XCTAssertEqual(try HostAddress("192.0.2.10").value, "192.0.2.10")
        XCTAssertEqual(try HostAddress("[2001:0DB8:0:0::1]").value, "2001:db8::1")
        XCTAssertEqual(try HostAddress("fe80::1%en0").value, "fe80::1%en0")
        XCTAssertEqual(try SSHUser("DOMAIN\\alice").value, "DOMAIN\\alice")
        XCTAssertEqual(try SSHUser("alice@example.com").value, "alice@example.com")
        for value in ["", "-oProxyCommand=id", "host user", "host\nProxyCommand id", "host\r", "host\0",
                      "host\t", "host\u{7f}", "host\u{85}", "host\u{2028}", "$(id)", "a;b", "a#b",
                      "a\"b", "a*b", "a?b", "a,b", "a|b", "user@host", "host:22", "[host]", "host%h",
                      "127.1", "010.0.0.1", "999.0.0.1", "foo..bar", "_service.example", "-foo.example",
                      "2001::db8::1", "fe80::1%", "fe80::1%a%b", "fe80::1%en 0", "fe80::1%eN0", "fe80::1%00", "fe80::1%0"] {
            XCTAssertThrowsError(try HostAddress(value), value)
        }
        for value in [0, -1, 65536, Int.max] { XCTAssertThrowsError(try SSHPort(value)) }
        for value in [1, 22, 2222, 65535] { XCTAssertEqual(Int(try SSHPort(value).value), value) }
        for value in ["", "-oOption", "a b", "a\n", "a\r", "a\0", "a\t", "a\u{7f}", "a\"b", "a%h", "a${HOME}", "a;id"] {
            XCTAssertThrowsError(try SSHUser(value), value)
        }
    }

    func testPathValidationAndLiteralCharacters() throws {
        for value in ["relative", "-F/tmp/file", "/", "//tmp/a", "/tmp/../a", "/tmp/./a", "/tmp//a",
                      "/tmp/a/", "/tmp/a\nHost *", "/tmp/a\r", "/tmp/a\0", "/tmp/a\u{7f}", "/tmp/${HOME}"] {
            XCTAssertThrowsError(try AbsolutePath(value), value)
        }
        XCTAssertEqual(try AbsolutePath("/tmp/a \"quoted\" \\ literal%h").value,
                       "/tmp/a \"quoted\" \\ literal%h")
    }

    func testControlledConfigurationAgainstSSHPreview() throws {
        let directory = try TemporaryDirectory(name: "OpenLXSSH quoted \" \\ %h ")
        let store = try HostTrustStore(directory: directory.path)
        let known = store.knownHostsPath
        let identity = try host("[2001:db8::1]", port: 2222)
        let configuration = ControlledSSHConfiguration(
            connection: SSHConnection(host: identity, user: try SSHUser("DOMAIN\\test-user")),
            trustStore: store)
        let prepared = try configuration.write(in: directory.path)
        let file = prepared.path
        let invocation = prepared.invocation(preview: true)
        XCTAssertEqual(invocation.executable, "/usr/bin/ssh")
        XCTAssertEqual(invocation.arguments, ["-G", "-F", file.value, "--", "openlxssh-direct"])
        XCTAssertEqual(Set(invocation.environment.keys), Set(["PATH", "LC_ALL", "TERM"]))
        XCTAssertFalse(configuration.text.contains("Include "))
        let result = try runTool(invocation.executable, invocation.arguments, environment: invocation.environment)
        XCTAssertEqual(result.status, 0, result.error)
        let values = Dictionary(result.output.split(separator: "\n").map { line in
            let fields = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false)
            return (String(fields[0]), fields.count > 1 ? String(fields[1]) : "")
        }, uniquingKeysWith: { first, _ in first })
        let expected: [String: String] = [
            "hostname": "2001:db8::1", "hostkeyalias": "[2001:db8::1]:2222", "port": "2222",
            "user": "DOMAIN\\test-user", "userknownhostsfile": known.value,
            "globalknownhostsfile": "/dev/null", "stricthostkeychecking": "true",
            "updatehostkeys": "false", "verifyhostkeydns": "false", "checkhostip": "no",
            "forwardagent": "no", "forwardx11": "no", "forwardx11trusted": "no",
            "clearallforwardings": "yes", "tunnel": "false", "gatewayports": "no",
            "controlmaster": "false", "controlpersist": "no", "permitlocalcommand": "no",
            "canonicalizehostname": "false", "connecttimeout": "10", "connectionattempts": "1",
            "serveraliveinterval": "15", "serveralivecountmax": "3", "numberofpasswordprompts": "1",
            "identityagent": "none", "identityfile": "none", "certificatefile": "none",
            "identitiesonly": "yes", "permitremoteopen": "none", "escapechar": "none"
        ]
        for (key, value) in expected { XCTAssertEqual(values[key], value, key) }
        for key in ["proxycommand", "proxyjump", "localforward", "remoteforward", "dynamicforward", "controlpath", "localcommand", "remotecommand", "knownhostscommand"] {
            XCTAssertTrue(values[key] == nil || values[key] == "none", "Unexpected \(key): \(values[key] ?? "")")
        }
        var metadata = stat()
        XCTAssertEqual(lstat(file.value, &metadata), 0)
        XCTAssertEqual(metadata.st_mode & 0o7777, 0o600)
        // -vvG provides evidence that neither ~/.ssh/config nor /etc/ssh/ssh_config is read.
        let verbose = try runTool("/usr/bin/ssh", ["-vvG", "-F", file.value, "--", "openlxssh-direct"])
        XCTAssertEqual(verbose.status, 0)
        let readLines = verbose.error.split(whereSeparator: { $0.isNewline }).filter { $0.contains("Reading configuration data") }
        XCTAssertEqual(readLines.count, 1, verbose.error)
        XCTAssertEqual(readLines.first.map(String.init),
                       "debug1: Reading configuration data " + file.value.replacingOccurrences(of: "\\", with: "\\\\"))
    }

    func testDNSIPv4AndScopedIPv6ArePreservedBySSH() throws {
        let directory = try TemporaryDirectory()
        let store = try HostTrustStore(directory: directory.path)
        for address in ["Server.Example.", "192.0.2.7", "2001:db8::20", "fe80::1%en0", "fe80::1%1234"] {
            let identity = try host(address, port: 2200)
            let configuration = ControlledSSHConfiguration(
                connection: SSHConnection(host: identity, user: try SSHUser("test.user+tag@example")),
                trustStore: store)
            let prepared = try configuration.write(in: directory.path)
            let invocation = prepared.invocation(preview: true)
            let result = try runTool(invocation.executable, invocation.arguments, environment: invocation.environment)
            XCTAssertEqual(result.status, 0, result.error)
            XCTAssertTrue(result.output.contains("hostname \(identity.address.value)\n"))
            XCTAssertTrue(result.output.contains("hostkeyalias \(identity.knownHostsName)\n"))
            XCTAssertTrue(result.output.contains("user test.user+tag@example\n"))
        }
        let nonexistentScope = ControlledSSHConfiguration(
            connection: SSHConnection(host: try host("fe80::1%openlxssh-missing-scope"), user: try SSHUser("probe")),
            trustStore: store)
        XCTAssertThrowsError(try nonexistentScope.write(in: directory.path))
    }

    func testPublicKeyValidationAndSystemFingerprint() throws {
        for line in [ed25519Fixture, rsaFixture] {
            let key = try HostPublicKey(openSSHPublicKey: line)
            let result = try runTool("/usr/bin/ssh-keygen", ["-l", "-f", "-", "-E", "sha256"],
                                     input: Data((line + "\n").utf8))
            XCTAssertEqual(result.status, 0)
            XCTAssertTrue(result.output.contains(" " + key.fingerprint + " "))
            XCTAssertEqual(key.openSSH, line)
        }
        for line in ["", "ssh-ed25519 invalid", "ssh-ed25519 aW52YWxpZA==", "ssh-rsa " + ed25519Fixture.split(separator: " ")[1],
                     ed25519Fixture + "\n", ed25519Fixture + "\0", "-oOption AAAA", "@cert-authority " + ed25519Fixture] {
            XCTAssertThrowsError(try HostPublicKey(openSSHPublicKey: line))
        }
    }

    func testTemporarySSHKeygenPublicKeysAndPrivatePermissions() throws {
        let directory = try TemporaryDirectory()
        for algorithm in ["ed25519", "rsa", "ecdsa"] {
            let keyPath = directory.file("disposable-" + algorithm).path
            var arguments = ["-q", "-t", algorithm, "-N", "", "-C", "disposable-test-only", "-f", keyPath]
            if algorithm == "rsa" { arguments += ["-b", "2048"] }
            let result = try runTool("/usr/bin/ssh-keygen", arguments)
            XCTAssertEqual(result.status, 0, result.error)
            var metadata = stat()
            XCTAssertEqual(lstat(directory.url.path, &metadata), 0)
            XCTAssertEqual(metadata.st_mode & 0o7777, 0o700)
            XCTAssertEqual(lstat(keyPath, &metadata), 0)
            XCTAssertEqual(metadata.st_mode & 0o7777, 0o600)
            // Read only the public file. The private file is never read, printed or copied.
            let publicLine = try String(contentsOfFile: keyPath + ".pub", encoding: .utf8)
                .trimmingCharacters(in: .newlines)
            let key = try HostPublicKey(openSSHPublicKey: publicLine)
            XCTAssertTrue(key.fingerprint.hasPrefix("SHA256:"))
        }
    }
}
