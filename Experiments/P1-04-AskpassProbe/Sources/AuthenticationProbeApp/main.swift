import AppKit
import Darwin
import Foundation
import OpenLXSSHAskpassProbe
import OpenLXSSHCredentialKeyProbe

@MainActor
final class ProbeDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { await run() }
    }
    func run() async {
        var store: KeyStore?
        var success = false
        do {
            // The same runtime-random bytes feed the reviewed generator's anonymous
            // pipe and the explicitly synthetic bridge answer, never argv/env/log.
            let random = try probeRandomPassphrase()
            let created = try KeyStore(); store = created
            let key = try await created.generateEd25519(protection: .passphrase(SecretBytes(random)))
            let path = created.rootURL.appendingPathComponent("\(key.id.uuidString).openssh")
            var directory = stat(), file = stat()
            guard lstat(created.rootURL.path, &directory) == 0, directory.st_mode & 0o777 == 0o700,
                  lstat(path.path, &file) == 0, file.st_mode & 0o777 == 0o600, key.encrypted else { throw ProbeError.identity }
            // Verify the generated envelope again without unlocking or Keychain.
            _ = try await created.publicKey(for: key.id)
            try verifyBundledReadpass(key: path, expectedPublicKey: Data(key.publicKey.copyString.utf8), passphrase: random)
            let root = created.rootURL.path
            try await created.destroy(); store = nil
            guard access(root, F_OK) != 0 else { throw ProbeError.unavailable }
            print("PASS temporary encrypted key and owner-only directory removed")
            print("APP-PROBE PASS scenarios=3 actual=OpenSSH-ssh-keygen-readpass-with-controlling-PTY")
            print("NOT VERIFIED SSH-server-authentication MFA macOS26 Sandbox DeveloperID notarization")
            success = true
        } catch {
            // Never interpolate key material, arbitrary subprocess output or prompts.
            print("APP-PROBE FAIL category=\((error as? ProbeError)?.rawValue ?? "key-or-environment")")
        }
        if let store {
            do { try await store.destroy() }
            catch { print("APP-PROBE cleanup_failed=true"); success = false }
        }
        fflush(stdout)
        exit(success ? 0 : 1)
    }
}

let application = NSApplication.shared
application.setActivationPolicy(.accessory)
let delegate = ProbeDelegate()
application.delegate = delegate
application.run()
