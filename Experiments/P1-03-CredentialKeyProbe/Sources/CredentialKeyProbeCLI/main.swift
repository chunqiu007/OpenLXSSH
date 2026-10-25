import Darwin
import Foundation
import OpenLXSSHCredentialKeyProbe

@main
struct CredentialKeyProbeCLI {
    @MainActor
    static func main() async {
        let arguments = CommandLine.arguments
        if arguments.count == 2, arguments[1] == "--signing-diagnostics" {
            let summary = LiveSigningDiagnostics.summary()
            for key in summary.keys.sorted() {
                print("SELF SIGNING \(key): \(summary[key]!)")
            }
            return
        }
        if arguments.count >= 2, arguments[1].hasPrefix("--keychain-handoff-") {
            do {
                guard arguments.count == 3 || arguments.count == 4 else { exit(64) }
                let ticketURL = URL(fileURLWithPath: arguments[2])
                if arguments[1] == "--keychain-handoff-cleanup", arguments.count == 3 {
                    try LiveKeychainHandoff.cleanup(ticketURL: ticketURL)
                    print("REAL Keychain cross-launch exact cleanup PASS; ticket removed")
                    return
                }
                guard arguments.count == 4, let descriptor = Int32(arguments[3]),
                      ["--keychain-handoff-create", "--keychain-handoff-read-delete"].contains(arguments[1]) else { exit(64) }
                let proof: LiveKeychainProof
                if arguments[1] == "--keychain-handoff-create" {
                    proof = try LiveKeychainHandoff.create(ticketURL: ticketURL)
                } else {
                    proof = try LiveKeychainHandoff.readAndDelete(ticketURL: ticketURL)
                }
                try proof.write(to: descriptor)
                print("REAL Keychain cross-launch step PASS; proof sent to memory-only pipe")
            } catch let failure as LiveKeychainLimitation {
                print("REAL Keychain cross-launch INCOMPLETE: \(failure.operation), \(failure.failure)")
                exit(2)
            } catch let failure as LiveKeychainCleanupFailure {
                print("REAL Keychain cross-launch cleanup INCOMPLETE: \(failure.failure); saveSucceeded=\(failure.saveSucceeded); exact ticket retained")
                exit(3)
            } catch {
                print("REAL Keychain cross-launch failed; details redacted; inspect exact cleanup ticket")
                exit(1)
            }
            return
        }
        guard arguments.count == 2,
              ["--keychain", "--local-keys"].contains(arguments[1]) else {
            print("Usage: openlxssh-credential-key-probe --keychain | --local-keys")
            exit(64)
        }
        if arguments[1] == "--keychain" {
            do {
                try LiveKeychainProbe.run()
                print("REAL Keychain UUID-only CRUD PASS; exact deferred cleanup completed; no secrets printed")
            } catch let failure as LiveKeychainLimitation {
                print("REAL Keychain INCOMPLETE: \(failure.operation), \(failure.failure); no insecure fallback")
                exit(2)
            } catch let failure as LiveKeychainCleanupFailure {
                print("REAL Keychain cleanup INCOMPLETE: \(failure.failure); saveSucceeded=\(failure.saveSucceeded)")
                if failure.saveSucceeded {
                    print("Exact cleanup namespace: \(failure.namespace.uuidString)")
                    for reference in failure.references {
                        print("Exact cleanup reference: \(reference.kind.rawValue) \(reference.id.uuidString)")
                    }
                }
                if let primary = failure.operationFailure {
                    print("REAL Keychain primary failure: \(primary.operation), \(primary.failure); no weaker storage fallback")
                }
                exit(3)
            } catch {
                print("REAL Keychain probe failed; details redacted")
                exit(1)
            }
            return
        }
        do {
            let store = try KeyStore()
            do {
                let secret = try SecretBytes.randomPassphrase()
                for protection in [KeyProtection.unencrypted, .passphrase(secret)] {
                    let key = try await store.generateEd25519(protection: protection)
                    let publicKey = try await store.publicKey(for: key.id)
                    guard publicKey == key.publicKey,
                          (try PublicKey(publicKey.copyString)) == publicKey else {
                        throw KeyFailure.invalidOpenSSH
                    }
                    try await store.delete(key.id)
                }
                try await store.destroy()
                print("REAL ssh-keygen Ed25519 encrypted+unencrypted generation/public-key/delete PASS; root removed")
            } catch {
                do { try await store.destroy() }
                catch {
                    print("Local key cleanup failed; no key data printed")
                    exit(3)
                }
                throw error
            }
        } catch {
            print("Local key probe failed; details redacted")
            exit(1)
        }
    }
}
