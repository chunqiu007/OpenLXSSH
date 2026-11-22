import Darwin
import Foundation
import OpenLXSSHSecurity

/// Local signed verification target only. No production namespace or user secret inputs.
@main
struct SecurityFixture {
    static func main() async {
        guard CommandLine.arguments.count == 1 else { exit(64) }
        do {
            let store = try CredentialStore(testNamespace: UUID())
            let second = try CredentialStore(testNamespace: UUID())
            let reference = CredentialReference(kind: .password)
            let unapproved = CredentialReference(kind: .privateKeyPassphrase)
            let secret = try SecretBytes.random()
            var success = false
            var cleanupOK = true
            do {
                guard await store.save(secret, as: unapproved, authorization: .notGranted) == .notAuthorized,
                      await store.save(secret, as: reference, authorization: .granted) == .saved(reference),
                      await store.save(secret, as: reference, authorization: .granted) == .failed(.duplicate) else {
                    throw CredentialFailure.invalidData
                }
                try await second.close() // closing another store must not affect this store.
                guard case .available(let observed) = await store.read(reference), observed.matches(secret) else {
                    throw CredentialFailure.invalidData
                }
                let replacement = try SecretBytes.random()
                guard await store.replace(replacement, at: reference, authorization: .granted) == .updated(reference),
                      case .available(let updated) = await store.read(reference), updated.matches(replacement) else {
                    throw CredentialFailure.invalidData
                }
                success = true
            } catch { print("SECURITY FIXTURE operation incomplete; details redacted") }
            for item in [reference, unapproved] {
                if case .retryRequired(let failure) = await store.deleteExact(item) {
                    cleanupOK = false
                    print("SECURITY FIXTURE exact cleanup failed: \(failure)")
                }
                if case .missing = await store.read(item) {} else { cleanupOK = false }
            }
            try await store.close()
            try await second.close()
            print("SECURITY FIXTURE signed CRUD authorization/multiowner/update: \(success)")
            print("SECURITY FIXTURE exact cleanup verified: \(cleanupOK)")
            if !success || !cleanupOK { exit(2) }
        } catch {
            print("SECURITY FIXTURE initialization/policy close incomplete; details redacted")
            exit(3)
        }
    }
}
