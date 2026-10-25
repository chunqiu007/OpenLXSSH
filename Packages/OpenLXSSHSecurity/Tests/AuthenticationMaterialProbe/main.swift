import Darwin
import Foundation
@testable import OpenLXSSHSecurity

// Only transient self-created key files are used. The returned authentication bytes and
// passphrases are passed to libssh2 in-process, never through argv, stdout or another file.
@main
struct AuthenticationMaterialProbe {
    static func main() async {
        do { try await verify() }
        catch {
            print("AUTH MATERIAL PROBE failure_type=\(type(of: error))")
            exit(1)
        }
    }

    private static func verify() async throws {
        guard let parent = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw KeyFailure.invalidPath }
        defer { free(parent) }
        let root = URL(fileURLWithPath: String(cString: parent))
            .appendingPathComponent("OpenLXSSHSecurity-AuthMaterial-\(UUID().uuidString)", isDirectory: true)
        guard mkdir(root.path, 0o700) == 0 else { throw KeyFailure.systemCall("create own probe", errno) }
        do {
            for algorithm in [KeyAlgorithm.ed25519, .rsa] {
                for encrypted in [false, true] {
                    let store = try KeyStore(directory: root.appendingPathComponent(UUID().uuidString))
                    let passphrase = encrypted ? Data(UUID().uuidString.utf8) : Data()
                    let protection: KeyProtection = encrypted ? .passphrase(SecretBytes(passphrase)) : .unencrypted
                    let key = try await store.generate(algorithm: algorithm, protection: protection)
                    let keyURL = store.rootURL.appendingPathComponent("\(key.id.uuidString).openssh")
                    let before = try PrivateDirectory.readSource(keyURL)
                    let material = try await store.privateKeyForAuthentication(id: key.id)
                    guard material.withUnsafeBytes({ Data($0) == before }),
                          let publicBlob = Data(base64Encoded: String(key.publicKey.copyString.split(separator: " ")[1])) else {
                        throw KeyFailure.invalidOpenSSH
                    }
                    let result = material.withUnsafeBytes { privateBytes in
                        // Mirror Files' NUL-terminated C buffers while retaining explicit lengths.
                        (Array(privateBytes) + [0]).withUnsafeBytes { privateCString in
                            (Array(passphrase) + [0]).withUnsafeBytes { passCString in
                                publicBlob.withUnsafeBytes { publicBytes in
                                    algorithm.rawValue.withCString { type in
                                        olxs_probe_authentication_material(
                                            privateCString.baseAddress!.assumingMemoryBound(to: CChar.self), privateBytes.count,
                                            passCString.baseAddress!.assumingMemoryBound(to: CChar.self), type,
                                            publicBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), publicBytes.count)
                                    }
                                }
                            }
                        }
                    }
                    guard result == 0 else {
                        print("AUTH MATERIAL PROBE parse_sign_verify_code=\(result)")
                        throw KeyFailure.keygenRejected
                    }
                    guard try PrivateDirectory.readSource(keyURL) == before else { throw KeyFailure.changedWhileReading }
                    try await store.close()
                    print("AUTH MATERIAL PROBE algorithm=\(algorithm.rawValue) encrypted=\(encrypted) memory_parse_sign_verify=PASS source_unchanged=true")
                }
            }
        } catch {
            try FileManager.default.removeItem(at: root)
            throw error
        }
        try FileManager.default.removeItem(at: root)
        guard !FileManager.default.fileExists(atPath: root.path) else { throw KeyFailure.cleanupRequired }
        print("AUTH MATERIAL PROBE own_UUID_tree_removed=true network_used=false")
    }
}
