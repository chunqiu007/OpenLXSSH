import CryptoKit
import Darwin
import Foundation
import OpenLXSSHFiles
import RealIntegrationCore
import RealIntegrationPOSIX
import RemoteFileMetrics

@main enum OfflineMain {
    @MainActor static func main() async {
        var checks = 0
        func check(_ condition: Bool) throws { try require(condition); checks += 1 }
        func refuses(_ action: () throws -> Void) throws {
            do { try action() } catch { checks += 1; return }; throw GateError.integrity
        }
        do {
            try check(try Arguments.parse([]).action == .help)
            try check(try Arguments.parse(["--help"]).action == .help)
            try check(try Arguments.parse(["validate", "--campaign", "/not/opened/campaign.json"]).action == .validate)
            for args in [["--live", "--campaign", "/not/opened/campaign.json"],
                         ["--live", "--authorized-local-fixture", "--campaign", "/not/opened/campaign.json"],
                         ["prepare", "--primary-reviewed", "--generation", "/not/opened"],
                         ["--live", "--host", "example.com"], ["--live", "--password", "synthetic"],
                         ["validate", "--campaign", "/a/../campaign.json"],
                         ["validate", "--campaign", "/a/campaign.json", "--campaign", "/a/campaign.json"],
                         ["validate", "--authorized-local-fixture", "--campaign", "/a/campaign.json"]] {
                try refuses { _ = try Arguments.parse(args) }
            }
            let fixed = "/synthetic/Tests/IntegrationEnvironment"
            try PublicMaterial.validateGeneration(fixed + "/.runtime/keyonly/credentials-012345abcdef", fixtureRoot: fixed); checks += 1
            for bad in [fixed + "/.runtime/keyonly/credentials-latest", fixed + "/.runtime/passwordonly/credentials-012345abcdef",
                        "/etc/passwd", fixed + "/.runtime/keyonly/credentials-012345abcdef/extra"] {
                try refuses { try PublicMaterial.validateGeneration(bad, fixtureRoot: fixed) }
            }
            let id = "12345678-1234-1234-1234-123456789abc", own = "/synthetic/Tests/RemoteFileAcceptance"
            let campaign = Campaign(schema: 1, id: id, generation: fixed + "/.runtime/keyonly/credentials-012345abcdef",
                provenanceSHA256: String(repeating: "a", count: 64), knownHostsSHA256: String(repeating: "b", count: 64),
                fingerprintSHA256: String(repeating: "c", count: 64), packagesSHA256: String(repeating: "d", count: 64),
                collectedAt: 1000, preparedAt: 1100, project: Fixed.project, container: Fixed.container, base: Fixed.base,
                image: Fixed.image, fingerprint: Fixed.fingerprint)
            let campaignPath = own + "/.runtime/campaign-" + id + "/campaign.json"
            try campaign.validate(path: campaignPath, ownRoot: own, fixtureRoot: fixed, now: 1200); checks += 1
            for now in [1099.0, 2900.1, .infinity, .nan] {
                try refuses { try campaign.validate(path: campaignPath, ownRoot: own, fixtureRoot: fixed, now: now) }
            }
            try refuses { try campaign.validate(path: campaignPath.replacingOccurrences(of: id, with: "latest"), ownRoot: own, fixtureRoot: fixed, now: 1200) }
            // Existing PUBLIC test key only; no generated or read private credentials.
            let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg"
            let blob = Data(base64Encoded: String(line.split(separator: " ")[1]))!
            let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().dropLast()
            let known = raw("[127.0.0.1]:22221 " + line + "\n"), exported = raw("256 " + fingerprint + " synthetic-public (ED25519)\n")
            try check(try PublicMaterial.hostKey(known: known, exported: exported, expected: String(fingerprint)) == line)
            for wrong in [raw("[127.0.0.1]:22222 " + line + "\n"), known + known, raw("[example.com]:22221 " + line + "\n")] {
                try refuses { _ = try PublicMaterial.hostKey(known: wrong, exported: exported, expected: String(fingerprint)) }
            }
            try refuses { _ = try PublicMaterial.hostKey(known: known, exported: exported, expected: Fixed.fingerprint) }
            let provenance: [String: Any] = ["base_image": Fixed.base, "built_image_id": Fixed.image, "service": "keyonly", "collected_at": 1000.0]
            try check(try PublicMaterial.provenance(JSONSerialization.data(withJSONObject: provenance), now: 1100, fresh: true, minimumCollectedAt: 999) == 1000)
            for (key, value) in [("base_image", "unreviewed"), ("built_image_id", "unreviewed"), ("service", "passwordonly")] {
                var wrong = provenance; wrong[key] = value
                try refuses { _ = try PublicMaterial.provenance(JSONSerialization.data(withJSONObject: wrong), now: 1100, fresh: true, minimumCollectedAt: 999) }
            }
            for (now, minimum) in [(2000.0, 999.0), (999.0, 999.0), (1100.0, 1001.0), (Double.nan, 0.0)] {
                try refuses { _ = try PublicMaterial.provenance(JSONSerialization.data(withJSONObject: provenance), now: now, fresh: true, minimumCollectedAt: minimum) }
            }
            let synthetic = Corpus(format: 1, complete_ac31_size: true, large_bytes: Fixed.largeBytes, small_file_count: 1000,
                files: Fixed.specifications.map { Payload(path: $0.0, bytes: $0.1, sha256: String(repeating: "a", count: 64)) }, symlinks: Fixed.links)
            let encoded = try JSONEncoder().encode(synthetic)
            let parsed = try Corpus.parse(encoded)
            try check(parsed.files.count == 1002)
            try parsed.compare(parsed.files.reversed()); checks += 1
            var object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
            for (key, value) in [("large_bytes", 2 * 1024 * 1024), ("small_file_count", 10), ("format", 2)] {
                var wrong = object; wrong[key] = value
                try refuses { _ = try Corpus.parse(JSONSerialization.data(withJSONObject: wrong)) }
            }
            for name in ["../escape", "/absolute", "1000-small-files/文件 0001 [#; $].txt", "目录 with spaces/Unicode é 中文.txt"] {
                var wrong = object, entries = wrong["files"] as! [[String: Any]]
                entries[1]["path"] = name; wrong["files"] = entries
                try refuses { _ = try Corpus.parse(JSONSerialization.data(withJSONObject: wrong)) }
            }
            object["extra"] = "not-accepted"
            try refuses { _ = try Corpus.parse(JSONSerialization.data(withJSONObject: object)) }
            let source = try rp(Fixed.corpus + "/1000-small-files")
            let listed = Fixed.specifications.filter { $0.0.hasPrefix("1000-small-files/") }.map {
                DirectoryEntry(name: try! FileName(String($0.0.split(separator: "/").last!)), attributes: FileAttributes(kind: .regular, size: $0.1))
            }
            try checkCorpusListing(path: source, entries: listed); checks += 1
            try refuses { try checkCorpusListing(path: source, entries: Array(listed.dropLast())) }
            try refuses { try checkCorpusListing(path: source, entries: listed + [DirectoryEntry(name: try FileName("unexpected"), attributes: FileAttributes(kind: .symbolicLink))]) }
            let links = Fixed.links.map { DirectoryEntry(name: try! FileName(String($0.split(separator: "/").last!)), attributes: FileAttributes(kind: .symbolicLink)) }
            try checkCorpusListing(path: rp(Fixed.corpus + "/links"), entries: links); checks += 1
            try refuses { try checkCorpusListing(path: rp(Fixed.corpus + "/links"), entries: links.map { DirectoryEntry(name: $0.name, attributes: FileAttributes(kind: .regular)) }) }
            let token = CancellationToken(), quarter = QuarterProgress(token: token)
            await quarter.update(Fixed.largeBytes / 4 - 1); try check(!token.isCancelled)
            await quarter.update(Fixed.largeBytes / 4); try check(token.isCancelled)
            // Synthetic file gates under OUR ignored UUID build only. No local-only stress rerun.
            let root = BuildLocation.offlineRoot + "/unit-" + UUID().uuidString.lowercased()
            try require(mkdir(root, 0o700) == 0)
            let parent = ri_open_private(root, 1); try check(parent >= 0)
            var device: UInt64 = 0, inode: UInt64 = 0
            try check(remote_file_identity(parent, &device, &inode) == 0)
            let file = root + "/synthetic.txt", bytes = raw("synthetic-not-a-key\n")
            try PrivateInput.writeExclusive(bytes, to: file)
            try check(try PrivateInput.read(file, limit: 128) == bytes)
            try refuses { _ = try PrivateInput.read(file, limit: 2) }
            try refuses { try PrivateInput.writeExclusive(Data(), to: file) }
            try check(chmod(file, 0o644) == 0); try refuses { _ = try PrivateInput.read(file, limit: 128) }
            try check(chmod(file, 0o600) == 0)
            try check(link(file, root + "/hard") == 0); try refuses { _ = try PrivateInput.read(file, limit: 128) }
            try check(unlinkat(parent, "hard", 0) == 0)
            try check(symlink(file, root + "/link") == 0); try refuses { _ = try PrivateInput.read(root + "/link", limit: 128) }
            try check(unlinkat(parent, "link", 0) == 0)
            try check(symlink(root, root + "/parent-link") == 0); try refuses { _ = try PrivateInput.read(root + "/parent-link/synthetic.txt", limit: 128) }
            try check(unlinkat(parent, "parent-link", 0) == 0)
            try check(mkfifo(root + "/fifo", 0o600) == 0); try refuses { _ = try PrivateInput.read(root + "/fifo", limit: 128) }
            try check(unlinkat(parent, "fifo", 0) == 0)
            var acl = acl_init(1), entry: acl_entry_t?
            try check(acl != nil && acl_create_entry(&acl, &entry) == 0)
            try check(acl_set_tag_type(entry!, ACL_EXTENDED_ALLOW) == 0)
            var identity = UUID().uuid
            try check(mbr_uid_to_uuid(getuid(), &identity) == 0 && acl_set_qualifier(entry!, &identity) == 0)
            var permissions: acl_permset_t?
            try check(acl_get_permset(entry!, &permissions) == 0 && acl_add_perm(permissions!, ACL_READ_DATA) == 0)
            try check(acl_set_file(file, ACL_TYPE_EXTENDED, acl) == 0)
            try refuses { _ = try PrivateInput.read(file, limit: 128) }
            acl_free(UnsafeMutableRawPointer(acl!)); try check(unlinkat(parent, "synthetic.txt", 0) == 0)
            // Cleanup allowlist must reject a bystander without deleting either entry.
            let service = ObservedService(try LocalFileService(rootDirectoryDescriptor: parent), ledger: Ledger(), ownsLocalRoot: true)
            try await put(service, rp("/owned"), bytes: raw("owned"))
            let bystander = openat(parent, "bystander", O_WRONLY | O_EXCL | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
            try check(bystander >= 0); Darwin.close(bystander)
            var refused = false
            do { try await service.cleanupOwned(root: .root) } catch { refused = true }
            try check(refused && access(root + "/owned", F_OK) == 0 && access(root + "/bystander", F_OK) == 0)
            try check(unlinkat(parent, "bystander", 0) == 0)
            // A known owned pathname swapped for a symlink is NOT an owned regular file.
            try check(unlinkat(parent, "owned", 0) == 0 && symlink("/does-not-exist-offline", root + "/owned") == 0)
            refused = false
            do { try await service.cleanupOwned(root: .root) } catch { refused = true }
            try check(refused)
            try check(unlinkat(parent, "owned", 0) == 0)
            try await put(service, rp("/owned"), bytes: raw("owned"))
            let scoped = ObservedService(try LocalFileService(rootDirectoryDescriptor: parent), ledger: Ledger(),
                remoteRoot: try rp("/fixture/home/owned-uuid"))
            for path in ["/fixture/home/owned-uuid-other", "/fixture/protected/denied.txt", "/outside"] {
                try refuses { try scoped.checkWrite(rp(path)) }
            }
            try scoped.checkWrite(rp("/fixture/home/owned-uuid/sub")); checks += 1
            await scoped.close()
            try await service.cleanupOwned(root: .root); await service.close(); checks += 1
            var final = stat()
            try check(fstat(parent, &final) == 0 && UInt64(final.st_dev) == device && UInt64(final.st_ino) == inode)
            Darwin.close(parent); try check(rmdir(root) == 0)
            try check(remote_file_fixture_sockets() == 0)
            print("Offline safety checks passed: \(checks). Synthetic metadata/private-file rejection only; no fixture, credential, socket, SSH/SFTP or large-data execution.")
        } catch {
            fputs("Offline safety failure after \(checks) checks; \((error as? GateError)?.rawValue ?? "private-gate-or-library-error"). No private details.\n", stderr)
            exit(1)
        }
    }
}
