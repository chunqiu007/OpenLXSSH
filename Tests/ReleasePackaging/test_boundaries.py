"""Additional license/provenance, archive and signing error boundaries; no real signing."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from fixtures import (FakeRunner, build_script_inputs, dependency_sources, fake_app, load_commands,
                      packaging as p, write_macho, zip_app)
from test_packaging import TemporaryCase


def app_lock(root):
    return root / "OpenLXSSH.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"


def add_transport_lock(root):
    lock = p.json_file(app_lock(root))
    lock["pins"] += p.json_file(root / "Packages/OpenLXSSHTransport/Package.resolved")["pins"]
    app_lock(root).write_text(json.dumps(lock))


def native_provenance(root):
    base = root / "Packages/OpenLXSSHFiles/.build/native"
    license_dir = base / "install/licenses"
    paths = {"libssh2/COPYING": b"UNIT BSD LICENSE PLACEHOLDER ONLY\n",
             "libssh2/SOURCE-NOTICES.txt": b"UNIT libssh2 file notices only\n",
             "openssl/LICENSE.txt": b"UNIT APACHE LICENSE PLACEHOLDER ONLY\n",
             "openssl/SOURCE-NOTICES.txt": b"UNIT OpenSSL source notices only\n"}
    for relative, content in paths.items():
        path = license_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    outputs = {}
    for name in ("libssh2.a", "libssl.a", "libcrypto.a"):
        path = base / "install/lib" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"UNIT ARCHIVE PLACEHOLDER ONLY " + name.encode())
        outputs[path.relative_to(base).as_posix()] = p.sha256(path)
    lock_path = root / "Packages/OpenLXSSHFiles/native-inputs.json"
    lock = p.json_file(lock_path)
    lock["openssl"]["licenseSHA256"] = p.sha256(license_dir / "openssl/LICENSE.txt")
    lock_path.write_text(json.dumps(lock))
    script = root / "Packages/OpenLXSSHFiles/Scripts/build-native.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("# UNIT build script fixture only; never executed\n")
    manifest = {"inputs": {"lockSHA256": p.sha256(lock_path), "scriptSHA256": p.sha256(script)}, "dependencies": lock,
                "outputs": outputs,
                "licenseSHA256": {relative: p.sha256(license_dir / relative) for relative in paths}}
    (base / "manifest.json").write_text(json.dumps(manifest))
    return base


class DependencyTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        dependency_sources(self.root)
        self.app = fake_app(self.root)
        _, self.code = p.inspect_bundle(self.app)

    def prepare(self, runner=None):
        return p.prepare_dependency_notices(self.root, self.app, self.code, runner or FakeRunner())

    def test_swiftterm_included_not_transitive_resolved_only_packages(self):
        add_transport_lock(self.root)
        records = self.prepare(FakeRunner(extra_symbols="_$s9SwiftTermUnit\n"))
        included = {item["identity"] for item in records if item["included"]}
        self.assertEqual(included, {"grdb.swift", "swiftterm"})
        self.assertTrue(all(not item["licensePaths"] for item in records if item["identity"] in {"h", "swift-png", "swift-argument-parser"}))

    def test_native_included_with_exact_archive_and_all_source_license_hashes(self):
        native_provenance(self.root)
        records = self.prepare(FakeRunner(extra_symbols="_libssh2_session_init_ex\n_OpenSSL_version\n"))
        included = {item["identity"] for item in records if item["included"]}
        self.assertEqual(included, {"grdb.swift", "libssh2", "openssl"})
        for item in records:
            if item["identity"] in {"libssh2", "openssl"}:
                self.assertEqual(len(item["licensePaths"]), 2)
                for license_item in item["licenses"]:
                    self.assertEqual(p.sha256(self.app / license_item["path"]), license_item["sha256"])

    def test_libssh2_without_openssl_cannot_claim_dependency_completeness(self):
        self.error("dependency-evidence", self.prepare, FakeRunner(extra_symbols="_libssh2_session_init_ex\n"))

    def test_native_archive_and_license_tamper_refused(self):
        native = native_provenance(self.root)
        archive = native / "install/lib/libcrypto.a"
        archive.write_bytes(archive.read_bytes() + b"tamper")
        runner = FakeRunner(extra_symbols="_libssh2_session_init_ex\n_OpenSSL_version\n")
        self.error("native-provenance", self.prepare, runner)
        # Recreate this test's own fake provenance; never touch another task's outputs.
        native_provenance(self.root)
        (native / "install/licenses/libssh2/SOURCE-NOTICES.txt").write_text("tampered fixture")
        self.error("license-checksum", self.prepare, runner)

    def test_changed_native_lock_refused(self):
        native_provenance(self.root)
        lock = self.root / "Packages/OpenLXSSHFiles/native-inputs.json"
        lock.write_bytes(lock.read_bytes() + b"\n")
        self.error("native-provenance", self.prepare,
                   FakeRunner(extra_symbols="_libssh2_session_init_ex\n_OpenSSL_version\n"))

    def test_escaping_license_path_and_symlink_input_refused(self):
        native = native_provenance(self.root)
        manifest_path = native / "manifest.json"
        manifest = p.json_file(manifest_path)
        manifest["licenseSHA256"]["../escape"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest))
        self.error("unsafe-path", self.prepare,
                   FakeRunner(extra_symbols="_libssh2_session_init_ex\n_OpenSSL_version\n"))
        source = self.root / "Packages/OpenLXSSHCore/ThirdPartyNotices/GRDB-LICENSE.txt"
        source.unlink()
        source.symlink_to(self.root / "Packages/OpenLXSSHFiles/native-inputs.json")
        self.error("symlink-parent", p.safe_source, self.root, source.relative_to(self.root).as_posix())

    def test_unknown_app_lock_dependency_refused_not_silently_omitted(self):
        path = app_lock(self.root)
        lock = p.json_file(path)
        lock["pins"].append({"identity": "unreviewed", "location": "https://example.invalid/unreviewed",
                             "state": {"revision": "9" * 40, "version": "1.0.0"}})
        path.write_text(json.dumps(lock))
        self.error("unknown-dependency", self.prepare)

    def test_integrated_product_requires_binary_evidence(self):
        with patch.object(p, "integrated_products", return_value={"OpenLXSSHCore", "OpenLXSSHTransport"}):
            self.error("dependency-evidence", self.prepare)

    def test_mismatched_app_revision_and_conflicting_notice_refused(self):
        path = app_lock(self.root)
        original = path.read_text()
        lock = p.json_file(path)
        lock["pins"][0]["state"]["revision"] = "0" * 40
        path.write_text(json.dumps(lock))
        self.error("dependency-pin", self.prepare)
        path.write_text(original)
        conflict = self.app / "Contents/Resources/ThirdPartyNotices/grdb-swift/GRDB-LICENSE.txt"
        conflict.parent.mkdir(parents=True)
        conflict.write_text("different fixture license")
        self.error("license-conflict", self.prepare)


class ArchiveAndRecoveryTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.app = fake_app(self.root)
        self.archive = self.root / "OpenLXSSH.zip"

    def test_ditto_archive_roundtrip_uses_only_temporary_fake_app(self):
        if not Path("/usr/bin/ditto").is_file():
            self.skipTest("macOS ditto not available")
        (self.app / "Contents/Resources/alias").symlink_to("NOTICE.txt")
        # Exercise the real local archiver only on disposable non-executable fixture bytes.
        p.Runner().checked(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", self.app, self.archive])
        p.verify_zip(self.archive, self.app, p.tree_inventory(self.app))

    def test_archive_metadata_must_correspond_to_validated_app(self):
        for name in ("__MACOSX/random/._secret", "__MACOSX/OpenLXSSH.app/._missing", "OpenLXSSH.app/extra/"):
            zip_app(self.app, self.archive)
            with zipfile.ZipFile(self.archive, "a") as stream:
                stream.writestr(name, b"")
            self.error("archive-layout", p.verify_zip, self.archive, self.app, p.tree_inventory(self.app))

    def test_manifest_incomplete_marker_never_looks_complete(self):
        zip_app(self.app, self.archive)
        path = self.root / "manifest.json"
        p.write_json_exclusive(path, {"schemaVersion": 1, "status": "internal-candidate", "notarized": False,
                                     "uploaded": False, "artifacts": p.artifact_record(self.app, self.archive), "dependencies": []})
        (self.root / "INCOMPLETE.json").write_text("{}")
        self.error("manifest-status", p.verify_manifest, path)

    def test_output_parent_dotdot_is_not_accepted_lexically(self):
        (self.root / "one").mkdir()
        self.error("unsafe-path", p.owned_directory, self.root / "one/../../outside", self.root)

    def test_json_created_exclusively_private_and_symlink_never_followed(self):
        target = self.root / "record.json"
        p.write_json_exclusive(target, {"status": "unit"})
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            p.write_json_exclusive(target, {"status": "overwritten"})
        link = self.root / "link.json"
        link.symlink_to(target)
        with self.assertRaises(FileExistsError):
            p.write_json_exclusive(link, {"status": "overwritten"})
        self.assertEqual(p.json_file(target), {"status": "unit"})

    def test_spctl_timeout_is_explicit_not_gatekeeper_acceptance(self):
        class TimeoutRunner:
            def run(inner, *args, **kwargs):
                raise p.PackagingError("command-timeout", "unit timeout")
        result = p.assess_gatekeeper(self.app, TimeoutRunner(), self.root / "spctl.log")
        self.assertIsNone(result["exitCode"])
        self.assertTrue(result["timedOut"])
        self.assertFalse(result["gatekeeperAccepted"])


class SigningErrorTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.app = fake_app(self.root)
        _, self.code = p.inspect_bundle(self.app)

    def test_wrong_authority_team_timestamp_and_deep_failure_refused(self):
        mutations = (("signature-identity", b"Authority=Apple Development: Fixture Only (TEAMTEST)", b"Authority=Apple Development: Wrong"),
                     ("runtime-policy", b"TeamIdentifier=TEAMTEST", b"TeamIdentifier=not set"),
                     ("timestamp-policy", b"TeamIdentifier=TEAMTEST", b"TeamIdentifier=TEAMTEST\nTimestamp=unit timestamp"))
        for error_code, original, replacement in mutations:
            class MutatedRunner(FakeRunner):
                def run(inner, arguments, timeout=60, log_path=None):
                    result = super().run(arguments, timeout, log_path)
                    if "--verbose=4" in arguments:
                        return p.CommandResult(result.returncode, result.output.replace(original, replacement))
                    return result
            runner = MutatedRunner()
            self.error(error_code, p.apply_and_verify_signatures, self.app, self.code, runner,
                       "development", runner.certificate)
        class StrictFailure(FakeRunner):
            def run(inner, arguments, timeout=60, log_path=None):
                result = super().run(arguments, timeout, log_path)
                return p.CommandResult(1, result.output) if "--deep" in arguments else result
        runner = StrictFailure()
        self.error("signature-verification", p.apply_and_verify_signatures, self.app, self.code, runner,
                   "development", runner.certificate)

    def test_developer_id_timestamp_flag_only_in_simulated_runner_after_permission(self):
        class DeveloperIDRunner(FakeRunner):
            def run(inner, arguments, timeout=60, log_path=None):
                result = super().run(arguments, timeout, log_path)
                if "--verbose=4" in arguments:
                    return p.CommandResult(result.returncode, result.output + b"Timestamp=UNIT ONLY, NO REQUEST\n")
                return result
        runner = DeveloperIDRunner()
        runner.certificate = p.Identity("C" * 40, "Developer ID Application: Fixture Only (TEAMTEST)")
        record = p.apply_and_verify_signatures(self.app, self.code, runner, "developer-id", runner.certificate, True)
        signing = [call for call in runner.calls if "--sign" in call]
        self.assertTrue(signing)
        self.assertTrue(all("--timestamp" in call and "--timestamp=none" not in call for call in signing))
        self.assertTrue(record["timestampRequestExplicitlyAllowed"])
        self.assertFalse(record["uploaded"])

    def test_identity_mode_mismatch_rejected_before_any_sign(self):
        runner = FakeRunner()
        wrong = p.Identity("C" * 40, "Developer ID Application: Fixture Only (TEAMTEST)")
        # The CLI path always select_identity first; the low-level signer must enforce it too.
        self.error("signing-identity", p.apply_and_verify_signatures, self.app, self.code, runner, "development", wrong)
        self.assertFalse(any("--sign" in call for call in runner.calls))


class R1PreflightTests(TemporaryCase):
    def test_symlink_writes_are_rejected_before_build_and_external_tree_is_unchanged(self):
        paths = (
            "DerivedData/Release", "DerivedData/Release/Build/Products/Release/OpenLXSSH.app",
            "DerivedData/Release/Build/Products/Release/OpenLXSSH.app/Contents/Helpers/openlxssh-askpass",
            "DerivedData/Release/Build/Products/Release/OpenLXSSH.app/Contents/Resources/SwiftTerm-LICENSE",
            "DerivedData/Release/Build/Intermediates.noindex/BuildToolPluginIntermediates/swiftterm.output/SwiftTerm/SwiftTermBuildInfoPlugin/Generated",
            "DerivedData/Askpass-Release", "DerivedData/Askpass-Release/checkouts",
            "DerivedData/Askpass-Release/checkouts/swiftterm",
            "DerivedData/Askpass-Release/plugins/outputs/swiftterm/SwiftTerm/destination/SwiftTermBuildInfoPlugin",
            "DerivedData/Askpass-Release/arm64-apple-macosx/release/openlxssh-askpass",
            "DerivedData/SourcePackages", "DerivedData/SourcePackages/checkouts/swiftterm",
            "Scripts/build-app.sh", "Scripts/verify-build-plugin.py",
        )
        for relative in paths:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory(prefix="r1-root-") as root_name, tempfile.TemporaryDirectory(prefix="r1-external-") as external_name:
                root, external = Path(root_name).resolve(), Path(external_name).resolve()
                build_script_inputs(root)
                sentinel = external / "do-not-change.txt"
                sentinel.write_text("external unchanged\n")
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    target.unlink()
                target.symlink_to(external)
                before = p.tree_inventory(external)
                runner = FakeRunner(root)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.error("symlink-parent", p.package_candidate, root, p.parser().parse_args([]), runner)
                self.assertFalse(any(call[0] == "/bin/bash" for call in runner.calls), "build must never be invoked before preflight refusal")
                self.assertEqual(p.tree_inventory(external), before)

    def test_known_internal_swiftpm_alias_and_checkout_source_links_are_allowed(self):
        build_script_inputs(self.root)
        target = self.root / "DerivedData/Askpass-Release/arm64-apple-macosx/release"
        target.mkdir(parents=True)
        (target.parents[1] / "release").symlink_to("arm64-apple-macosx/release")
        checkout = self.root / "DerivedData/SourcePackages/checkouts/unit-package"
        (checkout / "Sources").mkdir(parents=True)
        (checkout / "Sources/input.txt").write_text("public source fixture\n")
        (checkout / "Plugins").mkdir()
        (checkout / "Plugins/relative-input").symlink_to("../Sources/input.txt")
        before = p.tree_inventory(self.root)
        p.preflight_build_paths(self.root)
        self.assertEqual(p.tree_inventory(self.root), before)

    def test_bad_swiftpm_alias_and_cross_checkout_link_refused_without_writes(self):
        build_script_inputs(self.root)
        base = self.root / "DerivedData/Askpass-Release"
        (base / "other").mkdir(parents=True)
        alias = base / "release"
        alias.symlink_to("other")
        self.error("symlink-parent", p.preflight_build_paths, self.root)
        alias.unlink()
        first = base / "checkouts/first"
        second = base / "checkouts/second"
        first.mkdir(parents=True)
        second.mkdir()
        (first / "cross-checkout").symlink_to("../second")
        self.error("symlink-parent", p.preflight_build_paths, self.root)

    def test_internal_generated_output_symlink_also_refused_before_build(self):
        build_script_inputs(self.root)
        target = self.root / "DerivedData/Askpass-Release/plugins/outputs/swiftterm/SwiftTerm/destination/SwiftTermBuildInfoPlugin"
        target.parent.mkdir(parents=True)
        safe = self.root / "DerivedData/internal-other"
        safe.mkdir()
        target.symlink_to(safe)
        runner = FakeRunner(self.root)
        with contextlib.redirect_stderr(io.StringIO()):
            self.error("symlink-parent", p.package_candidate, self.root, p.parser().parse_args([]), runner)
        self.assertFalse(any(call[0] == "/bin/bash" for call in runner.calls))
        self.assertEqual(list(safe.iterdir()), [])


class R1LoaderTokenTests(TemporaryCase):
    def test_bare_loader_and_executable_rpaths_accept_real_helper_shape(self):
        app = fake_app(self.root)
        _, code = p.inspect_bundle(app)
        class BareRunner(FakeRunner):
            def run(inner, arguments, timeout=60, log_path=None):
                if len(arguments) > 1 and arguments[1] == "otool":
                    inner.calls.append([str(arg) for arg in arguments])
                    return p.CommandResult(0, load_commands(dependencies=("/usr/lib/libSystem.B.dylib",),
                                                            rpaths=("@loader_path", "@executable_path")).encode())
                return super().run(arguments, timeout, log_path)
        infos, edges = p.inspect_macho(app, code, BareRunner())
        self.assertEqual(len(infos), 2)
        self.assertEqual(edges, [])
        helper = app / p.HELPER
        self.assertEqual(p.expanded_path("@loader_path", helper, helper, app), helper.parent)
        self.assertEqual(p.expanded_path("@executable_path", helper, helper, app), helper.parent)

    def test_bare_tokens_reject_external_context_and_parent_or_symlink_escape(self):
        app = fake_app(self.root)
        helper = app / p.HELPER
        external = self.root / "outside/helper"
        for token, loader, executable in (("@loader_path", external, helper), ("@executable_path", helper, external),
                                          ("@loader_path/../../../../outside", helper, helper)):
            self.error("external-dependency", p.expanded_path, token, loader, executable, app)
        (app / "Contents/Helpers/link").symlink_to(self.root)
        self.error("external-dependency", p.expanded_path, "@loader_path/link", helper, helper, app)


class R1CodeProvenanceTests(TemporaryCase):
    def test_runtime_ownership_and_dependency_license_paths_are_explicit_per_node(self):
        dependency_sources(self.root)
        with contextlib.redirect_stdout(io.StringIO()):
            path = p.package_candidate(self.root, p.parser().parse_args([]), FakeRunner(self.root))
        manifest = p.verify_manifest(path)
        nodes = {item["path"]: item for item in manifest["runtimeCode"]}
        self.assertEqual(set(nodes), {"Contents/MacOS/OpenLXSSH", p.HELPER})
        self.assertEqual(nodes[p.HELPER]["source"]["owner"], "OpenLXSSHTransport")
        self.assertEqual(nodes["Contents/MacOS/OpenLXSSH"]["source"]["owner"], "OpenLXSSH")
        for node in nodes.values():
            self.assertEqual(node["filetype"], "MH_EXECUTE")
            self.assertEqual(node["source"]["revision"], manifest["source"]["commit"])
            for identity in node["linkedDependencies"]:
                dependency = next(item for item in manifest["dependencies"] if item["identity"] == identity)
                self.assertIn(node["path"], dependency["linkedCodePaths"])
                self.assertTrue(dependency["included"] and dependency["licensePaths"])

    def test_reachable_unreviewed_dylib_cannot_obtain_a_completed_manifest(self):
        dependency_sources(self.root)
        build_script_inputs(self.root)
        class UnknownLibraryRunner(FakeRunner):
            def run(inner, arguments, timeout=60, log_path=None):
                if str(arguments[0]) == "/bin/bash":
                    result = super().run(arguments, timeout, log_path)
                    app = self.root / "DerivedData/Release/Build/Products/Release/OpenLXSSH.app"
                    write_macho(app / "Contents/Frameworks/libunreviewed.dylib")
                    return result
                if len(arguments) > 1 and arguments[1] == "otool":
                    dependencies = ("@rpath/libunreviewed.dylib",) if str(arguments[-1]).endswith("Contents/MacOS/OpenLXSSH") else ("/usr/lib/libSystem.B.dylib",)
                    return p.CommandResult(0, load_commands(dependencies, ("@executable_path/../Frameworks",)).encode())
                return super().run(arguments, timeout, log_path)
        runner = UnknownLibraryRunner(self.root)
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.error("unreviewed-runtime-code", p.package_candidate, self.root, p.parser().parse_args([]), runner)
        self.assertEqual(list((self.root / "DerivedData/Distributions").rglob("manifest.json")), [])
        self.assertFalse(any("--sign" in call for call in runner.calls))


class R1HeaderTests(TemporaryCase):
    @staticmethod
    def header_bytes(filetype=2, entry=True, malformed_entry=False):
        # Independent mach_header_64 + segment_command_64 + entry_point_command.
        # This is a structural header fixture, not output supplied by FakeRunner.
        segment = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0x100000000, 0x1000,
                              0, 512, 5, 5, 0, 0)
        main = struct.pack("<IIQQ", 0x80000028, 16 if malformed_entry else 24, 160, 0) if entry else b""
        commands = segment + main
        header = struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, filetype, 2 if entry else 1, len(commands), 0x200085, 0)
        return (header + commands).ljust(512, b"\x00")

    def test_dylib_object_and_bundle_cannot_replace_executable_entrypoints(self):
        for relative in ("Contents/MacOS/OpenLXSSH", p.HELPER):
            for filetype in (1, 6, 8):
                with self.subTest(relative=relative, filetype=filetype), tempfile.TemporaryDirectory(prefix="r1-header-") as directory:
                    app = fake_app(Path(directory).resolve())
                    target = app / relative
                    target.write_bytes(self.header_bytes(filetype=filetype))
                    _, code = p.inspect_bundle(app)
                    self.error("macho-filetype", p.inspect_macho, app, code, FakeRunner())

    def test_executable_and_dylib_headers_require_their_actual_filetype(self):
        entry = write_macho(self.root / "entry", filetype=2)
        library = write_macho(self.root / "library.dylib", filetype=6)
        executable_header = p.inspect_macho_header(entry, 2)
        library_header = p.inspect_macho_header(library, 6)
        self.assertEqual(executable_header.filetype, 2)
        self.assertGreater(executable_header.entry_point, 0)
        self.assertEqual(library_header.filetype, 6)
        self.assertIsNone(library_header.entry_point)
        self.error("macho-filetype", p.inspect_macho_header, entry, 6)
        self.error("macho-filetype", p.inspect_macho_header, library, 2)
        library.write_bytes(self.header_bytes(filetype=6))
        self.error("macho-entrypoint", p.inspect_macho_header, library, 6)

    def test_truncated_nonarm64_fat_and_oversized_header_refused(self):
        path = self.root / "entry"
        original = self.header_bytes()
        cases = (original[:12], original[:4] + struct.pack("<I", 0x1000007) + original[8:],
                 bytes.fromhex("cafebabe") + original[4:],
                 original[:20] + struct.pack("<I", 20 * 1024 * 1024) + original[24:])
        for content in cases:
            path.write_bytes(content)
            self.error("macho-header", p.inspect_macho_header, path, 2)

    def test_missing_malformed_or_outside_executable_segment_entry_refused(self):
        for content in (self.header_bytes(entry=False), self.header_bytes(malformed_entry=True),
                        self.header_bytes()[:112] + struct.pack("<Q", 800) + self.header_bytes()[120:]):
            with self.subTest(length=len(content)), tempfile.TemporaryDirectory(prefix="r1-entry-") as directory:
                app = fake_app(Path(directory).resolve())
                (app / p.HELPER).write_bytes(content)
                _, code = p.inspect_bundle(app)
                self.error("macho-entrypoint", p.inspect_macho, app, code, FakeRunner())


if __name__ == "__main__":
    unittest.main()
