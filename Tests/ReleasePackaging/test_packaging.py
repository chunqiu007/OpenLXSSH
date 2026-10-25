import ast
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from fixtures import (FakeRunner, SCRIPT, build_script_inputs, dependency_sources, fake_app, load_commands,
                      packaging as p, update_info, write_macho, zip_app)


class TemporaryCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="OpenLXSSH-Packaging-Unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(p.PackagingError) as result:
            function(*args, **kwargs)
        self.assertEqual(result.exception.code, code)


class PathAndBundleTests(TemporaryCase):
    def test_safe_relative_path(self):
        self.assertEqual(p.relative_path("Contents/Resources/License.txt"), Path("Contents/Resources/License.txt"))

    def test_parent_absolute_backslash_and_empty_paths_rejected(self):
        for value in ("", "/tmp/escape", "../escape", "a/../escape", "a//b", "a/./b", "a\\b", "a\x00b"):
            with self.subTest(value=value):
                self.error("unsafe-path", p.relative_path, value)

    def test_output_existing_target_is_preserved(self):
        directory = p.owned_directory(self.root / "DerivedData/Distributions/one", self.root, exclusive=True)
        sentinel = directory / "do-not-touch.txt"
        sentinel.write_text("unchanged")
        self.error("output-exists", p.owned_directory, directory, self.root, exclusive=True)
        self.assertEqual(sentinel.read_text(), "unchanged")

    def test_output_symlink_parent_and_parent_escape_refused(self):
        (self.root / "DerivedData").symlink_to(self.root.parent)
        self.error("symlink-parent", p.owned_directory, self.root / "DerivedData/test", self.root)
        self.error("unsafe-path", p.owned_directory, self.root.parent / "other", self.root)

    def test_minimal_app_and_required_helper(self):
        app = fake_app(self.root)
        info, code = p.inspect_bundle(app)
        self.assertEqual(info["CFBundleName"], "OpenLXSSH")
        self.assertEqual({item.relative_to(app).as_posix() for item in code},
                         {"Contents/MacOS/OpenLXSSH", p.HELPER})
        (app / p.HELPER).unlink()
        self.error("missing-helper", p.inspect_bundle, app)

    def test_product_display_bundle_and_hostprobe_rejected(self):
        app = fake_app(self.root)
        for key, bad in (("CFBundleName", "Other"), ("CFBundleDisplayName", "Other"),
                         ("CFBundleExecutable", "../Other"), ("CFBundleIdentifier", p.BUNDLE_ID + ".HostProbe")):
            with self.subTest(key=key):
                original = plistlib.loads((app / "Contents/Info.plist").read_bytes())[key]
                update_info(app, **{key: bad})
                self.error("product-identity", p.inspect_bundle, app)
                update_info(app, **{key: original})

    def test_app_minimum_os_and_version_validation(self):
        app = fake_app(self.root)
        for value in ("15.0", "25.9", "26.1", "27.0"):
            update_info(app, LSMinimumSystemVersion=value)
            self.error("minimum-os", p.inspect_bundle, app)
        update_info(app, LSMinimumSystemVersion="26.0", CFBundleVersion="$(CURRENT_PROJECT_VERSION)")
        self.error("product-version", p.inspect_bundle, app)

    def test_escaping_and_absolute_symlinks_refused(self):
        app = fake_app(self.root)
        outside = self.root / "outside.txt"
        outside.write_text("outside fixture")
        link = app / "Contents/Resources/link.txt"
        for target in (str(outside), "../../../outside.txt"):
            link.symlink_to(target)
            self.error("escaping-symlink", p.inspect_bundle, app)
            link.unlink()

    def test_dangling_and_cyclic_symlinks_have_controlled_diagnostics(self):
        app = fake_app(self.root)
        link = app / "Contents/Resources/link"
        for target in ("does-not-exist", "link"):
            link.symlink_to(target)
            self.error("invalid-symlink", p.inspect_bundle, app)
            link.unlink()

    def test_internal_symlink_allowed_and_not_followed_twice(self):
        app = fake_app(self.root)
        (app / "Contents/Resources/alias.txt").symlink_to("NOTICE.txt")
        _, code = p.inspect_bundle(app)
        self.assertEqual(len(code), 2)
        symlinks = [item for item in p.tree_inventory(app) if item["type"] == "symlink"]
        self.assertEqual(symlinks[0]["target"], "NOTICE.txt")

    def test_top_level_resource_symlink_refused(self):
        app = fake_app(self.root)
        (app / "Contents/Resources/NOTICE.txt").unlink()
        (app / "Contents/Resources").rmdir()
        (app / "Contents/RealResources").mkdir()
        (app / "Contents/Resources").symlink_to("RealResources")
        self.error("bundle-layout", p.inspect_bundle, app)

    def test_fixture_xcuserdata_build_and_secret_filenames_refused(self):
        app = fake_app(self.root)
        for name in ("Fixtures", "unit-fixture.json", "TransportFixture", "testdata", "Tests", "xcuserdata", ".build",
                     "id_ed25519", ".env", "identity.p12", "unit.xctest", "debug.log", "secret.txt", "password.txt", "certificate.der"):
            with self.subTest(name=name):
                path = app / "Contents/Resources" / name
                path.write_text("disposable non-secret fixture")
                self.error("forbidden-content", p.inspect_bundle, app)
                path.unlink()

    def test_private_key_content_refused_without_echoing_content(self):
        app = fake_app(self.root)
        secret = app / "Contents/Resources/innocent.txt"
        secret.write_bytes(b"unit marker only\n-----BEGIN OPENSSH PRIVATE KEY-----\nNOT A REAL KEY\n")
        self.error("secret-content", p.inspect_bundle, app)

    def test_unknown_resource_code_and_script_refused(self):
        app = fake_app(self.root)
        code = write_macho(app / "Contents/Resources/unexpected-code")
        self.error("unknown-code-path", p.inspect_bundle, app)
        code.unlink()
        code.write_text("#!/bin/false\n")
        code.chmod(0o755)
        self.error("unexpected-executable", p.inspect_bundle, app)

    def test_fifo_hardlink_and_world_writable_refused(self):
        app = fake_app(self.root)
        target = app / "Contents/Resources/bad"
        os.mkfifo(target)
        self.error("special-file", p.inspect_bundle, app)
        target.unlink()
        os.link(app / "Contents/Resources/NOTICE.txt", target)
        self.error("hardlinked-file", p.inspect_bundle, app)
        target.unlink()
        target.write_text("fixture")
        target.chmod(0o666)
        self.error("unsafe-permissions", p.inspect_bundle, app)

    def test_extra_bundle_code_directory_refused(self):
        app = fake_app(self.root)
        (app / "Contents/XPCServices").mkdir()
        self.error("bundle-layout", p.inspect_bundle, app)


class MachOTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.app = fake_app(self.root)
        _, self.code = p.inspect_bundle(self.app)
        self.main = self.app / "Contents/MacOS/OpenLXSSH"
        self.helper = self.app / p.HELPER

    def info(self, path, dependencies=(), rpaths=(), **values):
        return p.parse_macho(path, "arm64", load_commands(dependencies, rpaths, **values))

    def graph(self, infos):
        return p.verify_dependency_graph(self.app, infos)

    def test_arm64_mac26_metadata(self):
        info = self.info(self.main, dependencies=("/usr/lib/libSystem.B.dylib",))
        self.assertEqual((info.minimum_os, info.sdk), ("26.0", "26.2"))

    def test_x86_universal_arm64e_and_empty_architecture_refused(self):
        for architecture in ("x86_64", "arm64 x86_64", "arm64e", ""):
            self.error("unsupported-architecture", p.parse_macho, self.main, architecture, load_commands())

    def test_lower_higher_nonmac_and_missing_deployment_refused(self):
        for minimum in ("15.0", "26.1", "27.0"):
            self.error("minimum-os", self.info, self.main, minimum=minimum)
        self.error("unsupported-platform", self.info, self.main, platform="2")
        self.error("minimum-os", p.parse_macho, self.main, "arm64", "fixture:\n")

    def test_system_only_dependency_closure(self):
        self.assertEqual(self.graph([self.info(path, dependencies=("/usr/lib/libSystem.B.dylib",)) for path in self.code]), [])

    def test_homebrew_temp_checkout_and_bare_dependency_refused(self):
        for dependency in ("/opt/homebrew/lib/libssh2.dylib", "/usr/local/lib/x.dylib", "/tmp/x.dylib",
                           str(self.root / "checkout/lib.dylib"), "lib.dylib", "/usr/lib/../../tmp/x"):
            self.error("external-dependency", self.graph,
                       [self.info(self.main, dependencies=(dependency,)), self.info(self.helper)])

    def test_internal_rpath_and_recursive_loader_resolution(self):
        first = write_macho(self.app / "Contents/Frameworks/libfirst.dylib")
        second = write_macho(self.app / "Contents/Frameworks/libsecond.dylib")
        edges = self.graph([self.info(self.main, ("@rpath/libfirst.dylib",), ("@executable_path/../Frameworks",)),
                            self.info(self.helper), self.info(first, ("@loader_path/libsecond.dylib",)), self.info(second)])
        self.assertEqual(len(edges), 2)

    def test_inherited_rpaths_resolve_framework_dependencies(self):
        first = write_macho(self.app / "Contents/Frameworks/libfirst.dylib")
        second = write_macho(self.app / "Contents/Frameworks/libsecond.dylib")
        edges = self.graph([self.info(self.main, ("@rpath/libfirst.dylib",), ("@executable_path/../Frameworks",)),
                            self.info(self.helper), self.info(first, ("@rpath/libsecond.dylib",)), self.info(second)])
        self.assertEqual(len(edges), 2)

    def test_unresolved_rpath_parent_escape_and_external_rpath_refused(self):
        self.error("unresolved-rpath", self.graph,
                   [self.info(self.main, ("@rpath/missing.dylib",), ("@executable_path/../Frameworks",)), self.info(self.helper)])
        self.error("unsafe-path", self.graph,
                   [self.info(self.main, ("@rpath/../outside.dylib",), ("@executable_path/../Frameworks",)), self.info(self.helper)])
        for rpath in ("/opt/homebrew/lib", "@executable_path/../../../../outside"):
            self.error("external-dependency", self.graph, [self.info(self.main, rpaths=(rpath,)), self.info(self.helper)])

    def test_symlink_runtime_escape_and_non_macho_target_refused(self):
        outside = write_macho(self.root / "external.dylib")
        framework = self.app / "Contents/Frameworks"
        framework.mkdir()
        link = framework / "libescape.dylib"
        link.symlink_to(outside)
        self.error("external-dependency", self.graph,
                   [self.info(self.main, ("@loader_path/../Frameworks/libescape.dylib",)), self.info(self.helper)])
        link.unlink()
        link.write_text("resource, not code")
        self.error("unvalidated-code", self.graph,
                   [self.info(self.main, ("@loader_path/../Frameworks/libescape.dylib",)), self.info(self.helper)])

    def test_unused_embedded_code_refused(self):
        unused = write_macho(self.app / "Contents/Frameworks/unused.dylib")
        self.error("unused-code", self.graph, [self.info(path) for path in (*self.code, unused)])

    def test_external_library_install_name_refused(self):
        self.error("external-dependency", self.info, self.main, install_name="/opt/homebrew/lib/libx.dylib")


class SourceAndIdentityTests(TemporaryCase):
    def git(self, *arguments):
        result = subprocess.run(["/usr/bin/git", "-C", str(self.root), *arguments], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True)
        return result.stdout

    def repository(self):
        self.git("init", "--quiet")
        (self.root / "Application").mkdir()
        (self.root / "Application/source.swift").write_text("// disposable repository\n")
        self.git("add", "Application/source.swift")
        self.git("-c", "user.name=Packaging Unit Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Disposable test fixture")

    def test_clean_dirty_refusal_and_explicit_dirty(self):
        self.repository()
        clean = p.source_state(self.root, p.Runner(), False)
        self.assertFalse(clean["dirty"])
        self.assertFalse(clean["dirtyExplicitFlag"])
        (self.root / "Application/source.swift").write_text("// changed fixture\n")
        self.error("dirty-source", p.source_state, self.root, p.Runner(), False)
        dirty = p.source_state(self.root, p.Runner(), True)
        self.assertTrue(dirty["dirty"])
        self.assertTrue(dirty["dirtyExplicitFlag"])
        self.assertNotEqual(clean["worktreeFingerprintSHA256"], dirty["worktreeFingerprintSHA256"])

    def test_untracked_build_input_change_detected_without_status_change(self):
        self.repository()
        source = self.root / "Application/new.swift"
        source.write_text("// first fixture\n")
        before = p.source_state(self.root, p.Runner(), True)
        source.write_text("// second fixture\n")
        self.assertNotEqual(before, p.source_state(self.root, p.Runner(), True))

    def test_certificate_selection_requires_correct_type_and_unique_or_exact(self):
        development = p.Identity("A" * 40, "Apple Development: Fixture One (TEAMONE)")
        second = p.Identity("B" * 40, "Apple Development: Fixture Two (TEAMTWO)")
        developer_id = p.Identity("C" * 40, "Developer ID Application: Fixture (TEAMID)")
        installer = p.Identity("D" * 40, "Developer ID Installer: Fixture (TEAMID)")
        self.assertEqual(p.select_identity([development, developer_id, installer], "development"), development)
        self.assertEqual(p.select_identity([development, developer_id, installer], "developer-id"), developer_id)
        self.error("signing-identity", p.select_identity, [development, second], "development")
        self.error("signing-identity", p.select_identity, [installer], "developer-id")
        self.error("signing-identity", p.select_identity, [development], "development", "Fixture")
        self.assertEqual(p.select_identity([development, second], "development", second.fingerprint.lower()), second)
        self.assertEqual(p.select_identity([development, second], "development", development.name), development)
        self.error("signing-identity", p.select_identity, [development, developer_id], "development", developer_id.fingerprint)

    def test_duplicate_certificate_name_requires_fingerprint(self):
        identities = [p.Identity(letter * 40, "Apple Development: Same Fixture") for letter in ("A", "B")]
        self.error("signing-identity", p.select_identity, identities, "development", identities[0].name)

    def test_parse_only_valid_identity_lines_and_deduplicate(self):
        line = f'  1) {"A" * 40} "Apple Development: Fixture"\n'
        parsed = p.parse_identities(line + line + f'  2) {"B" * 40} "Developer ID Application: Expired" (CSSMERR_TP_CERT_EXPIRED)\n')
        self.assertEqual(len(parsed), 1)

    def test_unsigned_default_and_timestamp_requires_extra_explicit_authorization(self):
        self.assertEqual(p.parser().parse_args([]).signing, "unsigned")
        self.error("timestamp-permission", p.validate_signing_options, "developer-id", None, False)
        self.error("signing-options", p.validate_signing_options, "unsigned", "A" * 40, False)
        self.error("signing-options", p.validate_signing_options, "development", None, True)
        p.validate_signing_options("developer-id", "A" * 40, True)


class SignatureTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.app = fake_app(self.root)
        _, self.code = p.inspect_bundle(self.app)

    def test_unsigned_never_runs_sign_or_security_and_records_failed_validation(self):
        runner = FakeRunner()
        record = p.apply_and_verify_signatures(self.app, self.code, runner, "unsigned")
        self.assertFalse(record["verified"])
        self.assertFalse(record["signingPerformed"])
        self.assertFalse(record["hardenedRuntimeVerified"])
        self.assertFalse(any("--sign" in call or call[0] == "/usr/bin/security" for call in runner.calls))
        self.assertTrue(any("--deep" in call and "--strict" in call for call in runner.calls))
        self.assertEqual(len(record["targets"]), 3)

    def test_development_signs_leaves_before_app_offline_and_strictly_verifies(self):
        runner = FakeRunner()
        record = p.apply_and_verify_signatures(self.app, self.code, runner, "development", runner.certificate)
        signing = [call for call in runner.calls if "--sign" in call]
        self.assertEqual(signing[-1][-1], str(self.app))
        self.assertLess(next(index for index, call in enumerate(signing) if call[-1] == str(self.app / p.HELPER)), len(signing) - 1)
        self.assertTrue(all("--timestamp=none" in call and "--deep" not in call for call in signing))
        self.assertTrue(record["verified"])
        self.assertTrue(record["hardenedRuntimeVerified"])
        self.assertFalse(record["notarized"])
        self.assertFalse(record["uploaded"])

    def test_nested_framework_signing_order(self):
        framework = self.app / "Contents/Frameworks/Outer.framework"
        outer = write_macho(framework / "Versions/A/Outer")
        inner_framework = framework / "Versions/A/Frameworks/Inner.framework"
        inner = write_macho(inner_framework / "Versions/A/Inner")
        targets = p.signing_targets(self.app, self.code + [outer, inner])
        self.assertLess(targets.index(inner), targets.index(inner_framework))
        self.assertLess(targets.index(inner_framework), targets.index(framework))
        self.assertLess(targets.index(outer), targets.index(framework))
        self.assertEqual(targets[-1], self.app)

    def test_bad_runtime_and_unexpected_preexisting_identity_refused(self):
        runner = FakeRunner(bad_runtime=True)
        self.error("runtime-policy", p.apply_and_verify_signatures, self.app, self.code, runner,
                   "development", runner.certificate)
        self.error("unexpected-signature", p.apply_and_verify_signatures, self.app, self.code,
                   FakeRunner(signed=True), "unsigned")

    def test_debug_entitlements_refused_but_empty_diagnostic_allowed(self):
        p.check_entitlements(b"Executable=fixture\n")
        p.check_entitlements(plistlib.dumps({}))
        for key in p.DANGEROUS_ENTITLEMENTS:
            self.error("runtime-policy", p.check_entitlements, plistlib.dumps({key: True}))
        self.error("entitlements-parse", p.check_entitlements, b"unrecognized tool output")


class ManifestAndWorkflowTests(TemporaryCase):
    def candidate(self):
        app = fake_app(self.root)
        archive = self.root / "OpenLXSSH.zip"
        zip_app(app, archive)
        manifest = {"schemaVersion": 1, "status": "internal-candidate", "notarized": False, "uploaded": False,
                    "artifacts": p.artifact_record(app, archive), "dependencies": []}
        path = self.root / "manifest.json"
        p.write_json_exclusive(path, manifest)
        return app, archive, path, manifest

    def test_manifest_verifies_fake_tree_and_zip_checksums(self):
        _, _, path, expected = self.candidate()
        self.assertEqual(p.verify_manifest(path), expected)

    def test_manifest_detects_app_content_mode_and_symlink_change(self):
        app, _, path, _ = self.candidate()
        resource = app / "Contents/Resources/NOTICE.txt"
        original = resource.read_bytes()
        resource.write_bytes(original + b"tamper")
        self.error("app-checksum", p.verify_manifest, path)
        resource.write_bytes(original)
        resource.chmod(0o600)
        self.error("app-checksum", p.verify_manifest, path)

    def test_manifest_license_list_and_hash_entries_must_agree(self):
        _, _, path, manifest = self.candidate()
        manifest["dependencies"] = [{"included": True, "licensePaths": ["Contents/Resources/ThirdPartyNotices/LICENSE.txt"], "licenses": []}]
        path.write_text(json.dumps(manifest))
        self.error("manifest-license", p.verify_manifest, path)

    def test_manifest_detects_zip_tampering_and_path_escape(self):
        _, archive, path, manifest = self.candidate()
        with archive.open("ab") as stream:
            stream.write(b"tamper")
        self.error("zip-checksum", p.verify_manifest, path)
        manifest["artifacts"]["zip"]["path"] = "../OpenLXSSH.zip"
        path.write_text(json.dumps(manifest))
        self.error("unsafe-path", p.verify_manifest, path)

    def test_archive_extra_file_and_parent_escape_refused(self):
        app = fake_app(self.root)
        archive = self.root / "OpenLXSSH.zip"
        for name in ("../escape", "secret.txt", "OpenLXSSH.app/../../escape"):
            zip_app(app, archive)
            with zipfile.ZipFile(archive, "a") as stream:
                stream.writestr(name, b"not a real secret")
            code = "unsafe-path" if ".." in name else "archive-layout"
            self.error(code, p.verify_zip, archive, app, p.tree_inventory(app))

    def test_zip_internal_symlink_roundtrip(self):
        app = fake_app(self.root)
        (app / "Contents/Resources/alias").symlink_to("NOTICE.txt")
        archive = self.root / "OpenLXSSH.zip"
        zip_app(app, archive)
        p.verify_zip(archive, app, p.tree_inventory(app))

    def test_missing_helper_preserves_incomplete_record_and_no_complete_manifest(self):
        dependency_sources(self.root)
        runner = FakeRunner(self.root, missing_helper=True)
        with contextlib.redirect_stderr(io.StringIO()):
            self.error("missing-helper", p.package_candidate, self.root, p.parser().parse_args([]), runner)
        failures = list((self.root / "DerivedData/Distributions").glob("*/*/failure.json"))
        self.assertEqual(len(failures), 1)
        record = json.loads(failures[0].read_text())
        self.assertEqual((record["status"], record["errorCode"]), ("incomplete", "missing-helper"))
        self.assertTrue((failures[0].parent / "INCOMPLETE.json").is_file())
        self.assertEqual(list((self.root / "DerivedData/Distributions").rglob("manifest.json")), [])
        self.assertFalse(any("--sign" in call for call in runner.calls))

    def test_fixture_full_unsigned_workflow_truthful_dependencies_and_uuid_repeat(self):
        dependency_sources(self.root)
        runner = FakeRunner(self.root)
        with contextlib.redirect_stdout(io.StringIO()):
            path = p.package_candidate(self.root, p.parser().parse_args([]), runner)
        manifest = p.verify_manifest(path)
        self.assertEqual(manifest["classification"], "UNSIGNED INTERNAL CANDIDATE")
        included = {item["identity"] for item in manifest["dependencies"] if item["included"]}
        self.assertEqual(included, {"grdb.swift"})
        excluded = {item["identity"] for item in manifest["dependencies"] if not item["included"]}
        self.assertTrue({"swiftterm", "libssh2", "openssl"} <= excluded)
        self.assertEqual(manifest["spctl"]["exitCode"], 3)
        self.assertFalse(manifest["spctl"]["gatekeeperAccepted"])
        self.assertFalse(manifest["codesign"]["verified"])
        self.assertFalse(manifest["source"]["dirtyExplicitFlag"])
        self.assertFalse((path.parent / "INCOMPLETE.json").exists())
        self.assertEqual(list(path.parent.rglob("*.log")), [])
        self.assertFalse(any(call[0] == "/usr/bin/security" or "--sign" in call for call in runner.calls))
        # Repeat without removing/changing a preexisting candidate or another build output.
        class RepeatRunner(FakeRunner):
            def run(inner, arguments, timeout=60, log_path=None):
                if str(arguments[0]) == "/bin/bash":
                    inner.calls.append([str(arg) for arg in arguments])
                    Path(log_path).write_text("fixture reused build\n")
                    return p.CommandResult(0)
                return super().run(arguments, timeout, log_path)
        original = path.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            second = p.package_candidate(self.root, p.parser().parse_args([]), RepeatRunner(self.root))
        self.assertNotEqual(path.parent, second.parent)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(len(list(path.parent.parent.glob("*/manifest.json"))), 2)

    def test_dirty_source_changes_during_build_refused(self):
        build_script_inputs(self.root)
        runner = FakeRunner(self.root, mutate_source=True)
        with contextlib.redirect_stderr(io.StringIO()):
            self.error("source-changed", p.package_candidate, self.root,
                       p.parser().parse_args(["--allow-dirty"]), runner)
        self.assertFalse((self.root / "DerivedData/Distributions").exists())

    def test_detected_unpinned_swiftterm_is_not_claimed_as_integrated(self):
        dependency_sources(self.root)
        app = fake_app(self.root)
        _, code = p.inspect_bundle(app)
        runner = FakeRunner(extra_symbols="_$s9SwiftTermFixture\n")
        self.error("dependency-pin", p.prepare_dependency_notices, self.root, app, code, runner)

    def test_included_license_bytes_are_exact_and_excluded_have_no_paths(self):
        dependency_sources(self.root)
        app = fake_app(self.root)
        _, code = p.inspect_bundle(app)
        records = p.prepare_dependency_notices(self.root, app, code, FakeRunner())
        for record in records:
            self.assertEqual(bool(record["licensePaths"]), record["included"])
            for license_item in record["licenses"]:
                self.assertEqual(p.sha256(app / license_item["path"]), license_item["sha256"])
        grdb = next(item for item in records if item["identity"] == "grdb.swift")
        self.assertEqual((app / grdb["licensePaths"][0]).read_bytes(),
                         (self.root / "Packages/OpenLXSSHCore/ThirdPartyNotices/GRDB-LICENSE.txt").read_bytes())


class RunnerAndStaticTests(TemporaryCase):
    def test_runner_reaps_timed_out_child(self):
        pid_file = self.root / "child.pid"
        script = "import os,time,pathlib; pathlib.Path(" + repr(str(pid_file)) + ").write_text(str(os.getpid())); time.sleep(30)"
        self.error("command-timeout", p.Runner().run, [sys.executable, "-c", script], timeout=0.5)
        pid = int(pid_file.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_static_no_shell_upload_install_gatekeeper_bypass_or_deep_signing(self):
        tree = ast.parse(SCRIPT.read_text())
        literal_strings = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        for forbidden in ("notarytool", "stapler", "altool", "xattr", "--deep-sign", "/Applications", "set-key-partition-list",
                          "create-keychain", "import", "--global-disable", "--master-disable"):
            self.assertNotIn(forbidden, literal_strings)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    self.assertFalse(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True)
        self.assertNotIn("shutil.rmtree", SCRIPT.read_text())
        self.assertNotIn("os.system", SCRIPT.read_text())

    def test_help_never_builds_signs_or_reads_identities(self):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"UNSIGNED INTERNAL CANDIDATE", result.stdout)
        self.assertIn(b"--allow-timestamp-request", result.stdout)

    def test_developer_id_without_timestamp_permission_fails_before_tools(self):
        runner = FakeRunner(self.root)
        arguments = p.parser().parse_args(["--signing", "developer-id"])
        self.error("timestamp-permission", p.package_candidate, self.root, arguments, runner)
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
