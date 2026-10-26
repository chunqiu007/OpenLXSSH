"""Hidden-native symbol adapter fixtures; no native build or formal App writes."""
import contextlib
import io
import json
from pathlib import Path

from fixtures import (FakeRunner, NATIVE_FIXTURE_SYMBOLS, dependency_sources, fake_app,
                      native_archive_nm, native_nm, packaging as p)
from test_boundaries import native_provenance
from test_packaging import TemporaryCase


LIBSSH2 = NATIVE_FIXTURE_SYMBOLS["libssh2.a"]
OPENSSL = NATIVE_FIXTURE_SYMBOLS["libcrypto.a"]
ALL_NATIVE = LIBSSH2 + OPENSSL
HIDDEN = "non-external (was a private external)"


class NativeRunner(FakeRunner):
    """Independent simulated nm output, including no native external exports."""
    def __init__(self, root=None, text=None, archives=None, per_path=None):
        super().__init__(root)
        self.text = native_nm(ALL_NATIVE, binding=HIDDEN) if text is None else text
        self.archives = archives or {}
        self.per_path = per_path or {}

    def run(self, arguments, timeout=60, log_path=None):
        args = [str(arg) for arg in arguments]
        if args[:2] == ["/usr/bin/xcrun", "nm"]:
            self.calls.append(args)
            path = Path(args[-1])
            if args[2:-1] == ["-g", "-U", "-m"] and path.suffix == ".a":
                output = self.archives.get(path.name, native_archive_nm(path.name))
            elif args[2:-1] == ["-U", "-m"]:
                output = self.per_path.get(path.name, self.text if path.name == "OpenLXSSH" else "")
            elif args[2:-1] == ["-g", "-U", "-j"]:
                output = "_$s4GRDB12UnitFixture\n" if path.name == "OpenLXSSH" else ""
            else:
                raise AssertionError(args)
            return p.CommandResult(0, output.encode())
        if args[:2] == ["/usr/bin/plutil", "-convert"]:
            self.calls.append(args)
            return p.CommandResult(0, json.dumps({"objects": {
                "target": {"isa": "PBXNativeTarget", "name": "OpenLXSSH",
                           "packageProductDependencies": ["core", "files"]},
                "core": {"productName": "OpenLXSSHCore"},
                "files": {"productName": "OpenLXSSHFiles"}}}).encode())
        return super().run(arguments, timeout, log_path)


class NativeEvidenceTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        dependency_sources(self.root)
        self.app = fake_app(self.root)
        _, self.code = p.inspect_bundle(self.app)

    def prepare(self, runner):
        return p.prepare_dependency_notices(self.root, self.app, self.code, runner)

    def test_parser_accepts_only_explicit_defined_text_with_actual_binding(self):
        for binding in ("external", "private external", "non-external", HIDDEN):
            with self.subTest(binding=binding):
                records = p.native_text_definitions(native_nm((LIBSSH2[0],), binding=binding))
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0], {"symbol": LIBSSH2[0], "address": "0000000100000000",
                                              "section": "__TEXT,__text", "binding": binding})
        archive = p.native_text_definitions(native_archive_nm("libssh2.a"), archive=True)
        self.assertEqual({item["symbol"] for item in archive}, set(LIBSSH2))
        self.assertTrue(all(item["member"] == "unit-native.o" and item["binding"] == "private external"
                            for item in archive))

    def test_parser_rejects_import_absolute_data_unknown_binding_and_substrings(self):
        invalid = [
            "                 (undefined) external _libssh2_session_init_ex (from libssh2)",
            "0000000100000000 (absolute) external _libssh2_session_init_ex",
            native_nm(ALL_NATIVE, section="__DATA,__data"),
            native_nm(ALL_NATIVE, section="__DATA_CONST,__const"),
            native_nm(ALL_NATIVE, binding="weak external"),
            native_nm(ALL_NATIVE, binding="non-external mystery-binding"),
            native_nm(("_wrapper_libssh2_session_init_ex", "_libssh2_session_init_ex_suffix.cold.1")),
            native_nm(("_LIBSSH2_session_init_ex", "_openssl_version")),
            "diagnostic prefix " + native_nm((LIBSSH2[0],)),
            native_nm((LIBSSH2[0],)).rstrip() + " (undefined)",
            "\n".join(ALL_NATIVE),
        ]
        for output in invalid:
            with self.subTest(output=output):
                self.assertEqual(p.native_text_definitions(output), [])

    def test_hidden_native_functions_map_exactly_to_verified_archive_members(self):
        base = native_provenance(self.root)
        runner = NativeRunner()
        records = self.prepare(runner)
        included = {item["identity"] for item in records if item["included"]}
        self.assertEqual(included, {"grdb.swift", "libssh2", "openssl"})
        for record in records:
            if record["identity"] not in {"libssh2", "openssl"}:
                continue
            evidence, = record["symbolEvidence"]
            self.assertEqual(evidence["path"], "Contents/MacOS/OpenLXSSH")
            self.assertEqual(evidence["nmArguments"], ["-U", "-m"])
            self.assertEqual(evidence["matchedSymbolsByBinding"], {HIDDEN: 3})
            self.assertEqual(evidence["matchedSymbolCount"], 3)
            self.assertEqual({item["symbol"] for item in evidence["witnesses"]},
                             set(evidence["requiredSymbols"]))
            self.assertGreaterEqual(len(evidence["requiredSymbols"]), 3)
            self.assertEqual(evidence["codeSHA256BeforeSigning"], p.sha256(self.app / evidence["path"]))
            for witness in evidence["witnesses"]:
                source = witness["archiveDefinition"]
                self.assertEqual(source["symbol"], witness["symbol"])
                self.assertEqual(source["binding"], "private external")
                self.assertEqual(source["member"], "unit-native.o")
                self.assertEqual(source["section"], "__TEXT,__text")
                self.assertEqual(source["sha256"], p.sha256(self.root / source["path"]))
            provenance = record["nativeBuildProvenance"]
            self.assertEqual(provenance["sha256"], p.sha256(base / "manifest.json"))
            for key in ("inputsLock", "buildScript"):
                self.assertEqual(provenance[key]["sha256"], p.sha256(self.root / provenance[key]["path"]))
            self.assertEqual(len(provenance["verifiedInputArchives"]), 3)
            self.assertIn("not bitcode equivalence or a complete binary SBOM", record["evidence"])
            self.assertTrue(record["licensePaths"])
        # A verified archive input is not automatically claimed as contributing code.
        openssl = next(item for item in records if item["identity"] == "openssl")
        self.assertEqual({Path(item["archiveDefinition"]["path"]).name
                          for item in openssl["symbolEvidence"][0]["witnesses"]}, {"libcrypto.a"})
        self.assertFalse(any(call[0] == "/bin/bash" or "--sign" in call or call[0] == "/usr/bin/security"
                             for call in runner.calls))

    def test_external_and_mixed_bindings_are_reported_without_claiming_all_external(self):
        native_provenance(self.root)
        output = (native_nm((LIBSSH2[0],), binding="external") +
                  native_nm(LIBSSH2[1:], binding="non-external") + native_nm(OPENSSL, binding="private external"))
        evidence, _, _, _ = p.native_dependency_evidence(self.root, self.app, self.code, NativeRunner(text=output))
        self.assertEqual(evidence["libssh2"][0]["matchedSymbolsByBinding"], {"external": 1, "non-external": 2})
        self.assertEqual(evidence["openssl"][0]["matchedSymbolsByBinding"], {"private external": 3})
        for identity in evidence:
            self.assertTrue(set(evidence[identity][0]["requiredSymbols"]) <=
                            {item["symbol"] for item in evidence[identity][0]["witnesses"]})

    def test_declared_files_without_native_or_with_stripped_symbols_fails_closed(self):
        for output in ("", "0000000100000000 (__TEXT,__text) external _main\n"):
            runner = NativeRunner(text=output)
            with self.subTest(output=output), self.assertRaises(p.PackagingError) as caught:
                self.prepare(runner)
            self.assertEqual(caught.exception.code, "dependency-evidence")
            self.assertIn("OpenLXSSHFiles", str(caught.exception))
            self.assertIn("libssh2", str(caught.exception))
            self.assertFalse((self.app / "Contents/Resources/ThirdPartyNotices").exists())

    def test_undefined_only_absolute_data_and_plain_names_never_prove_native_code(self):
        native_provenance(self.root)
        cases = ["\n".join(f"                 (undefined) external {symbol}" for symbol in ALL_NATIVE),
                 "\n".join(f"0000000100000000 (absolute) external {symbol}" for symbol in ALL_NATIVE),
                 native_nm(ALL_NATIVE, binding="non-external", section="__DATA,__data"),
                 native_nm(ALL_NATIVE, binding="non-external", section="__DATA_CONST,__const"),
                 "\n".join(ALL_NATIVE)]
        for output in cases:
            with self.subTest(output=output):
                self.error("dependency-evidence", self.prepare, NativeRunner(text=output))
        self.assertFalse((self.app / "Contents/Resources/ThirdPartyNotices").exists())

    def test_unknown_names_and_single_matching_api_cannot_substitute_required_functions(self):
        native_provenance(self.root)
        cases = (native_nm(("_libssh2_unreviewed",) + OPENSSL, binding=HIDDEN),
                 native_nm((LIBSSH2[0],) + OPENSSL, binding=HIDDEN),
                 native_nm(LIBSSH2 + (OPENSSL[0],), binding=HIDDEN))
        for output in cases:
            with self.subTest(output=output):
                self.error("dependency-evidence", self.prepare, NativeRunner(text=output))

    def test_native_function_witnesses_must_coexist_in_one_embedded_code_path(self):
        native_provenance(self.root)
        runner = NativeRunner(per_path={"OpenLXSSH": native_nm(LIBSSH2[:2] + OPENSSL, binding=HIDDEN),
                                        "openlxssh-askpass": native_nm(LIBSSH2[2:], binding=HIDDEN)})
        self.error("dependency-evidence", self.prepare, runner)

    def test_partial_extra_code_path_is_not_silently_omitted_from_provenance(self):
        native_provenance(self.root)
        runner = NativeRunner(per_path={"openlxssh-askpass": native_nm((LIBSSH2[0],), binding=HIDDEN)})
        self.error("dependency-evidence", self.prepare, runner)

    def test_duplicate_defined_api_names_are_ambiguous_not_extra_evidence(self):
        native_provenance(self.root)
        runner = NativeRunner(text=native_nm(ALL_NATIVE + (LIBSSH2[0],), binding=HIDDEN))
        self.error("dependency-evidence", self.prepare, runner)

    def test_correct_names_in_wrong_owned_archive_fail_closed(self):
        native_provenance(self.root)
        archives = {"libssh2.a": native_archive_nm("libcrypto.a"),
                    "libcrypto.a": native_archive_nm("libssh2.a")}
        self.error("dependency-evidence", self.prepare, NativeRunner(archives=archives))

    def test_archive_undefined_data_local_only_and_unknown_formats_are_not_mapping(self):
        native_provenance(self.root)
        for output in ("unit.o:\n" + native_nm(LIBSSH2, section="__DATA,__data"),
                       "unit.o:\n" + native_nm(LIBSSH2, binding="non-external"),
                       "unit.o:\n" + "\n".join(f"                 (undefined) external {symbol}" for symbol in LIBSSH2),
                       "\n".join(LIBSSH2)):
            with self.subTest(output=output):
                self.error("dependency-evidence", self.prepare, NativeRunner(archives={"libssh2.a": output}))

    def test_archive_member_must_be_explicit_and_mapping_unambiguous(self):
        native_provenance(self.root)
        for output in (native_nm(LIBSSH2, binding="private external"),
                       "../escape.o:\n" + native_nm(LIBSSH2, binding="private external"),
                       native_archive_nm("libssh2.a") + "duplicate.o:\n" + native_nm((LIBSSH2[0],))):
            with self.subTest(output=output):
                self.error("dependency-evidence", self.prepare, NativeRunner(archives={"libssh2.a": output}))

    def test_wrong_build_script_hash_fails_before_archive_symbol_collection(self):
        native_provenance(self.root)
        script = self.root / "Packages/OpenLXSSHFiles/Scripts/build-native.py"
        script.write_text("# changed unit script; never executed\n")
        runner = NativeRunner()
        self.error("native-provenance", self.prepare, runner)
        self.assertFalse(any(call[-1].endswith(".a") for call in runner.calls))
        self.assertFalse((self.app / "Contents/Resources/ThirdPartyNotices").exists())

    def test_all_native_archive_hashes_are_checked_before_archive_symbol_collection(self):
        base = native_provenance(self.root)
        # Last archive tamper must fail before nm is called even on earlier archives.
        (base / "install/lib/libcrypto.a").write_bytes(b"tampered UNIT archive")
        runner = NativeRunner()
        self.error("native-provenance", self.prepare, runner)
        self.assertFalse(any(call[-1].endswith(".a") for call in runner.calls))

    def test_native_symbol_collection_detects_archive_changes(self):
        base = native_provenance(self.root)
        class ChangingRunner(NativeRunner):
            def run(inner, arguments, timeout=60, log_path=None):
                result = super().run(arguments, timeout, log_path)
                if str(arguments[-1]).endswith("libcrypto.a"):
                    (base / "install/lib/libssh2.a").write_bytes(b"changed after nm UNIT archive")
                return result
        self.error("native-provenance", self.prepare, ChangingRunner())
        self.assertFalse((self.app / "Contents/Resources/ThirdPartyNotices").exists())

    def test_swift_symbols_require_anchored_names_not_substring_diagnostics(self):
        class SubstringRunner(NativeRunner):
            def run(inner, arguments, timeout=60, log_path=None):
                result = super().run(arguments, timeout, log_path)
                if [str(item) for item in arguments[2:-1]] == ["-g", "-U", "-j"]:
                    return p.CommandResult(0, b"_UnitWrapper_$s4GRDB12NotGRDB\n")
                return result
        self.error("dependency-evidence", self.prepare, SubstringRunner(text=""))


class NativeEvidenceWorkflowTests(TemporaryCase):
    def test_fixture_unsigned_manifest_records_native_proof_and_exact_per_node_licenses(self):
        dependency_sources(self.root)
        native_provenance(self.root)
        runner = NativeRunner(self.root)
        with contextlib.redirect_stdout(io.StringIO()):
            path = p.package_candidate(self.root, p.parser().parse_args([]), runner)
        manifest = p.verify_manifest(path)
        dependencies = {item["identity"]: item for item in manifest["dependencies"]}
        nodes = {item["path"]: item for item in manifest["runtimeCode"]}
        self.assertEqual(set(nodes["Contents/MacOS/OpenLXSSH"]["linkedDependencies"]),
                         {"grdb.swift", "libssh2", "openssl"})
        self.assertEqual(nodes[p.HELPER]["linkedDependencies"], [])
        for identity in ("libssh2", "openssl"):
            record = dependencies[identity]
            self.assertEqual(record["linkedCodePaths"], ["Contents/MacOS/OpenLXSSH"])
            self.assertTrue(record["included"])
            self.assertEqual(record["symbolEvidence"][0]["matchedSymbolsByBinding"], {HIDDEN: 3})
            for notice in record["licenses"]:
                self.assertEqual(notice["sha256"], p.sha256(path.parent / "OpenLXSSH.app" / notice["path"]))
        self.assertEqual(manifest["classification"], "UNSIGNED INTERNAL CANDIDATE")
        self.assertFalse(manifest["codesign"]["signingPerformed"])
        self.assertFalse(manifest["notarized"] or manifest["uploaded"])
        self.assertFalse(any("--sign" in call or call[0] == "/usr/bin/security" for call in runner.calls))
