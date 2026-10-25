"""Temporary fake.app builder. Bytes are NOT executable macOS interoperability evidence."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import sys
import zipfile

SCRIPT = Path(__file__).resolve().parents[2] / "Scripts/package-release-candidate.py"
spec = importlib.util.spec_from_file_location("release_packaging_under_test", SCRIPT)
packaging = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = packaging
spec.loader.exec_module(packaging)


def fake_app(parent, helper=True):
    app = parent / "OpenLXSSH.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Resources").mkdir()
    info = {"CFBundleName": "OpenLXSSH", "CFBundleDisplayName": "OpenLXSSH",
            "CFBundleExecutable": "OpenLXSSH", "CFBundleIdentifier": packaging.BUNDLE_ID,
            "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "0.1.0",
            "CFBundleVersion": "1", "LSMinimumSystemVersion": "26.0",
            "LSArchitecturePriority": ["arm64"]}
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    write_macho(app / "Contents/MacOS/OpenLXSSH")
    (app / "Contents/Resources/NOTICE.txt").write_text("First-party fixture notice, not a bundled dependency claim.\n")
    if helper:
        write_macho(app / packaging.HELPER)
    return app


def write_macho(path, filetype=None, entry=True):
    """Independent binary headers; still not runnable or interoperability evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if filetype is None:
        filetype = 6 if path.suffix == ".dylib" or any(parent.suffix == ".framework" for parent in path.parents) else 2
    segment = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0x100000000, 0x1000, 0, 512, 5, 5, 0, 0)
    main = struct.pack("<IIQQ", 0x80000028, 24, 160, 0) if filetype == 2 and entry else b""
    commands = segment + main
    header = struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, filetype, 1 + bool(main), len(commands), 0x200085, 0)
    path.write_bytes((header + commands).ljust(512, b"\x00"))
    path.chmod(0o755)
    return path


def update_info(app, **changes):
    path = app / "Contents/Info.plist"
    info = plistlib.loads(path.read_bytes())
    info.update(changes)
    path.write_bytes(plistlib.dumps(info))


def load_commands(dependencies=(), rpaths=(), minimum="26.0", platform="1", install_name=None):
    blocks = [f"      cmd LC_BUILD_VERSION\n platform {platform}\n    minos {minimum}\n      sdk 26.2\n"]
    for name in dependencies:
        blocks.append(f"      cmd LC_LOAD_DYLIB\n     name {name} (offset 24)\n")
    for name in rpaths:
        blocks.append(f"      cmd LC_RPATH\n     path {name} (offset 12)\n")
    if install_name:
        blocks.append(f"      cmd LC_ID_DYLIB\n     name {install_name} (offset 24)\n")
    return "fixture:\n" + "".join(f"Load command {index}\n{block}" for index, block in enumerate(blocks))


def zip_app(app, destination):
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for parent, dirs, files in os.walk(app, followlinks=False):
            for name in sorted(dirs + files):
                path = Path(parent) / name
                if path.is_symlink():
                    entry = zipfile.ZipInfo(app.name + "/" + path.relative_to(app).as_posix())
                    entry.create_system = 3
                    entry.external_attr = path.lstat().st_mode << 16
                    archive.writestr(entry, os.readlink(path).encode())
                elif path.is_file():
                    archive.write(path, app.name + "/" + path.relative_to(app).as_posix())


class FakeRunner:
    """Only simulates local tool boundaries. Never runs a build/signature/network call."""
    def __init__(self, root=None, missing_helper=False, signed=False, bad_runtime=False,
                 gatekeeper_exit=3, extra_symbols="", mutate_source=False):
        self.root = root
        self.calls = []
        self.signed = signed
        self.bad_runtime = bad_runtime
        self.missing_helper = missing_helper
        self.gatekeeper_exit = gatekeeper_exit
        self.extra_symbols = extra_symbols
        self.mutate_source = mutate_source
        self.certificate = packaging.Identity("A" * 40, "Apple Development: Fixture Only (TEAMTEST)")

    def checked(self, arguments, timeout=60, log_path=None):
        result = self.run(arguments, timeout, log_path)
        packaging.require(result.returncode == 0, "tool-failed", "Fixture local tool failed.")
        return result.output.decode().strip()

    def run(self, arguments, timeout=60, log_path=None):
        args = [str(arg) for arg in arguments]
        self.calls.append(args)
        output, returncode = b"", 0
        if args[:2] == ["/usr/bin/git", "-C"]:
            command = args[3]
            if command == "rev-parse":
                output = ("b" * 40 + "\n").encode()
            elif command == "status":
                changed = self.mutate_source and any(call[0] == "/bin/bash" for call in self.calls)
                output = b" M Application/changed.swift\x00" if changed else b""
            elif command not in {"diff", "ls-files"}:
                raise AssertionError(args)
        elif args[0] == "/bin/bash":
            assert args[2:] == ["Release", "build"]
            destination = self.root / "DerivedData/Release/Build/Products/Release"
            destination.mkdir(parents=True)
            fake_app(destination, helper=not self.missing_helper)
        elif args[:2] == ["/usr/bin/security", "find-identity"]:
            output = (f'  1) {self.certificate.fingerprint} "{self.certificate.name}"\n'
                      '     1 valid identities found\n').encode()
        elif args[0] == "/usr/bin/ditto":
            if "-c" in args:
                zip_app(Path(args[-2]), Path(args[-1]))
            else:
                shutil.copytree(args[-2], args[-1], symlinks=True)
        elif args[:2] == ["/usr/bin/plutil", "-convert"]:
            output = json.dumps({"objects": {"target": {"isa": "PBXNativeTarget", "name": "OpenLXSSH",
                "packageProductDependencies": ["core", "security"]}, "core": {"productName": "OpenLXSSHCore"},
                "security": {"productName": "OpenLXSSHSecurity"}}}).encode()
        elif args[0] == "/usr/bin/xcrun":
            if args[1] == "lipo":
                output = b"arm64\n"
            elif args[1] == "otool":
                output = load_commands(dependencies=("/usr/lib/libSystem.B.dylib",)).encode()
            elif args[1] == "nm":
                output = ("_$s4GRDB12FixtureOnly\n" + self.extra_symbols).encode()
            else:
                output = b"fixture toolchain version (not a real toolchain record)\n"
        elif args[0] == "/usr/bin/codesign":
            if "--sign" in args:
                self.signed = True
            elif "--verify" in args:
                returncode = 0 if self.signed else 1
            elif "--entitlements" in args:
                output = b"Executable=fixture\n"
            elif "--display" in args:
                if self.signed:
                    flags = "0x0(none)" if self.bad_runtime else "0x10000(runtime)"
                    output = (f"CodeDirectory v=20500 size=100 flags={flags} hashes=1+1\n"
                              f"Authority={self.certificate.name}\nTeamIdentifier=TEAMTEST\n").encode()
                else:
                    output = b"CodeDirectory v=20400 size=100 flags=0x2(adhoc)\nSignature=adhoc\nTeamIdentifier=not set\n"
            else:
                raise AssertionError(args)
        elif args[0] == "/usr/sbin/spctl":
            output = b"fixture rejection, not a real Gatekeeper result\n"
            returncode = self.gatekeeper_exit
        elif args[0] in {"/usr/bin/xcodebuild", "/usr/bin/ssh"}:
            output = b"fixture version (NOT REAL BUILD/SSH EVIDENCE)\n"
        else:
            raise AssertionError(f"Unexpected fixture tool call {args}")
        if log_path is not None:
            Path(log_path).write_bytes(output)
            return packaging.CommandResult(returncode)
        return packaging.CommandResult(returncode, output)


def build_script_inputs(root):
    for relative in ("Scripts/build-app.sh", "Scripts/verify-build-plugin.py"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# disposable script fixture; never executed\n")


def dependency_sources(root):
    """Own static metadata only; unrelated concurrent App edits cannot change tests."""
    build_script_inputs(root)
    dependencies = {
        "grdb.swift": ("7.11.1", "1" * 40),
        "swiftterm": ("1.99.1", "2" * 40),
        "swift-argument-parser": ("1.8.2", "3" * 40),
        "swift-png": ("4.5.2", "4" * 40),
        "h": ("1.0.1", "5" * 40),
    }
    pins = {identity: {"identity": identity, "kind": "remoteSourceControl",
                      "location": f"https://example.invalid/unit-only/{identity}",
                      "state": {"version": version, "revision": revision}}
            for identity, (version, revision) in dependencies.items()}
    locks = {
        "OpenLXSSH.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved": [pins["grdb.swift"]],
        "Packages/OpenLXSSHCore/Package.resolved": [pins["grdb.swift"]],
        "Packages/OpenLXSSHTransport/Package.resolved": [pin for identity, pin in pins.items() if identity != "grdb.swift"],
    }
    for relative, content in locks.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"version": 3, "pins": content}))
    notices = {"Core": ["GRDB-LICENSE.txt"], "Transport": ["SwiftTerm-LICENSE", "ArgumentParser-LICENSE",
                "SwiftPNG-LICENSE", "SwiftPNG-NOTICE", "H-LICENSE", "H-NOTICE"]}
    for package, names in notices.items():
        directory = root / f"Packages/OpenLXSSH{package}/ThirdPartyNotices"
        directory.mkdir()
        for name in names:
            (directory / name).write_text("UNIT FIXTURE ONLY — NOT AN UPSTREAM LICENSE: " + name + "\n")
    target = root / "Packages/OpenLXSSHFiles/native-inputs.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({identity: {"version": version, "commit": letter * 40,
                         "sha256": letter * 64, "licenseSHA256": "0" * 64,
                         "url": f"https://example.invalid/unit-only/{identity}.tar.gz"}
                         for identity, version, letter in (("libssh2", "1.11.1", "6"), ("openssl", "3.5.9", "7"))}))
