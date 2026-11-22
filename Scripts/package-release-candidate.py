#!/usr/bin/env python3
"""Local Release candidate preparation, never notarization, upload or installation.

Default: UNSIGNED INTERNAL CANDIDATE (linker ad-hoc signatures may already exist).
Requires Python 3.9+ and the project's existing macOS/Xcode build tools. All signing
is opt-in; a Developer ID timestamp request needs a separate explicit permission.
"""
import argparse
import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = "OpenLXSSH"
BUNDLE_ID = "org.openlxssh.OpenLXSSH"
MIN_OS = (26, 0, 0)
MACH_MAGICS = {bytes.fromhex(value) for value in (
    "feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca",
    "cafebabf", "bfbafeca")}
LOAD_COMMANDS = {"LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB",
                 "LC_LAZY_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB", "LC_LOAD_DYLINKER"}
FORBIDDEN_PARTS = {".git", ".build", ".swiftpm", "xcuserdata", "tests", "test",
                   "fixtures", "fixture", "testresults", "secrets", "credentials"}
FORBIDDEN_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".pkcs12", ".cer", ".crt",
                      ".keychain", ".keychain-db", ".mobileprovision", ".provisionprofile",
                      ".der", ".csr", ".p7b", ".p7c", ".pub", ".certsigningrequest",
                      ".secret", ".secrets", ".credential", ".credentials", ".token",
                      ".xctest", ".xcresult", ".xcodeproj", ".xcworkspace", ".dsym",
                      ".o", ".a", ".swift", ".c", ".h", ".py", ".sh", ".log",
                      ".swiftmodule", ".swiftdoc", ".swiftsourceinfo", ".xcuserstate",
                      ".app", ".xpc", ".appex", ".kext", ".plugin"}
DANGEROUS_ENTITLEMENTS = {
    "com.apple.security.get-task-allow", "get-task-allow",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.disable-executable-page-protection",
}
IDENTITY_PREFIXES = {"development": ("Apple Development:", "Mac Developer:"),
                     "developer-id": ("Developer ID Application:",)}


class PackagingError(Exception):
    """Diagnostics are controlled text, never raw build/signing output."""
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def require(condition, code, message):
    if not condition:
        raise PackagingError(code, message)


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    output: bytes = b""


class Runner:
    """No shell, no stdin answers; bound and reap each command's process group."""
    def run(self, arguments, timeout=60, log_path=None):
        with tempfile.TemporaryFile() as captured:
            target = captured
            if log_path is not None:
                descriptor = os.open(log_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                target = os.fdopen(descriptor, "wb")
            try:
                process = subprocess.Popen([str(arg) for arg in arguments], stdin=subprocess.DEVNULL,
                                           stdout=target, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                try:
                    returncode = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._stop_group(process)
                    raise PackagingError("command-timeout", "Local tool timed out; no authorization was supplied.")
                except BaseException:
                    self._stop_group(process)
                    raise
                if log_path is not None:
                    return CommandResult(returncode)
                captured.seek(0)
                output = captured.read(64 * 1024 * 1024 + 1)
                require(len(output) <= 64 * 1024 * 1024, "tool-output-limit", "Local tool output exceeded its bound.")
                return CommandResult(returncode, output)
            finally:
                if target is not captured:
                    target.close()

    @staticmethod
    def _stop_group(process):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
                # The leader may exit before a child. Kill only its still-owned group.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                return
            except subprocess.TimeoutExpired:
                continue
        process.wait()

    def checked(self, arguments, timeout=60, log_path=None):
        result = self.run(arguments, timeout, log_path)
        require(result.returncode == 0, "tool-failed", "Local tool failed; inspect the referenced local log, if any.")
        return result.output.decode("utf-8", errors="replace").strip()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative_path(value):
    require(isinstance(value, str) and value and "\\" not in value and "\x00" not in value,
            "unsafe-path", "Expected a safe relative artifact path.")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in ("", ".", "..") for part in value.split("/")),
            "unsafe-path", "Absolute paths and parent traversal are forbidden.")
    return Path(*path.parts)


def within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def no_symlink_ancestors(path, root):
    require(path.is_absolute() and root.is_absolute() and ".." not in path.parts and within(path, root),
            "unsafe-path", "Path is outside its assigned local root or contains parent traversal.")
    for item in (root, *reversed(path.parents), path):
        if within(item, root):
            require(not item.is_symlink(), "symlink-parent", "Symlink ancestors are not allowed for candidate inputs/outputs.")


def owned_directory(path, root, exclusive=False):
    no_symlink_ancestors(path, root)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=not exclusive)
    except FileExistsError:
        raise PackagingError("output-exists", "Candidate target already exists; it was not changed. Start a new run.")
    no_symlink_ancestors(path, root)
    require(path.is_dir(), "invalid-directory", "Candidate/log path is not a directory.")
    return path


def preflight_build_paths(root):
    """Check the existing build script's fixed write trees before invoking it.

    This is a fail-closed path preflight, not a sandbox against a concurrent same-UID
    attacker. The caller must still stop unrelated builds/editors before packaging.
    """
    scripts = ("Scripts/build-app.sh", "Scripts/verify-build-plugin.py")
    for relative in scripts:
        path = root / relative
        no_symlink_ancestors(path, root)
        require(path.is_file() and path.stat().st_nlink == 1, "build-script-input",
                "An existing build/plugin-verification script is missing, linked or not regular.")
    write_roots = (root / "DerivedData/Release", root / "DerivedData/SourcePackages")
    fixed_paths = (
        "DerivedData/Release/Build/Products/Release/OpenLXSSH.app/Contents/MacOS/OpenLXSSH",
        "DerivedData/Release/Build/Products/Release/OpenLXSSH.app/Contents/Resources",
        "DerivedData/Release/Build/Intermediates.noindex/BuildToolPluginIntermediates",
        "DerivedData/SourcePackages/checkouts", "DerivedData/SourcePackages/repositories",
        "DerivedData/SourcePackages/artifacts",
        "OpenLXSSH.xcodeproj/project.pbxproj",
        "OpenLXSSH.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved",
        "Packages/OpenLXSSHTransport/Package.swift", "Packages/OpenLXSSHTransport/Package.resolved",
    )
    for relative in fixed_paths:
        no_symlink_ancestors(root / relative, root)
    # Notices are installed into existing App resource paths by build-app.sh.
    notices = root / "Packages/OpenLXSSHTransport/ThirdPartyNotices"
    no_symlink_ancestors(notices, root)
    if notices.is_dir():
        for notice in notices.iterdir():
            no_symlink_ancestors(notice, root)
            no_symlink_ancestors(root / "DerivedData/Release/Build/Products/Release/OpenLXSSH.app/Contents/Resources" / notice.name, root)
    checkouts = (root / "DerivedData/SourcePackages/checkouts",)
    for build_root in write_roots:
        no_symlink_ancestors(build_root, root)
        if not build_root.exists():
            continue
        require(build_root.is_dir(), "build-output-layout", "A fixed build-output root is not a directory.")
        for parent, directories, files in os.walk(build_root, followlinks=False):
            for name in directories + files:
                path = Path(parent) / name
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(path)
                    try:
                        resolved = path.resolve(strict=True)
                    except (OSError, RuntimeError):
                        raise PackagingError("symlink-parent", "Build input/output has a dangling or cyclic symlink.") from None
                    # Upstream clean checkouts contain legitimate relative source
                    # links. They must stay inside their own checkout, never a sibling
                    # checkout, build/plugin output or an external directory.
                    checkout_root = next((base / path.relative_to(base).parts[0] for base in checkouts
                                          if within(path, base) and len(path.relative_to(base).parts) >= 2), None)
                    require(checkout_root is not None and not os.path.isabs(target)
                            and within(resolved, checkout_root), "symlink-parent",
                            "Build write paths/checkouts contain an unsupported or escaping symlink; no build was invoked.")
                    no_symlink_ancestors(checkout_root, root)
                    continue
                require(stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode),
                        "build-output-layout", "Build write tree contains a special file.")
                require(not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink == 1,
                        "build-output-layout", "A build write-tree file is hardlinked outside its owned path.")


def is_macho(path):
    with path.open("rb") as stream:
        return stream.read(4) in MACH_MAGICS


def version_tuple(value):
    require(isinstance(value, str) and re.fullmatch(r"\d+(?:\.\d+){0,2}", value) is not None,
            "invalid-version", "Version is not a numeric macOS version.")
    numbers = tuple(int(part) for part in value.split("."))
    return numbers + (0,) * (3 - len(numbers))


def read_bundle_info(app):
    require(app.name == "OpenLXSSH.app" and not app.is_symlink() and app.is_dir(),
            "bundle-layout", "Expected a real OpenLXSSH.app directory.")
    require((app / "Contents").is_dir() and not (app / "Contents").is_symlink(),
            "bundle-layout", "App Contents must be a real local directory.")
    info_path = app / "Contents/Info.plist"
    require(info_path.is_file() and not info_path.is_symlink(), "bundle-layout", "App Info.plist is missing or a symlink.")
    with info_path.open("rb") as stream:
        info = plistlib.load(stream)
    expected = {"CFBundleName": PRODUCT, "CFBundleDisplayName": PRODUCT,
                "CFBundleExecutable": PRODUCT, "CFBundleIdentifier": BUNDLE_ID,
                "CFBundlePackageType": "APPL"}
    require(all(info.get(key) == value for key, value in expected.items()),
            "product-identity", "Product, display name, executable and Bundle ID must match the shipping OpenLXSSH product.")
    require(version_tuple(info.get("LSMinimumSystemVersion")) == MIN_OS,
            "minimum-os", "App minimum macOS must be exactly 26.0; HostProbe is not a Release candidate.")
    for key in ("CFBundleShortVersionString", "CFBundleVersion"):
        require(isinstance(info.get(key), str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", info[key]) is not None,
                "product-version", "App version/build must be numeric, not an unresolved build setting.")
    require(info.get("LSArchitecturePriority", ["arm64"]) == ["arm64"],
            "unsupported-architecture", "App architecture priority must be arm64 only.")
    return info


def inspect_bundle(app):
    """Scan before copying and again after signing. Do not silently strip bad inputs."""
    info = read_bundle_info(app)
    require({item.name for item in app.iterdir()} == {"Contents"}, "bundle-layout", "Unexpected files at the App root.")
    allowed = {"Info.plist", "PkgInfo", "MacOS", "Frameworks", "Resources", "_CodeSignature"}
    require(all(item.name in allowed for item in (app / "Contents").iterdir()),
            "bundle-layout", "Unsupported Contents layout; add explicit code-path support rather than hiding it with deep signing.")
    require(not any((app / "Contents" / name).is_symlink() for name in allowed),
            "bundle-layout", "Top-level code/resource directories must not be symlinks.")
    require((app / "Contents/MacOS").is_dir() and
            {item.name for item in (app / "Contents/MacOS").iterdir()} == {PRODUCT},
            "bundle-layout", "Contents/MacOS must contain only the shipping executable.")
    root = app.resolve()
    code = []
    for parent, dirs, files in os.walk(app, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(parent) / name
            rel = path.relative_to(app)
            lower = name.lower()
            require(lower not in FORBIDDEN_PARTS and path.suffix.lower() not in FORBIDDEN_SUFFIXES
                    and "fixture" not in lower
                    and re.search(r"(?:^|[-_.])(?:tests?|testdata|secrets?|passwords?|passphrases?|credentials?|tokens?|certificates?)(?:[-_.]|$)", lower) is None
                    and not lower.startswith((".env", "id_rsa", "id_ed25519", "id_ecdsa"))
                    and lower not in {".ds_store", ".ssh"},
                    "forbidden-content", "App contains development/test/signing/secret material; fix the source bundle.")
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(path)
                try:
                    resolved = path.resolve(strict=True)
                except (OSError, RuntimeError):
                    raise PackagingError("invalid-symlink", "App contains a dangling or cyclic symlink.") from None
                require(not os.path.isabs(target) and within(resolved, root),
                        "escaping-symlink", "App symlink escapes the bundle or has an absolute target.")
                continue
            require(stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode),
                    "special-file", "App contains a socket/device/FIFO or other unsupported file.")
            require(not metadata.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWOTH),
                    "unsafe-permissions", "App contains set-id or world-writable files/directories.")
            if not stat.S_ISREG(metadata.st_mode):
                continue
            require(metadata.st_nlink == 1, "hardlinked-file", "App regular files must not be hardlinks to external material.")
            require(rel.parts[:2] != ("Contents", "Frameworks") or path.suffix != ".plist"
                    or name == "Info.plist", "bundle-layout", "Unexpected framework configuration file.")
            if is_macho(path):
                known = rel.as_posix() == "Contents/MacOS/OpenLXSSH" or rel.parts[:2] == ("Contents", "Frameworks")
                require(known, "unknown-code-path", "Executable code outside MacOS/Frameworks is not supported.")
                code.append(path.resolve())
            else:
                require(not metadata.st_mode & 0o111, "unexpected-executable", "App contains a non-Mach-O executable or script.")
                with path.open("rb") as stream:
                    previous = b""
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        sample = previous + block
                        require(re.search(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|openssh-key-v1\x00", sample) is None,
                                "secret-content", "App resource contains private-key material.")
                        previous = sample[-128:]
    required = {app / "Contents/MacOS/OpenLXSSH"}
    require(all(item.resolve() in code and item.stat().st_mode & 0o111 for item in required),
            "bundle-layout", "The App binary must be an executable Mach-O file.")
    return info, sorted(set(code))


@dataclasses.dataclass(frozen=True)
class MachHeader:
    filetype: int
    entry_point: int


def inspect_macho_header(path, expected_filetype):
    """Read real mach_header_64/load-command bytes, independently of tool output.

    V1 accepts thin little-endian arm64 only. Executable entrypoints must use a
    single modern LC_MAIN inside a file-backed executable segment, not a dylib,
    object, bundle, legacy thread entry or an arbitrary executable permission bit.
    """
    size = path.stat().st_size
    with path.open("rb") as stream:
        raw = stream.read(32)
        require(len(raw) == 32, "macho-header", "Mach-O header is truncated.")
        magic, cpu, subtype, filetype, count, command_size, _, reserved = struct.unpack("<8I", raw)
        require(magic == 0xfeedfacf and cpu == 0x100000c and subtype == 0 and reserved == 0,
                "macho-header", "Expected a thin little-endian arm64 Mach-O header, not a fat/other-architecture image.")
        require(filetype == expected_filetype and filetype in {2, 6}, "macho-filetype",
                "App/helper must be MH_EXECUTE; a dependency must be MH_DYLIB. Objects/bundles cannot substitute executable code.")
        require(0 < count <= 65536 and count * 8 <= command_size <= min(size - 32, 16 * 1024 * 1024),
                "macho-header", "Mach-O load-command count/size is invalid or exceeds its bound.")
        data = stream.read(command_size)
    require(len(data) == command_size, "macho-header", "Mach-O load commands are truncated.")
    offset, entries, segments, legacy = 0, [], [], False
    for _ in range(count):
        require(offset + 8 <= len(data), "macho-entrypoint", "Mach-O command table is truncated.")
        command, length = struct.unpack_from("<II", data, offset)
        require(length >= 8 and length % 8 == 0 and offset + length <= len(data),
                "macho-entrypoint", "Mach-O command length/alignment is invalid.")
        if command == 0x80000028:  # LC_MAIN / entry_point_command
            require(length == 24, "macho-entrypoint", "LC_MAIN has an invalid size.")
            entries.append(struct.unpack_from("<Q", data, offset + 8)[0])
        elif command == 0x19:  # LC_SEGMENT_64
            require(length >= 72, "macho-entrypoint", "Mach-O segment metadata is truncated.")
            fields = struct.unpack_from("<II16sQQQQiiII", data, offset)
            _, _, _, _, vm_size, file_offset, file_size, maximum, initial, sections, _ = fields
            require(length == 72 + sections * 80 and file_offset <= size and file_size <= size - file_offset
                    and file_size <= vm_size and not initial & ~maximum,
                    "macho-entrypoint", "Mach-O segment ranges/protection metadata are invalid.")
            if file_size and initial & 4:  # VM_PROT_EXECUTE, backed by real file bytes.
                segments.append((file_offset, file_offset + file_size))
        elif command in {4, 5}:  # LC_THREAD / LC_UNIXTHREAD
            legacy = True
        offset += length
    require(offset == len(data), "macho-entrypoint", "Mach-O command table size does not match the header.")
    if filetype == 2:
        require(not legacy and len(entries) == 1 and entries[0] >= 32 + command_size
                and any(start <= entries[0] < end for start, end in segments),
                "macho-entrypoint", "Executable requires one LC_MAIN entry inside its file-backed executable segment.")
    else:
        require(not entries and not legacy, "macho-entrypoint", "A dylib must not contain an executable entrypoint.")
    return MachHeader(filetype, entries[0] if entries else None)


@dataclasses.dataclass(frozen=True)
class MachInfo:
    path: Path
    dependencies: tuple
    rpaths: tuple
    minimum_os: str
    sdk: str
    filetype: str
    entry_point: int


def parse_macho(path, architectures, load_commands):
    require(architectures.split() == ["arm64"], "unsupported-architecture", "Every embedded Mach-O must contain arm64 only.")
    dependencies, rpaths, versions = [], [], []
    for block in re.split(r"(?m)^Load command \d+\s*$", load_commands)[1:]:
        command = re.search(r"(?m)^\s*cmd (LC_\w+)\s*$", block)
        if not command:
            continue
        kind = command.group(1)
        if kind in LOAD_COMMANDS | {"LC_ID_DYLIB"}:
            name = re.search(r"(?m)^\s*name (.+?) \(offset \d+\)\s*$", block)
            require(name is not None, "macho-parse", "Cannot parse a Mach-O dependency/install name.")
            value = name.group(1)
            if kind == "LC_ID_DYLIB":
                require(value.startswith(("@rpath/", "@loader_path/")) or system_path(value),
                        "external-dependency", "Embedded library has a non-relocatable install name.")
                require(".." not in PurePosixPath(value).parts, "external-dependency", "Library install name contains parent traversal.")
            else:
                dependencies.append(value)
        elif kind == "LC_RPATH":
            match = re.search(r"(?m)^\s*path (.+?) \(offset \d+\)\s*$", block)
            require(match is not None, "macho-parse", "Cannot parse a Mach-O runpath.")
            rpaths.append(match.group(1))
        elif kind == "LC_BUILD_VERSION":
            platform = re.search(r"(?m)^\s*platform (\S+)\s*$", block)
            minimum = re.search(r"(?m)^\s*minos (\S+)\s*$", block)
            sdk = re.search(r"(?m)^\s*sdk (\S+)\s*$", block)
            require(platform is not None and platform.group(1).lower() in {"1", "macos"} and minimum and sdk,
                    "unsupported-platform", "Embedded code is not a macOS Mach-O with build-version metadata.")
            versions.append((minimum.group(1), sdk.group(1)))
        elif kind.startswith("LC_VERSION_MIN_"):
            raise PackagingError("minimum-os", "Legacy/non-macOS deployment metadata is not supported for this macOS 26 product.")
    require(len(versions) == 1 and version_tuple(versions[0][0]) == MIN_OS,
            "minimum-os", "Every embedded Mach-O must have minimum macOS 26.0.")
    entry = path.name == PRODUCT and path.parent.name == "MacOS"
    header = inspect_macho_header(path, 2 if entry else 6)
    return MachInfo(path.resolve(), tuple(dependencies), tuple(rpaths), *versions[0],
                    "MH_EXECUTE" if header.filetype == 2 else "MH_DYLIB", header.entry_point)


def system_path(value):
    return (value.startswith(("/System/Library/", "/usr/lib/"))
            and ".." not in PurePosixPath(value).parts and "\\" not in value)


def expanded_path(value, loader, executable, app):
    for token, base in (("@loader_path", loader.parent), ("@executable_path", executable.parent)):
        if value == token or value.startswith(token + "/"):
            tail = value[len(token) + 1:] if value != token else "."
            require(tail and "\\" not in tail and "\x00" not in tail and not tail.startswith("/"),
                    "external-dependency", "Invalid relative runtime path.")
            candidate = (base / tail).resolve()
            require(within(candidate, app.resolve()), "external-dependency", "Runtime path escapes the App (including via symlink).")
            return candidate
    raise PackagingError("external-dependency", "Runtime dependency/runpath is not relocatable inside the App; Homebrew/temp/checkout paths are forbidden.")


def verify_dependency_graph(app, infos):
    """Resolve each executable's actual loader/runpath closure, including inherited rpaths."""
    app = app.resolve()
    mapping = {item.path: item for item in infos}
    roots = ((app / "Contents/MacOS/OpenLXSSH").resolve(),)
    visited, reached, edges = set(), set(), set()

    def visit(path, executable, inherited):
        require(path in mapping, "unvalidated-code", "Runtime target is missing or not a validated embedded Mach-O.")
        item = mapping[path]
        require(item.filetype == ("MH_EXECUTE" if path in roots else "MH_DYLIB"),
                "macho-filetype", "Only the App/helper are executable entries; embedded dependency nodes must be dylibs.")
        local = tuple(expanded_path(value, path, executable, app) for value in item.rpaths)
        runpaths = tuple(dict.fromkeys(local + inherited))
        state = (path, executable, runpaths)
        if state in visited:
            return
        visited.add(state)
        require(len(visited) <= 4096, "dependency-limit", "Runtime dependency graph exceeds its validation bound.")
        reached.add(path)
        for dependency in item.dependencies:
            if system_path(dependency):
                continue
            if dependency.startswith("@rpath/"):
                tail = relative_path(dependency[len("@rpath/"):])
                candidates = [(base / tail).resolve() for base in runpaths]
                require(all(within(candidate, app) for candidate in candidates), "external-dependency", "Runpath target escapes the App.")
                target = next((candidate for candidate in candidates if candidate.is_file()), None)
                require(target is not None, "unresolved-rpath", "A non-system @rpath dependency cannot be resolved inside the App.")
            else:
                target = expanded_path(dependency, path, executable, app)
                require(target.is_file(), "missing-dependency", "A relative runtime dependency is missing from the App.")
            require(target not in roots, "macho-filetype", "An executable entrypoint cannot be loaded as a dylib dependency.")
            edges.add((str(path.relative_to(app)), str(target.relative_to(app))))
            visit(target, executable, runpaths)

    for root in roots:
        visit(root, root, ())
    require(reached == set(mapping), "unused-code", "App contains embedded code not needed by the App/helper dependency closure.")
    return [{"loader": loader, "target": target} for loader, target in sorted(edges)]


def inspect_macho(app, code, runner):
    infos = []
    for path in code:
        architectures = runner.checked(["/usr/bin/xcrun", "lipo", "-archs", path])
        commands = runner.checked(["/usr/bin/xcrun", "otool", "-l", path])
        infos.append(parse_macho(path, architectures, commands))
    return infos, verify_dependency_graph(app, infos)


def source_state(root, runner, allow_dirty):
    git = ["/usr/bin/git", "-C", root]
    commit = runner.checked(git + ["rev-parse", "HEAD"])
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "source-commit", "Source must have a full Git commit ID.")
    status_bytes = runner.run(git + ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    require(status_bytes.returncode == 0, "git-status", "Cannot inspect Git working-tree state.")
    dirty = bool(status_bytes.output)
    require(not dirty or allow_dirty, "dirty-source", "Working tree is dirty. Commit through the normal review flow, or explicitly select --allow-dirty for an internal candidate.")
    diff = runner.run(git + ["diff", "--binary", "HEAD", "--"])
    require(diff.returncode == 0, "git-diff", "Cannot fingerprint tracked source changes.")
    untracked = runner.run(git + ["ls-files", "--others", "--exclude-standard", "-z"])
    require(untracked.returncode == 0, "git-status", "Cannot inspect untracked build inputs.")
    new_sources = []
    # Hash only recognized build inputs, never arbitrary untracked credentials/logs.
    for raw in untracked.output.split(b"\x00"):
        if not raw:
            continue
        rel = relative_path(os.fsdecode(raw))
        if rel.parts[0] not in {"Application", "Packages", "OpenLXSSH.xcodeproj", "Scripts"}:
            continue
        if rel.suffix not in {".swift", ".c", ".h", ".plist", ".pbxproj", ".xcscheme", ".resolved", ".json", ".sh", ".py", ".txt"} and "LICENSE" not in rel.name.upper() and "NOTICE" not in rel.name.upper():
            continue
        path = root / rel
        no_symlink_ancestors(path, root)
        require(path.is_file(), "source-input", "An untracked build input is not a regular file.")
        new_sources.append((rel.as_posix(), sha256(path)))
    fingerprint = hashlib.sha256(status_bytes.output + b"\x00" + diff.output + b"\x00" +
                                 json.dumps(sorted(new_sources)).encode()).hexdigest()
    return {"commit": commit, "dirty": dirty, "dirtyExplicitFlag": bool(allow_dirty),
            "worktreeFingerprintSHA256": fingerprint}


@dataclasses.dataclass(frozen=True)
class Identity:
    fingerprint: str
    name: str


def parse_identities(output):
    identities = {}
    for match in re.finditer(r'(?m)^\s*\d+\)\s+([A-Fa-f0-9]{40})\s+"([^"\r\n]+)"\s*$', output):
        identity = Identity(match.group(1).upper(), match.group(2))
        identities[identity.fingerprint] = identity
    return list(identities.values())


def select_identity(identities, mode, selector=None):
    require(mode in IDENTITY_PREFIXES, "signing-mode", "Unsigned candidates must not select an identity.")
    matches = [item for item in identities if item.name.startswith(IDENTITY_PREFIXES[mode])]
    if selector:
        matches = [item for item in matches if item.fingerprint == selector.upper() or item.name == selector]
    require(len(matches) == 1, "signing-identity", "Exactly one existing identity of the selected type is required. Use an exact fingerprint/name if ambiguous; no certificate was created.")
    return matches[0]


def validate_signing_options(mode, identity, allow_timestamp):
    require(mode != "unsigned" or not identity, "signing-options", "--identity requires explicit development or developer-id signing.")
    require(mode == "developer-id" or not allow_timestamp, "signing-options", "Timestamp permission is only valid with explicit developer-id signing.")
    require(mode != "developer-id" or allow_timestamp, "timestamp-permission", "Developer ID signing sends an Apple timestamp request. Explicit --allow-timestamp-request is required; nothing has been signed.")


def signing_targets(app, code):
    targets = set(code)
    for binary in code:
        for parent in binary.parents:
            if parent == app:
                break
            if parent.suffix == ".framework":
                targets.add(parent)
    # All leaf binaries/nested frameworks precede their enclosing framework/App.
    return sorted(targets, key=lambda path: (-len(path.parts), str(path))) + [app]


def signature_description(output):
    runtime = re.search(r"(?m)^CodeDirectory .*flags=0x[0-9a-fA-F]+\([^\n)]*\bruntime\b", output) is not None
    team = re.search(r"(?m)^TeamIdentifier=(\S+)\s*$", output)
    authorities = re.findall(r"(?m)^Authority=(.+)$", output)
    return {"runtime": runtime, "team": team.group(1) if team else None,
            "authorities": authorities, "timestamp": re.search(r"(?m)^Timestamp=.+$", output) is not None,
            "adhoc": "Signature=adhoc" in output}


def check_entitlements(output):
    start = output.find(b"<?xml")
    if start < 0:
        start = output.find(b"<plist")
    if start < 0:
        # codesign emits an Executable= diagnostic even for an empty entitlement blob.
        lines = [line for line in output.splitlines() if not line.startswith(b"Executable=")]
        require(not b"\n".join(lines).strip(), "entitlements-parse", "Unable to inspect signed code entitlements.")
        return
    end = output.find(b"</plist>", start)
    require(end >= 0, "entitlements-parse", "Signed code entitlements are incomplete.")
    entitlements = plistlib.loads(output[start:end + len(b"</plist>")])
    require(isinstance(entitlements, dict), "entitlements-parse", "Signed code entitlements are not a dictionary.")
    require(not any(entitlements.get(key) for key in DANGEROUS_ENTITLEMENTS),
            "runtime-policy", "Signed code has development/debug or Hardened Runtime bypass entitlements.")


def apply_and_verify_signatures(app, code, runner, mode, identity=None, allow_timestamp=False):
    validate_signing_options(mode, identity.fingerprint if identity else None, allow_timestamp)
    targets = signing_targets(app, code)
    if mode != "unsigned":
        require(identity is not None and identity.name.startswith(IDENTITY_PREFIXES[mode])
                and re.fullmatch(r"[A-F0-9]{40}", identity.fingerprint) is not None,
                "signing-identity", "No existing signing identity of the explicitly selected type was selected.")
        for target in targets:
            args = ["/usr/bin/codesign", "--force", "--sign", identity.fingerprint, "--options", "runtime",
                    "--timestamp" if mode == "developer-id" else "--timestamp=none"]
            if target == app:
                args += ["--identifier", BUNDLE_ID]
            runner.checked(args + [target], timeout=120)
    strict = runner.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app], timeout=120)
    if mode != "unsigned":
        require(strict.returncode == 0, "signature-verification", "Signed App failed strict/deep verification.")
    teams, all_runtime, target_checks = set(), True, []
    for target in targets:
        verification = runner.run(["/usr/bin/codesign", "--verify", "--strict", target], timeout=120)
        target_checks.append({"path": "." if target == app else target.relative_to(app).as_posix(),
                              "strictExitCode": verification.returncode})
        if mode != "unsigned":
            require(verification.returncode == 0, "signature-verification", "An embedded code target failed strict verification.")
        result = runner.run(["/usr/bin/codesign", "--display", "--verbose=4", target])
        description = signature_description(result.output.decode("utf-8", errors="replace"))
        all_runtime = all_runtime and result.returncode == 0 and description["runtime"]
        if mode == "unsigned":
            entitlements = runner.run(["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", target])
            if entitlements.returncode == 0:
                check_entitlements(entitlements.output)
            require(result.returncode != 0 or description["adhoc"], "unexpected-signature", "Unsigned build unexpectedly contains an identity signature. Rebuild through the unsigned project build path.")
            continue
        require(result.returncode == 0 and description["runtime"] and description["team"] not in {None, "not set"},
                "runtime-policy", "Every signed code target must have Hardened Runtime and a team identity.")
        require(description["authorities"] and description["authorities"][0] == identity.name,
                "signature-identity", "A signed code target does not have the selected certificate identity.")
        require(description["timestamp"] == (mode == "developer-id"), "timestamp-policy", "Code timestamp does not match the explicitly selected signing policy.")
        teams.add(description["team"])
        entitlements = runner.run(["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", target])
        require(entitlements.returncode == 0, "entitlements-parse", "Cannot inspect signed code entitlements.")
        check_entitlements(entitlements.output)
        require(verification.returncode == 0, "signature-verification", "An embedded code target failed strict verification.")
    require(mode == "unsigned" or len(teams) == 1, "signature-team", "All signed code must use one consistent team identity.")
    return {"mode": mode, "signingPerformed": mode != "unsigned",
            "verified": strict.returncode == 0 and all(item["strictExitCode"] == 0 for item in target_checks),
            "strictDeepExitCode": strict.returncode, "targets": target_checks, "hardenedRuntimeVerified": all_runtime,
            "runtimePolicy": "required-and-verified" if mode != "unsigned" else "not-required-for-unsigned-internal-candidate",
            "timestampRequestExplicitlyAllowed": allow_timestamp, "notarized": False, "uploaded": False}


def json_file(path):
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def pins_from(path):
    pins = json_file(path).get("pins", [])
    result = {}
    for pin in pins:
        identity = pin.get("identity")
        revision = pin.get("state", {}).get("revision", "")
        require(identity and re.fullmatch(r"[a-f0-9]{40}", revision), "dependency-pin", "A resolved dependency lacks an exact revision.")
        require(identity not in result, "dependency-pin", "Duplicate dependency identity in lock file.")
        result[identity] = pin
    return result


def integrated_products(root, runner):
    project = json.loads(runner.checked(["/usr/bin/plutil", "-convert", "json", "-o", "-", root / "OpenLXSSH.xcodeproj/project.pbxproj"]))
    objects = project["objects"]
    targets = [item for item in objects.values() if item.get("isa") == "PBXNativeTarget" and item.get("name") == PRODUCT]
    require(len(targets) == 1, "app-target", "Cannot identify the unique formal OpenLXSSH target.")
    return {objects[key]["productName"] for key in targets[0].get("packageProductDependencies", [])}


def safe_source(root, relative):
    path = root / relative_path(relative)
    no_symlink_ancestors(path, root)
    require(path.is_file() and path.stat().st_nlink == 1, "license-input", "A required dependency/license input is missing, linked or not regular.")
    return path


def copy_notice(source, app, relative):
    destination = app / relative_path(relative)
    no_symlink_ancestors(destination, app)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        require(destination.is_file() and sha256(destination) == sha256(source), "license-conflict", "Existing bundled notice differs from the verified license input.")
    else:
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(source.read_bytes())
    return {"path": relative, "sha256": sha256(destination)}


def runtime_code_sources(app, code):
    """V1 statically links its reviewed dependencies; no runtime dylib is approved."""
    owners = {
        "Contents/MacOS/OpenLXSSH": {"owner": "OpenLXSSH", "sourcePath": "Application/OpenLXSSH",
                                    "buildProduct": "OpenLXSSH"},
    }
    root = app.resolve()
    sources = {}
    for binary in code:
        require(within(binary.resolve(), root), "unreviewed-runtime-code", "Runtime code is outside the reviewed App.")
        relative = binary.resolve().relative_to(root).as_posix()
        require(relative in owners, "unreviewed-runtime-code",
                "V1 has no approved embedded framework/dylib: each new runtime node needs explicit source and license review; a valid dependency closure is not provenance.")
        require(relative not in sources, "unreviewed-runtime-code", "Duplicate runtime code provenance path.")
        sources[relative] = {"kind": "first-party-source", **owners[relative]}
    require(set(sources) == set(owners), "unreviewed-runtime-code", "App/helper runtime source ownership is incomplete.")
    return sources


NATIVE_SYMBOL_PATTERNS = {"libssh2": r"_libssh2_[A-Za-z0-9_]+",
                          "openssl": r"_(?:OpenSSL_version|OPENSSL_init_crypto|EVP_[A-Za-z0-9_]+)"}
NATIVE_REQUIRED_SYMBOLS = {
    "libssh2": {"_libssh2_session_init_ex", "_libssh2_session_handshake", "_libssh2_sftp_init"},
    "openssl": {"_OPENSSL_init_crypto", "_OpenSSL_version", "_EVP_CIPHER_fetch"},
}


def native_text_definitions(output, *, archive=False):
    """Accept only nm -U -m's explicit defined native functions, never imports/data.

    Hidden archive APIs can become non-external in the final Mach-O. A local name
    alone is not provenance: the caller must match it to a unique defined function
    in a hash-verified archive. Unknown output/bindings are not evidence.
    """
    definitions, member = [], None
    for line in output.splitlines():
        if archive and line.endswith(":"):
            header = re.fullmatch(r"([A-Za-z0-9_.+-]+\.o):", line)
            member = header.group(1) if header else None
            continue
        match = re.fullmatch(
            r"([0-9a-fA-F]{16}) \(([^(),\s]+),([^(),\s]+)\) "
            r"(external|private external|non-external(?: \(was a private external\))?) (_[A-Za-z0-9_]+)", line)
        if not match:
            continue
        address, segment, section, binding, symbol = match.groups()
        if (segment, section) != ("__TEXT", "__text") or not any(
                re.fullmatch(pattern, symbol) for pattern in NATIVE_SYMBOL_PATTERNS.values()):
            continue
        if archive and binding not in {"external", "private external"}:
            continue
        require(not archive or member is not None, "dependency-evidence",
                "Native archive symbol output lacks a reviewed object-member mapping.")
        definitions.append({"symbol": symbol, "address": address.lower(), "section": "__TEXT,__text",
                            "binding": binding, **({"member": member} if archive else {})})
    return definitions


def native_dependency_evidence(root, app, code, runner):
    """Read-only adapter for exact defined-text symbols and pinned native inputs."""
    candidates = {binary.relative_to(app).as_posix(): native_text_definitions(
        runner.checked(["/usr/bin/xcrun", "nm", "-U", "-m", binary])) for binary in code}
    evidence = {identity: [] for identity in NATIVE_SYMBOL_PATTERNS}
    present = {identity: any(re.fullmatch(pattern, entry["symbol"]) for entries in candidates.values() for entry in entries)
               for identity, pattern in NATIVE_SYMBOL_PATTERNS.items()}
    require(present["libssh2"] == present["openssl"], "dependency-evidence",
            "libssh2 and its selected OpenSSL backend must both have defined native functions.")
    for identity, required in NATIVE_REQUIRED_SYMBOLS.items():
        pattern = NATIVE_SYMBOL_PATTERNS[identity]
        require(all(not any(re.fullmatch(pattern, entry["symbol"]) for entry in entries)
                    or required <= {entry["symbol"] for entry in entries} for entries in candidates.values()),
                "dependency-evidence", f"Native {identity} lacks multiple required defined API functions in a code path.")
    lock_relative = "Packages/OpenLXSSHFiles/native-inputs.json"
    lock_path = safe_source(root, lock_relative)
    lock_hash = sha256(lock_path)
    native_lock = json_file(lock_path)
    if not any(candidates.values()):
        return evidence, native_lock, None, None
    native_root = root / "Packages/OpenLXSSHFiles/.build/native"
    no_symlink_ancestors(native_root, root)
    manifest_path = safe_source(native_root, "manifest.json")
    manifest_hash = sha256(manifest_path)
    native_manifest = json_file(manifest_path)
    script_relative = "Packages/OpenLXSSHFiles/Scripts/build-native.py"
    script_path = safe_source(root, script_relative)
    script_hash = sha256(script_path)
    require(native_manifest["inputs"]["lockSHA256"] == lock_hash
            and native_manifest["inputs"]["scriptSHA256"] == script_hash
            and native_manifest["dependencies"] == native_lock, "native-provenance",
            "Native build provenance does not match reviewed native-inputs.json/build script.")
    archives, definitions = [], {identity: {} for identity in evidence}
    archive_owners = (("libssh2.a", "libssh2"), ("libssl.a", "openssl"), ("libcrypto.a", "openssl"))
    for library, _ in archive_owners:
        source = safe_source(native_root, "install/lib/" + library)
        digest = sha256(source)
        require(digest == native_manifest["outputs"].get("install/lib/" + library),
                "native-provenance", "A native archive differs from its recorded build output.")
        archives.append({"path": source.relative_to(root).as_posix(), "sha256": digest})
    for archive, (_, identity) in zip(archives, archive_owners):
        output = runner.checked(["/usr/bin/xcrun", "nm", "-g", "-U", "-m", root / archive["path"]])
        for definition in native_text_definitions(output, archive=True):
            if re.fullmatch(NATIVE_SYMBOL_PATTERNS[identity], definition["symbol"]):
                definitions[identity].setdefault(definition["symbol"], []).append({**archive, **definition})
    provenance = {"path": manifest_path.relative_to(root).as_posix(), "sha256": manifest_hash,
                  "inputsLock": {"path": lock_relative, "sha256": lock_hash},
                  "buildScript": {"path": script_relative, "sha256": script_hash},
                  "verifiedInputArchives": archives}  # Verified inputs, not a claim that every archive contributed code.
    for identity, pattern in NATIVE_SYMBOL_PATTERNS.items():
        for path, entries in candidates.items():
            occurrences = {}
            for entry in entries:
                occurrences[entry["symbol"]] = occurrences.get(entry["symbol"], 0) + 1
            matched = [(entry, definitions[identity].get(entry["symbol"], [])) for entry in entries
                       if re.fullmatch(pattern, entry["symbol"]) and occurrences[entry["symbol"]] == 1]
            matched = [(entry, sources[0]) for entry, sources in matched if len(sources) == 1]
            require(not any(re.fullmatch(pattern, entry["symbol"]) for entry in entries)
                    or NATIVE_REQUIRED_SYMBOLS[identity] <= {entry["symbol"] for entry, _ in matched},
                    "dependency-evidence", f"Native {identity} code path lacks the required unique archive API mappings.")
            if not matched:
                continue
            bindings = {binding: sum(entry["binding"] == binding for entry, _ in matched)
                        for binding in sorted({entry["binding"] for entry, _ in matched})}
            witness_symbols = NATIVE_REQUIRED_SYMBOLS[identity] | {
                min(entry["symbol"] for entry, _ in matched if entry["binding"] == binding) for binding in bindings}
            witnesses = [{**entry, "archiveDefinition": source} for entry, source in matched
                         if entry["symbol"] in witness_symbols]
            evidence[identity].append({"path": path, "adapter": "nm-defined-text-exact-archive-match-v1",
                                       "nmArguments": ["-U", "-m"], "archiveNMArguments": ["-g", "-U", "-m"],
                                       "codeSHA256BeforeSigning": sha256(app / path),
                                       "requiredSymbols": sorted(NATIVE_REQUIRED_SYMBOLS[identity]),
                                       "matchedSymbolCount": len(matched), "matchedSymbolsByBinding": bindings,
                                       "witnesses": sorted(witnesses, key=lambda item: (item["symbol"], item["address"]))})
        require(not present[identity] or evidence[identity], "dependency-evidence",
                f"Native {identity} definitions lack the required API witnesses in the verified archives.")
    require(sha256(lock_path) == lock_hash and sha256(script_path) == script_hash
            and sha256(manifest_path) == manifest_hash
            and all(sha256(root / archive["path"]) == archive["sha256"] for archive in archives),
            "native-provenance", "Native provenance changed while collecting defined-symbol evidence.")
    return evidence, native_lock, native_manifest, provenance


def prepare_dependency_notices(root, app, code, runner):
    runtime_code_sources(app, code)
    products = integrated_products(root, runner)
    known_products = {"OpenLXSSHCore", "OpenLXSSHSecurity", "OpenLXSSHTrust", "OpenLXSSHTransport", "OpenLXSSHFiles", "SwiftTerm", "GRDB"}
    require(products <= known_products, "unknown-dependency", "Formal App links an unreviewed package product.")
    symbols_by_path = {binary.relative_to(app).as_posix(): runner.checked(
        ["/usr/bin/xcrun", "nm", "-g", "-U", "-j", binary]).splitlines() for binary in code}
    symbol_patterns = {"grdb.swift": r"_\$s4GRDB\S+", "swiftterm": r"_\$s9SwiftTerm\S+",
                       "swift-argument-parser": r"_\$s14ArgumentParser\S+", "swift-png": r"_\$s3PNG\S+", "h": r"_\$s1H\S+"}
    linked_paths = {identity: sorted(path for path, symbols in symbols_by_path.items()
                                   if any(re.fullmatch(pattern, symbol) for symbol in symbols))
                    for identity, pattern in symbol_patterns.items()}
    native_evidence, native_lock, native_manifest, native_provenance = native_dependency_evidence(root, app, code, runner)
    linked_paths.update({identity: sorted(item["path"] for item in evidence) for identity, evidence in native_evidence.items()})
    detected = {identity: bool(paths) for identity, paths in linked_paths.items()}
    expectations = {"OpenLXSSHCore": ("grdb.swift",), "OpenLXSSHTransport": ("swiftterm",),
                    "OpenLXSSHFiles": ("libssh2", "openssl")}
    for product, dependencies in expectations.items():
        for identity in dependencies:
            require(product not in products or detected[identity], "dependency-evidence",
                    f"Integrated product {product} lacks defined-symbol dependency evidence for {identity}; changed/stripped builds need an explicitly reviewed evidence adapter.")
    require(detected["grdb.swift"], "dependency-evidence", "Formal App does not contain verifiable GRDB code.")
    require(detected["libssh2"] == detected["openssl"], "dependency-evidence", "libssh2 and its selected OpenSSL backend must be integrated together.")
    lock_path = "OpenLXSSH.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"
    app_pins = pins_from(safe_source(root, lock_path))
    local_specs = {
        "grdb.swift": ("GRDB.swift", "Packages/OpenLXSSHCore/Package.resolved", ["Packages/OpenLXSSHCore/ThirdPartyNotices/GRDB-LICENSE.txt"]),
        "swiftterm": ("SwiftTerm", "Packages/OpenLXSSHTransport/Package.resolved", ["Packages/OpenLXSSHTransport/ThirdPartyNotices/SwiftTerm-LICENSE"]),
        "swift-argument-parser": ("swift-argument-parser", "Packages/OpenLXSSHTransport/Package.resolved", ["Packages/OpenLXSSHTransport/ThirdPartyNotices/ArgumentParser-LICENSE"]),
        "swift-png": ("swift-png", "Packages/OpenLXSSHTransport/Package.resolved", ["Packages/OpenLXSSHTransport/ThirdPartyNotices/SwiftPNG-LICENSE", "Packages/OpenLXSSHTransport/ThirdPartyNotices/SwiftPNG-NOTICE"]),
        "h": ("h", "Packages/OpenLXSSHTransport/Package.resolved", ["Packages/OpenLXSSHTransport/ThirdPartyNotices/H-LICENSE", "Packages/OpenLXSSHTransport/ThirdPartyNotices/H-NOTICE"]),
    }
    records = []
    for identity, (name, package_lock, licenses) in local_specs.items():
        local_pin = pins_from(safe_source(root, package_lock))[identity]
        pin = app_pins.get(identity, local_pin)
        included = detected[identity]
        if included:
            require(identity in app_pins and pin["state"] == local_pin["state"] and pin["location"].removesuffix(".git") == local_pin["location"].removesuffix(".git"),
                    "dependency-pin", "Integrated dependency does not match the formal App and package locks.")
        notices = [copy_notice(safe_source(root, source), app,
                              f"Contents/Resources/ThirdPartyNotices/{identity.replace('.', '-')}/{Path(source).name}") for source in licenses] if included else []
        records.append({"name": name, "identity": identity, "included": included, "linkedCodePaths": linked_paths[identity],
                        "version": pin["state"].get("version"), "revision": pin["state"]["revision"],
                        "source": pin["location"], "resolvedInAppGraph": identity in app_pins,
                        "evidence": "defined external symbols in embedded code (nm -g -U -j)" if included else "not linked; a resolved pin alone is not inclusion evidence",
                        "licensePaths": [notice["path"] for notice in notices], "licenses": notices})
    known = set(local_specs)
    require(not (set(app_pins) - known), "unknown-dependency", "App lock contains an unreviewed third-party dependency; add real integration/license evidence before packaging.")
    native_root = root / "Packages/OpenLXSSHFiles/.build/native"
    for identity, name in (("libssh2", "libssh2"), ("openssl", "OpenSSL")):
        item = native_lock[identity]
        included = detected[identity]
        notices = []
        if included:
            license_hashes = native_manifest["licenseSHA256"]
            required = {"libssh2/COPYING", "libssh2/SOURCE-NOTICES.txt"} if identity == "libssh2" else {"openssl/LICENSE.txt", "openssl/SOURCE-NOTICES.txt"}
            require(required <= set(license_hashes), "license-input", "Native manifest lacks the required full/file-level license notices.")
            for relative, expected_hash in sorted(license_hashes.items()):
                rel = relative_path(relative)
                if rel.parts[0] != identity:
                    continue
                source = safe_source(native_root / "install/licenses", relative)
                require(sha256(source) == expected_hash, "license-checksum", "A native dependency license differs from its verified build record.")
                if relative == "openssl/LICENSE.txt":
                    require(expected_hash == item["licenseSHA256"], "license-checksum", "OpenSSL license does not match the reviewed license pin.")
                notices.append(copy_notice(source, app, "Contents/Resources/ThirdPartyNotices/" + relative))
        records.append({"name": name, "identity": identity, "included": included, "version": item["version"],
                        "linkedCodePaths": linked_paths[identity],
                        "revision": item["commit"], "sourceArchiveSHA256": item["sha256"], "source": item["url"],
                        "evidence": ("defined __TEXT,__text API symbols (external/private external/non-external as recorded) "
                                     "matched by exact name to hash-verified native archive definitions; "
                                     "symbol-name provenance only, not bitcode equivalence or a complete binary SBOM") if included else "not linked into current App",
                        "symbolEvidence": native_evidence[identity], "nativeBuildProvenance": native_provenance if included else None,
                        "licensePaths": [notice["path"] for notice in notices], "licenses": notices})
    notice = app / "Contents/Resources/ThirdPartyNotices/NOTICE.txt"
    no_symlink_ancestors(notice, app)
    require(not notice.exists(), "license-conflict", "Packaging NOTICE target already exists; inspect before repackaging.")
    notice_text = "OpenLXSSH candidate — actually included third-party code\n" + "\n".join(
        f'{record["name"]} {record["version"]} ({record["revision"]}); see: ' + ", ".join(record["licensePaths"])
        for record in records if record["included"]) + "\nSystem OpenSSH, SQLite and Apple frameworks are supplied by macOS, not bundled.\n"
    descriptor = os.open(notice, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(notice_text)
    return records


def tree_inventory(app):
    """Canonical paths/types/modes/content hashes; no xattrs are removed or modified."""
    result = []
    for parent, dirs, files in os.walk(app, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(parent) / name
            mode = path.lstat().st_mode
            entry = {"path": path.relative_to(app).as_posix(), "mode": stat.S_IMODE(mode)}
            if path.is_symlink():
                entry.update(type="symlink", target=os.readlink(path))
            elif path.is_dir():
                entry.update(type="directory")
            else:
                require(stat.S_ISREG(mode), "special-file", "Cannot checksum a non-regular artifact.")
                entry.update(type="file", size=path.stat().st_size, sha256=sha256(path))
            result.append(entry)
    return sorted(result, key=lambda item: item["path"])


def inventory_digest(inventory):
    return hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def verify_zip(zip_path, app, inventory):
    files = {item["path"]: item for item in inventory if item["type"] != "directory"}
    inventory_paths = {item["path"] for item in inventory}
    seen = set()
    all_names = set()
    with zipfile.ZipFile(zip_path) as archive:
        require(len(archive.infolist()) <= 2 * len(inventory) + 16, "archive-layout", "Archive contains too many entries for the validated App.")
        for entry in archive.infolist():
            name = entry.filename.rstrip("/")
            rel = relative_path(name)
            require(name not in all_names, "archive-layout", "Archive contains duplicate paths.")
            all_names.add(name)
            if rel.parts[0] == "__MACOSX":
                # ditto's AppleDouble entries must correspond to actual App items.
                parts = list(rel.parts[1:])
                if entry.is_dir():
                    require(not parts or (parts[0] == app.name and (len(parts) == 1 or "/".join(parts[1:]) in inventory_paths)),
                            "archive-layout", "Archive metadata directory does not correspond to an App item.")
                    continue
                require(parts and parts[-1].startswith("._"), "archive-layout", "Unexpected archive metadata file.")
                parts[-1] = parts[-1][2:]
                require(parts[0] == app.name and (len(parts) == 1 or "/".join(parts[1:]) in inventory_paths),
                        "archive-layout", "Archive metadata does not correspond to an App item.")
                continue
            require(rel.parts[0] == app.name, "archive-layout", "Archive contains a file outside the validated App.")
            inside = "/".join(rel.parts[1:])
            if entry.is_dir():
                require(not inside or inside in inventory_paths, "archive-layout", "Archive contains an unexpected App directory.")
                continue
            require(inside in files and inside not in seen, "archive-layout", "Archive contains an unexpected or duplicate App file.")
            expected = files[inside]
            expected_size = len(expected["target"].encode()) if expected["type"] == "symlink" else expected["size"]
            require(entry.file_size == expected_size, "archive-checksum", "Archive file size differs from the validated App.")
            digest = hashlib.sha256()
            with archive.open(entry) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            wanted = hashlib.sha256(expected["target"].encode()).hexdigest() if expected["type"] == "symlink" else expected["sha256"]
            require(digest.hexdigest() == wanted, "archive-checksum", "Archive content differs from the validated App.")
            archived_type = (entry.external_attr >> 16) & 0o170000
            archived_mode = (entry.external_attr >> 16) & 0o7777
            require((archived_type == stat.S_IFLNK) == (expected["type"] == "symlink")
                    and archived_type in {stat.S_IFLNK, stat.S_IFREG}
                    and archived_mode == expected["mode"], "archive-layout", "Archive file type/mode differs from the App.")
            seen.add(inside)
    require(seen == set(files), "archive-layout", "Archive is missing App content.")


def artifact_record(app, archive):
    inventory = tree_inventory(app)
    verify_zip(archive, app, inventory)
    return {"app": {"path": app.name, "sha256": inventory_digest(inventory),
                    "checksumAlgorithm": "sha256-canonical-tree-v1", "inventory": inventory},
            "zip": {"path": archive.name, "sha256": sha256(archive)}}


def write_json_exclusive(path, data):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True, ensure_ascii=True)
        stream.write("\n")


def verify_manifest(path, *, _allow_incomplete=False):
    require(".." not in path.parts, "manifest-path", "Manifest path must not contain parent traversal.")
    path = path.absolute()
    no_symlink_ancestors(path, Path(path.anchor))
    require(not path.is_symlink() and path.is_file(), "manifest-path", "Manifest must be a regular local file, not a symlink.")
    root = path.parent.resolve()
    require(_allow_incomplete or (not (root / "INCOMPLETE.json").exists() and not (root / "failure.json").exists()),
            "manifest-status", "Candidate has an incomplete/failure marker; it is not a completed candidate.")
    manifest = json_file(path)
    require(manifest.get("schemaVersion") == 1 and manifest.get("status") == "internal-candidate",
            "manifest-status", "Manifest is not a completed internal candidate record.")
    require(manifest.get("notarized") is False and manifest.get("uploaded") is False,
            "manifest-status", "This local-only manifest must not claim notarization or upload.")
    artifacts = manifest["artifacts"]
    for kind, required_name in (("app", "OpenLXSSH.app"), ("zip", "OpenLXSSH.zip")):
        relative_path(artifacts[kind]["path"])
        require(artifacts[kind]["path"] == required_name, "manifest-path", "Manifest artifact names do not match the local candidate layout.")
        no_symlink_ancestors(root / required_name, root)
    app, archive = root / "OpenLXSSH.app", root / "OpenLXSSH.zip"
    _, code = inspect_bundle(app)
    runtime_code_sources(app, code)
    for binary in code:
        inspect_macho_header(binary, 2)
    inventory = tree_inventory(app)
    require(artifacts["app"].get("checksumAlgorithm") == "sha256-canonical-tree-v1"
            and inventory == artifacts["app"]["inventory"]
            and inventory_digest(inventory) == artifacts["app"]["sha256"], "app-checksum", "App content/mode/symlink inventory does not match its manifest.")
    require(archive.is_file() and sha256(archive) == artifacts["zip"]["sha256"], "zip-checksum", "ZIP SHA256 does not match its manifest.")
    verify_zip(archive, app, inventory)
    for dependency in manifest["dependencies"]:
        require(dependency["included"] or not dependency["licensePaths"], "manifest-license", "Excluded code must not claim bundled licenses.")
        require(not dependency["included"] or dependency["licensePaths"], "manifest-license", "Included dependency is missing license paths.")
        require(dependency["licensePaths"] == [item["path"] for item in dependency["licenses"]]
                and len(set(dependency["licensePaths"])) == len(dependency["licensePaths"]),
                "manifest-license", "Dependency license paths/hashes do not agree or are duplicated.")
        for license_item in dependency["licenses"]:
            license_relative = relative_path(license_item["path"])
            require(license_relative.parts[:3] == ("Contents", "Resources", "ThirdPartyNotices"),
                    "manifest-license", "Dependency licenses must be in the App notice resource directory.")
            license_path = app / license_relative
            no_symlink_ancestors(license_path, app)
            require(license_path.is_file() and sha256(license_path) == license_item["sha256"], "license-checksum", "Bundled license does not match its manifest.")
    return manifest


def toolchain_record(runner):
    return {"xcode": runner.checked(["/usr/bin/xcodebuild", "-version"]),
            "swift": runner.checked(["/usr/bin/xcrun", "swift", "--version"]),
            "clang": runner.checked(["/usr/bin/xcrun", "clang", "--version"]),
            "sdkVersion": runner.checked(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"]),
            "sshVersion": runner.checked(["/usr/bin/ssh", "-V"])}


def assess_gatekeeper(app, runner, log_path):
    try:
        result = runner.run(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4",
                             "--ignore-cache", "--no-cache", app], timeout=60, log_path=log_path)
        return {"exitCode": result.returncode, "gatekeeperAccepted": result.returncode == 0,
                "timedOut": False, "localLogPath": str(log_path), "installationVerified": False}
    except PackagingError as error:
        if error.code != "command-timeout":
            raise
        return {"exitCode": None, "gatekeeperAccepted": False, "timedOut": True,
                "localLogPath": str(log_path), "installationVerified": False}


def package_candidate(root, arguments, runner):
    validate_signing_options(arguments.signing, arguments.identity, arguments.allow_timestamp_request)
    preflight_build_paths(root)
    source = source_state(root, runner, arguments.allow_dirty)
    identity = None
    if arguments.signing != "unsigned":
        identities = runner.checked(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"])
        identity = select_identity(parse_identities(identities), arguments.signing, arguments.identity)
    run_id = str(uuid.uuid4())
    logs = owned_directory(root / "DerivedData/Verification/ReleasePackaging" / run_id, root, exclusive=True)
    write_json_exclusive(logs / "started.json", {"status": "incomplete", "source": source, "signing": arguments.signing,
                                               "notarized": False, "uploaded": False})
    destination = None
    phase = "build-preflight"
    try:
        toolchain = toolchain_record(runner)
        preflight_build_paths(root)
        phase = "build"
        runner.checked(["/bin/bash", root / "Scripts/build-app.sh", "Release", "build"], timeout=1800, log_path=logs / "build.log")
        require(source_state(root, runner, arguments.allow_dirty) == source, "source-changed", "Source changed during the Release build; do not package a concurrently edited build.")
        phase = "bundle-preflight"
        built = root / "DerivedData/Release/Build/Products/Release/OpenLXSSH.app"
        no_symlink_ancestors(built, root)
        info = read_bundle_info(built)
        group = f'{info["CFBundleShortVersionString"]}-{info["CFBundleVersion"]}-{source["commit"][:12]}'
        destination = owned_directory(root / "DerivedData/Distributions" / group / run_id, root, exclusive=True)
        write_json_exclusive(destination / "INCOMPLETE.json", {"status": "incomplete", "localLogPath": str(logs),
                                                              "notarized": False, "uploaded": False})
        inspect_bundle(built)
        before = tree_inventory(built)
        phase = "copy"
        app = destination / "OpenLXSSH.app"
        runner.checked(["/usr/bin/ditto", built, app], timeout=300)
        require(tree_inventory(built) == before and tree_inventory(app) == before, "bundle-changed", "Build output changed during copying; no complete candidate was recorded.")
        _, code = inspect_bundle(app)
        phase = "runtime-dependencies"
        infos, edges = inspect_macho(app, code, runner)
        code_sources = runtime_code_sources(app, code)
        original_code = {path.relative_to(app).as_posix(): sha256(path) for path in code}
        before_notices = tree_inventory(app)
        phase = "licenses"
        dependencies = prepare_dependency_notices(root, app, code, runner)
        inspect_bundle(app)
        require(all(sha256(app / relative) == digest for relative, digest in original_code.items()),
                "bundle-changed", "Embedded code changed while collecting dependency evidence.")
        after_notices = {item["path"]: item for item in tree_inventory(app)}
        require(all(after_notices.get(item["path"]) == item for item in before_notices),
                "bundle-changed", "An original App item changed while adding license notices.")
        originals_by_path = {item["path"]: item for item in before_notices}
        require(all(item["path"] in originals_by_path or item["path"] == "Contents/Resources/ThirdPartyNotices"
                    or item["path"].startswith("Contents/Resources/ThirdPartyNotices/") for item in after_notices.values()),
                "bundle-changed", "Unexpected App item appeared while collecting dependency notices.")
        phase = "signatures"
        signatures = apply_and_verify_signatures(app, code, runner, arguments.signing, identity, arguments.allow_timestamp_request)
        inspect_bundle(app)
        final_infos, final_edges = inspect_macho(app, code, runner)
        require(final_infos == infos and final_edges == edges, "bundle-changed", "Mach-O metadata/dependency closure changed during signing.")
        phase = "gatekeeper-assessment"
        assessment = assess_gatekeeper(app, runner, logs / "spctl.log")
        phase = "archive"
        archive = destination / "OpenLXSSH.zip"
        runner.checked(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", app, archive], timeout=300)
        artifacts = artifact_record(app, archive)
        require(source_state(root, runner, arguments.allow_dirty) == source, "source-changed", "Source changed while packaging; candidate remains incomplete.")
        manifest = {"schemaVersion": 1, "status": "internal-candidate", "candidateID": run_id,
                    "createdUTC": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "classification": "UNSIGNED INTERNAL CANDIDATE" if arguments.signing == "unsigned" else "SIGNED INTERNAL CANDIDATE — NOT NOTARIZED",
                    "version": info["CFBundleShortVersionString"], "build": info["CFBundleVersion"],
                    "product": PRODUCT, "bundleIdentifier": BUNDLE_ID,
                    "platform": {"os": "macOS", "architecture": "arm64", "minimumOS": "26.0"},
                    "source": source, "buildToolchain": toolchain, "buildLogPath": str(logs / "build.log"),
                    "artifacts": artifacts, "codesign": signatures, "spctl": assessment,
                    "notarized": False, "uploaded": False, "dependencies": dependencies,
                    "runtimeCode": [{"path": str(item.path.relative_to(app.resolve())), "minimumOS": item.minimum_os, "sdk": item.sdk,
                                     "filetype": item.filetype, "entryPointFileOffset": item.entry_point,
                                     "source": {**code_sources[str(item.path.relative_to(app.resolve()))], "revision": source["commit"]},
                                     "linkedDependencies": [record["identity"] for record in dependencies
                                                            if str(item.path.relative_to(app.resolve())) in record["linkedCodePaths"]]} for item in infos],
                    "runtimeDependencyEdges": edges,
                    "functionalAcceptance": "NOT PERFORMED; no installation, launch, macOS 26 or two-Mac acceptance is implied"}
        phase = "manifest"
        write_json_exclusive(destination / "manifest.json", manifest)
        verify_manifest(destination / "manifest.json", _allow_incomplete=True)
        # Only the marker this exact run created is removed, never an existing target.
        (destination / "INCOMPLETE.json").unlink()
        write_json_exclusive(logs / "completed.json", {"status": "internal-candidate", "manifestPath": str(destination / "manifest.json")})
        print(manifest["classification"])
        print("Manifest:", destination / "manifest.json")
        print("Local spctl exit:", assessment["exitCode"], "; Gatekeeper accepted:", assessment["gatekeeperAccepted"])
        print("Strict/deep code signature verified:", signatures["verified"], "; Hardened Runtime verified:", signatures["hardenedRuntimeVerified"])
        print("Not notarized; not uploaded; no installation or functional acceptance performed.")
        return destination / "manifest.json"
    except (PackagingError, OSError, ValueError, KeyError, plistlib.InvalidFileException, zipfile.BadZipFile) as error:
        code = error.code if isinstance(error, PackagingError) else "invalid-local-input"
        record = {"status": "incomplete", "phase": phase, "errorCode": code,
                  "localLogPath": str(logs), "candidatePath": str(destination) if destination else None,
                  "notarized": False, "uploaded": False}
        write_json_exclusive(logs / "failed.json", record)
        if destination is not None:
            write_json_exclusive(destination / "failure.json", record)
        print("INCOMPLETE: local recovery record:", logs / "failed.json", file=sys.stderr)
        raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--signing", choices=("unsigned", "development", "developer-id"), default="unsigned")
    result.add_argument("--identity", help="Existing certificate's exact SHA1 fingerprint or exact name; never a partial match")
    result.add_argument("--allow-dirty", action="store_true", help="Explicitly record a dirty-source internal candidate")
    result.add_argument("--allow-timestamp-request", action="store_true", help="Explicitly authorize Developer ID's outward Apple timestamp request (not notarization)")
    result.add_argument("--list-identities", action="store_true", help="Report existing identity counts only, without building/signing")
    result.add_argument("--verify-manifest", type=Path, help="Verify a local candidate's bundle/archive/notice checksums; no build or signing")
    return result


def main(argv=None):
    arguments = parser().parse_args(argv)
    runner = Runner()
    if arguments.verify_manifest is not None or arguments.list_identities:
        require(not (arguments.verify_manifest is not None and arguments.list_identities)
                and arguments.signing == "unsigned" and not arguments.identity and not arguments.allow_dirty
                and not arguments.allow_timestamp_request, "incompatible-options", "Inspection modes cannot also request build/signing options.")
        if arguments.verify_manifest is not None:
            verify_manifest(arguments.verify_manifest)
            print("Candidate bundle/archive/license checksums verified; no trust/installation/runtime acceptance implied.")
        else:
            identities = parse_identities(runner.checked(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"]))
            print(json.dumps({mode: sum(item.name.startswith(prefixes) for item in identities) for mode, prefixes in IDENTITY_PREFIXES.items()}, sort_keys=True))
        return 0
    require(sys.platform == "darwin", "unsupported-host", "Real packaging requires macOS and the existing Xcode toolchain.")
    validate_signing_options(arguments.signing, arguments.identity, arguments.allow_timestamp_request)
    lock_dir = owned_directory(ROOT / "DerivedData/Verification/ReleasePackaging", ROOT)
    lock_path = lock_dir / "packaging.lock"
    no_symlink_ancestors(lock_path, ROOT)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PackagingError("packaging-busy", "Another candidate run owns the build lock. No output was changed.")
        package_candidate(ROOT, arguments, runner)
    finally:
        os.close(descriptor)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PackagingError, OSError, ValueError, KeyError, plistlib.InvalidFileException, zipfile.BadZipFile) as error:
        if isinstance(error, PackagingError):
            print(f"INCOMPLETE [{error.code}]: {error}", file=sys.stderr)
        else:
            print("INCOMPLETE: invalid or unavailable local input/tool; no signing authorization was supplied automatically.", file=sys.stderr)
        raise SystemExit(1)
