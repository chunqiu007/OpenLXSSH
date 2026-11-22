#!/usr/bin/env python3
"""Stage, validate, optionally sign, and package OpenLXSSH.app into a read-only LZMA DMG."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_BUNDLE_ID = "org.openlxssh.OpenLXSSH"
MIN_MACOS = (26, 0)
REQUIRED_LICENSES = (
    "NOTICE.txt",
    "GRDB-LICENSE.txt",
    "SwiftTerm-LICENSE",
    "ArgumentParser-LICENSE",
    "SwiftPNG-LICENSE",
    "H-LICENSE",
    "FilesNativeLicenses/libssh2/COPYING",
    "FilesNativeLicenses/openssl/LICENSE.txt",
)
FORBIDDEN_SUFFIXES = (".dsym", ".pem", ".key")
FORBIDDEN_NAMES = (".git",)


class PackagingError(RuntimeError):
    """Raised when a packaging or validation check fails."""


def run(cmd: list[str], *, cwd: Path | None = None) -> str:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise PackagingError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{detail}")
    return proc.stdout


def parse_version(raw: str) -> tuple[int, ...]:
    parts = raw.strip().split(".")
    if not parts or not all(p.isdigit() for p in parts):
        raise PackagingError(f"Invalid version string: {raw!r}")
    return tuple(int(p) for p in parts)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_info_plist(app: Path) -> dict[str, Any]:
    plist_path = app / "Contents/Info.plist"
    if not plist_path.is_file():
        raise PackagingError(f"Missing Info.plist: {plist_path}")
    info = plistlib.loads(plist_path.read_bytes())

    bundle_id = info.get("CFBundleIdentifier")
    if bundle_id != EXPECTED_BUNDLE_ID:
        raise PackagingError(f"Unexpected CFBundleIdentifier: {bundle_id!r} (expected {EXPECTED_BUNDLE_ID!r})")

    version = str(info.get("CFBundleShortVersionString") or "").strip()
    build = str(info.get("CFBundleVersion") or "").strip()
    executable = str(info.get("CFBundleExecutable") or "").strip()
    min_os = str(info.get("LSMinimumSystemVersion") or "").strip()
    if not (version and build and executable):
        raise PackagingError("Info.plist missing CFBundleShortVersionString, CFBundleVersion, or CFBundleExecutable")
    if parse_version(min_os) < MIN_MACOS:
        raise PackagingError(f"LSMinimumSystemVersion {min_os!r} is below 26.0")

    return {"bundle_id": bundle_id, "version": version, "build": build, "executable": executable, "min_macos": min_os}


def stage_app(source_app: Path, output_dir: Path) -> Path:
    if not source_app.is_dir():
        raise PackagingError(f"Source app bundle not found: {source_app}")
    output_dir.mkdir(parents=True, exist_ok=True)
    staged_app = output_dir / "OpenLXSSH.app"
    if staged_app.resolve() == source_app.resolve():
        raise PackagingError("Output directory must not overwrite the source .app in place")
    if staged_app.exists():
        shutil.rmtree(staged_app)
    run(["ditto", str(source_app), str(staged_app)])
    return staged_app


def verify_binary(binary: Path) -> dict[str, Any]:
    if not binary.is_file():
        raise PackagingError(f"Missing main executable: {binary}")

    archs = run(["lipo", "-archs", str(binary)]).strip().split()
    if archs != ["arm64"]:
        raise PackagingError(f"Expected arm64-only Mach-O, found: {archs}")

    load_cmds = run(["otool", "-l", str(binary)])
    minos_match = re.search(r"cmd LC_BUILD_VERSION\b.*?minos\s+(\d+(?:\.\d+)*)", load_cmds, re.S)
    if not minos_match:
        raise PackagingError("Mach-O missing LC_BUILD_VERSION minos load command")
    minos = minos_match.group(1)
    if parse_version(minos) < MIN_MACOS:
        raise PackagingError(f"Mach-O minos {minos!r} is below 26.0")

    dylib_lines = run(["otool", "-L", str(binary)]).splitlines()[1:]
    non_system = [
        lib for line in dylib_lines
        if (lib := line.strip().split(" (")[0]) and not lib.startswith(("/System/Library/", "/usr/lib/"))
    ]
    if non_system:
        raise PackagingError(f"Forbidden non-system dylib dependencies: {non_system}")
    return {"archs": archs, "minos": minos, "dylib_count": len(dylib_lines)}


def verify_bundle_contents(staged_app: Path) -> None:
    if (staged_app / "Contents/Helpers").exists():
        raise PackagingError("Unexpected leftover Contents/Helpers directory in bundle")

    forbidden = [
        str(Path(root, name).relative_to(staged_app))
        for root, dirs, files in os.walk(staged_app)
        for name in dirs + files
        if name.lower() in FORBIDDEN_NAMES or name.lower().endswith(FORBIDDEN_SUFFIXES)
    ]
    if forbidden:
        raise PackagingError(f"Forbidden files present in bundle: {forbidden}")

    resources = staged_app / "Contents/Resources"
    if not (resources / "FilesNativeLicenses").is_dir():
        raise PackagingError("Missing Contents/Resources/FilesNativeLicenses directory")
    for rel in REQUIRED_LICENSES:
        target = resources / rel
        if not target.is_file() or target.stat().st_size == 0:
            raise PackagingError(f"Missing or empty bundled license/notice: Contents/Resources/{rel}")

    manifest_path = REPO_ROOT / "Packages/OpenLXSSHFiles/.build/native/manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for rel, expected in manifest.get("licenseSHA256", {}).items():
            target = resources / "FilesNativeLicenses" / rel
            if not target.is_file() or sha256_file(target) != expected:
                raise PackagingError(f"Native license SHA-256 mismatch: {rel}")


def sign_bundle(staged_app: Path, identity: str, use_timestamp: bool) -> None:
    ts_flag = "--timestamp" if use_timestamp else "--timestamp=none"
    run(["codesign", "--force", "--options", "runtime", "--sign", identity, ts_flag, str(staged_app)])
    run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(staged_app)])


def build_dmg(
    staged_app: Path, output_dir: Path, version: str, sign_identity: str | None, use_timestamp: bool
) -> tuple[Path, Path, str]:
    dmg_path = output_dir / f"OpenLXSSH-{version}-arm64.dmg"
    sha_path = Path(f"{dmg_path}.sha256")
    if dmg_path.exists():
        dmg_path.unlink()

    with tempfile.TemporaryDirectory(prefix="openlxssh-dmg-", dir=output_dir) as tmp:
        stage_dir = Path(tmp)
        run(["ditto", str(staged_app), str(stage_dir / "OpenLXSSH.app")])
        os.symlink("/Applications", stage_dir / "Applications")
        run([
            "hdiutil", "create", "-volname", f"OpenLXSSH {version}",
            "-srcfolder", str(stage_dir), "-ov", "-format", "ULMO", str(dmg_path),
        ])

    run(["hdiutil", "verify", str(dmg_path)])
    if sign_identity:
        ts_flag = "--timestamp" if use_timestamp else "--timestamp=none"
        run(["codesign", "--force", "--sign", sign_identity, ts_flag, str(dmg_path)])
        run(["codesign", "--verify", "--verbose=2", str(dmg_path)])

    digest = sha256_file(dmg_path)
    sha_path.write_text(f"{digest}  {dmg_path.name}\n", encoding="utf-8")
    return dmg_path, sha_path, digest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Stage, validate, optionally sign, and package OpenLXSSH.app as an arm64 LZMA DMG.",
    )
    parser.add_argument(
        "--app", type=Path, default=REPO_ROOT / "DerivedData/Release/Build/Products/Release/OpenLXSSH.app",
        help="Path to built OpenLXSSH.app (default: DerivedData/Release/Build/Products/Release/OpenLXSSH.app)",
    )
    parser.add_argument(
        "--output", type=Path, default=REPO_ROOT / "DerivedData/ReleasePackage",
        help="Output directory for staged .app, .dmg, and .sha256 (default: DerivedData/ReleasePackage)",
    )
    parser.add_argument("--build", action="store_true", help="Run Scripts/build-app.sh Release build first")
    parser.add_argument(
        "--sign", metavar="IDENTITY",
        help="Optional Developer ID / codesign identity (Hardened Runtime; offline --timestamp=none by default)",
    )
    parser.add_argument("--timestamp", action="store_true", help="Opt in to Apple timestamp server during codesign")
    parser.add_argument("--no-dmg", action="store_true", help="Stage and validate .app only; skip DMG creation")
    parser.add_argument("--no-strip", action="store_true", help="Skip stripping debug symbols with strip -x")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.timestamp and not args.sign:
        raise PackagingError("--timestamp requires --sign IDENTITY")
    if args.build:
        run([str(REPO_ROOT / "Scripts/build-app.sh"), "Release", "build"], cwd=REPO_ROOT)

    source_app, output_dir = args.app.resolve(), args.output.resolve()
    info = verify_info_plist(source_app)
    staged_app = stage_app(source_app, output_dir)

    binary = staged_app / "Contents/MacOS" / info["executable"]
    if not args.no_strip:
        run(["strip", "-x", str(binary)])

    binary_info = verify_binary(binary)
    verify_bundle_contents(staged_app)
    if args.sign:
        sign_bundle(staged_app, args.sign, args.timestamp)

    receipt: dict[str, Any] = {
        "bundle_id": info["bundle_id"],
        "version": info["version"],
        "build": info["build"],
        "min_macos": info["min_macos"],
        "archs": binary_info["archs"],
        "macho_minos": binary_info["minos"],
        "stripped": not args.no_strip,
        "signed": bool(args.sign),
        "timestamp": bool(args.timestamp),
        "staged_app": str(staged_app),
    }
    if not args.no_dmg:
        dmg_path, sha_path, digest = build_dmg(staged_app, output_dir, info["version"], args.sign, args.timestamp)
        receipt.update({
            "dmg": str(dmg_path),
            "dmg_bytes": dmg_path.stat().st_size,
            "dmg_sha256": digest,
            "sha256_file": str(sha_path),
        })

    print(json.dumps(receipt, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PackagingError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
