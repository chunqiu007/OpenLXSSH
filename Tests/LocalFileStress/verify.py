#!/usr/bin/env python3
"""Finite local-only stress verification. Default: one small run, then one full run.

Usage: python3 Tests/LocalFileStress/verify.py [--mode small|full|all]
Build products, build logs, context and JSON evidence stay in this fixture's ignored .build/.
No SSH, sockets, native rebuilds, remote servers, daemons, scheduling or power changes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parent.parent
FILES = WORKSPACE / "Packages" / "OpenLXSSHFiles"
NATIVE = FILES / ".build" / "native"
MIN_FREE = 12 * 1024**3


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            result.update(block)
    return result.hexdigest()


def output(argv):
    return subprocess.check_output(argv, cwd=HERE, text=True, stderr=subprocess.STDOUT).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("small", "full", "all"), default="all")
    args = parser.parse_args()
    os.umask(0o077)
    evidence_dir = HERE / ".build" / "evidence" / (time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex)
    evidence_dir.mkdir(parents=True, mode=0o700)
    scratch = HERE / ".build" / "swiftpm"
    context = {"taskID": "P7-LOCAL-FILE-STRESS-A", "fixturePath": str(HERE),
               "boundary": "local only, not product/remote/PERF/24h evidence"}
    summary = {"status": "preflight", "mode": args.mode, "buildExitCode": None, "runs": [], "context": context}
    result_path = evidence_dir / "verification.json"

    def save():
        result_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    try:
        ignored = subprocess.run(["git", "-C", str(WORKSPACE), "check-ignore", "-q", str(result_path)], cwd=HERE)
        if ignored.returncode != 0:
            raise RuntimeError("Refusing non-ignored evidence output")
        context["gitHEAD"] = output(["git", "-C", str(WORKSPACE), "rev-parse", "HEAD"])
        context["swift"] = output(["swift", "--version"])
        context["xcode"] = output(["xcodebuild", "-version"])
        context["sdk"] = output(["xcrun", "--show-sdk-version"])
        context["macOS"] = output(["sw_vers", "-productVersion"])
        context["model"] = output(["sysctl", "-n", "hw.model"])
        context["physicalMemoryBytes"] = output(["sysctl", "-n", "hw.memsize"])
        context["architecture"] = output(["uname", "-m"])
        context["dfBefore"] = output(["df", "-k", str(HERE)])
        context["datasetFilesystem"] = "FileManager.default.temporaryDirectory, exclusive 0700 UUID root"
        print(context["dfBefore"], flush=True)
        if shutil.disk_usage(HERE).free < MIN_FREE:
            raise RuntimeError("Less than 12 GiB free; no reduced dataset may claim the full baseline")
        manifest_path = NATIVE / "manifest.json"
        if not manifest_path.is_file():
            raise RuntimeError("Missing compiled native manifest; no native rebuild is authorized here")
        manifest = json.loads(manifest_path.read_text())
        if not manifest.get("outputs"):
            raise RuntimeError("Native manifest lacks verifiable outputs")
        for relative, expected in manifest["outputs"].items():
            path = (NATIVE / relative).resolve()
            if not path.is_relative_to(NATIVE.resolve()):
                raise RuntimeError("Native manifest output escapes native root")
            if not path.is_file() or sha256(path) != expected:
                raise RuntimeError(f"Native output missing/changed: {relative}; not rebuilding")
        context["nativeManifestSHA256"] = sha256(manifest_path)
        context["nativeOutputsChecked"] = str(len(manifest["outputs"]))
        formal_inputs = [FILES / "Package.swift", *sorted((FILES / "Sources").rglob("*")),
                         WORKSPACE / "Packages" / "OpenLXSSHTrust" / "Package.swift",
                         *sorted((WORKSPACE / "Packages" / "OpenLXSSHTrust" / "Sources").rglob("*"))]
        formal_hashes = {str(p.relative_to(WORKSPACE)): sha256(p) for p in formal_inputs if p.is_file()}
        context["formalInputSHA256"] = json.dumps(formal_hashes, sort_keys=True)
        context["fixtureSourceSHA256"] = json.dumps({str(p.relative_to(HERE)): sha256(p)
            for p in sorted((HERE / "Sources").rglob("*")) if p.is_file()} | {
                "Package.swift": sha256(HERE / "Package.swift"), "verify.py": sha256(Path(__file__))}, sort_keys=True)
        # External consumers must import COpenLXSSHFiles' public libssh2 headers as well.
        # This local command-line setting does not patch the production package or rebuild native archives.
        native_headers = str(NATIVE / "install" / "include")
        command = ["swift", "build", "--package-path", str(HERE), "--scratch-path", str(scratch),
                   "--configuration", "release", "--jobs", "2", "-Xcc", "-I" + native_headers]
        summary["buildCommand"] = command
        summary["buildCWD"] = str(HERE)
        context["buildConfiguration"] = "SwiftPM release, macOS 15 host fixture, explicit external C header search path"
        context["concurrentDevelopmentLoad"] = "App/Xcode development builds may run concurrently; self-only CPU/RSS and wall throughput are not product performance benchmarks"
        save()
        with (evidence_dir / "build.log").open("w") as log:
            built = subprocess.run(command, cwd=HERE, stdout=log, stderr=subprocess.STDOUT)
        summary["buildExitCode"] = built.returncode
        save()
        if built.returncode:
            print((evidence_dir / "build.log").read_text(), end="")
            raise RuntimeError("Release fixture build failed; see build.log")
        binary = scratch / "release" / "OpenLXSSHLocalFileStress"
        context["binarySHA256"] = sha256(binary)
        if any(sha256(WORKSPACE / p) != expected for p, expected in formal_hashes.items()):
            raise RuntimeError("Formal package inputs changed during build; await a stable package before running")
        modes = ("small", "full") if args.mode == "all" else (args.mode,)
        for mode in modes:
            if any(sha256(WORKSPACE / p) != expected for p, expected in formal_hashes.items()):
                raise RuntimeError("Formal package inputs changed before dataset run; stopping")
            path = evidence_dir / (mode + ".json")
            env = os.environ.copy()
            env["OPENLXSSH_STRESS_CONTEXT"] = json.dumps(context)
            argv = [str(binary), mode, str(path)]
            print("Run", mode, "evidence", path, flush=True)
            with (evidence_dir / (mode + ".log")).open("w") as log:
                completed = subprocess.run(argv, cwd=HERE, env=env, stdout=log, stderr=subprocess.STDOUT)
            print((evidence_dir / (mode + ".log")).read_text(), end="", flush=True)
            run = {"mode": mode, "command": argv, "cwd": str(HERE), "exitCode": completed.returncode,
                   "evidence": str(path)}
            summary["runs"].append(run)
            if path.is_file():
                data = json.loads(path.read_text())
                run.update(status=data["status"], durationSeconds=data["actualDurationSeconds"], cleanup=data["cleanup"])
                print(json.dumps({"mode": mode, "status": data["status"], "durationSeconds": data["actualDurationSeconds"],
                                  "largeBytes": data["largeFileBytes"], "smallFiles": data["smallFileCount"],
                                  "peakRSSBytes": max((s["processHighWaterRSSBytes"] for s in data["resources"]), default=0)}, indent=2), flush=True)
            save()
            if completed.returncode:
                raise RuntimeError(f"{mode} run failed; full mode will not run after a small failure")
            if any(sha256(WORKSPACE / p) != expected for p, expected in formal_hashes.items()):
                raise RuntimeError("Formal package inputs changed while the built fixture ran; evidence not accepted")
        context["dfAfter"] = output(["df", "-k", str(HERE)])
        summary["status"] = "passed-local-only"
        save()
        print("Finite verification passed (local only):", result_path, flush=True)
        return 0
    except Exception as error:
        summary["status"] = "failed"
        summary["error"] = str(error)
        save()
        print("Verification failed:", error, "evidence:", result_path, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
