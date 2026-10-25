#!/usr/bin/env python3
"""Offline memory-key interoperability against the existing pinned Files native build.

No new dependency, manifest edit, native rebuild, signing, network or Keychain operation.
Only this package's ignored .build and the fixture's self-created 0700 UUID tree are written.
libssh2 internal parser/sign callbacks are test-only; the product API remains native-free.
"""
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT.parent / "OpenLXSSHFiles" / ".build" / "native"
FIXTURE = ROOT / "Tests" / "AuthenticationMaterialProbe"
SCRATCH = ROOT / ".build" / "auth-material"


def main():
    if os.geteuid() == 0:
        print("Do not run the authentication material probe as root")
        return 64
    logs = ROOT / ".build" / "verification"
    logs.mkdir(parents=True, exist_ok=True)
    log = logs / ("auth-material-libssh2-" + str(uuid.uuid4()) + ".log")
    with log.open("w") as output:
        def emit(text):
            print(text)
            output.write(text + "\n")
            output.flush()

        def run(command, timeout=120):
            emit("cwd=" + str(ROOT))
            emit("command=" + repr([str(value) for value in command]))
            result = subprocess.run([str(value) for value in command], cwd=ROOT, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=timeout, text=True)
            emit(result.stdout.rstrip())
            emit("exit=" + str(result.returncode))
            if result.returncode:
                raise RuntimeError("verification command failed")
            return result.stdout

        result = 0
        try:
            include = NATIVE / "install" / "include"
            source = NATIVE / "work" / "libssh2-1.11.1" / "src"
            config = NATIVE / "work" / "ssh-build" / "src"
            archives = [NATIVE / "install" / "lib" / name for name in ["libssh2.a", "libssl.a", "libcrypto.a"]]
            required = archives + [include / "libssh2.h", source / "libssh2_priv.h", config / "libssh2_config.h"]
            if not all(path.is_file() for path in required):
                raise RuntimeError("existing Files native build is required; this script will not build it")
            if '#define LIBSSH2_VERSION "1.11.1"' not in (include / "libssh2.h").read_text():
                raise RuntimeError("review this test-only internal ABI before using another libssh2 version")
            run(["/usr/bin/swift", "build", "--package-path", ROOT, "--scratch-path", SCRATCH,
                 "-c", "debug", "-Xswiftc", "-warnings-as-errors", "-Xcc", "-Wall", "-Xcc", "-Wextra", "-Xcc", "-Werror"])
            binary_path = run(["/usr/bin/swift", "build", "--package-path", ROOT, "--scratch-path", SCRATCH,
                               "-c", "debug", "--show-bin-path"])
            binary = Path(binary_path.strip())
            work = SCRATCH / "libssh2-probe"
            work.mkdir(parents=True, exist_ok=True)
            c_object = work / "AuthenticationMaterialProbe.o"
            run(["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-DHAVE_CONFIG_H=1",
                 "-I" + str(include), "-I" + str(source), "-I" + str(config), "-I" + str(FIXTURE),
                 "-c", FIXTURE / "AuthenticationMaterialProbe.c", "-o", c_object])
            objects = sorted((binary / "OpenLXSSHSecurity.build").glob("*.swift.o"))
            posix = binary / "SecurityPOSIX.build" / "SecurityPOSIX.c.o"
            if len(objects) != 5 or not posix.is_file():
                raise RuntimeError("unexpected Security object layout; no fallback compilation attempted")
            executable = work / "AuthenticationMaterialProbe"
            run(["/usr/bin/xcrun", "swiftc", "-parse-as-library", "-warnings-as-errors", "-swift-version", "6",
                 "-I", binary / "Modules", "-Xcc", "-fmodule-map-file=" + str(binary / "SecurityPOSIX.build" / "module.modulemap"),
                 "-Xcc", "-I" + str(ROOT / "Sources" / "SecurityPOSIX" / "include"),
                 "-import-objc-header", FIXTURE / "AuthenticationMaterialProbe.h", FIXTURE / "main.swift",
                 *objects, posix, c_object, *archives, "-framework", "Security", "-framework", "CoreFoundation", "-o", executable])
            run([executable], timeout=30)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            emit("INCOMPLETE: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
            result = 1
        emit("script_exit=" + str(result))
    print("log=" + str(log))
    return result


if __name__ == "__main__":
    sys.exit(main())
