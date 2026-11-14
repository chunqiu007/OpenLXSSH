#!/usr/bin/env python3
"""Current approved keyonly identity and immutable evidence references. Import is inert."""
from pathlib import Path

ROOT = Path(__file__).absolute().parents[3]
CONTAINER = 'ed38148af68e2c6cdb70f18b9a716876754a393df2d530b168ddd2144d99021a'
FINGERPRINT = 'SHA256:d2G+w7lBrjYDFHHd6c6GxIhk7qzFs6df1i7EVJfeUYs'
IMAGE = 'sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363'
NETWORK = 'b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1'
PROJECT = 'openlxssh-fixture-61ed25328c13'
CONTEXT = 'desktop-linux'
ENDPOINT = 'unix:///Users/liuwenshuo/.docker/run/docker.sock'
PUBLIC_EVIDENCE = {
    str(ROOT / 'DerivedData/UXVerification/U0-NativeShell/live/positive-contracts.json'): '19277a92b45937fabbd2f91f6e34a69837765dfb73e90674b02a9f388567a5aa',
    str(ROOT / 'Experiments/UXNativeShellProbe/.build/sftp-auth-case-41e459dd6c2a/sftp-auth.json'): 'c250f0ab43d317599265a0521bf71069c1e02a7081f830f58f6f1eafe4d5febc',
}
