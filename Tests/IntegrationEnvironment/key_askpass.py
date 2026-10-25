#!/usr/bin/env python3
"""Private ssh-keygen askpass pipe only; never invoke from a terminal."""
import os
from pathlib import Path
import sys

if (sys.platform != 'linux' or os.geteuid() != 0 or not Path('/.dockerenv').is_file()
        or os.environ.get('OPENLXSSH_FIXTURE_KEYGEN') != '1' or sys.stdout.isatty()
        or Path('/proc/{}/exe'.format(os.getppid())).resolve().name != 'ssh-keygen'):
    sys.exit(1)
# stdout here is solely ssh-keygen's private askpass response pipe, not the
# fixture console, docker logs, an exec export channel or a test artifact.
sys.stdout.write(Path('/run/openlxssh-fixture/private/key-passphrase').read_text())
