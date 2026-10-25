#!/usr/bin/env python3
"""Run an actual native App process and sample it + directly owned children.
No OS event injection, permission changes, networking, or non-probe termination.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('executable', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--mode', default='--gui-smoke', choices=['--gui-smoke', '--vim-smoke'])
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
environment = dict(os.environ, P2_EVIDENCE_DIR=str(args.output), P2_SMOKE_HOLD_SECONDS='3')
seen = set()
samples = []
with (args.output / 'run.log').open('w') as log:
    process = subprocess.Popen([str(args.executable), args.mode], stdout=log, stderr=subprocess.STDOUT, env=environment)
    seen.add(process.pid)
    while process.poll() is None:
        output = subprocess.check_output(['/bin/ps', '-axo', 'pid=,ppid=,rss=,pcpu=,state='], text=True)
        rows = []
        for line in output.splitlines():
            pid, parent, rss, cpu, state = line.split()
            if int(pid) == process.pid or int(parent) == process.pid:
                rows.append(dict(pid=int(pid), parent=int(parent), rssKiB=int(rss), cpuPercent=float(cpu), state=state))
                seen.add(int(pid))
        samples.append(dict(seconds=time.monotonic(), rssKiB=sum(row['rssKiB'] for row in rows), processes=rows))
        time.sleep(0.05)
    code = process.wait()
time.sleep(0.25)
alive = []
for pid in seen:
    try:
        os.kill(pid, 0)
        alive.append(pid)
    except ProcessLookupError:
        pass
result = dict(exitCode=code, executable=str(args.executable), mode=args.mode,
              sampleCount=len(samples), peakOwnedRSSKiB=max((s['rssKiB'] for s in samples), default=0),
              observedPIDs=sorted(seen), aliveAfterExit=alive, samples=samples)
(args.output / 'resources.json').write_text(json.dumps(result, indent=2))
print(json.dumps({key: value for key, value in result.items() if key != 'samples'}, indent=2))
raise SystemExit(code if not alive else 2)
