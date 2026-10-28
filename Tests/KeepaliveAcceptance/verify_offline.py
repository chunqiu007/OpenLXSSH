#!/usr/bin/env python3
"""Only pure Python tests and Swift/C syntax/API typecheck. NEVER link/sign/socket/live."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HERE=Path(__file__).absolute().parent


def verify():
    os.umask(0o077)
    manifest=json.loads((HERE/'frozen-inputs.json').read_bytes())
    readonly={item['path']:item['sha256'] for item in manifest['dependencyObjects']}
    readonly.update(manifest['moduleSHA256']);readonly.update(manifest['frozenRelaySHA256'])
    readonly[manifest['helper']]=manifest['helperSHA256'];readonly[manifest['frozenLiveInput']]=manifest['frozenLiveInputSHA256']
    def check():
        if any(hashlib.sha256(Path(p).read_bytes()).hexdigest()!=h for p,h in readonly.items()):raise ValueError('frozen-input-changed')
    check()
    work=HERE/'.build'/('source-'+uuid.uuid4().hex);work.mkdir(mode=0o700)
    commands=[]
    def run(label,args):
        r=subprocess.run(list(map(str,args)),cwd=HERE,stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
        log=work/(label+'.log');log.write_bytes(r.stdout+r.stderr)
        commands.append({'command':list(map(str,args)),'cwd':str(HERE),'exitCode':r.returncode,'log':str(log)})
        if r.returncode:raise ValueError(label+'-failed')
        return r.stdout.decode().strip()
    status='failed-source-offline'
    try:
        run('python-pure',[sys.executable,'-B',HERE/'test_static.py'])
        sdk=run('sdk',['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'])
        compiler=run('swift-path',['/usr/bin/xcrun','-f','swiftc'])
        location=work/'BuildLocation.swift';location.write_text('enum BuildLocation { static let ownRoot="/not/opened"; static let buildRoot="/not/opened"; static let fixtureRoot="/not/opened"; static let team="UNSIGNED00" }\n')
        flags=['-parse-as-library','-swift-version','6','-target','arm64-apple-macosx15.0','-sdk',sdk,'-warnings-as-errors',
            '-module-cache-path',work/'module-cache','-I',manifest['moduleDirectory'],'-I',Path(manifest['parentCheckpoint'])/'cmodules']
        run('complete-consumer-typecheck',[compiler,*flags,'-typecheck',HERE/'Core.swift',HERE/'Main.swift',HERE/'LiveInput.swift',location])
        run('identity-c-syntax',['/usr/bin/xcrun','clang','-target','arm64-apple-macos15.0','-isysroot',sdk,'-Wall','-Wextra','-Werror','-fsyntax-only',HERE/'identity.c'])
        check();status='passed-pure-and-api-typecheck-no-link-sign-live'
        return 0
    finally:
        sources={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(HERE.iterdir()) if p.is_file()}
        (work/'result.json').write_text(json.dumps({'status':status,'commands':commands,'sourceSHA256':sources,'readonlyInputCount':len(readonly),
            'socketsOpened':False,'DockerInvoked':False,'linked':False,'signed':False,'liveExecuted':False},indent=2,sort_keys=True)+'\n')
        print('Keepalive source/offline evidence: '+str(work),flush=True)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('help','verify'),nargs='?',default='help');args=parser.parse_args(argv)
    if args.action=='help':parser.print_help();return 0
    return verify()


if __name__=='__main__':
    try:sys.exit(main())
    except Exception:sys.stderr.write('Keepalive source validation failed; inspect own offline logs.\n');sys.exit(2)
