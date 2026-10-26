#!/usr/bin/env python3
"""Independent auth-negative host15 offline build; defaults/help/validate inert."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent
ROOT=HERE.parent.parent
PARENT=HERE.parent/'RemoteFileAcceptance'


def build():
    spec=importlib.util.spec_from_file_location('accepted_builder',PARENT/'build_host.py');accepted=importlib.util.module_from_spec(spec);spec.loader.exec_module(accepted)
    os.umask(0o077);base=HERE/'.build';base.mkdir(mode=0o700,exist_ok=True)
    if base.resolve()!=base or base.stat().st_uid!=os.getuid() or base.stat().st_mode&0o777!=0o700:raise accepted.Refusal('unsafeBuildRoot')
    work=base/('host-'+str(uuid.uuid4()));work.mkdir(mode=0o700)
    print('Independent auth-negative offline build: '+str(work),flush=True)
    class ExactBuilder(accepted.Builder):
        def unchanged(self):
            for source,item in self.inputs.items():
                if accepted.digest(source,item['exported'])!=item['sha256'] or accepted.digest(item['snapshot'])!=item['sha256']:raise accepted.Refusal('changedInput')
            names={path.name for path in self.inputs if path.parent==accepted.CORE/'RealIntegrationCore'}
            if names!={'Contract.swift','PrivateInput.swift'}:raise accepted.Refusal('exactCoreClosure')
    b=ExactBuilder(work);b.record.update(taskID='REAL-AUTH-FAILURE-PREP-A',realIntegrationCoreClosure=['Contract.swift','PrivateInput.swift'],parallelCoreSourcesExcluded='SFTPAuth*, Mina*, OpenSSH*, UnexpectedChallengeShape*')
    try:
        for path in [PARENT/'build_host.py',HERE/'build_host.py',HERE/'test_static.py',HERE/'.gitignore',accepted.FILES/'Package.swift',accepted.FILES/'native-inputs.json',ROOT/'Packages/OpenLXSSHTrust/Package.swift']:b.snapshot(path)
        manifest=json.loads(b.snapshot(accepted.NATIVE/'manifest.json').read_bytes());lock=json.loads((accepted.FILES/'native-inputs.json').read_bytes())
        if manifest['dependencies']['toolchain']['deploymentTarget']!='15.0' or manifest['inputs']['lockSHA256']!=accepted.digest(accepted.FILES/'native-inputs.json') or any(manifest['dependencies'][key]!=lock[key] for key in ('libssh2','openssl')):raise accepted.Refusal('nativeInputMismatch')
        for relative,expected in manifest['outputs'].items():
            if not relative.startswith('install/') or '..' in Path(relative).parts or accepted.digest(accepted.NATIVE/relative,True)!=expected:raise accepted.Refusal('nativeOutputMismatch')
            b.snapshot(accepted.NATIVE/relative,True)
        native=work/'inputs'/accepted.NATIVE.relative_to(ROOT)/'install'
        b.swiftc=b.run('locate-swiftc',['/usr/bin/xcrun','-f','swiftc']).decode().strip();b.clang=b.run('locate-clang',['/usr/bin/xcrun','-f','clang']).decode().strip();b.sdk=b.run('locate-sdk',['/usr/bin/xcrun','--show-sdk-path']).decode().strip()
        b.run('swift-version',[b.swiftc,'--version'])
        cobjects=b.c('COpenLXSSHFiles',accepted.FILES/'Sources/COpenLXSSHFiles',native/'include')+b.c('RealIntegrationPOSIX',accepted.CORE/'RealIntegrationPOSIX')+b.c('RemoteFileMetrics',PARENT/'POSIX')
        objects=[]
        for name,directory,package in [('OpenLXSSHTrust',ROOT/'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust','openlxsshtrust'),('OpenLXSSHFiles',accepted.FILES/'Sources/OpenLXSSHFiles','openlxsshfiles')]:objects.append(b.swift(name,b.sources(directory),native/'include',package))
        objects.append(b.swift('RealIntegrationCore',[b.snapshot(accepted.CORE/'RealIntegrationCore'/name) for name in ('Contract.swift','PrivateInput.swift')],native/'include','realintegration'))
        location=work/'BuildLocation.swift';location.write_text('enum BuildLocation { static let ownRoot = '+json.dumps(str(HERE))+'; static let fixtureRoot = '+json.dumps(str(ROOT/'Tests/IntegrationEnvironment'))+'; static let offlineRoot = '+json.dumps(str(work/'test-data'))+'; static let buildEvidence = '+json.dumps(str(work/'result.json'))+'; static let builtAt = '+repr(time.time())+' }\n')
        shared=[b.snapshot(HERE/name) for name in ('AuthCore.swift','OwnedFiles.swift','AuthCase.swift')]+[location]
        obj=b.swift('OpenLXSSHAuthenticationFailure',shared+[b.snapshot(HERE/'Main.swift')],native/'include')
        symbols=b.run('production-symbols',['/usr/bin/xcrun','nm','-u',obj])
        for required in (b'LibSSH2FileService',b'HostTrustStore'):
            if required not in symbols:raise accepted.Refusal('missingProductionAPI')
        names=b.run('production-trust-replacement-symbol',['/usr/bin/xcrun','nm','-g',objects[0]])
        if b'prepareReplacement' not in names:raise accepted.Refusal('missingExplicitReplacementAPI')
        archives=[native/'lib'/name for name in ('libssh2.a','libssl.a','libcrypto.a')]
        driver=b.link('OpenLXSSHAuthenticationFailure',[obj,*objects,*cobjects],archives)
        testobj=b.swift('OpenLXSSHAuthenticationFailureOffline',shared+[b.snapshot(HERE/'OfflineMain.swift')],native/'include')
        tests=b.link('OpenLXSSHAuthenticationFailureOffline',[testobj,*objects,*cobjects],archives)
        b.unchanged();b.run('static-tests',[sys.executable,'-B',HERE/'test_static.py']);b.run('offline-tests',[tests])
        b.run('cli-default',[driver]);b.run('cli-help',[driver,'--help']);b.run('cli-validate',[driver,'validate','--case','/not/opened/case.json'])
        b.run('cli-negative-no-auth',[driver,'--run-negative','--case','/not/opened/case.json'],expected=2)
        b.run('cli-replace-no-auth',[driver,'--replace-and-control','--case','/not/opened/case.json'],expected=2)
        b.run('cli-prepare-no-auth',[driver,'prepare','--scenario','bad-key-passphrase','--generation','/not/opened'],expected=2)
        b.unchanged();b.record.update(status='passed-offline-only-live-not-run',driver=str(driver),driverSHA256=accepted.digest(driver),nativeOutputsChecked=len(manifest['outputs']),architecture=accepted.macho(driver,2))
        print('Auth-negative offline point passed; no Docker/relay/generation/private keys/network/live.');print('Exact driver: '+str(driver));return 0
    except BaseException as error:b.record.update(status='failed-offline',failure=type(error).__name__);raise
    finally:b.save()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',nargs='?',default='help',choices=('help','validate','build'));args=parser.parse_args(argv)
    if args.action=='help':parser.print_help();return 0
    if args.action=='validate':print('Recipe syntax only: no files/children/network.');return 0
    return build()


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:sys.stderr.write('Auth-negative build failed: '+type(error).__name__+'. No private details.\n');sys.exit(2)
