#!/usr/bin/env python3
"""Independent host15 offline build only; default/help/validate are inert."""
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
PARENT=HERE.parent/'RemoteFileAcceptance'
ROOT=HERE.parent.parent


def build():
    spec=importlib.util.spec_from_file_location('accepted_remote_builder',PARENT/'build_host.py')
    accepted=importlib.util.module_from_spec(spec);spec.loader.exec_module(accepted)
    os.umask(0o077)
    build_root=HERE/'.build';build_root.mkdir(mode=0o700,exist_ok=True)
    if build_root.resolve()!=build_root or build_root.stat().st_uid!=os.getuid() or build_root.stat().st_mode&0o777!=0o700:
        raise accepted.Refusal('unsafeBuildRoot')
    work=build_root/('host-'+str(uuid.uuid4()));work.mkdir(mode=0o700)
    print('Independent ENOSPC offline build: '+str(work),flush=True)
    class ExactBuilder(accepted.Builder):
        def unchanged(self):
            for source,item in self.inputs.items():
                if accepted.digest(source,item['exported'])!=item['sha256'] or accepted.digest(item['snapshot'])!=item['sha256']:
                    raise accepted.Refusal('inputChangedDuringOfflineBuild')
            selected={source.name for source in self.inputs if source.parent==accepted.CORE/'RealIntegrationCore'}
            if selected!={'Contract.swift','PrivateInput.swift'}:
                raise accepted.Refusal('exactCoreDependencyClosureChanged')
    b=ExactBuilder(work);b.record['taskID']='REAL-SFTP-DISKFULL-PREP-A'
    b.record['realIntegrationCoreClosure']=['Contract.swift','PrivateInput.swift']
    b.record['parallelCoreSourcesExcluded']='SFTPAuth*, Mina*, OpenSSH*, other unneeded source files'
    try:
        for path in [PARENT/'build_host.py',HERE/'build_host.py',HERE/'test_static.py',HERE/'management.py',HERE/'management_helper.py',HERE/'.gitignore',
                     ROOT/'Tests/IntegrationEnvironment/relay.py',ROOT/'Tests/IntegrationEnvironment/fixture.py',
                     accepted.FILES/'Package.swift',accepted.FILES/'native-inputs.json',ROOT/'Packages/OpenLXSSHTrust/Package.swift']:
            b.snapshot(path)
        manifest=json.loads(b.snapshot(accepted.NATIVE/'manifest.json').read_bytes())
        lock=json.loads((accepted.FILES/'native-inputs.json').read_bytes())
        if (manifest['dependencies']['toolchain']['deploymentTarget']!='15.0'
                or manifest['inputs']['lockSHA256']!=accepted.digest(accepted.FILES/'native-inputs.json')
                or any(manifest['dependencies'][key]!=lock[key] for key in ('libssh2','openssl'))):
            raise accepted.Refusal('nativeInputMismatch')
        for relative,expected in manifest['outputs'].items():
            if not relative.startswith('install/') or '..' in Path(relative).parts or accepted.digest(accepted.NATIVE/relative,True)!=expected:
                raise accepted.Refusal('nativeOutputMismatch')
            b.snapshot(accepted.NATIVE/relative,True)
        native=work/'inputs'/accepted.NATIVE.relative_to(ROOT)/'install'
        b.swiftc=b.run('locate-swiftc',['/usr/bin/xcrun','-f','swiftc']).decode().strip()
        b.clang=b.run('locate-clang',['/usr/bin/xcrun','-f','clang']).decode().strip()
        b.sdk=b.run('locate-sdk',['/usr/bin/xcrun','--show-sdk-path']).decode().strip()
        b.run('swift-version',[b.swiftc,'--version'])
        cobjects=b.c('COpenLXSSHFiles',accepted.FILES/'Sources/COpenLXSSHFiles',native/'include')
        cobjects+=b.c('RealIntegrationPOSIX',accepted.CORE/'RealIntegrationPOSIX')
        cobjects+=b.c('StressMetrics',ROOT/'Tests/LocalFileStress/Sources/StressMetrics')
        cobjects+=b.c('RemoteFileMetrics',PARENT/'POSIX')
        objects=[]
        for name,directory,package in [('OpenLXSSHTrust',ROOT/'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust','openlxsshtrust'),
            ('OpenLXSSHFiles',accepted.FILES/'Sources/OpenLXSSHFiles','openlxsshfiles')]:
            objects.append(b.swift(name,b.sources(directory),native/'include',package))
        objects.append(b.swift('RealIntegrationCore',[b.snapshot(accepted.CORE/'RealIntegrationCore'/name)
            for name in ('Contract.swift','PrivateInput.swift')],native/'include','realintegration'))
        management=b.inputs[HERE/'management.py']['snapshot']
        location=work/'BuildLocation.swift'
        location.write_text('enum BuildLocation { static let ownRoot = '+json.dumps(str(HERE))+
            '; static let fixtureRoot = '+json.dumps(str(ROOT/'Tests/IntegrationEnvironment'))+
            '; static let offlineRoot = '+json.dumps(str(work/'test-data'))+
            '; static let buildEvidence = '+json.dumps(str(work/'result.json'))+
            '; static let offlinePreparedAt = '+repr(time.time())+
            '; static let managementScript = '+json.dumps(str(management))+' }\n')
        shared=[b.snapshot(PARENT/name) for name in ('Core.swift','Observation.swift','Campaign.swift')]
        shared+=[b.snapshot(HERE/name) for name in ('DiskCore.swift','DiskManagement.swift','DiskCase.swift')]
        obj=b.swift('OpenLXSSHDiskFullCase',shared+[location,b.snapshot(HERE/'Main.swift')],native/'include')
        symbols=b.run('production-symbols',['/usr/bin/xcrun','nm','-u',obj])
        for required in (b'LibSSH2FileService',b'SafeTransferEngine',b'TransferManager'):
            if required not in symbols:raise accepted.Refusal('missingProductionAPI')
        archives=[native/'lib'/name for name in ('libssh2.a','libssl.a','libcrypto.a')]
        driver=b.link('OpenLXSSHDiskFullCase',[obj,*objects,*cobjects],archives)
        test_obj=b.swift('OpenLXSSHDiskFullOfflineTests',shared+[location,b.snapshot(HERE/'OfflineMain.swift')],native/'include')
        tests=b.link('OpenLXSSHDiskFullOfflineTests',[test_obj,*objects,*cobjects],archives)
        b.unchanged()
        b.run('static-tests',[sys.executable,'-B',HERE/'test_static.py'])
        b.run('offline-tests',[tests])
        b.run('cli-default',[driver]);b.run('cli-help',[driver,'--help'])
        b.run('cli-validate',[driver,'validate','--case','/not/opened/case.json'])
        b.run('cli-no-authorization',[driver,'--live','--case','/not/opened/case.json'],expected=2)
        b.run('cli-prepare-no-authorization',[driver,'prepare','--generation','/not/opened'],expected=2)
        b.unchanged()
        b.record.update(status='passed-offline-only-live-not-run',driver=str(driver),driverSHA256=accepted.digest(driver),
            nativeOutputsChecked=len(manifest['outputs']),architecture=accepted.macho(driver,2))
        print('Offline ENOSPC source/build checks passed; NO Docker, credentials, relay, remote files or actual ENOSPC.')
        print('Exact driver: '+str(driver));return 0
    except BaseException as error:
        b.record.update(status='failed-offline',failure=type(error).__name__)
        raise
    finally:b.save()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('help','validate','build'),nargs='?',default='help')
    args=parser.parse_args(argv)
    if args.action=='help':parser.print_help();return 0
    if args.action=='validate':print('Recipe syntax only; no files/subprocess/network.');return 0
    return build()


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:
        sys.stderr.write('Disk-full offline build failed: '+type(error).__name__+'. No private details.\n');sys.exit(2)
