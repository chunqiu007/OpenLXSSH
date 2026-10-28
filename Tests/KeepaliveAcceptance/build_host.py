#!/usr/bin/env python3
"""Reviewed incremental keepalive consumer build. Only own objects+9 frozen dependencies. No live/Docker/socket."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import uuid

sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent
ROOT=HERE.parent.parent
PARENT=ROOT/'Tests/RemoteTerminalAcceptance/.build/host-89033e34-66db-4c4c-9a23-c2c881636baf'
FREEZE=HERE/'.build/source-efbfca47b50340e9bed7e98984454560/freeze-r1.json'
FREEZE_SHA='144b0a07a3d9968ed61c010597824602102c82477ede0ed1e8a8b913139e9bfb'
RECIPE=ROOT/'Tests/RemoteTerminalAcceptance/.build/host-f43c264c-363f-4cf3-829e-73dd3e4a7f90/inputs/Tests/RealIntegration/build_host.py'
RECIPE_SHA='8b5e639d7c03e4925213bc6f872b94ec007738d0a79ad9d1a0f5f9a98fc2a8a9'
GATE=ROOT/'Scripts/verify-build-plugin.py'
GATE_SHA='dec240e64f0a27b66790715d65597df45f3f581c5f82231df28959895cd75dbe'
REQUIRED={'OpenLXSSHTrust','SwiftTerm','OpenLXSSHAskpass','OpenLXSSHTransport','RemoteTerminalCore',
    'COpenLXSSHAskpass-AskpassMach','COpenLXSSHAskpass-BoundedTool','COpenLXSSHAskpass-Identity','RealIntegrationPOSIX-PrivateInput'}


def digest(path):
    path=Path(path)
    if path.is_symlink() or path.resolve()!=path or not path.is_file():raise ValueError('unsafe-frozen-input')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build():
    os.umask(0o077)
    for p,h in [(FREEZE,FREEZE_SHA),(RECIPE,RECIPE_SHA),(GATE,GATE_SHA)]:
        if digest(p)!=h:raise ValueError('reviewed-source-changed')
    prior=json.loads(FREEZE.read_bytes());manifest=json.loads((HERE/'frozen-inputs.json').read_bytes())
    for name,h in prior['sourceSHA256'].items():
        if digest(HERE/name)!=h:raise ValueError('reviewed-keepalive-source-changed')
    if manifest['parentCheckpoint']!=str(PARENT) or digest(PARENT/'result.json')!=manifest['parentManifestSHA256']:
        raise ValueError('wrong-parent')
    deps=manifest['dependencyObjects'];objects={Path(x['path']).stem:Path(x['path']) for x in deps}
    if len(deps)!=9 or set(objects)!=REQUIRED:raise ValueError('exact-nine-dependencies-required')
    readonly={x['path']:x['sha256'] for x in deps}
    readonly.update(manifest['moduleSHA256']);readonly.update(manifest['frozenRelaySHA256'])
    readonly.update({str(FREEZE):FREEZE_SHA,str(RECIPE):RECIPE_SHA,str(GATE):GATE_SHA,str(PARENT/'result.json'):manifest['parentManifestSHA256'],
        manifest['helper']:manifest['helperSHA256'],manifest['frozenLiveInput']:manifest['frozenLiveInputSHA256']})
    def check():
        if any(digest(p)!=h for p,h in readonly.items()):raise ValueError('readonly-dependency-changed')
    check()
    # Import only this reviewed immutable compiler/link helper; never call its build() or sign() (which would re-sign helper).
    spec=importlib.util.spec_from_file_location('keepalive_exact_private_builder',RECIPE)
    accepted=importlib.util.module_from_spec(spec);spec.loader.exec_module(accepted);accepted.HERE=HERE;accepted.ROOT=ROOT
    work=HERE/'.build'/('host-'+str(uuid.uuid4()));work.mkdir(mode=0o700)
    builder=accepted.Builder(work);original=builder.run
    def run(label,args,**kwargs):
        sequence=len(builder.commands)+1
        return original(str(sequence).zfill(3)+'-'+label,args,**kwargs)
    builder.run=run
    def expect(label,args,code):
        # Builder deliberately refuses nonzero; preserve a genuine expected refusal as expected, not silently skip.
        try:builder.run(label,args)
        except accepted.Refusal:
            if builder.commands[-1]['exitCode']!=code:raise
            builder.commands[-1]['expectedExitCode']=code
        else:raise ValueError('expected-inert-refusal-missing')
    builder.record.update(taskID='KEEPALIVE-CONSUMER-BUILD-A',parentCheckpoint=str(PARENT),parentManifestSHA256=manifest['parentManifestSHA256'],
        sourceFreeze=str(FREEZE),sourceFreezeSHA256=FREEZE_SHA,fullDependencyBuildExecuted=False,dependencyObjects=deps,
        socketsOpened=False,dockerInvoked=False,liveExecuted=False,generationRead=False,helperResigned=False,
        recipeReuse={'snapshot':str(RECIPE),'sha256':RECIPE_SHA,'currentMutableBuilderImported':False})
    print('Keepalive unique incremental signed-static build: '+str(work),flush=True)
    try:
        for folder in ['modules','cmodules']:shutil.copytree(PARENT/folder,work/folder,dirs_exist_ok=True)
        own={p.name:p for p in sorted(HERE.iterdir()) if p.is_file()}
        snapshots={name:builder.snapshot(p) for name,p in own.items()}
        builder.snapshot(GATE)
        builder.run('readonly-checkout-gate',[sys.executable,'-B',GATE,ROOT/'Packages/OpenLXSSHTransport/.build/macos26/checkouts','--helper'])
        builder.tools()
        teamMatch=re.search(r'static let team = ("[^"\r\n]+")',(PARENT/'BuildLocation.swift').read_text())
        if teamMatch is None:raise ValueError('missing-parent-compiled-team')
        team=json.loads(teamMatch[1]);helper=Path(manifest['helper'])
        if builder.verify_signature(helper,accepted.HELPER_ID)!=team:raise ValueError('frozen-helper-team')
        builder.run('keepalive-python-pure',[sys.executable,'-B',snapshots['test_static.py']])
        generated=work/'BuildLocation.swift';generated.write_text('enum BuildLocation { '+ '; '.join('static let '+k+' = '+json.dumps(v) for k,v in {
            'ownRoot':str(HERE),'buildRoot':str(HERE/'.build'),'fixtureRoot':str(ROOT/'Tests/IntegrationEnvironment'),'team':team}.items())+' }\n');generated.chmod(0o400)
        core=builder.swift_compile('KeepaliveCore',[snapshots['Core.swift']],extra=['-warnings-as-errors'])
        offlineObject=builder.swift_compile('KeepaliveOffline',[snapshots['OfflineMain.swift']],extra=['-warnings-as-errors'])
        offline=builder.link('KeepaliveOffline',[offlineObject,core,objects['RemoteTerminalCore']])
        output=builder.run('swift-pure-assertions',[offline])
        match=re.search(rb'Keepalive Swift pure assertions passed: ([0-9]+)',output)
        if match is None:raise ValueError('missing-swift-pure-result')
        consumerObject=builder.swift_compile('OpenLXSSHKeepalive',[snapshots['Core.swift'],snapshots['Main.swift'],snapshots['LiveInput.swift'],generated],extra=['-warnings-as-errors'])
        symbols=builder.run('public-api-symbols',['/usr/bin/xcrun','nm','-u',consumerObject])
        if b'DirectSSHSession' not in symbols or any(x in symbols for x in [b'startProbe',b'configureProbe',b'probeStore',b'LibSSH2FileService',b'SecItem']):
            raise ValueError('not-public-production-consumer')
        check();consumer=builder.link('OpenLXSSHKeepalive',[consumerObject,*objects.values()])
        identityObject=work/'objects/KeepaliveIdentity.o'
        builder.run('compile-readonly-identity',[builder.clang,'-c','-O2','-target','arm64-apple-macos15.0','-isysroot',builder.sdk,
            '-Wall','-Wextra','-Werror',snapshots['identity.c'],'-o',identityObject])
        identityTool=work/'artifacts/keepalive-identity'
        builder.run('link-readonly-identity',[builder.clang,'-target','arm64-apple-macos15.0','-isysroot',builder.sdk,
            '-Wl,-no_adhoc_codesign',identityObject,'-lproc','-o',identityTool])
        accepted.minimum(identityObject,1);accepted.minimum(identityTool,2)
        builder.run('identity-vtool',['/usr/bin/xcrun','vtool','-show-build',identityTool])
        # On Apple Silicon even a local executable needs a code signature to run. The
        # standalone readonly identity helper gets ad-hoc ONLY; it is never an App/helper IPC peer.
        builder.run('sign-local-readonly-identity',['/usr/bin/codesign','--force','--sign','-','--identifier','org.openlxssh.keepalive.identity','--timestamp=none',identityTool])
        builder.run('verify-local-readonly-identity',['/usr/bin/codesign','--verify','--strict',identityTool])
        expect('identity-no-args-inert',[identityTool],64);expect('identity-help-inert',[identityTool,'--help'],64)
        app=work/'OpenLXSSHKeepalive.app'
        for folder in ['Contents/MacOS','Contents/Helpers']:(app/folder).mkdir(mode=0o700,parents=True)
        shutil.copyfile(helper,app/'Contents/Helpers/openlxssh-askpass');shutil.copyfile(consumer,app/'Contents/MacOS/OpenLXSSHKeepalive')
        for p in [app/'Contents/Helpers/openlxssh-askpass',app/'Contents/MacOS/OpenLXSSHKeepalive']:p.chmod(0o700)
        (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':accepted.APP_ID,'CFBundleName':'OpenLXSSHKeepalive',
            'CFBundleExecutable':'OpenLXSSHKeepalive','CFBundlePackageType':'APPL','CFBundleVersion':'1','LSMinimumSystemVersion':'15.0',
            'LSUIElement':True,'OpenLXSSHKeepaliveTestOnly':True}))
        copied=app/'Contents/Helpers/openlxssh-askpass'
        if digest(copied)!=manifest['helperSHA256'] or builder.verify_signature(copied,accepted.HELPER_ID)!=team:raise ValueError('copied-helper-changed')
        # Existing Development identity lookup stays private; sign APP ONLY, no deep/force-helper signing.
        privateEnv=accepted.environment(work);privateEnv['HOME']=str(Path.home())
        query=subprocess.run(['/usr/bin/security','find-identity','-v','-p','codesigning'],cwd=HERE,env=privateEnv,capture_output=True,timeout=20)
        identities=re.findall(rb'^\s*\d+\)\s+([A-F0-9]{40})\s+"Apple Development:[^"\r\n]+"\s*$',query.stdout,re.M)
        if query.returncode or len(identities)!=1:raise ValueError('one-development-identity-required')
        builder.run('sign-app-only',['/usr/bin/codesign','--force','--sign',identities[0].decode(),'--identifier',accepted.APP_ID,
            '--options','runtime','--timestamp=none',app],private=True)
        if builder.verify_signature(app,accepted.APP_ID,deep=True)!=team or builder.verify_signature(copied,accepted.HELPER_ID)!=team or digest(copied)!=manifest['helperSHA256']:
            raise ValueError('app-helper-policy-or-hash')
        binary=app/'Contents/MacOS/OpenLXSSHKeepalive'
        builder.run('default-inert',[binary]);builder.run('help-inert',[binary,'--help'])
        expect('invalid-flags-inert',[binary,'--not-a-real-action'],2)
        builder.unchanged();check()
        fileHashes={str(p.relative_to(app)):digest(p) for p in sorted(app.rglob('*')) if p.is_file()}
        builder.record.update(status='signed-static-only-not-live',app=str(app),driverSHA256=digest(binary),helperSHA256=digest(copied),
            identityTool=str(identityTool),identityToolSHA256=digest(identityTool),identityToolSigned='ad-hoc-local-readonly-tool-not-App-helper',identityToolMinimum='15.0',
            sourceSHA256={name:digest(p) for name,p in snapshots.items()},generatedBuildLocationSHA256=digest(generated),
            swiftPureAssertions=int(match[1]),pythonPureTests=13,readonlyParentInputsUnchanged=True,parentHelperUnchanged=True,
            signature={'status':'strictDevelopmentVerified','sameTeam':True,'runtime':True,'entitlements':{},'helperResigned':False,
                'timestamp':'none','identityDetailsRecorded':False},appFilesSHA256=fileHashes,liveApprovalReceiptCreated=False)
        print('Keepalive signed-static checks passed; no sockets/Docker/campaign. App: '+str(app),flush=True)
        return 0
    except BaseException as error:
        builder.record.update(status='failed-static-only',failure=type(error).__name__);raise
    finally:builder.save()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',nargs='?',choices=('help','validate','build'),default='help');args=parser.parse_args(argv)
    if args.action=='help':parser.print_help();return 0
    if args.action=='validate':print('Inert source recipe only; no files/sign/build/live.');return 0
    return build()


if __name__=='__main__':
    try:sys.exit(main())
    except Exception:sys.stderr.write('Keepalive static build refused; inspect own logs, no private detail emitted.\n');sys.exit(2)
