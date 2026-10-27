#!/usr/bin/env python3
"""Exact frozen htop consumer incremental build/sign. No dependency build or live operation."""
import argparse
import base64
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

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
PARENT = ROOT / 'Tests/RemoteTerminalAcceptance/.build/host-89033e34-66db-4c4c-9a23-c2c881636baf'
SOURCE_FREEZE = HERE / '.build/source-6af38c5f-2332-4025-9dfc-73765651280b/freeze.json'
SOURCE_FREEZE_SHA = 'cfeecfafddaf073cc1df4e46299c5748683e33d8775632c22b31234ac767370f'
MANIFEST_SHA = 'f9d8329a8ae38793dbfd0533ebeb1e802f336293073601286f54633146fadba0'
PARENT_MANIFEST_SHA = 'b2c3ea6e0862790eb47fdefd85705fd316b755550f97239cc05ca75d0d0eceb6'
PROBE_SHA = '4c78fd40f9ab1d4c8b92237d8bbc27369d18fe76da37b5ad54022a3b5fcce7eb'
RECIPE = ROOT / 'Tests/RemoteTerminalAcceptance/.build/host-f43c264c-363f-4cf3-829e-73dd3e4a7f90/inputs/Tests/RealIntegration/build_host.py'
RECIPE_SHA = '8b5e639d7c03e4925213bc6f872b94ec007738d0a79ad9d1a0f5f9a98fc2a8a9'
GATE = ROOT / 'Scripts/verify-build-plugin.py'
GATE_SHA = 'dec240e64f0a27b66790715d65597df45f3f581c5f82231df28959895cd75dbe'
REQUIRED = {'OpenLXSSHTrust', 'SwiftTerm', 'OpenLXSSHAskpass', 'OpenLXSSHTransport', 'RemoteTerminalCore',
            'COpenLXSSHAskpass-AskpassMach', 'COpenLXSSHAskpass-BoundedTool', 'COpenLXSSHAskpass-Identity', 'RealIntegrationPOSIX-PrivateInput'}
FROZEN_CINPUTS = {
    PARENT / 'cmodules/COpenLXSSHAskpass/module.modulemap': 'f12f9e77f544327762110d07af6f37cc354bb1b7049a3580eb9ec64012aaecae',
    PARENT / 'cmodules/RealIntegrationPOSIX/module.modulemap': '1d03954ebc0375cdcdd696c9977566341a48770fa262bde0e813e699517f43e2',
    RECIPE.parents[2] / 'Packages/OpenLXSSHTransport/Sources/COpenLXSSHAskpass/include/COpenLXSSHAskpass.h': 'ad040dd308dc108f2d5667649f7af4c25d6de8cf9d93cfc86dbf1d72a0596bf8',
    RECIPE.parents[2] / 'Tests/RealIntegration/Sources/RealIntegrationPOSIX/include/RealIntegrationPOSIX.h': 'ed80cbb104b0d0e6b45261e68a543b0914516008cebce3304669b7ce25254c85',
}


def digest(path):
    path = Path(path)
    if path.is_symlink() or path.resolve() != path or not path.is_file(): raise ValueError('unsafe frozen input')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build():
    os.umask(0o077)
    for path, expected in ((SOURCE_FREEZE, SOURCE_FREEZE_SHA), (HERE / 'frozen-inputs.json', MANIFEST_SHA),
                           (PARENT / 'result.json', PARENT_MANIFEST_SHA), (RECIPE, RECIPE_SHA), (GATE, GATE_SHA)):
        if digest(path) != expected: raise ValueError('reviewed gate changed')
    approved = json.loads(SOURCE_FREEZE.read_text())['sourceSHA256']
    for name, expected in approved.items():
        if digest(HERE / name) != expected: raise ValueError('reviewed htop source changed')
    manifest = json.loads((HERE / 'frozen-inputs.json').read_text())
    if manifest['parentCheckpoint'] != str(PARENT) or manifest['parentManifestSHA256'] != PARENT_MANIFEST_SHA: raise ValueError('wrong parent checkpoint')
    dependencies = manifest['dependencyObjects']
    objects = {Path(item['path']).stem: Path(item['path']) for item in dependencies}
    if len(dependencies) != 9 or set(objects) != REQUIRED: raise ValueError('exact nine dependency objects required')
    readonly = {Path(item['path']): item['sha256'] for item in dependencies}
    readonly.update({Path(path): expected for path, expected in manifest['moduleSHA256'].items()})
    readonly.update(FROZEN_CINPUTS)
    readonly.update({SOURCE_FREEZE: SOURCE_FREEZE_SHA, PARENT / 'result.json': PARENT_MANIFEST_SHA, RECIPE: RECIPE_SHA, GATE: GATE_SHA,
                    PARENT / 'BuildLocation.swift': '7b315d983024b566ba7410f0adcf7355351c9241ac5750ab9f8b384b6f521add'})
    helper = PARENT / 'OpenLXSSHRemoteTerminal.app/Contents/Helpers/openlxssh-askpass'
    readonly[helper] = 'b7d48e6a209c256c54b603247f5ed406b536daacd6e9525d6f9d59330e426f4e'
    for item in manifest['reviewedConsumerSources']: readonly[Path(item['snapshot'])] = item['sha256']
    for path, expected in readonly.items():
        if digest(path) != expected: raise ValueError('readonly dependency changed')
    spec = importlib.util.spec_from_file_location('htop_frozen_private_builder', RECIPE)
    accepted = importlib.util.module_from_spec(spec); spec.loader.exec_module(accepted)
    # The reviewed private module is imported only for compiler/link/sign owners; never its build().
    accepted.HERE = HERE; accepted.ROOT = ROOT
    if accepted.GATE_SHA256 != GATE_SHA: raise ValueError('private recipe gate differs')
    work = HERE / '.build' / ('host-' + str(uuid.uuid4())); work.mkdir(mode=0o700)
    builder = accepted.Builder(work)
    original_run = builder.run
    def exclusive_run(label, argv, **kwargs):
        sequence = len(builder.commands) + 1
        numbered = str(sequence).zfill(3) + '-' + label
        if (work / 'logs' / (numbered + '.log')).exists(): raise ValueError('command output already exists')
        return original_run(numbered, argv, **kwargs)
    builder.run = exclusive_run
    builder.record.update(taskID='HTOP-CONSUMER-BUILD-A', parentCheckpoint=str(PARENT), parentManifestSHA256=PARENT_MANIFEST_SHA,
        frozenSourceManifest=str(SOURCE_FREEZE), frozenSourceManifestSHA256=SOURCE_FREEZE_SHA,
        generationRead=False, socketsOpened=False, dockerInvoked=False, liveExecuted=False, fullDependencyBuildExecuted=False,
        dependencyObjects=dependencies, recipeReuse={'snapshot': str(RECIPE), 'sha256': RECIPE_SHA, 'currentRecipeImported': False})
    print('Unique offline htop consumer build: ' + str(work), flush=True)
    try:
        for folder in ('modules', 'cmodules'): shutil.copytree(PARENT / folder, work / folder, dirs_exist_ok=True)
        snapshots = {name: builder.snapshot(HERE / name) for name in (*approved.keys(), 'build_host.py')}
        snapshot_root = snapshots['Core.swift'].parent; (snapshot_root / '.build').mkdir(mode=0o700)
        builder.snapshot(GATE)
        location = (PARENT / 'BuildLocation.swift').read_text()
        match = re.search(r'static let team = ("[^"\r\n]+")', location)
        if match is None: raise ValueError('compiled Team missing')
        team = json.loads(match[1]); encoded = base64.b64encode(snapshots['remote_probe.py'].read_bytes()).decode()
        if digest(snapshots['remote_probe.py']) != PROBE_SHA or len(snapshots['remote_probe.py'].read_bytes()) > 32768: raise ValueError('probe snapshot mismatch')
        generated = work / 'BuildLocation.swift'
        constants = {'ownRoot': str(HERE), 'buildRoot': str(HERE / '.build'), 'fixtureRoot': str(ROOT / 'Tests/IntegrationEnvironment'),
                     'team': team, 'probeBase64': encoded, 'probeSHA256': PROBE_SHA}
        generated.write_text('enum BuildLocation { ' + '; '.join('static let ' + name + ' = ' + json.dumps(value) for name, value in constants.items()) + ' }\n')
        generated.chmod(0o400); generated_hash = digest(generated)
        if builder.verify_signature(helper, accepted.HELPER_ID) != team: raise ValueError('parent helper Team mismatch')
        builder.tools()
        core = builder.swift_compile('HTOPCore', [snapshots['Core.swift']], extra=['-warnings-as-errors'])
        offline_object = builder.swift_compile('HTOPOffline', [snapshots['OfflineMain.swift']], extra=['-warnings-as-errors'])
        offline = builder.link('HTOPOffline', [offline_object, core, objects['RemoteTerminalCore']])
        output = builder.run('htop-pure-core-tests', [offline])
        if b'HTOP pure core checks passed:' not in output: raise ValueError('offline check output missing')
        builder.run('htop-pure-source-typecheck-tests', [sys.executable, '-B', snapshots['test_static.py']])
        consumer_object = builder.swift_compile('OpenLXSSHHTOP', [snapshots['Main.swift'], snapshots['LiveInput.swift'], snapshots['StatusQuery.swift'], generated], extra=['-warnings-as-errors'])
        symbols = builder.run('public-api-symbols', ['/usr/bin/xcrun', 'nm', '-u', consumer_object])
        if b'DirectSSHSession' not in symbols or any(value in symbols for value in (b'startProbe', b'configureProbe', b'probeStore', b'LibSSH2FileService')): raise ValueError('not sole public production API')
        for item in dependencies:
            if digest(item['path']) != item['sha256']: raise ValueError('dependency changed before link')
        consumer = builder.link('OpenLXSSHHTOP', [consumer_object, core, *objects.values()])
        def embeds_probe(path):
            data = path.read_bytes()
            return encoded.encode() in data and PROBE_SHA.encode() in data
        if not embeds_probe(consumer): raise ValueError('new probe not embedded')
        app = work / 'OpenLXSSHHTOP.app'
        for folder in ('Contents/MacOS', 'Contents/Helpers'): (app / folder).mkdir(mode=0o700, parents=True)
        shutil.copyfile(helper, app / 'Contents/Helpers/openlxssh-askpass'); shutil.copyfile(consumer, app / 'Contents/MacOS/OpenLXSSHHTOP')
        for path in (app / 'Contents/Helpers/openlxssh-askpass', app / 'Contents/MacOS/OpenLXSSHHTOP'): path.chmod(0o700)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': accepted.APP_ID, 'CFBundleName': 'OpenLXSSHHTOP',
            'CFBundleExecutable': 'OpenLXSSHHTOP', 'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'LSMinimumSystemVersion': '15.0',
            'LSUIElement': True, 'OpenLXSSHHTOPTestOnly': True}))
        builder.sign(app)
        if builder.verify_signature(app, accepted.APP_ID, deep=True) != team or not embeds_probe(app / 'Contents/MacOS/OpenLXSSHHTOP'): raise ValueError('signed Team or probe mismatch')
        builder.run('default-inert', [app / 'Contents/MacOS/OpenLXSSHHTOP'])
        builder.run('validate-inert', [app / 'Contents/MacOS/OpenLXSSHHTOP', 'validate', '--contract', '/not/opened/remote-terminal.json'])
        builder.unchanged()
        if digest(generated) != generated_hash or any(digest(path) != expected for path, expected in readonly.items()): raise ValueError('readonly source changed during build')
        builder.record.update(status='signed-static-only-not-run', app=str(app), driverSHA256=digest(app / 'Contents/MacOS/OpenLXSSHHTOP'),
            helperSHA256=digest(app / 'Contents/Helpers/openlxssh-askpass'), parentHelperUnchanged=True, remoteProbeSHA256=PROBE_SHA,
            generatedBuildLocationSHA256=generated_hash, embeddedProbeVerified=True, compiledTeamMatchesSignature=True,
            readonlyParentInputsUnchanged=True, sourceSHA256={name: digest(snapshot) for name, snapshot in snapshots.items()},
            pixelsVerified=False, internalStateVerified=False, htopInteractiveTested=False)
        print('HTOP consumer signed; pure checks passed; no interactive/network operation.')
        print('Exact App: ' + str(app))
        return 0
    except BaseException as error:
        builder.record.update(status='failed-static-only', failure=type(error).__name__); raise
    finally:
        builder.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=('help', 'validate', 'build'))
    args = parser.parse_args(argv)
    if args.action == 'help': parser.print_help(); return 0
    if args.action == 'validate': print('Inert recipe syntax only; no build/sign/live.'); return 0
    return build()

if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error: sys.stderr.write('HTOP static build refused: ' + type(error).__name__ + '\n'); sys.exit(2)
