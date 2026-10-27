#!/usr/bin/env python3
"""Exact 5e8f incremental size/Vim synchronization build/sign; no dependency build or live operations."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
PARENT = HERE / '.build/host-5e8f715f-bccb-4458-93c6-5560a0751a7e'
PARENT_MANIFEST_SHA256 = 'ad20ca50a18b5e16f5a303aaf251d658834bdbc7f509d26eb3b77a716defbbb7'
LOCATION_SHA256 = 'ad10142cf1076b8980ca3882d2220d0caac8610160bba64a562821e0c63a4fb5'
RECIPE_SHA256 = '8b5e639d7c03e4925213bc6f872b94ec007738d0a79ad9d1a0f5f9a98fc2a8a9'
APPROVED = {
    'Core.swift': '2e9a75d09add80142bbf75e89d1d23c7942d925e79109a8dc5df69393a2de953',
    'Main.swift': '6e5acbdac1f193f613e79ff072acd251b60f77c119f53cb56ba77010972d4255',
    'remote_probe.py': 'a21f1e2931b873d75274da3e86b8723513d6ee7bc852dff1a9ca93e2a47f4391',
    'OfflineMain.swift': '8e1d75d13a75fe7fd7a6836cbe448eb8a0f736cc8bdd251bc59e14ab50519e8e',
    'test_static.py': '7e1f362208a9b6dea32243f052da9c5ea0ea973d3437a3fba17f6a4becd883cf',
}
REQUIRED = ('OpenLXSSHTrust', 'SwiftTerm', 'OpenLXSSHAskpass', 'OpenLXSSHTransport',
            'COpenLXSSHAskpass-AskpassMach', 'COpenLXSSHAskpass-BoundedTool',
            'COpenLXSSHAskpass-Identity', 'RealIntegrationPOSIX-PrivateInput')


def digest(path):
    path = Path(path)
    if path.is_symlink() or path.resolve() != path or not path.is_file():
        raise ValueError('unsafe checkpoint input')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resume(parent):
    os.umask(0o077)
    parent = Path(parent)
    if parent != PARENT or parent.resolve() != parent or digest(parent / 'result.json') != PARENT_MANIFEST_SHA256:
        raise ValueError('exact reviewed 5e8f checkpoint required')
    prior = json.loads((parent / 'result.json').read_text())
    for item in prior['inputs']:
        source, snapshot = Path(item['path']), Path(item['snapshot'])
        if digest(snapshot) != item['sha256']:
            raise ValueError('parent snapshot changed')
        if source.name != 'resume_consumer.py' and digest(source) != APPROVED.get(source.name, item['sha256']):
            raise ValueError('unapproved terminal source change')
    dependencies = prior['dependencyObjects']
    objects = {Path(item['path']).stem: item for item in dependencies}
    if len(dependencies) != 8 or set(objects) != set(REQUIRED):
        raise ValueError('exact eight dependency objects required')
    for item in dependencies + prior['objects']:
        if digest(item['path']) != item['sha256']:
            raise ValueError('parent object changed')
    readonly = {Path(item['path']): item['sha256'] for item in dependencies + prior['objects']}
    readonly[parent / 'result.json'] = PARENT_MANIFEST_SHA256
    readonly[parent / 'BuildLocation.swift'] = LOCATION_SHA256
    for folder in ('modules', 'cmodules'):
        for path in (parent / folder).rglob('*'):
            if path.is_symlink():
                raise ValueError('module alias refused')
            if path.is_file():
                readonly[path] = digest(path)
    recipe_snapshot = HERE / '.build/host-f43c264c-363f-4cf3-829e-73dd3e4a7f90/inputs/Tests/RealIntegration/build_host.py'
    if prior['recipeReuse']['snapshot'] != str(recipe_snapshot) or digest(recipe_snapshot) != RECIPE_SHA256:
        raise ValueError('reviewed private recipe mismatch')
    readonly[recipe_snapshot] = RECIPE_SHA256
    spec = importlib.util.spec_from_file_location('terminal_vim_diag_private_builder', recipe_snapshot)
    accepted = importlib.util.module_from_spec(spec); spec.loader.exec_module(accepted)
    rebound = {'HERE': HERE, 'ROOT': ROOT, 'BUILD': HERE / '.build', 'TRANSPORT': ROOT / 'Packages/OpenLXSSHTransport',
               'FILES': ROOT / 'Packages/OpenLXSSHFiles', 'NATIVE': ROOT / 'Packages/OpenLXSSHFiles/.build/native',
               'CHECKOUTS': ROOT / 'Packages/OpenLXSSHTransport/.build/macos26/checkouts', 'GATE': ROOT / 'Scripts/verify-build-plugin.py'}
    for name, path in rebound.items():
        setattr(accepted, name, path)
    if accepted.GATE_SHA256 != 'dec240e64f0a27b66790715d65597df45f3f581c5f82231df28959895cd75dbe' or accepted.sha(accepted.GATE) != accepted.GATE_SHA256:
        raise ValueError('original reviewed plugin gate changed')
    work = HERE / '.build' / ('host-' + str(uuid.uuid4())); work.mkdir(mode=0o700)
    builder = accepted.Builder(work)
    builder.record.update(taskID='TERMINAL-SIZE-VIM-SYNC-R2', parentCheckpoint=str(parent),
                          parentManifestSHA256=PARENT_MANIFEST_SHA256, dockerInvoked=False, liveExecuted=False,
                          generationRead=False, socketsOpened=False, reusedDependencyObjects=True,
                          recipeReuse={'snapshot': str(recipe_snapshot), 'sha256': RECIPE_SHA256, 'currentSourceImported': False},
                          dependencyObjects=dependencies)
    print('Unique offline Vim diagnostic incremental snapshot: ' + str(work), flush=True)
    try:
        for folder in ('modules', 'cmodules'):
            shutil.copytree(parent / folder, work / folder, dirs_exist_ok=True)
        names = ('.gitignore', 'Core.swift', 'LiveInput.swift', 'Main.swift', 'OfflineMain.swift',
                 'remote_probe.py', 'test_static.py', 'build_host.py', 'resume_consumer.py')
        snapshots = {name: builder.snapshot(HERE / name) for name in names}
        snapshot_root = snapshots['Core.swift'].parent
        (snapshot_root / '.build').mkdir(mode=0o700)
        builder.snapshot(accepted.GATE)
        source = snapshots['remote_probe.py'].read_bytes()
        source_hash = accepted.sha(snapshots['remote_probe.py'])
        if source_hash != APPROVED['remote_probe.py'] or len(source) > 32768:
            raise ValueError('approved probe snapshot mismatch')
        if digest(parent / 'BuildLocation.swift') != LOCATION_SHA256:
            raise ValueError('parent BuildLocation changed')
        location = (parent / 'BuildLocation.swift').read_text()
        def literal(name):
            matches = re.findall(r'static let ' + name + r' = ("[^"\r\n]*")', location)
            if len(matches) != 1:
                raise ValueError('BuildLocation literal mismatch')
            return json.loads(matches[0])
        old_encoded, old_hash, team = literal('probeBase64'), literal('probeSHA256'), literal('team')
        if hashlib.sha256(base64.b64decode(old_encoded, validate=True)).hexdigest() != old_hash or old_hash != prior['remoteProbeSHA256']:
            raise ValueError('parent embedded probe mismatch')
        encoded = base64.b64encode(source).decode()
        for name, value in (('probeBase64', encoded), ('probeSHA256', source_hash)):
            location, count = re.subn(r'(static let ' + name + r' = )"[^"\r\n]*"', lambda match: match[1] + json.dumps(value), location)
            if count != 1:
                raise ValueError('generated probe literal mismatch')
        generated = work / 'BuildLocation.swift'
        generated.write_text(location); generated.chmod(0o400)
        generated_hash = accepted.sha(generated)
        helper_source = parent / 'OpenLXSSHRemoteTerminal.app/Contents/Helpers/openlxssh-askpass'
        plist_source = parent / 'OpenLXSSHRemoteTerminal.app/Contents/Info.plist'
        if accepted.sha(helper_source) != prior['helperSHA256'] or digest(plist_source) != '2c66c1857564672093ece3bf6a2b430723af942f447560868d61872205594092':
            raise ValueError('parent helper or bundle metadata changed')
        readonly[helper_source] = prior['helperSHA256']
        readonly[plist_source] = digest(plist_source)
        if builder.verify_signature(helper_source, accepted.HELPER_ID) != team:
            raise ValueError('parent helper Team mismatch')
        builder.tools()
        core = builder.swift_compile('RemoteTerminalCore', [snapshots['Core.swift']], extra=['-warnings-as-errors'])
        test_object = builder.swift_compile('RemoteTerminalOffline', [snapshots['OfflineMain.swift']], extra=['-warnings-as-errors'])
        tests = builder.link('RemoteTerminalOffline', [test_object, core])
        baseline = builder.run('vim-diag-offline-core-tests', [tests])
        if b'original 128-check baseline passed;' not in baseline or b'original128 retained;' not in baseline:
            raise ValueError('original 128-check baseline missing')
        builder.run('vim-diag-offline-python-tests', [sys.executable, '-B', snapshots['test_static.py']])
        consumer_object = builder.swift_compile('OpenLXSSHRemoteTerminal',
            [snapshots['Main.swift'], snapshots['LiveInput.swift'], generated], extra=['-warnings-as-errors'])
        symbols = builder.run('vim-diag-public-api-symbols', ['/usr/bin/xcrun', 'nm', '-u', consumer_object])
        if b'DirectSSHSession' not in symbols or any(value in symbols for value in (b'startProbe', b'configureProbe', b'probeStore', b'LibSSH2FileService')):
            raise ValueError('not sole public production outer API')
        for item in dependencies:
            if accepted.sha(item['path']) != item['sha256']:
                raise ValueError('dependency changed before link')
        consumer = builder.link('OpenLXSSHRemoteTerminal', [consumer_object, core] + [Path(objects[name]['path']) for name in REQUIRED])
        def embedded_probe_matches(binary):
            data = binary.read_bytes()
            return encoded.encode() in data and source_hash.encode() in data and old_encoded.encode() not in data
        if not embedded_probe_matches(consumer):
            raise ValueError('linked consumer does not contain approved new probe')
        app = work / 'OpenLXSSHRemoteTerminal.app'
        for name in ('Contents/MacOS', 'Contents/Helpers'):
            (app / name).mkdir(mode=0o700, parents=True)
        shutil.copyfile(helper_source, app / 'Contents/Helpers/openlxssh-askpass')
        shutil.copyfile(consumer, app / 'Contents/MacOS/OpenLXSSHRemoteTerminal')
        for binary in (app / 'Contents/Helpers/openlxssh-askpass', app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'):
            binary.chmod(0o700)
        shutil.copyfile(plist_source, app / 'Contents/Info.plist')
        builder.sign(app)
        if builder.verify_signature(app, accepted.APP_ID, deep=True) != team:
            raise ValueError('signed bundle Team differs from compiled Team')
        if not embedded_probe_matches(app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'):
            raise ValueError('signed consumer embedded probe mismatch')
        builder.run('vim-diag-default-inert', [app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'])
        builder.run('vim-diag-validate-inert', [app / 'Contents/MacOS/OpenLXSSHRemoteTerminal', 'validate', '--contract', '/not/opened/remote-terminal.json'])
        builder.unchanged()
        if accepted.sha(generated) != generated_hash or any(digest(path) != expected for path, expected in readonly.items()):
            raise ValueError('readonly parent or generated input changed during build')
        builder.record.update(status='signed-static-only-not-run', app=str(app),
            driverSHA256=accepted.sha(app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'),
            helperSHA256=accepted.sha(app / 'Contents/Helpers/openlxssh-askpass'), remoteProbeSHA256=source_hash,
            sourceSHA256={name: accepted.sha(snapshot) for name, snapshot in snapshots.items()},
            generatedBuildLocationSHA256=generated_hash, embeddedProbeVerified=True, original128ChecksPassed=True,
            readonlyParentInputsUnchanged=True, fullDependencyBuildExecuted=False, compiledTeamMatchesSignature=True)
        print('Core/128-check baseline/pure tests/consumer compile/link/strict same-Team Runtime empty-entitlement signing passed; no live.')
        print('Exact diagnostic App: ' + str(app))
        return 0
    except BaseException as error:
        builder.record.update(status='failed-vim-diag-static', failure=type(error).__name__)
        raise
    finally:
        builder.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('checkpoint', type=Path)
    return resume(parser.parse_args().checkpoint)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.stderr.write('Vim diagnostic incremental build refused: ' + type(error).__name__ + '\n')
        sys.exit(2)
