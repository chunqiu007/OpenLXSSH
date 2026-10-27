#!/usr/bin/env python3
"""Own exact snapshot incremental retries; never overwrite a prior label/artifact."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent


def resume(parent):
    os.umask(0o077)
    parent = Path(parent)
    if parent.parent != HERE / '.build' or parent.resolve() != parent or parent.name != 'host-f43c264c-363f-4cf3-829e-73dd3e4a7f90':
        raise ValueError('exact reviewed dependency checkpoint required')
    reviewed_r1 = HERE / '.build/host-e2177fe4-f587-4f29-b710-7cd3278460c3'
    r1 = json.loads((reviewed_r1 / 'result.json').read_text())
    for name in ('LiveInput.swift', 'remote_probe.py', 'build_host.py', '.gitignore'):
        item = next(item for item in r1['inputs'] if Path(item['path']).name == name)
        if hashlib.sha256((HERE / name).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('unchanged runtime gate or probe changed')
    prior = json.loads((parent / 'result.json').read_text())
    objects = {Path(item['path']).stem: item for item in prior['objects']}
    for item in prior['objects']:
        if hashlib.sha256(Path(item['path']).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('dependency object changed')
    recipe_path = ROOT / 'Tests/RealIntegration/build_host.py'
    recipe_item = next(item for item in prior['inputs'] if item['path'] == str(recipe_path))
    known_parallel_changes = []
    # Preserve every snapshot/object gate. Only the explicitly coordinated shared
    # recipe working-tree change is isolated by importing its reviewed snapshot.
    for item in prior['inputs']:
        source, snapshot = Path(item['path']), Path(item['snapshot'])
        if hashlib.sha256(snapshot.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('parent snapshot changed')
        current = hashlib.sha256(source.read_bytes()).hexdigest()
        if source.parent != HERE and current != item['sha256']:
            if source != recipe_path:
                raise ValueError('shared source changed')
            known_parallel_changes.append({'path': str(source), 'reviewedSHA256': item['sha256'], 'currentSHA256': current, 'currentSourceImported': False})
    recipe_snapshot = Path(recipe_item['snapshot'])
    expected_snapshot = parent / 'inputs/Tests/RealIntegration/build_host.py'
    if recipe_snapshot != expected_snapshot or recipe_snapshot.is_symlink() or hashlib.sha256(recipe_snapshot.read_bytes()).hexdigest() != recipe_item['sha256']:
        raise ValueError('reviewed recipe snapshot mismatch')
    spec = importlib.util.spec_from_file_location('terminal_postauth_r1_builder', recipe_snapshot)
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
    builder.record.update(taskID='TERMINAL-POSTAUTH-DIAG-R1', parentCheckpoint=str(parent), reviewedR1Checkpoint=str(reviewed_r1), dockerInvoked=False,
                          liveExecuted=False, generationRead=False, socketsOpened=False, reusedDependencyObjects=True,
                          recipeReuse={'manifest': str(parent / 'result.json'), 'snapshot': str(recipe_snapshot), 'sha256': recipe_item['sha256'],
                                       'reboundConstants': {name: str(path) for name, path in rebound.items()}, 'GATE_SHA256': accepted.GATE_SHA256},
                          knownParallelChanges=known_parallel_changes)
    print('Unique post-auth diagnostic incremental snapshot: ' + str(work), flush=True)
    try:
        for folder in ('modules', 'cmodules'):
            shutil.copytree(parent / folder, work / folder, dirs_exist_ok=True)
        shutil.copyfile(parent / 'BuildLocation.swift', work / 'BuildLocation.swift')
        for name in ('.gitignore', 'Core.swift', 'LiveInput.swift', 'Main.swift', 'OfflineMain.swift', 'remote_probe.py', 'test_static.py', 'build_host.py', 'resume_consumer.py'):
            builder.snapshot(HERE / name)
        builder.tools()
        core = builder.swift_compile('RemoteTerminalCore', [builder.snapshot(HERE / 'Core.swift')], extra=['-warnings-as-errors'])
        test_object = builder.swift_compile('RemoteTerminalOffline', [builder.snapshot(HERE / 'OfflineMain.swift')], extra=['-warnings-as-errors'])
        tests = builder.link('RemoteTerminalOffline', [test_object, core])
        builder.run('postauth-r1-offline-core-tests', [tests])
        builder.run('postauth-r1-offline-python-tests', [sys.executable, '-B', HERE / 'test_static.py'])
        consumer_object = builder.swift_compile('OpenLXSSHRemoteTerminal', [builder.snapshot(HERE / 'Main.swift'), builder.snapshot(HERE / 'LiveInput.swift'), work / 'BuildLocation.swift'], extra=['-warnings-as-errors'])
        symbols = builder.run('postauth-r1-public-api-symbols', ['/usr/bin/xcrun', 'nm', '-u', consumer_object])
        if b'DirectSSHSession' not in symbols or any(value in symbols for value in (b'startProbe', b'configureProbe', b'probeStore', b'LibSSH2FileService')):
            raise ValueError('not sole public production outer API')
        required = ('OpenLXSSHTrust', 'SwiftTerm', 'OpenLXSSHAskpass', 'OpenLXSSHTransport', 'COpenLXSSHAskpass-AskpassMach', 'COpenLXSSHAskpass-BoundedTool', 'COpenLXSSHAskpass-Identity', 'RealIntegrationPOSIX-PrivateInput')
        consumer = builder.link('OpenLXSSHRemoteTerminal', [consumer_object, core] + [Path(objects[name]['path']) for name in required])
        app = work / 'OpenLXSSHRemoteTerminal.app'
        for name in ('Contents/MacOS', 'Contents/Helpers'): (app / name).mkdir(mode=0o700, parents=True)
        shutil.copyfile(parent / 'OpenLXSSHRemoteTerminal.app/Contents/Helpers/openlxssh-askpass', app / 'Contents/Helpers/openlxssh-askpass')
        shutil.copyfile(consumer, app / 'Contents/MacOS/OpenLXSSHRemoteTerminal')
        for binary in (app / 'Contents/Helpers/openlxssh-askpass', app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'): binary.chmod(0o700)
        shutil.copyfile(parent / 'OpenLXSSHRemoteTerminal.app/Contents/Info.plist', app / 'Contents/Info.plist')
        builder.sign(app)
        builder.unchanged()
        builder.run('postauth-r1-default-inert', [app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'])
        builder.run('postauth-r1-validate-inert', [app / 'Contents/MacOS/OpenLXSSHRemoteTerminal', 'validate', '--contract', '/not/opened/remote-terminal.json'])
        builder.record.update(status='signed-static-only-not-run', app=str(app), driverSHA256=accepted.sha(app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'),
            helperSHA256=accepted.sha(app / 'Contents/Helpers/openlxssh-askpass'), remoteProbeSHA256=accepted.sha(HERE / 'remote_probe.py'),
            sourceSHA256={name: accepted.sha(HERE / name) for name in ('Core.swift', 'Main.swift', 'LiveInput.swift', 'OfflineMain.swift', 'test_static.py', 'resume_consumer.py')},
            dependencyObjects=[{'path':objects[name]['path'],'sha256':objects[name]['sha256']} for name in required])
        print('Post-auth short ACK + typed diagnostic core/offline/consumer strict signing passed, no runtime.')
        print('Exact diagnostic App: ' + str(app))
        return 0
    except BaseException as error:
        builder.record.update(status='failed-r1-static', failure=type(error).__name__); raise
    finally:
        builder.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('checkpoint', type=Path)
    return resume(parser.parse_args().checkpoint)


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error: sys.stderr.write('R1 incremental build refused: ' + type(error).__name__ + '\n'); sys.exit(2)
