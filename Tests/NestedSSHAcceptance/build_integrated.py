#!/usr/bin/env python3
"""Inert by default. Later explicit build reuses EXACT89033 nine objects/recipe;
only frozen Main/LiveInput + new BuildLocation compile. No dependency/full build,
Docker, keygen, SSH, generation access or runtime execution is performed here.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid

import management_prep as core
from nested_probe import FROZEN, INNER_SHA256, wrapper

HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
PARENT = ROOT / 'Tests/RemoteTerminalAcceptance/.build/host-89033e34-66db-4c4c-9a23-c2c881636baf'
MANIFEST_SHA256 = 'b2c3ea6e0862790eb47fdefd85705fd316b755550f97239cc05ca75d0d0eceb6'
RECIPE = ROOT / 'Tests/RemoteTerminalAcceptance/.build/host-f43c264c-363f-4cf3-829e-73dd3e4a7f90/inputs/Tests/RealIntegration/build_host.py'
RECIPE_SHA256 = '8b5e639d7c03e4925213bc6f872b94ec007738d0a79ad9d1a0f5f9a98fc2a8a9'
MODULES = ('OpenLXSSHTrust', 'SwiftTerm', 'OpenLXSSHAskpass', 'OpenLXSSHTransport',
           'COpenLXSSHAskpass-AskpassMach', 'COpenLXSSHAskpass-BoundedTool',
           'COpenLXSSHAskpass-Identity', 'RealIntegrationPOSIX-PrivateInput')


def digest(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.resolve() != path or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o022:
        raise ValueError('unsafe-build-input')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_parent():
    if digest(PARENT / 'result.json') != MANIFEST_SHA256 or digest(RECIPE) != RECIPE_SHA256:
        raise ValueError('exact89033-recipe-required')
    prior = json.loads((PARENT / 'result.json').read_bytes())
    readonly = {PARENT / 'result.json': MANIFEST_SHA256, RECIPE: RECIPE_SHA256}
    sources = {}
    for name, expected in FROZEN.items():
        path = PARENT / 'inputs/Tests/RemoteTerminalAcceptance' / name
        if digest(path) != expected:
            raise ValueError('frozen-terminal-source-changed')
        readonly[path], sources[name] = expected, path
    dependencies = prior['dependencyObjects']
    if len(dependencies) != 8 or {Path(item['path']).stem for item in dependencies} != set(MODULES):
        raise ValueError('exact-eight-dependencies-required')
    frozen_core = [item for item in prior['objects'] if item['module'] == 'RemoteTerminalCore']
    if len(frozen_core) != 1:
        raise ValueError('exact-core-object-required')
    objects = frozen_core + dependencies
    for item in objects:
        path = Path(item['path'])
        if digest(path) != item['sha256']:
            raise ValueError('frozen-object-changed')
        readonly[path] = item['sha256']
    for folder in ('modules', 'cmodules'):
        for path in (PARENT / folder).rglob('*'):
            if path.is_symlink():
                raise ValueError('module-alias')
            if path.is_file():
                readonly[path] = digest(path)
                if path.name == 'module.modulemap':
                    for header in re.findall(r'header "([^"]+)"', path.read_text()):
                        header = Path(header)
                        if not header.is_relative_to(RECIPE.parents[3]):
                            raise ValueError('non-frozen-header')
                        readonly[header] = digest(header)
    location = PARENT / 'BuildLocation.swift'
    if digest(location) != prior['generatedBuildLocationSHA256']:
        raise ValueError('frozen-location-changed')
    readonly[location] = prior['generatedBuildLocationSHA256']
    teams = re.findall(r'static let team = "([A-Z0-9]{10})"', location.read_text())
    if len(teams) != 1:
        raise ValueError('frozen-team-required')
    helper = PARENT / 'OpenLXSSHRemoteTerminal.app/Contents/Helpers/openlxssh-askpass'
    plist = PARENT / 'OpenLXSSHRemoteTerminal.app/Contents/Info.plist'
    for path, expected in ((helper, prior['helperSHA256']), (plist, '2c66c1857564672093ece3bf6a2b430723af942f447560868d61872205594092')):
        if digest(path) != expected:
            raise ValueError('frozen-bundle-input-changed')
        readonly[path] = expected
    return sources, objects, teams[0], helper, plist, readonly


def workplan(nonce, source, location, app, app_hash, snapshots):
    key = core.key_plan(nonce)['argv'][-1]
    return {'schema': 1, 'taskID': 'NEST-INTEGRATED-PREP-A', 'case': 'NESTrealpublickeyonly',
            'nonce': nonce, 'container_id': core.CONTAINER_ID, 'fingerprint': core.HOST_FINGERPRINT,
            'key_directory': key.rsplit('/', 1)[0], 'app': str(app), 'app_sha256': app_hash,
            'wrapper_sha256': hashlib.sha256(source).hexdigest(), 'wrapper_bytes': len(source),
            'inner_sha256': INNER_SHA256, 'build_location_sha256': hashlib.sha256(location).hexdigest(),
            'parent_manifest_sha256': MANIFEST_SHA256, 'source_sha256': snapshots,
            'exclusion': 'global-idle-before-prepare-and-after-native-SSH-closed; no-running-registry',
            'finish_precondition': 'native-closed-ownedPID-nil-and-host-relay-no-connections',
            'not_covered': ['human-inner-password', 'human-inner-OTP', 'enterprise-human-acceptance']}


def build_builder(accepted):
    class ExclusiveLogBuilder(accepted.Builder):
        def run(self, label, argv, private=False, timeout=300):
            env = accepted.environment(self.work)
            if private:
                env['HOME'] = str(Path.home())
            # Repeated signature labels get new entries, never overwrite a prior log.
            label = str(len(self.commands) + 1).zfill(3) + '-' + label
            result = subprocess.run(list(map(str, argv)), cwd=HERE, env=env, capture_output=True, timeout=timeout)
            entry = {'label': label, 'cwd': str(HERE), 'command': '<private existing Development identity command>'
                     if private else list(map(str, argv)), 'exitCode': result.returncode}
            self.commands.append(entry)
            if not private:
                log = self.work / 'logs' / (label + '.log')
                with log.open('xb') as stream:
                    stream.write(result.stdout + result.stderr)
                entry['log'] = str(log)
            if result.returncode:
                raise accepted.Refusal(label + 'Failed')
            return result.stdout + result.stderr
    return ExclusiveLogBuilder


def build():
    sources, objects, team, helper, plist, readonly = inspect_parent()
    os.umask(0o077)
    base = HERE / '.build'
    base.mkdir(mode=0o700, exist_ok=True)
    if base.resolve() != base or base.stat().st_uid != os.getuid() or stat.S_IMODE(base.stat().st_mode) != 0o700:
        raise ValueError('unsafe-own-build-root')
    work = base / ('host-' + str(uuid.uuid4()))
    work.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('nested_frozen_builder', RECIPE)
    accepted = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(accepted)
    accepted.HERE, accepted.ROOT = HERE, ROOT
    builder = build_builder(accepted)(work)
    builder.record.update(taskID='NEST-INTEGRATED-BUILD-A', dependencyObjects=objects, fullDependencyBuildExecuted=False,
                          parentManifestSHA256=MANIFEST_SHA256, generationRead=False, socketsOpened=False)
    try:
        accepted.write_json(work / 'readonly-before.json', {str(path): expected for path, expected in readonly.items()})
        for folder in ('modules', 'cmodules'):
            shutil.copytree(PARENT / folder, work / folder, dirs_exist_ok=True)
        # Preserve modulemap references to their frozen private header snapshots.
        snapshots = {name: builder.snapshot(path) for name, path in sources.items()}
        for path in sorted(HERE.glob('*.py')):
            builder.snapshot(path)
        builder.snapshot(RECIPE)
        nonce = uuid.uuid4().hex
        source = wrapper(snapshots['remote_probe.py'].read_bytes(), nonce)
        (work / 'nested-wrapper.py').write_bytes(source)
        location = ('enum BuildLocation { static let ownRoot = ' + json.dumps(str(HERE)) +
                    '; static let buildRoot = ' + json.dumps(str(base)) + '; static let fixtureRoot = ' +
                    json.dumps(str(ROOT / 'Tests/IntegrationEnvironment')) + '; static let team = ' + json.dumps(team) +
                    '; static let probeBase64 = ' + json.dumps(base64.b64encode(source).decode()) +
                    '; static let probeSHA256 = ' + json.dumps(hashlib.sha256(source).hexdigest()) + ' }\n').encode()
        generated = work / 'BuildLocation.swift'
        generated.write_bytes(location)
        generated.chmod(0o400)
        if builder.verify_signature(helper, accepted.HELPER_ID) != team:
            raise ValueError('frozen-helper-team')
        builder.tools()
        consumer = builder.swift_compile('OpenLXSSHRemoteTerminal', [snapshots['Main.swift'], snapshots['LiveInput.swift'], generated], extra=['-warnings-as-errors'])
        symbols = builder.run('sole-public-outer-api', ['/usr/bin/xcrun', 'nm', '-u', consumer])
        if b'DirectSSHSession' not in symbols or any(value in symbols for value in (b'startProbe', b'configureProbe', b'probeStore', b'LibSSH2FileService')):
            raise ValueError('not-public-transport')
        binary = builder.link('OpenLXSSHRemoteTerminal', [consumer] + [Path(item['path']) for item in objects])
        app = work / 'OpenLXSSHRemoteTerminal.app'  # Frozen SignedConsumer requires this basename.
        for folder in ('Contents/MacOS', 'Contents/Helpers'):
            (app / folder).mkdir(mode=0o700, parents=True)
        shutil.copyfile(binary, app / 'Contents/MacOS/OpenLXSSHRemoteTerminal')
        shutil.copyfile(helper, app / 'Contents/Helpers/openlxssh-askpass')
        shutil.copyfile(plist, app / 'Contents/Info.plist')
        for path in (app / 'Contents/MacOS/OpenLXSSHRemoteTerminal', app / 'Contents/Helpers/openlxssh-askpass'):
            path.chmod(0o700)
        builder.sign(app)
        if builder.verify_signature(app, accepted.APP_ID, deep=True) != team:
            raise ValueError('signed-team-mismatch')
        binary = app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'
        if base64.b64encode(source) not in binary.read_bytes():
            raise ValueError('embedded-wrapper-missing')
        builder.unchanged()
        after = {str(path): digest(path) for path in readonly}
        accepted.write_json(work / 'readonly-after.json', after)
        if after != {str(path): expected for path, expected in readonly.items()}:
            raise ValueError('readonly-parent-changed')
        hashes = {name: digest(path) for name, path in snapshots.items()}
        hashes.update({path.name: digest(path) for path in HERE.glob('*.py')})
        plan = workplan(nonce, source, location, app, digest(binary), hashes)
        accepted.write_json(work / 'workplan.json', plan)
        builder.record.update(status='signed-static-only-not-run', app=str(app), driverSHA256=plan['app_sha256'],
                              helperSHA256=digest(app / 'Contents/Helpers/openlxssh-askpass'), case='NESTrealpublickeyonly',
                              remoteProbeSHA256=plan['wrapper_sha256'], workplanSHA256=digest(work / 'workplan.json'),
                              readonlyParentInputsUnchanged=True, compiledTeamMatchesSignature=True)
        print('Nested static App/workplan ready; NOT executed: ' + str(work))
    finally:
        builder.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=('help', 'validate', 'build'))
    args = parser.parse_args(argv)
    if args.action == 'help':
        parser.print_help()
    elif args.action == 'validate':
        print('Syntax only; no checkpoint read/build/sign/runtime.')
    else:
        build()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('Nested static preparation refused; details suppressed.\n')
        sys.exit(2)
