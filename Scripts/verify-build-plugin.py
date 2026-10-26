#!/usr/bin/env python3
"""Fail closed before Xcode's plugin-validation override, for the reviewed pinned graph only."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
# Independently compared with Core's GRDB pin and Transport's reviewed resolved
# graph. A clean checkout matching a newly edited lock is NOT new approval.
APPROVED_GRAPH = {
    'grdb.swift': 'b83108d10f42680d78f23fe4d4d80fc88dab3212',
    'swiftterm': '2f573f73af5e768d90847dce20c97fa9535d7164',
    'swift-argument-parser': '6a52f3251125d74daf04fcbd5e6f08a75d074382',
    'swift-png': '2d17c6c51c098628574c0383f1119892655a73a2',
    'h': 'aa3626829160917d4378330617971977cbd78f5b',
}
APPROVED_MANIFESTS = {
    'grdb.swift': '4118b6c48dcb87f91d95fe40420371b8a474a44b0b0be2bf0417e0be1ebf7853',
    'swiftterm': '91c0b9d4a3e753c07c3175e7ef7c0cde1407172094d9ad02607cccfd5b29d18f',
    'swift-argument-parser': '4eae0e28d24671d6ab75c2c7a0dd0326e6d48f8785510a3e403886fe8cf17d88',
    'swift-png': 'd3b74b582db206eb8d82861b0ec049d76a1a3accf0c0a4beb0fdd1ac7b4c1308',
    'h': '30fd4878f812d7296fa827e213da67c6eeaba4a5678e116b7989297e46ca6853',
}
# ArgumentParser's only plugins are dormant .command doc/manual tools: no
# App/SwiftTerm target attaches them. Manifests and source sets are fixed too.
ARGUMENT_PARSER_PLUGINS = {
    'Plugins/GenerateCommon/GeneratePlugin.swift': '7bee8dc1a6098c4a7ab8e5ba64364a2666b31de156456b8704e5a4056f0a1872',
    'Plugins/GenerateCommon/GeneratePluginError.swift': '69ec19a33b00635fddd58aef59cab109bf47e73805b24f955e71c4f3133f5a17',
    'Plugins/GenerateCommon/PackagePlugin+Helpers.swift': 'bde8fb092206560af4cac6bbf7b3fa6483673d657a173aed8d2086f15a798a97',
    'Plugins/GenerateDoccReference/GenerateDoccReference.swift': 'e8c673c61ba0176f9838b4366f0fb4d2af205eea631679669eb3306c62b0325a',
    'Plugins/GenerateManual/GenerateManualPlugin.swift': 'f2e14a74af745aedad9fc0e3eb339a2ab0bc70b7d64d067c8883003f3e5e2551',
}
APPROVED = {
    'Package.swift': '91c0b9d4a3e753c07c3175e7ef7c0cde1407172094d9ad02607cccfd5b29d18f',
    'Plugins/SwiftTermBuildInfoPlugin/plugin.swift': 'f687340542eeea5a4a3eb596b137aebc269460281a67b3105b37f2604ab02eef',
    'Sources/SwiftTermBuildInfoGenerator/BuildInfoGenerator.swift': 'ff30c1359fbd8ec1ae8e43dc20366c007b6c5e342e73060921246c0342369cdd',
    'Sources/SwiftTermBuildInfoGenerator/TerminfoSource.swift': '340baf55bbf94fd4ea7db600c1d2a646fbb3fb9053a2138afe5432ce28dd75f1',
    'Sources/SwiftTermBuildInfoGenerator/XtgettcapTableGenerator.swift': '02467e6425e37418c0a0f079dfcb193b88443d686079670cafedd720162fad0f',
    'swifterm-terminfo': '7819298c1e79b7ba292960fbab41d6604240cf9111f7f3617b775701e008276b',
}

def approved_graph(lock, helper=False):
    expected = {pin['identity']: pin['state']['revision'] for pin in lock['pins']}
    fixed = {identity: revision for identity, revision in APPROVED_GRAPH.items() if not helper or identity != 'grdb.swift'}
    if len(expected) != len(lock['pins']) or expected != fixed:
        raise ValueError('unreviewed package graph')
    return fixed

def verify(checkouts, helper=False):
    lock_path = 'Packages/OpenLXSSHTransport/Package.resolved' if helper else 'OpenLXSSH.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved'
    lock = json.loads((ROOT / lock_path).read_text())
    expected = approved_graph(lock, helper=helper)
    actual = {path.name.lower(): path for path in checkouts.iterdir() if path.is_dir()}
    if set(actual) != set(expected):
        raise ValueError('checkout graph changed')
    for identity, directory in actual.items():
        revision = subprocess.check_output(['/usr/bin/git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip()
        if revision != expected[identity]:
            raise ValueError('checkout revision changed')
        # Including untracked files prevents new build-tool/plugin sources from
        # being smuggled into an otherwise unchanged revision.
        if subprocess.check_output(['/usr/bin/git', '-C', str(directory), 'status', '--porcelain', '--untracked-files=all']):
            raise ValueError('checkout contains changes')
        manifest = directory / 'Package.swift'
        if manifest.is_symlink() or hashlib.sha256(manifest.read_bytes()).hexdigest() != APPROVED_MANIFESTS[identity]:
            raise ValueError('package manifest changed')
        allowed_plugins = ARGUMENT_PARSER_PLUGINS if identity == 'swift-argument-parser' else (
            {name: digest for name, digest in APPROVED.items() if name.startswith('Plugins/')} if identity == 'swiftterm' else {})
        plugin_files = {str(path.relative_to(directory)) for path in (directory / 'Plugins').rglob('*') if path.is_file()}
        if plugin_files != set(allowed_plugins):
            raise ValueError('package plugin set changed')
        for relative, digest in allowed_plugins.items():
            path = directory / relative
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('package plugin content changed')
    swiftterm = actual['swiftterm']
    for relative, digest in APPROVED.items():
        path = swiftterm / relative
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('reviewed plugin content changed')
    plugin_files = {str(path.relative_to(swiftterm)) for path in (swiftterm / 'Plugins').rglob('*') if path.is_file()}
    generator_files = {str(path.relative_to(swiftterm)) for path in (swiftterm / 'Sources/SwiftTermBuildInfoGenerator').rglob('*') if path.is_file()}
    if plugin_files | generator_files != {name for name in APPROVED if name.startswith(('Plugins/', 'Sources/'))}:
        raise ValueError('plugin or generator source set changed')
    print('Reviewed SwiftTerm build-info/terminfo plugin content and clean pinned checkout graph checked.')

if __name__ == '__main__':
    try:
        verify(Path(sys.argv[1]), helper='--helper' in sys.argv[2:])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('STOP: package/plugin graph differs from the reviewed source. Do not bypass approval.', file=sys.stderr)
        raise SystemExit(1)
