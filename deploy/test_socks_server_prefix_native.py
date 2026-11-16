#!/usr/bin/env python3
"""Require all encrypted SOCKS Server prefix component cases on one source/image.

Only the first physical tuple and interface monitor are component fixtures.
This gate cannot substitute for installed native-carrier/host acceptance.
"""
from pathlib import Path
import importlib.util
import json
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'github.com/sagernet/sing-box/protocol/routervpnamnezia'
PREFIX = 'TestRouterVPNSOCKSPrefixServer'
CASES = {
    'EncryptedWG': tuple(str(n) for n in range(4, 9)),
    'EncryptedFast': tuple(str(n) for n in range(4, 9)),
    'EncryptedStrong': tuple(str(n) for n in range(4, 9)),
    'Refusals': ('first-key', 'later-key', 'password', 'relay-domain', 'final-key'),
}

def load():
    spec = importlib.util.spec_from_file_location('socks_prefix_native_receipts', ROOT/'deploy/test_desktop_native_root_phases.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.PACKAGE = PACKAGE
    return module


def verdict(output, family):
    if family not in CASES:
        raise ValueError('uncaptured SOCKS prefix family')
    checker = load().load_receipt()
    _, runs, passes, failures, ended = checker.complete_receipt(output)
    root = PREFIX + family
    expected = {root, *(root+'/'+child for child in CASES[family])}
    if ended != 'pass' or failures or set(runs) != expected or set(passes) != expected or any(runs[name] != 1 or passes[name] != 1 for name in expected):
        raise ValueError('SOCKS prefix gate omitted, duplicated or changed an original native case')
    return len(expected)


def execute(source, target, tags, env, runner):
    if target not in ('linux/amd64', 'linux/arm64') or (env.get('GOOS'), env.get('GOARCH')) != tuple(target.split('/')):
        raise ValueError('SOCKS prefix native gate requires its original Linux target')
    source = source.resolve()
    helpers, captured = load(), dict(env)
    original = helpers.source_digest(source)
    with tempfile.TemporaryDirectory(prefix='routervpn-socks-prefix-native-') as directory:
        image = Path(directory)/'original.test'
        runner(['go', 'test', '-c', '-race', '-p=1', '-mod=readonly', '-tags='+tags,
                '-ldflags=-checklinkname=0', '-o', image, './protocol/routervpnamnezia'],
               cwd=source, env=captured, timeout=600)
        identity = helpers.image_identity(image)
        def unchanged():
            if captured != env or helpers.source_digest(source) != original or helpers.image_identity(image) != identity:
                raise ValueError('SOCKS prefix native gate changed its original source, environment or executable')
        unchanged()
        listed = runner([image, '-test.list=^'+PREFIX], cwd=source, env=captured, timeout=60).strip().splitlines()
        if len(listed) != len(CASES) or set(listed) != {PREFIX+name for name in CASES}:
            raise ValueError('SOCKS prefix native root inventory changed')
        counts = {}
        for family in CASES:
            unchanged()
            output = runner(['go', 'tool', 'test2json', '-p', PACKAGE, '-t', image, '-test.v',
                             '-test.run=^'+PREFIX+family+'$', '-test.count=1', '-test.timeout=120s'],
                            cwd=source, env=captured, timeout=135)
            counts[family] = verdict(output, family)
            unchanged()
        result = {'kind': 'native-socks-server-prefix-components-v1', 'target': target,
                  'source_sha256': original, 'image_sha256': identity[1], 'race': True,
                  'test_timeout': '120s', 'roots': [PREFIX+name for name in CASES], 'records': counts,
                  'installed_carrier_acceptance': False}
        print('Complete native SOCKS Server prefix components: '+json.dumps(result, sort_keys=True), flush=True)
        return result
