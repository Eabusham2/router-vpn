#!/usr/bin/env python3
"""Verify the selected native schema-six owner, independent SS2022 dials and joined retirement."""
import argparse
import importlib.util
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'multiple_imported_execution_native', ROOT/'deploy/test_node_chain_openvpn_execution_owner.py')
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)

LAYOUTS = ('single', 'adjacent', 'separated', 'before-paired-suffix', 'maximum-sparse',
           'maximum-public', 'packet-first', 'first-import-then-packet')
CASES = {
    'Owners': tuple(name+'/'+setting for name in ('single', 'adjacent', 'separated', 'maximum-public')
                    for setting in ('server', 'auto')),
    'Authority': ('equal-source', 'copied-construction', 'missing-member', 'swapped-members',
                  'manager-lookup', 'resolver', 'ordinary-outbound', 'cancelled', 'second-box'),
    'PublicServer': tuple('pos-'+str(position)+'/'+fault for position in (1, 3)
                          for fault in ('original', 'away-and-back', 'foreign-tag', 'foreign-address')),
    'LocalEncrypted': ('original', 'wrong-first-key', 'wrong-second-key'),
    'Retirement': ('success', 'original-error'),
    'Last': ('local', 'server'),
}
GENERATOR = NATIVE.phase('multiple_fixture', 'TestNodeChainMultipleImportedExecutionNative',
                         'router-vpn/internal/mobilemultihop', ('Fixtures',), {'Fixtures': LAYOUTS})
BOX = NATIVE.phase('multiple_box', 'TestRouterVPNMultipleImportedExecutionNative',
                   NATIVE.PACKAGE, tuple(CASES), CASES)
DESKTOP_LAYOUTS = ('single', 'adjacent', 'separated', 'maximum-sparse', 'maximum-public', 'packet-first')
DESKTOP_BOX_CASES = {
    'PhysicalActualBox': tuple(name+'/'+setting for name in DESKTOP_LAYOUTS for setting in ('server', 'auto')),
    'PhysicalTarget': ('linux', 'windows', 'darwin'),
    'PhysicalChangedGraph': ('first-password', 'second-password', 'first-remote', 'second-remote',
                             'first-detour', 'second-detour', 'final-detour', 'dns', 'physical-source', 'mtu', 'open-gate'),
}
DESKTOP_COMMAND_CASES = {
    'CommandOriginal': tuple(target+'/'+name+'/'+setting for target in ('linux', 'windows', 'darwin')
                             for name in DESKTOP_LAYOUTS for setting in ('server', 'auto')),
    'CommandRefusal': ('mobile', 'local', 'schema-three', 'schema-four', 'schema-five', 'schema-seven',
                       'schema-fraction', 'duplicate-schema', 'session', 'config', 'physical', 'execution',
                       'target', 'graph', 'paired-source', 'socks-source', 'connect-source'),
    'ConstructionRefusal': ('copy', 'preparation', 'physical', 'policy', 'source', 'native',
                            'context', 'config', 'metadata', 'cancelled', 'nil-caller'),
    'ChildPublication': ('server', 'auto'),
    'ChildSavedChoice': ('local', 'server'),
    'ChildRejectsForeignOwner': ('host', 'preparation', 'physical', 'reader', 'mtu', 'selected-proof', 'proof-kind'),
    'ChildRetainsFailedCleanup': ('remote-join', 'gate-retire'),
    'ChildJoinsLateConstructor': (),
    'ChildLongestOriginalObserver': tuple(name+'/'+setting for name in ('maximum-sparse', 'maximum-public')
                                         for setting in ('server', 'auto')),
}
DESKTOP_BOX = NATIVE.phase('multiple_desktop_box', 'TestRouterVPNDesktopMultipleImportedExecution',
                           NATIVE.PACKAGE, tuple(DESKTOP_BOX_CASES), DESKTOP_BOX_CASES)
DESKTOP_COMMAND = NATIVE.phase('multiple_desktop_command', 'TestRouterVPNDesktopMultipleImportedExecution',
                               NATIVE.PACKAGE+'/cmd/sing-box', tuple(DESKTOP_COMMAND_CASES), DESKTOP_COMMAND_CASES)


def verify(core, desktop):
    source = NATIVE.verify(core, desktop=desktop)
    if desktop:
        preparation = NATIVE.load('multiple_desktop_original_projection', 'prepare-desktop-external.py')
        copies = preparation.pt_copies()
        for template in sorted((ROOT/'mobile/desktop').glob('node*.go.tmpl')):
            if template.name in preparation.PT_TEMPLATES or template.name in preparation.BOX_TEMPLATES or template.name in preparation.PEER_TEMPLATES:
                continue
            copies['cmd/sing-box/routervpn_'+template.name.removesuffix('.tmpl')] = template.read_bytes()
        for relative, original in copies.items():
            if (core/relative).read_bytes() != original:
                raise ValueError('multiple imported desktop source differs from its original projection: '+relative)
    return (source, NATIVE.sha(Path(__file__).read_bytes()),
            NATIVE.sha((ROOT/'deploy/test_node_chain_multiple_imported_execution_owner_runner.py').read_bytes()))


def run(core, go, tags, race=False, desktop=False):
    source = verify(core, desktop)
    flags = ['-json', '-p=1', '-mod=readonly', '-count=1'] + (['-race'] if race else [])
    with tempfile.TemporaryDirectory(prefix='routervpn-multiple-imported-execution-') as temp:
        fixture = Path(temp)
        env = dict(os.environ, GOMAXPROCS='1',
                   ROUTERVPN_MULTIPLE_IMPORTED_EXECUTION_NATIVE_FIXTURES=str(fixture))
        generated = NATIVE.execute([go, 'test', *flags, '-timeout=160s', './internal/mobilemultihop',
                                    '-run', '^TestNodeChainMultipleImportedExecutionNativeFixtures$'],
                                   ROOT, env, 360)
        gen_records = NATIVE.verdict(GENERATOR, generated)
        paths = sorted(fixture.glob('*.json'))
        hashes = {path.name: NATIVE.sha(path.read_bytes()) for path in paths}
        if set(hashes) != {layout+'.json' for layout in LAYOUTS}:
            raise ValueError('native multiple imported fixture inventory incomplete')
        selected = '^'+BOX.PREFIX+'('+'|'.join(CASES)+')$'
        result = NATIVE.execute([go, 'test', *flags, '-timeout=240s', '-tags='+tags,
                                 '-ldflags=-checklinkname=0', '.', '-run', selected],
                                core, env, 600)
        box_records = NATIVE.verdict(BOX, result)
        desktop_records = []
        if desktop:
            for parser, cases, package in ((DESKTOP_BOX, DESKTOP_BOX_CASES, '.'),
                                          (DESKTOP_COMMAND, DESKTOP_COMMAND_CASES, './cmd/sing-box')):
                selected = '^'+parser.PREFIX+'('+'|'.join(cases)+')$'
                result = NATIVE.execute([go, 'test', *flags, '-timeout=240s', '-tags='+tags,
                                         '-ldflags=-checklinkname=0', package, '-run', selected],
                                        core, env, 600)
                desktop_records.append(NATIVE.verdict(parser, result))
        if verify(core, desktop) != source or any(
                NATIVE.sha((fixture/name).read_bytes()) != digest for name, digest in hashes.items()):
            raise ValueError('native multiple imported source or private fixture changed')
        print('Multiple imported execution ownership PASS', gen_records, box_records, desktop_records, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', required=True)
    parser.add_argument('--race', action='store_true')
    parser.add_argument('--desktop', action='store_true')
    args = parser.parse_args()
    run(args.core.absolute(), args.go, args.tags, args.race, args.desktop)
