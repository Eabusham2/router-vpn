#!/usr/bin/env python3
"""Require typed OpenVPN desktop child and actual closed Box ownership.

The complete prepared native core and six actual shared private profile pairs
are required. Command lifecycle tests state their native I/O doubles; Box tests
use real unstarted provider endpoints. Neither is installed/encrypted proof.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'TestRouterVPNDesktopOpenVPNExecution'
FIXTURES = ('3-tcp', '3-udp', '4-tcp', '4-udp', '8-tcp', '8-udp')
PHASES = ('source', 'lifecycle', 'longest', 'box', 'controls')
CASES = {
    'source': ('cmd/sing-box', {
        'CommandOriginal': tuple(target+'/'+name+'/'+setting for target in ('linux', 'windows', 'darwin') for name in FIXTURES for setting in ('server', 'auto')),
        'CommandRefusal': ('mobile', 'local', 'schema-three', 'schema-four', 'schema-fraction', 'duplicate-schema', 'session', 'config', 'physical', 'execution', 'target', 'graph', 'paired-source', 'socks-source', 'connect-source'),
        'ConstructionRefusal': ('copy', 'preparation', 'physical', 'policy', 'source', 'native', 'source-receipt', 'native-receipt', 'context', 'config', 'metadata', 'cancelled', 'nil-caller'),
    }),
    'lifecycle': ('cmd/sing-box', {
        'ChildPublication': ('server', 'auto'),
        'ChildSavedChoice': ('local', 'server'),
        'ChildRejectsForeignOwner': ('host', 'preparation', 'physical', 'reader', 'mtu', 'selected-proof', 'proof-kind'),
        'ChildRetainsFailedCleanup': ('remote-join', 'gate-retire'),
        'ChildJoinsLateConstructor': (),
    }),
    'longest': ('cmd/sing-box', {
        'ChildLongestOriginalObserver': tuple(name+'/'+setting for name in ('8-tcp', '8-udp') for setting in ('server', 'auto')),
    }),
    'box': ('.', {
        'PhysicalActualBox': tuple(name+'/'+setting for name in FIXTURES for setting in ('server', 'auto')),
        'PhysicalTarget': ('linux', 'windows', 'darwin'),
        'PhysicalChangedGraph': ('provider-password', 'provider-remote', 'middle-detour', 'final-detour', 'dns', 'physical-source', 'mtu', 'open-gate'),
    }),
}
DARWIN = {
    'DarwinControl': ('server', 'auto'),
    'DarwinRefusal': ('policy', 'preparation', 'second-policy', 'source', 'execution', 'missing-authority', 'retiring', 'cancelled', 'nil-caller'),
    'DarwinEarlyStop': ('receipt-before-acquisition', 'authenticated-before-run'),
}
CONTROLS = (
    ('typed command', 'cmd/sing-box/routervpn_node_chain_execution_command.go',
     'string(header.Schema) == "5"', 'string(header.Schema) == "50"',
     'CommandOriginal', 'linux/3-tcp/server', 'typed OpenVPN command lost original source'),
    ('original physical pointer', 'cmd/sing-box/routervpn_node_chain_openvpn_execution_construction.go',
     'physical != c.physical', 'false',
     'ConstructionRefusal', 'physical', 'copied or replaced OpenVPN child construction accepted'),
    ('selected native proof', 'cmd/sing-box/routervpn_node_chain_execution_runtime.go',
     ' || readyErr != nil', ' || (readyErr != nil && false)',
     'ChildRejectsForeignOwner', 'selected-proof', 'OpenVPN execution published a substituted owner or proof'),
)
TEMPLATES = {
    **{name: 'routervpn_desktop_'+name+'.go' for name in (
        'node_chain_openvpn_execution_box_physical', 'node_chain_openvpn_execution_box_linux',
        'node_chain_openvpn_execution_box_darwin', 'node_chain_openvpn_execution_box_test', 'node_chain_execution_box_mtu')},
    **{name: 'cmd/sing-box/routervpn_'+name+'.go' for name in (
        'node_chain_openvpn_execution_construction', 'node_chain_openvpn_execution_command_test',
        'node_chain_openvpn_execution_child_test', 'node_chain_openvpn_execution_darwin_test',
        'node_chain_execution_command', 'node_chain_execution_runtime', 'node_chain_execution_last_test',
        'node_chain_execution_runtime_test', 'node_command_run_linux', 'mtu_node',
        'node_chain_execution_control_darwin', 'node_chain_execution_run_darwin')},
    **{name: 'routervpn/desktoppt/'+name+'.go' for name in (
        'node_chain_openvpn_execution_physical_linux', 'node_chain_openvpn_execution_physical_windows',
        'node_chain_openvpn_execution_physical_darwin', 'node_chain_openvpn_execution_physical_other', 'node_physical_darwin')},
}


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHILD = load('openvpn_child_original_receipt', 'test_desktop_socks_execution_child.py')
NATIVE = load('openvpn_child_original_box', 'test_node_chain_openvpn_execution_owner.py')
PREP = load('openvpn_child_original_desktop', 'prepare-desktop-external.py')


def inventory(phase, darwin=False):
    package, roots = CASES[phase]
    roots = dict(roots)
    if phase == 'source' and darwin:
        roots.update(DARWIN)
    return package, {PREFIX+name: children for name, children in roots.items()}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def native_projections():
    # Use the exact selective desktop projection. The mobile-only Libbox ABI
    # and its tests are not installed by the shipping desktop preparer, while
    # the shared Go packages beneath libbox/routervpn are used by both hosts.
    return tuple((module, {
        target: (ROOT/'mobile'/folder/template).read_bytes()
        for template, target in module.TEMPLATES.items()
        if not selective or not target.startswith('experimental/libbox/') or
            target.startswith('experimental/libbox/routervpn/')
    }) for module, folder, selective in (
        (NATIVE.BASE.PREP, 'chain', False),
        (NATIVE.NATIVE, 'chain', True),
        (NATIVE.BASE.CONNECT, 'chain', True),
        (NATIVE.BASE.GATE, 'chain_gate', False),
    ))


def verify_projection(core, module, content):
    wanted = {name: sha(raw) for name, raw in content.items()}
    record = json.loads(PREP.TOR.destination(core, module.OWNER).read_bytes())
    if record != {'schema': 1, 'core': module.PIN, 'files': wanted}:
        raise ValueError('desktop native ownership inventory changed: '+module.OWNER)
    for name, raw in content.items():
        path = PREP.TOR.destination(core, name)
        if not path.is_file() or path.read_bytes() != raw:
            raise ValueError('desktop native original source changed: '+name)
    return wanted


def verify_native(core):
    if subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip() != PREP.PIN:
        raise ValueError('desktop native owner lost original core pin')
    identity = {'prepared_core': NATIVE.SNAPSHOT.source_digest(core)}
    for module, content in native_projections():
        identity[module.OWNER] = verify_projection(core, module, content)
    original = NATIVE.BASE.PREP
    for relative, transform in (('box.go', original.box_source), ('daemon/started_service.go', original.daemon_source)):
        raw = PREP.TOR.destination(core, relative).read_bytes()
        if transform(raw.decode()) != raw:
            raise ValueError('desktop native construction or close projection changed: '+relative)
    NATIVE.BASE.ADMISSION.verify_current_templates(core)
    for package in NATIVE.SHARED.PACKAGES:
        for source in (ROOT/'internal'/package).glob('*.go'):
            if source.name == 'core_config_test.go' or package == 'applexray' and source.name == 'preparation_test.go':
                continue
            expected = NATIVE.SHARED.OBSERVATION.rewrite(source.read_bytes())
            for name in NATIVE.SHARED.PACKAGES:
                expected = expected.replace(('"router-vpn/internal/'+name+'"').encode(),
                    ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"').encode())
            relative = 'experimental/libbox/routervpn/'+package+'/'+source.name
            if PREP.TOR.destination(core, relative).read_bytes() != expected:
                raise ValueError('desktop native shared source changed: '+relative)
            identity[relative] = sha(expected)
    return sha(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode())


def verify(core):
    identity = {'native_owner': verify_native(core), 'desktop_inputs': PREP.digest()}
    record = json.loads((core/PREP.PT_OWNER).read_bytes())
    if record.get('schema') != 1 or record.get('core') != PREP.PIN or record.get('source_sha256') != identity['desktop_inputs']:
        raise ValueError('OpenVPN child lost the complete desktop source identity')
    copied = PREP.pt_copies()
    if record.get('files') != {name: sha(raw) for name, raw in copied.items()}:
        raise ValueError('OpenVPN child lost complete desktop projection ownership')
    for relative, raw in copied.items():
        if PREP.TOR.destination(core, relative).read_bytes() != raw:
            raise ValueError('OpenVPN child lost a desktop projection source: '+relative)
    for template, destination in TEMPLATES.items():
        expected = (ROOT/'mobile/desktop'/(template+'.go.tmpl')).read_bytes()
        target = core/destination
        if target.is_symlink() or not target.is_file() or target.read_bytes() != expected:
            raise ValueError('OpenVPN child lost actual shipping template: '+template)
        identity[destination] = sha(expected)
    for name in ('test_desktop_openvpn_execution_child.py', 'test_desktop_openvpn_execution_child_runner.py',
                 'test_desktop_socks_execution_child.py', 'test_node_chain_openvpn_execution_owner.py'):
        identity['deploy/'+name] = sha((ROOT/'deploy'/name).read_bytes())
    return sha(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode())


def rejected(raw, code, root, child, witness):
    """A precise compiled refusal, never compiler failure or partial output."""
    if code != 1:
        return False
    package = CHILD.MODULE+'/cmd/sing-box'
    selected = root+'/'+child
    required = {root, selected}
    ran, failed = set(), set()
    started = finished = witnessed = False
    diagnostics = 0
    try:
        for line in raw.splitlines():
            row = json.loads(line)
            if not isinstance(row, dict):
                return False
            action, name, output = row.get('Action'), row.get('Test'), row.get('Output', '')
            if not isinstance(output, str) or any(value in output for value in ('DATA RACE', 'build failed', 'panic:', 'fatal error:', 'test timed out')):
                return False
            if action == 'build-output':
                if started or set(row) != {'Action', 'ImportPath', 'Output'} or row['ImportPath'] != package+'.test' or not output:
                    return False
                diagnostics += len(output.encode())
                if diagnostics > 64*1024:
                    return False
                continue
            if row.get('Package') != package or finished:
                return False
            if action == 'start' and not name and not started:
                started = True
            elif action == 'run' and started and name in required and name not in ran and (name == root or root in ran and root not in failed):
                ran.add(name)
            elif action == 'fail' and name in ran and name not in failed and (name != root or selected in failed):
                failed.add(name)
            elif action == 'fail' and not name and started and ran == failed == required:
                finished = True
            elif action == 'output' and started and (not name or name in ran and name not in failed):
                witnessed |= name == selected and witness in output
            else:
                return False
    except (TypeError, ValueError):
        return False
    return finished and witnessed and ran == failed == required


def run(command, cwd, env, timeout):
    result = subprocess.run(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    print(result.stdout, end='', flush=True)
    return result


def execute(core, go, tags, race=True, phase='source', receipt=None):
    if phase not in PHASES or 'with_openvpn' not in tags.split(','):
        raise ValueError('OpenVPN child requires its exact phase and real provider implementation')
    source = verify(core)
    env = dict(os.environ)
    env.setdefault('GOMAXPROCS', '2'); env.setdefault('GOGC', '50'); env.setdefault('GOMEMLIMIT', '1800MiB')
    with tempfile.TemporaryDirectory(prefix='routervpn-desktop-openvpn-') as temporary:
        temporary = Path(temporary)
        assets = temporary/'fixtures'; assets.mkdir()
        env['ROUTERVPN_OPENVPN_EXECUTION_NATIVE_FIXTURES'] = str(assets)
        generated = run([go, 'test', '-json', '-p=1', '-mod=readonly', '-count=1', *(['-race'] if race else []),
                         '-timeout=120s', './internal/mobilemultihop', '-run', '^TestNodeChainOpenVPNExecutionNativeFixtures$'], ROOT, env, 300)
        generator = NATIVE.GENERATOR.verdict(generated.stdout, generated.returncode)
        if set(path.name for path in assets.iterdir()) != {name+'.json' for name in FIXTURES}:
            raise ValueError('OpenVPN child requires every original independent provider fixture')
        fixture_hashes = {path.name: sha(path.read_bytes()) for path in assets.iterdir()}
        if phase != 'controls':
            package, roots = inventory(phase, platform.system() == 'Darwin')
            result = run(CHILD.command(go, tags, race, package, '^('+'|'.join(roots)+')$'), core, env, 600)
            records = CHILD.verdict(result.stdout, result.returncode, package, roots)
            evidence = {'package': package, 'roots': len(roots), 'test_records': len(records)}
        else:
            for label, relative, before, after, root, child, witness in CONTROLS:
                original = core/relative; body = original.read_text()
                if body.count(before) != 1:
                    raise ValueError('OpenVPN child causal boundary changed: '+label)
                mutant = temporary/'mutant.go'; mutant.write_text(body.replace(before, after, 1))
                overlay = temporary/'overlay.json'; overlay.write_text(json.dumps({'Replace': {str(original): str(mutant)}}))
                root = PREFIX+root
                selection = '^'+re.escape(root)+'$/'+ '/'.join('^'+re.escape(part)+'$' for part in child.split('/'))
                result = run(CHILD.command(go, tags, race, 'cmd/sing-box', selection, overlay), core, env, 600)
                if not rejected(result.stdout, result.returncode, root, child, witness) or original.read_text() != body:
                    raise ValueError('OpenVPN child compiled refusal missed exact witness: '+label)
                print('Desktop OpenVPN causal refusal PASS:', label, flush=True)
            evidence = {'causal_controls': len(CONTROLS)}
        if verify(core) != source or any(sha((assets/name).read_bytes()) != digest for name, digest in fixture_hashes.items()):
            raise ValueError('OpenVPN child source or original private profiles changed during execution')
    evidence.update(schema=1, phase=phase, source_sha256=source, race=race, generator=generator, fixture_sha256=fixture_hashes,
                    scope='actual typed sources, child lifecycle and unstarted native Box; provider traffic/TUN/process are separate acceptance')
    if receipt:
        Path(receipt).write_text(json.dumps(evidence, sort_keys=True, indent=2)+'\n')
    print(json.dumps(evidence, sort_keys=True), flush=True)
    return evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', default=CHILD.TAGS)
    parser.add_argument('--without-race', action='store_true')
    parser.add_argument('--phase', required=True, choices=PHASES)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    execute(args.core.resolve(), args.go, args.tags, not args.without_race, args.phase, args.receipt)
