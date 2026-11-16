#!/usr/bin/env python3
"""Execute original native OpenVPN client ownership, Last and MTU checks.

Real OpenVPN endpoints remain unstarted. Actual managers, shared discovery,
selector/gate and reader transactions run; endpoint receipt inputs and TUN I/O
are stated component boundaries, never encrypted or installed-host acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'github.com/sagernet/sing-box'
PREFIX = 'TestRouterVPNOpenVPNExecutionNative'
ROOTS = ('Original', 'Authority', 'ConnectedReceipt', 'Last', 'MTU', 'Retirement', 'PublicServer')
FIXTURES = ('3-tcp', '3-udp', '4-tcp', '4-udp', '8-tcp', '8-udp')
CHILDREN = {
    'Original': tuple(name+'/'+execution for name in FIXTURES for execution in ('server', 'auto')),
    'Authority': ('copied-construction', 'equivalent-source', 'preparation', 'config', 'middle',
                  'box', 'closed', 'manager', 'endpoint', 'output', 'lookup', 'cancelled', 'held-lock'),
    'ConnectedReceipt': ('same', 'generation', 'connected-at', 'remote', 'network', 'capacity',
                         'below-configured', 'invalid', 'cancelled', 'pending-after-pin'),
    'Last': ('local', 'server'),
    'MTU': ('candidate', 'rollback'),
    'Retirement': ('success', 'original-error'),
    'PublicServer': tuple(name+'/'+fault for name in ('3-tcp', '8-udp') for fault in ('original', 'away-and-back', 'foreign-tag', 'foreign-address')),
}


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load('openvpn_execution_original_owner', 'test_node_chain_execution_owner.py')
NATIVE = load('openvpn_execution_original_preparer', 'prepare-mobile-node-chain.py')
SHARED = load('openvpn_execution_original_shared', 'prepare-mobile-multihop.py')
SNAPSHOT = load('openvpn_execution_original_inputs', 'test_desktop_native_root_phases.py')


def phase(name, prefix, package, roots, children):
    # Reuse the existing strict complete-inventory parser in an independent
    # module. The previous owner's mandatory inventory and run are untouched.
    module = load('openvpn_execution_verdict_'+name, 'test_node_chain_execution_owner.py')
    module.PREFIX, module.ROOTS, module.CHILDREN = prefix, {package: roots}, children
    return module


POSITIVE = phase('positive', PREFIX, PACKAGE, ROOTS, CHILDREN)
STUB = phase('stub', PREFIX, PACKAGE, ('WithoutSupport',), {})
GENERATOR = phase('generator', 'TestNodeChainOpenVPNExecutionNative', 'router-vpn/internal/mobilemultihop',
                  ('Fixtures',), {'Fixtures': FIXTURES})

CONTROLS = (
    ('original construction', 'routervpn_node_chain_openvpn_execution.go',
     'c == nil || c.self != c || ctx == nil || ctx.Err() != nil || native == nil',
     'c == nil || ctx == nil || ctx.Err() != nil || native == nil',
     'Authority/copied-construction', 'foreign OpenVPN execution owner accepted'),
    ('original connected receipt', 'routervpn_node_chain_openvpn_execution.go',
     'if *c.state != actual {', 'if false {',
     'ConnectedReceipt/generation', 'original OpenVPN connected receipt was replaced'),
    ('pending after first connection', 'routervpn_node_chain_openvpn_execution.go',
     'if connected {', 'if connected && false {',
     'ConnectedReceipt/pending-after-pin', 'later pending OpenVPN endpoint acquired initial retry'),
    ('original native close join', 'routervpn_node_chain_openvpn_execution_retirement.go',
     'if err := c.close.JoinContext(ctx, c.instance); err != nil {',
     'if err := ctx.Err(); err != nil {',
     'Retirement/success', 'closed OpenVPN gate substituted for original Box close'),
    ('typed public dispatch', 'routervpn_node_chain_execution.go',
     'if e.prep.RequiresOpenVPNExecutionObserver() {\n\t\t\treturn e.dialOpenVPNPublicContext(ctx, state, tag)',
     'if false && e.prep.RequiresOpenVPNExecutionObserver() {\n\t\t\treturn e.dialOpenVPNPublicContext(ctx, state, tag)',
     'PublicServer/3-tcp/original', 'original remote hostname authority'),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(core, *, desktop=False):
    identity = {'original_execution': BASE.verify(core, desktop=desktop), 'prepared_core': SNAPSHOT.source_digest(core)}
    record = json.loads((core/NATIVE.OWNER).read_bytes())
    if record.get('schema') != 1 or record.get('core') != NATIVE.PIN:
        raise ValueError('native OpenVPN lost its original prepared core')
    for template, target in NATIVE.TEMPLATES.items():
        if target.startswith('experimental/libbox/'):
            continue
        expected = (ROOT/'mobile/chain'/template).read_bytes()
        if record['files'].get(target) != sha(expected) or (core/target).read_bytes() != expected:
            raise ValueError('native OpenVPN source differs from its original preparation: '+target)
        identity[target] = sha(expected)
    for package in SHARED.PACKAGES:
        for source in (ROOT/'internal'/package).glob('*.go'):
            if source.name == 'core_config_test.go' or package == 'applexray' and source.name == 'preparation_test.go':
                continue
            expected = SHARED.OBSERVATION.rewrite(source.read_bytes())
            for name in SHARED.PACKAGES:
                expected = expected.replace(('"router-vpn/internal/'+name+'"').encode(),
                    ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"').encode())
            target = 'experimental/libbox/routervpn/'+package+'/'+source.name
            if (core/target).read_bytes() != expected:
                raise ValueError('native OpenVPN shared source differs: '+target)
            identity[target] = sha(expected)
    for relative in ('deploy/test_node_chain_openvpn_execution_owner.py',
                     'deploy/test_node_chain_openvpn_execution_owner_runner.py',
                     'deploy/test_desktop_native_root_phases.py',
                     'internal/mobilemultihop/node_chain_openvpn_execution_native_fixture_test.go'):
        identity[relative] = sha((ROOT/relative).read_bytes())
    return sha(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode())


def execute(command, cwd, env, limit):
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=limit)
    print(result.stdout, end='', flush=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='', flush=True)
    return result


def verdict(parser, result):
    if 'DATA RACE' in result.stderr:
        raise ValueError('native OpenVPN test raced on stderr')
    return parser.verdict(result.stdout, result.returncode)


def rejected(result, selected, witness):
    output = result.stdout+'\n'+result.stderr
    if result.returncode != 1 or any(marker in output for marker in
                                    ('DATA RACE', 'build failed', 'panic:', 'fatal error:', 'test timed out')):
        return False
    return POSITIVE.rejected(result.stdout, result.returncode, selected, witness)


def run(core, go, tags, race, ldflags, receipt=None, tagged_only=False):
    core = core.absolute()
    if 'with_openvpn' not in tags.split(','):
        raise ValueError('positive native OpenVPN gate requires actual implementation')
    source = verify(core, desktop=tagged_only)
    env = dict(os.environ, GOMAXPROCS='1')
    flags = ['-p=1', '-mod=readonly', '-count=1'] + (['-race'] if race else [])
    with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-execution-owner-') as temporary:
        temporary = Path(temporary)
        assets = temporary/'fixtures'; assets.mkdir()
        env['ROUTERVPN_OPENVPN_EXECUTION_NATIVE_FIXTURES'] = str(assets)
        generator = execute([go, 'test', '-json', *flags, '-timeout=120s', './internal/mobilemultihop',
                             '-run', '^TestNodeChainOpenVPNExecutionNativeFixtures$'], ROOT, env, 300)
        generated = verdict(GENERATOR, generator)
        if set(p.name for p in assets.iterdir()) != {name+'.json' for name in FIXTURES}:
            raise ValueError('native OpenVPN requires every actual shared private fixture')
        fixture_hashes = {p.name: sha(p.read_bytes()) for p in assets.iterdir()}
        command = [go, 'test', '-json', *flags, '-timeout=120s', '-tags', tags]
        if ldflags:
            command += ['-ldflags', ldflags]
        baseline = execute([*command, '.', '-run', POSITIVE.selection()], core, env, 900)
        positive = verdict(POSITIVE, baseline)
        stub = None
        if not tagged_only:
            # Both mobile pipelines require this second actual compilation.
            # Desktop's additional endpoint fixtures import OpenVPN directly;
            # their shipped builds require its tag and run the positive phase.
            stub_tags = ','.join(tag for tag in tags.split(',') if tag != 'with_openvpn')
            stub_command = [go, 'test', '-json', *flags, '-timeout=120s', '-tags', stub_tags]
            if ldflags:
                stub_command += ['-ldflags', ldflags]
            stub = verdict(STUB, execute([*stub_command, '.', '-run', STUB.selection()], core, env, 900))
        for label, relative, before, after, selected, witness in CONTROLS:
            original = core/relative
            content = original.read_text()
            if content.count(before) != 1:
                raise ValueError('native OpenVPN causal source changed: '+label)
            mutant = temporary/'mutant.go'
            mutant.write_text(content.replace(before, after, 1))
            overlay = temporary/'overlay.json'
            overlay.write_text(json.dumps({'Replace': {str(original): str(mutant)}}))
            result = execute([*command, '-overlay', str(overlay), '.', '-run',
                              '^'+PREFIX+selected.replace('/', '$/^')+'$'], core, env, 600)
            if not rejected(result, selected, witness):
                raise ValueError('native OpenVPN compiled control missed its witness: '+label)
            print('Native OpenVPN causal refusal PASS:', label, flush=True)
        if verify(core, desktop=tagged_only) != source or any(sha((assets/name).read_bytes()) != digest for name, digest in fixture_hashes.items()):
            raise ValueError('native OpenVPN source or original fixture changed during execution')
    result = {'schema': 1, 'core': NATIVE.PIN, 'source_sha256': source, 'race': race,
              'generator': generated, 'native': positive, 'without_openvpn': stub, 'tagged_only': tagged_only,
              'causal_controls': len(CONTROLS), 'fixture_sha256': fixture_hashes,
              'scope': 'original native construction, equality, Last and reader transactions; encrypted/host acceptance separate'}
    if receipt:
        Path(receipt).write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps(result, sort_keys=True), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', default='with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego')
    parser.add_argument('--race', action='store_true')
    parser.add_argument('--ldflags', default='-checklinkname=0')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--tagged-only', action='store_true', help='Desktop: validate the required tagged implementation; both mobile builds additionally require the no-OpenVPN variant')
    args = parser.parse_args()
    run(args.core, args.go, args.tags, args.race, args.ldflags, args.receipt, args.tagged_only)
