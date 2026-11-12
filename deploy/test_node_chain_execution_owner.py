#!/usr/bin/env python3
"""Execute original native execution ownership and causal refusal checks.

Uses real pinned managers, selector, application gate, shared runtime and HTTP.
The TUN, physical monitor, encrypted prefix and DNS transport are explicit test
boundaries; this is not device, encrypted-path or privileged-host acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'github.com/sagernet/sing-box'
ROOTS = {
    PACKAGE: ('NativeRetainsOneGraphThroughDiscovery', 'NativeRejectsActualGraphSubstitution',
              'NativeDNSRejectsAwayAndBackSelection', 'NativeGateRejectsForeignProofAndRetiredSelection',
              'NativeOpenCannotFinishAfterRevoke', 'NativeDiscoveryKeepsLiteralOriginalEntry',
              'NativeRestoreRetainsOriginalFront', 'NativeRetiredSourceKeepsClosedReceipt',
              'NativeFailedAcquisitionRetainsSealedStop', 'NativeDuplicateBindKeepsOriginalOwner', 'NativeCloseReceipt'),
    PACKAGE+'/adapter/outbound': ('AppendPreservesActualManagers', 'AppendRejectsForeignOwnerAndLifecycle',
                                 'AppendConcurrentTagHasOneOriginalWinner'),
}
CHILDREN = {
    'NativeCloseReceipt': ('success', 'original-error'),
    'NativeRetainsOneGraphThroughDiscovery': ('auto', 'server'),
    'NativeRejectsActualGraphSubstitution': ('mtu', 'dns', 'rule', 'entry-key'),
    'AppendRejectsForeignOwnerAndLifecycle': ('entry', 'gate', 'detour', 'lifecycle', 'cancelled', 'closed-manager'),
}
PREFIX = 'TestRouterVPNExecution'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load('execution_owner_prep', 'prepare-node-chain-execution-owner.py')
ADMISSION = load('execution_owner_admission', 'prepare-node-chain-execution.py')
GATE = load('execution_owner_gate', 'prepare-node-chain-execution-gate.py')


def expected(package):
    return {PREFIX+name+suffix for name in ROOTS[package]
            for suffix in ('', *('/'+child for child in CHILDREN.get(name, ())))}


def verdict(raw, code):
    if code != 0:
        raise ValueError('native execution owner command failed')
    runs = {p: set() for p in ROOTS}
    passes = {p: set() for p in ROOTS}
    packages = set()
    for line in raw.splitlines():
        try:
            row = json.loads(line)
        except (ValueError, TypeError) as error:
            raise ValueError('non-JSON native execution owner verdict') from error
        if not isinstance(row, dict) or row.get('Package') not in ROOTS:
            raise ValueError('foreign native execution package')
        package, action, name = row['Package'], row.get('Action'), row.get('Test')
        if package in packages or action in ('fail', 'skip') or 'DATA RACE' in row.get('Output', ''):
            raise ValueError('failed, skipped, late or racing native owner verdict')
        if name:
            if name not in expected(package):
                raise ValueError('native execution test inventory changed')
            if action == 'run':
                if name in runs[package] or any(name.startswith(parent+'/') for parent in passes[package]):
                    raise ValueError('duplicate or late native execution test')
                runs[package].add(name)
            elif action == 'pass':
                if name not in runs[package] or name in passes[package] or any(child.startswith(name+'/') and child not in passes[package] for child in runs[package]):
                    raise ValueError('unrun, repeated or incomplete native execution pass')
                passes[package].add(name)
            elif action not in ('output', 'pause', 'cont'):
                raise ValueError('unexpected native execution action')
        elif action == 'pass':
            if runs[package] != expected(package) or passes[package] != runs[package]:
                raise ValueError('incomplete native execution owner inventory')
            packages.add(package)
        elif action not in ('start', 'output'):
            raise ValueError('unexpected native execution package action')
    if packages != set(ROOTS):
        raise ValueError('missing native execution package verdict')
    return {'roots': sum(map(len, ROOTS.values())), 'test_records': sum(map(len, passes.values()))}


def verify(core):
    if subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip() != PREP.PIN:
        raise ValueError('native owner lost original core pin')
    record = json.loads((core/PREP.OWNER).read_bytes())
    wanted = {name: hashlib.sha256((ROOT/'mobile/chain'/template).read_bytes()).hexdigest()
              for template, name in PREP.TEMPLATES.items()}
    if record != {'schema': 1, 'core': PREP.PIN, 'files': wanted}:
        raise ValueError('native owner source inventory changed')
    for name, checksum in wanted.items():
        path = PREP.target(core, name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
            raise ValueError('native owner source changed')
    if PREP.box_source((core/'box.go').read_text()) != (core/'box.go').read_bytes():
        raise ValueError('native Box lost original construction snapshot')
    if PREP.daemon_source((core/'daemon/started_service.go').read_text()) != (core/'daemon/started_service.go').read_bytes():
        raise ValueError('native daemon lost original close failure')
    ADMISSION.verify_current_templates(core)
    for template, relative in GATE.TEMPLATES.items():
        if GATE.destination(core, relative).read_bytes() != (ROOT/'mobile/chain_gate'/template).read_bytes():
            raise ValueError('native owner lost original application gate')
    return PREP.digest()


CONTROLS = (
    ('actual native close join', 'routervpn_node_chain_execution_close.go',
     '\tselect {\n\tcase <-ctx.Done():\n\t\treturn ctx.Err()\n\tcase <-done:\n\t}\n', '',
     '.', 'NativeCloseReceipt/success', 'early done or service slot fabricated joined native close'),
    ('original native close error', 'routervpn_node_chain_execution_close.go',
     '\treturn errors.Join(err, ctx.Err())', '\t_ = err\n\treturn ctx.Err()',
     '.', 'NativeCloseReceipt/original-error', 'native receipt discarded original close result'),
    ('actual construction graph', 'routervpn_node_chain_execution.go',
     'err != nil || routerVPNNodeChainExecutionOptionsDigest(s.ctx, options) != s.routerVPNNodeChainExecutionOptions', 'err != nil',
     '.', 'NativeRejectsActualGraphSubstitution/mtu', 'changed actual graph acquired native preparation'),
    ('selected DNS epoch', 'routervpn_node_chain_execution.go',
     'epoch != e.selector.RouterVPNNodeChainSelectionEpoch() {', 'epoch == 0 {',
     '.', 'NativeDNSRejectsAwayAndBackSelection', 'away-and-back selected DNS proof was accepted'),
    ('pending native admission', 'routervpn_node_chain_execution.go',
     '\te.admission.Add(1)\n', '',
     '.', 'NativeOpenCannotFinishAfterRevoke', 'older pending native open completed after revoke'),
    ('retired original cleanup', 'routervpn_node_chain_execution.go',
     'closed, err := e.control.ObserveRetired(ctx)', 'closed, err := e.control.Observe(ctx)',
     '.', 'NativeRetiredSourceKeepsClosedReceipt', 'retired source stranded closed native receipt'),
    ('exact managed default gate', 'adapter/outbound/routervpn_node_chain_execution.go',
     'm.defaultOutbound != gate || m.outboundByTag[gate.Tag()] != gate ||', '',
     './adapter/outbound', 'AppendRejectsForeignOwnerAndLifecycle/gate', 'foreign/retired append was accepted'),
)


def rejected(raw, code, selected, witness):
    if code == 0:
        return False
    rows = []
    for line in raw.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    name = PREFIX+selected
    return (any(row.get('Action') == 'run' and row.get('Test') == name for row in rows)
            and any(row.get('Action') == 'fail' and row.get('Test') == name for row in rows)
            and any(row.get('Test') == name and witness in row.get('Output', '') for row in rows)
            and not any('DATA RACE' in row.get('Output', '') or 'build failed' in row.get('Output', '') for row in rows))


def run(core, go, tags, race, ldflags, receipt):
    core = core.absolute()
    PREP.prepare(core)
    source = verify(core)
    command = [go, 'test', '-json', '-p=1', '-mod=readonly', '-count=1', '-timeout=120s']
    if race:
        command.append('-race')
    if tags:
        command.extend(['-tags', tags])
    if ldflags:
        command.extend(['-ldflags', ldflags])
    environment = dict(os.environ, GOMAXPROCS='1')
    baseline = subprocess.run([*command, '.', './adapter/outbound', '-run', '^'+PREFIX], cwd=core,
                              env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
    try:
        result = verdict(baseline.stdout, baseline.returncode)
    except ValueError:
        print(baseline.stdout, end='')
        raise
    print(baseline.stdout, end='')
    with tempfile.TemporaryDirectory(prefix='ordered-native-owner-controls-') as temporary:
        for label, relative, before, after, package, selected, witness in CONTROLS:
            original = PREP.target(core, relative)
            text = original.read_text()
            if text.count(before) != 1:
                raise ValueError('native owner causal boundary changed: '+label)
            target = Path(temporary)/'mutant.go'
            target.write_text(text.replace(before, after, 1))
            overlay = Path(temporary)/'overlay.json'
            overlay.write_text(json.dumps({'Replace': {str(original): str(target)}}))
            test = subprocess.run([*command, '-overlay', str(overlay), package, '-run', '^'+PREFIX+selected.replace('/', '$/^')+'$'],
                                  cwd=core, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            if not rejected(test.stdout, test.returncode, selected, witness):
                print(test.stdout, end='')
                raise ValueError('compiled original ownership control missed witness: '+label)
            print('Causal native owner refusal PASS:', label, '/', witness, flush=True)
    if verify(core) != source:
        raise ValueError('native owner source changed during execution')
    result.update(schema=1, source_sha256=source, core=PREP.PIN, race=race, causal_controls=len(CONTROLS),
                  scope='native ownership and shared control; privileged TUN/encrypted acceptance separate')
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
    args = parser.parse_args()
    run(args.core, args.go, args.tags, args.race, args.ldflags, args.receipt)
