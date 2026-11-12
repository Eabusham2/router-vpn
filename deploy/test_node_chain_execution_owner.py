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
              'NativeFailedAcquisitionRetainsSealedStop', 'NativeDuplicateBindKeepsOriginalOwner',
              'NativeCloseReceipt', 'NativeLastUsesOriginalDiscovery', 'NativeLastRetainsPendingPlan',
              'NativeLastAdoptsFreshClosedGraph', 'NativeLastCleanupRetainsExactPlan',
              'NativeLastRejectsKindSubstitution', 'NativeLastRejectsForeignAdmission',
              'NativeLastRuntimeRejectsForeignEngine', 'NativeLastJoinsBeforeNativeAppend',
              'NativeAdoptionRejectsRetainedSourceReplacement',
              'NativeMTUUsesJoinedReader', 'NativeMTURejectsChangedOwnership',
              'NativeMTUReadbackAndRetirementRemainOwned',
              'NativeTUNReadbackRetainsOriginal', 'NativeTUNReadbackRejectsAwayAndBack',
              'NativeTUNReadbackRequiresJoinedClose', 'NativeTUNReadbackRejectsReplacedReader',
              'NativeTUNReadbackRejectsInCaptureChange', 'NativeTUNReadbackKeepsTypedTarget', 'NativeTUNReadbackRetainsLateClosedLedger'),
    PACKAGE+'/protocol/tun': ('TUNMTUReadbackRequiresActualOwner', 'TUNTypedReadbackRequiresActualOwner'),
    PACKAGE+'/adapter/outbound': ('AppendPreservesActualManagers', 'AppendRejectsForeignOwnerAndLifecycle',
                                 'AppendConcurrentTagHasOneOriginalWinner'),
}
CHILDREN = {
    'NativeTUNReadbackRejectsInCaptureChange': ('name', 'index', 'mtu'),
    'NativeTUNReadbackKeepsTypedTarget': ('generic', 'linux', 'windows', 'darwin', 'missing'),
    'TUNTypedReadbackRequiresActualOwner': ('nil', 'unstarted', 'cancelled', 'locked'),
    'NativeLastAdoptsFreshClosedGraph': ('auto-local', 'auto-server', 'server-server'),
    'NativeLastCleanupRetainsExactPlan': ('retry', 'changed-choice', 'changed-target', 'changed-port'),
    'NativeLastRejectsKindSubstitution': ('last-ordinary', 'last-restore', 'ordinary-last', 'restore-last', 'ordinary-restore', 'restore-ordinary'),
    'NativeLastRejectsForeignAdmission': ('zero', 'foreign-preparation', 'peer', 'range', 'before-discovery', 'cancelled', 'retired-source', 'foreign-discovery'),
    'NativeAdoptionRejectsRetainedSourceReplacement': ('owner', 'projection'),
    'NativeTUNReadbackRetainsOriginal': ('android', 'ios'),
    'NativeTUNReadbackRejectsAwayAndBack': ('name', 'index', 'mtu', 'invalid-mtu', 'source', 'read-error'),
    'NativeTUNReadbackRequiresJoinedClose': ('success', 'original-error'),
    'NativeLastUsesOriginalDiscovery': ('local', 'server'),
    'NativeCloseReceipt': ('success', 'original-error'),
    'NativeMTUUsesJoinedReader': ('candidate', 'rollback', 'unchanged', 'pending-close'),
    'NativeMTURejectsChangedOwnership': ('zero-binding', 'foreign-identity', 'foreign-engine', 'foreign-selector', 'open-gate', 'retired-source', 'invalid-fixed', 'above-bound', 'cancelled', 'foreign-reader'),
    'TUNMTUReadbackRequiresActualOwner': ('nil', 'unstarted', 'cancelled', 'locked'),
    'NativeRetainsOneGraphThroughDiscovery': ('auto', 'server'),
    'NativeRejectsActualGraphSubstitution': ('mtu', 'dns', 'rule', 'entry-key'),
    'AppendRejectsForeignOwnerAndLifecycle': ('entry', 'gate', 'detour', 'lifecycle', 'cancelled', 'closed-manager'),
}
PREFIX = 'TestRouterVPNExecution'


def selection():
    return '^'+PREFIX+'('+'|'.join(sorted({name for roots in ROOTS.values() for name in roots}))+')$'


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
    ('actual typed native reader', 'routervpn_node_chain_execution_readback.go', 'return routerVPNExecutionMTUReadback{}, errRouterVPNExecutionOwner', 'return routerVPNExecutionMTUReadback{"original-tun", 14, 1400}, nil', '.', 'NativeTUNReadbackKeepsTypedTarget', 'typed native reader accepted a component TUN'),
    ('exact original typed target', 'routervpn_node_chain_execution_readback.go', ' || target != metadata.TargetOS', ' || metadata.TargetOS == "never"', '.', 'NativeTUNReadbackKeepsTypedTarget/windows', 'native target substituted original typed platform'),
    ('two actual native observations', 'routervpn_node_chain_execution_readback.go', 'confirmErr != nil || confirmed != actual', 'confirmErr != nil || confirmed.name == "never"', '.', 'NativeTUNReadbackRejectsInCaptureChange/name', 'single native observation accepted an interface changed during capture'),
    ('closed native ledger after Box join', 'routervpn_node_chain_execution_readback.go', 'closed, err := capture.control.ObserveClosedContext(ctx)', 'closed, err := G.State{Identity: e.gateID, Closed: true, Drained: true}, error(nil)', '.', 'NativeTUNReadbackRetainsLateClosedLedger', 'completed Box close hid a late unjoined native gate input'),
    ('Last join before native append', 'routervpn_node_chain_execution.go', '\tif last != nil {\n\t\tif err := last.plan.RequireJoinedContext(ctx); err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t}\n', '', '.', 'NativeLastJoinsBeforeNativeAppend', 'unjoined Last plan changed original native graph'),
    ('exact native retry kind', 'routervpn_node_chain_execution.go', 'if captured.kind != kind || captured.owner != owner || captured.projection != projection || captured.original != originalSource || captured.last != last || captured.lastSource != lastSource {', 'if false {', '.', 'NativeLastRejectsKindSubstitution/ordinary-restore', 'cleanup retry borrowed another native adoption kind'),
    ('original Last saved choice', 'routervpn_node_chain_execution_last.go', ' || retained.raw != last.JSON()', '', '.', 'NativeLastCleanupRetainsExactPlan/changed-choice', 'Last cleanup retry accepted a replacement saved record'),
    ('original native discovery on retry', 'routervpn_node_chain_execution.go', ' || captured.owner != owner', '', '.', 'NativeAdoptionRejectsRetainedSourceReplacement/owner', 'pending native adoption accepted replacement owner'),
    ('original native projection on retry', 'routervpn_node_chain_execution.go', ' || captured.projection != projection', '', '.', 'NativeAdoptionRejectsRetainedSourceReplacement/projection', 'pending native adoption accepted replacement projection'),
    ('readback original native close', 'routervpn_node_chain_execution_readback.go',
     '\tif err := capture.close.JoinContext(ctx, capture.instance); err != nil {\n\t\treturn err\n\t}\n', '',
     '.', 'NativeTUNReadbackRequiresJoinedClose/success', 'retired gate substituted for original actual Box close'),
    ('exact retained native readback', 'routervpn_node_chain_execution_readback.go',
     'capture.value != value || ', '',
     '.', 'NativeTUNReadbackRequiresJoinedClose/success', 'retired readback accepted a caller-forged observation'),
    ('retained Last adoption slot', 'routervpn_node_chain_execution.go',
     '\tif e.last != nil {\n\t\treturn nil, errRouterVPNExecutionOwner\n\t}\n', '',
     '.', 'NativeLastRetainsPendingPlan', 'normal adoption consumed the original Last plan'),
    ('original Last discovery owner', 'routervpn_node_chain_execution_last.go',
     'retained.owner != owner || ', '',
     '.', 'NativeLastRetainsPendingPlan', 'Last retry accepted another discovery owner'),
    ('actual native close join', 'routervpn_node_chain_execution_close.go',
     '\tselect {\n\tcase <-ctx.Done():\n\t\treturn ctx.Err()\n\tcase <-done:\n\t}\n', '',
     '.', 'NativeCloseReceipt/success', 'early done or service slot fabricated joined native close'),
    ('original native close error', 'routervpn_node_chain_execution_close.go',
     '\treturn errors.Join(err, ctx.Err())', '\t_ = err\n\treturn ctx.Err()',
     '.', 'NativeCloseReceipt/original-error', 'native receipt discarded original close result'),
    ('native MTU readback', 'routervpn_node_chain_execution_mtu.go',
     'actual, err := read(ctx, op.result.inbound)', 'actual, err := op.observed, error(nil)',
     '.', 'NativeMTUUsesJoinedReader/candidate', 'public native readback accepted a component TUN double'),
    ('original MTU engine', 'routervpn_node_chain_execution_mtu.go',
     '\t\t!binding.OwnsEngine(e) ||\n', '',
     '.', 'NativeMTURejectsChangedOwnership/foreign-engine', 'changed ownership acquired native MTU transaction'),
    ('MTU retained execution', 'routervpn_node_chain_execution.go',
     ' || tag != op.binding.SelectedTag()', '',
     '.', 'NativeMTUUsesJoinedReader/candidate', 'MTU resume reselected another execution'),
    ('MTU pending native retirement', 'routervpn_node_chain_execution.go',
     '\tif err := e.retireMTUContext(ctx); err != nil {\n\t\treturn err\n\t}\n', '',
     '.', 'NativeMTUReadbackAndRetirementRemainOwned', 'retired source abandoned original unused reader'),
    ('MTU fixed bounds', 'routervpn_node_chain_execution_mtu.go',
     ' || mtu < 1280 || mtu > plan.Ceiling', '',
     '.', 'NativeMTURejectsChangedOwnership/invalid-fixed', 'changed ownership acquired native MTU transaction'),
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
    selected_packages = ['.'+package.removeprefix(PACKAGE) for package in ROOTS]
    selected_roots = '^('+ '|'.join(PREFIX+name for names in ROOTS.values() for name in names)+')$'
    baseline = subprocess.run([*command, *selected_packages, '-run', selected_roots], cwd=core,
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
