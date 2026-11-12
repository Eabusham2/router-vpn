#!/usr/bin/env python3
"""Actual libbox/daemon execution ownership components, with explicit native boundaries.

No TUN, encrypted endpoint, private deployment or PQ diagnostic executes here.
The complete already-prepared mobile core is required; ordinary native tags
compile the real adapters, while named component tests exercise owned lifetime.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'github.com/sagernet/sing-box/'
TAGS = 'with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego'
spec = importlib.util.spec_from_file_location('mobile_execution_component_preparer', ROOT/'deploy/prepare-mobile-node-chain-execution.py')
PREP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)


def inventory():
    result = {}
    for template, target in PREP.TEMPLATES.items():
        if not target.endswith('_test.go'):
            continue
        package = str(Path(target).parent)
        source = (ROOT/'mobile/chain_execution'/template).read_text()
        names = re.findall(r'^func (Test(?:RouterNodeChainExecutionBridge|RouterVPNInstanceClose(?:Receipt|Capture))\w+)\(t \*testing.T\)', source, re.M)
        if not names or len(names) != len(set(names)):
            raise ValueError('missing or duplicate mobile execution test roots')
        previous = result.setdefault(package, set())
        if previous.intersection(names):
            raise ValueError('duplicate mobile execution package root')
        previous.update(names)
    if set(result) != {'experimental/libbox', 'daemon'}:
        raise ValueError('mobile execution component package inventory changed')
    return result


def verdict(raw, code, expected):
    if code != 0:
        raise ValueError('mobile execution component command failed')
    seen, passed, finished, started, records = {}, {}, set(), set(), []
    for line in raw.splitlines():
        event = json.loads(line)
        package = event.get('Package', '').removeprefix(PREFIX)
        action, name = event.get('Action'), event.get('Test')
        if package not in expected or package in finished or action in ('fail', 'skip') or 'DATA RACE' in event.get('Output', ''):
            raise ValueError('foreign, late, failed, skipped or racing component receipt')
        runs, passes = seen.setdefault(package, set()), passed.setdefault(package, set())
        if name:
            if package not in started or name.split('/')[0] not in expected[package]:
                raise ValueError('unstarted or unexpected component test')
            if action == 'run':
                if name in runs or any(name == item or name.startswith(item+'/') for item in passes):
                    raise ValueError('duplicate or late component work')
                runs.add(name)
            elif action == 'pass':
                if name not in runs or name in passes or any(item.startswith(name+'/') and item not in passes for item in runs):
                    raise ValueError('missing run or incomplete component child')
                passes.add(name); records.append(line)
            elif action not in ('output', 'pause', 'cont'):
                raise ValueError('unknown named component event')
        elif action == 'start':
            if package in started: raise ValueError('duplicate package start')
            started.add(package)
        elif action == 'pass':
            if package not in started or not expected[package].issubset(passes) or runs != passes:
                raise ValueError('missing original component acceptance')
            finished.add(package)
        elif action != 'output':
            raise ValueError('unknown component package event')
    if finished != set(expected):
        raise ValueError('incomplete component package inventory')
    return records


CONTROLS = (
    ('observed owner cannot return', 'experimental/libbox/routervpn_node_chain_execution_lifecycle.go',
     '\t\tif failure != nil && ctx.Err() == nil && state.cancel != nil {\n\t\t\tstate.cancel()\n\t\t}', '',
     'experimental/libbox', 'TestRouterNodeChainExecutionBridgeObservedOwnerCannotReturn/instance', 'observed foreign owner revived after pointer restoration'),
    ('pending startup lifetime', 'experimental/libbox/routervpn_node_chain_execution_lifecycle.go', '\t\tstate.cancel()\n\t\tclose(a.done)', '\t\tclose(a.done)', 'experimental/libbox', 'TestRouterNodeChainExecutionBridgeStartupBudgetOwnsPendingLifetime', 'expired startup budget did not retire original runtime'),
    ('successful lifetime independence', 'experimental/libbox/routervpn_node_chain_execution_lifecycle.go', '\tif !a.committed {', '\tif true {', 'experimental/libbox', 'TestRouterNodeChainExecutionBridgeSuccessfulLifetimeOutlivesStartup', 'successful admission close retired runtime'),
    ('original daemon failure', 'daemon/routervpn_instance_close.go', '\tif result != nil {\n\t\treturn result\n\t}', '\t_ = result', 'daemon', 'TestRouterVPNInstanceCloseReceiptPreservesFailure', 'failed native close became successful receipt'),
    ('exact original instance', 'experimental/libbox/routervpn_node_chain_execution_lifecycle.go', 'current != state.instance ||', '(current != state.instance && false) ||', 'experimental/libbox', 'TestRouterNodeChainExecutionBridgeNativeOwnerIdentityAndDeadline/instance', 'replaced native execution owner retained authority'),
    ('original remote join', 'experimental/libbox/routervpn_node_chain_execution_lifecycle.go', '\t\tif err := controller.value.CloseContext(ctx); err != nil {\n\t\t\treturn err\n\t\t}', '\t\t_ = controller.value.CloseContext(ctx)', 'experimental/libbox', 'TestRouterNodeChainExecutionBridgeRemoteJoinPrecedesNativeRetirement', 'unjoined remote stop allowed native teardown'),
    ('late owned native handle', 'experimental/libbox/routervpn_node_chain_execution_lifecycle.go', '\t\tstate.engine.Store(&routerNodeChainExecutionEngineRef{engine})', '\t\t_ = engine', 'experimental/libbox', 'TestRouterNodeChainExecutionBridgeRetainsLatePartialFactory', 'late owned native handle was lost'),
    ('original physical cleanup server', 'experimental/libbox/routervpn_node_chain_execution_lifecycle.go', 'state.server != server ||', '', 'experimental/libbox', 'TestRouterNodeChainExecutionBridgeRemoteJoinPrecedesNativeRetirement', 'foreign server borrowed cleanup authority'),
    ('recorded original construction', 'daemon/instance.go', '\tcapturedInstance = i\n', '\t_ = i\n', 'daemon', 'TestRouterVPNInstanceCloseCaptureActualConstructorAndClose/joined', 'actual constructor did not retain original instance'),
    ('sealed construction refusal', 'daemon/routervpn_instance_capture.go', ' || capture.sealed {', ' {', 'daemon', 'TestRouterVPNInstanceCloseCaptureProvesEmptyAcquisition/never-started', 'positive empty receipt allowed later native construction'),
    ('sealed no-acquisition receipt', 'daemon/routervpn_instance_capture.go', '\tif !sealed {', '\tif !sealed && false {', 'daemon', 'TestRouterVPNInstanceCloseCaptureProvesEmptyAcquisition/never-started', 'unsealed empty slot fabricated receipt'),
    ('uncertain Box acquisition', 'daemon/routervpn_instance_capture.go', 'failure == nil || attempted', 'failure == nil || (attempted && false)', 'daemon', 'TestRouterVPNInstanceCloseCaptureRefusesUnreturnedBox', 'attempted Box construction fabricated no-acquisition receipt'),
)


def command(go, packages, selected, overlay=None):
    result = [go, 'test', '-json', '-race', '-mod=readonly', '-p=1', '-count=1', '-timeout=180s', '-tags='+TAGS, '-ldflags=-checklinkname=0']
    if overlay is not None:
        result.append('-overlay='+str(overlay))
    return result+['./'+name for name in packages]+['-run', selected]


def execute(vendor, go):
    PREP.prepare(vendor)
    expected = inventory()
    environment = dict(os.environ, GOMAXPROCS='1', GOGC='20', GOMEMLIMIT='1536MiB')
    selected = '^('+'|'.join(sorted(set.union(*expected.values())))+')$'
    run = subprocess.run(command(go, expected, selected), cwd=vendor, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
    try:
        records = verdict(run.stdout, run.returncode, expected)
    except (ValueError, TypeError):
        print(run.stdout); raise
    for record in records: print(record)
    print('Actual mobile execution ownership:', sum(map(len, expected.values())), 'roots,', len(records), 'PASS records')
    for label, file, before, after, package, test, witness in CONTROLS:
        target = vendor/file
        original = target.read_text()
        if original.count(before) != 1: raise ValueError('causal mobile boundary changed: '+label)
        with tempfile.TemporaryDirectory(prefix='routervpn-mobile-execution-control-') as directory:
            changed, overlay = Path(directory)/target.name, Path(directory)/'overlay.json'
            changed.write_text(original.replace(before,after,1))
            overlay.write_text(json.dumps({'Replace':{str(target):str(changed)}}))
            selection = '/'.join('^'+re.escape(part)+'$' for part in test.split('/'))
            run = subprocess.run(command(go,[package],selection,overlay),cwd=vendor,env=environment,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
        events=[]
        for line in run.stdout.splitlines():
            try: events.append(json.loads(line))
            except ValueError: pass
        root=test.split('/')[0]
        entered=any(e.get('Action')=='run' and e.get('Test')==root for e in events)
        failed=any(e.get('Action')=='fail' and e.get('Test')==root for e in events)
        causal=any(e.get('Action')=='output' and e.get('Test','').startswith(root) and witness in e.get('Output','') for e in events)
        if run.returncode==0 or not entered or not failed or not causal or any('DATA RACE' in e.get('Output','') for e in events):
            print(run.stdout);raise ValueError('causal mobile execution witness missing: '+label)
        if target.read_text()!=original: raise ValueError('causal overlay changed original source')
        print('Causal mobile execution refusal PASS:',label,'/',witness)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor',type=Path,required=True)
    parser.add_argument('--go',default='go')
    args=parser.parse_args()
    execute(args.vendor.resolve(),args.go)
