#!/usr/bin/env python3
"""Execute the shipping retained-startup helper and causal controls.

This portable race suite grants no PF/WFP/TUN or installed-host acceptance.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('node_startup_race', ROOT/'deploy/darwin_race_toolchain.py')
RACE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RACE)


def check():
    source = (ROOT/'mobile/desktop/node_startup_lifecycle.go.tmpl').read_text()
    test = (ROOT/'mobile/desktop/node_startup_lifecycle_test.go.tmpl').read_text()
    # Check the actual constructor handoff in every outer producer. Native
    # integration still compiles/runs those complete producers separately.
    for name in ('node_chain_run_darwin', 'node_chain_execution_run_darwin', 'node_candidate_prefix_run_darwin', 'node_command_run_linux', 'mtu_node'):
        raw = (ROOT/'mobile/desktop'/(name+'.go.tmpl')).read_text()
        begin = raw.index('instance, ')
        capture = raw.index('native.startupOwner.original = instance', begin)
        transfer = raw.index('stopConstruction()', capture)
        start = raw.index('native.startupOwner.start(', transfer)
        if not begin < capture < transfer < start or 'watchStop, watchDone' in raw:
            raise AssertionError('Original constructor watcher transfer changed: '+name)
    controls = (
        ('watcher', 'close(stop); <-done', 'close(stop)', 'cancel-transfer-join', 'constructor transfer returned before cancellation joined'),
        ('middle', 'owner.original.RouterVPNCloseSOCKSMiddle', 'func() error { return nil }', 'exact-order', 'middle did not precede original graph cancellation'),
        ('startup', 'if owner.startup != nil {', 'if false {', 'held-startup', 'unjoined startup admitted native teardown'),
        ('duplicate', ' || owner.startup != nil', '', 'duplicate-start', 'startup replaced its original worker'),
    )
    with tempfile.TemporaryDirectory(prefix='node-startup-lifecycle-') as temporary:
        directory = Path(temporary)
        (directory/'go.mod').write_text('module github.com/sagernet/sing-box\n\ngo 1.26.3\n')
        code = directory/'startup.go'
        (directory/'startup_test.go').write_text(test)
        for label, before, after, leaf, witness in (('baseline', '', '', '', ''), *controls):
            if before and source.count(before) != 1:
                raise AssertionError('Changed original startup control: '+label)
            code.write_text(source.replace(before, after, 1) if before else source)
            command = ['go', 'test', '-race', '-count=1', '-timeout=10s', '-v']
            if leaf: command += ['-run=^TestRouterVPNNodeStartupOwnership$/^'+leaf+'$']
            command, environment = RACE.command(command, directory, dict(os.environ))
            result = subprocess.run(command, cwd=directory, env=environment, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
            if not witness:
                if result.returncode or result.stdout.count('--- PASS: TestRouterVPNNodeStartupOwnership/') != 9:
                    raise AssertionError(result.stdout)
            elif result.returncode != 1 or witness not in result.stdout or any(value in result.stdout for value in ('WARNING: DATA RACE', 'panic:', '[build failed]', 'test timed out')):
                raise AssertionError(label+': original causal failure missing\n'+result.stdout)
            print('Original startup lifecycle: '+label+' verified', flush=True)
        # Execute the actual Darwin retirement state machine on portable
        # component doubles already used by its native suite. Only its native
        # workspace/receipt publisher is outside this extracted unit.
        owner = (ROOT/'mobile/desktop/node_chain_retirement_darwin.go.tmpl').read_text().split('// finish is the sole native stopped-receipt producer.', 1)[0]
        owner = owner.removeprefix('//go:build darwin\n\n').replace('\t"github.com/sagernet/sing-box/routervpn/macosprocess"\n', '')
        owner_tests = (ROOT/'mobile/desktop/node_chain_retirement_darwin_test.go.tmpl').read_text().split('func TestRouterVPNNodeChainDarwinStoppedReceipt', 1)[0]
        owner_tests = owner_tests.removeprefix('//go:build darwin\n\n').replace('\t"encoding/json"\n', '').replace('\t"os"\n', '')
        lock = directory/'routervpn/desktopnetwork'
        lock.mkdir(parents=True)
        (lock/'lock.go').write_bytes((ROOT/'internal/desktopnetwork/desktop_network_lock.go').read_bytes())
        (directory/'failure.go').write_text('package main\nimport "errors"\nvar routerVPNExternalFailure = errors.New("original external failure")\n')
        (directory/'retirement_test.go').write_text(owner_tests)
        code.write_text(source)
        for mutated in (False, True):
            (directory/'retirement.go').write_text(owner.replace('if owner.startupOwner != nil {', 'if false {', 1) if mutated else owner)
            selection = '^TestRouterVPNNodeChainDarwinNativeRetirement'
            if mutated: selection += 'Order$/^middle-before-cancel$'
            command = ['go','test','-race','-count=1','-timeout=10s','-v','-run='+selection]
            command, environment = RACE.command(command, directory, dict(os.environ))
            result = subprocess.run(command,cwd=directory,env=environment,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
            if not mutated:
                if result.returncode or sum('--- PASS: TestRouterVPNNodeChainDarwinNativeRetirement' in line and '/' in line for line in result.stdout.splitlines()) != 15:
                    raise AssertionError(result.stdout)
            elif result.returncode != 1 or 'outer native cleanup bypassed original middle join' not in result.stdout or any(value in result.stdout for value in ('WARNING: DATA RACE','panic:','[build failed]','test timed out')):
                raise AssertionError(result.stdout)
            print('Original Darwin retirement component: '+('control' if mutated else 'baseline')+' verified',flush=True)



if __name__ == '__main__': check()
