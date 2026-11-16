#!/usr/bin/env python3
"""Require typed SOCKS desktop child/Box components, without a kernel claim."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'github.com/sagernet/sing-box'
TAGS = 'with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego'
PREFIX = 'TestRouterVPNDesktopSOCKSExecution'
CASES = {
    '.': {
        PREFIX+'PhysicalActualBox': ('server', 'auto'),
        PREFIX+'PhysicalRefusesChangedGraph': ('middle-user', 'middle-password', 'middle-detour', 'final-detour', 'dns', 'physical-source', 'mtu', 'open-gate'),
        PREFIX+'PhysicalKeepsTarget': ('linux', 'windows', 'darwin'),
    },
    'cmd/sing-box': {
        PREFIX+'ChildCommand': tuple(target+'/'+setting for target in ('linux', 'windows', 'darwin') for setting in ('server', 'auto')),
        PREFIX+'ChildCommandRefusesSubstitution': ('generic', 'connect', 'local', 'duplicate-schema', 'wrong-schema', 'noncanonical-schema', 'paired-source', 'socks-source', 'connect-source', 'config', 'source-digest', 'physical-digest', 'target'),
        PREFIX+'ChildPublication': ('server', 'auto'),
        PREFIX+'ChildRetainsFailedCleanup': ('remote-join', 'gate-retire'),
        PREFIX+'ChildJoinsLateConstructor': (),
        PREFIX+'ChildSavedChoice': ('local', 'server'),
        PREFIX+'ChildRejectsForeignOwner': ('host', 'preparation', 'physical', 'reader', 'mtu', 'selected-proof', 'proof-kind'),
    },
}
DARWIN = {
    'TestRouterVPNNodeChainSOCKSExecutionDarwinControl': ('server', 'auto', 'policy', 'preparation', 'mixed', 'mixed-connect', 'missing', 'source', 'session', 'cancelled', 'retiring', 'foreign-prepare'),
    'TestRouterVPNNodeChainSOCKSExecutionDarwinEarlyStop': ('receipt-before-acquisition', 'authenticated-before-run'),
    'TestRouterVPNNodeChainSOCKSExecutionDarwinMailboxStartup': ('absent', *(name+'-'+kind for name in ('adoption', 'ready', 'last') for kind in ('regular', 'directory', 'symlink'))),
}
CONTROLS = (
    ('cmd/sing-box/routervpn_node_chain_execution_command.go', 'string(header.Schema) == "3"', 'string(header.Schema) == "30"', PREFIX+'ChildCommand', 'linux/server', 'typed SOCKS execution command lost original capture'),
    ('cmd/sing-box/routervpn_node_chain_execution_runtime.go', ' || readyErr != nil', ' || (readyErr != nil && false)', PREFIX+'ChildRejectsForeignOwner', 'selected-proof', 'SOCKS execution published a substituted owner or proof'),
)
TEMPLATES = {
    **{name: 'routervpn_desktop_'+name+'.go' for name in ('node_chain_socks_execution_box_physical', 'node_chain_socks_execution_box_linux', 'node_chain_socks_execution_box_darwin', 'node_chain_socks_execution_box_test', 'node_chain_execution_box_mtu')},
    **{name: 'cmd/sing-box/routervpn_'+name+'.go' for name in ('node_chain_socks_execution_child_test', 'node_chain_socks_execution_darwin_test', 'node_chain_execution_command', 'node_chain_execution_runtime', 'node_command_run_linux', 'mtu_node', 'node_chain_execution_control_darwin', 'node_chain_execution_run_darwin', 'node_chain_execution_runtime_test', 'node_chain_execution_last_test')},
    **{name: 'routervpn/desktoppt/'+name+'.go' for name in ('node_chain_socks_physical_linux', 'node_chain_socks_physical_windows', 'node_chain_socks_physical_darwin', 'node_chain_socks_physical_other', 'node_physical_darwin')},
}


def inventory(darwin=False):
    result = {package: dict(roots) for package, roots in CASES.items()}
    if darwin:
        result['cmd/sing-box'].update(DARWIN)
    return result


def names(roots):
    return {name for root, children in roots.items() for name in (root, *(root+'/'+child for child in children))}


def verdict(raw, code, package, roots):
    if code != 0:
        raise ValueError('native SOCKS child command failed')
    wanted = MODULE if package == '.' else MODULE+'/'+package
    expected, ran, passed, records = names(roots), set(), set(), []
    started = finished = False
    diagnostics = 0
    for line in raw.splitlines():
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError('invalid native SOCKS event')
        action, name = row.get('Action'), row.get('Test')
        if action == 'build-output':
            output = row.get('Output')
            if (set(row) != {'Action', 'ImportPath', 'Output'} or row.get('ImportPath') != wanted+'.test' or started or
                    not isinstance(output, str) or not output or 'DATA RACE' in output):
                raise ValueError('foreign or late native build diagnostics')
            diagnostics += len(output.encode())
            if diagnostics > 64*1024:
                raise ValueError('native build diagnostics exceeded original bound')
            continue
        if row.get('Package') != wanted or finished or 'DATA RACE' in row.get('Output', ''):
            raise ValueError('foreign, late or racing native SOCKS receipt')
        if action == 'start' and not name and not started:
            started = True
        elif (action == 'run' and started and name in expected and name not in ran and
              (name in roots or name.split('/')[0] in ran and name.split('/')[0] not in passed)):
            ran.add(name)
        elif (action == 'pass' and name and name in ran and name not in passed and
              (name not in roots or all(child in passed for child in expected if child.startswith(name+'/')))):
            passed.add(name)
            records.append(row)
        elif action == 'pass' and not name and started and ran == passed == expected:
            finished = True
        elif action == 'output' and started and (not name or name in ran and name not in passed):
            pass
        else:
            raise ValueError('missing, repeated, failed or skipped native SOCKS work')
    if not finished or passed != expected:
        raise ValueError('native SOCKS child receipt incomplete')
    return records


def command(go, tags, race, package, selection, overlay=None):
    result = [go, 'test', '-json', *(['-race'] if race else []), '-mod=readonly', '-p=1', '-count=1', '-timeout=120s', '-tags='+tags, '-ldflags=-checklinkname=0']
    if overlay is not None:
        result.append('-overlay='+str(overlay))
    return result+['.' if package == '.' else './'+package, '-run', selection]


def execute(core, go, tags, race=True, phase='baselines'):
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=core, text=True).strip() != '1ac1a339cb1223e9c70eae14c44411c75033c02d':
        raise ValueError('native SOCKS child requires the original pinned core')
    # Validate every new template and every edited coordinator before execution.
    for template, destination in TEMPLATES.items():
        target = core/destination
        if target.is_symlink() or not target.is_file() or target.read_bytes() != (ROOT/'mobile/desktop'/(template+'.go.tmpl')).read_bytes():
            raise ValueError('native SOCKS child lost exact prepared template: '+template)
    env = dict(os.environ)
    env.setdefault('GOMAXPROCS', '2'); env.setdefault('GOGC', '50'); env.setdefault('GOMEMLIMIT', '1800MiB')
    if phase == 'baselines':
        for package, roots in inventory(platform.system() == 'Darwin').items():
            run = subprocess.run(command(go, tags, race, package, '^('+'|'.join(roots)+')$'), cwd=core, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            try:
                records = verdict(run.stdout, run.returncode, package, roots)
            except (ValueError, TypeError):
                print(run.stdout, flush=True)
                raise
            for row in records:
                print(json.dumps(row, separators=(',', ':')), flush=True)
            print('Native SOCKS child baseline:', package, len(roots), 'roots,', len(records), 'PASS records', flush=True)
    elif phase == 'controls':
        for relative, before, after, test, child, witness in CONTROLS:
            target = core/relative
            original = target.read_text()
            if original.count(before) != 1:
                raise ValueError('native SOCKS child control boundary changed')
            with tempfile.TemporaryDirectory(prefix='routervpn-socks-child-control-') as directory:
                changed, overlay = Path(directory)/target.name, Path(directory)/'overlay.json'
                changed.write_text(original.replace(before, after, 1))
                overlay.write_text(json.dumps({'Replace': {str(target): str(changed)}}))
                selection = '^'+re.escape(test)+'$/'+ '/'.join('^'+re.escape(part)+'$' for part in child.split('/'))
                run = subprocess.run(command(go, tags, race, 'cmd/sing-box', selection, overlay), cwd=core, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            rows = []
            for line in run.stdout.splitlines():
                try: rows.append(json.loads(line))
                except ValueError: pass
            if (run.returncode == 0 or not any(row.get('Action') == 'run' and row.get('Test') == test for row in rows) or
                    not any(row.get('Action') == 'fail' and row.get('Test') == test for row in rows) or
                    not any(row.get('Action') == 'output' and row.get('Test') == test+'/'+child and witness in row.get('Output', '') for row in rows) or
                    any('DATA RACE' in row.get('Output', '') for row in rows) or target.read_text() != original):
                print(run.stdout, flush=True)
                raise ValueError('native SOCKS child causal witness missing')
            print('Native SOCKS child causal refusal PASS:', test+'/'+child, flush=True)
    else:
        raise ValueError('unknown native SOCKS child phase')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', default=TAGS)
    parser.add_argument('--without-race', action='store_true')
    parser.add_argument('--phase', required=True, choices=('baselines', 'controls'))
    args = parser.parse_args()
    execute(args.core.resolve(), args.go, args.tags, not args.without_race, args.phase)
