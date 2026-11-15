#!/usr/bin/env python3
"""Execute the shipping Go baseline capture through the real Python validator.

The exact host constructor literal and selection struct are compiled unchanged.
The original private-store dispatcher executes with the existing explicit PF
fixture boundary. Its native plan is a rejecting sentinel: no successful PF
installation, native absence, controller startup or network proof is invented.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASE_PROTOCOLS = {'direct': None, 'wg-entry': 'wireguard',
                  'ss-entry': 'shadowsocks', 'openvpn-entry': 'openvpn'}


def captures(root, go, old_entry=False):
    host = (root/'cmd/client/desktop_external_host_darwin.go').read_text()
    marker = 'selection: desktopMacOSExternalSelection{'
    if host.count(marker) != 1:
        raise AssertionError('Mac external host lost its single original baseline capture')
    start = host.index(marker) + len('selection: ')
    literal = host[start:host.index('}', start)+1]
    if old_entry:
        before = 'ProfileID: launch.policyProfileID'
        if literal.count(before) != 1:
            raise AssertionError('Mac external baseline policy-ID mutation lost its exact boundary')
        literal = literal.replace(before, 'ProfileID: launch.profileID')
    source = (root/'cmd/client/desktop_external_darwin_baseline.go').read_text()
    start = source.index('type desktopMacOSExternalSelection struct {')
    structure = source[start:source.index('\n}', start)+2]
    program = '''package main
import("encoding/json";"os";"strings")
'''+structure+'''
func main(){
 results:=make(map[string]desktopMacOSExternalSelection)
 for _,kind:=range []string{"direct","wg-entry","ss-entry","openvpn-entry"}{
  for _,final:=range []string{"off","on-connect","always"}{
   entries:=[]string{"off","on-connect","always"};if kind=="direct"{entries=[]string{""}}
   for _,entry:=range entries{
    launch:=struct{profileID,policyProfileID string}{"original-entry","direct-tor"}
    captured:=struct{EntryID,FinalKillSwitchPolicy,EntryKillSwitchPolicy string}{"original-entry",final,entry}
    label:=entry;if kind=="direct"{launch.profileID=launch.policyProfileID;captured.EntryID="";label="none"}
    policy:=final;if entry=="always"||policy=="off"&&entry=="on-connect"{policy=entry}
    meta:=struct{Protocol,SessionID,SourceSHA256,ConfigSHA256,KillSwitchPolicy string;HomeLANAccess bool}{"shadowsocks",strings.Repeat("c",32),strings.Repeat("d",64),strings.Repeat("e",64),policy,false}
    results[kind+"/"+final+"/"+label]='''+literal+'''
   }
  }
 }
 if err:=json.NewEncoder(os.Stdout).Encode(results);err!=nil{panic(err)}
}
'''
    with tempfile.TemporaryDirectory(prefix='macos-baseline-capture-') as folder:
        path = Path(folder)/'main.go'
        path.write_text(program)
        result = subprocess.run([go, 'run', path], cwd=root, capture_output=True,
                                text=True, timeout=60, check=True)
    values = json.loads(result.stdout)
    expected = {kind+'/'+final+'/'+entry for kind in CASE_PROTOCOLS
                for final in ('off', 'on-connect', 'always')
                for entry in (('none',) if kind == 'direct' else ('off', 'on-connect', 'always'))}
    if type(values) is not dict or set(values) != expected:
        raise AssertionError('Actual compiled baseline capture lost its complete case inventory')
    return values


def load_fixture(root):
    sys.path.insert(0, str(root/'modes'))
    try:
        spec = importlib.util.spec_from_file_location('macos_baseline_identity_fixture', root/'modes/test_darwin_owned_pf.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def check_dispatch(module, values):
    reached, rejected = set(), set()
    for name, capture in values.items():
        kind, final_policy, entry_policy = name.split('/')
        fixture = module.OwnedDarwinPF()
        fixture.setUp()
        try:
            final = fixture.external_capture(final_policy)
            entry = None
            if kind != 'direct':
                final.update(entry_profile_id='original-entry', entry_policy=entry_policy,
                             policy=max((final_policy, entry_policy), key={'off': 0, 'on-connect': 1, 'always': 2}.__getitem__))
            if {key: value for key, value in capture.items() if key != 'profile_id'} != {key: value for key, value in final.items() if key != 'profile_id'}:
                raise AssertionError('Host changed original session/source/protocol/protection capture: '+name)
            if kind != 'direct':
                # Entry and final are independent records. Opposite LAN policy
                # also detects the wrong ID when both use the same SS protocol.
                entry = dict(fixture.selected, id='original-entry',
                             external={'protocol': CASE_PROTOCOLS[kind]}, home_lan_access=True,
                             kill_switch_policy=entry_policy)
                fixture.store['profiles'].append(entry)
                fixture.private_json(fixture.root/'routers.json', fixture.store)
            sentinel = RuntimeError('original native plan refusal sentinel')
            with module.patch.object(module.P._baseline, '_invoke', side_effect=sentinel) as native:
                try:
                    module.D.darwin_external('apply', dict(capture=capture, expected=None))
                except RuntimeError as error:
                    if error is sentinel and native.call_count == 1:
                        reached.add(name)
                    elif native.call_count == 0 and ('captured saved protection policy' in str(error)
                            or 'substituted its original entry protection' in str(error)):
                        rejected.add(name)
                    else:
                        raise AssertionError('Unexpected dispatch/refusal boundary: '+name+': '+str(error)) from error
                else:
                    raise AssertionError('Native refusal did not propagate: '+name)
            if kind == 'direct' or name in reached:
                # Saved final policy changes remain rejected before the native
                # plan; selecting the correct ID never weakens its validation.
                for field, value in (('kill_switch_policy', 'always' if final_policy != 'always' else 'on-connect'), ('home_lan_access', True),
                                     ('external', {'protocol': 'wireguard'})):
                    original = fixture.selected[field]
                    fixture.selected[field] = value
                    fixture.private_json(fixture.root/'routers.json', fixture.store)
                    with module.patch.object(module.P._baseline, '_invoke', side_effect=sentinel) as native:
                        try:
                            module.D.darwin_external('apply', dict(capture=capture, expected=None))
                        except RuntimeError as error:
                            if 'captured saved protection policy' not in str(error) or native.call_count:
                                raise AssertionError('Changed saved final reached native plan: '+name+'/'+field) from error
                        else:
                            raise AssertionError('Changed saved final was accepted: '+name+'/'+field)
                    fixture.selected[field] = original
                    fixture.private_json(fixture.root/'routers.json', fixture.store)
                if entry is not None:
                    # Even a member change that leaves the strongest policy
                    # unchanged must be rejected before native mutation.
                    for fault in ('entry-policy', 'missing-entry', 'duplicate-entry', 'duplicate-final'):
                        original_profiles = list(fixture.store['profiles'])
                        original_policy = entry['kill_switch_policy']
                        if fault == 'entry-policy':
                            entry['kill_switch_policy'] = 'always' if entry_policy != 'always' else 'on-connect'
                        elif fault == 'missing-entry':
                            fixture.store['profiles'].remove(entry)
                        elif fault == 'duplicate-entry':
                            fixture.store['profiles'].append(dict(entry))
                        else:
                            fixture.store['profiles'].append(dict(fixture.selected))
                        fixture.private_json(fixture.root/'routers.json', fixture.store)
                        with module.patch.object(module.P._baseline, '_invoke', side_effect=sentinel) as native:
                            try:
                                module.D.darwin_external('apply', dict(capture=capture, expected=None))
                            except RuntimeError as error:
                                if 'captured saved protection policy' not in str(error) or native.call_count:
                                    raise AssertionError('Changed saved member reached native plan: '+name+'/'+fault) from error
                            else:
                                raise AssertionError('Changed saved member was accepted: '+name+'/'+fault)
                        entry['kill_switch_policy'] = original_policy
                        fixture.store['profiles'] = original_profiles
                        fixture.private_json(fixture.root/'routers.json', fixture.store)
        finally:
            fixture.doCleanups()
    return reached, rejected


def execute(root: Path = ROOT, *, go='go', mutations=True):
    root = Path(root).resolve()
    module = load_fixture(root)
    values = captures(root, go)
    reached, rejected = check_dispatch(module, values)
    if rejected or reached != set(values):
        raise AssertionError('Actual host baseline borrowed entry identity instead of final policy: '+repr(sorted(rejected)))
    print('Mac external baseline identity: 30 actual captures and exact saved-member refusals verified', flush=True)
    if mutations:
        values = captures(root, go, old_entry=True)
        reached, rejected = check_dispatch(module, values)
        wanted = {name for name in values if not name.startswith('direct/')}
        if rejected != wanted or reached != set(values)-wanted:
            raise AssertionError('Old entry-ID control missed exact 27 pre-native member refusals')
        print('Mac external baseline identity: old entry-ID mutation rejected all 27 composed captures before native mutation', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    execute(args.root, go=args.go)
