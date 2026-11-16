#!/usr/bin/env python3
"""Strict native CONNECT gate controls; synthetic events are not native proof."""
import ast
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('connect_final_native',ROOT/'deploy/test_connect_final_layers_native.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)

def events(phase):
    relative,expected=G.PHASES[phase];package=G.package_name(relative)
    rows=[{'Action':'start','Package':package}]
    for name in sorted(expected):
        rows.extend({'Action':action,'Package':package,'Test':name} for action in ('run','pass'))
    rows.append({'Action':'pass','Package':package})
    return rows

def failure():
    package=G.package_name('./protocol/routervpnwhitening')
    target='TestCONNECTWhiteningFinalReadbackKeepsActualNativeOwners/key'
    names=sorted(G.inventory([target]))
    rows=[{'Action':'start','Package':package}]
    rows.extend({'Action':'run','Package':package,'Test':name} for name in names)
    rows.append({'Action':'output','Package':package,'Test':target,'Output':'replaced final acquired original native readback'})
    rows.extend({'Action':'fail','Package':package,'Test':name} for name in reversed(names))
    rows.append({'Action':'fail','Package':package})
    return rows,package,target

def wire(rows):return '\n'.join(json.dumps(row) for row in rows)+'\n'

def registration(builder,android):
    tree=ast.parse(builder)
    expected=ast.parse("""run([sys.executable, ROOT/'deploy/test_connect_final_layers_native_runner.py'], cwd=ROOT, env=env, timeout=60)
run([sys.executable, ROOT/'deploy/test_connect_final_layers_native.py', '--core', source, '--tags='+','.join(tags(target)), *(['--race'] if race else [])], cwd=source, env=env, timeout=3100)
""").body
    for wanted in expected:
        if sum(ast.dump(node)==ast.dump(wanted) for node in ast.walk(tree))!=1:raise ValueError('mandatory final native invocation changed')
    # A matching node buried beneath a new conditional/boolean must not pass.
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='build')
    calls=[n for n in ast.walk(function) if isinstance(n,ast.Expr) and ast.dump(n)==ast.dump(expected[1])]
    parents={child:parent for parent in ast.walk(function) for child in ast.iter_child_nodes(parent)}
    current=calls[0]; conditions=[]
    while current in parents:
        current=parents[current]
        if isinstance(current,ast.If):conditions.append(ast.dump(current.test))
    if conditions!=[ast.dump(ast.parse('target == host',mode='eval').body)]:raise ValueError('final native gate escaped original matching-host branch')
    for parent in ast.walk(function):
        for _,value in ast.iter_fields(parent):
            if isinstance(value,list) and calls[0] in value:
                index=value.index(calls[0])
                if index==0 or ast.dump(value[index-1])!=ast.dump(expected[0]):raise ValueError('final native gate lost adjacent verifier')
    inputs=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='inputs')
    constants=[n.value for n in ast.walk(inputs) if isinstance(n,ast.Constant)]
    for name in ('deploy/test_connect_final_layers_native.py','deploy/test_connect_final_layers_native_runner.py'):
        if constants.count(name)!=1:raise ValueError('final native gate input missing')
    commands='''  python3 "$ROOT/../deploy/test_connect_final_layers_native_runner.py"
  python3 "$ROOT/../deploy/test_connect_final_layers_native.py" --core "$VENDOR" --go "$(command -v go)" --race --tags with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego
'''
    if android.count(commands)!=1:raise ValueError('mandatory mobile native gate changed')

class NativeFinalGate(unittest.TestCase):
    def test_full_inventory(self):
        self.assertEqual(set(G.PHASES),{'encrypted-retirement','concrete-final','native-box-owners','native-box-replacement','native-box-last','native-box-server'})
        counts={}
        for phase,(relative,expected) in G.PHASES.items():
            counts[phase]=G.verdict(wire(events(phase)),0,G.package_name(relative),expected)
        self.assertEqual(counts,{'encrypted-retirement':6,'concrete-final':16,'native-box-owners':25,'native-box-replacement':9,'native-box-last':9,'native-box-server':5})
        self.assertNotIn('TestRouterVPNCONNECTFinalLayersNativeOwners/3',G.PHASES['native-box-owners'][1])
        self.assertIn('TestRouterVPNCONNECTFinalLayersNativeOwners/3/http-connect/aes-256-gcm/server',G.PHASES['native-box-owners'][1])
        self.assertEqual(sum(counts.values()),70)
        all_records=set()
        for _,expected in G.PHASES.values():
            self.assertFalse(all_records & expected, 'A phase duplicated another phase record')
            all_records.update(expected)
        for phase,(relative,expected) in G.PHASES.items():
            if phase.startswith('native-box-'):
                self.assertEqual(relative,'.')
                self.assertEqual(len([name for name in expected if '/' not in name]),1)

    def test_every_run_pass_start_and_terminal_is_required(self):
        for phase,(relative,expected) in G.PHASES.items():
            original=events(phase)
            for index in range(len(original)):
                with self.subTest(phase=phase,index=index),self.assertRaises(ValueError):
                    G.verdict(wire(original[:index]+original[index+1:]),0,G.package_name(relative),expected)

    def test_duplicate_foreign_skipped_failed_and_late_records(self):
        phase='encrypted-retirement';relative,expected=G.PHASES[phase]
        for fault in ('duplicate-run','duplicate-pass','duplicate-package','foreign','skip','fail','late','malformed'):
            rows=events(phase)
            if fault=='duplicate-run':rows.insert(2,dict(rows[1]))
            elif fault=='duplicate-pass':rows.insert(3,dict(rows[2]))
            elif fault=='duplicate-package':rows.append(dict(rows[-1]))
            elif fault=='foreign':rows[1]['Package']+='/foreign'
            elif fault in ('skip','fail'):rows[2]['Action']=fault
            elif fault=='late':rows.append({'Action':'output','Package':G.package_name(relative),'Output':'late'})
            else:rows[1]=[]
            with self.subTest(fault=fault),self.assertRaises(ValueError):G.verdict(wire(rows),0,G.package_name(relative),expected)

    def test_ordinary_causal_witness(self):
        rows,package,target=failure()
        G.rejected(wire(rows),1,package,target,'replaced final acquired original native readback')
        for index in range(len(rows)):
            with self.subTest(index=index),self.assertRaises(ValueError):G.rejected(wire(rows[:index]+rows[index+1:]),1,package,target,'replaced final acquired original native readback')

    def test_valid_failure_witness_cannot_hide_abort(self):
        rows,package,target=failure()
        for abort in ('WARNING: DATA RACE','panic: late panic','fatal error: concurrent map writes','signal: killed','build failed','runtime: out of memory','test timed out'):
            with self.subTest(abort=abort),self.assertRaises(ValueError):
                G.rejected(wire(rows),1,package,target,'replaced final acquired original native readback',abort)
            changed=rows[:-1]+[{'Action':'output','Package':package,'Test':target,'Output':abort}]+rows[-1:]
            with self.subTest(output=abort),self.assertRaises(ValueError):G.rejected(wire(changed),1,package,target,'replaced final acquired original native readback')
        for code in (0,2,-9):
            with self.subTest(code=code),self.assertRaises(ValueError):G.rejected(wire(rows),code,package,target,'replaced final acquired original native readback')

    def test_failure_cannot_borrow_witness_or_terminal(self):
        rows,package,target=failure()
        for fault in ('foreign-witness','wrong-witness','duplicate-terminal','pass','duplicate-run','unknown'):
            changed=[dict(r) for r in rows]
            if fault=='foreign-witness':changed[3]['Test']=target+'/foreign'
            elif fault=='wrong-witness':changed[3]['Output']='unrelated failure'
            elif fault=='duplicate-terminal':changed.append(dict(changed[-1]))
            elif fault=='pass':changed[-2]['Action']='pass'
            elif fault=='duplicate-run':changed.insert(2,dict(changed[1]))
            else:changed[1]['Test']+='foreign'
            with self.subTest(fault=fault),self.assertRaises(ValueError):G.rejected(wire(changed),1,package,target,'replaced final acquired original native readback')

    def test_required_builders_and_finite_bounds(self):
        builder=(ROOT/'deploy/build-native-runtime.py').read_text();android=(ROOT/'android/build-sing-box-libbox.sh').read_text()
        registration(builder,android)
        for before,after in (("'--core', source, '--tags='+','.join(tags(target)), *(['--race'] if race else [])", "'--core', foreign, '--tags='+','.join(tags(target)), *(['--race'] if race else [])"),("timeout=3100", "timeout=9999"),("ROOT/'deploy/test_connect_final_layers_native.py',", "ROOT/'deploy/omitted.py',")):
            with self.subTest(before=before),self.assertRaises(ValueError):registration(builder.replace(before,after,1),android)
        marker="            run([sys.executable, ROOT/'deploy/test_connect_final_layers_native_runner.py'],"
        hidden=builder.replace(marker,"            if False:\n    "+marker,1)
        # An explicit conditional swallowing the adjacent verifier is rejected;
        # the actual runner call cannot borrow a coincidental token elsewhere.
        with self.assertRaises(ValueError):registration(hidden,android)
        marker="            run([sys.executable, ROOT/'deploy/test_connect_final_layers_native.py',"
        with self.assertRaises(ValueError):registration(builder.replace(marker,marker.replace('run(', 'False and run('),1),android)
        for before,after in (('--race --tags with_wireguard','--tags with_wireguard'),(' --core "$VENDOR"',' --core "$FOREIGN"'),('  python3 "$ROOT/../deploy/test_connect_final_layers_native.py"','  true # python3 "$ROOT/../deploy/test_connect_final_layers_native.py"')):
            with self.subTest(mobile=before),self.assertRaises(ValueError):registration(builder,android.replace(before,after))
        source=(ROOT/'deploy/test_connect_final_layers_native.py').read_text()
        self.assertEqual(source.count('timeout=600'),2)
        self.assertIn("'-timeout=90s'",source)

if __name__=='__main__':unittest.main()
