#!/usr/bin/env python3
"""Guard native Server component verdicts and required shipping integration."""
from pathlib import Path
import importlib.util
import json
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('server_chain_native_runner',ROOT/'deploy/test_server_node_chain_native.py')
RUN=importlib.util.module_from_spec(spec);spec.loader.exec_module(RUN)

def record(action,name=None,**fields):
 row=dict(Action=action,Package=RUN.PACKAGE,**fields)
 if name:row['Test']=name
 return row

def success():
 rows=[record('start')]
 for root in RUN.ROOTS:
  rows.append(record('run',root))
  for child in RUN.CHILDREN.get(root,()):rows += [record('run',root+'/'+child),record('pass',root+'/'+child)]
  rows.append(record('pass',root))
 rows.append(record('pass'));return rows

def output(rows):return '\n'.join(json.dumps(row) for row in rows)+'\n'

class NativeServerChainRunner(unittest.TestCase):
 def test_complete_exact_inventory(self):
  receipt=RUN.verdict(output(success()),0)
  self.assertEqual(receipt['roots'],13);self.assertEqual(receipt['executed_records'],len(RUN.EXPECTED));self.assertGreater(len(RUN.EXPECTED),30)
 def test_missing_leaf_cannot_pass(self):
  name=RUN.ROOTS[3]+'/prefix-uot';rows=[r for r in success() if r.get('Test')!=name]
  with self.assertRaises(ValueError):RUN.verdict(output(rows),0)
 def test_skip_duplicate_race_and_package_failure_refused(self):
  for mode in ('skip','duplicate','race','exit','package','unknown-root'):
   with self.subTest(mode=mode):
    rows=success();code=0
    if mode=='skip':rows.insert(-1,record('skip',RUN.ROOTS[0]))
    elif mode=='duplicate':rows.insert(-1,record('pass',RUN.ROOTS[0]))
    elif mode=='race':rows.insert(-1,record('output',RUN.ROOTS[0],Output='WARNING: DATA RACE'))
    elif mode=='exit':code=1
    elif mode=='package':rows.pop()
    else:rows.insert(-1,record('run','TestServerChainUninventoried'))
    with self.assertRaises(ValueError):RUN.verdict(output(rows),code)
 def test_compile_error_is_not_causal_rejection(self):
  name=RUN.ROOTS[4];rows=[record('output',Output='build failed'),record('fail')]
  self.assertFalse(RUN.rejected(output(rows),1,name,'failed native close was acknowledged'))
  with self.assertRaises(ValueError):RUN.rejected('# compile failed\n',1,name,'failed native close was acknowledged')
 def test_causal_control_requires_exact_test_and_witness(self):
  name=RUN.ROOTS[4];witness='failed native close was acknowledged';rows=[record('run',name),record('output',name,Output=witness),record('fail',name),record('fail')]
  self.assertTrue(RUN.rejected(output(rows),1,name,witness));self.assertFalse(RUN.rejected(output(rows),0,name,witness));self.assertFalse(RUN.rejected(output(rows),1,RUN.ROOTS[0],witness));self.assertFalse(RUN.rejected(output(rows),1,name,'unrelated failure'))
 def test_actual_shipping_gate_and_original_families_remain(self):
  docker=(ROOT/'deploy/router-agent.Dockerfile').read_text();workflow=(ROOT/'.github/workflows/native-xray-exits.yml').read_text()
  self.assertIn("./cmd/sing-box ./routervpn/servertor -run '^TestServerTor' -count=1 -timeout 90s",docker)
  self.assertIn('python3 /routervpn-source/deploy/test_server_node_chain_native.py --core /core',docker)
  self.assertIn('--receipt /routervpn-server-node-chain-native.json',docker)
  self.assertIn('python3 deploy/test_server_node_chain_preparation.py',workflow);self.assertIn('python3 deploy/test_server_node_chain_native_runner.py',workflow)
  self.assertIn("'deploy/test_server_node_chain_*.py'",workflow)
  self.assertIn('docker build --progress=plain -f deploy/router-agent.Dockerfile',workflow)

if __name__=='__main__':unittest.main()
