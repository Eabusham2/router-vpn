from pathlib import Path
import importlib.util,json,tempfile,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
 s=importlib.util.spec_from_file_location(name,ROOT/'deploy'/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('stack_policy','mobile_wireguard_stack_policy.py');R=load('stack_runner','test_mobile_wireguard_stack.py')
class Tests(unittest.TestCase):
 def test_pin_partial_drift_idempotency(self):
  self.assertEqual(P.SOURCE_SHA,'3321ef8f0dd2a0800d13a0e7f5d7977d3179577d')
  original='\n'.join(old for old,new in P.REPLACEMENTS)
  with mock.patch.object(P,'SOURCE_SHA',P.blobsha(original.encode())):
   fixed=P.patch(original);self.assertEqual(P.patch(fixed),fixed)
   for changed in (original+'drift',fixed+'drift',fixed+P.REPLACEMENTS[0][1],original.replace(*P.REPLACEMENTS[0])):
    with self.subTest(changed=changed),self.assertRaises(ValueError):P.patch(changed)
  with self.assertRaises(ValueError):P.patch(original)
 def test_link_refused_before_source_write(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);p=root/'transport/wireguard/device_stack.go';p.parent.mkdir(parents=True);p.write_text('original');other=root/'other';other.write_text('retained');p.with_name('routervpn_stack_close_test.go').symlink_to(other)
   with mock.patch.object(P.subprocess,'check_output',return_value=P.PIN+'\n'),self.assertRaises(ValueError):P.prepare(root)
   self.assertEqual(p.read_text(),'original');self.assertEqual(other.read_text(),'retained')
 def test_transitive_shipping_hook_and_digest(self):
  bind=load('bind_policy','mobile_wireguard_bind_policy.py');self.assertTrue(set(P.inputs()).issubset(bind.inputs()))
  self.assertIn('deploy/test_mobile_wireguard_stack.py',(ROOT/'deploy/test_desktop_node_physical.py').read_text())
  for path in ('ios/RouterVPN/prepare-libbox.sh','android/build-sing-box-libbox.sh'):self.assertIn('test_mobile_wireguard_stack.py',(ROOT/path).read_text())
  self.assertIn('STACK.prepare(vendor)',(ROOT/'deploy/mobile_wireguard_bind_policy.py').read_text())
  for name,hook in [('prepare-mobile-multihop.py','WIREGUARD_BIND.prepare(vendor)'),('prepare-mobile-amnezia.py','WIREGUARD_BIND.prepare(vendor)'),('prepare-server-pq.py','BIND.prepare(vendor)')]:self.assertIn(hook,(ROOT/'deploy'/name).read_text())
 def test_native_verdicts_fail_closed(self):
  event=lambda action,name=R.CASE:json.dumps({'Test':name,'Action':action})
  good=event('run')+'\n'+event('pass');R.verdict(good)
  for raw in ('',event('run'),good+'\n'+event('pass'),event('run')+'\n'+event('skip'),good+'\n'+event('pass','foreign'),event('run')+'\n'+event('fail')):
   with self.subTest(raw=raw),self.assertRaises(ValueError):R.verdict(raw)
  R.verdict(event('run')+'\n'+event('fail'),True)
if __name__=='__main__':unittest.main()
