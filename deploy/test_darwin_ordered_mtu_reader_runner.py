#!/usr/bin/env python3
"""Strict inventory and actual ordinary parent MTU method controls."""
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import importlib.util
import os
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
def load(name):
 spec=importlib.util.spec_from_file_location(name,ROOT/'deploy'/name);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
G=load('test_darwin_node_child_tun.py');M=G.ORDERED_MTU

def transcript(names):return ''.join('=== RUN   '+n+'\n--- PASS: '+n+' (0.01s)\n' for n in names)+'PASS\n'

class OrderedMTUBoundaries(unittest.TestCase):
 def exercise(self,fault=None):
  with tempfile.TemporaryDirectory() as d:
   w=Path(d);child=w/'child';box=w/'paired-node-box.test'
   for p in (child,box):p.write_bytes(p.name.encode());p.chmod(0o755)
   source={'original':'a'*64};identities={p:G.image_identity(p) for p in (child,box)};calls=[];reads=[]
   def checked(_):
    reads.append(1);return w, {'foreign':'b'*64} if fault=='source' and len(reads)>1 else source
   def run(cmd,**kw):
    root=M.COMMAND if len(calls)==0 else M.BOX;calls.append((cmd,kw));names=[root,*(root+'/'+x for x in M.ROOTS[root])]
    if fault=='missing':names.pop()
    if fault=='duplicate':names.append(names[-1])
    if fault=='wrong-phase':names=[M.BOX]
    if fault=='image':child.write_bytes(b'changed')
    if fault=='failed':raise subprocess.CalledProcessError(1,cmd,output='original native refusal')
    out=transcript(names)
    if fault=='skip':out=out.replace('--- PASS:','--- SKIP:',1)
    if fault=='race':out+='DATA RACE\n'
    return out
   capture={'GOROOT':'/captured/root','GOTOOLCHAIN':'local'}
   gate=SimpleNamespace(UID=SimpleNamespace(run=run),NODE=G.NODE,checked_sources=checked,image_identity=G.image_identity)
   with patch.object(M,'execute_source') as original:
    result=M.execute(gate,w,source,'/captured/go',capture,child,identities,w)
    original.assert_called_once_with(go='/captured/go',environment=capture)
   self.assertEqual(len(calls),2)
   for cmd,kw in calls:self.assertEqual(kw['timeout'],100);self.assertIn('-test.timeout=90s',cmd)
   M.validate_receipt(result,G.PAIRED.source_digest(source),identities[child][-1],identities[box][-1]);return result
 def test_exact_original_phases(self):self.assertEqual(len(self.exercise()['cases']),31)
 def test_every_verdict_and_original_image_is_required(self):
  for f in ('missing','duplicate','wrong-phase','image','source','skip','race'):
   with self.subTest(fault=f),self.assertRaises(ValueError):self.exercise(f)
  with self.assertRaises(subprocess.CalledProcessError):self.exercise('failed')
 def test_receipt_cannot_omit_or_borrow_evidence(self):
  receipt=self.exercise()
  for key in receipt:
   other=dict(receipt);del other[key]
   with self.subTest(field=key),self.assertRaises(ValueError):M.validate_receipt(other,receipt['source_sha256'],receipt['command_sha256'],receipt['box_sha256'])
  for key,value in (('cases',receipt['cases'][:-1]),('command_sha256','b'*64),('box_sha256','c'*64),('source_sha256','d'*64)):
   other=dict(receipt);other[key]=value
   with self.subTest(field=key),self.assertRaises(ValueError):M.validate_receipt(other,receipt['source_sha256'],receipt['command_sha256'],receipt['box_sha256'])
 def test_publication_requires_ordinary_and_original_paired_receipts(self):
  receipt=self.exercise()
  paired=dict(schema=1,scope='paired-node-component-boundaries',verdicts=105,cases=list(G.PAIRED.CASES),phases=['command','box'],
              source_sha256=receipt['source_sha256'],command_sha256=receipt['command_sha256'],box_sha256=receipt['box_sha256'],output_sha256='f'*64)
  result=dict(gate='generated-darwin-ordered-child',source_sha256=receipt['source_sha256'],paired_node_boundaries=paired,ordinary_mtu_boundaries=receipt,
              artifacts={'generated-child-test':{'sha256':receipt['command_sha256']},'paired-node-box':{'sha256':receipt['box_sha256']}})
  result['typed_mtu_boundaries']=dict(receipt,scope='typed-execution-mtu-component-boundaries',cases=list(G.TYPED_MTU.CASES))
  with tempfile.TemporaryDirectory() as d:
   gone=Path(d)/'retired';G.publish_receipt(None,result,gone)
   for key in ('ordinary_mtu_boundaries','paired_node_boundaries','typed_mtu_boundaries'):
    missing=dict(result);del missing[key]
    with self.subTest(missing=key),self.assertRaises(ValueError):G.publish_receipt(None,missing,gone)

 def test_mandatory_wiring_preserves_original_paired_and_host_cases(self):
  s=(ROOT/'deploy/test_darwin_node_child_tun.py').read_text()
  self.assertIn('ordered_mtu = execute_ordered_mtu_boundaries(source, before, compiler, captured, child, identities, work)',s)
  self.assertIn("result['ordinary_mtu_boundaries'] = ordered_mtu",s)
  self.assertIn("ORDERED_MTU.validate_receipt(result.get('ordinary_mtu_boundaries')",s)
  self.assertEqual(len(G.PAIRED.CASES),105)
  for name in ('captured-mtu','mtu-rollback'):self.assertIn(name,G.CASES)
  for path in ('deploy/build-native-runtime.py','.github/workflows/darwin-node-child-tun.yml'):
   self.assertIn('test_darwin_ordered_mtu_reader', (ROOT/path).read_text())

 def test_actual_ordinary_parent_requires_ack_retirement_and_readback(self):
  method=M.function(ROOT,'cmd/client/desktop_node_mtu_darwin.go','func (owner *desktopMacOSNodeMTUOwner) verifyReaderChangeLocked(')
  validator=M.function(ROOT,'cmd/client/desktop_node_ordered_reader.go','func validateDesktopMacOSOrdinaryReaderRetirement(')
  record=(ROOT/'cmd/client/desktop_node_mtu.go').read_text().split('type desktopNodeMTURecord struct {',1)[1].split('\n}',1)[0]
  record='type desktopNodeMTURecord struct {'+record+'\n}\n'
  name=M.function(ROOT,'cmd/client/desktop_node_chain_launch.go','func desktopNodeChainDarwinInterfaceName(')
  compare=M.function(ROOT,'cmd/client/desktop_node_mtu_darwin.go','func sameDesktopMacOSMTUReadback(')
  header='''package parentreader
import("context";"errors";"net";"strings";"router-vpn/internal/mobilemultihop";"router-vpn/internal/nativeopenvpn";"router-vpn/ordinary-parent-fixture/desktopnetwork")
type desktopMacOSNodeChainHost struct{policy *int;execution *int;ack desktopNodeMTURecord;refused bool;reads int}
type desktopMacOSNodeMTUOwner struct{host *desktopMacOSNodeChainHost;native *rawOwner;snapshot int;foreign bool}
type rawOwner struct{record desktopNodeMTURecord}
func(o *desktopMacOSNodeMTUOwner)originalLocked()error{if o.foreign{return errors.New("foreign original")};return nil}
func validateDesktopMacOSMTUSnapshotLocked(h *desktopMacOSNodeChainHost,_ int)error{if h.refused{return errors.New("original captured proof refused")};return nil}
func readDesktopMacOSMTURecordLocked(ctx context.Context,h *desktopMacOSNodeChainHost)(desktopNodeMTURecord,error){h.reads++;return h.ack,ctx.Err()}
func validateDesktopMacOSTypedReaderRetirement(*mobilemultihop.DesktopNodeChainReadyRecord,desktopNodeMTURecord,[]net.Interface)error{return errors.New("other typed family refuses modeled authority")}
'''
  test='''package parentreader
import("context";"net";"testing";"router-vpn/ordinary-parent-fixture/desktopnetwork")
func TestActualOrdinaryParentReader(t *testing.T){for _,alias:=range []string{"same-alias","renamed"}{for _,fault:=range []string{"original","rollback","foreign-owner","foreign-ack","old-index","old-index-renamed","same-index","stale-reader","foreign-config","proof-refusal","cancelled"}{t.Run(alias+"/"+fault,func(t *testing.T){
 old:=desktopNodeMTURecord{Session:"session",Config:"config",Path:"path",Interface:"utun91",Index:91,Reader:4,MTU:1420}
 next:=old;next.Index=92;next.Reader++;next.MTU=1380;if alias=="renamed"{next.Interface="utun92"}
 marker:=1;owner:=&desktopMacOSNodeMTUOwner{host:&desktopMacOSNodeChainHost{policy:&marker},native:&rawOwner{old}}
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 switch fault{case "rollback":next.Reader++;next.MTU=old.MTU;case "foreign-owner":owner.foreign=true;case "same-index":next.Index=old.Index;case "stale-reader":next.Reader=old.Reader;case "foreign-config":next.Config+="foreign";case "proof-refusal":owner.host.refused=true;case "cancelled":cancel()}
 owner.host.ack=next;if fault=="foreign-ack"{owner.host.ack.Request+="foreign"}
 desktopnetwork.Inventory=[]net.Interface{{Name:next.Interface,Index:next.Index,MTU:next.MTU,Flags:net.FlagUp}}
 if fault=="old-index"||fault=="old-index-renamed"{name:=old.Interface;if fault=="old-index-renamed"{name="utun99"};desktopnetwork.Inventory=append(desktopnetwork.Inventory,net.Interface{Name:name,Index:old.Index})}
 err:=owner.verifyReaderChangeLocked(ctx,old,next);success:=fault=="original"||fault=="rollback"
 if (err==nil)!=success{t.Fatal("ordinary parent original reader verdict changed",alias,fault,err)}
 if success&&owner.host.reads!=1{t.Fatal("ordinary exact native ACK omitted")}
 })}}}
'''
  controls={'old-name-guard':(method.replace('next.Reader <= old.Reader','old.Interface == next.Interface || next.Reader <= old.Reader',1),validator),
    'old-index-name-filter':(method,validator.replace('link.Index == int(previous.InterfaceIndex)','link.Index == int(previous.InterfaceIndex) && link.Name == previous.InterfaceName',1)),
    'omit-ack':(method.replace('!sameDesktopMacOSMTUReadback(live, next)','false',1).replace('live, err := readDesktopMacOSMTURecordLocked','_, err := readDesktopMacOSMTURecordLocked',1),validator)}
  with tempfile.TemporaryDirectory(prefix='ordinary-parent-reader-') as d:
   w=Path(d);(w/'desktopnetwork').mkdir();(w/'desktopnetwork/network.go').write_text('package desktopnetwork\nimport("context";"net")\nvar Inventory []net.Interface\nfunc InterfacesContext(ctx context.Context)([]net.Interface,error){return Inventory,ctx.Err()}')
   (w/'go.mod').write_text('module router-vpn/ordinary-parent-fixture\n\ngo 1.26.3\nrequire router-vpn v0.0.0\nreplace router-vpn => '+str(ROOT)+'\n');(w/'parent_test.go').write_text(test)
   for label,(actual,retirement) in [('original',(method,validator)),*controls.items()]:
    (w/'parent.go').write_text('\n'.join((header,record,name,compare,retirement,actual)))
    result=M.execute_parent_variant(G,w,label,go=getattr(self,'parent_go',os.environ.get('GO','go')),
                                    environment=getattr(self,'parent_environment',None))
    with self.subTest(variant=label):
     self.assertNotIn('[build failed]',result.stdout);self.assertNotIn('DATA RACE',result.stdout);self.assertNotIn('panic:',result.stdout)
     if label=='original':self.assertEqual(result.returncode,0,result.stdout);self.assertEqual(result.stdout.count('--- PASS: TestActualOrdinaryParentReader/'),22)
     else:self.assertNotEqual(result.returncode,0,result.stdout);self.assertIn('ordinary parent original reader verdict changed',result.stdout)

class ParentVariantStages(unittest.TestCase):
 def exercise(self,fault=None):
  with tempfile.TemporaryDirectory(prefix='parent-mtu-stage-') as d:
   work=Path(d);source=work/'parent.go';source.write_text('package parent\n')
   image=work/'parent-original.test';calls=[]
   def run(command,**options):
    calls.append((command,options))
    if len(calls)==1:
     if fault=='compile-timeout':raise RuntimeError('owned compiler group joined after timeout; original partial compiler output')
     image.write_bytes(b'original compiled image');image.chmod(0o755)
     if fault=='compile-source':source.write_text('package foreign\n')
     return ''
    if fault=='run-timeout':raise RuntimeError('owned test group joined after timeout; original partial test output')
    if fault=='run-source':source.write_text('package foreign\n')
    if fault=='run-image':image.write_bytes(b'foreign compiled image')
    if fault=='negative':raise subprocess.CalledProcessError(1,command,output=b'original negative witness\n')
    return 'original executed witness\n'
   selected={'GOROOT':'/captured/compiler','GOTOOLCHAIN':'local'}
   with patch.object(G.UID.RACE,'command',side_effect=lambda command,*_:([Path('/captured/compiler/bin/go'),*command[1:]],selected)) as compiler,patch.object(G.UID,'run',side_effect=run):
    result=M.execute_parent_variant(G,work,'original',go='/selected/go',environment={'ORIGINAL':'only'})
   self.assertEqual(compiler.call_count,1)
   self.assertEqual(calls[0][0],[Path('/captured/compiler/bin/go'),'test','-c','-race','-p=1','-o',image,'.'])
   self.assertEqual(calls[0][1],dict(cwd=work,env=selected,timeout=600))
   self.assertEqual(calls[1][0],[image,'-test.count=1','-test.timeout=30s','-test.v'])
   self.assertEqual(calls[1][1],dict(cwd=work,env=selected,timeout=120))
   return result
 def test_compiler_and_original_execution_have_distinct_bounded_stages(self):
  self.assertEqual(self.exercise().stdout,'original executed witness\n')
 def test_compiled_negative_is_preserved_for_original_causal_oracle(self):
  result=self.exercise('negative');self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,'original negative witness\n')
 def test_source_or_image_replacement_cannot_complete(self):
  for fault in ('compile-source','run-source','run-image'):
   with self.subTest(fault=fault),self.assertRaises(ValueError):self.exercise(fault)
 def test_timeout_keeps_stage_and_original_partial_output(self):
  for fault,stage,partial in (('compile-timeout','compilation failed','partial compiler output'),('run-timeout','execution failed','partial test output')):
   with self.subTest(fault=fault),self.assertRaisesRegex(AssertionError,stage+'.*'+partial):self.exercise(fault)
 def test_component_invokes_original_parent_method_with_captured_environment(self):
  for kind,owner,method in (('ordinary','OrderedMTUBoundaries','test_actual_ordinary_parent_requires_ack_retirement_and_readback'),
                            ('typed','TypedMTUBoundaries','test_actual_typed_parent_requires_ack_retirement_and_readback')):
   calls=[]
   class OriginalCase:
    def __init__(self,selected):calls.append(selected)
    def debug(self):calls.append((self.parent_go,self.parent_environment))
   captured={'GOROOT':'/captured/compiler','GOTOOLCHAIN':'local'}
   with patch.object(M,'load',return_value=SimpleNamespace(**{owner:OriginalCase})),patch.object(M.subprocess,'run',side_effect=AssertionError('nested Python execution cap reintroduced')):
    M.execute_parent_source(ROOT,'/captured/compiler/bin/go',captured,kind)
   self.assertEqual(calls,[method,('/captured/compiler/bin/go',captured)])
   self.assertIsNot(calls[1][1],captured)
 def test_component_does_not_swallow_original_assertion(self):
  class RefusedCase:
   def __init__(self,_):pass
   def debug(self):raise AssertionError('original parent causal oracle refused')
  with patch.object(M,'load',return_value=SimpleNamespace(OrderedMTUBoundaries=RefusedCase)),self.assertRaisesRegex(AssertionError,'original parent causal oracle refused'):
   M.execute_parent_source(ROOT,'/captured/go',{},'ordinary')

if __name__=='__main__':unittest.main()
