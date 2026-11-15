#!/usr/bin/env python3
"""Original typed/execution MTU authority: source controls and exact native images.

The source controls model OS observations explicitly. The installed ordered host
cases separately require real encrypted traffic, PF, utun and Auto/Cancel/Retest.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
COMMAND='TestRouterVPNDesktopTypedDarwinMTURawContinuation'
LEAVES=('renamed','same-alias','unchanged','rollback','foreign-before','foreign-result','same-index','unjoined','receipt-replaced','physical-refused','source-changed','cancelled','late-cancel')
ROOTS={COMMAND:('renamed','same-alias','unchanged','refused','missing-capability','other-platform','reproof-failed','cancelled','mixed-prefix','mixed-openvpn'),
 'TestRouterVPNDesktopCONNECTDarwinMTUContinuation':LEAVES,
 'TestRouterVPNDesktopSOCKSDarwinMTUContinuation':LEAVES,
 'TestRouterVPNDesktopExecutionDarwinMTUContinuation':tuple(v for selected in ('local','server') for v in (selected,*(selected+'/'+leaf for leaf in (*LEAVES,'foreign-operation','cleanup-unchanged'))))}
CASES=tuple(name for root,leaves in ROOTS.items() for name in (root,*(root+'/'+leaf for leaf in leaves)))

def function(root,path,marker):
    source=(root/path).read_text();start=source.index(marker);end=source.find('\nfunc ',start+1)
    return source[start:] if end<0 else source[start:end]

def load(root,name):
    spec=importlib.util.spec_from_file_location(name,root/'deploy'/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def execute_source(root=ROOT,go='go',environment=None):
    captured=dict(os.environ if environment is None else environment,GOTOOLCHAIN='local')
    paired=load(root,'test_darwin_paired_mtu_reader.py')
    method=function(root,'mobile/desktop/node_chain_execution_box_mtu.go.tmpl','func (owner *RouterVPNDesktopNodePhysical) confirmTypedDarwinMTUReadback(')
    original=paired.TEST.split('func TestActualPairedReaderConfirmation')[0].replace(';"time"','')
    test=r'''
func TestActualTypedPhysicalConfirmation(t *testing.T){
 for _,fault:=range []string{"original","equal-policy-pointer","wrong-platform","reader","detached","alias","source","readback","cancelled"}{t.Run(fault,func(t *testing.T){
  policy:=original(t,"darwin");expected:=policy;meta:=policy.Metadata();b:=&Box{1};n:=&Box{2}
  owner:=&RouterVPNDesktopNodePhysical{instance:b,inbound:n,policy:policy,network:&modeledNetwork{session:meta.SessionID,source:meta.SourceSHA256},name:"utun71",index:72,mtu:1380}
  ctx,cancel:=context.WithCancel(t.Context());defer cancel()
  switch fault{
  case "equal-policy-pointer":expected=original(t,"darwin");if expected.Config()!=policy.Config(){t.Fatal("equal policy vector changed")}
  case "wrong-platform":expected=original(t,"linux");owner.policy=expected;m:=expected.Metadata();owner.network.source=m.SourceSHA256
  case "reader":n=&Box{3}
  case "detached":owner.detached=true
  case "alias":owner.interfaceName="utun71"
  case "source":owner.network.refused=true
  case "readback":owner.index++
  case "cancelled":cancel()
  }
  err:=owner.confirmTypedDarwinMTUReadback(ctx,expected,n,"utun71",72,1380)
  if (err==nil)!=(fault=="original"){t.Fatal("typed physical confirmation verdict changed",fault,err)}
 })}
}
'''
    controls={
      'original-policy-pointer':('owner.policy != expected','false'),
      'original-reader':('owner.inbound != next','false'),
      'original-source':('owner.network.MatchesContext(ctx, meta.SessionID, meta.SourceSHA256)','ctx.Err()'),
      'actual-readback':('actualName != name || actualIndex != index || actualMTU != mtu','false'),
    }
    lock=(root/'mobile/strategy/observation.go.tmpl').read_text();lock=lock[:lock.index('func RouterVPNInboundContext(')]+'\ntype Inbound interface{}\n'
    with tempfile.TemporaryDirectory(prefix='ordered-mtu-confirmation-') as temp:
        work=Path(temp);(work/'adapter').mkdir();(work/'adapter/adapter.go').write_text(lock)
        (work/'go.mod').write_text('module router-vpn/paired-mtu-fixture\n\ngo 1.26.3\nrequire router-vpn v0.0.0\nreplace router-vpn => '+str(root)+'\n')
        (work/'confirmation_test.go').write_text(original+test)
        for label in ('original',*controls):
            actual=method
            if label!='original':
                before,after=controls[label]
                if actual.count(before)!=1:raise ValueError('ordered control lost original source: '+label)
                actual=actual.replace(before,after,1)
                if label=='actual-readback':actual=actual.replace('actualName, actualIndex, actualMTU, err :=','_, _, _, err =',1)
            (work/'confirmation.go').write_text(paired.HEADER+actual)
            result=subprocess.run([go,'test','-race','-p=1','-count=1','-timeout=30s','-v','.'],cwd=work,env=captured,capture_output=True,text=True,timeout=120)
            output=result.stdout+result.stderr
            if any(x in output for x in ('build failed','DATA RACE','panic:')):raise AssertionError(output)
            if label=='original':
                if result.returncode or output.count('--- PASS: TestActualTypedPhysicalConfirmation/')!=9:raise AssertionError(output)
            elif result.returncode==0 or 'typed physical confirmation verdict changed' not in output:raise AssertionError(label+'\n'+output)
            print('Typed physical source control: '+label+' verified',flush=True)

    load(root,'test_darwin_ordered_mtu_reader.py').execute_parent_source(root,go,captured,'typed')
    print('Typed original parent method: 22 cases and 3 causal controls verified',flush=True)


def validate_receipt(receipt,source_hash,child_hash,box_hash):
    keys={'schema','scope','cases','source_sha256','command_sha256','box_sha256','output_sha256'}
    if not isinstance(receipt,dict) or set(receipt)!=keys or receipt['schema']!=1 or receipt['scope']!='typed-execution-mtu-component-boundaries' or receipt['cases']!=list(CASES) or len(CASES)!=72 or len(set(CASES))!=72 or receipt['source_sha256']!=source_hash or receipt['command_sha256']!=child_hash or receipt['box_sha256']!=box_hash or not isinstance(receipt['output_sha256'],str) or len(receipt['output_sha256'])!=64 or any(c not in '0123456789abcdef' for c in receipt['output_sha256']):
        raise ValueError('typed/execution MTU boundary receipt lost exact source/image/inventory')


def execute(gate,source,before,compiler,captured,child,identities,work):
    execute_source(go=str(compiler),environment=captured)
    box=work/'paired-node-box.test'
    if box not in identities:raise ValueError('ordered MTU gate lost original compiled Box image')
    original=dict(identities);outputs=[]
    for root in ROOTS:
        image=child if root==COMMAND else box
        if gate.checked_sources(source)[1]!=before or any(gate.image_identity(path)!=value for path,value in original.items()):raise ValueError('ordered MTU source/image changed before phase')
        expected=(root,*(root+'/'+leaf for leaf in ROOTS[root]))
        output=gate.UID.run([image,'-test.run=^'+root+'$','-test.v','-test.count=1','-test.timeout=90s'],cwd=source,env=captured,timeout=100)
        gate.NODE.require_native_verdicts(output,expected,'typed/execution original MTU '+root)
        if gate.checked_sources(source)[1]!=before or any(gate.image_identity(path)!=value for path,value in original.items()):raise ValueError('ordered MTU source/image changed during phase')
        outputs.append(output)
    receipt=dict(schema=1,scope='typed-execution-mtu-component-boundaries',cases=list(CASES),source_sha256=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest(),command_sha256=original[child][-1],box_sha256=original[box][-1],output_sha256=hashlib.sha256('\n'.join(outputs).encode()).hexdigest())
    validate_receipt(receipt,receipt['source_sha256'],original[child][-1],original[box][-1]);return receipt

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--go',default='go');args=parser.parse_args();execute_source(go=args.go)
