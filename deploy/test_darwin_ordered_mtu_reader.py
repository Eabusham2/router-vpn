#!/usr/bin/env python3
"""Original ordinary ordered MTU authority: source controls and exact native images.

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
COMMAND='TestRouterVPNDesktopNodeChainDarwinMTUOriginalSuccession'
BOX='TestRouterVPNDesktopNodeChainDarwinMTUReader'
ROOTS={COMMAND:('same-alias','renamed','missing-capability','refused-capability','foreign-policy','same-index','same-reader','missing-state','unjoined-state','unrevoked-state','foreign-predecessor','cancelled','mixed-prefix','mixed-openvpn'),
 BOX:('original','equal-policy-pointer','foreign-box','foreign-reader','nil-policy','detached','fixed-alias','session','config','name','index','mtu','readback','source','cancelled')}
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
    method=function(root,'mobile/desktop/node_box_physical.go.tmpl','func (owner *RouterVPNDesktopNodePhysical) ConfirmOrderedDarwinMTUReader(')
    target=function(root,'mobile/desktop/node_chain_box_physical.go.tmpl','func routerVPNDesktopNodeChainPhysicalTarget(')
    original=function(root,'mobile/desktop/node_chain_physical_darwin_test.go.tmpl','func nodeDarwinOrderedPolicy(').split('\ntype ')[0]
    imports='''package confirmation
import("bytes";"context";"crypto/ecdh";"crypto/sha256";"encoding/base64";"encoding/hex";"encoding/json";"fmt";"strings";"testing";"router-vpn/internal/mobilemultihop")
'''
    test=r'''
func TestActualOrderedConfirmation(t *testing.T){
 for _,fault:=range []string{"original","equal-policy-pointer","wrong-family","wrong-platform","box","reader","detached","alias","session","config","source","readback","cancelled"}{t.Run(fault,func(t *testing.T){
  p:=nodeDarwinOrderedPolicy(t,[]string{"wg","awg2-fast"});m:=p.Metadata();b:=&Box{1};n:=&Box{2};expected:=p
  o:=&RouterVPNDesktopNodePhysical{instance:b,inbound:n,policy:p,network:&modeledNetwork{session:m.SessionID,source:m.SourceSHA256},name:"utun91",index:92,mtu:1380}
  ctx,cancel:=context.WithCancel(t.Context());defer cancel();session,config:=m.SessionID,m.ConfigSHA256
  switch fault{
  case "equal-policy-pointer":expected=nodeDarwinOrderedPolicy(t,[]string{"wg","awg2-fast"});if expected.Config()!=p.Config()||expected.Metadata().SourceSHA256!=m.SourceSHA256{t.Fatal("policy clone is not semantically equal")}
  case "wrong-family":o.policy=nil
  case "wrong-platform":var err error;expected,err=mobilemultihop.NewDesktopNodeChainPolicy(p.OriginalChain(),m.SessionID,"linux",0);if err!=nil{t.Fatal(err)};o.policy=expected;o.network.source=expected.Metadata().SourceSHA256;config=expected.Metadata().ConfigSHA256
  case "box":b=&Box{3}
  case "reader":n=&Box{3}
  case "detached":o.detached=true
  case "alias":o.interfaceName="utun91"
  case "session":session+="bad"
  case "config":config+="bad"
  case "source":o.network.refused=true
  case "readback":o.index++
  case "cancelled":cancel()
  }
  err:=o.ConfirmOrderedDarwinMTUReader(ctx,b,expected,n,session,config,"utun91",92,1380)
  if (err==nil)!=(fault=="original"){t.Fatal("ordered original confirmation verdict changed",fault,err)}
 })}
}
'''
    controls={
      'original-policy-pointer':('policy != expected','false'),
      'original-box':('owner.instance != instance','false'),
      'original-reader':('owner.inbound != next','false'),
      'original-source':('owner.network.MatchesContext(ctx, meta.SessionID, meta.SourceSHA256)','ctx.Err()'),
      'actual-readback':('actualName != name || actualIndex != index || actualMTU != mtu','false'),
    }
    lock=(root/'mobile/strategy/observation.go.tmpl').read_text();lock=lock[:lock.index('func RouterVPNInboundContext(')]+'\ntype Inbound interface{}\n'
    with tempfile.TemporaryDirectory(prefix='ordered-mtu-confirmation-') as temp:
        work=Path(temp);(work/'adapter').mkdir();(work/'adapter/adapter.go').write_text(lock)
        (work/'go.mod').write_text('module router-vpn/paired-mtu-fixture\n\ngo 1.26.3\nrequire router-vpn v0.0.0\nreplace router-vpn => '+str(root)+'\n')
        (work/'confirmation_test.go').write_text(imports+original+test)
        for label in ('original',*controls):
            actual=method
            if label!='original':
                before,after=controls[label]
                if actual.count(before)!=1:raise ValueError('ordered control lost original source: '+label)
                actual=actual.replace(before,after,1)
                if label=='actual-readback':actual=actual.replace('actualName, actualIndex, actualMTU, err :=','_, _, _, err =',1)
            (work/'confirmation.go').write_text(paired.HEADER+target+actual)
            result=subprocess.run([go,'test','-race','-p=1','-count=1','-timeout=30s','-v','.'],cwd=work,env=captured,capture_output=True,text=True,timeout=120)
            output=result.stdout+result.stderr
            if any(x in output for x in ('build failed','DATA RACE','panic:')):raise AssertionError(output)
            if label=='original':
                if result.returncode or output.count('--- PASS: TestActualOrderedConfirmation/')!=13:raise AssertionError(output)
            elif result.returncode==0 or 'ordered original confirmation verdict changed' not in output:raise AssertionError(label+'\n'+output)
            print('Ordered original Box source control: '+label+' verified',flush=True)

    parent=subprocess.run([sys.executable,str(root/'deploy/test_darwin_ordered_mtu_reader_runner.py'),
                           'OrderedMTUBoundaries.test_actual_ordinary_parent_requires_ack_retirement_and_readback'],
                          cwd=root,env=dict(captured,GO=str(go)),capture_output=True,text=True,timeout=120)
    if parent.returncode:raise AssertionError(parent.stdout+parent.stderr)
    print('Ordered original parent method: 22 cases and 3 causal controls verified',flush=True)


def validate_receipt(receipt,source_hash,child_hash,box_hash):
    keys={'schema','scope','cases','source_sha256','command_sha256','box_sha256','output_sha256'}
    if not isinstance(receipt,dict) or set(receipt)!=keys or receipt['schema']!=1 or receipt['scope']!='ordinary-ordered-mtu-component-boundaries' or receipt['cases']!=list(CASES) or len(CASES)!=31 or len(set(CASES))!=31 or receipt['source_sha256']!=source_hash or receipt['command_sha256']!=child_hash or receipt['box_sha256']!=box_hash or not isinstance(receipt['output_sha256'],str) or len(receipt['output_sha256'])!=64 or any(c not in '0123456789abcdef' for c in receipt['output_sha256']):
        raise ValueError('ordinary ordered MTU boundary receipt lost exact source/image/inventory')


def execute(gate,source,before,compiler,captured,child,identities,work):
    execute_source(go=str(compiler),environment=captured)
    box=work/'paired-node-box.test'
    if box not in identities:raise ValueError('ordered MTU gate lost original compiled Box image')
    original=dict(identities);outputs=[]
    for image,root in ((child,COMMAND),(box,BOX)):
        if gate.checked_sources(source)[1]!=before or any(gate.image_identity(path)!=value for path,value in original.items()):raise ValueError('ordered MTU source/image changed before phase')
        expected=(root,*(root+'/'+leaf for leaf in ROOTS[root]))
        output=gate.UID.run([image,'-test.run=^'+root+'$','-test.v','-test.count=1','-test.timeout=90s'],cwd=source,env=captured,timeout=100)
        gate.NODE.require_native_verdicts(output,expected,'ordinary ordered original MTU '+root)
        if gate.checked_sources(source)[1]!=before or any(gate.image_identity(path)!=value for path,value in original.items()):raise ValueError('ordered MTU source/image changed during phase')
        outputs.append(output)
    receipt=dict(schema=1,scope='ordinary-ordered-mtu-component-boundaries',cases=list(CASES),source_sha256=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest(),command_sha256=original[child][-1],box_sha256=original[box][-1],output_sha256=hashlib.sha256('\n'.join(outputs).encode()).hexdigest())
    validate_receipt(receipt,receipt['source_sha256'],original[child][-1],original[box][-1]);return receipt

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--go',default='go');args=parser.parse_args();execute_source(go=args.go)
