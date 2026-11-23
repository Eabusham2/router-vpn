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

def execute_mtu_variant(gate,work,label,go='go',environment=None,*,owner='parent'):
    """Compile each MTU fixture before starting its original execution deadline."""
    if owner not in ('box', 'parent'):
        raise ValueError('Unknown MTU fixture owner')
    title = owner.capitalize() + ' MTU ' + label
    work=Path(work).resolve(strict=True)
    image=work/(owner+'-'+label+'.test')
    if image.exists() or image.is_symlink():
        raise ValueError(title+' cannot reuse an earlier image')
    def sources():
        paths=sorted({*work.rglob('*.go'),*(p for p in (work/'go.mod',work/'go.sum') if p.exists())})
        if any(p.is_symlink() or not p.is_file() for p in paths):
            raise ValueError(title+' lost its original source files')
        return {str(p.relative_to(work)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before=sources()
    command=[go,'test','-c','-race','-p=1','-o',image,'.']
    command,captured=gate.UID.RACE.command(command,work,dict(os.environ if environment is None else environment))
    print(title+': compiling original race image',flush=True)
    try:
        gate.UID.run(command,cwd=work,env=captured,timeout=600)
    except Exception as error:
        output=getattr(error,'output',b'') or b''
        if isinstance(output,bytes):output=output.decode('utf-8',errors='replace')
        raise AssertionError(title+' compilation failed: '+str(error)+'\n'+output[-8192:]) from error
    identity=gate.image_identity(image)
    if sources()!=before:
        raise ValueError(title+' source changed during compilation')
    command=[image,'-test.count=1','-test.timeout=30s','-test.v']
    print(title+': executing original 30-second test deadline',flush=True)
    try:
        output=gate.UID.run(command,cwd=work,env=captured,timeout=120)
        code=0
    except subprocess.CalledProcessError as error:
        output=error.output or b''
        if isinstance(output,bytes):output=output.decode('utf-8',errors='replace')
        code=error.returncode
    except Exception as error:
        raise AssertionError(title+' execution failed: '+str(error)) from error
    if sources()!=before or gate.image_identity(image)!=identity:
        raise ValueError(title+' original image or source changed during execution')
    return subprocess.CompletedProcess(command,code,output)

def execute_parent_source(root,go,environment,kind):
    # Execute the same original unittest method in this process. A second
    # Python timeout must not wrap four bounded compiler/test stages inside
    # one of the individual test execution budgets.
    cases={
        'ordinary':('test_darwin_ordered_mtu_reader_runner.py','OrderedMTUBoundaries',
                    'test_actual_ordinary_parent_requires_ack_retirement_and_readback'),
        'typed':('test_darwin_typed_mtu_reader_runner.py','TypedMTUBoundaries',
                 'test_actual_typed_parent_requires_ack_retirement_and_readback'),
    }
    if kind not in cases:
        raise ValueError('unknown original parent MTU source family')
    filename,owner,method=cases[kind]
    module=load(root,filename)
    case=getattr(module,owner)(method)
    case.parent_go=str(go)
    case.parent_environment=dict(environment)
    case.debug()

def execute_box_source(root=ROOT,go='go',environment=None):
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
            result=paired.execute_box_variant(work,label,go,captured)
            output=result.stdout
            if any(x in output for x in ('build failed','DATA RACE','panic:')):raise AssertionError(output)
            if label=='original':
                if result.returncode or output.count('--- PASS: TestActualOrderedConfirmation/')!=13:raise AssertionError(output)
            elif result.returncode==0 or 'ordered original confirmation verdict changed' not in output:raise AssertionError(label+'\n'+output)
            print('Ordered original Box source control: '+label+' verified',flush=True)


def execute_source(root=ROOT,go='go',environment=None):
    captured=dict(os.environ if environment is None else environment,GOTOOLCHAIN='local')
    execute_box_source(root,go,captured)
    execute_parent_source(root,go,captured,'ordinary')
    print('Ordered original parent method: 22 cases and 3 causal controls verified',flush=True)


def validate_receipt(receipt,source_hash,child_hash,box_hash):
    keys={'schema','scope','cases','source_sha256','command_sha256','box_sha256','output_sha256'}
    if not isinstance(receipt,dict) or set(receipt)!=keys or receipt['schema']!=1 or receipt['scope']!='ordinary-ordered-mtu-component-boundaries' or receipt['cases']!=list(CASES) or len(CASES)!=31 or len(set(CASES))!=31 or receipt['source_sha256']!=source_hash or receipt['command_sha256']!=child_hash or receipt['box_sha256']!=box_hash or not isinstance(receipt['output_sha256'],str) or len(receipt['output_sha256'])!=64 or any(c not in '0123456789abcdef' for c in receipt['output_sha256']):
        raise ValueError('ordinary ordered MTU boundary receipt lost exact source/image/inventory')


def execute(gate,source,before,compiler,captured,child,identities,work):
    execute_source(go=str(compiler),environment=captured)
    return execute_images(gate,source,before,captured,child,identities,work)


def execute_images(gate,source,before,captured,child,identities,work):
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
