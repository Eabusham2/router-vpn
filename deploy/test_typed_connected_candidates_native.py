#!/usr/bin/env python3
"""Additional exact encrypted typed connected candidate ownership suite."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
BASE=module('connected_native_base',ROOT/'deploy/test_focused_socks_bridge.py')
PARTITIONS=module('connected_native_partitions',ROOT/'deploy/typed_connected_candidates_native.py')

def validate(source,source_sha,output,family,go='go'):
    if family not in PARTITIONS.CASES or not BASE.HEX40.fullmatch(source_sha):raise ValueError('exact connected family/source required')
    source=Path(source).resolve(strict=True);output=Path(output).absolute()
    if output.exists() or output.is_symlink() or source==output or source in output.parents:raise ValueError('fresh external output required')
    if BASE.COMMON.git(source,'rev-parse','HEAD')!=source_sha or BASE.COMMON.git(source,'status','--porcelain','--untracked-files=all'):raise ValueError('connected source is not the exact clean commit')
    source_tree=BASE.COMMON.git(source,'rev-parse','HEAD^{tree}')
    if BASE.COMMON.git(ROOT,'rev-parse','HEAD')!=source_sha or BASE.COMMON.git(ROOT,'rev-parse','HEAD^{tree}')!=source_tree or BASE.COMMON.git(ROOT,'status','--porcelain','--untracked-files=all'):
        raise ValueError('connected validator and source must be the same clean published commit')
    before=BASE.CORE.snapshot(source)
    compiler=shutil.which(go)
    if compiler is None:raise ValueError('original pinned compiler missing')
    env=dict(os.environ,CGO_ENABLED='1',GOTOOLCHAIN='local',GOWORK='off',GOFLAGS='',PYTHONDONTWRITEBYTECODE='1',GOMAXPROCS='2',GOGC='100',GOMEMLIMIT='2GiB')
    env['PATH']=str(Path(compiler).parent)+os.pathsep+env.get('PATH','')
    version=subprocess.check_output([compiler,'version'],env=env,text=True,timeout=30).strip()
    if version!='go version go1.26.3 linux/amd64':raise ValueError('original pinned Linux compiler required')
    output.mkdir(parents=True,mode=0o700)
    receipt=dict(schema=1,status='running',source_sha=source_sha,source_tree=source_tree,family=family,cases=list(PARTITIONS.CASES[family]),phases=[],go_version=version,
        scope='original complete typed Run plus fifty candidate TCP handshakes through captured encrypted packet prefix',
        boundaries=['original test TUN','first physical tuple loopback mapping','isolated original TLS roots'],installed_host_accepted=False,replacement_authentication_accepted=False,
        executor_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),partition_sha256=hashlib.sha256((ROOT/'deploy/typed_connected_candidates_native.py').read_bytes()).hexdigest())
    (output/'source-before.json').write_text(json.dumps(before,sort_keys=True)+'\n')
    def save():(output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    def run(name,command,cwd,bound,captured=None):
        command=list(map(str,command));log=output/(name+'.log');start=time.monotonic()
        status,timed_out,joined=BASE.CORE.execute(command,cwd,captured or env,log,bound)
        raw=log.read_bytes();receipt['phases'].append(dict(name=name,command=command,bound=bound,status=status,timed_out=timed_out,process_group_joined=joined,seconds=time.monotonic()-start,sha256=hashlib.sha256(raw).hexdigest()));save()
        if timed_out or not joined:raise ValueError('connected candidate process did not join its original bound')
        return status,raw
    save()
    try:
        with tempfile.TemporaryDirectory(prefix='typed-connected-native-',dir=output.parent) as directory:
            work=Path(directory);mobile=work/'mobile';mx=work/'mobile-xray';owner=work/'owner';ox=work/'owner-xray'
            status,raw=run('original-daemon-preflight',[sys.executable,source/'deploy/test_desktop_tor_preparation.py','--daemon-capture-only'],source,60)
            BASE.OWNER.require_daemon_preflight(raw.decode(),status)
            for name,core,xray,flag in (('owner',owner,ox,'--prepare-owner'),('mobile',mobile,mx,'--prepare-mobile')):
                status,_=run('prepare-'+name,[sys.executable,ROOT/'deploy/test_focused_socks_bridge.py',flag,'--source',source,'--source-sha',source_sha,'--core',core,'--xray',xray,'--go',compiler],source,600)
                if status:raise ValueError('actual connected native source preparation failed')
            native=module('connected_original_projection',source/('deploy/test_focused_'+family.lower()+'_run.py'))
            native_before=native.sources(source,mobile,mx,owner,ox)
            prep=module('connected_original_templates',source/'deploy/prepare-mobile-node-chain.py')
            PARTITIONS.projection(source,mobile,prep.TEMPLATES)
            (output/'native-before.json').write_text(json.dumps(native_before,sort_keys=True)+'\n')
            gate=BASE.OWNER.load_gate(source);compiler,captured,arch=gate.NODE.selected_compiler(compiler,owner,env)
            if arch!='amd64':raise ValueError('connected native peer architecture changed')
            env.update(captured);env['CGO_ENABLED']='1'
            peer=work/'peer.test';client=work/'client.test'
            for name,image,core,target,tags in (('peer',peer,owner,'./protocol/routervpnamnezia',','.join(gate.NODE.TAGS)),('client',client,mobile,'./experimental/libbox',BASE.TAGS)):
                status,_=run(name+'-build',[compiler,'test','-c','-race','-p=1','-mod=readonly','-tags='+tags,'-ldflags=-checklinkname=0','-o',image,target],core,600)
                if status:raise ValueError('actual connected native '+name+' build failed')
            identities={'peer':list(BASE.COMMON.image_identity(peer)),'client':list(BASE.COMMON.image_identity(client))}
            receipt['peer_accounting']=PARTITIONS.accounting(BASE,run,compiler,owner,peer,env,work/'accounting')
            receipt.update(PARTITIONS.validate(BASE,run,compiler,mobile,peer,client,env,family))
            if native.sources(source,mobile,mx,owner,ox)!=native_before:raise ValueError('connected native source changed during execution')
            PARTITIONS.projection(source,mobile,prep.TEMPLATES)
            if BASE.CORE.snapshot(source)!=before or BASE.COMMON.git(source,'status','--porcelain','--untracked-files=all') or BASE.COMMON.git(source,'rev-parse','HEAD')!=source_sha:raise ValueError('original connected source changed')
            receipt.update(status='passed',images=identities,source_unchanged=True)
    except BaseException as error:
        receipt.update(status='failed',error=type(error).__name__+': '+str(error));raise
    finally:save()
    return receipt

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--require-commit',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--family',choices=tuple(PARTITIONS.CASES),required=True);p.add_argument('--go',default='go');a=p.parse_args();validate(a.source,a.require_commit,a.output,a.family,a.go)
