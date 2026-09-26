#!/usr/bin/env python3
"""Build corrected Xray from its exact revision for one desktop/server target.

The destination is an owned build directory, not an installed live runtime.
No precompiled upstream or moving-ref fallback is accepted.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('shared_xray',ROOT/'deploy/prepare-xray-runtime.py')
POLICY=importlib.util.module_from_spec(spec);spec.loader.exec_module(POLICY)
TARGETS=tuple(f'{system}/{arch}' for system in ('linux','darwin','windows') for arch in ('amd64','arm64'))
TOOLCHAIN='go1.26.3'
MAX_BINARY=160*1024*1024

def run(args,*,cwd=None,env=None):
    return subprocess.check_output(args,cwd=cwd,env=env,text=True,timeout=600).strip()

def marker(policy):
    return 'routervpn-'+POLICY.XRAY_PIN+'.'+policy

def environment(target):
    if target not in TARGETS:raise ValueError('Unsupported Xray build target')
    system,arch=target.split('/')
    env=os.environ.copy()
    env.update(GOTOOLCHAIN=TOOLCHAIN,GOWORK='off',GOFLAGS='',CGO_ENABLED='0',GOOS=system,GOARCH=arch,
               GOAMD64='v1',GOARM64='v8.0',GOSUMDB='sum.golang.org')
    return env

def regular(path,maximum):
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=maximum:
        raise ValueError('Invalid engine package input: '+str(path))
    return path.read_bytes()

def check_target(binary,target,env):
    metadata=run(['go','version','-m',str(binary)],env=env)
    system,arch=target.split('/')
    for required in ('GOOS='+system,'GOARCH='+arch,'CGO_ENABLED=0',TOOLCHAIN):
        if required not in metadata:raise ValueError('Engine build metadata differs: '+required)

def reuse(destination,target,policy,env):
    receipt=json.loads(regular(destination/'XRAY-RUNTIME.json',8192))
    binary=destination/('xray.exe' if target.startswith('windows/') else 'xray')
    raw=regular(binary,MAX_BINARY)
    expected={'schema_version':1,'runtime':'xray','version':POLICY.VERSION,'upstream_revision':POLICY.XRAY_PIN,
              'policy_sha256':policy,'target':target,'toolchain':TOOLCHAIN,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    if receipt!=expected:raise ValueError('Existing engine bundle differs from this exact source policy')
    regular(destination/'XRAY-LICENSE',128*1024)
    check_target(binary,target,env)
    return receipt

def fetch_source(path):
    run(['git','init',str(path)])
    run(['git','-C',str(path),'remote','add','origin','https://github.com/XTLS/Xray-core.git'])
    run(['git','-C',str(path),'fetch','--depth=1','origin',POLICY.XRAY_PIN])
    run(['git','-C',str(path),'checkout','--detach','FETCH_HEAD'])

def build(target,destination,source=None):
    env=environment(target)
    destination=Path(destination).absolute()
    if destination.is_symlink():raise ValueError('Refusing a symlink engine destination')
    destination.parent.mkdir(parents=True,exist_ok=True)
    policy=POLICY.digest()
    if destination.is_dir() and any(destination.iterdir()):
        reuse(destination,target,policy,env)
        print('Reused verified corrected Xray '+target,flush=True)
        return destination
    # Publish all files together. A failed compile or validation cannot leave a
    # partial directory that another package builder mistakes for ready.
    with tempfile.TemporaryDirectory(prefix='.xray-build-',dir=destination.parent) as temp:
        temp=Path(temp)
        if source is None:
            source=temp/'source';fetch_source(source)
        source=Path(source).resolve()
        POLICY.prepare(source)
        if run(['go','env','GOVERSION'],env=env)!=TOOLCHAIN:raise ValueError('Incorrect pinned Go compiler')
        run(['go','mod','download'],cwd=source,env=env)
        run(['go','mod','verify'],cwd=source,env=env)
        stage=temp/'bundle';stage.mkdir()
        binary=stage/('xray.exe' if target.startswith('windows/') else 'xray')
        ldflags='-s -w -buildid= -checklinkname=0 -X github.com/xtls/xray-core/core.build='+marker(policy)
        run(['go','build','-mod=readonly','-trimpath','-buildvcs=false','-ldflags='+ldflags,'-o',str(binary),'./main'],cwd=source,env=env)
        check_target(binary,target,env)
        raw=regular(binary,MAX_BINARY)
        receipt={'schema_version':1,'runtime':'xray','version':POLICY.VERSION,'upstream_revision':POLICY.XRAY_PIN,
                 'policy_sha256':policy,'target':target,'toolchain':TOOLCHAIN,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        (stage/'XRAY-RUNTIME.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
        license=regular(source/'LICENSE',128*1024)
        (stage/'XRAY-LICENSE').write_bytes(license)
        binary.chmod(0o755)
        reuse(stage,target,policy,env)
        if destination.exists():destination.rmdir() # require an empty owned staging destination
        os.replace(stage,destination)
    print('Built corrected Xray '+target+' '+policy,flush=True)
    return destination

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target',choices=TARGETS);parser.add_argument('destination',type=Path)
    parser.add_argument('--source',type=Path,help='existing disposable exact-pinned source checkout')
    args=parser.parse_args();build(args.target,args.destination,args.source)
