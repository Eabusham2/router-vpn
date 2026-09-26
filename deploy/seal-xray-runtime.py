#!/usr/bin/env python3
"""Reseal receipt bytes after validating the intended macOS code signature."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import subprocess
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('shared',ROOT/'deploy/prepare-xray-runtime.py')
POLICY=importlib.util.module_from_spec(spec);spec.loader.exec_module(POLICY)
def seal(directory,target):
    if target not in ('darwin/amd64','darwin/arm64'):raise ValueError('Only macOS engine signing changes its bytes')
    directory=Path(directory);binary=directory/'xray';receipt=directory/'XRAY-RUNTIME.json'
    if directory.is_symlink() or binary.is_symlink() or receipt.is_symlink():raise ValueError('Unsafe engine package')
    metadata=json.loads(receipt.read_text())
    if metadata['target']!=target or metadata['upstream_revision']!=POLICY.XRAY_PIN or metadata['policy_sha256']!=POLICY.digest():raise ValueError('Source identity changed before signing')
    subprocess.run(['codesign','--verify','--strict',str(binary)],check=True,timeout=20)
    info=subprocess.check_output(['go','version','-m',str(binary)],text=True,timeout=20)
    for expected in ('GOOS=darwin','GOARCH='+target.split('/')[1], 'routervpn-'+POLICY.XRAY_PIN+'.'+POLICY.digest()):
        if expected not in info:raise ValueError('Signed engine differs from its expected architecture/source')
    raw=binary.read_bytes();metadata['size']=len(raw);metadata['sha256']=hashlib.sha256(raw).hexdigest()
    receipt.write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);p.add_argument('target')
    a=p.parse_args();seal(a.directory,a.target)
