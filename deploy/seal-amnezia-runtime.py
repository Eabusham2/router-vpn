#!/usr/bin/env python3
"""Reseal only the verified macOS native AWG engine after code signing."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import subprocess
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('amnezia_build',ROOT/'deploy/build-amnezia-runtime.py')
BUILD=importlib.util.module_from_spec(spec);spec.loader.exec_module(BUILD)

def seal(directory,target):
    if target not in ('darwin/amd64','darwin/arm64'):
        raise ValueError('Only macOS signing may change native AWG engine bytes')
    directory=Path(directory)
    if directory.is_symlink():raise ValueError('Linked native AWG directory')
    receipt_path=directory/'AMNEZIA-RUNTIME.json'
    receipt=json.loads(BUILD.regular(receipt_path,8192))
    binary=directory/'sing-box-amnezia'
    raw=BUILD.regular(binary,BUILD.MAX_BINARY)
    if receipt['target']!=target or receipt['upstream_revision']!=BUILD.PIN or receipt['policy_sha256']!=BUILD.digest() or BUILD.marker(BUILD.digest()).encode() not in raw:
        raise ValueError('Native AWG source identity changed before signing')
    subprocess.run(['codesign','--verify','--strict',str(binary)],check=True,timeout=20)
    BUILD.check_target(binary,target,BUILD.environment(target))
    receipt['size']=len(raw);receipt['sha256']=hashlib.sha256(raw).hexdigest()
    receipt_path.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    BUILD.reuse(directory,target,BUILD.digest(),BUILD.environment(target))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path);parser.add_argument('target')
    args=parser.parse_args();seal(args.directory,args.target)
