#!/usr/bin/env python3
"""Verify a corrected Xray already authenticated by the exact-SHA app package.

This receipt detects corruption and build/architecture mismatch. It does not
replace the outer release signature/checksum authentication or platform trust.
"""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import re
import subprocess

PIN='50231eaff98ccc31b5cbd247a721c16e97fe5ec1'
VERSION='26.7.11'
TOOLCHAIN='go1.26.3'

def host_target():
    systems={'Linux':'linux','Darwin':'darwin','Windows':'windows'}
    arches={'x86_64':'amd64','amd64':'amd64','aarch64':'arm64','arm64':'arm64'}
    try:return systems[platform.system()]+'/'+arches[platform.machine().lower()]
    except KeyError:raise ValueError('Unsupported native Xray host')

def regular(path,maximum):
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=maximum:raise ValueError('Unsafe or missing bundled Xray file')
    return path.read_bytes()

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Ambiguous bundled engine receipt')
        result[key]=value
    return result

def verify(directory,target=None,execute=True):
    directory=Path(directory).absolute()
    if directory.is_symlink():raise ValueError('Unsafe bundled engine directory')
    target=target or host_target()
    if target not in tuple(s+'/'+a for s in ('linux','darwin','windows') for a in ('amd64','arm64')):
        raise ValueError('Invalid bundled engine target')
    name='xray.exe' if target.startswith('windows/') else 'xray'
    receipt=json.loads(regular(directory/'XRAY-RUNTIME.json',8192),object_pairs_hook=unique_object)
    if not isinstance(receipt,dict) or set(receipt)!=set(('schema_version','runtime','version','upstream_revision','policy_sha256','target','toolchain','size','sha256')):
        raise ValueError('Invalid engine receipt schema')
    if receipt['schema_version']!=1 or receipt['runtime']!='xray' or receipt['version']!=VERSION or receipt['upstream_revision']!=PIN or receipt['target']!=target or receipt['toolchain']!=TOOLCHAIN:
        raise ValueError('Bundled Xray source or architecture mismatch')
    if not re.fullmatch('[0-9a-f]{64}',str(receipt['policy_sha256'])) or not re.fullmatch('[0-9a-f]{64}',str(receipt['sha256'])):
        raise ValueError('Invalid engine fingerprint')
    raw=regular(directory/name,160*1024*1024)
    if type(receipt['size']) is not int or receipt['size']!=len(raw) or hashlib.sha256(raw).hexdigest()!=receipt['sha256']:
        raise ValueError('Bundled engine checksum or size mismatch')
    regular(directory/'XRAY-LICENSE',128*1024)
    binary=directory/name
    if execute:
        if target!=host_target():raise ValueError('Cannot execute a different-architecture runtime')
        output=subprocess.check_output([str(binary),'version'],stderr=subprocess.STDOUT,text=True,timeout=10)
        marker='routervpn-'+PIN+'.'+receipt['policy_sha256']
        if not any('Xray '+VERSION in line and marker in line for line in output.splitlines()):
            raise ValueError('Binary does not identify the required corrected runtime')
    return receipt,binary

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    parser.add_argument('--path',action='store_true')
    args=parser.parse_args()
    try:receipt,binary=verify(args.directory)
    except (ValueError,OSError,subprocess.SubprocessError) as error:raise SystemExit(str(error))
    print(str(binary) if args.path else json.dumps(receipt,sort_keys=True))
