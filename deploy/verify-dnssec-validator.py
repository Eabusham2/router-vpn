#!/usr/bin/env python3
"""Verify the pinned validator package before a separate owner seals/loads it."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess
ROOT=Path(__file__).resolve().parents[1]
EXPORTS=sorted('rvdns_'+x for x in ('abi','create','anchor','insecure','start','fd','process','cancel','result','destroy'))

def regular(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('package input is not a regular file: '+str(path))
    return path.read_bytes()

def verify(directory, architecture):
    manifest=json.loads(regular(directory/'manifest.json'))
    source=json.loads((ROOT/'native/dnssec/sources.json').read_text())
    if manifest['schema']!=1 or manifest['abi']!=1 or manifest['platform']!='linux' or manifest['architecture']!=architecture or manifest['sources']!=source:
        raise ValueError('package target/source identity mismatch')
    for key,path in [('shim_sha256',ROOT/'native/dnssec/validator.c'),('header_sha256',ROOT/'native/dnssec/validator.h'),('builder_sha256',ROOT/'deploy/build-dnssec-validator.py')]:
        if manifest[key]!=hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError('package source freshness mismatch: '+key)
    artifact=directory/'libroutervpn_dnssec.so'; content=regular(artifact)
    if manifest['artifact_size']!=len(content) or manifest['artifact_sha256']!=hashlib.sha256(content).hexdigest():
        raise ValueError('package artifact size/hash mismatch')
    machine={'x86_64':62,'aarch64':183}.get(architecture)
    if content[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(content[18:20],'little')!=machine or manifest['elf_machine']!=machine:
        raise ValueError('package ELF target mismatch')
    dynamic=subprocess.check_output(['/usr/bin/readelf','-d',str(artifact)],text=True)
    needed=[line.split('[')[1].split(']')[0] for line in dynamic.splitlines() if '(NEEDED)' in line]
    if needed!=manifest['needed'] or any(x not in ('libc.so.6','libpthread.so.0','libdl.so.2') for x in needed) or '(RPATH)' in dynamic or '(RUNPATH)' in dynamic:
        raise ValueError('package dependency mismatch')
    symbols=subprocess.check_output(['/usr/bin/nm','-D','--defined-only',str(artifact)],text=True)
    exports=sorted(line.split()[-1] for line in symbols.splitlines())
    if exports!=EXPORTS or sorted(manifest['exports'])!=EXPORTS:
        raise ValueError('package export mismatch')
    for name in ('unbound','openssl'):
        for filename,expected in source[name]['licenses'].items():
            if hashlib.sha256(regular(directory/'licenses'/(name+'-'+filename))).hexdigest()!=expected:
                raise ValueError('package license mismatch')
    if manifest['configure_projection']['removed_block_sha256']!='e36da3b8403ee6723434ad496633843b38655902f794f15d321bba4c29d85825' or manifest['configure_projection']['projected_sha256']!='f4b9df17aab6933befc8041f6c57c1dc7b869e52dfacbab6a4b0d80cd6500792':
        raise ValueError('package configure projection mismatch')
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True)
    p.add_argument('--architecture',choices=('x86_64','aarch64'),required=True)
    args=p.parse_args()
    result=verify(args.build,args.architecture)
    print('Verified DNSSEC ABI 1',args.architecture,result['artifact_sha256'])
