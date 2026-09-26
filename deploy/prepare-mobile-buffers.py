#!/usr/bin/env python3
"""Preserve complete UDP ciphertext in the exact pinned mobile Sing dependency.

Only UDP capacity changes; TCP buffers, wire protocol, authentication and packet
lengths remain unchanged. The original verified module cache is never modified.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

PIN='1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODULE='github.com/sagernet/sing'
VERSION='v0.9.4'
FILES={
 'common/buf/buffer_standard.go':('608fbf3f13067a7568c491990dba764b81107e87','16 * 1024'),
 'common/buf/buffer_low_memory.go':('81fb10a26460dea3586486118d091a43020284eb','8 * 1024'),
}
def blobsha(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def patched(source):
    result={}
    for name,(digest,size) in FILES.items():
        raw=(source/name).read_bytes()
        if blobsha(raw)!=digest:raise ValueError('pinned UDP buffer source differs')
        before=('UDPBufferSize = '+size).encode()
        if raw.count(before)!=1:raise ValueError('pinned UDP capacity boundary changed')
        result[name]=raw.replace(before,b'UDPBufferSize = 65535',1)
    return result

def copy_verified(source,dest):
    replacement=patched(source)
    if not (source/'go.mod').read_text().startswith('module '+MODULE+'\n'):
        raise ValueError('unexpected native buffer module')
    # Never follow symlinks out of the checksum-verified module tree.
    for path in source.rglob('*'):
        if path.is_symlink():raise ValueError('dependency source contains a symlink')
    if dest.exists():
        marker=dest/'.routervpn-buffer-policy.json'
        wanted={name:hashlib.sha256(raw).hexdigest() for name,raw in replacement.items()}
        if not marker.is_file() or json.loads(marker.read_text())!={'module':MODULE,'version':VERSION,'files':wanted}:
            raise ValueError('existing native dependency copy is not owned by this policy')
        expected={str(p.relative_to(source)):replacement.get(str(p.relative_to(source)),p.read_bytes()) for p in source.rglob('*') if p.is_file()}
        actual={str(p.relative_to(dest)) for p in dest.rglob('*') if p.is_file() and p.name!='.routervpn-buffer-policy.json'}
        if actual!=set(expected):raise ValueError('native dependency copy file set drifted')
        for name,raw in expected.items():
            target=dest/name
            if target.is_symlink() or target.read_bytes()!=raw:
                raise ValueError('native dependency copy differs from verified source')
        return
    dest.parent.mkdir(parents=True,exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix='sing-buffer-',dir=dest.parent))
    try:
        shutil.copytree(source,staging,dirs_exist_ok=True,copy_function=shutil.copyfile)
        # copytree copies directory metadata even with copyfile for files. Go's
        # immutable module cache uses read-only directories; only our fresh
        # disposable copy receives owner-write permission, never that cache.
        for folder in [staging, *(p for p in staging.rglob('*') if p.is_dir())]:
            if folder.is_symlink():raise ValueError('unsafe staged source directory')
            folder.chmod(folder.stat().st_mode | 0o700)
        for name,raw in replacement.items():(staging/name).write_bytes(raw)
        (staging/'.routervpn-buffer-policy.json').write_text(json.dumps({'module':MODULE,'version':VERSION,'files':{name:hashlib.sha256(raw).hexdigest() for name,raw in replacement.items()}},sort_keys=True))
        os.replace(staging,dest)
    finally:
        if staging.exists():shutil.rmtree(staging)

def prepare(vendor):
    vendor=vendor.resolve()
    head=subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()
    if head!=PIN or not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('native UDP policy requires the pinned disposable Libbox checkout')
    def go(*args):return subprocess.check_output(['go',*args],cwd=vendor,text=True)
    # Download by explicit version and use the Go checksum database. Source file
    # Git blob digests above independently bind both edits to that exact source.
    env=os.environ.copy();env['GOSUMDB']='sum.golang.org'
    info=json.loads(subprocess.check_output(['go','mod','download','-json',MODULE+'@'+VERSION],cwd=vendor,env=env,text=True))
    if info.get('Error') or info.get('Path')!=MODULE or info.get('Version')!=VERSION or not info.get('Sum','').startswith('h1:'):
        raise ValueError('native dependency checksum verification failed')
    source=Path(info['Dir']).resolve()
    dest=vendor/'.routervpn-sources/sing'
    copy_verified(source,dest)
    go('mod','edit','-replace='+MODULE+'='+str(dest))
    go('mod','tidy')
    print('Verified native UDP buffer policy: complete 65535-byte ciphertext; TCP capacities unchanged')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('vendor',type=Path)
    prepare(parser.parse_args().vendor)
