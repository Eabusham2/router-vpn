#!/usr/bin/env python3
"""Package the private pinned validator; this grants no DNS transport authority."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse
ROOT=Path(__file__).resolve().parents[1]
LIBRARY='libroutervpn_dnssec.so'
RECEIPT='DNSSEC-VALIDATOR.json'
LICENSES={'DNSSEC-UNBOUND-LICENSE':('unbound','LICENSE'),'DNSSEC-OPENSSL-LICENSE':('openssl','LICENSE.txt')}
EXPORTS=sorted('rvdns_'+x for x in ('abi','create','anchor','insecure','start','fd','process','cancel','result','destroy'))
TARGETS=('linux/amd64','linux/arm64')

def inputs():
    return sorted([* (ROOT/'native/dnssec').glob('*'), *(ROOT/'deploy'/name for name in (
        'build-dnssec-validator.py','verify-dnssec-validator.py','test_dnssec_validator.py',
        'test_dnssec_validator_build.py','test_dnssec_validator_package.py','desktop-dnssec-bundle.py',
        'test_desktop_dnssec_bundle.py')),
        ROOT/'cmd/client/bundled_dnssec.go',ROOT/'cmd/client/bundled_dnssec_test.go',ROOT/'cmd/client/bundled_native.go'])
def sha(raw):return hashlib.sha256(raw).hexdigest()
def source_inputs():return {p.relative_to(ROOT).as_posix():sha(regular(p,2<<20)) for p in inputs()}
def names(target):return {LIBRARY,RECEIPT,*LICENSES} if target in TARGETS else set()
def bound(name,target):
    if name not in names(target):raise ValueError('Unowned DNSSEC payload')
    return 32<<20 if name==LIBRARY else 64<<10 if name==RECEIPT else 256<<10

def regular(path,limit):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=limit:raise ValueError('Linked/oversized DNSSEC file: '+str(path))
    with path.open('rb') as f:
        opened=os.fstat(f.fileno())
        if (info.st_dev,info.st_ino,info.st_size)!=(opened.st_dev,opened.st_ino,opened.st_size):raise ValueError('DNSSEC file changed before read')
        raw=f.read(limit+1)
    if len(raw)!=info.st_size:raise ValueError('DNSSEC file changed during read')
    return raw

def unique(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise ValueError('Duplicate DNSSEC receipt field')
        out[key]=value
    return out

def elf_identity(raw,target):
    if target not in TARGETS or len(raw)<64 or raw[:7]!=b'\x7fELF\x02\x01\x01':raise ValueError('Invalid DNSSEC ELF identity')
    kind,machine=struct.unpack_from('<HH',raw,16)
    if kind!=3 or machine!=(62 if target=='linux/amd64' else 183):raise ValueError('Foreign DNSSEC ELF target')
    def bounded(offset,size):
        if offset<0 or size<0 or offset>len(raw) or size>len(raw)-offset:raise ValueError('Truncated DNSSEC ELF')
        return raw[offset:offset+size]
    phoff,shoff=struct.unpack_from('<QQ',raw,32)
    ehsize,phsize,phnum,shsize,shnum,_=struct.unpack_from('<HHHHHH',raw,52)
    if ehsize!=64 or phsize!=56 or not 1<=phnum<=128 or shsize!=64 or not 1<=shnum<=4096:raise ValueError('Unbounded DNSSEC ELF table')
    stack=False;programs=[];relro=False
    for n in range(phnum):
        program=struct.unpack('<IIQQQQQQ',bounded(phoff+n*phsize,phsize));programs.append(program)
        typ,flags,offset,_,_,size,_,_=program
        bounded(offset,size)
        if typ==1 and flags&3==3:raise ValueError('DNSSEC writable executable load')
        if typ==0x6474e552:relro=True
        if typ==3:raise ValueError('DNSSEC library has executable interpreter')
        if typ==0x6474e551:
            if stack or flags&1:raise ValueError('DNSSEC executable/duplicate stack')
            stack=True
    if not stack or not relro:raise ValueError('DNSSEC stack/RELRO protection missing')
    sections=[struct.unpack('<IIQQQQIIQQ',bounded(shoff+n*shsize,shsize)) for n in range(shnum)]
    def data(s):return bounded(s[4],s[5])
    def strings(s):
        if s[6]>=shnum or sections[s[6]][1]!=3:raise ValueError('Invalid DNSSEC string table')
        return data(sections[s[6]])
    def string(table,offset):
        if offset>=len(table):raise ValueError('Invalid DNSSEC string offset')
        end=table.find(b'\0',offset)
        if end<0 or end-offset>512:raise ValueError('Unbounded DNSSEC symbol')
        return table[offset:end].decode('ascii')
    dynamic=[s for s in sections if s[1]==6]; symbols=[s for s in sections if s[1]==11]
    if len(dynamic)!=1 or len(symbols)!=1:raise ValueError('Missing/duplicate DNSSEC dynamic tables')
    d=dynamic[0]; table=strings(d); needed=[]
    loaders=[p for p in programs if p[0]==2]
    if len(loaders)!=1 or (loaders[0][2],loaders[0][3],loaders[0][5])!=(d[4],d[3],d[5]):raise ValueError('DNSSEC loader and inspection tables differ')
    symbol=symbols[0];text=sections[d[6]]
    if symbol[6]!=d[6]:raise ValueError('DNSSEC loader symbol strings differ')
    for section in (d,symbol,text):
        if not any(p[0]==1 and p[3]<=section[3] and section[5]<=p[5]-(section[3]-p[3]) and p[2]+section[3]-p[3]==section[4] for p in programs):raise ValueError('Unmapped DNSSEC dynamic section')
    tags={}
    if d[9]!=16 or len(data(d))%16:raise ValueError('Invalid DNSSEC dynamic table')
    for tag,value in struct.iter_unpack('<qQ',data(d)):
        tags.setdefault(tag,[]).append(value)
        if tag in (15,29,0x7ffffffd,0x7fffffff,0x6ffffefa,0x6ffffefb,0x6ffffefc):raise ValueError('DNSSEC indirect loader/search path is forbidden')
        if tag==1:needed.append(string(table,value))
    if any(tags.get(tag)!=[value] for tag,value in ((5,text[3]),(10,text[5]),(6,symbol[3]),(11,24))):raise ValueError('DNSSEC loader addresses differ from inspected tables')
    if not needed or len(set(needed))!=len(needed) or any(x not in ('libc.so.6','libpthread.so.0','libdl.so.2') for x in needed):raise ValueError('Ambient DNSSEC dependency')
    s=symbols[0];table=strings(s);exports=[]
    if s[9]!=24 or len(data(s))%24:raise ValueError('Invalid DNSSEC symbol table')
    for name,info,other,section,_,_ in struct.iter_unpack('<IBBHQQ',data(s)):
        if section and info>>4 in (1,2) and other&3 in (0,3):exports.append(string(table,name))
    if sorted(exports)!=EXPORTS:raise ValueError('DNSSEC exported ABI changed')
    return machine,needed,sorted(exports)

def verify(directory,target):
    if target not in TARGETS:raise ValueError('DNSSEC package is Linux-only')
    value=json.loads(regular(directory/RECEIPT,64<<10),object_pairs_hook=unique)
    if set(value)!={'schema','abi','target','source_inputs','build','files'} or value['schema']!=1 or value['abi']!=1 or value['target']!=target or value['source_inputs']!=source_inputs():raise ValueError('DNSSEC source/target receipt mismatch')
    spec=json.loads((ROOT/'native/dnssec/sources.json').read_text())
    build=value['build'];raw=regular(directory/LIBRARY,32<<20)
    machine,needed,exports=elf_identity(raw,target)
    if build['schema']!=1 or build['abi']!=1 or build['platform']!='linux' or build['architecture']!=('x86_64' if target.endswith('amd64') else 'aarch64') or build['sources']!=spec:raise ValueError('DNSSEC build pins/target mismatch')
    for key,path in (('shim_sha256','native/dnssec/validator.c'),('header_sha256','native/dnssec/validator.h'),('builder_sha256','deploy/build-dnssec-validator.py')):
        if build[key]!=sha(regular(ROOT/path,2<<20)):raise ValueError('DNSSEC build source changed')
    if (build['artifact_sha256'],build['artifact_size'],build['elf_machine'],build['needed'],sorted(build['exports']))!=(sha(raw),len(raw),machine,needed,exports):raise ValueError('DNSSEC actual ELF differs from build receipt')
    expected={LIBRARY:{'size':len(raw),'sha256':sha(raw)}}
    for name,(dependency,filename) in LICENSES.items():
        body=regular(directory/name,256<<10)
        if sha(body)!=spec[dependency]['licenses'][filename]:raise ValueError('DNSSEC license changed')
        expected[name]={'size':len(body),'sha256':sha(body)}
    if value['files']!=expected:raise ValueError('DNSSEC payload receipt mismatch')
    projection=build['configure_projection']
    if projection!={'original_sha256':'9b18d449c2aedb76816009caec44978c23ea58d34f26c7ad4cb1625ba824a329','removed_block_sha256':'e36da3b8403ee6723434ad496633843b38655902f794f15d321bba4c29d85825','projected_sha256':'f4b9df17aab6933befc8041f6c57c1dc7b869e52dfacbab6a4b0d80cd6500792'}:raise ValueError('DNSSEC configure projection changed')
    return value

def fetch(name,spec,cache):
    cache.mkdir(parents=True,exist_ok=True)
    if cache.is_symlink():raise ValueError('Linked DNSSEC source cache')
    path=cache/(name+'-'+spec['archive_sha256']+'.tar.gz');limit=(8 if name=='unbound' else 64)<<20
    if path.exists():
        if sha(regular(path,limit))!=spec['archive_sha256']:raise ValueError('DNSSEC archive cache changed')
        return path
    url=spec.get('url') or spec['repository'].replace('https://github.com/','https://codeload.github.com/')+'/tar.gz/'+spec['commit']
    with urllib.request.urlopen(url,timeout=90) as response:
        final=urllib.parse.urlparse(response.geturl());original=urllib.parse.urlparse(url)
        if final.scheme!='https' or final.hostname!=original.hostname:raise ValueError('DNSSEC source redirect escaped pinned host')
        body=response.read(limit+1)
    if not 0<len(body)<=limit or sha(body)!=spec['archive_sha256']:raise ValueError('DNSSEC source download checksum/bound failed')
    fd,temp=tempfile.mkstemp(prefix='dnssec-download-',dir=cache)
    try:
        with os.fdopen(fd,'wb') as out:out.write(body)
        os.replace(temp,path)
    finally:Path(temp).unlink(missing_ok=True)
    return path

ACTUAL_CASES=('TestBundledDNSSECSourcePinsAndMandatoryReceipt','TestBundledDNSSECActualPackage',*(
    'TestBundledDNSSECActualPackage/'+name for name in ('abi','target','builder','duplicate-json','artifact','wrong-elf-machine','ambient-dependency','foreign-export','loader-strtab','inspection-dynamic','license','missing','symlink')))

def require_actual_verdicts(output):
    observed={name:[0,0] for name in ACTUAL_CASES}
    for line in output.splitlines():
        if not line.strip():continue
        event=json.loads(line,object_pairs_hook=unique)
        if event.get('Action') in ('fail','skip'):raise ValueError('DNSSEC actual package gate failed/skipped')
        name=event.get('Test')
        if name and event.get('Action') in ('run','pass'):
            if name not in observed:raise ValueError('Unexpected DNSSEC package verdict')
            observed[name][0 if event['Action']=='run' else 1]+=1
    if any(counts!=[1,1] for counts in observed.values()):raise ValueError('Missing/duplicate DNSSEC package verdict')

def test_actual_package(destination,env=None):
    captured={**(env or os.environ),'ROUTERVPN_DNSSEC_BUNDLE':str(Path(destination).resolve())}
    result=subprocess.run(['go','test','-p=1','-race','-json','./cmd/client','-run','^TestBundledDNSSEC(ActualPackage|SourcePinsAndMandatoryReceipt)$','-count=1','-timeout=60s'],cwd=ROOT,env=captured,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
    if result.returncode or len(result.stdout)>1<<20:
        raise ValueError('Actual DNSSEC package gate failed: '+result.stdout[-16384:])
    require_actual_verdicts(result.stdout)
    print('Actual pinned DNSSEC Go package verification and 13 refusal controls passed',flush=True)

def test_native_bundle(directory,target,env=None):
    host='linux/'+{'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine(),'')
    if platform.system()!='Linux' or target!=host:raise ValueError('DNSSEC native gate cannot execute a foreign library')
    receipt=verify(Path(directory),target)
    with tempfile.TemporaryDirectory(prefix='dnssec-native-package-') as tmp:
        layout=Path(tmp);(layout/'licenses').mkdir()
        shutil.copyfile(Path(directory)/LIBRARY,layout/LIBRARY)
        (layout/'manifest.json').write_text(json.dumps(receipt['build']))
        for name,(dependency,filename) in LICENSES.items():shutil.copyfile(Path(directory)/name,layout/'licenses'/(dependency+'-'+filename))
        subprocess.run([sys.executable,str(ROOT/'deploy/test_dnssec_validator.py'),'--build',str(layout)],check=True,env=env,timeout=130)
    test_actual_package(directory,env)

def build(target,destination,*,compiled=None,cache=None,env=None):
    host='linux/'+{'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine(),'')
    if platform.system()!='Linux' or target!=host:raise ValueError('DNSSEC producer requires the exact native Linux architecture')
    cache=Path(cache or ROOT/'dist/.dnssec-cache');destination=Path(destination)
    if compiled is None:
        spec=json.loads((ROOT/'native/dnssec/sources.json').read_text())
        archives={name:fetch(name,spec[name],cache/'sources') for name in ('unbound','openssl')}
        build_inputs={name:value for name,value in source_inputs().items() if name in ('native/dnssec/validator.c','native/dnssec/validator.h','native/dnssec/sources.json','deploy/build-dnssec-validator.py','deploy/verify-dnssec-validator.py')}
        identity=sha(json.dumps(build_inputs,sort_keys=True).encode())
        compiled=cache/('compiled-'+target.replace('/','-')+'-'+identity)
        if not compiled.exists():
            # Cache only the verified output and full provenance, not hundreds
            # of megabytes of disposable OpenSSL/unbound build objects.
            with tempfile.TemporaryDirectory(prefix='dnssec-compile-',dir=cache) as temporary:
                work=Path(temporary);built=work/'built'
                subprocess.run([sys.executable,str(ROOT/'deploy/build-dnssec-validator.py'),'--unbound-archive',str(archives['unbound']),'--openssl-archive',str(archives['openssl']),'--output',str(built)],check=True,timeout=1800)
                compact=work/'compact';compact.mkdir()
                for filename in (LIBRARY,'manifest.json'):shutil.copyfile(built/filename,compact/filename)
                shutil.copytree(built/'licenses',compact/'licenses')
                os.replace(compact,compiled)
    compiled=Path(compiled)
    subprocess.run([sys.executable,str(ROOT/'deploy/verify-dnssec-validator.py'),'--build',str(compiled),'--architecture','x86_64' if target.endswith('amd64') else 'aarch64'],check=True,timeout=30)
    subprocess.run([sys.executable,str(ROOT/'deploy/test_dnssec_validator.py'),'--build',str(compiled)],check=True,env=env,timeout=130)
    destination.mkdir()
    shutil.copyfile(compiled/LIBRARY,destination/LIBRARY)
    for name,(dependency,filename) in LICENSES.items():shutil.copyfile(compiled/'licenses'/(dependency+'-'+filename),destination/name)
    files={name:{'size':len(body),'sha256':sha(body)} for name in {LIBRARY,*LICENSES} for body in [regular(destination/name,bound(name,target))]}
    value={'schema':1,'abi':1,'target':target,'source_inputs':source_inputs(),'build':json.loads(regular(compiled/'manifest.json',128<<10),object_pairs_hook=unique),'files':files}
    (destination/RECEIPT).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    verify(destination,target)
    test_actual_package(destination,env)
    verify(destination,target) # Reject source movement during the actual gate.
    return destination

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('target',choices=TARGETS);p.add_argument('destination',type=Path);p.add_argument('--compiled',type=Path);p.add_argument('--cache',type=Path)
    a=p.parse_args();build(a.target,a.destination,compiled=a.compiled,cache=a.cache)
