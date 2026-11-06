#!/usr/bin/env python3
"""Exercise actual pinned DNSSEC signatures through only an offline TCP authority."""
import argparse
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import sys
import subprocess
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--build',type=Path,required=True)
    p.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    args=p.parse_args()
    if not args.worker:
        child=subprocess.Popen([sys.executable,__file__,'--build',str(args.build.resolve()),'--worker'],start_new_session=True)
        try:
            code=child.wait(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL);child.wait();raise
        if code: raise SystemExit(code)
        return
    artifact=args.build/'libroutervpn_dnssec.so'
    manifest=json.loads((args.build/'manifest.json').read_text())
    sha=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    assert manifest['artifact_sha256']==sha(artifact)
    assert manifest['shim_sha256']==sha(ROOT/'native/dnssec/validator.c')
    assert manifest['header_sha256']==sha(ROOT/'native/dnssec/validator.h')
    assert manifest['builder_sha256']==sha(ROOT/'deploy/build-dnssec-validator.py')
    assert manifest['sources']==json.loads((ROOT/'native/dnssec/sources.json').read_text())
    lib=c.CDLL(str(artifact.resolve()))
    void=c.c_void_p; u32=c.c_uint32; string=c.c_char_p
    signatures={'create':([c.c_uint16],void),'anchor':([void,string,u32],c.c_int),
        'insecure':([void,string,u32],c.c_int),'start':([void,string,u32,c.c_uint16],c.c_int),
        'fd':([void],c.c_int),'process':([void],c.c_int),'cancel':([void],c.c_int),
        'destroy':([void],None),'result':([void,c.POINTER(u32),u32,void,u32],c.c_int)}
    for name,(inputs,output) in signatures.items():
        fn=getattr(lib,'rvdns_'+name);fn.argtypes=inputs;fn.restype=output
    assert lib.rvdns_abi()==1
    assert not lib.rvdns_create(0)
    with tempfile.TemporaryDirectory(prefix='dnssec-fixture-') as tmp:
        source=Path(tmp)/'main.go'; source.write_bytes((ROOT/'native/dnssec/zone_fixture.go.tmpl').read_bytes())
        for filename in ('go.mod','go.sum'):
            (Path(tmp)/filename).write_bytes((ROOT/'native/dnssec'/('fixture.'+filename)).read_bytes())
        binary=Path(tmp)/'authority'
        subprocess.run(['go','build','-mod=readonly','-p=1','-o',str(binary),'.'],cwd=tmp,check=True,timeout=90)
        with (Path(tmp)/'queries.log').open('w+') as log:
            server=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True)
            try:
                assert select.select([server.stdout],[],[],5)[0], 'authority did not start'
                config=json.loads(server.stdout.readline()); anchor=config['anchor'].encode()
                def new():
                    v=lib.rvdns_create(config['port']);assert v, 'context configuration failed'
                    assert lib.rvdns_anchor(v,anchor,len(anchor))==0
                    return v
                def result(v):
                    header=(u32*8)(); packet=c.create_string_buffer(65535)
                    ready=lib.rvdns_result(v,header,8,packet,65535)
                    assert ready>=0
                    return ready,list(header),packet.raw[:header[6]]
                def resolve(name,want,qtype=1,insecure=None):
                    threads_before=len(list(Path('/proc/self/task').iterdir()))
                    v=new()
                    try:
                        if insecure:
                            n=insecure.encode();assert lib.rvdns_insecure(v,n,len(n))==0
                        n=name.encode();assert lib.rvdns_start(v,n,len(n),qtype)==0
                        assert lib.rvdns_anchor(v,anchor,len(anchor))==-1, 'anchors changed after start'
                        deadline=time.monotonic()+8
                        while not result(v)[0]:
                            assert time.monotonic()<deadline, name+' deadline'
                            if select.select([lib.rvdns_fd(v)],[],[],.1)[0]:assert lib.rvdns_process(v)==0
                        _,header,packet=result(v)
                        assert header[1]==want,(name,header)
                        if want in (1,2):
                            assert packet and header[7]==0
                            if name=='absent.signed.test.': assert header[2:5]==[3,0,1]
                            elif qtype==28: assert header[2:5]==[0,0,0]
                            elif qtype==5: assert header[2:5]==[0,1,0]
                            else:
                                assert header[2:5]==[0,1,0]
                                assert bytes([192,0,2,11 if name=='host.child.signed.test.' else 9]) in packet
                        if want==4: assert header[2]==2 and header[3:5]==[0,0]
                        print('PASS',name,header,flush=True)
                    finally:
                        lib.rvdns_destroy(v)
                        assert len(list(Path('/proc/self/task').iterdir()))==threads_before,'worker survived context destruction'
                v=new()
                try:
                    for bad in (b'UPPER.signed.test.',b'no-final-dot',b'a..signed.test.',b'\x00.signed.test.'):
                        assert lib.rvdns_start(v,bad,len(bad),1)==-1
                    for unsupported in (15,39,255):
                        assert lib.rvdns_start(v,b'good.signed.test.',17,unsupported)==-1
                    assert lib.rvdns_anchor(v,b'X'*4097,4097)==-1
                    assert lib.rvdns_insecure(v,b'bad\n.',5)==-1
                    print('PASS malformed and oversized inputs',flush=True)
                finally:lib.rvdns_destroy(v)
                resolve('good.signed.test.',1)
                resolve('good.signed.test.',1,insecure='signed.test.') # actual positive-TA precedence
                resolve('alias.signed.test.',1)
                resolve('bogus.signed.test.',3)
                resolve('expired.signed.test.',3)
                resolve('badalias.signed.test.',3)
                resolve('absent.signed.test.',1)
                resolve('badabsent.signed.test.',3)
                resolve('good.signed.test.',1,28)
                resolve('host.child.signed.test.',2)
                resolve('unsigned.signed.test.',2,insecure='unsigned.signed.test.')
                resolve('unsigned.signed.test.',3)
                resolve('localhost.',4)
                # CNAME queries prove the original alias link without following
                # its target. This also verifies a synthesized CNAME against its
                # signed DNAME. An independently bogus destination does not make
                # a correctly signed alias false: the parent must separately
                # capture and validate the target's policy before adoption.
                alias_offset=Path(log.name).stat().st_size
                for name,want in (('alias.signed.test.',1),('badalias.signed.test.',1),
                                  ('crossalias.signed.test.',1),('tampered-alias.signed.test.',3),
                                  ('host.branch.signed.test.',1),('host.badbranch.signed.test.',3)):
                    resolve(name,want,5)
                alias_queries=Path(log.name).read_text()[alias_offset:]
                assert not any(line.split()[-1] in ('1','28') for line in alias_queries.splitlines()), 'alias proof followed an address target'
                assert not any('query '+name in alias_queries for name in ('good.signed.test.','bogus.signed.test.','outside.example.net.','host.outside.example.net.','host.changed.example.net.')), 'alias proof inherited target query authority'
                assert 'query host.branch.signed.test. 5' in alias_queries and 'query signed.test. 48' in alias_queries, 'DNAME proof omitted original question or signing key'
                print('PASS separate CNAME/DNAME proof without target queries',flush=True)
                before=len(list(Path('/proc/self/task').iterdir()))
                v=new()
                try:
                    name=b'hold.signed.test.';assert lib.rvdns_start(v,name,len(name),1)==0
                    deadline=time.monotonic()+2
                    while True:
                        log.flush(); text=Path(log.name).read_text()
                        if 'query hold.signed.test.' in text:break
                        assert time.monotonic()<deadline,'cancel test never sent query'
                        time.sleep(.01)
                    start=time.monotonic(); assert lib.rvdns_cancel(v)==0
                    assert time.monotonic()-start<2,'worker cancellation did not join'
                    assert result(v)[1][1]==5 and not result(v)[2]
                    assert lib.rvdns_fd(v)==-1
                    assert lib.rvdns_process(v)==-1
                    assert len(list(Path('/proc/self/task').iterdir()))==before,'worker survived cancellation'
                    print('PASS cancellation and worker join',flush=True)
                finally:lib.rvdns_destroy(v)
            finally:
                server.stdin.write('\n');server.stdin.flush()
                try:server.wait(timeout=12)
                except subprocess.TimeoutExpired:server.kill();server.wait();raise
            assert server.returncode==0
            queries=Path(log.name).read_text()
            assert 'query localhost.' in queries, 'built-in local answer bypassed broker'
            assert 'query signed.test. 48' in queries, 'DNSKEY proof was not requested'
            assert 'query child.signed.test. 43' in queries, 'insecure delegation lacked DS proof'
if __name__=='__main__': main()
