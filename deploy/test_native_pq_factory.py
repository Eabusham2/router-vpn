#!/usr/bin/env python3
"""Execute the server Go/C boundary with the real C framing adapter.

The linked protocol library is a declared deterministic ABI test double, not
cryptography. Real pinned-Rust exchanges are a separate native integration gate.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
S=ROOT/'mobile/rosenpass'
spec=importlib.util.spec_from_file_location('pq_host_cases',ROOT/'deploy/test_mobile_pq_hosts.py')
HOST=importlib.util.module_from_spec(spec);spec.loader.exec_module(HOST)
GO_TEST=r'''package routervpnpq
import("bytes";"errors";"net";"sync";"testing";"github.com/sagernet/sing-box/experimental/libbox/routervpn/mobilepq")
func fixture(t *testing.T)mobilepq.Protocol{
 t.Helper();p,err:=(nativePQFactory{}).Open(bytes.Repeat([]byte{1},32),bytes.Repeat([]byte{2},32),bytes.Repeat([]byte{3},32),2)
 if err!=nil{t.Fatal(err)};t.Cleanup(func(){p.Close()});return p
}
func TestActualCFramingAndIndependentOutputs(t *testing.T){
 p:=fixture(t)
 e,err:=p.Step(1,[]byte{1});if err!=nil||!bytes.Equal(e.Key,bytes.Repeat([]byte{7},32))||string(e.Packet)!="test"||e.Expired{t.Fatal("valid ABI frame lost",err)}
 e.Key[0]=8;e.Packet[0]='X'
 again,err:=p.Step(1,[]byte{1});if err!=nil||again.Key[0]!=7||string(again.Packet)!="test"{t.Fatal("native buffers aliased",err)}
 e,err=p.Step(1,[]byte{2});if err!=nil||!e.Expired||len(e.Key)!=0{t.Fatal("expiry lost",err)}
 if _,err=p.Step(1,[]byte{3});!errors.Is(err,mobilepq.ErrPacket){t.Fatal("rejected datagram became success/fatal",err)}
 for n:=4;n<=8;n++ {if _,err=p.Step(1,[]byte{byte(n)});err==nil{t.Fatal("invalid native frame accepted",n)}}
 e,err=p.Step(1,[]byte{9});if err!=nil||len(e.Key)!=0{t.Fatal("unflagged native key escaped C sanitization",err)}
}
func TestCapturedKeySizesAndOperationBounds(t *testing.T){
 f:=nativePQFactory{};a,b,c:=bytes.Repeat([]byte{1},32),bytes.Repeat([]byte{2},32),bytes.Repeat([]byte{3},32)
 for _,args:=range [][3][]byte{{nil,b,c},{a,b[:31],c},{a,b,c[:31]},{a,b,b}}{if p,err:=f.Open(args[0],args[1],args[2],2);err==nil||p!=nil{t.Fatal("invalid ABI keys accepted")}}
 for _,v:=range []int{-1,0,1,4}{if p,err:=f.Open(a,b,c,v);err==nil||p!=nil{t.Fatal("invalid version accepted")}}
 p:=fixture(t)
 if _,err:=p.Step(3,nil);err==nil{t.Fatal("invalid kind accepted")}
 if _,err:=p.Step(0,[]byte{1});err==nil{t.Fatal("poll consumed an unsolicited packet")}
 if _,err:=p.Step(1,make([]byte,65536));err==nil{t.Fatal("oversized datagram accepted")}
}
func TestCloseAndConcurrentCallsRemainSessionOwned(t *testing.T){
 p:=fixture(t);other:=fixture(t)
 var group sync.WaitGroup
 for i:=0;i<32;i++{group.Add(1);go func(){defer group.Done();for n:=0;n<20;n++{_,err:=p.Step(1,[]byte{1});if err!=nil&&!errors.Is(err,net.ErrClosed){t.Error(err)}}}()}
 for i:=0;i<12;i++{group.Add(1);go func(){defer group.Done();if err:=p.Close();err!=nil{t.Error(err)}}()}
 group.Wait()
 if _,err:=p.Step(1,[]byte{1});!errors.Is(err,net.ErrClosed){t.Fatal("closed native owner accepted work",err)}
 if e,err:=other.Step(1,[]byte{1});err!=nil||len(e.Key)!=32{t.Fatal("closing one native owner damaged another",err)}
}
func TestCompiledFactoryInstalledWithoutStartingAPeer(t *testing.T){
 c:=mobilepq.Config{Endpoint:"192.0.2.1:51822",Version:3,Secret:bytes.Repeat([]byte{1},32),Public:bytes.Repeat([]byte{2},32),Peer:bytes.Repeat([]byte{3},32)}
 p,err:=mobilepq.NativeProtocols.Open(c);if err!=nil{t.Fatal(err)};defer p.Close()
 if err=mobilepq.NativeProtocols.Install(nativePQFactory{});err==nil{t.Fatal("active compiled factory replaced")}
}
'''

class Factory(unittest.TestCase):
    def test_production_factory_through_actual_c_adapter(self):
        with tempfile.TemporaryDirectory(prefix='server-pq-ffi-') as tmp:
            root=Path(tmp);package=root/'protocol/routervpnpq';package.mkdir(parents=True)
            (root/'go.mod').write_text('module github.com/sagernet/sing-box\n\ngo 1.23\n')
            internal=root/'experimental/libbox/routervpn/mobilepq';internal.mkdir(parents=True)
            for path in (ROOT/'internal/mobilepq').glob('*.go'):
                if not path.name.endswith('_test.go'):shutil.copyfile(path,internal/path.name)
            (package/'native_factory.go').write_bytes((ROOT/'mobile/pq/native_factory.go.tmpl').read_bytes())
            (package/'factory_test.go').write_text(GO_TEST)
            for name in ('routervpn_rosenpass.h','routervpn_pq_host.h','routervpn_pq_host.c'):shutil.copyfile(S/name,package/name)
            (root/'protocol_double.c').write_text(HOST.FAKE)
            subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fPIC','-I'+str(S),'-c',str(root/'protocol_double.c'),'-o',str(root/'double.o')],check=True,timeout=30)
            subprocess.run(['ar','rcs',str(root/'libroutervpn_rosenpass.a'),str(root/'double.o')],check=True,timeout=30)
            env=dict(os.environ,CGO_ENABLED='1',CGO_CFLAGS='-I'+str(package),CGO_LDFLAGS='-L'+str(root))
            subprocess.run(['go','test','-race','-count=10','-tags','routervpn_native_pq','./protocol/routervpnpq'],cwd=root,env=env,check=True,timeout=90)
            subprocess.run(['go','vet','-tags','routervpn_native_pq','./protocol/routervpnpq'],cwd=root,env=env,check=True,timeout=60)

if __name__=='__main__':unittest.main()
