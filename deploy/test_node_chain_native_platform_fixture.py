#!/usr/bin/env python3
"""Execute both exact native component platforms without acquiring a real TUN."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def fixture_source():
    socks = (ROOT / 'mobile/chain/socks_native_test.go.tmpl').read_text()
    connect = (ROOT / 'mobile/chain/connect_native_test.go.tmpl').read_text()
    first = socks[socks.index('func nodeChainNativeFixtureInterfaceValid('):
                  socks.index('func (*socksBridgeNativePlatform) UnderNetworkExtension()')]
    second = connect[connect.index('type connectBridgeNativePlatform struct'):
                     connect.index('func (*connectBridgeNativePlatform) UnderNetworkExtension()')]
    return first + second


PREAMBLE = r'''package fixture
import ("errors"; "net"; "runtime"; "strings"; "testing")
type socksBridgePlatform struct{}
type connectBridgePlatform struct{}
type InterfaceUpdateListener interface { UpdateDefaultInterface(string,int32,bool,bool) }
type NetworkInterface struct {
 Index, MTU, Flags, Type int32
 Name string
 Addresses, DNSServer, Gateway *iterator[string]
}
const InterfaceTypeEthernet = 1
type iterator[T any] struct { values []T; next int }
func newIterator[T any](values []T)*iterator[T]{ return &iterator[T]{values:values} }
func(i *iterator[T]) HasNext()bool{return i.next<len(i.values)}
func(i *iterator[T]) Next()T{v:=i.values[i.next];i.next++;return v}
type NetworkInterfaceIterator interface { HasNext()bool; Next()*NetworkInterface }
'''


CASES = r'''
type platform interface {
 StartDefaultInterfaceMonitor(InterfaceUpdateListener)error
 GetInterfaces()(NetworkInterfaceIterator,error)
}
type listener struct{name string;index int32;calls int}
func(l *listener)UpdateDefaultInterface(name string,index int32,expensive,constrained bool){
 l.name=name;l.index=index;l.calls++
 if expensive||constrained{panic("fixture changed route qualifiers")}
}
func platforms(iif net.Interface)map[string]platform{return map[string]platform{
 "SOCKS":&socksBridgeNativePlatform{physical:iif},
 "CONNECT":&connectBridgeNativePlatform{physical:iif},
}}
func validInterface()net.Interface{return net.Interface{Index:7,MTU:1492,Name:"en7",Flags:net.FlagUp|net.FlagBroadcast}}
func TestDarwinUsesOneEnumeratedIdentityForMonitorAndMetadata(t *testing.T){
 actual:=validInterface()
 for _,goos:=range []string{"darwin","ios"}{
 for _,order:=range [][]net.Interface{{actual},{
  {Index:31,MTU:1500,Name:"lo31",Flags:net.FlagUp|net.FlagLoopback},
  {Index:32,MTU:1500,Name:"down32"},actual}}{
  calls:=0
  got,err:=nodeChainNativeFixtureSelectInterface(goos,"invented-physical",func()([]net.Interface,error){calls++;return order,nil})
  if err!=nil||calls!=1||got.Index!=actual.Index||got.Name!=actual.Name||got.MTU!=actual.MTU{t.Fatalf("Darwin original interface identity lost: %+v calls=%d error=%v",got,calls,err)}
  for name,p:=range platforms(got){t.Run(name,func(t *testing.T){
   l:=new(listener)
   if err:=p.StartDefaultInterfaceMonitor(l);err!=nil{t.Fatal(err)}
   if l.calls!=1||l.name!=actual.Name||l.index!=int32(actual.Index){t.Fatalf("monitor announced a foreign interface: %+v",l)}
   // The Darwin finder resolves callback indices against its host table.
   found:=false;for _,host:=range order{if host.Index==int(l.index)&&host.Name==l.name{found=true}}
   if !found{t.Fatal("Darwin host finder cannot resolve callback")}
   for repeat:=0;repeat<2;repeat++{
    it,err:=p.GetInterfaces();if err!=nil||it==nil||!it.HasNext(){t.Fatal("original enumeration missing",err)}
    v:=it.Next();if v.Index!=l.index||v.Name!=l.name||v.MTU!=int32(actual.MTU)||v.Flags!=1||v.Type!=InterfaceTypeEthernet||it.HasNext(){t.Fatalf("platform enumeration diverged from captured monitor: %+v",v)}
    if !v.Addresses.HasNext()||v.Addresses.Next()!="192.0.2.2/24"||v.Addresses.HasNext()||v.DNSServer.HasNext()||v.Gateway.HasNext(){t.Fatal("explicit component address/DNS/route boundary changed")}
   }
  })}
 }
 }
}
func TestDarwinRejectsUnavailableOrInvalidPhysicalInterface(t *testing.T){
 failure:=errors.New("original enumeration failure")
 if _,err:=nodeChainNativeFixtureSelectInterface("darwin","invented",func()([]net.Interface,error){return []net.Interface{validInterface()},failure});!errors.Is(err,failure){t.Fatal("enumeration failure replaced by authority",err)}
 invalid:=[]net.Interface{{},{Index:1,MTU:1500,Name:"lo0",Flags:net.FlagUp|net.FlagLoopback},
 {Index:2,MTU:1500,Name:"down"},{Index:0,MTU:1500,Name:"zero",Flags:net.FlagUp},
 {Index:3,MTU:1500,Name:" ",Flags:net.FlagUp},{Index:4,Name:"missing-mtu",Flags:net.FlagUp},
 {Index:2147483648,MTU:1500,Name:"overflow-index",Flags:net.FlagUp},
 {Index:5,MTU:2147483648,Name:"overflow-mtu",Flags:net.FlagUp}}
 for _,iif:=range invalid{
  if _,err:=nodeChainNativeFixtureSelectInterface("darwin","invented",func()([]net.Interface,error){return []net.Interface{iif},nil});err==nil{t.Fatalf("invalid physical interface admitted: %+v",iif)}
  for name,p:=range platforms(iif){
   l:=new(listener);if err:=p.StartDefaultInterfaceMonitor(l);err==nil||l.calls!=0{t.Fatalf("%s invalid interface reached callback: %+v",name,iif)}
   if it,err:=p.GetInterfaces();err==nil||it!=nil{t.Fatalf("%s invalid interface reached enumeration: %+v",name,iif)}
  }
 }
 if _,err:=nodeChainNativeFixtureSelectInterface("darwin","invented",func()([]net.Interface,error){return nil,nil});err==nil{t.Fatal("absent host interface accepted")}
 for _,p:=range []platform{(*socksBridgeNativePlatform)(nil),(*connectBridgeNativePlatform)(nil)}{
  l:=new(listener);if err:=p.StartDefaultInterfaceMonitor(l);err==nil||l.calls!=0{t.Fatal("nil platform reached callback")}
  if it,err:=p.GetInterfaces();err==nil||it!=nil{t.Fatal("nil platform reached enumeration")}
 }
}
func TestOtherHostsKeepOriginalComponentBoundary(t *testing.T){
 for _,goos:=range []string{"linux","windows","android"}{
  calls:=0
  iif,err:=nodeChainNativeFixtureSelectInterface(goos,"original-fixture",func()([]net.Interface,error){calls++;return nil,errors.New("must not inspect host")})
  if err!=nil||calls!=0||iif.Index!=31||iif.Name!="original-fixture"||iif.MTU!=1500||iif.Flags!=net.FlagUp{t.Fatalf("%s component boundary changed: %+v %v",goos,iif,err)}
 }
}
'''


class NativePlatformFixture(unittest.TestCase):
    def test_original_constructors_capture_interface_before_native_server(self):
        for protocol in ('socks', 'connect'):
            text = (ROOT / f'mobile/chain/{protocol}_native_test.go.tmpl').read_text()
            start = text.index(f'func {protocol}BridgeNativeReserved(')
            end = text.index('server,', start)
            setup = text[start:end]
            self.assertRegex(setup, rf'platform:\s*&{protocol}BridgeNativePlatform\{{physical:\s*nodeChainNativeFixtureInterface\(t,\s*"original-{protocol}-physical"\)\}}')

    def test_original_ordinary_fifty_constructor_uses_same_interface(self):
        text = (ROOT / 'mobile/chain/latency_native_test.go.tmpl').read_text()
        start = text.index('func ordinaryFiftyNative(')
        end = text.index('t.Cleanup(', start)
        self.assertIn('NewCommandServer(&socksBridgeHandler{}, &socksBridgeNativePlatform{physical: nodeChainNativeFixtureInterface(t, "original-ordinary-physical")})', text[start:end])

    def test_exact_platforms_and_semantic_controls(self):
        original = fixture_source()
        controls = {
            'invented-darwin-interface': ('if goos != "darwin" && goos != "ios" {', 'if true {', 'Darwin original interface identity lost', 'TestDarwinUsesOneEnumeratedIdentityForMonitorAndMetadata'),
            'admit-loopback': (' && iif.Flags&net.FlagLoopback == 0', '', 'invalid physical interface admitted', 'TestDarwinRejectsUnavailableOrInvalidPhysicalInterface'),
            'admit-down': (' && iif.Flags&net.FlagUp != 0', '', 'invalid physical interface admitted', 'TestDarwinRejectsUnavailableOrInvalidPhysicalInterface'),
            'erase-discovery-error': ('if err != nil {', 'if err != nil && len(interfaces) == 0 {', 'enumeration failure replaced by authority', 'TestDarwinRejectsUnavailableOrInvalidPhysicalInterface'),
            'foreign-socks-callback': ('listener.UpdateDefaultInterface(p.physical.Name, int32(p.physical.Index), false, false)', 'listener.UpdateDefaultInterface("foreign", int32(p.physical.Index), false, false)', 'monitor announced a foreign interface', 'TestDarwinUsesOneEnumeratedIdentityForMonitorAndMetadata'),
            'foreign-connect-enumeration': ('Name: p.physical.Name,', 'Name: "foreign",', 'platform enumeration diverged from captured monitor', 'TestDarwinUsesOneEnumeratedIdentityForMonitorAndMetadata'),
        }
        with tempfile.TemporaryDirectory(prefix='routervpn-native-platform-') as directory:
            root = Path(directory)
            (root / 'go.mod').write_text('module routervpn.native-platform.fixture\n\ngo 1.24.0\n')
            path = root / 'fixture_test.go'
            env = dict(os.environ, GOWORK='off', GOMAXPROCS='1')
            for label in ('original', *controls):
                with self.subTest(case=label):
                    source = original
                    if label != 'original':
                        old, new, witness, root_case = controls[label]
                        self.assertIn(old, source)
                        source = source.replace(old, new, 1)
                    path.write_text(PREAMBLE + source + CASES)
                    result = subprocess.run(['go', 'test', '-count=1', '-timeout=20s', '-v', '.'], cwd=root, env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
                    print(f"Native platform fixture {label}: exit={result.returncode}\n{result.stdout}", flush=True)
                    self.assertNotIn('[build failed]', result.stdout, result.stdout)
                    self.assertNotRegex(result.stdout, r'(?i)panic:|test timed out|WARNING: DATA RACE|fatal error:')
                    if label == 'original':
                        self.assertEqual(result.returncode, 0, result.stdout)
                        self.assertIn('--- PASS: TestDarwinUsesOneEnumeratedIdentityForMonitorAndMetadata', result.stdout)
                    else:
                        self.assertNotEqual(result.returncode, 0, label + '\n' + result.stdout)
                        self.assertIn('--- FAIL: ' + root_case + ' (', result.stdout, result.stdout)
                        self.assertIn(witness, result.stdout, result.stdout)


if __name__ == '__main__':
    unittest.main()
