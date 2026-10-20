#!/usr/bin/env python3
"""Run shipping external DNS settings and Codable with store/OS boundaries.

The separate external-policy gate calls the real Go compiler. This gate proves
the visible sheet saves the exact selected node and retains bootstrap options.
"""
from pathlib import Path
import importlib.util
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('external_profiles', ROOT / 'deploy/test_ios_external_connection_profiles.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)


def method(source, signature):
    begin = source.index(signature)
    start = source.index('{', begin)
    depth = 1; index = start + 1
    while depth:
        if source[index] == '{': depth += 1
        if source[index] == '}': depth -= 1
        index += 1
    return source[begin:index].replace('private func ', 'func ').replace('private var ', 'var ')


SWIFT = r'''
import Foundation
import Network
enum IOSDNSRuntimePolicy {
 // SELECTED_PROFILE
 static func resolve(_ p:RouterProfile)throws->Int{1}
}
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?, entry:ClientBundle?, profileMutationBlocked=false, imports=0, message=""
 func importBundle(_ data:Data)throws {bundle=try JSONDecoder().decode(ClientBundle.self,from:data);imports+=1}
 func iosMultihopEntryBundle(for bundle:ClientBundle)throws->ClientBundle {
  guard let entry, entry.selectedRouterID==bundle.routerProfiles[0].multihopEntryID else{throw TestError.failed};return entry
 }
}
@MainActor final class Settings {
 let model:RouterVPNModel
 var mode="home",protocolName="udp",host="",port="53",serverName="",path="/dns-query",status=""
 var useHostnameBootstrap=false,results:[DNSBenchmarkResult]=[]
 var bootstrap=ExternalDNSBootstrap(server:.init(type:"tcp",server:"",serverPort:53))
 init(_ model:RouterVPNModel){self.model=model}
 // SHIPPING_SETTINGS
}
enum TestError {static var failed:NSError {NSError(domain:"DNSSettings",code:1)}}
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ label:String,_ condition:@autoclosure ()throws->Bool)throws {guard try condition()else{throw NSError(domain:"DNSSettingsTest",code:1,userInfo:[NSLocalizedDescriptionKey:label])};checks+=1}
 static func reject(_ label:String,_ operation:()throws->Void)throws{do{try operation()}catch{checks+=1;return};throw NSError(domain:"DNSSettingsRejection",code:1,userInfo:[NSLocalizedDescriptionKey:label])}
 static func json(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
 static func profile(_ kind:String)->RouterProfile {
  let value:[String:Any]=["id":"exit","name":"Selected exit","endpoint":"198.51.100.8","node_kind":"external",
   "router_api":"","api_token":"exact private token","adguard_ipv4":"","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":"exact private secret",
   "external":["protocol":kind,"expected_public_ip":"203.0.113.8"],"home_lan_access":false,"ipv6_mode":"off",
   "dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","dns_port":5353,"dns_server_name":"","dns_path":"/dns-query","mtu_policy":"fixed","manual_mtu":1380,"start_layer":"off"]
  return try! JSONDecoder().decode(RouterProfile.self,from:json(value))
 }
 static func bundle(_ p:RouterProfile)->ClientBundle{var b=ClientBundle.empty;b.selectedRouterID=p.id;b.routerProfiles=[p];b.profiles=["owned":["secret":"exact data"]];return b}
 static func boot()->ExternalDNSBootstrap {
  var b=ExternalDNSBootstrap(server:.init(type:"tcp",server:"9.9.9.9",serverPort:5353))
  b.query.strategy="prefer_ipv4";b.query.timeout="3.5s";b.query.disableCache=true;b.query.disableOptimisticCache=false;b.query.rewriteTTL=19;b.query.clientSubnet="192.0.2.0/24"
  return b
 }
 static func settings()throws {
  for kind in IOSExternalDNSPolicy.protocols {
   let p=profile(kind),model=RouterVPNModel();model.bundle=bundle(p)
   let editor=Settings(model);editor.load();editor.savePolicy()
   try check("ordinary node settings save "+kind+": "+editor.status,model.imports==1 && model.bundle!.routerProfiles[0]==p)
   try check("source private assets and transport stay owned",model.bundle!.profiles==bundle(p).profiles && model.bundle!.routerProfiles[0].external==p.external)
   var named=p;named.dnsMode="doh";named.dnsHost="resolver.example.test";named.dnsProtocol="https";named.dnsServerName="resolver.example.test";named.dnsPort=443;named.dnsPath="/captured-query";named.dnsBootstrap=boot()
   model.bundle=bundle(named);editor.load();editor.savePolicy()
   try check("hostname bootstrap and all query options survive UI save",model.imports==2 && model.bundle!.routerProfiles[0]==named && editor.bootstrap==boot())
   let decoded=try JSONDecoder().decode(RouterProfile.self,from:JSONEncoder().encode(named))
   try check("bootstrap object survives node import/export",decoded==named)
   editor.useHostnameBootstrap=false;editor.savePolicy()
   try check("missing hostname bootstrap cannot be silently inferred",model.imports==2 && model.bundle!.routerProfiles[0]==named)
   editor.load();editor.bootstrap.server.detour="direct";editor.savePolicy()
   try check("unowned DNS detour never saves",model.imports==2)
   editor.load();editor.bootstrap.server.server="lookup.example.test";editor.savePolicy()
   try check("recursive lookup never saves",model.imports==2)
   model.bundle=bundle(p);editor.load();editor.useHostnameBootstrap=true;editor.bootstrap=boot();editor.savePolicy()
   try check("unused bootstrap cannot survive a literal DNS selection",model.imports==2)
   editor.load();editor.port="invalid";editor.savePolicy()
   try check("invalid port cannot silently become default",model.imports==2)
   editor.load();model.profileMutationBlocked=true;editor.savePolicy()
   try check("active transition blocks DNS write",model.imports==2)
   model.profileMutationBlocked=false;model.bundle!.routerProfiles.append(p);editor.savePolicy()
   try check("duplicate node selection has no fallback",model.imports==2)
  }
 }
 static func home()throws {
  var home=profile("wireguard");home.id="home";home.nodeKind="router-vpn";home.nodeProofID=String(repeating:"a",count:64);home.routerAPI="http://10.8.0.1:8787";home.apiToken="home-token";home.adGuardIPv4="192.168.50.133";home.adGuardIPv6="fd12:3456::53"
  var exit=profile("http-connect");exit.dnsMode="home";exit.dnsProtocol="tcp";exit.dnsHost=home.adGuardIPv6;exit.dnsPort=5353
  exit.multihopEnabled=true;exit.multihopEntryID=home.id;exit.multihopEntryMode="wg";exit.multihopExitID=exit.id;exit.multihopExitMode="http-connect";exit.multihopExecution="local"
  let model=RouterVPNModel();model.bundle=bundle(exit);model.entry=bundle(home);let editor=Settings(model);editor.load();editor.savePolicy()
  try check("explicit Home IPv6 TCP and port retained",model.imports==1 && model.bundle!.routerProfiles[0]==exit)
  editor.host="192.168.1.1";editor.savePolicy();try check("another home's DNS cannot save",model.imports==1)
  editor.load();model.entry=nil;editor.savePolicy();try check("Home requires captured entry",model.imports==1)
  model.entry=bundle(home);model.bundle!.routerProfiles[0].multihopEnabled=false;editor.load();editor.savePolicy();try check("direct Home never changes to public DNS",model.imports==1)
  model.bundle=bundle(exit);editor.load();editor.protocolName="udp";editor.savePolicy()
  try check("Home UDP uses entry even with TCP-only exit",model.imports==2 && model.bundle!.routerProfiles[0].dnsProtocol=="udp")
 }
 static func hostileCodable()throws {
  let original=try JSONSerialization.jsonObject(with:JSONEncoder().encode(boot())) as! [String:Any]
  for owner in ["top","server","query","tls"] {
   var value=original
   if owner=="top"{value["unowned"]=true}
   else if owner=="tls"{var server=value["server"] as! [String:Any];server["tls"]=["enabled":true,"server_name":"resolver.example.test","insecure":true];value["server"]=server}
   else {var child=value[owner] as! [String:Any];child["unowned"]=true;value[owner]=child}
   try reject("unknown owner fields are rejected rather than dropped"){_ = try JSONDecoder().decode(ExternalDNSBootstrap.self,from:json(value))}
  }
  for raw:Any in [true,"53",1.5] {var value=original,server=value["server"] as! [String:Any];server["server_port"]=raw;value["server"]=server;try reject("invalid saved port type"){_ = try JSONDecoder().decode(ExternalDNSBootstrap.self,from:json(value))}}
 }
 static func main() {
  do {
   try settings();try home();try hostileCodable()
   print("Apple external DNS settings: PASS (\(checks) shipping sheet/model checks; storage and Network boundary substituted)")
  } catch { FileHandle.standardError.write(Data((error.localizedDescription+"\n").utf8));exit(1) }
 }
}
'''


def main():
    swift = shutil.which('swiftc')
    if not swift: raise RuntimeError('swiftc is required')
    view = (APP / 'IOSDNSPolicyView.swift').read_text()
    methods = '\n'.join(method(view, signature) for signature in [
        'private var ordinaryExternal:', 'private func selectedProfile()', 'private func load()',
        'private func savePolicy()', 'private func defaultPort(', 'private func sorted('
    ])
    dns = (APP / 'IOSDNSRuntimePolicy.swift').read_text()
    selected = dns[dns.index('    static func selectedProfile('):dns.index('    static func resolve(')]
    source = SWIFT.replace(' // SELECTED_PROFILE', selected).replace(' // SHIPPING_SETTINGS', methods)
    with tempfile.TemporaryDirectory(prefix='ios-external-dns-settings-') as temporary:
        work = Path(temporary)
        options = [swift, '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        if platform.system() != 'Darwin':
            network = work / 'Network.swift'; network.write_text(P.NETWORK)
            subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Network', str(network), '-emit-module-path', str(work / 'Network.swiftmodule'), '-o', str(work / 'libNetwork.so')], check=True, timeout=60)
            options += ['-I', str(work), '-L', str(work), '-lNetwork', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        code = work / 'Tests.swift'; code.write_text(source)
        binary = work / 'tests'
        subprocess.run(options + [str(APP / 'Models.swift'), str(APP / 'IOSExternalDNSPolicy.swift'), str(code), '-o', str(binary)], check=True, timeout=120)
        subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == '__main__':
    main()
