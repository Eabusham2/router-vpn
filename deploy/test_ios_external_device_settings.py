#!/usr/bin/env python3
"""Execute the shipping external device-policy editor and real native parsers.

Storage is an atomic in-memory boundary. The actual Swift models, visible
settings methods, exact transport assembly and Go ordinary/Tor policy validators
run unchanged. This idle test opens no VPN or network socket and makes no claim
of live MTU measurement or an Apple SDK/device build.
"""
from pathlib import Path
import argparse
import importlib.util
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T = load('device_native_bridge', 'deploy/test_ios_tor_profile.py')
E = load('device_external_fixtures', 'deploy/test_ios_external_policy.py')


def member(source, signature):
    begin = source.index(signature)
    start = source.index('{', begin)
    depth, index = 1, start + 1
    while depth:
        if source[index] == '{': depth += 1
        if source[index] == '}': depth -= 1
        index += 1
    return source[begin:index].replace('private func ', 'func ')


SWIFT = r'''
import Foundation
import Libbox
enum IOSRuntimeSelectionError:Error{case unsupportedMode(String)}
enum IOSDNSRuntimePolicy {
 // SELECTED_PROFILE
}
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?,profileMutationBlocked=false,imports=0,failImport=false,separateEntry=false
 func importBundle(_ data:Data)throws {
  if failImport {throw NSError(domain:"DeviceStoreWrite",code:1)}
  let prepared=try JSONDecoder().decode(ClientBundle.self,from:data)
  bundle=prepared;imports+=1
 }
 func iosMultihopEntryBundle(for source:ClientBundle)throws->ClientBundle {
  guard let selected=IOSDNSRuntimePolicy.selectedProfile(in:source)else{throw CancellationError()}
  let entries=source.routerProfiles.filter{$0.id==selected.multihopEntryID && $0.id != selected.id}
  guard entries.count==1 else{throw CancellationError()}
  var captured=source;captured.selectedRouterID=entries[0].id;if separateEntry{captured.routerProfiles=entries};return captured
 }
 // CAPTURE_ENTRY
}
@MainActor final class Settings {
 let model:RouterVPNModel
 var homeLANAccess=true,killSwitchPolicy="off",ipv6Mode="on",baseTunnel="auto",baseFallback=false,startLayer="off"
 var autoRequireEncrypted=false,autoRequireObfuscation=false,mtuPolicy="auto",manualMTU="",daitaEnabled=false,jumboTUN=false
 var startupMode="smart-auto",autoConnect=false,loadedProfile:RouterProfile?,loadedTorEntry:Data?,torPaddingRate="192",status=""
 init(_ model:RouterVPNModel){self.model=model}
 // SETTINGS_METHODS
}
@MainActor @main struct Tests {
 static var checks=0
 static let protocols=["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn","tor","tor-bridge"]
 static func check(_ label:String,_ condition:@autoclosure ()throws->Bool)throws {
  guard try condition()else{throw NSError(domain:"DeviceSettingsTest",code:1,userInfo:[NSLocalizedDescriptionKey:label])};checks+=1
 }
 static func json(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
 static func encoded<T:Encodable>(_ value:T)throws->Data{let e=JSONEncoder();e.outputFormatting=[.sortedKeys];return try e.encode(value)}
 static func key(_ byte:UInt8)->String{Data(repeating:byte,count:32).base64EncodedString()}
 // TRANSPORT_FIXTURES
 static func profile(_ kind:String)throws->RouterProfile {
  var value=ordinaryProfile(kind)
  for field in ["endpoint","router_api","api_token","adguard_ipv4","adguard_ipv6","socks_host","socks_username","socks_password"]{value[field]=""}
  value["socks_port"]=0
  if kind.hasPrefix("tor") {
   value["endpoint"]="tor"
   var ext:[String:Any]=["protocol":kind,"expected_public_ip":""]
   if kind=="tor-bridge"{ext["tor_bridge"]=["transport":"obfs4","bridges":["obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0"]]}
   value["external"]=ext
  }
  var p=try JSONDecoder().decode(RouterProfile.self,from:json(value))
  p.startupMode="last";p.autoConnect=true;p.autoRequireEncrypted=true;p.autoRequireObfuscation=true
  p.killSwitch=true;p.killSwitchPolicy="always";p.daitaEnabled=true;p.daitaHost="192.0.2.40";p.daitaPort=4444;p.daitaRateKbps=160
  p.jumboTUN=false
  p.multihopEnabled=true;p.multihopEntryID="paired-entry";p.multihopEntryMode="wg";p.multihopExitID=p.id;p.multihopExitMode=kind;p.multihopExecution="local"
  p.effectiveMTU=9000;p.effectiveMTUSource="historic-only";p.effectiveMTUPathKey="old-path";p.effectiveMTUTestedAt="2000-01-01T00:00:00Z"
  p.dnsMode="doh";p.dnsProtocol="https";p.dnsHost="resolver.example.test";p.dnsServerName="resolver.example.test";p.dnsPort=444;p.dnsPath="/exact-query"
  var bootstrap=ExternalDNSBootstrap(server:.init(type:"tcp",server:"9.9.9.9",serverPort:5353))
  bootstrap.query.strategy="prefer_ipv4";bootstrap.query.timeout="3.5s";bootstrap.query.disableCache=true;bootstrap.query.rewriteTTL=19
  p.dnsBootstrap=bootstrap
  if kind.hasPrefix("tor"){p.dnsHost="1.1.1.1";p.dnsServerName="cloudflare-dns.com";p.dnsBootstrap=nil;p.jumboTUN=false}
  return p
 }
 static func bundle(_ p:RouterProfile)throws->ClientBundle {
  var b=ClientBundle.empty,foreign=try profile("shadowsocks"),entry=try profile("wireguard")
  foreign.id="other-node";foreign.name="Independent node"
  entry.id="paired-entry";entry.nodeKind="router-vpn";entry.external=nil;entry.apiToken="private entry token";entry.routerAPI="http://10.8.0.1:8787"
  entry.nodeProofID=String(repeating:"a",count:64);entry.adGuardIPv4="192.168.50.133";entry.killSwitchPolicy="always";entry.homeLANAccess=false
  b.routerProfiles=[foreign,p,entry];b.selectedRouterID=p.id
  b.profiles=["wg":["wg.conf":"private entry bytes"],"owned":["secret":"exact private data"]]
  return try JSONDecoder().decode(ClientBundle.self,from:encoded(b))
 }
 static func saveMatrix()throws {
  for kind in protocols {for mtu in ["auto","manual","default"] {for lan in [false,true] {
   let p=try profile(kind),model=RouterVPNModel();model.bundle=try bundle(p)
   let before=model.bundle!,editor=Settings(model);editor.load()
   try check("load fixed alias and saved value "+kind,editor.loadedProfile==p && editor.mtuPolicy=="manual" && editor.manualMTU=="1380" && editor.killSwitchPolicy=="always")
   editor.homeLANAccess=lan;editor.ipv6Mode=lan ? "on":"off";editor.mtuPolicy=mtu;editor.manualMTU=" 1420 "
   editor.killSwitchPolicy=mtu=="auto" ? "off":mtu=="manual" ? "on-connect":"always"
   editor.saveExternalDevicePolicy()
   var expected=p;expected.homeLANAccess=lan;expected.ipv6Mode=editor.ipv6Mode;expected.mtuPolicy=mtu;expected.manualMTU=mtu=="manual" ? 1420:0
   expected.killSwitchPolicy=editor.killSwitchPolicy;expected.killSwitch=editor.killSwitchPolicy != "off"
   try check("native device save "+kind+"/"+mtu+": "+editor.status,model.imports==1 && model.bundle!.routerProfiles[1]==expected)
   try check("unrelated nodes and private assets stay exact",model.bundle!.routerProfiles[0]==before.routerProfiles[0] && model.bundle!.routerProfiles[2]==before.routerProfiles[2] && model.bundle!.profiles==before.profiles)
   try check("all hidden DNS keys graph startup and measurements stay exact",model.bundle!.routerProfiles[1].external==p.external && model.bundle!.routerProfiles[1].dnsBootstrap==p.dnsBootstrap && model.bundle!.routerProfiles[1].effectiveMTU==9000)
   try check("successful editor keeps current exact snapshot",editor.loadedProfile==expected)
   try check("saved policy is not a runtime proof",editor.status.contains("must still prove"))
  }}}
  for kind in protocols {
   let p=try profile(kind),model=RouterVPNModel();model.bundle=try bundle(p);let editor=Settings(model);editor.load();editor.ipv6Mode="auto";editor.saveExternalDevicePolicy()
   try check("IPv6 Auto remains a real saved policy "+kind,model.imports==1 && model.bundle!.routerProfiles[1].ipv6Mode=="auto")
   // A startup-only save must not adopt unsaved device form values.
   let before=model.bundle!.routerProfiles[1];editor.homeLANAccess=true;editor.killSwitchPolicy="off";editor.ipv6Mode="on";editor.mtuPolicy="manual";editor.manualMTU="1492"
   editor.startupMode="manual";editor.autoConnect=true;editor.save()
   var expected=before;expected.startupMode="manual";expected.autoConnect=false
   try check("startup save cannot reset hidden device policy "+kind,model.imports==2 && model.bundle!.routerProfiles[1]==expected)
  }
 }
 static func invalidDrafts()throws {
  for kind in ["wireguard","openvpn","tor"] {
   for value in ["","0","1279","9001","1380.5","text","-1","NaN"] {
    let model=RouterVPNModel();model.bundle=try bundle(profile(kind));let before=try encoded(model.bundle!),editor=Settings(model);editor.load()
    editor.mtuPolicy="manual";editor.manualMTU=value;editor.saveExternalDevicePolicy()
    try check("invalid fixed MTU cannot become a default "+kind+":"+value,model.imports==0 && encoded(model.bundle!)==before && editor.status.contains("Fixed MTU"))
   }
   for field in ["kill","ipv6","mtu"] {
    let model=RouterVPNModel();model.bundle=try bundle(profile(kind));let before=try encoded(model.bundle!),editor=Settings(model);editor.load()
    if field=="kill"{editor.killSwitchPolicy="unknown"};if field=="ipv6"{editor.ipv6Mode="unknown"};if field=="mtu"{editor.mtuPolicy="unknown"};editor.saveExternalDevicePolicy()
    try check("unknown policy cannot silently save "+kind+":"+field,model.imports==0 && encoded(model.bundle!)==before)
   }
  }
  for fault in ["busy","selection","credentials","policy","duplicate","write"] {
   let model=RouterVPNModel();model.bundle=try bundle(profile("socks5"));let editor=Settings(model);editor.load();editor.ipv6Mode="on"
   switch fault {
   case "busy":model.profileMutationBlocked=true
   case "selection":model.bundle!.selectedRouterID="other-node"
   case "credentials":model.bundle!.routerProfiles[1].external!.socks5!.password="new private secret"
   case "policy":model.bundle!.routerProfiles[1].dnsHost="different.example.test"
   case "duplicate":model.bundle!.routerProfiles.append(model.bundle!.routerProfiles[1])
   case "write":model.failImport=true
   default:break
   }
   let before=try encoded(model.bundle!);editor.saveExternalDevicePolicy()
   try check("device editor rejects stale or active write "+fault,model.imports==0 && encoded(model.bundle!)==before)
  }
 }
 static func nativeRejections()throws {
  for fault in ["wireguard-key","wireguard-mtu","wireguard-jumbo","proxy-jumbo-fixed","openvpn","tor-identity","lan"] {
   let kind=fault.hasPrefix("wireguard") ? "wireguard":fault=="openvpn" ? "openvpn":fault=="tor-identity" ? "tor":"socks5"
   var raw=try JSONSerialization.jsonObject(with:encoded(profile(kind))) as! [String:Any]
   if ["wireguard-key","wireguard-mtu"].contains(fault) {var ext=raw["external"] as! [String:Any],packet=ext["wireguard"] as! [String:Any];if fault=="wireguard-key"{packet["private_key"]="wrong"}else{packet["mtu"]=1200};ext["wireguard"]=packet;raw["external"]=ext}
   if fault=="wireguard-jumbo" || fault=="proxy-jumbo-fixed"{raw["jumbo_tun"]=true}
   if fault=="openvpn"{var ext=raw["external"] as! [String:Any],packet=ext["openvpn"] as! [String:Any];packet["config"]="client\ndev tun\nremote 198.51.100.8 1194\nscript-security 3\nup /tmp/unowned\n";ext["openvpn"]=packet;raw["external"]=ext}
   if fault=="tor-identity"{raw["api_token"]="foreign node token"}
   if fault=="lan"{raw["home_lan_cidrs"]=["0.0.0.0/0"]}
   let invalid=try JSONDecoder().decode(RouterProfile.self,from:json(raw)),model=RouterVPNModel();model.bundle=try bundle(invalid);let before=try encoded(model.bundle!),editor=Settings(model);editor.load();editor.homeLANAccess=false;editor.mtuPolicy=fault=="proxy-jumbo-fixed" ? "manual":"auto";editor.saveExternalDevicePolicy()
   try check("real native validator rejects "+fault,model.imports==0 && encoded(model.bundle!)==before && editor.status.hasPrefix("Device policy rejected:"))
  }
  // Idle drafts may retain unresolved Home until their real Router entry is
  // captured. This editor never substitutes a resolver or grants readiness.
  for kind in ["wireguard","tor"] {
   var p=try profile(kind);p.dnsMode="home";p.dnsHost="";p.dnsProtocol="udp";p.dnsPort=53;p.dnsServerName="";p.dnsPath="";p.dnsBootstrap=nil
   let model=RouterVPNModel();model.bundle=try bundle(p);let editor=Settings(model);editor.load();editor.saveExternalDevicePolicy()
   try check("unresolved Home draft remains owned "+kind,model.imports==1 && model.bundle!.routerProfiles[1].dnsMode=="home" && model.bundle!.routerProfiles[1].dnsHost=="")
  }
 }
 static func torJumboNativePolicy()throws {
  for kind in ["tor","tor-bridge"] {
   var p=try profile(kind);p.jumboTUN=true;p.mtuPolicy="manual";p.manualMTU=9000
   for selected in ["auto","default","manual"] {
    let model=RouterVPNModel();model.bundle=try bundle(p);let editor=Settings(model);editor.load()
    editor.mtuPolicy=selected;editor.manualMTU="9000";editor.saveExternalDevicePolicy()
    try check("valid native Tor Jumbo preserves saved preference "+kind+":"+selected,model.imports==1 && model.bundle!.routerProfiles[1].jumboTUN==true && model.bundle!.routerProfiles[1].mtuPolicy==selected)
   }
   for fixed in ["1280","1420","8999"] {
    let model=RouterVPNModel();model.bundle=try bundle(p);let before=try encoded(model.bundle!),editor=Settings(model);editor.load()
    editor.mtuPolicy="manual";editor.manualMTU=fixed;editor.saveExternalDevicePolicy()
    try check("native Tor Jumbo rejects conflicting Fixed MTU "+kind+":"+fixed,model.imports==0 && encoded(model.bundle!)==before && editor.status.hasPrefix("Device policy rejected:") && editor.status.contains("Jumbo"))
   }
  }
 }
 static func torJumboEditor()throws {
  for kind in ["tor","tor-bridge"] {for mode in ["auto","default","manual"] {
   var p=try profile(kind);p.jumboTUN=nil;p.mtuPolicy=mode;p.manualMTU=mode=="manual" ? 9000:0
   let model=RouterVPNModel();model.bundle=try bundle(p);let before=model.bundle!,editor=Settings(model);editor.load()
   try check("Tor Jumbo loads absent flag without inventing true",!editor.jumboTUN && editor.mtuPolicy==mode)
   editor.jumboTUN=true;editor.saveExternalDevicePolicy()
   var expected=p;expected.jumboTUN=true;expected.homeLANAccess=editor.homeLANAccess;expected.killSwitchPolicy=editor.killSwitchPolicy;expected.killSwitch=editor.killSwitchPolicy != "off";expected.ipv6Mode=editor.ipv6Mode
   try check("Tor Jumbo editor saves exact visible choice "+kind+":"+mode,model.imports==1 && model.bundle!.routerProfiles[1]==expected && editor.loadedProfile==expected)
   try check("Jumbo preserves credentials DNS entry and unrelated sources",model.bundle!.routerProfiles[0]==before.routerProfiles[0] && model.bundle!.routerProfiles[2]==before.routerProfiles[2] && model.bundle!.profiles==before.profiles)
   editor.load();try check("Tor Jumbo toggle reloads saved choice",editor.jumboTUN && editor.mtuPolicy==mode)
   editor.jumboTUN=false;editor.saveExternalDevicePolicy();expected.jumboTUN=false
   try check("Tor Jumbo toggle restores exact Auto or Default choice "+mode,model.imports==2 && model.bundle!.routerProfiles[1]==expected)
  }}
  for kind in protocols where !kind.hasPrefix("tor") {
   var p=try profile(kind);p.jumboTUN = !["wireguard","amneziawg","openvpn"].contains(kind)
   if p.jumboTUN==true{p.mtuPolicy="manual";p.manualMTU=9000}
   let model=RouterVPNModel();model.bundle=try bundle(p);let editor=Settings(model);editor.load()
   try check("ordinary hidden Jumbo loads unchanged "+kind,editor.jumboTUN==(p.jumboTUN ?? false))
   editor.jumboTUN = !editor.jumboTUN;editor.saveExternalDevicePolicy()
   try check("ordinary editor cannot mutate its hidden Jumbo flag "+kind,model.imports==1 && model.bundle!.routerProfiles[1].jumboTUN==p.jumboTUN)
  }
  for fault in ["active","stale","store"] {
   let model=RouterVPNModel();model.bundle=try bundle(profile("tor"));let editor=Settings(model);editor.load();editor.mtuPolicy="auto";editor.jumboTUN=true
   if fault=="active"{model.profileMutationBlocked=true}
   if fault=="stale"{model.bundle!.routerProfiles[1].external!.protocolName="tor-bridge"}
   if fault=="store"{model.failImport=true}
   let before=try encoded(model.bundle!);editor.saveExternalDevicePolicy()
   try check("Jumbo stale or failed transaction keeps source exact "+fault,model.imports==0 && encoded(model.bundle!)==before)
  }
 }
 static func main(){
  defer{RouterVPNTorTestClose()}
  do{try saveMatrix();try invalidDrafts();try nativeRejections();try torJumboNativePolicy();try torJumboEditor();try torPaddingEditor();print("Apple external device settings: PASS (\(checks) shipping editor/model checks with real native ordinary/Tor transport-policy validation)")}
  catch{FileHandle.standardError.write(Data((error.localizedDescription+"\n").utf8));exit(1)}
 }
 static func torPaddingEditor()throws {
  for kind in ["tor","tor-bridge"] {for execution in ["local","server"] {for rate in [32,64,192] {for enabled in [false,true] {for separate in [false,true] {
   var p=try profile(kind);p.multihopExecution=execution;p.daitaEnabled=false;p.daitaRateKbps=96
   let model=RouterVPNModel();model.separateEntry=separate;model.bundle=try bundle(p);let before=model.bundle!,editor=Settings(model);editor.load()
   try check("Tor padding loads exact saved rate",!editor.daitaEnabled && editor.torPaddingRate=="96")
   editor.daitaEnabled=enabled;editor.torPaddingRate=String(rate);editor.saveExternalDevicePolicy()
   var expected=p;expected.mtuPolicy="manual";expected.homeLANAccess=editor.homeLANAccess;expected.killSwitchPolicy=editor.killSwitchPolicy;expected.killSwitch=true;expected.ipv6Mode=editor.ipv6Mode
   expected.daitaEnabled=enabled;expected.daitaRateKbps=enabled ? rate:96
   try check("Tor padding atomically saves enabled and selected rate "+kind+execution+String(rate)+String(enabled),model.imports==1 && model.bundle!.routerProfiles[1]==expected && editor.loadedProfile==expected)
   try check("Tor padding leaves other credentials and entry policy exact",model.bundle!.routerProfiles[0]==before.routerProfiles[0] && model.bundle!.routerProfiles[2]==before.routerProfiles[2] && model.bundle!.profiles==before.profiles)
   editor.load();editor.daitaEnabled=false;editor.torPaddingRate="discarded while Off";editor.saveExternalDevicePolicy()
   try check("Tor Off preserves dormant rate",model.imports==2 && model.bundle!.routerProfiles[1].daitaEnabled==false && model.bundle!.routerProfiles[1].daitaRateKbps==expected.daitaRateKbps)
  }}}}}
  for rate in [Int?.none,0] {
   var p=try profile("tor");p.daitaEnabled=false;p.daitaRateKbps=rate
   let model=RouterVPNModel();model.bundle=try bundle(p);let editor=Settings(model);editor.load()
   try check("Tor unset rate displays bounded default",editor.torPaddingRate=="192")
   editor.saveExternalDevicePolicy();try check("Off retains exact unset or zero rate",model.imports==1 && model.bundle!.routerProfiles[1].daitaRateKbps==rate)
   editor.daitaEnabled=true;editor.saveExternalDevicePolicy();try check("Tor On persists bounded default",model.imports==2 && model.bundle!.routerProfiles[1].daitaRateKbps==192)
  }
  for value in ["31","193","-1","64.5","","true","999999999999999999999999"] {
   let model=RouterVPNModel();model.bundle=try bundle(profile("tor"));let before=try encoded(model.bundle!),editor=Settings(model);editor.load();editor.daitaEnabled=true;editor.torPaddingRate=value;editor.saveExternalDevicePolicy()
   try check("invalid padding rate cannot mutate profile "+value,model.imports==0 && encoded(model.bundle!)==before)
  }
  for fault in ["busy","selected","exit-policy","entry-credential","entry-policy","entry-assets","entry-missing","entry-duplicate","store"] {
   let model=RouterVPNModel();model.bundle=try bundle(profile("tor"));let editor=Settings(model);editor.load();editor.daitaEnabled=false;editor.torPaddingRate="64"
   switch fault {
   case "busy":model.profileMutationBlocked=true
   case "selected":model.bundle!.selectedRouterID="other-node"
   case "exit-policy":model.bundle!.routerProfiles[1].dnsHost="8.8.8.8"
   case "entry-credential":model.bundle!.routerProfiles[2].apiToken="replacement private token"
   case "entry-policy":model.bundle!.routerProfiles[2].ipv6Mode=model.bundle!.routerProfiles[2].ipv6Mode=="off" ? "on":"off"
   case "entry-assets":model.bundle!.profiles["wg"]=["wg.conf":"replacement private entry bytes"]
   case "entry-missing":model.bundle!.routerProfiles.removeLast()
   case "entry-duplicate":model.bundle!.routerProfiles.append(model.bundle!.routerProfiles[2])
   default:model.failImport=true
   }
   let before=try encoded(model.bundle!);editor.saveExternalDevicePolicy()
   try check("Tor padding rejects changed or failed owner "+fault,model.imports==0 && encoded(model.bundle!)==before)
  }
  for kind in protocols where !kind.hasPrefix("tor") {
   let model=RouterVPNModel();model.bundle=try bundle(profile(kind));let before=model.bundle!.routerProfiles[1],editor=Settings(model);editor.load();editor.daitaEnabled=false;editor.torPaddingRate="bad";editor.saveExternalDevicePolicy()
   try check("ordinary node cannot adopt hidden Tor padding controls",model.imports==1 && model.bundle!.routerProfiles[1].daitaEnabled==before.daitaEnabled && model.bundle!.routerProfiles[1].daitaRateKbps==before.daitaRateKbps)
  }
 }
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--shipping-only', action='store_true')
    parser.add_argument('--mutation', action='append', choices=['active-write', 'stale-source', 'native-validation', 'historical-mtu', 'jumbo-load', 'jumbo-save', 'padding-rate', 'padding-entry'])
    args = parser.parse_args()
    swift, go = shutil.which('swiftc'), shutil.which('go')
    if not swift or not go: raise RuntimeError('swiftc and go are required')
    view = (APP / 'IOSProfileSettingsView.swift').read_text()
    methods = '\n'.join(member(view, signature) for signature in [
        'private func selectedProfile()', 'private func load()', 'private func saveExternalDevicePolicy()', 'private func save()'])
    selected = member((APP / 'IOSDNSRuntimePolicy.swift').read_text(), 'static func selectedProfile(')
    fixtures = '\n'.join(member(E.SWIFT, signature) for signature in [
        'static func profile(', 'static func amneziaParameters(', 'static func openVPNConfig('])
    fixtures = fixtures.replace('profile(', 'ordinaryProfile(')
    source = SWIFT.replace(' // SETTINGS_METHODS', methods).replace(' // SELECTED_PROFILE', selected).replace(' // TRANSPORT_FIXTURES', fixtures)
    source = source.replace(' // CAPTURE_ENTRY', member((APP / 'RouterVPNModelExternal.swift').read_text(), 'func externalTorEntryData('))
    policy = (APP / 'IOSDevicePolicySettings.swift').read_text()
    assert 'Button("Save device policy for next connection") { saveExternalDevicePolicy() }' in view
    assert 'if torNode {\n                            Toggle("Jumbo virtual interface (9000)", isOn: $jumboTUN)' in view
    assert 'not a measured Internet packet limit' in view and 'Jumbo disables Auto MTU and Retest' in view
    assert '("Auto — default","auto")' in view and 'Auto measured — default' not in view
    assert view.index('Section("Live MTU")') > view.index('Section("MTU")'), 'keep the common current-owner MTU card'
    with tempfile.TemporaryDirectory(prefix='ios-external-device-settings-') as temporary, tempfile.TemporaryDirectory(prefix='.ios-device-go-', dir=ROOT) as go_dir:
        work = Path(temporary)
        compiler_source = Path(go_dir) / 'main.go'; compiler_source.write_text(T.GO)
        compiler = work / 'compiler'
        subprocess.run([go, 'build', '-o', str(compiler), str(compiler_source)], cwd=ROOT, check=True, timeout=120)
        options = [swift, '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        libbox = work / 'Libbox.swift'; libbox.write_text(T.LIBBOX)
        suffix = '.dylib' if platform.system() == 'Darwin' else '.so'
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(libbox), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(work / ('libLibbox' + suffix))], check=True, timeout=90)
        options += ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        code = work / 'Tests.swift'; code.write_text(source)
        draft = work / 'IOSDevicePolicySettings.swift'; draft.write_text(policy)
        binary = work / 'tests'
        command = options + ['-Onone', '-whole-module-optimization', str(APP / 'Models.swift'), str(APP / 'IOSStartupPolicy.swift'), str(APP / 'IOSExternalExecution.swift'), str(draft), str(code), '-o', str(binary)]
        subprocess.run(command, check=True, timeout=120)
        subprocess.run([str(binary), str(compiler)], check=True, timeout=60)
        if args.shipping_only: return
        for name, target, before, after, expected in (
            ('active-write', 'source', 'guard !model.profileMutationBlocked else { status = "Disconnect or let the active VPN transition finish before changing device policy."; return }', 'guard true else { return }', 'device editor rejects stale or active write busy'),
            ('stale-source', 'source', '              selected == loadedProfile,\n', '', 'device editor rejects stale or active write selection'),
            ('native-validation', 'source', 'try IOSExternalExecution.validateDeviceDraft(prepared)', '', 'real native validator rejects wireguard-key'),
            ('historical-mtu', 'policy', 'profile.mtuPolicy = mtuPolicy; profile.manualMTU = fixed', 'profile.mtuPolicy = mtuPolicy; profile.manualMTU = source.effectiveMTU ?? fixed', 'native device save wireguard/auto'),
            ('jumbo-load', 'source', '            jumboTUN = policy.jumboTUN', '            jumboTUN = false', 'valid native Tor Jumbo preserves saved preference'),
            ('jumbo-save', 'source', '        draft.jumboTUN = jumboTUN', '', 'Tor Jumbo editor saves exact visible choice'),
            ('padding-rate', 'source', 'draft.torPaddingRate = torPaddingRate', 'draft.torPaddingRate = torPaddingRate == "64" ? "192" : torPaddingRate', 'Tor padding atomically saves enabled and selected rate'),
            ('padding-entry', 'source', 'guard let loadedTorEntry, let currentEntry = try? model.externalTorEntryData(source: bundle), currentEntry == loadedTorEntry else', 'guard true else', 'Tor padding rejects changed or failed owner entry-credential'),
        ):
            if args.mutation and name not in args.mutation: continue
            original = source if target == 'source' else policy
            assert original.count(before) == 1, name
            code.write_text(source.replace(before, after, 1) if target == 'source' else source)
            draft.write_text(policy.replace(before, after, 1) if target == 'policy' else policy)
            subprocess.run(command, check=True, timeout=120)
            result = subprocess.run([str(binary), str(compiler)], capture_output=True, text=True, timeout=60)
            assert result.returncode == 1 and expected in result.stderr, name + ': ' + result.stderr[-2000:]
            print('Rejected external device-policy defect mutation: ' + name, flush=True)


if __name__ == '__main__':
    main()
