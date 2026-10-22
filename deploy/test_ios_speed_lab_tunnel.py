#!/usr/bin/env python3
"""Exercise shipping exact-runtime capture/stop/restore with system VPN doubles.

The native policy/proof engines have separate real-core gates. This suite tests
the actual host code against changed preferences, user intent, and stale owners.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
SHIM=r'''
import Foundation
import CoreFoundation
enum Status {case connected,connecting,reasserting,disconnecting,disconnected,invalid}
@MainActor enum FixtureClock {static var value=0.0;static var now:Double{value+=10;return value}}
@MainActor class NEVPNProtocol:NSObject,@preconcurrency NSCopying {
 var serverAddress:String?
 var includeAllNetworks=false,enforceRoutes=false,excludeLocalNetworks=false,excludeAPNs=false,excludeCellularServices=false
 func copy(with zone:NSZone?=nil)->Any {fatalError("copy exact protocol")}
}
@MainActor final class NETunnelProviderProtocol:NEVPNProtocol {
 var providerBundleIdentifier:String?,providerConfiguration:[String:Any]?
 override func copy(with zone:NSZone?=nil)->Any {
  let next=NETunnelProviderProtocol();next.providerBundleIdentifier=providerBundleIdentifier;next.serverAddress=serverAddress
  next.providerConfiguration=providerConfiguration;next.includeAllNetworks=includeAllNetworks;next.enforceRoutes=enforceRoutes
  next.excludeLocalNetworks=excludeLocalNetworks;next.excludeAPNs=excludeAPNs;next.excludeCellularServices=excludeCellularServices;return next
 }
}
@MainActor class NEOnDemandRule:NSObject,@preconcurrency NSCopying {
 var action=1,interfaceTypeMatch=0
 var dnsSearchDomainMatch:[String]?,dnsServerAddressMatch:[String]?,ssidMatch:[String]?,probeURL:URL?
 func copy(with zone:NSZone?=nil)->Any {
  let next=NEOnDemandRuleConnect();next.action=action;next.interfaceTypeMatch=interfaceTypeMatch
  next.dnsSearchDomainMatch=dnsSearchDomainMatch;next.dnsServerAddressMatch=dnsServerAddressMatch;next.ssidMatch=ssidMatch;next.probeURL=probeURL;return next
 }
}
@MainActor final class NEOnDemandRuleConnect:NEOnDemandRule{}
@MainActor final class Connection {
 var status:Status = .connected,connectedDate:Date?=Date(timeIntervalSince1970:1)
 var starts=0,stops=0,hold="",failedProof=false,stuckStop=false
 var execution="server",epoch=UUID().uuidString
 func startVPNTunnel(options:[String:NSObject]?=nil)throws{
  if let config=(NETunnelProviderManager.stored.first?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
     try IOSMultihopExecution.requiresCapture(configuration:config) {
   let source=try IOSMultihopExecution.Source(configuration:config,digest:RouterVPNModel.iosStrategyDigest)
   execution=try IOSMultihopExecution.restoredExecution(option:options?[IOSMultihopExecution.launchKey],source:source,mtuHold:options?["routervpn_mtu_hold"] as? String ?? "") ?? "local"
  }
  epoch=UUID().uuidString
  starts+=1;hold=options?["routervpn_mtu_hold"] as? String ?? "";status = .connected;connectedDate=Date(timeIntervalSince1970:Double(starts+10));Trace.values.append("native-start")
 }
 func stopVPNTunnel(){stops+=1;status=stuckStop ? .disconnecting:.disconnected;connectedDate=nil;Trace.values.append("native-stop")}
}
typealias NETunnelProviderSession=Connection
@MainActor enum Trace {static var values:[String]=[]}
@MainActor final class NETunnelProviderManager {
 static var stored:[NETunnelProviderManager]=[],hook:(()->Void)?
 var protocolConfiguration:NEVPNProtocol?,onDemandRules:[NEOnDemandRule]?,localizedDescription:String?
 var isEnabled=true,isOnDemandEnabled=true,saves=0,reads=0,autoStartsOnSave=true
 let connection=Connection()
 static func loadAllFromPreferences()async throws->[NETunnelProviderManager]{await Task.yield();return stored}
 func saveToPreferences()async throws{saves+=1;Trace.values.append("save");let action=Self.hook;Self.hook=nil;await Task.yield();action?();if autoStartsOnSave,isOnDemandEnabled,connection.status == .disconnected {try connection.startVPNTunnel()}}
 func loadFromPreferences()async throws{reads+=1;Trace.values.append("read");await Task.yield()}
}
@MainActor enum IOSMTUMeasurementGate{static var current=String(repeating:"a",count:32)}
@MainActor enum IOSMTUControl{
 static var healthy=true
 static func send(_ connection:Connection,operation:String,request:String,session:String)async throws->Data{
  guard healthy,operation=="speed-lab-execution",session.isEmpty,
        let config=(NETunnelProviderManager.stored.first?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration else{throw IOSMultihopExecution.issue()}
  let source=try IOSMultihopExecution.Source(configuration:config,digest:RouterVPNModel.iosStrategyDigest)
  return try IOSMultihopExecution.Capture(source:source,execution:connection.execution,session:connection.epoch,request:request).encoded()
 }
}
@MainActor final class RouterVPNModel {
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var connected=true,tunnelTransitioning=false,iosUserDisconnectInProgress=false
 var activeSessionIdentity:IOSSessionIdentity?,iosConnectGeneration=UUID()
 static func iosStrategyDigest(_ data:Data)->String{let hash=data.reduce(UInt64(14695981039346656037)){($0 ^ UInt64($1)) &* 1099511628211};return String(repeating:String(format:"%016llx",hash),count:4)}
 func refreshTunnelStatus()async {
  guard let m=NETunnelProviderManager.stored.first,let p=m.protocolConfiguration as? NETunnelProviderProtocol,let c=p.providerConfiguration else{connected=false;tunnelTransitioning=false;activeSessionIdentity=nil;return}
  connected=m.connection.status == .connected && !m.connection.failedProof
  tunnelTransitioning=[.connecting,.reasserting,.disconnecting].contains(m.connection.status) || m.connection.failedProof
  guard connected,let date=m.connection.connectedDate,let bundle=c["bundle"] as? Data else{activeSessionIdentity=nil;return}
  let raw=(c["strategy"] as? [String:Any]).flatMap{($0["candidates"] as? [[String:Any]])?.first?["raw"] as? String} ?? c["rawProfileID"] as? String ?? c["mode"] as? String ?? ""
  activeSessionIdentity=try! IOSSessionIdentity(connectedAt:date,engine:c["engine"] as! String,rawProfile:raw,bundleData:bundle,configuration:c)
 }
}
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ text:String,_ value:@autoclosure()->Bool){guard value()else{fatalError("FAIL: "+text)};checks+=1}
 static func rejected(_ text:String,_ action:()async throws->Void)async{do{try await action();fatalError("FAIL: "+text)}catch{checks+=1}}
 static func fresh(_ engine:String="libbox",_ raw:String="awg2-fast",_ strategy:Bool=false,_ entry:Bool=false)throws->(RouterVPNModel,NETunnelProviderManager,UUID){
  Trace.values=[];FixtureClock.value=0;NETunnelProviderManager.hook=nil;IOSMTUMeasurementGate.current=String(repeating:"a",count:32);IOSMTUControl.healthy=true
  let model=RouterVPNModel(),m=NETunnelProviderManager(),p=NETunnelProviderProtocol(),rule=NEOnDemandRuleConnect()
  rule.ssidMatch=["original-network"];m.onDemandRules=[rule];m.localizedDescription="Original selected router"
  p.providerBundleIdentifier="com.eabusham.routervpn.PacketTunnel";p.serverAddress="original-endpoint"
  p.includeAllNetworks=true;p.enforceRoutes=true;p.excludeLocalNetworks=false;p.excludeAPNs=false;p.excludeCellularServices=false
  let source:Data
  if engine=="external-libbox" {
   let kind=String(raw.dropFirst("external-".count))
   let selected:[String:Any]=["id":"exit","node_kind":"external","external":["protocol":kind,"shadowsocks":["server":"198.51.100.8","password":"exact external credentials"],"response_probe":["url":"https://198.51.100.8/response","server_name":"node.example.test"]],"multihop_enabled":entry,"multihop_entry_id":"entry","multihop_exit_id":"exit","multihop_entry_mode":"max-tls-awg","multihop_exit_mode":kind,"multihop_execution":kind=="shadowsocks" ? "auto":"local"]
   source=try JSONSerialization.data(withJSONObject:["selectedRouterID":"exit","routerProfiles":[selected]])
  }else{
   source=engine=="multihop-libbox" ? try JSONSerialization.data(withJSONObject:["selectedRouterID":"exit","routerProfiles":[["id":"exit","node_kind":"router-vpn","multihop_enabled":true,"multihop_entry_id":"entry","multihop_exit_id":"exit","multihop_entry_mode":"awg2-strong","multihop_exit_mode":raw,"multihop_execution":"auto"]],"profiles":["private-credential":"captured encrypted assets"]]) : Data("exact private profiles; DNS DoH; MTU Auto; execution Compare both".utf8)
  }
  var c:[String:Any]=["engine":engine,"mode":raw,"bundle":source,"max_source_sha256":["entry":"full-start-layer-pq-owner"]]
  if entry {
   if engine=="external-libbox" {let prefix=raw.hasPrefix("external-tor") ? "tor_entry":"external_entry";c[prefix+"_bundle"]=try JSONSerialization.data(withJSONObject:["selectedRouterID":"entry","routerProfiles":[["id":"entry","node_kind":"router-vpn"]],"profiles":["max":"exact MAX entry private assets"]]);c[prefix+"_mode"]="max-tls-awg"}
   else{c["entryBundle"]=try JSONSerialization.data(withJSONObject:["selectedRouterID":"entry","routerProfiles":[["id":"entry","node_kind":"router-vpn"]],"profiles":["awg":"exact AWG private assets"]])}
  }
  if strategy {
   c["mode"]="wg";c["strategy_catalog"]=["version":1,"candidates":[["raw":"wg","logical":"base-raw"],["raw":raw,"logical":"base-raw"]]]
   c["strategy"]=["version":1,"kind":"smart","candidates":[["raw":"wg","logical":"base-raw"],["raw":raw,"logical":"base-raw"]]]
  }
  p.providerConfiguration=c;m.protocolConfiguration=p;NETunnelProviderManager.stored=[m]
  model.activeSessionIdentity=try IOSSessionIdentity(connectedAt:m.connection.connectedDate!,engine:engine,rawProfile:raw,bundleData:source,configuration:c)
  let owner=try model.iosSpeedLabOwnership.begin{}
  return(model,m,owner)
 }
 static func main()async throws {
  for (engine,raw,strategy,entry) in [("libbox","awg2-fast",true,false),("wireguard","wg",false,false),("multihop-libbox","max-tls-awg",false,true),("external-libbox","external-amneziawg",false,true),("external-libbox","external-tor",false,true),("external-libbox","external-shadowsocks",false,true)]{
   let (model,m,owner)=try fresh(engine,raw,strategy,entry),before=model.activeSessionIdentity!
   try await IOSSpeedLabContext.$owner.withValue(owner){
    let captured=try await IOSSpeedLabTunnel.capture(model:model,owner:owner)
    try await captured.stopOriginal(model:model,owner:owner)
    check("original native owner fully stops before temporary changes",!model.connected && !model.tunnelTransitioning && m.connection.stops==1 && !m.isOnDemandEnabled)
    let temporary=(m.protocolConfiguration as! NETunnelProviderProtocol).copy() as! NETunnelProviderProtocol
    temporary.providerConfiguration=["engine":"external-libbox","mode":"external-tor","bundle":try JSONSerialization.data(withJSONObject:["selectedRouterID":"temporary","routerProfiles":[["id":"temporary","node_kind":"external","external":["protocol":"tor"]]]]),IOSSpeedLabContext.ownerKey:owner.uuidString]
    m.protocolConfiguration=temporary;try m.connection.startVPNTunnel();await model.refreshTunnelStatus()
    try await IOSSpeedLabTunnel.stopTemporary(model:model,owner:owner)
    check("temporary native owner stops before original restore",m.connection.stops==2 && !model.connected)
    try await captured.restore(model:model,owner:owner,reconnect:true)
    let after=model.activeSessionIdentity!,restored=m.protocolConfiguration as! NETunnelProviderProtocol
    check("exact source and predecessor survive restoration",after.bundleData==before.bundleData && after.entryBundleData==before.entryBundleData && after.entryMode==before.entryMode)
    check("fresh proof keeps exact original raw runtime",after.rawProfile==raw && after.engine==engine && after.connectedAt != before.connectedAt)
    check("MTU hold reaches restored native start",m.connection.hold==String(repeating:"a",count:32))
    check("On Demand cannot create an unheld original startup",m.connection.starts==2)
    check("route lockdown and reconnect policy restored",restored.includeAllNetworks && restored.enforceRoutes && !restored.excludeLocalNetworks && m.isOnDemandEnabled && m.onDemandRules?.first?.ssidMatch==["original-network"])
    if strategy {
     let plan=restored.providerConfiguration!["strategy"] as! [String:Any]
     check("SMART/AUTO restoration cannot reselect a different raw mode",plan["kind"] as? String=="manual" && (plan["candidates"] as? [[String:Any]])?.count==1 && ((plan["candidates"] as? [[String:Any]])?.first?["raw"] as? String)==raw)
    }
    if engine=="multihop-libbox" || raw=="external-shadowsocks" {
     let source=try IOSMultihopExecution.Source(configuration:restored.providerConfiguration!,digest:RouterVPNModel.iosStrategyDigest)
     check("restoration keeps actual server winner without changing Compare preference",m.connection.execution=="server" && source.requested=="auto" && restored.providerConfiguration?[IOSMultihopExecution.launchKey]==nil)
    }
   }
  }
  for mutation in ["entry","source","date","ambiguous"]{
   let(model,m,owner)=try fresh("external-libbox","external-tor",false,true)
   let snapshot=try await IOSSpeedLabTunnel.capture(model:model,owner:owner)
   if mutation=="date"{m.connection.connectedDate=Date(timeIntervalSince1970:99)}
   else if mutation=="ambiguous"{NETunnelProviderManager.stored.append(m)}
   else{(m.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration?[mutation=="entry" ? "tor_entry_bundle":"bundle"]=Data("replacement".utf8)}
   await rejected("changed native owner cannot be stopped "+mutation){try await snapshot.stopOriginal(model:model,owner:owner)}
   check("replacement was not stopped "+mutation,m.connection.stops==0)
  }
  for (engine,raw) in [("multihop-libbox","hysteria2"),("external-libbox","external-shadowsocks")] { for invalid in ["winner","health","epoch"]{
   let(model,m,owner)=try fresh(engine,raw,false,true)
   let captured=try await IOSSpeedLabTunnel.capture(model:model,owner:owner)
   if invalid=="winner"{m.connection.execution="local"}
   if invalid=="health"{IOSMTUControl.healthy=false}
   if invalid=="epoch"{m.connection.epoch=UUID().uuidString}
   await rejected("changed actual multihop owner prevents pause "+invalid){try await captured.stopOriginal(model:model,owner:owner)}
   check("changed multihop owner is not stopped "+invalid,m.connection.stops==0)
  }}
  do{
   let(model,m,owner)=try fresh();let snapshot=try await IOSSpeedLabTunnel.capture(model:model,owner:owner)
   NETunnelProviderManager.hook={_ = model.iosSpeedLabOwnership.admit(.disconnect)}
   await rejected("Disconnect during preference save supersedes original stop"){try await snapshot.stopOriginal(model:model,owner:owner)}
   check("late original stop cannot touch new user owner",m.connection.stops==0)
  }
  do{
   let(model,m,owner)=try fresh();let snapshot=try await IOSSpeedLabTunnel.capture(model:model,owner:owner)
   try await snapshot.stopOriginal(model:model,owner:owner)
   _=model.iosSpeedLabOwnership.admit(.disconnect)
   try await snapshot.restore(model:model,owner:owner,reconnect:false)
   check("Disconnect restores selection without reconnect or on-demand",m.connection.starts==0 && !m.isOnDemandEnabled && (m.onDemandRules ?? []).isEmpty)
  }
  do{
   let(model,m,owner)=try fresh();let snapshot=try await IOSSpeedLabTunnel.capture(model:model,owner:owner)
   try await snapshot.stopOriginal(model:model,owner:owner);IOSMTUMeasurementGate.current=""
   await rejected("restore refuses missing measurement hold"){try await snapshot.restore(model:model,owner:owner,reconnect:true)}
   check("missing hold never starts VPN",m.connection.starts==0)
  }
  do{
   let(model,m,owner)=try fresh();let snapshot=try await IOSSpeedLabTunnel.capture(model:model,owner:owner)
   try await snapshot.stopOriginal(model:model,owner:owner);m.connection.failedProof=true
   await rejected("restoration requires fresh native proof"){try await snapshot.restore(model:model,owner:owner,reconnect:true)}
   check("unproved source is not connected",!model.connected && model.activeSessionIdentity==nil)
  }
  print("Apple Speed Lab native capture/restoration: PASS (\(checks) shipping Swift checks; system handles substituted)")
 }
}
'''

def main():
    swift=shutil.which('swiftc')
    if not swift:raise SystemExit('swiftc required')
    wire=(APP/'IOSStrategySession.swift').read_text().split('#if canImport(NetworkExtension)',1)[0]
    source=(APP/'IOSSpeedLabTunnel.swift').read_text().replace('@preconcurrency import NetworkExtension','')
    source=source.replace('ProcessInfo.processInfo.systemUptime','FixtureClock.now')
    with tempfile.TemporaryDirectory(prefix='routervpn-speed-native-') as folder:
        path=Path(folder)/'test.swift';binary=Path(folder)/'test'
        path.write_text(SHIM+'\n'+(APP/'IOSMultihopExecution.swift').read_text()+'\n'+(APP/'IOSSpeedLabOwnership.swift').read_text()+'\n'+(APP/'IOSSessionIdentity.swift').read_text()+'\n'+wire+'\n'+source)
        subprocess.run([swift,'-swift-version','6','-parse-as-library',str(path),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=30)

if __name__=='__main__':main()
