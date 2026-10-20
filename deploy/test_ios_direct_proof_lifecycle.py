#!/usr/bin/env python3
"""Execute the shipping direct-runtime callbacks with deterministic OS boundaries.

No network, VPN or device is started. WireGuard/Libbox handles are doubles;
the callback bodies and captured-guard cleanup are the actual provider source.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
PROVIDER=ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift'
PRELUDE=r'''
import Foundation

@MainActor final class WireGuardAdapter {
 enum Level {case error}
 var startCallback: ((Error?)->Void)?
 var stopCallback: ((Error?)->Void)?
 var deferStop=false
 var stops=0
 init(with owner:PacketTunnelProvider,log:@escaping (Level,String)->Void){}
 func start(tunnelConfiguration:String,completionHandler:@escaping(Error?)->Void){startCallback=completionHandler}
 func stop(completionHandler:@escaping(Error?)->Void){stops += 1;if deferStop {stopCallback=completionHandler}else{completionHandler(nil)}}
}
@MainActor final class RouterVPNLibboxEngine {
 static let proofProxyPort=1099
 let owner:PacketTunnelProvider
 var stops=0
 var started=false
 var externalStarted=false
 var measurements:[String]=[]
 var externalMTU=0
 var held=""
 init(tunnel:PacketTunnelProvider){owner=tunnel}
 func prepareMTUHold(_ value:String)throws{held=value}
 func start(files:[String:Data],strict:Bool)throws{started=true}
 func start(files:[String:Data],strict:Bool,externalPolicy:String)throws{started=true;externalStarted=true}
 func stop(){stops += 1;started=false}
 func proveTor(sessionID:String,predecessorProfile:String?,completion:@escaping(Error?)->Void){precondition(owner.pathProofGuard != nil);owner.torSession=sessionID;owner.proofCallback=completion}
 func proveExternal(completion:@escaping(Error?)->Void){precondition(owner.pathProofGuard != nil && externalStarted);owner.nativeExternalProof=true;owner.proofCallback=completion}
 func enableExternalHopMeasurement(exitID:String)throws{precondition(owner.pathProofGuard != nil);measurements.append(exitID);owner.duringMeasurement?();if owner.measurementFails{throw NSError(domain:"MeasurementFixture",code:1)}}
 func activateExternalMTU()throws{precondition(owner.pathProofGuard != nil && externalStarted && !measurements.isEmpty);externalMTU += 1;owner.duringMTU?();if owner.mtuFails{throw NSError(domain:"MTUFixture",code:1)}}
}
enum IOSStartLayer {static func validateExternal(profile:[String:Any])throws{};static func selectedMode(profile:[String:Any])throws->String{"off"}}
enum RouterVPNExternalExitBuilder {
 static let torEntryModes:Set<String>=["wg"]
 static let ordinaryProtocols:Set<String>=["wireguard","socks5","http-connect","https-connect","shadowsocks","hysteria2"]
 struct Runtime {let expectedPublicIP="203.0.113.1";let files:[String:Data]=["sing-box.json":Data("{}".utf8)];var torSessionID:String?;var torPredecessorProfile:String?;var policy:String?}
 static func build(profile:[String:Any],predecessorFiles:[String:Data],predecessorProfile:[String:Any]?)throws->Runtime{Runtime(torSessionID:profile["tor"] as? Bool == true ? "captured-tor-session":nil,policy:profile["native"] as? Bool == true ? "captured-policy":nil)}
}
enum RouterVPNMTUPolicy {static func libbox(_ files:[String:Data],profile:[String:Any])throws->[String:Data]{files}}
final class NETunnelProviderProtocol {var includeAllNetworks=true;var enforceRoutes=true;var excludeLocalNetworks=true}
@MainActor final class NetworkProofGuard {}
@MainActor final class Monitor {var cancelled=false;func cancel(){cancelled=true}}
@MainActor final class PacketTunnelProvider {
 static let maxBundleBytes=32*1024*1024
 var protocolConfiguration:Any?=NETunnelProviderProtocol()
 var wireGuardAdapter:WireGuardAdapter?
 var libboxEngine:RouterVPNLibboxEngine?
 var pathProofGuard:NetworkProofGuard?
 var pathMonitor:Monitor?
 var pathProofOwnerLock=NSLock()
 var initialMTUHold="test-comparison-lease"
 var proofCallback:((Error?)->Void)?
 var torSession:String?
 var nativeExternalProof=false
 var duringMeasurement:(()->Void)?,measurementFails=false
 var duringMTU:(()->Void)?,mtuFails=false
 var arms=0
 var forwarded=0
 var duringForwarding:(()->Void)?
 func tunnelError(_ code:Int,_ message:String)->NSError{NSError(domain:"RouterVPN.Test",code:code,userInfo:[NSLocalizedDescriptionKey:message])}
 func armNetworkProofGuard()->NetworkProofGuard{arms += 1;pathMonitor?.cancel();pathMonitor=Monitor();let value=NetworkProofGuard();pathProofGuard=value;return value}
 func currentPathProofGuard()->NetworkProofGuard?{pathProofGuard}
 func enableForwarding(profileData:Data,proofID:String){forwarded += 1;duringForwarding?()}
 func proveSelectedNode(url:URL,expectedNodeID:String,proxyPort:Int?,completionHandler:@escaping(Error?)->Void){precondition(pathProofGuard != nil);proofCallback=completionHandler}
 func proveExternalExit(expectedPublicIP:String,proxyPort:Int,completion:@escaping(Error?)->Void){precondition(pathProofGuard != nil);proofCallback=completion}
 func beginExternal(tor:Bool=false,native:Bool=false,_ done:@escaping(Error?)->Void)throws{try startExternalLibbox(provider:[:],selectedProfile:["id":"saved-exit","tor":tor,"native":native,"external":["protocol":tor ? "tor":"socks5"]],strict:true,completionHandler:done)}
 func strictKillSwitchRequested(_ profile:[String:Any])->Bool{profile["strict"] as? Bool == true}
 func selectedRouterProfile(_ root:[String:Any])throws->[String:Any]{root}
 func suppliedNodeProof(root:[String:Any],selectedProfile:[String:Any])throws->String{String(repeating:"a",count:64)}
 func multihopWireGuardEndpoint(root:[String:Any],expectedProofID:String,name:String)throws->(endpoint:[String:Any],dns:[String]){(["type":"wireguard"],[])}
 struct Compilation {let files:[String:Data]=["sing-box.json":Data("{}".utf8)]}
 func compileLibbox(provider:[String:Any],root:[String:Any],selectedProfile:[String:Any])throws->Compilation{Compilation()}
 func beginRaw(_ completionHandler:@escaping(Error?)->Void){
  let tunnelConfiguration="fixture"
  let proofURL=URL(string:"http://10.77.0.1:8787/health")!
  let expectedNodeID=String(repeating:"a",count:64)
  let forwardingProfileData=Data("{}".utf8)
'''
TEST=r'''
}
@main struct Main {
 @MainActor static func main()throws {
  var checks=0
  func check(_ name:String,_ test:Bool){if !test{fatalError(name)};checks += 1}
  let failure=NSError(domain:"Fixture",code:1)
  for kind in ["raw","external","native-external","tor"] {
   for event in ["stable","network","proof-error","replacement","stop","forwarding-change","measurement-change","measurement-error","mtu-change","mtu-error"] {
    if kind != "raw" && event=="forwarding-change"{continue}
    if ["measurement-change","measurement-error"].contains(event) && !["native-external","tor"].contains(kind){continue}
    if ["mtu-change","mtu-error"].contains(event) && kind != "native-external"{continue}
    let p=PacketTunnelProvider();var replies:[Error?]=[]
    if kind=="raw"{p.beginRaw{replies.append($0)};p.wireGuardAdapter!.startCallback!(nil)}
    else {try p.beginExternal(tor:kind=="tor",native:kind=="native-external"){replies.append($0)}}
    let adapter=p.wireGuardAdapter,engine=p.libboxEngine,guardState=p.pathProofGuard,monitor=p.pathMonitor
    check("guard already armed before proof",p.arms==1 && guardState != nil && p.proofCallback != nil && replies.isEmpty)
    if kind != "raw"{check("MTU comparison owner held before proof",engine!.held==p.initialMTUHold && engine!.started)}
    if kind=="tor"{check("Tor uses the captured dynamic proof request",p.torSession=="captured-tor-session")}
    if kind=="native-external"{check("ordinary node requires native DNS/node proof",p.nativeExternalProof && engine!.externalStarted)}
    if event=="network" || event=="stop"{p.pathProofGuard=nil}
    if event=="stop"{p.wireGuardAdapter=nil;p.libboxEngine=nil}
    if event=="replacement"{
     _=p.armNetworkProofGuard()
     if kind=="raw"{p.wireGuardAdapter=WireGuardAdapter(with:p,log:{_,_ in})}
     else {p.libboxEngine=RouterVPNLibboxEngine(tunnel:p)}
    }
    if event=="forwarding-change"{p.duringForwarding={p.pathProofGuard=nil}}
    if event=="measurement-change"{p.duringMeasurement={p.pathProofGuard=nil}}
    if event=="measurement-error"{p.measurementFails=true}
    if event=="mtu-change"{p.duringMTU={p.pathProofGuard=nil}}
    if event=="mtu-error"{p.mtuFails=true}
    let nextGuard=p.pathProofGuard,nextMonitor=p.pathMonitor,nextEngine=p.libboxEngine,nextAdapter=p.wireGuardAdapter
    p.proofCallback!(event=="proof-error" ? failure:nil)
    check("one terminal proof result",replies.count==1)
    if event=="stable"{
     check("stable proof succeeds",replies[0]==nil)
     check("success retains the original guard",p.pathProofGuard===guardState && p.arms==1 && monitor?.cancelled==false)
     check("successful engine retained",kind=="raw" ? adapter?.stops==0 : engine?.stops==0)
     check("forwarding only for verified owned home",p.forwarded==(kind=="raw" ? 1:0))
     if ["native-external","tor"].contains(kind){check("measurement activation follows native proof and frozen exit",engine?.measurements==["saved-exit"])}
     if kind != "raw"{check("ordinary external MTU activates under final network guard",engine?.externalMTU==(kind=="native-external" ? 1:0))}
    }else{
     check("stale proof never becomes Connected",replies[0] != nil)
     check("only original engine stopped",kind=="raw" ? adapter?.stops==1 : engine?.stops==1)
     if event != "forwarding-change"{check("failed proof does not enable forwarding",p.forwarded==0)}
     if event=="proof-error"{check("failed proof releases own monitor",p.pathProofGuard==nil && p.pathMonitor==nil && monitor?.cancelled==true)}
     if event=="replacement"{
      check("replacement network guard survives",p.pathProofGuard===nextGuard && p.pathMonitor===nextMonitor && nextMonitor?.cancelled==false)
      check("replacement engine is not cleared or stopped",kind=="raw" ? (p.wireGuardAdapter===nextAdapter && nextAdapter?.stops==0):(p.libboxEngine===nextEngine && nextEngine?.stops==0))
     }
    }
   }
  }
  // Stop completion can arrive after a new raw runtime has become owner.
  let p=PacketTunnelProvider();var replies:[Error?]=[]
  p.beginRaw{replies.append($0)};let old=p.wireGuardAdapter!;old.startCallback!(nil);old.deferStop=true
  p.proofCallback!(failure);check("deferred cleanup owns its old adapter",replies.isEmpty && old.stops==1)
  let new=WireGuardAdapter(with:p,log:{_,_ in});p.wireGuardAdapter=new;let generation=p.armNetworkProofGuard()
  old.stopCallback!(nil)
  check("old stop callback cannot clear a new owner",p.wireGuardAdapter===new && new.stops==0 && p.pathProofGuard===generation && replies.count==1 && replies[0] != nil)
  // Direct guard release is compare-and-clear, not an unconditional invalidation.
  let retired=NetworkProofGuard(),current=p.pathProofGuard,monitor=p.pathMonitor
  p.testRelease(retired)
  check("old proof cleanup leaves the current monitor",p.pathProofGuard===current && p.pathMonitor===monitor && monitor?.cancelled==false)
  print("Shipping raw/external proof callbacks: PASS (\(checks) executable lifecycle checks; OS handles doubled)")
 }
}
'''

def method(source,name):
    prefix='    private func '+name+'('
    start=source.index(prefix)
    end=source.find('\n    private func ',start+1)
    if end<0:raise ValueError('Method boundary changed: '+name)
    return source[start:end]

def main():
    source=PROVIDER.read_text()
    raw=method(source,'startWireGuard')
    tail=raw[raw.index('        let adapter = WireGuardAdapter(with: self)'):]
    external=method(source,'startExternalLibbox')
    # The next method has an annotation; do not accidentally capture it.
    external=external.split('\n    @discardableResult',1)[0]
    release=method(source,'releasePathProofGuard')
    text=PRELUDE+tail+'\n'+external+'\n'+release+'\n func testRelease(_ value:NetworkProofGuard){releasePathProofGuard(value)}\n'+TEST
    with tempfile.TemporaryDirectory(prefix='router-direct-proof-') as temporary:
        path=Path(temporary);code=path/'main.swift';code.write_text(text);binary=path/'tests'
        subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(code),'-o',str(binary)],check=True,timeout=30)
        subprocess.run([str(binary)],check=True,timeout=10)

if __name__=='__main__':main()
