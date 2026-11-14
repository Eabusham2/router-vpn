#!/usr/bin/env python3
"""Execute the shipping CONNECT provider callback with explicit engine/OS boundaries.

The retained engine is separately compiled by test_ios_libbox_delivery. This
fixture executes the actual provider method; it claims no native TUN traffic.
"""
from pathlib import Path
import subprocess
import tempfile
import test_ios_startup_policy as S
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift'
BOUNDARY=r'''
import Foundation
func issue()->NSError{NSError(domain:"ProviderBoundary",code:1)}
final class Plan {var closes=0;func close()throws{closes+=1}}
final class IOSNodeChainCONNECTCapture {let plan=Plan();let strict=true,homeLANAccess=false;var finalProfile:[String:Any]=["node_proof_id":"original-proof"]}
enum IOSNodeChainCapture {static func issue(_ value:String)->NSError{NSError(domain:"Provider",code:1,userInfo:[NSLocalizedDescriptionKey:value])}}
final class NETunnelProviderProtocol {var includeAllNetworks=true,enforceRoutes=true,excludeLocalNetworks=false}
final class PathGuard {}
final class Boundary:@unchecked Sendable {static let shared=Boundary();var fault="";var created=0;var latest:RouterVPNLibboxEngine?}
final class RouterVPNLibboxEngine {
 weak var tunnel:PacketTunnelProvider?;var capture:IOSNodeChainCONNECTCapture?,callback:((Error?)->Void)?
 var stops=0,performance=0,mtu=0,ownsNodeChain=false
 init(tunnel:PacketTunnelProvider){self.tunnel=tunnel;Boundary.shared.created+=1;Boundary.shared.latest=self}
 func prepareMTUHold(_ value:Bool)throws{if Boundary.shared.fault=="hold-error"{throw issue()}}
 func start(nodeChainCONNECT capture:IOSNodeChainCONNECTCapture)throws{
  self.capture=capture;ownsNodeChain=true
  if Boundary.shared.fault=="start-error"{ownsNodeChain=false;throw issue()}
  if Boundary.shared.fault=="retained-start-error"{throw issue()}
 }
 func stop(){stops+=1;if Boundary.shared.fault != "retained-start-error"{ownsNodeChain=false}}
 func completeNodeChainCONNECT(_ callback:@escaping(Error?)->Void){self.callback=callback}
 func activatePerformance()throws{performance+=1;if Boundary.shared.fault=="performance-error"{throw issue()}}
 func activateNodeChainCONNECTMTU()throws{
  mtu+=1
  if Boundary.shared.fault=="mtu-error"{throw issue()}
  if Boundary.shared.fault=="mtu-generation"{tunnel?.generation=UUID()}
  if Boundary.shared.fault=="mtu-path"{tunnel?.path=PathGuard()}
 }
}
final class PacketTunnelProvider {
 var protocolConfiguration:Any=NETunnelProviderProtocol(),generation=UUID(),path=PathGuard(),initialMTUHold=false
 var libboxEngine:RouterVPNLibboxEngine?,forwarded=0
 func currentMAXGeneration(_ value:UUID)->Bool{generation==value}
 func armNetworkProofGuard()->PathGuard{path}
 func currentPathProofGuard()->PathGuard{path}
 func enableForwarding(profileData:Data,proofID:String,captured:PathGuard){
  precondition(proofID=="original-proof" && captured===path && !profileData.isEmpty)
  forwarded+=1
  if Boundary.shared.fault=="forward-generation"{generation=UUID()}
 }
 // SHIPPING_PROVIDER
}
@main struct Main {
 static func main(){do{try run()}catch{FileHandle.standardError.write(Data(("FAIL: \(error.localizedDescription)\n").utf8));exit(1)}}
 static func require(_ good:Bool,_ message:String)throws{if !good{throw NSError(domain:"ProviderCheck",code:1,userInfo:[NSLocalizedDescriptionKey:message])}}
 static func run()throws{
  let faults=["success","route-policy","initial-generation","hold-error","start-error","retained-start-error","proof-error","proof-generation","proof-owner","proof-path","performance-error","mtu-error","mtu-generation","mtu-path","forward-generation"]
  var checks=0
  for fault in faults {
   Boundary.shared.fault=fault;Boundary.shared.created=0;Boundary.shared.latest=nil
   let provider=PacketTunnelProvider(),capture=IOSNodeChainCONNECTCapture(),generation=provider.generation
   var callbacks=0,failures=0,thrown=false
   if fault=="route-policy"{(provider.protocolConfiguration as! NETunnelProviderProtocol).includeAllNetworks=false}
   if fault=="initial-generation"{provider.generation=UUID()}
   do{try provider.startNodeChainCONNECT(capture,generation:generation){error in callbacks+=1;if error != nil{failures+=1}}}catch{thrown=true}
   let early=["route-policy","initial-generation","hold-error","start-error","retained-start-error"].contains(fault)
   if early {
    try require(thrown && callbacks==0 && provider.forwarded==0,"early original provider boundary "+fault)
    try require(capture.plan.closes==(fault=="retained-start-error" ? 0:1),"original retained capture ownership "+fault)
    if fault=="retained-start-error"{try require(provider.libboxEngine?.ownsNodeChain==true,"failed native bind owner retained")}
   } else {
    let owner=provider.libboxEngine!
    try require(!thrown && callbacks==0 && provider.forwarded==0 && owner.mtu==0 && Boundary.shared.created==1,"proof must precede delivery and one native engine")
    if fault=="proof-generation"{provider.generation=UUID()}
    if fault=="proof-path"{provider.path=PathGuard()}
    if fault=="proof-owner"{provider.libboxEngine=RouterVPNLibboxEngine(tunnel:provider)}
    owner.callback?(fault=="proof-error" ? issue():nil)
    try require(callbacks==1 && failures==(fault=="success" ? 0:1),"original callback result "+fault)
    try require(provider.forwarded==(["success","forward-generation"].contains(fault) ? 1:0),"stale provider cannot forward "+fault)
    try require(fault=="success" ? owner.stops==0:owner.stops>0,"original native cleanup requested "+fault)
    try require(capture.plan.closes==0,"provider must not close transferred native capture")
   }
   checks+=1
  }
  print("Apple typed CONNECT provider: PASS (\(checks) actual callback scenarios; engine and NetworkExtension doubled)")
 }
}
'''
def main():
    original=S.member(SOURCE.read_text(),'    private func startNodeChainCONNECT(')
    method=original.replace('private func','func',1)
    with tempfile.TemporaryDirectory(prefix='ios-connect-provider-') as folder:
        work=Path(folder);source=work/'Provider.swift';binary=work/'test'
        def run(value):
            source.write_text(BOUNDARY.replace('// SHIPPING_PROVIDER',value))
            subprocess.run(['swiftc','-j','1','-swift-version','6','-parse-as-library',str(source),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
        result=run(method);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        for name,before,after,witness in (
            ('route-policy','proto.includeAllNetworks == capture.strict','true','early original provider boundary route-policy'),
            ('proof-result','if let failure { engine.stop(); completionHandler(failure); return }','_ = failure','original callback result proof-error'),
            ('transferred-owner','adopted = engine.ownsNodeChain','adopted = false','original retained capture ownership retained-start-error'),
        ):
            assert method.count(before)==1,name
            rejected=run(method.replace(before,after,1))
            assert rejected.returncode!=0 and witness in rejected.stdout+rejected.stderr,(name,rejected.stdout,rejected.stderr)
            print('Rejected CONNECT provider control: '+name)
if __name__=='__main__':main()
