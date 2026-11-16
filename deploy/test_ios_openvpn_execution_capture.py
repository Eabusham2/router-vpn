#!/usr/bin/env python3
"""Run the Apple OpenVPN execution consumers against the actual shared compiler.

The original independent provider pairs come from the shared Server-plan
fixture. Native Run, TUN, traffic and connected receipts are refusing boundaries.
"""
from pathlib import Path
import json
import os
import subprocess
import tempfile

import test_ios_socks_execution_capture as S

ROOT = Path(__file__).resolve().parents[1]
E = S.E
FIXTURE = r'''
func openVPNFixture(_ mode:String,_ network:String,_ requested:String,_ count:Int,_ layer:String="off")throws->[Data]{
 guard let path=ProcessInfo.processInfo.environment["ROUTER_VPN_APPLE_OPENVPN_FIXTURES"] else {throw NSError(domain:"MissingOriginalOpenVPNFixtures",code:1)}
 let cases=try object(Data(contentsOf:URL(fileURLWithPath:path)))
 guard let row=cases["\(count)/\(mode)/\(network)/\(layer)"] as? [String:Any],let values=row["bundles"] as? [Any],values.count==count else {throw NSError(domain:"MissingOriginalOpenVPNCase",code:1)}
 // The shared provider fixture has no Router control-plane fields. Supply
 // the app model's required empty values without inventing admin authority.
 let originals=try values.map{try data($0)}
 let modeled=try originals.map{value in try editProfile(value){p in
  if p["node_kind"] as? String=="external" {
   for key in ["router_api","api_token","adguard_ipv4"]{if p[key]==nil{p[key]=""}}
  }
 }}
 var bundles=try appFixture(modeled)
 bundles[count-1]=try editProfile(bundles[count-1]){$0["multihop_execution"]=requested}
 return bundles
}
'''
SWIFT = E.SWIFT[:E.SWIFT.index('@main struct Tests')] + FIXTURE + r'''
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ yes:Bool,_ message:String){checks+=1;if !yes{print("FAIL "+message);exit(1)}}
 @MainActor static func reject(_ name:String,_ run:()throws->Void){do{try run();print("FAIL ACCEPTED "+name);exit(1)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  guard CommandLine.arguments.count==3,let count=Int(CommandLine.arguments[2]),(3...8).contains(count) else {fatalError("missing original OpenVPN prefix phase")}
  for mode in ["wg","awg2-fast","awg2-strong","mixed"] {for network in ["tcp","udp"] {for requested in ["server","auto"] {
   try original(mode,network,requested,count,"off")
  }}}
  for layer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {for requested in ["server","auto"] {
   try original("mixed","udp",requested,count,layer)
  }}
  let bundles=try openVPNFixture("mixed","tcp","auto",count)
  for operation in ["local-new","execution-new"] {
   LibboxTestReturnedOwnerError(operation)
   reject("returned OpenVPN object plus error "+operation){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")}
   check(LibboxTestReturnedOwnerClosed(),"returned original OpenVPN owner was not closed exactly once: "+operation)
  }
  let original=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")
  LibboxTestReturnedOwnerError("execution-open")
  reject("returned OpenVPN replay plus error"){_ = try IOSNodeChainExecutionCapture.reopen(original.launchInput,selectedProfile:profile(bundles[count-1]))}
  check(LibboxTestReturnedOwnerClosed(),"returned original OpenVPN owner was not closed exactly once: execution-open")
  try original.close()
  for fault in ["config","requested","local-node","local-schema","local-identity","local-execution","preparation-schema","launch-schema","launch-error","openvpn-local-launch"] {
   LibboxTestExecutionFault(fault);reject("typed native readback "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")}
  }
  for fault in ["missing-pair","invalid-pair-key","shared-provider","endpoint","layer","order"] {
   var invalid=bundles
   if fault=="order"{invalid.swapAt(0,count-2)}
   else{invalid[count-2]=try editProfile(invalid[count-2]){p in
    if fault=="endpoint"{p["endpoint"]="203.0.113.99"}
    if fault=="layer"{p["start_layer"]="aes-256-gcm"}
    var external=p["external"] as! [String:Any]
    if fault=="missing-pair"{external.removeValue(forKey:"openvpn_pairing")}
    if fault=="invalid-pair-key"{var pair=external["openvpn_pairing"] as! [String:Any];pair["private_key"]="invalid-original-key";external["openvpn_pairing"]=pair}
    if fault=="shared-provider"{var provider=external["openvpn"] as! [String:Any];provider["username"]="original-server-provider";external["openvpn"]=provider}
    p["external"]=external
   }}
   reject("original OpenVPN source "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:invalid,requested:"auto")}
  }
  for position in 0..<count-2 {
   var invalid=bundles;invalid[position]=try editProfile(invalid[position]){$0["node_proof_id"]=String(repeating:"f",count:64)}
   reject("original packet prefix identity \(position)"){_ = try IOSNodeChainExecutionCapture.compile(bundles:invalid,requested:"auto")}
  }
  for modes in [["openvpn","shadowsocks"],["wg","openvpn","hysteria2"],["wg","hysteria2","openvpn","shadowsocks"],["wg","openvpn","wg","shadowsocks"],["wg","socks5","shadowsocks"],Array(repeating:"wg",count:7)+["openvpn","shadowsocks"]] {
   let nodes=modes.enumerated().map{IOSMultihopNodeSelection(id:"original-\($0.offset)",mode:$0.element)}
   check(!IOSMultihopNodeSelection.supportsOpenVPNExecution(nodes),"OpenVPN public choice refuses malformed member roles")
  }
  print("PASS Apple OpenVPN execution source nodes=\(count): \(checks) original source and consumer checks")
 }
 @MainActor static func original(_ mode:String,_ network:String,_ requested:String,_ count:Int,_ layer:String)throws{
  let bundles=try openVPNFixture(mode,network,requested,count,layer)
  let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested);defer{try? capture.close()}
  let source=try object(Data(capture.source.utf8)),launch=try object(Data(capture.launchInput.utf8)),local=try object(Data((source["local_source"] as! String).utf8))
  check(capture.isOpenVPN && !capture.isSOCKS && !capture.isCONNECT && source["schema"] as? Int==5 && source["execution"] as? String==requested,"original OpenVPN preparation family and selection")
  check(launch["kind"] as? String=="routervpn-node-chain-openvpn-execution-preparation-input" && launch["schema"] as? Int==1,"distinct OpenVPN execution launch")
  let prefixes=(0..<count-2).map{mode=="mixed" ? ["wg","awg2-fast","awg2-strong"][$0%3]:mode}
  check(capture.members.map(\.mode)==prefixes+["openvpn","shadowsocks"],"every original OpenVPN path transport retained")
  check((local["identity_sources"] as! [String]).enumerated().allSatisfy{$0.offset==count-2 ? $0.element.isEmpty:!$0.element.isEmpty},"OpenVPN provider cannot borrow paired packet identity")
  let encoded=try object(Data((local["nodes"] as! [String])[count-2].utf8)),saved=try object(Data((encoded["capture"] as! String).utf8))["profile"]!
  check(try data(saved)==data(profile(bundles[count-2])),"original OpenVPN credentials, private pair and policy")
  check(!capture.config.contains("server-private-password") && !capture.healthy() && !capture.nativeClosed(),"Local private configuration has no Server credentials or fabricated proof")
  check(capture.finalProfile["startup_mode"]==nil && capture.finalProfile["auto_connect"]==nil,"OpenVPN source only projects startup scheduling")
  let replay=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles[count-1]));defer{try? replay.close()}
  check(replay.isOpenVPN && replay.launchInput==capture.launchInput && replay.source==capture.source,"canonical complete OpenVPN replay")
  let typed=try JSONDecoder().decode(ClientBundle.self,from:bundles[count-1]).routerProfiles[0]
  check(IOSMultihopNodeSelection.supportsOpenVPNExecution(typed.multihopNodes!) && !IOSMultihopNodeSelection.supportsSOCKSExecution(typed.multihopNodes!) && !IOSMultihopNodeSelection.supportsCONNECTExecution(typed.multihopNodes!) && !IOSMultihopNodeSelection.supportsGenericExecution(typed.multihopNodes!),"distinct public OpenVPN choice")
  reject("generic source cannot borrow OpenVPN preparation"){_ = try IOSNodeChainCapture.compileOriginalForExecution(bundles:bundles,requested:requested)}
  var failure:NSError?
  check(LibboxNewRouterNodeChainExecutionLaunch(capture.launchInput,&failure)==nil && failure != nil,"generic parser cannot borrow OpenVPN launch")
  failure=nil;check(LibboxNewRouterNodeChainSOCKSExecutionLaunch(capture.launchInput,&failure)==nil && failure != nil,"SOCKS parser cannot borrow OpenVPN launch")
  failure=nil;check(LibboxNewRouterNodeChainCONNECTExecutionLaunch(capture.launchInput,&failure)==nil && failure != nil,"CONNECT parser cannot borrow OpenVPN launch")
  let original=try IOSNodeChainCapture.compileOriginalForOpenVPNExecution(bundles:bundles,requested:requested);defer{try? original.plan.close()}
  let sealed=try object(Data(original.launchInput.utf8))
  check(sealed["kind"] as? String=="routervpn-node-chain-launch-input" && sealed["schema"] as? Int==5,"OpenVPN execution keeps the sealed original Local envelope")
  check(Set(source.keys)==Set(["schema","execution","local_source","openvpn_local_launch"]) && source["openvpn_local_launch"] as? String==original.launchInput,"OpenVPN preparation retains the exact original sealed launch")
  failure=nil;check(LibboxRouterNodeChainOpenVPNExecutionFromLaunch(source["local_source"] as! String,requested,&failure)==nil && failure != nil,"typed OpenVPN cannot replace a sealed input with plain source")
  let graph=try object(Data(original.config.utf8)),endpoints=graph["endpoints"] as! [[String:Any]],outbounds=graph["outbounds"] as! [[String:Any]],all=endpoints+outbounds
  let middle=endpoints.first{$0["type"] as? String=="openvpn-client"}!
  check(middle["username"] as? String==" captured user " && middle["password"] as? String==" captured secret " && middle["system"] as? Bool==false,"original OpenVPN provider credentials and owned packet endpoint")
  check(middle["network"] as? String==network && middle["servers"]==nil && middle["server"] as? String=="203.0.113.24" && middle["server_port"] as? Int==1194,"original single OpenVPN TCP or UDP remote")
  check(try capture.members.dropLast(2).allSatisfy{try IOSMultihopStartLayer.selected($0.profile)==layer} && IOSMultihopStartLayer.selected(capture.finalProfile)==layer,"OpenVPN preserves independent prefix and final Start Layers")
  let route=graph["route"] as! [String:Any],finalTag=route["final"] as! String
  let final=all.first{$0["tag"] as? String==finalTag}!
  check(final["udp_over_tcp"]==nil,"OpenVPN packet path does not borrow CONNECT UoT")
  let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles[count-1],entryBundleData:nil,nodeChainExecutionSource:Data(capture.launchInput.utf8))
  let nodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)},model=RouterVPNModel(nodes,identity:identity),fifty=try IOSOrderedLatencyCapture(model)
  check(fifty.source==capture.sourceSHA256 && fifty.config==capture.configSHA256 && fifty.ids==capture.members.map(\.id) && fifty.kinds==Array(repeating:"private-node",count:count-2)+["public-path","private-node"],"OpenVPN measurements retain complete original source and roles")
  check(IOSNodeChainPresentation.active(identity)?.map(\.id)==capture.members.map(\.id),"active OpenVPN path retains original identities")
  let changed=try editProfile(bundles[count-1]){$0["api_token"]="foreign-final-control"}
  reject("changed final private source"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(changed))}
  let stale=try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:changed,entryBundleData:nil,nodeChainExecutionSource:identity.nodeChainExecutionSource)
  check(IOSNodeChainPresentation.active(stale)==nil,"OpenVPN presentation rejects replaced final private source")
  try fifty.require(model);model.iosConnectGeneration=UUID();reject("OpenVPN latency replacement generation"){try fifty.require(model)}
 }
}
'''


def emit_fixtures(destination):
    environment = dict(os.environ, ROUTER_VPN_APPLE_OPENVPN_FIXTURES=str(destination))
    subprocess.run(['go', 'test', '-p', '1', '-count=1', '-timeout=90s',
                    '-run', '^TestEmitAppleOpenVPNExecutionFixtures$', './internal/mobilemultihop'],
                   cwd=ROOT, env=environment, check=True, timeout=180)
    values = json.loads(destination.read_text())
    assert len(values) == 144 and all(len(value['bundles']) == int(key.split('/')[0]) for key, value in values.items())


def main():
    with tempfile.TemporaryDirectory(prefix='ios-openvpn-execution-') as folder:
        destination = Path(folder) / 'original-provider-fixtures.json'
        emit_fixtures(destination)
        previous = os.environ.get('ROUTER_VPN_APPLE_OPENVPN_FIXTURES')
        os.environ['ROUTER_VPN_APPLE_OPENVPN_FIXTURES'] = str(destination)
        try:
            S.main(swift=SWIFT, family='OpenVPN')
        finally:
            if previous is None:
                os.environ.pop('ROUTER_VPN_APPLE_OPENVPN_FIXTURES', None)
            else:
                os.environ['ROUTER_VPN_APPLE_OPENVPN_FIXTURES'] = previous


if __name__ == '__main__':
    main()
