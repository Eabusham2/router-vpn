#!/usr/bin/env python3
"""Execute the shipping ordinary delivery/factory/retirement ownership seam; native/OS are doubled."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
BOUNDARY=r'''
import Foundation
func issue()->NSError{NSError(domain:"ordinary-fifty-boundary",code:1)}
func LibboxRouterValidatePrivateNodeJSON(_ raw:String,_ error:inout NSError?)->Bool{(try? JSONSerialization.jsonObject(with:Data(raw.utf8))) != nil}
final class LibboxRouterOrderedLatency{
 var closed=false,failClose=false,cancels=0
 func start(_ r:String,nodeID:String)throws{}
 func cancel(_ r:String){cancels+=1}
 func drain(_ r:String)throws{}
 func statusJSON()->String{"{}"}
 func savedJSON(_ n:String)->String{""}
 func close()throws{if failClose{throw issue()};closed=true}
}
final class LibboxCommandServer{}
final class LibboxRouterHopMeasurement{func networkChanged(){}}
final class LibboxRouterNodeChain{
 var count=3,imported=false,valid=true,server:LibboxCommandServer?,measurement:LibboxRouterHopMeasurement?,latest:LibboxRouterOrderedLatency?,factories=0,hook:(()->Void)?
 func run(_ server:LibboxCommandServer)throws{self.server=server}
 func healthy()->Bool{valid&&server != nil}
 func networkChanged(){valid=false}
 func sourceSHA256()->String{String(repeating:"a",count:64)}
 func configSHA256()->String{String(repeating:"b",count:64)}
 func progressJSON()->String{
  let prefixes=(0..<count).map{p -> [String:Any] in var r:[String:Any]=["position":p,"profile_id":"node-\(p)","proven":valid];if imported&&p==1{r["kind"]="public-path"};return r}
  return String(data:try! JSONSerialization.data(withJSONObject:["ready":valid,"complete":true,"execution":"local","prefixes":prefixes]),encoding:.utf8)!
 }
}
func LibboxRouterNodeChainNewHopMeasurement(_ plan:LibboxRouterNodeChain,_ server:LibboxCommandServer,_ error:inout NSError?)->LibboxRouterHopMeasurement?{
 guard plan.server===server,plan.healthy()else{error=issue();return nil};let probe=LibboxRouterHopMeasurement();plan.measurement=probe;return probe
}
func LibboxRouterNodeChainNewLatencyBenchmark(_ plan:LibboxRouterNodeChain,_ server:LibboxCommandServer,_ probe:LibboxRouterHopMeasurement,_ error:inout NSError?)->LibboxRouterOrderedLatency?{
 guard plan.server===server,plan.measurement===probe,plan.healthy()else{error=issue();return nil};let facade=LibboxRouterOrderedLatency();plan.latest=facade;plan.factories+=1;plan.hook?();return facade
}
final class MTU{
 var lease=String(repeating:"c",count:32),ready=true,held=true
 var proofObservationToken:Int?{1}
 func request(operation:String,request:String,session:String)->Data?{try! JSONSerialization.data(withJSONObject:["session_id":"mtu-original","measurement_lease":lease,"measurement_hold":held,"measurement_ready":ready])}
}
final class Platform{let mtu=MTU()}
final class Tunnel{func nativeLibboxFailure(_ engine:RouterVPNLibboxEngine,error:Error){}}
final class RouterVPNLibboxEngine{
 let ownershipLock=NSLock(),platform=Platform();var nodeChain:LibboxRouterNodeChain?,server:LibboxCommandServer?,ownershipGeneration=UUID(),permanentlyStopped=false,hopMeasurement:LibboxRouterHopMeasurement?,multihopHealth:DispatchSourceTimer?,tunnel:Tunnel?=nil
 private var nodeChainDelivery:NodeChainDelivery?
 func error(_ text:String)->NSError{issue()}
 init(_ count:Int,_ imported:Bool=false){let plan=LibboxRouterNodeChain();plan.count=count;plan.imported=imported;nodeChain=plan;server=LibboxCommandServer();let d=NodeChainDelivery(owner:self,plan:plan,server:server!,generation:ownershipGeneration,completion:{error in if let error{fatalError("ordinary delivery failed \(error)")}});nodeChainDelivery=d;d.run()}
 func info(_ r:RouterVPNOrderedLatencyRequest)throws->Data?{try nodeChainDelivery!.latencyInfo(r,session:"original-provider")}
 func open(_ r:RouterVPNOrderedLatencyRequest)throws->RouterVPNOrderedLatencyOwner{try nodeChainDelivery!.latencyOpen(r)}
 func close()throws{nodeChainDelivery!.cancel();try nodeChainDelivery!.closeLatency();multihopHealth?.cancel()}
 // DELIVERY
}
func request(_ n:Int,_ position:Int=0)->RouterVPNOrderedLatencyRequest{
 let v=["operation":"ordered-latency-open","request_id":String(format:"%032x",n),"owner":String(repeating:"d",count:32),"session_id":"00000000-0000-0000-0000-000000000001","lease":String(repeating:"c",count:32),"source_sha256":String(repeating:"a",count:64),"config_sha256":String(repeating:"b",count:64),"node_id":"node-\(position)"]
 return RouterVPNOrderedLatencyRequest.parse(try! JSONSerialization.data(withJSONObject:v))!
}
@main struct Tests{
 nonisolated(unsafe)static var checks=0
 static func check(_ ok:Bool,_ text:String){if !ok{fatalError(text)};checks+=1}
 static func reject(_ text:String,_ f:()throws->Void){do{try f();fatalError(text)}catch{checks+=1}}
 static func main()throws{
  for count in 2...8{
   let e=RouterVPNLibboxEngine(count),plan=e.nodeChain!,probe=e.hopMeasurement!,req=request(count)
   let info=try JSONSerialization.jsonObject(with:e.info(req)!) as! [String:Any],nodes=info["nodes"] as! [[String:Any]]
   check(nodes.count==count&&nodes.allSatisfy{$0["kind"] as? String=="private-node"},"ordinary proved private inventory")
   e.platform.mtu.ready=false;reject("ordinary busy MTU must precede factory"){_ = try e.open(req)};check(plan.factories==0,"busy factory was entered");e.platform.mtu.ready=true
   let owner:RouterVPNOrderedLatencyOwner;do{owner=try e.open(req)}catch{fatalError("ordinary factory lost original service")};let facade=plan.latest!;check(plan.measurement===probe&&e.hopMeasurement===probe&&plan.factories==1,"ordinary factory lost original service")
   reject("pending facade replacement"){_ = try e.open(request(20+count))}
   facade.failClose=true;reject("failed facade close retained"){try e.close()};check(!facade.closed&&facade.cancels>0,"retirement lost pending original")
   facade.failClose=false;try e.close();check(facade.closed&&owner.isClosed(),"retirement failed original join")
  }
  do{let e=RouterVPNLibboxEngine(3,true);let data=try JSONSerialization.jsonObject(with:e.info(request(40))!) as! [String:Any];let nodes=data["nodes"] as! [[String:Any]];check(nodes[1]["kind"] as? String=="public-path","SS2022 imported middle lost original kind");try e.close()}
  do{let e=RouterVPNLibboxEngine(2),p=e.nodeChain!;p.hook={e.ownershipGeneration=UUID()};reject("late factory adopted replacement owner"){_ = try e.open(request(50))};check(p.latest != nil,"late factory result not retained");try e.close();check(p.latest!.closed,"late factory original cleanup lost")}
  do{let e=RouterVPNLibboxEngine(8);e.hopMeasurement=LibboxRouterHopMeasurement();reject("foreign measurement adopted"){_ = try e.open(request(60))};try e.close()}
  print("iOS ordinary50 delivery: PASS (\(checks) checks; original class executed, native/OS boundaries doubled)")
 }
}
'''
def main():
 engine=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text();a=engine.index('    private final class NodeChainDelivery:');b=engine.index('\n    /// Only this delivery object crosses',a);delivery=engine[a:b]
 owner=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNOrderedLatency.swift').read_text().replace('import Libbox\n','')
 with tempfile.TemporaryDirectory(prefix='ios-ordinary-host-') as temp:
  d=Path(temp);s=d/'Fixture.swift';binary=d/'fixture'
  def run(body):
   s.write_text(BOUNDARY.replace('// DELIVERY',body)+owner)
   subprocess.run(['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(d/'modules'),str(s),'-o',str(binary)],check=True,timeout=90)
   return subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
  r=run(delivery);assert r.returncode==0,r.stdout+r.stderr;print(r.stdout.strip(),flush=True)
  for name,old,new,witness in [
   ('original-probe','LibboxRouterNodeChainNewLatencyBenchmark(plan, server, probe,','LibboxRouterNodeChainNewLatencyBenchmark(plan, server, LibboxRouterHopMeasurement(),','ordinary factory lost original service'),
   ('MTU','mtu["measurement_ready"] as? Bool == true','true','ordinary busy MTU must precede factory'),
   ('retained-close','try original?.close()','_ = original','failed facade close retained')]:
   assert delivery.count(old)==1,name;r=run(delivery.replace(old,new));assert r.returncode!=0 and witness in r.stdout+r.stderr,(name,r.stdout,r.stderr);print('Rejected ordinary host causal control: '+name,flush=True)
if __name__=='__main__':main()
