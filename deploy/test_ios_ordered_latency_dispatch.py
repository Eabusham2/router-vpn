#!/usr/bin/env python3
"""Execute actual engine typed IPC dispatch with retained owner registry; native/OS handles doubled."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
BOUNDARY=r'''
import Foundation
final class LibboxRouterOrderedLatency {
 func start(_ request:String,nodeID:String)throws{}
 func cancel(_ request:String){}
 func drain(_ request:String)throws{}
 func statusJSON()->String{"{}"}
 func savedJSON(_ node:String)->String{""}
 func close()throws{}
}
func LibboxRouterValidatePrivateNodeJSON(_ raw:String,_ error:inout NSError?)->Bool{(try? JSONSerialization.jsonObject(with:Data(raw.utf8))) != nil}
class TypedBoundary {
 let kind:String;var events:[String]=[],hook:(()->Void)?
 init(_ kind:String){self.kind=kind}
 func latencyInfo(_ request:RouterVPNOrderedLatencyRequest,session:String)throws->Data?{events.append("info");hook?();return request.reply(["typed":kind])}
 func latencyOpen(_ request:RouterVPNOrderedLatencyRequest)throws->RouterVPNOrderedLatencyOwner{
  events.append("open");let owner=RouterVPNOrderedLatencyOwner(request,current:{})
  guard RouterVPNOrderedLatencyRegistry.shared.retain(owner) else{throw CancellationError()}
  try owner.open{$0(LibboxRouterOrderedLatency())};hook?();return owner
 }
}
final class RouterVPNNodeChainSOCKSHost:TypedBoundary{init(){super.init("socks")}}
final class RouterVPNNodeChainCONNECTHost:TypedBoundary{init(){super.init("connect")}}
final class RouterVPNLibboxEngine{
 let ownershipLock=NSLock(),settingsEpoch=UUID().uuidString
 var nodeChainSOCKS:RouterVPNNodeChainSOCKSHost?,nodeChainCONNECT:RouterVPNNodeChainCONNECTHost?,ownershipGeneration=UUID(),starting=false,permanentlyStopped=false,server:NSObject?=NSObject()
 // DISPATCH
}
final class Reply:@unchecked Sendable{
 let lock=NSLock(),joined=DispatchSemaphore(value:0);var value:Data?
 func finish(_ data:Data?){lock.lock();value=data;lock.unlock();joined.signal()}
 func wait()->Data?{guard joined.wait(timeout:.now()+3) == .success else{fatalError("IPC did not join")};lock.lock();defer{lock.unlock()};return value}
}
'''
TESTS=r'''
@main struct Tests{
 static var checks:Int{get{Counter.value}set{Counter.value=newValue}}
 static func check(_ good:Bool,_ text:String){if !good{fatalError(text)};checks+=1}
 static func request(_ engine:RouterVPNLibboxEngine,_ n:Int,_ operation:String="ordered-latency-info",foreign:Bool=false)->RouterVPNOrderedLatencyRequest{
  let info=operation=="ordered-latency-info"
  let v=["operation":operation,"request_id":String(format:"%032x",n),"owner":String(repeating:"b",count:32),"session_id":info ? "":foreign ? UUID().uuidString:engine.settingsEpoch,"lease":info ? "":String(repeating:"c",count:32),"source_sha256":info ? "":String(repeating:"1",count:64),"config_sha256":info ? "":String(repeating:"2",count:64),"node_id":info ? "":"middle"]
  return RouterVPNOrderedLatencyRequest.parse(try! JSONSerialization.data(withJSONObject:v))!
 }
 static func call(_ engine:RouterVPNLibboxEngine,_ request:RouterVPNOrderedLatencyRequest)->[String:Any]?{
  let reply=Reply();engine.orderedLatencyRequest(request,completion:reply.finish)
  guard let data=reply.wait() else{return nil};return try! JSONSerialization.jsonObject(with:data) as? [String:Any]
 }
 static func main()throws{
  for kind in ["socks","connect"]{
   let e=RouterVPNLibboxEngine();if kind=="socks"{e.nodeChainSOCKS=RouterVPNNodeChainSOCKSHost()}else{e.nodeChainCONNECT=RouterVPNNodeChainCONNECTHost()}
   check(call(e,request(e,1))?["typed"] as? String==kind,"typed info dispatch "+kind)
   check(call(e,request(e,2,"ordered-latency-open"))?["opened"] as? Bool==true,"typed open dispatch "+kind)
   check(call(e,request(e,2,"ordered-latency-start"))?["status"] as? String=="{}","typed start original facade "+kind)
   check(call(e,request(e,2,"ordered-latency-status"))?["status"] as? String=="{}","typed status original facade "+kind)
   check(call(e,request(e,3,"ordered-latency-open",foreign:true))==nil,"foreign provider session rejected")
   let events=e.nodeChainSOCKS?.events ?? e.nodeChainCONNECT!.events;check(events==["info","open"],"foreign session cannot call factory")
  }
  do{let e=RouterVPNLibboxEngine();check(call(e,request(e,4))==nil,"ordinary owner unavailable")}
  do{let e=RouterVPNLibboxEngine();e.nodeChainCONNECT=RouterVPNNodeChainCONNECTHost();e.nodeChainSOCKS=RouterVPNNodeChainSOCKSHost();check(call(e,request(e,5))==nil,"mixed typed owners rejected")}
  for stage in ["starting","retired","server"]{
   let e=RouterVPNLibboxEngine();e.nodeChainCONNECT=RouterVPNNodeChainCONNECTHost()
   if stage=="starting"{e.starting=true}else if stage=="retired"{e.permanentlyStopped=true}else{e.server=nil}
   check(call(e,request(e,6))==nil,"unavailable original engine "+stage)
  }
  for op in ["ordered-latency-info","ordered-latency-open"]{
   for change in ["owner","generation","retirement"]{
    let e=RouterVPNLibboxEngine(),host=RouterVPNNodeChainCONNECTHost();e.nodeChainCONNECT=host
    host.hook={if change=="owner"{e.nodeChainCONNECT=RouterVPNNodeChainCONNECTHost()}else if change=="generation"{e.ownershipGeneration=UUID()}else{e.permanentlyStopped=true}}
    let req=request(e,7,op);check(call(e,req)==nil,"late original owner response rejected "+change)
    if op=="ordered-latency-open"{check(RouterVPNOrderedLatencyRegistry.shared.find(req) != nil,"late facade remains retained for original cleanup")}
   }
  }
  print("iOS ordered fifty typed dispatch: PASS (\(checks) actual engine IPC checks; native/OS boundaries doubled)")
 }
}
enum Counter{nonisolated(unsafe)static var value=0}
'''
def main():
    engine=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
    start=engine.index('    func orderedLatencyRequest(');end=engine.index('    func completeNodeChainSOCKS(',start)
    dispatch=engine[start:end]
    owner=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNOrderedLatency.swift').read_text().replace('import Libbox\n','')
    with tempfile.TemporaryDirectory(prefix='ios-latency-dispatch-') as d:
        d=Path(d);s=d/'Fixture.swift';binary=d/'fixture'
        def run(body):
            s.write_text(BOUNDARY.replace('// DISPATCH',body)+owner+TESTS)
            subprocess.run(['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(d/'modules'),str(s),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary)],capture_output=True,text=True,timeout=35)
        v=run(dispatch);assert v.returncode==0,v.stdout+v.stderr;print(v.stdout.strip(),flush=True)
        for name,before,after,witness in [
            ('typed-connect-dispatch','if let connect { result = try connect.latencyInfo','if let connect = socks { result = try connect.latencyInfo','typed info dispatch connect'),
            ('exclusive-owner','(socks != nil) != (connect != nil)','(socks != nil) || (connect != nil)','mixed typed owners rejected'),
            ('original-session','request.session == engine.settingsEpoch','true','foreign provider session rejected'),
            ('post-response-owner','                guard current() else { throw CancellationError() }\n            } catch','                // Lost original owner check\n            } catch','late original owner response rejected'),
        ]:
            assert dispatch.count(before)==1,name
            v=run(dispatch.replace(before,after,1));assert v.returncode!=0 and witness in v.stdout+v.stderr,(name,v.stdout+v.stderr)
            print('Rejected ordered fifty dispatch control: '+name,flush=True)
if __name__=='__main__':main()
