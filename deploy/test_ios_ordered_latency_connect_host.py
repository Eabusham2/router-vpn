#!/usr/bin/env python3
"""Execute typed shipping host benchmark adoption/cleanup, with native and MTU boundaries explicit."""
from pathlib import Path
import importlib.util,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('host',ROOT/'deploy/test_ios_node_chain_connect_host.py');H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
BOUNDARY=r'''
final class LibboxRouterOrderedLatency {
 var closes=0,closeFailures=0
 func start(_ request:String,nodeID:String)throws{}
 func cancel(_ request:String){Trace.shared.add("fifty-cancel")}
 func drain(_ request:String)throws{}
 func statusJSON()->String{"{}"}
 func savedJSON(_ node:String)->String{""}
 func close()throws{Trace.shared.add("fifty-close");closes+=1;if closeFailures>0{closeFailures-=1;throw failure()}}
}
final class Native50:@unchecked Sendable{
 static let shared=Native50();var creates=0,returned:LibboxRouterOrderedLatency?,probe:LibboxRouterHopMeasurement?,hook:(()->Void)?
 let entered=DispatchSemaphore(value:0),joined=DispatchSemaphore(value:0)
 func reset(){creates=0;returned=nil;probe=nil;hook=nil}
}
func LibboxRouterNodeChainCONNECTNewLatencyBenchmark(_ plan:LibboxRouterNodeChainCONNECT,_ server:LibboxCommandServer,_ probe:LibboxRouterHopMeasurement,_ error:inout NSError?)->LibboxRouterOrderedLatency?{
 let f=Native50.shared;f.creates+=1;f.probe=probe;Trace.shared.add("fifty-create")
 guard plan.owner?.server===server,plan.healthy() else{error=failure();return nil}
 let result=LibboxRouterOrderedLatency();f.returned=result;f.hook?();return result
}
func LibboxRouterValidatePrivateNodeJSON(_ raw:String,_ error:inout NSError?)->Bool{(try? JSONSerialization.jsonObject(with:Data(raw.utf8))) != nil}
func req(_ n:Int)->RouterVPNOrderedLatencyRequest{
 let body:[String:String]=["operation":"ordered-latency-open","request_id":String(format:"%032x",n),"session_id":"00000000-0000-0000-0000-000000000001","owner":String(repeating:"b",count:32),"lease":String(repeating:"c",count:32),"source_sha256":String(repeating:"1",count:64),"config_sha256":String(repeating:"2",count:64),"node_id":"middle"]
 return RouterVPNOrderedLatencyRequest.parse(try! JSONSerialization.data(withJSONObject:body))!
}
'''
TESTS=r'''
extension RouterVPNNodeChainCONNECTHost{func fixtureHealth(){checkHealth()}}
@main struct Tests{
 nonisolated(unsafe) static var checks=0
 static func check(_ good:Bool,_ name:String){if !good{fatalError(name)};checks+=1}
 static func reject(_ name:String,_ work:()throws->Void){do{try work();fatalError(name)}catch{checks+=1}}
 static func ready()throws->(RouterVPNNodeChainCONNECTHost,RouterVPNLibboxPlatform){
  Factory.shared.reset();Native50.shared.reset()
  let capture=IOSNodeChainCONNECTCapture(),platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainCONNECTHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
  let server=LibboxCommandServer();try host.beginFactory();try host.finishFactory(server);try host.startNative();host.finishConstruction()
  let result=Result();host.run(adoptMeasurement:{_,_ in true},completion:result.finish);check(result.wait() && result.values==[false],"original typed proof")
  return(host,platform)
 }
 static func main()throws{
  do{
   let (host,platform)=try ready();let original=Factory.shared.probe!
   platform.mtu.ready=false
   reject("busy MTU must precede factory"){_ = try host.latencyOpen(req(1))}
   check(Native50.shared.creates==0,"no factory before MTU readback")
   platform.mtu.ready=true;platform.mtu.lease=String(repeating:"d",count:32)
   reject("foreign lease must refuse factory"){_ = try host.latencyOpen(req(2))}
   check(Native50.shared.creates==0,"foreign lease did not enter factory")
   platform.mtu.lease=String(repeating:"c",count:32)
   let owner:RouterVPNOrderedLatencyOwner
   do{owner=try host.latencyOpen(req(3))}catch{fatalError("returned facade missing original retention")}
   check(Native50.shared.probe === original,"factory borrows exact original throughput")
   let native=Native50.shared.returned!;native.closeFailures=1
   reject("failed benchmark close not acknowledged"){try owner.close()}
   reject("pending facade cannot be replaced"){_ = try host.latencyOpen(req(4))}
   check(Native50.shared.creates==1,"pending cleanup cannot create another facade")
   try owner.close();check(!original.closed,"facade close never closes throughput")
   platform.mtu.proofObservationToken=UUID();host.fixtureHealth()
   let next=try host.latencyOpen(req(5));check(Native50.shared.probe === original && Factory.shared.probe === original,"MTU reproof retains original measurement")
   try next.close();Trace.shared.reset();let last=try host.latencyOpen(req(6));_ = last
   try host.close();let trace=Trace.shared.values
   check(trace.contains("fifty-close") && trace.contains("measure-close") && trace.firstIndex(of:"fifty-close")! < trace.firstIndex(of:"measure-close")!,"facade joins before throughput teardown")
  }
  do{
   let (host,_)=try ready();Native50.shared.hook={host.cancel()}
   reject("cancelled factory cannot report open"){_ = try host.latencyOpen(req(7))}
   let native=Native50.shared.returned!
   try host.close();check(native.closes==1,"late facade retained before post observation rejection")
  }
  do{
   let (host,_)=try ready();let entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0),joined=DispatchSemaphore(value:0)
   Native50.shared.hook={entered.signal();_ = release.wait(timeout:.now()+4)}
   DispatchQueue.global().async{_ = try? host.latencyOpen(req(8));joined.signal()}
   check(entered.wait(timeout:.now()+4) == .success,"factory entered")
   reject("entered factory prevents host teardown"){try host.close()}
   check(Factory.shared.probe?.closed==false,"throughput retained until factory joins")
   release.signal();check(joined.wait(timeout:.now()+4) == .success,"factory joined")
   try host.close();check(Native50.shared.returned?.closes==1,"entered late facade closed on same host")
  }
  print("iOS ordered CONNECT fifty typed host: PASS (\(checks) ownership checks; native/MTU boundaries doubled)")
 }
}
'''
def main():
    boundary=H.BOUNDARY.replace(' func request(operation:String,request:String,session:String)->Data?{nil}',r''' var ready=true,lease=String(repeating:"c",count:32)
 func request(operation:String,request:String,session:String)->Data?{try! JSONSerialization.data(withJSONObject:["measurement_lease":lease,"measurement_hold":true,"measurement_ready":ready,"session_id":"00000000-0000-0000-0000-000000000002"])}'''.replace('\\"','"'))
    owner=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNOrderedLatency.swift').read_text().replace('import Libbox\n','')
    host=H.HOST.read_text().replace('import Libbox\n','')
    source=owner+host
    with tempfile.TemporaryDirectory(prefix='ios-ordered-host-') as tmp:
        p=Path(tmp);swift=p/'Fixture.swift';binary=p/'fixture'
        def run(value):
            swift.write_text(boundary+BOUNDARY+value+TESTS)
            subprocess.run(['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(p/'modules'),str(swift),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary)],capture_output=True,text=True,timeout=35)
        result=run(source);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip(),flush=True)
        for name,before,after,witness in [
            ('quiesce-before-factory','body["measurement_ready"] as? Bool == true','true','busy MTU must precede factory'),
            ('exact-lease','body["measurement_lease"] as? String == request.lease','true','foreign lease must refuse factory'),
            ('borrowed-service','capture.plan, original, probe, &failure','capture.plan, original, LibboxRouterHopMeasurement(), &failure','factory borrows exact original throughput'),
            ('retain-before-observation','if let returned { retain(returned) }','_ = returned','returned facade missing original retention'),
            ('facade-before-throughput','            try latency?.close()','            _ = latency','facade joins before throughput teardown'),
        ]:
            assert source.count(before)==1,name
            result=run(source.replace(before,after,1));assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,result.stdout+result.stderr)
            print('Rejected ordered CONNECT fifty typed-host control: '+name,flush=True)
if __name__=='__main__':main()
