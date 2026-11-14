#!/usr/bin/env python3
"""Execute actual ordinary2–8 app capture/IPC/history callbacks; native and OS are doubled."""
from pathlib import Path
import importlib.util,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ordinary_callbacks_base',ROOT/'deploy/test_ios_ordered_latency_callbacks.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
BOUNDARY=C.BOUNDARY
BOUNDARY=BOUNDARY.replace('let boundaryTransport="socks5"','let boundaryTransport="wg"\nnonisolated(unsafe)var ordinaryCount=2\nnonisolated(unsafe)var ordinaryExecution="local"')
BOUNDARY=BOUNDARY.replace('[PathPoint(mode:"wg"),PathPoint(mode:boundaryTransport),PathPoint(mode:"shadowsocks")]','(0..<ordinaryCount).map{PathPoint(mode:$0==ordinaryCount-1 ? "shadowsocks":"wg")}')
start=BOUNDARY.index('struct OrdinaryCapture{');end=BOUNDARY.index('\nenum IOSOrderedRouteCapture',start)
BOUNDARY=BOUNDARY[:start]+'''struct OrdinaryCapture{let selectionExecution=ordinaryExecution,launchInput="captured-source",sourceSHA256=String(repeating:"1",count:64),configSHA256=String(repeating:"2",count:64);var members:[Member]{(0..<ordinaryCount).map{Member(id:"node-\\($0)")}}}'''+BOUNDARY[end:]
BOUNDARY=BOUNDARY.replace('boundaryTransport == "socks5" ? .socks(SOCKSCapture()):.connect(CONNECTCapture())','.ordinary(OrdinaryCapture())')
BOUNDARY=BOUNDARY.replace('["entry","middle","final"].enumerated().map{["position":$0.offset,"node_id":$0.element,"kind":$0.offset==1 ? "public-path":"private-node"] as [String:Any]}','(0..<ordinaryCount).map{["position":$0,"node_id":"node-\\($0)","kind":"private-node"] as [String:Any]}')
BOUNDARY=BOUNDARY.replace('let p=["entry","middle","final"].firstIndex(of:v["node_id"]!)!,r=receipt(p,v["request_id"]!,2000)','let p=Int(v["node_id"]!.split(separator:"-").last!)!,r=ordinaryReceipt(p,v["request_id"]!)')
BOUNDARY+=r'''
func ordinaryReceipt(_ position:Int,_ request:String)->[String:Any]{
 var v=receipt(0,request,2000);v["position"]=position;v["node_id"]="node-\(position)"
 var row=v["result"] as! [String:Any];row["node_id"]=v["node_id"]!;row["role"]=position==0 ? "entry":position==ordinaryCount-1 ? "exit":"intermediate";row["label"]="Cumulative path through node \(position+1) of \(ordinaryCount)";v["result"]=row;return v
}
'''
TESTS=r'''
@main struct OrdinaryCallbackTests{
 @MainActor static var checks=0
 @MainActor static func check(_ ok:Bool,_ text:String){if !ok{fatalError(text)};checks+=1}
 @MainActor static func finish(_ p:IOSOrderedLatency)async{let deadline=ProcessInfo.processInfo.systemUptime+8;while p.running&&ProcessInfo.processInfo.systemUptime<deadline{try? await Task.sleep(for:.milliseconds(10))};check(!p.running,"ordinary callbacks failed to join")}
 @MainActor static func main()async throws{
  for count in 2...8{
   ordinaryCount=count;Fixture.reset();let model=RouterVPNModel(),p=IOSOrderedLatency();p.load(model);check(p.ids.count==count,"ordinary capture unavailable")
   for position in 0..<count{
    Fixture.closed=false;p.start(model,position:position);await finish(p)
    let capture=try IOSOrderedLatencyCapture(model),record=try IOSOrderedLatencyHistory.load(profile:capture.profile,source:capture.source,config:capture.config,position:position,node:capture.ids[position])
    check(record?.count==count&&record?.kind=="private-node"&&p.history[capture.ids[position]]?.contains("including connection establishment")==true,"ordinary app history lost actual count/kind")
    check(Fixture.closed && !IOSMTUMeasurementGate.held,"ordinary saved before original close")
   }
   let previous=IOSPrivateJSONStore.value;Fixture.mode="partial";p.start(model,position:count-1);await finish(p);check(IOSPrivateJSONStore.value==previous,"ordinary partial Retest replaced history")
   ordinaryExecution="server";let foreign=IOSOrderedLatency();foreign.load(model);check(foreign.ids.isEmpty,"Server capture borrowed ordinary Local proof");ordinaryExecution="local"
  }
  print("iOS ordinary50 app callbacks: PASS (\(checks) checks;35 positions2–8; native/OS boundaries doubled)")
 }
}
'''
def main():
 source=C.sources()
 with tempfile.TemporaryDirectory(prefix='ios-ordinary-callbacks-') as tmp:
  p=Path(tmp);s=p/'Fixture.swift';binary=p/'fixture'
  def run(text):
   s.write_text(C.C.BOUNDARY.split('func request(')[0]+BOUNDARY+text+TESTS)
   subprocess.run(['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(p/'modules'),str(s),'-o',str(binary)],check=True,timeout=90)
   return subprocess.run([str(binary)],capture_output=True,text=True,timeout=35)
  r=run(source);assert r.returncode==0,r.stdout+r.stderr;print(r.stdout.strip(),flush=True)
  for name,old,new,witness in [('local-owner','original.selectionExecution == "local"','true','Server capture borrowed ordinary Local proof'),('actual-kind','capture.kinds[index]','(index == 1 ? "public-path" : "private-node")','ordinary app history lost actual count/kind')]:
   assert source.count(old)==1;r=run(source.replace(old,new));assert r.returncode!=0 and witness in r.stdout+r.stderr,(name,r.stdout,r.stderr);print('Rejected ordinary callback control: '+name,flush=True)
if __name__=='__main__':main()
