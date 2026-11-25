#!/usr/bin/env python3
"""Execute actual ordinary2–8 app capture/IPC/history callbacks; native and OS are doubled."""
from pathlib import Path
import importlib.util,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ordinary_callbacks_base',ROOT/'deploy/test_ios_ordered_latency_callbacks.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
BOUNDARY=C.BOUNDARY
BOUNDARY=BOUNDARY.replace('let boundaryTransport="socks5"','let boundaryTransport="wg"\nnonisolated(unsafe)var ordinaryCount=2\nnonisolated(unsafe)var ordinaryExecution="local"\nnonisolated(unsafe)var ordinaryImported=false\nnonisolated(unsafe)var ordinaryWrongKind=false')
member='struct Member{let id:String;var profile:[String:Any]{["node_kind":(id=="middle" || id.hasPrefix("custom-")) ? "external":"router-vpn"]}}'
assert BOUNDARY.count(member)==1
BOUNDARY=BOUNDARY.replace(member,'struct Member{let id:String;var profile:[String:Any]{let position=Int(id.split(separator:"-").last!)!;return ["node_kind":ordinaryImported && position>0 && position<ordinaryCount-1 ? "external":"router-vpn"]}}')
BOUNDARY=BOUNDARY.replace('static var ids:[String]{multiple ? ["entry","custom-1","paired","custom-3","final"]:["entry","middle","final"]}', 'static var ids:[String]{(0..<ordinaryCount).map{"node-"+String($0)}}')
start=BOUNDARY.index('struct OrdinaryCapture{');end=BOUNDARY.index('\nstruct ExecutionCapture',start)
BOUNDARY=BOUNDARY[:start]+'''struct OrdinaryCapture{let sourceSchema=1;let plan=NativePlan(),selectionExecution=ordinaryExecution,launchInput="captured-source",sourceSHA256=String(repeating:"1",count:64),configSHA256=String(repeating:"2",count:64);var members:[Member]{(0..<ordinaryCount).map{Member(id:"node-\\($0)")}}}'''+BOUNDARY[end:]
BOUNDARY=BOUNDARY.replace('boundaryTransport == "socks5" ? .socks(SOCKSCapture()):.connect(CONNECTCapture())','.ordinary(OrdinaryCapture())')
BOUNDARY=BOUNDARY.replace('Fixture.publicSlots.contains($0.offset) ? "public-path":"private-node"', 'ordinaryImported && !ordinaryWrongKind && $0.offset>0 && $0.offset<ordinaryCount-1 ? "public-path":"private-node"')
BOUNDARY=BOUNDARY.replace('let r=receipt(Fixture.multiple ? Fixture.publicSlots.contains(p) ? 1 : 0 : p,v["request_id"]!,2000)', 'let r=ordinaryReceipt(p,v["request_id"]!)')
BOUNDARY+=r'''
func ordinaryReceipt(_ position:Int,_ request:String)->[String:Any]{
 let imported=ordinaryImported && position>0 && position<ordinaryCount-1
 var v=receipt(imported ? 1:0,request,2000);v["position"]=position;v["node_id"]="node-\(position)"
 var row=v["result"] as! [String:Any];row["node_id"]=v["node_id"]!;row["role"]=position==0 ? "entry":position==ordinaryCount-1 ? "exit":"intermediate";row["label"]=imported ? "Cumulative path through custom node \(position+1) of \(ordinaryCount) → Cloudflare edge":"Cumulative path through node \(position+1) of \(ordinaryCount)";v["result"]=row;return v
}
'''
TESTS=r'''
@main struct OrdinaryCallbackTests{
 @MainActor static var checks=0
 @MainActor static func check(_ ok:Bool,_ text:String){if !ok{fatalError(text)};checks+=1}
 @MainActor static func finish(_ p:IOSOrderedLatency)async{let deadline=ProcessInfo.processInfo.systemUptime+8;while p.running&&ProcessInfo.processInfo.systemUptime<deadline{try? await Task.sleep(for:.milliseconds(10))};check(!p.running,"ordinary callbacks failed to join")}
 @MainActor static func main()async throws{
  for imported in [false,true]{for count in 2...8 where !imported || count>=3{
   ordinaryCount=count;ordinaryImported=imported;ordinaryWrongKind=false;Fixture.reset();let model=RouterVPNModel(),p=IOSOrderedLatency();p.load(model);check(p.ids.count==count,"ordinary capture unavailable")
   for position in 0..<count{
    Fixture.closed=false;p.start(model,position:position);await finish(p)
    let capture=try IOSOrderedLatencyCapture(model),record=try IOSOrderedLatencyHistory.load(profile:capture.profile,source:capture.source,config:capture.config,position:position,node:capture.ids[position])
    let publicPath=imported && position>0 && position<count-1
    check(record?.count==count&&record?.position==position&&record?.kind==(publicPath ? "public-path":"private-node")&&p.history[capture.ids[position]]?.contains(publicPath ? "through the custom node":"including connection establishment")==true,"ordinary app history lost actual count/kind")
    check(Fixture.closed && !IOSMTUMeasurementGate.held,"ordinary saved before original close")
   }
   let previous=IOSPrivateJSONStore.value;Fixture.mode="partial";p.start(model,position:count-1);await finish(p);check(IOSPrivateJSONStore.value==previous,"ordinary partial Retest replaced history")
   if imported{
    Fixture.mode="normal";ordinaryWrongKind=true;let opens=Fixture.events.filter{$0=="ordered-latency-open"}.count
    p.start(model,position:1);await finish(p)
    check(IOSPrivateJSONStore.value==previous && Fixture.events.filter{$0=="ordered-latency-open"}.count==opens,"ordinary imported provider kind must match original capture")
    check(!IOSMTUMeasurementGate.held,"ordinary imported refusal lost lease cleanup");ordinaryWrongKind=false
   }
   ordinaryExecution="server";let foreign=IOSOrderedLatency();foreign.load(model);check(foreign.ids.isEmpty,"Server capture borrowed ordinary Local proof");ordinaryExecution="local"
  }}
  print("iOS ordinary50 app callbacks: PASS (\(checks) checks;68 positions2–8 including21 imported interiors; native/OS boundaries doubled)")
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
  for name,old,new,witness in [('local-owner','original.selectionExecution == "local"','true','Server capture borrowed ordinary Local proof'),('actual-kind','capture.kinds[index]','(index == 1 ? "public-path" : "private-node")','ordinary app history lost actual count/kind'),('provider-kind','item["kind"] as? String == capture.kinds[index]','true','ordinary imported provider kind must match original capture')]:
   assert source.count(old)==1;r=run(source.replace(old,new));assert r.returncode!=0 and witness in r.stdout+r.stderr,(name,r.stdout,r.stderr);print('Rejected ordinary callback control: '+name,flush=True)
if __name__=='__main__':main()
