#!/usr/bin/env python3
"""Run actual ordered-fifty app callbacks with explicit OS/native/private-file boundaries."""
from pathlib import Path
import importlib.util,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('components',ROOT/'deploy/test_ios_ordered_latency.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
BOUNDARY=r'''
protocol ObservableObject:AnyObject{}
@propertyWrapper struct Published<T>{var wrappedValue:T;init(wrappedValue:T){self.wrappedValue=wrappedValue}}
struct ClientBundle:Codable,Equatable {var secret="original-private-source"}
struct IOSSessionIdentity:Equatable {let nodeChainSource:Data?;let connectedAt:Date}
let boundaryTransport="socks5"
struct PathPoint{let mode:String}
enum IOSNodeChainPresentation {static func active(_ identity:IOSSessionIdentity?)->[PathPoint]?{identity==nil ? nil:[PathPoint(mode:"wg"),PathPoint(mode:boundaryTransport),PathPoint(mode:"shadowsocks")]}}
struct NativePlan{func sourceSHA256()->String{String(repeating:"1",count:64)};func configSHA256()->String{String(repeating:"2",count:64)}}
struct Member{let id:String;var profile:[String:Any]{["node_kind":id=="middle" ? "external":"router-vpn"]}}
struct SOCKSCapture{let plan=NativePlan(),source="captured-source",members=[Member(id:"entry"),Member(id:"middle"),Member(id:"final")]}
struct CONNECTCapture{let plan=NativePlan(),source="captured-source",members=[Member(id:"entry"),Member(id:"middle"),Member(id:"final")]}
struct OrdinaryCapture{let selectionExecution="local",launchInput="captured-source",sourceSHA256=String(repeating:"1",count:64),configSHA256=String(repeating:"2",count:64),members=[Member(id:"entry"),Member(id:"middle"),Member(id:"final")]}
enum IOSOrderedRouteCapture{case socks(SOCKSCapture),connect(CONNECTCapture),ordinary(OrdinaryCapture);var members:[Member]{switch self{case .socks(let v):return v.members;case .connect(let v):return v.members;case .ordinary(let v):return v.members}};func close()throws{}}
struct Ownership{var active=false}
@MainActor final class RouterVPNModel:ObservableObject{
 var connected=true,activeSessionIdentity:IOSSessionIdentity?=IOSSessionIdentity(nodeChainSource:Data("captured-source".utf8),connectedAt:Date(timeIntervalSince1970:1))
 var iosConnectGeneration=UUID(),bundle=ClientBundle(),selectedMode="wg",selectedLogicalMode="multihop",auto=false,iosSpeedLabOwnership=Ownership()
 func iosNodeChainBundles(for bundle:ClientBundle)throws->[ClientBundle]{[bundle]}
 func captureIOSOrderedRoute(_ bundle:ClientBundle)throws->IOSOrderedRouteCapture{boundaryTransport == "socks5" ? .socks(SOCKSCapture()):.connect(CONNECTCapture())}
 nonisolated static func iosStrategyDigest(_ data:Data)->String{let h=data.reduce(UInt64(14695981039346656037)){($0 ^ UInt64($1)) &* 1099511628211};return String(repeating:String(format:"%016llx",h),count:4)}
}
@MainActor enum Fixture{
 static var events:[String]=[],current=true,closed=false,closeFailures=0,hook:((String)->Void)?,mode="normal",holdReady=true,recordRequest=""
 static let session="00000000-0000-0000-0000-000000000001",mtu="00000000-0000-0000-0000-000000000002"
 static var connection=NETunnelProviderSession()
 static func reset(){events=[];current=true;closed=false;closeFailures=0;hook=nil;mode="normal";holdReady=true;recordRequest="";connection=NETunnelProviderSession();IOSPrivateJSONStore.value=nil;IOSPrivateJSONStore.writeHook=nil;IOSPrivateJSONStore.writes=0}
}
@MainActor final class NETunnelProviderSession{
 func sendProviderMessage(_ data:Data,responseHandler:((Data?)->Void)?)throws{
  let v=try JSONSerialization.jsonObject(with:data) as! [String:String],op=v["operation"]!
  Fixture.events.append(op);Fixture.hook?(op)
  var result:[String:Any]=["request_id":v["request_id"]!,"session_id":v["session_id"]!,"owner":v["owner"]!]
  if op=="ordered-latency-info"{
   result["provider_session"]=Fixture.session;result["mtu_session_id"]=Fixture.mtu;result["source_sha256"]=String(repeating:"1",count:64);result["config_sha256"]=String(repeating:"2",count:64)
   result["nodes"]=["entry","middle","final"].enumerated().map{["position":$0.offset,"node_id":$0.element,"kind":$0.offset==1 ? "public-path":"private-node"] as [String:Any]}
  }else if op=="ordered-latency-open"{result["opened"]=true;result["closed"]=false}
  else if op=="ordered-latency-close"{
   if Fixture.closeFailures>0{Fixture.closeFailures-=1;result["closed"]=false}
   else{Fixture.closed=true;result["closed"]=true}
  }else{
   let p=["entry","middle","final"].firstIndex(of:v["node_id"]!)!,r=receipt(p,v["request_id"]!,2000)
   Fixture.recordRequest=v["request_id"]!;result["status"]=status(r);result["saved"]=json(r)
   if Fixture.mode=="partial"{var invalid=r;var rr=r["result"] as! [String:Any];var b=rr["benchmark"] as! [String:Any];b["attempts"]=49;rr["benchmark"]=b;invalid["result"]=rr;result["saved"]=json(invalid)}
  }
  responseHandler?(Data(json(result).utf8))
 }
}
@MainActor enum IOSMTUControl{
 struct Binding{let connection:NETunnelProviderSession;let connectedDate:Date;let identity:IOSSessionIdentity;let session:String}
 static func capture(_ model:RouterVPNModel)async throws->Binding{Fixture.events.append("capture-before-hold");return Binding(connection:Fixture.connection,connectedDate:model.activeSessionIdentity!.connectedAt,identity:model.activeSessionIdentity!,session:Fixture.mtu)}
 static func current(_ binding:Binding,model:RouterVPNModel)->Bool{Fixture.current && model.connected && model.activeSessionIdentity==binding.identity && binding.connection === Fixture.connection}
 static func message(_ binding:Binding,model:RouterVPNModel,operation:String,request:String)async throws->Data{
  Fixture.events.append(operation);Fixture.hook?(operation)
  guard current(binding,model:model)else{throw fault()}
  return Data(json(["measurement_hold":true,"measurement_lease":request,"measurement_ready":Fixture.holdReady]).utf8)
 }
 static func send(_ connection:NETunnelProviderSession,operation:String,request:String,session:String)async throws->Data{
  Fixture.events.append(operation);Fixture.hook?(operation)
  guard connection === Fixture.connection,session==Fixture.mtu else{throw fault()};return Data("{}".utf8)
 }
}
'''
TESTS=r'''
@main struct CallbackTests{
 @MainActor static var checks=0
 @MainActor static func check(_ name:String,_ good:Bool){if !good{fatalError(name)};checks+=1}
 @MainActor static func finish(_ probe:IOSOrderedLatency)async{
  let deadline=ProcessInfo.processInfo.systemUptime+8
  while probe.running && ProcessInfo.processInfo.systemUptime<deadline{try? await Task.sleep(for:.milliseconds(10))}
  check("callback cleanup joined",!probe.running)
 }
 @MainActor static func main()async throws{
  for position in 0..<3{
   Fixture.reset();let model=RouterVPNModel(),probe=IOSOrderedLatency();probe.load(model)
   check("visible captured three node path",probe.ids==["entry","middle","final"])
   IOSPrivateJSONStore.writeHook={check("commit after original close",Fixture.closed && IOSMTUMeasurementGate.held)}
   probe.start(model,position:position);await finish(probe)
   check("history committed",IOSPrivateJSONStore.writes==1 && probe.history[probe.ids[position]] != nil)
   let e=Fixture.events
   check("MTU before factory",e.firstIndex(of:"mtu-hold")! < e.firstIndex(of:"ordered-latency-open")!)
   check("close before MTU release",e.lastIndex(of:"ordered-latency-close")! < e.lastIndex(of:"mtu-release")!)
   check("app lease released after join",!IOSMTUMeasurementGate.held)
  }
  for phase in ["mtu-hold","ordered-latency-info","ordered-latency-open","ordered-latency-start","ordered-latency-close"]{
   Fixture.reset();let model=RouterVPNModel(),probe=IOSOrderedLatency();probe.load(model)
   Fixture.hook={op in if op==phase{probe.cancel()}}
   probe.start(model,position:1);await finish(probe)
   check("cancelled callback never writes "+phase,IOSPrivateJSONStore.writes==0)
   check("cancel joins before lease release "+phase,!IOSMTUMeasurementGate.held)
   if phase=="mtu-hold" || phase=="ordered-latency-info" {check("prefactory cancellation never opens",!Fixture.events.contains("ordered-latency-open"))}
  }
  for phase in ["ordered-latency-info","ordered-latency-open","ordered-latency-start","ordered-latency-close"]{
   Fixture.reset();let model=RouterVPNModel(),probe=IOSOrderedLatency();probe.load(model)
   Fixture.hook={op in if op==phase{model.bundle.secret="changed private credential"}}
   probe.start(model,position:1);await finish(probe)
   check("full source change refuses commit "+phase,IOSPrivateJSONStore.writes==0)
  }
  Fixture.reset();let model=RouterVPNModel(),probe=IOSOrderedLatency();probe.load(model);Fixture.closeFailures=2
  Fixture.hook={op in if op=="ordered-latency-close"{check("failed close retains original lease",IOSMTUMeasurementGate.held && probe.running)}}
  probe.start(model,position:1);await finish(probe)
  check("same request retried close",Fixture.events.filter{$0=="ordered-latency-close"}.count==3 && IOSPrivateJSONStore.writes==0)
  Fixture.hook=nil;probe.start(model,position:1);await finish(probe)
  check("complete retry can save history",IOSPrivateJSONStore.writes==1)
  let previous=IOSPrivateJSONStore.value,display=probe.history
  Fixture.mode="partial";Fixture.closed=false;Fixture.hook=nil
  probe.start(model,position:1);await finish(probe)
  check("failed retest preserves last durable history",IOSPrivateJSONStore.value==previous && probe.history==display)
  Fixture.mode="normal";Fixture.hook={op in if op=="ordered-latency-open"{probe.cancel()}}
  probe.start(model,position:1);await finish(probe)
  check("cancelled retest preserves last durable history",IOSPrivateJSONStore.value==previous && probe.history==display)
  Fixture.reset();let failed=IOSOrderedLatency();failed.load(model);Fixture.mode="partial";failed.start(model,position:1);await finish(failed)
  check("partial receipt no durable write",IOSPrivateJSONStore.writes==0 && Fixture.closed)
  print("iOS ordered fifty actual app callbacks: PASS (\(checks) executable checks; native/OS/private-file boundaries doubled)")
 }
}
'''
def sources():
    history=(ROOT/'ios/RouterVPN/App/IOSOrderedLatencyHistory.swift').read_text()
    gate=(ROOT/'ios/RouterVPN/App/IOSMTUMeasurementGate.swift').read_text()
    app=(ROOT/'ios/RouterVPN/App/IOSOrderedLatency.swift').read_text().replace('import Combine\n','').replace('@preconcurrency import NetworkExtension\n','')
    return history+gate+app

def main(extra_controls=()):
    source=sources()
    with tempfile.TemporaryDirectory(prefix='ios-ordered-callbacks-') as tmp:
        p=Path(tmp);swift=p/'Fixture.swift';binary=p/'fixture'
        def run(value):
            swift.write_text(C.BOUNDARY.split('func request(')[0]+BOUNDARY+value+TESTS)
            subprocess.run(['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(p/'modules'),str(swift),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary)],capture_output=True,text=True,timeout=35)
        result=run(source);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip(),flush=True)
        for name,before,after,witness in [
            ('complete-source','try Self.bytes(model) == snapshot','!snapshot.isEmpty','full source change refuses commit'),
            ('close-before-history','        let cleanClose = await cleanup.value','        let cleanClose = true; _ = cleanup','commit after original close'),
        ] + list(extra_controls):
            assert source.count(before)==1,name
            result=run(source.replace(before,after,1));assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,result.stdout+result.stderr)
            print('Rejected ordered fifty callback control: '+name,flush=True)
if __name__=='__main__':main()
