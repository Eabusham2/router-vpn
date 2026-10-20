#!/usr/bin/env python3
"""Execute shipping Apple hop orchestration with deterministic native IPC.

The UI controller, transaction, result types, and app-side MTU lease gate are
shipping source. NetworkExtension handles/native payloads are explicit doubles;
the native service and proof factories have separate encrypted/ownership gates.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
FIXTURE=r'''
protocol ObservableObject {}
@propertyWrapper struct Published<T> {var wrappedValue:T}
@MainActor final class NETunnelProviderSession {
 enum Status {case connected,disconnected}
 var status=Status.connected,connectedDate:Date?=Date(timeIntervalSince1970:10)
 func sendProviderMessage(_ data:Data,responseHandler:@escaping(Data?)->Void)throws{Native.shared.handle(data,responseHandler)}
}
@MainActor final class RouterVPNModel {
 var connected=true,activeEngine="external-libbox",activeSessionIdentity:String?="proved-native-selection"
 func refreshTunnelStatus()async{}
}
@MainActor final class Native {
 static let shared=Native()
 let session=UUID().uuidString,connection=NETunnelProviderSession()
 var mode="stable",drained=true,starts=0,cancels=0,statuses=0,releases=0,held=false
 var captured:[String:Any]?,pending:((Data?)->Void)?,pendingRequest:[String:Any]?
 func reset(_ mode:String){self.mode=mode;drained=mode=="stable";starts=0;cancels=0;statuses=0;releases=0;held=false;captured=nil;pending=nil;pendingRequest=nil;connection.status = .connected;connection.connectedDate=Date(timeIntervalSince1970:10)}
 func body(_ request:[String:Any],complete:Bool,drained:Bool)->Data {
  try! JSONSerialization.data(withJSONObject:["request_id":request["request_id"]!,"session_id":request["session_id"]!,"stage":complete ? "complete":"running","complete":complete,"drained":drained,"results":[]])
 }
 func handle(_ data:Data,_ reply:@escaping(Data?)->Void) {
  let request=try! JSONSerialization.jsonObject(with:data) as! [String:Any]
  guard request.count==3 && request["session_id"] as? String==session && held else {FileHandle.standardError.write(Data("native IPC lost its captured session or MTU hold\n".utf8));exit(1)}
  captured=request
  switch request["operation"] as? String {
   case "hop-measure-start":
    starts += 1
    if mode=="late" || mode=="changed" {pending=reply;pendingRequest=request;return}
    if mode=="wrong-session" {var wrong=request;wrong["session_id"]=UUID().uuidString;reply(body(wrong,complete:true,drained:true));return}
    reply(body(request,complete:true,drained:drained))
   case "hop-measure-cancel":cancels += 1;reply(body(request,complete:true,drained:drained))
   case "hop-measure-status":statuses += 1;reply(body(request,complete:true,drained:drained))
   default:reply(nil)
  }
 }
 func deliverLate(){let callback=pending;pending=nil;callback?(body(pendingRequest!,complete:true,drained:drained))}
}
@MainActor enum IOSMTUControl {
 struct Binding {let connection:NETunnelProviderSession;let connectedDate:Date;let identity:String;let session:String}
 static func capture(_ model:RouterVPNModel)async throws->Binding{
  guard let identity=model.activeSessionIdentity else{throw CancellationError()}
  return Binding(connection:Native.shared.connection,connectedDate:Native.shared.connection.connectedDate!,identity:identity,session:Native.shared.session)
 }
 static func holdCurrent(_ model:RouterVPNModel,request:String)async throws{Native.shared.held=true}
 static func releaseCurrent(_ model:RouterVPNModel,request:String)async throws{Native.shared.held=false;Native.shared.releases+=1}
WITH_HOLD
}
'''
TEST=r'''
@main struct Main {
 @MainActor static func main()async throws {
  var checks=0
  func check(_ name:String,_ test:Bool){if !test{FileHandle.standardError.write(Data((name+"\n").utf8));exit(1)};checks+=1}
  func wait(_ condition:()->Bool)async {
   let deadline=ProcessInfo.processInfo.systemUptime+5
   while !condition() && ProcessInfo.processInfo.systemUptime<deadline{try? await Task.sleep(for:.milliseconds(5))}
   check("bounded fixture progress",condition())
  }
  let native=Native.shared
  for engine in ["multihop-libbox","external-libbox"] {
   native.reset("stable");let model=RouterVPNModel();model.activeEngine=engine;let probe=IOSHopMeasurements()
   probe.start(model:model);await wait{!probe.running}
   check("supported graph is measured",native.starts==1 && native.releases==1 && !IOSMTUMeasurementGate.held)
   check("native request captures immutable session epoch",native.captured?["session_id"] as? String==native.session)
  }
  for engine in ["libbox","wireguardkit","none"] {
   native.reset("stable");let model=RouterVPNModel();model.activeEngine=engine;let probe=IOSHopMeasurements();probe.start(model:model)
   check("non-owned engine cannot start per-hop work",!probe.running && native.starts==0 && !IOSMTUMeasurementGate.held)
  }
  native.reset("complete-undrained")
  do {
   let model=RouterVPNModel(),probe=IOSHopMeasurements();probe.start(model:model)
   await wait{native.starts==1};try? await Task.sleep(for:.milliseconds(30))
   check("logical completion does not release native work",probe.running && IOSMTUMeasurementGate.held && native.releases==0)
   probe.start(model:model);check("new run cannot overlap undrained request",native.starts==1)
   native.drained=true;await wait{!probe.running}
   check("drain permits exactly one MTU release",native.releases==1 && !IOSMTUMeasurementGate.held)
  }
  for mode in ["late","changed","wrong-session"] {
   native.reset(mode);let model=RouterVPNModel(),probe=IOSHopMeasurements();probe.start(model:model)
   await wait{native.starts==1}
   if mode=="changed" {model.activeSessionIdentity="replacement-node";native.deliverLate()}
   else if mode=="late" {probe.cancel()}
   await wait{native.cancels>0}
   check("cancel or stale reply retains native hold",probe.running && IOSMTUMeasurementGate.held && native.releases==0)
   probe.start(model:model);check("cancel cannot reopen a concurrent run",native.starts==1)
   native.drained=true
   if mode=="late"{native.deliverLate()}
   await wait{!probe.running}
   check("cancel cleanup drains before hold release",native.releases==1 && !IOSMTUMeasurementGate.held)
   check("stale result is discarded",probe.text.contains("discarded") && !probe.text.contains("Mbps"))
  }
  print("Apple owned hop transaction: PASS (\(checks) shipping UI/MTU/IPC cancellation checks; native OS handles doubled)")
 }
}
'''

def main():
    source=(APP/'IOSHopMeasurements.swift').read_text().split('\nstruct IOSHopMeasurementsCard:',1)[0]
    source=source.replace('import SwiftUI','import Foundation').replace('@preconcurrency import NetworkExtension','')
    mtu=(APP/'IOSMTUControl.swift').read_text()
    hold=mtu[mtu.index('    static func withHold<T>'):].rsplit('\n}',1)[0]
    fixture=FIXTURE.replace('WITH_HOLD',hold)
    gate=(APP/'IOSMTUMeasurementGate.swift').read_text()
    with tempfile.TemporaryDirectory(prefix='routervpn-apple-hop-') as directory:
        work=Path(directory);code=work/'Main.swift';binary=work/'test'
        code.write_text('import Foundation\n'+gate+fixture+source+TEST)
        subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(code),'-o',str(binary)],check=True,timeout=60)
        subprocess.run([str(binary)],check=True,timeout=25)
        # Execute the old logical-completion mistake and a wrong-session reply
        # acceptance as negative controls against the same shipping UI harness.
        for name,old,new in [
            ('undrained completion','if result.complete && result.drained { return }','if result.complete { return }'),
            ('foreign session','status.request_id == id, status.session_id == session','status.request_id == id')]:
            assert old in source
            bad=work/'Bad.swift';bad_binary=work/'bad'
            bad.write_text('import Foundation\n'+gate+fixture+source.replace(old,new)+TEST)
            subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(bad),'-o',str(bad_binary)],check=True,timeout=60)
            result=subprocess.run([str(bad_binary)],capture_output=True,text=True,timeout=25)
            assert result.returncode != 0 and ('logical completion does not release native work' in result.stderr or
                'bounded fixture progress' in result.stderr or
                'native IPC lost its captured session or MTU hold' in result.stderr), name+': ownership regression was accepted or failed for another reason: '+result.stderr[-500:]
        print('Negative controls: undrained completion and foreign-session reply rejected')

if __name__=='__main__':main()
