#!/usr/bin/env python3
"""Execute the shipping external50 controller, capture, transaction and store.

NetworkExtension and atomic-file I/O are explicit boundaries. Real CryptoKit is
used where available; the existing input-sensitive Linux hash double is labelled
when used. Actual routed TLS/proof workers run in the separate Go native gate.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

import test_ios_node_usage as usage
import test_ios_unified_telemetry as telemetry

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "ios/RouterVPN/App"

NATIVE = r'''
enum IOSTelemetryProtocol {
 static func issue(_ text:String)->NSError {NSError(domain:"TelemetryBoundary",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
}
@MainActor final class BenchmarkNative {
 let epoch=UUID().uuidString,mtu=UUID().uuidString
 let connection=NETunnelProviderSession()
 var drained=true,held=false,cancelled=false,starts=0,cancels=0,releases=0,informationCalls=0
 var mode="valid",informationNode="external-node",lease="",lastRequest=""
 var requested="local",selected="local",configuration=String(repeating:"a",count:64)
 var informationHook:(()->Void)?
 func response(_ request:[String:String],cancel:Bool=false)throws->Data {
  var body:[String:Any]=["request_id":request["request_id"]!,"session_id":epoch,
   "complete":true,"drained":drained,"stage":cancelled ? "cancelled":"complete","results":[]]
  if !cancelled {
   var distribution:[String:Any]=["samples":50,"min_ms":1.0,"median_ms":4.0,"average_ms":4.5,"p90_ms":8.0,"max_ms":10.0,"jitter_ms":2.0]
   var benchmark:[String:Any]=["schema":1,"measurement":"routed-https-response-after-tls",
    "endpoint":"https://speed.cloudflare.com/__down?bytes=1","attempts":50,"failed":0,"distribution":distribution,"trimmed_mean_ms":4.25]
   var result:[String:Any]=["node_id":"external-node","role":"exit","kind":"public-path","label":"Captured HTTPS path","ready":true]
   switch mode {
    case "partial":distribution["samples"]=49;benchmark["distribution"]=distribution
    case "failed":benchmark["failed"]=1
    case "wrong-endpoint":benchmark["endpoint"]="https://different.example/"
    case "wrong-metric":benchmark["measurement"]="icmp-rtt"
    case "zero":distribution["min_ms"]=0;benchmark["distribution"]=distribution
    case "unordered":distribution["median_ms"]=11;benchmark["distribution"]=distribution
    case "trim":benchmark["trimmed_mean_ms"]=11
    case "wrong-node":result["node_id"]="another-node"
    case "not-ready":result["ready"]=false
    case "private-kind":result["kind"]="private-node"
    case "entry-role":result["role"]="entry"
    case "foreign-session":if !cancel {body["session_id"]=UUID().uuidString}
    case "foreign-request":if !cancel {body["request_id"]=String(repeating:"f",count:32)}
    case "failed-status":body["failure"]="native proof refused"
    case "invalidated":body["stage"]="invalidated"
    default:break
   }
   result["benchmark"]=benchmark;body["results"]=[result]
  }
  return try json(body)
 }
 func handle(_ data:Data,_ reply:((Data?)->Void)?) {
  do {
   let request=try JSONDecoder().decode([String:String].self,from:data)
   guard request.count==3,let operation=request["operation"],let id=request["request_id"],let session=request["session_id"] else{throw CancellationError()}
   if operation.hasPrefix("mtu-") {
    if operation=="mtu-hold" {held=true;lease=id}
    if operation=="mtu-release" {
     guard drained || starts==0 else{throw CancellationError()}
     held=false;releases+=1
    }
    reply?(try json(["ack_id":id,"session_id":mtu,"measurement_hold":held,"measurement_ready":held,"measurement_lease":lease]));return
   }
   guard held else{throw CancellationError()}
   if operation=="hop-measure-info" {
    guard session.isEmpty else{throw CancellationError()}
    informationCalls+=1
    informationHook?()
    var execution:[String:Any]=["requested":requested,"selected":selected,"config_sha256":configuration]
    if informationCalls>1 {
     if mode=="winner-changed"{execution["selected"] = selected=="local" ? "server":"local"}
     if mode=="config-changed"{execution["config_sha256"] = String(repeating:"b",count:64)}
    }
    var information:[String:Any]=["request_id":id,"session_id":epoch,"mtu_session_id":mtu,"node_id":informationNode,"execution":execution]
    if mode=="missing-execution"{information.removeValue(forKey:"execution")}
    if informationCalls>1 && mode=="epoch-changed"{information["session_id"]=UUID().uuidString}
    reply?(try json(information));return
   }
   guard session==epoch else{throw CancellationError()}
   switch operation {
    case "hop-measure-latency-start":starts+=1;lastRequest=id
    case "hop-measure-status":guard id==lastRequest else{throw CancellationError()}
    case "hop-measure-cancel":cancels+=1;cancelled=true
    default:throw CancellationError()
   }
   reply?(try response(request,cancel:operation=="hop-measure-cancel"))
  } catch {reply?(nil)}
 }
}
'''

TESTS = r'''
@main struct ExternalBenchmarkTests {
 @MainActor static func main()async throws {
  var checks=0
  func check(_ label:String,_ value:Bool){guard value else{FileHandle.standardError.write(Data(("FAIL: "+label+"\n").utf8));exit(1)};checks+=1}
  func wait(_ label:String,_ ready:()->Bool)async {
   let end=ProcessInfo.processInfo.systemUptime+7
   while !ready() && ProcessInfo.processInfo.systemUptime<end{try? await Task.sleep(for:.milliseconds(5))}
   check("bounded progress: "+label,ready())
  }
  func fixture(paired:Bool=false,tor:Bool=false,requested:String="local",selected:String="local")throws->(RouterVPNModel,BenchmarkNative) {
   IOSPrivateJSONStore.values=[:];IOSPrivateJSONStore.writes=0;IOSPrivateJSONStore.failRead=false;IOSPrivateJSONStore.failWrite=false
   IOSPrivateJSONStore.beforeWrite=nil
   IOSViaEntryNetwork.shared.current=1;IOSViaEntryNetwork.shared.held=false
   NETunnelProviderManager.fail=false
   let model=RouterVPNModel(),native=BenchmarkNative()
   native.requested=requested;native.selected=selected
   let external:[String:Any]=tor ? ["protocol":"tor","expected_public_ip":""] : ["protocol":"socks5","expected_public_ip":"203.0.113.9","socks5":["host":"node.example","port":1080,"username":"account","password":"private-external-secret"]]
   var profile=try node("external-node",external:external)
   profile.multihopEnabled=paired;profile.multihopExecution=requested
   if paired {profile.multihopEntryID="paired-entry";profile.multihopExitID=profile.id;profile.multihopEntryMode="wg";profile.multihopExitMode=tor ? "tor":"socks5"}
   var bundle=ClientBundle.empty;bundle.routerProfiles=[profile];bundle.selectedRouterID=profile.id
   model.bundle=bundle;model.connected=true
   if paired {var entry=ClientBundle.empty;entry.routerProfiles=[try node("paired-entry")];entry.selectedRouterID="paired-entry";model.entry=entry}
   let source=try encoded(bundle),entry=try model.entry.map(encoded)
   model.activeSessionIdentity=try IOSSessionIdentity(connectedAt:native.connection.connectedDate!,engine:"external-libbox",rawProfile:tor ? "external-tor":"external-socks5",bundleData:source,entryBundleData:entry,entryMode:paired ? "wg":nil)
   let manager=NETunnelProviderManager();manager.connection=native.connection
   native.connection.handler={data,reply in native.handle(data,reply)}
   NETunnelProviderManager.all=[manager];IOSNodeBundleStore.shared.records=[profile.id:source]
   return(model,native)
  }
  for paired in [false,true] {for tor in [false,true] {for (requested,selected) in (paired ? [("local","local"),("server","server"),("auto","local"),("auto","server")]:[("local","local")]) {
   let(model,native)=try fixture(paired:paired,tor:tor,requested:requested,selected:selected),client=IOSExternalNodeBenchmark()
   let before=try encoded(model.bundle!),key=try IOSExternalNodeStatistics.selectedKey(model)
   IOSPrivateJSONStore.beforeWrite={check("save retains original MTU and measurement owners",native.held && native.drained && IOSMTUMeasurementGate.held && model.iosSpeedLabOwnership.active)}
   client.start(model:model);await wait("valid save"){!client.running}
   let record=try IOSExternalNodeStatistics.saved(key:key)
   check("routed50 saves only complete owned result \(paired)/\(tor): \(client.progress)",record?.benchmark.distribution.samples==50 && IOSPrivateJSONStore.writes==1 && native.starts==1)
   check("history retains requested choice and actual proved winner",record?.path.execution.requested==requested && record?.path.execution.selected==selected && record?.path.execution.config_sha256==native.configuration && native.informationCalls==2)
   check("completed native workers release both owners",native.releases==1 && !native.held && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
   check("history does not rewrite private profile or direct TCP statistics",try encoded(model.bundle!)==before && model.bundle!.routerProfiles[0].latencyMedianMs==nil)
   let raw=String(decoding:IOSPrivateJSONStore.values[IOSExternalNodeStatistics.filename]!,as:UTF8.self)
   check("durable store contains no credentials or node source",!raw.contains("private-external-secret") && !raw.contains("node.example") && !raw.contains("external-node"))
   check("labels identify actual measurement and history",client.savedText.contains("after TLS") && client.savedText.contains("historical") && !client.savedText.contains("Mbps"))
   check("history only renders for bound source",client.history(for:key)==client.savedText && client.history(for:String(repeating:"f",count:64)).isEmpty)
   model.connected=false;model.activeSessionIdentity=nil
   let reopened=IOSExternalNodeBenchmark();reopened.refreshSaved(model:model)
   check("saved same-path history survives disconnected sheet reopen",reopened.savedText.contains("50 routed HTTPS responses"))
   model.bundle!.routerProfiles[0].dnsHost="192.0.2.53"
   check("changed DNS cannot inherit another path result",try IOSExternalNodeStatistics.saved(key:IOSExternalNodeStatistics.selectedKey(model))==nil)
   check("stale displayed source history is hidden immediately",client.history(for:try IOSExternalNodeStatistics.selectedKey(model)).isEmpty)
   reopened.refreshSaved(model:model);check("source change refresh cannot display old numbers",!reopened.savedText.contains("Median"))
  }}}
  for mode in ["partial","failed","wrong-endpoint","wrong-metric","zero","unordered","trim","wrong-node","not-ready","private-kind","entry-role","foreign-session","foreign-request","failed-status","invalidated"] {
   let(model,native)=try fixture(),client=IOSExternalNodeBenchmark();native.mode=mode
   client.start(model:model);await wait(mode){!client.running}
   check("invalid native result never saves: "+mode,IOSPrivateJSONStore.writes==0 && client.savedText.isEmpty && !IOSMTUMeasurementGate.held)
  }
  for mode in ["winner-changed","config-changed","epoch-changed","missing-execution"] {
   let(model,native)=try fixture(paired:true,requested:"auto"),client=IOSExternalNodeBenchmark();native.mode=mode
   client.start(model:model);await wait(mode){!client.running}
   check("changed native execution receipt never saves: "+mode,IOSPrivateJSONStore.writes==0 && !IOSMTUMeasurementGate.held)
  }
  for bad in ["selected","requested","config"] {
   let(model,native)=try fixture(),client=IOSExternalNodeBenchmark()
   if bad=="selected"{native.selected="server"}
   if bad=="requested"{native.requested="auto"}
   if bad=="config"{native.configuration="not a digest"}
   client.start(model:model);await wait("bad execution "+bad){!client.running}
   check("invalid execution receipt cannot launch: "+bad,native.starts==0 && IOSPrivateJSONStore.writes==0)
  }
  for drift in ["cancel","selection","linked-source","paired-entry","session","network","generation","connection-date","connection-status","new-user-action"] {
   let(model,native)=try fixture(paired:true),client=IOSExternalNodeBenchmark();native.drained=false
   client.start(model:model);await wait("held "+drift){native.starts==1}
   check("complete but undrained cannot publish",client.running && IOSPrivateJSONStore.writes==0 && model.iosSpeedLabOwnership.active && IOSMTUMeasurementGate.held)
   let second=IOSExternalNodeBenchmark();second.start(model:model)
   check("reopened controller cannot overlap old native owner",!second.running && native.starts==1)
   switch drift {
    case "cancel":client.cancel()
    case "selection":model.bundle!.routerProfiles[0].dnsHost="192.0.2.53"
    case "linked-source":IOSNodeBundleStore.shared.records["external-node"]=Data("different stored source".utf8)
    case "paired-entry":model.entry!.routerProfiles[0].apiToken="replacement-entry"
    case "session":model.activeSessionIdentity=nil
    case "network":IOSViaEntryNetwork.shared.current=2
    case "generation":model.iosConnectGeneration=UUID()
    case "connection-date":native.connection.connectedDate=Date(timeIntervalSince1970:3000)
    case "connection-status":native.connection.status = .disconnected
    default:_ = model.iosSpeedLabOwnership.admit(.profile)
   }
   await wait("cancel native "+drift){native.cancels>0}
   check("cancel retains native workers and blocks stale publication",client.running && model.iosSpeedLabOwnership.active && IOSMTUMeasurementGate.held && IOSPrivateJSONStore.writes==0)
   native.drained=true;await wait("drain "+drift){!client.running}
   check("drained stale result never replaces statistics",IOSPrivateJSONStore.writes==0 && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
  }
  for changed in ["wrong-info-node","info-selection","source-before-start","cancel-before-task"] {
   let(model,native)=try fixture(),client=IOSExternalNodeBenchmark()
   if changed=="wrong-info-node"{native.informationNode="unrelated-node"}
   if changed=="info-selection"{native.informationHook={model.bundle!.routerProfiles[0].dnsHost="192.0.2.53"}}
   if changed=="source-before-start"{model.bundle!.routerProfiles[0].dnsHost="192.0.2.53"}
   client.start(model:model);if changed=="cancel-before-task"{client.cancel()}
   await wait(changed){!client.running}
   check("pre-start drift cannot launch a native worker: "+changed,native.starts==0 && IOSPrivateJSONStore.writes==0 && !IOSMTUMeasurementGate.held)
  }
  do {
   let(model,native)=try fixture(),client=IOSExternalNodeBenchmark()
   client.start(model:model);await wait("initial durable result"){!client.running}
   let key=try IOSExternalNodeStatistics.selectedKey(model),record=try IOSExternalNodeStatistics.saved(key:key)!,saved=IOSPrivateJSONStore.values[IOSExternalNodeStatistics.filename]!
   IOSPrivateJSONStore.failWrite=true;native.mode="valid";client.start(model:model);await wait("failed atomic write"){!client.running}
   check("write failure preserves exact previous bytes",IOSPrivateJSONStore.values[IOSExternalNodeStatistics.filename]==saved && IOSPrivateJSONStore.writes==1)
   IOSPrivateJSONStore.failWrite=false
   for corrupt in [Data("bad json".utf8),Data("{}".utf8),Data(String(decoding:saved,as:UTF8.self).replacingOccurrences(of:"\"schema\":1",with:"\"schema\":2").utf8)] {
    IOSPrivateJSONStore.values[IOSExternalNodeStatistics.filename]=corrupt
    do{_ = try IOSExternalNodeStatistics.save(key:key,benchmark:record.benchmark,path:record.path);check("corrupt history overwritten",false)}catch{checks+=1}
    check("corrupt history is retained",IOSPrivateJSONStore.values[IOSExternalNodeStatistics.filename]==corrupt)
   }
   IOSPrivateJSONStore.values[IOSExternalNodeStatistics.filename]=saved
   for index in 0..<130 {_ = try IOSExternalNodeStatistics.save(key:IOSNodeUsage.digest(Data("path-\(index)".utf8)),benchmark:record.benchmark,path:record.path)}
   let data=IOSPrivateJSONStore.values[IOSExternalNodeStatistics.filename]!,value=try JSONSerialization.jsonObject(with:data) as! [String:Any]
   check("private path history is bounded",(value["records"] as! [Any]).count==128 && data.count<=256*1024)
  }
  #if canImport(CryptoKit)
  print("Apple external50: PASS (\(checks) shipping capture/controller/store checks; real CryptoKit; native IPC and file I/O boundaries doubled)")
  #else
  print("Apple external50: PASS (\(checks) shipping capture/controller/store checks; explicitly doubled hash, native IPC and file I/O)")
  #endif
 }
}
'''


def source():
    capture = (APP / "IOSDNSMeasurementClient.swift").read_text()
    capture = capture[capture.index("@MainActor struct IOSDNSMeasurementCapture"):capture.index("private final class IOSDNSMeasurementReply")]
    text = usage.BOUNDARY.split("@main struct Tests", 1)[0]
    text = text.replace("static var values: [String: Data]", "static var beforeWrite: (() -> Void)?\n    static var values: [String: Data]")
    text = text.replace("values[filename] = data; writes += 1", "beforeWrite?(); values[filename] = data; writes += 1")
    boundaries = telemetry.BOUNDARIES.split("final class NetworkProofGuard", 1)[0]
    # The shipping paired-entry serializer uses sorted keys and captures exact
    # bytes. Keep the explicit model boundary faithful to that source contract.
    boundaries = boundaries.replace("try entry.map{try JSONEncoder().encode($0)}", "try entry.map(encoded)")
    text += boundaries + NATIVE + capture
    for name in ("Models.swift", "IOSSessionIdentity.swift", "IOSSpeedLabOwnership.swift", "IOSMTUMeasurementGate.swift",
                 "IOSNodeLatencyStatistics.swift", "IOSNodeUsage.swift", "IOSMTUControl.swift", "IOSExternalNodeStatistics.swift", "IOSExternalNodeBenchmark.swift"):
        text += "\n" + (APP / name).read_text().replace("import Combine\n", "").replace("@preconcurrency import NetworkExtension\n", "").replace("import CryptoKit\n", "")
    text += (APP / "IOSHopMeasurements.swift").read_text().split("\nstruct IOSHopMeasurementsCard:", 1)[0].replace("import SwiftUI", "import Foundation").replace("@preconcurrency import NetworkExtension", "")
    return text + TESTS


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc required for actual Apple external50 orchestration")
    text = source()
    with tempfile.TemporaryDirectory(prefix="routervpn-ios-external50-") as directory:
        work = Path(directory)
        code, binary = work / "Fixture.swift", work / "fixture"
        command = [swift, "-swift-version", "6", "-strict-concurrency=complete", "-parse-as-library",
                   "-module-cache-path", str(work / "modules"), str(code), "-o", str(binary)]
        code.write_text(text)
        subprocess.run(command, check=True, timeout=150)
        subprocess.run([str(binary)], check=True, timeout=70)
        controls = [
            ("undrained completion", "if result.complete && result.drained { return }", "if result.complete { return }", "complete but undrained cannot publish"),
            ("saved profile source", "try captured.requireCurrent(model: model); try model.iosSpeedLabOwnership.require(owner)", "try model.iosSpeedLabOwnership.require(owner)", "cancel native selection"),
            ("strict sample count", "d.samples == 50", "d.samples >= 1", "invalid native result never saves: partial"),
            ("selected exit identity", "result.node_id == captured.nodeID, result.role", "result.role", "invalid native result never saves: wrong-node"),
            ("proved execution receipt", "try IOSExternalNodeStatistics.PathReceipt(binding: finalBinding, requested: requested, network: network) == path,", "true,", "changed native execution receipt never saves: winner-changed"),
        ]
        for name, before, after, expected in controls:
            if text.count(before) != 1:
                raise AssertionError("control lost exact source boundary: " + name)
            code.write_text(text.replace(before, after, 1))
            subprocess.run(command, check=True, timeout=150)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=70)
            if result.returncode == 0 or expected not in result.stderr:
                raise AssertionError(name + " did not reject the intended defect: " + result.stderr[-1600:])
            print("PASS negative control:", name, flush=True)


if __name__ == "__main__":
    main()
