#!/usr/bin/env python3
"""Execute captured ordered map paths and the shipping progress callback.

The private graph source comes from the actual Go compiler. MapKit and
NetworkExtension are explicit boundaries here; actual SDK map compilation is
also required by test_apple_vector_map.py in the Apple shipping lanes.
"""
from pathlib import Path
import argparse
import importlib.util
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('ordered_presentation_launch', ROOT / 'deploy/test_ios_node_chain_launch.py')
L = importlib.util.module_from_spec(spec); spec.loader.exec_module(L)
C, S = L.C, L.S

BODY = r'''
import Foundation
import Libbox
// NETWORK_BOUNDARY
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?,allNodeProfiles:[RouterProfile]=[],activeSessionIdentity:IOSSessionIdentity?
 var connected=false,tunnelTransitioning=false,profileMutationBlocked=false,iosCandidateTesting=false
 var multihopProgressInFlight:UUID?,multihopProgressDeadline=Date.distantPast
 var multihopProgressGeneration=UUID(),iosConnectGeneration=UUID(),multihopProgressText=""
 var selectedNodeProfile:RouterProfile?{bundle?.routerProfiles.first(where:{$0.id==bundle?.selectedRouterID})}
 // SHIPPING_PROGRESS
}
struct CLLocationCoordinate2D:Equatable {var latitude:Double=0,longitude:Double=0}
@MainActor class MKPointAnnotation {
 var coordinate=CLLocationCoordinate2D(),title:String?,subtitle:String?
}
// SHIPPING_ANNOTATION
@MainActor final class Line {
 let a:CLLocationCoordinate2D,b:CLLocationCoordinate2D
 var title:String?
 init(_ a:CLLocationCoordinate2D,_ b:CLLocationCoordinate2D){self.a=a;self.b=b}
}
@MainActor final class MKMapView {
 enum Level{case aboveLabels}
 var annotations:[MKPointAnnotation]=[],overlays:[Line]=[],fits=0
 func removeAnnotations(_ nodes:[MKPointAnnotation]) {annotations.removeAll{item in nodes.contains{$0 === item}}}
 func removeAnnotation(_ node:MKPointAnnotation){removeAnnotations([node])}
 func addAnnotation(_ node:MKPointAnnotation){annotations.append(node)}
 func addOverlays(_ lines:[Line],level:Level){overlays+=lines}
 func showAnnotations(_ nodes:[MKPointAnnotation],animated:Bool){fits+=1}
}
@MainActor enum RouterVPNVectorMap {
 static func clearRoutes(on map:MKMapView){map.overlays=[]}
 static func routes(from a:CLLocationCoordinate2D,to b:CLLocationCoordinate2D)->[Line]{[Line(a,b)]}
}
@MainActor struct IOSUnifiedMap {
 let model:RouterVPNModel
 var latencyByID:[String:Double]=[:]
 struct Context{let coordinator:Coordinator}
 @MainActor final class Coordinator {
  var parent:IOSUnifiedMap,path:[CLLocationCoordinate2D]=[],fittedGeometryID=""
  fileprivate var packet:IOSUnifiedMapAnnotation?
  init(_ parent:IOSUnifiedMap){self.parent=parent}
  // SHIPPING_ENSURE_PACKET
 }
 // SHIPPING_MAP_UPDATE
}
'''

SESSION = r'''@MainActor final class NETunnelProviderSession:NEVPNConnection {
 weak var manager:NETunnelProviderManager?
 var requests=0,callback:((Data?)->Void)?
 func sendProviderMessage(_ data:Data,responseHandler:((Data?)->Void)?)throws{requests+=1;callback=responseHandler}
 func deliver(_ data:Data?){let response=callback;callback=nil;response?(data)}
}'''

TESTS = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ ok:@autoclosure ()throws->Bool)throws {
  guard try ok()else{throw IOSNodeChainCapture.issue("FAIL "+name)};checks+=1
 }
 static func encoded(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
 static func bundleData(_ bundle:ClientBundle)throws->Data {let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys];return try encoder.encode(bundle)}
 // ORIGINAL_COMPILER_SOURCES
 static func setup(_ count:Int=4,_ mixed:Bool=false)throws->(RouterVPNModel,NETunnelProviderManager,[ClientBundle]) {
  NETunnelProviderManager.reset()
  var nodes=try sources(count,mixed)
  for i in nodes.indices{nodes[i].routerProfiles[0].name="Original node \(i)";nodes[i].routerProfiles[0].latitude=20+Double(i)*7;nodes[i].routerProfiles[0].longitude = -120+Double(i)*25}
  let source=try IOSNodeChainCapture.compile(bundles:nodes.map{try bundleData($0)});defer{try? source.plan.close()}
  let model=RouterVPNModel(),manager=NETunnelProviderManager(),proto=NETunnelProviderProtocol()
  let data=try bundleData(nodes.last!),connectedAt=Date(timeIntervalSince1970:123456)
  model.bundle=nodes.last;model.allNodeProfiles=nodes.flatMap(\.routerProfiles);model.connected=true
  model.activeSessionIdentity=try IOSSessionIdentity(connectedAt:connectedAt,engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:data,entryBundleData:nil,nodeChainSource:Data(source.launchInput.utf8))
  proto.providerBundleIdentifier="com.eabusham.routervpn.PacketTunnel"
  proto.providerConfiguration=["bundle":data,"engine":"multihop-libbox","mode":"shadowsocks","rawProfileID":"shadowsocks","nodeChainSource":source.launchInput]
  manager.protocolConfiguration=proto;manager.connection.status = .connected;manager.connection.connectedDate=connectedAt
  return(model,manager,nodes)
 }
 static func progress(_ count:Int)->[String:Any] {
  ["stage":"selected","complete":true,"ready":true,"execution":"local","dns_proven":true,"public_proven":true,
   "prefixes":(0..<count).map{["position":$0,"profile_id":"chain-node-\($0)","response_ms":Double($0+1)*2.5,"proven":true] as [String:Any]}]
 }
 static func settle(_ model:RouterVPNModel)async {
  for _ in 0..<100{if model.multihopProgressInFlight==nil{return};await Task.yield()}
 }
 static func main()async {
  defer{LibboxTestClose()}
  do{try await run();print("Apple ordered presentation: PASS (\(checks) shipping Swift/shared Go checks; MapKit and IPC boundaries)")}
  catch{FileHandle.standardError.write(Data((error.localizedDescription+"\n").utf8));exit(1)}
 }
 static func run()async throws {
  do {
   var nodes=try sources(3)
   var custom=nodes[1].routerProfiles[0]
   custom.nodeKind="external";custom.nodeProofID=nil;custom.routerAPI="";custom.apiToken=""
   custom.external=try JSONDecoder().decode(ExternalNodeConfig.self,from:encoded(["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":"198.51.100.76","port":443,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:0,count:32).base64EncodedString()]]))
   custom.startLayer="off";nodes[1].routerProfiles=[custom];nodes[1].nodeProofID="";nodes[1].profiles=[:]
   nodes[2].routerProfiles[0].multihopNodes?[1].mode="shadowsocks"
   let captured=try IOSNodeChainCapture.compile(bundles:nodes.map{try bundleData($0)});defer{try? captured.plan.close()}
   let points=IOSNodeChainPresentation.captured(source:Data(captured.launchInput.utf8),bundleData:try bundleData(nodes[2]))
   try check("custom middle map retains original external identity",points?.count==3 && points?[1].id==custom.id && points?[1].kind=="external" && points?[1].mode=="shadowsocks")
   var value=progress(3),rows=value["prefixes"] as! [[String:Any]];rows[1]["kind"]="public-path";value["prefixes"]=rows
   let text=IOSNodeChainPresentation.progress(value,expected:nodes.map(\.selectedRouterID))
   try check("custom middle timing uses truthful public path wording",text?.contains("public path via custom node")==true && text?.components(separatedBy:"verification HTTP response").count==3)
  }
  do {
   let(model,_,_)=try setup(4,true)
   let modes=["awg2-fast","awg2-strong","wg","shadowsocks"]
   try check("active mixed path retains exact raw modes",model.iosVisibleOrderedNodePath?.compactMap(\.mode)==modes)
   model.connected=false;model.activeSessionIdentity=nil
   try check("planned mixed path retains exact raw modes",model.iosVisibleOrderedNodePath?.compactMap(\.mode)==modes)
  }
  for count in [2,3,4,8] {
   let(model,_,original)=try setup(count),path=model.iosVisibleOrderedNodePath!
   try check("actual captured path retains every ordered member",path.map(\.id)==original.map(\.selectedRouterID) && path.count==count)
   model.allNodeProfiles[1].name="Relinked display";model.allNodeProfiles[1].latitude=1
   try check("connected map keeps original middle source",model.iosVisibleOrderedNodePath==path && model.iosMapNodePoints.first(where:{$0.id==path[1].id})==path[1])
   let view=IOSUnifiedMap(model:model),coordinator=IOSUnifiedMap.Coordinator(view),map=MKMapView()
   view.updateUIView(map,context:.init(coordinator:coordinator))
   try check("all adjacent captured route legs are drawn",map.overlays.count==count-1 && coordinator.path.count==count)
   for (position,line) in map.overlays.enumerated() {
    try check("route keeps intermediate endpoint \(position)",line.a.latitude==path[position].latitude! && line.b.latitude==path[position+1].latitude!)
   }
   let annotations=map.annotations.compactMap{$0 as? IOSUnifiedMapAnnotation}.filter{$0.role != "packet"}
   try check("entry final and every middle have distinct roles",annotations.first(where:{$0.profileID==path.first!.id})?.role=="entry" && annotations.first(where:{$0.profileID==path.last!.id})?.role=="exit" && annotations.filter{$0.role=="hop"}.count==count-2)
   try check("verified complete route animates a single packet",coordinator.packet != nil && map.annotations.filter{($0 as? IOSUnifiedMapAnnotation)?.role=="packet"}.count==1)
   view.updateUIView(map,context:.init(coordinator:coordinator))
   try check("refresh replaces rather than duplicates route",map.overlays.count==count-1 && map.annotations.count==count+1)
   model.iosCandidateTesting=true
   view.updateUIView(map,context:.init(coordinator:coordinator))
   try check("temporary Testing uses saved path without live packet animation",model.iosVisibleOrderedNodePath?[1].latitude==1 && coordinator.packet==nil && map.annotations.count==count)
   model.iosCandidateTesting=false
   model.connected=false
   view.updateUIView(map,context:.init(coordinator:coordinator))
   try check("idle route shows changed planned coordinate without animation",model.iosVisibleOrderedNodePath?[1].latitude==1 && coordinator.packet==nil && map.annotations.count==count)
  }
  do {
   let(model,_,original)=try setup(4)
   model.connected=false;model.allNodeProfiles[1].latitude=nil
   let view=IOSUnifiedMap(model:model),coordinator=IOSUnifiedMap.Coordinator(view),map=MKMapView()
   view.updateUIView(map,context:.init(coordinator:coordinator))
   try check("missing middle coordinate cannot draw an invented shortcut",map.overlays.count==1 && map.overlays[0].a.latitude==original[2].routerProfiles[0].latitude! && map.overlays[0].b.latitude==original[3].routerProfiles[0].latitude! && coordinator.path.isEmpty && coordinator.packet==nil)
   model.connected=true;model.activeSessionIdentity=nil
   view.updateUIView(map,context:.init(coordinator:coordinator))
   try check("unread active source never adopts current planned graph",map.overlays.isEmpty && coordinator.packet==nil && model.iosVisibleOrderedNodePath==nil)
  }
  for fault in ["source-kind","projection","wrong-final","middle-mode","duplicate-node","source-hash","bundle-owner"] {
   let(model,_,_)=try setup(),identity=model.activeSessionIdentity!
   var root=try JSONSerialization.jsonObject(with:identity.nodeChainSource!) as! [String:Any]
   var data=identity.bundleData
   switch fault {
   case "source-kind":root["kind"]="another-source"
   case "projection":root["target_os"]="linux"
   case "wrong-final":var nodes=root["nodes"] as! [String];nodes.swapAt(0,nodes.count-1);root["nodes"]=nodes
   case "middle-mode":var nodes=root["nodes"] as! [String],member=try JSONSerialization.jsonObject(with:Data(nodes[1].utf8)) as! [String:Any];member["mode"]="hysteria2";nodes[1]=String(decoding:try encoded(member),as:UTF8.self);root["nodes"]=nodes
   case "duplicate-node":var nodes=root["nodes"] as! [String];nodes[1]=nodes[0];root["nodes"]=nodes
   case "source-hash":root["source_sha256"]="unverified"
   case "bundle-owner":var bundle=try JSONDecoder().decode(ClientBundle.self,from:data);bundle.routerProfiles[0].apiToken="different-final";data=try bundleData(bundle)
   default:fatalError()
   }
   try check("malformed display source refused "+fault,IOSNodeChainPresentation.captured(source:try encoded(root),bundleData:data)==nil)
  }
  let expected=(0..<4).map{"chain-node-\($0)"}
  let text=IOSNodeChainPresentation.progress(progress(4),expected:expected)!
  try check("all prefix timing labels state startup verification HTTP",text.components(separatedBy:"verification HTTP response").count==5 && !text.contains("HTTPS") && !text.contains("ICMP") && !text.contains("live RTT"))
  try check("each middle and final proof is visible",text.contains("Hop 1 · chain-node-1") && text.contains("Hop 2 · chain-node-2") && text.contains("Exit · chain-node-3") && text.contains("Final-path DNS verified") && text.contains("Final public exit verified"))
  for fault in ["wrong-id","reordered","bool-response","zero-response","infinite-response","bool-position","unproved","server","unknown-stage"] {
   var value=progress(4),rows=value["prefixes"] as! [[String:Any]]
   switch fault {
   case "wrong-id":rows[1]["profile_id"]="other-middle"
   case "reordered":rows.swapAt(1,2)
   case "bool-response":rows[1]["response_ms"]=true
   case "zero-response":rows[1]["response_ms"]=0
   case "infinite-response":rows[1]["response_ms"]=Double.infinity
   case "bool-position":rows[1]["position"]=true
   case "unproved":rows[1]["proven"]=false
   case "server":value["execution"]="server"
   case "unknown-stage":value["stage"]="connected"
   default:fatalError()
   }
   value["prefixes"]=rows
   try check("invalid ordered progress rejected "+fault,IOSNodeChainPresentation.progress(value,expected:expected)==nil)
  }
  do {
   var value=progress(4);value["prefixes"]=Array((value["prefixes"] as! [[String:Any]]).prefix(2));value["stage"]="verifying";value["ready"]=false;value["complete"]=false;value["dns_proven"]=false;value["public_proven"]=false
   let partial=IOSNodeChainPresentation.progress(value,expected:expected)!
   try check("partial proof cannot claim complete path",partial.contains("Verified 2 of 4") && !partial.contains("Every captured") && !partial.contains("Final-path DNS verified"))
  }
  for fault in ["none","identity","generation","source","bundle","connected-date","stopped","deadline","wrong-prefix"] {
   let(model,manager,_)=try setup(),session=manager.connection as! NETunnelProviderSession,proto=manager.protocolConfiguration as! NETunnelProviderProtocol
   await model.refreshIOSMultihopExecutionProgress()
   try check("one captured IPC starts "+fault,session.requests==1)
   await model.refreshIOSMultihopExecutionProgress()
   try check("in-flight progress cannot enqueue a second request",session.requests==1)
   var value=progress(4)
   switch fault {
   case "identity":model.activeSessionIdentity=nil
   case "generation":model.iosConnectGeneration=UUID()
   case "source":proto.providerConfiguration?["nodeChainSource"]="new-private-source"
   case "bundle":proto.providerConfiguration?["bundle"]=Data("replacement-bundle".utf8)
   case "connected-date":session.connectedDate=Date()
   case "stopped":session.status = .disconnected
   case "deadline":model.multihopProgressDeadline = .distantPast
   case "wrong-prefix":var rows=value["prefixes"] as! [[String:Any]];rows[1]["profile_id"]="wrong-node";value["prefixes"]=rows
   default:break
   }
   session.deliver(try encoded(value));await settle(model)
   try check("late progress ownership "+fault,(fault=="none") == model.multihopProgressText.contains("verification HTTP response"))
  }
  for fault in ["duplicate-manager","initial-source","initial-generation"] {
   let(model,manager,_)=try setup(),session=manager.connection as! NETunnelProviderSession
   NETunnelProviderManager.hook={phase in
    guard phase=="load-all" else{return}
    if fault=="duplicate-manager" {let other=NETunnelProviderManager();other.protocolConfiguration=manager.protocolConfiguration}
    if fault=="initial-source" {(manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration?["nodeChainSource"]="foreign-source"}
    if fault=="initial-generation" {model.iosConnectGeneration=UUID()}
   }
   await model.refreshIOSMultihopExecutionProgress()
   try check("changed initial manager cannot send progress "+fault,session.requests==0)
  }
  do {
   let(model,manager,original)=try setup(2),proto=manager.protocolConfiguration as! NETunnelProviderProtocol,session=manager.connection as! NETunnelProviderSession
   var selected=original[1];selected.routerProfiles[0].multihopNodes=nil;selected.routerProfiles[0].multihopEntryID=original[0].selectedRouterID;selected.routerProfiles[0].multihopExitID=selected.selectedRouterID
   let data=try bundleData(selected),entry=try bundleData(original[0]);model.bundle=selected
   proto.providerConfiguration?["bundle"]=data;proto.providerConfiguration?.removeValue(forKey:"nodeChainSource");proto.providerConfiguration?["entryBundle"]=entry
   model.activeSessionIdentity=try IOSSessionIdentity(connectedAt:session.connectedDate!,engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:data,entryBundleData:entry)
   await model.refreshIOSMultihopExecutionProgress()
   let value:[String:Any]=["stage":"selected","execution":"local","measurements":[["candidate":["execution":"local"],"eligible":true,"last_node_ms":20.0,"external_ms":40.0,"score_ms":30.0],["candidate":["execution":"server"],"eligible":false,"failure":"timeout"]]]
   session.deliver(try encoded(value));await settle(model)
   try check("legacy pair formula and failure retain original labels",model.multihopProgressText.contains("/ 2 = 30.0 ms") && model.multihopProgressText.contains("server: rejected") && !model.multihopProgressText.contains("verification HTTP"))
  }
 }
}
'''


def main(selected_mutations=None):
    network = S.BOUNDARIES[S.BOUNDARIES.index('enum NEVPNStatus'):S.BOUNDARIES.index('enum IOSRuntimeSelectionError')]
    network = network.replace('@MainActor final class NETunnelProviderSession:NEVPNConnection { weak var manager:NETunnelProviderManager? }', SESSION)
    body = BODY.replace('// NETWORK_BOUNDARY', network)
    progress = S.member((APP / 'IOSMultihopProgress.swift').read_text(), '    func refreshIOSMultihopExecutionProgress(')
    ui = (APP / 'IOSUnifiedProductView.swift').read_text()
    annotation = ui[ui.index('private final class IOSUnifiedMapAnnotation:'):ui.index('struct IOSUnifiedMap:')]
    body = body.replace('// SHIPPING_PROGRESS', progress).replace('// SHIPPING_ANNOTATION', annotation)
    body = body.replace('// SHIPPING_MAP_UPDATE', S.member(ui, '    func updateUIView('))
    body = body.replace('// SHIPPING_ENSURE_PACKET', S.member(ui, '        func ensurePacket('))
    tests = TESTS.replace('// ORIGINAL_COMPILER_SOURCES', S.member(L.TESTS, ' static func sources('))
    presentation = (APP / 'IOSNodeChainPresentation.swift').read_text()
    with tempfile.TemporaryDirectory(prefix='.ios-chain-presentation-', dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-chain-presentation-') as directory:
        go_dir, work = Path(go_dir), Path(directory)
        (go_dir / 'main.go').write_text(C.GO); compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-p', '1', '-o', str(compiler), str(go_dir / 'main.go')], cwd=ROOT, check=True, timeout=180)
        lib = work / 'Libbox.swift'; lib.write_text(C.LIBBOX)
        code = work / 'Tests.swift'; code.write_text(body + tests)
        source = work / 'IOSNodeChainPresentation.swift'; source.write_text(presentation)
        options = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        library = work / ('libLibbox.dylib' if platform.system() == 'Darwin' else 'libLibbox.so')
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(lib), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(library)], check=True, timeout=90)
        command = options + ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        command += [str(APP / name) for name in ('Models.swift', 'IOSSessionIdentity.swift', 'IOSMultihopStartLayer.swift', 'IOSNodeChainCapture.swift')]
        binary = work / 'tests'; command += [str(source), str(code), '-o', str(binary)]
        subprocess.run(command, check=True, timeout=120)
        subprocess.run([str(binary), str(compiler)], check=True, timeout=180)
        mutants = (
            ('testing-map-source', presentation.replace('if connected && !iosCandidateTesting {', 'if connected {', 1), body, 'FAIL temporary Testing uses saved path without live packet animation'),
            ('testing-map-animation', presentation, body.replace('if model.connected && !model.iosCandidateTesting { context.coordinator.ensurePacket(on: map) }', 'if model.connected { context.coordinator.ensurePacket(on: map) }', 1), 'FAIL temporary Testing uses saved path without live packet animation'),
            ('mutable-map-source', presentation.replace('if connected && !iosCandidateTesting { return IOSNodeChainPresentation.active(activeSessionIdentity) }', 'if false { return IOSNodeChainPresentation.active(activeSessionIdentity) }', 1), body, 'FAIL connected map keeps original middle source'),
            ('middle-map-shortcut', presentation, body.replace('let routeIDs = ordered?.map(\\.id)', 'let routeIDs = ordered.map { [$0.first!.id, $0.last!.id] }', 1), 'FAIL all adjacent captured route legs are drawn'),
            ('stale-session', presentation, body.replace('self.activeSessionIdentity == identity,', 'true,', 1), 'FAIL late progress ownership identity'),
            ('stale-provider-source', presentation, body.replace('current["nodeChainSource"] as? String == chainSource,', 'true,', 1), 'FAIL late progress ownership source'),
        )
        for name, changed_source, changed_body, failure in mutants:
            if selected_mutations and name not in selected_mutations: continue
            assert changed_source != presentation or changed_body != body, name + ' missing mutation'
            source.write_text(changed_source); code.write_text(changed_body + tests)
            subprocess.run(command, check=True, timeout=120)
            rejected = subprocess.run([str(binary), str(compiler)], capture_output=True, text=True, timeout=180)
            assert rejected.returncode != 0 and failure in rejected.stdout + rejected.stderr, name + ': no causal rejection: ' + (rejected.stdout + rejected.stderr)[-1800:]
            print('Rejected ordered presentation defect mutation: ' + name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutation', action='append', choices=['testing-map-source', 'testing-map-animation', 'mutable-map-source', 'middle-map-shortcut', 'stale-session', 'stale-provider-source'])
    main(parser.parse_args().mutation)
