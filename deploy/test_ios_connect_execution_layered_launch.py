#!/usr/bin/env python3
"""Execute selected final layers in actual CONNECT editor and launch callbacks.

Published complete-count/Off matrices stay unchanged. The original private
store, DNS preparation and NetworkExtension boundaries are explicit doubles;
the public callbacks and shared source/Last parsers are shipping code.
"""
import test_ios_connect_execution_launch as C
import test_ios_connect_execution_layered_control as L

TESTS=L.PRELUDE+r'''
@MainActor @main struct Tests {
 static var context="initial CONNECT source"
 static func check(_ good:Bool,_ name:String){if !good{print("FAIL "+name);exit(1)}}
 static func reject(_ name:String,_ action:()async throws->Void)async{do{try await action();print("FAIL ACCEPTED "+name);exit(1)}catch{}}
 static func main()async{do{try await run()}catch{print("FAIL Apple layered CONNECT launch "+context+": "+String(describing:error));exit(1)}}
 static func run()async throws {
  defer{LibboxTestClose()}
  for count in [4,8] {for finalLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {for requested in ["server","auto"] {
   let entryLayer=layeredCONNECTEntryLayer(count,finalLayer)
   for fault in ["none","cold-last-server","cold-last-local","middle-password","later-prefix-token","final-token","final-layer","cancel"] where (fault != "later-prefix-token" || count>3) && (fault != "cold-last-local" || requested=="auto") {
    context="CONNECT nodes=\(count) layer=\(finalLayer) execution=\(requested) fault=\(fault)"
    NETunnelProviderManager.reset();IOSNodeBundleStore.shared.records=[:];IOSPrivateJSONStore.bytes=nil
    let middle=count-2,final=count-1,bytes=try layeredCONNECTFixture(count,requested,finalLayer),nodes=try bytes.map{try JSONDecoder().decode(ClientBundle.self,from:$0)}
    let model=RouterVPNModel(),manager=NETunnelProviderManager(),selected=nodes[final]
    model.bundle=selected
    for node in nodes{IOSNodeBundleStore.shared.records[node.selectedRouterID]=try JSONEncoder().encode(node)}
    let capture=try model.captureIOSOrderedRoute(selected);defer{try? capture.close()}
    let selection=try IOSRuntimeSelector.selectNodeChain(capture)
    check(selection.nodeChainExecution==requested && capture.providerKey==IOSNodeChainProviderCapture.executionKey && capture.members.count==count,"layered CONNECT typed route precedes Local capture")
    check(capture.members[final].profile["start_layer"] as? String==finalLayer && capture.members.prefix(middle).allSatisfy{$0.profile["start_layer"] as? String==entryLayer},"public CONNECT capture keeps independent entry and final layers")
    NETunnelProviderManager.hook={phase in
     guard phase=="save" else{return}
     if fault=="middle-password"{let key=nodes[middle].selectedRouterID;IOSNodeBundleStore.shared.records[key]=try editProfile(IOSNodeBundleStore.shared.records[key]!){p in let key=layeredCONNECTKind(count).replacingOccurrences(of:"-",with:"_");var ext=p["external"] as! [String:Any],proxy=ext[key] as! [String:Any];proxy["password"]="changed-original-connect-password";ext[key]=proxy;p["external"]=ext}}
     if fault=="later-prefix-token"{let key=nodes[1].selectedRouterID;IOSNodeBundleStore.shared.records[key]=try editProfile(IOSNodeBundleStore.shared.records[key]!){$0["api_token"]="replacement-later-prefix"}}
     if fault=="final-token"{model.bundle?.routerProfiles[0].apiToken="foreign"}
     if fault=="final-layer"{model.bundle?.routerProfiles[0].startLayer="off"}
     if fault=="cancel"{model.iosConnectGeneration=UUID()}
    }
    if fault=="none" || fault.hasPrefix("cold-last-") {
     if fault.hasPrefix("cold-last-") {
      let source=try IOSNodeChainExecutionSession.Source.compile(bytes,requested:requested),id=String(repeating:"c",count:32)
      let winner=fault=="cold-last-local" ? "local":"server",record=try LibboxTestSavedLast(source.input,winner)
      let reply:[String:Any]=["schema":1,"kind":"routervpn-ordered-execution-last","request_id":id,"session_id":UUID().uuidString,"source_sha256":source.sourceSHA256,"preparation_config_sha256":source.configSHA256,"last":record]
      try IOSNodeChainExecutionLastStore.record(IOSNodeChainExecutionSession.Last.decode(data(reply),source:source,request:id))
      var lastSelected=selected;lastSelected.routerProfiles[0].startupMode="last";model.bundle=lastSelected
      _ = try await IOSSpeedLabContext.$startupAdmission.withValue({true}){try await model.launch(manager,lastSelected,selection)}
      check(manager.connection.options?[IOSNodeChainExecutionSession.lastKey] as? String==record,"layered CONNECT cold Last carries original winner without Compare rerank")
     }else{_ = try await model.launch(manager,selected,selection)}
     let config=(manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
     check(NETunnelProviderManager.starts==1 && config[IOSNodeChainProviderCapture.executionKey] as? String==capture.launchInput && config[IOSNodeChainSOCKSCapture.providerKey]==nil && config[IOSNodeChainCONNECTCapture.providerKey]==nil,"layered CONNECT execution source handed to original manager")
     let replay=try IOSNodeChainExecutionCapture.reopen(config[IOSNodeChainProviderCapture.executionKey] as! String,selectedProfile:profile(bytes[final]));try replay.close()
     check(!model.connected,"CONNECT preference save is not native proof")
    }else{
     await reject("stale launch "+fault){_ = try await model.launch(manager,selected,selection)}
     check(NETunnelProviderManager.starts==0,"stale CONNECT source never starts native")
    }
   }
  }}}
  try editor()
  print("PASS Apple layered CONNECT public launch: original sources, independent layers, exact Last winner, editor and private-source cancellation")
 }
 static func editor()throws {
  for count in [4,8] {for finalLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {for requested in ["server","auto"] {
   let entryLayer=layeredCONNECTEntryLayer(count,finalLayer)
   for fault in ["none","later-prefix","proxy-source","during-DNS","write"] {
    context="CONNECT editor nodes=\(count) layer=\(finalLayer) execution=\(requested) fault=\(fault)"
    IOSNodeBundleStore.shared.records=[:];IOSDNSRuntimePolicy.beforePatch=nil
    var nodes=try layeredCONNECTFixture(count,requested,finalLayer).map{try JSONDecoder().decode(ClientBundle.self,from:$0)}
    nodes[count-1].routerProfiles[0].multihopExecution="local"
    let model=RouterVPNModel();model.bundle=nodes.last!
    for node in nodes{IOSNodeBundleStore.shared.records[node.selectedRouterID]=try JSONEncoder().encode(node)}
    let owner=try model.captureIOSNodeChainEditorOwner(),selection=model.selectedNodeProfile!.multihopNodes!
    check(IOSNodeChainEditorVisible.candidates(model.iosNodeChainEditorProfiles(owner:owner),nodes:selection,position:count-2).contains{$0.id==nodes[count-2].selectedRouterID},"layered CONNECT editor retains original visible proxy")
    let change={@MainActor in let key=nodes[count-3].selectedRouterID;IOSNodeBundleStore.shared.records[key]=try editProfile(IOSNodeBundleStore.shared.records[key]!){$0["api_token"]="replacement-later-prefix"}}
    if fault=="later-prefix"{try change()}
    if fault=="proxy-source"{let key=nodes[count-2].selectedRouterID;IOSNodeBundleStore.shared.records[key]=try editProfile(IOSNodeBundleStore.shared.records[key]!){$0["name"]="replacement-proxy"}}
    if fault=="during-DNS"{IOSDNSRuntimePolicy.beforePatch=change}
    model.failLinkedWrite=fault=="write"
    if fault=="none" {
     try model.saveIOSNodeChain(selection,owner:owner,execution:requested)
     check(model.linkedWrites==1 && model.selectedNodeProfile?.multihopExecution==requested && model.selectedNodeProfile?.startLayer==finalLayer,"layered CONNECT editor saves original choice and final layer once")
     let capture=try model.captureIOSOrderedRoute(model.bundle!);defer{try? capture.close()}
     check(capture.providerKey==IOSNodeChainProviderCapture.executionKey && capture.members.map(\.id)==selection.map(\.id),"layered CONNECT editor compiles every original member before saving")
    }else{
     do{try model.saveIOSNodeChain(selection,owner:owner,execution:requested);check(false,"ACCEPTED layered CONNECT editor "+fault)}catch{}
     check(model.linkedWrites==0 && model.selectedNodeProfile?.multihopExecution=="local","failed layered CONNECT save preserves original selection and storage")
    }
   }
  }}}
 }
}
'''


def main():
    C.TESTS=TESTS
    C.main(label="layered CONNECT")


if __name__=='__main__':main()
