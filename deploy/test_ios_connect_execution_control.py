#!/usr/bin/env python3
"""Exercise the actual Apple opaque restoration control with a real source/Last compiler.

Actual Go source and Last parsers are invoked. Native/OS live authority is not
constructed; in-memory private-store I/O is an explicit persistence boundary.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1];APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('saved_execution',ROOT/'deploy/test_ios_node_chain_execution_restore_last.py')
SAVED=importlib.util.module_from_spec(spec);spec.loader.exec_module(SAVED)
SWIFT=SAVED.SOURCE.SWIFT[:SAVED.SOURCE.SWIFT.index('@main struct Tests')]+r'''
@MainActor enum IOSPrivateJSONStore {
 static var bytes:Data?
 static func read(_ filename:String,maximumBytes:Int)throws->Data?{guard filename=="ordered-execution-last-v1.json",bytes==nil || bytes!.count<=maximumBytes else{throw NSError(domain:"PrivateStoreBoundary",code:1)};return bytes}
 static func write(_ data:Data,filename:String,maximumBytes:Int)throws{guard filename=="ordered-execution-last-v1.json",!data.isEmpty,data.count<=maximumBytes else{throw NSError(domain:"PrivateStoreBoundary",code:1)};bytes=data}
}
func connectFixture(_ kind:String,_ mode:String,_ requested:String,_ count:Int=3,_ layer:String="off")throws->[Data]{
 let raw=try LibboxTestCONNECTExecutionFixture(kind)
 let original=try (JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)}
 let middle=count-2,final=count-1
 var bundles:[Data]
 if count==3 && layer=="off" {bundles=original}else{bundles=try fixture(count,layer,requested,true)}
 if count != 3 || layer != "off" {
  // The constructed middle keeps its own record ID; copying the original
  // trio ID would alias the second paired prefix in a longer route.
  let id=try profile(bundles[middle])["id"] as! String
  let imported=try editProfile(original[1]){$0["id"]=id}
  bundles[middle]=try edit(imported){$0["selectedRouterID"]=id}
 }
 for position in bundles.indices {bundles[position]=try editProfile(bundles[position]){p in p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""}}
 let proxyID=try profile(bundles[middle])["id"] as! String
 bundles[final]=try editProfile(bundles[final]){p in
  p["multihop_execution"]=requested;p["startup_mode"]="manual";p["auto_connect"]=true;p["start_layer"]="off"
  var nodes=p["multihop_nodes"] as! [[String:Any]]
  for position in 0..<middle {nodes[position]["mode"]=mode}
  nodes[middle]=["id":proxyID,"mode":kind];p["multihop_nodes"]=nodes
 }
 bundles[final]=Data(try LibboxTestCONNECTService(String(decoding:bundles[final],as:UTF8.self)).utf8)
 return bundles
}
@MainActor final class Provider {
 let source:IOSNodeChainExecutionSession.Source
 var process=UUID().uuidString,generation="1",session=UUID().uuidString,selected="server"
 let token=String(repeating:"d",count:32)
 var owner="",captureID="",failCapture=false,failRelease=false,releaseFault="",ownerFault="",verifyFault=false
 var captures=0,releases=0
 init(_ source:IOSNodeChainExecutionSession.Source){self.source=source}
 func send(_ input:Data)async throws->Data{
  let q=try object(input),op=q["operation"] as! String,id=q["request_id"] as! String
  var r:[String:Any]
  if op=="ordered-execution-owner"{
   r=["schema":1,"kind":"routervpn-ordered-execution-owner","request_id":id,"session_id":session,"source_sha256":source.sourceSHA256,"preparation_config_sha256":source.configSHA256,"last":try LibboxTestSavedLast(source.input,selected),"process_id":process,"registry_generation":generation]
   if !ownerFault.isEmpty{r[ownerFault]="foreign"}
  }else if op=="ordered-execution-capture" || op=="ordered-execution-verify"{
   if op=="ordered-execution-capture" {
    guard q["process_id"] as? String==process,q["registry_generation"] as? String==generation,q["session_id"] as? String==session else{throw IOSNodeChainExecutionSession.issue()}
    captures+=1;owner=q["owner_id"] as! String;captureID=id
    if failCapture{throw IOSNodeChainExecutionSession.issue()}
   }
   r=["schema":1,"kind":"routervpn-ordered-execution-restore","request_id":id,"session_id":session,"source_sha256":source.sourceSHA256,"preparation_config_sha256":source.configSHA256,"owner_id":owner,"token":verifyFault ? String(repeating:"e",count:32):token,"execution":selected]
  }else if op=="ordered-execution-capture-release"{
   guard q["process_id"] as? String==process,q["registry_generation"] as? String==generation,q["session_id"] as? String==session,q["owner_id"] as? String==owner,q["capture_request_id"] as? String==captureID else{throw IOSNodeChainExecutionSession.issue()}
   if failRelease{throw IOSNodeChainExecutionSession.issue()};releases+=1
   r=["schema":1,"kind":"routervpn-ordered-execution-capture-release","request_id":id,"session_id":session,"owner_id":owner,"capture_request_id":captureID,"released":true,"process_id":process,"registry_generation":generation]
   if !releaseFault.isEmpty{r[releaseFault]="foreign"}
  }else{throw IOSNodeChainExecutionSession.issue()}
  return try data(r)
 }
}
@main struct Tests {
 @MainActor static func check(_ yes:Bool,_ name:String){if !yes{print("FAIL "+name);exit(1)}}
 @MainActor static func reject(_ name:String,_ run:()async throws->Void)async{do{try await run();print("FAIL ACCEPTED "+name);exit(1)}catch{}}
 @MainActor static func main()async throws{
  defer{LibboxTestClose()}
   for count in [3,4,8] {for kind in ["http-connect","https-connect"] {for requested in ["server","auto"] {
    let bundles=try connectFixture(kind,"wg",requested,count),source=try IOSNodeChainExecutionSession.Source.compile(bundles,requested:requested)
   let p=Provider(source),owner=UUID()
   let c=IOSNodeChainExecutionControl(source:source,owner:owner,send:p.send,current:{})
   try await c.capture();try await c.verify();check(try c.options()[IOSNodeChainExecutionSession.restoreKey] as? String==p.token,"opaque token retained")
   p.verifyFault=true;await reject("foreign verification token"){try await c.verify()};p.verifyFault=false
   for fault in ["process_id","registry_generation","capture_request_id","owner_id","released"]{
    p.releaseFault=fault;await reject("release "+fault){try await c.retire()}
   }
   p.releaseFault="";try await IOSNodeChainExecutionControl.requireAvailable();check(p.releases==6,"failed cleanup retained original owner")
   try await c.retire();check(p.releases==6,"cleanup idempotence")
   let late=Provider(source);late.failCapture=true;late.failRelease=true
   let pending=IOSNodeChainExecutionControl(source:source,owner:UUID(),send:late.send,current:{})
   await reject("late capture"){try await pending.capture()}
   await reject("unjoined pending capture"){try await IOSNodeChainExecutionControl.requireAvailable()}
   late.failRelease=false;try await IOSNodeChainExecutionControl.requireAvailable();check(late.releases==1,"capture intent retained before asynchronous failure")
    for selected in requested=="auto" ? ["local","server"]:["server"] {
    let original=Provider(source);original.selected=selected
    let control=IOSNodeChainExecutionControl(source:source,owner:UUID(),send:original.send,current:{})
    try await control.capture()
    let restored=Provider(source);restored.process=original.process;restored.generation="2";restored.selected=selected
    restored.session=original.session;await reject("same restored session"){try await control.proveRestored(send:restored.send,current:{})};restored.session=UUID().uuidString
    restored.generation="1";await reject("same restored generation"){try await control.proveRestored(send:restored.send,current:{})};restored.generation="2"
    restored.process=UUID().uuidString;await reject("foreign restored process"){try await control.proveRestored(send:restored.send,current:{})};restored.process=original.process
    restored.selected=selected=="local" ? "server":"local";await reject("changed restored winner"){try await control.proveRestored(send:restored.send,current:{})};restored.selected=selected
    try await control.proveRestored(send:restored.send,current:{})
    check(try IOSNodeChainExecutionLastStore.stored(for:source) != nil,"restored Last retained")
    await reject("consumed capsule"){_ = try control.options()}
    try await control.retire();check(original.releases==0,"consumed owner not released twice")
   }
   let stale=Provider(source);var current=true
   let staleControl=IOSNodeChainExecutionControl(source:source,owner:UUID(),send:stale.send,current:{if !current{throw IOSNodeChainExecutionSession.issue()}})
   try await staleControl.capture();current=false;await reject("replaced original owner"){try await staleControl.verify()};try await staleControl.retire()
   check(stale.releases==1,"stale owner cleanup remains scoped")
  }}}
  print("PASS Apple CONNECT control: original capture, exact owner, joined retirement, fresh same-winner restore")
 }
}
'''

def main():
 with tempfile.TemporaryDirectory(prefix='.ios-app-session-',dir=ROOT) as gd,tempfile.TemporaryDirectory(prefix='ios-app-session-') as wd:
  gd,work=Path(gd),Path(wd);(gd/'main.go').write_text(SAVED.GO);compiler=work/'compiler'
  subprocess.run(['go','build','-p','1','-o',str(compiler),str(gd/'main.go')],cwd=ROOT,check=True,timeout=180)
  (work/'Libbox.swift').write_text(SAVED.LIBBOX);(work/'CryptoKit.swift').write_text(SAVED.SOURCE.CRYPTO);(work/'Tests.swift').write_text(SWIFT)
  options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
  suffix='.dylib' if platform.system()=='Darwin' else '.so'
  subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(work/('libLibbox'+suffix))],check=True,timeout=90)
  link=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
  subprocess.run(options+link+['-emit-module','-emit-library','-module-name','CryptoKit',str(work/'CryptoKit.swift'),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit'+suffix))],check=True,timeout=90)
  command=options+link+['-lCryptoKit']+[str(APP/name) for name in ['Models.swift','IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeChainCONNECTCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainExecutionCapture.swift','IOSSessionIdentity.swift','IOSNodeChainExecutionSession.swift']]
  source=APP/'IOSNodeChainExecutionControl.swift';tests=work/'Tests.swift';binary=work/'baseline'
  subprocess.run(command+[str(source),str(tests),'-o',str(binary)],check=True,timeout=90)
  subprocess.run([str(binary),str(compiler)],check=True,timeout=180)

  original=source.read_text()
  for name,before,after,witness in (
   ('capture-intent','captureRequest = request // before the asynchronous provider worker','_ = request // omitted pre-worker intent','ACCEPTED release process_id'),
   ('same-winner','fresh.selected == restoration.execution','true','ACCEPTED changed restored winner'),
   ('same-process','fresh.process == original.process','true','ACCEPTED foreign restored process'),
   ('exact-release','value["registry_generation"] as? String == observation.generation,','true,','ACCEPTED release registry_generation'),
  ):
   assert original.count(before)==1,name
   mutant=work/(name+'.swift');mutant.write_text(original.replace(before,after,1))
   subprocess.run(command+[str(mutant),str(tests),'-o',str(binary)],check=True,timeout=90)
   result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
   assert result.returncode==1 and ('FAIL '+witness+'\n') in result.stdout+result.stderr,(name,result.returncode,(result.stdout+result.stderr)[-2000:])
   print('Rejected Apple CONNECT control omission:',name,flush=True)
if __name__=='__main__':main()
