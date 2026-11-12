#!/usr/bin/env python3
"""Exercise Apple app execution identity, exact provider replies and Last storage.

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
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ yes:Bool,_ name:String){guard yes else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ action:()throws->Void){do{try action();fatalError("ACCEPTED "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  let owner=UUID(),session=UUID().uuidString,id=String(repeating:"c",count:32),token=String(repeating:"d",count:32)
  for count in [2,3,8]{for awg in [false,true]{for selected in ["local","server"]{
   let bundles=try fixture(count,"off","auto",awg)
   let source=try IOSNodeChainExecutionSession.Source.compile(bundles,requested:"auto")
   let reopened=try IOSNodeChainExecutionSession.Source.reopen(source.input,finalProfileJSON:source.finalProfileJSON)
   check(reopened==source,"original source did not survive app handoff")
   let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles.last!,entryBundleData:nil,nodeChainExecutionSource:Data(source.input.utf8))
   check(source.matches(identity),"execution source was not retained in exact session identity")
   check(try IOSNodeChainExecutionSession.Source.capture(identity)==source,"active source lost the selected final profile")
   let foreignBundle=try editProfile(bundles.last!){$0["api_token"]="foreign-final"}
   let foreignIdentity=try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:foreignBundle,entryBundleData:nil,nodeChainExecutionSource:identity.nodeChainExecutionSource)
   reject("changed active final source"){_ = try IOSNodeChainExecutionSession.Source.capture(foreignIdentity)}
   let configuration:[String:Any]=["nodeChainExecutionSource":source.input]
   let observed=try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:identity.bundleData,configuration:configuration)
   check(observed==identity && observed.nodeChainSource==nil,"execution borrowed Local identity")
   reject("mixed original entry source"){_ = try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:identity.bundleData,entryBundleData:Data("entry".utf8),nodeChainExecutionSource:Data(source.input.utf8))}
   reject("mixed Local and execution"){_ = try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:identity.bundleData,entryBundleData:nil,nodeChainSource:Data(source.input.utf8),nodeChainExecutionSource:Data(source.input.utf8))}
   let originalLast=try LibboxTestSavedLast(source.input,selected)
   var receipt:[String:Any]=["schema":1,"kind":"routervpn-ordered-execution-last","request_id":id,"session_id":session,"source_sha256":source.sourceSHA256,"preparation_config_sha256":source.configSHA256,"last":originalLast]
   let last=try IOSNodeChainExecutionSession.Last.decode(data(receipt),source:source,request:id)
   try IOSNodeChainExecutionLastStore.record(last)
   check(try IOSNodeChainExecutionLastStore.stored(for:source)==originalLast,"durable Last lost original exact source")
   let retained=try IOSNodeChainExecutionLastStore.stored(for:source)!
   try source.validateLast(retained)
   let startupOnly=try bundles.map{try editProfile($0){$0["startup_mode"]="last";$0["auto_connect"]=true}}
   let startupSource=try IOSNodeChainExecutionSession.Source.compile(startupOnly,requested:"auto")
   check(startupSource.input==source.input,"startup controls changed native path identity")
   try startupSource.validateLast(retained)
   check(try IOSNodeChainExecutionLastStore.stored(for:startupSource)==retained,"switching to Last lost the original proved execution")
   let restoredConfig=String(repeating:"f",count:64)
   receipt["preparation_config_sha256"]=restoredConfig
   _ = try IOSNodeChainExecutionSession.Last.decode(data(receipt),source:source,request:id)
   check(true,"actual typed configuration was relabeled as ordinary")
   for field in ["request_id","session_id","source_sha256","preparation_config_sha256","kind","last","extra"]{
    var bad=receipt;bad[field]="changed"
    reject("changed Last "+field){_ = try IOSNodeChainExecutionSession.Last.decode(data(bad),source:source,request:id)}
   }
   let restore:[String:Any]=["schema":1,"kind":"routervpn-ordered-execution-restore","request_id":id,"session_id":session,"owner_id":owner.uuidString,"token":token,"execution":selected,"source_sha256":source.sourceSHA256,"preparation_config_sha256":restoredConfig]
   let captured=try IOSNodeChainExecutionSession.Restoration.decode(data(restore),source:source,request:id,owner:owner)
   check(captured.source==source && captured.execution==selected && captured.options.count==2,"opaque restore option lost original choice/source")
   for field in ["request_id","session_id","owner_id","token","execution","source_sha256","preparation_config_sha256","kind","extra"]{
    var bad=restore;bad[field]="changed"
    reject("changed restore "+field){_ = try IOSNodeChainExecutionSession.Restoration.decode(data(bad),source:source,request:id,owner:owner)}
   }
   let raw=String(decoding:try data(restore),as:UTF8.self)
   reject("duplicate restore receipt"){_ = try IOSNodeChainExecutionSession.Restoration.decode(Data(raw.replacingOccurrences(of:"\"schema\":1",with:"\"schema\":1,\"schema\":1").utf8),source:source,request:id,owner:owner)}
   var changed=bundles;changed[0]=try editProfile(changed[0]){$0["api_token"]="changed-original-entry"}
   let replacement=try IOSNodeChainExecutionSession.Source.compile(changed,requested:"auto")
   let replacementLast=try IOSNodeChainExecutionLastStore.stored(for:replacement)
   check(!replacement.matches(identity) && replacementLast==nil,"changed original member reused Last/session identity")
  }}}
  for operation in ["ordered-execution-capture","ordered-execution-verify","ordered-execution-release"]{
   let message=try IOSNodeChainExecutionSession.request(operation:operation,id:id,session:operation=="ordered-execution-capture" ? "":session,owner:owner,token:operation=="ordered-execution-capture" ? "":token)
   check(try object(message)["owner_id"] as? String==owner.uuidString,"exact IPC owner lost")
   reject("missing original IPC owner"){_ = try IOSNodeChainExecutionSession.request(operation:operation,id:id)}
  }
  _ = try IOSNodeChainExecutionSession.request(operation:"ordered-execution-last",id:id)
  reject("Last borrowed restore owner"){_ = try IOSNodeChainExecutionSession.request(operation:"ordered-execution-last",id:id,owner:owner)}
  let old=IOSPrivateJSONStore.bytes
  for bad in [Data("{}".utf8),try data(["schema":2,"records":[]]),try data(["schema":1,"records":[["node":"bad","source":"bad","last":"{}"]]])]{
   IOSPrivateJSONStore.bytes=bad
   let bundles=try fixture(2,"off","auto",false),source=try IOSNodeChainExecutionSession.Source.compile(bundles,requested:"auto")
   reject("malformed private Last history"){_ = try IOSNodeChainExecutionLastStore.stored(for:source)}
  }
  IOSPrivateJSONStore.bytes=old
  print("PASS Apple execution app session: \(checks) checks")
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
  command=options+link+['-lCryptoKit']+[str(APP/name) for name in ['Models.swift','IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSNodeChainExecutionCapture.swift','IOSSessionIdentity.swift']]
  source=APP/'IOSNodeChainExecutionSession.swift';tests=work/'Tests.swift';binary=work/'baseline'
  subprocess.run(command+[str(source),str(tests),'-o',str(binary)],check=True,timeout=90)
  subprocess.run([str(binary),str(compiler)],check=True,timeout=180)
  text=source.read_text()
  for name,before,after,witness,count in (
   ('source','value["source_sha256"] as? String == source.sourceSHA256,','true,','ACCEPTED changed Last source_sha256',2),
   ('nonce','value["request_id"] as? String == request,','true,','ACCEPTED changed Last request_id',1),
   ('owner','value["owner_id"] as? String == owner.uuidString,','true,','ACCEPTED changed restore owner_id',1),
   ('canonical','try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) == data','true','ACCEPTED duplicate restore receipt',1),
   ('stored-source','record.source == source.sourceSHA256 else','true else','changed original member reused Last/session identity',1),
  ):
   assert text.count(before)==count,name
   mutant=work/(name+'.swift');mutant.write_text(text.replace(before,after));binary=work/name
   subprocess.run(command+[str(mutant),str(tests),'-o',str(binary)],check=True,timeout=90)
   result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
   assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-2000:])
   print('Rejected app execution control:',name,flush=True)
  capture=APP/'IOSNodeChainCapture.swift';capture_text=capture.read_text()
  for key in ('startup_mode','auto_connect'):
   before='        result.removeValue(forKey: "'+key+'")'
   assert capture_text.count(before)==1,key
   mutant=work/('capture-'+key+'.swift');mutant.write_text(capture_text.replace(before,'        // omitted startup-only normalization'))
   altered=[str(mutant) if item==str(capture) else item for item in command]
   binary=work/('normalization-'+key)
   subprocess.run(altered+[str(source),str(tests),'-o',str(binary)],check=True,timeout=90)
   result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
   assert result.returncode!=0 and 'startup controls changed native path identity' in result.stdout+result.stderr,(key,(result.stdout+result.stderr)[-1600:])
   print('Rejected startup-only normalization control:',key,flush=True)
if __name__=='__main__':main()
