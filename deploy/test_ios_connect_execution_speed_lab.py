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
spec=importlib.util.spec_from_file_location("speed_original",ROOT/"deploy/test_ios_speed_lab_tunnel.py")
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
spec=importlib.util.spec_from_file_location("control_original",ROOT/"deploy/test_ios_connect_execution_control.py")
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)

SWIFT=C.SWIFT[:C.SWIFT.index('@main struct Tests')]
SHIM=T.SHIM[:T.SHIM.index('@MainActor @main struct Tests')]
SHIM=SHIM.replace('var starts=0,stops=0', 'var provider:Provider?\n var starts=0,stops=0')
SHIM=SHIM.replace('func sendProviderMessage(_ data:Data,responseHandler:((Data?)->Void)?)throws{throw CancellationError()}', 'func sendProviderMessage(_ data:Data,responseHandler:((Data?)->Void)?)throws{guard let provider else{throw CancellationError()};Task{@MainActor in do{responseHandler?(try await provider.send(data))}catch{responseHandler?(nil)}}}')
SHIM=SHIM.replace('func startVPNTunnel(options:[String:NSObject]?=nil)throws{', '''func startVPNTunnel(options:[String:NSObject]?=nil)throws{
  if let provider {
   guard options?[IOSNodeChainExecutionSession.restoreKey] as? String==provider.token,options?[IOSNodeChainExecutionSession.restoreOwnerKey] as? String==provider.owner else{throw CancellationError()}
   provider.session=UUID().uuidString;provider.generation="2"
  }
''')
SHIM=SHIM.replace('config["nodeChainSource"] == nil,', 'config["nodeChainExecutionSource"] == nil, config["nodeChainSource"] == nil,')
refresh=T.declaration((APP/'RouterVPNModel.swift').read_text(),'    func refreshTunnelStatus() async {')
old_refresh=T.declaration(SHIM,' func refreshTunnelStatus()async {')
SHIM=SHIM.replace(old_refresh,refresh)
SHIM=SHIM.replace('let iosSpeedLabOwnership=IOSSpeedLabOwnership()', 'let iosSpeedLabOwnership=IOSSpeedLabOwnership()\n var userDisconnectInProgress:Bool{iosUserDisconnectInProgress};var iosStrategyStatus:IOSStrategyStatus?;var activeEngine="",activeRawProfile=""\n func iosAdoptStrategyStatus(_ status:IOSStrategyStatus,manager:NETunnelProviderManager,bundleData:Data)throws{throw CancellationError()}')
SHIM+=r'''
enum IOSRuntimeSelectionError:Error{case unsupportedMode(String)}
enum IOSNodeCandidatePrefixProviderCapture{static let key="candidatePrefixSource",engine="candidate-prefix-libbox"}
@MainActor enum IOSStrategyTransport{static func send(_ connection:NETunnelProviderSession,request:[String:String])async throws->Data{throw CancellationError()}}
'''
TESTS=r'''
@MainActor @main struct Tests {
 static func check(_ good:Bool,_ name:String){if !good{print("FAIL "+name);exit(1)}}
 static func reject(_ name:String,_ action:()async throws->Void)async{do{try await action();print("FAIL ACCEPTED "+name);exit(1)}catch{}}
 static func main()async throws{
  defer{LibboxTestClose()}
  for family in ["connect","paired-two","paired-eight","imported","imported-eight"]{for selected in ["local","server"]{for reconnect in [false,true]{
   NETunnelProviderManager.stored=[];FixtureClock.value=0
   let raw:[Data]
   switch family {
   case "paired-two":raw=try fixture(2,"off","auto",false)
   case "paired-eight":raw=try fixture(8,"off","auto",true)
   case "imported":raw=try importedFixture("auto","awg2-strong","2022-blake3-aes-256-gcm")
   case "imported-eight":raw=try importedFixture("auto","awg2-strong","2022-blake3-aes-256-gcm",8)
   default:raw=try connectFixture("http-connect","wg","auto")
   }
   let bytes=try appFixture(raw),source=try IOSNodeChainExecutionSession.Source.compile(bytes,requested:"auto")
   let provider=Provider(source);provider.selected=selected
   let model=RouterVPNModel(),manager=NETunnelProviderManager(),proto=NETunnelProviderProtocol()
   proto.providerBundleIdentifier="com.eabusham.routervpn.PacketTunnel";proto.serverAddress="original"
   proto.providerConfiguration=["engine":"multihop-libbox","rawProfileID":"shadowsocks","mode":"shadowsocks","bundle":bytes.last!,"nodeChainExecutionSource":source.input]
   manager.protocolConfiguration=proto;manager.connection.provider=provider;manager.onDemandRules=[NEOnDemandRuleConnect()]
   NETunnelProviderManager.stored=[manager]
   provider.ownerFault="process_id";await model.refreshTunnelStatus()
   check(!model.connected && model.activeSessionIdentity==nil,"ordinary Connected waits for original execution owner stamp")
   provider.ownerFault="";await model.refreshTunnelStatus()
   let before=model.activeSessionIdentity!,owner=try model.iosSpeedLabOwnership.begin{}
   let captured=try await IOSSpeedLabTunnel.capture(model:model,owner:owner)
   check(provider.captures==1,"capture original opaque capsule before stopping")
   try captured.requireMeasuredExecution(requested:"auto",selected:selected)
   provider.verifyFault=true;await reject("changed original token cannot stop"){try await captured.stopOriginal(model:model,owner:owner)}
   check(manager.connection.stops==0,"unverified capsule cannot stop original");provider.verifyFault=false
   try await captured.stopOriginal(model:model,owner:owner)
   check(!model.connected && manager.connection.stops==1,"original stopped after verify")
   try await captured.restore(model:model,owner:owner,reconnect:reconnect)
   check(manager.connection.comparisonStarts==0,"restore never reranks Compare")
   if reconnect {
    check(manager.connection.starts==1 && model.connected && model.activeSessionIdentity?.nodeChainExecutionSource==before.nodeChainExecutionSource,"same execution source restored through original manager")
    check(provider.releases==0,"consumed original capsule not released")
    check(try IOSNodeChainExecutionLastStore.stored(for:source) != nil,"fresh proof stored Last")
   }else{check(manager.connection.starts==0 && provider.releases==1 && !model.connected,"Disconnect joins capsule without reconnect")}
  }}}
  print("PASS Apple ordered Speed Lab: CONNECT and generic actual capture/stop/restore, Local/Server winner and Disconnect")
 }
}
'''
def main():
 with tempfile.TemporaryDirectory(prefix='.ios-app-session-',dir=ROOT) as gd,tempfile.TemporaryDirectory(prefix='ios-app-session-') as wd:
  gd,work=Path(gd),Path(wd);(gd/'main.go').write_text(SAVED.GO);compiler=work/'compiler'
  subprocess.run(['go','build','-p','1','-o',str(compiler),str(gd/'main.go')],cwd=ROOT,check=True,timeout=180)
  (work/'Libbox.swift').write_text(SAVED.LIBBOX);(work/'CryptoKit.swift').write_text(SAVED.SOURCE.CRYPTO);(work/'Tests.swift').write_text(SWIFT+SHIM+TESTS)
  options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
  suffix='.dylib' if platform.system()=='Darwin' else '.so'
  subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(work/('libLibbox'+suffix))],check=True,timeout=90)
  link=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
  subprocess.run(options+link+['-emit-module','-emit-library','-module-name','CryptoKit',str(work/'CryptoKit.swift'),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit'+suffix))],check=True,timeout=90)
  command=options+link+['-lCryptoKit']+[str(APP/name) for name in ['Models.swift','IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeChainCONNECTCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainExecutionCapture.swift','IOSSessionIdentity.swift','IOSNodeChainExecutionSession.swift','IOSMultihopExecution.swift','IOSSpeedLabOwnership.swift']]
  tunnel=work/'Tunnel.swift';original=(APP/'IOSSpeedLabTunnel.swift').read_text().replace('@preconcurrency import NetworkExtension','');tunnel.write_text(original)
  wire=work/'Strategy.swift';wire.write_text((APP/'IOSStrategySession.swift').read_text().split('#if canImport(NetworkExtension)',1)[0]);command += [str(tunnel),str(wire)]
  source=APP/'IOSNodeChainExecutionControl.swift';tests=work/'Tests.swift';binary=work/'baseline'
  subprocess.run(command+[str(source),str(tests),'-o',str(binary)],check=True,timeout=90)
  subprocess.run([str(binary),str(compiler)],check=True,timeout=180)


  for name,before,after,witness in (
   ('verify-before-stop','try await orderedExecution?.verify()','_ = orderedExecution','ACCEPTED changed original token cannot stop'),
   ('disconnect-retirement','if !reconnect { try await orderedExecution?.retire(); try requireOwner() }','if !reconnect { try requireOwner() }','Disconnect joins capsule without reconnect'),
  ):
   assert original.count(before)==1,name
   tunnel.write_text(original.replace(before,after,1))
   subprocess.run(command+[str(source),str(tests),'-o',str(binary)],check=True,timeout=90)
   result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
   assert result.returncode==1 and ('FAIL '+witness+'\n') in result.stdout+result.stderr,(name,result.returncode,(result.stdout+result.stderr)[-2000:])
   print('Rejected CONNECT Speed Lab omission:',name,flush=True)
if __name__=='__main__':main()
