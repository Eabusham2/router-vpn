#!/usr/bin/env python3
"""Execute the shipping engine's whole prefix construction and cleanup methods.

The complete prefix host is compiled unchanged. Other engine families, mobile
ABI and the provider Stop coordinator have explicit independent gate boundaries.
"""
from pathlib import Path
import platform,subprocess,tempfile
import test_ios_node_candidate_prefix_host as H
from test_ios_node_chain_provider import member
ROOT=H.ROOT;TUN=ROOT/'ios/RouterVPN/PacketTunnel'
LIBBOX=H.LIBBOX+r'''
public final class LibboxSetupOptions {
 public var basePath="",workingPath="",tempPath="",commandServerSecret="";public var logMaxLines:Int64=0,oomKillerEnabled=false
 public init(){}
}
public final class NativeFactory: @unchecked Sendable {
 public static let shared=NativeFactory();public var mode="",hook:(()->Void)?,server:LibboxCommandServer?,directory=""
 public func reset(){mode="";hook=nil;server=nil;directory=""}
}
public func LibboxSetup(_ options:LibboxSetupOptions,_ error:UnsafeMutablePointer<NSError?>?){
 NativeFactory.shared.directory=options.basePath
 if NativeFactory.shared.mode=="setup-error"{error?.pointee=NSError(domain:"Setup",code:1)}
 if NativeFactory.shared.mode=="cancel-before-factory"{NativeFactory.shared.hook?()}
}
public func LibboxNewCommandServer(_ platform:AnyObject,_ handler:AnyObject,_ error:UnsafeMutablePointer<NSError?>?)->LibboxCommandServer?{
 if NativeFactory.shared.mode=="nil-error"{error?.pointee=NSError(domain:"Factory",code:1);return nil}
 let server=LibboxCommandServer();NativeFactory.shared.server=server
 if NativeFactory.shared.mode=="server-error"{error?.pointee=NSError(domain:"Factory",code:1)}
 if NativeFactory.shared.mode=="late-server"{NativeFactory.shared.hook?()}
 return server
}
'''
BOUNDARY=H.BOUNDARY.replace('let native:Native;let metadata=Metadata();let config="closed-ingress-only"','let native:Native;let metadata=Metadata();let config="closed-ingress-only";let strict=true')
BOUNDARY=BOUNDARY.replace('let mtu=MTU();private let lock=NSLock();private var resets=0','let mtu=MTU();var includeAllNetworksRequested=false;private let lock=NSLock();private var resets=0')
BOUNDARY+=r'''
final class LegacyRetirement: @unchecked Sendable {func requireAvailable()throws{}}
enum RouterVPNNodeChainExecutionHost {static func requireAvailable()throws{}}
enum RouterVPNLibboxCompileProbe {static func verifyPinnedRuntime()throws{}}
enum RouterVPNPQFactory {static func install()throws{}}
final class PacketTunnelProvider {func nativeLibboxFailure(_ owner:RouterVPNLibboxEngine,error:Error){}}
final class RouterVPNLibboxEngine {
 private static let torRetirement=LegacyRetirement(),torServerRetirement=LegacyRetirement(),externalRetirement=LegacyRetirement(),measurementRetirement=LegacyRetirement()
 private let ownershipLock=NSLock();private var ownershipGeneration=UUID()
 private var server:LibboxCommandServer?,nodeCandidatePrefix:RouterVPNNodeCandidatePrefixHost?,pendingNodeCandidatePrefixCleanup:RouterVPNNodeCandidatePrefixHost?
 private var starting=false,permanentlyStopped=false,stopInProgress=false,nativeCloseFailure:Error?,configContent="",runtimeRoot:URL?
 let platform=RouterVPNLibboxPlatform();let tunnel:PacketTunnelProvider?=PacketTunnelProvider()
 func error(_ text:String)->NSError{NSError(domain:"Engine",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
 // Existing engine stop coordination is independently exercised by provider
 // Stop tests. This boundary retains and invokes the actual prefix cleanup.
 func stopGeneration(_ expected:UUID?)->Error?{
  ownershipLock.lock()
  if let expected,expected != ownershipGeneration{ownershipLock.unlock();return nil}
  if !permanentlyStopped{
   permanentlyStopped=true;ownershipGeneration=UUID();pendingNodeCandidatePrefixCleanup=nodeCandidatePrefix
   nodeCandidatePrefix=nil;server=nil;runtimeRoot=nil;configContent=""
   pendingNodeCandidatePrefixCleanup?.retainForRetirement()
  }
  guard let pending=pendingNodeCandidatePrefixCleanup else{let result=nativeCloseFailure;ownershipLock.unlock();return result}
  stopInProgress=true;ownershipLock.unlock();return finishNodeCandidatePrefixCleanup(pending)
 }
 func stop()->Error?{stopGeneration(nil)}
 var retained:Bool{pendingNodeCandidatePrefixCleanup != nil}
 // SHIPPING_ENGINE
}
'''
TEST=r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ value:Bool,_ text:String)throws{checks+=1;guard value else{throw NSError(domain:"EngineCheck",code:1,userInfo:[NSLocalizedDescriptionKey:text])}}
 static func main(){do{try run();print("Apple prefix engine construction: \(checks) shipping method/host checks PASS")}catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func run()throws{
  for fault in ["none","server-error","nil-error","setup-error","late-server","cancel-before-factory"]{
   NativeFactory.shared.reset();NativeFactory.shared.mode=fault
   let engine=RouterVPNLibboxEngine(),state=State(),input=IOSNodeCandidatePrefixProviderCapture(state)
   NativeFactory.shared.hook={_ = engine.stop()}
   var failure:Error?
   do{try engine.start(candidatePrefix:input)}catch{failure=error}
   if fault=="none"{
    try check(failure==nil,"shipping prefix factory did not bind original server")
    let done=Completion();engine.completeCandidatePrefix{done.call($0)}
    let end=Date().addingTimeInterval(3);while !done.done && Date()<end{Thread.sleep(forTimeInterval:0.005)}
    try check(done.done && !done.failed,"shipping construction barrier never completed")
    try check(NativeFactory.shared.server?.bound==true && state.read{$0.capturedServer === NativeFactory.shared.server},"shipping Run adopted a foreign native server")
    NativeFactory.shared.server!.rejectClose=true
    try check(engine.stop() != nil && engine.retained && engine.platform.resetCount==0,"failed native close lost original cleanup owner")
    NativeFactory.shared.server!.rejectClose=false;NativeFactory.shared.server!.denyReceipt=true
    try check(engine.stop() != nil && engine.retained && engine.platform.resetCount==0,"nil service falsely released native owner")
    NativeFactory.shared.server!.denyReceipt=false
   }else{try check(failure != nil,"failed original construction gained startup authority")}
   _ = engine.stop()
   if let server=NativeFactory.shared.server{try check(server.closes==1,"factory error lost original returned server")}
   try check(!engine.retained && engine.platform.resetCount==1 && engine.platform.mtu.stopCount==1,"original factory resources did not join cleanup")
   try check(!FileManager.default.fileExists(atPath:NativeFactory.shared.directory),"original private construction directory leaked")
  }
 }
}
'''

def main():
    source=(TUN/'RouterVPNLibboxEngine.swift').read_text()
    methods='\n'.join(member(source,signature) for signature in ('    func start(candidatePrefix ', '    private func finishNodeCandidatePrefixCleanup(', '    func completeCandidatePrefix('))
    with tempfile.TemporaryDirectory(prefix='ios-prefix-engine-') as folder:
        work=Path(folder);module=work/'Libbox.swift';module.write_text(LIBBOX);fixture=work/'Fixture.swift';host=H.HOST
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(module),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        binary=work/'test';command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work),str(host),str(fixture),'-o',str(binary)]
        def exercise(code,witness=None):
            fixture.write_text(BOUNDARY.replace(' // SHIPPING_ENGINE',code)+TEST)
            subprocess.run(command,check=True,timeout=90)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            if witness:
                assert result.returncode!=0 and witness in result.stdout+result.stderr,(witness,result.stdout+result.stderr[-2000:]);print('Rejected prefix engine defect: '+witness,flush=True)
            else:assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip(),flush=True)
        exercise(methods)
        for before,after,witness in [
            ('try host.finishFactory(created)\n        if let createError { throw createError }','if let createError { throw createError }\n        try host.finishFactory(created)','factory error lost original returned server'),
            ('host.finishConstruction()','// omitted construction join','shipping construction barrier never completed'),
            ('if failure == nil { pendingNodeCandidatePrefixCleanup = nil }','pendingNodeCandidatePrefixCleanup = nil','failed native close lost original cleanup owner'),
        ]:
            assert methods.count(before)==1,before
            changed=methods.replace(before,after);assert changed!=methods;exercise(changed,witness)
if __name__=='__main__':main()
