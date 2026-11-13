#!/usr/bin/env python3
"""Execute the complete shipping prefix host with explicit native/MTU boundaries.

These controls prove host ownership and joined callback behavior. The separate
30+9 native gate and real Xcode/PacketTunnel gates remain independently required.
"""
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / 'ios/RouterVPN/PacketTunnel/RouterVPNNodeCandidatePrefixHost.swift'
LIBBOX = r'''
import Foundation
public protocol LibboxRouterNodeChainCandidateCatalogProtocol: AnyObject { func currentInventorySHA256()->String }
public final class LibboxRouterMTUState: @unchecked Sendable {
 public var session="session",path="physical",interface="reader"; public var mtu:Int32=1280
 public init(){}
}
public final class LibboxCommandServer: @unchecked Sendable {
 private let lock=NSLock();private var stops=0;public var rejectClose=false,denyReceipt=false,bound=false,attempted=false,actualClosed=false
 public init(){}
 public func start()throws{}
 public func close(){lock.lock();stops+=1;lock.unlock()}
 public var closes:Int{lock.lock();defer{lock.unlock()};return stops}
}
public func LibboxRouterStrategyStartService(_ server:LibboxCommandServer,_ config:String,_ error:UnsafeMutablePointer<NSError?>?)->Bool{
 guard server.bound else{error?.pointee=NSError(domain:"OriginalBind",code:1,userInfo:[NSLocalizedDescriptionKey:"original native bind required before Start"]);return false};server.attempted=true;return true
}
public func LibboxRouterStrategyCloseService(_ server:LibboxCommandServer,_ error:UnsafeMutablePointer<NSError?>?)->Bool{
 if server.rejectClose{error?.pointee=NSError(domain:"HeldOriginalBox",code:1);return false};if !server.denyReceipt{server.actualClosed=true};return true
}
'''
BOUNDARY = r'''
import Foundation
import Libbox
final class State: @unchecked Sendable {
 let lock=NSLock();var current=true,holdRun=false,holdClose=false,runEntered=false,nativeClosed=false,closedReceipt=false,healthy=true
 var runCount=0,nativeCloses=0,failures=0;var capturedServer:LibboxCommandServer?
 let entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0)
 func read<T>(_ operation:(State)->T)->T{lock.lock();defer{lock.unlock()};return operation(self)}
 func set(_ operation:(State)->Void){lock.lock();operation(self);lock.unlock()}
}
final class Native: @unchecked Sendable {
 let state:State;init(_ state:State){self.state=state}
 func bindNative(_ server:LibboxCommandServer)throws{
  guard state.read({$0.capturedServer==nil || $0.capturedServer === server})else{throw IOSNodeCandidatePrefixCapture.issue()}
  state.set{$0.capturedServer=server};server.bound=true
 }
 func nativeClosed()->Bool{state.read{$0.nativeClosed && ($0.capturedServer != nil && ($0.capturedServer?.attempted==false || $0.capturedServer?.actualClosed==true) )}}
 func run(_ server:LibboxCommandServer,catalog:LibboxRouterNodeChainCandidateCatalogProtocol)throws{
  state.set{$0.runEntered=true;$0.runCount+=1;$0.capturedServer=server}
  state.entered.signal();defer{state.set{$0.runEntered=false}}
  if state.read({$0.holdRun}){state.release.wait()}
  guard !catalog.currentInventorySHA256().isEmpty else{throw IOSNodeCandidatePrefixCapture.issue()}
 }
 func healthy()->Bool{state.read{$0.healthy && !$0.nativeClosed}}
 func progressJSON()->String{"{\"stage\":\"prefix-prepared\",\"prepared\":true,\"application_open\":false,\"dns_open\":false}"}
 func metadata()->String{"{\"schema\":1}"}
 func start(_ request:String,candidateID:String)throws{}
 func statusJSON()->String{"{\"complete\":true,\"drained\":true}"}
 func networkChanged(){}
 func close()throws{
  state.set{$0.nativeCloses+=1}
  guard !state.read({$0.holdClose || $0.runEntered})else{throw IOSNodeCandidatePrefixCapture.issue()}
  state.set{$0.nativeClosed=true}
 }
}
struct IOSNodeCandidatePrefixCapture {
 struct Metadata{struct MTU{let original=1280};let mtu=MTU();let prefix_position=0}
 let native:Native;let metadata=Metadata();let config="closed-ingress-only"
 static func issue()->NSError{NSError(domain:"PrefixHost",code:1)}
}
struct IOSCandidateCatalogPublication {
 static func validRequest(_ s:String)->Bool{s.count==32 && s.allSatisfy{("0"..."9").contains($0) || ("a"..."f").contains($0)}}
}
struct IOSNodeCandidatePrefixProviderCapture {
 struct Source{let request=String(repeating:"a",count:32);let inventorySHA256=String(repeating:"b",count:64)}
 let capture:IOSNodeCandidatePrefixCapture;let source=Source();let epoch="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";let state:State
 init(_ state:State){self.state=state;capture=IOSNodeCandidatePrefixCapture(native:Native(state))}
 func requireCurrent()throws{guard state.read({$0.current && !$0.closedReceipt})else{throw IOSNodeCandidatePrefixCapture.issue()}}
 func storeCandidatesClosed()throws{state.set{$0.closedReceipt=true}}
}
final class MTU: @unchecked Sendable {
 private let lock=NSLock();private var path="physical",mtu:Int32=1280,stops=0;var isChanging=false
 func captureMTU()->LibboxRouterMTUState?{lock.lock();defer{lock.unlock()};let value=LibboxRouterMTUState();value.path=path;value.mtu=mtu;return value}
 func change(path:String?=nil,mtu:Int32?=nil){lock.lock();if let path{self.path=path};if let mtu{self.mtu=mtu};lock.unlock()}
 func stopChecked()throws{lock.lock();stops+=1;lock.unlock()}
 var stopCount:Int{lock.lock();defer{lock.unlock()};return stops}
}
final class RouterVPNLibboxPlatform: @unchecked Sendable {
 let mtu=MTU();private let lock=NSLock();private var resets=0
 func reset(){lock.lock();resets+=1;lock.unlock()}
 var resetCount:Int{lock.lock();defer{lock.unlock()};return resets}
}
final class Completion: @unchecked Sendable {
 private let lock=NSLock();private var result:Error?,finished=false
 func call(_ error:Error?){lock.lock();result=error;finished=true;lock.unlock()}
 var done:Bool{lock.lock();defer{lock.unlock()};return finished}
 var failed:Bool{lock.lock();defer{lock.unlock()};return result != nil}
}
final class Fixture: @unchecked Sendable {
 let state=State(),platform=RouterVPNLibboxPlatform(),server=LibboxCommandServer();let input:IOSNodeCandidatePrefixProviderCapture;let host:RouterVPNNodeCandidatePrefixHost
 init(){let s=state,p=platform;input=IOSNodeCandidatePrefixProviderCapture(s);host=RouterVPNNodeCandidatePrefixHost(input:input,platform:p,current:{s.read{$0.current}},failure:{_ in s.set{$0.failures+=1}})}
 func construct()throws{try host.beginFactory();try host.finishFactory(server);try host.startNative();host.finishConstruction()}
 func run()throws->Completion{try construct();let c=Completion();host.run{c.call($0)};return c}
 func reply(_ operation:String="prefix-candidate-open",request:String?=nil,epoch:String?=nil,owner:String?=nil,prefix:String="0",candidate:String="")->Data?{host.reply(operation:operation,request:request ?? input.source.request,epoch:epoch ?? input.epoch,owner:owner ?? input.source.request,prefix:prefix,candidate:candidate)}
}
'''
SWIFT = r'''
import Foundation
import Libbox
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ value:Bool,_ text:String)throws{guard value else{throw NSError(domain:"HostCheck",code:1,userInfo:[NSLocalizedDescriptionKey:text])};checks+=1}
 static func rejects(_ text:String,_ action:()throws->Void)throws{do{try action()}catch{checks+=1;return};throw NSError(domain:"HostCheck",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+text])}
 static func wait(_ text:String,_ ready:()->Bool)throws{let end=Date().addingTimeInterval(3);while !ready() && Date()<end{Thread.sleep(forTimeInterval:0.005)};try check(ready(),text)}
 static func main(){do{try run();print("Apple independent prefix host: \(checks) actual shipping lifecycle checks PASS")}catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func run()throws{
  do{let f=Fixture(),result=try f.run();try wait("prepared callback joined"){result.done};try check(!result.failed,"original prefix preparation succeeds")
   try check(f.state.read{$0.capturedServer === f.server && $0.runCount==1},"exact original server used once")
   try check(f.reply() != nil,"prepared prefix metadata available")
   for foreign in ["foreign",String(repeating:"c",count:32)]{try check(f.reply(owner:foreign)==nil,"foreign owner rejected")}
   try check(f.reply(epoch:UUID().uuidString)==nil,"foreign epoch rejected")
   try check(f.reply(prefix:"1")==nil,"foreign prefix rejected")
   try check(f.reply(request:"bad")==nil,"malformed request rejected")
   try check(f.reply("candidate-open")==nil,"ordinary candidate scope rejected")
   let request=String(repeating:"d",count:32)
   try check(f.reply("prefix-candidate-start",request:request,prefix:"",candidate:"target") != nil,"owned candidate starts")
   try check(f.reply("prefix-candidate-start",request:request,prefix:"",candidate:"other")==nil,"repeat request cannot replace candidate")
   try check(f.reply("prefix-candidate-status",request:request,prefix:"") != nil,"owned candidate status")
   try check(f.reply("prefix-candidate-status",request:request,owner:String(repeating:"c",count:32),prefix:"")==nil,"foreign owner cannot read active status")
   try check(f.reply("prefix-candidate-close",prefix:"") != nil,"candidate native join acknowledged")
   try check(f.state.read{$0.nativeClosed && $0.closedReceipt} && f.platform.mtu.stopCount==0 && f.server.closes==0,"candidate close does not assert Box or MTU DOWN")
   try f.host.close();try check(f.server.closes==1 && f.platform.resetCount==1 && f.platform.mtu.stopCount==1,"original Box and MTU retire after candidate join")
   try f.host.close();try check(f.server.closes==1,"repeat close retains one original resource retirement")
  }
  for failedFactory in [false,true] {
   let f=Fixture()
   if failedFactory { try f.host.beginFactory();let returned:LibboxCommandServer?=nil;let failure=NSError(domain:"OriginalFactory",code:1);try f.host.finishFactory(returned);try check(returned==nil && failure.code==1,"original factory returned nil and NSError") }
   f.host.finishConstruction();try f.host.close()
   try check(f.state.read{$0.nativeClosed} && !f.input.capture.native.nativeClosed() && f.platform.resetCount==1 && f.platform.mtu.stopCount==1,"sealed no-acquisition factory retires only after join")
  }
  do{let f=Fixture();try f.host.beginFactory();f.host.finishConstruction()
   try rejects("unjoined nil factory cannot retire"){try f.host.close()}
   try check(f.platform.resetCount==0 && f.platform.mtu.stopCount==0,"unknown no-acquisition keeps MTU hold")
   try? f.host.finishFactory(nil);try f.host.close()
  }
  do{let f=Fixture();try f.host.beginFactory();f.host.cancel();try rejects("late factory after cancel"){try f.host.finishFactory(f.server)}
   try rejects("construction still entered"){try f.host.close()}
   try check(f.server.closes==0 && f.platform.resetCount==0,"entered construction retains late server")
   f.host.finishConstruction();try f.host.close();try check(f.server.closes==1,"late returned original server must be closed")
  }
  do{let f=Fixture();f.state.set{$0.holdRun=true};let result=try f.run();try check(f.state.entered.wait(timeout:.now()+2) == .success,"native Run entered")
   try rejects("native Run still entered"){try f.host.close()}
   try check(f.platform.resetCount==0 && f.platform.mtu.stopCount==0 && !f.state.read{$0.closedReceipt},"entered Run cannot publish join or release MTU")
   f.state.release.signal();try wait("cancelled Run callback returned"){result.done};try check(result.failed,"cancelled startup cannot report prepared")
   try f.host.close();try check(f.server.closes==1,"original server retires after Run joins")
  }
  do{let f=Fixture(),result=try f.run();try wait("close retry preparation"){result.done};f.state.set{$0.holdClose=true}
   try rejects("native callback close held"){try f.host.close()}
   try check(f.server.closes==0 && f.platform.resetCount==0 && f.platform.mtu.stopCount==0 && !f.state.read{$0.closedReceipt},"held native close cannot release original Box or MTU")
   f.state.set{$0.holdClose=false};try f.host.close();try check(f.state.read{$0.nativeClosed} && f.server.closes==1,"retry joins original native callbacks")
  }
  do{let f=Fixture(),result=try f.run();try wait("Box retry preparation"){result.done};f.server.rejectClose=true
   try rejects("original Box close held"){try f.host.close()};try check(f.platform.resetCount==0 && f.platform.mtu.stopCount==0,"held Box retains physical observer and MTU hold")
   f.server.rejectClose=false;f.server.denyReceipt=true
   try rejects("empty daemon service is not original native DOWN"){try f.host.close()}
   try check(f.platform.resetCount==0 && f.platform.mtu.stopCount==0 && f.server.closes==0,"missing original native receipt retains MTU and Box")
   f.server.denyReceipt=false;try f.host.close();try check(f.server.closes==1,"Box retry uses original server")
  }
  do{let f=Fixture();f.platform.mtu.change(mtu:1400);let result=try f.run();try wait("MTU mismatch returns"){result.done};try check(result.failed && f.state.read{$0.runCount==0},"configured MTU mismatch prevents native prefix Run");try f.host.close()}
  do{let f=Fixture(),result=try f.run();try wait("readback test prepared"){result.done};f.platform.mtu.change(path:"replacement")
   try check(f.reply()==nil,"changed physical readback rejects candidate admission");try f.host.close()}
  do{let f=Fixture(),result=try f.run();try wait("catalog test prepared"){result.done};f.state.set{$0.current=false}
   try check(f.reply()==nil,"changed original catalog rejects admission");try f.host.close()}
  do{let f=Fixture(),result=try f.run();try wait("health test prepared"){result.done};f.state.set{$0.healthy=false}
   try check(f.reply()==nil,"expired native prefix proof rejects admission");try f.host.close()}
 }
}
'''

def run():
    with tempfile.TemporaryDirectory(prefix='ios-prefix-host-') as folder:
        work=Path(folder);module=work/'Libbox.swift';module.write_text(LIBBOX)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(module),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        boundary=work/'Boundary.swift';boundary.write_text(BOUNDARY);test=work/'Tests.swift';test.write_text(SWIFT)
        binary=work/'test';command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work),str(boundary),str(test)]
        def exercise(path,witness=None):
            subprocess.run(command+[str(path),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            if witness:
                assert result.returncode!=0 and witness in result.stdout+result.stderr,(witness,result.stdout+result.stderr)
                print('Rejected prefix host defect: '+witness,flush=True)
            else:
                assert result.returncode==0,result.stdout+result.stderr
                print(result.stdout.strip(),flush=True)
        exercise(HOST)
        source=HOST.read_text()
        for before,after,witness in [
            ('server = value; factoryEntered = false; factoryJoined = true; state.unlock()','if !stopped { server = value }; factoryEntered = false; factoryJoined = true; state.unlock()','late returned original server must be closed'),
            ('let pending = constructing || factoryEntered || runEntered || observers != 0','let pending = factoryEntered || runEntered || observers != 0','ACCEPTED construction still entered'),
            ('try input.capture.native.close()','// deliberately omitted original native close','candidate close does not assert Box or MTU DOWN'),
            ('Readback(actual) == expected,','expected.session == actual.session,','changed physical readback rejects candidate admission'),
            ('guard epoch == input.epoch, owner == input.source.request,','guard epoch == input.epoch, true,','foreign owner cannot read active status'),
            ('actual.mtu == Int32(input.capture.metadata.mtu.original),\n                      !actual.session.isEmpty','true,\n                      !actual.session.isEmpty','configured MTU mismatch prevents native prefix Run'),
            ('guard input.capture.native.nativeClosed() else { throw Self.issue() }','guard true else { throw Self.issue() }','ACCEPTED empty daemon service is not original native DOWN'),
            ('try input.capture.native.bindNative(value)','// omitted original native bind','original native bind required before Start'),
        ]:
            assert source.count(before)==(2 if before=='try input.capture.native.close()' else 1),before
            changed=source.replace(before,after);assert changed!=source
            mutant=work/'Host.swift';mutant.write_text(changed);exercise(mutant,witness)
if __name__=='__main__':run()
