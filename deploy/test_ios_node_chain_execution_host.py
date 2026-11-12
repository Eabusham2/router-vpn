#!/usr/bin/env python3
"""Execute the shipping Apple ordered execution owner with explicit native doubles.

This is a Swift ownership/ordering gate. Libbox handles and OS interfaces are
controlled boundaries; it does not claim Apple SDK, system TUN or relay traffic.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
HOST=ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNNodeChainExecutionHost.swift'

BOUNDARY=r'''
import Foundation
func failure(_ text:String="native boundary")->NSError{NSError(domain:"ExecutionHostBoundary",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
final class Trace:@unchecked Sendable {
 static let shared=Trace();private let lock=NSLock();private var events:[String]=[]
 func add(_ x:String){lock.lock();events.append(x);lock.unlock()}
 var values:[String]{lock.lock();defer{lock.unlock()};return events}
 func reset(){lock.lock();events=[];lock.unlock()}
}
final class LibboxCommandServer {
 var capture:IOSNodeChainExecutionCapture?,started=false,service=false,released=false
 var failStart=false,failService=false,failClose=0,receipt=true,boxCloses=0
 func start()throws{Trace.shared.add("server-start");guard capture != nil,!failStart else{throw failure()};started=true}
 func close(){released=true;Trace.shared.add("server-release")}
}
func LibboxRouterStrategyStartService(_ server:LibboxCommandServer,_ config:String,_ error:inout NSError?)->Bool{
 Trace.shared.add("box-start");server.service=true
 if server.failService{error=failure();return false};return true
}
func LibboxRouterStrategyCloseService(_ server:LibboxCommandServer,_ error:inout NSError?)->Bool{
 Trace.shared.add("box-close");server.boxCloses+=1
 if server.failClose>0{server.failClose-=1;error=failure();return false}
 server.service=false;server.capture?.recordNativeClose(server.receipt);return true
}
final class LibboxRouterHopMeasurement {
 var closeFailures=0,closed=false
 func networkChanged(){Trace.shared.add("measure-cancel")}
 func close()throws{Trace.shared.add("measure-close");if closeFailures>0{closeFailures-=1;throw failure()};closed=true}
}
final class LibboxRouterNodeChainExecution {
 var owner:IOSNodeChainExecutionCapture?
 func progressJSON()->String{"{\"stage\":\"selected\"}"}
}
final class IOSNodeChainExecutionCapture:@unchecked Sendable {
 let plan=LibboxRouterNodeChainExecution(),config="exact-preparation"
 private let lock=NSLock()
 var runGate:DispatchSemaphore?,healthGate:DispatchSemaphore?,healthEntered=DispatchSemaphore(value:0)
 let runEntered=DispatchSemaphore(value:0),runReturned=DispatchSemaphore(value:0)
 var closeFailures=0,valid=true,runFails=false,bindFails=false
 private var closed=false,cancelled=false,nativeReceipt=false,ran=false
 private(set) var server:LibboxCommandServer?
 init(){plan.owner=self}
 func requireCurrent()throws{lock.lock();let good = !closed;lock.unlock();if !good{throw failure("closed capture")}}
 func bindNative(_ server:LibboxCommandServer)throws{
  lock.lock();defer{lock.unlock()};Trace.shared.add("bind")
  guard self.server==nil || self.server===server else{throw failure("replaced slot")}
  self.server=server;server.capture=self
  if closed{nativeReceipt=true;throw failure("sealed empty")};if bindFails{throw failure("uncertain bind")}
 }
 func run(_ server:LibboxCommandServer)throws{
  Trace.shared.add("run");runEntered.signal();defer{runReturned.signal()}
  guard self.server===server,server.service else{throw failure("unbound run")}
  if let runGate{guard runGate.wait(timeout:.now()+4) == .success else{throw failure("held run")}}
  lock.lock();let bad=closed || cancelled || runFails;ran = !bad;lock.unlock()
  if bad{throw failure("proof refused")}
 }
 func healthy()->Bool{
  Trace.shared.add("healthy");healthEntered.signal()
  if let healthGate{_ = healthGate.wait(timeout:.now()+4)}
  lock.lock();defer{lock.unlock()};return valid && ran && !closed && !cancelled
 }
 func execution()throws->String{guard healthy()else{throw failure("unproved execution")};return "server"}
 func networkChanged(){lock.lock();cancelled=true;lock.unlock();Trace.shared.add("network")}
 func close()throws{
  Trace.shared.add("remote-close");lock.lock();defer{lock.unlock()}
  if closeFailures>0{closeFailures-=1;throw failure("remote close pending")}
  closed=true;if let server,!server.service{nativeReceipt=true}
 }
 func recordNativeClose(_ valid:Bool){lock.lock();nativeReceipt=valid;lock.unlock()}
 func nativeClosed()->Bool{lock.lock();defer{lock.unlock()};Trace.shared.add("native-receipt");return closed && nativeReceipt}
}
final class MTU:@unchecked Sendable {
 var proofObservationToken:UUID?=UUID(),isChanging=false,optimizerRunning=false,failDrain=0,activateFailure=false,activated=false
 func observeNodeChainExecutionMeasurement(_ token:UUID,_ action:()throws->Void)throws->Bool{guard !optimizerRunning,proofObservationToken==token else{return false};try action();return true}
 func drainForNodeChainExecutionCleanup()throws{Trace.shared.add("mtu-drain");if failDrain>0{failDrain-=1;throw failure("optimizer join pending")}}
 func activateNodeChainExecution(server:LibboxCommandServer,plan:LibboxRouterNodeChainExecution,runAutomatic:Bool=true,onAbort:@escaping @Sendable(String)->Void)throws{
  Trace.shared.add("mtu-activate");guard server.capture === plan.owner,!activateFailure else{throw failure()};activated=true
 }
}
final class RouterVPNLibboxPlatform:@unchecked Sendable {
 let mtu=MTU();var resets=0
 func reset(){resets+=1;Trace.shared.add("platform-reset")}
}
final class Factory:@unchecked Sendable {
 static let shared=Factory();var fail=false,errorWithOwner=false,hook:(()->Void)?,probe:LibboxRouterHopMeasurement?
 func reset(){fail=false;errorWithOwner=false;hook=nil;probe=nil}
}
func LibboxRouterNodeChainExecutionNewHopMeasurement(_ plan:LibboxRouterNodeChainExecution,_ server:LibboxCommandServer,_ error:inout NSError?)->LibboxRouterHopMeasurement?{
 Trace.shared.add("measure-create");let f=Factory.shared
 guard let owner=plan.owner,owner.server===server,owner.healthy(),!f.fail else{error=failure();return nil}
 let probe=LibboxRouterHopMeasurement();f.probe=probe;f.hook?()
 if f.errorWithOwner{error=failure()};return probe
}
final class Result:@unchecked Sendable {
 let signal=DispatchSemaphore(value:0),lock=NSLock();private var errors:[Bool]=[]
 func finish(_ error:Error?){lock.lock();errors.append(error != nil);lock.unlock();signal.signal()}
 var values:[Bool]{lock.lock();defer{lock.unlock()};return errors}
 func wait()->Bool{signal.wait(timeout:.now()+4) == .success}
}
final class Current:@unchecked Sendable{let lock=NSLock();private var value=true;func retire(){lock.lock();value=false;lock.unlock()};func get()->Bool{lock.lock();defer{lock.unlock()};return value}}
'''
RESTORE_BOUNDARY=r'''
// Source/native restore has its own gate. These old owner scenarios refuse
// accidental restoration or Last use instead of fabricating such authority.
final class RouterVPNNodeChainExecutionRegistry {
 final class Restored { func require(_ capture:IOSNodeChainExecutionCapture)throws{throw failure("unproved restore")}}
}
extension IOSNodeChainExecutionCapture {
 final class Restoration {}
 func captureRestoration()throws->Restoration{throw failure("unproved restore")}
 func captureLastRecord()throws->String{throw failure("unproved Last")}
}
'''
TESTS=r'''
extension RouterVPNNodeChainExecutionHost { func fixtureHealth(){checkHealth()} }
@main struct Tests {
 static func check(_ ok:Bool,_ name:String){if !ok{FileHandle.standardError.write(Data(("FAIL "+name+"\n").utf8));exit(1)}}
 static func reject(_ name:String,_ action:()throws->Void){do{try action();check(false,name)}catch{}}
 static func start(_ capture:IOSNodeChainExecutionCapture=IOSNodeChainExecutionCapture())throws->(RouterVPNNodeChainExecutionHost,LibboxCommandServer,RouterVPNLibboxPlatform){
  let platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainExecutionHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
  let server=LibboxCommandServer();try host.bindNative(server);try host.startNative();host.finishConstruction();return(host,server,platform)
 }
 static func run(_ host:RouterVPNNodeChainExecutionHost)->Result{let r=Result();host.run(adoptMeasurement:{_,_ in true},completion:r.finish);check(r.wait() && r.values==[false],"proof success missing");return r}
 static func main()throws{
  Trace.shared.reset();Factory.shared.reset()
  do{
   let (host,server,platform)=try start();_ = run(host);try host.activateMTU();check(platform.mtu.activated && host.progress() != nil,"owned activities missing")
   try host.close();let events=Trace.shared.values
   check(events.firstIndex(of:"bind")! < events.firstIndex(of:"server-start")! && events.firstIndex(of:"bind")! < events.firstIndex(of:"box-start")!,"native bind must precede start")
   check(events.firstIndex(of:"remote-close")! < events.firstIndex(of:"box-close")! && events.firstIndex(of:"measure-close")! < events.firstIndex(of:"box-close")!,"original joins must precede native close")
   check(events.lastIndex(of:"native-receipt")! < events.firstIndex(of:"server-release")! && server.released && platform.resets==1,"native receipt must precede resource release")
   try host.close();check(server.boxCloses==1 && platform.resets==1,"joined cleanup repeated native close")
   check(host.progress()==nil,"retired progress observed native state")
  }
  for pending in ["remote","measurement","mtu"]{
   Factory.shared.reset();let capture=IOSNodeChainExecutionCapture();let (host,server,platform)=try start(capture);_ = run(host)
   if pending=="remote"{capture.closeFailures=1};if pending=="measurement"{Factory.shared.probe!.closeFailures=1};if pending=="mtu"{platform.mtu.failDrain=1}
   reject("unjoined "+pending+" cleanup accepted"){try host.close()}
   check(server.boxCloses==0 && !server.released && platform.resets==0,"pending original cleanup closed native owner")
   try host.close();check(server.boxCloses==1 && server.released,"original cleanup retry did not join")
  }
  Factory.shared.reset()
  do{
   let capture=IOSNodeChainExecutionCapture();let (host,server,platform)=try start(capture);server.failClose=1
   reject("failed native close accepted"){try host.close()};check(!server.released && platform.resets==0,"native close error released owner")
   try host.close();check(server.boxCloses==2 && server.released,"native close retry lost original")
  }
  do{
   let capture=IOSNodeChainExecutionCapture();let (host,server,platform)=try start(capture);server.receipt=false
   reject("missing original instance receipt accepted"){try host.close()};check(!server.released && platform.resets==0,"missing instance receipt released resources")
   capture.recordNativeClose(true);try host.close();check(server.boxCloses==1 && server.released,"late instance receipt repeated native close")
  }
  do{
   let capture=IOSNodeChainExecutionCapture(),platform=RouterVPNLibboxPlatform()
   let host=RouterVPNNodeChainExecutionHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   let path=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
   try FileManager.default.createDirectory(at:path,withIntermediateDirectories:false);try host.retainDirectory(path)
   reject("construction prematurely joined"){try host.close()}
   check(FileManager.default.fileExists(atPath:path.path) && platform.resets==0,"construction resources released before late factory")
   let late=LibboxCommandServer();reject("cancelled late server was started"){try host.bindNative(late)}
   check(capture.server===late && !late.started && !late.released,"late factory original was dropped")
   host.finishConstruction();try host.close();check(late.released && !FileManager.default.fileExists(atPath:path.path),"sealed never-acquired cleanup not joined")
  }
  do{
   let capture=IOSNodeChainExecutionCapture(),platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainExecutionHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   host.finishConstruction();try host.close();check(platform.resets==1,"pure preparation discard failed")
  }
  Factory.shared.reset()
  do{
   let capture=IOSNodeChainExecutionCapture(),gate=DispatchSemaphore(value:0);capture.runGate=gate
   let (host,server,_)=try start(capture),result=Result();host.run(adoptMeasurement:{_,_ in true},completion:result.finish)
   check(capture.runEntered.wait(timeout:.now()+4) == .success,"run did not enter")
   reject("entered proof was not retained"){try host.close()}
   check(result.wait() && result.values==[true] && server.boxCloses==0,"cancelled run closed native before return")
   gate.signal();check(capture.runReturned.wait(timeout:.now()+4) == .success,"run did not unwind")
   // The host's final join point follows the native callback return.
   for _ in 0..<100{do{try host.close();break}catch{Thread.sleep(forTimeInterval:0.005)}}
   check(server.released && result.values==[true],"late proof delivered twice or lost original close")
  }
  for withError in [false,true]{
   Factory.shared.reset();let (host,server,_)=try start(),result=Result()
   Factory.shared.errorWithOwner=withError;Factory.shared.hook={host.cancel()}
   host.run(adoptMeasurement:{_,_ in false},completion:result.finish);check(result.wait() && result.values==[true],"late factory cancellation reported success")
   for _ in 0..<100{do{try host.close();break}catch{Thread.sleep(forTimeInterval:0.005)}}
   check(Factory.shared.probe?.closed==true && server.released,"late returned measurement owner dropped")
  }
  Factory.shared.reset()
  do{
   let (host,server,_)=try start(),entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0),finished=DispatchSemaphore(value:0)
   DispatchQueue.global().async{try? host.observe{entered.signal();_ = release.wait(timeout:.now()+4)};finished.signal()}
   check(entered.wait(timeout:.now()+4) == .success,"observation did not enter")
   reject("entered observation was not retained"){try host.close()};check(server.boxCloses==0,"observation native owner closed before callback joined")
   release.signal();check(finished.wait(timeout:.now()+4) == .success,"observation did not return");try host.close()
   let events=Trace.shared.values.count;reject("stale observation admitted"){try host.observe{Trace.shared.add("forbidden")}}
   check(Trace.shared.values.count==events,"retired observation called native")
  }
  Factory.shared.reset()
  do{
   let (host,server,_)=try start(),result=Result()
   host.run(adoptMeasurement:{_,_ in true},completion:{error in do{try host.close();result.finish(error)}catch{result.finish(error)}})
   check(result.wait() && result.values==[false] && server.released,"callback stop deadlocked or ran before proof join")
  }
  do{
   Factory.shared.reset();let (host,server,platform)=try start(),result=Result()
   var current:LibboxRouterHopMeasurement?
   host.run(adoptMeasurement:{previous,next in guard previous === current else{return false};current=next;return true},completion:result.finish)
   check(result.wait() && result.values==[false],"rotation fixture proof missing")
   let old=current!;platform.mtu.optimizerRunning=true;platform.mtu.proofObservationToken=UUID()
   host.fixtureHealth();check(current === old && !old.closed,"probe rotated before full optimizer joined")
   platform.mtu.optimizerRunning=false;host.fixtureHealth()
   check(current !== old && old.closed && current === Factory.shared.probe,"proved MTU generation did not rotate exact old probe")
   let next=current;host.fixtureHealth();check(current === next,"stable MTU epoch recreated measurement")
   try host.close();check(next?.closed==true && server.released,"rotated probe was not retained for cleanup")
  }
  do{
   let capture=IOSNodeChainExecutionCapture();let (host,server,_)=try start(capture);capture.closeFailures=2
   host.retainForRetirement();reject("retirement owner joined unexpectedly"){try host.close()}
   reject("replacement admission ignored original retained owner"){try RouterVPNNodeChainExecutionHost.requireAvailable()}
   check(server.boxCloses==0,"retirement gate closed unjoined native owner")
   try RouterVPNNodeChainExecutionHost.requireAvailable();check(server.released,"retirement original retry failed")
  }
  print("PASS Apple ordered execution host: 17 ownership scenarios; native/OS boundaries doubled")
 }
}
'''

def main():
    text=HOST.read_text().replace('import Libbox\n','')
    with tempfile.TemporaryDirectory(prefix='ios-execution-host-') as d:
        work=Path(d);source=work/'Host.swift';binary=work/'host'
        command=['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(work/'modules'),str(source),'-o',str(binary)]
        def run(value):
            source.write_text(BOUNDARY+RESTORE_BOUNDARY+value+TESTS)
            subprocess.run(command,check=True,timeout=90)
            return subprocess.run([str(binary)],capture_output=True,text=True,timeout=35)
        result=run(text);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        for name,before,after,witness in (
          ('remote-before-box','            if let failure { throw failure }','            _ = failure','pending original cleanup closed native owner'),
          ('instance-receipt','            guard capture.nativeClosed() else {','            guard capture.nativeClosed() || true else {','missing original instance receipt accepted'),
          ('construction-join','let pending = constructing || runEntered || observations != 0','let pending = runEntered || observations != 0','construction prematurely joined'),
          ('observation-join','let pending = constructing || runEntered || observations != 0','let pending = constructing || runEntered','entered observation was not retained'),
          ('proof-join','let pending = constructing || runEntered || observations != 0','let pending = constructing || observations != 0','entered proof was not retained'),
          ('mtu-probe-rotation','if epoch != token, let original {','if false, let original {','proved MTU generation did not rotate exact old probe'),
          ('late-measurement','if let returned { lock.lock(); measurement = returned; lock.unlock() }','if let returned, createError == nil { lock.lock(); measurement = returned; lock.unlock() }','late returned measurement owner dropped'),
        ):
            assert text.count(before)==1,name
            result=run(text.replace(before,after,1))
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,result.stdout+result.stderr)
            print('Rejected host causal control:',name)

if __name__=='__main__':main()
