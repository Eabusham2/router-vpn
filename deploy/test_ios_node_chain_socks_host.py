#!/usr/bin/env python3
"""Execute the shipping Apple ordered execution owner with explicit native doubles.

This is a Swift ownership/ordering gate. Libbox handles and OS interfaces are
controlled boundaries; it does not claim Apple SDK, system TUN or relay traffic.
"""
from pathlib import Path
import subprocess
import importlib.util
import tempfile

ROOT=Path(__file__).resolve().parents[1]
HOST=ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNNodeChainSOCKSHost.swift'
spec=importlib.util.spec_from_file_location('ordered_latency_boundary',ROOT/'deploy/ios_ordered_latency_boundary.py')
LATENCY=importlib.util.module_from_spec(spec);spec.loader.exec_module(LATENCY)

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
 var capture:IOSNodeChainSOCKSCapture?,started=false,service=false,released=false
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
final class LibboxRouterNodeChainSOCKS {
 var owner:IOSNodeChainSOCKSCapture?
 func bindNative(_ server:LibboxCommandServer)throws{try owner!.bindNative(server)}
 func run(_ server:LibboxCommandServer)throws{try owner!.run(server)}
 func healthy()->Bool{owner!.healthy()}
 func networkChanged(){owner!.networkChanged()}
 func close()throws{try owner!.close()}
 func nativeClosed()->Bool{owner!.nativeClosed()}
 func sourceSHA256()->String{String(repeating:"1",count:64)}
 func configSHA256()->String{String(repeating:"2",count:64)}
 func progressJSON()->String{"{\"stage\":\"selected\"}"}
}
final class IOSNodeChainSOCKSCapture:@unchecked Sendable {
 struct Member{let id:String}
 let members=[Member(id:"entry"),Member(id:"middle"),Member(id:"final")]
 let plan=LibboxRouterNodeChainSOCKS(),config="exact-preparation"
 private let lock=NSLock()
 var runGate:DispatchSemaphore?,healthGate:DispatchSemaphore?,healthEntered=DispatchSemaphore(value:0)
 let runEntered=DispatchSemaphore(value:0),runReturned=DispatchSemaphore(value:0)
 var closeFailures=0,valid=true,runFails=false,bindFails=false
 var bindHook:(()->Void)?
 private var closed=false,cancelled=false,nativeReceipt=false,ran=false,reserved=false
 private(set) var server:LibboxCommandServer?
 init(){plan.owner=self}
 func requireCurrent()throws{lock.lock();let good = !closed;lock.unlock();if !good{throw failure("closed capture")}}
 func bindNative(_ server:LibboxCommandServer)throws{
  bindHook?()
  lock.lock();defer{lock.unlock()};Trace.shared.add("bind")
  guard self.server==nil || self.server===server else{throw failure("replaced slot")}
  self.server=server;server.capture=self
  if bindFails{bindFails=false;throw failure("uncertain bind")};reserved=true
  if closed{nativeReceipt=true;throw failure("sealed empty")}
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
  guard server==nil || reserved else{throw failure("missing construction reservation")}
  closed=true;if let server,!server.service{nativeReceipt=true}
 }
 func recordNativeClose(_ valid:Bool){lock.lock();nativeReceipt=valid;lock.unlock()}
 func nativeClosed()->Bool{lock.lock();defer{lock.unlock()};Trace.shared.add("native-receipt");return closed && nativeReceipt}
}
final class MTU:@unchecked Sendable {
 func request(operation:String,request:String,session:String)->Data?{nil}
 var proofObservationToken:UUID?=UUID(),isChanging=false,optimizerRunning=false,failDrain=0,activateFailure=false,activated=false
 func observeNodeChainExecutionMeasurement(_ token:UUID,_ action:()throws->Void)throws->Bool{guard !optimizerRunning,proofObservationToken==token else{return false};try action();return true}
 func drainForNodeChainExecutionCleanup()throws{Trace.shared.add("mtu-drain");if failDrain>0{failDrain-=1;throw failure("optimizer join pending")}}
 func activateNodeChainSOCKS(server:LibboxCommandServer,plan:LibboxRouterNodeChainSOCKS,runAutomatic:Bool=true,onAbort:@escaping @Sendable(String)->Void)throws{
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
func LibboxRouterNodeChainSOCKSNewHopMeasurement(_ plan:LibboxRouterNodeChainSOCKS,_ server:LibboxCommandServer,_ error:inout NSError?)->LibboxRouterHopMeasurement?{
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
TESTS=r'''
extension RouterVPNNodeChainSOCKSHost { func fixtureHealth(){checkHealth()}; func fixtureRetains(_ original:LibboxCommandServer)->Bool{lock.lock();defer{lock.unlock()};return server === original} }
@main struct Tests {
 nonisolated(unsafe) static var scenarios=0
 static func scenario(){scenarios+=1}
 static func check(_ ok:Bool,_ name:String){if !ok{FileHandle.standardError.write(Data(("FAIL "+name+"\n").utf8));exit(1)}}
 static func reject(_ name:String,_ action:()throws->Void){do{try action();check(false,name)}catch{}}
 static func start(_ capture:IOSNodeChainSOCKSCapture=IOSNodeChainSOCKSCapture())throws->(RouterVPNNodeChainSOCKSHost,LibboxCommandServer,RouterVPNLibboxPlatform){
  let platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainSOCKSHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
  let server=LibboxCommandServer();try host.beginFactory();try host.finishFactory(server);try host.startNative();host.finishConstruction();return(host,server,platform)
 }
 static func run(_ host:RouterVPNNodeChainSOCKSHost)->Result{let r=Result();host.run(adoptMeasurement:{_,_ in true},completion:r.finish);check(r.wait() && r.values==[false],"proof success missing");return r}
 static func main()throws{
  Trace.shared.reset();Factory.shared.reset()
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture(),platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainSOCKSHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   let original=LibboxCommandServer();capture.bindHook={check(host.fixtureRetains(original),"original factory return not retained before bind")}
   try host.beginFactory();try host.finishFactory(original);capture.bindHook=nil;host.finishConstruction();try host.close()
   check(original.released,"retained-before-bind original was lost during cleanup")
  }
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture(),platform=RouterVPNLibboxPlatform(),current=Current()
   let host=RouterVPNNodeChainSOCKSHost(capture:capture,platform:platform,isCurrent:current.get,onFailure:{_ in})
   current.retire();reject("retired generation entered native factory"){try host.beginFactory()}
   host.finishConstruction();try host.close();check(capture.server==nil && platform.resets==1,"pre-factory retirement acquired a native resource")
  }
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture(),platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainSOCKSHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   try host.beginFactory();host.cancel();reject("cancelled empty factory return accepted"){try host.finishFactory(nil)}
   host.finishConstruction();try host.close();check(capture.server==nil && platform.resets==1,"joined empty factory retained nonexistent acquisition")
  }
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture(),platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainSOCKSHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   let original=LibboxCommandServer();original.failService=true
   try host.beginFactory();try host.finishFactory(original);reject("failed Box startup accepted"){try host.startNative()}
   host.finishConstruction();try host.close();check(original.boxCloses==1 && original.released && platform.resets==1,"failed original Box startup lost native close")
  }

  Trace.shared.reset();Factory.shared.reset()
  do{scenario()
   let (host,server,platform)=try start();_ = run(host);try host.activateMTU();check(platform.mtu.activated && host.progress() != nil,"owned activities missing")
   try host.close();let events=Trace.shared.values
   check(events.firstIndex(of:"bind")! < events.firstIndex(of:"server-start")! && events.firstIndex(of:"bind")! < events.firstIndex(of:"box-start")!,"native bind must precede start")
   check(events.firstIndex(of:"remote-close")! < events.firstIndex(of:"box-close")! && events.firstIndex(of:"measure-close")! < events.firstIndex(of:"box-close")!,"original joins must precede native close")
   check(events.lastIndex(of:"native-receipt")! < events.firstIndex(of:"server-release")! && server.released && platform.resets==1,"native receipt must precede resource release")
   try host.close();check(server.boxCloses==1 && platform.resets==1,"joined cleanup repeated native close")
   check(host.progress()==nil,"retired progress observed native state")
  }
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture(),platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainSOCKSHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   let original=LibboxCommandServer();capture.bindFails=true;try host.beginFactory()
   reject("failed binding accepted"){try host.finishFactory(original)}
   host.finishConstruction()
   do{try host.close()}catch{check(false,"failed initial bind did not retry original receipt")}
   check(original.released && platform.resets==1,"retried original binding did not release resources")
  }
  for pending in ["remote","measurement","mtu"]{scenario()
   Factory.shared.reset();let capture=IOSNodeChainSOCKSCapture();let (host,server,platform)=try start(capture);_ = run(host)
   if pending=="remote"{capture.closeFailures=1};if pending=="measurement"{Factory.shared.probe!.closeFailures=1};if pending=="mtu"{platform.mtu.failDrain=1}
   reject("unjoined "+pending+" cleanup accepted"){try host.close()}
   check(server.boxCloses==0 && !server.released && platform.resets==0,"pending original cleanup closed native owner")
   try host.close();check(server.boxCloses==1 && server.released,"original cleanup retry did not join")
  }
  Factory.shared.reset()
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture();let (host,server,platform)=try start(capture);server.failClose=1
   reject("failed native close accepted"){try host.close()};check(!server.released && platform.resets==0,"native close error released owner")
   try host.close();check(server.boxCloses==2 && server.released,"native close retry lost original")
  }
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture();let (host,server,platform)=try start(capture);server.receipt=false
   reject("missing original instance receipt accepted"){try host.close()};check(!server.released && platform.resets==0,"missing instance receipt released resources")
   capture.recordNativeClose(true);try host.close();check(server.boxCloses==1 && server.released,"late instance receipt repeated native close")
  }
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture(),platform=RouterVPNLibboxPlatform()
   let host=RouterVPNNodeChainSOCKSHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   let path=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
   try FileManager.default.createDirectory(at:path,withIntermediateDirectories:false);try host.retainDirectory(path)
   try host.beginFactory()
   reject("construction prematurely joined"){try host.close()}
   check(FileManager.default.fileExists(atPath:path.path) && platform.resets==0,"construction resources released before late factory")
   let late=LibboxCommandServer();reject("cancelled late server was started"){try host.finishFactory(late)}
   check(capture.server===late && !late.started && !late.released,"late factory original was dropped")
   host.finishConstruction();try host.close();check(late.released && !FileManager.default.fileExists(atPath:path.path),"sealed never-acquired cleanup not joined")
  }
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture(),platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainSOCKSHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   host.finishConstruction();try host.close();check(platform.resets==1,"pure preparation discard failed")
  }
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture(),platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainSOCKSHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   let original=LibboxCommandServer();try host.beginFactory();try host.finishFactory(original)
   reject("bound construction prematurely joined"){try host.close()}
   check(!original.released && platform.resets==0,"bound factory owner released during construction")
   host.finishConstruction();try host.close();check(original.released,"bound unstarted original did not close")
  }
  Factory.shared.reset()
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture(),gate=DispatchSemaphore(value:0);capture.runGate=gate
   let (host,server,_)=try start(capture),result=Result();host.run(adoptMeasurement:{_,_ in true},completion:result.finish)
   check(capture.runEntered.wait(timeout:.now()+4) == .success,"run did not enter")
   reject("entered proof was not retained"){try host.close()}
   check(result.wait() && result.values==[true] && server.boxCloses==0,"cancelled run closed native before return")
   gate.signal();check(capture.runReturned.wait(timeout:.now()+4) == .success,"run did not unwind")
   // The host's final join point follows the native callback return.
   for _ in 0..<100{do{try host.close();break}catch{Thread.sleep(forTimeInterval:0.005)}}
   check(server.released && result.values==[true],"late proof delivered twice or lost original close")
  }
  for withError in [false,true]{scenario()
   Factory.shared.reset();let (host,server,_)=try start(),result=Result()
   Factory.shared.errorWithOwner=withError;Factory.shared.hook={host.cancel()}
   host.run(adoptMeasurement:{_,_ in false},completion:result.finish);check(result.wait() && result.values==[true],"late factory cancellation reported success")
   for _ in 0..<100{do{try host.close();break}catch{Thread.sleep(forTimeInterval:0.005)}}
   check(Factory.shared.probe?.closed==true && server.released,"late returned measurement owner dropped")
  }
  Factory.shared.reset()
  do{scenario()
   let (host,server,_)=try start(),entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0),finished=DispatchSemaphore(value:0)
   DispatchQueue.global().async{try? host.observe{entered.signal();_ = release.wait(timeout:.now()+4)};finished.signal()}
   check(entered.wait(timeout:.now()+4) == .success,"observation did not enter")
   reject("entered observation was not retained"){try host.close()};check(server.boxCloses==0,"observation native owner closed before callback joined")
   release.signal();check(finished.wait(timeout:.now()+4) == .success,"observation did not return");try host.close()
   let events=Trace.shared.values.count;reject("stale observation admitted"){try host.observe{Trace.shared.add("forbidden")}}
   check(Trace.shared.values.count==events,"retired observation called native")
  }
  Factory.shared.reset()
  do{scenario()
   let (host,server,_)=try start(),result=Result()
   host.run(adoptMeasurement:{_,_ in true},completion:{error in do{try host.close();result.finish(error)}catch{result.finish(error)}})
   check(result.wait() && result.values==[false] && server.released,"callback stop deadlocked or ran before proof join")
  }
  do{scenario()
   Factory.shared.reset();let (host,server,platform)=try start(),result=Result()
   var current:LibboxRouterHopMeasurement?
   host.run(adoptMeasurement:{previous,next in guard previous === current else{return false};current=next;return true},completion:result.finish)
   check(result.wait() && result.values==[false],"rotation fixture proof missing")
   let old=current!;platform.mtu.optimizerRunning=true;platform.mtu.proofObservationToken=UUID()
   host.fixtureHealth();check(current === old && !old.closed,"probe rotated before full optimizer joined")
   platform.mtu.optimizerRunning=false;host.fixtureHealth()
   check(current === old && !old.closed && current === Factory.shared.probe,"authorized MTU reproof replaced original typed service")
   let next=current;host.fixtureHealth();check(current === next,"stable MTU epoch recreated measurement")
   try host.close();check(next?.closed==true && server.released,"retained probe was not joined for cleanup")
  }
  do{scenario()
   let capture=IOSNodeChainSOCKSCapture();let (host,server,_)=try start(capture);capture.closeFailures=2
   host.retainForRetirement();reject("retirement owner joined unexpectedly"){try host.close()}
   reject("replacement admission ignored original retained owner"){try RouterVPNNodeChainSOCKSHost.requireAvailable()}
   check(server.boxCloses==0,"retirement gate closed unjoined native owner")
   try RouterVPNNodeChainSOCKSHost.requireAvailable();check(server.released,"retirement original retry failed")
  }
  check(scenarios==21,"original host scenario inventory changed")
  print("PASS Apple typed SOCKS host: \(scenarios) ownership scenarios; native/OS boundaries doubled")
 }
}
'''

def main():
    text=HOST.read_text().replace('import Libbox\n','')
    with tempfile.TemporaryDirectory(prefix='ios-execution-host-') as d:
        work=Path(d);source=work/'Host.swift';binary=work/'host'
        command=['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(work/'modules'),str(source),'-o',str(binary)]
        def run(value):
            source.write_text(BOUNDARY+LATENCY.NATIVE.replace('public ','')+(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNOrderedLatency.swift').read_text().replace('import Libbox\n','')+value+TESTS)
            subprocess.run(command,check=True,timeout=90)
            return subprocess.run([str(binary)],capture_output=True,text=True,timeout=35)
        result=run(text);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        for name,before,after,witness in (
          ('shared-before-box','            if let failure { throw failure }','            _ = failure','pending original cleanup closed native owner'),
          ('native-receipt','            guard capture.plan.nativeClosed() else {','            guard capture.plan.nativeClosed() || true else {','missing original instance receipt accepted'),
          ('construction-join','let pending = constructing || factoryEntered || runEntered || observations != 0','let pending = runEntered || observations != 0','bound construction prematurely joined'),
          ('observation-join','let pending = constructing || factoryEntered || runEntered || observations != 0','let pending = constructing || factoryEntered || runEntered','entered observation was not retained'),
          ('proof-join','let pending = constructing || factoryEntered || runEntered || observations != 0','let pending = constructing || factoryEntered || observations != 0','entered proof was not retained'),
          ('mtu-probe-rotation','        if previous != nil {','        try previous?.close()\n        if false {','authorized MTU reproof replaced original typed service'),
          ('late-measurement','if let returned { lock.lock(); measurement = returned; lock.unlock() }','if let returned, createError == nil { lock.lock(); measurement = returned; lock.unlock() }','late returned measurement owner dropped'),
          ('retain-before-bind','server = value; factoryEntered = false; factoryJoined = true; lock.unlock()','_ = value; factoryEntered = false; factoryJoined = true; lock.unlock()','original factory return not retained before bind'),
          ('failed-bind-retry','            if let unbound { try? capture.plan.bindNative(unbound) }','            _ = unbound','failed initial bind did not retry original receipt'),
        ):
            assert text.count(before)==1,name
            result=run(text.replace(before,after,1))
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,result.stdout+result.stderr)
            print('Rejected typed SOCKS host causal control:',name)

if __name__=='__main__':main()
