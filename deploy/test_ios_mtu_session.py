#!/usr/bin/env python3
"""Execute the real Swift MTU owner; double only generated Libbox/OS boundaries."""
from pathlib import Path
import os, platform, shutil, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[1]
SWIFT=shutil.which('swiftc')
if not SWIFT:raise SystemExit('swiftc is required; no source-only substitute')
STUB=r"""
import Foundation
public protocol LibboxRouterMTUPlatformProtocol:AnyObject {
 func captureMTU()->LibboxRouterMTUState?
 func beginMTUChange(_ expected:LibboxRouterMTUState?)throws
 func endMTUChange()throws
 func bindMTUSocket(_ expected:LibboxRouterMTUState?,fd:Int64)throws
 func readMTUCache()->String
 func compareAndSwapMTUCache(_ expected:String?,replacement:String?)->Bool
 func abortMTU(_ reason:String?)
}
public final class LibboxRouterMTUState:NSObject {
 public var session="",path="",interface="";public var mtu:Int32=0
}
public final class LibboxCommandServer:NSObject {}
public enum FakeOS {
 nonisolated(unsafe) public static var mtu:Int32=1420
 nonisolated(unsafe) public static var path="physical-path-a"
 nonisolated(unsafe) public static var readable=true
 nonisolated(unsafe) public static var bindOK=true
 nonisolated(unsafe) public static var changedDuringBind=false
 nonisolated(unsafe) public static var bound=""
 nonisolated(unsafe) public static var starts=0
 nonisolated(unsafe) public static var closes=0
 nonisolated(unsafe) public static var current:LibboxRouterMTU?
}
public final class LibboxRouterMTU:NSObject {
 private var active=false;private var request="";private var phase="idle"
 public func start(_ request:String,force:Bool)throws {
  if active {throw NSError(domain:"fixture",code:1)}
  self.request=request;active=true;phase="proving";FakeOS.starts += 1
 }
 public func cancel(_ request:String){if request==self.request{active=false;phase="cancelled"}}
 public func close()throws{FakeOS.closes += 1;active=false}
 public func networkChanged(){active=false;phase="invalidated"}
 public func running()->Bool{active}
 public func statusJSON()->String{
  let body:[String:Any]=["request_id":request,"phase":phase,"running":active,"complete":!active,
   "measured":false,"effective_mtu":Int(FakeOS.mtu),"original_mtu":1420,"source":"unmeasured","candidates":[]]
  return String(data:try! JSONSerialization.data(withJSONObject:body),encoding:.utf8)!
 }
}
public func LibboxNewRouterMTU(_ server:LibboxCommandServer?,_ platform:LibboxRouterMTUPlatformProtocol?,_ config:String?,_ profile:String?,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterMTU?{
 guard platform?.captureMTU() != nil else {error?.pointee=NSError(domain:"fixture",code:1);return nil}
 let core=LibboxRouterMTU();FakeOS.current=core;return core
}
public func LibboxRouterMTUPhysicalPath(_ name:String?,_ error:UnsafeMutablePointer<NSError?>?)->String?{
 if name != "en0" {error?.pointee=NSError(domain:"fixture",code:1);return nil};return FakeOS.path
}
public func LibboxRouterReadMTUInterface(_ name:String?,_ result:UnsafeMutablePointer<Int32>?,_ error:UnsafeMutablePointer<NSError?>?)->Bool {
 guard FakeOS.readable,name=="utun7" else{return false};result?.pointee=FakeOS.mtu;return true
}
public func LibboxRouterMTUBindInterface(_ fd:Int64,_ name:String?,_ error:UnsafeMutablePointer<NSError?>?)->Bool{
 FakeOS.bound=name ?? "";if FakeOS.changedDuringBind{FakeOS.path="changed-while-binding"};return FakeOS.bindOK
}
"""
TEST=r"""
import Foundation
import Libbox
var checks=0
@MainActor func check(_ value:Bool,_ name:String){checks += 1;if !value{fatalError(name)}}
@MainActor func rejects(_ name:String,_ block:()throws->Void){do{try block();fatalError(name)}catch{checks += 1}}
func request(_ owner:RouterVPNMTUSession,_ op:String,_ id:String,_ session:String)->[String:Any]?{
 guard let data=owner.request(operation:op,request:id,session:session) else{return nil}
 return try! JSONSerialization.jsonObject(with:data) as? [String:Any]
}
@MainActor func ready(_ hold:String="")->RouterVPNMTUSession{
 FakeOS.path="physical-path-a";FakeOS.mtu=1420;FakeOS.readable=true;FakeOS.bindOK=true;FakeOS.changedDuringBind=false
 let owner=RouterVPNMTUSession();try! owner.initialMeasurementHold(hold)
 check(owner.captureMTU()==nil,"unopened TUN looked live")
 owner.observePhysicalPath(name:"en0",signature:"route-a")
 let token=try! owner.beforeOpen(mtu:1420)
 check(owner.captureMTU()==nil,"partially opening TUN looked live")
 try! owner.didOpen(token,mtu:1420);owner.registerInterface("utun7")
 check(owner.captureMTU()?.mtu==1420,"real interface readback missing")
 return owner
}
let id=String(repeating:"a",count:32),other=String(repeating:"b",count:32)
let owner=ready();let before=owner.captureMTU()!
check(!owner.observePhysicalPath(name:"en0",signature:"route-a"),"duplicate callback reset endpoints")
rejects("unowned replacement permitted"){_ = try owner.beforeOpen(mtu:1400)}
rejects("negative socket allowed"){try owner.bindMTUSocket(before,fd:-1)}
try owner.bindMTUSocket(before,fd:42)
check(FakeOS.bound=="utun7","socket not bound to actual owned utun")
FakeOS.bindOK=false;rejects("bind failure got fallback"){try owner.bindMTUSocket(before,fd:42)};FakeOS.bindOK=true
try owner.beginMTUChange(before)
rejects("overlapping mutation permitted"){try owner.beginMTUChange(before)}
let token=try owner.beforeOpen(mtu:1400);FakeOS.mtu=1400
try owner.didOpen(token,mtu:1400);try owner.endMTUChange()
let after=owner.captureMTU()!
check(after.mtu==1400 && after.session==before.session && after.path==before.path && after.interface != before.interface,"reader replacement mutated session or failed readback")
rejects("old reader mutated new reader"){try owner.beginMTUChange(before)}
FakeOS.readable=false;check(owner.captureMTU()==nil,"invented missing MTU readback");FakeOS.readable=true
FakeOS.mtu=1380;check(owner.captureMTU()==nil,"accepted mismatched OS MTU");FakeOS.mtu=1400
let cache=owner.readMTUCache()
check(owner.compareAndSwapMTUCache(cache,replacement:"{}"),"durable private CAS failed")
check(!owner.compareAndSwapMTUCache("stale",replacement:"bad"),"stale CAS clobbered cache")
check(!owner.compareAndSwapMTUCache("{}",replacement:String(repeating:"x",count:65537)),"oversized cache stored")
check(owner.readMTUCache()=="{}","wrong cache after failed CAS")
check(request(owner,"mtu-status","short","")==nil,"malformed request accepted")
check(request(owner,"mtu-start",id,UUID().uuidString)==nil,"foreign session accepted")
check(request(owner,"arbitrary",id,before.session)==nil,"arbitrary native operation accepted")
let hold=request(owner,"mtu-hold",id,before.session)!
check(hold["measurement_ready"] as? Bool == true,"idle owned path did not grant measurement hold")
check(request(owner,"mtu-hold",other,before.session)==nil,"competing lease stole hold")
check(request(owner,"mtu-release",other,before.session)==nil,"stale lease released hold")
check(request(owner,"mtu-release",id,before.session)?["measurement_hold"] as? Bool == false,"valid lease not released")
FakeOS.changedDuringBind=true;rejects("path race during socket bind ignored"){try owner.bindMTUSocket(after,fd:42)}
owner.stop();check(owner.captureMTU()==nil,"stopped TUN came back")
rejects("stop reopened interface"){_ = try owner.beforeOpen(mtu:1400)}
check(request(owner,"mtu-status",id,"")==nil,"stopped IPC owner replied as live")
let pending=ready();let old=pending.captureMTU()!;try pending.beginMTUChange(old)
let abandoned=try pending.beforeOpen(mtu:1400);pending.stop()
rejects("late open resurrected stopped TUN"){try pending.didOpen(abandoned,mtu:1400)}
let changed=ready();changed.observePhysicalPath(name:"en0",signature:"route-b")
check(changed.captureMTU()==nil,"changed physical route retained measurement authority")
let held=ready(id),starts=FakeOS.starts
held.activate(server:LibboxCommandServer(),config:"{}",profile:"{\"mtu_policy\":\"auto\"}"){_ in}
let heldSession=held.captureMTU()!.session
check(FakeOS.starts==starts,"Auto-MTU started inside comparison hold")
check(request(held,"mtu-start",other,heldSession)?["measurement_hold"] as? Bool == true,"Retest bypassed comparison hold")
check(FakeOS.starts==starts,"held Retest reached native mutation")
_ = request(held,"mtu-release",id,heldSession)
check(FakeOS.starts==starts+1,"deferred Auto-MTU did not start after final release")
check(request(held,"mtu-hold",id,heldSession)?["measurement_ready"] as? Bool == true,"running Auto-MTU was not drained for Speed Lab")
let stoppedCount=FakeOS.closes;held.stop();check(FakeOS.closes==stoppedCount+1,"native controller not closed on Stop")
let manual=ready();let manualStarts=FakeOS.starts
manual.activate(server:LibboxCommandServer(),config:"{}",profile:"{\"mtu_policy\":\"manual\"}"){_ in}
check(FakeOS.starts==manualStarts,"manual policy silently optimized")
let jumbo=ready();jumbo.activate(server:LibboxCommandServer(),config:"{}",profile:"{\"mtu_policy\":\"auto\",\"jumbo_tun\":true}"){_ in}
check(FakeOS.starts==manualStarts,"Jumbo silently optimized")
print("Production Swift MTU owner: PASS (\(checks) checks; Libbox/OS boundary doubled)")
"""
GATE=r"""
import Foundation
@main struct Tests {
 @MainActor static func main(){
  let first=IOSMTUMeasurementGate.acquire(),second=IOSMTUMeasurementGate.acquire()
  precondition(first.request==second.request && IOSMTUMeasurementGate.held)
  precondition(!IOSMTUMeasurementGate.release(first) && IOSMTUMeasurementGate.held)
  precondition(!IOSMTUMeasurementGate.release(first))
  precondition(IOSMTUMeasurementGate.release(second) && !IOSMTUMeasurementGate.held)
  let next=IOSMTUMeasurementGate.acquire()
  precondition(next.request != first.request && !IOSMTUMeasurementGate.release(second))
  precondition(IOSMTUMeasurementGate.current==next.request && IOSMTUMeasurementGate.release(next))
  print("Production Swift MTU comparison lease: PASS")
 }
}
"""
with tempfile.TemporaryDirectory(prefix='routervpn-ios-mtu-') as directory:
 tmp=Path(directory);(tmp/'Libbox.swift').write_text(STUB);(tmp/'main.swift').write_text(TEST)
 extension = 'dylib' if platform.system() == 'Darwin' else 'so'
 env={**os.environ,'XDG_DATA_HOME':str(tmp/'data'),'HOME':str(tmp/'home')}
 def run(args):subprocess.run(args,check=True,cwd=tmp,env=env,timeout=120)
 # Compile the real production owner, not a test copy or a source-marker audit.
 run([SWIFT,'-swift-version','6','-emit-module','-emit-library','-module-name','Libbox',str(tmp/'Libbox.swift'),'-o',str(tmp/('libLibbox.'+extension))])
 source=ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNMTUSession.swift'
 run([SWIFT,'-swift-version','6','-I',str(tmp),'-L',str(tmp),'-lLibbox',str(source),str(tmp/'main.swift'),'-o',str(tmp/'test')])
 env['LD_LIBRARY_PATH']=str(tmp)
 env['DYLD_LIBRARY_PATH']=str(tmp)
 run([str(tmp/'test')])
 (tmp/'gate.swift').write_text(GATE)
 run([SWIFT,'-swift-version','6',str(ROOT/'ios/RouterVPN/App/IOSMTUMeasurementGate.swift'),str(tmp/'gate.swift'),'-o',str(tmp/'gate')])
 run([str(tmp/'gate')])
