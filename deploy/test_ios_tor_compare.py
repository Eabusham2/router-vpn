#!/usr/bin/env python3
"""Execute shipping Apple Tor Compare host/provider callbacks under Swift 6.

The complete Swift host and the real PacketTunnel capture/install/activation
methods are compiled. OS handles, native compiler and Go round are explicit
boundaries; shared Go coordinator/native tests separately prove actual scoring,
HTTP/TLS and native stream lifetimes. This gate claims no public Tor or device
traffic. The fake Go round never supplies timing to a production network path.
"""
from pathlib import Path
import importlib.util
import os
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TUN = ROOT / 'ios/RouterVPN/PacketTunnel'
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('tor_compare_crypto', ROOT / 'deploy/test_ios_physical_path.py')
CRYPTO = importlib.util.module_from_spec(spec); spec.loader.exec_module(CRYPTO)

LIBBOX = r'''
import Foundation
public protocol LibboxRouterTorCompareCandidateProtocol: NSObjectProtocol {
 func current()->Bool;func start()throws;func server()->LibboxCommandServer?;func proof()->LibboxRouterTorProofRequest?;func cancel();func close()throws
}
public protocol LibboxRouterTorCompareHostProtocol: NSObjectProtocol {
 func current()->Bool;func newCandidate(_ execution:String?,target:String?)->(any LibboxRouterTorCompareCandidateProtocol)?;func progress(_ stage:String?,execution:String?)
}
public final class LibboxCommandServer { public init(){} }
public final class LibboxRouterTorProofRequest { public init(){} }
public final class CompareBoundary: @unchecked Sendable {
 public static let shared=CompareBoundary()
 private let lock=NSLock();private var value:LibboxRouterTorCompare?
 public var winner="local",fault="",target="https://1.1.1.1/cdn-cgi/trace"
 public var keepEntered=DispatchSemaphore(value:0),keepRelease=DispatchSemaphore(value:0)
 public func reset(_ fault:String="",winner:String="local") {
  lock.lock();self.fault=fault;self.winner=winner;value=nil;keepEntered=DispatchSemaphore(value:0);keepRelease=DispatchSemaphore(value:0);lock.unlock()
 }
 public func made(_ round:LibboxRouterTorCompare){lock.lock();value=round;lock.unlock()}
 public func current()->LibboxRouterTorCompare?{lock.lock();defer{lock.unlock()};return value}
}
public final class LibboxRouterTorCompare: @unchecked Sendable {
 private let host:any LibboxRouterTorCompareHostProtocol
 private let entry:String,exit:String,mode:String
 private let lock=NSLock();private var active:(any LibboxRouterTorCompareCandidateProtocol)?,kept=false,cancelled=false
 public private(set) var paths:[any LibboxRouterTorCompareCandidateProtocol]=[]
 public private(set) var targets:[String]=[]
 public private(set) var keeps=0,closes=0
 init(_ host:any LibboxRouterTorCompareHostProtocol,_ entry:String,_ exit:String,_ mode:String){self.host=host;self.entry=entry;self.exit=exit;self.mode=mode}
 public func run()throws {
  let fixture=CompareBoundary.shared
  let failedFinal=fixture.winner=="local" ? "server":"local"
  let executions=fixture.fault=="final-fallback" ? ["local","server",failedFinal,fixture.winner]:["local","server",fixture.winner]
  for (index,execution) in executions.enumerated() {
   guard host.current() else{throw Self.error()}
   host.progress(index>=2 ? "rechecking":"starting",execution:execution)
   let selectedTarget=fixture.fault=="changed-target" && index==1 ? "https://1.0.0.1/cdn-cgi/trace":fixture.target
   guard let candidate=host.newCandidate(execution,target:selectedTarget) else{throw Self.error()}
   lock.lock();active=candidate;paths.append(candidate);targets.append(fixture.target);let stopped=cancelled;lock.unlock()
   if stopped{candidate.cancel();throw Self.error()}
   try candidate.start()
   guard candidate.current(),candidate.server() != nil,candidate.proof() != nil,host.current() else{throw Self.error()}
   if index<executions.count-1{try candidate.close();lock.lock();active=nil;lock.unlock()}
  }
 }
 public func resultJSON()->String {
  let fixture=CompareBoundary.shared
  func path(_ choice:String)->[String:Any]{["execution":choice,"entry_id":entry,"exit_id":exit,"transport":mode]}
  func measurement(_ choice:String)->[String:Any]{["candidate":path(choice),"last_node_ms":choice==fixture.winner ? 20.0:40.0,"external_ms":choice==fixture.winner ? 30.0:50.0,"score_ms":choice==fixture.winner ? 25.0:45.0,"eligible":true]}
  var value:[String:Any]=["target":fixture.target,"measurements":[measurement("local"),measurement("server")],"winner":path(fixture.winner),"final":measurement(fixture.winner)]
  switch fixture.fault {
  case "wrong-target":value["target"]="https://unselected.invalid/"
  case "result-other-target":value["target"]="https://1.0.0.1/cdn-cgi/trace"
  case "wrong-owner":var winner=path(fixture.winner);winner["entry_id"]="replacement";value["winner"]=winner
  case "zero","wrong-score","bool-score","final-failed":var final=measurement(fixture.winner);if fixture.fault=="zero"{final["last_node_ms"]=0}else if fixture.fault=="wrong-score"{final["score_ms"]=50}else if fixture.fault=="bool-score"{final["score_ms"]=true}else{final["eligible"]=false;final["failure"]="failed";final.removeValue(forKey:"score_ms")};value["final"]=final
  case "scored-failure":var failed=measurement("server");failed["eligible"]=false;failed["failure"]="timeout";value["measurements"]=[measurement("local"),failed]
  case "duplicate":value["measurements"]=[measurement("local"),measurement("local")]
  case "ineligible-winner":value["measurements"]=[["candidate":path(fixture.winner),"eligible":false,"failure":"timeout"],measurement("server")]
  case "higher-winner":var cheaper=measurement("server");cheaper["last_node_ms"]=10.0;cheaper["external_ms"]=20.0;cheaper["score_ms"]=15.0;value["measurements"]=[measurement("local"),cheaper]
  case "final-fallback":
   let failedChoice=fixture.winner=="local" ? "server":"local"
   var failed=measurement(failedChoice);failed["last_node_ms"]=10.0;failed["external_ms"]=20.0
   failed["eligible"]=false;failed["failure"]="Final proof failed";failed.removeValue(forKey:"score_ms")
   value["measurements"]=fixture.winner=="local" ? [measurement("local"),failed]:[failed,measurement("server")]
  default:break
  }
  return String(decoding:try! JSONSerialization.data(withJSONObject:value),as:UTF8.self)
 }
 public func execution()->String{lock.lock();defer{lock.unlock()};return cancelled ? "":CompareBoundary.shared.winner}
 public func keep()throws {
  let fixture=CompareBoundary.shared;fixture.keepEntered.signal()
  if fixture.fault=="hold-keep"{guard fixture.keepRelease.wait(timeout:.now()+5) == .success else{throw Self.error()}}
  lock.lock();defer{lock.unlock()};guard !cancelled,active?.current()==true else{throw Self.error()};keeps += 1;kept=true
 }
 public func cancel(){lock.lock();if kept{lock.unlock();return};cancelled=true;let path=active;lock.unlock();path?.cancel()}
 public func close()throws{lock.lock();closes += 1;let held=kept,path=active;lock.unlock();if held{return};cancel();try path?.close()}
 private static func error()->NSError{NSError(domain:"GoRoundBoundary",code:1)}
}
public func LibboxRouterTorNewCompare(_ host:(any LibboxRouterTorCompareHostProtocol)?,_ entry:String,_ exit:String,_ mode:String,_ source:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterTorCompare? {
 guard let host,host.current() else{return nil};let round=LibboxRouterTorCompare(host,entry,exit,mode);CompareBoundary.shared.made(round);return round
}
'''

BOUNDARIES = r'''
import Foundation
import CryptoKit
import Libbox
struct RouterVPNExternalExitRuntime {
 let protocolName:String,expectedPublicIP:String,files:[String:Data]
 let torSessionID:String?,torPredecessorProfile:String?,torProfileJSON:String?,torSourceProfileJSON:String?,torExecution:String?
}
enum RouterVPNExternalExitBuilder {
 static func build(profile:[String:Any],predecessorFiles:[String:Data],predecessorProfile:[String:Any]?,restoredExecution:String?)throws->RouterVPNExternalExitRuntime {
  guard let execution=restoredExecution,let entry=predecessorProfile,entry["node_kind"] as? String=="router-vpn" else{throw IOSMultihopExecution.issue()}
  let leaf=try IOSMultihopExecution.torLeaf(profile,execution:execution)
  let encoded=try JSONSerialization.data(withJSONObject:leaf,options:.sortedKeys),original=try JSONSerialization.data(withJSONObject:profile,options:.sortedKeys)
  return RouterVPNExternalExitRuntime(protocolName:"tor",expectedPublicIP:"",files:["sing-box.json":encoded],torSessionID:UUID().uuidString,torPredecessorProfile:String(decoding:try JSONSerialization.data(withJSONObject:entry),as:UTF8.self),torProfileJSON:String(decoding:encoded,as:UTF8.self),torSourceProfileJSON:String(decoding:original,as:UTF8.self),torExecution:execution)
 }
}
final class EngineBoundary: @unchecked Sendable {
 let lock=NSLock();var engines:[RouterVPNLibboxEngine]=[],live=Set<Int>(),events:[String]=[],maximum=0
 var physicalOwners=Set<ObjectIdentifier>()
 var holdStart=false,holdProof=false,holdClose=false,failClose=false,failMTU=false
 var closeIndex=0
 let startEntered=DispatchSemaphore(value:0),startRelease=DispatchSemaphore(value:0),closeEntered=DispatchSemaphore(value:0),closeRelease=DispatchSemaphore(value:0)
 let proofEntered=DispatchSemaphore(value:0),proofRelease=DispatchSemaphore(value:0)
 func record(_ event:String){lock.lock();events.append(event);lock.unlock()}
 func values()->([String],Int,Int){lock.lock();defer{lock.unlock()};return(events,maximum,live.count)}
}
final class RouterVPNLibboxEngine {
 let settingsEpoch:String
 let fixture:EngineBoundary
 let index:Int
 private let lock=NSLock();private var started=false,stopped=false,cancelled=false,proved=false
 private let native=LibboxCommandServer(),request=LibboxRouterTorProofRequest()
 init(tunnel:PacketTunnelProvider,strategyEpoch:String?=nil){settingsEpoch=strategyEpoch ?? UUID().uuidString;fixture=tunnel.fixture;let physical=tunnel.currentPathProofGuard();fixture.lock.lock();index=fixture.engines.count;fixture.engines.append(self);if let physical{fixture.physicalOwners.insert(ObjectIdentifier(physical))};fixture.lock.unlock()}
 func prepareMTUHold(_ hold:String)throws{fixture.record("hold:\(index):\(hold)")}
 func start(files:[String:Data],strict:Bool)throws {
  fixture.lock.lock();let blocked=fixture.holdStart && index==0;fixture.live.insert(index);fixture.maximum=max(fixture.maximum,fixture.live.count);fixture.events.append("start:\(index)");fixture.lock.unlock()
  if blocked{fixture.startEntered.signal();guard fixture.startRelease.wait(timeout:.now()+5) == .success else{throw IOSMultihopExecution.issue()}}
  lock.lock();defer{lock.unlock()};guard !stopped,!cancelled else{throw IOSMultihopExecution.issue()};started=true
 }
 func proveTor(sessionID:String,profile:String,predecessorProfile:String?,sourceProfile:String?,completion:@escaping(Error?)->Void){
  fixture.lock.lock();let blocked=fixture.holdProof && index==0;fixture.lock.unlock()
  if blocked{fixture.proofEntered.signal();guard fixture.proofRelease.wait(timeout:.now()+5) == .success else{completion(IOSMultihopExecution.issue());return}}
  lock.lock();proved=started && !stopped && !cancelled;let valid=proved;lock.unlock();fixture.record("proof:\(index)");completion(valid ? nil:IOSMultihopExecution.issue())
 }
 func torComparisonNative()->(LibboxCommandServer,LibboxRouterTorProofRequest)?{lock.lock();defer{lock.unlock()};return proved && !cancelled && !stopped ? (native,request):nil}
 func invalidateMultihop(){lock.lock();cancelled=true;proved=false;lock.unlock();fixture.record("cancel:\(index)")}
 func stopCheckedForStrategy()throws {
  lock.lock();let finished=stopped;lock.unlock();if finished{return}
  fixture.lock.lock();let blocked=fixture.holdClose && index==fixture.closeIndex,failed=fixture.failClose && index==fixture.closeIndex;fixture.lock.unlock()
  if blocked{fixture.closeEntered.signal();guard fixture.closeRelease.wait(timeout:.now()+5) == .success else{throw IOSMultihopExecution.issue()}}
  if failed{throw IOSMultihopExecution.issue()}
  lock.lock();stopped=true;proved=false;lock.unlock();fixture.lock.lock();fixture.live.remove(index);fixture.events.append("close:\(index)");fixture.lock.unlock()
 }
 func enableExternalHopMeasurement(exitID:String)throws{guard torComparisonNative() != nil else{throw IOSMultihopExecution.issue()};fixture.record("hop:\(index):\(exitID)")}
 func enableExternalDNSMeasurement(exitID:String)throws{guard torComparisonNative() != nil else{throw IOSMultihopExecution.issue()};fixture.record("dns:\(index):\(exitID)")}
 func activateTorMTU()throws{fixture.lock.lock();let failed=fixture.failMTU;fixture.lock.unlock();if failed{throw IOSMultihopExecution.issue()};fixture.record("mtu:\(index)")}
 func bindTorExecutionSource(_ source:IOSMultihopExecution.Source)throws{guard torComparisonNative() != nil,source.requested=="auto" else{throw IOSMultihopExecution.issue()};fixture.record("receipt:\(index):\(source.requested)")}
 func stop(){try? stopCheckedForStrategy()}
}
final class NetworkProofGuard {}
final class StrategyBoundary {let currentEpoch="unused";func stop(){};func isCurrent(_ value:String)->Bool{false};func invalidate(epoch:String){}}
final class StrategyDriverBoundary {func drain(_ completion:()->Void){completion()}}
final class MAXStartBoundary {func cancelAndDrain(_ completion:()->Void){completion()}}
final class WireGuardBoundary {func stop(_ completion:(Error?)->Void){completion(nil)}}
enum NEProviderStopReason {case userInitiated}
class PacketTunnelBase {func stopTunnel(with reason:NEProviderStopReason,completionHandler:@escaping()->Void){}}
final class PacketTunnelProvider: PacketTunnelBase, @unchecked Sendable {
 let fixture=EngineBoundary()
 private let torCompareOwnerLock=NSLock(),pathLock=NSLock()
 private var torCompareOwner:RouterVPNTorCompare?,torCompareGuard:NetworkProofGuard?,torCompareDraining=false
 private var libboxEngine:RouterVPNLibboxEngine?
 private var guardState:NetworkProofGuard?
 private var multihopExecutionSource:IOSMultihopExecution.Source?
 private var initialMTUHold=String(repeating:"d",count:32)
 private let maxStartOwnerLock=NSLock(),strategyOwnerLock=NSLock()
 private var maxStartGeneration=UUID(),maxStartDraining=false
 private var maxStartOwner:MAXStartBoundary?,wireGuardAdapter:WireGuardBoundary?,providerStrategy:StrategyBoundary?
 private var strategyDriver:StrategyDriverBoundary?
 func tunnelError(_ number:Int,_ text:String)->NSError{NSError(domain:"ProviderBoundary",code:number,userInfo:[NSLocalizedDescriptionKey:text])}
 func beginLibboxSettings(epoch:String){fixture.record("epoch:"+epoch)}
 func currentPathProofGuard()->NetworkProofGuard?{pathLock.lock();defer{pathLock.unlock()};return guardState}
 func armNetworkProofGuard()->NetworkProofGuard{let value=NetworkProofGuard();pathLock.lock();guardState=value;pathLock.unlock();return value}
 func releasePathProofGuard(_ value:NetworkProofGuard){pathLock.lock();if guardState === value{guardState=nil};pathLock.unlock()}
 func currentProviderStrategy()->StrategyBoundary?{nil}
 func retireLibboxSettings(epoch:String){}
 func writeLibboxLog(_ text:String){fixture.record("log:"+text)}
 func cancelTunnelWithError(_ error:Error){currentTorComparison()?.cancel();fixture.record("tunnel-cancel")}
 func nativeLibboxFailure(_ engine:RouterVPNLibboxEngine,error:Error){if self.engine() === engine{cancelTunnelWithError(error)}}
 func clearPathProofGuard(){pathLock.lock();guardState=nil;pathLock.unlock();fixture.record("provider-stopped")}
 func cancelActiveProof(){}
 // SHIPPING_PROVIDER
 func begin(_ result:ResultBox,kind:String="tor")throws {
  let entry:[String:Any]=["id":"entry","node_kind":"router-vpn","node_proof_id":String(repeating:"b",count:64)]
  var external:[String:Any]=["protocol":kind,"expected_public_ip":""]
  if kind=="tor-bridge"{external["tor_bridge"]=["transport":"obfs4","bridges":["private captured bridge"]]}
  let selected:[String:Any]=["id":"exit","node_kind":"external","external":external,"multihop_enabled":true,"multihop_execution":"auto","multihop_entry_id":"entry","multihop_entry_mode":"wg","multihop_exit_id":"exit","multihop_exit_mode":kind,"dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","ipv6_mode":"off","home_lan_access":false]
  let config:[String:Any]=["engine":"external-libbox","mode":"external-"+kind,"bundle":try JSONSerialization.data(withJSONObject:["selectedRouterID":"exit","routerProfiles":[selected]]),"tor_entry_bundle":try JSONSerialization.data(withJSONObject:["selectedRouterID":"entry","routerProfiles":[entry]]),"tor_entry_mode":"wg"]
  multihopExecutionSource=try IOSMultihopExecution.Source(configuration:config){SHA256.hash(data:$0).map{String(format:"%02x",$0)}.joined()}
  try beginTorComparison(profile:selected,entry:ExternalLibboxInputs(files:[:],profile:entry,strict:true),completion:result.finish)
 }
 func owner()->RouterVPNTorCompare?{currentTorComparison()}
 func wholeStop(_ result:ResultBox){stopTunnel(with:.userInitiated){result.finish(nil)}}
 func startupDraining()->Bool{maxStartOwnerLock.lock();defer{maxStartOwnerLock.unlock()};return maxStartDraining}
 func engine()->RouterVPNLibboxEngine?{torCompareOwnerLock.lock();defer{torCompareOwnerLock.unlock()};return libboxEngine}
 func changePath(cancel:Bool=true){_ = armNetworkProofGuard();if cancel{currentTorComparison()?.cancel()}}
 func replacement(keepOwner:Bool=false)->RouterVPNLibboxEngine{let next=RouterVPNLibboxEngine(tunnel:self);torCompareOwnerLock.lock();libboxEngine=next;if !keepOwner{torCompareOwner=nil;torCompareGuard=nil};torCompareOwnerLock.unlock();if !keepOwner{_ = armNetworkProofGuard()};return next}
}
final class ResultBox: @unchecked Sendable {
 let completed=DispatchSemaphore(value:0);private let lock=NSLock();private var results:[Bool]=[]
 func finish(_ error:Error?){lock.lock();results.append(error != nil);lock.unlock();completed.signal()}
 func values()->[Bool]{lock.lock();defer{lock.unlock()};return results}
 func wait()->Bool{completed.wait(timeout:.now()+8) == .success}
}
'''
TESTS = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ valid:@autoclosure()->Bool){guard valid()else{fatalError("FAIL: "+name)};checks += 1}
 static func main()throws {
  for winner in ["local","server"]{for kind in ["tor","tor-bridge"]{
   CompareBoundary.shared.reset(winner:winner)
   let provider=PacketTunnelProvider(),result=ResultBox();try provider.begin(result,kind:kind)
   check("final proved winner completes once",result.wait() && result.values()==[false])
   let round=CompareBoundary.shared.current()!,host=provider.owner()!,engine=provider.engine()!,events=provider.fixture.values()
   check("sequential engines keep one physical path and distinct settings owners",provider.fixture.engines.count==3 && Set(provider.fixture.engines.map{$0.settingsEpoch}).count==3 && provider.fixture.physicalOwners.count==1 && events.1==1 && events.2==1)
   check("both candidates and final repeat use one target",round.targets==Array(repeating:CompareBoundary.shared.target,count:3) && round.keeps==1)
   check("only the transferred winner publishes measurements and receipt",events.0.filter{$0.hasPrefix("hop:") || $0.hasPrefix("dns:") || $0.hasPrefix("mtu:") || $0.hasPrefix("receipt:")}==["hop:2:exit","dns:2:exit","mtu:2","receipt:2:auto"])
   check("native teardown precedes every replacement",events.0.firstIndex(of:"close:0")!<events.0.firstIndex(of:"start:1")! && events.0.firstIndex(of:"close:1")!<events.0.firstIndex(of:"start:2")!)
   let progress=try JSONSerialization.jsonObject(with:host.progressData()!) as! [String:Any]
   check("progress identifies actual response measurements",progress["execution"] as? String==winner && progress["last_node_measurement"] as? String=="tor-relay-http-response-time" && progress["external_measurement"] as? String=="https-response-time")
   host.cancel();try round.close();round.paths.last!.cancel();try round.paths.last!.close()
   let drained=ResultBox();host.cancelAndDrain(drained.finish)
   check("late round and candidate cleanup cannot stop adopted VPN",drained.wait() && drained.values()==[false] && provider.engine() === engine && engine.torComparisonNative() != nil && provider.fixture.values().2==1)
   let replacement=provider.replacement();try round.paths.last!.close();try round.close()
   check("old cleanup never clears a replacement",provider.engine() === replacement)
   try engine.stopCheckedForStrategy()
  }}
  // The shared coordinator disqualifies an initially cheaper path when its
  // final repeat fails. The host must retain the next proved path while still
  // rejecting an unexplained higher-score winner below. These are native
  // callback/result boundaries, not fabricated live timing measurements.
  for winner in ["local","server"]{for kind in ["tor","tor-bridge"]{
   CompareBoundary.shared.reset("final-fallback",winner:winner)
   let provider=PacketTunnelProvider(),result=ResultBox();try provider.begin(result,kind:kind)
   check("disqualified final failure permits proved fallback "+winner,result.wait() && result.values()==[false])
   let round=CompareBoundary.shared.current()!,host=provider.owner()!,engine=provider.engine()!,events=provider.fixture.values()
   check("fallback keeps one physical owner with four sequential native engines",provider.fixture.engines.count==4 && Set(provider.fixture.engines.map{$0.settingsEpoch}).count==4 && provider.fixture.physicalOwners.count==1 && events.1==1 && events.2==1)
   check("fallback repeats both candidates on the same captured target",round.targets==Array(repeating:CompareBoundary.shared.target,count:4) && round.keeps==1)
   let progress=try JSONSerialization.jsonObject(with:host.progressData()!) as! [String:Any]
   let measurements=progress["measurements"] as! [[String:Any]]
   let failed=measurements.first{($0["candidate"] as? [String:Any])?["execution"] as? String != winner}!
   let selected=measurements.first{($0["candidate"] as? [String:Any])?["execution"] as? String == winner}!
   check("failed final candidate has no score in accepted progress",failed["eligible"] as? Bool==false && failed["score_ms"]==nil && failed["failure"] as? String=="Final proof failed")
   check("valid fallback preserves exact winner score and saved requested auto",selected["score_ms"] as? Double==25 && progress["execution"] as? String==winner && progress["complete"] as? Bool==true && events.0.contains("receipt:3:auto"))
   check("failed final engine is joined before fallback starts",events.0.firstIndex(of:"close:0")!<events.0.firstIndex(of:"start:1")! && events.0.firstIndex(of:"close:1")!<events.0.firstIndex(of:"start:2")! && events.0.firstIndex(of:"close:2")!<events.0.firstIndex(of:"start:3")!)
   check("only proved fallback publishes native measurements",events.0.filter{$0.hasPrefix("hop:") || $0.hasPrefix("dns:") || $0.hasPrefix("mtu:") || $0.hasPrefix("receipt:")}==["hop:3:exit","dns:3:exit","mtu:3","receipt:3:auto"])
   host.cancel();try round.close();for path in round.paths{path.cancel();try path.close()}
   check("failed trial cleanup cannot stop transferred fallback",provider.engine() === engine && engine.torComparisonNative() != nil && provider.fixture.values().2==1)
   try engine.stopCheckedForStrategy()
  }}
  for fault in ["wrong-target","result-other-target","changed-target","wrong-owner","zero","wrong-score","bool-score","final-failed","scored-failure","duplicate","ineligible-winner","higher-winner"] {
   CompareBoundary.shared.reset(fault)
   let provider=PacketTunnelProvider(),result=ResultBox();try provider.begin(result)
   check("invalid native result is rejected "+fault,result.wait() && result.values()==[true])
   check("invalid result never activates and fully drains "+fault,!provider.fixture.values().0.contains(where:{$0.hasPrefix("receipt:")}) && provider.fixture.values().2==0 && CompareBoundary.shared.current()!.keeps==0)
  }
  do {
   CompareBoundary.shared.reset();let provider=PacketTunnelProvider(),result=ResultBox();provider.fixture.holdClose=true;try provider.begin(result)
   check("actual close entered before next trial",provider.fixture.closeEntered.wait(timeout:.now()+3) == .success && provider.fixture.engines.count==1)
   let old=provider.owner()!;provider.changePath();provider.fixture.closeRelease.signal()
   check("physical path change rejects pending result",result.wait() && result.values()==[true] && provider.fixture.engines.count==1)
   let joined=ResultBox();old.cancelAndDrain(joined.finish)
   check("physical cancellation joins only old owner",joined.wait() && provider.fixture.values().2==0)
  }
  do {
   CompareBoundary.shared.reset();let provider=PacketTunnelProvider(),result=ResultBox();provider.fixture.holdStart=true;try provider.begin(result)
   check("startup is entered under captured candidate",provider.fixture.startEntered.wait(timeout:.now()+3) == .success)
   let host=provider.owner()!,joined=ResultBox();host.cancelAndDrain(joined.finish)
   check("cancel does not allocate a replacement",provider.fixture.engines.count==1)
   provider.fixture.startRelease.signal()
   check("pending startup joins before round drain",result.wait() && result.values()==[true] && joined.wait() && joined.values()==[false] && provider.fixture.values().2==0)
  }
  do {
   CompareBoundary.shared.reset("hold-keep");let provider=PacketTunnelProvider(),result=ResultBox();try provider.begin(result)
   check("Keep begins after final trial",CompareBoundary.shared.keepEntered.wait(timeout:.now()+3) == .success)
   let old=provider.owner()!,replacement=provider.replacement();old.cancel();CompareBoundary.shared.keepRelease.signal()
   check("replacement during Keep prevents adoption",result.wait() && result.values()==[true] && provider.engine() === replacement && !provider.fixture.values().0.contains(where:{$0.hasPrefix("receipt:")}))
   check("cancelled Keep drains captured final engine",provider.fixture.values().2==0)
  }
  for fault in ["path","engine"] {
   CompareBoundary.shared.reset("hold-keep");let provider=PacketTunnelProvider(),result=ResultBox();try provider.begin(result)
   check("final transfer is held for ownership race "+fault,CompareBoundary.shared.keepEntered.wait(timeout:.now()+3) == .success)
   let host=provider.owner()!
   if fault=="path"{provider.changePath(cancel:false)}else{_ = provider.replacement(keepOwner:true)}
   CompareBoundary.shared.keepRelease.signal()
   check("live owner check independently rejects changed "+fault,result.wait() && result.values()==[true] && !provider.fixture.values().0.contains(where:{$0.hasPrefix("receipt:")}))
   check("changed owner cannot transfer the final native trial "+fault,CompareBoundary.shared.current()!.keeps==0)
   let joined=ResultBox();host.cancelAndDrain(joined.finish);check("retired original owner drains "+fault,joined.wait() && joined.values()==[false] && provider.fixture.values().2==0)
  }
  do {
   CompareBoundary.shared.reset("hold-keep");let provider=PacketTunnelProvider(),result=ResultBox();try provider.begin(result)
   check("new trial retains final settings token",CompareBoundary.shared.keepEntered.wait(timeout:.now()+3) == .success)
   let old=provider.fixture.engines[0],current=provider.engine()!
   check("retired platform has no current settings authority",!provider.isStrategySettings(epoch:old.settingsEpoch) && provider.isStrategySettings(epoch:current.settingsEpoch))
   provider.nativeLibboxSettingsInvalidated(epoch:old.settingsEpoch)
   CompareBoundary.shared.keepRelease.signal()
   check("late old settings failure cannot cancel the final owner",result.wait() && result.values()==[false] && provider.engine() === current && !provider.fixture.values().0.contains("tunnel-cancel"))
   try current.stopCheckedForStrategy()
  }
  do {
   CompareBoundary.shared.reset();let provider=PacketTunnelProvider(),result=ResultBox();provider.fixture.failClose=true;try provider.begin(result)
   check("failed teardown prevents candidate replacement",result.wait() && result.values()==[true] && provider.fixture.engines.count==1 && provider.fixture.values().2==1 && provider.owner() != nil)
   let host=provider.owner()!,joined=ResultBox();provider.fixture.lock.lock();provider.fixture.failClose=false;provider.fixture.lock.unlock();host.cancelAndDrain(joined.finish)
   check("failed close remains retained and retryable",joined.wait() && joined.values()==[false] && host.isDrained && provider.fixture.values().2==0)
  }
  do {
   CompareBoundary.shared.reset();let provider=PacketTunnelProvider(),result=ResultBox();provider.fixture.failMTU=true;try provider.begin(result)
   check("post-Keep activation failure stops exact adopted path",result.wait() && result.values()==[true] && provider.fixture.values().2==0 && !provider.fixture.values().0.contains(where:{$0.hasPrefix("receipt:")}))
   check("joined activation failure releases comparison admission",provider.owner()==nil && provider.engine()==nil && provider.currentPathProofGuard()==nil)
   provider.fixture.lock.lock();provider.fixture.failMTU=false;provider.fixture.lock.unlock();CompareBoundary.shared.reset()
   let retry=ResultBox();try provider.begin(retry)
   check("joined activation failure permits immediate retry",retry.wait() && retry.values()==[false] && provider.fixture.values().2==1)
   let stopped=ResultBox();provider.wholeStop(stopped);check("activation retry drains its exact new owner",stopped.wait() && !provider.startupDraining() && provider.fixture.values().2==0)
  }
  do {
   CompareBoundary.shared.reset();let provider=PacketTunnelProvider(),result=ResultBox()
   provider.fixture.failMTU=true;provider.fixture.failClose=true;provider.fixture.closeIndex=2;try provider.begin(result)
   check("activation cleanup failure retains actual native owner",result.wait() && result.values()==[true] && provider.owner() != nil && provider.engine() != nil && provider.fixture.values().2==1)
   let owner=provider.owner()!,engine=provider.engine()!;var rejected=false
   do{try provider.begin(ResultBox())}catch{rejected=true}
   check("unjoined activation failure cannot release admission",rejected && !owner.isDrained && provider.owner() === owner && provider.engine() === engine)
   provider.fixture.lock.lock();provider.fixture.failClose=false;provider.fixture.lock.unlock();let stopped=ResultBox();provider.wholeStop(stopped)
   check("failed activation cleanup remains retryable through whole stop",stopped.wait() && !provider.startupDraining() && provider.owner()==nil && provider.engine()==nil && provider.fixture.values().2==0)
   provider.fixture.lock.lock();provider.fixture.failMTU=false;provider.fixture.lock.unlock();CompareBoundary.shared.reset();let retry=ResultBox();try provider.begin(retry)
   check("joined activation cleanup retry permits fresh native owner",retry.wait() && retry.values()==[false] && provider.fixture.values().2==1)
   let done=ResultBox();provider.wholeStop(done);check("activation cleanup replacement drains independently",done.wait() && !provider.startupDraining() && provider.fixture.values().2==0)
  }
  for replacement in [false,true] {
   CompareBoundary.shared.reset();let provider=PacketTunnelProvider(),result=ResultBox();try provider.begin(result)
   check("whole stop starts with an adopted winner",result.wait() && result.values()==[false])
   let host=provider.owner()!,engine=provider.engine()!,stopped=ResultBox()
   provider.fixture.lock.lock();provider.fixture.closeIndex=2;provider.fixture.holdClose=true;provider.fixture.lock.unlock()
   provider.wholeStop(stopped)
   check("whole stop joins actual adopted native service",provider.fixture.closeEntered.wait(timeout:.now()+3) == .success)
   var rejected=false;do{try provider.begin(ResultBox())}catch{rejected=true}
   check("pending whole stop retains its admission owner",rejected && provider.owner() === host && provider.fixture.values().2==1)
   let next=replacement ? provider.replacement():nil
   provider.fixture.closeRelease.signal()
   check("whole stop completes only after captured native drain",stopped.wait() && provider.fixture.values().2==0 && engine.torComparisonNative()==nil)
   if let next {
    check("old whole-stop callback preserves replacement engine",provider.engine() === next && !provider.fixture.values().0.contains("provider-stopped"))
   }else{
    check("whole stop releases owner only after native cleanup",provider.owner()==nil && provider.engine()==nil && provider.fixture.values().0.last=="provider-stopped")
   }
  }
  do {
   CompareBoundary.shared.reset();let provider=PacketTunnelProvider(),result=ResultBox();try provider.begin(result)
   check("failed whole-stop fixture owns proved winner",result.wait() && result.values()==[false])
   let host=provider.owner()!,engine=provider.engine()!,first=ResultBox()
   provider.fixture.lock.lock();provider.fixture.closeIndex=2;provider.fixture.failClose=true;provider.fixture.lock.unlock();provider.wholeStop(first)
   check("failed whole stop retains exact native and provider owners",first.wait() && provider.owner() === host && provider.engine() === engine && provider.fixture.values().2==1 && !provider.fixture.values().0.contains("provider-stopped"))
   provider.fixture.lock.lock();provider.fixture.failClose=false;provider.fixture.lock.unlock();let second=ResultBox();provider.wholeStop(second)
   check("whole stop retry drains only retained owner",second.wait() && provider.owner()==nil && provider.engine()==nil && provider.fixture.values().2==0)
  }
  do {
   CompareBoundary.shared.reset();let provider=PacketTunnelProvider(),result=ResultBox();try provider.begin(result)
   check("bridge lifetime fixture owns adopted winner",result.wait() && result.values()==[false])
   weak var nativeRound=CompareBoundary.shared.current()
   let host=provider.owner()!,engine=provider.engine()!,settled=ResultBox()
   CompareBoundary.shared.reset();host.cancelAndDrain(settled.finish)
   check("completed coordinator releases cross-language host cycle",settled.wait() && nativeRound==nil && engine.torComparisonNative() != nil && provider.engine() === engine)
   try engine.stopCheckedForStrategy()
  }
  for phase in ["start","proof"] {
   CompareBoundary.shared.reset();let provider=PacketTunnelProvider(),result=ResultBox(),stopped=ResultBox()
   provider.fixture.holdStart=phase=="start";provider.fixture.holdProof=phase=="proof";provider.fixture.holdClose=true
   try provider.begin(result)
   let entered=phase=="start" ? provider.fixture.startEntered:provider.fixture.proofEntered
   let released=phase=="start" ? provider.fixture.startRelease:provider.fixture.proofRelease
   check("whole stop fixture holds unfinished "+phase,entered.wait(timeout:.now()+3) == .success)
   let owner=provider.owner()!;provider.wholeStop(stopped)
   check("whole stop retains pending "+phase+" owner",provider.owner() === owner && provider.startupDraining() && stopped.values().isEmpty)
   released.signal()
   check("whole stop joins native close after "+phase,provider.fixture.closeEntered.wait(timeout:.now()+3) == .success)
   var rejected=false;do{try provider.begin(ResultBox())}catch{rejected=true}
   check("whole stop keeps admission while "+phase+" drain is pending",rejected && provider.owner() === owner && provider.startupDraining() && stopped.values().isEmpty)
   provider.fixture.closeRelease.signal()
   check("cancelled "+phase+" start completes once",result.wait() && result.values()==[true])
   check("whole stop during "+phase+" performs native final cleanup",stopped.wait() && stopped.values()==[false] && !provider.startupDraining() && provider.owner()==nil && provider.engine()==nil && provider.fixture.values().2==0 && provider.fixture.values().0.filter{$0=="provider-stopped"}.count==1)
   CompareBoundary.shared.reset();let retry=ResultBox();try provider.begin(retry)
   check("fully joined "+phase+" stop permits fresh connection",retry.wait() && retry.values()==[false] && provider.fixture.values().2==1)
   let done=ResultBox();provider.wholeStop(done);check("retried "+phase+" connection stops cleanly",done.wait() && !provider.startupDraining() && provider.fixture.values().2==0)
  }
  print("Apple shipping Tor Compare host/provider: PASS (\(checks) ownership and callback checks; native/OS boundaries doubled)")
 }
}
'''


def member(source, signature):
    start = source.index(signature)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        if source[end] == '{': depth += 1
        if source[end] == '}': depth -= 1
        end += 1
    return source[start:end]


def main():
    swift = shutil.which('swiftc')
    if not swift: raise RuntimeError('swiftc required')
    source = (TUN / 'PacketTunnelProvider.swift').read_text()
    host_source = (TUN / 'RouterVPNTorCompare.swift').read_text()
    def provider_body(text):
        return '\n'.join(member(text, signature) for signature in (
            '    private struct ExternalLibboxInputs {', '    private func currentTorComparison(',
            '    private func torComparisonAvailable(', '    private func beginTorComparison(',
            '    override func stopTunnel(', '    private func finishOwnedStop(', '    private func finishNativeStop(', '    func isStrategySettings(',
            '    func nativeLibboxSettingsInvalidated('))
    with tempfile.TemporaryDirectory(prefix='ios-tor-compare-') as temporary:
        work = Path(temporary)
        lib = work / 'Libbox.swift'; lib.write_text(LIBBOX)
        suffix = '.dylib' if platform.system() == 'Darwin' else '.so'
        subprocess.run([swift,'-swift-version','6','-emit-module','-emit-library','-module-name','Libbox',str(lib),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(work/('libLibbox'+suffix))],check=True,timeout=90)
        args=[swift,'-swift-version','6','-parse-as-library','-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        if platform.system() != 'Darwin':
            crypto=work/'CryptoKit.swift'; crypto.write_text(CRYPTO.LINUX_CRYPTO)
            subprocess.run([swift,'-swift-version','6','-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-lcrypto','-o',str(work/'libCryptoKit.so')],cwd=work,check=True,timeout=90)
            args += ['-lCryptoKit']
        test=work/'Tests.swift'; test.write_text(BOUNDARIES.replace(' // SHIPPING_PROVIDER',provider_body(source))+TESTS)
        host=work/'RouterVPNTorCompare.swift'; host.write_text(host_source)
        command=args+[str(APP/'IOSMultihopExecution.swift'),str(TUN/'RouterVPNSettingsQueue.swift'),str(host),str(test),'-o',str(work/'tests')]
        subprocess.run(command,check=True,timeout=90)
        subprocess.run([str(work/'tests')],check=True,timeout=45)
        mutations = (
            ('adopted-cancel', 'host', '            guard !adopted else { condition.unlock(); return }',
             '            // Broken: cancel the adopted owner', 'late round and candidate cleanup cannot stop adopted VPN'),
            ('adopted-close', 'host', '            if adopted || closed { condition.unlock(); return }',
             '            if closed { condition.unlock(); return }', 'late round and candidate cleanup cannot stop adopted VPN'),
            ('physical-generation', 'provider', '        return matches && guardState != nil && currentPathProofGuard() === guardState',
             '        return matches && guardState != nil', 'live owner check independently rejects changed path'),
            ('native-engine-owner', 'provider', '                return self.torCompareOwner === owner && !self.torCompareDraining && self.libboxEngine === engine',
             '                return self.torCompareOwner === owner && !self.torCompareDraining', 'changed owner cannot transfer the final native trial engine'),
            ('exact-average', 'host', '              abs(score.doubleValue - (last.doubleValue / 2 + external.doubleValue / 2)) <= 0.000001 else',
             '              true else', 'invalid native result is rejected wrong-score'),
            ('same-random-endpoint', 'host', '              self.target.isEmpty || self.target == target else',
             '              true else', 'invalid native result is rejected changed-target'),
            ('valid-lowest-winner', 'host', '        guard let winnerScore, winnerScore <= lowestScore + 0.000001 else { throw Self.issue() }',
             '        _ = winnerScore; _ = lowestScore', 'invalid native result is rejected ineligible-winner'),
            ('native-settings-generation', 'host', '        guard let engine = try? makeEngine(UUID().uuidString) else',
             '        guard let engine = try? makeEngine(epoch) else', 'sequential engines keep one physical path and distinct settings owners'),
            ('completed-round-retention', 'host', '            transferred = true; round = nil; result = verified; stage = "selected"; execution = choice',
             '            transferred = true; result = verified; stage = "selected"; execution = choice', 'completed coordinator releases cross-language host cycle'),
            ('whole-stop-retention', 'provider', '                // Keep/Close transfers measurement ownership only.',
             '                self.torCompareOwnerLock.lock(); self.torCompareOwner = nil; self.torCompareOwnerLock.unlock()\n                // Keep/Close transfers measurement ownership only.',
             'activation retry drains its exact new owner'),
            ('unfinished-whole-stop-owner', 'provider', '                    let canRelease = matches && owner.isDrained && !self.torCompareDraining',
             '                    let canRelease = matches && owner.isDrained',
             'whole stop during start performs native final cleanup'),
            ('joined-activation-admission', 'host', '                lock.lock(); drained = true; candidate = nil; lock.unlock()',
             '                // Broken: retain admission after acknowledged activation-failure teardown',
             'joined activation failure releases comparison admission'),
        )
        for label, target, before, after, expected in mutations:
            original = host_source if target == 'host' else source
            if original.count(before) != 1:
                raise AssertionError('Missing unique mutation boundary: ' + label)
            changed = original.replace(before, after, 1)
            host.write_text(changed if target == 'host' else host_source)
            test.write_text(BOUNDARIES.replace(' // SHIPPING_PROVIDER', provider_body(changed if target == 'provider' else source)) + TESTS)
            subprocess.run(command, check=True, timeout=90)
            result = subprocess.run([str(work/'tests')], capture_output=True, text=True, timeout=45)
            if result.returncode == 0 or 'FAIL: ' + expected not in result.stdout + result.stderr:
                output = result.stdout + result.stderr
                witness = '\n'.join(line for line in output.splitlines() if 'FAIL:' in line)
                raise AssertionError(label + ': regression was not rejected at its ownership assertion: ' + (witness or output[-2000:]))
            print('Shipping Apple Tor Compare negative control rejected: ' + label, flush=True)


if __name__ == '__main__': main()
