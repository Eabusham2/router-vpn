#!/usr/bin/env python3
"""Execute Apple candidate capture, owned temporary routing, socket drain and receipts.

Shipping Swift is compiled with only the OS network/PacketTunnel/storage
boundaries doubled. This is not a claim of physical-device routed traffic.
"""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
import signal
import struct
import sys
import shutil
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('speed_path_fixture', ROOT / 'deploy/test_ios_speed_lab_external_paths.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)


# Keep the original session leader alive until the parent has signalled its
# complete compiler group. A finished swiftc driver may leave only a zombie;
# Darwin refuses killpg on that group with EPERM, which is not absence proof.
COMPILER_OWNER = r"""
import os, signal, struct, subprocess, sys
channel = int(sys.argv[1])
try:
    result = subprocess.run(sys.argv[2:], close_fds=True).returncode
except BaseException:
    result = 125
os.write(channel, struct.pack("!i", result))
os.close(channel)
while True:
    signal.pause()
"""


class OwnedCandidateCompiler:
    """One original live session leader and its private compiler exit receipt."""

    def __init__(self, deadline):
        self.deadline = deadline
        self.lock = threading.Lock()
        self.process = None
        self.signalled = None
        self.cancelled = False
        self.wake = threading.Event()

    def terminate_original_group(self, process):
        # No poll, PID lookup, or reap precedes this signal. The retained live
        # supervisor pins its creation-time session until this acknowledged kill.
        if self.process is process and process.returncode is None and self.signalled is not process:
            os.killpg(process.pid, signal.SIGKILL)
            self.signalled = process

    def run(self, command, *, check, timeout):
        assert check
        reader, writer = os.pipe()
        process = None
        try:
            os.set_blocking(reader, False)
            with self.lock:
                if self.cancelled:
                    raise RuntimeError('Candidate compilation was cancelled')
                if self.deadline <= time.monotonic():
                    raise subprocess.TimeoutExpired(command, timeout)
                if os.name != 'posix':
                    raise RuntimeError('Candidate compiler requires original POSIX session ownership')
                if self.process is not None:
                    raise RuntimeError('Candidate compiler already owns an unjoined child')
                process = subprocess.Popen([sys.executable, '-c', COMPILER_OWNER, str(writer), *command],
                                           start_new_session=True, pass_fds=(writer,))
                self.process, self.signalled = process, None
            os.close(writer)
            writer = None
            deadline = min(self.deadline, time.monotonic() + timeout)
            receipt = b''
            while True:
                if self.cancelled:
                    raise subprocess.CalledProcessError(-signal.SIGKILL, command)
                try:
                    block = os.read(reader, 5 - len(receipt))
                except BlockingIOError:
                    block = None
                if block == b'':
                    if len(receipt) != 4:
                        raise RuntimeError('Original compiler owner omitted its exact exit receipt')
                    result, = struct.unpack('!i', receipt)
                    if not -127 <= result <= 255:
                        raise RuntimeError('Original compiler owner returned an invalid exit status')
                    break
                if block:
                    receipt += block
                    if len(receipt) > 4:
                        raise RuntimeError('Original compiler owner exceeded its exit receipt')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                self.wake.wait(min(.01, remaining))
        finally:
            if writer is not None:
                os.close(writer)
            os.close(reader)
            if process is not None:
                with self.lock:
                    self.terminate_original_group(process)
                    process.wait()
                    if self.process is process:
                        self.process = None
        if result:
            raise subprocess.CalledProcessError(result, command)

    def cancel(self):
        with self.lock:
            self.cancelled = True
            if self.process is not None:
                self.terminate_original_group(self.process)
            self.wake.set()

NETWORK = r'''
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
public struct IPv4Address: Sendable {
 public let rawValue:Data
 public init?(_ text:String){var address=in_addr();guard inet_pton(AF_INET,text,&address)==1 else{return nil};rawValue=withUnsafeBytes(of:&address){Data($0)}}
 public var debugDescription:String{rawValue.map{String($0)}.joined(separator:".")}
}
public struct IPv6Address: Sendable {
 public let rawValue:Data
 private let text:String
 public init?(_ text:String){var address=in6_addr();guard inet_pton(AF_INET6,text,&address)==1 else{return nil};rawValue=withUnsafeBytes(of:&address){Data($0)};self.text=text.lowercased()}
 public var debugDescription:String{text}
}
public enum NWEndpoint {
 public struct Host:Sendable{let value:String;public init(_ value:String){self.value=value}}
 public struct Port:Sendable{let value:UInt16;public init?(rawValue:UInt16){guard rawValue>0 else{return nil};value=rawValue}}
}
public final class NWParameters:@unchecked Sendable{public static var tcp:NWParameters{NWParameters()};public var requiredInterface:NWInterface?}
public struct NWInterface:Sendable { public enum InterfaceType:Sendable {case other,loopback,wifi,cellular,wiredEthernet};public let type:InterfaceType;public let name:String }
public struct NWPath:Sendable{public enum Status:Sendable{case satisfied,unsatisfied};public let status:Status
 public var availableInterfaces:[NWInterface]{[NWInterface(type:.wifi,name:"physical-wifi")]}
 public func usesInterfaceType(_ type:NWInterface.InterfaceType)->Bool{type == .wifi}
}
public final class NWTest:@unchecked Sendable {
 public static let shared=NWTest()
 private let lock=NSLock()
 private var listeners:[@Sendable(NWPath)->Void]=[]
 private var retained:[@Sendable()->Void]=[]
 private var traces:[String]=[]
 private var hold=false
 private var connectCounts:[String:Int]=[:]
 private var inverted=false,partial=false,changeDuring=false
 private var measuredClock:UInt64=1,measuredReads=0
 private var delayedInitialPath=false
 public private(set) var excludesVirtual=false
 public func prohibit(_ types:[NWInterface.InterfaceType]){excludesVirtual=types.contains(.other) && types.contains(.loopback)}
 public var events:[String]{lock.lock();defer{lock.unlock()};return traces}
 public func record(_ event:String){lock.lock();traces.append(event);lock.unlock()}
 public func reset(){lock.lock();traces=[];hold=false;connectCounts=[:];inverted=false;partial=false;changeDuring=false;measuredClock=1;measuredReads=0;lock.unlock()}
 public func configure(inverted:Bool=false,partial:Bool=false,changeDuring:Bool=false){lock.lock();self.inverted=inverted;self.partial=partial;self.changeDuring=changeDuring;lock.unlock()}
 // Only the synthetic inversion uses this clock. Queue delivery, cancellation,
 // timeout tasks and the production network/deadline checks remain real.
 public var measurementReads:Int{lock.lock();defer{lock.unlock()};return measuredReads}
 public func measurementNow()->UInt64{lock.lock();defer{lock.unlock()};if inverted{measuredReads+=1;return measuredClock};return DispatchTime.now().uptimeNanoseconds}
 public func measurementDelivered(_ delay:Double){lock.lock();if inverted{measuredClock+=UInt64((delay*1_000_000_000).rounded())};lock.unlock()}
 public func connect(_ host:String)->(Double,Bool){lock.lock();let count=(connectCounts[host] ?? 0)+1;connectCounts[host]=count;let invert=inverted,fail=partial && count==11,change=changeDuring && count==11;lock.unlock();if change{changed()};return (invert ? (host.hasSuffix(".20") ? (count<=27 ? 0.001 : 0.035) : 0.010) : 0.003,fail)}
 public func holdCancellation(_ value:Bool){lock.lock();hold=value;lock.unlock()}
 public func cancelled(_ deliver:@escaping @Sendable()->Void){lock.lock();if hold{retained.append(deliver);lock.unlock()}else{lock.unlock();deliver()}}
 public func drain(){lock.lock();hold=false;let work=retained;retained=[];lock.unlock();for f in work{f()}}
 public func delayInitialPath(_ value:Bool){lock.lock();delayedInitialPath=value;lock.unlock()}
 public func register(_ callback:@escaping @Sendable(NWPath)->Void){lock.lock();listeners.append(callback);let deliver = !delayedInitialPath;lock.unlock();if deliver{callback(NWPath(status:.satisfied))}}
 public func changed(){lock.lock();let callbacks=listeners;lock.unlock();for f in callbacks{f(NWPath(status:.satisfied))}}
}
public final class NWPathMonitor:@unchecked Sendable {
 public var pathUpdateHandler:(@Sendable(NWPath)->Void)?
 public init(prohibitedInterfaceTypes:[NWInterface.InterfaceType]){NWTest.shared.prohibit(prohibitedInterfaceTypes)}
 public func start(queue:DispatchQueue){if let f=pathUpdateHandler{NWTest.shared.register(f)}}
}
public final class NWConnection:@unchecked Sendable {
 public enum State:Sendable{case ready,failed(URLError),cancelled,setup}
 public var stateUpdateHandler:(@Sendable(State)->Void)?
 private let host:String,port:UInt16
 private let requiredInterface:String?
 private var queue:DispatchQueue?
 public init(host:NWEndpoint.Host,port:NWEndpoint.Port,using:NWParameters){self.host=host.value;self.port=port.value;self.requiredInterface=using.requiredInterface?.name}
 public func start(queue:DispatchQueue){self.queue=queue;if let requiredInterface{NWTest.shared.record("bound:"+requiredInterface)};NWTest.shared.record("start:"+host+":"+String(port));let (delay,fail)=NWTest.shared.connect(host);queue.asyncAfter(deadline:.now()+delay){
   NWTest.shared.measurementDelivered(delay)
   if self.host.hasSuffix(".99") || fail{self.stateUpdateHandler?(.failed(URLError(.cannotConnectToHost)))}else{self.stateUpdateHandler?(.ready)}
 }}
 public func cancel(){NWTest.shared.record("cancel:"+host);NWTest.shared.cancelled{[self] in queue?.async{NWTest.shared.record("drained:"+self.host);self.stateUpdateHandler?(.cancelled)}}}
}
'''

FIXTURE = r'''
import Network
@MainActor enum IOSRuntimeSelector {
 static let multihopModeIDs:Set<String>=["wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","ss-v2ray","split","max","naive-h2","naive-h3"]
 static func selectRaw(bundle:ClientBundle,rawProfileID:String)throws->Int{guard multihopModeIDs.contains(rawProfileID),bundle.profiles[rawProfileID] != nil else{throw Failure.error};return 1}
}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore()
 var records:[String:Data]=[:]
 func bundleData(containing id:String,current:ClientBundle?)->Data?{records[id]}
}
@MainActor extension RouterVPNModel {
 var profileMutationBlocked:Bool{connected || tunnelTransitioning || iosUserDisconnectInProgress}
 var persistedNodeBundle:ClientBundle?{nil}
 func connect(rawProfileID:String?)async{selectedMode=rawProfileID ?? selectedMode;await connect();if CandidateFault.wrongRaw{activeRawProfile="substituted-mode"}}
}
@MainActor enum CandidateFault {static var wrongRaw=false;static var refreshHook:((RouterVPNModel)->Void)?}
@MainActor final class CandidatePicker {
 let model:RouterVPNModel,viaEntry:IOSViaEntryLatency
 var entryID="entry",entryMode="wg",exitID="original-exit",detail=""
 init(_ model:RouterVPNModel,_ runner:IOSViaEntryLatency){self.model=model;viaEntry=runner}
 // SHIPPING_MANUAL_EXIT_CHOICE
}
@MainActor @main struct CandidateTests {
 static var checks=0
 static func fail(_ name:String)->Never{FileHandle.standardError.write(Data(("FAIL: "+name+"\n").utf8));exit(1)}
 static func check(_ name:String,_ condition:@autoclosure()->Bool){guard condition()else{fail(name)};checks+=1}
 static func reject(_ name:String,_ block:()throws->Void){do{try block()}catch{checks+=1;return};fail("ACCEPTED: "+name)}
 static func bundle(_ id:String,_ endpoint:String)throws->ClientBundle {
  let object:[String:Any]=["id":id,"name":id,"node_kind":"router-vpn","node_proof_id":String(repeating:id=="entry" ? "a":"b",count:64),
   "endpoint":endpoint,"router_api":"http://10.77.0.1:8787","api_token":"private-"+id,"adguard_ipv4":"10.77.0.1","adguard_ipv6":"fd77:77::1", "socks_host":"10.77.0.1","socks_port":1080,"socks_username":"","socks_password":"",
   "dns_mode":"home","home_lan_access":false,"ipv6_mode":"on","multihop_enabled":id=="entry"]
  var b=ClientBundle.empty;b.selectedRouterID=id;b.routerProfiles=[try JSONDecoder().decode(RouterProfile.self,from:JSONSerialization.data(withJSONObject:object))]
  for mode in IOSRuntimeSelector.multihopModeIDs {b.profiles[mode]=["sing-box.json":Data("{\"outbounds\":[{\"server\":\"203.0.113.10\"}]}".utf8).base64EncodedString()]}
  return b
 }
 static func fresh()throws->RouterVPNModel {
  Trace.reset();IOSSpeedLabPersistenceJournal.active=false;NWTest.shared.reset();CandidateFault.wrongRaw=false;CandidateFault.refreshHook=nil
  let model=RouterVPNModel();model.bundle=try bundle("original","203.0.113.4")
  let entry=try bundle("entry","203.0.113.10"),one=try bundle("one","203.0.113.1"),two=try bundle("two","203.0.113.2"),failed=try bundle("failed","203.0.113.99")
  model.nodes=["entry":entry,"one":one,"two":two,"failed":failed]
  IOSNodeBundleStore.shared.records=try model.nodes.mapValues{try JSONEncoder().encode($0)}
  return model
 }
 static func candidates(_ model:RouterVPNModel)->[RouterProfile]{["one","two","failed"].map{model.nodes[$0]!.routerProfiles[0]}}
 static func wait(_ predicate:@escaping()->Bool)async {
  for _ in 0..<2000{if predicate(){return};try? await Task.sleep(for:.milliseconds(1))}
  fail("boundary was not reached")
 }
 static func retirementNetwork() async throws {
   let model=try fresh(),runner=IOSViaEntryLatency();Trace.restoreHook={NWTest.shared.changed()}
   await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))
   check("a network change during teardown cannot adopt old results onto the new path",runner.receipt==nil && !runner.error.isEmpty && !model.connected && !IOSMTUMeasurementGate.held)
 }
 static func socketDrain() async throws {
  for fault in ["cancel","disconnect","new-profile","network","source","session"] {
   let model=try fresh(),runner=IOSViaEntryLatency();NWTest.shared.holdCancellation(true)
   let worker=Task{await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))}
   await wait{NWTest.shared.events.contains(where:{$0.hasPrefix("cancel:")})}
   check("socket completion retains owned temporary runtime "+fault,runner.running && model.connected && IOSMTUMeasurementGate.held && !Trace.values.contains("journal-finish"))
   if fault=="cancel"{runner.cancel()}
   else if fault=="network"{NWTest.shared.changed()}
   else if fault=="source"{IOSNodeBundleStore.shared.records["one"]=Data("changed-source".utf8)}
   else if fault=="session"{model.activeSessionIdentity=nil}
   else{IOSSpeedLabContext.$owner.withValue(nil){model.disconnect();if fault=="new-profile"{model.nodes["replacement"]=try! bundle("replacement","203.0.113.3");model.selectNode("replacement")}}}
   try? await Task.sleep(for:.milliseconds(5))
   check("Cancel is not fabricated socket drain: "+fault,runner.running && IOSMTUMeasurementGate.held && !NWTest.shared.events.contains(where:{$0.hasPrefix("drained:")}))
   NWTest.shared.drain();await worker.value
   check("invalidated response never publishes a result: "+fault,runner.receipt==nil && !runner.error.isEmpty && !runner.running && !IOSMTUMeasurementGate.held)
   check("newer intent respected: "+fault,model.bundle?.selectedRouterID==(fault=="new-profile" ? "replacement":"original") && !model.connected)
  }
 }
 static func robustSamples() async throws {
   NWTest.shared.reset();NWTest.shared.configure(inverted:true)
   let first=try await IOSViaEntryTCP.measure(IOSViaEntryTCPTarget(id:"one",name:"A",endpoint:"203.0.113.20"),excluding:[])
   let second=try await IOSViaEntryTCP.measure(IOSViaEntryTCPTarget(id:"two",name:"B",endpoint:"203.0.113.21"),excluding:[])
   check("actual routed comparison has fifty samples",first.samples==50 && second.samples==50 && first.failed==0 && second.failed==0 && NWTest.shared.events.filter{$0.hasPrefix("start:")}.count==102)
   check("synthetic clock observes both edges of all discovery and fifty-response probes",NWTest.shared.measurementReads==204)
   check("actual routed trimmed mean differs from favorable median",first.medianMS!<second.medianMS! && first.trimmedMeanMS!>second.trimmedMeanMS!)
   let model=try fresh(),capture=try IOSViaEntryCapture(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))
   let network=try await IOSViaEntryNetwork.shared.snapshot()
   let ranked=try IOSViaEntryReceipt(capture:capture,values:[first,second],model:model,network:network)
   check("receipt selects robust fifty-sample winner",ranked.fastest?.id=="two")
   let summary=IOSViaEntryTCP.summarize(IOSViaEntryTCPTarget(id:"summary",name:"Summary",endpoint:"203.0.113.20"),values:Array(repeating:1.0,count:26)+Array(repeating:100.0,count:24),failed:0)
   check("actual summary removes five samples at each end",summary.medianMS==1 && abs(summary.trimmedMeanMS!-48.025)<0.000001 && summary.samples==50)
   let a=IOSViaEntryValue(id:"one",name:"A",medianMS:1,trimmedMeanMS:20,samples:50,failed:0,reason:"fixture")
   let b=IOSViaEntryValue(id:"two",name:"B",medianMS:2,trimmedMeanMS:20,samples:50,failed:0,reason:"fixture")
   let tied=try IOSViaEntryReceipt(capture:capture,values:[b,a],model:model,network:network)
   check("receipt trimmed ties use stable ID",tied.fastest?.id=="one")
   for value in [IOSViaEntryValue(id:"short",name:"short",medianMS:1,trimmedMeanMS:1,samples:49,failed:0,reason:"fixture"),IOSViaEntryValue(id:"failed",name:"failed",medianMS:1,trimmedMeanMS:1,samples:50,failed:1,reason:"fixture"),IOSViaEntryValue(id:"invalid",name:"invalid",medianMS:1,trimmedMeanMS:.nan,samples:50,failed:0,reason:"fixture")] {check("incomplete/invalid result has no automatic score",!value.eligible)}
 }
 static func physicalBinding() async throws {
   NWTest.shared.reset();let captured=try await IOSViaEntryNetwork.shared.snapshot()
   _ = try await IOSViaEntryTCP.probeDirect(host:"203.0.113.22",port:443,timeoutMS:100,network:captured)
   check("direct measurements require captured physical interface",NWTest.shared.events.contains("bound:physical-wifi"))
   NWTest.shared.reset();_ = try await IOSViaEntryTCP.probe(host:"203.0.113.22",port:443,timeoutMS:100)
   check("routed candidate probe never bypasses tunnel with physical binding",!NWTest.shared.events.contains(where:{$0.hasPrefix("bound:")}))
   NWTest.shared.changed();NWTest.shared.reset()
   do{_ = try await IOSViaEntryTCP.probeDirect(host:"203.0.113.22",port:443,timeoutMS:100,network:captured);check("stale physical interface must reject",false)}catch{}
   check("stale physical interface cannot fall back to unbound socket",NWTest.shared.events.isEmpty)
 }
 static func main()async throws {
  // Baseline runs every case below. Each mutant executes its original owning
  // witness directly, without replaying unrelated fifty-sample mode coverage.
  if CommandLine.arguments.count > 1 {
   guard CommandLine.arguments.count == 2 else{fail("invalid focused witness arguments")}
   switch CommandLine.arguments[1] {
   case "statistics":try await robustSamples()
   case "retirement-network":try await retirementNetwork()
   case "socket-drain":try await socketDrain()
   case "physical-binding":try await physicalBinding()
   default:fail("unknown focused witness")
   }
   print("Apple candidate focused witness: PASS (\(checks) checks)")
   return
  }
  do {
   let model=try fresh(),runner=IOSViaEntryLatency()
   let queued=runner.start(model:model,entryID:"entry",mode:"wg",candidates:candidates(model));runner.cancel();await queued.value
   check("sheet dismissal revokes a queued UI start before it runs",!runner.running && runner.receipt==nil && !Trace.values.contains("native-proof"))
  }
  do {
   let model=try fresh(),runner=IOSViaEntryLatency();NWTest.shared.delayInitialPath(true)
   let worker=Task{await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))}
   await wait{runner.running};runner.cancel();NWTest.shared.delayInitialPath(false);NWTest.shared.changed();await worker.value
   check("Cancel during initial network snapshot prevents native start and result",!runner.running && runner.receipt==nil && !runner.error.isEmpty && !Trace.values.contains("mtu-hold") && NWTest.shared.events.isEmpty)
  }
  for mode in IOSRuntimeSelector.multihopModeIDs.sorted() {
   let model=try fresh(),runner=IOSViaEntryLatency()
   let before=try JSONEncoder().encode(model.bundle!),saved=IOSNodeBundleStore.shared.records
   await runner.measure(model:model,entryID:"entry",mode:mode,candidates:candidates(model))
   check("all entry modes produce routed results: "+mode+" "+runner.error,runner.receipt != nil && runner.error.isEmpty && !runner.running)
   let receipt=runner.receipt!
   try receipt.requireCurrent(model:model,entryID:"entry",entryMode:mode)
   check("only valid responses can win",receipt.values.count==3 && receipt.values.filter(\.eligible).count==2 && receipt.fastest != nil && receipt.fastest!.id != "failed")
   check("temporary tunnel stopped before results",!model.connected && Trace.values.contains("native-proof") && Trace.values.contains("disconnect") && Trace.values.contains("journal-finish") && !IOSMTUMeasurementGate.held)
   let original=try JSONDecoder().decode(ClientBundle.self,from:before)
   check("source catalog and saved policies unchanged",IOSNodeBundleStore.shared.records==saved && model.bundle!.routerProfiles==original.routerProfiles)
   check("exact display selection restored",model.selectedLogicalMode=="original-mode" && model.selectedMode=="original-raw" && model.auto)
   check("every started response socket drains",NWTest.shared.events.filter{$0.hasPrefix("start:")}.count==NWTest.shared.events.filter{$0.hasPrefix("drained:")}.count)
   reject("receipt entry mode substitution"){try receipt.requireCurrent(model:model,entryID:"entry",entryMode:"wrong")}
   let originalID=model.bundle!.selectedRouterID
   model.bundle!.selectedRouterID="new-user-selection";reject("newer idle node selection revokes receipt"){try receipt.requireCurrent(model:model,entryID:"entry",entryMode:mode)}
   model.bundle!.selectedRouterID=originalID
   model.auto=false;reject("newer idle mode choice revokes receipt"){try receipt.requireCurrent(model:model,entryID:"entry",entryMode:mode)};model.auto=true
   model.iosConnectGeneration=UUID();reject("newer decision revokes receipt"){try receipt.requireCurrent(model:model,entryID:"entry",entryMode:mode)}
  }
  check("physical path excludes the owned temporary virtual interface",NWTest.shared.excludesVirtual)
  do {
   let model=try fresh(),runner=IOSViaEntryLatency();var entry=model.nodes["entry"]!
   entry.routerProfiles[0].startLayer="aes-256-gcm"
   entry.profiles["shadowsocks"]=["sing-box.json":Data("{\"outbounds\":[{\"server\":\"203.0.113.1\"}]}".utf8).base64EncodedString()]
   IOSNodeBundleStore.shared.records["entry"]=try JSONEncoder().encode(entry)
   await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))
   check("Start Layer physical endpoint cannot be mislabeled as routed candidate response",runner.receipt?.values.first(where:{$0.id=="one"})?.medianMS==nil && !NWTest.shared.events.contains(where:{$0.hasPrefix("start:203.0.113.1:")}))
  }
  do {
   let model=try fresh(),runner=IOSViaEntryLatency()
   CandidateFault.refreshHook={value in CandidateFault.refreshHook=nil;value.bundle!.selectedRouterID="new-user-choice"}
   await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))
   check("newer choice before native ownership prevents any temporary start",runner.receipt==nil && !runner.error.isEmpty && model.bundle?.selectedRouterID=="new-user-choice" && NWTest.shared.events.isEmpty && !Trace.values.contains("mtu-hold"))
  }
  try await retirementNetwork()
  do {
   let model=try fresh(),runner=IOSViaEntryLatency();Trace.delayedRetirement=true
   let worker=Task{await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))}
   await wait{Trace.values.contains("retirement-pending")}
   check("native teardown acknowledgement precedes result publication",runner.running && runner.receipt==nil && model.connected && IOSMTUMeasurementGate.held)
   runner.cancel();try? await Task.sleep(for:.milliseconds(5))
   check("Cancel does not fabricate native retirement",runner.running && runner.receipt==nil && IOSMTUMeasurementGate.held)
   Trace.delayedRetirement=false;await worker.value
   check("cancelled pending retirement eventually drains without a result",!runner.running && runner.receipt==nil && !model.connected && !IOSMTUMeasurementGate.held)
  }
  do {
   let model=try fresh(),runner=IOSViaEntryLatency();await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))
   let receipt=runner.receipt!,picker=CandidatePicker(model,runner)
   picker.chooseExit(id:"one");check("manual measured choice validates and selects only exit",picker.exitID=="one" && !model.connected)
   NWTest.shared.changed();reject("network change revokes receipt"){try receipt.requireCurrent(model:model,entryID:"entry",entryMode:"wg")}
   picker.chooseExit(id:"two");check("manual measured row rejects stale receipt before picker mutation",picker.exitID=="one" && !picker.detail.isEmpty && runner.receipt==nil)
   // A new valid receipt checks the periodic UI invalidator independently.
   await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model));NWTest.shared.changed()
   runner.invalidateIfStale(model:model,entryID:"entry",mode:"wg");check("stale UI receipt cleared",runner.receipt==nil && !runner.error.isEmpty)
  }
  do {
   let model=try fresh(),runner=IOSViaEntryLatency();await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))
   let receipt=runner.receipt!;IOSNodeBundleStore.shared.records["one"]=Data("changed-private-source".utf8)
   reject("changed candidate credentials revoke selection"){try receipt.requireCurrent(model:model,entryID:"entry",entryMode:"wg")}
  }
  try await socketDrain()
  for endpoint in ["203.0.113.10","127.0.0.1","10.0.0.1","169.254.1.1","100.64.0.1","fd12::1","::1","router.example","tor"] {
   var p=try bundle("blocked",endpoint).routerProfiles[0];p.endpoint=endpoint;NWTest.shared.reset()
   let result=try await IOSViaEntryTCP.measure(IOSViaEntryTCPTarget(id:p.id,name:p.name,endpoint:p.endpoint),excluding:["203.0.113.10"])
   check("LAN/bootstrap/entry bypass cannot become routed evidence: "+endpoint,result.medianMS==nil && !result.eligible && NWTest.shared.events.isEmpty)
  }
  do {
   let p=try bundle("ipv6","2001:db8::2").routerProfiles[0];NWTest.shared.reset()
   let value=try await IOSViaEntryTCP.measure(IOSViaEntryTCPTarget(id:p.id,name:p.name,endpoint:p.endpoint),excluding:[],allowIPv6:false)
   check("IPv6-Off cannot probe a candidate over an excluded physical route",value.medianMS==nil && NWTest.shared.events.isEmpty)
  }
  do {
   var p=try bundle("captured","203.0.113.21:8388").routerProfiles[0];p.name="Captured candidate"
   let target=IOSViaEntryTCPTarget(id:p.id,name:p.name,endpoint:p.endpoint)
   p.id="replacement";p.name="Replacement candidate";p.endpoint="203.0.113.22:443"
   NWTest.shared.reset();let value=try await IOSViaEntryTCP.measure(target,excluding:[])
   check("asynchronous probe retains captured scalar identity",value.id=="captured" && value.name=="Captured candidate" && value.eligible)
   check("asynchronous probe retains captured endpoint and port",NWTest.shared.events.contains("start:203.0.113.21:8388") && !NWTest.shared.events.contains(where:{$0.hasPrefix("start:203.0.113.22:")}))
   check("probe cannot mutate the replacement private profile",p.id=="replacement" && p.name=="Replacement candidate" && p.endpoint=="203.0.113.22:443")
  }
  try await robustSamples()
  do {
   NWTest.shared.reset();NWTest.shared.configure(partial:true)
   let value=try await IOSViaEntryTCP.measure(IOSViaEntryTCPTarget(id:"partial",name:"Partial",endpoint:"203.0.113.22"),excluding:[])
   check("actual partial response preserves failures without a score",value.samples==49 && value.failed==1 && !value.eligible && value.label.contains("no comparison score") && NWTest.shared.events.filter{$0.hasPrefix("start:")}.count==51)
   NWTest.shared.reset();NWTest.shared.configure(changeDuring:true)
   let network=try await IOSViaEntryNetwork.shared.snapshot()
   do{_ = try await IOSViaEntryTCP.measure(IOSViaEntryTCPTarget(id:"drift",name:"Drift",endpoint:"203.0.113.22"),excluding:[],network:network);fail("network drift inside a fifty-sample candidate returned a result")}catch{}
   check("network drift stops before another candidate probe",NWTest.shared.events.filter{$0.hasPrefix("start:")}.count==11 && NWTest.shared.events.filter{$0.hasPrefix("start:")}.count==NWTest.shared.events.filter{$0.hasPrefix("drained:")}.count)
   NWTest.shared.reset()
   do{_ = try await IOSViaEntryTCP.measure(IOSViaEntryTCPTarget(id:"expired",name:"Expired",endpoint:"203.0.113.22"),excluding:[],deadline:ProcessInfo.processInfo.systemUptime-1);fail("expired comparison started a candidate")}catch{}
   check("expired comparison has no native sockets",NWTest.shared.events.isEmpty)
   do{_ = try await IOSViaEntryTCP.measure(IOSViaEntryTCPTarget(id:"deadline",name:"Deadline",endpoint:"203.0.113.22"),excluding:[],deadline:ProcessInfo.processInfo.systemUptime+0.100);fail("comparison deadline was only checked between candidates")}catch{}
   let starts=NWTest.shared.events.filter{$0.hasPrefix("start:")}.count
   check("comparison deadline drains within one candidate",starts>0 && starts<51 && starts==NWTest.shared.events.filter{$0.hasPrefix("drained:")}.count)
  }
  try await physicalBinding()
  do {
   let model=try fresh(),runner=IOSViaEntryLatency();CandidateFault.wrongRaw=true
   await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))
   check("substituted entry transport cannot emit candidate sockets",runner.receipt==nil && NWTest.shared.events.isEmpty && model.bundle?.selectedRouterID=="original")
  }
  do {
   let model=try fresh(),runner=IOSViaEntryLatency();Trace.failProof=true
   await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))
   check("failed entry proof cannot emit candidate sockets",runner.receipt==nil && NWTest.shared.events.isEmpty && model.bundle?.selectedRouterID=="original")
  }
  print("Apple via-entry candidates: PASS (\(checks) shipping Swift capture, lifetime, socket-drain and stale-result checks; OS boundaries doubled)")
 }
}
'''


def main():
    aggregate_deadline = time.monotonic() + 150
    swift = shutil.which('swiftc')
    if not swift: raise SystemExit('swiftc is required')
    types = (APP / 'IOSSpeedLab.swift').read_text().split('// One shared HTTP policy', 1)[0].replace('import Security', '')
    boundaries = P.FIXTURE.split('@MainActor @main struct Tests', 1)[0]
    assert boundaries.count('func refreshTunnelStatus()async{}') == 1
    boundaries = boundaries.replace('func refreshTunnelStatus()async{}', 'func refreshTunnelStatus()async{CandidateFault.refreshHook?(self)}')
    source_names = ('IOSMultihopExecution.swift', 'Models.swift', 'IOSSessionIdentity.swift', 'IOSSpeedLabOwnership.swift', 'IOSMultihopStartLayer.swift',
                    'IOSSpeedLabRunner.swift', 'IOSViaEntryLatency.swift', 'IOSViaEntryTCP.swift')
    # Preserve the shipping source-file boundaries. Concatenating Models with
    # the caller masks Swift's non-Sendable cross-file actor diagnostics.
    code = {name: (APP / name).read_text().replace('import Combine\n', '') for name in source_names}
    shipping_tcp = code['IOSViaEntryTCP.swift']
    # The Network double controls callback delivery. Make its inversion values
    # deterministic without changing shipping probe queues, timers or ownership.
    # Real elapsed reads remain in use for every non-inversion fixture case.
    elapsed = 'DispatchTime.now().uptimeNanoseconds'
    assert code['IOSViaEntryTCP.swift'].count(elapsed) == 2, 'Probe elapsed clock boundary changed'
    code['IOSViaEntryTCP.swift'] = code['IOSViaEntryTCP.swift'].replace(elapsed, 'NWTest.shared.measurementNow()')
    view = (APP / 'IOSMultihopView.swift').read_text()
    manual = view.split('    private func chooseExit(id: String) {', 1)[1].rsplit('\n}', 1)[0]
    manual = '    func chooseExit(id: String) {' + manual
    assert 'selection: Binding(get: { exitID }, set: { chooseExit(id: $0) })' in view
    code['Fixture.swift'] = 'import Foundation\n' + types + '\n' + boundaries + '\n' + FIXTURE.replace('// SHIPPING_MANUAL_EXIT_CHOICE', manual)
    with tempfile.TemporaryDirectory(prefix='ios-via-entry-') as temporary:
        folder = Path(temporary); network = folder / 'Network.swift'; network.write_text(NETWORK)
        import platform
        suffix = '.dylib' if platform.system() == 'Darwin' else '.so'
        args = [swift, '-swift-version', '6', '-module-cache-path', str(folder / 'modules')]
        subprocess.run(args + ['-emit-module', '-emit-library', '-module-name', 'Network', str(network),
            '-emit-module-path', str(folder / 'Network.swiftmodule'), '-o', str(folder / ('libNetwork' + suffix))], check=True, timeout=120)
        def write_sources(contents, destination=folder):
            destination.mkdir(parents=True, exist_ok=True)
            paths = []
            for name, source in contents.items():
                path = destination / name; path.write_text(source); paths.append(str(path))
            return paths
        def compile_fixture(contents, label, destination, owned_compiler=None):
            print(f'Apple candidate stage: compile {label}', flush=True)
            paths = write_sources(contents, destination)
            binary = destination / 'tests'
            compile_run = owned_compiler.run if owned_compiler is not None else subprocess.run
            compile_run(args + ['-parse-as-library', '-I', str(folder), '-L', str(folder), '-lNetwork',
                '-Xlinker', '-rpath', '-Xlinker', str(folder)] + paths + ['-o', str(binary)], check=True, timeout=150)
            return binary
        def execute(binary, mutation=None, expected=None, witness=None):
            label = mutation or 'shipping baseline'
            print(f'Apple candidate stage: execute {label}', flush=True)
            result = subprocess.run([str(binary)] + ([witness] if witness else []), text=True, capture_output=True, timeout=120)
            if mutation:
                assert result.returncode != 0 and 'FAIL:' in result.stderr, f'Negative control escaped: {mutation}\n{result.stdout}\n{result.stderr}'
                if expected:
                    allowed = (expected,) if isinstance(expected, str) else expected
                    assert any('FAIL: '+item in result.stderr for item in allowed), f'{mutation} failed at an unrelated witness: {result.stdout}{result.stderr}'
                print(f'Apple candidate negative control rejected: {mutation}', flush=True)
            else:
                assert result.returncode == 0, result.stdout + result.stderr
                print(result.stdout.strip(), flush=True)
        mutations = {
            'fifty candidate samples': ('for _ in 0..<50 {', 'for _ in 0..<5 {'),
            'trimmed candidate statistic': ('middle.reduce(0, +) / Double(middle.count)', 'values.reduce(0, +) / Double(values.count)'),
            'receipt robust winner': ('$0.trimmedMeanMS! == $1.trimmedMeanMS! ? $0.id < $1.id : $0.trimmedMeanMS! < $1.trimmedMeanMS!', '$0.medianMS! < $1.medianMS!'),
            'network changed during native retirement': (
                'try Task.checkCancellation(); try capture.requireSources(model: model)\n            guard IOSViaEntryNetwork.shared.current == network else { throw CancellationError() }',
                'try Task.checkCancellation(); try capture.requireSources(model: model)'),
            'cancel substituted for acknowledged socket drain': (
                'if let connection { connection.cancel() } else { deliver() }',
                'if let connection { connection.cancel(); self.connection = nil; deliver() } else { deliver() }'),
            'direct probe lost its required physical interface': (
                'if let physical { parameters.requiredInterface = physical }',
                '_ = physical'),
        }
        expected_witnesses = {
            'fifty candidate samples': 'actual routed comparison has fifty samples',
            'trimmed candidate statistic': 'actual summary removes five samples at each end',
            'receipt robust winner': 'receipt selects robust fifty-sample winner',
            'network changed during native retirement': 'a network change during teardown cannot adopt old results onto the new path',
            'cancel substituted for acknowledged socket drain': (
                'socket completion retains owned temporary runtime cancel',
                'Cancel is not fabricated socket drain: cancel'),
            'direct probe lost its required physical interface': 'direct measurements require captured physical interface',
        }
        focused_witnesses = {
            'fifty candidate samples': 'statistics',
            'trimmed candidate statistic': 'statistics',
            'receipt robust winner': 'statistics',
            'network changed during native retirement': 'retirement-network',
            'cancel substituted for acknowledged socket drain': 'socket-drain',
            'direct probe lost its required physical interface': 'physical-binding',
        }
        assert set(mutations) == set(expected_witnesses) == set(focused_witnesses)
        variants = []
        for name, (before, after) in mutations.items():
            assert sum(source.count(before) for source in code.values()) == 1, f'Mutation anchor changed: {name}'
            variants.append((name, {path: source.replace(before, after) for path, source in code.items()}))
        baseline = compile_fixture(code, 'shipping baseline', folder / 'baseline')
        # The full baseline spends real time delivering every response and
        # draining every owned socket. Compile independent mutant executables
        # during that work, with at most one compiler and one running fixture.
        # Each compiler input/output directory is immutable after compilation;
        # all six native witnesses still execute serially after the baseline.
        # No shipping sample count, timer, deadline or aggregate bound changes.
        owned_compiler = OwnedCandidateCompiler(aggregate_deadline)
        with ThreadPoolExecutor(max_workers=1) as compiler:
            pending = [(name, compiler.submit(compile_fixture, contents, name, folder / ('mutation-' + str(index)), owned_compiler))
                       for index, (name, contents) in enumerate(variants)]
            try:
                execute(baseline)
                for name, compiled in pending:
                    execute(compiled.result(), name, expected_witnesses[name], focused_witnesses[name])
            finally:
                owned_compiler.cancel()
                for _, compiled in pending:
                    compiled.cancel()
        unsafe = dict(code)
        before = '_ target: IOSViaEntryTCPTarget, excluding excluded:'
        assert unsafe['IOSViaEntryTCP.swift'].count(before) == 1
        unsafe['IOSViaEntryTCP.swift'] = unsafe['IOSViaEntryTCP.swift'].replace(before, '_ target: RouterProfile, excluding excluded:')
        # Keep the unrelated scalar fixture calls well typed so the negative
        # reaches SIL actor-isolation checking at the shipping caller. This
        # overload is never executed: the unsafe composition must not compile.
        unsafe['IOSViaEntryTCP.swift'] = unsafe['IOSViaEntryTCP.swift'].replace(
            'return summarize(target, values: values, failed: failed)',
            'return summarize(IOSViaEntryTCPTarget(id: target.id, name: target.name, endpoint: target.endpoint), values: values, failed: failed)')
        unsafe['IOSViaEntryTCP.swift'] += '''
extension IOSViaEntryTCP {
    static func measure(_ target: IOSViaEntryTCPTarget, excluding excluded: Set<String>, allowIPv6: Bool = true, network: UInt64? = nil, deadline: TimeInterval = .infinity) async throws -> IOSViaEntryValue {
        throw CancellationError()
    }
}
'''
        before = 'IOSViaEntryTCP.measure(target, excluding: capture.excludedHosts'
        assert unsafe['IOSViaEntryLatency.swift'].count(before) == 1
        unsafe['IOSViaEntryLatency.swift'] = unsafe['IOSViaEntryLatency.swift'].replace(before, 'IOSViaEntryTCP.measure(candidate, excluding: capture.excludedHosts')
        unsafe['Fixture.swift'] = unsafe['Fixture.swift'].replace('IOSViaEntryTCPTarget(id:p.id,name:p.name,endpoint:p.endpoint)', 'p')
        # Region-isolation diagnostics are emitted during SIL/code generation;
        # a typecheck-only invocation can accept the historical broken call.
        print('Apple candidate stage: reject full-profile actor crossing', flush=True)
        binary = folder / 'tests'
        rejected = subprocess.run(args + ['-parse-as-library', '-I', str(folder), '-L', str(folder), '-lNetwork',
            '-Xlinker', '-rpath', '-Xlinker', str(folder)] + write_sources(unsafe) + ['-o', str(binary)],
            text=True, capture_output=True, timeout=150)
        assert rejected.returncode != 0 and "sending 'candidate' risks causing data races" in rejected.stderr and 'IOSViaEntryLatency.swift' in rejected.stderr, (
            'Historical full-profile actor crossing was not rejected at the shipping call site:\n' + rejected.stdout + rejected.stderr)
        print('Apple candidate negative control rejected: full private profile crosses MainActor')
        if platform.system() == 'Darwin':
            # The executable fixture doubles OS behavior. Independently typecheck
            # the real helper and its actor crossing against the iOS SDK, with
            # the same deployment target as the shipping application.
            actual = folder / 'ActualValue.swift'
            value = (APP / 'IOSViaEntryLatency.swift').read_text().split('@MainActor', 1)[0].replace('import Combine\n', '')
            actual.write_text(value)
            actor = folder / 'ActualActorBoundary.swift'
            capture = ('let target = IOSViaEntryTCPTarget(id: candidate.id, name: candidate.name, endpoint: candidate.endpoint)\n'
                       '                        let value = try await IOSViaEntryTCP.measure(target, excluding: capture.excludedHosts, allowIPv6: capture.allowsIPv6, network: network, deadline: deadline)')
            assert code['IOSViaEntryLatency.swift'].count(capture) == 1
            crossing = capture.replace('capture.excludedHosts', 'excludedHosts').replace('capture.allowsIPv6', 'allowsIPv6')
            actor_code = '''import Foundation
@MainActor final class ActualViaEntryActorBoundary {
    let candidates: [RouterProfile]
    let excludedHosts: Set<String>
    let allowsIPv6: Bool
    init(candidates: [RouterProfile], excludedHosts: Set<String>, allowsIPv6: Bool) {
        self.candidates = candidates; self.excludedHosts = excludedHosts; self.allowsIPv6 = allowsIPv6
    }
    func measure() async throws -> [IOSViaEntryValue] {
        let network: UInt64 = 1
        let deadline = ProcessInfo.processInfo.systemUptime + 120
        var values: [IOSViaEntryValue] = []
        for candidate in candidates {
            // SHIPPING_SCALAR_CAPTURE
            values.append(value)
        }
        return values
    }
}
'''.replace('// SHIPPING_SCALAR_CAPTURE', crossing)
            actor.write_text(actor_code)
            # The synthetic measurement clock belongs only to the executable
            # Network double. Real-SDK evidence must compile the shipping helper
            # without importing that test-only API into Apple's Network module.
            helper = folder / 'ActualTCP.swift'; helper.write_text(shipping_tcp)
            sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
            sdk_sources = [APP / 'Models.swift', actual, helper, actor]
            output_map = folder / 'sdk-output-map.json'
            output_map.write_text(json.dumps({str(path): {'object': str(folder / (path.stem + '.o'))} for path in sdk_sources}))
            sdk_args = [swift, '-swift-version', '6', '-parse-as-library', '-c', '-sdk', sdk, '-target', 'arm64-apple-ios17.0',
                        '-module-cache-path', str(folder / 'sdk-modules'), '-output-file-map', str(output_map)] + [str(path) for path in sdk_sources]
            print('Apple candidate stage: compile shipping helper against real iOS SDK', flush=True)
            subprocess.run(sdk_args, check=True, timeout=120)
            unsafe_sdk = unsafe['IOSViaEntryTCP.swift']
            assert unsafe_sdk.count('NWTest.shared.measurementNow()') == 2
            unsafe_sdk = unsafe_sdk.replace('NWTest.shared.measurementNow()', elapsed)
            helper.write_text(unsafe_sdk)
            actor.write_text(actor_code.replace('IOSViaEntryTCP.measure(target,', 'IOSViaEntryTCP.measure(candidate,'))
            print('Apple candidate stage: reject full-profile crossing against real iOS SDK', flush=True)
            rejected = subprocess.run(sdk_args, text=True, capture_output=True, timeout=120)
            assert rejected.returncode != 0 and "sending 'candidate' risks causing data races" in rejected.stderr, (
                'Real iOS SDK failed to reject the full-profile actor crossing:\n' + rejected.stdout + rejected.stderr)
            print('Apple candidate network owner: real iOS SDK actor crossing PASS; full-profile negative rejected')


if __name__ == '__main__': main()
