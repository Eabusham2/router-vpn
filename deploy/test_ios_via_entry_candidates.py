#!/usr/bin/env python3
"""Execute Apple candidate capture, owned temporary routing, socket drain and receipts.

Shipping Swift is compiled with only the OS network/PacketTunnel/storage
boundaries doubled. This is not a claim of physical-device routed traffic.
"""
from pathlib import Path
import importlib.util
import json
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('speed_path_fixture', ROOT / 'deploy/test_ios_speed_lab_external_paths.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)

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
 private var delayedInitialPath=false
 public private(set) var excludesVirtual=false
 public func prohibit(_ types:[NWInterface.InterfaceType]){excludesVirtual=types.contains(.other) && types.contains(.loopback)}
 public var events:[String]{lock.lock();defer{lock.unlock()};return traces}
 public func record(_ event:String){lock.lock();traces.append(event);lock.unlock()}
 public func reset(){lock.lock();traces=[];hold=false;lock.unlock()}
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
 public func start(queue:DispatchQueue){self.queue=queue;if let requiredInterface{NWTest.shared.record("bound:"+requiredInterface)};NWTest.shared.record("start:"+host+":"+String(port));queue.asyncAfter(deadline:.now()+0.003){
   if self.host.hasSuffix(".99"){self.stateUpdateHandler?(.failed(URLError(.cannotConnectToHost)))}else{self.stateUpdateHandler?(.ready)}
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
 static func main()async throws {
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
  do {
   let model=try fresh(),runner=IOSViaEntryLatency();Trace.restoreHook={NWTest.shared.changed()}
   await runner.measure(model:model,entryID:"entry",mode:"wg",candidates:candidates(model))
   check("a network change during teardown cannot adopt old results onto the new path",runner.receipt==nil && !runner.error.isEmpty && !model.connected && !IOSMTUMeasurementGate.held)
  }
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
  do {
   NWTest.shared.reset();let captured=try await IOSViaEntryNetwork.shared.snapshot()
   _ = try await IOSViaEntryTCP.probeDirect(host:"203.0.113.22",port:443,timeoutMS:100,network:captured)
   check("direct measurements require captured physical interface",NWTest.shared.events.contains("bound:physical-wifi"))
   NWTest.shared.reset();_ = try await IOSViaEntryTCP.probe(host:"203.0.113.22",port:443,timeoutMS:100)
   check("routed candidate probe never bypasses tunnel with physical binding",!NWTest.shared.events.contains(where:{$0.hasPrefix("bound:")}))
   NWTest.shared.changed();NWTest.shared.reset()
   do{_ = try await IOSViaEntryTCP.probeDirect(host:"203.0.113.22",port:443,timeoutMS:100,network:captured);check("stale physical interface must reject",false)}catch{}
   check("stale physical interface cannot fall back to unbound socket",NWTest.shared.events.isEmpty)
  }
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
    swift = shutil.which('swiftc')
    if not swift: raise SystemExit('swiftc is required')
    types = (APP / 'IOSSpeedLab.swift').read_text().split('// One shared HTTP policy', 1)[0].replace('import Security', '')
    boundaries = P.FIXTURE.split('@MainActor @main struct Tests', 1)[0]
    assert boundaries.count('func refreshTunnelStatus()async{}') == 1
    boundaries = boundaries.replace('func refreshTunnelStatus()async{}', 'func refreshTunnelStatus()async{CandidateFault.refreshHook?(self)}')
    source_names = ('Models.swift', 'IOSSessionIdentity.swift', 'IOSSpeedLabOwnership.swift', 'IOSMultihopStartLayer.swift',
                    'IOSSpeedLabRunner.swift', 'IOSViaEntryLatency.swift', 'IOSViaEntryTCP.swift')
    # Preserve the shipping source-file boundaries. Concatenating Models with
    # the caller masks Swift's non-Sendable cross-file actor diagnostics.
    code = {name: (APP / name).read_text().replace('import Combine\n', '') for name in source_names}
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
        binary = folder / 'tests'
        def write_sources(contents):
            paths = []
            for name, source in contents.items():
                path = folder / name; path.write_text(source); paths.append(str(path))
            return paths
        def execute(contents, mutation=None):
            paths = write_sources(contents)
            subprocess.run(args + ['-parse-as-library', '-I', str(folder), '-L', str(folder), '-lNetwork',
                '-Xlinker', '-rpath', '-Xlinker', str(folder)] + paths + ['-o', str(binary)], check=True, timeout=150)
            result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=120)
            if mutation:
                assert result.returncode != 0 and 'FAIL:' in result.stderr, f'Negative control escaped: {mutation}\n{result.stdout}\n{result.stderr}'
                print(f'Apple candidate negative control rejected: {mutation}')
            else:
                assert result.returncode == 0, result.stdout + result.stderr
                print(result.stdout.strip())
        execute(code)
        mutations = {
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
        for name, (before, after) in mutations.items():
            assert sum(source.count(before) for source in code.values()) == 1, f'Mutation anchor changed: {name}'
            execute({path: source.replace(before, after) for path, source in code.items()}, name)
        unsafe = dict(code)
        before = '_ target: IOSViaEntryTCPTarget, excluding excluded:'
        assert unsafe['IOSViaEntryTCP.swift'].count(before) == 1
        unsafe['IOSViaEntryTCP.swift'] = unsafe['IOSViaEntryTCP.swift'].replace(before, '_ target: RouterProfile, excluding excluded:')
        before = 'IOSViaEntryTCP.measure(target, excluding: capture.excludedHosts'
        assert unsafe['IOSViaEntryLatency.swift'].count(before) == 1
        unsafe['IOSViaEntryLatency.swift'] = unsafe['IOSViaEntryLatency.swift'].replace(before, 'IOSViaEntryTCP.measure(candidate, excluding: capture.excludedHosts')
        unsafe['Fixture.swift'] = unsafe['Fixture.swift'].replace('IOSViaEntryTCPTarget(id:p.id,name:p.name,endpoint:p.endpoint)', 'p')
        # Region-isolation diagnostics are emitted during SIL/code generation;
        # a typecheck-only invocation can accept the historical broken call.
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
                       '                        let value = try await IOSViaEntryTCP.measure(target, excluding: capture.excludedHosts, allowIPv6: capture.allowsIPv6)')
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
            helper = folder / 'ActualTCP.swift'; helper.write_text(code['IOSViaEntryTCP.swift'])
            sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
            sdk_sources = [APP / 'Models.swift', actual, helper, actor]
            output_map = folder / 'sdk-output-map.json'
            output_map.write_text(json.dumps({str(path): {'object': str(folder / (path.stem + '.o'))} for path in sdk_sources}))
            sdk_args = [swift, '-swift-version', '6', '-parse-as-library', '-c', '-sdk', sdk, '-target', 'arm64-apple-ios17.0',
                        '-module-cache-path', str(folder / 'sdk-modules'), '-output-file-map', str(output_map)] + [str(path) for path in sdk_sources]
            subprocess.run(sdk_args, check=True, timeout=120)
            helper.write_text(unsafe['IOSViaEntryTCP.swift'])
            actor.write_text(actor_code.replace('IOSViaEntryTCP.measure(target,', 'IOSViaEntryTCP.measure(candidate,'))
            rejected = subprocess.run(sdk_args, text=True, capture_output=True, timeout=120)
            assert rejected.returncode != 0 and "sending 'candidate' risks causing data races" in rejected.stderr, (
                'Real iOS SDK failed to reject the full-profile actor crossing:\n' + rejected.stdout + rejected.stderr)
            print('Apple candidate network owner: real iOS SDK actor crossing PASS; full-profile negative rejected')


if __name__ == '__main__': main()
