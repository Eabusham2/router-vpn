#!/usr/bin/env python3
"""Execute shipping Apple DNS capture, IPC ownership, validation and cleanup.

Native sockets and OS provider messaging are explicit boundary doubles. Shared
Go tests cover the real routed DNS workers; test_ios_dns_retirement_receipts.py
covers the real private filesystem. This fixture executes the shipping Swift
client, transaction, native-session wrapper and model capture builders.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
TUNNEL = ROOT / 'ios/RouterVPN/PacketTunnel'


def method(source, signature):
    begin = source.index(signature)
    index = source.index('{', begin) + 1
    depth = 1
    while depth:
        if source[index] == '{': depth += 1
        elif source[index] == '}': depth -= 1
        index += 1
    return source[begin:index]


# Also used by the whole-engine fixture to compile the actual generated API
# boundary without declaring native foreign references Sendable.
NATIVE = r'''
public final class LibboxRouterDNSMeasurement {
 private let lock=NSLock()
 private let node:String,session:String
 private var request="",transport="",stage="idle",failure:String?
 private var complete=false,drained=true,closed=false,invalidated=false,hold=false,rejectStart=false
 private var used:Set<String>=[],rows:[[String:Any]]=[]
 private var starts=0,cancels:[String]=[],drains:[String]=[],closes=0,workers=0
 public init(node:String="saved-exit",session:String=UUID().uuidString){self.node=node;self.session=session}
 public func configure(hold:Bool=false,rejectStart:Bool=false){lock.lock();self.hold=hold;self.rejectStart=rejectStart;lock.unlock()}
 public func counts()->(Int,Int,Int){lock.lock();defer{lock.unlock()};return(starts,workers,closes)}
 public func cancelled()->[String]{lock.lock();defer{lock.unlock()};return cancels}
 public func drainedRequests()->[String]{lock.lock();defer{lock.unlock()};return drains}
 public func start(_ request:String,transport:String)throws{
  lock.lock();defer{lock.unlock()}
  guard !closed,!invalidated,!rejectStart,!used.contains(request),drained else{throw NSError(domain:"NativeDNSStart",code:1,userInfo:[NSLocalizedDescriptionKey:"NativeDNSStart boundary failure"])}
  used.insert(request);self.request=request;self.transport=transport;starts+=1;workers=1
  complete=false;drained=false;stage="measuring";failure=nil;rows=[]
 }
 public func cancel(_ request:String){
  lock.lock();defer{lock.unlock()};used.insert(request);cancels.append(request)
  if self.request==request{complete=true;stage="cancelled";failure="Native DNS request cancelled";rows=[];if !hold{workers=0;drained=true}}
 }
 public func drain(_ request:String)throws{
  lock.lock();defer{lock.unlock()};drains.append(request)
  if self.request==request{guard !hold else{throw NSError(domain:"NativeDNSDrain",code:1,userInfo:[NSLocalizedDescriptionKey:"NativeDNSDrain boundary failure"])};workers=0;drained=true;return}
  guard used.contains(request) || closed else{throw NSError(domain:"NativeDNSUnknown",code:1,userInfo:[NSLocalizedDescriptionKey:"NativeDNSUnknown boundary failure"])}
 }
 public func finish(_ rows:[[String:Any]]){
  lock.lock();defer{lock.unlock()};self.rows=rows;complete=true;stage="complete";failure=nil
  if !hold{workers=0;drained=true}
 }
 public func networkChanged(){
  lock.lock();defer{lock.unlock()};invalidated=true
  if !request.isEmpty{complete=true;stage="invalidated";failure="Native network changed";rows=[];if !hold{workers=0;drained=true}}
 }
 public func close()throws{
  networkChanged();lock.lock();defer{lock.unlock()};closes+=1
  guard !hold else{throw NSError(domain:"NativeDNSClose",code:1,userInfo:[NSLocalizedDescriptionKey:"NativeDNSClose boundary failure"])}
  workers=0;drained=true;closed=true
 }
 public func statusJSON()->String{
  lock.lock();defer{lock.unlock()}
  var value:[String:Any]=["schema":1,"node_id":node,"session_id":session,"request_id":request,
   "public_transport":transport,"stage":stage,"complete":complete,"drained":drained,"results":rows]
  if let failure{value["failure"]=failure}
  return String(decoding:try! JSONSerialization.data(withJSONObject:value),as:UTF8.self)
 }
}
'''

# Actual filesystem correctness is independently executed in the companion
# fixture. This boundary makes write failures and lost-IPC recovery controllable.
STORAGE = r'''
final class IOSDNSRetirementReceipts:@unchecked Sendable {
 static let shared=IOSDNSRetirementReceipts()
 private let lock=NSLock()
 private var values:[String:Data]=[:],available=true,writable=true
 func reset(available:Bool=true,writable:Bool=true){lock.lock();values=[:];self.available=available;self.writable=writable;lock.unlock()}
 func configure(available:Bool=true,writable:Bool=true){lock.lock();self.available=available;self.writable=writable;lock.unlock()}
 func requireAvailable()throws{lock.lock();defer{lock.unlock()};if !available || !writable{throw NSError(domain:"DNSReceiptStorage",code:1,userInfo:[NSLocalizedDescriptionKey:"DNSReceiptStorage boundary failure"])}}
 func storeDrained(_ data:Data)throws{
  let v=try JSONSerialization.jsonObject(with:data) as! [String:Any]
  guard v["complete"] as? Bool==true,v["drained"] as? Bool==true,v["ack_id"] as? String==v["request_id"] as? String else{throw NSError(domain:"UndrainedReceipt",code:1,userInfo:[NSLocalizedDescriptionKey:"UndrainedReceipt boundary failure"])}
  lock.lock();defer{lock.unlock()};guard available,writable else{throw NSError(domain:"DNSReceiptWrite",code:1,userInfo:[NSLocalizedDescriptionKey:"DNSReceiptWrite boundary failure"])}
  var clean=v;clean["results"]=[];clean["failure"]="Native cleanup recovered";clean["public_transport"]="";clean["stage"]="cancelled"
  values[(v["session_id"] as! String)+":"+(v["request_id"] as! String)]=try JSONSerialization.data(withJSONObject:clean)
 }
 func drained(providerSession:String,nativeSession:String,request:String,nodeID:String)->Data?{
  lock.lock();defer{lock.unlock()}
  guard let data=values[providerSession+":"+request],let v=try? JSONSerialization.jsonObject(with:data) as? [String:Any],
   v["native_session_id"] as? String==nativeSession,v["node_id"] as? String==nodeID else{return nil};return data
 }
 func count()->Int{lock.lock();defer{lock.unlock()};return values.count}
}
'''

BOUNDARIES = r'''
@propertyWrapper struct Published<Value>{var wrappedValue:Value;init(wrappedValue:Value){self.wrappedValue=wrappedValue}}
protocol ObservableObject:AnyObject{}
enum IOSRuntimeSelectionError:Error{case unsupportedMode(String)}
enum IOSDNSRuntimePolicy{
 // SELECTED_PROFILE
 static func resolve(_ profile:RouterProfile)throws->Int{1}
}
// The companion external-DNS editor gate calls the actual Go validator. This
// fixture exercises capture and commit gating, never replaces runtime checks.
enum IOSExternalDNSPolicy{
 static let protocols:Set<String>=["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"]
 static func validate(_ profile:RouterProfile,entry:RouterProfile?)throws{}
}
func LibboxRouterValidateTorProfile(_ source:String,_ failure:inout NSError?)->Bool{true}
@MainActor final class NETunnelProviderSession {
 var handler:((Data,((Data?)->Void)?)->Void)?
 func sendProviderMessage(_ data:Data,responseHandler:((Data?)->Void)?=nil)throws{handler?(data,responseHandler)}
}
@MainActor final class IOSViaEntryNetwork {
 static let shared=IOSViaEntryNetwork()
 var current:UInt64=1,hold=false
 private var pending:CheckedContinuation<UInt64,Error>?
 func snapshot()async throws->UInt64{if !hold{return current};return try await withCheckedThrowingContinuation{pending=$0}}
 func release(){hold=false;pending?.resume(returning:current);pending=nil}
}
@MainActor final class RouterVPNModel {
 var connected=true,tunnelTransitioning=false,iosUserDisconnectInProgress=false,auto=false
 var bundle:ClientBundle?,entry:ClientBundle?,activeSessionIdentity:IOSSessionIdentity?
 var selectedMode="external-socks5",selectedLogicalMode="external",iosConnectGeneration=UUID()
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var activeEngine:String{activeSessionIdentity?.engine ?? ""}
 var refresh:(()->Void)?
 var imports=0
 var profileMutationBlocked:Bool{connected || tunnelTransitioning || iosUserDisconnectInProgress}
 func importBundle(_ data:Data)throws{bundle=try JSONDecoder().decode(ClientBundle.self,from:data);imports+=1}
 func refreshTunnelStatus()async{refresh?()}
 func iosMultihopEntryBundle(for source:ClientBundle)throws->ClientBundle{guard let entry else{throw CancellationError()};return entry}
 // EXACT_CONNECT_BUILDERS
}
@MainActor enum IOSMTUControl {
 struct Binding {let connection:NETunnelProviderSession;let identity:IOSSessionIdentity;let session:String}
 static let connection=NETunnelProviderSession()
 static let mtuSession=UUID().uuidString
 static func capture(_ model:RouterVPNModel)async throws->Binding{
  guard model.connected,let identity=model.activeSessionIdentity else{throw CancellationError()}
  return Binding(connection:connection,identity:identity,session:mtuSession)
 }
 static func current(_ b:Binding,model:RouterVPNModel)->Bool{model.connected && model.activeSessionIdentity==b.identity}
 static func withHold<T>(model:RouterVPNModel,operation:@MainActor()async throws->T)async throws->T{
  let lease=IOSMTUMeasurementGate.acquire();defer{_ = IOSMTUMeasurementGate.release(lease)}
  return try await operation()
 }
}
@MainActor final class DNSDraftEditor {
 let model:RouterVPNModel,nativeMeasurement:IOSDNSMeasurementClient
 var mode="home",protocolName="udp",host="",port="53",serverName="",path="/dns-query",status=""
 var useHostnameBootstrap=true,measuredDraft=false
 var measuredSource:IOSDNSMeasurementCapture?,loadedExternalDNS:[String]?,loadedExternalProfile:RouterProfile?
 var bootstrap=ExternalDNSBootstrap(server:.init(type:"tcp",server:"",serverPort:53))
 init(_ model:RouterVPNModel,_ client:IOSDNSMeasurementClient){self.model=model;nativeMeasurement=client;load()}
 func choose(_ value:IOSDNSMeasurementResult){useMeasured(value)}
 func save(){savePolicy()}
 // SHIPPING_DNS_EDITOR
}
'''

TESTS = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func fail(_ label:String)->Never{FileHandle.standardError.write(Data(("FAIL: "+label+"\n").utf8));exit(1)}
 static func check(_ label:String,_ value:@autoclosure()throws->Bool)throws{guard try value()else{fail(label)};checks+=1}
 static func rejects(_ label:String,_ work:()throws->Void)throws{do{try work()}catch{checks+=1;return};fail("accepted "+label)}
 static func json(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
 static func obj(_ data:Data)throws->[String:Any]{try JSONSerialization.jsonObject(with:data) as! [String:Any]}
 static func wait(_ label:String,_ predicate:@escaping()->Bool)async{
  for _ in 0..<3000{if predicate(){return};try? await Task.sleep(for:.milliseconds(1))};fail("timeout "+label)
 }
 static func rows(_ transport:String="tls",tor:Bool=false,selected:String="udp") -> [[String:Any]] {
  var all:[[String:Any]]=[["id":"selected","kind":"selected","name":"Selected DNS","address":"10.77.0.1","port":53,
   "transport":selected,"route":"captured-private-entry","route_label":"Selected DNS via captured-private-entry","samples":3,"failed":0,"ready":true,"median_ms":2.5]]
  for (id,catalog) in IOSDNSMeasurementResult.catalog.sorted(by:{$0.key<$1.key}) {
   var value:[String:Any]=["id":id,"kind":"public","name":id,"address":catalog.0,
    "port":transport=="tcp" ? 53:transport=="tls" ? 853:443,"transport":transport,
    "route":"exit","route_label":tor ? "Current Tor connection":"Current external exit",
    "samples":3,"failed":0,"ready":true,"median_ms":Double(all.count)+3]
   if transport != "tcp"{value["server_name"]=catalog.1};if transport=="https"{value["path"]="/dns-query"}
   all.append(value)
  };return all
 }
 static func owner(_ id:String,_ epoch:String=UUID().uuidString,_ proof:String=UUID().uuidString)throws->IOSDNSMeasurementInfo{
  try IOSDNSMeasurementInfo.decode(json(["schema":1,"ack_id":id,"node_id":"exit","session_id":epoch,"native_session_id":proof]),request:id,node:"exit")
 }
 static func receipt(_ id:String,_ owner:IOSDNSMeasurementInfo,_ transport:String="tls",tor:Bool=false)throws->[String:Any]{
  ["schema":1,"ack_id":id,"request_id":id,"node_id":owner.node_id,"session_id":owner.session_id,"native_session_id":owner.native_session_id,
   "public_transport":transport,"stage":"complete","complete":true,"drained":true,"results":rows(transport,tor:tor)]
 }
 static func fixtureProfile()throws->RouterProfile{
  try JSONDecoder().decode(RouterProfile.self,from:json(["id":"exit","name":"Saved exit","node_kind":"external","endpoint":"198.51.100.8",
   "router_api":"","api_token":"private","adguard_ipv4":"","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":"",
   "external":["protocol":"socks5","expected_public_ip":"203.0.113.8"],"dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","dns_port":53,
   "dns_server_name":"","dns_path":"/dns-query","ipv6_mode":"on"]))
 }
 static func model()throws->RouterVPNModel{
  let m=RouterVPNModel();var b=ClientBundle.empty;b.selectedRouterID="exit";b.routerProfiles=[try fixtureProfile()];m.bundle=b
  m.activeSessionIdentity=try IOSSessionIdentity(connectedAt:Date(),engine:"external-libbox",rawProfile:"external-socks5",
   bundleData:m.externalRuntimeBundleData(source:b,profile:b.routerProfiles[0]),entryBundleData:nil)
  return m
 }
 static func pairEntry(_ m:RouterVPNModel)throws{
  var b=m.bundle!;b.routerProfiles[0].multihopEnabled=true;b.routerProfiles[0].multihopEntryID="entry";b.routerProfiles[0].multihopExitID="exit";b.routerProfiles[0].multihopEntryMode="wg"
  var e=ClientBundle.empty,p=try fixtureProfile();p.id="entry";p.nodeKind="router-vpn";p.external=nil;p.adGuardIPv4="10.77.0.1"
  e.selectedRouterID="entry";e.routerProfiles=[p];m.entry=e;m.bundle=b
  m.activeSessionIdentity=try IOSSessionIdentity(connectedAt:Date(),engine:"external-libbox",rawProfile:"external-socks5",
   bundleData:m.externalRuntimeBundleData(source:b,profile:b.routerProfiles[0]),entryBundleData:m.externalTorEntryData(source:b),entryMode:"wg")
 }
 static func info(_ session:RouterVPNDNSMeasurementSession,_ id:String)throws->IOSDNSMeasurementInfo{
  try IOSDNSMeasurementInfo.decode(session.info(request:id)!,request:id,node:"exit")
 }
 static func reply(_ session:RouterVPNDNSMeasurementSession,_ information:IOSDNSMeasurementInfo,_ operation:String,_ id:String,_ transport:String="")->Data?{
  session.reply(operation:"dns-measure-"+operation,request:id,session:information.session_id,nativeSession:information.native_session_id,transport:transport)
 }
 static func validation()throws{
  let id=String(repeating:"a",count:32),information=try owner(String(repeating:"a",count:32))
  for tor in [false,true]{for transport in ["tcp","tls","https"]{for selected in ["udp","tcp","tls","https","h3"]{
   var value=try receipt(id,information,transport,tor:tor);value["results"]=rows(transport,tor:tor,selected:selected)
   let decoded=try IOSDNSMeasurementStatus.decode(json(value),request:id,owner:information).validatedResults(transport:transport,tor:tor)
   try check("catalog and exact selected transport "+transport+"/"+selected,decoded.count==13 && decoded.first!.transport==selected && decoded.first!.route=="captured-private-entry")
  }}}
  let valid=try receipt(id,information)
  for (key,bad):(String,Any) in [("schema",2),("request_id",String(repeating:"b",count:32)),("ack_id",String(repeating:"b",count:32)),("node_id","other"),("session_id",UUID().uuidString),("native_session_id",UUID().uuidString),("complete",false),("drained",false),("public_transport","https"),("failure","native failure")] {
   var value=valid;value[key]=bad
   try rejects("foreign or incomplete receipt "+key){_ = try IOSDNSMeasurementStatus.decode(json(value),request:id,owner:information).validatedResults(transport:"tls",tor:false)}
  }
  for (key,bad):(String,Any) in [("id","foreign"),("kind","selected"),("address","203.0.113.8"),("transport","udp"),("port",53),("server_name","unverified.example"),("path","/other"),("route","direct"),("route_label","Current Tor connection"),("samples",2),("failed",1),("median_ms",0),("ready",false)] {
   var value=valid,varRows=rows();varRows[1][key]=bad;value["results"]=varRows
   try rejects("public endpoint/result mismatch "+key){_ = try IOSDNSMeasurementStatus.decode(json(value),request:id,owner:information).validatedResults(transport:"tls",tor:false)}
  }
  for kind in ["missing","duplicate","selected-route","no-median","numeric-unavailable","control-name"]{
   var value=valid,varRows=rows()
   switch kind{case "missing":varRows.removeLast();case "duplicate":varRows[2]=varRows[1]
   case "selected-route":varRows[0]["route_label"]="Current Tor connection"
   case "no-median":varRows[1].removeValue(forKey:"median_ms")
   case "numeric-unavailable":varRows[1]["ready"]=false;varRows[1]["samples"]=0;varRows[1]["failed"]=3;varRows[1]["failure"]="unreachable"
   default:varRows[1]["name"]="bad\nname"};value["results"]=varRows
   try rejects(kind){_ = try IOSDNSMeasurementStatus.decode(json(value),request:id,owner:information).validatedResults(transport:"tls",tor:false)}
  }
  var unavailable=valid,varRows=rows();varRows[1]["ready"]=false;varRows[1]["samples"]=0;varRows[1]["failed"]=3;varRows[1]["failure"]="IPv6 is disabled for this captured connection";varRows[1].removeValue(forKey:"median_ms");unavailable["results"]=varRows
  let accepted=try IOSDNSMeasurementStatus.decode(json(unavailable),request:id,owner:information).validatedResults(transport:"tls",tor:false)
  try check("unavailable stays labelled without a numeric substitute",accepted.last?.ready==false && accepted.last?.median_ms==nil)
  try rejects("wrong native info acknowledgement"){_ = try IOSDNSMeasurementInfo.decode(json(["schema":1,"ack_id":"wrong","node_id":"exit","session_id":information.session_id,"native_session_id":information.native_session_id]),request:id,node:"exit")}
 }
 static func provider()throws{
  let disk=IOSDNSRetirementReceipts.shared,id=String(repeating:"a",count:32),other=String(repeating:"b",count:32)
  for kind in ["never-started","started","complete","native-close-fails","write-fails"]{
   disk.reset();let native=LibboxRouterDNSMeasurement(node:"exit"),session=try RouterVPNDNSMeasurementSession(native:native,epoch:UUID().uuidString,nodeID:"exit")
   let information=try info(session,id)
   try check("Info reservations do not launch native DNS",native.counts().0==0 && disk.count()==0)
   if kind != "never-started"{_ = reply(session,information,"start",id,"tls")}
   if kind=="complete"{native.finish(rows());_ = reply(session,information,"status",id)}
   if kind=="native-close-fails"{native.configure(hold:true)}
   if kind=="write-fails"{disk.configure(writable:false)}
   if ["native-close-fails","write-fails"].contains(kind){
    try rejects("unconfirmed native drain or persistence retains close owner"){try session.close()}
    try check("failed Close stays retryable",!session.isClosed && disk.count()==0)
    native.configure();disk.configure();try session.close()
   }else{try session.close()}
   try check("Close joins each reserved request including lost Start: "+kind,session.isClosed && native.drainedRequests().contains(id) && native.counts().1==0)
   let recovered=disk.drained(providerSession:information.session_id,nativeSession:information.native_session_id,request:id,nodeID:"exit")!
   let clean=try IOSDNSMeasurementStatus.decode(recovered,request:id,owner:information)
   try check("persisted recovery has no native timings",clean.complete && clean.drained && clean.results.isEmpty && clean.failure != nil)
   try rejects("disk cannot be adopted as DNS timing"){_ = try clean.validatedResults(transport:"tls",tor:false)}
   try check("retired info cannot create a new reservation",session.info(request:other)==nil)
   try check("wrong proof cannot address retained native cleanup",session.reply(operation:"dns-measure-drain",request:id,session:information.session_id,nativeSession:UUID().uuidString,transport:"")==nil)
  }
  disk.reset();do{
   let native=LibboxRouterDNSMeasurement(node:"exit"),session=try RouterVPNDNSMeasurementSession(native:native,epoch:UUID().uuidString,nodeID:"exit")
   native.configure(hold:true);let information=try info(session,id);_ = reply(session,information,"start",id,"tls")
   let duplicate=try IOSDNSMeasurementStatus.decode(reply(session,information,"start",id,"tls")!,request:id,owner:information)
   try check("duplicate active Start returns live ownership, never fake drain",!duplicate.drained && native.counts().0==1)
   let second=try info(session,other);let rejected=try IOSDNSMeasurementStatus.decode(reply(session,second,"start",other,"https")!,request:other,owner:second)
   try check("busy request is tombstoned without cancelling active work",rejected.complete && rejected.drained && native.counts().0==1 && native.counts().1==1 && !native.cancelled().contains(id))
   let pending=try IOSDNSMeasurementStatus.decode(reply(session,information,"drain",id)!,request:id,owner:information)
   try check("Drain timeout cannot release active workers",!pending.drained && disk.drained(providerSession:information.session_id,nativeSession:information.native_session_id,request:id,nodeID:"exit")==nil)
   native.configure();_ = reply(session,information,"drain",id)
   try check("later actual drain becomes recoverable",disk.drained(providerSession:information.session_id,nativeSession:information.native_session_id,request:id,nodeID:"exit") != nil)
   try session.close()
  }
  disk.reset();do{
   let native=LibboxRouterDNSMeasurement(node:"exit"),session=try RouterVPNDNSMeasurementSession(native:native,epoch:UUID().uuidString,nodeID:"exit")
   let information=try info(session,id);_ = reply(session,information,"cancel",id);_ = reply(session,information,"start",id,"tls")
   try check("cancel overtaking Start prevents all native work",native.counts().0==0 && native.drainedRequests().contains(id))
   try session.close()
  }
  disk.reset(available:false);do{
   let native=LibboxRouterDNSMeasurement(node:"exit"),session=try RouterVPNDNSMeasurementSession(native:native,epoch:UUID().uuidString,nodeID:"exit")
   try rejects("missing App Group rejects Info before work"){_ = try info(session,id)}
   try check("failed preflight creates no start reservation",session.reply(operation:"dns-measure-start",request:id,session:session.epoch,nativeSession:UUID().uuidString,transport:"tls")==nil && native.counts().0==0)
  }
  disk.reset();do{
   let native=LibboxRouterDNSMeasurement(node:"exit"),session=try RouterVPNDNSMeasurementSession(native:native,epoch:UUID().uuidString,nodeID:"exit")
   for number in 0..<128{try check("bounded info reservation",session.info(request:String(format:"%032x",number)) != nil)}
   try check("reservation exhaustion cannot silently evict an unretired nonce",session.info(request:String(repeating:"f",count:32))==nil)
   try session.close();try check("all bounded lost Starts are drained at retirement",native.drainedRequests().count==128 && disk.count()==128)
  }
 }
 static func captures()throws{
  let m=try model(),capture=try IOSDNSMeasurementCapture(model:m)
  try capture.requireCurrent(model:m)
  try check("source capture accepts exact runtime sanitization",capture.nodeID=="exit" && !capture.tor)
  let original=m.bundle!
  for field in ["mode","protocol","host","port","server","path","bootstrap","private-source","selected-node"]{
   var b=original
   switch field{case "mode":b.routerProfiles[0].dnsMode="home";case "protocol":b.routerProfiles[0].dnsProtocol="tls"
   case "host":b.routerProfiles[0].dnsHost="1.1.1.1";case "port":b.routerProfiles[0].dnsPort=853
   case "server":b.routerProfiles[0].dnsServerName="dns.example";case "path":b.routerProfiles[0].dnsPath="/changed"
   case "bootstrap":b.routerProfiles[0].dnsBootstrap=ExternalDNSBootstrap(server:.init(type:"tcp",server:"1.1.1.1",serverPort:53))
   case "private-source":b.apiToken="changed-private-token";default:b.selectedRouterID="other"};m.bundle=b
   try rejects("source mutation "+field){try capture.requireCurrent(model:m)};m.bundle=original
  }
  for field in ["decision","mode","logical-mode","auto","connection","disconnect","transition","network"]{
   let m=try model();var capture=try IOSDNSMeasurementCapture(model:m);capture.network=IOSViaEntryNetwork.shared.current
   switch field{case "decision":m.iosConnectGeneration=UUID();case "mode":m.selectedMode="different";case "logical-mode":m.selectedLogicalMode="different"
   case "auto":m.auto=true;case "connection":let old=m.activeSessionIdentity!;m.activeSessionIdentity=try IOSSessionIdentity(connectedAt:old.connectedAt.addingTimeInterval(1),engine:old.engine,rawProfile:old.rawProfile,bundleData:old.bundleData,entryBundleData:nil)
   case "disconnect":m.iosUserDisconnectInProgress=true;case "transition":m.tunnelTransitioning=true;default:IOSViaEntryNetwork.shared.current+=1}
   try rejects("captured identity revoked by "+field){try capture.requireCurrent(model:m)}
  }
  let paired=try model();try pairEntry(paired);let pairedCapture=try IOSDNSMeasurementCapture(model:paired)
  paired.connected=false;paired.activeSessionIdentity=nil;paired.iosConnectGeneration=UUID()
  try pairedCapture.requireSources(model:paired)
  try check("source-bound draft survives a legitimate Disconnect",!paired.connected)
  paired.entry!.routerProfiles[0].adGuardIPv4="10.88.0.1"
  try rejects("linked entry edit invalidates disconnected source capture"){try pairedCapture.requireSources(model:paired)}
 }
 static func clients()async throws{
  for scenario in ["complete","complete-tcp","complete-https","linked-change","cancel-pending","lost-start","lost-start-reply","storage-retry","stop-after-info","source-change","network-change","info-preflight"]{
   IOSDNSRetirementReceipts.shared.reset();let m=try model(),client=IOSDNSMeasurementClient(),native=LibboxRouterDNSMeasurement(node:"exit")
   if scenario=="linked-change"{try pairEntry(m)}
   let session=try RouterVPNDNSMeasurementSession(native:native,epoch:UUID().uuidString,nodeID:"exit")
   var ipc=true,nonce="",information:IOSDNSMeasurementInfo?,afterStart=false
   let transport=scenario=="complete-tcp" ? "tcp":scenario=="complete-https" ? "https":"tls"
   if ["cancel-pending","lost-start-reply"].contains(scenario){native.configure(hold:true)}
   IOSMTUControl.connection.handler={data,callback in
    guard ipc else{callback?(nil);return}
    let request=try! obj(data),operation=request["operation"] as! String,id=request["request_id"] as! String
    if operation=="dns-measure-info"{
     if scenario=="info-preflight"{IOSDNSRetirementReceipts.shared.configure(available:false)}
     let result=session.info(request:id);nonce=id
     if let result{information=try? IOSDNSMeasurementInfo.decode(result,request:id,node:"exit")}
     if scenario=="stop-after-info"{client.cancel();ipc=false;try! session.close();m.connected=false}
     callback?(result);return
    }
    if operation=="dns-measure-start",scenario=="lost-start"{ipc=false;try! session.close();m.connected=false;callback?(nil);return}
    let result=session.reply(operation:operation,request:id,session:request["session_id"] as! String,nativeSession:request["native_session_id"] as! String,transport:request["transport"] as! String)
    if operation=="dns-measure-start"{
     afterStart=true
     if scenario=="lost-start-reply"{ipc=false;m.connected=false;callback?(nil);return}
     if scenario=="storage-retry"{
      IOSDNSRetirementReceipts.shared.configure(writable:false)
      try? session.close();try? session.close() // The engine's two synchronous attempts both fail.
      ipc=false;m.connected=false;callback?(nil);return
     }
     if scenario.hasPrefix("complete") || ["linked-change","source-change","network-change"].contains(scenario){native.finish(rows(transport))
      if scenario=="source-change"{m.bundle!.routerProfiles[0].dnsHost="1.1.1.1"}
      if scenario=="network-change"{IOSViaEntryNetwork.shared.current+=1}
      callback?(reply(session,information!,"status",id));return
     }
    }
    callback?(result)
   }
   client.start(model:m,transport:transport)
   if ["cancel-pending","lost-start-reply","storage-retry"].contains(scenario){
    await wait("native active"){afterStart}
    if scenario=="cancel-pending"{client.cancel()}
    await wait("cleanup pending"){client.cleanupPending}
    try check("native workers retain host transaction and MTU hold",client.running && m.iosSpeedLabOwnership.active && IOSMTUMeasurementGate.held && native.counts().1==(scenario=="storage-retry" ? 0:1))
    try check("unconfirmed cleanup cannot produce timing",client.results.isEmpty)
    var newConnection=false
    let queued=Task{if await m.iosSpeedLabOwnership.admitConnection(){newConnection=true}}
    try? await Task.sleep(for:.milliseconds(25))
    try check("new Connect waits for actual DNS drain",!newConnection)
    native.configure()
    if scenario=="lost-start-reply"{try session.close()}
    if scenario=="storage-retry"{
     try check("failed stop writes remain unknown after IPC disappears",!ipc && !session.isClosed && IOSDNSRetirementReceipts.shared.count()==0 && native.counts().2>=2)
     IOSDNSRetirementReceipts.shared.configure()
     // Do not call Close or provider IPC again. The retained shipping timer
     // alone must commit the already-drained exact native receipt.
    }
    await wait("captured cleanup complete"){!client.running}
    await queued.value
    try check("only acknowledged cleanup releases queued Connect",newConnection && !m.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
    if scenario=="storage-retry"{try check("retained provider retry recovers transient storage without IPC",session.isClosed && native.counts().2>=3 && IOSDNSRetirementReceipts.shared.count()==1 && !ipc)}
   }else{await wait("client complete "+scenario){!client.running}}
   if scenario.hasPrefix("complete") || scenario=="linked-change"{
    try check("completed native path publishes all labelled DNS rows",client.results.count==13 && client.error.isEmpty)
    let result=client.results.first(where:{$0.kind=="public"})!;try client.requireCurrent(model:m,result:result)
    let before=m.bundle!.routerProfiles,editor=DNSDraftEditor(m,client)
    editor.choose(result)
    try check("measured Fastest fills exact transport fields without saving",editor.mode=="custom" && editor.protocolName==result.transport && editor.host==result.address && editor.port==String(result.port) && editor.serverName==(result.server_name ?? "") && editor.path==(result.path ?? "/dns-query") && !editor.useHostnameBootstrap && editor.measuredDraft && m.bundle!.routerProfiles==before)
    let validEditor=DNSDraftEditor(m,client);validEditor.choose(result)
    editor.host="untouched";editor.choose(client.results[0])
    try check("selected Home row cannot silently replace the DNS editor",editor.host=="untouched" && m.bundle!.routerProfiles==before)
    m.bundle!.routerProfiles[0].dnsHost="1.0.0.1"
    try rejects("stale measured choice cannot fill editor"){try client.requireCurrent(model:m,result:result)}
    editor.choose(result);try check("stale Fastest click leaves editor fields unchanged",editor.host=="untouched")
    m.bundle!.routerProfiles=before;m.connected=false;m.activeSessionIdentity=nil;m.iosConnectGeneration=UUID()
    if scenario=="linked-change"{
     m.entry!.routerProfiles[0].adGuardIPv4="10.88.0.1";validEditor.save()
     try check("explicit Save rejects a changed linked entry without writes",m.imports==0 && m.bundle!.routerProfiles==before && validEditor.measuredSource != nil)
    }else{
     validEditor.host="1.0.0.1" // Manual edits are allowed within the same source-bound draft.
     validEditor.save()
     try check("explicit disconnected Save commits the manually editable draft once",m.imports==1 && m.bundle!.routerProfiles[0].dnsHost=="1.0.0.1" && m.bundle!.routerProfiles[0].dnsProtocol==transport && validEditor.measuredSource==nil && !validEditor.measuredDraft)
     try check("explicit draft never writes unlabelled historical timings",m.bundle!.routerProfiles[0].fastestDNSHost==before[0].fastestDNSHost && m.bundle!.routerProfiles[0].fastestDNSLatencyMs==before[0].fastestDNSLatencyMs && m.bundle!.routerProfiles[0].dnsResults==before[0].dnsResults)
    }
    client.invalidateIfStale(model:m);try check("stale displayed results are discarded",client.results.isEmpty)
   }else{try check("failure/cancel/retirement never publishes timings: "+scenario,client.results.isEmpty && !client.error.isEmpty)}
   try check("finished host releases exact transaction and MTU hold",!m.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
   if ["lost-start","stop-after-info"].contains(scenario){
    try check("lost Start is actually tombstoned and drained",native.counts().0==0 && native.cancelled().contains(nonce) && native.drainedRequests().contains(nonce))
    try check("stopped provider recovery has exact native identity",IOSDNSRetirementReceipts.shared.drained(providerSession:information!.session_id,nativeSession:information!.native_session_id,request:nonce,nodeID:"exit") != nil)
   }
   IOSDNSRetirementReceipts.shared.configure();native.configure();try session.close()
  }
  for delay in [false,true]{
   IOSDNSRetirementReceipts.shared.reset();let m=try model(),client=IOSDNSMeasurementClient();var calls=0
   IOSMTUControl.connection.handler={_,reply in calls+=1;reply?(nil)}
   IOSViaEntryNetwork.shared.hold=delay
   client.start(model:m,transport:"tls")
   if delay{try? await Task.sleep(for:.milliseconds(10))}
   client.cancel();IOSViaEntryNetwork.shared.release()
   await wait("queued start cancelled"){!client.running}
   try check("Cancel before ownership cannot send native Start",calls==0 && !m.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
  }
  IOSDNSRetirementReceipts.shared.reset(available:false);do{
   let m=try model(),client=IOSDNSMeasurementClient();var calls=0;IOSMTUControl.connection.handler={_,reply in calls+=1;reply?(nil)}
   client.start(model:m,transport:"tls");await wait("app preflight"){!client.running}
   try check("app capability preflight precedes native ownership",calls==0 && !m.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
  };IOSDNSRetirementReceipts.shared.reset()
 }
 static func main()async throws{
  try validation();try provider();try captures();try await clients()
  print("Apple DNS measurements: PASS (\(checks) shipping Swift checks; native/OS/storage boundaries doubled)")
 }
}
'''


def boundaries():
    capture_builders = (APP / 'RouterVPNModelExternal.swift').read_text()
    boundaries = BOUNDARIES.replace('// SELECTED_PROFILE', method((APP / 'IOSDNSRuntimePolicy.swift').read_text(), '    static func selectedProfile('))
    boundaries = boundaries.replace('// EXACT_CONNECT_BUILDERS', '\n'.join(method(capture_builders, signature) for signature in
        ('    func externalTorEntryData(', '    func externalRuntimeBundleData(')))
    view = (APP / 'IOSDNSPolicyView.swift').read_text()
    boundaries = boundaries.replace('// SHIPPING_DNS_EDITOR', '\n'.join(method(view, signature) for signature in (
        '    private var ordinaryExternal:', '    private var torExternal:', '    private var nativeExternal:',
        '    private var externalDNSFields:', '    private func selectedProfile(', '    private func load(',
        '    private func savePolicy(', '    private func defaultPort(', '    private func useMeasured(')))
    return boundaries


def source():
    shipping = '\n'.join((APP / path).read_text() for path in (
        'Models.swift', 'IOSSessionIdentity.swift', 'IOSSpeedLabOwnership.swift', 'IOSMTUMeasurementGate.swift',
        'IOSDNSMeasurement.swift', 'IOSDNSMeasurementClient.swift'))
    shipping += '\n' + (TUNNEL / 'RouterVPNDNSMeasurementSession.swift').read_text()
    for imported in ('import Combine\n', '@preconcurrency import NetworkExtension\n', 'import Libbox\n'):
        shipping = shipping.replace(imported, '')
    return 'import Foundation\n' + NATIVE + STORAGE + boundaries() + shipping + TESTS


def main():
    swift = shutil.which('swiftc')
    if not swift: raise SystemExit('swiftc is required')
    view = (APP / 'IOSDNSPolicyView.swift').read_text()
    provider = (TUNNEL / 'PacketTunnelProvider.swift').read_text()
    for marker in ('nativeMeasurement.start(model: model, transport: comparisonTransport)',
                   'try nativeMeasurement.captureForEditor(model: model, result: value)',
                   'nativeMeasurement.cancel()', 'try captured.requireCurrent(model: model)',
                   'Disconnect to save this DNS choice', 'No public UDP fallback',
                   'Button("Use fastest \\(fastest.transportLabel) in editor") { useMeasured(fastest) }'):
        assert marker in view, marker
    comparison = view[view.index('    private func retest('):view.index('    private func usePreset(')]
    for forbidden in ('fastestDNSHost =', 'fastestDNSLatencyMs =', '.dnsResults =', 'model.importBundle(', 'savePolicy()'):
        assert forbidden not in comparison, 'comparison may only prepare editor fields: ' + forbidden
    for marker in ('messageData.count <= 512', 'Set(["operation", "request_id", "session_id", "native_session_id", "transport"])', 'RouterVPNDNSMeasurementRegistry.shared.reply',
                   'try engine.enableExternalDNSMeasurement(exitID: exitID)', '"hop-measure-info"'):
        assert marker in provider, marker
    with tempfile.TemporaryDirectory(prefix='ios-dns-measurement-') as directory:
        work = Path(directory)
        code, binary = work / 'test.swift', work / 'test'
        args = [swift, '-swift-version', '6', '-parse-as-library', '-module-cache-path', str(work / 'modules')]
        good = source()
        def execute(contents, mutation=None):
            code.write_text(contents)
            subprocess.run(args + [str(code), '-o', str(binary)], check=True, timeout=150)
            result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=35)
            if mutation:
                assert result.returncode != 0 and 'FAIL:' in result.stderr, f'Negative control escaped: {mutation}\n{result.stdout}\n{result.stderr}'
                print('Apple DNS negative control rejected: ' + mutation)
            else:
                assert result.returncode == 0, result.stdout + result.stderr
                print(result.stdout.strip())
        execute(good)
        for name, before, after in (
            ('lost Start reservation discarded', '            reservations.insert(request)', '            // broken: lost Info reservation'),
            ('native proof session not bound', 'value.native_session_id == owner.native_session_id,', 'true,'),
            ('stopped provider does not retry receipt persistence', '            scheduleRetirementRetry()', '            // broken: no retained retirement retry'),
            ('paired entry source not checked at explicit Save', 'do { try measuredSource?.requireSources(model: model) }', 'do { try Optional<IOSDNSMeasurementCapture>.none?.requireSources(model: model) }'),
        ):
            assert good.count(before) == 1, name
            execute(good.replace(before, after), name)
        subprocess.run([swift, '-frontend', '-parse', '-swift-version', '6', str(APP / 'IOSDNSPolicyView.swift'),
            str(TUNNEL / 'PacketTunnelProvider.swift')], check=True, timeout=90)
        if platform.system() == 'Darwin':
            # Functional OS doubles cannot certify SDK signatures or Swift 6
            # actor isolation of the actual Combine/NetworkExtension imports.
            sdk_boundaries = boundaries()
            sdk_boundaries = sdk_boundaries[sdk_boundaries.index('enum IOSRuntimeSelectionError'):]
            begin = sdk_boundaries.index('@MainActor final class NETunnelProviderSession')
            end = sdk_boundaries.index('@MainActor final class IOSViaEntryNetwork', begin)
            sdk_boundaries = sdk_boundaries[:begin] + sdk_boundaries[end:]
            sdk_boundaries = sdk_boundaries.replace('static let connection=NETunnelProviderSession()',
                'static var connection: NETunnelProviderSession!')
            actual = work / 'SDKBoundaries.swift'
            actual.write_text('import Foundation\n@preconcurrency import NetworkExtension\n' + sdk_boundaries)
            sdk = subprocess.check_output(['xcrun', '--sdk', 'iphonesimulator', '--show-sdk-path'], text=True).strip()
            sources = [APP / name for name in ('Models.swift', 'IOSSessionIdentity.swift', 'IOSSpeedLabOwnership.swift',
                'IOSMTUMeasurementGate.swift', 'IOSDNSMeasurement.swift', 'IOSDNSMeasurementClient.swift', 'IOSDNSRetirementReceipts.swift')]
            subprocess.run([swift, '-swift-version', '6', '-typecheck', '-sdk', sdk,
                '-target', 'arm64-apple-ios16.0-simulator', str(actual)] + [str(p) for p in sources], check=True, timeout=150)
            print('Apple DNS client: actual iPhoneSimulator Combine/NetworkExtension SDK typecheck PASS')
    print('Apple DNS IPC/UI wiring and Swift 6 parser: PASS; full generated framework/SDK compilation remains mandatory in the Apple build')


if __name__ == '__main__': main()
