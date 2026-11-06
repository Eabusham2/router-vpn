#!/usr/bin/env python3
"""Execute Apple external comparison with the shipping temporary lifecycle.

The actual public external Connect, native capture/stop/restore, task ownership,
MTU lease, native50 transaction, journal, result store and final usage accounting
run together. System VPN, physical-network callbacks and private storage are
explicit failure-injectable boundaries. No network/device acceptance is claimed.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

import test_ios_node_usage as usage
import test_ios_speed_lab_tunnel as tunnel

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "ios/RouterVPN/App"

BOUNDARY = r'''
@propertyWrapper struct Published<Value>{var wrappedValue:Value;init(wrappedValue:Value){self.wrappedValue=wrappedValue}}
protocol ObservableObject:AnyObject{}
func json(_ object:Any)throws->Data{try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys])}
@MainActor func encoded<T:Encodable>(_ value:T)throws->Data{try IOSNodeUsage.canonical(value)}
enum IOSTelemetryProtocol{static func issue(_ text:String)->NSError{NSError(domain:"NativeBoundary",code:1,userInfo:[NSLocalizedDescriptionKey:text])}}
enum IOSDNSMeasurementStatus{static func issue(_ text:String)->NSError{IOSTelemetryProtocol.issue(text)}}
enum IOSRuntimeSelectionError:Error{case unsupportedMode(String)}
enum IOSDNSRuntimePolicy{
 static func selectedProfile(in value:ClientBundle)->RouterProfile?{let p=value.routerProfiles.filter{$0.id==value.selectedRouterID};return p.count==1 ? p[0]:nil}
}
@MainActor final class UserDefaults {
 static let standard=UserDefaults()
 var values:[String:Data]=[:],syncs=0
 var syncHook:(()->Void)?,writeHook:((String,Data?)->Void)?,failSync=0
 func data(forKey key:String)->Data?{values[key]}
 func set(_ value:Any?,forKey key:String){values[key]=value as? Data;writeHook?(key,value as? Data)}
 func removeObject(forKey key:String){values.removeValue(forKey:key);writeHook?(key,nil)}
 func synchronize()->Bool{syncs+=1;syncHook?();if failSync>0{failSync-=1;return false};return true}
 func reset(){values=[:];syncs=0;syncHook=nil;writeHook=nil;failSync=0}
}
@MainActor final class IOSViaEntryNetwork{
 static let shared=IOSViaEntryNetwork()
 var current:UInt64?=1,hook:(()->Void)?
 func snapshot()async throws->UInt64{await Task.yield();hook?();guard let current else{throw CancellationError()};return current}
}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore();var records:[String:Data]=[:]
 func bundleData(containing id:String,current:ClientBundle?)->Data?{
  records.keys.sorted().compactMap{records[$0]}.first{(try? JSONDecoder().decode(ClientBundle.self,from:$0).routerProfiles.contains{$0.id==id})==true}
 }
 func profiles(current:ClientBundle?)->[RouterProfile]{records.keys.sorted().flatMap{(try? JSONDecoder().decode(ClientBundle.self,from:records[$0]!).routerProfiles) ?? []}}
}
@MainActor enum Trace {
 static var values:[String]=[],starts:[String:Int]=[:],stops:[String:Int]=[:],measures:[String:Int]=[:],comparisons:[String:Int]=[:]
 static var leases=Set<String>(),releases=0,heldDrain=false,cancels=0
 static var scores:[String:Double]=[:],failures:[String:String]=[:],winners:[String:String]=[:]
 static var infoHook:((Connection)->Void)?,saveHook:((NETunnelProviderManager)->Void)?,refreshHook:((RouterVPNModel)->Void)?
 static var failMarkerSave=false,failMarkerRead=false,failRelease=false,failRetireSave=false,failRetireRead=false
 static func reset(){values=[];starts=[:];stops=[:];measures=[:];comparisons=[:];leases=[];releases=0;heldDrain=false;cancels=0;scores=[:];failures=[:];winners=[:];infoHook=nil;saveHook=nil;refreshHook=nil;failMarkerSave=false;failMarkerRead=false;failRelease=false;failRetireSave=false;failRetireRead=false}
}
@MainActor final class Connection {
 weak var manager:NETunnelProviderManager?
 var status:Status = .disconnected,connectedDate:Date?
 var epoch=UUID().uuidString,mtu=UUID().uuidString,execution="local",nodeID="",requested="local",configuration=""
 var held=false,lease="",drained=true,cancelled=false,lastRequest="",infoCalls=0
 func startVPNTunnel(options:[String:NSObject]?=nil)throws{
  guard let config=(manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
        let data=config["bundle"] as? Data,
        let bundle=try? JSONDecoder().decode(ClientBundle.self,from:data),let profile=IOSDNSRuntimePolicy.selectedProfile(in:bundle)else{throw CancellationError()}
  nodeID=profile.id;requested=profile.multihopExecution ?? "local"
  if try IOSMultihopExecution.requiresCapture(configuration:config){
   let source=try IOSMultihopExecution.Source(configuration:config,digest:RouterVPNModel.iosStrategyDigest)
   let restore=try IOSMultihopExecution.restoredCapture(option:options?[IOSMultihopExecution.launchKey],source:source,mtuHold:options?["routervpn_mtu_hold"] as? String ?? "")
   if restore==nil && source.requested=="auto"{Trace.comparisons[nodeID,default:0]+=1}
   execution=restore?.execution ?? Trace.winners[nodeID] ?? (requested=="auto" ? "local":requested)
  }else{execution="local"}
  Trace.starts[nodeID,default:0]+=1;Trace.values.append("start:"+nodeID)
  if Trace.failures[nodeID]=="proof" || Trace.failures[nodeID]=="final-proof" && Trace.starts[nodeID,default:0]>1{status = .disconnected;connectedDate=nil;throw IOSTelemetryProtocol.issue("native path proof rejected")}
  if Trace.failures[nodeID]=="restore-execution",options?[IOSMultihopExecution.launchKey] != nil{execution=execution=="local" ? "server":"local"}
  epoch=UUID().uuidString;mtu=UUID().uuidString;connectedDate=Date();status = .connected
  configuration=IOSNodeUsage.digest(Data((nodeID+epoch+execution).utf8))
  lease=options?["routervpn_mtu_hold"] as? String ?? "";held = !lease.isEmpty
  if held{Trace.leases.insert(lease)}
  drained=true;cancelled=false;lastRequest="";infoCalls=0
 }
 func stopVPNTunnel(){Trace.stops[nodeID,default:0]+=1;Trace.values.append("stop:"+nodeID);status = .disconnected;connectedDate=nil}
 func sendProviderMessage(_ data:Data,responseHandler reply:((Data?)->Void)?=nil)throws{
  do{
   let q=try JSONDecoder().decode([String:String].self,from:data)
   guard q.count==3,let op=q["operation"],let id=q["request_id"],let session=q["session_id"],
         status == .connected || op=="hop-measure-cancel" else{throw CancellationError()}
   if op.hasPrefix("mtu-"){
    if op=="mtu-hold"{held=true;lease=id;Trace.leases.insert(id)}
    if op=="mtu-release"{
     guard !Trace.failRelease,drained else{throw CancellationError()};held=false;Trace.releases+=1
    }
    reply?(try json(["ack_id":id,"session_id":mtu,"measurement_hold":held,"measurement_ready":held,"measurement_lease":lease]));return
   }
   if op=="speed-lab-execution"{
    let config=(manager!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
    let source=try IOSMultihopExecution.Source(configuration:config,digest:RouterVPNModel.iosStrategyDigest)
    reply?(try IOSMultihopExecution.Capture(source:source,execution:execution,session:epoch,request:id,pins:.empty).encoded());return
   }
   guard held else{throw CancellationError()}
   if op=="hop-measure-info"{
    infoCalls+=1;Trace.infoHook?(self)
    let failure=Trace.failures[nodeID] ?? ""
    var e:[String:Any]=["requested":requested,"selected":execution,"config_sha256":configuration]
    if infoCalls>1 && failure=="execution"{e["selected"]=execution=="local" ? "server":"local"}
    if infoCalls>1 && failure=="configuration"{e["config_sha256"]=String(repeating:"f",count:64)}
    var value:[String:Any]=["request_id":id,"session_id":epoch,"mtu_session_id":mtu,"node_id":nodeID,"execution":e]
    if failure=="missing-execution"{value.removeValue(forKey:"execution")}
    reply?(try json(value));return
   }
   guard session==epoch else{throw CancellationError()}
   if op=="hop-measure-latency-start"{Trace.measures[nodeID,default:0]+=1;lastRequest=id;drained = !Trace.heldDrain}
   else if op=="hop-measure-cancel"{cancelled=true;Trace.cancels+=1;drained = !Trace.heldDrain}
   else if op != "hop-measure-status"{throw CancellationError()}
   if !Trace.heldDrain{drained=true}
   var value:[String:Any]=["request_id":id,"session_id":epoch,"complete":true,"drained":drained,"stage":cancelled ? "cancelled":"complete","results":[]]
   if !cancelled{
    let failure=Trace.failures[nodeID] ?? "",score=Trace.scores[nodeID] ?? 10
    let stats:[String:Any]=["samples":failure=="partial" ? 49:50,"min_ms":score/2,"median_ms":score,"average_ms":score,"p90_ms":score*1.5,"max_ms":score*2,"jitter_ms":1]
    let benchmark:[String:Any]=["schema":1,"measurement":"routed-https-response-after-tls","endpoint":failure=="endpoint" ? "https://other.example/":"https://speed.cloudflare.com/__down?bytes=1","attempts":50,"failed":failure=="failed" ? 1:0,"distribution":stats,"trimmed_mean_ms":score]
    value["results"]=[["node_id":failure=="wrong-node" ? "foreign":nodeID,"role":"exit","kind":"public-path","label":"Native HTTPS boundary","ready":true,"benchmark":benchmark]]
   }
   reply?(try json(value))
  }catch{reply?(nil)}
 }
}
typealias NETunnelProviderSession=Connection
@MainActor final class NETunnelProviderManager{
 static var stored:[NETunnelProviderManager]=[],allReadHook:(()->Void)?
 var protocolConfiguration:NEVPNProtocol?,onDemandRules:[NEOnDemandRule]?,localizedDescription:String?
 var isEnabled=false,isOnDemandEnabled=false
 let connection=Connection()
 private var saved:NETunnelProviderProtocol?,savedRules:[NEOnDemandRule]?,enabled=false,onDemand=false,label:String?
 init(){connection.manager=self}
 static func loadAllFromPreferences()async throws->[NETunnelProviderManager]{await Task.yield();let action=allReadHook;allReadHook=nil;action?();return stored}
 func saveToPreferences()async throws{
  await Task.yield();Trace.saveHook?(self)
  let proto=protocolConfiguration as? NETunnelProviderProtocol
  if Trace.failMarkerSave,connection.status == .connected,connection.nodeID != "home",proto?.providerConfiguration?[IOSSpeedLabContext.ownerKey]==nil{Trace.failMarkerSave=false;throw IOSTelemetryProtocol.issue("native preference save failed")}
  if Trace.failRetireSave,connection.status == .connected,connection.nodeID=="b-fast",proto?.providerConfiguration?[IOSSpeedLabContext.ownerKey]==nil,!isOnDemandEnabled{Trace.failRetireSave=false;throw IOSTelemetryProtocol.issue("retirement save acknowledgement lost")}
  saved=proto?.copy() as? NETunnelProviderProtocol;savedRules=onDemandRules?.map{$0.copy() as! NEOnDemandRule}
  enabled=isEnabled;onDemand=isOnDemandEnabled;label=localizedDescription
  if !Self.stored.contains(where:{$0===self}){Self.stored.append(self)}
 }
 func loadFromPreferences()async throws{
  await Task.yield()
  if Trace.failMarkerRead,connection.status == .connected,connection.nodeID != "home",saved?.providerConfiguration?[IOSSpeedLabContext.ownerKey]==nil{Trace.failMarkerRead=false;throw IOSTelemetryProtocol.issue("native preference readback failed")}
  if Trace.failRetireRead,connection.status == .connected,connection.nodeID=="b-fast",saved?.providerConfiguration?[IOSSpeedLabContext.ownerKey]==nil,!onDemand{Trace.failRetireRead=false;throw IOSTelemetryProtocol.issue("retirement readback unavailable")}
  protocolConfiguration=saved?.copy() as? NETunnelProviderProtocol
  onDemandRules=savedRules?.map{$0.copy() as! NEOnDemandRule};isEnabled=enabled;isOnDemandEnabled=onDemand;localizedDescription=label
 }
}
enum IOSMAXSourceSelection{
 static func issue()->NSError{IOSTelemetryProtocol.issue("MAX unavailable in this fixture")}
 static func sourceHashes(provider:[String:Any],check:(String,String,String)throws->String)throws->[String:String]{[:]}
}
func LibboxRouterCheckMAXProfile(_ mode:String,_ assets:String,_ metadata:String,_ error:inout NSError?)->String?{nil}
enum IOSStartupPolicy{static func issue(_ value:String)->NSError{IOSTelemetryProtocol.issue(value)}}
enum IOSStartupLastChoice{static func restored(configuration:[String:Any],digest:(Data)->String)throws->IOSMultihopExecution.Capture{throw CancellationError()}}
@MainActor enum IOSSpeedLabEngine{static func run(duration:IOSSpeedLabDuration)async throws->IOSSpeedLabMeasurement{throw CancellationError()}}
@MainActor final class RouterVPNModel{
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var bundle:ClientBundle?,connected=false,tunnelTransitioning=false,iosUserDisconnectInProgress=false,iosStrategyTaskActive=false
 var activeSessionIdentity:IOSSessionIdentity?,iosConnectGeneration=UUID(),iosStrategyStatus:IOSStrategyStatus?
 var selectedLogicalMode="smart-auto",selectedMode="wg",auto=true,message="original"
 var persistedNodeBundle:ClientBundle?{UserDefaults.standard.data(forKey:"router-vpn.bundle").flatMap{try? JSONDecoder().decode(ClientBundle.self,from:$0)}}
 var profileMutationBlocked:Bool{connected || tunnelTransitioning || iosUserDisconnectInProgress}
 var activeEngine:String{activeSessionIdentity?.engine ?? "none"}
 var activeRawProfile:String{activeSessionIdentity?.rawProfile ?? ""}
 var unifiedSelectedProfile:RouterProfile?{selectedNodeProfile}
 static func iosStrategyDigest(_ data:Data)->String{SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
 func refreshTunnelStatus()async{
  await Task.yield();Trace.refreshHook?(self)
  guard let m=NETunnelProviderManager.stored.first,let p=m.protocolConfiguration as? NETunnelProviderProtocol,let c=p.providerConfiguration else{connected=false;tunnelTransitioning=false;activeSessionIdentity=nil;return}
  connected=m.connection.status == .connected;tunnelTransitioning=[.connecting,.reasserting,.disconnecting].contains(m.connection.status)
  guard connected,let date=m.connection.connectedDate,let data=c["bundle"] as? Data else{activeSessionIdentity=nil;return}
  activeSessionIdentity=try? IOSSessionIdentity(connectedAt:date,engine:c["engine"] as! String,rawProfile:c["mode"] as! String,bundleData:data,configuration:c)
 }
 func importBundle(_ data:Data)throws{
  guard iosSpeedLabOwnership.admit(.profile),!profileMutationBlocked else{throw CancellationError()}
  bundle=try JSONDecoder().decode(ClientBundle.self,from:data)
  if IOSSpeedLabContext.owner==nil{UserDefaults.standard.set(try encoded(bundle!),forKey:"router-vpn.bundle")}
 }
 func restoreIOSSpeedLabBundle(_ data:Data?)throws{
  guard let owner=IOSSpeedLabContext.owner,iosSpeedLabOwnership.mayRestoreSelection(owner),!profileMutationBlocked else{throw CancellationError()}
  if let data{try importBundle(data)}else{bundle=nil}
 }
 func iosMultihopEntryBundle(for source:ClientBundle)throws->ClientBundle{
  guard let p=IOSDNSRuntimePolicy.selectedProfile(in:source),p.multihopEnabled==true,let id=p.multihopEntryID,
        let data=IOSNodeBundleStore.shared.bundleData(containing:id,current:persistedNodeBundle)else{throw CancellationError()}
  var entry=try JSONDecoder().decode(ClientBundle.self,from:data);entry.selectedRouterID=id;return entry
 }
 func rememberIOSMultihopExecution(manager:NETunnelProviderManager,source:ClientBundle,entry:Data?,generation:UUID)async throws{throw CancellationError()}
 func connect()async{fatalError("unexpected Router selection in external comparison")}
 func connect(rawProfileID:String)async{fatalError("unexpected Router raw selection")}
 func runIOSSmartAuto()async{fatalError("unexpected AUTO reselection")}
 func runIOSCustom(layers:[String])async{fatalError("unexpected CUSTOM selection")}
 func disconnect(){guard iosSpeedLabOwnership.admit(.disconnect)else{return};iosConnectGeneration=UUID();NETunnelProviderManager.stored.first?.connection.stopVPNTunnel();connected=false;tunnelTransitioning=false;activeSessionIdentity=nil}
}
'''

TESTS = r'''
@MainActor @main struct ExternalComparisonTests{
 static var checks=0
 static func check(_ name:String,_ value:Bool){guard value else{FileHandle.standardError.write(Data(("FAIL: "+name+"\n").utf8));exit(1)};checks+=1}
 static func wait(_ name:String,_ ready:()->Bool)async{
  let end=ProcessInfo.processInfo.systemUptime+8
  while !ready() && ProcessInfo.processInfo.systemUptime<end{try? await Task.sleep(for:.milliseconds(3))}
  check("bounded progress: "+name,ready())
 }
 static func fixture(connected:Bool=true,paired:Bool=false,requested:String="local",selected:String="local",tor:Bool=false)async throws->(RouterVPNModel,NETunnelProviderManager,ClientBundle){
  Trace.reset();UserDefaults.standard.reset();IOSPrivateJSONStore.values=[:];IOSPrivateJSONStore.writes=0;IOSPrivateJSONStore.failRead=false;IOSPrivateJSONStore.failWrite=false
  IOSViaEntryNetwork.shared.current=1;IOSViaEntryNetwork.shared.hook=nil;IOSNodeBundleStore.shared.records=[:];NETunnelProviderManager.stored=[];NETunnelProviderManager.allReadHook=nil
  check("previous batch lease released",!IOSMTUMeasurementGate.held)
  let model=RouterVPNModel(),manager=NETunnelProviderManager()
  var home=ClientBundle.empty;home.routerProfiles=[try node("home")];home.selectedRouterID="home";home.endpoint="home.example"
  home=try JSONDecoder().decode(ClientBundle.self,from:encoded(home))
  IOSNodeBundleStore.shared.records["home"]=try encoded(home);model.bundle=home
  UserDefaults.standard.set(try encoded(home),forKey:"router-vpn.bundle")
  UserDefaults.standard.set(Data("original runtime choice".utf8),forKey:"router-vpn.ios.last-runtime-v1")
  for id in ["a-slow","b-fast"]{
   var external:[String:Any]=["protocol":"socks5","expected_public_ip":"203.0.113.9","socks5":["host":id+".example","port":1080,"username":"account","password":"private-"+id],"response_probe":["url":"https://198.51.100.8/response","server_name":"node.example"]]
   if tor{external=["protocol":"tor","expected_public_ip":""]}
   var profile=try node(id,external:external);profile.multihopEnabled=paired;profile.multihopExecution=requested
   profile.dnsMode="custom";profile.dnsHost="192.0.2.53";profile.dnsProtocol="udp";profile.dnsPort=53;profile.mtuPolicy="fixed";profile.manualMTU=1376
   profile.killSwitchPolicy="always";profile.homeLANAccess=false;profile.ipv6Mode="on"
   if paired{profile.multihopEntryID="home";profile.multihopExitID=id;profile.multihopEntryMode="wg";profile.multihopExitMode=tor ? "tor":"socks5"}
   var value=ClientBundle.empty;value.routerProfiles=[profile];value.selectedRouterID=id;value.endpoint=profile.endpoint
   IOSNodeBundleStore.shared.records[id]=try encoded(value)
   Trace.scores[id]=id=="a-slow" ? 30:8;Trace.winners[id]=selected
  }
  let proto=NETunnelProviderProtocol();proto.providerBundleIdentifier="com.eabusham.routervpn.PacketTunnel";proto.serverAddress="home.example"
  proto.includeAllNetworks=true;proto.enforceRoutes=true;proto.excludeLocalNetworks=false
  proto.providerConfiguration=["engine":"libbox","mode":"wg","bundle":try encoded(home)]
  manager.protocolConfiguration=proto;manager.isEnabled=true;manager.isOnDemandEnabled=connected
  let rule=NEOnDemandRuleConnect();rule.ssidMatch=["home-wifi"];manager.onDemandRules=connected ? [rule]:[];manager.localizedDescription="Original home"
  try await manager.saveToPreferences()
  if connected{try manager.connection.startVPNTunnel()}
  await model.refreshTunnelStatus()
  return(model,manager,home)
 }
 static func main()async throws{
  for connected in [false,true]{for adopt in [false,true]{
   let(model,manager,home)=try await fixture(connected:connected),client=IOSExternalNodeComparison()
   let original=try encoded(home),records=IOSNodeBundleStore.shared.records
   client.start(model:model,connectFastest:adopt);await wait("comparison"){!client.running}
   check("two complete scored paths: "+client.error+" / "+client.progress,client.rows.count==2 && client.rows.allSatisfy{$0.trimmedMeanMS != nil})
   check("common trimmed-mean ranking",client.rows.map(\.id)==["b-fast","a-slow"] && client.rows[0].trimmedMeanMS==8)
   check("one shared lease across candidate and original sessions",Trace.leases.count==1 && !IOSMTUMeasurementGate.held && !model.iosSpeedLabOwnership.active)
   check("private source records never rewritten",IOSNodeBundleStore.shared.records==records)
   check("each candidate measured exactly once",Trace.measures==["a-slow":1,"b-fast":1])
   check("temporary journal settled",!IOSSpeedLabPersistenceJournal.active)
   if adopt{
    check("explicit winner freshly connected",client.connectedWinner=="b-fast" && model.connected && model.selectedNodeProfile?.id=="b-fast" && Trace.starts["b-fast"]==2)
    check("saved winner follows exact live source",try IOSNodeUsage.canonical(model.bundle!)==UserDefaults.standard.data(forKey:"router-vpn.bundle"))
    check("native final tag removed",(manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration?[IOSSpeedLabContext.ownerKey]==nil)
    check("only successful final user connection counts",IOSNodeUsage.display(model.allNodeProfiles).profiles.first{$0.id=="b-fast"}?.useCount==1 && IOSNodeUsage.display(model.allNodeProfiles).profiles.first{$0.id=="a-slow"}?.useCount==nil)
   }else{
    check("comparison keeps original selection",UserDefaults.standard.data(forKey:"router-vpn.bundle")==original && model.selectedNodeProfile?.id=="home")
    check("comparison restores exact connected state",model.connected==connected && client.connectedWinner==nil)
    check("trials and restoration do not count usage",IOSPrivateJSONStore.values[IOSNodeUsage.filename]==nil)
   }
  }}
  for tor in [false,true]{for (requested,winner) in [("local","local"),("server","server"),("auto","local"),("auto","server")]{
   let(model,manager,_)=try await fixture(paired:true,requested:requested,selected:winner,tor:tor),client=IOSExternalNodeComparison()
   client.start(model:model,connectFastest:true);await wait("paired winner"){!client.running}
   check("paired winner is freshly adopted: "+client.error,client.connectedWinner=="b-fast" && model.connected && manager.connection.execution==winner)
   check("final restore never reruns Compare",Trace.comparisons["b-fast",default:0]==(requested=="auto" ? 1:0))
   check("saved request remains unchanged",model.selectedNodeProfile?.multihopExecution==requested && model.activeSessionIdentity?.entryMode=="wg")
   let display=IOSNodeUsage.display(model.allNodeProfiles).profiles
   check("distinct final entry and exit counted once",display.first{$0.id=="home"}?.useCount==1 && display.first{$0.id=="b-fast"}?.useCount==1 && display.first{$0.id=="a-slow"}?.useCount==nil)
   check("exact fixed policy retained",model.selectedNodeProfile?.manualMTU==1376 && model.selectedNodeProfile?.dnsHost=="192.0.2.53" && (manager.protocolConfiguration as! NETunnelProviderProtocol).includeAllNetworks && !(manager.protocolConfiguration as! NETunnelProviderProtocol).excludeLocalNetworks)
  }}
  for failure in ["partial","failed","endpoint","wrong-node","configuration","execution","missing-execution","proof"]{
   let(model,_,_)=try await fixture(),client=IOSExternalNodeComparison();Trace.scores["a-slow"]=1;Trace.failures["a-slow"]=failure
   client.start(model:model,connectFastest:true);await wait("invalid "+failure){!client.running}
   check("invalid candidate never scores: "+failure+" "+client.error,client.rows.first{$0.id=="a-slow"}?.trimmedMeanMS==nil && client.connectedWinner=="b-fast")
   check("valid alternative proves again: "+failure,Trace.starts["b-fast"]==2 && model.connected && !IOSSpeedLabPersistenceJournal.active)
  }
  do{
   let(model,_,home)=try await fixture(),client=IOSExternalNodeComparison();Trace.failures=["a-slow":"partial","b-fast":"proof"]
   client.start(model:model,connectFastest:true);await wait("neither valid"){!client.running}
   check("neither invalid candidate wins",client.rows.count==2 && client.rows.allSatisfy{$0.trimmedMeanMS==nil} && client.connectedWinner==nil)
   check("no valid winner preserves original",try model.connected && model.selectedNodeProfile?.id=="home" && UserDefaults.standard.data(forKey:"router-vpn.bundle")==encoded(home) && IOSPrivateJSONStore.values[IOSNodeUsage.filename]==nil)
  }
  do{
   let(model,_,home)=try await fixture(),client=IOSExternalNodeComparison();Trace.failures["home"]="final-proof"
   client.start(model:model,connectFastest:true);await wait("original restoration failure"){!client.running}
   check("failed original restoration never publishes candidate history",Trace.measures["a-slow"]==1 && IOSPrivateJSONStore.values[IOSExternalNodeStatistics.filename]==nil && client.rows.isEmpty && client.connectedWinner==nil)
   check("failed restoration keeps a truthful recovery receipt",try !model.connected && IOSSpeedLabPersistenceJournal.active && !client.error.isEmpty && UserDefaults.standard.data(forKey:"router-vpn.bundle")==encoded(home))
  }
  for change in ["cancel-before-task","selection-before-owner","saved-before-owner","network-before-owner"]{
   let(model,_,home)=try await fixture(),client=IOSExternalNodeComparison()
   if change != "cancel-before-task"{IOSViaEntryNetwork.shared.hook={
    if change=="selection-before-owner"{model.selectedMode="replacement";model.iosConnectGeneration=UUID()}
    if change=="saved-before-owner"{UserDefaults.standard.set(Data("replacement".utf8),forKey:"router-vpn.bundle")}
    if change=="network-before-owner"{IOSViaEntryNetwork.shared.current=nil}
   }}
   client.start(model:model,connectFastest:true);if change=="cancel-before-task"{client.cancel()}
   await wait(change){!client.running}
   check("pre-start drift does not stop original: "+change,Trace.measures.isEmpty && Trace.stops["home",default:0]==0 && model.connected && client.connectedWinner==nil)
   if change != "saved-before-owner"{check("pre-start persistence unchanged",try UserDefaults.standard.data(forKey:"router-vpn.bundle")==encoded(home))}
  }
  for change in ["cancel","network","saved-source","entry-source","selection","generation","new-profile","disconnect"]{
   let(model,_,home)=try await fixture(paired:true,requested:"auto",selected:"server"),client=IOSExternalNodeComparison()
   Trace.heldDrain=true;client.start(model:model,connectFastest:true)
   await wait("held "+change){Trace.measures["a-slow"]==1}
   check("complete undrained batch retains both owners",client.running && IOSMTUMeasurementGate.held && model.iosSpeedLabOwnership.active && IOSSpeedLabPersistenceJournal.active)
   let second=IOSExternalNodeComparison();second.start(model:model,connectFastest:false)
   check("second controller cannot take active batch",!second.running)
   switch change{
    case "cancel":client.cancel()
    case "network":IOSViaEntryNetwork.shared.current=2
    case "saved-source":var value=try JSONDecoder().decode(ClientBundle.self,from:IOSNodeBundleStore.shared.records["a-slow"]!);value.routerProfiles[0].external?.socks5?.password="new credential";IOSNodeBundleStore.shared.records["a-slow"]=try encoded(value)
    case "entry-source":var value=home;value.routerProfiles[0].apiToken="new entry credential";IOSNodeBundleStore.shared.records["home"]=try encoded(value)
    case "selection":model.bundle!.routerProfiles[0].manualMTU=9000
    case "generation":model.iosConnectGeneration=UUID()
    case "new-profile":_ = model.iosSpeedLabOwnership.admit(.profile)
    default:model.disconnect()
   }
   await wait("cancel owned probes "+change){Trace.cancels>0}
   check("cancel cannot fake native drain: "+change,client.running && IOSMTUMeasurementGate.held && model.iosSpeedLabOwnership.active && client.connectedWinner==nil)
   Trace.heldDrain=false;await wait("joined drain "+change){!client.running}
   check("cancelled cohort cannot save winner or usage: "+change,client.connectedWinner==nil && IOSPrivateJSONStore.values[IOSNodeUsage.filename]==nil && !IOSMTUMeasurementGate.held)
   check("drained cancellation retains saved initial bytes: "+change,try UserDefaults.standard.data(forKey:"router-vpn.bundle")==encoded(home))
   if change=="disconnect"{check("user disconnect is not undone",!model.connected)}
   else if change != "new-profile"{check("ordinary cancellation freshly restores original",model.connected && model.selectedNodeProfile?.id=="home")}
  }
  for failure in ["final-proof","marker-save","marker-read","selection-sync","clear-sync","cancel-before-commit","release","usage"]{
   let(model,manager,home)=try await fixture(),client=IOSExternalNodeComparison()
   if failure=="final-proof"{Trace.failures["b-fast"]=failure}
   if failure=="marker-save"{Trace.failMarkerSave=true}
   if failure=="marker-read"{Trace.failMarkerRead=true}
   if ["release","usage"].contains(failure){Trace.saveHook={m in
    if m.connection.nodeID=="b-fast",m.connection.status == .connected,(m.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[IOSSpeedLabContext.ownerKey]==nil{
     if failure=="release"{Trace.failRelease=true}else{IOSPrivateJSONStore.failWrite=true}
    }
   }}
   if ["selection-sync","clear-sync","cancel-before-commit"].contains(failure){UserDefaults.standard.writeHook={key,value in
    let selected=UserDefaults.standard.data(forKey:"router-vpn.bundle").flatMap{try? JSONDecoder().decode(ClientBundle.self,from:$0).selectedRouterID}
    if selected=="b-fast",(key=="router-vpn.bundle" && failure=="selection-sync" || key=="router-vpn.speed-lab-journal-v1" && value==nil && failure != "selection-sync"){
     UserDefaults.standard.writeHook=nil
     if failure=="cancel-before-commit"{client.cancel()}else{UserDefaults.standard.failSync=1}
    }
   }}
   client.start(model:model,connectFastest:true);await wait(failure){!client.running}
   if ["release","usage"].contains(failure){
    check("committed winner survives optional cleanup failure: "+failure,model.connected && model.selectedNodeProfile?.id=="b-fast" && client.connectedWinner=="b-fast" && Trace.stops["b-fast"]==1)
    check("committed selection is durable despite warning",try UserDefaults.standard.data(forKey:"router-vpn.bundle")==encoded(model.bundle!) && !IOSSpeedLabPersistenceJournal.active)
    if failure=="release"{check("release warning reports committed state",client.error.contains("committed") && client.error.contains("cleanup"))}
    else{check("usage failure remains optional and visible",model.message.contains("usage history could not be saved") && IOSPrivateJSONStore.values[IOSNodeUsage.filename]==nil)}
   }else{
    check("failed adoption is never called successful: "+failure+" "+client.error,client.connectedWinner==nil && !client.error.isEmpty)
    check("failed adoption restores original source: "+failure,try model.connected && model.selectedNodeProfile?.id=="home" && manager.connection.nodeID=="home" && UserDefaults.standard.data(forKey:"router-vpn.bundle")==encoded(home))
    check("failed adoption settles original receipt without usage: "+failure,!IOSSpeedLabPersistenceJournal.active && IOSPrivateJSONStore.values[IOSNodeUsage.filename]==nil)
   }
  }
  for drift in ["decision","source","network","entry","entry-mode","route","extra-config","description"]{
   let(model,manager,home)=try await fixture(paired:true,requested:"auto",selected:"server"),client=IOSExternalNodeComparison()
   var injected=false
   Trace.infoHook={connection in
    guard !injected,connection.nodeID=="b-fast",Trace.starts["b-fast"]==2 else{return}
    injected=true
    if drift=="decision"{model.iosConnectGeneration=UUID()}
    else if drift=="source"{model.bundle!.routerProfiles[0].dnsHost="192.0.2.54"}
    else if drift=="network"{IOSViaEntryNetwork.shared.current=2}
    else{NETunnelProviderManager.allReadHook={
     let proto=manager.protocolConfiguration as! NETunnelProviderProtocol
     if drift=="entry"{proto.providerConfiguration?["external_entry_bundle"]=Data("different exact entry".utf8)}
     if drift=="entry-mode"{proto.providerConfiguration?["external_entry_mode"]="shadowsocks"}
     if drift=="route"{proto.excludeLocalNetworks=true}
     if drift=="extra-config"{proto.providerConfiguration?["unrequested-policy"]="changed"}
     if drift=="description"{manager.localizedDescription="Different native source"}
    }}
   }
   client.start(model:model,connectFastest:true);await wait("post-proof "+drift){!client.running}
   check("post-proof drift cannot gain adoption: "+drift+" "+client.error,injected && client.connectedWinner==nil && !client.error.isEmpty)
   check("post-proof drift keeps original preference: "+drift,try UserDefaults.standard.data(forKey:"router-vpn.bundle")==encoded(home) && IOSPrivateJSONStore.values[IOSNodeUsage.filename]==nil)
  }
  for field in ["enabled","on-demand","rules","description","during-retirement"]{
   let(model,manager,home)=try await fixture(),client=IOSExternalNodeComparison();var changed=false
   Trace.saveHook={m in
    guard !changed,m.connection.nodeID=="b-fast",m.connection.status == .connected,
          (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[IOSSpeedLabContext.ownerKey]==nil else{return}
    if field=="during-retirement",m.isOnDemandEnabled{return}
    changed=true
    if field=="enabled"{m.isEnabled=false}
    if field=="on-demand"{m.isOnDemandEnabled=false;m.onDemandRules=[]}
    if field=="rules"{let rule=NEOnDemandRuleConnect();rule.ssidMatch=["new-policy-owner"];m.onDemandRules=[rule]}
    if field=="description" || field=="during-retirement"{m.localizedDescription="New native policy"}
   }
   if field=="during-retirement"{UserDefaults.standard.writeHook={key,value in
    if key=="router-vpn.bundle",let value,(try? JSONDecoder().decode(ClientBundle.self,from:value).selectedRouterID)=="b-fast"{UserDefaults.standard.writeHook=nil;UserDefaults.standard.failSync=1}
   }}
   client.start(model:model,connectFastest:true);await wait("foreign retirement policy "+field){!client.running}
   check("new native policy is never retired: "+field,changed && model.connected && manager.connection.nodeID=="b-fast" && Trace.stops["b-fast"]==1 && client.connectedWinner==nil)
   check("unsettled new native policy retains recovery: "+field,try IOSSpeedLabPersistenceJournal.active && client.error.contains("recovery remains pending") && UserDefaults.standard.data(forKey:"router-vpn.bundle")==encoded(home) && IOSPrivateJSONStore.values[IOSNodeUsage.filename]==nil)
   if field=="enabled"{check("new enable flag preserved",!manager.isEnabled)}
   if field=="on-demand"{check("unowned empty reconnect image not adopted",!manager.isOnDemandEnabled && (manager.onDemandRules ?? []).isEmpty)}
   if field=="rules"{check("new reconnect rule preserved",manager.onDemandRules?.first?.ssidMatch==["new-policy-owner"])}
   if field=="description" || field=="during-retirement"{check("new native description preserved",manager.localizedDescription=="New native policy")}
  }
  for boundary in ["save","read"]{
   let(model,_,home)=try await fixture(),client=IOSExternalNodeComparison()
   if boundary=="save"{Trace.failRetireSave=true}else{Trace.failRetireRead=true}
   UserDefaults.standard.writeHook={key,value in
    if key=="router-vpn.bundle",let value,(try? JSONDecoder().decode(ClientBundle.self,from:value).selectedRouterID)=="b-fast"{UserDefaults.standard.writeHook=nil;UserDefaults.standard.failSync=1}
   }
   client.start(model:model,connectFastest:true);await wait("owned retirement retry "+boundary){!client.running}
   check("own partial retirement remains retryable: "+boundary,try model.connected && model.selectedNodeProfile?.id=="home" && UserDefaults.standard.data(forKey:"router-vpn.bundle")==encoded(home) && !IOSSpeedLabPersistenceJournal.active && client.connectedWinner==nil)
   check("retry never stops another native owner",Trace.stops["b-fast"]==2 && IOSPrivateJSONStore.values[IOSNodeUsage.filename]==nil)
  }
  do{
   let(model,manager,home)=try await fixture(),client=IOSExternalNodeComparison()
   var replaced=false
   Trace.saveHook={m in
    guard !replaced,m.connection.nodeID=="b-fast",m.connection.status == .connected,(m.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[IOSSpeedLabContext.ownerKey]==nil else{return}
    replaced=true;_ = model.iosSpeedLabOwnership.admit(.profile)
    var other=home;other.selectedRouterID="replacement";other.routerProfiles[0].id="replacement"
    model.bundle=other;model.iosConnectGeneration=UUID()
    UserDefaults.standard.set(try! encoded(other),forKey:"router-vpn.bundle")
    let proto=NETunnelProviderProtocol();proto.providerBundleIdentifier="com.eabusham.routervpn.PacketTunnel";proto.serverAddress="replacement.example"
    proto.providerConfiguration=["engine":"libbox","mode":"wg","bundle":try! encoded(other)]
    m.protocolConfiguration=proto;try! m.connection.startVPNTunnel()
    model.activeSessionIdentity=try! IOSSessionIdentity(connectedAt:m.connection.connectedDate!,engine:"libbox",rawProfile:"wg",bundleData:try! encoded(other),configuration:proto.providerConfiguration!)
   }
   client.start(model:model,connectFastest:true);await wait("replacement native"){!client.running}
   check("replacement native session is never stopped",replaced && model.connected && manager.connection.nodeID=="replacement" && Trace.stops["replacement",default:0]==0)
   check("replacement preference is never overwritten",model.persistedNodeBundle?.selectedRouterID=="replacement" && client.connectedWinner==nil && IOSPrivateJSONStore.values[IOSNodeUsage.filename]==nil)
  }
  do{
   let(model,manager,_)=try await fixture(),client=IOSExternalNodeComparison()
   var replaced=false
   UserDefaults.standard.syncHook={
    guard !replaced,Trace.measures["a-slow"]==1,Trace.measures["b-fast"]==nil,manager.connection.nodeID=="home",manager.connection.status == .connected,!IOSSpeedLabPersistenceJournal.active else{return}
    replaced=true;try! manager.connection.startVPNTunnel()
    let p=manager.protocolConfiguration as! NETunnelProviderProtocol,c=p.providerConfiguration!
    model.activeSessionIdentity=try! IOSSessionIdentity(connectedAt:manager.connection.connectedDate!,engine:"libbox",rawProfile:"wg",bundleData:c["bundle"] as! Data,configuration:c)
   }
   client.start(model:model,connectFastest:true);await wait("original reconnect after proof"){!client.running}
   check("renewed original cannot become refreshed baseline",replaced && Trace.measures["b-fast"]==nil && client.connectedWinner==nil && !client.error.isEmpty)
   check("post-proof replacement original is left running",model.connected && manager.connection.nodeID=="home" && Trace.stops["home"]==1)
  }
  for shared in [false,true]{
   let(model,_,_)=try await fixture(),client=IOSExternalNodeComparison()
   let padding=String(repeating:"x",count:18*1024*1024)
   var first=try JSONDecoder().decode(ClientBundle.self,from:IOSNodeBundleStore.shared.records["a-slow"]!)
   var second=try JSONDecoder().decode(ClientBundle.self,from:IOSNodeBundleStore.shared.records["b-fast"]!)
   first.profiles=["unused-private-assets":["retained":padding]]
   if shared{
    first.routerProfiles+=second.routerProfiles;IOSNodeBundleStore.shared.records.removeValue(forKey:"b-fast")
   }else{
    second.profiles=["unused-private-assets":["retained":padding]];IOSNodeBundleStore.shared.records["b-fast"]=try encoded(second)
   }
   IOSNodeBundleStore.shared.records["a-slow"]=try encoded(first)
   if shared{
    let captured=try IOSExternalComparisonCohort(model:model)
    check("shared source is captured once within aggregate bound",captured.candidates.count==2 && Trace.stops["home",default:0]==0 && !model.iosSpeedLabOwnership.active)
   }else{
    client.start(model:model,connectFastest:false)
    check("aggregate overflow rejects before any mutation",!client.running && client.error.contains("64 MiB") && Trace.stops["home",default:0]==0 && Trace.measures.isEmpty && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
   }
  }
  print("Apple external comparison: PASS (\(checks) shipping lifecycle checks; native/system/storage boundaries doubled)")
 }
}
'''


def declaration(source, marker):
    return tunnel.declaration(source, marker)


def source():
    text = usage.BOUNDARY.split("@main struct Tests", 1)[0]
    # Exact native protocol/rule copying is shared with the existing restoration
    # suite. The new system boundary below additionally exposes IPC and storage.
    text += tunnel.SHIM.split("@MainActor final class Connection", 1)[0]
    text += BOUNDARY
    external = (APP / "RouterVPNModelExternal.swift").read_text()
    declarations = ["var allNodeProfiles:", "var selectedNodeProfile:", "var selectedNodeIsExternal:",
                    "var selectedExternalProtocol:", "var selectedExternalSupportedOnIOS:",
                    "func nodeRuntimeSummary(", "func selectNode(",
                    "func connectSelectedExternal()", "func connectSelectedExternal(startupAdmission:",
                    "private func requireExternalPreparation(", "func externalTorEntryData(",
                    "func externalRuntimeBundleData(", "private func externalStrict(", "private func waitExternalConnection("]
    text += "\nextension RouterVPNModel {\n" + "\n".join(declaration(external, key) for key in declarations) + "\n}\n"
    capture = (APP / "IOSDNSMeasurementClient.swift").read_text()
    text += capture[capture.index("@MainActor struct IOSDNSMeasurementCapture"):capture.index("private final class IOSDNSMeasurementReply")]
    # Imported capture validation calls the actual Start Layer declaration.
    # Keep its conditional CryptoKit import outside the fixture import stripping.
    text += "\n" + (APP / "IOSMultihopStartLayer.swift").read_text()
    for name in ("Models.swift", "IOSSessionIdentity.swift", "IOSNodeLatencyStatistics.swift", "IOSNodeUsage.swift", "IOSNodeUsageAccounting.swift",
                 "IOSMultihopExecution.swift", "IOSSpeedLabOwnership.swift", "IOSMTUMeasurementGate.swift",
                 "IOSMTUControl.swift", "IOSSpeedLabPersistenceJournal.swift", "IOSSpeedLabTunnel.swift",
                 "IOSSpeedLabRunner.swift", "IOSExternalNodeStatistics.swift", "IOSExternalNodeBenchmark.swift",
                 "IOSExternalNodeComparison.swift"):
        text += "\n" + (APP / name).read_text().replace("import Combine\n", "").replace("@preconcurrency import NetworkExtension\n", "").replace("import CryptoKit\n", "")
    text += (APP / "IOSStrategySession.swift").read_text().split("#if canImport(NetworkExtension)", 1)[0]
    text += (APP / "IOSSpeedLab.swift").read_text().split("// One shared HTTP policy", 1)[0].replace("import Security", "")
    text += (APP / "IOSHopMeasurements.swift").read_text().split("\nstruct IOSHopMeasurementsCard:", 1)[0].replace("import SwiftUI", "import Foundation").replace("@preconcurrency import NetworkExtension", "")
    return text + TESTS


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc is required for actual Apple comparison lifecycle checks")
    text = source()
    with tempfile.TemporaryDirectory(prefix="routervpn-ios-external-comparison-") as directory:
        work = Path(directory)
        code, binary = work / "Fixture.swift", work / "fixture"
        code.write_text(text)
        command = [swift, "-swift-version", "6", "-strict-concurrency=complete", "-parse-as-library",
                   "-module-cache-path", str(work / "modules"), str(code), "-o", str(binary)]
        subprocess.run(command, check=True, timeout=180)
        subprocess.run([str(binary)], check=True, timeout=100)
        controls = [
            ("captured retirement policy", "try requireCapturedPolicy?()", "", 1,
             "new native policy is never retired: during-retirement"),
            ("publication after original restoration", "requested: requested, saveResult: false, validate:",
             "requested: requested, saveResult: true, validate:", 1,
             "failed original restoration never publishes candidate history"),
            ("latched user selection", "try cohort.observeSelection(choice, model: model)", "", 2,
             "cancelled cohort cannot save winner or usage: selection"),
            ("exact freshly proved preference", "sameProtocol(proto, frozen), manager.isEnabled == expected.savedEnabled,",
             "manager.isEnabled == expected.savedEnabled,", 1, "post-proof drift cannot gain adoption: entry"),
            ("native terminal restoration receipt", "try IOSSpeedLabPersistenceJournal.finish()\n        try requireNative()",
             "try IOSSpeedLabPersistenceJournal.finish()", 1, "renewed original cannot become refreshed baseline"),
            ("retained execution without Compare", 'options[IOSMultihopExecution.launchKey] = String(decoding: try multihopExecution.encoded(), as: UTF8.self) as NSString',
             "_ = multihopExecution", 1, "final restore never reruns Compare"),
        ]
        for name, before, after, count, expected in controls:
            if text.count(before) != count:
                raise AssertionError("comparison control lost its exact source boundary: " + name)
            code.write_text(text.replace(before, after))
            subprocess.run(command, check=True, timeout=180)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=100)
            if result.returncode == 0 or expected not in result.stderr:
                raise AssertionError(name + " did not reject the intended defect: " + result.stderr[-1800:])
            print("PASS comparison negative control:", name, flush=True)
    view = (APP / "IOSUnifiedProductView.swift").read_text()
    for required in ("Compare all external nodes", "Compare & connect fastest external", "connectFastest: false",
                     "connectFastest: true", "its own saved entry, DNS and device policy", "externalComparison.cancel()"):
        if required not in view:
            raise AssertionError("comparison UI lost its explicit operation/ownership contract: " + required)


if __name__ == "__main__":
    main()
