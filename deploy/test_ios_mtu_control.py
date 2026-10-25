#!/usr/bin/env python3
"""Run production MTU IPC/measurement ownership; NetworkExtension is doubled."""
from pathlib import Path
import os,platform,resource,shutil,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
STUB=r"""
import Foundation
public enum NEVPNStatus {case connected,disconnected}
public class NEVPNProtocol {}
public class NETunnelProviderProtocol:NEVPNProtocol {public var providerBundleIdentifier:String?}
public class NEVPNConnection {
 public var status=NEVPNStatus.connected
 public var connectedDate:Date?=Date(timeIntervalSince1970:123)
}
public enum Fixture {
 nonisolated(unsafe) public static var wrongAck=false
 nonisolated(unsafe) public static var wrongSession=false
 nonisolated(unsafe) public static var changeConnection=false
 nonisolated(unsafe) public static var ready=true
 nonisolated(unsafe) public static var failCommand=false
 nonisolated(unsafe) public static var lease=""
 nonisolated(unsafe) public static var releases=0
 nonisolated(unsafe) public static var messages=0
 nonisolated(unsafe) public static var session=UUID().uuidString
 nonisolated(unsafe) public static var managers:[NETunnelProviderManager]=[NETunnelProviderManager()]
}
public final class NETunnelProviderSession:NEVPNConnection {
 public func sendProviderMessage(_ data:Data,responseHandler:((Data?)->Void)?)throws {
  Fixture.messages += 1
  let query=try JSONSerialization.jsonObject(with:data) as! [String:String]
  let request=query["request_id"]!,operation=query["operation"]!
  if operation=="mtu-hold" {
   if !Fixture.lease.isEmpty && Fixture.lease != request {responseHandler?(nil);return}
   Fixture.lease=request
  }
  if operation=="mtu-release" {
   if Fixture.lease != request {responseHandler?(nil);return}
   Fixture.lease="";Fixture.releases += 1
  }
  if Fixture.changeConnection {connectedDate=Date(timeIntervalSince1970:456)}
  var body:[String:Any]=["session_id":Fixture.wrongSession && !(query["session_id"] ?? "").isEmpty ? UUID().uuidString : Fixture.session,
   "ack_id":Fixture.wrongAck ? "wrong" : request,"measurement_hold":!Fixture.lease.isEmpty,
   "measurement_lease":Fixture.lease,"measurement_ready":Fixture.ready]
  if Fixture.failCommand {body["command_failure"]="fixture command rejected"}
  responseHandler?(try JSONSerialization.data(withJSONObject:body))
 }
}
public final class NETunnelProviderManager {
 public var protocolConfiguration:NEVPNProtocol?
 public var connection:NEVPNConnection=NETunnelProviderSession()
 public init(){let p=NETunnelProviderProtocol();p.providerBundleIdentifier="com.eabusham.routervpn.PacketTunnel";protocolConfiguration=p}
 public static func loadAllFromPreferences()async throws->[NETunnelProviderManager]{Fixture.managers}
}
"""
TEST=r"""
import Foundation
import NetworkExtension
@MainActor final class RouterVPNModel {
 var connected=true
 var activeEngine="libbox"
 var activeSessionIdentity:IOSSessionIdentity?=try! IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:123),engine:"libbox",rawProfile:"shadowsocks",bundleData:Data("owned".utf8),entryBundleData:nil)
 var startupAllowed=true
 var refreshHook:(()->Void)?
 func refreshTunnelStatus()async{refreshHook?()}
}
@main struct Tests {
 @MainActor static func main()async throws{
  var checks=0
  func check(_ value:Bool,_ label:String){checks += 1;if !value{fatalError(label)}}
  func reject(_ label:String,_ action:()async throws->Void)async{do{try await action();fatalError(label)}catch{checks += 1}}
  let model=RouterVPNModel()
  let binding=try await IOSMTUControl.capture(model)
  check(binding.session==Fixture.session,"initial session handshake failed")
  check(IOSMTUControl.retestTimeout(binding)==55,"ordinary native MTU timeout changed")
  for raw in ["external-tor","external-tor-bridge","external-socks5"] {
   let identity=try IOSSessionIdentity(connectedAt:binding.connectedDate,engine:"external-libbox",rawProfile:raw,bundleData:Data("captured".utf8),entryBundleData:nil)
   let captured=IOSMTUControl.Binding(connection:binding.connection,connectedDate:binding.connectedDate,identity:identity,session:binding.session)
   check(IOSMTUControl.retestTimeout(captured)==(raw=="external-socks5" ? 55:270),"Tor native proof budget was truncated or granted to another path")
  }
  let liveIdentity=model.activeSessionIdentity
  model.activeSessionIdentity=try IOSSessionIdentity(connectedAt:binding.connectedDate,engine:"external-libbox",rawProfile:"external-tor",bundleData:Data("new selection".utf8),entryBundleData:nil)
  check(IOSMTUControl.retestTimeout(binding)==55,"mutable selection changed a captured measurement deadline")
  model.activeSessionIdentity=liveIdentity
  let id=String(repeating:"c",count:32)
  _ = try await IOSMTUControl.message(binding,model:model,operation:"mtu-status",request:id)
  check(IOSMTUControl.current(binding,model:model),"owned tunnel unexpectedly stale")
  Fixture.wrongAck=true
  await reject("mismatched acknowledgement accepted"){_ = try await IOSMTUControl.message(binding,model:model,operation:"mtu-status",request:id)}
  Fixture.wrongAck=false;Fixture.wrongSession=true
  await reject("foreign native session reply accepted"){_ = try await IOSMTUControl.message(binding,model:model,operation:"mtu-status",request:id)}
  Fixture.wrongSession=false;Fixture.failCommand=true
  await reject("command failure ignored"){_ = try await IOSMTUControl.message(binding,model:model,operation:"mtu-start",request:id)}
  Fixture.failCommand=false;Fixture.changeConnection=true
  await reject("same-node reconnect accepted"){_ = try await IOSMTUControl.message(binding,model:model,operation:"mtu-status",request:id)}
  Fixture.changeConnection=false;Fixture.managers=[NETunnelProviderManager(),NETunnelProviderManager()]
  await reject("ambiguous VPN managers accepted"){_ = try await IOSMTUControl.capture(model)}
  Fixture.managers=[NETunnelProviderManager()]
  let current=try await IOSMTUControl.capture(model)
  model.connected=false
  await reject("disconnected owner accepted"){_ = try await IOSMTUControl.message(current,model:model,operation:"mtu-status",request:id)}
  model.connected=true
  let saved=model.activeSessionIdentity;model.activeSessionIdentity=nil
  await reject("unverified identity accepted"){_ = try await IOSMTUControl.capture(model)}
  model.activeSessionIdentity=saved
  let beforeStartupMessages=Fixture.messages
  model.refreshHook={model.startupAllowed=false}
  await reject("retired startup admitted MTU hold after status refresh"){
   try await IOSSpeedLabContext.$startupAdmission.withValue({model.startupAllowed}){
    try await IOSMTUControl.holdCurrent(model,request:id)
   }
  }
  check(Fixture.messages==beforeStartupMessages && Fixture.lease.isEmpty,"retired startup touched the current native owner")
  model.refreshHook=nil;model.startupAllowed=true
  let releases=Fixture.releases
  let result:Int=try await IOSMTUControl.withHold(model:model){
   check(IOSMTUMeasurementGate.held && !Fixture.lease.isEmpty,"measurement entered without native hold")
   return try await IOSMTUControl.withHold(model:model){
    check(IOSMTUMeasurementGate.current==Fixture.lease,"nested selection got another lease")
    return 17
   }
  }
  check(result==17 && !IOSMTUMeasurementGate.held && Fixture.lease.isEmpty && Fixture.releases==releases+1,"final lease cleanup failed")
  await reject("measurement error swallowed"){
   try await IOSMTUControl.withHold(model:model){throw NSError(domain:"fixture",code:1)}
  }
  check(!IOSMTUMeasurementGate.held && Fixture.lease.isEmpty,"error leaked measurement hold")
  Fixture.ready=false
  let cancelled=Task<Int,Error>{@MainActor in
   try await IOSMTUControl.withHold(model:model){check(false,"undrained MTU reached throughput test");return 0}
  }
  try await Task.sleep(for:.milliseconds(150))
  check(!Fixture.lease.isEmpty,"cancellation test did not acquire its native hold")
  cancelled.cancel()
  _ = await cancelled.result
  check(!IOSMTUMeasurementGate.held && Fixture.lease.isEmpty,"cancellation leaked native comparison lease")
  Fixture.ready=true;model.activeEngine="wireguard"
  let raw=try await IOSMTUControl.withHold(model:model){42}
  check(raw==42 && !IOSMTUMeasurementGate.held,"nonadaptive WireGuardKit path mislabeled or blocked")
  print("Production Swift MTU IPC/isolation: PASS (\(checks) checks; NetworkExtension boundary doubled)")
 }
}
"""
def verify_startup_holds(provider):
    sections=(('startMultihop(', 'multihopWireGuardEndpoint('),
              ('startLibbox(', 'performanceFiles('),
              ('startExternalLibbox(', 'selectedRouterProfile('))
    for start, end in sections:
        begin=provider.index('    private func '+start)
        finish=provider.index('    private func '+end,begin)
        body=provider[begin:finish]
        assert body.count('try engine.prepareMTUHold(initialMTUHold)')==1, start+' lost startup MTU hold'
        assert body.index('try engine.prepareMTUHold(initialMTUHold)') < body.index('engine.start('), start+' starts before holding MTU'

provider=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
client=(ROOT/'ios/RouterVPN/App/IOSMTUClient.swift').read_text()
assert 'ProcessInfo.processInfo.systemUptime + IOSMTUControl.retestTimeout(captured)' in client, 'Retest must honor its captured native runtime budget'
assert 'ProcessInfo.processInfo.systemUptime + 55' not in client, 'Legacy UI timeout truncates Tor final proof'
raw=provider[provider.index('        let requestedMode ='):provider.index('    private func startMultihop(')]
assert raw.index('!RouterVPNMTUPolicy.requiresAdaptiveOwner(profile: selectedProfile)') < raw.index('WireGuardAdapter(with: self)')

verify_startup_holds(provider)
for index in range(3):
    marker='try engine.prepareMTUHold(initialMTUHold)'
    before, after=provider.split(marker,index+1)[:-1],provider.split(marker,index+1)[-1]
    mutant=marker.join(before)+'// missing comparison hold'+after
    try:verify_startup_holds(mutant)
    except AssertionError:pass
    else:raise AssertionError('Startup-hold negative control was accepted: '+str(index))
print('Every native Apple startup holds MTU before launch; all three missing-hold controls rejected.')

with tempfile.TemporaryDirectory(prefix='routervpn-mtu-control-') as directory:
 tmp=Path(directory);(tmp/'NetworkExtension.swift').write_text(STUB);(tmp/'Harness.swift').write_text(TEST)
 swift=shutil.which('swiftc')
 if not swift:raise SystemExit('swiftc required; no skipped ownership tests')
 ext='dylib' if platform.system()=='Darwin' else 'so'
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def run(args,broken=False):
  result=subprocess.run(args,cwd=tmp,check=False,timeout=90,text=True,capture_output=True)
  if broken:
   assert result.returncode!=0 and 'retired startup admitted MTU hold after status refresh' in result.stdout+result.stderr, 'Startup-admission negative did not reach its executable assertion: '+result.stdout+result.stderr
  elif result.returncode:
   raise RuntimeError(result.stdout+result.stderr)
  elif result.stdout:print(result.stdout,end='')
 compiler=[swift,'-swift-version','6','-module-cache-path',str(tmp/'module-cache')]
 run(compiler+['-emit-module','-emit-library','-module-name','NetworkExtension',str(tmp/'NetworkExtension.swift'),'-o',str(tmp/('libNetworkExtension.'+ext))])
 app=ROOT/'ios/RouterVPN/App'
 inputs=compiler+['-I',str(tmp),'-L',str(tmp),'-lNetworkExtension','-Xlinker','-rpath','-Xlinker',str(tmp),str(app/'IOSMTUControl.swift'),str(app/'IOSMTUMeasurementGate.swift'),str(app/'IOSSessionIdentity.swift'),str(app/'IOSSpeedLabOwnership.swift'),str(tmp/'Harness.swift'),'-o',str(tmp/'test')]
 run(inputs)
 run([str(tmp/'test')])
 original=(app/'IOSMTUControl.swift').read_text()
 marker='guard startup() else { throw CancellationError() }'
 assert original.count(marker)==1
 mutated=tmp/'IOSMTUControl.swift';mutated.write_text(original.replace(marker,'guard true else { throw CancellationError() }',1))
 run([str(mutated) if value==str(app/'IOSMTUControl.swift') else value for value in inputs])
 run([str(tmp/'test')],broken=True)
 print('Retired startup MTU-admission executable negative rejected.')
