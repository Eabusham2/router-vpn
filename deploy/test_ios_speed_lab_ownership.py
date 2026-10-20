#!/usr/bin/env python3
"""Execute the shipping Apple Speed Lab user-intent lease, including late tasks."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
SWIFT = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ text:String,_ value:@autoclosure()->Bool){guard value()else{fatalError("FAIL: "+text)};checks+=1}
 static func main()async throws {
  let owner=IOSSpeedLabOwnership();var invalidations=0
  check("ordinary connection remains available",owner.admit(.connection))
  let first=try owner.begin{invalidations+=1}
  do{_ = try owner.begin{};fatalError("concurrent Speed Lab owner accepted")}catch{}
  try await IOSSpeedLabContext.$owner.withValue(first){
   check("captured test can connect",owner.admit(.connection))
   var config:[String:Any]=["bundle":Data("exact-private-source".utf8)]
   IOSSpeedLabContext.mark(&config)
   check("owned runtime is tagged without changing source",config[IOSSpeedLabContext.ownerKey] as? String==first.uuidString && config["bundle"] as? Data==Data("exact-private-source".utf8))
   let inherited=Task{@MainActor in owner.admit(.profile)}
   let accepted=await inherited.value
   check("captured task inherits lease",accepted)
   try owner.require(first)
  }
  check("user Disconnect accepted while test between paths",owner.admit(.disconnect))
  check("Disconnect revokes reconnect but retains selection cleanup",!owner.current(first) && owner.mayRestoreSelection(first) && invalidations==1)
  IOSSpeedLabContext.$owner.withValue(first){
   check("late preparation cannot restart",!owner.admit(.connection))
   check("late profile mutation rejected",!owner.admit(.profile))
   check("late owned Disconnect cannot stop a replacement",!owner.admit(.disconnect))
   IOSSpeedLabContext.$restoringSelection.withValue(true){
    check("idle cleanup may restore only selected data",owner.admit(.profile) && !owner.admit(.connection))
   }
  }
  check("new user selection accepted",owner.admit(.profile))
  check("new selection cancels original preference restoration",!owner.mayRestoreSelection(first))
  owner.finish(UUID());check("foreign finalizer cannot release transaction",!owner.admitOwnTest(first))
  owner.finish(first)
  let second=try owner.begin{invalidations+=1}
  owner.finish(first);check("old finalizer cannot release replacement",owner.current(second))
  check("new Home Connect supersedes old test",owner.admit(.connection))
  check("superseded test cannot overwrite idle or new connection",!owner.current(second) && !owner.mayRestoreSelection(second))
  _=owner.admit(.disconnect);check("later Disconnect does not erase newer-selection protection",!owner.mayRestoreSelection(second))
  owner.finish(second)
  for newerDisconnect in [false,true] {
   let third=try owner.begin{invalidations+=1};var returned=false
   let waiting=Task{let accepted=await owner.admitConnection();returned=true;return accepted}
   try await Task.sleep(for:.milliseconds(5))
   check("new Home connection waits for actual retirement",!returned && !owner.current(third) && owner.owns(third))
   if newerDisconnect {_=owner.admit(.disconnect)}
   owner.finish(third)
   let accepted=await waiting.value
   check("waiting connection observes newer Disconnect",accepted == !newerDisconnect)
  }
  print("Apple Speed Lab task/user ownership: PASS (\(checks) shipping Swift checks)")
 }
}
extension IOSSpeedLabOwnership {
 @MainActor func admitOwnTest(_ owner:UUID)->Bool {
  IOSSpeedLabContext.$owner.withValue(owner){admit(.connection)}
 }
}
'''

def main():
    swift=shutil.which('swiftc')
    if not swift: raise SystemExit('swiftc required')
    with tempfile.TemporaryDirectory(prefix='routervpn-speed-owner-') as folder:
        path=Path(folder)/'test.swift';binary=Path(folder)/'test'
        path.write_text((APP/'IOSSpeedLabOwnership.swift').read_text()+'\n'+SWIFT)
        subprocess.run([swift,'-swift-version','6','-parse-as-library',str(path),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=20)
    for filename,signature,action in [
        ('RouterVPNModel.swift','func connect(rawProfileID:', 'connection'),
        ('RouterVPNModel.swift','func disconnect()', 'disconnect'),
        ('RouterVPNModel.swift','func importBundle(', 'profile'),
        ('RouterVPNModel.swift','func saveRouter()', 'profile'),
        ('RouterVPNModelExternal.swift','func connectSelectedExternal()', 'connection'),
        ('RouterVPNModelExternal.swift','func selectNode(', 'profile'),
        ('RouterVPNModelExternal.swift','func linkNodeBundle(', 'profile'),
        ('IOSOwnedStrategy.swift','func runIOSOwnedStrategy(', 'connection'),
        ('IOSStrategySupport.swift','func runIOSSmartAuto()', 'connection'),
        ('IOSStrategySupport.swift','func runIOSCustom(', 'connection'),
    ]:
        body=(APP/filename).read_text().split(signature,1)[1].split('{',1)[1]
        required='guard await iosSpeedLabOwnership.admitConnection()' if action=='connection' else 'guard iosSpeedLabOwnership.admit(.'+action+')'
        assert body.lstrip().startswith(required),(filename,signature)
    external=(APP/'RouterVPNModelExternal.swift').read_text()
    assert 'let hold = IOSMTUMeasurementGate.current' in external
    assert '"routervpn_mtu_hold": hold as NSString' in external
    assert 'startVPNTunnel(options: options)' in external
    for name in ['RouterVPNModel.swift','RouterVPNModelExternal.swift','IOSOwnedStrategy.swift']:
        assert 'IOSSpeedLabContext.mark(&' in (APP/name).read_text(),name
    print('All production mutation entries and external/Tor startup MTU hold are wired')

if __name__=='__main__':main()
