#!/usr/bin/env python3
"""Execute captured Apple startup budgets and the shipping connection wait.

Only NetworkExtension and monotonic scheduling are doubles. Neither the actual
wait method nor its policy is rewritten; no device or encrypted path is claimed.
"""
from pathlib import Path
import importlib.util
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('startup_members', ROOT/'deploy/test_ios_startup_policy.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

BOUNDARIES = r'''
import Foundation
@MainActor enum Clock {static var time=0.0;static var change:(()->Void)?;static func reset(){time=0;change=nil;Task.isCancelled=false}}
@MainActor struct ProcessInfo {static let processInfo=ProcessInfo();var systemUptime:Double{Clock.time}}
@MainActor enum Task {static var isCancelled=false;static func sleep(for duration:Duration)async throws{Clock.time+=0.25;Clock.change?()}}
enum Status{case connected,invalid,disconnected,disconnecting,connecting,reasserting}
@MainActor final class Connection{var ready=31.0;var terminal:Status?;var status:Status{terminal ?? (Clock.time>=ready ? .connected:.connecting)}}
@MainActor final class NETunnelProviderManager{let connection=Connection()}
@MainActor final class Model{var iosConnectGeneration=UUID();var userDisconnectInProgress=false
// ACTUAL_WAIT
func wait(_ manager:NETunnelProviderManager,_ timeout:Double)async->Bool{await waitForConnection(manager,timeout:timeout)}
}
enum IOSMultihopExecution{
// ACTUAL_BUDGET
static func issue()->NSError{NSError(domain:"captured-startup",code:1)}
}
@main struct Tests{
 @MainActor static var checks=0
 @MainActor static func check(_ value:Bool,_ message:String){if !value{fatalError(message)};checks+=1}
 @MainActor static func main()async throws{
 let modes=["wg","awg2-fast","wg-pq","awg2-pq","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","max","reality-pq-vision","shadowsocks"]
 let key:Set<String>=["wg-pq","awg2-pq","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"]
 for entry in modes{for exit in modes{for execution in ["local","server","auto"]{
  let budget=try IOSMultihopExecution.startupTimeout(execution:execution,entryMode:entry,exitMode:exit)
  let local=Double((key.contains(entry) ? 30:0)+(key.contains(exit) ? 30:0))
  let remote=Double(key.contains(exit) ? (execution=="auto" ? 60:execution=="server" ? 30:0):0)
  check(budget==(execution=="local" ? 25:120)+local+remote,"captured phase or final Server recheck was omitted")
  check(budget<=240,"unbounded Apple startup")
 }}}
 do{_ = try IOSMultihopExecution.startupTimeout(execution:"unknown",entryMode:"wg-pq",exitMode:"wg-pq");fatalError("invalid execution accepted")}catch{checks+=1}
 Clock.reset();let model=Model(),manager=NETunnelProviderManager()
 let delayed=try IOSMultihopExecution.startupTimeout(execution:"local",entryMode:"wg-pq",exitMode:"shadowsocks")
 check(await model.wait(manager,delayed),"valid native initial-key phase was cut off")
 check(Clock.time==31,"startup did not retain actual ready transition")
 Clock.reset();manager.connection.ready=40
 let ordinary=try IOSMultihopExecution.startupTimeout(execution:"local",entryMode:"wg",exitMode:"shadowsocks")
 check(!(await model.wait(manager,ordinary))&&Clock.time==25,"ordinary startup deadline widened or failed to expire")
 for action in ["cancel","replace","task","terminal"]{
  Clock.reset();manager.connection.ready=1000;manager.connection.terminal=nil;model.userDisconnectInProgress=false
  Clock.change={if Clock.time==1 {switch action{case "cancel":model.userDisconnectInProgress=true;case "replace":model.iosConnectGeneration=UUID();case "task":Task.isCancelled=true;default:manager.connection.terminal = .disconnecting}}}
  check(!(await model.wait(manager,240))&&Clock.time==1,"expanded startup delayed cancellation or adopted another owner")
 }
 print("Apple captured startup deadlines: \(checks) shipping Swift checks")
 }
}
'''

def main():
    source = (APP/'RouterVPNModel.swift').read_text()
    policy = (APP/'IOSMultihopExecution.swift').read_text()
    waiting = M.member(source, '    private func waitForConnection(')
    budget = M.member(policy, '    static func startupTimeout(')
    captured = source[source.index('        let startupTimeout: TimeInterval'):source.index('        try manager.connection.startVPNTunnel(options: options)')]
    assert 'IOSDNSRuntimePolicy.selectedProfile(in: bundle)?.multihopExecution' in captured
    assert 'entryMode: selection.multihopEntryMode' in captured and 'exitMode: selection.rawProfileID' in captured
    assert 'selectedRouterProfile?' not in captured, 'startup budget must not follow mutable selection'
    restore = (APP/'IOSSpeedLabTunnel.swift').read_text()
    assert 'startupTimeout(execution: multihopExecution.execution,' in restore
    assert 'entryMode: multihopExecution.source.entryMode, exitMode: multihopExecution.source.exitMode)' in restore
    template = BOUNDARIES.replace('// ACTUAL_WAIT', waiting).replace('// ACTUAL_BUDGET', budget)
    with tempfile.TemporaryDirectory(prefix='routervpn-apple-startup-deadline-') as folder:
        path,binary=Path(folder)/'tests.swift',Path(folder)/'tests'
        def run(text):
            path.write_text(text)
            compiled=subprocess.run([shutil.which('swiftc') or 'swiftc','-swift-version','6','-parse-as-library',str(path),'-o',str(binary)],timeout=90,capture_output=True,text=True)
            assert not compiled.returncode, compiled.stderr
            return subprocess.run([str(binary)],timeout=20,capture_output=True,text=True)
        result=run(template)
        assert not result.returncode,(result.stdout,result.stderr)
        print(result.stdout.strip())
        for before,after,error in (
            ('+ entry + exit + remoteCount * exit','+ exit + remoteCount * exit','captured phase or final Server recheck was omitted'),
            ('execution == "auto" ? 2 : 1','execution == "auto" ? 1 : 1','captured phase or final Server recheck was omitted'),
            ('iosConnectGeneration == generation, !userDisconnectInProgress, !Task.isCancelled','true, !userDisconnectInProgress, !Task.isCancelled','expanded startup delayed cancellation or adopted another owner'),
        ):
            assert template.count(before)==1, before
            result=run(template.replace(before,after))
            assert result.returncode and error in result.stderr,(before,result.stdout,result.stderr)
        print('Apple startup deadline: missing entry phase, missing Server recheck, and stale owner mutations rejected')

if __name__=='__main__':main()
