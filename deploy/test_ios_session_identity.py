#!/usr/bin/env python3
"""Execute exact running-session equality/bounds used by Speed Lab."""
from pathlib import Path
import shutil
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
POLICY=ROOT/'ios/RouterVPN/App/IOSSessionIdentity.swift'
TEST=r'''
import Foundation
var checks=0
@MainActor func check(_ label:String,_ ok:@autoclosure () throws -> Bool) throws { guard try ok() else { fatalError(label) }; checks += 1 }
@MainActor func reject(_ label:String,_ f:() throws -> Void) { do { try f();fatalError("accepted "+label) } catch { checks += 1 } }
let t=Date(timeIntervalSince1970:1)
func identity(time:Date = t, engine:String = "multihop-libbox", raw:String = "shadowsocks", exit:Data = Data("exit-a".utf8), entry:Data? = Data("entry-a".utf8)) throws -> IOSSessionIdentity {
    try IOSSessionIdentity(connectedAt:time,engine:engine,rawProfile:raw,bundleData:exit,entryBundleData:entry)
}
let original=try identity()
try check("unchanged identity compares equal",original == identity())
try check("same-node reconnect is different",original != identity(time:t.addingTimeInterval(1)))
try check("entry bundle change invalidates result",original != identity(entry:Data("entry-b".utf8)))
try check("exit bundle change invalidates result",original != identity(exit:Data("exit-b".utf8)))
try check("raw mode change invalidates result",original != identity(raw:"hysteria2"))
try check("ordinary path is different",original != identity(engine:"libbox",entry:nil))
reject("missing entry") { _ = try identity(entry:nil) }
reject("empty entry") { _ = try identity(entry:Data()) }
reject("missing exit") { _ = try identity(exit:Data()) }
reject("foreign engine") { _ = try identity(engine:"foreign",entry:nil) }
reject("empty mode") { _ = try identity(raw:"") }
reject("oversized mode") { _ = try identity(raw:String(repeating:"a",count:129)) }
reject("entry in ordinary path") { _ = try identity(engine:"libbox") }
reject("oversized entry") { _ = try identity(entry:Data(repeating:0,count:32*1024*1024+1)) }
reject("oversized exit") { _ = try identity(exit:Data(repeating:0,count:32*1024*1024+1)) }
print("Exact iOS session identity: PASS (\(checks) executable checks)")
'''
def main():
    swift=shutil.which('swiftc')
    if not swift: raise SystemExit('swiftc required for exact session identity tests')
    with tempfile.TemporaryDirectory(prefix='routervpn-session-') as tmp:
        source=Path(tmp)/'main.swift'; binary=Path(tmp)/'session-test'; source.write_text(TEST)
        subprocess.run([swift,'-swift-version','6',str(POLICY),str(source),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=15)
    model=(POLICY.parent/'RouterVPNModel.swift').read_text()
    runner=(POLICY.parent/'IOSSpeedLabRunner.swift').read_text()
    for marker in ['manager.connection.connectedDate','activeSessionIdentity = identity','entryBundleData: configuration["entryBundle"] as? Data','Tunnel status is unverified']:
        assert marker in model, marker
    for marker in ['let sessionIdentity: IOSSessionIdentity?', 'model.activeSessionIdentity', 'transitioning: model.tunnelTransitioning', 'withTaskCancellationHandler']:
        assert marker in runner, marker
if __name__=='__main__':main()
