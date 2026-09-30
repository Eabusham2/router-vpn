#!/usr/bin/env python3
"""Execute the shipping scalar/error binding call, with native handles doubled.
The complete Apple CI compiles the same caller against the generated XCFramework.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
start=source.index('        var count: Int64 = 0',source.index('    func activatePerformance()'))
end=source.index('        let watcher = PerformanceWatch',start)
body=source[start:end]
assert 'LibboxRouterStartPerformance(owned, &count, &failure)' in body
swift=r'''
import Foundation
final class LibboxCommandServer {
    let result: Bool; let count: Int64; let failure: NSError?
    init(_ result: Bool,_ count: Int64,_ failure: NSError? = nil) { self.result=result; self.count=count; self.failure=failure }
}
// Exact generated scalar/error ABI: BOOL(server, int64_t*, NSError**).
func LibboxRouterStartPerformance(_ owned: LibboxCommandServer, _ count: UnsafeMutablePointer<Int64>, _ failure: UnsafeMutablePointer<NSError?>) -> Bool {
    count.pointee=owned.count; failure.pointee=owned.failure; return owned.result
}
final class Owner {
    var monitorRequested=false
    func error(_ text: String) -> NSError { NSError(domain:"fixture",code:1,userInfo:[NSLocalizedDescriptionKey:text]) }
    func activate(_ owned: LibboxCommandServer) throws {
'''+body+r'''
        monitorRequested=true
    }
}
let disabled=Owner();try disabled.activate(LibboxCommandServer(true,0));precondition(!disabled.monitorRequested)
for count: Int64 in [1,2] { let owner=Owner();try owner.activate(LibboxCommandServer(true,count));precondition(owner.monitorRequested) }
for server in [LibboxCommandServer(false,1),LibboxCommandServer(false,0),LibboxCommandServer(true,-1),LibboxCommandServer(true,3),LibboxCommandServer(true,1,NSError(domain:"native",code:2))] {
    let owner=Owner();var rejected=false
    do { try owner.activate(server) } catch { rejected=true }
    precondition(rejected && !owner.monitorRequested)
}
print("Apple performance scalar/error bridge: PASS (8 shipping-call cases; native handles doubled)")
'''
compiler=shutil.which('swiftc')
if compiler is None:
    raise SystemExit('swiftc is required for the executable native-signature contract')
with tempfile.TemporaryDirectory(prefix='routervpn-performance-bridge-') as tmp:
    file=Path(tmp)/'main.swift';exe=Path(tmp)/'test';file.write_text(swift)
    subprocess.run([compiler,'-swift-version','6',str(file),'-o',str(exe)],check=True,timeout=90)
    subprocess.run([str(exe)],check=True,timeout=15)
