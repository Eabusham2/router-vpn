#!/usr/bin/env python3
"""Execute the shipping Codable preference/record types, not parallel mock models."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ios/RouterVPN/App/IOSConnectionProfilesView.swift'
TEST = r'''
var checks = 0
func check(_ name: String, _ condition: @autoclosure () throws -> Bool) throws {
    guard try condition() else { fatalError("FAIL " + name) }
    checks += 1
}
func preferences(_ raw: String) throws -> IOSConnectionSafePreferences {
    try JSONDecoder().decode(IOSConnectionSafePreferences.self, from: Data(raw.utf8))
}
let legacy = try preferences("{}")
try check("legacy stays ordinary single node", !legacy.multihopEnabled)
try check("legacy has no fabricated entry", legacy.multihopEntryID == nil && legacy.multihopExitID == nil && legacy.multihopExitMode == nil)
try check("legacy IPv6 default preserved", legacy.ipv6Mode == "on")
try check("legacy SMART default preserved", legacy.startupMode == "smart-auto")
var graph = legacy
graph.multihopEnabled = true
graph.multihopEntryID = "home-entry"
graph.multihopExitID = "home-exit"
graph.multihopExitMode = "shadowsocks"
// Every offered exit mode survives the real private Codable profile model.
for mode in ["wg", "shadowsocks", "hysteria2"] {
    var candidate = graph
    candidate.multihopExitMode = mode
    let copy = try JSONDecoder().decode(IOSConnectionSafePreferences.self, from: JSONEncoder().encode(candidate))
    try check("saved graph preserves exact exit family \(mode)", copy == candidate && copy.multihopExitMode == mode)
}
let encoded = try JSONEncoder().encode(graph)
let restored = try JSONDecoder().decode(IOSConnectionSafePreferences.self, from: encoded)
try check("all non-secret preferences round trip", restored == graph)
let object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
let expectedKeys: Set<String> = [
    "homeLANAccess", "killSwitch", "killSwitchPolicy", "ipv6Mode", "baseTunnel", "baseFallback", "startLayer",
    "autoRequireEncrypted", "autoRequireObfuscation", "mtuPolicy", "manualMTU", "startupMode", "autoConnect",
    "dnsMode", "dnsProtocol", "dnsHost", "dnsPort", "dnsServerName", "dnsPath",
    "multihopEnabled", "multihopEntryID", "multihopExitID", "multihopExitMode"
]
try check("exact non-secret serialization whitelist", Set(object.keys) == expectedKeys)
let injected = try preferences("""
{"apiToken":"never-copy-me", "privateKey":"never-copy-me", "private_key":"never-copy-me", "socksPassword":"never-copy-me",
"multihopEnabled":true,"multihopEntryID":"home-entry","multihopExitID":"home-exit","multihopExitMode":"hysteria2"}
""")
let injectedData = try JSONEncoder().encode(injected)
try check("injected secret values never persisted", !String(decoding: injectedData, as: UTF8.self).contains("never-copy-me"))
let injectedObject = try JSONSerialization.jsonObject(with: injectedData) as! [String: Any]
try check("injected secret property names never persisted", Set(injectedObject.keys) == expectedKeys)
let record = IOSConnectionProfileRecord(id:"fixture-profile",name:"Saved graph",nodeID:"home-exit",nodeKind:"router-vpn",mode:"smart-auto",customLayers:[],preferences:graph,updatedAt:Date(timeIntervalSince1970:0))
let envelope = IOSConnectionProfileEnvelope(schemaVersion:4,profiles:[record])
let envelopeData = try JSONEncoder().encode(envelope)
let readback = try JSONDecoder().decode(IOSConnectionProfileEnvelope.self,from:envelopeData)
try check("whole record still targets selected exit", readback.profiles[0].nodeID == "home-exit")
try check("whole record keeps exact graph", readback.profiles[0].preferences == graph)
try check("existing schema stays compatible", readback.schemaVersion == 4)
var bad = object
bad["multihopEnabled"] = "true"
do {
    _ = try JSONDecoder().decode(IOSConnectionSafePreferences.self,from:JSONSerialization.data(withJSONObject:bad))
    fatalError("Invalid nonboolean graph flag was accepted")
} catch { checks += 1 }
print("iOS shipping multihop profile serialization: PASS (\(checks) executable checks; no credentials/network/storage used)")
'''

def main() -> None:
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc is required for real profile serialization checks')
    text = SOURCE.read_text()
    start = text.index('private struct IOSConnectionSafePreferences:')
    end = text.index('@MainActor\nprivate enum IOSConnectionProfileStore', start)
    # Put the unchanged private types and harness in the SAME source file so
    # Swift access control and synthesized Codable implementations stay real.
    test = 'import Foundation\n' + text[start:end] + '\n@MainActor private func runChecks() throws {\n' + TEST + '\n}\ntry runChecks()\n'
    with tempfile.TemporaryDirectory(prefix='routervpn-multihop-profiles-') as tmp:
        source, binary = Path(tmp) / 'main.swift', Path(tmp) / 'profiles'
        source.write_text(test)
        subprocess.run([swift,'-swift-version','6',str(source),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=20)
    print('This verifies encoded graph preferences, not physical UI or full persistence transactions.')

if __name__ == '__main__':
    main()
