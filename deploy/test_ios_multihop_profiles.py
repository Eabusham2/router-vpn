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
try check("legacy does not fabricate captured Home DNS", !legacy.homeDNSCaptured)
var graph = legacy
graph.multihopEnabled = true
graph.multihopEntryID = "home-entry"
graph.multihopExitID = "home-exit"
graph.multihopExitMode = "shadowsocks"
// Every offered exit mode survives the real private Codable profile model.
for mode in ["wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "naive-h2", "naive-h3", "ss-v2ray", "split", "max"] {
    var candidate = graph
    candidate.multihopExitMode = mode
    let copy = try JSONDecoder().decode(IOSConnectionSafePreferences.self, from: JSONEncoder().encode(candidate))
    try check("saved graph preserves exact exit family \(mode)", copy == candidate && copy.multihopExitMode == mode)
}
for mode in ["wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "naive-h2", "naive-h3", "ss-v2ray", "split", "max"] {
    var candidate = graph; candidate.multihopEntryMode = mode
    let copy = try JSONDecoder().decode(IOSConnectionSafePreferences.self,from:JSONEncoder().encode(candidate))
    try check("saved entry mode keeps exact engine variant",copy.multihopEntryMode == mode && copy == candidate)
}
for entry in ["wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"] {
    for exit in ["wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"] {
        var candidate = graph; candidate.multihopEntryMode = entry; candidate.multihopExitMode = exit; candidate.multihopExecution = "local"
        let copy = try JSONDecoder().decode(IOSConnectionSafePreferences.self, from: JSONEncoder().encode(candidate))
        try check("ordinary external graph keeps exact imported protocols", copy == candidate && copy.multihopEntryMode == entry && copy.multihopExitMode == exit)
    }
}
for mode in ["tor", "tor-bridge"] {
    var candidate = graph; candidate.multihopExitMode = mode; candidate.multihopExecution = "local"
    let copy = try JSONDecoder().decode(IOSConnectionSafePreferences.self, from: JSONEncoder().encode(candidate))
    try check("Tor exit keeps its exact saved protocol", copy == candidate && copy.multihopExitMode == mode)
}
for mode in ["ss-v2ray-unknown", "split-unknown", "max-unknown", "tor-unknown", "wg-pq-unknown", "awg2-pq-unknown", "unregistered", "reality-vision\n"] {
    var invalid = try JSONSerialization.jsonObject(with:JSONEncoder().encode(graph)) as! [String:Any]
    invalid["multihopExitMode"] = mode
    do { _ = try JSONDecoder().decode(IOSConnectionSafePreferences.self,from:JSONSerialization.data(withJSONObject:invalid));fatalError("unknown exit silently accepted") } catch { checks += 1 }
}
for mode in ["awg2-pq-unknown", "tor", "tor-bridge"] {
    var badEntry = try JSONSerialization.jsonObject(with:JSONEncoder().encode(graph)) as! [String:Any]
    badEntry["multihopEntryMode"] = mode
    do { _ = try JSONDecoder().decode(IOSConnectionSafePreferences.self,from:JSONSerialization.data(withJSONObject:badEntry));fatalError("unsupported entry silently downgraded") } catch { checks += 1 }
}
let encoded = try JSONEncoder().encode(graph)
let restored = try JSONDecoder().decode(IOSConnectionSafePreferences.self, from: encoded)
try check("all non-secret preferences round trip", restored == graph)
var capturedHome = graph; capturedHome.homeDNSCaptured = true
let capturedHomeRestored = try JSONDecoder().decode(IOSConnectionSafePreferences.self, from: JSONEncoder().encode(capturedHome))
try check("explicit captured Home DNS survives serialization", capturedHomeRestored == capturedHome && capturedHomeRestored.homeDNSCaptured)
let object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
let expectedKeys: Set<String> = [
    "homeLANAccess", "killSwitch", "killSwitchPolicy", "ipv6Mode", "baseTunnel", "baseFallback", "startLayer",
    "autoRequireEncrypted", "autoRequireObfuscation", "mtuPolicy", "manualMTU", "daitaEnabled", "jumboTUN", "startupMode", "autoConnect",
    "dnsMode", "dnsProtocol", "dnsHost", "dnsPort", "dnsServerName", "dnsPath", "homeDNSCaptured",
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
let padded = try preferences(#"{"daitaEnabled":true,"jumboTUN":true}"#)
try check("padding and Jumbo choices are saved", padded.daitaEnabled && padded.jumboTUN)
let paddingRestored = try JSONDecoder().decode(IOSConnectionSafePreferences.self,from:JSONEncoder().encode(padded))
try check("padding and Jumbo choices round trip", paddingRestored == padded)
for key in ["daitaEnabled","jumboTUN"] {
    var bad = object;bad[key] = "true"
    do { _ = try JSONDecoder().decode(IOSConnectionSafePreferences.self,from:JSONSerialization.data(withJSONObject:bad));fatalError("invalid performance flag accepted") } catch { checks += 1 }
}
var chain = legacy
chain.multihopEnabled = true; chain.multihopExecution = "local"
chain.multihopNodes = (0..<4).map { IOSMultihopNodeSelection(id:"ordered-\($0)",mode:$0 == 3 ? "shadowsocks" : "wg") }
let chainData = try JSONEncoder().encode(chain)
let chainCopy = try JSONDecoder().decode(IOSConnectionSafePreferences.self,from:chainData)
try check("ordered chain keeps every position and mode",chainCopy == chain && chainCopy.multihopNodes?.count == 4)
try check("ordered chain does not fabricate legacy pair fields",chainCopy.multihopEntryID == nil && chainCopy.multihopEntryMode == nil && chainCopy.multihopExitID == nil && chainCopy.multihopExitMode == nil)
let chainObject = try JSONSerialization.jsonObject(with:chainData) as! [String:Any]
for count in [0,1,9] {
 var bad=chainObject;bad["multihopNodes"]=(0..<count).map{["id":"node-\($0)","mode":"wg"]}
 do {_ = try preferences(String(decoding:JSONSerialization.data(withJSONObject:bad),as:UTF8.self));fatalError("invalid chain count accepted")}catch{checks+=1}
}
for key in ["multihopEntryID","multihopEntryMode","multihopExitID","multihopExitMode"] {
 var bad=chainObject;bad[key]=key.hasSuffix("Mode") ? "wg":"legacy-node"
 do {_ = try preferences(String(decoding:JSONSerialization.data(withJSONObject:bad),as:UTF8.self));fatalError("mixed pair and chain accepted")}catch{checks+=1}
}
for selection in ["local","server","auto"] {
 var selected=chain;selected.multihopExecution=selection
 let selectedData=try JSONEncoder().encode(selected)
 let copy:IOSConnectionSafePreferences
 do {copy=try JSONDecoder().decode(IOSConnectionSafePreferences.self,from:selectedData)}
 catch {fatalError("supported explicit chain execution rejected: \(selection)")}
 try check("explicit chain choice and every original position survive",copy == selected && copy.multihopExecution == selection && copy.multihopNodes == chain.multihopNodes)
 var saved=record;saved.preferences=selected;saved.nodeID=selected.multihopNodes!.last!.id;saved.mode=selected.multihopNodes!.last!.mode
 let data=try JSONEncoder().encode(IOSConnectionProfileEnvelope(schemaVersion:4,profiles:[saved]))
 let restored=try JSONDecoder().decode(IOSConnectionProfileEnvelope.self,from:data)
 try check("whole profile preserves explicit chain execution",restored.profiles[0].preferences == selected && restored.profiles[0].nodeID == saved.nodeID && restored.profiles[0].mode == saved.mode)
}
for missing in [true,false] {
 var bad=chainObject
 if missing {bad.removeValue(forKey:"multihopExecution")}else{bad["multihopExecution"]=NSNull()}
 do {_ = try preferences(String(decoding:JSONSerialization.data(withJSONObject:bad),as:UTF8.self));fatalError("implicit chain execution accepted")}catch{checks+=1}
}
for selection in ["","AUTO","server\n"," server","remote"] {
 var bad=chainObject;bad["multihopExecution"]=selection
 do {_ = try preferences(String(decoding:JSONSerialization.data(withJSONObject:bad),as:UTF8.self));fatalError("malformed chain execution accepted")}catch{checks+=1}
}
for selection in ["server","auto"] {
 for count in 3...8 {for kind in ["socks5","http-connect","https-connect","openvpn"] {
  var raw=chainObject;raw["multihopExecution"]=selection
  var references=[[String:String]]()
  for position in 0..<count {
   let mode:String
   if position==count-1 {mode="shadowsocks"}
   else if position==count-2 {mode=kind}
   else {mode=["wg","awg2-fast","awg2-strong"][position%3]}
   references.append(["id":"typed-\(position)","mode":mode])
  }
  raw["multihopNodes"]=references
  let selected:IOSConnectionSafePreferences
  do {selected=try preferences(String(decoding:JSONSerialization.data(withJSONObject:raw),as:UTF8.self))}
  catch {fatalError("complete typed path preferences refused: \(kind)/\(count)/\(selection)")}
  let expected=references.map{IOSMultihopNodeSelection(id:$0["id"]!,mode:$0["mode"]!)}
  try check("complete typed preferences preserve every original reference",selected.multihopNodes==expected && selected.multihopExecution==selection)
  var saved=record;saved.preferences=selected;saved.nodeID=selected.multihopNodes!.last!.id;saved.mode=selected.multihopNodes!.last!.mode
  let data=try JSONEncoder().encode(IOSConnectionProfileEnvelope(schemaVersion:4,profiles:[saved]))
  let restored=try JSONDecoder().decode(IOSConnectionProfileEnvelope.self,from:data)
  try check("complete typed profile preserves all settings and node references",restored.profiles[0]==saved)
 }}
 for modes in [["wg","hysteria2"],["wg","shadowsocks","awg2-fast","shadowsocks"],["awg2-strong","shadowsocks","shadowsocks","wg","shadowsocks"]] {
  var raw=chainObject;raw["multihopExecution"]=selection
  raw["multihopNodes"]=modes.enumerated().map{["id":"node-\($0.offset)","mode":$0.element]}
  let expected=try preferences(String(decoding:JSONSerialization.data(withJSONObject:raw),as:UTF8.self))
  var saved=record;saved.preferences=expected;saved.nodeID=expected.multihopNodes!.last!.id;saved.mode=expected.multihopNodes!.last!.mode
  let restored=try JSONDecoder().decode(IOSConnectionProfileEnvelope.self,from:JSONEncoder().encode(IOSConnectionProfileEnvelope(schemaVersion:4,profiles:[saved])))
  try check("paired Hysteria2 final and literal multiple-import selections preserve the full future profile",restored.profiles==[saved] && expected.multihopExecution==selection && expected.multihopNodes?.map(\.mode)==modes)
 }
 for modes in [["wg","hysteria2","openvpn","shadowsocks"],["wg","hysteria2","socks5","shadowsocks"],["wg","hysteria2","http-connect","shadowsocks"],["wg","hysteria2","https-connect","shadowsocks"]] {
  var bad=chainObject;bad["multihopExecution"]=selection
  bad["multihopNodes"]=modes.enumerated().map{["id":"node-\($0.offset)","mode":$0.element]}
  do {_ = try preferences(String(decoding:JSONSerialization.data(withJSONObject:bad),as:UTF8.self));fatalError("unsupported Server or Compare chain accepted")}catch{checks+=1}
 }
}
for invalid in [["id":"ordered-0","mode":"wg"],["id":"node.1","mode":"wg"],["id":"node-1","mode":"WG"],["id":"node-1","mode":"wg\n"]] {
 var bad=chainObject;var nodes=bad["multihopNodes"] as! [[String:Any]];nodes[1]=invalid;bad["multihopNodes"]=nodes
 do {_ = try preferences(String(decoding:JSONSerialization.data(withJSONObject:bad),as:UTF8.self));fatalError("ambiguous ordered reference accepted")}catch{checks+=1}
}
var injectedChain=chainObject;var injectedNodes=injectedChain["multihopNodes"] as! [[String:Any]]
injectedNodes[1]["api_token"]="never-copy-chain-secret";injectedChain["multihopNodes"]=injectedNodes
let cleanChain=try preferences(String(decoding:JSONSerialization.data(withJSONObject:injectedChain),as:UTF8.self))
try check("ordered references never persist injected credentials",!String(decoding:JSONEncoder().encode(cleanChain),as:UTF8.self).contains("never-copy-chain-secret"))
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
    models = (SOURCE.parent / 'Models.swift').read_text()
    chain = models[models.index('struct IOSMultihopNodeSelection:'):models.index('struct RouterProfile:')]
    test = models + '\n' + text[start:end] + '\n@MainActor private func runChecks() throws {\n' + TEST + '\n}\ntry runChecks()\n'
    with tempfile.TemporaryDirectory(prefix='routervpn-multihop-profiles-') as tmp:
        source, binary = Path(tmp) / 'main.swift', Path(tmp) / 'profiles'
        source.write_text(test)
        subprocess.run([swift,'-swift-version','6',str(source),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=20)
        guard = 'execution == "local" || ["server", "auto"].contains(execution ?? "") && supportsServerExecution(nodes)'
        assert chain.count(guard) == 1, 'Original chain execution guard changed'
        for name, replacement, witness in (
                ('local-only', 'execution == "local"', 'supported explicit chain execution rejected: server'),
                ('implicit', 'true', 'implicit chain execution accepted'),
                ('unsupported', 'execution == "local" || ["server", "auto"].contains(execution ?? "")', 'unsupported Server or Compare chain accepted')):
            source.write_text(test.replace(chain, chain.replace(guard,replacement,1),1))
            subprocess.run([swift,'-swift-version','6',str(source),'-o',str(binary)],check=True,timeout=90)
            failed=subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
            assert failed.returncode != 0 and witness in failed.stdout+failed.stderr, (name,failed.stdout+failed.stderr)
            print('Apple profile execution causal refusal:',name)
        for family, next_function, kind in (
                ('OpenVPN', 'supportsCONNECTExecution', 'openvpn'),
                ('CONNECT', 'supportsGenericExecution', 'http-connect'),
                ('SOCKS', 'supportsMultipleImportedExecution', 'socks5')):
            start = chain.index('    static func supports' + family + 'Execution(')
            end = chain.index('    static func ' + next_function + '(', start)
            original = chain[start:end]
            bound = '(3...maximumNodes).contains(nodes.count)'
            assert original.count(bound) == 1
            replaced = chain[:start] + original.replace(bound, 'nodes.count == 3', 1) + chain[end:]
            source.write_text(test.replace(chain, replaced, 1))
            subprocess.run([swift,'-swift-version','6',str(source),'-o',str(binary)],check=True,timeout=90)
            failed = subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
            assert failed.returncode != 0 and 'complete typed path preferences refused: '+kind+'/4/server' in failed.stdout+failed.stderr, (family,failed.stdout+failed.stderr)
            print('Apple profile execution causal refusal: old-'+family.lower()+'-trio')
    print('This verifies encoded graph preferences, not physical UI or full persistence transactions.')

if __name__ == '__main__':
    main()
