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
func captured(_ configuration:[String:Any],_ engine:String="external-libbox",_ raw:String="external-openvpn")throws->IOSSessionIdentity {
    try IOSSessionIdentity(connectedAt:t,engine:engine,rawProfile:raw,bundleData:Data("exact-exit".utf8),configuration:configuration)
}
for (prefix,raw) in [("external_entry","external-openvpn"),("tor_entry","external-tor"),("tor_entry","external-tor-bridge")] {
    let data=Data("complete predecessor keys, policy, and assets".utf8)
    let config:[String:Any]=[prefix+"_bundle":data,prefix+"_mode":"max-quic-awg"]
    let owner=try captured(config,"external-libbox",raw)
    try check("external graph captures exact predecessor",owner.entryBundleData==data && owner.entryMode=="max-quic-awg")
    try check("external graph readback stays equal",owner==captured(config,"external-libbox",raw))
    try check("external graph is not direct",owner != captured([:],"external-libbox",raw))
    for changed in ["policy-and-credentials","same-mode-new-assets"] {
        var copy=config;copy[prefix+"_bundle"]=Data(changed.utf8)
        try check("changed predecessor invalidates same labels",owner != captured(copy,"external-libbox",raw))
    }
    var changedMode=config;changedMode[prefix+"_mode"]="max-tls-awg"
    try check("captured entry mode participates in identity",owner != captured(changedMode,"external-libbox",raw))
    for bad in [
        [prefix+"_mode":"wg"], [prefix+"_bundle":data],
        [prefix+"_bundle":"not-data",prefix+"_mode":"wg"],
        [prefix+"_bundle":Data(),prefix+"_mode":"wg"],
        [prefix+"_bundle":data,prefix+"_mode":""],
        [prefix+"_bundle":data,prefix+"_mode":"wg\n"],
        [prefix+"_bundle":data,prefix+"_mode":true],
        [prefix+"_bundle":data,prefix+"_mode":"wg","entryBundle":data],
        ["external_entry_bundle":data,"external_entry_mode":"wg","tor_entry_bundle":data,"tor_entry_mode":"wg"]
    ] as [[String:Any]] { reject("ambiguous external predecessor owner") { _=try captured(bad,"external-libbox",raw) } }
    for engine in ["wireguard","libbox","multihop-libbox"] {
        reject("external predecessor cannot attach to a different engine") { _=try captured(config,engine) }
    }
}
reject("Tor slot cannot disappear into ordinary identity") {_=try captured(["tor_entry_bundle":Data("entry".utf8),"tor_entry_mode":"wg"])}
reject("ordinary slot cannot disappear into Tor identity") {_=try captured(["external_entry_bundle":Data("entry".utf8),"external_entry_mode":"wg"],"external-libbox","external-tor")}

func chainInput(_ members:[String] = ["original-first-source", "original-middle-source", "original-final-source"])throws->String {
 String(decoding:try JSONSerialization.data(withJSONObject:["kind":"routervpn-node-chain-launch-input","schema":1,"execution":"local","nodes":members],options:[.sortedKeys]),as:UTF8.self)
}
let chain=try chainInput(),ordered=try captured(["nodeChainSource":chain],"multihop-libbox","shadowsocks")
try check("ordered identity captures all private source bytes",ordered.nodeChainSource==Data(chain.utf8) && ordered.entryBundleData==nil)
try check("identical ordered readback remains equal",ordered==captured(["nodeChainSource":chain],"multihop-libbox","shadowsocks"))
// Equality capture only; native typed parsing/proof has its independent gate.
let socks=String(decoding:try JSONSerialization.data(withJSONObject:["schema":3,"execution":"local","nodes":["first","middle","final"],"identity_sources":["first-identity","","final-identity"]]),as:UTF8.self)
let typed=try captured(["nodeChainSOCKSSource":socks],"multihop-libbox","shadowsocks")
try check("typed session retains complete source",typed.nodeChainSource==Data(socks.utf8) && typed != ordered)
reject("typed source cannot use ordinary provider discriminator"){_ = try captured(["nodeChainSource":socks],"multihop-libbox","shadowsocks")}
reject("ordinary source cannot use typed provider discriminator"){_ = try captured(["nodeChainSOCKSSource":chain],"multihop-libbox","shadowsocks")}
reject("typed source cannot mix ordinary owner"){_ = try captured(["nodeChainSOCKSSource":socks,"nodeChainSource":chain],"multihop-libbox","shadowsocks")}
reject("typed source cannot borrow legacy pair"){_ = try captured(["nodeChainSOCKSSource":socks,"entryBundle":Data("legacy".utf8)],"multihop-libbox","shadowsocks")}
let connect=String(decoding:try JSONSerialization.data(withJSONObject:["schema":4,"execution":"local","nodes":["first","connect-middle","final"],"identity_sources":["first-identity","","final-identity"]]),as:UTF8.self)
let connected=try captured(["nodeChainCONNECTSource":connect],"multihop-libbox","shadowsocks")
try check("CONNECT session retains original complete source",connected.nodeChainSource==Data(connect.utf8) && connected != typed && connected != ordered)
for extra in [["nodeChainSource":connect],["nodeChainSOCKSSource":connect],["nodeChainCONNECTSource":socks],["nodeChainCONNECTSource":chain],["nodeChainCONNECTSource":connect,"nodeChainSOCKSSource":socks],["nodeChainCONNECTSource":connect,"nodeChainSource":chain]] {
 reject("CONNECT source discriminator cannot borrow another owner"){_ = try captured(extra,"multihop-libbox","shadowsocks")}
}
reject("CONNECT source cannot borrow legacy pair"){_ = try captured(["nodeChainCONNECTSource":connect,"entryBundle":Data("legacy".utf8)],"multihop-libbox","shadowsocks")}
for sources in [["original-first-source","changed-middle-source","original-final-source"],
                ["original-middle-source","original-first-source","original-final-source"],
                ["original-first-source","original-final-source"]] {
 try check("same final labels cannot hide middle source change",ordered != captured(["nodeChainSource":chainInput(sources)],"multihop-libbox","shadowsocks"))
}
try check("ordered source cannot equal legacy pair",ordered != identity())
for engine in ["wireguard","libbox","external-libbox"] {
 reject("ordered source attached to foreign owner"){_ = try captured(["nodeChainSource":chain],engine,"shadowsocks")}
}
for bad in [
 ["nodeChainSource":chain,"entryBundle":Data("legacy-entry".utf8)],
 ["nodeChainSource":chain,"external_entry_bundle":Data("entry".utf8),"external_entry_mode":"wg"],
 ["nodeChainSource":chain,"tor_entry_mode":"wg"],
 ["nodeChainSource":Data(chain.utf8)], ["nodeChainSource":true],
 ["nodeChainSource":""], ["nodeChainSource":"{}"],
 ["nodeChainSource":String(repeating:" ",count:40*1024*1024+1)]
] as [[String:Any]] {reject("ambiguous or malformed ordered owner"){_ = try captured(bad,"multihop-libbox","shadowsocks")}}
for key in ["projection_kind","session_id","target_os","restored_mtu"] {
 var changed=try JSONSerialization.jsonObject(with:Data(chain.utf8)) as! [String:Any];changed[key]="foreign-desktop-owner"
 let source=String(decoding:try JSONSerialization.data(withJSONObject:changed),as:UTF8.self)
 reject("desktop projection cannot become mobile session identity"){_ = try captured(["nodeChainSource":source],"multihop-libbox","shadowsocks")}
}
for members in [[String](),["single"],Array(repeating:"member",count:9)] {
 let source=try chainInput(members)
 reject("ordered identity bounds"){_ = try captured(["nodeChainSource":source],"multihop-libbox","shadowsocks")}
}

print("Exact iOS session identity: PASS (\(checks) executable checks)")
'''
def main():
    swift=shutil.which('swiftc')
    if not swift: raise SystemExit('swiftc required for exact session identity tests')
    with tempfile.TemporaryDirectory(prefix='routervpn-session-') as tmp:
        source=Path(tmp)/'main.swift'; binary=Path(tmp)/'session-test'; source.write_text(TEST)
        subprocess.run([swift,'-swift-version','6',str(POLICY),str(source),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=15)
        text=POLICY.read_text();before='self.nodeChainSource = nodeChainSource'
        assert text.count(before)==1
        mutated=Path(tmp)/'ChangedIdentity.swift';mutated.write_text(text.replace(before,'self.nodeChainSource = nil',1))
        subprocess.run([swift,'-swift-version','6',str(mutated),str(source),'-o',str(binary)],check=True,timeout=90)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=15)
        assert result.returncode != 0 and 'ordered identity captures all private source bytes' in result.stdout+result.stderr,'ordered session source mutation not detected'
        print('Rejected session identity mutation: omitted ordered source')
    model=(POLICY.parent/'RouterVPNModel.swift').read_text()
    runner=(POLICY.parent/'IOSSpeedLabRunner.swift').read_text()
    for marker in ['manager.connection.connectedDate','activeSessionIdentity = identity','bundleData: data, configuration: configuration','Tunnel status is unverified']:
        assert marker in model, marker
    for marker in ['let sessionIdentity: IOSSessionIdentity?', 'model.activeSessionIdentity', 'transitioning: model.tunnelTransitioning', 'withTaskCancellationHandler']:
        assert marker in runner, marker
if __name__=='__main__':main()
