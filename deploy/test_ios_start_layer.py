#!/usr/bin/env python3
"""Execute the shipping iOS Start Layer composer without a network or a VPN."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
TEST=r'''
import Foundation
func encode(_ object: Any) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }
func decode(_ data: Data) throws -> [String: Any] { try JSONSerialization.jsonObject(with: data) as! [String: Any] }
func aes() -> [String: Any] { ["type":"shadowsocks", "tag":"proxy", "server":"192.0.2.1", "server_port":8388, "method":IOSStartLayer.aesMethod, "password":Data(repeating:7,count:32).base64EncodedString()] }
func graph(_ raw: String, outer: [String: Any]? = nil) -> [String: Any] {
    let proxy: [String: Any] = outer ?? (raw == "shadowsocks" ? aes() : ["type": raw == "hysteria2" ? "hysteria2" : "naive", "tag":"proxy", "server":"192.0.2.1", "server_port":8443, "password":"inner-fixture", "tls":["enabled":true,"server_name":"vpn.example.com"]])
    return ["inbounds":[["type":"tun","auto_route":true,"strict_route":true]],
            "outbounds":[proxy,["type":"direct","tag":"direct"]],
            "dns":["servers":[["type":"https","tag":"selected","server":"1.1.1.1","detour":"proxy"]],"final":"selected"],
            "route":["rules":[["protocol":"dns","action":"hijack-dns"]],"final":"proxy"]]
}
func compose(_ raw: String, _ start: String, target: [String: Any]? = nil, source: [String: Any]? = nil, kind: String = "router-vpn") throws -> [String: Data] {
    let ss = try encode(graph("shadowsocks",outer:source))
    return try IOSStartLayer.apply(root:["profiles":["shadowsocks":["sing-box.json":ss.base64EncodedString()]]],
                                  selectedProfile:["start_layer":start,"node_kind":kind],
                                  files:["sing-box.json":try encode(target ?? graph(raw)),"cert.pem":Data("unchanged test certificate".utf8)], rawProfileID:raw)
}
@main struct Tests {
    @MainActor static var checks=0
    @MainActor static func check(_ label: String, _ condition: @autoclosure () throws -> Bool) throws {
        guard try condition() else { fatalError("FAIL "+label) }; checks += 1
    }
    @MainActor static func rejects(_ label: String, _ body: () throws -> Void) {
        do { try body(); fatalError("accepted "+label) } catch { checks += 1 }
    }
    @MainActor static func main() throws {
        for raw in ["shadowsocks","hysteria2","naive-h2","naive-h3"] {
            let original=graph(raw)
            for start in [IOSStartLayer.off,IOSStartLayer.aes,IOSStartLayer.aesXOR] {
                let files=try compose(raw,start)
                let next=try decode(files["sing-box.json"]!)
                try check("certificate unchanged", files["cert.pem"]==Data("unchanged test certificate".utf8))
                for key in ["inbounds","dns","route"] {
                    try check("preserves "+key, encode(next[key]!)==encode(original[key]!))
                }
                let out=next["outbounds"] as! [[String:Any]]
                if start==IOSStartLayer.off || (raw=="shadowsocks" && start==IOSStartLayer.aes) {
                    try check("unchanged disabled/AES-only profile",files["sing-box.json"]==encode(original))
                    continue
                }
                let aesOut=out[raw=="shadowsocks" ? 0 : 2]
                try check("auth method preserved",aesOut["method"] as? String==IOSStartLayer.aesMethod)
                try check("AES key preserved",aesOut["password"] as? String==aes()["password"] as? String)
                try check("outer still physical node",aesOut["server"] as? String=="192.0.2.1")
                try check("correct authenticated engine",aesOut["type"] as? String==(start==IOSStartLayer.aesXOR ? IOSStartLayer.nativeWhiteningType : "shadowsocks"))
                try check("correct outer port",aesOut["server_port"] as? Int==(start==IOSStartLayer.aesXOR ? 8389 : 8388))
                if raw != "shadowsocks" {
                    try check("remote node dials inner service",out[0]["server"] as? String=="127.0.0.1" && out[0]["detour"] as? String==IOSStartLayer.aesTag)
                    try check("inner authentication preserved",encode(out[0]["tls"]!)==encode((original["outbounds"] as! [[String:Any]])[0]["tls"]!))
                    try check("inner service port preserved",out[0]["server_port"] as? Int==8443)
                }
            }
        }
        for field in ["plugin","detour","bind_interface","multiplex","udp_over_tcp"] {
            var bad=aes();bad[field]="unowned"
            rejects("unowned "+field) { _=try compose("shadowsocks",IOSStartLayer.aesXOR,target:graph("shadowsocks",outer:bad)) }
        }
        for port: Any in [true,0,65536,8388.5,"8388",NSNull()] {
            var bad=aes();bad["server_port"]=port
            rejects("non-integer/range port") { _=try compose("shadowsocks",IOSStartLayer.aesXOR,target:graph("shadowsocks",outer:bad)) }
        }
        for method in ["xor","none","aes-256-gcm","2022-blake3-aes-128-gcm"] {
            var bad=aes();bad["method"]=method
            rejects("authentication downgrade") { _=try compose("hysteria2",IOSStartLayer.aesXOR,source:bad) }
        }
        for key in ["","short",String(repeating:"x",count:4097),"invalid\0password-for-whitening"] {
            var bad=aes();bad["password"]=key
            rejects("invalid key") { _=try compose("hysteria2",IOSStartLayer.aesXOR,source:bad) }
        }
        for detour: Any in ["foreign",true,NSNull(),["tag":"other"]] {
            var target=graph("hysteria2");var out=target["outbounds"] as! [[String:Any]];out[0]["detour"]=detour;target["outbounds"]=out
            rejects("existing detour") { _=try compose("hysteria2",IOSStartLayer.aesXOR,target:target) }
        }
        var target=graph("hysteria2");var out=target["outbounds"] as! [[String:Any]]
        out.append(["type":"direct","tag":IOSStartLayer.aesTag]);target["outbounds"]=out
        rejects("route ownership collision") { _=try compose("hysteria2",IOSStartLayer.aesXOR,target:target) }
        out.append(out[0]);target["outbounds"]=out
        rejects("duplicate route tags") { _=try compose("hysteria2",IOSStartLayer.aesXOR,target:target) }
        rejects("external node") { _=try compose("hysteria2",IOSStartLayer.aesXOR,kind:"external") }
        rejects("missing generated AES") { _=try IOSStartLayer.apply(root:[:],selectedProfile:["start_layer":IOSStartLayer.aesXOR],files:["sing-box.json":encode(graph("hysteria2"))],rawProfileID:"hysteria2") }
        rejects("reapplied graph cannot stack duplicate owners") {
            let once=try compose("hysteria2",IOSStartLayer.aesXOR)
            _=try IOSStartLayer.apply(root:[:],selectedProfile:["start_layer":IOSStartLayer.aesXOR],files:once,rawProfileID:"hysteria2")
        }
        for mode in ["xor","xor-only","invalid"] { rejects("unsafe preference") { _=try compose("shadowsocks",mode) } }
        for mode in ["wg","awg2-fast","max-tls-wg"] { rejects("no silent partial graph") { _=try compose(mode,IOSStartLayer.aesXOR) } }
        for alias in ["aes+xor","xor+aes"," AES_256_GCM+XOR_WHITENING "] {
            try check("preference normalization",IOSStartLayer.selectedMode(profile:["start_layer":alias])==IOSStartLayer.aesXOR)
        }
        let tooBig=Data(repeating:32,count:4*1024*1024+1)
        rejects("bounded config") { _=try IOSStartLayer.apply(root:[:],selectedProfile:["start_layer":IOSStartLayer.aesXOR],files:["sing-box.json":tooBig],rawProfileID:"shadowsocks") }
        print("iOS shipping authenticated Start Layer: PASS (\(checks) executable checks)")
    }
}
'''

def main():
    swift=shutil.which('swiftc')
    if not swift:raise SystemExit('swiftc is required to execute the shipping Start Layer composer')
    with tempfile.TemporaryDirectory(prefix='routervpn-ios-start-') as tmp:
        path=Path(tmp)/'Tests.swift';binary=Path(tmp)/'tests'
        path.write_text(TEST)
        subprocess.run([swift,'-swift-version','6','-parse-as-library',str(ROOT/'ios/RouterVPN/PacketTunnel/IOSStartLayer.swift'),str(path),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=30)
    print('Pure composition/ownership checks; real cipher traffic is tested by the pinned native mobile core gate.')

if __name__=='__main__':main()
