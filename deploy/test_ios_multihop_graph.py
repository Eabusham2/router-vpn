#!/usr/bin/env python3
"""Execute the shipping multihop graph builder offline, with no network mocks.

A --fixture-dir output is also accepted by test_ios_multihop_pinned.sh, which
runs the exact pinned Libbox source's configuration parser in native CI.
"""
from pathlib import Path
import argparse
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "ios/RouterVPN/PacketTunnel/RouterVPNMultihopGraph.swift"
TEST = r'''
import Foundation

typealias P = RouterVPNMultihopGraph
let key = Data(repeating: 1, count: 32).base64EncodedString()
let entry: [String:Any] = ["id":"entry", "node_kind":"router-vpn", "node_proof_id":String(repeating:"a",count:64), "socks_host":"10.77.0.1", "socks_port":1080, "start_layer":"off"]
let exit: [String:Any] = ["id":"exit", "node_kind":"router-vpn", "node_proof_id":String(repeating:"b",count:64), "start_layer":"off"]
let wg: [String:Any] = ["type":"wireguard", "address":["10.77.0.2/32","fd77:77::2/128"], "private_key":key, "mtu":1400,
    "peers":[["address":"192.0.2.1", "port":51820, "public_key":key, "pre_shared_key":key,
        "allowed_ips":["0.0.0.0/0","::/0"], "persistent_keepalive_interval":25]]]
func original(_ mode: String = "shadowsocks") -> [String:Any] {
    var proxy: [String:Any] = ["type":mode,"tag":"proxy","server":"198.51.100.2","server_port":8388,"password":key]
    if mode == "shadowsocks" { proxy["method"] = "2022-blake3-aes-256-gcm" }
    else { proxy["tls"] = ["enabled":true,"server_name":"router-vpn.home"]; proxy["obfs"] = ["type":"salamander","password":"fixture"] }
    return ["log":["level":"warn"],
        "inbounds":[["type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"auto_route":true,"mtu":1380]],
        "outbounds":[proxy,["type":"direct","tag":"direct"]],
        "dns":["servers":[["type":"udp","tag":"home-dns","server":"10.77.0.1","server_port":53,"detour":"proxy"]],"final":"home-dns"],
        "route":["final":"proxy","rules":[["protocol":"dns","action":"hijack-dns"]]]]
}
func files(_ root: [String:Any]) throws -> [String:Data] {
    ["sing-box.json":try JSONSerialization.data(withJSONObject:root, options:[.sortedKeys]), "cert.pem":Data("fixture certificate is preserved".utf8)]
}
@MainActor func build(_ root: [String:Any], _ e: [String:Any] = entry, _ x: [String:Any] = exit, _ ep: [String:Any] = wg, mode: String = "shadowsocks") throws -> [String:Data] {
    try P.build(entryEndpoint:ep, entryProfile:e, exitProfile:x, exitMode:mode, files:files(root))
}
var checks = 0
@MainActor func check(_ name: String, _ body: @autoclosure () throws -> Bool) throws {
    guard try body() else { fatalError("FAIL " + name) }; checks += 1
}
@MainActor func reject(_ name: String, _ body: () throws -> Void) {
    do { try body(); fatalError("Accepted invalid " + name) } catch { checks += 1 }
}
for mode in ["shadowsocks", "hysteria2"] {
    let before = try files(original(mode))
    let built = try P.build(entryEndpoint:wg,entryProfile:entry,exitProfile:exit,exitMode:mode,files:before)
    let root = try JSONSerialization.jsonObject(with:built["sing-box.json"]!) as! [String:Any]
    let out = root["outbounds"] as! [[String:Any]], endpoints = root["endpoints"] as! [[String:Any]], inbounds = root["inbounds"] as! [[String:Any]]
    let route = root["route"] as! [String:Any], dns = root["dns"] as! [String:Any]
    let rules = route["rules"] as! [[String:Any]], servers = dns["servers"] as! [[String:Any]]
    try check("exit sockets traverse actual WG endpoint", out[0]["detour"] as? String == P.entryTag)
    try check("final path remains encrypted exit", route["final"] as? String == "proxy" && out[0]["type"] as? String == mode)
    try check("no direct fallback outbound", out.allSatisfy { $0["type"] as? String != "direct" })
    try check("entry private proof uses WG", out[1]["detour"] as? String == P.entryTag && out[1]["tag"] as? String == P.entryPrivateTag)
    try check("proof inlet specifically selects entry private proxy", rules[0]["outbound"] as? String == P.entryPrivateTag)
    try check("entry proof is loopback-only", inbounds[1]["listen"] as? String == "127.0.0.1" && inbounds[1]["listen_port"] as? Int == 1098)
    try check("one system TUN", inbounds.filter { $0["type"] as? String == "tun" }.count == 1 && endpoints[0]["system"] as? Bool == false)
    try check("DNS uses exit, not entry or system", servers.count == 1 && servers[0]["detour"] as? String == "proxy")
    try check("keys remain in owned endpoint", endpoints[0]["private_key"] as? String == key)
    try check("cert stays byte identical", built["cert.pem"] == before["cert.pem"])
    try check("input remains immutable", try files(original(mode)) == before)
    try check("deterministic composition", try build(original(mode), mode:mode) == built)
    if CommandLine.arguments.count == 2 {
        let directory = URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true)
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true)
        try built["sing-box.json"]!.write(to:directory.appendingPathComponent(mode+".json"))
    }
}
var e = entry; e["id"] = "exit"
reject("same displayed node") { _ = try build(original(),e) }
e = entry; e["node_proof_id"] = exit["node_proof_id"]
reject("same identity under different id") { _ = try build(original(),e) }
e = entry; e["node_proof_id"] = String(repeating:"a",count:64)+"\n"
reject("malformed proof id") { _ = try build(original(),e) }
e = entry; e["node_kind"] = "external"
reject("external entry not masquerading as Router") { _ = try build(original(),e) }
for host in ["127.0.0.1", "8.8.8.8", "fd.evil.invalid", "10.77.0.1\u{0}evil", "fd77::1%en0"] {
    e = entry; e["socks_host"] = host
    reject("unsafe private proxy host \(host)") { _ = try build(original(),e) }
}
e = entry; e["socks_username"] = "user"
reject("partial SOCKS credentials") { _ = try build(original(),e) }
e = entry; e["start_layer"] = "aes-256-gcm"
reject("no silent layer omission") { _ = try build(original(),e) }
for (key, value) in [("home_lan_access", false), ("daita_enabled", true), ("jumbo_tun", true)] {
    var unsupportedEntry = entry; unsupportedEntry[key] = value
    reject("do not drop entry policy " + key) { _ = try build(original(), unsupportedEntry) }
    var unsupportedExit = exit; unsupportedExit[key] = value
    reject("do not drop exit policy " + key) { _ = try build(original(), entry, unsupportedExit) }
}
for port: Any in [true, "1080", 0, -1, 65536] {
    e = entry; e["socks_port"] = port
    reject("invalid private proxy port") { _ = try build(original(),e) }
}
for mode in ["wg", "awg2-fast", "reality-vision", "max", "all"] {
    reject("unowned exit \(mode)") { _ = try build(original(),mode:mode) }
}
var invalid = original(); invalid["endpoints"] = [["type":"wireguard"]]
reject("existing endpoint graph") { _ = try build(invalid) }
invalid = original(); invalid["inbounds"] = [["type":"tun","auto_route":true],["type":"mixed","listen_port":1098]]
reject("unowned listener") { _ = try build(invalid) }
for field in ["detour", "bind_interface", "domain_resolver", "routing_mark"] {
    invalid = original(); var out = invalid["outbounds"] as! [[String:Any]]; out[0][field] = "foreign"; invalid["outbounds"] = out
    reject("foreign exit dial ownership \(field)") { _ = try build(invalid) }
}
invalid = original(); invalid["route"] = ["final":"direct"]
reject("wrong final exit") { _ = try build(invalid) }
invalid = original(); var out = invalid["outbounds"] as! [[String:Any]]; out.append(out[0]); invalid["outbounds"] = out
reject("duplicate exit") { _ = try build(invalid) }
invalid = original(); out = invalid["outbounds"] as! [[String:Any]]; out[0]["server"] = "exit.example"; invalid["outbounds"] = out
reject("unproved DNS bootstrap") { _ = try build(invalid) }
invalid = original("hysteria2"); out = invalid["outbounds"] as! [[String:Any]]; out[0]["tls"] = ["enabled":true,"insecure":true]; invalid["outbounds"] = out
reject("HY2 certificate bypass") { _ = try build(invalid,mode:"hysteria2") }
var ep = wg; var peers = ep["peers"] as! [[String:Any]]; peers[0]["allowed_ips"] = ["10.77.0.0/24"]; ep["peers"] = peers
reject("split entry must not become full route silently") { _ = try build(original(),entry,exit,ep) }
var f = try files(original()); f["xray.json"] = Data("{}".utf8)
reject("unowned helper") { _ = try P.build(entryEndpoint:wg,entryProfile:entry,exitProfile:exit,exitMode:"shadowsocks",files:f) }
f = ["sing-box.json":Data(repeating:32,count:4*1024*1024+1)]
reject("oversized config") { _ = try P.build(entryEndpoint:wg,entryProfile:entry,exitProfile:exit,exitMode:"shadowsocks",files:f) }
invalid = original(); invalid["route"] = ["final":"proxy", "rules":[["domain":"example.com", "outbound":"direct"]]]
reject("do not silently erase custom routes") { _ = try build(invalid) }
invalid = original(); var dns = invalid["dns"] as! [String:Any]; dns["rules"] = [["domain":"example.com","server":"other"]]; invalid["dns"] = dns
reject("do not silently erase custom DNS rules") { _ = try build(invalid) }
invalid = original(); var ins = invalid["inbounds"] as! [[String:Any]]; ins[0]["route_exclude_address"] = ["10.0.0.0/8"]; invalid["inbounds"] = ins
reject("do not silently erase split route exclusions") { _ = try build(invalid) }
var v4 = exit; v4["ipv6_mode"] = "off"
let v4Data = try build(original(),entry,v4)["sing-box.json"]!
let v4Root = try JSONSerialization.jsonObject(with:v4Data) as! [String:Any]
let v4Rules = (v4Root["route"] as! [String:Any])["rules"] as! [[String:Any]]
try check("IPv6 Off rejects inside TUN instead of leaking around it", v4Rules.contains { $0["ip_version"] as? Int == 6 && $0["action"] as? String == "reject" })
try check("IPv6 Off selects IPv4 DNS", (v4Root["dns"] as! [String:Any])["strategy"] as? String == "ipv4_only")
var v4Entry = entry; v4Entry["ipv6_mode"] = "off"
let entryV4Data = try build(original(),v4Entry,exit)["sing-box.json"]!
try check("entry IPv6-Off policy is not silently weakened", entryV4Data == v4Data)
if CommandLine.arguments.count == 2 {
    try v4Data.write(to:URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true).appendingPathComponent("shadowsocks-ipv4-only.json"))
}
print("Native iOS multihop graph: PASS (\(checks) executable checks; no node was contacted)")
'''

def main():
    args = argparse.ArgumentParser()
    args.add_argument("--fixture-dir", type=Path)
    args = args.parse_args()
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc is required; a text search cannot certify the multihop graph")
    with tempfile.TemporaryDirectory(prefix="routervpn-multihop-") as directory:
        source, exe = Path(directory) / "main.swift", Path(directory) / "graph-tests"
        source.write_text(TEST)
        subprocess.run([swift, "-swift-version", "6", str(POLICY), str(source), "-o", str(exe)], check=True, timeout=90)
        command = [str(exe)]
        if args.fixture_dir:
            command.append(str(args.fixture_dir.resolve()))
        subprocess.run(command, check=True, timeout=30)
    provider = (POLICY.parent / "PacketTunnelProvider.swift").read_text()
    for required in [
        'case "multihop-libbox": try startMultihop',
        'RouterVPNMultihopGraph.build(entryEndpoint:',
        'deriveNodeProof(from: peer.publicKey.base64Key) == entryProofID',
        'expectedNodeID: entryProofID, proxyPort: RouterVPNMultihopGraph.entryProofPort',
        'expectedNodeID: exitProofID, proxyPort: RouterVPNLibboxEngine.proofProxyPort',
        'self.libboxEngine === engine',
    ]:
        assert required in provider, "shipping proof/ownership chain missing " + required
    start = provider.index('private func startMultihop(')
    end = provider.index('private func startLibbox(', start)
    scope = provider[start:end]
    assert scope.index('expectedNodeID: entryProofID') < scope.index('expectedNodeID: exitProofID') < scope.index('completionHandler(nil)')
    app = ROOT / 'ios/RouterVPN/App'
    model = (app / 'RouterVPNModel.swift').read_text()
    view = (app / 'IOSUnifiedProductView.swift').read_text()
    for required in ['selection.engine == .multihop', 'configuration["entryBundle"]', 'iosMultihopEntryBundle(for: bundle)']:
        assert required in model, required
    assert 'IOSMultihopView().environmentObject(model)' in view
    assert 'selectedProfile?.multihopEnabled == true { Task { await model.connect() }; return }' in view
    print('Graph builder is wired into the real Connect → PacketTunnel → two-node proof path.')

if __name__ == '__main__':
    main()
