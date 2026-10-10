#!/usr/bin/env python3
"""Execute the shipping multihop graph builder offline, with no network mocks.

A --fixture-dir output is also accepted by test_ios_multihop_pinned.sh, which
runs the exact pinned Libbox source's configuration parser in native CI.
"""
from pathlib import Path
import argparse
import os
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
let xrayExitPath = ProcessInfo.processInfo.environment["ROUTERVPN_XRAY_EXIT_FIXTURES"]!
let xrayExits = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath:xrayExitPath))) as! [String:[String:Any]]
@MainActor func original(_ mode: String = "shadowsocks") -> [String:Any] {
    if let native = xrayExits[mode] { return native }
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
        try RouterVPNMTUPolicy.multihop(built,entryProfile:entry,exitProfile:exit)["sing-box.json"]!.write(to:directory.appendingPathComponent(mode+".json"))
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
for (key, value) in [("daita_enabled", true), ("jumbo_tun", true)] {
    var unsupportedEntry = entry; unsupportedEntry[key] = value
    try check("entry performance policy reaches next compiler " + key, try build(original(),unsupportedEntry)["sing-box.json"] != nil)
    var unsupportedExit = exit; unsupportedExit[key] = value
    try check("exit performance policy reaches next compiler " + key, try build(original(),entry,unsupportedExit)["sing-box.json"] != nil)
}
// Exercise the actual private-bundle Codable model before graph validation.
// A raw-dictionary test alone misses flags silently stripped during app import.
func imported(_ raw: [String:Any]) throws -> [String:Any] {
    var profile: [String:Any] = ["name":"fixture", "endpoint":"192.0.2.1",
        "router_api":"http://10.77.0.1:8787", "api_token":"fixture", "adguard_ipv4":"10.77.0.1",
        "adguard_ipv6":"fd77:77::1", "socks_host":"10.77.0.1", "socks_port":1080,
        "socks_username":"", "socks_password":""]
    profile.merge(raw) { _, incoming in incoming }
    let model = try JSONDecoder().decode(RouterProfile.self, from:JSONSerialization.data(withJSONObject:profile))
    return try JSONSerialization.jsonObject(with:JSONEncoder().encode(model)) as! [String:Any]
}
for node in [entry, exit] {
    var lanOff = node; lanOff["home_lan_access"] = false
    lanOff["home_lan_cidrs"] = ["192.168.50.0/24"]
    let captured = try imported(lanOff)
    try check("LAN-Off survives the actual private model", captured["home_lan_access"] as? Bool == false)
    try check("LAN ranges survive the actual private model", captured["home_lan_cidrs"] as? [String] == ["192.168.50.0/24"])
}
let legacyImported = try imported(entry)
try check("legacy import does not invent padding", legacyImported["daita_enabled"] == nil)
try check("legacy import does not invent Jumbo", legacyImported["jumbo_tun"] == nil)
for flag in ["daita_enabled", "jumbo_tun"] {
    for enabled in [true, false] {
        var requested = entry; requested[flag] = enabled
        let roundTrip = try imported(requested)
        try check("import preserves exact \(flag)=\(enabled)", roundTrip[flag] as? Bool == enabled)
        if enabled {
            try check("imported entry performance flag is available", try build(original(),roundTrip)["sing-box.json"] != nil)
            requested = exit; requested[flag] = true
            try check("imported exit performance flag is available", try build(original(),entry,imported(requested))["sing-box.json"] != nil)
        } else {
            try check("false policy keeps graph runnable " + flag, !(try build(original(),roundTrip)).isEmpty)
        }
    }
    var invalidFlag = entry; invalidFlag[flag] = "true"
    reject("nonboolean imported " + flag) { _ = try imported(invalidFlag) }
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
    try RouterVPNMTUPolicy.multihop(["sing-box.json":v4Data],entryProfile:entry,exitProfile:v4)["sing-box.json"]!.write(to:URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true).appendingPathComponent("shadowsocks-ipv4-only.json"))
}

// Nested WG exits are native endpoints, never outbounds mislabeled as proxies.
var wgExit = wg
var wgExitPeer = (wg["peers"] as! [[String:Any]])[0]
wgExitPeer["public_key"] = Data(repeating:2,count:32).base64EncodedString()
wgExitPeer["address"] = "198.51.100.2"
wgExit["private_key"] = Data(repeating:3,count:32).base64EncodedString()
wgExit["peers"] = [wgExitPeer]
var wgExitProfile = exit
wgExitProfile["dns_mode"] = "home"
wgExitProfile["adguard_ipv4"] = "10.77.0.1"
@MainActor func wgFiles(_ ep: [String:Any] = wgExit, _ profile: [String:Any] = wgExitProfile, _ dns: [String] = ["10.77.0.1"]) throws -> [String:Data] {
    try P.wireGuardFiles(endpoint:ep, profile:profile, dnsServers:dns)
}
@MainActor func wgGraph(_ files: [String:Data], _ profile: [String:Any] = wgExitProfile) throws -> [String:Data] {
    try P.build(entryEndpoint:wg,entryProfile:entry,exitProfile:profile,exitMode:"wg",files:files)
}
let nestedInput = try wgFiles()
let nested = try wgGraph(nestedInput)
let nestedRoot = try JSONSerialization.jsonObject(with:nested["sing-box.json"]!) as! [String:Any]
let nestedEndpoints = nestedRoot["endpoints"] as! [[String:Any]]
let nestedOutbounds = nestedRoot["outbounds"] as! [[String:Any]]
let nestedInbounds = nestedRoot["inbounds"] as! [[String:Any]]
let nestedRoute = nestedRoot["route"] as! [String:Any]
let nestedDNS = nestedRoot["dns"] as! [String:Any]
try check("WG has two independently owned endpoints", nestedEndpoints.count == 2 && nestedEndpoints.allSatisfy { $0["type"] as? String == "wireguard" && $0["system"] as? Bool == false })
try check("only entry can dial underlay", nestedEndpoints[0]["detour"] == nil && nestedEndpoints[1]["detour"] as? String == P.entryTag)
try check("public route uses WG exit endpoint", nestedRoute["final"] as? String == "proxy" && nestedEndpoints[1]["tag"] as? String == "proxy")
try check("entry proof alone uses private socks", nestedOutbounds.count == 1 && nestedOutbounds[0]["tag"] as? String == P.entryPrivateTag)
try check("WG key ownership preserved", nestedEndpoints[0]["private_key"] as? String == key && nestedEndpoints[1]["private_key"] as? String == wgExit["private_key"] as? String)
try check("WG DNS traverses exit endpoint", (nestedDNS["servers"] as! [[String:Any]])[0]["detour"] as? String == "proxy")
try check("WG has only one system TUN", nestedInbounds.filter { $0["type"] as? String == "tun" }.count == 1)
try check("WG input remains unchanged", try wgFiles() == nestedInput)
try check("WG output deterministic", try wgGraph(nestedInput) == nested)
reject("same WG server hidden behind distinct node IDs") { _ = try wgGraph(wgFiles(wg)) }
for unsafeHost in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "169.254.1.1", "::", "::1", "ff02::1", "fe80::1", "::ffff:127.0.0.1", "example.com", "fd77::1%en0"] {
    var endpoint = wgExit; var peer = wgExitPeer; peer["address"] = unsafeHost; endpoint["peers"] = [peer]
    reject("unsafe WG exit transport \(unsafeHost)") { _ = try wgGraph(wgFiles(endpoint)) }
    reject("unsafe WG DNS \(unsafeHost)") { _ = try wgFiles(wgExit,[:],[unsafeHost]) }
}
for extra in ["detour", "bind_interface", "routing_mark", "domain_resolver", "workers"] {
    var endpoint = wgExit; endpoint[extra] = "unowned"
    reject("WG imported dial policy \(extra)") { _ = try wgFiles(endpoint) }
}
for (field,value) in [("system",true as Any),("mtu",true as Any),("mtu",1279 as Any),("mtu",9001 as Any),("private_key","bad-key" as Any),("address",["not-a-cidr"] as Any)] {
    var endpoint = wgExit; endpoint[field] = value
    reject("invalid WG endpoint \(field)") { _ = try wgFiles(endpoint) }
}
for (field,value) in [("port",true as Any),("port",65536 as Any),("port",0 as Any),("public_key","bad-key" as Any),("pre_shared_key","bad-key" as Any),("allowed_ips",["0.0.0.0/0"] as Any),("persistent_keepalive_interval",-1 as Any),("persistent_keepalive_interval",65536 as Any)] {
    var endpoint = wgExit;var peer = wgExitPeer;peer[field] = value;endpoint["peers"] = [peer]
    reject("invalid WG peer \(field)") { _ = try wgFiles(endpoint) }
}
var secondPeer = wgExit; secondPeer["peers"] = [wgExitPeer,wgExitPeer]
reject("multiple WG exit peers") { _ = try wgFiles(secondPeer) }
for dns in [[],["10.77.0.1","1.1.1.1"],["8.8.8.8"]] {
    reject("no missing, duplicated or changed selected DNS") { _ = try wgFiles(wgExit,wgExitProfile,dns) }
}
for mode in ["dot","doh","doh3","invented"] {
    var profile = wgExitProfile;profile["dns_mode"] = mode
    reject("do not relabel unsupported native DNS \(mode)") { _ = try wgFiles(wgExit,profile) }
}
var customDNS = wgExitProfile;customDNS["dns_mode"]="custom";customDNS["dns_host"]="10.77.0.1";customDNS["dns_protocol"]="udp"
try check("WG custom UDP53 DNS", try wgFiles(wgExit,customDNS)["sing-box.json"] != nil)
customDNS["dns_port"]=5353
let customPort = try JSONSerialization.jsonObject(with:wgFiles(wgExit,customDNS)["sing-box.json"]!) as! [String:Any]
try check("nonstandard DNS port retained", ((customPort["dns"] as! [String:Any])["servers"] as! [[String:Any]])[0]["server_port"] as? Int == 5353)
customDNS["dns_port"]=53;customDNS["dns_protocol"]="tcp"
let customTCP = try JSONSerialization.jsonObject(with:wgFiles(wgExit,customDNS)["sing-box.json"]!) as! [String:Any]
try check("custom TCP DNS retained", ((customTCP["dns"] as! [String:Any])["servers"] as! [[String:Any]])[0]["type"] as? String == "tcp")
var measuredDNS = wgExitProfile;measuredDNS["dns_mode"]="fastest";measuredDNS["fastest_dns_host"]="10.77.0.1"
try check("WG measured DNS selection", try wgFiles(wgExit,measuredDNS)["sing-box.json"] != nil)
measuredDNS.removeValue(forKey:"fastest_dns_host")
reject("fastest without measurements") { _ = try wgFiles(wgExit,measuredDNS) }
measuredDNS["dns_results"]=[["address":"1.1.1.1","working":false,"latency_ms":1.0],["address":"10.77.0.1","working":true,"latency_ms":3.0]]
try check("WG real successful fastest DNS result", try wgFiles(wgExit,measuredDNS)["sing-box.json"] != nil)
var v6Profile=wgExitProfile;v6Profile["adguard_ipv4"]="";v6Profile["adguard_ipv6"]="fd77:77::1"
try check("WG IPv6 resolver remains inside exit", try wgFiles(wgExit,v6Profile,["fd77:77::1"])["sing-box.json"] != nil)
var bypassRoot = try JSONSerialization.jsonObject(with:nestedInput["sing-box.json"]!) as! [String:Any]
bypassRoot["outbounds"] = [["type":"direct","tag":"direct"]]
reject("WG no alternate direct outbound") { _ = try wgGraph(files(bypassRoot)) }
bypassRoot = try JSONSerialization.jsonObject(with:nestedInput["sing-box.json"]!) as! [String:Any]
bypassRoot["endpoints"] = [wgExit,wgExit]
reject("WG no duplicate exit endpoint") { _ = try wgGraph(files(bypassRoot)) }

// The exact extension graph supports encrypted DNS and its exit-routed bootstrap.
var advancedFixtures: [String:Data] = [:]
for (mode,type,port) in [("dot","tls",853),("doh","https",443),("doh3","h3",443),("custom","tcp",5353)] {
    for host in ["192.0.2.53","resolver.example.test"] {
        var profile = wgExitProfile
        profile["dns_mode"] = mode; profile["dns_protocol"] = "tcp"; profile["dns_host"] = host
        profile["dns_port"] = port; profile["dns_server_name"] = "resolver.example.test"; profile["dns_path"] = "/owned-query"
        let raw = try wgFiles(wgExit,profile)
        let graph = try wgGraph(raw,profile)
        let object = try JSONSerialization.jsonObject(with:graph["sing-box.json"]!) as! [String:Any]
        let dns = object["dns"] as! [String:Any], servers = dns["servers"] as! [[String:Any]]
        let selected = servers.last!
        try check("WG keeps DNS protocol", selected["type"] as? String == type)
        try check("WG keeps selected DNS host and port", selected["server"] as? String == host && selected["server_port"] as? Int == port)
        try check("all DNS dialers use the encrypted exit", servers.allSatisfy { $0["detour"] as? String == "proxy" })
        if !P.literalIP(host) {
            try check("hostname has literal bootstrap", servers.count == 2 && servers[0]["server"] as? String == "10.77.0.1" && selected["domain_resolver"] as? String == servers[0]["tag"] as? String)
        } else { try check("literal DNS needs no bootstrap", servers.count == 1 && selected["domain_resolver"] == nil) }
        if type != "tcp" {
            let tls = selected["tls"] as! [String:Any]
            try check("DNS certificate identity preserved", tls["enabled"] as? Bool == true && tls["server_name"] as? String == "resolver.example.test" && tls["insecure"] == nil)
        }
        if mode == "doh" || mode == "doh3" { try check("encrypted request path preserved", selected["path"] as? String == "/owned-query") }
        var ipv4 = profile; ipv4["ipv6_mode"] = "off"
        let single = try P.singleWireGuardPolicy(raw, profile:ipv4)
        let singleObject = try JSONSerialization.jsonObject(with:single["sing-box.json"]!) as! [String:Any]
        let tuns = singleObject["inbounds"] as! [[String:Any]]
        let rules = (singleObject["route"] as! [String:Any])["rules"] as! [[String:Any]]
        try check("single WG uses one dual-stack captured TUN", tuns.count == 1 && (tuns[0]["address"] as? [String])?.count == 2)
        try check("single IPv6 policy rejects only TUN traffic", rules[0]["inbound"] as? [String] == ["tun-in"] && rules[0]["ip_version"] as? Int == 6 && rules[0]["action"] as? String == "reject")
        try check("single DNS policy also disables AAAA", (singleObject["dns"] as! [String:Any])["strategy"] as? String == "ipv4_only")
        advancedFixtures["wg-dns-"+mode+(P.literalIP(host) ? "-literal" : "-hostname")+".json"] = try RouterVPNMTUPolicy.multihop(graph,entryProfile:entry,exitProfile:profile)["sing-box.json"]!
        advancedFixtures["single-wg-dns-"+mode+(P.literalIP(host) ? "-literal" : "-hostname")+".json"] = try RouterVPNMTUPolicy.libbox(single,profile:ipv4)["sing-box.json"]!
    }
}
var hostnamePolicy = wgExitProfile
hostnamePolicy["dns_mode"]="doh";hostnamePolicy["dns_host"]="resolver.example.test";hostnamePolicy["dns_server_name"]="resolver.example.test"
let hostnameInput = try wgFiles(wgExit,hostnamePolicy)
let hostnameRoot = try JSONSerialization.jsonObject(with:hostnameInput["sing-box.json"]!) as! [String:Any]
for mutation in ["direct-bootstrap","self-reference","missing-bootstrap","duplicate-tag","insecure","wrong-port","custom-rule","wrong-final","hostname-bootstrap","extra-direct"] {
    var changed = hostnameRoot
    var dns = changed["dns"] as! [String:Any], servers = dns["servers"] as! [[String:Any]]
    switch mutation {
    case "direct-bootstrap":servers[0]["detour"]="direct"
    case "self-reference":servers[1]["domain_resolver"]="selected-dns"
    case "missing-bootstrap":servers.removeFirst()
    case "duplicate-tag":servers[0]["tag"]="selected-dns"
    case "insecure":var tls=servers[1]["tls"] as! [String:Any];tls["insecure"]=true;servers[1]["tls"]=tls
    case "wrong-port":servers[1]["server_port"]=true
    case "custom-rule":dns["rules"]=[["query_type":"A","server":"direct"]]
    case "wrong-final":dns["final"]="unowned"
    case "hostname-bootstrap":servers[0]["server"]="another.example.test"
    default:servers.append(["type":"local","tag":"unowned-system"])
    }
    dns["servers"]=servers;changed["dns"]=dns
    reject("unsafe DNS graph " + mutation) { _ = try wgGraph(files(changed),hostnamePolicy) }
}
for (field,value) in [("dns_port",0 as Any),("dns_port",true as Any),("dns_host","https://resolver.example.test" as Any),("dns_host","localhost" as Any),("dns_server_name","" as Any),("dns_path","relative-path" as Any)] {
    var changed = hostnamePolicy;changed["dns_host"]="192.0.2.53";changed[field]=value
    reject("invalid DNS policy " + field) { _ = try wgFiles(wgExit,changed) }
}
for (field,value) in [("ipv6_mode","unrecognized" as Any),("ipv6_mode",true as Any),("jumbo_tun",true as Any)] {
    var changed=wgExitProfile;changed[field]=value
    reject("single graph does not ignore " + field) { _ = try P.singleWireGuardPolicy(nestedInput,profile:changed) }
}
if CommandLine.arguments.count == 2 {
    let directory=URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true)
    for (name,data) in advancedFixtures { try data.write(to:directory.appendingPathComponent(name)) }
}
if CommandLine.arguments.count == 2 {
    let directory=URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true)
    try RouterVPNMTUPolicy.multihop(nested,entryProfile:entry,exitProfile:wgExitProfile)["sing-box.json"]!.write(to:directory.appendingPathComponent("wireguard.json"))
    var ipv4 = wgExitProfile;ipv4["ipv6_mode"]="off"
    let blocked = try wgGraph(wgFiles(wgExit,ipv4),ipv4)
    try RouterVPNMTUPolicy.multihop(blocked,entryProfile:entry,exitProfile:ipv4)["sing-box.json"]!.write(to:directory.appendingPathComponent("wireguard-ipv4-only.json"))
    let blockedRoot=try JSONSerialization.jsonObject(with:blocked["sing-box.json"]!) as! [String:Any]
    let blockedRules=(blockedRoot["route"] as! [String:Any])["rules"] as! [[String:Any]]
    try check("WG IPv6 OFF is a reject route not omission", blockedRules.contains { $0["ip_version"] as? Int == 6 && $0["action"] as? String == "reject" })
}

// Exercise the shipping Swift graph with a real native AWG-shaped entry.
var nativeAWG = wg
nativeAWG["type"] = "routervpn-amneziawg"
nativeAWG["amnezia"] = ["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"]
for exitMode in ["wg","shadowsocks","hysteria2"] {
    let before = try exitMode == "wg" ? wgFiles() : files(original(exitMode))
    let composed = try P.build(entryEndpoint:nativeAWG,entryProfile:entry,exitProfile:wgExitProfile,exitMode:exitMode,files:before)
    let sized = try RouterVPNMTUPolicy.multihop(composed,entryProfile:entry,exitProfile:wgExitProfile)
    let root = try JSONSerialization.jsonObject(with:sized["sing-box.json"]!) as! [String:Any]
    let endpoints = root["endpoints"] as! [[String:Any]]
    try check("AWG entry remains the actual native engine", endpoints[0]["type"] as? String == "routervpn-amneziawg")
    try check("AWG padding is not stripped", endpoints[0]["amnezia"] as? [String:String] == nativeAWG["amnezia"] as? [String:String])
    if CommandLine.arguments.count == 2 {
        try sized["sing-box.json"]!.write(to:URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true).appendingPathComponent("amnezia-entry-"+exitMode+".json"))
    }
}
for mutation in ["missing","wrong-type","overlap","extra"] {
    var changed = nativeAWG
    var params = changed["amnezia"] as! [String:String]
    switch mutation {
    case "missing": params.removeValue(forKey:"s4")
    case "wrong-type": changed["type"]="wireguard"
    case "overlap": params["h2"]=params["h1"]
    default: params["unowned"]="1"
    }
    changed["amnezia"]=params
    reject("invalid native AWG " + mutation) { _ = try P.build(entryEndpoint:changed,entryProfile:entry,exitProfile:wgExitProfile,exitMode:"wg",files:wgFiles()) }
}

// Both AWG strengths are native EXIT transports, never labels over raw WG.
for mode in ["awg2-fast", "awg2-strong"] {
    var exit = wgExit
    exit["type"] = "routervpn-amneziawg"
    var parameters = nativeAWG["amnezia"] as! [String:String]
    if mode == "awg2-strong" { parameters["jc"] = "6"; parameters["s4"] = "48" }
    exit["amnezia"] = parameters
    let input = try wgFiles(exit,wgExitProfile)
    for entryEndpoint in [wg,nativeAWG] {
        let graph = try P.build(entryEndpoint:entryEndpoint,entryProfile:entry,exitProfile:wgExitProfile,exitMode:mode,files:input)
        let sized = try RouterVPNMTUPolicy.multihop(graph,entryProfile:entry,exitProfile:wgExitProfile)
        let root = try JSONSerialization.jsonObject(with:sized["sing-box.json"]!) as! [String:Any]
        let endpoints = root["endpoints"] as! [[String:Any]]
        try check("AWG exit uses real native engine", endpoints.count == 2 && endpoints[1]["type"] as? String == "routervpn-amneziawg")
        try check("exit strength and every native AWG parameter preserved", endpoints[1]["amnezia"] as? [String:String] == parameters)
        try check("AWG exit uses only the selected entry", endpoints[1]["detour"] as? String == endpoints[0]["tag"] as? String)
        try check("AWG peer credentials are retained", JSONSerialization.data(withJSONObject:endpoints[1]["peers"]!,options:[.sortedKeys]) == JSONSerialization.data(withJSONObject:exit["peers"]!,options:[.sortedKeys]))
        let entryMTU = endpoints[0]["mtu"] as! Int
        let padding = Int(parameters["s4"]!)!
        let limit = ((entryMTU - 60 - padding) / 16) * 16
        try check("AWG exit MTU accounts for transport padding", endpoints[1]["mtu"] as? Int == min(exit["mtu"] as! Int,limit))
        if CommandLine.arguments.count == 2 {
            try sized["sing-box.json"]!.write(to:URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true).appendingPathComponent("native-"+(entryEndpoint["type"] as! String)+"-to-"+mode+".json"))
        }
    }
    reject("AWG exit cannot be relabeled as WG") { _ = try P.build(entryEndpoint:wg,entryProfile:entry,exitProfile:wgExitProfile,exitMode:"wg",files:input) }
    for mutation in ["missing-s4", "overlap", "unowned", "bad-peer", "cannot-carry"] {
        var badExit = exit, badParameters = parameters
        switch mutation {
        case "missing-s4": badParameters.removeValue(forKey:"s4")
        case "overlap": badParameters["h2"] = badParameters["h1"]
        case "unowned": badParameters["listen_port"] = "42"
        case "bad-peer": badExit["peers"] = [] as [[String:Any]]
        default: badParameters["s4"] = "1280"
        }
        badExit["amnezia"] = badParameters
        reject("malformed native AWG exit " + mutation) {
            let graph = try P.build(entryEndpoint:wg,entryProfile:entry,exitProfile:wgExitProfile,exitMode:mode,files:wgFiles(badExit,wgExitProfile))
            _ = try RouterVPNMTUPolicy.multihop(graph,entryProfile:entry,exitProfile:wgExitProfile)
        }
    }
}
// Native proxy-entry composition. The entry has no virtual IP interface: it
// remains an outbound while packet exits keep their existing endpoint owner.
let xrayEntryPath = ProcessInfo.processInfo.environment["ROUTERVPN_XRAY_ENTRY_FIXTURES"]!
let xrayEntries = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath:xrayEntryPath))) as! [String:[String:Any]]
@MainActor func proxyInput(_ mode: String) -> [String:Any] {
    if let native = xrayEntries[mode] { return native }

    var result: [String:Any] = ["type":mode,"tag":"compiled-entry","server":"192.0.2.77","server_port":443,"password":key]
    if mode == "shadowsocks" { result["method"]="2022-blake3-aes-256-gcm" }
    else { result["tls"]=["enabled":true,"server_name":"entry.router-vpn.home"]; result["obfs"]=["type":"salamander","password":"entry-only-obfuscation"] }
    return result
}
@MainActor func sameJSON(_ a: Any, _ b: Any) throws -> Bool {
    try JSONSerialization.data(withJSONObject:a,options:[.sortedKeys]) == JSONSerialization.data(withJSONObject:b,options:[.sortedKeys])
}
for entryMode in ["shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp"] {
    let importedEntry = proxyInput(entryMode)
    var expectedEntry = importedEntry; expectedEntry["tag"] = P.entryTag
    try check("all native exit fixtures generated", Set(xrayExits.keys) == Set(P.nativeXrayModes))
    for exitMode in P.supportedExitModes {
        let packetExit = ["wg", "awg2-fast", "awg2-strong"].contains(exitMode)
        var exitEndpoint = wgExit
        if exitMode.hasPrefix("awg2-") {
            exitEndpoint["type"]="routervpn-amneziawg"
            var parameters=nativeAWG["amnezia"] as! [String:String]
            parameters["s4"] = exitMode == "awg2-strong" ? "48" : "32"
            exitEndpoint["amnezia"] = parameters
        }
        let input = try packetExit ? wgFiles(exitEndpoint,wgExitProfile) : files(original(exitMode))
        let graph = try P.build(entryEndpoint:importedEntry,entryProfile:entry,exitProfile:wgExitProfile,exitMode:exitMode,files:input)
        let composed = try RouterVPNMTUPolicy.multihop(graph,entryProfile:entry,exitProfile:wgExitProfile)
        let root = try JSONSerialization.jsonObject(with:composed["sing-box.json"]!) as! [String:Any]
        let out = root["outbounds"] as! [[String:Any]], endpoints = root["endpoints"] as! [[String:Any]]
        let tun = (root["inbounds"] as! [[String:Any]]).filter { $0["type"] as? String == "tun" }
        let actualEntry = out.first { $0["tag"] as? String == P.entryTag }!
        let actualExit = (packetExit ? endpoints : out).first { $0["tag"] as? String == "proxy" }!
        let privateEntry = out.first { $0["tag"] as? String == P.entryPrivateTag }!
        let dns = (root["dns"] as! [String:Any])["servers"] as! [[String:Any]]
        try check("proxy entry credentials and trust retained", sameJSON(actualEntry, expectedEntry))
        try check("proxy entry not mislabeled as a TUN", actualEntry["mtu"] == nil && actualEntry["address"] == nil && actualEntry["system"] == nil)
        try check("entry appears only in outbound manager", endpoints.count == (packetExit ? 1 : 0) && !endpoints.contains { $0["tag"] as? String == P.entryTag })
        try check("one strict system capture path", tun.count == 1 && tun[0]["auto_route"] as? Bool == true && tun[0]["strict_route"] as? Bool == true)
        try check("exit must dial only its captured proxy entry", actualExit["detour"] as? String == P.entryTag && actualEntry["detour"] == nil)
        try check("node proofs do not collapse to one path", privateEntry["detour"] as? String == P.entryTag && privateEntry["server"] as? String == "10.77.0.1")
        try check("resolver remains on exit path", dns.allSatisfy { $0["detour"] as? String == "proxy" })
        try check("no direct fallback inserted", out.allSatisfy { $0["type"] as? String != "direct" })
        try check("proxy input remains immutable", sameJSON(importedEntry, proxyInput(entryMode)))
        try check("entry assets cannot overwrite exit files", composed["cert.pem"] == input["cert.pem"])
        try check("proxy composition deterministic", try P.build(entryEndpoint:importedEntry,entryProfile:entry,exitProfile:wgExitProfile,exitMode:exitMode,files:input) == graph)
        if P.nativeXrayModes.contains(exitMode) {
            let reference = (xrayExits[exitMode]!["outbounds"] as! [[String:Any]]).first { $0["type"] as? String == "routervpn-xray" }!
            try check("native exit retains exact compiled authentication", actualExit["config_json"] as? String == reference["config_json"] as? String)
            try check("native exit retains its requested mode", actualExit["mode"] as? String == exitMode)
            var expectedExit = reference; expectedExit["detour"] = P.entryTag
            try check("native exit changes only its owned detour", sameJSON(actualExit, expectedExit))
            reject("old generic proxy fixture cannot masquerade as Xray") {
                _ = try P.build(entryEndpoint:importedEntry,entryProfile:entry,exitProfile:wgExitProfile,exitMode:exitMode,files:files(original()))
            }
        }
        if packetExit {
            try check("proxy does not impose an invented outer WG MTU", actualExit["mtu"] as? Int == exitEndpoint["mtu"] as? Int)
            try check("native encrypted exit credentials retained", sameJSON(actualExit["peers"]!,exitEndpoint["peers"]!))
        }
        for fixed in [1280,1500,9000] {
            var fixedEntry=entry; fixedEntry["mtu_policy"]="fixed";fixedEntry["manual_mtu"]=fixed
            let sized = try RouterVPNMTUPolicy.multihop(graph,entryProfile:fixedEntry,exitProfile:wgExitProfile)
            let sizedRoot = try JSONSerialization.jsonObject(with:sized["sing-box.json"]!) as! [String:Any]
            let sizedTun = (sizedRoot["inbounds"] as! [[String:Any]]).first { $0["type"] as? String == "tun" }!
            try check("entry fixed value owns the actual TUN", sizedTun["mtu"] as? Int == fixed)
            try check("MTU never rewrites proxy credentials or trust", sameJSON(sizedRoot["outbounds"]!, root["outbounds"]!))
            try check("MTU projection idempotent", try RouterVPNMTUPolicy.multihop(sized,entryProfile:fixedEntry,exitProfile:wgExitProfile) == sized)
            if packetExit {
                try check("fixed proxy TUN agrees with packet exit MTU", (sizedRoot["endpoints"] as! [[String:Any]])[0]["mtu"] as? Int == fixed)
            }
            var conflictingExit=wgExitProfile;conflictingExit["mtu_policy"]="fixed";conflictingExit["manual_mtu"]=fixed == 1500 ? 1400 : 1500
            reject("conflicting fixed values cannot silently win") { _ = try RouterVPNMTUPolicy.multihop(graph,entryProfile:fixedEntry,exitProfile:conflictingExit) }
        }
        var staleEntry=entry;staleEntry["effective_mtu"]=9000
        var staleExit=wgExitProfile;staleExit["effective_mtu"]=9000
        try check("stale measurements cannot replace current interface policy", try RouterVPNMTUPolicy.multihop(graph,entryProfile:staleEntry,exitProfile:staleExit) == composed)
        for changed in ["entry-duplicate", "packet-duplicate", "wrong-manager", "wrong-detour", "fake-mtu"] {
            var broken=root
            switch changed {
            case "entry-duplicate": broken["outbounds"] = out + [actualEntry]
            case "packet-duplicate": var bad=wg;bad["tag"]=P.entryTag;broken["endpoints"]=endpoints+[bad]
            case "wrong-manager": var bad=actualEntry;bad["type"]="socks";broken["outbounds"]=out.filter { $0["tag"] as? String != P.entryTag }+[bad]
            case "wrong-detour": var bad=actualEntry;bad["detour"]="bypass";broken["outbounds"]=out.filter { $0["tag"] as? String != P.entryTag }+[bad]
            default: var bad=actualEntry;bad["mtu"]=1500;broken["outbounds"]=out.filter { $0["tag"] as? String != P.entryTag }+[bad]
            }
            reject("MTU rejects lost proxy ownership " + changed) { _ = try RouterVPNMTUPolicy.multihop(files(broken),entryProfile:entry,exitProfile:wgExitProfile) }
        }
        if CommandLine.arguments.count == 2 {
            try composed["sing-box.json"]!.write(to:URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true).appendingPathComponent("proxy-"+entryMode+"-to-"+exitMode+".json"))
        }
    }
    for (field,value) in [("server", "localhost" as Any), ("server", "127.0.0.1" as Any), ("server_port",true as Any), ("server_port",0 as Any), ("server_port",65536 as Any), ("server_port",443.5 as Any), ("password","" as Any), ("password","bad\u{0}secret" as Any), ("network","tcp" as Any), ("mtu",1500 as Any), ("detour","bypass" as Any), ("bind_interface","en0" as Any), ("system",true as Any), ("certificate_path","entry.pem" as Any)] {
        var broken=importedEntry;broken[field]=value
        reject("malformed proxy entry " + field) { _ = try build(original(), entry, exit, broken) }
    }
    if entryMode == "hysteria2" {
        for tls in [["enabled":false], ["enabled":true,"insecure":true], ["enabled":true,"certificate_path":"entry.pem"], ["enabled":true,"nested":["path":"/unowned"]]] as [[String:Any]] {
            var broken=importedEntry;broken["tls"]=tls
            reject("unverified or file-backed proxy TLS") { _ = try build(original(), entry, exit, broken) }
        }
    } else {
        var broken=importedEntry;broken["method"]="none"
        reject("unauthenticated proxy cipher") { _ = try build(original(), entry, exit, broken) }
    }
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
        native_entries = Path(directory) / "xray-entry-fixtures.json"
        with native_entries.open("w") as output:
            subprocess.run(["go", "run", "./deploy/testfixtures/xray-entry"], cwd=ROOT, stdout=output, check=True, timeout=90)
        native_exits = Path(directory) / "xray-exit-fixtures.json"
        with native_exits.open("w") as output:
            subprocess.run(["go", "run", "./deploy/testfixtures/xray-entry", "--exits"], cwd=ROOT, stdout=output, check=True, timeout=90)
        env = dict(os.environ, ROUTERVPN_XRAY_ENTRY_FIXTURES=str(native_entries), ROUTERVPN_XRAY_EXIT_FIXTURES=str(native_exits))
        source.write_text(TEST)
        subprocess.run([swift, "-swift-version", "6", str(POLICY), str(POLICY.with_name("RouterVPNMTUPolicy.swift")), str(ROOT / "ios/RouterVPN/App/Models.swift"), str(source), "-o", str(exe)], check=True, timeout=90)
        command = [str(exe)]
        if args.fixture_dir:
            command.append(str(args.fixture_dir.resolve()))
        subprocess.run(command, env=env, check=True, timeout=30)
    provider = (POLICY.parent / "PacketTunnelProvider.swift").read_text()
    for required in [
        'case "multihop-libbox": try startMultihop',
        'RouterVPNMultihopGraph.build(entryEndpoint:',
        'RouterVPNMTUPolicy.multihop(files, entryProfile: entryProfile, exitProfile: exitProfile)',
        'deriveNodeProof(from: peer.publicKey.base64Key) == expectedProofID',
        'multihopWireGuardEndpoint(root: entryRoot, expectedProofID: entryProofID',
        'multihopWireGuardEndpoint(root: root, expectedProofID: exitProofID',
        'RouterVPNMultihopGraph.wireGuardFiles(endpoint: exit.endpoint',
        'expectedNodeID: entryProofID, proxyPort: RouterVPNMultihopGraph.entryProofPort',
        'expectedNodeID: exitProofID, proxyPort: RouterVPNLibboxEngine.proofProxyPort',
        'self.libboxEngine === engine',
        'LibboxRouterCompileProxyEntry(',
        'LibboxRouterMultihopMTUProfile(',
        'JSONSerialization.jsonObject(with: mtuProfileData)',
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
