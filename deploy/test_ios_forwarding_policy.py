#!/usr/bin/env python3
"""Execute the shipping Swift forwarding policy; never contact a node or mutate it."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SWIFT = ROOT / "ios/RouterVPN/PacketTunnel/RouterVPNForwardingPolicy.swift"
TEST = r'''
import Foundation

typealias P = RouterVPNForwardingPolicy
var checks = 0
@MainActor
func check(_ name: String, _ test: @autoclosure () throws -> Bool) throws {
    guard try test() else { fatalError("FAIL: " + name) }
    checks += 1
}
@MainActor
func reject(_ name: String, _ body: () throws -> Void) {
    do { try body(); fatalError("Accepted invalid case: " + name) }
    catch { checks += 1 }
}
func json(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: value) }
let proofID = String(repeating: "a", count: 64)
let token = String(repeating: "b", count: 64)
let profile: [String: Any] = ["node_kind":"router-vpn", "id":"home", "router_api":"http://10.77.0.1:8787", "api_token":token]
let endpoint = try P.Endpoint(profile: profile, proofID: proofID)
let lease = UUID().uuidString
let get = try P.decode(json(["version":1,"action":"get","node_id":"home"]))
try P.authorize(get, endpoint: endpoint, sessionID: lease)
try check("private IPv4", endpoint.host == "10.77.0.1" && endpoint.port == 8787)
var v6 = profile; v6["router_api"] = "http://[fd77:77::1]:8787"
try check("private IPv6 authority", P.Endpoint(profile: v6, proofID: proofID).authority == "[fd77:77::1]:8787")
for host in ["https://10.77.0.1:8787", "http://8.8.8.8:8787", "http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787", "http://[::ffff:127.0.0.1]:8787", "http://[fe80::1]:8787", "http://169.254.1.1:8787", "http://name.invalid:8787", "http://u:p@10.77.0.1:8787", "http://10.77.0.1:8787/admin", "http://10.77.0.1:8787?x=1", "http://10.77.0.1:8787#x", "http://10.77.0.1:0", "http://fd.attacker.invalid:8787", "http://fc.attacker.invalid:8787", "http://10.bad.0.0.1:8787", "http://10.0.0.1.attacker.invalid:8787", "http://[fd77::1%25en0]:8787", "http://[fd77::1%en0]:8787", "http://%31%30.77.0.1:8787", "http://10.77.0.1:8787\n", "http://10.77.0.1:8787\u{0000}"] {
    reject("unsafe API \(host)") { var value=profile; value["router_api"]=host; _=try P.Endpoint(profile:value,proofID:proofID) }
}
reject("external node") { var value=profile; value["node_kind"]="external"; _=try P.Endpoint(profile:value,proofID:proofID) }
reject("embedded external credentials") { var value=profile; value["external"]=["protocol":"socks5"]; _=try P.Endpoint(profile:value,proofID:proofID) }
reject("header injection") { var value=profile; value["api_token"]=token+"\r\nX: y"; _=try P.Endpoint(profile:value,proofID:proofID) }
reject("missing node identity") { _=try P.Endpoint(profile:profile,proofID:"") }
reject("future version") { _=try P.decode(json(["version":2,"action":"get","node_id":"home"])) }
reject("URL in IPC") { _=try P.decode(json(["version":1,"action":"get","node_id":"home","url":"http://10.77.0.2"])) }
reject("secret in IPC") { _=try P.decode(json(["version":1,"action":"get","node_id":"home","token":"secret"])) }
reject("arbitrary admin action") { _=try P.decode(json(["version":1,"action":"dmz","node_id":"home"])) }
reject("read contains mutation") { _=try P.decode(json(["version":1,"action":"get","node_id":"home","enabled":true])) }
reject("set without lease") { _=try P.decode(json(["version":1,"action":"set","node_id":"home","enabled":true])) }
reject("nonboolean set") { _=try P.decode(json(["version":1,"action":"set","node_id":"home","session_id":lease,"enabled":1])) }
reject("oversized IPC") { _=try P.decode(Data(repeating:32,count:4097)) }
let set = try P.decode(json(["version":1,"action":"set","node_id":"home","session_id":lease,"enabled":false]))
try P.authorize(set, endpoint:endpoint,sessionID:lease)
reject("reconnected session") { try P.authorize(set,endpoint:endpoint,sessionID:UUID().uuidString) }
reject("wrong node") { let wrong=try P.decode(json(["version":1,"action":"get","node_id":"other"]));try P.authorize(wrong,endpoint:endpoint,sessionID:lease) }
let proofRequest=String(decoding:P.request(endpoint:endpoint,proof:true),as:UTF8.self)
try check("proof has no secret", !proofRequest.contains(token) && proofRequest.hasPrefix("GET /health HTTP/1.1"))
let put=String(decoding:P.request(endpoint:endpoint,enabled:false),as:UTF8.self)
try check("fixed route", put.hasPrefix("PUT /api/forwarding/master HTTP/1.1"))
try check("bounded boolean payload", put.hasSuffix("{\"enabled\":false}") && put.contains("Content-Length: 17\r\n"))
try check("private credential", put.contains("Authorization: Bearer " + token))
func wire(_ body: Data, status: String="200 OK", extra: String="") -> Data {
    Data("HTTP/1.1 \(status)\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\n\(extra)\r\n".utf8)+body
}
let on=try json(["ok":true,"enabled":true]), off=try json(["ok":true,"enabled":false])
try check("readback on", P.master(P.response(wire(on)),expected:true))
try check("readback off", !P.master(P.response(wire(off)),expected:false))
reject("wrong returned state") { _=try P.master(P.response(wire(off)),expected:true) }
reject("nonboolean response") { _=try P.master(["ok":true,"enabled":1]) }
reject("missing master field") { _=try P.master(["ok":true]) }
reject("redirect forbidden") { _=try P.response(wire(on,status:"302 Found",extra:"Location: http://example.com\r\n")) }
reject("server refusal") { _=try P.response(wire(on,status:"403 Forbidden")) }
reject("duplicate length") { _=try P.response(wire(on,extra:"Content-Length: \(on.count)\r\n")) }
reject("ambiguous chunking") { _=try P.response(wire(on,extra:"Transfer-Encoding: chunked\r\n")) }
reject("encoded body") { _=try P.response(wire(on,extra:"Content-Encoding: gzip\r\n")) }
reject("truncated body") { _=try P.response(wire(on).dropLast()) }
reject("trailing response") { _=try P.response(wire(on)+Data("extra".utf8)) }
reject("oversized response") { _=try P.response(Data(repeating:32,count:P.maxResponse+1)) }
try P.verifyProof(["ok":true,"node_id":proofID,"proof":"router-vpn-private-agent-v1"],endpoint:endpoint)
reject("wrong private proof") { try P.verifyProof(["ok":true,"node_id":String(repeating:"c",count:64),"proof":"router-vpn-private-agent-v1"],endpoint:endpoint) }
let reply=String(decoding:P.reply(sessionID:lease,nodeID:"home",enabled:true),as:UTF8.self)
try check("reply contains no credential", !reply.contains(token) && reply.contains(lease))
print("iOS forwarding executable policy tests: PASS (\(checks) checks)")
'''


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc required: run this executable policy gate on the macOS native lane")
    with tempfile.TemporaryDirectory(prefix="routervpn-forwarding-") as tmp:
        test = Path(tmp) / "main.swift"
        exe = Path(tmp) / "forwarding-tests"
        test.write_text(TEST)
        subprocess.run([swift, "-swift-version", "6", str(SWIFT), str(test), "-o", str(exe)], check=True, timeout=90)
        subprocess.run([str(exe)], check=True, timeout=15)
    subprocess.run([sys.executable, str(ROOT / "deploy/test_ios_forwarding_ui.py")], check=True, timeout=150)
    print("No VPN or server networking was used by these tests.")


if __name__ == "__main__":
    main()
