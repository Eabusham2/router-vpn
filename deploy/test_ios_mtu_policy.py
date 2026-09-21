#!/usr/bin/env python3
"""Execute the fixed-MTU policy used by the shipping PacketTunnel, offline."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "ios/RouterVPN/PacketTunnel/RouterVPNMTUPolicy.swift"
TEST = r'''
import Foundation

typealias P = RouterVPNMTUPolicy
var checks = 0
@MainActor func check(_ name: String, _ body: @autoclosure () throws -> Bool) throws {
    guard try body() else { fatalError("FAILED " + name) }
    checks += 1
}
@MainActor func reject(_ name: String, _ body: () throws -> Void) {
    do { try body(); fatalError("Accepted invalid " + name) } catch { checks += 1 }
}
func sameJSON(_ a: Any, _ b: Any) throws -> Bool {
    try JSONSerialization.data(withJSONObject:a, options:[.sortedKeys]) == JSONSerialization.data(withJSONObject:b, options:[.sortedKeys])
}
func fixed(_ value: Any) -> [String: Any] { ["mtu_policy": "manual", "manual_mtu": value] }
let source = "[Interface]\nPrivateKey = preserve-key\nAddress = 10.77.0.2/32, fd77:77::2/128\nMTU = 1420\nDNS = 10.77.0.1\n[Peer]\nPublicKey = preserve-peer\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
try check("default byte identity", P.wireGuard(source, profile: [:]) == source)
try check("auto ignores stale effective MTU", P.wireGuard(source, profile: ["mtu_policy":"auto", "effective_mtu":9000]) == source)
try check("runtime default byte identity", P.wireGuard(source, profile: ["mtu_policy":"default"]) == source)
for value in [1280, 1380, 1420, 1500, 9000] {
    let patched = try P.wireGuard(source, profile: fixed(value))
    try check("only interface MTU changed", patched == source.replacingOccurrences(of:"MTU = 1420", with:"MTU = \(value)"))
    try check("repeat application idempotent", P.wireGuard(patched, profile: fixed(value)) == patched)
}
let absent = source.replacingOccurrences(of:"MTU = 1420\n", with:"")
try check("insert missing MTU", P.wireGuard(absent, profile: fixed(1300)) == absent.replacingOccurrences(of:"[Interface]\n", with:"[Interface]\nMTU = 1300\n"))
let commented = source.replacingOccurrences(of:"MTU = 1420", with:"  mtu = 1420 # old mtu")
try check("case insensitive exact key", P.wireGuard(commented, profile: fixed(1300)).contains("MTU = 1300\n"))
let crlf = source.replacingOccurrences(of:"\n", with:"\r\n")
try check("CRLF accepted", P.wireGuard(crlf, profile: fixed(1400)) == crlf.replacingOccurrences(of:"MTU = 1420", with:"MTU = 1400"))
let awg = source.replacingOccurrences(of:"[Interface]\n", with:"[Interface]\nJc=4\nJmin=40\nJmax=70\nS1=40\nS2=60\nS3=0\nS4=0\nH1=11111\nH2=22222\nH3=33333\nH4=44444\n")
try check("AWG parameters preserved", P.wireGuard(awg, profile:fixed(1380)) == awg.replacingOccurrences(of:"MTU = 1420",with:"MTU = 1380"))
for value: Any in [0, -1, 576, 1279, 9001, 65535, true, "1400", 1400.5] {
    reject("bad fixed MTU \(value)") { _ = try P.fixedMTU(profile: fixed(value)) }
}
reject("missing fixed MTU") { _ = try P.fixedMTU(profile:["mtu_policy":"manual"]) }
reject("unknown policy") { _ = try P.fixedMTU(profile:["mtu_policy":"ignore-me"]) }
reject("missing interface") { _ = try P.wireGuard("[Peer]\nMTU=1420", profile:fixed(1400)) }
reject("duplicate MTU") { _ = try P.wireGuard(source.replacingOccurrences(of:"MTU = 1420", with:"MTU=1420\nMTU=1500"), profile:fixed(1400)) }
reject("duplicate interface") { _ = try P.wireGuard(source + "[Interface]\nMTU=1400", profile:fixed(1400)) }
reject("oversized WG") { _ = try P.wireGuard(String(repeating:" ", count:4*1024*1024+1), profile:fixed(1400)) }
let root: [String: Any] = [
    "inbounds": [["type":"tun", "tag":"tun-in", "mtu":1420, "address":["172.29.94.1/30", "fd29:94::1/126"]], ["type":"mixed", "listen_port":1099]],
    "endpoints": [["type":"wireguard", "tag":"exit", "mtu":1420, "private_key":"preserve-key", "peers":[["public_key":"preserve-peer"]]]],
    "outbounds": [["type":"shadowsocks", "tag":"proxy", "server":"192.0.2.1", "password":"preserve-secret"]],
    "route": ["final":"exit"], "dns":["final":"selected-dns"]
]
func files(_ object: [String: Any]) throws -> [String: Data] {
    ["sing-box.json":try JSONSerialization.data(withJSONObject:object), "ca.pem":Data("keep certificate".utf8)]
}
let originalFiles = try files(root)
try check("default file identity", P.libbox(originalFiles, profile:[:]) == originalFiles)
let patchedFiles = try P.libbox(originalFiles, profile:fixed(1380))
let patchedRoot = try JSONSerialization.jsonObject(with:patchedFiles["sing-box.json"]!) as! [String:Any]
let inbounds = patchedRoot["inbounds"] as! [[String:Any]]
let endpoints = patchedRoot["endpoints"] as! [[String:Any]]
try check("OS TUN MTU applied", inbounds[0]["mtu"] as? Int == 1380)
try check("WG userspace TUN MTU applied", endpoints[0]["mtu"] as? Int == 1380)
try check("proxy untouched", sameJSON(inbounds[1], (root["inbounds"] as! [[String:Any]])[1]))
try check("secrets preserved", endpoints[0]["private_key"] as? String == "preserve-key")
try check("DNS and routes preserved", sameJSON(patchedRoot["route"]!, root["route"]!) && sameJSON(patchedRoot["dns"]!, root["dns"]!))
try check("non-config assets preserved", patchedFiles["ca.pem"] == originalFiles["ca.pem"])
try check("patch leaves original immutable", (try JSONSerialization.jsonObject(with:originalFiles["sing-box.json"]!) as! [String:Any])["inbounds"] is [[String:Any]] && (((try JSONSerialization.jsonObject(with:originalFiles["sing-box.json"]!) as! [String:Any])["inbounds"] as! [[String:Any]])[0]["mtu"] as? Int) == 1420)
try check("JSON patch idempotent", P.libbox(patchedFiles, profile:fixed(1380)) == patchedFiles)
reject("missing config") { _ = try P.libbox([:], profile:fixed(1400)) }
reject("invalid JSON") { _ = try P.libbox(["sing-box.json":Data("false".utf8)], profile:fixed(1400)) }
reject("no TUN") { _ = try P.libbox(files(["inbounds":[["type":"mixed"]]]), profile:fixed(1400)) }
reject("ambiguous TUNs") { _ = try P.libbox(files(["inbounds":[["type":"tun"],["type":"tun"]]]), profile:fixed(1400)) }
print("iOS fixed-MTU executable policy: PASS (\(checks) checks)")
'''


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc required for native fixed-MTU behavior tests")
    provider = (POLICY.parent / "PacketTunnelProvider.swift").read_text()
    for call in (
        "RouterVPNMTUPolicy.wireGuard(wireGuardLikeProfile(root, rawProfileID: requestedMode), profile: selectedProfile)",
        "RouterVPNMTUPolicy.libbox(composedFiles, profile: selectedProfile)",
        "RouterVPNMTUPolicy.libbox(runtime.files, profile: selectedProfile)",
    ):
        assert call in provider, "fixed MTU is not connected to the shipping native engine: " + call
    for name in ("IOSProfileSettingsView.swift", "IOSConnectionProfilesView.swift"):
        source = (ROOT / "ios/RouterVPN/App" / name).read_text()
        assert "(1280...9000).contains(" in source, name + ": UI/import range differs from dual-stack native TUN"
    with tempfile.TemporaryDirectory(prefix="routervpn-mtu-") as tmp:
        test, binary = Path(tmp) / "main.swift", Path(tmp) / "mtu-tests"
        test.write_text(TEST)
        subprocess.run([swift, "-swift-version", "6", str(POLICY), str(test), "-o", str(binary)], check=True, timeout=90)
        subprocess.run([str(binary)], check=True, timeout=20)
    print("Fixed MTU applies to raw WireGuard/AmneziaWG, Router Libbox, and external Libbox; no live network used.")


if __name__ == "__main__":
    main()
