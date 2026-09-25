#!/usr/bin/env python3
"""Execute shipping Apple Xray graph selection and DNS composition, offline.

The actual Xray parser/transport is tested separately against pinned core source.
This suite tests host graph policy using production Swift, not copied functions.
"""
from pathlib import Path
import importlib.util
import platform
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('native_base_fixture',ROOT/'deploy/test_ios_native_base_selection.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
FIXTURE=base.TEST[base.TEST.index('func json('):base.TEST.index('@main struct Tests')]
TEST=r'''
import Foundation
func xray(_ mode: String) throws -> Data {
    var user: [String:Any] = ["id":"11111111-1111-4111-8111-111111111111","flow":"xtls-rprx-vision","encryption":"none"]
    var stream: [String:Any] = ["network":"raw","security":"reality","realitySettings":["serverName":"www.example.com","fingerprint":"chrome","password":"fixture-public-key","shortId":"0123456789abcdef"]]
    if ["reality-pq-vision","reality-xhttp","max"].contains(mode) { user["encryption"]="mlkem768x25519plus.native.0rtt.fixture" }
    if mode == "reality-xhttp" { user.removeValue(forKey:"flow");stream["network"]="xhttp";stream["xhttpSettings"]=["path":"/assets/sync","mode":"auto"];stream["finalmask"]=["tcp":[["type":"fragment","settings":["packets":"tlshello","length":"100-300","delay":"10-30","maxSplit":"3-7"]]]] }
    return try json(["log":["loglevel":"warning"],"inbounds":[["protocol":"socks","tag":"local","listen":"127.0.0.1","port":1090,"settings":["auth":"noauth","udp":true]]],"outbounds":[["tag":"proxy","protocol":"vless","settings":["vnext":[["address":"192.0.2.1","port":443,"users":[user]]]],"streamSettings":stream]]])
}
func xrayBundle(_ mode: String, dns: String = "home") throws -> ClientBundle {
    var value = try fixture(dns:dns)
    let paired = mode == "split" || mode == "max"
    let tag = paired ? "tcp-stack" : "proxy"
    var config: [String:Any] = ["inbounds":[["type":"tun","auto_route":true,"strict_route":true]],"outbounds":[["type":"socks","tag":tag,"server":"127.0.0.1","server_port":1090,"version":"5"]],"route":["final":tag],"dns":["servers":[["type":"udp","tag":"home","server":"10.77.0.1","detour":tag]]]]
    if paired {
        var outgoing = config["outbounds"] as! [[String:Any]]
        outgoing.append(["type":"hysteria2","tag":"udp-stack","server":"192.0.2.1","server_port":8443,"password":"fixture","tls":["enabled":true,"server_name":"www.example.com"]])
        config["outbounds"] = outgoing
        config["route"] = ["rules":[["network":"tcp","outbound":"tcp-stack"],["network":"udp","outbound":"udp-stack"]],"final":"tcp-stack"]
    }
    var assets = ["xray.json":try xray(mode).base64EncodedString()]
    if mode != "reality-xhttp" { assets["sing-box.json"] = try json(config).base64EncodedString() }
    value.profiles[mode] = assets
    value.logicalModes.append(LogicalMode(id:mode,name:mode,description:"",baseSelector:false,fallback:false,variants:["native":mode]))
    return value
}
@main struct Tests {
    @MainActor static var checks = 0
    @MainActor static func check(_ name: String, _ value: @autoclosure () throws -> Bool) throws {
        guard try value() else { fatalError("FAIL: "+name) }; checks += 1
    }
    @MainActor static func reject(_ name: String, _ operation: () throws -> Void) {
        do { try operation();fatalError("Accepted "+name) } catch { checks += 1 }
    }
    @MainActor static func main() throws {
        for mode in ["reality-vision","reality-pq-vision","reality-xhttp","split","max"] {
            for dns in ["home","custom","dot","doh","doh3","rescue"] {
                let original = try xrayBundle(mode,dns:dns)
                let patched = try IOSDNSRuntimePolicy.patch(original)
                let selection = try IOSRuntimeSelector.selectRaw(bundle:patched,rawProfileID:mode)
                try check("native engine selected \\(mode)", selection.engine == .libbox)
                let config = try JSONSerialization.jsonObject(with:selection.files["sing-box.json"]!) as! [String:Any]
                let outgoing = config["outbounds"] as! [[String:Any]]
                let native = outgoing.filter { $0["type"] as? String == IOSNativeXrayProfile.nativeType }
                try check("one exact native Xray outbound", native.count == 1 && native[0]["mode"] as? String == mode)
                try check("raw security JSON not rewritten", native[0]["config_json"] as? String == String(data:selection.files["xray.json"]!,encoding:.utf8))
                let dnsObject = config["dns"] as! [String:Any]
                let servers = dnsObject["servers"] as! [[String:Any]]
                let expected = mode == "split" || mode == "max" ? "tcp-stack" : "proxy"
                try check("DNS never escapes the native route", servers.allSatisfy { $0["detour"] as? String == expected })
                let types = ["home":"udp","custom":"udp","dot":"tls","doh":"https","doh3":"h3","rescue":"udp"]
                try check("selected DNS protocol preserved", servers.last?["type"] as? String == types[dns])
                try check("saved composition is idempotent", IOSDNSRuntimePolicy.patch(patched).profiles == patched.profiles)
                if mode == "split" || mode == "max" {
                    try check("independent UDP stack survives", outgoing.contains { $0["type"] as? String == "hysteria2" && $0["tag"] as? String == "udp-stack" })
                    let rules = (config["route"] as! [String:Any])["rules"] as! [[String:Any]]
                    try check("TCP and UDP route split survives", rules.contains { $0["network"] as? String == "udp" && $0["outbound"] as? String == "udp-stack" })
                }
            }
            var invalid = try xrayBundle(mode)
            invalid.profiles[mode]?["chain.env"] = Data("exec forbidden".utf8).base64EncodedString()
            reject("unowned extra helper") { _ = try IOSRuntimeSelector.selectRaw(bundle:invalid,rawProfileID:mode) }
        }
        var ordinary = try xrayBundle("reality-vision")
        ordinary.profiles["reality-pq-vision"] = ordinary.profiles["reality-vision"]
        reject("ordinary encryption cannot acquire PQ label") { _ = try IOSRuntimeSelector.selectRaw(bundle:ordinary,rawProfileID:"reality-pq-vision") }
        var wrong = try xrayBundle("reality-vision")
        let wrapper = String(data:Data(base64Encoded:wrong.profiles["reality-vision"]!["sing-box.json"]!)!,encoding:.utf8)!
        wrong.profiles["reality-vision"]?["sing-box.json"] = Data(wrapper.replacingOccurrences(of:"1090",with:"1091").utf8).base64EncodedString()
        reject("wrong local listener") { _ = try IOSRuntimeSelector.selectRaw(bundle:wrong,rawProfileID:"reality-vision") }
        print("Apple native Xray profile/DNS composition: PASS (\(checks) checks)")
    }
}
'''

def main():
    swift=shutil.which('swiftc')
    if not swift:raise SystemExit('swiftc is required for native profile integration tests')
    with tempfile.TemporaryDirectory(prefix='routervpn-xray-profiles-') as tmp:
        tmp=Path(tmp);dns=APP/'IOSDNSRuntimePolicy.swift'
        if platform.system()!='Darwin':
            text=dns.read_text();dns=tmp/dns.name;dns.write_text(text.replace('import Network\n',base.NETWORK_SHIM))
        tests=tmp/'Tests.swift';tests.write_text('import Foundation\n'+FIXTURE+TEST)
        executable=tmp/'tests'
        subprocess.run([swift,'-swift-version','6',str(APP/'Models.swift'),str(dns),str(APP/'IOSNativeXrayProfile.swift'),str(APP/'IOSRuntimeSelection.swift'),str(tests),'-o',str(executable)],check=True,timeout=90)
        subprocess.run([str(executable)],check=True,timeout=25)
    source=(APP/'RouterVPNModel.swift').read_text()
    assert 'launchBundle.profiles[selection.rawProfileID] = launchFiles.mapValues' in source
    assert 'LibboxRouterResolveXrayProfile' in source
    assert 'self.bundle?.profiles == bundle.profiles' in source
    assert '"bundle": try JSONEncoder().encode(launchBundle)' in source
    provider=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
    start=provider.index('private func startLibbox(');end=provider.index('private func startExternalLibbox(',start)
    body=provider[start:end]
    assert body.index('LibboxRouterCompileXrayProfile') < body.index('IOSStartLayer.apply') < body.index('engine.start(')
    print('Pure host policy uses production Swift; native core parsing/transport is a separate mandatory pinned-engine gate.')

if __name__=='__main__':main()
