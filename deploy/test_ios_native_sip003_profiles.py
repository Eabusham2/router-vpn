#!/usr/bin/env python3
"""Exercise the shipping iOS native SIP003 selection and DNS policy, offline."""
from pathlib import Path
import importlib.util, platform, shutil, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[1];APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('base_fixture',ROOT/'deploy/test_ios_native_base_selection.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
FIXTURE=base.TEST[base.TEST.index('func json('):base.TEST.index('@main struct Tests')]
TEST=r"""
import Foundation
func sipBundle(_ dns: String = "home", host: String = "1.1.1.1") throws -> ClientBundle {
    var bundle = try fixture(dns:dns)
    bundle.routerProfiles[0].dnsHost = host
    let helper: [String:Any] = ["server":"192.0.2.1","server_port":10443,"password":Data(repeating:7,count:32).base64EncodedString(),"method":"2022-blake3-aes-256-gcm","local_address":"127.0.0.1","local_port":1092,"mode":"tcp_only","plugin":"v2ray-plugin","plugin_opts":"tls;host=vpn.example.com;path=/shadowsocks"]
    let graph: [String:Any] = ["log":["level":"warn"],"inbounds":[["type":"tun","auto_route":true,"strict_route":true,"mtu":1320]],
        "outbounds":[["type":"socks","tag":"tcp-stack","server":"127.0.0.1","server_port":1092,"version":"5"],
                     ["type":"hysteria2","tag":"udp-stack","server":"192.0.2.1","server_port":8443,"password":"hy-fixture","tls":["enabled":true,"server_name":"node.test","certificate_path":"cert.pem"],"obfs":["type":"salamander","password":"hy-mask"]],
                     ["type":"direct","tag":"direct"]],
        "route":["final":"tcp-stack","rules":[["protocol":"dns","action":"hijack-dns"],["network":"tcp","action":"route","outbound":"tcp-stack"],["network":"udp","action":"route","outbound":"udp-stack"]]],
        "dns":["final":"home","servers":[["type":"udp","tag":"home","server":"10.77.0.1","detour":"tcp-stack"]]]]
    bundle.profiles["ss-v2ray"] = ["sing-box.json":try json(graph).base64EncodedString(),"sslocal.json":try json(helper).base64EncodedString(),"cert.pem":Data("fixture-certificate".utf8).base64EncodedString()]
    bundle.logicalModes.append(LogicalMode(id:"ss-v2ray",name:"SS2022 + V2Ray TLS",description:"",baseSelector:false,fallback:false,variants:["native":"ss-v2ray"]))
    return bundle
}
func obj(_ value: String) throws -> [String:Any] { try JSONSerialization.jsonObject(with:Data(base64Encoded:value)!) as! [String:Any] }
@main struct Tests {
    @MainActor static var checks=0
    @MainActor static func check(_ label: String, _ value: @autoclosure () throws -> Bool) throws { guard try value() else { fatalError(label) };checks+=1 }
    @MainActor static func reject(_ label: String,_ operation: () throws -> Void) {do{try operation();fatalError("accepted "+label)}catch{checks+=1}}
    @MainActor static func main() throws {
        for dns in ["home","custom","dot","doh","doh3","rescue"] {
            for host in ["1.1.1.1","resolver.example.com"] {
                let original=try sipBundle(dns,host:host), patched=try IOSDNSRuntimePolicy.patch(original)
                let selected=try IOSRuntimeSelector.selectRaw(bundle:patched,rawProfileID:"ss-v2ray")
                try check("native Libbox selection",selected.engine == .libbox && selected.rawProfileID == "ss-v2ray")
                try check("mode is genuinely selectable",IOSRuntimeSelector.runnableModes(in:patched).contains{$0.id == "ss-v2ray"})
                try check("original helper bytes retained",selected.files["sslocal.json"] == Data(base64Encoded:original.profiles["ss-v2ray"]!["sslocal.json"]!))
                let config=try JSONSerialization.jsonObject(with:selected.files["sing-box.json"]!) as! [String:Any]
                let outbounds=config["outbounds"] as! [[String:Any]], helper=try obj(original.profiles["ss-v2ray"]!["sslocal.json"]!)
                let ss=outbounds[0]
                try check("no local helper",ss["type"] as? String == "shadowsocks" && ss["plugin"] as? String == "v2ray-plugin" && ss["network"] as? String == "tcp")
                for field in ["server","server_port","password","method","plugin","plugin_opts"] {
                    try check("exact protocol field "+field,NSDictionary(dictionary:[field:ss[field]!]).isEqual(to:[field:helper[field]!]))
                }
                let before=try obj(original.profiles["ss-v2ray"]!["sing-box.json"]!), old=before["outbounds"] as! [[String:Any]]
                try check("UDP cryptography preserved",NSDictionary(dictionary:outbounds[1]).isEqual(to:old[1]))
                let servers=(config["dns"] as! [String:Any])["servers"] as! [[String:Any]]
                for server in servers {
                    let type=server["type"] as! String, expected=["udp","h3","quic"].contains(type) ? "udp-stack" : "tcp-stack"
                    try check("compatible encrypted DNS leg",server["detour"] as? String == expected)
                }
                try check("selected DNS transport preserved",servers.last?["type"] as? String == ["home":"udp","custom":"udp","dot":"tls","doh":"https","doh3":"h3","rescue":"udp"][dns])
                try check("repeated patch stable",IOSDNSRuntimePolicy.patch(patched).profiles == patched.profiles)
            }
        }
        for (field,value) in [("plugin","/bin/foreign-helper"),("method","none"),("password","invalid"),("plugin_opts","host=vpn.example.com;path=/x"),("plugin_opts","tls;host=vpn.example.com;path=/x;insecure"),("plugin_opts","tls;host=vpn.example.com;path=/x;tls"),("local_address","0.0.0.0")] {
            var bundle=try sipBundle();var helper=try obj(bundle.profiles["ss-v2ray"]!["sslocal.json"]!);helper[field]=value
            bundle.profiles["ss-v2ray"]?["sslocal.json"]=try json(helper).base64EncodedString()
            reject("unowned helper "+field){_=try IOSRuntimeSelector.selectRaw(bundle:bundle,rawProfileID:"ss-v2ray")}
        }
        for asset in ["chain.env","outer-xray.json","wg.conf","../escape"] {
            var bundle=try sipBundle();bundle.profiles["ss-v2ray"]?[asset]=Data("unused helper".utf8).base64EncodedString()
            reject("extra asset "+asset){_=try IOSRuntimeSelector.selectRaw(bundle:bundle,rawProfileID:"ss-v2ray")}
        }
        var mismatch=try sipBundle();var graph=try obj(mismatch.profiles["ss-v2ray"]!["sing-box.json"]!);var outs=graph["outbounds"] as! [[String:Any]]
        outs[0]["server_port"]=1093;graph["outbounds"]=outs;mismatch.profiles["ss-v2ray"]?["sing-box.json"]=try json(graph).base64EncodedString()
        reject("foreign local port"){_=try IOSRuntimeSelector.selectRaw(bundle:mismatch,rawProfileID:"ss-v2ray")}
        var partial=try sipBundle();graph=try obj(partial.profiles["ss-v2ray"]!["sing-box.json"]!);outs=graph["outbounds"] as! [[String:Any]];outs.remove(at:1);graph["outbounds"]=outs
        partial.profiles["ss-v2ray"]?["sing-box.json"]=try json(graph).base64EncodedString()
        reject("missing authenticated UDP leg"){_=try IOSRuntimeSelector.selectRaw(bundle:partial,rawProfileID:"ss-v2ray")}
        print("iOS native SIP003 selection/DNS/credential preservation: PASS (\(checks) checks)")
    }
}
"""
def main():
    swift=shutil.which('swiftc')
    if not swift:raise SystemExit('swiftc is required for native SIP003 host tests')
    with tempfile.TemporaryDirectory(prefix='routervpn-sip003-swift-') as temp:
        temp=Path(temp);dns=APP/'IOSDNSRuntimePolicy.swift'
        if platform.system()!='Darwin':
            contents=dns.read_text();dns=temp/'IOSDNSRuntimePolicy.swift';dns.write_text(contents.replace('import Network\n',base.NETWORK_SHIM))
        tests=temp/'Tests.swift';tests.write_text('import Foundation\n'+FIXTURE+TEST)
        binary=temp/'tests'
        subprocess.run([swift,'-swift-version','6',str(APP/'Models.swift'),str(dns),str(APP/'IOSNativeXrayProfile.swift'),str(APP/'IOSRuntimeSelection.swift'),str(tests),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=30)
    provider=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
    section=provider[provider.index('private func startLibbox('):provider.index('private func startExternalLibbox(')]
    assert section.index('LibboxRouterCompileSIP003Profile') < section.index('IOSStartLayer.apply') < section.index('engine.start(')
    print('Shipping host composition and pre-start native validation are both wired.')
if __name__=='__main__':main()
