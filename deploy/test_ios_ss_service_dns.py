#!/usr/bin/env python3
"""Run shipping Apple import, captured-source and runtime DNS projections.

The Linux Network parser shim and real SHA256 test module are existing test
boundaries. This does not start NetworkExtension, a peer, or an OS VPN.
"""
from pathlib import Path
import base64
import importlib.util
import json
import os
import platform
import runpy
import subprocess
import tempfile

import ios_test_crypto_bridge as crypto

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "ios/RouterVPN/App"
TUN = ROOT / "ios/RouterVPN/PacketTunnel"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("ss_dns_network", ROOT / "deploy/test_ios_native_base_selection.py")

TEST = r'''
import Foundation
@MainActor @main struct Tests {
 static var checks = 0
 static func check(_ name: String, _ value: @autoclosure () throws -> Bool) throws {
  guard try value() else { throw NSError(domain:"SSSourceDNS",code:1,userInfo:[NSLocalizedDescriptionKey:name]) }; checks += 1
 }
 static func reject(_ name: String, _ body: () throws -> Void) throws {
  do { try body() } catch { checks += 1; return }
  throw NSError(domain:"SSSourceDNS",code:2,userInfo:[NSLocalizedDescriptionKey:"Accepted " + name])
 }
 static func data(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]) }
 static func object(_ value: Data) throws -> [String:Any] { try JSONSerialization.jsonObject(with:value) as! [String:Any] }
 static func root(_ value: ClientBundle) throws -> [String:Any] { try object(JSONEncoder().encode(value)) }
 static func profile(_ value: [String:Any]) throws -> RouterProfile { try JSONDecoder().decode(RouterProfile.self,from:data(value)) }
 static func bundle(_ files:[String:String], _ value:[String:Any]) throws -> ClientBundle {
  var result = ClientBundle.empty; result.nodeProofID = String(repeating:"a",count:64)
  result.endpoint = value["endpoint"] as? String ?? "192.0.2.44"; result.routerProfiles = [try profile(value)]; result.selectedRouterID = "home"
  result.profiles = ["shadowsocks":files]; return result
 }
 static func main() throws {
  let fixtures = try object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[1])))
  let files = fixtures["files"] as! [String:String], original = Data(base64Encoded:files["sing-box.json"]!)!
  let saved = fixtures["profile"] as! [String:Any], node = String(repeating:"a",count:64)
  let consumer = CaptureConsumer(), originalGraph = try object(original)
  var policies:[[String:Any]] = []
  for transport in ["udp","tcp","tls","https","h3"] { for host in ["192.168.50.133","fd12::53"] {
   policies.append(["dns_mode":"home","dns_protocol":transport,"dns_host":host,"dns_port":5443,
                    "dns_server_name":"adguard.home.example","dns_path":"/owned-query"])
  }}
  for transport in ["udp","tcp"] {
   policies.append(["dns_mode":"custom","dns_protocol":transport,"dns_host":"192.0.2.53","dns_port":5353])
  }
  for mode in ["dot","doh","doh3"] {
   policies.append(["dns_mode":mode,"dns_host":"resolver.example","dns_port":5443,
                    "dns_server_name":"resolver.example","dns_path":"/private-query"])
  }
  for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] { for policy in policies {
   var value = saved; for (name, field) in policy { value[name] = field }; value["start_layer"] = layer
   let input = try bundle(files,value), patched = try IOSDNSRuntimePolicy.patch(input)
   try check("SS original bytes and authority were rewritten by DNS preparation", patched.profiles["shadowsocks"] == files)
   try check("repeated preparation changed original source", try IOSDNSRuntimePolicy.patch(patched).profiles["shadowsocks"] == files)
   let captured = try root(patched), runtime = try consumer.compile(captured,profile:value,node:node)
   try check("runtime retained a stale source declaration", Set(runtime.keys) == Set(["sing-box.json"]))
   let graph = try object(runtime["sing-box.json"]!), dns = graph["dns"] as! [String:Any]
   let servers = dns["servers"] as! [[String:Any]], selected = servers.first { $0["tag"] as? String == dns["final"] as? String }!
   let wanted = try IOSDNSRuntimePolicy.resolve(profile(value))!
   try check("runtime ignored the selected resolver", selected["type"] as? String == wanted.type && selected["server"] as? String == wanted.host && selected["server_port"] as? Int == wanted.port && selected["detour"] as? String == "proxy")
   if ["tls","https","h3"].contains(wanted.type) {
    try check("runtime lost selected DNS TLS identity", (selected["tls"] as? [String:Any])?["server_name"] as? String == wanted.serverName)
   }
   if ["https","h3"].contains(wanted.type) { try check("runtime lost selected DNS path", selected["path"] as? String == wanted.path) }
   if wanted.host == "resolver.example" {
    try check("hostname bootstrap escaped the captured path", servers.count == 2 && servers[0]["server"] as? String == "192.168.50.133" && servers[0]["detour"] as? String == "proxy" && selected["domain_resolver"] as? String == servers[0]["tag"] as? String)
   }
   for name in ["outbounds","inbounds","route"] { try check("DNS projection changed " + name, try data(graph[name]!) == data(originalGraph[name]!)) }
   try consumer.validate(captured,node:node)
   let layerCapture = try IOSMultihopStartLayer.capture(profile:value,profiles:patched.profiles)
   if layer != "off" {
    let raw = try object(Data(layerCapture.source!.utf8))
    try check("Start Layer lost original service source", raw["profile"] as? [String:String] == files)
   }
   var entry = value; entry["id"] = "entry"; entry["node_proof_id"] = String(repeating:"b",count:64); entry["start_layer"] = "off"
   let key = Data(repeating:2,count:32).base64EncodedString()
   let endpoint:[String:Any] = ["type":"wireguard","address":["10.77.0.2/32","fd77::2/128"],"private_key":key,"mtu":1380,
     "peers":[["address":"198.51.100.2","port":51820,"public_key":key,"allowed_ips":["0.0.0.0/0","::/0"]]]]
   let nested = try RouterVPNMultihopGraph.build(entryEndpoint:endpoint,entryProfile:entry,exitProfile:layerCapture.graphProfile,exitMode:"shadowsocks",files:runtime)
   try check("paired final lost selected DNS", try data(object(nested["sing-box.json"]!)["dns"]!) == data(dns))
   try check("source changed while compiling runtime", patched.profiles["shadowsocks"] == files && captured["profiles"] as? [String:[String:String]] == patched.profiles)
  }}
  for name in ["inherited-tcp","inherited-doh"] {
   let inherited = fixtures[name] as! [String:String]
   var value = saved; value["dns_mode"] = ""
   let input = try bundle(inherited,value), patched = try IOSDNSRuntimePolicy.patch(input)
   let runtime = try consumer.compile(root(patched),profile:value,node:node)
   try check("unset policy changed complete imported resolver", runtime["sing-box.json"] == Data(base64Encoded:inherited["sing-box.json"]!))
   var entry = value; entry["id"] = "entry"; entry["node_proof_id"] = String(repeating:"b",count:64)
   let key = Data(repeating:2,count:32).base64EncodedString()
   let endpoint:[String:Any] = ["type":"wireguard","address":["10.77.0.2/32","fd77::2/128"],"private_key":key,"mtu":1380,
     "peers":[["address":"198.51.100.2","port":51820,"public_key":key,"allowed_ips":["0.0.0.0/0","::/0"]]]]
   let nested = try RouterVPNMultihopGraph.build(entryEndpoint:endpoint,entryProfile:entry,exitProfile:value,exitMode:"shadowsocks",files:runtime)
   try check("paired unset DNS changed complete imported resolver", try data(object(nested["sing-box.json"]!)["dns"]!) == data(object(runtime["sing-box.json"]!)["dns"]!))
   value["dns_mode"] = "custom"; value["dns_protocol"] = "tcp"; value["dns_host"] = "192.0.2.53"; value["dns_port"] = 5353
   let overridden = try IOSDNSRuntimePolicy.patch(bundle(inherited,value))
   let selectedRuntime = try consumer.compile(root(overridden),profile:value,node:node)
   let selectedGraph = try object(selectedRuntime["sing-box.json"]!)
   let resolver = ((selectedGraph["dns"] as! [String:Any])["servers"] as! [[String:Any]])[0]
   try check("explicit policy could not replace imported encrypted DNS", resolver["type"] as? String == "tcp" && resolver["server"] as? String == "192.0.2.53" && resolver["server_port"] as? Int == 5353)
   try check("explicit policy rewrote inherited source", overridden.profiles["shadowsocks"] == inherited)
  }
  var legacy = files; legacy.removeValue(forKey:"routervpn-ss-service.json")
  var custom = saved; custom["dns_mode"] = "custom"; custom["dns_protocol"] = "tcp"; custom["dns_host"] = "192.0.2.53"; custom["dns_port"] = 5353
  let old = try IOSDNSRuntimePolicy.patch(bundle(legacy,custom))
  try check("legacy source-only DNS patch stopped working", old.profiles["shadowsocks"]?["sing-box.json"] != legacy["sing-box.json"])
  for fault in ["raw-whitespace","foreign-node","foreign-top","missing-node","malformed-claim"] {
   var input = try bundle(files,saved)
   switch fault {
   case "raw-whitespace": var raw = original; raw.append(10); input.profiles["shadowsocks"]?["sing-box.json"] = raw.base64EncodedString()
   case "foreign-node": input.routerProfiles[0].nodeProofID = String(repeating:"b",count:64); input.nodeProofID = String(repeating:"b",count:64)
   case "foreign-top": input.nodeProofID = String(repeating:"b",count:64)
   case "missing-node": input.nodeProofID = ""; input.routerProfiles[0].nodeProofID = nil
   default: input.profiles["shadowsocks"]?["routervpn-ss-service.json"] = Data("{".utf8).base64EncodedString()
   }
   try reject("app " + fault) { _ = try IOSDNSRuntimePolicy.patch(input) }
   if fault != "foreign-top" {
    try reject("extension " + fault) { try consumer.validate(root(input),node:input.nodeProofID) }
   }
  }
  var topOnly = try bundle(files,saved); topOnly.routerProfiles[0].nodeProofID = ""
  try check("explicit top-level legacy node was lost", try IOSDNSRuntimePolicy.patch(topOnly).profiles["shadowsocks"] == files)
  let hostnameFiles = fixtures["hostname"] as! [String:String]
  var xrayValue = saved; xrayValue["endpoint"] = "vpn.example"
  let originalBundle = try bundle(hostnameFiles,xrayValue)
  let hostnameGraph = try object(Data(base64Encoded:hostnameFiles["sing-box.json"]!)!)
  var resolvedGraph = hostnameGraph, outs = hostnameGraph["outbounds"] as! [[String:Any]]
  outs[0]["server"] = "192.0.2.77"; resolvedGraph["outbounds"] = outs
  let resolvedAES = try data(resolvedGraph), xray = Data("{}".utf8), wrapper = Data("{}".utf8)
  let replacements = ["sing-box.json":wrapper,"xray.json":xray,"start-layer-source.json":resolvedAES]
  let selection = IOSRuntimeSelection(engine:.libbox,logicalModeID:"reality-vision",rawProfileID:"reality-vision",files:["sing-box.json":wrapper,"xray.json":xray])
  let launched = try LaunchConsumer.prepare(source:originalBundle,selection:selection,replacements:replacements)
  try check("Xray launch rewrote original SS source", launched.profiles["shadowsocks"] == hostnameFiles)
  try check("Xray launch lost its own resolved AES", launched.profiles["reality-vision"]?["start-layer-source.json"] == resolvedAES.base64EncodedString())
  let projected = try consumer.xrayProjection(root(launched),files:replacements,node:node)
  let projectedSS = (projected["profiles"] as! [String:Any])["shadowsocks"] as! [String:String]
  try check("Xray projection did not consume original authority", projectedSS == ["sing-box.json":resolvedAES.base64EncodedString()])
  try check("Xray projection mutated original source", launched.profiles["shadowsocks"] == hostnameFiles)
  for fault in ["password","port","dns","route","extra-outbound","second-ss","hostname","foreign-node","literal-change"] {
   var altered = resolvedGraph, alteredOutputs = resolvedGraph["outbounds"] as! [[String:Any]], changed = replacements
   var captured = try root(launched), expected = node
   switch fault {
   case "password": alteredOutputs[0]["password"] = Data(repeating:7,count:32).base64EncodedString()
   case "port": alteredOutputs[0]["server_port"] = 9443
   case "dns": altered["dns"] = ["servers":[["type":"udp","tag":"other","server":"192.0.2.53"]],"final":"other"]
   case "route": altered["route"] = ["final":"direct"]
   case "extra-outbound": alteredOutputs.append(["type":"direct","tag":"foreign"])
   case "second-ss": alteredOutputs.append(alteredOutputs[0])
   case "hostname": alteredOutputs[0]["server"] = "other.example"
   case "foreign-node": expected = String(repeating:"b",count:64)
   default: captured = try root(bundle(files,saved))
   }
   altered["outbounds"] = alteredOutputs; changed["start-layer-source.json"] = try data(altered)
   try reject("projection " + fault) { _ = try consumer.xrayProjection(captured,files:changed,node:expected) }
  }
  var ipv6Original = hostnameGraph, ipv6Outputs = hostnameGraph["outbounds"] as! [[String:Any]]
  ipv6Outputs[0]["server"] = "2001:db8:0:0:0:0:0:44"; ipv6Original["outbounds"] = ipv6Outputs
  var ipv6Resolved = ipv6Original; ipv6Outputs[0]["server"] = "2001:db8::44"; ipv6Resolved["outbounds"] = ipv6Outputs
  try RouterVPNMultihopGraph.validateResolvedSSSource(data(ipv6Original),resolved:data(ipv6Resolved))
  try check("same canonical IPv6 source normalization failed", true)
  print("Apple SS source/DNS: PASS \(checks) shipping import, capture, policy and launch checks")
 }
}
'''


def sources():
    provider = (TUN / "PacketTunnelProvider.swift").read_text()
    methods = provider[provider.index("    private func validateCapturedSSSource("):provider.index("    private func strictKillSwitchRequested(")]
    for marker in (
        "try validateCapturedSSSource(entryRoot, nodeID: entryProofID)",
        "try validateCapturedSSSource(root, nodeID: exitProofID)",
        "try validateCapturedSSSource(root, nodeID: expectedNodeID)",
        "capturedSSProfile(root, profile: exitProfile, nodeID: exitProofID)",
        "capturedSSProfile(root, profile: selectedProfile, nodeID: expectedNodeID)",
    ):
        assert marker in provider, marker
    compilation = provider[provider.index("    private func compileLibbox("):provider.index("    private func performanceFiles(")]
    assert compilation.index("try validateCapturedSSSource(") < compilation.index("var rawFiles:")
    projection = compilation[compilation.index("        var compositionRoot = root"):compilation.index("        let completeChain =")]
    consumer = '''import Foundation
struct CaptureConsumer {
 static let maxProfileBytes = 4 * 1024 * 1024, maxLayeredBytes = 12 * 1024 * 1024
 func tunnelError(_ code:Int,_ message:String)->NSError { NSError(domain:"CapturedProvider",code:code,userInfo:[NSLocalizedDescriptionKey:message]) }
''' + methods + '''
 func compile(_ root:[String:Any],profile:[String:Any],node:String)throws->[String:Data] { try capturedSSProfile(root,profile:profile,nodeID:node) }
 func validate(_ root:[String:Any],node:String)throws { try validateCapturedSSSource(root,nodeID:node) }
 func xrayProjection(_ root:[String:Any],files:[String:Data],node:String)throws->[String:Any] {
 let rawFiles = files, expectedNodeID = node
''' + projection + '''
 return compositionRoot
 }
}
'''
    model = (APP / "RouterVPNModel.swift").read_text()
    launch = model[model.index("            var launchFiles = selection.files"):]
    boundary = "            launchBundle = try IOSDNSRuntimePolicy.patch(launchBundle)"
    launch = launch[:launch.index(boundary) + len(boundary)]
    consumer += '''
enum LaunchConsumer {
 static func prepare(source:ClientBundle,selection:IOSRuntimeSelection,replacements:[String:Data])throws->ClientBundle {
 var launchBundle = source
''' + launch + '''
 return launchBundle
 }
}
'''
    return consumer


def fixture():
    cap = runpy.run_path(str(ROOT / "server/scripts/ss_service_capability.py"))
    key = base64.b64encode(b"s" * 32).decode()
    out = {"type":"shadowsocks","tag":"proxy","server":"192.0.2.44","server_port":8388,"method":"2022-blake3-aes-256-gcm","password":key}
    server = cap["encoded"]({"inbounds":[{"type":"shadowsocks","tag":"ss-in","listen":"::","listen_port":8388,"method":out["method"],"password":key}]})
    graph = {"log":{"level":"warn"},"outbounds":[out,{"type":"direct","tag":"direct"}],
             "inbounds":[{"type":"tun","tag":"tun-in","interface_name":"router-vpn","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"mtu":1380,"auto_route":True,"strict_route":True}],
             "route":{"rules":[{"protocol":"dns","action":"hijack-dns"}],"auto_detect_interface":True,"final":"proxy"}}
    result = {}
    for name, dns in (
        ("files", {"type":"udp","tag":"home-dns","server":"192.168.50.133","server_port":53,"detour":"proxy"}),
        ("inherited-tcp", {"type":"tcp","tag":"home-dns","server":"192.168.50.133","server_port":5353,"detour":"proxy"}),
        ("inherited-doh", {"type":"https","tag":"home-dns","server":"resolver.example","server_port":5443,"detour":"proxy","tls":{"enabled":True,"server_name":"resolver.example"},"path":"/original-query"}),
    ):
        servers = [dns]
        if name == "inherited-doh":
            dns["domain_resolver"] = "captured-bootstrap"
            servers = [{"type":"udp","tag":"captured-bootstrap","server":"192.168.50.133","server_port":53,"detour":"proxy"}, dns]
        graph["dns"] = {"servers":servers,"final":"home-dns"}
        raw = cap["encoded"](graph)
        claim = cap["capture"](cap["declaration"](server,raw,cap["IMAGE"],cap["IMAGE"]),server,raw,"a"*64,"192.0.2.44")
        result[name] = {"sing-box.json":base64.b64encode(raw).decode(),cap["ASSET"]:base64.b64encode(cap["encoded"](claim)).decode()}
    hostname = json.loads(base64.b64decode(result["files"]["sing-box.json"]))
    hostname["outbounds"][0]["server"] = "vpn.example"
    raw = cap["encoded"](hostname)
    claim = cap["capture"](cap["declaration"](server,raw,cap["IMAGE"],cap["IMAGE"]),server,raw,"a"*64,"vpn.example")
    result["hostname"] = {"sing-box.json":base64.b64encode(raw).decode(),cap["ASSET"]:base64.b64encode(cap["encoded"](claim)).decode()}
    result["profile"] = {"id":"home","name":"Home","node_kind":"router-vpn","node_proof_id":"a"*64,
        "endpoint":"192.0.2.44","router_api":"http://10.77.0.1:8787","api_token":"owned-token",
        "adguard_ipv4":"192.168.50.133","adguard_ipv6":"fd12::53","socks_host":"10.77.0.1","socks_port":1080,
        "socks_username":"","socks_password":"","dns_mode":"home","dns_protocol":"udp","dns_port":53,
        "ipv6_mode":"on","start_layer":"off","mtu_policy":"fixed","manual_mtu":1380,"home_lan_access":True}
    return result


def main():
    with tempfile.TemporaryDirectory(prefix="ios-ss-dns-") as directory:
        work = Path(directory)
        flags, environment = crypto.prepare(work / "crypto")
        dns = APP / "IOSDNSRuntimePolicy.swift"
        if platform.system() != "Darwin":
            dns = work / dns.name
            dns.write_text((APP / dns.name).read_text().replace("import Network\n", BASE.NETWORK_SHIM))
        consumer = work / "Consumer.swift"; consumer.write_text(sources())
        test = work / "Tests.swift"; test.write_text(TEST)
        captured = work / "fixture.json"; captured.write_text(json.dumps(fixture()))
        files = [APP / name for name in ("Models.swift","IOSHomeDNSPolicy.swift","IOSNativeXrayProfile.swift",
                 "IOSNativePQProfile.swift","IOSMultihopStartLayer.swift","IOSMultihopExecution.swift","IOSRuntimeSelection.swift")]
        files += [dns,TUN / "RouterVPNMultihopGraph.swift",TUN / "RouterVPNMTUPolicy.swift",consumer,test]
        executable = work / "test"
        command = ["swiftc","-swift-version","6",*flags,*map(str,files),"-o",str(executable)]
        run_environment = dict(os.environ, **environment)
        subprocess.run(command, check=True, timeout=180)
        subprocess.run([str(executable),str(captured)], env=run_environment, check=True, timeout=60)
        # Each overlay changes only one shipping behavior; original validators,
        # assertions, ownership checks and sources remain unchanged.
        old = dns.read_text()
        skip = '            if rawID == "shadowsocks", encodedFiles["routervpn-ss-service.json"] != nil { continue }'
        assert old.count(skip) == 1
        mutant_dns = work / "MutantDNS.swift"; mutant_dns.write_text(old.replace(skip,""))
        graph = TUN / "RouterVPNMultihopGraph.swift"; body = graph.read_text()
        start = body.index("    static func ssServiceDNSPolicy(")
        end = body.index("    /// Freeze the selected exit resolver", start)
        section = body[start:end]
        replacement = '        graph["dns"] = try selectedDNS(profile, importedDNS: "", requireImportedMatch: false)'
        assert section.count(replacement) == 1
        mutant_graph = work / "MutantGraph.swift"
        mutant_graph.write_text(body[:start] + section.replace(replacement,"") + body[end:])
        for label, source, mutant, expected in (
            ("original-source mutation",dns,mutant_dns,"SS original bytes and authority were rewritten"),
            ("selected-policy omission",graph,mutant_graph,"runtime ignored the selected resolver"),
        ):
            changed = [str(mutant) if arg == str(source) else arg for arg in command]
            subprocess.run(changed, check=True, timeout=180)
            result = subprocess.run([str(executable),str(captured)],env=run_environment,capture_output=True,text=True,timeout=60)
            assert result.returncode != 0 and expected in result.stderr, (label,result.returncode,result.stderr[-2000:])
            print("Rejected causal " + label)


if __name__ == "__main__":
    main()
