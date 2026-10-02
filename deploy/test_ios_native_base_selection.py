#!/usr/bin/env python3
"""Execute shipping native base selection and exact-raw strategy dispatch offline.

Apple CI compiles the real Network.framework DNS policy. Linux substitutes only
IPv4Address/IPv6Address literal parsing with inet_pton; the selector, models, DNS
policy, and extracted shipping strategy method are otherwise unchanged.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "ios/RouterVPN/App"
NETWORK_SHIM = r'''
import Glibc
struct IPv4Address {
    init?(_ raw: String) { var value = in_addr(); guard inet_pton(AF_INET, raw, &value) == 1 else { return nil } }
}
struct IPv6Address {
    init?(_ raw: String) { var value = in6_addr(); guard inet_pton(AF_INET6, raw, &value) == 1 else { return nil } }
}
'''
TEST = r'''
import Foundation

@MainActor final class RouterVPNModel {
    var bundle: ClientBundle?
    var connected = false, auto = false
    var selectedLogicalMode = "", selectedMode = "", activeRawProfile = ""
    var attempts: [String] = []
    var wrongDispatches = 0, stops = 0
    var pretendWrongRuntime = false, stopSucceeds = true
    func stopIOSStrategyTunnel() async -> Bool {
        stops += 1
        if stopSucceeds { connected = false }
        return stopSucceeds
    }
    func connect() async { wrongDispatches += 1 }
    func connect(rawProfileID: String?) async {
        guard let rawProfileID, let bundle,
              let selected = try? IOSRuntimeSelector.selectRaw(bundle: bundle, rawProfileID: rawProfileID) else { return }
        attempts.append(rawProfileID); connected = true
        activeRawProfile = pretendWrongRuntime ? "wrong-runtime" : selected.rawProfileID
    }
}
@MainActor extension RouterVPNModel {
    // SHIPPING_STRATEGY_METHOD
    func exerciseRaw(_ raw: String) async -> Bool { await connectIOSRawCandidate(raw) }
}

func json(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value) }
func fixture(base: String = "auto", fallback: Bool = false, dns: String = "home", start: String = "off") throws -> ClientBundle {
    let fields: [String: Any] = [
        "id":"home", "name":"Home", "node_kind":"router-vpn", "endpoint":"192.0.2.1",
        "router_api":"http://10.77.0.1:8787", "api_token":"fixture-only-not-a-secret",
        "adguard_ipv4":"10.77.0.1", "adguard_ipv6":"fd77:77::1", "socks_host":"10.77.0.1",
        "socks_port":1080, "socks_username":"", "socks_password":"", "base_tunnel":base,
        "mtu_policy":"fixed", "manual_mtu":1380, "base_fallback":fallback, "dns_mode":dns, "dns_host":"1.1.1.1", "dns_server_name":"cloudflare-dns.com", "start_layer":start
    ]
    var bundle = ClientBundle.empty
    bundle.selectedRouterID = "home"
    bundle.routerProfiles = [try JSONDecoder().decode(RouterProfile.self, from: json(fields))]
    bundle.logicalModes = [
        LogicalMode(id:"base-raw", name:"Raw tunnel", description:"", baseSelector:true, fallback:true, variants:["wg":"wg","awg":"awg2-fast"]),
        LogicalMode(id:"awg-strong", name:"Strong", description:"", baseSelector:false, fallback:false, variants:["awg":"awg2-strong"]),
        LogicalMode(id:"shadowsocks", name:"SS", description:"", baseSelector:false, fallback:false, variants:["native":"shadowsocks"])
    ]
    let conf = "[Interface]\nPrivateKey=fixture\n[Peer]\nPublicKey=fixture\n"
    let config: [String:Any] = ["inbounds":[["type":"tun"]],"outbounds":[["type":"shadowsocks","tag":"proxy","server":"192.0.2.1"]],"route":["final":"proxy"]]
    bundle.profiles = ["wg":["wg.conf":Data(conf.utf8).base64EncodedString()],
                       "awg2-fast":["awg.conf":Data(conf.utf8).base64EncodedString()],
                       "awg2-strong":["awg.conf":Data(conf.utf8).base64EncodedString()],
                       "shadowsocks":["sing-box.json":try json(config).base64EncodedString()]]
    return bundle
}
func candidates(_ bundle: ClientBundle, _ logical: String = "base-raw") throws -> [String] {
    try IOSRuntimeSelector.candidates(bundle: bundle, logicalModeID: logical).map(\.rawProfileID)
}
@main struct Tests {
    @MainActor static var checks = 0
    @MainActor static func check(_ name: String, _ body: @autoclosure () throws -> Bool) throws {
        guard try body() else { fatalError("FAIL: " + name) }; checks += 1
    }
    @MainActor static func reject(_ name: String, _ body: () throws -> Void) {
        do { try body(); fatalError("Accepted invalid " + name) } catch { checks += 1 }
    }
    @MainActor static func main() async throws {
        try check("default ordered native bases", candidates(fixture()) == ["wg", "awg2-fast"])
        try check("explicit WG no fallback", candidates(fixture(base:"wg")) == ["wg"])
        try check("explicit AWG no fallback", candidates(fixture(base:"awg")) == ["awg2-fast"])
        try check("AWG fallback ordering", candidates(fixture(base:"awg", fallback:true)) == ["awg2-fast", "wg"])
        try check("WG fallback ordering", candidates(fixture(base:"wg", fallback:true)) == ["wg", "awg2-fast"])
        try check("AWG Strong independent mode", candidates(fixture(base:"wg"), "awg-strong") == ["awg2-strong"])
        try check("exact Fast bypasses logical preferred WG", IOSRuntimeSelector.selectRaw(bundle:fixture(base:"wg"), rawProfileID:"awg2-fast").rawProfileID == "awg2-fast")
        try check("exact Strong stays strong", IOSRuntimeSelector.selectRaw(bundle:fixture(), rawProfileID:"awg2-strong").rawProfileID == "awg2-strong")
        try check("logical selects preferred AWG", IOSRuntimeSelector.select(bundle:fixture(base:"awg"), logicalModeID:"base-raw").rawProfileID == "awg2-fast")
        for base in ["awg2", "amneziawg", " AWG "] { try check("AWG alias \(base)", candidates(fixture(base:base)) == ["awg2-fast"]) }
        reject("unknown base") { _ = try candidates(fixture(base:"not-an-engine")) }
        var unavailable = try fixture(base:"awg"); unavailable.profiles.removeValue(forKey:"awg2-fast")
        reject("no silent WG fallback") { _ = try candidates(unavailable) }
        unavailable.routerProfiles[0].baseFallback = true
        try check("explicit fallback when AWG missing", candidates(unavailable) == ["wg"])
        var badWG = try fixture(base:"wg"); badWG.profiles.removeValue(forKey:"wg")
        reject("WG without configuration") { _ = try candidates(badWG) }
        badWG.routerProfiles[0].baseFallback = true
        try check("explicit fallback when WG missing", candidates(badWG) == ["awg2-fast"])
        for raw in ["wg", "awg2-fast", "awg2-strong"] {
            let asset = raw == "wg" ? "wg.conf" : "awg.conf"
            for data in [Data(), Data([0xff]), Data(repeating:32,count:1024*1024+1)] {
                var bad = try fixture(); bad.profiles[raw] = [asset:data.base64EncodedString()]
                reject("invalid native asset \(raw) \(data.count)") { _ = try IOSRuntimeSelector.selectRaw(bundle:bad,rawProfileID:raw) }
            }
            var bad = try fixture(); bad.profiles[raw] = [asset:"not-base64"]
            reject("invalid native encoding \(raw)") { _ = try IOSRuntimeSelector.selectRaw(bundle:bad,rawProfileID:raw) }
            reject("Start Layer not silently ignored \(raw)") { _ = try IOSRuntimeSelector.selectRaw(bundle:fixture(start:"aes-256-gcm"),rawProfileID:raw) }
            try check("native family encrypted DNS keeps exact mode", IOSRuntimeSelector.selectRaw(bundle:fixture(dns:"dot"),rawProfileID:raw).engine == .libbox && IOSRuntimeSelector.selectRaw(bundle:fixture(dns:"dot"),rawProfileID:raw).rawProfileID == raw)
        }
        for raw in ["wg", "awg2-fast", "awg2-strong"] {
            var unsupportedPort = try fixture(dns:"custom")
            unsupportedPort.routerProfiles[0].dnsProtocol = "udp"
            unsupportedPort.routerProfiles[0].dnsPort = 5353
            try check("native family custom port uses Libbox", IOSRuntimeSelector.selectRaw(bundle:unsupportedPort,rawProfileID:raw).engine == .libbox)
        }
        for raw in ["wg", "awg2-fast", "awg2-strong"] {
            for policy: String? in [nil, "", "auto", "AUTO", " auto "] {
                var adaptive = try fixture(); adaptive.routerProfiles[0].mtuPolicy = policy
                let selected = try IOSRuntimeSelector.selectRaw(bundle: adaptive, rawProfileID: raw)
                let asset = raw == "wg" ? "wg.conf" : "awg.conf"
                try check("Auto-MTU uses its owned Libbox TUN \(raw) \(policy ?? "absent")", selected.engine == .libbox)
                try check("Auto-MTU preserves exact protocol and peer bytes", selected.rawProfileID == raw && selected.files[asset]?.base64EncodedString() == adaptive.profiles[raw]?[asset])
            }
            for policy in ["fixed", "manual", "default"] {
                var fixed = try fixture(); fixed.routerProfiles[0].mtuPolicy = policy
                try check("nonadaptive native adapter remains runnable \(raw) \(policy)", IOSRuntimeSelector.selectRaw(bundle: fixed, rawProfileID: raw).engine == .wireGuard)
            }
            var invalid = try fixture(); invalid.routerProfiles[0].mtuPolicy = "unknown-mtu"
            reject("invalid MTU policy cannot silently pick a backend") { _ = try IOSRuntimeSelector.selectRaw(bundle: invalid, rawProfileID: raw) }
        }
        var allowedCustomPort = try fixture(dns:"custom")
        allowedCustomPort.routerProfiles[0].dnsProtocol = "udp"
        allowedCustomPort.routerProfiles[0].dnsPort = 53
        try check("native DNS accepts explicit UDP53", IOSRuntimeSelector.selectRaw(bundle:allowedCustomPort,rawProfileID:"wg").rawProfileID == "wg")
        for mode in ["dot", "doh", "doh3"] {
            let selected = try IOSRuntimeSelector.selectRaw(bundle:fixture(dns:mode),rawProfileID:"wg")
            try check("WG advanced DNS keeps raw identity", selected.engine == .libbox && selected.rawProfileID == "wg" && selected.files["wg.conf"] != nil)
        }
        var lanOff = try fixture(); lanOff.routerProfiles[0].homeLANAccess = false
        try check("WG LAN filtering uses Libbox", IOSRuntimeSelector.selectRaw(bundle:lanOff,rawProfileID:"wg").engine == .libbox)
        var ipv6Off = try fixture(); ipv6Off.routerProfiles[0].ipv6Mode = "off"
        try check("WG IPv6 filtering uses Libbox", IOSRuntimeSelector.selectRaw(bundle:ipv6Off,rawProfileID:"wg").engine == .libbox)
        ipv6Off.routerProfiles[0].ipv6Mode = "unrecognized"
        reject("unknown IPv6 not ignored") { _ = try IOSRuntimeSelector.selectRaw(bundle:ipv6Off,rawProfileID:"wg") }
        var noFallback = try fixture(base:"awg", fallback:true)
        noFallback.logicalModes[0] = LogicalMode(id:"base-raw",name:"Raw",description:"",baseSelector:true,fallback:false,variants:["wg":"wg","awg":"awg2-fast"])
        try check("catalog can forbid fallback", candidates(noFallback) == ["awg2-fast"])
        var missingNode = try fixture(); missingNode.selectedRouterID = "absent"
        reject("DNS cannot borrow the first node") { _ = try IOSDNSRuntimePolicy.patch(missingNode) }
        reject("runtime cannot borrow the first node") { _ = try candidates(missingNode) }
        var duplicateNode = try fixture(); duplicateNode.routerProfiles.append(duplicateNode.routerProfiles[0])
        reject("duplicate selected nodes are ambiguous") { _ = try candidates(duplicateNode) }
        reject("duplicate DNS node is ambiguous") { _ = try IOSDNSRuntimePolicy.patch(duplicateNode) }
        var emptySelection = try fixture(); emptySelection.selectedRouterID = ""
        try check("one legacy node can be selected", IOSDNSRuntimePolicy.selectedProfile(in: emptySelection)?.id == "home")
        emptySelection.routerProfiles.append(emptySelection.routerProfiles[0])
        reject("multiple unnamed nodes cannot be guessed") { _ = try candidates(emptySelection) }
        var duplicate = try fixture(); duplicate.logicalModes[0] = LogicalMode(id:"base-raw",name:"Raw",description:"",baseSelector:true,fallback:true,variants:["wg":"wg","awg":"wg"])
        try check("deduplicate identical runtime", candidates(duplicate) == ["wg"])
        reject("path traversal raw id") { _ = try IOSRuntimeSelector.selectRaw(bundle:fixture(),rawProfileID:"../wg") }
        reject("unowned PQ runtime") { _ = try IOSRuntimeSelector.selectRaw(bundle:fixture(),rawProfileID:"awg2-pq") }
        var nested = try fixture(); nested.profiles["shadowsocks"]?["xray.json"] = Data("{}".utf8).base64EncodedString()
        reject("unowned helper remains rejected") { _ = try candidates(nested,"shadowsocks") }
        let patched = try IOSDNSRuntimePolicy.patch(fixture())
        for raw in ["wg", "awg2-fast", "awg2-strong"] {
            let asset = raw == "wg" ? "wg.conf" : "awg.conf"
            let text = String(data:Data(base64Encoded:patched.profiles[raw]![asset]!)!,encoding:.utf8)!
            try check("DNS reaches \(raw)", text.contains("DNS = 10.77.0.1"))
        }
        let model = RouterVPNModel(); model.bundle = try fixture(base:"wg")
        let fast = await model.exerciseRaw("awg2-fast")
        try check("shipping strategy dispatches exact Fast", fast && model.attempts == ["awg2-fast"] && model.wrongDispatches == 0)
        let strong = await model.exerciseRaw("awg2-strong")
        try check("shipping strategy stops before exact Strong", strong && model.stops == 1 && model.attempts == ["awg2-fast","awg2-strong"])
        model.pretendWrongRuntime = true
        let wrong = await model.exerciseRaw("wg")
        try check("shipping strategy rejects wrong runtime", !wrong && !model.connected && model.stops == 3)
        let missing = await model.exerciseRaw("awg2-pq")
        try check("missing runtime starts nothing", !missing && model.attempts.count == 3)
        model.connected = true; model.stopSucceeds = false
        let before = model.attempts.count
        let unverifiedStop = await model.exerciseRaw("awg2-fast")
        try check("unverified teardown prevents a new attempt", !unverifiedStop && model.attempts.count == before)
        print("Native Apple WG/AWG selection + exact-raw strategy: PASS (\(checks) checks)")
    }
}
'''

def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc is required for executable native selection tests")
    strategy = (APP / "IOSStrategySupport.swift").read_text()
    begin = strategy.index("    private func connectIOSRawCandidate(")
    end = strategy.index("    func runIOSSmartAuto()", begin)
    method = strategy[begin:end]
    provider=(ROOT / "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift").read_text()
    scope=provider[provider.index("    private func startLibbox("):provider.index("    private func startExternalLibbox(")]
    for marker in ("[\"wg\", \"awg2-fast\", \"awg2-strong\"].contains(rawProfileID)", "multihopWireGuardEndpoint(root: root, expectedProofID: expectedNodeID", "RouterVPNMultihopGraph.wireGuardFiles(", "RouterVPNMultihopGraph.singleWireGuardPolicy(", "LibboxRouterApplyMultihopLANPolicy(", "expectedNodeID: provenNodeID"):
        assert marker in scope, "native WireGuard launch wiring missing: " + marker
    assert scope.index("LibboxRouterApplyMultihopLANPolicy(") < scope.index("engine.start(")
    selection=provider[provider.index("    private func selectedRouterProfile("):provider.index("    private func wireGuardLikeProfile(")]
    assert "matches.count == 1" in selection and "profiles.count == 1" in selection
    model = (APP / "RouterVPNModel.swift").read_text()
    assert 'func connect(rawProfileID: String?) async' in model
    assert 'selections = [try IOSRuntimeSelector.selectRaw(bundle: bundle, rawProfileID: rawProfileID)]' in model
    assert 'IOSRuntimeSelector.candidates(bundle: bundle, logicalModeID: selectedLogicalMode)' in model
    assert 'configuration["rawProfileID"] = selection.rawProfileID' in model
    with tempfile.TemporaryDirectory(prefix="routervpn-native-selection-") as tmp:
        tmp = Path(tmp)
        dns = APP / "IOSDNSRuntimePolicy.swift"
        if platform.system() != "Darwin":
            text = dns.read_text()
            assert text.count("import Network\n") == 1
            dns = tmp / dns.name
            dns.write_text(text.replace("import Network\n", NETWORK_SHIM))
        test = tmp / "Tests.swift"
        test.write_text(TEST.replace("    // SHIPPING_STRATEGY_METHOD", method))
        binary = tmp / "tests"
        subprocess.run([swift, "-swift-version", "6", str(APP / "Models.swift"),
                        str(dns), str(APP / "IOSNativeXrayProfile.swift"), str(APP / "IOSRuntimeSelection.swift"), str(test), "-o", str(binary)],
                       check=True, timeout=90)
        subprocess.run([str(binary)], check=True, timeout=25)
    print("Apple CI uses real Network.framework; no VPN/server connections were made.")

if __name__ == "__main__":
    main()
