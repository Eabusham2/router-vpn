#!/usr/bin/env python3
"""Execute the shipping iOS private usage store and Node Manager sort.

The atomic private-file boundary is an in-memory failure-injectable map. macOS
uses real CryptoKit. On Linux only SHA256 is an explicitly labelled deterministic
input-sensitive boundary double; these checks prove accounting and source
separation, not cryptography, filesystem protection or device VPN traffic.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'

BOUNDARY = r'''
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
enum SHA256 {
    static func hash(data: Data) -> [UInt8] {
        var h: UInt64 = 14695981039346656037
        for byte in data { h = (h ^ UInt64(byte)) &* 1099511628211 }
        return (0..<32).map { UInt8(truncatingIfNeeded: h >> (($0 % 8) * 8)) }
    }
}
#endif
@MainActor enum IOSPrivateJSONStore {
    static var values: [String: Data] = [:], writes = 0, failRead = false, failWrite = false
    static func read(_ filename: String, maximumBytes: Int) throws -> Data? {
        guard !failRead, (values[filename]?.count ?? 0) <= maximumBytes else { throw NSError(domain: "ReadBoundary", code: 1) }
        return values[filename]
    }
    static func write(_ data: Data, filename: String, maximumBytes: Int) throws {
        guard !failWrite, data.count <= maximumBytes else { throw NSError(domain: "WriteBoundary", code: 1) }
        values[filename] = data; writes += 1
    }
}
func node(_ id: String, external: [String: Any]? = nil) throws -> RouterProfile {
    var root: [String: Any] = ["id": id, "name": id, "node_kind": external == nil ? "router-vpn" : "external",
        "node_proof_id": String(repeating: "a", count: 64), "endpoint": "node.example",
        "router_api": "http://10.77.0.1:8787", "api_token": "private-credential",
        "adguard_ipv4": "10.77.0.1", "adguard_ipv6": "fd77::1", "socks_host": "10.77.0.1",
        "socks_port": 1080, "socks_username": "", "socks_password": ""]
    if let external { root["external"] = external }
    return try JSONDecoder().decode(RouterProfile.self, from: JSONSerialization.data(withJSONObject: root))
}
@main struct Tests {
    @MainActor static func main() throws {
        var checks = 0
        func check(_ label: String, _ value: Bool) {
            guard value else { FileHandle.standardError.write(Data(("FAIL: " + label + "\n").utf8)); exit(1) }
            checks += 1
        }
        func rejects(_ label: String, _ body: () throws -> Void) {
            do { try body(); check(label, false) } catch { checks += 1 }
        }
        func receipt(_ id: String) -> String { IOSNodeUsage.digest(Data(id.utf8)) }
        func count(_ profile: RouterProfile) -> Int { IOSNodeUsage.display([profile]).profiles[0].useCount ?? 0 }
        let now = Date()
        var home = try node("home"); home.useCount = 7
        let raw = try IOSNodeUsage.canonical(home), key = try IOSNodeUsage.key(home)
        try IOSNodeUsage.record(profiles: [home], adoption: receipt("one"), at: now)
        check("imported baseline is incremented once", count(home) == 8 && IOSPrivateJSONStore.writes == 1)
        for _ in 0..<4 { try IOSNodeUsage.record(profiles: [home], adoption: receipt("one"), at: now) }
        check("same terminal adoption is idempotent", count(home) == 8 && IOSPrivateJSONStore.writes == 1)
        try IOSNodeUsage.record(profiles: [home], adoption: receipt("two"), at: now.addingTimeInterval(1))
        check("next adopted connection adds one", count(home) == 9)
        check("display keeps complete private source unchanged", try IOSNodeUsage.canonical(home) == raw && home.useCount == 7)
        check("display exposes time in sidecar only", home.lastUsedAt == nil && IOSNodeUsage.display([home]).profiles[0].lastUsedAt != nil)
        let firstStore = IOSPrivateJSONStore.values[IOSNodeUsage.filename]!
        let text = String(decoding: firstStore, as: UTF8.self)
        check("private metric stores no credentials node ids or source", !text.contains("private-credential") && !text.contains("10.77") && !text.contains("home"))
        home.useCount = 20
        try IOSNodeUsage.record(profiles: [home], adoption: receipt("new-import"), at: now.addingTimeInterval(2))
        check("new imported baseline uses maximum not sum", count(home) == 21)
        for _ in 0..<10 { _ = IOSNodeUsage.display([home]) }
        check("UI refresh never adds the imported baseline again", count(home) == 21)

        var policy = home
        policy.name = "Different display"; policy.dnsMode = "custom"; policy.dnsHost = "192.0.2.53"
        policy.manualMTU = 1376; policy.startupMode = "last"; policy.startLayer = "aes-256-gcm"
        policy.homeLANAccess = false; policy.ipv6Mode = "off"; policy.useCount = 0; policy.lastUsedAt = nil
        check("saved policy and telemetry preserve authenticated identity", try IOSNodeUsage.key(policy) == key && count(policy) == 21)
        var replacement = home; replacement.apiToken = "replacement-credential"; replacement.useCount = 0
        check("relinking credentials cannot inherit local usage", try IOSNodeUsage.key(replacement) != key && count(replacement) == 0)
        replacement = home; replacement.nodeProofID = String(repeating: "b", count: 64)
        check("different authenticated Router identity has distinct key", try IOSNodeUsage.key(replacement) != key)
        replacement = home; replacement.routerAPI = "http://10.78.0.1:8787"
        check("same authenticated Router can move its API endpoint", try IOSNodeUsage.key(replacement) == key)
        replacement.apiToken = ""
        rejects("missing API credential cannot create authenticated identity") { _ = try IOSNodeUsage.key(replacement) }
        check("future timestamps cannot dominate recency", IOSNodeUsage.parsedDate("2999-11-01T00:00:00Z") == nil)
        let originalJSON = Data("{\"apiToken\":\"one\",\"selected\":{\"apiToken\":\"same\"}}".utf8)
        let replacedJSON = Data("{\"selected\":{\"apiToken\":\"same\"},\"apiToken\":\"two\"}".utf8)
        check("raw source comparison retains every compatibility field", try IOSNodeUsage.canonicalJSON(originalJSON) != IOSNodeUsage.canonicalJSON(replacedJSON))

        let entry = try node("entry")
        let beforePath = IOSPrivateJSONStore.writes
        try IOSNodeUsage.record(profiles: [home, entry, home], adoption: receipt("path"), at: now.addingTimeInterval(3))
        check("final distinct entry and exit update atomically", count(home) == 22 && count(entry) == 1 && IOSPrivateJSONStore.writes == beforePath + 1)
        try IOSNodeUsage.record(profiles: [entry, home], adoption: receipt("path"), at: now.addingTimeInterval(3))
        check("same path reordered cannot double count", count(home) == 22 && count(entry) == 1)
        replacement = home; replacement.apiToken = "foreign"
        rejects("same node id with foreign credentials rejects entire event") {
            try IOSNodeUsage.record(profiles: [entry, home, replacement], adoption: receipt("ambiguous"), at: now)
        }
        check("ambiguous path cannot partially increment entry", count(entry) == 1)
        let committed = IOSPrivateJSONStore.values[IOSNodeUsage.filename]!
        IOSPrivateJSONStore.failWrite = true
        rejects("storage failure is reported") { try IOSNodeUsage.record(profiles: [entry, home], adoption: receipt("retry"), at: now) }
        check("failed write commits neither node", IOSPrivateJSONStore.values[IOSNodeUsage.filename] == committed && count(entry) == 1 && count(home) == 22)
        check("failed optional save has visible warning", IOSNodeUsage.display([home]).warning != nil)
        IOSPrivateJSONStore.failWrite = false
        try IOSNodeUsage.record(profiles: [home, entry], adoption: receipt("retry"), at: now.addingTimeInterval(4))
        check("same failed event retries exactly once", count(home) == 23 && count(entry) == 2 && IOSNodeUsage.display([home]).warning == nil)
        let persisted = IOSPrivateJSONStore.values[IOSNodeUsage.filename]!
        IOSPrivateJSONStore.values = [:]
        IOSPrivateJSONStore.values[IOSNodeUsage.filename] = persisted
        check("fresh sidecar read retains usage", count(home) == 23 && count(entry) == 2)

        for corrupt in [Data("{}".utf8), Data("{\"schema\":1,\"schema\":1,\"records\":[]}".utf8),
                        Data("{\"records\":[],\"schema\":1,\"unknown\":true}".utf8)] {
            IOSPrivateJSONStore.values[IOSNodeUsage.filename] = corrupt
            rejects("corruption is never overwritten as empty history") { try IOSNodeUsage.record(profiles: [home], adoption: receipt("bad"), at: now) }
            check("corrupt file preserved with truthful imported fallback", IOSPrivateJSONStore.values[IOSNodeUsage.filename] == corrupt && count(home) == 20 && IOSNodeUsage.display([home]).warning != nil)
        }
        IOSPrivateJSONStore.values[IOSNodeUsage.filename] = persisted
        IOSPrivateJSONStore.failRead = true
        rejects("read failure cannot discard existing history") { try IOSNodeUsage.record(profiles: [home], adoption: receipt("unreadable"), at: now) }
        IOSPrivateJSONStore.failRead = false
        check("read failure preserves committed bytes", IOSPrivateJSONStore.values[IOSNodeUsage.filename] == persisted)
        rejects("invalid adoption is rejected") { try IOSNodeUsage.record(profiles: [home], adoption: "not-a-receipt", at: now) }
        rejects("empty path is rejected") { try IOSNodeUsage.record(profiles: [], adoption: receipt("empty"), at: now) }
        var saturated = try node("saturated"); saturated.useCount = Int.max
        try IOSNodeUsage.record(profiles: [saturated], adoption: receipt("saturation"), at: now)
        check("maximum imported count never overflows", count(saturated) == Int.max)

        let external: [String: Any] = ["protocol": "socks5", "expected_public_ip": "203.0.113.9",
            "socks5": ["host": "edge.example", "port": 1080, "username": "account", "password": "secret"]]
        let proxy = try node("proxy", external: external), proxyKey = try IOSNodeUsage.key(proxy)
        try IOSNodeUsage.record(profiles: [proxy], adoption: receipt("proxy"), at: now)
        var proxyPolicy = proxy; proxyPolicy.dnsHost = "192.0.2.53"; proxyPolicy.manualMTU = 1280
        check("external saved policy retains same remote identity", try IOSNodeUsage.key(proxyPolicy) == proxyKey && count(proxyPolicy) == 1)
        proxyPolicy.external?.socks5?.password = "new-secret"
        check("external credential replacement starts fresh local history", try IOSNodeUsage.key(proxyPolicy) != proxyKey && count(proxyPolicy) == 0)
        let wgObject: [String: Any] = ["protocol": "wireguard", "expected_public_ip": "203.0.113.9", "wireguard": [
            "private_key": "private", "peer_public_key": "peer", "preshared_key": "psk", "endpoint": "peer.example:51820",
            "addresses": ["10.8.0.2/32"], "allowed_ips": ["0.0.0.0/0"], "dns": ["10.8.0.1"], "mtu": 1380, "keepalive": 25]]
        let wg = try node("wg", external: wgObject), wgKey = try IOSNodeUsage.key(wg)
        var wgPolicy = wg; wgPolicy.external?.wireGuard?.dns = ["10.8.0.53"]; wgPolicy.external?.wireGuard?.mtu = 1280
        check("WG runtime DNS and MTU are not credential identity", try IOSNodeUsage.key(wgPolicy) == wgKey)
        wgPolicy.external?.wireGuard?.privateKey = "replacement private"
        check("external WG key replacement resets identity", try IOSNodeUsage.key(wgPolicy) != wgKey)

        var a = try node("a"), b = try node("b"), c = try node("c"), d = try node("d")
        a.name = "Alpha"; b.name = "Beta"; c.name = "Alpha"; d.name = "Delta"
        a.useCount = 3; b.useCount = 8; c.useCount = 3; d.useCount = 3
        a.lastUsedAt = "2026-11-01T02:00:00Z"; b.lastUsedAt = "2026-10-31T23:00:00Z"
        c.lastUsedAt = "2026-11-01T02:00:00.000Z"; d.lastUsedAt = "2026-11-01T03:00:00Z"
        let unordered = [c, d, b, a]
        check("Most used orders count then actual date then name and id", IOSNodeSort.used.ordered(unordered, selectedID: "").map(\.id) == ["b", "d", "a", "c"])
        check("Last used uses time not lexical formatting", IOSNodeSort.recent.ordered(unordered, selectedID: "").map(\.id) == ["d", "a", "c", "b"])
        check("current selection remains first", IOSNodeSort.current.ordered(unordered, selectedID: "b").first?.id == "b")
        check("name sorting retains stable duplicate-name tie", IOSNodeSort.name.ordered(unordered, selectedID: "").map(\.id) == ["a", "c", "b", "d"])
        a.latencySamples = 50; a.latencyMedianMs = 5; b.latencySamples = 50; b.latencyMedianMs = 10
        check("measured latency order is preserved", IOSNodeSort.latency.ordered([c, b, a], selectedID: "").map(\.id) == ["a", "b", "c"])
        check("Most used is exposed as real picker option", IOSNodeSort.allCases.contains(.used))
        #if canImport(CryptoKit)
        print("iOS node usage + sort: PASS (\(checks) executable checks; real CryptoKit; private-file boundary double)")
        #else
        print("iOS node usage + sort: PASS (\(checks) executable checks; SHA256 and private-file boundary doubles)")
        #endif
    }
}
'''


def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc required for executable iOS usage tests')
    source = BOUNDARY + '\n' + (APP / 'Models.swift').read_text()
    source += '\n' + (APP / 'IOSNodeUsage.swift').read_text().replace('import CryptoKit\n', '')
    with tempfile.TemporaryDirectory(prefix='routervpn-ios-usage-') as tmp:
        path = Path(tmp) / 'Usage.swift'
        binary = Path(tmp) / 'usage-tests'
        path.write_text(source)
        subprocess.run([swift, '-swift-version', '6', '-module-cache-path', str(Path(tmp) / 'modules'),
                        '-parse-as-library', str(path), '-o', str(binary)], check=True, timeout=150)
        subprocess.run([str(binary)], check=True, timeout=20)


if __name__ == '__main__':
    main()
