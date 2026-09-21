#!/usr/bin/env python3
"""Run the shipping WG/AWG parser using API type doubles, without a VPN.

Only the adapter's data types are doubled. Native IPA compilation separately
checks these property assignments against the exact pinned Apple engine.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "ios/RouterVPN/PacketTunnel/WireGuardQuickConfig.swift"
TYPES = r'''
import Foundation
public struct PrivateKey: Equatable {
    public let base64Key: String
    public init?(base64Key: String) { guard Data(base64Encoded:base64Key)?.count == 32 else { return nil }; self.base64Key = base64Key }
}
public typealias PublicKey = PrivateKey
public typealias PreSharedKey = PrivateKey
public struct IPAddressRange {
    public let raw: String
    public init?(from raw: String) { guard !raw.isEmpty else { return nil }; self.raw = raw }
}
public struct DNSServer {
    public let raw: String
    public init?(from raw: String) { guard !raw.isEmpty else { return nil }; self.raw = raw }
}
public struct Endpoint {
    public let raw: String
    public init?(from raw: String) { guard !raw.isEmpty else { return nil }; self.raw = raw }
}
public struct InterfaceConfiguration {
    public var privateKey: PrivateKey
    public var addresses: [IPAddressRange] = []
    public var listenPort: UInt16?, mtu: UInt16?
    public var dns: [DNSServer] = []
    public var junkPacketCount: UInt16?, junkPacketMinSize: UInt16?, junkPacketMaxSize: UInt16?
    public var initPacketJunkSize: UInt16?, responsePacketJunkSize: UInt16?
    public var cookieReplyPacketJunkSize: UInt16?, transportPacketJunkSize: UInt16?
    public var initPacketMagicHeader: String?, responsePacketMagicHeader: String?
    public var underloadPacketMagicHeader: String?, transportPacketMagicHeader: String?
    public init(privateKey: PrivateKey) { self.privateKey = privateKey }
}
public struct PeerConfiguration {
    public var publicKey: PublicKey
    public var preSharedKey: PreSharedKey?
    public var allowedIPs: [IPAddressRange] = []
    public var endpoint: Endpoint?
    public var persistentKeepAlive: String?
    public init(publicKey: PublicKey) { self.publicKey = publicKey }
}
public struct TunnelConfiguration {
    public let name: String, interface: InterfaceConfiguration, peers: [PeerConfiguration]
    public init(name: String, interface: InterfaceConfiguration, peers: [PeerConfiguration]) { self.name = name; self.interface = interface; self.peers = peers }
}
'''
TEST = r'''
import Foundation
import WireGuardKit

let key = Data(repeating:1,count:32).base64EncodedString()
let peer = Data(repeating:2,count:32).base64EncodedString()
let psk = Data(repeating:3,count:32).base64EncodedString()
let plain = "[Interface]\nPrivateKey = \(key)\nAddress = 10.78.0.2/24, fd78:78::2/64\nDNS = 10.77.0.1\nMTU = 1400\nListenPort = 51820\n[Peer]\nPublicKey = \(peer)\nPresharedKey = \(psk)\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.1:51822\nPersistentKeepalive = 25\n"
let parameters = "Jc = 3\nJmin = 40\nJmax = 900\nS1 = 56\nS2 = 48\nS3 = 24\nS4 = 32\nH1 = 10000000-19999999\nH2 = 20000000-29999999\nH3 = 30000000-39999999\nH4 = 40000000-49999999\n"
let awg = plain.replacingOccurrences(of:"[Peer]",with:parameters + "[Peer]")
@main struct Tests {
    @MainActor static var checks = 0
    @MainActor static func check(_ name: String, _ value: @autoclosure () throws -> Bool) throws {
        guard try value() else { fatalError("FAIL: " + name) }; checks += 1
    }
    @MainActor static func reject(_ name: String, _ text: String, amnezia: Bool = false) {
        do { _ = try RouterVPNWireGuardConfig.parse(text, amnezia:amnezia); fatalError("Accepted invalid " + name) }
        catch { checks += 1 }
    }
    @MainActor static func main() throws {
        let wg = try RouterVPNWireGuardConfig.parse(plain)
        try check("WG key preserved", wg.interface.privateKey.base64Key == key)
        try check("WG peer and PSK preserved", wg.peers[0].publicKey.base64Key == peer && wg.peers[0].preSharedKey?.base64Key == psk)
        try check("WG dual-stack addresses", wg.interface.addresses.count == 2 && wg.peers[0].allowedIPs.count == 2)
        try check("WG keepalive uses pinned string API", wg.peers[0].persistentKeepAlive == "25")
        try check("WG has no AWG fields", wg.interface.junkPacketCount == nil && wg.interface.initPacketMagicHeader == nil)
        let fast = try RouterVPNWireGuardConfig.parse(awg, amnezia:true)
        try check("AWG Jc/Jmin/Jmax", fast.interface.junkPacketCount == 3 && fast.interface.junkPacketMinSize == 40 && fast.interface.junkPacketMaxSize == 900)
        try check("AWG S1/S2", fast.interface.initPacketJunkSize == 56 && fast.interface.responsePacketJunkSize == 48)
        try check("AWG S3/S4", fast.interface.cookieReplyPacketJunkSize == 24 && fast.interface.transportPacketJunkSize == 32)
        try check("AWG H1/H2", fast.interface.initPacketMagicHeader == "10000000-19999999" && fast.interface.responsePacketMagicHeader == "20000000-29999999")
        try check("AWG H3/H4", fast.interface.underloadPacketMagicHeader == "30000000-39999999" && fast.interface.transportPacketMagicHeader == "40000000-49999999")
        let strongText = awg.replacingOccurrences(of:"Jc = 3",with:"Jc = 8").replacingOccurrences(of:"Jmax = 900",with:"Jmax = 1200").replacingOccurrences(of:"MTU = 1400",with:"MTU = 1360")
        let strong = try RouterVPNWireGuardConfig.parse(strongText,amnezia:true)
        try check("AWG Strong remains distinct", strong.interface.junkPacketCount == 8 && strong.interface.junkPacketMaxSize == 1200 && strong.interface.mtu == 1360)
        try check("CRLF accepted", RouterVPNWireGuardConfig.parse(awg.replacingOccurrences(of:"\n",with:"\r\n"),amnezia:true).interface.junkPacketCount == 3)
        reject("AWG cannot claim WG", awg)
        reject("AWG cannot silently use plain WG", plain, amnezia:true)
        for line in parameters.split(separator:"\n") {
            reject("missing AWG field \(line)", awg.replacingOccurrences(of:String(line)+"\n",with:""), amnezia:true)
            reject("duplicate AWG field \(line)", awg.replacingOccurrences(of:String(line)+"\n",with:String(line)+"\n"+String(line)+"\n"), amnezia:true)
        }
        for bad in ["4294967296", "1-4294967296", "4294967296-1", "19999999-10000000", "10-20-30", "-1", "+1", "abc"] {
            reject("invalid H1 \(bad)",awg.replacingOccurrences(of:"10000000-19999999",with:bad),amnezia:true)
        }
        for bad in ["-1", "65536", "three"] { reject("invalid Jc \(bad)",awg.replacingOccurrences(of:"Jc = 3",with:"Jc = \(bad)"),amnezia:true) }
        reject("inverted junk-size interval",awg.replacingOccurrences(of:"Jmin = 40",with:"Jmin = 901"),amnezia:true)
        for field in ["PrivateKey = \(key)","MTU = 1400","ListenPort = 51820","PublicKey = \(peer)","PresharedKey = \(psk)","PersistentKeepalive = 25","Endpoint = 192.0.2.1:51822"] {
            reject("duplicate singleton",plain.replacingOccurrences(of:field,with:field+"\n"+field))
        }
        reject("multiple interface sections",plain+"[Interface]\nAddress = 10.78.0.3/32\n")
        reject("peer before interface","[Peer]\nPublicKey = \(peer)\n"+plain)
        reject("unknown interface hook",plain.replacingOccurrences(of:"[Peer]",with:"PostUp = forbidden\n[Peer]"))
        reject("unknown peer key",plain+"Forbidden = value\n")
        reject("no interface", "[Peer]\nPublicKey = \(peer)\n")
        reject("no peer", plain.components(separatedBy:"[Peer]")[0])
        reject("duplicate peer identity",plain+"[Peer]\nPublicKey = \(peer)\nAllowedIPs = 192.0.2.0/24\n")
        reject("oversized input",String(repeating:"x",count:1024*1024+1))
        try check("repeated address list supported",RouterVPNWireGuardConfig.parse(plain.replacingOccurrences(of:"[Peer]",with:"Address = 10.79.0.2/32\n[Peer]")).interface.addresses.count == 3)
        print("Native WireGuard/AmneziaWG parser: PASS (\(checks) checks; adapter types doubled, no tunnel opened)")
    }
}
'''

def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc required for native parser behavior tests")
    provider = (PARSER.parent / "PacketTunnelProvider.swift").read_text()
    assert 'amnezia: requestedMode != "wg"' in provider, "native provider does not enforce the claimed WG/AWG family"
    with tempfile.TemporaryDirectory(prefix="routervpn-wg-parser-") as tmp:
        tmp = Path(tmp)
        types, tests = tmp / "AdapterTypes.swift", tmp / "Tests.swift"
        types.write_text(TYPES); tests.write_text(TEST)
        library = tmp / ("libWireGuardKit.dylib" if platform.system() == "Darwin" else "libWireGuardKit.so")
        subprocess.run([swift, "-swift-version", "6", "-emit-module", "-emit-library", "-module-name", "WireGuardKit",
                        str(types), "-emit-module-path", str(tmp / "WireGuardKit.swiftmodule"), "-o", str(library)],
                       check=True, timeout=60)
        binary = tmp / "parser-tests"
        subprocess.run([swift, "-swift-version", "6", "-I", str(tmp), "-L", str(tmp), "-lWireGuardKit",
                        "-Xlinker", "-rpath", "-Xlinker", str(tmp), str(PARSER), str(tests), "-o", str(binary)],
                       check=True, timeout=60)
        subprocess.run([str(binary)], check=True, timeout=15)

if __name__ == "__main__":
    main()
