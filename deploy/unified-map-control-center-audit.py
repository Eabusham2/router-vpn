#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing {marker!r}")


def forbid(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden {marker!r}")


contract = json.loads(read("client/unified-control-center-v2.json") or "{}")
if contract.get("bottom_sheet_order") != ["connection", "multihop", "settings", "mode", "dns"]:
    errors.append("canonical bottom-sheet order drifted")
for key, expected in {
    "mode": "smart-auto",
    "selected_node_count": 1,
    "ipv6": True,
    "mtu_policy": "auto",
    "auto_require_encrypted": False,
    "auto_require_obfuscation": False,
    "authenticated_transport": True,
}.items():
    if contract.get("defaults", {}).get(key) != expected:
        errors.append(f"default {key} drifted")
secure = contract.get("secure_transport", {})
if secure.get("mandatory") is not True or secure.get("xor_allowed") is not False or secure.get("custom_crypto_allowed") is not False:
    errors.append("secure transport must be mandatory and reject XOR/custom ciphers")

need(
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "IOSUnifiedMap",
    "controlSheet(height:",
    "connectionButtonTitle",
    "Test & select fastest",
    'title: "Multihop"',
    'title: "Profiles & bridges"',
    'title: "Settings"',
    'title: "Mode"',
    'Label("DNS"',
    "IOSUnifiedCustomBuilder",
    "IOSUnifiedSecureTransport.handshakeLabel",
    'Section("Secure transport")',
    ".presentationDetents([.medium, .large])",
    "Setup is ready. Open Setup guide",
)
ios_profile_sources = "\n".join(
    p.read_text(encoding="utf-8", errors="replace")
    for p in (ROOT / "ios/RouterVPN/App").glob("*.swift")
)
for marker in ("IOSConnectionProfileStore", "static func add", "static func update", "static func delete", "static func load"):
    if marker not in ios_profile_sources:
        errors.append(f"iOS profile CRUD source missing {marker!r}")

forbid(
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "Test & connect fastest",
    "private func connectSpecific",
    "private func connectFastest",
)

# iOS policy must be an intersection of the shared product catalog and the real
# Apple PacketTunnel, not a copy of desktop/cross-platform capability. The
# PacketTunnel currently owns WG + the bounded Libbox external families; AWG,
# OpenVPN and Tor remain explicit unavailable truths.
need(
    "ios/RouterVPN/App/IOSUnifiedSecureTransport.swift",
    "alwaysOn = true",
    '"router-vpn"',
    '"wireguard"',
    '"shadowsocks-2022"',
    '"hysteria2"',
    '"socks5"',
    '"http-connect"',
    '"https-connect"',
    '"amneziawg": "AmneziaWG is unavailable on iOS',
    '"openvpn": "OpenVPN is unavailable on iOS',
    '"tor-bridge": "Tor bridges are unavailable on iOS',
    "Noise_IK",
    "TLS 1.3",
)
forbid(
    "ios/RouterVPN/App/IOSUnifiedSecureTransport.swift",
    'Set(["router-vpn", "wireguard", "amneziawg", "openvpn", "shadowsocks-2022"])',
    "AmneziaWG Noise_IK + ChaCha20-Poly1305",
    "OpenVPN TLS 1.3 + AEAD",
    "Tor ntor-v3 outer bridge",
)
need(
    "ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift",
    '["wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"]',
    "OpenVPN external exits are unavailable on iOS",
    "Tor bridges are unavailable on iOS",
    "must be a literal IP so setup cannot leak pre-tunnel DNS",
)

# Android has a separate VpnService/runtime capability boundary. OpenVPN and Tor
# are deliberately unavailable there; the unified control policy must not accept
# either merely because the cross-platform catalog contains those node families.
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedControlCenterPolicy.java",
    'DEFAULT_MODE = "smart-auto"',
    "BOTTOM_SHEET_ORDER",
    "AUTHENTICATED_TRANSPORT_ALWAYS_ON = true",
    '"router-vpn", "wireguard", "amneziawg", "shadowsocks", "shadowsocks-2022", "hysteria2"',
    'unavailable.put("openvpn", "OpenVPN is unavailable on Android',
    'unavailable.put("tor-bridge", "Tor bridges are unavailable on Android',
    "String unavailable = UNAVAILABLE_TYPES.get(last)",
    "is a bridge only. Add an authenticated encrypted tunnel after it.",
    "Noise_IK",
    "TLS 1.3",
)
forbid(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedControlCenterPolicy.java",
    '"router-vpn", "wireguard", "amneziawg", "openvpn", "shadowsocks-2022"',
    '"socks5", "http-connect", "https-connect", "shadowsocks-2022", "tor-bridge"',
    "OpenVPN TLS 1.3 + AEAD",
    "Tor ntor-v3 outer bridge",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java",
    'new Capability("openvpn",false',
    'new Capability("tor-bridge",false',
    "OpenVPN custom exit is unavailable on pinned sing-box 1.13.x",
    "Tor bridges (obfs4 / meek / Snowflake / WebTunnel / Custom) are unavailable on Android",
    'Arrays.asList("wireguard","socks5","http","https","shadowsocks","hysteria2")',
    "must be a literal IP to avoid pre-tunnel DNS",
)

need(
    "client/RouterVPN-Windows-UnifiedControlCenter.ps1",
    "DefaultMode = 'smart-auto'",
    "BottomSheetOrder",
    "Tor bridge",
    "Test-RouterVPNSecureNodeChain",
    "Authenticated handshake",
)
need(
    "client/routervpn_unified_control_center.py",
    'default_mode: str = "smart-auto"',
    "bottom_sheet_order",
    "tor-bridge",
    "validate_secure_node_chain",
    "Authenticated handshake",
)
need(
    "server/scripts/setup_center_ux_patch.py",
    "Unified Map Control Center non-blocking overlay contract",
    "pointer-events:none!important",
    "max-height:calc(100dvh - 24px)",
)
need(
    "docs/UNIFIED-MAP-CONTROL-CENTER.md",
    "Node selection never starts a connection",
    "Profiles support create, load, update, delete",
    "per-hop throughput",
    "never invents XOR-based or custom packet encryption",
)

# Existing platform UIs must still be present; the v2 work augments rather than
# deletes their runtime and recovery surfaces.
platform_groups = {
    "windows": list((ROOT / "client").glob("*Windows*.ps1")),
    "linux": [p for p in (ROOT / "client/linux").rglob("*") if p.is_file()] + list((ROOT / "client").glob("*Linux*.py")) + list((ROOT / "client").glob("*linux*.py")),
    "android": list((ROOT / "android").rglob("*.java")) + list((ROOT / "android").rglob("*.kt")),
    "ios": list((ROOT / "ios").rglob("*.swift")),
    "macos": list((ROOT / "client/macos").rglob("*.swift")),
}
for platform, files in platform_groups.items():
    if platform != "macos" and not files:
        errors.append(f"{platform}: native source surface disappeared")

if errors:
    print("UNIFIED MAP CONTROL CENTER AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("UNIFIED MAP CONTROL CENTER AUDIT: PASS")
