
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
need(
    "ios/RouterVPN/App/IOSUnifiedSecureTransport.swift",
    "alwaysOn = true",
    "tor-bridge",
    "Noise_IK",
    "TLS 1.3",
    "ntor-v3",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedControlCenterPolicy.java",
    'DEFAULT_MODE = "smart-auto"',
    "DEFAULT_NODE_COUNT" if False else "BOTTOM_SHEET_ORDER",
    "tor-bridge",
    "AUTHENTICATED_TRANSPORT_ALWAYS_ON = true",
    "bridge only",
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
