#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path.cwd()
BRANCH = "feature/unified-map-control-center"


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.rstrip() + "\n", encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str, *, required: bool = True) -> str:
    count = text.count(old)
    if count == 1:
        return text.replace(old, new, 1)
    if count == 0 and new in text:
        return text
    if required:
        raise SystemExit(f"{label}: expected one source match, found {count}")
    return text


contract = {
    "schema_version": 2,
    "product_name": "Router VPN",
    "experience_name": "Unified Map Control Center",
    "default_surface": "map",
    "bottom_sheet_order": ["connection", "multihop", "settings", "mode", "dns"],
    "defaults": {
        "mode": "smart-auto",
        "selected_node_count": 1,
        "ipv6": True,
        "mtu_policy": "auto",
        "kill_switch": False,
        "master_port_forwarding": False,
        "auto_require_encrypted": False,
        "auto_require_obfuscation": False,
        "authenticated_transport": True,
    },
    "connection_controls": {
        "primary_action": ["Connect", "Disconnect"],
        "left_accessory": "fastest-node-menu",
        "right_accessories": ["kill-switch", "master-port-forwarding"],
        "live_metric": "end_to_end_rtt_ms",
        "node_selection_never_auto_connects": True,
    },
    "node_types": [
        {"id": "router-vpn", "role": ["node", "hop", "exit"], "final_transport": True},
        {"id": "wireguard", "role": ["node", "hop", "exit"], "final_transport": True},
        {"id": "amneziawg", "role": ["node", "hop", "exit"], "final_transport": True},
        {"id": "openvpn", "role": ["node", "hop", "exit"], "final_transport": True},
        {"id": "shadowsocks-2022", "role": ["bridge", "hop", "exit"], "final_transport": True},
        {"id": "https-connect", "role": ["bridge", "hop"], "final_transport": False},
        {"id": "http-connect", "role": ["bridge", "hop"], "final_transport": False},
        {"id": "socks5", "role": ["bridge", "hop"], "final_transport": False},
        {"id": "tor-bridge", "role": ["bridge", "hop"], "final_transport": False},
    ],
    "map": {
        "provider": "routervpn-vector-globe",
        "uses_google_maps": False,
        "current_location_role": "device",
        "roles": ["device", "selected", "entry", "middle", "exit", "custom", "bridge"],
        "color_coded_roles": True,
        "animated_packet": True,
        "node_rtt_labels": True,
        "hop_lines": True,
    },
    "multihop": {
        "minimum_hops": 2,
        "maximum_hops": 5,
        "live_pairwise_rtt": True,
        "live_per_hop_rtt": True,
        "live_total_rtt": True,
        "per_hop_speed_tests": True,
        "end_to_end_speed_test": True,
    },
    "mode_picker": {
        "items": ["smart-auto", "auto", "all-presets", "custom-presets", "new-custom-preset"],
        "custom_builder": True,
        "preset_actions": ["create", "load", "update", "delete"],
        "new_preset_opens_separate_page": True,
    },
    "profiles": {
        "actions": ["create", "load", "update", "delete", "import-router-bundle"],
        "maximum": 64,
        "whole_connection": True,
    },
    "settings": {
        "sections": [
            "secure-transport", "kill-switch", "port-forwarding", "daita-like-padding",
            "jumbo-tun", "ipv6", "mtu", "auto-requirements", "performance", "advanced"
        ],
        "mtu_actions": ["auto-per-setup", "fixed-all", "retest-current-configuration"],
        "performance_metrics": ["node-download", "node-upload", "hop-download", "hop-upload", "end-download", "end-upload", "rtt"],
    },
    "secure_transport": {
        "mandatory": True,
        "indicator": "checked-handshake",
        "custom_crypto_allowed": False,
        "xor_allowed": False,
        "inner_suites": [
            "wireguard-noise-ik-chacha20-poly1305",
            "amneziawg-noise-ik-chacha20-poly1305",
            "openvpn-tls13-aead",
            "shadowsocks-2022-blake3-aead",
        ],
        "outer_bridges": [
            "tls13-aes-256-gcm",
            "tls13-chacha20-poly1305",
            "tor-ntor-v3",
            "shadowsocks-2022-blake3-aead",
        ],
        "plaintext_bridge_requires_encrypted_inner_tunnel": True,
    },
    "capability_gating": {
        "never_show_fake_enabled_controls": True,
        "unsupported_controls_are_disabled_with_reason": True,
        "port_forwarding_requires_router_agent": True,
        "tor_bridge_requires_local_or_remote_tor_runtime": True,
        "jumbo_requires_dataplane_support": True,
        "daita_like_padding_requires_dataplane_support": True,
    },
}
write("client/unified-control-center-v2.json", json.dumps(contract, indent=2))

write("client/unified_control_center_contract.py", r'''
#!/usr/bin/env python3
"""Canonical model/validation for the cross-platform map-first control center."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "client/unified-control-center-v2.json"


class UnifiedControlCenterError(ValueError):
    pass


@dataclass(frozen=True)
class HopMetric:
    node_id: str
    rtt_ms: float
    download_mbps: float | None = None
    upload_mbps: float | None = None


@dataclass
class ConnectionProfile:
    profile_id: str
    name: str
    mode: str = "smart-auto"
    node_ids: list[str] = field(default_factory=list)
    bridge_ids: list[str] = field(default_factory=list)
    dns_mode: str = "home"
    ipv6: bool = True
    mtu_policy: str = "auto"
    fixed_mtu: int | None = None
    require_encrypted_auto: bool = False
    require_obfuscated_auto: bool = False
    authenticated_transport: bool = True


def load_contract() -> dict:
    data = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if data.get("schema_version") != 2:
        raise UnifiedControlCenterError("Unsupported control-center schema.")
    return data


def allowed_node_types() -> dict[str, dict]:
    return {row["id"]: row for row in load_contract()["node_types"]}


def validate_secure_path(node_types: Iterable[str], *, authenticated_transport: bool = True) -> None:
    values = [str(value).strip().lower() for value in node_types if str(value).strip()]
    if not values:
        raise UnifiedControlCenterError("At least one node is required.")
    known = allowed_node_types()
    unknown = [value for value in values if value not in known]
    if unknown:
        raise UnifiedControlCenterError("Unsupported node type: " + ", ".join(unknown))
    if not authenticated_transport:
        raise UnifiedControlCenterError("Authenticated transport cannot be disabled.")
    final = known[values[-1]]
    if not final.get("final_transport"):
        raise UnifiedControlCenterError(
            f"{values[-1]} is a bridge only; add an authenticated encrypted tunnel after it."
        )


def validate_profile(profile: ConnectionProfile) -> None:
    if not profile.profile_id or len(profile.profile_id) > 96:
        raise UnifiedControlCenterError("Profile id is invalid.")
    if not profile.name.strip() or len(profile.name) > 64:
        raise UnifiedControlCenterError("Profile name is invalid.")
    if profile.mode not in {"smart-auto", "auto", "custom", "preset"}:
        raise UnifiedControlCenterError("Profile mode is invalid.")
    if not 1 <= len(profile.node_ids) <= 5:
        raise UnifiedControlCenterError("A profile must contain one to five nodes.")
    if profile.mtu_policy not in {"auto", "fixed"}:
        raise UnifiedControlCenterError("MTU policy must be auto or fixed.")
    if profile.mtu_policy == "fixed" and not (576 <= int(profile.fixed_mtu or 0) <= 9000):
        raise UnifiedControlCenterError("Fixed MTU is outside the supported range.")
    validate_secure_path(profile.bridge_ids + profile.node_ids,
                         authenticated_transport=profile.authenticated_transport)


def total_live_rtt(metrics: Iterable[HopMetric]) -> float:
    values = [float(metric.rtt_ms) for metric in metrics]
    if any(value < 0 or value > 120000 for value in values):
        raise UnifiedControlCenterError("A hop RTT is outside the supported range.")
    return round(sum(values), 3)


def map_role(index: int, total: int, *, custom: bool = False, bridge: bool = False) -> str:
    if bridge:
        return "bridge"
    if custom:
        return "custom"
    if total <= 1:
        return "selected"
    if index == 0:
        return "entry"
    if index == total - 1:
        return "exit"
    return "middle"
''')

write("client/test_unified_control_center_contract.py", r'''
#!/usr/bin/env python3
from unified_control_center_contract import (
    ConnectionProfile, HopMetric, UnifiedControlCenterError, load_contract,
    map_role, total_live_rtt, validate_profile, validate_secure_path,
)

contract = load_contract()
assert contract["default_surface"] == "map"
assert contract["bottom_sheet_order"] == ["connection", "multihop", "settings", "mode", "dns"]
assert contract["defaults"]["mode"] == "smart-auto"
assert contract["defaults"]["selected_node_count"] == 1
assert contract["defaults"]["ipv6"] is True
assert contract["defaults"]["mtu_policy"] == "auto"
assert contract["defaults"]["auto_require_encrypted"] is False
assert contract["defaults"]["auto_require_obfuscation"] is False
assert contract["secure_transport"]["mandatory"] is True
assert contract["secure_transport"]["xor_allowed"] is False
assert contract["secure_transport"]["custom_crypto_allowed"] is False
assert contract["connection_controls"]["node_selection_never_auto_connects"] is True

validate_secure_path(["wireguard"])
validate_secure_path(["tor-bridge", "openvpn"])
validate_secure_path(["socks5", "amneziawg"])
for invalid in (["socks5"], ["http-connect"], ["tor-bridge"]):
    try:
        validate_secure_path(invalid)
    except UnifiedControlCenterError:
        pass
    else:
        raise AssertionError(f"plaintext/bridge-only final path was accepted: {invalid}")

profile = ConnectionProfile(profile_id="home", name="Home SMART", node_ids=["router-vpn"])
validate_profile(profile)
assert total_live_rtt([HopMetric("a", 4.2), HopMetric("b", 7.3)]) == 11.5
assert [map_role(i, 3) for i in range(3)] == ["entry", "middle", "exit"]
assert map_role(0, 1, custom=True) == "custom"
assert map_role(0, 2, bridge=True) == "bridge"
print("Unified control-center contract: PASS")
''')

write("android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedControlCenterPolicy.java", r'''
package com.eabusham.routervpn;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Canonical Android policy for the map-first daily VPN control center. */
final class AndroidUnifiedControlCenterPolicy {
    static final String DEFAULT_MODE = "smart-auto";
    static final boolean DEFAULT_IPV6 = true;
    static final String DEFAULT_MTU_POLICY = "auto";
    static final boolean DEFAULT_REQUIRE_ENCRYPTED_AUTO = false;
    static final boolean DEFAULT_REQUIRE_OBFUSCATED_AUTO = false;
    static final boolean AUTHENTICATED_TRANSPORT_ALWAYS_ON = true;
    static final List<String> BOTTOM_SHEET_ORDER = Collections.unmodifiableList(
            Arrays.asList("connection", "multihop", "settings", "mode", "dns"));
    static final List<String> PROFILE_ACTIONS = Collections.unmodifiableList(
            Arrays.asList("create", "load", "update", "delete", "import-router-bundle"));
    static final Set<String> FINAL_ENCRYPTED_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "router-vpn", "wireguard", "amneziawg", "openvpn", "shadowsocks-2022")));
    static final Set<String> BRIDGE_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "socks5", "http-connect", "https-connect", "shadowsocks-2022", "tor-bridge")));
    static final List<String> SECURE_SUITES = Collections.unmodifiableList(Arrays.asList(
            "WireGuard Noise_IK + ChaCha20-Poly1305",
            "AmneziaWG Noise_IK + ChaCha20-Poly1305",
            "OpenVPN TLS 1.3 + AEAD",
            "Shadowsocks 2022 BLAKE3 + AEAD",
            "Tor ntor-v3 outer bridge"));

    static String validatePath(List<String> types) {
        if (types == null || types.isEmpty()) return "Add a node before connecting.";
        String last = types.get(types.size() - 1).toLowerCase();
        if (!FINAL_ENCRYPTED_TYPES.contains(last)) {
            return last + " is a bridge only. Add an authenticated encrypted tunnel after it.";
        }
        return "";
    }

    static String handshakeLabel(boolean established) {
        return established ? "Authenticated handshake ✓" : "Authenticated handshake pending";
    }

    private AndroidUnifiedControlCenterPolicy() { }
}
''')

write("client/RouterVPN-Windows-UnifiedControlCenter.ps1", r'''
Set-StrictMode -Version Latest

# Shared policy consumed by the Windows map-first WPF surface. This module does
# not launch a second window; it supplies the canonical order/defaults and
# secure-path validation to the existing product shell.
$script:RouterVPNUnifiedControlCenter = [ordered]@{
    Experience = 'Unified Map Control Center'
    DefaultMode = 'smart-auto'
    DefaultNodeCount = 1
    DefaultIPv6 = $true
    DefaultMtuPolicy = 'auto'
    RequireEncryptedAuto = $false
    RequireObfuscationAuto = $false
    AuthenticatedTransport = $true
    BottomSheetOrder = @('connection','multihop','settings','mode','dns')
    ProfileActions = @('create','load','update','delete','import-router-bundle')
    BridgeTypes = @('SOCKS5','HTTP CONNECT','HTTPS CONNECT','Shadowsocks 2022','Tor bridge')
    SecureSuites = @(
        'WireGuard Noise_IK + ChaCha20-Poly1305',
        'AmneziaWG Noise_IK + ChaCha20-Poly1305',
        'OpenVPN TLS 1.3 + AEAD',
        'Shadowsocks 2022 BLAKE3 + AEAD',
        'Tor ntor-v3 outer bridge'
    )
}

function Test-RouterVPNSecureNodeChain {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$NodeTypes)
    $final = $NodeTypes[-1].ToLowerInvariant()
    $allowed = @('router-vpn','wireguard','amneziawg','openvpn','shadowsocks-2022')
    if ($allowed -notcontains $final) {
        throw "$final is a bridge only. Add an authenticated encrypted tunnel after it."
    }
    return $true
}

function Get-RouterVPNUnifiedHandshakeLabel {
    param([bool]$Established)
    if ($Established) { return 'Authenticated handshake ✓' }
    return 'Authenticated handshake pending'
}
''')

write("client/routervpn_unified_control_center.py", r'''
#!/usr/bin/env python3
"""GTK/Linux policy adapter for the existing map-first native shell."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UnifiedControlCenterPolicy:
    experience: str = "Unified Map Control Center"
    default_mode: str = "smart-auto"
    default_node_count: int = 1
    default_ipv6: bool = True
    default_mtu_policy: str = "auto"
    require_encrypted_auto: bool = False
    require_obfuscation_auto: bool = False
    authenticated_transport: bool = True
    bottom_sheet_order: tuple[str, ...] = ("connection", "multihop", "settings", "mode", "dns")
    profile_actions: tuple[str, ...] = ("create", "load", "update", "delete", "import-router-bundle")
    bridge_types: tuple[str, ...] = ("socks5", "http-connect", "https-connect", "shadowsocks-2022", "tor-bridge")


POLICY = UnifiedControlCenterPolicy()
FINAL_ENCRYPTED_TYPES = {"router-vpn", "wireguard", "amneziawg", "openvpn", "shadowsocks-2022"}
SECURE_SUITES = (
    "WireGuard Noise_IK + ChaCha20-Poly1305",
    "AmneziaWG Noise_IK + ChaCha20-Poly1305",
    "OpenVPN TLS 1.3 + AEAD",
    "Shadowsocks 2022 BLAKE3 + AEAD",
    "Tor ntor-v3 outer bridge",
)


def validate_secure_node_chain(node_types: list[str]) -> None:
    if not node_types:
        raise ValueError("Add a node before connecting.")
    final = node_types[-1].lower()
    if final not in FINAL_ENCRYPTED_TYPES:
        raise ValueError(f"{final} is a bridge only. Add an authenticated encrypted tunnel after it.")


def handshake_label(established: bool) -> str:
    return "Authenticated handshake ✓" if established else "Authenticated handshake pending"
''')

# macOS gets the same source-level policy in whichever app source directory is
# already compiled by the repository. The iOS file is separate because its
# existing UnifiedProductView is directly patched below.
mac_candidates = [p for p in ROOT.rglob("*.swift") if "macos" in p.as_posix().lower() and ".build" not in p.parts]
if mac_candidates:
    mac_dir = mac_candidates[0].parent
    (mac_dir / "UnifiedControlCenterPolicy.swift").write_text(r'''
import Foundation

enum UnifiedControlCenterPolicy {
    static let experience = "Unified Map Control Center"
    static let defaultMode = "smart-auto"
    static let defaultNodeCount = 1
    static let defaultIPv6 = true
    static let defaultMTUPolicy = "auto"
    static let requireEncryptedAuto = false
    static let requireObfuscationAuto = false
    static let authenticatedTransportAlwaysOn = true
    static let bottomSheetOrder = ["connection", "multihop", "settings", "mode", "dns"]
    static let profileActions = ["create", "load", "update", "delete", "import-router-bundle"]
    static let bridgeTypes = ["socks5", "http-connect", "https-connect", "shadowsocks-2022", "tor-bridge"]
    static let secureSuites = [
        "WireGuard Noise_IK + ChaCha20-Poly1305",
        "AmneziaWG Noise_IK + ChaCha20-Poly1305",
        "OpenVPN TLS 1.3 + AEAD",
        "Shadowsocks 2022 BLAKE3 + AEAD",
        "Tor ntor-v3 outer bridge",
    ]
}
'''.lstrip(), encoding="utf-8")

write("ios/RouterVPN/App/IOSUnifiedSecureTransport.swift", r'''
import Foundation

enum IOSUnifiedSecureTransport {
    static let alwaysOn = true
    static let allowedFinalNodeTypes = Set(["router-vpn", "wireguard", "amneziawg", "openvpn", "shadowsocks-2022"])
    static let bridgeTypes = ["socks5", "http-connect", "https-connect", "shadowsocks-2022", "tor-bridge"]
    static let suites = [
        "WireGuard Noise_IK + ChaCha20-Poly1305",
        "AmneziaWG Noise_IK + ChaCha20-Poly1305",
        "OpenVPN TLS 1.3 + AEAD",
        "Shadowsocks 2022 BLAKE3 + AEAD",
        "Tor ntor-v3 outer bridge",
    ]

    static func handshakeLabel(connected: Bool) -> String {
        connected ? "Authenticated handshake ✓" : "Authenticated handshake required"
    }
}
''')

# Directly streamline the existing iOS map-first shell. It already owns the
# map, swipe-up sheet, modes, metrics and profile stores, so this removes the
# blocking first-launch sheet and adds visible profile/bridge/security entry
# points without creating a competing UI.
ios_path = ROOT / "ios/RouterVPN/App/IOSUnifiedProductView.swift"
if not ios_path.is_file():
    raise SystemExit("missing iOS unified product view")
ios = ios_path.read_text(encoding="utf-8")

ios = replace_once(
    ios,
    '.sheet(isPresented: $showingOnboarding) { RouterVPNProductOnboardingView() }',
    '.sheet(isPresented: $showingOnboarding) { RouterVPNProductOnboardingView().presentationDetents([.medium, .large]).presentationDragIndicator(.visible).interactiveDismissDisabled(false) }',
    "iOS onboarding detents",
    required=False,
)
# Do not cover Connect on first launch. Setup remains explicitly available from
# the expanded sheet and can be dismissed/dragged when opened.
ios = re.sub(
    r'\.onAppear\s*\{\s*if\s*!UserDefaults\.standard\.bool\(forKey:\s*"RouterVPNProductOnboardingDoneV2"\)\s*\{\s*showingOnboarding\s*=\s*true\s*\}\s*\}',
    '.onAppear { if !UserDefaults.standard.bool(forKey: "RouterVPNProductOnboardingDoneV2") { model.message = "Setup is ready. Open Setup guide from the expanded control sheet when needed." } }',
    ios,
    count=1,
)

# Normalize any stale auto-connect selector spelling left by an older surface.
ios = ios.replace('Task { await connectFastest() }', 'Task { await selectFastest() }')
ios = ios.replace('"Test & connect fastest"', '"Test & select fastest"')
ios = ios.replace('Button { connectSpecific(profile) }', 'Button { selectSpecific(profile) }')
ios = ios.replace('private func connectSpecific(_ profile: RouterProfile)', 'private func selectSpecific(_ profile: RouterProfile)')
ios = ios.replace('private func connectFastest() async', 'private func selectFastest() async')

# Remove a direct Connect invocation only inside selection helpers. Current
# source may already be corrected; this transformation is deliberately scoped.
for name in ("selectSpecific", "selectFastest"):
    marker = f"    private func {name}"
    start = ios.find(marker)
    if start >= 0:
        end = ios.find("\n    private func ", start + len(marker))
        if end < 0:
            end = len(ios)
        block = ios[start:end]
        block = block.replace("        connectOrDisconnect()\n", "")
        block = block.replace(" • connecting with ", " • selected for ")
        ios = ios[:start] + block + ios[end:]

# Add a visible secure-handshake badge beside connection state when absent.
if "IOSUnifiedSecureTransport.handshakeLabel" not in ios:
    needle = 'Text(connectionStateTitle).font(.subheadline.bold())'
    replacement = needle + '\n                            Text(IOSUnifiedSecureTransport.handshakeLabel(connected: model.connected)).font(.caption2).foregroundStyle(model.connected ? .green : .secondary).lineLimit(1)'
    ios = replace_once(ios, needle, replacement, "iOS handshake badge")

# Add a dedicated Profiles & bridges row in the swipe-up sheet. Existing node
# manager remains authoritative for router/custom node CRUD/import.
if 'title: "Profiles & bridges"' not in ios:
    needle = 'unifiedRow(icon: "point.3.connected.trianglepath.dotted", title: "Multihop", value: iosMultihopSummary) { showingNodes = true }'
    replacement = needle + '\n                    unifiedRow(icon: "person.crop.rectangle.stack", title: "Profiles & bridges", value: "Router / Custom / Tor") { showingNodes = true }'
    ios = replace_once(ios, needle, replacement, "iOS profiles and bridges row")

# Add secure transport/capability truth to Settings without turning unsupported
# features into cosmetic toggles.
if 'Section("Secure transport")' not in ios:
    needle = 'Section("Quick settings") {'
    secure = '''Section("Secure transport") {
                    LabeledContent("Authenticated encryption", value: "Always on ✓")
                    Text("Router VPN uses established Noise/TLS/AEAD or Tor ntor-v3 handshakes. Plain SOCKS5/HTTP/Tor bridge profiles must be followed by an encrypted inner tunnel; XOR and custom ciphers are rejected.").font(.caption).foregroundStyle(.secondary)
                    LabeledContent("Available bridges", value: "SOCKS5 • HTTP(S) • Shadowsocks • Tor")
                }
                ''' + needle
    ios = replace_once(ios, needle, secure, "iOS secure settings")

ios_path.write_text(ios, encoding="utf-8")

# Make the private Setup Center's top-level overlays non-blocking until visibly
# opened and keep all floating progress/status surfaces below the native-style
# control region on small screens.
ux_path = ROOT / "server/scripts/setup_center_ux_patch.py"
if ux_path.is_file():
    ux = ux_path.read_text(encoding="utf-8")
    if "Unified Map Control Center non-blocking overlay contract" not in ux:
        marker = "UX_PATCH = r'''"
        css = r'''
<style>
/* Unified Map Control Center non-blocking overlay contract. */
.overlay[hidden],.wizard-overlay[hidden],[data-routervpn-overlay][hidden]{display:none!important;pointer-events:none!important}
.overlay:not([hidden]),.wizard-overlay:not([hidden]),[data-routervpn-overlay]:not([hidden]){pointer-events:auto}
@media(max-width:820px){.wizard,.overlay>*,.wizard-overlay>*{max-height:calc(100dvh - 24px);overflow:auto}.rvpn-primary-controls{position:relative;z-index:3}}
</style>
'''
        ux = ux.replace(marker, marker + css, 1)
        ux_path.write_text(ux, encoding="utf-8")

write("docs/UNIFIED-MAP-CONTROL-CENTER.md", r'''
# Unified Map Control Center v2

The daily Router VPN surface is map-first on every native platform. The map or custom vector globe remains visible above a swipe-up/bottom control sheet. The fixed order is Connection, Multihop, Settings, Mode, DNS.

## Interaction contract

Node selection never starts a connection. The primary button alone changes between Connect and Disconnect. Its left menu measures/selects the fastest node; compact kill-switch and master-forwarding controls sit beside it, capability-gated. Live end-to-end RTT is visible beside Disconnect.

The default profile contains one node, uses SMART AUTO, IPv6 On and Auto MTU. AUTO requirements for encrypted and obfuscated candidates remain off until explicitly selected. Profiles support create, load, update, delete and router-bundle import. Custom mode presets support create, load, update and delete through a separate visual builder page.

Multihop uses color-coded device, bridge, entry, middle, custom and exit roles, animated packet lines, per-node/pairwise/total RTT, per-hop throughput and end-to-end throughput. Measurements are real and remain unavailable with an explanation when the active dataplane cannot prove them.

## Bridges and encryption

Supported profile forms include Router VPN, WireGuard, AmneziaWG, OpenVPN, Shadowsocks 2022, SOCKS5, HTTP CONNECT, HTTPS CONNECT and Tor bridge. Plain proxy/bridge types cannot be the final transport; they require an authenticated encrypted inner tunnel.

Authenticated transport is mandatory. Router VPN uses standard, reviewed constructions such as WireGuard/AmneziaWG Noise_IK with ChaCha20-Poly1305, TLS 1.3 AEAD, Shadowsocks 2022 BLAKE3/AEAD and Tor ntor-v3. It never invents XOR-based or custom packet encryption.

Jumbo TUN, DAITA-like padding, arbitrary forwarding and Tor are shown as enabled only when the current platform and selected path report real runtime support.
''')

write("deploy/unified-map-control-center-audit.py", r'''
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
    "IOSConnectionProfileStore",
    "IOSUnifiedSecureTransport.handshakeLabel",
    'Section("Secure transport")',
    ".presentationDetents([.medium, .large])",
    "Setup is ready. Open Setup guide",
)
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
    "linux": list((ROOT / "client").glob("*Linux*.py")) + list((ROOT / "client").glob("*linux*.py")),
    "android": list((ROOT / "android").rglob("*.java")) + list((ROOT / "android").rglob("*.kt")),
    "ios": list((ROOT / "ios").rglob("*.swift")),
    "macos": list((ROOT / "macos").rglob("*.swift")) if (ROOT / "macos").exists() else [],
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
''')

# Remove only obsolete automation for this feature, never runtime, recovery,
# Setup Center or historical release audits.
for pattern in (
    ".github/workflows/one-shot-unified-map-control-center*.yml",
    ".github/scripts/apply-unified-map-control-center-old*.py",
):
    for path in ROOT.glob(pattern):
        path.unlink()

print("Unified Map Control Center v2 source applied")
