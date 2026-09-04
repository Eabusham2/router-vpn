#!/usr/bin/env python3
"""Authoritative Tor censorship-circumvention and shipping contract."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing Tor source: {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing Tor marker {marker!r}")


def forbid(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden Tor marker {marker!r}")


# Canonical external profile model: PT family is explicit, dynamic Tor exit is
# never replaced with a user-supplied fixed public IP, and imported data cannot
# supply executable paths or torrc directives.
need(
    "internal/common/types.go",
    "ExternalTorBridgeConfig",
    'Transport string `json:"transport,omitempty"`',
    'TorBridge *ExternalTorBridgeConfig `json:"tor_bridge,omitempty"`',
)
need(
    "internal/common/tor_bridge.go",
    'return "obfs4", nil',
    'return "meek_lite", nil',
    'return "snowflake", nil',
    'return "webtunnel", nil',
    'return "custom", nil',
    "TorBridgeTransport",
    "mixed Tor pluggable transports require transport=custom",
    "ClientTransportPlugin",
)
need(
    "internal/common/profile_schema.go",
    'case "tor", "tor_bridge", "tor-bridge"',
    'ext.Protocol = "tor-bridge"',
    "Tor bridge uses a dynamic circuit exit",
    "normalizeExternalTorBridge",
)
need(
    "internal/common/tor_bridge_test.go",
    "TestTorBridgeSupportsCircumventionTransportFamilies",
    "TestTorBridgeCustomAndAutoAllowRecognizedMixedPTSets",
    "modern meek no fingerprint",
    "TestTorBridgeRejectsCustomTransportInjection",
)

# Desktop runtime: trusted Tor/PT helpers, private torrc, exact transport set,
# bootstrap=100%, full-device TUN, owned children, and dynamic Tor exit proof.
need(
    "cmd/client/tor_bridge_runtime.go",
    'safeExecutable("lyrebird")',
    'safeExecutable("obfs4proxy")',
    "torBridgeTransportBinary",
    "ClientTransportPlugin ",
    "strings.Join(transports, \",\")",
    "strictLiteralObfs4",
    "multiple or dynamic/CDN/WebRTC bootstrap egress",
    "selectedTorBridgeDNS",
    "HOMEVPN_TOR_PLUGIN_TRANSPORTS=",
    "HOMEVPN_TOR_PT_BINARY=",
)
need(
    "modes/native-tor-bridge.sh",
    "Bootstrapped 100%",
    "Tor process start is not connectivity",
    "HOMEVPN_TOR_PT_BINARY",
    "HOMEVPN_TOR_PLUGIN_TRANSPORTS",
    "Tor PT binary changed after capability proof",
    "legacy obfs4proxy cannot provide Snowflake or WebTunnel",
    "record \"$ROOT\" \"$PID_MODE\" \"$tor_pid\"",
    "record \"$ROOT\" \"$PID_MODE\" \"$sing_pid\"",
    "Tor circumvention process exited; tearing down full-device path",
)
need(
    "cmd/client/tor_bridge_proof.go",
    "IsTor",
    "publicTorExit",
    "check.torproject.org",
)
need(
    "cmd/client/tor_bridge_routes.go",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "/api/tor-bridge/connect",
    "tor_transport",
    "tor-project-is-tor-passed",
    "a.stopOwnedConnectionRuntime(cmd)",
    "a.persistProfilesLocked()",
)
need(
    "cmd/client/tor_bridge_dns.go",
    'case "tcp", "tls", "https"',
    "cannot use UDP/Fastest-UDP",
    "cannot use DoH3/QUIC",
)
need(
    "cmd/client/tor_bridge_dns_test.go",
    "TestTorBridgeDNSAllowsTCPCompatibleTransports",
    "TestTorBridgeDNSRejectsDatagramTransports",
)

# Capability and native profile-builder APIs are the one UI-facing source of
# truth. PT descriptions explain censorship behavior while unsupported platform
# dataplanes remain unavailable with reasons.
need(
    "cmd/client/tor_bridge_capabilities.go",
    "obfs4",
    "meek_lite",
    "snowflake",
    "webtunnel",
    "custom",
    "active probing",
    "WebRTC",
    "HTTPS/domain-fronting",
    "strict_kill_switch",
    "upstream_hop",
)
need(
    "cmd/client/tor_bridge_import.go",
    "torBridgeImportRequest",
    "/api/external-profile/import",
    "common.NormalizeRouterProfile",
)
need(
    "cmd/client/tor_bridge_profile.go",
    "torBridgeProfileCreateRequest",
    "beginMutationOperation",
    "a.persistProfilesLocked()",
    "a.rollbackProfilesLocked(previousStore)",
)

# Product semantics: PT is circumvention; the proved Tor circuit is the
# encrypted final path. Tor-as-upstream-hop remains unavailable.
need(
    "client/unified-control-center-v2.json",
    '"id": "tor-bridge"',
    '"final_transport": true',
    '"upstream_hop": false',
    '"meek_lite"',
    '"snowflake"',
    '"webtunnel"',
    '"custom"',
    '"tor-ntor-v3-circuit"',
    '"tor_dynamic_pt_strict_kill_switch_requires_process_scoped_egress": true',
)
need("client/routervpn_unified_control_center.py", '"tor-bridge"', "proven ntor-v3 circuit")
need("client/RouterVPN-Windows-UnifiedControlCenter.ps1", "Tor pluggable transport + proven ntor-v3 circuit")
need("client/macos/UnifiedControlCenterPolicy.swift", "Tor pluggable transport + proven ntor-v3 circuit")

# macOS has a shipping native form today. iOS remains explicit/unavailable
# rather than pretending the desktop Tor/Lyrebird graph exists in PacketTunnel.
need(
    "client/macos/RouterVPNMenuBar.m",
    "Tor Bridges…",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "obfs4",
    "meek",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
    "short-lived volunteer WebRTC proxies",
    "profile data cannot inject ClientTransportPlugin commands",
)
need(
    "ios/RouterVPN/App/RouterVPNModelExternal.swift",
    "Tor bridges — obfs4 / meek / Snowflake / WebTunnel / Custom",
    "real native Tor + pluggable-transport PacketTunnel dataplane",
)
forbid(
    "ios/RouterVPN/App/RouterVPNModelExternal.swift",
    "Tor obfs4 bridge — unavailable",
    "Tor obfs4 bridges are unavailable",
)

# Homemade cipher ideas are explicitly superseded. The outer PT can disguise
# traffic, but confidentiality is provided by vetted Tor/tunnel cryptography.
for rel in (
    "client/unified-control-center-v2.json",
    "client/routervpn_unified_control_center.py",
    "client/RouterVPN-Windows-UnifiedControlCenter.ps1",
    "client/macos/UnifiedControlCenterPolicy.swift",
):
    forbid(rel, "xor cipher", "homemade cipher", "custom packet cipher")

if errors:
    print("TOR CIRCUMVENTION SHIPPING AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("TOR CIRCUMVENTION SHIPPING AUDIT: PASS")
