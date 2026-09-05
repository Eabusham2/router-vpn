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
# Windows x64 uses the pinned Tor Expert Bundle + native PowerShell lifecycle;
# Windows ARM64 remains unavailable until Tor Project publishes a pinned native
# Expert Bundle for that architecture.
need(
    "cmd/client/tor_bridge_runtime.go",
    'safeExecutable("lyrebird")',
    'safeExecutable("obfs4proxy")',
    "torBridgeTransportBinary",
    "torBridgeRuntimeCapabilityForRoot",
    'case "windows":',
    'runtime.GOARCH != "amd64"',
    'windowsTorRuntimeExecutable(root, "tor.exe")',
    'windowsTorRuntimeExecutable(root, "lyrebird.exe")',
    'windowsTorRuntimeExecutable(root, "sing-box.exe")',
    "native-tor-bridge-windows.ps1",
    'safeExecutable("powershell.exe")',
    '"-Action", "up"',
    '"-TunnelAlias", "router-vpn-tor"',
    "ClientTransportPlugin ",
    "strings.Join(transports, \",\")",
    "strictLiteralObfs4",
    "multiple or dynamic/CDN/WebRTC bootstrap egress",
    "selectedTorBridgeDNS",
    "HOMEVPN_TOR_PLUGIN_TRANSPORTS=",
    "HOMEVPN_TOR_PT_BINARY=",
)
need(
    "cmd/client/tor_bridge_windows_runtime.go",
    "torWindowsRuntimeWalkLimit",
    "safePinnedRuntimeExecutable",
    "findUniquePinnedRuntimeExecutable",
    "windowsTorRuntimeExecutable",
    'filepath.Join(windowsRoot, "tor-expert")',
    "must contain exactly one",
    "runtime.GOARCH != \"amd64\"",
    "has no Windows ARM64 build",
)
need(
    "client/Setup-Windows-Runtime.ps1",
    "TorExpertVersion = '15.0.21'",
    "TorExpertWindowsX64Sha256",
    "Install-PinnedTorExpertBundle",
    "tor.exe",
    "lyrebird.exe",
    "TorNativeAvailable = $true",
    "Tor unavailable on Windows ARM64",
)
need(
    "client/native-tor-bridge-windows.ps1",
    "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
    "AssignProcessToJobObject",
    "windows-kill-switch.ps1",
    "Bootstrapped 100%",
    "Tor SOCKS listener is unavailable after bootstrap",
    "Tor PT binary changed after capability proof",
    "Tor circumvention process exited; tearing down full-device path",
)
need(
    "cmd/client/tor_bridge_windows_runtime_test.go",
    "TestPinnedWindowsTorRuntimeResolverRequiresOneRegularExecutable",
    "TestPinnedWindowsTorRuntimeResolverRejectsSymlink",
    "TestWindowsTorControllerUsesPinnedNativeLifecycle",
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
# truth. The shipping /api/tor-bridge/import boundary owns all Tor profile
# construction and delegates only final transactional persistence to the shared
# private external-profile store. A second unregistered Tor builder is forbidden.
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
    "torBridgeRuntimeCapabilityForRoot",
    'runtime.GOOS == "windows"',
    'windowsTorRuntimeExecutable(root, "lyrebird.exe")',
)
need(
    "cmd/client/tor_bridge_import.go",
    "torBridgeImportRequest",
    "/api/external-profile/import",
    "common.NormalizeRouterProfile",
    'profile.DNSMode = "rescue"',
    "strictLiteralObfs4",
    "dynamic bootstrap egress can be scoped safely",
    "standardExitFromExternalProfile(profile)",
    "externalRuntimePolicy(profile)",
)
if (ROOT / "cmd/client/tor_bridge_profile.go").exists():
    errors.append("cmd/client/tor_bridge_profile.go: duplicate/unregistered Tor profile builder must remain removed")

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

# Native desktop forms must actually ship, not merely exist as orphan sources.
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
    "client/RouterVPN-Windows-TorBridge.ps1",
    "UnifiedTorButton",
    "Tor bridges…",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
)
need(
    "client/RouterVPN-Windows-App.ps1",
    "RouterVPN-Windows-TorBridge.ps1",
    "Add-RouterVPNTorBridgeUI",
)
need(
    "client/linux/routervpn-tor-bridge-v13.inc",
    "LinuxTorBridgeV13",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "obfs4",
    "meek / meek_lite",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
    "profile data cannot inject ClientTransportPlugin commands",
)
need(
    "client/linux/routervpn-unified-shell-v8.inc",
    '#include "routervpn-tor-bridge-v13.inc"',
    "linux_unified_tor_v13",
    "Tor bridges…",
)
need(
    "client/linux/build-native-app.sh",
    "routervpn-unified-shell-v8.inc",
    "gcc -O2 -Wall -Wextra -Werror",
)

# Setup Center must explain the same real censorship-evasion family without
# publishing private bridge lines or pretending dynamic PT bootstrap is covered
# by the endpoint-only strict kill switch.
need(
    "server/scripts/setup_center_guide.py",
    "Tor censorship bridges in the Router VPN app",
    "obfs4",
    "meek / meek_lite",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
    "short-lived volunteer WebRTC proxies",
    "dynamic CDN/WebRTC/bootstrap egress",
    "Tor's proved circuit remains the encrypted final path",
    "does not substitute homemade XOR/custom cryptography",
)

# Mobile clients remain explicit about the full PT family instead of exposing a
# cosmetic desktop-equivalent path. Android and iOS only become connect-capable
# after they own real native Tor/PT tunnel lifecycles and dynamic-exit proof.
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java",
    "Tor bridges (obfs4 / meek / Snowflake / WebTunnel / Custom) are unavailable on Android",
    "real native Tor + pluggable-transport VpnService dataplane",
    "must not be approximated as SOCKS5",
)
forbid(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java",
    "Tor obfs4 bridge is unavailable on Android",
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
