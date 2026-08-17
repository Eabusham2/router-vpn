#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def text(path: str) -> str:
    p = ROOT / path
    try:
        return p.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{path}: unreadable: {exc}")
        return ""


def require(path: str, *markers: str) -> str:
    body = text(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing product-parity marker: {marker}")
    return body


def require_combined(label: str, paths: tuple[str, ...], *markers: str) -> str:
    body = "\n".join(text(path) for path in paths)
    for marker in markers:
        if marker not in body:
            errors.append(f"{label}: missing composed product-parity marker: {marker}")
    return body


dns_api = require(
    "cmd/client/dns_policy_api.go",
    "/api/dns/policy", 'case "home"', 'case "fastest"', 'case "custom"', 'case "dot"',
    'case "doh"', 'case "doh3"', 'case "rescue"', "disconnect before changing DNS policy",
    "DNS benchmark values are real A/AAAA DNS query RTTs", "profile.DNSMode = mode",
)
for forbidden in ("APIToken =", "NodeProofID =", "PrivateKey ="):
    if forbidden in dns_api:
        errors.append(f"cmd/client/dns_policy_api.go: DNS mutation unexpectedly writes secret/identity field: {forbidden}")
require("cmd/client/dns_policy_api_test.go", "TestDNSPolicyOnlyMutatesDNSFields", "TestApplyDNSPolicyEncryptedInference", "TestApplyDNSPolicyRejectsUnsafeOrUnsupported")
require("cmd/client/logical_modes.go", "ping_min_ms", "ping_max_ms", "traffic_min_pct", "traffic_max_pct", "speed_loss_min_pct", "speed_loss_max_pct", "ready_bases", "reason")

home = require(
    "cmd/client/home_summary.go",
    "/api/home-summary", "/api/home-summary/prove-exit", "SessionID", "ActualExitStatus",
    "actual public exit is not proven for this live session", "session changed while public-exit proof was running",
    "a.profiles.Profiles[i].PublicIP = ip", "proof.SessionID == session.ID", "probePublicExitIP",
)
for forbidden in (
    "ActualExitIP: profile.PublicIP", "ActualExitIP: profile.Endpoint", "actualExit = profile.PublicIP",
    "actualExit = profile.Endpoint",
):
    if forbidden in home:
        errors.append(f"cmd/client/home_summary.go: cached/expected endpoint can be mislabeled as actual exit: {forbidden}")
require(
    "cmd/client/home_summary_test.go",
    "TestHomeSummaryDoesNotTreatCachedProfilePublicIPAsLiveProof",
    "TestHomeSummaryUsesOnlyProofForCurrentSession",
    "TestHomeSummaryReportsFallbackDNSAndSharedState",
)
require("cmd/client/mtu_retest.go", "registerHomeSummaryRoute(h, a)")

require(
    "client/RouterVPN-Windows-App.ps1",
    "Get-Content -LiteralPath $Product -Raw -Encoding UTF8",
    'MinHeight=\"480\" MinWidth=\"640\"', 'Height=\"2*\" MinHeight=\"140\"',
    'MaxWidth=\"760\"', 'MinHeight=\"180\"',
    "SMART AUTO is the default mode", "WireGuard / AmneziaWG",
)
require(
    "client/RouterVPN-Windows-UnifiedShell.ps1",
    "UnifiedShell", "UnifiedMapCanvas", "UnifiedConnectButton", "UnifiedKillSwitch",
    "UnifiedProofButton", "UnifiedEmergencyButton", "Prove actual exit", "Emergency disconnect",
    "/api/home-summary/prove-exit", "actual_exit_status", "actual_exit_ip",
    "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "/api/multihop/connect", "/api/profile/settings", "/api/mtu/retest", "/api/dns/policy",
    "SMART AUTO", "New CUSTOM preset", "real coordinates", "color-coded hop roles",
)
require(
    "client/RouterVPN-Windows-Product-v2.ps1",
    'Header="Layers"', 'Header="Added ms"', 'Header="Traffic"', 'Header="Speed loss"',
    'Header="Exact reason"', "layers_text", "ping_text", "traffic_text", "speed_text", "reason_text",
    "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS",
    "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "/api/dns/retest",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6", "latitude", "longitude",
    "No real node coordinates",
)

require(
    "client/macos/RouterVPNMacProduct.swift",
    "import MapKit", "MKMapView", "latitude", "longitude", "layers: ", "added latency",
    "traffic", "speed loss", "readiness:", "reason:", "Home AdGuard", "Fastest measured",
    "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue",
    "/api/dns/policy", "/api/dns/retest", "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    ".resizable", "window.minSize",
)
require(
    "client/macos/RouterVPNHomeSummary.swift",
    "/api/home-summary", "/api/home-summary/prove-exit", 'actualExitStatus == "proved"',
    "Actual public VPN exit", "Connection:", "Logical/runtime/base", "Fallback:", "DNS:",
    "Node latency", "LAN access", "Kill switch", "Effective MTU", "Warnings:",
)
require_combined(
    "macOS unified shipping product",
    ("client/macos/build-native-app.sh", "client/macos/RouterVPNMacUnifiedShell.swift", "client/macos/RouterVPNHomeSummary.swift"),
    "UNIFIED_SRC", "HOME_SRC", '"$UNIFIED_SRC"', '"$HOME_SRC"',
    "Prove actual exit", "Emergency Disconnect", "SMART AUTO", "CUSTOM", "map-first",
)

require(
    "client/linux/routervpn-gtk-product-v5.c",
    "build_modes_page_v5", "Added latency", "traffic", "speed loss", "Readiness:", "Reason:",
    "build_dns_page_v5", "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "/api/dns/retest",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6", "gtk_notebook_set_scrollable",
)
require("client/linux/routervpn-gtk-product-v4.c", "latitude", "longitude", "Map")
require(
    "client/linux/routervpn-home-summary-v1.inc",
    "/api/home-summary", "/api/home-summary/prove-exit", "Actual public VPN exit", "Connection:",
    "Logical/runtime/base", "Fallback:", "DNS:", "Node measured latency", "LAN access", "Kill switch",
    "Effective MTU", "Warnings:", "on_home_exit_v6",
)
require_combined(
    "Linux unified shipping product",
    ("client/linux/build-native-app.sh", "client/linux/routervpn-unified-shell-v8.inc", "client/linux/routervpn-home-summary-v1.inc"),
    "routervpn-unified-shell-v8.inc", "routervpn-home-summary-v1.inc", "SMART AUTO", "CUSTOM",
    "Connect", "Disconnect", "Kill switch", "Multihop", "Settings", "Mode", "DNS",
    "gcc -O2 -Wall -Wextra -Werror",
)

require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProductParity.java",
    "listDirectLibboxModes", "listDirectXrayModes", "AndroidKillSwitchPolicy.strictRequested",
    "Added latency", "traffic", "speed loss", "Readiness:", "Home AdGuard", "Fastest measured",
    "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6", "/api/dns/benchmark",
    "transfer-encoding: chunked", "parseContentLength", "decodeChunked", "MAX_HTTP",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeSummary.java",
    "TRANSPORT_VPN", "getOwnerUid()", "Process.myUid()", "getNetworkHandle()",
    "AndroidPathProbe.prove", "network.openConnection", "api64.ipify.org", "api.ipify.org",
    "Actual public VPN exit", "Logical/runtime/base", "Node latency", "LAN access", "Kill switch",
    "Effective MTU", "Warnings:", "Emergency Disconnect",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeStateStore.java",
    "session_id", "actual_exit_session", "actualExitForCurrentSession", "begin(", "connected(", "disconnected(",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "RouterVpnNodeMapView", "SMART AUTO — recommended", "New CUSTOM preset", "Details / proof",
    "showConnectionDetails", "AndroidHomeSummary.format", "AndroidHomeSummary.proveActualExit",
    "AndroidHomeSummary.emergencyDisconnect", "Prove actual exit", "Emergency disconnect",
    "AndroidProductParity.showModes", "AndroidProductParity.showDNS", "showSettings",
    "Multihop", "Add Router node", "Add custom / external",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java",
    "AndroidHomeStateStore.begin", "AndroidHomeStateStore.connected", "AndroidHomeStateStore.disconnected",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java",
    "AndroidHomeStateStore.begin", "AndroidHomeStateStore.connected", "AndroidHomeStateStore.disconnected",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java",
    '"SMART AUTO"', '"CUSTOM"', '"AUTO"', '"ALL"', "AndroidHomeStateStore.begin",
    "AndroidHomeStateStore.connected", "baseFor(best)", "AndroidHomeStateStore.disconnected",
)
require(
    "android/app/src/main/AndroidManifest.xml",
    "android.permission.BIND_VPN_SERVICE", 'android:usesCleartextTraffic="false"',
    'android:name=".ProductActivity"', 'android.intent.category.LAUNCHER', 'android:name=".MainActivity"',
)

require(
    "ios/RouterVPN/App/ProductParitySheets.swift",
    "RouterVPNModeMetricsSheet", "RouterVPNDNSSettingsSheet", "Added latency", "traffic", "speed loss",
    "Readiness:", "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    "/api/dns/benchmark", "NavigationStack", "List(", "Form",
)
require(
    "ios/RouterVPN/App/IOSHomeSummaryView.swift",
    "Actual public VPN exit", "selected-node proof passed", "Logical/runtime/base", "Fallback:", "DNS:",
    "Node latency", "LAN access", "Kill switch", "Effective MTU", "Warnings:", "Prove actual exit",
    "Emergency Disconnect", "api64.ipify.org", "api.ipify.org", "model.bundle?.selectedRouterID == selectedNode",
    "model.activeEngine == engine", "model.activeRawProfile == rawProfile", "Cached profile.publicIP is never used as live proof",
)
require_combined(
    "iOS/iPadOS unified root lifecycle",
    ("ios/RouterVPN/App/ProductRootView.swift", "ios/RouterVPN/App/IOSUnifiedProductView.swift"),
    "IOSUnifiedProductView()", "map-first", "SMART AUTO default", "CUSTOM preset builder",
    "RouterVPNProductOnboardingDoneV2",
)
require(
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "IOSUnifiedMap", "IOSHomeSummaryView", "Connect", "Disconnect", "Kill switch", "Multihop",
    "Settings", "Mode", "DNS", "SMART AUTO", "New CUSTOM preset", "real coordinates",
    "systemBlue", "systemOrange", "systemPink", "Require encrypted", "Require obfuscation",
)
require(
    "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift",
    "WireGuardAdapter(with: self)", "RouterVPNLibboxEngine", "includeAllNetworks", "enforceRoutes",
)
require("ios/RouterVPN/project.yml", "NSAllowsLocalNetworking", 'TARGETED_DEVICE_FAMILY: "1,2"')

setup = require(
    "server/scripts/generate-setup-assets.py",
    "Server/source readiness", "Reason / next gate", "20 raw runtimes", "16 logical modes",
    "installed client still revalidates its platform engine/path", "Complex Router VPN stacks stay in the Router VPN app",
    "@media(max-width:820px)", "-webkit-overflow-scrolling:touch", "Home AdGuard", "Fastest measured",
    "Custom UDP/TCP", "DoT", "DoH", "DoH3", "DNS Rescue",
)
for stale in (
    "Multi-hop is intentionally not labeled ready here yet",
    "strict firewall kill switch and remote “kick every peer” control are not advertised as ready",
    "Shadowsocks, Hysteria2, AmneziaWG, Xray, OverTLS",
):
    if stale in setup:
        errors.append(f"server/scripts/generate-setup-assets.py: stale/superseded product claim returned: {stale}")

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN cross-platform unified mode/DNS/proof/responsive product parity audit: PASS")
