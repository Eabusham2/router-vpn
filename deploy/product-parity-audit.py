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


dns_api = require(
    "cmd/client/dns_policy_api.go",
    "/api/dns/policy",
    'case "home"', 'case "fastest"', 'case "custom"', 'case "dot"',
    'case "doh"', 'case "doh3"', 'case "rescue"',
    "disconnect before changing DNS policy",
    "DNS benchmark values are real A/AAAA DNS query RTTs",
    "profile.DNSMode = mode",
)
for forbidden in ("APIToken =", "NodeProofID =", "PrivateKey ="):
    if forbidden in dns_api:
        errors.append(f"cmd/client/dns_policy_api.go: DNS mutation unexpectedly writes secret/identity field: {forbidden}")
require(
    "cmd/client/dns_policy_api_test.go",
    "TestDNSPolicyOnlyMutatesDNSFields",
    "TestApplyDNSPolicyEncryptedInference",
    "TestApplyDNSPolicyRejectsUnsafeOrUnsupported",
)
require(
    "cmd/client/logical_modes.go",
    "ping_min_ms", "ping_max_ms", "traffic_min_pct", "traffic_max_pct",
    "speed_loss_min_pct", "speed_loss_max_pct", "ready_bases", "reason",
)

# Windows ships through the stable wrapper. It must decode Unicode explicitly
# for Windows PowerShell 5.1 and apply exact small-effective-resolution layout
# substitutions before parsing the native WPF product.
require(
    "client/RouterVPN-Windows-App.ps1",
    "Get-Content -LiteralPath $Product -Raw -Encoding UTF8",
    "/api/dns/policy",
    'MinHeight=\"480\" MinWidth=\"640\"',
    'Height=\"2*\" MinHeight=\"140\"',
    'MaxWidth=\"760\"',
    'MinHeight=\"180\"',
    "adaptive small-effective-resolution layout",
)
require(
    "client/RouterVPN-Windows-Product-v2.ps1",
    'Header="Layers"', 'Header="Added ms"', 'Header="Traffic"', 'Header="Speed loss"',
    'Header="Exact reason"', "layers_text", "ping_text", "traffic_text", "speed_text", "reason_text",
    "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS",
    "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "/api/dns/retest",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    "latitude", "longitude", "No real node coordinates",
    "HorizontalScrollBarVisibility=\"Auto\"",
)

# macOS keeps one AppKit/MapKit product source. The build creates an exact
# deterministic adaptive-layout view of that same source before swiftc so the
# shipped app remains usable on compact/high-scaling logical desktops.
require(
    "client/macos/RouterVPNMacProduct.swift",
    "import MapKit", "MKMapView", "latitude", "longitude",
    "layers: ", "added latency", "traffic", "speed loss", "readiness:", "reason:",
    "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "/api/dns/retest",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    ".resizable", "window.minSize",
)
require(
    "client/macos/build-native-app.sh",
    "ADAPTIVE_SRC",
    "window.minSize = NSSize(width: 720, height: 520)",
    "greaterThanOrEqualToConstant: 360",
    "split.setPosition(430, ofDividerAt: 0)",
    "adaptive layout",
)

require(
    "client/linux/routervpn-gtk-product-v5.c",
    "build_modes_page_v5", "Added latency", "traffic", "speed loss", "Readiness:", "Reason:",
    "build_dns_page_v5", "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "/api/dns/retest",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6", "gtk_notebook_set_scrollable",
)
# The tracked v4 source is embedded into the v5 build and contains the actual
# coordinate fields/map path. The explicit empty-state phrase is generated in
# the embedded build layer, so the source guard checks real coordinate facts
# here rather than requiring a build-generated string.
require("client/linux/routervpn-gtk-product-v4.c", "latitude", "longitude", "Map")

require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProductParity.java",
    "listDirectLibboxModes", "listDirectXrayModes", "AndroidKillSwitchPolicy.strictRequested",
    "Added latency", "traffic", "speed loss", "Readiness:",
    "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    "/api/dns/benchmark", "transfer-encoding: chunked", "parseContentLength", "decodeChunked", "MAX_HTTP",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "AndroidProductParity.showModes", "AndroidProductParity.showDNS",
    "HorizontalScrollView", "ScrollView", "Nodes & Map",
)
require("android/app/src/main/AndroidManifest.xml", "android.permission.BIND_VPN_SERVICE", 'android:usesCleartextTraffic="false"')

require(
    "ios/RouterVPN/App/ProductParitySheets.swift",
    "RouterVPNModeMetricsSheet", "RouterVPNDNSSettingsSheet",
    "Added latency", "traffic", "speed loss", "Readiness:",
    "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    "/api/dns/benchmark", "NavigationStack", "List(", "Form",
)
require(
    "ios/RouterVPN/App/ProductRootView.swift",
    "Nodes & Map", "Mode Details", "DNS Settings", "No real node coordinates",
)
require(
    "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift",
    "WireGuardAdapter(with: self)", "RouterVPNLibboxEngine", "includeAllNetworks", "enforceRoutes",
)
require("ios/RouterVPN/project.yml", "NSAllowsLocalNetworking", 'TARGETED_DEVICE_FAMILY: "1,2"')

setup = require(
    "server/scripts/generate-setup-assets.py",
    "Server/source readiness", "Reason / next gate", "20 raw runtimes", "16 logical modes",
    "installed client still revalidates its platform engine/path",
    "Complex Router VPN stacks stay in the Router VPN app",
    "@media(max-width:820px)", "-webkit-overflow-scrolling:touch",
    "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DoT", "DoH", "DoH3", "DNS Rescue",
)
for stale in (
    "Multi-hop is intentionally not labeled ready here yet",
    "strict firewall kill switch and remote “kick every peer” control are not advertised as ready",
    "Shadowsocks, Hysteria2, AmneziaWG, Xray, OverTLS",
):
    if stale in setup:
        errors.append(f"server/scripts/generate-setup-assets.py: stale/superseded product claim returned: {stale}")

require(
    "docs/MODES.md",
    "layers / stack", "engineering added-latency estimate", "engineering traffic-overhead estimate",
    "engineering speed-loss estimate", "runtime readiness", "exact readiness / unavailability reason",
    "Home AdGuard", "Fastest measured resolver", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "A/AAAA DNS query RTTs",
)

if errors:
    for item in errors:
        print("ERROR:", item)
    raise SystemExit(1)

print("Router VPN cross-platform mode/DNS/responsive product-parity audit: PASS")
