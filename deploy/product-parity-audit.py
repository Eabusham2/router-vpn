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


# Shared controller contract: DNS is a narrow profile mutation, not a redacted
# full-profile overwrite, and logical-mode metrics come from the canonical
# controller response with live availability/reason.
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

# Windows: native WPF, explicit UTF-8 for Windows PowerShell 5.1, complete mode
# chart, real DNS controls, real-coordinate map and resizable/scrollable product.
require(
    "client/RouterVPN-Windows-App.ps1",
    "Get-Content -LiteralPath $Product -Raw -Encoding UTF8",
    "/api/dns/policy",
)
require(
    "client/RouterVPN-Windows-Product-v2.ps1",
    'Header="Layers"', 'Header="Added ms"', 'Header="Traffic"', 'Header="Speed loss"',
    'Header="Exact reason"', "layers_text", "ping_text", "traffic_text", "speed_text", "reason_text",
    "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS",
    "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "/api/dns/retest",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    "latitude", "longitude", "No real node coordinates",
    'MinHeight="680"', 'MinWidth="980"', "HorizontalScrollBarVisibility=\"Auto\"",
)

# macOS: native AppKit/MapKit existing dataplane plus complete mode and DNS views.
require(
    "client/macos/RouterVPNMacProduct.swift",
    "import MapKit", "MKMapView", "latitude", "longitude",
    "layers: ", "added latency", "traffic", "speed loss", "readiness:", "reason:",
    "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "/api/dns/retest",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    ".resizable", "window.minSize",
)

# Linux: native GTK product keeps the existing dataplane and now exposes the
# complete mode/DNS contract. Scrollable tabs and scrollers protect narrow UI.
require(
    "client/linux/routervpn-gtk-product-v5.c",
    "build_modes_page_v5", "Added latency", "traffic", "speed loss", "Readiness:", "Reason:",
    "build_dns_page_v5", "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "/api/dns/retest",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6", "gtk_notebook_set_scrollable",
)
require("client/linux/routervpn-gtk-product-v4-embedded.c", "No real node coordinates", "latitude", "longitude")

# Android: one real VpnService product; mode readiness comes from the existing
# WG/AWG/libbox/Xray engine controllers. DNS benchmark is bounded private HTTP
# and understands all standard Go HTTP response framing.
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

# iOS/iPadOS: adaptive SwiftUI sheets, real platform selector/readiness, real
# WireGuardKit/Libbox PacketTunnel, and truthful unsupported graphs.
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

# Setup Center: server/source readiness is deliberately not confused with
# installed-platform runtime readiness. Complex Router VPN stacks stay out of
# the simple Methods lane; stale pre-implementation multihop/kill-switch claims
# must not return. Responsive/mobile behavior remains source-enforced while
# rendered DPI/orientation proof stays a physical release gate.
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
