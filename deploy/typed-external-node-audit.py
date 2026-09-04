#!/usr/bin/env python3
"""Release-lock the typed Add external node product contract."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing typed-node source: {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing typed-node marker {marker!r}")


def forbid(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden typed-node marker {marker!r}")


# One backend typed creation boundary owns desktop profile validation and durable
# selection. Rich/raw OpenVPN and Tor input remain on dedicated hardened paths.
need(
    "cmd/client/external_profile_create.go",
    "externalProfileCreateRequest",
    'case "wireguard"', 'case "socks5"', 'case "http-connect"',
    'case "https-connect"', 'case "shadowsocks"', 'case "hysteria2"',
    "OpenVPN uses the hardened config import path",
    "Tor bridges use the dedicated censorship-circumvention builder",
    "beginMutationOperation",
    "previousStore := cloneRouterProfileStore(a.profiles)",
    "a.rollbackProfilesLocked(previousStore)",
    'h.HandleFunc("/api/external-profile/create"',
)
need("cmd/client/pairing.go", "registerExternalProfileCreateRoute(h, a)")
need(
    "cmd/client/external_profile_create_test.go",
    "externalProfileCreate",
    "http-connect",
    "https-connect",
    "persistence",
)

# Windows composes the typed form through the already-shipping deterministic Tor
# transform, so the large WPF product does not need a second parallel source.
need(
    "client/RouterVPN-Windows-TorBridge.ps1",
    "Add-RouterVPNExternalNodeWindowsShell",
    "UnifiedExternalNodeButton",
    "Add external node…",
    "/api/external-profile/create",
    "wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2",
    "TestUnifiedExternalMutationIdle",
    "VPN state changed while the external-node dialog was open",
    "Add-RouterVPNExternalNodeWindowsShell -ProductSource",
)
need("client/RouterVPN-Windows-App.ps1", "Add-RouterVPNTorBridgeWindowsShell -ProductSource")

# macOS owns the same typed backend form directly from the native AppKit product.
need(
    "client/macos/RouterVPNMacExternalNode.swift",
    "addExternalNode",
    "/api/external-profile/create",
    '"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"',
    "externalMutationIdle",
    "VPN state changed while the external-node dialog was open",
)

# Linux must physically compose the creator before the map-first unified shell is
# compiled under -Werror. The wiring wrapper only changes the exact Add/manage
# node button and preserves every other make_button() call.
need(
    "client/linux/routervpn-external-node-v14.inc",
    "LinuxExternalNodeV14",
    "/api/external-profile/create",
    "wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2",
    "linux_external_mutation_idle_v14",
    "VPN state changed while the external-node dialog was open",
)
need(
    "client/linux/routervpn-external-node-wire-v14.inc",
    '#include "routervpn-external-node-v14.inc"',
    'g_strcmp0(label, "Add / manage nodes") != 0',
    'make_button("Add external node…"',
    "#define make_button routervpn_make_button_external_v14",
)
need(
    "client/linux/routervpn-auto-requirements-v11.inc",
    '#include "routervpn-external-node-wire-v14.inc"',
)
need(
    "client/linux/build-native-app.sh",
    "routervpn-auto-requirements-v11.inc",
    "gcc -O2 -Wall -Wextra -Werror",
)
need(
    "client/linux/routervpn-unified-shell-v8.inc",
    "typedef struct {\n    App *app;",
    'make_button("Add / manage nodes"',
)

# Android has its own process-owned VpnService/custom-exit store rather than the
# desktop local-controller API. It still exposes the same six real typed families
# and rejects OpenVPN/Tor instead of manufacturing support.
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java",
    'new Capability("wireguard",true', 'new Capability("socks5",true',
    'new Capability("http",true', 'new Capability("https",true',
    'new Capability("shadowsocks",true', 'new Capability("hysteria2",true',
    'new Capability("openvpn",false', 'new Capability("tor-bridge",false',
    "AndroidPrivateFileStore.write",
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java",
    "Add custom exit",
    "HTTP CONNECT",
    "HTTPS CONNECT + TLS",
    "Shadowsocks",
    "Hysteria2",
    "activeOrTransitioning()",
)

# iOS/iPadOS must only offer protocols its pinned PacketTunnel actually runs.
# HTTP/HTTPS CONNECT, OpenVPN and Tor stay absent from the creator until their
# Apple dataplanes are real; external bundles must not inherit home Router/SOCKS
# defaults merely to satisfy the compatibility envelope.
need(
    "ios/RouterVPN/App/IOSExternalNodeBuilderView.swift",
    "IOSExternalNodeProtocol",
    "case wireguard, socks5, shadowsocks, hysteria2",
    "createIOSExternalNode",
    "linkNodeBundle(data)",
    "profileMutationBlocked",
    "literal IP so setup cannot leak pre-tunnel DNS",
    "HTTP/HTTPS CONNECT, OpenVPN and Tor are not presented here",
    '"router_api": ""',
    '"adguard_ipv4": ""',
    '"adguard_ipv6": ""',
    '"socks_host": ""',
    '"socks_port": 0',
    '"routerAPI": ""',
    '"socks5Host": ""',
    '"socks5Port": 0',
)
forbid(
    "ios/RouterVPN/App/IOSExternalNodeBuilderView.swift",
    '"socks_port": 1080',
    '"socks5Port": 1080',
)
need(
    "ios/RouterVPN/App/ProductRootView.swift",
    "showingExternalNodeBuilder",
    "IOSExternalNodeBuilderView",
    "Add external VPN node",
    ".disabled(model.profileMutationBlocked)",
)
need(
    "ios/RouterVPN/App/RouterVPNModelExternal.swift",
    '["wireguard", "socks5", "shadowsocks", "hysteria2"]',
    "Tor bridges — obfs4 / meek / Snowflake / WebTunnel / Custom",
    "IOSNodeBundleStore.shared.link",
)
need(
    "ios/RouterVPN/App/IOSNodeBundleStore.swift",
    "func link(",
    "private func store(",
    "External node id is unsafe",
    "records[key] = normalized",
    "try persist()",
    'bundle.apiToken = ""; bundle.routerAPI = ""; bundle.adGuardIPv4 = ""; bundle.adGuardIPv6 = ""',
    'bundle.socks5Host = ""; bundle.socks5Port = 0',
)
forbid(
    "ios/RouterVPN/App/IOSNodeBundleStore.swift",
    'bundle.socks5Host = ""; bundle.socks5Port = 1080',
)
need(
    "ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift",
    '["wireguard", "socks5", "shadowsocks", "hysteria2"]',
    'case "wireguard"', 'case "socks5"', 'case "shadowsocks"', 'case "hysteria2"',
    "OpenVPN external exits are unavailable on iOS",
)
forbid(
    "ios/RouterVPN/App/IOSExternalNodeBuilderView.swift",
    'case http', 'case https', 'case openvpn', 'case tor',
)

if errors:
    print("TYPED EXTERNAL NODE SHIPPING AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("TYPED EXTERNAL NODE SHIPPING AUDIT: PASS")
