# Router VPN native applications

Router VPN client packages are **generic application/runtime packages**. Installing an app and linking a home router are separate operations. The app is installed once; private router/node data can then be added, replaced, revoked or expanded without reinstalling.

A source/build claim is not a physical-device release claim. Real VPN permission, route/DNS/IPv4/IPv6 behavior, reconnect/network-change handling, leak-negative behavior and exact selected-node/exit proof remain live gates where applicable.

## Windows

The Windows daily-use application is native WPF (`PresentationFramework`) and talks to the private loopback Router VPN controller at `127.0.0.1:8788`. Installed and Portable packages launch the WPF application, not Edge/Chrome app mode or a WebView wrapper. Portable self-tests must exit the native UI/controller cleanly and still pass after the folder is relocated.

Windows source includes native raw WireGuard, full-device layered TUN/DNS paths, a Windows firewall kill-switch helper and real multihop where supported. WSL is not counted as the native Windows VPN implementation.

Validated custom exits support WireGuard, SOCKS5, Shadowsocks and Hysteria2. A native OpenVPN 2.7 Windows adapter/helper path is implemented where the required pinned runtime/helper and requested direct/hop graph can be represented safely. Unsupported graphs fail closed; every supported custom exit withholds Connected until its expected public exit is proven.

## macOS

The macOS package contains a native AppKit/MapKit `RouterVPN.app` for amd64 and arm64. It owns a sibling Router VPN controller only when it starts that controller itself. Closing the app performs Router VPN emergency cleanup and stops only the owned process. The app contains no WebKit view.

Native routing, PF kill-switch handling and real multihop are source-implemented. Standard custom exits support WireGuard, SOCKS5, Shadowsocks and Hysteria2. Native OpenVPN 2.7 supports direct and the safe TCP-over-entry case; unsupported OpenVPN/DNS/hop combinations fail closed.

Unsigned/local builds use the targeted System Settings → Privacy & Security → Open Anyway flow only after verifying the artifact. Do not globally disable Gatekeeper. Signed/notarized distribution plus physical macOS visual/network validation remain release gates.

## Linux

Linux packages contain a native GTK3 application for amd64 and arm64, built on matching native GitHub runners. It uses libcurl/json-glib for the loopback controller API and does not launch or embed a browser. The package remains generic and requires GTK3/libcurl/json-glib desktop runtime libraries.

Linux has broad native runtime coverage, nftables kill-switch handling and real multihop. Validated custom exits support WireGuard, SOCKS5, Shadowsocks, Hysteria2 and a native OpenVPN 2.7 direct/safe TCP-over-entry path. Expected-public-exit proof is required before Connected.

## Android

Android is a native `VpnService` application. It has real WireGuard and native AmneziaWG paths plus the pinned combined libbox/Xray runtime for supported layered modes. AUTO/SMART/CUSTOM require exact selected-node private path proof. Strict embedded sessions require the platform lockdown contract; unsupported strict paths fail closed.

The first real Android multihop subset is standard-WireGuard entry → supported Shadowsocks/Hysteria2 exit with exit proof. AWG-entry and incompatible mixed-engine multihop remain unavailable rather than simulated.

Android also has an app-private typed custom-exit store and native Custom Exits UI. WireGuard, SOCKS5, Shadowsocks and Hysteria2 exits are supported through one full-device path with expected-public-exit proof. OpenVPN remains unavailable because this project does not ship a pinned native Android OpenVPN dataplane.

Physical VPN permission, lockdown, reconnect/network change, DNS/IPv4/IPv6, custom-exit traffic and leak-negative validation remain release gates.

## iOS / iPadOS

The SwiftUI app uses a real pinned WireGuardKit PacketTunnel for raw WireGuard and the pinned Libbox Apple bridge for supported Router VPN layered profiles. The tunnel verifies the exact selected node before reporting success.

Strict mode uses NetworkExtension route lockdown (`includeAllNetworks` + `enforceRoutes`), aligns local-network exclusion with imported LAN policy and enables on-demand reconnect; strict startup fails closed when those platform controls are not active.

Per-node private bundle storage and validated external-node selection are implemented. External WireGuard, SOCKS5, Shadowsocks and Hysteria2 use the Libbox PacketTunnel path and require the exact expected public exit before Connected.

External OpenVPN, AmneziaWG-only paths and full desktop-equivalent multihop remain unavailable until a real pinned Apple dataplane exists for them. Unsupported MAX/ALL combinations remain unavailable rather than being inferred from labels.

Physical iPhone/iPad permission, route-lockdown, reconnect/network change, DNS/IPv4/IPv6, Libbox/custom-exit traffic, leak-negative behavior and signing validation remain release gates.

## Nodes, maps and latency

Native node managers support current/recent, last-used, measured-latency and name ordering. Automatic lowest-latency selection is withheld until at least two usable nodes have real measurements. Missing coordinates remain missing; a node can stay fully usable in the list without an invented map position.

## Router linking and node identity

A private router bundle import is data, not application installation. Generic packages contain no linked router secrets. The desktop importer stages decoded private files in a bounded `0700` temporary tree, uses `0600` files, validates names/counts/sizes and the WireGuard server-public-key-derived node identity, then atomically commits the generated profile. A failed import must not leave a partially visible node.

The stable public proof identity is derived from the server WireGuard public key. `Connected` requires the private Router VPN proof endpoint or the custom exit proof path to return/observe the exact expected identity/exit. Generic Internet reachability or `{"ok":true}` alone is not VPN path proof.

## Truth boundary

Unsupported platform capabilities remain unavailable with a real reason. CI/source readiness does not replace physical full-device validation, and UI/CSS must never force a mode or platform feature Ready/Connected.
