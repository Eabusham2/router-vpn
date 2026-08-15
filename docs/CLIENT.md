# Install and use Router VPN clients

The complete server/router walkthrough is in `docs/CURRENT-GUIDE.md`. This file focuses on installing the generic app once and linking one or more private nodes afterward.

## Recommended link path

You normally **do not need a permanent `router-vpn-client-bundle.zip`**.

1. Stay on the home LAN.
2. Open `http://AI_BOARD_IP:8786/`.
3. Install the generic client package for the device, or use one of the Setup Center Simple Methods in a compatible external app.
4. Link Router VPN using the small private `router-vpn-bundle.json`, LAN import/pairing where exposed, or the validated external-profile import path for a custom standard exit.
5. Start with **Raw tunnel** using **Base: Auto**. Auto prefers the saved/default base and can fall back to the other compatible base when the platform supports it.
6. Verify the exact selected node/public exit before moving to stronger methods.

The full private bundle remains available on demand for offline recovery/advanced use; generic public installer/Portable artifacts contain no linked home secrets. One installed application can link multiple nodes without reinstalling.

## Setup Center

The Setup Center is the private server/router onboarding, recovery and compatibility surface. It provides:

- persistent onboarding and Full Guide
- ASUS SSH/JFFS/forwarding checks and helper download
- current fixed WAN listener list and private ports that must never be exposed
- private node profile/bundle linking material
- platform packages and checksums
- Simple Methods for interoperable external/native clients
- Connected Clients/admin controls
- download progress/cancel/fallback handling
- server-side multi-provider AI Help

Large packages are requested through the download broker. It prefers the matching same-SHA GitHub artifact. If unavailable/unusable, the AI Board compiles only the requested generic client package with the bounded local toolchain, validates/packages it, streams it and removes temporary build/output. Private node data remains separate from the generic application package.

QR images are generated only for a real supported import payload. Treat private JSON, QR codes and generated profiles as credentials.

## Simple Methods

Setup Center Methods is intentionally limited to simple, interoperable external/native-compatible configurations. Complex Router VPN logical stacks remain inside the Router VPN app.

Current Simple Methods are:

- WireGuard Raw
- AmneziaWG 2
- Shadowsocks 2022
- Hysteria2 + QUIC
- SOCKS5 + TLS / OverTLS compatibility
- ShadowsocksR legacy compatibility
- private in-tunnel SOCKS5

A public import URL/QR is emitted only when the required public endpoint and protocol material are actually known. Private SOCKS5 does not get a WAN QR and must never be exposed just to make a third-party app work.

External-app interoperability is a live release gate: off-LAN import → connect → tunneled DNS → HTTP → exact expected public exit must be proven in a genuinely compatible client.

## Logical modes and base selection

The Router VPN app shows one row per logical method instead of duplicating WireGuard and AmneziaWG runtime variants. The server still retains the raw 20-mode catalog internally for AUTO and compatibility.

For compatible logical methods, choose:

- **Auto** — preferred base first, alternate compatible base as fallback
- **WireGuard**
- **AmneziaWG**

The current logical mapping lives in `configs/client/logical-modes.json`. Availability comes from actual generated-profile/runtime checks. If a preferred base fails and fallback succeeds, the UI must report that real fallback instead of claiming the original base stayed active.

## Windows — x64 and ARM64

GitHub Actions produces native WPF Windows packages and Router VPN's own no-install Portable ZIPs for both architectures. Installed and Portable packages use the loopback controller as private implementation plumbing and launch the WPF app rather than a browser/WebView shell.

PortableApps.com/PAF packages are not produced or supported. Use `RouterVPN-Portable-Windows-amd64.zip` or `RouterVPN-Portable-Windows-arm64.zip` for the no-install layout.

Windows source includes native raw WireGuard, full-device layered TUN/DNS paths, a Windows firewall kill switch and real multihop where supported. WSL is **not** counted as the native Windows VPN implementation.

Validated custom exits support WireGuard, SOCKS5, Shadowsocks and Hysteria2 through the standard external runtime. A native OpenVPN 2.7 adapter/helper path is also implemented where the required pinned runtime/helper and requested direct/hop policy can be represented safely. Unsupported graphs fail closed and Connected is withheld until the expected public exit is proven.

Physical Windows full-device routing, DNS/IPv4/IPv6, reconnect/network-change, leak-negative, custom-exit and package-variant testing remain release gates.

## macOS — Apple Silicon and Intel

The macOS package contains the real AppKit/MapKit `RouterVPN.app` for arm64 and amd64. Native routing, PF kill-switch handling, real multihop and standard custom exits are source-implemented. WireGuard/SOCKS5/Shadowsocks/Hysteria2 custom exits are supported. OpenVPN 2.7 supports direct and the safe TCP-over-entry case; unsupported OpenVPN/DNS/hop combinations fail closed.

Unsigned/local builds should use the targeted System Settings → Privacy & Security → Open Anyway flow only after checksum verification. Do not globally disable Gatekeeper. Signing/notarization plus physical macOS networking/visual validation remain release gates.

Legacy/full-bundle installer paths remain available for recovery, but the current daily-use package opens the native AppKit app.

## Linux

Linux x64/ARM64 packages contain the native GTK application. Linux has broad native runtime coverage, nftables kill-switch handling, real multihop, validated external-node import/direct/hopped flows and native OpenVPN 2.7 direct/safe TCP-over-entry support.

Live distro/runtime integration, DNS/IPv4/IPv6, leak-negative and custom-exit testing remain release gates.

## Android

Android is a real native `VpnService` application, not a controller/importer-only shell. It includes real WireGuard and AmneziaWG paths plus the pinned combined libbox/Xray runtime for supported layered modes. AUTO/SMART/CUSTOM require exact selected-node proof. Strict policy, reconnect/network-change handling and a deliberately narrow real multihop subset are source-implemented.

Custom exits support WireGuard, SOCKS5, Shadowsocks and Hysteria2 in one full-device path with expected-public-exit proof. OpenVPN and unsupported AWG-entry/mixed-engine multihop remain unavailable rather than simulated.

Physical Android VPN-permission, lockdown, reconnect, DNS/IPv4/IPv6, custom-exit and leak-negative tests remain release gates.

## iPhone / iPad

The SwiftUI app uses a real pinned WireGuardKit PacketTunnel for raw WireGuard and the pinned Libbox Apple bridge for supported Router VPN layered profiles. It imports/links private nodes, preserves per-node bundle ownership, requires exact selected-node proof and follows real NetworkExtension state rather than marking Connected merely because startup was requested.

Strict mode uses NetworkExtension route-lockdown controls and fails closed when those controls are not active. External WireGuard, SOCKS5, Shadowsocks and Hysteria2 use the Libbox PacketTunnel path and require the expected public exit before Connected.

External OpenVPN, AmneziaWG-only paths and full desktop-equivalent multihop remain unavailable until a real pinned Apple dataplane exists for them. Unsupported MAX/ALL combinations stay unavailable rather than being inferred from labels.

Physical iPhone/iPad VPN permission, route lockdown, reconnect, DNS/IPv4/IPv6, Libbox/custom-exit traffic, leak-negative behavior and signing remain release gates.

## Multiple routers / nodes

Each linked node keeps separate private generated/profile material. Native node managers support:

- current/recent and last-used ordering
- name ordering
- real measured-latency ordering
- automatic lowest-latency selection only after at least two usable nodes have real measurements
- at least about 50 TCP handshake samples per requested node test where practical
- min / median / trimmed mean / average / p90 / max

Coordinate-less nodes remain usable in the list. Never invent map coordinates or infer a location merely from an IP.

## Custom standard exits

Custom standard exits are separate from Router VPN's `CUSTOM` transport selector and separate from Setup Center Methods. They can be direct exits or, where the platform/runtime safely supports it, be reached through a selected entry while preserving one fail-closed full-device path.

Current source support:

- WireGuard — Windows/macOS/Linux/Android/iOS
- SOCKS5 — Windows/macOS/Linux/Android/iOS
- Shadowsocks — Windows/macOS/Linux/Android/iOS
- Hysteria2 — Windows/macOS/Linux/Android/iOS
- OpenVPN 2.7 — Windows/macOS/Linux only where the required runtime/helper and requested direct/hop policy are supported

Desktop secrets stay in private `0600` controller storage; Android uses app-private storage; iOS uses its private per-node bundle store. Public profile/node APIs expose redacted summaries only.

## DNS

Default policy is Home AdGuard. Other choices include fastest measured public DNS, common primary/secondary IPv4/IPv6 resolvers, custom UDP/TCP, DoT, DoH, DoH3 and DNS Rescue. Fastest uses real DNS-query timing, not ICMP ping. Live tunneled-DNS/leak-negative proof remains separate from configuration readiness.

## SOCKS5 and compatibility

Private home SOCKS5:

```text
LINKED_NODE_PRIVATE_HOST:1080
```

Trusted LAN/tunnel only, no authentication. **Never WAN-forward TCP 1080.**

OverTLS:

```text
Public TCP:       14443
Private backend:  127.0.0.1:14444
```

Never expose `14444`.

ShadowsocksR legacy compatibility:

```text
Public TCP+UDP: 15443
```

Prefer modern Shadowsocks 2022 for new setups.

## Port forwarding / Protected DMZ

Inbound forwarding requires an authenticated peer-capable path, normally WireGuard or AmneziaWG. Proxy-only modes do not magically gain arbitrary inbound forwarding. Protected DMZ excludes reserved VPN, SSH, DNS, management, Portainer, Setup Center/API and internal SOCKS5 ports.

## Availability / truth rule

Do not hide a broken mode and do not force it green. Generated configuration/runtime checks decide readiness. `Connected` requires exact selected-node or expected-exit proof, not generic Internet reachability. Unsupported platform features remain unavailable with an exact reason until their real dataplane is present and validated.
