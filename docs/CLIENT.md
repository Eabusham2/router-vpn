# Install and use Router VPN clients

The complete server/router walkthrough is in `docs/CURRENT-GUIDE.md`. This file focuses on installing the generic app once and linking one or more private nodes afterward.

## Recommended link path

You normally **do not need a permanent `router-vpn-client-bundle.zip`**.

1. Stay on the home LAN.
2. Open `http://AI_BOARD_IP:8786/`.
3. Install the generic client package for the device, or use one of the Setup Center Simple Methods in a compatible external app.
4. Link Router VPN using the small private `router-vpn-bundle.json`, LAN import/pairing where exposed, or the validated external-profile import path for a custom standard exit.
5. The default is **SMART AUTO**. For an explicit basic-path check, choose **Raw tunnel** with **Base: Auto**; it uses the saved/default base and may select the alternate compatible base only when the saved fallback policy permits it.
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

Large packages are requested through the download broker. It tries an exact-SHA published GitHub Release asset first, then a matching same-SHA Actions artifact. Only Windows x64/ARM64 installed and Portable packages have a bounded requested-package fallback on the AI Board. macOS, Linux, Android and iOS require matching native artifacts; the AI Board does not substitute a controller archive or compile the production server stack. Private node data remains separate from the generic application package.

A completed package and its owned workspace remain available for **30 minutes from READY**. Repeat downloads and interrupted-delivery retries do not extend that deadline. Cancel, Delete now and service shutdown clean immediately; expiry cleans automatically, and a failed cleanup remains visible and is retried.

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

The current native external-node path supports WireGuard, AmneziaWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN. OpenVPN readiness depends on the verified packaged native engine; the older helper API's Windows restriction does not describe this path. Every accepted graph requires its selected DNS and expected-public-exit proof before Connected.

Tor bridges use an owned standalone Tor process and native Go pluggable transports. Windows ARM64 runs the verified x64 Tor process through checked Windows 11 userspace compatibility while retaining ARM64 app, packet engine and driver components. See [WINDOWS-TOR-ARM64.md](WINDOWS-TOR-ARM64.md) for the exact boundary.

Physical Windows full-device routing, DNS/IPv4/IPv6, reconnect/network-change, leak-negative, custom-exit and package-variant testing remain release gates.

## macOS — Apple Silicon and Intel

The macOS package contains the real AppKit/MapKit `RouterVPN.app` for arm64 and amd64. Native routing, PF kill-switch handling, real multihop and ordinary external-node paths are source-implemented. The current native external runtime supports WG/AWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN. Tor bridges use the owned standalone Tor/native Go transport path. Graph and device-policy validation still decides whether a particular saved connection is runnable.

Unsigned/local builds should use the targeted System Settings → Privacy & Security → Open Anyway flow only after checksum verification. Do not globally disable Gatekeeper. Signing/notarization plus physical macOS networking/visual validation remain release gates.

Legacy/full-bundle installer paths remain available for recovery, but the current daily-use package opens the native AppKit app.

## Linux

Linux x64/ARM64 packages contain the native GTK application. Linux source includes nftables kill-switch handling, real multihop, native external-node direct/composed paths and the owned Tor bridge runtime. The current native external runtime supports the same eight ordinary protocol families as Windows/macOS, including bounded inline OpenVPN inside one owned packet runtime. Legacy helper restrictions and the current external-node API are separate contracts.

Live distro/runtime integration, DNS/IPv4/IPv6, leak-negative and custom-exit testing remain release gates.

## Android

Android is a real native `VpnService` application. It includes WireGuard and AmneziaWG plus the pinned combined Libbox/Xray runtime for supported layered modes. AUTO/SMART/CUSTOM require exact selected-node proof. Multihop supports captured WG/AWG, PQ, proxy/Xray, helper/composite and complete MAX families, including separately captured Start Layers and supported Local/Server/Compare execution. Each accepted graph retains one system VPN owner and its policy/proof lifecycle.

Ordinary custom nodes support WireGuard, AmneziaWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN through the shared native policy compiler. Plain Tor and supported bridges use the packaged native Tor and Go pluggable transports, directly or through a captured Router entry with Local execution. Tor Server/Compare remains unfinished. Protocol support does not promise every graph combination or every provider's OpenVPN configuration.

Physical Android VPN-permission, lockdown, reconnect, DNS/IPv4/IPv6, custom-exit and leak-negative tests remain release gates. The authoritative delivery supports a configured persistent production signing key, verifies the actual APK and publishes its signing/version receipt; the dedicated CI fallback stays debug-only. The updater compares the actual installed certificate and version before offering a compatible upgrade. See [Android signing and upgrade delivery](../android/PRODUCTION-SIGNING.md). The owner's production configuration and real-device installation/upgrade still require separate evidence.

## iPhone / iPad

The SwiftUI app uses the pinned WireGuardKit/AmneziaWG owner for applicable raw WG/AWG paths and the pinned Libbox Apple bridge for layered, adaptive-MTU, multihop, Tor and ordinary external paths. It imports/links private nodes, preserves per-node bundle ownership, requires exact selected-node proof and follows real NetworkExtension state.

Strict mode uses NetworkExtension route-lockdown controls and fails closed when those controls are not active. External WireGuard, AmneziaWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN use the same owned PacketTunnel and require selected-DNS and expected-public-exit proof.

Supported native multihop includes WG/AWG, PQ, proxy/Xray, helper/composite and complete MAX families with separate entry/exit identities and Start Layers. AUTO, SMART AUTO, CUSTOM and ALL retain their captured trial and restoration contracts. Plain Tor and supported bridges use the native Tor/PT owner, directly or through a captured Router entry with Local execution. Tor Server/Compare remains unfinished; unsupported graphs retain their actual rejection reasons.

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

The current native external-node implementations on Windows, macOS, Linux, Android and iOS/iPadOS include these protocol families:

| Protocol | Required boundary |
| --- | --- |
| WireGuard / AmneziaWG | Preserve the imported peer keys, exact WG/AWG parameters, policy and supported graph. |
| SOCKS5 / HTTP CONNECT / HTTPS CONNECT | Preserve authentication and HTTPS TLS/SNI identity where selected. A plaintext proxy is not authenticated encryption and needs an encrypted inner transport when confidentiality is required. |
| Shadowsocks / Hysteria2 | Preserve the imported protocol, secrets and requested layers. |
| OpenVPN | Use the bounded inline-profile native compiler and userspace endpoint. Literal remote addresses, supported TLS/authentication options, captured remote fallback and transport/MTU compatibility are required. |

OpenVPN Server/Compare through a paired Router entry requires independent provider credentials for Local and Server plus authenticated response-probe metadata. An unmanaged provider import alone does not authorize server execution. Scripts, plugins, local file references, active compression and interactive authentication are outside the supported inline OpenVPN subset; see [MOBILE-OPENVPN.md](MOBILE-OPENVPN.md).

Desktop Router VPN node-to-node multihop is a separate, narrower path: WG/AWG entry with Shadowsocks, Hysteria2, REALITY Vision, PQ REALITY Vision, REALITY XHTTP, Naive H2, Naive H3, WireGuard, AWG Fast or AWG Strong exit. The desktop native selectors, complete profiles and Speed Lab preserve the selected exit mode and Local/Server/Compare execution. WG/AWG Server/Compare requires the updated agent and an independently paired client key on the exit; an older agent that cannot enforce the public identity pin is rejected. Broader Router entry modes and other requested node-to-node compositions remain unfinished. The native external-node API and mobile graph families support additional captured compositions, which do not establish desktop node-to-node parity. See [MULTIHOP-EXECUTION.md](MULTIHOP-EXECUTION.md).

Tor uses a separate circuit/DNS proof and has no fixed expected public exit. Desktop supports direct bridges and captured Router-entry Local execution; mobile also supports plain Tor. Tor Server/Compare, desktop ordinary external predecessors, exit-side desktop Tor padding and dynamic desktop PT strict protection remain unfinished. A single fixed obfs4 bridge can use the desktop strict policy. See [NATIVE-APPS.md](NATIVE-APPS.md).

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

Explicit inbound forwarding from a daily Router VPN app requires an authenticated peer-capable path, normally WireGuard or AmneziaWG, and is owned by that requesting tunnel peer. Clearing peer forwarding removes only that peer's rules. Proxy-only modes do not magically gain arbitrary inbound forwarding.

**Protected DMZ is broader and is intentionally an authenticated Setup Center/server-admin action, not a peer-app mutation.** It excludes reserved VPN, SSH, DNS, management, Portainer, Setup Center/API and internal SOCKS5 ports, and also excludes enabled explicit forwarding ranges so ownership does not collide.

## Availability / truth rule

Do not hide a broken mode and do not force it green. Generated configuration/runtime checks decide readiness. `Connected` requires the selected path's node, DNS and exit/circuit proofs, not generic Internet reachability. Unsupported platform features remain unfinished requirements with an exact reason until their real dataplane is present and validated. Native compilation, exact-SHA publication, physical acceptance and private deployment require separate evidence; an older release cannot certify later source changes.
