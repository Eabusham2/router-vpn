# Router VPN

Self-hosted home-exit VPN/proxy platform for an ASUS AI Board / Portainer Docker host, with persistent ASUS Merlin WAN forwarding, a private Setup Center, generated per-node profiles, native daily-use client apps and cross-platform builds.

Router VPN is MIT-licensed open-source software. See `LICENSE`.

## Normal setup — no giant ZIP required

1. Deploy `server/portainer-current.yaml` from this repository in Portainer using the release-approved exact-SHA image pins.
2. On the home LAN open the Setup Center at `http://AI_BOARD_IP:8786/`.
3. Use its ASUS section to inspect current SSH/JFFS forwarding state before changing anything; preserve unrelated hooks.
4. Install the generic Router VPN app for the device once, then link/import one or more private router/node bundles independently.
5. Start with Raw tunnel / Base Auto, verify the exact selected home node/public exit, then use AUTO, SMART AUTO, CUSTOM or another validated logical mode.

The Setup Center prefers matching same-SHA GitHub client artifacts. If the requested generic artifact is unavailable/unusable, the AI Board can compile only that requested generic client package with a bounded local toolchain, validate/package it, stream it and remove temporary build/output. The production Portainer server stack itself remains exact-SHA image-only and never silently falls back to a moving source build.

Private node data is not baked into public generic installers/Portable ZIPs. One installed application can link multiple nodes without reinstalling.

## Product split

- **Setup Center** — private deployment/setup/admin/recovery/downloads/pairing/Simple Methods/Full Guide/AI Help.
- **Router VPN app** — native daily-use client for nodes, maps, logical modes, AUTO/SMART AUTO/CUSTOM, DNS, kill switch, multihop where supported, MTU/Jumbo, forwarding, settings and diagnostics.

Setup Center **Simple Methods** are simple interoperable protocol configurations for compatible third-party/native clients. Complex Router VPN stacks remain inside the Router VPN app.

## Mode model

The server keeps the established **20 raw runtime profiles** so AUTO, compatibility and generated profile paths remain stable. The app presents **16 logical choices** so WireGuard and AmneziaWG variants are not duplicated as separate user-facing rows.

Where both bases are genuinely supported, the app exposes:

- **Base: Auto** — preferred base first with real compatible fallback
- **Base: WireGuard**
- **Base: AmneziaWG**

Current logical choices, lightest to strongest:

1. Raw tunnel — WireGuard / AmneziaWG Fast
2. Base tunnel + Rosenpass PQ — WireGuard / AmneziaWG
3. AmneziaWG Strong — AWG-only by design
4. Shadowsocks 2022
5. VLESS + REALITY + Vision
6. Hysteria2 + QUIC + Salamander
7. PQ VLESS + REALITY + Vision
8. Shadowsocks + V2Ray TLS
9. Naive HTTPS HTTP/2
10. Naive HTTPS HTTP/3 + QUIC
11. Dual Transport
12. PQ REALITY + XHTTP + FinalMask
13. PQ Dual Transport
14. MAX QUIC — WireGuard / AmneziaWG base selector
15. MAX TLS — WireGuard / AmneziaWG base selector
16. ALL — strongest validated MAX TLS branch with MAX QUIC and cross-base fallback

Utility choices remain **AUTO**, **SMART AUTO**, and **CUSTOM**. Canonical mappings live in `configs/client/logical-modes.json`; the raw runtime catalog lives in `configs/client/modes.json`.

## Included server/runtime functionality

- WireGuard with userspace `wireguard-go` fallback
- AmneziaWG Fast / Strong
- Rosenpass PQ variants
- VLESS + REALITY + Vision
- hybrid-PQ REALITY
- Shadowsocks 2022
- Hysteria2 / QUIC / Salamander
- Shadowsocks + V2Ray TLS
- Naive H2/H3
- XHTTP / FinalMask
- Dual Transport
- MAX TLS / MAX QUIC
- ALL health-tested fallback
- AUTO / SMART AUTO / CUSTOM
- IPv4/IPv6
- Home AdGuard/public/custom/encrypted DNS policies and real DNS-query RTT benchmarking
- DAITA-like bounded cover traffic; not claimed to be Mullvad DAITA/Maybenot
- private SOCKS5
- OverTLS compatibility
- ShadowsocksR legacy compatibility
- authenticated peer-owned explicit forwarding on eligible tunnel paths; broad Protected DMZ is an authenticated Setup Center/server-admin action
- persistent ASUS Merlin forwarding helper
- authenticated Setup Center, Connected Clients and policy controls
- dynamic client-download jobs with progress/cancel/fallback handling
- bounded/redacted server-side multi-provider AI Help
- multiple saved nodes and real measured-latency ordering
- MTU/PMTU/per-path memory and throughput-aware MTU optimization after private-path proof

## Setup Center Simple Methods

Current simple interoperable Methods are:

- WireGuard Raw
- AmneziaWG 2
- Shadowsocks 2022
- Hysteria2 + QUIC
- SOCKS5 + TLS / OverTLS compatibility
- ShadowsocksR legacy compatibility
- private in-tunnel SOCKS5

Public QR/import URLs are generated only when the required public endpoint/config is actually known. Private SOCKS5 at port `1080` stays LAN/tunnel-only and must never be WAN-forwarded. External-client interoperability remains a live off-LAN release gate.

## Native application targets

First-class native product targets are:

- Windows x64 / ARM64 — native WPF daily-use app and normal Portable ZIPs
- macOS arm64 / amd64 — native AppKit/MapKit app
- Linux amd64 / arm64 — native GTK app
- Android — native `VpnService` app
- iOS / iPadOS — SwiftUI app with PacketTunnel

CI also compiles supported controller/package targets for Linux ARMv7, BSD and illumos where documented.

### Windows

Source includes native raw WireGuard, full-device layered TUN/DNS paths, Windows firewall kill-switch handling, real multihop where supported and validated custom exits. WireGuard/SOCKS5/Shadowsocks/Hysteria2 custom exits are supported. The native OpenVPN 2.7 Windows import/helper/adapter work remains in source because Windows OpenVPN is still a project target, but the current product capability intentionally reports it unavailable until strict Windows lifecycle cleanup passes native leak tests. WSL is not counted as the native Windows VPN implementation.

### macOS

Native routing, PF kill switch, real multihop and standard custom exits are source-implemented. OpenVPN 2.7 supports direct and safe TCP-over-entry cases; unsupported combinations fail closed. Signing/notarization and physical networking/visual validation remain release gates.

### Linux

Native GTK app with broad native runtime coverage, nftables kill switch, real multihop and validated custom exits including native OpenVPN 2.7 direct/safe TCP-over-entry support. Live distro/integration/leak-negative validation remains a release gate.

### Android

Android is a real native `VpnService` implementation with WireGuard, AmneziaWG and the pinned combined libbox/Xray runtime for supported layered modes. AUTO/SMART/CUSTOM, strict-policy handling, exact selected-node proof and a narrow real multihop subset are source-implemented. WireGuard/SOCKS5/Shadowsocks/Hysteria2 custom exits are supported; OpenVPN and unsupported mixed-engine/AWG-entry multihop remain unavailable rather than simulated.

### iOS / iPadOS

The PacketTunnel uses pinned WireGuardKit for real raw WireGuard and the pinned Libbox Apple bridge for supported Router VPN layered profiles. Strict mode uses NetworkExtension route-lockdown controls and fails closed if they are not active. External WireGuard/SOCKS5/Shadowsocks/Hysteria2 use the Libbox PacketTunnel path with exact expected-public-exit proof. OpenVPN, AmneziaWG-only paths and full desktop-equivalent multihop remain unavailable until real pinned Apple dataplanes exist for those capabilities.

## Custom standard-protocol exits

Custom exits are separate from Router VPN `CUSTOM` transport selection and Setup Center Methods. Current product capability:

- WireGuard — Windows/macOS/Linux/Android/iOS
- SOCKS5 — Windows/macOS/Linux/Android/iOS
- Shadowsocks — Windows/macOS/Linux/Android/iOS
- Hysteria2 — Windows/macOS/Linux/Android/iOS
- OpenVPN 2.7 — Linux/macOS where the required runtime and requested direct/hop policy are safely supported; Windows import/helper/adapter source exists but remains unavailable until native strict lifecycle/leak validation passes

Private external-profile credentials stay in platform-private storage. Public list/status/profile APIs expose redacted summaries only. Connected requires exact selected-node/private-exit proof or exact expected-public-exit proof; generic Internet reachability is insufficient.

## Nodes, maps and latency

Native node managers support current/recent, last-used, measured-latency and name ordering. Automatic lowest-latency selection is withheld until at least two usable nodes have real measurements. Node tests use at least about 50 TCP handshake samples where practical and report real statistics. Coordinate-less nodes remain usable in lists; map coordinates are never invented from an IP.

## Production/security boundaries

- Production Portainer is exact-SHA image-only.
- `8786` Setup Center stays private.
- `1080`, `8787`, `14444`, `9443`, SSH and AdGuard admin stay off WAN.
- A mode becomes Ready only from real generated configuration/runtime validation.
- Unsupported platform features stay unavailable with a real reason.
- UI/CSS must never force readiness.
- A green CI build is not physical-device, off-LAN, leak-negative, signing/notarization or production-deploy proof.
- Do not deploy an old release candidate merely because it passed previously.

## Validation policy

GitHub Actions is the normal compile/test environment. Source/security/runtime/package audits, native builds and exact-SHA ARM64 image publication are required before manual release gates.

Physical release validation still requires the relevant real-device VPN permission/TUN, route/DNS/IPv4/IPv6 behavior, exact selected node/public exit, reconnect/network-change handling, fail-closed/leak-negative transitions and custom-exit behavior. Simple external Methods require real off-LAN compatible-client interoperability. Apple distribution requires real signing/notarization. Production requires a deliberate exact-SHA Portainer deploy and live smoke test, followed by ASUS forwarding revalidation where needed.

## More documentation

- `docs/CURRENT-GUIDE.md` — authoritative deployment/use guide
- `docs/CURRENT-STATUS.md` — current source-vs-live release boundary
- `docs/CLIENT.md` — client/platform linking notes
- `docs/NATIVE-APPS.md` — native application boundaries
- `docs/WINDOWS-PORTABLE.md` — Windows Portable ZIP behavior
- `docs/MODES.md` — raw runtime mode details
- `docs/AI-HELP.md` — AI Help provider/configuration boundary
- `SECURITY.md` — security boundaries
- `router/asus-merlin-router-vpn-forwards.sh` — persistent ASUS WAN forwarding helper
