# Router VPN

Self-hosted home-exit VPN/proxy platform for an ASUS AI Board / Portainer Docker host, with persistent ASUS Merlin WAN forwarding, a private Setup Center, generated per-node client profiles, and cross-platform client builds.

## Normal setup — no giant ZIP required

1. Deploy `server/portainer-current.yaml` from this repository in Portainer.
2. On the home LAN open the Setup Center at `http://AI_BOARD_IP:8786/`.
3. Use its ASUS section to enable/check LAN-only SSH, inspect existing JFFS forwarding hooks, download the current helper, install it over SSH stdin, and verify `/jffs/scripts/router-vpn-forward.sh status`.
4. Install the Router VPN client for the device, then import the small private `router-vpn-bundle.json` from Files **or directly over the home LAN where the native client supports LAN import**.
5. Start with Raw tunnel / WireGuard, verify the public exit, then use AUTO, SMART AUTO, CUSTOM, or another logical mode.

The complete all-platform ZIP remains an offline/advanced fallback, not the default install path.

## Mode model

The server keeps the established **20 raw runtime modes** so AUTO, compatibility and generated profile paths remain stable. The app presents **16 logical choices** so WireGuard and AmneziaWG variants are not duplicated as separate user-facing modes.

Where both bases are genuinely supported, the app exposes:

- **Base: Auto** — uses the preferred base and can fall back to the other compatible base.
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
11. Dual Transport — REALITY TCP + Hysteria2 QUIC UDP
12. PQ REALITY + XHTTP + FinalMask
13. PQ Dual Transport
14. MAX QUIC — WireGuard / AmneziaWG base selector
15. MAX TLS — WireGuard / AmneziaWG base selector
16. ALL — strongest validated MAX TLS branch with MAX QUIC and cross-base fallback

Utility choices remain **AUTO**, **SMART AUTO**, and **CUSTOM**. The canonical mappings are in `configs/client/logical-modes.json`; the raw runtime catalog remains in `configs/client/modes.json`.

## Included functionality

- WireGuard and AmneziaWG 2 full-tunnel bases
- live Rosenpass hybrid-PQ base profiles
- Shadowsocks 2022
- VLESS / REALITY / Vision / Chrome uTLS
- PQ VLESS / REALITY
- Hysteria2 / QUIC / Salamander
- Shadowsocks + V2Ray-plugin TLS
- Naive HTTPS H2 and H3/QUIC
- XHTTP / FinalMask
- validated MAX TLS/QUIC generated chains
- protocol-split TCP/UDP combined profiles
- runtime-selected endpoint; public address is not compiled into the app
- internal no-auth SOCKS5, never intended for WAN exposure
- SOCKS5 + TLS / OverTLS compatibility profile
- ShadowsocksR legacy compatibility profile
- IPv4 + IPv6 routing/profile material
- Home AdGuard DNS by default
- Fastest public DNS benchmark from the home exit using real DNS queries
- common primary/secondary DNS choices, custom UDP/TCP, DoT, DoH, DoH3 and DNS Rescue policy
- authenticated inbound TCP/UDP/range forwarding and Protected DMZ on a peer-capable WireGuard/AmneziaWG path
- DAITA-like bounded cover traffic; this is not claimed to be Mullvad Maybenot DAITA
- Jumbo TUN option for compatible paths
- multiple saved router/node profiles
- local node map coordinates and sorting by median latency, trimmed mean, distance, usage or name
- node tests with at least 50 TCP handshake samples plus min, median, trimmed mean, average, p90 and max
- public VPN exit IP shown separately from the internal SOCKS5 address
- emergency local transport stop
- persistent/reopenable onboarding and full Setup Center guide
- ASUS Merlin helper that preserves existing JFFS hook contents and keeps management/private ports out of WAN forwarding

## Setup Center

The AI Board Setup Center is the server/router onboarding and recovery surface. It publishes small direct downloads for:

- `router-vpn-bundle.json`
- `asus-merlin-router-vpn-forwards.sh`
- platform mini packages for common desktop architectures
- universal/native protocol configuration and QR guidance
- checksums
- the full private bundle as an advanced fallback

It also documents WireGuard, AmneziaWG, Shadowsocks 2022, Hysteria2, Xray/REALITY, SOCKS5, OverTLS, ShadowsocksR and other generated compatibility paths.

## Client/build targets

GitHub Actions is the compile/test environment; the AI Board should host/publish already-built clients rather than being used as the iterative build/debug machine.

First-class build targets include:

- iOS / iPadOS IPA project and artifacts
- Android APK
- macOS Apple Silicon (`darwin/arm64`)
- macOS Intel (`darwin/amd64`)
- Windows x64 and ARM64
- Linux x64, ARM64 and ARMv7
- FreeBSD x64 / ARM64
- OpenBSD x64 / ARM64
- NetBSD x64 / ARM64
- DragonFly BSD x64
- illumos x64

Common macOS/Linux/Windows packages are also published by the home node when the matching binaries are present.

## Validation policy

A mode is never made green merely to improve the UI. `modes/check-mode.sh` and `modes/check-combined.sh` validate the generated assets used by the client. ARM64 CI explicitly regenerates and checks the previously problematic Dual Transport, PQ Dual Transport, MAX QUIC WG/AWG, MAX TLS WG/AWG and ALL branches.

Production Portainer compose is image-only. Do not treat a Dockerfile build alone as deployment proof; reproduce failures in GitHub Actions first.

## Current platform boundary

The server/runtime, generated desktop/Unix controller paths, Setup Center, forwarding and mode validation are separate from mobile NetworkExtension/VpnService engine integration. The iOS Packet Tunnel target and Android native VPN engine must not claim a successful full-device connection until their platform tunnel engines are actually linked and validated. The apps may still import/link the private router bundle and expose setup/profile controls while that platform-specific engine work is in progress.

This boundary is intentional: the UI must report an unavailable capability rather than fake a successful tunnel.

## More documentation

- `docs/FULL-TUTORIAL.md` — full deployment/use guide
- `docs/CLIENT.md` — client/platform notes
- `docs/MODES.md` — raw runtime mode details
- `SECURITY.md` — security boundaries
- `router/asus-merlin-router-vpn-forwards.sh` — persistent ASUS WAN forwarding helper
