# Current implementation status

## Router + macOS/Linux client path

Implemented and wired with runtime validation/fail-closed checks:

- Standard WireGuard full tunnel
- AmneziaWG 2 Fast / Strong
- WireGuard + Rosenpass PQ
- AmneziaWG 2 + Rosenpass PQ
- Xray VLESS + REALITY + XTLS Vision + Chrome fingerprint on TCP 443 with sing-box TUN
- Hybrid-PQ VLESS + REALITY + Vision
- Shadowsocks 2022
- Shadowsocks + V2Ray SIP003 WebSocket/TLS with automatic public TLS identity
- Hysteria2 + QUIC + Salamander
- Naive HTTPS HTTP/2 and HTTP/3/QUIC with automatic public TLS identity
- REALITY + XHTTP + FinalMask full TUN when the installed Xray build validates the profile
- Dual TCP/UDP transport profiles
- Rosenpass-enhanced MAX TLS and MAX QUIC branches on both WG and AmneziaWG bases
- ALL health-tested TLS-to-QUIC fallback
- Normal AUTO and slower SMART AUTO
- CUSTOM compatible-layer selection
- IPv4 + IPv6
- Home AdGuard / fastest public DNS / custom DNS / DoT / DoH / DoH3 / rescue policy
- DAITA-like bidirectional bounded cover traffic toggle
- Jumbo TUN on compatible proxy/TUN modes
- tunnel-only no-auth SOCKS5 using IP + port
- single-port, range, TCP/UDP/both, target-port and Protected DMZ forwarding
- dynamic reservation of the actual generated listener ports
- credential-stable current Portainer redeploy/upgrade path

## Onboarding and setup help

The WebGUI, Android controller app, and iOS app all include first-run onboarding with these rules:

- onboarding starts automatically until it is completed
- progress is persisted so a closed setup flow resumes later
- completion stays remembered after setup is finished
- **Run onboarding again** remains available afterward and does not erase the saved router profile
- setup explains runtime router/profile import, DNS choices, AUTO / SMART AUTO / CUSTOM, DAITA-like/Jumbo behavior, SOCKS5 safety, and forwarding boundaries
- optional setup checks validate configuration/catalog state without pretending a protocol handshake happened
- WebGUI live protocol testing remains explicit: an actual mode must be connected before a WireGuard/AWG/REALITY/QUIC handshake can be claimed

The native mobile onboarding keeps the same product-boundary wording as the rest of the repo: Android/iOS controller builds do not claim full native all-mode tunneling until their platform tunnel adapters are linked.

## Exact boundaries

- **Exact Mullvad DAITA/Maybenot:** not claimed. The current toggle is a self-hosted DAITA-like bidirectional cover-traffic implementation. Exact DAITA requires a coordinated Maybenot-capable tunnel implementation/server.
- **Universal censorship bypass:** not claimed. AUTO provides multiple independent transports and escalating fallbacks, but no self-hosted endpoint can guarantee connectivity if the home IP itself is blocked or the network is fully allow-listed/shut down.
- **Port forwarding:** inbound forwarding to the remote device requires a mode with a WireGuard/AmneziaWG peer path (raw/PQ/MAX/ALL). Proxy-only modes are outbound tunnels.
- **Naive/V2Ray public TLS:** generated automatically when the home endpoint has a usable public IPv4/hostname and ACME succeeds; otherwise those modes remain unavailable instead of silently downgrading.
- **Windows/PortableApps/Unix artifacts:** the controller/packages build in CI, but full native engine coverage is not equivalent to the macOS/Linux engine installers yet.
- **Android/iOS:** APK and IPA projects/artifacts build as controller/importer applications. The native full-mode Android `VpnService` and iOS Packet Tunnel engine adapters are not yet linked, so these are not claimed as complete all-mode mobile VPN clients.

Use `docs/CURRENT-GUIDE.md` for the current mode chart and setup steps.
