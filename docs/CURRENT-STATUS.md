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
- persistent Asuswrt-Merlin WAN-forward helper with dedicated chains and preserved existing JFFS hooks

## Complete onboarding and setup help

The WebGUI, Android controller app, and iOS app include a full first-run path rather than only client-profile import. The flow covers:

```text
Portainer / ASUS AI Board deployment
→ init/finalizer + running-service verification
→ private client bundle download
→ persistent ASUS Merlin WAN-forward installation
→ client install/profile import
→ DNS selection
→ AUTO / SMART AUTO / CUSTOM / manual modes
→ DAITA-like / Jumbo / SOCKS5 behavior
→ forwarding / Protected DMZ
→ optional safe checks and real off-LAN testing guidance
```

Onboarding behavior:

- starts automatically until completed
- persists the current step if closed
- closing does not mark it complete
- **Finish** persists completion on that client surface
- **Run full onboarding again** remains available afterward and does not erase the saved router profile
- optional setup checks do not pretend a live protocol handshake happened
- WebGUI live protocol testing remains explicit: a mode must actually connect/pass its health check before success is claimed

The private client bundle includes:

```text
router/asus-merlin-router-vpn-forwards.sh
```

The default ASUS WAN mapping uses external TCP `80` to AI Board TCP `18080` for ACME, leaving the AI Board's normal TCP `80` free for the AdGuard block page. Router VPN uses UDP `8443`; that does not collide with ASUS remote-management TCP `8443`.

The helper never exposes `1080`, `8786`, `8787`, `9443`, SSH, Portainer, or AdGuard admin. It appends Router VPN calls to existing `nat-start` / `firewall-start` content rather than replacing those scripts.

The native mobile onboarding keeps the same product-boundary wording as the rest of the repo: Android/iOS controller builds do not claim full native all-mode tunneling until their platform tunnel adapters are linked.

## Exact boundaries

- **Exact Mullvad DAITA/Maybenot:** not claimed. The current toggle is a self-hosted DAITA-like bidirectional cover-traffic implementation. Exact DAITA requires a coordinated Maybenot-capable tunnel implementation/server.
- **Jumbo packets:** the optional Jumbo TUN behavior does not mean 9000-byte frames stay intact across the public Internet. Payloads still segment to the actual path MTU, and IPv6 PMTU behavior must remain functional.
- **Universal censorship bypass:** not claimed. AUTO provides multiple independent transports and escalating fallbacks, but no self-hosted endpoint can guarantee connectivity if the home IP itself is blocked or the network is fully allow-listed/shut down.
- **Port forwarding:** inbound forwarding to the remote device requires a mode with a WireGuard/AmneziaWG peer path (raw/PQ/MAX/ALL). Proxy-only modes are outbound tunnels.
- **Naive/V2Ray public TLS:** generated automatically when the home endpoint has a usable public IPv4/hostname and ACME succeeds; otherwise those modes remain unavailable instead of silently downgrading.
- **Windows/PortableApps/Unix artifacts:** the controller/packages build in CI, but full native engine coverage is not equivalent to the macOS/Linux engine installers yet.
- **Android/iOS:** APK and IPA projects/artifacts build as controller/importer applications. The native full-mode Android `VpnService` and iOS Packet Tunnel engine adapters are not yet linked, so these are not claimed as complete all-mode mobile VPN clients.

Use `docs/CURRENT-GUIDE.md` for the authoritative mode chart and complete setup sequence.
