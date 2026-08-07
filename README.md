# Router VPN

Private home-exit VPN package for an ASUS AI Board/Portainer Docker host.

## Included

- Raw WireGuard full tunnel
- AmneziaWG 2 Fast and Strong full tunnels
- Shadowsocks 2022
- VLESS + REALITY + Vision + Chrome uTLS
- Hybrid-PQ VLESS + REALITY + Vision
- Hysteria2 + QUIC + Salamander
- Dual TCP/UDP transport profiles
- Generated XHTTP/FinalMask and MAX TLS/QUIC chains on either WireGuard base
- ALL mode with TLS-first and QUIC fallback across both bases
- AUTO escalation from the lightest available mode to stronger modes
- Runtime-selectable router endpoint; no public address is compiled into the app
- Private no-auth SOCKS5 using only the tunnel IP and port
- IPv4 and IPv6 routing
- Home AdGuard DNS
- Port, range, TCP/UDP/both, target-port, and protected-DMZ forwarding
- DAITA-like randomized cover-traffic toggle
- Jumbo TUN toggle for compatible proxy modes
- Portainer Git-stack and SSH/Docker Compose installation paths
- Desktop/router binaries and iOS Xcode project

## Honest limitations

- Rosenpass WireGuard/AmneziaWG slots still require a live Rosenpass engine on both ends and generated exchange keys.
- Exact Mullvad DAITA/Maybenot is not claimed; the included toggle is DAITA-like cover traffic.
- V2Ray-plugin TLS and Naive HTTPS require an appropriate TLS endpoint and certificate, so they remain integration slots.
- Generated advanced profiles are configuration-validated, but must still be tested on the exact AI Board kernel, Docker version, ISP, and client operating system.
- The iOS interface/project is included, but the Packet Tunnel engine adapter, Apple Network Extension entitlement, and signing are still required. No universal pre-signed IPA is included.

## Start

Use **`router-vpn.zip`** and follow **`docs/FULL-TUTORIAL.md`**.
