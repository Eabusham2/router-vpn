# Implementation status

## Ready in the base package

- Raw WireGuard
- AmneziaWG 2 Fast and Strong
- Shadowsocks 2022
- VLESS + REALITY + Vision + Chrome uTLS
- Hybrid-PQ VLESS + REALITY + Vision
- Hysteria2 + QUIC + Salamander
- IPv4/IPv6 full tunnel and NAT
- Home AdGuard DNS
- Desktop AUTO/manual picker
- Runtime-selectable router profiles
- DAITA-like randomized cover traffic
- Jumbo TUN option for compatible proxy modes
- No-auth private SOCKS5 at the tunnel IP and port
- Port/range/target-port/TCP/UDP/both/protected-DMZ forwarding for WireGuard and AmneziaWG peers

## Generated and configuration-validated by the finalizer

- Dual Transport: REALITY/Vision TCP + Hysteria2/QUIC UDP
- PQ Dual Transport: PQ REALITY/Vision TCP + Hysteria2/QUIC UDP
- PQ VLESS + REALITY + XHTTP + FinalMask
- MAX QUIC on a standard WireGuard base
- MAX QUIC on an AmneziaWG 2 base
- MAX TLS on a standard WireGuard base
- MAX TLS on an AmneziaWG 2 base
- ALL orchestration across both TLS bases and both QUIC bases

These profiles are enabled only when their generated files pass the included Xray/sing-box validation. Exact router/kernel/network testing is still required before treating them as production-ready.

## Remaining integration requirements

- Rosenpass-enhanced WireGuard/AmneziaWG: requires Rosenpass binaries, exchanged client/server keys, and live PSK application on both peers.
- Exact Mullvad Maybenot/DAITA: not included; the current toggle is DAITA-like cover traffic.
- Shadowsocks + V2Ray-plugin TLS: requires the plugin and a suitable TLS endpoint/certificate.
- Naive HTTPS HTTP/2: requires a NaiveProxy client/server and suitable TLS endpoint/certificate.

## iOS

- SwiftUI profile/mode/control interface: included
- Network Extension target: included
- Functional AWG/Xray Packet Tunnel adapter: not yet linked
- Signed IPA: not included; Apple signing and entitlement approval are required
