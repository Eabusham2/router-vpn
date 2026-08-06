# Implementation status

## Generated and runnable when the target host supports the required kernel/userspace engine

- Raw WireGuard
- AmneziaWG 2 Fast
- AmneziaWG 2 Strong
- VLESS + REALITY/Vision
- Hybrid-PQ VLESS + REALITY/Vision
- Hysteria2/QUIC
- Shadowsocks 2022
- Authenticated private SOCKS5
- IPv4/IPv6 full tunnel and NAT
- Home AdGuard DNS
- Desktop AUTO/manual picker
- Runtime-selectable router profiles
- DAITA-like cover traffic
- Jumbo TUN option for proxy modes
- Port/range/protected-DMZ forwarding for WireGuard/AmneziaWG peers

## Included as disabled integration slots

- Rosenpass-enhanced WireGuard/AmneziaWG
- Exact Mullvad Maybenot/DAITA
- Shadowsocks + V2Ray-plugin TLS
- XHTTP/FinalMask
- Naive HTTP/2 and HTTP/3
- WireGuard over QUIC or Shadowsocks
- MAX TLS and MAX QUIC serial chains

## iOS

- SwiftUI profile/mode/control interface: included
- Network Extension target: included
- Functional AWG/Xray Packet Tunnel adapter: not yet linked
- Signed IPA: not included; Apple signing and entitlement are required
