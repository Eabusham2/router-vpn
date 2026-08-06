# Router VPN

Private home-exit VPN stack for the ASUS AI Board/Portainer.

## Included in the single ZIP

- Router Portainer stack and SSH installer
- Raw WireGuard
- AmneziaWG 2 Fast and Strong
- Hybrid post-quantum VLESS encryption + REALITY/Vision
- VLESS + REALITY/Vision
- Hysteria2/QUIC
- Shadowsocks 2022
- Authenticated private SOCKS5
- AUTO escalation and manual mode picker
- IPv4/IPv6, home AdGuard DNS, jumbo-payload toggle
- Single-port, range, TCP/UDP/both, and protected-DMZ controls
- Prebuilt desktop controller binaries
- iOS SwiftUI/Xcode project and signing workflow

Start with [`START-HERE.md`](START-HERE.md).

## Honest limits

The single signed iOS IPA is not included because Apple requires the owner's signing certificate, provisioning profiles, Apple Team ID, and Network Extension entitlement. The Xcode project and workflow are included.

Rosenpass, exact Mullvad Maybenot/DAITA, V2Ray-plugin TLS requiring a real certificate/domain, Naive, XHTTP/FinalMask, and serial MAX chains are included as disabled integration slots until their required engines or credentials are added. Ready modes are generated automatically.
