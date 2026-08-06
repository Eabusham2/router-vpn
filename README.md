# Router VPN

Private home-exit VPN package for the ASUS AI Board/Portainer host.

## Included now

- Raw WireGuard full tunnel
- AmneziaWG 2 Fast and Strong full tunnels
- VLESS + REALITY + Vision
- Hybrid-PQ VLESS + REALITY + Vision
- Hysteria2/QUIC
- Shadowsocks 2022
- AUTO escalation and manual mode picker on macOS/Linux
- Runtime-selectable router endpoint; no public address is compiled into the app
- Authenticated router SOCKS5 and local SOCKS5-only mode
- IPv4 and IPv6 routing
- Home AdGuard DNS
- Port, range, TCP/UDP/both, and protected-DMZ forwarding for WG/AWG peers
- Jumbo-payload toggle for compatible proxy TUN modes
- DAITA-like cover-traffic toggle
- Portainer and SSH installers
- Desktop/router binaries
- iOS Xcode project and signed-IPA workflow scaffold

## Not falsely labeled as finished

The picker includes disabled integration slots for Rosenpass, exact Mullvad DAITA/Maybenot, V2Ray-plugin TLS, XHTTP/FinalMask, NaiveProxy, WireGuard-over-transports, and MAX chains. They become selectable only after their required engine/profile files exist.

The iOS project has the interface and router-profile importer, but its Packet Tunnel engine adapter still must be linked and signed with your Apple Developer Team. No usable IPA is included.

## Start

Read **`INSTALL-EVERYTHING.md`**. Use only **`router-vpn.zip`**.
