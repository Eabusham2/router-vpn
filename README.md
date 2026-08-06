# router-vpn

Private home-exit VPN for an ASUS GT-BE19000AI AI Board or another Linux Docker host.

## What the single ZIP contains

- Router/Portainer stack
- Raw WireGuard server and client profile
- AmneziaWG 2 Fast and Strong server/client profiles
- VLESS + REALITY Vision profile
- Hysteria2/QUIC profile
- Shadowsocks 2022 profile
- Authenticated SOCKS5 proxy available after the VPN connects
- IPv4 + IPv6 full-tunnel routes
- Home AdGuard DNS
- AUTO/manual desktop mode controller
- Single-port, range, TCP/UDP/both, and protected-DMZ forwarding controls
- Jumbo-payload/TUN option where supported
- Source and prebuilt desktop controller binaries
- iPhone/iPad Xcode project and build workflow
- Integration adapters for PQ, exact DAITA, XHTTP/FinalMask, Naive, V2Ray-plugin, and MAX chains

## What is ready now

`WireGuard Raw`, `AmneziaWG 2 Fast`, `AmneziaWG 2 Strong`, `VLESS + REALITY Vision`, `Hysteria2 QUIC`, `Shadowsocks 2022`, private `SOCKS5`, AdGuard DNS, IPv4/IPv6, desktop AUTO/manual selection, and port forwarding through WireGuard/AWG peers.

## What still needs an upstream engine or credentials

Rosenpass PQ, exact Mullvad/Maybenot DAITA, XHTTP/FinalMask, NaiveProxy, domain-backed Shadowsocks+V2Ray TLS, and the MAX serial chains are included as disabled adapters. The iOS app source is included, but a signed working IPA requires your Apple signing identity, Network Extension entitlement, and a linked packet-tunnel engine.

## Start here

1. [Portainer installation](docs/INSTALL-PORTAINER.md) — easiest for the ASUS AI Board.
2. [SSH installation](docs/INSTALL-SSH.md) — Linux terminal alternative.
3. [Client use](docs/CLIENT.md).
4. [Mode list and overhead](docs/MODES.md).
5. [iPhone/iPad build](docs/IOS.md).

## Safety defaults

- SOCKS5, Portainer, AdGuard administration, SSH, bundle downloads, and the control API are LAN/tunnel-only.
- Dynamic public forwarding is accepted only from an authenticated WireGuard/AWG tunnel peer.
- Protected DMZ excludes management and VPN-listener ports.
- No generated keys or client bundles are stored in GitHub.
