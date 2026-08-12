# What `router-vpn.zip` contains

`router-vpn.zip` is the all-in-one open-source project package. It contains the server/router stack, client source, mode definitions, platform projects, build/package scripts, Setup Center source, and documentation.

Included technology covers:

- WireGuard and AmneziaWG
- Rosenpass PQ augmentation
- VLESS + REALITY + Vision
- Hysteria2 / QUIC / Salamander
- Shadowsocks 2022
- Shadowsocks + V2Ray TLS
- Naive H2/H3
- XHTTP / FinalMask
- Dual, MAX, ALL, AUTO, SMART AUTO, CUSTOM
- SOCKS5, OverTLS, and legacy ShadowsocksR compatibility
- IPv4/IPv6, DNS policies, forwarding/Protected DMZ
- DAITA-like bounded cover traffic
- normal Router VPN Portable ZIP support
- Android/iOS projects with explicit platform tunnel limitations
- MIT license

The product does **not** claim exact Mullvad DAITA/Maybenot compatibility.

PortableApps/PAF is retired and is not a supported deliverable.

The home node does not keep one giant platform archive forever. Private packages are generated on demand: GitHub artifact first, router-local requested-package build fallback, temporary private customization, stream, cleanup.

Mobile note: Android and iOS controller projects build, but full native all-mode tunneling is not claimed until their platform-specific tunnel adapters are linked and validated.
