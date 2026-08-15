# What `router-vpn.zip` contains

`router-vpn.zip` is the all-in-one open-source **project/source package**. It contains the server/router stack, client source, native platform projects, mode definitions, build/package scripts, Setup Center source and documentation. It is not a private per-home-node client installer.

Included technology covers:

- WireGuard with userspace fallback
- AmneziaWG Fast / Strong
- Rosenpass PQ augmentation
- VLESS + REALITY + Vision and hybrid-PQ REALITY paths
- Hysteria2 / QUIC / Salamander
- Shadowsocks 2022
- Shadowsocks + V2Ray TLS
- Naive H2/H3
- XHTTP / FinalMask
- Dual, MAX, ALL, AUTO, SMART AUTO and CUSTOM runtime/logical orchestration
- SOCKS5, OverTLS and legacy ShadowsocksR compatibility
- IPv4/IPv6 and DNS policies
- forwarding / Protected DMZ
- DAITA-like bounded cover traffic
- native Windows WPF + Portable ZIP support
- native macOS AppKit/MapKit and Linux GTK apps
- native Android `VpnService` app
- native iOS/iPadOS SwiftUI + PacketTunnel with pinned WireGuardKit and supported Libbox paths
- validated custom standard-protocol exits, including desktop OpenVPN where its real dataplane is supported
- MIT license

The product does **not** claim exact Mullvad DAITA/Maybenot compatibility. Unsupported platform/protocol graphs remain unavailable rather than simulated.

PortableApps/PAF is retired and is not a supported deliverable. Normal Router VPN Portable ZIP x64/ARM64 remains supported.

## Client package model

The home node does not keep one giant platform archive forever. Generic client downloads are generated/selected on demand:

```text
matching same-SHA GitHub artifact
↓ if unavailable/unusable on supported desktop fallback targets
bounded router-local build of the requested generic client package only
↓
validate/package secret-free generic application
↓
stream
↓
cleanup
```

Private node data is **not baked into the public generic package**. Install the generic app once, then link/import/pair one or more private Router VPN nodes separately. Android/iOS do not use fake Linux-host mobile build fallbacks; they require matching real mobile artifacts.

## Mobile boundary

Android and iOS are no longer controller-only preview projects. Android has real native `VpnService` dataplanes for its supported modes. iOS has real pinned WireGuardKit raw WireGuard plus supported pinned Libbox PacketTunnel paths. Their unsupported subsets remain explicit and fail closed.

Physical mobile permission/routing/DNS/IPv4/IPv6, reconnect, leak-negative, supported custom-exit behavior and Apple signing/provisioning remain separate release gates; a successful source/package build is not that live proof.
