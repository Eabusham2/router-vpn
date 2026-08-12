# Current implementation status

## Server/runtime

Implemented with validation/fail-closed checks:

- WireGuard with userspace `wireguard-go` fallback
- AmneziaWG Fast / Strong
- Rosenpass PQ variants
- VLESS + REALITY + Vision
- hybrid-PQ REALITY
- Shadowsocks 2022
- Hysteria2 / QUIC / Salamander
- Shadowsocks + V2Ray TLS
- Naive H2/H3
- XHTTP / FinalMask
- Dual transport
- MAX TLS / MAX QUIC
- ALL health-tested fallback
- AUTO / SMART AUTO / CUSTOM
- IPv4/IPv6
- Home AdGuard/public/custom/encrypted DNS policies
- DAITA-like bounded cover traffic
- SOCKS5
- OverTLS compatibility
- ShadowsocksR legacy compatibility
- forwarding / Protected DMZ
- persistent ASUS Merlin forwarding helper
- dynamic Setup Center/download broker

## Build/deploy policy

GitHub Actions is the normal compile/test environment.

The **production Portainer server stack is exact-SHA image-only**. This avoids relying on Portainer Git-stack image builds.

Client package downloads use:

```text
matching GitHub artifact
→ router-local requested-package build fallback
→ temporary home profile injection
→ stream
→ cleanup
```

The router-local fallback is bounded to the requested client package and is tested on native ARM64. PortableApps/PAF is retired; normal Router VPN Portable ZIP x64/ARM64 remains supported.

## Platform boundaries

### macOS / Linux
Most complete current multi-engine path.

### Windows
Packages and Portable ZIPs build and execute in CI. WSL transport execution is not claimed as a complete Windows full-device VPN; native TUN/Wintun + DNS integration remains required for that claim.

### Android
APK is a controller/importer shell. Full native `VpnService` tunnel adapters remain unimplemented.

### iOS / iPadOS
SwiftUI app and Packet Tunnel target build. The Packet Tunnel intentionally fails closed until real native engines are linked.

### Multihop / kill switch
These remain product requirements, but must stay marked unavailable until real networking implementations are complete.

## Security boundaries

- DAITA-like is not exact Mullvad DAITA/Maybenot.
- Proxy-only modes do not magically provide arbitrary inbound forwarding.
- `8786` Setup Center stays private.
- `1080`, `8787`, `14444`, `9443`, SSH and admin services stay off WAN.
- A mode becomes Ready only because its real generated configuration/runtime validates.

Use `docs/CURRENT-GUIDE.md` for the authoritative setup and feature guide.
