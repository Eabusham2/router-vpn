# Current implementation status

This file describes the **current source implementation**. It does not turn a source feature into a release claim by itself: physical-device, off-LAN, leak-negative, signing and production-deploy gates remain separate and must be passed before release.

## Product split

Router VPN has two separate products/surfaces:

- **Setup Center** — private deployment/setup/admin/recovery/downloads/pairing/simple third-party Methods/Full Guide/AI Help.
- **Router VPN app** — native daily-use VPN client for nodes, map, logical modes, AUTO/SMART AUTO/CUSTOM, DNS, kill switch, multihop where supported, MTU/Jumbo, forwarding, settings and diagnostics.

Generic application packages contain no home secrets. Install the app once, then import/link one or more private router/node bundles independently.

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
- Home AdGuard/public/custom/encrypted DNS policies and home-node DNS benchmark
- DAITA-like bounded cover traffic
- private SOCKS5
- OverTLS compatibility
- ShadowsocksR legacy compatibility
- forwarding / Protected DMZ
- persistent ASUS Merlin forwarding helper
- authenticated Setup Center admin surface, Connected Clients and persistent policy controls
- dynamic download jobs with progress/cancel/fallback handling
- server-side multi-provider AI Help with bounded/redacted repository/runtime context

## Build/deploy policy

GitHub Actions is the normal compile/test environment.

The **production Portainer server stack is exact-SHA image-only**. Production should never silently rebuild an unpinned server image from a moving branch.

Client package downloads use:

```text
matching GitHub artifact
→ bounded router-local requested-package build fallback when needed
→ temporary private node/profile injection
→ stream
→ cleanup
```

The router-local fallback is bounded to the requested generic client package and is tested on native ARM64. PortableApps/PAF is retired; normal Router VPN Portable ZIP x64/ARM64 remains supported.

## Native platform status

### Windows

Router VPN ships a native WPF daily-use application for x64 and ARM64. The native runtime has elevated full-device TUN paths for the supported layered modes, applies Router VPN DNS policy inside the TUN runtime, and has a Windows firewall kill-switch helper. Raw/native WireGuard and native multihop paths are part of the Windows implementation; WSL is not counted as the Windows VPN implementation.

**Still a release gate:** physical Windows validation must prove full-device routing, DNS behavior, strict leak blocking, reconnect/network-change behavior and all supported Windows packaging/install variants. Do not infer that gate merely from CI/package success.

### macOS

Router VPN ships a native AppKit/MapKit application. Native macOS routing, PF kill-switch handling and real native multihop are implemented. Physical macOS visual/network validation plus signing/notarization remain release work.

### Linux

Router VPN ships a native GTK application. Linux has the broadest native runtime coverage, nftables kill-switch handling and real multihop. Distro/runtime/desktop integration and live leak-negative validation remain release gates.

### Android

Android is a native `VpnService` application, not a controller-only shell. It has real WireGuard and AmneziaWG paths, the pinned combined libbox/Xray runtime for supported layered modes, AUTO/SMART/CUSTOM orchestration, strict-policy handling, exact selected-node proof and a real narrow multihop path (standard WireGuard entry to supported Shadowsocks/Hysteria2 exit).

**Current boundary:** incompatible mixed-engine/AWG-entry multihop combinations remain unavailable rather than simulated. Physical Android VPN-permission, lockdown, reconnect, DNS/IPv4/IPv6 and leak-negative tests remain release gates.

### iOS / iPadOS

The SwiftUI application uses a real pinned WireGuardKit PacketTunnel for raw WireGuard and exact selected-node path proof. When strict policy is requested, the host configures NetworkExtension route lockdown (`includeAllNetworks` + `enforceRoutes`), aligns local-network exclusion with the imported LAN policy and enables on-demand reconnect; the PacketTunnel refuses strict mode unless those controls are actually active.

**Current boundary:** iOS still has a real native WireGuard dataplane only. AmneziaWG, layered modes, ALL/MAX and multihop remain unavailable until real Apple dataplanes exist; they must never report fake Connected state.

## Multihop / kill switch

- Linux, Windows and macOS have real entry→exit multihop implementations with entry != exit, exit-node proof, DNS-through-exit requirements and rollback/fail-closed handling.
- Android has a deliberately narrower real multihop subset.
- iOS multihop remains unavailable.
- Strict kill-switch source paths exist for Linux/macOS/Windows/Android and strict Apple WireGuard route-lockdown is now wired on iOS.
- Physical negative-leak validation during connect/fallback/reconnect/crash/sleep/network-change/DNS/IPv4/IPv6/LAN-policy transitions is still mandatory before final release.

## MTU / Jumbo

Router VPN supports catalog/default MTU, manual MTU, safe PMTU-based auto selection, effective-MTU proof metadata, per-path auto-MTU memory and explicit Jumbo (`9000`) policy where requested.

A stronger **throughput-aware MTU optimizer** that tests multiple safe candidates over the proven tunnel path and remembers the best-performing candidate is still product work; the PMTU ceiling alone must not be described as a throughput benchmark.

## Setup Center Methods

Setup Center Methods is for simple, interoperable external/native-compatible configurations. Complex Router VPN stacks remain in the Router VPN app. Current method metadata explicitly distinguishes public direct tunnels/proxies from private/tunnel-only SOCKS5 and records whether an import/QR contract is actually supported.

External-app compatibility remains a live gate: remotely usable Methods must be tested off-LAN with real import → connect → DNS → HTTP → correct-exit proof. SOCKS5 `1080` remains private and must not be exposed to WAN merely to make a third-party client work.

## AI Help

AI Help is server-side and provider-neutral. Current adapters cover OpenAI, Google Gemini, Anthropic/Claude, DeepSeek, xAI/Grok, Moonshot/Kimi and a restricted private/local OpenAI-compatible endpoint suitable for an AI Board service. Keys stay server-side; repository/runtime/page context is bounded and redacted. Provider web capability is optional and must not become an arbitrary SSRF path.

## Security boundaries

- DAITA-like is not exact Mullvad DAITA/Maybenot.
- Proxy-only modes do not magically provide arbitrary inbound forwarding.
- `8786` Setup Center stays private.
- `1080`, `8787`, `14444`, `9443`, SSH and admin services stay off WAN.
- A mode becomes Ready only because its real generated configuration/runtime validates.
- `Connected` requires exact selected-node private-path proof, not generic Internet reachability.
- Unsupported platform features stay unavailable with a real reason; UI/CSS must never force them Ready.

Use `docs/CURRENT-GUIDE.md` for setup/operation detail and `docs/NATIVE-APPS.md` for native application boundaries.