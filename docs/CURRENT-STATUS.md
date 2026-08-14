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
matching same-SHA GitHub artifact
→ bounded router-local build of the requested generic desktop/Portable package when needed
→ validate/package the generic secret-free application
→ stream
→ cleanup
```

Private node data is linked/imported separately after installation and is never baked into the generic installer or Portable package. One installed application can link multiple Router VPN nodes without reinstalling.

The router-local fallback is bounded to the requested generic client package and is tested on native ARM64. PortableApps/PAF is retired; normal Router VPN Portable ZIP x64/ARM64 remains supported.

## Native platform status

### Windows

Router VPN ships a native WPF daily-use application for x64 and ARM64. The native runtime has elevated full-device TUN paths for the supported layered modes, applies Router VPN DNS policy inside the TUN runtime, and has a Windows firewall kill-switch helper. Raw/native WireGuard and native multihop paths are part of the Windows implementation; WSL is not counted as the Windows VPN implementation.

Windows also has a source-implemented custom standard-exit path for saved WireGuard, SOCKS5, Shadowsocks and Hysteria2 exits behind a linked Router VPN WireGuard entry. It withholds Connected until the expected public exit IP is observed through the forced custom-exit path.

**Still a release gate:** physical Windows validation must prove full-device routing, DNS behavior, strict leak blocking, reconnect/network-change behavior, custom-exit traffic and all supported Windows packaging/install variants. Do not infer that gate merely from CI/package success.

### macOS

Router VPN ships a native AppKit/MapKit application. Native macOS routing, PF kill-switch handling and real native multihop are implemented. Saved WireGuard/SOCKS5/Shadowsocks/Hysteria2 custom standard exits use the same strict native desktop entry→exit model and expected-public-IP proof.

The current installer now installs and opens the real AppKit `RouterVPN.app`; it no longer creates a Chrome/Edge/Brave browser-app wrapper. The loopback controller remains private implementation/recovery plumbing. Physical macOS visual/network/custom-exit validation plus signing/notarization remain release work.

### Linux

Router VPN ships a native GTK application. Linux has the broadest native runtime coverage, nftables kill-switch handling and real multihop. Its custom standard-exit runtime applies the fail-closed nftables policy before the full-device `router-vpn` TUN starts and proves the expected public exit IP. Distro/runtime/desktop integration and live leak-negative/custom-exit validation remain release gates.

### Android

Android is a native `VpnService` application, not a controller-only shell. It has real WireGuard and AmneziaWG paths, the pinned combined libbox/Xray runtime for supported layered modes, AUTO/SMART/CUSTOM orchestration, strict-policy handling, exact selected-node proof and a real narrow multihop path (standard WireGuard entry to supported Shadowsocks/Hysteria2 exit).

Android now also has an app-private typed custom-exit store and native Custom Exits product screen for WireGuard, SOCKS5, Shadowsocks and Hysteria2. The libbox graph is one full-device VPN path (`TUN → custom exit → Router VPN WireGuard entry`) and success is withheld until a forced loopback proof request observes the saved expected public exit IP.

**Current boundary:** incompatible mixed-engine/AWG-entry multihop combinations remain unavailable rather than simulated. Physical Android VPN-permission, lockdown, reconnect, DNS/IPv4/IPv6, custom-exit traffic and leak-negative tests remain release gates.

### iOS / iPadOS

The SwiftUI application uses a real pinned WireGuardKit PacketTunnel for raw WireGuard and exact selected-node path proof. When strict policy is requested, the host configures NetworkExtension route lockdown (`includeAllNetworks` + `enforceRoutes`), aligns local-network exclusion with the imported LAN policy and enables on-demand reconnect; the PacketTunnel refuses strict mode unless those controls are actually active.

A reproducible Apple Libbox foundation is now being source-integrated from the exact Router VPN sing-box 1.13.12 commit (`1086ab2563320e0da0c23b3a491d8dfa0939dff4`) as an iOS/iOS-Simulator `Libbox.xcframework`. Until the PacketTunnel bridge itself compiles and is wired, this does **not** earn layered-engine readiness.

**Current boundary:** the shipping iOS PacketTunnel still has a real native WireGuard dataplane only. AmneziaWG, layered modes, ALL/MAX, multihop and custom standard exits remain unavailable until real Apple dataplanes exist; they must never report fake Connected state.

## Multihop / kill switch

- Linux, Windows and macOS have real entry→exit multihop implementations with entry != exit, exit-node proof, DNS-through-exit requirements and rollback/fail-closed handling.
- Android has a deliberately narrower real multihop subset.
- iOS multihop remains unavailable.
- Strict kill-switch source paths exist for Linux/macOS/Windows/Android and strict Apple WireGuard route-lockdown is now wired on iOS.
- Physical negative-leak validation during connect/fallback/reconnect/crash/sleep/network-change/DNS/IPv4/IPv6/LAN-policy transitions is still mandatory before final release.

## MTU / Jumbo

Router VPN supports catalog/default MTU, manual MTU, safe PMTU-based auto selection, effective-MTU proof metadata, per-path auto-MTU memory and explicit Jumbo (`9000`) policy where requested.

The current source also implements a bounded **throughput-aware MTU optimizer** after the selected private Router VPN path is proven. It tests safe candidate MTUs with bidirectional packet success, RTT and private-tunnel transfer-rate measurements, persists the winner by path context, and restores the original MTU if optimization fails. Windows has a native PowerShell implementation and Unix-like platforms use the shared optimizer contract. This remains subject to physical performance/path-change validation; it is not evidence that Jumbo or any specific MTU works Internet-wide.

## Setup Center Methods

Setup Center Methods is for simple, interoperable external/native-compatible configurations. Complex Router VPN stacks remain in the Router VPN app. Current method metadata explicitly distinguishes public direct tunnels/proxies from private/tunnel-only SOCKS5 and records whether an import/QR contract is actually supported.

External-app compatibility remains a live gate: remotely usable Methods must be tested off-LAN with real import → connect → DNS → HTTP → correct-exit proof. SOCKS5 `1080` remains private and must not be exposed to WAN merely to make a third-party client work.

## Custom standard-protocol exits

Custom standard exits are separate from Router VPN's `CUSTOM` transport-layer selector and separate from Setup Center Methods. They let the daily app use a linked Router VPN WireGuard node as an entry and then force full-device traffic through a saved external standard exit.

Current source support:

- **WireGuard exit** — Windows/macOS/Linux/Android
- **SOCKS5 exit** — Windows/macOS/Linux/Android
- **Shadowsocks exit** — Windows/macOS/Linux/Android
- **Hysteria2 exit** — Windows/macOS/Linux/Android
- **OpenVPN exit** — intentionally unavailable on the exact pinned sing-box 1.13.12 runtime because that Apple/mobile/runtime build does not include the OpenVPN endpoint. No fake OpenVPN checkbox/Connected state is permitted.
- **iOS custom exits** — still unavailable until the new Apple Libbox PacketTunnel bridge is real.

Desktop custom-exit secrets stay in local `standard-exits.json` with private-file/non-symlink checks; Android uses app-private storage. List/status APIs expose redacted summaries only. Every supported custom exit requires an expected public exit IP and must pass that exact path proof before Connected.

## AI Help

AI Help is server-side and provider-neutral. Current adapters cover OpenAI, Google Gemini, Anthropic/Claude, DeepSeek, xAI/Grok, Moonshot/Kimi and a restricted private/local OpenAI-compatible endpoint suitable for an AI Board service. Keys stay server-side; repository/runtime/page context is bounded and redacted. Provider web capability is optional and must not become an arbitrary SSRF path.

## Security boundaries

- DAITA-like is not exact Mullvad DAITA/Maybenot.
- Proxy-only modes do not magically provide arbitrary inbound forwarding.
- `8786` Setup Center stays private.
- `1080`, `8787`, `14444`, `9443`, SSH and admin services stay off WAN.
- A mode becomes Ready only because its real generated configuration/runtime validates.
- `Connected` requires exact selected-node/private-exit proof, not generic Internet reachability.
- Unsupported platform features stay unavailable with a real reason; UI/CSS must never force them Ready.

Use `docs/CURRENT-GUIDE.md` for setup/operation detail and `docs/NATIVE-APPS.md` for native application boundaries.
