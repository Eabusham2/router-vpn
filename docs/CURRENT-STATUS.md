# Current implementation status

This file describes the **current source implementation**. It does not turn a source feature into a release claim by itself: physical-device, off-LAN, leak-negative, signing and production-deploy gates remain separate and must be passed before release.

## Product split

Router VPN has two separate products/surfaces:

- **Setup Center** — private deployment/setup/admin/recovery/downloads/pairing/simple third-party Methods/Full Guide/AI Help.
- **Router VPN app** — native daily-use VPN client for nodes, map, logical modes, AUTO/SMART AUTO/CUSTOM, DNS, kill switch, multihop where supported, MTU/Jumbo, forwarding, settings and diagnostics.

Generic application packages contain no home secrets. Install the app once, then import/link one or more private router/node bundles independently. Native node managers support current/recent, last-used, measured-latency and name ordering; automatic lowest-latency selection is withheld until at least two usable nodes have real measurements.

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
- peer-owned explicit forwarding plus authenticated Setup Center/server-admin Protected DMZ
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

Router VPN ships a native WPF daily-use application for x64 and ARM64. The native runtime has elevated full-device TUN paths for supported layered modes, applies Router VPN DNS policy inside the TUN runtime, and has a Windows firewall kill-switch helper. Raw/native WireGuard and native multihop paths are part of the Windows implementation; WSL is not counted as the Windows VPN implementation.

Windows has validated external-profile import and direct/entry→exit connect flows for supported custom exits. WireGuard, SOCKS5, Shadowsocks and Hysteria2 use the standard external runtime. OpenVPN 2.7 profile import and a native Windows helper/adapter remain source-implemented because Windows OpenVPN is still a project target, but `openVPNRuntimeCapability()` intentionally reports OpenVPN unavailable on Windows until strict lifecycle cleanup passes native leak tests. Every currently supported external exit withholds Connected until its expected public exit is proven.

The Nodes/Map product surface exposes current/recent, last-used, lowest measured latency and name ordering plus 50-sample latency testing. Automatic lowest-latency selection requires at least two measured usable nodes; unmeasured nodes are not guessed fastest.

**Still a release gate:** physical Windows validation must prove full-device routing, DNS behavior, strict leak blocking, reconnect/network-change behavior, custom-exit traffic and all supported Windows packaging/install variants. Windows OpenVPN additionally remains unavailable until the native strict lifecycle/leak gate is passed; source helper presence alone does not make it supported.

### macOS

Router VPN ships a native AppKit/MapKit application. Native macOS routing, PF kill-switch handling and real native multihop are implemented. Saved WireGuard/SOCKS5/Shadowsocks/Hysteria2 custom exits use the strict native desktop entry→exit model and expected-public-IP proof. A native OpenVPN 2.7 source path is also implemented for direct exits and the supported TCP-over-entry hop case; unsupported OpenVPN/DNS/hop combinations fail closed instead of bypassing the selected path.

The Nodes & Map surface supports current/recent, last-used, lowest measured latency and name ordering, and automatic fastest selection only after at least two real measurements exist.

The current installer installs and opens the real AppKit `RouterVPN.app`; it does not create a browser-app wrapper. The loopback controller remains private implementation/recovery plumbing. Physical macOS visual/network/custom-exit validation plus signing/notarization remain release work.

### Linux

Router VPN ships a native GTK application. Linux has broad native runtime coverage, nftables kill-switch handling and real multihop. Its external runtime supports validated Router VPN/external node import, direct and supported entry→exit paths, current/recent/last-used/latency/name ordering, and measured-fastest selection. Coordinate-less nodes remain usable in the list and are never given invented map positions.

Linux also has a native OpenVPN 2.7 custom-exit path. It applies Router VPN-owned DNS/LAN/IPv6 policy, supports direct OpenVPN and the safe TCP OpenVPN-over-entry case, applies fail-closed platform policy before the full-device TUN, and proves the expected public exit before Connected. Distro/runtime/desktop integration and live leak-negative/custom-exit validation remain release gates.

### Android

Android is a native `VpnService` application, not a controller-only shell. It has real WireGuard and AmneziaWG paths, the pinned combined libbox/Xray runtime for supported layered modes, AUTO/SMART/CUSTOM orchestration, strict-policy handling, exact selected-node proof and a real narrow multihop path.

Android has an app-private typed external/custom-exit store and native Custom Exits product screen for WireGuard, SOCKS5, Shadowsocks and Hysteria2. Supported external graphs remain one full-device VPN path and success is withheld until a forced proof observes the saved expected public exit IP. OpenVPN remains unavailable on Android because no pinned native Android OpenVPN dataplane is shipped by this project.

The unified Android node catalog and product UI support current/recent, last-used, measured-latency and name ordering. Automatic fastest selection is withheld until at least two usable nodes have real latency measurements. Nodes without real coordinates remain list-only and are not geolocated from an IP.

**Current boundary:** incompatible mixed-engine/AWG-entry multihop combinations and OpenVPN remain unavailable rather than simulated. Physical Android VPN-permission, lockdown, reconnect, DNS/IPv4/IPv6, custom-exit traffic and leak-negative tests remain release gates.

### iOS / iPadOS

The SwiftUI application uses a real pinned WireGuardKit PacketTunnel for raw WireGuard and exact selected-node path proof. When strict policy is requested, the host configures NetworkExtension route lockdown (`includeAllNetworks` + `enforceRoutes`), aligns local-network exclusion with the imported LAN policy and enables on-demand reconnect; the PacketTunnel refuses strict mode unless those controls are actually active.

The pinned Libbox Apple bridge is now wired into the PacketTunnel source for the supported Router VPN layered profiles. It starts the exact imported Libbox assets and still requires the selected private node proof before startup is accepted. This source implementation does not remove the physical Apple-device validation gate.

iOS also has per-node private bundle storage and validated external-node selection. External WireGuard, SOCKS5, Shadowsocks and Hysteria2 use the Libbox PacketTunnel path and require an exact expected-public-IP proof before Connected. External OpenVPN remains explicitly unavailable because Router VPN does not ship a pinned native Apple OpenVPN dataplane.

The Linked Nodes UI supports current/recent, last-used, measured-latency and name ordering. Automatic lowest-latency selection requires at least two real measured nodes. Missing coordinates remain missing rather than being guessed.

**Current boundary:** AmneziaWG, full desktop-equivalent multihop, and any Router VPN modes whose real imported Apple dataplane is not available remain unavailable/fail-closed. MAX/ALL labels do not grant readiness by themselves. Physical iPhone/iPad permission, lockdown, reconnect, DNS/IPv4/IPv6, Libbox/external-exit traffic, leak-negative and signing validation remain release gates.

## Multihop / kill switch

- Linux, Windows and macOS have real entry→exit multihop implementations with entry != exit, exit-node proof, DNS-through-exit requirements and rollback/fail-closed handling.
- Android has a deliberately narrower real multihop subset.
- iOS full Router VPN multihop remains unavailable; external-node direct Libbox support does not pretend otherwise.
- Strict kill-switch source paths exist for Linux/macOS/Windows/Android and strict Apple route-lockdown is wired on iOS.
- Linux strict nftables policy does not preserve blanket pre-existing public established flows; only explicitly allowed endpoint/tunnel/LAN/link-maintenance paths survive.
- Physical negative-leak validation during connect/fallback/reconnect/crash/sleep/network-change/DNS/IPv4/IPv6/LAN-policy transitions is still mandatory before final release.

## MTU / Jumbo

Router VPN supports catalog/default MTU, manual MTU, safe PMTU-based auto selection, effective-MTU proof metadata, per-path auto-MTU memory and explicit Jumbo (`9000`) policy where requested.

The current source also implements a bounded **throughput-aware MTU optimizer** after the selected private Router VPN path is proven. It tests safe candidate MTUs with bidirectional packet success, RTT and private-tunnel transfer-rate measurements, persists the winner by path context, and restores the original MTU if optimization fails. Windows has a native PowerShell implementation and Unix-like platforms use the shared optimizer contract. This remains subject to physical performance/path-change validation; it is not evidence that Jumbo or any specific MTU works Internet-wide.

## Setup Center Methods

Setup Center Methods is for simple, interoperable external/native-compatible configurations. Complex Router VPN stacks remain in the Router VPN app. Current method metadata explicitly distinguishes public direct tunnels/proxies from private/tunnel-only SOCKS5 and records whether an import/QR contract is actually supported.

External-app compatibility remains a live gate: remotely usable Methods must be tested off-LAN with real import → connect → DNS → HTTP → correct-exit proof. SOCKS5 `1080` remains private and must not be exposed to WAN merely to make a third-party client work.

## Custom standard-protocol exits

Custom standard exits are separate from Router VPN's `CUSTOM` transport-layer selector and separate from Setup Center Methods. They can be direct external exits or, where the platform/runtime supports it, be reached through a selected Router VPN/external entry while preserving one fail-closed full-device path.

Current product capability:

- **WireGuard exit** — Windows/macOS/Linux/Android/iOS
- **SOCKS5 exit** — Windows/macOS/Linux/Android/iOS
- **Shadowsocks exit** — Windows/macOS/Linux/Android/iOS
- **Hysteria2 exit** — Windows/macOS/Linux/Android/iOS
- **OpenVPN exit** — Linux/macOS where the required OpenVPN 2.7 runtime and requested direct/hop policy are supported; Windows import/helper/adapter source exists but remains unavailable until native strict lifecycle/leak validation passes; unavailable on Android/iOS

Desktop external-profile secrets stay in private 0600 controller storage; Android uses app-private storage; iOS keeps full node bundles in its per-node private bundle store. Public list/status/profile APIs expose redacted summaries only. Every supported external exit requires an expected public exit IP and must pass that exact path proof before Connected.

## Forwarding / LAN policy

Explicit daily-client inbound forwarding is authenticated and peer-owned. Peer clear deletes only that peer's tagged rules and cannot flush Setup Center/admin or another peer's forwarding state. Broad Protected DMZ is an authenticated Setup Center/server-admin action; its allowed ranges exclude reserved infrastructure and enabled explicit admin forwards.

When LAN access is OFF, Router VPN drops both tunnel-peer traffic addressed to the AI Board's home-LAN address space and forwarded traffic from tunnel peers into the home LAN, while private tunnel control destinations remain available for the minimum recovery/control plane.

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
